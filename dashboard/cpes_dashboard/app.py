"""FastAPI application: JSON API under /api, built frontend served from web/dist."""

from __future__ import annotations

import hashlib
import json
import platform
from collections import Counter
from decimal import Decimal
from typing import Any

from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

from . import __version__, analyst
from .evidence import available_models
from .experiments import METHOD_NOTES, ExperimentStore
from .live import LiveStore, elastic_settings
from .ingest import (
    CANONICAL_FIELDS,
    FORMATS,
    MAPPING_PRESETS,
    MAX_UPLOAD_BYTES,
    REQUIRED_FIELDS,
    detect_format,
    inspect_record,
    mapping_key,
    mapping_table,
    preset_configuration,
    resolve_mapping,
)
from .paths import REPO_ROOT, WEB_DIST, data_root
from .runner import DEFAULT_MODE, RESOLVER_MODES, RESOLVER_SETTINGS, SIGNAL_IDS, SIGNAL_WIRING, RunStore, cpes_version, git_state
from .storage import ARTIFACTS, DatasetStore

app = FastAPI(title="CPES research dashboard", version=__version__)
datasets = DatasetStore()
runs = RunStore(datasets)
experiments = ExperimentStore()
live = LiveStore(datasets)


@app.exception_handler(KeyError)
async def _not_found(_: Request, error: KeyError) -> JSONResponse:
    return JSONResponse({"detail": f"not found: {error.args[0] if error.args else ''}"}, status_code=404)


@app.exception_handler(ValueError)
async def _bad_request(_: Request, error: ValueError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=400)


@app.exception_handler(FileNotFoundError)
async def _missing_file(_: Request, error: FileNotFoundError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=409)


def _spec_from_query(mapping: str | None) -> dict[str, Any] | None:
    if not mapping:
        return None
    try:
        return json.loads(mapping)
    except json.JSONDecodeError as error:
        raise ValueError("mapping must be a JSON object.") from error


def _validation(dataset_id: str, spec: dict[str, Any] | None) -> dict[str, Any]:
    try:
        _, normalised = resolve_mapping(spec)
        key = mapping_key(normalised)
    except ValueError:
        key = "invalid-" + hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:12]
    return datasets.validation(dataset_id, spec, key)


def _default_spec(dataset_id: str) -> dict[str, Any] | None:
    return datasets.meta(dataset_id).get("suggested_mapping")


# ------------------------------------------------------------------- system


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "dashboard": __version__, "cpes": cpes_version(), "python": platform.python_version(), **git_state()}


@app.get("/api/system")
def system() -> dict[str, Any]:
    mapping = preset_configuration("elastic-sysmon-field-mapping-v1")
    return {
        "versions": health(),
        "data_root": str(data_root()),
        "formats": [
            {"format": "jsonl", "extensions": [".jsonl", ".ndjson"], "rule": "one JSON object per line; blank lines skipped and counted"},
            {"format": "json", "extensions": [".json"], "rule": "array of objects, {records: [...]}, Elasticsearch hits, or a single object"},
            {"format": "csv", "extensions": [".csv"], "rule": "header row; dotted column names are nested paths; empty cell = field absent; values stay strings"},
        ],
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "telemetry_sources": [
            {"name": "Sysmon via Winlogbeat (ECS) — Elasticsearch export", "status": "supported", "mapping": mapping.version},
            {"name": "Live Elasticsearch query", "status": "package only", "note": "cpes.adapters.ElasticRetrievalAdapter exists; the dashboard does not connect to a cluster."},
            {"name": "Other schemas (CSV/JSON)", "status": "via custom field mapping", "note": "map columns to the 11 canonical fields; values are copied, never transformed"},
        ],
        "canonical_fields": [{"name": name, "required": name in REQUIRED_FIELDS} for name in CANONICAL_FIELDS],
        "default_mapping": mapping_table(mapping),
        "signals": [{"signal_id": signal, **SIGNAL_WIRING[signal]} for signal in SIGNAL_IDS],
        "resolver": {key: list(value) for key, value in RESOLVER_SETTINGS.items()},
        "evidence_models": available_models(),
        "known_unsupported_techniques": [
            {"technique": "T1053.005 Scheduled task", "evidence": "README honest-miss check: executed, 0 detections (no signal implemented)."},
            {"technique": "T1547.001 Registry Run key", "evidence": "README honest-miss check: executed, 0 detections."},
            {"technique": "T1546.003 WMI event subscription", "evidence": "README honest-miss check: executed, 0 detections."},
            {"technique": "T1055.001 injection without CreateRemoteThread", "evidence": "mavinject.exe produced no Sysmon EID 8 in corpus-v3; the package observes remote threads only, so it cannot see these injections."},
            {"technique": "Any technique without an implemented signal", "evidence": "CPES scores only its four mechanism signals; the generic 'unexplained privilege gain' test exists only as an ablation script."},
        ],
        "limitations": [
            "Single endpoint: every telemetry record comes from one lab Windows 11 VM; no multi-host or organic-traffic evaluation exists in the repository.",
            "Two engines: published metrics come from the analysis scripts (process-instance unit); dashboard detection runs use cpes.CpesPipeline (lineage-chain × window unit). Their numbers are not interchangeable.",
            "Package engine vs research scripts (docs/RESULTS.md): with evidence channels the package reaches grouped-CV F1 0.684 on corpus-v3 against the research 0.993 — injection 0/18 (no mavinject remote threads in the data; the research signal is an image-name rule), UAC 15/33 (capped registry export), and 12 benign service flags because the package rule does not require parent = services.exe.",
            "Research labels are defined partly by the signals themselves (recall favourable by construction); corpus_eval_independent.py is the non-circular check and has no independent channel for injection.",
            "Lineage chains on real telemetry can be very large (one chain held 1,346 of 2,219 processes in corpus-v3), which makes chain-level metrics coarse.",
            "The frozen evidence model is in-sample for corpus-v3; detection runs on corpus-v3 are not held-out tests.",
            "Base rate: the robustness script shows precision falling from 0.996 at a 10% attack prior to 0.172 at 0.01%.",
            "Breadth: on 53 public Sysmon attack captures (EVTX-ATTACK-SAMPLES) CPES alone flags 9 and CPES with its generic test 26; SigmaHQ core rules flag 42 (docs/RESULTS.md §6, §9). CPES's auto-elevation signal names four binaries and does not generalise to other UAC methods.",
            "Renaming the injector defeats the research injection signal (an image-name rule); signals that read structure (service location, pipe pairing) are unaffected (docs/RESULTS.md §7).",
            "Service rule precision on cloud VMs is poor: on 100 unused OTRF captures all 7 of its alerts were Azure agents, and a pre-registered signature suppressor removed none (no image-load records for those agents). Not adopted (docs/RESULTS.md §12).",
            "Uploads have no ground-truth channel in this version, so no metric is computed for them.",
        ],
        "data_availability": [
            {"item": "Lab corpora (v3, combined)", "state": "local only, git-ignored", "note": "contain the lab hostname and account; never deploy"},
            {"item": "Expansion corpus v4", "state": "zipped only", "note": "1.1 GB archive, not extracted"},
            {"item": "Synthetic samples", "state": "in repository", "note": "illustrative only"},
        ],
    }


# ------------------------------------------------------------------- inventory / datasets


@app.get("/api/inventory")
def inventory() -> dict[str, Any]:
    items = datasets.list()
    run_counts = Counter(run["dataset_id"] for run in runs.list())
    for item in items:
        item["runs"] = run_counts.get(item["id"], 0)
    artifacts = []
    for artifact in ARTIFACTS:
        path = REPO_ROOT / artifact["path"]
        artifacts.append({**artifact, "available": path.exists(), "size_bytes": path.stat().st_size if path.exists() else None})
    return {"datasets": items, "artifacts": artifacts}


@app.post("/api/datasets/upload")
async def upload(
    file: UploadFile = File(...),
    name: str | None = Form(None),
    declared_source: str | None = Form(None),
    declared_synthetic: bool = Form(False),
) -> dict[str, Any]:
    fmt = detect_format(file.filename or "")
    if fmt is None:
        raise ValueError(f"unsupported file type '{file.filename}'. Supported: .csv, .json, .jsonl, .ndjson, .evtx.")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
    if not data.strip():
        raise ValueError("file is empty.")
    meta = datasets.upload(file.filename or "upload", data, fmt, name=name, declared_source=declared_source, declared_synthetic=declared_synthetic)
    meta["validation_report"] = _validation(meta["id"], _default_spec(meta["id"]))
    return meta


@app.delete("/api/datasets/{dataset_id}")
def delete_dataset(dataset_id: str) -> dict[str, Any]:
    if any(run["dataset_id"] == dataset_id for run in runs.list()):
        raise ValueError("this upload has recorded runs; delete is refused so those runs stay reproducible.")
    datasets.delete_upload(dataset_id)
    return {"deleted": dataset_id}


@app.get("/api/datasets/{dataset_id}")
def dataset(dataset_id: str) -> dict[str, Any]:
    meta = datasets.meta(dataset_id)
    parsed, index = datasets.load(dataset_id)
    meta = datasets.meta(dataset_id)
    return {
        **meta,
        "records": len(parsed),
        "parse_errors": parsed.parse_errors[:200],
        "parse_error_count": len(parsed.parse_errors),
        "structure_errors": parsed.structure_errors,
        "blank_lines": parsed.blank_lines,
        "csv_columns": parsed.csv_columns,
        "default_columns": index.default_columns(),
        "facet_fields": index.facet_fields(),
        "timestamp_field": index.timestamp_field(),
    }


@app.get("/api/datasets/{dataset_id}/schema")
def dataset_schema(dataset_id: str) -> list[dict[str, Any]]:
    _, index = datasets.load(dataset_id)
    return index.schema()


@app.post("/api/datasets/{dataset_id}/validate")
def dataset_validate(dataset_id: str, spec: dict[str, Any] | None = Body(None)) -> dict[str, Any]:
    return _validation(dataset_id, spec if spec else _default_spec(dataset_id))


@app.get("/api/datasets/{dataset_id}/validation")
def dataset_validation(dataset_id: str, mapping: str | None = None) -> dict[str, Any]:
    spec = _spec_from_query(mapping)
    return _validation(dataset_id, spec if spec is not None else _default_spec(dataset_id))


def _filters(request: Request) -> dict[str, list[str]]:
    filters: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        if key.startswith("f."):
            filters.setdefault(key[2:], []).append(value)
    return filters


@app.get("/api/datasets/{dataset_id}/records")
def dataset_records(
    request: Request,
    dataset_id: str,
    q: str | None = None,
    sort: str | None = None,
    order: str = "asc",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    columns: str | None = None,
    missing: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    indices: str | None = None,
    facets: bool = True,
) -> dict[str, Any]:
    _, index = datasets.load(dataset_id)
    wanted = [c for c in (columns.split(",") if columns else index.default_columns()) if c]
    chosen = [int(i) for i in indices.split(",") if i.strip()] if indices else None
    selection = index.select(q=q, filters=_filters(request), missing=missing, time_from=time_from, time_to=time_to, indices=chosen)
    page = index.page(selection, columns=wanted, sort=sort, order=order, offset=offset, limit=limit)
    if facets:
        page["facets"] = index.facets(index.facet_fields(), selection)
    return page


@app.get("/api/datasets/{dataset_id}/records/{record_index}")
def dataset_record(dataset_id: str, record_index: int, mapping: str | None = None) -> dict[str, Any]:
    parsed, _ = datasets.load(dataset_id)
    if not 0 <= record_index < len(parsed):
        raise KeyError(f"record {record_index}")
    spec = _spec_from_query(mapping)
    return inspect_record(parsed, record_index, spec if spec is not None else _default_spec(dataset_id))


@app.get("/api/datasets/{dataset_id}/export")
def dataset_export(request: Request, dataset_id: str, q: str | None = None, missing: str | None = None, time_from: str | None = None, time_to: str | None = None) -> Response:
    parsed, index = datasets.load(dataset_id)
    selection = index.select(q=q, filters=_filters(request), missing=missing, time_from=time_from, time_to=time_to)
    body = "\n".join(parsed.originals[i] for i in selection) + ("\n" if selection else "")
    return Response(body, media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{dataset_id}-filtered-{len(selection)}.jsonl"'})


@app.get("/api/mappings")
def mappings() -> dict[str, Any]:
    return {
        "presets": [{"id": name, "fields": mapping_table(preset_configuration(name))} for name in MAPPING_PRESETS],
        "canonical_fields": [{"name": name, "required": name in REQUIRED_FIELDS} for name in CANONICAL_FIELDS],
        "formats": list(FORMATS),
    }


# ------------------------------------------------------------------- runs


@app.get("/api/evidence-models")
def evidence_models() -> list[dict[str, Any]]:
    return available_models()


@app.get("/api/resolver-modes")
def resolver_modes() -> dict[str, Any]:
    return {"default": DEFAULT_MODE, "modes": list(RESOLVER_MODES)}


@app.post("/api/runs")
def start_run(request: dict[str, Any] = Body(...)) -> dict[str, Any]:
    if "mapping" not in request:
        request["mapping"] = _default_spec(request.get("dataset_id"))
    validation = _validation(request["dataset_id"], request.get("mapping"))
    if validation["status"] == "invalid":
        raise ValueError("dataset is invalid under this mapping; fix the validation errors first.")
    return runs.start(request)


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    return runs.list()


@app.get("/api/runs/{run_id}")
def run(run_id: str) -> dict[str, Any]:
    status = runs.status(run_id)
    status["config"] = runs.artifact(run_id, "config.json")
    return status


@app.get("/api/runs/{run_id}/windows")
def run_windows(
    run_id: str,
    detected: bool | None = None,
    chain: str | None = None,
    signal: str | None = None,
    q: str | None = None,
    min_score: float | None = None,
    max_score: float | None = None,
    baseline: bool | None = None,
    sort: str = "score",
    order: str = "desc",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
) -> dict[str, Any]:
    windows = runs.artifact(run_id, "windows.json") or []
    if detected is not None:
        windows = [w for w in windows if w["is_detected"] == detected]
    if baseline is not None:
        windows = [w for w in windows if w["baseline_detected"] == baseline]
    if min_score is not None:
        windows = [w for w in windows if Decimal(w["cpes_score"]) >= Decimal(str(min_score))]
    if max_score is not None:
        windows = [w for w in windows if Decimal(w["cpes_score"]) < Decimal(str(max_score))]
    if chain:
        windows = [w for w in windows if w["lineage_chain_id"] == chain]
    if signal:
        windows = [w for w in windows if signal in w["signals"]]
    if q:
        needle = q.lower()
        windows = [w for w in windows if needle in w["lineage_chain_id"].lower()]
    key = {"score": lambda w: (Decimal(w["cpes_score"]), w["start"]), "time": lambda w: (w["start"], w["window_index"]), "events": lambda w: (w["event_count"], w["start"])}.get(sort)
    if key is None:
        raise ValueError("sort must be score, time or events.")
    windows = sorted(windows, key=key, reverse=order == "desc")
    return {"total": len(windows), "offset": offset, "limit": limit, "rows": windows[offset: offset + limit]}


@app.get("/api/runs/{run_id}/windows/{window_index}")
def run_window(run_id: str, window_index: int) -> dict[str, Any]:
    export = runs.artifact(run_id, "export.json")
    if not 0 <= window_index < len(export["detections"]):
        raise KeyError(f"window {window_index}")
    record = export["detections"][window_index]
    audit = (runs.artifact(run_id, "audit.json") or {}).get(str(window_index))
    baseline = runs.artifact(run_id, "baseline.json")[window_index]
    summary = next((w for w in runs.artifact(run_id, "windows.json") if w["window_index"] == window_index), None)
    processes = runs.artifact(run_id, "processes.json")
    event_index = runs.artifact(run_id, "event_index.json")
    config = runs.artifact(run_id, "config.json")
    referenced = sorted({ref["process_guid"] for c in record["observations"] for ref in c["source_references"]})
    if audit:
        referenced = sorted(set(referenced) | {g for r in audit["resolved"] for g in (r["anchor_process_guid"], r["actor_process_guid"]) if g})
    evidence_events = sorted({e for r in (audit or {}).get("resolved", []) for e in r["evidence_event_ids"]})
    weights = {t["signal_id"]: t["signed_log_likelihood"] for t in config["evidence_model"]["terms"]}
    return {
        "window_index": window_index,
        "record": record,
        "summary": summary,
        "audit": audit,
        "baseline": baseline,
        "weights": weights,
        "prior_applied": config["evidence_model"]["prior_applied"],
        "processes": {guid: processes.get(guid) for guid in referenced},
        "evidence_events": [{"event_id": e, "record_indices": event_index.get(e, [])} for e in evidence_events],
        "dataset_id": config["dataset"]["id"],
        "signals": config["signals"],
    }


@app.get("/api/runs/{run_id}/chains")
def run_chains(run_id: str, sort: str = "score", detected_only: bool = False) -> list[dict[str, Any]]:
    chains = runs.artifact(run_id, "chains.json") or []
    export = runs.artifact(run_id, "export.json")
    labels = {r["lineage_chain_id"]: r.get("label") for r in export["detections"]}
    for chain in chains:
        chain["label"] = labels.get(chain["lineage_chain_id"])
    if detected_only:
        chains = [c for c in chains if c["detected_windows"]]
    if sort == "score":
        chains.sort(key=lambda c: (Decimal(c["max_score"]) if c["max_score"] is not None else Decimal("-1e9"), c["process_count"]), reverse=True)
    elif sort == "size":
        chains.sort(key=lambda c: c["process_count"], reverse=True)
    return chains


@app.get("/api/runs/{run_id}/chains/{chain_id}/graph")
def run_chain_graph(run_id: str, chain_id: str, focus: str | None = None, depth: int = Query(2, ge=0, le=12), max_nodes: int = Query(250, ge=10, le=2000)) -> dict[str, Any]:
    """Real reconstructed structure only. For large chains, a neighbourhood around
    ``focus`` (ancestors to the root, descendants to ``depth``) is returned and the
    response says how many nodes were left out."""

    structure = (runs.artifact(run_id, "structure.json") or {}).get(chain_id)
    if structure is None:
        raise KeyError(f"chain {chain_id}")
    processes = runs.artifact(run_id, "processes.json")
    parent_of = structure["parent_by_process_guid"]
    children = structure["children_by_process_guid"]
    members = set(structure["process_guids"])
    if len(members) <= max_nodes and focus is None:
        chosen = set(members)
    else:
        start = focus if focus in members else _default_focus(members, processes)
        chosen = set()
        node: str | None = start
        while node in members and node not in chosen:
            chosen.add(node)
            node = parent_of.get(node)
        frontier = [(start, 0)]
        while frontier and len(chosen) < max_nodes:
            current, level = frontier.pop(0)
            if level >= depth:
                continue
            for child in children.get(current, []):
                if child not in chosen and len(chosen) < max_nodes:
                    chosen.add(child)
                    frontier.append((child, level + 1))
    nodes = []
    for guid in sorted(chosen):
        info = processes.get(guid) or {"process_guid": guid}
        hidden_children = [c for c in children.get(guid, []) if c not in chosen]
        nodes.append({
            "id": guid,
            "image_path": info.get("image_path"),
            "process_id": info.get("process_id"),
            "integrity_level": info.get("integrity_level"),
            "first_seen": info.get("first_seen"),
            "event_count": info.get("event_count", 0),
            "detected_windows": info.get("detected_window_indices", []),
            "label": info.get("label"),
            "parent_process_guid": parent_of.get(guid),
            "parent_unresolved": parent_of.get(guid) is not None and parent_of.get(guid) not in members,
            "hidden_children": len(hidden_children),
            "is_root": guid == chain_id,
        })
    edges = [{"source": parent_of[guid], "target": guid} for guid in chosen if parent_of.get(guid) in chosen]
    return {
        "lineage_chain_id": chain_id,
        "total_nodes": len(members),
        "shown_nodes": len(nodes),
        "focus": focus,
        "unresolved_parent_process_guids": structure["unresolved_parent_process_guids"],
        "nodes": nodes,
        "edges": edges,
    }


def _default_focus(members: set[str], processes: dict[str, Any]) -> str:
    detected = [g for g in members if (processes.get(g) or {}).get("detected_window_indices")]
    return sorted(detected)[0] if detected else sorted(members)[0]


@app.get("/api/runs/{run_id}/processes/{process_guid}")
def run_process(run_id: str, process_guid: str) -> dict[str, Any]:
    processes = runs.artifact(run_id, "processes.json")
    if process_guid not in processes:
        raise KeyError(process_guid)
    info = dict(processes[process_guid])
    structure = (runs.artifact(run_id, "structure.json") or {}).get(info.get("lineage_chain_id"), {})
    info["children"] = structure.get("children_by_process_guid", {}).get(process_guid, [])
    parent = info.get("parent_process_guid")
    info["parent"] = processes.get(parent) if parent else None
    info["parent_in_telemetry"] = parent in processes if parent else None
    return info


@app.get("/api/runs/{run_id}/evaluation")
def run_evaluation(run_id: str) -> dict[str, Any]:
    return runs.artifact(run_id, "evaluation.json") or {"available": False, "reason": "run has not finished."}


@app.get("/api/runs/{run_id}/rejections")
def run_rejections(run_id: str) -> list[dict[str, Any]]:
    return runs.artifact(run_id, "rejections.json") or []


def _run_incidents(run_id: str) -> dict[str, Any]:
    """Recorded incidents; runs made before the incidents stage get CPES-only incidents built from their artifacts."""

    status = runs.status(run_id)
    if status.get("state") != "completed":
        raise FileNotFoundError("run has not completed")
    recorded = runs.artifact(run_id, "incidents.json")
    if recorded is not None:
        return recorded
    processes = runs.artifact(run_id, "processes.json") or {}
    cpes = analyst.cpes_alerts(runs.artifact(run_id, "export.json"), runs.artifact(run_id, "audit.json") or {}, processes)
    return {"rule": "cpes.correlation.correlate (built on request: this run predates the incidents stage)", "gap_seconds": 300.0,
            "sigma": {"enabled": False, "reason": "run predates the incidents stage"}, "cpes_alerts": len(cpes), "sigma_alerts": 0,
            "incidents": analyst.build_incidents(cpes, [], processes)}


@app.get("/api/runs/{run_id}/incidents")
def run_incidents(run_id: str) -> dict[str, Any]:
    return _run_incidents(run_id)


@app.get("/api/runs/{run_id}/incidents/{incident_id}/report.md")
def incident_report(run_id: str, incident_id: str) -> Response:
    status = runs.status(run_id)
    status["config"] = runs.artifact(run_id, "config.json")
    incident = next((i for i in _run_incidents(run_id)["incidents"] if i["id"] == incident_id), None)
    if incident is None:
        raise KeyError(incident_id)
    return Response(analyst.report_markdown(status, incident), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{run_id}-{incident_id}.md"'})


@app.get("/api/sigma")
def sigma_status() -> dict[str, Any]:
    return analyst.sigma_available()


ARTIFACT_FILES = {
    "export.json": ("export.json", "application/json"),
    "config.json": ("config.json", "application/json"),
    "evaluation.json": ("evaluation.json", "application/json"),
    "baseline.json": ("baseline.json", "application/json"),
    "rejections.json": ("rejections.json", "application/json"),
}


@app.get("/api/runs/{run_id}/download/{name}")
def run_download(run_id: str, name: str) -> Response:
    runs.status(run_id)
    if name == "detections.csv":
        return PlainTextResponse(runs.detections_csv(run_id), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{run_id}-detections.csv"'})
    if name == "incidents.json":
        return JSONResponse(_run_incidents(run_id), headers={"Content-Disposition": f'attachment; filename="{run_id}-incidents.json"'})
    if name == "attack-layer.json":
        layer = analyst.attack_layer(runs.status(run_id), _run_incidents(run_id)["incidents"])
        return JSONResponse(layer, headers={"Content-Disposition": f'attachment; filename="{run_id}-attack-layer.json"'})
    if name == "alerts.ecs.ndjson":
        body = analyst.ecs_alerts(runs.status(run_id), [a for i in _run_incidents(run_id)["incidents"] for a in i["alerts"] if a["source"] == "cpes"])
        return Response(body, media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{run_id}-alerts.ecs.ndjson"'})
    if name not in ARTIFACT_FILES:
        raise KeyError(name)
    path = runs.root / run_id / ARTIFACT_FILES[name][0]
    if not path.exists():
        raise KeyError(name)
    return FileResponse(path, media_type=ARTIFACT_FILES[name][1], filename=f"{run_id}-{name}")


# ------------------------------------------------------------------- experiments


@app.get("/api/experiments/catalog")
def experiment_catalog() -> list[dict[str, Any]]:
    return experiments.catalog()


@app.get("/api/experiments")
def experiment_list() -> list[dict[str, Any]]:
    return experiments.list()


@app.post("/api/experiments")
def experiment_start(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    return experiments.start(body.get("experiment_id", ""))


@app.get("/api/experiments/claims")
def experiment_claims() -> list[dict[str, Any]]:
    return experiments.claims()


@app.get("/api/experiments/notes")
def experiment_notes() -> list[dict[str, Any]]:
    return METHOD_NOTES


@app.get("/api/experiments/{execution_id}")
def experiment_get(execution_id: str) -> dict[str, Any]:
    return experiments.get(execution_id)


# ------------------------------------------------------------------- live


@app.get("/api/live")
def live_sessions() -> dict[str, Any]:
    settings = elastic_settings()
    return {"sessions": live.list(), "elasticsearch": {k: settings[k] for k in ("configured", "url", "index", "how")}}


@app.post("/api/live")
def live_start(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    return live.start(body)


@app.get("/api/live/{session_id}")
def live_get(session_id: str, since: int = Query(0, ge=0)) -> dict[str, Any]:
    return live.get(session_id, since)


@app.post("/api/live/{session_id}/stop")
def live_stop(session_id: str) -> dict[str, Any]:
    return live.stop(session_id)


# ------------------------------------------------------------------- overview


def _featured_chain(completed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The highest-scoring CPES outcome among recent runs, with its ancestry and actor (all from recorded artifacts)."""

    best = None
    for status in completed[:12]:
        try:
            private = bool(datasets.meta(status["dataset_id"]).get("private"))
        except KeyError:
            private = True
        try:
            incidents = _run_incidents(status["id"])["incidents"]
        except (KeyError, FileNotFoundError, TypeError):
            continue
        for incident in incidents:
            for alert in incident["alerts"]:
                if alert["source"] != "cpes":
                    continue
                # real public data first, then synthetic, private last: the landing page stays safe to screenshot or record
                rank = (not private, status.get("dataset_category") != "synthetic", alert.get("actor_process_guid") is not None, float(alert["score"]))
                if best is None or rank > best[0]:
                    best = (rank, status, incident, alert)
    if best is None:
        return None
    _, status, incident, alert = best
    processes = runs.artifact(status["id"], "processes.json") or {}
    config = runs.artifact(status["id"], "config.json") or {}

    def node(guid: str | None) -> dict[str, Any] | None:
        info = processes.get(guid or "")
        if not info:
            return None
        return {"process_guid": guid, "image": analyst._basename(info.get("image_path")), "pid": info.get("process_id"), "integrity_level": info.get("integrity_level")}

    chain, guid = [], alert["process_guid"]
    for _ in range(3):
        item = node(guid)
        if item is None:
            break
        chain.insert(0, item)
        guid = processes[guid].get("parent_process_guid")
    actor = node(alert.get("actor_process_guid"))
    sigma = [a for a in incident["alerts"] if a["source"] == "sigma"]
    return {
        "run_id": status["id"], "dataset_name": status.get("dataset_name"), "dataset_category": status.get("dataset_category"),
        "incident_id": incident["id"], "signal_id": alert["signal_id"], "weight": alert["weight"], "score": alert["score"],
        "threshold": config.get("threshold"), "window_index": alert["window_index"], "explanation": (alert.get("explanation") or [None])[0],
        "chain": chain, "actor": actor,
        "sigma_alerts": len(sigma), "sigma_titles": sorted({a["title"] for a in sigma})[:3],
    }


def _headline_results() -> list[dict[str, Any]]:
    """Headline figures read from the committed results/ files; an item is skipped if its file is missing."""

    def load(name: str) -> dict[str, Any] | None:
        path = REPO_ROOT / "results" / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    out = []
    if (r := load("research-grouped")) and "detectors" in r["result"]:
        d = r["result"]["detectors"]
        out.append({"label": "Lab corpus", "value": f"F1 {d['cpes']['fold_mean']['f1']:.3f}", "detail": f"grouped 5-fold CV · single-event rule {d['single_event_research']['fold_mean']['f1']:.3f}", "protocol": "research-grouped"})
    if (r := load("stream-replay-v3")):
        s = r["result"]["summary"]
        out.append({"label": "Live scoring", "value": f"{s['agree']}/{s['live_alerts']}", "detail": f"alerts identical to hindsight · median {s['median_time_to_alert_s']:.0f} s to alert", "protocol": "stream-replay-v3"})
    if (r := load("ext-evtx-privesc")):
        rows = {k: v for k, v in r["result"]["summary_by_category"].items() if k != "not_applicable_no_sysmon"}
        files = sum(v["files"] for v in rows.values())
        found = sum(v["cpes_or_generic"] for v in rows.values())
        specific = sum(v["cpes_detected"] for v in rows.values())
        sigma = load("sigma-ext-evtx")
        sigma_hits = sum(v["core_high"] for k, v in sigma["result"]["summary_by_category"].items() if k != "not_applicable_no_sysmon") if sigma else None
        out.append({"label": "Unseen public attacks", "value": f"{found}/{files}", "detail": f"{specific}/{files} by the specific signals" + (f" · SigmaHQ core {sigma_hits}/{files}" if sigma_hits is not None else ""), "protocol": "ext-evtx-privesc"})
    if (r := load("incidents-lab-v3")):
        c = r["result"]["configurations"]
        out.append({"label": "Names the elevated process", "value": c["fused"]["runs_whose_incident_names_the_elevated_process"], "detail": f"lab runs · SigmaHQ alone {c['sigma_alone']['runs_whose_incident_names_the_elevated_process']}", "protocol": "incidents-lab-v3"})
    return out


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    run_list = runs.list()
    completed = [r for r in run_list if r["state"] == "completed"]
    latest = completed[0] if completed else None
    latest_detail = None
    if latest:
        windows = runs.artifact(latest["id"], "windows.json") or []
        bins: Counter = Counter()
        detected_bins: Counter = Counter()
        for window in windows:
            key = int(float(window["cpes_score"]) // 1)
            bins[key] += 1
            detected_bins[key] += window["is_detected"]
        detected = sorted((w for w in windows if w["is_detected"]), key=lambda w: (Decimal(w["cpes_score"]), w["start"]), reverse=True)
        meta = None
        try:
            meta = datasets.meta(latest["dataset_id"])
        except KeyError:
            pass
        event_codes = {}
        try:
            report = _validation(latest["dataset_id"], runs.artifact(latest["id"], "config.json")["mapping"]["spec"])
            event_codes = report.get("event_codes", {})
            validation_status = report.get("status")
        except (KeyError, FileNotFoundError, ValueError):
            validation_status = None
        latest_detail = {
            "run": latest,
            "dataset": meta,
            "validation_status": validation_status,
            "score_histogram": [{"bin": b, "count": bins[b], "detected": detected_bins[b]} for b in sorted(bins)],
            "nonempty_windows": len(windows),
            "recent_detections": detected[:8],
            "event_codes": event_codes,
            "signals_fired": latest.get("summary", {}).get("signals_fired", {}),
        }
    return {
        "featured": _featured_chain(completed),
        "headline": _headline_results(),
        "runs": run_list[:8],
        "run_counts": dict(Counter(r["state"] for r in run_list)),
        "latest": latest_detail,
        "experiments": experiments.list()[:6],
        "claims": experiments.claims(),
        "datasets": len(datasets.list()),
        "health": health(),
    }


# ------------------------------------------------------------------- static frontend


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str) -> Response:
    if path.startswith("api/"):
        raise KeyError(path)
    if not WEB_DIST.exists():
        return PlainTextResponse("Frontend not built. Run `npm run build` in dashboard/web, or use the Vite dev server.", status_code=503)
    target = (WEB_DIST / path).resolve()
    if path and target.is_file() and WEB_DIST.resolve() in target.parents:
        return FileResponse(target)  # hashed asset names: safe to cache
    return FileResponse(WEB_DIST / "index.html", headers={"Cache-Control": "no-cache"})
