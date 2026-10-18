"""Detection runs: the unchanged ``CpesPipeline`` on a validated dataset.

What this module adds around the package is bookkeeping only: it records the
exact configuration and dataset checksum, keeps the package exporter's output
verbatim, indexes processes/chains/windows for the UI, and (when ground truth
exists) calls the package's ``EvaluationHarness`` and ``SingleEventBaselineDetector``.
"""

from __future__ import annotations

import csv
import io
import platform
import subprocess
import threading
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from cpes.baseline import SingleEventBaselineDetector
from cpes.context.resolver import ContextResolver
from cpes.evaluation import EvaluationHarness, LabeledChainDecision
from cpes.evaluation.metrics import evaluate as evaluate_decisions
from cpes.exporting import ResultExporter
from cpes.orchestration import CompositeObservationGenerator, CpesPipeline, PipelineConfiguration
from cpes.orchestration.resolved_observations import ResolvedSignalObservationGenerator
from cpes.windowing.models import SlidingWindowParameters

from . import __version__
from .evidence import LABEL_TABLE, load_model, read_label_table, to_evidence_model
from .ingest import KNOWN_INTEGRITY_LEVELS, map_records, mapping_table, resolve_mapping
from .paths import REPO_ROOT, data_root
from .storage import DatasetStore, new_id, now, read_json, write_json

SIGNAL_IDS = ("autoelevation_lolbin", "service_dropped_binary", "remote_thread_injection", "token_impersonation")
# Same discriminators as demo/cpes_demo.py and analysis/corpus_eval_grouped.py.
RESOLVER_SETTINGS = {
    "integrity_order": KNOWN_INTEGRITY_LEVELS,
    "auto_elevating_images": ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe"),
    "hijack_registry_tokens": ("ms-settings", "mscfile", "\\shell\\open\\command"),
    "elevated_levels": ("high", "system"),
    "system_path_tokens": ("\\windows\\", "\\program files"),
    "service_registry_tokens": ("\\services\\",),
    "interactive_shell_images": ("cmd.exe", "powershell.exe", "pwsh.exe"),
}
# Wiring status inside CpesPipeline, established by reading the package (see
# cpes/context/resolver.py docstring and cpes/windowing/manager.py).
SIGNAL_WIRING = {
    "autoelevation_lolbin": {"wired": True, "reads": "image_path, integrity_level, registry_object", "note": "Fires only when the auto-elevating binary and a hijack registry write fall in the same window (stricter than the research script, which needs no registry write)."},
    "service_dropped_binary": {"wired": True, "reads": "image_path, integrity_level, registry_object", "note": "SYSTEM-integrity binary outside \\Windows\\ and \\Program Files; a service registry write in the window is recorded as corroboration."},
    "remote_thread_injection": {"wired": False, "reads": "RemoteThreadEvidence (EID 8)", "note": "WindowManager never populates EventGroup.remote_thread_evidence, so this signal cannot fire through CpesPipeline yet."},
    "token_impersonation": {"wired": False, "reads": "PipeEvidence (EID 17/18)", "note": "WindowManager never populates EventGroup.pipe_evidence and CanonicalEvent has no pipe or user field, so this signal cannot fire through CpesPipeline yet."},
}
STAGES = ("queued", "loading", "mapping", "pipeline", "export", "baseline", "evaluation", "indexing", "completed")

_run_lock = threading.Lock()


def make_resolver() -> ContextResolver:
    settings = RESOLVER_SETTINGS
    return ContextResolver(
        settings["integrity_order"],
        settings["auto_elevating_images"],
        settings["hijack_registry_tokens"],
        elevated_levels=settings["elevated_levels"],
        system_path_tokens=settings["system_path_tokens"],
        service_registry_tokens=settings["service_registry_tokens"],
        interactive_shell_images=settings["interactive_shell_images"],
    )


def make_generator(resolver: ContextResolver) -> CompositeObservationGenerator:
    return CompositeObservationGenerator(
        tuple(ResolvedSignalObservationGenerator(signal, resolver, signal) for signal in SIGNAL_IDS)
    )


def git_state() -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=10).stdout.strip()

    try:
        return {"commit": run("rev-parse", "HEAD") or None, "cpes_package_modified": bool(run("status", "--porcelain", "--", "cpes"))}
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "cpes_package_modified": None}


def cpes_version() -> str:
    for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _decimal(value: Any, name: str) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{name} must be a decimal number.") from error


class RunStore:
    def __init__(self, datasets: DatasetStore) -> None:
        self.datasets = datasets

    @property
    def root(self):
        directory = data_root() / "runs"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def list(self) -> list[dict[str, Any]]:
        runs = [status for directory in self.root.iterdir() if (status := read_json(directory / "status.json"))]
        return sorted(runs, key=lambda status: (status.get("created_ns", 0), status["id"]), reverse=True)

    def status(self, run_id: str) -> dict[str, Any]:
        status = read_json(self.root / run_id / "status.json")
        if status is None:
            raise KeyError(run_id)
        return status

    def artifact(self, run_id: str, name: str) -> Any:
        self.status(run_id)
        return read_json(self.root / run_id / name)

    # ------------------------------------------------------------------ start
    def start(self, request: dict[str, Any], *, background: bool = True) -> dict[str, Any]:
        dataset_id = request.get("dataset_id")
        meta = self.datasets.meta(dataset_id)
        span = float(request.get("span_seconds", 300))
        advance = float(request.get("advance_seconds", 150))
        if span <= 0 or advance <= 0:
            raise ValueError("window span and advance must be positive.")
        if advance > span:
            raise ValueError("advance must not exceed span, otherwise events between windows are never scored.")
        model = load_model(request.get("evidence_model_id", "research-v3-full-table"))
        threshold = _decimal(request.get("threshold", model["default_threshold"]), "threshold")
        configuration, normalised = resolve_mapping(request.get("mapping"))
        run_id = new_id("run")
        status = {
            "id": run_id,
            "state": "queued",
            "stage": "queued",
            "stages": list(STAGES),
            "created_at": now(),
            "created_ns": time.time_ns(),
            "dataset_id": dataset_id,
            "dataset_name": meta["name"],
            "dataset_category": meta["category"],
            "note": (request.get("note") or "").strip()[:500],
            "kind": "detection_run",
        }
        directory = self.root / run_id
        write_json(directory / "status.json", status)
        params = {"span": span, "advance": advance, "threshold": threshold, "model": model, "mapping_spec": normalised, "mapping": configuration}
        if background:
            threading.Thread(target=self._execute, args=(run_id, params), daemon=True).start()
        else:
            self._execute(run_id, params)
        return self.status(run_id)

    def _update(self, run_id: str, **changes: Any) -> None:
        path = self.root / run_id / "status.json"
        status = read_json(path)
        status.update(changes)
        write_json(path, status)

    # ------------------------------------------------------------------ execute
    def _execute(self, run_id: str, params: dict[str, Any]) -> None:
        with _run_lock:
            timings: dict[str, float] = {}
            stage_started = time.perf_counter()

            def stage(name: str) -> None:
                nonlocal stage_started
                current = read_json(self.root / run_id / "status.json")["stage"]
                if current not in ("queued",):
                    timings[current] = round(time.perf_counter() - stage_started, 3)
                stage_started = time.perf_counter()
                self._update(run_id, stage=name, state="running", timings=timings)

            try:
                self._run(run_id, params, stage)
                stage("completed")  # closes the timing of the last real stage
                self._update(run_id, state="completed", stage="completed", completed_at=now(), timings=timings)
            except Exception as error:  # recorded, never hidden
                self._update(run_id, state="failed", error=str(error), error_type=type(error).__name__, traceback=traceback.format_exc()[-4000:], failed_at=now(), timings=timings)

    def _run(self, run_id: str, params: dict[str, Any], stage) -> None:
        directory = self.root / run_id
        status = read_json(directory / "status.json")
        dataset_id = status["dataset_id"]

        stage("loading")
        meta = self.datasets.meta(dataset_id)
        parsed, _ = self.datasets.load(dataset_id)
        meta = self.datasets.meta(dataset_id)
        if parsed.structure_errors:
            raise ValueError("dataset has structural errors: " + "; ".join(parsed.structure_errors))

        stage("mapping")
        mapped = map_records(parsed, params["mapping"], params["mapping_spec"]["event_id_from_position"])
        if not mapped.events:
            raise ValueError("no record passed validation under this mapping; nothing to run.")
        events = mapped.events
        stamps = [_ts(event.source_timestamp) for event in events]
        start_at = min(stamps)
        horizon_end_at = max(stamps) + timedelta(seconds=params["span"])
        window_parameters = SlidingWindowParameters(start_at, horizon_end_at, params["span"], params["advance"])
        resolver = make_resolver()
        evidence_model = to_evidence_model(params["model"], SIGNAL_IDS)
        configuration = PipelineConfiguration(window_parameters, evidence_model, params["threshold"], make_generator(resolver))

        config = {
            "run_id": run_id,
            "created_at": status["created_at"],
            "dataset": {
                "id": dataset_id,
                "name": meta["name"],
                "category": meta["category"],
                "origin": meta["origin"],
                "sha256": meta.get("sha256"),
                "records_read": len(parsed),
                "parse_errors": len(parsed.parse_errors),
                "records_accepted": len(events),
                "records_rejected": len(mapped.rejections),
                "rejection_note": "Rejected records are excluded from the run and listed in rejections.json; nothing was repaired.",
            },
            "mapping": {"spec": params["mapping_spec"], "version": params["mapping"].version, "fields": mapping_table(params["mapping"])},
            "window": {
                "span_seconds": params["span"],
                "advance_seconds": params["advance"],
                "start_at": start_at.isoformat(),
                "horizon_end_at": horizon_end_at.isoformat(),
                "rule": "start = earliest accepted timestamp; horizon = latest + span; advance ≤ span so every event is in at least one window.",
            },
            "threshold": str(params["threshold"]),
            "evidence_model": params["model"],
            "signals": {signal: SIGNAL_WIRING[signal] for signal in SIGNAL_IDS},
            "resolver": {key: list(value) for key, value in RESOLVER_SETTINGS.items()},
            "versions": {"cpes": cpes_version(), "dashboard": __version__, "python": platform.python_version(), **git_state()},
            "engine": "cpes.orchestration.CpesPipeline (unchanged package code)",
        }
        write_json(directory / "config.json", config)
        write_json(directory / "rejections.json", mapped.rejections)

        stage("pipeline")
        context = CpesPipeline().run(events, configuration)

        stage("export")
        labels = self._process_labels(meta)
        chain_labels = self._chain_labels(context, labels) if labels else None
        export = ResultExporter().build(
            context,
            run_metadata={"run_id": run_id, "dataset_id": dataset_id, "dataset_sha256": meta.get("sha256"), "threshold": str(params["threshold"]), "evidence_model": params["model"]["id"], "window": config["window"]},
            chain_labels=chain_labels,
        )
        write_json(directory / "export.json", export)

        stage("baseline")
        baseline = SingleEventBaselineDetector(KNOWN_INTEGRITY_LEVELS)
        baseline_decisions = [baseline.evaluate(item.detection_window.event_group) for item in context.window_observations]
        write_json(directory / "baseline.json", [
            {"window_index": index, "lineage_chain_id": d.lineage_chain_id, "is_detected": d.is_detected, "triggering_process_guids": list(d.triggering_process_guids)}
            for index, d in enumerate(baseline_decisions)
        ])

        stage("evaluation")
        evaluation = self._evaluate(context, export, baseline_decisions, labels, chain_labels, meta)
        write_json(directory / "evaluation.json", evaluation)

        stage("indexing")
        self._index(directory, context, events, mapped.record_indices, resolver, baseline_decisions, params, labels)
        summary = export["summary"]
        detected = [record for record in export["detections"] if record["is_detected"]]
        self._update(
            run_id,
            summary={
                "records_accepted": len(events),
                "records_rejected": len(mapped.rejections),
                "process_nodes": len(context.process_nodes),
                "lineage_chains": len(context.lineage_chains),
                "scored_windows": summary["scored_units"],
                "nonempty_windows": sum(1 for w in context.detection_windows if w.event_group.events),
                "detected_windows": summary["detections"],
                "detected_chains": len({record["lineage_chain_id"] for record in detected}),
                "signals_fired": dict(Counter(c["signal_id"] for record in detected for c in record["contributions"])),
                "threshold": str(params["threshold"]),
                "evidence_model": params["model"]["id"],
                "evaluated": evaluation.get("available", False),
            },
            dataset_sha256=meta.get("sha256"),
        )

    # ------------------------------------------------------------------ labels
    @staticmethod
    def _process_labels(meta: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
        if meta.get("id") != "lab-corpus-v3" or not LABEL_TABLE.exists():
            return None
        return {
            row["instance_id"]: {"is_attack": row["label_is_escalation"] == "1", "technique": None if row["technique"] == "benign" else row["technique"]}
            for row in read_label_table(LABEL_TABLE)
        }

    @staticmethod
    def _chain_labels(context, labels: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        out = {}
        for chain in context.lineage_chains:
            labelled = [labels[guid] for guid in chain.process_guids if guid in labels]
            if labelled:
                techniques = sorted({item["technique"] for item in labelled if item["technique"]})
                out[chain.lineage_chain_id] = {
                    "is_attack": any(item["is_attack"] for item in labelled),
                    "techniques": techniques,
                    "labelled_processes": len(labelled),
                    "attack_processes": sum(item["is_attack"] for item in labelled),
                    "derivation": "chain is attack if it contains ≥1 process labelled attack in the v3 feature table",
                }
        return out

    @staticmethod
    def _evaluate(context, export, baseline_decisions, labels, chain_labels, meta) -> dict[str, Any]:
        if not labels:
            return {
                "available": False,
                "reason": "This dataset has no ground truth the dashboard can read, so no precision/recall/F1 is computed. Detection outputs are still inspectable.",
                "ground_truth": meta.get("ground_truth"),
            }
        harness = EvaluationHarness()
        labelled_export = {"detections": [record for record in export["detections"] if record["lineage_chain_id"] in chain_labels]}
        excluded_chains = sorted({record["lineage_chain_id"] for record in export["detections"]} - set(chain_labels))
        cpes_chain = harness.evaluate("cpes", harness.cpes_chain_decisions(labelled_export))
        base_chain = harness.evaluate("single_event_baseline", harness.baseline_chain_decisions([d for d in baseline_decisions if d.lineage_chain_id in chain_labels], chain_labels))
        chain_comparison = harness.compare(cpes_chain, base_chain)
        sizes = sorted(((len(c.process_guids), c.lineage_chain_id) for c in context.lineage_chains), reverse=True)

        flagged = {
            reference["process_guid"]
            for record in export["detections"] if record["is_detected"]
            for contribution in record["contributions"]
            for reference in contribution["source_references"]
        }
        baseline_flagged = {guid for d in baseline_decisions for guid in d.triggering_process_guids}
        cpes_process = evaluate_decisions("cpes", [LabeledChainDecision(g, v["is_attack"], g in flagged) for g, v in labels.items()])
        base_process = evaluate_decisions("single_event_baseline", [LabeledChainDecision(g, v["is_attack"], g in baseline_flagged) for g, v in labels.items()])
        per_technique = defaultdict(lambda: {"attack_processes": 0, "cpes_flagged": 0, "baseline_flagged": 0})
        for guid, value in labels.items():
            if value["is_attack"]:
                row = per_technique[value["technique"]]
                row["attack_processes"] += 1
                row["cpes_flagged"] += guid in flagged
                row["baseline_flagged"] += guid in baseline_flagged
        unlabelled_flags = sorted(flagged - set(labels))
        images: dict[str, str] = {}
        for event in context.canonical_events:
            if isinstance(event.process_guid, str) and event.image_path and event.process_guid not in images:
                images[event.process_guid] = event.image_path
        false_positives = [
            {"process_guid": guid, "image_path": images.get(guid)}
            for guid in sorted(flagged) if guid in labels and not labels[guid]["is_attack"]
        ]
        missed = Counter(labels[guid]["technique"] for guid in labels if labels[guid]["is_attack"] and guid not in flagged)
        return {
            "available": True,
            "ground_truth": meta.get("ground_truth"),
            "in_sample_warning": "The evidence model was derived from this same corpus's labelled table. These are in-sample figures, not a held-out test, and they are not the paper's protocol.",
            "chain_level": {
                "protocol": "EvaluationHarness: one decision per lineage chain (flagged if any window ≥ threshold); chain label derived from process labels.",
                "labelled_chains": len(chain_labels),
                "excluded_unlabelled_chains": len(excluded_chains),
                "largest_chains": [{"lineage_chain_id": chain_id, "processes": size, "label": chain_labels.get(chain_id)} for size, chain_id in sizes[:5]],
                "caveat": "Real lineage chains are coarse: the largest chain can contain most of the host's processes, so one detection anywhere marks the whole chain. Treat these numbers as a property of the chain unit, not as detection quality.",
                "comparison": chain_comparison,
            },
            "process_level_diagnostic": {
                "protocol": "Dashboard reduction (not a paper metric): a labelled process counts as flagged if a contribution in a detected window references it; baseline flags the child of every integrity elevation in any window. All 2,161 labelled process instances are scored.",
                "cpes": harness._evaluation_dict(cpes_process),
                "single_event_baseline": harness._evaluation_dict(base_process),
                "per_technique": dict(sorted(per_technique.items())),
                "flagged_but_unlabelled": len(unlabelled_flags),
                "false_positive_processes": false_positives,
                "missed_by_technique": dict(sorted(missed.items())),
                "explanation": "Token-impersonation and injection signals are not wired through CpesPipeline (see System page), so those attack processes cannot be flagged by this engine; the research scripts implement them separately.",
            },
        }

    # ------------------------------------------------------------------ index
    @staticmethod
    def _index(directory, context, events, record_indices, resolver, baseline_decisions, params, labels) -> None:
        record_by_event: dict[str, list[int]] = defaultdict(list)
        processes: dict[str, dict[str, Any]] = {}
        for event, record_index in zip(events, record_indices):
            record_by_event[str(event.source_event_id)].append(record_index)
            guid = event.process_guid
            if not isinstance(guid, str):
                continue
            item = processes.setdefault(guid, {
                "process_guid": guid, "parent_process_guid": None, "process_id": None, "image_path": None,
                "integrity_level": None, "command_line": None, "first_seen": event.source_timestamp,
                "last_seen": event.source_timestamp, "event_count": 0, "event_codes": Counter(), "events": [],
            })
            item["event_count"] += 1
            item["event_codes"][str(event.event_code)] += 1
            item["last_seen"] = event.source_timestamp
            for name in ("parent_process_guid", "process_id", "image_path", "integrity_level", "command_line"):
                if item[name] is None and getattr(event, name) is not None:
                    item[name] = getattr(event, name)
            if len(item["events"]) < 400:
                item["events"].append({"event_id": str(event.source_event_id), "timestamp": event.source_timestamp, "event_code": event.event_code, "record_index": record_index})
        for item in processes.values():
            item["event_codes"] = dict(item["event_codes"])
            item["label"] = labels.get(item["process_guid"]) if labels else None

        node_flags = {node.process_guid: node for node in context.process_nodes}
        chain_of = {}
        windows = []
        audits = {}
        per_chain = defaultdict(lambda: {"windows": 0, "nonempty_windows": 0, "detected_windows": 0, "max_score": None, "signals": Counter()})
        detected_processes: dict[str, list[int]] = defaultdict(list)
        for index, (item, decision, base) in enumerate(zip(context.window_observations, context.threshold_decisions, baseline_decisions)):
            window = item.detection_window
            group = window.event_group
            result = decision.cpes_score_result
            stats = per_chain[group.lineage_chain_id]
            stats["windows"] += 1
            if not group.events:
                continue
            stats["nonempty_windows"] += 1
            score = result.cpes_score
            stats["max_score"] = str(score) if stats["max_score"] is None or score > Decimal(stats["max_score"]) else stats["max_score"]
            present = [o.signal_id for o in item.observations if o.is_present]
            if decision.is_detected:
                stats["detected_windows"] += 1
                stats["signals"].update(present)
            windows.append({
                "window_index": index,
                "lineage_chain_id": group.lineage_chain_id,
                "start": window.start_at.isoformat(),
                "end": window.end_at.isoformat(),
                "event_count": len(group.events),
                "process_count": len({e.process_guid for e in group.events}),
                "cpes_score": str(score),
                "is_detected": decision.is_detected,
                "signals": present,
                "baseline_detected": base.is_detected,
                "integrity_transitions": len(group.integrity_transitions),
                "flags": {"truncated": group.is_truncated, "incomplete": group.is_incomplete, "fragmented": group.is_fragmented},
            })
            if present:
                resolved = resolver.resolve(group, pipe_evidence=group.pipe_evidence, remote_thread_evidence=group.remote_thread_evidence)
                audits[str(index)] = {
                    "event_ids": [e.event_id for e in group.events],
                    "integrity_transitions": [vars(t) for t in group.integrity_transitions],
                    "resolved": [
                        {"anchor_process_guid": r.anchor_process_guid, "anchor_kind": r.anchor_kind, "actor_process_guid": r.actor_process_guid, "mediator": r.mediator, "privilege_level": r.privilege_level, "evidence_event_ids": list(r.evidence_event_ids), "resolution_path": list(r.resolution_path)}
                        for r in resolved
                    ],
                    "baseline_triggering_process_guids": list(base.triggering_process_guids),
                }
                if decision.is_detected:
                    for contribution in result.evidence_contributions:
                        for reference in contribution.source_references:
                            detected_processes[reference.process_guid].append(index)
        chains = []
        for chain in context.lineage_chains:
            for guid in chain.process_guids:
                chain_of[guid] = chain.lineage_chain_id
            stats = per_chain[chain.lineage_chain_id]
            chains.append({
                "lineage_chain_id": chain.lineage_chain_id,
                "root_process_guid": chain.root_process_guid,
                "process_count": len(chain.process_guids),
                "unresolved_parent_count": len(chain.unresolved_parent_process_guids),
                "is_truncated": chain.is_truncated,
                "is_incomplete": chain.is_incomplete,
                "is_fragmented": chain.is_fragmented,
                "root_image": processes.get(chain.root_process_guid, {}).get("image_path"),
                "windows": stats["windows"],
                "nonempty_windows": stats["nonempty_windows"],
                "detected_windows": stats["detected_windows"],
                "max_score": stats["max_score"],
                "signals": dict(stats["signals"]),
                "label": None,
            })
        structure = {
            chain.lineage_chain_id: {
                "process_guids": list(chain.process_guids),
                "parent_by_process_guid": dict(chain.parent_by_process_guid),
                "children_by_process_guid": {k: list(v) for k, v in chain.children_by_process_guid},
                "unresolved_parent_process_guids": list(chain.unresolved_parent_process_guids),
            }
            for chain in context.lineage_chains
        }
        for guid, item in processes.items():
            item["lineage_chain_id"] = chain_of.get(guid)
            item["is_incomplete"] = node_flags[guid].is_incomplete if guid in node_flags else None
            item["detected_window_indices"] = sorted(set(detected_processes.get(guid, [])))
        write_json(directory / "chains.json", chains)
        write_json(directory / "structure.json", structure)
        write_json(directory / "processes.json", processes)
        write_json(directory / "windows.json", windows)
        write_json(directory / "audit.json", audits)
        write_json(directory / "event_index.json", record_by_event)

    # ------------------------------------------------------------------ exports
    def detections_csv(self, run_id: str) -> str:
        export = self.artifact(run_id, "export.json")
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["run_id", "lineage_chain_id", "window_start", "window_end", "cpes_score", "detection_threshold", "is_detected", "signals", "signed_log_likelihoods", "source_process_guids", "source_event_ids", "is_truncated", "label_is_attack"])
        for record in export["detections"]:
            if not record["is_detected"]:
                continue
            contributions = record["contributions"]
            references = [ref for c in contributions for ref in c["source_references"]]
            writer.writerow([
                run_id, record["lineage_chain_id"], record["window_start"], record["window_end"], record["cpes_score"],
                record["detection_threshold"], record["is_detected"],
                ";".join(c["signal_id"] for c in contributions),
                ";".join(c["signed_log_likelihood"] for c in contributions),
                ";".join(sorted({r["process_guid"] for r in references})),
                ";".join(sorted({r["event_id"] for r in references if r["event_id"]})),
                record["is_truncated"],
                (record.get("label") or {}).get("is_attack"),
            ])
        return buffer.getvalue()
