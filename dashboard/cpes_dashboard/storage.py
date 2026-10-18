"""Dataset, run and experiment stores on the local filesystem.

Every run and experiment gets a fresh directory; nothing is ever overwritten.
Built-in datasets are registered by reference (never copied); uploads are
stored byte-for-byte with their SHA-256.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .explorer import DatasetIndex
from .ingest import DEFAULT_PRESET_BY_FORMAT, ParsedDataset, parse_file, sha256_file, validate
from .paths import REPO_ROOT, data_root

_lock = threading.RLock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"


# On Windows a file another thread is reading cannot be replaced (or read while
# being replaced); both raise PermissionError for a few milliseconds. Retry briefly.
_RETRIES = 40


def read_json(path: Path, default: Any = None) -> Any:
    for attempt in range(_RETRIES):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except PermissionError:
            if attempt == _RETRIES - 1:
                raise
            time.sleep(0.025)
    return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    for attempt in range(_RETRIES):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == _RETRIES - 1:
                raise
            time.sleep(0.025)


# --------------------------------------------------------------------------- built-in datasets

BUILTIN: list[dict[str, Any]] = [
    {
        "id": "lab-corpus-v3",
        "name": "Lab corpus v3 (frozen evaluation corpus)",
        "path": "analysis/corpus-v3.ndjson",
        "format": "jsonl",
        "category": "research_telemetry",
        "source": "Sysmon 15 via Winlogbeat 9.4.3 (ECS), one isolated Windows 11 lab VM, exported from Elasticsearch on 2026-09-01.",
        "contents": "Atomic Red Team detonations (T1548.002, T1543.003, T1055.001, T1134.001/.002) plus a blind benign session.",
        "ground_truth": {
            "available": True,
            "unit": "process instance",
            "source": "Claude outputs/cpes_privilege_escalation_dataset.csv",
            "how": "A process is labelled an attack outcome when one of the four mechanism signals fires within 150 s of a logged Atomic execution (cpes-atomic-log-v3.csv). Recall is therefore favourable by construction; see corpus_eval_independent.py for the non-circular check.",
        },
        "private": True,
        "notes": "Per-event-code caps at export (10,000 EID 13; 6,000 EID 10/11/12; 4,000 EID 7). Contains the lab hostname and account name: local use only, never publish.",
        "experiments": ["grouped_cv", "ungrouped_cv_v3", "generic_ablation", "partial_evidence", "independent_channel", "robustness", "standalone_demo"],
    },
    {
        "id": "lab-corpus-combined",
        "name": "Lab corpus v1+v2 combined",
        "path": "analysis/corpus-combined.ndjson",
        "format": "jsonl",
        "category": "research_telemetry",
        "source": "Same lab VM and pipeline; earlier collection rounds combined.",
        "contents": "Earlier detonation rounds (cpes-atomic-log-combined.csv) and background activity.",
        "ground_truth": {
            "available": False,
            "unit": "run (provenance)",
            "source": "analysis/cpes-atomic-log-combined.csv",
            "how": "Only the provenance experiment labels this corpus (runner-root fingerprint inside the script). No per-record labels are exposed to the dashboard.",
        },
        "private": True,
        "notes": "Used by corpus_eval_provenance.py. Contains the lab hostname: local use only.",
        "experiments": ["provenance"],
    },
    {
        "id": "synthetic-format-preview",
        "name": "Synthetic format preview (10 records)",
        "path": "docs/sample-telemetry-SYNTHETIC.ndjson",
        "format": "jsonl",
        "category": "synthetic",
        "source": "Hand-written illustrative records (docs/CPES-Sample-Data-Format-SYNTHETIC-2026-09-10.md). NOT collected telemetry.",
        "contents": "One illustrative UAC-bypass-shaped chain. Has no winlog.record_id, so it needs position-derived event ids to map.",
        "ground_truth": {"available": False, "unit": None, "source": None, "how": "Synthetic; no labels."},
        "private": False,
        "notes": "Safe to show publicly. Any output on it demonstrates mechanics only, not detection performance.",
        "suggested_mapping": {"preset": "elastic-sysmon-field-mapping-v1", "event_id_from_position": True},
        "experiments": [],
    },
    {
        "id": "synthetic-legacy-sample",
        "name": "Synthetic legacy-schema sample (examples/)",
        "path": "examples/synthetic-telemetry-sample.json",
        "format": "json",
        "category": "synthetic",
        "source": "Hand-written sample used by examples/run_end_to_end_demo.py. NOT collected telemetry.",
        "contents": "Raw winlog.event_data.* fields that predate the ECS mapping; fails the v1 mapping as-is (the example script fails the same way).",
        "ground_truth": {"available": False, "unit": None, "source": None, "how": "Synthetic; the example script's labels are illustrative."},
        "private": False,
        "notes": "Demonstrates validation failure and custom column mapping.",
        "suggested_mapping": {
            "preset": None,
            "overrides": {
                "source_timestamp": "@timestamp",
                "source_event_id": "event.id",
                "event_code": "event.code",
                "process_guid": "winlog.event_data.ProcessGuid",
                "parent_process_guid": "winlog.event_data.ParentProcessGuid",
                "process_id": "winlog.event_data.ProcessId",
                "integrity_level": "winlog.event_data.IntegrityLevel",
                "command_line": "winlog.event_data.CommandLine",
                "registry_object": "winlog.event_data.TargetObject",
                "image_path": "winlog.event_data.Image",
                "module_path": "winlog.event_data.ImageLoaded",
            },
        },
        "experiments": [],
    },
]

PUBLIC_SAMPLES = [
    ("public-uac-eventvwr", "Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx", "UAC bypass via eventvwr.exe registry hijack"),
    ("public-roguepotato", "privesc_roguepotato_sysmon_17_18.evtx", "RoguePotato token impersonation (SeImpersonate to SYSTEM)"),
    ("public-uacme-56", "Sysmon_UACME_56.evtx", "UACME method 56 (WSReset) — elevation through a binary CPES does not list"),
]
for _id, _file, _what in PUBLIC_SAMPLES:
    BUILTIN.append({
        "id": _id,
        "name": f"Public sample: {_what}",
        "path": f"external/evtx-attack-samples/privesc/{_file}",
        "format": "evtx",
        "category": "public_dataset",
        "source": "EVTX-ATTACK-SAMPLES (github.com/sbousseaden, commit 4ceed2f), GPL-3.0. A published attack capture from a different machine; never used to build CPES.",
        "contents": _what,
        "ground_truth": {"available": False, "unit": "file", "source": None, "how": "The whole file is a published attack sample; there is no per-record label."},
        "private": False,
        "notes": "Fetched by scripts/fetch_external.py into external/ (not committed). Raw Windows event log records.",
        "suggested_mapping": {"preset": "evtx-sysmon-field-mapping-v1"},
        "experiments": ["pkg_ext_evtx", "pkg_sigma_ext"],
    })

ARTIFACTS: list[dict[str, Any]] = [
    {"name": "Labelled process-instance feature table", "path": "Claude outputs/cpes_privilege_escalation_dataset.csv", "category": "derived_labels", "description": "2,161 rows (87 attack, 2,074 benign) with four signal flags and labels, derived from corpus-v3. Source of the frozen evidence model and of corpus-v3 ground truth."},
    {"name": "Atomic execution ledger v3", "path": "analysis/cpes-atomic-log-v3.csv", "category": "ground_truth_source", "description": "126 logged Atomic Red Team executions (time, technique, test). Used by the research labelling."},
    {"name": "Atomic execution ledger (combined)", "path": "analysis/cpes-atomic-log-combined.csv", "category": "ground_truth_source", "description": "100 logged executions for the combined corpus."},
    {"name": "Corpus archive v1", "path": "cpes-corpus.zip", "category": "archive", "description": "Zipped Elasticsearch export + ledger. Not loaded by the dashboard."},
    {"name": "Corpus archive v2", "path": "cpes-corpus-v2.zip", "category": "archive", "description": "Zipped export + ledger. Not loaded."},
    {"name": "Corpus archive v3", "path": "cpes-corpus-v3.zip", "category": "archive", "description": "Zipped export of the frozen v3 corpus. Not loaded (the extracted copy is lab-corpus-v3)."},
    {"name": "Corpus archive v4 (expansion)", "path": "cpes-corpus-v4.zip", "category": "archive", "description": "1.1 GB expansion export used by corpus_eval_v4.py. Not extracted, so that script cannot run here."},
]


class DatasetStore:
    """Registry of built-in and uploaded datasets, with a small parse cache."""

    def __init__(self, cache_size: int = 2) -> None:
        self._cache: OrderedDict[str, tuple[ParsedDataset, DatasetIndex]] = OrderedDict()
        self._cache_size = cache_size

    @property
    def uploads_dir(self) -> Path:
        return data_root() / "datasets"

    def _builtin_meta(self, entry: dict[str, Any]) -> dict[str, Any]:
        path = REPO_ROOT / entry["path"]
        meta = dict(entry)
        meta["origin"] = "builtin"
        meta["available"] = path.exists()
        meta["size_bytes"] = path.stat().st_size if path.exists() else None
        cached = read_json(self._sidecar(entry["id"]) / "meta-cache.json", {}) or {}
        if path.exists() and cached.get("mtime") == path.stat().st_mtime:
            meta.update({k: cached[k] for k in ("sha256", "records", "summary") if k in cached})
        return meta

    def _sidecar(self, dataset_id: str) -> Path:
        return data_root() / "builtin" / dataset_id

    def list(self) -> list[dict[str, Any]]:
        items = [self._builtin_meta(entry) for entry in BUILTIN]
        if self.uploads_dir.exists():
            uploads = [meta for directory in self.uploads_dir.iterdir() if (meta := read_json(directory / "meta.json"))]
            items.extend(sorted(uploads, key=lambda meta: (meta.get("uploaded_ns", 0), meta["id"]), reverse=True))
        for item in items:
            item["validation"] = self._validation_summary(item["id"])
        return items

    def meta(self, dataset_id: str) -> dict[str, Any]:
        for entry in BUILTIN:
            if entry["id"] == dataset_id:
                return self._builtin_meta(entry)
        meta = read_json(self.uploads_dir / dataset_id / "meta.json")
        if meta is None:
            raise KeyError(dataset_id)
        return meta

    def path(self, dataset_id: str) -> Path:
        meta = self.meta(dataset_id)
        if meta["origin"] == "builtin":
            return REPO_ROOT / meta["path"]
        return self.uploads_dir / dataset_id / meta["stored_file"]

    def state_dir(self, dataset_id: str) -> Path:
        meta = self.meta(dataset_id)
        return self._sidecar(dataset_id) if meta["origin"] == "builtin" else self.uploads_dir / dataset_id

    def load(self, dataset_id: str) -> tuple[ParsedDataset, DatasetIndex]:
        with _lock:
            if dataset_id in self._cache:
                self._cache.move_to_end(dataset_id)
                return self._cache[dataset_id]
            meta = self.meta(dataset_id)
            path = self.path(dataset_id)
            if not path.exists():
                raise FileNotFoundError(f"dataset file is not present locally: {meta.get('path') or path.name}")
            parsed = parse_file(path, meta["format"])
            index = DatasetIndex(parsed)
            self._cache[dataset_id] = (parsed, index)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
            if meta["origin"] == "builtin":
                write_json(self._sidecar(dataset_id) / "meta-cache.json", {
                    "mtime": path.stat().st_mtime,
                    "sha256": sha256_file(path),
                    "records": len(parsed),
                    "summary": {"parse_errors": len(parsed.parse_errors), "blank_lines": parsed.blank_lines},
                })
            return parsed, index

    def upload(self, filename: str, data: bytes, fmt: str, *, name: str | None, declared_source: str | None, declared_synthetic: bool) -> dict[str, Any]:
        dataset_id = new_id("upload")
        directory = self.uploads_dir / dataset_id
        directory.mkdir(parents=True)
        stored = f"original{Path(filename).suffix.lower()}"
        (directory / stored).write_bytes(data)
        meta = {
            "id": dataset_id,
            "origin": "upload",
            "name": name or filename,
            "original_filename": filename,
            "stored_file": stored,
            "format": fmt,
            "size_bytes": len(data),
            "sha256": sha256_file(directory / stored),
            "uploaded_at": now(),
            "uploaded_ns": time.time_ns(),
            "category": "synthetic" if declared_synthetic else "user_upload",
            **({"suggested_mapping": {"preset": DEFAULT_PRESET_BY_FORMAT[fmt]}} if fmt in DEFAULT_PRESET_BY_FORMAT else {}),
            "source": declared_source or "Declared by uploader: not provided.",
            "ground_truth": {"available": False, "unit": None, "source": None, "how": "Uploads carry no ground truth in this version; metrics that need labels are not computed."},
            "private": True,
            "available": True,
            "experiments": [],
        }
        write_json(directory / "meta.json", meta)
        parsed, _ = self.load(dataset_id)
        meta["records"] = len(parsed)
        meta["summary"] = {"parse_errors": len(parsed.parse_errors), "blank_lines": parsed.blank_lines}
        write_json(directory / "meta.json", meta)
        return meta

    def delete_upload(self, dataset_id: str) -> None:
        meta = self.meta(dataset_id)
        if meta["origin"] != "upload":
            raise ValueError("built-in datasets cannot be deleted.")
        with _lock:
            self._cache.pop(dataset_id, None)
        shutil.rmtree(self.uploads_dir / dataset_id)

    # -- validation cache --------------------------------------------------------
    def validation(self, dataset_id: str, spec: dict[str, Any] | None, key: str) -> dict[str, Any]:
        directory = self.state_dir(dataset_id) / "validation"
        cached = read_json(directory / f"{key}.json")
        meta = self.meta(dataset_id)
        if cached and cached.get("dataset_sha256") == meta.get("sha256"):
            return cached
        parsed, _ = self.load(dataset_id)
        meta = self.meta(dataset_id)
        report = validate(parsed, spec)
        report["dataset_id"] = dataset_id
        report["dataset_sha256"] = meta.get("sha256")
        write_json(directory / f"{key}.json", report)
        write_json(self.state_dir(dataset_id) / "last-validation.json", {k: report.get(k) for k in ("status", "accepted", "rejected", "parse_error_count", "computed_at", "mapping")})
        return report

    def _validation_summary(self, dataset_id: str) -> dict[str, Any] | None:
        try:
            return read_json(self.state_dir(dataset_id) / "last-validation.json")
        except KeyError:
            return None
