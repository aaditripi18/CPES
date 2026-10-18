"""Reproduce the recorded research experiments by running ``analysis/`` scripts unchanged.

Each execution gets its own directory with stdout, stderr, exit code, duration,
and SHA-256 of the script and every input file, so a figure on screen can be
traced to the exact bytes that produced it. Parsing only extracts numbers that
the script itself printed; nothing is recomputed here.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from typing import Any

from .ingest import sha256_file
from .paths import ANALYSIS, REPO_ROOT, data_root
from .runner import git_state
from .storage import new_id, now, read_json, write_json

CATALOG: list[dict[str, Any]] = [
    {
        "id": "grouped_cv",
        "script": "analysis/corpus_eval_grouped.py",
        "title": "Grouped 5-fold CV — all three detectors",
        "protocol": "process instance · 5 folds grouped by attack run · weights re-derived on each training fold · threshold 0.50 · mean ± std over folds",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "canonical",
        "role_note": "Named canonical in docs/CPES-Friend-Reply-2026-09-06.md and the paper hand-off.",
        "parser": "detector_table",
    },
    {
        "id": "ungrouped_cv_v3",
        "script": "analysis/corpus_eval_v3.py",
        "title": "Ungrouped 5-fold CV + pooled confusion (v3)",
        "protocol": "process instance · 5 folds, not grouped by run · token signal design ablation (old heuristic vs pipe-grounded)",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "supporting",
        "role_note": "Source of the README headline (0.995 / 0.519 / 0.736). The docs call these supporting, not headline, figures.",
        "parser": "v3_table",
        "needs_package": True,
    },
    {
        "id": "independent_channel",
        "script": "analysis/corpus_eval_independent.py",
        "title": "Non-circular recall (label channel ≠ signal channel)",
        "protocol": "run level · detonation confirmed from channels CPES does not score · injection has no independent channel",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "validity_check",
        "parser": None,
    },
    {
        "id": "generic_ablation",
        "script": "analysis/corpus_eval_generic.py",
        "title": "Generic 'unexplained privilege gain' with each specific signal held out",
        "protocol": "process instance · ablation, no CV",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "ablation",
        "parser": None,
    },
    {
        "id": "partial_evidence",
        "script": "analysis/corpus_eval_partial.py",
        "title": "Weight-of-evidence vs plain OR with a weak signal",
        "protocol": "process instance · in-sample · different label set (79 attack)",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "ablation",
        "parser": None,
    },
    {
        "id": "robustness",
        "script": "analysis/corpus_eval_robustness.py",
        "title": "Robustness: grouped CV, leave-one-technique-out, OR vs WoE, base rate, learned baseline",
        "protocol": "process instance · several protocols in one script (see output)",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "robustness",
        "parser": None,
        "needs_package": True,
    },
    {
        "id": "provenance",
        "script": "analysis/corpus_eval_provenance.py",
        "title": "Provenance-labelled run-level detection (combined corpus)",
        "protocol": "run level · labels from runner-root provenance, independent of CPES features · 5-fold by run id",
        "dataset": "lab-corpus-combined",
        "inputs": ["analysis/corpus-combined.ndjson", "analysis/cpes-atomic-log-combined.csv"],
        "role": "adverse_result",
        "role_note": "Much lower recall than the v3 figures (CPES F1 ≈ 0.5). Not in the README; shown here so it is not hidden.",
        "parser": "provenance_table",
        "needs_package": True,
    },
    {
        "id": "expansion_v4",
        "script": "analysis/corpus_eval_v4.py",
        "title": "Expansion corpus (v4) checks",
        "protocol": "see script",
        "dataset": None,
        "inputs": ["analysis/corpus-v4.ndjson"],
        "role": "unavailable",
        "role_note": "Needs analysis/corpus-v4.ndjson, which exists only inside cpes-corpus-v4.zip (1.1 GB). Not runnable until extracted.",
        "parser": None,
    },
    {
        "id": "pkg_research_grouped",
        "module": "evaluation.run",
        "script": "evaluation/run.py",
        "args": ["research-grouped"],
        "title": "Versioned replication of the grouped CV",
        "protocol": "process instance · grouped 5-fold · weights via cpes.derivation · must equal corpus_eval_grouped.py",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "validity_check",
        "role_note": "Validates the versioned fold code before any package result is trusted.",
        "parser": "results_json",
    },
    {
        "id": "pkg_package_grouped",
        "module": "evaluation.run",
        "script": "evaluation/run.py",
        "args": ["package-grouped"],
        "title": "Package engine (CpesPipeline + evidence channels), grouped CV",
        "protocol": "process instance · signals observed by cpes.CpesPipeline · same folds and labels as the research protocol",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "adverse_result",
        "role_note": "Pre-registered in docs/design/evidence-channels-and-package-evaluation.md. Lower than the research figure for reasons stated there.",
        "parser": "results_json",
    },
    {
        "id": "pkg_ea_chain_grouped",
        "module": "evaluation.run",
        "script": "evaluation/run.py",
        "args": ["ea-chain-grouped"],
        "title": "E-a: benign units grouped by lineage chain",
        "protocol": "process instance · grouped 5-fold, benign groups = lineage chains",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "robustness",
        "parser": "results_json",
    },
    {
        "id": "pkg_ec_ledger_time",
        "module": "evaluation.run",
        "script": "evaluation/run.py",
        "args": ["ec-ledger-time"],
        "title": "E-c: run-level detection, labels from the execution ledger only",
        "protocol": "logged run · detected if a flagged process is within ±150 s · technique-consistent variant · no fitting",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "validity_check",
        "parser": "results_json",
    },
    {
        "id": "pkg_ext_evtx",
        "module": "evaluation.run",
        "script": "evaluation/external.py",
        "args": ["ext-evtx-privesc"],
        "title": "External generalisation: EVTX-ATTACK-SAMPLES (53 public Sysmon captures)",
        "protocol": "sample file · shipped package engine · weights frozen from the lab corpus (held out) · per-file alerts with anchors",
        "dataset": None,
        "inputs": ["configs/external-datasets.json", "external/evtx-attack-samples/privesc"],
        "role": "validity_check",
        "role_note": "Never-seen attacks from other machines. Run `python scripts/fetch_external.py` first.",
        "parser": "results_json",
    },
    {
        "id": "pkg_evasion",
        "module": "evaluation.run",
        "script": "evaluation/evasion.py",
        "args": ["evasion-v3"],
        "title": "Evasion robustness: renamed tools, unlisted binaries, random pipes, obfuscated command lines",
        "protocol": "corpus-v3 variants V0–V5 (attack records only) · research signals, package engine, generic test, IOC, single-event",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "robustness",
        "parser": "results_json",
    },
    {
        "id": "pkg_stream",
        "module": "evaluation.run",
        "script": "evaluation/streaming_eval.py",
        "args": ["stream-replay-v3"],
        "title": "Live scoring: replay as a stream, live-vs-hindsight agreement, time to alert",
        "protocol": "cpes.streaming.StreamingScorer · window 300 s / advance 150 s · 30 s watermark ticks",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"],
        "role": "validity_check",
        "parser": "results_json",
    },
    {
        "id": "pkg_sigma_lab",
        "module": "evaluation.run",
        "script": "evaluation/sigma_eval.py",
        "args": ["sigma-lab-v3"],
        "title": "CPES vs SigmaHQ rules on the lab corpus (run level, alert noise)",
        "protocol": "SigmaHQ r2026-07-01 core and all packs · ledger-time labels · alerts outside attack runs",
        "dataset": "lab-corpus-v3",
        "inputs": [*["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"], "external/sigma"],
        "role": "adverse_result",
        "role_note": "Sigma detects more attack runs than CPES on this corpus; reported as is.",
        "parser": "results_json",
    },
    {
        "id": "pkg_sigma_ext",
        "module": "evaluation.run",
        "script": "evaluation/sigma_eval.py",
        "args": ["sigma-ext-evtx"],
        "title": "CPES vs SigmaHQ rules on EVTX-ATTACK-SAMPLES",
        "protocol": "per sample file · Sigma core high+ and all any-level",
        "dataset": None,
        "inputs": [*["configs/external-datasets.json", "external/evtx-attack-samples/privesc"], "external/sigma"],
        "role": "adverse_result",
        "parser": "results_json",
    },
    {
        "id": "pkg_sigma_evasion",
        "module": "evaluation.run",
        "script": "evaluation/sigma_eval.py",
        "args": ["sigma-evasion"],
        "title": "Sigma on the evasion variants (V0, V1, V3)",
        "protocol": "run level and outcome-process level, core and all packs",
        "dataset": "lab-corpus-v3",
        "inputs": [*["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv", "Claude outputs/cpes_privilege_escalation_dataset.csv"], "external/sigma"],
        "role": "robustness",
        "parser": "results_json",
    },
    {
        "id": "standalone_demo",
        "script": "demo/cpes_demo.py",
        "args": ["--no-color"],
        "cwd": "demo",
        "title": "Standalone live demo (pooled, in-sample)",
        "protocol": "process instance · weights estimated on the whole corpus · pooled confusion (no CV)",
        "dataset": "lab-corpus-v3",
        "inputs": ["analysis/corpus-v3.ndjson", "analysis/cpes-atomic-log-v3.csv"],
        "role": "demo",
        "role_note": "Prints pooled in-sample figures; section 7 'Extended validation' prints fixed text from the v4 analysis rather than computing it.",
        "parser": "demo_table",
    },
]

# README statements and where they come from. "expected" is what the README says.
PUBLISHED_CLAIMS = [
    {"claim": "CPES precision (README)", "expected": 0.989, "experiment": "ungrouped_cv_v3", "metric": ("CPES sharp token-pipe", "precision")},
    {"claim": "CPES recall (README)", "expected": 1.000, "experiment": "ungrouped_cv_v3", "metric": ("CPES sharp token-pipe", "recall")},
    {"claim": "CPES F1 (README)", "expected": 0.995, "experiment": "ungrouped_cv_v3", "metric": ("CPES sharp token-pipe", "f1")},
    {"claim": "Single-event baseline F1 (README)", "expected": 0.519, "experiment": "ungrouped_cv_v3", "metric": ("baseline1 (integrity edge)", "f1")},
    {"claim": "Signature baseline F1 (README)", "expected": 0.736, "experiment": "ungrouped_cv_v3", "metric": ("baseline2 (IOC/signature)", "f1")},
    {"claim": "CPES F1, grouped CV (paper hand-off, canonical)", "expected": 0.993, "experiment": "grouped_cv", "metric": ("CPES (context WoE)", "f1")},
    {"claim": "Single-event F1, grouped CV (canonical)", "expected": 0.551, "experiment": "grouped_cv", "metric": ("Single-event (integrity)", "f1")},
    {"claim": "IOC/signature F1, grouped CV (canonical)", "expected": 0.705, "experiment": "grouped_cv", "metric": ("IOC / signature", "f1")},
]

# Findings of the dashboard's review of the evaluation scripts. These are
# concerns, not changes: the published method is untouched, and corrective
# experiments are proposed in docs/dashboard/EVALUATION-NOTES.md.
METHOD_NOTES = [
    {"topic": "Label construction", "severity": "high", "where": "corpus_eval_grouped.py, corpus_eval_v3.py, demo/cpes_demo.py",
     "finding": "A process is labelled an attack only if one of the four CPES signals fires within 150 s of a logged Atomic execution, so CPES recall is 1.0 by construction.",
     "mitigation_in_repo": "Tested by E-c (labels from ledger times only): research CPES flags a technique-consistent process in 98/126 runs with one false alarm. See docs/RESULTS.md."},
    {"topic": "Grouping of benign units", "severity": "low", "where": "corpus_eval_grouped.py",
     "finding": "Every benign process was its own CV group.",
     "mitigation_in_repo": "Tested by E-a (benign groups = lineage chains): no measurable effect (CPES F1 0.996 vs 0.993)."},
    {"topic": "Fold aggregation", "severity": "low", "where": "corpus_eval_grouped.py, corpus_eval_v3.py",
     "finding": "Folds without an attack are skipped; precision with no positive call is 1.0; figures are fold means.",
     "mitigation_in_repo": "Versioned protocols report fold mean ± sd, pooled confusion and skipped folds (0)."},
    {"topic": "Two engines", "severity": "high", "where": "analysis/ vs cpes/",
     "finding": "Published metrics come from stdlib scripts; the package engine with evidence channels reaches grouped-CV F1 0.684 on the same folds.",
     "mitigation_in_repo": "Measured and pre-registered: docs/design/evidence-channels-and-package-evaluation.md, docs/RESULTS.md."},
    {"topic": "Injection signal is an image IOC", "severity": "high", "where": "corpus_eval_grouped.py (remote_thread_injection)",
     "finding": "corpus-v3 has no CreateRemoteThread from mavinject.exe; the research signal fires on image == mavinject.exe, the same rule the IOC baseline uses. The package, which observes real remote threads, finds none of the 18 injections.",
     "mitigation_in_repo": "Open: wording in the paper should reflect this."},
    {"topic": "Service rule differs between engines", "severity": "medium", "where": "cpes/context/resolver.py vs research signal 520",
     "finding": "The package rule omits parent = services.exe; all 12 benign package flags (MpCmdRun.exe, winlogbeat.exe) come from it.",
     "mitigation_in_repo": "Open decision; found after seeing results, so any alignment must be reported as post hoc and confirmed on new data."},
    {"topic": "Unit blind spot", "severity": "medium", "where": "process-instance unit definition",
     "finding": "Processes without a ProcessCreate in the capture are not units, so alerts anchored on them are never counted (35 csrss/dwm remote-thread windows in the package run).",
     "mitigation_in_repo": "Now counted and printed in docs/RESULTS.md."},
    {"topic": "Adverse result", "severity": "medium", "where": "corpus_eval_provenance.py",
     "finding": "Provenance-labelled run-level evaluation gives CPES F1 ≈ 0.5 (lineage provenance loses re-parented outcomes).",
     "mitigation_in_repo": "Reported in the README and the experiment catalog."},
    {"topic": "Weighting adds nothing measurable", "severity": "info", "where": "corpus_eval_robustness.py",
     "finding": "On this corpus weight-of-evidence and a plain OR of the four signals give identical results, and a learned logistic regression on the same signals matches CPES.",
     "mitigation_in_repo": "Stated by the script itself; corpus_eval_partial.py shows a case where weighting matters."},
]

_NUM = r"([0-9]+\.[0-9]+)"
_PM = r"[±�]|\+/-"


def parse_output(parser: str | None, stdout: str) -> dict[str, Any] | None:
    if parser is None:
        return None
    rows: dict[str, dict[str, float]] = {}
    if parser == "detector_table":
        pattern = re.compile(rf"^\s{{2}}(.+?)\s+{_NUM}(?:{_PM}){_NUM}\s+{_NUM}(?:{_PM}){_NUM}\s+{_NUM}(?:{_PM}){_NUM}\s+{_NUM}(?:{_PM}){_NUM}\s*$", re.M)
        for match in pattern.finditer(stdout):
            name = match.group(1).strip()
            values = [float(v) for v in match.groups()[1:]]
            rows[name] = {"precision": values[0], "precision_std": values[1], "recall": values[2], "recall_std": values[3], "fpr": values[4], "fpr_std": values[5], "f1": values[6], "f1_std": values[7]}
        header = re.search(r"units=(\d+) attack=(\d+) benign=(\d+)", stdout)
        units = {"units": int(header.group(1)), "attack": int(header.group(2)), "benign": int(header.group(3))} if header else None
        return {"detectors": rows, "units": units, "aggregation": "mean ± population std over folds"}
    if parser in ("v3_table", "provenance_table"):
        pattern = re.compile(rf"^\s{{2}}(.+?)\s+P={_NUM}(?:{_PM}){_NUM}\s+R={_NUM}(?:{_PM}){_NUM}\s+FPR={_NUM}(?:{_PM}){_NUM}\s+F1={_NUM}(?:{_PM}){_NUM}\s*$", re.M)
        for match in pattern.finditer(stdout):
            name = match.group(1).strip()
            values = [float(v) for v in match.groups()[1:]]
            rows[name] = {"precision": values[0], "precision_std": values[1], "recall": values[2], "recall_std": values[3], "fpr": values[4], "fpr_std": values[5], "f1": values[6], "f1_std": values[7]}
        pooled = {}
        for match in re.finditer(r"^\s{2}(.+?)\s+TP=(\d+) FP=(\d+) TN=(\d+) FN=(\d+)\s*$", stdout, re.M):
            pooled[match.group(1).strip()] = {"tp": int(match.group(2)), "fp": int(match.group(3)), "tn": int(match.group(4)), "fn": int(match.group(5))}
        return {"detectors": rows, "pooled_confusion": pooled or None, "aggregation": "mean ± population std over folds"}
    if parser == "demo_table":
        pattern = re.compile(rf"^\s+(Single-event \(integrity\)|IOC / signature rule|CPES \(context WoE\))\s+{_NUM}\s+{_NUM}\s+{_NUM}\s+{_NUM}\s+(\d+)/(\d+)/(\d+)\s*$", re.M)
        for match in pattern.finditer(stdout):
            p, r, fpr, f1 = (float(v) for v in match.groups()[1:5])
            tp, fp, fn = (int(v) for v in match.groups()[5:8])
            rows[match.group(1)] = {"precision": p, "recall": r, "fpr": fpr, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
        weights = {m.group(1): float(m.group(2)) for m in re.finditer(r"^\s+(autoelevation_lolbin|service_dropped_binary|remote_thread_injection|token_impersonation)\s+([+-][0-9.]+)", stdout, re.M)}
        return {"detectors": rows, "weights": weights, "aggregation": "pooled, in-sample"}
    return None


def parse_results_file(path) -> dict[str, Any] | None:
    """Read a versioned evaluation result (results/<protocol>.json) into the catalog shape."""

    import json

    if not path.exists():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    result = record["result"]
    detectors = {}
    for name, value in result.get("detectors", {}).items():
        if "fold_mean" in value:
            detectors[name] = {**value["fold_mean"], "tp": value["pooled"]["tp"], "fp": value["pooled"]["fp"], "fn": value["pooled"]["fn"]}
    return {"detectors": detectors, "aggregation": "mean ± population std over folds (pooled TP/FP/FN attached)" if detectors else "run level (see raw)", "results_id": record["id"], "code_sha256": record["code_sha256"], "raw": result}


def _input_record(path: str) -> dict[str, Any]:
    target = REPO_ROOT / path
    if target.is_dir():  # external datasets: each file is pinned in configs/external-datasets.json
        files = [f for f in target.rglob("*") if f.is_file()]
        return {"path": path, "sha256": None, "bytes": sum(f.stat().st_size for f in files), "note": f"directory of {len(files)} files, pinned by SHA-256 in configs/external-datasets.json"}
    return {"path": path, "sha256": sha256_file(target), "bytes": target.stat().st_size}


class ExperimentStore:
    @property
    def root(self):
        directory = data_root() / "experiments"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def catalog(self) -> list[dict[str, Any]]:
        items = []
        for entry in CATALOG:
            item = dict(entry)
            missing = [path for path in [entry["script"], *entry["inputs"]] if not (REPO_ROOT / path).exists()]
            item["runnable"] = not missing
            item["missing_inputs"] = missing
            latest = next((run for run in self.list() if run["experiment_id"] == entry["id"]), None)
            item["latest"] = latest
            items.append(item)
        return items

    def list(self) -> list[dict[str, Any]]:
        records = [record for directory in self.root.iterdir() if (record := read_json(directory / "record.json"))]
        records.sort(key=lambda record: (record.get("started_ns", 0), record["id"]), reverse=True)
        return [{k: v for k, v in record.items() if k not in ("stdout", "stderr")} for record in records]

    def get(self, execution_id: str) -> dict[str, Any]:
        record = read_json(self.root / execution_id / "record.json")
        if record is None:
            raise KeyError(execution_id)
        return record

    def start(self, experiment_id: str, *, background: bool = True) -> dict[str, Any]:
        entry = next((item for item in CATALOG if item["id"] == experiment_id), None)
        if entry is None:
            raise KeyError(experiment_id)
        missing = [path for path in [entry["script"], *entry["inputs"]] if not (REPO_ROOT / path).exists()]
        if missing:
            raise ValueError("cannot run: missing " + ", ".join(missing))
        execution_id = new_id("exp")
        record = {
            "id": execution_id,
            "experiment_id": experiment_id,
            "title": entry["title"],
            "script": entry["script"],
            "protocol": entry["protocol"],
            "role": entry["role"],
            "dataset": entry["dataset"],
            "state": "running",
            "started_at": now(),
            "started_ns": time.time_ns(),
            "kind": "research_experiment",
            "script_sha256": sha256_file(REPO_ROOT / entry["script"]),
            "inputs": [_input_record(path) for path in entry["inputs"]],
            "versions": {"python": sys.version.split()[0], **git_state()},
        }
        write_json(self.root / execution_id / "record.json", record)
        if background:
            threading.Thread(target=self._execute, args=(execution_id, entry), daemon=True).start()
        else:
            self._execute(execution_id, entry)
        return self.get(execution_id)

    def _execute(self, execution_id: str, entry: dict[str, Any]) -> None:
        path = self.root / execution_id / "record.json"
        record = read_json(path)
        environment = dict(os.environ)
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONPATH"] = str(REPO_ROOT)
        cwd = REPO_ROOT / entry.get("cwd", "analysis")
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                ([sys.executable, "-m", entry["module"]] if entry.get("module") else [sys.executable, str(REPO_ROOT / entry["script"])]) + list(entry.get("args", [])),
                cwd=REPO_ROOT if entry.get("module") else cwd, env=environment, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800,
            )
            record.update(exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr[-20000:])
            record["state"] = "completed" if completed.returncode == 0 else "failed"
        except subprocess.TimeoutExpired as error:
            record.update(state="failed", exit_code=None, stdout=error.stdout or "", stderr="timed out after 1800 s")
        record["duration_seconds"] = round(time.perf_counter() - started, 2)
        record["completed_at"] = now()
        if record["state"] != "completed":
            record["parsed"] = None
        elif entry.get("parser") == "results_json":
            record["parsed"] = parse_results_file(REPO_ROOT / "results" / f"{entry['args'][0]}.json")
        else:
            record["parsed"] = parse_output(entry.get("parser"), record.get("stdout", ""))
        write_json(path, record)

    def claims(self) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for run in self.list():
            if run["state"] == "completed" and run["experiment_id"] not in latest:
                latest[run["experiment_id"]] = run
        out = []
        for claim in PUBLISHED_CLAIMS:
            run = latest.get(claim["experiment"])
            detector, metric = claim["metric"]
            observed = None
            if run and run.get("parsed"):
                observed = (run["parsed"].get("detectors") or {}).get(detector, {}).get(metric)
            status = "not_reproduced_yet" if run is None else ("unparsed" if observed is None else ("matches" if abs(observed - claim["expected"]) < 0.0005 else "differs"))
            out.append({"claim": claim["claim"], "expected": claim["expected"], "experiment": claim["experiment"], "detector": detector, "metric": metric, "observed": observed, "status": status, "execution_id": run["id"] if run else None})
        return out
