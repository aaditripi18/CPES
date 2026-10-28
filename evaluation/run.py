"""Run one or more evaluation protocols and record them.

    python -m evaluation.run research-grouped package-grouped ...
    python -m evaluation.run all

Each execution appends one line to results/ledger.jsonl and overwrites
results/<protocol>.json with the latest full output (the ledger keeps history).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import time
from datetime import datetime, timezone

from . import data, engine, protocols

RESULTS = data.ROOT / "results"
PROTOCOLS = ("research-grouped", "package-grouped", "package-grouped-noevidence", "ea-chain-grouped", "ec-ledger-time", "ext-evtx-privesc", "evasion-v3", "stream-replay-v3", "sigma-lab-v3", "sigma-ext-evtx", "sigma-evasion", "heldout-otrf-v2", "incidents-lab-v3", "service-signature-v1", "vm-live-v1", "package-v3-dev", "vm2")


def _code_fingerprint() -> str:
    digest = hashlib.sha256()
    for path in sorted([*(data.ROOT / "evaluation").glob("*.py"), *(data.ROOT / "cpes").rglob("*.py")]):
        digest.update(path.relative_to(data.ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _git() -> dict:
    def call(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], cwd=data.ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    return {"commit": call("rev-parse", "HEAD") or None, "dirty": bool(call("status", "--porcelain", "--", "cpes", "evaluation", "configs"))}


_engine_cache: dict[bool, dict] = {}


def _package(with_evidence: bool) -> dict:
    if with_evidence not in _engine_cache:
        _engine_cache[with_evidence] = engine.run_package(with_evidence=with_evidence)
    return _engine_cache[with_evidence]


def _outside_units(flags: dict[str, tuple[str, ...]], window_flags: dict[str, int]) -> dict:
    """Signals that fired on processes which are not evaluation units.

    Units are processes with a ProcessCreate record inside the capture. A process
    that started earlier (e.g. csrss.exe) can still be the anchor of an alert,
    which the unit-level metrics never count. Reported so that blind spot is visible.
    """

    unit_guids = {u.guid for u in data.units()}
    images: dict[str, str] = {}
    for document in data.documents():
        process = document.get("process") or {}
        guid = process.get("entity_id")
        if guid and guid not in images and process.get("executable"):
            images[guid] = process["executable"].replace("/", "\\").split("\\")[-1].lower()
    outside = {guid: signals for guid, signals in flags.items() if guid not in unit_guids}
    by_signal: dict[str, dict[str, int]] = {}
    for guid, signals in outside.items():
        for signal in signals:
            bucket = by_signal.setdefault(signal, {})
            bucket[images.get(guid, "unknown")] = bucket.get(images.get(guid, "unknown"), 0) + 1
    return {
        "processes": len(outside),
        "by_signal_and_image": by_signal,
        "windows_with_signal_anchored_only_outside_units": {signal: count for signal, count in window_flags.items() if count},
    }


def run_protocol(name: str) -> dict:
    research_flags = {u.guid: u.research_signals for u in data.units()}
    baselines = data.research_baselines()
    if name == "research-grouped":
        result = protocols.grouped_cv(data.research_group, lambda u: u.research_signals, {"single_event_research": baselines["single_event_research"], "ioc_signature_research": baselines["ioc_signature_research"]})
        result["note"] = "Replication of analysis/corpus_eval_grouped.py; must equal its printed figures."
        return result
    if name in ("package-grouped", "package-grouped-noevidence"):
        package = _package(name == "package-grouped")
        flags = package["flags"]
        result = protocols.grouped_cv(data.research_group, lambda u: flags.get(u.guid, ()), {"single_event_package": package["single_event_package"], "ioc_signature_research": baselines["ioc_signature_research"]})
        result["engine"] = {k: package[k] for k in ("windows", "evidence", "settings")}
        result["signal_firings_on_units"] = {s: {"attack": sum(1 for u in data.units() if u.is_attack and s in flags.get(u.guid, ())), "benign": sum(1 for u in data.units() if not u.is_attack and s in flags.get(u.guid, ()))} for s in data.SIGNALS}
        unit_guids = {u.guid for u in data.units()}
        window_flags: dict[str, int] = {}
        for signal, anchors in package["window_anchors"]:
            if anchors and not any(guid in unit_guids for guid in anchors):
                window_flags[signal] = window_flags.get(signal, 0) + 1
        result["flags_outside_units"] = _outside_units(flags, window_flags)
        return result
    if name == "ea-chain-grouped":
        chain_of = _package(False)["chain_of"]
        group = lambda u: data.research_group(u) if u.is_attack else "chain_" + (chain_of.get(u.guid) or u.guid)  # noqa: E731
        result = protocols.grouped_cv(group, lambda u: u.research_signals, {"single_event_research": baselines["single_event_research"], "ioc_signature_research": baselines["ioc_signature_research"]})
        result["note"] = "E-a: benign units grouped by lineage chain (cpes.lineage) instead of one group per process."
        result["benign_groups"] = len({group(u) for u in data.units() if not u.is_attack})
        return result
    if name == "ec-ledger-time":
        package = _package(True)
        return protocols.ledger_time({
            "cpes_research_signals": research_flags,
            "ioc_signature_research": {g: ("ioc",) for g in baselines["ioc_signature_research"]},
            "single_event_research": {g: ("integrity_edge",) for g in baselines["single_event_research"]},
            "cpes_package_with_evidence": package["flags"],
            "single_event_package": {g: ("integrity_edge",) for g in package["single_event_package"]},
        }) | {"note": "E-c: unit = logged run; CPES decision = OR of signals (every research weight exceeds the 0.50 threshold)."}
    if name == "ext-evtx-privesc":
        from . import external

        return external.run()
    if name == "evasion-v3":
        from . import evasion

        return evasion.run()
    if name in ("sigma-lab-v3", "sigma-ext-evtx", "sigma-evasion"):
        from . import sigma_eval

        return {"sigma-lab-v3": sigma_eval.run_lab, "sigma-ext-evtx": sigma_eval.run_external, "sigma-evasion": sigma_eval.run_evasion}[name]()
    if name == "heldout-otrf-v2":
        from . import heldout

        return heldout.run()
    if name == "incidents-lab-v3":
        from . import incidents_eval

        return incidents_eval.run()
    if name == "service-signature-v1":
        from . import service_signature

        return service_signature.run()
    if name == "vm-live-v1":
        from . import vm_live

        return vm_live.run()
    if name == "package-v3-dev":
        from . import package_v3

        return package_v3.run()
    if name == "vm2":
        from . import vm2

        return vm2.run()
    if name == "stream-replay-v3":
        from . import streaming_eval

        return streaming_eval.run()
    raise ValueError(f"unknown protocol {name!r}; choose from {', '.join(PROTOCOLS)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("protocols", nargs="+", help=f"{', '.join(PROTOCOLS)} or all")
    args = parser.parse_args()
    names = PROTOCOLS if args.protocols == ["all"] else tuple(args.protocols)
    RESULTS.mkdir(exist_ok=True)
    for name in names:
        if name.startswith("ext-") or name == "sigma-ext-evtx":
            from . import external

            inputs = external.verify_manifest()
        elif name == "heldout-otrf-v2":
            from . import heldout

            inputs = heldout.verify_manifest()
        elif name == "service-signature-v1":
            from . import external, service_signature

            inputs = [{"path": f"external/otrf/test/{n}"} for n in service_signature.verify_test_manifest()] + external.verify_manifest() + data.inputs_manifest()
        elif name == "vm-live-v1":
            from . import external, vm_live

            inputs = vm_live.inputs_manifest() + external.verify_manifest()
        elif name == "package-v3-dev":
            from . import external, vm_live

            inputs = data.inputs_manifest() + vm_live.inputs_manifest() + external.verify_manifest()
        elif name == "vm2":
            from . import external, vm2

            inputs = vm2.inputs_manifest() + external.verify_manifest()
        else:
            inputs = data.inputs_manifest()
        started = time.perf_counter()
        result = run_protocol(name)
        record = {
            "id": f"{name}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}",
            "protocol": name,
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": round(time.perf_counter() - started, 2),
            "code_sha256": _code_fingerprint(),
            "git": _git(),
            "python": platform.python_version(),
            "inputs": inputs,
            "design": "docs/design/evidence-channels-and-package-evaluation.md",
        }
        (RESULTS / f"{name}.json").write_text(json.dumps({**record, "result": result}, indent=2, default=str) + "\n", encoding="utf-8")
        if "detectors" in result and "summary" not in result:
            summary = {d: v.get("fold_mean", {}).get("f1") if "fold_mean" in v else v.get("modelled_runs_detected_any") for d, v in result["detectors"].items()}
        else:
            summary = result.get("summary_by_category") or result.get("summary")
        with (RESULTS / "ledger.jsonl").open("a", encoding="utf-8") as ledger:
            ledger.write(json.dumps({**record, "summary": summary}, default=str) + "\n")
        print(f"{name}: {json.dumps(summary)}")


if __name__ == "__main__":
    main()
