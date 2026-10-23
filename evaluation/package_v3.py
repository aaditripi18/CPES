"""package-v3-dev: development checks of the package v3 modes on already-seen data.

Pre-registered in docs/design/package-v3-and-vm2.md ("Development checks"). These
are not tests of the changes; VM2 is. They show, before VM2, whether
``research-v3`` reproduces the research rules and what B1/B2 change.

* corpus-v3: per-unit flags of research-v3 vs the labelled research signals, and
  grouped CV for research-v3 and structural-v3.
* vm-live-v1: research-v3 vs R per created process; structural-v3 vs package-v2
  on service runs and false alarms; packaged B2 alone vs the protocol S2.
* EVTX-ATTACK-SAMPLES: service detections and outcomes, structural-v3 vs package-v2.
"""

from __future__ import annotations

import json
from collections import Counter

from . import data, engine, external, protocols, research_signals, vm_live
from .data import SIGNALS

VM_EXTRA_MODE = "service-install-only"  # B2 alone, for the comparison with the protocol S2
engine.MODES.setdefault(VM_EXTRA_MODE, {"require_service_install": True})


def _flag_diff(left: dict, right: dict, guids) -> dict:
    out = Counter()
    for guid in guids:
        a, b = set(left.get(guid, ())), set(right.get(guid, ()))
        for signal in a - b:
            out[f"{signal}: research only"] += 1
        for signal in b - a:
            out[f"{signal}: research-v3 only"] += 1
    return dict(out)


def _cv(flags: dict) -> dict:
    result = protocols.grouped_cv(data.research_group, lambda u: flags.get(u.guid, ()), {})
    cpes = result["detectors"]["cpes"]
    return {"f1_mean": cpes["fold_mean"]["f1"], "fold_mean": cpes["fold_mean"], "fold_std": cpes.get("fold_std"), "recall_by_technique": cpes["recall_by_technique"]}


def lab() -> dict:
    research = {u.guid: u.research_signals for u in data.units()}
    unit_guids = [u.guid for u in data.units()]
    out = {}
    for mode in ("research-v3", "structural-v3"):
        flags = engine.run_package(with_evidence=True, mode=mode)["flags"]
        row = {"cv": _cv(flags), "flag_differences_vs_research": _flag_diff(research, flags, unit_guids)}
        row["benign_units_with_service_flag"] = sum(1 for u in data.units() if not u.is_attack and "service_dropped_binary" in flags.get(u.guid, ()))
        out[mode] = row
    current = engine.run_package(with_evidence=True)["flags"]
    out["package-v2_benign_units_with_service_flag"] = sum(1 for u in data.units() if not u.is_attack and "service_dropped_binary" in current.get(u.guid, ()))
    out["research_identical"] = not out["research-v3"]["flag_differences_vs_research"]
    return out


def _vm_docs() -> tuple[list, list]:
    """Process, pipe and thread records, resolver-relevant registry records and service installs."""

    tokens = tuple(t.lower() for t in (*engine.RESOLVER_SETTINGS["hijack_registry_tokens"], *engine.RESOLVER_SETTINGS["service_registry_tokens"]))
    process, package = [], []
    with vm_live.CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            d = json.loads(line)
            channel, code = vm_live._get(d, "winlog", "channel"), str(vm_live._get(d, "event", "code"))
            if (channel, code) in vm_live.INSTALL_CODES:
                package.append(d)
            elif channel == vm_live.SYSMON and code in vm_live.PROCESS_CODES:
                process.append(d)
                package.append(d)
            elif channel == vm_live.SYSMON and code in vm_live.REGISTRY_CODES and any(t in (vm_live._get(d, "registry", "path") or "").lower() for t in tokens):
                package.append(d)
    return vm_live._sorted(process), vm_live._sorted(package)


def vm() -> dict:
    process, package_docs = _vm_docs()
    nodes = research_signals.nodes(process)
    created = {}
    for d in process:
        if str(d["event"]["code"]) == "1" and d.get("process", {}).get("entity_id"):
            created.setdefault(d["process"]["entity_id"], vm_live._ts(d["@timestamp"]))
    runs = vm_live.runs()
    research = research_signals.signal_flags(process)
    flags = {mode: engine.run_package(with_evidence=True, docs=package_docs, mode=mode)["flags"] for mode in ("package-v2", "research-v3", "structural-v3", VM_EXTRA_MODE)}
    service_runs = [r for r in runs if r.technique == "T1543.003"]

    def service_summary(f: dict) -> dict:
        s = {g: ("service_dropped_binary",) for g, sig in f.items() if "service_dropped_binary" in sig}
        level = vm_live.run_level(s, created, service_runs, with_semantics=True)
        alarms = vm_live.run_level(s, created, runs, with_semantics=True)["_false_alarms"]
        return {"service_runs_detected": level["runs_consistent"], "false_alarm_processes": len(alarms),
                "false_alarm_images": dict(Counter(nodes[g].image for g in alarms if g in nodes))}

    levels = {mode: {k: v for k, v in vm_live.run_level(f, created, runs, with_semantics=True).items() if not k.startswith("_")} for mode, f in flags.items()}
    return {
        "research_v3_vs_R": _flag_diff(research, flags["research-v3"], list(created)),
        "research_identical": not _flag_diff(research, flags["research-v3"], list(created)),
        "run_level": levels,
        "service": {mode: service_summary(f) for mode, f in flags.items()},
        "note": f"'{VM_EXTRA_MODE}' is B2 alone (no parent check), compared with the protocol S2 in results/vm-live-v1.json "
                "(P: service runs 10 -> 10, false-alarm processes 4 -> 0).",
    }


def evtx() -> dict:
    inputs = external.verify_manifest()
    out = {}
    for mode in ("package-v2", "structural-v3"):
        rows = [external.evaluate_file(external.SAMPLES / item["path"].split("/")[-1], mode=mode) for item in inputs]
        out[mode] = {
            "files_detected": sum(r.get("outcome") == "detected" for r in rows),
            "files_with_service_signal": sorted(r["file"] for r in rows if "service_dropped_binary" in r.get("cpes_signals", {})),
        }
    lost = sorted(set(out["package-v2"]["files_with_service_signal"]) - set(out["structural-v3"]["files_with_service_signal"]))
    out["service_files_lost_by_B1"] = lost
    return out


def run() -> dict:
    lab_result, vm_result, evtx_result = lab(), vm(), evtx()
    return {
        "corpus_v3": lab_result,
        "vm_live_v1": vm_result,
        "evtx_attack_samples": evtx_result,
        "summary": {
            "research_v3_identical_lab": lab_result["research_identical"],
            "research_v3_identical_vm": vm_result["research_identical"],
            "research_v3_lab_f1": lab_result["research-v3"]["cv"]["f1_mean"],
            "structural_v3_lab_f1": lab_result["structural-v3"]["cv"]["f1_mean"],
            "evtx_service_files_lost_by_B1": len(evtx_result["service_files_lost_by_B1"]),
        },
    }
