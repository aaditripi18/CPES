"""vm3: frozen detectors on the VM3 session (docs/design/vm3-session.md).

A third live corpus, Windows 11 with Defender real-time protection off and the token
tests made to run offline, so that almost every run contains a completed escalation and
the token signal is exercised for the first time. Pre-registered before the session.

Detectors, labels and the mechanical "escalation completed" definition are unchanged from
VM2 (`evaluation.vm2`), which this module reuses directly; only the inputs, the
"binary absent" set (empty on Windows 11) and the hypotheses (W1-W6) differ.

Inputs are private (git-ignored ``lab-data/vm3/``). ``pilot()`` reports, for a one-round
dry-run corpus, whether each test completed an escalation; it is not a recorded result.
"""

from __future__ import annotations

import sys
from collections import Counter

from . import package_v3, research_signals, vm2, vm_live
from .data import ROOT, SIGNAL_TECHNIQUES, TOLERANCE_SECONDS
from .sigma import RuleSet
from .sigma_eval import LEVELS_HIGH, _lab_ruleset

LAB = ROOT / "lab-data" / "vm3"
CORPUS = LAB / "corpus.ndjson"
ATOMIC_LOG = LAB / "atomic-log.csv"
BENIGN_LOG = LAB / "benign-period.csv"
DEFENDER_DETECTIONS = LAB / "defender-detections.csv"
DEFENDER_THREATS = LAB / "defender-threats.csv"
PILOT_CORPUS = LAB / "pilot-corpus.ndjson"
PILOT_ATOMIC_LOG = LAB / "pilot-atomic-log.csv"
# Recorded in lab/vm-session/VM3-SETUP-NOTES.md at export; None until the session has run.
CORPUS_SHA256: str | None = None
# Windows 11 has every UAC binary; nothing is "binary absent" unless an amendment adds it.
ABSENT_TESTS: set[tuple[str, str]] = set()
MODES = vm2.MODES


def inputs_manifest() -> list[dict]:
    from .data import sha256

    paths = (CORPUS, ATOMIC_LOG, BENIGN_LOG, DEFENDER_DETECTIONS, DEFENDER_THREATS)
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"vm3 inputs missing from lab-data/vm3: {', '.join(missing)} (private; see lab/vm-session/VM3-RUNBOOK.md).")
    out = [{"path": str(p.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(p)} for p in paths]
    if CORPUS_SHA256 is None:
        raise ValueError("vm3.CORPUS_SHA256 is not set: record the export's SHA-256 before running the protocol.")
    if out[0]["sha256"] != CORPUS_SHA256:
        raise ValueError("lab-data/vm3/corpus.ndjson does not match the SHA-256 recorded at export.")
    return out


def runs():
    return vm2.runs(atomic_log=ATOMIC_LOG, defender=DEFENDER_DETECTIONS)


def _prepare(run_list, corpus):
    """Load a corpus and build the process nodes / creation times / SYSTEM-pipe list shared by run() and pilot()."""

    ruleset, dropped = _lab_ruleset("core")
    high = RuleSet([r for r in ruleset.rules if r.level in LEVELS_HIGH], ruleset.unsupported, ruleset.skipped_examples)
    window = vm2.check_slice(run_list)
    loaded = vm2.load(high, window, corpus=corpus)
    process_docs = loaded["process_docs"]
    nodes = research_signals.nodes(process_docs)
    created = {}
    for d in process_docs:
        if str(vm_live._get(d, "event", "code")) == "1" and vm_live._get(d, "process", "entity_id"):
            created.setdefault(d["process"]["entity_id"], vm_live._ts(d["@timestamp"]))
    return loaded, high, dropped, window, process_docs, nodes, created


def pilot() -> dict:
    """Dry run (one round): per test, did an escalation complete? Not a recorded result."""

    run_list = vm2.runs(atomic_log=PILOT_ATOMIC_LOG, defender=DEFENDER_DETECTIONS) if DEFENDER_DETECTIONS.exists() \
        else vm2.runs(atomic_log=PILOT_ATOMIC_LOG, defender=PILOT_ATOMIC_LOG)
    loaded, *_rest, nodes, created = _prepare(run_list, PILOT_CORPUS)
    out = {}
    for r in run_list:
        done = vm2.escalation_completed(r, nodes, created, loaded["system_pipes"])
        out[f"{r.technique} #{r.test}"] = "escalated" if done else "DID NOT escalate"
    return {"corpus_documents": loaded["total"], "per_test": out,
            "all_escalated": all(v == "escalated" for v in out.values())}


def run() -> dict:
    run_list = runs()
    loaded, high, dropped, window, process_docs, nodes, created = _prepare(run_list, CORPUS)

    from . import engine
    in_slice = lambda d: window[0] <= vm_live._ts(d["@timestamp"]) < window[1]  # noqa: E731
    full = engine.run_package(with_evidence=True, docs=loaded["slice_docs"], bounds=window)["flags"]
    reduced = engine.run_package(with_evidence=True, docs=[d for d in loaded["package_docs"] if in_slice(d) and vm_live._get(d, "winlog", "channel") == vm_live.SYSMON], bounds=window)["flags"]
    equivalence = {"slice": [window[0].isoformat(), window[1].isoformat()], "documents_full": len(loaded["slice_docs"]),
                   "flags_full": len(full), "flags_reduced": len(reduced), "identical": full == reduced}
    if not equivalence["identical"]:
        raise ValueError(f"registry pre-filter changed the package engine's flags on the check slice: {equivalence}")

    research = research_signals.signal_flags(process_docs)
    flags = {mode: engine.run_package(with_evidence=True, docs=loaded["package_docs"], mode=mode)["flags"] for mode in MODES}

    completed = [vm2.escalation_completed(r, nodes, created, loaded["system_pipes"]) for r in run_list]
    absent = [(r.technique, r.test) in ABSENT_TESTS for r in run_list]
    subsets = {
        "all_runs": list(run_list),
        "excluding_binary_absent": [r for r, a in zip(run_list, absent) if not a],
        "escalation_completed": [r for r, c in zip(run_list, completed) if c],
    }

    detectors = {"R_research_signals": research, **{f"P_{mode}": f for mode, f in flags.items()}}
    clean = lambda level: {k: v for k, v in level.items() if not k.startswith("_")}  # noqa: E731
    levels = {sub: {name: clean(vm_live.run_level(f, created, sub_runs, with_semantics=True, alarm_runs=run_list)) for name, f in detectors.items()}
              for sub, sub_runs in subsets.items()}
    sigma = vm_live.sigma_level(loaded["alerts"], run_list)

    r_any = {i for i, r in enumerate(run_list) if any(s and g in created and abs((created[g] - r.at).total_seconds()) <= TOLERANCE_SECONDS for g, s in research.items())}
    union = len(r_any | sigma["_detected"])

    naming = {"runs_with_outcome_process": 0, "R": 0, "Sigma": 0, **{mode: 0 for mode in MODES}}
    sigma_guids = {a["guid"] for a in loaded["alerts"]}
    for run_ in run_list:
        outcome = vm_live.outcome_processes(nodes, created, run_)
        if not outcome:
            continue
        naming["runs_with_outcome_process"] += 1
        naming["R"] += bool(outcome & {g for g, s in research.items() if s})
        naming["Sigma"] += bool(outcome & sigma_guids)
        for mode in MODES:
            naming[mode] += bool(outcome & {g for g, s in flags[mode].items() if s})

    service_runs = [r for r in run_list if r.technique == "T1543.003"]
    service = {mode: vm2._service(flags[mode], created, service_runs, run_list, nodes) for mode in MODES}
    base, b2 = service["package-v2"], service[package_v3.VM_EXTRA_MODE]
    diff = package_v3._flag_diff(research, flags["research-v3"], list(created))

    all_R = levels["all_runs"]["R_research_signals"]
    done_R = levels["escalation_completed"]["R_research_signals"]
    # W3: does the token signal flag the SYSTEM process in any completed token run?
    token_runs = [(r, c) for r, c in zip(run_list, completed) if r.technique.startswith("T1134") and c]
    token_hits = 0
    for r, _ in token_runs:
        near = lambda g: g in created and abs((created[g] - r.at).total_seconds()) <= TOLERANCE_SECONDS  # noqa: E731
        if any("token_impersonation" in research.get(g, ()) and near(g) for g in research):
            token_hits += 1
    done_total = len(subsets["escalation_completed"])

    hypotheses = {
        "W1": {"expected": "On completed-escalation runs, R flags >= 95% consistently",
               "observed": f"{done_R['runs_consistent']}/{done_R['runs']}",
               "supported": (done_R["runs_consistent"] >= 0.95 * done_R["runs"]) if done_R["runs"] else None},
        "W2": {"expected": "R detects >= 70% of all 50 runs consistently",
               "observed": f"{all_R['runs_consistent']}/{all_R['runs']}",
               "supported": all_R["runs_consistent"] >= 0.7 * all_R["runs"]},
        "W3": {"expected": "The token signal flags the SYSTEM process in >= 1 completed token run",
               "observed": f"{token_hits}/{len(token_runs)} completed token runs",
               "supported": (token_hits >= 1) if token_runs else None},
        "W4": {"expected": "research-v3 flags exactly the processes R flags", "observed": diff or "no differences", "supported": not diff},
        "W5": {"expected": "R or Sigma (any flag) detects more runs than Sigma alone",
               "observed": f"{union} vs {sigma['runs_any']}", "supported": union > sigma["runs_any"]},
        "W6": {"expected": "service-install-only keeps >= 90% of package-v2 service detections, no extra false alarm",
               "observed": f"{b2['service_runs_detected']}/{base['service_runs_detected']} runs, {b2['false_alarm_processes']} vs {base['false_alarm_processes']} FA",
               "supported": (vm2._ratio_holds(b2["service_runs_detected"], base["service_runs_detected"]) and b2["false_alarm_processes"] <= base["false_alarm_processes"])
               if base["service_runs_detected"] else None},
    }

    return {
        "corpus": {"documents": loaded["total"], "unique": loaded["unique"], "duplicates_removed": sum(loaded["duplicates"].values()),
                   "duplicates_by_channel_code": loaded["duplicates"], "process_records": len(process_docs),
                   "service_install_events": dict(Counter(i["source"] for i in loaded["installs"])), "filter_equivalence": equivalence},
        "runs": {"total": len(run_list), "by_technique": dict(sorted(Counter(r.technique for r in run_list).items())),
                 "nonzero_or_empty_exit": sum(1 for r in run_list if r.exit_code != "0"),
                 "defender_detected": sum(r.defender for r in run_list), "binary_absent": sum(absent),
                 "escalation_completed": sum(completed),
                 "escalation_completed_by_technique": {t: f"{sum(c for r, c in zip(run_list, completed) if r.technique == t)}/{n}"
                                                       for t, n in sorted(Counter(r.technique for r in run_list).items())}},
        "detectors": levels,
        "sigma_core_high": {**{k: v for k, v in sigma.items() if not k.startswith("_")}, "rules_evaluated": len(high.rules), "rules_dropped_details": dropped},
        "r_or_sigma_runs_any": union,
        "outcome_process_named": naming,
        "service_by_mode": service,
        "research_v3_vs_R": diff,
        "token_signal_first_test": {"completed_token_runs": len(token_runs), "flagged_by_token_signal": token_hits},
        "hypotheses": hypotheses,
        "summary": {k: v["supported"] for k, v in hypotheses.items()},
        "signal_techniques": {k: list(v) for k, v in SIGNAL_TECHNIQUES.items()},
    }


if __name__ == "__main__":
    import json

    if "--pilot" in sys.argv:
        print(json.dumps(pilot(), indent=2, default=str))
    else:
        print(json.dumps(run(), indent=2, default=str))
