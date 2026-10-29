"""vm2: frozen detectors and the package v3 modes on the VM2 session.

Pre-registered in docs/design/package-v3-and-vm2.md (VM2 session, Amendments 1-2),
written before the session ran. Inputs are private (git-ignored ``lab-data/vm2/``):
the Elasticsearch export, the Atomic execution log, the benign-period marks and
Defender's detection history. Only aggregate figures are returned.

Detectors and labels are vm-live-v1's (``evaluation.vm_live``): E-c labels (±150 s
around each logged run), research signals R, SigmaHQ core high/critical, and the
package engine in four modes: ``package-v2`` (P, the current package),
``research-v3``, ``structural-v3`` and ``service-install-only`` (B2 alone).

Fixed in advance:
* Hypotheses V1-V5 and V3b/V4b, exactly as worded in the pre-registration.
* "Escalation completed" per run, mechanically: UAC = an auto-elevating binary at
  High/System; service = a SYSTEM child of ``services.exe`` (not svchost); token = a
  SYSTEM-integrity process started by the test's shell (powershell/cmd) or a named-pipe
  connection made as SYSTEM by that shell; injection = ``mavinject.exe`` ran. All within ±150 s.
  (The first execution counted any SYSTEM pipe connection, against the pre-registered wording;
  corrected and disclosed in lab/vm-session/VM2-SETUP-NOTES.md.)
* T1548.002 #7 runs are "binary absent" (``sdclt.exe`` is not on Windows Server 2022,
  Amendment 2): kept in every primary denominator and also reported separately.
* The registry pre-filter for the package engine is checked, as on vm-live-v1, on the
  first 30 minutes of attack part 1 (identical flags required).
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import engine, package_v3, research_signals, vm_live
from .data import ROOT, SIGNAL_TECHNIQUES, TOLERANCE_SECONDS, sha256
from .sigma import RuleSet
from .sigma_eval import LEVELS_HIGH, _lab_ruleset, ecs_view

LAB = ROOT / "lab-data" / "vm2"
CORPUS = LAB / "corpus.ndjson"
ATOMIC_LOG = LAB / "atomic-log.csv"
BENIGN_LOG = LAB / "benign-period.csv"
DEFENDER_DETECTIONS = LAB / "defender-detections.csv"
DEFENDER_THREATS = LAB / "defender-threats.csv"
# Recorded in lab/vm-session/VM2-SETUP-NOTES.md at export; None until the session has run.
CORPUS_SHA256: str | None = "2ff842a7944455cd879f73ddaae303f4501342c6bd0ba4f72f88e16bdee95427"
ABSENT_TESTS = {("T1548.002", "7")}  # sdclt.exe is not present on Windows Server 2022
SHELLS = ("powershell.exe", "cmd.exe", "pwsh.exe")
MODES = ("package-v2", "research-v3", "structural-v3", package_v3.VM_EXTRA_MODE)


def inputs_manifest() -> list[dict]:
    paths = (CORPUS, ATOMIC_LOG, BENIGN_LOG, DEFENDER_DETECTIONS, DEFENDER_THREATS)
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"vm2 inputs missing from lab-data/vm2: {', '.join(missing)} (private; see lab/vm-session/VM2-RUNBOOK.md).")
    out = [{"path": str(p.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(p)} for p in paths]
    if CORPUS_SHA256 is None:
        raise ValueError("vm2.CORPUS_SHA256 is not set: record the export's SHA-256 before running the protocol.")
    if out[0]["sha256"] != CORPUS_SHA256:
        raise ValueError("lab-data/vm2/corpus.ndjson does not match the SHA-256 recorded at export.")
    return out


def _defender_times(path=None) -> list[datetime]:
    """Detection times from the export in the runbook's export step (UTC, ISO 8601)."""

    path = path or DEFENDER_DETECTIONS  # resolve at call time so monkeypatching the module attr works
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [vm_live._ts(row["InitialDetectionTimeUtc"]) for row in csv.DictReader(handle) if row.get("InitialDetectionTimeUtc")]


def runs(atomic_log=None, defender=None) -> tuple[vm_live.Run, ...]:
    detections = _defender_times(defender)
    out = []
    with (atomic_log or ATOMIC_LOG).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            at = vm_live._ts(row["Execution Time (UTC)"])
            out.append(vm_live.Run(row["Technique"].split()[0].upper(), row["Test Number"], at, row["ExitCode"],
                                   any(timedelta(seconds=-5) <= d - at <= timedelta(seconds=TOLERANCE_SECONDS) for d in detections)))
    return tuple(out)


def check_slice(run_list) -> tuple[datetime, datetime]:
    start = min(r.at for r in run_list if r.technique == "T1548.002") - timedelta(minutes=2)
    return start, start + timedelta(minutes=30)


def _key(d: dict):
    # System/Security record ids are strings, Sysmon's integers: order on both as text.
    return (d["@timestamp"], vm_live._get(d, "winlog", "channel") or "", str(vm_live._get(d, "winlog", "record_id")))


def load(ruleset: RuleSet, window: tuple[datetime, datetime], corpus=None) -> dict:
    """One streaming pass: de-duplicate on (channel, record id), keep what each detector reads, match Sigma."""

    corpus = corpus or CORPUS  # resolve at call time so monkeypatching the module attr works
    seen: set[tuple[str, str]] = set()
    duplicates: Counter = Counter()
    process_docs, package_docs, slice_docs, installs, alerts, system_pipes = [], [], [], [], [], []
    tokens = tuple(t.lower() for t in (*engine.RESOLVER_SETTINGS["hijack_registry_tokens"], *engine.RESOLVER_SETTINGS["service_registry_tokens"]))
    rules_for: dict[str, list] = {}
    total = 0
    with corpus.open(encoding="utf-8") as handle:
        for line in handle:
            total += 1
            d = json.loads(line)
            channel, code = vm_live._get(d, "winlog", "channel"), str(vm_live._get(d, "event", "code"))
            key = (channel, str(vm_live._get(d, "winlog", "record_id")))
            if key in seen:
                duplicates[f"{channel} {code}"] += 1
                continue
            seen.add(key)
            if (channel, code) in vm_live.INSTALL_CODES:
                installs.append({"t": vm_live._ts(d["@timestamp"]), "image": vm_live.install_image(vm_live._get(d, "winlog", "event_data", vm_live.INSTALL_CODES[(channel, code)])), "source": code})
                package_docs.append(d)
                continue
            if channel != vm_live.SYSMON:
                continue
            if window[0] <= vm_live._ts(d["@timestamp"]) < window[1]:
                slice_docs.append(d)
            if code in vm_live.PROCESS_CODES:
                process_docs.append(d)
                package_docs.append(d)
                if code == "18" and vm_live._get(d, "user", "name") == "SYSTEM":
                    system_pipes.append((vm_live._ts(d["@timestamp"]), vm_live._bn(vm_live._get(d, "process", "executable"))))
            elif code in vm_live.REGISTRY_CODES and any(t in (vm_live._get(d, "registry", "path") or "").lower() for t in tokens):
                package_docs.append(d)
            eid, view = ecs_view(d)
            rules = rules_for.get(eid)
            if rules is None:
                rules = rules_for[eid] = ruleset.for_eid(eid)
            for rule in rules:
                if rule.match(view):
                    alerts.append(vm_live._sigma_alert(rule, d, view))
    return {"total": total, "unique": len(seen), "duplicates": dict(duplicates), "process_docs": sorted(process_docs, key=_key),
            "package_docs": sorted(package_docs, key=_key), "slice_docs": sorted(slice_docs, key=_key), "installs": installs,
            "alerts": alerts, "system_pipes": system_pipes}


def escalation_completed(run: vm_live.Run, nodes: dict, created: dict[str, datetime], system_pipes: list[tuple[datetime, str]]) -> bool:
    """``system_pipes``: (time, image basename) of named-pipe connections made as SYSTEM."""

    near = lambda t: abs((t - run.at).total_seconds()) <= TOLERANCE_SECONDS  # noqa: E731
    close = [nodes[g] for g, t in created.items() if near(t) and g in nodes]
    if run.technique == "T1548.002":
        return any(n.image in research_signals.LOL and n.integrity in ("high", "system") for n in close)
    if run.technique == "T1543.003":
        return any(n.parent_image == "services.exe" and n.image != "svchost.exe" and n.integrity == "system" for n in close)
    if run.technique.startswith("T1134"):
        # "from the test's shell" applies to both: the pipe connection must be made by a shell as SYSTEM
        # (corrected 2026-10-29 after the first execution, which counted any SYSTEM pipe connection).
        return any(n.integrity == "system" and n.parent_image in SHELLS for n in close) or any(near(t) and image in SHELLS for t, image in system_pipes)
    if run.technique == "T1055.001":
        return any(n.image == "mavinject.exe" for n in close)
    return False


def _service(flags: dict, created, service_runs, all_runs, nodes) -> dict:
    s = {g: ("service_dropped_binary",) for g, sig in flags.items() if "service_dropped_binary" in sig}
    level = vm_live.run_level(s, created, service_runs, with_semantics=True)
    alarms = vm_live.run_level(s, created, all_runs, with_semantics=True)["_false_alarms"]
    return {"service_runs_detected": level["runs_consistent"], "false_alarm_processes": len(alarms),
            "false_alarm_images": dict(Counter(nodes[g].image for g in alarms if g in nodes))}


def _ratio_holds(new: int, base: int) -> bool | None:
    return new >= 0.9 * base if base else None


def run() -> dict:
    ruleset, dropped = _lab_ruleset("core")
    high = RuleSet([r for r in ruleset.rules if r.level in LEVELS_HIGH], ruleset.unsupported, ruleset.skipped_examples)
    run_list = runs()
    window = check_slice(run_list)
    loaded = load(high, window)
    process_docs = loaded["process_docs"]
    nodes = research_signals.nodes(process_docs)
    created: dict[str, datetime] = {}
    for d in process_docs:
        if str(vm_live._get(d, "event", "code")) == "1" and vm_live._get(d, "process", "entity_id"):
            created.setdefault(d["process"]["entity_id"], vm_live._ts(d["@timestamp"]))

    research = research_signals.signal_flags(process_docs)
    flags = {mode: engine.run_package(with_evidence=True, docs=loaded["package_docs"], mode=mode)["flags"] for mode in MODES}

    in_slice = lambda d: window[0] <= vm_live._ts(d["@timestamp"]) < window[1]  # noqa: E731
    full = engine.run_package(with_evidence=True, docs=loaded["slice_docs"], bounds=window)["flags"]
    reduced = engine.run_package(with_evidence=True, docs=[d for d in loaded["package_docs"] if in_slice(d) and vm_live._get(d, "winlog", "channel") == vm_live.SYSMON], bounds=window)["flags"]
    equivalence = {"slice": [window[0].isoformat(), window[1].isoformat()], "documents_full": len(loaded["slice_docs"]),
                   "flags_full": len(full), "flags_reduced": len(reduced), "identical": full == reduced}
    if not equivalence["identical"]:
        raise ValueError(f"registry pre-filter changed the package engine's flags on the check slice: {equivalence}")

    completed = [escalation_completed(r, nodes, created, loaded["system_pipes"]) for r in run_list]
    absent = [(r.technique, r.test) in ABSENT_TESTS for r in run_list]
    subsets = {
        "all_runs": list(run_list),
        "excluding_binary_absent": [r for r, a in zip(run_list, absent) if not a],
        "escalation_completed": [r for r, c in zip(run_list, completed) if c],
    }

    detectors = {"R_research_signals": research, **{f"P_{mode}": f for mode, f in flags.items()}}
    clean = lambda level: {k: v for k, v in level.items() if not k.startswith("_")}  # noqa: E731
    levels = {subset: {name: clean(vm_live.run_level(f, created, subset_runs, with_semantics=True, alarm_runs=run_list)) for name, f in detectors.items()}
              for subset, subset_runs in subsets.items()}
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
    service = {mode: _service(flags[mode], created, service_runs, run_list, nodes) for mode in MODES}
    base, b1b2, b2 = service["package-v2"], service["structural-v3"], service[package_v3.VM_EXTRA_MODE]
    diff = package_v3._flag_diff(research, flags["research-v3"], list(created))
    R = levels["all_runs"]["R_research_signals"]

    hypotheses = {
        "V1": {"expected": "R detects >= 70% of the 50 runs consistently", "observed": f"{R['runs_consistent']}/{R['runs']}",
               "supported": R["runs_consistent"] >= 0.7 * R["runs"]},
        "V2": {"expected": "research-v3 flags exactly the processes R flags", "observed": diff or "no differences", "supported": not diff},
        "V3": {"expected": "structural-v3 detects >= 90% of the service runs package-v2 detects",
               "observed": f"{b1b2['service_runs_detected']}/{base['service_runs_detected']}", "supported": _ratio_holds(b1b2["service_runs_detected"], base["service_runs_detected"])},
        "V4": {"expected": "structural-v3 raises no more false-alarm processes than package-v2",
               "observed": f"{b1b2['false_alarm_processes']} vs {base['false_alarm_processes']}", "supported": b1b2["false_alarm_processes"] <= base["false_alarm_processes"]},
        "V3b": {"expected": "B2 alone detects >= 90% of the service runs package-v2 detects",
                "observed": f"{b2['service_runs_detected']}/{base['service_runs_detected']}", "supported": _ratio_holds(b2["service_runs_detected"], base["service_runs_detected"])},
        "V4b": {"expected": "B2 alone raises no more false-alarm processes than package-v2",
                "observed": f"{b2['false_alarm_processes']} vs {base['false_alarm_processes']}", "supported": b2["false_alarm_processes"] <= base["false_alarm_processes"]},
        "V5": {"expected": "R or Sigma (any flag) detects more runs than Sigma alone", "observed": f"{union} vs {sigma['runs_any']}", "supported": union > sigma["runs_any"]},
    }

    structural_ok = bool(hypotheses["V3"]["supported"] and hypotheses["V4"]["supported"])
    b2_ok = bool(hypotheses["V3b"]["supported"] and hypotheses["V4b"]["supported"])
    adoption = {
        "dashboard_default": "research-v3 (labelled name rules)" if hypotheses["V2"]["supported"] else "unchanged (package-v2)",
        "recommended_structural_setting": "service-install-only (B2 alone)" if b2_ok else ("structural-v3" if structural_ok else "none"),
        "rule": "research-v3 if the development checks held (they did, package-v3-dev) and V2 holds; B2 alone if V3b and V4b hold "
                "(Amendment 1), else structural-v3 if V3 and V4 hold.",
    }

    return {
        "corpus": {"documents": loaded["total"], "unique": loaded["unique"], "duplicates_removed": sum(loaded["duplicates"].values()),
                   "duplicates_by_channel_code": loaded["duplicates"], "process_records": len(process_docs),
                   "service_install_events": dict(Counter(i["source"] for i in loaded["installs"])), "filter_equivalence": equivalence},
        "runs": {"total": len(run_list), "by_technique": dict(sorted(Counter(r.technique for r in run_list).items())),
                 "nonzero_or_empty_exit": sum(1 for r in run_list if r.exit_code != "0"),
                 "defender_detected": sum(r.defender for r in run_list),
                 "binary_absent": sum(absent),
                 "escalation_completed": sum(completed),
                 "escalation_completed_by_technique": {t: f"{sum(c for r, c in zip(run_list, completed) if r.technique == t)}/{n}"
                                                       for t, n in sorted(Counter(r.technique for r in run_list).items())}},
        "detectors": levels,
        "sigma_core_high": {**{k: v for k, v in sigma.items() if not k.startswith("_")}, "rules_evaluated": len(high.rules), "rules_dropped_details": dropped},
        "r_or_sigma_runs_any": union,
        "outcome_process_named": naming,
        "service_by_mode": service,
        "research_v3_vs_R": diff,
        "hypotheses": hypotheses,
        "adoption": adoption,
        "summary": {k: v["supported"] for k, v in hypotheses.items()},
        "signal_techniques": {k: list(v) for k, v in SIGNAL_TECHNIQUES.items()},
    }
