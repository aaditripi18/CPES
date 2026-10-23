"""vm-live-v1: frozen detectors on the live VM session (docs/design/vm-live-v1.md).

Inputs are private (git-ignored ``lab-data/vm-live-v1/``): the Elasticsearch
export, the Atomic execution log, the benign-period marks and Defender's
detection history. Only aggregate figures are returned.

Implementation choices fixed by the pre-registration: E-c labels (±150 s around
each logged run), research signals R from ``evaluation.research_signals``,
package engine P with evidence channels, SigmaHQ core high/critical on the
Sysmon events (same ECS view and Details exclusion as ``sigma-lab-v3``), and
the service-install corroboration S2.

Two implementation details, neither of which changes a detector:
* Winlogbeat re-sent events after the in-session Elasticsearch outage, so
  documents are de-duplicated on (channel, record id); the count is reported.
* P is given process, pipe and remote-thread records plus only the registry
  records its resolver can read (hijack or service tokens). The resolver
  ignores every other registry record and reads integrity only from process
  creation; ``filter_equivalence`` re-runs P on all Sysmon records of one
  30-minute slice and requires identical flags.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import engine, research_signals
from .data import ROOT, SIGNAL_TECHNIQUES, TOLERANCE_SECONDS, sha256
from .sigma import RuleSet
from .sigma_eval import LEVELS_HIGH, TECHNIQUE_TAGS, _lab_ruleset, ecs_view

LAB = ROOT / "lab-data" / "vm-live-v1"
CORPUS = LAB / "corpus.ndjson"
ATOMIC_LOG = LAB / "atomic-log.csv"
BENIGN_LOG = LAB / "benign-period.csv"
DEFENDER_DETECTIONS = LAB / "defender-detections.csv"
DEFENDER_THREATS = LAB / "defender-threats.csv"
CORPUS_SHA256 = "e5057de4afb6c08925fbe85fa8cfb4d1a2e35bd987fef3617aa0767535427232"  # lab/vm-session/SESSION-NOTES.md
SYSMON = "Microsoft-Windows-Sysmon/Operational"
PROCESS_CODES = {"1", "8", "17", "18"}
REGISTRY_CODES = {"12", "13", "14"}
INSTALL_CODES = {("System", "7045"): "ImagePath", ("Security", "4697"): "ServiceFileName"}
# The VM clock: benign-period.ps1 printed 00:14:47 local for 15:14:47Z.
VM_UTC_OFFSET = timedelta(hours=9)
SLICE = (datetime(2026, 10, 23, 15, 45, tzinfo=timezone.utc), datetime(2026, 10, 23, 16, 15, tzinfo=timezone.utc))


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _get(d: dict, *path: str):
    value = d
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def _bn(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


def install_image(command: str | None) -> str:
    """Executable basename of a service ImagePath / ServiceFileName (quotes and arguments stripped)."""

    text = (command or "").strip()
    if text.startswith('"'):
        text = text[1:].split('"', 1)[0]
    else:
        lowered = text.lower()
        end = lowered.find(".exe")
        text = text[: end + 4] if end >= 0 else text.split(" ", 1)[0]
    return _bn(text)


def inputs_manifest() -> list[dict]:
    paths = (CORPUS, ATOMIC_LOG, BENIGN_LOG, DEFENDER_DETECTIONS, DEFENDER_THREATS)
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"vm-live-v1 inputs missing from lab-data/vm-live-v1: {', '.join(missing)} (private; see lab/vm-session).")
    out = [{"path": str(p.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(p)} for p in paths]
    if out[0]["sha256"] != CORPUS_SHA256:
        raise ValueError("lab-data/vm-live-v1/corpus.ndjson does not match the SHA-256 recorded at export.")
    return out


@dataclass(frozen=True)
class Run:
    technique: str
    test: str
    at: datetime
    exit_code: str
    defender: bool  # Defender reported a detection during this run


def runs() -> tuple[Run, ...]:
    detections = []
    with DEFENDER_DETECTIONS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            local = datetime.strptime(row["InitialDetectionTime"], "%d-%m-%Y %H:%M:%S")
            detections.append((local - VM_UTC_OFFSET).replace(tzinfo=timezone.utc))
    out = []
    with ATOMIC_LOG.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            at = _ts(row["Execution Time (UTC)"])
            out.append(Run(row["Technique"].split()[0].upper(), row["Test Number"], at, row["ExitCode"],
                           any(timedelta(seconds=-5) <= d - at <= timedelta(seconds=TOLERANCE_SECONDS) for d in detections)))
    return tuple(out)


def _sigma_alert(rule, document: dict, view: dict) -> dict:
    return {"t": _ts(document["@timestamp"]), "guid": view.get("ProcessGuid"), "rule": rule.title, "id": rule.id,
            "level": rule.level, "tags": frozenset(rule.tags)}


def load(ruleset: RuleSet) -> dict:
    """One streaming pass: de-duplicate, keep what each detector reads, match Sigma."""

    seen: set[tuple[str, str]] = set()
    duplicates: Counter = Counter()
    process_docs, registry_docs, slice_docs, installs, alerts = [], [], [], [], []
    tokens = tuple(t.lower() for t in (*engine.RESOLVER_SETTINGS["hijack_registry_tokens"], *engine.RESOLVER_SETTINGS["service_registry_tokens"]))
    rules_for: dict[str, list] = {}
    total = 0
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            total += 1
            d = json.loads(line)
            channel, code = _get(d, "winlog", "channel"), str(_get(d, "event", "code"))
            key = (channel, str(_get(d, "winlog", "record_id")))
            if key in seen:
                duplicates[f"{channel} {code}"] += 1
                continue
            seen.add(key)
            if (channel, code) in INSTALL_CODES:
                installs.append({"t": _ts(d["@timestamp"]), "image": install_image(_get(d, "winlog", "event_data", INSTALL_CODES[(channel, code)])), "source": code})
                continue
            if channel != SYSMON:
                continue
            if SLICE[0] <= _ts(d["@timestamp"]) < SLICE[1]:
                slice_docs.append(d)
            if code in PROCESS_CODES:
                process_docs.append(d)
            elif code in REGISTRY_CODES and any(t in (_get(d, "registry", "path") or "").lower() for t in tokens):
                registry_docs.append(d)
            eid, view = ecs_view(d)
            rules = rules_for.get(eid)
            if rules is None:
                rules = rules_for[eid] = ruleset.for_eid(eid)
            for rule in rules:
                if rule.match(view):
                    alerts.append(_sigma_alert(rule, d, view))
    return {"total": total, "unique": len(seen), "duplicates": dict(duplicates), "process_docs": process_docs, "registry_docs": registry_docs,
            "slice_docs": slice_docs, "installs": installs, "alerts": alerts}


def _sorted(docs: list[dict]) -> list[dict]:
    return sorted(docs, key=lambda d: (d["@timestamp"], _get(d, "winlog", "record_id") or 0))


def run_level(flags: dict[str, tuple[str, ...]], created: dict[str, datetime], run_list, *, with_semantics: bool) -> dict:
    """E-c rule on this session's runs: a run is detected if a flagged process was created within ±150 s."""

    near = lambda t, at: abs((t - at).total_seconds()) <= TOLERANCE_SECONDS  # noqa: E731
    flagged = [(g, s) for g, s in flags.items() if s and g in created]
    any_hit, consistent, totals = Counter(), Counter(), Counter()
    for run in run_list:
        totals[run.technique] += 1
        close = [s for g, s in flagged if near(created[g], run.at)]
        any_hit[run.technique] += bool(close)
        consistent[run.technique] += any(run.technique in SIGNAL_TECHNIQUES.get(sig, ()) for s in close for sig in s)
    false_alarms = [g for g, _ in flagged if not any(near(created[g], r.at) for r in run_list)]
    out = {
        "flagged_processes": len(flagged),
        "flagged_without_creation_record": sum(1 for g, s in flags.items() if s and g not in created),
        "false_alarm_processes": len(false_alarms),
        "runs_any": sum(any_hit.values()),
        "by_technique_any": {t: f"{any_hit[t]}/{n}" for t, n in sorted(totals.items())},
        "runs": sum(totals.values()),
    }
    if with_semantics:
        out["runs_consistent"] = sum(consistent.values())
        out["by_technique_consistent"] = {t: f"{consistent[t]}/{n}" for t, n in sorted(totals.items())}
    return out | {"_false_alarms": false_alarms, "_consistent": consistent, "_totals": totals}


def sigma_level(alerts: list[dict], run_list) -> dict:
    near = lambda a, at: abs((a["t"] - at).total_seconds()) <= TOLERANCE_SECONDS  # noqa: E731
    any_hit, consistent, totals = Counter(), Counter(), Counter()
    detected = set()
    for index, run in enumerate(run_list):
        totals[run.technique] += 1
        close = [a for a in alerts if near(a, run.at)]
        if close:
            detected.add(index)
        any_hit[run.technique] += bool(close)
        consistent[run.technique] += any(a["tags"] & TECHNIQUE_TAGS.get(run.technique, set()) for a in close)
    outside = [a for a in alerts if not any(near(a, r.at) for r in run_list)]
    return {
        "alerts": len(alerts), "runs_any": sum(any_hit.values()), "runs_consistent": sum(consistent.values()), "runs": sum(totals.values()),
        "by_technique_any": {t: f"{any_hit[t]}/{n}" for t, n in sorted(totals.items())},
        "by_technique_consistent": {t: f"{consistent[t]}/{n}" for t, n in sorted(totals.items())},
        "outside_runs": {"alerts": len(outside), "processes": len({a["guid"] for a in outside}), "top_rules": Counter(a["rule"] for a in outside).most_common(8)},
        "_detected": detected,
    }


def outcome_processes(nodes: dict, created: dict[str, datetime], run: Run) -> set[str]:
    """The process that gained privilege, mechanically: the auto-elevated LOLBin (UAC) or the SYSTEM service binary."""

    near = {g for g, t in created.items() if abs((t - run.at).total_seconds()) <= TOLERANCE_SECONDS}
    if run.technique == "T1548.002":
        return {g for g in near if nodes[g].image in research_signals.LOL and nodes[g].integrity in ("high", "system")}
    if run.technique == "T1543.003":
        return {g for g in near if nodes[g].parent_image == "services.exe" and nodes[g].image != "svchost.exe" and nodes[g].integrity == "system"}
    return set()


def service_corroborated(guid: str, nodes: dict, created: dict[str, datetime], installs: list[dict]) -> bool:
    if guid not in created:
        return False
    return any(i["image"] == nodes[guid].image and i["t"] <= created[guid] for i in installs)


def run() -> dict:
    ruleset, dropped = _lab_ruleset("core")
    high = RuleSet([r for r in ruleset.rules if r.level in LEVELS_HIGH], ruleset.unsupported, ruleset.skipped_examples)
    loaded = load(high)
    run_list = runs()
    process_docs = _sorted(loaded["process_docs"])
    nodes = research_signals.nodes(process_docs)
    created: dict[str, datetime] = {}
    for d in process_docs:
        if str(_get(d, "event", "code")) == "1" and _get(d, "process", "entity_id"):
            created.setdefault(d["process"]["entity_id"], _ts(d["@timestamp"]))

    research = research_signals.signal_flags(process_docs)
    baselines = research_signals.baselines(process_docs)
    package_docs = _sorted(loaded["process_docs"] + loaded["registry_docs"])
    package = engine.run_package(with_evidence=True, docs=package_docs)

    slice_docs = _sorted(loaded["slice_docs"])
    in_slice = lambda d: SLICE[0] <= _ts(d["@timestamp"]) < SLICE[1]  # noqa: E731
    full = engine.run_package(with_evidence=True, docs=slice_docs, bounds=SLICE)["flags"]
    reduced = engine.run_package(with_evidence=True, docs=[d for d in package_docs if in_slice(d)], bounds=SLICE)["flags"]
    equivalence = {"slice": [SLICE[0].isoformat(), SLICE[1].isoformat()], "documents_full": len(slice_docs), "flags_full": len(full),
                   "flags_reduced": len(reduced), "identical": full == reduced}
    if not equivalence["identical"]:
        raise ValueError(f"registry pre-filter changed the package engine's flags on the check slice: {equivalence}")

    detectors = {
        "R_research_signals": (research, True),
        "P_package_with_evidence": (package["flags"], True),
        "single_event_research": ({g: ("integrity_edge",) for g in baselines["single_event_research"]}, False),
        "ioc_signature_research": ({g: ("ioc",) for g in baselines["ioc_signature_research"]}, False),
    }
    blocked = [r for r in run_list if r.defender]
    unblocked = [r for r in run_list if not r.defender]
    levels = {name: run_level(flags, created, run_list, with_semantics=sem) for name, (flags, sem) in detectors.items()}
    levels_unblocked = {name: run_level(flags, created, unblocked, with_semantics=sem) for name, (flags, sem) in detectors.items()}
    sigma = sigma_level(loaded["alerts"], run_list)

    # L7: R or Sigma, any flag, per run.
    r_any = {i for i, r in enumerate(run_list) if any(s and g in created and abs((created[g] - r.at).total_seconds()) <= TOLERANCE_SECONDS for g, s in research.items())}
    union = len(r_any | sigma["_detected"])

    # Outcome naming (no hypothesis).
    naming = {"runs_with_outcome_process": 0, "R": 0, "P": 0, "Sigma": 0}
    sigma_guids = {a["guid"] for a in loaded["alerts"]}
    for run_ in run_list:
        outcome = outcome_processes(nodes, created, run_)
        if not outcome:
            continue
        naming["runs_with_outcome_process"] += 1
        naming["R"] += bool(outcome & {g for g, s in research.items() if s})
        naming["P"] += bool(outcome & set(package["flags"]))
        naming["Sigma"] += bool(outcome & sigma_guids)

    # S2: service-install corroboration on the service signal of R and P.
    s2 = {}
    pooled = Counter()
    for name, flags in (("R", research), ("P", package["flags"])):
        s0 = {g: s for g, s in flags.items() if "service_dropped_binary" in s}
        kept = {g: s for g, s in s0.items() if service_corroborated(g, nodes, created, loaded["installs"])}
        service_runs = [r for r in run_list if r.technique == "T1543.003"]
        s0_level = run_level({g: ("service_dropped_binary",) for g in s0}, created, service_runs, with_semantics=True)
        s2_level = run_level({g: ("service_dropped_binary",) for g in kept}, created, service_runs, with_semantics=True)
        s0_fa = set(run_level({g: ("service_dropped_binary",) for g in s0}, created, run_list, with_semantics=True)["_false_alarms"])
        s2_fa = set(run_level({g: ("service_dropped_binary",) for g in kept}, created, run_list, with_semantics=True)["_false_alarms"])
        s2[name] = {"s0_service_runs_detected": s0_level["runs_consistent"], "s2_service_runs_detected": s2_level["runs_consistent"],
                    "s0_false_alarm_processes": len(s0_fa), "s2_false_alarm_processes": len(s2_fa),
                    "s0_false_alarm_images": dict(Counter(nodes[g].image for g in s0_fa if g in nodes)),
                    "s2_false_alarm_images": dict(Counter(nodes[g].image for g in s2_fa if g in nodes))}
        pooled["s0_runs"] += s0_level["runs_consistent"]
        pooled["s2_runs"] += s2_level["runs_consistent"]
        pooled["s0_fa"] += len(s0_fa)
        pooled["s2_fa"] += len(s2_fa)

    def frac(level: dict, technique_prefix: str) -> tuple[int, int]:
        hit = sum(v for t, v in level["_consistent"].items() if t.startswith(technique_prefix))
        total = sum(v for t, v in level["_totals"].items() if t.startswith(technique_prefix))
        return hit, total

    R, P = levels["R_research_signals"], levels["P_package_with_evidence"]
    uac, svc, inj, tok = (frac(R, p) for p in ("T1548", "T1543", "T1055", "T1134"))
    s2_testable = pooled["s0_fa"] > 0
    s2a = pooled["s2_runs"] >= 0.9 * pooled["s0_runs"] if pooled["s0_runs"] else None
    s2b = (pooled["s0_fa"] - pooled["s2_fa"]) >= 0.8 * pooled["s0_fa"] if s2_testable else None
    hypotheses = {
        "L1": {"expected": "R consistent >= 70% of runs", "observed": f"{R['runs_consistent']}/{R['runs']}", "supported": R["runs_consistent"] >= 0.7 * R["runs"]},
        "L2": {"expected": "R consistent: UAC >= 80%, service >= 80%, injection >= 70%", "observed": {"uac": f"{uac[0]}/{uac[1]}", "service": f"{svc[0]}/{svc[1]}", "injection": f"{inj[0]}/{inj[1]}"},
               "supported": uac[0] >= 0.8 * uac[1] and svc[0] >= 0.8 * svc[1] and inj[0] >= 0.7 * inj[1]},
        "L3": {"expected": "R consistent on T1134 <= 50%", "observed": f"{tok[0]}/{tok[1]}", "supported": tok[0] <= 0.5 * tok[1]},
        "L4": {"expected": "R false-alarm processes <= 5", "observed": R["false_alarm_processes"], "supported": R["false_alarm_processes"] <= 5},
        "L5": {"expected": "P consistent < R consistent", "observed": f"P {P['runs_consistent']} vs R {R['runs_consistent']}", "supported": P["runs_consistent"] < R["runs_consistent"]},
        "L6": {"expected": "Sigma any >= R any", "observed": f"Sigma {sigma['runs_any']} vs R {R['runs_any']}", "supported": sigma["runs_any"] >= R["runs_any"]},
        "L7": {"expected": "R or Sigma (any) > Sigma alone (any)", "observed": f"{union} vs {sigma['runs_any']}", "supported": union > sigma["runs_any"]},
        "S2a": {"expected": "S2 keeps >= 90% of service runs S0 detects (R and P pooled)", "observed": f"{pooled['s2_runs']}/{pooled['s0_runs']}", "supported": s2a},
        "S2b": {"expected": "S2 removes >= 80% of S0 false-alarm processes (R and P pooled)", "observed": f"{pooled['s0_fa'] - pooled['s2_fa']}/{pooled['s0_fa']}", "supported": s2b},
    }
    adopted = bool(s2_testable and s2a and s2b)

    clean = lambda level: {k: v for k, v in level.items() if not k.startswith("_")}  # noqa: E731
    return {
        "corpus": {"documents": loaded["total"], "unique": loaded["unique"], "duplicates_removed": sum(loaded["duplicates"].values()),
                   "duplicates_by_channel_code": loaded["duplicates"], "process_records": len(process_docs), "registry_records_for_P": len(loaded["registry_docs"]),
                   "service_install_events": dict(Counter(i["source"] for i in loaded["installs"])), "filter_equivalence": equivalence},
        "runs": {"total": len(run_list), "by_technique": dict(sorted(Counter(r.technique for r in run_list).items())),
                 "nonzero_or_empty_exit": sum(1 for r in run_list if r.exit_code != "0"), "defender_detected": len(blocked),
                 "defender_detected_by_technique": dict(Counter(r.technique for r in blocked))},
        "detectors": {name: clean(level) for name, level in levels.items()},
        "detectors_excluding_defender_runs": {name: clean(level) for name, level in levels_unblocked.items()},
        "sigma_core_high": {**{k: v for k, v in sigma.items() if not k.startswith("_")}, "rules_evaluated": len(high.rules), "rules_dropped_details": dropped},
        "r_or_sigma_runs_any": union,
        "outcome_process_named": naming,
        "service_install_corroboration": {"by_engine": s2, "pooled": dict(pooled), "testable": s2_testable, "adopted": adopted},
        "hypotheses": hypotheses,
        "live_time_to_alert": "not recorded: the dashboard Live page was not run during the session",
        "summary": {k: v["supported"] for k, v in hypotheses.items()},
    }
