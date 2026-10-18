"""Protocols comparing CPES with SigmaHQ rules (pre-registered: Part C of
docs/design/external-and-evasion-evaluation.md).

* sigma-lab-v3     corpus-v3, run level (E-c) and alert noise outside attack runs
* sigma-ext-evtx   EVTX-ATTACK-SAMPLES, per file
* sigma-evasion    corpus-v3 variants V0/V1/V3, run level and unit level
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from . import data, evtx_source
from .sigma import RuleSet, load_rules, match_events

PACKS = ("core", "all")
SIGMA_DIR = data.ROOT / "external" / "sigma"
LEVELS_HIGH = {"high", "critical"}
TECHNIQUE_TAGS = {
    "T1548.002": {"attack.t1548.002", "attack.t1548"},
    "T1543.003": {"attack.t1543.003", "attack.t1543"},
    "T1055.001": {"attack.t1055.001", "attack.t1055"},
    "T1134.001": {"attack.t1134.001", "attack.t1134.002", "attack.t1134"},
    "T1134.002": {"attack.t1134.001", "attack.t1134.002", "attack.t1134"},
}


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _get(d: dict, *path: str):
    value = d
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def ecs_view(d: dict) -> tuple[str, dict]:
    """Sysmon field names for one Winlogbeat/ECS document (documented ECS→Sysmon view)."""

    eid = str(_get(d, "event", "code"))
    p = d.get("process") or {}
    ed = _get(d, "winlog", "event_data") or {}
    domain, name = _get(d, "user", "domain"), _get(d, "user", "name")
    view = {
        "EventID": eid,
        "ProcessGuid": p.get("entity_id"),
        "ProcessId": p.get("pid"),
        "Image": p.get("executable"),
        "User": f"{domain}\\{name}" if domain and name else name,
    }
    if eid == "1":
        pe, parent = p.get("pe") or {}, p.get("parent") or {}
        sha = _get(p, "hash", "sha256")
        view.update(
            CommandLine=p.get("command_line"), CurrentDirectory=p.get("working_directory"),
            ParentImage=parent.get("executable"), ParentCommandLine=parent.get("command_line"),
            ParentProcessGuid=parent.get("entity_id"), ParentProcessId=parent.get("pid"),
            OriginalFileName=pe.get("original_file_name"), Description=pe.get("description") or ed.get("Description"),
            Product=pe.get("product") or ed.get("Product"), Company=pe.get("company") or ed.get("Company"),
            FileVersion=pe.get("file_version") or ed.get("FileVersion"), IntegrityLevel=ed.get("IntegrityLevel"),
            LogonId=ed.get("LogonId"), TerminalSessionId=ed.get("TerminalSessionId"), ParentUser=ed.get("ParentUser"),
            Hashes=f"SHA256={sha.upper()}" if sha else None,
        )
    elif eid == "7":
        f = d.get("file") or {}
        view.update(ImageLoaded=f.get("path"), OriginalFileName=_get(f, "pe", "original_file_name"), Description=_get(f, "pe", "description"),
                    Product=_get(f, "pe", "product"), Company=_get(f, "pe", "company"), Signed=ed.get("Signed"), Signature=ed.get("Signature"),
                    SignatureStatus=ed.get("SignatureStatus"))
    elif eid in ("8", "10"):
        view.update(SourceImage=p.get("executable"), SourceProcessGuid=p.get("entity_id"), SourceProcessGUID=p.get("entity_id"),
                    TargetImage=ed.get("TargetImage"), TargetProcessGuid=ed.get("TargetProcessGUID"), SourceUser=ed.get("SourceUser"),
                    TargetUser=ed.get("TargetUser"), StartAddress=ed.get("StartAddress"), StartModule=ed.get("StartModule"),
                    StartFunction=ed.get("StartFunction"), GrantedAccess=ed.get("GrantedAccess"), CallTrace=ed.get("CallTrace"))
    elif eid == "11":
        view.update(TargetFilename=_get(d, "file", "path"))
    elif eid in ("12", "13", "14"):
        view.update(TargetObject=_get(d, "registry", "path"), EventType=ed.get("EventType"))  # Details: not reproducible from ECS
    elif eid in ("17", "18"):
        view.update(PipeName=_get(d, "file", "name"), EventType=ed.get("EventType"))
    return eid, view


def evtx_view(d: dict) -> tuple[str, dict]:
    system = d["Event"]["System"]
    eid = str(system.get("EventID"))
    view = dict(d["Event"].get("EventData") or {})
    view["EventID"] = eid
    return eid, view


def _rules(pack: str) -> RuleSet:
    return load_rules(SIGMA_DIR / pack)


def _lab_ruleset(pack: str) -> tuple[RuleSet, int]:
    """Lab corpus: drop rules that test registry Details (not reproducible from ECS)."""

    ruleset = _rules(pack)
    kept = [r for r in ruleset.rules if "Details" not in r.fields]
    return RuleSet(kept, ruleset.unsupported, ruleset.skipped_examples), len(ruleset.rules) - len(kept)


def lab_alerts(docs, ruleset: RuleSet) -> list[dict]:
    views = [ecs_view(d) for d in docs]
    hits = match_events(ruleset, views)
    out = []
    for position, rule in hits:
        view = views[position][1]
        out.append({"t": _ts(docs[position]["@timestamp"]), "guid": view.get("ProcessGuid"), "image": str(view.get("Image") or "").split("\\")[-1].lower(),
                    "rule": rule.title, "id": rule.id, "level": rule.level, "tags": set(rule.tags)})
    return out


def _run_level(alerts: list[dict], level_filter) -> dict:
    runs = data.ledger_runs()
    chosen = [a for a in alerts if level_filter(a["level"])]
    near = lambda a, at: abs((a["t"] - at).total_seconds()) <= data.TOLERANCE_SECONDS  # noqa: E731
    by_technique_any, by_technique_consistent, totals = Counter(), Counter(), Counter()
    for technique, at in runs:
        totals[technique] += 1
        close = [a for a in chosen if near(a, at)]
        by_technique_any[technique] += bool(close)
        by_technique_consistent[technique] += any(a["tags"] & TECHNIQUE_TAGS.get(technique, set()) for a in close)
    outside = [a for a in chosen if not any(near(a, at) for _, at in runs)]
    return {
        "alerts": len(chosen),
        "runs_any": f"{sum(by_technique_any.values())}/{sum(totals.values())}",
        "runs_consistent": f"{sum(by_technique_consistent.values())}/{sum(totals.values())}",
        "consistent_by_technique": {t: f"{by_technique_consistent[t]}/{n}" for t, n in sorted(totals.items())},
        "outside_runs": {"alerts": len(outside), "processes": len({a["guid"] for a in outside}), "rules": len({a["id"] for a in outside}),
                         "top_rules": Counter(a["rule"] for a in outside).most_common(8)},
    }


def _unit_level(alerts: list[dict], level_filter) -> dict:
    units = {u.guid: u for u in data.units()}
    flagged = {a["guid"] for a in alerts if level_filter(a["level"]) and a["guid"] in units}
    totals, hit = Counter(), Counter()
    for u in units.values():
        if u.is_attack:
            key = "T1134" if (u.technique or "").startswith("T1134") else u.technique
            totals[key] += 1
            hit[key] += u.guid in flagged
    return {"attack_units": f"{sum(hit.values())}/{sum(totals.values())}", "by_technique": {t: f"{hit[t]}/{n}" for t, n in sorted(totals.items())},
            "benign_units_flagged": sum(1 for g in flagged if not units[g].is_attack)}


FILTERS = {"high_or_critical": lambda level: level in LEVELS_HIGH, "any_level": lambda level: True}


def run_lab() -> dict:
    docs = list(data.documents())
    out = {"packs": {}}
    for pack in PACKS:
        ruleset, dropped = _lab_ruleset(pack)
        alerts = lab_alerts(docs, ruleset)
        out["packs"][pack] = {
            "rules_evaluated": len(ruleset.rules), "rules_dropped_details": dropped, "rules_unsupported": ruleset.unsupported,
            **{name: {"run_level": _run_level(alerts, f), "unit_level": _unit_level(alerts, f)} for name, f in FILTERS.items()},
        }
    ec = data.ROOT / "results" / "ec-ledger-time.json"
    if ec.exists():
        cpes = json.loads(ec.read_text(encoding="utf-8"))["result"]["detectors"]
        out["cpes_reference"] = {k: {key: cpes[k][key] for key in ("modelled_runs_detected_consistent", "modelled_runs_detected_any", "false_alarm_processes")} for k in ("cpes_research_signals", "cpes_package_with_evidence") if k in cpes}
    out["summary"] = {pack: {f: out["packs"][pack][f]["run_level"]["runs_consistent"] for f in FILTERS} for pack in PACKS}
    return out


def run_external() -> dict:
    from .external import SAMPLES, category, verify_manifest

    verify_manifest()
    rulesets = {pack: _rules(pack) for pack in PACKS}
    files = []
    for path in sorted(SAMPLES.glob("*.evtx")):
        docs = evtx_source.sysmon_records(path)
        row = {"file": path.name, "category": category(path.name, bool(docs))}
        views = [evtx_view(d) for d in docs]
        for pack, ruleset in rulesets.items():
            hits = match_events(ruleset, views)
            row[pack] = {
                "high_or_critical": sorted({r.title for _, r in hits if r.level in LEVELS_HIGH}),
                "any_level": sorted({r.title for _, r in hits}),
            }
        files.append(row)
    summary = defaultdict(lambda: defaultdict(int))
    for row in files:
        bucket = summary[row["category"]]
        bucket["files"] += 1
        for pack in PACKS:
            bucket[f"{pack}_high"] += bool(row[pack]["high_or_critical"])
            bucket[f"{pack}_any"] += bool(row[pack]["any_level"])
    ext = data.ROOT / "results" / "ext-evtx-privesc.json"
    cpes = json.loads(ext.read_text(encoding="utf-8"))["result"]["summary_by_category"] if ext.exists() else {}
    for key, bucket in summary.items():
        if key in cpes:
            bucket["cpes_detected"] = cpes[key]["cpes_detected"]
            bucket["cpes_or_generic"] = cpes[key]["cpes_or_generic"]
    return {"summary_by_category": {k: dict(v) for k, v in summary.items()}, "files": files,
            "rules": {pack: {"evaluated": len(rs.rules), "unsupported": rs.unsupported} for pack, rs in rulesets.items()}}


def run_evasion() -> dict:
    from . import evasion

    variants = evasion.variants()
    out = {"variants": {}}
    for pack in PACKS:
        ruleset, dropped = _lab_ruleset(pack)
        for name in ("V0", "V1", "V3"):
            description, docs = variants[name]
            alerts = lab_alerts(docs, ruleset)
            out["variants"].setdefault(name, {"transform": description, "packs": {}})["packs"][pack] = {
                f: {"runs_consistent": _run_level(alerts, flt)["runs_consistent"], "consistent_by_technique": _run_level(alerts, flt)["consistent_by_technique"], "unit_level": _unit_level(alerts, flt)}
                for f, flt in FILTERS.items()
            }
    out["summary"] = {v: {p: b["packs"][p]["any_level"]["unit_level"]["attack_units"] for p in PACKS} for v, b in out["variants"].items()}
    return out
