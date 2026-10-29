"""Analyst outputs for a run: incidents (CPES + optional Sigma), a Markdown
incident report, a MITRE ATT&CK Navigator layer and ECS alert documents.

Everything here is derived from artifacts the run already recorded (export,
resolver audit, processes) plus, when requested, SigmaHQ rule matches. Nothing
is invented: a field with no source is omitted, not filled in.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from functools import lru_cache
from typing import Any

from cpes.correlation import Alert, correlate

from .paths import REPO_ROOT

SIGMA_CORE = REPO_ROOT / "external" / "sigma" / "core"
# ATT&CK techniques each CPES signal is designed to detect. A CPES alert's
# technique is this design mapping, not a claim about what the attacker did: the
# service rule also fires on RoguePotato (token impersonation), for example.
TECHNIQUE_NOTE = "CPES techniques are the technique each signal was designed for, not a verified attribution; Sigma techniques are the rule's own ATT&CK tags."
SIGNAL_TECHNIQUE = {
    "autoelevation_lolbin": ("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control"),
    "service_dropped_binary": ("T1543.003", "Create or Modify System Process: Windows Service"),
    "remote_thread_injection": ("T1055", "Process Injection"),
    "token_impersonation": ("T1134.001", "Access Token Manipulation: Token Impersonation/Theft"),
}


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _basename(path: Any) -> str | None:
    return str(path).replace("/", "\\").split("\\")[-1] if path else None


# --------------------------------------------------------------------------- Sigma


def sigma_available() -> dict[str, Any]:
    present = SIGMA_CORE.exists()
    return {"available": present, "pack": "SigmaHQ core r2026-07-01" if present else None,
            "how": None if present else "Run `python scripts/fetch_external.py` to download the SigmaHQ rule packs."}


@lru_cache(maxsize=2)
def _sigma_rules(drop_details: bool):
    """Core pack; on ECS input, rules testing registry ``Details`` are dropped (not reproducible from ECS), as in sigma-lab-v3."""

    from evaluation.sigma import RuleSet, load_rules

    ruleset = load_rules(SIGMA_CORE)
    if not drop_details:
        return ruleset
    return RuleSet([r for r in ruleset.rules if "Details" not in r.fields], ruleset.unsupported, ruleset.skipped_examples)


def run_sigma(parsed, record_indices: list[int], preset: str | None) -> tuple[list[dict], dict[str, Any]]:
    """Match SigmaHQ core rules on the accepted records (ECS or raw EVTX presets)."""

    from evaluation.sigma import match_events
    from evaluation.sigma_eval import ecs_view, evtx_view

    if not SIGMA_CORE.exists():
        return [], {"enabled": False, "reason": sigma_available()["how"]}
    ecs = preset in ("elastic-sysmon-field-mapping-v1", "elastic-sysmon-field-mapping-v2")
    if ecs:
        view, timestamp = ecs_view, lambda d: d.get("@timestamp")
    elif preset in ("evtx-sysmon-field-mapping-v1", "evtx-sysmon-field-mapping-v2"):
        view, timestamp = evtx_view, lambda d: d["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
    else:
        return [], {"enabled": False, "reason": "Sigma field views exist for the Winlogbeat/ECS and raw EVTX presets only."}
    ruleset = _sigma_rules(ecs)
    documents, views = [], []
    for index in record_indices:
        document = parsed.document(index)
        if preset == "evtx-sysmon-field-mapping-v1" and not str(((document.get("Event") or {}).get("System") or {}).get("Channel", "")).endswith("Sysmon/Operational"):
            continue
        documents.append((index, document))
        views.append(view(document))
    alerts = []
    for position, rule in match_events(ruleset, views):
        if rule.level not in ("high", "critical"):
            continue
        index, document = documents[position]
        fields = views[position][1]
        alerts.append({
            "id": f"sigma:{len(alerts)}", "source": "sigma", "time": timestamp(document), "record_index": index,
            "process_guid": fields.get("ProcessGuid"), "image": _basename(fields.get("Image")),
            "title": rule.title, "rule_id": rule.id, "level": rule.level, "tags": list(rule.tags),
        })
    return alerts, {"enabled": True, "pack": "SigmaHQ core r2026-07-01", "rules": len(ruleset.rules), "levels": "high, critical", "alerts": len(alerts)}


# --------------------------------------------------------------------- incidents


def cpes_alerts(export: dict, audit: dict, processes: dict) -> list[dict]:
    """One alert per (elevated process, signal), timed at the process's first event."""

    out: dict[tuple[str, str], dict] = {}
    for index, record in enumerate(export["detections"]):
        if not record["is_detected"]:
            continue
        resolved = (audit.get(str(index)) or {}).get("resolved", [])
        actors = {r["anchor_process_guid"]: r["actor_process_guid"] for r in resolved}
        paths = {r["anchor_process_guid"]: r["resolution_path"] for r in resolved}
        for contribution in record["contributions"]:
            for reference in contribution["source_references"]:
                guid = reference["process_guid"]
                key = (guid, contribution["signal_id"])
                if key in out:
                    continue
                info = processes.get(guid) or {}
                technique = SIGNAL_TECHNIQUE.get(contribution["signal_id"])
                out[key] = {
                    "id": f"cpes:{contribution['signal_id']}:{guid}", "source": "cpes",
                    "time": info.get("first_seen") or record["window_start"], "process_guid": guid, "image": _basename(info.get("image_path")),
                    "title": f"CPES: {contribution['signal_id']}", "level": "high", "signal_id": contribution["signal_id"],
                    "weight": contribution["signed_log_likelihood"], "window_index": index, "score": record["cpes_score"],
                    "actor_process_guid": actors.get(guid), "explanation": paths.get(guid, []),
                    "tags": [f"attack.{technique[0].lower()}"] if technique else [],
                }
    return list(out.values())


def build_incidents(cpes: list[dict], sigma: list[dict], processes: dict) -> list[dict]:
    parent_of = {guid: info.get("parent_process_guid") for guid, info in processes.items()}
    by_id = {a["id"]: a for a in cpes + sigma}
    alerts = [
        Alert(id=a["id"], source=a["source"], time=_ts(a["time"]), process_guid=a.get("process_guid"), title=a["title"], level=a.get("level", "high"),
              tags=tuple(a.get("tags", ())), related_guids=(a["actor_process_guid"],) if a.get("actor_process_guid") and a.get("actor_process_guid") != a.get("process_guid") else ())
        for a in by_id.values()
    ]
    incidents = []
    for incident in correlate(alerts, parent_of, gap_seconds=300.0):
        members = [by_id[a.id] for a in incident.alerts]
        techniques = sorted({t.split(".", 1)[1].upper() for t in incident.tags if t.startswith("attack.t")})
        incidents.append({
            "id": incident.id, "start": incident.start.isoformat(), "end": incident.end.isoformat(), "level": incident.level,
            "sources": list(incident.sources), "techniques": techniques,
            "outcome": [{"process_guid": g, "image": _basename((processes.get(g) or {}).get("image_path")), "integrity_level": (processes.get(g) or {}).get("integrity_level")} for g in incident.outcome_processes],
            "processes": list(incident.processes), "alerts": members,
            "headline": _headline(members),
        })
    return incidents


def _headline(members: list[dict]) -> str:
    cpes = [m for m in members if m["source"] == "cpes"]
    if cpes:
        first = cpes[0]
        return f"{first.get('image') or 'process'} gained privilege ({first['signal_id']})" + (f", with {sum(m['source'] == 'sigma' for m in members)} related Sigma alert(s)" if any(m["source"] == "sigma" for m in members) else "")
    titles = Counter(m["title"] for m in members)
    return f"{titles.most_common(1)[0][0]}" + (f" (+{len(members) - 1} more)" if len(members) > 1 else "")


# ------------------------------------------------------------------------ outputs


def report_markdown(run: dict, incident: dict) -> str:
    config = run.get("config") or {}
    dataset = config.get("dataset", {})
    lines = [
        f"# Incident {incident['id']} — {incident['headline']}", "",
        f"* Run: `{run['id']}` · dataset: {dataset.get('name')} (`{dataset.get('id')}`, SHA-256 `{(dataset.get('sha256') or '')[:16]}…`)",
        f"* Time: {incident['start']} → {incident['end']}",
        f"* Highest level: **{incident['level']}** · sources: {', '.join(incident['sources'])}",
        f"* ATT&CK techniques: {', '.join(incident['techniques']) or '—'} ({TECHNIQUE_NOTE})",
        "",
    ]
    if incident["outcome"]:
        lines += ["## Process that gained privilege (CPES)", ""]
        for item in incident["outcome"]:
            lines.append(f"* `{item['image']}` — integrity {item['integrity_level'] or 'unknown'} — `{item['process_guid']}`")
        lines.append("")
    else:
        lines += ["## Process that gained privilege", "", "CPES did not flag an elevated process in this incident.", ""]
    lines += ["## Timeline", "", "| Time | Source | Alert | Process |", "|---|---|---|---|"]
    for alert in sorted(incident["alerts"], key=lambda a: a["time"]):
        lines.append(f"| {alert['time']} | {alert['source']} | {alert['title']} ({alert.get('level')}) | `{alert.get('image') or '—'}` |")
    explanations = [line for a in incident["alerts"] if a["source"] == "cpes" for line in a.get("explanation", [])]
    if explanations:
        lines += ["", "## Evidence chain (CPES resolver)", ""] + [f"* {line}" for line in explanations]
    cpes = [a for a in incident["alerts"] if a["source"] == "cpes"]
    if cpes:
        lines += ["", "## Score", ""]
        for a in cpes:
            lines.append(f"* {a['signal_id']}: weight {float(a['weight']):+.4f}; window score {float(a['score']):.4f} ≥ threshold {config.get('threshold')} (window #{a['window_index']})")
    lines += ["", "---", f"Generated by the CPES dashboard from recorded run artifacts. Evidence model `{(config.get('evidence_model') or {}).get('id')}`, engine `{config.get('engine')}`.", ""]
    return "\n".join(lines)


def attack_layer(run: dict, incidents: list[dict]) -> dict:
    """MITRE ATT&CK Navigator layer (format 4.5) of the techniques alerted in this run."""

    counts: Counter = Counter()
    sources: dict[str, set] = {}
    for incident in incidents:
        for alert in incident["alerts"]:
            for tag in alert.get("tags", []):
                if tag.startswith("attack.t"):
                    technique = tag.split(".", 1)[1].upper()
                    counts[technique] += 1
                    sources.setdefault(technique, set()).add(alert["source"])
    top = max(counts.values(), default=1)
    return {
        "name": f"CPES run {run['id']}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques alerted in CPES run {run['id']} on dataset {run.get('dataset_id')}. Score = number of alerts. " + TECHNIQUE_NOTE,
        "techniques": [{"techniqueID": t, "score": n, "comment": f"{n} alert(s) from {', '.join(sorted(sources[t]))}"} for t, n in sorted(counts.items())],
        "gradient": {"colors": ["#ffffff", "#ff7b6b"], "minValue": 0, "maxValue": top},
        "legendItems": [], "showTacticRowBackground": True,
    }


def ecs_alerts(run: dict, cpes: list[dict]) -> str:
    """One ECS alert document per CPES alert (newline-delimited JSON)."""

    lines = []
    for alert in cpes:
        technique = SIGNAL_TECHNIQUE.get(alert["signal_id"])
        document = {
            "@timestamp": alert["time"],
            "event": {"kind": "alert", "category": ["process"], "type": ["info"], "module": "cpes", "dataset": "cpes.alerts"},
            "rule": {"name": f"CPES {alert['signal_id']}", "id": alert["signal_id"], "ruleset": "cpes", "description": " ".join(alert.get("explanation") or []) or None},
            "process": {"entity_id": alert["process_guid"], "name": alert.get("image")},
            "threat": {"framework": "MITRE ATT&CK", "tactic": {"id": ["TA0004"], "name": ["Privilege Escalation"]},
                       "technique": {"id": [technique[0]], "name": [technique[1]]} if technique else None},
            "cpes": {"run_id": run["id"], "window_index": alert["window_index"], "weight": alert["weight"], "score": alert["score"], "actor_process_guid": alert.get("actor_process_guid")},
        }
        lines.append(json.dumps(_drop_none(document), ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def _drop_none(value):
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    return value
