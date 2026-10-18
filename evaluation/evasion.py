"""Protocol evasion-v3: do detections survive cheap attacker-controlled changes?

Pre-registered in docs/design/external-and-evasion-evaluation.md (Part B). Each
variant is a deterministic transform of corpus-v3 that touches only the records
of labelled attack processes and artifacts they control (pipe names are renamed
by a bijection, which cannot change benign pairing). Labels never change.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter

from . import data, engine, research_signals

WSRESET_PE = {"original_file_name": "WSReset.exe", "description": "This tool resets the Windows Store without changing account settings or deleting installed apps", "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation"}
RENAMES = {"V1": ("mavinject.exe", "msupdhlp.exe"), "V3_target": "wsreset.exe", "V2_target": "svchost_update.exe"}
TECHNIQUES = ("T1055.001", "T1134.001", "T1543.003", "T1548.002")


def _bn(path) -> str:
    return str(path or "").replace("/", "\\").split("\\")[-1]


def _rename_path(path: str | None, old_lower: set[str], new: str) -> str | None:
    if not path or _bn(path).lower() not in old_lower:
        return path
    head = path[: len(path) - len(_bn(path))]
    return head + new


def _rename_in_doc(doc: dict, old_lower: set[str], new: str, guids: set[str] | None, pe: dict | None = None) -> dict:
    """Rename an image (and references to it) in one document, if it concerns ``guids``."""

    process = doc.get("process") or {}
    parent = process.get("parent") or {}
    own = guids is None or process.get("entity_id") in guids
    child_of = guids is None or parent.get("entity_id") in guids
    if not (own or child_of):
        return doc
    doc = copy.deepcopy(doc)
    process = doc.get("process") or {}
    if own and process.get("executable") and _bn(process["executable"]).lower() in old_lower:
        old = _bn(process["executable"])
        process["executable"] = _rename_path(process["executable"], old_lower, new)
        if process.get("name"):
            process["name"] = new
        if process.get("command_line"):
            process["command_line"] = re.sub(re.escape(old), new, process["command_line"], flags=re.IGNORECASE)
        if isinstance(process.get("args"), list) and process["args"]:
            process["args"][0] = _rename_path(process["args"][0], old_lower, new)
        if pe is not None:  # a different binary carries its own PE header; a renamed copy (pe=None) keeps its own
            process.setdefault("pe", {}).update(pe)
            event_data = (doc.get("winlog") or {}).get("event_data")
            if isinstance(event_data, dict) and "Description" in event_data:
                event_data["Description"] = pe.get("description", event_data["Description"])
    parent = process.get("parent") or {}
    if child_of and parent.get("executable") and _bn(parent["executable"]).lower() in old_lower:
        parent["executable"] = _rename_path(parent["executable"], old_lower, new)
        if parent.get("name"):
            parent["name"] = new
    return doc


def _attack_guids(technique_prefix: str | None = None) -> set[str]:
    return {u.guid for u in data.units() if u.is_attack and (technique_prefix is None or (u.technique or "").startswith(technique_prefix))}


def variants() -> dict[str, tuple[str, list[dict]]]:
    docs = list(data.documents())
    out: dict[str, tuple[str, list[dict]]] = {"V0": ("none (gate: must equal the published table)", docs)}

    old, new = RENAMES["V1"]
    out["V1"] = (f"renamed injector: {old} → {new} (all mavinject processes are attack processes)", [_rename_in_doc(d, {old}, new, None) for d in docs])

    service_guids = _attack_guids("T1543.003")
    service_images = {_bn((d.get("process") or {}).get("executable")).lower() for d in docs if (d.get("process") or {}).get("entity_id") in service_guids}
    out["V2"] = (f"renamed dropped service binary: {sorted(service_images)} → {RENAMES['V2_target']}", [_rename_in_doc(d, service_images, RENAMES["V2_target"], service_guids) for d in docs])

    uac_guids = _attack_guids("T1548.002")
    lol = set(research_signals.LOL)
    out["V3"] = (f"unlisted auto-elevating binary: {sorted(lol)} → {RENAMES['V3_target']} on the elevated attack processes", [_rename_in_doc(d, lol, RENAMES["V3_target"], uac_guids, pe=WSRESET_PE) for d in docs])

    def pipe(name: str) -> str:
        return "\\" + hashlib.sha256(name.encode()).hexdigest()[:12]

    v4 = []
    for d in docs:
        if str(d.get("event", {}).get("code")) in ("17", "18") and (d.get("file") or {}).get("name"):
            d = copy.deepcopy(d)
            d["file"]["name"] = pipe(d["file"]["name"])
        v4.append(d)
    out["V4"] = ("random but consistent pipe names (bijection over every pipe name)", v4)

    attack = _attack_guids()

    def noisy(text: str) -> str:
        return re.sub(r"([A-Za-z]{3})", r"\1^", text)

    v5 = []
    for d in docs:
        process = d.get("process") or {}
        if process.get("entity_id") in attack and process.get("command_line"):
            d = copy.deepcopy(d)
            d["process"]["command_line"] = noisy(d["process"]["command_line"])
        v5.append(d)
    out["V5"] = ("caret-obfuscated command lines on attack processes", v5)
    return out


def _score(flagged: set[str]) -> dict:
    units = data.units()
    recall = {}
    for technique in TECHNIQUES:
        # Token labels are T1134.001/.002; the others are matched exactly.
        match = (lambda t: t.startswith("T1134")) if technique.startswith("T1134") else (lambda t, want=technique: t == want)
        attack = [u for u in units if u.is_attack and match(u.technique or "")]
        recall[technique] = f"{sum(u.guid in flagged for u in attack)}/{len(attack)}"
    return {
        "recall_by_technique": recall,
        "attack_detected": f"{sum(u.guid in flagged for u in units if u.is_attack)}/{sum(u.is_attack for u in units)}",
        "benign_flagged": sum(u.guid in flagged for u in units if not u.is_attack),
    }


def run() -> dict:
    table = {u.guid: u.research_signals for u in data.units()}
    results = {}
    for name, (description, docs) in variants().items():
        flags = research_signals.signal_flags(docs)
        if name == "V0" and any(tuple(flags.get(g, ())) != s for g, s in table.items()):
            raise ValueError("replication gate failed: V0 research signals differ from the labelled table.")
        base = research_signals.baselines(docs)
        package = engine.run_package(with_evidence=True, docs=docs, generic=True)
        detectors = {
            "cpes_research_signals": {g for g, s in flags.items() if s},
            "cpes_package": {g for g, s in package["flags"].items() if s},
            "generic_unexplained_gain_package": package["generic_flags"],
            "ioc_signature_research": base["ioc_signature_research"],
            "single_event_research": base["single_event_research"],
        }
        results[name] = {"transform": description, "detectors": {k: _score(v) for k, v in detectors.items()}}
    return {
        "summary": {name: {d: s["attack_detected"] for d, s in body["detectors"].items()} for name, body in results.items()},
        "note": "CPES decisions are the OR of signals (every research weight exceeds the 0.5 threshold); in-sample labels; the question is change under transformation, not absolute accuracy.",
        "variants": results,
    }
