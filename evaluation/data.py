"""Inputs shared by all protocols: corpus process units, labels, ledger, groups.

The research replication here (process nodes, groups, the two research
baselines) mirrors analysis/corpus_eval_grouped.py line for line in meaning; it
is checked by the ``research-grouped`` protocol, which must reproduce that
script's printed figures exactly before any other protocol is trusted.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "analysis" / "corpus-v3.ndjson"
LEDGER_CSV = ROOT / "analysis" / "cpes-atomic-log-v3.csv"
LABELS = ROOT / "Claude outputs" / "cpes_privilege_escalation_dataset.csv"

SIGNALS = ("autoelevation_lolbin", "service_dropped_binary", "remote_thread_injection", "token_impersonation")
SIGNAL_TECHNIQUES = {
    "autoelevation_lolbin": ("T1548.002",),
    "service_dropped_binary": ("T1543.003",),
    "remote_thread_injection": ("T1055.001",),
    "token_impersonation": ("T1134.001", "T1134.002"),
}
LOL = ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe")
RANK = {"untrusted": 0, "low": 1, "appcontainer": 1, "medium": 2, "high": 3, "system": 4}
TOLERANCE_SECONDS = 150


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _bn(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


@dataclass(frozen=True)
class Unit:
    """One process instance with a ProcessCreate record (the research unit)."""

    guid: str
    parent: str | None
    image: str
    integrity: str
    created_at: datetime
    is_attack: bool
    technique: str | None
    research_signals: tuple[str, ...]


@lru_cache(maxsize=1)
def documents() -> tuple[dict, ...]:
    with CORPUS.open(encoding="utf-8") as handle:
        return tuple(json.loads(line) for line in handle)


@lru_cache(maxsize=1)
def ledger_runs() -> tuple[tuple[str, datetime], ...]:
    with LEDGER_CSV.open(encoding="utf-8", newline="") as handle:
        return tuple((row["Technique"].split()[0].upper(), _ts(row["Execution Time (UTC)"])) for row in csv.DictReader(handle))


@lru_cache(maxsize=1)
def units() -> tuple[Unit, ...]:
    labels = {}
    with LABELS.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            labels[row["instance_id"]] = row
    out = []
    seen = set()
    for document in documents():
        if str(document.get("event", {}).get("code")) != "1":
            continue
        process = document.get("process", {})
        guid = process.get("entity_id")
        if not guid or guid in seen:
            continue
        seen.add(guid)
        row = labels[guid]  # every create event has a labelled row; KeyError would mean a data mismatch
        out.append(Unit(
            guid=guid,
            parent=(process.get("parent") or {}).get("entity_id"),
            image=_bn(process.get("executable")),
            integrity=((document.get("winlog", {}).get("event_data", {}) or {}).get("IntegrityLevel") or "").lower(),
            created_at=_ts(document["@timestamp"]),
            is_attack=row["label_is_escalation"] == "1",
            technique=None if row["technique"] == "benign" else row["technique"],
            research_signals=tuple(signal for signal in SIGNALS if row[f"sig_{signal}"] == "1"),
        ))
    if len(out) != len(labels):
        raise ValueError(f"corpus has {len(out)} process units but the label table has {len(labels)} rows.")
    return tuple(out)


def research_group(unit: Unit) -> str:
    """Group key exactly as corpus_eval_grouped.py builds it."""

    if not unit.is_attack:
        return "benign_" + hashlib.sha256(unit.guid.encode()).hexdigest()[:6]
    techniques = SIGNAL_TECHNIQUES["token_impersonation"] if unit.technique and unit.technique.startswith("T1134") else (unit.technique,)
    runs = defaultdict(list)
    for technique, at in ledger_runs():
        runs[technique].append(at)
    for technique in techniques:
        for at in runs.get(technique, ()):
            if abs((unit.created_at - at).total_seconds()) <= TOLERANCE_SECONDS:
                return f"{technique}@{at:%H%M%S}"
    raise ValueError(f"attack unit {unit.guid} matches no logged run.")


def fold_of(group: str, folds: int = 5) -> int:
    return int(hashlib.sha256(group.encode()).hexdigest(), 16) % folds


def research_baselines() -> dict[str, set[str]]:
    """Process GUIDs flagged by the two research baselines (b1, b2 in the scripts)."""

    by_guid = {unit.guid: unit for unit in units()}
    rank = lambda level: RANK.get(level, -1)  # noqa: E731
    single_event = {
        unit.guid for unit in units()
        if unit.parent in by_guid and rank(by_guid[unit.parent].integrity) >= 0 and rank(unit.integrity) > rank(by_guid[unit.parent].integrity)
    }
    ioc = {unit.guid for unit in units() if (unit.image in LOL and unit.integrity == "high") or unit.image == "mavinject.exe"}
    return {"single_event_research": single_event, "ioc_signature_research": ioc}


def inputs_manifest() -> list[dict]:
    return [{"path": str(path.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(path)} for path in (CORPUS, LEDGER_CSV, LABELS)]
