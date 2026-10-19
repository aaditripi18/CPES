"""Group alerts from several detectors into incidents (analyst-facing, additive).

Backend-neutral and deterministic. An alert concerns one process and may name
related processes (for a CPES alert: the resolver's actor). Two alerts join the
same incident when they concern the same process, when their processes are
within two generations of each other in the lineage and their times are at most
``gap_seconds`` apart, or when one alert's related process is the other's
process (a cross-channel link recorded by the resolver). Incidents are the
connected components. See docs/design/incident-correlation.md.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Alert:
    id: str
    source: str  # "sigma" | "cpes" | any detector name
    time: datetime
    process_guid: str | None
    title: str
    level: str = "high"
    tags: tuple[str, ...] = ()
    related_guids: tuple[str, ...] = ()
    detail: Mapping = field(default_factory=dict)


@dataclass(frozen=True)
class Incident:
    id: str
    alerts: tuple[Alert, ...]
    start: datetime
    end: datetime
    processes: tuple[str, ...]
    outcome_processes: tuple[str, ...]  # processes a CPES alert flagged as elevated
    sources: tuple[str, ...]
    level: str
    tags: tuple[str, ...]


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _ancestors(guid: str, parent_of: Mapping[str, str | None], depth: int = 2) -> set[str]:
    found, current = set(), guid
    for _ in range(depth):
        current = parent_of.get(current)
        if current is None:
            break
        found.add(current)
    return found


def _within_two_generations(a: str, b: str, parent_of: Mapping[str, str | None]) -> bool:
    """Same process, or one is the other's parent or grandparent (siblings are not linked)."""

    return a == b or b in _ancestors(a, parent_of) or a in _ancestors(b, parent_of)


def correlate(alerts: Iterable[Alert], parent_of: Mapping[str, str | None], *, gap_seconds: float = 300.0, outcome_source: str = "cpes") -> list[Incident]:
    items = sorted(alerts, key=lambda a: (a.time, a.id))
    uf = _UnionFind(len(items))
    by_process: dict[str, list[int]] = defaultdict(list)
    for index, alert in enumerate(items):
        if alert.process_guid:
            by_process[alert.process_guid].append(index)
    for indices in by_process.values():  # rule 1
        for other in indices[1:]:
            uf.union(indices[0], other)
    for index, alert in enumerate(items):  # rule 3
        for related in alert.related_guids:
            for other in by_process.get(related, ()):
                uf.union(index, other)
    # rule 2: lineage within two generations and time gap (sweep over time order)
    for i, a in enumerate(items):
        if not a.process_guid:
            continue
        for j in range(i + 1, len(items)):
            b = items[j]
            if (b.time - a.time).total_seconds() > gap_seconds:
                break
            if b.process_guid and _within_two_generations(a.process_guid, b.process_guid, parent_of):
                uf.union(i, j)
    groups: dict[int, list[Alert]] = defaultdict(list)
    for index, alert in enumerate(items):
        groups[uf.find(index)].append(alert)
    incidents = []
    for number, members in enumerate(sorted(groups.values(), key=lambda g: (g[0].time, g[0].id)), start=1):
        processes = sorted({a.process_guid for a in members if a.process_guid})
        outcome = sorted({a.process_guid for a in members if a.source == outcome_source and a.process_guid})
        level = max((a.level for a in members), key=lambda l: LEVEL_RANK.get(l, 0))
        incidents.append(Incident(
            id=f"INC-{number:04d}", alerts=tuple(members), start=members[0].time, end=max(a.time for a in members),
            processes=tuple(processes), outcome_processes=tuple(outcome), sources=tuple(sorted({a.source for a in members})),
            level=level, tags=tuple(sorted({t for a in members for t in a.tags})),
        ))
    return incidents
