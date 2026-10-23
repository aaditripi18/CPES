"""Backend-neutral models for supplied sliding-window parameters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cpes.context.models import (
    ContextEvent,
    IntegrityTransition,
    PipeEvidence,
    RemoteThreadEvidence,
    ServiceInstallEvidence,
)


@dataclass(frozen=True)
class SlidingWindowParameters:
    """Explicit bounds and advancement supplied by the caller."""

    start_at: datetime
    horizon_end_at: datetime
    span_seconds: float
    advance_seconds: float


@dataclass(frozen=True)
class EventGroup:
    """Windowed events plus derived context for one lineage chain (Bible §8.5).

    Per the Project Bible, an event group is ``windowed events + derived
    context``. ``integrity_transitions`` carries the parent->child integrity
    transitions whose participating processes both fall inside this window, so
    that context-aware observation generators can reason over lineage
    relationships and not just per-event fields. It defaults to empty for
    callers that assemble structural groups without derived context.
    """

    lineage_chain_id: str
    events: tuple[ContextEvent, ...]
    is_truncated: bool
    is_incomplete: bool
    is_fragmented: bool
    integrity_transitions: tuple[IntegrityTransition, ...] = ()
    pipe_evidence: tuple[PipeEvidence, ...] = ()
    remote_thread_evidence: tuple[RemoteThreadEvidence, ...] = ()
    service_install_evidence: tuple[ServiceInstallEvidence, ...] = ()


@dataclass(frozen=True)
class DetectionWindow:
    """One concrete bounded window and its structural event group."""

    start_at: datetime
    end_at: datetime
    event_group: EventGroup
