"""Technique-agnostic escalation test: unexplained privilege gain.

The per-mechanism signals (510-540) are precise but only cover mechanisms we have
built a signal for. This generic test provides *generalisation*: it flags a
privilege escalation for which **no bespoke signal exists**, by reasoning over
the resolved context rather than a named mechanism.

It fires when a process reaches an **elevated** integrity level via an integrity
transition that is (a) **not explained** by any resolved specific mechanism in
the window, and (b) **not attributable to a legitimate mediator** (e.g. the
``consent.exe``/AppInfo path a real interactive UAC elevation takes).

Honest trade-off: because it does not know the specific mechanism, it is broad
rather than precise — it may also fire on legitimate auto-elevating programs
(installers) that gain integrity without a consent prompt. That is the expected
generalisation-vs-precision trade-off against the specific signals, and it is
why the per-mechanism signals remain valuable. No evaluative weight is embedded
here; presence is observed and weighted downstream like any other signal.
"""

from __future__ import annotations

from cpes.context.resolver import ContextResolver
from cpes.scoring.models import SignalObservation, SourceReference
from cpes.windowing.models import EventGroup


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


class GenericEscalationObservationGenerator:
    """Emit an 'unexplained privilege gain' signal over the resolved context."""

    def __init__(
        self,
        signal_id: str,
        integrity_order: tuple[str, ...],
        resolver: ContextResolver,
        *,
        elevated_levels: tuple[str, ...] = ("high", "system"),
        legitimate_mediators: tuple[str, ...] = ("consent.exe",),
    ) -> None:
        if not signal_id or not signal_id.strip():
            raise ValueError("signal_id must be a nonblank identifier.")
        if not integrity_order or len(set(integrity_order)) != len(integrity_order):
            raise ValueError("integrity_order must be a nonempty tuple of unique levels.")
        if not isinstance(resolver, ContextResolver):
            raise ValueError("resolver must be a ContextResolver.")
        if not elevated_levels:
            raise ValueError("at least one elevated level is required.")
        self._signal_id = signal_id
        self._rank = {level.lower(): index for index, level in enumerate(integrity_order)}
        self._resolver = resolver
        self._elevated = frozenset(level.lower() for level in elevated_levels)
        self._legit = frozenset(m.lower() for m in legitimate_mediators)

    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        # processes already accounted for by a specific mechanism are not "unexplained"
        explained = {
            resolved.anchor_process_guid
            for resolved in self._resolver.resolve(
                event_group,
                pipe_evidence=event_group.pipe_evidence,
                remote_thread_evidence=event_group.remote_thread_evidence,
                service_install_evidence=event_group.service_install_evidence,
            )
        }
        image_by_guid = {
            event.process_guid: _basename(event.image_path) for event in event_group.events
        }
        references: list[SourceReference] = []
        for transition in event_group.integrity_transitions:
            child_rank = self._rank.get(transition.child_integrity_level.lower())
            parent_rank = self._rank.get(transition.parent_integrity_level.lower())
            if child_rank is None or parent_rank is None:
                continue
            # an actual privilege gain into an elevated level
            if child_rank <= parent_rank:
                continue
            if transition.child_integrity_level.lower() not in self._elevated:
                continue
            # explained by a specific mechanism -> not "unexplained"
            if transition.child_process_guid in explained:
                continue
            # attributable to a legitimate mediator (consented interactive elevation) -> not flagged
            if image_by_guid.get(transition.parent_process_guid) in self._legit:
                continue
            references.append(SourceReference(transition.child_process_guid))
        return (SignalObservation(self._signal_id, bool(references), tuple(references)),)
