"""Observation generators that consume the re-associated (resolved) context.

These keep the pipeline seam unchanged (each is an ``ObservationGenerator`` with
``generate(event_group)``), but instead of reading a single event field they read
the cross-channel ``ResolvedContext`` produced by ``ContextResolver``. This is
what makes context re-association *load-bearing*: e.g. the auto-elevation signal
fires only when the elevated LOLBin has been re-associated with the actor's
hijack registry write, not merely because an image ran at High integrity.

One resolver instance is shared across generators; each generator emits one
signal for one ``anchor_kind``. Weights remain corpus-derived and applied in C9.
"""

from __future__ import annotations

from cpes.context.resolver import ContextResolver
from cpes.scoring.models import SignalObservation, SourceReference
from cpes.windowing.models import EventGroup


class ResolvedSignalObservationGenerator:
    """Emit one signal from resolved contexts of a given anchor kind."""

    def __init__(self, signal_id: str, resolver: ContextResolver, anchor_kind: str) -> None:
        if not signal_id or not signal_id.strip():
            raise ValueError("signal_id must be a nonblank identifier.")
        if not isinstance(resolver, ContextResolver):
            raise ValueError("resolver must be a ContextResolver.")
        if not anchor_kind or not anchor_kind.strip():
            raise ValueError("anchor_kind must be a nonblank identifier.")
        self._signal_id = signal_id
        self._resolver = resolver
        self._anchor_kind = anchor_kind

    def generate(self, event_group: EventGroup) -> tuple[SignalObservation, ...]:
        resolved = self._resolver.resolve(
            event_group,
            pipe_evidence=event_group.pipe_evidence,
            remote_thread_evidence=event_group.remote_thread_evidence,
            service_install_evidence=event_group.service_install_evidence,
        )
        references = tuple(
            SourceReference(context.anchor_process_guid)
            for context in resolved
            if context.anchor_kind == self._anchor_kind
        )
        return (SignalObservation(self._signal_id, bool(references), references),)
