"""C13 deterministic replay over supplied canonical events."""

from __future__ import annotations

from collections.abc import Iterable

from cpes.adapters.models import CanonicalEvent


class ReplayDriver:
    """Emit the same ordered canonical stream C5 supplies downstream."""

    def replay(self, events: Iterable[CanonicalEvent]) -> tuple[CanonicalEvent, ...]:
        """Preserve event values and order only by supplied timestamp and event ID."""

        return tuple(
            sorted(events, key=lambda event: (event.source_timestamp, event.source_event_id))
        )
