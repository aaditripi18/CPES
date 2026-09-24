"""C5/C13 downstream event-stream contract."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from .models import CanonicalEvent


class CanonicalEventStream(Protocol):
    """Provide an ordered backend-neutral stream to C5 downstream consumers."""

    def events(self) -> Iterable[CanonicalEvent]:
        """Yield canonical events ordered by source timestamp then source event ID."""

