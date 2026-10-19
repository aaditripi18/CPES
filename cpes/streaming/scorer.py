"""Score detection windows as they close, using the unchanged CpesPipeline.

Windows lie on a fixed grid ``start_at + k * advance`` with length ``span``.
When the event-time watermark passes a window's end, that window is scored
exactly once, with everything that had arrived by then. Scoring re-runs
``CpesPipeline`` on all events received so far but asks it only for the newly
closed windows, so lineage, context and resolver behaviour are the package's
own. Cost is linear in the events seen so far per tick, which is fine for one
endpoint; a production version would bound the history.

Live and batch results can differ, and that difference is real: a chain that is
later joined to another (a parent's events arrive late) has a different event
group in hindsight. ``evaluation.streaming`` measures it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from cpes.adapters.models import CanonicalEvent
from cpes.detection.models import ThresholdDecision
from cpes.orchestration import CpesPipeline, PipelineConfiguration
from cpes.orchestration.models import WindowObservations
from cpes.scoring.models import EvidenceModel
from cpes.windowing.models import SlidingWindowParameters


@dataclass(frozen=True)
class ClosedWindow:
    """One window scored at close time, with what was known then."""

    index: int  # grid position k
    scored_at_watermark: datetime
    window: WindowObservations
    decision: ThresholdDecision
    events_known: int


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class StreamingScorer:
    def __init__(
        self,
        *,
        start_at: datetime,
        span_seconds: float,
        advance_seconds: float,
        evidence_model: EvidenceModel,
        detection_threshold: Decimal,
        observation_generator,
        pipeline: CpesPipeline | None = None,
    ) -> None:
        if span_seconds <= 0 or advance_seconds <= 0:
            raise ValueError("span and advance must be positive.")
        if advance_seconds > span_seconds:
            raise ValueError("advance must not exceed span, or events between windows are never scored.")
        if start_at.tzinfo is None:
            raise ValueError("start_at must include an offset.")
        self._start = start_at
        self._span = timedelta(seconds=span_seconds)
        self._advance = timedelta(seconds=advance_seconds)
        self._model = evidence_model
        self._threshold = detection_threshold
        self._generator = observation_generator
        self._pipeline = pipeline or CpesPipeline()
        self._events: list[CanonicalEvent] = []
        self._evidence: list = []
        self._next = 0  # first grid index not yet scored
        self._watermark = start_at

    @property
    def events_received(self) -> int:
        return len(self._events)

    @property
    def watermark(self) -> datetime:
        return self._watermark

    def window_bounds(self, index: int) -> tuple[datetime, datetime]:
        start = self._start + self._advance * index
        return start, start + self._span

    def ingest(self, events: Iterable[CanonicalEvent] = (), evidence: Iterable = ()) -> None:
        """Add arrived events (any order); events before ``start_at`` are kept for lineage."""

        self._events.extend(events)
        self._evidence.extend(evidence)

    def advance_to(self, watermark: datetime) -> list[ClosedWindow]:
        """Score every window that ends at or before ``watermark`` and was not scored yet."""

        if watermark < self._watermark:
            raise ValueError("watermark must not move backwards.")
        self._watermark = watermark
        last = self._next
        while self.window_bounds(last)[1] <= watermark:
            last += 1
        if last == self._next or not self._events:
            self._next = last if not self._events else self._next
            return []
        first_start, _ = self.window_bounds(self._next)
        _, last_end = self.window_bounds(last - 1)
        configuration = PipelineConfiguration(
            SlidingWindowParameters(first_start, last_end, self._span.total_seconds(), self._advance.total_seconds()),
            self._model, self._threshold, self._generator,
        )
        context = self._pipeline.run(self._events, configuration, evidence=self._evidence)
        closed = []
        for item, decision in zip(context.window_observations, context.threshold_decisions):
            offset = item.detection_window.start_at - self._start
            index = round(offset / self._advance)
            closed.append(ClosedWindow(index, watermark, item, decision, len(self._events)))
        self._next = last
        return closed

    def flush(self) -> list[ClosedWindow]:
        """Close every window that contains the latest received event."""

        if not self._events:
            return []
        latest = max(_ts(e.source_timestamp) for e in self._events)
        return self.advance_to(max(self._watermark, latest + self._span))
