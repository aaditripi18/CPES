"""Deterministic bounded event-group assembly from supplied inputs."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from cpes.context.models import ContextEvent, LineageContext

from .models import DetectionWindow, EventGroup, SlidingWindowParameters


class WindowManager:
    """Assemble fixed-span windows without inferring events or timestamps."""

    def assemble(
        self,
        lineage_context: LineageContext,
        parameters: SlidingWindowParameters,
    ) -> tuple[DetectionWindow, ...]:
        """Assemble windows using only supplied events and supplied parameters."""

        self._validate_parameters(parameters)
        event_group_events = self._ordered_events(lineage_context.events)
        span = timedelta(seconds=parameters.span_seconds)
        advance = timedelta(seconds=parameters.advance_seconds)
        windows: list[DetectionWindow] = []
        window_start = parameters.start_at
        while window_start + span <= parameters.horizon_end_at:
            window_end = window_start + span
            included_events = tuple(
                event
                for event in event_group_events
                if window_start <= event.occurred_at < window_end
            )
            windows.append(
                DetectionWindow(
                    start_at=window_start,
                    end_at=window_end,
                    event_group=EventGroup(
                        lineage_chain_id=lineage_context.lineage_chain_id,
                        events=included_events,
                        is_truncated=lineage_context.is_truncated,
                        is_incomplete=lineage_context.is_incomplete,
                        is_fragmented=lineage_context.is_fragmented,
                        integrity_transitions=self._windowed_transitions(
                            lineage_context, included_events
                        ),
                    ),
                )
            )
            window_start += advance
        return tuple(windows)

    @staticmethod
    def _windowed_transitions(
        lineage_context: LineageContext,
        included_events: tuple[ContextEvent, ...],
    ) -> tuple:
        """Scope derived integrity transitions to processes present in the window.

        A transition is admitted only when both its parent and child process
        have at least one event inside this window, so the relationship is
        genuinely observable within the bounded interval.
        """

        window_process_guids = {event.process_guid for event in included_events}
        return tuple(
            transition
            for transition in lineage_context.integrity_transitions
            if transition.parent_process_guid in window_process_guids
            and transition.child_process_guid in window_process_guids
        )

    @staticmethod
    def _validate_parameters(parameters: SlidingWindowParameters) -> None:
        if parameters.span_seconds <= 0:
            raise ValueError("span_seconds must be positive.")
        if parameters.advance_seconds <= 0:
            raise ValueError("advance_seconds must be positive.")
        if parameters.horizon_end_at < parameters.start_at:
            raise ValueError("horizon_end_at must not precede start_at.")

    @staticmethod
    def _ordered_events(events: Iterable[ContextEvent]) -> tuple[ContextEvent, ...]:
        return tuple(sorted(events, key=lambda event: (event.occurred_at, event.event_id)))
