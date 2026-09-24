"""C12 single-event baseline detector.

A literature-grounded comparison detector modelled on the Splunk/Elastic-style
privilege-escalation analytic (Bible §4.1, §10.5): it flags a lineage chain
when a single qualifying event exists -- a process whose integrity level is
higher than its parent's -- **without** cross-event correlation, evidence
aggregation, or a tunable threshold. Its sole role is to quantify what CPES's
context adds (FR-12, O3); it is not a contribution.

It consumes the identical C8 windowed input (``EventGroup``) that CPES scores,
so the comparison is like-for-like (§6.7). It is deliberately self-contained
and depends on no CPES scoring or observation machinery, keeping the comparison
fair and the component independently replaceable.
"""

from __future__ import annotations

from cpes.windowing.models import EventGroup

from .models import BaselineDecision


class SingleEventBaselineDetector:
    """Flag a chain on a single integrity-elevation event, without correlation."""

    def __init__(self, integrity_order: tuple[str, ...]) -> None:
        if not integrity_order or len(set(integrity_order)) != len(integrity_order):
            raise ValueError("integrity_order must be a nonempty tuple of unique levels.")
        if any(not level or not level.strip() for level in integrity_order):
            raise ValueError("integrity_order levels must be nonblank.")
        self._rank = {level: index for index, level in enumerate(integrity_order)}

    def evaluate(self, event_group: EventGroup) -> BaselineDecision:
        """Return a chain-level decision from the windowed integrity transitions.

        The chain is flagged if any parent->child transition in the window is an
        elevation (child integrity strictly higher than parent). Transitions
        whose levels are outside the supplied ordering are ignored (fail-safe).
        """

        triggering_process_guids = tuple(
            transition.child_process_guid
            for transition in event_group.integrity_transitions
            if self._is_elevation(transition)
        )
        return BaselineDecision(
            lineage_chain_id=event_group.lineage_chain_id,
            is_detected=bool(triggering_process_guids),
            triggering_process_guids=triggering_process_guids,
            is_truncated=event_group.is_truncated,
            is_incomplete=event_group.is_incomplete,
            is_fragmented=event_group.is_fragmented,
        )

    def _is_elevation(self, transition) -> bool:
        parent_rank = self._rank.get(transition.parent_integrity_level)
        child_rank = self._rank.get(transition.child_integrity_level)
        return parent_rank is not None and child_rank is not None and child_rank > parent_rank
