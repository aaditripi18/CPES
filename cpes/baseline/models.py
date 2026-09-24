"""Backend-neutral decision model for the single-event baseline (C12)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BaselineDecision:
    """Chain-level decision from the literature-grounded single-event baseline.

    The baseline flags a lineage chain when a single qualifying event exists,
    with no cross-event correlation or evidence aggregation. Structural flags
    are carried through so baseline and CPES decisions are counted at the same
    lineage-chain granularity (Bible §11.3).
    """

    lineage_chain_id: str
    is_detected: bool
    triggering_process_guids: tuple[str, ...]
    is_truncated: bool
    is_incomplete: bool
    is_fragmented: bool
