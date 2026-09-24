"""Backend-neutral structured threshold-decision data."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from cpes.scoring.models import CpesScoreResult


@dataclass(frozen=True)
class ThresholdDecision:
    """A caller-threshold comparison and its complete arithmetic result."""

    cpes_score_result: CpesScoreResult
    detection_threshold: Decimal
    is_detected: bool
