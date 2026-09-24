"""Pure deterministic application of a caller-supplied detection threshold."""

from __future__ import annotations

from decimal import Decimal

from cpes.scoring.models import CpesScoreResult

from .models import ThresholdDecision


class DetectionEmitter:
    """Emit structured threshold decisions without rendering or narration."""

    def emit(
        self,
        cpes_score_result: CpesScoreResult,
        detection_threshold: Decimal,
    ) -> ThresholdDecision:
        """Compare one supplied score with one supplied threshold."""

        return ThresholdDecision(
            cpes_score_result=cpes_score_result,
            detection_threshold=detection_threshold,
            is_detected=cpes_score_result.cpes_score >= detection_threshold,
        )
