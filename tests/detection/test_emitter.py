"""Tests for caller-threshold decisions."""

from decimal import Decimal
import unittest

from cpes.detection import DetectionEmitter
from cpes.scoring.models import CpesScoreResult


class DetectionEmitterTests(unittest.TestCase):
    def test_detects_when_score_equals_supplied_threshold(self) -> None:
        result = CpesScoreResult(
            lineage_chain_id="lineage-fixture",
            prior_log_odds=Decimal("0"),
            evidence_contributions=(),
            cpes_score=Decimal("1.00"),
            is_truncated=False,
            is_incomplete=False,
            is_fragmented=False,
        )

        decision = DetectionEmitter().emit(result, Decimal("1.00"))

        self.assertTrue(decision.is_detected)
        self.assertEqual(decision.cpes_score_result, result)
