"""Tests for exact-Decimal chain-level evaluation metrics."""

from __future__ import annotations

from decimal import Decimal
import unittest

from cpes.evaluation import LabeledChainDecision, confusion_matrix, evaluate


def _decisions(spec):
    # spec: list of (chain_id, is_attack, is_detected)
    return tuple(LabeledChainDecision(c, a, d) for c, a, d in spec)


class ConfusionTests(unittest.TestCase):
    def test_counts_each_quadrant(self) -> None:
        decisions = _decisions(
            [
                ("a1", True, True),   # TP
                ("a2", True, False),  # FN
                ("b1", False, True),  # FP
                ("b2", False, False),  # TN
            ]
        )
        confusion = confusion_matrix(decisions)
        self.assertEqual(
            (
                confusion.true_positives,
                confusion.false_negatives,
                confusion.false_positives,
                confusion.true_negatives,
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(confusion.total, 4)

    def test_rejects_duplicate_chain(self) -> None:
        with self.assertRaises(ValueError):
            confusion_matrix(_decisions([("a1", True, True), ("a1", True, False)]))


class MetricTests(unittest.TestCase):
    def test_exact_values(self) -> None:
        # TP=2, FP=1, TN=3, FN=1
        decisions = _decisions(
            [
                ("a1", True, True),
                ("a2", True, True),
                ("a3", True, False),   # FN
                ("b1", False, True),   # FP
                ("b2", False, False),
                ("b3", False, False),
                ("b4", False, False),
            ]
        )
        result = evaluate("cpes", decisions)
        self.assertEqual(result.precision, Decimal(2) / Decimal(3))
        self.assertEqual(result.recall, Decimal(2) / Decimal(3))
        self.assertEqual(result.false_positive_rate, Decimal(1) / Decimal(4))
        self.assertEqual(result.false_negative_rate, Decimal(1) / Decimal(3))
        self.assertEqual(result.accuracy, Decimal(5) / Decimal(7))
        self.assertEqual(result.f1_score, Decimal(2) / Decimal(3))

    def test_fnr_is_one_minus_recall(self) -> None:
        result = evaluate("cpes", _decisions([("a1", True, True), ("a2", True, False)]))
        self.assertEqual(result.recall + result.false_negative_rate, Decimal(1))

    def test_undefined_precision_and_recall_are_none(self) -> None:
        # No positives predicted, no actual attacks -> precision, recall undefined.
        result = evaluate("cpes", _decisions([("b1", False, False), ("b2", False, False)]))
        self.assertIsNone(result.precision)
        self.assertIsNone(result.recall)
        self.assertEqual(result.false_positive_rate, Decimal(0))
        self.assertEqual(result.accuracy, Decimal(1))
        self.assertIsNone(result.f1_score)

    def test_f1_zero_when_no_true_positives_but_defined(self) -> None:
        # TP=0, FP=1, FN=1, TN=1 -> precision=0, recall=0, f1=0.
        result = evaluate(
            "cpes",
            _decisions([("b1", False, True), ("a1", True, False), ("b2", False, False)]),
        )
        self.assertEqual(result.precision, Decimal(0))
        self.assertEqual(result.recall, Decimal(0))
        self.assertEqual(result.f1_score, Decimal(0))

    def test_deterministic(self) -> None:
        decisions = _decisions([("a1", True, True), ("b1", False, True)])
        self.assertEqual(evaluate("cpes", decisions), evaluate("cpes", decisions))


if __name__ == "__main__":
    unittest.main()
