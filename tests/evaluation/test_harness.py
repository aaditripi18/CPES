"""Tests for the M9 evaluation harness (reduction, comparison, artifacts)."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from cpes.evaluation import EvaluationHarness


@dataclass(frozen=True)
class _FakeBaselineDecision:
    lineage_chain_id: str
    is_detected: bool


def _export(records):
    return {"run_metadata": {}, "summary": {}, "detections": records}


def _record(chain_id, is_detected, is_attack):
    return {
        "lineage_chain_id": chain_id,
        "is_detected": is_detected,
        "label": {"is_attack": is_attack},
    }


class CpesReductionTests(unittest.TestCase):
    def test_reduces_windows_per_chain_with_or(self) -> None:
        export = _export(
            [
                _record("a1", False, True),
                _record("a1", True, True),   # same chain flagged in one window
                _record("b1", False, False),
            ]
        )
        decisions = EvaluationHarness().cpes_chain_decisions(export)
        by_chain = {d.lineage_chain_id: d for d in decisions}
        self.assertTrue(by_chain["a1"].is_detected)
        self.assertTrue(by_chain["a1"].is_attack)
        self.assertFalse(by_chain["b1"].is_detected)
        # Deterministic sorted order.
        self.assertEqual([d.lineage_chain_id for d in decisions], ["a1", "b1"])

    def test_rejects_unlabeled_record(self) -> None:
        export = _export([{"lineage_chain_id": "a1", "is_detected": True, "label": None}])
        with self.assertRaises(ValueError):
            EvaluationHarness().cpes_chain_decisions(export)

    def test_rejects_inconsistent_labels(self) -> None:
        export = _export([_record("a1", True, True), _record("a1", False, False)])
        with self.assertRaises(ValueError):
            EvaluationHarness().cpes_chain_decisions(export)


class BaselineReductionTests(unittest.TestCase):
    def test_reduces_and_labels(self) -> None:
        decisions = [
            _FakeBaselineDecision("a1", False),
            _FakeBaselineDecision("a1", True),
            _FakeBaselineDecision("b1", True),
        ]
        labels = {"a1": {"is_attack": True}, "b1": {"is_attack": False}}
        reduced = EvaluationHarness().baseline_chain_decisions(decisions, labels)
        by_chain = {d.lineage_chain_id: d for d in reduced}
        self.assertTrue(by_chain["a1"].is_detected)
        self.assertTrue(by_chain["a1"].is_attack)
        self.assertTrue(by_chain["b1"].is_detected)
        self.assertFalse(by_chain["b1"].is_attack)

    def test_rejects_missing_label(self) -> None:
        with self.assertRaises(ValueError):
            EvaluationHarness().baseline_chain_decisions([_FakeBaselineDecision("a1", True)], {})


class ComparisonTests(unittest.TestCase):
    def _evaluations(self):
        harness = EvaluationHarness()
        # Attack chain: both detect (TP). Benign chain: baseline flags (FP), CPES does not (TN).
        cpes_export = _export([_record("attack", True, True), _record("benign", False, False)])
        baseline_decisions = [
            _FakeBaselineDecision("attack", True),
            _FakeBaselineDecision("benign", True),
        ]
        labels = {"attack": {"is_attack": True}, "benign": {"is_attack": False}}
        cpes_eval = harness.evaluate("cpes", harness.cpes_chain_decisions(cpes_export))
        baseline_eval = harness.evaluate(
            "baseline", harness.baseline_chain_decisions(baseline_decisions, labels)
        )
        return harness, cpes_eval, baseline_eval

    def test_reports_fpr_reduction_at_equal_recall(self) -> None:
        harness, cpes_eval, baseline_eval = self._evaluations()
        self.assertEqual(cpes_eval.false_positive_rate, Decimal(0))
        self.assertEqual(baseline_eval.false_positive_rate, Decimal(1))
        self.assertEqual(cpes_eval.recall, Decimal(1))
        self.assertEqual(baseline_eval.recall, Decimal(1))

        artifact = harness.compare(cpes_eval, baseline_eval)
        self.assertEqual(artifact["comparison"]["fpr_reduction"], "1")
        self.assertEqual(artifact["comparison"]["recall_delta"], "0")
        self.assertEqual(artifact["cpes"]["confusion"]["false_positives"], 0)
        self.assertEqual(artifact["baseline"]["confusion"]["false_positives"], 1)

    def test_metrics_serialized_as_strings_or_null(self) -> None:
        harness, cpes_eval, baseline_eval = self._evaluations()
        artifact = harness.compare(cpes_eval, baseline_eval)
        self.assertIsInstance(artifact["cpes"]["precision"], str)
        # A detector with no positives-predicted would have null precision.
        empty = harness.evaluate("cpes", ())
        empty_artifact = harness.compare(empty, empty)
        self.assertIsNone(empty_artifact["cpes"]["precision"])

    def test_write_round_trips_and_is_deterministic(self) -> None:
        harness, cpes_eval, baseline_eval = self._evaluations()
        artifact = harness.compare(cpes_eval, baseline_eval)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evaluation.json"
            harness.write(path, artifact)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), artifact)
        self.assertEqual(
            json.dumps(artifact, indent=2, sort_keys=True),
            json.dumps(harness.compare(cpes_eval, baseline_eval), indent=2, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
