"""Tests for the C11 Result Exporter."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from cpes.detection.models import ThresholdDecision
from cpes.exporting import ResultExporter
from cpes.orchestration.models import PipelineContext, WindowObservations
from cpes.scoring.models import (
    CpesScoreResult,
    EvidenceContribution,
    SignalObservation,
    SourceReference,
)
from cpes.windowing.models import DetectionWindow, EventGroup

_START = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
_END = datetime(2026, 7, 20, 10, 3, tzinfo=timezone.utc)


def _context(*, detected: bool = True, aligned: bool = True) -> PipelineContext:
    event_group = EventGroup("chain-x", (), False, False, False)
    window = DetectionWindow(_START, _END, event_group)
    contribution = EvidenceContribution(
        "s.integrity_elevation", Decimal("1.3863"), (SourceReference("guid-child"),)
    )
    result = CpesScoreResult(
        "chain-x", Decimal("0"), (contribution,), Decimal("1.3863"), False, False, False
    )
    decision = ThresholdDecision(result, Decimal("1.0"), detected)
    observations = (
        SignalObservation("s.integrity_elevation", True, (SourceReference("guid-child"),)),
        SignalObservation("s.autoelevation_cmdline", False, ()),
    )
    window_observations = WindowObservations(window, observations)
    decisions = (decision,) if aligned else ()
    return PipelineContext(
        canonical_events=(),
        process_nodes=(),
        context_events=(),
        lineage_chains=(),
        lineage_contexts=(),
        detection_windows=(window,),
        window_observations=(window_observations,),
        cpes_scores=(result,),
        threshold_decisions=decisions,
    )


class ResultExporterTests(unittest.TestCase):
    def test_builds_expected_detection_record(self) -> None:
        export = ResultExporter().build(_context(), run_metadata={"corpus": "demo"})
        self.assertEqual(export["run_metadata"], {"corpus": "demo"})
        self.assertEqual(export["summary"], {"scored_units": 1, "detections": 1})
        record = export["detections"][0]
        self.assertEqual(record["lineage_chain_id"], "chain-x")
        self.assertEqual(record["window_start"], "2026-07-20T10:00:00+00:00")
        self.assertTrue(record["is_detected"])

    def test_decimals_are_exact_strings_not_floats(self) -> None:
        record = ResultExporter().build(_context())["detections"][0]
        self.assertEqual(record["cpes_score"], "1.3863")
        self.assertIsInstance(record["cpes_score"], str)
        self.assertEqual(record["contributions"][0]["signed_log_likelihood"], "1.3863")
        self.assertEqual(record["detection_threshold"], "1.0")

    def test_includes_all_observations_present_and_absent(self) -> None:
        record = ResultExporter().build(_context())["detections"][0]
        signals = {obs["signal_id"]: obs["is_present"] for obs in record["observations"]}
        self.assertEqual(signals, {"s.integrity_elevation": True, "s.autoelevation_cmdline": False})

    def test_attaches_label_when_supplied(self) -> None:
        labels = {"chain-x": {"is_attack": True, "technique_id": "T1548.002"}}
        record = ResultExporter().build(_context(), chain_labels=labels)["detections"][0]
        self.assertEqual(record["label"], {"is_attack": True, "technique_id": "T1548.002"})

    def test_label_is_null_when_not_supplied_or_unmatched(self) -> None:
        self.assertIsNone(ResultExporter().build(_context())["detections"][0]["label"])
        unmatched = {"other-chain": {"is_attack": False}}
        record = ResultExporter().build(_context(), chain_labels=unmatched)["detections"][0]
        self.assertIsNone(record["label"])

    def test_detected_count_reflects_decision(self) -> None:
        export = ResultExporter().build(_context(detected=False))
        self.assertEqual(export["summary"], {"scored_units": 1, "detections": 0})

    def test_write_round_trips_and_is_deterministic(self) -> None:
        exporter = ResultExporter()
        export = exporter.build(_context(), run_metadata={"corpus": "demo"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.json"
            exporter.write(path, export)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded, export)
        # Same input -> byte-identical serialization.
        self.assertEqual(
            json.dumps(export, indent=2, sort_keys=True),
            json.dumps(exporter.build(_context(), run_metadata={"corpus": "demo"}), indent=2, sort_keys=True),
        )

    def test_empty_context_yields_no_detections(self) -> None:
        empty = PipelineContext((), (), (), (), (), (), (), (), ())
        export = ResultExporter().build(empty)
        self.assertEqual(export["summary"], {"scored_units": 0, "detections": 0})
        self.assertEqual(export["detections"], [])

    def test_rejects_misaligned_context(self) -> None:
        with self.assertRaises(ValueError):
            ResultExporter().build(_context(aligned=False))


if __name__ == "__main__":
    unittest.main()
