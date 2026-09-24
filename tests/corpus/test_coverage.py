"""Tests for manual M3 coverage-observation validation."""

import unittest

from cpes.corpus.coverage import validate_coverage_observation


class CoverageObservationTests(unittest.TestCase):
    def test_accepts_complete_manual_observation(self) -> None:
        observation = {
            "observation_id": "review-fixture-001",
            "technique_id": "T1548.002",
            "event_id": "1",
            "coverage_status": "passed",
            "observation_timestamp": "2026-07-18T04:30:00Z",
            "evidence_reference": "fixture/evidence-001",
            "reviewer": "reviewer-id",
        }

        validate_coverage_observation(observation)

    def test_requires_manual_reason_for_missing_telemetry(self) -> None:
        observation = {
            "observation_id": "review-fixture-002",
            "technique_id": "T1548.002",
            "event_id": "1",
            "coverage_status": "missing",
            "observation_timestamp": "2026-07-18T04:30:00Z",
            "evidence_reference": "fixture/evidence-002",
            "reviewer": "reviewer-id",
        }

        with self.assertRaises(ValueError):
            validate_coverage_observation(observation)
