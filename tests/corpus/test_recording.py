"""Unit tests for deterministic M2 execution-bracket metadata."""

import unittest

from cpes.corpus.recording import create_execution_bracket


class CreateExecutionBracketTests(unittest.TestCase):
    def test_identical_metadata_produces_identical_bracket(self) -> None:
        arguments = {
            "run_type": "attack",
            "technique_id": "T1548.002",
            "atomic_test_id": "T1548.002-EXAMPLE",
            "variant": "planned-variant",
            "started_at": "2026-07-18T10:00:00+05:30",
            "ended_at": "2026-07-18T10:05:00+05:30",
            "operator": "operator-id",
            "cleanup_status": "completed",
            "evidence_reference": "evidence/run-001",
        }

        first = create_execution_bracket(**arguments)
        second = create_execution_bracket(**arguments)

        self.assertEqual(first, second)
        self.assertEqual(first.started_at, "2026-07-18T04:30:00Z")
        self.assertEqual(first.ended_at, "2026-07-18T04:35:00Z")

    def test_attack_requires_technique_and_atomic_identifier(self) -> None:
        with self.assertRaises(ValueError):
            create_execution_bracket(
                run_type="attack",
                technique_id=None,
                atomic_test_id=None,
                variant="planned-variant",
                started_at="2026-07-18T04:30:00Z",
                ended_at="2026-07-18T04:35:00Z",
                operator="operator-id",
                cleanup_status="completed",
                evidence_reference="evidence/run-001",
            )

    def test_end_before_start_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_execution_bracket(
                run_type="benign",
                technique_id=None,
                atomic_test_id=None,
                variant="planned-activity",
                started_at="2026-07-18T04:35:00Z",
                ended_at="2026-07-18T04:30:00Z",
                operator="operator-id",
                cleanup_status="completed",
                evidence_reference="evidence/run-001",
            )
