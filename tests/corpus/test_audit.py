"""Tests for manual M3 audit-record validation."""

import unittest

from cpes.corpus.audit import (
    validate_benign_review_record,
    validate_label_audit_record,
)


class AuditRecordTests(unittest.TestCase):
    def test_accepts_complete_manual_label_audit(self) -> None:
        record = {
            "audit_id": "audit-fixture-001",
            "run_id": "m2-fixture-001",
            "recorded_label": "attack",
            "audit_outcome": "confirmed",
            "evidence_reference": "fixture/evidence-001",
            "reviewer": "reviewer-id",
            "reviewed_at": "2026-07-18T04:30:00Z",
        }

        validate_label_audit_record(record)

    def test_rejects_incomplete_benign_review(self) -> None:
        record = {
            "review_id": "review-fixture-001",
            "category": "legitimate-uac-elevation",
            "observed_status": "present",
            "evidence_reference": "fixture/evidence-001",
            "reviewer": "reviewer-id",
        }

        with self.assertRaises(ValueError):
            validate_benign_review_record(record)
