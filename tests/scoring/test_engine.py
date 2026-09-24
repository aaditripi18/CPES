"""Tests for additive signed-evidence CPES calculation."""

from decimal import Decimal
import unittest

from cpes.scoring import CpesScoringEngine, EvidenceModel, SignalObservation
from cpes.scoring.models import EvidenceTerm, SourceReference
from cpes.windowing.models import EventGroup


class CpesScoringEngineTests(unittest.TestCase):
    def test_adds_supplied_signed_evidence_for_present_signals(self) -> None:
        event_group = EventGroup("lineage-fixture", (), False, True, False)
        evidence_model = EvidenceModel(
            prior_log_odds=Decimal("0.25"),
            evidence_terms=(
                EvidenceTerm("negative-signal", Decimal("-0.75")),
                EvidenceTerm("positive-signal", Decimal("1.50")),
                EvidenceTerm("absent-signal", Decimal("9.00")),
            ),
        )
        observations = [
            SignalObservation(
                "positive-signal",
                True,
                (SourceReference("process-guid", "event-positive"),),
            ),
            SignalObservation(
                "absent-signal",
                False,
                (SourceReference("process-guid", "event-absent"),),
            ),
            SignalObservation(
                "negative-signal",
                True,
                (SourceReference("process-guid", "event-negative"),),
            ),
        ]

        result = CpesScoringEngine().calculate(event_group, reversed(observations), evidence_model)

        self.assertEqual(result.cpes_score, Decimal("1.00"))
        self.assertEqual(
            [contribution.signal_id for contribution in result.evidence_contributions],
            ["negative-signal", "positive-signal"],
        )
        self.assertTrue(result.is_incomplete)
        self.assertEqual(
            result.prior_log_odds
            + sum(
                (contribution.signed_log_likelihood for contribution in result.evidence_contributions),
                start=Decimal("0"),
            ),
            result.cpes_score,
        )

    def test_rejects_present_signal_without_supplied_evidence_term(self) -> None:
        event_group = EventGroup("lineage-fixture", (), False, False, False)
        evidence_model = EvidenceModel(Decimal("0"), ())
        observations = (SignalObservation("missing-term", True, ()),)

        with self.assertRaises(ValueError):
            CpesScoringEngine().calculate(event_group, observations, evidence_model)
