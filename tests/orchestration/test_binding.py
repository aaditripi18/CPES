"""Tests for the M8 derivation-to-runtime binding layer."""

from datetime import datetime, timezone
from decimal import Decimal
import unittest

from cpes.derivation.models import (
    BinningPolicy,
    DerivationPolicy,
    DerivedEvidenceModel,
    EstimationPolicy,
    FoldPolicy,
    SelectionPolicy,
)
from cpes.orchestration.binding import (
    evidence_model_from_derived,
    resolve_detection_threshold,
    resolve_window_parameters,
)


def _policy(window_candidate: str, threshold_candidate: str) -> DerivationPolicy:
    window = SelectionPolicy("window-v1", (window_candidate,), ((0, window_candidate),))
    threshold = SelectionPolicy("threshold-v1", (threshold_candidate,), ((0, threshold_candidate),))
    return DerivationPolicy(
        signal_specification_version="signals-v1",
        fold_policy=FoldPolicy("folds-v1", 7, 2),
        estimation_policy=EstimationPolicy("estimation-v1", Decimal(1), Decimal(1), Decimal(1), Decimal(1)),
        binning_policy=BinningPolicy("bins-v1", 1),
        threshold_selection_policy=threshold,
        window_selection_policy=window,
    )


class EvidenceBindingTests(unittest.TestCase):
    def test_maps_prior_and_terms_exactly(self) -> None:
        derived = DerivedEvidenceModel(
            fold=0,
            prior_log_odds=Decimal("0.125"),
            signed_terms=(("signal-a", Decimal("1.50")), ("signal-b", Decimal("-0.75"))),
            bin_boundaries=(),
            policy=_policy("span=30;advance=15", "1.0"),
            decimal_precision=28,
            decimal_rounding="ROUND_HALF_EVEN",
        )

        model = evidence_model_from_derived(derived)

        self.assertEqual(model.prior_log_odds, Decimal("0.125"))
        self.assertEqual(
            [(term.signal_id, term.signed_log_likelihood) for term in model.evidence_terms],
            [("signal-a", Decimal("1.50")), ("signal-b", Decimal("-0.75"))],
        )

    def test_rejects_duplicate_signal_ids(self) -> None:
        derived = DerivedEvidenceModel(
            fold=0,
            prior_log_odds=Decimal("0"),
            signed_terms=(("dup", Decimal("1")), ("dup", Decimal("2"))),
            bin_boundaries=(),
            policy=_policy("span=30;advance=15", "1.0"),
            decimal_precision=28,
            decimal_rounding="ROUND_HALF_EVEN",
        )
        with self.assertRaises(ValueError):
            evidence_model_from_derived(derived)


class ParameterResolutionTests(unittest.TestCase):
    def test_resolves_window_parameters_from_candidate(self) -> None:
        policy = _policy("span=45;advance=20", "1.0").window_selection_policy
        start_at = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
        horizon_end_at = datetime(2026, 7, 20, 10, 5, tzinfo=timezone.utc)

        parameters = resolve_window_parameters(
            policy, 0, start_at=start_at, horizon_end_at=horizon_end_at
        )

        self.assertEqual(parameters.span_seconds, 45.0)
        self.assertEqual(parameters.advance_seconds, 20.0)
        self.assertEqual(parameters.start_at, start_at)
        self.assertEqual(parameters.horizon_end_at, horizon_end_at)

    def test_resolves_threshold_from_candidate(self) -> None:
        policy = _policy("span=45;advance=20", "1.75").threshold_selection_policy
        self.assertEqual(resolve_detection_threshold(policy, 0), Decimal("1.75"))

    def test_rejects_malformed_window_candidate(self) -> None:
        policy = _policy("span=45", "1.0").window_selection_policy
        start_at = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            resolve_window_parameters(policy, 0, start_at=start_at, horizon_end_at=start_at)

    def test_rejects_non_positive_window_value(self) -> None:
        policy = _policy("span=0;advance=15", "1.0").window_selection_policy
        start_at = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            resolve_window_parameters(policy, 0, start_at=start_at, horizon_end_at=start_at)

    def test_rejects_non_decimal_threshold(self) -> None:
        policy = _policy("span=45;advance=20", "not-a-number").threshold_selection_policy
        with self.assertRaises(ValueError):
            resolve_detection_threshold(policy, 0)


if __name__ == "__main__":
    unittest.main()
