"""Pure deterministic additive signed-evidence CPES calculation."""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal

from cpes.windowing.models import EventGroup

from .models import (
    CpesScoreResult,
    EvidenceContribution,
    EvidenceModel,
    SignalObservation,
)


class CpesScoringEngine:
    """Calculate CPES Score from caller-supplied observations and evidence."""

    def calculate(
        self,
        event_group: EventGroup,
        signal_observations: Iterable[SignalObservation],
        evidence_model: EvidenceModel,
    ) -> CpesScoreResult:
        """Return prior plus signed values for supplied present signals only."""

        evidence_by_signal = self._evidence_by_signal(evidence_model)
        observations = self._ordered_observations(signal_observations)
        self._validate_present_observations(observations, evidence_by_signal)
        contributions = tuple(
            EvidenceContribution(
                signal_id=observation.signal_id,
                signed_log_likelihood=evidence_by_signal[observation.signal_id],
                source_references=observation.source_references,
            )
            for observation in observations
            if observation.is_present
        )
        score = evidence_model.prior_log_odds + sum(
            (contribution.signed_log_likelihood for contribution in contributions),
            start=Decimal("0"),
        )
        return CpesScoreResult(
            lineage_chain_id=event_group.lineage_chain_id,
            prior_log_odds=evidence_model.prior_log_odds,
            evidence_contributions=contributions,
            cpes_score=score,
            is_truncated=event_group.is_truncated,
            is_incomplete=event_group.is_incomplete,
            is_fragmented=event_group.is_fragmented,
        )

    @staticmethod
    def _evidence_by_signal(evidence_model: EvidenceModel) -> dict[str, Decimal]:
        evidence_by_signal: dict[str, Decimal] = {}
        for evidence_term in evidence_model.evidence_terms:
            if evidence_term.signal_id in evidence_by_signal:
                raise ValueError("evidence_terms must have unique signal_id values.")
            evidence_by_signal[evidence_term.signal_id] = evidence_term.signed_log_likelihood
        return evidence_by_signal

    @staticmethod
    def _ordered_observations(
        signal_observations: Iterable[SignalObservation],
    ) -> tuple[SignalObservation, ...]:
        observations_by_signal: dict[str, SignalObservation] = {}
        for observation in signal_observations:
            if observation.signal_id in observations_by_signal:
                raise ValueError("signal_observations must have unique signal_id values.")
            observations_by_signal[observation.signal_id] = observation
        return tuple(
            observations_by_signal[signal_id] for signal_id in sorted(observations_by_signal)
        )

    @staticmethod
    def _validate_present_observations(
        observations: tuple[SignalObservation, ...],
        evidence_by_signal: dict[str, Decimal],
    ) -> None:
        missing_terms = [
            observation.signal_id
            for observation in observations
            if observation.is_present and observation.signal_id not in evidence_by_signal
        ]
        if missing_terms:
            raise ValueError("present observations require supplied evidence terms.")
