"""Bridge M8 derivation artifacts onto C9/C8/C10 runtime inputs.

This module is the single seam that connects the "learn the model" half of the
project (``cpes.derivation``) to the "apply the model" half (``cpes.scoring``,
``cpes.windowing``, ``cpes.detection``). It lives in ``orchestration`` because
that is the only package permitted to depend on both halves; keeping the bridge
here preserves ``derivation`` as an island and ``scoring`` as a pure calculator.

The functions perform direct, deterministic translation only. They derive no
statistics and invent no values: an evidence model is mapped field-for-field
from a derived model, and window/threshold parameters are resolved by parsing
the caller-declared candidate label selected by the fold's selection policy.

Candidate-label encoding (design decision of record):

* Window candidate: ``"span=<seconds>;advance=<seconds>"`` (e.g. ``"span=30;advance=15"``).
* Threshold candidate: a plain decimal string (e.g. ``"1.50"``).

Encoding the numeric value inside the candidate keeps the ``SelectionPolicy``
the single source of truth; no separate lookup table is introduced.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation

from cpes.derivation.models import DerivedEvidenceModel, SelectionPolicy
from cpes.derivation.tuning import derive_selected_parameter
from cpes.scoring.models import EvidenceModel, EvidenceTerm
from cpes.windowing.models import SlidingWindowParameters


def evidence_model_from_derived(derived: DerivedEvidenceModel) -> EvidenceModel:
    """Map a per-fold derived model onto the scorer's evidence-model contract.

    The prior and every signed term are copied exactly; no value is altered.
    Duplicate signal identifiers are rejected here so the mismatch surfaces at
    the bridge rather than deeper inside the scorer.
    """

    signal_ids = [signal_id for signal_id, _ in derived.signed_terms]
    if len(signal_ids) != len(set(signal_ids)):
        raise ValueError("derived signed_terms must have unique signal_id values.")
    return EvidenceModel(
        prior_log_odds=derived.prior_log_odds,
        evidence_terms=tuple(
            EvidenceTerm(signal_id=signal_id, signed_log_likelihood=signed_log_likelihood)
            for signal_id, signed_log_likelihood in derived.signed_terms
        ),
    )


def resolve_window_parameters(
    window_selection_policy: SelectionPolicy,
    fold: int,
    *,
    start_at: datetime,
    horizon_end_at: datetime,
) -> SlidingWindowParameters:
    """Resolve the fold's selected window candidate into sliding-window bounds.

    ``span`` and ``advance`` come from the policy-selected candidate label; the
    temporal bounds (``start_at`` / ``horizon_end_at``) are supplied by the
    caller because they are properties of the data being replayed, not of the
    tuning policy.
    """

    selected = derive_selected_parameter(fold, window_selection_policy)
    span_seconds, advance_seconds = _parse_window_candidate(selected)
    return SlidingWindowParameters(
        start_at=start_at,
        horizon_end_at=horizon_end_at,
        span_seconds=span_seconds,
        advance_seconds=advance_seconds,
    )


def resolve_detection_threshold(threshold_selection_policy: SelectionPolicy, fold: int) -> Decimal:
    """Resolve the fold's selected threshold candidate into a Decimal cutoff."""

    selected = derive_selected_parameter(fold, threshold_selection_policy)
    return _parse_decimal(selected)


def _parse_window_candidate(candidate: str) -> tuple[float, float]:
    parts = [segment.strip() for segment in candidate.split(";") if segment.strip()]
    values: dict[str, float] = {}
    for part in parts:
        if "=" not in part:
            raise ValueError("window candidate must use 'key=value' segments.")
        key, raw_value = (token.strip() for token in part.split("=", maxsplit=1))
        if key not in {"span", "advance"}:
            raise ValueError("window candidate keys must be 'span' and 'advance'.")
        if key in values:
            raise ValueError("window candidate keys must not repeat.")
        values[key] = _parse_positive_float(key, raw_value)
    if set(values) != {"span", "advance"}:
        raise ValueError("window candidate must declare both 'span' and 'advance'.")
    return values["span"], values["advance"]


def _parse_positive_float(key: str, raw_value: str) -> float:
    try:
        value = float(raw_value)
    except ValueError as error:
        raise ValueError(f"window candidate '{key}' must be numeric.") from error
    if value <= 0:
        raise ValueError(f"window candidate '{key}' must be positive.")
    return value


def _parse_decimal(candidate: str) -> Decimal:
    try:
        return Decimal(candidate.strip())
    except (InvalidOperation, ValueError) as error:
        raise ValueError("threshold candidate must be a decimal value.") from error
