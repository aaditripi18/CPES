"""Backend-neutral data structures for supplied CPES evidence values."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class SourceReference:
    """A supplied structural source reference for one evidence contribution."""

    process_guid: str
    event_id: str | None = None


@dataclass(frozen=True)
class SignalObservation:
    """A supplied present/absent signal observation; no value is derived here."""

    signal_id: str
    is_present: bool
    source_references: tuple[SourceReference, ...]


@dataclass(frozen=True)
class EvidenceTerm:
    """One caller-supplied signed log-likelihood evidence value."""

    signal_id: str
    signed_log_likelihood: Decimal


@dataclass(frozen=True)
class EvidenceModel:
    """Caller-supplied prior and evidence terms for one scoring invocation."""

    prior_log_odds: Decimal
    evidence_terms: tuple[EvidenceTerm, ...]


@dataclass(frozen=True)
class EvidenceContribution:
    """The exact signed value applied for one present signal."""

    signal_id: str
    signed_log_likelihood: Decimal
    source_references: tuple[SourceReference, ...]


@dataclass(frozen=True)
class CpesScoreResult:
    """Machine-readable CPES arithmetic result for one lineage chain."""

    lineage_chain_id: str
    prior_log_odds: Decimal
    evidence_contributions: tuple[EvidenceContribution, ...]
    cpes_score: Decimal
    is_truncated: bool
    is_incomplete: bool
    is_fragmented: bool
