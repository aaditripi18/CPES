"""Backend-neutral, explicit inputs and artifacts for M8."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal

@dataclass(frozen=True)
class SignalValue:
    signal_id: str
    is_present: bool

@dataclass(frozen=True)
class DerivationRecord:
    lineage_chain_id: str
    stratum: str
    is_attack: bool
    signals: tuple[SignalValue, ...]
    continuous_values: tuple[tuple[str, Decimal], ...]

@dataclass(frozen=True)
class FoldPolicy:
    version: str
    seed: int
    fold_count: int

@dataclass(frozen=True)
class EstimationPolicy:
    version: str
    attack_pseudocount: Decimal
    benign_pseudocount: Decimal
    prior_attack_pseudocount: Decimal
    prior_benign_pseudocount: Decimal

@dataclass(frozen=True)
class BinningPolicy:
    version: str
    boundary_count: int

@dataclass(frozen=True)
class SelectionPolicy:
    version: str
    candidate_values: tuple[str, ...]
    selected_candidate_by_fold: tuple[tuple[int, str], ...]

@dataclass(frozen=True)
class DerivationPolicy:
    signal_specification_version: str
    fold_policy: FoldPolicy
    estimation_policy: EstimationPolicy
    binning_policy: BinningPolicy
    threshold_selection_policy: SelectionPolicy
    window_selection_policy: SelectionPolicy

@dataclass(frozen=True)
class FoldAssignment:
    lineage_chain_id: str
    held_out_fold: int

@dataclass(frozen=True)
class DerivedEvidenceModel:
    fold: int
    prior_log_odds: Decimal
    signed_terms: tuple[tuple[str, Decimal], ...]
    bin_boundaries: tuple[tuple[str, tuple[Decimal, ...]], ...]
    policy: DerivationPolicy
    decimal_precision: int
    decimal_rounding: str

@dataclass(frozen=True)
class ReproducibilityMetadata:
    signal_specification_version: str
    fold_seed: int
    fold_count: int
    estimation_policy_version: str
    binning_policy_version: str
    threshold_selection_policy_version: str
    window_selection_policy_version: str
    decimal_precision: int
    decimal_rounding: str

@dataclass(frozen=True)
class DerivedFoldAssignment:
    assignment: FoldAssignment
    metadata: ReproducibilityMetadata
