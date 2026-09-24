"""Fail-closed O1 and policy validation."""
from __future__ import annotations
from collections.abc import Iterable
from .models import DerivationPolicy, FoldAssignment, ReproducibilityMetadata

def validate_no_leakage(assignments: Iterable[FoldAssignment], fold_count: int) -> None:
    assignments = tuple(assignments)
    if fold_count < 2 or len({a.lineage_chain_id for a in assignments}) != len(assignments): raise ValueError("valid unique chain-level assignments are required.")
    if {a.held_out_fold for a in assignments} - set(range(fold_count)): raise ValueError("assignment contains an invalid held-out fold.")

def validate_policy(policy: DerivationPolicy) -> None:
    if policy is None: raise ValueError("derivation policy is required.")
    if not policy.signal_specification_version: raise ValueError("signal specification version is required.")
    if policy.fold_policy is None or not policy.fold_policy.version or policy.fold_policy.fold_count < 2: raise ValueError("explicit valid fold policy is required.")
    if policy.estimation_policy is None or not policy.estimation_policy.version: raise ValueError("explicit estimation policy is required.")
    if policy.binning_policy is None or not policy.binning_policy.version or policy.binning_policy.boundary_count < 1: raise ValueError("explicit valid binning policy is required.")
    for selection in (policy.threshold_selection_policy, policy.window_selection_policy):
        if selection is None or not selection.version or not selection.candidate_values or not selection.selected_candidate_by_fold: raise ValueError("explicit selection policy and candidates are required.")
        folds = [fold for fold, _ in selection.selected_candidate_by_fold]
        if len(folds) != len(set(folds)): raise ValueError("duplicate per-fold parameter selections are not allowed.")

def reproducibility_metadata(policy: DerivationPolicy, decimal_precision: int, decimal_rounding: str) -> ReproducibilityMetadata:
    validate_policy(policy)
    return ReproducibilityMetadata(policy.signal_specification_version, policy.fold_policy.seed, policy.fold_policy.fold_count, policy.estimation_policy.version, policy.binning_policy.version, policy.threshold_selection_policy.version, policy.window_selection_policy.version, decimal_precision, decimal_rounding)
