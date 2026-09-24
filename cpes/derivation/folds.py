"""Deterministic chain-level stratified fold assignment."""
from __future__ import annotations
from collections import defaultdict
from hashlib import sha256
from collections.abc import Iterable
from .models import DerivationPolicy, DerivationRecord, DerivedFoldAssignment, FoldAssignment
from .validation import reproducibility_metadata

def assign_folds(records: Iterable[DerivationRecord], policy: DerivationPolicy) -> tuple[DerivedFoldAssignment, ...]:
    if policy is None:
        raise ValueError("an explicit derivation policy is required.")
    metadata = reproducibility_metadata(policy, 28, "ROUND_HALF_EVEN")
    fold_policy = policy.fold_policy
    records = tuple(records)
    if not fold_policy.version or fold_policy.fold_count < 2:
        raise ValueError("fold policy version and fold_count >= 2 are required.")
    by_stratum: dict[str, list[DerivationRecord]] = defaultdict(list)
    for record in records: by_stratum[record.stratum].append(record)
    if len({record.lineage_chain_id for record in records}) != len(records): raise ValueError("lineage_chain_id values must be unique.")
    assignments: list[FoldAssignment] = []
    for stratum, members in by_stratum.items():
        if len(members) < fold_policy.fold_count: raise ValueError(f"stratum {stratum} cannot populate every fold.")
        ordered = sorted(members, key=lambda r: sha256(f"{fold_policy.seed}:{stratum}:{r.lineage_chain_id}".encode()).hexdigest())
        assignments.extend(FoldAssignment(record.lineage_chain_id, index % fold_policy.fold_count) for index, record in enumerate(ordered))
    return tuple(DerivedFoldAssignment(item, metadata) for item in sorted(assignments, key=lambda item: item.lineage_chain_id))
