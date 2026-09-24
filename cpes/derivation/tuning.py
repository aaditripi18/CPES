"""Record only explicitly supplied per-fold parameter selections."""
from __future__ import annotations
from .models import SelectionPolicy

def derive_selected_parameter(fold: int, policy: SelectionPolicy) -> str:
    if policy is None: raise ValueError("explicit selection policy is required.")
    selections = tuple(policy.selected_candidate_by_fold)
    if len({selected_fold for selected_fold, _ in selections}) != len(selections): raise ValueError("duplicate per-fold parameter selections are not allowed.")
    selected=dict(selections).get(fold)
    if not policy.version or selected is None or selected not in policy.candidate_values: raise ValueError("an explicit valid candidate selection is required for every fold.")
    return selected
