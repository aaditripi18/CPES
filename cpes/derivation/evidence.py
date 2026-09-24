"""Derive per-fold signed evidence from supplied derivation records only."""
from __future__ import annotations
from collections.abc import Iterable
from decimal import Decimal, Context, localcontext
from .models import DerivationPolicy, DerivationRecord, DerivedEvidenceModel
from .validation import validate_policy

def derive_evidence_model(records: Iterable[DerivationRecord], fold: int, policy: DerivationPolicy) -> DerivedEvidenceModel:
    if policy is None:
        raise ValueError("an explicit derivation policy is required.")
    validate_policy(policy); records = tuple(records)
    if not records: raise ValueError("derivation records are required.")
    attack = tuple(r for r in records if r.is_attack); benign = tuple(r for r in records if not r.is_attack)
    if not attack or not benign: raise ValueError("derivation records require attack and benign chains.")
    ep = policy.estimation_policy
    if min(ep.attack_pseudocount, ep.benign_pseudocount, ep.prior_attack_pseudocount, ep.prior_benign_pseudocount) < 0: raise ValueError("explicit pseudocounts must be non-negative.")
    context = Context(prec=28)
    with localcontext(context):
        prior = ((Decimal(len(attack))+ep.prior_attack_pseudocount)/(Decimal(len(benign))+ep.prior_benign_pseudocount)).ln()
    signal_ids = sorted({s.signal_id for r in records for s in r.signals})
    terms=[]
    for signal_id in signal_ids:
        ap=Decimal(sum(s.is_present for r in attack for s in r.signals if s.signal_id==signal_id)); bp=Decimal(sum(s.is_present for r in benign for s in r.signals if s.signal_id==signal_id))
        pa=(ap+ep.attack_pseudocount)/(Decimal(len(attack))+ep.attack_pseudocount*2); pb=(bp+ep.benign_pseudocount)/(Decimal(len(benign))+ep.benign_pseudocount*2)
        if pa <= 0 or pb <= 0: raise ValueError("estimation policy must explicitly prevent undefined evidence values.")
        with localcontext(context): terms.append((signal_id,(pa/pb).ln()))
    boundaries=[]
    for signal_id in sorted({n for r in records for n,_ in r.continuous_values}):
        values=sorted(v for r in records for n,v in r.continuous_values if n==signal_id)
        if len(values) <= policy.binning_policy.boundary_count: raise ValueError("insufficient supplied values for requested bins.")
        boundaries.append((signal_id,tuple(values[(len(values)*i)//(policy.binning_policy.boundary_count+1)] for i in range(1,policy.binning_policy.boundary_count+1))))
    return DerivedEvidenceModel(fold,prior,tuple(terms),tuple(boundaries),policy,context.prec,context.rounding)
