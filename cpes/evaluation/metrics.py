"""Exact-Decimal chain-level evaluation metrics (Bible §11.3).

All ratios use a fixed Decimal context so results are deterministic and exact to
28 significant digits. A ratio with a zero denominator is returned as ``None``
(undefined) rather than fabricated, so the reporting layer can render it as
null and never imply false precision.
"""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Context, Decimal, localcontext

from .models import ConfusionMatrix, DetectorEvaluation, LabeledChainDecision

_CONTEXT = Context(prec=28)


def confusion_matrix(decisions: Iterable[LabeledChainDecision]) -> ConfusionMatrix:
    """Count TP/FP/TN/FN from per-chain labeled decisions.

    Chains must already be reduced to one decision each; duplicate chain ids are
    rejected so a chain cannot be double-counted.
    """

    seen: set[str] = set()
    true_positives = false_positives = true_negatives = false_negatives = 0
    for decision in decisions:
        if decision.lineage_chain_id in seen:
            raise ValueError(
                "decisions must be reduced to one per lineage chain before counting."
            )
        seen.add(decision.lineage_chain_id)
        if decision.is_attack and decision.is_detected:
            true_positives += 1
        elif decision.is_attack and not decision.is_detected:
            false_negatives += 1
        elif not decision.is_attack and decision.is_detected:
            false_positives += 1
        else:
            true_negatives += 1
    return ConfusionMatrix(
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
    )


def evaluate(detector: str, decisions: Iterable[LabeledChainDecision]) -> DetectorEvaluation:
    """Build a detector's confusion matrix and derived metrics."""

    confusion = confusion_matrix(decisions)
    tp = confusion.true_positives
    fp = confusion.false_positives
    tn = confusion.true_negatives
    fn = confusion.false_negatives

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return DetectorEvaluation(
        detector=detector,
        confusion=confusion,
        scored_chains=confusion.total,
        precision=precision,
        recall=recall,
        false_positive_rate=_ratio(fp, fp + tn),
        false_negative_rate=_ratio(fn, fn + tp),
        accuracy=_ratio(tp + tn, confusion.total),
        f1_score=_f1_score(precision, recall),
    )


def _ratio(numerator: int, denominator: int) -> Decimal | None:
    if denominator == 0:
        return None
    with localcontext(_CONTEXT):
        return Decimal(numerator) / Decimal(denominator)


def _f1_score(precision: Decimal | None, recall: Decimal | None) -> Decimal | None:
    if precision is None or recall is None:
        return None
    with localcontext(_CONTEXT):
        denominator = precision + recall
        if denominator == 0:
            return Decimal(0)
        return (Decimal(2) * precision * recall) / denominator
