"""Backend-neutral models for chain-level evaluation (M9)."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class LabeledChainDecision:
    """One detector's per-chain decision paired with its ground-truth label.

    Counting is at lineage-chain granularity (Bible §11.3, CON-11): the decision
    is the chain's final verdict (flagged if any of its windows crossed), and
    ``is_attack`` is the manual ground-truth label from the corpus.
    """

    lineage_chain_id: str
    is_attack: bool
    is_detected: bool


@dataclass(frozen=True)
class ConfusionMatrix:
    """Chain-level TP/FP/TN/FN counts (Bible §11.3)."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )


@dataclass(frozen=True)
class DetectorEvaluation:
    """A detector's confusion matrix and derived metrics (exact Decimal).

    Metrics with a zero denominator are ``None`` (undefined), never fabricated.
    """

    detector: str
    confusion: ConfusionMatrix
    scored_chains: int
    precision: Decimal | None
    recall: Decimal | None
    false_positive_rate: Decimal | None
    false_negative_rate: Decimal | None
    accuracy: Decimal | None
    f1_score: Decimal | None
