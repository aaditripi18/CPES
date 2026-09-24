"""Chain-level evaluation harness: CPES vs. single-event baseline (M9)."""

from .harness import EvaluationHarness
from .metrics import confusion_matrix, evaluate
from .models import ConfusionMatrix, DetectorEvaluation, LabeledChainDecision

__all__ = [
    "ConfusionMatrix",
    "DetectorEvaluation",
    "EvaluationHarness",
    "LabeledChainDecision",
    "confusion_matrix",
    "evaluate",
]
