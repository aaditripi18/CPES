"""Literature-grounded single-event baseline detector (C12)."""

from .detector import SingleEventBaselineDetector
from .models import BaselineDecision

__all__ = ["BaselineDecision", "SingleEventBaselineDetector"]
