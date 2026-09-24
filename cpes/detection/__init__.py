"""Deterministic structured threshold decisions (C10)."""

from .emitter import DetectionEmitter
from .generic import GenericEscalationObservationGenerator
from .models import ThresholdDecision

__all__ = [
    "DetectionEmitter",
    "ThresholdDecision",
    "GenericEscalationObservationGenerator",
]
