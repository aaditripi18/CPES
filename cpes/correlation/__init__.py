"""Analyst-facing correlation of alerts from several detectors (additive)."""

from .incidents import Alert, Incident, correlate

__all__ = ["Alert", "Incident", "correlate"]
