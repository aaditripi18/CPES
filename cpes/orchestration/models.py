"""Immutable orchestration inputs and stage artifacts."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING
from cpes.adapters.models import CanonicalEvent
from cpes.context.models import ContextEvent, LineageContext
from cpes.detection.models import ThresholdDecision
from cpes.lineage.models import ProcessLineageChain, ProcessNode
from cpes.scoring.models import CpesScoreResult, EvidenceModel, SignalObservation
from cpes.windowing.models import DetectionWindow, SlidingWindowParameters
if TYPE_CHECKING:
    from .observations import ObservationGenerator

@dataclass(frozen=True)
class PipelineConfiguration:
    window_parameters: SlidingWindowParameters
    evidence_model: EvidenceModel
    detection_threshold: Decimal
    observation_generator: ObservationGenerator

@dataclass(frozen=True)
class WindowObservations:
    detection_window: DetectionWindow
    observations: tuple[SignalObservation, ...]

@dataclass(frozen=True)
class PipelineContext:
    """Complete immutable provenance of one C5-downstream pipeline run."""
    canonical_events: tuple[CanonicalEvent, ...]
    process_nodes: tuple[ProcessNode, ...]
    context_events: tuple[ContextEvent, ...]
    lineage_chains: tuple[ProcessLineageChain, ...]
    lineage_contexts: tuple[LineageContext, ...]
    detection_windows: tuple[DetectionWindow, ...]
    window_observations: tuple[WindowObservations, ...]
    cpes_scores: tuple[CpesScoreResult, ...]
    threshold_decisions: tuple[ThresholdDecision, ...]
