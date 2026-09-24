"""Coordinator for the backend-neutral C5-downstream CPES workflow."""
from __future__ import annotations
from collections.abc import Iterable
from cpes.adapters.models import CanonicalEvent
from cpes.context.builder import ContextBuilder
from cpes.detection.emitter import DetectionEmitter
from cpes.lineage.builder import LineageBuilder
from cpes.scoring.engine import CpesScoringEngine
from cpes.windowing.manager import WindowManager
from .models import PipelineConfiguration, PipelineContext, WindowObservations
from .translation import CanonicalEventTranslator

class CpesPipeline:
    def __init__(self, translator: CanonicalEventTranslator | None = None) -> None:
        self._translator = translator or CanonicalEventTranslator()
        self._lineage_builder = LineageBuilder(); self._context_builder = ContextBuilder(); self._window_manager = WindowManager(); self._scorer = CpesScoringEngine(); self._emitter = DetectionEmitter()
    def run(self, canonical_events: Iterable[CanonicalEvent], configuration: PipelineConfiguration) -> PipelineContext:
        translated = self._translator.translate(canonical_events)
        chains = self._lineage_builder.build(translated.process_nodes)
        contexts = tuple(self._context_builder.build(chain, translated.context_events) for chain in chains)
        windows = tuple(window for context in contexts for window in self._window_manager.assemble(context, configuration.window_parameters))
        observations = tuple(WindowObservations(window, configuration.observation_generator.generate(window.event_group)) for window in windows)
        scores = tuple(self._scorer.calculate(item.detection_window.event_group, item.observations, configuration.evidence_model) for item in observations)
        decisions = tuple(self._emitter.emit(score, configuration.detection_threshold) for score in scores)
        return PipelineContext(translated.canonical_events, translated.process_nodes, translated.context_events, chains, contexts, windows, observations, scores, decisions)
