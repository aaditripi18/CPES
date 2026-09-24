"""C11 Result Exporter: portable, UI-independent export of pipeline results.

Serializes a completed ``PipelineContext`` into a plain, JSON-serializable
structure that a third party can inspect or feed into evaluation, with no
dependency on Elasticsearch, Kibana, or any UI (FR-14, NFR-02). All ``Decimal``
values are emitted as exact strings and timestamps as ISO 8601, so the export
is bit-reproducible and preserves score/contribution values precisely.

Per-chain ground-truth labels are a corpus artifact, not a pipeline output, so
they are supplied optionally by the caller and attached by lineage-chain id.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

from cpes.orchestration.models import PipelineContext, WindowObservations
from cpes.scoring.models import EvidenceContribution, SignalObservation, SourceReference


class ResultExporter:
    """Build and write a portable, deterministic export of pipeline results."""

    def build(
        self,
        context: PipelineContext,
        *,
        run_metadata: Mapping[str, Any] | None = None,
        chain_labels: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assemble a JSON-serializable export from a completed pipeline run."""

        if len(context.window_observations) != len(context.threshold_decisions):
            raise ValueError(
                "window_observations and threshold_decisions must be aligned one-to-one."
            )

        detections = [
            self._detection_record(window_observations, decision, chain_labels)
            for window_observations, decision in zip(
                context.window_observations, context.threshold_decisions
            )
        ]
        return {
            "run_metadata": dict(run_metadata) if run_metadata is not None else {},
            "summary": {
                "scored_units": len(detections),
                "detections": sum(1 for record in detections if record["is_detected"]),
            },
            "detections": detections,
        }

    def write(self, path: Path, export: Mapping[str, Any]) -> None:
        """Write the export as deterministic, indented JSON."""

        path.write_text(json.dumps(export, indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def _detection_record(
        cls,
        window_observations: WindowObservations,
        decision,
        chain_labels: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        result = decision.cpes_score_result
        window = window_observations.detection_window
        label = None
        if chain_labels is not None:
            label = chain_labels.get(result.lineage_chain_id)
        return {
            "lineage_chain_id": result.lineage_chain_id,
            "window_start": window.start_at.isoformat(),
            "window_end": window.end_at.isoformat(),
            "prior_log_odds": str(result.prior_log_odds),
            "cpes_score": str(result.cpes_score),
            "detection_threshold": str(decision.detection_threshold),
            "is_detected": decision.is_detected,
            "is_truncated": result.is_truncated,
            "is_incomplete": result.is_incomplete,
            "is_fragmented": result.is_fragmented,
            "contributions": [
                cls._contribution(contribution)
                for contribution in result.evidence_contributions
            ],
            "observations": [
                cls._observation(observation)
                for observation in window_observations.observations
            ],
            "label": label,
        }

    @classmethod
    def _contribution(cls, contribution: EvidenceContribution) -> dict[str, Any]:
        return {
            "signal_id": contribution.signal_id,
            "signed_log_likelihood": str(contribution.signed_log_likelihood),
            "source_references": [
                cls._source_reference(reference)
                for reference in contribution.source_references
            ],
        }

    @classmethod
    def _observation(cls, observation: SignalObservation) -> dict[str, Any]:
        return {
            "signal_id": observation.signal_id,
            "is_present": observation.is_present,
            "source_references": [
                cls._source_reference(reference)
                for reference in observation.source_references
            ],
        }

    @staticmethod
    def _source_reference(reference: SourceReference) -> dict[str, Any]:
        return {"process_guid": reference.process_guid, "event_id": reference.event_id}
