"""M9 evaluation harness: reduce results, compare CPES vs. baseline, export.

Backend-neutral and decoupled: it consumes a C11 export *dict* and duck-typed
baseline decisions (any object exposing ``lineage_chain_id`` and ``is_detected``),
so the evaluation package imports no other CPES package. All reductions are
deterministic (chains emitted in sorted order); artifacts serialize Decimals as
exact strings and undefined metrics as null.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

from .metrics import evaluate
from .models import DetectorEvaluation, LabeledChainDecision


class EvaluationHarness:
    """Reduce detector results to chain-level metrics and a paired comparison."""

    def cpes_chain_decisions(self, export: Mapping[str, Any]) -> tuple[LabeledChainDecision, ...]:
        """Reduce a C11 export to per-chain labeled decisions.

        A chain is flagged if any of its exported windows crossed threshold. Each
        record must carry a ground-truth ``label.is_attack``; unlabeled or
        label-inconsistent chains are rejected (evaluation needs ground truth).
        """

        reduced: dict[str, tuple[bool, bool]] = {}
        for record in export["detections"]:
            chain_id = record["lineage_chain_id"]
            label = record.get("label")
            if not isinstance(label, Mapping) or "is_attack" not in label:
                raise ValueError(f"chain {chain_id} is unlabeled; cannot evaluate.")
            is_attack = bool(label["is_attack"])
            is_detected = bool(record["is_detected"])
            reduced[chain_id] = self._merge(reduced.get(chain_id), chain_id, is_attack, is_detected)
        return self._as_decisions(reduced)

    def baseline_chain_decisions(
        self,
        decisions: Iterable[Any],
        chain_labels: Mapping[str, Any],
    ) -> tuple[LabeledChainDecision, ...]:
        """Reduce per-window baseline decisions to per-chain labeled decisions."""

        reduced: dict[str, tuple[bool, bool]] = {}
        for decision in decisions:
            chain_id = decision.lineage_chain_id
            is_attack = self._label_is_attack(chain_id, chain_labels)
            reduced[chain_id] = self._merge(
                reduced.get(chain_id), chain_id, is_attack, bool(decision.is_detected)
            )
        return self._as_decisions(reduced)

    def evaluate(self, detector: str, decisions: Iterable[LabeledChainDecision]) -> DetectorEvaluation:
        return evaluate(detector, decisions)

    def compare(
        self,
        cpes_evaluation: DetectorEvaluation,
        baseline_evaluation: DetectorEvaluation,
    ) -> dict[str, Any]:
        """Build a portable, joint CPES-vs-baseline comparison artifact (§11.7)."""

        return {
            "scored_chains": cpes_evaluation.scored_chains,
            "cpes": self._evaluation_dict(cpes_evaluation),
            "baseline": self._evaluation_dict(baseline_evaluation),
            "comparison": {
                # Positive fpr_reduction means CPES produced fewer false positives.
                "fpr_reduction": self._delta(
                    baseline_evaluation.false_positive_rate, cpes_evaluation.false_positive_rate
                ),
                "recall_delta": self._delta(
                    cpes_evaluation.recall, baseline_evaluation.recall
                ),
                "precision_delta": self._delta(
                    cpes_evaluation.precision, baseline_evaluation.precision
                ),
                "f1_delta": self._delta(cpes_evaluation.f1_score, baseline_evaluation.f1_score),
            },
        }

    def write(self, path: Path, artifact: Mapping[str, Any]) -> None:
        """Write the evaluation artifact as deterministic, indented JSON."""

        path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _merge(
        existing: tuple[bool, bool] | None,
        chain_id: str,
        is_attack: bool,
        is_detected: bool,
    ) -> tuple[bool, bool]:
        if existing is None:
            return (is_attack, is_detected)
        existing_attack, existing_detected = existing
        if existing_attack != is_attack:
            raise ValueError(f"inconsistent ground-truth labels for chain {chain_id}.")
        return (existing_attack, existing_detected or is_detected)

    @staticmethod
    def _as_decisions(reduced: Mapping[str, tuple[bool, bool]]) -> tuple[LabeledChainDecision, ...]:
        return tuple(
            LabeledChainDecision(chain_id, is_attack, is_detected)
            for chain_id, (is_attack, is_detected) in sorted(reduced.items())
        )

    @staticmethod
    def _label_is_attack(chain_id: str, chain_labels: Mapping[str, Any]) -> bool:
        label = chain_labels.get(chain_id)
        if label is None:
            raise ValueError(f"chain {chain_id} has no ground-truth label; cannot evaluate.")
        if isinstance(label, Mapping):
            if "is_attack" not in label:
                raise ValueError(f"chain {chain_id} label lacks is_attack.")
            return bool(label["is_attack"])
        return bool(label)

    @classmethod
    def _evaluation_dict(cls, evaluation: DetectorEvaluation) -> dict[str, Any]:
        confusion = evaluation.confusion
        return {
            "detector": evaluation.detector,
            "scored_chains": evaluation.scored_chains,
            "confusion": {
                "true_positives": confusion.true_positives,
                "false_positives": confusion.false_positives,
                "true_negatives": confusion.true_negatives,
                "false_negatives": confusion.false_negatives,
            },
            "precision": cls._metric(evaluation.precision),
            "recall": cls._metric(evaluation.recall),
            "false_positive_rate": cls._metric(evaluation.false_positive_rate),
            "false_negative_rate": cls._metric(evaluation.false_negative_rate),
            "accuracy": cls._metric(evaluation.accuracy),
            "f1_score": cls._metric(evaluation.f1_score),
        }

    @staticmethod
    def _metric(value: Decimal | None) -> str | None:
        return None if value is None else str(value)

    @staticmethod
    def _delta(minuend: Decimal | None, subtrahend: Decimal | None) -> str | None:
        if minuend is None or subtrahend is None:
            return None
        return str(minuend - subtrahend)
