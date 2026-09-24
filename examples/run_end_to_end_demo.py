"""End-to-end CPES demonstration on synthetic telemetry.

This script exercises every runtime stage of the contribution zone, front to
back, on an in-memory synthetic sample so the whole pipeline can be shown to
work before any real corpus exists:

    load mapping (C5 config)      -> cpes/adapters/mapping.py
    map source docs -> canonical  -> CanonicalEventMapper
    order the stream (C13)        -> ReplayDriver
    derive evidence (M8)          -> derive_evidence_model + assign_folds
    bind M8 -> C9/C8/C10 inputs   -> cpes/orchestration/binding.py   (the new seam)
    run C6->C10                    -> CpesPipeline
    report scores + decisions

The evidence model is DERIVED here (not hand-written) from a small labelled
derivation set, so the demonstration genuinely covers the derivation stage.

Deliberately out of scope for this demo (later milestones):
  * real §8.4 privilege-escalation signals (the observation generator used here
    is the trivial field-presence generator);
  * evaluation metrics / baseline comparison (M9 / M10);
  * a portable exporter (C11).

Note on the synthetic sample: the registry event (ev-4) carries no
ParentProcessGuid, exactly as real Sysmon EID 13 events behave. The
CanonicalEventTranslator merges repeated ProcessGuid assertions across events
(known parent from the create event supersedes the registry event's unknown
parent), so no synthetic workaround is required.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
import json
from pathlib import Path

from cpes.adapters.mapping import CanonicalEventMapper, load_mapping_configuration
from cpes.derivation.evidence import derive_evidence_model
from cpes.derivation.folds import assign_folds
from cpes.derivation.models import (
    BinningPolicy,
    DerivationPolicy,
    DerivationRecord,
    EstimationPolicy,
    FoldPolicy,
    SelectionPolicy,
    SignalValue,
)
from cpes.orchestration import (
    CommandLineIndicatorObservationGenerator,
    CompositeObservationGenerator,
    CpesPipeline,
    IntegrityElevationObservationGenerator,
    PipelineConfiguration,
    evidence_model_from_derived,
    resolve_detection_threshold,
    resolve_window_parameters,
)
from cpes.baseline import SingleEventBaselineDetector
from cpes.evaluation import EvaluationHarness
from cpes.exporting import ResultExporter
from cpes.replay.driver import ReplayDriver

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MAPPING_PATH = _REPO_ROOT / "configs" / "elastic-sysmon-field-mapping-v1.yaml"
_SAMPLE_PATH = Path(__file__).resolve().parent / "synthetic-telemetry-sample.json"

_SPAN_SECONDS = 180.0
_WINDOW_CANDIDATE = "span=180;advance=180"
_THRESHOLD_CANDIDATE = "1.0"

# Real privilege-escalation signals. Identifiers are shared verbatim between the
# derivation set and the runtime observation generators so corpus-derived
# evidence terms line up with the observations emitted at runtime.
_SIGNAL_INTEGRITY_ELEVATION = "s.integrity_elevation"
_SIGNAL_AUTOELEVATION_CMDLINE = "s.autoelevation_cmdline"
_INTEGRITY_ORDER = ("Untrusted", "Low", "Medium", "High", "System")
_AUTOELEVATION_INDICATORS = ("fodhelper.exe", "eventvwr.exe", "sdclt.exe")
_SIGNAL_IDS = (_SIGNAL_INTEGRITY_ELEVATION, _SIGNAL_AUTOELEVATION_CMDLINE)

# Illustrative ground-truth labels for the two synthetic runtime chains. In a
# real run these come from the manually labelled corpus (M2/M3), not the demo.
_CHAIN_LABELS = {
    "{GUID-EXPLORER}": {"is_attack": True, "technique_id": "T1548.002"},
    "{GUID-EXPLORER-2}": {"is_attack": False, "technique_id": None},
}
_EXPORT_PATH = Path(__file__).resolve().parent / "demo-export.json"
_EVALUATION_PATH = Path(__file__).resolve().parent / "demo-evaluation.json"


def _load_canonical_events():
    mapper = CanonicalEventMapper(load_mapping_configuration(_MAPPING_PATH))
    documents = json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))
    mapped = tuple(mapper.map_document(document) for document in documents)
    # ReplayDriver applies the same deterministic ordering C5 guarantees.
    return ReplayDriver().replay(mapped)


def _signal(signal_id: str, present: bool) -> SignalValue:
    return SignalValue(signal_id=signal_id, is_present=present)


def _derivation_records() -> tuple[DerivationRecord, ...]:
    # Columns: integrity_elevation, autoelevation_cmdline.
    # Benign b2 carries the command-line token but no elevation (a hard negative).
    attack_rows = {
        "chain-a1": (True, True),
        "chain-a2": (True, True),
        "chain-a3": (True, False),
    }
    benign_rows = {
        "chain-b1": (False, False),
        "chain-b2": (False, True),
        "chain-b3": (False, False),
    }

    def _record(chain_id: str, stratum: str, is_attack: bool, flags) -> DerivationRecord:
        signals = tuple(_signal(_SIGNAL_IDS[i], flags[i]) for i in range(len(_SIGNAL_IDS)))
        return DerivationRecord(
            lineage_chain_id=chain_id,
            stratum=stratum,
            is_attack=is_attack,
            signals=signals,
            continuous_values=(),
        )

    records = [_record(cid, "attack", True, flags) for cid, flags in attack_rows.items()]
    records += [_record(cid, "benign", False, flags) for cid, flags in benign_rows.items()]
    return tuple(records)


def _derivation_policy() -> DerivationPolicy:
    window = SelectionPolicy(
        "window-v1", (_WINDOW_CANDIDATE,), ((0, _WINDOW_CANDIDATE), (1, _WINDOW_CANDIDATE))
    )
    threshold = SelectionPolicy(
        "threshold-v1", (_THRESHOLD_CANDIDATE,), ((0, _THRESHOLD_CANDIDATE), (1, _THRESHOLD_CANDIDATE))
    )
    return DerivationPolicy(
        signal_specification_version="demo-signals-v1",
        fold_policy=FoldPolicy("folds-v1", seed=7, fold_count=2),
        estimation_policy=EstimationPolicy(
            "estimation-v1", Decimal(1), Decimal(1), Decimal(1), Decimal(1)
        ),
        binning_policy=BinningPolicy("bins-v1", 1),
        threshold_selection_policy=threshold,
        window_selection_policy=window,
    )


def _observation_generator() -> CompositeObservationGenerator:
    return CompositeObservationGenerator(
        (
            IntegrityElevationObservationGenerator(_SIGNAL_INTEGRITY_ELEVATION, _INTEGRITY_ORDER),
            CommandLineIndicatorObservationGenerator(
                _SIGNAL_AUTOELEVATION_CMDLINE, _AUTOELEVATION_INDICATORS
            ),
        )
    )


def _format(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.0001'))}"


def main() -> None:
    fold = 0
    ordered_events = _load_canonical_events()
    timestamps = [
        datetime.fromisoformat(event.source_timestamp.replace("Z", "+00:00"))
        for event in ordered_events
    ]
    start_at = min(timestamps)
    horizon_end_at = start_at + timedelta(seconds=_SPAN_SECONDS)

    records = _derivation_records()
    policy = _derivation_policy()

    fold_assignments = assign_folds(records, policy)
    derived = derive_evidence_model(records, fold, policy)
    evidence_model = evidence_model_from_derived(derived)
    window_parameters = resolve_window_parameters(
        policy.window_selection_policy, fold, start_at=start_at, horizon_end_at=horizon_end_at
    )
    detection_threshold = resolve_detection_threshold(policy.threshold_selection_policy, fold)

    configuration = PipelineConfiguration(
        window_parameters=window_parameters,
        evidence_model=evidence_model,
        detection_threshold=detection_threshold,
        observation_generator=_observation_generator(),
    )
    context = CpesPipeline().run(ordered_events, configuration)

    print("=" * 68)
    print("CPES END-TO-END DEMONSTRATION (synthetic telemetry)")
    print("=" * 68)

    print(f"\nCanonical events ingested: {len(ordered_events)}")
    print(f"Lineage chains reconstructed: {len(context.lineage_chains)}")
    for chain in context.lineage_chains:
        marker = " [truncated]" if chain.is_truncated else ""
        print(f"  - {chain.lineage_chain_id}: {len(chain.process_guids)} process(es){marker}")

    print("\nM8 stratified fold assignments (chain-level):")
    for item in fold_assignments:
        print(f"  - {item.assignment.lineage_chain_id} -> fold {item.assignment.held_out_fold}")

    print(f"\nDerived evidence model (fold {derived.fold}):")
    print(f"  prior_log_odds = {_format(derived.prior_log_odds)}")
    for signal_id, term in derived.signed_terms:
        print(f"  {signal_id:26s} term = {_format(term)}")

    print(f"\nDetection threshold: {_format(detection_threshold)}")
    print(f"Window: span={window_parameters.span_seconds}s advance={window_parameters.advance_seconds}s")

    print("\nDetection results (per chain / window):")
    for decision in context.threshold_decisions:
        result = decision.cpes_score_result
        verdict = "DETECTED" if decision.is_detected else "benign"
        print(f"  - {result.lineage_chain_id}: score={_format(result.cpes_score)} -> {verdict}")
        for contribution in result.evidence_contributions:
            print(
                f"        {contribution.signal_id:26s} "
                f"+= {_format(contribution.signed_log_likelihood)}"
            )

    # C12: run the single-event baseline over the IDENTICAL windowed input for
    # a like-for-like comparison (Bible §6.7, §10.5). Same integrity ordering as
    # the CPES integrity signal so the two agree on what an elevation is.
    baseline = SingleEventBaselineDetector(_INTEGRITY_ORDER)
    baseline_decisions = [
        baseline.evaluate(item.detection_window.event_group)
        for item in context.window_observations
    ]
    print("\nSingle-event baseline (C12) over identical windowed input:")
    for baseline_decision in baseline_decisions:
        verdict = "DETECTED" if baseline_decision.is_detected else "benign"
        print(f"  - {baseline_decision.lineage_chain_id}: baseline -> {verdict}")

    detections = sum(1 for decision in context.threshold_decisions if decision.is_detected)
    print(f"\nSummary: {detections} detection(s) across {len(context.threshold_decisions)} scored chain-window(s).")

    # C11: export the run to a portable, UI-independent artifact.
    exporter = ResultExporter()
    export = exporter.build(
        context,
        run_metadata={"demo": "cpes-end-to-end", "corpus": "synthetic-sample"},
        chain_labels=_CHAIN_LABELS,
    )
    exporter.write(_EXPORT_PATH, export)
    print(f"\nC11 export written to: {_EXPORT_PATH.name}")

    # M9: evaluate CPES vs. the single-event baseline over the exported results.
    harness = EvaluationHarness()
    cpes_evaluation = harness.evaluate("cpes", harness.cpes_chain_decisions(export))
    baseline_evaluation = harness.evaluate(
        "baseline", harness.baseline_chain_decisions(baseline_decisions, _CHAIN_LABELS)
    )
    evaluation = harness.compare(cpes_evaluation, baseline_evaluation)
    harness.write(_EVALUATION_PATH, evaluation)

    print(f"\nM9 evaluation ({evaluation['scored_chains']} chains) written to: {_EVALUATION_PATH.name}")
    for detector in ("cpes", "baseline"):
        block = evaluation[detector]
        confusion = block["confusion"]
        print(
            f"  {detector:8s} TP={confusion['true_positives']} FP={confusion['false_positives']} "
            f"TN={confusion['true_negatives']} FN={confusion['false_negatives']} | "
            f"precision={block['precision']} recall={block['recall']} FPR={block['false_positive_rate']}"
        )
    print(f"  comparison: FPR reduction={evaluation['comparison']['fpr_reduction']} "
          f"recall delta={evaluation['comparison']['recall_delta']}")
    print("=" * 68)


if __name__ == "__main__":
    main()
