"""Evaluation protocols. Each returns a JSON-serialisable result dictionary."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from decimal import Decimal

from cpes.derivation.evidence import derive_evidence_model
from cpes.derivation.models import BinningPolicy, DerivationPolicy, DerivationRecord, EstimationPolicy, FoldPolicy, SelectionPolicy, SignalValue

from .data import SIGNAL_TECHNIQUES, SIGNALS, TOLERANCE_SECONDS, Unit, fold_of, ledger_runs, research_group, units

THRESHOLD = Decimal("0.5")
FOLDS = 5


def _policy() -> DerivationPolicy:
    selection = SelectionPolicy("fixed", ("0.5",), ((0, "0.5"),))
    window = SelectionPolicy("fixed", ("span=300;advance=150",), ((0, "span=300;advance=150"),))
    return DerivationPolicy("research-v3-mechanism-signals", FoldPolicy("grouped-v1", 0, FOLDS), EstimationPolicy("woe-half-pseudocount-v1", Decimal("0.5"), Decimal("0.5"), Decimal(0), Decimal(0)), BinningPolicy("none-v1", 1), selection, window)


def fit_weights(train: list[Unit], signals_of: Callable[[Unit], Iterable[str]]) -> dict[str, Decimal]:
    records = tuple(
        DerivationRecord(u.guid, "attack" if u.is_attack else "benign", u.is_attack, tuple(SignalValue(s, s in set(signals_of(u))) for s in SIGNALS), ())
        for u in train
    )
    return dict(derive_evidence_model(records, 0, _policy()).signed_terms)


def _rates(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    # Same conventions as the research scripts: P = 1.0 when nothing is flagged.
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    }


def grouped_cv(group_of: Callable[[Unit], str], signals_of: Callable[[Unit], Iterable[str]], fixed_detectors: dict[str, set[str]]) -> dict:
    all_units = list(units())
    folds = {u.guid: fold_of(group_of(u), FOLDS) for u in all_units}
    detectors = ["cpes", *fixed_detectors]
    per_fold: dict[str, list[dict]] = defaultdict(list)
    pooled: dict[str, Counter] = {name: Counter() for name in detectors}
    technique_hits: dict[str, Counter] = {name: Counter() for name in detectors}
    technique_totals: Counter = Counter()
    skipped = []
    weights_by_fold = {}
    for k in range(FOLDS):
        test = [u for u in all_units if folds[u.guid] == k]
        train = [u for u in all_units if folds[u.guid] != k]
        weights = fit_weights(train, signals_of)
        weights_by_fold[k] = {s: float(w) for s, w in weights.items()}
        decide = {
            "cpes": lambda u, w=weights: sum((w[s] for s in set(signals_of(u))), Decimal(0)) >= THRESHOLD,
            **{name: (lambda u, flagged=flagged: u.guid in flagged) for name, flagged in fixed_detectors.items()},
        }
        for name in detectors:
            confusion = Counter()
            for u in test:
                hit = decide[name](u)
                confusion["tp" if u.is_attack and hit else "fn" if u.is_attack else "fp" if hit else "tn"] += 1
                if u.is_attack:
                    technique_hits[name][u.technique] += hit
            pooled[name].update(confusion)
            if any(u.is_attack for u in test):
                per_fold[name].append({**_rates(confusion["tp"], confusion["fp"], confusion["tn"], confusion["fn"]), **{key: confusion[key] for key in ("tp", "fp", "tn", "fn")}, "fold": k})
        for u in test:
            if u.is_attack:
                technique_totals[u.technique] += 1
        if not any(u.is_attack for u in test):
            skipped.append(k)
    out = {"units": len(all_units), "attack": sum(u.is_attack for u in all_units), "benign": sum(not u.is_attack for u in all_units), "folds": FOLDS, "skipped_folds_without_attack": skipped, "detectors": {}, "weights_by_fold": weights_by_fold}
    for name in detectors:
        rows = per_fold[name]
        summary = {}
        for metric in ("precision", "recall", "fpr", "f1"):
            values = [row[metric] for row in rows]
            summary[metric] = statistics.mean(values)
            summary[f"{metric}_std"] = statistics.pstdev(values) if len(values) > 1 else 0.0
        c = pooled[name]
        out["detectors"][name] = {
            "fold_mean": summary,
            "pooled": {**_rates(c["tp"], c["fp"], c["tn"], c["fn"]), **{key: c[key] for key in ("tp", "fp", "tn", "fn")}},
            "per_fold": rows,
            "recall_by_technique": {t: f"{technique_hits[name][t]}/{technique_totals[t]}" for t in sorted(technique_totals)},
        }
    return out


def ledger_time(flags_by_detector: dict[str, dict[str, tuple[str, ...]]]) -> dict:
    """E-c: unit = logged Atomic run; label from the ledger time only."""

    by_guid = {u.guid: u for u in units()}
    runs = ledger_runs()
    modelled = {t for techniques in SIGNAL_TECHNIQUES.values() for t in techniques}
    out = {"runs": len(runs), "runs_by_technique": dict(sorted(Counter(t for t, _ in runs).items())), "tolerance_seconds": TOLERANCE_SECONDS, "detectors": {}}
    for name, flags in flags_by_detector.items():
        flagged = [(by_guid[g], signals) for g, signals in flags.items() if g in by_guid and signals]
        any_hit: Counter = Counter()
        consistent_hit: Counter = Counter()
        for technique, at in runs:
            near = [(u, signals) for u, signals in flagged if abs((u.created_at - at).total_seconds()) <= TOLERANCE_SECONDS]
            any_hit[technique] += bool(near)
            consistent_hit[technique] += any(technique in SIGNAL_TECHNIQUES.get(s, ()) for _, signals in near for s in signals)
        false_alarms = [u for u, _ in flagged if not any(abs((u.created_at - at).total_seconds()) <= TOLERANCE_SECONDS for _, at in runs)]
        totals = Counter(t for t, _ in runs)
        modelled_runs = sum(n for t, n in totals.items() if t in modelled)
        has_semantics = any(s in SIGNALS for _, signals in flagged for s in signals)
        out["detectors"][name] = {
            "flagged_processes": len(flagged),
            "false_alarm_processes": len(false_alarms),
            "false_alarm_images": dict(Counter(u.image for u in false_alarms).most_common(10)),
            "modelled_runs_detected_any": f"{sum(any_hit[t] for t in totals if t in modelled)}/{modelled_runs}",
            "modelled_runs_detected_consistent": f"{sum(consistent_hit[t] for t in totals if t in modelled)}/{modelled_runs}" if has_semantics else None,
            "unmodelled_runs_with_any_flag": {t: f"{any_hit[t]}/{n}" for t, n in sorted(totals.items()) if t not in modelled},
            "by_technique_any": {t: f"{any_hit[t]}/{n}" for t, n in sorted(totals.items()) if t in modelled},
            "by_technique_consistent": {t: f"{consistent_hit[t]}/{n}" for t, n in sorted(totals.items()) if t in modelled} if has_semantics else None,
        }
    return out


def research_group_key(u: Unit) -> str:
    return research_group(u)
