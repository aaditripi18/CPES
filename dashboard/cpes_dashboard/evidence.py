"""Frozen evidence models for detection runs.

A run on unlabelled data needs weights from somewhere. The only weights the
project has published come from the labelled v3 feature table. They are
derived here with the package's own ``cpes.derivation.derive_evidence_model``
(pseudocounts 0.5, which is exactly the research formula
``w = ln[(a+0.5)/(N_A+1)] − ln[(b+0.5)/(N_B+1)]``) and frozen to JSON with the
table's checksum, so a run records precisely which weights it used.

The research decision rule is "sum of fired weights ≥ 0.50" with no prior
(``demo/cpes_demo.py``, ``analysis/corpus_eval_grouped.py``). The package
scorer adds ``prior_log_odds``; to apply the research rule the frozen model
sets ``prior_applied`` to 0 and keeps the derived prior on record. Both are
shown in the UI.
"""

from __future__ import annotations

import csv
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from cpes.derivation.evidence import derive_evidence_model
from cpes.derivation.models import (
    BinningPolicy,
    DerivationPolicy,
    DerivationRecord,
    EstimationPolicy,
    FoldPolicy,
    SelectionPolicy,
    SignalValue,
)
from cpes.scoring.models import EvidenceModel, EvidenceTerm

from .ingest import sha256_file
from .paths import MODELS, REPO_ROOT

SIGNAL_COLUMNS = {
    "autoelevation_lolbin": "sig_autoelevation_lolbin",
    "service_dropped_binary": "sig_service_dropped_binary",
    "remote_thread_injection": "sig_remote_thread_injection",
    "token_impersonation": "sig_token_impersonation",
}
LABEL_TABLE = REPO_ROOT / "Claude outputs" / "cpes_privilege_escalation_dataset.csv"


def research_policy() -> DerivationPolicy:
    window = SelectionPolicy("dashboard-window-v1", ("span=300;advance=150",), ((0, "span=300;advance=150"),))
    threshold = SelectionPolicy("research-threshold-v1", ("0.5",), ((0, "0.5"),))
    return DerivationPolicy(
        signal_specification_version="research-v3-mechanism-signals",
        fold_policy=FoldPolicy("full-table-v1", seed=0, fold_count=2),
        estimation_policy=EstimationPolicy("woe-half-pseudocount-v1", Decimal("0.5"), Decimal("0.5"), Decimal(0), Decimal(0)),
        binning_policy=BinningPolicy("none-v1", 1),
        threshold_selection_policy=threshold,
        window_selection_policy=window,
    )


def read_label_table(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def derive_research_model(path: Path = LABEL_TABLE) -> dict[str, Any]:
    rows = read_label_table(path)
    records = tuple(
        DerivationRecord(
            lineage_chain_id=row["instance_id"],
            stratum="attack" if row["label_is_escalation"] == "1" else "benign",
            is_attack=row["label_is_escalation"] == "1",
            signals=tuple(SignalValue(signal, row[column] == "1") for signal, column in SIGNAL_COLUMNS.items()),
            continuous_values=(),
        )
        for row in rows
    )
    derived = derive_evidence_model(records, 0, research_policy())
    attack = [row for row in rows if row["label_is_escalation"] == "1"]
    benign = [row for row in rows if row["label_is_escalation"] != "1"]
    counts = {
        signal: {
            "attack_present": sum(row[column] == "1" for row in attack),
            "benign_present": sum(row[column] == "1" for row in benign),
        }
        for signal, column in SIGNAL_COLUMNS.items()
    }
    return {
        "id": "research-v3-full-table",
        "title": "Research v3 weights (full labelled table, in-sample)",
        "derived_with": "cpes.derivation.derive_evidence_model",
        "source_table": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
        "source_table_sha256": sha256_file(path),
        "units": {"total": len(rows), "attack": len(attack), "benign": len(benign)},
        "signal_counts": counts,
        "estimation_policy": {"attack_pseudocount": "0.5", "benign_pseudocount": "0.5"},
        "prior_log_odds_derived": str(derived.prior_log_odds),
        "prior_applied": "0",
        "prior_note": "Research decision rule scores Σ fired weights (no prior); the derived prior is recorded but not applied.",
        "default_threshold": "0.5",
        "terms": [{"signal_id": signal, "signed_log_likelihood": str(value)} for signal, value in derived.signed_terms],
        "scope_note": "Derived from all 2,161 labelled process instances: in-sample for corpus-v3, so a run on corpus-v3 is not a held-out test.",
    }


# The adopted model. cpes-v2 stays available but was not adopted (held-out test, RESULTS §10).
DEFAULT_MODEL_ID = "research-v3-full-table"


def available_models() -> list[dict[str, Any]]:
    """All models, the adopted one first (the run form uses the first entry)."""

    models = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(MODELS.glob("*.json"))]
    return sorted(models, key=lambda model: model["id"] != DEFAULT_MODEL_ID)


def load_model(model_id: str) -> dict[str, Any]:
    for model in available_models():
        if model["id"] == model_id:
            return model
    raise ValueError(f"unknown evidence model '{model_id}'.")


def to_evidence_model(model: dict[str, Any], signal_ids: tuple[str, ...]) -> EvidenceModel:
    terms = {term["signal_id"]: Decimal(term["signed_log_likelihood"]) for term in model["terms"]}
    missing = [signal for signal in signal_ids if signal not in terms]
    if missing:
        raise ValueError(f"evidence model lacks terms for: {', '.join(missing)}.")
    return EvidenceModel(
        prior_log_odds=Decimal(model["prior_applied"]),
        evidence_terms=tuple(EvidenceTerm(signal, terms[signal]) for signal in signal_ids),
    )
