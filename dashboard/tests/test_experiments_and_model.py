"""Experiment output parsing, claim status logic and the frozen evidence model."""

from __future__ import annotations

import json
import math

import pytest

from cpes_dashboard import experiments as experiments_module
from cpes_dashboard.evidence import LABEL_TABLE, derive_research_model
from cpes_dashboard.experiments import ExperimentStore, parse_output
from cpes_dashboard.paths import MODELS
from cpes_dashboard.storage import write_json

# Captured verbatim from analysis/corpus_eval_grouped.py and corpus_eval_v3.py on 2026-10-18.
GROUPED = """Grouped 5-fold CV (folds split by attack run; leakage-free)  --  units=2161 attack=87 benign=2074
  detector                           Precision          Recall             FPR              F1
  Single-event (integrity)       0.982+/-0.036   0.404+/-0.163   0.001+/-0.001   0.551+/-0.136
  IOC / signature                1.000+/-0.000   0.567+/-0.194   0.000+/-0.000   0.705+/-0.151
  CPES (context WoE)             0.986+/-0.029   1.000+/-0.000   0.000+/-0.001   0.993+/-0.015
"""
V3 = """=== v3 5-fold mean +/- std (blind benign) ===
  baseline1 (integrity edge) P=0.950±0.100  R=0.362±0.101  FPR=0.000±0.001  F1=0.519±0.119
  CPES sharp token-pipe      P=0.989±0.021  R=1.000±0.000  FPR=0.000±0.001  F1=0.995±0.011

=== pooled confusion ===
  CPES sharp token-pipe      TP=87 FP=1 TN=2073 FN=0
"""


def test_parse_grouped_table():
    parsed = parse_output("detector_table", GROUPED)
    assert parsed["units"] == {"units": 2161, "attack": 87, "benign": 2074}
    assert parsed["detectors"]["CPES (context WoE)"]["f1"] == 0.993
    assert parsed["detectors"]["Single-event (integrity)"]["recall_std"] == 0.163
    assert set(parsed["detectors"]) == {"Single-event (integrity)", "IOC / signature", "CPES (context WoE)"}


def test_parse_v3_table_and_pooled_confusion():
    parsed = parse_output("v3_table", V3)
    assert parsed["detectors"]["CPES sharp token-pipe"]["precision"] == 0.989
    assert parsed["pooled_confusion"]["CPES sharp token-pipe"] == {"tp": 87, "fp": 1, "tn": 2073, "fn": 0}
    assert parse_output(None, V3) is None


def test_claim_status_reflects_the_latest_completed_execution(data_root, monkeypatch):
    store = ExperimentStore()
    write_json(store.root / "exp-1" / "record.json", {"id": "exp-1", "experiment_id": "grouped_cv", "state": "completed", "parsed": parse_output("detector_table", GROUPED.replace("0.993+/-0.015", "0.990+/-0.015"))})
    claims = {c["claim"]: c for c in store.claims()}
    assert claims["CPES F1, grouped CV (paper hand-off, canonical)"]["status"] == "differs"
    assert claims["Single-event F1, grouped CV (canonical)"]["status"] == "matches"
    assert claims["CPES F1 (README)"]["status"] == "not_reproduced_yet"
    write_json(store.root / "exp-2" / "record.json", {"id": "exp-2", "experiment_id": "grouped_cv", "state": "completed", "parsed": parse_output("detector_table", GROUPED)})
    claims = {c["claim"]: c for c in store.claims()}
    assert claims["CPES F1, grouped CV (paper hand-off, canonical)"]["status"] == "matches"
    assert claims["CPES F1, grouped CV (paper hand-off, canonical)"]["execution_id"] == "exp-2"


def test_missing_inputs_make_an_experiment_unrunnable(data_root):
    catalog = {entry["id"]: entry for entry in ExperimentStore().catalog()}
    v4 = catalog["expansion_v4"]
    if v4["runnable"]:
        pytest.skip("corpus-v4.ndjson is present on this machine")
    assert "analysis/corpus-v4.ndjson" in v4["missing_inputs"]
    with pytest.raises(ValueError, match="missing"):
        ExperimentStore().start("expansion_v4", background=False)


def test_frozen_model_matches_the_research_formula():
    model = json.loads((MODELS / "research-v3-full-table.json").read_text(encoding="utf-8"))
    attack, benign = model["units"]["attack"], model["units"]["benign"]
    for term in model["terms"]:
        counts = model["signal_counts"][term["signal_id"]]
        expected = math.log((counts["attack_present"] + 0.5) / (attack + 1)) - math.log((counts["benign_present"] + 0.5) / (benign + 1))
        assert abs(float(term["signed_log_likelihood"]) - expected) < 1e-12
    assert model["prior_applied"] == "0"


@pytest.mark.skipif(not LABEL_TABLE.exists(), reason="private labelled table not present")
def test_frozen_model_is_reproducible_from_the_table():
    model = json.loads((MODELS / "research-v3-full-table.json").read_text(encoding="utf-8"))
    assert derive_research_model() == model


@pytest.mark.skipif(not (experiments_module.REPO_ROOT / "analysis" / "corpus-v3.ndjson").exists(), reason="private lab corpus not present")
def test_canonical_experiment_reproduces_the_documented_figures(data_root):
    record = ExperimentStore().start("grouped_cv", background=False)
    assert record["state"] == "completed" and record["exit_code"] == 0
    detectors = record["parsed"]["detectors"]
    assert detectors["CPES (context WoE)"]["f1"] == 0.993
    assert detectors["Single-event (integrity)"]["f1"] == 0.551
    assert detectors["IOC / signature"]["f1"] == 0.705


def test_the_adopted_model_is_listed_first(client):
    # The run form starts runs with the first model; cpes-v2 was not adopted (RESULTS §10).
    models = client.get("/api/evidence-models").json()
    assert models[0]["id"] == "research-v3-full-table"
