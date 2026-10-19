"""Freeze the CPES v2 evidence model (run once, before any held-out evaluation).

v2 = v1's four frozen research weights + a weight for the package's generic
"unexplained privilege gain" signal, derived from the LAB corpus only with the
same estimation policy as v1 (pseudocount 0.5). Pre-registered in
docs/design/cpes-v2-heldout.md.
"""

from __future__ import annotations

import json
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "dashboard")]

from cpes.derivation.evidence import derive_evidence_model  # noqa: E402
from cpes.derivation.models import DerivationRecord, SignalValue  # noqa: E402
from cpes_dashboard.evidence import research_policy  # noqa: E402
from evaluation import data, engine  # noqa: E402

GENERIC = "unexplained_privilege_gain"


def main() -> None:
    v1 = json.loads((ROOT / "dashboard" / "models" / "research-v3-full-table.json").read_text(encoding="utf-8"))
    package = engine.run_package(with_evidence=True, generic=True)
    flagged = package["generic_flags"]
    units = data.units()
    records = tuple(
        DerivationRecord(u.guid, "attack" if u.is_attack else "benign", u.is_attack, (SignalValue(GENERIC, u.guid in flagged),), ())
        for u in units
    )
    derived = derive_evidence_model(records, 0, research_policy())
    weight = dict(derived.signed_terms)[GENERIC]
    attack = sum(u.is_attack and u.guid in flagged for u in units)
    benign = sum((not u.is_attack) and u.guid in flagged for u in units)
    model = {
        **{k: v1[k] for k in ("source_table", "source_table_sha256", "units", "estimation_policy", "prior_log_odds_derived", "prior_applied", "prior_note", "default_threshold")},
        "id": "cpes-v2",
        "title": "CPES v2: v1 weights + weighted generic 'unexplained privilege gain' (lab-derived)",
        "derived_with": "cpes.derivation.derive_evidence_model (generic term); v1 terms copied unchanged",
        "signal_counts": {**v1["signal_counts"], GENERIC: {"attack_present": attack, "benign_present": benign}},
        "terms": [*v1["terms"], {"signal_id": GENERIC, "signed_log_likelihood": str(weight)}],
        "generic_flags_from": "evaluation.engine.run_package(with_evidence=True, generic=True) on corpus-v3",
        "scope_note": "All weights derived from the lab corpus only. Frozen before the OTRF held-out evaluation (docs/design/cpes-v2-heldout.md).",
    }
    out = ROOT / "dashboard" / "models" / "cpes-v2.json"
    out.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    print(f"generic flags on lab units: {attack} attack / {benign} benign -> weight {float(weight):+.4f}")
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
