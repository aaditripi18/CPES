"""Freeze the research v3 evidence model to dashboard/models/ (run once; output is committed)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1])]

from cpes_dashboard.evidence import derive_research_model  # noqa: E402
from cpes_dashboard.paths import MODELS  # noqa: E402


def main() -> None:
    model = derive_research_model()
    MODELS.mkdir(parents=True, exist_ok=True)
    out = MODELS / f"{model['id']}.json"
    out.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    for term in model["terms"]:
        print(f"{term['signal_id']:<26} {float(term['signed_log_likelihood']):+.4f}")
    print("prior (derived, not applied):", model["prior_log_odds_derived"][:8], "->", out)


if __name__ == "__main__":
    main()
