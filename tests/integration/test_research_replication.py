"""The versioned evaluation must reproduce the published grouped-CV figures.

Needs the private lab corpus (git-ignored); skipped on a clean clone.
"""

from __future__ import annotations

import unittest

from evaluation import data


@unittest.skipUnless(data.CORPUS.exists() and data.LABELS.exists() and data.LEDGER_CSV.exists(), "private lab corpus not present")
class ResearchReplicationTests(unittest.TestCase):
    def test_grouped_cv_matches_corpus_eval_grouped(self) -> None:
        from evaluation.run import run_protocol

        detectors = run_protocol("research-grouped")["detectors"]
        expected = {  # printed by analysis/corpus_eval_grouped.py
            "cpes": (0.986, 0.029, 1.000, 0.993, 0.015),
            "single_event_research": (0.982, 0.036, 0.404, 0.551, 0.136),
            "ioc_signature_research": (1.000, 0.000, 0.567, 0.705, 0.151),
        }
        for name, (p, p_sd, r, f1, f1_sd) in expected.items():
            m = detectors[name]["fold_mean"]
            self.assertEqual((round(m["precision"], 3), round(m["precision_std"], 3), round(m["recall"], 3), round(m["f1"], 3), round(m["f1_std"], 3)), (p, p_sd, r, f1, f1_sd), name)
        self.assertEqual({k: detectors["cpes"]["pooled"][k] for k in ("tp", "fp", "fn")}, {"tp": 87, "fp": 1, "fn": 0})


if __name__ == "__main__":
    unittest.main()
