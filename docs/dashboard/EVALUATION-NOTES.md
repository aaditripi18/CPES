# Evaluation method — review notes and proposed corrective experiments

Written while wiring the analysis scripts into the dashboard (2026-10-18). The
published method has **not** been changed. Every number quoted here was printed
by a script executed on 2026-10-18 and recorded under `dashboard/data/experiments/`.

## What reproduces

All eight figures the README and the paper hand-off quote reproduce exactly:

| Figure | Stated | Script | Reproduced |
|---|---|---|---|
| CPES P / R / F1 (README) | 0.989 / 1.000 / 0.995 | `corpus_eval_v3.py` (ungrouped 5-fold) | yes |
| Single-event F1 (README) | 0.519 | `corpus_eval_v3.py` | yes |
| Signature F1 (README) | 0.736 | `corpus_eval_v3.py` | yes |
| CPES / single-event / IOC F1, grouped (canonical) | 0.993 / 0.551 / 0.705 | `corpus_eval_grouped.py` | yes |

## Concerns

1. **Labels are partly defined by the signals.** In the v3 scripts a process is
   an attack iff one of the four signals fires within 150 s of a logged Atomic
   execution. CPES recall is 1.0 by construction, and an attack process the
   signals miss is labelled benign, which can only lower the baselines' scores.
   `corpus_eval_independent.py` is the non-circular check for UAC, service and
   token (20/20, 8/8, 8/8); injection has no independent channel.
2. **Benign units are not grouped.** Attack units are grouped by run; each
   benign process is its own group, so processes from one benign session or one
   lineage chain land in different folds. Because WoE weights depend only on
   per-class signal frequencies the effect is probably small, but it is not
   measured.
3. **Headline choice.** The README quotes the ungrouped figures; the project's
   own notes name the grouped figures canonical.
4. **Fold aggregation.** Folds without an attack are skipped; precision with no
   positive call is set to 1.0; figures are fold means.
5. **Adverse result not in the README.** `corpus_eval_provenance.py`
   (combined corpus, provenance labels, run level) gives CPES F1 ≈ 0.505,
   recall ≈ 0.359. Different corpus, unit and label source — not comparable to
   the v3 table — but it should be reported with its explanation.
6. **Two engines.** The published numbers come from stdlib re-implementations at
   the process level. The `cpes` package scores (chain × window) units and does
   not wire the token and injection signals. On corpus-v3 the package engine,
   reduced to processes, reaches recall 0.494 with in-sample weights (UAC 15/33,
   service 28/28, injection 0/18, token 0/8) — see a dashboard run's
   Evaluation band 3. The UAC gap matches the "capped registry" artefact noted in
   `demo/cpes_demo.py` (the package signal requires the hijack write in the same
   window; the capped export dropped many of those writes).

## Proposed corrective experiments (separate, pre-registered before running)

| # | Experiment | Answers |
|---|---|---|
| E-a | Grouped CV with benign units grouped by lineage chain *and* by 10-minute session, all three detectors | concern 2 |
| E-b | Report pooled and fold-mean figures side by side; count folds skipped | concern 4 |
| E-c | Label attack processes from Atomic provenance alone (runner-root lineage, as in `corpus_eval_provenance.py`) on corpus-v3, then score all three detectors | concern 1 |
| E-d | Wire `PipeEvidence` / `RemoteThreadEvidence` through windowing (method change — needs your approval), then run the package engine through the same grouped protocol at the process level | concern 6 |
| E-e | Re-export corpus-v3 without per-event-code caps, re-run E-d | UAC gap in concern 6 |

Decide the README headline (concern 3) before any of these run, so the choice is
not made after seeing results.
