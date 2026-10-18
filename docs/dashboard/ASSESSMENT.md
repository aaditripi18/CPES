# CPES dashboard — repository assessment and plan (2026-10-18)

This records what the audit of the repository found before any dashboard code
was written, and the phased plan that follows from it. Everything below was
checked by reading the code or running it; nothing is assumed.

## 1. What is already implemented and working

| Area | State (verified) |
|---|---|
| `cpes` package, C5–C13 | All stages present and small (~2,900 lines). `pytest tests` → **120 passed**. |
| `CpesPipeline.run` | Backend-neutral; takes `CanonicalEvent`s plus an explicit `PipelineConfiguration` (window bounds, evidence model, threshold, observation generator). No hidden defaults. |
| Mapping (C5) | `configs/elastic-sysmon-field-mapping-v1.yaml` maps Winlogbeat/ECS documents. Mapped all 35,345 events of `analysis/corpus-v3.ndjson` with zero errors. |
| Real corpus through the package | `CpesPipeline` on corpus-v3 runs in < 2 s: 2,219 process nodes, 96 lineage chains (38 truncated), 6,336 windows at span 300 s / advance 150 s. |
| Resolver signals | `ContextResolver` + `ResolvedSignalObservationGenerator` fire `autoelevation_lolbin` and `service_dropped_binary` on the real corpus. |
| Exporter (C11), harness (M9), baseline (C12), derivation (M8) | Work as documented; exporter output is the natural API payload for a run. |
| Research evaluation | `analysis/corpus_eval_*.py` reproduce the documented numbers when run (grouped 5-fold CV: CPES F1 0.993 ± 0.015, single-event 0.551, IOC/signature 0.705). |
| Standalone demo | `demo/cpes_demo.py` runs on corpus-v3 (stdlib only). |

## 2. Findings that affect the dashboard (and the paper)

1. **Two engines, not one.** The published numbers come from the stand-alone
   analysis scripts and `demo/cpes_demo.py`, which re-implement the four
   mechanism signals in plain Python at the *process-instance* level. They do
   not call `CpesPipeline`. The package scores *(lineage chain, window)* units.
   The dashboard keeps the two apart: fresh **detection runs** use the package;
   **research experiments** run the analysis scripts unchanged and record their
   output.
2. **Token and injection signals cannot fire through `CpesPipeline` yet.**
   `EventGroup.pipe_evidence` / `remote_thread_evidence` are never populated by
   `WindowManager` (the resolver's docstring calls this "a separate integration
   step"), and the canonical event has no pipe-name or user field. A package run
   on corpus-v3 therefore detects UAC and service escalations only. The
   dashboard shows these two signals as "not wired" rather than hiding them.
3. **Lineage chains are coarse on real telemetry.** One corpus-v3 chain holds
   1,346 of 2,219 processes. Chain-level evaluation (`EvaluationHarness`) on such
   a chain is nearly meaningless, which is why the research protocol counts
   process instances. The dashboard labels the chain-level evaluation with its
   protocol and does not put it next to the paper's numbers as if comparable.
4. **README headline uses the ungrouped CV figures.** README "Results" quotes
   0.989 / 1.000 / 0.995 and baselines 0.519 / 0.736 (`corpus_eval_v3.py`,
   ungrouped 5-fold). `docs/CPES-Friend-Reply-2026-09-06.md` and the paper
   hand-off say the leakage-free **grouped** figures (CPES 0.993, single-event
   0.551, IOC 0.705) are canonical. Not changed here; flagged for you.
5. **A less favourable experiment is not in the README.** The provenance-labelled
   run-level evaluation (`corpus_eval_provenance.py`, combined corpus) gives CPES
   F1 0.505 ± 0.104 (recall 0.359). The dashboard lists it with the others.
6. **Label construction (documented, but worth surfacing).** In the v3 scripts a
   process is an attack *iff* one of the four signals fires within 150 s of a
   logged Atomic execution, so CPES recall is 1.0 by construction and any attack
   process the signals miss is counted as benign. `corpus_eval_independent.py`
   is the non-circular check (UAC/service/token; injection has no independent
   channel).
7. **Other evaluation-protocol notes** (concerns, not changes): benign units are
   each their own CV group (benign processes from one session are not grouped);
   folds without attacks are skipped; precision with no positive calls is set to
   1.0; reported numbers are per-fold means, not pooled. Corrective experiments
   are proposed in `EVALUATION-NOTES.md`.
8. **`examples/run_end_to_end_demo.py` is broken.** Its synthetic sample uses raw
   `winlog.event_data.*` keys; the mapping was reconciled to ECS on 2026-08-23
   and requires `winlog.record_id`. Running it raises
   `required source field is missing: winlog.record_id`.
9. **`pytest` from the repo root fails collection** because the untracked
   `verify-bundle/` copies duplicate test module names. `pytest tests` passes. A
   clean clone is unaffected (the bundles are git-ignored).
10. **Sensitive data in local files.** The corpus and Atomic logs contain the lab
    hostname, account name and agent IDs. They are git-ignored; the dashboard
    reads them locally and must never be deployed with them.

## 3. What the professor's requirement needs beyond the existing project

* An ingest layer for uploaded CSV / JSON / JSONL with per-record validation
  (the package mapper and translator raise on the first bad record; the
  dashboard validates record-by-record so the report can list every failure).
* A persistent run store (config, dataset checksum, exporter output) so runs are
  never overwritten and can be reopened.
* An HTTP API and a browser UI over the above.
* A frozen, versioned evidence model for runs on unlabelled uploads (derived with
  the package's own `derive_evidence_model`).

## 4. Phases

**Phase 1 (this change): end-to-end vertical slice.** Upload → validate →
explore records → run the real `CpesPipeline` → detections with evidence →
lineage graph → explainable score → research experiments reproduced → export →
run history → limitations page.

**Phase 2.** Stitch-designed visual pass (prompts in `stitch_prompts.md`);
ground-truth upload for user datasets; saved filters; run-vs-run comparison.

**Phase 3 (needs your decision; changes the method).** Wire pipe /
remote-thread evidence through windowing so token and injection signals run in
the package; process-instance evaluation through the package harness; grouped
benign sessions in CV.

## 5. Portfolio presentation — recommendations (not applied)

1. Decide the README headline: grouped CV (canonical per your notes) or
   ungrouped. Show the other as supporting, and add the provenance result
   (F1 ≈ 0.5) with one sentence on why it differs.
2. README says the demo runs "against synthetic telemetry"; `demo/cpes_demo.py`
   actually reads the private `analysis/corpus-v3.ndjson`. Fix the sentence, and
   fix or retire `examples/run_end_to_end_demo.py` (finding 8).
3. Add two screenshots: a detection's score waterfall with its evidence, and the
   lineage view around a UAC bypass. Take them from the synthetic dataset so no
   lab hostname, SID or account appears.
4. A public demo can only use synthetic data. If you want one, add a small,
   explicitly labelled synthetic scenario per technique (needs your approval —
   it would be new synthetic telemetry) and deploy the dashboard read-only.
5. State the two-engine situation in the README Architecture section.

**Postponed on purpose:** authentication, multi-user state, database server,
live Elasticsearch ingestion from the UI, public deployment of real telemetry.
