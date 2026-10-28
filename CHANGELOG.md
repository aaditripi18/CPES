# Changelog

Versions follow `MAJOR.MINOR.PATCH`; while the major version is 0, a minor
release may change signals, weights and report fields. Every evaluation and its
expected outcome are pre-registered in [docs/design/](docs/design); results are
generated into [docs/RESULTS.md](docs/RESULTS.md).

## Unreleased

- **Package v3 modes** (opt-in, defaults unchanged): `research-v3` reproduces the
  published research rules exactly, with name rules labelled (corpus-v3 F1 0.993 in
  the package); `structural-v3` adds the `services.exe` parent check and
  service-install corroboration (System 7045 / Security 4697 evidence channel).
  Field mappings v2 add the parent image. Development checks: RESULTS §14.
  `service-install-only` (B2 alone) is a named mode as well.

- **Dashboard**: the run form selects the resolver mode; each run records the mode, the
  field mapping it used (v1 presets are read with v2 for the parent image) and whether
  service-install corroboration was active, and research-v3 is marked as containing name
  rules. **Fix:** the run form used the first evidence model alphabetically, `cpes-v2`
  (not adopted, RESULTS §10), instead of `research-v3-full-table`; the adopted model is
  now listed first.

- **Live VM evaluation** (`vm-live-v1`, pre-registered in
  [docs/design/vm-live-v1.md](docs/design/vm-live-v1.md)): a second corpus of 50
  Atomic runs with detectors frozen and Defender on. CPES 20/50 (expectation
  ≥ 70% not met), SigmaHQ 30/50, both 35/50; service-install corroboration
  (S2) removed 4/4 service false alarms. Session scripts in `lab/vm-session/`,
  export in `lab/export_live.py`; the corpus stays private.

## 0.2.0 — 2026-10-19

- **Dashboard** (`dashboard/`): upload Sysmon JSONL / CSV / raw `.evtx` with
  record-level validation, dataset explorer, CPES runs with score
  decomposition, process-lineage graph, live replay and Elasticsearch polling,
  evaluation workbench, light and dark themes.
- **Incidents and analyst outputs**: CPES alerts joined with SigmaHQ matches
  (`cpes.correlation`); Markdown incident report, MITRE ATT&CK Navigator layer,
  ECS alert export.
- **Package**: named-pipe and remote-thread evidence channels, streaming scorer
  (`cpes.streaming`), Elasticsearch polling source, optional own-image signature
  suppressor (off by default).
- **Evaluation** (`python -m evaluation.run`): 14 versioned protocols with a
  ledger of commit, code fingerprint and input hashes — grouped CV, package
  engine, ledger-time labels, 53 public captures, evasion variants, live
  replay, SigmaHQ comparison, held-out OTRF test of CPES v2 (not adopted),
  incident correlation, and a service-rule fix tested on 100 unused captures
  (not adopted).
- Public data fetched and SHA-256 verified by `scripts/fetch_external.py`, never
  redistributed. CI on Linux and Windows, plus the Docker image. MIT license.

## 0.1.0 — 2026-09-24

First publication: the `cpes` package (mapping, lineage, context resolver,
windowing, signals, additive signed-evidence scoring, derivation, evaluation
harness, replay, export), its tests, configurations and milestone design docs.
