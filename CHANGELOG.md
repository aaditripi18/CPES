# Changelog

Versions follow `MAJOR.MINOR.PATCH`; while the major version is 0, a minor
release may change signals, weights and report fields. Every evaluation and its
expected outcome are pre-registered in [docs/design/](docs/design); results are
generated into [docs/RESULTS.md](docs/RESULTS.md).

## 0.4.0 — 2026-10-30

- **VM3 evaluation** (`vm3`, pre-registered in [docs/design/vm3-session.md](docs/design/vm3-session.md) with a pilot
  amendment): a third live corpus on Windows 11 with every detector frozen, Defender real-time protection off during
  the attacks, and the token tests made to run offline (a pinned local `Get-System.ps1` served to the one run-time
  download). 50 runs; an escalation completed in 35 (the other 15 are three tests pre-registered as "cannot complete
  here" on build 26200.9711 — the patched mscfile UAC hijack, a failed `SeDebugPrivilege` duplication, and PPL-protected
  `lsass`). **All six hypotheses W1–W6 supported**: the research signals flagged all 35 completed-escalation runs
  consistently with no false alarm (W1) and 35/50 of all runs (W2, the headline rate VM1/VM2 missed); the token signal
  flagged the SYSTEM process in 5/5 completed token runs — its first real test (W3); research-v3 matched the research
  rules exactly (W4); CPES ∪ Sigma 45/50 vs Sigma 35/50 (W5); service-install-only kept every service detection with no
  extra false alarm (W6). CPES named the escalated process in 25/25 runs where it appeared, Sigma in 0/25. The recorded
  session spanned a ~6 h idle pause between the UAC and admin parts (benign time outside every test window; disclosed in
  the setup notes). Corpus 1,128,188 documents, not published. RESULTS §16, FINDINGS §13.

## 0.3.0 — 2026-10-29

- **VM2 evaluation** (`vm2`, pre-registered with two amendments in
  [docs/design/package-v3-and-vm2.md](docs/design/package-v3-and-vm2.md)): a third corpus on Windows Server 2022,
  detectors frozen, Defender real-time protection off during the attacks, analysis code committed before the session.
  25 of 50 runs contained an escalation and CPES flagged all 25 (V1 ≥ 70% of all runs: 25/50, not supported);
  research-v3 matched the research rules except for one false alarm of the latter (V2 not supported); the
  service-install fixes kept every service detection (V3/V4, V3b/V4b supported); CPES ∪ Sigma 40/50 vs Sigma 35/50
  (V5 supported); CPES named the escalated process in 20/20 runs, Sigma in 0/20. Two of the three Atomic token tests
  download their script at run time and cannot run on an isolated VM. RESULTS §15, FINDINGS §12; lab tooling in
  `lab/vm-session/` (runbook, read-only preflight, setup and session notes).
- **Adoption** (pre-registered rule): the default stays `package-v2`; `service-install-only` is the recommended
  structural setting for telemetry with service-install events, and the dashboard labels it.

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
