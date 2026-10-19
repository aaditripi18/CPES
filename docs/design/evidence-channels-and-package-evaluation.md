# Evidence channels in the package, and a package-based evaluation

Status: design + pre-registration, written 2026-10-18 **before** any package
result described in §4 was computed. Approved to proceed by the user ("go
through the recommended steps"). Changes are additive: with no evidence supplied,
`CpesPipeline` output must be byte-identical to today's.

## 1. Problem

`ContextResolver.resolve` already supports two cross-channel mechanisms —
named-pipe token impersonation (`PipeEvidence`, Sysmon EID 17/18) and
remote-thread injection (`RemoteThreadEvidence`, EID 8) — but nothing produces
that evidence:

* `CanonicalEvent` (C5) has no pipe name, user or remote-thread target field;
* `WindowManager` (C8) never fills `EventGroup.pipe_evidence` /
  `remote_thread_evidence`.

So the package cannot fire `token_impersonation` or `remote_thread_injection`,
and every published number comes from stand-alone scripts in `analysis/`.

## 2. What the data contains (inspected before writing §4)

corpus-v3, inspected 2026-10-18:

| EID | records | content |
|---|---|---|
| 8 CreateRemoteThread | 39 | all from `csrss.exe` (into cmd/powershell/MpCmdRun, `StartFunction=CtrlRoutine`) or `dwm.exe` → `csrss.exe`. **None from `mavinject.exe`.** |
| 17 PipeCreated | 488 | all by the (non-SYSTEM) lab user account |
| 18 PipeConnected | 649 | SYSTEM connects: `vboxservice.exe` 205, `cmd.exe` 8 |

Consequence, stated now: the research `remote_thread_injection` signal is
`image == mavinject.exe` (plus EID 8 from mavinject, of which there are none),
i.e. a process-image IOC, and the IOC/signature baseline contains the same rule.
A faithful remote-thread channel will find **no** injection in this corpus. We
will not filter `csrss`/`CtrlRoutine` after seeing results; any such filter is a
new signal that needs data it was not designed on.

## 3. Design

All new code is caller-configured and backend-neutral, following existing
conventions (no hidden defaults, no inference).

1. **C5 evidence mapping** — `cpes/adapters/evidence.py`,
   `configs/elastic-sysmon-evidence-mapping-v1.yaml`. A second declarative
   mapping copies raw fields (timestamp, record id, event code, process GUID,
   image, user name, pipe name, pipe event type, target process GUID) into an
   `EvidenceRecord`. Direct copy only, like `CanonicalEventMapper`.
   `CanonicalEvent` is not changed, so the existing mapping and its tests stay valid.
2. **Evidence builder** — `cpes/orchestration/evidence.py`.
   `EvidenceChannelBuilder(pipe_create_codes, pipe_connect_codes,
   remote_thread_codes, system_user_names)` turns records into timestamped
   `PipeEvidence` / `RemoteThreadEvidence`. `user_is_system` is decided by the
   caller-supplied `system_user_names`; `image_basename` uses the resolver's own
   basename rule. Records with a missing required field are skipped and counted,
   never guessed.
3. **Window attachment** — `cpes/windowing/evidence.py`,
   `EvidenceWindowAttacher`. For a window of chain *C* covering [start, end):
   * remote-thread evidence whose `source_process_guid` ∈ *C* and time ∈ window;
   * pipe **connect** evidence whose `process_guid` ∈ *C* and time ∈ window;
   * pipe **create** evidence with the same `pipe_name` as an attached connect
     and time ∈ the same window, from any chain — the cross-chain
     re-association is the point of the mechanism, and the window is its only
     temporal scope (as in the resolver docstring).
4. **Pipeline** — `CpesPipeline.run(events, configuration, *, evidence=())`.
   Empty → existing behaviour exactly.

Differences from the research script, recorded on purpose: the script pairs a
pipe with its creator anywhere in the corpus (no time bound) and its injection
signal is an image IOC; the package pairs within the window and uses observed
remote threads only.

## 4. Pre-registered package evaluation

Script: `evaluation/package_cv.py` (versioned). Output: one ledger record per
execution in `results/ledger.jsonl` and `results/package_cv-<protocol>.json`.

* **Units:** the 2,161 process instances with a ProcessCreate (EID 1), the same
  units as the research scripts.
* **Signals:** a process has signal *s* if a present observation of *s* in any
  window references it. Engine = `CpesPipeline` with the four resolver signals,
  window span 300 s / advance 150 s, with and without evidence channels.
* **Labels L1:** `Claude outputs/cpes_privilege_escalation_dataset.csv`
  (research labels; circular for CPES as documented).
* **Folds:** grouped 5-fold exactly as `corpus_eval_grouped.py`: attack units
  grouped by `technique@run-time` (first logged run of that technique within
  150 s), benign units each their own group, fold = SHA-256(group) mod 5.
* **Model per fold:** `cpes.derivation.derive_evidence_model` on the training
  fold, pseudocounts 0.5, prior not applied, threshold 0.5.
* **Reported:** fold mean ± population std *and* pooled P / R / FPR / F1,
  folds skipped, per-technique recall, for CPES-package, CPES-package without
  evidence, and the package single-event baseline.

**Expectations written now** (so they can be wrong):

* E1 token recall rises from 0/8 to 8/8 with evidence channels.
* E2 injection recall stays 0/18 (no mavinject remote threads), and EID 8
  evidence adds false positives on `csrss`-anchored processes.
* E3 UAC recall stays below the research 33/33 because the capped export
  dropped hijack registry writes (15/33 seen in the in-sample run).
* E4 therefore the package F1 will be well below the research 0.993. That gap
  is the result, not a bug to tune away.

## 5. Corrective experiments (same script, separate protocols)

* **E-a** benign units grouped by lineage chain (research engine signals),
  everything else as in `corpus_eval_grouped.py`.
* **E-b** pooled vs fold-mean reporting and skipped-fold counts, for E-a and the
  original protocol.
* **E-c** labels from the execution ledger only — no signal, no lineage
  (lineage provenance loses re-parented outcomes, which is why
  `corpus_eval_provenance.py` reports recall ≈ 0.36). Unit = logged Atomic run.
  A run counts as detected by a detector if any process it flags was created
  within ±150 s of the run's logged time (the research labelling tolerance).
  Reported both "any flag" and "technique-consistent flag" (the flag's signal
  belongs to the run's technique: autoelevation→T1548.002, service→T1543.003,
  injection→T1055.001, token→T1134.*). False alarms = flagged processes not
  within ±150 s of any logged run. With the research weights every single
  signal is above the 0.50 threshold, so CPES's decision on a process is the OR
  of its signals; no fitting is involved and E-c needs no CV.
* E-a / E-c use the research signal flags from the labelled table and a
  replication of the research baselines; the replication must first reproduce
  `corpus_eval_grouped.py` exactly (0.551 / 0.705 / 0.993) or nothing else is
  reported.
* E-c is also run with the package engine's flags (with evidence channels).

Amendment log: E-c definition fixed on 2026-10-18 before any E-c number was
computed (the earlier one-line description was ambiguous about the unit).

## 6. Outcome against the expectations (recorded 2026-10-18, after the runs)

Numbers: [../RESULTS.md](../RESULTS.md) (generated from `results/`).

| Expectation | Outcome |
|---|---|
| E1 token recall 0/8 → 8/8 with evidence | **Held** (8/8). |
| E2 injection stays 0/18; EID 8 evidence adds false positives on `csrss`-anchored processes | **Held, but invisible to the unit metric.** Injection 0/18. The EID 8 channel produced 35 detected windows anchored on `csrss.exe`/`dwm.exe`; those processes started before the capture, have no ProcessCreate record and are therefore not evaluation units, so the unit-level FP count does not move. The report now counts alerts anchored outside units. |
| E3 UAC recall below 33/33 | **Held** (15/33). |
| E4 package F1 well below 0.993 | **Held** (grouped-CV F1 0.684 with evidence, 0.605 without). |

Not anticipated: all 12 benign package flags are `service_dropped_binary`
(Defender `MpCmdRun.exe` from `C:\ProgramData\…` and `winlogbeat.exe`). The
package resolver's service rule omits the research rule's `parent =
services.exe` condition. Aligning the two is a decision for the author, recorded
as open; it was not applied after seeing these results.
E-a: grouping benign units by lineage chain did not lower CPES (0.996 ± 0.008);
the grouping concern has no measurable effect on this corpus.
E-c: with ledger-time labels only, research CPES flags a technique-consistent
process in 98/126 runs with one false-alarm process; most misses are token runs
(8/23), matching the independent-channel finding that many token detonations
left no SYSTEM-shell pipe connection.
