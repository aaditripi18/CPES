# Evaluation method — review notes, status of each concern

First written 2026-10-18 while wiring the analysis scripts into the dashboard;
updated the same day after the pre-registered experiments in
[../design/evidence-channels-and-package-evaluation.md](../design/evidence-channels-and-package-evaluation.md)
ran. Numbers live in [../RESULTS.md](../RESULTS.md) (generated). The published
research method has not been changed.

## What reproduces

All eight figures the README and paper hand-off quote reproduce exactly from
the analysis scripts, and the versioned replication (`python -m evaluation.run
research-grouped`) reproduces `corpus_eval_grouped.py` to every printed digit
(means and standard deviations, all three detectors) plus the pooled confusions
in the paper hand-off.

## Concerns and their status

| # | Concern | Status |
|---|---|---|
| 1 | **Labels partly defined by the signals** (attack iff a signal fires within 150 s of a logged run; CPES recall 1.0 by construction). | **Tested (E-c).** With labels from ledger times only, research CPES flags a technique-consistent process in 98/126 runs, one false-alarm process. Recall is not 1.0 when the label is independent of the signals; most misses are token runs. |
| 2 | **Benign units not grouped** across folds. | **Tested (E-a), no effect:** benign groups = lineage chains gives CPES F1 0.996 ± 0.008 vs 0.993 ± 0.015. |
| 3 | **Headline choice** (README quoted ungrouped figures; notes call grouped canonical). | Resolved in README: grouped CV is the headline, ungrouped is supporting. |
| 4 | **Fold aggregation** (fold means; P = 1.0 with no positive call; skipped folds). | Versioned protocols now report fold mean ± sd *and* pooled confusion, and the number of skipped folds (0 in every protocol run). |
| 5 | **Adverse provenance result** (F1 ≈ 0.5) not in README. | README now reports it with its reason (lineage provenance loses re-parented outcomes). |
| 6 | **Two engines** (scripts vs package). | **Measured.** Package with evidence channels: grouped-CV F1 0.684. Gaps: injection (see 7), UAC 15/33 (capped registry export), 12 benign service flags (see 8). |
| 7 | **Injection signal is an image IOC.** corpus-v3 has no CreateRemoteThread from `mavinject.exe`; the research `remote_thread_injection` fires on `image == mavinject.exe`, which the IOC baseline also uses. | Open. The package observes real remote threads only and finds none of the 18 injections; the only EID 8 records (`csrss.exe` `CtrlRoutine`) produce 35 alert windows outside the unit set. Paper wording should not call this signal a remote-thread observation on this corpus. |
| 8 | **Service rule differs.** Package resolver: SYSTEM binary outside system dirs. Research signal 520: same *and* parent = `services.exe`. | **Settled by held-out data (OTRF, RESULTS §10):** the false alarms there are vendor services (Defender `MsMpEng`, Azure agents) that *are* children of `services.exe`, so the parent condition would not remove them. The defect is the location test (vendor services live under `ProgramData`, `WindowsAzure`, `Packages`). A signed-vendor-path or signature check is the next hypothesis, to be tested on new data. |
| 9 | **Unit blind spot.** Processes without a ProcessCreate in the capture are not units, so alerts anchored on them are never counted. | Now measured and printed in RESULTS.md for every package protocol. |

## Still to do (needs the lab VM or your decision)

* Re-export corpus-v3 from Elasticsearch **without per-event-code caps**, then re-run
  `package-grouped` (expected to recover UAC recall; not verifiable here).
* Decide concern 8.
* Collect a fresh detonation set (or use public Sysmon datasets) to test any rule
  changed after these results.
