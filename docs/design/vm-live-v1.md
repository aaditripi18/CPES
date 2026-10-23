# Live VM corpus (vm-live-v1) — pre-registration

Written 2026-10-23, before any attack was run in the session described here.
Nothing below may change after the first Atomic test of the session; changes
before that are amendments, dated and committed before the session.

## Why

Every lab figure so far comes from one corpus (corpus-v3) that also shaped the
signals. This session collects a second corpus on the same kind of endpoint,
with the signals and weights frozen, and adds the Windows service-install events
that [service-rule-feasibility.md](service-rule-feasibility.md) found missing.

## Setup (fixed)

- One Windows 11 VirtualBox VM (`CPES-Windows11-Lab12`), Sysmon with the lab
  configuration, Winlogbeat 9.4.3 shipping to Elasticsearch 9.4.3 in the VM,
  index `cpes-live-v1`. Channels: `Microsoft-Windows-Sysmon/Operational`,
  `System` (event 7045 only), `Security` (event 4697 only; audit subcategory
  *Security System Extension* enabled).
- Isolation during the session: host-only network to the host only, NAT off,
  no shared folder, clipboard and drag-and-drop off. Snapshot before; revert after.
- Microsoft Defender left as found in the VM (antivirus and real-time protection
  on). Defender detections during the session are exported and reported.

## Session (fixed)

1. **Benign period, 30 min**, logged start/end: ordinary interactive use (open
   and close Explorer, Notepad, Settings, Task Manager, an elevated PowerShell
   prompt via UAC consent), and one Defender quick scan (`Start-MpScan -ScanType
   QuickScan`).
2. **Attack runs**: the ten Atomic Red Team tests used for corpus-v3, **five runs
   each (50 runs)**, in a fixed interleaved order (round-robin over the list
   below), ≥ 120 s apart, each followed by the test's cleanup command. Logged by
   `Invoke-AtomicTest` with the default execution logger (same CSV columns as
   `analysis/cpes-atomic-log-v3.csv`).

   | Technique | Atomic tests |
   |---|---|
   | T1548.002 UAC bypass | 1 (eventvwr), 3 (fodhelper), 5 (ComputerDefaults), 7 (sdclt) |
   | T1543.003 service | 2 (sc.exe), 3 (PowerShell) |
   | T1055.001 injection | 1 (mavinject) |
   | T1134.001 / .002 token | T1134.001 #1, T1134.001 #2, T1134.002 #1 |

3. The corpus is the `cpes-live-v1` documents with `@timestamp` from the benign
   period's start to 10 min after the last run, exported once to a git-ignored
   `lab-data/vm-live-v1/` with its SHA-256 recorded. It contains host and
   account identifiers and is **never published**; only aggregate results are.

Runs whose Atomic exit code is non-zero or that Defender reports blocking stay
in the primary denominators and are also reported separately.

## Labels and detectors

Labels come **only from the execution log**: a run is detected by a detector if
it flags a process created within ±150 s of the run's logged time (E-c rule,
`evaluation.protocols.ledger_time`). "Consistent" means the flagging signal was
designed for the run's technique (`evaluation.data.SIGNAL_TECHNIQUES`). A flagged
process not within 150 s of any run is a false-alarm process.

Detectors, all frozen at commit of this file:
- **R**: the four research signals, `evaluation.research_signals` on raw ECS.
- **P**: the package engine with evidence channels (research-v3 model, 300/150 s
  windows), as in `ec-ledger-time`.
- **Sigma**: SigmaHQ core r2026-07-01, high/critical, `evaluation.sigma` (descriptive).

## Hypotheses

| | Expectation | Basis (corpus-v3) |
|---|---|---|
| L1 | R detects ≥ 70% of the 50 runs consistently | 98/126 = 78% |
| L2 | R per technique: UAC ≥ 80%, service ≥ 80%, injection ≥ 70% | 44/48, 28/32, 18/22 |
| L3 | R detects ≤ 50% of T1134 runs consistently (a known weakness) | 8/24 |
| L4 | R raises ≤ 5 false-alarm processes in the session | 1 |
| L5 | P detects fewer runs consistently than R | 56/126 vs 98/126 |
| L6 | Sigma detects at least as many runs (any flag) as R | 106/126 vs 108/126 |

## Service-install corroboration (S2)

**S2** = `service_dropped_binary` (for R and P), keeping an alert only when a
service-install event (System 7045 `ImagePath` or Security 4697
`ServiceFileName`) whose executable basename equals the flagged process's image
basename (case-insensitive, quotes and arguments stripped) is recorded in the
corpus at or before the process's creation. Missing install events suppress
(unlike S1, this needs the install, which every service *creation* produces).

| | Expectation |
|---|---|
| S2a | S2 keeps ≥ 90% of the service runs S0 detects |
| S2b | S2 removes ≥ 80% of S0's false-alarm processes (all engines pooled) |

S2 is adopted as an optional setting (off by default, for telemetry that includes
these events) only if S2a and S2b both hold, and only if S0 raises at least one
false alarm in the session; with zero false alarms S2b is untestable and S2 is
not adopted. Known limit stated now: a service installed before telemetry
starts, or by a technique that reuses an existing service, is suppressed.

## Also recorded (no hypothesis)

The dashboard's Live page polls `cpes-live-v1` during the attack runs; the time
from each run's logged start to the first live alert is reported as observed,
and the session may be screen-recorded for a demo.
