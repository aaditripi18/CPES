# Live VM corpus 3 (vm3) — pre-registration

Written 2026-10-29, before the VM3 session exists and before any attack is run in it.
Nothing below may change after the first Atomic test of the real session; changes before
that are amendments, dated and committed first. VM3 reuses the vm-live-v1 / VM2 procedure
([vm-live-v1.md](vm-live-v1.md), [package-v3-and-vm2.md](package-v3-and-vm2.md)) and differs
only where this document says so.

## Why

Across vm-live-v1 (Windows 11, Defender on) and VM2 (Windows Server 2022, Defender off),
CPES flagged **every escalation that actually completed** (20/20 and 25/25), but half the runs
in each session never escalated — for reasons in the *test setup*, not the detector:

1. Defender stopped the UAC bypasses on vm-live-v1.
2. `sdclt.exe` is absent on Windows Server, and the Event Viewer bypass did not elevate there.
3. Two of the three Atomic token tests download their attack script (`Get-System.ps1`) from
   GitHub at run time and so did nothing on the deliberately isolated VMs; the third never
   reached SYSTEM. The **token signal has therefore never been tested on a completed escalation.**

VM3 removes causes 1–3 by construction, so that almost every run contains a real escalation and
the token signal is finally exercised. The detectors and weights stay frozen.

## Setup (fixed)

- One **Windows 11** VirtualBox VM (so every UAC binary exists: `eventvwr.exe`, `fodhelper.exe`,
  `ComputerDefaults.exe`, `sdclt.exe`), same Sysmon configuration (`sysmon-config-v2.xml`,
  SHA-256 `B58F8F5B…2373E2C8`), Winlogbeat and Elasticsearch 9.4.3, index **`cpes-live-vm3`**,
  channels Sysmon Operational + System 7045 + Security 4697. Same isolation, snapshot, export and
  private-data rules as the earlier sessions.
- **Microsoft Defender real-time protection is off during the attack runs** (on during the benign
  period, as before). Its state is exported before the attacks and its history after.
- **Offline token tests.** The token tests' only network dependency is a run-time
  `IEX (IWR 'https://raw.githubusercontent.com/.../Get-System.ps1')`. During setup (NAT on) that
  exact file is fetched once, its SHA-256 recorded, and saved to `C:\CPES-session\Get-System.ps1`.
  A machine-wide PowerShell profile on the VM intercepts a web request for **that one URL** and
  returns the pre-fetched local copy; every other request is unaffected. This removes the
  incidental download without changing the technique (named-pipe / token impersonation to SYSTEM).
  The profile and the pinned hash are committed in `lab/vm-session/`. If the URL or file content
  has changed upstream so the hash does not match, the session is not run until the pin is updated
  and re-committed. No other test is modified.

## Pilot (fixed, before the pre-registered session)

A dry run proves the setup before the recorded session, on a throwaway snapshot:

1. From `vm3-ready`, run each of the ten tests **once** (one round), Defender off, logging to a
   separate `pilot-atomic-log.csv`.
2. Export that slice and run `python -m evaluation.run vm3 --pilot`, which reports, per test,
   whether an escalation **completed** under the mechanical definition below.
3. **Revert to `vm3-ready`.** The pilot corpus is discarded and never analysed as a result.

The pilot outcome is recorded in `VM3-SETUP-NOTES.md`. Any test that does **not** complete an
escalation even in the pilot is handled by a dated **amendment committed before the real session**:
either the cause is fixed (and the pilot re-run) or the test is declared "cannot complete here",
kept in the procedure for comparability, and reported separately — exactly as VM2 handled
`sdclt.exe`. The pilot never changes a detector, a weight, or a hypothesis.

## Session (fixed)

Identical to VM2 Phase D: 30-minute benign period (Defender on), then Defender real-time protection
off, then the ten Atomic tests × 5 (50 runs) in two round-robin parts (UAC in a non-administrator
window, the rest elevated), ≥ 180 s apart, each followed by its cleanup. Logged by `Invoke-AtomicTest`
to `atomic-log.csv`. The corpus is `cpes-live-vm3` from the benign start to 10 min after the last run,
exported once to the git-ignored `lab-data/vm3/` with its SHA-256 recorded.

## Labels and detectors (frozen, unchanged)

Labels from the execution log only (E-c, ±150 s). Detectors frozen at this commit: research signals
**R** (`evaluation.research_signals`), the package engine **P** in modes `package-v2`, `research-v3`,
`structural-v3`, `service-install-only`, and **SigmaHQ** core high/critical. "Escalation completed"
per run is mechanical and identical to VM2's corrected definition: UAC = an auto-elevating binary at
High/System near the run; service = a SYSTEM child of `services.exe` (not `svchost.exe`); token = a
SYSTEM-integrity process started by the test's shell (powershell/cmd) **or** a named-pipe connection
made as SYSTEM **by that shell**; injection = `mavinject.exe` ran. All within ±150 s.

## Hypotheses

Denominators matter and are pre-registered. "Completed" = the escalation-completed subset above.

| | Expectation | Basis |
|---|---|---|
| W1 | **On the runs where an escalation completes, R flags ≥ 95% consistently.** | VM1 20/20, VM2 25/25 |
| W2 | R detects ≥ 70% of **all 50** runs consistently (the headline VM1/VM2 missed because escalations failed). | the setup fixes above |
| W3 | **The token signal (`token_impersonation`) flags the SYSTEM process in ≥ 1 completed token run** — the first real test of that signal; direction only, not a rate. | never tested before |
| W4 | `research-v3` flags exactly the processes R flags (replication on a third corpus). | VM2 one benign-pipe difference |
| W5 | R ∪ Sigma (any flag) detects more runs than Sigma alone. | VM1 35 vs 30, VM2 40 vs 35 |
| W6 | `service-install-only` keeps ≥ 90% of `package-v2`'s service detections and adds no false-alarm process. | VM2 10/10, 0 |

W6 is again a weak test while Defender real-time protection is off (the vendor false alarm it
targets may not occur); that is stated now and the service false-alarm count is reported either way.
W3 is deliberately modest: the token signal is unproven, and a directional first result is the honest
bar. All counts are reported for three denominators (all 50, excluding any "cannot complete" tests,
and completed-escalation only), as in VM2.

## Adoption

VM3 changes **no** default on its own. It is a replication and the first token-signal test. If W4
holds (research-v3 == R with no benign-pipe false alarm on this corpus too), that is recorded as
added evidence for the labelled `research-v3` mode but does not by itself flip the dashboard default,
which the VM2 pre-registration already settled. Any outcome is reported as-is.

## Amendment 2026-10-29 — pilot outcome (committed before the recorded session)

The pilot (one round, Defender off, `pilot-atomic-log.csv`, a 185,176-document slice) ran all ten
tests; `python -m evaluation.vm3 --pilot` reports an escalation **completed** for seven and **not**
for three. Per the pilot clause above, each non-escalation is resolved here, before the first Atomic
test of the recorded session. None is "fixed" by changing a test, a detector or a weight — that is
forbidden, and VM2 did not hack `sdclt.exe` to work either. All three are therefore declared
**"cannot complete here"**, kept in the procedure for comparability, and reported separately.
Evidence is the pilot transcript (`lab-data/vm3/pilot-master-log.txt`) and the pilot corpus.

1. **T1548.002 #1 — Bypass UAC using Event Viewer (mscfile).** Its two commands ran at Medium
   integrity (`cmd /c reg add HKCU\…\mscfile\shell\open\command …`, then `cmd /c eventvwr.msc`), but
   **no process reached High or System** in the ±150 s window — no elevated `eventvwr.exe`/`mmc.exe`
   child appears at all. The mscfile-association hijack is patched on Windows 11 build 26200.9711; it
   no longer elevates. (The other three UAC bypasses — fodhelper #3, ComputerDefaults #5, and
   **sdclt #7**, the binary absent on VM2's Server — all completed here.)

2. **T1134.001 #2 — `SeDebugPrivilege` token duplication.** The atomic's own token primitive failed:
   `OpenProcessToken` / `DuplicateToken` / `SetThreadToken` each returned `Win32Exception (0x80004005)`.
   The test impersonates in-thread and never spawns a process, so it yields no process-tree escalation
   even in principle, and here the primitive did not succeed. No SYSTEM process with a shell parent,
   and no SYSTEM-made named pipe, is present in the window.

3. **T1134.002 #1 — Access Token Manipulation (create process from a parent token).** The atomic
   calls `CreateProcessFromParent` against `lsass` and received **"Access is denied"** — lsass runs as
   a protected process (PPL) on build 26200.9711 — so no child was created and no escalation completed.

This does not affect the VM3 goal. The offline token shim is proven by **T1134.001 #1** (named-pipe
client impersonation), which served the pinned local `Get-System.ps1`, reached `WORKGROUP\SYSTEM`,
and **completed an escalation** — the first time the token signal is exercised on a completed run
(W3). The recorded session thus has **seven** escalation-completing tests and **three** "cannot
complete here"; the three pre-registered denominators (all 50, excluding cannot-complete,
completed-only) already cover this, and the headline detection rate is reported over the
escalation-completing runs. The pilot changed no detector, weight or hypothesis.

Setup note (also before the session): a pending Windows feature update applied during setup, so the
frozen build is **26200.9711**, and the Hyper-V paravirtual timer was replaced with `minimal` to stop
a guest hang. The recorded session starts from snapshot **`vm3-ready-postupdate`** rather than
`vm3-ready`. No test, detector or weight changed.

## Outcome 2026-10-30 — recorded session (after the session)

The recorded session ran 2026-10-29/30 (a ~6 h idle pause separated the UAC and admin parts — benign
time outside every test window, which only enlarges the corpus). 50 runs, all ExitCode 0, Defender
detections in 0 runs. An escalation completed in **35**, exactly the seven escalation-completing
tests × 5 the pilot predicted (T1543.003 10/10, T1055.001 5/5, T1548.002 15/20, T1134.001 5/10,
T1134.002 0/5); the three "cannot complete here" tests behaved as declared. Corpus **1,128,188**
documents, SHA-256 `964bdb6ed7315a0caf94b5826930be69d8296eb16a0872d49b29feccf79ce3b7`.

All six hypotheses are **supported** (execution `vm3-20261030T041508Z`, RESULTS §16):

| | Observed | Verdict |
|---|---|---|
| W1 | R flags 35/35 completed-escalation runs consistently, 0 false alarm | supported |
| W2 | R detects 35/50 of all runs (>= 70%) | supported |
| W3 | token signal flags SYSTEM in 5/5 completed token runs | supported |
| W4 | research-v3 flags exactly the processes R flags (no differences) | supported |
| W5 | R or Sigma 45 vs Sigma 35 | supported |
| W6 | service-install-only keeps 10/10 service detections, 0 vs 0 false alarm | supported |

No test, detector, weight or hypothesis was changed after the pre-registration.
