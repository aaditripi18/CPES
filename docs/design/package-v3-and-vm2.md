# Package v3 (research parity + structural service fixes) and VM2 — pre-registration

Written 2026-10-24, before any of the package changes below were implemented and
before the second VM exists. Development data (already seen): corpus-v3,
EVTX-ATTACK-SAMPLES, the OTRF sets, vm-live-v1. Test data: the VM2 session only.

## Why the two engines differ (diagnosis on development data)

The published figures come from the research rules (`evaluation.research_signals`);
the package (`cpes`, the dashboard engine) reached 0.684 on corpus-v3. The gap has
three causes:

1. **Injection.** The research signal fires on the image name `mavinject.exe`
   (or on remote threads from it). `mavinject.exe` leaves no remote-thread record
   in corpus-v3 or vm-live-v1, so the package's structural remote-thread evidence
   never sees the attack (corpus-v3 0/18, vm-live-v1 0/5).
2. **UAC.** The package also requires a hijack registry write in the same window;
   the corpus-v3 export capped registry events (15/33). A data limit, not a rule
   difference that new data would show.
3. **Service false alarms.** The package's service test is location-only; the
   research rule also requires the parent `services.exe`. Defender's `MpCmdRun.exe`
   (parent `MsMpEng.exe`) is the package's recurring false alarm.

## Changes

All are **opt-in**; with default arguments the package behaves exactly as now, so
every recorded result stays reproducible.

**A. `research-v3` signal set (a replication, not a hypothesis).** A package
mode that applies the four research rules exactly as published, including their
two name rules, which are labelled as name rules in the code, the dashboard and the
docs: `mavinject.exe` (injection) and image names containing `atomicservice`
(service). UAC = an auto-elevating binary at High/System, with no registry
requirement. Needs the parent image, so a field mapping v2 adds
`process.parent.executable` as an optional field.

**B1. Service parent check.** The structural service anchor additionally
requires the parent image `services.exe`.

**B2. Service-install corroboration (S2, packaged).** With a service-install
evidence channel (System 7045 `ImagePath`, Security 4697 `ServiceFileName`), the
service anchor requires an install record naming the same executable at or before
the process in the same window. This differs from the protocol S2 (anywhere earlier
in the corpus) and is checked against it on vm-live-v1 before VM2.

`structural-v3` = the current package + B1 + B2.

## Development checks (seen data, run before VM2, reported as-is)

- **A**: on corpus-v3 and vm-live-v1, per process, research-v3 flags equal the
  research flags. Expected: identical, so package grouped-CV F1 = research F1
  (0.993). Any difference is reported with its cause (for example, a pipe
  create and connect falling in different windows) and is not patched to force
  equality.
- **B1**: the change in corpus-v3 benign service flags, in the vm-live-v1 package
  false alarms, and in the EVTX-ATTACK-SAMPLES service detections. The structural
  rule caught 5/7 Potato attacks there, which do not run under `services.exe`; a
  loss there is reported as the cost of B1.
- **B2**: on vm-live-v1 the packaged S2 gives the same kept/removed service anchors
  as the protocol S2.

## VM2 session

A second VirtualBox VM with a different Windows edition (Windows Server 2022
evaluation), same Sysmon configuration, Winlogbeat channels and index layout,
same `lab/vm-session` scripts (30-minute benign period, ten tests × 5).
**Defender real-time protection is off during the attack runs.** vm-live-v1
showed that Defender stops 15 of 20 UAC escalations, and VM2 tests the signals,
not Defender. Same isolation, snapshot, export and private-data rules as vm-live-v1.

Escalation completed (descriptive, mechanical): UAC = an auto-elevating binary at
High/System near the run; service = a SYSTEM child of `services.exe`; token = a
SYSTEM-integrity process or SYSTEM pipe connection from the test's shell; injection
= `mavinject.exe` ran. Runs without a completed escalation stay in the primary
denominators and are reported separately.

| | Expectation (VM2) |
|---|---|
| V1 | R detects ≥ 70% of the 50 runs consistently |
| V2 | research-v3 mode flags exactly the processes R flags |
| V3 | structural-v3 detects ≥ 90% of the service runs the current package detects |
| V4 | structural-v3 raises no more false-alarm processes than the current package |
| V5 | R ∪ Sigma (any flag) detects more runs than Sigma alone |

Adoption: the dashboard switches its default to `research-v3` (labelled) if A's
development checks hold and V2 holds; `structural-v3` becomes the recommended
structural setting if V3 and V4 hold. Either outcome is reported.

## Development checks: outcome (2026-10-25, before VM2)

`results/package-v3-dev.json`, commit `a6398bc`, clean tree:

- **A holds.** research-v3 flags equal the research flags per process on corpus-v3
  and on vm-live-v1 (zero differences). Package grouped-CV F1 0.993 (was 0.684).
- **B1 + B2 (structural-v3).** corpus-v3 benign units with a service flag drop from 12 to 1,
  and grouped-CV F1 goes from 0.684 to 0.734. vm-live-v1 service false alarms drop
  from 4 to 0, with service runs kept at 10/10. **Cost:** on EVTX-ATTACK-SAMPLES the
  service signal is lost on 4 of 5 files (EfsPotato, RogueWinRM, RoguePotato, a
  NetSvc impersonation), and detected files fall from 9 to 5.
- **B2 alone** gives the same vm-live-v1 result as the protocol S2 (10 runs kept,
  4 false alarms removed). On the EVTX samples it changes nothing, because they
  hold no install records.

## Amendment 1 (2026-10-25, before VM2 exists)

Because of the B1 cost above, VM2 also evaluates **B2 alone** (`service-install-only`)
with the same criteria as V3 and V4 (V3b, V4b). If structural-v3 and B2 alone both
hold, B2 alone is recommended: on the development data it keeps the Potato detections
that B1 loses.

## Amendment 2 (2026-10-29, after setup, before the benign period and any attack run)

The VM2 build and its preflight are recorded in
[../../lab/vm-session/VM2-SETUP-NOTES.md](../../lab/vm-session/VM2-SETUP-NOTES.md); the procedure
is [../../lab/vm-session/VM2-RUNBOOK.md](../../lab/vm-session/VM2-RUNBOOK.md) phases C–D, with
`benign-period.ps1` and `run-attacks.ps1` unchanged at this commit.

**Setup as built.** Windows Server 2022 Standard Evaluation (Desktop Experience), build 20348 with
the 2026-09 cumulative update (KB5122882); session user `cpeslab`, an ordinary administrator,
because the built-in Administrator runs without UAC admin approval. Sysmon **15.22** (vm-live-v1:
15.21) with the identical configuration file (SHA-256 `B58F8F5B…2373E2C8`). Elasticsearch and
Winlogbeat 9.4.3, same channels; index `cpes-live-vm2`; the Elasticsearch password sits in
Winlogbeat's keystore instead of `winlogbeat.yml`. Atomic Red Team installed from master on
2026-10-28, prerequisites met for all ten tests. Defender exclusion `C:\AtomicRedTeam`, as on
vm-live-v1.

**`sdclt.exe` is absent on Windows Server 2022**, so T1548.002 #7 cannot elevate. The test is still
run five times, as fixed; those runs stay in every primary denominator (so at most 45 of the 50 runs
can contain an escalation) and are also reported separately as "binary absent". No test is
substituted. Consequence stated in advance: the one UAC method that completed on vm-live-v1 is not
tested here; UAC is tested through eventvwr, fodhelper and ComputerDefaults with Defender's real-time
protection off.

**Defender.** Real-time protection stays on during the benign period (including its quick scan) and
is turned off with `Set-MpPreference -DisableRealtimeMonitoring $true` immediately before part 1;
its state is exported before the attacks and its detection history after the session.

**Isolation.** Before the benign period: NAT adapter disabled, shared folder removed, clipboard and
drag-and-drop disabled, snapshot `vm2-ready`. The host reads Elasticsearch over the host-only network
only; a VPN on the host must allow that network (infrastructure only).

**Correction to vm-live-v1's record.** Its pre-registration says the shared clipboard was off; the
VM's settings and its `vm-live-v1-ready` snapshot show it was on (bidirectional). No data crossed it
as far as the session notes record; reported here so the published setup is accurate.
