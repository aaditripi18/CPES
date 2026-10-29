# Findings

Every number here is in [RESULTS.md](RESULTS.md), which is generated from
`results/`. This file is the narrative. Thirteen protocols were last recorded at
commit `52efc6d` (`999337f` before the history rewrite; see
[../results/COMMIT-MAP.md](../results/COMMIT-MAP.md)) from a clean tree, and the
service-rule test at `e7acead`. Each test's expected outcome was committed in
[design/](design) before it ran; where an expectation failed, it says so below.

## 1. On its own lab data, CPES finds the process that gained privilege

Lab corpus: one Windows 11 endpoint, UAC bypass, service creation, injection and
token theft run with Atomic Red Team, plus benign activity — 2,161 process
instances, 87 of them attacks. Grouped 5-fold cross-validation (folds split by
attack run): **CPES F1 0.993 ± 0.015**, against 0.551 for a single-event
integrity rule and 0.705 for an IOC rule. Grouping benign activity by lineage
chain as well leaves it at 0.996 (no leakage effect).

That figure favours CPES by construction: attack labels come partly from the
same mechanisms. Labelling only from the execution log's run times, CPES flags a
technique-consistent process in **98 of 126** runs, with one false-alarm process.

## 2. The packaged engine is not the research engine

The published figures come from the research scripts. The `cpes` package, which
the dashboard runs, scores (process chain × time window) units and reached
grouped-CV F1 **0.684** — as pre-registered (E4). Adding pipe evidence made
token impersonation detectable (0/8 → **8/8**, E1). Injection stayed at 0/18:
on this corpus the research injection signal is an image-name rule
(`mavinject.exe`), and the only remote threads recorded are `csrss.exe`
control routines. UAC reached 15/33 because the corpus export capped registry
events. These are properties of the data and the unit of analysis, reported
next to the research figure rather than merged into it.

## 3. Beyond the lab: structure generalises, name lists do not

On 53 public attack captures with weights frozen from the lab, CPES alone
detects **9**, and **26** with its generic "unexplained privilege gain" test.
The listed-binary UAC signal catches 2 of 33 UAC methods: a list of four
auto-elevating binaries does not generalise (A). Unplanned: the structural
service signal — a SYSTEM process running from outside the system directories —
caught **5 of 7** Potato-style token attacks it was never designed for. The same
breadth is what produces its false alarms (section 8).

## 4. Renaming breaks name rules, not structure

Attacker-controlled variants of the lab telemetry (B): renaming the injector
drops the research injection signal and the IOC rule from 18/18 to **0/18**;
renaming the service binary, randomising pipe names and obfuscating command
lines change nothing. Switching to an unlisted auto-elevating binary drops the
UAC signal from 33 to **0**, while the generic test rises from 18 to **32** —
once no specific signal explains an elevation, the generic test stops
deferring to it.

## 5. It runs live with no loss

Replaying the lab corpus as a stream and scoring each window once, when it
closes, gives **160/160** alerts identical to the hindsight result; the median
time from elevation to alert is **83 s** of event time.

## 6. SigmaHQ detects more; CPES says which process gained privilege

Against 850 SigmaHQ core rules (C): Sigma detects **42/53** public captures and
106/126 lab runs (CPES 26/53 and 98/126), as expected (C1). The expectation that
Sigma would be much noisier outside attack runs was **wrong** (C2): 8 alerts
against CPES's one false-alarm process. What Sigma does not do is name the
elevated process: it flags the attacker's tools (`reg.exe`, `sc.exe`) and 0 of
33 elevated UAC processes or 28 service binaries. CPES complements a rule set;
it does not replace one.

## 7. A refined model did not survive held-out data

CPES v2 adds the generic test to the score. Pre-registered and frozen before
21 OTRF captures were opened (V2), it detected **6/13** escalation captures —
the same as v1 — because those captures rarely contain both parent and child as
process-creation records, which the generic test needs. **v2 was not adopted.**
The same run showed real remote-thread evidence detecting **4/4** injection
captures (SigmaHQ core 2/4), and the service rule's only "detection" was an
Azure agent, not the attack.

## 8. The service rule's false alarms cannot be fixed with this telemetry

Every service-rule false alarm on cloud captures is a vendor agent installed
outside `Program Files` (Defender, Azure). An exploratory check
([design/service-rule-feasibility.md](design/service-rule-feasibility.md))
found no structural discriminator in Sysmon-only data: signatures are missing
for most agents, attacker binaries are also staged before recording, and
service-registry writes are constant background noise. The one safe option, a
suppressor that trusts a validly signed own image, was pre-registered and run on
**100 OTRF captures never used before** (S1): it removed **0 of 7** vendor
alarms, because those captures record no image loads for the agents. **Not
adopted.** A real fix needs service-install events (System 7045 / Security 4697)
or unfiltered image loads; section 10 tests exactly that.

## 9. Joining CPES and Sigma helps less than hoped

Correlating both tools' alerts into incidents (I) names the elevated process in
**90/126** runs against Sigma's 0 — but that equals CPES alone, and only **7**
incidents actually join a Sigma alert to a CPES outcome. Service escalations
re-parent the elevated binary under `services.exe`, outside the attacker's
process tree, and the resolver records no actor for them. Fused incidents
remain useful as a hand-off format (report, ATT&CK layer, ECS alerts).

## 10. A second, live corpus: some figures held, UAC did not replicate

A new VM session (vm-live-v1) with every detector frozen: 30 minutes of benign
use, then the ten corpus-v3 Atomic tests five times each (50 runs), Microsoft
Defender left on, System 7045 and Security 4697 collected alongside Sysmon.

- **Overall detection fell short of the expectation**: CPES detected **20 of 50**
  runs against an expected ≥ 70% (L1 not supported), and **5 of 20** UAC runs
  against ≥ 80% (L2 not supported). Defender reported a successful detection in
  all 20 UAC runs. Inspecting the corpus afterwards (outside the protocol), the
  privilege gain actually happened only in the five sdclt runs: Event Viewer
  never started, Fodhelper was blocked before it ran, and ComputerDefaults ran
  without elevating. CPES flagged all five. The pre-registered denominator still
  counts all 20; without the Defender runs, CPES detects 15 of 30.
- **Service 10/10 and injection 5/5** replicated; injection is again caught by
  the `mavinject.exe` name. **Token theft 0/15**, below the lab's 8/24 (L3
  predicted a weakness). Inspecting the corpus afterwards, the token tests never
  reached SYSTEM on this VM: every process they started ran at High integrity,
  and no SYSTEM shell connected to a named pipe. So the runs contain no
  escalation for any detector to find, and they do not test the token signal.
- **No false alarms**: zero false-alarm processes from the research signals
  across the benign period and the session (L4).
- **Next to SigmaHQ**: Sigma flags 30/50 runs, CPES 20/50, together 35/50 (L7).
  Sigma flagged none of the UAC runs. In every run where the privileged process
  actually appeared (15), CPES named it and Sigma did not.
- **The service-rule fix works on this data (S2)**: keeping a service alert only
  when a service-install record names the same binary removed all **4** false
  alarms of the package engine (Defender's `MpCmdRun.exe`) and kept all 20
  service detections. The adoption criteria were met. The evidence is small: 4
  false alarms, one image, one machine. S2 is now the opt-in `service-install-only` resolver mode (section 12).

The session ran with one guest freeze and recovery, recorded in
[../lab/vm-session/SESSION-NOTES.md](../lab/vm-session/SESSION-NOTES.md).

## 11. The packaged engine can now reproduce the published figures

The dashboard engine (`cpes` package) has an opt-in **research-v3** mode that
applies the published research rules, including their two name rules
(`mavinject.exe`, `atomicservice`), which are labelled as such. It flags exactly
the same processes as the research scripts on corpus-v3 and on the live VM corpus,
and its grouped-CV F1 is **0.993** instead of 0.684. The gap was never a scoring
difference: it came from those name rules, a registry requirement, and a missing
parent check.

A structural alternative, **structural-v3**, adds the `services.exe` parent check
and service-install corroboration. On data already seen during development it
removed the recurring Defender false alarm (lab 12 → 1 benign service flags; VM 4 → 0)
but lost the service signal on 4 of 5 Potato-style public samples. The
service-install check alone kept those samples and removed the VM false alarms. Both
variants were then tested on a second VM (section 12).

## 12. A different Windows edition: every escalation that happened was caught

VM2 repeated the live session on Windows Server 2022 with every detector frozen and Defender's real-time
protection off during the attacks, so the signals rather than Defender were tested
([design](design/package-v3-and-vm2.md), RESULTS §15).

- **Detected 25 of 50 runs** against an expected ≥ 70% (V1 not supported), but **25 of 50 runs contained no
  escalation**: the token tests never reached SYSTEM (two of the three download their attack script at run time and
  cannot run on an isolated VM, which very likely also explains vm-live-v1's 0/15), Event Viewer never elevated on
  Server 2022, and `sdclt.exe` does not exist there. **Of the 25 runs where an escalation happened, the research
  signals flagged all 25** (UAC 10/10, service 10/10, injection 5/5), and the packaged research-v3 mode did the same
  with **no false alarm**.
- **The UAC signal replicated once Defender was out of the way**: Fodhelper 5/5 and ComputerDefaults 5/5 elevated
  and were flagged. On vm-live-v1 Defender had stopped them.
- **Injection is a name rule here too**: no remote-thread record exists (EID 8: 0), so only the `mavinject.exe` rule
  finds the five injections; the structural package (package-v2) finds none.
- **Next to SigmaHQ**: Sigma flagged more runs (35/50) but named the escalated process in **0 of 20** runs where it
  appeared; CPES named it in **20 of 20**. Together they cover **40/50** (V5 supported).
- **One false alarm, explained**: the research token rule treats every anonymous pipe as one pipe, so a benign SYSTEM
  `cmd.exe` connecting to `<Anonymous Pipe>` looked like impersonation. The packaged mode scopes pipes to their window
  and did not fire; this is V2's only difference (V2 not supported, so the dashboard default stays unchanged).
- **The service-rule fixes held** (V3/V4, V3b/V4b): every service detection kept. The test was weak, because without
  Defender's real-time protection its recurring false alarm never appeared. B2 alone (`service-install-only`) is now
  the recommended structural setting for telemetry with service-install events.

## What would change these conclusions

- Token-theft tests that run offline (bundling `Get-System.ps1` as a prerequisite), so the token signal is finally
  tested on escalations that complete; neither live session could.
- More hosts and techniques: every corpus so far is one machine at a time.
- Recording an actor for service escalations, so correlation can cross the
  `services.exe` boundary (section 9).
