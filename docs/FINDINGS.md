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
or unfiltered image loads.

## 9. Joining CPES and Sigma helps less than hoped

Correlating both tools' alerts into incidents (I) names the elevated process in
**90/126** runs against Sigma's 0 — but that equals CPES alone, and only **7**
incidents actually join a Sigma alert to a CPES outcome. Service escalations
re-parent the elevated binary under `services.exe`, outside the attacker's
process tree, and the resolver records no actor for them. Fused incidents
remain useful as a hand-off format (report, ATT&CK layer, ECS alerts).

## What would change these conclusions

- A second, independently collected corpus — ideally live captures from the
  planned VM lab, with System and Security logs alongside Sysmon, which would
  also make the service-install fix testable.
- Recording an actor for service escalations, so correlation can cross the
  `services.exe` boundary (section 9).
