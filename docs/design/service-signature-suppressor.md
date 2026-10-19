# Service rule + signature suppressor (S1) — pre-registration

Written 2026-10-19, before the test captures were downloaded. Background and
the exploratory check that led here: [service-rule-feasibility.md](service-rule-feasibility.md).

## Change under test

`service_dropped_binary` (S0, unchanged) fires on a SYSTEM-integrity process
whose image is outside `\Windows\` and `\Program Files`.

**S1** = S0, except the anchor is **suppressed** when Sysmon positively
recorded that the process's own image is validly signed: an EID 7 (image load)
record of the same process where `ImageLoaded` equals `Image` (case-insensitive),
`Signed` = `true` and `SignatureStatus` = `Valid`. Missing EID 7 data never
suppresses anything (unknown ≠ signed).

Implementation: `ContextResolver(..., validly_signed_process_guids=...)`, empty
by default so S0 behaviour is byte-identical; the set is built by
`cpes.context.signatures.validly_signed_processes` from EID 7 records.

Known, accepted limits (stated before the run): a signed attacker binary is
suppressed (a signed-binary service abuse would be missed); captures whose
Sysmon config filters image loads gain nothing.

## Data

**Test set T (never used before):** every OTRF Security-Datasets archive under
`datasets/atomic/windows/*/host/` at commit `d9d40ef`, excluding the 21 archives
of the held-out run — **100 archives, 47.6 MB**, pinned by SHA-256 in
`configs/external-datasets.json` when downloaded. Same mapping as the held-out
run (`otrf-sysmon-field-mapping-v1`, Amendment 1), research-v3 model, 300/150 s
windows, evidence channels on.

**Non-regression sets (development data, already seen):** lab corpus-v3
(package engine) and EVTX-ATTACK-SAMPLES privilege escalation.

## Measures and judging rule

For S0 and S1, every distinct (archive, image) `service_dropped_binary`
anchor in a detected window. Each S0 anchor is judged, mechanically:

* **vendor** — image path under `C:\ProgramData\Microsoft\Windows Defender\`,
  `C:\WindowsAzure\` or `C:\Packages\Plugins\`;
* **other** — everything else (treated as a possible attack).

Primary: number of S0 vendor anchors that S1 removes. Safety: number of
**other** anchors S1 removes on T, and any change in `service_dropped_binary`
anchors on the non-regression sets.

## Expectations

* S1 removes only Defender binaries (Azure agents had no EID 7 in the
  exploratory data): expected reduction small, under a quarter of the vendor
  anchors.
* S1 removes no **other** anchor on T, and changes nothing on the lab corpus
  (`AtomicService.exe` is recorded unsigned) or the EVTX samples (no EID 7).

## Adoption rule

S1 becomes the default resolver setting (dashboard runs and future protocols)
**iff** it removes ≥ 1 vendor anchor on T, removes **no** other anchor on T,
and leaves the non-regression sets unchanged. Otherwise it is not adopted and
S0 stays. Either way the outcome is recorded below.

## Outcome (recorded 2026-10-19, after the run; ../RESULTS.md §12)

Execution `service-signature-v1-20261019T075145Z` at clean commit `3642180`.

| Expectation | Outcome |
|---|---|
| S1 removes only Defender binaries; small reduction | **Did not hold — no reduction at all.** S0 raised 7 service anchors on T, all vendor (Azure agents: `CollectGuestLogs.exe`, `WaAppAgent.exe`, `WindowsAzureGuestAgent.exe`, `WindowsAzureNetAgent.exe`, `NetworkWatcherAgent.exe`); S1 removed **0**. No Defender binary alerted on T. |
| S1 removes no other anchor on T | **Held** (S0 raised no non-vendor service anchor on T). |
| No change on the lab corpus or EVTX samples | **Held** (0/66 EVTX files changed; lab anchors unchanged — `AtomicService.exe` is recorded unsigned, `MpCmdRun.exe` has no own-image record). |

**Verdict (pre-registered rule): S1 is not adopted;** the service rule stays S0.

Why, checked afterwards on one alerting archive (`collection__msf_record_mic.zip`;
descriptive, not part of the protocol): the capture has hundreds of image-load
records for ordinary processes but **none** for the alerting
`CollectGuestLogs.exe` process, so S1 had nothing to act on. 86 of the 100
archives contain own-image signature records (protocol output). The suppressor
is safe but did not touch the false alarms that actually occur.

Also visible on T: every service alert was a vendor agent; none was on an
attack. On cloud-hosted
Windows VMs this rule's precision is poor, and fixing it needs evidence these
captures do not carry (service-install events naming the binary, or unfiltered
image loads) — see [service-rule-feasibility.md](service-rule-feasibility.md).
