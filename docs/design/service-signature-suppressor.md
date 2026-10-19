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

## Outcome

_To be recorded after the run._
