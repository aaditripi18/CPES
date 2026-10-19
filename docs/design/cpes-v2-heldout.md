# CPES v2 and a held-out test on OTRF Security-Datasets — pre-registration

Written 2026-10-19 **before** any detector was run on the OTRF data. Inspected
beforehand: archive list and sizes, per-file Sysmon event-ID counts, and the
record field names. No CPES, generic-test, baseline or Sigma output existed for
these files when this was written.

## 1. Why a v2, and why a new dataset

The external and evasion tests (`external-and-evasion-evaluation.md`) showed:
the auto-elevation signal names four binaries and does not generalise; the
package's generic "unexplained privilege gain" test catches elevation through
unlisted binaries (18 → 32 of 33 under V3; 15 of 33 UACME files). Those results
*motivated* v2, so they cannot also be its evidence. v2 is therefore judged on a
dataset not used for anything so far.

## 2. CPES v2 (fixed now)

* **Signals:** the four v1 mechanism signals, unchanged, plus
  `unexplained_privilege_gain` (`cpes.detection.generic.GenericEscalationObservationGenerator`,
  default mediators `consent.exe`), now **weighted and scored**.
* **Weights:** v1's four frozen research weights unchanged. The generic weight is
  derived once, from the **lab corpus only**, with the same estimation policy
  (pseudocount 0.5, `cpes.derivation`), from per-process generic flags of the
  package engine against the lab labels. It is frozen in
  `dashboard/models/cpes-v2.json` before the held-out run.
* **Threshold:** 0.5, prior not applied (as v1). Consequence stated now: every
  weight exceeds 0.5, so a v2 decision is the OR of its five signals.
* **Service rule:** unchanged (the `parent = services.exe` question stays an
  open decision; the held-out results for it are reported, not acted on).

## 3. Held-out data

OTRF Security-Datasets (MIT), commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`,
21 archives (18 MB), pinned by SHA-256 in `configs/external-datasets.json`.
Captures from other lab environments (`theshire.local`), produced with Empire,
Covenant, PurpleSharp and Atomic tooling, with substantial background activity.

Field facts that limit what can be tested (fixed before running):
* The pipe events have no process user; `AccountName`/`UserID` describe the log
  writer (SYSTEM). The token signal **cannot fire**; pipe records are skipped.
* `@timestamp` (collector time, UTC, ≈1 s after the event) is used as event time.

**Unit** = one capture file. **Categories** from the published file name and
folder, fixed in `evaluation/heldout.py`:

| Category | Files | Expectation for v1 / v2 |
|---|---|---|
| UAC, listed binary (`empire_uac_shellapi_fodhelper`) | 1 | v1 detects if the ms-settings write and fodhelper at High share a window; v2 the same or more |
| UAC, other method (`psh_cmstp_execution_bypassuac`) | 1 | v1 **misses** (binary not listed); v2 detects only if the elevated child and its parent are both in the capture |
| Code injection (CreateRemoteThread, PE inject, mavinject, PurpleSharp) | 4 | v1 = v2: detected where a real EID 8 from an in-capture source exists (psinject has 88 EID 8); mavinject/PurpleSharp files show no EID 8 in the counts, so **likely missed** |
| Service-based execution as SYSTEM (fax service modification, PsExec, SmbExec, SharpSC create/start, service DLL hijack) | 7 | mostly **missed**: these run binaries from `C:\Windows`, which the structural rule excludes; possible hits where a payload runs from a non-system path |
| No Sysmon events (`empire_invoke_runas`) | 1 | not applicable |
| Not privilege escalation by dataset category (Run keys, scheduled task, WMI subscription, 3× event-log tampering, LSASS dump) | 7 | ideally **no** CPES alert; any alert is listed with its anchor for judgement — "elevated user" persistence can legitimately produce SYSTEM processes, so these are *controls*, not guaranteed negatives |

**Detectors, all on identical records:** CPES v1, CPES v2, generic test alone,
single-event integrity rule, Sigma core high+ (same matcher as Part C).

**Primary measure (fixed now):** number of the 13 privilege-escalation files
detected by v1 vs v2, and number of the 7 control files with any alert. v2 is
called an improvement only if it detects more escalation files **and** does not
alert on more control files than v1 plus one. Expected: small gain (cmstp is the
only file where the generic test plausibly adds a detection), no control cost.
The honest prior is that this held-out set is small and service-heavy, so v1 and
v2 may tie.

Secondary: alerts per 10,000 Sysmon events over the control files (noise rate),
for v1, v2, the single-event rule and Sigma core high+.
