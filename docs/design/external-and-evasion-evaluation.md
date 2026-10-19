# External generalisation and evasion robustness — pre-registration

Written 2026-10-18 **before** any result in this document was computed. Inputs
inspected beforehand: file names, per-file Sysmon event-ID counts and which
EventData fields exist. No CPES, baseline or rule output had been produced on
these inputs.

## Part A — EVTX-ATTACK-SAMPLES (external, never seen by CPES)

**Data.** `sbousseaden/EVTX-ATTACK-SAMPLES`, folder *Privilege Escalation*, commit
`4ceed2f4706daf601c212a8f91c113dd85349a2c`, 66 files, pinned by SHA-256 in
`configs/external-datasets.json`. GPL-3.0 data, downloaded to `external/`
(git-ignored), never redistributed. Captures come from several machines and
dates (2019–2021), not from the CPES lab.

**What can be tested.** 53 files contain Sysmon events; 13 contain only Security
or System channel events, which CPES does not read — reported as *not
applicable*, not as misses. (Counts from the file list; the category of every
file is fixed in `evaluation/external.py` before running.)

**Engine.** The shipped package engine, unchanged: `CpesPipeline` with evidence
channels, frozen research weights (`dashboard/models/research-v3-full-table.json`,
derived from the CPES lab corpus only — so this is a true held-out test),
threshold 0.5, window 300 s / advance 150 s per file. Raw Sysmon fields are read
through declarative mappings (`configs/evtx-sysmon-*.yaml`); no field is
derived.

**Unit and label.** Unit = one sample file. Every file is a published
privilege-escalation capture, so the label is "attack" by construction; the
*category* below comes from the file name as published by the dataset author,
assigned here before running. Files contain little benign activity, so
precision is **not** estimated; instead every alert is listed with the process it
is anchored on, so a reader can judge it.

**Reported per file:** CPES decision and signals; the package's generic
"unexplained privilege gain" observation (an ablation signal, unweighted,
reported separately); the single-event integrity baseline; records rejected by
validation.

**Expectations (written now):**

| Category | Files | Expectation |
|---|---|---|
| UAC via a listed auto-elevating binary (eventvwr, sdclt) | 2 | Detected **iff** the hijack registry write and the elevated binary fall in one window. |
| UAC via other methods (UACME and named bypasses) | 33 | CPES's auto-elevation signal mostly **misses** — its binary list has four names. The generic test and the single-event baseline should catch the cases where parent and elevated child are both in the capture. This is the coverage boundary of a list-based signal. |
| Token impersonation (Potato family, PrintSpoofer, getsystem, RogueWinRM) | 7 | **Token signal: 0 detected.** These pipe events carry no `User` field, so the evidence builder cannot decide `user_is_system`; in the Potato variants the SYSTEM connector is the kernel (`System`), which the CPES rule (SYSTEM *shell* connects to a user pipe) does not model. The rotten-potato file has an EID 8 (w3wp → notepad), so `remote_thread_injection` may fire there. `service_dropped_binary` may fire where the exploit tool itself ends up at System from a user folder. |
| Service abuse (unquoted service path, PsExec) | 2 | Unquoted path may fire `service_dropped_binary` if the binary runs at System from outside the system directories; PsExec's `PSEXESVC.exe` lives in `C:\Windows`, so **no**. |
| Other exploits (CVE/spooler/registry/app-container/handle-inheritance/schtask) | 9 | Mostly **not detected**; `service_dropped_binary` may fire where a System-integrity process runs from a non-system path. |

Success criterion: none — this is a coverage measurement. The point is to show
honestly where the four modelled mechanisms generalise and where they do not.

## Part B — Evasion robustness on corpus-v3

**Question.** Do the detectors still fire when an attacker changes cheap,
attacker-controlled details? Mechanism-based signals should survive
renaming; name-based rules should not.

**Method.** Deterministic transforms of the corpus-v3 telemetry, each applied
only to the records of the labelled attack processes and the artifacts they
create; ground-truth labels are unchanged. Detectors re-run on each variant:
research signals (replicated on raw telemetry and verified first to equal the
labelled table exactly on the unmodified corpus), the package engine with
evidence channels, the IOC/signature rule and the single-event baseline.

| Variant | Transform | Expectation |
|---|---|---|
| V0 | none | equals the published table (gate) |
| V1 renamed injector | `mavinject.exe` → `msupdhlp.exe` (same signed binary, renamed copy) | research injection and IOC drop to 0/18 (both are image-name rules); package unchanged (already 0) |
| V2 renamed service binary | dropped service binary → `svchost_update.exe` in the same folder | research and package service signals unchanged (structural: SYSTEM, outside system dirs, parent services.exe) |
| V3 unlisted auto-elevating binary | elevated `fodhelper/eventvwr/sdclt/computerdefaults` → `wsreset.exe` | auto-elevation signal (research and package) drops to 0 — list-based; single-event baseline unchanged; generic test should still fire |
| V4 random pipe names | every pipe name → a random but consistent name | token signal unchanged (pairs create/connect by equality, not by name) |
| V5 obfuscated command lines | insert caret/quote noise into attack command lines | no CPES signal reads command lines → unchanged |

Reported: per-variant recall by technique for each detector, and benign false
positives (must be unchanged, since benign records are untouched).

## Outcome (recorded 2026-10-18, after the runs; numbers in ../RESULTS.md §6–7)

**Part A.** Held: listed-binary UAC detected when the hijack write and the
elevated binary share a window (eventvwr yes; sdclt no — the generic test
caught that file instead); list-based UAC does not generalise to other methods
(2/33, both UACME methods that use a listed binary); token signal 0 (17 pipe
records skipped for missing `User`); other exploits 0/9; PsExec not detected.
Not anticipated: CPES caught **5/7 token-impersonation files** through
`service_dropped_binary` (the exploit tool itself running at System from a user
folder: EfsPotato, RoguePotato, RogueWinRM, NetworkServiceExploit) and
`remote_thread_injection` (rotten potato). This is the same structural rule —
without the research rule's `parent = services.exe` condition — that produced
the 12 benign lab flags: broader coverage and more false alarms are the same
design choice. Across the 53 applicable files: CPES 9, generic test 19,
single-event rule 21, CPES-or-generic 26.

**Part B.** Every expectation held (V1 injector rename: research injection and
IOC 18/18 → 0/18; V2/V4/V5 no change; V3 list-based UAC 33/33 → 0/33 for CPES and
IOC, single-event unchanged). Not anticipated in size: the generic test rose
from 18/33 to **32/33** under V3, because once no specific signal explains the
elevation the generic test no longer suppresses it.

**What this supports.** Mechanism signals that read structure (service: SYSTEM +
location; token: pipe pairing) are robust to renaming; signals that read names
(injection, auto-elevation list) are not. The generic test is the complement
that covers renamed/unlisted elevation. A detector combining the specific
signals with a weighted generic test is the obvious next design — it must be
evaluated on data it was not designed on (a new external set or fresh lab
captures), since these results motivated it.

## Part C — CPES vs Sigma (pre-registered 2026-10-18, before any Sigma result)

**Rules.** SigmaHQ release `r2026-07-01`, packs *core* (the curated set) and
*all*, pinned in `configs/external-datasets.json`. Every Windows rule whose
log source is a Sysmon category present in the data is evaluated:
process_creation (EID 1), registry_add/set/delete/event (12/13/14),
pipe_created (17/18), create_remote_thread (8), process_access (10),
image_load (7), file_event (11), driver_load (6). Rules using features the
in-house matcher does not implement (aggregations, `base64*`, `wide`, `cidr`,
`fieldref`, keyword searches over Security-log text) are **skipped and
counted**, never guessed. The matcher (`evaluation/sigma.py`) implements Sigma
semantics: case-insensitive wildcard equality by default; `contains`,
`startswith`, `endswith`, `all`, `re`, `windash`, `exists`; lists are OR unless
`|all`; condition grammar with `and/or/not`, parentheses, `1 of X*`,
`all of X*`, `them`. It is unit-tested against hand-written rule/event pairs.

**Fields.** EVTX samples carry raw Sysmon EventData, used as-is. corpus-v3 is
ECS (Winlogbeat); a documented ECS→Sysmon field view supplies the Sysmon names
(Image, CommandLine, ParentImage, OriginalFileName, User = domain\name,
TargetObject, PipeName, …). Registry `Details` cannot be reproduced faithfully
from ECS, so rules that test `Details` are reported as *not evaluable on the
lab corpus*.

**Comparisons.**
1. Lab corpus, run level (E-c protocol): a logged run is detected if an alert
   fires within ±150 s; technique-consistent if the rule's ATT&CK tags include
   the run's technique (or its parent technique). Alert noise = alerts not
   within ±150 s of any run, by level.
2. EVTX-ATTACK-SAMPLES: per file, any alert at level ≥ high, and any alert at
   all.
3. Evasion V1 (renamed injector) and V3 (different auto-elevating binary).
   Amendment before running: V3 now also replaces the PE metadata
   (`OriginalFileName`, description) with WSReset's, because a different binary
   carries different metadata; V1 keeps them (a renamed copy keeps its PE
   header). Non-Sigma detectors do not read these fields, so their V3 results
   cannot change.

**Expectations.**
- Sigma *all* will detect **more** EVTX samples than CPES, especially UAC
  methods (UACME-specific rules exist). On breadth, CPES loses.
- Sigma will raise **far more alerts outside attack runs** on the lab corpus
  than CPES (1 false-alarm process), at medium level; fewer at high/critical.
- Sigma rules that test `OriginalFileName` survive V1 (rename), where the CPES
  research injection signal and the image-name IOC fail.
- Under V3, Sigma rules specific to fodhelper/eventvwr/sdclt/computerdefaults
  stop firing on those processes; any rule on the registry hijack keys keeps
  firing on the registry write.

## Outcome of Part C (recorded 2026-10-18, after the runs; ../RESULTS.md §9)

| Expectation | Outcome |
|---|---|
| Sigma *all* detects more EVTX samples than CPES | **Held, by a wide margin:** Sigma core high+ 42/53 applicable files, Sigma all any-level 47/53; CPES 9/53, CPES-or-generic 26/53. 3 of the 46 core rules that fired cite this dataset or its author. |
| Sigma raises far more alerts outside attack runs on the lab corpus | **Wrong.** Sigma core high+ raised 8 alerts (8 processes, 2 rules) outside any run; Sigma all any-level 21 alerts (13 processes). CPES research: 1 false-alarm process. Comparable noise. |
| Sigma `OriginalFileName` rules survive V1 | **Held.** Sigma injection detection unchanged under renaming. |
| Under V3, binary-specific Sigma rules stop firing; registry-hijack rules keep firing | **Superseded:** WSReset has its own Sigma rule, so Sigma's UAC detection on the elevated process rose (0/33 → 33/33). The variant tests "switch to another known bypass binary", which per-binary rules cover. |

Not anticipated: on the lab corpus Sigma core high+ flags a technique-consistent
alert in **106/126 runs** versus CPES research 98/126 and the package engine
56/126. CPES does not out-detect a mature community rule set on its own data.
What Sigma does not do is attribute the alert to the elevated process: it flags
0/33 elevated UAC processes and 0/28 service binaries (it alerts on the actor).
The defensible positioning is therefore *complementary*: Sigma for breadth of
"something suspicious ran", CPES for "which process gained privilege, by which
mechanism, with the evidence chain" — and a generic unexplained-gain test that
covers elevation through binaries no rule names.
