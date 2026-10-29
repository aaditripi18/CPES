# VM3 setup notes

Facts recorded while building and running VM3 ([VM3-RUNBOOK.md](VM3-RUNBOOK.md)), for the outcome
section of [docs/design/vm3-session.md](../../docs/design/vm3-session.md). Filled in as the session
proceeds; empty until then.

## Machine

- Base: _clone of `CPES-Windows11-Lab12` @ `vm-live-v1-ready`_ (or fresh Windows 11). VM `CPES-Windows11-VM3`.
- Windows 11 build: _TBD_. Host-only IP: _TBD_. USB off; clipboard and drag-and-drop disabled.
- Sysmon: _TBD_ with `sysmon-config-v2.xml`, config hash `B58F8F5B…2373E2C8`. Elasticsearch + Winlogbeat 9.4.3,
  index `cpes-live-vm3`.
- UAC binaries present: eventvwr, fodhelper, ComputerDefaults, **sdclt** (all on Windows 11).

## Token-offline shim

- Script URL fetched during setup: _TBD_.
- `Get-System.ps1` SHA-256 pin: _TBD_ (set in `token-offline-profile.ps1` `$CPES_TokenScriptSha256` and
  installed as `$PSHOME\Profile.ps1`).
- `CPES-TokenScriptOk` at freeze: _TBD (must be True)_.

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
