# VM3 session runbook

Step-by-step for the VM3 session pre-registered in
[docs/design/vm3-session.md](../../docs/design/vm3-session.md). It reuses the VM2 procedure
([VM2-RUNBOOK.md](VM2-RUNBOOK.md)) and spells out only what differs: a **Windows 11** base, the
**token tests made to run offline**, and a **pilot dry run** before the recorded session.

Rule, as before: anything that differs from the pre-registration is a dated amendment committed
**before the first attack run** of the recorded session. The pilot never changes a detector, a
weight, or a hypothesis.

## Phase A: the Windows 11 VM

Fastest clean base is a **clone of the vm-live-v1 Windows 11 VM**, which already has Sysmon,
Elasticsearch, Winlogbeat and Atomic Red Team.

A1. In VirtualBox, right-click `CPES-Windows11-Lab12` ▸ **Clone**. Name `CPES-Windows11-VM3`,
    **Full clone**, clone from the `vm-live-v1-ready` snapshot, "Keep disk names" off. (Full clone,
    not linked, so VM3 is independent.)
A2. Settings: host-only adapter only for the session, a temporary NAT adapter for setup; clipboard
    and drag-and-drop **disabled**; USB **off** (VM2 froze on restart with the USB tablet on). Note the
    new host-only IP once booted (likely `192.168.56.x`, different from .101/.102).
A3. Boot, sign in as the lab admin user (not the built-in Administrator). Confirm Sysmon and the
    config hash, and that `eventvwr.exe`, `fodhelper.exe`, `ComputerDefaults.exe` **and `sdclt.exe`**
    all exist (they do on Windows 11).

If you prefer a fresh Windows 11 build instead, follow VM2-RUNBOOK phases A–B with the Windows 11
media; everything else here is the same.

## Phase B: reconfigure for VM3

B1. **Fresh index.** Change Winlogbeat's output to index **`cpes-live-vm3`** (and the template
    name/pattern), as VM2-RUNBOOK B7 did for its index. Restart Winlogbeat.
B2. **Clear old data (optional but clean).** If the clone's Elasticsearch still holds `cpes-live-v1`,
    leave it — the export reads only `cpes-live-vm3` by time range, so the old index is never touched.
B3. **Copy the VM3 kit** into `C:\CPES-session\`: `benign-period.ps1`, `run-attacks.ps1`,
    `preflight.ps1`, `token-offline-profile.ps1` (all from `lab/vm-session/` at this commit).
B4. **Fetch and pin the token script (NAT on).** The token atomics download one file at run time;
    fetch it once and pin it:
    ```powershell
    # URL is the one the T1134.001 atomics use; confirm it from the atomic yaml if upstream changed it.
    $u = 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/Get-System.ps1'
    Invoke-WebRequest $u -OutFile C:\CPES-session\Get-System.ps1 -UseBasicParsing
    (Get-FileHash C:\CPES-session\Get-System.ps1 -Algorithm SHA256).Hash   # record this
    ```
    Put that URL in `$CPES_TokenScriptMatch` is already the filename; put the recorded hash in
    `$CPES_TokenScriptSha256` inside `C:\CPES-session\token-offline-profile.ps1`, then install the
    shim machine-wide:
    ```powershell
    Copy-Item C:\CPES-session\token-offline-profile.ps1 "$PSHOME\Profile.ps1" -Force
    ```
    Record the URL and the pinned hash in `VM3-SETUP-NOTES.md` and in the design doc's setup section.
    **Amendment rule:** if the atomic uses a different URL or download method than the shim handles,
    extend the shim and re-pin **before** the pilot; commit the change.
B5. **Fetch Atomic prerequisites (NAT on)**, as VM2-RUNBOOK B8:
    `foreach ($t in "T1548.002","T1543.003","T1055.001","T1134.001","T1134.002") { Invoke-AtomicTest $t -GetPrereqs }`.
B6. **Preflight** (`preflight.ps1`), elevated. Then, still elevated, confirm the token shim:
    ```powershell
    . C:\CPES-session\token-offline-profile.ps1; CPES-TokenScriptOk   # must print True
    ```
B7. Host health check (`lab/check_lab.py`, `CPES_ES_INDEX=cpes-live-vm3`, VPN off for the check).

## Phase C: freeze

C1. Disable the NAT adapter, remove any shared folder. Final preflight: all OK, no internet route,
    token shim True.
C2. Shut the VM down cleanly and take snapshot **`vm3-ready`** (powered off — never a live snapshot;
    VM2's live snapshot froze the guest and the host).

## Phase D: pilot (throwaway)

D1. Start from `vm3-ready`, sign in. Turn Defender real-time protection off
    (`Set-MpPreference -DisableRealtimeMonitoring 1`), as in the real session.
D2. **One round of all ten tests**, logging to a separate file:
    ```powershell
    # normal (non-admin) window:
    C:\CPES-session\run-attacks.ps1 -Part uac   -Rounds 1 -LogName pilot-atomic-log.csv
    # elevated window:
    C:\CPES-session\run-attacks.ps1 -Part admin -Rounds 1 -LogName pilot-atomic-log.csv
    ```
D3. Export that slice to `lab-data/vm3/pilot-corpus.ndjson` and copy `pilot-atomic-log.csv`, then:
    ```powershell
    python -m evaluation.vm3 --pilot
    ```
    It prints, per test, `escalated` or `DID NOT escalate`.
D4. **Revert to `vm3-ready`.** The pilot corpus is discarded.
D5. If any test shows `DID NOT escalate`: fix the cause (e.g. extend the token shim), re-pin,
    re-snapshot `vm3-ready`, and re-run the pilot; or, if it genuinely cannot complete here, write a
    dated amendment declaring it "cannot complete", keep it in the procedure, and report it
    separately — **before** the recorded session. Commit the amendment.

## Phase E: the recorded session

Exactly VM2 Phase D, from `vm3-ready-postupdate` (see the 2026-10-29 amendment; build 26200.9711,
paravirt minimal): 30-min benign period (Defender on) → Defender real-time
protection off, state exported → part 1 (20 UAC runs, non-admin) → part 2 (30 runs, elevated) →
wait 10 min → export Defender history → export the corpus:
```powershell
python lab/export_live.py --name vm3 --start <benign-start>Z --end <last-run+10min>Z
```
Record the document count and SHA-256 in `VM3-SETUP-NOTES.md` and set `vm3.CORPUS_SHA256`.

## Phase F: results (Claude)

`python -m evaluation.run vm3`, then RESULTS §16, FINDINGS, README, CHANGELOG, and the pre-registration
outcome table. The token-signal first test (W3) and the completed-escalation detection rate (W1) are the
new contributions.

## Operational reminders (from VM1/VM2)

- **Restoring `vm3-ready-postupdate` resets `--paravirtprovider` to hyperv** (the snapshot stores the
  hyperv config). Re-apply **`VBoxManage modifyvm "CPES-Windows11-VM3" --paravirtprovider minimal`**
  after every restore and before starting, or the guest hangs mid-session (frozen clock, no disk I/O).
  Verify with `showvminfo --machinereadable | grep paravirt` → both nominal and effective `minimal`.
- Proton VPN and McAfee VPN on the host block the host-only network — disconnect for host checks and the export.
- Never take a **live** snapshot; power off first.
- Host key is Left Ctrl + Left Alt. Start the VM so its window can close without stopping it
  (`--type separate` or headless) only if you are comfortable with that; otherwise a normal window is fine.
- Typing into the VM from the host drops/shifts characters on long lines and after `:` or `\\`; prefer
  signing in and running the kit scripts directly in the VM.
