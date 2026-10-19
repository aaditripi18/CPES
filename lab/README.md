# CPES detection lab

This turns CPES from an offline research tool into a **live detection lab**: your
Kali VM emulates attacker techniques against your Windows VM, Sysmon + Winlogbeat
ship the telemetry to Elasticsearch, and CPES scores it and shows explained alerts
— and we measure CPES against the rules real defenders use.

Everything here runs on **your own isolated VMs**. No internet access to the
Windows VM during tests, snapshots before every session, authorized test
frameworks only.

## The picture

```
  Kali VM                 Windows 11 VM                      Host (this repo)
  ─────────               ──────────────                     ────────────────
  adversary      ──▶      Sysmon  ──▶  Winlogbeat  ──▶  Elasticsearch  ──▶  CPES
  emulation              (records      (ships to         (stores)            live scorer
  (Atomic / Caldera)      events)       Elasticsearch)                       + dashboard
       │                                                                          ▲
       └──────────────── records exact attack times (ground-truth labels) ───────┘
```

All three machines sit on one **host-only network** so they can talk to each
other but the Windows VM has no path to the internet during a run.

## Phases (each one is demo-able on its own)

| Phase | What you get | Who does what |
|---|---|---|
| **0** | Lab is safe and healthy; telemetry flows to Elasticsearch | You run the steps; `lab/check_lab.py` confirms |
| **1** | CPES scores live telemetry; alerts appear in the dashboard in seconds | Claude builds the streaming scorer; you watch it |
| **2** | Attack scenarios from Kali with automatic, honest ground-truth labels | Claude builds the runner; you launch scenarios |
| **3** | CPES vs Sigma / Elastic rules on identical telemetry | Claude builds the comparison |
| **4** | Evasion robustness (renamed tools, swapped binaries) | Claude builds the test matrix; you run variants |
| **5** | False-alarms/day, Kibana + ATT&CK map, replay CI, demo video | Claude builds; you record normal activity |

## Phase 0 — lab safety and health check

Goal: both VMs isolated and snapshotted, and live Sysmon telemetry reaching
Elasticsearch where CPES (on the host) can read it. Resumable; ~1 hour.

### 0.1 Snapshot both VMs (VirtualBox)
In VirtualBox Manager, select each VM → **Machine ▸ Take Snapshot**. Name them
`before-cpes-lab`. This is your undo button for everything below.

### 0.2 Put both VMs on one host-only network
1. VirtualBox ▸ **Tools ▸ Network ▸ Host-only Networks ▸ Create** (if none exists).
   It will have a range like `192.168.56.0/24`.
2. For **each** VM: **Settings ▸ Network**
   - **Adapter 1**: Host-only Adapter, the network from step 1.
   - **Adapter 2 (Windows VM only, temporary)**: NAT — leave enabled *only while
     installing/updating software*. **Disable it before any attack run** so the
     Windows VM is fully isolated.
   - Kali: Host-only only (it needs no internet for the emulation frameworks once installed).
3. Start the Windows VM, open PowerShell, run `ipconfig` and note the host-only
   IPv4 (e.g. `192.168.56.10`). This is your `CPES_ES_URL` host.
4. From Kali, `ping <windows-host-only-ip>` should succeed. That's the attack path.

### 0.3 Is Elasticsearch still installed on the Windows VM?
In PowerShell on the Windows VM:
```powershell
Test-Path "C:\Elastic\elasticsearch\elasticsearch-9.4.3\bin\elasticsearch.bat"
```
- `True`  → it's installed; go to 0.4.
- `False` → it was removed or this is a different VM. Tell Claude; we install
  Elasticsearch 9.4.3 + Winlogbeat 9.4.3 together (10-minute guided step).

Also confirm Sysmon is running:
```powershell
Get-Service Sysmon*, Winlogbeat | Select-Object Name, Status
```

### 0.4 Start the stack and point it at a fresh index
We keep new lab telemetry separate from the old corpus by using a new index
pattern `cpes-live-*`. Claude will give you the exact Winlogbeat output setting
and the start commands based on what 0.3 finds.

### 0.5 Confirm it from the host
On the host, in this repo, with the venv active:
```powershell
.\.venv\Scripts\Activate.ps1
$env:CPES_ES_URL = "https://<windows-host-only-ip>:9200"
$env:CPES_ES_PASSWORD = "<elastic password>"
python lab/check_lab.py
```
Green `[ OK ]` down to "Lab is ready for live CPES" means Phase 0 is done.
`python lab/check_lab.py --list` lists the indices if you need to find the name.

When the health check passes, tell Claude **"Phase 0 done"** and we start Phase 1
(live scoring).

## Safety rules (always)
- Host-only network during attack runs; Windows VM NAT off.
- Snapshot before each session; revert after, so every run starts clean.
- Only published, authorized test frameworks (Atomic Red Team, Caldera) against
  your own VM. Never anything against a machine you don't own.
- No real malware — these frameworks emulate technique *behaviour*, which is
  exactly what a mechanism detector like CPES is meant to catch.
