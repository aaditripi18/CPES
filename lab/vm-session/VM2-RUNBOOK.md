# VM2 session runbook

Step-by-step procedure for the VM2 session pre-registered in
[docs/design/package-v3-and-vm2.md](../../docs/design/package-v3-and-vm2.md).
It follows the vm-live-v1 procedure ([SESSION-NOTES.md](SESSION-NOTES.md)) and differs
only where that document says so: Windows Server 2022, and Defender real-time
protection off during the attack runs.

**Rule:** anything that differs from the pre-registration is written down as a dated
amendment and committed *before the first attack run*. Once the first Atomic test
starts, nothing in the procedure changes; operational problems go into the session notes.

Times are rough: phase A–B about 3 h (mostly downloads and installs), phase D about 3.5 h.

## Phase A: build the VM (host, VirtualBox)

A1. Download the **Windows Server 2022 evaluation ISO** (64-bit, English) from the
    Microsoft Evaluation Center. Note the file name and its SHA-256:
    `Get-FileHash <iso> -Algorithm SHA256`.

A2. VirtualBox ▸ **New**:
    - Name `CPES-WinServer2022-VM2`, ISO from A1, type Microsoft Windows / Windows 2022 (64-bit).
    - Tick **Skip Unattended Installation** (you need to pick the Desktop Experience edition).
    - 8192 MB RAM, 4 CPUs, 80 GB dynamically allocated disk.

A3. VM ▸ **Settings** before first boot:
    - Network: Adapter 1 = **Host-only**, the same host-only network as vm-live-v1
      (`192.168.56.0/24`). Adapter 2 = **NAT**, for setup only.
    - General ▸ Advanced: shared clipboard **Disabled**, drag'n'drop **Disabled**.
    - No shared folder yet (B4 adds a temporary one).
    - Leave USB off and the mouse on PS/2. With the USB tablet (xHCI) on, the VM hung in
      the firmware on every guest-initiated restart during setup (2026-10-28).

A4. Boot and install **Windows Server 2022 Standard Evaluation (Desktop Experience)**,
    then choose Custom install on the empty disk. Set the built-in Administrator password.
    (Server Core lacks the GUI binaries the UAC tests rely on.)

A5. **Guest Additions** (needed for the shared folder in B4 and for a free mouse;
    vm-live-v1 had them too): VM window ▸ Devices ▸ **Insert Guest Additions CD image**,
    then run it silently from Win+R (elevated as the built-in Administrator):
    `powershell -NoProfile -Command "$d=(Get-Volume | Where-Object FileSystemLabel -like 'VBox*').DriveLetter; Start-Process ($d+':\VBoxWindowsAdditions.exe') -ArgumentList '/S' -Wait; Restart-Computer -Force"`.
    VM2 got Guest Additions 7.2.12 this way.

## Phase B: configure Windows (inside the VM)

B1. **Session user.** As Administrator, in an elevated PowerShell:
    ```powershell
    $pw = Read-Host -AsSecureString "Password for cpeslab"
    New-LocalUser cpeslab -Password $pw -PasswordNeverExpires
    Add-LocalGroupMember Administrators cpeslab
    ```
    Sign out, then sign in as **cpeslab** and use it for everything from here on.
    The built-in Administrator runs without UAC admin approval, so a UAC bypass from
    it gains nothing. vm-live-v1 also ran as an ordinary administrator (`cpeslab`).

B2. **Updates.** While NAT is on, run Windows Update once until nothing is pending, then
    reboot. In `sconfig`, set updates to **Manual** so nothing installs during the session.

B3. **Audit policy** (Security 4697 service installs), elevated:
    ```powershell
    auditpol /set /subcategory:"Security System Extension" /success:enable
    ```

B4. **Setup kit.** The vm-live-v1 configuration was copied out of that VM on
    2026-10-25 (it runs Sysmon 15.21 with `C:\CPES\sysmon-config-v2.xml`, config hash
    `SHA256=B58F8F5B...E2C8`; Winlogbeat 9.4.3 with Sysmon, System 7045, Security 4697).
    The host's git-ignored `lab-data\vm2\setup\` holds what VM2 needs:
    - `sysmon-config-v2.xml`: byte-identical to the file vm-live-v1 ran (the repo's
      `configs/sysmon-config-v2.xml` differs from it in one comment line, so use this one);
    - `winlogbeat.yml`: vm-live-v1's, with `cpes-live-v1` changed to `cpes-live-vm2` and
      the password replaced by a placeholder;
    - `heap.options`: the 2 GB Elasticsearch heap cap (`-Xms2g` / `-Xmx2g`), added during
      vm-live-v1 after its snapshot, so it is not in the copied VM;
    - `benign-period.ps1`, `run-attacks.ps1`, `preflight.ps1`.

    Claude attaches the kit to VM2 as a temporary shared folder `\\VBoxSvr\vm2setup`.
    In the VM, copy it to `C:\CPES-session\`:
    ```powershell
    New-Item -ItemType Directory -Force C:\CPES-session | Out-Null
    Copy-Item \\VBoxSvr\vm2setup\* C:\CPES-session\ -Force
    ```
    The shared folder is removed again in phase C. `elasticsearch.yml` is *not* copied:
    Elasticsearch writes its own on first start (it names the host).

B5. **Sysmon 15.21** (or the current Sysinternals release; record it). Elevated:
    ```powershell
    .\Sysmon64.exe -accepteula -i C:\CPES-session\sysmon-config-v2.xml
    .\Sysmon64.exe -c | Select-String "Config hash"
    ```
    The hash must read `SHA256=B58F8F5B8947588E3BDEFD93905927D496790B07E7B458BE6EF268BD2373E2C8`.

B6. **Elasticsearch 9.4.3** into `C:\Elastic\elasticsearch\elasticsearch-9.4.3`, as on
    vm-live-v1. Copy `C:\CPES-session\heap.options` into `config\jvm.options.d\`. On the first
    start (`bin\elasticsearch.bat`) note the generated `elastic` password, stop it with Ctrl+C,
    then install it as a service (`bin\elasticsearch-service.bat install`, then `start`).
    Allow the host to reach it:
    ```powershell
    New-NetFirewallRule -DisplayName "Elasticsearch 9200" -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Allow
    ```

B7. **Winlogbeat 9.4.3** into `C:\Elastic\winlogbeat-9.4.3-windows-x86_64`. Copy
    `C:\CPES-session\winlogbeat.yml` over the default one and put the `elastic` password from
    B6 in place of `PASTE-VM2-ELASTIC-PASSWORD-HERE`. The config sends events through the
    `winlogbeat-9.4.3-routing` ingest pipeline, so load the pipelines and template once,
    then install and start the service:
    ```powershell
    cd C:\Elastic\winlogbeat-9.4.3-windows-x86_64
    .\winlogbeat.exe test config -c winlogbeat.yml
    .\winlogbeat.exe setup --pipelines --index-management -c winlogbeat.yml
    .\install-service-winlogbeat.ps1
    Start-Service winlogbeat
    ```

B8. **Atomic Red Team**, elevated, with NAT on. Defender quarantines the atomics folder
    unless it is excluded, so exclude it first and record that you did:
    ```powershell
    Add-MpPreference -ExclusionPath C:\AtomicRedTeam
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics
    ```
    Then fetch each test's prerequisites:
    ```powershell
    Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
    foreach ($t in "T1548.002","T1543.003","T1055.001","T1134.001","T1134.002") { Invoke-AtomicTest $t -GetPrereqs }
    ```

B9. **Session scripts** are already in `C:\CPES-session\` from the kit (B4). They must be
    the committed versions, unchanged.

B10. **Preflight**, elevated, as cpeslab:
     ```powershell
     Set-ExecutionPolicy -Scope Process Bypass
     C:\CPES-session\preflight.ps1
     ```
     It changes nothing. Bring `C:\CPES-session\preflight.txt` back to the host.
     NAT is still on at this point, so the "no internet route" line is expected to fail.

B11. From the **host**, in this repo:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     $env:CPES_ES_URL = "https://<vm2-host-only-ip>:9200"
     $env:CPES_ES_PASSWORD = Read-Host "Elastic password"
     $env:CPES_ES_INDEX = "cpes-live-vm2"
     python lab/check_lab.py
     ```

## Phase C: freeze (host and VM)

C1. Claude writes **Amendment 2** to the design doc from `preflight.txt` and your setup notes:
    OS build, Sysmon version, atomics date, the cpeslab user, the index name, the Defender
    exclusion, and any test whose binary or prerequisites are missing on Server 2022.
    It is committed before C3.

C2. In the VM: **disable the NAT adapter** (VM ▸ Settings ▸ Network ▸ Adapter 2, untick
    *Enable*, or unplug its cable from the running VM), and remove any shared folder.
    Run `preflight.ps1` again: every line should be OK now, including "no internet route".

C3. Shut the VM down and take a snapshot named `vm2-ready`.

## Phase D: the session (one sitting)

D1. Start the VM and sign in as cpeslab. On the host, run `python lab/check_lab.py` (as in B11)
    and confirm recent events are flowing. Optionally start the dashboard and leave its
    Live page polling `cpes-live-vm2` (time-to-alert was planned but not recorded on vm-live-v1).

D2. **Benign period**, Defender still **on** (as on vm-live-v1), elevated window:
    ```powershell
    C:\CPES-session\benign-period.ps1
    ```
    Use the VM normally for the 30 minutes as the script tells you (Explorer, Notepad,
    Settings / Server Manager, Task Manager, two "Run as administrator" consents).

D3. **Defender real-time protection off**, elevated window, and record the state:
    ```powershell
    Set-MpPreference -DisableRealtimeMonitoring $true
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected |
        Export-Csv C:\CPES-session\defender-state-before-attacks.csv -NoTypeInformation
    ```
    `RealTimeProtectionEnabled` must read `False`.

D4. **Part 1: UAC.** In a **normal** (not elevated) PowerShell window as cpeslab:
    ```powershell
    Set-ExecutionPolicy -Scope Process Bypass
    C:\CPES-session\run-attacks.ps1 -Part uac
    ```
    20 runs, about 60 minutes. Don't use the VM meanwhile. Note anything odd (prompts,
    errors, freezes) with its clock time.

D5. **Part 2: admin.** In an **elevated** window:
    ```powershell
    C:\CPES-session\run-attacks.ps1 -Part admin
    ```
    30 runs, about 90 minutes.

D6. **Wait 10 minutes** after the last run (the corpus ends 10 min after it). Then, elevated:
    ```powershell
    Get-MpThreatDetection | Select-Object @{n='InitialDetectionTimeUtc';e={$_.InitialDetectionTime.ToUniversalTime().ToString('o')}}, ThreatID, ProcessName, Resources, ActionSuccess |
        Export-Csv C:\CPES-session\defender-detections.csv -NoTypeInformation
    Get-MpThreat          | Export-Csv C:\CPES-session\defender-threats.csv -NoTypeInformation
    ```

D7. **Export from the host** while Elasticsearch in the VM is still up. Take the start
    from `benign-period.csv` (`benign-start`) and the end = the last run in
    `atomic-log.csv` + 10 min, both in UTC:
    ```powershell
    $env:CPES_ES_INDEX = "cpes-live-vm2"
    python lab/export_live.py --name vm2 --start <benign-start>Z --end <last-run+10min>Z
    ```
    Note the document count and SHA-256 it prints.

D8. Copy `C:\CPES-session\*` (atomic-log.csv, benign-period.csv, preflight.txt,
    defender-*.csv) to the host's `lab-data/vm2/`; a temporary shared folder is fine now
    that the session is over. Then power off and **revert to `vm2-ready`**.

## Phase E: results (Claude)

Session notes, the `vm2` evaluation protocol (V1–V5, V3b, V4b), `results/vm2.json`,
RESULTS §15, the adoption decisions, README and changelog.
