# ðŸŽ¯ Threat Hunting with MITRE ATT&CK, Splunk, Sigma & Atomic Red Team

**Author:** Wamba JosÃ©  
**Role focus:** SOC Analyst / Threat Hunter  
**Tools:** Splunk Enterprise (Docker) Â· Sysmon Â· Splunk Universal Forwarder Â· Atomic Red Team Â· Sigma Â· MITRE ATT&CK Navigator Â· VirtualBox

---

## ðŸ“Œ Overview

In this home lab I emulated **five real attacker techniques** from the MITRE ATT&CK framework on a Windows 10 endpoint, then **hunted for them in Splunk**, confirmed each hypothesis with evidence from **two independent log sources**, and turned every finding into a reusable **Sigma rule** and a **scheduled Splunk alert**.

Each hunt follows the same hypothesis-driven method used by SOC threat-hunting teams:

```
Hypothesis â†’ Emulate (Atomic Red Team) â†’ Hunt (SPL) â†’ Analyze â†’ Sigma rule â†’ Splunk alert â†’ Cleanup
```

**Result:** 5 techniques emulated Â· 5 hypotheses confirmed Â· 5 Sigma rules Â· 5 scheduled alerts Â· 1 benign event investigated and closed.

---

## ðŸ—ï¸ Lab Architecture

```
[ Windows host PC ]
   â”œâ”€â”€ Docker Desktop
   â”‚     â””â”€â”€ Splunk Enterprise container  â† SIEM (web UI :8000, receives logs on :9997)
   â”‚
   â””â”€â”€ VirtualBox
         â””â”€â”€ Win10-lab VM  (Host-Only 192.168.160.150 + NAT for internet)
               â”œâ”€â”€ Sysmon (SwiftOnSecurity config)   â† endpoint telemetry
               â”œâ”€â”€ PowerShell Script Block Logging   â† decoded PowerShell (4104)
               â”œâ”€â”€ Splunk Universal Forwarder â”€â”€â–º 192.168.160.1:9997
               â””â”€â”€ Atomic Red Team                   â† attack emulation
```

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise in Docker, persistent volumes, custom index `endpoint` |
| Add-ons | Splunk Add-on for Microsoft Windows, Splunk Add-on for Sysmon |
| Log sources | Sysmon Operational, Windows Security, System, PowerShell Operational |
| Network | VirtualBox Host-Only network (192.168.160.0/24) for log forwarding |

**Why Docker for Splunk?** One-command deployment, isolation from the host OS, persistent volumes for data and configuration, and an easy reset if something breaks.

![4 log sources arriving in Splunk](screenshots/14-splunk-4-sources.png)

---

## ðŸ—ºï¸ ATT&CK Coverage

| # | Technique | Tactic | Data source | Severity |
|---|---|---|---|---|
| 1 | **T1087.001** Local Account Discovery | Discovery | Sysmon 1 | Medium |
| 2 | **T1136.001** Create Local Account | Persistence | Sysmon 1 + Security 4720/4732 | High |
| 3 | **T1547.001** Registry Run Keys | Persistence, Privilege Escalation | Sysmon 1 + 13 | High |
| 4 | **T1053.005** Scheduled Task | Persistence, Execution | Sysmon 1 + Security 4698 | High |
| 5 | **T1059.001** Encoded PowerShell | Execution | Sysmon 1 + PowerShell 4104 | High |

![ATT&CK Navigator coverage](screenshots/53-attack-navigator-matrix.png)

The Navigator layer is in [`attack-navigator/threat-hunting-layer.json`](attack-navigator/threat-hunting-layer.json) and can be opened at <https://mitre-attack.github.io/attack-navigator/>.

---

## ðŸ”Ž Hunts

### Hunt 1 â€” T1087.001 Local Account Discovery
**Hypothesis:** An attacker enumerating local accounts will run `net.exe`, `net1.exe`, `whoami.exe` or `cmdkey.exe`, often several within seconds.

**Findings:** `whoami.exe` launched by `powershell.exe`; `net user`, `net localgroup` and `cmdkey /list` launched by `cmd.exe`, all by `WIN10-LAB\wamba` within a few seconds.

**Detection logic:** 3+ distinct discovery commands in 5 minutes. **The scheduled alert fired automatically** after the emulation.

![Hunt 1](screenshots/19-T1087-splunk-hunt.png)

---

### Hunt 2 â€” T1136.001 Create Local Account
**Hypothesis:** A backdoor account will appear as `net user ... /add` in Sysmon and as Security Event **4720**.

**Findings:**
```text
cmd.exe  ->  net user /add "T1136.001_CMD" "T1136.001_CMD!"
   net.exe  ->  net1 user /add "T1136.001_CMD" "T1136.001_CMD!"
```
- Security **4720** (account created) and **4732** (added to Users) in the **same second** as the Sysmon event â€” cross-source correlation.
- The backdoor **password was visible in clear text** in the command line.

**Benign finding:** A 4732 event adding an account to `Event Log Readers` was traced to legitimate admin work (granting the Splunk forwarder log access) â€” **investigated and closed as benign**.

![Hunt 2](screenshots/26b-T1136-security-4720-users.png)

---

### Hunt 3 â€” T1547.001 Registry Run Keys
**Hypothesis:** Run-key persistence will produce Sysmon **EventCode 13** (registry value set) on `CurrentVersion\Run`, written by `reg.exe` (EventCode 1).

**Findings:** `cmd.exe â†’ reg.exe REG ADD HKCU\...\CurrentVersion\Run /V "Atomic Red Team" /D C:\Path\AtomicRedTeam.exe`. The command (EventCode 1) and the registry write (EventCode 13) occurred **32 ms apart**. A baseline of legitimate Run values (OneDrive, Edge) was documented after cleanup.

![Hunt 3](screenshots/33-T1547-registry-hunt.png)

---

### Hunt 4 â€” T1053.005 Scheduled Task
**Hypothesis:** A malicious task will show `schtasks.exe /create` in Sysmon and Security Event **4698**.

**Preparation:** Event 4698 is not logged by default â€” enabled with
`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`

**Findings:** `schtasks /create` created task `\spawn` running `cmd.exe`; Security 4698 confirmed the creation by `wamba` at the same time as the Sysmon event.

![Hunt 4](screenshots/43-T1053-security-4698.png)

---

### Hunt 5 â€” T1059.001 Encoded PowerShell
**Hypothesis:** Encoded PowerShell will show `-EncodedCommand` in Sysmon, and Script Block Logging (**4104**) will reveal the decoded command.

**Findings:** `powershell.exe` spawned `powershell.exe -NoProfile -EncodedCommand VwByAGkA...` (unreadable). Script Block Logging recorded the decoded payload in clear text: `Write-Output "Hunt5 encoded test"; whoami`. **Obfuscation defeated.**

![Hunt 5](screenshots/50-T1059-scriptblock-decoded.png)

---

## ðŸ›¡ï¸ Detections

| Technique | Sigma rule | SPL | Splunk alert |
|---|---|---|---|
| T1087.001 | [sigma](sigma-rules/T1087.001_local_account_discovery.yml) | [spl](spl-queries/T1087.001_local_account_discovery.spl) | Hourly Â· Medium |
| T1136.001 | [sigma](sigma-rules/T1136.001_create_local_account.yml) | [spl](spl-queries/T1136.001_create_local_account.spl) | Hourly Â· High |
| T1547.001 | [sigma](sigma-rules/T1547.001_registry_run_key.yml) | [spl](spl-queries/T1547.001_registry_run_key.spl) | Hourly Â· High |
| T1053.005 | [sigma](sigma-rules/T1053.005_scheduled_task_creation.yml) | [spl](spl-queries/T1053.005_scheduled_task_creation.spl) | Hourly Â· High |
| T1059.001 | [sigma](sigma-rules/T1059.001_encoded_powershell.yml) | [spl](spl-queries/T1059.001_encoded_powershell.spl) | Hourly Â· High |

Sigma rules are vendor-neutral and can be converted to Splunk, Microsoft Sentinel, Elastic and other SIEMs.

---

## ðŸ§° Troubleshooting I Solved

Real problems encountered and fixed while building the lab:

- **Duplicate IP on the Host-Only network** â€” the host itself had a stray 192.168.160.10; found with `Get-NetIPAddress` (`AddressState: Duplicate`) and removed.
- **Forwarder could not read the Sysmon log** (`errorCode=5`, access denied) â€” switched the service from the virtual account to `LocalSystem`.
- **No field extraction for XML Windows events** â€” installed the Splunk Add-ons for Windows and Sysmon; verified with `table EventCode Image CommandLine`.
- **Events invisible in time-bound searches** â€” VM clock drift after snapshot restore; fixed with `w32tm /resync`.
- **Firewall blocking log forwarding** â€” added inbound rules for TCP 9997 and the Docker backend.
- **Security 4698 missing** â€” enabled the audit subcategory with `auditpol`.

---

## ðŸ“ Repository Structure

```
threat-hunting-mitre-attack/
â”œâ”€â”€ README.md
â”œâ”€â”€ screenshots/          # evidence for every phase and hunt
â”œâ”€â”€ sigma-rules/          # 5 Sigma detection rules (.yml)
â”œâ”€â”€ spl-queries/          # 5 Splunk detection searches (.spl)
â”œâ”€â”€ attack-navigator/     # ATT&CK Navigator layer (.json)
â””â”€â”€ report/
    â””â”€â”€ findings.txt      # full threat hunting findings
```

---

## ðŸ’¼ Skills Demonstrated

- Hypothesis-driven **threat hunting** mapped to **MITRE ATT&CK**
- **Adversary emulation** with Atomic Red Team
- **Splunk SPL**: filtering, `stats`, `bin`, `rex`, cross-source correlation
- **Detection engineering**: Sigma rules and scheduled SIEM alerts with severity
- **Windows telemetry**: Sysmon (1, 13), Security (4720, 4732, 4698), PowerShell (4104)
- **Log pipeline**: Universal Forwarder, `inputs.conf`, indexes, add-ons
- **Infrastructure**: Docker, VirtualBox networking, Windows firewall, audit policy
- **Triage**: separating malicious activity from benign admin activity

---

## âš ï¸ Disclaimer

All attacks were run in an **isolated lab VM** for educational purposes. Passwords shown in screenshots are lab-only test values.
