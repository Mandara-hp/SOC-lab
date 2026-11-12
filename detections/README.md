# Detection Rules

MITRE ATT&CK–mapped detection rules for the **SIEM & Detection Engineering Lab**, authored and validated in Elastic Security (Kibana) against a Sysmon-instrumented Windows 11 endpoint.

Each rule was built, triggered with a benign simulation of the real technique, and confirmed firing before being documented here.

## Environment

- **SIEM:** Elastic Stack 8.15.3 (Elasticsearch, Kibana, Fleet) on an isolated Ubuntu VM.
- **Monitored endpoint:** Windows 11 (`DESKTOP-K5UCSBI`), Elastic Agent + **Sysmon** (SwiftOnSecurity config).
- **Telemetry sources used:** Sysmon process creation (Event 1), Sysmon registry (Event 13), Windows Security log, Windows System log.
- **Query language:** KQL. **Rule types:** Custom Query and Threshold.

## Coverage summary

10 detections spanning 6 MITRE ATT&CK tactics across the early intrusion lifecycle:

| # | Detection | Rule type | Severity | Tactic | Technique |
|---|-----------|-----------|----------|--------|-----------|
| 1 | Suspicious Encoded PowerShell Execution | Query | High | Execution | T1059.001 |
| 2 | Possible Brute Force – Multiple Failed Logons | Threshold | Medium | Credential Access | T1110 |
| 3 | Certutil LOLBin Abuse – Download Cradle | Query | High | Command & Control | T1105 |
| 4 | Mshta Execution (LOLBin) | Query | High | Defense Evasion | T1218.005 |
| 5 | Command Shell Spawned by PowerShell | Query | Medium | Execution | T1059.003 |
| 6 | Host Reconnaissance Burst | Threshold | Medium | Discovery | T1082 |
| 7 | Registry Run Key Persistence | Query | High | Persistence | T1547.001 |
| 8 | New Windows Service Installed | Query | Medium | Persistence / Priv-Esc | T1543.003 |
| 9 | Event Log Cleared | Query | High | Defense Evasion | T1070.001 |
| 10 | New Local User Account Created | Query | Medium | Persistence | T1136.001 |

**Mapped to the attack lifecycle:** Credential Access (#2) → Defense Evasion (#4, #9) → Discovery (#6) → Execution (#1, #5) → Command & Control (#3) → Persistence (#7, #8, #10).

---

## Detections

### 1. Suspicious Encoded PowerShell Execution
- **MITRE:** T1059.001 (Command & Scripting Interpreter: PowerShell) · Execution
- **Severity:** High · **Data source:** Sysmon Event 1
- **Logic:**
  ```
  process.name : ("powershell.exe" or "pwsh.exe") and process.command_line : (*-enc* or *-Enc* or *-ENC*)
  ```
- **What it catches:** PowerShell launched with a base64-encoded command (`-enc` / `-EncodedCommand`), a near-universal obfuscation technique used to hide malicious script content from log review.
- **Test:** encode a harmless command and run `powershell.exe -EncodedCommand <b64>`.
- **Notes / evasion:** KQL keyword matches are case-sensitive, so the query enumerates common casings; also covers PowerShell 7 (`pwsh.exe`). A determined attacker could use the minimal `-e` abbreviation — future hardening would lowercase the command line at ingest for true case-insensitivity.

### 2. Possible Brute Force – Multiple Failed Logons
- **MITRE:** T1110 (Brute Force) · Credential Access
- **Severity:** Medium · **Data source:** Windows Security log (Event 4625)
- **Logic:** Threshold — `event.code : "4625"`, grouped by `host.name`, threshold **≥ 5**.
- **What it catches:** 5+ failed logons from a single host inside the rule window — the fingerprint of password guessing. A single failed logon is normal; a cluster is not.
- **Test:** repeated failed authentications, e.g. a loop of `net use \\127.0.0.1\IPC$ /user:baduser<n> WrongPass`.
- **Notes:** Threshold rules collapse the whole burst into one alert, avoiding alert fatigue.

### 3. Certutil LOLBin Abuse – Download Cradle
- **MITRE:** T1105 (Ingress Tool Transfer) · Command & Control
- **Severity:** High · **Data source:** Sysmon Event 1
- **Logic:**
  ```
  process.name : "certutil.exe" and process.command_line : *urlcache*
  ```
- **What it catches:** `certutil.exe` used with `-urlcache` to download files — a living-off-the-land technique that abuses a trusted Microsoft-signed binary as a malware download cradle.
- **Test:** `certutil.exe -urlcache *` (lists the cache; exercises the command pattern without a network download).
- **Notes:** Windows Defender blocks the live download variant, and Tamper Protection prevents disabling AV from PowerShell — a good illustration of **AV as the first line, SIEM detection as the backstop** for when AV is absent or evaded.

### 4. Mshta Execution (LOLBin)
- **MITRE:** T1218.005 (System Binary Proxy Execution: Mshta) · Defense Evasion
- **Severity:** High · **Data source:** Sysmon Event 1
- **Logic:**
  ```
  process.name : "mshta.exe"
  ```
- **What it catches:** execution of `mshta.exe`, a legitimate HTA host rarely used on modern business endpoints and commonly abused to run script payloads while blending in.
- **Test:** `mshta.exe about:blank`.
- **Notes:** mere execution is high-signal here; in a noisier environment this would be scoped by command-line or parent process.

### 5. Command Shell Spawned by PowerShell (behavioural)
- **MITRE:** T1059.003 (Windows Command Shell) · Execution
- **Severity:** Medium · **Data source:** Sysmon Event 1 (parent-child lineage)
- **Logic:**
  ```
  process.parent.name : "powershell.exe" and process.name : "cmd.exe"
  ```
- **What it catches:** a `cmd.exe` process whose **parent** is `powershell.exe`. This is a *behavioural* detection keyed on process **lineage**, not on a name or string — so it survives binary renaming. The same rule shape generalises to high-signal lineages such as `winword.exe → powershell.exe` (malicious Office macros).
- **Test:** `cmd.exe /c echo lineage-test` from a PowerShell session.
- **Notes:** demonstrates the shift from signature-style to behavioural detection; relies on Sysmon, which provides `process.parent.name` that native Windows logging does not cleanly expose.

### 6. Host Reconnaissance Burst
- **MITRE:** T1082 (System Information Discovery) · Discovery
- **Severity:** Medium · **Data source:** Sysmon Event 1
- **Logic:** Threshold —
  ```
  process.name : ("whoami.exe" or "systeminfo.exe" or "ipconfig.exe" or "net.exe" or "net1.exe" or "nltest.exe" or "tasklist.exe" or "hostname.exe" or "arp.exe")
  ```
  grouped by `host.name`, threshold **≥ 4**.
- **What it catches:** a burst of 4+ host/network discovery commands from one machine — the enumeration an attacker performs immediately after gaining access. Any single command is benign; the cluster is the signal.
- **Test:** run `whoami`, `hostname`, `ipconfig /all`, `systeminfo`, `net user`, `tasklist` in sequence.

### 7. Registry Run Key Persistence
- **MITRE:** T1547.001 (Boot/Logon Autostart: Registry Run Keys) · Persistence
- **Severity:** High · **Data source:** Sysmon Event 13 (registry value set)
- **Logic:**
  ```
  event.code : "13" and registry.path : *CurrentVersion* and registry.path : *Run*
  ```
- **What it catches:** writes to a `...\CurrentVersion\Run` autostart key, used by attackers to relaunch malware at every logon.
- **Test:** `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`.
- **Notes:** built hunt-first — the real event was located in Discover and its fields confirmed before authoring. Two wildcard conditions on `registry.path` avoid KQL backslash-escaping. Benign software also uses Run keys, so the `registry.data.strings` payload is reviewed during triage.

### 8. New Windows Service Installed
- **MITRE:** T1543.003 (Create/Modify System Process: Windows Service) · Persistence / Privilege Escalation / Lateral Movement
- **Severity:** Medium · **Data source:** Windows System log (Event 7045)
- **Logic:**
  ```
  event.code : "7045"
  ```
- **What it catches:** installation of a new Windows service. Services typically run as SYSTEM and auto-start, so one action grants persistence, privilege, and (via tools like PsExec) lateral movement.
- **Test:** `sc.exe create <name> binPath= "C:\Windows\System32\calc.exe" start= demand`.
- **Notes:** `winlog.event_data.AccountName = LocalSystem` confirms SYSTEM-level execution. Legitimate installers also create services → review the `ImagePath` during triage.

### 9. Event Log Cleared
- **MITRE:** T1070.001 (Indicator Removal: Clear Windows Event Logs) · Defense Evasion
- **Severity:** High · **Data source:** Windows Security / System logs
- **Logic:**
  ```
  event.code : "1102" or event.code : "104"
  ```
- **What it catches:** clearing of an event log (1102 = Security audit log cleared; 104 = another log cleared) — an anti-forensics / track-covering action that is rare in normal use. The act of clearing a log is itself logged.
- **Test:** `wevtutil cl Application` (generates Event 104 without touching security data).

### 10. New Local User Account Created
- **MITRE:** T1136.001 (Create Account: Local Account) · Persistence
- **Severity:** Medium · **Data source:** Windows Security log (Event 4720)
- **Logic:**
  ```
  event.code : "4720"
  ```
- **What it catches:** creation of a new local user account — a common backdoor for regaining access later. Rare and deliberate on a normal endpoint.
- **Test:** `net user <name> <password> /add`.

---

## Engineering notes

- **Hunt-first workflow:** for events whose field layout wasn't known (registry, service install), the technique was triggered first, the real event located in Discover, and the exact fields read before the rule was written — so queries match reality rather than guesses.
- **Alert tuning (alert fatigue):** on a Basic (free) licence, Elastic's alert suppression is a paid feature. Query rules were set to **run every 5 min with a 1 min look-back** to minimise overlapping-window duplicate alerts (verified: one rule dropped from 21 duplicate alerts to ~3). The trade-off is slightly higher alert latency. Threshold rules aggregate natively and don't exhibit this.
- **Multiple data sources & fallbacks:** the same behaviour often surfaces in more than one log (e.g. service creation appears as Event 7045 in the System log *and* as an `sc.exe` process via Sysmon) — useful when the preferred source isn't available.
- **Defensive context:** Windows Defender (with Tamper Protection) blocked the live malicious variants of some techniques. The SIEM detections exist as the backstop for environments where endpoint AV is disabled, misconfigured, or evaded.

## Validation

Every rule in this catalogue was triggered with a benign simulation of its technique and confirmed to generate an alert in Elastic Security. All test artefacts (accounts, services, registry entries) were removed after validation.
