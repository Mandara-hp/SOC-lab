# Phase 1 — Telemetry first

**Objective:** A Windows 11 Arm64 VM that produces rich, security-relevant logs — correct audit policy, PowerShell logging, and Sysmon (ARM build) tuned and understood — *before* any SIEM exists to collect them.

**Why it matters in a SOC:** You cannot detect what you cannot see. A detection is only as good as the telemetry underneath it. Most junior analysts can read an alert; far fewer can answer "what log source would even show that, and is it turned on?" Doing telemetry *before* the SIEM forces you to understand each event on its own terms, so that in Phase 2 the SIEM is just a place to collect things you already understand — not a magic box. This is also the single biggest "depth" signal in an interview: anyone can install Sysmon; you'll be able to explain *which* events matter for *which* attacks and *why the defaults are wrong*.

---

## Concepts (read these first)

### Windows logging has layers

1. **Windows Event Log** — the built-in system. Events live in **channels**. The ones you care about:
   - `Security` — authentication, privilege use, object access, account/group changes. Driven by **audit policy** (off or thin by default).
   - `System` — service installs, driver loads, system-level events.
   - `Application` — app events.
   - `Microsoft-Windows-PowerShell/Operational` — PowerShell script-block & module logging (off by default).
   - `Microsoft-Windows-Sysmon/Operational` — Sysmon's channel (exists only after you install Sysmon).

2. **Event IDs** — each event type has a number. You'll memorise a core set (below). This is shared industry vocabulary, like ATT&CK IDs.

3. **Audit policy** — Windows won't write most Security events unless you *tell it to*. "Advanced Audit Policy" lets you enable specific categories (e.g. "Audit Process Creation") rather than blunt on/off. One critical extra setting makes 4688 events include the **full command line** — without it, process-creation events are nearly useless for detection.

4. **Sysmon** — a free Microsoft Sysinternals tool that adds a *much* richer, detection-focused event stream (process creation with hashes and parent process, network connections, image loads, named pipes, WMI, DNS, etc.). It's the backbone of most home and many enterprise detections. **It is driven by an XML config** — the default behaviour is thin, so the config is where the skill lives.

### The core event IDs to know cold

**Windows Security channel**

| Event ID | Meaning | Why it matters |
|---|---|---|
| 4624 | Successful logon | Who logged in, logon type (interactive/network/remote) |
| 4625 | Failed logon | Brute force, password spray |
| 4672 | Special privileges assigned at logon | Admin/privileged logon |
| 4688 | Process creation | *With command line enabled* = your single most valuable Security event |
| 4720 | User account created | Persistence / rogue account |
| 4728 / 4732 / 4756 | Member added to a privileged group | Privilege escalation |
| 4698 | Scheduled task created | Persistence |
| 7045 (System) | Service installed | Persistence / lateral movement (e.g. PsExec) |
| 4104 (PowerShell/Operational) | Script block logged | Deobfuscated PowerShell — catches fileless attacks |

**Sysmon operational channel** (the headline ones — full list in Sysmon's docs)

| Sysmon Event ID | Meaning | Why it matters |
|---|---|---|
| 1 | Process create (full cmdline, hashes, **parent process**) | Richer than 4688; parent-child chains reveal attacks |
| 3 | Network connection (process → dst IP/port) | C2, exfil, lateral movement |
| 7 | Image/DLL loaded | DLL side-loading, injected modules (noisy — tune it) |
| 8 | CreateRemoteThread | Code injection |
| 10 | ProcessAccess | Opening `lsass.exe` = likely credential dumping |
| 11 | File create | Dropped payloads, startup-folder persistence |
| 13 | Registry value set | Run-key persistence |
| 22 | DNS query | C2 domains, DGA |

> **Primary sources — live in these, don't trust memory:**
> Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
> Windows audit policy: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
> MITRE ATT&CK (for the "why"): https://attack.mitre.org

---

## Build spec

### 1.1 — Build the Windows 11 Arm64 VM

1. Download the **Windows 11 Arm64 ISO** from Microsoft's official page (`microsoft.com/software-download/windows11arm64`). Nothing else is legitimate for Apple Silicon.
2. In Fusion, create a new VM from that ISO. When asked, the guest OS is **Windows 11 64-bit Arm**.
3. Resources: **4 GB RAM** (you can lower to 3 GB when running Kali too), 2 CPUs, a 64 GB thin disk.
4. **Network: attach to `labnet` (host-only).** Attach NAT *temporarily* only for the install/activation and tool downloads; the design file already says to disconnect it afterward.
5. Install **VMware Tools** for ARM (Fusion → Virtual Machine → Install VMware Tools) so networking/clipboard/display work. On recent Win11 ARM the network driver may need the Tools install to get connectivity — expect this and don't panic if the first boot has no network.
6. Create a **local account** (you don't want this tied to a real Microsoft account). The common offline-install trick is to disconnect the network during OOBE; document whatever you do.
7. Set the static IP per your network-design file (e.g. `10.10.10.20`).
8. **Take your clean baseline snapshot now**, named `clean-baseline`. (This is your "one snapshot" for this VM — you'll replace it later, not stack on it.)

### 1.2 — Delete the ISO

Per the disk rules: once the VM boots and you've confirmed it works, delete the Windows ISO from the Mac. Note it in `writeups/phase1.md`.

### 1.3 — Enable Windows audit policy

Configure Advanced Audit Policy so the Security channel actually records what you need. At minimum enable (Success + Failure where relevant):

- Account Logon / Logon-Logoff: logon, logoff, account lockout
- Detailed Tracking: **Process Creation** (gives 4688)
- Account Management: user & security-group management
- Object Access: you can leave most off initially (noisy) — note which and why

Then enable the critical companion setting: **"Include command line in process creation events"** (Administrative Templates → System → Audit Process Creation). Without this, 4688 doesn't show what command actually ran.

> You may apply these via the Local Group Policy Editor (`gpedit.msc`) or `auditpol.exe`. Decide which, and record the exact settings in `infra/windows/audit-policy.md` so it's reproducible.

### 1.4 — Enable PowerShell logging

Turn on, via Group Policy (Administrative Templates → Windows Components → Windows PowerShell):

- **Script Block Logging** (produces 4104 — the big one; logs the *actual* code even if obfuscated)
- **Module Logging**
- Optionally **Transcription** (writes a transcript file per session)

### 1.5 — Install and tune Sysmon (ARM build)

1. Download Sysmon from the official Sysinternals page. The ZIP contains `Sysmon.exe`, `Sysmon64.exe`, and **`Sysmon64a.exe`** — the last is the **Arm64** build. On your Win11 ARM VM you must use `Sysmon64a.exe`; the x64 driver will fail with "driver blocked from loading."
2. **Do not install with a blank or default config.** Start from a well-known community base config so you're not staring at a blank XML — but your job is to **read it and tune it**, not run it blind. Two standard starting points (read their READMEs; do not just paste):
   - SwiftOnSecurity `sysmon-config` (a well-commented general baseline)
   - olafhartong `sysmon-modular` (modular, ATT&CK-tagged)
3. Install with your chosen config: `Sysmon64a.exe -accepteula -i <yourconfig>.xml`
4. Confirm events are flowing: open Event Viewer → `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational` and watch Event ID 1 appear as you open programs.
5. Save **your** tuned config to `infra/windows/sysmon-config.xml` and write, in comments or a sibling note, *why* you changed what you changed from the base (e.g. "excluded ImageLoad for VMware processes — too noisy, not security-relevant here").

> The point of 1.5 is the tuning judgement, not the install. "I took the SwiftOnSecurity base and tuned X, Y, Z for my environment because of noise/coverage trade-offs" is a strong, specific thing to say in an interview. "I installed Sysmon" is not.

### 1.6 — Generate benign baseline activity

You need to know what *normal* looks like before Phase 3's attacks. Do ordinary things on the VM — open apps, browse (via NAT, then disconnect), run a few PowerShell commands — and observe the events they produce. Note two or three "normal but suspicious-looking" patterns (e.g. legitimate `powershell.exe` spawned by a scheduled task) so you don't false-positive on them later.

---

## Acceptance tests

1. The Win11 ARM VM boots, has a static `labnet` IP, and a `clean-baseline` snapshot exists.
2. Open `cmd.exe` and run any command. In Event Viewer → Security, a **4688** event for it appears **and includes the full command line**. (If the command line is missing, 1.3's companion setting isn't applied.)
3. Run `Get-Date` in PowerShell. A **4104** script-block event appears in the PowerShell/Operational channel.
4. `Sysmon64a.exe -c` prints the active config without error (proves the ARM build installed and a config is loaded).
5. Opening Notepad produces a Sysmon **Event ID 1** with a populated `ParentImage` field.
6. `infra/windows/` contains committed `audit-policy.md` and `sysmon-config.xml`, and your write-up names at least 3 tuning decisions.
7. You can explain, from memory, the difference between **4688** and **Sysmon Event ID 1** (hint: parent process, hashes, richer fields — and why you'd want both).

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

If the Win11 ARM VM has no network after install, that's expected before VMware Tools is installed — the guest is missing the virtual NIC driver. Install Tools first; connectivity usually follows.

If Sysmon says the driver is blocked from loading, you used the wrong binary. There are three in the zip; only one is for ARM.
</details>

<details>
<summary>Hint 2 — approach</summary>

For audit policy, `auditpol /get /category:*` shows current state so you can confirm before/after. The "include command line" setting is a *separate* GPO from enabling 4688 — enabling process creation gives you the event; the companion setting adds the command line field. Both are needed.

For Sysmon tuning: skim the base config top-to-bottom once. Look for `onmatch="exclude"` blocks — those are the noise-reduction rules. Your tuning will mostly be adding excludes for *your* VM's noisy-but-benign processes (VMware tools, Edge updater), not rewriting detection logic.
</details>

<details>
<summary>Hint 3 — structure</summary>

Reproducible order: snapshot clean → audit policy (gpedit or auditpol) → confirm 4688 w/ cmdline → PowerShell logging → confirm 4104 → Sysmon install w/ base config → confirm EID 1 → tune excludes → re-install config with `-c` → generate baseline activity → commit configs. Snapshot again *replacing* clean-baseline only once everything works, naming it `telemetry-ready`.
</details>

---

## Break it

- **Disable one source and watch the blind spot appear.** Turn off PowerShell script-block logging, run an obfuscated one-liner (e.g. a base64-encoded `-EncodedCommand`), and confirm you now *can't* see what it did. Re-enable it and see the decoded script appear in 4104. This is the single most convincing demonstration of *why* telemetry config matters — screenshot both states.
- **Stop the Sysmon service** and note that Event ID 1 stops. Attackers do exactly this (defence evasion, `T1562` — Impair Defenses). How would you *detect* Sysmon being stopped? (Keep that question for Phase 3.)

---

## Evidence to commit

- `evidence/phase1/` — screenshots of: a 4688 with command line, a 4104 script block, a Sysmon EID 1 with parent process, and the "blind spot" before/after from Break it.
- `infra/windows/audit-policy.md`, `infra/windows/sysmon-config.xml`.
- `writeups/phase1.md` — what telemetry you enabled, your 3+ Sysmon tuning decisions and reasoning, and the obfuscated-PowerShell blind-spot demonstration in your own words.

**Commit message:** `feat(telemetry): win11 arm endpoint logging + tuned sysmon`

---

## Interview questions this phase lets you answer

1. "What log sources would you want on a Windows endpoint, and which are off by default?" → Security (needs audit policy), PowerShell operational, Sysmon (not present by default).
2. "What's the difference between Windows 4688 and Sysmon Event ID 1?" → parent process, file hashes, richer context in Sysmon; command line in 4688 needs a GPO.
3. "How would you detect obfuscated PowerShell?" → script-block logging (4104) logs the deobfuscated code.
4. "Sysmon config is huge — how do you decide what to log?" → start from a vetted baseline, tune excludes for environment noise, prioritise by ATT&CK coverage vs volume.
5. "How might an attacker blind you, and how would you notice?" → stopping Sysmon/clearing logs (T1562/T1070); detect service stop + log-clear events.

---

## Done? → Phase 2 (SIEM build) — *coming in the next installment*
