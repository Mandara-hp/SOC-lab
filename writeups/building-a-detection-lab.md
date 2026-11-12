# Building a SIEM Detection Lab — and Ten Detections That Actually Fire

A write-up of how I built an Elastic SIEM lab on an Apple-Silicon laptop, instrumented a Windows endpoint, and engineered ten MITRE ATT&CK–mapped detections — each one triggered with a benign simulation of the real technique and confirmed firing.

The goal was never "install a SIEM and watch some alerts." It was to practise the full loop a real SOC runs on: **visibility → collection → detection → triage**, and to be able to explain every rule — what it catches, and how an attacker would slip past it.

---

## The setup, and a hardware constraint that shaped everything

The whole lab runs in VMware Fusion on an Apple-Silicon (ARM64) Mac:

- **SIEM01** — Ubuntu Server running the Elastic Stack (Elasticsearch, Kibana, Fleet) in Docker, over TLS.
- **WS01** — Windows 11, instrumented with **Sysmon** and native Windows event logging, shipping telemetry to the SIEM via the Elastic Agent.

ARM64 forced real engineering decisions instead of copy-paste. Splunk has no ARM build and crashes under emulation, so I went with Elastic, which runs natively. Sysmon's normal driver is blocked on Windows-11-ARM, so the ARM-specific `Sysmon64a.exe` was required. There's no native Windows ARM64 Elastic Agent at this version, so the x86_64 agent runs under emulation — fine for log collection. Working around those constraints, and confirming support in vendor docs rather than assuming, is exactly the judgement the job asks for.

Once the pipeline was verified — WS01 → Agent → Fleet → Elasticsearch → Kibana — the real work began: writing detections.

---

## Three detections, told as an analyst would

I built ten rules across six ATT&CK tactics (Credential Access, Execution, Defense Evasion, Discovery, Command & Control, Persistence). Three of them show the range.

### 1. Encoded PowerShell (Execution — T1059.001)

**The behaviour:** attackers base64-encode PowerShell commands (`-EncodedCommand`) to hide what they're running from anyone reading the logs. Legitimate admins almost never do this.

**The rule** keys on the command line of a `powershell.exe` / `pwsh.exe` process containing an encoded-command flag. The first version was case-sensitive and only caught lowercase `-enc` — so I hardened it to catch the common casings (`-enc`, `-Enc`, `-ENC`) and added PowerShell 7. I validated it by running a harmless `-EncodedCommand` that just printed a string, and confirmed the alert fired on the capital-E form the first version would have missed.

**Evasion note:** a determined attacker can abbreviate to `-e` or obfuscate further; true case-insensitivity would need lowercasing the command line at ingest.

### 2. Brute force (Credential Access — T1110)

**The behaviour:** repeated failed logons from one host — the fingerprint of password guessing.

**The rule** is a *threshold* rule: count Windows failed-logon events (Event ID 4625) grouped by host, and alert when one host crosses five in the window. A single failed logon is noise; five in a couple of minutes is a signal. I triggered it with a loop of failed authentications and watched sixteen raw events collapse into **one** alert — which is the whole point of a threshold rule: one actionable alert for the burst, not sixteen.

### 3. Shell spawned by PowerShell (Execution — T1059.003, behavioural)

This one is different: it doesn't match a name or a string, it matches a **relationship** — a `cmd.exe` process whose *parent* is `powershell.exe`.

That matters because an attacker can rename a malicious binary, but they can't easily fake **who launched it**. Process name and path are attacker-controlled; process ancestry is much harder to forge. So the highest-signal endpoint detections key on parent-child lineage, not the process name alone. The same rule shape generalises straight to the classic phishing-killer — Microsoft Word spawning PowerShell. This is the jump from signature-style detection to behavioural detection, and it only works because Sysmon exposes the parent process that native logging doesn't cleanly provide.

---

## Two lessons worth more than the rules themselves

**Alert fatigue is real, and tuning is half the job.** My early query rules re-alerted the same event across overlapping schedule windows — one certutil command produced **21 duplicate alerts**. In a real SOC that's how analysts start ignoring the queue and how breaches get missed. Proper alert suppression is a paid Elastic feature, so on the free tier I tuned the rule schedule (longer run interval, shorter look-back) to minimise window overlap, cutting duplicates by ~85%. The trade-off is slightly slower alerts — and being able to explain *that* trade-off, and that enterprise tiers solve it with real suppression, is the kind of practical judgement interviewers probe for.

**AV is the first line; the SIEM is the backstop.** When I tried the real `certutil` download-cradle technique, Windows Defender blocked it outright — and Tamper Protection stopped me disabling Defender from PowerShell. That's Defender doing its job. But AV gets disabled, misconfigured, or evaded constantly, and when it does, the SIEM detection is what still catches the technique. That layered thinking — not relying on any single control — is the point of detection engineering.

---

## What I ended with

Ten detections spanning six ATT&CK tactics and four telemetry sources (Sysmon process events, the Windows Security log, the registry, and the Windows System log), covering the early attack lifecycle end to end: break in (brute force) → evade (mshta, log clearing) → look around (recon) → execute (encoded PowerShell, shell lineage) → phone home (certutil) → dig in (registry run key, new service, new account).

Every rule was built hunt-first — find the real event in Discover, read its actual fields, then write the query against them — validated by simulation, and exported as **detection-as-code**: re-importable rules plus a documented catalogue, version-controlled in Git.

The detection catalogue, with each rule's logic, ATT&CK mapping, test trigger, and evasion notes, is in the repository.
