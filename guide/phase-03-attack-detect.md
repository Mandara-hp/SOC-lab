# Phase 3 — The attack → detect loop

**Objective:** Run controlled attacks against WS01 with Atomic Red Team, map each to MITRE ATT&CK, and write **10 custom detection rules** in Elastic that fire on them — each one tested, tuned against false positives, and documented with a triage write-up.

**Why it matters in a SOC:** This is the actual job of a detection engineer and the daily reality of an analyst: an attack technique exists, telemetry captures it, a detection fires, an analyst triages it. Doing the full loop yourself — *cause* the attack, *see* it in the logs, *write* the rule, *prove* it fires, *reduce* its false positives, *write up* the triage — is the most convincing thing in your entire portfolio. "I wrote and validated detections against real attack telemetry" beats a wall of certificates.

This phase is where your repo stops being "infrastructure" and starts being "detection engineering."

---

## Concepts (read these first)

### Atomic Red Team

**Atomic Red Team** (by Red Canary) is an open library of small, precise tests ("atomics"), each mapped to an ATT&CK technique. You run one atomic, it performs one technique (e.g. "dump LSASS", "create a run-key"), and you check whether your telemetry + detections caught it. It's the standard way to safely exercise detections.

- You drive it in PowerShell via the `Invoke-AtomicRedTeam` module.
- **ARM caveat (be honest in your write-up):** many atomics call x64 binaries, which Windows 11 ARM runs through its built-in x64 *emulation*. Most behavioural techniques still produce the right telemetry, but a few binary-specific tests may behave differently or fail. Note which ones did; "I validated technique coverage on an ARM endpoint and documented emulation edge cases" is a *stronger* portfolio signal than pretending everything was clean.

### The detection lifecycle (memorise this — it's an interview answer)

```
Technique (ATT&CK) → Telemetry (which event proves it?) → Logic (the rule)
      → Validate (atomic fires it; rule triggers) → Tune (kill false positives)
      → Document (triage write-up) → Maintain (what evades it?)
```

### What a good detection is (and isn't)

A detection is not "alert whenever `powershell.exe` runs" — that fires thousands of times a day and gets ignored. A *good* detection targets the **behaviour** that distinguishes malicious from benign: an encoded command, an unusual parent process, access to `lsass.exe` by a non-system process. You will feel this the moment you write your first naive rule and it buries you in noise. That feeling is the lesson.

### Writing rules in Elastic Security

- Kibana → Security → Rules → "Create rule."
- Rule types you'll use: **Custom query (KQL)** for simple field matches, **EQL** for behavioural/sequence logic (parent-child, "process did X then Y"), **Threshold** for "N events in M minutes" (e.g. failed logons).
- Every rule gets: a name, a **MITRE ATT&CK mapping**, severity, and a description of *why* it fires and what an analyst should check. You will **export every rule to `detections/`** (Elastic exports rules as `.ndjson`) so they live in git, not just in Kibana.

> **Primary sources:**
> Atomic Red Team: https://github.com/redcanaryco/atomic-red-team and https://www.atomicredteam.io
> ATT&CK: https://attack.mitre.org
> Elastic detection rules (also your Python reading for Phase 9): https://github.com/elastic/detection-rules

---

## Build spec

### 3.1 — Install the attack harness on WS01

Install `Invoke-AtomicRedTeam` and the atomics folder on WS01, per its install docs. **Take a fresh snapshot first** (`pre-attack`) so you can roll back a messy VM — some atomics intentionally leave artefacts.

### 3.2 — The target technique set (your first 10 detections)

All ten are generatable on a single endpoint with the telemetry you built in Phase 1. For each: run the atomic, find the telemetry, write the rule, validate, tune, document.

| # | Technique | ATT&CK ID | Primary telemetry | Detection idea (you write the logic) |
|---|---|---|---|---|
| 1 | Encoded PowerShell | T1059.001 | 4104 / Sysmon 1 | command line contains `-enc`/`-EncodedCommand`; or 4104 script block indicators |
| 2 | LSASS credential access | T1003.001 | Sysmon 10 | `TargetImage` ends `lsass.exe` and `SourceImage` is not a known-good process |
| 3 | Scheduled task persistence | T1053.005 | 4698 / Sysmon 1 (`schtasks.exe`) | task creation, especially with suspicious actions |
| 4 | Service installation | T1543.003 | 7045 (System) | new service with unusual binary path / user context |
| 5 | Run-key persistence | T1547.001 | Sysmon 13 | registry value set under a `...\CurrentVersion\Run` key |
| 6 | Ingress tool transfer | T1105 | Sysmon 1 / 3 | `certutil.exe -urlcache`, `bitsadmin /transfer`, unusual downloader |
| 7 | Defense evasion: log/Sysmon tamper | T1562 / T1070 | 4104, service-stop, 1102 | Sysmon service stopped, event log cleared |
| 8 | Local account creation | T1136.001 | 4720 | new local user, especially added to admins (4732) |
| 9 | Suspicious parent-child | T1059 / T1203 | Sysmon 1 (EQL) | `winword.exe`/`excel.exe` → `powershell.exe`/`cmd.exe` (Office spawning a shell) |
| 10 | Suspicious DNS / beaconing | T1071.004 | Sysmon 22 | repeated queries to one domain at regular intervals, or to a random-looking domain |

(Detections 9 and 10 are where EQL/threshold logic earns its keep — they're *behavioural*, not single-field matches.)

### 3.3 — For each detection, the required loop

1. **Run the atomic** for the technique (note the atomic number used).
2. **Find it in Discover** — write the KQL/EQL that isolates the malicious event(s). Save the query.
3. **Write the rule** in Elastic Security with ATT&CK mapping + a real description.
4. **Validate** — re-run the atomic; confirm the rule generates an alert.
5. **Tune** — generate *benign* activity that might trip it (e.g. a legitimate scheduled task) and adjust the rule or add exceptions until benign is quiet but malicious still fires. **Record the false positive you killed** — this is the gold interviewers dig for.
6. **Export** the rule's `.ndjson` to `detections/` and commit.
7. **Triage write-up** (short; see template below).

### 3.4 — Triage write-up template (put in `writeups/detections/`)

Each detection gets ~8–15 lines in SOC-ticket style:
```
Rule: <name>   ATT&CK: <Txxxx.xxx>   Severity: <low/med/high>
Trigger: what condition fires it (plain English)
Telemetry: which event IDs / ECS fields
Validation: atomic <id> run on <date>; alert fired (screenshot ref)
False positives considered: <benign thing that could trip it> → handled by <how>
Analyst guidance: if this fires, check <X, Y, Z> next; escalate if <condition>
Evasion: how an attacker could avoid this rule (be honest)
```

That "Evasion" line is what separates a detection engineer from someone who copied a rule. Every rule has a bypass; knowing yours is the skill.

---

## Acceptance tests

1. **10 rules** exist in Kibana → Security → Rules, each with a non-empty ATT&CK mapping.
2. Each rule has been **validated**: re-running its atomic produces an alert in the Security app (keep a screenshot per rule, or a single annotated alerts view).
3. At least **3 rules** have a documented, deliberately-handled **false positive** in their write-up.
4. `detections/` contains the exported `.ndjson` for all 10 rules, committed.
5. `writeups/detections/` contains a triage write-up per rule, each including an **Evasion** note.
6. At least **2 rules use behavioural logic** (EQL sequence or threshold), not just single-field KQL.
7. You can pick any one rule and explain, unprompted: what it detects, why that telemetry, what a false positive looks like, and how to evade it.

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Start with the easy single-field ones (1, 5, 8) to get the *loop* working end-to-end before attempting the behavioural ones (9, 10). Getting one full loop done — atomic → Discover → rule → alert → export → write-up — teaches you the whole machine; the other nine are repetition with variation.

For "find it in Discover": run the atomic, then sort Discover by time descending and look at what appeared in the last minute. The malicious events are usually obvious against your Phase 1 baseline.
</details>

<details>
<summary>Hint 2 — approach</summary>

For the LSASS rule (2): the signal is Sysmon Event ID 10 where `winlog.event_data.TargetImage` ends with `lsass.exe`. The *tuning* is excluding legitimate accessors (some AV/EDR, Windows itself). That exclusion list IS the false-positive handling you document.

For parent-child (9): EQL shines here. The shape is `process where process.parent.name in ("winword.exe","excel.exe") and process.name in ("powershell.exe","cmd.exe")`. Confirm the ECS field names in Discover first — don't guess field names, read them off a real event.

For beaconing (10): a threshold rule on Sysmon 22 grouped by destination domain, or eyeball the regularity in Discover. Perfect detection of beaconing is hard; a *reasonable* heuristic plus an honest Evasion note is the right scope for this phase.
</details>

<details>
<summary>Hint 3 — structure</summary>

Per-rule checklist you repeat 10×:
```
[ ] snapshot/know rollback point
[ ] run atomic (record number)
[ ] isolate event in Discover (save query)
[ ] create rule + ATT&CK mapping + description
[ ] re-run atomic → alert fires (screenshot)
[ ] generate a benign near-miss → tune → benign quiet, malicious fires
[ ] export .ndjson → detections/
[ ] write triage note incl. Evasion → writeups/detections/
[ ] git commit
```
Commit after *each* rule, not all ten at once — ten small commits is better evidence than one big one.
</details>

---

## Break it

- **Evade your own rule.** Take detection #1 (encoded PowerShell): your rule probably keys on `-enc`. Now run the same payload using a different abbreviation of the parameter or a lower-case/obfuscated variant. Watch your rule miss. *Now* improve it. This back-and-forth is detection engineering in miniature and makes a fantastic write-up.
- **Clear the Security event log** (`wevtutil cl Security`) after an attack and observe what you lose — and whether you logged the *clearing* itself (1102). This is detection #7 in action against you.

---

## Evidence to commit

- `detections/*.ndjson` (10 rules).
- `writeups/detections/*.md` (10 triage notes, each with Evasion).
- `evidence/phase3/` — the alerts view showing your rules firing; at least one before/after of the "evade your own rule" exercise.
- `writeups/phase3.md` — overview: your technique set, the single most stubborn false positive and how you killed it, and what the ARM/emulation caveats were for Atomic Red Team.

**Commit messages:** one per rule, e.g. `detect: T1003.001 lsass access via sysmon eid10`.

**CV line you've now earned (draft):** *"Authored and validated 10 MITRE ATT&CK-mapped detection rules in Elastic Security against Atomic Red Team telemetry, including behavioural (EQL) detections, with documented false-positive tuning and evasion analysis."*

---

## Interview questions this phase lets you answer

1. "Walk me through how you'd build a detection for credential dumping." → T1003.001, Sysmon EID 10 on lsass, exclude known-good accessors, validate with an atomic, note the evasion (direct syscalls / alternative dumpers).
2. "What makes a detection *good* vs noisy?" → targets distinguishing behaviour, tuned for FPs, has analyst guidance.
3. "How do you test a detection?" → Atomic Red Team → confirm alert → generate benign near-miss → tune.
4. "A rule is firing 500 times a day. What do you do?" → characterise the FP source, tune/exception without blinding the control, measure.
5. "How would an attacker evade your PowerShell detection?" → obfuscation, parameter abbreviation, LOLBins, AMSI bypass — and what layered telemetry (4104) still catches.
6. "Why map to ATT&CK?" → coverage measurement, shared language, gap analysis.

---

## Done? → Phase 4 (Python I — the log parser). *This is where the Python track begins, from fundamentals.*
