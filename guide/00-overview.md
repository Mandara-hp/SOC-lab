# 00 — Overview: how this works

> Read this once, fully, before touching a VM. It is the map. Each later file is one leg of the journey.

---

## 1. What you're actually building, and why it's different

The default home SOC lab — install a SIEM, install Sysmon, watch some alerts appear — is now the *baseline* on UK graduate CVs. Everyone has done it, so it no longer differentiates you. Hiring managers for Tier-1 / junior roles have said plainly that they value a candidate who can **explain a triage decision and show a working lab** over one who has collected certificates with no operational practice.

So this programme is built around producing **three things an interviewer can actually inspect**, not around installing software:

1. **Detections you wrote and *proved*** — each one tested against real recorded attack data, mapped to MITRE ATT&CK, with a note on what evades it.
2. **Python tools in a public repo** — with tests, type hints, and automated checks (CI) that run on every commit.
3. **Incident write-ups** — short reports that read the way a real SOC ticket reads: what fired, what you checked, what you concluded, what you'd do next.

Everything in the twelve phases feeds one of those three outputs.

### The honest limits of a one-person lab

A lab you build alone cannot manufacture the *volume and ambiguity* of alerts that make triage a real skill. You'll see the alerts you caused, which you already know the answer to. That's a weakness, and you close it two ways:

- **Recorded attack datasets** (OTRF Security-Datasets) give you logs from attacks you *didn't* run and don't already understand — closer to real triage.
- **~2 hours a week of external guided triage** — BTLO (Blue Team Labs Online), LetsDefend, or TryHackMe SOC rooms. These throw pre-built alerts at you with a correct answer to check against. This guide is the spine; those are the sparring partner. (This is the one place I'm overriding your "only resource" ask — a single static document physically cannot be a triage queue.)

---

## 2. Why your hardware shapes everything (ARM64 reality)

Your MacBook Air M4 is **ARM64 (aarch64)**, not x86-64. Most SOC-lab tutorials assume x86 and will waste your time or fail silently. The research behind this guide confirmed, as of late 2026:

| Component | x86 tutorial assumption | ARM64 reality (what this guide does) |
|---|---|---|
| **SIEM** | "Install Splunk" | Splunk Enterprise has **no ARM build** and its Docker image crashes under emulation. → We use **Elastic**, which runs natively on ARM. |
| **Windows endpoint** | Any Windows 11 ISO | Must be **Windows 11 *Arm64*** (Microsoft now publishes official Arm64 ISOs). |
| **Sysmon** | `Sysmon64.exe` | On Win11 ARM the normal driver is *blocked from loading*. Use **`Sysmon64a.exe`** (the ARM build). |
| **Domain Controller** | "Spin up Windows Server + AD" | Windows Server **has no ARM64 release** and Microsoft says there are no plans. → AD attacks are learned via **replayed datasets** (Phase 8), which you build the replayer for. |
| **Endpoint agent** | Any agent | **Elastic Agent for Windows ARM64** (incl. Elastic Defend) exists, in technical preview. We use it and note the "preview" caveats. |
| **Microsoft KQL / Sentinel** | Runs locally | Sentinel is cloud-only anyway; we use **free cloud tiers** (no credit card) — see §5. |

None of this is a limitation on your learning. It's actually *more* instructive: working around platform constraints, reading vendor docs to confirm support, and choosing tools on evidence is exactly the engineering judgement the job wants.

---

## 3. Lab architecture

```
                         MacBook Air M4 — 16 GB RAM, 161 GB free
                         (host also = your Python dev box)
  ┌─────────────────────────────────────────────────────────────────────┐
  │  macOS host: uv (Python), git, VS Code, VMware Fusion (free)         │
  │                                                                       │
  │  VMware Fusion — two networks:                                        │
  │   • labnet   : host-only / private   10.10.10.0/24   (attack traffic)│
  │   • natnet   : NAT, internet         (updates/installs only)         │
  │                                                                       │
  │   ┌────────────────────┐  ┌────────────────────┐  ┌────────────────┐ │
  │   │ SIEM01             │  │ WS01               │  │ KALI01         │ │
  │   │ Ubuntu 24.04 ARM   │  │ Windows 11 ARM     │  │ Kali ARM       │ │
  │   │ Elastic (Docker)   │  │ Sysmon(ARM)+audit  │  │ attacker       │ │
  │   │ Fleet, Suricata,   │◄─┤ Elastic Agent      │  │ (run on demand)│ │
  │   │ Zeek               │  │ Atomic Red Team    │  │                │ │
  │   │ ~6 GB RAM          │  │ ~4 GB RAM          │  │ ~2 GB RAM      │ │
  │   └────────────────────┘  └────────────────────┘  └────────────────┘ │
  └─────────────────────────────────────────────────────────────────────┘
                                   │  (logs you export with your own code)
                                   ▼
             FREE CLOUD TRACK (£0, no credit card) — Phase 11
             • Azure Data Explorer free cluster  → practise Kusto KQL
             • Microsoft Sentinel 31-day free trial → the UK's #1 SIEM
             • Azure for Students ($100 credit, no card) as backstop
```

**The 16 GB rule:** you never run all three VMs at full tilt at once. Steady state is SIEM01 + WS01 (~10 GB committed, the rest for macOS). KALI01 boots only when you're actively attacking, and you pause WS01's heavy work while it runs. Phase 0 sets the RAM allocations that make this fit.

---

## 4. Disk budget (you have 161 GB — this is the plan that fits)

Disk, not RAM, is your tight constraint. Here's the budget. Stay inside it and you never need an external SSD.

| Item | Realistic size on disk | Notes |
|---|---|---|
| Win11 ARM VM | 25–35 GB | Thin-provisioned; grows with use |
| Ubuntu SIEM VM | 15–25 GB | Elastic + Docker images are the bulk |
| Kali ARM VM | 12–18 GB | Keep it minimal |
| ISOs (Win/Ubuntu/Kali) | ~11 GB | **Delete after install** — biggest easy win |
| Datasets + repo | 3–6 GB | `datasets/` is gitignored |
| **Steady-state total** | **~60–90 GB** | Comfortable inside 161 GB |

**The two rules that keep you out of trouble:**

1. **One snapshot per VM, maximum.** A VM snapshot stores every change since you took it; keep three and a single VM can silently eat 60 GB. Take a "clean baseline" snapshot after install, and *replace* it (don't stack) when you reach a new stable point.
2. **Delete ISOs once each VM boots.** You can re-download; you can't get the space back while they sit there.

A `disk-check` habit (run `df -h /` on the Mac, check Fusion's VM sizes) goes in your weekly routine. Phase 0 gives you the exact commands.

---

## 5. The free cloud track (why it exists, what it costs: £0)

Your local lab runs Elastic. But the **single most-requested SIEM skill in UK job ads is Microsoft Sentinel**, which uses **Kusto Query Language (KQL)**. Important trap: Elastic/Kibana also has a thing *called* "KQL" (Kibana Query Language) — it is **not** the same language. Employers mean Microsoft's Kusto KQL. A lab that only touches Elastic quietly misses the #1 skill.

You close that gap for free:

- **Azure Data Explorer free cluster** — needs *no Azure subscription and no credit card*, ~100 GB storage, lasts a year (often auto-extended). This is where you practise real Kusto KQL. You'll fill it with your own lab's logs using Python you wrote.
- **Microsoft Sentinel free trial** — first 10 GB/day is free for 31 days. You do a focused **31-day Sentinel sprint** at the end (Phase 11) so the clock only starts when you're ready to use it hard.
- **Azure for Students** — $100 credit, no credit card, for full-time university students (that's you). Backstop for anything beyond the free limits.
- **Learn Sentinel in the *Defender* portal, not the Azure portal.** After **31 March 2027** Sentinel lives only in the Microsoft Defender portal. Your visa runs to May 2027 and you'll be job-hunting into 2027 — learn the interface that will still exist.

---

## 6. How each phase is written (the format you're about to judge)

Every phase file has the same skeleton. This is deliberate: it trains you to work from a spec, which is what a real ticket or a real engineering task is.

- **Objective** — one sentence, what you'll have built.
- **Why it matters in a SOC** — the real-world reason, so you can answer "why did you do that?" in an interview.
- **Concepts** — the minimum theory, in plain terms, with links to the *primary* source (vendor docs, MITRE, Python docs). You're expected to read those; learning to read docs is part of the job.
- **Build spec** — requirements, interfaces, expected inputs/outputs. **No solution code for the things you're learning.**
- **Acceptance tests** — concrete checks. You're done when these pass. Many are commands you run or queries that must return a specific result.
- **Hint ladder** — three rungs, collapsed by default. Rung 1 = a nudge. Rung 2 = the approach / which functions. Rung 3 = pseudocode or structure. **Never finished code.** Use the lowest rung that unblocks you; every rung you skip is a rung you learned.
- **Break it** — deliberately damage what you built (kill a log source, evade your own rule) and observe. This is where real understanding forms.
- **Evidence to commit** — exactly what goes in `evidence/` and what to write in `writeups/`.
- **Interview questions** — what this phase lets you answer. Rehearse these out loud.

**The one exception to "no code":** infrastructure configuration (Docker Compose, Sysmon XML, TLS setup). You get *annotated skeletons with gaps you fill*, because writing a TLS cert chain from a blank file teaches nothing useful and just causes rage-quitting. You will still understand every line, because the annotations explain them and the acceptance tests force you to.

---

## 7. The Python track — ramp from beginner (your stated level) to advanced

You told me your Python is at the fundamentals level (syntax, loops, functions). The track is built for that start and climbs deliberately. Nothing advanced appears without an on-ramp in the same phase.

| Phase | Tool you build | New Python concepts (each introduced from scratch) |
|---|---|---|
| 4 | Log parser | reading files, `for`/generators, `re` (regex), `dict`, `dataclass`, basic type hints, `argparse` |
| 5 | Enrichment CLI | functions as objects, **decorators** (retry/cache/rate-limit), `httpx`, env vars & secrets, **pytest** + mocking, exceptions |
| 6 | SIEM API client + hunt runner | **context managers** (`with`), generator-based **pagination**, **pydantic** models, sessions, JSON APIs |
| 8 | Dataset replayer | **`asyncio`** (async/await), concurrency limits/backpressure, bulk APIs, timestamp math |
| 9 | Detection-as-code | **packaging** (`pyproject.toml`), `pySigma`, **GitHub Actions CI**, fixtures |
| 10 | Mini-SOAR | **FastAPI**, async web handlers, **`typing.Protocol`** (plugin design), structured logging, queues |

Each concept is introduced *because a tool needs it*, never as abstract theory. By Phase 10 you're writing typed, tested, async Python — advanced by any junior-role standard — but you got there one justified step at a time.

If a phase's Python feels too steep when you reach it, that's a signal to tell me and I'll add a warm-up exercise. Calibrating this is exactly why Phase 0 and Phase 1 come to you first.

---

## 8. MITRE ATT&CK — your shared vocabulary

From Phase 3 on, every detection is tagged with an ATT&CK **technique ID** (e.g. `T1059.001` = PowerShell). This is non-negotiable because it's how the whole industry talks about attacks. When an interviewer says "walk me through detecting credential dumping," the expected answer references `T1003` and its sub-techniques. You'll build the habit early so it's automatic.

Primary source you'll live in: **https://attack.mitre.org**.

---

## 9. Your definition of done

You can stop calling yourself "studying" and start calling yourself "job-ready for Tier-1 SOC / junior security engineer" when:

- [ ] The repo builds: someone can clone it, read it, and understand what you did.
- [ ] You have **≥20 detections**, each ATT&CK-tagged and tested against data.
- [ ] You have **≥4 Python tools**, each with tests and green CI.
- [ ] You have **≥3 incident write-ups** in SOC-ticket style.
- [ ] You can run both **Elastic (ES|QL/EQL)** and **Microsoft KQL** queries from memory for the common cases.
- [ ] You can answer every interview question listed across the phases, out loud, unprompted.
- [ ] You've mapped your work to **SC-200** and **BTL1** objectives (Phase 12) so you know exactly what a cert would add.

---

## 10. Next

Go to [`phase-00-foundations.md`](phase-00-foundations.md). It sets up the Mac, the repo, and the lab network — and ends with your first git commit.
