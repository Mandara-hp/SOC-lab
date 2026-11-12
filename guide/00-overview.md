# 00 — Overview

Read this first. It's the map of what the lab is, how it's put together, and where to go next.

---

## 1. What this lab is

A self-contained **SOC / detection-engineering lab** built on a single Apple-Silicon laptop. It stands up a working SIEM, instruments a Windows endpoint with security telemetry, and ships a suite of **MITRE ATT&CK–mapped detection rules** — each one triggered with a benign simulation of the real technique and confirmed firing.

The aim is to demonstrate the full detection-engineering loop the way a real SOC runs it:

> **Visibility → Collection → Detection → Triage.** You can't detect what you can't see.

The tangible outputs are:
- **Detections that were written and proved** — each tested by simulating the technique, mapped to ATT&CK, with a note on what would evade it. See [`../detections/`](../detections/).
- **Reproducible, documented infrastructure** — the SIEM, the endpoint telemetry, and the build steps, all in this repo.

---

## 2. Why the hardware shapes the build (ARM64 reality)

The lab runs on an Apple-Silicon Mac — **ARM64 (aarch64)**, not x86-64. Most SOC-lab tutorials assume x86 and fail or mislead on ARM. The choices here were made deliberately for ARM, which is itself part of the engineering story:

| Component | Typical x86 tutorial | ARM64 choice made here |
|---|---|---|
| **SIEM** | "Install Splunk" | Splunk has **no ARM build** and crashes under emulation → **Elastic Stack**, which runs natively on ARM. |
| **Windows endpoint** | Any Windows 11 ISO | Must be **Windows 11 Arm64** (Microsoft publishes official Arm64 ISOs). |
| **Sysmon** | `Sysmon64.exe` | On Win11 ARM the normal driver is blocked → use **`Sysmon64a.exe`** (the ARM build). |
| **Endpoint agent** | Any agent | **Elastic Agent for Windows** (x86_64 under Win11-ARM emulation — no native ARM64 build at this version; works for log collection). |

Working around these constraints — reading vendor docs to confirm support and choosing tools on evidence — is exactly the kind of judgement the work calls for.

---

## 3. Lab architecture

```
                 Apple-Silicon Mac (host)
  ┌───────────────────────────────────────────────────────┐
  │  VMware Fusion — isolated virtual lab                  │
  │                                                        │
  │   ┌────────────────────┐      ┌────────────────────┐   │
  │   │ SIEM01             │      │ WS01               │   │
  │   │ Ubuntu Server ARM  │      │ Windows 11 ARM     │   │
  │   │ Elastic (Docker):  │◄─────┤ Sysmon (ARM) +     │   │
  │   │  Elasticsearch,    │ logs │ Windows event logs │   │
  │   │  Kibana, Fleet     │      │ Elastic Agent      │   │
  │   └────────────────────┘      └────────────────────┘   │
  │     stores + detects            generates telemetry    │
  └───────────────────────────────────────────────────────┘

  WS01 generates telemetry → Elastic Agent ships it → Fleet receives →
  Elasticsearch stores/indexes → Kibana searches it and runs the detection rules.
```

- **SIEM01** — Ubuntu Server (ARM) running the Elastic Stack in Docker (Elasticsearch, Kibana, Fleet Server) over TLS.
- **WS01** — Windows 11 (ARM) instrumented with Sysmon and native Windows logging, shipping telemetry via the Elastic Agent.

Telemetry sources collected: Sysmon (process creation, registry, network), the Windows Security log, and the Windows System log.

---

## 4. The detection approach

From the moment telemetry is flowing, the work is writing and validating detections:

- Every rule is **mapped to a MITRE ATT&CK technique** (e.g. `T1059.001` = PowerShell). ATT&CK is how the industry talks about attacker behaviour, so each detection carries its technique ID.
- Each rule is **validated** — the technique is simulated on WS01 with a benign command, and the alert is confirmed firing before the rule is considered done.
- Rules use both **signature-style** logic (process names, command lines) and **behavioural** logic (parent-child process lineage), plus **threshold** rules that collapse bursts (e.g. brute force) into a single alert.
- Rules are tuned for **alert fatigue** and exported as **detection-as-code** (re-importable rules + a documented catalog).

The full detection catalogue — logic, ATT&CK mapping, test triggers, and evasion notes — is in [`../detections/README.md`](../detections/README.md).

Primary ATT&CK reference: **https://attack.mitre.org**

---

## 5. What's in this repo

```
detections/   Exported detection rules (NDJSON) + documented catalog
guide/        This overview + the step-by-step build guide (phases 00–03)
infra/        Infrastructure build notes (endpoint telemetry, etc.)
writeups/     Attack → detect write-ups
```

The build is documented across the `guide/` phase files:
- **Phase 00 — Foundations:** the Mac toolchain, the repo, and the lab network.
- **Phase 01 — Telemetry:** what to log on the Windows endpoint and why.
- **Phase 02 — SIEM build:** the Elastic Stack, Fleet, and enrolling the endpoint.
- **Phase 03 — Attack → Detect:** simulating techniques and writing the detections.

---

## 6. Next

Start with [`phase-00-foundations.md`](phase-00-foundations.md) — it sets up the Mac, the repo, and the lab network, and ends with the first git commit.
