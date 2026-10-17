# soc-lab

A build-it-yourself Security Operations Center lab and detection-engineering portfolio, running entirely on an Apple Silicon (ARM64) MacBook, plus a free cloud track for Microsoft KQL / Sentinel.

This repo is **two things at once**:

1. **A learning programme.** Twelve phases that take you from an empty laptop to someone who can stand up a SIEM, write and prove detections, automate SOC work in Python, and talk about all of it in an interview. The guide never hands you finished code for the things you're supposed to learn — it hands you a spec, tests, and a hint ladder.
2. **A portfolio.** By the end this repo contains working detections, Python tools with tests and CI, and incident write-ups. It is the artefact you link on your CV.

## Start here

Read [`guide/00-overview.md`](guide/00-overview.md). It explains how the guide works, the lab architecture, the disk budget, and how the Python track ramps from beginner to advanced. Then do the phases in order.

## Repo layout

```
soc-lab/
├── README.md                 ← you are here
├── guide/                    ← the programme, one file per phase
│   ├── 00-overview.md
│   ├── phase-00-foundations.md
│   ├── phase-01-telemetry.md
│   └── ...                    (phases 02–12 added as you progress)
├── infra/                    ← lab infrastructure (configs YOU fill in)
│   ├── fusion/               ← VM notes, network design
│   ├── elastic/              ← docker-compose, agent policies
│   └── windows/              ← Sysmon config, audit policy, GPO notes
├── detections/               ← your detection rules (Sigma + Elastic)
├── tools/                    ← your Python tools (one package per phase)
├── writeups/                 ← your incident reports and lab notes
├── datasets/                 ← downloaded attack datasets (gitignored)
└── evidence/                 ← screenshots / exports proving each phase
```

## Ground rules you set for yourself

- **No copy-paste of detection or tool code from an AI.** Infra config (Docker, Sysmon XML) may start from an annotated skeleton; everything you're meant to learn, you write.
- **Commit after every phase.** A messy, honest git history is itself evidence you did the work.
- **Every phase produces a write-up.** If you can't explain it, you haven't learned it.

## Safety

This lab generates and replays real malware-adjacent telemetry and runs offensive tooling (Kali, Atomic Red Team). Keep it on an **isolated host-only network**. Never point attack tools at anything you don't own. Details in Phase 0.
