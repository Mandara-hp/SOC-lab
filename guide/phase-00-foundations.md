# Phase 0 — Foundations

**Objective:** A prepared Mac, a version-controlled repo with its skeleton, a correctly isolated VMware Fusion lab network, and a written network design — committed to git.

**Why it matters in a SOC:** Before anyone detects anything, someone built the environment: segmented networks, a place for evidence, a repeatable setup. Getting network isolation *wrong* in a malware lab is how people infect their real machine or their home network. "I designed an isolated lab and can explain the segmentation" is a legitimate interview answer. Rushing this phase is the single most common way home labs become a liability instead of an asset.

---

## Concepts (read these first)

**Host-only vs NAT vs Bridged networking.** A VM's virtual NIC attaches to a virtual network. The three modes matter enormously for a malware lab:

- **Bridged** — the VM gets an IP on your *real* home/university network, as if it were a physical machine plugged into the wall. **Never use this for the Windows or Kali VMs.** Attack traffic would reach your real LAN.
- **NAT** — the VM shares the Mac's internet connection through a private address; it can reach the internet but your LAN can't easily reach *it*. Fine for pulling updates and installers.
- **Host-only / private** — the VM can talk only to the Mac and to other VMs on that same private network, with **no internet path**. This is where attack traffic lives.

Your design uses **two networks**: a private `labnet` for attacker↔victim↔SIEM traffic, and NAT only when a VM genuinely needs to download something. During active attacks, you disconnect NAT so the compromised VM is fully contained.

**Why a repo from minute one.** The commit history *is* evidence. An interviewer who sees 40 commits over three months spanning "add Sysmon config" → "first detection fires" → "async replayer" is looking at proof of sustained, real work. Start committing before you've built anything impressive.

**`uv` instead of raw `pip`/`venv`.** `uv` is the modern Python project/dependency manager (one fast tool that replaces `pip`, `venv`, and more). You're a beginner, so learning the current standard tool now saves you re-learning later. It's what you'll meet in modern codebases.

---

## Build spec

### 0.1 — Prepare the Mac

Install, via the terminal, in this order. (These are environment-setup commands, not the code you're here to learn — run them as given.)

1. **Homebrew** (macOS package manager) — from https://brew.sh (one command, on their homepage).
2. Using brew: **git**, **uv**, **Visual Studio Code**, and **VMware Fusion**.
   - `brew install git uv`
   - `brew install --cask visual-studio-code`
   - `brew install --cask vmware-fusion`  *(Fusion is free for personal use; a free Broadcom account is required at download/first-run.)*
3. Configure git identity: set `user.name` and `user.email` (use the email tied to your GitHub account).
4. Create a **GitHub account** if you don't have one, and generate an **SSH key** (`ssh-keygen -t ed25519`), then add the public key to GitHub. (GitHub's own docs walk this exactly — search "GitHub add SSH key".)

> ARM note: all four tools are native Apple-Silicon. If brew ever installs something under Rosetta, you'll see it warn — for these four you won't.

### 0.2 — Create the repo and its skeleton

1. On GitHub, create a **private** repo named `soc-lab`. (Keep it private until Phase 12, when you polish and make it public — you don't want half-finished work judged.)
2. Clone it to the Mac.
3. Create the directory skeleton from the README's "Repo layout" section (`guide/`, `infra/`, `detections/`, `writeups/`).
4. Add a `.gitignore` that excludes at least: `datasets/`, VM files, `.env` and any secrets, `__pycache__/`, `.venv/`, OS cruft (`.DS_Store`).
5. Add this guide's files into `guide/` (you'll receive them as they're written).
6. **First commit:** message `chore: initial repo skeleton`. Push it.

### 0.3 — Define the lab network (design before you build)

Write `infra/fusion/network-design.md`. It must specify:

- The two networks (`labnet` private `10.10.10.0/24`; NAT for updates), and the rule for when NAT is connected vs disconnected.
- A static IP plan: which host gets which address (e.g. `.10` SIEM01, `.20` WS01, `.30` KALI01 — your choice, just write it down).
- A one-paragraph **threat/safety statement**: what traffic is allowed to leave the lab (answer: effectively none during attacks), and what would happen if you got it wrong.
- A simple diagram (ASCII is fine) of the two networks and the three VMs.

### 0.4 — Create the custom Fusion network

In VMware Fusion → Settings → Network, create a **custom** network for `labnet`:

- Private to host (host-only); **no** "Connect this network to the internet / NAT".
- Subnet `10.10.10.0`, mask `255.255.255.0`.
- DHCP: your call — static IPs are cleaner for a lab, so you may disable DHCP and assign inside each guest. Document whichever you choose in the design file.

You won't attach VMs yet (no VMs exist). You're creating the network they'll plug into.

### 0.5 — Establish the disk-hygiene habit

Add `infra/fusion/disk-budget.md` containing the budget table from the overview, plus the two commands you'll run weekly:

- `df -h /` (Mac free space)
- Fusion → Virtual Machine Library shows each VM's size; note where snapshots are managed.

Write down the two rules (one snapshot per VM; delete ISOs after install) so future-you can't claim ignorance.

---

## Acceptance tests

You are done with Phase 0 when **all** of these are true:

1. `git -C <repo> log --oneline` shows at least one commit, and the repo exists on GitHub (private).
2. `uv --version`, `git --version`, and `code --version` all print a version on the Mac.
3. VMware Fusion opens and the custom `labnet` network appears in its network settings with **no NAT/internet** enabled.
4. `infra/fusion/network-design.md` exists, is committed, and contains the IP plan + safety statement + diagram.
5. `.gitignore` is committed and actually ignores `datasets/` and `.env` (test: create `datasets/test.txt` and confirm `git status` does not list it).
6. You can state, from memory, the difference between host-only, NAT, and bridged — and why bridged is banned here.

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Everything in 0.1 is "follow the official page." Homebrew's homepage has the one install line; GitHub's docs have the exact SSH steps. Don't improvise these; the whole point is building the habit of following vendor docs precisely.
</details>

<details>
<summary>Hint 2 — approach</summary>

For the skeleton (0.2), you can create all the empty dirs at once and drop a `.gitkeep` file in each so git tracks the empty folder. For `.gitignore`, GitHub maintains template `.gitignore` files for Python and macOS — start from those and add `datasets/` and VM extensions.
</details>

<details>
<summary>Hint 3 — structure</summary>

Order of operations that avoids pain: create repo on GitHub → clone → `mkdir` the folders + `.gitkeep` → write `.gitignore` → write `network-design.md` → `git add -A` → commit → push. Do the SSH key *before* the first push or the push will ask for a password and fail.
</details>

---

## Break it

- Attach a throwaway test VM (or just reason it through on paper for now) to **bridged** mode and look at the IP it would get — confirm it's on your real subnet. Understand *viscerally* why that's forbidden for victim/attacker VMs. Delete the test VM.
- Delete your network-design file locally, run `git status`, and restore it with `git restore`. You just learned your safety net works.

---

## Evidence to commit

- `evidence/phase0/` — a screenshot of the Fusion `labnet` network settings (showing NAT off), and `git log --oneline` output.
- `writeups/phase0.md` — 5–10 sentences: what you set up, your network design choice (static vs DHCP) and why, and the one thing that was more fiddly than expected.

**Commit message:** `docs: phase 0 foundations complete`

---

## Interview questions this phase lets you answer

1. "How did you isolate your lab so malware testing couldn't escape?" → two networks, host-only for attack traffic, NAT disconnected during attacks, bridged banned.
2. "Walk me through your lab network." → your diagram + IP plan.
3. "Why version-control a lab?" → reproducibility + evidence of work + rollback.
4. "What's the difference between NAT and host-only networking?" → internet path vs no internet path; containment.

---

## Done? → [`phase-01-telemetry.md`](phase-01-telemetry.md)
