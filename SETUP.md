# SETUP — turn this folder into your repo (do this first)

This folder is the starter. Make it *yours* and get it onto GitHub before Phase 0's lab work.

## 1. Put it where you keep code, and open it
```bash
# move/unzip it somewhere sensible, then:
cd ~/soc-lab          # wherever you put it
code .                # open in VS Code (Phase 0 installs 'code')
```

## 2. Install the toolchain (Phase 0 §0.1 — the real detail is there)
```bash
# Homebrew first (see https://brew.sh), then:
brew install git uv
brew install --cask visual-studio-code vmware-fusion
git config --global user.name  "Mandara Hassan Puttaswamy"
git config --global user.email "hpmandara756@gmail.com"
```

## 3. Make it a git repo and commit
```bash
cd ~/soc-lab
git init
git add -A
git commit -m "chore: initial repo skeleton"
```

## 4. Create a PRIVATE GitHub repo named soc-lab, then push
```bash
# after creating the empty private repo on github.com (no README):
git remote add origin git@github.com:<your-username>/soc-lab.git
git branch -M main
git push -u origin main
```
> Set up your SSH key first (Phase 0 §0.1 step 4) or the push will fail.
> Keep the repo **private** until Phase 12 — you don't want half-finished work judged.

## 5. Start the programme
Open `guide/00-overview.md`, read it once, then do `guide/phase-00-foundations.md`.

---

**Where you are:** the guide covers Phases 0–6 (foundations → telemetry → SIEM → detections → the three Python tools). Phases 7–12 (network visibility, the async dataset replayer, detection-as-code + CI, mini-SOAR, the Microsoft/KQL/Sentinel track, portfolio) get added to `guide/` as you reach them — ask for the next one when you're ready.
