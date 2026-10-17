# Phase 4 — Python I: the log parser

> **This is where the Python track starts.** You told me your Python is at the fundamentals level (syntax, loops, functions). Everything new is introduced here from scratch, and only because the tool in front of you needs it. If any concept lands too fast, that's a signal to slow down and do the linked exercise — don't push through on faith.

**Objective:** A command-line tool, `logparser`, that reads raw security-log files, turns each event into a clean typed Python object, flags suspicious patterns with regex, and prints simple analytics (counts, filters). It's small, but it teaches the five idioms every later tool depends on.

**Why it matters in a SOC:** Analysts constantly deal with logs that aren't in a SIEM yet — an exported file, a colleague's dump, a forensic artefact. Being able to parse and triage a raw log file in Python, instead of scrolling it by eye, is a daily force-multiplier and a very common interview coding task ("here's a log file, find the suspicious events"). It also forces you to understand event structure at the field level, which makes you better at writing SIEM queries too.

---

## Concepts (each introduced from zero, in the order the tool needs them)

### 1. Reading a file without blowing up memory → **generators**

A security log can be hundreds of MB. If you do `lines = open(f).readlines()` you load the whole thing into RAM. Instead, Python lets you read **one line at a time, lazily**, with a **generator** — a function that `yield`s values one by one instead of building a list and `return`ing it.

Mental model: a `return` hands back the whole cake; a `yield` hands you one slice each time you ask, and remembers where it left off. You "ask" by looping over it.

```python
def read_lines(path):          # a generator function
    with open(path) as f:      # 'with' auto-closes the file (more on this in Phase 6)
        for line in f:         # files are already iterable line-by-line
            yield line.rstrip("\n")
```
Read: https://docs.python.org/3/tutorial/classes.html#generators and https://docs.python.org/3/howto/functional.html

### 2. Each line is JSON → **`dict`** and the `json` module

Your log lines are JSON objects (one per line = "JSON Lines" / JSONL — the format Elastic exports and the format the Phase 8 datasets use). `json.loads(line)` turns a JSON string into a Python **`dict`** (key→value map). You pull fields with `event["process"]["name"]`, but real logs have missing keys, so you'll use `.get()` which returns `None` instead of crashing.

### 3. A clean record type → **`dataclass`** + **type hints**

A raw `dict` is messy — any key might be missing, and nothing tells you what fields exist. A **dataclass** is a lightweight way to define a structured record with named, typed fields:

```python
from dataclasses import dataclass

@dataclass
class LogEvent:
    timestamp: str
    event_id: int
    process_name: str | None       # may be absent → Optional
    command_line: str | None
    # ...you decide the rest
```
**Type hints** (`: int`, `: str | None`) don't change how Python runs, but they document intent and let your editor catch mistakes. You'll lean on them more every phase. Read: https://docs.python.org/3/library/dataclasses.html and https://docs.python.org/3/library/typing.html

### 4. Flagging patterns → **regular expressions** (`re`)

To spot suspicious command lines you match patterns: a base64 blob, an IP address, an encoded-command flag. That's **regex**. The `re` module: `re.search(pattern, text)` returns a match (truthy) or `None`. **Compile patterns once** (`re.compile(...)`) and reuse them — it's faster and cleaner. Read: https://docs.python.org/3/howto/regex.html

### 5. Counting and filtering → **comprehensions** + **`collections.Counter`**

"How many of each event type?" is `Counter(e.event_id for e in events)`. "Just the PowerShell events" is `[e for e in events if e.process_name == "powershell.exe"]` (a **list comprehension**). These replace clunky manual loops and are everywhere in real Python.

### 6. A real command-line interface → **`argparse`**

A tool takes arguments: which file, which filter. `argparse` (standard library) parses `--event-id 1 --contains powershell` for you and generates `--help`. Read: https://docs.python.org/3/library/argparse.html

---

## Project setup (your first `uv` project)

In `tools/`, create the project with uv:
```bash
cd tools
uv init logparser
cd logparser
# uv creates pyproject.toml, a src layout, and a virtual env on first run
```
You'll run your tool with `uv run logparser ...` and add dependencies (none needed yet — Phase 4 is standard-library only) with `uv add <pkg>`.

---

## Build spec

Build `logparser` as a package under `tools/logparser/`. It must provide:

### 4.1 — `read_events(path) -> Iterator[LogEvent]`
A generator that reads a JSONL file, parses each line, and yields a `LogEvent`. Requirements:
- Lazy (generator, not a list).
- Skips blank lines and lines that aren't valid JSON **without crashing** — log a warning to stderr and continue. (Real logs have corrupt lines; a parser that dies on line 3 of 100,000 is useless.)
- Maps raw fields to the dataclass using `.get()` so missing keys become `None`, never a `KeyError`.

### 4.2 — `LogEvent` dataclass
At least: `timestamp`, `event_id: int`, `process_name`, `command_line`, `parent_name`, and a `raw: dict` field keeping the original (you'll want it later). Use type hints throughout.

### 4.3 — `flag(event) -> list[str]`
Returns a list of string tags for suspicious indicators found in the event, using compiled regexes. At minimum detect:
- an encoded-PowerShell flag in the command line → tag `"encoded_powershell"`
- a base64-looking blob (long run of base64 chars) → tag `"base64_blob"`
- an IPv4 address in the command line → tag `"ip_literal"`
- `lsass` appearing in the command line → tag `"lsass_reference"`
(You choose the regexes. Getting them *slightly wrong* and seeing false matches is part of the lesson — note it.)

### 4.4 — Analytics functions
- `count_by_event_id(events) -> Counter`
- `filter_events(events, event_id=None, contains=None) -> Iterator[LogEvent]` (filter by event id and/or a substring in the command line)

### 4.5 — CLI
`uv run logparser <file> [--event-id N] [--contains TEXT] [--flagged-only] [--stats]`
- default: print one line per event (timestamp, event_id, process, any flags)
- `--stats`: print the count-by-event-id table instead
- `--flagged-only`: show only events with at least one flag
- `--help` works (argparse gives this free)

### 4.6 — Get test input
Produce a small JSONL file from your own lab to run against. Easiest route: on WS01, `Get-WinEvent` for the Sysmon channel piped to `ConvertTo-Json`, or export a few hundred events from Kibana → Discover. Save a sample to `tools/logparser/sample.jsonl` (small; real exports are gitignored). Run some Atomic Red Team first so there's something suspicious to flag.

---

## Acceptance tests

Run these and confirm the behaviour:

1. `uv run logparser sample.jsonl --stats` prints a table of event-id → count that matches what you see in Kibana for the same data.
2. `uv run logparser sample.jsonl --event-id 1 --contains powershell` prints only PowerShell process-creation events.
3. `uv run logparser sample.jsonl --flagged-only` surfaces at least the encoded-PowerShell event you generated (if you ran atomic T1059.001).
4. Corrupt your sample: insert a line that says `not json` in the middle. The tool still processes every other line and prints a warning about the bad one — **it does not crash**.
5. Feed it an **empty file** and a **non-existent file**: empty → no output, clean exit; missing → a clear error message, non-zero exit (not a raw Python traceback).
6. `read_events` is a generator: `type(read_events("sample.jsonl"))` is a generator, and the tool works on a file far larger than you'd want in memory (test conceptually, or with a big export).
7. Every function has type hints, and `LogEvent` is a `@dataclass`.

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Build it in the order the data flows: get `read_events` yielding raw dicts first and just `print` them. Then wrap each dict in a `LogEvent`. Then add `flag`. Then analytics. Then the CLI last. Don't write the CLI first — you can't test it until the core works.

For the "don't crash on bad JSON" requirement: `json.loads` raises `json.JSONDecodeError`. You want `try/except` around just that line's parse.
</details>

<details>
<summary>Hint 2 — approach</summary>

Shape of the core (signatures only — you write the bodies):
```python
from collections.abc import Iterator
from collections import Counter

def read_events(path: str) -> Iterator[LogEvent]:
    ...   # generator: open, loop, try json.loads, map to LogEvent, yield

def flag(event: LogEvent) -> list[str]:
    ...   # run compiled regexes against event.command_line, collect tags

def count_by_event_id(events: Iterator[LogEvent]) -> Counter:
    ...   # Counter over e.event_id
```
ECS field names differ from raw Sysmon names depending on how you exported. Open one line of your sample and *read* the actual keys before writing the field mapping — don't assume. (If you exported via `Get-WinEvent | ConvertTo-Json` the shape differs from a Kibana ECS export; pick one source and map to it.)

For regex: `re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE)` is the idea for the encoded-PowerShell flag. Compile your patterns once at module level, not inside the loop.
</details>

<details>
<summary>Hint 3 — structure</summary>

Module layout:
```
tools/logparser/
├── pyproject.toml            (uv made this)
├── sample.jsonl
└── src/logparser/
    ├── __init__.py
    ├── model.py     # LogEvent dataclass
    ├── parse.py     # read_events (generator), field mapping
    ├── detect.py    # compiled regexes + flag()
    ├── analytics.py # count_by_event_id, filter_events
    └── cli.py       # argparse, wires it together, handles file errors
```
CLI pseudocode:
```
parse args (file, event_id, contains, flagged_only, stats)
if file missing: print error to stderr, sys.exit(1)
events = read_events(file)
if stats: print count_by_event_id(events) as a table; return
events = filter_events(events, event_id, contains)
for e in events:
    flags = flag(e)
    if flagged_only and not flags: continue
    print(f"{e.timestamp}  {e.event_id}  {e.process_name}  {flags}")
```
Remember a generator is single-use — if you need the events twice (stats *and* listing), re-create it or materialise a list deliberately.
</details>

---

## Break it

- **The generator gotcha:** try to loop over the same `read_events(...)` result twice. The second loop is empty — generators exhaust. Understand *why* (it's not a list). This bites every beginner once; better here than at 2am in a job.
- **Regex false positives:** your `base64_blob` pattern will probably flag legitimate long tokens (hashes, GUIDs). Find one in your real data, then decide: tighten the pattern, or accept and document the FP? That trade-off is identical to SIEM detection tuning — same skill, different tool.

---

## Evidence to commit

- `tools/logparser/` — the working package, committed (with `sample.jsonl`, small).
- `writeups/phase4.md` — what each of the five idioms (generators, dataclasses, type hints, regex, argparse) is *for*, in your own words; the generator-exhaustion gotcha; and one regex FP you found and how you handled it.

**Commit message:** `feat(tools): logparser — generator-based security log parser`

**CV line you've now earned (draft):** *"Wrote a Python CLI that parses and triages raw security logs using generators for memory-efficient streaming, dataclasses, and regex-based indicator flagging."*

---

## Interview questions this phase lets you answer

1. "Why use a generator to read a big log file?" → lazy, constant memory, streams one record at a time.
2. "What's a dataclass and why not just use a dict?" → typed, named fields; self-documenting; fewer `KeyError`s.
3. "How would you find suspicious commands in a raw log with Python?" → stream, parse, regex-flag, filter — your actual tool.
4. "What do type hints give you if Python ignores them at runtime?" → tooling catches bugs, documentation, editor help.
5. "Your parser hits a corrupt line — what happens?" → caught, warned, skipped; the run completes. (Robustness is a real interview concern.)

---

## Done? → Phase 5 (Python II — enrichment CLI: decorators, HTTP, pytest). *Next installment.*
