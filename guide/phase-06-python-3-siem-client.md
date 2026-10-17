# Phase 6 — Python III: SIEM API client + hunt runner

> Closes the core Python track. New this phase: **context managers** (`with`), **generator-based pagination**, **pydantic** models, and loading **YAML**. You'll query your *own* Elastic SIEM from Python and build a reusable threat-hunting engine. Builds on `logparser` and `iocenrich`.

**Objective:** `siemhunt` — a Python client that connects to your Elastic SIEM, runs queries, **paginates through large result sets** without loading everything into memory, parses responses into validated **pydantic** models, and runs a library of **threat hunts defined in YAML** (each hunt = a named query + ATT&CK mapping), producing a report of hits per hunt.

**Why it matters in a SOC:** Analysts and detection engineers automate against the SIEM's API constantly — scheduled hunts, bulk IOC sweeps, pulling alerts into other tools. "I wrote a Python client for our SIEM and a hunt runner" is a senior-sounding thing for a junior to have done. Threat hunting (proactively querying for attacker behaviour rather than waiting for alerts) is an explicit 2026 SOC expectation, and a YAML-driven hunt library is how mature teams keep hunts version-controlled and repeatable — which is also detection-as-code's foundation (Phase 9).

---

## Concepts (from zero, in build order)

### 1. **Context managers** — `with`, and writing your own

You've used `with open(...) as f:` — that's a context manager. It guarantees setup and **cleanup** happen even if an error occurs midway. For an HTTP client or a SIEM connection you want the same guarantee: open the connection, use it, **always close it**.

Two ways to write one:
```python
# A) class with __enter__ / __exit__
class SiemClient:
    def __enter__(self):
        self._client = httpx.Client(...)   # setup
        return self
    def __exit__(self, exc_type, exc, tb):
        self._client.close()               # cleanup — runs even on exception

# B) the @contextmanager decorator (simpler for small cases)
from contextlib import contextmanager
@contextmanager
def siem_session(...):
    client = httpx.Client(...)
    try:
        yield client          # 'with' binds this to 'as'
    finally:
        client.close()        # always runs
```
Used as: `with SiemClient(...) as siem:` — when the block ends, cleanup fires automatically. Read: https://docs.python.org/3/reference/datamodel.html#context-managers and https://docs.python.org/3/library/contextlib.html

### 2. **Pagination** with generators — reading more than one page

Elastic returns a *page* of results, not everything (a plain search caps at 10,000 hits). To walk a large result set you ask for pages repeatedly using a cursor, and the clean way to expose that is a **generator that yields records across pages** — the caller just loops, unaware of page boundaries.

The current Elastic pattern for deep pagination: open a **Point-In-Time (PIT)**, then `search` with a **`sort`** and **`search_after`** (the sort values of the last hit become the cursor for the next page), until a page comes back empty; then close the PIT. Your generator hides all of that:
```python
def search_all(client, index, query) -> Iterator[dict]:
    # open PIT, loop: search with search_after cursor, yield each hit,
    # advance cursor, stop when a page is empty, then close PIT (finally)
    ...
```
This fuses Phase 4's generators with a real API. Read: https://www.elastic.co/guide/en/elasticsearch/reference/current/paginate-search-results.html

> ES|QL is an alternative (piped queries, simpler for analytics). You may implement hunts in either DSL+search_after or ES|QL; do at least one hunt each way and note the trade-off in your write-up.

### 3. **pydantic** — validated, typed models for messy API JSON

A dataclass (Phase 4) holds typed fields but doesn't *validate* input. API responses are untrusted and messy. **pydantic** models parse and validate JSON into typed Python objects, raising a clear error when the data doesn't match — so bad data fails loudly at the boundary instead of silently corrupting your logic later.
```python
from pydantic import BaseModel
class Hit(BaseModel):
    timestamp: str
    event_code: str | None = None
    process_name: str | None = None
    host: str
# Hit.model_validate(raw_dict)  -> a validated Hit, or a ValidationError
```
This is the professional upgrade from "reach into a dict and hope." Install `uv add pydantic`. Read: https://docs.pydantic.dev/

### 4. **YAML** hunt definitions

Hunts live as data, not code, so they're reviewable and version-controlled. Each hunt is a small YAML file:
```yaml
# hunts/T1059.001_encoded_powershell.yml
id: T1059.001-encoded-ps
name: Encoded PowerShell execution
attack: T1059.001
index: logs-*
description: PowerShell launched with an encoded command.
query_type: esql          # or dsl
query: >
  FROM logs-* | WHERE process.name == "powershell.exe"
  AND process.command_line LIKE "*-enc*"
```
Load with `uv add pyyaml` → `yaml.safe_load`. **Always `safe_load`, never `load`** (plain `load` can execute arbitrary objects — a real security footgun). Read: https://pyyaml.org/wiki/PyYAMLDocumentation

---

## Build spec

Build `siemhunt` under `tools/siemhunt/`.

### 6.1 — `SiemClient` (context manager)
A class that:
- takes base URL, auth (from env/.env — reuse Phase 5's secret handling), and the CA cert path for TLS verification,
- opens an `httpx.Client` in `__enter__`, closes it in `__exit__`,
- exposes `search(index, body) -> dict` and `esql(query) -> dict`,
- sets a timeout and **verifies TLS against your lab CA** (don't disable verification — learn to point httpx at the CA file). Raises clear errors on `401` (bad creds) / connection failure.

### 6.2 — `search_all(...) -> Iterator[Hit]`
A generator that paginates a DSL query via PIT + `search_after`, yielding validated `Hit` models across all pages, and **always closes the PIT** (use `try/finally` — this is exactly what context managers are for; you may wrap the PIT itself as one).

### 6.3 — pydantic models
`Hit` (normalised fields you care about) and `HuntResult` (`hunt_id`, `name`, `attack`, `count`, `sample_hits: list[Hit]`). Validation must reject a malformed hit with a clear error.

### 6.4 — Hunt loader + runner
- `load_hunts(dir) -> list[Hunt]` — read every `*.yml`, `safe_load`, validate each into a `Hunt` pydantic model (bad hunt file → clear error naming the file).
- `run_hunt(client, hunt) -> HuntResult` — execute the hunt's query (esql or dsl), count hits, keep a few samples.
- `run_all(client, hunts) -> list[HuntResult]`.

### 6.5 — Author ≥5 hunts (YAML)
Write at least five hunt files mapped to ATT&CK, reusing logic from your Phase 3 detections but as *hunts* (broader, exploratory) rather than *alerts*. E.g. encoded PowerShell, LSASS access, new service installs, rare parent-child pairs, outbound to rare destinations. These go in `tools/siemhunt/hunts/` and are **portfolio artefacts** in their own right.

### 6.6 — CLI + report
`uv run siemhunt [--hunt ID] [--all] [--json] [--min-hits N]`
- `--all` runs every hunt and prints a report table: hunt | ATT&CK | hits.
- `--hunt ID` runs one and shows sample hits.
- `--json` for machine-readable output (so Phase 10's SOAR can consume it).
- `--min-hits N` only reports hunts with ≥N hits (triage focus).

### 6.7 — Tests
- `test_search_after_paginates` — with a **mocked** client returning two pages then empty, `search_all` yields all records from both pages and stops (assert the mock was asked for the right number of pages).
- `test_hit_validation_rejects_bad` — a malformed hit raises `ValidationError`.
- `test_load_hunts` — loads sample YAML into `Hunt` models; a broken YAML file errors clearly.
All offline (mock the SIEM), `uv run pytest` green.

---

## Acceptance tests

1. `with SiemClient(...) as siem:` connects to your **real** Elastic over TLS (verified against your CA), runs a search, and the client is closed afterward (prove: a second use outside the `with` fails because it's closed).
2. `uv run siemhunt --hunt <id>` returns a hit count that **matches the same query run in Kibana** (correctness check against ground truth).
3. A hunt whose result set exceeds one page returns **all** hits via `search_all` (test against an index with >100 matching events; confirm the count matches Kibana's).
4. `uv run siemhunt --all` prints a report of all ≥5 hunts with ATT&CK IDs and hit counts.
5. Feed `load_hunts` a deliberately broken YAML file → clear error naming the file, not a raw traceback.
6. `uv run pytest` green and offline (no real SIEM in tests).
7. TLS is **verified** (your code points httpx at the CA; verification is not disabled). Grep to confirm there's no `verify=False`.

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Get a single search working inside a `with SiemClient(...)` first — just print the raw JSON. Prove TLS + auth against your lab before adding pagination, pydantic, or YAML. Each layer on a proven one.

For TLS: httpx accepts `verify="/path/to/ca.crt"`. You exported/have that CA from Phase 2. Pointing at it (rather than `verify=False`) is the lesson — real clients verify.
</details>

<details>
<summary>Hint 2 — approach</summary>

`search_after` pagination shape (you write it):
```
open PIT (gets a pit id)
cursor = None
try:
    while True:
        body = {query, sort: [...stable sort...], pit: {id, keep_alive}, size: 500}
        if cursor: body["search_after"] = cursor
        resp = client.search(body)
        hits = resp hits
        if not hits: break
        for h in hits: yield Hit.model_validate(normalise(h))
        cursor = sort values of the LAST hit
finally:
    close PIT
```
The sort must be *stable and total* (e.g. a timestamp plus a tiebreaker like `_shard_doc`) or you'll skip/duplicate records — a classic pagination bug worth understanding.

For the context manager, the class form (`__enter__/__exit__`) is the better fit here because the client has state and multiple methods; `@contextmanager` is nicer for the PIT (open→yield→close).
</details>

<details>
<summary>Hint 3 — structure</summary>

```
tools/siemhunt/
├── pyproject.toml
├── hunts/                     # ≥5 YAML hunts (portfolio!)
│   └── *.yml
└── src/siemhunt/
    ├── client.py     # SiemClient (ctx mgr), search(), esql()
    ├── pagination.py # search_all generator + PIT ctx mgr
    ├── models.py     # pydantic Hit, Hunt, HuntResult
    ├── hunts.py      # load_hunts (safe_load + validate), run_hunt, run_all
    ├── report.py     # format the results table / json
    └── cli.py
tests/ ...
```
Work order: client (prove real connection) → models → pagination (mock it) → hunt loader → runner → CLI/report → author the 5 hunts → tests. Commit per green piece.
</details>

---

## Break it

- **Pagination correctness:** change your sort to something non-unique (e.g. just a coarse timestamp with ties) on an index with duplicate timestamps, and compare the total count to Kibana. You'll see records skipped or doubled. Fix it with a tiebreaker. This is the bug that silently corrupts real hunt results — meeting it in the lab is cheap.
- **Disable TLS verification** (`verify=False`) and notice it "works" — then understand you just turned off the protection that stops a man-in-the-middle reading your SIEM traffic. Re-enable it. Know *why* `verify=False` in real code is a finding.
- **`yaml.load` vs `safe_load`:** read (don't run blindly) why `yaml.load` on untrusted input is a remote-code-execution risk. Confirm your loader uses `safe_load`.

---

## Evidence to commit

- `tools/siemhunt/` with passing tests and ≥5 YAML hunts.
- `writeups/phase6.md` — context managers in your words (why cleanup-on-error matters), the `search_after` tiebreaker bug you reproduced and fixed, why `verify=False` and `yaml.load` are dangerous, and dataclass-vs-pydantic (when you'd reach for each).

**Commit message:** `feat(tools): siemhunt — elastic client + yaml-driven hunt runner`

**CV line you've now earned (draft):** *"Built a Python client for Elasticsearch with TLS verification, generator-based deep pagination (PIT + search_after), and pydantic response validation, plus a YAML-driven threat-hunting engine mapped to MITRE ATT&CK."*

---

## Interview questions this phase lets you answer

1. "What's a context manager and why use one for a network client?" → guaranteed cleanup (close) even on error; `with`.
2. "How do you page through more results than the API returns at once?" → cursor pagination (search_after/PIT), exposed as a generator; needs a stable total sort.
3. "dataclass vs pydantic?" → dataclass = typed container; pydantic = parsing + validation at trust boundaries.
4. "What is threat hunting and how does it differ from alerting?" → proactive querying for behaviour vs waiting for a rule to fire; yours are YAML-defined, ATT&CK-mapped, version-controlled.
5. "Why not `verify=False` / `yaml.load`?" → MITM exposure / arbitrary code execution — concrete security footguns.

---

## Done? → Phase 7 (Network visibility — Suricata + Zeek, attacks from Kali). *Next installment. The core Python track is now complete; later phases compose these tools.*
