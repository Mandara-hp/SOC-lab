# Phase 5 — Python II: the enrichment CLI

> Builds directly on `logparser`. New Python this phase: **decorators** (the big one), **HTTP** with `httpx`, **secrets/env vars**, **custom exceptions**, and your **first pytest suite with mocking**. Each is introduced from scratch, in the order the tool needs it.

**Objective:** A tool, `iocenrich`, that takes indicators of compromise (IPs, file hashes, domains) — pulled from your logs or a file — and enriches them against free threat-intelligence APIs, returning a verdict per IOC. Along the way you build the three decorators every API client needs (retry, cache, rate-limit), handle API keys safely, and write tests that never touch the real internet.

**Why it matters in a SOC:** Enrichment is half of triage. An alert says "connection to 185.x.x.x" — is that IP known-bad? An analyst checks threat intel. Automating that lookup, with caching and rate-limiting so you don't hammer (or get banned from) free APIs, is a genuinely useful SOC automation and a very common "build me a small tool" interview task. It also teaches the professional handling of secrets, which juniors routinely get wrong (hardcoded keys in GitHub are a classic, embarrassing, real-world breach).

---

## Concepts (from zero, in build order)

### 1. Functions are objects → the thing that makes decorators possible

In Python a function is a value you can pass around, store in a variable, and return from another function. This is the prerequisite for decorators, so get it straight first:
```python
def shout(text): return text.upper()
f = shout            # no parentheses: f now IS the function
f("hi")              # "HI"
```
A function can take another function as an argument and return a new function that wraps it. That wrapping is what a decorator does.

### 2. **Decorators** — wrapping behaviour around a function

A decorator adds behaviour *around* a function without changing the function's own code. You've seen the `@something` syntax; here's what it means:
```python
@retry                 # this line...
def query(ioc): ...

# ...is exactly the same as:
def query(ioc): ...
query = retry(query)   # retry takes the function and returns a wrapped version
```
`retry` is a function that receives `query`, and returns a *new* function that calls `query` but adds "try again on failure" logic. The new function usually looks like:
```python
import functools
def retry(func):
    @functools.wraps(func)          # preserves func's name/docstring
    def wrapper(*args, **kwargs):
        # ...attempt logic around func(*args, **kwargs)...
        return func(*args, **kwargs)
    return wrapper
```
`*args, **kwargs` means "accept whatever arguments the wrapped function takes and pass them through." You will write three of these:
- **`@retry`** — on a transient network error, wait and try again (a few times, with a growing delay = backoff).
- **`@cache`** — remember results so the same IOC isn't queried twice (free-tier APIs are rate-limited; caching saves your quota).
- **`@rate_limit`** — ensure no more than N calls happen per time window, so you respect the API's limit and don't get blocked.

Read: https://docs.python.org/3/glossary.html#term-decorator and https://realpython.com/primer-on-python-decorators/ (clear primer). For caching, also meet `functools.lru_cache` (built-in memoisation) and understand when a hand-written cache is needed instead.

### 3. Talking to APIs → **`httpx`**

`httpx` is a modern HTTP client (think `requests`, but also supports async for Phase 8+). You'll:
- create a `Client` (reusable connection), set a **timeout** (never make a network call with no timeout — it can hang forever),
- `GET`/`POST` with headers (your API key goes in a header),
- check `response.status_code` and use `response.raise_for_status()`, and read `response.json()`.
Status codes you must handle: `200` ok, `401/403` bad key, `404` not found, `429` **rate-limited**, `5xx` server error. Install: `uv add httpx`. Read: https://www.python-httpx.org/

### 4. **Secrets** — API keys the right way

Your API keys are secrets. Rules:
- **Never** hardcode a key in a `.py` file. **Never** commit one.
- Load keys from **environment variables** (`os.environ["VT_API_KEY"]`) or a local **`.env`** file (already gitignored from Phase 0) loaded with `python-dotenv` (`uv add python-dotenv`).
- If a key is missing, fail with a clear message, not a confusing `KeyError`.
Read: https://12factor.net/config (the principle) and dotenv docs.

### 5. **Custom exceptions** — meaningful failures

Instead of letting a raw `httpx` error bubble up, define your own exceptions so callers can handle them cleanly:
```python
class EnrichmentError(Exception): ...
class RateLimited(EnrichmentError): ...
class InvalidKey(EnrichmentError): ...
```
Raising `RateLimited` on a `429` lets your `@retry`/`@rate_limit` logic react specifically. Read: https://docs.python.org/3/tutorial/errors.html

### 6. **pytest** + **mocking** — tests that don't hit the real internet

Your tests must be fast and offline. You do **not** call the real VirusTotal in a test — you **mock** the HTTP layer so it returns a canned response. Tools:
- `pytest` — the standard test runner. A test is just a function named `test_*` with `assert` statements. Run with `uv run pytest`.
- Mock HTTP with **`respx`** (purpose-built for `httpx`) or `monkeypatch`. You assert your code does the right thing given a fake `200`, a fake `429`, a fake malformed body — *without* a network.
Install: `uv add --dev pytest respx`. Read: https://docs.pytest.org/ and https://lundberg.github.io/respx/

---

## Build spec

Build `iocenrich` under `tools/iocenrich/`. (New uv project, or a second package in the same repo — your call; document it.)

### 5.1 — IOC extraction
`extract_iocs(events) -> set[IOC]` — pull IOCs from `LogEvent`s (reuse your Phase 4 `logparser`) or from a plain text file. Classify each as `ip` / `domain` / `sha256` (regex again). Use a `set` to dedupe. Model an `IOC` as a dataclass with `value` and `type`.

### 5.2 — The three decorators
Write them yourself in a `decorators.py`:
- `@retry(times=3, backoff=1.0)` — retries on `EnrichmentError`/network errors, waiting `backoff * attempt` seconds, giving up after `times`. (A decorator that takes arguments is a decorator *factory* — a function returning a decorator. Hint ladder covers the shape.)
- `@cache` — memoises by the function's arguments so repeat IOCs return instantly. Decide: `functools.lru_cache` or your own dict-based cache? Justify in your write-up (hint: lru_cache has limits with unhashable args and you can't inspect it easily).
- `@rate_limit(calls=4, period=60)` — blocks so no more than `calls` happen per `period` seconds (VirusTotal's free tier is ~4/min — this is exactly why it exists).

### 5.3 — Provider clients
Implement **at least one** enrichment provider, ideally two, using free tiers:
- **abuse.ch ThreatFox / URLhaus** — free, some endpoints need no key (good first provider).
- **AbuseIPDB** — free tier, key required, IP reputation.
- **VirusTotal** — free key, ~4 req/min (your rate-limiter's reason to exist).

Each provider is a function/class `enrich_ip` / `enrich_hash` / `enrich_domain` that:
- reads its key from env (fails clearly if absent),
- calls the API via a shared `httpx.Client` with a timeout,
- is wrapped with `@rate_limit`, `@retry`, `@cache`,
- maps the raw response to a normalised `Verdict` dataclass (`ioc`, `source`, `malicious: bool | None`, `score`, `detail`),
- raises your custom exceptions on `401`/`429`/bad body.

### 5.4 — CLI
`uv run iocenrich <input> [--provider vt|abuseipdb|threatfox] [--json] [--only-malicious]`
- input = a logparser-readable file or a plain IOC list
- prints a verdict table, or JSON with `--json`
- `--only-malicious` filters to flagged IOCs
- missing API key → clear message + non-zero exit, not a traceback

### 5.5 — Tests (`tests/`)
At minimum:
- `test_extract_iocs` — given sample events, returns the expected deduped IOC set with correct types.
- `test_retry_retries` — a function that fails twice then succeeds is called 3 times and returns the value (use a counter/mock).
- `test_cache_hits` — the second identical call does **not** invoke the underlying function (assert call count).
- `test_provider_parses_200` — with a **mocked** `200` body, returns the right `Verdict`.
- `test_provider_raises_on_429` — with a mocked `429`, raises `RateLimited`.
All tests run **offline** and pass with `uv run pytest`.

---

## Acceptance tests

1. `uv run pytest` → all tests green, and it completes in well under a second (proof there's no real network in tests).
2. `uv run iocenrich sample.jsonl --provider threatfox` returns verdicts for the IOCs in your sample.
3. Unset the relevant API-key env var and run → a clear "missing API key: set X" message and non-zero exit (no traceback).
4. Run the same IOC twice in one invocation → the second is served from cache (prove it: add a debug log or a counter; it should not make a second HTTP call).
5. With a provider that limits to 4/min, enriching 10 IOCs visibly **paces** itself rather than firing all 10 instantly (watch the timing).
6. `git status` / `git grep` confirms **no API key anywhere in the repo** and `.env` is untracked.
7. Every provider call has a timeout set (grep your code to confirm).

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Build and test the decorators against *fake* functions first, before wiring them to real APIs. A decorator doesn't care what it wraps — test `@retry` on a function that raises twice then returns `"ok"`, using a simple counter. Get the three decorators solid in isolation; then enrichment is just "call httpx, map the JSON."

Start with the no-key provider (ThreatFox/URLhaus) so you're not blocked on signing up for keys while learning the mechanics.
</details>

<details>
<summary>Hint 2 — approach</summary>

A decorator *with arguments* is a function returning a decorator (three nested layers):
```python
def retry(times=3, backoff=1.0):          # factory: takes config
    def decorator(func):                  # takes the function
        @functools.wraps(func)
        def wrapper(*args, **kwargs):     # the replacement function
            # loop up to `times`, sleep backoff*attempt on failure, re-raise if exhausted
            ...
        return wrapper
    return decorator
```
For `@rate_limit`: track the timestamps of recent calls (a `deque`), and before each call, if you've hit the limit in the window, `time.sleep` until the oldest call ages out.

For mocking httpx with respx: you declare "when the code GETs this URL, respond with this JSON and status," then call your function and assert on the `Verdict`. No real request leaves your machine.
</details>

<details>
<summary>Hint 3 — structure</summary>

```
tools/iocenrich/
├── pyproject.toml
├── .env.example           # documents WHICH keys are needed (no real values) — committed
└── src/iocenrich/
    ├── model.py           # IOC, Verdict dataclasses + custom exceptions
    ├── decorators.py      # retry, cache, rate_limit
    ├── extract.py         # extract_iocs (reuses logparser)
    ├── providers/
    │   ├── threatfox.py
    │   ├── abuseipdb.py
    │   └── virustotal.py
    ├── config.py          # load keys from env/.env, fail clearly if missing
    └── cli.py
tests/
    ├── test_extract.py
    ├── test_decorators.py
    └── test_providers.py  # respx-mocked
```
Order of work: model+exceptions → decorators (+their tests) → config/secrets → one provider (+mocked test) → extract (+test) → CLI → second provider. Commit after each green test file. Ship `.env.example` so a reader knows what keys to supply without ever seeing yours.
</details>

---

## Break it

- **Feel the secret-leak danger (safely):** temporarily hardcode a *fake* key string in a `.py`, commit it locally, then run `git grep FAKE_KEY`. See how trivially a committed secret is found. Remove it, and understand why `git` history means a leaked key is leaked *forever* (you'd have to rotate the key, not just delete the line). This is why real breaches happen. Then delete that commit.
- **Kill the network** (disconnect NAT on SIEM01 or run offline) and watch `@retry` exhaust and your custom exception surface cleanly instead of an ugly traceback. Good error handling is a visible maturity signal.
- **Blow the rate limit** by removing `@rate_limit` and spamming a real free API — watch the `429`s. Re-add it. You just learned *why* the decorator exists, empirically.

---

## Evidence to commit

- `tools/iocenrich/` with passing tests and `.env.example` (never the real `.env`).
- `writeups/phase5.md` — explain decorators in your own words (include the "it's just `f = deco(f)`" insight), your cache choice (`lru_cache` vs custom) and why, how you kept secrets out of git, and the empirical rate-limit lesson.

**Commit message:** `feat(tools): iocenrich — threat-intel enrichment with retry/cache/ratelimit`

**CV line you've now earned (draft):** *"Built a Python threat-intel enrichment CLI integrating multiple free TI APIs, with custom retry/cache/rate-limit decorators, environment-based secret management, and a mocked pytest suite (no live network in tests)."*

---

## Interview questions this phase lets you answer

1. "What's a decorator? Give a real use." → wraps behaviour around a function; retry/cache/rate-limit on API calls.
2. "How do you handle secrets in code?" → env vars/.env, never hardcode, never commit, rotate if leaked; `.env.example` to document.
3. "Why rate-limit and cache API calls?" → respect provider limits, avoid bans, save quota, faster repeat lookups.
4. "How do you test code that calls an external API?" → mock the HTTP layer (respx/monkeypatch); tests stay fast and offline.
5. "A committed API key — how bad is it and what do you do?" → it's in history forever; rotate the key immediately, then purge/accept.
6. "How would you enrich an alert's IOCs?" → extract → classify → query TI (cached, rate-limited) → normalise verdicts — your tool.

---

## Done? → Phase 6 (Python III — SIEM API client + hunt runner: context managers, pagination, pydantic). *Next installment.*
