# Phase 2 — SIEM build (Elastic)

**Objective:** A working Elastic SIEM on an Ubuntu ARM VM — Elasticsearch + Kibana + Fleet — with TLS, your Windows endpoint enrolled via Elastic Agent, and its logs normalised into the Elastic Common Schema. This is the **first thing you can legitimately put on your CV**.

**Why it matters in a SOC:** The SIEM is the analyst's primary workplace. You'll spend a career inside one. Standing one up end-to-end — certificates, log ingestion, an enrolled agent, a working search — proves you understand the pipeline most people only consume. "Log source → collection → parsing → normalisation → detection → alert" is a flow interviewers explicitly probe; after this phase you've *built* every arrow.

**Front-loaded on purpose:** you're applying for jobs now, so we get a demonstrable SIEM standing before the deeper Python and detection work. After Phase 3 you'll have "built a SIEM and wrote detections that fire on real attacks" — a complete, interview-ready story in two phases.

---

## Concepts (read these first)

### The Elastic pieces, and why Elastic (not Splunk)

Splunk is more common in UK job ads, but it has **no ARM build** and its container crashes under emulation on Apple Silicon — so it cannot be your *local* SIEM. You get Splunk's query-language exposure indirectly, and you fully cover the UK's #1 ask (Microsoft Sentinel/KQL) in Phase 11. Locally, Elastic is the right ARM-native choice, and its detection-rules ecosystem is itself open-source Python, which feeds your Python track.

- **Elasticsearch** — the search/storage engine. Stores events as JSON documents in *indices*.
- **Kibana** — the web UI. "Elastic Security" is the SIEM app *inside* Kibana (alerts, detection rules, timelines, cases).
- **Fleet** — the management plane for agents. **Fleet Server** is a component you run; it lets you enrol and configure **Elastic Agents** centrally.
- **Elastic Agent** — the single agent you install on endpoints (WS01). It ships logs and can run **Elastic Defend** (endpoint/EDR features). The Windows **ARM64** agent, including Defend, exists in **technical preview** — note that word in your write-up; it means "works, but don't expect enterprise-grade polish."
- **Elastic Common Schema (ECS)** — a standard set of field names. Instead of every source naming things differently, ECS normalises to `event.code`, `process.command_line`, `process.parent.name`, `source.ip`, `destination.port`, etc. **This is the quiet superpower of the phase:** once logs are ECS, one query works across sources. Interviewers love "I normalised to a common schema so detections are source-agnostic."

### Query languages you'll meet in Elastic (keep them straight)

- **KQL (Kibana Query Language)** — simple filtering in the search bar. **NOT** Microsoft's Kusto. Easy, limited.
- **EQL (Event Query Language)** — built for **sequences and parent-child relationships** ("process A spawned B which made a network connection"). This is where endpoint detection gets powerful.
- **ES|QL** — Elastic's newer piped query language (like `... | where ... | stats ...`). Increasingly the modern default.

You'll use all three over the next phases. KQL for quick triage, EQL for behavioural detections, ES|QL for analytics.

> **Primary sources:**
> Elastic Docker setup: https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html
> Fleet & Elastic Agent: https://www.elastic.co/guide/en/fleet/current/index.html
> ECS reference: https://www.elastic.co/guide/en/ecs/current/index.html
> EQL: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html

---

## Build spec

### 2.1 — Build the Ubuntu ARM SIEM VM (SIEM01)

1. Download **Ubuntu Server 24.04 LTS for ARM64** (`ubuntu.com/download/server/arm`).
2. Fusion VM: **6 GB RAM**, 2 CPUs, 40 GB thin disk, guest "Ubuntu 64-bit Arm".
3. Network: **`labnet`** (static IP, e.g. `10.10.10.10`) + NAT attached (the SIEM genuinely needs to pull Docker images and updates; you can leave NAT on for SIEM01 since it's not a victim — but document that choice).
4. Install **Docker Engine + the Compose plugin** (from Docker's official apt repo, not the old `docker.io` package).
5. Set the kernel setting Elasticsearch needs: `vm.max_map_count=262144` (and make it persist across reboots via `/etc/sysctl.d/`). Elasticsearch refuses to start without it.
6. Snapshot `clean-baseline`, then delete the Ubuntu ISO.

### 2.2 — Stand up Elasticsearch + Kibana with TLS (annotated skeleton — fill the gaps)

This is the **infra exception**: you get a skeleton with gaps marked `# >>> FILL:`. You will understand every line because the comments explain it and the acceptance tests force it. Put this in `infra/elastic/docker-compose.yml` and an `infra/elastic/.env`.

`.env` (never commit — it's gitignored):
```dotenv
# Pin ONE stack version. Check the current release and set it here.
STACK_VERSION=      # >>> FILL: e.g. 8.x.y — use the current GA release
# Strong passwords you choose:
ELASTIC_PASSWORD=   # >>> FILL
KIBANA_PASSWORD=    # >>> FILL
CLUSTER_NAME=soc-lab
LICENSE=basic
# Memory limit per ES node. On 6 GB RAM, keep ES heap modest:
ES_MEM_LIMIT=2147483648      # 2 GB
KIBANA_MEM_LIMIT=1073741824  # 1 GB
ENCRYPTION_KEY=     # >>> FILL: 32+ random chars (Kibana needs this for saved objects/alerts)
```

`docker-compose.yml` skeleton (the shape; you complete the marked parts):
```yaml
services:
  # --- one-shot container that generates the TLS certificate authority + certs ---
  setup:
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    # >>> FILL: a command/script that creates a CA and node certs into a shared volume,
    #           then waits until ES is reachable and sets the kibana_system password.
    #   (Elastic's official docker-compose example in the docs above does exactly this —
    #    read it, understand the certutil steps, then reproduce them here. Do NOT paste blindly;
    #    you must be able to explain what the CA is and why Kibana needs to trust it.)
    volumes:
      - certs:/usr/share/elasticsearch/config/certs

  es01:
    depends_on: { setup: { condition: service_healthy } }
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    environment:
      - node.name=es01
      - cluster.name=${CLUSTER_NAME}
      - discovery.type=single-node          # single node for a lab
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true # >>> FILL in the cert paths below
      # >>> FILL: ssl key/cert/ca file paths pointing into /certs
    mem_limit: ${ES_MEM_LIMIT}
    ulimits: { memlock: { soft: -1, hard: -1 } }
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata:/usr/share/elasticsearch/data
    ports: [ "9200:9200" ]
    healthcheck:
      # >>> FILL: a curl against https://localhost:9200 using the CA + elastic password
      test: [ "CMD-SHELL", "..." ]

  kibana:
    depends_on: { es01: { condition: service_healthy } }
    image: docker.elastic.co/kibana/kibana:${STACK_VERSION}
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://es01:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      # >>> FILL: CA path so Kibana trusts ES's cert; and the encryption keys for saved objects
    mem_limit: ${KIBANA_MEM_LIMIT}
    volumes:
      - certs:/usr/share/kibana/config/certs
    ports: [ "5601:5601" ]

volumes:
  certs:
  esdata:
```

Bring it up with `docker compose up -d`, watch logs with `docker compose logs -f`, and reach Kibana at `https://10.10.10.10:5601` from the Mac's browser (accept the self-signed cert warning — you *are* the CA).

> **Memory reality on 16 GB:** ES heap 2 GB + Kibana 1 GB + the VM's own overhead ≈ 4–5 GB for SIEM01. With WS01 at 4 GB you're at ~9 GB committed, leaving room for macOS. If ES gets OOM-killed, lower `ES_MEM_LIMIT`. Note any tuning in your write-up.

### 2.3 — Add Fleet Server and enrol WS01

1. In Kibana → Fleet, set up a **Fleet Server** (it can run as another Elastic Agent container/host on SIEM01, or as a policy — follow the Fleet docs for the lab topology you chose).
2. Create an **Agent Policy** that includes the **System** integration (collects Windows event logs → ECS) and, if the preview agent cooperates, **Elastic Defend**.
3. On **WS01**, install the **Windows ARM64 Elastic Agent** and enrol it to Fleet using the enrolment token. Expect preview rough edges; if Defend misbehaves on ARM, fall back to shipping Windows event logs + Sysmon via the System/Windows integrations, which is plenty for detections. Document whatever you land on.
4. Add the **Sysmon** data: ensure the agent policy collects the `Microsoft-Windows-Sysmon/Operational` channel (the Windows integration can target custom channels).

### 2.4 — Confirm ECS normalisation

In Kibana → Discover, find a process-creation event from WS01 and confirm it carries **ECS fields**: `process.command_line`, `process.parent.name`, `host.name`, `event.code`, `user.name`. This is the proof that raw Windows/Sysmon events became normalised, queryable data.

---

## Acceptance tests

1. `docker compose ps` on SIEM01 shows `es01` and `kibana` healthy.
2. From the Mac: `curl -k -u elastic:<pw> https://10.10.10.10:9200` returns the cluster JSON (proves ES + auth + TLS).
3. Kibana loads over **https** at `:5601` and you can log in.
4. Kibana → Fleet shows **WS01 enrolled and "Healthy"**.
5. Kibana → Discover shows live events from `host.name: WS01`, including a Sysmon Event ID 1 **with ECS fields populated** (`process.parent.name` is not empty).
6. A **KQL** search in Discover like `event.code: "1" and process.name: "notepad.exe"` returns your test event after you open Notepad on WS01.
7. `infra/elastic/docker-compose.yml` is committed (with the gaps filled); `.env` is **not** committed (confirm with `git status`).

---

## Hint ladder

<details>
<summary>Hint 1 — nudge</summary>

Don't hand-write TLS from scratch. Elastic's own documentation ships a complete multi-service `docker-compose.yml` with a `setup` container that generates the CA and certs. Read it, map each piece to the skeleton's `# >>> FILL` markers, and reproduce it *understanding* each line. The learning here is comprehension, not invention.

If ES won't start and the logs mention `max_map_count`, you skipped 2.1 step 5.
</details>

<details>
<summary>Hint 2 — approach</summary>

Order that avoids cert pain: get ES up with security + TLS and prove the `curl` works *before* adding Kibana. Add Kibana and prove login *before* touching Fleet. Add Fleet and prove it's healthy *before* enrolling WS01. Each layer builds on a proven one, so when something breaks you know which layer.

For WS01 enrolment, the enrolment command is generated for you in the Fleet UI — but it defaults to the x64 artifact. You need the **ARM64** agent package. Get the arm64 download, then use the same enrolment token/URL.
</details>

<details>
<summary>Hint 3 — structure</summary>

Milestones, each independently testable:
1. `vm.max_map_count` set → 2. ES single-node + TLS + `curl` works → 3. Kibana login works → 4. Fleet Server healthy → 5. WS01 agent (arm64) enrolled → 6. System + Sysmon data visible in Discover → 7. ECS fields confirmed → commit.
Snapshot SIEM01 as `siem-ready` (replacing clean-baseline) once Discover shows WS01 data.
</details>

---

## Break it

- **Kill `es01`** (`docker compose stop es01`) and watch Kibana lose its backend. Understand that Kibana is a *client* of Elasticsearch — a distinction interviewers test. Restart and confirm recovery.
- **Stop the Elastic Agent on WS01** and watch the agent go "Offline" in Fleet and the event stream dry up. An attacker killing the agent is `T1562` again — note how you'd detect agent-health gaps (Fleet reports last-checkin time).

---

## Evidence to commit

- `evidence/phase2/` — screenshots: `docker compose ps` healthy, the `curl` cluster response, Fleet showing WS01 healthy, a Discover event with ECS fields.
- `infra/elastic/docker-compose.yml` (gaps filled), `infra/elastic/README.md` (how to start/stop/reset the stack, written by you).
- `writeups/phase2.md` — the pipeline in your words (log source → agent → Fleet → ES → Kibana), your memory-tuning decisions, and what "technical preview" cost you on the ARM agent (honesty here reads as maturity).

**Commit message:** `feat(siem): elastic stack with TLS + fleet + WS01 enrolled`

**CV line you've now earned (draft):** *"Built a TLS-secured Elastic SIEM (Elasticsearch/Kibana/Fleet) on ARM64, enrolled a Windows endpoint via Elastic Agent, and normalised Windows/Sysmon telemetry to the Elastic Common Schema."*

---

## Interview questions this phase lets you answer

1. "Describe the log pipeline in a SIEM." → source → agent → Fleet → ingest/parse → ECS → index → search/detect.
2. "What is a common schema and why does it matter?" → ECS; source-agnostic detections, consistent fields.
3. "Kibana vs Elasticsearch — what's the difference?" → UI/client vs engine/store.
4. "KQL vs EQL vs ES|QL in Elastic?" → filtering vs sequences/parent-child vs piped analytics. (And the trap: Kibana KQL ≠ Kusto KQL.)
5. "How did you secure the stack?" → TLS via a self-managed CA, security enabled, per-component system users.

---

## Done? → [`phase-03-attack-detect.md`](phase-03-attack-detect.md)
