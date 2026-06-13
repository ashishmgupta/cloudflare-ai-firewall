# Architecture — Cloudflare AI Firewall

## Component diagram

```mermaid
flowchart TB
    %% ── Clients ──────────────────────────────────────────────────────────────
    subgraph clients["Clients"]
        ext["External Application\n(your product)"]
        admin["Admin / Operator"]
        tester["Firewall Tester\n(testing UI)"]
    end

    %% ── Workers ──────────────────────────────────────────────────────────────
    subgraph workers["Cloudflare Workers"]
        fw["firewall-api\n──────────────\nInspection endpoint\nPOST /v1/inspect"]
        pm["policy-manager\n──────────────\nAdmin REST API\n+ Web UI"]
        ft["firewall-tester\n──────────────\nPrompt runner\n+ reporting UI"]
    end

    %% ── Detection Pipeline ───────────────────────────────────────────────────
    subgraph pipeline["Detection Pipeline  (inside firewall-api)"]
        direction LR
        l0["Layer 0\nHeuristics\nRegex · PII · obfuscation\n≤ 1 ms"]
        l1["Layer 1\nVerdict Cache\nKV lookup\n5–10 ms"]
        l2["Layer 2\nVector Similarity\nbge-small-en-v1.5\n20–40 ms"]
        l3["Layer 3\nLLM Classifier\nllama-3.3-70b-fp8\n100–500 ms"]
        verdict(["Verdict\npass · monitor · block"])
        l0 -->|"high confidence\n→ short-circuit"| verdict
        l0 -->|uncertain| l1
        l1 -->|"cache hit\n→ short-circuit"| verdict
        l1 -->|miss| l2
        l2 -->|"match ≥ threshold\n→ short-circuit"| verdict
        l2 -->|low confidence| l3
        l3 --> verdict
    end

    %% ── Middleware (firewall-api) ─────────────────────────────────────────────
    subgraph middleware["Auth & Rate-limit  (inside firewall-api)"]
        direction LR
        auth["Auth middleware\nSHA-256(key) → profile lookup"]
        rl["RateLimiter DO\nper-key RPM cap"]
        kr["KeyRevocation DO\ninstant revocation\n(bypasses KV TTL)"]
    end

    %% ── KV Namespaces ────────────────────────────────────────────────────────
    subgraph kv["Workers KV  (global, low-latency reads)"]
        kv_policy["POLICY_CACHE\n──────────────\nkey hash → profile ID\nprofile ID → SecurityProfile\n(propagates in ~60 s)"]
        kv_verdict["VERDICT_CACHE\n──────────────\nSHA-256(prompt) → verdict\n(TTL: configurable)"]
    end

    %% ── R2 Buckets ───────────────────────────────────────────────────────────
    subgraph r2["R2  (durable, cheap-at-rest)"]
        r2_pol["ai-firewall-policies\n──────────────\nProfile documents\nAPI key records"]
        r2_aud["ai-firewall-audit\n──────────────\nAudit log events"]
    end

    %% ── AI & Vectorize ───────────────────────────────────────────────────────
    subgraph ai["Workers AI  +  Vectorize"]
        emb["bge-small-en-v1.5\n(embeddings)"]
        llm["llama-3.3-70b-instruct-fp8-fast\n(content safety classification)"]
        vec[("Vectorize index\nai-firewall-attacks\n384-dim cosine")]
        emb -->|"query vector"| vec
    end

    %% ── D1 ───────────────────────────────────────────────────────────────────
    d1[("D1 SQLite\nfirewall-events\n──────────────\nTest run history\nraw request · response\nverdict · latency")]

    %% ── Traffic flows ─────────────────────────────────────────────────────────
    ext  -->|"POST /v1/inspect\nX-API-Key: fw_…"| fw
    admin -->|"REST API + Admin UI\nAuthorization: Bearer …"| pm
    tester -->|"Service Binding\n(internal, no public internet)"| fw
    tester -->|"INSERT run results"| d1

    fw --> middleware
    middleware --> pipeline

    auth -->|"1. hash key\n2. KV lookup"| kv_policy
    auth -->|"revocation check"| kr
    rl -.->|"per-key counter"| rl

    l1 <-->|"read / write verdicts"| kv_verdict
    l2 -->|"embed prompt"| emb
    l3 -->|"classify prompt"| llm

    pm -->|"write key hash + profile\n(fast path)"| kv_policy
    pm -->|"write full docs\n(durable)"| r2_pol
    pm -->|"append audit event"| r2_aud
```

---

## Component roles

| Component | Type | Role |
|-----------|------|------|
| `firewall-api` | Worker | Latency-critical inspection endpoint. Runs the 4-layer detection pipeline for every prompt. |
| `policy-manager` | Worker | Admin control plane. Manages SecurityProfiles, API keys, audit log. Writes to KV + R2. |
| `firewall-tester` | Worker | Developer tool. Runs prompt sets against `firewall-api` via Service Binding, stores results in D1, serves reporting UI. |
| `POLICY_CACHE` | KV | Shared between both Workers. Stores SHA-256(key)→profileId pointer and full SecurityProfile documents. Globally replicated, ~60 s propagation. |
| `VERDICT_CACHE` | KV | Per-prompt verdict cache keyed by SHA-256(prompt). Short-circuits layers 2 and 3 on cache hit. |
| `ai-firewall-policies` | R2 | Durable storage for profile documents and API key records. Written by policy-manager; never read on the hot path. |
| `ai-firewall-audit` | R2 | Append-only audit log for all admin actions. |
| `firewall-events` | D1 | SQLite database owned by firewall-tester. Stores prompt, verdict, violations, latency, and raw request/response per test run. |
| `RateLimiter` | Durable Object | Per-key request counter. Enforces `rateLimit.requestsPerMinute` from the SecurityProfile. |
| `KeyRevocation` | Durable Object | Instant revocation store. Bypasses KV's ~60 s propagation delay — revoked keys are rejected immediately. |
| `bge-small-en-v1.5` | Workers AI | Embeds the incoming prompt into a 384-dim vector for similarity search (Layer 2). |
| `llama-3.3-70b-instruct-fp8-fast` | Workers AI | LLM safety classifier (Layer 3). Evaluates prompts against S1–S14 content safety categories. |
| `ai-firewall-attacks` (Vectorize) | Vectorize | 384-dim cosine index of known attack signatures. Layer 2 queries this with the prompt embedding. |
| Service Binding | Binding | Allows `firewall-tester` to call `firewall-api` directly over Cloudflare's internal network, bypassing the workers.dev public URL restriction. |

---

## Detection pipeline — short-circuit logic

```
prompt
  │
  ▼
Layer 0 — Heuristics (regex, PII patterns, base64/unicode obfuscation)
  ├─ high confidence  ──────────────────────────────► verdict  (≤1ms)
  └─ uncertain
       │
       ▼
Layer 1 — Verdict Cache  (KV lookup by SHA-256(prompt))
  ├─ cache hit  ─────────────────────────────────────► verdict  (5–10ms)
  └─ miss
       │
       ▼
Layer 2 — Vector Similarity  (embed → Vectorize cosine search)
  ├─ score ≥ threshold  ─────────────────────────────► verdict  (20–40ms)
  └─ low confidence
       │
       ▼
Layer 3 — LLM Classifier  (llama-3.3-70b content safety)
       └──────────────────────────────────────────────► verdict  (100–500ms)
```

Each layer only runs if the previous layer was inconclusive. The vast majority of obvious attacks exit at Layer 0 or Layer 1.

---

## Key data paths

### Hot path (every /v1/inspect request)
1. `firewall-api` auth middleware: SHA-256(key) → `POLICY_CACHE` KV read (x2) → SecurityProfile
2. `RateLimiter` DO: increment + check counter
3. `KeyRevocation` DO: check revoked flag
4. Layer 0–3 pipeline (short-circuits as early as possible)
5. On Layer 1 miss + final verdict: write verdict back to `VERDICT_CACHE`

### Admin path (policy-manager changes)
1. Validate + persist profile/key to `ai-firewall-policies` R2
2. Write fast-read copies to `POLICY_CACHE` KV (propagates globally in ~60 s)
3. Append structured event to `ai-firewall-audit` R2

### Test path (firewall-tester)
1. Browser → `firewall-tester` Worker → Service Binding → `firewall-api`
2. `firewall-tester` inserts result row into `D1 firewall-events`
3. Stats dashboard reads aggregates from D1 (`GROUP BY prompt_set, verdict`)
