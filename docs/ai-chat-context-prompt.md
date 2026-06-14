# Context Prompt — Cloudflare AI Firewall Project

> Paste everything below this line into Claude or ChatGPT to start a conversation with full project context.

---

I'm working on a project called **Cloudflare AI Firewall** — a prompt inspection firewall built entirely on Cloudflare's edge infrastructure. Here is the full context so you can help me discuss, design, and improve it.

---

## What it does

Every AI prompt from my application passes through a **Cloudflare Worker** (`firewall-api`) before reaching the LLM. That Worker runs a 4-layer detection pipeline and returns one of three verdicts: `pass`, `monitor`, or `block`. Blocked prompts get a 403 response with violation details and MITRE ATLAS technique tags. The whole thing is designed to run at the edge with a target latency of ≤10 ms on cache hits.

---

## The three Workers

### 1. `firewall-api` (inspection endpoint)
- Receives `POST /v1/inspect` with `{ prompt }` in the body and `X-API-Key` header
- Authenticates by SHA-256 hashing the key, looking up a profile ID in KV, then loading the full SecurityProfile
- Runs a 4-layer detection pipeline (described below)
- Returns `{ verdict, violations, latencyMs, requestId, cached }`
- Returns 200 for pass/monitor, 403 for block — both have the full JSON body

### 2. `policy-manager` (admin control plane)
- REST API + web dashboard for managing SecurityProfiles, API keys, attack signatures
- Writes to two places: KV (fast path, ~60s global propagation) and R2 (durable source of truth)
- Also manages attack signatures: embeds text with `bge-small-en-v1.5` and upserts vectors into Vectorize
- Protected by `Authorization: Bearer <ADMIN_TOKEN>`

### 3. `firewall-tester` (developer testing tool)
- Web UI for running curated prompt sets against `firewall-api`
- Calls `firewall-api` via a **Service Binding** (internal Cloudflare network, no public URL needed)
- Stores every test run in D1 SQLite: prompt, verdict, violations, latency, raw request/response
- Shows verdict charts, pass/fail per prompt, violations detail

---

## Detection pipeline (inside firewall-api)

Layers run in order with short-circuit logic — each layer only runs if the previous was inconclusive.

**Layer 0 — Heuristics (synchronous, ~0 ms)**
- Pure regex + pattern matching, no I/O
- Detects: PII (SSN, credit card with Luhn check, phone, email — context-aware, won't fire on bare numbers), technical info (IP, MAC, API secrets, URLs), prompt injection patterns (override/ignore/forget instructions, system prompt token injection, mode switching), jailbreaks (DAN, developer mode, roleplay-as, persistence commands), obfuscation (base64 blobs, hex strings, zero-width unicode, delimiter flooding)
- If any `block`-mode violation found → immediately returns, no AI calls made

**Layer 1 — Verdict Cache (two-tier)**
- Tier 1: Workers Cache API (colocated, same datacenter) — fastest
- Tier 2: VERDICT_CACHE KV (cross-region fallback)
- Cache key: `SHA-256(normalize(prompt)):profileId`
- **Layer 1 and Layer 2 fire in parallel** — if L1 hits, L2 result is discarded

**Layer 2 — Vector Similarity (optional, ~20–40 ms)**
- Embeds the prompt with `bge-small-en-v1.5` → 384-dim vector
- Queries Vectorize index `ai-firewall-attacks` (cosine similarity, topK=5)
- Triggers if top match score ≥ 0.82
- Only runs for injection/jailbreak detections, not content moderation
- Vectorize is optional — returns nothing if not bound (requires Workers paid plan)

**Layer 3 — LLM Classifier (~1–3 s)**
- Uses `llama-3.3-70b-instruct-fp8-fast` via Workers AI
- **Only runs if Content Moderation detections are active in the profile** — completely skipped otherwise
- Builds a dynamic system prompt from the active detection profile
- Returns structured JSON with violations matching the profile's enabled settings
- Hallucinates are discarded: violations are cross-checked against the active detection list

---

## Cloudflare services used

| Service | Binding | Purpose |
|---|---|---|
| Workers KV (`POLICY_CACHE`) | firewall-api + policy-manager | Key-hash → profile ID pointer; profile ID → SecurityProfile document. Shared namespace. ~60s propagation. |
| Workers KV (`VERDICT_CACHE`) | firewall-api | Two-tier verdict cache. Cache API first, KV fallback. Keyed by SHA-256(normalize(prompt)):profileId |
| R2 (`ai-firewall-policies`) | policy-manager | Durable source of truth: `profiles/`, `apikeys/`, `signatures/` — never read on hot path |
| R2 (`ai-firewall-audit`) | policy-manager | Append-only admin action audit log |
| D1 SQLite (`firewall-events`) | firewall-tester + policy-manager (shared) | Tables: users, sessions, events, inspect_keys. Session auth for both apps. Test run history. Inspect-tab profile registry. |
| Workers AI | firewall-api + policy-manager | `bge-small-en-v1.5` for embeddings; `llama-3.3-70b-instruct-fp8-fast` for L3 classification |
| Vectorize (`ai-firewall-attacks`) | firewall-api (read) + policy-manager (write) | 384-dim cosine index of known attack prompt embeddings |
| Service Binding | firewall-tester → firewall-api | Internal call, no public internet, no workers.dev restriction |

---

## Data model — SecurityProfile

```typescript
{
  id: string,                    // UUID
  name: string,
  policies: [{
    name: string,
    categories: [{
      name: string,
      detections: [{
        id: string,              // e.g. "det-injection", "det-jailbreak", "det-content-mod"
        name: string,
        mode: "block" | "monitor",
        mitreAtlas: { id, name, url },
        settings: [{             // granular toggles, e.g. "set-ssn", "set-inj-override"
          id: string,
          name: string,
          enabled: boolean
        }]
      }]
    }]
  }],
  rateLimit: { requestsPerMinute: number },
  failOpen: boolean,             // true = pass on pipeline error; false = block
  cacheTtlSeconds: number,
  createdAt: string,
  updatedAt: string
}
```

---

## Auth flow (firewall-api)

1. Read `X-API-Key` header (raw key, e.g. `fw_abc123...`)
2. SHA-256 hash the raw key
3. KV lookup: `securityProfile:{hash}` → `{ profileId }`
4. KV lookup: `securityProfile:{profileId}` → full SecurityProfile JSON
5. Run pipeline

---

## Monorepo structure

```
cloudflare-ai-firewall/
  apps/
    firewall-api/src/
      index.ts              — Hono app, /v1/inspect route
      pipeline.ts           — 4-layer orchestration
      env.ts                — Env interface (AI, POLICY_CACHE, VERDICT_CACHE, FIREWALL_VECTORIZE?, DOs)
      middleware/
        auth.ts             — key hash → KV → SecurityProfile
      layers/
        layer0-heuristics.ts
        layer1-cache.ts     — Cache API + KV two-tier
        layer2-vector.ts    — bge-small + Vectorize (injection/jailbreak only)
        layer3-llm.ts       — llama-3.3-70b (content-mod only)
      durable-objects/
        legacy-stubs.ts     — empty KeyRevocation + RateLimiter stubs (migration only)
    policy-manager/src/
      routes/
        profiles.ts         — CRUD SecurityProfiles
        api-keys.ts         — Create/revoke API keys
        signatures.ts       — Add/delete attack signatures (embeds + Vectorize upsert)
        audit.ts            — Read audit log
        templates.ts        — Built-in policy templates
      storage/
        kv.ts               — Write to POLICY_CACHE
        r2.ts               — Write to POLICY_STORE + AUDIT_LOG
    firewall-tester/src/
      index.ts              — Hono app, /api/run-set, /api/events, /api/stats
      db.ts                 — D1 helpers
      prompts.ts            — Curated prompt sets (benign, injection, jailbreak, PII, content mod)
      html.ts               — Inline reporting UI
  packages/shared/src/
    schemas.ts              — Zod schemas (SecurityProfile, InspectRequest/Response, Violation)
    constants.ts            — KV prefixes, R2 prefixes, model IDs
    atlas.ts                — MITRE ATLAS technique definitions
  scripts/
    seed-kv.ts              — Directly writes SecurityProfile + API key hash to KV via wrangler
```

---

## Deployed URLs

- `https://firewall-api.ashishmgupta.workers.dev` — inspection endpoint
- `https://policy-manager.ashishmgupta.workers.dev` — admin UI + REST API
- `https://firewall-tester.ashishmgupta.workers.dev` — test runner UI

---

## Key design decisions made so far

- **R2 vs D1**: R2 for policy/config objects (key-based access, no SQL needed). D1 for test event history (needs GROUP BY, WHERE, pagination). Different services, different access patterns — not overengineering.
- **Two-tier verdict cache**: Cache API is colocated (same DC, sub-ms), KV is cross-region fallback. Both are written on every cache miss.
- **L1+L2 parallel**: Both fire simultaneously; L2 result is thrown away if L1 hits first.
- **Layer 3 scoping**: LLM only runs for Content Moderation. Injection/jailbreak are fully handled by L0 (regex) + L2 (vector). This keeps median latency low.
- **No Durable Objects**: RateLimiter and KeyRevocation DOs were removed — rate limiting is handled by Cloudflare AI Gateway; revocation uses KV (accepts ~60s propagation window).
- **KV seeding**: Done directly via `scripts/seed-kv.ts` + `wrangler kv key put --remote` rather than through the policy-manager HTTP API, because it's simpler for bootstrapping.
- **Vectorize is optional**: Both Workers check `if (!env.FIREWALL_VECTORIZE)` and degrade gracefully — L2 returns empty, signature routes return 503.
- **failOpen flag**: Per SecurityProfile — if `true`, pipeline errors default to `pass`; if `false`, they default to `block`.
