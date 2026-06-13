import { Hono } from 'hono';
import { PROMPT_SETS } from './prompts.js';
import { insertEvent, queryEvents, getStats, clearEvents } from './db.js';
import { getHtml } from './html.js';

interface Env {
  DB: D1Database;
  ADMIN_TOKEN: string;
  FIREWALL_API: Fetcher; // Service Binding — avoids workers.dev cross-Worker fetch restriction
  FIREWALL_API_KEY: string;
}

const app = new Hono<{ Bindings: Env }>();

// ── Serve UI ──────────────────────────────────────────────────────────────────
app.get('/', c => c.html(getHtml()));

// ── Prompt sets (public — static data) ───────────────────────────────────────
app.get('/api/prompt-sets', c =>
  c.json(PROMPT_SETS.map(s => ({ id: s.id, name: s.name, description: s.description, items: s.items }))),
);

// ── Auth middleware for all other /api routes ─────────────────────────────────
app.use('/api/*', async (c, next) => {
  const token = c.req.header('X-Admin-Token');
  if (!token || token !== c.env.ADMIN_TOKEN) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  await next();
});

// ── Run an entire prompt set ──────────────────────────────────────────────────
app.post('/api/run-set', async c => {
  const { setId } = await c.req.json<{ setId: string }>();
  const set = PROMPT_SETS.find(s => s.id === setId);
  if (!set) return c.json({ error: 'Unknown set id' }, 404);

  const results = await Promise.allSettled(
    set.items.map(item => runAndStore(item.prompt, setId, item.label, item.expected, c.env)),
  );

  const mapped = await Promise.all(results.map(async (r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const errMsg = String(r.reason);
    console.error(`[run-set] prompt "${set.items[i].label}" failed: ${errMsg}`);
    try {
      await insertEvent(c.env.DB, {
        id: crypto.randomUUID(),
        ts: new Date().toISOString(),
        prompt_set: setId,
        prompt_label: set.items[i].label,
        prompt: set.items[i].prompt,
        verdict: 'error',
        expected: set.items[i].expected,
        violations: '[]',
        latency_ms: 0,
        request_id: null,
        raw_request: JSON.stringify({ prompt: set.items[i].prompt }),
        raw_response: JSON.stringify({ error: errMsg }),
      });
    } catch (dbErr) {
      console.error('[run-set] D1 insert failed:', String(dbErr));
    }
    return {
      label: set.items[i].label,
      prompt: set.items[i].prompt,
      expected: set.items[i].expected,
      verdict: 'error',
      violations: [],
      latencyMs: 0,
      pass: false,
      error: errMsg,
    };
  }));

  return c.json({
    setId,
    results: mapped,
    summary: { total: mapped.length, passed: mapped.filter(r => r.pass).length },
  });
});

// ── Events ────────────────────────────────────────────────────────────────────
app.get('/api/events', async c => {
  const { set, verdict, limit = '100', offset = '0' } = c.req.query();
  const rows = await queryEvents(c.env.DB, {
    set: set || undefined,
    verdict: verdict || undefined,
    limit: Number(limit),
    offset: Number(offset),
  });
  return c.json(rows);
});

app.delete('/api/events', async c => {
  await clearEvents(c.env.DB);
  return c.json({ ok: true });
});

// ── Stats ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', async c => {
  const stats = await getStats(c.env.DB);
  return c.json(stats);
});

// ── Internal: run one prompt, store result, return row ────────────────────────
async function runAndStore(
  prompt: string,
  promptSet: string,
  promptLabel: string,
  expected: string,
  env: Env,
) {
  const rawRequest = JSON.stringify({ prompt });
  const t0 = Date.now();

  const res = await env.FIREWALL_API.fetch('https://firewall-api/v1/inspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': env.FIREWALL_API_KEY },
    body: rawRequest,
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`HTTP ${res.status}: ${errBody}`);
  }

  const data = await res.json<{
    verdict: string;
    violations: unknown[];
    latencyMs?: { total?: number };
    requestId?: string;
  }>();

  const latencyMs = data.latencyMs?.total ?? (Date.now() - t0);

  await insertEvent(env.DB, {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    prompt_set: promptSet,
    prompt_label: promptLabel,
    prompt,
    verdict: data.verdict,
    expected,
    violations: JSON.stringify(data.violations ?? []),
    latency_ms: latencyMs,
    request_id: data.requestId ?? null,
    raw_request: rawRequest,
    raw_response: JSON.stringify(data),
  });

  return {
    label: promptLabel,
    prompt,
    expected,
    verdict: data.verdict,
    violations: data.violations ?? [],
    latencyMs,
    pass: data.verdict === expected,
  };
}

export default app;
