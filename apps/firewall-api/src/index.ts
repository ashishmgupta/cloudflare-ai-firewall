import { Hono } from 'hono';
import { InspectRequestSchema, MAX_PROMPT_BYTES } from '@firewall/shared';
import type { SecurityProfile } from '@firewall/shared';
import type { Env } from './env.js';
import { authMiddleware } from './middleware/auth.js';
import { runPipeline } from './pipeline.js';

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error('[firewall-api] unhandled error:', err);
  return c.json({ error: 'Internal server error', code: 'INTERNAL_ERROR' }, 500);
});

app.get('/', c => c.text('AI Firewall API v2'));
app.get('/health', c => c.json({ status: 'ok', version: 2 }));

app.get('/v1/debug/l3-prompt', async c => {
  const { SYSTEM_PROMPT } = await import('./layers/layer3-llm.js');
  return c.json({ systemPrompt: SYSTEM_PROMPT });
});

app.get('/v1/profile-info', authMiddleware, async c => {
  const profile = c.get('profile' as never) as SecurityProfile;
  const { getActiveDetections } = await import('./pipeline.js');
  const active = getActiveDetections(profile);
  return c.json({
    id: profile.id,
    name: profile.name,
    detections: active.map(ad => ({
      policyName:    ad.policyName,
      categoryName:  ad.categoryName,
      detectionName: ad.detection.name,
      mode:          ad.detection.mode,
      settings:      ad.enabledSettings.map(s => ({ id: s.id, name: s.name })),
    })),
  });
});

app.delete('/v1/cache', authMiddleware, async c => {
  const { hashPrompt } = await import('./layers/layer1-cache.js');
  const profile = c.get('profile' as never) as SecurityProfile;

  let body: { prompt?: string } = {};
  try { body = await c.req.json(); } catch { /* no body = purge all KV */ }

  if (body.prompt) {
    // Purge a single prompt from both Cache API and KV
    const hash = await hashPrompt(body.prompt);
    const cacheKey = `${hash}:${profile.id}`;
    const cacheApiDeleted = await caches.default.delete(
      new Request(`https://firewall-cache.internal/${cacheKey}`),
    );
    await c.env.VERDICT_CACHE.delete(`verdict:${cacheKey}`);
    return c.json({ purged: 1, cacheApiDeleted });
  }

  // No prompt supplied — purge all KV keys for this profile
  const list = await c.env.VERDICT_CACHE.list({ prefix: 'verdict:' });
  const profileSuffix = `:${profile.id}`;
  const toDelete = list.keys
    .map(k => k.name)
    .filter(name => name.endsWith(profileSuffix));
  await Promise.all(toDelete.map(name => c.env.VERDICT_CACHE.delete(name)));
  return c.json({ purged: toDelete.length, note: 'KV only — Cache API entries expire via TTL' });
});

app.post('/v1/inspect', authMiddleware, async c => {
  const body = await c.req.json();

  // Check the last message (the prompt being inspected) against the byte limit
  const lastContent = Array.isArray(body?.messages)
    ? (body.messages[body.messages.length - 1]?.content ?? '')
    : '';
  const byteLen = new TextEncoder().encode(lastContent).length;
  if (byteLen > MAX_PROMPT_BYTES) {
    return c.json(
      { error: `Prompt exceeds ${MAX_PROMPT_BYTES} bytes`, code: 'PROMPT_TOO_LARGE' },
      413,
    );
  }

  const parsed = InspectRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'Validation error', code: 'VALIDATION_ERROR', details: parsed.error.flatten() }, 400);
  }

  const profile = c.get('profile' as never) as SecurityProfile;
  const requestId = crypto.randomUUID();
  const bypassCache = c.req.header('X-Bypass-Cache') === '1';

  const wallStart = Date.now();
  const result = await runPipeline(parsed.data, profile, c.env, c.executionCtx, requestId, bypassCache);
  const wallMs = Date.now() - wallStart;

  // Latency as response headers — always accurate for THIS request.
  // Cached responses only get the cache-lookup time; layer breakdown is omitted
  // because those layers did not run.
  c.header('X-Firewall-Request-Id', requestId);
  c.header('X-Firewall-Cached', result.cached ? 'true' : 'false');
  if (result.cached) {
    c.header('X-Firewall-Latency-Ms', String(wallMs));
  } else if (result.latencyMs) {
    c.header('X-Firewall-Latency-Ms', String(result.latencyMs.total));
    for (const [layer, ms] of Object.entries(result.latencyMs.perLayer)) {
      c.header(`X-Firewall-${layer}-Ms`, String(ms));
    }
  }

  // Strip latencyMs from the response body — it lives in headers now.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { latencyMs: _dropped, ...responseBody } = result;
  const status = result.verdict === 'block' ? 403 : 200;
  return c.json(responseBody, status);
});

export default app;

// Legacy DO stubs — required by Cloudflare while the deleted_classes migration runs.
export { KeyRevocation, RateLimiter } from './durable-objects/legacy-stubs.js';
