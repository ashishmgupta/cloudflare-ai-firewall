import { Hono } from 'hono';
import { InspectRequestSchema, MAX_PROMPT_BYTES } from '@firewall/shared';
import type { SecurityProfile } from '@firewall/shared';
import type { Env } from './env.js';
import { authMiddleware } from './middleware/auth.js';
import { rateLimitMiddleware } from './middleware/rate-limit.js';
import { runPipeline } from './pipeline.js';
import { RateLimiter } from './durable-objects/rate-limiter.js';
import { KeyRevocation } from './durable-objects/key-revocation.js';

export { RateLimiter, KeyRevocation };

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error('[firewall-api] unhandled error:', err);
  return c.json({ error: 'Internal server error', code: 'INTERNAL_ERROR' }, 500);
});

app.get('/', c => c.text('AI Firewall API v2'));
app.get('/health', c => c.json({ status: 'ok', version: 2 }));

app.post('/v1/inspect', authMiddleware, rateLimitMiddleware, async c => {
  const body = await c.req.json();

  const byteLen = new TextEncoder().encode(body?.prompt ?? '').length;
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

  const result = await runPipeline(parsed.data, profile, c.env, c.executionCtx, requestId, bypassCache);
  const status = result.verdict === 'block' ? 403 : 200;
  return c.json(result, status);
});

export default app;
