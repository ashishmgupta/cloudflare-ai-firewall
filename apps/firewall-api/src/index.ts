import { Hono } from 'hono';
import { InspectRequestSchema } from '@firewall/shared';
import { MAX_PROMPT_BYTES } from '@firewall/shared';
import type { Env } from './env.js';
import type { Policy, ApiKeyRecord } from '@firewall/shared';
import { authMiddleware } from './middleware/auth.js';
import { rateLimitMiddleware } from './middleware/rate-limit.js';
import { runPipeline } from './pipeline.js';
import { RateLimiter } from './durable-objects/rate-limiter.js';
import { KeyRevocation } from './durable-objects/key-revocation.js';

export { RateLimiter, KeyRevocation };

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: 'Internal server error', code: 'INTERNAL_ERROR' }, 500);
});

app.get('/', c => c.text('AI Firewall API'));
app.get('/health', c => c.json({ status: 'ok' }));

app.post('/v1/inspect', authMiddleware, rateLimitMiddleware, async c => {
  const body = await c.req.json();

  // Size gate before Zod (cheap)
  const byteLen = new TextEncoder().encode(body?.prompt ?? '').length;
  if (byteLen > MAX_PROMPT_BYTES) {
    return c.json(
      { error: `Prompt exceeds maximum size of ${MAX_PROMPT_BYTES} bytes`, code: 'PROMPT_TOO_LARGE' },
      413,
    );
  }

  const parsed = InspectRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'Validation error', code: 'VALIDATION_ERROR', details: parsed.error.flatten() }, 400);
  }

  const req = parsed.data;
  const policy = c.get('policy' as never) as Policy;
  const keyRecord = c.get('keyRecord' as never) as ApiKeyRecord;
  const requestId = crypto.randomUUID();

  // Async mode: return 202 immediately, run pipeline in background
  if (req.mode === 'async') {
    if (!policy.webhookUrl) {
      return c.json({ error: 'Async mode requires a webhookUrl configured in the policy', code: 'VALIDATION_ERROR' }, 400);
    }

    c.executionCtx.waitUntil(
      runPipeline(req, policy, c.env, c.executionCtx, requestId)
        .then(verdict =>
          fetch(policy.webhookUrl!, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Firewall-Key-Id': keyRecord.id },
            body: JSON.stringify(verdict),
          }),
        )
        .catch(console.error),
    );

    return c.json({ requestId, status: 'queued' }, 202);
  }

  // Sync mode
  const verdict = await runPipeline(req, policy, c.env, c.executionCtx, requestId);
  const status = verdict.verdict === 'block' ? 403 : 200;
  return c.json(verdict, status);
});

export default app;
