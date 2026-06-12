import type { Context, Next } from 'hono';
import type { Policy, ApiKeyRecord } from '@firewall/shared';
import type { Env } from '../env.js';

// Hard ceiling applied to every key regardless of policy configuration
const GLOBAL_RPM_CAP = 60;

export async function rateLimitMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const keyRecord = c.get('keyRecord' as never) as ApiKeyRecord;
  const policy = c.get('policy' as never) as Policy;

  const requestsPerMinute = policy.rateLimit?.requestsPerMinute ?? GLOBAL_RPM_CAP;
  const requestsPerHour = policy.rateLimit?.requestsPerHour ?? undefined;
  const doId = c.env.RATE_LIMITER.idFromName(keyRecord.id);
  const stub = c.env.RATE_LIMITER.get(doId);

  // Check per-minute window
  const minRes = await stub.fetch('https://rl/', {
    method: 'POST',
    body: JSON.stringify({ windowMs: 60_000, limit: requestsPerMinute }),
    headers: { 'Content-Type': 'application/json' },
  });
  const { allowed: minAllowed } = await minRes.json<{ allowed: boolean }>();

  if (!minAllowed) {
    return c.json(
      { error: 'Rate limit exceeded (per-minute)', code: 'RATE_LIMITED', retryAfterSeconds: 60 },
      429,
    );
  }

  return next();
}
