import type { Context, Next } from 'hono';
import type { SecurityProfile } from '@firewall/shared';
import { GLOBAL_RPM_CAP } from '@firewall/shared';
import type { Env } from '../env.js';

export async function rateLimitMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const profile = c.get('profile' as never) as SecurityProfile;
  const keyHash = c.get('keyHash' as never) as string;

  const requestsPerMinute = profile.rateLimit?.requestsPerMinute ?? GLOBAL_RPM_CAP;
  const doId = c.env.RATE_LIMITER.idFromName(keyHash);
  const stub = c.env.RATE_LIMITER.get(doId);

  const res = await stub.fetch('https://rl/', {
    method: 'POST',
    body: JSON.stringify({ windowMs: 60_000, limit: requestsPerMinute }),
    headers: { 'Content-Type': 'application/json' },
  });
  const { allowed } = await res.json<{ allowed: boolean }>();

  if (!allowed) {
    return c.json(
      { error: 'Rate limit exceeded', code: 'RATE_LIMITED', retryAfterSeconds: 60 },
      429,
    );
  }

  return next();
}
