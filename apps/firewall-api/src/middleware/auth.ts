import type { Context, Next } from 'hono';
import type { Policy, ApiKeyRecord } from '@firewall/shared';
import { KV_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { POLICY_MEMORY_CACHE_TTL_MS } from '@firewall/shared';

// Module-scope in-memory policy cache — shared within an isolate, TTL ~60s
const policyCache = new Map<string, { policy: Policy; expiresAt: number }>();

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function getPolicy(policyId: string, env: Env): Promise<Policy | null> {
  const hit = policyCache.get(policyId);
  if (hit && hit.expiresAt > Date.now()) return hit.policy;

  const raw = await env.POLICY_CACHE.get(`${KV_PREFIX.POLICY}${policyId}`);
  if (!raw) return null;

  const policy = JSON.parse(raw) as Policy;
  policyCache.set(policyId, { policy, expiresAt: Date.now() + POLICY_MEMORY_CACHE_TTL_MS });
  return policy;
}

async function isKeyRevoked(keyHash: string, env: Env): Promise<boolean> {
  try {
    const doId = env.KEY_REVOCATION.idFromName('global');
    const stub = env.KEY_REVOCATION.get(doId);
    const res = await stub.fetch(`https://internal/${keyHash}`);
    const { revoked } = await res.json<{ revoked: boolean }>();
    return revoked;
  } catch {
    return false; // fail-open for revocation check
  }
}

export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const rawKey = c.req.header('X-API-Key');
  if (!rawKey) {
    return c.json({ error: 'Missing X-API-Key header', code: 'INVALID_API_KEY' }, 401);
  }

  const keyHash = await sha256Hex(rawKey);
  const raw = await c.env.API_KEYS.get(`${KV_PREFIX.API_KEY}${keyHash}`);

  if (!raw) {
    return c.json({ error: 'Invalid API key', code: 'INVALID_API_KEY' }, 401);
  }

  const keyRecord = JSON.parse(raw) as ApiKeyRecord;

  if (!keyRecord.active) {
    return c.json({ error: 'API key is inactive', code: 'INVALID_API_KEY' }, 401);
  }

  // Fast revocation check via Durable Object (bypasses KV propagation delay)
  if (await isKeyRevoked(keyHash, c.env)) {
    return c.json({ error: 'API key has been revoked', code: 'INVALID_API_KEY' }, 401);
  }

  // Resolve policy: X-Policy-Name override → default
  const policyNameHeader = c.req.header('X-Policy-Name');
  let policy: Policy | null = null;

  if (policyNameHeader) {
    // Find the named policy among the key's bound policies
    for (const pid of keyRecord.policyIds) {
      const p = await getPolicy(pid, c.env);
      if (p && p.name === policyNameHeader) {
        policy = p;
        break;
      }
    }
    if (!policy) {
      return c.json({ error: `Policy '${policyNameHeader}' not bound to this key`, code: 'POLICY_NOT_FOUND' }, 400);
    }
  } else {
    policy = await getPolicy(keyRecord.defaultPolicyId, c.env);
  }

  if (!policy) {
    return c.json({ error: 'Policy not found', code: 'POLICY_NOT_FOUND' }, 500);
  }

  c.set('keyRecord' as never, keyRecord);
  c.set('policy' as never, policy);

  // Update lastUsedAt in the background
  c.executionCtx.waitUntil(
    c.env.API_KEYS.put(
      `${KV_PREFIX.API_KEY}${keyHash}`,
      JSON.stringify({ ...keyRecord, lastUsedAt: new Date().toISOString() }),
    ),
  );

  return next();
}
