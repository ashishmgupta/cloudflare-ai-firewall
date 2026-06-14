import type { Context, Next } from 'hono';
import { KV_PROFILE_PREFIX, PROFILE_MEMORY_CACHE_TTL_MS, SecurityProfileSchema } from '@firewall/shared';
import type { SecurityProfile } from '@firewall/shared';
import type { Env } from '../env.js';

// Module-scope — shared within a Workers isolate, TTL 60s
const profileCache = new Map<string, { profile: SecurityProfile; expiresAt: number }>();

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function loadProfile(profileId: string, env: Env): Promise<SecurityProfile | null> {
  const hit = profileCache.get(profileId);
  if (hit && hit.expiresAt > Date.now()) return hit.profile;

  const raw = await env.POLICY_CACHE.get(`${KV_PROFILE_PREFIX}${profileId}`);
  if (!raw) return null;

  const profile = SecurityProfileSchema.parse(JSON.parse(raw));
  profileCache.set(profileId, { profile, expiresAt: Date.now() + PROFILE_MEMORY_CACHE_TTL_MS });
  return profile;
}

export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const rawKey = c.req.header('X-API-Key');
  if (!rawKey) {
    return c.json({ error: 'Missing X-API-Key header', code: 'INVALID_API_KEY' }, 401);
  }

  const keyHash = await sha256Hex(rawKey);

  // Read 1: keyHash → { profileId }
  const pointerRaw = await c.env.POLICY_CACHE.get(`${KV_PROFILE_PREFIX}${keyHash}`);
  if (!pointerRaw) {
    return c.json({ error: 'Invalid API key', code: 'INVALID_API_KEY' }, 401);
  }

  const { profileId } = JSON.parse(pointerRaw) as { profileId: string };

  // Read 2: profileId → full document (in-memory cached)
  const profile = await loadProfile(profileId, c.env);
  if (!profile) {
    return c.json({ error: 'Profile not found', code: 'PROFILE_NOT_FOUND' }, 500);
  }

  c.set('profile' as never, profile);

  return next();
}
