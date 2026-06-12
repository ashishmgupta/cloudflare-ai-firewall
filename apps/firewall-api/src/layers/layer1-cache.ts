import type { InspectResponse } from '@firewall/shared';
import type { Env } from '../env.js';

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function normalize(prompt: string): string {
  return prompt.toLowerCase().replace(/\s+/g, ' ').trim();
}

export async function hashPrompt(prompt: string): Promise<string> {
  return sha256Hex(normalize(prompt));
}

export async function checkLayer1Cache(
  cacheKey: string,
  env: Env,
): Promise<InspectResponse | null> {
  // Try colocated Cache API first (fastest — same datacenter)
  const cacheUrl = `https://firewall-cache.internal/${cacheKey}`;
  const cached = await caches.default.match(new Request(cacheUrl));
  if (cached) {
    return cached.json<InspectResponse>();
  }

  // Fall back to KV (cross-region)
  const raw = await env.VERDICT_CACHE.get(`verdict:${cacheKey}`);
  if (raw) {
    return JSON.parse(raw) as InspectResponse;
  }

  return null;
}

export async function writeLayer1Cache(
  cacheKey: string,
  verdict: InspectResponse,
  ttlSeconds: number,
  env: Env,
): Promise<void> {
  const serialized = JSON.stringify(verdict);

  // Write to Cache API with TTL header
  const cacheUrl = `https://firewall-cache.internal/${cacheKey}`;
  const response = new Response(serialized, {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `max-age=${ttlSeconds}`,
    },
  });
  await caches.default.put(new Request(cacheUrl), response);

  // Also write to KV for cross-region availability
  await env.VERDICT_CACHE.put(`verdict:${cacheKey}`, serialized, {
    expirationTtl: ttlSeconds,
  });
}
