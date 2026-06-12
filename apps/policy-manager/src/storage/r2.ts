import type { Env } from '../env.js';
import { R2_PREFIX } from '@firewall/shared';

export async function r2GetJson<T>(bucket: R2Bucket, key: string): Promise<T | null> {
  const obj = await bucket.get(key);
  if (!obj) return null;
  return obj.json<T>();
}

export async function r2PutJson(bucket: R2Bucket, key: string, value: unknown): Promise<void> {
  await bucket.put(key, JSON.stringify(value), {
    httpMetadata: { contentType: 'application/json' },
  });
}

export async function r2ListKeys(bucket: R2Bucket, prefix: string): Promise<string[]> {
  const list = await bucket.list({ prefix });
  return list.objects.map(o => o.key);
}

export async function r2Delete(bucket: R2Bucket, key: string): Promise<void> {
  await bucket.delete(key);
}

export async function appendAuditLog(env: Env, event: unknown): Promise<void> {
  const now = new Date().toISOString();
  const key = `${R2_PREFIX.AUDIT}${now}-${crypto.randomUUID()}.json`;
  await r2PutJson(env.AUDIT_LOG, key, event);
}
