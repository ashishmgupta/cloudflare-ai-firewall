import type { Policy, ApiKeyRecord, Tenant } from '@firewall/shared';
import { KV_PREFIX, R2_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { r2PutJson } from './r2.js';

// Push policy to KV (called after every R2 write so firewall-api reads are fast)
export async function syncPolicyToKV(env: Env, policy: Policy): Promise<void> {
  await Promise.all([
    env.POLICY_CACHE.put(`${KV_PREFIX.POLICY}${policy.id}`, JSON.stringify(policy)),
    r2PutJson(env.POLICY_STORE, `${R2_PREFIX.POLICY}${policy.id}.json`, policy),
  ]);
}

export async function deletePolicyFromKV(env: Env, policyId: string): Promise<void> {
  await env.POLICY_CACHE.delete(`${KV_PREFIX.POLICY}${policyId}`);
}

export async function putApiKey(env: Env, record: ApiKeyRecord): Promise<void> {
  await env.API_KEYS.put(`${KV_PREFIX.API_KEY}${record.keyHash}`, JSON.stringify(record));
}

export async function deleteApiKey(env: Env, keyHash: string): Promise<void> {
  await env.API_KEYS.delete(`${KV_PREFIX.API_KEY}${keyHash}`);
}

export async function getApiKeyByHash(env: Env, keyHash: string): Promise<ApiKeyRecord | null> {
  const raw = await env.API_KEYS.get(`${KV_PREFIX.API_KEY}${keyHash}`);
  return raw ? JSON.parse(raw) : null;
}

export async function putTenant(env: Env, tenant: Tenant): Promise<void> {
  await env.TENANTS.put(`${KV_PREFIX.TENANT}${tenant.id}`, JSON.stringify(tenant));
}

export async function getTenant(env: Env, tenantId: string): Promise<Tenant | null> {
  const raw = await env.TENANTS.get(`${KV_PREFIX.TENANT}${tenantId}`);
  return raw ? JSON.parse(raw) : null;
}

export async function listTenants(env: Env): Promise<Tenant[]> {
  const list = await env.TENANTS.list({ prefix: KV_PREFIX.TENANT });
  const tenants: Tenant[] = [];
  for (const key of list.keys) {
    const raw = await env.TENANTS.get(key.name);
    if (raw) tenants.push(JSON.parse(raw));
  }
  return tenants;
}
