import type { SecurityProfile, ApiKeyRecord } from '@firewall/shared';
import { KV_PROFILE_PREFIX, R2_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { r2PutJson } from './r2.js';

// Write profile to both R2 (durable) and KV (fast reads for firewall-api)
export async function syncProfileToKV(env: Env, profile: SecurityProfile): Promise<void> {
  const profileJson = JSON.stringify(profile);
  await Promise.all([
    // R2: authoritative copy
    r2PutJson(env.POLICY_STORE, `${R2_PREFIX.PROFILES}${profile.id}.json`, profile),
    // KV: profileId → full document
    env.POLICY_CACHE.put(`${KV_PROFILE_PREFIX}${profile.id}`, profileJson),
  ]);
}

export async function deleteProfileFromKV(env: Env, profileId: string): Promise<void> {
  await Promise.all([
    env.POLICY_CACHE.delete(`${KV_PROFILE_PREFIX}${profileId}`),
    env.POLICY_STORE.delete(`${R2_PREFIX.PROFILES}${profileId}.json`),
  ]);
}

// API key KV pointer: keyHash → { profileId }
export async function putApiKeyPointer(env: Env, keyHash: string, profileId: string): Promise<void> {
  await env.POLICY_CACHE.put(`${KV_PROFILE_PREFIX}${keyHash}`, JSON.stringify({ profileId }));
}

export async function deleteApiKeyPointer(env: Env, keyHash: string): Promise<void> {
  await env.POLICY_CACHE.delete(`${KV_PROFILE_PREFIX}${keyHash}`);
}

// Full ApiKeyRecord lives in R2 only (not needed on the hot request path)
export async function putApiKeyRecord(env: Env, record: ApiKeyRecord): Promise<void> {
  await r2PutJson(env.POLICY_STORE, `${R2_PREFIX.APIKEYS}${record.keyHash}.json`, record);
}

export async function deleteApiKeyRecord(env: Env, keyHash: string): Promise<void> {
  await env.POLICY_STORE.delete(`${R2_PREFIX.APIKEYS}${keyHash}.json`);
}
