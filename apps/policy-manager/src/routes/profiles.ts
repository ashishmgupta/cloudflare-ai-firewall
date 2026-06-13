import { Hono } from 'hono';
import { CreateProfileSchema, UpdateProfileSchema } from '@firewall/shared';
import type { SecurityProfile } from '@firewall/shared';
import { R2_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { syncProfileToKV, deleteProfileFromKV } from '../storage/kv.js';
import { r2GetJson, r2ListKeys, appendAuditLog } from '../storage/r2.js';

const app = new Hono<{ Bindings: Env }>();

app.get('/', async c => {
  const keys = await r2ListKeys(c.env.POLICY_STORE, R2_PREFIX.PROFILES);
  const profiles: SecurityProfile[] = [];
  for (const key of keys) {
    const p = await r2GetJson<SecurityProfile>(c.env.POLICY_STORE, key);
    if (p) profiles.push(p);
  }
  return c.json(profiles);
});

app.get('/:id', async c => {
  const profile = await r2GetJson<SecurityProfile>(
    c.env.POLICY_STORE,
    `${R2_PREFIX.PROFILES}${c.req.param('id')}.json`,
  );
  if (!profile) return c.json({ error: 'Not found' }, 404);
  return c.json(profile);
});

app.post('/', async c => {
  const body = await c.req.json();
  const parsed = CreateProfileSchema.safeParse(body);
  if (!parsed.success) {
    return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);
  }
  const now = new Date().toISOString();
  const profile: SecurityProfile = { ...parsed.data, id: crypto.randomUUID(), createdAt: now, updatedAt: now };
  await syncProfileToKV(c.env, profile);
  await appendAuditLog(c.env, { action: 'create', resourceType: 'profile', resourceId: profile.id, after: profile, timestamp: now });
  return c.json(profile, 201);
});

app.put('/:id', async c => {
  const existing = await r2GetJson<SecurityProfile>(
    c.env.POLICY_STORE,
    `${R2_PREFIX.PROFILES}${c.req.param('id')}.json`,
  );
  if (!existing) return c.json({ error: 'Not found' }, 404);

  const parsed = UpdateProfileSchema.safeParse(await c.req.json());
  if (!parsed.success) {
    return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);
  }
  const updated: SecurityProfile = { ...existing, ...parsed.data, id: existing.id, updatedAt: new Date().toISOString() };
  await syncProfileToKV(c.env, updated);
  await appendAuditLog(c.env, { action: 'update', resourceType: 'profile', resourceId: updated.id, before: existing, after: updated, timestamp: updated.updatedAt });
  return c.json(updated);
});

app.delete('/:id', async c => {
  const id = c.req.param('id');
  const existing = await r2GetJson<SecurityProfile>(c.env.POLICY_STORE, `${R2_PREFIX.PROFILES}${id}.json`);
  if (!existing) return c.json({ error: 'Not found' }, 404);

  await deleteProfileFromKV(c.env, id);
  await appendAuditLog(c.env, { action: 'delete', resourceType: 'profile', resourceId: id, before: existing, after: null, timestamp: new Date().toISOString() });
  return c.json({ ok: true });
});

export default app;
