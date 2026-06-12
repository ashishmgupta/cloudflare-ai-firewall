import { Hono } from 'hono';
import { CreatePolicySchema, UpdatePolicySchema } from '@firewall/shared';
import type { Policy } from '@firewall/shared';
import { KV_PREFIX, R2_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { syncPolicyToKV, deletePolicyFromKV } from '../storage/kv.js';
import { r2GetJson, r2ListKeys } from '../storage/r2.js';
import { appendAuditLog } from '../storage/r2.js';

const app = new Hono<{ Bindings: Env }>();

app.get('/', async c => {
  const keys = await r2ListKeys(c.env.POLICY_STORE, R2_PREFIX.POLICY);
  const policies: Policy[] = [];
  for (const key of keys) {
    const p = await r2GetJson<Policy>(c.env.POLICY_STORE, key);
    if (p) policies.push(p);
  }
  return c.json(policies);
});

app.get('/:id', async c => {
  const policy = await r2GetJson<Policy>(c.env.POLICY_STORE, `${R2_PREFIX.POLICY}${c.req.param('id')}.json`);
  if (!policy) return c.json({ error: 'Not found' }, 404);
  return c.json(policy);
});

app.post('/', async c => {
  const body = await c.req.json();
  const parsed = CreatePolicySchema.safeParse(body);
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const now = new Date().toISOString();
  const policy: Policy = {
    ...parsed.data,
    id: crypto.randomUUID(),
    tenantId: body.tenantId ?? 'default',
    createdAt: now,
    updatedAt: now,
  };

  await syncPolicyToKV(c.env, policy);
  await appendAuditLog(c.env, { action: 'create', resourceType: 'policy', resourceId: policy.id, after: policy, timestamp: now });

  return c.json(policy, 201);
});

app.put('/:id', async c => {
  const existing = await r2GetJson<Policy>(c.env.POLICY_STORE, `${R2_PREFIX.POLICY}${c.req.param('id')}.json`);
  if (!existing) return c.json({ error: 'Not found' }, 404);

  const parsed = UpdatePolicySchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const updated: Policy = { ...existing, ...parsed.data, id: existing.id, updatedAt: new Date().toISOString() };
  await syncPolicyToKV(c.env, updated);
  await appendAuditLog(c.env, { action: 'update', resourceType: 'policy', resourceId: updated.id, before: existing, after: updated, timestamp: updated.updatedAt });

  return c.json(updated);
});

app.delete('/:id', async c => {
  const existing = await r2GetJson<Policy>(c.env.POLICY_STORE, `${R2_PREFIX.POLICY}${c.req.param('id')}.json`);
  if (!existing) return c.json({ error: 'Not found' }, 404);

  await Promise.all([
    deletePolicyFromKV(c.env, c.req.param('id')),
    c.env.POLICY_STORE.delete(`${R2_PREFIX.POLICY}${c.req.param('id')}.json`),
  ]);
  await appendAuditLog(c.env, { action: 'delete', resourceType: 'policy', resourceId: c.req.param('id'), before: existing, timestamp: new Date().toISOString() });

  return c.json({ ok: true });
});

export default app;
