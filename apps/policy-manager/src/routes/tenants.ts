import { Hono } from 'hono';
import { CreateTenantSchema } from '@firewall/shared';
import type { Env } from '../env.js';
import { putTenant, getTenant, listTenants } from '../storage/kv.js';
import { appendAuditLog } from '../storage/r2.js';

const app = new Hono<{ Bindings: Env }>();

app.get('/', async c => {
  const tenants = await listTenants(c.env);
  return c.json(tenants);
});

app.get('/:id', async c => {
  const tenant = await getTenant(c.env, c.req.param('id'));
  if (!tenant) return c.json({ error: 'Not found' }, 404);
  return c.json(tenant);
});

app.post('/', async c => {
  const parsed = CreateTenantSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const tenant = { ...parsed.data, id: crypto.randomUUID(), createdAt: new Date().toISOString() };
  await putTenant(c.env, tenant);
  await appendAuditLog(c.env, { action: 'create', resourceType: 'tenant', resourceId: tenant.id, after: tenant, timestamp: new Date().toISOString() });

  return c.json(tenant, 201);
});

app.delete('/:id', async c => {
  const tenant = await getTenant(c.env, c.req.param('id'));
  if (!tenant) return c.json({ error: 'Not found' }, 404);

  await c.env.TENANTS.delete(`tenant:${c.req.param('id')}`);
  await appendAuditLog(c.env, { action: 'delete', resourceType: 'tenant', resourceId: c.req.param('id'), before: tenant, timestamp: new Date().toISOString() });

  return c.json({ ok: true });
});

export default app;
