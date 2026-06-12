import { Hono } from 'hono';
import { CreateApiKeySchema } from '@firewall/shared';
import type { ApiKeyRecord } from '@firewall/shared';
import type { Env } from '../env.js';
import { putApiKey, deleteApiKey, getApiKeyByHash } from '../storage/kv.js';
import { appendAuditLog } from '../storage/r2.js';

const app = new Hono<{ Bindings: Env }>();

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateRawKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'fw_' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// List all API key records for a tenant
app.get('/tenant/:tenantId', async c => {
  const list = await c.env.API_KEYS.list({ prefix: 'apikey:' });
  const records: ApiKeyRecord[] = [];
  for (const key of list.keys) {
    const raw = await c.env.API_KEYS.get(key.name);
    if (raw) {
      const rec = JSON.parse(raw) as ApiKeyRecord;
      if (rec.tenantId === c.req.param('tenantId')) records.push(rec);
    }
  }
  return c.json(records);
});

// Create a new API key — raw key returned ONCE
app.post('/', async c => {
  const parsed = CreateApiKeySchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const rawKey = generateRawKey();
  const keyHash = await sha256Hex(rawKey);

  const record: ApiKeyRecord = {
    id: crypto.randomUUID(),
    keyHash,
    tenantId: parsed.data.tenantId,
    name: parsed.data.name,
    policyIds: parsed.data.policyIds,
    defaultPolicyId: parsed.data.defaultPolicyId,
    active: true,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };

  await putApiKey(c.env, record);
  await appendAuditLog(c.env, { action: 'create', resourceType: 'api_key', resourceId: record.id, after: { ...record, keyHash: '[redacted]' }, timestamp: new Date().toISOString() });

  return c.json({ ...record, rawKey }, 201);
});

// Revoke (deactivate) a key by its ID
app.post('/:id/revoke', async c => {
  const list = await c.env.API_KEYS.list({ prefix: 'apikey:' });
  for (const key of list.keys) {
    const raw = await c.env.API_KEYS.get(key.name);
    if (!raw) continue;
    const rec = JSON.parse(raw) as ApiKeyRecord;
    if (rec.id !== c.req.param('id')) continue;

    const updated = { ...rec, active: false };
    await putApiKey(c.env, updated);
    await appendAuditLog(c.env, { action: 'revoke', resourceType: 'api_key', resourceId: rec.id, timestamp: new Date().toISOString() });

    return c.json({ ok: true });
  }
  return c.json({ error: 'Not found' }, 404);
});

// Rotate — revoke old, issue new
app.post('/:id/rotate', async c => {
  const list = await c.env.API_KEYS.list({ prefix: 'apikey:' });
  for (const key of list.keys) {
    const raw = await c.env.API_KEYS.get(key.name);
    if (!raw) continue;
    const rec = JSON.parse(raw) as ApiKeyRecord;
    if (rec.id !== c.req.param('id')) continue;

    // Revoke old
    await putApiKey(c.env, { ...rec, active: false });

    // Issue new
    const newRawKey = generateRawKey();
    const newHash = await sha256Hex(newRawKey);
    const newRecord: ApiKeyRecord = {
      ...rec,
      id: crypto.randomUUID(),
      keyHash: newHash,
      active: true,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    };
    await putApiKey(c.env, newRecord);
    await appendAuditLog(c.env, { action: 'rotate', resourceType: 'api_key', resourceId: rec.id, after: newRecord.id, timestamp: new Date().toISOString() });

    return c.json({ ...newRecord, rawKey: newRawKey }, 201);
  }
  return c.json({ error: 'Not found' }, 404);
});

// Delete permanently
app.delete('/:id', async c => {
  const list = await c.env.API_KEYS.list({ prefix: 'apikey:' });
  for (const key of list.keys) {
    const raw = await c.env.API_KEYS.get(key.name);
    if (!raw) continue;
    const rec = JSON.parse(raw) as ApiKeyRecord;
    if (rec.id !== c.req.param('id')) continue;

    await deleteApiKey(c.env, rec.keyHash);
    await appendAuditLog(c.env, { action: 'delete', resourceType: 'api_key', resourceId: rec.id, timestamp: new Date().toISOString() });
    return c.json({ ok: true });
  }
  return c.json({ error: 'Not found' }, 404);
});

export default app;
