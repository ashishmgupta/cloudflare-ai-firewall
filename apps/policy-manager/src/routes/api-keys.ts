import { Hono } from 'hono';
import { CreateApiKeySchema } from '@firewall/shared';
import type { ApiKeyRecord } from '@firewall/shared';
import { R2_PREFIX } from '@firewall/shared';
import type { Env } from '../env.js';
import { putApiKeyPointer, deleteApiKeyPointer, putApiKeyRecord, deleteApiKeyRecord } from '../storage/kv.js';
import { r2GetJson, r2ListKeys, appendAuditLog } from '../storage/r2.js';

const app = new Hono<{ Bindings: Env }>();

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateRawKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'fw_' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

app.get('/', async c => {
  const keys = await r2ListKeys(c.env.POLICY_STORE, R2_PREFIX.APIKEYS);
  const records: ApiKeyRecord[] = [];
  for (const key of keys) {
    const r = await r2GetJson<ApiKeyRecord>(c.env.POLICY_STORE, key);
    if (r) records.push({ ...r, keyHash: '[redacted]' } as ApiKeyRecord);
  }
  return c.json(records);
});

app.post('/', async c => {
  const parsed = CreateApiKeySchema.safeParse(await c.req.json());
  if (!parsed.success) {
    return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);
  }

  const rawKey = generateRawKey();
  const keyHash = await sha256Hex(rawKey);
  const now = new Date().toISOString();

  const record: ApiKeyRecord = {
    id: crypto.randomUUID(),
    name: parsed.data.name,
    keyHash,
    profileId: parsed.data.profileId,
    active: true,
    createdAt: now,
    revokedAt: null,
  };

  await Promise.all([
    putApiKeyPointer(c.env, keyHash, record.profileId),
    putApiKeyRecord(c.env, record),
  ]);
  await appendAuditLog(c.env, { action: 'create', resourceType: 'api_key', resourceId: record.id, after: { ...record, keyHash: '[redacted]' }, timestamp: now });

  return c.json({ ...record, rawKey }, 201);
});

app.post('/:id/revoke', async c => {
  const record = await findKeyById(c.env, c.req.param('id'));
  if (!record) return c.json({ error: 'Not found' }, 404);

  const updated = { ...record, active: false, revokedAt: new Date().toISOString() };
  await Promise.all([
    deleteApiKeyPointer(c.env, record.keyHash),
    putApiKeyRecord(c.env, updated),
  ]);
  await appendAuditLog(c.env, { action: 'revoke', resourceType: 'api_key', resourceId: record.id, timestamp: updated.revokedAt });

  return c.json({ ok: true });
});

app.post('/:id/rotate', async c => {
  const record = await findKeyById(c.env, c.req.param('id'));
  if (!record) return c.json({ error: 'Not found' }, 404);

  const now = new Date().toISOString();
  const revokedRecord = { ...record, active: false, revokedAt: now };
  await Promise.all([
    deleteApiKeyPointer(c.env, record.keyHash),
    putApiKeyRecord(c.env, revokedRecord),
  ]);

  const newRawKey = generateRawKey();
  const newHash = await sha256Hex(newRawKey);
  const newRecord: ApiKeyRecord = {
    ...record,
    id: crypto.randomUUID(),
    keyHash: newHash,
    active: true,
    createdAt: now,
    revokedAt: null,
  };

  await Promise.all([
    putApiKeyPointer(c.env, newHash, newRecord.profileId),
    putApiKeyRecord(c.env, newRecord),
  ]);
  await appendAuditLog(c.env, { action: 'rotate', resourceType: 'api_key', resourceId: record.id, after: newRecord.id, timestamp: now });

  return c.json({ ...newRecord, rawKey: newRawKey }, 201);
});

app.delete('/:id', async c => {
  const record = await findKeyById(c.env, c.req.param('id'));
  if (!record) return c.json({ error: 'Not found' }, 404);

  await Promise.all([
    deleteApiKeyPointer(c.env, record.keyHash),
    deleteApiKeyRecord(c.env, record.keyHash),
  ]);
  await appendAuditLog(c.env, { action: 'delete', resourceType: 'api_key', resourceId: record.id, timestamp: new Date().toISOString() });

  return c.json({ ok: true });
});

async function findKeyById(env: Env, id: string): Promise<ApiKeyRecord | null> {
  const keys = await r2ListKeys(env.POLICY_STORE, R2_PREFIX.APIKEYS);
  for (const key of keys) {
    const r = await r2GetJson<ApiKeyRecord>(env.POLICY_STORE, key);
    if (r?.id === id) return r;
  }
  return null;
}

export default app;
