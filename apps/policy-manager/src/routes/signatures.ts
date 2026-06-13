import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../env.js';
import { r2PutJson, r2ListKeys } from '../storage/r2.js';
import { R2_PREFIX } from '@firewall/shared';

const AddSignatureSchema = z.object({
  text: z.string().min(1),
  category: z.string().min(1),
  description: z.string().default(''),
  mitreAtlasId: z.string().default('AML.T0051'),
});

const app = new Hono<{ Bindings: Env }>();

app.get('/', async c => {
  const keys = await r2ListKeys(c.env.POLICY_STORE, R2_PREFIX.SIGNATURES);
  const sigs = [];
  for (const key of keys) {
    const obj = await c.env.POLICY_STORE.get(key);
    if (obj) sigs.push(await obj.json());
  }
  return c.json(sigs);
});

app.post('/', async c => {
  if (!c.env.FIREWALL_VECTORIZE) {
    return c.json({ error: 'Vectorize not configured (requires Workers Paid plan)' }, 503);
  }
  const parsed = AddSignatureSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const { text, category, description, mitreAtlasId } = parsed.data;
  const embedResult = await c.env.AI.run('@cf/baai/bge-small-en-v1.5', { text: [text] });
  const vector = (embedResult as { data: number[][] }).data[0];
  if (!vector) return c.json({ error: 'Embedding failed' }, 500);

  const id = crypto.randomUUID();
  await c.env.FIREWALL_VECTORIZE.upsert([{ id, values: vector, metadata: { category, description, mitreAtlasId, text } }]);

  const sig = { id, text, category, description, mitreAtlasId, createdAt: new Date().toISOString() };
  await r2PutJson(c.env.POLICY_STORE, `${R2_PREFIX.SIGNATURES}${id}.json`, sig);
  return c.json(sig, 201);
});

app.delete('/:id', async c => {
  if (!c.env.FIREWALL_VECTORIZE) {
    return c.json({ error: 'Vectorize not configured' }, 503);
  }
  const sigId = c.req.param('id');
  await Promise.all([
    c.env.FIREWALL_VECTORIZE.deleteByIds([sigId]),
    c.env.POLICY_STORE.delete(`${R2_PREFIX.SIGNATURES}${sigId}.json`),
  ]);
  return c.json({ ok: true });
});

export default app;
