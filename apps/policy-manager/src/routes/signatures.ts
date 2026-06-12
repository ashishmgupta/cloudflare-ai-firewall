import { Hono } from 'hono';
import { AddSignatureSchema } from '@firewall/shared';
import type { Env } from '../env.js';
import { r2PutJson, r2ListKeys } from '../storage/r2.js';
import { R2_PREFIX } from '@firewall/shared';

const app = new Hono<{ Bindings: Env }>();

// List all known attack signatures
app.get('/', async c => {
  const keys = await r2ListKeys(c.env.POLICY_STORE, R2_PREFIX.SIGNATURES);
  const sigs = [];
  for (const key of keys) {
    const obj = await c.env.POLICY_STORE.get(key);
    if (obj) sigs.push(await obj.json());
  }
  return c.json(sigs);
});

// Add a new attack signature — embeds and upserts into Vectorize
app.post('/', async c => {
  const parsed = AddSignatureSchema.safeParse(await c.req.json());
  if (!parsed.success) return c.json({ error: 'Validation error', details: parsed.error.flatten() }, 400);

  const { text, category, description, mitreAtlasId } = parsed.data;

  // Embed the attack text
  const embedResult = await c.env.AI.run('@cf/baai/bge-small-en-v1.5', { text: [text] });
  const vector = (embedResult as { data: number[][] }).data[0];
  if (!vector) return c.json({ error: 'Embedding failed' }, 500);

  const id = crypto.randomUUID();

  // Upsert into Vectorize index
  await c.env.FIREWALL_VECTORIZE.upsert([{
    id,
    values: vector,
    metadata: { category, description, mitreAtlasId, text },
  }]);

  // Persist signature record to R2 for management
  const sig = { id, text, category, description, mitreAtlasId, createdAt: new Date().toISOString() };
  await r2PutJson(c.env.POLICY_STORE, `${R2_PREFIX.SIGNATURES}${id}.json`, sig);

  return c.json(sig, 201);
});

// Delete a signature from Vectorize and R2
app.delete('/:id', async c => {
  const sigId = c.req.param('id');
  await Promise.all([
    c.env.FIREWALL_VECTORIZE.deleteByIds([sigId]),
    c.env.POLICY_STORE.delete(`${R2_PREFIX.SIGNATURES}${sigId}.json`),
  ]);
  return c.json({ ok: true });
});

export default app;
