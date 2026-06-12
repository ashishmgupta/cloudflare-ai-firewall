import { Hono } from 'hono';
import type { Env } from '../env.js';
import { R2_PREFIX } from '@firewall/shared';

const app = new Hono<{ Bindings: Env }>();

app.get('/', async c => {
  const limit = Number(c.req.query('limit') ?? '50');
  const list = await c.env.AUDIT_LOG.list({ prefix: R2_PREFIX.AUDIT, limit: Math.min(limit, 200) });

  const events = [];
  // Return most recent first
  const sorted = [...list.objects].sort((a, b) => b.key.localeCompare(a.key));
  for (const obj of sorted) {
    const raw = await c.env.AUDIT_LOG.get(obj.key);
    if (raw) events.push(await raw.json());
  }

  return c.json(events);
});

export default app;
