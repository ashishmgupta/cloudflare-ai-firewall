import type { Context, Next } from 'hono';
import type { Env } from '../env.js';

export async function adminAuth(c: Context<{ Bindings: Env }>, next: Next) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!token || token !== c.env.ADMIN_TOKEN) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return next();
}
