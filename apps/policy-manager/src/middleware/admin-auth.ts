import type { Context, Next } from 'hono';
import type { Env } from '../env.js';
import { getCookie } from 'hono/cookie';

const COOKIE = 'fw_session';

export async function adminAuth(c: Context<{ Bindings: Env }>, next: Next) {
  const token = getCookie(c, COOKIE) ||
    (c.req.header('Authorization') ?? '').replace(/^Bearer\s+/, '');

  if (!token) return c.json({ error: 'Not authenticated', code: 'UNAUTHENTICATED' }, 401);

  const session = await c.env.DB
    .prepare('SELECT role FROM sessions WHERE token = ? AND expires_at > ?')
    .bind(token, new Date().toISOString())
    .first<{ role: string }>();

  if (!session) return c.json({ error: 'Session expired', code: 'UNAUTHENTICATED' }, 401);
  if (session.role !== 'admin') return c.json({ error: 'Admin access required', code: 'FORBIDDEN' }, 403);

  return next();
}
