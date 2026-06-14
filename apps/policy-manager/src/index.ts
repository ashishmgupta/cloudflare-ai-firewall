import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Env } from './env.js';
import { adminAuth } from './middleware/admin-auth.js';
import { hashPassword, generateToken } from './auth.js';
import profilesRouter from './routes/profiles.js';
import apiKeysRouter from './routes/api-keys.js';
import signaturesRouter from './routes/signatures.js';
import templatesRouter from './routes/templates.js';
import auditRouter from './routes/audit.js';

const COOKIE = 'fw_session';
const SESSION_HOURS = 24;

const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error('[policy-manager] error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

app.get('/', async c => {
  const html = await import('./ui/index.js');
  return c.html(html.default);
});

app.get('/health', c => c.json({ status: 'ok', version: 2 }));

// Public: template listing (no auth — used by UI on load)
app.route('/api/templates', templatesRouter);

// Public: auth endpoints
app.post('/api/auth/login', async c => {
  let body: { username?: string; password?: string } = {};
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }

  const { username, password } = body;
  if (!username?.trim() || !password) {
    return c.json({ error: 'username and password are required' }, 400);
  }

  const user = await c.env.DB
    .prepare('SELECT * FROM users WHERE username = ?')
    .bind(username.trim().toLowerCase())
    .first<{ id: string; username: string; password_hash: string; password_salt: string; role: string }>();

  if (!user) return c.json({ error: 'Invalid credentials' }, 401);

  const hash = await hashPassword(password, user.password_salt);
  if (hash !== user.password_hash) return c.json({ error: 'Invalid credentials' }, 401);

  if (user.role !== 'admin') return c.json({ error: 'Admin access required' }, 403);

  const token = generateToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_HOURS * 3_600_000).toISOString();

  await c.env.DB
    .prepare('INSERT INTO sessions (token,user_id,username,role,expires_at,created_at) VALUES (?,?,?,?,?,?)')
    .bind(token, user.id, user.username, user.role, expiresAt, now.toISOString())
    .run();

  setCookie(c, COOKIE, token, { httpOnly: true, path: '/', sameSite: 'Strict', maxAge: SESSION_HOURS * 3600 });
  return c.json({ id: user.id, username: user.username, role: user.role });
});

app.get('/api/auth/me', async c => {
  const token = getCookie(c, COOKIE) ||
    (c.req.header('Authorization') ?? '').replace(/^Bearer\s+/, '');
  if (!token) return c.json({ error: 'Not authenticated' }, 401);

  const session = await c.env.DB
    .prepare('SELECT user_id, username, role FROM sessions WHERE token = ? AND expires_at > ?')
    .bind(token, new Date().toISOString())
    .first<{ user_id: string; username: string; role: string }>();

  if (!session) return c.json({ error: 'Session expired' }, 401);
  return c.json({ id: session.user_id, username: session.username, role: session.role });
});

app.post('/api/auth/logout', async c => {
  const token = getCookie(c, COOKIE);
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  deleteCookie(c, COOKIE, { path: '/' });
  return c.json({ ok: true });
});

// Admin-only API
const api = new Hono<{ Bindings: Env }>();
api.use('*', adminAuth);
api.route('/profiles', profilesRouter);
api.route('/keys', apiKeysRouter);
api.route('/signatures', signaturesRouter);
api.route('/audit', auditRouter);

app.route('/api', api);

export default app;
