import { Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { PROMPT_SETS } from './prompts.js';
import {
  insertEvent, queryEvents, getStats, clearEvents, getAdminStats,
  listEventProfiles, getInspectKeyByApiKey,
  getUserByUsername, listUsers, createUser, updateUser, deleteUser, countUsers,
  createSession, getSession, deleteSession, deleteUserSessions,
  listInspectKeys, getInspectKey, upsertInspectKey, deleteInspectKey,
} from './db.js';
import { hashPassword, generateSalt, generateToken } from './auth.js';
import { getHtml } from './html.js';

interface Env {
  DB: D1Database;
  ADMIN_TOKEN: string;
  FIREWALL_API: Fetcher;
  FIREWALL_API_KEY: string;
  POLICY_MANAGER_URL: string;
}

interface UserCtx {
  id: string;
  username: string;
  role: 'admin' | 'tester';
}

type Vars = { user: UserCtx };
type AppEnv = { Bindings: Env; Variables: Vars };

const app = new Hono<AppEnv>();

const COOKIE = 'fw_session';
const SESSION_HOURS = 24;

// ── UI ─────────────────────────────────────────────────────────────────────────
app.get('/', c => c.html(getHtml()));

// ── Public: static prompt set catalogue ───────────────────────────────────────
app.get('/api/prompt-sets', c =>
  c.json(PROMPT_SETS.map(s => ({ id: s.id, name: s.name, description: s.description, items: s.items }))),
);

// ── Public: login ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', async c => {
  await bootstrapAdmin(c.env);

  let body: { username?: string; password?: string } = {};
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }

  const { username, password } = body;
  if (!username?.trim() || !password) {
    return c.json({ error: 'username and password are required' }, 400);
  }

  const user = await getUserByUsername(c.env.DB, username.trim().toLowerCase());
  if (!user) return c.json({ error: 'Invalid credentials' }, 401);

  const hash = await hashPassword(password, user.password_salt);
  if (hash !== user.password_hash) return c.json({ error: 'Invalid credentials' }, 401);

  const token = generateToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_HOURS * 3_600_000).toISOString();

  await createSession(c.env.DB, {
    token,
    user_id: user.id,
    username: user.username,
    role: user.role,
    expires_at: expiresAt,
    created_at: now.toISOString(),
  });

  setCookie(c, COOKIE, token, {
    httpOnly: true,
    path: '/',
    sameSite: 'Strict',
    maxAge: SESSION_HOURS * 3600,
  });

  return c.json({ id: user.id, username: user.username, role: user.role });
});


// ── Session middleware: all /api/* routes registered AFTER this require auth ──
app.use('/api/*', async (c, next) => {
  const token = getCookie(c, COOKIE) ||
    (c.req.header('Authorization') ?? '').replace(/^Bearer\s+/, '');

  if (!token) return c.json({ error: 'Not authenticated', code: 'UNAUTHENTICATED' }, 401);

  const session = await getSession(c.env.DB, token);
  if (!session) return c.json({ error: 'Session expired', code: 'UNAUTHENTICATED' }, 401);

  c.set('user', { id: session.user_id, username: session.username, role: session.role as 'admin' | 'tester' });
  await next();
});

// ── Auth: me + logout ──────────────────────────────────────────────────────────
app.get('/api/auth/me', c => c.json(c.get('user')));

app.post('/api/auth/logout', async c => {
  const token = getCookie(c, COOKIE);
  if (token) await deleteSession(c.env.DB, token);
  deleteCookie(c, COOKIE, { path: '/' });
  return c.json({ ok: true });
});

// ── Admin guard helper ─────────────────────────────────────────────────────────
const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (c.get('user')?.role !== 'admin') {
    return c.json({ error: 'Admin access required', code: 'FORBIDDEN' }, 403);
  }
  await next();
};

// ── User management (admin only) ───────────────────────────────────────────────
app.get('/api/users', requireAdmin, async c => c.json(await listUsers(c.env.DB)));

app.post('/api/users', requireAdmin, async c => {
  const { username, password, role } = await c.req.json<{
    username: string; password: string; role: string;
  }>();
  if (!username?.trim() || !password || !['admin', 'tester'].includes(role)) {
    return c.json({ error: 'username, password, and role (admin|tester) are required' }, 400);
  }
  const salt = generateSalt();
  const now = new Date().toISOString();
  try {
    await createUser(c.env.DB, {
      id: crypto.randomUUID(),
      username: username.trim().toLowerCase(),
      password_hash: await hashPassword(password, salt),
      password_salt: salt,
      role: role as 'admin' | 'tester',
      created_at: now,
    });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return c.json({ error: 'Username already taken' }, 409);
    throw e;
  }
  return c.json({ ok: true }, 201);
});

app.put('/api/users/:id/role', requireAdmin, async c => {
  const { role } = await c.req.json<{ role: string }>();
  if (!['admin', 'tester'].includes(role)) return c.json({ error: 'Invalid role' }, 400);
  await updateUser(c.env.DB, c.req.param('id'), { role: role as 'admin' | 'tester' });
  return c.json({ ok: true });
});

app.put('/api/users/:id/password', requireAdmin, async c => {
  const { password } = await c.req.json<{ password: string }>();
  if (!password) return c.json({ error: 'password is required' }, 400);
  const salt = generateSalt();
  const hash = await hashPassword(password, salt);
  const id = c.req.param('id');
  await updateUser(c.env.DB, id, { password_hash: hash, password_salt: salt });
  await deleteUserSessions(c.env.DB, id);
  return c.json({ ok: true });
});

app.delete('/api/users/:id', requireAdmin, async c => {
  const id = c.req.param('id');
  if (c.get('user').id === id) return c.json({ error: 'Cannot delete your own account' }, 400);
  await deleteUserSessions(c.env.DB, id);
  await deleteUser(c.env.DB, id);
  return c.json({ ok: true });
});

// ── Ad-hoc inspect (auth required — uses per-profile API key from inspect_keys) ──
app.post('/api/adhoc', async c => {
  const { prompt, profileId } = await c.req.json<{ prompt: string; profileId: string }>();
  if (!prompt || !profileId) return c.json({ error: 'prompt and profileId are required' }, 400);

  const inspectKey = await getInspectKey(c.env.DB, profileId);
  if (!inspectKey) return c.json({ error: 'No API key registered for this profile. Ask an admin to add one in the Users tab.', code: 'PROFILE_NOT_FOUND' }, 404);

  const requestBody = JSON.stringify({ messages: [{ role: 'user', content: prompt }] });
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-API-Key': '[redacted]',
  };
  const t0 = Date.now();

  const res = await c.env.FIREWALL_API.fetch('https://firewall-api/v1/inspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': inspectKey.api_key },
    body: requestBody,
  });

  const responseBody = await res.text();
  const wallMs = Date.now() - t0;

  const responseHeaders: Record<string, string> = {};
  res.headers.forEach((value, key) => { responseHeaders[key] = value; });

  let parsed: Record<string, unknown> = {};
  try { parsed = JSON.parse(responseBody); } catch { /* malformed */ }

  // Reconstruct latencyMs from headers — body no longer carries it.
  // Cached responses only emit X-Firewall-Latency-Ms (the cache-hit cost).
  // Non-cached responses also emit X-Firewall-Layer{n}-Ms for each layer that ran.
  const isCached = responseHeaders['x-firewall-cached'] === 'true';
  const totalMs = parseInt(responseHeaders['x-firewall-latency-ms'] || '0') || wallMs;
  const perLayer: Record<string, number> = {};
  if (!isCached) {
    for (const [k, v] of Object.entries(responseHeaders)) {
      const m = k.match(/^x-firewall-(layer\d+)-ms$/);
      if (m) perLayer[m[1]] = parseInt(v);
    }
  }

  return c.json({
    status: res.status,
    statusText: res.statusText,
    requestMethod: 'POST',
    requestUrl: 'https://firewall-api/v1/inspect',
    requestHeaders,
    requestBody,
    responseHeaders,
    responseBody,
    verdict: parsed.verdict as string | undefined,
    violations: (parsed.violations as unknown[]) ?? [],
    latencyMs: { total: totalMs, perLayer },
    requestId: parsed.requestId as string | undefined,
    cached: isCached,
    wallMs,
    error: parsed.error as string | undefined,
    code: parsed.code as string | undefined,
    profileName: inspectKey.profile_name,
  });
});

// ── Inspect profiles — only profiles with a registered API key ─────────────────
app.get('/api/inspect-profiles', async c =>
  c.json(await listInspectKeys(c.env.DB)),
);

// ── Cache purge — admin only, proxies DELETE /v1/cache to firewall-api ────────
app.delete('/api/cache', requireAdmin, async c => {
  const res = await c.env.FIREWALL_API.fetch('https://firewall-api/v1/cache', {
    method: 'DELETE',
    headers: { 'X-API-Key': c.env.FIREWALL_API_KEY },
  });
  const data = await res.json();
  return c.json(data, res.status as 200);
});

// ── L3 system prompt — proxies to firewall-api (no auth: static public info) ──
app.get('/api/l3-prompt', async c => {
  const res = await c.env.FIREWALL_API.fetch('https://firewall-api/v1/debug/l3-prompt');
  const data = await res.json();
  return c.json(data, res.status as 200);
});

// ── Inspect profile details — proxies to firewall-api /v1/profile-info ────────
app.get('/api/inspect-profiles/:profileId/details', async c => {
  const inspectKey = await getInspectKey(c.env.DB, c.req.param('profileId'));
  if (!inspectKey) return c.json({ error: 'Profile not found' }, 404);
  const res = await c.env.FIREWALL_API.fetch('https://firewall-api/v1/profile-info', {
    headers: { 'X-API-Key': inspectKey.api_key },
  });
  const data = await res.json();
  return c.json(data, res.status as 200);
});

// ── Inspect key management (admin only) ────────────────────────────────────────
app.get('/api/inspect-keys', requireAdmin, async c =>
  c.json(await listInspectKeys(c.env.DB)),
);

app.post('/api/inspect-keys', requireAdmin, async c => {
  const body = await c.req.json<{ profile_id?: string; profile_name?: string; api_key?: string }>();
  const { profile_id, profile_name, api_key } = body;
  if (!profile_id?.trim() || !profile_name?.trim() || !api_key?.trim()) {
    return c.json({ error: 'profile_id, profile_name, and api_key are required' }, 400);
  }
  await upsertInspectKey(c.env.DB, {
    profile_id: profile_id.trim(),
    profile_name: profile_name.trim(),
    api_key: api_key.trim(),
    created_at: new Date().toISOString(),
  });
  return c.json({ ok: true }, 201);
});

app.delete('/api/inspect-keys/:profileId', requireAdmin, async c => {
  await deleteInspectKey(c.env.DB, c.req.param('profileId'));
  return c.json({ ok: true });
});

// ── Run an entire prompt set ───────────────────────────────────────────────────
app.post('/api/run-set', async c => {
  const { setId } = await c.req.json<{ setId: string }>();
  const set = PROMPT_SETS.find(s => s.id === setId);
  if (!set) return c.json({ error: 'Unknown set id' }, 404);

  const sessionUser = c.get('user');
  const ip = c.req.header('CF-Connecting-IP')
    ?? c.req.header('X-Forwarded-For')?.split(',')[0]?.trim()
    ?? null;
  const cf = c.req.raw.cf as { country?: string; city?: string } | undefined;
  const userCtx = {
    username:   sessionUser?.username ?? null,
    ip_address: ip,
    country:    cf?.country ?? null,
    city:       cf?.city    ?? null,
  };

  const inspectKey = await getInspectKeyByApiKey(c.env.DB, c.env.FIREWALL_API_KEY);
  const profileName = inspectKey?.profile_name ?? null;

  const results = await Promise.allSettled(
    set.items.map(item => runAndStore(item.prompt, setId, item.label, item.expected, c.env, userCtx, profileName)),
  );

  const mapped = await Promise.all(results.map(async (r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const errMsg = String(r.reason);
    console.error(`[run-set] prompt "${set.items[i].label}" failed: ${errMsg}`);
    try {
      await insertEvent(c.env.DB, {
        id: crypto.randomUUID(),
        ts: new Date().toISOString(),
        prompt_set: setId,
        prompt_label: set.items[i].label,
        prompt: set.items[i].prompt,
        verdict: 'error',
        expected: set.items[i].expected,
        violations: '[]',
        latency_ms: 0,
        request_id: null,
        raw_request: JSON.stringify({ messages: [{ role: 'user', content: set.items[i].prompt }] }),
        raw_response: JSON.stringify({ error: errMsg }),
        ...userCtx,
        profile_name: profileName,
      });
    } catch (dbErr) {
      console.error('[run-set] D1 insert failed:', String(dbErr));
    }
    return {
      label: set.items[i].label,
      prompt: set.items[i].prompt,
      expected: set.items[i].expected,
      verdict: 'error',
      violations: [],
      latencyMs: 0,
      pass: false,
      error: errMsg,
    };
  }));

  return c.json({
    setId,
    results: mapped,
    summary: { total: mapped.length, passed: mapped.filter(r => r.pass).length },
  });
});

// ── Events ─────────────────────────────────────────────────────────────────────
app.get('/api/events', async c => {
  const { set, verdict, profile, limit = '100', offset = '0' } = c.req.query();
  const rows = await queryEvents(c.env.DB, {
    set: set || undefined,
    verdict: verdict || undefined,
    profile: profile || undefined,
    limit: Number(limit),
    offset: Number(offset),
  });
  return c.json(rows);
});

app.get('/api/events-profiles', async c => {
  const profiles = await listEventProfiles(c.env.DB);
  return c.json(profiles);
});

app.delete('/api/events', async c => {
  await clearEvents(c.env.DB);
  return c.json({ ok: true });
});

// ── Stats ──────────────────────────────────────────────────────────────────────
app.get('/api/stats', async c => c.json(await getStats(c.env.DB)));

// ── Admin stats (per-user + per-location breakdown) ────────────────────────────
app.get('/api/admin/stats', requireAdmin, async c => c.json(await getAdminStats(c.env.DB)));

// ── Bootstrap default admin from ADMIN_TOKEN ───────────────────────────────────
async function bootstrapAdmin(env: Env): Promise<void> {
  if ((await countUsers(env.DB)) > 0) return;
  const salt = generateSalt();
  const now = new Date().toISOString();
  await createUser(env.DB, {
    id: crypto.randomUUID(),
    username: 'admin',
    password_hash: await hashPassword(env.ADMIN_TOKEN, salt),
    password_salt: salt,
    role: 'admin',
    created_at: now,
  });
}

// ── Internal: run one prompt, store result ─────────────────────────────────────
async function runAndStore(
  prompt: string,
  promptSet: string,
  promptLabel: string,
  expected: string,
  env: Env,
  userCtx: { username: string | null; ip_address: string | null; country: string | null; city: string | null },
  profileName: string | null = null,
) {
  const requestBody = JSON.stringify({ messages: [{ role: 'user', content: prompt }] });
  const requestHeaders = { 'Content-Type': 'application/json', 'X-API-Key': '[redacted]' };
  const t0 = Date.now();

  const res = await env.FIREWALL_API.fetch('https://firewall-api/v1/inspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': env.FIREWALL_API_KEY },
    body: requestBody,
  });

  const responseBodyText = await res.text();
  const responseHeaders: Record<string, string> = {};
  res.headers.forEach((value, key) => { responseHeaders[key] = value; });

  if (res.status !== 200 && res.status !== 403) {
    throw new Error(`HTTP ${res.status}: ${responseBodyText}`);
  }

  const data = JSON.parse(responseBodyText) as {
    verdict: string;
    violations: unknown[];
    requestId?: string;
  };

  const latencyMs = parseInt(responseHeaders['x-firewall-latency-ms'] || '0') || (Date.now() - t0);

  await insertEvent(env.DB, {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    prompt_set: promptSet,
    prompt_label: promptLabel,
    prompt,
    verdict: data.verdict,
    expected,
    violations: JSON.stringify(data.violations ?? []),
    latency_ms: latencyMs,
    request_id: data.requestId ?? null,
    raw_request: JSON.stringify({
      method: 'POST',
      url: 'https://firewall-api/v1/inspect',
      headers: requestHeaders,
      body: { messages: [{ role: 'user', content: prompt }] },
    }),
    raw_response: JSON.stringify({
      status: res.status,
      statusText: res.statusText,
      headers: responseHeaders,
      body: data,
    }),
    ...userCtx,
    profile_name: profileName,
  });

  return {
    label: promptLabel,
    prompt,
    expected,
    verdict: data.verdict,
    violations: data.violations ?? [],
    latencyMs,
    pass: data.verdict === expected,
  };
}

export default app;
