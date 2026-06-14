// ── User / session types ──────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  password_hash: string;
  password_salt: string;
  role: 'admin' | 'tester';
  created_at: string;
  updated_at: string;
}

export interface Session {
  token: string;
  user_id: string;
  username: string;
  role: string;
  expires_at: string;
  created_at: string;
}

export async function getUserByUsername(db: D1Database, username: string): Promise<User | null> {
  return db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first<User>();
}

export async function listUsers(db: D1Database): Promise<Omit<User, 'password_hash' | 'password_salt'>[]> {
  const r = await db
    .prepare('SELECT id, username, role, created_at, updated_at FROM users ORDER BY created_at')
    .all<Omit<User, 'password_hash' | 'password_salt'>>();
  return r.results;
}

export async function createUser(db: D1Database, u: Omit<User, 'updated_at'>): Promise<void> {
  await db
    .prepare(
      'INSERT INTO users (id,username,password_hash,password_salt,role,created_at,updated_at) VALUES (?,?,?,?,?,?,?)',
    )
    .bind(u.id, u.username, u.password_hash, u.password_salt, u.role, u.created_at, u.created_at)
    .run();
}

export async function updateUser(
  db: D1Database,
  id: string,
  fields: { role?: 'admin' | 'tester'; password_hash?: string; password_salt?: string },
): Promise<void> {
  const sets: string[] = ['updated_at = ?'];
  const vals: unknown[] = [new Date().toISOString()];
  if (fields.role !== undefined) { sets.push('role = ?'); vals.push(fields.role); }
  if (fields.password_hash !== undefined) { sets.push('password_hash = ?'); vals.push(fields.password_hash); }
  if (fields.password_salt !== undefined) { sets.push('password_salt = ?'); vals.push(fields.password_salt); }
  vals.push(id);
  await db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
}

export async function deleteUser(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
}

export async function countUsers(db: D1Database): Promise<number> {
  const r = await db.prepare('SELECT COUNT(*) as n FROM users').first<{ n: number }>();
  return r?.n ?? 0;
}

export async function createSession(db: D1Database, s: Session): Promise<void> {
  await db
    .prepare(
      'INSERT INTO sessions (token,user_id,username,role,expires_at,created_at) VALUES (?,?,?,?,?,?)',
    )
    .bind(s.token, s.user_id, s.username, s.role, s.expires_at, s.created_at)
    .run();
}

export async function getSession(db: D1Database, token: string): Promise<Session | null> {
  return db
    .prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?')
    .bind(token, new Date().toISOString())
    .first<Session>();
}

export async function deleteSession(db: D1Database, token: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
}

export async function deleteUserSessions(db: D1Database, userId: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
}

// ── Event types ───────────────────────────────────────────────────────────────

export interface EventRow {
  id: string;
  ts: string;
  prompt_set: string;
  prompt_label: string;
  prompt: string;
  verdict: string;
  expected: string | null;
  violations: string;
  latency_ms: number;
  request_id: string | null;
  raw_request: string;
  raw_response: string;
}

export async function insertEvent(db: D1Database, e: EventRow): Promise<void> {
  await db.prepare(
    `INSERT INTO events (id,ts,prompt_set,prompt_label,prompt,verdict,expected,violations,latency_ms,request_id,raw_request,raw_response)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(e.id, e.ts, e.prompt_set, e.prompt_label, e.prompt, e.verdict,
         e.expected ?? null, e.violations, e.latency_ms, e.request_id ?? null,
         e.raw_request, e.raw_response).run();
}

export async function queryEvents(
  db: D1Database,
  { set, verdict, limit, offset }: { set?: string; verdict?: string; limit: number; offset: number },
): Promise<EventRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (set)     { conditions.push('prompt_set = ?'); params.push(set); }
  if (verdict) { conditions.push('verdict = ?');    params.push(verdict); }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(limit, offset);

  const result = await db.prepare(
    `SELECT * FROM events ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
  ).bind(...params).all<EventRow>();

  return result.results;
}

export async function getStats(db: D1Database) {
  const [verdictCounts, setCounts, setLatency, accuracy, total] = await Promise.all([
    db.prepare(`SELECT verdict, COUNT(*) as count FROM events GROUP BY verdict`)
      .all<{ verdict: string; count: number }>(),

    db.prepare(`SELECT prompt_set, verdict, COUNT(*) as count FROM events GROUP BY prompt_set, verdict`)
      .all<{ prompt_set: string; verdict: string; count: number }>(),

    db.prepare(`SELECT prompt_set, ROUND(AVG(latency_ms)) as avg_ms FROM events GROUP BY prompt_set`)
      .all<{ prompt_set: string; avg_ms: number }>(),

    db.prepare(
      `SELECT ROUND(
        COUNT(CASE WHEN verdict = expected THEN 1 END) * 100.0 /
        NULLIF(COUNT(CASE WHEN expected IS NOT NULL THEN 1 END), 0)
       , 1) as pct FROM events`
    ).first<{ pct: number | null }>(),

    db.prepare(`SELECT ROUND(AVG(latency_ms)) as avg_ms FROM events`)
      .first<{ avg_ms: number | null }>(),
  ]);

  return {
    verdictCounts: verdictCounts.results,
    setCounts: setCounts.results,
    setLatency: setLatency.results,
    accuracy: accuracy?.pct ?? 0,
    avgLatencyMs: total?.avg_ms ?? 0,
  };
}

export async function clearEvents(db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM events').run();
}

// ── Inspection profile registry ───────────────────────────────────────────────

export interface InspectKey {
  profile_id: string;
  profile_name: string;
  api_key: string;
  created_at: string;
}

export async function listInspectKeys(
  db: D1Database,
): Promise<Omit<InspectKey, 'api_key'>[]> {
  const r = await db
    .prepare('SELECT profile_id, profile_name, created_at FROM inspect_keys ORDER BY profile_name')
    .all<Omit<InspectKey, 'api_key'>>();
  return r.results;
}

export async function getInspectKey(db: D1Database, profileId: string): Promise<InspectKey | null> {
  return db
    .prepare('SELECT * FROM inspect_keys WHERE profile_id = ?')
    .bind(profileId)
    .first<InspectKey>();
}

export async function upsertInspectKey(db: D1Database, k: InspectKey): Promise<void> {
  await db
    .prepare(
      'INSERT INTO inspect_keys (profile_id,profile_name,api_key,created_at) VALUES (?,?,?,?)' +
      ' ON CONFLICT(profile_id) DO UPDATE SET profile_name=excluded.profile_name, api_key=excluded.api_key',
    )
    .bind(k.profile_id, k.profile_name, k.api_key, k.created_at)
    .run();
}

export async function deleteInspectKey(db: D1Database, profileId: string): Promise<void> {
  await db.prepare('DELETE FROM inspect_keys WHERE profile_id = ?').bind(profileId).run();
}
