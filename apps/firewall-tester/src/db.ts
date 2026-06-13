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
