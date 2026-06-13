CREATE TABLE IF NOT EXISTS events (
  id          TEXT    PRIMARY KEY,
  ts          TEXT    NOT NULL,
  prompt_set  TEXT    NOT NULL,
  prompt_label TEXT   NOT NULL,
  prompt      TEXT    NOT NULL,
  verdict     TEXT    NOT NULL,
  expected    TEXT,
  violations  TEXT    NOT NULL DEFAULT '[]',
  latency_ms  INTEGER NOT NULL DEFAULT 0,
  request_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts      ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_set     ON events (prompt_set);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events (verdict);
