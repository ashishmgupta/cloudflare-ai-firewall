-- Add run grouping to events
ALTER TABLE events ADD COLUMN run_id TEXT;
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);

-- Run history: one row per prompt set execution
CREATE TABLE IF NOT EXISTS runs (
  id              TEXT PRIMARY KEY,
  ts              TEXT NOT NULL,
  prompt_set_id   TEXT NOT NULL,
  prompt_set_name TEXT NOT NULL,
  profile_id      TEXT,
  profile_name    TEXT,
  username        TEXT,
  total_prompts   INTEGER NOT NULL DEFAULT 0,
  blocked         INTEGER NOT NULL DEFAULT 0,
  monitored       INTEGER NOT NULL DEFAULT 0,
  passed          INTEGER NOT NULL DEFAULT 0,
  avg_latency_ms  REAL    NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_runs_ts ON runs(ts DESC);
