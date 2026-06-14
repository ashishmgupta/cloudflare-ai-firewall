CREATE TABLE IF NOT EXISTS users (
  id            TEXT    PRIMARY KEY,
  username      TEXT    UNIQUE NOT NULL,
  password_hash TEXT    NOT NULL,
  password_salt TEXT    NOT NULL,
  role          TEXT    NOT NULL CHECK(role IN ('admin', 'tester')) DEFAULT 'tester',
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  username    TEXT NOT NULL,
  role        TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
