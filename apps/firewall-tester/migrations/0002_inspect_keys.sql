CREATE TABLE IF NOT EXISTS inspect_keys (
  profile_id   TEXT PRIMARY KEY,
  profile_name TEXT NOT NULL,
  api_key      TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
