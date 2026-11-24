-- Optional dares feature. Safe to re-run.
ALTER TABLE groups ADD COLUMN IF NOT EXISTS dares_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS dares (
  id SERIAL PRIMARY KEY,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  from_member_id INTEGER NOT NULL REFERENCES group_members(id) ON DELETE CASCADE,
  to_member_id INTEGER NOT NULL REFERENCES group_members(id) ON DELETE CASCADE,
  text VARCHAR(280) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  seen_at TIMESTAMPTZ,
  done_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dares_to ON dares (to_member_id);
CREATE INDEX IF NOT EXISTS idx_dares_from ON dares (from_member_id, created_at);
