-- v2 schema. WARNING: drops all existing tables (including v1 data).
DROP TABLE IF EXISTS dares CASCADE;
DROP TABLE IF EXISTS group_members CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS session CASCADE;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  invite_code VARCHAR(8) UNIQUE NOT NULL,
  admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  drawn_at TIMESTAMPTZ,
  dares_enabled BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
  id SERIAL PRIMARY KEY,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  display_name VARCHAR(50) NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  assigned_child TEXT, -- encrypted member id of the child
  revealed_at TIMESTAMPTZ,
  UNIQUE (group_id, display_name),
  UNIQUE (group_id, user_id)
);

CREATE TABLE dares (
  id SERIAL PRIMARY KEY,
  group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  from_member_id INTEGER NOT NULL REFERENCES group_members(id) ON DELETE CASCADE,
  to_member_id INTEGER NOT NULL REFERENCES group_members(id) ON DELETE CASCADE,
  text VARCHAR(280) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  seen_at TIMESTAMPTZ,
  done_at TIMESTAMPTZ
);
CREATE INDEX idx_dares_to ON dares (to_member_id);
CREATE INDEX idx_dares_from ON dares (from_member_id, created_at);

-- connect-pg-simple session store
CREATE TABLE session (
  sid VARCHAR NOT NULL PRIMARY KEY,
  sess JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IDX_session_expire ON session (expire);
