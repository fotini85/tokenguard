CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT        NOT NULL,
    password_hash BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique on the normalised form, matching what ByEmail compares.
CREATE UNIQUE INDEX users_email_key ON users (lower(email));

CREATE TABLE sessions (
    id           TEXT        PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_hash BYTEA       NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);

-- Refresh lookup goes through this on every rotation.
CREATE UNIQUE INDEX sessions_refresh_hash_key ON sessions (refresh_hash);

-- RevokeAllForUser matches on user_id AND revoked_at IS NULL, so the
-- index carries the same condition and holds only live sessions.
CREATE INDEX sessions_user_live ON sessions (user_id) WHERE revoked_at IS NULL;