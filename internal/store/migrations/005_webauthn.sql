-- Security keys and passkeys as a second factor (WebAuthn). Only public
-- keys are stored.
CREATE TABLE webauthn_credentials (
    id           text PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    public_key   bytea NOT NULL,
    alg          int NOT NULL,
    sign_count   bigint NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX webauthn_user ON webauthn_credentials (user_id);
