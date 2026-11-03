-- Quick unlock with a passkey of the device (Windows Hello, Touch ID …)
-- through the WebAuthn PRF extension. The server keeps only the account key
-- sealed under a key that never leaves the authenticator.
CREATE TABLE unlock_keys (
    id           text PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    salt         text NOT NULL,
    wrapped      text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX unlock_keys_user ON unlock_keys (user_id);
