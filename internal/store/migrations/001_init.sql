CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);

-- Revisions of vault data: every change takes the next number, clients
-- sync what changed since the last number they saw.
CREATE SEQUENCE revisions;

-- Accounts. The server never sees the master password or any key in plain
-- form: auth_hash is an argon2id hash of the auth key the client derives
-- from the master password; the account key and the private key are stored
-- only wrapped (AES-256-GCM) by keys the server does not have.
CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    email                text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    role                 text NOT NULL CHECK (role IN ('admin', 'user')),
    disabled             boolean NOT NULL DEFAULT false,
    lang                 text NOT NULL DEFAULT '',
    prefs                jsonb NOT NULL DEFAULT '{}',
    kdf                  jsonb NOT NULL,
    salt                 text NOT NULL,
    auth_hash            text NOT NULL,
    wrapped_account_key  text NOT NULL,
    public_key           text NOT NULL,
    wrapped_private_key  text NOT NULL,
    recovery_auth_hash   text NOT NULL DEFAULT '',
    recovery_wrapped_key text NOT NULL DEFAULT '',
    totp_secret          text NOT NULL DEFAULT '',
    totp_enabled         boolean NOT NULL DEFAULT false,
    totp_last_step       bigint NOT NULL DEFAULT 0,
    recovery_codes       text[] NOT NULL DEFAULT '{}',
    revision             bigint NOT NULL DEFAULT nextval('revisions'),
    created_at           timestamptz NOT NULL DEFAULT now(),
    password_changed_at  timestamptz NOT NULL DEFAULT now(),
    last_login_at        timestamptz
);
CREATE UNIQUE INDEX users_email ON users (lower(email));

-- Sign-in sessions; only the SHA-256 of the cookie value is stored.
-- stage 'mfa' is a sign-in waiting for the second factor. unlock_key
-- (sealed with the server key) lets the browser keep its unlocked keys
-- encrypted in its session storage; locking replaces it.
CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage      text NOT NULL CHECK (stage IN ('mfa', 'full')),
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    unlock_key text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Invitations: the only way to get an account (besides the first-run setup).
CREATE TABLE invites (
    id         bigserial PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    email      text NOT NULL,
    role       text NOT NULL CHECK (role IN ('admin', 'user')),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

-- Addresses blocked after failed sign-ins.
CREATE TABLE login_blocks (
    ip         text PRIMARY KEY,
    until      timestamptz NOT NULL,
    strikes    int NOT NULL,
    reason     text NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Append-only, hash-chained audit log: hash = SHA-256(prev_hash, fields).
CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL,
    username  text NOT NULL,
    ip        text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    detail    text NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL
);

-- Vaults. Ids are made by the clients (they are part of the encryption).
-- Every user has one personal vault; shared vaults come later.
CREATE TABLE vaults (
    id         uuid PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('personal', 'shared')),
    owner_id   bigint REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX vaults_personal ON vaults (owner_id) WHERE kind = 'personal';

-- Who may open a vault: the vault key wrapped for that member.
CREATE TABLE vault_members (
    vault_id    uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key text NOT NULL,
    rights      text NOT NULL DEFAULT 'manage' CHECK (rights IN ('use', 'view', 'edit', 'manage')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_members_user ON vault_members (user_id);

-- Items: data is one sealed JSON document (type, name, URLs, user name,
-- password, notes, folder …) — the server sees only ids, sizes and times.
CREATE TABLE items (
    id         uuid PRIMARY KEY,
    vault_id   uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    data       text NOT NULL,
    revision   bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz
);
CREATE INDEX items_vault ON items (vault_id, revision);

-- Folders are personal (sealed name under the account key).
CREATE TABLE folders (
    id         uuid PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data       text NOT NULL,
    revision   bigint NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX folders_user ON folders (user_id, revision);

-- Removed items and folders are remembered for a while, so other devices
-- learn about the removal at their next sync.
CREATE TABLE tombstones (
    id       uuid PRIMARY KEY,
    kind     text NOT NULL CHECK (kind IN ('item', 'folder')),
    user_id  bigint,
    vault_id uuid,
    revision bigint NOT NULL,
    at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tombstones_rev ON tombstones (revision);
