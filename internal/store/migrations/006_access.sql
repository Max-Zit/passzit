-- Secret links (Send): a text or file sealed in the browser with a key
-- that travels only in the link's #fragment. The server keeps the sealed
-- bytes, the end, the number of opens and, with a password, an argon2id
-- hash of a value derived from it (the content key needs it too).
CREATE TABLE sends (
    id          text PRIMARY KEY,
    owner_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data        bytea NOT NULL,
    auth_hash   text NOT NULL DEFAULT '',
    max_views   int NOT NULL,
    views       int NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_viewed timestamptz
);
CREATE INDEX sends_owner ON sends (owner_id);

-- Emergency access: the grantor's account key sealed to a trusted user's
-- public key, released by the server only after a request and the waiting
-- time (or the grantor's approval).
CREATE TABLE emergency_contacts (
    id           bigserial PRIMARY KEY,
    grantor_id   bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id   bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_key   text NOT NULL,
    wait_days    int NOT NULL CHECK (wait_days BETWEEN 0 AND 90),
    requested_at timestamptz,
    approved_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (grantor_id, grantee_id)
);

-- Who used an item of a shared vault (reported by the clients).
CREATE TABLE item_access (
    id       bigserial PRIMARY KEY,
    item_id  uuid NOT NULL,
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id  bigint REFERENCES users(id) ON DELETE SET NULL,
    email    text NOT NULL,
    action   text NOT NULL,
    ip       text NOT NULL DEFAULT '',
    at       timestamptz NOT NULL
);
CREATE INDEX item_access_item ON item_access (item_id, at DESC);

-- Four-eyes approval of sensitive administrator actions.
CREATE TABLE approvals (
    id           bigserial PRIMARY KEY,
    action       text NOT NULL,
    summary      text NOT NULL,
    path         text NOT NULL,
    form         jsonb NOT NULL,
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL,
    decided_by   text NOT NULL DEFAULT '',
    decided_at   timestamptz,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'failed')),
    result       text NOT NULL DEFAULT ''
);
CREATE INDEX approvals_pending ON approvals (status, requested_at);
