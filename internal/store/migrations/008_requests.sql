-- The access log names the device (from the session) and where the use
-- came from (web vault, extension, a MaxZit console such as WatchZit, the
-- command line).
ALTER TABLE item_access ADD COLUMN device text NOT NULL DEFAULT '';
ALTER TABLE item_access ADD COLUMN via text NOT NULL DEFAULT '';

-- Temporary rights: an approved request raises rights until a time, then
-- base_rights come back.
ALTER TABLE vault_members ADD COLUMN base_rights text CHECK (base_rights IN ('use', 'view', 'edit', 'manage'));
ALTER TABLE vault_members ADD COLUMN rights_until timestamptz;

-- Requests for access: a member asks for more rights in a vault for some
-- hours (vault_id set), or a user asks a person (a manager or an
-- administrator) for access to a vault the user is not in (vault_id NULL;
-- the person gives it in the vault, which needs their browser for the key).
CREATE TABLE access_requests (
    id           bigserial PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_id     uuid REFERENCES vaults(id) ON DELETE CASCADE,
    asked_id     bigint REFERENCES users(id) ON DELETE CASCADE,
    rights       text NOT NULL CHECK (rights IN ('use', 'view', 'edit', 'manage')),
    hours        int NOT NULL CHECK (hours BETWEEN 1 AND 720),
    reason       text NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'expired')),
    decided_by   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    decided_at   timestamptz,
    CHECK (vault_id IS NOT NULL OR asked_id IS NOT NULL)
);
CREATE INDEX access_requests_pending ON access_requests (status, created_at);
