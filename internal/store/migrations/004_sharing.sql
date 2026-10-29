-- Shared vaults (0.6). A shared vault has a name sealed with its own key
-- (data); its key is sealed to the X25519 public key of every member.
-- key_version changes when a manager replaces the key (after a member
-- left); needs_rotation asks the managers to do that.
ALTER TABLE vaults ADD COLUMN data text NOT NULL DEFAULT '';
ALTER TABLE vaults ADD COLUMN revision bigint NOT NULL DEFAULT nextval('revisions');
ALTER TABLE vaults ADD COLUMN key_version int NOT NULL DEFAULT 1;
ALTER TABLE vaults ADD COLUMN needs_rotation boolean NOT NULL DEFAULT false;
ALTER TABLE vaults ADD COLUMN created_by bigint REFERENCES users(id) ON DELETE SET NULL;

-- Groups of users, managed by administrators. A vault given to a group is
-- opened by its members once a manager of the vault has sealed the key to
-- them (pending access until then).
CREATE TABLE groups (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_name ON groups (lower(name));

CREATE TABLE group_members (
    group_id bigint NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members (user_id);

CREATE TABLE vault_groups (
    vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    group_id bigint NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    rights   text NOT NULL CHECK (rights IN ('use', 'view', 'edit', 'manage')),
    PRIMARY KEY (vault_id, group_id)
);

-- A membership comes directly (group_id NULL) or through a group; it may
-- end at a time (time-limited access). revision makes clients sync again.
ALTER TABLE vault_members ADD COLUMN group_id bigint REFERENCES groups(id) ON DELETE CASCADE;
ALTER TABLE vault_members ADD COLUMN expires_at timestamptz;
ALTER TABLE vault_members ADD COLUMN revision bigint NOT NULL DEFAULT nextval('revisions');
ALTER TABLE vault_members ADD COLUMN added_by text NOT NULL DEFAULT '';

-- Public keys a user has confirmed (fingerprints), sealed with the account
-- key, so a changed key of a member is noticed.
ALTER TABLE users ADD COLUMN known_keys text NOT NULL DEFAULT '';
