-- Files attached to items. data is ciphertext made in the browser with a
-- random key that is kept inside the (encrypted) item; the server sees only
-- the size. Purging an item deletes its files.
CREATE TABLE attachments (
    id         uuid PRIMARY KEY,
    item_id    uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    owner_id   bigint REFERENCES users(id) ON DELETE CASCADE,
    size       int NOT NULL,
    data       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attachments_item ON attachments (item_id);
CREATE INDEX attachments_owner ON attachments (owner_id);
