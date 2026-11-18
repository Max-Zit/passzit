-- The "new version available" notice of the console: the version an
-- administrator hid it for and until when (five days). A newer version
-- shows it again at once.
ALTER TABLE users ADD COLUMN update_hidden_version text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN update_hidden_until timestamptz;
