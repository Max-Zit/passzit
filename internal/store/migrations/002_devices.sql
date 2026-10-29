-- Sessions of browser extensions (and later other clients) use a bearer
-- token instead of a cookie and live longer; device names the browser.
ALTER TABLE sessions ADD COLUMN kind text NOT NULL DEFAULT 'web' CHECK (kind IN ('web', 'ext'));
ALTER TABLE sessions ADD COLUMN device text NOT NULL DEFAULT '';
