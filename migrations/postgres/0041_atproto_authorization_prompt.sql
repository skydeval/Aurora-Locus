-- atproto-OAuth `prompt` (chainlink #503). Postgres counterpart of sqlite
-- 0040; see that file for the rationale. NULL means no prompt.
ALTER TABLE atproto_authorization_request ADD COLUMN prompt TEXT;
