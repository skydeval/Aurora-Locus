-- atproto-OAuth account selection (chainlink #502). Postgres counterpart of
-- sqlite 0039; see that file for the rationale. NULL means no hint.
ALTER TABLE atproto_authorization_request ADD COLUMN login_hint TEXT;
