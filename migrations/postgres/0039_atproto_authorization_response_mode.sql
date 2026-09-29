-- atproto-OAuth authorization responses (chainlink #483). Postgres counterpart
-- of sqlite 0038; see that file for the rationale. NULL means `query`.
ALTER TABLE atproto_authorization_request ADD COLUMN response_mode TEXT;
