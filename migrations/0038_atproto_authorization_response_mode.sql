-- atproto-OAuth authorization responses (chainlink #483): the response_mode a
-- client asked for (`query`, `fragment` or `form_post`), so the approve / deny
-- redirect delivers `code` / `error` + `state` + `iss` where the client reads
-- them. Browser clients built on the reference OAuth libraries ask for
-- `fragment` and never see a code sent in the query string.
--
-- Nullable + additive: rows written before this migration read back NULL,
-- which means `query` (the OAuth default for response_type=code).
ALTER TABLE atproto_authorization_request ADD COLUMN response_mode TEXT;
