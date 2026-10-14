-- atproto-OAuth account selection (chainlink #502): the `login_hint` a client
-- sent (a handle or DID), so the authorize step can sign in, or switch to, the
-- account the client asked for instead of binding whichever account the
-- browser session holds. A pushed (PAR) request carries it from the push to
-- the authorize step, where the query has only `client_id` and `request_uri`.
--
-- Nullable + additive: rows written before this migration read back NULL,
-- meaning no hint was given.
ALTER TABLE atproto_authorization_request ADD COLUMN login_hint TEXT;
