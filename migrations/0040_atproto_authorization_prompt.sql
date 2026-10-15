-- atproto-OAuth `prompt` (chainlink #503): what the client asked the
-- authorization server to show — `create` (sign up a new account), `login`
-- or `select_account` (sign in again even with a browser session), `none`
-- (show nothing; fail if the user would have to act). A pushed (PAR) request
-- carries it from the push to the authorize step. Cleared once acted on, so
-- returning to the authorize URL after signing up or in does not repeat it.
--
-- Nullable + additive: NULL means no prompt was given.
ALTER TABLE atproto_authorization_request ADD COLUMN prompt TEXT;
