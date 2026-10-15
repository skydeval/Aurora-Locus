-- Email two-factor sign-in (chainlink #503): when set, signing in with the
-- account password also needs a one-time code sent to the account's
-- (confirmed) email address. Set through com.atproto.server.updateEmail's
-- `emailAuthFactor`; reported by getSession. App passwords are not affected.
--
-- Additive with a default: existing accounts keep signing in as before.
ALTER TABLE account ADD COLUMN email_auth_factor INTEGER NOT NULL DEFAULT 0;
