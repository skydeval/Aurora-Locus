-- Email two-factor sign-in (chainlink #503). Postgres counterpart of sqlite
-- 0041; see that file for the rationale.
ALTER TABLE account ADD COLUMN email_auth_factor BOOLEAN NOT NULL DEFAULT false;
