-- Account preferences (chainlink #470): com.atproto/app.bsky
-- `app.bsky.actor.getPreferences` / `putPreferences` are served by the PDS,
-- not proxied (as in the reference PDS). One row per preference object:
-- `name` is its `$type` (e.g. app.bsky.actor.defs#savedFeedsPrefV2) and
-- `value_json` the full object. `id` preserves insertion order, which clients
-- rely on. putPreferences replaces a namespace's rows wholesale.
CREATE TABLE account_pref (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    did         TEXT NOT NULL,
    name        TEXT NOT NULL,
    value_json  TEXT NOT NULL
);

CREATE INDEX idx_account_pref_did ON account_pref(did);
