-- Account preferences (chainlink #470). Postgres counterpart of sqlite 0037;
-- see that file for the rationale. One row per preference object, `id`
-- preserving insertion order.
CREATE TABLE account_pref (
    id          BIGSERIAL PRIMARY KEY,
    did         TEXT NOT NULL,
    name        TEXT NOT NULL,
    value_json  TEXT NOT NULL
);

CREATE INDEX idx_account_pref_did ON account_pref(did);
