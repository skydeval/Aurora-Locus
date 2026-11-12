-- Labeler accounts a cairn manages: no sign-in of any kind; the cairn
-- writes their records through the trust link.
CREATE TABLE managed_account (
    did         TEXT PRIMARY KEY,
    cairn       TEXT NOT NULL,
    managed_at  BIGINT NOT NULL
);
