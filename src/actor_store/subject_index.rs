//! An index of who an account's follow and block records name (#495).
//!
//! The private-tier audience check asks, of one repository: is there a
//! record in this collection whose `subject` is that DID? The `record` table
//! has no column to answer from, and its writers are given a URI and a CID,
//! never the record's value. This module adds the answer to each per-account
//! file without changing any of those writers:
//!
//! - **Triggers** on `record` note that a follow or block record was
//!   created, changed or removed, by queueing its URI in
//!   `record_subject_pending`. SQLite cannot decode a record block, so the
//!   triggers do not derive anything.
//! - **The drain** ([`subject_facts`], when the queue is not empty) reads each
//!   queued record's block, decodes its `subject`, and writes one row of
//!   `record_subject`.
//! - **The probe** answers from `record_subject`, joined to `record` on URI
//!   and CID so that a row can speak only for a record that still exists
//!   with the block the row was derived from.
//!
//! In every committed state of an installed file, each follow or block record
//! is queued, or has an index row carrying its current CID, or names nobody.
//! A probe is only ever run in a snapshot whose queue is empty, so it reads a
//! complete index.
//!
//! [`ensure_installed`] must have completed on a pool before the pool is
//! handed to any caller: a write through a pool on a file without the
//! triggers would not be queued.

use sqlx::{Row, SqliteConnection, SqlitePool};

use crate::error::{PdsError, PdsResult};

/// The value of the `version` row this build writes. A file carrying any
/// other value is reinstalled: triggers replaced, index emptied, every
/// follow and block record queued again.
const INDEX_VERSION: &str = "1";

/// Queued records indexed per drain transaction.
const DRAIN_BATCH: usize = 500;

/// The collections whose records are indexed by subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectCollection {
    /// `app.bsky.graph.follow`.
    Follow,
    /// `app.bsky.graph.block`.
    PublicBlock,
    /// `tools.kryphocron.graph.block`.
    PrivateBlock,
}

impl SubjectCollection {
    /// Every indexed collection.
    pub const ALL: [Self; 3] = [Self::Follow, Self::PublicBlock, Self::PrivateBlock];

    /// The collection's NSID.
    pub const fn nsid(self) -> &'static str {
        match self {
            Self::Follow => "app.bsky.graph.follow",
            Self::PublicBlock => "app.bsky.graph.block",
            Self::PrivateBlock => "tools.kryphocron.graph.block",
        }
    }

    fn from_nsid(nsid: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.nsid() == nsid)
    }
}

/// How a probe compares a record's stored `subject` with a DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectMatch {
    /// The stored string equals the DID, and the record is not under a
    /// record takedown. For a fact that allows.
    Exact,
    /// The stored string, with surrounding whitespace removed, equals the
    /// DID. For a fact that denies.
    Trimmed,
}

/// One question for [`subject_facts`]: does the repository hold a record of
/// `collection` naming `subject`?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectProbe<'a> {
    /// The collection to look in.
    pub collection: SubjectCollection,
    /// The DID the record must name.
    pub subject: &'a str,
    /// How the stored subject is compared.
    pub matching: SubjectMatch,
}

/// The indexed collections as a SQL list of string literals. The NSIDs are
/// constants of this module and contain no quote.
fn collections_sql() -> String {
    SubjectCollection::ALL
        .map(|c| format!("'{}'", c.nsid()))
        .join(", ")
}

/// The statements that install the index, in order. Run inside one
/// transaction.
fn install_statements() -> Vec<String> {
    let collections = collections_sql();
    // Written with NOT EXISTS, not INSERT OR IGNORE: inside a trigger SQLite
    // applies the conflict handling of the statement that fired it, so an
    // upsert of a record whose URI is already queued would fail on the
    // queue's primary key.
    let queue_new = format!(
        "INSERT INTO record_subject_pending (uri)
         SELECT NEW.uri
         WHERE NEW.collection IN ({collections})
           AND NOT EXISTS (SELECT 1 FROM record_subject_pending WHERE uri = NEW.uri);"
    );
    vec![
        "CREATE TABLE IF NOT EXISTS record_subject (
             uri TEXT PRIMARY KEY NOT NULL,
             cid TEXT NOT NULL,
             collection TEXT NOT NULL,
             subject TEXT NOT NULL,
             subject_trim TEXT NOT NULL
         )"
        .to_string(),
        "CREATE INDEX IF NOT EXISTS idx_record_subject_lookup
             ON record_subject (collection, subject_trim, subject)"
            .to_string(),
        "CREATE TABLE IF NOT EXISTS record_subject_pending (
             uri TEXT PRIMARY KEY NOT NULL
         )"
        .to_string(),
        "CREATE TABLE IF NOT EXISTS record_subject_meta (
             key TEXT PRIMARY KEY NOT NULL,
             value TEXT NOT NULL
         )"
        .to_string(),
        "DROP TRIGGER IF EXISTS record_subject_ai".to_string(),
        "DROP TRIGGER IF EXISTS record_subject_au".to_string(),
        "DROP TRIGGER IF EXISTS record_subject_ad".to_string(),
        format!(
            "CREATE TRIGGER record_subject_ai AFTER INSERT ON record
             WHEN NEW.collection IN ({collections})
             BEGIN
                 {queue_new}
             END"
        ),
        format!(
            "CREATE TRIGGER record_subject_au AFTER UPDATE OF uri, cid, collection ON record
             WHEN OLD.collection IN ({collections}) OR NEW.collection IN ({collections})
             BEGIN
                 DELETE FROM record_subject WHERE uri = OLD.uri;
                 DELETE FROM record_subject_pending WHERE uri = OLD.uri;
                 {queue_new}
             END"
        ),
        format!(
            "CREATE TRIGGER record_subject_ad AFTER DELETE ON record
             WHEN OLD.collection IN ({collections})
             BEGIN
                 DELETE FROM record_subject WHERE uri = OLD.uri;
                 DELETE FROM record_subject_pending WHERE uri = OLD.uri;
             END"
        ),
        "DELETE FROM record_subject".to_string(),
        format!(
            "INSERT OR IGNORE INTO record_subject_pending (uri)
             SELECT uri FROM record WHERE collection IN ({collections})"
        ),
        format!(
            "INSERT INTO record_subject_meta (key, value) VALUES ('version', '{INDEX_VERSION}')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        ),
    ]
}

/// Whether the file behind `conn` carries this build's index.
async fn is_installed(conn: &mut SqliteConnection) -> PdsResult<bool> {
    let has_meta: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'record_subject_meta'",
    )
    .fetch_optional(&mut *conn)
    .await?;
    if has_meta.is_none() {
        return Ok(false);
    }
    let version: Option<String> =
        sqlx::query_scalar("SELECT value FROM record_subject_meta WHERE key = 'version'")
            .fetch_optional(&mut *conn)
            .await?;
    Ok(version.as_deref() == Some(INDEX_VERSION))
}

/// Install the index in the per-account file behind `pool` unless it is
/// already there.
///
/// An installed file is recognised by two reads, with no transaction and no
/// write lock, so opening a file never waits for a writer of it. Otherwise
/// one `BEGIN IMMEDIATE` transaction creates the tables and triggers, empties
/// the index, and queues every existing follow and block record; the file is
/// left either untouched or fully installed.
///
/// # Errors
///
/// A store error, including the write lock not becoming free within the
/// connection's busy timeout on a file that still needs installing. The
/// caller must not hand out the pool in that case.
pub(crate) async fn ensure_installed(pool: &SqlitePool) -> PdsResult<()> {
    {
        let mut conn = pool.acquire().await?;
        if is_installed(&mut conn).await? {
            return Ok(());
        }
    }
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if is_installed(&mut tx).await? {
        // A concurrent open installed it while this one waited for the lock.
        tx.commit().await?;
        return Ok(());
    }
    for statement in install_statements() {
        sqlx::query(&statement).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Answer each probe for the repository behind `pool`.
///
/// When nothing is queued the probes run in one read transaction and no
/// write lock is taken. Otherwise the queue is drained first, a batch per
/// `BEGIN IMMEDIATE` transaction, and the probes run inside the transaction
/// of the batch that emptied it, where nothing more can be queued.
///
/// # Errors
///
/// A store error: the write lock not becoming free within the busy timeout
/// while a drain is needed, or a queued record whose block is not in the
/// store. An error is never an answer.
pub(crate) async fn subject_facts(
    pool: &SqlitePool,
    probes: &[SubjectProbe<'_>],
) -> PdsResult<Vec<bool>> {
    {
        let mut tx = pool.begin().await?;
        let queued: i64 =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM record_subject_pending)")
                .fetch_one(&mut *tx)
                .await?;
        if queued == 0 {
            let answers = run_probes(&mut tx, probes).await?;
            tx.commit().await?;
            return Ok(answers);
        }
        tx.rollback().await?;
    }

    loop {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        // The first statement is a write, so the batch owns the URIs it
        // returns: no other drain can take them.
        let uris: Vec<String> = sqlx::query_scalar(
            "DELETE FROM record_subject_pending
             WHERE uri IN (SELECT uri FROM record_subject_pending LIMIT ?1)
             RETURNING uri",
        )
        .bind(i64::try_from(DRAIN_BATCH).unwrap_or(i64::MAX))
        .fetch_all(&mut *tx)
        .await?;
        for uri in &uris {
            index_record(&mut tx, uri).await?;
        }
        if uris.len() < DRAIN_BATCH {
            let answers = run_probes(&mut tx, probes).await?;
            tx.commit().await?;
            return Ok(answers);
        }
        tx.commit().await?;
    }
}

/// Derive the index row of one queued record from its current block, or
/// remove the row when the record is gone or names nobody.
async fn index_record(conn: &mut SqliteConnection, uri: &str) -> PdsResult<()> {
    let row = sqlx::query(
        "SELECT r.cid AS cid, r.collection AS collection, b.content AS content
         FROM record r LEFT JOIN repo_block b ON b.cid = r.cid
         WHERE r.uri = ?1",
    )
    .bind(uri)
    .fetch_optional(&mut *conn)
    .await?;

    let indexed = match row {
        None => None,
        Some(row) => {
            let cid: String = row.get("cid");
            let collection: String = row.get("collection");
            let content: Option<Vec<u8>> = row.get("content");
            match SubjectCollection::from_nsid(&collection) {
                None => None,
                Some(_) => {
                    let Some(content) = content else {
                        tracing::error!(
                            target: "aurora_locus::actor_store",
                            event = "subject_index_block_missing",
                            uri = %uri,
                            cid = %cid,
                            "queued record has no block in the store",
                        );
                        return Err(PdsError::Internal(format!(
                            "record {uri} has no block in the store"
                        )));
                    };
                    record_subject(&content).map(|subject| (cid, collection, subject))
                }
            }
        }
    };

    match indexed {
        Some((cid, collection, subject)) => {
            sqlx::query(
                "INSERT INTO record_subject (uri, cid, collection, subject, subject_trim)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(uri) DO UPDATE SET
                    cid = excluded.cid,
                    collection = excluded.collection,
                    subject = excluded.subject,
                    subject_trim = excluded.subject_trim",
            )
            .bind(uri)
            .bind(cid)
            .bind(collection)
            .bind(&subject)
            // Trimmed in Rust: SQL trim() removes spaces only.
            .bind(subject.trim())
            .execute(&mut *conn)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM record_subject WHERE uri = ?1")
                .bind(uri)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

/// The string `subject` of a stored record block. `None` when the block does
/// not decode or carries no string `subject`: such a record names nobody.
fn record_subject(content: &[u8]) -> Option<String> {
    let lex = proto_blue::lex_cbor::decode(content).ok()?;
    let record = proto_blue::lex_json::lex_to_json(&lex);
    record
        .get("subject")
        .and_then(|subject| subject.as_str())
        .map(str::to_string)
}

const PROBE_TRIMMED_SQL: &str = "SELECT EXISTS (
         SELECT 1 FROM record_subject s
         JOIN record r ON r.uri = s.uri AND r.cid = s.cid
         WHERE s.collection = ?1 AND s.subject_trim = ?2
     )";

const PROBE_EXACT_SQL: &str = "SELECT EXISTS (
         SELECT 1 FROM record_subject s
         JOIN record r ON r.uri = s.uri AND r.cid = s.cid
         WHERE s.collection = ?1 AND s.subject_trim = ?2 AND s.subject = ?2
           AND r.takedown_ref IS NULL
     )";

/// Run each probe on `conn`, which must be inside a transaction whose
/// snapshot has an empty queue.
async fn run_probes(
    conn: &mut SqliteConnection,
    probes: &[SubjectProbe<'_>],
) -> PdsResult<Vec<bool>> {
    let mut answers = Vec::with_capacity(probes.len());
    for probe in probes {
        let sql = match probe.matching {
            SubjectMatch::Exact => PROBE_EXACT_SQL,
            SubjectMatch::Trimmed => PROBE_TRIMMED_SQL,
        };
        let found: i64 = sqlx::query_scalar(sql)
            .bind(probe.collection.nsid())
            .bind(probe.subject)
            .fetch_one(&mut *conn)
            .await?;
        answers.push(found != 0);
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::{ActorStore, ActorStoreConfig};
    use serde_json::json;

    const DID: &str = "did:plc:indexed";
    const OTHER: &str = "did:plc:other";
    const FOLLOW: &str = "app.bsky.graph.follow";
    const BLOCK: &str = "tools.kryphocron.graph.block";

    struct Fixture {
        store: ActorStore,
        pool: SqlitePool,
        _dir: tempfile::TempDir,
    }

    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ActorStore::new(ActorStoreConfig {
            base_directory: dir.path().to_path_buf(),
            cache_size: 100,
        });
        store.create(DID).await.expect("create");
        let pool = store.open_db(DID).await.expect("open");
        Fixture {
            store,
            pool,
            _dir: dir,
        }
    }

    fn encode(record: &serde_json::Value) -> Vec<u8> {
        proto_blue::lex_cbor::encode(&proto_blue::lex_json::json_to_lex(record)).expect("encode")
    }

    impl Fixture {
        /// Store a record whose block is `bytes`, under a CID named by `cid`.
        async fn put_bytes(&self, collection: &str, rkey: &str, cid: &str, bytes: &[u8]) -> String {
            let uri = format!("at://{DID}/{collection}/{rkey}");
            self.store.put_block(DID, cid, bytes).await.expect("block");
            self.store
                .put_record(DID, &uri, cid, collection, rkey, "rev")
                .await
                .expect("record");
            uri
        }

        async fn put(&self, collection: &str, rkey: &str, subject: &str) -> String {
            let cid = format!("cid-{collection}-{rkey}-{subject}");
            self.put_bytes(
                collection,
                rkey,
                &cid,
                &encode(&json!({ "subject": subject })),
            )
            .await
        }

        async fn has(
            &self,
            collection: SubjectCollection,
            subject: &str,
            matching: SubjectMatch,
        ) -> bool {
            subject_facts(
                &self.pool,
                &[SubjectProbe {
                    collection,
                    subject,
                    matching,
                }],
            )
            .await
            .expect("facts")[0]
        }

        async fn follows(&self, subject: &str) -> bool {
            self.has(SubjectCollection::Follow, subject, SubjectMatch::Exact)
                .await
        }

        async fn blocks(&self, subject: &str) -> bool {
            self.has(
                SubjectCollection::PrivateBlock,
                subject,
                SubjectMatch::Trimmed,
            )
            .await
        }

        async fn count(&self, table: &str) -> i64 {
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&self.pool)
                .await
                .expect("count")
        }

        /// Remove the index from the file, as a file written by an earlier
        /// build would be.
        async fn uninstall(&self) {
            for statement in [
                "DROP TRIGGER record_subject_ai",
                "DROP TRIGGER record_subject_au",
                "DROP TRIGGER record_subject_ad",
                "DROP TABLE record_subject",
                "DROP TABLE record_subject_pending",
                "DROP TABLE record_subject_meta",
            ] {
                sqlx::query(statement)
                    .execute(&self.pool)
                    .await
                    .expect("uninstall");
            }
        }
    }

    #[test]
    fn collections_round_trip_and_match_the_endpoint_constant() {
        for collection in SubjectCollection::ALL {
            assert_eq!(
                SubjectCollection::from_nsid(collection.nsid()),
                Some(collection)
            );
        }
        assert_eq!(SubjectCollection::from_nsid("app.bsky.feed.post"), None);
        assert_eq!(
            SubjectCollection::PrivateBlock.nsid(),
            crate::api::kryphocron_endpoints::NSID_BLOCK
        );
    }

    #[tokio::test]
    async fn a_new_file_is_installed() {
        let f = fixture().await;
        let mut conn = f.pool.acquire().await.expect("conn");
        assert!(is_installed(&mut conn).await.expect("installed"));
        let triggers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'record'",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("triggers");
        assert_eq!(triggers, 3);
    }

    #[tokio::test]
    async fn an_existing_file_is_installed_once_with_its_records_queued() {
        let f = fixture().await;
        f.uninstall().await;
        // Written while the file has no index.
        f.put(FOLLOW, "f1", OTHER).await;
        f.put(BLOCK, "b1", OTHER).await;
        f.put("app.bsky.feed.like", "l1", OTHER).await;

        ensure_installed(&f.pool).await.expect("install");
        assert_eq!(f.count("record_subject_pending").await, 2);
        assert_eq!(f.count("record_subject").await, 0);

        assert!(f.follows(OTHER).await);
        assert!(f.blocks(OTHER).await);
        assert_eq!(f.count("record_subject_pending").await, 0);
        assert_eq!(f.count("record_subject").await, 2);

        // A second run finds it installed and queues nothing.
        ensure_installed(&f.pool).await.expect("install again");
        assert_eq!(f.count("record_subject_pending").await, 0);
        assert_eq!(f.count("record_subject").await, 2);
    }

    #[tokio::test]
    async fn another_version_reinstalls_and_requeues() {
        let f = fixture().await;
        f.put(FOLLOW, "f1", OTHER).await;
        assert!(f.follows(OTHER).await);
        sqlx::query("UPDATE record_subject_meta SET value = '0' WHERE key = 'version'")
            .execute(&f.pool)
            .await
            .expect("age the version");

        ensure_installed(&f.pool).await.expect("reinstall");
        assert_eq!(f.count("record_subject").await, 0);
        assert_eq!(f.count("record_subject_pending").await, 1);
        assert!(f.follows(OTHER).await);
    }

    #[tokio::test]
    async fn concurrent_installs_both_succeed() {
        let f = fixture().await;
        f.uninstall().await;
        f.put(FOLLOW, "f1", OTHER).await;
        let (a, b) = tokio::join!(ensure_installed(&f.pool), ensure_installed(&f.pool));
        a.expect("first");
        b.expect("second");
        assert_eq!(f.count("record_subject_pending").await, 1);
    }

    #[tokio::test]
    async fn open_db_and_create_return_an_installed_pool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = ActorStoreConfig {
            base_directory: dir.path().to_path_buf(),
            cache_size: 100,
        };
        // Created, then stripped, as a file from an earlier build.
        let first = ActorStore::new(config.clone());
        first.create(DID).await.expect("create");
        let f = Fixture {
            pool: first.open_db(DID).await.expect("open"),
            store: first,
            _dir: dir,
        };
        f.uninstall().await;
        f.put(BLOCK, "b0", OTHER).await;

        // A second store has an empty cache, so this is a real open.
        let second = ActorStore::new(config.clone());
        let pool = second.open_db(DID).await.expect("open installs");
        let mut conn = pool.acquire().await.expect("conn");
        assert!(is_installed(&mut conn).await.expect("installed"));
        drop(conn);
        let reopened = Fixture {
            store: second,
            pool,
            _dir: tempfile::tempdir().expect("unused"),
        };
        assert!(reopened.blocks(OTHER).await, "the earlier block was queued");

        // `create` on an existing file installs too.
        reopened.uninstall().await;
        let third = ActorStore::new(config);
        third.create(DID).await.expect("create on existing");
        let pool = third.open_db(DID).await.expect("open");
        let mut conn = pool.acquire().await.expect("conn");
        assert!(is_installed(&mut conn).await.expect("installed"));
    }

    #[tokio::test]
    async fn writes_keep_the_answers_equal_to_the_records() {
        let f = fixture().await;
        assert!(!f.follows(OTHER).await);

        // create
        let uri = f.put(FOLLOW, "f1", OTHER).await;
        assert!(f.follows(OTHER).await);

        // upsert to a new block naming someone else
        f.put(FOLLOW, "f1", "did:plc:third").await;
        assert!(!f.follows(OTHER).await);
        assert!(f.follows("did:plc:third").await);

        // upsert to the same block
        f.put(FOLLOW, "f1", "did:plc:third").await;
        assert!(f.follows("did:plc:third").await);

        // delete
        f.store.delete_record(DID, &uri).await.expect("delete");
        assert!(!f.follows("did:plc:third").await);
        assert_eq!(f.count("record_subject").await, 0);
        assert_eq!(f.count("record_subject_pending").await, 0);
    }

    #[tokio::test]
    async fn an_upsert_of_a_queued_record_succeeds() {
        let f = fixture().await;
        // Two writes to one URI with no lookup between: the URI is already
        // queued when the second fires the update trigger.
        f.put(FOLLOW, "f1", OTHER).await;
        f.put(FOLLOW, "f1", "did:plc:third").await;
        assert_eq!(f.count("record_subject_pending").await, 1);
        assert!(f.follows("did:plc:third").await);
        assert!(!f.follows(OTHER).await);

        // The same through the in-transaction writer.
        let cid = "cid-in-tx";
        f.store
            .put_block(DID, cid, &encode(&json!({ "subject": OTHER })))
            .await
            .expect("block");
        let uri = format!("at://{DID}/{FOLLOW}/f1");
        for _ in 0..2 {
            let mut tx = f.pool.begin().await.expect("begin");
            ActorStore::put_record_in_tx(&mut tx, &uri, cid, FOLLOW, "f1", "rev")
                .await
                .expect("put in tx");
            tx.commit().await.expect("commit");
        }
        assert!(f.follows(OTHER).await);
    }

    #[tokio::test]
    async fn insert_or_replace_and_delete_all_are_followed() {
        let f = fixture().await;
        f.put(BLOCK, "b1", OTHER).await;
        assert!(f.blocks(OTHER).await);

        // INSERT OR REPLACE onto the same URI with another block.
        let cid = "cid-replaced";
        f.store
            .put_block(DID, cid, &encode(&json!({ "subject": "did:plc:third" })))
            .await
            .expect("block");
        sqlx::query(
            "INSERT OR REPLACE INTO record (uri, cid, collection, rkey, repo_rev, indexed_at)
             VALUES (?1, ?2, ?3, 'b1', 'rev', CURRENT_TIMESTAMP)",
        )
        .bind(format!("at://{DID}/{BLOCK}/b1"))
        .bind(cid)
        .bind(BLOCK)
        .execute(&f.pool)
        .await
        .expect("replace");
        assert!(!f.blocks(OTHER).await);
        assert!(f.blocks("did:plc:third").await);

        // The rebuild's first statement.
        sqlx::query("DELETE FROM record")
            .execute(&f.pool)
            .await
            .expect("delete all");
        assert!(!f.blocks("did:plc:third").await);
        assert_eq!(f.count("record_subject").await, 0);
    }

    #[tokio::test]
    async fn deleting_a_block_removes_its_record_from_the_index() {
        let f = fixture().await;
        f.put_bytes(BLOCK, "b1", "cid-b1", &encode(&json!({ "subject": OTHER })))
            .await;
        assert!(f.blocks(OTHER).await);
        sqlx::query("DELETE FROM repo_block WHERE cid = 'cid-b1'")
            .execute(&f.pool)
            .await
            .expect("cascade");
        assert_eq!(f.count("record").await, 0);
        assert_eq!(f.count("record_subject").await, 0);
        assert!(!f.blocks(OTHER).await);
    }

    #[tokio::test]
    async fn other_collections_are_never_queued() {
        let f = fixture().await;
        f.put("app.bsky.feed.like", "l1", OTHER).await;
        f.put("app.bsky.graph.followx", "x1", OTHER).await;
        assert_eq!(f.count("record_subject_pending").await, 0);
        assert!(!f.follows(OTHER).await);
    }

    #[tokio::test]
    async fn follows_match_exactly_and_blocks_match_trimmed() {
        for padded in [
            format!("{OTHER} "),
            format!("\t{OTHER}"),
            format!("{OTHER}\n"),
            format!("\u{a0}{OTHER}"),
        ] {
            let f = fixture().await;
            f.put(FOLLOW, "f1", &padded).await;
            f.put(BLOCK, "b1", &padded).await;
            assert!(!f.follows(OTHER).await, "padded follow {padded:?}");
            assert!(f.blocks(OTHER).await, "padded block {padded:?}");
        }
        let f = fixture().await;
        f.put(FOLLOW, "f1", OTHER).await;
        // A follow is not a block, and the collections do not mix.
        assert!(!f.blocks(OTHER).await);
        assert!(
            !f.has(SubjectCollection::PublicBlock, OTHER, SubjectMatch::Trimmed)
                .await
        );
        f.put("app.bsky.graph.block", "p1", OTHER).await;
        assert!(
            f.has(SubjectCollection::PublicBlock, OTHER, SubjectMatch::Trimmed)
                .await
        );
    }

    #[tokio::test]
    async fn a_follow_under_takedown_is_not_a_follow_but_a_block_is_a_block() {
        let f = fixture().await;
        f.put(FOLLOW, "f1", OTHER).await;
        f.put(BLOCK, "b1", OTHER).await;
        sqlx::query("UPDATE record SET takedown_ref = 'td'")
            .execute(&f.pool)
            .await
            .expect("takedown");
        assert!(!f.follows(OTHER).await);
        assert!(f.blocks(OTHER).await);
    }

    #[tokio::test]
    async fn an_index_row_answers_only_for_its_record_and_block() {
        let f = fixture().await;
        let uri = f.put(BLOCK, "b1", OTHER).await;
        assert!(f.blocks(OTHER).await);

        // Change the record behind the triggers' back.
        for statement in [
            "DROP TRIGGER record_subject_au",
            "DROP TRIGGER record_subject_ad",
        ] {
            sqlx::query(statement).execute(&f.pool).await.expect("drop");
        }
        f.store
            .put_block(
                DID,
                "cid-elsewhere",
                &encode(&json!({ "subject": "did:plc:third" })),
            )
            .await
            .expect("block");
        sqlx::query("UPDATE record SET cid = 'cid-elsewhere' WHERE uri = ?1")
            .bind(&uri)
            .execute(&f.pool)
            .await
            .expect("repoint");
        assert!(
            !f.blocks(OTHER).await,
            "the row's block is no longer the record's"
        );

        sqlx::query("DELETE FROM record WHERE uri = ?1")
            .bind(&uri)
            .execute(&f.pool)
            .await
            .expect("remove");
        assert_eq!(
            f.count("record_subject").await,
            1,
            "the stale row is still there"
        );
        assert!(!f.blocks(OTHER).await, "and answers for nothing");
    }

    #[tokio::test]
    async fn records_that_name_nobody_leave_the_queue() {
        let f = fixture().await;
        f.put_bytes(BLOCK, "b1", "cid-junk", b"not cbor").await;
        f.put_bytes(BLOCK, "b2", "cid-number", &encode(&json!({ "subject": 5 })))
            .await;
        f.put_bytes(BLOCK, "b3", "cid-none", &encode(&json!({ "note": "x" })))
            .await;
        assert_eq!(f.count("record_subject_pending").await, 3);
        assert!(!f.blocks(OTHER).await);
        assert_eq!(f.count("record_subject_pending").await, 0);
        assert_eq!(f.count("record_subject").await, 0);
    }

    #[tokio::test]
    async fn a_record_whose_block_is_missing_fails_the_lookup_and_stays_queued() {
        let f = fixture().await;
        f.put_bytes(BLOCK, "b1", "cid-b1", &encode(&json!({ "subject": OTHER })))
            .await;
        // Only reachable with the foreign key switched off.
        let mut conn = f.pool.acquire().await.expect("conn");
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .expect("fk off");
        sqlx::query("DELETE FROM repo_block WHERE cid = 'cid-b1'")
            .execute(&mut *conn)
            .await
            .expect("delete block");
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .expect("fk on");
        drop(conn);

        let result = subject_facts(
            &f.pool,
            &[SubjectProbe {
                collection: SubjectCollection::PrivateBlock,
                subject: OTHER,
                matching: SubjectMatch::Trimmed,
            }],
        )
        .await;
        assert!(matches!(result, Err(PdsError::Internal(_))), "{result:?}");
        assert_eq!(f.count("record_subject_pending").await, 1);
    }

    #[tokio::test]
    async fn a_large_queue_drains_in_batches() {
        for queued in [DRAIN_BATCH, 1200] {
            let f = fixture().await;
            f.put(FOLLOW, "0000", OTHER).await;
            for n in 1..queued {
                f.put(FOLLOW, &format!("{n:04}"), "did:plc:third").await;
            }
            assert_eq!(
                f.count("record_subject_pending").await,
                i64::try_from(queued).expect("small")
            );
            assert!(f.follows(OTHER).await, "{queued} queued");
            assert_eq!(f.count("record_subject_pending").await, 0);
            assert_eq!(
                f.count("record_subject").await,
                i64::try_from(queued).expect("small")
            );
        }
    }

    #[tokio::test]
    async fn a_lookup_with_an_empty_queue_does_not_wait_for_a_writer() {
        let f = fixture().await;
        f.put(BLOCK, "b1", OTHER).await;
        assert!(f.blocks(OTHER).await);

        let mut writer = f.pool.begin_with("BEGIN IMMEDIATE").await.expect("lock");
        sqlx::query("UPDATE record SET repo_rev = 'held'")
            .execute(&mut *writer)
            .await
            .expect("write");
        let answered = tokio::time::timeout(std::time::Duration::from_secs(2), f.blocks(OTHER))
            .await
            .expect("the lookup did not wait for the write lock");
        assert!(answered);
        writer.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn probes_use_the_lookup_index() {
        let f = fixture().await;
        for (sql, columns) in [
            (PROBE_TRIMMED_SQL, "(collection=? AND subject_trim=?)"),
            (
                PROBE_EXACT_SQL,
                "(collection=? AND subject_trim=? AND subject=?)",
            ),
        ] {
            let rows = sqlx::query(&format!("EXPLAIN QUERY PLAN {sql}"))
                .bind("c")
                .bind("s")
                .fetch_all(&f.pool)
                .await
                .expect("explain");
            let plan: Vec<String> = rows
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
            let plan = plan.join(" | ");
            assert!(
                plan.contains(&format!("idx_record_subject_lookup {columns}")),
                "{plan}"
            );
            assert!(plan.contains("sqlite_autoindex_record_1 (uri=?)"), "{plan}");
        }
    }
}
