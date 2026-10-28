//! Retirement of the follow and block subject index (#495, #536).
//!
//! #495 added to each per-account file an index of whom its follow and block
//! records name, for the private-tier audience check: triggers on `record`
//! queued every follow or block write in `record_subject_pending`, and the
//! check drained the queue into `record_subject` before reading it.
//!
//! #536 moved audiences to the AppView, and locus no longer checks who may
//! write under one, so nothing reads the index or drains its queue. Left
//! installed, the triggers would keep queueing every follow and block write
//! in a table nothing empties. [`remove_installed`] drops the triggers and
//! tables from a file that has them; it runs when a file is opened.

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::PdsResult;

/// The triggers the index installed on `record`.
const TRIGGERS: [&str; 3] = ["record_subject_ai", "record_subject_au", "record_subject_ad"];

/// The tables the index installed. Its lookup index goes with
/// `record_subject`.
const TABLES: [&str; 3] = ["record_subject", "record_subject_pending", "record_subject_meta"];

/// Drop the subject index from the file behind `pool`, if it is there.
///
/// A file without it costs one read of `sqlite_master` and takes no write
/// lock. A file with it loses its triggers first, so no write is queued
/// while the tables go, then the tables, in one `BEGIN IMMEDIATE`
/// transaction; a concurrent open waiting on the lock finds nothing left.
///
/// # Errors
///
/// A store error, such as the write lock not becoming free within the busy
/// timeout.
pub(crate) async fn remove_installed(pool: &SqlitePool) -> PdsResult<()> {
    if !is_installed(&mut *pool.acquire().await?).await? {
        return Ok(());
    }
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if !is_installed(&mut tx).await? {
        // A concurrent open removed it while this one waited for the lock.
        tx.commit().await?;
        return Ok(());
    }
    for trigger in TRIGGERS {
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger}"))
            .execute(&mut *tx)
            .await?;
    }
    for table in TABLES {
        sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!("subject index removed from an account store (#536)");
    Ok(())
}

/// Whether any trigger or table of the index is in the file.
async fn is_installed(conn: &mut SqliteConnection) -> PdsResult<bool> {
    let found: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE (type = 'trigger' AND name IN ('record_subject_ai', 'record_subject_au', 'record_subject_ad'))
            OR (type = 'table' AND name IN ('record_subject', 'record_subject_pending', 'record_subject_meta'))",
    )
    .fetch_one(conn)
    .await?;
    Ok(found > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    /// The objects of the #495 index, as it installed them.
    const INSTALLED: [&str; 7] = [
        "CREATE TABLE record (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, collection TEXT NOT NULL)",
        "CREATE TABLE record_subject (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, collection TEXT NOT NULL, subject TEXT NOT NULL, subject_trim TEXT NOT NULL)",
        "CREATE INDEX idx_record_subject_lookup ON record_subject (collection, subject_trim)",
        "CREATE TABLE record_subject_pending (uri TEXT PRIMARY KEY NOT NULL)",
        "CREATE TABLE record_subject_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)",
        "CREATE TRIGGER record_subject_ai AFTER INSERT ON record BEGIN INSERT INTO record_subject_pending (uri) SELECT NEW.uri WHERE NOT EXISTS (SELECT 1 FROM record_subject_pending WHERE uri = NEW.uri); END",
        "CREATE TRIGGER record_subject_ad AFTER DELETE ON record BEGIN INSERT INTO record_subject_pending (uri) SELECT OLD.uri WHERE NOT EXISTS (SELECT 1 FROM record_subject_pending WHERE uri = OLD.uri); END",
    ];

    async fn pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    async fn subject_objects(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE name LIKE '%record_subject%' ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// An installed file loses every trigger, table and index of the index,
    /// and its `record` table and rows stay; writes are no longer queued.
    #[tokio::test]
    async fn an_installed_index_is_removed_and_records_are_kept() {
        let pool = pool().await;
        for statement in INSTALLED {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO record VALUES ('at://did:plc:a/app.bsky.graph.follow/1', 'c1', 'app.bsky.graph.follow')")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!subject_objects(&pool).await.is_empty());

        remove_installed(&pool).await.unwrap();
        assert!(subject_objects(&pool).await.is_empty(), "{:?}", subject_objects(&pool).await);
        let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(records, 1);
        // A later write fires no trigger into a dropped table.
        sqlx::query("INSERT INTO record VALUES ('at://did:plc:a/app.bsky.graph.follow/2', 'c2', 'app.bsky.graph.follow')")
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A file that never had it, or has already lost it, is left as it is.
    #[tokio::test]
    async fn a_file_without_the_index_is_untouched() {
        let pool = pool().await;
        sqlx::query(INSTALLED[0]).execute(&pool).await.unwrap();
        remove_installed(&pool).await.unwrap();
        remove_installed(&pool).await.unwrap();
        assert!(subject_objects(&pool).await.is_empty());
    }
}
