//! `repair-tree`: put back the records a repository's tree lost while its
//! index kept them (#505).
//!
//! proto-blue-repo 0.3.3's tree delete could drop neighbouring records from
//! a commit's tree. The records stayed indexed, so reads still found them,
//! but they were gone from the signed repository: relays and AppViews no
//! longer saw them, and deleting them failed. This command restores them
//! through the ordinary write path, in signed commits that announce each
//! record as a create, and records the repair in the audit chain.

use crate::{
    actor_store::repository::RepositoryManager,
    admin::{
        audit_chain::{self, AppendEntryParams},
        defs::Subject,
    },
    context::AppContext,
    error::{PdsError, PdsResult},
};

const DEFAULT_RATIONALE: &str = "restore records missing from the repository tree";

/// List, and unless `dry_run` restore, the records `did`'s index holds that
/// its tree does not.
///
/// # Errors
///
/// When `did` has no account, when the repository cannot be read, or when
/// the restore or its audit entry fails (see
/// [`RepositoryManager::restore_missing_to_tree`]).
pub async fn run(
    ctx: &AppContext,
    did: &str,
    dry_run: bool,
    rationale: Option<&str>,
) -> PdsResult<()> {
    ctx.account_manager.get_account(did).await?;
    let repo_mgr = RepositoryManager::for_writer(ctx, did.to_string());

    let lost = repo_mgr.records_missing_from_tree().await?;
    if lost.is_empty() {
        println!("{did}: the tree holds every indexed record; nothing to restore");
        return Ok(());
    }
    println!("{did}: {} indexed record(s) missing from the tree:", lost.len());
    for record in &lost {
        println!("  {}/{}  {}", record.collection, record.rkey, record.cid);
    }
    if dry_run {
        println!("dry run: nothing written");
        return Ok(());
    }

    let signer = crate::api::repo::create_actor_signer(&ctx.account_manager, did).await?;
    let restore = repo_mgr.restore_missing_to_tree(signer).await?;
    if restore.restored.is_empty() {
        println!("{did}: nothing left to restore");
        return Ok(());
    }

    let subject = Subject::Repo {
        did: did.to_string(),
    };
    let snapshot_id = audit_chain::capture_snapshot(&ctx.account_db, &subject).await?;
    let payload = serde_json::json!({
        "restored": restore
            .restored
            .iter()
            .map(|r| serde_json::json!({
                "collection": r.collection,
                "rkey": r.rkey,
                "cid": r.cid,
            }))
            .collect::<Vec<_>>(),
        "commits": restore.commits.iter().map(|c| c.commit_cid.clone()).collect::<Vec<_>>(),
        "entry_point": "cli",
    });
    let _chain_guard = audit_chain::AppendChainGuard::acquire().await;
    let mut tx = audit_chain::begin_chain_tx(&ctx.account_db, ctx.config.database.backend)
        .await
        .map_err(PdsError::Database)?;
    audit_chain::insert_chain_entry(
        &mut tx,
        ctx.config.database.backend,
        AppendEntryParams {
            source: "manual",
            payload: Some(payload),
            actor_did: &ctx.config.service.service_did,
            action: "repo.tree_restored",
            subject: Some(&subject),
            rationale: rationale.unwrap_or(DEFAULT_RATIONALE),
            snapshot_id,
            event_id: None,
            cascade_subjects: &[],
            cascade_snapshot_ids: &[],
        },
    )
    .await?;
    tx.commit().await.map_err(PdsError::Database)?;

    for commit in &restore.commits {
        println!("restored in commit {} (rev {})", commit.commit_cid, commit.rev);
    }
    tracing::info!(did = %did, restored = restore.restored.len(), "Restored records to the repository tree via CLI");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::federation_peers::test_support::create_test_context_with;
    use clap::Parser;
    use proto_blue::lex_cbor::cid_for_lex;
    use proto_blue::lex_json::json_to_lex;

    async fn seed_account(ctx: &AppContext, handle: &str) -> String {
        let acc = ctx
            .account_manager
            .create_account(handle.into(), Some(format!("{handle}@example.com")), "password123".into(), None, None)
            .await
            .unwrap();
        RepositoryManager::with_validation_mode(
            acc.did.clone(),
            (*ctx.actor_store).clone(),
            ctx.config.validation_mode,
        )
        .initialize()
        .await
        .expect("init actor repo");
        let h = acc.handle.clone().unwrap_or_else(|| handle.to_string());
        crate::api::account_emit::create_account_emit_sequence(ctx, &acc.did, &h)
            .await
            .expect("seed genesis repo");
        acc.did
    }

    /// Index a post the tree does not hold, as #505 left them.
    async fn lose_a_post(ctx: &AppContext, did: &str) -> String {
        let value = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "lost",
            "createdAt": "2026-10-17T00:00:00Z",
        });
        let lex = json_to_lex(&value);
        let cid = cid_for_lex(&lex).unwrap().to_string();
        let bytes = proto_blue::lex_cbor::encode(&lex).unwrap();
        ctx.actor_store.put_block(did, &cid, &bytes).await.unwrap();
        let uri = format!("at://{did}/app.bsky.feed.post/3mxupbno2ps2k");
        ctx.actor_store
            .put_record(did, &uri, &cid, "app.bsky.feed.post", "3mxupbno2ps2k", "r")
            .await
            .unwrap();
        cid
    }

    async fn audit_payloads(ctx: &AppContext) -> Vec<String> {
        sqlx::query_scalar("SELECT payload FROM audit_chain_entry WHERE action = $1")
            .bind("repo.tree_restored")
            .fetch_all(&ctx.account_db)
            .await
            .unwrap()
    }

    #[test]
    fn repair_tree_parses() {
        use crate::cli::{Cli, Commands};
        let cli = Cli::try_parse_from(["aurora", "repair-tree", "did:plc:a", "--dry-run"]).unwrap();
        match cli.command {
            Some(Commands::RepairTree { did, dry_run, rationale }) => {
                assert_eq!(did, "did:plc:a");
                assert!(dry_run);
                assert!(rationale.is_none());
            }
            _ => panic!("expected RepairTree"),
        }
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let ctx = create_test_context_with(|_| {}).await;
        let did = seed_account(&ctx, "drytree").await;
        lose_a_post(&ctx, &did).await;
        let seq_before = ctx.sequencer.current_seq().await.unwrap();

        run(&ctx, &did, true, None).await.unwrap();

        let repo_mgr = RepositoryManager::for_writer(&ctx, did.clone());
        assert_eq!(repo_mgr.records_missing_from_tree().await.unwrap().len(), 1);
        assert_eq!(ctx.sequencer.current_seq().await.unwrap(), seq_before);
        assert!(audit_payloads(&ctx).await.is_empty());
    }

    #[tokio::test]
    async fn a_repair_restores_announces_and_audits() {
        let ctx = create_test_context_with(|_| {}).await;
        let did = seed_account(&ctx, "fixtree").await;
        let cid = lose_a_post(&ctx, &did).await;
        let seq_before = ctx.sequencer.current_seq().await.unwrap();

        run(&ctx, &did, false, Some("test repair")).await.unwrap();

        let repo_mgr = RepositoryManager::for_writer(&ctx, did.clone());
        assert!(repo_mgr.records_missing_from_tree().await.unwrap().is_empty());
        assert!(ctx.sequencer.current_seq().await.unwrap() > seq_before, "a commit went out");
        let payloads = audit_payloads(&ctx).await;
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].contains(&cid), "got {}", payloads[0]);
        assert!(payloads[0].contains("\"entry_point\":\"cli\""));

        // Run again: nothing to do, no second entry.
        run(&ctx, &did, false, None).await.unwrap();
        assert_eq!(audit_payloads(&ctx).await.len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_account_is_an_error() {
        let ctx = create_test_context_with(|_| {}).await;
        assert!(run(&ctx, "did:plc:nobodyhere", true, None).await.is_err());
    }
}
