//! An account's status, read in one place and announced in one way (#499).
//!
//! An account's status is spread over two stores: the actor row
//! (`takedown_ref`, `deactivated_at`, `suspended_at`, `desynchronized_at`)
//! and the moderation record (unreversed takedowns and suspensions). Every
//! surface that reports status (`sync.getRepoStatus`, `sync.listRepos`,
//! session documents) and every `#account` event reads it through
//! [`account_state`], so they cannot disagree.
//!
//! Precedence, highest first: taken down, suspended, deactivated,
//! desynchronized. An operator's action outranks the account's own choice,
//! so a suspended account that deactivates is still reported suspended, and
//! reactivating it does not announce it active.
//!
//! Every path that changes an account's status calls
//! [`announce_account_state`] after its change commits. Deleting an account
//! goes through [`finish_account_deletion`] once its row is gone.

use crate::{
    admin::moderation::ModerationFlags,
    context::AppContext,
    db::account::ActorAccount,
    error::{PdsError, PdsResult},
    sequencer::events::{AccountEvent, AccountStatus},
};

/// An account's status as relays and AppViews see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    /// Whether the account is active.
    pub active: bool,
    /// Why it is not active; `None` when it is.
    pub status: Option<AccountStatus>,
}

impl AccountState {
    /// The status as the lexicons spell it.
    pub fn status_str(&self) -> Option<&'static str> {
        self.status.map(|status| match status {
            AccountStatus::Takendown => "takendown",
            AccountStatus::Suspended => "suspended",
            AccountStatus::Deleted => "deleted",
            AccountStatus::Deactivated => "deactivated",
            AccountStatus::Desynchronized => "desynchronized",
            AccountStatus::Throttled => "throttled",
        })
    }

    /// The `#account` event that announces this state for `did`.
    pub fn event(&self, did: &str) -> AccountEvent {
        AccountEvent {
            did: did.to_string(),
            active: self.active,
            status: self.status,
        }
    }
}

/// The state of an account from its actor row and its moderation facts.
pub fn state_of(account: &ActorAccount, moderation: ModerationFlags) -> AccountState {
    let status = if account.takedown_ref.is_some() || moderation.taken_down {
        Some(AccountStatus::Takendown)
    } else if account.suspended_at.is_some() || moderation.suspended {
        Some(AccountStatus::Suspended)
    } else if account.deactivated_at.is_some() {
        Some(AccountStatus::Deactivated)
    } else if account.desynchronized_at.is_some() {
        Some(AccountStatus::Desynchronized)
    } else {
        None
    };
    AccountState {
        active: status.is_none(),
        status,
    }
}

/// The state of an account whose row the caller already holds.
///
/// # Errors
///
/// A failed moderation lookup.
pub async fn state_for(ctx: &AppContext, account: &ActorAccount) -> PdsResult<AccountState> {
    let moderation = ctx.moderation_manager.active_flags(&account.did).await?;
    Ok(state_of(account, moderation))
}

/// [`state_for`] as the `(active, status)` pair an `#account` event carries,
/// for emit sites that log rather than fail. If the moderation lookup fails
/// the state is read from the actor row alone, and a warning says so.
pub async fn state_pair(ctx: &AppContext, account: &ActorAccount) -> (bool, Option<AccountStatus>) {
    let state = match state_for(ctx, account).await {
        Ok(state) => state,
        Err(e) => {
            tracing::warn!(
                did = %account.did,
                error = %e,
                "moderation lookup failed; account state read from the account row alone",
            );
            state_of(account, ModerationFlags::default())
        }
    };
    (state.active, state.status)
}

/// The state of the account `did`; `None` when no such account exists here.
///
/// # Errors
///
/// A failed account or moderation lookup.
pub async fn account_state(ctx: &AppContext, did: &str) -> PdsResult<Option<AccountState>> {
    match ctx.account_manager.get_account(did).await {
        Ok(account) => Ok(Some(state_for(ctx, &account).await?)),
        Err(PdsError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Emit `#account` with the current state of `did`. Call after the change
/// that altered the state has committed. An account that no longer exists
/// is not announced here: deletion announces itself
/// ([`finish_account_deletion`]).
///
/// # Errors
///
/// A failed lookup or a failure to sequence the event.
pub async fn announce_account_state(ctx: &AppContext, did: &str) -> PdsResult<()> {
    if let Some(state) = account_state(ctx, did).await? {
        ctx.sequencer.sequence_account(state.event(did)).await?;
    }
    Ok(())
}

/// Finish deleting an account whose rows have already been removed: announce
/// `#account active:false status:"deleted"`, remove the account's earlier
/// events, destroy its repository store, and delete the blobs only it used.
/// The order is the reference PDS's: the account stops existing before its
/// data does, so a failure part-way leaves data that nothing serves, never
/// an account without data.
///
/// The repository store and the blobs are removed best-effort: a failure is
/// logged and the rest still runs. The event is not optional: if it cannot
/// be sequenced the error is returned and nothing further is removed.
///
/// # Errors
///
/// A failure to sequence the deletion event or to remove earlier events.
pub async fn finish_account_deletion(ctx: &AppContext, did: &str) -> PdsResult<()> {
    let deletion_seq = ctx
        .sequencer
        .sequence_account(AccountEvent::from_status(
            did.to_string(),
            AccountStatus::Deleted,
        ))
        .await?;
    ctx.sequencer
        .delete_all_for_user(did, &[deletion_seq])
        .await?;

    if let Err(e) = ctx.actor_store.destroy(did).await {
        tracing::warn!(
            did = %did,
            error = %e,
            "account deletion: repository store not removed",
        );
    }
    match ctx.blob_store.delete_account_blobs(did).await {
        Ok(removed) => tracing::info!(did = %did, removed, "account deletion: blobs removed"),
        Err(e) => tracing::warn!(
            did = %did,
            error = %e,
            "account deletion: blobs not removed",
        ),
    }
    tracing::info!(did = %did, deletion_seq, "account_deleted_permanently");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn account() -> ActorAccount {
        ActorAccount {
            did: "did:plc:state".into(),
            handle: Some("state.localhost".into()),
            created_at: Utc::now(),
            takedown_ref: None,
            deactivated_at: None,
            delete_after: None,
            suspended_at: None,
            desynchronized_at: None,
            email: None,
            password_hash: None,
            email_confirmed_at: None,
            invites_disabled: Some(false),
        }
    }

    fn flags(taken_down: bool, suspended: bool) -> ModerationFlags {
        ModerationFlags {
            taken_down,
            suspended,
        }
    }

    #[test]
    fn an_account_with_nothing_set_is_active() {
        let state = state_of(&account(), ModerationFlags::default());
        assert_eq!(state, AccountState { active: true, status: None });
        assert_eq!(state.status_str(), None);
    }

    #[test]
    fn each_source_of_each_status_is_read() {
        let mut taken_down_row = account();
        taken_down_row.takedown_ref = Some("ref".into());
        let mut suspended_row = account();
        suspended_row.suspended_at = Some(Utc::now());
        let mut deactivated = account();
        deactivated.deactivated_at = Some(Utc::now());
        let mut desynchronized = account();
        desynchronized.desynchronized_at = Some(Utc::now());

        let cases = [
            (state_of(&taken_down_row, flags(false, false)), "takendown"),
            (state_of(&account(), flags(true, false)), "takendown"),
            (state_of(&suspended_row, flags(false, false)), "suspended"),
            (state_of(&account(), flags(false, true)), "suspended"),
            (state_of(&deactivated, flags(false, false)), "deactivated"),
            (state_of(&desynchronized, flags(false, false)), "desynchronized"),
        ];
        for (state, expected) in cases {
            assert!(!state.active, "{expected}");
            assert_eq!(state.status_str(), Some(expected));
        }
    }

    #[test]
    fn an_operators_action_outranks_the_accounts_own() {
        let mut deactivated = account();
        deactivated.deactivated_at = Some(Utc::now());
        assert_eq!(
            state_of(&deactivated, flags(false, true)).status_str(),
            Some("suspended")
        );
        assert_eq!(
            state_of(&deactivated, flags(true, true)).status_str(),
            Some("takendown")
        );
    }

    mod live {
        //! Against a real context: each status path of the AppView's audit,
        //! items 1 – 5 and 10.
        use super::super::*;
        use crate::admin::moderation::{ApplyActionParams, Lift, ModerationAction};
        use axum::extract::{Query, State};

        async fn ctx_with_account(handle: &str) -> (AppContext, String) {
            let ctx =
                crate::api::federation_peers::test_support::create_test_context_with(|_| {})
                    .await;
            let did = add_account(&ctx, handle).await;
            (ctx, did)
        }

        async fn add_account(ctx: &AppContext, handle: &str) -> String {
            let account = ctx
                .account_manager
                .create_account(handle.to_string(), None, "password123".to_string(), None, None)
                .await
                .expect("create account");
            ctx.actor_store
                .create(&account.did)
                .await
                .expect("create repo");
            account.did
        }

        async fn moderate(
            ctx: &AppContext,
            did: &str,
            action: ModerationAction,
            expires_in: Option<chrono::Duration>,
        ) {
            ctx.moderation_manager
                .apply_action(ApplyActionParams {
                    did,
                    action,
                    reason: "test",
                    moderated_by: "did:plc:admin",
                    expires_in,
                    report_id: None,
                    notes: None,
                })
                .await
                .expect("moderate");
        }

        async fn account_events(ctx: &AppContext) -> i64 {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM repo_seq WHERE event_type = 'account' AND invalidated = 0",
            )
            .fetch_one(&ctx.account_db)
            .await
            .expect("count events")
        }

        async fn status(ctx: &AppContext, did: &str) -> Option<&'static str> {
            account_state(ctx, did)
                .await
                .expect("state")
                .expect("account exists")
                .status_str()
        }

        async fn repo_status(ctx: &AppContext, did: &str) -> PdsResult<serde_json::Value> {
            let params = serde_json::from_value(serde_json::json!({ "did": did })).unwrap();
            let resp =
                crate::api::sync::get_repo_status_endpoint(State(ctx.clone()), Query(params))
                    .await?;
            Ok(serde_json::to_value(resp.0).unwrap())
        }

        #[tokio::test]
        async fn a_suspension_is_reported_and_announced() {
            let (ctx, did) = ctx_with_account("suspended.localhost").await;
            moderate(&ctx, &did, ModerationAction::Suspend, None).await;
            assert_eq!(status(&ctx, &did).await, Some("suspended"));

            let before = account_events(&ctx).await;
            announce_account_state(&ctx, &did).await.expect("announce");
            assert_eq!(account_events(&ctx).await, before + 1);

            let reported = repo_status(&ctx, &did).await.expect("getRepoStatus");
            assert_eq!(reported["active"], false);
            assert_eq!(reported["status"], "suspended");
        }

        #[tokio::test]
        async fn a_suspended_account_that_reactivates_stays_suspended() {
            let (ctx, did) = ctx_with_account("stays.localhost").await;
            moderate(&ctx, &did, ModerationAction::Suspend, None).await;
            ctx.account_manager
                .deactivate_account(&did)
                .await
                .expect("deactivate");
            assert_eq!(status(&ctx, &did).await, Some("suspended"));
            ctx.account_manager
                .cancel_account_deletion(&did)
                .await
                .expect("reactivate");
            assert_eq!(status(&ctx, &did).await, Some("suspended"));
        }

        #[tokio::test]
        async fn a_restore_lifts_both_records_of_a_takedown() {
            let (ctx, did) = ctx_with_account("restored.localhost").await;
            moderate(&ctx, &did, ModerationAction::Takedown, None).await;
            assert_eq!(status(&ctx, &did).await, Some("takendown"));

            let mut tx = ctx.account_db.begin().await.unwrap();
            crate::admin::moderation::ModerationManager::restore_account_in_tx(
                &mut tx,
                &did,
                "did:plc:admin",
                "test",
                Lift::Takedowns,
            )
            .await
            .expect("restore");
            tx.commit().await.unwrap();

            assert_eq!(status(&ctx, &did).await, None);
            assert!(!ctx.moderation_manager.is_taken_down(&did).await.unwrap());
            let row = ctx.account_manager.get_account(&did).await.unwrap();
            assert!(row.takedown_ref.is_none());
        }

        #[tokio::test]
        async fn a_takedown_lift_leaves_a_suspension_in_force() {
            let (ctx, did) = ctx_with_account("partial.localhost").await;
            moderate(&ctx, &did, ModerationAction::Takedown, None).await;
            moderate(&ctx, &did, ModerationAction::Suspend, None).await;

            let mut tx = ctx.account_db.begin().await.unwrap();
            crate::admin::moderation::ModerationManager::restore_account_in_tx(
                &mut tx,
                &did,
                "did:plc:admin",
                "test",
                Lift::Takedowns,
            )
            .await
            .expect("restore");
            tx.commit().await.unwrap();
            assert_eq!(status(&ctx, &did).await, Some("suspended"));
        }

        #[tokio::test]
        async fn an_expired_suspension_ends_with_an_announcement() {
            let (ctx, did) = ctx_with_account("expired.localhost").await;
            moderate(
                &ctx,
                &did,
                ModerationAction::Suspend,
                Some(chrono::Duration::seconds(-5)),
            )
            .await;
            let before = account_events(&ctx).await;
            let announced = crate::jobs::tasks::cleanup_expired_suspensions(&ctx)
                .await
                .expect("cleanup");
            assert_eq!(announced, 1);
            assert_eq!(account_events(&ctx).await, before + 1);
            assert_eq!(status(&ctx, &did).await, None);

            // Nothing left to end, nothing announced.
            let again = crate::jobs::tasks::cleanup_expired_suspensions(&ctx)
                .await
                .expect("cleanup");
            assert_eq!(again, 0);
        }

        #[tokio::test]
        async fn a_deleted_account_is_announced_and_gone() {
            let (ctx, did) = ctx_with_account("deleted.localhost").await;
            ctx.account_manager
                .delete_account_permanent(&did)
                .await
                .expect("delete rows");
            let before = account_events(&ctx).await;
            finish_account_deletion(&ctx, &did).await.expect("finish");

            assert!(!ctx.actor_store.exists(&did).await, "repository removed");
            assert!(account_state(&ctx, &did).await.unwrap().is_none());
            let latest: String = sqlx::query_scalar(
                "SELECT did FROM repo_seq WHERE event_type = 'account' AND invalidated = 0
                 ORDER BY seq DESC LIMIT 1",
            )
            .fetch_one(&ctx.account_db)
            .await
            .unwrap();
            assert_eq!(latest, did);
            // Earlier events of the account are removed; the deletion stays.
            let remaining: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM repo_seq WHERE did = $1 AND invalidated = 0",
            )
            .bind(&did)
            .fetch_one(&ctx.account_db)
            .await
            .unwrap();
            assert_eq!(remaining, 1);
            assert!(account_events(&ctx).await <= before + 1);
            let err = repo_status(&ctx, &did).await.expect_err("gone");
            assert!(matches!(err, PdsError::RepoNotFound(_)), "{err:?}");
        }

        #[tokio::test]
        async fn the_purge_deletes_an_account_past_its_delete_after() {
            let (ctx, did) = ctx_with_account("purged.localhost").await;
            ctx.account_manager
                .deactivate_account(&did)
                .await
                .expect("deactivate");
            ctx.account_manager
                .set_delete_after(&did, chrono::Utc::now() - chrono::Duration::minutes(1))
                .await
                .expect("deleteAfter");
            let purged = crate::jobs::tasks::purge_deleted_accounts(&ctx)
                .await
                .expect("purge");
            assert_eq!(purged, 1);
            assert!(account_state(&ctx, &did).await.unwrap().is_none(), "row gone");
            assert!(!ctx.actor_store.exists(&did).await, "repository removed");
        }

        async fn put_blob_metadata(ctx: &AppContext, cid: &str, creator: &str) {
            sqlx::query(
                "INSERT INTO blob_metadata (cid, mime_type, size, creator_did, created_at)
                 VALUES ($1, 'image/png', 1, $2, $3)",
            )
            .bind(cid)
            .bind(creator)
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&ctx.account_db)
            .await
            .expect("blob metadata");
        }

        async fn sync_get_blob(ctx: &AppContext, did: &str, cid: &str) -> PdsError {
            let params =
                serde_json::from_value(serde_json::json!({ "did": did, "cid": cid })).unwrap();
            match crate::api::sync::get_blob(
                State(ctx.clone()),
                axum::http::HeaderMap::new(),
                Query(params),
            )
            .await
            {
                Ok(_) => panic!("expected a refusal"),
                Err(e) => e,
            }
        }

        #[tokio::test]
        async fn a_blob_is_served_only_under_its_owners_name() {
            let (ctx, owner) = ctx_with_account("owner.localhost").await;
            let other = add_account(&ctx, "other.localhost").await;
            put_blob_metadata(&ctx, "bafyownedblob", &owner).await;

            assert_eq!(
                ctx.blob_store.owners("bafyownedblob").await.unwrap(),
                vec![owner.clone()]
            );
            let err = sync_get_blob(&ctx, &other, "bafyownedblob").await;
            assert!(matches!(err, PdsError::BlobNotFound(_)), "{err:?}");

            // A taken-down owner's blob is refused under its own name too.
            moderate(&ctx, &owner, ModerationAction::Takedown, None).await;
            let err = sync_get_blob(&ctx, &owner, "bafyownedblob").await;
            assert!(matches!(err, PdsError::RepoTakendown(_)), "{err:?}");
        }

        #[tokio::test]
        async fn deletion_keeps_blobs_another_account_uses() {
            let (ctx, gone) = ctx_with_account("leaving.localhost").await;
            let stays = add_account(&ctx, "staying.localhost").await;
            put_blob_metadata(&ctx, "bafyshared", &gone).await;
            put_blob_metadata(&ctx, "bafyonlymine", &gone).await;
            sqlx::query(
                "INSERT INTO record_blob (blob_cid, record_uri, indexed_at) VALUES ($1, $2, $3)",
            )
            .bind("bafyshared")
            .bind(format!("at://{stays}/app.bsky.feed.post/1"))
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&ctx.account_db)
            .await
            .expect("record_blob");

            let removed = ctx.blob_store.delete_account_blobs(&gone).await;
            // The backend has no bytes for these test rows; what matters is
            // which rows are chosen.
            let _ = removed;
            let left: Vec<String> =
                sqlx::query_scalar("SELECT cid FROM blob_metadata ORDER BY cid")
                    .fetch_all(&ctx.account_db)
                    .await
                    .unwrap();
            assert!(left.contains(&"bafyshared".to_string()), "{left:?}");
        }

        #[tokio::test]
        async fn a_handle_in_repo_resolves_to_its_account() {
            let (ctx, did) = ctx_with_account("named.localhost").await;
            assert_eq!(
                crate::api::repo::resolve_repo(&ctx, "named.localhost").await.unwrap(),
                did
            );
            assert_eq!(
                crate::api::repo::resolve_repo(&ctx, "Named.Localhost").await.unwrap(),
                did
            );
            assert_eq!(crate::api::repo::resolve_repo(&ctx, &did).await.unwrap(), did);
            for unknown in ["nobody.localhost", "someone@example.com"] {
                let err = crate::api::repo::resolve_repo(&ctx, unknown)
                    .await
                    .expect_err("unknown");
                assert!(matches!(err, PdsError::RepoNotFound(_)), "{unknown}: {err:?}");
            }
        }

        #[tokio::test]
        async fn the_account_itself_reads_its_inactive_repository() {
            let (ctx, did) = ctx_with_account("selfread.localhost").await;
            ctx.account_manager
                .deactivate_account(&did)
                .await
                .expect("deactivate");
            crate::api::repo::assert_readable_by(&ctx, &did, Some(&did))
                .await
                .expect("self may read");
            let err = crate::api::repo::assert_readable_by(&ctx, &did, None)
                .await
                .expect_err("others may not");
            assert!(matches!(err, PdsError::RepoDeactivated(_)), "{err:?}");
        }

        #[tokio::test]
        async fn list_repos_pages_past_accounts_without_a_repository() {
            let ctx =
                crate::api::federation_peers::test_support::create_test_context_with(|_| {})
                    .await;
            add_account(&ctx, "first.localhost").await;
            add_account(&ctx, "second.localhost").await;

            // Neither account has a repository root yet, so each page returns
            // no repositories; the listing must still page to the end.
            let mut cursor: Option<String> = None;
            let mut pages = 0;
            loop {
                let mut query = serde_json::json!({ "limit": 1 });
                if let Some(c) = &cursor {
                    query["cursor"] = serde_json::json!(c);
                }
                let params = serde_json::from_value(query).unwrap();
                let resp = crate::api::sync::list_repos(State(ctx.clone()), Query(params))
                    .await
                    .expect("listRepos");
                let body = serde_json::to_value(resp.0).unwrap();
                pages += 1;
                match body.get("cursor").and_then(|c| c.as_str()) {
                    Some(c) => cursor = Some(c.to_string()),
                    None => break,
                }
                assert!(pages < 10, "listing does not end");
            }
            assert!(pages >= 2, "the listing stopped at the first page");
        }
    }

    #[test]
    fn the_event_carries_the_state() {
        let mut deactivated = account();
        deactivated.deactivated_at = Some(Utc::now());
        let event = state_of(&deactivated, ModerationFlags::default()).event("did:plc:state");
        assert_eq!(event.did, "did:plc:state");
        assert!(!event.active);
        assert_eq!(event.status, Some(AccountStatus::Deactivated));
    }
}
