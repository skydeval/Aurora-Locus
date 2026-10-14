//! Sync Protocol Helper Functions
//!
//! Shared utilities for ATProto sync endpoints (com.atproto.sync.*)

use crate::{
    account::AccountManager,
    error::{PdsError, PdsResult},
};

/// Check if repository is available for sync access
///
/// This mimics Bluesky's `assertRepoAvailability` function.
///
/// # Behavior
///
/// - Returns `Ok(())` if repo is accessible
/// - Returns `Err(RepoNotFound)` if account doesn't exist
/// - Returns `Err(RepoTakendown)` if takendown (unless `is_admin_or_self`)
/// - Returns `Err(RepoDeactivated)` if deactivated (unless `is_admin_or_self`)
///
/// # Arguments
///
/// * `account_manager` - The account manager to check account status
/// * `did` - The DID to check
/// * `is_admin_or_self` - Whether the requester is an admin or the repo owner
///
/// # Returns
///
/// Ok(()) if the repo is available, or an appropriate error
pub async fn assert_repo_availability(
    account_manager: &AccountManager,
    did: &str,
    is_admin_or_self: bool,
) -> PdsResult<()> {
    // Arc 14 §7.3.5 / §7.6.5: typed-error envelope per Sub-step 0.D
    // Case A. RepoNotFound when the actor row is absent.
    let account = match account_manager.get_account(did).await {
        Ok(a) => a,
        Err(PdsError::NotFound(_)) => {
            return Err(PdsError::RepoNotFound(did.to_string()));
        }
        Err(e) => return Err(e),
    };

    // Admins and repo owners can access any repo state.
    if is_admin_or_self {
        return Ok(());
    }

    if account.takedown_ref.is_some() {
        return Err(PdsError::RepoTakendown(did.to_string()));
    }

    if account.deactivated_at.is_some() {
        return Err(PdsError::RepoDeactivated(did.to_string()));
    }

    // Arc 14 §7.3.6 / migration 0010: suspended/desync columns. In
    // v0.5 these are populated only by test-affordance direct DB
    // writes (no production setter yet — v0.6+ for both).
    if account.suspended_at.is_some() {
        return Err(PdsError::RepoSuspended(did.to_string()));
    }

    if account.desynchronized_at.is_some() {
        return Err(PdsError::RepoDesynchronized(did.to_string()));
    }

    Ok(())
}

/// Refuse a read of a repository that is not active (#491): everything
/// [`assert_repo_availability`] refuses, plus an account under an active
/// moderation suspension.
///
/// The suspension check is separate because an operator's Suspend action is
/// recorded in `account_moderation`, not in the actor row's `suspended_at`
/// column that `assert_repo_availability` reads; on its own that check lets a
/// suspended account through. A failed suspension lookup fails the request
/// rather than serving the repository.
///
/// The repository's own account and admins may still read (`is_admin_or_self`),
/// as in the reference PDS. The refusal is `RepoNotFound`, `RepoTakendown`,
/// `RepoDeactivated`, `RepoSuspended` or `RepoDesynchronized`; it is never a
/// record-level "not found", which consumers read as "this record was
/// deleted".
pub async fn assert_repo_readable(
    ctx: &crate::context::AppContext,
    did: &str,
    is_admin_or_self: bool,
) -> PdsResult<()> {
    assert_repo_availability(&ctx.account_manager, did, is_admin_or_self).await?;
    if !is_admin_or_self && ctx.moderation_manager.is_suspended(did).await? {
        return Err(PdsError::RepoSuspended(did.to_string()));
    }
    Ok(())
}
