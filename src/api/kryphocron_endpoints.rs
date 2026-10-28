//! v0.7 arc 2 step 5 — dedicated user-class kryphocron endpoints.
//!
//! Four XRPC procedures per the arc 2 kickoff §5:
//!
//! - `tools.kryphocron.feed.createPostPrivate` — capability
//!   `EditPrivatePost` (user class). Creates a
//!   `tools.kryphocron.feed.postPrivate` record.
//! - `tools.kryphocron.feed.deletePostPrivate` — capability
//!   `DeletePrivatePost` (user class). Deletes a
//!   `tools.kryphocron.feed.postPrivate` record.
//! - `tools.kryphocron.actor.participatePrivate` — capability
//!   `ParticipatePrivate` (user class). Creates a
//!   `tools.kryphocron.feed.postPrivate` record positioned as a
//!   reply to an existing private post. The writer is checked
//!   against the audience the reply names before anything is
//!   written; this is the only procedure that stores a post under
//!   an audience the writer does not own (#495).
//! - `tools.kryphocron.policy.manageAudience` — capability
//!   `ManageAudience` (user class). Creates / updates a
//!   `tools.kryphocron.policy.audience` record.
//!
//! Each handler authenticates via Aurora-Locus's existing
//! `require_auth_unified` flow, enforces the appropriate OAuth
//! scope, builds a `RepositoryManager` via `for_writer` (which
//! plumbs the shared pool needed for the relay-race lent-tx
//! mechanism), constructs a `WriteOp` with
//! `kryphocron_authorization:
//! Some(KryphocronWriteAuthorization::DedicatedEndpoint {
//! capability_class: CapabilityClass::User })`, and routes through
//! `apply_writes`.
//!
//! Inside `apply_writes`, the step-5-restructured validate loop
//! threads the lent shared tx into `validate_write`, whose
//! kryphocron-prefix dispatcher routes the `Some(_)`-authorized
//! write into `bind_pipeline`. Step 4 wired the framework + 5
//! match arms; this is the first production code path that
//! constructs a `Some(_)` authorization, so it's the first commit
//! where `bind_pipeline` is reachable from the production write
//! path. Step 7 will add the per-capability bind-pipeline stages
//! (oracle calls, audit-emit payloads). Until step 7 ships, the
//! `DedicatedEndpoint` arm just emits the
//! `kryphocron_bind_pipeline_authorized` tracing event and returns
//! Ok.

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use proto_blue::common::next_tid;
use serde::{Deserialize, Serialize};

use crate::{
    actor_store::{repository::WriteOpAction, RepositoryManager, WriteOp},
    api::{middleware, repo::create_actor_signer},
    auth::AuthenticatedDid,
    context::AppContext,
    error::{PdsError, PdsResult},
    kryphocron::{CapabilityClass, KryphocronWriteAuthorization},
    kryphocron_audience::{audience_owner, audience_reference, parse_record_uri, AudienceRef},
    kryphocron_audit::{AudienceCheckDeniedPayload, AudienceCheckResult},
    oauth::AtProtoScope,
};

/// Record collection NSIDs the four dedicated endpoints write to.
/// Held as constants so the deny-map population
/// ([`crate::kryphocron::build_deny_map`]) can route the same
/// names through the `RequiresDedicatedEndpoint` rewrite without
/// duplicating string literals.
pub(crate) const NSID_POST_PRIVATE: &str = "tools.kryphocron.feed.postPrivate";
pub(crate) const NSID_AUDIENCE: &str = "tools.kryphocron.policy.audience";
/// `graph.block` record collection (Arc H §7.2.5 / #281). Private-tier; written
/// only via the dedicated `createBlock`/`deleteBlock` procedures.
pub(crate) const NSID_BLOCK: &str = "tools.kryphocron.graph.block";

/// XRPC procedure NSIDs (the dedicated-endpoint paths the
/// `RequiresDedicatedEndpoint` suggested_endpoint field points to).
pub(crate) const PROC_CREATE_POST_PRIVATE: &str = "tools.kryphocron.feed.createPostPrivate";
pub(crate) const PROC_DELETE_POST_PRIVATE: &str = "tools.kryphocron.feed.deletePostPrivate";
pub(crate) const PROC_PARTICIPATE_PRIVATE: &str = "tools.kryphocron.actor.participatePrivate";
pub(crate) const PROC_MANAGE_AUDIENCE: &str = "tools.kryphocron.policy.manageAudience";
pub(crate) const PROC_UPDATE_POST_PRIVATE: &str = "tools.kryphocron.feed.updatePostPrivate";
pub(crate) const PROC_DELETE_AUDIENCE: &str = "tools.kryphocron.policy.deleteAudience";
/// `graph.block` create/delete procedures (#281). The routes are intentionally
/// NOT registered in [`routes`] until #282 wires the block cascade (rev4 F6/M-5)
/// — a `createBlock` that persists the block without removing the blocked DID
/// from the blocker's audiences would be a silent privacy failure.
pub(crate) const PROC_CREATE_BLOCK: &str = "tools.kryphocron.graph.createBlock";
pub(crate) const PROC_DELETE_BLOCK: &str = "tools.kryphocron.graph.deleteBlock";

/// Build the four route bindings. Plain `.route(...)` per the arc
/// 2 recon R2 finding: user-class endpoints aren't advertised in
/// `RouteRegistry` (which is admin-tier only).
pub fn routes() -> Router<AppContext> {
    let mounted = Router::new()
        .route(
            &format!("/xrpc/{PROC_CREATE_POST_PRIVATE}"),
            post(create_post_private),
        )
        .route(
            &format!("/xrpc/{PROC_DELETE_POST_PRIVATE}"),
            post(delete_post_private),
        )
        .route(
            &format!("/xrpc/{PROC_PARTICIPATE_PRIVATE}"),
            post(participate_private),
        )
        .route(
            &format!("/xrpc/{PROC_MANAGE_AUDIENCE}"),
            post(manage_audience),
        )
        .route(
            &format!("/xrpc/{PROC_UPDATE_POST_PRIVATE}"),
            post(update_post_private),
        )
        .route(
            &format!("/xrpc/{PROC_DELETE_AUDIENCE}"),
            post(delete_audience),
        );

    // #282 — the `graph.block` cascade now ships, so the create/delete routes
    // are registered. (#281 built these routes but deliberately left them
    // unmerged — a `createBlock` that persisted a block without cascading the
    // audience removals would be a silent privacy failure. `create_block` now
    // runs the cascade pass after the block-create, so the public route is
    // safe to mount.) The former `routes_omit_block_endpoints` tripwire is
    // inverted to assert the routes ARE present.
    let block_routes = Router::<AppContext>::new()
        .route(&format!("/xrpc/{PROC_CREATE_BLOCK}"), post(create_block))
        .route(&format!("/xrpc/{PROC_DELETE_BLOCK}"), post(delete_block));

    mounted.merge(block_routes)
}

/// Common request shape for the three create-style endpoints:
/// the importing repo's DID, an optional rkey, and the record body
/// the substrate's lexicons will validate.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateLikeRequest {
    repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validate: Option<bool>,
    record: serde_json::Value,
}

/// Delete-shaped request: repo + rkey of the record to delete.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteLikeRequest {
    repo: String,
    rkey: String,
}

/// `manageAudience` request: as [`CreateLikeRequest`], plus the swap for an
/// update of an existing record.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManageAudienceRequest {
    repo: String,
    #[serde(default)]
    rkey: Option<String>,
    #[serde(default)]
    validate: Option<bool>,
    #[serde(default)]
    swap_record: Option<String>,
    record: serde_json::Value,
}

/// `updatePostPrivate` request (A-9).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePostPrivateRequest {
    repo: String,
    rkey: String,
    audience_list: String,
    #[serde(default)]
    swap_record: Option<String>,
}

/// Bsky-style createRecord response: uri + cid.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteResponse {
    uri: String,
    cid: String,
}

/// Helper — verify caller is authenticated, OAuth scope is OK,
/// and `req.repo` matches the authenticated DID. Returns the DID
/// for the handler to use downstream.
async fn authenticated_did_for_repo(
    ctx: &AppContext,
    headers: HeaderMap,
    requested_repo: &str,
    scope: AtProtoScope,
) -> PdsResult<AuthenticatedDid> {
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers).await?;
    middleware::enforce_scope(&auth, &scope)?;
    if auth.is_cross_pds() {
        ctx.rate_limiter
            .check_cross_pds(&crate::rate_limit::CallerKey::Account(auth.did().to_string()))?;
    }
    let auth_did = auth.did();
    if requested_repo != auth_did {
        return Err(PdsError::Authorization(
            "Cannot write into another user's repo via kryphocron \
             dedicated endpoint"
                .to_string(),
        ));
    }
    // Per-account capability-issuance gate (#316 / §6.6.2 item 4): a SuperAdmin
    // can block a specific account from issuing kryphocron capabilities at all.
    // This chokepoint covers every dedicated-endpoint write (postPrivate /
    // participatePrivate / block …), so the block is enforced uniformly here —
    // a host-side gate, not a substrate concept. Default (no override) = allowed.
    if crate::kryphocron_override::capability_blocked(&ctx.account_db, auth_did).await {
        return Err(PdsError::Authorization(
            "this account is blocked from issuing kryphocron capabilities \
             (per-account override)"
                .to_string(),
        ));
    }
    // New-account access policy (#334 / §6.6.2 item 1): when the deployment runs
    // `delayed` access, an account younger than the delay window can't issue any
    // kryphocron capability yet — the host-side guard the design places "before
    // the kryphocron capability is even issued". Default `immediate` is open;
    // the check is fail-soft (a settings hiccup never blocks). Same chokepoint as
    // the capability-issuance gate above, so it covers every dedicated write.
    if let Some(days) = crate::kryphocron_policy::new_account_access_delay_remaining(
        &ctx.account_db,
        auth_did,
        chrono::Utc::now(),
    )
    .await
    {
        return Err(PdsError::Authorization(format!(
            "this account cannot use private-tier writes yet: the deployment \
             delays new-account access (about {days} day(s) remaining)"
        )));
    }
    // This is THE request-auth chokepoint: the requester is authenticated, the
    // scope is enforced, and the target repo is confirmed to be the requester's
    // own. Wrap the validated DID so the write helpers take `AuthenticatedDid`,
    // not a bare `&str` (Arc H §7.2.5 / #281; see `AuthenticatedDid` rustdoc).
    Ok(AuthenticatedDid::from_authenticated(auth_did.to_string()))
}

/// Helper — apply a single kryphocron-authorized create `WriteOp`
/// and return the record's URI and CID (the stored record's, not the
/// commit's: A-1). Wraps the `repo_mgr.apply_writes` call so the
/// create-style endpoints share the same plumbing.
async fn apply_single_create(
    ctx: &AppContext,
    auth: &AuthenticatedDid,
    collection: &str,
    rkey: Option<String>,
    record: serde_json::Value,
    validate: Option<bool>,
) -> PdsResult<WriteResponse> {
    let auth_did = auth.value();
    let rkey = rkey.unwrap_or_else(|| next_tid(None).to_string());
    let repo_mgr = RepositoryManager::for_writer(ctx, auth_did.to_string());
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    let write = WriteOp {
        action: WriteOpAction::Create,
        collection: collection.to_string(),
        rkey: rkey.clone(),
        value: Some(record),
        validate,
        swap_cid: None,
        kryphocron_authorization: Some(KryphocronWriteAuthorization::DedicatedEndpoint {
            capability_class: CapabilityClass::User,
            prior: None,
        }),
    };

    let outcome = repo_mgr
        .apply_writes_detailed(
            vec![write],
            signer,
            Arc::new(crate::blob_store::StrictPromoter),
        )
        .await?;

    Ok(WriteResponse {
        uri: format!("at://{auth_did}/{collection}/{rkey}"),
        cid: outcome.single_record_cid()?,
    })
}

/// A record of the writer's own repository as stored: its CID and value.
struct StoredRecord {
    cid: String,
    value: serde_json::Value,
}

/// Read one record of `did`'s repository. `None` when there is no such
/// record.
///
/// # Errors
///
/// A store error, or `PdsError::Internal` when the record is indexed but its
/// block is missing or does not decode.
async fn read_own_record(
    ctx: &AppContext,
    did: &str,
    collection: &str,
    rkey: &str,
) -> PdsResult<Option<StoredRecord>> {
    let uri = format!("at://{did}/{collection}/{rkey}");
    let Some(record) = ctx.actor_store.get_record(did, &uri).await? else {
        return Ok(None);
    };
    let block = ctx
        .actor_store
        .get_block(did, &record.cid)
        .await?
        .ok_or_else(|| PdsError::Internal(format!("{uri}: record block is missing")))?;
    let lex = proto_blue::lex_cbor::decode(&block)
        .map_err(|e| PdsError::Internal(format!("{uri}: record does not decode: {e}")))?;
    Ok(Some(StoredRecord {
        cid: record.cid,
        value: proto_blue::lex_json::lex_to_json(&lex),
    }))
}

/// Refuse a write whose `swapRecord` does not name the record's current CID:
/// 409 `InvalidSwap`, as `putRecord`.
fn check_swap(current: &StoredRecord, swap_cid: Option<&str>, path: &str) -> PdsResult<()> {
    match swap_cid {
        Some(expected) if expected != current.cid => Err(PdsError::SwapCidMismatch(format!(
            "{path}: expected '{expected}', found '{}'",
            current.cid
        ))),
        _ => Ok(()),
    }
}

/// Helper — replace `current`, an existing record of the writer's own
/// repository, with `record`, under the same `DedicatedEndpoint`/`User`
/// authorization as [`apply_single_create`], and return its URI and new
/// record CID. The caller has already checked any `swapRecord` against
/// `current` ([`check_swap`]).
async fn apply_single_update(
    ctx: &AppContext,
    auth: &AuthenticatedDid,
    collection: &str,
    rkey: &str,
    record: serde_json::Value,
    current: StoredRecord,
) -> PdsResult<WriteResponse> {
    let auth_did = auth.value();
    let repo_mgr = RepositoryManager::for_writer(ctx, auth_did.to_string());
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    let write = WriteOp {
        action: WriteOpAction::Update,
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        value: Some(record),
        validate: None,
        swap_cid: Some(current.cid),
        kryphocron_authorization: Some(KryphocronWriteAuthorization::DedicatedEndpoint {
            capability_class: CapabilityClass::User,
            prior: Some(current.value),
        }),
    };

    let outcome = repo_mgr
        .apply_writes_detailed(
            vec![write],
            signer,
            Arc::new(crate::blob_store::StrictPromoter),
        )
        .await?;

    Ok(WriteResponse {
        uri: format!("at://{auth_did}/{collection}/{rkey}"),
        cid: outcome.single_record_cid()?,
    })
}

/// Helper — apply a single kryphocron-authorized delete `WriteOp` for the
/// authenticated writer's own repo. The delete-side analog of
/// [`apply_single_create`]; shares the `DedicatedEndpoint`/`User` authorization
/// so the dispatcher routes through `bind_pipeline`, not the deny-map.
///
/// Deleting a record that is not there succeeds without a commit, as
/// `deleteRecord` does; the tree delete would otherwise fail on the
/// missing key.
async fn apply_single_delete(
    ctx: &AppContext,
    auth: &AuthenticatedDid,
    collection: &str,
    rkey: String,
) -> PdsResult<()> {
    let auth_did = auth.value();
    let Some(current) = read_own_record(ctx, auth_did, collection, &rkey).await? else {
        return Ok(());
    };
    let repo_mgr = RepositoryManager::for_writer(ctx, auth_did.to_string());
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    let write = WriteOp {
        action: WriteOpAction::Delete,
        collection: collection.to_string(),
        rkey,
        value: None,
        validate: None,
        swap_cid: None,
        kryphocron_authorization: Some(KryphocronWriteAuthorization::DedicatedEndpoint {
            capability_class: CapabilityClass::User,
            prior: Some(current.value),
        }),
    };

    repo_mgr
        .apply_writes(
            vec![write],
            signer,
            Arc::new(crate::blob_store::StrictPromoter),
        )
        .await?;
    Ok(())
}

/// What both private-post procedures require before they read anything
/// (#495): the record is a JSON object, the private tier is switched on, and
/// the writer's repository is held here. Each answer depends on the request
/// or the caller alone, never on another account's records.
///
/// The repository test matters because authentication also accepts tokens
/// for accounts hosted elsewhere; such a caller could otherwise put questions
/// to the audience check without being able to write.
async fn private_post_preconditions(
    ctx: &AppContext,
    writer_did: &str,
    record: &serde_json::Value,
) -> PdsResult<()> {
    if !record.is_object() {
        return Err(PdsError::Validation(
            "record must be an object".to_string(),
        ));
    }
    if !ctx.config.kryphocron.enabled {
        return Err(PdsError::UnsupportedNamespace {
            nsid: NSID_POST_PRIVATE.to_string(),
        });
    }
    if !ctx.actor_store.exists(writer_did).await {
        return Err(PdsError::Authorization(
            "private-tier posts can only be written by an account hosted on this PDS"
                .to_string(),
        ));
    }
    Ok(())
}

/// `createPostPrivate` writes under the writer's own audiences only (#495).
/// A record that names another account's audience is refused here: that is
/// what `participatePrivate` is for, and it checks the writer against the
/// audience first. A record naming no audience is accepted; it is readable
/// by its author alone.
///
/// The test is on the caller's own input, so the refusal says what is wrong.
fn require_own_audience(record: &serde_json::Value, writer_did: &str) -> PdsResult<()> {
    match audience_reference(record) {
        AudienceRef::None => Ok(()),
        AudienceRef::Malformed => Err(PdsError::Validation(
            "record.audienceList must be the at:// URI of an audience record".to_string(),
        )),
        AudienceRef::Uri(uri) => {
            if audience_owner(&uri) == Some(writer_did) {
                Ok(())
            } else {
                Err(PdsError::Validation(format!(
                    "{PROC_CREATE_POST_PRIVATE} writes under one of the writer's own \
                     audiences; to reply under another account's audience use \
                     {PROC_PARTICIPATE_PRIVATE}"
                )))
            }
        }
    }
}

/// Where a reply written with `createPostPrivate` may sit. A record without a
/// `reply` passes. Otherwise it is one of:
///
/// - **a branch root** (A-13): its parent is a public post, so it starts a
///   private branch under the writer's own audience (checked by
///   [`require_own_audience`]); `reply.root` must then be public too (the
///   public thread's root). Nothing is walked.
/// - **a reply in the writer's own private thread or branch**, naming its
///   root's (or branch root's) current audience ([`crate::kryphocron_thread`]).
///
/// A reply in another account's thread or branch goes through
/// `participatePrivate`.
async fn require_own_thread(
    ctx: &AppContext,
    record: &serde_json::Value,
    writer_did: &str,
) -> PdsResult<()> {
    use crate::kryphocron_thread::{is_private, reply_uri, Unanchored};
    if record.get("reply").is_none_or(|reply| reply.is_null()) {
        return Ok(());
    }
    let (Some(parent_uri), Some(root_uri)) = (reply_uri(record, "parent"), reply_uri(record, "root"))
    else {
        return Err(PdsError::Validation(
            "record.reply needs parent.uri and root.uri, each an at:// record URI".to_string(),
        ));
    };
    if !is_private(&parent_uri) {
        if is_private(&root_uri) {
            return Err(PdsError::Validation(
                "a reply to a public post sits in a public thread: its reply.root is that \
                 thread's public root"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    // Someone else's private thread: refused before anything is read.
    if is_private(&root_uri) && parse_record_uri(&root_uri).map(|uri| uri.did) != Some(writer_did) {
        return Err(not_own_thread());
    }
    let AudienceRef::Uri(audience_uri) = audience_reference(record) else {
        return Err(PdsError::Validation(
            "a reply names its thread's audience: the current audienceList of its root \
             (or of its branch's root)"
                .to_string(),
        ));
    };
    // Every refusal past this point is the same answer: the walk may read
    // other accounts' private posts (a branch is found by walking up to it),
    // and a reason would tell the caller whether such a post exists or which
    // public post it sits under. The reason is logged instead.
    match crate::kryphocron_thread::check_reply_thread(ctx, writer_did, record, &audience_uri).await
    {
        Ok(anchor) if anchor.author == writer_did => Ok(()),
        Err(Unanchored::RateLimited) => Err(PdsError::RateLimitExceeded {
            retry_after: std::time::Duration::from_secs(60),
        }),
        outcome => {
            tracing::info!(
                target: "aurora_locus::kryphocron",
                event = "create_post_private_reply_refused",
                writer_did = %writer_did,
                outcome = ?outcome,
                "createPostPrivate reply refused: not in the writer's own thread or branch \
                 under its current audience",
            );
            Err(not_own_thread())
        }
    }
}

/// The one refusal for a `createPostPrivate` reply that is not in the
/// writer's own thread or branch, under its root's current audience.
fn not_own_thread() -> PdsError {
    PdsError::Validation(format!(
        "{PROC_CREATE_POST_PRIVATE} replies only in the writer's own thread or branch, naming \
         its root's current audienceList; to reply in another account's use \
         {PROC_PARTICIPATE_PRIVATE}"
    ))
}

/// `tools.kryphocron.feed.createPostPrivate` — create a
/// `tools.kryphocron.feed.postPrivate` record under the
/// `EditPrivatePost` (user-class) capability. The bind pipeline
/// runs during `apply_writes`'s validate loop.
///
/// The record may name only an audience in the writer's own repository
/// ([`require_own_audience`]). It may carry a `reply` only in the writer's
/// own thread (the writer wrote its root), and must then name the root's
/// current audience: a thread's audience is its root's, downthread (A-12).
/// Replies in another account's thread go through `participatePrivate`,
/// which checks the writer against that thread's audience.
async fn create_post_private(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<CreateLikeRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoCreate).await?;
    private_post_preconditions(&ctx, auth_did.value(), &req.record).await?;
    require_own_audience(&req.record, auth_did.value())?;
    require_own_thread(&ctx, &req.record, auth_did.value()).await?;

    // #236 — encode-on-write floor. Fix the rkey up-front (so the
    // at-rest content context's rkey matches the stored record), then
    // run the record's `text` through the installed codec before it
    // reaches the write path. No-op when kryphocron is disabled.
    let rkey = req.rkey.unwrap_or_else(|| next_tid(None).to_string());
    let mut record = req.record;
    crate::kryphocron_content::encode_private_content(
        &ctx,
        auth_did.value(),
        NSID_POST_PRIVATE,
        &rkey,
        &mut record,
    )
    .await?;

    let resp = apply_single_create(
        &ctx,
        &auth_did,
        NSID_POST_PRIVATE,
        Some(rkey),
        record,
        req.validate,
    )
    .await?;
    Ok(Json(resp))
}

/// `tools.kryphocron.feed.deletePostPrivate` — delete a
/// `tools.kryphocron.feed.postPrivate` record under the
/// `DeletePrivatePost` (user-class) capability. Constructs the
/// delete `WriteOp` with the same `DedicatedEndpoint`
/// authorization so the dispatcher routes through
/// `bind_pipeline` rather than the deny-map.
async fn delete_post_private(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<DeleteLikeRequest>,
) -> PdsResult<Json<serde_json::Value>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoDelete).await?;
    apply_single_delete(&ctx, &auth_did, NSID_POST_PRIVATE, req.rkey).await?;
    Ok(Json(serde_json::json!({})))
}

/// `tools.kryphocron.actor.participatePrivate` — participate in a
/// private thread under the `ParticipatePrivate` (user-class)
/// capability.
///
/// **What the record must carry.** A `reply.parent.uri` that is a record
/// URI, and an `audienceList` naming an audience record (as a string or as
/// `{ "uri": … }`). Either missing or malformed is a 400, decided from the
/// request alone. A post without a reply parent is what `createPostPrivate`
/// is for.
///
/// **The audience.** Who may write under another account's audience is the
/// AppView's to decide (#536): audiences are held there as member state, not
/// as records in a repository, so locus has none to read
/// ([`participate_audience`]). The AppView serves a reply only to readers its
/// audience rule admits.
///
/// **The thread check (#515, A-12).** A thread's audience is its root's
/// current one: an audience change applies downthread. The reply must name
/// exactly that audience, and must belong to the thread: walking up from its
/// parent, every post names an audience of the root's author (one the thread
/// had before a move counts) and agrees on the root, and a post by the root's
/// author is reached within a few posts. Posts held elsewhere are fetched
/// from their PDS within a fixed budget ([`crate::kryphocron_thread`]). So a
/// member added by a move may reply anywhere in the thread, and a member
/// removed by it nowhere. A reply that fails writes
/// `KryphocronAudienceCheckDenied` in its own short tx on the shared account
/// DB and gets a 403 with one fixed message, whatever the cause.
async fn participate_private(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<CreateLikeRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoCreate).await?;
    private_post_preconditions(&ctx, auth_did.value(), &req.record).await?;
    let (parent_uri, audience_uri) = participation_refs(&req.record)?;

    // #335 — instrument the write-side audience-oracle consultation (§6.4.1).
    // Aggregate counts only; surfaced by getOracleActivity.
    use crate::kryphocron_oracle_activity::OracleConsultation;
    match participate_audience(&audience_uri, auth_did.value()) {
        ParticipateAudienceOutcome::Owner => {
            ctx.audience_oracle_activity.record(OracleConsultation::WriteAllowed);
        }
        ParticipateAudienceOutcome::Deferred { audience_owner } => {
            ctx.audience_oracle_activity.record(OracleConsultation::WriteDeferred);
            tracing::debug!(
                target: "aurora_locus::kryphocron",
                event = "participate_private_audience_check_deferred",
                requester_did = %auth_did.value(),
                parent_uri = %parent_uri,
                audience_owner = %audience_owner,
                "audience check deferred to the AppView, which holds audiences",
            );
        }
    }

    // #515, A-12 — the reply must belong to a thread under the audience it
    // names, and that audience must be the thread's: the root's current one.
    // Its chain reaches a post by the root's author through posts under that
    // author's audiences.
    if let Err(reason) = crate::kryphocron_thread::check_reply_thread(
        &ctx,
        auth_did.value(),
        &req.record,
        &audience_uri,
    )
    .await
    {
        if reason == crate::kryphocron_thread::Unanchored::RateLimited {
            return Err(PdsError::RateLimitExceeded {
                retry_after: std::time::Duration::from_secs(60),
            });
        }
        if reason == crate::kryphocron_thread::Unanchored::BranchRoot {
            return Err(PdsError::Validation(format!(
                "a private reply to a public post starts a private branch under one of the \
                 writer's own audiences; write it with {PROC_CREATE_POST_PRIVATE}"
            )));
        }
        tracing::warn!(
            target: "aurora_locus::kryphocron",
            event = "participate_private_thread_unanchored",
            requester_did = %auth_did.value(),
            parent_uri = %parent_uri,
            audience_uri = %audience_uri,
            reason = ?reason,
            "reply refused: it is not part of a thread under its audience",
        );
        ctx.audience_oracle_activity.record(OracleConsultation::WriteDenied);
        let payload = AudienceCheckDeniedPayload {
            capability_attempted: "ParticipatePrivate".to_string(),
            subject_uri: parent_uri.clone(),
            requester_did: auth_did.value().to_string(),
            audience_uri: Some(audience_uri.clone()),
            audience_mode: "unknown".to_string(),
            audience_check_result: AudienceCheckResult::NoAudienceConfigured,
            trace_id: crate::kryphocron_audit::synthesize_trace_id(),
            payload_completeness: crate::kryphocron_audit::PayloadCompleteness::Full,
        };
        return Err(refuse_participation(&ctx, auth_did.value(), payload).await);
    }

    // #236 — encode-on-write floor (same seam as create_post_private),
    // applied after the audience pre-check passes and before the write.
    let rkey = req.rkey.unwrap_or_else(|| next_tid(None).to_string());
    let mut record = req.record;
    crate::kryphocron_content::encode_private_content(
        &ctx,
        auth_did.value(),
        NSID_POST_PRIVATE,
        &rkey,
        &mut record,
    )
    .await?;

    let resp = apply_single_create(
        &ctx,
        &auth_did,
        NSID_POST_PRIVATE,
        Some(rkey),
        record,
        req.validate,
    )
    .await?;
    Ok(Json(resp))
}

/// Write the `KryphocronAudienceCheckDenied` event in its own short tx on the
/// shared account DB and give the one refusal `participatePrivate` gives,
/// whatever the cause. A failure to record the event is that error instead.
async fn refuse_participation(
    ctx: &AppContext,
    writer_did: &str,
    payload: AudienceCheckDeniedPayload,
) -> PdsError {
    let recorded = async {
        let mut tx = ctx.account_db.begin().await.map_err(PdsError::Database)?;
        crate::kryphocron_audit::emit_audience_check_denied_in_tx(&mut tx, writer_did, payload)
            .await?;
        tx.commit().await.map_err(PdsError::Database)
    }
    .await;
    match recorded {
        Ok(()) => PdsError::Authorization("Audience check denied".to_string()),
        Err(e) => e,
    }
}

/// Read what `participatePrivate` needs from the record: the parent post's
/// URI and the reply's audience URI. Both tests are on the request alone.
fn participation_refs(record: &serde_json::Value) -> PdsResult<(String, String)> {
    let parent_uri = record
        .get("reply")
        .and_then(|r| r.get("parent"))
        .and_then(|p| p.get("uri"))
        .and_then(|u| u.as_str())
        .filter(|uri| parse_record_uri(uri).is_some())
        .ok_or_else(|| {
            PdsError::Validation(
                "participatePrivate requires record.reply.parent.uri: the at:// URI \
                 of the post being replied to"
                    .to_string(),
            )
        })?;
    let audience_uri = match audience_reference(record) {
        AudienceRef::Uri(uri) if audience_owner(&uri).is_some() => uri,
        _ => {
            return Err(PdsError::Validation(
                "participatePrivate requires record.audienceList: the at:// URI of \
                 the audience record of the post being replied to"
                    .to_string(),
            ));
        }
    };
    Ok((parent_uri.to_string(), audience_uri))
}

/// Who decides whether a writer may reply under an audience (#536).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParticipateAudienceOutcome {
    /// The writer owns the audience, so may always write under it.
    Owner,
    /// Another account's audience. Audiences are held by the AppView as member
    /// state, not as records in a repository, so locus has nothing to read and
    /// leaves the decision to the AppView's read rule. The handler logs it.
    Deferred { audience_owner: String },
}

/// Who decides whether `writer_did` may reply under `audience_uri` (#495,
/// #536). `audience_uri` was syntax-checked by [`participation_refs`].
/// Whether the reply belongs to its thread, and names the thread's audience,
/// is still checked here, by [`crate::kryphocron_thread`].
fn participate_audience(audience_uri: &str, writer_did: &str) -> ParticipateAudienceOutcome {
    match audience_owner(audience_uri) {
        Some(owner) if owner == writer_did => ParticipateAudienceOutcome::Owner,
        owner => ParticipateAudienceOutcome::Deferred {
            audience_owner: owner.unwrap_or_default().to_string(),
        },
    }
}

/// Read and decode one stored record. `None` when the record or its block is
/// absent, or when the block does not decode (logged): to the audience check
/// and the thread check ([`crate::kryphocron_thread`]) each of those is a
/// record that is not there.
pub(crate) async fn load_record_json(
    ctx: &AppContext,
    did: &str,
    uri: &str,
) -> PdsResult<Option<serde_json::Value>> {
    let Some(record) = ctx.actor_store.get_record(did, uri).await? else {
        return Ok(None);
    };
    let Some(block) = ctx.actor_store.get_block(did, &record.cid).await? else {
        return Ok(None);
    };
    match proto_blue::lex_cbor::decode(&block) {
        Ok(lex) => Ok(Some(proto_blue::lex_json::lex_to_json(&lex))),
        Err(e) => {
            tracing::error!(
                target: "aurora_locus::kryphocron",
                event = "audience_check_record_undecodable",
                uri = %uri,
                error = %e,
                "stored record does not decode; the audience check treats it as absent",
            );
            Ok(None)
        }
    }
}

/// Extract the owner DID from an `at://<did>/<collection>/<rkey>`
/// URI. Returns `None` if the URI doesn't match the expected
/// shape. `pub(crate)` so the read-side authorization resolver
/// ([`crate::kryphocron_content`]) can reuse it (#237a).
pub(crate) fn parse_at_uri_did(uri: &str) -> Option<String> {
    let after_scheme = uri.strip_prefix("at://")?;
    let did = after_scheme.split('/').next()?;
    if did.starts_with("did:") {
        Some(did.to_string())
    } else {
        None
    }
}

/// `tools.kryphocron.policy.manageAudience` — create or update a
/// `tools.kryphocron.policy.audience` record under the
/// `ManageAudience` (user-class) capability.
///
/// With the `rkey` of a record that exists, the record is replaced (A-4):
/// `swapRecord`, when given, must be its current CID (409 `InvalidSwap`).
/// Membership changes apply to every post that names the audience. Without
/// an `rkey`, or with one that names no record, a record is created and
/// `swapRecord` must be absent. The answer carries the record's CID.
async fn manage_audience(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<ManageAudienceRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoCreate).await?;
    if !req.record.is_object() {
        return Err(PdsError::Validation("record must be an object".to_string()));
    }
    let current = match req.rkey.as_deref() {
        Some(rkey) => read_own_record(&ctx, auth_did.value(), NSID_AUDIENCE, rkey).await?,
        None => None,
    };
    let resp = match (current, req.rkey) {
        (Some(current), Some(rkey)) => {
            let path = format!("{NSID_AUDIENCE}/{rkey}");
            check_swap(&current, req.swap_record.as_deref(), &path)?;
            apply_single_update(&ctx, &auth_did, NSID_AUDIENCE, &rkey, req.record, current)
                .await?
        }
        (_, rkey) => {
            if req.swap_record.is_some() {
                return Err(PdsError::Validation(
                    "swapRecord names a record to replace, and there is no audience \
                     record at this rkey"
                        .to_string(),
                ));
            }
            apply_single_create(&ctx, &auth_did, NSID_AUDIENCE, rkey, req.record, req.validate)
                .await?
        }
    };
    Ok(Json(resp))
}

/// `tools.kryphocron.policy.deleteAudience` — delete one of the writer's
/// `tools.kryphocron.policy.audience` records (A-4). Posts that still name it
/// are then readable by their authors only; nothing is reassigned. Deleting
/// an audience that is not there succeeds, as `deleteRecord` does. The audit
/// names the members the audience had.
async fn delete_audience(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<DeleteLikeRequest>,
) -> PdsResult<Json<serde_json::Value>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoDelete).await?;
    apply_single_delete(&ctx, &auth_did, NSID_AUDIENCE, req.rkey).await?;
    Ok(Json(serde_json::json!({})))
}

/// `tools.kryphocron.feed.updatePostPrivate` — move a posted private post to
/// another of the writer's audiences (A-9).
///
/// Only `audienceList` changes: every other field of the stored record is
/// kept, `encodedContent` included (the codec's seed is the originator, NSID
/// and rkey, so it decodes as before). The URI stays the same and the
/// answer carries the new record CID.
///
/// Refused with 400 `InvalidRequest`: no such post; a reply (a reply's
/// audience is its thread's), except a branch root, a private reply to a
/// public post, which anchors its branch as a root anchors its thread
/// (A-13); an `audienceList` that is not the URI of one of the writer's own
/// audiences (whether it exists is the AppView's to know, #536).
/// `swapRecord` must be the post's current CID (409 `InvalidSwap`).
///
/// The change applies downthread (A-12): replies already written keep their
/// own `audienceList` but are read under the root's new audience, and every
/// new reply anywhere in the thread must name the new audience, which
/// `participatePrivate` and `createPostPrivate` both require.
async fn update_post_private(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<UpdatePostPrivateRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoUpdate).await?;
    let writer = auth_did.value();
    let reference = serde_json::json!({ "audienceList": req.audience_list });
    private_post_preconditions(&ctx, writer, &reference).await?;
    // Ownership only: audiences are held by the AppView, not in the repo
    // (#536), so there is no record here to test for, as in createPostPrivate.
    if audience_owner(&req.audience_list) != Some(writer) {
        return Err(PdsError::Validation(
            "audienceList must be the at:// URI of one of the writer's own audience records"
                .to_string(),
        ));
    }

    let Some(current) = read_own_record(&ctx, writer, NSID_POST_PRIVATE, &req.rkey).await?
    else {
        return Err(PdsError::Validation(format!(
            "no private post at {NSID_POST_PRIVATE}/{}",
            req.rkey
        )));
    };
    // A branch root (A-13: a private reply whose parent is public) anchors its
    // branch as a root anchors its thread, so its author may move it; any
    // other reply's audience is its thread's or branch's.
    let is_branch_root = crate::kryphocron_thread::reply_uri(&current.value, "parent")
        .is_some_and(|parent| !crate::kryphocron_thread::is_private(&parent));
    if current.value.get("reply").is_some_and(|reply| !reply.is_null()) && !is_branch_root {
        return Err(PdsError::Validation(
            "a reply's audience is its thread's (or its branch's) and cannot be changed"
                .to_string(),
        ));
    }
    let path = format!("{NSID_POST_PRIVATE}/{}", req.rkey);
    check_swap(&current, req.swap_record.as_deref(), &path)?;

    let mut record = current.value.clone();
    record
        .as_object_mut()
        .ok_or_else(|| PdsError::Internal(format!("{path}: stored record is not an object")))?
        .insert(
            "audienceList".to_string(),
            serde_json::Value::String(req.audience_list),
        );
    let resp =
        apply_single_update(&ctx, &auth_did, NSID_POST_PRIVATE, &req.rkey, record, current)
            .await?;
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// graph.block entry-point substrate (Arc H §7.2.5 / #281)
//
// These two handlers are the user-facing block create/delete surface. They use
// the SAME `DedicatedEndpoint{User}` write path as the four endpoints above —
// not security-sensitive at #282's level (per the #280 design doc §1/§5).
//
// ROUTES REGISTERED IN #282 (rev4 F6/M-5). #281 shipped these handlers but left
// their routes UNMERGED, because a `createBlock` that persisted the block record
// without removing the blocked DID from the blocker's audiences would be a silent
// privacy failure. #282 wires the cascade pass into `create_block` (it walks the
// blocker's list-mode audiences and removes the subject — `crate::cascade`), so
// the routes are now safe to mount and `routes()` merges them.
// ---------------------------------------------------------------------------

/// `tools.kryphocron.graph.createBlock` — create a
/// `tools.kryphocron.graph.block` record (carrying `subject`, the blocked DID)
/// in the caller's own repo, under the `DedicatedEndpoint`/`User` authorization.
/// Private-tier, consumed by `BlockOracle` outside the normal capability flow
/// (§7.2.4). The record is not secret: its commit goes out on the firehose
/// like any other, so firehose readers can see who blocked whom (private is
/// friction, not encryption; kryphocron-lexicons 0.3.3). **Route intentionally unregistered until
/// #282** (see the module note above): this persists the block but does not yet
/// cascade the audience removals.
async fn create_block(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<CreateLikeRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoCreate).await?;
    // Recover the blocked subject from the record body before it is moved into
    // the write helper — the cascade pass and the audience audit both need it.
    let subject = req
        .record
        .get("subject")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let resp = apply_single_create(
        &ctx,
        &auth_did,
        NSID_BLOCK,
        req.rkey,
        req.record,
        req.validate,
    )
    .await?;
    // #282 — cascade the audience removals (§3.1): walk the blocker's list-mode
    // audiences, remove `subject` (swap_cid-pinned), mint per-write cascade
    // tokens, and emit the KryphocronBlockChanged pair + block-cascade.log. The
    // minting lives in `crate::cascade` (H-5 confinement). Best-effort and
    // forward-only: the block is already committed, so a cascade failure is
    // logged loudly and never un-commits the block.
    match subject {
        Some(subject) => {
            if let Err(e) =
                crate::cascade::run_block_cascade(&ctx, auth_did.value(), &subject, &resp.uri).await
            {
                tracing::error!(
                    target: "aurora_locus::kryphocron",
                    block_uri = %resp.uri,
                    error = %e,
                    "createBlock committed but the block cascade failed (block stays committed)",
                );
            }
        }
        None => {
            tracing::warn!(
                target: "aurora_locus::kryphocron",
                block_uri = %resp.uri,
                "createBlock record carries no `subject`; audience cascade skipped",
            );
        }
    }
    Ok(Json(resp))
}

/// `tools.kryphocron.graph.deleteBlock` — delete a
/// `tools.kryphocron.graph.block` record from the caller's repo. Forward-only
/// per §7.2.4: deleting a block does NOT re-add the subject to audiences (#282
/// emits the `removed: 0` audit). **Route intentionally unregistered until
/// #282** (see the module note above).
async fn delete_block(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<DeleteLikeRequest>,
) -> PdsResult<Json<serde_json::Value>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoDelete).await?;
    let block_uri = format!("at://{}/{}/{}", auth_did.value(), NSID_BLOCK, req.rkey);
    // Recover the subject before the record is gone, so the forward-only delete
    // audit can name it (best-effort — `None` if already absent).
    let subject = crate::cascade::read_block_subject(&ctx, auth_did.value(), &block_uri).await;
    apply_single_delete(&ctx, &auth_did, NSID_BLOCK, req.rkey).await?;
    // §3.3 forward-only: record the delete (KryphocronBlockChanged Deleted +
    // block-cascade.log removed:0); membership is NOT restored.
    crate::cascade::record_block_deleted(&ctx, auth_did.value(), subject.as_deref(), &block_uri)
        .await;
    Ok(Json(serde_json::json!({})))
}

#[cfg(test)]
mod participate_audience_tests {
    //! #495, #536: who decides whether a writer may reply under an audience.
    use super::*;
    use crate::kryphocron_audience::test_support::ctx_with_repos;
    use serde_json::json;

    const OWNER: &str = "did:plc:owner";
    const WRITER: &str = "did:plc:writer";
    const REMOTE: &str = "did:plc:elsewhere";

    fn audience_uri(did: &str) -> String {
        format!("at://{did}/{NSID_AUDIENCE}/aud")
    }

    fn post_uri(did: &str, rkey: &str) -> String {
        format!("at://{did}/{NSID_POST_PRIVATE}/{rkey}")
    }

    /// #536: audiences are held by the AppView, so locus reads no audience
    /// record. The owner may always write under its own audience; any other
    /// writer is left to the AppView, whoever holds the owner's repository.
    #[test]
    fn only_the_owner_is_decided_here_and_every_other_writer_is_deferred() {
        assert_eq!(
            participate_audience(&audience_uri(OWNER), OWNER),
            ParticipateAudienceOutcome::Owner
        );
        for owner in [OWNER, REMOTE] {
            assert_eq!(
                participate_audience(&audience_uri(owner), WRITER),
                ParticipateAudienceOutcome::Deferred {
                    audience_owner: owner.to_string()
                },
                "{owner}"
            );
        }
    }

    #[test]
    fn participation_refs_are_read_from_the_request_alone() {
        let parent = post_uri(OWNER, "p1");
        let audience = audience_uri(OWNER);
        let record = |audience_list: serde_json::Value, parent_uri: &str| {
            json!({
                "audienceList": audience_list,
                "reply": { "parent": { "uri": parent_uri } },
            })
        };

        for form in [json!(audience), json!({ "uri": audience })] {
            assert_eq!(
                participation_refs(&record(form, &parent)).expect("accepted"),
                (parent.clone(), audience.clone())
            );
        }

        let refused = [
            // no reply parent
            json!({ "audienceList": audience }),
            // a parent that is not a record URI
            record(json!(audience), "at://owner.example/x.y.z/p1"),
            record(json!(audience), &format!("{parent} ")),
            // no audience, or one that is not an audience URI
            json!({ "reply": { "parent": { "uri": parent } } }),
            record(json!(null), &parent),
            record(json!(7), &parent),
            record(json!(parent), &parent),
            record(json!(format!("{audience} ")), &parent),
        ];
        for bad in refused {
            let err = participation_refs(&bad).expect_err("refused");
            assert!(matches!(err, PdsError::Validation(_)), "{bad}: {err:?}");
        }
    }

    #[test]
    fn create_post_private_accepts_only_the_writers_own_audience() {
        let own = audience_uri(WRITER);
        let reply = json!({ "parent": { "uri": post_uri(OWNER, "p1") } });
        for accepted in [
            json!({ "audienceList": own }),
            json!({ "audienceList": { "uri": own } }),
            json!({ "audienceList": own, "reply": reply }),
            json!({ "text": "no audience" }),
        ] {
            require_own_audience(&accepted, WRITER).expect("accepted");
        }
        for refused in [
            json!({ "audienceList": audience_uri(OWNER) }),
            json!({ "audienceList": { "uri": audience_uri(OWNER) } }),
            json!({ "audienceList": audience_uri(OWNER), "reply": reply }),
            json!({ "audienceList": 7 }),
            json!({ "audienceList": {} }),
            json!({ "audienceList": format!("at://{WRITER}/app.bsky.feed.post/aud") }),
            json!({ "audienceList": format!("{own} ") }),
        ] {
            let err = require_own_audience(&refused, WRITER).expect_err("refused");
            assert!(matches!(err, PdsError::Validation(_)), "{refused}: {err:?}");
        }
    }

    #[tokio::test]
    async fn preconditions_do_not_depend_on_any_audience() {
        let record = json!({ "audienceList": audience_uri(OWNER) });

        let mut off = ctx_with_repos(&[WRITER]).await;
        let mut config = (*off.config).clone();
        config.kryphocron.enabled = false;
        off.config = std::sync::Arc::new(config);
        let err = private_post_preconditions(&off, WRITER, &record)
            .await
            .expect_err("tier off");
        assert_eq!(
            err,
            PdsError::UnsupportedNamespace {
                nsid: NSID_POST_PRIVATE.to_string()
            }
        );

        let err = private_post_preconditions(&off, WRITER, &json!("text"))
            .await
            .expect_err("not an object");
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn preconditions_require_a_repository_here() {
        let mut ctx = ctx_with_repos(&[WRITER]).await;
        let mut config = (*ctx.config).clone();
        config.kryphocron.enabled = true;
        ctx.config = std::sync::Arc::new(config);
        let record = json!({});

        private_post_preconditions(&ctx, WRITER, &record)
            .await
            .expect("a local writer passes");
        let err = private_post_preconditions(&ctx, REMOTE, &record)
            .await
            .expect_err("no repository here");
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");
    }
}

#[cfg(test)]
mod procedure_tests {
    //! The procedures end to end, through an OAuth session (A-1, A-4, A-9).
    use super::*;
    use serde_json::json;

    /// A local account with its repository and genesis commit, as
    /// `createAccount` leaves it.
    async fn account(ctx: &AppContext, handle: &str) -> String {
        let acc = ctx
            .account_manager
            .create_account(
                handle.into(),
                Some(format!("{handle}@example.com")),
                "password123".into(),
                None,
                None,
            )
            .await
            .unwrap();
        RepositoryManager::for_writer(ctx, acc.did.clone())
            .initialize()
            .await
            .unwrap();
        crate::api::account_emit::create_account_emit_sequence(ctx, &acc.did, handle)
            .await
            .unwrap();
        acc.did
    }

    fn session(did: &str) -> HeaderMap {
        middleware::oauth_gate_headers(did, "atproto transition:generic")
    }

    async fn stored_cid(ctx: &AppContext, did: &str, uri: &str) -> String {
        ctx.actor_store.get_record(did, uri).await.unwrap().unwrap().cid
    }

    async fn audience(
        ctx: &AppContext,
        did: &str,
        rkey: &str,
        record: serde_json::Value,
        swap_record: Option<String>,
    ) -> PdsResult<WriteResponse> {
        manage_audience(
            State(ctx.clone()),
            session(did),
            Json(ManageAudienceRequest {
                repo: did.to_string(),
                rkey: Some(rkey.to_string()),
                validate: None,
                swap_record,
                record,
            }),
        )
        .await
        .map(|Json(resp)| resp)
    }

    async fn post(ctx: &AppContext, did: &str, record: serde_json::Value) -> WriteResponse {
        create_post_private(
            State(ctx.clone()),
            session(did),
            Json(CreateLikeRequest {
                repo: did.to_string(),
                rkey: None,
                validate: None,
                record,
            }),
        )
        .await
        .unwrap()
        .0
    }

    async fn update(
        ctx: &AppContext,
        did: &str,
        rkey: &str,
        audience_list: &str,
        swap_record: Option<String>,
    ) -> PdsResult<WriteResponse> {
        update_post_private(
            State(ctx.clone()),
            session(did),
            Json(UpdatePostPrivateRequest {
                repo: did.to_string(),
                rkey: rkey.to_string(),
                audience_list: audience_list.to_string(),
                swap_record,
            }),
        )
        .await
        .map(|Json(resp)| resp)
    }

    fn rkey_of(uri: &str) -> &str {
        uri.rsplit('/').next().unwrap()
    }

    fn post_record(audience_uri: &str) -> serde_json::Value {
        json!({
            "$type": NSID_POST_PRIVATE,
            "text": "for some eyes",
            "createdAt": "2026-10-15T00:00:00Z",
            "audienceList": audience_uri,
        })
    }

    #[tokio::test]
    async fn a_post_moves_to_another_audience_and_keeps_everything_else() {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let alice = account(&ctx, "alice").await;
        let followers = audience(&ctx, &alice, "followers", json!({ "mode": "followers" }), None)
            .await
            .unwrap();
        let close = audience(&ctx, &alice, "close", json!({ "mode": "list", "members": [] }), None)
            .await
            .unwrap();
        // A-1: the answered CID is the stored record's.
        assert_eq!(close.cid, stored_cid(&ctx, &alice, &close.uri).await);

        let written = post(&ctx, &alice, post_record(&followers.uri)).await;
        assert_eq!(written.cid, stored_cid(&ctx, &alice, &written.uri).await);
        let before = load_record_json(&ctx, &alice, &written.uri).await.unwrap().unwrap();

        // A stale swap is refused and changes nothing.
        let err = update(&ctx, &alice, rkey_of(&written.uri), &close.uri, Some(close.cid.clone()))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::SwapCidMismatch(_)), "{err:?}");

        let moved = update(
            &ctx,
            &alice,
            rkey_of(&written.uri),
            &close.uri,
            Some(written.cid.clone()),
        )
        .await
        .unwrap();
        assert_eq!(moved.uri, written.uri);
        assert_ne!(moved.cid, written.cid);
        assert_eq!(moved.cid, stored_cid(&ctx, &alice, &written.uri).await);

        let after = load_record_json(&ctx, &alice, &written.uri).await.unwrap().unwrap();
        assert_eq!(after["audienceList"], json!(close.uri));
        let mut expected = before;
        expected["audienceList"] = json!(close.uri);
        assert_eq!(after, expected, "only audienceList changes");
    }

    #[tokio::test]
    async fn update_refuses_replies_foreign_or_missing_audiences_and_missing_posts() {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let alice = account(&ctx, "alice").await;
        let bob = account(&ctx, "bob").await;
        let mine = audience(&ctx, &alice, "aud", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let theirs = audience(&ctx, &bob, "aud", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let root = post(&ctx, &alice, post_record(&mine.uri)).await;
        let mut reply_record = post_record(&mine.uri);
        reply_record["reply"] = json!({
            "root": { "uri": root.uri, "cid": root.cid },
            "parent": { "uri": root.uri, "cid": root.cid },
        });
        let reply = post(&ctx, &alice, reply_record).await;

        for (rkey, audience_list) in [
            (rkey_of(&reply.uri), mine.uri.as_str()),
            (rkey_of(&root.uri), theirs.uri.as_str()),
            ("3nosuchpost22", mine.uri.as_str()),
        ] {
            let err = update(&ctx, &alice, rkey, audience_list, None).await.unwrap_err();
            assert!(matches!(err, PdsError::Validation(_)), "{rkey} {audience_list}: {err:?}");
        }

        // #536: an audience of the writer's with no record in the repo is
        // accepted; audiences are held by the AppView, which knows whether it
        // exists.
        let held_elsewhere = format!("at://{alice}/{NSID_AUDIENCE}/held-by-the-appview");
        update(&ctx, &alice, rkey_of(&root.uri), &held_elsewhere, None)
            .await
            .expect("an own audience without a record is accepted");
    }

    async fn participate(
        ctx: &AppContext,
        did: &str,
        record: serde_json::Value,
    ) -> PdsResult<WriteResponse> {
        participate_private(
            State(ctx.clone()),
            session(did),
            Json(CreateLikeRequest {
                repo: did.to_string(),
                rkey: None,
                validate: None,
                record,
            }),
        )
        .await
        .map(|Json(resp)| resp)
    }

    fn reply_record(audience_uri: &str, root: &WriteResponse, parent_uri: &str) -> serde_json::Value {
        let mut record = post_record(audience_uri);
        record["reply"] = json!({
            "root": { "uri": root.uri, "cid": root.cid },
            "parent": { "uri": parent_uri, "cid": root.cid },
        });
        record
    }

    /// #515: a reply must hang off the audience owner's thread.
    #[tokio::test]
    async fn a_reply_must_belong_to_the_owners_thread() {
        let mut ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        // Nothing elsewhere resolves: no test reaches the network.
        ctx.identity_resolver =
            std::sync::Arc::new(crate::identity::resolver::test_doubles::MockIdentityResolver::new());
        let alice = account(&ctx, "alice").await;
        let bob = account(&ctx, "bob").await;
        let dave = account(&ctx, "dave").await;
        let open = audience(&ctx, &alice, "aud", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let root = post(&ctx, &alice, post_record(&open.uri)).await;

        // A reply to the owner's post is anchored.
        let first = participate(&ctx, &bob, reply_record(&open.uri, &root, &root.uri))
            .await
            .expect("a reply in the owner's thread");
        // So is a third member's reply to that reply, walked through Bob's.
        participate(&ctx, &dave, reply_record(&open.uri, &root, &first.uri))
            .await
            .expect("a reply further down the owner's thread");

        // A thread planted by Dave under Alice's audience, written around the
        // procedures: neither a member nor Alice herself (the audience's
        // owner, not this root's author) may reply into it.
        let planted = crate::kryphocron_audience::test_support::seed(
            &ctx,
            &dave,
            NSID_POST_PRIVATE,
            "3planted22",
            json!({ "$type": NSID_POST_PRIVATE, "audienceList": open.uri,
                    "createdAt": "2026-10-16T00:00:00Z" }),
        )
        .await;
        let planted_ref = WriteResponse {
            uri: planted.clone(),
            cid: "bafyplanted".to_string(),
        };
        for writer in [&bob, &alice] {
            let err = participate(&ctx, writer, reply_record(&open.uri, &planted_ref, &planted))
                .await
                .unwrap_err();
            assert!(matches!(err, PdsError::Authorization(_)), "{writer}: {err:?}");
        }

        // An invented parent on another PDS is refused.
        let invented = format!("at://did:plc:elsewhere/{NSID_POST_PRIVATE}/3abc");
        let err = participate(&ctx, &bob, reply_record(&open.uri, &root, &invented))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");

        // A real parent paired with a root that is not its thread's.
        let other_root = post(&ctx, &alice, post_record(&open.uri)).await;
        let err = participate(&ctx, &bob, reply_record(&open.uri, &other_root, &first.uri))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");
    }

    /// A-12, Horizon's "done when": an audience change applies downthread.
    #[tokio::test]
    async fn a_move_takes_the_whole_thread_with_it() {
        let mut ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        ctx.identity_resolver =
            std::sync::Arc::new(crate::identity::resolver::test_doubles::MockIdentityResolver::new());
        let alice = account(&ctx, "alice").await;
        let bob = account(&ctx, "bob").await;
        let carol = account(&ctx, "carol").await;
        let followers = audience(&ctx, &alice, "followers", json!({ "mode": "followers" }), None)
            .await
            .unwrap();
        let close = audience(
            &ctx,
            &alice,
            "close",
            json!({ "mode": "list", "members": [carol] }),
            None,
        )
        .await
        .unwrap();
        // Bob follows Alice.
        RepositoryManager::for_writer(&ctx, bob.clone())
            .create_record(
                "app.bsky.graph.follow",
                None,
                json!({ "$type": "app.bsky.graph.follow", "subject": alice,
                        "createdAt": "2026-10-16T00:00:00Z" }),
                Some(false),
                create_actor_signer(&ctx.account_manager, &bob).await.unwrap(),
            )
            .await
            .unwrap();

        let root = post(&ctx, &alice, post_record(&followers.uri)).await;
        let bobs = participate(&ctx, &bob, reply_record(&followers.uri, &root, &root.uri))
            .await
            .expect("a follower replies under followers");

        // Alice moves the root to a list with Carol but not Bob.
        update(&ctx, &alice, rkey_of(&root.uri), &close.uri, None)
            .await
            .unwrap();

        // Carol replies to Bob's reply, written before the move, naming the list.
        participate(&ctx, &carol, reply_record(&close.uri, &root, &bobs.uri))
            .await
            .expect("a member added by the move replies anywhere in the thread");

        // Bob cannot reply under the thread's old audience: it is no longer
        // the root's.
        for parent in [&root.uri, &bobs.uri] {
            let err = participate(&ctx, &bob, reply_record(&followers.uri, &root, parent))
                .await
                .unwrap_err();
            assert!(matches!(err, PdsError::Authorization(_)), "{parent}: {err:?}");
        }
        // Under the new one, whether the list admits him is the AppView's to
        // decide (#536): locus stores the reply, and the AppView serves it
        // only to readers the list admits.
        participate(&ctx, &bob, reply_record(&close.uri, &root, &root.uri))
            .await
            .expect("membership of the list is the AppView's to decide");

        // Nor can Bob get in through createPostPrivate under his own audience.
        let bobs_own = audience(&ctx, &bob, "own", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let err = create_post_private(
            State(ctx.clone()),
            session(&bob),
            Json(CreateLikeRequest {
                repo: bob.clone(),
                rkey: None,
                validate: None,
                record: reply_record(&bobs_own.uri, &root, &bobs.uri),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");

        // Alice replies in her own thread through createPostPrivate: under the
        // root's current audience, not the old one.
        let alices_reply = |audience_uri: &str| CreateLikeRequest {
            repo: alice.clone(),
            rkey: None,
            validate: None,
            record: reply_record(audience_uri, &root, &bobs.uri),
        };
        let err = create_post_private(
            State(ctx.clone()),
            session(&alice),
            Json(alices_reply(&followers.uri)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
        let _stored = create_post_private(
            State(ctx.clone()),
            session(&alice),
            Json(alices_reply(&close.uri)),
        )
        .await
        .expect("the root's author replies under the current audience");
    }

    /// Write a stock record into `did`'s repository.
    async fn stock_record(
        ctx: &AppContext,
        did: &str,
        collection: &str,
        record: serde_json::Value,
    ) -> String {
        let outcome = RepositoryManager::for_writer(ctx, did.to_string())
            .create_record(
                collection,
                None,
                record,
                Some(false),
                create_actor_signer(&ctx.account_manager, did).await.unwrap(),
            )
            .await
            .unwrap();
        outcome.results[0].uri.clone()
    }

    async fn follow(ctx: &AppContext, from: &str, to: &str) {
        stock_record(
            ctx,
            from,
            "app.bsky.graph.follow",
            json!({ "$type": "app.bsky.graph.follow", "subject": to,
                    "createdAt": "2026-10-16T00:00:00Z" }),
        )
        .await;
    }

    /// A-13, Horizon's "done when": private branches under a public post.
    #[tokio::test]
    async fn a_private_branch_hangs_off_a_public_post() {
        let mut ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        ctx.identity_resolver =
            std::sync::Arc::new(crate::identity::resolver::test_doubles::MockIdentityResolver::new());
        let alice = account(&ctx, "alice").await;
        let bob = account(&ctx, "bob").await;
        let carol = account(&ctx, "carol").await;
        let dave = account(&ctx, "dave").await;

        // A's public post.
        let public = stock_record(
            &ctx,
            &alice,
            "app.bsky.feed.post",
            json!({ "$type": "app.bsky.feed.post", "text": "hello",
                    "createdAt": "2026-10-16T00:00:00Z" }),
        )
        .await;
        let public_ref = WriteResponse {
            uri: public.clone(),
            cid: "bafypublic".to_string(),
        };

        // B replies privately under B's followers audience: a branch root.
        let followers = audience(&ctx, &bob, "followers", json!({ "mode": "followers" }), None)
            .await
            .unwrap();
        let branch_root = post(&ctx, &bob, reply_record(&followers.uri, &public_ref, &public)).await;

        // C follows B and replies in the branch; D does not follow B.
        follow(&ctx, &carol, &bob).await;

        // Starting a branch is its author's own write: even an admitted
        // follower cannot start one under B's audience.
        let err = participate(&ctx, &carol, reply_record(&followers.uri, &public_ref, &public))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
        let carols = participate(&ctx, &carol, reply_record(&followers.uri, &public_ref, &branch_root.uri))
            .await
            .expect("a follower of the branch's author replies in it");

        // Only a branch root may be moved; a reply inside the branch may not.
        let carols_own = audience(&ctx, &carol, "own", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let err = update(&ctx, &carol, rkey_of(&carols.uri), &carols_own.uri, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
        // D does not follow B, but whether B's followers audience admits D is
        // the AppView's to decide (#536): locus stores the reply.
        participate(&ctx, &dave, reply_record(&followers.uri, &public_ref, &branch_root.uri))
            .await
            .expect("audience membership is the AppView's to decide");

        // B moves the branch root to a list with D but not C.
        let close = audience(&ctx, &bob, "close", json!({ "mode": "list", "members": [dave] }), None)
            .await
            .unwrap();
        update(&ctx, &bob, rkey_of(&branch_root.uri), &close.uri, None)
            .await
            .expect("a branch root can be moved");

        participate(&ctx, &dave, reply_record(&close.uri, &public_ref, &branch_root.uri))
            .await
            .expect("a member added by the move replies in the branch");

        // A member whose reply does not hang off the branch (it claims another
        // public root) gets the one 403.
        let other_public = WriteResponse {
            uri: format!("at://{alice}/app.bsky.feed.post/3other22"),
            cid: "bafyother".to_string(),
        };
        let err = participate(&ctx, &dave, reply_record(&close.uri, &other_public, &branch_root.uri))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");
        // Nobody replies under the branch's old audience: it is no longer the
        // branch root's.
        let err = participate(&ctx, &carol, reply_record(&followers.uri, &public_ref, &branch_root.uri))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");

        // B replies in B's own branch with createPostPrivate, under its
        // current audience; under the old one it is refused.
        let bobs = |audience_uri: &str| CreateLikeRequest {
            repo: bob.clone(),
            rkey: None,
            validate: None,
            record: reply_record(audience_uri, &public_ref, &branch_root.uri),
        };
        let err = create_post_private(State(ctx.clone()), session(&bob), Json(bobs(&followers.uri)))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
        let _stored = create_post_private(State(ctx.clone()), session(&bob), Json(bobs(&close.uri)))
            .await
            .expect("the branch's author replies in it");

        // Someone else's branch is not the writer's own: participatePrivate.
        // Whatever the walk found, the refusal is the same words, so it tells
        // nothing about other accounts' private posts.
        let daves_own = audience(&ctx, &dave, "own", json!({ "mode": "everyone" }), None)
            .await
            .unwrap();
        let daves = |parent_uri: &str| CreateLikeRequest {
            repo: dave.clone(),
            rkey: None,
            validate: None,
            record: reply_record(&daves_own.uri, &public_ref, parent_uri),
        };
        let missing = format!("at://{bob}/{NSID_POST_PRIVATE}/3nosuchpost22");
        let mut refusals = Vec::new();
        for parent in [branch_root.uri.as_str(), missing.as_str(), carols.uri.as_str()] {
            let err = create_post_private(State(ctx.clone()), session(&dave), Json(daves(parent)))
                .await
                .unwrap_err();
            assert!(matches!(err, PdsError::Validation(_)), "{parent}: {err:?}");
            refusals.push(err.to_string());
        }
        assert!(
            refusals.windows(2).all(|pair| pair[0] == pair[1]),
            "one refusal, whatever the cause: {refusals:?}"
        );

        // A reply to a public post sits in a public thread: its root is public.
        let private_root = WriteResponse {
            uri: branch_root.uri.clone(),
            cid: branch_root.cid.clone(),
        };
        let mut misplaced = reply_record(&daves_own.uri, &private_root, &public);
        misplaced["reply"]["parent"]["uri"] = json!(public);
        let err = create_post_private(
            State(ctx.clone()),
            session(&dave),
            Json(CreateLikeRequest {
                repo: dave.clone(),
                rkey: None,
                validate: None,
                record: misplaced,
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");
    }

    #[tokio::test]
    async fn manage_audience_replaces_an_existing_record_and_delete_removes_it() {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let alice = account(&ctx, "alice").await;
        let created = audience(
            &ctx,
            &alice,
            "friends",
            json!({ "mode": "list", "name": "friends", "members": ["did:plc:a"] }),
            None,
        )
        .await
        .unwrap();

        let renamed = json!({ "mode": "list", "name": "close friends", "members": ["did:plc:b"] });
        let err = audience(&ctx, &alice, "friends", renamed.clone(), Some("bafystale".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::SwapCidMismatch(_)), "{err:?}");

        let updated = audience(&ctx, &alice, "friends", renamed.clone(), Some(created.cid.clone()))
            .await
            .unwrap();
        assert_eq!(updated.uri, created.uri);
        assert_eq!(updated.cid, stored_cid(&ctx, &alice, &created.uri).await);
        let stored = load_record_json(&ctx, &alice, &created.uri).await.unwrap().unwrap();
        assert_eq!(stored, renamed);

        // A swap for a record that is not there cannot hold.
        let err = audience(&ctx, &alice, "other", renamed, Some(updated.cid.clone()))
            .await
            .unwrap_err();
        assert!(matches!(err, PdsError::Validation(_)), "{err:?}");

        for _ in 0..2 {
            let _answer = delete_audience(
                State(ctx.clone()),
                session(&alice),
                Json(DeleteLikeRequest {
                    repo: alice.clone(),
                    rkey: "friends".to_string(),
                }),
            )
            .await
            .expect("delete, and delete again, succeed");
        }
        assert!(ctx.actor_store.get_record(&alice, &created.uri).await.unwrap().is_none());
    }
}
