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
    kryphocron_audience::{
        audience_owner, audience_reference, parse_record_uri, resolve_write, AudienceRef,
        AudienceWriteDecision,
    },
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
        ctx.rate_limiter.check_cross_pds()?;
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

/// Build the default `policy.audience` record for a freshly-created account
/// (#334 / §7.3.3). Only `list` mode carries a member list (empty — the holder
/// populates it); the relational modes (`everyone`/`followers`/`following`)
/// need none. Pure, so the record shape is unit-testable without a repo.
fn default_audience_record(mode: &str) -> serde_json::Value {
    let mut record = serde_json::json!({ "$type": NSID_AUDIENCE, "mode": mode });
    if mode == "list" {
        record["members"] = serde_json::json!([]);
    }
    record
}

/// Author the deployment's default `policy.audience` record on a newly-created
/// account's own repo (#334 / §6.6.2 item 2 / §7.3.3). Host-initiated on the
/// account's behalf at setup: it authors through `apply_writes` directly (not
/// the request chokepoint, so the new-account-access delay guard doesn't apply
/// to this host write), signed with the new account's key, emitting a normal
/// #commit. The caller treats failure as non-fatal — the account already
/// exists. `mode` must be a participating mode (the `nobody` default never
/// reaches here; see [`crate::kryphocron_policy::default_audience_mode`]).
pub async fn author_default_audience(
    ctx: &AppContext,
    did: &str,
    mode: &str,
) -> PdsResult<String> {
    let auth = AuthenticatedDid::from_authenticated(did.to_string());
    let resp =
        apply_single_create(ctx, &auth, NSID_AUDIENCE, None, default_audience_record(mode), None)
            .await?;
    Ok(resp.uri)
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

/// `tools.kryphocron.feed.createPostPrivate` — create a
/// `tools.kryphocron.feed.postPrivate` record under the
/// `EditPrivatePost` (user-class) capability. The bind pipeline
/// runs during `apply_writes`'s validate loop.
///
/// The record may name only an audience in the writer's own repository
/// ([`require_own_audience`]). It may carry a `reply`: an author replying in
/// their own thread, or anyone replying under their own audience, writes
/// through this procedure.
async fn create_post_private(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<CreateLikeRequest>,
) -> PdsResult<Json<WriteResponse>> {
    let auth_did =
        authenticated_did_for_repo(&ctx, headers, &req.repo, AtProtoScope::RepoCreate).await?;
    private_post_preconditions(&ctx, auth_did.value(), &req.record).await?;
    require_own_audience(&req.record, auth_did.value())?;

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
/// **The audience check.** The writer is checked against the audience the
/// reply itself names ([`check_participate_audience`]): that is the audience
/// whose readers will be served the reply. When the parent post is held
/// here, the reply must name the parent's audience. On refusal the handler
/// writes `KryphocronAudienceCheckDenied` in its own short tx on the shared
/// account DB and answers 403 with one fixed message, whatever the cause: a
/// post that does not exist, an audience that does not admit the writer, a
/// block, and a mismatched audience are the same response.
///
/// **Audiences held elsewhere.** When the audience's owner is not an account
/// on this PDS its record cannot be read; the write is allowed and a warning
/// is logged so the unchecked write is visible to the operator.
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
    match check_participate_audience(&ctx, &parent_uri, &audience_uri, auth_did.value()).await? {
        ParticipateAudienceOutcome::Allowed => {
            ctx.audience_oracle_activity.record(OracleConsultation::WriteAllowed);
        }
        ParticipateAudienceOutcome::DeferredCrossDid { audience_owner } => {
            ctx.audience_oracle_activity.record(OracleConsultation::WriteDeferred);
            tracing::warn!(
                target: "aurora_locus::kryphocron",
                event = "participate_private_audience_check_deferred",
                requester_did = %auth_did.value(),
                parent_uri = %parent_uri,
                audience_owner = %audience_owner,
                reason = "audience_owner_not_local",
                "audience check deferred: the audience's owner is not an \
                 account on this PDS, so its audience record cannot be read",
            );
        }
        ParticipateAudienceOutcome::Denied(payload) => {
            ctx.audience_oracle_activity.record(OracleConsultation::WriteDenied);
            let mut tx = ctx
                .account_db
                .begin()
                .await
                .map_err(PdsError::Database)?;
            crate::kryphocron_audit::emit_audience_check_denied_in_tx(
                &mut tx, auth_did.value(), payload,
            )
            .await?;
            tx.commit().await.map_err(PdsError::Database)?;
            return Err(PdsError::Authorization(
                "Audience check denied".to_string(),
            ));
        }
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

/// Outcome of the host-side audience check that runs before
/// `participatePrivate` writes. See [`check_participate_audience`].
#[derive(Debug)]
enum ParticipateAudienceOutcome {
    /// The writer may store the reply under the audience it names.
    Allowed,
    /// The audience's owner is not an account on this PDS, so the audience
    /// record cannot be read. The participation is allowed; the handler logs
    /// the unchecked write.
    DeferredCrossDid { audience_owner: String },
    /// The handler writes the audience-check-denied event and returns 403.
    Denied(AudienceCheckDeniedPayload),
}

/// Host-side audience check for `participatePrivate` (#495).
///
/// `audience_uri` is the audience the reply names; `parent_uri` is the post
/// it replies to. Both have been syntax-checked by [`participation_refs`].
///
/// 1. When the parent's owner is an account here, the parent must exist and
///    name the same audience as the reply. Otherwise the reply is denied.
///    Nothing is read from a parent held elsewhere.
/// 2. The audience's owner may always write under its own audience.
/// 3. When the audience's owner is not an account here the check cannot run:
///    [`ParticipateAudienceOutcome::DeferredCrossDid`].
/// 4. Otherwise the audience record decides, by its mode
///    ([`crate::kryphocron_audience::resolve_write`]). A missing or
///    undecodable audience record denies.
///
/// # Errors
///
/// A store error. A denial is an `Ok` outcome, never an error, so that every
/// denial reaches the one refusal the handler gives.
async fn check_participate_audience(
    ctx: &AppContext,
    parent_uri: &str,
    audience_uri: &str,
    writer_did: &str,
) -> PdsResult<ParticipateAudienceOutcome> {
    let parent_owner = parse_record_uri(parent_uri)
        .map(|uri| uri.did)
        .ok_or_else(|| PdsError::Validation("invalid parent URI".to_string()))?;
    let owner_did = audience_owner(audience_uri)
        .ok_or_else(|| PdsError::Validation("invalid audience URI".to_string()))?;
    let denied = |mode: &str, result: AudienceCheckResult| {
        ParticipateAudienceOutcome::Denied(AudienceCheckDeniedPayload {
            capability_attempted: "ParticipatePrivate".to_string(),
            subject_uri: parent_uri.to_string(),
            requester_did: writer_did.to_string(),
            audience_uri: Some(audience_uri.to_string()),
            audience_mode: mode.to_string(),
            audience_check_result: result,
            trace_id: crate::kryphocron_audit::synthesize_trace_id(),
            payload_completeness: crate::kryphocron_audit::PayloadCompleteness::Full,
        })
    };

    if ctx.actor_store.exists(parent_owner).await {
        let names_same_audience = load_record_json(ctx, parent_owner, parent_uri)
            .await?
            .is_some_and(|parent| {
                audience_reference(&parent) == AudienceRef::Uri(audience_uri.to_string())
            });
        if !names_same_audience {
            return Ok(denied("unknown", AudienceCheckResult::NoAudienceConfigured));
        }
    }

    if owner_did == writer_did {
        return Ok(ParticipateAudienceOutcome::Allowed);
    }
    if !ctx.actor_store.exists(owner_did).await {
        return Ok(ParticipateAudienceOutcome::DeferredCrossDid {
            audience_owner: owner_did.to_string(),
        });
    }

    let Some(audience) = load_record_json(ctx, owner_did, audience_uri).await? else {
        return Ok(denied("unknown", AudienceCheckResult::NoAudienceConfigured));
    };
    let (mode, decision) = resolve_write(ctx, writer_did, owner_did, &audience).await?;
    Ok(match decision {
        AudienceWriteDecision::Allowed => ParticipateAudienceOutcome::Allowed,
        AudienceWriteDecision::NotInAudience => {
            denied(mode.as_audit_str(), AudienceCheckResult::NotInAudience)
        }
        AudienceWriteDecision::Unresolved => {
            denied(mode.as_audit_str(), AudienceCheckResult::NoAudienceConfigured)
        }
    })
}

/// Read and decode one stored record. `None` when the record or its block is
/// absent, or when the block does not decode (logged): to the audience check
/// each of those is a record that is not there.
async fn load_record_json(
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
/// audience is its thread's); an `audienceList` that is not one of the
/// writer's own audience records, or names one that does not exist.
/// `swapRecord` must be the post's current CID (409 `InvalidSwap`).
///
/// Replies already written keep their own `audienceList`. A new reply to
/// this post must name the new audience: `participatePrivate` requires a
/// reply to name its local parent's audience.
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
    if audience_owner(&req.audience_list) != Some(writer) {
        return Err(PdsError::Validation(
            "audienceList must be the at:// URI of one of the writer's own audience records"
                .to_string(),
        ));
    }
    if load_record_json(&ctx, writer, &req.audience_list).await?.is_none() {
        return Err(PdsError::Validation(format!(
            "audienceList names no audience record: {}",
            req.audience_list
        )));
    }

    let Some(current) = read_own_record(&ctx, writer, NSID_POST_PRIVATE, &req.rkey).await?
    else {
        return Err(PdsError::Validation(format!(
            "no private post at {NSID_POST_PRIVATE}/{}",
            req.rkey
        )));
    };
    if current.value.get("reply").is_some_and(|reply| !reply.is_null()) {
        return Err(PdsError::Validation(
            "a reply's audience is its thread's and cannot be changed".to_string(),
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
/// Private-tier (existence is private; consumed by `BlockOracle` outside the
/// normal capability flow — §7.2.4). **Route intentionally unregistered until
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
mod tests {
    use super::*;

    // #334 — the default policy.audience record shape authored at account setup.
    #[test]
    fn default_audience_record_shapes_per_mode() {
        let list = default_audience_record("list");
        assert_eq!(list["$type"], NSID_AUDIENCE);
        assert_eq!(list["mode"], "list");
        assert_eq!(list["members"], serde_json::json!([]), "list mode carries an empty member list");

        for mode in ["everyone", "followers", "following"] {
            let rec = default_audience_record(mode);
            assert_eq!(rec["mode"], mode);
            assert!(rec.get("members").is_none(), "{mode} mode carries no member list");
        }
    }
}

#[cfg(test)]
mod participate_audience_tests {
    //! #495: who may reply under whose audience.
    use super::*;
    use crate::kryphocron_audience::test_support::{ctx_with_repos, seed, seed_bytes};
    use serde_json::json;

    const OWNER: &str = "did:plc:owner";
    const WRITER: &str = "did:plc:writer";
    const THIRD: &str = "did:plc:third";
    const REMOTE: &str = "did:plc:elsewhere";
    const FOLLOW: &str = "app.bsky.graph.follow";

    fn audience_uri(did: &str) -> String {
        format!("at://{did}/{NSID_AUDIENCE}/aud")
    }

    fn post_uri(did: &str, rkey: &str) -> String {
        format!("at://{did}/{NSID_POST_PRIVATE}/{rkey}")
    }

    /// Owner, writer and a third account, with the owner's audience in
    /// `mode` and a post by the owner under it. Returns the post's URI.
    async fn thread(mode: serde_json::Value) -> (AppContext, String) {
        let ctx = ctx_with_repos(&[OWNER, WRITER, THIRD]).await;
        seed(&ctx, OWNER, NSID_AUDIENCE, "aud", json!({ "mode": mode, "members": [] })).await;
        let post = seed(
            &ctx,
            OWNER,
            NSID_POST_PRIVATE,
            "p1",
            json!({ "audienceList": audience_uri(OWNER) }),
        )
        .await;
        (ctx, post)
    }

    async fn check(ctx: &AppContext, parent: &str, audience: &str, writer: &str) -> ParticipateAudienceOutcome {
        check_participate_audience(ctx, parent, audience, writer)
            .await
            .expect("check")
    }

    fn denial(outcome: ParticipateAudienceOutcome) -> AudienceCheckDeniedPayload {
        match outcome {
            ParticipateAudienceOutcome::Denied(payload) => payload,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn assert_allowed(outcome: ParticipateAudienceOutcome) {
        assert!(
            matches!(outcome, ParticipateAudienceOutcome::Allowed),
            "expected allowed, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn followers_audience_admits_a_follower_and_refuses_others() {
        let (ctx, post) = thread(json!("followers")).await;
        let audience = audience_uri(OWNER);
        let follow = seed(&ctx, WRITER, FOLLOW, "f1", json!({ "subject": OWNER })).await;

        assert_allowed(check(&ctx, &post, &audience, WRITER).await);

        let refused = denial(check(&ctx, &post, &audience, THIRD).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        assert_eq!(refused.audience_mode, "followers");
        assert_eq!(refused.audience_uri.as_deref(), Some(audience.as_str()));
        assert_eq!(refused.subject_uri, post);

        ctx.actor_store
            .delete_record(WRITER, &follow)
            .await
            .expect("unfollow");
        let after_unfollow = denial(check(&ctx, &post, &audience, WRITER).await);
        assert_eq!(
            after_unfollow.audience_check_result,
            AudienceCheckResult::NotInAudience
        );
    }

    #[tokio::test]
    async fn a_block_refuses_a_follower_and_is_recorded_as_not_in_audience() {
        let (ctx, post) = thread(json!("followers")).await;
        seed(&ctx, WRITER, FOLLOW, "f1", json!({ "subject": OWNER })).await;
        seed(&ctx, OWNER, NSID_BLOCK, "b1", json!({ "subject": WRITER })).await;
        let refused = denial(check(&ctx, &post, &audience_uri(OWNER), WRITER).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        assert_eq!(refused.audience_mode, "followers");
    }

    #[tokio::test]
    async fn everyone_admits_anyone_not_blocked() {
        let (ctx, post) = thread(json!("everyone")).await;
        let audience = audience_uri(OWNER);
        assert_allowed(check(&ctx, &post, &audience, WRITER).await);
        seed(&ctx, THIRD, "app.bsky.graph.block", "b1", json!({ "subject": OWNER })).await;
        let refused = denial(check(&ctx, &post, &audience, THIRD).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        assert_eq!(refused.audience_mode, "everyone");
    }

    #[tokio::test]
    async fn list_audience_is_members_only_and_unmoved_by_blocks() {
        let ctx = ctx_with_repos(&[OWNER, WRITER, THIRD]).await;
        seed(
            &ctx,
            OWNER,
            NSID_AUDIENCE,
            "aud",
            json!({ "mode": "list", "members": [WRITER] }),
        )
        .await;
        let post = seed(
            &ctx,
            OWNER,
            NSID_POST_PRIVATE,
            "p1",
            json!({ "audienceList": audience_uri(OWNER) }),
        )
        .await;
        let audience = audience_uri(OWNER);
        seed(&ctx, OWNER, NSID_BLOCK, "b1", json!({ "subject": WRITER })).await;
        seed(&ctx, THIRD, FOLLOW, "f1", json!({ "subject": OWNER })).await;

        assert_allowed(check(&ctx, &post, &audience, WRITER).await);
        let refused = denial(check(&ctx, &post, &audience, THIRD).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        assert_eq!(refused.audience_mode, "list");
    }

    #[tokio::test]
    async fn following_admits_a_writer_the_owner_follows() {
        let (ctx, post) = thread(json!("following")).await;
        let audience = audience_uri(OWNER);
        seed(&ctx, OWNER, FOLLOW, "f1", json!({ "subject": WRITER })).await;
        assert_allowed(check(&ctx, &post, &audience, WRITER).await);
        let refused = denial(check(&ctx, &post, &audience, THIRD).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        assert_eq!(refused.audience_mode, "following");
    }

    #[tokio::test]
    async fn nobody_following_and_unknown_modes_refuse_everyone_but_the_owner() {
        // The writer follows the owner below; `following` needs the reverse.
        let cases = [
            (json!("nobody"), AudienceCheckResult::NotInAudience, "nobody"),
            (json!("following"), AudienceCheckResult::NotInAudience, "following"),
            (json!("Followers"), AudienceCheckResult::NoAudienceConfigured, "unknown"),
            (json!(7), AudienceCheckResult::NoAudienceConfigured, "unknown"),
        ];
        for (mode, result, word) in cases {
            let (ctx, post) = thread(mode.clone()).await;
            let audience = audience_uri(OWNER);
            seed(&ctx, WRITER, FOLLOW, "f1", json!({ "subject": OWNER })).await;
            let refused = denial(check(&ctx, &post, &audience, WRITER).await);
            assert_eq!(refused.audience_check_result, result, "{mode}");
            assert_eq!(refused.audience_mode, word, "{mode}");
            assert_allowed(check(&ctx, &post, &audience, OWNER).await);
        }
    }

    #[tokio::test]
    async fn a_reply_must_name_its_local_parents_audience() {
        let (ctx, post) = thread(json!("everyone")).await;
        // The writer's own audience, and the third account's open one.
        seed(&ctx, WRITER, NSID_AUDIENCE, "aud", json!({ "mode": "everyone" })).await;
        seed(&ctx, THIRD, NSID_AUDIENCE, "aud", json!({ "mode": "everyone" })).await;
        for other in [audience_uri(WRITER), audience_uri(THIRD)] {
            let refused = denial(check(&ctx, &post, &other, WRITER).await);
            assert_eq!(
                refused.audience_check_result,
                AudienceCheckResult::NoAudienceConfigured
            );
            assert_eq!(refused.audience_mode, "unknown");
        }
    }

    #[tokio::test]
    async fn a_missing_or_unreadable_parent_is_refused_alike() {
        let (ctx, _post) = thread(json!("everyone")).await;
        let audience = audience_uri(OWNER);
        seed(&ctx, OWNER, NSID_POST_PRIVATE, "noaud", json!({ "text": "x" })).await;
        seed(&ctx, OWNER, NSID_POST_PRIVATE, "junk", json!({ "audienceList": "garbage" })).await;
        seed_bytes(&ctx, OWNER, NSID_POST_PRIVATE, "broken", b"not cbor").await;
        for rkey in ["absent", "noaud", "junk", "broken"] {
            let refused = denial(check(&ctx, &post_uri(OWNER, rkey), &audience, WRITER).await);
            assert_eq!(
                refused.audience_check_result,
                AudienceCheckResult::NoAudienceConfigured,
                "{rkey}"
            );
            assert_eq!(refused.audience_mode, "unknown", "{rkey}");
        }
    }

    #[tokio::test]
    async fn a_parent_naming_its_audience_as_an_object_is_matched() {
        let ctx = ctx_with_repos(&[OWNER, WRITER]).await;
        seed(&ctx, OWNER, NSID_AUDIENCE, "aud", json!({ "mode": "everyone" })).await;
        let post = seed(
            &ctx,
            OWNER,
            NSID_POST_PRIVATE,
            "p1",
            json!({ "audienceList": { "uri": audience_uri(OWNER) } }),
        )
        .await;
        assert_allowed(check(&ctx, &post, &audience_uri(OWNER), WRITER).await);
    }

    #[tokio::test]
    async fn a_reply_to_a_reply_in_a_third_repository_is_checked_against_the_thread_audience() {
        let (ctx, _post) = thread(json!("followers")).await;
        let audience = audience_uri(OWNER);
        // THIRD replied under the owner's audience; WRITER replies to that.
        let reply = seed(
            &ctx,
            THIRD,
            NSID_POST_PRIVATE,
            "r1",
            json!({ "audienceList": audience }),
        )
        .await;
        let refused = denial(check(&ctx, &reply, &audience, WRITER).await);
        assert_eq!(refused.audience_mode, "followers");
        seed(&ctx, WRITER, FOLLOW, "f1", json!({ "subject": OWNER })).await;
        assert_allowed(check(&ctx, &reply, &audience, WRITER).await);
    }

    #[tokio::test]
    async fn a_parent_held_elsewhere_does_not_skip_a_local_audience() {
        let (ctx, _post) = thread(json!("followers")).await;
        let parent = post_uri(REMOTE, "p1");
        let refused = denial(check(&ctx, &parent, &audience_uri(OWNER), WRITER).await);
        assert_eq!(refused.audience_check_result, AudienceCheckResult::NotInAudience);
        seed(&ctx, WRITER, FOLLOW, "f1", json!({ "subject": OWNER })).await;
        assert_allowed(check(&ctx, &parent, &audience_uri(OWNER), WRITER).await);
    }

    #[tokio::test]
    async fn an_audience_held_elsewhere_is_deferred() {
        let (ctx, _post) = thread(json!("everyone")).await;
        let outcome = check(&ctx, &post_uri(REMOTE, "p1"), &audience_uri(REMOTE), WRITER).await;
        match outcome {
            ParticipateAudienceOutcome::DeferredCrossDid { audience_owner } => {
                assert_eq!(audience_owner, REMOTE);
            }
            other => panic!("expected a deferral, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_missing_or_undecodable_audience_record_refuses() {
        let ctx = ctx_with_repos(&[OWNER, WRITER]).await;
        let post = seed(
            &ctx,
            OWNER,
            NSID_POST_PRIVATE,
            "p1",
            json!({ "audienceList": audience_uri(OWNER) }),
        )
        .await;
        let refused = denial(check(&ctx, &post, &audience_uri(OWNER), WRITER).await);
        assert_eq!(
            refused.audience_check_result,
            AudienceCheckResult::NoAudienceConfigured
        );
        seed_bytes(&ctx, OWNER, NSID_AUDIENCE, "aud", b"not cbor").await;
        let refused = denial(check(&ctx, &post, &audience_uri(OWNER), WRITER).await);
        assert_eq!(refused.audience_mode, "unknown");
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

        let missing_audience = format!("at://{alice}/{NSID_AUDIENCE}/nothing-here");
        for (rkey, audience_list) in [
            (rkey_of(&reply.uri), mine.uri.as_str()),
            (rkey_of(&root.uri), theirs.uri.as_str()),
            (rkey_of(&root.uri), missing_audience.as_str()),
            ("3nosuchpost22", mine.uri.as_str()),
        ] {
            let err = update(&ctx, &alice, rkey, audience_list, None).await.unwrap_err();
            assert!(matches!(err, PdsError::Validation(_)), "{rkey} {audience_list}: {err:?}");
        }
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
