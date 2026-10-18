/// com.atproto.repo.* endpoints
use crate::{
    actor_store::{RepositoryManager, WriteOp, WriteOpAction},
    api::{labels::LabelView, middleware},
    context::AppContext,
    error::{PdsError, PdsResult},
    oauth::{atproto::scope::RepoAction, AtProtoScope},
};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use proto_blue::common::next_tid;
use serde::{Deserialize, Serialize};

/// Build repository routes
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route(
            "/xrpc/com.atproto.repo.listMissingBlobs",
            get(list_missing_blobs),
        )
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
}

/// Request to create a record
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRecordRequest {
    repo: String, // DID or handle
    collection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validate: Option<bool>,
    record: serde_json::Value,
    /// The commit the repository must be at (`InvalidSwap` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_commit: Option<String>,
}

/// Response from creating a record: the record's URI and CID (the stored
/// record's, not the commit's), and the commit that wrote it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateRecordResponse {
    uri: String,
    cid: String,
    commit: CommitMeta,
}

/// `com.atproto.repo.defs#commitMeta`: the commit a write landed in.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitMeta {
    cid: String,
    rev: String,
}

impl CommitMeta {
    fn of(outcome: &crate::actor_store::repository::CommitOutcome) -> Self {
        Self {
            cid: outcome.commit_cid.clone(),
            rev: outcome.rev.clone(),
        }
    }
}

/// Request to update a record
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutRecordRequest {
    repo: String,
    collection: String,
    rkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    validate: Option<bool>,
    record: serde_json::Value,
    /// Record-level optimistic-concurrency precondition: the CID the
    /// caller believes is currently at `(collection, rkey)`. Enforced by
    /// `RepositoryManager::put_record` via the substrate's CAS —
    /// a mismatch is `SwapCidMismatch` (409), and supplying it for a
    /// record that does not exist is `NotFound` (404).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_record: Option<String>,
    /// The commit the repository must be at (`InvalidSwap` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_commit: Option<String>,
}

/// Response from updating a record: as [`CreateRecordResponse`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PutRecordResponse {
    uri: String,
    cid: String,
    commit: CommitMeta,
}

/// Request to delete a record
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecordRequest {
    repo: String,
    collection: String,
    rkey: String,
    /// Record-level optimistic-concurrency precondition: the CID the
    /// caller believes is currently at `(collection, rkey)`. Enforced by
    /// `RepositoryManager::delete_record` via the substrate's CAS —
    /// a mismatch is `SwapCidMismatch` (409), and supplying it for a
    /// record that does not exist is `NotFound` (404).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_record: Option<String>,
    /// The commit the repository must be at (`InvalidSwap` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_commit: Option<String>,
}

/// Query parameters for getRecord
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRecordQuery {
    repo: String,
    collection: String,
    rkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)] // TODO: Implement CID-specific record retrieval
    cid: Option<String>,
}

/// Response from getting a record
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetRecordResponse {
    uri: String,
    cid: String,
    value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<Vec<LabelView>>,
}

/// Query parameters for listRecords
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRecordsQuery {
    repo: String,
    collection: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    /// Oldest first instead of newest first.
    #[serde(default)]
    reverse: bool,
}

/// The `limit` bounds of `com.atproto.repo.listRecords`.
const LIST_RECORDS_LIMIT: std::ops::RangeInclusive<i64> = 1..=100;

fn default_limit() -> i64 {
    50
}

/// Record entry in list response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordEntry {
    uri: String,
    cid: String,
    value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<Vec<LabelView>>,
}

/// Response from listing records
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListRecordsResponse {
    records: Vec<RecordEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// Query parameters for describeRepo
#[derive(Debug, Deserialize)]
struct DescribeRepoQuery {
    repo: String,
}

/// Response from describing a repo
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeRepoResponse {
    did: String,
    handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_doc: Option<serde_json::Value>,
    collections: Vec<String>,
    handle_is_correct: bool,
}

/// Request to apply writes
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyWritesRequest {
    repo: String,
    /// Applies to every write that does not set its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    validate: Option<bool>,
    writes: Vec<WriteOpInput>,
    /// The commit the repository must be at (`InvalidSwap` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_commit: Option<String>,
}

/// A single applyWrites operation as received on the wire (#110, Option A).
///
/// Accepts BOTH shapes and normalizes to the internal [`WriteOp`]:
/// - the atproto-spec `$type`-discriminated shape
///   (`com.atproto.repo.applyWrites#{create,update,delete}`), which standard
///   bsky-PDS-shaped clients send, and
/// - Aurora's legacy flat `{action, collection, rkey, value}` shape, which
///   existing internal consumers (Phase B cookbooks, admin UI, dev scripts)
///   send.
///
/// `#[serde(untagged)]` tries the discriminated variant first (its `$type` tag
/// is a strong discriminator); a body lacking `$type` falls through to flat.
/// Each `writes` entry deserializes independently, so a request that mixes
/// shapes across entries is accepted — flagged but not policed (no deprecation
/// planned for either shape).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WriteOpInput {
    Discriminated(WriteOpDiscriminated),
    Flat(WriteOpFlat),
}

/// atproto-spec discriminated applyWrites operation (lexicon shape).
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
enum WriteOpDiscriminated {
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        collection: String,
        #[serde(default)]
        rkey: Option<String>,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

/// Aurora's legacy flat applyWrites operation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteOpFlat {
    action: WriteOpAction,
    collection: String,
    #[serde(default)]
    rkey: Option<String>,
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    validate: Option<bool>,
    #[serde(default)]
    swap_cid: Option<String>,
}

impl WriteOpInput {
    /// Normalize either wire shape into the canonical internal [`WriteOp`].
    ///
    /// `create` with an absent rkey gets a server-generated TID (proto-blue
    /// `next_tid`), matching the lexicon (`rkey` optional on create) and the
    /// single-record `createRecord` path. `update`/`delete` require an rkey
    /// (you cannot target a record without one); a flat update/delete missing
    /// rkey is rejected rather than silently mis-targeted. `kryphocron_
    /// authorization` is always `None` here — it is in-process state populated
    /// at internal call sites, never request-bearable (see `WriteOp`).
    fn into_write_op(self) -> PdsResult<WriteOp> {
        match self {
            WriteOpInput::Discriminated(d) => Ok(match d {
                WriteOpDiscriminated::Create {
                    collection,
                    rkey,
                    value,
                } => WriteOp {
                    action: WriteOpAction::Create,
                    collection,
                    rkey: rkey.unwrap_or_else(|| next_tid(None).to_string()),
                    value: Some(value),
                    validate: None,
                    swap_cid: None,
                    kryphocron_authorization: None,
                },
                WriteOpDiscriminated::Update {
                    collection,
                    rkey,
                    value,
                } => WriteOp {
                    action: WriteOpAction::Update,
                    collection,
                    rkey,
                    value: Some(value),
                    validate: None,
                    swap_cid: None,
                    kryphocron_authorization: None,
                },
                WriteOpDiscriminated::Delete { collection, rkey } => WriteOp {
                    action: WriteOpAction::Delete,
                    collection,
                    rkey,
                    value: None,
                    validate: None,
                    swap_cid: None,
                    kryphocron_authorization: None,
                },
            }),
            WriteOpInput::Flat(f) => {
                let rkey = match (f.action, f.rkey) {
                    // create with no rkey → server-generated TID.
                    (WriteOpAction::Create, None) => next_tid(None).to_string(),
                    (_, Some(rkey)) => rkey,
                    // update/delete must name a record.
                    (WriteOpAction::Update, None) | (WriteOpAction::Delete, None) => {
                        return Err(PdsError::Validation(
                            "applyWrites update/delete requires rkey".to_string(),
                        ));
                    }
                };
                Ok(WriteOp {
                    action: f.action,
                    collection: f.collection,
                    rkey,
                    value: f.value,
                    validate: f.validate,
                    swap_cid: f.swap_cid,
                    kryphocron_authorization: None,
                })
            }
        }
    }
}

/// Build the proto-blue Signer that the repository manager uses to sign
/// commits.
///
/// Arc 18 (chainlink #117 / CF3 recon §G): resolve the per-account
/// signing key for `did` and wrap it as `Arc<dyn Signer>`.
///
/// Pre-Arc-18, the four record-write handlers below all signed with
/// the server-wide `ctx.config.authentication.repo_signing_key` (a
/// single key shared across every actor on the instance). This left a
/// signature-chain discontinuity at commit 2 of every repo — genesis
/// was signed by the per-actor key from `plc_keys.atproto_signing_key`
/// ([src/api/account_emit.rs:59-63]) but every subsequent record-write
/// commit was signed by the global key. Latent for Aurora's own paths
/// (which don't verify commit signatures), but federation-visible:
/// any external verifier rotating through the importing DID's
/// published `#atproto` verification method would fail to verify
/// post-genesis commits.
///
/// Caught by Arc 16f Step 5 Phase B Scenario 2 (chainlink #121) on
/// 2026-05-21: importing alice's CAR from instance A into instance B
/// failed `InvalidCommitSignature` despite the signature being
/// genuinely valid for the global key — the published per-account
/// verification method correctly rejected it.
///
/// Mirrors the per-account-signer template inlined at the importRepo
/// handler's CF3 gate ([src/api/repo_import.rs] `account_emit.rs:59`
/// template). Surfaces `Internal` (500) on NotFound — record-write
/// handlers have already passed createSession, so a missing
/// `plc_keys` row is a server-side inconsistency, not an
/// `ActorNotInitialized` (400) condition reserved for importRepo's
/// pre-account-init gate.
pub(crate) async fn create_actor_signer(
    account_manager: &crate::account::AccountManager,
    did: &str,
) -> PdsResult<std::sync::Arc<dyn proto_blue::crypto::Signer>> {
    let key_bytes = account_manager
        .get_atproto_signing_key_bytes(did)
        .await
        .map_err(|e| PdsError::Internal(format!(
            "could not resolve per-account signing key for {}: {}",
            did, e
        )))?;
    let signer = crate::crypto::proto_blue_signer::RepoSigner::from_bytes(&key_bytes)
        .map_err(|e| PdsError::Internal(format!(
            "Failed to construct per-account repo signer for {}: {}",
            did, e
        )))?;
    Ok(std::sync::Arc::new(signer))
}

/// Create a new record (`com.atproto.repo.createRecord`).
///
/// Writes a record to the actor's repo and reconciles blob references
/// in Phase B. Aurora-Locus's lexicons-as-Rust-types convention means
/// the wire contract for this endpoint is this handler's signature
/// (request / response shapes from [`CreateRecordRequest`] /
/// [`CreateRecordResponse`]) plus the error set below.
///
/// # Errors
///
/// Returns `PdsError` mapped to one of the following wire-error codes
/// (see [`crate::error::PdsError`]'s `IntoResponse` for the full
/// HTTP-status mapping):
///
/// - `AuthRequired` (401) — caller is unauthenticated.
/// - `InsufficientScope` / `Forbidden` (403) — OAuth scope check
///   against `AtProtoScope::RepoCreate` failed, or the request's
///   `repo` field disagrees with the authenticated DID.
/// - `RateLimitExceeded` (429) — cross-PDS rate limiter rejected the
///   request.
/// - `InvalidCid` (400) — Arc 16e §9.5.3.5: validate-phase walker
///   ([`extract_blob_cids`](crate::repository::blob_refs::extract_blob_cids))
///   found a malformed or non-DASL CID in a blob ref in the record
///   body. No state mutation occurs (rejection is before Phase A).
/// - `BlobNotFound` (400) — Arc 16e §9.5.3.5: Phase B STRICT could
///   not find a referenced blob's `blob_metadata` row. Per R0c.A
///   spec pin, the wire shape matches bsky-PDS at
///   `packages/pds/src/actor-store/blob/transactor.ts:259-260`.
/// - `Validation` (400) — record-body size limit, lexicon validation,
///   or swap-CID mismatch.
/// - `Database` / `Internal` (500) — sqlx or proto-blue commit
///   failures.
async fn create_record(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<CreateRecordRequest>,
) -> PdsResult<Json<CreateRecordResponse>> {
    tracing::info!("create_record: Starting for collection: {}", req.collection);

    // Require authentication (OAuth, local, or cross-PDS) - Phase 6
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers.clone())
        .await
        .map_err(|e| {
            tracing::error!("create_record: Auth failed: {}", e);
            e
        })?;

    // Enforce OAuth scope if using OAuth authentication
    middleware::enforce_repo_permission(
        &auth,
        &req.collection,
        RepoAction::Create,
        &AtProtoScope::RepoCreate,
    )?;

    let auth_did = auth.did();
    tracing::debug!(
        "create_record: Authenticated as DID: {}, auth_type: {}",
        auth_did,
        if auth.is_oauth() {
            "oauth"
        } else if auth.is_local() {
            "local"
        } else {
            "cross_pds"
        }
    );

    // Apply stricter rate limiting for cross-PDS requests (Phase 4 Security)
    if auth.is_cross_pds() {
        ctx.rate_limiter
            .check_cross_pds(&crate::rate_limit::CallerKey::Account(auth.did().to_string()))?;
        tracing::debug!("create_record: Cross-PDS rate limit check passed");
    }

    // Verify repo matches authenticated user
    if req.repo != auth_did {
        tracing::error!(
            "create_record: Repo mismatch - req: {}, auth: {}",
            req.repo,
            auth_did
        );
        return Err(PdsError::Authorization(
            "Cannot create record in another user's repo".to_string(),
        ));
    }

    // Create repository manager with sequencer
    tracing::debug!("create_record: Creating repository manager with sequencer");
    // §17.4 Step 4 + #136 — go through `for_writer` so the Arc 17
    // lexicon resolver + config snapshot get plumbed when
    // `lexicon_resolver` is `Some`. Centralization is load-bearing:
    // pre-#136, this site chained `.with_blob_store` but not
    // `.with_lexicon`, leaving the dispatch ladder's PRIORITY 2 gate
    // empty and forcing every unknown-NSID write through Optimistic
    // fall-through.
    let repo_mgr =
        RepositoryManager::for_writer(&ctx, auth_did.to_string()).with_swap_commit(req.swap_commit);

    // Create signer from repo key
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    // Create the record. Arc 16e §9.5.4 Step 2: blob refs are tracked
    // inside `apply_writes` Phase B via the wired `blob_store` field
    // rather than by this handler — see the `.with_blob_store(...)`
    // builder call above.
    tracing::debug!("create_record: Calling repo_mgr.create_record");
    let outcome = repo_mgr
        .create_record(
            &req.collection,
            req.rkey.as_deref(),
            req.record,
            req.validate,
            signer,
        )
        .await
        .map_err(|e| {
            tracing::error!("create_record: Failed to create record: {}", e);
            e
        })?;
    let cid = outcome.single_record_cid()?;
    let uri = outcome.results[0].uri.clone();

    // Invalidate read-after-write cache for this user
    ctx.cache_invalidator.invalidate_did(auth_did).await;
    tracing::debug!("create_record: Invalidated cache for DID: {}", auth_did);

    tracing::info!(
        "create_record: Successfully created record - URI: {}, CID: {}",
        uri,
        cid
    );

    // §5.5.4 Phase C: Pipeline C account-age-activity auto-label rules fire on
    // post creation. Best-effort; scoped to feed posts (the activity signal).
    if req.collection == "app.bsky.feed.post" {
        if let Err(e) =
            crate::api::auto_label_rules::evaluate_pipeline_c(&ctx, auth_did, &uri).await
        {
            tracing::warn!(error = %e, author = auth_did, "auto-label Pipeline C failed");
        }
    }

    Ok(Json(CreateRecordResponse {
        uri,
        cid,
        commit: CommitMeta::of(&outcome),
    }))
}

/// Update an existing record, or create if it doesn't exist
/// (`com.atproto.repo.putRecord`).
///
/// Per-record Phase B computes the existing-refs / new-refs
/// difference: added CIDs go through STRICT; dropped CIDs go through
/// `unreference_blob`. Wire contract = this handler's signature
/// (request / response shapes from [`PutRecordRequest`] /
/// [`PutRecordResponse`]) plus the error set below.
///
/// # Errors
///
/// - `AuthRequired` (401) — caller is unauthenticated.
/// - `InsufficientScope` / `Forbidden` (403) — OAuth scope check
///   against `AtProtoScope::RepoUpdate` failed, or `repo` disagrees
///   with the authenticated DID.
/// - `RateLimitExceeded` (429) — cross-PDS rate limiter rejected.
/// - `InvalidCid` (400) — Arc 16e §9.5.3.5: validate-phase walker
///   found a malformed or non-DASL CID in a blob ref in the new
///   record body. No state mutation (rejection is before Phase A).
/// - `BlobNotFound` (400) — Arc 16e §9.5.3.5: Phase B STRICT could
///   not find a newly-referenced blob's `blob_metadata` row.
/// - `Validation` (400) — record-body size or lexicon validation.
/// - `SwapCidMismatch` (409) — `swapRecord` was supplied and does not
///   match the record's current CID (#449).
/// - `NotFound` (404) — `swapRecord` supplied for a record that does
///   not exist. Absent record *without* a swap is a create, not an
///   error.
/// - `Database` / `Internal` (500) — sqlx or proto-blue commit
///   failures.
async fn put_record(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<PutRecordRequest>,
) -> PdsResult<Json<PutRecordResponse>> {
    // Require authentication (OAuth, local, or cross-PDS) - Phase 6
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers.clone()).await?;

    // Enforce OAuth scope if using OAuth authentication
    // putRecord creates the record when it does not exist yet.
    for action in [RepoAction::Create, RepoAction::Update] {
        middleware::enforce_repo_permission(
            &auth,
            &req.collection,
            action,
            &AtProtoScope::RepoUpdate,
        )?;
    }

    let auth_did = auth.did();

    // Apply stricter rate limiting for cross-PDS requests (Phase 4 Security)
    if auth.is_cross_pds() {
        ctx.rate_limiter
            .check_cross_pds(&crate::rate_limit::CallerKey::Account(auth.did().to_string()))?;
    }

    // Verify repo matches authenticated user
    if req.repo != auth_did {
        return Err(PdsError::Authorization(
            "Cannot update record in another user's repo".to_string(),
        ));
    }

    // Create repository manager via §17.4-Step-4 / #136 helper —
    // plumbs the lexicon resolver + config when enabled.
    let repo_mgr =
        RepositoryManager::for_writer(&ctx, auth_did.to_string()).with_swap_commit(req.swap_commit);

    // Create signer from repo key
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    // Upsert the record. putRecord creates when nothing exists at the
    // target rkey and updates otherwise; the swap-CID precondition is
    // enforced by the substrate's single CAS site (#449). Arc 16e §9.5.4
    // Step 2: blob-ref add/drop is computed in Phase B via
    // `read_existing_refs` + set differences; see the
    // `.with_blob_store(...)` builder call above.
    let outcome = repo_mgr
        .put_record(
            &req.collection,
            &req.rkey,
            req.record,
            req.validate,
            req.swap_record,
            signer,
        )
        .await?;

    let uri = format!("at://{}/{}/{}", auth_did, req.collection, req.rkey);

    // Invalidate read-after-write cache for this user
    ctx.cache_invalidator.invalidate_did(auth_did).await;

    Ok(Json(PutRecordResponse {
        uri,
        cid: outcome.single_record_cid()?,
        commit: CommitMeta::of(&outcome),
    }))
}

/// Delete a record (`com.atproto.repo.deleteRecord`).
///
/// Per-record Phase B reads the existing refs and runs
/// `unreference_blob` for each. Delete records carry no new CIDs, so
/// neither `InvalidCid` nor `BlobNotFound` surface from the
/// Arc 16e wiring on this path (`unreference_blob`'s six-variant
/// `UnreferenceOutcome` is log-and-continue, never an error
/// propagation). Wire contract = this handler's signature
/// (request shape from [`DeleteRecordRequest`]) plus the error set
/// below.
///
/// # Errors
///
/// - `AuthRequired` (401) — caller is unauthenticated.
/// - `InsufficientScope` / `Forbidden` (403) — OAuth scope check
///   against `AtProtoScope::RepoDelete` failed, or `repo` disagrees
///   with the authenticated DID.
/// - `RateLimitExceeded` (429) — cross-PDS rate limiter rejected.
/// - `SwapCidMismatch` (409) — `swapRecord` was supplied and does not
///   match the record's current CID (#450).
/// - `NotFound` (404) — `swapRecord` supplied for a record that does
///   not exist. A delete of a non-existent record *without* a swap is
///   an idempotent success, not an error.
/// - `Database` / `Internal` (500) — sqlx or proto-blue commit
///   failures.
async fn delete_record(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<DeleteRecordRequest>,
) -> PdsResult<Json<serde_json::Value>> {
    // Require authentication (OAuth, local, or cross-PDS) - Phase 6
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers.clone()).await?;

    // Enforce OAuth scope if using OAuth authentication
    middleware::enforce_repo_permission(
        &auth,
        &req.collection,
        RepoAction::Delete,
        &AtProtoScope::RepoDelete,
    )?;

    let auth_did = auth.did();

    // Apply stricter rate limiting for cross-PDS requests (Phase 4 Security)
    if auth.is_cross_pds() {
        ctx.rate_limiter
            .check_cross_pds(&crate::rate_limit::CallerKey::Account(auth.did().to_string()))?;
    }

    // Verify repo matches authenticated user
    if req.repo != auth_did {
        return Err(PdsError::Authorization(
            "Cannot delete record from another user's repo".to_string(),
        ));
    }

    // §17.4-Step-4 / #136 — delete writes don't reach the lexicon
    // path (`validate_write` early-returns on `write.value = None`),
    // but route through `for_writer` anyway so the audit grep
    // (#136-guard-2) has a uniform rule.
    let repo_mgr =
        RepositoryManager::for_writer(&ctx, auth_did.to_string()).with_swap_commit(req.swap_commit);

    // Create signer from repo key
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    // Delete the record. deleteRecord is idempotent — an absent record is
    // a no-op success (`Ok(None)`), not a 500 — and the swap-CID
    // precondition is enforced by the substrate's single CAS site
    // (#450). Arc 16e §9.5.4 Step 2: blob refs for the record are
    // unreferenced in Phase B via the wired `blob_store`; see the
    // `.with_blob_store(...)` builder call above.
    let commit = repo_mgr
        .delete_record(&req.collection, &req.rkey, req.swap_record, signer)
        .await?;

    // Invalidate read-after-write cache for this user
    ctx.cache_invalidator.invalidate_did(auth_did).await;

    // The commit the delete landed in; none when the record was already gone.
    Ok(Json(match commit {
        Some((cid, rev)) => serde_json::json!({ "commit": { "cid": cid, "rev": rev } }),
        None => serde_json::json!({}),
    }))
}

/// Get a record
async fn get_record(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(query): Query<GetRecordQuery>,
) -> PdsResult<Json<GetRecordResponse>> {
    let did = &resolve_repo(&ctx, &query.repo).await?;

    // A repository that is taken down, suspended or deactivated is not served
    // (#491), to anyone but its own account and admins. This runs before any
    // read, so neither a public record nor a private post in either form
    // leaves a non-active repository.
    let reader_did = optional_reader(&ctx, &headers).await;
    assert_readable_by(&ctx, did, reader_did.as_deref()).await?;

    // Create repository manager
    let repo_mgr = RepositoryManager::with_validation_mode(
        did.clone(),
        (*ctx.actor_store).clone(),
        ctx.config.validation_mode,
    );

    // Get the record
    let uri = format!("at://{}/{}/{}", did, query.collection, query.rkey);
    let record = match repo_mgr.get_record(&uri).await {
        // The store has no repository for this DID. That is `RepoNotFound`,
        // never a record miss: consumers treat a record miss as "this record
        // was deleted", which a missing repository must not read as (#489).
        Err(PdsError::NotFound(_)) => return Err(PdsError::RepoNotFound(did.clone())),
        other => other?,
    };

    match record {
        Some(value) => {
            // Extract CID from the returned value
            let cid = value
                .get("cid")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // A request for a particular version (`cid`) of a record that
            // has since changed finds nothing (#499), as on the reference
            // PDS: a strong reference that no longer points at the current
            // version must not be told that it does.
            if query.cid.as_deref().is_some_and(|wanted| wanted != cid) {
                return Err(PdsError::RecordNotFound(uri));
            }

            let mut record_value = value
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // v0.9 Arc D (#237a) — decode-on-read for private-tier records.
            // `feed.postPrivate` content is encoded at rest (#236); an
            // authorized reader fetching it here gets decoded plaintext, a
            // non-authorized/anonymous reader gets the encoded form unchanged
            // (transparent — atproto's getRecord-is-public contract + the
            // friction model are both preserved). Aurora-Locus owns the
            // authorization decision (architecture (Y)); the substrate codec is
            // the at-rest layer only. Other NSIDs (public records, audience/
            // block/mute structural records) pass through untouched.
            if query.collection == crate::api::kryphocron_endpoints::NSID_POST_PRIVATE {
                // Optional reader auth (resolved above): a valid session
                // identifies the reader; no/invalid credentials -> anonymous
                // (treated as non-member).
                if matches!(
                    crate::kryphocron_content::authorize_private_read(
                        &ctx,
                        reader_did.as_deref(),
                        did,
                        &record_value,
                    )
                    .await,
                    crate::kryphocron_content::ReadAuthz::Authorized
                ) {
                    // Decode in place. Codec skew surfaces as 410 (the record is
                    // valid but undecodable here); other decode failures surface
                    // as 500. A non-encoded (legacy `text`) record is a no-op.
                    crate::kryphocron_content::decode_private_content(
                        &ctx,
                        did,
                        &query.collection,
                        &query.rkey,
                        &mut record_value,
                    )
                    .await?;
                }
                // Non-authorized: leave the encoded form as stored.
            }

            // Fetch labels for this record
            let labels = ctx
                .label_manager
                .get_labels(&uri)
                .await
                .ok()
                .map(|lbls| lbls.into_iter().map(LabelView::from).collect());

            Ok(Json(GetRecordResponse {
                uri,
                cid,
                value: record_value,
                labels,
            }))
        }
        // A record that does not exist in a repository that does, in any
        // collection, is `RecordNotFound` (HTTP 400): the one error the
        // lexicon declares for the method, and the name consumers use to tell
        // "absent" from any other failure (#489). Private-tier collections
        // answer the same way (#493): an existing private record is served to
        // any caller (decoded or encoded), so a different answer for a
        // missing one would hide nothing.
        None => Err(PdsError::RecordNotFound(uri)),
    }
}

/// The DID named by a read request's `repo`, which the lexicons type as an
/// at-identifier (#499): a DID is taken as given; a handle is looked up among
/// this PDS's accounts, by handle only (never by email), and resolves exactly
/// when `resolveHandle` would. A handle that does not resolve here is
/// `RepoNotFound`.
pub(crate) async fn resolve_repo(ctx: &AppContext, repo: &str) -> PdsResult<String> {
    if repo.starts_with("did:") {
        return Ok(repo.to_string());
    }
    ctx.account_manager
        .get_resolvable_did_by_handle(&repo.to_ascii_lowercase())
        .await?
        .ok_or_else(|| PdsError::RepoNotFound(repo.to_string()))
}

/// The account a read request is made as, if it carries valid credentials.
/// Reads are public, so missing or invalid credentials mean an anonymous
/// reader, not an error.
pub(crate) async fn optional_reader(ctx: &AppContext, headers: &HeaderMap) -> Option<String> {
    if !headers.contains_key(axum::http::header::AUTHORIZATION) {
        return None;
    }
    middleware::require_auth_unified(State(ctx.clone()), headers.clone())
        .await
        .ok()
        .map(|auth| auth.did().to_string())
}

/// Refuse a read of `repo_did` unless the repository is active, or the reader
/// is its own account or an admin (#491). See
/// [`crate::api::sync_helpers::assert_repo_readable`] for what is refused and
/// with which error.
pub(crate) async fn assert_readable_by(
    ctx: &AppContext,
    repo_did: &str,
    reader_did: Option<&str>,
) -> PdsResult<()> {
    let is_admin_or_self = match reader_did {
        Some(reader) if reader == repo_did => true,
        Some(reader) => matches!(ctx.admin_role_manager.get_role(reader).await, Ok(Some(_))),
        None => false,
    };
    crate::api::sync_helpers::assert_repo_readable(ctx, repo_did, is_admin_or_self).await
}


/// List records in a collection (`com.atproto.repo.listRecords`), as the
/// reference PDS does: newest first by record key, oldest first with
/// `reverse=true`, and `cursor` (a record key) continuing in the same order.
async fn list_records(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(query): Query<ListRecordsQuery>,
) -> PdsResult<Json<ListRecordsResponse>> {
    if !LIST_RECORDS_LIMIT.contains(&query.limit) {
        return Err(PdsError::Validation(format!(
            "limit must be between {} and {}",
            LIST_RECORDS_LIMIT.start(),
            LIST_RECORDS_LIMIT.end()
        )));
    }

    // Get the DID
    let did = &resolve_repo(&ctx, &query.repo).await?;

    // Not served for a repository that is not active (#491).
    let reader_did = optional_reader(&ctx, &headers).await;
    assert_readable_by(&ctx, did, reader_did.as_deref()).await?;

    // Create repository manager
    let repo_mgr = RepositoryManager::with_validation_mode(
        did.clone(),
        (*ctx.actor_store).clone(),
        ctx.config.validation_mode,
    );

    // Fetch limit + 1 to determine if there are more records
    let fetch_limit = query.limit + 1;
    let order = if query.reverse {
        crate::actor_store::RkeyOrder::Ascending
    } else {
        crate::actor_store::RkeyOrder::Descending
    };
    let records = repo_mgr
        .list_records(&query.collection, fetch_limit, query.cursor.as_deref(), order)
        .await?;

    // Determine if we have more records and calculate cursor
    let has_more = records.len() as i64 > query.limit;
    let records_to_return = if has_more {
        &records[0..query.limit as usize]
    } else {
        &records[..]
    };

    // Convert to response format and fetch labels
    let mut entries = Vec::new();
    let mut next_cursor: Option<String> = None;

    for rec in records_to_return {
        let uri = rec
            .get("uri")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cid = rec
            .get("cid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let value = rec.get("value").cloned().unwrap_or(serde_json::Value::Null);

        // Extract rkey from URI for cursor (format: at://did/collection/rkey)
        if let Some(rkey) = uri.split('/').next_back() {
            next_cursor = Some(rkey.to_string());
        }

        // Fetch labels for this record
        let labels = ctx
            .label_manager
            .get_labels(&uri)
            .await
            .ok()
            .map(|lbls| lbls.into_iter().map(LabelView::from).collect());

        entries.push(RecordEntry {
            uri,
            cid,
            value,
            labels,
        });
    }

    Ok(Json(ListRecordsResponse {
        records: entries,
        cursor: if has_more { next_cursor } else { None },
    }))
}

/// Describe a repository
async fn describe_repo(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(query): Query<DescribeRepoQuery>,
) -> PdsResult<Json<DescribeRepoResponse>> {
    // Get the DID
    let did = &resolve_repo(&ctx, &query.repo).await?;

    // Not served for a repository that is not active (#491).
    let reader_did = optional_reader(&ctx, &headers).await;
    assert_readable_by(&ctx, did, reader_did.as_deref()).await?;

    // Create repository manager
    let repo_mgr = RepositoryManager::with_validation_mode(
        did.clone(),
        (*ctx.actor_store).clone(),
        ctx.config.validation_mode,
    );

    // Get description with account manager and identity resolver
    let desc = repo_mgr
        .describe_repo(
            Some(&ctx.account_manager),
            Some(ctx.identity_resolver.as_ref()),
        )
        .await?;

    Ok(Json(DescribeRepoResponse {
        did: desc
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        handle: desc
            .get("handle")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        did_doc: desc.get("didDoc").cloned(),
        collections: desc
            .get("collections")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        handle_is_correct: desc
            .get("handleIsCorrect")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
    }))
}

/// Apply a batch of writes (`com.atproto.repo.applyWrites`).
///
/// Performs atomic batch operations with full validation of all
/// operations before execution, duplicate detection, size limit
/// enforcement, and all-or-nothing atomicity. Arc 16e §9.5.3.2.0
/// gives this endpoint the same validate-phase walker as the single-
/// record write handlers: a malformed CID anywhere in the batch
/// rejects the WHOLE batch before Phase A opens, so partial state
/// mutation is structurally impossible.
///
/// Wire contract = this handler's signature (request shape from
/// [`ApplyWritesRequest`]) plus the error set below.
///
/// # Errors
///
/// - `AuthRequired` (401) — caller is unauthenticated.
/// - `InsufficientScope` / `Forbidden` (403) — OAuth scope check
///   against `AtProtoScope::RepoAll` failed, or `repo` disagrees
///   with the authenticated DID.
/// - `RateLimitExceeded` (429) — cross-PDS rate limiter rejected.
/// - `InvalidCid` (400) — Arc 16e §9.5.3.5: validate-phase walker
///   found a malformed or non-DASL CID in a blob ref in any
///   Create/Update record body in the batch. Aborts the whole
///   batch with zero state mutation.
/// - `BlobNotFound` (400) — Arc 16e §9.5.3.5: Phase B STRICT could
///   not find a referenced blob's `blob_metadata` row for any
///   Create/Update in the batch.
/// - `Validation` (400) — batch size limit (>200 ops), duplicate
///   operations, record size, lexicon validation, swap-CID
///   mismatch, or per-op shape errors.
/// - `NotFound` (404) — swap-CID supplied for a record that does
///   not exist.
/// - `Database` / `Internal` (500) — sqlx or proto-blue commit
///   failures.
async fn apply_writes(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<ApplyWritesRequest>,
) -> PdsResult<Json<serde_json::Value>> {
    // Require authentication (OAuth, local, or cross-PDS) - Phase 6
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers.clone()).await?;

    // Enforce OAuth scope if using OAuth authentication
    // apply_writes can do create/update/delete, so a legacy OAuth token needs
    // RepoAll; an atproto-OAuth token is checked per write below.
    if auth.granted_scopes().is_none() {
        middleware::enforce_scope(&auth, &AtProtoScope::RepoAll)?;
    }

    let auth_did = auth.did();

    // Apply stricter rate limiting for cross-PDS requests
    if auth.is_cross_pds() {
        ctx.rate_limiter
            .check_cross_pds(&crate::rate_limit::CallerKey::Account(auth.did().to_string()))?;
    }

    // Verify repo matches authenticated user
    if req.repo != auth_did {
        return Err(PdsError::Authorization(
            "Cannot apply writes to another user's repo".to_string(),
        ));
    }

    // §17.4-Step-4 / #136 — batch writes route the same way: each
    // per-write validate dispatch goes through the lexicon resolver
    // when plumbed, and the §17.3.4 `validate_imports` override
    // fires at validate-phase entry for each write in the batch.
    let repo_mgr =
        RepositoryManager::for_writer(&ctx, auth_did.to_string()).with_swap_commit(req.swap_commit);

    // Prepare writes (converts to PreparedWrite format)
    // Normalize both accepted wire shapes (#110) into the canonical WriteOp.
    // The request's `validate` applies to every write that sets none itself.
    let mut writes = req
        .writes
        .into_iter()
        .map(WriteOpInput::into_write_op)
        .collect::<PdsResult<Vec<WriteOp>>>()?;
    for write in &mut writes {
        write.validate = write.validate.or(req.validate);
    }
    // An OAuth client needs a permission for every write in the batch.
    if auth.granted_scopes().is_some() {
        for write in &writes {
            let action = match write.action {
                WriteOpAction::Create => RepoAction::Create,
                WriteOpAction::Update => RepoAction::Update,
                WriteOpAction::Delete => RepoAction::Delete,
            };
            middleware::enforce_repo_permission(
                &auth,
                &write.collection,
                action,
                &AtProtoScope::RepoAll,
            )?;
        }
    }
    let prepared = repo_mgr.prepare_writes(writes)?;

    tracing::info!(
        "Applying batch of {} operations for {}",
        prepared.len(),
        auth_did
    );

    // Create signer from repo key
    let signer = create_actor_signer(&ctx.account_manager, auth_did).await?;

    // Apply batch atomically (includes validation)
    let outcome = repo_mgr.apply_batch_writes_detailed(prepared, signer).await?;

    tracing::info!(
        "Successfully committed batch for {} (rev: {})",
        auth_did,
        outcome.rev
    );

    Ok(Json(apply_writes_body(&outcome)))
}

/// The `applyWrites` answer: the commit, and one result per write in the
/// order given, each create and update with the stored record's CID.
fn apply_writes_body(outcome: &crate::actor_store::repository::CommitOutcome) -> serde_json::Value {
    let results: Vec<serde_json::Value> = outcome
        .results
        .iter()
        .map(|result| match result.action {
            WriteOpAction::Create => serde_json::json!({
                "$type": "com.atproto.repo.applyWrites#createResult",
                "uri": result.uri,
                "cid": result.cid,
            }),
            WriteOpAction::Update => serde_json::json!({
                "$type": "com.atproto.repo.applyWrites#updateResult",
                "uri": result.uri,
                "cid": result.cid,
            }),
            WriteOpAction::Delete => serde_json::json!({
                "$type": "com.atproto.repo.applyWrites#deleteResult",
            }),
        })
        .collect();
    serde_json::json!({
        "commit": CommitMeta::of(outcome),
        "results": results,
    })
}

/// Query parameters for listMissingBlobs
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMissingBlobsQuery {
    #[serde(default = "default_missing_blobs_limit")]
    limit: i64,
    #[serde(default)]
    cursor: Option<String>,
}

fn default_missing_blobs_limit() -> i64 {
    500
}

/// A blob that is referenced by a record but not yet uploaded
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBlob {
    cid: String,
    record_uri: String,
}

/// Response for listMissingBlobs
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListMissingBlobsResponse {
    blobs: Vec<RecordBlob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// List missing blobs endpoint
///
/// Returns blobs that are referenced by records but have not yet been uploaded.
/// This is useful for resuming failed uploads or identifying incomplete records.
async fn list_missing_blobs(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(query): Query<ListMissingBlobsQuery>,
) -> PdsResult<Json<ListMissingBlobsResponse>> {
    // Require authentication
    let auth = middleware::require_auth_unified(State(ctx.clone()), headers.clone()).await?;
    let auth_did = auth.did();

    // Validate limit (1-1000)
    let limit = query.limit.clamp(1, 1000);

    // Query for missing blobs
    let missing = ctx
        .blob_store
        .list_missing_blobs(auth_did, limit + 1, query.cursor.as_deref())
        .await?;

    // Determine if there's more data (pagination)
    let has_more = missing.len() > limit as usize;
    let results: Vec<_> = missing.into_iter().take(limit as usize).collect();

    // Build cursor from last item
    let cursor = if has_more {
        results.last().map(|(cid, _)| cid.clone())
    } else {
        None
    };

    // Convert to response format
    let blobs = results
        .into_iter()
        .map(|(cid, record_uri)| RecordBlob { cid, record_uri })
        .collect();

    Ok(Json(ListMissingBlobsResponse { blobs, cursor }))
}

#[cfg(test)]
mod get_record_miss_tests {
    //! #489: what `getRecord` answers when there is nothing to return.
    //! #491: and that a repository which is not active is not read at all.
    use super::*;
    use crate::admin::moderation::{ApplyActionParams, ModerationAction};

    const PROFILE: &str = "app.bsky.actor.profile";
    const PRIVATE_POST: &str = "tools.kryphocron.feed.postPrivate";

    /// A context with one account (and its repository); returns its DID.
    async fn ctx_with_repo() -> (AppContext, String) {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let account = ctx
            .account_manager
            .create_account(
                "getrecord.localhost".to_string(),
                None,
                "password123".to_string(),
                None,
                None,
            )
            .await
            .expect("create account");
        ctx.actor_store
            .create(&account.did)
            .await
            .expect("create repo");
        (ctx, account.did)
    }

    async fn moderate(ctx: &AppContext, did: &str, action: ModerationAction) {
        ctx.moderation_manager
            .apply_action(ApplyActionParams {
                did,
                action,
                reason: "test",
                moderated_by: "did:plc:admin",
                expires_in: None,
                report_id: None,
                notes: None,
            })
            .await
            .expect("apply moderation action");
    }

    /// Call the handler anonymously and return its error.
    async fn miss(ctx: &AppContext, repo: &str, collection: &str) -> PdsError {
        let query: GetRecordQuery = serde_json::from_value(serde_json::json!({
            "repo": repo,
            "collection": collection,
            "rkey": "self",
        }))
        .unwrap();
        match get_record(State(ctx.clone()), HeaderMap::new(), Query(query)).await {
            Ok(_) => panic!("expected a miss for {repo}/{collection}"),
            Err(e) => e,
        }
    }

    /// #499: a `cid` that is not the record's current one finds nothing.
    #[tokio::test]
    async fn a_cid_that_is_not_current_is_record_not_found() {
        let (ctx, did) = ctx_with_repo().await;
        crate::kryphocron_audience::test_support::seed(
            &ctx,
            &did,
            PROFILE,
            "self",
            serde_json::json!({ "displayName": "x" }),
        )
        .await;
        let current = format!("cid-{PROFILE}-self");
        let fetch = |cid: &str| {
            let query: GetRecordQuery = serde_json::from_value(serde_json::json!({
                "repo": did,
                "collection": PROFILE,
                "rkey": "self",
                "cid": cid,
            }))
            .unwrap();
            get_record(State(ctx.clone()), HeaderMap::new(), Query(query))
        };
        let found = fetch(&current).await.expect("current version");
        assert_eq!(found.0.cid, current);
        let err = fetch("bafyolderversion").await.expect_err("stale version");
        assert_eq!(
            err,
            PdsError::RecordNotFound(format!("at://{did}/{PROFILE}/self"))
        );
    }

    #[tokio::test]
    async fn missing_public_record_is_record_not_found() {
        let (ctx, did) = ctx_with_repo().await;
        let err = miss(&ctx, &did, PROFILE).await;
        assert_eq!(
            err,
            PdsError::RecordNotFound(format!("at://{did}/{PROFILE}/self"))
        );
    }

    #[tokio::test]
    async fn missing_repository_is_repo_not_found_not_a_record_miss() {
        let (ctx, _did) = ctx_with_repo().await;
        let absent = "did:plc:nosuchrepo0000000000000000";
        let err = miss(&ctx, absent, PROFILE).await;
        assert!(
            matches!(&err, PdsError::RepoNotFound(did) if did == absent),
            "got {err:?}"
        );
    }

    /// #493: a missing private-tier record is the same `RecordNotFound` as a
    /// public one, in each private collection a consumer keeps a copy of.
    #[tokio::test]
    async fn missing_private_tier_record_is_record_not_found() {
        let (ctx, did) = ctx_with_repo().await;
        for collection in [
            PRIVATE_POST,
            "tools.kryphocron.policy.audience",
            "tools.kryphocron.graph.block",
        ] {
            let err = miss(&ctx, &did, collection).await;
            assert_eq!(
                err,
                PdsError::RecordNotFound(format!("at://{did}/{collection}/self")),
                "{collection}"
            );
        }
    }

    /// #493: `com.atproto.sync.getRecord` reads through the same store and
    /// answers a miss with the error its lexicon declares.
    #[tokio::test]
    async fn sync_get_record_miss_is_record_not_found() {
        let (ctx, did) = ctx_with_repo().await;
        let err = crate::actor_store::car::export_record_to_car(
            &ctx.actor_store,
            &did,
            PROFILE,
            "self",
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            PdsError::RecordNotFound(format!("at://{did}/{PROFILE}/self"))
        );
    }

    /// #491: a deactivated repository is refused for both tiers, and served
    /// again once reactivated. The refusal is never a record-level miss.
    #[tokio::test]
    async fn deactivated_repository_is_refused_then_served_again() {
        let (ctx, did) = ctx_with_repo().await;
        ctx.account_manager.deactivate_account(&did).await.unwrap();
        for collection in [PROFILE, PRIVATE_POST] {
            let err = miss(&ctx, &did, collection).await;
            assert!(
                matches!(&err, PdsError::RepoDeactivated(d) if d == &did),
                "{collection}: got {err:?}"
            );
        }

        ctx.account_manager.reactivate_account(&did).await.unwrap();
        // Active again: back to the ordinary answer (nothing was written, so
        // that is a record miss in both tiers).
        for collection in [PROFILE, PRIVATE_POST] {
            assert!(matches!(
                miss(&ctx, &did, collection).await,
                PdsError::RecordNotFound(_)
            ));
        }
    }

    #[tokio::test]
    async fn taken_down_repository_is_refused() {
        let (ctx, did) = ctx_with_repo().await;
        moderate(&ctx, &did, ModerationAction::Takedown).await;
        for collection in [PROFILE, PRIVATE_POST] {
            let err = miss(&ctx, &did, collection).await;
            assert!(
                matches!(&err, PdsError::RepoTakendown(d) if d == &did),
                "{collection}: got {err:?}"
            );
        }
    }

    /// A Suspend action lives in `account_moderation`, not on the actor row,
    /// so it needs its own check.
    #[tokio::test]
    async fn suspended_repository_is_refused() {
        let (ctx, did) = ctx_with_repo().await;
        moderate(&ctx, &did, ModerationAction::Suspend).await;
        for collection in [PROFILE, PRIVATE_POST] {
            let err = miss(&ctx, &did, collection).await;
            assert!(
                matches!(&err, PdsError::RepoSuspended(d) if d == &did),
                "{collection}: got {err:?}"
            );
        }
    }

    /// Who may still read a repository that is not active: its own account
    /// and admins, as in the reference PDS. An audience member (any other
    /// account) and an anonymous reader may not.
    #[tokio::test]
    async fn only_the_owner_and_admins_read_a_non_active_repository() {
        let (ctx, did) = ctx_with_repo().await;
        ctx.account_manager.deactivate_account(&did).await.unwrap();

        assert!(assert_readable_by(&ctx, &did, Some(&did)).await.is_ok());
        let other = "did:plc:audiencemember00000000000";
        assert!(matches!(
            assert_readable_by(&ctx, &did, Some(other)).await,
            Err(PdsError::RepoDeactivated(_))
        ));
        assert!(matches!(
            assert_readable_by(&ctx, &did, None).await,
            Err(PdsError::RepoDeactivated(_))
        ));

        let admin = "did:plc:adminreader000000000000000";
        ctx.admin_role_manager
            .grant_role(admin, crate::admin::roles::Role::Admin, "system", None)
            .await
            .unwrap();
        assert!(assert_readable_by(&ctx, &did, Some(admin)).await.is_ok());
    }

    #[tokio::test]
    async fn list_records_and_describe_repo_refuse_a_non_active_repository() {
        let (ctx, did) = ctx_with_repo().await;
        ctx.account_manager.deactivate_account(&did).await.unwrap();

        let list: ListRecordsQuery =
            serde_json::from_value(serde_json::json!({"repo": did, "collection": PROFILE}))
                .unwrap();
        match list_records(State(ctx.clone()), HeaderMap::new(), Query(list)).await {
            Err(PdsError::RepoDeactivated(_)) => {}
            Err(e) => panic!("listRecords: got {e:?}"),
            Ok(_) => panic!("listRecords served a deactivated repository"),
        }

        let describe: DescribeRepoQuery =
            serde_json::from_value(serde_json::json!({"repo": did})).unwrap();
        match describe_repo(State(ctx.clone()), HeaderMap::new(), Query(describe)).await {
            Err(PdsError::RepoDeactivated(_)) => {}
            Err(e) => panic!("describeRepo: got {e:?}"),
            Ok(_) => panic!("describeRepo served a deactivated repository"),
        }

        // A repository this PDS does not host is RepoNotFound on both.
        let absent: ListRecordsQuery = serde_json::from_value(
            serde_json::json!({"repo": "did:plc:nosuchrepo0000000000000000", "collection": PROFILE}),
        )
        .unwrap();
        match list_records(State(ctx.clone()), HeaderMap::new(), Query(absent)).await {
            Err(PdsError::RepoNotFound(_)) => {}
            Err(e) => panic!("listRecords absent: got {e:?}"),
            Ok(_) => panic!("listRecords served an absent repository"),
        }
    }

    // ---- listRecords order (prism's locus-listrecords-order.md) ----

    const POST: &str = "app.bsky.feed.post";
    const RKEYS: [&str; 5] = [
        "3mxaaaaaaaa2a",
        "3mxbbbbbbbb2b",
        "3mxcccccccc2c",
        "3mxdddddddd2d",
        "3mxeeeeeeee2e",
    ];

    async fn ctx_with_posts() -> (AppContext, String) {
        let (ctx, did) = ctx_with_repo().await;
        for (i, rkey) in RKEYS.iter().enumerate() {
            let lex = proto_blue::lex_json::json_to_lex(&serde_json::json!({ "n": i }));
            let cid = proto_blue::lex_cbor::cid_for_lex(&lex).unwrap().to_string();
            let bytes = proto_blue::lex_cbor::encode(&lex).unwrap();
            ctx.actor_store.put_block(&did, &cid, &bytes).await.unwrap();
            let uri = format!("at://{did}/{POST}/{rkey}");
            ctx.actor_store
                .put_record(&did, &uri, &cid, POST, rkey, "r")
                .await
                .unwrap();
        }
        (ctx, did)
    }

    /// One `listRecords` call, from a query string as a client sends it:
    /// the record keys it answers, and its cursor.
    async fn list(ctx: &AppContext, did: &str, params: &str) -> PdsResult<(Vec<String>, Option<String>)> {
        let query: ListRecordsQuery =
            serde_urlencoded::from_str(&format!("repo={did}&collection={POST}{params}")).unwrap();
        let Json(page) = list_records(State(ctx.clone()), HeaderMap::new(), Query(query)).await?;
        let rkeys = page
            .records
            .iter()
            .map(|r| r.uri.rsplit('/').next().unwrap().to_string())
            .collect();
        Ok((rkeys, page.cursor))
    }

    /// Every page of a listing, following the cursor.
    async fn all_pages(ctx: &AppContext, did: &str, params: &str) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let after = cursor.as_ref().map(|c| format!("&cursor={c}")).unwrap_or_default();
            let (rkeys, next) = list(ctx, did, &format!("{params}{after}")).await.unwrap();
            pages.push(rkeys);
            match next {
                Some(next) => cursor = Some(next),
                None => return pages,
            }
        }
    }

    #[tokio::test]
    async fn list_records_is_newest_first_and_pages_downward() {
        let (ctx, did) = ctx_with_posts().await;
        let pages = all_pages(&ctx, &did, "&limit=2").await;
        assert_eq!(
            pages,
            vec![
                vec![RKEYS[4], RKEYS[3]],
                vec![RKEYS[2], RKEYS[1]],
                vec![RKEYS[0]],
            ]
        );
    }

    #[tokio::test]
    async fn list_records_reverse_is_oldest_first_and_pages_upward() {
        let (ctx, did) = ctx_with_posts().await;
        let pages = all_pages(&ctx, &did, "&limit=2&reverse=true").await;
        assert_eq!(
            pages,
            vec![
                vec![RKEYS[0], RKEYS[1]],
                vec![RKEYS[2], RKEYS[3]],
                vec![RKEYS[4]],
            ]
        );
        // reverse=false is the default order.
        let (rkeys, _) = list(&ctx, &did, "&reverse=false").await.unwrap();
        assert_eq!(rkeys, RKEYS.iter().rev().copied().collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn list_records_refuses_a_limit_out_of_range() {
        let (ctx, did) = ctx_with_posts().await;
        for limit in ["0", "-1", "101"] {
            let result = list(&ctx, &did, &format!("&limit={limit}")).await;
            assert!(
                matches!(result, Err(PdsError::Validation(_))),
                "limit={limit}: got {result:?}"
            );
        }
        let (rkeys, cursor) = list(&ctx, &did, "&limit=100").await.unwrap();
        assert_eq!(rkeys.len(), RKEYS.len());
        assert!(cursor.is_none());
    }
}

#[cfg(test)]
mod apply_writes_shape_tests {
    //! #110: applyWrites accepts both the atproto-spec `$type`-discriminated
    //! shape and Aurora's legacy flat shape; both normalize to `WriteOp`.
    use super::*;

    fn norm(json: &str) -> WriteOp {
        serde_json::from_str::<WriteOpInput>(json)
            .expect("deserialize WriteOpInput")
            .into_write_op()
            .expect("normalize to WriteOp")
    }

    #[test]
    fn apply_writes_answers_a_result_per_write_with_record_cids() {
        use crate::actor_store::repository::{CommitOutcome, WriteResult};
        let outcome = CommitOutcome {
            commit_cid: "bafycommit".to_string(),
            rev: "3rev".to_string(),
            results: vec![
                WriteResult {
                    action: WriteOpAction::Create,
                    uri: "at://did:plc:a/app.bsky.feed.post/1".to_string(),
                    cid: Some("bafyrecord1".to_string()),
                },
                WriteResult {
                    action: WriteOpAction::Update,
                    uri: "at://did:plc:a/app.bsky.actor.profile/self".to_string(),
                    cid: Some("bafyrecord2".to_string()),
                },
                WriteResult {
                    action: WriteOpAction::Delete,
                    uri: "at://did:plc:a/app.bsky.feed.like/2".to_string(),
                    cid: None,
                },
            ],
        };
        let body = apply_writes_body(&outcome);
        assert_eq!(body["commit"], serde_json::json!({"cid": "bafycommit", "rev": "3rev"}));
        let results = body["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["$type"], "com.atproto.repo.applyWrites#createResult");
        assert_eq!(results[0]["cid"], "bafyrecord1");
        assert_eq!(results[1]["$type"], "com.atproto.repo.applyWrites#updateResult");
        assert_eq!(results[1]["uri"], "at://did:plc:a/app.bsky.actor.profile/self");
        assert_eq!(
            results[2],
            serde_json::json!({"$type": "com.atproto.repo.applyWrites#deleteResult"})
        );
    }

    #[test]
    fn both_shapes_normalize_equivalently() {
        // create
        let disc = norm(
            r#"{"$type":"com.atproto.repo.applyWrites#create","collection":"app.bsky.feed.post","rkey":"rk1","value":{"text":"hi"}}"#,
        );
        let flat = norm(
            r#"{"action":"create","collection":"app.bsky.feed.post","rkey":"rk1","value":{"text":"hi"}}"#,
        );
        assert_eq!(disc.action, WriteOpAction::Create);
        assert_eq!(flat.action, WriteOpAction::Create);
        assert_eq!(disc.collection, flat.collection);
        assert_eq!(disc.rkey, "rk1");
        assert_eq!(disc.rkey, flat.rkey);
        assert_eq!(disc.value, flat.value);

        // update
        let disc = norm(
            r#"{"$type":"com.atproto.repo.applyWrites#update","collection":"c","rkey":"rk2","value":{"a":1}}"#,
        );
        let flat = norm(r#"{"action":"update","collection":"c","rkey":"rk2","value":{"a":1}}"#);
        assert_eq!(disc.action, WriteOpAction::Update);
        assert_eq!(flat.action, WriteOpAction::Update);
        assert_eq!(disc.rkey, flat.rkey);
        assert_eq!(disc.value, flat.value);

        // delete — discriminated #delete has no `value` field at all.
        let disc =
            norm(r#"{"$type":"com.atproto.repo.applyWrites#delete","collection":"c","rkey":"rk3"}"#);
        let flat = norm(r#"{"action":"delete","collection":"c","rkey":"rk3"}"#);
        assert_eq!(disc.action, WriteOpAction::Delete);
        assert_eq!(flat.action, WriteOpAction::Delete);
        assert_eq!(disc.rkey, "rk3");
        assert_eq!(flat.rkey, "rk3");
        assert!(disc.value.is_none());
    }

    #[test]
    fn create_without_rkey_server_generates_and_update_delete_require_it() {
        // create with no rkey → server-generated TID (both shapes).
        let disc = norm(
            r#"{"$type":"com.atproto.repo.applyWrites#create","collection":"c","value":{"x":1}}"#,
        );
        let flat = norm(r#"{"action":"create","collection":"c","value":{"x":1}}"#);
        assert!(!disc.rkey.is_empty(), "discriminated create rkey server-generated");
        assert!(!flat.rkey.is_empty(), "flat create rkey server-generated");

        // flat update/delete without rkey is rejected (cannot target a record).
        let err = serde_json::from_str::<WriteOpInput>(r#"{"action":"delete","collection":"c"}"#)
            .expect("deserialize")
            .into_write_op();
        assert!(err.is_err(), "flat delete without rkey must error");
    }
}
