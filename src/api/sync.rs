//! Synchronization API endpoints
//!
//! Implements com.atproto.sync.* endpoints for federation and repository export
//!
//! These endpoints enable:
//! - Repository synchronization across PDSs
//! - External crawlers and indexers
//! - Backup and migration
//! - ATProto spec compliance

use crate::{
    actor_store::car,
    context::AppContext,
    error::{PdsError, PdsResult},
};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

/// Request parameters for getRepo
#[derive(Debug, Deserialize)]
pub struct GetRepoParams {
    /// DID of the repository
    pub did: String,
    /// Optional: commit CID to retrieve specific version (incremental sync)
    pub since: Option<String>,
}

/// Request parameters for getLatestCommit
#[derive(Debug, Deserialize)]
pub struct GetLatestCommitParams {
    /// DID of the repository
    pub did: String,
}

/// Response for getLatestCommit
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatestCommitResponse {
    pub cid: String,
    pub rev: String,
}

/// Request parameters for getBlocks
#[derive(Debug, Deserialize)]
pub struct GetBlocksParams {
    /// DID of the repository
    pub did: String,
    /// List of CIDs to fetch
    pub cids: Vec<String>,
}

/// Request parameters for getBlob
#[derive(Debug, Deserialize)]
pub struct GetBlobParams {
    /// DID of the repository
    pub did: String,
    /// CID of the blob
    pub cid: String,
}

/// Request parameters for listBlobs
#[derive(Debug, Deserialize)]
pub struct ListBlobsParams {
    /// DID of the repository
    pub did: String,
    /// Optional: only return blobs since this timestamp
    pub since: Option<String>,
    /// Optional: maximum number of results (default: 100, max: 1000)
    pub limit: Option<i64>,
    /// Optional: cursor for pagination
    pub cursor: Option<String>,
}

/// Response for listBlobs
#[derive(Debug, Serialize)]
pub struct ListBlobsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub cids: Vec<String>,
}

/// Request parameters for listRepos
#[derive(Debug, Deserialize)]
pub struct ListReposParams {
    /// Optional cursor for pagination
    pub cursor: Option<String>,
    /// Optional limit (default: 500, max: 1000)
    pub limit: Option<i64>,
}

/// Response for listRepos
#[derive(Debug, Serialize)]
pub struct ListReposResponse {
    pub repos: Vec<RepoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Repository information
#[derive(Debug, Serialize)]
pub struct RepoInfo {
    pub did: String,
    pub head: String,
    pub rev: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Request parameters for getRepoStatus
#[derive(Debug, Deserialize)]
pub struct GetRepoStatusParams {
    /// DID of the repository
    pub did: String,
}

/// Response for getRepoStatus
#[derive(Debug, Serialize)]
pub struct GetRepoStatusResponse {
    pub did: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

/// Request parameters for getRecord
#[derive(Debug, Deserialize)]
pub struct GetRecordParams {
    /// DID of the repository
    pub did: String,
    /// Collection name
    pub collection: String,
    /// Record key
    pub rkey: String,
}

/// Get a repository as a CAR file export.
///
/// Implements `com.atproto.sync.getRepo`. Arc 14 §7.3.9 / §7.4 Step 7:
/// federation-public, no auth required (matches bsky-PDS
/// `authorizationOrAdminTokenOptional` posture per Sub-step 0.B).
/// `is_admin_or_self` is `false` for unauthenticated callers.
pub async fn get_repo(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(params): Query<GetRepoParams>,
) -> PdsResult<Response> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    // Export repository as CAR
    let car_bytes =
        car::export_repo_to_car(&ctx.actor_store, &params.did, params.since.as_deref())
            .await
            .map_err(repo_not_found(&params.did))?;

    // Return CAR file as application/vnd.ipld.car
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.car\"", params.did),
        )
        .body(Body::from(car_bytes))
        .unwrap())
}

/// Get the latest commit for a repository.
///
/// Implements `com.atproto.sync.getLatestCommit`. Arc 14 §7.3.9 /
/// §7.4 Step 7: federation-public, no auth required.
pub async fn get_latest_commit(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(params): Query<GetLatestCommitParams>,
) -> PdsResult<Json<LatestCommitResponse>> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    // Get the repository root CID (latest commit)
    let repo_root = ctx
        .actor_store
        .get_repo_root(&params.did)
        .await
        .map_err(repo_not_found(&params.did))?;

    Ok(Json(LatestCommitResponse {
        cid: repo_root.cid,
        rev: repo_root.rev,
    }))
}

/// Get specific blocks from a repository.
///
/// Implements `com.atproto.sync.getBlocks`. Arc 14 §7.4 Step 7
/// (parity edge case noted in recon Sub-step 0.B enumeration —
/// `getBlocks` is not in §7.3.9's locked-7 list but exhibits the
/// same auth-required vs bsky-PDS-optional divergence, so auth is
/// removed for parity).
pub async fn get_blocks(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    // `cids` repeats in the query string (`cids=a&cids=b`); the axum-extra
    // extractor reads repeated keys into the list (#499). The plain one
    // refused every request with "expected a sequence".
    axum_extra::extract::Query(params): axum_extra::extract::Query<GetBlocksParams>,
) -> PdsResult<Response> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    // Fetch the requested blocks
    let block_data = ctx
        .actor_store
        .get_blocks_by_cids(&params.did, &params.cids)
        .await?;

    // Check if any blocks are missing
    if block_data.len() != params.cids.len() {
        let found_cids: Vec<&str> = block_data.iter().map(|(cid, _)| cid.as_str()).collect();
        let missing: Vec<&str> = params
            .cids
            .iter()
            .filter(|cid| !found_cids.contains(&cid.as_str()))
            .map(|s| s.as_str())
            .collect();
        return Err(PdsError::BlockNotFound(format!(
            "Could not find cids: {:?}",
            missing
        )));
    }

    // Get repo root for CAR header
    let repo_root = ctx
        .actor_store
        .get_repo_root(&params.did)
        .await
        .map_err(repo_not_found(&params.did))?;

    // Convert blocks to CAR
    let car_bytes = car::blocks_to_car(block_data, Some(&repo_root.cid)).await?;

    // Return CAR file
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
        .body(Body::from(car_bytes))
        .unwrap())
}

/// Get a blob by CID.
///
/// Implements `com.atproto.sync.getBlob`. Arc 14 §7.3.9 / §7.4 Step 7:
/// federation-public, no auth required.
pub async fn get_blob(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(params): Query<GetBlobParams>,
) -> PdsResult<Response> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    // The blob must be this account's (#499): uploaded by it, or used by
    // one of its records. Fetching by CID alone served any blob on the PDS,
    // a taken-down account's included, under any active account's name.
    if !ctx
        .blob_store
        .owners(&params.cid)
        .await?
        .iter()
        .any(|owner| owner == &params.did)
    {
        return Err(PdsError::BlobNotFound(params.cid.clone()));
    }
    let (data, mime_type) = ctx
        .blob_store
        .get(&params.cid)
        .await?
        .ok_or_else(|| PdsError::BlobNotFound(params.cid.clone()))?;

    // Byte ranges, ETag and 304 as on `/blob/:cid`: video players need
    // ranges to play and seek, and private videos play from here. Security
    // headers as on the reference PDS.
    let mut response =
        crate::api::blob::blob_bytes_response(data, &mime_type, &params.cid, &headers);
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        header::HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    Ok(response)
}

/// List blob CIDs in a repository.
///
/// Implements `com.atproto.sync.listBlobs`. Arc 14 §7.3.9 / §7.4 Step 7:
/// federation-public, no auth required.
pub async fn list_blobs(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(params): Query<ListBlobsParams>,
) -> PdsResult<Json<ListBlobsResponse>> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    let limit = params.limit.unwrap_or(100).min(1000);

    // Get blob CIDs
    let cids = ctx
        .blob_store
        .list_blob_cids(
            &params.did,
            params.since.as_deref(),
            limit,
            params.cursor.as_deref(),
        )
        .await?;

    // Cursor is the last CID if we hit the limit
    let cursor = if cids.len() as i64 == limit {
        cids.last().cloned()
    } else {
        None
    };

    Ok(Json(ListBlobsResponse { cursor, cids }))
}

/// List all repositories on this PDS
///
/// Implements com.atproto.sync.listRepos
pub async fn list_repos(
    State(ctx): State<AppContext>,
    Query(params): Query<ListReposParams>,
) -> PdsResult<Json<ListReposResponse>> {
    let limit = params.limit.unwrap_or(500).min(1000);

    // Get list of all accounts with pagination
    let accounts = ctx
        .account_manager
        .list_accounts(params.cursor.as_deref(), limit)
        .await?;

    // Status reads the moderation record too (#499), for the whole page at
    // once.
    let dids: Vec<String> = accounts.iter().map(|a| a.did.clone()).collect();
    let moderation = ctx.moderation_manager.active_flags_for(&dids).await?;

    // Build repository info for each account
    let mut repos = Vec::new();
    for account in &accounts {
        // Get the repository root for this DID
        if let Ok(repo_root) = ctx.actor_store.get_repo_root(&account.did).await {
            let state = crate::api::account_state::state_of(
                account,
                moderation.get(&account.did).copied().unwrap_or_default(),
            );

            repos.push(RepoInfo {
                did: account.did.clone(),
                head: repo_root.cid,
                rev: repo_root.rev,
                active: state.active,
                status: state.status_str().map(str::to_string),
            });
        }
    }

    // The cursor follows the accounts read, not the repositories returned
    // (#499): an account without a repository root is skipped, and counting
    // only what was kept ended the listing early at any page with such an
    // account, so relays never saw the accounts after it.
    let cursor = if accounts.len() as i64 == limit {
        accounts.last().map(|a| a.did.clone())
    } else {
        None
    };

    Ok(Json(ListReposResponse { repos, cursor }))
}

/// Get repository status
///
/// Implements com.atproto.sync.getRepoStatus
pub async fn get_repo_status_endpoint(
    State(ctx): State<AppContext>,
    Query(params): Query<GetRepoStatusParams>,
) -> PdsResult<Json<GetRepoStatusResponse>> {
    // No auth required - this is public info about repo availability

    // An account not hosted here is `RepoNotFound`, as the lexicon declares
    // (#499); it was a generic `NotFound`.
    let account = match ctx.account_manager.get_account(&params.did).await {
        Ok(account) => account,
        Err(PdsError::NotFound(_)) => return Err(PdsError::RepoNotFound(params.did.clone())),
        Err(e) => return Err(e),
    };

    // One status for every surface (#499): this read the account row only,
    // so a suspended account was reported active.
    let state = crate::api::account_state::state_for(&ctx, &account).await?;
    let (active, status) = (state.active, state.status_str().map(str::to_string));

    let rev = if active {
        ctx.actor_store
            .get_repo_root(&params.did)
            .await
            .ok()
            .map(|root| root.rev)
    } else {
        None
    };

    Ok(Json(GetRepoStatusResponse {
        did: params.did,
        active,
        status,
        rev,
    }))
}

/// Get a specific record as CAR file.
///
/// Implements `com.atproto.sync.getRecord`. Arc 14 §7.3.9 / §7.4 Step 7:
/// federation-public, no auth required.
pub async fn get_record(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(params): Query<GetRecordParams>,
) -> PdsResult<Response> {
    // The account itself and admins read a repository that is not active,
    // as on the reference PDS (#499); a deactivated account exports its
    // own repository before migrating.
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    crate::api::repo::assert_readable_by(&ctx, &params.did, reader.as_deref()).await?;

    // Export record as CAR
    let car_bytes = car::export_record_to_car(
        &ctx.actor_store,
        &params.did,
        &params.collection,
        &params.rkey,
    )
    .await?;

    // Return CAR file
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response())
}

/// Map the store's "no repository root" to `RepoNotFound`, the name the
/// sync lexicons declare (#499); other errors pass through.
fn repo_not_found(did: &str) -> impl Fn(PdsError) -> PdsError + '_ {
    move |e| match e {
        PdsError::NotFound(_) => PdsError::RepoNotFound(did.to_string()),
        other => other,
    }
}

/// Build sync API routes
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(get_latest_commit),
        )
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
        .route(
            "/xrpc/com.atproto.sync.getRepoStatus",
            get(get_repo_status_endpoint),
        )
        .route("/xrpc/com.atproto.sync.getRecord", get(get_record))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #499: getBlocks reads `cids` from a query string, once or repeated.
    #[tokio::test]
    async fn get_blocks_reads_repeated_cids_from_the_query_string() {
        use axum::extract::FromRequestParts;
        for (query, expected) in [
            ("did=did:plc:test&cids=a", vec!["a"]),
            ("did=did:plc:test&cids=a&cids=b", vec!["a", "b"]),
        ] {
            let (mut parts, ()) = axum::http::Request::builder()
                .uri(format!("/xrpc/com.atproto.sync.getBlocks?{query}"))
                .body(())
                .unwrap()
                .into_parts();
            let axum_extra::extract::Query(params) =
                axum_extra::extract::Query::<GetBlocksParams>::from_request_parts(&mut parts, &())
                    .await
                    .expect(query);
            assert_eq!(params.did, "did:plc:test");
            assert_eq!(params.cids, expected);
        }
    }

    #[test]
    fn test_get_repo_params_deserialize() {
        let json = r#"{"did":"did:plc:test","since":"bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"}"#;
        let params: GetRepoParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.did, "did:plc:test");
        assert!(params.since.is_some());
    }

    #[test]
    fn test_latest_commit_response_serialize() {
        let response = LatestCommitResponse {
            cid: "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454".to_string(),
            rev: "3l4example".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("cid"));
        assert!(json.contains("rev"));
    }

    #[test]
    fn test_list_blobs_params_deserialize() {
        let json = r#"{"did":"did:plc:test","limit":50,"cursor":"bafyreiabc"}"#;
        let params: ListBlobsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.did, "did:plc:test");
        assert_eq!(params.limit, Some(50));
        assert_eq!(params.cursor, Some("bafyreiabc".to_string()));
    }

    /// getBlob serves byte ranges, which video players need to play and
    /// seek (private videos play from here), with its security headers.
    #[tokio::test]
    async fn get_blob_serves_byte_ranges() {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let account = ctx
            .account_manager
            .create_account("ranges.localhost".into(), None, "password123".into(), None, None)
            .await
            .unwrap();
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let staged = ctx
            .blob_store
            .stage_blob(data.clone(), Some("video/mp4"), &account.did)
            .await
            .unwrap();
        ctx.blob_store.commit_blob(&staged.cid).await.unwrap();

        let fetch = |range: Option<&'static str>| {
            let ctx = ctx.clone();
            let params = GetBlobParams { did: account.did.clone(), cid: staged.cid.clone() };
            async move {
                let mut headers = HeaderMap::new();
                if let Some(range) = range {
                    headers.insert(header::RANGE, range.parse().unwrap());
                }
                get_blob(State(ctx), headers, Query(params)).await.unwrap()
            }
        };

        let whole = fetch(None).await;
        assert_eq!(whole.status(), StatusCode::OK);
        assert_eq!(whole.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(whole.headers()["x-content-type-options"], "nosniff");

        let first = fetch(Some("bytes=0-1023")).await;
        assert_eq!(first.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(first.headers()[header::CONTENT_RANGE], "bytes 0-1023/4096");
        assert_eq!(first.headers()["content-security-policy"], "default-src 'none'; sandbox");
        let body = axum::body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), &data[..1024]);

        let tail = fetch(Some("bytes=-96")).await;
        assert_eq!(tail.headers()[header::CONTENT_RANGE], "bytes 4000-4095/4096");

        assert_eq!(fetch(Some("bytes=4096-")).await.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }
}
