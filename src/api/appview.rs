//! AppView reads with read-after-write consistency (#471).
//!
//! Every `app.bsky.*` method this PDS does not implement is forwarded by the
//! generic service proxy (`api::service_proxy`). The three methods here are
//! the ones the reference PDS also keeps local: they go through the same proxy
//! (same target resolution and service auth) and then merge in the account's
//! own records the AppView has not indexed yet, so a user sees their new post
//! or profile edit immediately. Reading another account's feed or profile is
//! a plain proxied call.

use crate::{
    api::{middleware::AccountAuth, service_proxy},
    context::AppContext,
    error::{PdsError, PdsResult},
    read_after_write::{self, LocalViewer},
};
use axum::{
    body::{Body, Bytes},
    extract::{Query, RawQuery, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

/// Largest upstream JSON body merged (bytes).
const MAX_MERGE_BODY: usize = 16 * 1024 * 1024;

/// Read-after-write routes.
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route("/xrpc/app.bsky.feed.getTimeline", get(get_timeline))
        .route("/xrpc/app.bsky.feed.getAuthorFeed", get(get_author_feed))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
}

/// The `actor` query parameter.
#[derive(Debug, Deserialize)]
struct ActorParam {
    actor: String,
}

/// The account's timeline, with its own unindexed posts merged in.
async fn get_timeline(
    State(ctx): State<AppContext>,
    auth: AccountAuth,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> PdsResult<Response> {
    proxy_with_read_after_write(
        &ctx,
        &auth,
        &headers,
        "app.bsky.feed.getTimeline",
        query.as_deref(),
        merge_timeline_feed,
    )
    .await
}

/// An author feed; the account's own feed gets its unindexed posts merged in.
async fn get_author_feed(
    State(ctx): State<AppContext>,
    auth: AccountAuth,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Query(param): Query<ActorParam>,
) -> PdsResult<Response> {
    const NSID: &str = "app.bsky.feed.getAuthorFeed";
    if param.actor == auth.did {
        proxy_with_read_after_write(
            &ctx,
            &auth,
            &headers,
            NSID,
            query.as_deref(),
            merge_author_feed,
        )
        .await
    } else {
        plain_proxy(&ctx, &auth, &headers, NSID, query.as_deref()).await
    }
}

/// A profile; the account's own profile gets its unindexed edits merged in.
async fn get_profile(
    State(ctx): State<AppContext>,
    auth: AccountAuth,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Query(param): Query<ActorParam>,
) -> PdsResult<Response> {
    const NSID: &str = "app.bsky.actor.getProfile";
    if param.actor == auth.did {
        proxy_with_read_after_write(&ctx, &auth, &headers, NSID, query.as_deref(), merge_profile)
            .await
    } else {
        plain_proxy(&ctx, &auth, &headers, NSID, query.as_deref()).await
    }
}

/// Forward a GET through the service proxy, as the account.
async fn plain_proxy(
    ctx: &AppContext,
    auth: &AccountAuth,
    headers: &HeaderMap,
    nsid: &str,
    query: Option<&str>,
) -> PdsResult<Response> {
    let target = service_proxy::resolve_target(ctx, headers, nsid).await?;
    service_proxy::forward(
        ctx,
        &target,
        nsid,
        Method::GET,
        query,
        headers,
        Bytes::new(),
        Some(auth),
    )
    .await
}

/// Forward through the service proxy, then merge the account's records newer
/// than the AppView's `atproto-repo-rev` into the response. Any response that
/// can't be merged (an error, no rev header, a non-JSON body, nothing newer
/// locally) is returned exactly as the upstream sent it.
async fn proxy_with_read_after_write<F>(
    ctx: &AppContext,
    auth: &AccountAuth,
    headers: &HeaderMap,
    nsid: &str,
    query: Option<&str>,
    merge_fn: F,
) -> PdsResult<Response>
where
    F: FnOnce(
        serde_json::Value,
        &LocalViewer,
        read_after_write::LocalRecords,
    ) -> PdsResult<serde_json::Value>,
{
    let target = service_proxy::resolve_target(ctx, headers, nsid).await?;
    let upstream = service_proxy::forward(
        ctx,
        &target,
        nsid,
        Method::GET,
        query,
        headers,
        Bytes::new(),
        Some(auth),
    )
    .await?;

    let repo_rev = upstream
        .headers()
        .get("atproto-repo-rev")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(repo_rev) = repo_rev.filter(|_| upstream.status().is_success()) else {
        return Ok(upstream);
    };

    let (parts, body) = upstream.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_MERGE_BODY)
        .await
        .map_err(|e| {
            PdsError::UpstreamFailure(format!("reading the AppView response failed: {e}"))
        })?;
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    };

    let user_did = auth.did.as_str();
    let local_records = if let Some(cached) = ctx.local_records_cache.get(user_did, &repo_rev).await
    {
        tracing::debug!(
            "Cache HIT for read-after-write: did={}, rev={}",
            user_did,
            repo_rev
        );
        (*cached).clone()
    } else {
        tracing::debug!(
            "Cache MISS for read-after-write: did={}, rev={}",
            user_did,
            repo_rev
        );
        let records = ctx
            .actor_store
            .get_records_since_rev(user_did, &repo_rev)
            .await?;
        ctx.local_records_cache
            .set(user_did, &repo_rev, records.clone())
            .await;
        records
    };
    if local_records.count == 0 {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }

    let viewer = LocalViewer::with_appview(
        user_did.to_string(),
        Arc::clone(&ctx.account_manager),
        Arc::clone(&ctx.actor_store),
        // Arc 12 §5.3.2 Gap 1: localhost-aware self-URL.
        ctx.service_url(),
        Some(target.url.clone()),
    );
    let merged = merge_fn(json, &viewer, local_records)?;
    Ok(build_response(parts.status, parts.headers, merged))
}

/// Merge local posts into timeline feed
fn merge_timeline_feed(
    mut body: serde_json::Value,
    viewer: &LocalViewer,
    local: read_after_write::LocalRecords,
) -> PdsResult<serde_json::Value> {
    let feed = body
        .get_mut("feed")
        .and_then(|f| f.as_array_mut())
        .ok_or_else(|| PdsError::Internal("Invalid timeline response format".to_string()))?;

    let feed_vec: Vec<serde_json::Value> = std::mem::take(feed);
    let merged = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            read_after_write::format_and_insert_posts_in_feed(viewer, feed_vec, &local.posts),
        )
    })?;

    body["feed"] = serde_json::Value::Array(merged);
    Ok(body)
}

/// Merge local posts into author feed
fn merge_author_feed(
    mut body: serde_json::Value,
    viewer: &LocalViewer,
    local: read_after_write::LocalRecords,
) -> PdsResult<serde_json::Value> {
    let feed = body
        .get_mut("feed")
        .and_then(|f| f.as_array_mut())
        .ok_or_else(|| PdsError::Internal("Invalid author feed response format".to_string()))?;

    let feed_vec: Vec<serde_json::Value> = std::mem::take(feed);
    let merged = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            read_after_write::format_and_insert_posts_in_feed(viewer, feed_vec, &local.posts),
        )
    })?;

    body["feed"] = serde_json::Value::Array(merged);
    Ok(body)
}

/// Merge local profile into profile response
fn merge_profile(
    mut body: serde_json::Value,
    viewer: &LocalViewer,
    local: read_after_write::LocalRecords,
) -> PdsResult<serde_json::Value> {
    // If there's a local profile update, merge it into the response
    if let Some(_profile_descript) = local.profile {
        let local_profile = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(viewer.get_profile_basic())
        })?;

        if let Some(profile) = local_profile {
            // Update display name if present
            if let Some(display_name) = profile.display_name {
                body["displayName"] = serde_json::Value::String(display_name);
            }

            // Update avatar if present
            if let Some(avatar) = profile.avatar {
                body["avatar"] = serde_json::Value::String(avatar);
            }
        }
    }

    Ok(body)
}

/// Build HTTP response from status, headers, and body
fn build_response(status: StatusCode, headers: HeaderMap, body: serde_json::Value) -> Response {
    let mut response = Json(body).into_response();
    *response.status_mut() = status;

    // Copy relevant headers
    let response_headers = response.headers_mut();
    for (key, value) in headers.iter() {
        if let Ok(header_name) = HeaderName::try_from(key.as_str()) {
            if let Ok(header_value) = HeaderValue::try_from(value.as_bytes()) {
                response_headers.insert(header_name, header_value);
            }
        }
    }

    response
}
