//! Federation management API endpoints (Phase 1 & 2).
//!
//! Phase 2 federated-search handlers (`search_actors`, `search_posts` and
//! their request/response structs) are staged but intentionally not yet
//! wired to routes — they collide with the appview proxy paths and are
//! held for a follow-up. Allow dead_code at the module level rather than
//! sprinkling per-item attributes.
#![allow(dead_code)]

use crate::{
    auth::AdminAuthContext,
    context::AppContext,
    error::{PdsError, PdsResult},
    federation::search::{ActorResult, PostResult},
};
use axum::{
    extract::{Query, State},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

/// Build federation routes
pub fn routes() -> Router<AppContext> {
    Router::new()
        // Phase 1: Admin & status endpoints
        .route("/xrpc/com.aurora.federation.status", get(federation_status))
        // Federation-scoped describe (#344) — public; Aurora-aware posture.
        .route(
            "/xrpc/com.aurora.federation.describePosture",
            get(describe_posture),
        )
        .route(
            "/xrpc/com.aurora.federation.listInstances",
            get(list_instances),
        )
        .route(
            "/xrpc/com.aurora.federation.refreshDiscovery",
            post(refresh_discovery),
        )
        // Phase 2: Federated search (dead code, see commit message)
        // Routes deferred to avoid collision with appview proxy.
        .route(
            "/xrpc/com.aurora.federation.aggregateTimeline",
            get(aggregate_timeline),
        )
        // Phase 4: DPoP support
        .route("/xrpc/com.aurora.dpop.getNonce", get(get_dpop_nonce))
}

/// `com.aurora.federation.describePosture` — public, federation-scoped describe
/// (#344). Aurora-aware tooling calls this for richer federation posture than
/// upstream `com.atproto.server.describeServer`'s minimal `federation`
/// extension provides. Under Aurora-Locus's per-subsystem describe convention
/// (Path B), server-identity fields (DID, handle domains, links) live in
/// `describeServer`; this endpoint is federation-only. Future Aurora subsystems
/// get their own `describe*` in their own namespace as needed. Public-readable
/// (no auth), mirroring describeServer's public contract — Aurora-aware peers
/// discover capabilities without credentials.
///
/// Intentionally excludes `peer_pds` (the trusted-issuer allowlist — disclosing
/// who this PDS trusts invites adversarial probing). When federation is off, only
/// `enabled` + `auroraVersion` are emitted.
///
/// Every field is the live, effective value — the same resolution
/// `describeServer` uses — because Aurora peers (and kryphocron) federate on
/// this endpoint, the way standard PDSes federate on `describeServer`.
async fn describe_posture(State(ctx): State<AppContext>) -> Json<FederationDescribePosture> {
    use crate::api::aurora_admin::{
        resolve_appview_url, resolve_federation_flag, FEDERATION_CRAWL_ENABLED_KEY,
        FEDERATION_FIREHOSE_ENABLED_KEY,
    };
    let fc = &ctx.config.federation;
    // §2.1 (#397): effective gate (runtime override → config), not raw env.
    let on = ctx.federation_enabled;
    // Runtime overrides (→ env fallback), so a panel change is advertised
    // without a restart, exactly as describeServer advertises it.
    let firehose_enabled =
        resolve_federation_flag(&ctx, FEDERATION_FIREHOSE_ENABLED_KEY, fc.firehose_enabled).await;
    let crawl_enabled =
        resolve_federation_flag(&ctx, FEDERATION_CRAWL_ENABLED_KEY, fc.crawl_enabled).await;
    let appview_url = resolve_appview_url(&ctx).await;
    // The live relay set (#460), not the boot env seed.
    let relays = crate::api::federation_crawl::live_relays(&ctx).await;
    Json(FederationDescribePosture {
        enabled: on,
        appview_url: if on { appview_url } else { None },
        // The deployment's real public URL (PDS_SERVICE_PUBLIC_URL, runtime
        // override applied at boot), not the deprecated, consumer-less
        // PDS_PUBLIC_URL (federation.public_url), which is usually unset.
        public_url: on.then(|| ctx.config.service.effective_public_url()),
        firehose_enabled: on.then_some(firehose_enabled),
        crawl_enabled: on.then_some(crawl_enabled),
        relay_urls: if on && !relays.is_empty() {
            Some(relays)
        } else {
            None
        },
        aurora_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Federation-scoped posture (`com.aurora.federation.describePosture`, #344).
/// All optional fields are omitted when federation is off (or, for the URLs,
/// when not configured); `aurora_version` is always present for
/// compatibility-check tooling.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FederationDescribePosture {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    appview_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    firehose_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crawl_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_urls: Option<Vec<String>>,
    aurora_version: String,
}

/// Get federation status (public endpoint)
async fn federation_status(State(ctx): State<AppContext>) -> Json<FederationStatusResponse> {
    // §2.1 (#397): effective gate (runtime override → config), not raw env.
    let enabled = ctx.federation_enabled;
    let relay_state = crate::api::federation_crawl::relay_state(&ctx)
        .await
        .to_string();
    let discovery_active = ctx.pds_discovery.is_some();
    let auth_active = ctx.federation_auth.is_some();

    let known_instances = if let Some(discovery) = &ctx.pds_discovery {
        discovery.get_known_instances().await.len()
    } else {
        0
    };

    Json(FederationStatusResponse {
        enabled,
        relay_state,
        discovery_active,
        auth_active,
        known_instances,
        relay_urls: crate::api::federation_crawl::live_relays(&ctx).await,
    })
}

/// List known PDS instances (admin only)
async fn list_instances(
    State(ctx): State<AppContext>,
    _admin: AdminAuthContext,
) -> PdsResult<Json<ListInstancesResponse>> {
    let instances = if let Some(discovery) = &ctx.pds_discovery {
        discovery.get_known_instances().await
    } else {
        vec![]
    };

    Ok(Json(ListInstancesResponse { instances }))
}

/// Manually trigger discovery refresh (admin only)
async fn refresh_discovery(
    State(ctx): State<AppContext>,
    _admin: AdminAuthContext,
) -> PdsResult<Json<RefreshResponse>> {
    if let Some(discovery) = &ctx.pds_discovery {
        discovery.refresh_instances().await;
        let count = discovery.get_known_instances().await.len();
        Ok(Json(RefreshResponse {
            success: true,
            instances_found: count,
        }))
    } else {
        Ok(Json(RefreshResponse {
            success: false,
            instances_found: 0,
        }))
    }
}

// Response types

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationStatusResponse {
    pub enabled: bool,
    /// `disabled`, `none`, `idle` or `announcing` (see `federation_crawl::relay_state`).
    pub relay_state: String,
    pub discovery_active: bool,
    pub auth_active: bool,
    pub known_instances: usize,
    pub relay_urls: Vec<String>,
}

#[derive(Serialize)]
pub struct ListInstancesResponse {
    pub instances: Vec<crate::federation::discovery::PdsInstance>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub success: bool,
    pub instances_found: usize,
}

// Phase 2: Federated Search Endpoints

/// Search for actors across federated PDS instances
async fn search_actors(
    State(ctx): State<AppContext>,
    Query(params): Query<SearchQuery>,
) -> PdsResult<Json<SearchActorsResponse>> {
    // Validate query
    if params.q.trim().is_empty() {
        return Err(PdsError::Validation("Query cannot be empty".to_string()));
    }

    // Check if federation is enabled
    let search = ctx
        .federated_search
        .as_ref()
        .ok_or_else(|| PdsError::Validation("Federation is not enabled".to_string()))?;

    // Rate limiting is handled by the rate_limiter middleware
    let limit = params.limit.unwrap_or(25).min(100); // Cap at 100 results

    let actors = search.search_actors(&params.q, limit).await?;

    Ok(Json(SearchActorsResponse { actors }))
}

/// Search for posts across federated PDS instances
async fn search_posts(
    State(ctx): State<AppContext>,
    Query(params): Query<SearchQuery>,
) -> PdsResult<Json<SearchPostsResponse>> {
    // Validate query
    if params.q.trim().is_empty() {
        return Err(PdsError::Validation("Query cannot be empty".to_string()));
    }

    // Check if federation is enabled
    let search = ctx
        .federated_search
        .as_ref()
        .ok_or_else(|| PdsError::Validation("Federation is not enabled".to_string()))?;

    let limit = params.limit.unwrap_or(25).min(100);

    let posts = search.search_posts(&params.q, limit).await?;

    Ok(Json(SearchPostsResponse { posts }))
}

/// Aggregate timeline from multiple users across federated PDS instances
async fn aggregate_timeline(
    State(ctx): State<AppContext>,
    Query(params): Query<TimelineQuery>,
) -> PdsResult<Json<TimelineResponse>> {
    // Validate DIDs
    if params.dids.is_empty() {
        return Err(PdsError::Validation(
            "At least one DID is required".to_string(),
        ));
    }

    if params.dids.len() > 50 {
        return Err(PdsError::Validation("Maximum 50 DIDs allowed".to_string()));
    }

    // Check if federation is enabled
    let search = ctx
        .federated_search
        .as_ref()
        .ok_or_else(|| PdsError::Validation("Federation is not enabled".to_string()))?;

    let limit = params.limit.unwrap_or(50).min(200);

    let posts = search.aggregate_timeline(params.dids, limit).await?;

    Ok(Json(TimelineResponse { feed: posts }))
}

// Query parameter types

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub dids: Vec<String>,
    pub limit: Option<usize>,
}

/// Custom deserializer for comma-separated string lists
fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

// Response types for Phase 2

#[derive(Serialize)]
pub struct SearchActorsResponse {
    pub actors: Vec<ActorResult>,
}

#[derive(Serialize)]
pub struct SearchPostsResponse {
    pub posts: Vec<PostResult>,
}

#[derive(Serialize)]
pub struct TimelineResponse {
    pub feed: Vec<PostResult>,
}

/// Get DPoP nonce (Phase 4)
///
/// Returns a fresh nonce for clients to use in DPoP proof JWTs.
/// Clients should call this endpoint before making DPoP-protected requests.
///
/// Reference: https://datatracker.ietf.org/doc/html/rfc9449#section-8
async fn get_dpop_nonce(State(ctx): State<AppContext>) -> PdsResult<Json<DPopNonceResponse>> {
    let dpop_nonce_store = ctx
        .dpop_nonce_store
        .as_ref()
        .ok_or_else(|| PdsError::Internal("DPoP support not enabled".to_string()))?;

    let nonce = dpop_nonce_store.generate_nonce().await;

    Ok(Json(DPopNonceResponse { nonce }))
}

#[derive(Serialize)]
pub struct DPopNonceResponse {
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aurora peers and kryphocron federate on describePosture, so it must
    /// advertise the live values: runtime overrides over env, the real service
    /// public URL, and the live relay set.
    #[tokio::test]
    async fn describe_posture_advertises_live_values() {
        let _g = crate::api::federation_peers::test_support::serial()
            .lock()
            .await;
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|c| {
            c.federation.enabled = true;
            c.federation.firehose_enabled = false;
            c.federation.crawl_enabled = false;
            c.federation.appview_url = Some("https://env-appview.example".to_string());
            c.federation.public_url = None; // deprecated PDS_PUBLIC_URL unset
            c.federation.relay_urls = vec!["https://relay.example".to_string()];
        })
        .await;
        for (key, value) in [
            (
                crate::api::aurora_admin::FEDERATION_FIREHOSE_ENABLED_KEY,
                "true",
            ),
            (
                crate::api::aurora_admin::FEDERATION_CRAWL_ENABLED_KEY,
                "true",
            ),
            (
                crate::api::aurora_admin::FEDERATION_APPVIEW_URL_KEY,
                r#""https://runtime-appview.example""#,
            ),
        ] {
            sqlx::query(
                "INSERT INTO runtime_settings (key, value, last_modified, last_modified_by) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(key)
            .bind(value)
            .bind("2026-01-01T00:00:00Z")
            .bind("did:plc:op")
            .execute(&ctx.account_db)
            .await
            .unwrap();
        }

        let Json(posture) = describe_posture(State(ctx.clone())).await;
        let v = serde_json::to_value(posture).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["firehoseEnabled"], true, "runtime override, not env");
        assert_eq!(v["crawlEnabled"], true, "runtime override, not env");
        assert_eq!(v["appviewUrl"], "https://runtime-appview.example");
        assert_eq!(v["publicUrl"], ctx.config.service.effective_public_url());
        assert_eq!(v["relayUrls"], serde_json::json!(["https://relay.example"]));
    }

    #[test]
    fn test_routes_compile() {
        // Ensure routes() compiles correctly
        let _router = routes();
    }

    // #344 — describePosture wire shape. Disabled posture is enabled +
    // auroraVersion only (all flags/urls omitted by the optional serializer).
    #[test]
    fn describe_posture_disabled_emits_minimal_shape() {
        let v = serde_json::to_value(FederationDescribePosture {
            enabled: false,
            appview_url: None,
            public_url: None,
            firehose_enabled: None,
            crawl_enabled: None,
            relay_urls: None,
            aurora_version: "0.0.0-test".to_string(),
        })
        .unwrap();
        assert_eq!(v["enabled"], false);
        assert!(v["auroraVersion"].is_string());
        assert_eq!(
            v.as_object().unwrap().len(),
            2,
            "disabled posture omits all flags/urls: {v}"
        );
    }

    // The federation-scoped posture must never leak the trusted-peer allowlist,
    // the internal auto-stream toggle, or server-identity fields — even fully
    // populated. (Those are SuperAdmin-only / live in describeServer.)
    #[test]
    fn describe_posture_excludes_peer_and_identity_fields() {
        let v = serde_json::to_value(FederationDescribePosture {
            enabled: true,
            appview_url: Some("https://api.example".to_string()),
            public_url: Some("https://pds.example".to_string()),
            firehose_enabled: Some(true),
            crawl_enabled: Some(false),
            relay_urls: Some(vec!["https://relay.example".to_string()]),
            aurora_version: "0.0.0-test".to_string(),
        })
        .unwrap();
        assert_eq!(v["appviewUrl"], "https://api.example");
        assert!(v["relayUrls"].is_array());
        let obj = v.as_object().unwrap();
        for forbidden in [
            "peerPds",
            "peer_pds",
            "did",
            "availableUserDomains",
            "links",
        ] {
            assert!(!obj.contains_key(forbidden), "describePosture must not expose {forbidden}");
        }
    }
}
