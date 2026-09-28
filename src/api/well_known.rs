use crate::identity::did_document::{build_did_document, DidDocument};
use crate::identity::handle_validation::is_under_service_handle_domain;
/// Well-known endpoints
/// Handles /.well-known/* endpoints for DID resolution and other standards
use crate::{context::AppContext, crypto::plc::PlcSigner, error::PdsResult};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri},
    response::{Json, Response},
    routing::get,
    Router,
};

/// Build well-known routes
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route("/.well-known/atproto-did", get(atproto_did))
        .route("/.well-known/did.json", get(did_document))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
}

/// Arc 12 §5.3.10 OAuth protected-resource metadata.
///
/// Registered unconditionally. The only mode-dependent field is
/// `authorization_servers`: `[entryway_url]` when `EntrywayConfig`
/// is set, `[service_url]` otherwise. CORS preflight succeeds and
/// the response advertises permissive cross-origin headers per the
/// spec's "publicly fetchable" semantics.
pub async fn oauth_protected_resource(
    State(ctx): State<AppContext>,
) -> PdsResult<Response> {
    let resource = ctx.service_url();
    let authorization_server = match ctx.config.entryway.as_ref() {
        Some(entryway) => entryway.url.clone(),
        None => resource.clone(),
    };
    let body = serde_json::json!({
        "resource": resource,
        "authorization_servers": [authorization_server],
        "scopes_supported": ["atproto", "transition:generic"],
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| {
        crate::error::PdsError::Internal(format!(
            "Failed to serialise oauth-protected-resource body: {}",
            e
        ))
    })?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body_bytes.into())
        .map_err(|e| {
            crate::error::PdsError::Internal(format!(
                "Failed to build oauth-protected-resource response: {}",
                e
            ))
        })
}

/// /.well-known/atproto-did
///
/// Answers by the request's `Host` (the hostname being verified):
/// - the service host (`PDS_HOSTNAME`, or the host of `PDS_SERVICE_PUBLIC_URL`)
///   → the server's own DID (did:web service resolution, federation discovery);
/// - a host strictly under a service handle domain → the DID of the active
///   local account holding that handle (ATProto HTTPS handle verification),
///   or 404 `User not found` when there is none or it is deactivated/taken down;
/// - any other host → 404.
///
/// Only the plain `Host` header (or HTTP/2 `:authority`) is read.
/// `X-Forwarded-Host` is deliberately not trusted (nothing else in the codebase
/// trusts it, and it is client-controlled unless a proxy overwrites it); reverse
/// proxies must preserve the original `Host`, which Caddy's `reverse_proxy`
/// does by default.
pub async fn atproto_did(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    uri: Uri,
) -> PdsResult<Response> {
    // HTTP/1.1 carries the hostname in `Host`; HTTP/2 in the `:authority`
    // pseudo-header, which surfaces as the request URI's authority.
    let raw_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()));
    let Some(host) = raw_host.and_then(normalize_host) else {
        return plain_text(StatusCode::NOT_FOUND, "User not found");
    };

    if is_service_host(&ctx, &host) {
        return plain_text(StatusCode::OK, ctx.service_did());
    }

    if !is_under_service_handle_domain(&host, &ctx.config.identity.service_handle_domains) {
        return plain_text(StatusCode::NOT_FOUND, "User not found");
    }

    match ctx.account_manager.get_active_did_by_handle(&host).await? {
        Some(did) => plain_text(StatusCode::OK, &did),
        None => plain_text(StatusCode::NOT_FOUND, "User not found"),
    }
}

/// Reduce a `Host` value to a bare lowercase hostname: strip any `:port`
/// (including after a bracketed IPv6 literal) and a trailing root dot.
/// `None` for an empty result.
fn normalize_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let host = if let Some(rest) = raw.strip_prefix('[') {
        // [v6]:port → v6 literal (kept bracket-free; never a handle anyway).
        rest.split(']').next().unwrap_or_default()
    } else {
        raw.split(':').next().unwrap_or_default()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether `host` (already normalised) names this PDS itself rather than one
/// of its account handles.
fn is_service_host(ctx: &AppContext, host: &str) -> bool {
    let service = &ctx.config.service;
    if normalize_host(&service.hostname).as_deref() == Some(host) {
        return true;
    }
    service
        .public_url
        .as_deref()
        .and_then(|url| url.split_once("://").map(|(_, rest)| rest))
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .and_then(normalize_host)
        .as_deref()
        == Some(host)
}

/// Build a `text/plain` response.
fn plain_text(status: StatusCode, body: &str) -> PdsResult<Response> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(body.to_string().into())
        .map_err(|e| crate::error::PdsError::Internal(format!("Failed to build response: {}", e)))
}

/// /.well-known/did.json
///
/// Returns the full DID document for this PDS server
/// Used for did:web DID resolution
pub async fn did_document(State(ctx): State<AppContext>) -> PdsResult<Json<DidDocument>> {
    let did = ctx.service_did().to_string();

    // Generate the DID document with verification methods and services
    let doc = generate_did_document(&ctx, &did).await?;

    Ok(Json(doc))
}

/// Generate a complete DID document for a did:web DID
///
/// Creates a DID document containing:
/// - Service endpoints (PDS URL)
/// - Verification methods (signing keys)
/// - Also known as (handles)
async fn generate_did_document(ctx: &AppContext, did: &str) -> PdsResult<DidDocument> {
    // v0.10 Arc 1 Phase D (#414 / R1 F-6): the server-own doc is now built by the
    // shared `build_did_document` builder (the same one the per-account did:web
    // serve route uses), supplying the server's own repo signing key as the
    // `#atproto` verification method and no `alsoKnownAs`. Byte-equivalence with
    // the prior hand-built doc is not required (R2 Focus #3).
    let signer = PlcSigner::from_hex(&ctx.config.authentication.repo_signing_key)?;
    let public_key_multibase = generate_multibase_key(&signer)?;
    Ok(build_did_document(
        did,
        &public_key_multibase,
        ctx.service_url(),
        None,
    ))
}

/// Generate multibase-encoded public key from signer
///
/// Uses base58btc encoding with 'z' prefix (multibase format)
fn generate_multibase_key(signer: &PlcSigner) -> PdsResult<String> {
    use k256::ecdsa::VerifyingKey;

    // Get the verifying key from the signing key
    let verifying_key: VerifyingKey = signer.verifying_key();

    // Get compressed public key (33 bytes: 1 byte prefix + 32 bytes X coordinate)
    let public_key_bytes = verifying_key.to_encoded_point(true);
    let compressed_bytes = public_key_bytes.as_bytes();

    // Encode as base58btc with multibase 'z' prefix
    // For secp256k1, we use the compressed form
    let encoded = bs58::encode(compressed_bytes).into_string();

    // Return with multibase prefix 'z' for base58btc
    Ok(format!("z{}", encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    // Service/VerificationMethod are no longer constructed in module code (the
    // shared build_did_document owns that); the tests still build them directly.
    use crate::identity::did_document::{Service, VerificationMethod};
    use std::path::PathBuf;

    #[test]
    fn test_well_known_path() {
        // Well-known path should be at root level
        assert_eq!("/.well-known/atproto-did", "/.well-known/atproto-did");
    }

    fn create_test_config() -> ServerConfig {
        ServerConfig {
            service: ServiceConfig {
                hostname: "localhost".to_string(),
                port: 2583,
                service_did: "did:web:localhost".to_string(),
                version: "0.1.0".to_string(),
                blob_upload_limit: 5242880,
                public_url: None,
                max_blob_fetch_size: 50_000_000,
                blob_fetch_timeout_seconds: 30,
                blob_fetch_max_retries: 3,
                accepting_imports: true,
                max_import_size: None,
            },
            storage: StorageConfig {
                data_directory: PathBuf::from("./data"),
                account_db: PathBuf::from("./data/account.sqlite"),
                sequencer_db: PathBuf::from("./data/sequencer.sqlite"),
                did_cache_db: PathBuf::from("./data/did_cache.sqlite"),
                actor_store_directory: PathBuf::from("./data/actors"),
                blobstore: BlobstoreConfig::Disk {
                    location: PathBuf::from("./data/blobs"),
                    tmp_location: PathBuf::from("./data/temp"),
                },
            },
            database: Default::default(),
            authentication: AuthConfig {
                jwt_secret: "test_secret_key_that_is_32_chars".to_string(),
                repo_signing_key: "a".repeat(64), // Valid hex key
                plc_rotation_key: "b".repeat(64), // Valid hex key
                password_login_enabled: false,
                admin_totp_encryption_key_hex: None,
                oauth: OAuthConfig {
                    client_id: "test-client".to_string(),
                    redirect_uri: "http://localhost:3000/oauth/callback".to_string(),
                    pds_url: "http://localhost:3000".to_string(),
                },
                jwt_sunset_date: "Sat, 31 Dec 2024 23:59:59 GMT".to_string(),
                oauth_migration_guide_url: "https://docs.example.com/oauth-migration".to_string(),
            },
            identity: IdentityConfig {
                did_plc_url: "https://plc.directory".to_string(),
                service_handle_domains: vec![".localhost".to_string()],
                did_cache_stale_ttl: 3600,
                did_cache_max_ttl: 86400,
                recovery_did_key: None,
            },
            email: None,
            invites: InviteConfig {
                required: false,
                interval: 604800,
                epoch: "2024-01-01T00:00:00Z".to_string(),
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                global_requests_per_minute: 3000,
                exempt_admin_assets: true,
                buckets_retention_days: 7,
                trust_proxy: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
            federation: FederationConfig {
                enabled: false,
                relay_urls: vec![],
                appview_url: None,
                firehose_enabled: false,
                crawl_enabled: false,
                public_url: None,
                peer_pds: vec![],
            },
            validation_mode: crate::validation::ValidationMode::Optimistic,
            distributed_state_mode: Default::default(),
            maintenance_pool: Default::default(),
            gc_sweep: Default::default(),
            bind_audit_orphan_marker: Default::default(),
            blob_metadata: Default::default(),
            entryway: None,
            lexicon: crate::config::LexiconConfig::default(),
            kryphocron: crate::config::KryphocronConfig::default(),
        }
    }

    #[test]
    fn test_multibase_key_generation() {
        // Create a test signer
        let test_key = vec![0x42u8; 32]; // Valid 32-byte key
        let signer = PlcSigner::new(&test_key).unwrap();

        let result = generate_multibase_key(&signer);

        assert!(result.is_ok());
        let multibase = result.unwrap();

        // Should start with 'z' (base58btc multibase prefix)
        assert!(multibase.starts_with('z'));

        // Should be longer than just the prefix
        assert!(multibase.len() > 1);

        // Should be valid base58 after the prefix
        let base58_part = &multibase[1..];
        assert!(bs58::decode(base58_part).into_vec().is_ok());
    }

    #[test]
    fn test_multibase_determinism() {
        // Same key should produce same multibase encoding
        let test_key = vec![0x42u8; 32];
        let signer1 = PlcSigner::new(&test_key).unwrap();
        let signer2 = PlcSigner::new(&test_key).unwrap();

        let multibase1 = generate_multibase_key(&signer1).unwrap();
        let multibase2 = generate_multibase_key(&signer2).unwrap();

        assert_eq!(multibase1, multibase2);
    }

    #[tokio::test]
    async fn test_did_document_structure() {
        let config = create_test_config();
        let did = "did:web:localhost";

        // Test verification method generation with config
        let signer = PlcSigner::from_hex(&config.authentication.repo_signing_key).unwrap();
        let multibase = generate_multibase_key(&signer).unwrap();

        // Verify multibase format
        assert!(multibase.starts_with('z'));

        // Create verification method manually
        let vm = VerificationMethod {
            id: format!("{}#atproto", did),
            key_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(multibase),
        };

        // Create service
        let service = Service {
            id: format!("{}#atproto_pds", did),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: "http://localhost:2583".to_string(),
        };

        // Create DID document
        let doc = DidDocument {
            context: Some(serde_json::json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ])),
            id: did.to_string(),
            also_known_as: vec![],
            service: vec![service],
            verification_method: vec![vm],
        };

        // Verify DID document structure
        assert_eq!(doc.id, did);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].service_type, "AtprotoPersonalDataServer");
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].key_type, "Multikey");

        // Test serialization
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("\"@context\""));
        assert!(json.contains("did:web:localhost"));
        assert!(json.contains("AtprotoPersonalDataServer"));
        assert!(json.contains("Multikey"));
    }

    // ---------- Arc 12 §5.3.10 oauth-protected-resource ----------

    /// Shape verifier — read the response body bytes and assert the
    /// JSON skeleton + the mode-dependent `authorization_servers`
    /// list value. Each call gets its own tempdir so DB / actor-store
    /// state doesn't leak across cases.
    async fn run_oauth_protected_resource(
        mut config: ServerConfig,
        expected_auth_server: &str,
    ) {
        let dir = tempfile::tempdir().unwrap().keep();
        config.storage.data_directory = dir.clone();
        config.storage.account_db = dir.join("account.sqlite");
        config.storage.sequencer_db = dir.join("sequencer.sqlite");
        config.storage.did_cache_db = dir.join("did_cache.sqlite");
        config.storage.actor_store_directory = dir.join("actors");
        config.storage.blobstore = BlobstoreConfig::Disk {
            location: dir.join("blobs"),
            tmp_location: dir.join("temp"),
        };

        let ctx = AppContext::new(
            config,
            std::sync::Arc::new(crate::api::registry::RouteRegistry::default()),
        )
        .await
        .expect("AppContext::new");

        let response = oauth_protected_resource(axum::extract::State(ctx)).await.expect("ok");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["resource"].is_string());
        assert_eq!(json["authorization_servers"][0], expected_auth_server);
        assert_eq!(json["scopes_supported"][0], "atproto");
        assert_eq!(json["scopes_supported"][1], "transition:generic");
    }

    #[tokio::test]
    async fn oauth_protected_resource_standalone_mode_advertises_self() {
        let config = create_test_config();
        // In standalone mode, authorization_servers = [service_url].
        let expected = "http://localhost:2583";
        run_oauth_protected_resource(config, expected).await;
    }

    #[tokio::test]
    async fn oauth_protected_resource_entryway_mode_advertises_entryway_url() {
        let mut config = create_test_config();
        // Manually wire an EntrywayConfig to assert the multi-mode
        // switch. The k256 pubkey is a deterministic SEC1-compressed
        // 33-byte stub derived from a fixed private key so the test
        // is self-contained.
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32])
            .expect("k256 from_slice");
        let verifying_key = *signing_key.verifying_key();
        config.entryway = Some(EntrywayConfig {
            url: "https://entryway.test".to_string(),
            admin_token: "test-admin-token".to_string(),
            jwt_public_key: verifying_key,
            did: "did:web:entryway.test".to_string(),
        });
        run_oauth_protected_resource(config, "https://entryway.test").await;
    }

    // ── /.well-known/atproto-did: Host-aware handle verification (#454) ──

    const SERVICE_HOST: &str = "locus.nearhorizon.app";
    const SERVICE_DID: &str = "did:web:locus.nearhorizon.app";

    async fn handle_ctx() -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(|c| {
            c.service.hostname = SERVICE_HOST.to_string();
            c.service.service_did = SERVICE_DID.to_string();
            c.identity.service_handle_domains = vec![".nearhorizon.app".to_string()];
        })
        .await
    }

    async fn seed_actor(ctx: &AppContext, did: &str, handle: &str) {
        sqlx::query("INSERT INTO actor (did, handle, created_at) VALUES ($1, $2, $3)")
            .bind(did)
            .bind(handle)
            .bind("2026-01-01T00:00:00Z")
            .execute(&ctx.account_db)
            .await
            .unwrap();
    }

    async fn get_atproto_did(ctx: &AppContext, host: Option<&str>) -> (StatusCode, String) {
        let mut headers = HeaderMap::new();
        if let Some(h) = host {
            headers.insert(header::HOST, h.parse().unwrap());
        }
        let resp = atproto_did(
            State(ctx.clone()),
            headers,
            Uri::from_static("/.well-known/atproto-did"),
        )
        .await
        .unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(content_type, "text/plain");
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn atproto_did_service_host_returns_service_did() {
        let ctx = handle_ctx().await;
        let got = get_atproto_did(&ctx, Some(SERVICE_HOST)).await;
        assert_eq!(got, (StatusCode::OK, SERVICE_DID.to_string()));
        let got = get_atproto_did(&ctx, Some("Locus.NearHorizon.app:2583")).await;
        assert_eq!(got, (StatusCode::OK, SERVICE_DID.to_string()));
    }

    #[tokio::test]
    async fn atproto_did_public_url_host_returns_service_did() {
        // Build with a coherent config (WebAuthn RP setup rejects a hostname
        // that disagrees with the public URL), then swap in the split one.
        let mut ctx = handle_ctx().await;
        let mut config = (*ctx.config).clone();
        config.service.hostname = "internal-name".to_string();
        config.service.public_url = Some("https://pds.example.com/".to_string());
        config.service.service_did = "did:web:pds.example.com".to_string();
        ctx.config = std::sync::Arc::new(config);
        let got = get_atproto_did(&ctx, Some("pds.example.com")).await;
        assert_eq!(got, (StatusCode::OK, "did:web:pds.example.com".to_string()));
    }

    #[tokio::test]
    async fn atproto_did_local_handle_host_returns_account_did() {
        let ctx = handle_ctx().await;
        seed_actor(
            &ctx,
            "did:plc:testaccount0000000000000",
            "sky.nearhorizon.app",
        )
        .await;
        let got = get_atproto_did(&ctx, Some("sky.nearhorizon.app")).await;
        assert_eq!(
            got,
            (
                StatusCode::OK,
                "did:plc:testaccount0000000000000".to_string()
            )
        );
    }

    #[tokio::test]
    async fn atproto_did_normalises_port_case_and_root_dot() {
        let ctx = handle_ctx().await;
        seed_actor(&ctx, "did:plc:alice", "alice.nearhorizon.app").await;
        for host in [
            "ALICE.NearHorizon.App:2583",
            "alice.nearhorizon.app.",
            "alice.nearhorizon.app.:443",
        ] {
            let got = get_atproto_did(&ctx, Some(host)).await;
            assert_eq!(got, (StatusCode::OK, "did:plc:alice".to_string()), "{host}");
        }
    }

    #[tokio::test]
    async fn atproto_did_unknown_handle_under_domain_is_404() {
        let ctx = handle_ctx().await;
        let got = get_atproto_did(&ctx, Some("nobody.nearhorizon.app")).await;
        assert_eq!(got, (StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    #[tokio::test]
    async fn atproto_did_taken_down_or_deactivated_account_is_404() {
        let ctx = handle_ctx().await;
        seed_actor(&ctx, "did:plc:gone", "gone.nearhorizon.app").await;
        seed_actor(&ctx, "did:plc:asleep", "asleep.nearhorizon.app").await;
        sqlx::query("UPDATE actor SET takedown_ref = $1 WHERE did = $2")
            .bind("mod-action-1")
            .bind("did:plc:gone")
            .execute(&ctx.account_db)
            .await
            .unwrap();
        sqlx::query("UPDATE actor SET deactivated_at = $1 WHERE did = $2")
            .bind("2026-02-01T00:00:00Z")
            .bind("did:plc:asleep")
            .execute(&ctx.account_db)
            .await
            .unwrap();
        for host in ["gone.nearhorizon.app", "asleep.nearhorizon.app"] {
            let got = get_atproto_did(&ctx, Some(host)).await;
            assert_eq!(
                got,
                (StatusCode::NOT_FOUND, "User not found".to_string()),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn atproto_did_unrelated_or_lookalike_host_is_404() {
        let ctx = handle_ctx().await;
        // A local actor whose handle is outside the service domains must not be
        // vouched for, even though the row exists.
        seed_actor(&ctx, "did:plc:outside", "alice.other.example").await;
        for host in [
            "alice.other.example",
            "nearhorizon.app",
            "evil-nearhorizon.app",
            "sky.nearhorizon.app.evil.com",
        ] {
            let got = get_atproto_did(&ctx, Some(host)).await;
            assert_eq!(
                got,
                (StatusCode::NOT_FOUND, "User not found".to_string()),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn atproto_did_missing_host_is_404() {
        let ctx = handle_ctx().await;
        let got = get_atproto_did(&ctx, None).await;
        assert_eq!(got, (StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    #[tokio::test]
    async fn atproto_did_uses_uri_authority_when_host_absent() {
        let ctx = handle_ctx().await;
        let resp = atproto_did(
            State(ctx.clone()),
            HeaderMap::new(),
            Uri::from_static("https://locus.nearhorizon.app/.well-known/atproto-did"),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn normalize_host_shapes() {
        assert_eq!(
            normalize_host("Example.COM:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_host(" example.com. ").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_host("[::1]:2583").as_deref(), Some("::1"));
        assert_eq!(normalize_host("").as_deref(), None);
        assert_eq!(normalize_host(":443").as_deref(), None);
    }
}
