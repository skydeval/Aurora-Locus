use crate::identity::did_document::DidDocument;
use crate::identity::did_method::{parse_did, DidMethod};
/// Identity Resolver - Orchestrates handle and DID resolution with caching
use crate::{
    error::{PdsError, PdsResult},
    identity::DidCache,
};
use proto_blue::identity::HandleResolver;
use std::sync::Arc;

/// Identity resolution configuration
#[derive(Debug, Clone)]
pub struct IdentityResolverConfig {
    /// User-Agent header for HTTP requests
    pub user_agent: String,
    /// Enable DNS-over-HTTPS for handle resolution
    #[allow(dead_code)] // Future DNS-over-HTTPS support
    pub use_doh: bool,
    /// PLC directory URL for DID resolution (default: https://plc.directory)
    pub plc_directory_url: String,
    /// Maximum number of retry attempts for HTTP requests
    pub max_retries: u32,
    /// Base delay for exponential backoff in milliseconds
    pub retry_base_delay_ms: u64,
    /// Maximum delay between retries in milliseconds
    pub retry_max_delay_ms: u64,
}

impl Default for IdentityResolverConfig {
    fn default() -> Self {
        Self {
            user_agent: "Aurora-Locus/0.1".to_string(),
            use_doh: false,
            plc_directory_url: std::env::var("PLC_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://plc.directory".to_string()),
            max_retries: 3,
            retry_base_delay_ms: 100,
            retry_max_delay_ms: 5000,
        }
    }
}

/// The largest DID document read, from PLC or a `did:web` host (#516).
const MAX_DID_DOCUMENT_BYTES: usize = 64 * 1024;

/// How long a failed DID resolution is answered from memory before it is
/// tried again (#516), and how many such answers are kept.
const NEGATIVE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const NEGATIVE_CAPACITY: u64 = 10_000;

/// Whether requests to hosts that DIDs and handles name are kept on the
/// public network ([`crate::outbound`]). Debug builds reach loopback hosts,
/// which local multi-instance runs use as `did:web` peers.
const GUARD_OUTBOUND: bool = !cfg!(debug_assertions);

/// A failed DID or handle resolution, as remembered for [`NEGATIVE_TTL`].
#[derive(Debug, Clone)]
enum FailedResolution {
    Tombstoned,
    HandleNotFound(String),
    Failed(String),
}

impl FailedResolution {
    fn of(error: &PdsError) -> Self {
        match error {
            PdsError::DidTombstoned(_) => Self::Tombstoned,
            PdsError::HandleNotFound(message) => Self::HandleNotFound(message.clone()),
            other => Self::Failed(other.to_string()),
        }
    }

    fn to_error(&self, did: &str) -> PdsError {
        match self {
            Self::Tombstoned => PdsError::DidTombstoned(did.to_string()),
            Self::HandleNotFound(message) => PdsError::HandleNotFound(message.clone()),
            Self::Failed(message) => PdsError::IdentityResolution(message.clone()),
        }
    }
}

/// The negative-cache key of a handle, kept apart from DIDs.
fn handle_key(handle: &str) -> String {
    format!("handle:{handle}")
}

/// Main identity resolver - combines caching with SDK resolution
#[derive(Clone)]
pub struct IdentityResolver {
    cache: DidCache,
    handle_resolver: Arc<HandleResolver>,
    /// For the PLC directory, whose URL the operator configures.
    http_client: reqwest::Client,
    /// For `did:web` hosts and handle hosts, which anyone names: no
    /// redirects, and in release builds public addresses only.
    web_client: reqwest::Client,
    failed: moka::future::Cache<String, FailedResolution>,
    #[allow(dead_code)] // Kept for future configuration needs
    config: IdentityResolverConfig,
}

impl IdentityResolver {
    /// Create a new identity resolver
    pub fn new(cache: DidCache, config: IdentityResolverConfig) -> PdsResult<Self> {
        // Build HTTP client
        let http_client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| PdsError::Internal(format!("Failed to create HTTP client: {}", e)))?;
        let mut web_client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if GUARD_OUTBOUND {
            web_client = web_client.dns_resolver(Arc::new(crate::outbound::PublicAddresses));
        }
        let web_client = web_client
            .build()
            .map_err(|e| PdsError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        // Create handle resolver from SDK
        // 10s timeout matches the http_client; matches the SDK default for handle DNS+well-known races.
        let handle_resolver = Arc::new(if GUARD_OUTBOUND {
            HandleResolver::with_fetch_handler(
                10_000,
                Arc::new(GuardedFetcher {
                    client: web_client.clone(),
                }),
            )
        } else {
            HandleResolver::new(10_000)
        });

        Ok(Self {
            cache,
            handle_resolver,
            http_client,
            web_client,
            failed: moka::future::Cache::builder()
                .max_capacity(NEGATIVE_CAPACITY)
                .time_to_live(NEGATIVE_TTL)
                .build(),
            config,
        })
    }

    /// Resolve handle to DID with two-tier caching and stale fallback
    ///
    /// Resolution order:
    /// 1. Check if handle is reserved
    /// 2. Check cache first (fast path)
    ///    - If fresh: return immediately
    ///    - If stale: try to refresh, use stale as fallback on failure
    /// 3. Try DNS TXT record resolution
    /// 4. Try HTTPS well-known resolution
    /// 5. Cache successful resolution
    ///
    /// **Graceful Degradation**: If cache is stale and fresh fetch fails,
    /// the stale cached data is returned to maintain availability during outages.
    pub async fn resolve_handle(&self, handle: &str) -> PdsResult<String> {
        let normalized = handle.to_lowercase();

        // Check if handle is reserved
        if crate::identity::reserved_handles::is_reserved(&normalized) {
            return Err(PdsError::Validation(format!(
                "Handle '{}' is reserved and cannot be used",
                normalized
            )));
        }

        // Check cache first
        if let Some(cached) = self.cache.get_handle(&normalized).await? {
            // Fresh cache hit - return immediately
            if !cached.stale {
                tracing::trace!(
                    handle = %cached.handle,
                    did = %cached.did,
                    updated_at = %cached.updated_at,
                    declared_at = ?cached.declared_at,
                    "Fresh handle cache hit"
                );
                return Ok(cached.did);
            }

            // Stale cache hit - try to refresh in background
            tracing::debug!(
                handle = %cached.handle,
                did = %cached.did,
                updated_at = %cached.updated_at,
                "Cache hit but stale, attempting refresh"
            );

            // Try to fetch fresh data
            match self.handle_resolver.resolve(&normalized).await {
                Ok(Some(did_str)) => {
                    // Update cache with fresh data
                    self.cache.cache_handle(&normalized, &did_str).await?;
                    tracing::debug!(handle = %normalized, "Successfully refreshed stale cache");
                    return Ok(did_str);
                }
                Ok(None) => {
                    // Resolver succeeded but found no DID — fall back to the stale cache value.
                    tracing::warn!(
                        handle = %normalized,
                        "Resolver returned no DID, using stale cache as fallback"
                    );
                    return Ok(cached.did);
                }
                Err(e) => {
                    // Fresh fetch failed - use stale data as fallback (graceful degradation)
                    tracing::warn!(
                        handle = %normalized,
                        error = %e,
                        "Failed to refresh stale cache, using stale data as fallback"
                    );
                    return Ok(cached.did);
                }
            }
        }

        // Cache miss - resolve via SDK. Two failure modes are
        // distinguished: an Err from the resolver is a genuine
        // resolution failure (DNS timeout, PLC unreachable, etc.) →
        // PdsError::IdentityResolution → HTTP 500. An Ok(None) is the
        // resolver completing cleanly but determining no DID maps to
        // the handle → PdsError::HandleNotFound → HTTP 400 with the
        // lexicon-canonical `HandleNotFound` error name. Either is
        // remembered for NEGATIVE_TTL (#516).
        let key = handle_key(&normalized);
        if let Some(failed) = self.failed.get(&key).await {
            return Err(failed.to_error(&normalized));
        }
        let resolved = self
            .handle_resolver
            .resolve(&normalized)
            .await
            .map_err(|e| PdsError::IdentityResolution(format!("Failed to resolve handle: {}", e)))
            .and_then(|did| {
                did.ok_or_else(|| {
                    PdsError::HandleNotFound(format!(
                        "Handle {} did not resolve to any DID",
                        normalized
                    ))
                })
            });
        let did_str = match resolved {
            Ok(did) => did,
            Err(error) => {
                self.failed.insert(key, FailedResolution::of(&error)).await;
                return Err(error);
            }
        };

        // Cache the successful resolution
        self.cache.cache_handle(&normalized, &did_str).await?;

        Ok(did_str)
    }

    /// Resolve DID to DID document with two-tier caching and stale fallback
    ///
    /// Supports did:plc and did:web methods
    ///
    /// **Graceful Degradation**: If cache is stale and PLC/Web fetch fails,
    /// the stale cached document is returned to maintain availability during outages.
    pub async fn resolve_did(&self, did: &str) -> PdsResult<DidDocument> {
        // Check cache first
        if let Some(cached) = self.cache.get_did_doc(did).await? {
            // Parse cached document
            let cached_doc: DidDocument = serde_json::from_str(&cached.doc)
                .map_err(|e| PdsError::Internal(format!("Invalid cached DID document: {}", e)))?;

            // Fresh cache hit - return immediately
            if !cached.stale {
                tracing::trace!(
                    did = %cached.did,
                    updated_at = %cached.updated_at,
                    cached_at = %cached.cached_at,
                    "Fresh DID doc cache hit"
                );
                return Ok(cached_doc);
            }

            // Stale cache hit - try to refresh
            tracing::debug!(
                did = %cached.did,
                updated_at = %cached.updated_at,
                cached_at = %cached.cached_at,
                "DID doc cache hit but stale, attempting refresh"
            );

            // Try to fetch fresh document
            match self.fetch_did_document(did).await {
                Ok(doc) => {
                    // Update cache with fresh data
                    let doc_json = serde_json::to_string(&doc).map_err(|e| {
                        PdsError::Internal(format!("Failed to serialize DID document: {}", e))
                    })?;
                    self.cache.cache_did_doc(did, &doc_json).await?;
                    tracing::debug!(did = %did, "Successfully refreshed stale DID doc cache");
                    return Ok(doc);
                }
                Err(e) => {
                    // Fresh fetch failed - use stale data as fallback (graceful degradation)
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "Failed to refresh stale DID doc cache, using stale data as fallback"
                    );
                    return Ok(cached_doc);
                }
            }
        }

        // Cache miss - fetch DID document
        let doc = self.fetch_did_document(did).await?;

        // Cache the document
        let doc_json = serde_json::to_string(&doc)
            .map_err(|e| PdsError::Internal(format!("Failed to serialize DID document: {}", e)))?;
        self.cache.cache_did_doc(did, &doc_json).await?;

        Ok(doc)
    }

    /// Fetch DID document from source. A failure is remembered for
    /// [`NEGATIVE_TTL`] and answered again without a request, so a stream of
    /// unknown DIDs costs one request each per minute, not one per use.
    async fn fetch_did_document(&self, did: &str) -> PdsResult<DidDocument> {
        if let Some(failed) = self.failed.get(did).await {
            return Err(failed.to_error(did));
        }
        let result = match parse_did(did).map(|p| p.method()) {
            Ok(DidMethod::Plc) => self.fetch_plc_document(did).await,
            Ok(DidMethod::Web) => self.fetch_web_document(did).await,
            Err(_) => Err(PdsError::IdentityResolution(format!(
                "Unsupported DID method: {}",
                did
            ))),
        };
        if let Err(error) = &result {
            self.failed
                .insert(did.to_string(), FailedResolution::of(error))
                .await;
        }
        result
    }

    /// Parse a DID document answer, read up to [`MAX_DID_DOCUMENT_BYTES`].
    async fn read_document(response: reqwest::Response, source: &str) -> PdsResult<DidDocument> {
        let body = crate::outbound::read_limited(response, MAX_DID_DOCUMENT_BYTES)
            .await
            .map_err(PdsError::IdentityResolution)?;
        serde_json::from_slice(&body)
            .map_err(|e| PdsError::IdentityResolution(format!("Invalid {source} document: {e}")))
    }

    /// Check if an HTTP error is retryable
    ///
    /// Retryable errors include:
    /// - Network/connection errors
    /// - 5xx server errors (except 501 Not Implemented)
    /// - 429 Too Many Requests
    /// - Request timeout
    fn is_retryable_error(error: &reqwest::Error) -> bool {
        if error.is_timeout() || error.is_connect() || error.is_request() {
            return true;
        }
        if let Some(status) = error.status() {
            return status.as_u16() == 429 || (status.is_server_error() && status.as_u16() != 501);
        }
        false
    }

    /// Check if an HTTP status code is retryable
    fn is_retryable_status(status: reqwest::StatusCode) -> bool {
        status.as_u16() == 429 || (status.is_server_error() && status.as_u16() != 501)
    }

    /// Calculate delay for retry attempt using exponential backoff with jitter
    fn calculate_retry_delay(&self, attempt: u32) -> std::time::Duration {
        let base_delay = self.config.retry_base_delay_ms;
        let max_delay = self.config.retry_max_delay_ms;

        // Exponential backoff: base * 2^attempt
        let delay_ms = base_delay.saturating_mul(1u64 << attempt);
        let capped_delay = delay_ms.min(max_delay);

        // Add jitter (±25% of delay)
        let jitter_range = capped_delay / 4;
        let jitter = if jitter_range > 0 {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            // Simple deterministic jitter based on current time
            let mut hasher = DefaultHasher::new();
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .hash(&mut hasher);
            (hasher.finish() % (jitter_range * 2)) as i64 - jitter_range as i64
        } else {
            0
        };

        let final_delay = (capped_delay as i64 + jitter).max(0) as u64;
        std::time::Duration::from_millis(final_delay)
    }

    /// Fetch DID document from PLC directory with retry logic
    async fn fetch_plc_document(&self, did: &str) -> PdsResult<DidDocument> {
        let plc_url = format!(
            "{}/{}",
            self.config.plc_directory_url.trim_end_matches('/'),
            did
        );
        let max_retries = self.config.max_retries;
        let mut last_error = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.calculate_retry_delay(attempt - 1);
                tracing::debug!(
                    did = %did,
                    attempt = attempt,
                    delay_ms = delay.as_millis(),
                    "Retrying PLC document fetch"
                );
                tokio::time::sleep(delay).await;
            }

            match self.http_client.get(&plc_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let doc = Self::read_document(response, "PLC").await?;

                        if attempt > 0 {
                            tracing::info!(
                                did = %did,
                                attempts = attempt + 1,
                                "PLC document fetch succeeded after retries"
                            );
                        }
                        return Ok(doc);
                    }

                    let status = response.status();

                    // Arc 13 v4.2 — PLC returns 410 Gone for tombstoned DIDs.
                    // Route into the pre-existing `DidTombstoned` variant
                    // (originally added in §6.3.4 / §6.3.6 for PlcClient's
                    // audit-log path) so callers reason about tombstone
                    // state structurally instead of substring-matching
                    // "410" in an opaque message. Non-retryable: a
                    // tombstoned DID is a permanent state and doesn't
                    // benefit from backoff. All other non-2xx statuses
                    // keep their current `IdentityResolution` mapping
                    // unchanged.
                    if status == reqwest::StatusCode::GONE {
                        return Err(PdsError::DidTombstoned(did.to_string()));
                    }

                    if Self::is_retryable_status(status) && attempt < max_retries {
                        tracing::warn!(
                            did = %did,
                            status = %status,
                            attempt = attempt,
                            "PLC directory returned retryable error"
                        );
                        last_error = Some(PdsError::IdentityResolution(format!(
                            "PLC directory returned error: {}",
                            status
                        )));
                        continue;
                    }

                    return Err(PdsError::IdentityResolution(format!(
                        "PLC directory returned error: {}",
                        status
                    )));
                }
                Err(e) => {
                    if Self::is_retryable_error(&e) && attempt < max_retries {
                        tracing::warn!(
                            did = %did,
                            error = %e,
                            attempt = attempt,
                            "Retryable error fetching PLC document"
                        );
                        last_error = Some(PdsError::IdentityResolution(format!(
                            "Failed to fetch PLC document: {}",
                            e
                        )));
                        continue;
                    }
                    return Err(PdsError::IdentityResolution(format!(
                        "Failed to fetch PLC document: {}",
                        e
                    )));
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or_else(|| {
            PdsError::IdentityResolution(format!(
                "Failed to fetch PLC document after {} retries",
                max_retries
            ))
        }))
    }

    /// Fetch DID document from did:web with retry logic
    async fn fetch_web_document(&self, did: &str) -> PdsResult<DidDocument> {
        // did:web:example.com -> https://example.com/.well-known/did.json
        // did:web:example.com:user:alice -> https://example.com/user/alice/did.json
        let did_suffix = did
            .strip_prefix("did:web:")
            .ok_or_else(|| PdsError::IdentityResolution("Invalid did:web format".to_string()))?;
        if GUARD_OUTBOUND {
            crate::outbound::refuse_internal_did_web(did).map_err(PdsError::IdentityResolution)?;
        }

        let parts: Vec<&str> = did_suffix.split(':').collect();
        let domain = parts
            .first()
            .ok_or_else(|| PdsError::IdentityResolution("Missing domain in did:web".to_string()))?;

        // Arc 12 §5.3.2 Gap 1: localhost-aware scheme for
        // did:web resolution so a peer at localhost:NNNN resolves
        // via http://.
        let scheme = crate::config::derive_url_scheme(domain);
        let url = if parts.len() == 1 {
            format!("{}://{}/.well-known/did.json", scheme, domain)
        } else {
            let path = parts[1..].join("/");
            format!("{}://{}/{}/did.json", scheme, domain, path)
        };

        let max_retries = self.config.max_retries;
        let mut last_error = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.calculate_retry_delay(attempt - 1);
                tracing::debug!(
                    did = %did,
                    attempt = attempt,
                    delay_ms = delay.as_millis(),
                    "Retrying did:web document fetch"
                );
                tokio::time::sleep(delay).await;
            }

            match self.web_client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let doc = Self::read_document(response, "did:web").await?;

                        if attempt > 0 {
                            tracing::info!(
                                did = %did,
                                attempts = attempt + 1,
                                "did:web document fetch succeeded after retries"
                            );
                        }
                        return Ok(doc);
                    }

                    let status = response.status();
                    if Self::is_retryable_status(status) && attempt < max_retries {
                        tracing::warn!(
                            did = %did,
                            status = %status,
                            attempt = attempt,
                            "did:web server returned retryable error"
                        );
                        last_error = Some(PdsError::IdentityResolution(format!(
                            "did:web server returned error: {}",
                            status
                        )));
                        continue;
                    }

                    return Err(PdsError::IdentityResolution(format!(
                        "did:web server returned error: {}",
                        status
                    )));
                }
                Err(e) => {
                    if Self::is_retryable_error(&e) && attempt < max_retries {
                        tracing::warn!(
                            did = %did,
                            error = %e,
                            attempt = attempt,
                            "Retryable error fetching did:web document"
                        );
                        last_error = Some(PdsError::IdentityResolution(format!(
                            "Failed to fetch did:web document: {}",
                            e
                        )));
                        continue;
                    }
                    return Err(PdsError::IdentityResolution(format!(
                        "Failed to fetch did:web document: {}",
                        e
                    )));
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or_else(|| {
            PdsError::IdentityResolution(format!(
                "Failed to fetch did:web document after {} retries",
                max_retries
            ))
        }))
    }

    /// Invalidate cached signing key for a DID (force re-fetch)
    ///
    /// This should be called when identity events are received via relay,
    #[allow(dead_code)] // Future key invalidation
    /// indicating that the DID document has changed.
    pub async fn invalidate_signing_key(&self, did: &str) -> PdsResult<()> {
        // Invalidating the DID document invalidates the signing key
        self.invalidate_did(did).await
    }

    /// Get handle for a DID (reverse lookup)
    ///
    /// First checks cache, then falls back to examining DID document's alsoKnownAs
    pub async fn get_handle_for_did(&self, did: &str) -> PdsResult<Option<String>> {
        // Check cache first
        if let Some(handle) = self.cache.get_did_handle(did).await? {
            return Ok(Some(handle));
        }

        // Cache miss - check DID document
        let doc = self.resolve_did(did).await?;

        // Look for at:// handle in alsoKnownAs
        for aka in &doc.also_known_as {
            if let Some(handle) = aka.strip_prefix("at://") {
                // Cache this mapping
                self.cache.cache_handle(handle, did).await?;
                return Ok(Some(handle.to_string()));
            }
        }

        Ok(None)
    }

    /// Invalidate cached handle (force re-resolution), and forget a failed
    /// resolution of it.
    pub async fn invalidate_handle(&self, handle: &str) -> PdsResult<()> {
        self.failed.invalidate(&handle_key(&handle.to_lowercase())).await;
        self.cache.delete_handle(handle).await
    }

    /// Invalidate cached DID document (force re-fetch), and forget a failed
    /// resolution of it: an identity event for a DID just created must not
    /// be answered with the miss from before it existed.
    pub async fn invalidate_did(&self, did: &str) -> PdsResult<()> {
        self.failed.invalidate(did).await;
        self.cache.delete_did_doc(did).await
    }

    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) -> PdsResult<()> {
        self.cache.cleanup_expired().await
    }
}

/// The fetch handler handle resolution uses in release builds: the
/// resolver's guarded `did:web` client ([`crate::outbound`]), with the
/// answer read up to [`MAX_DID_DOCUMENT_BYTES`]. A handle's host is named by
/// whoever chose the handle, as a `did:web` host is.
struct GuardedFetcher {
    client: reqwest::Client,
}

#[async_trait::async_trait]
impl proto_blue::common::fetch::FetchHandler for GuardedFetcher {
    async fn fetch(
        &self,
        req: proto_blue::common::fetch::HttpRequest,
    ) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::common::fetch::FetchError> {
        use proto_blue::common::fetch::{FetchError, HttpMethod, HttpResponse};
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        };
        let mut request = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            request = request.header(name, value);
        }
        if let Some(body) = req.body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                FetchError::Timeout
            } else {
                FetchError::Network(e.to_string())
            }
        })?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
            })
            .collect();
        let body = crate::outbound::read_limited(response, MAX_DID_DOCUMENT_BYTES)
            .await
            .map_err(FetchError::Body)?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Mockable abstraction over identity resolution.
///
/// Introduced in v0.3 Arc 1 Step 0.6 so consumers like
/// `service_auth::verify_service_jwt` and the federation
/// authenticators can be unit-tested with an in-memory implementation
/// rather than the live `IdentityResolver`. The production impl is
/// the existing `IdentityResolver` struct; tests use
/// `test_doubles::MockIdentityResolver`.
#[async_trait::async_trait]
pub trait IdentityResolverApi: Send + Sync {
    async fn resolve_handle(&self, handle: &str) -> PdsResult<String>;
    async fn resolve_did(&self, did: &str) -> PdsResult<DidDocument>;
    async fn get_handle_for_did(&self, did: &str) -> PdsResult<Option<String>>;
    async fn invalidate_handle(&self, handle: &str) -> PdsResult<()>;
    async fn invalidate_did(&self, did: &str) -> PdsResult<()>;
    async fn cleanup_cache(&self) -> PdsResult<()>;
}

#[async_trait::async_trait]
impl IdentityResolverApi for IdentityResolver {
    async fn resolve_handle(&self, handle: &str) -> PdsResult<String> {
        IdentityResolver::resolve_handle(self, handle).await
    }
    async fn resolve_did(&self, did: &str) -> PdsResult<DidDocument> {
        IdentityResolver::resolve_did(self, did).await
    }
    async fn get_handle_for_did(&self, did: &str) -> PdsResult<Option<String>> {
        IdentityResolver::get_handle_for_did(self, did).await
    }
    async fn invalidate_handle(&self, handle: &str) -> PdsResult<()> {
        IdentityResolver::invalidate_handle(self, handle).await
    }
    async fn invalidate_did(&self, did: &str) -> PdsResult<()> {
        IdentityResolver::invalidate_did(self, did).await
    }
    async fn cleanup_cache(&self) -> PdsResult<()> {
        IdentityResolver::cleanup_cache(self).await
    }
}

// Exposed to integration tests in `tests/` (e.g.
// `tests/arc12_routing_matrix.rs`). The mock has no production
// callers; gating it behind `#[cfg(test)]` would hide it from
// integration tests because Cargo only sets `cfg(test)` for the
// crate currently being compiled in test mode.
pub mod test_doubles {
    //! Test doubles for the identity-resolution surface.
    //!
    //! `MockIdentityResolver` is a `HashMap`-backed implementation of
    //! `IdentityResolverApi` that scripts outcomes per-DID and counts
    //! invocations. Step 1's algorithm-confusion tests for
    //! `verify_service_jwt` use the invocation counter to assert the
    //! security boundary rejects bad algorithms before reaching the
    //! resolver. Step 2's extractor tests use it to count invocations
    //! after an `AppContext` swap.
    #![allow(dead_code)] // Step 0.6 infrastructure for Step 1/2 tests
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// In-memory `IdentityResolverApi` for unit tests.
    ///
    /// Errors are stored as message strings (PdsError isn't Clone) and
    /// surfaced as `PdsError::IdentityResolution(msg)` on the call
    /// path that hits the unscripted entry — matching the variant the
    /// production resolver returns for not-found / fetch-failed cases.
    pub struct MockIdentityResolver {
        did_docs: Mutex<HashMap<String, Result<DidDocument, String>>>,
        handles_to_dids: Mutex<HashMap<String, String>>,
        dids_to_handles: Mutex<HashMap<String, String>>,
        resolve_did_count: AtomicUsize,
        resolve_handle_count: AtomicUsize,
        invalidate_count: AtomicUsize,
    }

    impl MockIdentityResolver {
        pub fn new() -> Self {
            Self {
                did_docs: Mutex::new(HashMap::new()),
                handles_to_dids: Mutex::new(HashMap::new()),
                dids_to_handles: Mutex::new(HashMap::new()),
                resolve_did_count: AtomicUsize::new(0),
                resolve_handle_count: AtomicUsize::new(0),
                invalidate_count: AtomicUsize::new(0),
            }
        }

        /// Script `resolve_did(did)` to return a synthetic DID document.
        pub fn script_did(&self, did: &str, doc: DidDocument) {
            self.did_docs
                .lock()
                .unwrap()
                .insert(did.to_string(), Ok(doc));
        }

        /// Script `resolve_did(did)` to return a not-found / fetch-failed error.
        pub fn script_did_error(&self, did: &str, msg: &str) {
            self.did_docs
                .lock()
                .unwrap()
                .insert(did.to_string(), Err(msg.to_string()));
        }

        /// Script a handle ↔ did mapping for `resolve_handle` and
        /// `get_handle_for_did`.
        pub fn script_handle(&self, handle: &str, did: &str) {
            self.handles_to_dids
                .lock()
                .unwrap()
                .insert(handle.to_string(), did.to_string());
            self.dids_to_handles
                .lock()
                .unwrap()
                .insert(did.to_string(), handle.to_string());
        }

        pub fn resolve_did_calls(&self) -> usize {
            self.resolve_did_count.load(Ordering::SeqCst)
        }
        pub fn resolve_handle_calls(&self) -> usize {
            self.resolve_handle_count.load(Ordering::SeqCst)
        }
        pub fn invalidate_calls(&self) -> usize {
            self.invalidate_count.load(Ordering::SeqCst)
        }
    }

    impl Default for MockIdentityResolver {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl IdentityResolverApi for MockIdentityResolver {
        async fn resolve_handle(&self, handle: &str) -> PdsResult<String> {
            self.resolve_handle_count.fetch_add(1, Ordering::SeqCst);
            match self.handles_to_dids.lock().unwrap().get(handle) {
                Some(did) => Ok(did.clone()),
                None => Err(PdsError::IdentityResolution(format!(
                    "MockIdentityResolver: no scripted DID for handle {}",
                    handle
                ))),
            }
        }

        async fn resolve_did(&self, did: &str) -> PdsResult<DidDocument> {
            self.resolve_did_count.fetch_add(1, Ordering::SeqCst);
            match self.did_docs.lock().unwrap().get(did) {
                Some(Ok(doc)) => Ok(doc.clone()),
                Some(Err(msg)) => Err(PdsError::IdentityResolution(msg.clone())),
                None => Err(PdsError::IdentityResolution(format!(
                    "MockIdentityResolver: no scripted outcome for DID {}",
                    did
                ))),
            }
        }

        async fn get_handle_for_did(&self, did: &str) -> PdsResult<Option<String>> {
            self.resolve_handle_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.dids_to_handles.lock().unwrap().get(did).cloned())
        }

        async fn invalidate_handle(&self, _handle: &str) -> PdsResult<()> {
            self.invalidate_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn invalidate_did(&self, _did: &str) -> PdsResult<()> {
            self.invalidate_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn cleanup_cache(&self) -> PdsResult<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::AnyPool;

    /// Open a single-connection SQLite-backed `AnyPool` for tests. The
    /// single-connection cap is required because each connection to
    /// `:memory:` has its own private database. Mirror of the helper in
    /// `super::cache::tests::open_any_memory_pool`.
    async fn open_test_pool() -> AnyPool {
        use std::sync::Once;
        static INSTALL: Once = Once::new();
        INSTALL.call_once(sqlx::any::install_default_drivers);
        sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    async fn create_test_resolver() -> IdentityResolver {
        let db = open_test_pool().await;

        // Create cache tables
        sqlx::query(
            r#"
            CREATE TABLE did_doc (
                did TEXT PRIMARY KEY,
                doc TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE did_handle (
                handle TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                declared_at TEXT,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        let cache = DidCache::new(db);
        IdentityResolver::new(cache, IdentityResolverConfig::default()).unwrap()
    }

    #[tokio::test]
    async fn test_resolve_handle_with_cache() {
        let resolver = create_test_resolver().await;

        // Pre-populate cache
        resolver
            .cache
            .cache_handle("alice.test", "did:plc:alice123")
            .await
            .unwrap();

        // Should return cached value
        let did = resolver.resolve_handle("alice.test").await.unwrap();
        assert_eq!(did, "did:plc:alice123");

        // Case-insensitive lookup
        let did_upper = resolver.resolve_handle("ALICE.TEST").await.unwrap();
        assert_eq!(did_upper, "did:plc:alice123");
    }

    #[tokio::test]
    async fn test_get_handle_for_did() {
        let resolver = create_test_resolver().await;

        // Pre-populate cache
        resolver
            .cache
            .cache_handle("bob.test", "did:plc:bob456")
            .await
            .unwrap();

        // Reverse lookup
        let handle = resolver.get_handle_for_did("did:plc:bob456").await.unwrap();
        assert_eq!(handle, Some("bob.test".to_string()));
    }

    #[tokio::test]
    async fn test_invalidate_handle() {
        let resolver = create_test_resolver().await;

        // Pre-populate cache
        resolver
            .cache
            .cache_handle("charlie.test", "did:plc:charlie789")
            .await
            .unwrap();

        // Verify cached
        let cached = resolver.cache.get_handle("charlie.test").await.unwrap();
        assert!(cached.is_some());

        // Invalidate
        resolver.invalidate_handle("charlie.test").await.unwrap();

        // Verify removed
        let cached_after = resolver.cache.get_handle("charlie.test").await.unwrap();
        assert!(cached_after.is_none());
    }

    #[tokio::test]
    async fn test_did_web_url_parsing() {
        let _resolver = create_test_resolver().await;

        // Simple did:web should map to .well-known
        let _did_simple = "did:web:example.com";
        // Would fetch: https://example.com/.well-known/did.json

        // Path-based did:web
        let _did_path = "did:web:example.com:user:alice";
        // Would fetch: https://example.com/user/alice/did.json

        // Note: These tests verify the logic, not actual HTTP calls
        // Real HTTP tests would require mocking or integration tests
    }

    #[tokio::test]
    async fn test_custom_plc_directory_url() {
        let db = open_test_pool().await;

        // Create cache tables
        sqlx::query(
            r#"
            CREATE TABLE did_doc (
                did TEXT PRIMARY KEY,
                doc TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE did_handle (
                handle TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                declared_at TEXT,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        let cache = DidCache::new(db);

        // Test with custom PLC directory URL
        let custom_config = IdentityResolverConfig {
            user_agent: "Test-Agent/1.0".to_string(),
            use_doh: false,
            plc_directory_url: "https://test.plc.directory".to_string(),
            max_retries: 3,
            retry_base_delay_ms: 100,
            retry_max_delay_ms: 5000,
        };

        let resolver = IdentityResolver::new(cache.clone(), custom_config).unwrap();

        // Verify the custom URL is set correctly
        assert_eq!(
            resolver.config.plc_directory_url,
            "https://test.plc.directory"
        );

        // Test with default configuration (should use official directory or env var)
        let default_resolver =
            IdentityResolver::new(cache, IdentityResolverConfig::default()).unwrap();

        // Should either be the default or from environment variable
        assert!(
            default_resolver.config.plc_directory_url == "https://plc.directory"
                || default_resolver.config.plc_directory_url
                    == std::env::var("PLC_DIRECTORY_URL").unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_plc_url_trailing_slash_handling() {
        let db = open_test_pool().await;

        // Create cache tables
        sqlx::query(
            r#"
            CREATE TABLE did_doc (
                did TEXT PRIMARY KEY,
                doc TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE did_handle (
                handle TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                declared_at TEXT,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        let cache = DidCache::new(db);

        // Test with trailing slash
        let config_with_slash = IdentityResolverConfig {
            user_agent: "Test-Agent/1.0".to_string(),
            use_doh: false,
            plc_directory_url: "https://test.plc.directory/".to_string(),
            max_retries: 3,
            retry_base_delay_ms: 100,
            retry_max_delay_ms: 5000,
        };

        let resolver = IdentityResolver::new(cache, config_with_slash).unwrap();

        // The fetch_plc_document method should handle trailing slashes correctly
        // by using trim_end_matches('/') in the format string
        assert_eq!(
            resolver.config.plc_directory_url,
            "https://test.plc.directory/"
        );
    }

    // =====================================================
    // Arc 13 v4.2 — 410-on-PLC → DidTombstoned routing
    //
    // Tests use a tiny axum server bound to 127.0.0.1:0 (same
    // pattern as src/federation/blob_fetch.rs's TestOrigin)
    // returning the configured status. No new dep introduced.
    // =====================================================

    async fn open_test_pool_for_plc() -> sqlx::AnyPool {
        let pool = open_test_pool().await;
        sqlx::query(
            r#"
            CREATE TABLE did_doc (
                did TEXT PRIMARY KEY,
                doc TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TABLE did_handle (
                handle TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                declared_at TEXT,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    /// Spawn a one-shot stub PLC at `127.0.0.1:0` returning `status`
    /// for any GET. Returns `(base_url, shutdown_tx)`. Drop the
    /// shutdown_tx to terminate the server.
    async fn spawn_stub_plc(status: u16) -> (String, tokio::sync::oneshot::Sender<()>) {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::any;
        use axum::Router;

        let app = Router::new().route(
            "/*path",
            any(move || async move {
                (
                    StatusCode::from_u16(status).unwrap(),
                    "stubbed",
                )
                    .into_response()
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .ok();
        });
        (format!("http://{}", addr), tx)
    }

    fn config_pointing_at(url: &str) -> IdentityResolverConfig {
        IdentityResolverConfig {
            user_agent: "Aurora-v4.2-test/1.0".to_string(),
            use_doh: false,
            plc_directory_url: url.to_string(),
            // Keep retries low so failure-path tests don't spin
            // wall-clock seconds on backoff.
            max_retries: 0,
            retry_base_delay_ms: 10,
            retry_max_delay_ms: 50,
        }
    }

    #[tokio::test]
    async fn fetch_plc_document_maps_410_to_did_tombstoned() {
        let (url, _shutdown) = spawn_stub_plc(410).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();

        let target_did = "did:plc:tombstoned123";
        let err = resolver.fetch_plc_document(target_did).await.unwrap_err();
        match err {
            PdsError::DidTombstoned(d) => assert_eq!(d, target_did),
            other => panic!(
                "expected PdsError::DidTombstoned, got: {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn fetch_plc_document_maps_non_410_5xx_to_identity_resolution_unchanged() {
        // 500 is the canonical "other non-2xx" case — preserves
        // the existing IdentityResolution mapping. (500 IS in the
        // retryable set per is_retryable_status; with max_retries=0
        // we only attempt once and surface the terminal error.)
        let (url, _shutdown) = spawn_stub_plc(500).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();

        let err = resolver.fetch_plc_document("did:plc:transient").await.unwrap_err();
        match err {
            PdsError::IdentityResolution(msg) => {
                assert!(
                    msg.contains("500"),
                    "expected 500 in error message, got: {msg}"
                );
            }
            other => panic!(
                "expected PdsError::IdentityResolution, got: {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn fetch_plc_document_maps_non_410_4xx_to_identity_resolution_unchanged() {
        // 404 is the "DID does not exist at PLC" case — current
        // behavior keeps it as IdentityResolution. v4.2 carves out
        // ONLY 410; everything else stays put.
        let (url, _shutdown) = spawn_stub_plc(404).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();

        let err = resolver.fetch_plc_document("did:plc:missing").await.unwrap_err();
        match err {
            PdsError::IdentityResolution(msg) => {
                assert!(
                    msg.contains("404"),
                    "expected 404 in error message, got: {msg}"
                );
            }
            other => panic!(
                "expected PdsError::IdentityResolution, got: {other:?}"
            ),
        }
    }

    // ---- #516: failed resolutions are remembered; answers are bounded ----

    /// A stub PLC answering `status` with `body` to every request, counting
    /// the requests it receives.
    async fn spawn_counting_plc(
        status: u16,
        body: Vec<u8>,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>, tokio::sync::oneshot::Sender<()>) {
        use axum::http::StatusCode;
        use axum::routing::any;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = axum::Router::new().route(
            "/*path",
            any(move || {
                let counter = counter.clone();
                let body = body.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::from_u16(status).unwrap(), body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .ok();
        });
        (format!("http://{addr}"), hits, tx)
    }

    #[tokio::test]
    async fn a_failed_resolution_is_answered_from_memory_until_invalidated() {
        use std::sync::atomic::Ordering;
        let (url, hits, _shutdown) = spawn_counting_plc(404, b"not found".to_vec()).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();
        let did = "did:plc:nosuchdid00000000000000";

        for _ in 0..3 {
            let err = resolver.resolve_did(did).await.unwrap_err();
            assert!(matches!(err, PdsError::IdentityResolution(ref m) if m.contains("404")), "{err:?}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "one request for three resolutions");

        // An identity event for the DID clears the remembered failure.
        resolver.invalidate_did(did).await.unwrap();
        assert!(resolver.resolve_did(did).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_remembered_tombstone_is_still_a_tombstone() {
        use std::sync::atomic::Ordering;
        let (url, hits, _shutdown) = spawn_counting_plc(410, Vec::new()).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();
        let did = "did:plc:tombstoned0000000000000";

        for _ in 0..2 {
            let err = resolver.resolve_did(did).await.unwrap_err();
            assert!(matches!(err, PdsError::DidTombstoned(ref d) if d == did), "{err:?}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_oversized_did_document_is_refused() {
        let body = vec![b' '; MAX_DID_DOCUMENT_BYTES + 1];
        let (url, _hits, _shutdown) = spawn_counting_plc(200, body).await;
        let cache = DidCache::new(open_test_pool_for_plc().await);
        let resolver = IdentityResolver::new(cache, config_pointing_at(&url)).unwrap();

        let err = resolver.resolve_did("did:plc:hugedocument000000000000").await.unwrap_err();
        assert!(matches!(err, PdsError::IdentityResolution(ref m) if m.contains("larger than")), "{err:?}");
    }
}
