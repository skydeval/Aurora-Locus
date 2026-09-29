//! Generic XRPC service proxy (#471).
//!
//! Any `/xrpc/<nsid>` this PDS does not implement locally is forwarded, as the
//! reference PDS does:
//! - with an `atproto-proxy: <did>#<service id>` header, to the endpoint of
//!   that service in the DID's document;
//! - without one, `app.bsky.*` goes to the configured AppView.
//!
//! An authenticated request carries a fresh service-auth JWT in the account's
//! name (`iss` = account DID, `aud` = target DID, `lxm` = the method, a short
//! expiry); an anonymous one is forwarded anonymously. The upstream status,
//! body and the atproto response headers come back unchanged, errors included.
//!
//! Locally implemented methods never reach this module: it is the router's
//! fallback. Account-management namespaces are never forwarded.

use crate::{
    api::middleware::AccountAuth,
    context::AppContext,
    error::{PdsError, PdsResult},
};
use axum::{
    body::{Body, Bytes},
    extract::{FromRequestParts, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::OnceLock;
use std::time::Duration;

/// The request header naming the target service.
pub const PROXY_HEADER: &str = "atproto-proxy";

/// Lifetime of the minted service-auth JWT (seconds).
const SERVICE_JWT_TTL_SECS: i64 = 60;

/// Upstream request timeout.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest request body forwarded (bytes).
const MAX_PROXY_BODY: usize = 50 * 1024 * 1024;

/// Request headers forwarded to the upstream service.
const FORWARDED_REQUEST_HEADERS: [&str; 4] = [
    "atproto-accept-labelers",
    "accept-language",
    "content-type",
    "x-bsky-topics",
];

/// Response headers passed back to the client.
const FORWARDED_RESPONSE_HEADERS: [&str; 4] = [
    "content-type",
    "atproto-content-labelers",
    "atproto-repo-rev",
    "content-language",
];

/// Namespaces never forwarded: they act on the account itself, so an
/// unimplemented one must fail here rather than hand the account's credentials
/// to another service.
const PROTECTED_NAMESPACES: [&str; 3] = [
    "com.atproto.admin.",
    "com.atproto.server.",
    "com.atproto.identity.",
];

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .user_agent(concat!("aurora-locus/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Where a proxied call goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    /// The service's DID: the `aud` of the service-auth JWT.
    pub did: String,
    /// The service's base URL.
    pub url: String,
    /// The service as `did#id`: the `aud` an OAuth rpc permission names.
    pub service: String,
}

/// The service id Bluesky AppViews publish, used for `app.bsky.*` calls
/// forwarded without an `atproto-proxy` header.
const APPVIEW_SERVICE_ID: &str = "bsky_appview";

/// Split an `atproto-proxy` value into `(did, service id)`.
fn parse_proxy_header(value: &str) -> PdsResult<(String, String)> {
    match value.split_once('#') {
        Some((did, id)) if did.starts_with("did:") && !id.is_empty() && !id.contains('#') => {
            Ok((did.to_string(), id.to_string()))
        }
        _ => Err(PdsError::Validation(format!(
            "invalid {} header: expected <did>#<service id>",
            PROXY_HEADER
        ))),
    }
}

/// The DID of an AppView reached by URL: `did:web:<host>` (port encoded as
/// `%3A`, per did:web), which is how AppViews identify themselves — Bluesky's
/// is `did:web:api.bsky.app`.
pub fn appview_did_from_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("did:web:{host}%3A{port}"),
        None => format!("did:web:{host}"),
    })
}

/// The configured AppView as `did#bsky_appview`, the service an OAuth rpc
/// permission for an `app.bsky` method names; `None` without an AppView.
pub async fn appview_service(ctx: &AppContext) -> Option<String> {
    let url = crate::api::aurora_admin::resolve_appview_url(ctx).await?;
    let did = appview_did_from_url(&url)?;
    Some(format!("{did}#{APPVIEW_SERVICE_ID}"))
}

/// Resolve where `nsid` should go, from the `atproto-proxy` header or, for
/// `app.bsky.*` without one, the configured AppView.
pub async fn resolve_target(
    ctx: &AppContext,
    headers: &HeaderMap,
    nsid: &str,
) -> PdsResult<ProxyTarget> {
    if let Some(value) = headers.get(PROXY_HEADER) {
        let value = value
            .to_str()
            .map_err(|_| PdsError::Validation(format!("invalid {} header", PROXY_HEADER)))?;
        let (did, id) = parse_proxy_header(value)?;
        let doc = ctx.identity_resolver.resolve_did(&did).await.map_err(|e| {
            PdsError::UpstreamFailure(format!("could not resolve proxy DID {did}: {e}"))
        })?;
        let (short, full) = (format!("#{id}"), format!("{did}#{id}"));
        let url = doc
            .service
            .iter()
            .find(|s| s.id == short || s.id == full)
            .map(|s| s.service_endpoint.clone())
            .ok_or_else(|| {
                PdsError::Validation(format!(
                    "service {short} not found in the DID document of {did}"
                ))
            })?;
        let service = full;
        return Ok(ProxyTarget { did, url, service });
    }

    if nsid.starts_with("app.bsky.") {
        let url = crate::api::aurora_admin::resolve_appview_url(ctx)
            .await
            .ok_or_else(|| {
                PdsError::MethodNotImplemented(
                    "no AppView is configured to serve app.bsky methods".to_string(),
                )
            })?;
        let did = appview_did_from_url(&url).ok_or_else(|| {
            PdsError::Internal(format!("configured AppView URL has no host: {url}"))
        })?;
        let service = format!("{did}#{APPVIEW_SERVICE_ID}");
        return Ok(ProxyTarget { did, url, service });
    }

    Err(PdsError::MethodNotImplemented(format!(
        "{nsid} is not implemented by this PDS"
    )))
}

/// Forward one XRPC call to `target` and return its response.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    ctx: &AppContext,
    target: &ProxyTarget,
    nsid: &str,
    method: Method,
    query: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    auth: Option<&AccountAuth>,
) -> PdsResult<Response> {
    let mut url = format!("{}/xrpc/{}", target.url.trim_end_matches('/'), nsid);
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }

    let mut req = http_client().request(method.clone(), &url);
    for name in FORWARDED_REQUEST_HEADERS {
        if let Some(v) = headers.get(name) {
            req = req.header(name, v.as_bytes());
        }
    }
    if let Some(auth) = auth {
        // An OAuth client may only act as the account where its scopes allow
        // this method on this service (#478).
        auth.require_rpc(nsid, &target.service)?;
        let token = crate::api::server::mint_account_service_jwt(
            ctx,
            &auth.did,
            &target.did,
            Some(SERVICE_JWT_TTL_SECS),
            Some(nsid),
        )
        .await?;
        req = req.bearer_auth(token);
    }
    if method != Method::GET && method != Method::HEAD {
        req = req.body(body);
    }

    let resp = req.send().await.map_err(|e| {
        if e.is_timeout() {
            PdsError::UpstreamTimeout(format!("{} did not answer in time", target.url))
        } else {
            PdsError::UpstreamFailure(format!("could not reach {}: {}", target.url, e))
        }
    })?;

    let status = resp.status();
    let mut out_headers = HeaderMap::new();
    for name in FORWARDED_RESPONSE_HEADERS {
        if let Some(v) = resp.headers().get(name) {
            if let Ok(v) = HeaderValue::from_bytes(v.as_bytes()) {
                out_headers.insert(HeaderName::from_static(name), v);
            }
        }
    }
    let bytes = resp.bytes().await.map_err(|e| {
        PdsError::UpstreamFailure(format!("reading the upstream response failed: {e}"))
    })?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    response.headers_mut().extend(out_headers);
    Ok(response)
}

/// The JSON 404 for paths no route serves.
pub fn not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "error": "NotFound",
            "message": "Endpoint not found"
        })),
    )
        .into_response()
}

/// Router fallback: forward unimplemented `/xrpc/<nsid>` calls; anything else
/// is a JSON 404.
pub async fn xrpc_fallback(State(ctx): State<AppContext>, req: Request) -> Response {
    match proxy_request(&ctx, req).await {
        Ok(Some(resp)) => resp,
        Ok(None) => not_found_response(),
        Err(e) => e.into_response(),
    }
}

/// `Ok(None)` when `req` is not an XRPC call at all.
async fn proxy_request(ctx: &AppContext, req: Request) -> PdsResult<Option<Response>> {
    let (mut parts, body) = req.into_parts();
    let Some(nsid) = parts.uri.path().strip_prefix("/xrpc/") else {
        return Ok(None);
    };
    let nsid = nsid.to_string();
    if nsid.is_empty() || nsid.contains('/') {
        return Ok(None);
    }
    if PROTECTED_NAMESPACES.iter().any(|ns| nsid.starts_with(ns)) {
        return Err(PdsError::MethodNotImplemented(format!(
            "{nsid} is not implemented by this PDS"
        )));
    }
    if parts.method != Method::GET && parts.method != Method::POST && parts.method != Method::HEAD {
        return Err(PdsError::Validation(format!(
            "XRPC methods are GET or POST, not {}",
            parts.method
        )));
    }

    // Authenticated when the client sent credentials (then they must be valid
    // account credentials); anonymous otherwise.
    let auth = if parts.headers.contains_key(header::AUTHORIZATION) {
        Some(AccountAuth::from_request_parts(&mut parts, ctx).await?)
    } else {
        None
    };
    // The reference PDS keeps chat away from non-privileged app passwords.
    if nsid.starts_with("chat.bsky.") && auth.as_ref().is_some_and(|a| !a.privileged) {
        return Err(PdsError::Authorization(
            "chat requires a privileged app password".to_string(),
        ));
    }

    let target = resolve_target(ctx, &parts.headers, &nsid).await?;
    let body = axum::body::to_bytes(body, MAX_PROXY_BODY)
        .await
        .map_err(|e| PdsError::Validation(format!("request body unreadable or too large: {e}")))?;
    forward(
        ctx,
        &target,
        &nsid,
        parts.method.clone(),
        parts.uri.query(),
        &parts.headers,
        body,
        auth.as_ref(),
    )
    .await
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did_document::{DidDocument, Service};
    use crate::identity::resolver::test_doubles::MockIdentityResolver;
    use axum::routing::any;
    use std::sync::{Arc, Mutex};

    /// What the fake upstream saw.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        query: Option<String>,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    struct FakeUpstream {
        url: String,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    /// An upstream that records each request and answers `status` with `body`
    /// and an `atproto-content-labelers` header.
    async fn fake_upstream(status: u16, body: &'static str) -> FakeUpstream {
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = seen.clone();
        let app = axum::Router::new().route(
            "/xrpc/:nsid",
            any(move |req: Request| {
                let log = log.clone();
                async move {
                    let (parts, req_body) = req.into_parts();
                    let req_body = axum::body::to_bytes(req_body, usize::MAX)
                        .await
                        .unwrap()
                        .to_vec();
                    log.lock().unwrap().push(Seen {
                        method: parts.method.to_string(),
                        path: parts.uri.path().to_string(),
                        query: parts.uri.query().map(str::to_string),
                        headers: parts.headers,
                        body: req_body,
                    });
                    (
                        StatusCode::from_u16(status).unwrap(),
                        [
                            ("content-type", "application/json"),
                            ("atproto-content-labelers", "did:plc:labeler"),
                            ("x-internal-upstream", "secret"),
                        ],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeUpstream {
            url: format!("http://{addr}"),
            seen,
        }
    }

    /// A context whose AppView is `appview_url`, with one real account.
    async fn ctx_with_account(appview_url: Option<String>) -> (AppContext, String) {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(move |c| {
            c.federation.appview_url = appview_url;
        })
        .await;
        let account = ctx
            .account_manager
            .create_account(
                "proxy.localhost".to_string(),
                None,
                "password123".to_string(),
                None,
                None,
            )
            .await
            .unwrap();
        (ctx, account.did)
    }

    fn jwt_claims(authorization: &HeaderValue) -> serde_json::Value {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let token = authorization
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap();
        let payload = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }

    fn request(method: Method, uri: &str, headers: &[(&str, &str)], body: &'static str) -> Request {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::from(body)).unwrap()
    }

    async fn body_string(resp: Response) -> String {
        String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn appview_did_is_did_web_of_its_host() {
        assert_eq!(
            appview_did_from_url("https://api.bsky.app").as_deref(),
            Some("did:web:api.bsky.app")
        );
        assert_eq!(
            appview_did_from_url("http://127.0.0.1:2584/").as_deref(),
            Some("did:web:127.0.0.1%3A2584")
        );
        assert_eq!(appview_did_from_url("not a url"), None);
    }

    #[test]
    fn proxy_header_parsing() {
        assert_eq!(
            parse_proxy_header("did:web:api.bsky.chat#bsky_chat").unwrap(),
            ("did:web:api.bsky.chat".to_string(), "bsky_chat".to_string())
        );
        for bad in [
            "did:web:x",
            "did:web:x#",
            "#svc",
            "notadid#svc",
            "did:web:x#a#b",
        ] {
            assert!(parse_proxy_header(bad).is_err(), "{bad}");
        }
    }

    /// The bsky.app case: an app.bsky method this PDS does not implement goes
    /// to the AppView with a valid service-auth JWT for exactly that method.
    #[tokio::test]
    async fn unknown_app_bsky_method_goes_to_the_appview_with_service_auth() {
        let up = fake_upstream(200, r#"{"checkEmailConfirmed":true}"#).await;
        let (ctx, did) = ctx_with_account(Some(up.url.clone())).await;
        let token = ctx
            .account_manager
            .create_session(&did, None)
            .await
            .unwrap()
            .access_token;

        let resp = xrpc_fallback(
            State(ctx.clone()),
            request(
                Method::GET,
                "/xrpc/app.bsky.unspecced.getConfig?x=1&y=two",
                &[
                    ("authorization", &format!("Bearer {token}")),
                    (
                        "atproto-accept-labelers",
                        "did:plc:ar7c4by46qjdydhdevvrndac;redact",
                    ),
                    ("cookie", "must-not-leak"),
                ],
                "",
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("atproto-content-labelers").unwrap(),
            "did:plc:labeler"
        );
        assert!(
            resp.headers().get("x-internal-upstream").is_none(),
            "only listed headers pass back"
        );
        assert_eq!(body_string(resp).await, r#"{"checkEmailConfirmed":true}"#);

        let seen = up.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/xrpc/app.bsky.unspecced.getConfig");
        assert_eq!(seen.query.as_deref(), Some("x=1&y=two"));
        assert_eq!(
            seen.headers.get("atproto-accept-labelers").unwrap(),
            "did:plc:ar7c4by46qjdydhdevvrndac;redact"
        );
        assert!(
            seen.headers.get("cookie").is_none(),
            "unlisted headers are not forwarded"
        );
        let claims = jwt_claims(seen.headers.get("authorization").unwrap());
        assert_eq!(claims["iss"], did);
        assert_eq!(claims["aud"], appview_did_from_url(&up.url).unwrap());
        assert_eq!(claims["lxm"], "app.bsky.unspecced.getConfig");
        let ttl = claims["exp"].as_i64().unwrap() - chrono::Utc::now().timestamp();
        assert!(
            (1..=SERVICE_JWT_TTL_SECS).contains(&ttl),
            "short-lived: {ttl}s"
        );
    }

    /// `atproto-proxy` sends the call to the named service of another DID,
    /// with that DID as the audience; POST bodies are forwarded.
    #[tokio::test]
    async fn atproto_proxy_header_routes_to_the_named_service() {
        let appview = fake_upstream(200, "{}").await;
        let chat = fake_upstream(200, r#"{"ok":true}"#).await;
        let (mut ctx, did) = ctx_with_account(Some(appview.url.clone())).await;
        let resolver = Arc::new(MockIdentityResolver::new());
        resolver.script_did(
            "did:web:chat.example",
            DidDocument {
                context: None,
                id: "did:web:chat.example".to_string(),
                also_known_as: vec![],
                service: vec![Service {
                    id: "#bsky_chat".to_string(),
                    service_type: "BskyChatService".to_string(),
                    service_endpoint: chat.url.clone(),
                }],
                verification_method: vec![],
            },
        );
        ctx.identity_resolver = resolver;
        let token = ctx
            .account_manager
            .create_session(&did, None)
            .await
            .unwrap()
            .access_token;

        let resp = xrpc_fallback(
            State(ctx.clone()),
            request(
                Method::POST,
                "/xrpc/chat.bsky.convo.sendMessage",
                &[
                    ("authorization", &format!("Bearer {token}")),
                    ("atproto-proxy", "did:web:chat.example#bsky_chat"),
                    ("content-type", "application/json"),
                ],
                r#"{"convoId":"c1","message":{"text":"hi"}}"#,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            appview.seen.lock().unwrap().is_empty(),
            "not sent to the AppView"
        );
        let seen = chat.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.method, "POST");
        assert_eq!(
            seen.body,
            br#"{"convoId":"c1","message":{"text":"hi"}}"#.to_vec()
        );
        assert_eq!(
            seen.headers.get("content-type").unwrap(),
            "application/json"
        );
        let claims = jwt_claims(seen.headers.get("authorization").unwrap());
        assert_eq!(claims["aud"], "did:web:chat.example");
        assert_eq!(claims["lxm"], "chat.bsky.convo.sendMessage");
    }

    #[tokio::test]
    async fn upstream_errors_pass_through_unchanged() {
        let up = fake_upstream(400, r#"{"error":"InvalidRequest","message":"nope"}"#).await;
        let (ctx, _) = ctx_with_account(Some(up.url.clone())).await;
        let resp = xrpc_fallback(
            State(ctx),
            request(Method::GET, "/xrpc/app.bsky.feed.getPosts?uris=x", &[], ""),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(resp).await,
            r#"{"error":"InvalidRequest","message":"nope"}"#
        );
    }

    #[tokio::test]
    async fn anonymous_calls_are_forwarded_without_credentials() {
        let up = fake_upstream(200, "{}").await;
        let (ctx, _) = ctx_with_account(Some(up.url.clone())).await;
        let resp = xrpc_fallback(
            State(ctx),
            request(
                Method::GET,
                "/xrpc/app.bsky.actor.getProfiles?actors=a",
                &[],
                "",
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(up.seen.lock().unwrap()[0]
            .headers
            .get("authorization")
            .is_none());
    }

    #[tokio::test]
    async fn refusals_and_non_xrpc_paths() {
        let up = fake_upstream(200, "{}").await;
        let (ctx, did) = ctx_with_account(Some(up.url.clone())).await;
        let call = |uri: &'static str, headers: Vec<(&'static str, String)>| {
            let ctx = ctx.clone();
            async move {
                let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
                xrpc_fallback(State(ctx), request(Method::GET, uri, &hs, "")).await
            }
        };

        // Not XRPC → the JSON 404.
        let r = call("/no/such/page", vec![]).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(body_string(r).await.contains("Endpoint not found"));
        // Account-management namespaces are never forwarded.
        assert_eq!(
            call("/xrpc/com.atproto.server.requestAccountDelete", vec![])
                .await
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
        // No header and not app.bsky → nothing to forward to.
        assert_eq!(
            call("/xrpc/com.example.custom.thing", vec![])
                .await
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
        // Credentials that are present but invalid are refused, not dropped.
        assert_eq!(
            call(
                "/xrpc/app.bsky.feed.getPosts",
                vec![("authorization", "Bearer garbage".into())]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        // A non-privileged app password cannot reach chat.
        ctx.account_manager
            .create_app_password(&did, "phone", false)
            .await
            .unwrap();
        let app_token = ctx
            .account_manager
            .create_session(&did, Some("phone".to_string()))
            .await
            .unwrap()
            .access_token;
        assert_eq!(
            call(
                "/xrpc/chat.bsky.convo.listConvos",
                vec![
                    ("authorization", format!("Bearer {app_token}")),
                    ("atproto-proxy", "did:web:api.bsky.chat#bsky_chat".into())
                ]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(
            up.seen.lock().unwrap().is_empty(),
            "none of these reached an upstream"
        );
    }

    #[tokio::test]
    async fn no_appview_configured_is_method_not_implemented() {
        let (ctx, _) = ctx_with_account(None).await;
        let resp = xrpc_fallback(
            State(ctx),
            request(Method::GET, "/xrpc/app.bsky.unspecced.getConfig", &[], ""),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
