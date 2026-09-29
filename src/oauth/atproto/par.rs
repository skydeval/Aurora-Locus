//! atproto-OAuth Pushed Authorization Request (PAR) endpoint (Arc 2 Phase β.3,
//! chainlink #420 / LOCKED design §3.2 PAR / RFC 9126).
//!
//! `POST /oauth/atproto/par` lets a client push its authorization parameters
//! to the AS over a back channel and receive an opaque `request_uri`, which it
//! then hands to the authorize endpoint in lieu of the individual parameters.
//! atproto OAuth makes PAR mandatory (the AS metadata advertises
//! `require_pushed_authorization_requests: true`).
//!
//! The endpoint is **client-authenticated by DPoP**: the proof demonstrates
//! the client controls its key. The pushed request is persisted with NO holder
//! DID — the DID is bound later, at the authorize step, once the resource
//! owner authenticates their browser session. A short (60s) TTL bounds the
//! window between push and use.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use chrono::{Duration, Utc};

use super::params::{self, RawAuthParams};
use super::request_store::{self, AtprotoAuthorizationRequest};
use super::{oauth_error_json, opaque_token, verify_dpop_required};
use crate::context::AppContext;

/// Lifetime of a pushed authorization request before it must be consumed by
/// the authorize endpoint.
const PAR_TTL_SECS: i64 = 60;

/// `POST /oauth/atproto/par`
pub async fn par(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Form(raw): Form<RawAuthParams>,
) -> Response {
    match par_inner(&ctx, &headers, raw).await {
        Ok(resp) => resp,
        Err(e) => e,
    }
}

async fn par_inner(
    ctx: &AppContext,
    headers: &HeaderMap,
    raw: RawAuthParams,
) -> Result<Response, Response> {
    // 1. Client authentication via DPoP. Absent/invalid proof → 401.
    let htu = format!("{}/oauth/atproto/par", ctx.service_url());
    verify_dpop_required(ctx, headers, &htu)
        .await
        .map_err(|e| oauth_error_json(StatusCode::UNAUTHORIZED, "invalid_client", &e.to_string()))?;

    // 2. Validate the pushed parameters against the atproto-OAuth profile.
    let validated = params::validate(&raw).map_err(|e| {
        oauth_error_json(StatusCode::BAD_REQUEST, e.oauth_code(), &e.description())
    })?;

    // 3. Resolve + trust the client by its metadata document.
    let metadata = ctx
        .client_metadata_fetcher
        .fetch(&validated.client_id)
        .await
        .map_err(|e| {
            oauth_error_json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("client metadata resolution failed: {e}"),
            )
        })?;

    // 4. The pushed redirect_uri must be registered for this client.
    if !metadata.allows_redirect_uri(&validated.redirect_uri) {
        return Err(oauth_error_json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri not registered for this client",
        ));
    }

    // 5. Persist the request with a fresh opaque request_uri and NO did yet
    //    (bound at the authorize step once the holder authenticates).
    let now = Utc::now();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", opaque_token());
    let req = AtprotoAuthorizationRequest {
        request_id: opaque_token(),
        request_uri: Some(request_uri.clone()),
        client_id: validated.client_id,
        redirect_uri: validated.redirect_uri,
        scope: validated.scope.to_canonical_string(),
        state: validated.state,
        code_challenge: validated.code_challenge,
        code_challenge_method: "S256".to_string(),
        did: None,
        code_hash: None,
        code_used_at: None,
        denied_at: None,
        created_at: now.to_rfc3339(),
        expires_at: (now + Duration::seconds(PAR_TTL_SECS)).to_rfc3339(),
        response_mode: Some(validated.response_mode.as_str().to_string()),
    };
    request_store::insert(&ctx.account_db, &req)
        .await
        .map_err(|e| {
            oauth_error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        })?;

    // 6. Return the request_uri + its lifetime (RFC 9126 §2.2).
    let body = serde_json::json!({
        "request_uri": request_uri,
        "expires_in": PAR_TTL_SECS,
    });
    let bytes = serde_json::to_vec(&body).map_err(|e| {
        oauth_error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        )
    })?;
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(bytes.into())
        .expect("static header set builds a valid response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn ctx() -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await
    }

    fn form(client_id: &str, redirect_uri: &str) -> RawAuthParams {
        RawAuthParams {
            client_id: Some(client_id.to_string()),
            response_type: Some("code".to_string()),
            scope: Some("atproto".to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some("st".to_string()),
            code_challenge: Some("chal".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request_uri: None,
            response_mode: None,
        }
    }

    #[tokio::test]
    async fn par_without_dpop_is_401() {
        let ctx = ctx().await;
        let resp = par(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(form(
                "https://app.example.com/client-metadata.json",
                "https://app.example.com/cb",
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = to_bytes(resp.into_body(), 8192).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["error"], "invalid_client");
    }

    // ---- a client that sends RFC 9449 proofs (no exp) ----

    fn fresh_keypair_jwk() -> (p256::ecdsa::SigningKey, crate::federation::dpop::Jwk) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = crate::federation::dpop::Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        };
        (sk, jwk)
    }

    /// A proof shaped as third-party clients send it: jti, htm, htu, iat, and
    /// no exp.
    fn rfc_9449_proof(
        sk: &p256::ecdsa::SigningKey,
        jwk: &crate::federation::dpop::Jwk,
        htu: &str,
    ) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use p256::pkcs8::EncodePrivateKey;
        let claims = serde_json::json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": "POST",
            "htu": htu,
            "iat": Utc::now().timestamp(),
        });
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(serde_json::from_value(serde_json::to_value(jwk).unwrap()).unwrap());
        encode(&header, &claims, &key).unwrap()
    }

    /// Serve one client-metadata document on loopback http (allowed in debug
    /// builds) and return its client_id.
    async fn serve_client_metadata(redirect_uri: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_id = format!(
            "http://127.0.0.1:{}/client-metadata.json",
            listener.local_addr().unwrap().port()
        );
        let body = serde_json::json!({
            "client_id": client_id,
            "redirect_uris": [redirect_uri],
            "dpop_bound_access_tokens": true,
        })
        .to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });
        client_id
    }

    #[tokio::test]
    async fn par_accepts_a_dpop_proof_without_exp() {
        let ctx = ctx().await;
        let redirect_uri = "https://app.example.com/cb";
        let client_id = serve_client_metadata(redirect_uri).await;
        let (sk, jwk) = fresh_keypair_jwk();
        let htu = format!("{}/oauth/atproto/par", ctx.service_url());
        let mut headers = HeaderMap::new();
        headers.insert("DPoP", rfc_9449_proof(&sk, &jwk, &htu).parse().unwrap());

        let resp = par(
            State(ctx.clone()),
            headers,
            Form(form(&client_id, redirect_uri)),
        )
        .await;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 8192).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::CREATED, "PAR response: {doc}");
        assert!(doc["request_uri"]
            .as_str()
            .unwrap()
            .starts_with("urn:ietf:params:oauth:request_uri:"));
    }

    /// #478: the Blacksky client's exact request — its full scope string and
    /// a proof without exp — is accepted, and the scope recorded for the
    /// grant is exactly the one requested (every token in it is supported).
    #[tokio::test]
    async fn par_accepts_the_blacksky_request() {
        const SCOPE: &str = "atproto transition:generic transition:email transition:chat.bsky \
                             identity:handle account:email?action=manage account:status?action=manage";
        let ctx = ctx().await;
        let redirect_uri = "https://app.example.com/cb";
        let client_id = serve_client_metadata(redirect_uri).await;
        let (sk, jwk) = fresh_keypair_jwk();
        let htu = format!("{}/oauth/atproto/par", ctx.service_url());
        let mut headers = HeaderMap::new();
        headers.insert("DPoP", rfc_9449_proof(&sk, &jwk, &htu).parse().unwrap());
        let mut params = form(&client_id, redirect_uri);
        params.scope = Some(SCOPE.to_string());
        // Browser clients on the reference libraries ask for fragment (#483).
        params.response_mode = Some("fragment".to_string());

        let resp = par(State(ctx.clone()), headers, Form(params)).await;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 8192).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::CREATED, "PAR response: {doc}");

        let stored = request_store::get_by_request_uri(
            &ctx.account_db,
            doc["request_uri"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .expect("pushed request stored");
        assert_eq!(stored.scope, SCOPE);
        assert_eq!(stored.response_mode.as_deref(), Some("fragment"));
    }
}
