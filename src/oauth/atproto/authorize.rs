//! atproto-OAuth authorize endpoint + consent screen (Arc 2 Phase β.3,
//! chainlink #420 / LOCKED design §3.2 steps 1-5).
//!
//! `GET /oauth/atproto/authorize` is the resource owner's entry point. It
//! resolves the client (either inline parameters or a PAR `request_uri`),
//! verifies the client trust + redirect URI, requires an authenticated browser
//! session (login-α; redirecting to login when absent), persists the
//! authorization request bound to the session DID, and renders the consent
//! screen. The consent POSTs are handled in [`super::consent`].
//!
//! Browser-facing failures render a small HTML error page (not a JSON dump):
//! the resource owner is looking at this in their browser.

use axum::extract::{Query, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use chrono::{Duration, Utc};

use super::account_choice;
use super::browser_session::{self, BrowserSession};
use super::client_metadata::ClientMetadata;
use super::html::html_escape;
use super::params::{self, RawAuthParams};
use super::request_store::{self, AtprotoAuthorizationRequest};
use super::response::{respond_to_client, ResponseMode};
use crate::context::AppContext;

/// Consent-window lifetime: how long the resource owner has to approve/deny
/// after reaching the authorize step.
const CONSENT_WINDOW_SECS: i64 = 600;

/// `GET /oauth/atproto/authorize`
pub async fn authorize(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(raw): Query<RawAuthParams>,
) -> Response {
    match authorize_inner(&ctx, &headers, raw_query, raw).await {
        Ok(resp) => resp,
        Err(resp) => resp,
    }
}

/// The client + parameters of an authorization request, resolved from either
/// the inline query parameters or a referenced PAR row.
struct Resolved {
    /// `Some(id)` when an existing (PAR) row must be promoted; `None` when a
    /// fresh row must be inserted.
    existing_request_id: Option<String>,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    response_mode: ResponseMode,
    /// The account the client asked for (`login_hint`), as sent (#502).
    login_hint: Option<String>,
    /// The client's `prompt`, not yet acted on (#503).
    prompt: Option<String>,
    /// The account a PAR row is already bound to, if any. A request is bound
    /// once and never rebound (#502).
    bound_did: Option<String>,
}

async fn authorize_inner(
    ctx: &AppContext,
    headers: &HeaderMap,
    raw_query: Option<String>,
    raw: RawAuthParams,
) -> Result<Response, Response> {
    // 1. Resolve the request: a PAR `request_uri` reference, or inline params.
    let resolved = resolve_request(ctx, &raw).await?;

    // 2. Resolve + trust the client by its metadata document.
    let metadata = ctx
        .client_metadata_fetcher
        .fetch(&resolved.client_id)
        .await
        .map_err(|e| {
            error_page(
                StatusCode::BAD_REQUEST,
                "Invalid client",
                &format!("Could not resolve the client's metadata: {e}"),
            )
        })?;

    // 3. The redirect_uri must be exactly registered for this client.
    if !metadata.allows_redirect_uri(&resolved.redirect_uri) {
        return Err(error_page(
            StatusCode::BAD_REQUEST,
            "Invalid redirect_uri",
            "redirect_uri not registered for this client.",
        ));
    }
    // 3b. Only scopes the client declares in its metadata (#503). A pushed
    //     request was checked at the push; an inline one is checked here.
    if !metadata.allows_scope(&resolved.scope) {
        return Err(error_page(
            StatusCode::BAD_REQUEST,
            "Invalid scope",
            "The app asked for permissions it does not declare.",
        ));
    }

    // 4. The account the client asked for, when it named one hosted here
    //    (#502). An unknown hint is ignored, as if none had been sent.
    let hinted_did = match resolved.login_hint.as_deref() {
        Some(hint) => account_choice::resolve_hint(ctx, hint).await,
        None => None,
    };
    // The place to come back to. An inline `prompt` is dropped from it, so
    // coming back after acting on the prompt does not ask again; a pushed
    // request's prompt is cleared on its row by the page that acts on it.
    let return_to = without_prompt(&authorize_url(ctx, raw_query.as_deref()));

    // 4b. `prompt` (#503): sign up, or sign in afresh, before anything else.
    match resolved.prompt.as_deref() {
        Some("create") => {
            give_time_to_act(ctx, &resolved).await?;
            let suggested = match hinted_did {
                None => resolved.login_hint.as_deref(),
                Some(_) => None,
            };
            return Ok(redirect(&super::signup::signup_url(ctx, &return_to, suggested)));
        }
        Some("login") | Some("select_account") => {
            give_time_to_act(ctx, &resolved).await?;
            let prefill = hinted_did.as_ref().and(resolved.login_hint.as_deref());
            return Ok(redirect(&account_choice::signin_url(ctx, &return_to, prefill)));
        }
        _ => {}
    }
    let prompt_none = resolved.prompt.as_deref() == Some("none");

    // 5. Require an authenticated browser session. Absent → the sign-in page,
    //    prefilled with the requested account, returning here afterwards.
    let session = match resolve_session(ctx, headers).await {
        Some(s) => s,
        // `prompt=none`: no page may be shown, and signing in would be one.
        None if prompt_none => return Ok(prompt_none_error(ctx, &resolved, "login_required")),
        None => {
            if let Some(id) = &resolved.existing_request_id {
                let window = (Utc::now() + Duration::seconds(CONSENT_WINDOW_SECS)).to_rfc3339();
                request_store::extend_unbound(&ctx.account_db, id, &window)
                    .await
                    .map_err(internal_error_page)?;
            }
            let prefill = hinted_did.as_ref().and(resolved.login_hint.as_deref());
            return Ok(redirect(&account_choice::signin_url(ctx, &return_to, prefill)));
        }
    };

    let now = Utc::now();
    let consent_expiry = (now + Duration::seconds(CONSENT_WINDOW_SECS)).to_rfc3339();

    // 6. Never authorize an account other than the one this request is for
    //    (#502): the account a PAR row is already bound to, else the one the
    //    client asked for. A session holding another account binds nothing;
    //    the resource owner chooses to sign in as the requested account or to
    //    cancel.
    let wanted = resolved.bound_did.clone().or(hinted_did);
    if prompt_none {
        // Another account would need choosing, or consent would need asking:
        // both are pages. Only the first-party admin client, which skips
        // consent, can complete without one.
        let other_account = wanted.as_ref().is_some_and(|did| *did != session.did);
        if other_account {
            return Ok(prompt_none_error(ctx, &resolved, "login_required"));
        }
        if !is_first_party_admin(ctx, &resolved.client_id, &session.did).await {
            return Ok(prompt_none_error(ctx, &resolved, "consent_required"));
        }
    }
    if let Some(wanted) = wanted.filter(|did| *did != session.did) {
        let request_id = match &resolved.existing_request_id {
            Some(id) => {
                request_store::extend_unbound(&ctx.account_db, id, &consent_expiry)
                    .await
                    .map_err(internal_error_page)?;
                id.clone()
            }
            None => {
                let id = super::opaque_token();
                request_store::insert(&ctx.account_db, &new_row(&id, &resolved, None, &now, &consent_expiry))
                    .await
                    .map_err(internal_error_page)?;
                id
            }
        };
        let client_name = metadata.client_name.as_deref().unwrap_or(&metadata.client_id);
        return Ok(account_choice::render_switch_page(
            &request_id,
            &session.csrf_token,
            client_name,
            &account_choice::account_label(ctx, &wanted).await,
            &account_choice::account_label(ctx, &session.did).await,
            &return_to,
        ));
    }

    // 7. Persist the authorization request bound to the session DID, with the
    //    consent-window TTL. Direct requests insert fresh; PAR requests promote
    //    the pushed row in place, and only if no other account holds it.
    let request_id = match &resolved.existing_request_id {
        Some(id) => {
            let bound =
                request_store::promote_par_request(&ctx.account_db, id, &session.did, &consent_expiry)
                    .await
                    .map_err(internal_error_page)?;
            if !bound {
                return Err(error_page(
                    StatusCode::BAD_REQUEST,
                    "Request already in use",
                    "This sign-in was started for another account. Please start again from the app.",
                ));
            }
            id.clone()
        }
        None => {
            let id = super::opaque_token();
            request_store::insert(
                &ctx.account_db,
                &new_row(&id, &resolved, Some(&session.did), &now, &consent_expiry),
            )
            .await
            .map_err(internal_error_page)?;
            id
        }
    };

    // 6a. First-party admin auto-approve. When the requesting client is Aurora's
    //     own admin client AND the authenticated resource owner holds an admin
    //     role on this PDS, skip the consent screen — an admin authorizing the
    //     admin panel on their own PDS is not the third-party-app scenario consent
    //     exists for (chainlink #439). Safety holds without the consent CSRF
    //     token: the code lands only at the first-party client's pre-registered
    //     redirect_uri, and redemption still requires the PKCE verifier the admin
    //     client holds server-side, so a cross-site-triggered authorize cannot be
    //     completed by anyone but the admin's own callback.
    if is_first_party_admin(ctx, &resolved.client_id, &session.did).await {
        return Ok(auto_approve(
            ctx,
            &request_id,
            &resolved.redirect_uri,
            resolved.response_mode,
            resolved.state.as_deref(),
        )
        .await);
    }

    // 8. Render the consent screen. The CSRF token is the SESSION's token
    //    (β.2's browser_session.csrf_token) — the request_id is a correlation
    //    key, never a trust token (F-3.2). It names the account the code will
    //    be issued for (#502).
    Ok(render_consent_screen(
        &request_id,
        &session.csrf_token,
        &metadata,
        &resolved.scope,
        &resolved.redirect_uri,
        &account_choice::account_label(ctx, &session.did).await,
        &return_to,
    ))
}

/// A new (non-PAR) request row for `resolved`, bound to `did` when given.
fn new_row(
    request_id: &str,
    resolved: &Resolved,
    did: Option<&str>,
    now: &chrono::DateTime<Utc>,
    expires_at: &str,
) -> AtprotoAuthorizationRequest {
    AtprotoAuthorizationRequest {
        request_id: request_id.to_string(),
        request_uri: None,
        client_id: resolved.client_id.clone(),
        redirect_uri: resolved.redirect_uri.clone(),
        scope: resolved.scope.clone(),
        state: resolved.state.clone(),
        code_challenge: resolved.code_challenge.clone(),
        code_challenge_method: "S256".to_string(),
        did: did.map(str::to_string),
        code_hash: None,
        code_used_at: None,
        denied_at: None,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_string(),
        response_mode: Some(resolved.response_mode.as_str().to_string()),
        login_hint: resolved.login_hint.clone(),
        prompt: None,
    }
}

/// Resolve the request parameters from either a PAR `request_uri` (loaded from
/// the store) or the inline query parameters (validated here).
async fn resolve_request(
    ctx: &AppContext,
    raw: &RawAuthParams,
) -> Result<Resolved, Response> {
    if let Some(request_uri) = raw.request_uri.as_deref().filter(|s| !s.is_empty()) {
        let row = request_store::get_by_request_uri(&ctx.account_db, request_uri)
            .await
            .map_err(internal_error_page)?
            .ok_or_else(|| {
                error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid request_uri",
                    "The request_uri is unknown or has already been used.",
                )
            })?;
        if row.is_expired(Utc::now()) {
            return Err(error_page(
                StatusCode::BAD_REQUEST,
                "Expired request_uri",
                "The pushed authorization request has expired; please restart.",
            ));
        }
        let response_mode = row.response_mode();
        Ok(Resolved {
            existing_request_id: Some(row.request_id),
            response_mode,
            login_hint: row.login_hint,
            prompt: row.prompt,
            bound_did: row.did,
            client_id: row.client_id,
            redirect_uri: row.redirect_uri,
            scope: row.scope,
            state: row.state,
            code_challenge: row.code_challenge,
        })
    } else {
        let validated = params::validate(raw).map_err(|e| {
            error_page(StatusCode::BAD_REQUEST, "Invalid request", &e.description())
        })?;
        Ok(Resolved {
            existing_request_id: None,
            client_id: validated.client_id,
            redirect_uri: validated.redirect_uri,
            scope: validated.scope.to_canonical_string(),
            state: validated.state,
            code_challenge: validated.code_challenge,
            response_mode: validated.response_mode,
            login_hint: validated.login_hint,
            prompt: validated.prompt,
            bound_did: None,
        })
    }
}

/// Resolve a valid browser session from the request cookie, if any.
async fn resolve_session(ctx: &AppContext, headers: &HeaderMap) -> Option<BrowserSession> {
    let id = browser_session::read_session_cookie(headers)?;
    browser_session::get_valid_session(&ctx.account_db, &id)
        .await
        .ok()
        .flatten()
}

/// This authorize URL, as the place to come back to after signing in.
///
/// Sign-in goes to `/oauth/atproto/signin` (browser password login for local
/// accounts), NOT `/oauth/atproto/login` (login-α: machine, key-signing,
/// did:web-only) — the latter cannot serve a did:plc account authenticating
/// with a password in a browser (chainlink #439).
fn authorize_url(ctx: &AppContext, raw_query: Option<&str>) -> String {
    match raw_query {
        Some(q) if !q.is_empty() => {
            format!("{}/oauth/atproto/authorize?{}", ctx.service_url(), q)
        }
        _ => format!("{}/oauth/atproto/authorize", ctx.service_url()),
    }
}

/// `prompt=none` could not be honoured: answer the client with `error`
/// (`login_required` or `consent_required`), `state` and `iss`, showing no
/// page (#503).
fn prompt_none_error(ctx: &AppContext, resolved: &Resolved, error: &str) -> Response {
    let mut pairs: Vec<(&str, &str)> = vec![("error", error)];
    if let Some(state) = resolved.state.as_deref() {
        pairs.push(("state", state));
    }
    respond_to_client(
        &resolved.redirect_uri,
        resolved.response_mode,
        &ctx.service_url(),
        &pairs,
    )
}

/// Give a pushed request the consent window while the resource owner signs
/// up or signs in (#502, #503).
async fn give_time_to_act(ctx: &AppContext, resolved: &Resolved) -> Result<(), Response> {
    if let Some(id) = &resolved.existing_request_id {
        let window = (Utc::now() + Duration::seconds(CONSENT_WINDOW_SECS)).to_rfc3339();
        request_store::extend_unbound(&ctx.account_db, id, &window)
            .await
            .map_err(internal_error_page)?;
    }
    Ok(())
}

/// `url` without its `prompt` query parameter.
fn without_prompt(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| key != "prompt")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if kept.is_empty() {
        parsed.set_query(None);
    } else {
        parsed.query_pairs_mut().clear().extend_pairs(kept);
    }
    parsed.to_string()
}

/// A 302 to `location`.
fn redirect(location: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response()
}

/// Whether this authorization request should skip consent: Aurora's own admin
/// client requesting authorization from a resource owner who holds an admin role
/// on this PDS. Both conditions are required — a non-Aurora client, or a
/// non-admin holder, still sees the consent screen.
async fn is_first_party_admin(ctx: &AppContext, client_id: &str, did: &str) -> bool {
    if client_id != ctx.config.authentication.oauth.client_id {
        return false;
    }
    matches!(ctx.admin_role_manager.get_role(did).await, Ok(Some(_)))
}

/// Mint the authorization code and 302 to the client — the auto-approve
/// counterpart to [`super::consent::approve`], minus the consent form + CSRF
/// (there is no form; approval is implicit for the first-party admin case). The
/// code's hash is persisted; the raw code travels only in the redirect.
async fn auto_approve(
    ctx: &AppContext,
    request_id: &str,
    redirect_uri: &str,
    response_mode: ResponseMode,
    state: Option<&str>,
) -> Response {
    let code = super::opaque_token();
    let code_hash = super::token_hash(&code);
    if let Err(e) = request_store::set_code_hash(&ctx.account_db, request_id, &code_hash).await {
        return internal_error_page(e);
    }
    let mut pairs: Vec<(&str, &str)> = vec![("code", &code)];
    if let Some(s) = state {
        pairs.push(("state", s));
    }
    respond_to_client(redirect_uri, response_mode, &ctx.service_url(), &pairs)
}

/// Render the HTML consent screen. Every interpolated value is HTML-escaped.
fn render_consent_screen(
    request_id: &str,
    csrf_token: &str,
    metadata: &ClientMetadata,
    scope: &str,
    redirect_uri: &str,
    account: &str,
    return_to: &str,
) -> Response {
    let client_name = metadata
        .client_name
        .as_deref()
        .unwrap_or(&metadata.client_id);
    let scope_items: String = super::scope::ScopeSet::from_granted(scope)
        .tokens()
        .map(|(token, parsed)| {
            format!(
                "<li>{} <small><code>{}</code></small></li>",
                html_escape(&parsed.describe()),
                html_escape(token)
            )
        })
        .collect();

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize application</title>
</head>
<body>
  <main>
    <h1>Authorize <strong>{client_name}</strong></h1>
    <p>The application <strong>{client_name}</strong> is requesting access to your account.</p>
    <p>Signed in as <strong>{account}</strong>.</p>
    <form method="post" action="/oauth/atproto/session/choose">
      <input type="hidden" name="request_id" value="{request_id}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="return_to" value="{return_to}">
      <button type="submit" name="action" value="switch">Not you? Switch account</button>
    </form>
    <h2>Requested permissions</h2>
    <ul>{scope_items}</ul>
    <p>After authorizing, you will be redirected to:<br><code>{redirect_uri}</code></p>
    <form method="post" action="/oauth/atproto/consent/approve" style="display:inline">
      <input type="hidden" name="request_id" value="{request_id}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <button type="submit">Approve</button>
    </form>
    <form method="post" action="/oauth/atproto/consent/deny" style="display:inline">
      <input type="hidden" name="request_id" value="{request_id}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <button type="submit">Deny</button>
    </form>
  </main>
</body>
</html>"#,
        client_name = html_escape(client_name),
        scope_items = scope_items,
        redirect_uri = html_escape(redirect_uri),
        request_id = html_escape(request_id),
        csrf_token = html_escape(csrf_token),
        account = html_escape(account),
        return_to = html_escape(return_to),
    );

    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Html(body),
    )
        .into_response()
}

/// Minimal HTML error page for browser-facing authorize failures.
fn error_page(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body><main><h1>{title}</h1><p>{detail}</p></main></body>
</html>"#,
        title = html_escape(title),
        detail = html_escape(detail),
    );
    (status, Html(body)).into_response()
}

fn internal_error_page(e: crate::error::PdsError) -> Response {
    error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Server error",
        &e.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn ctx() -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn query(client_id: &str, redirect_uri: &str) -> RawAuthParams {
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
            login_hint: None,
            prompt: None,
        }
    }

    #[tokio::test]
    async fn missing_client_id_renders_error_page() {
        let ctx = ctx().await;
        let mut raw = query("https://app/cm.json", "https://app/cb");
        raw.client_id = None;
        let resp = authorize(
            State(ctx.clone()),
            HeaderMap::new(),
            RawQuery(None),
            Query(raw),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let html = body_string(resp).await;
        assert!(html.contains("Invalid request"));
    }

    #[tokio::test]
    async fn no_session_redirects_to_login_with_return_to() {
        let ctx = ctx().await;
        // Valid inline params but no session cookie → redirect to login. The
        // client metadata fetch must succeed first, so serve a localhost doc.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client_id = format!("http://127.0.0.1:{port}/client-metadata.json");
        let redirect_uri = "https://app.example.com/cb".to_string();
        let body = format!(
            r#"{{"client_id":"{client_id}","redirect_uris":["{redirect_uri}"]}}"#
        );
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let raw_query = format!(
            "client_id={}&response_type=code&scope=atproto&redirect_uri={}&state=st&code_challenge=chal&code_challenge_method=S256",
            urlencoding(&client_id),
            urlencoding(&redirect_uri)
        );
        let resp = authorize(
            State(ctx.clone()),
            HeaderMap::new(),
            RawQuery(Some(raw_query)),
            Query(query(&client_id, &redirect_uri)),
        )
        .await;
        server.await.unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/oauth/atproto/signin?return_to="));
        // The return_to round-trips the authorize URL (percent-encoded).
        assert!(location.contains("authorize"));
    }

    fn urlencoding(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }

    #[tokio::test]
    async fn consent_screen_renders_with_request_fields() {
        // Direct render-path unit check: a synthetic metadata + scope produces a
        // consent form carrying the request_id, csrf token, and escaped client
        // name + redirect URI.
        let metadata = ClientMetadata {
            client_id: "https://app.example.com/cm.json".to_string(),
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            client_name: Some("Cool <App>".to_string()),
            scope: None,
            response_types: None,
            grant_types: None,
            token_endpoint_auth_method: None,
            dpop_bound_access_tokens: None,
            jwks_uri: None,
            application_type: None,
        };
        let resp = render_consent_screen(
            "req-123",
            "csrf-abc",
            &metadata,
            "atproto transition:generic",
            "https://app.example.com/cb",
            "@alice.<test> (did:plc:alice)",
            "https://pds.example/oauth/atproto/authorize?request_uri=x",
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains(r#"name="request_id" value="req-123""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-abc""#));
        assert!(html.contains("/oauth/atproto/consent/approve"));
        assert!(html.contains("/oauth/atproto/consent/deny"));
        // Client name is escaped (no raw angle brackets).
        assert!(html.contains("Cool &lt;App&gt;"));
        assert!(html.contains("<code>atproto</code>"));
        assert!(html.contains("<code>transition:generic</code>"));
        // Each permission is described in words (#478).
        assert!(html.contains("Sign in as your account"));
        assert!(html.contains("upload files"));
        // #502: the account the code will be issued for is named, escaped,
        // with a way to switch.
        assert!(html.contains("Signed in as <strong>@alice.&lt;test&gt; (did:plc:alice)</strong>"));
        assert!(html.contains(r#"action="/oauth/atproto/session/choose""#));
        assert!(html.contains(r#"value="switch""#));
    }

    // ---- First-party admin auto-approve (chainlink #439) ----

    /// Spawn a one-shot client-metadata server; returns (client_id, join).
    async fn spawn_metadata(redirect_uri: &str) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client_id = format!("http://127.0.0.1:{port}/client-metadata.json");
        let body = format!(
            r#"{{"client_id":"{client_id}","redirect_uris":["{redirect_uri}"]}}"#
        );
        let join = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        (client_id, join)
    }

    async fn ctx_with_admin_client(client_id: String) -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(move |cfg| {
            cfg.authentication.oauth.client_id = client_id;
        })
        .await
    }

    fn session_cookie(session_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", browser_session::SESSION_COOKIE, session_id)
                .parse()
                .unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn first_party_admin_auto_approves_without_consent() {
        use crate::admin::roles::Role;
        let did = "did:web:admin.example.com";
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx_with_admin_client(client_id.clone()).await;

        // The operator holds an admin role AND has an authenticated session.
        ctx.admin_role_manager
            .grant_role(did, Role::SuperAdmin, "system", None)
            .await
            .unwrap();
        let session = browser_session::create_session(&ctx.account_db, did, None, None)
            .await
            .unwrap();

        let resp = authorize(
            State(ctx.clone()),
            session_cookie(&session.id),
            RawQuery(None),
            Query(query(&client_id, redirect_uri)),
        )
        .await;
        server.await.unwrap();

        // Auto-approved: 302 straight to the client with a code, no consent screen.
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://app.example.com/cb?"), "loc: {loc}");
        assert!(loc.contains("code="));
        assert!(loc.contains("state=st"));
    }

    #[tokio::test]
    async fn first_party_non_admin_still_sees_consent() {
        let did = "did:web:notadmin.example.com";
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx_with_admin_client(client_id.clone()).await;

        // Same first-party client, but the session holder has NO admin role.
        let session = browser_session::create_session(&ctx.account_db, did, None, None)
            .await
            .unwrap();

        let resp = authorize(
            State(ctx.clone()),
            session_cookie(&session.id),
            RawQuery(None),
            Query(query(&client_id, redirect_uri)),
        )
        .await;
        server.await.unwrap();

        // Not auto-approved: the consent screen renders (200 HTML with Approve).
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Authorize"));
        assert!(html.contains("Approve"));
    }

    // ---- Account selection (chainlink #502) ----

    /// Two local accounts; returns (did_a, did_b).
    async fn two_accounts(ctx: &AppContext) -> (String, String) {
        let mut dids = Vec::new();
        for handle in ["alice.localhost", "bob.localhost"] {
            let account = ctx
                .account_manager
                .create_account(handle.to_string(), None, "password123".to_string(), None, None)
                .await
                .expect("create account");
            dids.push(account.did);
        }
        (dids[0].clone(), dids[1].clone())
    }

    /// A pushed request for `client_id`, unbound, hinting `hint`.
    async fn push(ctx: &AppContext, client_id: &str, redirect_uri: &str, hint: &str) -> (String, String) {
        let request_id = super::super::opaque_token();
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{request_id}");
        let now = Utc::now();
        request_store::insert(
            &ctx.account_db,
            &AtprotoAuthorizationRequest {
                request_id: request_id.clone(),
                request_uri: Some(request_uri.clone()),
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                scope: "atproto".to_string(),
                state: Some("st".to_string()),
                code_challenge: "chal".to_string(),
                code_challenge_method: "S256".to_string(),
                did: None,
                code_hash: None,
                code_used_at: None,
                denied_at: None,
                created_at: now.to_rfc3339(),
                expires_at: (now + Duration::seconds(60)).to_rfc3339(),
                response_mode: None,
                login_hint: Some(hint.to_string()),
                prompt: None,
            },
        )
        .await
        .unwrap();
        (request_id, request_uri)
    }

    fn par_query(client_id: &str, request_uri: &str) -> (RawQuery, Query<RawAuthParams>) {
        let raw = format!(
            "client_id={}&request_uri={}",
            urlencoding(client_id),
            urlencoding(request_uri)
        );
        (
            RawQuery(Some(raw)),
            Query(RawAuthParams {
                client_id: Some(client_id.to_string()),
                request_uri: Some(request_uri.to_string()),
                ..RawAuthParams::default()
            }),
        )
    }

    #[tokio::test]
    async fn a_session_for_another_account_binds_nothing_and_asks() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let (alice, _bob) = two_accounts(&ctx).await;
        let session = browser_session::create_session(&ctx.account_db, &alice, None, None)
            .await
            .unwrap();
        let (request_id, request_uri) = push(&ctx, &client_id, redirect_uri, "bob.localhost").await;

        let (raw_query, query) = par_query(&client_id, &request_uri);
        let resp = authorize(State(ctx.clone()), session_cookie(&session.id), raw_query, query).await;
        server.await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("@bob.localhost"), "names the requested account: {html}");
        assert!(html.contains("@alice.localhost"), "names the signed-in account");
        assert!(html.contains(r#"value="switch""#) && html.contains(r#"value="cancel""#));
        assert!(!html.contains("consent/approve"), "no way to approve as alice");
        let row = request_store::get_by_request_id(&ctx.account_db, &request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(row.did.is_none(), "the request is not bound to alice");
    }

    #[tokio::test]
    async fn a_session_for_the_requested_account_reaches_consent() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let (_alice, bob) = two_accounts(&ctx).await;
        let session = browser_session::create_session(&ctx.account_db, &bob, None, None)
            .await
            .unwrap();
        let (request_id, request_uri) = push(&ctx, &client_id, redirect_uri, "bob.localhost").await;

        let (raw_query, query) = par_query(&client_id, &request_uri);
        let resp = authorize(State(ctx.clone()), session_cookie(&session.id), raw_query, query).await;
        server.await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("consent/approve"));
        assert!(html.contains(&format!("@bob.localhost ({bob})")));
        let row = request_store::get_by_request_id(&ctx.account_db, &request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.did.as_deref(), Some(bob.as_str()));
    }

    #[tokio::test]
    async fn no_session_goes_to_sign_in_with_the_hint() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        two_accounts(&ctx).await;
        let (_request_id, request_uri) = push(&ctx, &client_id, redirect_uri, "bob.localhost").await;

        let (raw_query, query) = par_query(&client_id, &request_uri);
        let resp = authorize(State(ctx.clone()), HeaderMap::new(), raw_query, query).await;
        server.await.unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.contains("/oauth/atproto/signin?return_to="), "{location}");
        assert!(location.ends_with("&login_hint=bob.localhost"), "{location}");
    }

    #[tokio::test]
    async fn a_request_bound_to_one_account_is_never_rebound() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let (alice, bob) = two_accounts(&ctx).await;
        let (request_id, request_uri) = push(&ctx, &client_id, redirect_uri, "bob.localhost").await;
        let later = (Utc::now() + Duration::seconds(600)).to_rfc3339();
        assert!(request_store::promote_par_request(&ctx.account_db, &request_id, &bob, &later)
            .await
            .unwrap());

        // Alice's browser revisits the authorize URL: she is shown the choice,
        // the row stays Bob's.
        let session = browser_session::create_session(&ctx.account_db, &alice, None, None)
            .await
            .unwrap();
        let (raw_query, query) = par_query(&client_id, &request_uri);
        let resp = authorize(State(ctx.clone()), session_cookie(&session.id), raw_query, query).await;
        server.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!body_string(resp).await.contains("consent/approve"));
        let row = request_store::get_by_request_id(&ctx.account_db, &request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.did.as_deref(), Some(bob.as_str()));
    }

    // ---- prompt (chainlink #503) ----

    async fn with_prompt(ctx: &AppContext, client_id: &str, redirect_uri: &str, prompt: &str, headers: HeaderMap) -> Response {
        let mut raw = query(client_id, redirect_uri);
        raw.prompt = Some(prompt.to_string());
        let raw_query = format!(
            "client_id={}&response_type=code&scope=atproto&redirect_uri={}&state=st&code_challenge=chal&code_challenge_method=S256&prompt={prompt}",
            urlencoding(client_id),
            urlencoding(redirect_uri)
        );
        authorize(State(ctx.clone()), headers, RawQuery(Some(raw_query)), Query(raw)).await
    }

    fn location(resp: &Response) -> String {
        resp.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn prompt_create_goes_to_sign_up_without_the_prompt() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let resp = with_prompt(&ctx, &client_id, redirect_uri, "create", HeaderMap::new()).await;
        server.await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = location(&resp);
        assert!(loc.contains("/oauth/atproto/signup?return_to="), "{loc}");
        assert!(!loc.contains("prompt%3Dcreate"), "coming back must not ask again: {loc}");
    }

    #[tokio::test]
    async fn prompt_login_signs_in_afresh_even_with_a_session() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let (alice, _) = two_accounts(&ctx).await;
        let session = browser_session::create_session(&ctx.account_db, &alice, None, None)
            .await
            .unwrap();
        let resp = with_prompt(&ctx, &client_id, redirect_uri, "login", session_cookie(&session.id)).await;
        server.await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert!(location(&resp).contains("/oauth/atproto/signin?return_to="));
    }

    #[tokio::test]
    async fn prompt_none_without_a_session_is_login_required() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let resp = with_prompt(&ctx, &client_id, redirect_uri, "none", HeaderMap::new()).await;
        server.await.unwrap();
        let loc = location(&resp);
        assert!(loc.starts_with("https://app.example.com/cb?"), "{loc}");
        assert!(loc.contains("error=login_required") && loc.contains("state=st"), "{loc}");
    }

    #[tokio::test]
    async fn prompt_none_with_a_session_is_consent_required() {
        let redirect_uri = "https://app.example.com/cb";
        let (client_id, server) = spawn_metadata(redirect_uri).await;
        let ctx = ctx().await;
        let (alice, _) = two_accounts(&ctx).await;
        let session = browser_session::create_session(&ctx.account_db, &alice, None, None)
            .await
            .unwrap();
        let resp = with_prompt(&ctx, &client_id, redirect_uri, "none", session_cookie(&session.id)).await;
        server.await.unwrap();
        assert!(location(&resp).contains("error=consent_required"));
    }

    #[test]
    fn the_prompt_is_dropped_from_the_return_url() {
        assert_eq!(
            without_prompt("https://pds.example/oauth/atproto/authorize?client_id=a&prompt=create&state=s"),
            "https://pds.example/oauth/atproto/authorize?client_id=a&state=s"
        );
        assert_eq!(
            without_prompt("https://pds.example/oauth/atproto/authorize?prompt=login"),
            "https://pds.example/oauth/atproto/authorize"
        );
    }
}
