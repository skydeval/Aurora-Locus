//! Browser-interactive AS sign-in for local accounts (chainlink #439 follow-on).
//!
//! The atproto authorize flow ([`super::authorize`]) requires an authenticated
//! browser session before it will bind + consent an authorization request.
//! login-α (`/oauth/atproto/login`) covers did:web holders that sign a challenge
//! with their key, but the admin OAuth ceremony authenticates a LOCAL operator
//! with their account password in a browser — which login-α cannot do (it is
//! machine, key-signing, did:web-only). A live-VPS smoke of the admin OAuth flow
//! hit exactly this gap: the authorize→login bounce landed on the login-α
//! challenge endpoint and 400'd on its required `did` query field.
//!
//! This endpoint fills the gap: a server-rendered password form whose POST
//! verifies the account credential (`account.password_hash`, via
//! [`crate::account::AccountManager::verify_password`]) and mints the SAME
//! browser session the authorize/consent handlers read, then returns to the
//! authorize URL.
//!
//! `return_to` is validated to be an authorize URL on THIS server before any
//! redirect, so the endpoint can never be used as an open redirector. All
//! credential failures collapse to one uniform message (no existence oracle).

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use super::browser_session;
use super::html::html_escape;
use crate::context::AppContext;

/// Query for the sign-in page: where to return after a successful login,
/// and the account the client asked for (#502), to prefill.
#[derive(Debug, Deserialize)]
pub struct SigninPageQuery {
    #[serde(default)]
    pub return_to: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
}

/// What the sign-in page shows besides the form (#502).
#[derive(Debug, Default)]
struct PageContext {
    /// The identifier to prefill: the account the client asked for.
    login_hint: Option<String>,
    /// The name of the app asking, from its client metadata.
    client_name: Option<String>,
    /// The account this browser is already signed in as, and the session's
    /// CSRF token for the sign-out form.
    signed_in: Option<(String, String)>,
    /// The identifier typed, kept when the page is shown again.
    identifier: Option<String>,
    /// The account signs in with an emailed code too: show its field (#503).
    code_requested: bool,
}

/// The sign-in form body.
#[derive(Debug, Deserialize)]
pub struct SigninForm {
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub return_to: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    /// The emailed sign-in code, for an account with `emailAuthFactor` (#503).
    #[serde(default)]
    pub auth_code: Option<String>,
}

/// `GET /oauth/atproto/signin?return_to=…&login_hint=…` — render the sign-in
/// form.
pub async fn signin_page(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Query(q): Query<SigninPageQuery>,
) -> Response {
    let return_to = sanitize_return_to(&ctx, q.return_to.as_deref());
    let extras = page_context(&ctx, &headers, &return_to, q.login_hint.as_deref()).await;
    page(StatusCode::OK, &return_to, None, &extras)
}

/// Gather what the page shows besides the form: the hint (kept only when it
/// names an account here, so an unknown hint reveals nothing), the asking
/// app's name, and the account already signed in, if any.
async fn page_context(
    ctx: &AppContext,
    headers: &HeaderMap,
    return_to: &str,
    login_hint: Option<&str>,
) -> PageContext {
    let login_hint = match super::params::normalize_login_hint(login_hint) {
        Some(hint) if super::account_choice::resolve_hint(ctx, &hint).await.is_some() => Some(hint),
        _ => None,
    };
    let signed_in = match browser_session::read_session_cookie(headers) {
        Some(id) => match browser_session::get_valid_session(&ctx.account_db, &id).await {
            Ok(Some(session)) => Some((
                super::account_choice::account_label(ctx, &session.did).await,
                session.csrf_token,
            )),
            _ => None,
        },
        None => None,
    };
    PageContext {
        login_hint,
        client_name: client_name_for(ctx, return_to).await,
        signed_in,
        ..PageContext::default()
    }
}

/// The name of the app an authorize URL is for: its `client_id` (inline, or
/// from the pushed request its `request_uri` names), looked up in the client's
/// metadata. `None` when it cannot be found.
async fn client_name_for(ctx: &AppContext, return_to: &str) -> Option<String> {
    let url = url::Url::parse(return_to).ok()?;
    let mut client_id = None;
    let mut request_uri = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            "request_uri" => request_uri = Some(value.into_owned()),
            _ => {}
        }
    }
    let client_id = match (client_id, request_uri) {
        (Some(id), _) => id,
        (None, Some(uri)) => {
            super::request_store::get_by_request_uri(&ctx.account_db, &uri)
                .await
                .ok()??
                .client_id
        }
        (None, None) => return None,
    };
    let metadata = ctx.client_metadata_fetcher.fetch(&client_id).await.ok()?;
    Some(
        metadata
            .client_name
            .clone()
            .unwrap_or_else(|| metadata.client_id.clone()),
    )
}

/// `POST /oauth/atproto/signin` — verify the account password, mint a browser
/// session, and 302 to the validated `return_to`.
pub async fn submit_signin(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Form(form): Form<SigninForm>,
) -> Response {
    let return_to = sanitize_return_to(&ctx, form.return_to.as_deref());
    let identifier = form.identifier.as_deref().unwrap_or_default().trim();
    let mut extras = PageContext {
        login_hint: super::params::normalize_login_hint(form.login_hint.as_deref()),
        identifier: Some(identifier.to_string()).filter(|i| !i.is_empty()),
        ..PageContext::default()
    };
    let password = form.password.as_deref().unwrap_or_default();

    // Verify the account credential (account.password_hash) via the same
    // timing-attack-mitigated path the password admin login uses. Any failure —
    // unknown identifier, wrong password, taken-down, no local credential —
    // collapses to one uniform message (no existence oracle). A deactivated
    // account signs in like any other (#492).
    let account = match ctx.account_manager.verify_password(identifier, password).await {
        Ok(account) => account,
        Err(_) => {
            return page(
                StatusCode::UNAUTHORIZED,
                &return_to,
                Some("Invalid handle or password."),
                &extras,
            )
        }
    };

    // An account that signs in with an emailed code as well (#503): ask for
    // it, or check it. The password must be typed again with the code; it is
    // never sent back to the browser.
    match crate::api::email_factor::require_sign_in_code(&ctx, &account, form.auth_code.as_deref())
        .await
    {
        Ok(()) => {}
        Err(crate::error::PdsError::AuthFactorTokenRequired) => {
            extras.code_requested = true;
            return page(
                StatusCode::UNAUTHORIZED,
                &return_to,
                Some("We emailed you a sign-in code. Enter it with your password."),
                &extras,
            );
        }
        Err(crate::error::PdsError::InvalidAuthFactorToken) => {
            extras.code_requested = true;
            return page(
                StatusCode::UNAUTHORIZED,
                &return_to,
                Some("That sign-in code is wrong or has expired."),
                &extras,
            );
        }
        Err(_) => {
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &return_to,
                Some("A sign-in code could not be sent. Please try again later."),
                &extras,
            )
        }
    }

    // Session-fixation defense: discard any pre-existing session before minting.
    if let Some(old) = browser_session::read_session_cookie(&headers) {
        let _ = browser_session::delete_session(&ctx.account_db, &old).await;
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let session =
        match browser_session::create_session(&ctx.account_db, &account.did, user_agent, None).await {
            Ok(session) => session,
            Err(_) => {
                return page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &return_to,
                    Some("Could not start a session. Please try again."),
                    &extras,
                )
            }
        };

    // A pushed request that asked for a fresh sign-in (`prompt=login`) has
    // had one (#503).
    if let Some(request_uri) = super::signup::request_uri_of(&return_to) {
        if let Err(e) = super::request_store::clear_prompt(&ctx.account_db, &request_uri).await {
            tracing::warn!(error = %e, "signin: request prompt not cleared");
        }
    }

    let cookie = browser_session::set_session_cookie(&session.id);
    // Fetch-driven single-page admin login: when the caller is JS
    // (`Accept: application/json`), set the session cookie and return 204 with NO
    // redirect — the caller's JS drives the subsequent navigation into the OAuth
    // flow, which then finds this session and auto-approves (so the signin page
    // is never rendered). A normal top-level browser navigation
    // (`Accept: text/html` — federated clients, direct visits) still gets the 302
    // back to `return_to`.
    if wants_json(&headers) {
        (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
    } else {
        ([(header::SET_COOKIE, cookie)], Redirect::to(&return_to)).into_response()
    }
}

/// Whether the caller prefers a JSON/programmatic response (a `fetch`) over an
/// HTML page + redirect (a top-level browser navigation).
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false)
}

/// Validate `return_to`: it MUST be an authorize URL on this server. Anything
/// else — off-site, wrong path, or absent — falls back to the bare authorize
/// path, so this endpoint can never be turned into an open redirector.
fn sanitize_return_to(ctx: &AppContext, return_to: Option<&str>) -> String {
    let authorize_url = format!("{}/oauth/atproto/authorize", ctx.service_url());
    match return_to {
        Some(url) if url.starts_with(&authorize_url) => url.to_string(),
        _ => authorize_url,
    }
}

/// Render the sign-in page (with an optional error banner) as a `no-store`
/// HTML response. Every interpolated value is HTML-escaped.
fn page(status: StatusCode, return_to: &str, error: Option<&str>, extras: &PageContext) -> Response {
    let error_html = error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, html_escape(e)))
        .unwrap_or_default();
    let asking_html = extras
        .client_name
        .as_deref()
        .map(|name| format!("<p><strong>{}</strong> is asking you to sign in.</p>", html_escape(name)))
        .unwrap_or_default();
    // Signed in already: say as whom, with a way out that comes back to this
    // same sign-in (#502).
    let signed_in_html = extras
        .signed_in
        .as_ref()
        .map(|(account, csrf)| {
            format!(
                r#"<form method="post" action="/oauth/atproto/session/choose">
      <p>Signed in as <strong>{account}</strong>.
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="login_hint" value="{hint}">
      <button type="submit" name="action" value="signout">Sign out</button></p>
    </form>"#,
                account = html_escape(account),
                csrf = html_escape(csrf),
                return_to = html_escape(return_to),
                hint = html_escape(extras.login_hint.as_deref().unwrap_or_default()),
            )
        })
        .unwrap_or_default();
    let hint = extras.login_hint.as_deref().unwrap_or_default();
    let identifier_value = extras.identifier.as_deref().unwrap_or(hint);
    let code_html = if extras.code_requested {
        r#"<label>Sign-in code<br>
        <input type="text" name="auth_code" autocomplete="one-time-code" required>
      </label><br>"#
    } else {
        ""
    };
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
</head>
<body>
  <main>
    <h1>Sign in</h1>
    {asking_html}
    {signed_in_html}
    {error_html}
    <form method="post" action="/oauth/atproto/signin">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="login_hint" value="{hint}">
      <label>Handle or DID<br>
        <input type="text" name="identifier" value="{identifier_value}" autocomplete="username" autofocus required>
      </label><br>
      <label>Password<br>
        <input type="password" name="password" autocomplete="current-password" required>
      </label><br>
      {code_html}
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"#,
        error_html = error_html,
        asking_html = asking_html,
        signed_in_html = signed_in_html,
        return_to = html_escape(return_to),
        hint = html_escape(hint),
        identifier_value = html_escape(identifier_value),
        code_html = code_html,
    );
    (status, [(header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn ctx() -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await
    }

    /// Seed a local account with a real argon2 password hash.
    async fn seed_account(ctx: &AppContext, did: &str, handle: &str, password: &str) {
        let hash = crate::auth::PasswordHasher::hash(password).unwrap();
        sqlx::query("INSERT INTO actor (did, handle, created_at) VALUES ($1, $2, $3)")
            .bind(did)
            .bind(handle)
            .bind("2026-01-01T00:00:00Z")
            .execute(&ctx.account_db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO account (did, email, password_hash, email_confirmed_at, invites_disabled) \
             VALUES ($1, $2, $3, NULL, 0)",
        )
        .bind(did)
        .bind(Some("op@example.test"))
        .bind(&hash)
        .execute(&ctx.account_db)
        .await
        .unwrap();
    }

    async fn body(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn authorize_url(ctx: &AppContext) -> String {
        format!("{}/oauth/atproto/authorize?client_id=x&request_uri=y", ctx.service_url())
    }

    #[tokio::test]
    async fn page_renders_form_with_return_to_and_no_store() {
        let ctx = ctx().await;
        let rt = authorize_url(&ctx);
        let resp = signin_page(
            State(ctx.clone()),
            HeaderMap::new(),
            Query(SigninPageQuery {
                return_to: Some(rt.clone()),
                login_hint: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
        let html = body(resp).await;
        assert!(html.contains(r#"name="identifier""#));
        assert!(html.contains(r#"name="password""#));
        assert!(html.contains(r#"action="/oauth/atproto/signin""#));
        assert!(html.contains(&html_escape(&rt)));
    }

    #[tokio::test]
    async fn offsite_return_to_falls_back_to_authorize_path() {
        let ctx = ctx().await;
        let resp = signin_page(
            State(ctx.clone()),
            HeaderMap::new(),
            Query(SigninPageQuery {
                return_to: Some("https://evil.example.com/steal".to_string()),
                login_hint: None,
            }),
        )
        .await;
        let html = body(resp).await;
        // The hidden field must be the local authorize URL, never the off-site one.
        assert!(html.contains(&format!("{}/oauth/atproto/authorize", ctx.service_url())));
        assert!(!html.contains("evil.example.com"));
    }

    #[tokio::test]
    async fn correct_password_mints_session_and_redirects_to_return_to() {
        let ctx = ctx().await;
        let did = "did:plc:signinadmin000000000000000";
        seed_account(&ctx, did, "admin.localhost", "correct-horse-battery-staple").await;
        let rt = authorize_url(&ctx);

        let resp = submit_signin(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SigninForm {
                identifier: Some("admin.localhost".to_string()),
                password: Some("correct-horse-battery-staple".to_string()),
                return_to: Some(rt.clone()),
                login_hint: None,
                auth_code: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap().to_str().unwrap(), rt);
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.contains(browser_session::SESSION_COOKIE));
        assert!(set_cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn fetch_mode_returns_204_with_cookie_and_no_redirect() {
        // The single-page admin login path: JS POSTs with Accept: application/json
        // and drives navigation itself, so success is 204 + Set-Cookie, never a
        // 302 (which a fetch would follow into the OAuth flow prematurely).
        let ctx = ctx().await;
        let did = "did:plc:signinadmin000000000000000";
        seed_account(&ctx, did, "admin.localhost", "correct-horse-battery-staple").await;

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        let resp = submit_signin(
            State(ctx.clone()),
            headers,
            Form(SigninForm {
                identifier: Some("admin.localhost".to_string()),
                password: Some("correct-horse-battery-staple".to_string()),
                return_to: None,
                login_hint: None,
                auth_code: None,
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            resp.headers().get(header::LOCATION).is_none(),
            "fetch mode must not redirect"
        );
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.contains(browser_session::SESSION_COOKIE));
        assert!(set_cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn wrong_password_is_uniform_401() {
        let ctx = ctx().await;
        let did = "did:plc:signinadmin000000000000000";
        seed_account(&ctx, did, "admin.localhost", "the-right-password").await;
        let resp = submit_signin(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SigninForm {
                identifier: Some("admin.localhost".to_string()),
                password: Some("the-WRONG-password".to_string()),
                return_to: Some(authorize_url(&ctx)),
                login_hint: None,
                auth_code: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body(resp).await.contains("Invalid handle or password"));
    }

    #[tokio::test]
    async fn unknown_identifier_is_uniform_401() {
        let ctx = ctx().await;
        let resp = submit_signin(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SigninForm {
                identifier: Some("ghost.localhost".to_string()),
                password: Some("whatever".to_string()),
                return_to: Some(authorize_url(&ctx)),
                login_hint: None,
                auth_code: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body(resp).await.contains("Invalid handle or password"));
    }

    /// #502: the account the client asked for is prefilled; a hint that
    /// names no account here is not shown at all.
    #[tokio::test]
    async fn the_requested_account_is_prefilled() {
        let ctx = ctx().await;
        let did = "did:plc:signinhint00000000000000";
        seed_account(&ctx, did, "hinted.localhost", "pw-hinted").await;
        let rt = authorize_url(&ctx);
        for (hint, shown) in [
            ("hinted.localhost", Some("hinted.localhost")),
            (did, Some(did)),
            ("nobody.localhost", None),
            ("\"><script>alert(1)</script>", None),
        ] {
            let resp = signin_page(
                State(ctx.clone()),
                HeaderMap::new(),
                Query(SigninPageQuery {
                    return_to: Some(rt.clone()),
                    login_hint: Some(hint.to_string()),
                }),
            )
            .await;
            let html = body(resp).await;
            assert!(!html.contains("<script>"), "{hint}");
            match shown {
                Some(value) => assert!(
                    html.contains(&format!(r#"name="identifier" value="{value}""#)),
                    "{hint}: {html}"
                ),
                None => assert!(
                    html.contains(r#"name="identifier" value="""#),
                    "{hint} must not be shown"
                ),
            }
        }
    }

    /// #502: a browser already signed in is told as whom, with a sign-out
    /// that comes back to this sign-in.
    #[tokio::test]
    async fn a_signed_in_browser_is_offered_sign_out() {
        let ctx = ctx().await;
        let did = "did:plc:signinsignedin00000000000";
        seed_account(&ctx, did, "already.localhost", "pw-already").await;
        let session = browser_session::create_session(&ctx.account_db, did, None, None)
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", browser_session::SESSION_COOKIE, session.id)
                .parse()
                .unwrap(),
        );
        let rt = authorize_url(&ctx);
        let resp = signin_page(
            State(ctx.clone()),
            headers,
            Query(SigninPageQuery {
                return_to: Some(rt.clone()),
                login_hint: None,
            }),
        )
        .await;
        let html = body(resp).await;
        assert!(html.contains("@already.localhost"), "{html}");
        assert!(html.contains(r#"action="/oauth/atproto/session/choose""#));
        assert!(html.contains(r#"value="signout""#));
        assert!(html.contains(&html_escape(&session.csrf_token)));
    }
}
