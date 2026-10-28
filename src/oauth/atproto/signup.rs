//! Sign up during an OAuth authorization (`prompt=create`; chainlink #503).
//!
//! A client that asks for `prompt=create` wants its user to make a new account
//! on this PDS and come back signed in to it. The authorize step sends the
//! browser here with `return_to` (the authorize URL) and, when the client gave
//! one that is not taken, the `login_hint` as the suggested handle. The form
//! creates the account exactly as `com.atproto.server.createAccount` does
//! ([`crate::api::server::provision_account`]: invite code, repository,
//! firehose announcements, verification email), starts a
//! browser session for it, marks the request's prompt as acted on, and returns
//! to the authorize URL, which goes on to the consent page for the new account.
//!
//! `return_to` is validated to be an authorize URL on this server, as on the
//! sign-in page. Account creation is rate-limited per client IP, as
//! `createAccount` is.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use super::browser_session;
use super::html::html_escape;
use crate::context::AppContext;

/// The sign-up page's query.
#[derive(Debug, Deserialize)]
pub struct SignupPageQuery {
    #[serde(default)]
    pub return_to: Option<String>,
    /// A handle to suggest.
    #[serde(default)]
    pub login_hint: Option<String>,
}

/// The sign-up form body.
#[derive(Debug, Deserialize)]
pub struct SignupForm {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub invite_code: Option<String>,
    #[serde(default)]
    pub return_to: Option<String>,
}

/// The sign-up URL for an authorization.
pub fn signup_url(ctx: &AppContext, return_to: &str, suggested_handle: Option<&str>) -> String {
    let mut url = format!(
        "{}/oauth/atproto/signup?return_to={}",
        ctx.service_url(),
        url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
    );
    if let Some(handle) = suggested_handle {
        url.push_str("&login_hint=");
        url.extend(url::form_urlencoded::byte_serialize(handle.as_bytes()));
    }
    url
}

/// `GET /oauth/atproto/signup`
pub async fn signup_page(State(ctx): State<AppContext>, Query(q): Query<SignupPageQuery>) -> Response {
    let return_to = sanitize_return_to(&ctx, q.return_to.as_deref());
    let suggested = suggested_handle(&ctx, q.login_hint.as_deref()).await;
    page(&ctx, StatusCode::OK, &return_to, &SignupValues {
        handle: suggested.unwrap_or_default(),
        ..SignupValues::default()
    }, None)
}

/// `POST /oauth/atproto/signup`
pub async fn submit_signup(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Response {
    let return_to = sanitize_return_to(&ctx, form.return_to.as_deref());
    let values = SignupValues {
        handle: form.handle.as_deref().unwrap_or_default().trim().to_ascii_lowercase(),
        email: form.email.as_deref().unwrap_or_default().trim().to_string(),
        invite_code: form.invite_code.as_deref().unwrap_or_default().trim().to_string(),
    };
    let password = form.password.unwrap_or_default();

    if let Some(ip) = crate::rate_limit::extract_client_ip(&headers) {
        if ctx.rate_limiter.check_ip(&ip).is_err() {
            return page(
                &ctx,
                StatusCode::TOO_MANY_REQUESTS,
                &return_to,
                &values,
                Some("Too many attempts. Please wait a few minutes and try again."),
            );
        }
    }
    if values.handle.is_empty() || password.is_empty() {
        return page(
            &ctx,
            StatusCode::BAD_REQUEST,
            &return_to,
            &values,
            Some("A handle and a password are required."),
        );
    }

    let account = match crate::api::server::provision_account(
        &ctx,
        values.handle.clone(),
        Some(values.email.clone()).filter(|e| !e.is_empty()),
        password,
        Some(values.invite_code.clone()).filter(|c| !c.is_empty()),
        None,
    )
    .await
    {
        Ok(account) => account,
        // The account could not be created: say why. These messages are about
        // what the person typed (a handle in use, an invalid invite code), the
        // same answers createAccount gives.
        Err(e) => {
            return page(
                &ctx,
                StatusCode::BAD_REQUEST,
                &return_to,
                &values,
                Some(&e.to_string()),
            )
        }
    };

    // The new account is the one signed in now: any earlier browser session
    // ends (session fixation), and the request's prompt has been acted on.
    if let Some(old) = browser_session::read_session_cookie(&headers) {
        let _ = browser_session::delete_session(&ctx.account_db, &old).await;
    }
    if let Some(request_uri) = request_uri_of(&return_to) {
        if let Err(e) = super::request_store::clear_prompt(&ctx.account_db, &request_uri).await {
            tracing::warn!(error = %e, "signup: request prompt not cleared");
        }
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let session = match browser_session::create_session(&ctx.account_db, &account.did, user_agent, None).await {
        Ok(session) => session,
        // The account exists; only the automatic sign-in failed.
        Err(_) => {
            return redirect_with(
                None,
                &super::account_choice::signin_url(&ctx, &return_to, account.handle.as_deref()),
            )
        }
    };
    redirect_with(Some(browser_session::set_session_cookie(&session.id)), &return_to)
}

fn redirect_with(cookie: Option<axum::http::HeaderValue>, to: &str) -> Response {
    match cookie {
        Some(cookie) => ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response(),
        None => Redirect::to(to).into_response(),
    }
}

/// The `request_uri` of an authorize URL, if it names a pushed request.
pub fn request_uri_of(authorize_url: &str) -> Option<String> {
    url::Url::parse(authorize_url)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == "request_uri")
        .map(|(_, value)| value.into_owned())
}

/// A `login_hint` worth suggesting as the new handle: a syntactically valid
/// handle that no account here already has. Anything else (a DID, a taken
/// handle, a string a handle cannot be) suggests nothing.
async fn suggested_handle(ctx: &AppContext, hint: Option<&str>) -> Option<String> {
    let hint = super::params::normalize_login_hint(hint)?;
    let handle = hint.strip_prefix('@').unwrap_or(&hint).to_ascii_lowercase();
    if !proto_blue::syntax::Handle::is_valid(&handle) {
        return None;
    }
    match super::account_choice::resolve_hint(ctx, &handle).await {
        Some(_) => None,
        None => Some(handle),
    }
}

fn sanitize_return_to(ctx: &AppContext, return_to: Option<&str>) -> String {
    match return_to {
        Some(url) if super::account_choice::is_authorize_url(ctx, url) => url.to_string(),
        _ => format!("{}/oauth/atproto/authorize", ctx.service_url()),
    }
}

/// What the person typed, kept when the form is shown again.
#[derive(Debug, Default)]
struct SignupValues {
    handle: String,
    email: String,
    invite_code: String,
}

/// Render the sign-up form. Every interpolated value is escaped.
fn page(
    ctx: &AppContext,
    status: StatusCode,
    return_to: &str,
    values: &SignupValues,
    error: Option<&str>,
) -> Response {
    let error_html = error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, html_escape(e)))
        .unwrap_or_default();
    let domains = ctx.config.identity.service_handle_domains.join(", ");
    let invite_html = if ctx.config.invites.required {
        format!(
            r#"<label>Invite code<br>
        <input type="text" name="invite_code" value="{}" autocomplete="off" required>
      </label><br>"#,
            html_escape(&values.invite_code)
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Create account</title>
</head>
<body>
  <main>
    <h1>Create an account</h1>
    {error_html}
    <form method="post" action="/oauth/atproto/signup">
      <input type="hidden" name="return_to" value="{return_to}">
      <label>Handle<br>
        <input type="text" name="handle" value="{handle}" autocomplete="username" autofocus required>
      </label><br>
      <small>Your handle ends in one of: {domains}</small><br>
      <label>Email<br>
        <input type="email" name="email" value="{email}" autocomplete="email">
      </label><br>
      <label>Password<br>
        <input type="password" name="password" autocomplete="new-password" required>
      </label><br>
      {invite_html}
      <button type="submit">Create account</button>
    </form>
    <p><a href="{signin}">I already have an account</a></p>
  </main>
</body>
</html>"#,
        error_html = error_html,
        return_to = html_escape(return_to),
        handle = html_escape(&values.handle),
        email = html_escape(&values.email),
        domains = html_escape(&domains),
        invite_html = invite_html,
        signin = html_escape(&super::account_choice::signin_url(ctx, return_to, None)),
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

    async fn body(resp: Response) -> String {
        String::from_utf8(to_bytes(resp.into_body(), 64 * 1024).await.unwrap().to_vec()).unwrap()
    }

    fn return_to(ctx: &AppContext) -> String {
        format!(
            "{}/oauth/atproto/authorize?client_id=x&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc",
            ctx.service_url()
        )
    }

    #[tokio::test]
    async fn the_page_suggests_an_untaken_handle_only() {
        let ctx = ctx().await;
        ctx.account_manager
            .create_account("taken.localhost".to_string(), None, "password123".to_string(), None, None)
            .await
            .unwrap();
        for (hint, shown) in [
            ("newname.localhost", "newname.localhost"),
            ("taken.localhost", ""),
            ("did:plc:abc", ""),
            ("<b>x.localhost", ""),
        ] {
            let resp = signup_page(
                State(ctx.clone()),
                Query(SignupPageQuery {
                    return_to: Some(return_to(&ctx)),
                    login_hint: Some(hint.to_string()),
                }),
            )
            .await;
            let html = body(resp).await;
            assert!(!html.contains("<b>"), "{hint}");
            if shown.is_empty() {
                assert!(html.contains(r#"name="handle" value="""#), "{hint}");
            } else {
                assert!(html.contains(&format!(r#"name="handle" value="{shown}""#)), "{hint}");
            }
        }
    }

    #[tokio::test]
    async fn a_new_account_lands_on_the_authorize_url_with_a_session() {
        let ctx = ctx().await;
        let rt = return_to(&ctx);
        let resp = submit_signup(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SignupForm {
                // Typed with capitals: handles are stored lower-case.
                handle: Some("Landed.localhost".to_string()),
                email: None,
                password: Some("a-long-password".to_string()),
                invite_code: None,
                return_to: Some(rt.clone()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap().to_str().unwrap(), rt);
        let cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains(browser_session::SESSION_COOKIE));
        let did = ctx
            .account_manager
            .get_resolvable_did_by_handle("landed.localhost")
            .await
            .unwrap()
            .expect("account created");
        assert!(ctx.actor_store.exists(&did).await, "repository created");
    }

    #[tokio::test]
    async fn a_taken_handle_is_refused_and_the_form_kept() {
        let ctx = ctx().await;
        ctx.account_manager
            .create_account("dupe.localhost".to_string(), None, "password123".to_string(), None, None)
            .await
            .unwrap();
        let resp = submit_signup(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SignupForm {
                handle: Some("dupe.localhost".to_string()),
                email: Some("keep@example.com".to_string()),
                password: Some("a-long-password".to_string()),
                invite_code: None,
                return_to: Some(return_to(&ctx)),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let html = body(resp).await;
        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains(r#"value="keep@example.com""#));
    }

    #[tokio::test]
    async fn an_invite_is_asked_for_when_required() {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|c| c.invites.required = true)
                .await;
        let resp = signup_page(
            State(ctx.clone()),
            Query(SignupPageQuery {
                return_to: None,
                login_hint: None,
            }),
        )
        .await;
        assert!(body(resp).await.contains(r#"name="invite_code""#));
        let resp = submit_signup(
            State(ctx.clone()),
            HeaderMap::new(),
            Form(SignupForm {
                handle: Some("noinvite.localhost".to_string()),
                email: None,
                password: Some("a-long-password".to_string()),
                invite_code: None,
                return_to: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_request_uri_is_read_from_the_authorize_url() {
        assert_eq!(
            request_uri_of("https://pds.example/oauth/atproto/authorize?client_id=x&request_uri=urn%3Aa%3Ab"),
            Some("urn:a:b".to_string())
        );
        assert_eq!(request_uri_of("https://pds.example/oauth/atproto/authorize?client_id=x"), None);
    }
}
