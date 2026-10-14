//! Which account an authorization is for (chainlink #502).
//!
//! The authorize step binds a request to the account of the browser session.
//! A client may name the account it wants with `login_hint` (a handle or DID).
//! When the browser session holds another account, the request is not bound:
//! the resource owner sees [`render_switch_page`], naming both accounts, and
//! chooses to sign in as the requested account or to cancel. The same handler
//! ([`choose`]) serves "Not you? Switch account" on the consent page and
//! "Sign out" on the sign-in page.
//!
//! Every choice is a POST carrying the session's CSRF token. Signing out
//! returns to the sign-in page for the same authorization, never elsewhere.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use chrono::Utc;
use serde::Deserialize;

use super::browser_session::{self, BrowserSessionContext};
use super::html::html_escape;
use super::request_store;
use super::response::respond_to_client;
use crate::context::AppContext;
use crate::error::PdsError;

/// The DID of the local account a `login_hint` names, or `None` when it names
/// no account here. A DID names itself when an account with it exists; a
/// handle is resolved as `resolveHandle` would resolve it. Unknown hints are
/// ignored, so they reveal nothing beyond what handle resolution already does.
pub async fn resolve_hint(ctx: &AppContext, hint: &str) -> Option<String> {
    if hint.starts_with("did:") {
        // As handle resolution does: a taken-down account is not named.
        return match ctx.account_manager.get_account(hint).await {
            Ok(account) if account.takedown_ref.is_none() => Some(account.did),
            _ => None,
        };
    }
    let handle = hint.strip_prefix('@').unwrap_or(hint).to_ascii_lowercase();
    ctx.account_manager
        .get_resolvable_did_by_handle(&handle)
        .await
        .ok()
        .flatten()
}

/// How an account is named to the resource owner: `@handle (did)`, or the
/// DID alone when it has no handle. Not escaped; callers escape.
pub async fn account_label(ctx: &AppContext, did: &str) -> String {
    match ctx.account_manager.get_account(did).await {
        Ok(account) => match account.handle {
            Some(handle) => format!("@{handle} ({did})"),
            None => did.to_string(),
        },
        Err(_) => did.to_string(),
    }
}

/// The sign-in URL for an authorization, carrying the hint so the page can
/// prefill it. `return_to` must already be a validated authorize URL.
pub fn signin_url(ctx: &AppContext, return_to: &str, login_hint: Option<&str>) -> String {
    let mut url = format!(
        "{}/oauth/atproto/signin?return_to={}",
        ctx.service_url(),
        url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
    );
    if let Some(hint) = login_hint {
        url.push_str("&login_hint=");
        url.extend(url::form_urlencoded::byte_serialize(hint.as_bytes()));
    }
    url
}

/// Whether `return_to` is an authorize URL on this server. Anything else is
/// refused, so the choice handler cannot be used as an open redirector.
pub fn is_authorize_url(ctx: &AppContext, return_to: &str) -> bool {
    return_to.starts_with(&format!("{}/oauth/atproto/authorize", ctx.service_url()))
}

/// What the resource owner sees when the browser is signed in as one account
/// and the client asked for another. Nothing has been bound; the request
/// waits for the choice. Every interpolated value is escaped.
pub fn render_switch_page(
    request_id: &str,
    csrf_token: &str,
    client_name: &str,
    requested: &str,
    signed_in: &str,
    return_to: &str,
) -> Response {
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Choose account</title>
</head>
<body>
  <main>
    <h1>Which account?</h1>
    <p><strong>{client_name}</strong> asked to sign in as <strong>{requested}</strong>.</p>
    <p>You are signed in as <strong>{signed_in}</strong>.</p>
    <form method="post" action="/oauth/atproto/session/choose" style="display:inline">
      <input type="hidden" name="request_id" value="{request_id}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="return_to" value="{return_to}">
      <button type="submit" name="action" value="switch">Sign in as {requested}</button>
      <button type="submit" name="action" value="cancel">Cancel</button>
    </form>
  </main>
</body>
</html>"#,
        client_name = html_escape(client_name),
        requested = html_escape(requested),
        signed_in = html_escape(signed_in),
        request_id = html_escape(request_id),
        csrf_token = html_escape(csrf_token),
        return_to = html_escape(return_to),
    );
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Html(body),
    )
        .into_response()
}

/// The choice form: posted from the switch page, the consent page's
/// "Not you?" control, or the sign-in page's "Sign out".
#[derive(Debug, Deserialize)]
pub struct ChoiceForm {
    pub csrf_token: String,
    /// `switch` / `signout` (end this browser session and sign in again for
    /// the same authorization) or `cancel` (refuse the authorization).
    pub action: String,
    /// The authorization the choice is about. Absent for a plain sign-out
    /// from the sign-in page.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The authorize URL to come back to after signing in again.
    #[serde(default)]
    pub return_to: Option<String>,
    /// The account to prefill on the sign-in page, when no request is named
    /// (the sign-in page's own "Sign out").
    #[serde(default)]
    pub login_hint: Option<String>,
}

/// `POST /oauth/atproto/session/choose`
pub async fn choose(
    session: BrowserSessionContext,
    State(ctx): State<AppContext>,
    Form(form): Form<ChoiceForm>,
) -> Response {
    if form.csrf_token != session.session.csrf_token {
        return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
    }
    let request = match form.request_id.as_deref() {
        Some(id) => match request_store::get_by_request_id(&ctx.account_db, id).await {
            Ok(Some(request)) => Some(request),
            Ok(None) => {
                return (StatusCode::NOT_FOUND, "unknown authorization request").into_response()
            }
            Err(e) => return internal(e),
        },
        None => None,
    };

    match form.action.as_str() {
        "switch" | "signout" => {
            let return_to = form
                .return_to
                .as_deref()
                .filter(|url| is_authorize_url(&ctx, url))
                .map(str::to_string)
                .unwrap_or_else(|| format!("{}/oauth/atproto/authorize", ctx.service_url()));
            // A request this session had bound, with no code minted yet, is
            // released, so the account that signs in next can take it.
            // Otherwise "Not you?" would lead back only to the account the
            // resource owner just said was not them.
            if let Some(request) = &request {
                if let Err(e) =
                    request_store::unbind(&ctx.account_db, &request.request_id, &session.session.did)
                        .await
                {
                    return internal(e);
                }
            }
            if let Err(e) = browser_session::delete_session(&ctx.account_db, &session.session.id).await
            {
                return internal(e);
            }
            let form_hint = super::params::normalize_login_hint(form.login_hint.as_deref());
            let hint = request
                .as_ref()
                .and_then(|r| r.login_hint.as_deref())
                .or(form_hint.as_deref());
            (
                [(header::SET_COOKIE, browser_session::clear_session_cookie())],
                Redirect::to(&signin_url(&ctx, &return_to, hint)),
            )
                .into_response()
        }
        "cancel" => {
            let Some(request) = request else {
                return (StatusCode::BAD_REQUEST, "no authorization request to cancel")
                    .into_response();
            };
            // A request bound to another account is not this session's to
            // cancel.
            if request
                .did
                .as_deref()
                .is_some_and(|did| did != session.session.did)
            {
                return (
                    StatusCode::FORBIDDEN,
                    "session does not match this authorization request",
                )
                    .into_response();
            }
            if request.is_expired(Utc::now()) || request.code_is_used() || request.is_denied() {
                return (StatusCode::BAD_REQUEST, "authorization request is no longer open")
                    .into_response();
            }
            if let Err(e) = request_store::mark_denied(
                &ctx.account_db,
                &request.request_id,
                &Utc::now().to_rfc3339(),
            )
            .await
            {
                return internal(e);
            }
            let mut pairs: Vec<(&str, &str)> = vec![
                ("error", "access_denied"),
                (
                    "error_description",
                    "The account holder cancelled the sign-in",
                ),
            ];
            if let Some(state) = request.state.as_deref() {
                pairs.push(("state", state));
            }
            respond_to_client(
                &request.redirect_uri,
                request.response_mode(),
                &ctx.service_url(),
                &pairs,
            )
        }
        _ => (StatusCode::BAD_REQUEST, "unknown action").into_response(),
    }
}

fn internal(e: PdsError) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}


#[cfg(test)]
mod tests {
    //! #502: the account-choice handler.
    use super::*;
    use super::super::request_store::AtprotoAuthorizationRequest;

    async fn ctx() -> AppContext {
        crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await
    }

    async fn bound_request(ctx: &AppContext, did: &str) -> String {
        let id = super::super::opaque_token();
        let now = Utc::now();
        request_store::insert(
            &ctx.account_db,
            &AtprotoAuthorizationRequest {
                request_id: id.clone(),
                request_uri: Some(format!("urn:ietf:params:oauth:request_uri:{id}")),
                client_id: "https://app.example.com/cm.json".to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "atproto".to_string(),
                state: Some("st".to_string()),
                code_challenge: "chal".to_string(),
                code_challenge_method: "S256".to_string(),
                did: Some(did.to_string()),
                code_hash: None,
                code_used_at: None,
                denied_at: None,
                created_at: now.to_rfc3339(),
                expires_at: (now + chrono::Duration::minutes(10)).to_rfc3339(),
                response_mode: None,
                login_hint: None,
            },
        )
        .await
        .unwrap();
        id
    }

    async fn post(ctx: &AppContext, did: &str, action: &str, request_id: Option<String>) -> Response {
        let session = browser_session::create_session(&ctx.account_db, did, None, None)
            .await
            .unwrap();
        let csrf = session.csrf_token.clone();
        choose(
            BrowserSessionContext { session },
            State(ctx.clone()),
            Form(ChoiceForm {
                csrf_token: csrf,
                action: action.to_string(),
                request_id,
                return_to: Some(format!("{}/oauth/atproto/authorize?request_uri=x", ctx.service_url())),
                login_hint: None,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn switching_away_releases_the_request_for_the_next_account() {
        let ctx = ctx().await;
        let id = bound_request(&ctx, "did:plc:alice").await;
        let resp = post(&ctx, "did:plc:alice", "switch", Some(id.clone())).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.contains("/oauth/atproto/signin?return_to="), "{location}");
        let set_cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(set_cookie.contains("Max-Age=0") || set_cookie.contains("Expires"), "{set_cookie}");
        let row = request_store::get_by_request_id(&ctx.account_db, &id).await.unwrap().unwrap();
        assert!(row.did.is_none(), "the next account can take the request");
    }

    #[tokio::test]
    async fn another_accounts_request_is_neither_released_nor_cancelled() {
        let ctx = ctx().await;
        let id = bound_request(&ctx, "did:plc:alice").await;
        let _ = post(&ctx, "did:plc:mallory", "switch", Some(id.clone())).await;
        let row = request_store::get_by_request_id(&ctx.account_db, &id).await.unwrap().unwrap();
        assert_eq!(row.did.as_deref(), Some("did:plc:alice"));
        let resp = post(&ctx, "did:plc:mallory", "cancel", Some(id.clone())).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cancel_returns_access_denied_to_the_client() {
        let ctx = ctx().await;
        let id = bound_request(&ctx, "did:plc:alice").await;
        let resp = post(&ctx, "did:plc:alice", "cancel", Some(id.clone())).await;
        let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.starts_with("https://app.example.com/cb?"), "{location}");
        assert!(location.contains("error=access_denied") && location.contains("state=st"));
        let row = request_store::get_by_request_id(&ctx.account_db, &id).await.unwrap().unwrap();
        assert!(row.is_denied());
    }

    #[tokio::test]
    async fn a_wrong_csrf_token_changes_nothing() {
        let ctx = ctx().await;
        let id = bound_request(&ctx, "did:plc:alice").await;
        let session = browser_session::create_session(&ctx.account_db, "did:plc:alice", None, None)
            .await
            .unwrap();
        let resp = choose(
            BrowserSessionContext { session },
            State(ctx.clone()),
            Form(ChoiceForm {
                csrf_token: "forged".to_string(),
                action: "switch".to_string(),
                request_id: Some(id.clone()),
                return_to: None,
                login_hint: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let row = request_store::get_by_request_id(&ctx.account_db, &id).await.unwrap().unwrap();
        assert_eq!(row.did.as_deref(), Some("did:plc:alice"));
    }
}
