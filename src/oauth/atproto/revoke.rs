//! atproto-OAuth token revocation (RFC 7009; chainlink #503).
//!
//! `POST /oauth/atproto/revoke` lets a client end its own grant, typically
//! when its user signs out. The body is `token` (an access or a refresh token
//! of the grant) and `client_id`. A `token_type_hint` is not needed, since
//! both kinds are looked up, and is ignored like any other extra field. The
//! grant is marked revoked, which
//! stops its access token at once and refuses every later refresh — the same
//! revocation the holder's "Connected apps" page and device revocation use.
//!
//! As RFC 7009 §2.2 requires, the answer is 200 with an empty body whether or
//! not the token was found, so the endpoint reveals nothing about tokens it is
//! shown. A token is revoked only when the request's `client_id` is the client
//! the grant was issued to: the provider's clients are public, so the client is
//! identified, not authenticated, and possession of the token is what
//! authorizes ending it.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Form;
use chrono::Utc;
use serde::Deserialize;
use sqlx::Row;

use super::oauth_error_json;
use crate::context::AppContext;

/// The revocation request body (RFC 7009 §2.1).
#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    pub client_id: Option<String>,
}

/// `POST /oauth/atproto/revoke`
pub async fn revoke(State(ctx): State<AppContext>, Form(form): Form<RevokeForm>) -> Response {
    let Some(token) = form.token.as_deref().filter(|t| !t.is_empty()) else {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing required parameter: token",
        );
    };
    let Some(client_id) = form.client_id.as_deref().filter(|c| !c.is_empty()) else {
        return oauth_error_json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing required parameter: client_id",
        );
    };

    match revoke_grant(&ctx, token, client_id).await {
        Ok(_) => revoked_response(),
        Err(e) => oauth_error_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

/// Revoke the grant `token` belongs to, if it is live and was issued to
/// `client_id`. Returns whether a grant was revoked.
async fn revoke_grant(
    ctx: &AppContext,
    token: &str,
    client_id: &str,
) -> Result<bool, crate::error::PdsError> {
    let row = sqlx::query(
        "SELECT token_id, client_id FROM token \
         WHERE (access_token_hash = $1 OR current_refresh_token = $2) AND NOT revoked",
    )
    .bind(crate::oauth::access_token_hash(token))
    .bind(token)
    .fetch_optional(&ctx.account_db)
    .await
    .map_err(crate::error::PdsError::Database)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row.get::<String, _>("client_id") != client_id {
        return Ok(false);
    }
    let token_id: String = row.get("token_id");
    let revoked = sqlx::query(
        "UPDATE token SET revoked = TRUE, revoked_at = $1 WHERE token_id = $2 AND NOT revoked",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(&token_id)
    .execute(&ctx.account_db)
    .await
    .map_err(crate::error::PdsError::Database)?
    .rows_affected();
    Ok(revoked == 1)
}

/// RFC 7009 §2.2: 200, nothing to say.
fn revoked_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .body(axum::body::Body::empty())
        .expect("static header set builds a valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "https://app.example.com/cm.json";

    async fn ctx_with_grant() -> (AppContext, String, String) {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let account = ctx
            .account_manager
            .create_account("revoker.localhost".to_string(), None, "password123".to_string(), None, None)
            .await
            .expect("create account");
        let access = "at_revoketest".to_string();
        let refresh = "rt_revoketest".to_string();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO token (token_id, did, client_id, current_refresh_token, scope,
                                created_at, updated_at, expires_at, access_token_hash)
             VALUES ('tok-revoke', $1, $2, $3, 'atproto', $4, $4, $5, $6)",
        )
        .bind(&account.did)
        .bind(CLIENT)
        .bind(&refresh)
        .bind(&now)
        .bind((Utc::now() + chrono::Duration::days(90)).to_rfc3339())
        .bind(crate::oauth::access_token_hash(&access))
        .execute(&ctx.account_db)
        .await
        .expect("insert token");
        (ctx, access, refresh)
    }

    async fn call(ctx: &AppContext, token: &str, client_id: &str) -> Response {
        revoke(
            State(ctx.clone()),
            Form(RevokeForm {
                token: Some(token.to_string()),
                client_id: Some(client_id.to_string()),
            }),
        )
        .await
    }

    async fn is_revoked(ctx: &AppContext) -> bool {
        let row = sqlx::query("SELECT revoked FROM token WHERE token_id = 'tok-revoke'")
            .fetch_one(&ctx.account_db)
            .await
            .unwrap();
        crate::db::read_bool(&row, "revoked").unwrap()
    }

    #[tokio::test]
    async fn the_access_token_ends_the_grant() {
        let (ctx, access, refresh) = ctx_with_grant().await;
        assert_eq!(call(&ctx, &access, CLIENT).await.status(), StatusCode::OK);
        assert!(is_revoked(&ctx).await);
        assert!(crate::auth::validate_oauth_token(&ctx, &access).await.is_err());
        let manager = crate::oauth::token_rotation::TokenRotationManager::new(ctx.account_db.clone());
        assert!(manager.rotate_token(&refresh, CLIENT).await.is_err(), "no refresh after revoke");
    }

    #[tokio::test]
    async fn the_refresh_token_ends_the_grant() {
        let (ctx, access, refresh) = ctx_with_grant().await;
        assert_eq!(call(&ctx, &refresh, CLIENT).await.status(), StatusCode::OK);
        assert!(is_revoked(&ctx).await);
        assert!(crate::auth::validate_oauth_token(&ctx, &access).await.is_err());
    }

    #[tokio::test]
    async fn another_client_cannot_revoke_and_learns_nothing() {
        let (ctx, access, _) = ctx_with_grant().await;
        let resp = call(&ctx, &access, "https://other.example.com/cm.json").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!is_revoked(&ctx).await);
    }

    #[tokio::test]
    async fn an_unknown_token_is_answered_the_same() {
        let (ctx, _, _) = ctx_with_grant().await;
        let resp = call(&ctx, "at_nosuchtoken", CLIENT).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!is_revoked(&ctx).await);
    }

    #[tokio::test]
    async fn a_missing_token_or_client_is_invalid_request() {
        let (ctx, _, _) = ctx_with_grant().await;
        for (token, client_id) in [(None, Some(CLIENT)), (Some("at_x"), None)] {
            let resp = revoke(
                State(ctx.clone()),
                Form(RevokeForm {
                    token: token.map(str::to_string),
                        client_id: client_id.map(str::to_string),
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }
}
