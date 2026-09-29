//! `app.bsky.actor.getPreferences` / `putPreferences` (#470).
//!
//! Served by the PDS from `account_pref`, never proxied: preferences belong to
//! the account, and the reference PDS keeps them locally for the same reason.
//! Accepts any account session (password, app password or OAuth); app-password
//! sessions can neither see nor set full-access-only preferences. An OAuth
//! client needs permission to call the method on the AppView, as the reference
//! PDS requires (`transition:generic` includes it).

use crate::{
    api::{middleware::AccountAuth, service_proxy},
    context::AppContext,
    error::PdsResult,
};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

/// The namespace these endpoints manage.
const NAMESPACE: &str = "app.bsky";

/// Preference routes.
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route("/xrpc/app.bsky.actor.getPreferences", get(get_preferences))
        .route("/xrpc/app.bsky.actor.putPreferences", post(put_preferences))
}

/// `{preferences: [...]}` — the shape of both the getPreferences output and
/// the putPreferences input.
#[derive(Debug, Serialize, Deserialize)]
pub struct Preferences {
    /// Preference objects, each carrying its `$type`.
    pub preferences: Vec<serde_json::Value>,
}

/// For an OAuth client, require permission to call `lxm` on the AppView.
async fn require_permission(ctx: &AppContext, auth: &AccountAuth, lxm: &str) -> PdsResult<()> {
    if auth.oauth_scopes.is_none() {
        return Ok(());
    }
    // Without an AppView only a permission for any service can match.
    let aud = service_proxy::appview_service(ctx)
        .await
        .unwrap_or_default();
    auth.require_rpc(lxm, &aud)
}

async fn get_preferences(
    State(ctx): State<AppContext>,
    auth: AccountAuth,
) -> PdsResult<Json<Preferences>> {
    require_permission(&ctx, &auth, "app.bsky.actor.getPreferences").await?;
    let preferences = ctx
        .account_manager
        .get_preferences(&auth.did, NAMESPACE, auth.full_access)
        .await?;
    Ok(Json(Preferences { preferences }))
}

async fn put_preferences(
    State(ctx): State<AppContext>,
    auth: AccountAuth,
    Json(body): Json<Preferences>,
) -> PdsResult<()> {
    require_permission(&ctx, &auth, "app.bsky.actor.putPreferences").await?;
    ctx.account_manager
        .put_preferences(&auth.did, NAMESPACE, body.preferences, auth.full_access)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PdsError;
    use axum::extract::FromRequestParts;
    use serde_json::json;

    async fn ctx_with_account() -> (AppContext, String) {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let account = ctx
            .account_manager
            .create_account(
                "prefs.localhost".to_string(),
                None,
                "password123".to_string(),
                None,
                None,
            )
            .await
            .unwrap();
        (ctx, account.did)
    }

    /// Run a bearer token through the real `AccountAuth` extractor.
    async fn auth_from_token(ctx: &AppContext, token: &str) -> PdsResult<AccountAuth> {
        let (mut parts, _) = axum::http::Request::builder()
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap()
            .into_parts();
        AccountAuth::from_request_parts(&mut parts, ctx).await
    }

    fn prefs(values: Vec<serde_json::Value>) -> Json<Preferences> {
        Json(Preferences {
            preferences: values,
        })
    }

    async fn stored(ctx: &AppContext, auth: &AccountAuth) -> Vec<serde_json::Value> {
        get_preferences(State(ctx.clone()), auth.clone())
            .await
            .unwrap()
            .0
            .preferences
    }

    /// The bsky.app password-login case (#470): a createSession access JWT is
    /// accepted, and preferences round-trip in order.
    #[tokio::test]
    async fn session_jwt_round_trips_preferences_in_order() {
        let (ctx, did) = ctx_with_account().await;
        let session = ctx
            .account_manager
            .create_session(&did, None)
            .await
            .unwrap();
        let auth = auth_from_token(&ctx, &session.access_token)
            .await
            .expect("session JWT accepted");
        assert_eq!(auth.did, did);
        assert!(auth.full_access);

        assert!(stored(&ctx, &auth).await.is_empty());
        let values = vec![
            json!({"$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": []}),
            json!({"$type": "app.bsky.actor.defs#adultContentPref", "enabled": false}),
        ];
        put_preferences(State(ctx.clone()), auth.clone(), prefs(values.clone()))
            .await
            .unwrap();
        assert_eq!(stored(&ctx, &auth).await, values);

        // A second put replaces, not appends.
        let replacement =
            vec![json!({"$type": "app.bsky.actor.defs#threadViewPref", "sort": "newest"})];
        put_preferences(State(ctx.clone()), auth.clone(), prefs(replacement.clone()))
            .await
            .unwrap();
        assert_eq!(stored(&ctx, &auth).await, replacement);
    }

    #[tokio::test]
    async fn app_password_sessions_cannot_see_or_set_personal_details() {
        let (ctx, did) = ctx_with_account().await;
        let full = auth_from_token(
            &ctx,
            &ctx.account_manager
                .create_session(&did, None)
                .await
                .unwrap()
                .access_token,
        )
        .await
        .unwrap();
        ctx.account_manager
            .create_app_password(&did, "phone", false)
            .await
            .unwrap();
        let app = auth_from_token(
            &ctx,
            &ctx.account_manager
                .create_session(&did, Some("phone".to_string()))
                .await
                .unwrap()
                .access_token,
        )
        .await
        .unwrap();
        assert!(!app.full_access);

        let personal = json!({"$type": "app.bsky.actor.defs#personalDetailsPref", "birthDate": "2000-01-01T00:00:00Z"});
        let feeds = json!({"$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": []});
        put_preferences(
            State(ctx.clone()),
            full.clone(),
            prefs(vec![personal.clone(), feeds.clone()]),
        )
        .await
        .unwrap();

        // Hidden from the app password…
        assert_eq!(stored(&ctx, &app).await, vec![feeds.clone()]);
        // …which cannot set it…
        let err = put_preferences(
            State(ctx.clone()),
            app.clone(),
            prefs(vec![personal.clone()]),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PdsError::Authorization(_)), "{err:?}");
        // …and whose puts leave it in place.
        let muted = json!({"$type": "app.bsky.actor.defs#mutedWordsPref", "items": []});
        put_preferences(State(ctx.clone()), app.clone(), prefs(vec![muted.clone()]))
            .await
            .unwrap();
        assert_eq!(stored(&ctx, &full).await, vec![personal, muted]);
    }

    #[tokio::test]
    async fn preferences_must_be_typed_and_in_namespace() {
        let (ctx, did) = ctx_with_account().await;
        let auth = auth_from_token(
            &ctx,
            &ctx.account_manager
                .create_session(&did, None)
                .await
                .unwrap()
                .access_token,
        )
        .await
        .unwrap();
        for bad in [
            json!({"enabled": true}),
            json!({"$type": ""}),
            json!({"$type": "com.example.pref"}),
            json!({"$type": "app.bskyx.fake#pref"}),
        ] {
            let err = put_preferences(State(ctx.clone()), auth.clone(), prefs(vec![bad.clone()]))
                .await
                .unwrap_err();
            assert!(matches!(err, PdsError::Validation(_)), "{bad}: {err:?}");
        }
        assert!(stored(&ctx, &auth).await.is_empty(), "nothing written");
    }

    #[tokio::test]
    async fn missing_or_bad_token_is_rejected() {
        let (ctx, _) = ctx_with_account().await;
        assert!(auth_from_token(&ctx, "not-a-token").await.is_err());
        let (mut parts, _) = axum::http::Request::builder()
            .body(())
            .unwrap()
            .into_parts();
        assert!(AccountAuth::from_request_parts(&mut parts, &ctx)
            .await
            .is_err());
    }

    fn oauth_auth(did: &str, scope: &str) -> AccountAuth {
        AccountAuth {
            did: did.to_string(),
            full_access: true,
            privileged: true,
            oauth_scopes: Some(crate::oauth::atproto::scope::ScopeSet::from_granted(scope)),
        }
    }

    /// An OAuth client needs a grant that covers preferences (#478).
    #[tokio::test]
    async fn oauth_clients_need_a_scope_covering_preferences() {
        let (ctx, did) = ctx_with_account().await;

        let base_only = oauth_auth(&did, "atproto");
        assert!(matches!(
            get_preferences(State(ctx.clone()), base_only.clone()).await,
            Err(PdsError::Authorization(_))
        ));
        assert!(matches!(
            put_preferences(State(ctx.clone()), base_only, prefs(vec![])).await,
            Err(PdsError::Authorization(_))
        ));

        let generic = oauth_auth(&did, "atproto transition:generic");
        let values =
            vec![json!({"$type": "app.bsky.actor.defs#adultContentPref", "enabled": false})];
        put_preferences(State(ctx.clone()), generic.clone(), prefs(values.clone()))
            .await
            .expect("transition:generic covers putPreferences");
        assert_eq!(stored(&ctx, &generic).await, values);

        // A granular grant for any service covers the one method it names.
        let granular = oauth_auth(&did, "atproto rpc:app.bsky.actor.getPreferences?aud=*");
        assert_eq!(stored(&ctx, &granular).await, values);
        assert!(matches!(
            put_preferences(State(ctx.clone()), granular, prefs(vec![])).await,
            Err(PdsError::Authorization(_))
        ));
    }
}
