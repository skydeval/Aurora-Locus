//! Verification of service-auth JWTs from other servers (cross-PDS requests).
//!
//! A peer (another PDS, an Aurora instance, a kryphocron service) calls this
//! PDS on a user's behalf with a short-lived JWT signed by that user's atproto
//! key: `iss` = the user's DID, `aud` = this service's DID, `lxm` = the method,
//! `exp`, and usually `iat` / `jti`.
//!
//! (#474) This used to decode with `jsonwebtoken` as ES256 (P-256) against a
//! PEM key, so it could never verify an atproto token (ES256K, or ES256 with a
//! multikey from the DID document). It now delegates to the one atproto
//! verifier, [`crate::service_auth::verify_service_jwt_for_method`], which
//! resolves the issuer's DID document, checks the signature strictly (compact,
//! low-S, either curve), and checks `aud`, `lxm` and the expiry window.
//!
//! References:
//! - https://atproto.com/specs/xrpc
//! - https://docs.bsky.app/docs/advanced-guides/service-auth

use crate::error::PdsResult;
use crate::identity::IdentityResolverApi;
use chrono::Utc;
use std::sync::Arc;
use tracing::debug;

/// A verified cross-PDS token, in the shape the auth call sites use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAuthClaims {
    /// Issuer: the user's DID.
    pub iss: String,
    /// Audience: this service's DID (possibly with a `#service` fragment).
    pub aud: String,
    /// Expiration time (Unix seconds).
    pub exp: i64,
    /// Issued-at (Unix seconds); the verification time when the token has
    /// none.
    pub iat: i64,
    /// The method the token was minted for, if any.
    pub lxm: Option<String>,
    /// Replay-prevention key: the token's `jti`, or, when it has none (the
    /// reference PDS omits it), the hex SHA-256 of the whole token, so the
    /// exact same token still cannot be replayed.
    pub jti: String,
}

/// Verifies service-auth JWTs from other servers.
pub struct ServiceAuthenticator {
    identity_resolver: Arc<dyn IdentityResolverApi>,
}

impl ServiceAuthenticator {
    /// Create an authenticator resolving issuers through `identity_resolver`.
    pub fn new(identity_resolver: Arc<dyn IdentityResolverApi>) -> Self {
        Self { identity_resolver }
    }

    /// Verify `token` for this service (`expected_audience`), for any method.
    pub async fn verify_service_jwt(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> PdsResult<ServiceAuthClaims> {
        self.verify_service_jwt_for_method(token, expected_audience, None)
            .await
    }

    /// Verify `token` for this service and, when `expected_lxm` is given, for
    /// exactly that method (the token's `lxm` must name it).
    pub async fn verify_service_jwt_for_method(
        &self,
        token: &str,
        expected_audience: &str,
        expected_lxm: Option<&str>,
    ) -> PdsResult<ServiceAuthClaims> {
        let claims = crate::service_auth::verify_service_jwt_for_method(
            token,
            expected_audience,
            expected_lxm,
            self.identity_resolver.as_ref(),
        )
        .await?;
        let jti = claims
            .jti
            .clone()
            .unwrap_or_else(|| proto_blue::crypto::sha256_hex(token.as_bytes()));
        debug!(iss = %claims.iss, lxm = ?claims.lxm, "cross-PDS service JWT verified");
        Ok(ServiceAuthClaims {
            iat: claims.iat.unwrap_or_else(|| Utc::now().timestamp()),
            iss: claims.iss,
            aud: claims.aud,
            exp: claims.exp,
            lxm: claims.lxm,
            jti,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did_document::{DidDocument, VerificationMethod};
    use crate::identity::resolver::test_doubles::MockIdentityResolver;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    const ISSUER: &str = "did:plc:peeruser";
    const SERVICE: &str = "did:web:pds.example.com";

    /// A resolver that knows `ISSUER` with `key`'s public half as #atproto.
    fn resolver_for(key: &SigningKey) -> Arc<MockIdentityResolver> {
        let did_key = crate::crypto::plc::PlcSigner::new(&key.to_bytes())
            .unwrap()
            .public_key_did_key();
        let multibase = did_key.strip_prefix("did:key:").unwrap().to_string();
        let resolver = Arc::new(MockIdentityResolver::new());
        resolver.script_did(
            ISSUER,
            DidDocument {
                context: None,
                id: ISSUER.to_string(),
                also_known_as: vec![],
                service: vec![],
                verification_method: vec![VerificationMethod {
                    id: format!("{ISSUER}#atproto"),
                    key_type: "Multikey".to_string(),
                    controller: ISSUER.to_string(),
                    public_key_multibase: Some(multibase),
                }],
            },
        );
        resolver
    }

    /// Hand-build a token with explicit claims and signature encoding.
    fn token(key: &SigningKey, claims: serde_json::Value, der: bool) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let input = format!("{header}.{body}");
        let sig: Signature = key.sign(input.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_bytes = if der {
            sig.to_der().as_bytes().to_vec()
        } else {
            sig.to_bytes().to_vec()
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig_bytes))
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    /// The #474 regression: a token minted the atproto way (here by this
    /// PDS's own minter, as a peer Aurora-Locus would) verifies.
    #[tokio::test]
    async fn verifies_an_atproto_minted_token() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let auth = ServiceAuthenticator::new(resolver_for(&key));
        let minted = crate::service_auth::create_service_jwt(
            ISSUER,
            SERVICE,
            None,
            Some("com.atproto.repo.getRecord"),
            &key.to_bytes(),
        )
        .unwrap();

        let claims = auth
            .verify_service_jwt_for_method(&minted, SERVICE, Some("com.atproto.repo.getRecord"))
            .await
            .expect("verifies");
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.lxm.as_deref(), Some("com.atproto.repo.getRecord"));
        assert!(!claims.jti.is_empty());
    }

    #[tokio::test]
    async fn checks_method_audience_and_signer() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let auth = ServiceAuthenticator::new(resolver_for(&key));
        let claims = serde_json::json!({
            "iss": ISSUER, "aud": SERVICE, "iat": now(), "exp": now() + 60,
            "lxm": "com.atproto.repo.getRecord", "jti": "n1"
        });
        let good = token(&key, claims, false);

        assert!(auth
            .verify_service_jwt_for_method(&good, SERVICE, Some("com.atproto.repo.putRecord"))
            .await
            .is_err());
        assert!(auth
            .verify_service_jwt(&good, "did:web:other.example")
            .await
            .is_err());

        let impostor = SigningKey::random(&mut rand::thread_rng());
        let forged = token(
            &impostor,
            serde_json::json!({"iss": ISSUER, "aud": SERVICE, "iat": now(), "exp": now() + 60}),
            false,
        );
        assert!(
            auth.verify_service_jwt(&forged, SERVICE).await.is_err(),
            "wrong key"
        );

        let expired = token(
            &key,
            serde_json::json!({"iss": ISSUER, "aud": SERVICE, "iat": now() - 120, "exp": now() - 60}),
            false,
        );
        assert!(
            auth.verify_service_jwt(&expired, SERVICE).await.is_err(),
            "expired"
        );
    }

    /// Reference-PDS-shaped tokens (no jti, aud with a service fragment) and
    /// legacy DER signatures from not-yet-updated Aurora peers are accepted.
    #[tokio::test]
    async fn accepts_reference_shapes_and_legacy_der() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let auth = ServiceAuthenticator::new(resolver_for(&key));

        let no_jti = token(
            &key,
            serde_json::json!({
                "iss": ISSUER, "aud": format!("{SERVICE}#atproto_pds"),
                "iat": now(), "exp": now() + 60
            }),
            false,
        );
        let claims = auth
            .verify_service_jwt(&no_jti, SERVICE)
            .await
            .expect("verifies");
        assert_eq!(
            claims.jti,
            proto_blue::crypto::sha256_hex(no_jti.as_bytes()),
            "replay key falls back to the token hash"
        );

        let legacy = token(
            &key,
            serde_json::json!({"iss": ISSUER, "aud": SERVICE, "iat": now(), "exp": now() + 60, "jti": "n2"}),
            true,
        );
        assert!(
            auth.verify_service_jwt(&legacy, SERVICE).await.is_ok(),
            "DER accepted"
        );
    }
}
