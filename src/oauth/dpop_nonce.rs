//! Server-issued DPoP nonces (RFC 9449 §8, §9; chainlink #486).
//!
//! A DPoP proof the client signs now must carry a `nonce` this server
//! issued, so a proof cannot be made ahead of time and replayed later. The
//! nonce is stateless: an HMAC of the current three-minute window under a key
//! derived from the server's secret. The current, previous and next windows
//! are accepted, so a nonce stays good for at least three minutes, survives a
//! restart, and agrees across instances that share the secret.
//!
//! Every response to a request that carried a DPoP proof includes the current
//! nonce in `DPoP-Nonce` ([`crate::api::middleware::dpop_nonce_header`]), so
//! clients stay primed. A proof without a valid nonce is refused with
//! `use_dpop_nonce`: HTTP 400 in the OAuth error body at the authorization
//! server's endpoints, HTTP 401 with `WWW-Authenticate: DPoP
//! error="use_dpop_nonce"` on API requests. Clients retry once with the nonce
//! from that answer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::context::AppContext;
use crate::error::{PdsError, PdsResult};

/// The header the nonce travels in, both ways.
pub const DPOP_NONCE_HEADER: &str = "dpop-nonce";

/// How long one nonce window lasts.
const WINDOW_SECS: i64 = 180;

/// The nonce of window `window` under `secret`.
fn nonce_for(secret: &str, window: i64) -> String {
    // HMAC accepts a key of any length, so construction cannot fail.
    let mut mac = Hmac::<Sha256>::new_from_slice(format!("dpop-nonce:{secret}").as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&window.to_be_bytes());
    URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes()[..18])
}

/// The window `unix_secs` falls in.
fn window_of(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(WINDOW_SECS)
}

/// The nonce to hand out now.
pub fn current(ctx: &AppContext) -> String {
    nonce_for(
        &ctx.config.authentication.jwt_secret,
        window_of(chrono::Utc::now().timestamp()),
    )
}

/// Whether `nonce` is one this server issued in the current window or one
/// either side of it.
pub fn is_valid(ctx: &AppContext, nonce: &str) -> bool {
    valid_at(
        &ctx.config.authentication.jwt_secret,
        nonce,
        chrono::Utc::now().timestamp(),
    )
}

fn valid_at(secret: &str, nonce: &str, unix_secs: i64) -> bool {
    let window = window_of(unix_secs);
    (window - 1..=window + 1).any(|w| nonce_for(secret, w) == nonce)
}

/// The `nonce` claim of a DPoP proof, if it has one. Reads the payload only:
/// call it after the proof's signature has been verified.
pub fn proof_nonce(proof: &str) -> Option<String> {
    let payload = proof.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("nonce")
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

/// Require a verified DPoP proof to carry a valid server nonce.
///
/// # Errors
///
/// [`PdsError::UseDpopNonce`] when the proof has no nonce, or one that is not
/// current.
pub fn require(ctx: &AppContext, proof: &str) -> PdsResult<()> {
    match proof_nonce(proof) {
        Some(nonce) if is_valid(ctx, &nonce) => Ok(()),
        _ => Err(PdsError::UseDpopNonce),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn a_nonce_is_good_in_its_window_and_the_ones_beside_it() {
        let now = 1_700_000_000;
        let nonce = nonce_for(SECRET, window_of(now));
        assert!(valid_at(SECRET, &nonce, now));
        assert!(valid_at(SECRET, &nonce, now + WINDOW_SECS));
        assert!(valid_at(SECRET, &nonce, now - WINDOW_SECS));
        assert!(!valid_at(SECRET, &nonce, now + 2 * WINDOW_SECS + WINDOW_SECS));
        assert!(!valid_at(SECRET, &nonce, now - 3 * WINDOW_SECS));
    }

    #[test]
    fn a_nonce_is_bound_to_the_secret() {
        let now = 1_700_000_000;
        let nonce = nonce_for(SECRET, window_of(now));
        assert!(!valid_at("another-secret", &nonce, now));
        assert!(!valid_at(SECRET, "made-up", now));
        assert!(!valid_at(SECRET, "", now));
    }

    #[test]
    fn the_nonce_claim_is_read_from_the_payload() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"jti":"x","nonce":"abc"}"#);
        assert_eq!(proof_nonce(&format!("h.{payload}.s")), Some("abc".to_string()));
        let without = URL_SAFE_NO_PAD.encode(br#"{"jti":"x"}"#);
        assert_eq!(proof_nonce(&format!("h.{without}.s")), None);
        assert_eq!(proof_nonce("not-a-jwt"), None);
    }
}
