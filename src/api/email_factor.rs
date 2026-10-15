//! Email two-factor sign-in (`emailAuthFactor`; chainlink #503).
//!
//! An account can ask that signing in with its password also needs a
//! one-time code sent to its email address. The setting is
//! `com.atproto.server.updateEmail`'s `emailAuthFactor` (it needs a confirmed
//! email address and an email server, so the account cannot lock itself out),
//! and `getSession` reports it.
//!
//! [`require_sign_in_code`] is the one check, used by `createSession` and by
//! the OAuth sign-in page. Without a code it sends one and answers
//! `AuthFactorTokenRequired`; with a code it uses it up or answers
//! `InvalidToken`. App passwords are not affected, as on the reference PDS.

use chrono::Duration;
use rand::Rng;

use crate::{
    context::AppContext,
    db::account::ActorAccount,
    error::{PdsError, PdsResult},
};

/// How long a sign-in code works.
pub const CODE_VALID_MINUTES: i64 = 15;

/// The code alphabet: base32 capitals and digits, easy to read and type.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new sign-in code, `XXXXX-XXXXX` (50 bits).
pub fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let mut part = || -> String {
        (0..5)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect()
    };
    let first = part();
    let second = part();
    format!("{first}-{second}")
}

/// A code as typed, in the form it is stored: trimmed and upper-case.
pub fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

/// Enforce the email factor for a password sign-in of `account` (#503).
///
/// - The factor is off: `Ok`.
/// - No code was given: a code is issued and emailed, and the answer is
///   `AuthFactorTokenRequired`.
/// - A code was given: it is used up and the answer is `Ok`, or it is not the
///   account's current code and the answer is `InvalidToken`.
///
/// # Errors
///
/// As above, or a failure to store or send the code. A code that cannot be
/// sent fails the sign-in: the factor is never skipped.
pub async fn require_sign_in_code(
    ctx: &AppContext,
    account: &ActorAccount,
    presented: Option<&str>,
) -> PdsResult<()> {
    if !ctx.account_manager.email_auth_factor(&account.did).await? {
        return Ok(());
    }
    match presented.map(normalize_code).filter(|c| !c.is_empty()) {
        Some(code) => {
            if ctx
                .account_manager
                .consume_sign_in_code(&account.did, &code)
                .await?
            {
                Ok(())
            } else {
                Err(PdsError::InvalidAuthFactorToken)
            }
        }
        None => {
            send_sign_in_code(ctx, account).await?;
            Err(PdsError::AuthFactorTokenRequired)
        }
    }
}

/// Issue a sign-in code for `account` and email it.
async fn send_sign_in_code(ctx: &AppContext, account: &ActorAccount) -> PdsResult<()> {
    let email = account.email.as_deref().ok_or_else(|| {
        PdsError::Internal("the account has no email address for its sign-in code".to_string())
    })?;
    let code = generate_code();
    ctx.account_manager
        .issue_sign_in_code(&account.did, &code, Duration::minutes(CODE_VALID_MINUTES))
        .await?;
    ctx.mailer
        .send_sign_in_code_email(
            email,
            account.handle.as_deref().unwrap_or(&account.did),
            &code,
            CODE_VALID_MINUTES,
        )
        .await
}

/// Whether `emailAuthFactor` may be turned on for `account`: it needs a
/// confirmed email address and a configured email server, or the account
/// could not sign in again.
pub fn can_enable(ctx: &AppContext, account: &ActorAccount) -> PdsResult<()> {
    if account.email.is_none() || account.email_confirmed_at.is_none() {
        return Err(PdsError::Validation(
            "emailAuthFactor needs a confirmed email address".to_string(),
        ));
    }
    if !ctx.mailer.is_configured() {
        return Err(PdsError::Validation(
            "emailAuthFactor is unavailable: this server cannot send email".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_the_expected_shape() {
        for _ in 0..50 {
            let code = generate_code();
            assert_eq!(code.len(), 11, "{code}");
            assert_eq!(&code[5..6], "-");
            assert!(code
                .chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8))));
        }
        assert_ne!(generate_code(), generate_code());
    }

    #[test]
    fn typed_codes_are_normalized() {
        assert_eq!(normalize_code(" abcde-fghij \n"), "ABCDE-FGHIJ");
    }

    async fn ctx_with_account() -> (AppContext, ActorAccount) {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let account = ctx
            .account_manager
            .create_account(
                "factor.localhost".to_string(),
                Some("factor@example.com".to_string()),
                "password123".to_string(),
                None,
                None,
            )
            .await
            .expect("create account");
        (ctx, account)
    }

    #[tokio::test]
    async fn without_the_factor_nothing_is_asked() {
        let (ctx, account) = ctx_with_account().await;
        require_sign_in_code(&ctx, &account, None)
            .await
            .expect("no factor");
    }

    #[tokio::test]
    async fn a_code_works_once_and_only_the_newest() {
        let (ctx, account) = ctx_with_account().await;
        ctx.account_manager
            .set_email_auth_factor(&account.did, true)
            .await
            .unwrap();
        let ttl = Duration::minutes(CODE_VALID_MINUTES);
        ctx.account_manager
            .issue_sign_in_code(&account.did, "AAAAA-AAAAA", ttl)
            .await
            .unwrap();
        ctx.account_manager
            .issue_sign_in_code(&account.did, "BBBBB-BBBBB", ttl)
            .await
            .unwrap();

        let err = require_sign_in_code(&ctx, &account, Some("aaaaa-aaaaa"))
            .await
            .expect_err("a withdrawn code");
        assert!(matches!(err, PdsError::InvalidAuthFactorToken), "{err:?}");
        require_sign_in_code(&ctx, &account, Some(" bbbbb-bbbbb "))
            .await
            .expect("the newest code, as typed");
        let err = require_sign_in_code(&ctx, &account, Some("BBBBB-BBBBB"))
            .await
            .expect_err("used once already");
        assert!(matches!(err, PdsError::InvalidAuthFactorToken), "{err:?}");
    }

    #[tokio::test]
    async fn an_expired_code_does_not_work() {
        let (ctx, account) = ctx_with_account().await;
        ctx.account_manager
            .set_email_auth_factor(&account.did, true)
            .await
            .unwrap();
        ctx.account_manager
            .issue_sign_in_code(&account.did, "CCCCC-CCCCC", Duration::minutes(-1))
            .await
            .unwrap();
        let err = require_sign_in_code(&ctx, &account, Some("CCCCC-CCCCC"))
            .await
            .expect_err("expired");
        assert!(matches!(err, PdsError::InvalidAuthFactorToken), "{err:?}");
    }

    #[tokio::test]
    async fn without_a_code_one_is_asked_for_and_never_skipped() {
        let (ctx, account) = ctx_with_account().await;
        ctx.account_manager
            .set_email_auth_factor(&account.did, true)
            .await
            .unwrap();
        // The test server has no email configured: the code cannot be sent,
        // and the sign-in fails rather than going on without it.
        let err = require_sign_in_code(&ctx, &account, None)
            .await
            .expect_err("no code");
        assert!(
            matches!(err, PdsError::AuthFactorTokenRequired | PdsError::Internal(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn enabling_needs_a_confirmed_email_and_a_mail_server() {
        let (ctx, account) = ctx_with_account().await;
        let err = can_enable(&ctx, &account).expect_err("unconfirmed");
        assert!(matches!(err, PdsError::Validation(_)));
    }
}
