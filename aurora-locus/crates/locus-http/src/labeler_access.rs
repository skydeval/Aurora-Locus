//! Account creation for registered cairn labelers: a cairn listed in
//! `moderation.cairn_labelers` can create its labeler's account without an
//! invite code, up to its cap. The labeler's DID still proves it owns the
//! account, with the same service token `createAccount` takes for an
//! existing DID. After each account, Locus tells the cairn, so a cairn can
//! spot an account it didn't ask for.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use locus_core::locus_nsid;
use proto_blue_crypto::Keypair;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth;
use crate::error::{XrpcError, XrpcResult};
use crate::server::CreateAccountInput;
use crate::state::AppState;

type St = State<Arc<AppState>>;

pub const GET_ACCESS: &str = locus_nsid!("getLabelerAccess");
pub const CREATE_ACCOUNT: &str = locus_nsid!("createLabelerAccount");
/// What Locus calls on the cairn after creating an account for it.
pub const NOTIFY: &str = "tools.cairn.labeler.notifyAccountCreated";

/// The setting that lists registered cairn labelers: each item is a DID,
/// optionally followed by a space and its cap.
pub const SETTING: &str = "moderation.cairn_labelers";
/// A cairn's cap when its entry names none.
pub const DEFAULT_CAP: i64 = 5;
/// The audit action each account is logged under, and counted by.
pub const AUDIT_ACTION: &str = "labeler.createAccount";

/// Waits before each try at notifying a cairn, in seconds.
const NOTIFY_BACKOFF_S: &[u64] = &[0, 10, 60, 300, 1800, 3600];

/// One setting item as (DID, cap): `did:...` or `did:... 3`.
#[must_use]
pub fn parse_entry(item: &str) -> Option<(String, i64)> {
    let mut parts = item.split_whitespace();
    let did = parts.next()?;
    let cap = match parts.next() {
        None => DEFAULT_CAP,
        Some(n) => n.parse().ok().filter(|n: &i64| *n >= 0)?,
    };
    if parts.next().is_some() || !did.starts_with("did:") || did.contains('#') {
        return None;
    }
    Some((did.to_owned(), cap))
}

/// One setting item for (DID, cap); the default cap is left implicit.
#[must_use]
pub fn format_entry(did: &str, cap: i64) -> String {
    if cap == DEFAULT_CAP {
        did.to_owned()
    } else {
        format!("{did} {cap}")
    }
}

/// The moderation service DIDs whose console cards can register the cairn
/// they name.
pub const TRUST_KEYS: &[&str] = &["moderation.service_did", "moderation.report_service_did"];

/// Whether `did` is registered, and its cap (the default if it isn't).
#[must_use]
pub fn trust_of(
    snap: &locus_core::settings::Snapshot,
    did: &str,
) -> locus_web::console_pages::Trust {
    let found = snap
        .list(SETTING)
        .iter()
        .filter_map(|item| parse_entry(item))
        .find(|(d, _)| !did.is_empty() && d == did);
    locus_web::console_pages::Trust {
        on: found.is_some(),
        cap: found.map_or(DEFAULT_CAP, |(_, cap)| cap),
    }
}

/// The registered list after a moderation service DID's card is saved: the
/// card's DID goes from `old` to `new`, registered with `cap` or not at
/// all. The trust moves with the DID, so `old` is dropped too, unless
/// `keep` (another card still names it). Items that don't parse are kept.
#[must_use]
pub fn retrust(
    items: &[String],
    old: &str,
    new: &str,
    cap: Option<i64>,
    keep: bool,
) -> Vec<String> {
    let drop_old = old != new && !old.is_empty() && !keep;
    let cap = cap.filter(|_| !new.is_empty());
    let mut placed = false;
    let mut out: Vec<String> = items
        .iter()
        .filter_map(|item| match parse_entry(item) {
            Some((d, _)) if d == new => match cap {
                Some(cap) if !placed => {
                    placed = true;
                    Some(format_entry(new, cap))
                }
                _ => None,
            },
            Some((d, _)) if drop_old && d == old => None,
            _ => Some(item.clone()),
        })
        .collect();
    if let (Some(cap), false) = (cap, placed) {
        out.push(format_entry(new, cap));
    }
    out
}

/// The calling cairn's DID and cap, if its service token is good and it is
/// registered.
async fn registered(s: &AppState, headers: &HeaderMap, lxm: &str) -> XrpcResult<(String, i64)> {
    let did = auth::user_service_auth(s, headers, lxm).await?;
    let cap = s
        .snapshot()
        .list(SETTING)
        .iter()
        .filter_map(|item| parse_entry(item))
        .find(|(d, _)| *d == did)
        .map(|(_, cap)| cap);
    match cap {
        Some(cap) => Ok((did, cap)),
        None => Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "NotRegisteredLabeler",
            "This labeler isn't registered with this PDS",
        )),
    }
}

/// `getLabelerAccess`: whether the calling cairn is registered here, and
/// how many of its accounts are left.
pub async fn get_labeler_access(State(s): St, headers: HeaderMap) -> XrpcResult<Json<Value>> {
    let (cairn, cap) = registered(&s, &headers, GET_ACCESS).await?;
    let used = s.store.audit_count(&cairn, AUDIT_ACTION).await?;
    Ok(Json(json!({
        "registered": true,
        "cap": cap,
        "used": used,
        "handleDomains": s.handle_domains(),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLabelerAccountInput {
    did: Option<String>,
    handle: String,
    email: Option<String>,
    password: Option<String>,
    did_proof: Option<String>,
}

/// One creation at a time, so two at once can't both pass the cap.
static CREATING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `createLabelerAccount`: `createAccount` for an existing DID, with no
/// invite code. The account starts deactivated, as any account created for
/// an existing DID; the caller points the DID document here and activates it.
pub async fn create_labeler_account(
    State(s): St,
    headers: HeaderMap,
    Json(input): Json<CreateLabelerAccountInput>,
) -> XrpcResult<Json<Value>> {
    if s.role == locus_core::bootstrap::Role::Entryway {
        return Err(XrpcError::new(
            StatusCode::NOT_IMPLEMENTED,
            "MethodNotImplemented",
            "Create labeler accounts on a shard",
        ));
    }
    let (cairn, cap) = registered(&s, &headers, CREATE_ACCOUNT).await?;
    let did = input
        .did
        .filter(|d| !d.is_empty())
        .ok_or_else(|| XrpcError::invalid_request("did is required"))?;
    let bad_proof = |m: &str| XrpcError::new(StatusCode::UNAUTHORIZED, "InvalidDidProof", m);
    let proof = input
        .did_proof
        .filter(|p| !p.is_empty())
        .ok_or_else(|| bad_proof("didProof is required"))?;
    let bearer = HeaderValue::from_str(&format!("Bearer {proof}"))
        .map_err(|_| bad_proof("didProof isn't a token"))?;
    let mut proof_headers = HeaderMap::new();
    proof_headers.insert(header::AUTHORIZATION, bearer);

    let _one_at_a_time = CREATING.lock().await;
    if s.store.audit_count(&cairn, AUDIT_ACTION).await? >= cap {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "LabelerAccountCapReached",
            format!("This labeler has created its {cap} accounts here"),
        ));
    }
    let create = CreateAccountInput {
        email: input.email,
        handle: input.handle,
        did: Some(did.clone()),
        invite_code: None,
        password: input.password,
        recovery_key: None,
        locus_did_method: None,
        skip_invite: true,
    };
    // Any auth failure inside is the DID proof's: the cairn's token passed.
    let Json(session) =
        crate::server::create_account(State(Arc::clone(&s)), proof_headers, Json(create))
            .await
            .map_err(|e| {
                if e.status == StatusCode::UNAUTHORIZED {
                    bad_proof(&e.message)
                } else {
                    e
                }
            })?;
    let handle = session["handle"].as_str().unwrap_or_default().to_owned();
    // The cap counts these rows, so a failed write is an error.
    s.store
        .audit(
            &cairn,
            AUDIT_ACTION,
            Some(&did),
            Some(&json!({"handle": handle})),
        )
        .await?;
    drop(_one_at_a_time);

    let signing = s.signing_key(&did).await?;
    spawn_notify(
        Arc::clone(&s),
        cairn,
        json!({
            "did": did,
            "handle": handle,
            "createdAt": locus_core::time::iso8601(locus_core::time::now_ms()),
            "pds": s.public_url,
        }),
    );
    Ok(Json(json!({
        "did": did,
        "handle": handle,
        "accessJwt": session["accessJwt"],
        "refreshJwt": session["refreshJwt"],
        "signingKey": signing.did(),
        "pdsEndpoint": s.public_url,
    })))
}

/// Tells the cairn about a new account, retrying with backoff.
fn spawn_notify(s: Arc<AppState>, cairn: String, body: Value) {
    tokio::spawn(async move {
        for (attempt, wait) in NOTIFY_BACKOFF_S.iter().enumerate() {
            tokio::time::sleep(Duration::from_secs(*wait)).await;
            match notify_once(&s, &cairn, &body, attempt > 0).await {
                Ok(()) => return,
                Err(e) => tracing::warn!(cairn, attempt, "labeler account notice failed: {e}"),
            }
        }
        tracing::error!(cairn, did = %body["did"], "gave up telling the cairn about a new labeler account");
    });
}

async fn notify_once(s: &AppState, cairn: &str, body: &Value, fresh: bool) -> Result<(), String> {
    let doc = s
        .resolve_did_doc(cairn, fresh)
        .await
        .map_err(|e| e.message)?
        .ok_or("the cairn's DID doesn't resolve")?;
    let endpoint = proto_blue_common::did_doc::get_service_endpoint(&doc, "#atproto_labeler", None)
        .ok_or("the cairn's DID document has no #atproto_labeler service")?;
    let now = locus_core::time::now_ms() / 1000;
    let token = locus_auth::service_jwt::create(
        &s.secrets.service_key,
        &s.service_did,
        cairn,
        Some(now + 300),
        Some(NOTIFY),
        now,
    )
    .map_err(|e| e.to_string())?;
    let client = crate::pipethrough::client(s, true).map_err(|e| e.message)?;
    let res = client
        .post(format!("{}/xrpc/{NOTIFY}", endpoint.trim_end_matches('/')))
        .bearer_auth(token)
        .json(body)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("the cairn answered {}", res.status()))
    }
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            concat!("/xrpc/", locus_nsid!("getLabelerAccess")),
            get(get_labeler_access),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("createLabelerAccount")),
            post(create_labeler_account),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_name_a_did_and_maybe_a_cap() {
        assert_eq!(
            parse_entry("did:web:cairn.example"),
            Some(("did:web:cairn.example".into(), DEFAULT_CAP))
        );
        assert_eq!(
            parse_entry("  did:plc:abc   2 "),
            Some(("did:plc:abc".into(), 2))
        );
        for bad in [
            "",
            "cairn.example",
            "did:plc:abc -1",
            "did:plc:abc x",
            "did:plc:abc 1 2",
            "did:plc:abc#atproto_labeler",
        ] {
            assert_eq!(parse_entry(bad), None, "{bad}");
        }
        assert_eq!(format_entry("did:plc:abc", DEFAULT_CAP), "did:plc:abc");
        assert_eq!(format_entry("did:plc:abc", 9), "did:plc:abc 9");
    }

    #[test]
    fn a_card_moves_its_trust_with_its_did() {
        let items = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let list = items(&["did:web:a", "did:web:other 2", "not a did"]);
        // Checked, same DID, new cap: replaced where it was.
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:a", Some(3), false),
            items(&["did:web:a 3", "did:web:other 2", "not a did"])
        );
        // Checked, new DID: the old one's trust moves to it.
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:b", Some(5), false),
            items(&["did:web:other 2", "not a did", "did:web:b"])
        );
        // ...unless another card still names the old one.
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:b", Some(5), true),
            items(&["did:web:a", "did:web:other 2", "not a did", "did:web:b"])
        );
        // Unchecked: removed; other cairns stay.
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:a", None, false),
            items(&["did:web:other 2", "not a did"])
        );
        // An emptied card registers nothing.
        assert_eq!(
            retrust(&list, "did:web:a", "", Some(5), false),
            items(&["did:web:other 2", "not a did"])
        );
    }
}
