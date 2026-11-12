//! Account creation for registered cairn labelers: a cairn listed in
//! `moderation.cairn_labelers` can create its labeler's account without an
//! invite code, up to its cap. The labeler's DID still proves it owns the
//! account, with the same service token `createAccount` takes for an
//! existing DID. After each account, Locus tells the cairn, so a cairn can
//! spot an account it didn't ask for.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
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
pub const DELETE_ACCOUNT: &str = locus_nsid!("deleteLabelerAccount");
/// The audit action each deletion is logged under.
pub const DELETE_AUDIT_ACTION: &str = "labeler.deleteAccount";
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

/// A registered cairn: its DID, its cap, and the key its tokens must be
/// signed with, once pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub did: String,
    pub cap: i64,
    /// A `did:key`. Until one is pinned, tokens are checked against the
    /// DID document's `#atproto_label` key.
    pub key: Option<String>,
}

/// One setting item: the DID, then optionally its cap and its pinned
/// `did:key`, space-separated (`did:web:c`, `did:web:c 3`,
/// `did:web:c 3 did:key:z...`).
#[must_use]
pub fn parse_entry(item: &str) -> Option<Entry> {
    let mut parts = item.split_whitespace();
    let did = parts.next()?;
    if !did.starts_with("did:") || did.starts_with("did:key:") || did.contains('#') {
        return None;
    }
    let mut entry = Entry {
        did: did.to_owned(),
        cap: DEFAULT_CAP,
        key: None,
    };
    let mut cap_seen = false;
    for part in parts {
        if let Some(k) = part.strip_prefix("did:key:") {
            if entry.key.is_some() || k.is_empty() {
                return None;
            }
            entry.key = Some(part.to_owned());
        } else {
            let n: i64 = part.parse().ok().filter(|n: &i64| *n >= 0)?;
            if cap_seen {
                return None;
            }
            cap_seen = true;
            entry.cap = n;
        }
    }
    Some(entry)
}

/// One setting item for an entry; the default cap is left implicit.
#[must_use]
pub fn format_entry(e: &Entry) -> String {
    let mut out = e.did.clone();
    if e.cap != DEFAULT_CAP || e.key.is_some() {
        out.push_str(&format!(" {}", e.cap));
    }
    if let Some(k) = &e.key {
        out.push_str(&format!(" {k}"));
    }
    out
}

/// Whether `k` is a `did:key` (secp256k1 or P-256) a cairn can pin.
#[must_use]
pub fn valid_key(k: &str) -> bool {
    proto_blue_crypto::parse_did_key(k).is_ok()
}

/// Refuses a registered list with an item that doesn't read as an entry, or
/// a key that isn't a `did:key` (it would silently unregister that cairn).
pub fn check_list(value: &Value) -> Result<(), String> {
    for item in value.as_array().into_iter().flatten() {
        let text = item.as_str().unwrap_or_default();
        match parse_entry(text) {
            None => return Err(format!("\"{text}\" isn't a DID, then a cap and a did:key")),
            Some(Entry { key: Some(k), .. }) if !valid_key(&k) => {
                return Err(format!("{k} isn't a secp256k1 or P-256 did:key"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The registered entry for `did`, if any.
#[must_use]
pub fn entry_for(snap: &locus_core::settings::Snapshot, did: &str) -> Option<Entry> {
    snap.list(SETTING)
        .iter()
        .filter_map(|item| parse_entry(item))
        .find(|e| !did.is_empty() && e.did == did)
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
    let found = entry_for(snap, did);
    locus_web::console_pages::Trust {
        on: found.is_some(),
        cap: found.map_or(DEFAULT_CAP, |e| e.cap),
    }
}

/// The registered list after a moderation service DID's card is saved: the
/// card's DID goes from `old` to `new`, registered with `cap` or not at
/// all. The trust moves with the DID, so `old` is dropped too, unless
/// `keep` (another card still names it). Items that don't parse are kept,
/// and a DID that stays keeps its pinned key (a new DID starts with none).
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
            Some(e) if e.did == new => match cap {
                Some(cap) if !placed => {
                    placed = true;
                    Some(format_entry(&Entry { cap, ..e }))
                }
                _ => None,
            },
            Some(e) if drop_old && e.did == old => None,
            _ => Some(item.clone()),
        })
        .collect();
    if let (Some(cap), false) = (cap, placed) {
        out.push(format_entry(&Entry {
            did: new.to_owned(),
            cap,
            key: None,
        }));
    }
    out
}

/// The longest a trust-link token may live, in seconds.
const MAX_TOKEN_S: i64 = 300;

/// base64url (no padding) SHA-256 of a request body, as `bodyHash`.
#[must_use]
pub fn body_hash(body: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(body))
}

/// A JSON request body, read after its hash was checked.
fn json_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> XrpcResult<T> {
    serde_json::from_slice(body)
        .map_err(|e| XrpcError::invalid_request(format!("Invalid request body: {e}")))
}

fn unauthorized(name: &str, message: &str) -> XrpcError {
    XrpcError::new(StatusCode::UNAUTHORIZED, name, message)
}

/// The calling cairn's entry, if its token is good and it is registered.
///
/// A cairn with a pinned key signs as its bare DID with that key, and every
/// POST carries `bodyHash`; its DID document is never read. Until a key is
/// pinned, the token's `iss` is `<did>#atproto_labeler`, checked against
/// the document's `#atproto_label` key, and `bodyHash` is checked when
/// present. `needs_key`: the method only serves a pinned cairn
/// (`KeyNotPinned` otherwise). Every token is single-use and lives at most
/// five minutes. `body` is the POST body (None for a GET).
async fn cairn_auth(
    s: &AppState,
    headers: &HeaderMap,
    lxm: &str,
    body: Option<&[u8]>,
    needs_key: bool,
) -> XrpcResult<Entry> {
    use locus_auth::service_jwt;
    let token = auth::bearer(headers)?;
    let now = locus_core::time::now_ms() / 1000;
    let jwt = service_jwt::parse(token, Some(lxm), now)
        .map_err(|e| unauthorized(e.name(), &e.to_string()))?;
    if !jwt.lifetime_ok(now) || jwt.exp - now > MAX_TOKEN_S + service_jwt::SKEW_S {
        return Err(unauthorized(
            "BadJwt",
            "jwt lifetime is longer than five minutes",
        ));
    }
    let Some(jti) = jwt.jti.clone() else {
        return Err(unauthorized("BadJwt", "jwt has no jti"));
    };
    let did = jwt.iss.split('#').next().unwrap_or_default();
    let Some(entry) = entry_for(&s.snapshot(), did) else {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "NotRegisteredLabeler",
            "This labeler isn't registered with this PDS",
        ));
    };
    let bad_iss = || unauthorized("BadJwtIss", "jwt iss is not this cairn's");
    let bad_sig = || unauthorized("BadJwtSignature", "jwt signature does not match jwt issuer");
    match &entry.key {
        Some(key) => {
            if jwt.iss != entry.did {
                return Err(bad_iss());
            }
            if !jwt.verifies_with(key) {
                return Err(bad_sig());
            }
        }
        None => {
            if needs_key {
                return Err(XrpcError::new(
                    StatusCode::FORBIDDEN,
                    "KeyNotPinned",
                    "This cairn has no key pinned here yet",
                ));
            }
            if jwt.iss != format!("{}#atproto_labeler", entry.did) {
                return Err(bad_iss());
            }
            let mut verified = false;
            for force in [false, true] {
                let Some(doc) = s.resolve_did_doc(&entry.did, force).await? else {
                    return Err(XrpcError::auth_required("could not resolve iss did"));
                };
                let key =
                    proto_blue_common::did_doc::get_verification_material(&doc, "atproto_label")
                        .map(|k| format!("did:key:{}", k.public_key_multibase));
                if key.is_some_and(|k| jwt.verifies_with(&k)) {
                    verified = true;
                    break;
                }
            }
            if !verified {
                return Err(bad_sig());
            }
        }
    }
    if !s.accepts_aud(&jwt.aud) {
        return Err(unauthorized(
            "BadJwtAudience",
            "jwt audience does not match service did",
        ));
    }
    if let Some(body) = body {
        let ok = match &jwt.body_hash {
            Some(h) => *h == body_hash(body),
            None => entry.key.is_none(),
        };
        if !ok {
            return Err(unauthorized(
                "BadJwtBodyHash",
                "jwt bodyHash does not match the request body",
            ));
        }
    }
    let ttl = (jwt.exp - now + service_jwt::SKEW_S).max(1) * 1000;
    if !s
        .unique(&format!("ServiceAuth@{}", jwt.iss), &jti, ttl)
        .await?
    {
        return Err(unauthorized("BadJwt", "jwt replayed"));
    }
    Ok(entry)
}

/// `getLabelerAccess`: whether the calling cairn is registered here, and
/// how many of its accounts are left.
pub async fn get_labeler_access(State(s): St, headers: HeaderMap) -> XrpcResult<Json<Value>> {
    let Entry {
        did: cairn, cap, ..
    } = cairn_auth(&s, &headers, GET_ACCESS, None, false).await?;
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
    body: Bytes,
) -> XrpcResult<Json<Value>> {
    if s.role == locus_core::bootstrap::Role::Entryway {
        return Err(XrpcError::new(
            StatusCode::NOT_IMPLEMENTED,
            "MethodNotImplemented",
            "Create labeler accounts on a shard",
        ));
    }
    let Entry {
        did: cairn, cap, ..
    } = cairn_auth(&s, &headers, CREATE_ACCOUNT, Some(&body), false).await?;
    let input: CreateLabelerAccountInput = json_body(&body)?;
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
        // Managed accounts have no password: no one signs in to them.
        password: None,
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
    // Locked to the cairn from the start; the session below is for
    // activateAccount only, and ends when the account is activated.
    s.store.set_managed(&did, &cairn).await?;
    drop(_one_at_a_time);

    let signing = s.signing_key(&did).await?;
    spawn_notify(
        Arc::clone(&s),
        cairn,
        NOTIFY,
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

#[derive(Deserialize)]
pub struct DeleteLabelerAccountInput {
    did: String,
}

/// `deleteLabelerAccount`: deletes an account this cairn created here, as
/// `deleteAccount` does (repo, blobs, sessions, `#account deleted`), with
/// no password or email token: the cairn's registration stands in for
/// them. 404 `AccountNotFound` once it's gone, so a retry is safe.
pub async fn delete_labeler_account(
    State(s): St,
    headers: HeaderMap,
    body: Bytes,
) -> XrpcResult<Json<Value>> {
    if s.role == locus_core::bootstrap::Role::Entryway {
        return Err(XrpcError::new(
            StatusCode::NOT_IMPLEMENTED,
            "MethodNotImplemented",
            "Delete labeler accounts on a shard",
        ));
    }
    let Entry { did: cairn, .. } =
        cairn_auth(&s, &headers, DELETE_ACCOUNT, Some(&body), false).await?;
    let input: DeleteLabelerAccountInput = json_body(&body)?;
    if !s.store.audit_has(&cairn, AUDIT_ACTION, &input.did).await? {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "NotCreatedByThisCairn",
            "This labeler didn't create that account here",
        ));
    }
    if crate::admin::any_account(&s, &input.did).await?.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            "Account not found",
        ));
    }
    let job = crate::account::start_deletion(&s, &input.did).await?;
    crate::account::spawn_deletion(&s, job);
    s.store.oauth_delete_account_tokens(&input.did).await?;
    s.store.release_managed(&input.did).await?;
    s.store
        .audit(&cairn, DELETE_AUDIT_ACTION, Some(&input.did), None)
        .await?;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------- managed accounts

/// What every way into a managed account answers.
#[must_use]
pub fn managed_error() -> XrpcError {
    XrpcError::new(
        StatusCode::BAD_REQUEST,
        "AccountManaged",
        "This account is managed by its cairn and can't be signed in to",
    )
}

/// Refuses when a cairn manages `did`.
pub async fn refuse_managed(s: &AppState, did: &str) -> XrpcResult<()> {
    if s.store.managed_by(did).await?.is_some() {
        return Err(managed_error());
    }
    Ok(())
}

/// Ends every way `did` is signed in: sessions (app passwords' too) and
/// OAuth tokens.
pub async fn end_sessions(s: &AppState, did: &str) -> XrpcResult<()> {
    let mut tx = s.store.begin().await?;
    tx.revoke_sessions(did, locus_store::accounts::SessionFilter::All)
        .await?;
    tx.commit().await?;
    s.store.oauth_delete_account_tokens(did).await?;
    Ok(())
}

pub const PUT_RECORD: &str = locus_nsid!("putLabelerRecord");
pub const DELETE_RECORD: &str = locus_nsid!("deleteLabelerRecord");
pub const UPLOAD_BLOB: &str = locus_nsid!("uploadLabelerBlob");
pub const MANAGE: &str = locus_nsid!("admin.manageLabelerAccount");
pub const RELEASE: &str = locus_nsid!("admin.releaseLabelerAccount");
/// What Locus calls on the cairn after each write to an account it manages.
pub const NOTIFY_WRITTEN: &str = "tools.cairn.labeler.notifyRecordWritten";
/// What Locus calls on the cairn when an operator releases its account.
pub const NOTIFY_RELEASED: &str = "tools.cairn.labeler.notifyAccountReleased";
/// The only records a cairn writes, each at `self`.
pub const WRITABLE: &[&str] = &[
    "app.bsky.labeler.service",
    "app.bsky.actor.profile",
    REASON_SET,
];
/// A moderation labeler's report reasons. Its lexicon is cairn's, so Locus
/// checks only its `$type` and size.
pub const REASON_SET: &str = "tools.cairn.report.reasonSet";
/// The largest reason set, as JSON.
const MAX_REASON_SET_BYTES: usize = 64 * 1024;
/// The largest image a cairn uploads.
pub const MAX_BLOB_BYTES: u64 = 1_000_000;

/// The account `did` if `cairn` manages it, active or not as `active` asks.
async fn managed_target(
    s: &AppState,
    cairn: &str,
    did: &str,
    active: bool,
) -> XrpcResult<locus_store::accounts::Account> {
    if s.store.managed_by(did).await?.as_deref() != Some(cairn) {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "NotManagedByThisCairn",
            "This cairn doesn't manage that account here",
        ));
    }
    auth::account_checked(s, did, active).await
}

fn writable(collection: &str, rkey: &str) -> XrpcResult<()> {
    if !WRITABLE.contains(&collection) {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "CollectionNotAllowed",
            format!("A cairn writes only {}", WRITABLE.join(" and ")),
        ));
    }
    if rkey != "self" {
        return Err(XrpcError::invalid_request("The record key is self"));
    }
    Ok(())
}

/// Tells the cairn about a write it made (or one it should know of).
fn notify_written(s: &Arc<AppState>, cairn: String, body: Value) {
    spawn_notify(Arc::clone(s), cairn, NOTIFY_WRITTEN, body);
}

fn now_iso() -> String {
    locus_core::time::iso8601(locus_core::time::now_ms())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutLabelerRecordInput {
    did: String,
    collection: String,
    rkey: String,
    record: Value,
    /// Absent: no check; `null`: the record must not exist yet; a CID: the
    /// record must be that one.
    #[serde(default, deserialize_with = "present")]
    swap_record: Option<Value>,
}

/// A field that was sent, even as `null` (absent stays `None`).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// `putLabelerRecord`: the labeler service, profile or report-reason record
/// of an account this cairn manages, validated against its lexicon (the
/// reason set by its type and size).
pub async fn put_labeler_record(
    State(s): St,
    headers: HeaderMap,
    body: Bytes,
) -> XrpcResult<Json<Value>> {
    let Entry { did: cairn, .. } = cairn_auth(&s, &headers, PUT_RECORD, Some(&body), true).await?;
    let input: PutLabelerRecordInput = json_body(&body)?;
    writable(&input.collection, &input.rkey)?;
    let reasons = input.collection == REASON_SET;
    if reasons
        && (input.record["$type"] != REASON_SET
            || input.record.to_string().len() > MAX_REASON_SET_BYTES)
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRecord",
            "A reason set is a tools.cairn.report.reasonSet of at most 64 KB",
        ));
    }
    let account = managed_target(&s, &cairn, &input.did, true).await?;
    let put = crate::repo::PutRecordInput {
        repo: account.did.clone(),
        collection: input.collection.clone(),
        rkey: input.rkey.clone(),
        // Locus has no lexicon for the reason set: it's checked above.
        validate: if reasons { None } else { Some(true) },
        record: input.record,
        swap_record: input.swap_record,
        swap_commit: None,
    };
    let Json(out) = crate::repo::put_record_for(&s, &account, &put).await?;
    notify_written(
        &s,
        cairn,
        json!({"did": account.did, "op": "put", "collection": input.collection,
               "rkey": input.rkey, "cid": out["cid"], "at": now_iso()}),
    );
    Ok(Json(json!({"uri": out["uri"], "cid": out["cid"]})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteLabelerRecordInput {
    did: String,
    collection: String,
    rkey: String,
    swap_record: Option<String>,
}

/// `deleteLabelerRecord`: removes one of those records.
pub async fn delete_labeler_record(
    State(s): St,
    headers: HeaderMap,
    body: Bytes,
) -> XrpcResult<Json<Value>> {
    let Entry { did: cairn, .. } =
        cairn_auth(&s, &headers, DELETE_RECORD, Some(&body), true).await?;
    let input: DeleteLabelerRecordInput = json_body(&body)?;
    writable(&input.collection, &input.rkey)?;
    let account = managed_target(&s, &cairn, &input.did, true).await?;
    let del = crate::repo::DeleteRecordInput {
        repo: account.did.clone(),
        collection: input.collection.clone(),
        rkey: input.rkey.clone(),
        swap_record: input.swap_record,
        swap_commit: None,
    };
    let _ = crate::repo::delete_record_for(&s, &account, &del).await?;
    notify_written(
        &s,
        cairn,
        json!({"did": account.did, "op": "delete", "collection": input.collection,
               "rkey": input.rkey, "at": now_iso()}),
    );
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
pub struct UploadLabelerBlobParams {
    did: String,
}

/// `uploadLabelerBlob?did=`: a PNG or JPEG image, at most a megabyte, for an
/// account this cairn manages (an avatar or banner); 30 an hour per account.
pub async fn upload_labeler_blob(
    State(s): St,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<UploadLabelerBlobParams>,
    body: Bytes,
) -> XrpcResult<Json<Value>> {
    let Entry { did: cairn, .. } = cairn_auth(&s, &headers, UPLOAD_BLOB, Some(&body), true).await?;
    let account = managed_target(&s, &cairn, &p.did, false).await?;
    if body.len() as u64 > MAX_BLOB_BYTES {
        return Err(XrpcError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BlobTooLarge",
            "An image is at most 1,000,000 bytes",
        ));
    }
    let mime = locus_blob::mime_type(&body, None);
    if mime != "image/png" && mime != "image/jpeg" {
        return Err(XrpcError::invalid_request("Only PNG and JPEG images"));
    }
    crate::ratelimit::limit_always(
        &s,
        &[(
            crate::ratelimit::buckets::LABELER_BLOB_HOUR,
            &account.did,
            1,
        )],
    )
    .await?;
    let Json(out) = crate::repo::store_blob(
        &s,
        &account.did,
        Some(&mime),
        axum::body::Body::from(body),
        MAX_BLOB_BYTES,
    )
    .await?;
    notify_written(
        &s,
        cairn,
        json!({"did": account.did, "op": "blob", "cid": out["blob"]["ref"]["$link"],
               "at": now_iso()}),
    );
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct AccountInput {
    did: String,
}

/// An operator call for the managing methods (admins only).
async fn admin_op(
    s: &AppState,
    headers: &HeaderMap,
    lxm: &str,
) -> XrpcResult<crate::admin_auth::Caller> {
    crate::admin_auth::require(
        s,
        headers,
        lxm,
        crate::admin_auth::Surface::Locus,
        crate::admin_auth::Role::Admin,
    )
    .await
}

/// `admin.manageLabelerAccount`: locks an account a cairn created to that
/// cairn (an account from before managed accounts existed). Every session
/// ends.
pub async fn manage_labeler_account(
    State(s): St,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> XrpcResult<Json<Value>> {
    let who = admin_op(&s, &headers, MANAGE).await?;
    let Some(cairn) = s.store.audit_actor(AUDIT_ACTION, &input.did).await? else {
        return Err(XrpcError::invalid_request(
            "No cairn created that account here",
        ));
    };
    crate::admin::any_account(&s, &input.did)
        .await?
        .ok_or_else(|| XrpcError::invalid_request("Account not found"))?;
    s.store.set_managed(&input.did, &cairn).await?;
    end_sessions(&s, &input.did).await?;
    crate::admin_auth::audit(
        &s,
        &who,
        "labeler.manage",
        Some(&input.did),
        Some(json!({"cairn": cairn})),
    )
    .await;
    Ok(Json(json!({"did": input.did, "cairn": cairn})))
}

/// `admin.releaseLabelerAccount`: unlocks a managed account. It has no
/// password until an operator sets one (or its email resets it); its cairn
/// is told.
pub async fn release_labeler_account(
    State(s): St,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> XrpcResult<Json<Value>> {
    let who = admin_op(&s, &headers, RELEASE).await?;
    let Some(cairn) = s.store.managed_by(&input.did).await? else {
        return Err(XrpcError::invalid_request("That account isn't managed"));
    };
    s.store.release_managed(&input.did).await?;
    crate::admin_auth::audit(
        &s,
        &who,
        "labeler.release",
        Some(&input.did),
        Some(json!({"cairn": cairn})),
    )
    .await;
    spawn_notify(
        Arc::clone(&s),
        cairn.clone(),
        NOTIFY_RELEASED,
        json!({"did": input.did, "at": now_iso()}),
    );
    Ok(Json(json!({"did": input.did, "cairn": cairn})))
}

/// Tells the cairn something through its `nsid` (a new account, a write,
/// a release), retrying with backoff.
fn spawn_notify(s: Arc<AppState>, cairn: String, nsid: &'static str, body: Value) {
    tokio::spawn(async move {
        for (attempt, wait) in NOTIFY_BACKOFF_S.iter().enumerate() {
            tokio::time::sleep(Duration::from_secs(*wait)).await;
            match notify_once(&s, &cairn, nsid, &body, attempt > 0).await {
                Ok(()) => return,
                Err(e) => tracing::warn!(cairn, nsid, attempt, "labeler notice failed: {e}"),
            }
        }
        tracing::error!(cairn, nsid, did = %body["did"], "gave up telling the cairn");
    });
}

async fn notify_once(
    s: &AppState,
    cairn: &str,
    nsid: &str,
    body: &Value,
    fresh: bool,
) -> Result<(), String> {
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
        Some(nsid),
        now,
    )
    .map_err(|e| e.to_string())?;
    let client = crate::pipethrough::client(s, true).map_err(|e| e.message)?;
    let res = client
        .post(format!("{}/xrpc/{nsid}", endpoint.trim_end_matches('/')))
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
        .route(
            concat!("/xrpc/", locus_nsid!("deleteLabelerAccount")),
            post(delete_labeler_account),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("putLabelerRecord")),
            post(put_labeler_record),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("deleteLabelerRecord")),
            post(delete_labeler_record),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("uploadLabelerBlob")),
            post(upload_labeler_blob),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("admin.manageLabelerAccount")),
            post(manage_labeler_account),
        )
        .route(
            concat!("/xrpc/", locus_nsid!("admin.releaseLabelerAccount")),
            post(release_labeler_account),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(did: &str, cap: i64, key: Option<&str>) -> Entry {
        Entry {
            did: did.into(),
            cap,
            key: key.map(Into::into),
        }
    }

    #[test]
    fn entries_name_a_did_and_maybe_a_cap_and_key() {
        assert_eq!(
            parse_entry("did:web:cairn.example"),
            Some(e("did:web:cairn.example", DEFAULT_CAP, None))
        );
        assert_eq!(
            parse_entry("  did:plc:abc   2 "),
            Some(e("did:plc:abc", 2, None))
        );
        assert_eq!(
            parse_entry("did:plc:abc 2 did:key:zQ3abc"),
            Some(e("did:plc:abc", 2, Some("did:key:zQ3abc")))
        );
        assert_eq!(
            parse_entry("did:plc:abc did:key:zQ3abc"),
            Some(e("did:plc:abc", DEFAULT_CAP, Some("did:key:zQ3abc")))
        );
        for bad in [
            "",
            "cairn.example",
            "did:plc:abc -1",
            "did:plc:abc x",
            "did:plc:abc 1 2",
            "did:plc:abc#atproto_labeler",
            "did:plc:abc did:key:a did:key:b",
            "did:plc:abc did:key:",
            "did:key:zQ3abc",
        ] {
            assert_eq!(parse_entry(bad), None, "{bad}");
        }
        assert_eq!(
            format_entry(&e("did:plc:abc", DEFAULT_CAP, None)),
            "did:plc:abc"
        );
        assert_eq!(format_entry(&e("did:plc:abc", 9, None)), "did:plc:abc 9");
        let pinned = e("did:plc:abc", DEFAULT_CAP, Some("did:key:zQ3abc"));
        assert_eq!(format_entry(&pinned), "did:plc:abc 5 did:key:zQ3abc");
        assert_eq!(parse_entry(&format_entry(&pinned)), Some(pinned));
    }

    #[test]
    fn a_card_keeps_the_pinned_key_of_a_did_that_stays() {
        let list = vec!["did:web:a 5 did:key:zQ3abc".to_owned()];
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:a", Some(2), false),
            vec!["did:web:a 2 did:key:zQ3abc".to_owned()]
        );
        // A new DID is a different cairn: no key carried over.
        assert_eq!(
            retrust(&list, "did:web:a", "did:web:b", Some(5), false),
            vec!["did:web:b".to_owned()]
        );
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
