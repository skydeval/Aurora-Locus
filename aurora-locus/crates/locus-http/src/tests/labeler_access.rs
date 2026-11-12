//! Labeler accounts for registered cairn labelers: the probe, the cap, the
//! DID proof, and the notice back to the cairn.

use std::time::Duration;

use locus_store::accounts::Status;
use proto_blue_crypto::K256Keypair;

use super::*;
use crate::labeler_access::{CREATE_ACCOUNT, DELETE_ACCOUNT, GET_ACCESS, NOTIFY, SETTING};

const CAIRN: &str = "did:plc:cairncairncairncairncair";
const AUD: &str = "did:web:pds.example.com";

/// A DID in the directory with these verification methods and services.
fn put_did(h: &Harness, did: &str, methods: Value, services: Value) {
    h.plc.lock().unwrap().log.insert(
        did.into(),
        vec![json!({
            "type": "plc_operation",
            "alsoKnownAs": [],
            "verificationMethods": methods,
            "services": services,
        })],
    );
}

fn jwt(key: &K256Keypair, iss: &str, lxm: &str) -> String {
    let now = locus_core::time::now_ms() / 1000;
    locus_auth::service_jwt::create(key, iss, AUD, Some(now + 60), Some(lxm), now).unwrap()
}

/// A cairn's notice receiver: the (authorization, body) of each call.
type Notices = Arc<Mutex<Vec<(String, Value)>>>;

async fn mock_cairn() -> (String, Notices) {
    let seen: Notices = Arc::default();
    let app = Router::new()
        .route(
            &format!("/xrpc/{NOTIFY}"),
            post(
                |State(seen): State<Notices>,
                 headers: axum::http::HeaderMap,
                 axum::Json(body): axum::Json<Value>| async move {
                    let auth = headers["authorization"].to_str().unwrap_or("").to_owned();
                    seen.lock().unwrap().push((auth, body));
                    StatusCode::OK
                },
            ),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn a_registered_cairn_creates_labeler_accounts_up_to_its_cap() {
    let h = harness_build(HarnessOpts {
        invite_required: true,
        ssrf_protection: false,
        ..HarnessOpts::default()
    })
    .await;
    let (cairn_url, notices) = mock_cairn().await;
    let cairn_key = K256Keypair::generate();
    put_did(
        &h,
        CAIRN,
        json!({"atproto_label": cairn_key.did()}),
        json!({"atproto_labeler": {"type": "AtprotoLabeler", "endpoint": cairn_url}}),
    );
    let labeler = "did:plc:labellabellabellabellabe";
    let temp = K256Keypair::generate();
    put_did(&h, labeler, json!({"atproto": temp.did()}), json!({}));
    let as_cairn = |lxm: &str| jwt(&cairn_key, &format!("{CAIRN}#atproto_labeler"), lxm);
    let probe = || async {
        h.call(
            "GET",
            &format!("/xrpc/{GET_ACCESS}"),
            Some(&as_cairn(GET_ACCESS)),
            None,
        )
        .await
    };
    let body = |did: &str, handle: &str, proof: String| {
        json!({"did": did, "handle": handle, "email": format!("{handle}@example.com"),
               "password": "a labeler password", "didProof": proof})
    };
    let proof = |key: &K256Keypair, did: &str| jwt(key, did, "com.atproto.server.createAccount");

    // Not registered yet: refused, and createAccount still wants an invite.
    let (st, v) = probe().await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("NotRegisteredLabeler")),
        "{v}"
    );
    let (st, v) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(CREATE_ACCOUNT)),
            body(labeler, "cairnone.pds.example.com", proof(&temp, labeler)),
        )
        .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("NotRegisteredLabeler")),
        "{v}"
    );
    let (_, v) = h
        .post(
            "com.atproto.server.createAccount",
            Some(&proof(&temp, labeler)),
            json!({"did": labeler, "handle": "cairnone.pds.example.com", "email": "cairnone@example.com", "password": "pw"}),
        )
        .await;
    assert_eq!(v["error"], "InvalidInviteCode", "{v}");

    h.state
        .settings
        .set(SETTING, json!([format!("{CAIRN} 1")]), "test")
        .await
        .unwrap();
    let (st, v) = probe().await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["registered"].as_bool(),
            v["cap"].as_i64(),
            v["used"].as_i64()
        ),
        (Some(true), Some(1), Some(0))
    );

    // A token for another method, or a proof the DID's key didn't sign.
    let (st, _) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(GET_ACCESS)),
            body(labeler, "cairnone.pds.example.com", proof(&temp, labeler)),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, v) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(CREATE_ACCOUNT)),
            body(
                labeler,
                "cairnone.pds.example.com",
                proof(&K256Keypair::generate(), labeler),
            ),
        )
        .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("InvalidDidProof")),
        "{v}"
    );
    assert!(
        h.state
            .store
            .account_by_did(labeler)
            .await
            .unwrap()
            .is_none()
    );

    // The real thing: created deactivated, with the key to publish.
    let (st, v) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(CREATE_ACCOUNT)),
            body(labeler, "cairnone.pds.example.com", proof(&temp, labeler)),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["did"], labeler);
    assert_eq!(v["handle"], "cairnone.pds.example.com");
    assert_eq!(v["pdsEndpoint"], "https://pds.example.com");
    assert_eq!(
        v["signingKey"].as_str(),
        Some(h.state.signing_key(labeler).await.unwrap().did().as_str())
    );
    assert!(v["accessJwt"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(
        h.outbox_kinds(labeler).await.is_empty(),
        "nothing emitted until activated"
    );
    let (_, v) = probe().await;
    assert_eq!(v["used"], 1);

    // The cairn hears about it, from this PDS.
    let mut notice = None;
    for _ in 0..50 {
        notice = notices.lock().unwrap().first().cloned();
        if notice.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (auth, notice) = notice.expect("the cairn was told");
    assert_eq!(
        (&notice["did"], &notice["handle"], &notice["pds"]),
        (
            &json!(labeler),
            &json!("cairnone.pds.example.com"),
            &json!("https://pds.example.com")
        )
    );
    assert!(notice["createdAt"].as_str().is_some());
    let token = auth.strip_prefix("Bearer ").unwrap();
    let now = locus_core::time::now_ms() / 1000;
    let parsed = locus_auth::service_jwt::parse(token, Some(NOTIFY), now).unwrap();
    assert_eq!((parsed.iss.as_str(), parsed.aud.as_str()), (AUD, CAIRN));
    assert!(parsed.verifies_with(&h.state.service_did_key()));

    // Past the cap: refused, nothing written.
    let second = "did:plc:secondsecondsecondsecond";
    let temp2 = K256Keypair::generate();
    put_did(&h, second, json!({"atproto": temp2.did()}), json!({}));
    let (st, v) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(CREATE_ACCOUNT)),
            body(second, "cairntwo.pds.example.com", proof(&temp2, second)),
        )
        .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("LabelerAccountCapReached")),
        "{v}"
    );
    assert!(
        h.state
            .store
            .account_by_did(second)
            .await
            .unwrap()
            .is_none()
    );

    // Raising the cap lets it through.
    h.state
        .settings
        .set(SETTING, json!([format!("{CAIRN} 2")]), "test")
        .await
        .unwrap();
    let (st, v) = h
        .post(
            CREATE_ACCOUNT,
            Some(&as_cairn(CREATE_ACCOUNT)),
            body(second, "cairntwo.pds.example.com", proof(&temp2, second)),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    // Deleting: only accounts this cairn created, with its own token.
    h.state
        .settings
        .set("accounts.invite_required", json!(false), "test")
        .await
        .unwrap();
    let other = h
        .create_account("plain.pds.example.com", "plain@example.com", "pw")
        .await;
    let other = other["did"].as_str().unwrap();
    let delete = |did: &str, token: String| {
        let did = did.to_owned();
        let h = &h;
        async move {
            h.post(DELETE_ACCOUNT, Some(&token), json!({"did": did}))
                .await
        }
    };
    let (st, v) = delete(other, as_cairn(DELETE_ACCOUNT)).await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("NotCreatedByThisCairn")),
        "{v}"
    );
    let (st, _) = delete(labeler, as_cairn(CREATE_ACCOUNT)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "another method's token");
    let stranger = K256Keypair::generate();
    let stranger_did = "did:plc:strangerstrangerstrangers";
    put_did(
        &h,
        stranger_did,
        json!({"atproto_label": stranger.did()}),
        json!({}),
    );
    let (st, v) = delete(
        labeler,
        jwt(
            &stranger,
            &format!("{stranger_did}#atproto_labeler"),
            DELETE_ACCOUNT,
        ),
    )
    .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("NotRegisteredLabeler")),
        "{v}"
    );
    for did in [labeler, other] {
        let a = h.state.store.account_by_did(did).await.unwrap().unwrap();
        assert_ne!(a.status, Status::Deleted, "{did} untouched so far");
    }

    let (st, v) = delete(labeler, as_cairn(DELETE_ACCOUNT)).await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({})));
    let gone = h.state.store.account_by_did(labeler).await.unwrap();
    assert!(gone.is_none_or(|a| a.status == Status::Deleted), "deleted");
    assert!(
        h.outbox_kinds(labeler)
            .await
            .contains(&"account".to_owned()),
        "#account deleted is announced"
    );
    // Already gone: 404, so a retry is safe; the other cairn account stays.
    let (st, v) = delete(labeler, as_cairn(DELETE_ACCOUNT)).await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("AccountNotFound")),
        "{v}"
    );
    let kept = h.state.store.account_by_did(second).await.unwrap().unwrap();
    assert_ne!(kept.status, Status::Deleted);
    // A deleted account still counts toward the cap.
    let (_, v) = probe().await;
    assert_eq!(v["used"], 2);
}

/// The moderation service DID cards' trust checkbox keeps the registered
/// list in step with the DID they name.
#[tokio::test]
async fn the_moderation_service_card_trusts_its_cairn() {
    let h = harness(false).await;
    h.console_operator("own", "owner", "an owner password")
        .await;
    let o = Browser::default();
    h.console_sign_in(&o, "own", "an owner password").await;
    let (_, _, page) = o.get(&h, "/admin/moderation").await;
    assert!(
        page.contains("Trust this cairn")
            && page.contains(r#"name="trust_cap" value="5""#)
            && !page.contains(r#"name="trust" value="1" checked"#),
        "{page}"
    );
    let csrf = hidden(&page, "csrf");
    let list = |h: &Harness| {
        h.state
            .snapshot()
            .list(SETTING)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let save = |did: &'static str, trust: Option<&'static str>| {
        let csrf = csrf.clone();
        let o = &o;
        let h = &h;
        async move {
            let mut f = vec![
                ("csrf", csrf.as_str()),
                ("key", "moderation.report_service_did"),
                ("back", "/admin/moderation"),
                ("value", did),
                ("trust_shown", "1"),
            ];
            if let Some(cap) = trust {
                f.extend([("trust", "1"), ("trust_cap", cap)]);
            }
            o.post(h, "/admin/settings/save", &f).await
        }
    };
    // A cairn trusted by some other means stays put throughout.
    h.state
        .settings
        .set(SETTING, json!(["did:web:other.example 1"]), "test")
        .await
        .unwrap();

    let (st, _, _) = save("did:web:cairn.example", Some("3")).await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(
        list(&h),
        ["did:web:other.example 1", "did:web:cairn.example 3"]
    );
    let (_, _, page) = o.get(&h, "/admin/moderation").await;
    assert!(
        page.contains(r#"name="trust" value="1" checked"#)
            && page.contains(r#"name="trust_cap" value="3""#),
        "{page}"
    );

    // A new DID takes the trust with it.
    save("did:web:cairn2.example", Some("3")).await;
    assert_eq!(
        list(&h),
        ["did:web:other.example 1", "did:web:cairn2.example 3"]
    );

    // A bad cap saves nothing.
    let (st, _, page) = save("did:web:cairn3.example", Some("lots")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(page.contains("a whole number"), "{page}");
    assert_eq!(
        h.state.snapshot().text("moderation.report_service_did"),
        "did:web:cairn2.example"
    );
    assert_eq!(
        list(&h),
        ["did:web:other.example 1", "did:web:cairn2.example 3"]
    );

    // Unchecked: no longer trusted.
    save("did:web:cairn2.example", None).await;
    assert_eq!(list(&h), ["did:web:other.example 1"]);
}

/// A token for the trust link: `iss`, signed by `key`, for `lxm`, living
/// `ttl` seconds, with `bodyHash` over `body` when given.
fn link_jwt(key: &K256Keypair, iss: &str, lxm: &str, ttl: i64, body: Option<&Value>) -> String {
    let now = locus_core::time::now_ms() / 1000;
    let hash = body.map(|b| crate::labeler_access::body_hash(b.to_string().as_bytes()));
    let extra: Vec<(&str, &str)> = hash
        .as_deref()
        .map(|h| ("bodyHash", h))
        .into_iter()
        .collect();
    locus_auth::service_jwt::create_with(key, iss, AUD, Some(now + ttl), Some(lxm), now, &extra)
        .unwrap()
}

/// Once a key is pinned, only it signs (as the bare DID, with no DID
/// document read) and every POST's body is bound to its token; before,
/// the label key under `#atproto_labeler`, with a bare `iss` refused.
#[tokio::test]
async fn the_trust_link_takes_only_the_pinned_key_and_bound_bodies() {
    let h = harness(false).await;
    let label_key = K256Keypair::generate();
    put_did(
        &h,
        CAIRN,
        json!({"atproto": label_key.did(), "atproto_label": label_key.did()}),
        json!({}),
    );
    h.state
        .settings
        .set(SETTING, json!([CAIRN]), "test")
        .await
        .unwrap();
    let probe = |token: String| {
        let h = &h;
        async move {
            h.call("GET", &format!("/xrpc/{GET_ACCESS}"), Some(&token), None)
                .await
        }
    };
    let err = |r: (StatusCode, Value)| (r.0, r.1["error"].as_str().unwrap_or("").to_owned());
    let labeler = format!("{CAIRN}#atproto_labeler");

    // Not pinned: the label key as #atproto_labeler; a bare iss is refused,
    // even signed with the #atproto key (a session's getServiceAuth).
    assert_eq!(
        probe(link_jwt(&label_key, &labeler, GET_ACCESS, 60, None))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        err(probe(link_jwt(&label_key, CAIRN, GET_ACCESS, 60, None)).await),
        (StatusCode::UNAUTHORIZED, "BadJwtIss".into())
    );
    // At most five minutes, and once only.
    assert_eq!(
        err(probe(link_jwt(&label_key, &labeler, GET_ACCESS, 3600, None)).await),
        (StatusCode::UNAUTHORIZED, "BadJwt".into())
    );
    let once = link_jwt(&label_key, &labeler, GET_ACCESS, 60, None);
    assert_eq!(probe(once.clone()).await.0, StatusCode::OK);
    assert_eq!(
        err(probe(once).await),
        (StatusCode::UNAUTHORIZED, "BadJwt".into())
    );
    // A bodyHash, when sent before pinning, must match.
    let body = json!({"did": "did:plc:nobodynobodynobodynobody"});
    let other = json!({"did": "did:plc:otherotherotherotherothe"});
    let (st, v) = h
        .post(
            DELETE_ACCOUNT,
            Some(&link_jwt(
                &label_key,
                &labeler,
                DELETE_ACCOUNT,
                60,
                Some(&other),
            )),
            body.clone(),
        )
        .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("BadJwtBodyHash"))
    );

    // Pinned: a key of its own. The DID document is gone, so nothing is
    // read from it.
    let pinned = K256Keypair::generate();
    h.state
        .settings
        .set(
            SETTING,
            json!([format!("{CAIRN} 5 {}", pinned.did())]),
            "test",
        )
        .await
        .unwrap();
    h.plc.lock().unwrap().log.remove(CAIRN);
    assert_eq!(
        probe(link_jwt(&pinned, CAIRN, GET_ACCESS, 60, None))
            .await
            .0,
        StatusCode::OK
    );
    for (token, want) in [
        // The old way, or the label key, no longer works.
        (
            link_jwt(&label_key, &labeler, GET_ACCESS, 60, None),
            "BadJwtIss",
        ),
        (
            link_jwt(&label_key, CAIRN, GET_ACCESS, 60, None),
            "BadJwtSignature",
        ),
        (
            link_jwt(&pinned, &labeler, GET_ACCESS, 60, None),
            "BadJwtIss",
        ),
    ] {
        assert_eq!(
            err(probe(token).await),
            (StatusCode::UNAUTHORIZED, want.to_owned())
        );
    }
    // Every POST carries the hash of its exact body.
    for token in [
        link_jwt(&pinned, CAIRN, DELETE_ACCOUNT, 60, None),
        link_jwt(&pinned, CAIRN, DELETE_ACCOUNT, 60, Some(&other)),
    ] {
        let (st, v) = h.post(DELETE_ACCOUNT, Some(&token), body.clone()).await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("BadJwtBodyHash")),
            "{v}"
        );
    }
    let (st, v) = h
        .post(
            DELETE_ACCOUNT,
            Some(&link_jwt(&pinned, CAIRN, DELETE_ACCOUNT, 60, Some(&body))),
            body,
        )
        .await;
    assert_eq!(
        (st, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("NotCreatedByThisCairn")),
        "past the token check"
    );
}

/// The registered list refuses an item that would silently unregister its
/// cairn, such as a key that isn't a did:key.
#[tokio::test]
async fn a_bad_key_is_refused_before_it_is_saved() {
    let h = harness(false).await;
    let admin = format!("Bearer {}", h.operator("ad", "admin").await);
    let path = format!("/xrpc/{}.admin.setSetting", locus_core::LOCUS_NS);
    let set = |value: Value| {
        let (h, admin, path) = (&h, &admin, &path);
        async move {
            h.admin_call(
                "POST",
                path,
                admin,
                Some(json!({"key": SETTING, "value": value})),
            )
            .await
        }
    };
    let (st, v) = set(json!(["did:web:c 5 did:key:znotakey"])).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    let good = K256Keypair::generate().did();
    let (st, v) = set(json!([format!("did:web:c 5 {good}")])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
}
