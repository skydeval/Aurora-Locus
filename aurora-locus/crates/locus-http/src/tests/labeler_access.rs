//! Labeler accounts for registered cairn labelers: the probe, the cap, the
//! DID proof, and the notice back to the cairn.

use std::time::Duration;

use proto_blue_crypto::K256Keypair;

use super::*;
use crate::labeler_access::{CREATE_ACCOUNT, GET_ACCESS, NOTIFY, SETTING};

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
}
