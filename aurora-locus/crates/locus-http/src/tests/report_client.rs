//! A proxied `createReport` from an OAuth session tells the labeler which
//! client it came from, in the service token's `client_id`.

use super::*;

/// The claims of the bearer token on a recorded request.
fn claims(seen: &Seen) -> Value {
    let auth = seen.headers["authorization"].to_str().unwrap();
    let token = auth.strip_prefix("Bearer ").unwrap();
    let payload = token.split('.').nth(1).unwrap();
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn an_oauth_report_names_its_client() {
    let h = harness(false).await;
    let (url, seen) = mock_service().await;
    for (k, v) in [
        ("moderation.service_url", url.as_str()),
        ("moderation.service_did", "did:web:labeler.test"),
    ] {
        h.state.settings.set(k, json!(v), "test").await.unwrap();
    }
    let acct = h
        .create_account("rpc.pds.example.com", "rpc@example.com", "pw")
        .await;
    let did = acct["did"].as_str().unwrap().to_owned();
    let access = acct["accessJwt"].as_str().unwrap().to_owned();
    let report = json!({"reasonType": "com.atproto.moderation.defs#reasonSpam",
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:abc"}});
    let last = |seen: &SeenLog| seen.lock().unwrap().last().cloned().unwrap();

    // OAuth: the report's token names the client.
    let client = DpopClient::new();
    let client_id = "http://localhost?scope=atproto+rpc%3Acom.atproto.moderation.createReport%3Faud%3D*+rpc%3Atools.ozone.moderation.getRepo%3Faud%3D*";
    let scope = "atproto rpc:com.atproto.moderation.createReport?aud=* rpc:tools.ozone.moderation.getRepo?aud=*";
    let tok = h.oauth_grant(&client, client_id, scope, &did).await;
    let at = tok["access_token"].as_str().unwrap().to_owned();
    let (st, _, v) = h
        .oauth_call(
            &client,
            &at,
            "POST",
            "/xrpc/com.atproto.moderation.createReport",
            Some(report.clone()),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let c = claims(&last(&seen));
    assert_eq!(
        (
            c["iss"].as_str(),
            c["lxm"].as_str(),
            c["client_id"].as_str()
        ),
        (
            Some(did.as_str()),
            Some("com.atproto.moderation.createReport"),
            Some(client_id)
        ),
        "{c}"
    );

    // Other proxied calls from the same session don't carry it.
    let (st, _, v) = h
        .oauth_call(
            &client,
            &at,
            "GET",
            "/xrpc/tools.ozone.moderation.getRepo?did=did:plc:abc",
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let c = claims(&last(&seen));
    assert_eq!(c["lxm"], "tools.ozone.moderation.getRepo");
    assert!(c.get("client_id").is_none(), "{c}");

    // A password session has no client.
    let (st, v) = h
        .call(
            "POST",
            "/xrpc/com.atproto.moderation.createReport",
            Some(&access),
            Some(report),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let c = claims(&last(&seen));
    assert_eq!(c["lxm"], "com.atproto.moderation.createReport");
    assert!(c.get("client_id").is_none(), "{c}");
}
