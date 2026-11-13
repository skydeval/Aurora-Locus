//! The console's navigation and in-place saving: nested pages say where they
//! are and lead back up, saves come back to the card they were made in,
//! a failed action shows its page with the problem, and every signed-in page
//! loads the one script (under the CSP that lets it run).

use super::*;

async fn signed_in() -> (Harness, Browser) {
    let h = harness(false).await;
    h.console_operator("own", "owner", "an owner password")
        .await;
    let o = Browser::default();
    h.console_sign_in(&o, "own", "an owner password").await;
    (h, o)
}

#[tokio::test]
async fn every_console_page_loads_the_script_and_marks_its_sections() {
    let (h, o) = signed_in().await;
    let (st, headers, page) = o.get(&h, "/admin/moderation").await;
    assert_eq!(st, StatusCode::OK);
    // The script, with its integrity, and the CSP that lets it run.
    let tag = format!(
        r#"<script src="{}" integrity="{}" defer>"#,
        *locus_web::assets::JS_HREF,
        *locus_web::assets::JS_SRI
    );
    assert!(page.contains(&tag), "{page}");
    assert_eq!(
        headers["content-security-policy"],
        locus_web::assets::CSP_LIVE
    );
    // Its setting cards are sections a save replaces; a lookup (a GET)
    // isn't one.
    assert!(
        page.contains(r#"<div class="card" id="s-moderation.service_did" data-section>"#)
            && page.contains(r#"<div class="card" id="f-moderation">"#),
        "{page}"
    );
    // A page before sign-in loads nothing.
    let (_, headers, page) = Browser::default().get(&h, "/admin/sign-in").await;
    assert!(!page.contains("<script"), "{page}");
    assert_eq!(headers["content-security-policy"], locus_web::assets::CSP);
}

#[tokio::test]
async fn a_save_comes_back_to_its_card_and_a_failure_shows_its_page() {
    let (h, o) = signed_in().await;
    let (_, _, page) = o.get(&h, "/admin/moderation").await;
    let csrf = hidden(&page, "csrf");

    // A setting saved from the moderation page: back there, at its card.
    let (st, headers, _) = o
        .post(
            &h,
            "/admin/settings/save",
            &[
                ("csrf", &csrf),
                ("key", "moderation.service_did"),
                ("back", "/admin/moderation"),
                ("value", "did:web:mod.example"),
            ],
        )
        .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(
        headers["location"],
        "/admin/moderation?saved=moderation.service_did#s-moderation.service_did"
    );

    // A refused value: its card with the problem, under the page it came
    // from, so the way back is one click.
    let (st, _, page) = o
        .post(
            &h,
            "/admin/settings/save",
            &[
                ("csrf", &csrf),
                ("key", "moderation.service_url"),
                ("back", "/admin/moderation"),
                ("value", "not a url"),
            ],
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(
        page.contains(r#"id="s-moderation.service_url" data-section"#)
            && page.contains(r#"role="alert""#)
            && page.contains(r#"<nav class="crumbs" aria-label="Breadcrumb">"#)
            && page.contains(r#"<p class="back"><a href="/admin/moderation">← Moderation</a></p>"#),
        "{page}"
    );

    // A failed takedown shows the whole moderation page with the problem,
    // not an empty one.
    let (st, _, page) = o
        .post(
            &h,
            "/admin/moderation/status",
            &[
                ("csrf", &csrf),
                ("subject", "did:plc:nobodynobodynobodynobody"),
                ("applied", "true"),
            ],
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{page}");
    assert!(
        page.contains(r#"role="alert""#) && page.contains("Look up a subject"),
        "{page}"
    );
}

#[tokio::test]
async fn a_nested_page_shows_its_trail_and_actions_land_on_their_card() {
    let (h, o) = signed_in().await;
    let acct = h
        .create_account("nav.pds.example.com", "nav@example.com", "pw")
        .await;
    let did = acct["did"].as_str().unwrap().to_owned();
    let path = format!("/admin/accounts/{did}");
    let (st, _, page) = o.get(&h, &path).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        page.contains(r#"<li><a href="/admin/accounts">Accounts</a></li><li aria-current="page">@nav.pds.example.com</li>"#)
            && page.contains(r#"<p class="back"><a href="/admin/accounts">← Accounts</a></p>"#)
            && page.contains(r#"id="a-suspend" data-section"#)
            && page.contains(r#"data-confirm="Take down @nav.pds.example.com?""#)
            // A new handle renames the whole page (title, trail, the
            // confirm questions), so that form reloads it.
            && page.contains(r#"/handle" data-full>"#),
        "{page}"
    );
    let csrf = hidden(&page, "csrf");
    let (st, headers, _) = o
        .post(
            &h,
            &format!("{path}/suspend"),
            &[("csrf", &csrf), ("days", "3"), ("note", "")],
        )
        .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(
        headers["location"],
        format!(
            "{}?done=suspend#a-suspend",
            crate::console_people::account_href(&did)
        )
    );
    // Its delete page sits two levels down.
    let (_, _, page) = o.get(&h, &format!("{path}/delete")).await;
    assert!(
        page.contains(&format!(
            r#"<li><a href="/admin/accounts">Accounts</a></li><li><a href="{}">@nav.pds.example.com</a></li>"#,
            crate::console_people::account_href(&did)
        )) || page.contains("Confirm it"),
        "{page}"
    );
}
