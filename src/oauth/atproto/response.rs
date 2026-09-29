//! atproto-OAuth authorization responses (chainlink #483).
//!
//! The authorize step ends by sending the browser back to the client with
//! either `code` or `error` / `error_description`, plus the echoed `state` and
//! the issuer as `iss` (RFC 9207, which atproto OAuth requires so a client
//! talking to several servers can tell which one answered). Where those
//! parameters go is the client's `response_mode`:
//!
//! - `query` (the default for `response_type=code`): appended to the redirect
//!   URI's query string;
//! - `fragment`: the redirect URI's fragment, which is where browser clients
//!   built on the reference OAuth libraries read them;
//! - `form_post`: an auto-submitting HTML form that POSTs them to the redirect
//!   URI.

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use super::html::html_escape;

/// Where an authorization response's parameters are delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ResponseMode {
    /// The redirect URI's query string.
    #[default]
    Query,
    /// The redirect URI's fragment.
    Fragment,
    /// An auto-submitting form POSTed to the redirect URI.
    FormPost,
}

impl ResponseMode {
    /// Every supported mode, as advertised in `response_modes_supported`.
    pub fn all() -> [ResponseMode; 3] {
        [
            ResponseMode::Query,
            ResponseMode::Fragment,
            ResponseMode::FormPost,
        ]
    }

    /// The mode's wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
        }
    }

    /// Parse a requested `response_mode`; `None` if unsupported.
    pub fn parse(s: &str) -> Option<ResponseMode> {
        ResponseMode::all().into_iter().find(|m| m.as_str() == s)
    }

    /// The mode stored on an authorization request. Absent (a request stored
    /// before modes were recorded) means `query`.
    pub fn from_stored(stored: Option<&str>) -> ResponseMode {
        stored.and_then(ResponseMode::parse).unwrap_or_default()
    }
}

/// Send the browser back to the client at `redirect_uri` with `params` (plus
/// `iss` = `issuer`), delivered according to `mode`.
pub fn respond_to_client(
    redirect_uri: &str,
    mode: ResponseMode,
    issuer: &str,
    params: &[(&str, &str)],
) -> Response {
    let mut all: Vec<(&str, &str)> = params.to_vec();
    all.push(("iss", issuer));
    match mode {
        ResponseMode::Query => redirect(append_query(redirect_uri, &all)),
        ResponseMode::Fragment => redirect(with_fragment(redirect_uri, &all)),
        ResponseMode::FormPost => form_post(redirect_uri, &all),
    }
}

fn redirect(location: String) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

fn encode(params: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter().copied())
        .finish()
}

/// `redirect_uri` with `params` appended to its query, keeping any query it
/// already has.
fn append_query(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    match url::Url::parse(redirect_uri) {
        Ok(mut url) => {
            url.query_pairs_mut().extend_pairs(params.iter().copied());
            url.to_string()
        }
        // The redirect_uri was matched against the client's metadata upstream,
        // so this is defensive; compose by hand.
        Err(_) => {
            let (base, fragment) = split_fragment(redirect_uri);
            let sep = if base.contains('?') { '&' } else { '?' };
            let fragment = fragment.map(|f| format!("#{f}")).unwrap_or_default();
            format!("{base}{sep}{}{fragment}", encode(params))
        }
    }
}

/// `redirect_uri` with its fragment replaced by `params`.
fn with_fragment(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let encoded = encode(params);
    match url::Url::parse(redirect_uri) {
        Ok(mut url) => {
            url.set_fragment(Some(&encoded));
            url.to_string()
        }
        Err(_) => format!("{}#{encoded}", split_fragment(redirect_uri).0),
    }
}

fn split_fragment(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (uri, None),
    }
}

/// An HTML page whose form POSTs `params` to `redirect_uri` on load (with a
/// button for browsers that do not run the script).
fn form_post(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let inputs: String = params
        .iter()
        .map(|(k, v)| {
            format!(
                r#"<input type="hidden" name="{}" value="{}">"#,
                html_escape(k),
                html_escape(v)
            )
        })
        .collect();
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Returning to the application</title>
</head>
<body onload="document.forms[0].submit()">
  <form method="post" action="{action}">{inputs}<button type="submit">Continue</button></form>
</body>
</html>"#,
        action = html_escape(redirect_uri),
    );
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Html(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://locus.example.com";

    fn location(resp: &Response) -> String {
        assert_eq!(resp.status(), StatusCode::FOUND);
        resp.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn modes_parse_and_default_to_query() {
        for mode in ResponseMode::all() {
            assert_eq!(ResponseMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(ResponseMode::parse("web_message"), None);
        assert_eq!(ResponseMode::from_stored(None), ResponseMode::Query);
        assert_eq!(
            ResponseMode::from_stored(Some("fragment")),
            ResponseMode::Fragment
        );
    }

    #[test]
    fn query_mode_appends_to_the_query_with_iss() {
        let resp = respond_to_client(
            "https://app.example.com/cb?keep=1",
            ResponseMode::Query,
            ISS,
            &[("code", "c 1"), ("state", "s")],
        );
        assert_eq!(
            location(&resp),
            "https://app.example.com/cb?keep=1&code=c+1&state=s&iss=https%3A%2F%2Flocus.example.com"
        );
    }

    #[test]
    fn fragment_mode_replaces_the_fragment_and_leaves_the_query() {
        let resp = respond_to_client(
            "https://app.example.com/cb#old",
            ResponseMode::Fragment,
            ISS,
            &[("code", "abc"), ("state", "s/1")],
        );
        let loc = location(&resp);
        assert_eq!(
            loc,
            "https://app.example.com/cb#code=abc&state=s%2F1&iss=https%3A%2F%2Flocus.example.com"
        );
        let url = url::Url::parse(&loc).unwrap();
        assert!(url.query().is_none(), "no code in the query");
    }

    #[test]
    fn errors_carry_iss_too() {
        let resp = respond_to_client(
            "https://app.example.com/cb",
            ResponseMode::Fragment,
            ISS,
            &[("error", "access_denied"), ("state", "s")],
        );
        let loc = location(&resp);
        assert!(loc.contains("#error=access_denied&state=s&iss="), "{loc}");
    }

    #[tokio::test]
    async fn form_post_mode_renders_an_escaped_auto_submitting_form() {
        let resp = respond_to_client(
            "https://app.example.com/cb?a=1&b=2",
            ResponseMode::FormPost,
            ISS,
            &[("code", "abc"), ("state", "<s>")],
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains(r#"action="https://app.example.com/cb?a=1&amp;b=2""#));
        assert!(html.contains(r#"name="code" value="abc""#));
        assert!(html.contains(r#"name="state" value="&lt;s&gt;""#));
        assert!(html.contains(r#"name="iss" value="https://locus.example.com""#));
        assert!(html.contains("document.forms[0].submit()"));
    }
}
