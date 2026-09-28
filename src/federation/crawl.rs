//! Outbound `com.atproto.sync.requestCrawl` (#462).
//!
//! A relay only indexes a PDS it knows about. `requestCrawl` tells a relay
//! that this PDS exists; the relay then connects to this PDS's own
//! `com.atproto.sync.subscribeRepos` and crawls it. Without it a new PDS is
//! never indexed unless the operator calls each relay by hand.
//!
//! This module is the transport: one POST per relay, with bounded backoff for
//! failures worth retrying. Deciding *when* to ask (and auditing it) lives in
//! `api::federation_crawl`.

use serde::Serialize;
use std::time::Duration;

/// Per-request timeout for a single `requestCrawl` call.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Longest relay error body kept in a [`CrawlError::Rejected`] (bytes).
const MAX_ERROR_BODY: usize = 300;

/// Delays before each attempt for automatic (background) requests: an
/// immediate try, then two retries. Bounded so a dead relay costs at most
/// three requests per trigger.
pub const BACKGROUND_BACKOFF: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_secs(10),
    Duration::from_secs(60),
];

/// Why a `requestCrawl` call failed.
#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    /// The request never got an HTTP answer (DNS, connect, TLS, timeout).
    #[error("could not reach {relay}: {message}")]
    Transport {
        /// Relay base URL.
        relay: String,
        /// Transport error description.
        message: String,
    },
    /// The relay answered with a non-2xx status.
    #[error("{relay} answered HTTP {status}: {body}")]
    Rejected {
        /// Relay base URL.
        relay: String,
        /// HTTP status code.
        status: u16,
        /// Start of the relay's response body.
        body: String,
    },
    /// The HTTP client could not be constructed.
    #[error("could not build HTTP client: {0}")]
    Client(String),
}

impl CrawlError {
    /// Whether another attempt could plausibly succeed: transport failures,
    /// rate limiting and server errors. Other 4xx answers are final.
    pub fn is_retryable(&self) -> bool {
        match self {
            CrawlError::Transport { .. } => true,
            CrawlError::Rejected { status, .. } => *status == 429 || *status >= 500,
            CrawlError::Client(_) => false,
        }
    }
}

#[derive(Serialize)]
struct RequestCrawlBody<'a> {
    hostname: &'a str,
}

/// Sends `requestCrawl` to relays.
#[derive(Debug, Clone)]
pub struct CrawlRequester {
    http: reqwest::Client,
}

impl CrawlRequester {
    /// Build a requester with a bounded per-request timeout.
    pub fn new() -> Result<Self, CrawlError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("aurora-locus/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CrawlError::Client(e.to_string()))?;
        Ok(Self { http })
    }

    /// One `POST {relay}/xrpc/com.atproto.sync.requestCrawl` with
    /// `{"hostname": hostname}`.
    pub async fn request_crawl(&self, relay: &str, hostname: &str) -> Result<(), CrawlError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.requestCrawl",
            relay.trim_end_matches('/')
        );
        let response = self
            .http
            .post(&url)
            .json(&RequestCrawlBody { hostname })
            .send()
            .await
            .map_err(|e| CrawlError::Transport {
                relay: relay.to_string(),
                message: e.to_string(),
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let mut body = response.text().await.unwrap_or_default();
        if body.len() > MAX_ERROR_BODY {
            let mut cut = MAX_ERROR_BODY;
            while !body.is_char_boundary(cut) {
                cut -= 1;
            }
            body.truncate(cut);
        }
        Err(CrawlError::Rejected {
            relay: relay.to_string(),
            status: status.as_u16(),
            body,
        })
    }

    /// [`request_crawl`](Self::request_crawl) with one attempt per entry of
    /// `delays`, sleeping that long before the attempt. Stops at the first
    /// success or non-retryable failure. Returns the final result and the
    /// number of attempts made.
    pub async fn request_crawl_with_backoff(
        &self,
        relay: &str,
        hostname: &str,
        delays: &[Duration],
    ) -> (Result<(), CrawlError>, usize) {
        let mut last = Err(CrawlError::Client("no attempts configured".to_string()));
        let mut attempts = 0;
        for delay in delays {
            if !delay.is_zero() {
                tokio::time::sleep(*delay).await;
            }
            attempts += 1;
            last = self.request_crawl(relay, hostname).await;
            match &last {
                Ok(()) => break,
                Err(e) if !e.is_retryable() => break,
                Err(_) => {}
            }
        }
        (last, attempts)
    }
}

#[cfg(test)]
pub(crate) mod test_relay {
    //! An in-process fake relay for `requestCrawl` tests: answers each call
    //! with the next scripted status (the last one repeats) and records the
    //! path and JSON body it received.

    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Script {
        statuses: Arc<Mutex<Vec<u16>>>,
        received: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    /// A running fake relay.
    pub(crate) struct FakeRelay {
        /// `http://127.0.0.1:<port>` — the relay base URL.
        pub(crate) url: String,
        received: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl FakeRelay {
        /// Bodies received on `/xrpc/com.atproto.sync.requestCrawl`, in order.
        pub(crate) fn received(&self) -> Vec<serde_json::Value> {
            self.received.lock().unwrap().clone()
        }
    }

    async fn handle(
        State(script): State<Script>,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, &'static str) {
        script.received.lock().unwrap().push(body);
        let mut statuses = script.statuses.lock().unwrap();
        let status = if statuses.len() > 1 {
            statuses.remove(0)
        } else {
            statuses[0]
        };
        (StatusCode::from_u16(status).unwrap(), "relay says hi")
    }

    /// Start a fake relay answering with `statuses` in turn.
    pub(crate) async fn start(statuses: &[u16]) -> FakeRelay {
        let script = Script {
            statuses: Arc::new(Mutex::new(statuses.to_vec())),
            received: Arc::new(Mutex::new(Vec::new())),
        };
        let received = script.received.clone();
        let app = Router::new()
            .route("/xrpc/com.atproto.sync.requestCrawl", post(handle))
            .with_state(script);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeRelay {
            url: format!("http://{addr}"),
            received,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_relay::start;
    use super::*;

    const NO_WAIT: [Duration; 3] = [Duration::ZERO; 3];

    #[tokio::test]
    async fn posts_hostname_to_request_crawl() {
        let relay = start(&[200]).await;
        let requester = CrawlRequester::new().unwrap();
        requester
            .request_crawl(&format!("{}/", relay.url), "pds.example.com")
            .await
            .unwrap();
        assert_eq!(
            relay.received(),
            vec![serde_json::json!({ "hostname": "pds.example.com" })]
        );
    }

    #[tokio::test]
    async fn retries_server_errors_then_succeeds() {
        let relay = start(&[503, 429, 200]).await;
        let requester = CrawlRequester::new().unwrap();
        let (result, attempts) = requester
            .request_crawl_with_backoff(&relay.url, "pds.example.com", &NO_WAIT)
            .await;
        result.unwrap();
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn a_client_error_is_final() {
        let relay = start(&[400]).await;
        let requester = CrawlRequester::new().unwrap();
        let (result, attempts) = requester
            .request_crawl_with_backoff(&relay.url, "pds.example.com", &NO_WAIT)
            .await;
        match result {
            Err(CrawlError::Rejected { status, body, .. }) => {
                assert_eq!(status, 400);
                assert_eq!(body, "relay says hi");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(attempts, 1, "a 400 is not retried");
    }

    #[tokio::test]
    async fn gives_up_after_the_last_attempt() {
        let relay = start(&[502]).await;
        let requester = CrawlRequester::new().unwrap();
        let (result, attempts) = requester
            .request_crawl_with_backoff(&relay.url, "pds.example.com", &NO_WAIT)
            .await;
        assert!(matches!(
            result,
            Err(CrawlError::Rejected { status: 502, .. })
        ));
        assert_eq!(attempts, 3);
        assert_eq!(relay.received().len(), 3);
    }

    #[tokio::test]
    async fn unreachable_relay_is_a_retryable_transport_error() {
        // Bind then drop a listener so the port is (almost certainly) closed.
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let requester = CrawlRequester::new().unwrap();
        let err = requester
            .request_crawl(&format!("http://127.0.0.1:{port}"), "pds.example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, CrawlError::Transport { .. }), "{err:?}");
        assert!(err.is_retryable());
    }

    #[test]
    fn retryability_by_status() {
        let rejected = |status| CrawlError::Rejected {
            relay: "r".into(),
            status,
            body: String::new(),
        };
        assert!(rejected(500).is_retryable());
        assert!(rejected(429).is_retryable());
        assert!(!rejected(400).is_retryable());
        assert!(!rejected(404).is_retryable());
        assert!(!CrawlError::Client("x".into()).is_retryable());
    }
}
