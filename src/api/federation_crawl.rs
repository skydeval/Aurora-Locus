//! When and how this PDS asks its relays to crawl it (#462).
//!
//! `federation::crawl` is the transport; this module decides when to call it
//! and records each call on the audit chain. Requests go to the live relay set
//! (the relays this PDS announces itself to), and only while crawling is
//! active: federation enabled and `federation.crawl_enabled` on.
//!
//! Triggers:
//! - boot, once the scheduler starts ([`CrawlTrigger::Boot`]);
//! - `federation.crawl_enabled` switched on at runtime
//!   ([`CrawlTrigger::CrawlEnabled`]);
//! - relays added to the live set ([`CrawlTrigger::RelayAdded`]);
//! - the SuperAdmin `tools.aurora.ops.requestRelayCrawl` call
//!   ([`CrawlTrigger::Manual`]).

use crate::api::aurora_admin::{resolve_federation_flag, FEDERATION_CRAWL_ENABLED_KEY};
use crate::api::federation_peers::emit;
use crate::context::AppContext;
use crate::federation::crawl::{CrawlRequester, BACKGROUND_BACKOFF};
use serde::Serialize;
use std::time::Duration;

/// A relay acknowledged a `requestCrawl`.
pub(crate) const ACTION_CRAWL_REQUESTED: &str = "federation.crawl_requested";
/// A `requestCrawl` failed after its last attempt.
pub(crate) const ACTION_CRAWL_REQUEST_FAILED: &str = "federation.crawl_request_failed";

const SOURCE_MANUAL: &str = "manual";
const SOURCE_DIAGNOSTIC: &str = "system_diagnostic";

/// What caused a crawl request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlTrigger {
    /// Server start with crawling active.
    Boot,
    /// `federation.crawl_enabled` switched on at runtime.
    CrawlEnabled,
    /// Relays added to the live relay set.
    RelayAdded,
    /// An operator pressed "Request crawl".
    Manual,
}

impl CrawlTrigger {
    /// Wire/audit name.
    pub fn as_str(self) -> &'static str {
        match self {
            CrawlTrigger::Boot => "boot",
            CrawlTrigger::CrawlEnabled => "crawl_enabled",
            CrawlTrigger::RelayAdded => "relay_added",
            CrawlTrigger::Manual => "manual",
        }
    }
}

/// Result of asking one relay to crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlOutcome {
    /// Relay base URL.
    pub url: String,
    /// Whether the relay acknowledged the request.
    pub ok: bool,
    /// Attempts made (retries included).
    pub attempts: usize,
    /// Why the last attempt failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether this PDS should be asking relays to crawl it: federation enabled
/// (boot-resolved) and `federation.crawl_enabled` on (runtime row, else env).
pub async fn crawl_active(ctx: &AppContext) -> bool {
    ctx.federation_enabled
        && resolve_federation_flag(
            ctx,
            FEDERATION_CRAWL_ENABLED_KEY,
            ctx.config.federation.crawl_enabled,
        )
        .await
}

/// The hostname relays should crawl: the host (and non-default port) of the
/// public service URL, e.g. `locus.nearhorizon.app`.
pub fn crawl_hostname(ctx: &AppContext) -> Option<String> {
    let url = url::Url::parse(&ctx.config.service.effective_public_url()).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The live relay set (empty when no relay is configured).
pub async fn live_relays(ctx: &AppContext) -> Vec<String> {
    match ctx.relay_client.as_ref() {
        Some(client) => client.lock().await.servers().to_vec(),
        None => Vec::new(),
    }
}

/// One-word relay state for health surfaces: `disabled` (federation off),
/// `none` (empty relay set), `idle` (relays, but crawl off) or `announcing`
/// (relays are being asked to crawl this PDS). There is no relay *connection*
/// to report: relays connect to this PDS, not the other way round (#459).
pub async fn relay_state(ctx: &AppContext) -> &'static str {
    if !ctx.federation_enabled {
        "disabled"
    } else if live_relays(ctx).await.is_empty() {
        "none"
    } else if crawl_active(ctx).await {
        "announcing"
    } else {
        "idle"
    }
}

/// Relays present in `after` but not in `before`, in `after`'s order.
pub fn newly_added(before: &[String], after: &[String]) -> Vec<String> {
    after
        .iter()
        .filter(|u| !before.contains(u))
        .cloned()
        .collect()
}

/// Ask each of `relays` to crawl this PDS, one attempt per entry of `delays`,
/// and append one audit entry per relay. Does not check [`crawl_active`]; the
/// callers do.
pub async fn request_crawl_from(
    ctx: &AppContext,
    relays: &[String],
    trigger: CrawlTrigger,
    actor_did: &str,
    delays: &[Duration],
) -> Vec<CrawlOutcome> {
    let Some(hostname) = crawl_hostname(ctx) else {
        tracing::error!(
            public_url = %ctx.config.service.effective_public_url(),
            "requestCrawl skipped: the public service URL has no hostname"
        );
        return Vec::new();
    };
    let requester = match CrawlRequester::new() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "requestCrawl skipped");
            return Vec::new();
        }
    };

    let source = if trigger == CrawlTrigger::Manual {
        SOURCE_MANUAL
    } else {
        SOURCE_DIAGNOSTIC
    };
    let mut outcomes = Vec::with_capacity(relays.len());
    for relay in relays {
        let (result, attempts) = requester
            .request_crawl_with_backoff(relay, &hostname, delays)
            .await;
        let outcome = CrawlOutcome {
            url: relay.clone(),
            ok: result.is_ok(),
            attempts,
            error: result.err().map(|e| e.to_string()),
        };
        let (action, rationale) = if outcome.ok {
            tracing::info!(relay = %relay, hostname = %hostname, trigger = trigger.as_str(), "requestCrawl acknowledged");
            (ACTION_CRAWL_REQUESTED, "relay asked to crawl this PDS")
        } else {
            tracing::warn!(
                relay = %relay,
                hostname = %hostname,
                trigger = trigger.as_str(),
                attempts,
                error = outcome.error.as_deref().unwrap_or_default(),
                "requestCrawl failed"
            );
            (ACTION_CRAWL_REQUEST_FAILED, "relay crawl request failed")
        };
        let payload = serde_json::json!({
            "url": relay,
            "hostname": hostname,
            "trigger": trigger.as_str(),
            "attempts": attempts,
            "error": outcome.error,
        });
        if let Err(e) = emit(ctx, actor_did, action, source, payload, rationale).await {
            tracing::error!(error = ?e, relay = %relay, "requestCrawl audit emit failed");
        }
        outcomes.push(outcome);
    }
    outcomes
}

/// Ask relays to crawl this PDS in the background, with backoff, if crawling
/// is active. `relays: None` means the whole live set.
pub fn spawn_crawl_requests(ctx: &AppContext, relays: Option<Vec<String>>, trigger: CrawlTrigger) {
    let ctx = ctx.clone();
    tokio::spawn(async move {
        if !crawl_active(&ctx).await {
            return;
        }
        let relays = match relays {
            Some(r) => r,
            None => live_relays(&ctx).await,
        };
        if relays.is_empty() {
            return;
        }
        request_crawl_from(
            &ctx,
            &relays,
            trigger,
            crate::api::moderation_defaults::SYSTEM_DID,
            &BACKGROUND_BACKOFF,
        )
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::federation_peers::test_support::{create_test_context_with, serial};
    use crate::federation::crawl::test_relay;

    async fn audit_rows(ctx: &AppContext, action: &str) -> Vec<String> {
        sqlx::query_scalar("SELECT source FROM audit_chain_entry WHERE action = $1")
            .bind(action)
            .fetch_all(&ctx.account_db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn crawl_hostname_is_the_public_host() {
        let ctx = create_test_context_with(|_| {}).await;
        // Test config: hostname localhost, port 2583 → http://localhost:2583.
        assert_eq!(crawl_hostname(&ctx).as_deref(), Some("localhost:2583"));

        let mut ctx = ctx;
        let mut config = (*ctx.config).clone();
        config.service.public_url = Some("https://locus.example.app".to_string());
        ctx.config = std::sync::Arc::new(config);
        assert_eq!(crawl_hostname(&ctx).as_deref(), Some("locus.example.app"));
    }

    #[tokio::test]
    async fn relay_state_covers_each_case() {
        let _g = serial().lock().await;
        let with = |fed: bool, crawl: bool, relays: Vec<String>| {
            create_test_context_with(move |c| {
                c.federation.enabled = fed;
                c.federation.crawl_enabled = crawl;
                c.federation.relay_urls = relays;
            })
        };
        let r = || vec!["https://relay.example".to_string()];
        assert_eq!(relay_state(&with(false, true, r()).await).await, "disabled");
        assert_eq!(relay_state(&with(true, true, vec![]).await).await, "none");
        assert_eq!(relay_state(&with(true, false, r()).await).await, "idle");
        assert_eq!(
            relay_state(&with(true, true, r()).await).await,
            "announcing"
        );
    }

    #[test]
    fn newly_added_keeps_order_and_drops_existing() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            newly_added(
                &s(&["https://a", "https://b"]),
                &s(&["https://c", "https://a", "https://d"])
            ),
            s(&["https://c", "https://d"])
        );
        assert!(newly_added(&s(&["https://a"]), &s(&[])).is_empty());
    }

    #[tokio::test]
    async fn crawl_active_needs_federation_and_the_crawl_flag() {
        let _g = serial().lock().await;
        let off = create_test_context_with(|c| {
            c.federation.enabled = true;
            c.federation.crawl_enabled = false;
        })
        .await;
        assert!(!crawl_active(&off).await);

        let no_fed = create_test_context_with(|c| {
            c.federation.enabled = false;
            c.federation.crawl_enabled = true;
        })
        .await;
        assert!(!crawl_active(&no_fed).await);

        let on = create_test_context_with(|c| {
            c.federation.enabled = true;
            c.federation.crawl_enabled = true;
        })
        .await;
        assert!(crawl_active(&on).await);
    }

    #[tokio::test]
    async fn request_crawl_from_asks_each_relay_and_audits_each() {
        let _g = serial().lock().await;
        let ctx = create_test_context_with(|_| {}).await;
        let good = test_relay::start(&[200]).await;
        let bad = test_relay::start(&[400]).await;

        let outcomes = request_crawl_from(
            &ctx,
            &[good.url.clone(), bad.url.clone()],
            CrawlTrigger::Manual,
            "did:plc:op",
            &[Duration::ZERO],
        )
        .await;

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].ok && outcomes[0].error.is_none());
        assert!(!outcomes[1].ok);
        assert!(outcomes[1].error.as_deref().unwrap().contains("400"));
        assert_eq!(
            good.received(),
            vec![serde_json::json!({ "hostname": "localhost:2583" })]
        );
        assert_eq!(
            audit_rows(&ctx, ACTION_CRAWL_REQUESTED).await,
            vec!["manual"]
        );
        assert_eq!(
            audit_rows(&ctx, ACTION_CRAWL_REQUEST_FAILED).await,
            vec!["manual"]
        );
    }

    #[tokio::test]
    async fn spawned_boot_request_reaches_the_live_relays_when_crawl_is_active() {
        let _g = serial().lock().await;
        let relay = test_relay::start(&[200]).await;
        let url = relay.url.clone();
        let ctx = create_test_context_with(move |c| {
            c.federation.enabled = true;
            c.federation.crawl_enabled = true;
            c.federation.relay_urls = vec![url];
        })
        .await;

        spawn_crawl_requests(&ctx, None, CrawlTrigger::Boot);
        for _ in 0..100 {
            if !relay.received().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(relay.received().len(), 1);
        // Background triggers audit as system diagnostics.
        for _ in 0..100 {
            if !audit_rows(&ctx, ACTION_CRAWL_REQUESTED).await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            audit_rows(&ctx, ACTION_CRAWL_REQUESTED).await,
            vec!["system_diagnostic"]
        );
    }

    #[tokio::test]
    async fn spawned_request_does_nothing_when_crawl_is_off() {
        let _g = serial().lock().await;
        let relay = test_relay::start(&[200]).await;
        let url = relay.url.clone();
        let ctx = create_test_context_with(move |c| {
            c.federation.enabled = true;
            c.federation.crawl_enabled = false;
            c.federation.relay_urls = vec![url];
        })
        .await;

        spawn_crawl_requests(&ctx, None, CrawlTrigger::Boot);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(relay.received().is_empty());
    }
}
