//! The registry of known peer PDS instances.
//!
//! Instances come from the configured peers (`PDS_FEDERATION_PEER_PDS`,
//! registered at startup) and dev tooling. Federated search resolves peers
//! through it, and the discovery scan re-checks it against the trusted-peer
//! allowlist.
//!
//! (#463) This module used to also "discover" instances from each relay's
//! `com.atproto.sync.listRepos`, which lists user *accounts*, not PDS hosts:
//! every scan recorded up to a page of random network accounts as PDS
//! instances with no URL, and in allowlist-only mode pushed each into the
//! pending-discoveries queue. Relay-based discovery is gone.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// How long an instance with a `last_seen` stamp stays known without being
/// seen again.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

/// PDS instance information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PdsInstance {
    /// PDS service DID
    pub did: String,

    /// Public URL of the PDS
    pub url: String,

    /// Optional display name
    pub name: Option<String>,

    /// Whether this PDS accepts registrations
    pub open_registrations: bool,

    /// Number of users (if public)
    pub user_count: Option<i64>,

    /// Last seen timestamp (unix seconds); `None` for configured peers, which
    /// never go stale
    pub last_seen: Option<i64>,

    /// Supported features
    pub features: Vec<String>,
}

/// The known-instance registry.
#[derive(Default)]
pub struct PdsDiscovery {
    known_instances: Arc<RwLock<HashMap<String, PdsInstance>>>,
}

impl PdsDiscovery {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all known PDS instances
    pub async fn get_known_instances(&self) -> Vec<PdsInstance> {
        let known = self.known_instances.read().await;
        known.values().cloned().collect()
    }

    /// Add (or replace) a known PDS instance
    pub async fn add_instance(&self, instance: PdsInstance) {
        let mut known = self.known_instances.write().await;
        known.insert(instance.did.clone(), instance);
    }

    /// Find PDS by DID
    pub async fn find_by_did(&self, did: &str) -> Option<PdsInstance> {
        let known = self.known_instances.read().await;
        known.get(did).cloned()
    }

    /// Drop instances not seen for seven days. Instances without a `last_seen`
    /// stamp (configured peers) are kept.
    pub async fn refresh_instances(&self) {
        let cutoff = chrono::Utc::now().timestamp() - STALE_AFTER_SECS;
        let mut known = self.known_instances.write().await;
        known.retain(|_, instance| instance.last_seen.is_none_or(|ts| ts > cutoff));
        info!("Instance list refreshed: {} known instances", known.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(did: &str, last_seen: Option<i64>) -> PdsInstance {
        PdsInstance {
            did: did.to_string(),
            url: format!("https://{}.example.com", did.trim_start_matches("did:plc:")),
            name: None,
            open_registrations: false,
            user_count: None,
            last_seen,
            features: vec![],
        }
    }

    #[test]
    fn test_pds_instance_serialization() {
        let instance = PdsInstance {
            did: "did:plc:test123".to_string(),
            url: "https://pds.example.com".to_string(),
            name: Some("Example PDS".to_string()),
            open_registrations: true,
            user_count: Some(100),
            last_seen: Some(1234567890),
            features: vec!["firehose".to_string(), "labels".to_string()],
        };

        let json = serde_json::to_string(&instance).unwrap();
        let deserialized: PdsInstance = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized, instance);
    }

    #[tokio::test]
    async fn new_registry_is_empty() {
        let discovery = PdsDiscovery::new();
        assert!(discovery.get_known_instances().await.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_find_instance() {
        let discovery = PdsDiscovery::new();
        discovery
            .add_instance(instance(
                "did:plc:test123",
                Some(chrono::Utc::now().timestamp()),
            ))
            .await;

        let found = discovery.find_by_did("did:plc:test123").await;
        assert_eq!(found.unwrap().url, "https://test123.example.com");
        assert!(discovery.find_by_did("did:plc:absent").await.is_none());
    }

    #[tokio::test]
    async fn refresh_drops_stale_instances_and_keeps_configured_peers() {
        let discovery = PdsDiscovery::new();
        let now = chrono::Utc::now().timestamp();
        discovery
            .add_instance(instance("did:plc:fresh", Some(now)))
            .await;
        discovery
            .add_instance(instance("did:plc:stale", Some(now - STALE_AFTER_SECS - 60)))
            .await;
        discovery
            .add_instance(instance("did:plc:configured", None))
            .await;

        discovery.refresh_instances().await;

        let mut dids: Vec<String> = discovery
            .get_known_instances()
            .await
            .into_iter()
            .map(|i| i.did)
            .collect();
        dids.sort();
        assert_eq!(dids, ["did:plc:configured", "did:plc:fresh"]);
    }
}
