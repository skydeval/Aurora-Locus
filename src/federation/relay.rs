//! The PDS's live relay set.
//!
//! A PDS federates by being *crawled*: a relay connects to this PDS's own
//! `com.atproto.sync.subscribeRepos` and indexes it. The PDS therefore never
//! consumes a relay's firehose. The relay set is the list of relays this PDS
//! announces itself to.
//!
//! (#459) This module used to subscribe to every configured relay's
//! `subscribeRepos` (the whole network firehose, ~130 GB/day from
//! bsky.network), decode nothing (frames are DAG-CBOR; the parser only tried
//! JSON, so every frame fell through as `raw`) and act on nothing, and it
//! POSTed each local sequencer event as JSON to `<relay>/xrpc/...uploadBlob`.
//! All of that is gone.

/// The live relay set, swapped at runtime by the relay-switch primitive
/// (`api::federation_relays`, v0.9 Federation Pattern-1 Phase D, #354).
///
/// Held as `Arc<tokio::sync::Mutex<RelayClient>>` on `AppContext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClient {
    servers: Vec<String>,
}

impl RelayClient {
    /// Create a relay set from the configured relay base URLs.
    pub fn new(servers: Vec<String>) -> Self {
        Self { servers }
    }

    /// Replace the live relay set (runtime relay switch).
    ///
    /// Caller holds the `Arc<Mutex<RelayClient>>` lock.
    pub fn reconfigure(&mut self, new_relays: &[String]) {
        self.servers = new_relays.to_vec();
    }

    /// The current live relay set.
    pub fn servers(&self) -> &[String] {
        &self.servers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconfigure_swaps_the_live_set() {
        let mut client = RelayClient::new(vec!["https://r1.invalid".to_string()]);
        assert_eq!(client.servers(), ["https://r1.invalid".to_string()]);

        client.reconfigure(&[
            "https://r2.invalid".to_string(),
            "https://r3.invalid".to_string(),
        ]);
        assert_eq!(
            client.servers(),
            [
                "https://r2.invalid".to_string(),
                "https://r3.invalid".to_string()
            ]
        );

        client.reconfigure(&[]);
        assert!(client.servers().is_empty());
    }
}
