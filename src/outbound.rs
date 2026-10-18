//! Guards for requests this server makes to hosts that others name: a DID
//! document's host, a handle's host, a PDS endpoint read from a DID document.
//!
//! Such a host is chosen by whoever wrote the DID or the handle, so it may
//! point inward, at this machine or its private network. These guards keep
//! those requests on the public network (#515, #516):
//!
//! - [`PublicAddresses`], a DNS resolver for a `reqwest` client that answers
//!   only public addresses, so a name that resolves inward is not reached;
//! - [`refuse_internal_did_web`], which refuses a `did:web` whose host is an
//!   address or a loopback name before anything is fetched;
//! - [`read_limited`], which reads a response body up to a size limit.

use std::net::IpAddr;

/// A DNS resolver that answers only public addresses ([`is_internal`]).
pub(crate) struct PublicAddresses;

impl reqwest::dns::Resolve for PublicAddresses {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(public_addresses(host))
    }
}

/// The public addresses `host` resolves to; an error when it has none.
async fn public_addresses(
    host: String,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
        .await?
        .filter(|address| !is_internal(address.ip()))
        .collect();
    if addresses.is_empty() {
        return Err(format!("{host} resolves to no public address").into());
    }
    Ok(Box::new(addresses.into_iter()))
}

/// Refuse a `did:web` whose host is an address or a loopback name: its DID
/// document would be fetched from there. Any other DID passes.
pub(crate) fn refuse_internal_did_web(did: &str) -> Result<(), String> {
    let Some(rest) = did.strip_prefix("did:web:") else {
        return Ok(());
    };
    let host_and_port = rest.split(':').next().unwrap_or_default().replace("%3A", ":");
    let host = host_and_port
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map_or(host_and_port.as_str(), |(host, _)| host)
        .to_ascii_lowercase();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok() {
        return Err(format!("{did}: a did:web on an address or loopback name"));
    }
    Ok(())
}

/// Read `response`'s body, refusing one larger than `max` bytes.
pub(crate) async fn read_limited(
    mut response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    let url = response.url().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        if body.len() + chunk.len() > max {
            return Err(format!("{url}: answer larger than {max} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Addresses a public server never has.
pub(crate) fn is_internal(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local
                || (first & 0xFE00) == 0xFC00
                || (first & 0xFFC0) == 0xFE80
                || v6.to_ipv4_mapped().is_some_and(|v4| is_internal(IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses_are_recognised() {
        for internal in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_internal(internal.parse().unwrap()), "{internal}");
        }
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "100.128.0.1"] {
            assert!(!is_internal(public.parse().unwrap()), "{public}");
        }
    }

    #[tokio::test]
    async fn names_resolving_inward_get_no_address() {
        assert!(public_addresses("localhost".to_string()).await.is_err());
        assert!(public_addresses("127.0.0.1".to_string()).await.is_err());
    }
}
