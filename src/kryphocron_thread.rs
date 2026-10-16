//! Thread anchoring for private replies (#515).
//!
//! `participatePrivate` stores a reply under another account's audience. The
//! audience check ([`crate::kryphocron_audience`]) decides whether the writer
//! may write under that audience at all; this module decides whether the
//! reply belongs to a thread under it. Without it, a writer the audience
//! admits could attach a reply to an invented parent, or to a post on another
//! PDS under the same audience, and the reply would be served to the whole
//! audience as if it were part of the owner's conversation.
//!
//! A thread's audience is its root's current audience (skydeval, 2026-10-15:
//! a change of who can see a post applies downthread; A-12). The root's
//! author may move the root to another of their audiences
//! (`updatePostPrivate`); every reply, old or new, is then read under the
//! new one, and new replies are written under it.
//!
//! A reply is anchored when:
//!
//! - its `reply.parent` and `reply.root` name `tools.kryphocron.feed.postPrivate`
//!   records;
//! - the root exists, is not itself a reply, and names an audience of its own
//!   author's; that is the thread's audience, and the reply names exactly it;
//! - walking up from the parent through each post's `reply.parent`, every post
//!   exists, names an audience of the root's author (the current one, or one
//!   the thread had before a move), and agrees on the thread's root (a reply
//!   names `reply.root` as its root; a post that is not a reply is that
//!   root); and a post by the root's author is reached within the walk bound
//!   (`PDS_KRYPHOCRON_MAX_CHAIN` posts, default 16, at most 100).
//!
//! A reply by the root's author is not walked (they may write anywhere in
//! their own thread, and the AppView serves their posts without the walk),
//! but its root is still read: it must start the thread and name the audience
//! the reply names. Whether the writer may write under the thread's audience
//! at all is the audience check's question, asked of the same audience.
//!
//! Posts held here are read from the store. Posts held elsewhere are fetched
//! from their owner's PDS with `com.atproto.repo.getRecord`: at most
//! [`REMOTE_FETCH_BUDGET`] fetches, [`MAX_RECORD_BYTES`] per response, over
//! https without redirects, never to a loopback or private address, and the
//! whole check within [`CHECK_DEADLINE`]. A post that cannot be fetched counts
//! as not anchored. The AppView applies the same chain rule on reads.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::{
    api::kryphocron_endpoints::NSID_POST_PRIVATE,
    context::AppContext,
    kryphocron_audience::{audience_owner, audience_reference, parse_record_uri, AudienceRef},
};

/// The most records fetched from other PDSes for one reply. Posts held here
/// cost a local read and are bounded by the walk bound alone
/// (`PDS_KRYPHOCRON_MAX_CHAIN`, [`crate::config::KryphocronConfig`]); a chain
/// that needs more remote posts than this is refused.
pub(crate) const REMOTE_FETCH_BUDGET: usize = 16;

/// The longest one check may take, remote fetches included.
pub(crate) const CHECK_DEADLINE: Duration = Duration::from_secs(3);

/// The largest `getRecord` answer read from another PDS.
pub(crate) const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Why a reply is not anchored. Each is logged; the caller gives the one
/// refusal the audience check gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unanchored {
    /// `reply.parent` or `reply.root` is missing, or is not a record URI.
    MissingRefs,
    /// The parent is a public post: the record starts a private branch (A-13)
    /// rather than replying inside one. Only its author writes it, with
    /// `createPostPrivate`.
    BranchRoot,
    /// A post in the chain, or the root, does not exist.
    NotFound(String),
    /// A post in the chain, or the root, is not a private post naming an
    /// audience of the root's author.
    OtherAudience(String),
    /// The reply does not name the thread's audience (the root's current one).
    NotThreadAudience,
    /// The chain ended at a post that is not a reply, before the root
    /// author's post.
    NoOwnerPost,
    /// The walk bound was reached without reaching the anchor.
    TooDeep,
    /// A post on the walk is not in the thread of `reply.root`.
    RootMismatch,
    /// The root is itself a reply.
    RootIsReply,
    /// A post held elsewhere could not be fetched.
    Unreachable(String),
    /// The writer started more checks needing other PDSes than
    /// [`REMOTE_CHECKS_PER_MINUTE`] allows.
    RateLimited,
    /// The check did not finish within [`CHECK_DEADLINE`].
    TimedOut,
}

/// Where the check reads posts from.
#[async_trait::async_trait]
pub(crate) trait RecordSource: Send {
    /// The record at `uri`: `Ok(None)` when it does not exist, `Err` with a
    /// reason when it could not be read.
    async fn fetch(&mut self, uri: &str) -> Result<Option<serde_json::Value>, String>;
}

/// How many checks that need another PDS one account may start per minute.
const REMOTE_CHECKS_PER_MINUTE: u32 = 30;

/// What anchors a reply: the author of its thread's root, or of its branch's
/// root. The thread or branch is that author's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Anchor {
    pub(crate) author: String,
}

/// Check that `record`, a reply by `writer_did` naming `audience_uri`,
/// belongs to a private thread or branch whose audience is `audience_uri`,
/// and answer whose it is. Reads from the store and from other PDSes as the
/// module describes, within [`CHECK_DEADLINE`].
///
/// A reply whose parent is public is a branch root, not a reply inside
/// anything: [`Unanchored::BranchRoot`]. For a reply by a private thread's
/// root author only the root is checked: it exists, starts the thread, and
/// names `audience_uri`; the walk is not needed, since the author may write
/// anywhere in their own thread.
pub(crate) async fn check_reply_thread(
    ctx: &AppContext,
    writer_did: &str,
    record: &serde_json::Value,
    audience_uri: &str,
) -> Result<Anchor, Unanchored> {
    let mut source = StoreOrRemote {
        ctx,
        writer_did,
        remote_left: REMOTE_FETCH_BUDGET,
        admitted: false,
    };
    let verdict = tokio::time::timeout(
        CHECK_DEADLINE,
        check_thread(
            &mut source,
            record,
            audience_uri,
            Some(writer_did),
            ctx.config.kryphocron.private_max_chain,
        ),
    )
    .await
    .map_err(|_| Unanchored::TimedOut)?;
    match verdict {
        Err(Unanchored::Unreachable(reason)) if reason == RATE_LIMITED => {
            Err(Unanchored::RateLimited)
        }
        other => other,
    }
}

/// The chain rule, over any [`RecordSource`], walking at most `max_chain`
/// posts. `writer_did`, when given, lets a private thread's root author skip
/// the walk.
pub(crate) async fn check_thread(
    source: &mut dyn RecordSource,
    record: &serde_json::Value,
    audience_uri: &str,
    writer_did: Option<&str>,
    max_chain: usize,
) -> Result<Anchor, Unanchored> {
    let parent_uri = reply_uri(record, "parent").ok_or(Unanchored::MissingRefs)?;
    let root_uri = reply_uri(record, "root").ok_or(Unanchored::MissingRefs)?;
    if !is_private(&parent_uri) {
        return Err(Unanchored::BranchRoot);
    }
    let mut posts: HashMap<String, serde_json::Value> = HashMap::new();
    if is_private(&root_uri) {
        check_in_thread(
            source,
            &mut posts,
            &parent_uri,
            &root_uri,
            audience_uri,
            writer_did,
            max_chain,
        )
        .await
    } else {
        check_in_branch(source, &mut posts, &parent_uri, &root_uri, audience_uri, max_chain).await
    }
}

/// A reply inside a private thread: its root is private (A-12).
async fn check_in_thread(
    source: &mut dyn RecordSource,
    posts: &mut HashMap<String, serde_json::Value>,
    parent_uri: &str,
    root_uri: &str,
    audience_uri: &str,
    writer_did: Option<&str>,
    max_chain: usize,
) -> Result<Anchor, Unanchored> {
    let root_author = author(root_uri).ok_or(Unanchored::MissingRefs)?.to_string();

    // The thread's audience is the root's current one, an audience of the
    // root's author; the reply must name exactly it.
    let root = load(source, posts, root_uri).await?;
    require_audience_of(&root, root_uri, &root_author)?;
    if is_reply(&root) {
        return Err(Unanchored::RootIsReply);
    }
    if audience_reference(&root) != AudienceRef::Uri(audience_uri.to_string()) {
        return Err(Unanchored::NotThreadAudience);
    }
    let anchor = Anchor {
        author: root_author.clone(),
    };
    if writer_did == Some(root_author.as_str()) {
        return Ok(anchor);
    }

    // Walk up from the parent. Every post on the way names an audience of the
    // root's author (one the thread had before a move counts) and agrees on
    // the thread's root: a reply names `root_uri` as its root, and a post
    // that is not a reply is `root_uri` itself.
    let mut current = parent_uri.to_string();
    for _ in 0..max_chain {
        let post = load(source, posts, &current).await?;
        require_audience_of(&post, &current, &root_author)?;
        let agrees_on_root = if is_reply(&post) {
            reply_uri(&post, "root").as_deref() == Some(root_uri)
        } else {
            current == root_uri
        };
        if !agrees_on_root {
            return Err(Unanchored::RootMismatch);
        }
        if author(&current) == Some(root_author.as_str()) {
            return Ok(anchor);
        }
        current = reply_uri(&post, "parent")
            .filter(|parent| is_private(parent))
            .ok_or(Unanchored::NoOwnerPost)?;
    }
    Err(Unanchored::TooDeep)
}

/// A reply inside a private branch (A-13): its root is a public post, and
/// the branch's root is the topmost private post above it, whose own parent
/// is public. The branch root is named nowhere in the reply, so it is found
/// by walking up to it, within `max_chain` posts. Every post on the way
/// agrees on the public `reply.root` and names an audience of the branch
/// root's author; the reply names the branch root's current audience.
async fn check_in_branch(
    source: &mut dyn RecordSource,
    posts: &mut HashMap<String, serde_json::Value>,
    parent_uri: &str,
    root_uri: &str,
    audience_uri: &str,
    max_chain: usize,
) -> Result<Anchor, Unanchored> {
    let mut walked: Vec<String> = Vec::new();
    let mut current = parent_uri.to_string();
    let mut branch_root = None;
    for _ in 0..max_chain {
        let post = load(source, posts, &current).await?;
        if reply_uri(&post, "root").as_deref() != Some(root_uri) {
            return Err(Unanchored::RootMismatch);
        }
        let parent = reply_uri(&post, "parent").ok_or(Unanchored::NoOwnerPost)?;
        walked.push(current.clone());
        if !is_private(&parent) {
            branch_root = Some(current);
            break;
        }
        current = parent;
    }
    let branch_root = branch_root.ok_or(Unanchored::TooDeep)?;
    let branch_author = author(&branch_root).ok_or(Unanchored::MissingRefs)?.to_string();
    for uri in &walked {
        let post = posts
            .get(uri)
            .ok_or_else(|| Unanchored::NotFound(uri.clone()))?;
        require_audience_of(post, uri, &branch_author)?;
    }
    let root = posts
        .get(&branch_root)
        .ok_or_else(|| Unanchored::NotFound(branch_root.clone()))?;
    if audience_reference(root) != AudienceRef::Uri(audience_uri.to_string()) {
        return Err(Unanchored::NotThreadAudience);
    }
    Ok(Anchor {
        author: branch_author,
    })
}

/// Read a post once per check, and require it to exist and be a private post.
async fn load(
    source: &mut dyn RecordSource,
    posts: &mut HashMap<String, serde_json::Value>,
    uri: &str,
) -> Result<serde_json::Value, Unanchored> {
    let post = match posts.get(uri) {
        Some(post) => post.clone(),
        None => {
            let post = source
                .fetch(uri)
                .await
                .map_err(Unanchored::Unreachable)?
                .ok_or_else(|| Unanchored::NotFound(uri.to_string()))?;
            posts.insert(uri.to_string(), post.clone());
            post
        }
    };
    let declared_type = post.get("$type").and_then(|t| t.as_str());
    if declared_type.is_some_and(|t| t != NSID_POST_PRIVATE) {
        return Err(Unanchored::OtherAudience(uri.to_string()));
    }
    Ok(post)
}

/// Require `post` (at `uri`) to name an audience of `audience_holder`'s.
fn require_audience_of(
    post: &serde_json::Value,
    uri: &str,
    audience_holder: &str,
) -> Result<(), Unanchored> {
    match audience_reference(post) {
        AudienceRef::Uri(audience) if audience_owner(&audience) == Some(audience_holder) => Ok(()),
        _ => Err(Unanchored::OtherAudience(uri.to_string())),
    }
}

/// `reply.<which>.uri` of a post, when it is a record URI (private or not).
pub(crate) fn reply_uri(post: &serde_json::Value, which: &str) -> Option<String> {
    let uri = post.get("reply")?.get(which)?.get("uri")?.as_str()?;
    parse_record_uri(uri).map(|_| uri.to_string())
}

/// Whether a record URI names a private post.
pub(crate) fn is_private(uri: &str) -> bool {
    parse_record_uri(uri).is_some_and(|parsed| parsed.collection == NSID_POST_PRIVATE)
}

/// Whether a post is a reply (carries a non-null `reply`).
fn is_reply(post: &serde_json::Value) -> bool {
    post.get("reply").is_some_and(|reply| !reply.is_null())
}

/// The repository a post URI names.
fn author(uri: &str) -> Option<&str> {
    parse_record_uri(uri).map(|parsed| parsed.did)
}

/// The marker [`StoreOrRemote`] returns when the writer is over its limit;
/// [`check_reply_thread`] turns it into [`Unanchored::RateLimited`].
const RATE_LIMITED: &str = "remote thread checks rate-limited";

/// Posts of accounts held here from the store; others from their PDS, within
/// the remote budget and the writer's rate.
struct StoreOrRemote<'a> {
    ctx: &'a AppContext,
    writer_did: &'a str,
    remote_left: usize,
    /// Whether this check already counted against the writer's rate.
    admitted: bool,
}

#[async_trait::async_trait]
impl RecordSource for StoreOrRemote<'_> {
    async fn fetch(&mut self, uri: &str) -> Result<Option<serde_json::Value>, String> {
        let did = author(uri).ok_or_else(|| format!("not a record URI: {uri}"))?;
        if self.ctx.actor_store.exists(did).await {
            return crate::api::kryphocron_endpoints::load_record_json(self.ctx, did, uri)
                .await
                .map_err(|e| e.to_string());
        }
        if !self.admitted {
            if remote_checks().check_key(&self.writer_did.to_string()).is_err() {
                return Err(RATE_LIMITED.to_string());
            }
            self.admitted = true;
        }
        if self.remote_left == 0 {
            return Err("remote fetch budget spent".to_string());
        }
        self.remote_left -= 1;
        fetch_remote(self.ctx, uri).await
    }
}

/// Checks needing other PDSes, per writer.
fn remote_checks() -> &'static governor::DefaultKeyedRateLimiter<String> {
    static LIMITER: OnceLock<governor::DefaultKeyedRateLimiter<String>> = OnceLock::new();
    LIMITER.get_or_init(|| {
        let per_minute = std::num::NonZeroU32::new(REMOTE_CHECKS_PER_MINUTE)
            .expect("REMOTE_CHECKS_PER_MINUTE is not zero");
        governor::RateLimiter::keyed(governor::Quota::per_minute(per_minute))
    })
}

/// The HTTP client for remote reads: no redirects, bounded by the deadline,
/// and resolving names only to public addresses ([`PublicAddresses`]).
fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(CHECK_DEADLINE)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(std::sync::Arc::new(PublicAddresses))
            .user_agent(concat!("aurora-locus/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client builds with static config")
    })
}

/// A DNS resolver that answers only public addresses, so a PDS name that
/// resolves inward is not reached ([`is_internal`]).
struct PublicAddresses;

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
fn refuse_internal_did_web(did: &str) -> Result<(), String> {
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

/// Fetch `uri` from its owner's PDS, as the DID document names it.
async fn fetch_remote(ctx: &AppContext, uri: &str) -> Result<Option<serde_json::Value>, String> {
    let mut segments = uri
        .strip_prefix("at://")
        .ok_or_else(|| format!("not a record URI: {uri}"))?
        .split('/');
    let (did, collection, rkey) = match (segments.next(), segments.next(), segments.next()) {
        (Some(did), Some(collection), Some(rkey)) => (did, collection, rkey),
        _ => return Err(format!("not a record URI: {uri}")),
    };
    refuse_internal_did_web(did)?;
    let document = ctx
        .identity_resolver
        .resolve_did(did)
        .await
        .map_err(|e| format!("{did}: {e}"))?;
    let endpoint = document
        .get_service_endpoint()
        .ok_or_else(|| format!("{did}: no PDS in its DID document"))?;
    let mut url = url::Url::parse(&endpoint)
        .and_then(|base| base.join("/xrpc/com.atproto.repo.getRecord"))
        .map_err(|e| format!("{did}: PDS endpoint {endpoint}: {e}"))?;
    require_fetchable(&url)?;
    url.query_pairs_mut()
        .append_pair("repo", did)
        .append_pair("collection", collection)
        .append_pair("rkey", rkey);
    get_record_answer(url).await
}

/// GET a `getRecord` URL and read its record: `None` for a record or
/// repository the PDS says is not there.
async fn get_record_answer(url: url::Url) -> Result<Option<serde_json::Value>, String> {
    let mut response = client()
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        if body.len() + chunk.len() > MAX_RECORD_BYTES {
            return Err(format!("{url}: answer larger than {MAX_RECORD_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    let answer: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("{url}: {status}: {e}"))?;
    if status.is_success() {
        return answer
            .get("value")
            .cloned()
            .map(Some)
            .ok_or_else(|| format!("{url}: answer carries no value"));
    }
    let missing = matches!(
        answer.get("error").and_then(|e| e.as_str()),
        Some("RecordNotFound" | "RepoNotFound" | "NotFound")
    );
    if missing && (status.as_u16() == 400 || status.as_u16() == 404) {
        Ok(None)
    } else {
        Err(format!("{url}: {status}"))
    }
}

/// Only https, and never a loopback, private, link-local or unspecified
/// address written as the host. Plain http to loopback is allowed in debug
/// builds, for tests.
fn require_fetchable(url: &url::Url) -> Result<(), String> {
    let loopback_name = matches!(url.host_str(), Some(h) if h == "localhost" || h.ends_with(".localhost"));
    let address: Option<IpAddr> = match url.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        _ => None,
    };
    if url.scheme() == "http"
        && cfg!(debug_assertions)
        && (loopback_name || address.is_some_and(|a| a.is_loopback()))
    {
        return Ok(());
    }
    if url.scheme() != "https" {
        return Err(format!("{url}: not https"));
    }
    if loopback_name || address.is_some_and(is_internal) {
        return Err(format!("{url}: internal address"));
    }
    Ok(())
}

/// Addresses a PDS never has on the public network.
fn is_internal(address: IpAddr) -> bool {
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
    use serde_json::json;

    /// The walk bound the tests use: the default.
    const MAX_CHAIN: usize = crate::config::DEFAULT_PRIVATE_MAX_CHAIN;

    const OWNER: &str = "did:plc:owner";
    const MEMBER: &str = "did:plc:member";
    const OTHER: &str = "did:plc:other";

    fn audience() -> String {
        format!("at://{OWNER}/tools.kryphocron.policy.audience/aud")
    }

    fn post_uri(did: &str, rkey: &str) -> String {
        format!("at://{did}/{NSID_POST_PRIVATE}/{rkey}")
    }

    /// A post under `audience`, replying to `parent` in the thread `root`
    /// when given.
    fn post(audience: &str, thread: Option<(&str, &str)>) -> serde_json::Value {
        let mut post = json!({ "$type": NSID_POST_PRIVATE, "audienceList": audience });
        if let Some((root, parent)) = thread {
            post["reply"] = json!({ "root": { "uri": root }, "parent": { "uri": parent } });
        }
        post
    }

    struct Posts {
        posts: HashMap<String, serde_json::Value>,
        fetches: usize,
    }

    #[async_trait::async_trait]
    impl RecordSource for Posts {
        async fn fetch(&mut self, uri: &str) -> Result<Option<serde_json::Value>, String> {
            self.fetches += 1;
            Ok(self.posts.get(uri).cloned())
        }
    }

    fn posts(entries: Vec<(String, serde_json::Value)>) -> Posts {
        Posts {
            posts: entries.into_iter().collect(),
            fetches: 0,
        }
    }

    async fn check(source: &mut Posts, reply: &serde_json::Value) -> Result<(), Unanchored> {
        check_thread(source, reply, &audience(), None, MAX_CHAIN).await.map(|_| ())
    }

    #[tokio::test]
    async fn a_reply_to_the_owners_post_is_anchored() {
        let root = post_uri(OWNER, "root");
        let mut source = posts(vec![(root.clone(), post(&audience(), None))]);
        let reply = post(&audience(), Some((&root, &root)));
        assert_eq!(check(&mut source, &reply).await, Ok(()));
        assert_eq!(source.fetches, 1, "the root is the parent, read once");
    }

    #[tokio::test]
    async fn a_reply_deep_in_the_thread_is_anchored_by_the_owners_post() {
        let root = post_uri(OWNER, "root");
        let first = post_uri(MEMBER, "r1");
        let second = post_uri(OTHER, "r2");
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (first.clone(), post(&audience(), Some((&root, &root)))),
            (second.clone(), post(&audience(), Some((&root, &first)))),
        ]);
        let reply = post(&audience(), Some((&root, &second)));
        assert_eq!(check(&mut source, &reply).await, Ok(()));
    }

    #[tokio::test]
    async fn an_invented_or_foreign_parent_is_refused() {
        let root = post_uri(OWNER, "root");
        let mut source = posts(vec![(root.clone(), post(&audience(), None))]);
        let invented = post_uri(OTHER, "nothere");
        let reply = post(&audience(), Some((&root, &invented)));
        assert_eq!(
            check(&mut source, &reply).await,
            Err(Unanchored::NotFound(invented))
        );

        // A post on the walk under a third account's audience.
        let theirs = post_uri(OTHER, "theirs");
        let other_audience = format!("at://{OTHER}/tools.kryphocron.policy.audience/aud");
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (theirs.clone(), post(&other_audience, Some((&root, &root)))),
        ]);
        let reply = post(&audience(), Some((&root, &theirs)));
        assert_eq!(
            check(&mut source, &reply).await,
            Err(Unanchored::OtherAudience(theirs))
        );
    }

    /// A thread under another account's audience is that account's thread:
    /// a reply naming the owner's audience does not belong in it.
    #[tokio::test]
    async fn a_reply_must_name_the_threads_audience() {
        let elsewhere = post_uri(OTHER, "theirs");
        let other_audience = format!("at://{OTHER}/tools.kryphocron.policy.audience/aud");
        let mut source = posts(vec![(elsewhere.clone(), post(&other_audience, None))]);
        let reply = post(&audience(), Some((&elsewhere, &elsewhere)));
        assert_eq!(
            check(&mut source, &reply).await,
            Err(Unanchored::NotThreadAudience)
        );
    }

    /// The hole #515 closes: a second account elsewhere plants a top-level
    /// post under the owner's audience, as a root to reply to.
    #[tokio::test]
    async fn a_root_under_someone_elses_audience_is_refused() {
        let planted = post_uri(OTHER, "planted");
        let mut source = posts(vec![(planted.clone(), post(&audience(), None))]);
        let reply = post(&audience(), Some((&planted, &planted)));
        assert_eq!(
            check(&mut source, &reply).await,
            Err(Unanchored::OtherAudience(planted))
        );
    }

    #[tokio::test]
    async fn a_chain_longer_than_the_bound_is_refused() {
        let root = post_uri(OWNER, "root");
        let mut entries = vec![(root.clone(), post(&audience(), None))];
        let mut parent = root.clone();
        for i in 0..MAX_CHAIN {
            let uri = post_uri(MEMBER, &format!("r{i}"));
            entries.push((uri.clone(), post(&audience(), Some((&root, &parent)))));
            parent = uri;
        }
        let mut source = posts(entries);
        let reply = post(&audience(), Some((&root, &parent)));
        assert_eq!(check(&mut source, &reply).await, Err(Unanchored::TooDeep));
        assert_eq!(source.fetches, MAX_CHAIN + 1, "the root, then the walk");
    }

    #[tokio::test]
    async fn the_root_must_be_the_threads_and_not_a_reply() {
        let root = post_uri(OWNER, "root");
        let other_root = post_uri(OWNER, "another");
        let first = post_uri(MEMBER, "r1");
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (other_root.clone(), post(&audience(), None)),
            (first.clone(), post(&audience(), Some((&root, &root)))),
        ]);
        // A real parent paired with another root.
        let reply = post(&audience(), Some((&other_root, &first)));
        assert_eq!(check(&mut source, &reply).await, Err(Unanchored::RootMismatch));

        // A "root" that is itself a reply.
        let owners_reply = post_uri(OWNER, "o1");
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (owners_reply.clone(), post(&audience(), Some((&root, &root)))),
        ]);
        let reply = post(&audience(), Some((&owners_reply, &owners_reply)));
        assert_eq!(check(&mut source, &reply).await, Err(Unanchored::RootIsReply));
    }

    /// A-12: the root's author moved the root to another of their audiences.
    /// The thread's audience is now that one, downthread too: a reply must
    /// name it, wherever in the thread it replies, and replies written before
    /// the move still carry the thread.
    #[tokio::test]
    async fn after_a_move_the_thread_follows_the_roots_audience() {
        let root = post_uri(OWNER, "root");
        let before_move = post_uri(MEMBER, "b1");
        let moved_to = format!("at://{OWNER}/tools.kryphocron.policy.audience/close");
        let mut source = posts(vec![
            (root.clone(), post(&moved_to, None)),
            (before_move.clone(), post(&audience(), Some((&root, &root)))),
        ]);
        // A reply to the reply written before the move, naming the new audience.
        let reply = post(&moved_to, Some((&root, &before_move)));
        assert_eq!(
            check_thread(&mut source, &reply, &moved_to, None, MAX_CHAIN).await.map(|_| ()),
            Ok(())
        );
        // Naming the old audience, anywhere in the thread, is refused.
        for parent in [&before_move, &root] {
            let reply = post(&audience(), Some((&root, parent)));
            assert_eq!(
                check(&mut source, &reply).await,
                Err(Unanchored::NotThreadAudience),
                "{parent}"
            );
        }
    }

    /// A post on the walk that claims another root breaks the thread: a
    /// member cannot graft a planted thread onto one of the owner's roots.
    #[tokio::test]
    async fn every_post_on_the_walk_must_agree_on_the_root() {
        let planted = post_uri(OTHER, "planted");
        let owners_root = post_uri(OWNER, "root");
        let owners_reply = post_uri(OWNER, "o1");
        let member = post_uri(MEMBER, "m1");
        let mut source = posts(vec![
            (planted.clone(), post(&audience(), None)),
            (owners_root.clone(), post(&audience(), None)),
            (owners_reply.clone(), post(&audience(), Some((&planted, &planted)))),
            (member.clone(), post(&audience(), Some((&owners_root, &owners_reply)))),
        ]);
        let reply = post(&audience(), Some((&owners_root, &member)));
        assert_eq!(check(&mut source, &reply).await, Err(Unanchored::RootMismatch));
    }

    /// The root's author need not be walked, but still names the root's
    /// current audience: after a move, the old one is refused to them too.
    #[tokio::test]
    async fn the_roots_author_is_held_to_the_current_audience() {
        let root = post_uri(OWNER, "root");
        let deep = post_uri(MEMBER, "deep");
        let moved_to = format!("at://{OWNER}/tools.kryphocron.policy.audience/close");
        let mut source = posts(vec![(root.clone(), post(&moved_to, None))]);
        // Not walked: the parent is never read.
        let reply = post(&moved_to, Some((&root, &deep)));
        assert_eq!(check_thread(&mut source, &reply, &moved_to, Some(OWNER), MAX_CHAIN).await.map(|_| ()), Ok(()));
        assert_eq!(source.fetches, 1, "only the root");
        let reply = post(&audience(), Some((&root, &deep)));
        assert_eq!(
            check_thread(&mut source, &reply, &audience(), Some(OWNER), MAX_CHAIN).await.map(|_| ()),
            Err(Unanchored::NotThreadAudience)
        );
    }

    /// Two replies written before a move, under the old audience, then one
    /// after it under the new: the chain carries through all of them.
    #[tokio::test]
    async fn a_chain_mixing_audiences_from_before_and_after_a_move_anchors() {
        let root = post_uri(OWNER, "root");
        let moved_to = format!("at://{OWNER}/tools.kryphocron.policy.audience/close");
        let first = post_uri(MEMBER, "b1");
        let second = post_uri(OTHER, "b2");
        let after = post_uri(MEMBER, "a1");
        let mut source = posts(vec![
            (root.clone(), post(&moved_to, None)),
            (first.clone(), post(&audience(), Some((&root, &root)))),
            (second.clone(), post(&audience(), Some((&root, &first)))),
            (after.clone(), post(&moved_to, Some((&root, &second)))),
        ]);
        let reply = post(&moved_to, Some((&root, &after)));
        assert_eq!(
            check_thread(&mut source, &reply, &moved_to, None, MAX_CHAIN).await.map(|_| ()),
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_post_with_a_junk_audience_breaks_the_chain() {
        let root = post_uri(OWNER, "root");
        let junk = post_uri(MEMBER, "junk");
        let mut junk_post = post(&audience(), Some((&root, &root)));
        junk_post["audienceList"] = json!(42);
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (junk.clone(), junk_post),
        ]);
        let reply = post(&audience(), Some((&root, &junk)));
        assert_eq!(
            check(&mut source, &reply).await,
            Err(Unanchored::OtherAudience(junk))
        );
    }

    /// A reply on the walk that names a root but no parent ends the chain
    /// before the root's author is reached.
    #[tokio::test]
    async fn a_reply_without_a_parent_ends_the_chain() {
        let root = post_uri(OWNER, "root");
        let orphan = post_uri(MEMBER, "orphan");
        let mut orphan_post = post(&audience(), None);
        orphan_post["reply"] = json!({ "root": { "uri": root } });
        let mut source = posts(vec![
            (root.clone(), post(&audience(), None)),
            (orphan.clone(), orphan_post),
        ]);
        let reply = post(&audience(), Some((&root, &orphan)));
        assert_eq!(check(&mut source, &reply).await, Err(Unanchored::NoOwnerPost));
    }

    #[tokio::test]
    async fn an_audience_named_as_an_object_is_read_like_a_string() {
        let root = post_uri(OWNER, "root");
        let mut root_post = post(&audience(), None);
        root_post["audienceList"] = json!({ "uri": audience() });
        let mut source = posts(vec![(root.clone(), root_post)]);
        let reply = post(&audience(), Some((&root, &root)));
        assert_eq!(check(&mut source, &reply).await, Ok(()));
    }

    #[test]
    fn a_did_web_on_an_address_or_loopback_name_is_not_resolved() {
        for refused in [
            "did:web:127.0.0.1",
            "did:web:10.0.0.5",
            "did:web:localhost",
            "did:web:localhost%3A8080",
            "did:web:pds.localhost",
            "did:web:127.0.0.1:user:alice",
        ] {
            assert!(refuse_internal_did_web(refused).is_err(), "{refused}");
        }
        for allowed in [
            "did:web:example.com",
            "did:web:example.com%3A8443",
            "did:web:example.com:user:alice",
            "did:plc:abc123",
        ] {
            assert!(refuse_internal_did_web(allowed).is_ok(), "{allowed}");
        }
    }

    #[tokio::test]
    async fn missing_or_foreign_references_are_refused() {
        let mut source = posts(vec![]);
        let root = post_uri(OWNER, "root");
        for reply in [
            post(&audience(), None),
            json!({ "audienceList": audience(), "reply": { "parent": { "uri": root } } }),
            json!({ "audienceList": audience(),
                    "reply": { "root": { "uri": root }, "parent": { "uri": "not a uri" } } }),
        ] {
            assert_eq!(check(&mut source, &reply).await, Err(Unanchored::MissingRefs));
        }
        assert_eq!(source.fetches, 0);
    }

    // ---- private branches (A-13) ----

    const PUBLIC: &str = "did:plc:public";

    fn public_uri(rkey: &str) -> String {
        format!("at://{PUBLIC}/app.bsky.feed.post/{rkey}")
    }

    fn member_audience() -> String {
        format!("at://{MEMBER}/tools.kryphocron.policy.audience/aud")
    }

    /// A reply whose parent is public starts a branch; it is not a reply
    /// inside anything, and nothing is read.
    #[tokio::test]
    async fn a_private_reply_to_a_public_post_is_a_branch_root() {
        let public = public_uri("p1");
        let mut source = posts(vec![]);
        let branch_root = post(&member_audience(), Some((&public, &public)));
        assert_eq!(
            check_thread(&mut source, &branch_root, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::BranchRoot)
        );
        assert_eq!(source.fetches, 0);
    }

    /// Replies inside a branch are anchored by the branch root, found by
    /// walking up to the first private post whose parent is public.
    #[tokio::test]
    async fn a_reply_inside_a_branch_is_anchored_by_its_branch_root() {
        let public = public_uri("p1");
        let branch_root = post_uri(MEMBER, "b0");
        let inside = post_uri(OTHER, "b1");
        let mut source = posts(vec![
            (branch_root.clone(), post(&member_audience(), Some((&public, &public)))),
            (inside.clone(), post(&member_audience(), Some((&public, &branch_root)))),
        ]);
        for parent in [&branch_root, &inside] {
            let reply = post(&member_audience(), Some((&public, parent)));
            assert_eq!(
                check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
                Ok(Anchor {
                    author: MEMBER.to_string()
                }),
                "{parent}"
            );
        }
    }

    /// The branch root's author moved it to another audience: the branch
    /// follows, downthread, as a thread does (A-12).
    #[tokio::test]
    async fn a_moved_branch_follows_its_roots_audience() {
        let public = public_uri("p1");
        let branch_root = post_uri(MEMBER, "b0");
        let before_move = post_uri(OTHER, "b1");
        let moved_to = format!("at://{MEMBER}/tools.kryphocron.policy.audience/close");
        let mut source = posts(vec![
            (branch_root.clone(), post(&moved_to, Some((&public, &public)))),
            (before_move.clone(), post(&member_audience(), Some((&public, &branch_root)))),
        ]);
        let reply = post(&moved_to, Some((&public, &before_move)));
        assert_eq!(
            check_thread(&mut source, &reply, &moved_to, None, MAX_CHAIN).await.map(|_| ()),
            Ok(())
        );
        let reply = post(&member_audience(), Some((&public, &before_move)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::NotThreadAudience)
        );
    }

    #[tokio::test]
    async fn a_branch_post_under_another_authors_audience_breaks_it() {
        let public = public_uri("p1");
        let branch_root = post_uri(MEMBER, "b0");
        let planted = post_uri(OTHER, "b1");
        let other_audience = format!("at://{OTHER}/tools.kryphocron.policy.audience/aud");
        let mut source = posts(vec![
            (branch_root.clone(), post(&member_audience(), Some((&public, &public)))),
            (planted.clone(), post(&other_audience, Some((&public, &branch_root)))),
        ]);
        let reply = post(&member_audience(), Some((&public, &planted)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::OtherAudience(planted))
        );
    }

    #[tokio::test]
    async fn a_branch_post_must_agree_on_the_public_root() {
        let public = public_uri("p1");
        let elsewhere = public_uri("p2");
        let branch_root = post_uri(MEMBER, "b0");
        let mut source = posts(vec![(
            branch_root.clone(),
            post(&member_audience(), Some((&elsewhere, &elsewhere))),
        )]);
        let reply = post(&member_audience(), Some((&public, &branch_root)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::RootMismatch)
        );
    }

    /// The branch root may be the 8th post walked, the last within reach.
    #[tokio::test]
    async fn a_branch_root_at_the_bound_anchors() {
        let public = public_uri("p1");
        let branch_root = post_uri(MEMBER, "b0");
        let mut entries = vec![(
            branch_root.clone(),
            post(&member_audience(), Some((&public, &public))),
        )];
        let mut parent = branch_root.clone();
        for i in 0..MAX_CHAIN - 1 {
            let uri = post_uri(OTHER, &format!("r{i}"));
            entries.push((uri.clone(), post(&member_audience(), Some((&public, &parent)))));
            parent = uri;
        }
        let mut source = posts(entries);
        let reply = post(&member_audience(), Some((&public, &parent)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await.map(|_| ()),
            Ok(())
        );
        assert_eq!(source.fetches, MAX_CHAIN);
    }

    /// Two branch posts naming each other as parent: the walk ends at the
    /// bound, reading each once.
    #[tokio::test]
    async fn a_cycle_in_a_branch_ends_at_the_bound() {
        let public = public_uri("p1");
        let a = post_uri(MEMBER, "a");
        let b = post_uri(OTHER, "b");
        let mut source = posts(vec![
            (a.clone(), post(&member_audience(), Some((&public, &b)))),
            (b.clone(), post(&member_audience(), Some((&public, &a)))),
        ]);
        let reply = post(&member_audience(), Some((&public, &a)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::TooDeep)
        );
        assert_eq!(source.fetches, 2, "each post is read once");
    }

    /// A post from a private thread, or a top-level private post, met while
    /// walking a branch does not belong to it.
    #[tokio::test]
    async fn a_thread_post_met_in_a_branch_breaks_it() {
        let public = public_uri("p1");
        let thread_root = post_uri(MEMBER, "t0");
        let thread_reply = post_uri(OTHER, "t1");
        let mut source = posts(vec![
            (thread_root.clone(), post(&member_audience(), None)),
            (
                thread_reply.clone(),
                post(&member_audience(), Some((&thread_root, &thread_root))),
            ),
        ]);
        for parent in [&thread_reply, &thread_root] {
            let reply = post(&member_audience(), Some((&public, parent)));
            assert_eq!(
                check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
                Err(Unanchored::RootMismatch),
                "{parent}"
            );
        }
    }

    /// The branch root is not named in any record, so it must be within reach
    /// of the walk.
    #[tokio::test]
    async fn a_branch_root_beyond_the_bound_is_refused() {
        let public = public_uri("p1");
        let branch_root = post_uri(MEMBER, "b0");
        let mut entries = vec![(
            branch_root.clone(),
            post(&member_audience(), Some((&public, &public))),
        )];
        let mut parent = branch_root.clone();
        for i in 0..MAX_CHAIN {
            let uri = post_uri(OTHER, &format!("r{i}"));
            entries.push((uri.clone(), post(&member_audience(), Some((&public, &parent)))));
            parent = uri;
        }
        let mut source = posts(entries);
        let reply = post(&member_audience(), Some((&public, &parent)));
        assert_eq!(
            check_thread(&mut source, &reply, &member_audience(), None, MAX_CHAIN).await,
            Err(Unanchored::TooDeep)
        );
    }

    #[test]
    fn only_public_https_hosts_are_fetched() {
        let ok = |u: &str| require_fetchable(&url::Url::parse(u).unwrap()).is_ok();
        assert!(ok("https://pds.example.com/xrpc/x"));
        assert!(ok("https://203.0.113.9/xrpc/x"), "a public address literal");
        for refused in [
            "http://pds.example.com/xrpc/x",
            "https://localhost/xrpc/x",
            "https://pds.localhost/xrpc/x",
            "https://127.0.0.1/xrpc/x",
            "https://10.1.2.3/xrpc/x",
            "https://192.168.0.5/xrpc/x",
            "https://169.254.169.254/xrpc/x",
            "https://100.64.0.1/xrpc/x",
            "https://0.0.0.0/xrpc/x",
            "https://[::1]/xrpc/x",
            "https://[fd00::1]/xrpc/x",
            "https://[fe80::1]/xrpc/x",
            "https://[::ffff:10.0.0.1]/xrpc/x",
            "ftp://pds.example.com/x",
        ] {
            assert!(!ok(refused), "{refused} must be refused");
        }
    }

    /// Serve `count` HTTP answers of `status` with `body` on loopback, and
    /// return the base URL.
    async fn serve(status: u16, body: String, count: usize) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            for _ in 0..count {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await.unwrap();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.flush().await.unwrap();
            }
        });
        base
    }

    #[tokio::test]
    async fn a_remote_answer_is_read_within_its_bounds() {
        let found = serve(200, json!({ "uri": "x", "value": { "a": 1 } }).to_string(), 1).await;
        let url = url::Url::parse(&format!("{found}/xrpc/com.atproto.repo.getRecord")).unwrap();
        assert_eq!(get_record_answer(url).await, Ok(Some(json!({ "a": 1 }))));

        let missing = serve(400, json!({ "error": "RecordNotFound" }).to_string(), 1).await;
        let url = url::Url::parse(&format!("{missing}/xrpc/com.atproto.repo.getRecord")).unwrap();
        assert_eq!(get_record_answer(url).await, Ok(None));

        let failing = serve(500, json!({ "error": "InternalServerError" }).to_string(), 1).await;
        let url = url::Url::parse(&format!("{failing}/xrpc/com.atproto.repo.getRecord")).unwrap();
        assert!(get_record_answer(url).await.is_err());

        let huge = json!({ "value": { "text": "x".repeat(MAX_RECORD_BYTES) } }).to_string();
        let large = serve(200, huge, 1).await;
        let url = url::Url::parse(&format!("{large}/xrpc/com.atproto.repo.getRecord")).unwrap();
        assert!(get_record_answer(url).await.is_err(), "over the size bound");
    }
}
