//! What a private-tier record's audience reference names (#495).
//!
//! A `tools.kryphocron.feed.postPrivate` record names one audience by URI.
//! This module holds the single reader of a record's `audienceList`
//! ([`audience_reference`]) and the single test of a record URI
//! ([`parse_record_uri`], [`audience_owner`]), so every caller agrees on what
//! a record names.
//!
//! Who may write under an audience is not decided here (#536). Audiences are
//! held by the AppView as member state, not as records in a repository, so
//! there is no record to read; the AppView's read rule decides who is served
//! a reply. Locus still requires a post to name the writer's own audience, or
//! its thread's ([`crate::kryphocron_thread`]).

use proto_blue::syntax::{Did, Nsid, RecordKey};

use crate::api::kryphocron_endpoints::NSID_AUDIENCE;

/// What a record's `audienceList` field names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AudienceRef {
    /// The field is absent or null.
    None,
    /// The field is a string, or an object whose `uri` is a string.
    Uri(String),
    /// The field is present in any other form.
    Malformed,
}

/// Read a record's audience reference. Readers of private posts accept the
/// URI as a string or as an object with a string `uri`; anything else names
/// nothing a reader would honour.
pub(crate) fn audience_reference(record: &serde_json::Value) -> AudienceRef {
    match record.get("audienceList") {
        None | Some(serde_json::Value::Null) => AudienceRef::None,
        Some(serde_json::Value::String(uri)) => AudienceRef::Uri(uri.clone()),
        Some(serde_json::Value::Object(map)) => match map.get("uri") {
            Some(serde_json::Value::String(uri)) => AudienceRef::Uri(uri.clone()),
            _ => AudienceRef::Malformed,
        },
        Some(_) => AudienceRef::Malformed,
    }
}

/// The repository and collection of a record URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordUri<'a> {
    /// The DID in the URI's authority.
    pub did: &'a str,
    /// The collection NSID.
    pub collection: &'a str,
}

/// Parse `at://<did>/<collection>/<rkey>`: exactly three segments, a valid
/// DID, a valid NSID and a valid record key. Nothing is trimmed or
/// case-folded, so a URI that parses is in its only accepted spelling.
pub(crate) fn parse_record_uri(uri: &str) -> Option<RecordUri<'_>> {
    let mut segments = uri.strip_prefix("at://")?.split('/');
    let (did, collection, rkey) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    (Did::is_valid(did) && Nsid::is_valid(collection) && RecordKey::is_valid(rkey))
        .then_some(RecordUri { did, collection })
}

/// The owner of a well-formed audience URI: a record URI in the audience
/// collection. `None` for anything else.
pub(crate) fn audience_owner(audience_uri: &str) -> Option<&str> {
    parse_record_uri(audience_uri)
        .filter(|uri| uri.collection == NSID_AUDIENCE)
        .map(|uri| uri.did)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Seeding repositories for audience tests without going through the
    //! write path.
    use crate::context::AppContext;

    /// A context with the named local accounts' repositories created.
    pub(crate) async fn ctx_with_repos(dids: &[&str]) -> AppContext {
        let ctx =
            crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        for did in dids {
            ctx.actor_store.create(did).await.expect("create repo");
        }
        ctx
    }

    /// Store `record` at `at://<did>/<collection>/<rkey>` and return its URI.
    pub(crate) async fn seed(
        ctx: &AppContext,
        did: &str,
        collection: &str,
        rkey: &str,
        record: serde_json::Value,
    ) -> String {
        let lex = proto_blue::lex_json::json_to_lex(&record);
        let bytes = proto_blue::lex_cbor::encode(&lex).expect("encode record");
        seed_bytes(ctx, did, collection, rkey, &bytes).await
    }

    /// Store raw block bytes as the record at `at://<did>/<collection>/<rkey>`.
    pub(crate) async fn seed_bytes(
        ctx: &AppContext,
        did: &str,
        collection: &str,
        rkey: &str,
        bytes: &[u8],
    ) -> String {
        let uri = format!("at://{did}/{collection}/{rkey}");
        let cid = format!("cid-{collection}-{rkey}");
        ctx.actor_store
            .put_block(did, &cid, bytes)
            .await
            .expect("put block");
        ctx.actor_store
            .put_record(did, &uri, &cid, collection, rkey, "rev")
            .await
            .expect("put record");
        uri
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OWNER: &str = "did:plc:owner";

    fn audience_uri(did: &str) -> String {
        format!("at://{did}/{NSID_AUDIENCE}/aud")
    }

    #[test]
    fn audience_reference_reads_string_and_object_forms() {
        assert_eq!(audience_reference(&json!({})), AudienceRef::None);
        assert_eq!(
            audience_reference(&json!({ "audienceList": null })),
            AudienceRef::None
        );
        assert_eq!(
            audience_reference(&json!({ "audienceList": "at://x" })),
            AudienceRef::Uri("at://x".to_string())
        );
        assert_eq!(
            audience_reference(&json!({ "audienceList": { "uri": "at://y" } })),
            AudienceRef::Uri("at://y".to_string())
        );
        for malformed in [json!({}), json!({ "uri": 1 }), json!(7), json!(["at://z"])] {
            assert_eq!(
                audience_reference(&json!({ "audienceList": malformed })),
                AudienceRef::Malformed
            );
        }
    }

    #[test]
    fn audience_owner_accepts_only_a_well_formed_audience_uri() {
        assert_eq!(audience_owner(&audience_uri(OWNER)), Some(OWNER));
        let rejected = [
            // a handle as authority
            format!("at://owner.example/{NSID_AUDIENCE}/aud"),
            // another collection
            format!("at://{OWNER}/app.bsky.feed.post/aud"),
            // trailing whitespace
            format!("at://{OWNER}/{NSID_AUDIENCE}/aud "),
            // a fourth segment
            format!("at://{OWNER}/{NSID_AUDIENCE}/aud/extra"),
            // an upper-case scheme in the DID
            format!("at://DID:plc:owner/{NSID_AUDIENCE}/aud"),
            // no record key
            format!("at://{OWNER}/{NSID_AUDIENCE}"),
            format!("at://{OWNER}/{NSID_AUDIENCE}/"),
            String::new(),
        ];
        for uri in rejected {
            assert_eq!(audience_owner(&uri), None, "accepted {uri:?}");
        }
    }

    #[test]
    fn parse_record_uri_returns_repo_and_collection() {
        assert_eq!(
            parse_record_uri("at://did:plc:abc/app.bsky.feed.post/3k"),
            Some(RecordUri {
                did: "did:plc:abc",
                collection: "app.bsky.feed.post",
            })
        );
        assert_eq!(
            parse_record_uri("https://did:plc:abc/app.bsky.feed.post/3k"),
            None
        );
    }
}
