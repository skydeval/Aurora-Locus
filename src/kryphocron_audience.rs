//! Who may write under a private-tier audience (#495).
//!
//! A `tools.kryphocron.feed.postPrivate` record names one audience record.
//! This module answers one question for the write path: may this writer
//! store a post under that audience? It holds
//!
//! - the single reader of a record's `audienceList` ([`audience_reference`])
//!   and the single test of a record URI ([`parse_record_uri`],
//!   [`audience_owner`]), so every caller agrees on what a record names;
//! - the audience's mode ([`AudienceMode`]) and the rule that turns a mode
//!   and three facts into a decision ([`decide_write`]);
//! - the readers of those facts from the repositories held here
//!   ([`resolve_write`]).
//!
//! The rule follows the AppView's read-side rule for the same modes: `list`
//! consults `members`; `followers` needs a follow record by the writer naming
//! the audience's owner; `everyone` admits anyone; `nobody`, `following` and
//! unknown values admit no one. For `followers` and `everyone` a block in
//! either direction between the writer and the audience's owner denies. `list`
//! is not subject to the block test: there the owner removes a writer by
//! editing `members`.
//!
//! The audience's owner is not handled here: the caller admits it before any
//! record is read.

use proto_blue::syntax::{Did, Nsid, RecordKey};

use crate::{
    actor_store::subject_index::{SubjectCollection, SubjectMatch, SubjectProbe},
    api::kryphocron_endpoints::NSID_AUDIENCE,
    context::AppContext,
    error::PdsResult,
};

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

/// The mode of an audience record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudienceMode {
    /// Membership is the record's `members` array.
    List,
    /// Membership is following the audience's owner.
    Followers,
    /// Every account.
    Everyone,
    /// No account but the owner.
    Nobody,
    /// The accounts the owner follows. Not resolved yet.
    Following,
    /// Any other stored value.
    Unknown,
}

impl AudienceMode {
    /// Read the mode of a decoded audience record. An absent or null `mode`
    /// reads as `list`. The match is exact and case-sensitive; any other
    /// string, and any value that is not a string, is [`AudienceMode::Unknown`].
    pub(crate) fn from_record(audience: &serde_json::Value) -> Self {
        match audience.get("mode") {
            None | Some(serde_json::Value::Null) => Self::List,
            Some(serde_json::Value::String(mode)) => match mode.as_str() {
                "list" => Self::List,
                "followers" => Self::Followers,
                "everyone" => Self::Everyone,
                "nobody" => Self::Nobody,
                "following" => Self::Following,
                _ => Self::Unknown,
            },
            Some(_) => Self::Unknown,
        }
    }

    /// The fixed word recorded for this mode in an audit entry.
    pub(crate) fn as_audit_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Followers => "followers",
            Self::Everyone => "everyone",
            Self::Nobody => "nobody",
            Self::Following => "following",
            Self::Unknown => "unknown",
        }
    }
}

/// The facts the rule reads. A fact the mode does not use is left `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AudienceFacts {
    /// The writer's DID is in the audience's `members`.
    pub is_member: bool,
    /// The writer's repository holds a follow of the audience's owner.
    pub follows: bool,
    /// A block exists, in either direction, between the writer and the
    /// audience's owner.
    pub blocked: bool,
}

/// The decision for a writer who is not the audience's owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AudienceWriteDecision {
    /// The writer may store a post under this audience.
    Allowed,
    /// The mode is resolved and does not admit the writer.
    NotInAudience,
    /// The mode is one this PDS does not resolve.
    Unresolved,
}

/// The rule: one mode and its facts to a decision.
pub(crate) fn decide_write(mode: AudienceMode, facts: AudienceFacts) -> AudienceWriteDecision {
    let admitted = match mode {
        AudienceMode::List => facts.is_member,
        AudienceMode::Followers => facts.follows && !facts.blocked,
        AudienceMode::Everyone => !facts.blocked,
        AudienceMode::Nobody => false,
        AudienceMode::Following | AudienceMode::Unknown => {
            return AudienceWriteDecision::Unresolved;
        }
    };
    if admitted {
        AudienceWriteDecision::Allowed
    } else {
        AudienceWriteDecision::NotInAudience
    }
}

/// Decide whether `writer_did` may store a post under the decoded audience
/// record `audience`, owned by `owner_did`. Both repositories must be held
/// here, and the writer must not be the owner (the caller admits the owner
/// without reading anything).
///
/// Only the facts the mode uses are read, each from the subject index of one
/// repository: none for `list` beyond `members`; for `followers` the writer's
/// follow of the owner, and the blocks once the follow is found; for
/// `everyone` the blocks.
///
/// # Errors
///
/// A store error while reading a fact. It is never turned into a decision.
pub(crate) async fn resolve_write(
    ctx: &AppContext,
    writer_did: &str,
    owner_did: &str,
    audience: &serde_json::Value,
) -> PdsResult<(AudienceMode, AudienceWriteDecision)> {
    let mode = AudienceMode::from_record(audience);
    let mut facts = AudienceFacts::default();
    match mode {
        AudienceMode::List => {
            facts.is_member = audience
                .get("members")
                .and_then(|members| members.as_array())
                .is_some_and(|members| {
                    members
                        .iter()
                        .any(|member| member.as_str() == Some(writer_did))
                });
        }
        AudienceMode::Followers => {
            // One read of the writer's repository: the follow, and the
            // writer's own blocks of the owner.
            let answers = ctx
                .actor_store
                .subject_facts(
                    writer_did,
                    &[
                        SubjectProbe {
                            collection: SubjectCollection::Follow,
                            subject: owner_did,
                            matching: SubjectMatch::Exact,
                        },
                        block_probe(SubjectCollection::PublicBlock, owner_did),
                        block_probe(SubjectCollection::PrivateBlock, owner_did),
                    ],
                )
                .await?;
            facts.follows = answers.first().copied().unwrap_or(false);
            if facts.follows {
                facts.blocked = answers.iter().skip(1).any(|&b| b)
                    || blocks(ctx, owner_did, writer_did).await?;
            }
        }
        AudienceMode::Everyone => {
            facts.blocked = blocks(ctx, writer_did, owner_did).await?
                || blocks(ctx, owner_did, writer_did).await?;
        }
        AudienceMode::Nobody | AudienceMode::Following | AudienceMode::Unknown => {}
    }
    Ok((mode, decide_write(mode, facts)))
}

/// A probe for a block record naming `subject_did`. Blocks are compared
/// trimmed: the fact denies, so a padded subject still counts.
fn block_probe(collection: SubjectCollection, subject_did: &str) -> SubjectProbe<'_> {
    SubjectProbe {
        collection,
        subject: subject_did,
        matching: SubjectMatch::Trimmed,
    }
}

/// Whether the repository of `blocker_did` holds a block record naming
/// `subject_did`, in the public or the private-tier block collection.
async fn blocks(ctx: &AppContext, blocker_did: &str, subject_did: &str) -> PdsResult<bool> {
    let answers = ctx
        .actor_store
        .subject_facts(
            blocker_did,
            &[
                block_probe(SubjectCollection::PublicBlock, subject_did),
                block_probe(SubjectCollection::PrivateBlock, subject_did),
            ],
        )
        .await?;
    Ok(answers.iter().any(|&b| b))
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
    use super::test_support::{ctx_with_repos, seed, seed_bytes};
    use super::*;
    use serde_json::json;

    const WRITER: &str = "did:plc:writer";
    const OWNER: &str = "did:plc:owner";
    const NSID_FOLLOW: &str = "app.bsky.graph.follow";
    const NSID_PUBLIC_BLOCK: &str = "app.bsky.graph.block";
    const NSID_BLOCK: &str = crate::api::kryphocron_endpoints::NSID_BLOCK;

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

    #[test]
    fn mode_is_read_exactly() {
        let mode = |value: serde_json::Value| AudienceMode::from_record(&json!({ "mode": value }));
        assert_eq!(AudienceMode::from_record(&json!({})), AudienceMode::List);
        assert_eq!(mode(json!(null)), AudienceMode::List);
        assert_eq!(mode(json!("list")), AudienceMode::List);
        assert_eq!(mode(json!("followers")), AudienceMode::Followers);
        assert_eq!(mode(json!("everyone")), AudienceMode::Everyone);
        assert_eq!(mode(json!("nobody")), AudienceMode::Nobody);
        assert_eq!(mode(json!("following")), AudienceMode::Following);
        for unknown in [
            json!("Followers"),
            json!(""),
            json!("friends"),
            json!(3),
            json!([]),
        ] {
            assert_eq!(mode(unknown.clone()), AudienceMode::Unknown, "{unknown}");
        }
    }

    #[test]
    fn audit_words_are_fixed() {
        assert_eq!(AudienceMode::List.as_audit_str(), "list");
        assert_eq!(AudienceMode::Followers.as_audit_str(), "followers");
        assert_eq!(AudienceMode::Everyone.as_audit_str(), "everyone");
        assert_eq!(AudienceMode::Nobody.as_audit_str(), "nobody");
        assert_eq!(AudienceMode::Following.as_audit_str(), "following");
        assert_eq!(AudienceMode::Unknown.as_audit_str(), "unknown");
    }

    #[test]
    fn rule_per_mode() {
        use AudienceWriteDecision::{Allowed, NotInAudience, Unresolved};
        let facts = |is_member, follows, blocked| AudienceFacts {
            is_member,
            follows,
            blocked,
        };
        let cases = [
            (AudienceMode::List, facts(true, false, false), Allowed),
            (AudienceMode::List, facts(false, true, false), NotInAudience),
            // a block changes nothing for a list
            (AudienceMode::List, facts(true, false, true), Allowed),
            (AudienceMode::Followers, facts(false, true, false), Allowed),
            (
                AudienceMode::Followers,
                facts(true, false, false),
                NotInAudience,
            ),
            (
                AudienceMode::Followers,
                facts(false, true, true),
                NotInAudience,
            ),
            (AudienceMode::Everyone, facts(false, false, false), Allowed),
            (
                AudienceMode::Everyone,
                facts(true, true, true),
                NotInAudience,
            ),
            (
                AudienceMode::Nobody,
                facts(true, true, false),
                NotInAudience,
            ),
            (
                AudienceMode::Following,
                facts(true, true, false),
                Unresolved,
            ),
            (AudienceMode::Unknown, facts(true, true, false), Unresolved),
        ];
        for (mode, given, expected) in cases {
            assert_eq!(decide_write(mode, given), expected, "{mode:?} {given:?}");
        }
    }

    async fn decision(ctx: &AppContext, audience: serde_json::Value) -> AudienceWriteDecision {
        resolve_write(ctx, WRITER, OWNER, &audience)
            .await
            .expect("resolve")
            .1
    }

    #[tokio::test]
    async fn followers_admits_a_follower_until_it_unfollows() {
        let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
        let audience = json!({ "mode": "followers" });
        assert_eq!(
            decision(&ctx, audience.clone()).await,
            AudienceWriteDecision::NotInAudience
        );

        let follow = seed(&ctx, WRITER, NSID_FOLLOW, "f1", json!({ "subject": OWNER })).await;
        assert_eq!(
            decision(&ctx, audience.clone()).await,
            AudienceWriteDecision::Allowed
        );

        ctx.actor_store
            .delete_record(WRITER, &follow)
            .await
            .expect("delete follow");
        assert_eq!(
            decision(&ctx, audience).await,
            AudienceWriteDecision::NotInAudience
        );
    }

    #[tokio::test]
    async fn a_follow_must_name_the_owner_exactly() {
        let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
        seed(
            &ctx,
            WRITER,
            NSID_FOLLOW,
            "f1",
            json!({ "subject": format!("{OWNER} ") }),
        )
        .await;
        seed(
            &ctx,
            WRITER,
            NSID_FOLLOW,
            "f2",
            json!({ "subject": "did:plc:other" }),
        )
        .await;
        seed(&ctx, WRITER, NSID_FOLLOW, "f3", json!({ "subject": 5 })).await;
        seed_bytes(&ctx, WRITER, NSID_FOLLOW, "f4", b"not cbor").await;
        // the owner following the writer is not the writer following the owner
        seed(&ctx, OWNER, NSID_FOLLOW, "f1", json!({ "subject": WRITER })).await;
        assert_eq!(
            decision(&ctx, json!({ "mode": "followers" })).await,
            AudienceWriteDecision::NotInAudience
        );
    }

    #[tokio::test]
    async fn a_block_in_either_repository_and_collection_denies() {
        for mode in ["followers", "everyone"] {
            for (repo, subject) in [(OWNER, WRITER), (WRITER, OWNER)] {
                for collection in [NSID_PUBLIC_BLOCK, NSID_BLOCK] {
                    let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
                    seed(&ctx, WRITER, NSID_FOLLOW, "f1", json!({ "subject": OWNER })).await;
                    let audience = json!({ "mode": mode });
                    assert_eq!(
                        decision(&ctx, audience.clone()).await,
                        AudienceWriteDecision::Allowed,
                        "{mode} before the block"
                    );
                    // surrounding whitespace in a block's subject still denies
                    seed(
                        &ctx,
                        repo,
                        collection,
                        "b1",
                        json!({ "subject": format!(" {subject}\n") }),
                    )
                    .await;
                    assert_eq!(
                        decision(&ctx, audience).await,
                        AudienceWriteDecision::NotInAudience,
                        "{mode}: block in {repo} {collection}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_block_of_someone_else_does_not_deny() {
        let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
        seed(
            &ctx,
            OWNER,
            NSID_BLOCK,
            "b1",
            json!({ "subject": "did:plc:other" }),
        )
        .await;
        assert_eq!(
            decision(&ctx, json!({ "mode": "everyone" })).await,
            AudienceWriteDecision::Allowed
        );
    }

    #[tokio::test]
    async fn list_reads_members_and_ignores_blocks_and_follows() {
        let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
        seed(&ctx, OWNER, NSID_BLOCK, "b1", json!({ "subject": WRITER })).await;
        seed(&ctx, WRITER, NSID_FOLLOW, "f1", json!({ "subject": OWNER })).await;

        for member_audience in [
            json!({ "mode": "list", "members": [WRITER] }),
            json!({ "members": ["did:plc:other", WRITER] }),
            json!({ "mode": null, "members": [WRITER] }),
        ] {
            assert_eq!(
                decision(&ctx, member_audience).await,
                AudienceWriteDecision::Allowed
            );
        }
        for other_audience in [
            json!({ "mode": "list", "members": ["did:plc:other"] }),
            json!({ "mode": "list" }),
            json!({ "mode": "list", "members": "not an array" }),
        ] {
            assert_eq!(
                decision(&ctx, other_audience).await,
                AudienceWriteDecision::NotInAudience
            );
        }
    }

    #[tokio::test]
    async fn nobody_following_and_unknown_modes_admit_no_one() {
        let ctx = ctx_with_repos(&[WRITER, OWNER]).await;
        seed(&ctx, WRITER, NSID_FOLLOW, "f1", json!({ "subject": OWNER })).await;
        let members = json!([WRITER]);
        assert_eq!(
            decision(&ctx, json!({ "mode": "nobody", "members": members })).await,
            AudienceWriteDecision::NotInAudience
        );
        for mode in [json!("following"), json!("Followers"), json!(""), json!(1)] {
            assert_eq!(
                decision(&ctx, json!({ "mode": mode, "members": members })).await,
                AudienceWriteDecision::Unresolved
            );
        }
    }
}
