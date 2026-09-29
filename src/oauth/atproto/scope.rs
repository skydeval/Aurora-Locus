//! atproto-OAuth scope vocabulary (Arc 2 Phase β.3, chainlink #420 /
//! LOCKED design §3.2 / R1 F-3.5; granular permissions #478).
//!
//! atproto OAuth uses its own scope grammar, distinct from Aurora's internal
//! colon-namespaced capability scopes in [`crate::oauth::scope`]:
//!
//! - four **static** scopes: `atproto` (the base scope, required),
//!   `transition:generic` (the app-password-equivalent surface),
//!   `transition:email` (read the account's email) and `transition:chat.bsky`
//!   (chat);
//! - **granular permissions** of the form `prefix[:positional][?k=v&k=v]`:
//!   `account:<email|repo|status>[?action=read|manage]`,
//!   `identity:<handle|*>`, `repo:<collection>[?action=create|update|delete]`,
//!   `rpc:<lxm>?aud=<did#service|*>`, `blob:<mime>` and `include:<nsid>`.
//!
//! Parsing follows the reference authorization server: a token that is not a
//! well-formed atproto scope is dropped from the request (not an error), the
//! base `atproto` scope must be present, and `openid` is refused because
//! OpenID Connect is not part of atproto OAuth. `include:` permission sets are
//! parsed but dropped: they name a lexicon-published set of permissions that
//! this server does not resolve, so it grants nothing for them.
//!
//! A [`ScopeSet`] keeps each accepted token exactly as the client wrote it, so
//! the scope stored on the issued token (and echoed in the token response)
//! names precisely what was granted. The `allows_*` checks evaluate the set
//! with the transition mappings the reference PDS uses: `transition:generic`
//! grants every repo write, every blob upload and every rpc call except
//! `chat.bsky.*`; `transition:chat.bsky` grants the `chat.bsky.*` calls;
//! `transition:email` grants reading the email address.

use std::fmt;
use std::str::FromStr;

/// The error returned when a scope token is not a recognised static scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScope(pub String);

impl fmt::Display for UnknownScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown atproto scope: {}", self.0)
    }
}

impl std::error::Error for UnknownScope {}

/// A static atproto-OAuth scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtprotoScope {
    /// `atproto`: the base scope; presence is required for a usable session.
    Atproto,
    /// `transition:generic`: the app-password-equivalent surface.
    TransitionGeneric,
    /// `transition:email`: read the account's email address.
    TransitionEmail,
    /// `transition:chat.bsky`: chat (DM) access.
    TransitionChatBsky,
}

impl AtprotoScope {
    /// The canonical bare-token spelling of this scope.
    pub fn as_str(&self) -> &'static str {
        match self {
            AtprotoScope::Atproto => "atproto",
            AtprotoScope::TransitionGeneric => "transition:generic",
            AtprotoScope::TransitionEmail => "transition:email",
            AtprotoScope::TransitionChatBsky => "transition:chat.bsky",
        }
    }

    /// Every static scope, as advertised in the AS metadata
    /// (`scopes_supported`), in canonical order.
    pub fn all() -> [AtprotoScope; 4] {
        [
            AtprotoScope::Atproto,
            AtprotoScope::TransitionEmail,
            AtprotoScope::TransitionGeneric,
            AtprotoScope::TransitionChatBsky,
        ]
    }

    /// Parse a space-separated scope string into the set of scopes it grants.
    ///
    /// Tokens that are not well-formed atproto scopes are dropped, as the
    /// reference authorization server does; duplicates collapse. The result
    /// must include the base `atproto` scope, and `openid` is refused.
    pub fn parse_set(s: &str) -> Result<ScopeSet, ScopeParseError> {
        let mut saw_token = false;
        let mut set = ScopeSet(Vec::new());
        for token in s.split_whitespace() {
            saw_token = true;
            if token == "openid" {
                return Err(ScopeParseError::Unsupported(token.to_string()));
            }
            match ScopeToken::parse(token) {
                Some(parsed) => set.insert(token, parsed),
                None => tracing::debug!(scope = token, "dropping unsupported OAuth scope"),
            }
        }
        if !saw_token {
            return Err(ScopeParseError::Empty);
        }
        if !set.has(AtprotoScope::Atproto) {
            return Err(ScopeParseError::MissingBase);
        }
        Ok(set)
    }
}

impl fmt::Display for AtprotoScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AtprotoScope {
    type Err = UnknownScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "atproto" => Ok(AtprotoScope::Atproto),
            "transition:generic" => Ok(AtprotoScope::TransitionGeneric),
            "transition:email" => Ok(AtprotoScope::TransitionEmail),
            "transition:chat.bsky" => Ok(AtprotoScope::TransitionChatBsky),
            other => Err(UnknownScope(other.to_string())),
        }
    }
}

/// An `account:` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAttr {
    /// The account's email address.
    Email,
    /// The account's repository as a whole (export / import).
    Repo,
    /// The account's hosting status (active / deactivated).
    Status,
}

/// What an `account:` permission allows on its attribute. `Manage` implies
/// `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAction {
    /// See the attribute.
    Read,
    /// See and change the attribute.
    Manage,
}

/// An `identity:` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityAttr {
    /// The handle.
    Handle,
    /// The whole identity: handle and DID document.
    All,
}

/// A record write a `repo:` permission can allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoAction {
    /// Create records.
    Create,
    /// Update records.
    Update,
    /// Delete records.
    Delete,
}

impl RepoAction {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "create" => Some(RepoAction::Create),
            "update" => Some(RepoAction::Update),
            "delete" => Some(RepoAction::Delete),
            _ => None,
        }
    }

    /// The action's name in a scope (`create`, `update`, `delete`).
    pub fn as_str(&self) -> &'static str {
        match self {
            RepoAction::Create => "create",
            RepoAction::Update => "update",
            RepoAction::Delete => "delete",
        }
    }
}

/// A granular atproto permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// `account:<attr>[?action=read|manage]`
    Account {
        attr: AccountAttr,
        action: AccountAction,
    },
    /// `identity:<handle|*>`
    Identity { attr: IdentityAttr },
    /// `repo:<collection>[?collection=..][&action=..]`; `*` is every
    /// collection. With no `action`, every action.
    Repo {
        collections: Vec<String>,
        actions: Vec<RepoAction>,
    },
    /// `rpc:<lxm>[?lxm=..]&aud=<did#service|*>`; `*` is every method.
    Rpc { lxms: Vec<String>, aud: String },
    /// `blob:<mime>[?accept=..]`, with `type/subtype`, `type/*` or `*/*`.
    Blob { accept: Vec<String> },
}

/// One accepted scope token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeToken {
    /// A static scope.
    Static(AtprotoScope),
    /// A granular permission.
    Permission(Permission),
}

impl ScopeToken {
    /// Parse one scope token. `None` for anything that is not a well-formed
    /// atproto scope this server can grant (including `include:` sets).
    pub fn parse(token: &str) -> Option<ScopeToken> {
        if let Ok(scope) = AtprotoScope::from_str(token) {
            return Some(ScopeToken::Static(scope));
        }
        let (head, query) = match token.split_once('?') {
            Some((head, query)) => (head, Some(query)),
            None => (token, None),
        };
        let (prefix, positional) = match head.split_once(':') {
            Some((prefix, positional)) => (prefix, Some(decode(positional)?)),
            None => (head, None),
        };
        let params = Params::parse(query)?;
        let permission = match prefix {
            "account" => parse_account(positional, params)?,
            "identity" => parse_identity(positional, params)?,
            "repo" => parse_repo(positional, params)?,
            "rpc" => parse_rpc(positional, params)?,
            "blob" => parse_blob(positional, params)?,
            _ => return None,
        };
        Some(ScopeToken::Permission(permission))
    }

    /// A sentence describing what this scope allows, for the consent screen.
    pub fn describe(&self) -> String {
        match self {
            ScopeToken::Static(AtprotoScope::Atproto) => {
                "Sign in as your account (your handle and DID)".to_string()
            }
            ScopeToken::Static(AtprotoScope::TransitionGeneric) => {
                "Create, change and delete your posts, profile and other public data, \
                 upload files, and use other atproto services (except chat) as you"
                    .to_string()
            }
            ScopeToken::Static(AtprotoScope::TransitionEmail) => {
                "See your email address".to_string()
            }
            ScopeToken::Static(AtprotoScope::TransitionChatBsky) => {
                "Read and send your Bluesky chat messages".to_string()
            }
            ScopeToken::Permission(p) => describe_permission(p),
        }
    }
}

fn describe_permission(p: &Permission) -> String {
    match p {
        Permission::Account { attr, action } => match (attr, action) {
            (AccountAttr::Email, AccountAction::Read) => "See your email address".to_string(),
            (AccountAttr::Email, AccountAction::Manage) => {
                "See and change your email address".to_string()
            }
            (AccountAttr::Status, AccountAction::Read) => {
                "See whether your account is active".to_string()
            }
            (AccountAttr::Status, AccountAction::Manage) => {
                "See your account's status, and deactivate or reactivate your account".to_string()
            }
            (AccountAttr::Repo, AccountAction::Read) => "Export your repository".to_string(),
            (AccountAttr::Repo, AccountAction::Manage) => {
                "Export your repository and import data into it".to_string()
            }
        },
        Permission::Identity {
            attr: IdentityAttr::Handle,
        } => "Change your handle".to_string(),
        Permission::Identity {
            attr: IdentityAttr::All,
        } => "Change your handle and your DID document (signing keys and services)".to_string(),
        Permission::Repo {
            collections,
            actions,
        } => {
            let verbs: Vec<&str> = actions.iter().map(RepoAction::as_str).collect();
            let what = if collections.iter().any(|c| c == "*") {
                "records of every type".to_string()
            } else {
                format!("records of type {}", collections.join(", "))
            };
            format!(
                "{} {what} in your repository",
                capitalize(&verbs.join(", "))
            )
        }
        Permission::Rpc { lxms, aud } => {
            let methods = if lxms.iter().any(|l| l == "*") {
                "any method".to_string()
            } else {
                lxms.join(", ")
            };
            let service = if aud == "*" {
                "any service".to_string()
            } else {
                aud.clone()
            };
            format!("Call {methods} on {service} as you")
        }
        Permission::Blob { accept } => {
            if accept.iter().any(|a| a == "*/*") {
                "Upload files of any type".to_string()
            } else {
                format!("Upload files of type {}", accept.join(", "))
            }
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Percent-decode a scope component (the reference parses with
/// `URLSearchParams` / `decodeURIComponent`). `None` for invalid UTF-8.
fn decode(s: &str) -> Option<String> {
    urlencoding::decode(s).ok().map(|c| c.into_owned())
}

/// A scope's query parameters, in order.
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(query: Option<&str>) -> Option<Params> {
        let Some(query) = query else {
            return Some(Params(Vec::new()));
        };
        if query.is_empty() {
            return None;
        }
        let pairs = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Some(Params(pairs))
    }

    /// Every value of `key`.
    fn all(&self, key: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// At most one value of `key`; `Err` if it appears more than once.
    fn single(&self, key: &str) -> Result<Option<String>, ()> {
        let mut values = self.all(key);
        match values.len() {
            0 => Ok(None),
            1 => Ok(values.pop()),
            _ => Err(()),
        }
    }

    /// True when every key is one of `allowed`.
    fn only(&self, allowed: &[&str]) -> bool {
        self.0.iter().all(|(k, _)| allowed.contains(&k.as_str()))
    }
}

/// The permission's subject: the positional value, or the one named
/// parameter (not both, and exactly one).
fn single_subject(positional: Option<String>, params: &Params, key: &str) -> Option<String> {
    match (positional, params.single(key).ok()?) {
        (Some(p), None) => Some(p),
        (None, Some(q)) => Some(q),
        _ => None,
    }
}

/// The permission's subjects: the positional value plus every named
/// parameter, at least one.
fn many_subjects(positional: Option<String>, params: &Params, key: &str) -> Option<Vec<String>> {
    let mut values: Vec<String> = positional.into_iter().collect();
    for v in params.all(key) {
        if !values.contains(&v) {
            values.push(v);
        }
    }
    (!values.is_empty()).then_some(values)
}

fn is_nsid(s: &str) -> bool {
    proto_blue::syntax::Nsid::new(s).is_ok()
}

fn parse_account(positional: Option<String>, params: Params) -> Option<Permission> {
    if !params.only(&["attr", "action"]) {
        return None;
    }
    let attr = match single_subject(positional, &params, "attr")?.as_str() {
        "email" => AccountAttr::Email,
        "repo" => AccountAttr::Repo,
        "status" => AccountAttr::Status,
        _ => return None,
    };
    let action = match params.single("action").ok()?.as_deref() {
        None | Some("read") => AccountAction::Read,
        Some("manage") => AccountAction::Manage,
        Some(_) => return None,
    };
    Some(Permission::Account { attr, action })
}

fn parse_identity(positional: Option<String>, params: Params) -> Option<Permission> {
    if !params.only(&["attr"]) {
        return None;
    }
    let attr = match single_subject(positional, &params, "attr")?.as_str() {
        "handle" => IdentityAttr::Handle,
        "*" => IdentityAttr::All,
        _ => return None,
    };
    Some(Permission::Identity { attr })
}

fn parse_repo(positional: Option<String>, params: Params) -> Option<Permission> {
    if !params.only(&["collection", "action"]) {
        return None;
    }
    let collections = many_subjects(positional, &params, "collection")?;
    if !collections.iter().all(|c| c == "*" || is_nsid(c)) {
        return None;
    }
    let mut actions = Vec::new();
    for a in params.all("action") {
        let action = RepoAction::parse(&a)?;
        if !actions.contains(&action) {
            actions.push(action);
        }
    }
    if actions.is_empty() {
        actions = vec![RepoAction::Create, RepoAction::Update, RepoAction::Delete];
    }
    Some(Permission::Repo {
        collections,
        actions,
    })
}

fn parse_rpc(positional: Option<String>, params: Params) -> Option<Permission> {
    if !params.only(&["lxm", "aud"]) {
        return None;
    }
    let lxms = many_subjects(positional, &params, "lxm")?;
    if !lxms.iter().all(|l| l == "*" || is_nsid(l)) {
        return None;
    }
    let aud = params.single("aud").ok()??;
    if aud != "*" && !is_service_ref(&aud) {
        return None;
    }
    // Any method on any service is not a grantable permission.
    if aud == "*" && lxms.iter().any(|l| l == "*") {
        return None;
    }
    Some(Permission::Rpc { lxms, aud })
}

/// `did:<method>:<id>#<service>`.
fn is_service_ref(s: &str) -> bool {
    match s.split_once('#') {
        Some((did, service)) => {
            !service.is_empty()
                && did.starts_with("did:")
                && did.splitn(3, ':').filter(|p| !p.is_empty()).count() == 3
        }
        None => false,
    }
}

fn parse_blob(positional: Option<String>, params: Params) -> Option<Permission> {
    if !params.only(&["accept"]) {
        return None;
    }
    let accept = many_subjects(positional, &params, "accept")?;
    if !accept.iter().all(|m| is_mime_pattern(m)) {
        return None;
    }
    Some(Permission::Blob { accept })
}

/// `type/subtype`, `type/*` or `*/*`.
fn is_mime_pattern(s: &str) -> bool {
    let token = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
    };
    match s.split_once('/') {
        Some(("*", "*")) => true,
        Some((ty, "*")) => token(ty),
        Some((ty, sub)) => token(ty) && token(sub),
        None => false,
    }
}

fn mime_matches(pattern: &str, mime: &str) -> bool {
    let mime = mime.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.split_once('/') {
        Some(("*", "*")) => true,
        Some((ty, "*")) => mime.split_once('/').is_some_and(|(t, _)| t == ty),
        _ => pattern == mime,
    }
}

/// Why a scope string was refused. Distinct variants so the authorize / PAR
/// endpoints can surface a precise `invalid_scope` reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeParseError {
    /// No scope tokens at all.
    Empty,
    /// The required base `atproto` scope was absent.
    MissingBase,
    /// A scope atproto OAuth does not support (`openid`).
    Unsupported(String),
}

impl fmt::Display for ScopeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeParseError::Empty => f.write_str("scope must name at least one scope"),
            ScopeParseError::MissingBase => {
                f.write_str("scope must include the base 'atproto' scope")
            }
            ScopeParseError::Unsupported(s) => {
                write!(f, "scope '{s}' is not supported by atproto OAuth")
            }
        }
    }
}

impl std::error::Error for ScopeParseError {}

/// The scopes granted to a client: each accepted token as the client wrote it,
/// de-duplicated, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(Vec<(String, ScopeToken)>);

impl ScopeSet {
    /// The scopes a stored scope string grants. Unlike
    /// [`AtprotoScope::parse_set`] this never fails: it reads the scope of an
    /// issued token, where unknown tokens simply grant nothing.
    pub fn from_granted(s: &str) -> ScopeSet {
        let mut set = ScopeSet(Vec::new());
        for token in s.split_whitespace() {
            if let Some(parsed) = ScopeToken::parse(token) {
                set.insert(token, parsed);
            }
        }
        set
    }

    fn insert(&mut self, token: &str, parsed: ScopeToken) {
        if !self.0.iter().any(|(t, _)| t == token) {
            self.0.push((token.to_string(), parsed));
        }
    }

    /// The space-separated scope string: what gets persisted on the
    /// authorization request and the issued `token` row, and echoed in the
    /// token response.
    pub fn to_canonical_string(&self) -> String {
        self.0
            .iter()
            .map(|(t, _)| t.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The accepted tokens with their parsed meaning, in order.
    pub fn tokens(&self) -> impl Iterator<Item = (&str, &ScopeToken)> {
        self.0.iter().map(|(t, p)| (t.as_str(), p))
    }

    /// True when the static scope `scope` was granted.
    pub fn has(&self, scope: AtprotoScope) -> bool {
        self.0.iter().any(|(_, p)| *p == ScopeToken::Static(scope))
    }

    fn permissions(&self) -> impl Iterator<Item = &Permission> {
        self.0.iter().filter_map(|(_, p)| match p {
            ScopeToken::Permission(permission) => Some(permission),
            ScopeToken::Static(_) => None,
        })
    }

    /// May the client `action` records in `collection`?
    pub fn allows_repo(&self, collection: &str, action: RepoAction) -> bool {
        self.has(AtprotoScope::TransitionGeneric)
            || self.permissions().any(|p| match p {
                Permission::Repo {
                    collections,
                    actions,
                } => {
                    actions.contains(&action)
                        && collections.iter().any(|c| c == "*" || c == collection)
                }
                _ => false,
            })
    }

    /// May the client upload a blob of type `mime`?
    pub fn allows_blob(&self, mime: &str) -> bool {
        self.has(AtprotoScope::TransitionGeneric)
            || self.permissions().any(|p| match p {
                Permission::Blob { accept } => accept.iter().any(|a| mime_matches(a, mime)),
                _ => false,
            })
    }

    /// May the client call `lxm` on the service `aud` (`did#service`) as the
    /// account?
    pub fn allows_rpc(&self, lxm: &str, aud: &str) -> bool {
        let chat = lxm.starts_with("chat.bsky.");
        if chat && self.has(AtprotoScope::TransitionChatBsky) {
            return true;
        }
        if !chat && self.has(AtprotoScope::TransitionGeneric) {
            return true;
        }
        self.permissions().any(|p| match p {
            Permission::Rpc { lxms, aud: allowed } => {
                (allowed == "*" || allowed == aud) && lxms.iter().any(|l| l == "*" || l == lxm)
            }
            _ => false,
        })
    }

    /// May the client `action` the account's `attr`?
    pub fn allows_account(&self, attr: AccountAttr, action: AccountAction) -> bool {
        if attr == AccountAttr::Email
            && action == AccountAction::Read
            && self.has(AtprotoScope::TransitionEmail)
        {
            return true;
        }
        self.permissions().any(|p| match p {
            Permission::Account {
                attr: granted,
                action: granted_action,
            } => {
                *granted == attr
                    && (*granted_action == AccountAction::Manage || action == AccountAction::Read)
            }
            _ => false,
        })
    }

    /// May the client change the account's identity `attr`?
    pub fn allows_identity(&self, attr: IdentityAttr) -> bool {
        self.permissions().any(|p| match p {
            Permission::Identity { attr: granted } => {
                *granted == IdentityAttr::All || *granted == attr
            }
            _ => false,
        })
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

/// Translate an atproto-OAuth scope string into the **internal**-vocabulary
/// scope string the XRPC handlers evaluate via
/// `crate::oauth::require_scope` / `api::middleware::enforce_scope` (Arc 2
/// Phase ε.4, scope-α: translate-at-gate).
///
/// Only whole-surface grants translate: `transition:generic` grants the
/// internal repo-write family (`atproto:repo.*`) and blob upload
/// (`atproto:blob.upload`). Granular permissions are checked against the
/// [`ScopeSet`] itself where the handler knows the collection, blob type or
/// method, so they add nothing here. Admin is never granted.
///
/// Input need not be a validated [`ScopeSet`]: it reads the raw stored token
/// scope string, ignoring unknown tokens.
pub fn to_internal_scope(atproto_scope: &str) -> String {
    let mut internal: Vec<&str> = Vec::new();
    for token in atproto_scope.split_whitespace() {
        if token == AtprotoScope::TransitionGeneric.as_str() {
            for cap in ["atproto:repo.*", "atproto:blob.upload"] {
                if !internal.contains(&cap) {
                    internal.push(cap);
                }
            }
        }
    }
    internal.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope string the Blacksky client requests (#478).
    const BLACKSKY: &str = "atproto transition:generic transition:email transition:chat.bsky \
                            identity:handle account:email?action=manage account:status?action=manage";

    fn perm(token: &str) -> Permission {
        match ScopeToken::parse(token) {
            Some(ScopeToken::Permission(p)) => p,
            other => panic!("{token} parsed as {other:?}"),
        }
    }

    #[test]
    fn from_str_recognises_each_static_scope() {
        for scope in AtprotoScope::all() {
            assert_eq!(scope.as_str().parse(), Ok(scope));
        }
        assert_eq!(
            "atproto:repo".parse::<AtprotoScope>(),
            Err(UnknownScope("atproto:repo".to_string()))
        );
    }

    #[test]
    fn all_lists_the_four_static_scopes() {
        let all: Vec<&str> = AtprotoScope::all().iter().map(|s| s.as_str()).collect();
        assert_eq!(
            all,
            [
                "atproto",
                "transition:email",
                "transition:generic",
                "transition:chat.bsky"
            ]
        );
    }

    #[test]
    fn blacksky_scope_string_is_granted_verbatim() {
        let set = AtprotoScope::parse_set(BLACKSKY).unwrap();
        assert_eq!(
            set.to_canonical_string(),
            BLACKSKY.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        assert!(set.allows_account(AccountAttr::Email, AccountAction::Manage));
        assert!(set.allows_account(AccountAttr::Status, AccountAction::Read));
        assert!(!set.allows_account(AccountAttr::Repo, AccountAction::Read));
        assert!(set.allows_identity(IdentityAttr::Handle));
        assert!(!set.allows_identity(IdentityAttr::All));
        assert!(set.allows_rpc(
            "chat.bsky.convo.listConvos",
            "did:web:api.bsky.chat#bsky_chat"
        ));
    }

    #[test]
    fn parse_set_dedups_and_drops_unknown_tokens() {
        let set = AtprotoScope::parse_set(
            "atproto  transition:generic atproto bogus rpc:foo include:com.example.set",
        )
        .unwrap();
        assert_eq!(set.to_canonical_string(), "atproto transition:generic");
    }

    #[test]
    fn parse_set_requires_base_scope_and_refuses_openid() {
        assert_eq!(
            AtprotoScope::parse_set("transition:generic"),
            Err(ScopeParseError::MissingBase)
        );
        // Only unsupported tokens: dropped, so the base is missing.
        assert_eq!(
            AtprotoScope::parse_set("bogus"),
            Err(ScopeParseError::MissingBase)
        );
        assert_eq!(AtprotoScope::parse_set("   "), Err(ScopeParseError::Empty));
        assert_eq!(
            AtprotoScope::parse_set("atproto openid"),
            Err(ScopeParseError::Unsupported("openid".to_string()))
        );
    }

    #[test]
    fn account_permissions_parse() {
        assert_eq!(
            perm("account:email"),
            Permission::Account {
                attr: AccountAttr::Email,
                action: AccountAction::Read
            }
        );
        assert_eq!(
            perm("account:status?action=manage"),
            Permission::Account {
                attr: AccountAttr::Status,
                action: AccountAction::Manage
            }
        );
        assert_eq!(
            perm("account?attr=repo&action=read"),
            Permission::Account {
                attr: AccountAttr::Repo,
                action: AccountAction::Read
            }
        );
        for bad in [
            "account",
            "account:phone",
            "account:email?action=write",
            "account:email?action=read&action=manage",
            "account:email?attr=status",
            "account:email?x=1",
        ] {
            assert_eq!(ScopeToken::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn identity_permissions_parse() {
        assert_eq!(
            perm("identity:handle"),
            Permission::Identity {
                attr: IdentityAttr::Handle
            }
        );
        assert_eq!(
            perm("identity:*"),
            Permission::Identity {
                attr: IdentityAttr::All
            }
        );
        assert_eq!(ScopeToken::parse("identity:did"), None);
        assert_eq!(ScopeToken::parse("identity"), None);
    }

    #[test]
    fn repo_permissions_parse() {
        assert_eq!(
            perm("repo:app.bsky.feed.post"),
            Permission::Repo {
                collections: vec!["app.bsky.feed.post".to_string()],
                actions: vec![RepoAction::Create, RepoAction::Update, RepoAction::Delete],
            }
        );
        assert_eq!(
            perm("repo?collection=app.bsky.feed.post&collection=app.bsky.feed.like&action=create"),
            Permission::Repo {
                collections: vec![
                    "app.bsky.feed.post".to_string(),
                    "app.bsky.feed.like".to_string()
                ],
                actions: vec![RepoAction::Create],
            }
        );
        assert_eq!(
            perm("repo:*?action=delete"),
            Permission::Repo {
                collections: vec!["*".to_string()],
                actions: vec![RepoAction::Delete],
            }
        );
        for bad in [
            "repo",
            "repo:notansid",
            "repo:app.bsky.feed.post?action=read",
        ] {
            assert_eq!(ScopeToken::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn rpc_permissions_parse() {
        assert_eq!(
            perm("rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app%23bsky_appview"),
            Permission::Rpc {
                lxms: vec!["app.bsky.feed.getTimeline".to_string()],
                aud: "did:web:api.bsky.app#bsky_appview".to_string(),
            }
        );
        assert_eq!(
            perm("rpc:*?aud=did:web:api.bsky.app%23bsky_appview"),
            Permission::Rpc {
                lxms: vec!["*".to_string()],
                aud: "did:web:api.bsky.app#bsky_appview".to_string(),
            }
        );
        for bad in [
            "rpc:app.bsky.feed.getTimeline",
            "rpc:*?aud=*",
            "rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
            "rpc:nope?aud=*",
        ] {
            assert_eq!(ScopeToken::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn blob_and_include_permissions() {
        assert_eq!(
            perm("blob:image/*?accept=video/mp4"),
            Permission::Blob {
                accept: vec!["image/*".to_string(), "video/mp4".to_string()],
            }
        );
        assert_eq!(ScopeToken::parse("blob:*/png"), None);
        assert_eq!(ScopeToken::parse("blob"), None);
        // Permission sets are not resolved, so they grant nothing.
        assert_eq!(ScopeToken::parse("include:app.bsky.authFullApp"), None);
    }

    #[test]
    fn transition_generic_grants_repo_blob_and_non_chat_rpc() {
        let set = ScopeSet::from_granted("atproto transition:generic");
        assert!(set.allows_repo("app.bsky.feed.post", RepoAction::Delete));
        assert!(set.allows_blob("video/mp4"));
        assert!(set.allows_rpc(
            "app.bsky.feed.getTimeline",
            "did:web:api.bsky.app#bsky_appview"
        ));
        assert!(!set.allows_rpc(
            "chat.bsky.convo.listConvos",
            "did:web:api.bsky.chat#bsky_chat"
        ));
        assert!(!set.allows_account(AccountAttr::Email, AccountAction::Read));
        assert!(!set.allows_identity(IdentityAttr::Handle));
    }

    #[test]
    fn base_scope_alone_grants_nothing() {
        let set = ScopeSet::from_granted("atproto");
        assert!(!set.allows_repo("app.bsky.feed.post", RepoAction::Create));
        assert!(!set.allows_blob("image/png"));
        assert!(!set.allows_rpc(
            "app.bsky.feed.getTimeline",
            "did:web:api.bsky.app#bsky_appview"
        ));
        assert!(!set.allows_account(AccountAttr::Email, AccountAction::Read));
    }

    #[test]
    fn granular_permissions_grant_exactly_what_they_name() {
        let set = ScopeSet::from_granted(
            "atproto repo:app.bsky.feed.post?action=create blob:image/* \
             rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app%23bsky_appview \
             account:email transition:email",
        );
        assert!(set.allows_repo("app.bsky.feed.post", RepoAction::Create));
        assert!(!set.allows_repo("app.bsky.feed.post", RepoAction::Delete));
        assert!(!set.allows_repo("app.bsky.feed.like", RepoAction::Create));
        assert!(set.allows_blob("image/jpeg"));
        assert!(!set.allows_blob("video/mp4"));
        assert!(set.allows_rpc(
            "app.bsky.feed.getTimeline",
            "did:web:api.bsky.app#bsky_appview"
        ));
        assert!(!set.allows_rpc(
            "app.bsky.feed.getTimeline",
            "did:web:evil.example#bsky_appview"
        ));
        assert!(!set.allows_rpc(
            "app.bsky.feed.getAuthorFeed",
            "did:web:api.bsky.app#bsky_appview"
        ));
        assert!(set.allows_account(AccountAttr::Email, AccountAction::Read));
        assert!(!set.allows_account(AccountAttr::Email, AccountAction::Manage));
    }

    #[test]
    fn describe_reads_as_sentences() {
        let set = AtprotoScope::parse_set(BLACKSKY).unwrap();
        let lines: Vec<String> = set.tokens().map(|(_, t)| t.describe()).collect();
        assert!(lines.contains(&"See your email address".to_string()));
        assert!(lines.contains(&"Change your handle".to_string()));
        assert!(lines.contains(&"See and change your email address".to_string()));
        assert_eq!(
            ScopeToken::parse("repo:app.bsky.feed.post?action=create")
                .unwrap()
                .describe(),
            "Create records of type app.bsky.feed.post in your repository"
        );
    }

    #[test]
    fn to_internal_scope_maps_transition_generic_to_repo_and_blob() {
        assert_eq!(to_internal_scope("atproto"), "");
        assert_eq!(
            to_internal_scope("atproto transition:generic"),
            "atproto:repo.* atproto:blob.upload"
        );
        assert_eq!(
            to_internal_scope(
                "atproto transition:chat.bsky transition:generic bogus transition:generic"
            ),
            "atproto:repo.* atproto:blob.upload"
        );
        // Granular grants are checked against the ScopeSet, not translated.
        assert_eq!(to_internal_scope("atproto repo:*"), "");
        assert!(!to_internal_scope("atproto transition:generic").contains("admin"));
    }
}
