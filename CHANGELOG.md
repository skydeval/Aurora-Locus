# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `aurora-locus repair-tree <did> [--dry-run] [--rationale …]` puts back records that a repository's index holds but its signed record tree lost, as proto-blue-repo 0.3.3's tree delete could do. Each record goes back as the block the index points at, so its CID is unchanged (the repair stops before writing if any would change), in ordinary signed commits that announce each record as a create on the firehose, checked like every other commit. The repair is recorded in the audit trail as `repo.tree_restored`. `--dry-run` only lists the missing records. Private-tier records are not restored this way
- Private replies to public posts (private branches). A private post whose parent is a public post starts a branch: written with `createPostPrivate` under one of the writer's own audiences, keeping the public thread's root as `reply.root`. Replies inside a branch are checked like replies in a private thread, with the branch root (the topmost private post, whose parent is public) as the anchor: every post up to it names an audience of the branch root's author and agrees on `reply.root`, the branch root is reached within the walk bound (`PDS_KRYPHOCRON_MAX_CHAIN` posts, default 16, at most 100), and the reply names the branch root's current audience, against which the writer is checked. The branch's author replies with `createPostPrivate`, others with `participatePrivate`. `updatePostPrivate` can move a branch root, and the move applies down the branch
- `tools.kryphocron.feed.updatePostPrivate` moves a posted private post to another of the writer's own audiences. Only `audienceList` changes; the URI stays the same and the answer carries the new record CID. Replies are refused (a reply's audience is its thread's), as are audiences that are not the writer's or do not exist; `swapRecord` must match. Replies already written keep their audience, and new replies must name the new one
- `tools.kryphocron.policy.manageAudience` updates an audience record when given the rkey of one that exists (with an optional `swapRecord`); before, it always created. `tools.kryphocron.policy.deleteAudience` deletes one; posts that still name it are then readable by their authors only. The audit of an audience change names the members added and removed and the mode before and after, instead of listing every member as added. `createRecord`, `putRecord` and `deleteRecord` on a private post's update or an audience's update or delete now point at these procedures
- `participatePrivate` admits a reply under a `following` audience when the audience's owner follows the writer, with the same block rules as `followers`
- atproto OAuth clients can end their grant when their user signs out: a token revocation endpoint (RFC 7009) at `/oauth/atproto/revoke`, advertised as `revocation_endpoint`. Given an access or refresh token and the `client_id` it was issued to, it revokes the grant, so neither token works again; it answers 200 whatever it was given, as the RFC requires, and does nothing for another client's token
- atproto OAuth sign-up: a client that asks for `prompt=create` sends its user to a sign-up page on this PDS (handle, email, password, and an invite code when invites are required), which creates the account exactly as `com.atproto.server.createAccount` does, signs it in, and continues to the consent page for it. `prompt=login` and `prompt=select_account` ask for a fresh sign-in even when the browser is already signed in; `prompt=none` answers `login_required` or `consent_required` instead of showing a page. The supported values are advertised as `prompt_values_supported`; any other value is refused
- Email two-factor sign-in (`emailAuthFactor`), as on the reference PDS. An account with a confirmed email address can turn it on through `com.atproto.server.updateEmail`; signing in with the account password then also needs a one-time code (`XXXXX-XXXXX`, valid 15 minutes, newest only) emailed to it. `createSession` answers `AuthFactorTokenRequired` and sends the code when none is given, and accepts it as `authFactorToken`; the OAuth sign-in page asks for it in the same way. `getSession` reports `emailAuthFactor`. App passwords are not affected, and the factor cannot be turned on where the server cannot send email
- atproto OAuth loopback development clients: a `client_id` of `http://localhost` (optionally carrying `redirect_uri` and `scope` query parameters) is accepted without a hosted metadata document, as atproto OAuth specifies for local development. Its redirect URIs must be on `127.0.0.1` or `[::1]`, where the port is not compared
- The PDS asks its relays to crawl it (`com.atproto.sync.requestCrawl`) when federation and relay crawl are both on: at startup, as soon as relay crawl is switched on, and for each relay added to the relay set, retrying failures with backoff and recording each request in the audit trail. Previously nothing told a relay the PDS existed, so a new PDS was never indexed unless the operator called each relay by hand. SuperAdmins can also request a crawl on demand (`tools.aurora.ops.requestRelayCrawl`, for all relays or one)

### Changed

- Replies to private posts work for `followers` and `everyone` audiences, and the check that decides who may reply can no longer be walked around. `tools.kryphocron.actor.participatePrivate` understood only `list` audiences and refused every other mode, so nobody but the author could reply to a followers-only post. It now admits a writer under a `followers` audience when the writer's own repository holds a follow of the audience's owner, under `everyone` always, and under `nobody` and unknown modes never; `list` is unchanged. For `followers` and `everyone` a block in either direction between the writer and the audience's owner (an `app.bsky.graph.block` or a private-tier block record; not a list block) refuses the reply. The audience's owner may always reply under its own audience. The check now runs on the audience the reply itself names, which must be the audience of the post replied to when that post is held here; before, it read only the parent's audience, a parent on a DID not hosted here skipped it entirely, and `tools.kryphocron.feed.createPostPrivate` accepted any account's audience. `createPostPrivate` now accepts only an audience in the writer's own repository (HTTP 400 otherwise), and both procedures require `audienceList` to be an audience record's URI, as a string or `{ "uri": … }`. Every refusal by the audience check is the same HTTP 403, whatever the cause; a parent post with a malformed audience reference or an undecodable block no longer answers 400 or 500. Both procedures refuse callers whose repository is not held here before reading anything. Direct reads of private posts from the PDS still resolve `list` audiences only. The follow and block facts are answered from a new index in each account's repository database (who its follow and block records name), so the check costs the same however many accounts someone follows or blocks; the index is installed when an account's database is first opened by this version and filled the first time it is needed
- `.env.example` sets `RUST_LOG=info` (was `info,aurora_locus=debug`), so a copied example config doesn't write debug-level logs

### Fixed

- Audit-chain entries are no longer lost when another write lands at the same moment. On SQLite a chain write began as a read and then tried to become a write; if any other account-database write landed in between, SQLite refused it at once (the busy timeout cannot wait out that case) and the entry was dropped, as the boot-time relay crawl's entry was. Every chain-writing transaction now takes the write lock when it begins (`BEGIN IMMEDIATE`), so a concurrent writer waits instead
- `participatePrivate` no longer lets a reply into an audience's conversation that it is not part of. It checked the reply's parent only when the parent's owner was an account here, never read `reply.root`, and wrote without any check when the audience's owner was held elsewhere, so a writer the audience admits could attach a reply to an invented parent, or to a post its own second account made elsewhere, and have it served to the whole audience. A reply must now hang off its thread, and the thread's audience is its root's current one, so a change of audience applies downthread: the reply must name exactly the root's current audience (and the writer is checked against it), and walking up from its parent every post exists, names an audience of the root's author (one the thread had before a move counts) and agrees on the root, and a post by the root's author is reached within the walk bound (`PDS_KRYPHOCRON_MAX_CHAIN` posts, default 16, at most 100); the root must not itself be a reply. So after the root's author moves the root to another audience, a member added by the move may reply anywhere in the thread and a member removed by it nowhere. The root author's own replies are not walked, but must name the root's current audience too. `createPostPrivate` accepts a reply only in the writer's own thread, under the root's current audience (HTTP 400 otherwise); it used to accept a reply in anyone's thread under the writer's own audience, which let a member removed from a thread's audience keep writing into it. Replies in another account's thread go through `participatePrivate`. Posts held on other PDSes are fetched with `com.atproto.repo.getRecord` from the PDS in their DID document: at most 16 fetches from other servers per reply (posts held here cost a local read), 64 KiB per answer, 3 seconds for the whole check, https only, no redirects, never to a loopback or private address (names are resolved to public addresses only, and a `did:web` on an address or loopback name is not resolved), and at most 30 such checks per account per minute (429 beyond). A reply that fails is refused with the same 403 as the audience check, and audited the same way
- The operator documentation says that `AURORA_RECOVERY_MODE` lets private-tier records be written without the dedicated procedures' checks, and that AppViews serve such records as if they had been checked
- A blob is stored with the type its bytes show, as the reference PDS does, falling back to the declared `Content-Type` and then to `application/octet-stream`; a declared wildcard (`*/*`) names no type. Bluesky's video service uploads its processed video with `Content-Type: */*`, which was refused as an unsupported type, so video posts still failed after the upload was authorised. WebM and QuickTime are recognised from their bytes too
- Video posts work. Bluesky's video service uploads a processed video back to the user's PDS with a service-auth token the user signed (from `getServiceAuth`), and `uploadBlob` refused it: only this PDS, its peers and an entryway were accepted as issuers. `uploadBlob` now accepts such a token from an account held here, as the reference PDS does, when it names this PDS as audience and `uploadBlob` as its method, carries the account's signature, is within its lifetime, and the account may write. Uploads were also capped at 2 MiB by the web framework, below the configured limit, which now decides alone; it defaults to 100 MiB, Bluesky's video limit (was 5 MiB). A `Content-Type` with parameters (`video/mp4; codecs=…`) is accepted. An upload is read into one buffer, refused as soon as it passes the limit, and given ten minutes to arrive; at most four uploads over 8 MiB are read and staged at once. Image dimensions are read from the image header instead of decoding the image, and hashing runs off the request threads
- Write responses carry the written record's CID, not the commit's. `createRecord`, `putRecord` and the `tools.kryphocron.*` write procedures answered the commit CID as `cid`, so a strong reference built from it (a reply, a like, a quote) pointed at nothing. `createRecord` and `putRecord` now also answer `commit: {cid, rev}`, `deleteRecord` answers the commit when it wrote one, and `applyWrites` answers `results` with one entry per write (`createResult`/`updateResult` with `uri` and `cid`, `deleteResult`), as the reference PDS does
- A swap mismatch (`swapRecord` not the record's current CID) is answered with the error name the lexicons give, `InvalidSwap`, instead of `SwapCidMismatch`; the status stays 409
- `deletePostPrivate` on a post that is not there succeeds, as `deleteRecord` does, instead of answering 500
- DPoP proofs must carry a nonce this server issued (RFC 9449 §8, §9), so a proof cannot be signed ahead of time and replayed later. Every response to a request with a DPoP proof carries the current nonce in `DPoP-Nonce`; a proof without a current one is answered `use_dpop_nonce`, as HTTP 400 at PAR and the token endpoint and as HTTP 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` on API requests, and the client retries with the nonce from that answer. Nonces are stateless, rotate every three minutes and stay valid for the window either side. The admin panel's own sign-in retries on the challenge
- A record write whose stored repository cannot be read (a missing commit or tree block, or a failed read) now fails, instead of signing a new empty repository over the old one. A new repository is started only when none has been stored
- A record write can no longer store a repository tree that lost records. The repository library's tree delete (proto-blue-repo 0.3.3) can drop neighbouring records when the deleted record sits between two subtrees, and one such commit removed six records from a test account's signed repository while deleting one; the records stayed in the index, so deleting them afterwards answered 500. Every commit is now checked before it is stored: its tree must hold exactly the previous tree's records with the batch's creates, updates and deletes applied, or the write is refused and nothing is stored. Until the library is fixed, a delete that would trigger the bug fails instead of damaging the repository
- An atproto OAuth sign-in that can no longer go on (its pushed request expired, was cancelled, or was already completed) returns to the app with an OAuth error it can act on (`invalid_request` or `access_denied`, with `state` and `iss`), instead of stopping on an error page of this server. A `request_uri` presented with another client's `client_id` is refused
- A 401 answered to a request that carried a credential now says why in `WWW-Authenticate` (`DPoP algs="ES256", error="invalid_token"` or `Bearer error="invalid_token"`), so an OAuth client knows its token is dead and refreshes, instead of waiting for a refresh to fail
- Calls forwarded to other services pass back `Retry-After` and the `RateLimit-*` headers, so a client refused by an upstream's rate limit knows when to try again
- `POST /oauth/atproto/logout` requires the session's CSRF token in `X-CSRF-Token` when it would end a live session; another site could sign a browser out by posting to it
- An atproto OAuth client is granted only the scopes it declares in its client metadata. The requested scope was accepted whatever the client's metadata said; a request for a permission the client does not declare is now refused with `invalid_scope`
- An atproto OAuth client gets the account it asked for, and the person approving sees which account that is. The authorize step bound every request to whichever account the browser was signed in to on this PDS's web pages, ignoring the client's `login_hint`, and the consent page named no account; a client that asked for one account could be issued tokens for another. The provider now keeps `login_hint` (from the pushed request or the authorize query): with no browser session the sign-in page opens prefilled with the requested account and names the app asking; with a session for a different account nothing is bound and a page names both accounts, offering "Sign in as" the requested one or "Cancel" (which returns `access_denied` to the client). A request is bound to one account once and never rebound, and approval refuses a request bound to an account other than the one asked for. The consent page says which account it is signed in as, with "Not you? Switch account", and the sign-in page offers "Sign out" when a browser session exists; both end the session and return to the same sign-in. A hint that names no account here is ignored and not shown
- A revoked OAuth grant can no longer be refreshed: revoking it (connected apps, a device, or a takedown) stopped its access token but its refresh token still minted new ones. An OAuth access token now stops working when its advertised `expires_in` (one hour) has passed; it was accepted for the refresh token's 90 days
- `com.atproto.sync.getBlocks` works: it refused every request with "expected a sequence", because the query parser it used cannot read a repeated `cids` parameter, even one given once
- Every change of an account's status is announced, and every surface reports the same status. An account's status is now read in one place, from the account row and the moderation record together, by `sync.getRepoStatus`, `sync.listRepos`, session documents and every `#account` event; before, all of these read the account row only, so an operator's suspension was reported as active and a later reactivation of a still-suspended account announced it active. Precedence is taken down, then suspended, then deactivated. Deleting an account (the account's own `deleteAccount`, `com.atproto.admin.deleteAccount`, the Aurora admin `DeleteAccount` action, and the purge of accounts past their deletion date) removes the account's rows, announces `#account status:"deleted"`, removes its earlier events, and then removes its repository and the blobs no other account uses; the admin paths and the purge announced nothing and left the repository behind, the purge also left the account row, and the account's own deletion removed the repository before the rows. The Aurora admin takedown, suspend, restore and status actions, their batch versions and an approved appeal announce the resulting status. A restore lifts the takedown from both places it is recorded; restoring only the account row, as `updateSubjectStatus` and `batchRestoreAccounts` did, announced the account active while its requests were still refused, and the Aurora admin `RestoreAccount` lifted nothing. `com.atproto.admin`'s restore refuses a moderation record that belongs to another account. A suspension that expires is announced within a minute. `suspendAccount` refuses a DID with no account here
- A blob is served only for the account it belongs to and only while that account may be read. `com.atproto.sync.getBlob` checked the named account's status and then served any blob by CID, so any active account's name served every blob on the PDS, a taken-down account's included; it now requires the blob to have been uploaded by, or be used by a record of, the named account, and answers `BlobNotFound` otherwise. `/blob/:cid` follows the same rule (one of the blob's accounts must be readable by the caller) and tells caches to revalidate instead of keeping the blob for a year. The `com.atproto.sync.*` reads let the account itself and admins read a repository that is not active, as `com.atproto.repo.*` does, so a deactivated account can export its repository before migrating. `activateAccount` refuses a taken-down account; its handle-and-password path could reach the reactivation
- Missing things answer the names their lexicons declare, with the reference PDS's status codes: `sync.getRepoStatus`, `getRepo` and `getLatestCommit` answer `RepoNotFound`, `sync.getBlob` `BlobNotFound`, `sync.getBlocks` `BlockNotFound`. `RepoNotFound` is HTTP 400 (was 404) and `AccountTakedown` 401 (was 403). `sync.listRepos` no longer ends early: the cursor followed only the accounts that had a repository, so one account without one ended the listing and relays missed every account after it. `repo.getRecord` honours `cid` (a version that is no longer current is `RecordNotFound`); `repo.getRecord`, `listRecords` and `describeRepo` accept a handle in `repo`, resolved among this PDS's accounts by handle only. `checkAccountStatus` fills the repository fields its lexicon requires (they were null). `deactivateAccount` honours `deleteAfter`: the account is deleted once that time has passed
- A deactivated account looks deactivated to the network instead of broken. Its handle keeps resolving: `/.well-known/atproto-did` and `com.atproto.identity.resolveHandle` return its DID as they do for an active account (they treated a deactivated account as absent, so clients reported "unable to resolve handle" and never got as far as the account's status; behind on-demand TLS the handle's hostname lost its certificate too). A taken-down account's handle still does not resolve. An operator's Suspend action now announces itself with an `#account` event (`active: false`, `status: "suspended"`), as takedown and deactivation already did, so relays and AppViews stop showing a suspended account as active; restoring the account already emitted the matching `active: true`
- A record that does not exist answers `RecordNotFound` (HTTP 400) in every collection and on both read endpoints. `com.atproto.repo.getRecord` still answered 404 `NotFound` for a missing record in a `tools.kryphocron.*` collection, an exception that hid nothing (an existing private record is served to any caller, decoded or encoded) and that an AppView could not act on: it only drops its copy of a private post, audience or block once the PDS says `RecordNotFound`. `com.atproto.sync.getRecord` also answered 404 `NotFound` for a missing record, where its lexicon declares `RecordNotFound`. A repository that is not hosted here or is not active still answers `RepoNotFound`, `RepoTakendown`, `RepoSuspended` or `RepoDeactivated` first
- Deactivated and taken-down accounts now behave as on the reference PDS. A **deactivated** account can log in (password, app password or OAuth) and stays logged in when it is deactivated; `createSession`, `refreshSession` and `getSession` report `active: false` and `status: "deactivated"`, which is what clients use to show their reactivate screen. While deactivated it may only use its session, reactivate, check its status, delete the account, read its own repository, and finish migrating in (`importRepo`, `uploadBlob`, `listMissingBlobs`, preferences, the PLC endpoints, `getServiceAuth`); everything else answers HTTP 401 `AccountDeactivated`. Previously login was refused and password sessions were deleted, so clients could not show a way back, while OAuth logins kept working in full: a deactivated account could still post through an OAuth app. A **taken-down** account cannot log in (HTTP 403 `AccountTakedown`, given only with the right password), its OAuth logins are revoked at takedown along with its sessions, and its requests are refused on the account's own takedown flag as well as on the moderation record. Session documents of active accounts now carry `active: true`
- A taken-down, suspended or deactivated account's repository is no longer readable through `com.atproto.repo.getRecord`, `listRecords` or `describeRepo`. These endpoints had no account-status check, so such an account's public records were still served to anyone, and its private posts were still served decoded to their audience. They now refuse with `RepoTakendown`, `RepoSuspended` or `RepoDeactivated` (HTTP 400), as the sync endpoints do, before anything is read; the account itself and admins can still read, as in the reference PDS. A repository this PDS does not host answers `RepoNotFound` on all three. An operator's Suspend action is now honoured by the sync endpoints as well (`com.atproto.sync.getRepo`, `getRecord`, `getBlocks`, `getBlob`, `listBlobs`, `getLatestCommit`): it was recorded as a moderation action but those endpoints only looked at the account row, so a suspended account's repository could still be downloaded
- `com.atproto.repo.getRecord` answers a record that does not exist with HTTP 400 `RecordNotFound` ("Could not locate record: at://…"), the error its lexicon declares and the reference PDS returns. It answered 404 `NotFound`, which AppViews and clients could not tell apart from a wrong route or a missing repository, so a new account's setup on an AppView failed on its not-yet-created profile record. A repository this PDS does not host now answers 404 `RepoNotFound` (it was 404 `NotFound`), so the two stay distinguishable
- atproto OAuth clients can upload video and use the other endpoints that previously accepted only session tokens. `com.atproto.server.getServiceAuth` refused every OAuth token, so a client logged in with OAuth could not get the service-auth token a video upload needs; it now issues one when the client was granted the method on that service (`transition:generic` covers every method except chat, `transition:chat.bsky` covers chat, and a granular `rpc:` permission naming the service covers its methods; a token usable for any method needs `rpc:*` on that service). The PLC endpoints (`getRecommendedDidCredentials`, `requestPlcOperationSignature`, `submitPlcOperation`) accept OAuth tokens granted `identity:*`, `createReport` those granted permission to call it, and `checkSignupQueue` any account token
- atproto OAuth clients keep the tokens they are issued. Token responses (code exchange and refresh) now include `sub`, the account's DID, which atproto OAuth requires; the reference client libraries discarded responses without it, so Blacksky reached the token exchange and then did nothing, leaving the user logged out. Token responses also carry `Pragma: no-cache` alongside `Cache-Control: no-store` (RFC 6749). The admin panel's OAuth client requires `sub` and checks it names the account it signed in
- Browser-based atproto OAuth clients (Blacksky and others built on the reference browser client) finish logging in. After Approve, the authorization code was always put in the redirect's query string, but these clients ask for `response_mode=fragment` and read the response from the URL fragment, so they never saw the code and landed back logged out. The provider now honours `response_mode` (`query`, the default, `fragment` or `form_post`) for both approval and denial, adds the issuer as `iss` to every authorization response (RFC 9207, which atproto OAuth requires), and advertises `response_modes_supported` and `authorization_response_iss_parameter_supported` in its metadata. The admin panel's OAuth login asks for `query` explicitly and now requires the `iss` to be this server
- A taken-down or suspended account can no longer keep acting through an atproto OAuth client: the moderation check read only `Bearer` credentials, so requests authenticated with `Authorization: DPoP` skipped it
- atproto OAuth clients can request the scopes the reference PDS supports. The provider accepted only `atproto`, `transition:generic` and `transition:chat.bsky` and refused any other scope, so clients asking for more (Blacksky asks for `transition:email identity:handle account:email?action=manage account:status?action=manage`) could not start a login. It now also accepts `transition:email` (advertised in `scopes_supported` with the other three static scopes) and the granular `account:`, `identity:`, `repo:`, `rpc:` and `blob:` permissions; scopes it cannot grant (including `include:` permission sets) are dropped rather than failing the request, `atproto` is still required, and `openid` is refused. The token is granted exactly the accepted scopes, and they are enforced: record writes by collection and action, blob uploads by type, proxied calls and preferences by method and service, the email in `getSession` (only with `transition:email` or `account:email`), email changes, account activation/deactivation/status and repository import by `account:` permission, handle changes and PLC operations by `identity:` permission; app passwords, account deletion and invite codes are refused to OAuth clients. `transition:generic` keeps granting record writes, uploads and every proxied call except chat, which needs `transition:chat.bsky`. The consent screen describes each requested permission in words. OAuth clients can also call `getSession`, `updateHandle` and `signPlcOperation`, which previously rejected every OAuth token
- An access token issued to an atproto OAuth client can no longer be used as a plain `Authorization: Bearer` token. These tokens are bound to the client's DPoP key and are only valid as `Authorization: DPoP <token>` with a proof signed by that key (RFC 9449); three authentication paths looked the token up without checking the binding, so anyone holding a copy of it could act as the account without the key. Tokens that are not DPoP-bound are unaffected
- Third-party atproto OAuth clients (Blacksky, and any client built on the reference OAuth libraries) can log in. DPoP proofs were rejected with `missing field exp` because the verifier required an `exp` claim, which RFC 9449 does not define and those clients do not send. Freshness now comes from `iat`: a proof may be up to 5 minutes old and up to 60 seconds ahead of the server's clock, and its `jti` is remembered for as long as it could be accepted. A proof that does carry `exp` (as the admin panel's own client sends) is still refused once that time has passed. After login, the client's DPoP key is registered as one of the account's devices when it exchanges its authorization code, so its requests pass the device check (previously only keys registered through the account's device page could make authenticated requests) and the account holder can see and revoke it
- Requests from other servers that authenticate with a service-auth token (another Aurora-Locus, a kryphocron service, any atproto PDS acting for its user) are accepted. The verifier checked these tokens as P-256 against a PEM key, so it could not verify an atproto token at all; it now resolves the issuer's DID document and checks the signature strictly (ES256K or ES256, compact low-S), the audience (with or without a `#service` fragment), the expiry window, and, where the method is known, that the token was minted for it. Tokens without a `jti` (as the reference PDS sends) are replay-protected by their hash
- Service-auth tokens this PDS mints (for proxied calls, `com.atproto.server.getServiceAuth`, and entryway/holder signing) follow the atproto profile, so strict verifiers accept them: the signature is the 64-byte compact low-S ES256K form (it was DER), and the claims now include `iat` and a random `jti`, default to a 60-second lifetime, cap any requested lifetime so `exp - iat` is at most an hour, and give `aud` as the bare service DID (a `#service` fragment is dropped). Incoming tokens are accepted in the compact form and, from not-yet-updated issuers, the old DER form
- bsky.app and other clients can load an account: any XRPC method the PDS does not implement itself is forwarded, as the reference PDS does. With an `atproto-proxy: <did>#<service>` header it goes to that service (resolved from the DID document); without one, `app.bsky.*` goes to the configured AppView. Each authenticated call carries a short-lived service-auth token in the account's name for exactly that method, anonymous calls go through anonymously, and the upstream answer (errors included) comes back unchanged. Previously only a fixed list of `app.bsky` methods was forwarded, without service auth, and only for OAuth tokens, so password-login sessions got 401s and everything else (e.g. `app.bsky.unspecced.getConfig`) got 404. Timeline, author feed and profile still merge in the account's own not-yet-indexed posts and edits. `chat.bsky.*` needs a full session or a privileged app password, and account-management methods are never forwarded
- `app.bsky.actor.getPreferences` and `putPreferences` are served by the PDS from its own storage, as the reference PDS does, and accept the session tokens bsky.app gets from password login as well as app passwords and OAuth. `getPreferences` used to be forwarded to the AppView with OAuth-only auth (so password-login sessions got 401), and `putPreferences` did not exist. App-password sessions can neither see nor set `personalDetailsPref`. Preferences are deleted with the account
- Browser clients such as bsky.app can make proxied calls: CORS now allows any request header (it allowed only `content-type` and `authorization`, so preflights carrying `atproto-proxy` or `atproto-accept-labelers` were blocked), allows the methods XRPC uses, exposes the response headers clients read (`atproto-content-labelers`, `atproto-repo-rev`, `dpop-nonce`, `www-authenticate`, `ratelimit-*`), and lets browsers cache preflights for a day
- `com.atproto.server.createSession` with a wrong password answers `Invalid identifier or password` instead of `Invalid app password`
- Federation stalls after an account's first post or profile edit. The firehose sent each `#commit` event's `since` as the previous commit's CID; the lexicon defines it as the previous commit's rev (a TID string), and the Bluesky relay dropped the connection on every such frame, reconnected, and replayed the same event forever, so nothing after it reached the network. `since` is now the previous rev, and an explicit null for a repo's first commit (it was omitted). Events already stored with the old value are corrected as they are sent, so a relay stuck on one moves past it after this update, with no re-sync needed
- `subscribeRepos?cursor=0` replays the retained event window instead of returning nothing, and a cursor just before the window no longer gets a spurious `OutdatedCursor` notice
- The startup relay crawl request now waits until the PDS is answering; sent too early, the relay's check timed out and it replied `HostNotFound`
- A relay reconnecting repeatedly no longer floods the log: per-connection firehose messages and client disconnects are logged at debug level
- Signing up with `PDS_INVITE_REQUIRED=true` works. The invite code was checked twice: the sign-up endpoint used it up, then account creation asked for it again and failed with "Invite code required", so no account was created and the invite was burned. The code is now checked once, before anything is written, and used inside the same database transaction as the new account, so a sign-up that fails for any reason (handle taken, PLC error) leaves the invite usable. Its use is recorded against the new account's DID (it was recorded against the handle, which hid the account's "invited by" in the admin panel), and a missing, unknown, disabled, expired or used-up code returns `InvalidInviteCode`
- `com.atproto.server.getAccountInviteCodes`, `createInviteCode` and `createInviteCodes` work (they queried invite-table columns that do not exist and always failed). `createInviteCode` and `createInviteCodes` now require an Admin (previously any signed-in account was allowed to mint codes, which would have made invite-only sign-up meaningless), and `createInviteCodes` creates `codeCount` codes per account and returns them grouped per account, as the lexicon specifies. `getAccountInviteCodes` returns the codes issued for the account, with their uses
- Handles under the PDS's handle domains now verify: `/.well-known/atproto-did` answers by the requested hostname, returning the account's DID for `<name>.<handle-domain>` (404 `User not found` for unknown or taken-down accounts, and for unrelated hosts) while the service hostname still returns the server's DID. Previously every hostname got the server's DID, so Bluesky and other clients showed hosted handles as invalid
- `com.atproto.identity.resolveHandle` resolves handles of this PDS's own active accounts locally before trying DNS/HTTPS (previously returned `HandleNotFound` for handles it hosts)
- Admin handle changes (`com.atproto.admin.updateAccountHandle`) now publish the new handle to the PLC directory for did:plc accounts and announce it on the firehose, so AppViews accept it; previously only the local record changed, leaving the account's DID document on the old handle and the new handle shown as invalid. A failed PLC update now fails the change and leaves the account's handle as it was, and behind an entryway the change is refused (the entryway owns handles)
- `com.atproto.identity.updateHandle` to a handle on this PDS's own domains no longer fails after already updating the PLC directory (it tried to verify the new handle over HTTPS before the PDS had stored it); both handle-change paths now finish every check before anything is published
- The admin panel's Update handle, Update email and Send password reset actions send their request after the rationale is submitted (previously the modal closed and nothing happened)
- The admin panel no longer reports "Update failed: JSON.parse: unexpected end of data" after actions that succeed with an empty response, such as changing an account's handle; the change had been applied, only the success was misreported
- With federation enabled and a relay configured (the default is `https://bsky.network`), the PDS no longer subscribes to the relay's firehose. It was downloading the entire network's event stream (about 130 GB a day from bsky.network), discarding every event, and logging a line per event; relays crawl a PDS, a PDS does not need their firehose. It also no longer sends each of its own events to the relay as a request the relay rejects. The unused relay metrics (`relay_events_total`, `relay_event_processing_duration_seconds`, `relay_connection_status`, `relay_connections_total`, `relay_events_published_total`) and the `relay` block of the admin system-metrics response are removed
- Operations → Federation shows the live relay set, with Add, Remove and Request crawl controls for SuperAdmins, whether relay crawl is on and which hostname is announced; its status panel and known-instances table now show real values (they read field names the server never sent, so the page said "Relay: unconfigured" and listed blank hosts). Relay changes made in the panel now survive a restart (the relay set was rebuilt from `PDS_FEDERATION_RELAY_URLS` at every boot)
- Health surfaces no longer report a relay "connection" (the PDS holds none since it stopped consuming the relay firehose). The dashboard's federation health shows the relay count and whether crawl is on; system health, the health checks and the public federation status report the relay state as `disabled`, `none`, `idle` or `announcing`, and a relay state never marks the checks degraded. The public federation status and `com.aurora.federation.describePosture` list the live relay set instead of the startup value
- `com.aurora.federation.describePosture`, which Aurora peers and kryphocron federate on, advertises the live federation settings: Firehose, Relay crawl and the AppView URL now reflect changes made in the panel (they reported the startup values, so they could contradict `describeServer`), and `publicUrl` is the deployment's real public URL from `PDS_SERVICE_PUBLIC_URL` (it came from the deprecated `PDS_PUBLIC_URL` and was usually missing)
- The relay set may be empty. Removing the last relay, clearing the set, or starting with `PDS_FEDERATION_RELAY_URLS` empty no longer fails; with federation on, an empty `PDS_FEDERATION_RELAY_URLS` used to fail the boot seed and block every federation-policy change until the next restart
- Peer discovery no longer treats a relay's account list as PDS servers. It read `com.atproto.sync.listRepos`, which lists user accounts, recorded each account as a "PDS instance" with no URL, and queued them as pending discoveries; relay-based discovery is removed, and the leftover URL-less pending entries are cleared at startup

## [0.10.1] - 2026-07-27

### Fixed

- `com.atproto.repo.putRecord` correctly creates records that don't exist yet, and correctly rejects updates when the `swapRecord` precondition fails (previously returned 500 on first-publish, and silently overwrote records when `swapRecord` was mismatched)
- `com.atproto.repo.deleteRecord` treats deleting an already-absent record as the idempotent success it is, and correctly rejects deletes when the `swapRecord` precondition fails (previously returned 500 for an absent record, and silently deleted records when `swapRecord` was mismatched)
- Outbound HTTPS/WSS calls now succeed reliably (previously failed with "TLS support not compiled in" — federation relay, external DID resolution, and cross-PDS calls affected)

## [0.10.0] - 2026-07-12

### Added

- Account holders get a self-service portal to sign in and manage their own account: home page, sign-in methods, connected apps, registered devices, personal theme, and sign-out
- Account holders can sign in three ways: password (Argon2id), cryptographic key sign-in (proves control of the account's published key via a signed challenge, no server-stored secret, on by default, disable with `PDS_HOLDER_LOGIN_ALPHA_ENABLED=false`), and passkeys (WebAuthn). The portal refuses to remove a holder's last remaining sign-in method
- Account holders can review and revoke their connected OAuth applications and registered devices; revoking a device also revokes the tokens bound to it
- atproto OAuth provider — third-party applications sign in as account holders through `/oauth/atproto/*` with DPoP-bound tokens. Admin scope is never granted to an OAuth bearer
- did:web accounts are now first-class alongside did:plc — the PDS classifies the DID method, stores did:web accounts locally, and serves each account's DID document with `alsoKnownAs` composed from the handle
- did:web accounts whose atproto key the PDS holds sign repo commits and service-auth JWTs identically to did:plc; app passwords work on the same terms. Holder-mediated signing (did:web sovereignty) lands in v0.11 alongside the did:web account-creation route
- Password-based admin login coexists with admin OAuth for operators who administer their own PDS, gated by `PDS_ADMIN_PASSWORD_LOGIN_ENABLED` (off by default)

### Changed

- Admin login now runs on Aurora's own OAuth authorization server and client end-to-end. The operator sees one page, one field, and one Sign in button; the authorization ceremony happens invisibly on the loopback path
- Admin and superadmin roles are now constrained to local accounts — admin trust is a claim about accounts the operator provably controls
- `install.sh` has been rewritten, verified across multiple Linux distributions (Rocky, Alma, Arch) via containerized smoke tests, and brought to native-install parity with docker-compose. The generated `.env` derives line-for-line from `.env.example` (making phantom or broken config vars structurally impossible), a Rust toolchain bootstraps via rustup, the script composes the deployment's public URL into `PDS_SERVICE_PUBLIC_URL` so a federated did.json advertises the reachable URL, and it offers to configure a TLS-terminating reverse proxy
- `create-account.sh` uses `PDS_SERVICE_PUBLIC_URL` when set, adds curl timeouts, accepts the admin prompt case-insensitively, and corrects its printed admin-grant instructions (the right database path and the `admin_roles` table)
- The Docker path is at v0.10 parity: `.dockerignore`, updated builder image, persistent data volume, readiness health check, and an automatic-TLS Caddy sidecar
- The admin Installed Themes gallery is now the single theme surface, carrying both the per-operator personal theme and the superadmin deployment default within one card
- `PDS_JWT_SUNSET_DATE` and `PDS_OAUTH_MIGRATION_GUIDE_URL` are now operator-tunable; previously the JWT sunset silently recomputed to "now + 90 days" on every boot

### Removed

- The dormant legacy OAuth surface at `/oauth/*` is retired — superseded by the atproto OAuth provider at `/oauth/atproto/*`. Legacy database tables are left dormant in-schema and dropped in a future version; clients on the legacy flow migrate to atproto OAuth

### Security

- Admin sessions now carry a task-time lifetime per role (SuperAdmin 15 minutes, Admin 30 minutes, Moderator 1 hour, with a per-account override inside sane bounds) that slides forward on activity and lapses on idle. The admin UI refreshes proactively before expiry
- Admin hardening endpoints (session lifetime, TOTP enroll/confirm/disable, IP binding) require a recently-authenticated session (within five minutes) and fail closed when session freshness can't be established
- TOTP two-factor authentication for admins, self-service, with the secret encrypted at rest under AES-256-GCM (keyed by `PDS_ADMIN_TOTP_ENCRYPTION_KEY_HEX`). Enforced at login on both the password and OAuth paths
- Admin login credentials are submitted by POST and never appear in a URL, browser history, or access log. Admin HTML and static assets are served `no-store`, so a stale cached page can't strand a shipped security fix
- Admin session IP binding ships as substrate only; the operator enable path is gated off until v0.11. Live testing behind a CDN showed the client IP resolved at login can differ from the IP seen on later requests, which would reject an operator's own traffic. Reliable enforcement lands with a single per-request layer in a future version

### Fixed

- Account creation against a live PLC directory now succeeds — the genesis operation serializes `prev` as an explicit `null` and the DID suffix is derived from the signed operation's canonical CBOR, so the DID this PDS registers matches the one PLC recomputes. Together these clear the rejections that had blocked did:plc account creation on production PLC
- OAuth bearer tokens issued by the atproto provider now validate — tokens are stored and looked up by SHA-256 hash instead of a mismatched identifier
- The admin UI no longer flashes the wrong theme (FOUC): active-theme CSS routes are served `no-store`, the post-login transition screen inherits the shared token layer, and a live theme swap loads the new theme before dropping the old one
- The admin session's access-token expiry now tracks the session's actual lifetime instead of a hardcoded hour, so the proactive-refresh timer fires on schedule
- `install.sh` is marked executable in git — a fresh clone can `./install.sh` without a manual `chmod +x` first

### Dependencies

- `dotenv` (unmaintained, RUSTSEC-2021-0141) replaced with its maintained fork `dotenvy` — identical API, already present transitively
- `webauthn-rs` added for account-holder passkey support; a vendored `@noble/secp256k1` browser module backs in-browser cryptographic-key sign-in

## [0.9.0] - 2026-06-28

### Added

- Admin UI reorganized into four domains (Moderation, Operations, Configuration, Kryphocron) with role-tiered dashboards, role- and mode-based visibility, and a reshaped sidebar, breadcrumbs, and routing
- Customizable theming with manifest-based inheritance, a design-token contract, WCAG 2.2 contrast checking, an effect-class library, and theme selection in UI settings
- Ten bundled themes — Dark, Light, Aurora Classic (default), Ember, Emerald, Glacier, Meridian, Pride, High Contrast Dark, and High Contrast Light. All ten pass WCAG 2.2 AA contrast checks via the substrate's verifier; High Contrast Dark and Light clear AAA for text (7:1). Programmatic contrast only — not a full accessibility audit
- Login page now matches the deployment-default theme
- Operator-customizable login splash branding: logo, banner, title, subtitle, and text colors, with a live preview
- Theme extension points — themes can declare and provide named extension points that surfaces opt into at runtime
- Theme lifecycle hook declarations (install, activate, deactivate) — the substrate lists them but does not execute them yet; script execution waits on a security-reviewed sandbox in a later version
- Theme authoring documentation and a reference example theme
- Kryphocron admin surface: overview, deployment-wide audiences, laquna status with rotation history, and tier-activity pages, plus a per-account drawer, a policy page, and a dashboard summary block
- Per-account kryphocron overrides on the Account Detail page: operators can block a specific account from issuing kryphocron capabilities (and flag a rate-limit exemption), audited with rationale
- New-account access policy: operators can require new accounts to wait a configurable number of days before posting to the private tier (off by default)
- Default audience for new accounts: operators can have each new account start with a chosen kryphocron audience mode, created automatically at signup (off by default)
- Encryption-at-rest for private-tier posts — encoded on write and transparently decoded for authorized readers — with a standard rotation oracle, automatic re-encoding on key rotation, and operator read endpoints
- Recovery surfaces: recovery-mode status display, single-repository rebuild, bulk repository repair, and sequencer integrity validation. The validator can route accounts it flags with malformed events straight to a per-account rebuild
- Forensic export now includes the account's full repository (as a CAR file) and uploaded blobs alongside audit events, in one verifiable archive
- Blocking a subject now also removes them from the blocker's audiences, with an audit log of the cascade
- Moderation list pages (Reports, Appeals, Events, Audit) share unified pagination and filtering behavior
- The moderation queue can be filtered by report status (open, acknowledged, escalated, resolved, or all), with the selection preserved in the URL across navigation and reload
- The Kryphocron Overview shows recent audience-oracle consultation activity — how often private-tier writes and reads are checked against audiences and how those checks resolved (aggregate counts only)
- A Registration policy page consolidates the deployment's account-registration settings (registration mode, new-account access, default audience) into one overview
- An Observability page provides a read-only overview of the deployment's monitoring surfaces (Prometheus metrics endpoint, system health, database, audit log, substrate metrics) with notes on env-scoped logging and telemetry
- A Federation policy page where SuperAdmins manage runtime federation without a restart: trusted peer allowlist (add/remove/modify peers without restart, every change audited, trust changes effective immediately), peer discovery mode (allowlist-only with a review list, auto-accept with delegation warning, or discovery-disabled), pending-discovery review (bounded to 100 most-recently-seen, de-duplicated by DID with last-seen refresh), and runtime-mutable relay set (add/remove individual relays or replace the whole set; the live firehose is re-pointed live; at least one relay always required)
- The Federation policy page also shows the read-only peer-visible posture (exactly what this PDS advertises to peers) and boot-seed status; `describeServer` advertises a minimal federation posture, and a federation-scoped describe endpoint exposes richer posture to federation-aware tooling
- Boot-seed safety: if federation policy can't be seeded at startup (for example, federation is enabled but no relays are configured), the deployment surfaces the failure in the audit log, the policy page, and the describe endpoint, and blocks federation-policy changes until the configuration is fixed and the deployment restarts — other operations keep working
- The audit log can be filtered to federation activity ("Federation management" filter); peers added automatically in auto-accept mode are tagged with a "Discovery" source you can filter on
- All federation-policy changes are blocked while the deployment is in recovery mode, consistent with the rest of the admin surface
- UI building blocks: loading skeletons, spinners, inline errors, error boundaries, consistent timestamps, source-tier indicators, and a save-with-rationale confirmation
- The Dashboard shows a real account-growth sparkline (Admin+) over the last 30 days, off account creation dates, with a header toggle between new-accounts-per-day and the cumulative deployment total
- The repository-rebuild deep preflight reports how many times an account has rotated its signing key, read from the full PLC audit-log history — giving operators forensic visibility into rotated accounts before a rebuild
- A new SuperAdmin dry-run endpoint lets operators validate a signing-key rotation before committing — reporting the key the PDS would generate, or checking an operator-supplied keypair (catching mismatched keys) — without mutating anything or publishing to PLC
- A new SuperAdmin "Key rotation policy" page with a "Run migration check" button: verifies that every account's locally-stored signing key matches what PLC publishes, reporting any divergences for review. Read-only; expected to find none
- Every federation policy field is now editable from the Federation policy page. The AppView URL and the advertised firehose/relay-crawl flags take effect immediately on save; enabling or disabling federation, and changing the deployment's public URL, save through a restart-required flow — the change is recorded, a pending-restart banner appears across the admin pages, and the operator restarts now or leaves it for the next supervisor restart. Each field shows whether its value is environment-seeded (Default) or operator-set (Runtime), with one-click revert-to-default
- When the deployment's public URL changes, the PDS automatically re-points every account's did:plc DID document on PLC to the new URL after restart; the Federation policy page shows per-account progress and offers a retry control for any accounts that failed
- Disabling federation now also refuses inbound federation requests immediately — before the restart that fully tears the federation subsystem down — for incident response

### Changed

- Account signing-key rotation now mints a fresh per-account key by default (or accepts an operator-supplied keypair when the runtime gate is on), publishes it to PLC, stores it, and signs the rotation's empty commit with the new per-account key. The rotation audit records the generation source (PDS-generated vs operator-supplied) and the old and new public keys
  - **Breaking:** the rotation endpoint no longer takes a `signingKey` field (the old single-operator-key model is removed) — it takes the account DID, an optional rationale, and an optional operator keypair. The admin Account page's rotation form is updated to match
- The `aurora-cli rotate-keys` command now mints a fresh per-account key per DID by default (bulk rotation still supported), or — for a single DID — accepts an operator-supplied keypair via `--public-key` and `--private-key-hex` when the runtime gate is on, with an optional `--rationale`. CLI rotations now publish, store, sign the empty commit with the new key, and emit an audit entry; the old server-wide signing-key shortcut is removed
- Repository rebuild (and bulk repo-repair, which repairs through the same path) verifies the reconstructed repo history-aware — every commit against the key valid at its revision from PLC history — instead of checking only the head commit against the current key
- The repository-rebuild deep preflight runs the same history-aware verification, so operators see whether a rotated account verifies cleanly across its full history before triggering a rebuild
- Audit entries are now individually addressable: a direct link to an audit entry (or a page refresh) loads it from the server, and the "walk to previous" control follows the hash chain across the whole log rather than only the entries currently on screen
- The deployment moderation tier (full, reduced, disabled) is now set on the Moderation policy page instead of UI & modes; switching to the disabled tier requires a typed confirmation
- Kryphocron is now enabled by default on fresh deployments; operators can disable it by setting `PDS_KRYPHOCRON_ENABLED=false`
- Operator role changes now take effect on the next request, without requiring re-login
- The Federation policy page distinguishes immediately-editable fields from restart-required fields, each with its own save flow; the "Relay binding" card is reframed as the boot seed (the live relay set is managed at Operations → Federation)
- The audit log now records operator-triggered restarts, the automatic bulk DID-document update, and per-account DID-document retries
- The bundled theme `stack-classic` is renamed to `aurora-classic` for brand coherence with the other Aurora-prefixed themes; its display name is now "Aurora Classic". It remains the deployment default. Operators with `stack-classic` as their preferred or deployment-default theme are migrated to `aurora-classic` automatically — personal preferences on next load, the deployment-default runtime setting by migration
- The Aurora Classic theme now carries an Aurora color scheme instead of reading near-identical to Dark: a teal-forward tri-accent palette (teal `#00F5D4` primary, green `#9AEF82` secondary, purple `#B900F5` decoration), a teal→green→purple heading gradient, a diagonal body surface gradient, an ambient aurora-wave backdrop, teal accent glow on the primary action and dashboard cards, and a left-border-and-glow sidebar active state. Motion (the wave, hover lifts) is disabled under `prefers-reduced-motion`, and the theme still certifies WCAG 2.2 AA

### Deprecated

- `PDS_PUBLIC_URL` is deprecated, ignored at runtime, and now logs a startup warning. Configure the deployment's public URL via `PDS_SERVICE_PUBLIC_URL` (now editable from the Federation policy page); `PDS_PUBLIC_URL` is removed in a future version

### Removed

- The unused `PDS_FEDERATION_AUTO_STREAM` setting and its `auto_stream_events` field are retired — the flag governed no behavior

### Security

- Admin authentication: refresh-token flow with rotation on use, and per-operator session management with a Sessions page to view and revoke active sessions
- SuperAdmin can revoke all of an operator's active sessions in one action (for suspected compromise or operator departure), audited with rationale
- Operator-supplied keypair gate (`key_rotation.operator_supplied_keys_enabled`) on the Key rotation policy page controls whether operator-supplied keypairs are accepted by the rotation flow. Off by default; flip it on for HSM-backed or pre-generated rotation paths. Enabling it asks for a confirmation and rationale, and the change is recorded in the audit log
- Admin password override, email change, and handle change now record the operator's rationale in the audit chain (previously these three actions logged a generic descriptive entry regardless of what the operator typed)
- Destructive operator actions (repository rebuild, repair, and manual rotation) are recorded in the tamper-evident audit chain
- The admin UI now runs only first-party JavaScript — no third-party scripts are loaded

### Fixed

- Kryphocron Policy settings now save instead of erroring (new-account access, default audience mode, deployment process-shape, and per-account cadence range); the process-shape declaration drives the Overview's single-/multi-process mismatch warning
- Admin UI displayed all operators as moderator regardless of their actual role
- Moderation metrics failed to load on the dashboard
- Configuration fields with no backing store are now shown read-only instead of offering saves that always fail
- Runtime-setting errors now report the specific reason instead of a generic moderation message
- Subject context and history drawers failed to load on the account-detail page
- Report-detail pages returned not-found
- Corrected the laquna rotation-history empty-state copy
- Switching the default theme now repaints colors immediately instead of only after a reload
- The reduced-motion preference now also suppresses smooth scrolling
- Cosmetic settings such as the theme save with a lighter confirmation instead of requiring a typed rationale
- Account search now filters by the search term instead of returning every account
- Restored the installed-themes listing to the server's advertised capabilities
- Audit-chain verification no longer reports entries written before the v0.9 hash-format change as tampered. The verifier now recognizes the pre-v0.9 canonical form, marks those rows verified, and keeps the per-row badge and chain banner green where they belong; the CLI chain report annotates how many entries (and which sequence range) verified under the legacy format. Only an entry matching neither the current nor the legacy form — a genuine tamper — halts the chain walk, and linkage is still checked across the format boundary
- Admin UI sidebar background now matches each theme's palette. Previously the sidebar tokens were defined only in base CSS with a single `[data-theme="dark"]` override, so every non-dark theme rendered the sidebar with a cool-slate fallback regardless of palette. The sidebar token family now derives from each theme's surface and text tokens, so every theme — light, ember, emerald, glacier, meridian, pride, aurora-classic, high-contrast-light, high-contrast-dark — renders a sidebar that matches its palette and preserves WCAG AA contrast (the derived foreground/background pairs are ones the substrate's contrast gate already certifies)
- Inline links throughout the admin UI now render in each theme's palette instead of falling through to the browser-default dim purple. Link colour derives from a new `--color-link` token (defaulted to the theme's interactive accent), so all ten themes get coherent, underlined links without per-theme work; anchors styled as buttons, sidebar nav, or row wrappers keep their own styling. Link-as-text contrast is now part of the substrate's WCAG gate — every theme is certified AA for links against its page surface, and the one theme whose accent read too light as text (Pride) gets a slightly deeper link colour that clears AA
- Sidebar nav items now use exact "longest matching route wins" matching for their active state. Previously, opening Sequencer recovery (route `ops/sequencer/recovery`) lit both the Sequencer item and the Sequencer recovery item, because a nav item also lit whenever the current path was nested under its route. Now a page lights only its own nav entry, while a detail page with no nav entry of its own (e.g. an account-detail page) still lights its parent

### Dependencies

- proto-blue pin updated to 0.3.3 to match the already-resolved version (no API impact)

## [0.8.0] - 2026-06-08

### Added
- Persistent forensic record of writes whose downstream commit failed, with automatic reconciliation against actor-store state
- Recovery mode for restoring otherwise-denied private-tier writes during operator recovery — off unless explicitly enabled, with every recovery write recorded as an audit event

### Changed
- Session refresh and logout now read credentials from the standard Authorization header (breaking change — clients sending credentials in the request body must update); logout fully revokes the session, and app-password revocation now also revokes that app password's active sessions and refresh tokens

### Fixed
- Login endpoints now accept DIDs in addition to handles; email addresses containing ':' are no longer accepted
- Rotated refresh tokens are now correctly invalidated, closing a replay path where a rotated token stayed usable
- Account restoration now emits a firehose event, so downstream subscribers no longer remain stuck in a stale takedown state
- applyWrites now accepts both the standard atproto request shape and the existing flat shape, so standard PDS-shaped requests no longer fail
- Bulk session revocation in the OAuth migration tool now also removes paired refresh tokens
- Operators are now warned at startup when orphan recovery or its reconciliation job is disabled, and when a client write produces an unusually large repository commit

## [0.7.0] - 2026-06-02

### Added
- Private-tier posting: dedicated endpoints for creating and deleting private posts, joining a private audience, and managing audiences
- Writes to a private audience are checked against the audience and rejected when the author isn't a member (cross-instance audiences deferred)
- Generic record writes to private-tier collections are redirected to their dedicated endpoints
- Audit-first write ordering — a write's audit record is committed before the write, so the audit trail is never lost if the write fails partway

## [0.6.0] - 2026-05-27

### Added
- Operator-tunable retention window for rate-limit buckets
- Configuration validation now warns about a service-DID form that breaks cross-PDS auth, and about test-only overrides that shouldn't be set in production

### Changed
- Federation is now enabled by default; opt out via configuration
- Service-auth tokens are now signed with the per-account key so receiving servers can verify them
- Fetched lexicons are verified against the publishing authority's signature before being trusted
- Requests authenticated by a tombstoned DID now return a clear 400 error instead of a server error

### Fixed
- Fixed malformed did:web handle generation under the default domain configuration
- Blob upload now accepts application/octet-stream
- Blob staging cleans up its temporary file when the write fails
- Role grant and revoke errors now return structured JSON instead of plain text
- Unresolvable handles now return a 400 error instead of a server error

## [0.5.0] - 2026-05-23

### Added
- Repository import: upload a full repository, with structure validation and blob pre-fetch from the origin server
- Account-lifecycle changes (creation, deactivation, reactivation, takedown, deletion, identity submission) now emit firehose events matching the reference PDS
- Dynamic lexicon loading with on-disk and in-memory caching and configurable failure handling, plus admin endpoints to inspect, refresh, and evict the cache
- Postgres backend coverage across every shipped surface
- Blob writes are now durable before their metadata is recorded
- Metrics for lexicon fetching and validation

### Changed
- Record writes are signed with the per-account repository key rather than a server-wide key
- Tombstoned DIDs now return a typed error instead of a server error

### Fixed
- Fixed a Postgres login failure caused by a timestamp type mismatch
- Missing-blob requests now return the spec-correct error code

## [0.4.0] - 2026-05-13

### Added
- Multi-instance support: a distributed state backend keeps auth state and rate-limit buckets coherent across instances, with configurable backends, a dedicated maintenance database pool, and background cleanup of expired DPoP records, OAuth flow state, and rate-limit buckets
- Optional background blob garbage-collection sweep (off by default), plus a CLI command for one-off operator-initiated sweeps
- Admin UI: reusable modal dialogs with validation, typed-confirmation, and required rationale for destructive actions; readable mapping of server error codes; and operator role grant/revoke behind that confirmation gate
- Audit and dashboard: a chain-verification indicator with detail, subject-CID filtering, a time-range preset selector, and success notifications that link through to the audit entry
- Moderation event and subject-status endpoints accept both current and legacy request shapes (sending both is rejected)

### Changed
- Forensic-export bundles now use the same audit-entry shape as the audit-trail API (breaking change for scripts parsing the previous bundle format)
- Settings screens now show the source (runtime / file / default / recovery) of each value
- Bulk-action batch sizes are now configured per action rather than as a single shared limit

## [0.3.0] - 2026-05-10

### Added
- File-based runtime configuration (YAML), layered between the live settings API and the built-in defaults
- API stability contracts committed for subject types, capability descriptions, action-ID surfacing, audit-trail reads, and multi-subject event emission

### Changed
- Moderation event emission now takes a list of subjects and returns a snapshot per subject (breaking change — single-subject callers must wrap their subject in a one-element list)
- Batch moderation operations are now all-or-nothing: any per-subject failure rolls back the whole batch (breaking change — the per-subject failures field is removed from responses)
- Role grant and revoke responses now use camelCase fields (breaking change against the previous ad-hoc JSON)
- Moderation metrics accept both the current time-range shape and the legacy start/end shape

### Removed
- Admin authority now comes only from the roles table; the environment-variable admin list is removed and the first super-admin is bootstrapped via CLI (breaking change for deployments that relied on the env-var admin list)

## [0.2.0] - 2026-05-04

### Added
- Live moderation-event subscription backed by a retention-bounded feed, with an operator-configurable retention window and background cleanup of older entries (subscribers whose cursor has aged out receive an explicit outdated-cursor signal)
- Audit-chain entries can be streamed live over the moderation-event subscription
- The audit-trail API reports chain-verification status, backed by per-row hash and linkage checks
- Audit-chain coverage extended across administrative endpoints, with a per-subject snapshot captured for batch operations
- DPoP proof-of-possession enforced on resource requests, closing a stolen-token replay path

### Changed
- Moderation metrics moved from POST to GET (breaking change — POST clients receive 405)
- Sending email via a moderation event now requires Admin, and several operator endpoints (password reset, forensic export, runtime settings) now require admin server scope (breaking change for moderation-only tokens)
- The moderation-event subscription's action filter is now a list and gains a record-level subject filter (breaking change for clients sending a scalar filter)
- Invalid DPoP proofs are rejected with a 400 instead of silently downgrading to Bearer
- Unknown runtime-setting keys are rejected with a 400
- The admin audit-log endpoint now reads from the hash-chained audit store (IP address omitted)

### Fixed
- Administrative actions now write their audit-chain entry atomically with the action, so an action can't land un-audited
- Concurrent audit-chain writes are serialized, eliminating silent loss of entries under load
- Forensic-export integrity hash now covers the entire bundle, not just the manifest
- Admin error pages no longer render URL-derived input as HTML (cross-site-scripting fix)
- Debug admin pages are no longer reachable in production builds
- Fixed admin-UI role grant and revoke (a field-name mismatch)

### Removed
- The legacy admin audit-log table is removed; every administrative decision is recorded in the hash-chained audit store
- The environment-variable admin list no longer grants admin authority — authority comes from the roles table
- The admin UI no longer stores the refresh token in browser local storage

## [0.1.0] - 2026-04-30

### Changed

- Fix rotted integration tests in tests/ (#14)
- Update deps + run clippy/fmt (#13)
- Migrate from embedded Rust-Atproto-SDK to proto-blue crate (#1)
- Delete Rust-Atproto-SDK directory and verify build (#12)
- Adapt cli/rotate_keys.rs to format_resign_commit (#11)
- Update api/repo.rs callers and signer plumbing (#10)
- Rewrite actor_store/repository.rs against proto_blue::repo::Repo (#9)
- Implement Signer wrapper around k256 PLC key (#8)
- Implement RepoStorage for ActorStore (SQLite-backed) (#7)
- Adapt actor_store/car.rs to proto-blue read_car/blocks_to_car (#6)
- Migrate leaf imports: did_doc, identity, oauth, syntax, tid (#5)
- Vendor blob mime/size helpers into src/blob_store/mime.rs (#4)
- Vendor PasswordHasher into src/auth/password.rs (#3)
- Add proto-blue dep, remove path dep on Rust-Atproto-SDK (#2)
