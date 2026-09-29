# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The PDS asks its relays to crawl it (`com.atproto.sync.requestCrawl`) when federation and relay crawl are both on: at startup, as soon as relay crawl is switched on, and for each relay added to the relay set, retrying failures with backoff and recording each request in the audit trail. Previously nothing told a relay the PDS existed, so a new PDS was never indexed unless the operator called each relay by hand. SuperAdmins can also request a crawl on demand (`tools.aurora.ops.requestRelayCrawl`, for all relays or one)

### Changed

- `.env.example` sets `RUST_LOG=info` (was `info,aurora_locus=debug`), so a copied example config doesn't write debug-level logs

### Fixed

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
- Handles under the PDS's handle domains now verify: `/.well-known/atproto-did` answers by the requested hostname, returning the account's DID for `<name>.<handle-domain>` (404 `User not found` for unknown, deactivated or taken-down accounts, and for unrelated hosts) while the service hostname still returns the server's DID. Previously every hostname got the server's DID, so Bluesky and other clients showed hosted handles as invalid
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
