// Render pins for Operations → Federation (#458: #460 / #461 / #462).
//
// The page used to read fields the server never sent (relay.relayUrl /
// relay.mode, i.hostname / i.lastSeenAt / i.status), so it showed
// "Relay: unconfigured" while a relay was in use and a Known-instances table
// of blank hosts marked "active". These tests render the page's pure view
// functions against representative server responses, and pin the Rust
// response field names the page depends on so the two cannot drift apart
// again unnoticed.
//
//   node --test static/admin/scripts/pages/__tests__/federation-page-render.test.js

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const SCRIPTS = path.resolve(__dirname, '..', '..');
const pageSrc = fs.readFileSync(path.join(SCRIPTS, 'pages', 'Federation.js'), 'utf8');
const adminRs = fs.readFileSync(path.resolve(SCRIPTS, '..', '..', '..', 'src', 'api', 'admin.rs'), 'utf8');

function loadView() {
  const win = {
    AuroraDom: {
      esc: (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
    },
    AuroraTimestamp: { render: ({ value }) => '<time>' + value + '</time>' },
  };
  new Function('window', pageSrc)(win);
  return win.AuroraFederationView;
}

// Representative responses, shaped exactly as src/api/admin.rs serializes them.
const RELAY_ACTIVE = {
  servers: [{ url: 'https://bsky.network' }, { url: 'https://relay.example' }],
  status: 'active',
  crawlActive: true,
  hostname: 'locus.nearhorizon.app',
};
const STATUS = {
  enabled: true,
  serviceDid: 'did:web:locus.nearhorizon.app',
  relayCount: 2,
  crawlActive: true,
  discoveryEnabled: true,
  searchEnabled: true,
  knownInstances: 2,
  status: 'active',
};
const INSTANCES = [
  { did: 'did:plc:peer', url: 'https://peer.example.com', name: 'Peer', openRegistrations: false, userCount: null, lastSeen: 1790000000 },
  { did: 'did:plc:configured', url: 'https://cfg.example.com:8443', name: null, openRegistrations: false, userCount: null, lastSeen: null },
];

test('relays: lists the live set with crawl and remove controls for a SuperAdmin', () => {
  const html = loadView().renderRelays(RELAY_ACTIVE, true);
  assert.match(html, /<code>https:\/\/bsky\.network<\/code>/);
  assert.match(html, /<code>https:\/\/relay\.example<\/code>/);
  assert.match(html, /<code>locus\.nearhorizon\.app<\/code>/, 'announced hostname shown');
  assert.equal((html.match(/data-action="crawl" data-url=/g) || []).length, 2);
  assert.equal((html.match(/data-action="remove" data-url=/g) || []).length, 2);
  assert.match(html, /data-action="crawl-all"/);
  assert.match(html, /data-action="add"/);
  assert.doesNotMatch(html, /unconfigured/);
  assert.doesNotMatch(html, / disabled title="Relay crawl is off"/);
});

test('relays: crawl off disables Request crawl and says how to turn it on', () => {
  const html = loadView().renderRelays(Object.assign({}, RELAY_ACTIVE, { crawlActive: false }), true);
  assert.match(html, /Relay crawl is <strong>off<\/strong>/);
  assert.match(html, /href="#configuration\/federation-policy"/);
  assert.equal((html.match(/ disabled title="Relay crawl is off"/g) || []).length, 2);
  assert.doesNotMatch(html, /crawl-all/);
});

test('relays: an empty set is shown as such and can still be added to', () => {
  const html = loadView().renderRelays({ servers: [], status: 'no_servers', crawlActive: true, hostname: 'h' }, true);
  assert.match(html, /No relays\. This PDS is not announced to any relay\./);
  assert.match(html, /data-action="add"/);
  assert.doesNotMatch(html, /crawl-all/);
});

test('relays: federation disabled, and read-only for non-SuperAdmins', () => {
  const view = loadView();
  assert.match(view.renderRelays({ servers: [], status: 'disabled', crawlActive: false, hostname: null }, true),
    /Federation is disabled/);
  const ro = view.renderRelays(RELAY_ACTIVE, false);
  assert.match(ro, /https:\/\/bsky\.network/);
  assert.doesNotMatch(ro, /data-action=/);
  assert.match(ro, /SuperAdmin role required/);
});

test('relays: URLs are escaped', () => {
  const html = loadView().renderRelays({ servers: [{ url: 'https://x"><script>' }], status: 'active', crawlActive: true, hostname: 'h' }, true);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&quot;&gt;&lt;script&gt;/);
});

test('status: renders the fields the server sends', () => {
  const html = loadView().renderStatus(STATUS);
  assert.match(html, /Federation:<\/strong> enabled/);
  assert.match(html, /Relays:<\/strong> 2/);
  assert.match(html, /Relay crawl:<\/strong> on/);
  assert.match(html, /Known instances:<\/strong> 2/);
  assert.match(html, /Federated search:<\/strong> on/);
});

test('instances: real hosts, DIDs and last-seen times; configured peers labelled', () => {
  const html = loadView().renderInstances(INSTANCES);
  assert.match(html, /<td>peer\.example\.com <span class="settings-help">Peer<\/span><\/td>/);
  assert.match(html, /<td>cfg\.example\.com:8443<\/td>/);
  assert.match(html, /<code>did:plc:peer<\/code>/);
  assert.match(html, /<time>1790000000000<\/time>/, 'lastSeen seconds rendered as milliseconds');
  assert.match(html, /configured peer/);
  assert.doesNotMatch(html, /active/, 'no invented status column');
});

test('instances: empty list and URL-less rows', () => {
  const view = loadView();
  assert.match(view.renderInstances([]), /No known instances/);
  assert.match(view.renderInstances([{ did: 'did:plc:x', url: '', lastSeen: null }]), /<em>no URL<\/em>/);
});

test('crawl summary: all ok vs failures named', () => {
  const view = loadView();
  assert.deepEqual(view.summarizeCrawl({ results: [{ url: 'a', ok: true, attempts: 1 }] }),
    { ok: true, message: 'Crawl requested from 1 relay.' });
  const bad = view.summarizeCrawl({ results: [
    { url: 'https://a', ok: true, attempts: 1 },
    { url: 'https://b', ok: false, attempts: 1, error: 'https://b answered HTTP 400: nope' },
  ] });
  assert.equal(bad.ok, false);
  assert.match(bad.message, /^1 of 2 crawl requests failed: https:\/\/b \(https:\/\/b answered HTTP 400: nope\)$/);
});

// ---- Server-side field pins: the view reads these camelCase names. ----

function structBody(name) {
  const m = adminRs.match(new RegExp('struct ' + name + ' \\{([\\s\\S]*?)\\n\\}'));
  assert.ok(m, name + ' not found in admin.rs');
  return m[1];
}

test('server: RelayConfigResponse / RelayServerInfo fields match the view', () => {
  const relay = structBody('RelayConfigResponse');
  for (const f of ['servers', 'status', 'crawl_active', 'hostname']) {
    assert.match(relay, new RegExp('\\b' + f + ':'), 'RelayConfigResponse.' + f);
  }
  assert.match(structBody('RelayServerInfo'), /\burl:/);
});

test('server: FederationStatusResponse and KnownInstanceInfo fields match the view', () => {
  const status = structBody('FederationStatusResponse');
  for (const f of ['enabled', 'relay_count', 'crawl_active', 'known_instances', 'search_enabled']) {
    assert.match(status, new RegExp('\\b' + f + ':'), 'FederationStatusResponse.' + f);
  }
  const inst = structBody('KnownInstanceInfo');
  for (const f of ['did', 'url', 'name', 'last_seen']) {
    assert.match(inst, new RegExp('\\b' + f + ':'), 'KnownInstanceInfo.' + f);
  }
});
