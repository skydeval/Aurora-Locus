// Federation ops page (route: #ops/federation).
// Per docs/AURORA_ADMIN_UI_DESIGN.md §5.4.6.2.
//
// #458: renders the server's real response shapes (getRelayConfig,
// getFederationStatus, listKnownInstances) and manages the LIVE relay set —
// the relays this PDS asks to crawl it — where Configuration → Federation
// policy points operators. The render functions are pure (data in, HTML out)
// and exposed as AuroraFederationView so tests can render real responses.

(function (global) {
  'use strict';

  let pollHandle = null;
  let isSuper = false;

  function esc(s) { return global.AuroraDom ? global.AuroraDom.esc(s) : String(s == null ? '' : s); }

  // Host (and port) of a URL, or the input when it isn't a URL.
  function hostOf(url) {
    try { return new URL(url).host; } catch (e) { return url || ''; }
  }

  // ---------- Pure renderers ----------

  // relay: getRelayConfig → { servers: [{url}], status, crawlActive, hostname }
  function renderRelays(relay, canManage) {
    const servers = (relay && Array.isArray(relay.servers)) ? relay.servers : [];
    if (!relay || relay.status === 'disabled') {
      return '<p class="empty-state">Federation is disabled, so this PDS has no relays.</p>';
    }
    const crawlLine = relay.crawlActive
      ? '<p class="settings-help">Relay crawl is <strong>on</strong>: this PDS asks each relay below to crawl ' +
        '<code>' + esc(relay.hostname || '') + '</code> at startup and when a relay is added.</p>'
      : '<p class="settings-help">Relay crawl is <strong>off</strong>: relays are not being asked to crawl this PDS. ' +
        'Turn on <a href="#configuration/federation-policy">Relay crawl</a> to announce it.</p>';

    let list;
    if (servers.length === 0) {
      list = '<p class="empty-state">No relays. This PDS is not announced to any relay.</p>';
    } else {
      list = '<table class="data-table"><thead><tr><th>Relay</th>' + (canManage ? '<th>Actions</th>' : '') +
        '</tr></thead><tbody>' +
        servers.map(function (s) {
          const url = esc(s.url);
          const actions = canManage
            ? '<td>' +
              '<button type="button" class="btn-secondary" data-action="crawl" data-url="' + url + '"' +
                (relay.crawlActive ? '' : ' disabled title="Relay crawl is off"') + '>Request crawl</button> ' +
              '<button type="button" class="btn-secondary" data-action="remove" data-url="' + url + '">Remove</button>' +
              '</td>'
            : '';
          return '<tr><td><code>' + url + '</code></td>' + actions + '</tr>';
        }).join('') +
        '</tbody></table>';
    }

    const controls = canManage
      ? '<div id="fed-relay-error"></div>' +
        '<div class="action-panel-buttons" style="margin-top:0.5rem;">' +
        '<input type="text" id="fed-relay-url" placeholder="https://relay.example" aria-label="Relay URL (https)">' +
        ' <button type="button" class="btn-primary" data-action="add">Add relay</button>' +
        (relay.crawlActive && servers.length
          ? ' <button type="button" class="btn-secondary" data-action="crawl-all">Request crawl from all</button>'
          : '') +
        '</div>'
      : '<p class="settings-help">SuperAdmin role required to manage relays.</p>';

    return crawlLine + list + controls;
  }

  // status: getFederationStatus → { enabled, relayCount, crawlActive, knownInstances, searchEnabled, status }
  function renderStatus(status) {
    const s = status || {};
    const onOff = function (b) { return b ? 'on' : 'off'; };
    return '<p><strong>Federation:</strong> ' + (s.enabled ? 'enabled' : 'disabled') + '</p>' +
      '<p><strong>Relays:</strong> ' + esc(s.relayCount || 0) + '</p>' +
      '<p><strong>Relay crawl:</strong> ' + onOff(s.crawlActive) + '</p>' +
      '<p><strong>Known instances:</strong> ' + esc(s.knownInstances || 0) + '</p>' +
      '<p><strong>Federated search:</strong> ' + onOff(s.searchEnabled) + '</p>';
  }

  // items: listKnownInstances.instances → [{ did, url, name, openRegistrations, userCount, lastSeen }]
  // lastSeen is unix seconds; configured peers carry none.
  function renderInstances(items) {
    if (!items || items.length === 0) {
      return '<p class="empty-state">No known instances. Trusted peers configured under ' +
        '<a href="#configuration/federation-policy">Federation policy</a> appear here.</p>';
    }
    return '<table class="data-table"><thead><tr><th>Host</th><th>DID</th><th>Last seen</th></tr></thead><tbody>' +
      items.map(function (i) {
        const host = i.url ? hostOf(i.url) : '';
        const seen = (typeof i.lastSeen === 'number')
          ? global.AuroraTimestamp.render({ value: i.lastSeen * 1000, context: 'activity' })
          : 'configured peer';
        return '<tr>' +
          '<td>' + (host ? esc(host) : '<em>no URL</em>') + (i.name ? ' <span class="settings-help">' + esc(i.name) + '</span>' : '') + '</td>' +
          '<td><code>' + esc(i.did) + '</code></td>' +
          '<td>' + seen + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table>';
  }

  // requestRelayCrawl → { hostname, results: [{url, ok, attempts, error?}] }
  function summarizeCrawl(resp) {
    const results = (resp && resp.results) || [];
    const failed = results.filter(function (r) { return !r.ok; });
    if (failed.length === 0) {
      return { ok: true, message: 'Crawl requested from ' + results.length + ' relay' + (results.length === 1 ? '' : 's') + '.' };
    }
    return {
      ok: false,
      message: failed.length + ' of ' + results.length + ' crawl request' + (results.length === 1 ? '' : 's') +
        ' failed: ' + failed.map(function (r) { return r.url + ' (' + (r.error || 'error') + ')'; }).join('; '),
    };
  }

  // ---------- Page ----------

  async function mount({ container }) {
    const session = global.AuroraSession;
    isSuper = !!(session && session.hasRole('superadmin'));
    container.innerHTML =
      '<nav class="breadcrumb"><a href="#dashboard">Operations</a> <span class="breadcrumb-sep">›</span> Federation</nav>' +
      '<header class="page-header"><div><h2>Federation</h2><p class="page-subtitle">Relays, peers, federation activity</p></div></header>' +
      '<div class="ops-section"><h3>Relays</h3><div id="fed-relay">' + global.AuroraSkeleton.lines(3) + '</div></div>' +
      '<div class="ops-section"><h3>Federation status</h3><div id="fed-status">' + global.AuroraSkeleton.lines(3) + '</div></div>' +
      '<div class="ops-section"><h3>Known instances</h3><div id="fed-peers">' + global.AuroraSkeleton.lines(3) + '</div></div>';
    container.addEventListener('click', onClick);
    await refresh();
    pollHandle = setInterval(refresh, 60_000);
    return {
      unmount: function () {
        if (pollHandle) clearInterval(pollHandle);
        pollHandle = null;
        container.removeEventListener('click', onClick);
      },
    };
  }

  function set(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  async function refresh() {
    const ep = global.AuroraEndpoints;
    if (!ep) return;
    try {
      set('fed-relay', renderRelays(await ep.ops.getRelayConfig(), isSuper));
    } catch (e) {
      set('fed-relay', '<p class="empty-state">Unavailable.</p>');
    }
    try {
      set('fed-status', renderStatus(await ep.ops.getFederationStatus()));
    } catch (e) {
      set('fed-status', '<p class="empty-state">Unavailable.</p>');
    }
    try {
      const resp = await ep.ops.listKnownInstances({ limit: 25 });
      set('fed-peers', renderInstances((resp && resp.instances) || []));
    } catch (e) {
      set('fed-peers', '<p class="empty-state">Unavailable.</p>');
    }
  }

  function showRelayError(e, fallback) {
    const msg = (e && e.message) ? e.message : fallback;
    const el = document.getElementById('fed-relay-error');
    if (el && global.AuroraInlineError) el.innerHTML = global.AuroraInlineError.render({ message: msg });
    else global.AuroraToast.danger(msg);
  }

  async function onClick(ev) {
    const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-action]') : null;
    if (!btn || !isSuper) return;
    const action = btn.getAttribute('data-action');
    const url = btn.getAttribute('data-url');
    const ops = global.AuroraEndpoints.ops;
    try {
      if (action === 'crawl' || action === 'crawl-all') {
        const resp = await global.AuroraSpinner.busy(btn, function () {
          return ops.requestRelayCrawl(action === 'crawl' ? { url: url } : {});
        });
        const summary = summarizeCrawl(resp);
        if (summary.ok) global.AuroraToast.success(summary.message);
        else showRelayError(null, summary.message);
      } else if (action === 'remove') {
        const r = await global.AuroraModal.destructiveConfirm({
          heading: 'Remove relay',
          body: 'Remove ' + url + ' from the relay set? This PDS stops announcing itself to it.',
          confirmLabel: 'Remove relay',
        });
        if (!r.confirmed) return;
        await ops.removeRelayUrl({ url: url });
        global.AuroraToast.success('Relay removed.');
        await refresh();
      } else if (action === 'add') {
        const input = document.getElementById('fed-relay-url');
        const value = ((input && input.value) || '').trim();
        if (!value) { showRelayError(null, 'Enter a relay URL (https).'); return; }
        await ops.addRelayUrl({ url: value });
        global.AuroraToast.success('Relay added.');
        await refresh();
      }
    } catch (e) {
      showRelayError(e, 'Relay action failed.');
    }
  }

  global.AuroraFederationView = {
    renderRelays: renderRelays,
    renderStatus: renderStatus,
    renderInstances: renderInstances,
    summarizeCrawl: summarizeCrawl,
  };
  if (global.AuroraRouter) global.AuroraRouter.register('opsFederation', { mount: mount });
})(window);
