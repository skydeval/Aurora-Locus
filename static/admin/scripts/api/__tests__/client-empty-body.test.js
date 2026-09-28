// Response-body handling in AuroraClient's handle() (#457).
//
// Several admin XRPC procedures have no output schema and answer a bare 200
// with an empty body (the Rust handlers return `Ok(StatusCode::OK)`, as the
// reference PDS does for e.g. com.atproto.admin.updateAccountHandle). handle()
// used to call res.json() on every non-204 success, which throws on an empty
// body — so a change the server had already applied showed as
// "Update failed: JSON.parse: unexpected end of data". An empty 2xx body now
// resolves null; JSON bodies still parse; non-2xx still throws.
//
// No framework: bare Node, with a stub window and a stubbed fetch returning
// real WHATWG Responses (Node 18+ global).
//
//   node --test static/admin/scripts/api/__tests__/client-empty-body.test.js

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

// Load client.js against a stub window whose fetch always answers `respond()`.
function loadClient(respond) {
  const storage = new Map();
  const win = {
    localStorage: {
      getItem: (k) => (storage.has(k) ? storage.get(k) : null),
      setItem: (k, v) => storage.set(k, String(v)),
      removeItem: (k) => storage.delete(k),
    },
    addEventListener() {},
  };
  globalThis.localStorage = win.localStorage;
  globalThis.fetch = async () => respond();
  const src = fs.readFileSync(path.resolve(__dirname, '..', 'client.js'), 'utf8');
  return new Function('window', src + '\nreturn window.AuroraClient;')(win);
}

const json = (status, obj) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

test('a 200 with an empty body resolves null (POST and GET)', async () => {
  const client = loadClient(() => new Response('', { status: 200 }));
  assert.equal(
    await client.post('com.atproto.admin.updateAccountHandle', { did: 'did:plc:x', handle: 'a.test' }),
    null,
  );
  assert.equal(await client.get('tools.aurora.admin.someQuery'), null);
});

test('a whitespace-only 2xx body also resolves null', async () => {
  const client = loadClient(() => new Response('  \n', { status: 200 }));
  assert.equal(await client.post('x.y.z', {}), null);
});

test('a 204 still resolves null', async () => {
  const client = loadClient(() => new Response(null, { status: 204 }));
  assert.equal(await client.post('x.y.z', {}), null);
});

test('a 200 with a JSON body parses', async () => {
  const client = loadClient(() => json(200, { did: 'did:plc:x', ok: true }));
  assert.deepEqual(await client.get('x.y.z'), { did: 'did:plc:x', ok: true });
});

test('a 2xx with a malformed JSON body still rejects', async () => {
  const client = loadClient(() => new Response('{"half":', { status: 200 }));
  await assert.rejects(client.get('x.y.z'), SyntaxError);
});

test('a non-2xx still throws, carrying the status and server message', async () => {
  const client = loadClient(() => json(409, { error: 'Conflict', message: 'Handle taken' }));
  await assert.rejects(client.post('x.y.z', {}), (err) => {
    assert.equal(err.status, 409);
    assert.equal(err.serverMessage, 'Handle taken');
    return true;
  });
});

test('a non-2xx with an empty body still throws', async () => {
  const client = loadClient(() => new Response('', { status: 500 }));
  await assert.rejects(client.post('x.y.z', {}), (err) => {
    assert.equal(err.status, 500);
    assert.match(err.message, /HTTP 500/);
    return true;
  });
});
