// Behavioural pins for AccountDetail's promptRationale() (#455).
//
// The bug: the confirm handler called handle.close() BEFORE resolve(v).
// AuroraModal.close() synchronously fires the spec's onClose → resolve(null),
// and a promise keeps its first settlement, so every Submit resolved null and
// the callers (Update handle / Update email / Send password reset) returned
// silently. Each piece looked right in isolation — the defect is the ordering
// between the page and the modal — so these tests run the REAL Modal.js and the
// REAL promptRationale source together instead of asserting on source shape.
//
// No jsdom (the repo carries no JS dependencies): a minimal fake DOM below
// covers exactly the surface Modal.js and promptRationale touch. Elements
// resolve querySelector('#id' / '.class') against their innerHTML string and
// hand back one stable fake child per selector, so a test can type into
// '#pr-r' and click '#pr-confirm'.
//
//   node --test static/admin/scripts/pages/__tests__/account-detail-rationale-prompt.test.js

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const SCRIPTS = path.resolve(__dirname, '..', '..');
const modalSrc = fs.readFileSync(path.join(SCRIPTS, 'components', 'Modal.js'), 'utf8');
const pageSrc = fs.readFileSync(path.join(SCRIPTS, 'pages', 'AccountDetail.js'), 'utf8');

// Pull `function promptRationale(...) { ... }` out of the page IIFE by brace
// matching (the function's string literals contain no braces).
function extractFunction(src, name) {
  const start = src.indexOf('function ' + name + '(');
  assert.ok(start >= 0, name + ' not found in AccountDetail.js');
  let depth = 0;
  for (let i = src.indexOf('{', start); i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error('unbalanced braces in ' + name);
}
const promptRationaleSrc = extractFunction(pageSrc, 'promptRationale');

class FakeNode {
  constructor(tagName) {
    this.tagName = tagName;
    this.id = '';
    this.className = '';
    this.value = '';
    this.children = [];
    this.parentNode = null;
    this._html = '';
    this._query = new Map();
    this._listeners = {};
    this._attrs = {};
    const classes = new Set();
    this.classList = {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
    };
  }
  set innerHTML(html) { this._html = html; this._query.clear(); }
  get innerHTML() { return this._html; }
  setAttribute(k, v) { this._attrs[k] = String(v); }
  getAttribute(k) { return k in this._attrs ? this._attrs[k] : null; }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  removeChild(child) {
    this.children = this.children.filter((c) => c !== child);
    child.parentNode = null;
    return child;
  }
  querySelector(sel) {
    if (this._query.has(sel)) return this._query.get(sel);
    let present = false;
    if (sel.startsWith('#')) {
      present = this._html.includes('id="' + sel.slice(1) + '"');
    } else if (sel.startsWith('.')) {
      present = new RegExp('class="[^"]*\\b' + sel.slice(1) + '\\b').test(this._html);
    }
    // Appended (non-innerHTML) children are searched too.
    if (!present) {
      for (const c of this.children) {
        const hit = c.querySelector(sel);
        if (hit) return hit;
      }
      return null;
    }
    const node = new FakeNode('x');
    node.parentNode = this;
    if (sel.startsWith('#')) node.id = sel.slice(1);
    this._query.set(sel, node);
    return node;
  }
  addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); }
  removeEventListener(type, fn) {
    this._listeners[type] = (this._listeners[type] || []).filter((f) => f !== fn);
  }
  dispatch(type, event) {
    for (const fn of [...(this._listeners[type] || [])]) fn(event);
  }
  click() { this.dispatch('click', { target: this }); }
}

// Build a fresh window with the real Modal.js loaded and promptRationale bound.
function setup() {
  const body = new FakeNode('body');
  const document = new FakeNode('#document');
  document.body = body;
  document.createElement = (tag) => new FakeNode(tag);
  document.getElementById = (id) => {
    const walk = (n) => {
      if (n.id === id) return n;
      for (const c of n.children) {
        const hit = walk(c);
        if (hit) return hit;
      }
      return null;
    };
    return walk(body);
  };
  const warnings = [];
  const win = {
    document,
    Node: FakeNode,
    setTimeout,
    AuroraToast: { warning: (m) => warnings.push(m) },
  };
  win.window = win;
  vm.createContext(win);
  vm.runInContext(modalSrc, win);
  vm.runInContext(
    '(function (global) {\n' +
      "  function esc(s) { return String(s == null ? '' : s); }\n" +
      promptRationaleSrc + '\n' +
      '  global.promptRationale = promptRationale;\n' +
      '})(window);',
    win,
  );

  const promise = win.promptRationale('Update handle', 'New handle: x', 'Update handle');
  const root = document.getElementById('modal-root');
  const modal = root.children[0];
  const panel = modal.querySelector('.modal-body').children[0];
  return {
    promise,
    warnings,
    modalOpen: () => root.children.length > 0,
    type: (text) => { panel.querySelector('#pr-r').value = text; },
    confirm: () => panel.querySelector('#pr-confirm').click(),
    cancel: () => panel.querySelector('#pr-cancel').click(),
    closeX: () => modal.querySelector('.modal-close').click(),
    escape: () => document.dispatch('keydown', { key: 'Escape' }),
    overlay: () => {
      const ov = document.getElementById('modal-overlay');
      ov.dispatch('click', { target: ov });
    },
  };
}

const PENDING = Symbol('pending');
const settled = (p) => Promise.race([p, new Promise((r) => setImmediate(() => r(PENDING)))]);

test('confirm with a typed rationale resolves to the trimmed rationale', async () => {
  const ui = setup();
  ui.type('  rename requested by holder  ');
  ui.confirm();
  assert.equal(await settled(ui.promise), 'rename requested by holder');
  assert.equal(ui.modalOpen(), false, 'modal closes on confirm');
  assert.deepEqual(ui.warnings, []);
});

for (const [how, act] of [
  ['Cancel', (ui) => ui.cancel()],
  ['the × button', (ui) => ui.closeX()],
  ['Esc', (ui) => ui.escape()],
  ['an overlay click', (ui) => ui.overlay()],
]) {
  test('dismissing via ' + how + ' resolves null', async () => {
    const ui = setup();
    ui.type('typed but abandoned');
    act(ui);
    assert.equal(await settled(ui.promise), null);
    assert.equal(ui.modalOpen(), false);
  });
}

test('an empty rationale keeps the modal open with a warning', async () => {
  const ui = setup();
  ui.type('   ');
  ui.confirm();
  assert.equal(await settled(ui.promise), PENDING, 'promise must not settle');
  assert.equal(ui.modalOpen(), true, 'modal stays open');
  assert.deepEqual(ui.warnings, ['Rationale is required.']);

  // Still usable afterwards: a real rationale then goes through.
  ui.type('now with a reason');
  ui.confirm();
  assert.equal(await settled(ui.promise), 'now with a reason');
});
