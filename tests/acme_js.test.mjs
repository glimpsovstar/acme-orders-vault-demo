// Run with: node --test tests/
// Loads static/acme.js in a vm context with a minimal stand-in for the DOM,
// then checks the text the AWS panel shows for each kind of report job note,
// and the labels on the Vault version tabs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function load() {
  const nodes = {};
  const node = () => ({
    textContent: '', className: '', classList: { add() {}, toggle() {} },
    replaceChildren(...kids) { this.children = kids; this.textContent = kids.map((k) => (typeof k === 'string' ? k : k.textContent)).join(''); },
    append(...kids) { this.kids = kids; }, setAttribute() {},
  });
  const document = {
    getElementById: (id) => (nodes[id] ??= node()),
    createElement: () => node(),
  };
  const ctx = vm.createContext({ document, fetch: () => new Promise(() => {}), setInterval: () => 0, Date });
  vm.runInContext(readFileSync(new URL('../acme/static/acme.js', import.meta.url), 'utf8'), ctx);
  return { aws: ctx.aws, vault: ctx.vault, nodes };
}

const changed = () => new Date(Date.now() - 10_000).toISOString();

function shown(message) {
  const { aws, nodes } = load();
  aws({ state: 'ok', message, masked: 'abcd1234', changed: changed() });
  return nodes['a-changed'].textContent;
}

test('a note that starts with an acronym keeps its capitals', () => {
  assert.match(shown('AWS matches Vault v8. Database login: ok'), /, AWS matches Vault v8$/);
});

test('a note that starts with an ordinary word continues the sentence in lower case', () => {
  assert.match(shown('The AWS password does not match a readable Vault version. Database login: refused'),
    /, the AWS password does not match a readable Vault version$/);
  assert.match(shown('Cannot compare with Vault right now. Database login: ok'), /, cannot compare with Vault right now$/);
});

test('the database result goes to the result line', () => {
  const { aws, nodes } = load();
  aws({ state: 'ok', message: 'AWS matches Vault v8. Database login: ok', masked: 'x', changed: changed() });
  assert.equal(nodes['a-result'].textContent, 'Database login: ok');
});

function tabLabels(versions, latest) {
  const { vault, nodes } = load();
  vault({ state: 'ok', version: latest, latest, message: 'Database login with v3: accepted', versions });
  return nodes.versions.children.map((b) => `${b.textContent} ${b.kids[0].textContent}`);
}

const ver = (version, state) => ({ version, state, created: '2026-11-25T01:00:00Z' });

test('the latest tab says Latest while the latest version is live', () => {
  assert.deepEqual(tabLabels([ver(1, 'destroyed'), ver(2, 'deleted'), ver(3, 'live')], 3).slice(0, 2),
    ['v1 Destroyed', 'v2 Deleted']);
  assert.equal(tabLabels([ver(1, 'live'), ver(2, 'live'), ver(3, 'live')], 3)[2], 'v3 Latest');
});

test('the latest tab says Deleted or Destroyed when the latest version is', () => {
  assert.equal(tabLabels([ver(1, 'live'), ver(2, 'deleted')], 2)[1], 'v2 Deleted');
  assert.equal(tabLabels([ver(1, 'live'), ver(2, 'destroyed')], 2)[1], 'v2 Destroyed');
});
