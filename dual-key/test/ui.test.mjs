import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash, webcrypto} from 'node:crypto';
globalThis.crypto ??= webcrypto;
const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
const elements = new Map(ids.map(id => [id, {id, value: '', files: [], checked: false, disabled: false, hidden: false, type: '', dataset: {}, listeners: new Map(), addEventListener(event, handler) {this.listeners.set(event, handler);}, setAttribute(name, value) {this[name] = value;}}]));
const points = Array.from({length: 9}, (_, index) => ({dataset: {point: String(index + 1)}, textContent: '', listeners: new Map(), addEventListener(event, handler) {this.listeners.set(event, handler);}, setAttribute(name, value) {this[name] = value;}}));
const downloads = [];
const blobs = new Map();
globalThis.document = {getElementById: id => elements.get(id), querySelector: () => null, querySelectorAll: query => query === '[data-point]' ? points : [...elements.values(), ...points], createElement: () => ({href: '', download: '', click() {downloads.push({name: this.download, blob: blobs.get(this.href)});}, remove() {}}), body: {append() {}}};
globalThis.window = {addEventListener() {}};
URL.createObjectURL = blob => {const url = `blob:fixture-${blobs.size}`; blobs.set(url, blob); return url;};
URL.revokeObjectURL = () => {};
globalThis.setTimeout = () => 1;
await import('../app.js');
const $ = id => elements.get(id);
const click = id => $(id).listeners.get('click')();
const select = async () => {await click('clearPattern'); for (const index of [0, 4, 8, 7, 3, 1, 2, 5]) await points[index].listeners.get('click')();};
test('unchanged dual-key module and original tests retain exact hashes', async () => {
  for (const [name, expected] of [['../site/assets/zmath-shield.js', 'f12953ded126c9991f4137b64f1aa609fc2391942960b4d7d8a3c7f0ed7d3fc8'], ['./zmath-shield.test.mjs', '744c1896128fc8d76523032fb20990b43025722e7d8bbda2d02cd1c4d0110560']]) assert.equal(createHash('sha256').update(await readFile(new URL(name, import.meta.url))).digest('hex'), expected);
});
test('standalone links exist and runtime scripts have no network/storage primitives', async () => {
  assert.match(html, /connect-src 'none'/); assert.equal(new Set(ids).size, ids.length);
  for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {assert.doesNotMatch(match[1], /^https?:|^\/\//); await readFile(new URL(match[1].endsWith('/') ? `${match[1]}index.html` : match[1], new URL('../index.html', import.meta.url)));}
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage|sessionStorage|indexedDB)\b/);
  assert.match(html, /under 20 bits/); assert.match(source, /type: 'application\/octet-stream'/);
});
test('dual-key interface round-trips synthetic note and attachment and clears failures', {timeout: 30_000}, async () => {
  const passphrase = 'Synthetic independent dual-key fixture passphrase 2026';
  $('passphrase').value = passphrase; $('confirm').value = passphrase; $('title').value = 'Synthetic review'; $('note').value = 'Local browser vault fixture';
  const raw = new Uint8Array([1, 2, 3, 4, 255]);
  $('attachment').files = [{name: '../../example.html', type: 'text/html', size: raw.length, arrayBuffer: async () => raw.slice().buffer}];
  await select(); await click('encrypt'); assert.equal($('status').dataset.kind, 'success');
  const vault = $('vaultOutput').value; assert.equal($('passphrase').value, ''); assert.equal($('note').value, ''); assert.match(downloads.at(-1).name, /^zmath-shield-.*\.zmath$/);
  assert.equal(vault.includes('Local browser vault fixture'), false);
  await click('unlockTab'); $('vaultInput').value = vault; $('passphrase').value = passphrase; await select(); await click('decrypt');
  assert.equal($('result').hidden, false); assert.equal($('resultNote').textContent, 'Local browser vault fixture');
  await click('downloadAttachment'); assert.equal(downloads.at(-1).name, '.._.._example.html'); assert.equal(downloads.at(-1).blob.type, 'application/octet-stream'); assert.deepEqual(new Uint8Array(await downloads.at(-1).blob.arrayBuffer()), raw);
  $('passphrase').value = 'Wrong fixture passphrase long enough'; await click('decrypt'); assert.equal($('status').dataset.kind, 'error'); assert.equal($('result').hidden, true); assert.equal($('resultNote').textContent, '');
  $('vaultFile').files = [{size: 21 * 1024 * 1024, text() {throw new Error('Oversized file must not be read');}}]; await click('decrypt'); assert.match($('status').textContent, /20 MiB/);
  await click('clear'); assert.equal($('vaultInput').value, ''); assert.equal($('vaultOutput').value, ''); assert.equal($('downloadVault').disabled, true);
});
test('passphrase generation and synthetic local self-test are independent of private input', {timeout: 30_000}, async () => {
  await click('generate'); assert.match($('passphrase').value, /^[a-f0-9]{48}$/); assert.equal($('confirm').value, $('passphrase').value);
  const privateInput = $('passphrase').value; await click('selfTest'); assert.equal($('status').dataset.kind, 'success'); assert.match($('status').textContent, /self-test passed/); assert.equal($('passphrase').value, privateInput); await click('clear');
});
