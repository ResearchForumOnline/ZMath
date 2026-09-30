import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash, webcrypto} from 'node:crypto';
import * as Core from './zshield-core.js';

globalThis.crypto ??= webcrypto;
const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
for (const name of ['app.js', 'zshield-core.js', 'qpu-factor-core.js']) {
  const code = await readFile(new URL(name, import.meta.url), 'utf8');
  assert.doesNotMatch(code, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/);
  assert.doesNotMatch(code, /\b(?:localStorage|sessionStorage|indexedDB)\b/);
}
assert.match(html, /connect-src 'none'/);
for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
  const target = match[1];
  assert.doesNotMatch(target, /^https?:|^\/\//);
  if (target !== './') await readFile(new URL(target, import.meta.url));
}
assert.equal(createHash('sha256').update(await readFile(new URL('./zshield-core.js', import.meta.url))).digest('hex'), 'c48b5af56a50a2c75f682d56843fdc9a82da7714cda1ddee602c5620fa5df8d6');
assert.match(source, /MAX_CONTAINER_BYTES = 72 \* 1024 \* 1024/);
assert.match(source, /transport: 'offline'/);

const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
assert.equal(new Set(ids).size, ids.length);
const elements = new Map(ids.map(id => [id, {id, value: '', files: [], checked: false, disabled: false, hidden: false, dataset: {}, listeners: new Map(), addEventListener(event, handler) {this.listeners.set(event, handler);}, setAttribute(name, value) {this[name] = value;}}]));
const downloads = [];
globalThis.document = {
  getElementById: id => elements.get(id),
  querySelectorAll: () => [...elements.values()],
  createElement: () => ({href: '', download: '', click() {downloads.push(this.download);}, remove() {}}),
  body: {append() {}}
};
const urls = new Map();
URL.createObjectURL = blob => {const url = `blob:fixture-${urls.size}`; urls.set(url, blob); return url;};
URL.revokeObjectURL = () => {};
globalThis.setTimeout = () => 1;
const {safeDownloadName} = await import('./app.js');
const element = id => elements.get(id);
const click = async id => element(id).listeners.get('click')();
assert.equal(safeDownloadName('../../payload.html'), '.._.._payload.html');
element('passphrase').value = 'Noncommercial-test-passphrase-2026';
element('message').value = 'Local preservation UI round trip';
await click('encryptMessage');
assert.equal(element('status').dataset.kind, 'success');
const envelope = element('messageOutput').value;
assert.match(envelope, /^ZSHIELD1:/);
assert.equal(Core.decodeMessageContainer(envelope).header.context.transport, 'offline');
element('message').value = envelope;
await click('decryptMessage');
assert.equal(element('messageOutput').value, 'Local preservation UI round trip');
await click('downloadMessage');
assert.equal(downloads.at(-1), 'zmath-message.txt');
element('passphrase').value = 'Wrong-passphrase-long-enough';
element('messageOutput').value = '';
await click('decryptMessage');
assert.equal(element('status').dataset.kind, 'error');
assert.equal(element('messageOutput').value, '');
element('passphrase').value = 'Noncommercial-test-passphrase-2026';
const plaintext = new TextEncoder().encode('local-file-fixture');
element('payload').files = [{name: 'evidence.txt', type: 'text/plain', size: plaintext.length, arrayBuffer: async () => plaintext.slice().buffer}];
await click('encryptFile');
assert.equal(downloads.at(-1), 'evidence.txt.zme1.json');
const encrypted = await [...urls.values()].at(-1).text();
const raw = new TextEncoder().encode(encrypted);
element('payload').files = [{name: 'evidence.txt.zme1.json', size: raw.length, arrayBuffer: async () => raw.slice().buffer}];
await click('decryptFile');
assert.equal(element('status').dataset.kind, 'success');
assert.equal(downloads.at(-1), 'evidence.txt');
assert.equal(await [...urls.values()].at(-1).text(), 'local-file-fixture');
element('payload').files = [{name: 'oversized.json', size: 73 * 1024 * 1024, arrayBuffer() {throw new Error('Must not read oversized input');}}];
await click('decryptFile');
assert.match(element('status').textContent, /size limit/);
await click('generate');
assert.match(element('passphrase').value, /^[a-f0-9]{48}$/);
await click('clear');
assert.equal(element('passphrase').value, '');
assert.equal(element('messageOutput').value, '');
console.log('Preservation source hashes, local links, no network/storage APIs, file/message UI round trips and bounds: passed');
