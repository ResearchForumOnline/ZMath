import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  decryptVault,
  encryptVault,
  MAX_PASSPHRASE_LENGTH,
  PBKDF2_ITERATIONS,
  updatePatternSequence,
} from '../site/assets/zmath-shield.js';

const passphrase = 'Violet train windows remember 7 quiet stars!';
const pattern = [1, 5, 9, 8, 4, 2, 3, 6];
const payload = {
  title: 'Project Phoenix',
  note: 'Private launch phrase: cobalt orchard.',
  attachment: {
    name: 'launch-plan.txt',
    type: 'text/plain',
    bytes: new Uint8Array([0, 1, 2, 65, 90, 253, 254, 255]),
  },
};

let fixturePromise;
const fixture = () => {
  fixturePromise ||= encryptVault(payload, passphrase, pattern);
  return fixturePromise;
};

test('ZMath Shield round-trips a note and binary attachment through two AES-GCM layers', { timeout: 30_000 }, async () => {
  const vault = await fixture();

  assert.equal(vault.format, 'zmath-shield');
  assert.equal(vault.version, 1);
  assert.equal(vault.protection, 'two-layer-authenticated-encryption');
  assert.equal(vault.outer.factor, 'visual-pattern');
  assert.equal(vault.outer.cipher, 'AES-256-GCM');
  assert.equal(vault.outer.kdf.name, 'PBKDF2-HMAC-SHA-256');
  assert.equal(vault.outer.kdf.iterations, PBKDF2_ITERATIONS);
  assert.equal(Object.hasOwn(vault, 'inner'), false, 'the passphrase layer must itself be inside outer ciphertext');

  const opened = await decryptVault(vault, passphrase, pattern);
  assert.equal(opened.title, payload.title);
  assert.equal(opened.note, payload.note);
  assert.equal(opened.attachment.name, payload.attachment.name);
  assert.equal(opened.attachment.type, payload.attachment.type);
  assert.deepEqual(opened.attachment.bytes, payload.attachment.bytes);
  opened.attachment.bytes.fill(0);
});

test('the exported JSON contains no note, label, filename, passphrase, or pattern sequence', { timeout: 30_000 }, async () => {
  const vault = await fixture();
  const serialized = JSON.stringify(vault);

  for (const secret of [
    payload.title,
    payload.note,
    payload.attachment.name,
    passphrase,
    pattern.join('-'),
  ]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test('wrong inputs and authenticated-envelope tampering fail closed', { timeout: 30_000 }, async () => {
  const vault = await fixture();

  await assert.rejects(
    decryptVault(vault, passphrase, [1, 2, 3, 4, 5, 6]),
    (error) => error?.code === 'OPEN_FAILED',
  );
  await assert.rejects(
    decryptVault(vault, 'This is definitely the wrong passphrase!', pattern),
    (error) => error?.code === 'OPEN_FAILED',
  );

  const tampered = structuredClone(vault);
  tampered.createdAt = new Date(Date.parse(vault.createdAt) + 1000).toISOString();
  await assert.rejects(
    decryptVault(tampered, passphrase, pattern),
    (error) => error?.code === 'OPEN_FAILED',
  );
});

test('weak metadata and oversized direct-use passphrases are rejected before decryption', { timeout: 30_000 }, async () => {
  const vault = structuredClone(await fixture());
  vault.outer.kdf.iterations = 1;
  await assert.rejects(
    decryptVault(vault, passphrase, pattern),
    (error) => error?.code === 'FORMAT',
  );
  await assert.rejects(
    encryptVault({ note: 'x' }, 'p'.repeat(MAX_PASSPHRASE_LENGTH + 1), pattern),
    (error) => error?.code === 'PASSPHRASE',
  );
});

test('the browser vault module contains no network or persistent-storage primitive', async () => {
  const source = await readFile(new URL('../site/assets/zmath-shield.js', import.meta.url), 'utf8');
  for (const primitive of [
    'fetch(',
    'XMLHttpRequest',
    'sendBeacon',
    'WebSocket',
    'localStorage',
    'sessionStorage',
  ]) {
    assert.equal(source.includes(primitive), false, primitive);
  }
});

test('the visual pattern controller adds the first point and only removes the last point', () => {
  const sequence = [];
  updatePatternSequence(sequence, 1);
  updatePatternSequence(sequence, 5);
  updatePatternSequence(sequence, 9);
  assert.deepEqual(sequence, [1, 5, 9]);

  updatePatternSequence(sequence, 5);
  assert.deepEqual(sequence, [1, 5, 9], 'a middle point cannot be removed out of order');

  updatePatternSequence(sequence, 9);
  assert.deepEqual(sequence, [1, 5], 'the last point acts as undo');
});
