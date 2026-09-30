import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
globalThis.crypto ??= webcrypto;
await import('./zmath-mail-crypto.js');
const core = globalThis.ZMathMailCrypto;
const recipient = (address, device) => ({address, deviceId: device.deviceId, encryptionPublicJwk: device.encryptionPublicJwk, signingPublicJwk: device.signingPublicJwk});
async function fixture(extra = []) {
  const sender = await core.generateDevice(); const receiver = await core.generateDevice();
  const envelope = await core.encryptForDevices({plaintext: 'Two independent layers and a device signature.', from: 'sender@example.invalid', devices: [recipient('receiver@example.invalid', receiver), ...extra], senderDevice: sender});
  return {sender, receiver, envelope};
}
test('portable signed envelope restores both AES-GCM layers and validates its included key', async () => {
  const {receiver, envelope} = await fixture();
  assert.equal(envelope.version, 2); assert.equal(envelope.algorithm, 'AES-256-GCMx2/ECDH-P256/HKDF-SHA256/ECDSA-P256');
  const opened = await core.decryptForDevice(core.unarmor(core.armor(envelope)).envelope, receiver);
  assert.equal(opened.plaintext, 'Two independent layers and a device signature.'); assert.equal(opened.verified, true); assert.equal(opened.from, 'sender@example.invalid');
});
test('non-recipient device cannot open the signed envelope', async () => {
  const {envelope} = await fixture(); const stranger = await core.generateDevice();
  await assert.rejects(core.decryptForDevice(envelope, stranger), /not encrypted for this browser device/);
});
test('changed ciphertext fails signature validation before plaintext is produced', async () => {
  const {receiver, envelope} = await fixture();
  envelope.outer.ciphertext = envelope.outer.ciphertext.slice(0, -1) + (envelope.outer.ciphertext.endsWith('A') ? 'B' : 'A');
  await assert.rejects(core.decryptForDevice(envelope, receiver), /signature is invalid/);
});
test('opaque v2 slots hide recipient addresses and device identifiers', async () => {
  const blind = await core.generateDevice(); const {receiver, envelope} = await fixture([recipient('private-bcc@example.invalid', blind)]);
  const serialized = JSON.stringify(envelope);
  for (const secret of ['receiver@example.invalid', 'private-bcc@example.invalid', receiver.deviceId, blind.deviceId]) assert.equal(serialized.includes(secret), false);
  assert.equal(Object.hasOwn(envelope, 'to'), false); assert.equal(Object.hasOwn(envelope, 'recipients'), false);
  assert.equal((await core.decryptForDevice(envelope, blind)).plaintext, 'Two independent layers and a device signature.');
});
test('a recomputed signature cannot authenticate a false fingerprint label', async () => {
  const {sender, receiver, envelope} = await fixture(); envelope.sender.fingerprint = 'forged-fingerprint';
  const signed = {...envelope}; delete signed.signature;
  envelope.signature = Buffer.from(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, sender.signingPrivateKey, new TextEncoder().encode(core.canonical(signed)))).toString('base64url');
  await assert.rejects(core.decryptForDevice(envelope, receiver), /sender fingerprint is invalid/);
});
test('preserved code has exact published hash and no network or persistent store', async () => {
  const bytes = await readFile(new URL('./zmath-mail-crypto.js', import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '01c6442ac4080a64a8641ea657cac872f43514c1a9822b11b5ba1eb7287de7d9');
  assert.doesNotMatch(bytes.toString(), /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage|sessionStorage|indexedDB)\b/);
});
test('unsupported versions and excessive recipient directories are refused', async () => {
  const {receiver, envelope} = await fixture();
  await assert.rejects(core.decryptForDevice({...envelope, version: 99}, receiver), /not a supported/);
  await assert.rejects(core.decryptForDevice({...envelope, recipientSlots: Array(65).fill({})}, receiver), /invalid recipient directory/);
});
