import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

await import(pathToFileURL(resolve(
  'ops/roundcube-zmath-mail/zmath-mail-crypto.js'
)).href);

const cryptoModule = globalThis.ZMathMailCrypto;

function recipient(address, device) {
  return {
    address,
    deviceId: device.deviceId,
    encryptionPublicJwk: device.encryptionPublicJwk,
    signingPublicJwk: device.signingPublicJwk,
  };
}

test('ZMath Mail dual-layer envelope round-trips and verifies its sender signature', async () => {
  const sender = await cryptoModule.generateDevice();
  const receiver = await cryptoModule.generateDevice();
  const envelope = await cryptoModule.encryptForDevices({
    plaintext: 'Two independent layers and a device signature.',
    from: 'alice@zmail.my',
    devices: [
      recipient('alice@zmail.my', sender),
      recipient('bob@zmail.my', receiver),
    ],
    senderDevice: sender,
  });
  assert.equal(envelope.version, 2);
  assert.equal(envelope.algorithm, 'AES-256-GCMx2/ECDH-P256/HKDF-SHA256/ECDSA-P256');
  assert.equal(envelope.recipientSlots.length, 2);
  const armored = cryptoModule.armor(envelope);
  const parsed = cryptoModule.unarmor(armored);
  const opened = await cryptoModule.decryptForDevice(parsed.envelope, receiver);
  assert.equal(opened.plaintext, 'Two independent layers and a device signature.');
  assert.equal(opened.verified, true);
  assert.equal(opened.from, 'alice@zmail.my');
});

test('ZMath Mail refuses a device that was not an envelope recipient', async () => {
  const sender = await cryptoModule.generateDevice();
  const receiver = await cryptoModule.generateDevice();
  const stranger = await cryptoModule.generateDevice();
  const envelope = await cryptoModule.encryptForDevices({
    plaintext: 'Only the intended device opens this.',
    from: 'alice@zmail.my',
    devices: [recipient('bob@zmail.my', receiver)],
    senderDevice: sender,
  });
  await assert.rejects(
    cryptoModule.decryptForDevice(envelope, stranger),
    /not encrypted for this browser device/
  );
});

test('ZMath Mail detects envelope tampering before opening content', async () => {
  const sender = await cryptoModule.generateDevice();
  const receiver = await cryptoModule.generateDevice();
  const envelope = await cryptoModule.encryptForDevices({
    plaintext: 'Authenticated twice.',
    from: 'alice@zmail.my',
    devices: [recipient('bob@zmail.my', receiver)],
    senderDevice: sender,
  });
  envelope.outer.ciphertext = `${envelope.outer.ciphertext.slice(0, -1)}${
    envelope.outer.ciphertext.endsWith('A') ? 'B' : 'A'
  }`;
  await assert.rejects(
    cryptoModule.decryptForDevice(envelope, receiver),
    /signature is invalid/
  );
});

test('ZMath Mail v2 hides recipient and BCC addresses behind unlinkable opaque slots', async () => {
  const sender = await cryptoModule.generateDevice();
  const receiver = await cryptoModule.generateDevice();
  const blindCopy = await cryptoModule.generateDevice();
  const envelope = await cryptoModule.encryptForDevices({
    plaintext: 'Recipient privacy survives the shared protected payload.',
    from: 'alice@zmail.my',
    devices: [
      recipient('bob@zmail.my', receiver),
      recipient('private-bcc@zmail.my', blindCopy),
    ],
    senderDevice: sender,
  });
  const serialized = JSON.stringify(envelope);
  assert.equal(Object.hasOwn(envelope, 'to'), false);
  assert.equal(Object.hasOwn(envelope, 'recipients'), false);
  assert.equal(serialized.includes('bob@zmail.my'), false);
  assert.equal(serialized.includes('private-bcc@zmail.my'), false);
  assert.equal(serialized.includes(receiver.deviceId), false);
  assert.equal(serialized.includes(blindCopy.deviceId), false);
  assert.equal(envelope.recipientSlots.every((slot) => typeof slot.slotId === 'string'), true);
  assert.equal(
    (await cryptoModule.decryptForDevice(envelope, blindCopy)).plaintext,
    'Recipient privacy survives the shared protected payload.',
  );
});

test('ZMath Mail recomputes and rejects a forged sender fingerprint label', async () => {
  const sender = await cryptoModule.generateDevice();
  const receiver = await cryptoModule.generateDevice();
  const envelope = await cryptoModule.encryptForDevices({
    plaintext: 'The label must match the actual signing key.',
    from: 'alice@zmail.my',
    devices: [recipient('bob@zmail.my', receiver)],
    senderDevice: sender,
  });
  envelope.sender.fingerprint = 'forged-fingerprint';
  const signed = { ...envelope };
  delete signed.signature;
  envelope.signature = await (async () => {
    const signature = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      sender.signingPrivateKey,
      new TextEncoder().encode(cryptoModule.canonical(signed)),
    );
    return Buffer.from(signature).toString('base64url');
  })();
  await assert.rejects(
    cryptoModule.decryptForDevice(envelope, receiver),
    /sender fingerprint is invalid/,
  );
});

test('Roundcube integration synchronises encrypted content and fails closed server-side', async () => {
  const browserPlugin = await readFile(
    resolve('ops/roundcube-zmath-mail/zmath_mail.js'),
    'utf8'
  );
  const serverPlugin = await readFile(
    resolve('ops/roundcube-zmath-mail/zmath_mail.php'),
    'utf8'
  );
  assert.match(browserPlugin, /rcmail\.editor\.save\(\)/);
  assert.match(browserPlugin, /Require ZMath/);
  assert.match(browserPlugin, /Drafts remain standard mailbox data/);
  assert.match(browserPlugin, /mode === "require"/);
  assert.match(serverPlugin, /message_before_send/);
  assert.match(serverPlugin, /BEGIN ZMAIL ZMATH PROTECTED MESSAGE/);
  assert.match(serverPlugin, /X-Zmail-ZMath/);
  assert.match(serverPlugin, /\$args\['abort'\]\s*=\s*true/);
  assert.match(serverPlugin, /zmath_rate_limits/);
  assert.doesNotMatch(serverPlugin, /'lastSeenAt'\s*=>/);
});
