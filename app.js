import * as Core from './zshield-core.js';
import {parseQuantumFactorFile} from './qpu-factor-core.js';

const byId = id => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});
let busy = false;
let result = '';
const MAX_CONTAINER_BYTES = 72 * 1024 * 1024;
const MAX_FACTOR_BYTES = 1024 * 1024;

export function safeDownloadName(value) {
  return String(value || 'restored.bin').replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_').replace(/[. ]+$/g, '').slice(0, 160) || 'restored.bin';
}

function status(message, kind = '') {
  byId('status').textContent = message;
  byId('status').dataset.kind = kind;
}

function download(bytes, name, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], {type}));
  const link = document.createElement('a');
  link.href = url; link.download = safeDownloadName(name);
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

async function fileBytes(file, limit, label) {
  if (!file) throw new Error(`Choose ${label} first.`);
  if (file.size > limit) throw new Error(`${label} exceeds its supported size limit.`);
  return new Uint8Array(await file.arrayBuffer());
}

async function factors() {
  const passphrase = byId('passphrase').value;
  if (passphrase.length < 14) throw new Error('Use a passphrase with at least 14 characters.');
  const patternFile = byId('pattern').files[0];
  const patternBytes = patternFile ? await fileBytes(patternFile, MAX_FACTOR_BYTES, 'pattern file') : new Uint8Array();
  const externalFile = byId('external').files[0];
  let quantumFactorBytes = new Uint8Array();
  try {
    if (externalFile) {
      const raw = await fileBytes(externalFile, MAX_FACTOR_BYTES, 'external factor file');
      if (!raw.length) throw new Error('The external factor must not be empty.');
      if (byId('structuredFactor').checked) {
        try {
          const parsed = await parseQuantumFactorFile(decoder.decode(raw), {requireHardware: false});
          quantumFactorBytes = parsed.factorBytes;
        } finally { raw.fill(0); }
      } else quantumFactorBytes = raw;
    }
    return {passphrase, patternBytes, quantumFactorBytes};
  } catch (error) {patternBytes.fill(0); quantumFactorBytes.fill(0); throw error;}
}

async function run(operation) {
  if (busy) return;
  if (!globalThis.crypto?.subtle) {status('Web Crypto is unavailable. Open this app on localhost or HTTPS.', 'error'); return;}
  busy = true;
  result = '';
  byId('messageOutput').value = '';
  document.querySelectorAll('button').forEach(button => button.disabled = true);
  status('Working locally. Password derivation can take a few seconds…');
  let secrets;
  try {secrets = await factors(); await operation(secrets);}
  catch (error) {status(error.message || 'Operation failed.', 'error');}
  finally {
    secrets?.patternBytes.fill(0); secrets?.quantumFactorBytes.fill(0);
    busy = false;
    document.querySelectorAll('button').forEach(button => button.disabled = false);
  }
}

byId('encryptFile').addEventListener('click', () => run(async secrets => {
  const file = byId('payload').files[0];
  const bytes = await fileBytes(file, Core.MAX_PAYLOAD_BYTES, 'a plaintext file');
  try {
    const container = await Core.protectPayload({...secrets, bytes, name: file.name, type: file.type || 'application/octet-stream', kind: 'file', context: {purpose: 'local-file', transport: 'offline'}});
    download(JSON.stringify(container, null, 2), file.name + '.zme1.json', 'application/json');
    status('Encrypted container downloaded. Keep the passphrase and factor files separately.', 'success');
  } finally {bytes.fill(0);}
}));

byId('decryptFile').addEventListener('click', () => run(async secrets => {
  const raw = await fileBytes(byId('payload').files[0], MAX_CONTAINER_BYTES, 'a ZME1 container');
  let container;
  try {container = JSON.parse(decoder.decode(raw));}
  catch {throw new Error('This file is not a valid ZME1 JSON container.');}
  finally {raw.fill(0);}
  if (container.mode || !container.header) throw new Error('This older Portable/Exclusive format is not supported by the preserved ZShield core. Do not discard its original recovery factors.');
  const opened = await Core.openContainerPayload({...secrets, container});
  try {download(opened.bytes, opened.header.payload.name);}
  finally {opened.bytes.fill(0);}
  status('Authentication succeeded. Restored file downloaded as an attachment.', 'success');
}));

byId('encryptMessage').addEventListener('click', () => run(async secrets => {
  const bytes = encoder.encode(byId('message').value);
  if (!bytes.length || bytes.length > Core.MAX_MESSAGE_BYTES) throw new Error('Enter a message between 1 byte and 12 KiB.');
  let container;
  try {container = await Core.protectPayload({...secrets, bytes, name: 'zmath-message.txt', type: 'text/plain;charset=utf-8', kind: 'matrix-message', context: {purpose: 'local-message', transport: 'offline'}});}
  finally {bytes.fill(0);}
  result = Core.encodeMessageContainer(container);
  byId('messageOutput').value = result;
  status('Encrypted message ready. Copy the complete envelope or download it.', 'success');
}));

byId('decryptMessage').addEventListener('click', () => run(async secrets => {
  if (encoder.encode(byId('message').value).length > 90000) throw new Error('The message envelope exceeds its supported size limit.');
  const opened = await Core.openMessage({...secrets, envelope: byId('message').value});
  result = opened.message;
  byId('messageOutput').value = result;
  status('Authentication succeeded. Message restored locally.', 'success');
}));
byId('downloadMessage').addEventListener('click', () => {
  if (!result) {status('Create or decrypt a message first.', 'error'); return;}
  download(result, 'zmath-message.txt', 'text/plain;charset=utf-8');
});
byId('generate').addEventListener('click', () => {
  const random = crypto.getRandomValues(new Uint8Array(24));
  byId('passphrase').value = Array.from(random, value => value.toString(16).padStart(2, '0')).join('');
  random.fill(0);
  status('A 192-bit random passphrase was generated locally. Save it before using it.', 'success');
});
byId('showPassphrase').addEventListener('change', () => byId('passphrase').type = byId('showPassphrase').checked ? 'text' : 'password');
for (const [tab, visible, hidden] of [['fileTab', 'files', 'messages'], ['messageTab', 'messages', 'files']]) {
  byId(tab).addEventListener('click', () => {
    byId(visible).hidden = false; byId(hidden).hidden = true;
    byId('fileTab').setAttribute('aria-pressed', String(visible === 'files'));
    byId('messageTab').setAttribute('aria-pressed', String(visible === 'messages'));
  });
}
byId('clear').addEventListener('click', () => {
  for (const id of ['passphrase', 'pattern', 'external', 'payload', 'message', 'messageOutput']) byId(id).value = '';
  byId('showPassphrase').checked = false; byId('passphrase').type = 'password';
  byId('structuredFactor').checked = false; result = '';
  status('Inputs cleared. JavaScript cannot guarantee immediate erasure of all browser memory copies.');
});
if (!globalThis.crypto?.subtle) status('Web Crypto requires HTTPS or localhost. Follow README.md to serve this app locally.', 'error');
