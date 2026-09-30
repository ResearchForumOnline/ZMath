import {decryptVault, encryptVault, updatePatternSequence, MAX_ATTACHMENT_BYTES, MAX_IMPORT_BYTES} from './site/assets/zmath-shield.js';

const $ = id => document.getElementById(id);
const pattern = [];
let encrypted = '';
let restoredAttachment = null;
let busy = false;
const encoder = new TextEncoder();
const points = [...document.querySelectorAll('[data-point]')];
const status = (message, kind = '') => { $('status').textContent = message; $('status').dataset.kind = kind; };
const clearResult = () => {
  restoredAttachment?.bytes.fill(0); restoredAttachment = null;
  $('resultTitle').textContent = ''; $('resultMeta').textContent = ''; $('resultNote').textContent = '';
  $('result').hidden = true; $('downloadAttachment').hidden = true;
};
const paintPattern = () => {
  for (const point of points) {
    const order = pattern.indexOf(Number(point.dataset.point));
    point.setAttribute('aria-pressed', String(order >= 0));
    point.textContent = order >= 0 ? `${point.dataset.point} · ${order + 1}` : point.dataset.point;
  }
  $('patternCount').textContent = pattern.length ? `${pattern.length} selected in order. ${pattern.length < 6 ? `Choose ${6 - pattern.length} more.` : 'Pattern ready.'}` : 'Choose at least 6 squares.';
};
const clearPattern = () => { pattern.splice(0); paintPattern(); };
const setBusy = value => {
  busy = value;
  for (const control of document.querySelectorAll('button, input, textarea')) control.disabled = value;
  $('downloadVault').disabled = value || !encrypted;
  $('status').setAttribute('aria-busy', String(value));
};
const download = (blob, filename) => {
  const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.rel = 'noopener'; document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
};
const downloadVault = () => {
  if (!encrypted) return;
  const suffix = [...crypto.getRandomValues(new Uint8Array(4))].map(x => x.toString(16).padStart(2, '0')).join('');
  download(new Blob([encrypted], {type: 'application/json'}), `zmath-shield-${new Date().toISOString().slice(0, 10)}-${suffix}.zmath`);
};
const operate = async operation => {
  if (busy) return;
  setBusy(true);
  try { await operation(); } catch (error) { status(error?.message || 'This local operation failed.', 'error'); }
  finally { setBusy(false); }
};
const switchTab = unlock => {
  $('lockPanel').hidden = unlock; $('unlockPanel').hidden = !unlock;
  $('lockTab').setAttribute('aria-pressed', String(!unlock)); $('unlockTab').setAttribute('aria-pressed', String(unlock));
  clearResult();
};
for (const point of points) point.addEventListener('click', () => {updatePatternSequence(pattern, Number(point.dataset.point)); paintPattern();});
$('clearPattern').addEventListener('click', clearPattern);
$('lockTab').addEventListener('click', () => switchTab(false));
$('unlockTab').addEventListener('click', () => switchTab(true));
$('showPassphrase').addEventListener('change', () => { $('passphrase').type = $('showPassphrase').checked ? 'text' : 'password'; $('confirm').type = $('passphrase').type; });
$('generate').addEventListener('click', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(24)); const secret = [...bytes].map(x => x.toString(16).padStart(2, '0')).join(''); bytes.fill(0);
  $('passphrase').value = secret; $('confirm').value = secret; status('Random passphrase generated. Save it in your password manager before encryption.');
});
$('encrypt').addEventListener('click', () => operate(async () => {
  if ($('passphrase').value !== $('confirm').value) throw new Error('The passphrase entries do not match.');
  const file = $('attachment').files?.[0];
  if (file && file.size > MAX_ATTACHMENT_BYTES) throw new Error('Choose an attachment no larger than 8 MiB.');
  status('Deriving two keys and building both authenticated layers locally…', 'working');
  let bytes = null;
  try {
    bytes = file ? new Uint8Array(await file.arrayBuffer()) : null;
    const vault = await encryptVault({title: $('title').value, note: $('note').value, attachment: file ? {name: file.name, type: file.type, bytes} : null}, $('passphrase').value, [...pattern]);
    encrypted = JSON.stringify(vault, null, 2); $('vaultOutput').value = encrypted; downloadVault();
    for (const id of ['title', 'note', 'attachment', 'passphrase', 'confirm']) $(id).value = '';
    clearPattern(); status('Encrypted vault downloaded. Plaintext and inputs cleared from this page. Keep your vault and both inputs safely.', 'success');
  } finally { bytes?.fill(0); }
}));
$('downloadVault').addEventListener('click', downloadVault);
$('decrypt').addEventListener('click', () => operate(async () => {
  clearResult(); const file = $('vaultFile').files?.[0];
  if (file && file.size > MAX_IMPORT_BYTES) throw new Error('The vault exceeds the 20 MiB import limit.');
  const input = file ? await file.text() : $('vaultInput').value;
  if (encoder.encode(input).length > MAX_IMPORT_BYTES) throw new Error('The vault exceeds the 20 MiB import limit.');
  if (!input.trim()) throw new Error('Choose a .zmath file or paste its encrypted JSON.');
  status('Opening the pattern layer, then the passphrase layer locally…', 'working');
  const opened = await decryptVault(input, $('passphrase').value, [...pattern]);
  $('resultTitle').textContent = opened.title || 'Untitled protected item'; $('resultNote').textContent = opened.note;
  $('resultMeta').textContent = `${opened.createdAt}${opened.attachment ? ` · ${opened.attachment.name} · ${opened.attachment.size} bytes` : ' · private note'}`;
  restoredAttachment = opened.attachment; $('downloadAttachment').hidden = !restoredAttachment; $('result').hidden = false;
  status('Both authenticated layers opened. The restored content stays in this tab until you clear it.', 'success');
}));
$('downloadAttachment').addEventListener('click', () => {
  if (restoredAttachment) download(new Blob([restoredAttachment.bytes], {type: 'application/octet-stream'}), restoredAttachment.name);
});
$('clearResult').addEventListener('click', () => { clearResult(); status('Decrypted result cleared from this tab.'); });
$('clear').addEventListener('click', () => {
  for (const id of ['passphrase', 'confirm', 'title', 'note', 'attachment', 'vaultFile', 'vaultInput', 'vaultOutput']) $(id).value = '';
  encrypted = ''; $('downloadVault').disabled = true; $('showPassphrase').checked = false; $('passphrase').type = 'password'; $('confirm').type = 'password';
  clearPattern(); clearResult(); status('Inputs and results cleared. Browser and operating-system memory erasure is not guaranteed.');
});
$('selfTest').addEventListener('click', () => operate(async () => {
  status('Testing two layers with synthetic content and checking wrong-input rejection…', 'working');
  const testPass = 'Local-synthetic-self-test-passphrase-2026'; const testPattern = [1, 5, 9, 8, 4, 2, 3, 6];
  const fixture = await encryptVault({note: 'ZMath local self-test'}, testPass, testPattern);
  const opened = await decryptVault(fixture, testPass, testPattern);
  if (opened.note !== 'ZMath local self-test') throw new Error('Local self-test failed: content mismatch.');
  let rejected = false; try { await decryptVault(fixture, 'Wrong-synthetic-self-test-passphrase', testPattern); } catch (error) { rejected = error?.code === 'OPEN_FAILED'; }
  if (!rejected) throw new Error('Local self-test failed: wrong passphrase accepted.');
  status('Local self-test passed: both layers restored synthetic content and refused a wrong passphrase. Your inputs were not used.', 'success');
}));
window.addEventListener('pagehide', clearResult);
paintPattern();
