const FORMAT = "zmath-shield";
const VERSION = 1;
const CIPHER = "AES-256-GCM";
const KDF = "PBKDF2-HMAC-SHA-256";
const HASH = "SHA-256";

export const PBKDF2_ITERATIONS = 600_000;
export const MIN_PASSPHRASE_LENGTH = 12;
export const MAX_PASSPHRASE_LENGTH = 512;
export const MIN_PATTERN_POINTS = 6;
export const MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024;
export const MAX_NOTE_CHARACTERS = 100_000;
export const MAX_IMPORT_BYTES = 20 * 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class ZMathShieldError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ZMathShieldError";
    this.code = code;
  }
}

function webCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new ZMathShieldError("UNAVAILABLE", "This browser does not provide the Web Crypto API required by ZMath Shield.");
  }
  return globalThis.crypto;
}

function randomBytes(length) {
  return webCrypto().getRandomValues(new Uint8Array(length));
}

function toBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(value, maximumBytes = MAX_IMPORT_BYTES) {
  if (
    typeof value !== "string"
    || value.length > Math.ceil(maximumBytes / 3) * 4 + 8
    || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new ZMathShieldError("FORMAT", "The selected file is not a valid ZMath Shield vault.");
  }
  const binary = atob(value);
  if (binary.length > maximumBytes) {
    throw new ZMathShieldError("TOO_LARGE", "The selected vault is larger than this browser tool accepts.");
  }
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
  return output;
}

function assertPassphrase(passphrase) {
  if (
    typeof passphrase !== "string"
    || passphrase.length < MIN_PASSPHRASE_LENGTH
    || passphrase.length > MAX_PASSPHRASE_LENGTH
  ) {
    throw new ZMathShieldError(
      "PASSPHRASE",
      `Use a passphrase of ${MIN_PASSPHRASE_LENGTH}–${MAX_PASSPHRASE_LENGTH} characters. Spaces and punctuation are allowed.`,
    );
  }
}

function normalisePattern(pattern) {
  if (!Array.isArray(pattern)) {
    throw new ZMathShieldError("PATTERN", `Choose at least ${MIN_PATTERN_POINTS} different pattern squares.`);
  }
  const points = pattern.map((point) => Number(point));
  if (
    points.length < MIN_PATTERN_POINTS
    || points.length > 9
    || points.some((point) => !Number.isInteger(point) || point < 1 || point > 9)
    || new Set(points).size !== points.length
  ) {
    throw new ZMathShieldError(
      "PATTERN",
      `Choose ${MIN_PATTERN_POINTS} to 9 different pattern squares in a memorable order.`,
    );
  }
  return points;
}

function patternSecret(pattern) {
  return `ZMath-Shield-visual-pattern-v1\u0000${normalisePattern(pattern).join("-")}`;
}

function aadFor(layer, factor, createdAt = "") {
  return encoder.encode([
    FORMAT,
    String(VERSION),
    layer,
    factor,
    CIPHER,
    KDF,
    HASH,
    String(PBKDF2_ITERATIONS),
    createdAt,
  ].join("\u0000"));
}

async function deriveAesKey(secret, salt) {
  const secretBytes = encoder.encode(secret);
  try {
    const material = await webCrypto().subtle.importKey(
      "raw",
      secretBytes,
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return await webCrypto().subtle.deriveKey(
      { name: "PBKDF2", hash: HASH, salt, iterations: PBKDF2_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    secretBytes.fill(0);
  }
}

async function encryptLayer(plaintext, secret, factor, layer, createdAt = "") {
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const key = await deriveAesKey(secret, salt);
  const ciphertext = new Uint8Array(await webCrypto().subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadFor(layer, factor, createdAt), tagLength: 128 },
    key,
    plaintext,
  ));
  return {
    factor,
    cipher: CIPHER,
    kdf: { name: KDF, hash: HASH, iterations: PBKDF2_ITERATIONS },
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
}

function assertLayer(layer, expectedFactor) {
  if (
    !layer
    || typeof layer !== "object"
    || layer.factor !== expectedFactor
    || layer.cipher !== CIPHER
    || layer.kdf?.name !== KDF
    || layer.kdf?.hash !== HASH
    || layer.kdf?.iterations !== PBKDF2_ITERATIONS
    || typeof layer.salt !== "string"
    || typeof layer.iv !== "string"
    || typeof layer.ciphertext !== "string"
  ) {
    throw new ZMathShieldError("FORMAT", "The selected file is not a supported ZMath Shield vault.");
  }
}

async function decryptLayer(layer, secret, expectedFactor, layerName, createdAt = "") {
  assertLayer(layer, expectedFactor);
  const salt = fromBase64(layer.salt, 64);
  const iv = fromBase64(layer.iv, 32);
  if (salt.length !== 32 || iv.length !== 12) {
    throw new ZMathShieldError("FORMAT", "The selected file has invalid cryptographic parameters.");
  }
  const ciphertext = fromBase64(layer.ciphertext);
  const key = await deriveAesKey(secret, salt);
  try {
    return new Uint8Array(await webCrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: aadFor(layerName, expectedFactor, createdAt),
        tagLength: 128,
      },
      key,
      ciphertext,
    ));
  } finally {
    salt.fill(0);
    iv.fill(0);
    ciphertext.fill(0);
  }
}

function cleanTitle(value) {
  return typeof value === "string" ? value.slice(0, 120) : "";
}

function cleanFilename(value) {
  if (typeof value !== "string") return "restored-file";
  const cleaned = value.replace(/[\u0000-\u001f\u007f/\\:*?"<>|]/g, "_").trim().slice(0, 180);
  return cleaned || "restored-file";
}

function cleanMime(value) {
  if (typeof value !== "string" || value.length > 160 || !/^[\w.+-]+\/[\w.+-]+(?:;[\w .="'()+,-]+)?$/.test(value)) {
    return "application/octet-stream";
  }
  return value;
}

function payloadForEncryption(payload) {
  if (!payload || typeof payload !== "object") {
    throw new ZMathShieldError("CONTENT", "Add a private note or choose a file to protect.");
  }
  const note = typeof payload.note === "string" ? payload.note : "";
  if (note.length > MAX_NOTE_CHARACTERS) {
    throw new ZMathShieldError("NOTE_TOO_LARGE", `Keep the private note under ${MAX_NOTE_CHARACTERS.toLocaleString()} characters.`);
  }
  let attachment = null;
  if (payload.attachment) {
    const bytes = payload.attachment.bytes;
    if (!(bytes instanceof Uint8Array)) {
      throw new ZMathShieldError("CONTENT", "The selected attachment could not be read.");
    }
    if (bytes.byteLength > MAX_ATTACHMENT_BYTES) {
      throw new ZMathShieldError("ATTACHMENT_TOO_LARGE", "Choose a file no larger than 8 MB.");
    }
    attachment = {
      name: cleanFilename(payload.attachment.name),
      type: cleanMime(payload.attachment.type),
      size: bytes.byteLength,
      data: toBase64(bytes),
    };
  }
  if (!note && !attachment) {
    throw new ZMathShieldError("CONTENT", "Add a private note, choose a file, or do both.");
  }
  return {
    payloadVersion: 1,
    title: cleanTitle(payload.title),
    note,
    attachment,
    createdAt: new Date().toISOString(),
  };
}

function parsePayload(bytes) {
  let payload;
  try {
    payload = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new ZMathShieldError("OPEN_FAILED", "The vault could not be opened.");
  }
  if (
    !payload
    || typeof payload !== "object"
    || payload.payloadVersion !== 1
    || typeof payload.title !== "string"
    || payload.title.length > 120
    || typeof payload.note !== "string"
    || payload.note.length > MAX_NOTE_CHARACTERS
    || typeof payload.createdAt !== "string"
  ) {
    throw new ZMathShieldError("FORMAT", "The decrypted payload is not a supported ZMath Shield item.");
  }
  let attachment = null;
  if (payload.attachment !== null) {
    if (
      !payload.attachment
      || typeof payload.attachment !== "object"
      || typeof payload.attachment.name !== "string"
      || typeof payload.attachment.type !== "string"
      || !Number.isInteger(payload.attachment.size)
      || payload.attachment.size < 0
      || payload.attachment.size > MAX_ATTACHMENT_BYTES
    ) {
      throw new ZMathShieldError("FORMAT", "The decrypted attachment metadata is invalid.");
    }
    const attachmentBytes = fromBase64(payload.attachment.data, MAX_ATTACHMENT_BYTES);
    if (attachmentBytes.byteLength !== payload.attachment.size) {
      attachmentBytes.fill(0);
      throw new ZMathShieldError("FORMAT", "The decrypted attachment length is invalid.");
    }
    attachment = {
      name: cleanFilename(payload.attachment.name),
      type: cleanMime(payload.attachment.type),
      size: attachmentBytes.byteLength,
      bytes: attachmentBytes,
    };
  }
  return {
    title: payload.title,
    note: payload.note,
    attachment,
    createdAt: payload.createdAt,
  };
}

export async function encryptVault(payload, passphrase, pattern) {
  assertPassphrase(passphrase);
  const selectedPattern = normalisePattern(pattern);
  const protectedPayload = payloadForEncryption(payload);
  const payloadBytes = encoder.encode(JSON.stringify(protectedPayload));
  try {
    const inner = await encryptLayer(payloadBytes, passphrase, "passphrase", "inner");
    const innerBytes = encoder.encode(JSON.stringify({ version: VERSION, layer: "inner", ...inner }));
    try {
      const outer = await encryptLayer(
        innerBytes,
        patternSecret(selectedPattern),
        "visual-pattern",
        "outer",
        protectedPayload.createdAt,
      );
      return {
        format: FORMAT,
        version: VERSION,
        createdAt: protectedPayload.createdAt,
        protection: "two-layer-authenticated-encryption",
        outer: { layer: "outer", ...outer },
      };
    } finally {
      innerBytes.fill(0);
    }
  } finally {
    payloadBytes.fill(0);
  }
}

function parseEnvelope(input) {
  let envelope = input;
  if (typeof input === "string") {
    if (new Blob([input]).size > MAX_IMPORT_BYTES) {
      throw new ZMathShieldError("TOO_LARGE", "The selected vault is larger than this browser tool accepts.");
    }
    try {
      envelope = JSON.parse(input);
    } catch {
      throw new ZMathShieldError("FORMAT", "The selected file is not valid JSON.");
    }
  }
  if (
    !envelope
    || typeof envelope !== "object"
    || envelope.format !== FORMAT
    || envelope.version !== VERSION
    || envelope.protection !== "two-layer-authenticated-encryption"
    || typeof envelope.createdAt !== "string"
    || Number.isNaN(Date.parse(envelope.createdAt))
  ) {
    throw new ZMathShieldError("FORMAT", "The selected file is not a supported ZMath Shield vault.");
  }
  assertLayer(envelope.outer, "visual-pattern");
  if (envelope.outer.layer !== "outer") {
    throw new ZMathShieldError("FORMAT", "The selected file has an invalid outer layer.");
  }
  return envelope;
}

export async function decryptVault(input, passphrase, pattern) {
  assertPassphrase(passphrase);
  const selectedPattern = normalisePattern(pattern);
  const envelope = parseEnvelope(input);
  let innerBytes;
  let payloadBytes;
  try {
    innerBytes = await decryptLayer(
      envelope.outer,
      patternSecret(selectedPattern),
      "visual-pattern",
      "outer",
      envelope.createdAt,
    );
    let inner;
    try {
      inner = JSON.parse(decoder.decode(innerBytes));
    } catch {
      throw new ZMathShieldError("OPEN_FAILED", "The vault could not be opened.");
    }
    if (inner?.version !== VERSION || inner?.layer !== "inner") {
      throw new ZMathShieldError("FORMAT", "The decrypted vault contains an unsupported inner layer.");
    }
    payloadBytes = await decryptLayer(inner, passphrase, "passphrase", "inner");
    return parsePayload(payloadBytes);
  } catch (error) {
    if (error instanceof ZMathShieldError && ["FORMAT", "TOO_LARGE", "UNAVAILABLE"].includes(error.code)) throw error;
    throw new ZMathShieldError(
      "OPEN_FAILED",
      "Could not open this vault. A passphrase or pattern is wrong, or the file was changed or damaged.",
    );
  } finally {
    innerBytes?.fill(0);
    payloadBytes?.fill(0);
  }
}

function select(root, selector) {
  return root.querySelector(selector);
}

function selectAll(root, selector) {
  return Array.from(root.querySelectorAll(selector));
}

function setStatus(node, message, kind = "") {
  node.textContent = message;
  node.className = `shield-status${kind ? ` ${kind}` : ""}`;
}

function setBusy(form, busy) {
  form.setAttribute("aria-busy", String(busy));
  selectAll(form, "button, input, textarea").forEach((control) => {
    control.disabled = busy;
  });
}

export function updatePatternSequence(sequence, number) {
  if (
    !Array.isArray(sequence)
    || !Number.isInteger(number)
    || number < 1
    || number > 9
  ) {
    throw new ZMathShieldError("PATTERN", "The visual pattern selection is invalid.");
  }
  const selectedAt = sequence.indexOf(number);
  if (selectedAt >= 0 && selectedAt === sequence.length - 1) sequence.pop();
  else if (selectedAt < 0 && sequence.length < 9) sequence.push(number);
  return sequence;
}

function createPatternController(root) {
  const sequence = [];
  const points = selectAll(root, "[data-pattern-point]");
  const output = select(root, "[data-pattern-count]");

  const paint = () => {
    points.forEach((point) => {
      const number = Number(point.dataset.patternPoint);
      const order = sequence.indexOf(number);
      point.classList.toggle("selected", order >= 0);
      point.setAttribute("aria-pressed", String(order >= 0));
      select(point, "span").textContent = order >= 0 ? String(order + 1) : String(number);
      point.setAttribute(
        "aria-label",
        order >= 0 ? `Pattern point ${number}, selected ${order + 1}` : `Pattern point ${number}`,
      );
    });
    output.textContent = sequence.length
      ? `${sequence.length} selected · choose ${Math.max(0, MIN_PATTERN_POINTS - sequence.length)} more minimum`
      : `Choose ${MIN_PATTERN_POINTS}–9 different squares`;
    root.dispatchEvent(new CustomEvent("zmath:pattern-change", { bubbles: true }));
  };

  points.forEach((point) => point.addEventListener("click", () => {
    const number = Number(point.dataset.patternPoint);
    updatePatternSequence(sequence, number);
    paint();
  }));
  select(root, "[data-pattern-clear]").addEventListener("click", () => {
    sequence.splice(0);
    paint();
  });
  paint();
  return {
    value: () => [...sequence],
    clear: () => {
      sequence.splice(0);
      paint();
    },
  };
}

function safeDownloadName() {
  const suffix = Array.from(randomBytes(4), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `zmath-shield-${new Date().toISOString().slice(0, 10)}-${suffix}.zmath`;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function describeBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function initialiseShield(root) {
  const tabs = selectAll(root, "[data-shield-mode]");
  const panels = selectAll(root, "[data-shield-panel]");
  const lockForm = select(root, "[data-shield-lock-form]");
  const unlockForm = select(root, "[data-shield-unlock-form]");
  const lockPattern = createPatternController(select(lockForm, "[data-pattern-pad]"));
  const unlockPattern = createPatternController(select(unlockForm, "[data-pattern-pad]"));
  const lockStatus = select(lockForm, "[data-shield-status]");
  const unlockStatus = select(unlockForm, "[data-shield-status]");
  const fileSummary = select(lockForm, "[data-lock-file-summary]");
  const vaultSummary = select(unlockForm, "[data-vault-file-summary]");
  const result = select(root, "[data-shield-result]");
  let activeAttachment = null;

  const clearResult = () => {
    activeAttachment?.bytes?.fill(0);
    activeAttachment = null;
    select(result, "[data-result-title]").textContent = "";
    select(result, "[data-result-meta]").textContent = "";
    select(result, "[data-result-note]").textContent = "";
    select(result, "[data-result-note-wrap]").hidden = true;
    select(result, "[data-result-attachment]").hidden = true;
    result.hidden = true;
  };

  const switchMode = (mode) => {
    tabs.forEach((tab) => {
      const selected = tab.dataset.shieldMode === mode;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.shieldPanel !== mode;
    });
    if (mode !== "unlock") clearResult();
  };

  tabs.forEach((tab) => tab.addEventListener("click", () => switchMode(tab.dataset.shieldMode)));
  tabs.forEach((tab, index) => tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    event.preventDefault();
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const next = tabs[(index + offset + tabs.length) % tabs.length];
    switchMode(next.dataset.shieldMode);
    next.focus();
  }));

  select(lockForm, "[data-lock-file]").addEventListener("change", (event) => {
    const file = event.currentTarget.files?.[0];
    fileSummary.textContent = file ? `${file.name} · ${describeBytes(file.size)}` : "No file selected";
    fileSummary.classList.toggle("error", Boolean(file && file.size > MAX_ATTACHMENT_BYTES));
  });
  select(unlockForm, "[data-vault-file]").addEventListener("change", (event) => {
    const file = event.currentTarget.files?.[0];
    vaultSummary.textContent = file ? `${file.name} · ${describeBytes(file.size)}` : "No vault selected";
    vaultSummary.classList.toggle("error", Boolean(file && file.size > MAX_IMPORT_BYTES));
  });

  lockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const passphrase = select(lockForm, "[name=lockPassphrase]").value;
    const confirmation = select(lockForm, "[name=lockPassphraseConfirm]").value;
    const file = select(lockForm, "[data-lock-file]").files?.[0] || null;
    if (passphrase !== confirmation) {
      setStatus(lockStatus, "The passphrase entries do not match.", "error");
      return;
    }
    if (file && file.size > MAX_ATTACHMENT_BYTES) {
      setStatus(lockStatus, "Choose a file no larger than 8 MB.", "error");
      return;
    }
    let attachmentBytes = null;
    try {
      setBusy(lockForm, true);
      setStatus(lockStatus, "Deriving two independent keys and building both authenticated layers locally…", "working");
      attachmentBytes = file ? new Uint8Array(await file.arrayBuffer()) : null;
      const attachment = file ? {
        name: file.name,
        type: file.type,
        bytes: attachmentBytes,
      } : null;
      const title = select(lockForm, "[name=lockTitle]").value;
      const vault = await encryptVault({
        title,
        note: select(lockForm, "[name=lockNote]").value,
        attachment,
      }, passphrase, lockPattern.value());
      downloadBlob(
        new Blob([JSON.stringify(vault, null, 2)], { type: "application/vnd.zmail.zmath+json" }),
        safeDownloadName(),
      );
      lockForm.reset();
      lockPattern.clear();
      fileSummary.textContent = "No file selected";
      setStatus(
        lockStatus,
        "Encrypted vault downloaded. Store the .zmath file safely—Zmail has no copy and cannot recover either input.",
        "success",
      );
    } catch (error) {
      setStatus(lockStatus, error?.message || "The vault could not be created in this browser.", "error");
    } finally {
      attachmentBytes?.fill(0);
      setBusy(lockForm, false);
    }
  });

  unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearResult();
    const file = select(unlockForm, "[data-vault-file]").files?.[0];
    if (!file) {
      setStatus(unlockStatus, "Choose the encrypted .zmath file you want to open.", "error");
      return;
    }
    if (file.size > MAX_IMPORT_BYTES) {
      setStatus(unlockStatus, "This vault is larger than the 20 MB import limit.", "error");
      return;
    }
    try {
      setBusy(unlockForm, true);
      setStatus(unlockStatus, "Opening the pattern layer, then the passphrase layer—entirely in this browser…", "working");
      const opened = await decryptVault(
        await file.text(),
        select(unlockForm, "[name=unlockPassphrase]").value,
        unlockPattern.value(),
      );
      select(result, "[data-result-title]").textContent = opened.title || "Untitled protected item";
      const date = Number.isNaN(Date.parse(opened.createdAt))
        ? "Protected date unavailable"
        : `Protected ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(opened.createdAt))}`;
      select(result, "[data-result-meta]").textContent = opened.attachment
        ? `${date} · ${opened.attachment.name} · ${describeBytes(opened.attachment.size)}`
        : `${date} · private note`;
      if (opened.note) {
        select(result, "[data-result-note]").textContent = opened.note;
        select(result, "[data-result-note-wrap]").hidden = false;
      }
      if (opened.attachment) {
        activeAttachment = opened.attachment;
        const attachmentButton = select(result, "[data-result-attachment]");
        attachmentButton.hidden = false;
        attachmentButton.textContent = `Download restored ${opened.attachment.name}`;
      }
      result.hidden = false;
      select(unlockForm, "[name=unlockPassphrase]").value = "";
      select(unlockForm, "[data-vault-file]").value = "";
      unlockPattern.clear();
      vaultSummary.textContent = "No vault selected";
      setStatus(
        unlockStatus,
        "Vault opened locally. Decrypted content remains on this page only until you clear it or leave.",
        "success",
      );
    } catch (error) {
      setStatus(
        unlockStatus,
        error?.message || "Could not open this vault. Check both inputs and the file.",
        "error",
      );
    } finally {
      setBusy(unlockForm, false);
    }
  });

  select(result, "[data-result-attachment]").addEventListener("click", () => {
    if (!activeAttachment) return;
    downloadBlob(
      new Blob([activeAttachment.bytes], { type: activeAttachment.type }),
      activeAttachment.name,
    );
  });
  select(result, "[data-result-clear]").addEventListener("click", () => {
    clearResult();
    setStatus(unlockStatus, "Decrypted result cleared from this page.", "success");
  });
  window.addEventListener("pagehide", clearResult);
  switchMode("lock");
}

if (typeof document !== "undefined") {
  const root = document.querySelector("[data-zmath-shield]");
  if (root) {
    try {
      initialiseShield(root);
      root.dataset.zmathReady = "true";
    } catch (error) {
      root.dataset.zmathReady = "false";
      const status = root.querySelector("[data-shield-status]");
      if (status) {
        setStatus(
          status,
          "ZMath Shield could not start in this browser. Refresh the page or use a current browser with Web Crypto enabled.",
          "error",
        );
      }
      console.error("ZMath Shield initialisation failed.", error);
    }
  }
}
