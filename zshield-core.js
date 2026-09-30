export const FORMAT = "ZME1";
export const VERSION = 1;
export const LEGACY_PROFILE = "ZSHIELD-PBKDF2-AESGCM-1";
export const PROFILE = "ZMATH-PBKDF2-HKDF-AESGCM-2";
export const QPU_FACTOR_PROFILE = "ZMATH-PBKDF2-HKDF-AESGCM-QPUFACTOR-3";
export const ITERATIONS = 600000;
export const MAX_ITERATIONS = 1200000;
export const MAX_PAYLOAD_BYTES = 50 * 1024 * 1024;
export const MAX_MESSAGE_BYTES = 12 * 1024;
export const MESSAGE_PREFIX = "ZSHIELD1:";
const HKDF_INFO = "CallChat-ZMath-ZME1-v2";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", {fatal: true});

function randomBytes(length) {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function bytesToBase64(bytes) {
  let value = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    value += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunk));
  }
  return btoa(value);
}

function base64ToBytes(value) {
  const encoded = String(value || "");
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error("The ZME1 container contains malformed Base64 data.");
  }
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

async function patternDigest(patternBytes) {
  const source = patternBytes && patternBytes.length ? patternBytes : new Uint8Array();
  if (!source.length) return new Uint8Array(32);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", source));
}

async function factorDigest(factorBytes) {
  const source = factorBytes && factorBytes.length ? factorBytes : new Uint8Array();
  if (!source.length) return new Uint8Array();
  return new Uint8Array(await crypto.subtle.digest("SHA-256", source));
}

async function deriveLegacyKey(passphrase, patternBytes, salt, iterations) {
  if (String(passphrase || "").length < 14) {
    throw new Error("Use a passphrase with at least 14 characters.");
  }
  const pattern = await patternDigest(patternBytes);
  const material = concatBytes([encoder.encode(passphrase), new Uint8Array([0]), pattern]);
  const imported = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name: "PBKDF2", hash: "SHA-256", salt, iterations},
    imported,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveZMathKey(passphrase, patternBytes, salt, mixSalt, iterations, quantumFactorBytes) {
  if (String(passphrase || "").length < 14) {
    throw new Error("Use a passphrase with at least 14 characters.");
  }
  const passwordInput = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const passwordFactor = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "PBKDF2", hash: "SHA-256", salt, iterations},
    passwordInput,
    256
  ));
  const imageFactor = await patternDigest(patternBytes);
  const factors = [
    encoder.encode(HKDF_INFO),
    new Uint8Array([0]),
    passwordFactor,
    imageFactor
  ];
  const quantumFactor = await factorDigest(quantumFactorBytes);
  if (quantumFactor.length) factors.push(new Uint8Array([0]), quantumFactor);
  const mixedInput = concatBytes(factors);
  const mixedKey = await crypto.subtle.importKey("raw", mixedInput, "HKDF", false, ["deriveKey"]);
  passwordFactor.fill(0);
  mixedInput.fill(0);
  return crypto.subtle.deriveKey(
    {name: "HKDF", hash: "SHA-256", salt: mixSalt, info: encoder.encode(HKDF_INFO)},
    mixedKey,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
}

function validateHeader(header) {
  if (
    !header ||
    header.format !== FORMAT ||
    header.version !== VERSION ||
    ![PROFILE, QPU_FACTOR_PROFILE, LEGACY_PROFILE].includes(header.profile)
  ) {
    throw new Error("Unsupported or invalid ZME1 container.");
  }
  if (!header.payload || !header.kdf || !header.cipher) {
    throw new Error("The ZME1 header is incomplete.");
  }
  const iterations = Number(header.kdf.iterations);
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < ITERATIONS ||
    iterations > MAX_ITERATIONS
  ) {
    throw new Error("The container KDF profile is outside the supported bounds.");
  }
  if (
    header.profile === LEGACY_PROFILE &&
    header.kdf.name !== "PBKDF2-SHA-256"
  ) {
    throw new Error("The container KDF profile is outside the supported bounds.");
  }
  if (
    [PROFILE, QPU_FACTOR_PROFILE].includes(header.profile) &&
    (
      header.kdf.name !== (
        header.profile === QPU_FACTOR_PROFILE
          ? "PBKDF2-SHA-256+HKDF-SHA-256+EXTERNAL-FACTOR"
          : "PBKDF2-SHA-256+HKDF-SHA-256"
      ) ||
      base64ToBytes(header.kdf.mixSalt).length !== 16
    )
  ) {
    throw new Error("The container KDF profile is outside the supported bounds.");
  }
  if (
    typeof header.kdf.patternRequired !== "boolean"
  ) {
    throw new Error("The container KDF profile is outside the supported bounds.");
  }
  if (header.profile === QPU_FACTOR_PROFILE) {
    if (
      header.kdf.quantumFactorRequired !== true ||
      !/^[a-f0-9]{64}$/.test(String(header.kdf.quantumFactorCommitment || ""))
    ) {
      throw new Error("The QPU factor profile is incomplete.");
    }
  } else if (header.kdf.quantumFactorRequired === true) {
    throw new Error("The container KDF profile is outside the supported bounds.");
  }
  if (header.cipher.name !== "AES-256-GCM" || Number(header.cipher.tagLength) !== 128) {
    throw new Error("The container cipher profile is unsupported.");
  }
  const payloadSize = Number(header.payload.size);
  if (!Number.isSafeInteger(payloadSize) || payloadSize < 0 || payloadSize > MAX_PAYLOAD_BYTES) {
    throw new Error("The container payload size is unsupported.");
  }
  if (base64ToBytes(header.kdf.salt).length !== 16 || base64ToBytes(header.cipher.iv).length !== 12) {
    throw new Error("The container salt or IV length is invalid.");
  }
  if (header.context !== undefined) {
    if (!header.context || typeof header.context !== "object" || Array.isArray(header.context)) {
      throw new Error("The authenticated ZMath context is invalid.");
    }
    for (const [key, limit] of [
      ["purpose", 64],
      ["zmathPolicy", 128],
      ["transport", 64],
      ["quantumReceipt", 256],
      ["qpuBackend", 64],
      ["qpuJob", 80],
      ["qpuEvidenceDigest", 128],
      ["profileKeyId", 32]
    ]) {
      if (header.context[key] !== undefined && (typeof header.context[key] !== "string" || header.context[key].length > limit)) {
        throw new Error("The authenticated ZMath context is invalid.");
      }
    }
    if (
      header.context.profileKeyId !== undefined &&
      !/^[a-f0-9]{16,32}$/i.test(header.context.profileKeyId)
    ) {
      throw new Error("The authenticated ZMath context is invalid.");
    }
  }
}

export async function protectPayload(options) {
  const bytes = options.bytes instanceof Uint8Array ? options.bytes : new Uint8Array(options.bytes);
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw new Error("Choose a payload no larger than 50 MB.");
  }
  const patternBytes = options.patternBytes || new Uint8Array();
  const quantumFactorBytes = options.quantumFactorBytes || new Uint8Array();
  const quantumFactor = await factorDigest(quantumFactorBytes);
  const salt = randomBytes(16);
  const mixSalt = randomBytes(16);
  const iv = randomBytes(12);
  const header = {
    format: FORMAT,
    version: VERSION,
    profile: quantumFactor.length ? QPU_FACTOR_PROFILE : PROFILE,
    payload: {
      name: String(options.name || "payload.bin"),
      type: String(options.type || "application/octet-stream"),
      size: bytes.length,
      kind: String(options.kind || "file")
    },
    createdAt: options.createdAt || new Date().toISOString(),
    kdf: {
      name: quantumFactor.length
        ? "PBKDF2-SHA-256+HKDF-SHA-256+EXTERNAL-FACTOR"
        : "PBKDF2-SHA-256+HKDF-SHA-256",
      iterations: ITERATIONS,
      salt: bytesToBase64(salt),
      mixSalt: bytesToBase64(mixSalt),
      patternRequired: patternBytes.length > 0,
      quantumFactorRequired: quantumFactor.length > 0
    },
    cipher: {
      name: "AES-256-GCM",
      iv: bytesToBase64(iv),
      tagLength: 128
    }
  };
  if (quantumFactor.length) {
    header.kdf.quantumFactorCommitment = bytesToHex(quantumFactor);
  }
  if (options.context) {
    header.context = {
      purpose: String(options.context.purpose || "protected-payload"),
      zmathPolicy: String(options.context.zmathPolicy || "ZMath-Shield-Policy-1"),
      transport: String(options.context.transport || "independent")
    };
    if (options.context.quantumReceipt) {
      header.context.quantumReceipt = String(options.context.quantumReceipt);
    }
    for (const key of ["qpuBackend", "qpuJob", "qpuEvidenceDigest"]) {
      if (options.context[key]) header.context[key] = String(options.context[key]);
    }
    if (options.context.profileKeyId) {
      header.context.profileKeyId = String(options.context.profileKeyId);
    }
  }
  validateHeader(header);
  const key = await deriveZMathKey(
    options.passphrase,
    patternBytes,
    salt,
    mixSalt,
    ITERATIONS,
    quantumFactorBytes
  );
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: "AES-GCM", iv, additionalData: encoder.encode(canonical(header)), tagLength: 128},
    key,
    bytes
  ));
  return {header, ciphertext: bytesToBase64(ciphertext)};
}

export async function openContainerPayload(options) {
  const container = options.container;
  if (!container || !container.ciphertext) throw new Error("Unsupported or invalid ZME1 container.");
  const header = container.header;
  validateHeader(header);
  const patternBytes = options.patternBytes || new Uint8Array();
  const quantumFactorBytes = options.quantumFactorBytes || new Uint8Array();
  if (header.kdf.patternRequired && !patternBytes.length) {
    throw new Error("This container requires the sender's pattern file.");
  }
  if (header.profile === QPU_FACTOR_PROFILE) {
    if (!quantumFactorBytes.length) {
      throw new Error("This container requires the sender's separate QPU factor file.");
    }
    const suppliedFactorCommitment = bytesToHex(await factorDigest(quantumFactorBytes));
    if (suppliedFactorCommitment !== header.kdf.quantumFactorCommitment) {
      throw new Error("The QPU factor does not match this container.");
    }
  }
  const ciphertext = base64ToBytes(container.ciphertext);
  if (ciphertext.length !== Number(header.payload.size) + 16) {
    throw new Error("Authenticated payload size does not match the header.");
  }
  const key = header.profile === LEGACY_PROFILE
    ? await deriveLegacyKey(
      options.passphrase,
      patternBytes,
      base64ToBytes(header.kdf.salt),
      Number(header.kdf.iterations)
    )
    : await deriveZMathKey(
      options.passphrase,
      patternBytes,
      base64ToBytes(header.kdf.salt),
      base64ToBytes(header.kdf.mixSalt),
      Number(header.kdf.iterations),
      header.profile === QPU_FACTOR_PROFILE ? quantumFactorBytes : new Uint8Array()
    );
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(header.cipher.iv),
        additionalData: encoder.encode(canonical(header)),
        tagLength: Number(header.cipher.tagLength)
      },
      key,
      ciphertext
    ));
  } catch (error) {
    throw new Error("Authentication failed. Check the passphrase, pattern file and container integrity.");
  }
  if (plaintext.length !== Number(header.payload.size)) {
    throw new Error("Authenticated payload size does not match the header.");
  }
  return {bytes: plaintext, header};
}

export function encodeMessageContainer(container) {
  const encoded = encoder.encode(JSON.stringify(container));
  if (encoded.length > 64 * 1024) throw new Error("The shielded message envelope is too large for chat.");
  return MESSAGE_PREFIX + bytesToBase64(encoded);
}

export function decodeMessageContainer(value) {
  const envelope = String(value || "").trim();
  if (!envelope.startsWith(MESSAGE_PREFIX)) {
    throw new Error("Paste a complete ZSHIELD1 message envelope.");
  }
  let container;
  try {
    container = JSON.parse(decoder.decode(base64ToBytes(envelope.slice(MESSAGE_PREFIX.length))));
  } catch (error) {
    throw new Error("The shielded message envelope is malformed.");
  }
  validateHeader(container && container.header);
  if (container.header.payload.kind !== "matrix-message") {
    throw new Error("This ZShield envelope does not contain a chat message.");
  }
  return container;
}

export async function protectMessage(options) {
  const bytes = encoder.encode(String(options.message || ""));
  if (!bytes.length) throw new Error("Enter a message first.");
  if (bytes.length > MAX_MESSAGE_BYTES) throw new Error("Keep shielded messages below 12 KB.");
  const container = await protectPayload({
    bytes,
    name: "zshield-message.txt",
    type: "text/plain;charset=utf-8",
    kind: "matrix-message",
    passphrase: options.passphrase,
    patternBytes: options.patternBytes,
    quantumFactorBytes: options.quantumFactorBytes,
    createdAt: options.createdAt,
    context: {
      purpose: "matrix-message",
      zmathPolicy: "ZMath-Shield-Policy-1",
      transport: "Matrix-E2EE",
      quantumReceipt: options.quantumReceipt,
      qpuBackend: options.qpuBackend,
      qpuJob: options.qpuJob,
      qpuEvidenceDigest: options.qpuEvidenceDigest,
      profileKeyId: options.profileKeyId
    }
  });
  return {container, envelope: encodeMessageContainer(container)};
}

export async function openMessage(options) {
  const container = decodeMessageContainer(options.envelope);
  const opened = await openContainerPayload({
    container,
    passphrase: options.passphrase,
    patternBytes: options.patternBytes,
    quantumFactorBytes: options.quantumFactorBytes
  });
  let message;
  try {
    message = decoder.decode(opened.bytes);
  } catch (error) {
    throw new Error("The authenticated message is not valid UTF-8 text.");
  }
  return {message, header: opened.header};
}

export async function containerFingerprint(container) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical(container))));
  return Array.from(digest.subarray(0, 12), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
