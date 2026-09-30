export const QPU_FACTOR_FORMAT = "ZQF1";
export const QPU_FACTOR_VERSION = 1;
export const QPU_FACTOR_PROFILE = "CALLCHAT-LOCAL-CSPRNG+IONQ-QPU-HKDF-SHA-512-1";
export const SIMULATOR_FACTOR_PROFILE = "CALLCHAT-LOCAL-CSPRNG+IONQ-SIMULATOR-HKDF-SHA-512-TEST-1";
const FACTOR_INFO_PREFIX = "CallChat-QPU-Factor-v1";

const encoder = new TextEncoder();

export function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export function bytesToBase64(bytes) {
  let value = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    value += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(value);
}

export function base64ToBytes(value) {
  const encoded = String(value || "");
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error("The QPU factor contains malformed Base64 data.");
  }
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function hexToBytes(value) {
  const text = String(value || "");
  if (!text.length || text.length % 2 !== 0 || !/^[a-f0-9]+$/.test(text)) {
    throw new Error("The IonQ measurement digest is invalid.");
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export async function digestHex(name, bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest(name, bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validatedEvidence(result) {
  if (
    !result ||
    result.schema !== "callchat.ionq.factor-job.v1" ||
    result.provider !== "IonQ" ||
    result.api !== "v0.4" ||
    result.status !== "completed" ||
    !["qpu-measurement", "simulator-test"].includes(result.source_class) ||
    !/^(?:qpu\.[a-z0-9.-]+|simulator)$/.test(String(result.backend || "")) ||
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(String(result.job_id || "")) ||
    !/^[a-f0-9]{64}$/.test(String(result.client_commitment || "")) ||
    !/^[a-f0-9]{64}$/.test(String(result.result_sha256 || "")) ||
    !/^[a-f0-9]{128}$/.test(String(result.measurement_sha512 || "")) ||
    !Number.isSafeInteger(Number(result.qubits)) ||
    !Number.isSafeInteger(Number(result.requested_shots))
  ) {
    throw new Error("The IonQ factor evidence is incomplete or invalid.");
  }
  const hardware = result.source_class === "qpu-measurement" && String(result.backend).startsWith("qpu.");
  if ((result.source_class === "simulator-test") !== (result.backend === "simulator")) {
    throw new Error("The IonQ factor source classification is inconsistent.");
  }
  return {
    hardware,
    evidence: {
      schema: result.schema,
      provider: result.provider,
      api: result.api,
      backend: result.backend,
      source_class: result.source_class,
      job_id: result.job_id,
      status: result.status,
      client_commitment: result.client_commitment,
      qubits: Number(result.qubits),
      requested_shots: Number(result.requested_shots),
      completed_at: String(result.completed_at || "").slice(0, 40),
      result_outcomes: Number(result.result_outcomes),
      result_sha256: result.result_sha256,
      measurement_sha512: result.measurement_sha512,
      receipt: String(result.receipt || "").slice(0, 256)
    }
  };
}

export async function buildQuantumFactorFile(localNonce, result) {
  if (!(localNonce instanceof Uint8Array) || localNonce.length !== 32) {
    throw new Error("The browser entropy input must be exactly 256 bits.");
  }
  const {hardware, evidence} = validatedEvidence(result);
  if (await digestHex("SHA-256", localNonce) !== evidence.client_commitment) {
    throw new Error("The browser entropy does not match the submitted commitment.");
  }
  const measurement = hexToBytes(evidence.measurement_sha512);
  const info = encoder.encode(
    `${FACTOR_INFO_PREFIX}|${evidence.backend}|${evidence.job_id}|${evidence.client_commitment}`
  );
  const material = await crypto.subtle.importKey("raw", localNonce, "HKDF", false, ["deriveBits"]);
  const factor = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "HKDF", hash: "SHA-512", salt: measurement, info},
    material,
    256
  ));
  try {
    return {
      format: QPU_FACTOR_FORMAT,
      version: QPU_FACTOR_VERSION,
      profile: hardware ? QPU_FACTOR_PROFILE : SIMULATOR_FACTOR_PROFILE,
      factor: bytesToBase64(factor),
      factorCommitment: await digestHex("SHA-256", factor),
      evidence,
      evidenceDigest: await digestHex("SHA-512", encoder.encode(canonical(evidence)))
    };
  } finally {
    factor.fill(0);
    measurement.fill(0);
  }
}

export async function parseQuantumFactorFile(value, options = {}) {
  let parsed = value;
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed);
    } catch (error) {
      throw new Error("The QPU factor file is not valid JSON.");
    }
  }
  const hardware = parsed && parsed.profile === QPU_FACTOR_PROFILE;
  const simulator = parsed && parsed.profile === SIMULATOR_FACTOR_PROFILE;
  if (
    !parsed ||
    parsed.format !== QPU_FACTOR_FORMAT ||
    parsed.version !== QPU_FACTOR_VERSION ||
    (!hardware && !simulator)
  ) {
    throw new Error("This is not a supported CallChat QPU factor file.");
  }
  if (options.requireHardware !== false && !hardware) {
    throw new Error("Simulator factors are contract tests and cannot enable the hardware QPU profile.");
  }
  const validated = validatedEvidence(parsed.evidence);
  if (validated.hardware !== hardware) {
    throw new Error("The QPU factor profile does not match its IonQ evidence.");
  }
  const factorBytes = base64ToBytes(parsed.factor);
  if (factorBytes.length !== 32) throw new Error("The QPU factor length is invalid.");
  if (await digestHex("SHA-256", factorBytes) !== parsed.factorCommitment) {
    factorBytes.fill(0);
    throw new Error("The QPU factor commitment does not match the file.");
  }
  const evidenceDigest = await digestHex("SHA-512", encoder.encode(canonical(validated.evidence)));
  if (evidenceDigest !== parsed.evidenceDigest) {
    factorBytes.fill(0);
    throw new Error("The QPU evidence digest does not match the file.");
  }
  return {factorBytes, evidence: validated.evidence, evidenceDigest, hardware};
}
