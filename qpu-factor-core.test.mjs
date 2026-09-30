import assert from "node:assert/strict";

import {
  QPU_FACTOR_PROFILE,
  SIMULATOR_FACTOR_PROFILE,
  buildQuantumFactorFile,
  digestHex,
  parseQuantumFactorFile
} from "./qpu-factor-core.js";

const localNonce = Uint8Array.from({length: 32}, (_, index) => index + 1);
const commitment = await digestHex("SHA-256", localNonce);
const baseResult = {
  schema: "callchat.ionq.factor-job.v1",
  provider: "IonQ",
  api: "v0.4",
  backend: "qpu.forte-1",
  source_class: "qpu-measurement",
  job_id: "019f52ea-8506-74f8-acb1-2699c0a8fcec",
  status: "completed",
  client_commitment: commitment,
  qubits: 8,
  requested_shots: 512,
  completed_at: "2026-07-11T20:00:00Z",
  result_outcomes: 128,
  result_sha256: "a".repeat(64),
  measurement_sha512: "b".repeat(128),
  receipt: "ionq-factor:v1:qpu.forte-1:019f52ea-8506-74f8-acb1-2699c0a8fcec:" + "a".repeat(64)
};

const factorFile = await buildQuantumFactorFile(localNonce, baseResult);
assert.equal(factorFile.profile, QPU_FACTOR_PROFILE);
const parsed = await parseQuantumFactorFile(JSON.stringify(factorFile));
assert.equal(parsed.factorBytes.length, 32);
assert.equal(parsed.evidence.job_id, baseResult.job_id);
assert.equal(parsed.hardware, true);

const deterministic = await buildQuantumFactorFile(localNonce, baseResult);
assert.equal(deterministic.factor, factorFile.factor);

const changedMeasurement = await buildQuantumFactorFile(localNonce, {
  ...baseResult,
  measurement_sha512: "c".repeat(128)
});
assert.notEqual(changedMeasurement.factor, factorFile.factor);

const tamperedFactor = structuredClone(factorFile);
tamperedFactor.factor = tamperedFactor.factor.slice(0, -4) + "AAAA";
await assert.rejects(parseQuantumFactorFile(tamperedFactor), /commitment|length/);

const tamperedEvidence = structuredClone(factorFile);
tamperedEvidence.evidence.result_outcomes += 1;
await assert.rejects(parseQuantumFactorFile(tamperedEvidence), /evidence digest/);

const simulatorFile = await buildQuantumFactorFile(localNonce, {
  ...baseResult,
  backend: "simulator",
  source_class: "simulator-test"
});
assert.equal(simulatorFile.profile, SIMULATOR_FACTOR_PROFILE);
await assert.rejects(parseQuantumFactorFile(simulatorFile), /contract tests/);
const simulatorParsed = await parseQuantumFactorFile(simulatorFile, {requireHardware: false});
assert.equal(simulatorParsed.hardware, false);

assert.equal(baseResult.client_commitment, commitment);
assert.notEqual(factorFile.factor, Buffer.from(localNonce).toString("base64"));

console.log("QPU factor derivation, evidence, tamper and simulator-boundary tests: ok");
