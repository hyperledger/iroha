import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as signRaw } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AccountAddress,
} from "../src/address.js";
import {
  LocalSigningContext,
  ToriiClient,
  buildIdentifierRequestForPolicy,
  encodeIdentifierResolutionReceiptAttestation,
  encodeIdentifierResolutionReceiptPayload,
  encryptIdentifierInputForPolicy,
  RamLfeEncryptionUnavailableError,
  getIdentifierBfvPublicParameters,
  hashIdentifierEncryptedInput,
  verifyIdentifierResolutionReceipt as verifyReceiptForNetwork,
} from "../src/toriiClient.js";
import { encryptDiagnosticIdentifierInputForPolicy } from "./helpers/diagnosticIdentifierBfv.js";
import { NetworkId } from "../src/networkId.js";
import { normalizeIdentifierInput } from "../src/normalizers.js";
import { blake2b256 } from "../src/blake2b.js";
import { ValidationError, ValidationErrorCode } from "../src/validationError.js";

const ACCOUNT_ID = AccountAddress.fromAccount({ publicKey: ed25519.getPublicKey(Buffer.alloc(32, 0x5a)) }).toI105();
const APPLICATION_SIGNING_CONTEXT = new LocalSigningContext(NetworkId.fromBytes(Buffer.alloc(32, 0xa5)), 753);
const APPLICATION_AUTH = Object.freeze({ accountId: ACCOUNT_ID, privateKey: Buffer.alloc(32, 0x5a) });
const RESOLVER_PUBLIC_KEY =
  "ed25519:ed0120D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737";
const POLICY_ID = "email#retail";
const PROGRAM_ID = "identifier_lookup_retail";
const OUTPUT_OPENING_PUBLIC_KEY = "ed25519:output-opening-key";
const OPAQUE_ID = `opaque:${"11".repeat(32)}`;
const RECEIPT_HASH = "22".repeat(32);
const UAID = `uaid:${"33".repeat(31)}35`;
const SIGNATURE = "AA".repeat(64);
const PROGRAM_DIGEST = "44".repeat(32);
const INPUT_CIPHERTEXT_HASH = "55".repeat(32);
const OUTPUT_CIPHERTEXT_HASH = "66".repeat(32);
const PARAMETER_DIGEST = "77".repeat(32);
const EVALUATION_KEY_DIGEST = "88".repeat(32);
const OUTPUT_HASH = "99".repeat(32);
const ASSOCIATED_DATA_HASH = "aa".repeat(32);
const PROOF_SCHEMA_HASH = "bb".repeat(32);

// Independently chosen test audiences. These SOFTWARE DATA controls establish
// serialization/transport/signature behavior, not Native policy admission.
const APPLICATION_NETWORK = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const SHARED_NETWORK = NetworkId.fromBytes(Buffer.from("5e60c5da42509f0077c6adf39b7dd708611eb4d6a9f1cbb71769092c26d20bf1", "hex"));
const INPUT_NONCE = "a1".repeat(32);
const NORMALIZED_INPUT = "alice@example.test";
function verifyReceiptInApplicationNetwork(receipt, policy) {
  return verifyReceiptForNetwork(receipt, policy, APPLICATION_NETWORK);
}
function verifyReceiptInSharedNetwork(receipt, policy) {
  return verifyReceiptForNetwork(receipt, policy, SHARED_NETWORK);
}
function dataHashLiteral(raw) {
  const bytes = Buffer.from(raw, "hex");
  bytes[31] |= 1;
  return NetworkId.fromBytes(bytes).literal;
}
function ownerOriginalOpening(program = PROGRAM_ID) {
  return {
    payload: {
      program_id: { name: program },
      input_ciphertext_hash: dataHashLiteral(INPUT_CIPHERTEXT_HASH),
      output_ciphertext_hash: dataHashLiteral(OUTPUT_HASH),
      parameter_digest: dataHashLiteral(PARAMETER_DIGEST),
      evaluation_key_digest: dataHashLiteral(EVALUATION_KEY_DIGEST),
      opened_output_hash: dataHashLiteral(OUTPUT_HASH),
      opened_at_ms: 42,
      expires_at_ms: 142,
    },
    signature: "AB".repeat(64),
  };
}
function ownerFlatOpening(original = ownerOriginalOpening()) {
  const payload = { ...original.payload, program_id: original.payload.program_id.name };
  for (const field of ["input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "opened_output_hash"]) {
    payload[field] = Buffer.from(NetworkId.parse(payload[field]).toBytes()).toString("hex");
  }
  return { payload, signature: original.signature.toLowerCase() };
}
function ownerRequestFields() {
  return { policyId: POLICY_ID, normalizedInput: NORMALIZED_INPUT, inputNonce: INPUT_NONCE, outputOpening: ownerOriginalOpening() };
}
function ownerSignedReceiptFixture() {
  const opening = ownerFlatOpening();
  return signedReceiptFixture({
    execution: { program_id: PROGRAM_ID, backend: "hkdf-sha3-512-prf-v1", input_ciphertext_hash: opening.payload.input_ciphertext_hash,
      output_ciphertext_hash: opening.payload.output_ciphertext_hash, output_hash: opening.payload.opened_output_hash,
      parameter_digest: opening.payload.parameter_digest, evaluation_key_digest: opening.payload.evaluation_key_digest },
    opening,
  });
}
function ownerPolicyFixture() {
  return identifierPolicyFixture({ backend: "hkdf-sha3-512-prf-v1", input_encryption: undefined,
    input_encryption_public_parameters: undefined, input_encryption_public_parameters_decoded: undefined,
    ram_fhe_profile: undefined, proof_verifier: undefined });
}

const BFV_SEED_HEX =
  "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
const BFV_PUBLIC_PARAMETERS = {
  parameters: {
    polynomial_degree: 8,
    plaintext_modulus: 257,
    ciphertext_modulus: 16_842_752,
    decomposition_base_log: 12,
  },
  public_key: {
    a: [3503246, 2379264, 12091019, 30169, 15804162, 8155629, 2418997, 3003107],
    b: [11472226, 15791131, 10301391, 6321610, 502045, 1948157, 5332249, 12641494],
  },
  max_input_bytes: 3,
};
const BFV_ENCRYPTED_INPUT_HEX =
  "4e52543000001042e5b988077612440e4cd45673596b00b004000000000000dd479e32bf99dbd000a804000000000000040000000000000020010000000000008800000000000000080000000000000008000000000000002dac6c00000000000800000000000000440e92000000000008000000000000005b2600000000000008000000000000004a681100000000000800000000000000bc3d2300000000000800000000000000413e85000000000008000000000000005619f900000000000800000000000000bd73fc0000000000880000000000000008000000000000000800000000000000ee894300000000000800000000000000dd22b000000000000800000000000000fe7c50000000000008000000000000001639a3000000000008000000000000006a969b00000000000800000000000000ddd4410000000000080000000000000051076600000000000800000000000000ef14ae00000000002001000000000000880000000000000008000000000000000800000000000000d86c690000000000080000000000000093070e0000000000080000000000000033067500000000000800000000000000ddc5190000000000080000000000000062ea230000000000080000000000000056f00a00000000000800000000000000ab51d400000000000800000000000000e945790000000000880000000000000008000000000000000800000000000000f2204400000000000800000000000000c9ecd2000000000008000000000000001dfc5b00000000000800000000000000d16d660000000000080000000000000016ec0e000000000008000000000000003def83000000000008000000000000006e7ff900000000000800000000000000c1fabb00000000002001000000000000880000000000000008000000000000000800000000000000c8c6eb00000000000800000000000000c9c14800000000000800000000000000f01f8700000000000800000000000000aed22c000000000008000000000000006122990000000000080000000000000036ad8c00000000000800000000000000d1429300000000000800000000000000891f6d0000000000880000000000000008000000000000000800000000000000417eed00000000000800000000000000d79c34000000000008000000000000009f322c0000000000080000000000000091fe5700000000000800000000000000533ce8000000000008000000000000005db8df00000000000800000000000000a8c313000000000008000000000000006e03c20000000000200100000000000088000000000000000800000000000000080000000000000003d654000000000008000000000000005d884400000000000800000000000000567ab50000000000080000000000000007273100000000000800000000000000ff6d0a00000000000800000000000000077466000000000008000000000000006d1d1a000000000008000000000000007050c200000000008800000000000000080000000000000008000000000000002f884f0000000000080000000000000041b0a100000000000800000000000000cbfa290000000000080000000000000057477300000000000800000000000000608f9200000000000800000000000000f5f5dd00000000000800000000000000445b3b00000000000800000000000000999e690000000000";
const BFV_VECTOR_FIXTURE = JSON.parse(
  readFileSync(
    new URL("../../../fixtures/soracloud/bfv_identifier_vectors_v1.json", import.meta.url),
    "utf8",
  ),
);
const IDENTIFIER_RECEIPT_VECTOR_FIXTURE = JSON.parse(
  readFileSync(
    new URL("../../../fixtures/soracloud/identifier_receipt_vectors_v1.json", import.meta.url),
    "utf8",
  ),
);
// These shared arithmetic/receipt fixtures have explicit policy metadata in this SDK suite.
const BFV_POLICY_FIXTURE = {
  ...BFV_VECTOR_FIXTURE.policy,
  program_id: PROGRAM_ID,
  output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
};
const IDENTIFIER_RECEIPT_POLICY_FIXTURE = {
  ...IDENTIFIER_RECEIPT_VECTOR_FIXTURE.policy,
  program_id: PROGRAM_ID,
  output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
};
const BFV_COMPONENT_DIGEST_RE = /^[0-9A-F]{64}$/u;
const BFV_CHAIN_DIGEST_RE = /^[0-9a-f]{64}$/u;
function jsonResponse(status, body) {
  return new Response(body == null ? null : JSON.stringify(body), {
    status,
    headers: body == null ? undefined : { "Content-Type": "application/json" },
  });
}

function irohaPrehash(bytes) {
  const digest = Buffer.from(blake2b256(bytes));
  digest[digest.length - 1] |= 1;
  return digest;
}

test("hashIdentifierEncryptedInput binds exact ciphertext bytes with Iroha hash semantics", () => {
  const ciphertext = "abcd00ff";
  assert.equal(
    hashIdentifierEncryptedInput(ciphertext),
    irohaPrehash(Buffer.from(ciphertext, "hex")).toString("hex"),
  );
  assert.throws(
    () => hashIdentifierEncryptedInput("ABCD"),
    /exact lowercase byte-aligned hex/,
  );
  assert.throws(
    () => hashIdentifierEncryptedInput("abc"),
    /exact lowercase byte-aligned hex/,
  );
  assert.throws(
    () => hashIdentifierEncryptedInput(" abcd"),
    /exact lowercase byte-aligned hex|surrounding whitespace/,
  );
});

function ed25519MultihashLiteral(publicKeyBytes) {
  return `ed25519:ed0120${Buffer.from(publicKeyBytes).toString("hex").toUpperCase()}`;
}

function sampleOutputOpening(overrides = {}) {
  return {
    payload: {
      program_id: POLICY_ID,
      input_ciphertext_hash: INPUT_CIPHERTEXT_HASH,
      output_ciphertext_hash: OUTPUT_CIPHERTEXT_HASH,
      parameter_digest: PARAMETER_DIGEST,
      evaluation_key_digest: EVALUATION_KEY_DIGEST,
      opened_output_hash: OUTPUT_HASH,
      opened_at_ms: 42,
      expires_at_ms: 142,
      ...(overrides.payload ?? {}),
    },
    signature: overrides.signature ?? "ab".repeat(64),
  };
}

function sha256HexFromHex(hex) {
  return createHash("sha256")
    .update(Buffer.from(hex, "hex"))
    .digest("hex")
    .toUpperCase();
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex").toUpperCase();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertBfvComponentDigest(label, value, seen) {
  assert.equal(typeof value, "string", `${label}: digest must be a string`);
  assert.match(value, BFV_COMPONENT_DIGEST_RE, `${label}: digest must be canonical uppercase SHA-256`);
  assert.notEqual(value, "0".repeat(64), `${label}: digest must not be zero`);
  assert.equal(seen.has(value), false, `${label}: component digest must be unique`);
  seen.add(value);
}

function assertBfvUpperSha256(label, value) {
  assert.equal(typeof value, "string", `${label}: digest must be a string`);
  assert.match(value, BFV_COMPONENT_DIGEST_RE, `${label}: digest must be canonical uppercase SHA-256`);
  assert.notEqual(value, "0".repeat(64), `${label}: digest must not be zero`);
}

function balancedBfvMultiplicationDepth(inputCount) {
  assert.equal(inputCount > 0, true, "BFV multiplication depth requires at least one input");
  let covered = 1;
  let depth = 0;
  while (covered < inputCount) {
    covered *= 2;
    depth += 1;
  }
  return depth;
}

function assertBfvLowerDigest(label, value) {
  assert.equal(typeof value, "string", `${label}: digest must be a string`);
  assert.match(value, BFV_CHAIN_DIGEST_RE, `${label}: digest must be canonical lowercase hex`);
  assert.notEqual(value, "0".repeat(64), `${label}: digest must not be zero`);
}

function assertBfvRnsPolynomialFixture(label, polynomial, publicDegree, limbCount) {
  assert.equal(polynomial.coefficient_count, publicDegree, `${label}: coefficient count`);
  assert.equal(polynomial.residue_limb_sha256.length, limbCount, `${label}: residue limb count`);
  assertBfvUpperSha256(`${label}: reconstructed coefficients`, polynomial.reconstructed_sha256);
  for (const [index, digest] of polynomial.residue_limb_sha256.entries()) {
    assertBfvUpperSha256(`${label}: residue limb ${index}`, digest);
  }
}

function assertBfvRnsModulusChainFixture(operationVectors, publicDegree) {
  const rns = operationVectors.rns_modulus_chain;
  assert.equal(Array.isArray(rns.moduli), true, "RNS moduli must be an array");
  assert.equal(rns.moduli.length > 0, true, "RNS moduli must not be empty");
  assert.deepEqual([...rns.moduli].sort((lhs, rhs) => lhs - rhs), rns.moduli, "RNS moduli must be sorted");
  for (const [index, modulus] of rns.moduli.entries()) {
    assert.equal(Number.isSafeInteger(modulus), true, `RNS modulus ${index} must be a safe integer`);
    assert.equal(modulus > 2 && modulus % 2 === 1, true, `RNS modulus ${index} must be an odd prime candidate`);
  }
  assert.match(rns.product, /^[0-9]+$/, "RNS product must be decimal");
  assertBfvLowerDigest("RNS chain digest", rns.expected_digest_hex);

  const samples = rns.sample_polynomials;
  assert.equal(samples.lhs_coefficients.length, publicDegree, "RNS lhs sample coefficient count");
  assert.equal(samples.rhs_coefficients.length, publicDegree, "RNS rhs sample coefficient count");
  for (const [label, coefficients] of [
    ["lhs", samples.lhs_coefficients],
    ["rhs", samples.rhs_coefficients],
  ]) {
    for (const [index, coefficient] of coefficients.entries()) {
      assert.equal(Number.isSafeInteger(coefficient), true, `RNS ${label}[${index}] must be a safe integer`);
      assert.equal(coefficient >= 0, true, `RNS ${label}[${index}] must be non-negative`);
    }
  }

  for (const label of ["lhs", "rhs", "sum", "negacyclic_product"]) {
    assertBfvRnsPolynomialFixture(label, samples[label], publicDegree, rns.moduli.length);
  }
}

function assertBfvOperationKeyComponentVectors(operationVectors) {
  assert.equal(operationVectors.vector_set, "soracloud-bfv-operation-v1");
  const publicDegree = operationVectors.public_parameters.polynomial_degree;
  assertBfvRnsModulusChainFixture(operationVectors, publicDegree);
  const evaluationKey = operationVectors.evaluation_key_bundle;
  assert.equal(evaluationKey.decomposition_base_log, operationVectors.public_parameters.decomposition_base_log);
  assert.equal(evaluationKey.decomposition_digit_count, evaluationKey.relinearization_entry_count);
  assert.equal(evaluationKey.relinearization_entries.length, evaluationKey.relinearization_entry_count);
  const componentDigests = new Set();
  for (const [index, entry] of evaluationKey.relinearization_entries.entries()) {
    assert.equal(entry.index, index, `relinearization entry ${index}: index`);
    assert.equal(entry.coefficient_count, publicDegree, `relinearization entry ${index}: coefficient count`);
    assertBfvComponentDigest(`relinearization entry ${index} b`, entry.b_sha256, componentDigests);
    assertBfvComponentDigest(`relinearization entry ${index} a`, entry.a_sha256, componentDigests);
  }
  assert.equal(operationVectors.galois_keys.length, evaluationKey.galois_key_count);
  for (const key of operationVectors.galois_keys) {
    assert.equal(key.entries.length, key.entry_count, `Galois key ${key.automorphism_power}: entry count`);
    for (const [index, entry] of key.entries.entries()) {
      assert.equal(entry.index, index, `Galois key ${key.automorphism_power} entry ${index}: index`);
      assert.equal(entry.coefficient_count, publicDegree, `Galois key ${key.automorphism_power} entry ${index}: coefficient count`);
      assertBfvComponentDigest(`Galois key ${key.automorphism_power} entry ${index} b`, entry.b_sha256, componentDigests);
      assertBfvComponentDigest(`Galois key ${key.automorphism_power} entry ${index} a`, entry.a_sha256, componentDigests);
    }
  }
  assert.equal(operationVectors.galois_switch_vectors.length > 0, true, "Galois switch vectors must not be empty");
  for (const vector of operationVectors.galois_switch_vectors) {
    assert.equal(
      operationVectors.galois_keys.some((key) => key.automorphism_power === vector.automorphism_power),
      true,
      `Galois switch vector ${vector.name}: matching key`,
    );
    assert.equal(vector.input_plaintext_slots.length > 0, true, `Galois switch vector ${vector.name}: plaintext slots`);
    for (const [index, slot] of vector.input_plaintext_slots.entries()) {
      assert.equal(Number.isSafeInteger(slot), true, `Galois switch vector ${vector.name}: slot ${index}`);
      assert.equal(slot >= 0, true, `Galois switch vector ${vector.name}: slot ${index} non-negative`);
    }
    assert.equal(vector.expected_input_ciphertext_bytes > 0, true, `Galois switch vector ${vector.name}: input bytes`);
    assert.equal(vector.expected_output_ciphertext_bytes > 0, true, `Galois switch vector ${vector.name}: output bytes`);
    assertBfvUpperSha256(`Galois switch vector ${vector.name}: input`, vector.expected_input_ciphertext_sha256);
    assertBfvUpperSha256(`Galois switch vector ${vector.name}: output`, vector.expected_output_ciphertext_sha256);
    assertBfvUpperSha256(`Galois switch vector ${vector.name}: plaintext`, vector.expected_plaintext_sha256);
    assert.equal(vector.output_components.coefficient_count, publicDegree, `Galois switch vector ${vector.name}: coefficient count`);
    assertBfvComponentDigest(`Galois switch vector ${vector.name} c0`, vector.output_components.c0_sha256, componentDigests);
    assertBfvComponentDigest(`Galois switch vector ${vector.name} c1`, vector.output_components.c1_sha256, componentDigests);
  }
  assert.equal(operationVectors.packed_galois_switch_vectors.length > 0, true, "packed Galois switch vectors must not be empty");
  for (const vector of operationVectors.packed_galois_switch_vectors) {
    assert.equal(
      operationVectors.galois_keys.some((key) => key.automorphism_power === vector.automorphism_power),
      true,
      `packed Galois switch vector ${vector.name}: matching key`,
    );
    assert.equal(vector.input_packed_slots.length, publicDegree, `packed Galois switch vector ${vector.name}: input slot count`);
    assert.equal(vector.expected_slot_permutation.length, publicDegree, `packed Galois switch vector ${vector.name}: permutation count`);
    assert.equal(vector.expected_packed_slots.length, publicDegree, `packed Galois switch vector ${vector.name}: output slot count`);
    for (const [label, values] of [
      ["input", vector.input_packed_slots],
      ["permutation", vector.expected_slot_permutation],
      ["output", vector.expected_packed_slots],
    ]) {
      for (const [index, value] of values.entries()) {
        assert.equal(Number.isSafeInteger(value), true, `packed Galois switch vector ${vector.name}: ${label} ${index}`);
        assert.equal(value >= 0, true, `packed Galois switch vector ${vector.name}: ${label} ${index} non-negative`);
      }
    }
    assertBfvUpperSha256(`packed Galois switch vector ${vector.name}: packed plaintext`, vector.expected_packed_plaintext_sha256);
    assertBfvUpperSha256(`packed Galois switch vector ${vector.name}: input`, vector.expected_input_ciphertext_sha256);
    assertBfvUpperSha256(`packed Galois switch vector ${vector.name}: output`, vector.expected_output_ciphertext_sha256);
    assertBfvUpperSha256(`packed Galois switch vector ${vector.name}: plaintext`, vector.expected_plaintext_coefficients_sha256);
    assert.equal(vector.output_components.coefficient_count, publicDegree, `packed Galois switch vector ${vector.name}: coefficient count`);
    assertBfvComponentDigest(`packed Galois switch vector ${vector.name} c0`, vector.output_components.c0_sha256, componentDigests);
    assertBfvComponentDigest(`packed Galois switch vector ${vector.name} c1`, vector.output_components.c1_sha256, componentDigests);
  }
  assert.equal(operationVectors.rotation_keys.length, evaluationKey.rotation_key_count);
  for (const key of operationVectors.rotation_keys) {
    const components = key.zero_refresh_components;
    assert.equal(components.coefficient_count, publicDegree, `rotation key ${key.rotation_steps}: coefficient count`);
    assertBfvComponentDigest(`rotation key ${key.rotation_steps} c0`, components.c0_sha256, componentDigests);
    assertBfvComponentDigest(`rotation key ${key.rotation_steps} c1`, components.c1_sha256, componentDigests);
  }
  const bootstrap = operationVectors.bootstrap_key;
  assert.equal(bootstrap.key_id, evaluationKey.bootstrap_key_id);
  assert.equal(bootstrap.max_refresh_rounds, evaluationKey.bootstrap_max_refresh_rounds);
  assert.equal(Number.isSafeInteger(bootstrap.max_refresh_rounds), true, "bootstrap max refresh rounds");
  assert.equal(bootstrap.max_refresh_rounds > 0, true, "bootstrap max refresh rounds positive");
  assert.equal(bootstrap.zero_refresh_components.coefficient_count, publicDegree);
  assertBfvComponentDigest("bootstrap key c0", bootstrap.zero_refresh_components.c0_sha256, componentDigests);
  assertBfvComponentDigest("bootstrap key c1", bootstrap.zero_refresh_components.c1_sha256, componentDigests);
  assert.equal(Array.isArray(bootstrap.round_refreshes), true, "bootstrap round refresh list");
  assert.equal(bootstrap.round_refreshes.length, bootstrap.max_refresh_rounds, "bootstrap round refresh count");
  for (const [index, refresh] of bootstrap.round_refreshes.entries()) {
    assert.equal(refresh.round_index, index, `bootstrap round ${index}: index`);
    assert.equal(refresh.expected_refresh_bytes > 0, true, `bootstrap round ${index}: bytes`);
    assertBfvUpperSha256(`bootstrap round ${index}: refresh`, refresh.expected_refresh_sha256);
    assert.equal(refresh.components.coefficient_count, publicDegree, `bootstrap round ${index}: coefficient count`);
    if (index === 0) {
      assert.equal(refresh.components.c0_sha256, bootstrap.zero_refresh_components.c0_sha256, "bootstrap round 0 c0 mirrors zero_refresh");
      assert.equal(refresh.components.c1_sha256, bootstrap.zero_refresh_components.c1_sha256, "bootstrap round 0 c1 mirrors zero_refresh");
      assertBfvUpperSha256("bootstrap round 0 c0", refresh.components.c0_sha256);
      assertBfvUpperSha256("bootstrap round 0 c1", refresh.components.c1_sha256);
    } else {
      assertBfvComponentDigest(`bootstrap round ${index} c0`, refresh.components.c0_sha256, componentDigests);
      assertBfvComponentDigest(`bootstrap round ${index} c1`, refresh.components.c1_sha256, componentDigests);
    }
  }
  assert.equal(
    bootstrap.round_refreshes[0].expected_refresh_sha256,
    bootstrap.expected_zero_refresh_sha256,
    "bootstrap first round mirrors zero_refresh",
  );
  assert.notEqual(
    bootstrap.round_refreshes[0].expected_refresh_sha256,
    bootstrap.round_refreshes[1]?.expected_refresh_sha256,
    "bootstrap round refresh material must be domain separated",
  );
  assert.equal(operationVectors.bootstrap_refresh_vectors.length > 0, true, "bootstrap refresh vectors must not be empty");
  for (const vector of operationVectors.bootstrap_refresh_vectors) {
    assert.equal(vector.key_id, bootstrap.key_id, `bootstrap refresh vector ${vector.name}: key id`);
    assert.equal(Number.isSafeInteger(vector.refresh_rounds), true, `bootstrap refresh vector ${vector.name}: refresh rounds`);
    assert.equal(vector.refresh_rounds > 0, true, `bootstrap refresh vector ${vector.name}: refresh rounds positive`);
    assert.equal(vector.input_plaintext_slots.length > 0, true, `bootstrap refresh vector ${vector.name}: plaintext slots`);
    for (const [index, slot] of vector.input_plaintext_slots.entries()) {
      assert.equal(Number.isSafeInteger(slot), true, `bootstrap refresh vector ${vector.name}: slot ${index}`);
      assert.equal(slot >= 0, true, `bootstrap refresh vector ${vector.name}: slot ${index} non-negative`);
    }
    assert.equal(vector.expected_input_ciphertext_bytes > 0, true, `bootstrap refresh vector ${vector.name}: input bytes`);
    assertBfvUpperSha256(`bootstrap refresh vector ${vector.name}: input`, vector.expected_input_ciphertext_sha256);
    if (vector.expected_error !== undefined) {
      assert.equal(vector.refresh_rounds > bootstrap.max_refresh_rounds, true, "rejected refresh count exceeds supported capacity");
      assert.equal(vector.expected_error, "invalid BFV parameters: BFV bootstrap refresh rounds 2 exceeds bootstrap key max_refresh_rounds 1");
      assert.equal(vector.expected_output_ciphertext_sha256, undefined);
      continue;
    }
    assert.equal(
      vector.refresh_rounds <= bootstrap.max_refresh_rounds,
      true,
      `bootstrap refresh vector ${vector.name}: refresh rounds within key bound`,
    );
    assert.equal(vector.expected_output_ciphertext_bytes > 0, true, `bootstrap refresh vector ${vector.name}: output bytes`);
    assertBfvUpperSha256(`bootstrap refresh vector ${vector.name}: output`, vector.expected_output_ciphertext_sha256);
    assertBfvUpperSha256(`bootstrap refresh vector ${vector.name}: plaintext`, vector.expected_plaintext_sha256);
    assert.equal(vector.output_components.coefficient_count, publicDegree, `bootstrap refresh vector ${vector.name}: coefficient count`);
    assertBfvComponentDigest(`bootstrap refresh vector ${vector.name} c0`, vector.output_components.c0_sha256, componentDigests);
    assertBfvComponentDigest(`bootstrap refresh vector ${vector.name} c1`, vector.output_components.c1_sha256, componentDigests);
  }
  for (const vector of operationVectors.vectors) {
    const expectedDepth =
      vector.operation === "Multiply" ? balancedBfvMultiplicationDepth(vector.inputs.length) : 0;
    assert.equal(
      vector.requested_multiplication_depth,
      expectedDepth,
      `${vector.name}: requested multiplication depth`,
    );
  }
  const packedRotate = operationVectors.vectors.find((vector) => vector.name === "soracloud-packed-rotate-left-output");
  assert.notEqual(packedRotate, undefined, "packed RotateLeft operation vector must be present");
  assert.equal(packedRotate.operation, "RotateLeft");
  assert.equal(packedRotate.rotation_steps, publicDegree / 2, "packed RotateLeft half rotation");
  assert.equal(packedRotate.automorphism_power, publicDegree + 1, "packed RotateLeft Galois power");
  assert.equal(
    operationVectors.galois_keys.some((key) => key.automorphism_power === packedRotate.automorphism_power),
    true,
    "packed RotateLeft vector must have matching Galois key",
  );
  assert.equal(packedRotate.inputs.length, 1, "packed RotateLeft input count");
  const packedRotateInput = packedRotate.inputs[0];
  assert.equal(packedRotateInput.packed_slots.length, publicDegree, "packed RotateLeft input slot count");
  assert.equal(packedRotate.expected_packed_slots.length, publicDegree, "packed RotateLeft output slot count");
  for (const [label, values] of [
    ["input", packedRotateInput.packed_slots],
    ["output", packedRotate.expected_packed_slots],
  ]) {
    for (const [index, value] of values.entries()) {
      assert.equal(Number.isSafeInteger(value), true, `packed RotateLeft ${label} ${index}`);
      assert.equal(value >= 0, true, `packed RotateLeft ${label} ${index} non-negative`);
    }
  }
  assert.equal(packedRotateInput.expected_ciphertext_bytes > 0, true, "packed RotateLeft input bytes");
  assert.equal(packedRotate.expected_output_ciphertext_bytes > 0, true, "packed RotateLeft output bytes");
  assertBfvUpperSha256("packed RotateLeft input plaintext", packedRotateInput.expected_packed_plaintext_sha256);
  assertBfvUpperSha256("packed RotateLeft input", packedRotateInput.expected_ciphertext_sha256);
  assertBfvUpperSha256("packed RotateLeft output", packedRotate.expected_output_ciphertext_sha256);
  assertBfvUpperSha256("packed RotateLeft plaintext", packedRotate.expected_plaintext_coefficients_sha256);
  assert.equal(packedRotate.output_components.coefficient_count, publicDegree, "packed RotateLeft coefficient count");
  assertBfvComponentDigest("packed RotateLeft c0", packedRotate.output_components.c0_sha256, componentDigests);
  assertBfvComponentDigest("packed RotateLeft c1", packedRotate.output_components.c1_sha256, componentDigests);

  const packedRotateSchedule = operationVectors.vectors.find(
    (vector) => vector.name === "soracloud-packed-rotate-left-schedule-output",
  );
  assert.notEqual(packedRotateSchedule, undefined, "packed RotateLeft schedule vector must be present");
  assert.equal(packedRotateSchedule.operation, "RotateLeft");
  assert.equal(packedRotateSchedule.rotation_steps, 1, "packed RotateLeft schedule rotation");
  assert.equal(Array.isArray(packedRotateSchedule.automorphism_powers), true, "packed RotateLeft schedule powers");
  assert.equal(packedRotateSchedule.automorphism_powers.length > 1, true, "packed RotateLeft schedule must use multiple powers");
  for (const [index, power] of packedRotateSchedule.automorphism_powers.entries()) {
    assert.equal(Number.isSafeInteger(power), true, `packed RotateLeft schedule power ${index}`);
    assert.equal(power > 0, true, `packed RotateLeft schedule power ${index} positive`);
    assert.equal(
      operationVectors.galois_keys.some((key) => key.automorphism_power === power),
      true,
      `packed RotateLeft schedule power ${power} must have matching Galois key`,
    );
  }
  assert.equal(packedRotateSchedule.inputs.length, 1, "packed RotateLeft schedule input count");
  const scheduleInput = packedRotateSchedule.inputs[0];
  assert.equal(scheduleInput.packed_slots.length, publicDegree, "packed RotateLeft schedule input slot count");
  assert.equal(packedRotateSchedule.expected_packed_slots.length, publicDegree, "packed RotateLeft schedule output slot count");
  const expectedScheduleSlots = scheduleInput.packed_slots.slice(1).concat(scheduleInput.packed_slots[0]);
  assert.deepEqual(
    packedRotateSchedule.expected_packed_slots,
    expectedScheduleSlots,
    "packed RotateLeft schedule output slots",
  );
  for (const [label, values] of [
    ["input", scheduleInput.packed_slots],
    ["output", packedRotateSchedule.expected_packed_slots],
  ]) {
    for (const [index, value] of values.entries()) {
      assert.equal(Number.isSafeInteger(value), true, `packed RotateLeft schedule ${label} ${index}`);
      assert.equal(value >= 0, true, `packed RotateLeft schedule ${label} ${index} non-negative`);
    }
  }
  assert.equal(scheduleInput.expected_ciphertext_bytes > 0, true, "packed RotateLeft schedule input bytes");
  assert.equal(packedRotateSchedule.expected_output_ciphertext_bytes > 0, true, "packed RotateLeft schedule output bytes");
  assertBfvUpperSha256("packed RotateLeft schedule input plaintext", scheduleInput.expected_packed_plaintext_sha256);
  assertBfvUpperSha256("packed RotateLeft schedule input", scheduleInput.expected_ciphertext_sha256);
  assertBfvUpperSha256("packed RotateLeft schedule output", packedRotateSchedule.expected_output_ciphertext_sha256);
  assertBfvUpperSha256("packed RotateLeft schedule plaintext", packedRotateSchedule.expected_plaintext_coefficients_sha256);
  assert.equal(
    packedRotateSchedule.output_components.coefficient_count,
    publicDegree,
    "packed RotateLeft schedule coefficient count",
  );
  assertBfvComponentDigest("packed RotateLeft schedule c0", packedRotateSchedule.output_components.c0_sha256, componentDigests);
  assertBfvComponentDigest("packed RotateLeft schedule c1", packedRotateSchedule.output_components.c1_sha256, componentDigests);
}

function sampleExecution(overrides = {}) {
  return {
    program_id: POLICY_ID,
    program_digest: PROGRAM_DIGEST,
    backend: "bfv-programmed-v1",
    verification_mode: "signed",
    input_ciphertext_hash: INPUT_CIPHERTEXT_HASH,
    output_ciphertext_hash: OUTPUT_CIPHERTEXT_HASH,
    parameter_digest: PARAMETER_DIGEST,
    evaluation_key_digest: EVALUATION_KEY_DIGEST,
    output_hash: OUTPUT_HASH,
    associated_data_hash: ASSOCIATED_DATA_HASH,
    executed_at_ms: 42,
    expires_at_ms: 142,
    ...overrides,
  };
}

function signedReceiptFixture(overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  const rawPublicKey = new Uint8Array(der.subarray(der.length - 32));
  const payload = {
    network_id: "a5".repeat(32),
    policy_id: POLICY_ID,
    execution: sampleExecution(overrides.execution),
    opening: overrides.opening ?? sampleOutputOpening(),
    opaque_id: OPAQUE_ID,
    receipt_hash: RECEIPT_HASH,
    uaid: UAID,
    account_id: ACCOUNT_ID,
    ...(overrides.payload ?? {}),
  };
  const signaturePayload = encodeIdentifierResolutionReceiptPayload(payload);
  const signature = signRaw(
    null,
    irohaPrehash(signaturePayload),
    privateKey,
  ).toString("hex").toUpperCase();
  return {
    resolver_public_key: ed25519MultihashLiteral(rawPublicKey),
    payload,
    attestation: { kind: "signed", signature },
  };
}

function claimRecordFixture(overrides = {}) {
  return {
    policy_id: POLICY_ID,
    opaque_id: OPAQUE_ID,
    receipt_hash: RECEIPT_HASH,
    uaid: UAID,
    account_id: ACCOUNT_ID,
    verified_at_ms: 7,
    expires_at_ms: 17,
    ...overrides,
  };
}

function identifierPolicyFixture(overrides = {}) {
  return {
    policy_id: POLICY_ID,
    program_id: PROGRAM_ID,
    owner: ACCOUNT_ID,
    active: true,
    normalization: "email_address",
    resolver_public_key: "ed25519:resolver-key",
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    backend: "bfv-affine-v1",
    input_encryption: "bfv-v1",
    input_encryption_public_parameters: "ABCD",
    input_encryption_public_parameters_decoded: {
      parameters: {
        polynomial_degree: 64,
        plaintext_modulus: 257,
        ciphertext_modulus: 1099511627776,
        decomposition_base_log: 12,
      },
      public_key: {
        b: [1, 2, 3],
        a: [4, 5, 6],
      },
      max_input_bytes: 32,
      norito_length_encoding: "u64-v1",
    },
    proof_verifier: {
      proof_backend: "halo2-ipa",
      circuit_id: "identifier-ram-lfe-v1",
      public_inputs_schema_hash: PROOF_SCHEMA_HASH,
      verifying_key_bytes_b64: "AQID",
    },
    ram_fhe_profile: {
      initializer_descriptor_hash: "ab".repeat(31) + "01",
      profile_version: 1,
      register_count: 4,
      memory_lane_count: 32,
      ciphertext_mul_per_step: 16,
      encrypted_input_mode: "encrypted_envelope_v1",
      min_ciphertext_modulus: 1099511627776,
    },
    note: "retail email policy",
    ...overrides,
  };
}

test("listIdentifierPolicies normalizes BFV and proof-verifier metadata", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "GET");
      assert.equal(new URL(input).pathname, "/v1/identifier-policies");
      return jsonResponse(200, {
        total: 1,
        items: [identifierPolicyFixture()],
      });
    },
  });

  const result = await client.listIdentifierPolicies();
  assert.equal(result.total, 1);
  assert.equal(result.items[0].policy_id, POLICY_ID);
  assert.equal(result.items[0].program_id, PROGRAM_ID);
  assert.equal(result.items[0].owner, ACCOUNT_ID);
  assert.equal(
    result.items[0].output_opening_public_key,
    OUTPUT_OPENING_PUBLIC_KEY,
  );
  assert.equal(result.items[0].input_encryption, "bfv-v1");
  assert.equal(result.items[0].input_encryption_public_parameters, "ABCD");
  assert.equal(result.items[0].proof_verifier.proof_backend, "halo2-ipa");
  assert.equal(result.items[0].proof_verifier.public_inputs_schema_hash, PROOF_SCHEMA_HASH);
  assert.equal(result.items[0].ram_fhe_profile.register_count, 4);
  assert.equal(
    result.items[0].ram_fhe_profile.initializer_descriptor_hash,
    "ab".repeat(31) + "01",
  );
  assert.equal(
    result.items[0].ram_fhe_profile.encrypted_input_mode,
    "encrypted_envelope_v1",
  );
  assert.equal(
    result.items[0].input_encryption_public_parameters_decoded.parameters.polynomial_degree,
    64,
  );
  assert.deepEqual(getIdentifierBfvPublicParameters(result.items[0]), {
    parameters: {
      polynomial_degree: 64,
      plaintext_modulus: 257,
      ciphertext_modulus: 1099511627776,
      decomposition_base_log: 12,
    },
    public_key: {
      b: [1, 2, 3],
      a: [4, 5, 6],
    },
    max_input_bytes: 32,
    norito_length_encoding: "u64-v1",
  });
});

test("identifier policy helpers require explicit program and independent opening key", () => {
  const policy = identifierPolicyFixture();
  const signed = signedReceiptFixture();
  const receipt = { payload: signed.payload, attestation: signed.attestation };
  const consumers = [
    (value) => getIdentifierBfvPublicParameters(value),
    (value) => buildIdentifierRequestForPolicy(value, {
      normalizedInput: NORMALIZED_INPUT, inputNonce: INPUT_NONCE, outputOpening: ownerOriginalOpening(), networkId: APPLICATION_NETWORK,
    }),
    (value) => verifyReceiptInApplicationNetwork(receipt, value),
  ];
  for (const field of ["program_id", "output_opening_public_key"]) {
    const missing = { ...policy };
    delete missing[field];
    for (const consume of consumers) {
      assert.throws(() => consume(missing), new RegExp(field, "u"));
      for (const invalid of [null, "", " ", " padded", "padded ", "embedded space", "control\u0001", 7]) {
        assert.throws(() => consume({ ...policy, [field]: invalid }), new RegExp(field, "u"));
      }
    }
  }
});

test("listIdentifierPolicies rejects non-exact policy metadata", async () => {
  const cases = [
    ["program_id", { program_id: ` ${PROGRAM_ID}` }],
    ["owner", { owner: ` ${ACCOUNT_ID}` }],
    ["normalization", { normalization: "Phone_E164" }],
    ["backend", { backend: "bfv-affine-v1 " }],
    ["backend", { backend: "bfv-affine-sha3-256-v1" }],
    ["backend", { backend: "bfv-programmed-sha3-256-v1" }],
    ["backend", { backend: "unknown" }],
    [
      "output_opening_public_key",
      { output_opening_public_key: ` ${OUTPUT_OPENING_PUBLIC_KEY}` },
    ],
    ["input_encryption", { input_encryption: "BFV-v1" }],
    ["input_encryption_public_parameters", { input_encryption_public_parameters: " ABCD" }],
    ["note", { note: "retail phone policy " }],
    [
      "ram_fhe_profile.encrypted_input_mode",
      {
        ram_fhe_profile: {
          ...identifierPolicyFixture().ram_fhe_profile,
          encrypted_input_mode: "EncryptedEnvelopeV1",
        },
      },
    ],
    [
      "input_encryption_public_parameters_decoded.norito_length_encoding",
      {
        input_encryption_public_parameters_decoded: {
          ...identifierPolicyFixture().input_encryption_public_parameters_decoded,
          norito_length_encoding: " u64-v1",
        },
      },
    ],
  ];

  for (const [field, overrides] of cases) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, {
        total: 1,
        items: [identifierPolicyFixture(overrides)],
      }),
    });
    await assert.rejects(
      () => client.listIdentifierPolicies(),
      new RegExp(`identifier policy list response\\.items\\[0\\]\\.${field.replaceAll(".", "\\.")}`),
      `identifier policy metadata ${field} exactness`,
    );
  }
});

test("listIdentifierPolicies requires the exact initializer descriptor hash", async () => {
  for (const hash of [undefined, null, "", "ab".repeat(31), "AB".repeat(32), ` ${"ab".repeat(32)}`, "ab".repeat(31) + "00"]) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, {
        total: 1,
        items: [identifierPolicyFixture({
          ram_fhe_profile: {
            ...identifierPolicyFixture().ram_fhe_profile,
            initializer_descriptor_hash: hash,
          },
        })],
      }),
    });
    await assert.rejects(
      () => client.listIdentifierPolicies(),
      /ram_fhe_profile\.initializer_descriptor_hash/u,
    );
  }
});

for (const method of ["listIdentifierPolicies", "listRamLfeProgramPolicies"]) {
  const wire = JSON.stringify({
    total: 1,
    items: [identifierPolicyFixture({ verification_mode: "signed" })],
  });
  const modulusField = '"min_ciphertext_modulus":1099511627776';
  const rawResponse = (body) => new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

  test(`${method} preserves raw u64 profile integers without rounding`, async () => {
    for (const value of [9007199254740991n, 9007199254740993n, 18446744073709551615n]) {
      const client = new ToriiClient("https://example.test", {
        fetchImpl: async () => rawResponse(wire.replace(
          modulusField,
          `"min_ciphertext_modulus":${value}`,
        )),
      });
      const result = await client[method]();
      assert.equal(
        result.items[0].ram_fhe_profile.min_ciphertext_modulus,
        value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value,
      );
    }
  });

  test(`${method} rejects duplicate fields and noncanonical profile integers`, async () => {
    const cases = [
      [wire.replace('"profile_version":1', '"profile_version":1,"profile_version":2'), /duplicate object key/u],
      ...["18446744073709551616", "0", "-1", "1.0", "1e0", '"257"', '" 257"'].map(
        (token) => [wire.replace(modulusField, `"min_ciphertext_modulus":${token}`), /min_ciphertext_modulus|canonical integers/u],
      ),
    ];
    for (const [body, error] of cases) {
      const client = new ToriiClient("https://example.test", {
        fetchImpl: async () => rawResponse(body),
      });
      await assert.rejects(() => client[method](), error);
    }
  });
}

test("listIdentifierPolicies bounds profile dimensions and rejects retired modes", async () => {
  const invalid = [
    ["profile_version", 0], ["profile_version", 256],
    ["register_count", 0], ["register_count", 65536],
    ["memory_lane_count", 0], ["memory_lane_count", 65536],
    ["ciphertext_mul_per_step", 0], ["ciphertext_mul_per_step", 256],
    ["min_ciphertext_modulus", 0], ["min_ciphertext_modulus", "18446744073709551616"],
    ["encrypted_input_mode", "resolver_canonicalized_envelope_v1"],
    ["encrypted_input_mode", { mode: "EncryptedEnvelopeV1" }],
    ["retired_initializer", "chacha20"],
  ];
  for (const [field, value] of invalid) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, {
        total: 1,
        items: [identifierPolicyFixture({
          ram_fhe_profile: { ...identifierPolicyFixture().ram_fhe_profile, [field]: value },
        })],
      }),
    });
    await assert.rejects(() => client.listIdentifierPolicies(), /ram_fhe_profile/u);
  }
});

test("listIdentifierPolicies rejects non-exact proof-verifier metadata", async () => {
  const cases = [
    ["proof_backend", { proof_backend: " halo2-ipa" }],
    ["circuit_id", { circuit_id: "identifier-ram-lfe-v1 " }],
    ["public_inputs_schema_hash", { public_inputs_schema_hash: ` ${PROOF_SCHEMA_HASH}` }],
    ["verifying_key_bytes_b64", { verifying_key_bytes_b64: "AQID " }],
  ];

  for (const [field, proofOverrides] of cases) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, {
        total: 1,
        items: [
          identifierPolicyFixture({
            proof_verifier: {
              ...identifierPolicyFixture().proof_verifier,
              ...proofOverrides,
            },
          }),
        ],
      }),
    });
    await assert.rejects(
      () => client.listIdentifierPolicies(),
      new RegExp(`identifier policy list response\\.items\\[0\\]\\.proof_verifier\\.${field}`),
      `identifier policy proof verifier ${field} exactness`,
    );
  }
});

test("resolveIdentifier binds current owner inputs and original opening", async () => {
  const receipt = ownerSignedReceiptFixture();
  const client = new ToriiClient("https://example.test", {
    localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (input, init) => {
      assert.equal(new URL(input).pathname, "/v1/identifiers/resolve");
      assert.deepEqual(JSON.parse(init.body), { phase: "claim", policy_id: POLICY_ID,
        normalized_input: NORMALIZED_INPUT, input_nonce: INPUT_NONCE, output_opening: ownerOriginalOpening() });
      return jsonResponse(200, { payload: receipt.payload, attestation: receipt.attestation });
    },
  });
  const result = await client.resolveIdentifier({ ...ownerRequestFields(), canonicalAuth: APPLICATION_AUTH });
  assert.deepEqual(result.payload.opening, ownerFlatOpening());
  assert.equal(result.payload.network_id, "a5".repeat(32));
  assert.equal(verifyReceiptForNetwork(result, { ...ownerPolicyFixture(), resolver_public_key: receipt.resolver_public_key }, APPLICATION_NETWORK), true);
});
test("current identifier responses reject audience, original metadata and opening substitution", async () => {
  const original = ownerSignedReceiptFixture();
  for (const mutate of [
    (r) => { r.payload.network_id = "a7".repeat(32); },
    (r) => { r.payload.execution.parameter_digest = "97".repeat(32); },
    (r) => { r.payload.execution.evaluation_key_digest = "97".repeat(32); },
    (r) => { r.payload.execution.expires_at_ms += 1; },
    (r) => { r.payload.opening.payload.opened_at_ms += 1; },
    (r) => { r.payload.opening.signature = "cd".repeat(64); },
  ]) {
    const changed = clone(original); mutate(changed);
    const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
      fetchImpl: async () => jsonResponse(200, { payload: changed.payload, attestation: changed.attestation }) });
    await assert.rejects(() => client.resolveIdentifier({ ...ownerRequestFields(), canonicalAuth: APPLICATION_AUTH }));
  }
});

test("resolveIdentifier rejects retired or unknown execution tags during response decoding", async () => {
  const receipt = signedReceiptFixture();
  for (const [field, value] of [
    ["backend", "bfv-affine-sha3-256-v1"],
    ["backend", "bfv-programmed-sha3-256-v1"],
    ["backend", "unknown"],
    ["verification_mode", "signed-v1"],
    ["verification_mode", "unknown"],
  ]) {
    const body = {
      payload: { ...receipt.payload, execution: { ...receipt.payload.execution, [field]: value } },
      attestation: receipt.attestation,
    };
    const client = new ToriiClient("https://example.test", {
      localSigningContext: APPLICATION_SIGNING_CONTEXT,
      fetchImpl: async () => jsonResponse(200, body),
    });
    await assert.rejects(
      () => client.resolveIdentifier({
        policyId: POLICY_ID,
        normalizedInput: NORMALIZED_INPUT, inputNonce: INPUT_NONCE,
        outputOpening: ownerOriginalOpening(),
        canonicalAuth: APPLICATION_AUTH,
      }),
      new RegExp(`execution\\.${field} must be one of:`),
    );
  }
});

test("resolveIdentifier requires exact current private inputs and original opening", async () => {
  let calls = 0;
  const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async () => { calls += 1; return jsonResponse(200, {}); } });
  for (const fields of [
    { policyId: POLICY_ID },
    { ...ownerRequestFields(), normalizedInput: undefined },
    { ...ownerRequestFields(), inputNonce: "00".repeat(32) },
    { ...ownerRequestFields(), inputNonce: "A1".repeat(32) },
    { ...ownerRequestFields(), outputOpening: sampleOutputOpening() },
    { ...ownerRequestFields(), encryptedInput: "ABCD" },
  ]) await assert.rejects(() => client.resolveIdentifier({ ...fields, canonicalAuth: APPLICATION_AUTH }));
  assert.equal(calls, 0);
});

test("phone owner claims require the independent typed original attestation", async () => {
  let calls = 0;
  const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async () => { calls += 1; return jsonResponse(200, {}); } });
  await assert.rejects(() => client.resolveIdentifier({ policyId: "phone#retail", normalizedInput: "+6771234567",
    inputNonce: INPUT_NONCE, outputOpening: ownerOriginalOpening("phone_retail"), canonicalAuth: APPLICATION_AUTH }), /phoneRetailCanonicality/u);
  assert.equal(calls, 0);
});

test("verifyIdentifierResolutionReceipt rejects adversarial receipt mutations", () => {
  const signedReceipt = signedReceiptFixture();
  const policy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: POLICY_ID,
    owner: ACCOUNT_ID,
    active: true,
    normalization: "email_address",
    resolver_public_key: signedReceipt.resolver_public_key,
    backend: "bfv-programmed-v1",
  };
  const receipt = {
    payload: signedReceipt.payload,
    attestation: signedReceipt.attestation,
  };

  assert.equal(verifyReceiptInApplicationNetwork(receipt, policy), true);

  const tampered = JSON.parse(JSON.stringify(receipt));
  tampered.payload.execution.output_ciphertext_hash = "67".repeat(32);
  assert.equal(verifyReceiptInApplicationNetwork(tampered, policy), false);

  assert.equal(
    verifyReceiptInApplicationNetwork(receipt, {
      ...policy,
      resolver_public_key: "ed25519:ed0120" + "45".repeat(32),
    }),
    false,
  );

  const malformedSignature = JSON.parse(JSON.stringify(receipt));
  malformedSignature.attestation.signature = "GG";
  assert.throws(
    () => verifyReceiptInApplicationNetwork(malformedSignature, policy),
    /attestation\.signature/,
  );

  for (const signature of [
    ` ${signedReceipt.attestation.signature}`,
    `${signedReceipt.attestation.signature} `,
  ]) {
    const paddedSignature = JSON.parse(JSON.stringify(receipt));
    paddedSignature.attestation.signature = signature;
    assert.throws(
      () => verifyReceiptInApplicationNetwork(paddedSignature, policy),
      /attestation\.signature must not contain surrounding whitespace/,
    );
  }

  for (const signature of [
    ` ${signedReceipt.payload.opening.signature}`,
    `${signedReceipt.payload.opening.signature} `,
  ]) {
    const paddedOpeningSignature = JSON.parse(JSON.stringify(receipt));
    paddedOpeningSignature.payload.opening.signature = signature;
    assert.throws(
      () => verifyReceiptInApplicationNetwork(paddedOpeningSignature, policy),
      /payload\.opening\.signature must not contain surrounding whitespace/,
    );
  }

  const signedWithProofFields = JSON.parse(JSON.stringify(receipt));
  signedWithProofFields.attestation.proof_backend = "pipa-r/pasta";
  signedWithProofFields.attestation.proof_b64 = "AQID";
  assert.throws(
    () => verifyReceiptInApplicationNetwork(signedWithProofFields, policy),
    /attestation contains unsupported fields: proof_backend, proof_b64/,
  );

  const proofAttestation = {
    payload: signedReceipt.payload,
    attestation: {
      kind: "proof",
      proof_backend: "pipa-r/pasta",
      proof_b64: "AQID",
    },
  };
  assert.throws(
    () => verifyReceiptInApplicationNetwork(proofAttestation, policy),
    /proof attestations require an external verifier/,
  );

  const otherPolicyId = "email#wholesale";
  assert.notEqual(otherPolicyId, signedReceipt.payload.policy_id);
  assert.throws(
    () =>
      verifyReceiptInApplicationNetwork(receipt, {
        ...policy,
        policy_id: otherPolicyId,
      }),
    /does not match policy/,
  );
});

test("encodeIdentifierResolutionReceiptPayload rejects non-exact execution tags", () => {
  const basePayload = signedReceiptFixture().payload;
  for (const [field, value, pattern] of [
    ["backend", " bfv-programmed-v1", /payload\.execution\.backend must not contain surrounding whitespace/],
    ["backend", "BFV-PROGRAMMED-SHA3-256-V1", /payload\.execution\.backend must be an exact lowercase/],
    ["verification_mode", "signed ", /payload\.execution\.verification_mode must not contain surrounding whitespace/],
    ["verification_mode", "Signed", /payload\.execution\.verification_mode must be an exact lowercase/],
  ]) {
    const payload = clone(basePayload);
    payload.execution[field] = value;
    assert.throws(
      () => encodeIdentifierResolutionReceiptPayload(payload),
      pattern,
      `${field}=${value}`,
    );
  }
});

test("encodeIdentifierResolutionReceiptAttestation rejects padded proof backend", () => {
  for (const kind of [" signed", "signed ", "Signed"]) {
    assert.throws(
      () =>
        encodeIdentifierResolutionReceiptAttestation({
          kind,
          signature: IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.attestation.signature,
        }),
      /identifier receipt attestation\.kind/,
      `attestation kind ${JSON.stringify(kind)}`,
    );
  }

  for (const proofBackend of [" halo2/ipa", "halo2/ipa "]) {
    assert.throws(
      () =>
        encodeIdentifierResolutionReceiptAttestation({
          kind: "proof",
          proof_backend: proofBackend,
          proof_b64: "AQID",
        }),
      /identifier receipt attestation\.proof_backend must not contain surrounding whitespace/,
    );
  }

  for (const proofB64 of [" AQID", "AQID "]) {
    assert.throws(
      () =>
        encodeIdentifierResolutionReceiptAttestation({
          kind: "proof",
          proof_backend: "pipa-r/pasta",
          proof_b64: proofB64,
        }),
      /identifier receipt attestation\.proof_b64 must be exact standard-base64/,
    );
  }

  assert.throws(
    () =>
      encodeIdentifierResolutionReceiptAttestation({
        kind: "proof",
        proof_backend: "pipa-r/pasta",
        proof_b64: "@@@",
      }),
    /attestation\.proof_b64 must be exact standard-base64/,
  );
});

test("verifyIdentifierResolutionReceipt matches shared receipt vectors", () => {
  assert.equal(
    IDENTIFIER_RECEIPT_VECTOR_FIXTURE.vector_set,
    "identifier-receipt-attestation-v1",
  );
  const payloadBytes = Buffer.from(
    encodeIdentifierResolutionReceiptPayload(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload),
  );
  assert.equal(
    sha256Hex(payloadBytes),
    IDENTIFIER_RECEIPT_VECTOR_FIXTURE.canonical_payload_sha256,
  );
  assert.equal(
    verifyReceiptInSharedNetwork(
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt,
      IDENTIFIER_RECEIPT_POLICY_FIXTURE,
    ),
    true,
  );

  for (const vector of IDENTIFIER_RECEIPT_VECTOR_FIXTURE.attestation_vectors) {
    const encoded = Buffer.from(
      encodeIdentifierResolutionReceiptAttestation(vector.attestation),
    );
    assert.equal(
      encoded.length,
      vector.expected_attestation_bytes,
      `${vector.name}: attestation byte length`,
    );
    assert.equal(
      sha256Hex(encoded),
      vector.expected_attestation_sha256,
      `${vector.name}: attestation digest`,
    );
    if (vector.attestation.kind === "proof") {
      assert.throws(
        () =>
          verifyReceiptInSharedNetwork(
            {
              payload: IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload,
              attestation: vector.attestation,
            },
            IDENTIFIER_RECEIPT_POLICY_FIXTURE,
          ),
        /proof attestations require an external verifier/,
        `${vector.name}: proof verifier gate`,
      );
    }
  }

  for (const policyId of [" phone#retail", "phone#retail ", "phone #retail", "phone# retail"]) {
    const paddedPolicyId = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
    paddedPolicyId.payload.policy_id = policyId;
    assert.throws(
      () =>
        verifyReceiptInSharedNetwork(
          paddedPolicyId,
          IDENTIFIER_RECEIPT_POLICY_FIXTURE,
        ),
      /payload\.policy_id/,
      `policy_id exactness ${policyId}`,
    );
  }

  for (const programId of [" identifier_lookup_retail", "identifier_lookup_retail "]) {
    const paddedExecutionProgram = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
    paddedExecutionProgram.payload.execution.program_id = programId;
    assert.throws(
      () =>
        verifyReceiptInSharedNetwork(
          paddedExecutionProgram,
          IDENTIFIER_RECEIPT_POLICY_FIXTURE,
        ),
      /payload\.execution\.program_id/,
      `execution program_id exactness ${programId}`,
    );

    const paddedOpeningProgram = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
    paddedOpeningProgram.payload.opening.payload.program_id = programId;
    assert.throws(
      () =>
        verifyReceiptInSharedNetwork(
          paddedOpeningProgram,
          IDENTIFIER_RECEIPT_POLICY_FIXTURE,
        ),
      /payload\.opening\.payload\.program_id/,
      `opening program_id exactness ${programId}`,
    );
  }

  for (const accountId of [
    ` ${IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.account_id}`,
    `${IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.account_id} `,
  ]) {
    const paddedAccountId = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
    paddedAccountId.payload.account_id = accountId;
    assert.throws(
      () =>
        verifyReceiptInSharedNetwork(
          paddedAccountId,
          IDENTIFIER_RECEIPT_POLICY_FIXTURE,
        ),
      /payload\.account_id/,
      "account_id exactness",
    );
  }

  const hashExactnessCases = [
    ["payload.opaque_id", ["payload", "opaque_id"], IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.opaque_id],
    ["payload.receipt_hash", ["payload", "receipt_hash"], IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.receipt_hash],
    ["payload.uaid", ["payload", "uaid"], IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.uaid],
    [
      "payload.execution.program_digest",
      ["payload", "execution", "program_digest"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.execution.program_digest,
    ],
    [
      "payload.opening.payload.input_ciphertext_hash",
      ["payload", "opening", "payload", "input_ciphertext_hash"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.opening.payload.input_ciphertext_hash,
    ],
  ];
  for (const [context, path, value] of hashExactnessCases) {
    for (const paddedValue of [` ${value}`, `${value} `]) {
      const paddedHash = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
      let target = paddedHash;
      for (const component of path.slice(0, -1)) {
        target = target[component];
      }
      target[path.at(-1)] = paddedValue;
      assert.throws(
        () =>
          verifyReceiptInSharedNetwork(
            paddedHash,
            IDENTIFIER_RECEIPT_POLICY_FIXTURE,
          ),
        new RegExp(context.replaceAll(".", "\\.")),
        `hash exactness ${context}`,
      );
    }
  }

  const timestampExactnessCases = [
    [
      "payload.execution.executed_at_ms",
      ["payload", "execution", "executed_at_ms"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.execution.executed_at_ms,
    ],
    [
      "payload.execution.expires_at_ms",
      ["payload", "execution", "expires_at_ms"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.execution.expires_at_ms,
    ],
    [
      "payload.opening.payload.opened_at_ms",
      ["payload", "opening", "payload", "opened_at_ms"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.opening.payload.opened_at_ms,
    ],
    [
      "payload.opening.payload.expires_at_ms",
      ["payload", "opening", "payload", "expires_at_ms"],
      IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.opening.payload.expires_at_ms,
    ],
  ];
  for (const [context, path, value] of timestampExactnessCases) {
    for (const paddedValue of [` ${value}`, `${value} `]) {
      const paddedTimestamp = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
      let target = paddedTimestamp;
      for (const component of path.slice(0, -1)) {
        target = target[component];
      }
      target[path.at(-1)] = paddedValue;
      assert.throws(
        () =>
          verifyReceiptInSharedNetwork(
            paddedTimestamp,
            IDENTIFIER_RECEIPT_POLICY_FIXTURE,
          ),
        new RegExp(context.replaceAll(".", "\\.")),
        `timestamp exactness ${context}`,
      );
    }
  }

  for (const negative of IDENTIFIER_RECEIPT_VECTOR_FIXTURE.negative_cases) {
    const receipt = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt));
    const policy = JSON.parse(JSON.stringify(IDENTIFIER_RECEIPT_POLICY_FIXTURE));
    switch (negative.mutation) {
      case "receipt.payload.network_id":
        receipt.payload.network_id = negative.value;
        break;
      case "receipt.payload.execution.output_ciphertext_hash":
        receipt.payload.execution.output_ciphertext_hash = negative.value;
        break;
      case "policy.resolver_public_key":
        policy.resolver_public_key = negative.value;
        break;
      case "policy.policy_id":
        policy.policy_id = negative.value;
        break;
      case "receipt.attestation.signature":
        receipt.attestation.signature = negative.value;
        break;
      case "receipt.attestation":
        receipt.attestation = negative.value;
        break;
      default:
        throw new Error(`unhandled receipt vector mutation ${negative.mutation}`);
    }

    if (negative.mutation === "receipt.payload.network_id") {
      assert.throws(() => verifyReceiptForNetwork(receipt, policy, SHARED_NETWORK), /independently selected network/u);
      const independentlySelectedTamperedAudience = NetworkId.fromBytes(Buffer.from(negative.value, "hex"));
      assert.equal(verifyReceiptForNetwork(receipt, policy, independentlySelectedTamperedAudience), false);
    } else if (negative.expected_error_contains) {
      assert.throws(
        () => verifyReceiptInSharedNetwork(receipt, policy),
        new RegExp(negative.expected_error_contains, "i"),
        negative.name,
      );
    } else {
      assert.equal(
        verifyReceiptInSharedNetwork(receipt, policy),
        negative.expected_result,
        negative.name,
      );
    }
  }
});

test("public identifier encryption refuses before inspecting inputs or randomness", () => {
  let reads = 0;
  const unreadable = new Proxy({}, {
    get() { reads += 1; throw new Error("must not read private input or policy"); },
    ownKeys() { reads += 1; throw new Error("must not enumerate private input or policy"); },
  });
  for (const [policy, input] of [[unreadable, unreadable], [null, null], [{}, "private identifier"]]) {
    assert.throws(
      () => encryptIdentifierInputForPolicy(policy, input),
      (error) => error instanceof RamLfeEncryptionUnavailableError
        && error.code === "ram_lfe_encryption_unavailable",
    );
  }
  assert.equal(reads, 0);
});

test("encryptDiagnosticIdentifierInputForPolicy builds deterministic BFV Norito envelopes", () => {
  const policy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: "string#retail",
    owner: ACCOUNT_ID,
    active: true,
    normalization: "exact",
    resolver_public_key: RESOLVER_PUBLIC_KEY,
    backend: "bfv-affine-v1",
    input_encryption: "bfv-v1",
    input_encryption_public_parameters_decoded: BFV_PUBLIC_PARAMETERS,
  };

  assert.equal(
    encryptDiagnosticIdentifierInputForPolicy(policy, "ab", { seedHex: BFV_SEED_HEX }),
    BFV_ENCRYPTED_INPUT_HEX,
  );
  assert.throws(() => buildIdentifierRequestForPolicy(policy, {
    encryptedInput: BFV_ENCRYPTED_INPUT_HEX, outputOpening: sampleOutputOpening(),
  }), /active native HKDF identifier policy/u);
});

test("encryptDiagnosticIdentifierInputForPolicy matches shared Soracloud BFV vectors", () => {
  assert.equal(BFV_VECTOR_FIXTURE.vector_set, "soracloud-bfv-identifier-envelope-v1");
  const observedDigests = new Set();

  for (const vector of BFV_VECTOR_FIXTURE.vectors) {
    const ciphertextHex = encryptDiagnosticIdentifierInputForPolicy(
      BFV_POLICY_FIXTURE,
      vector.input_utf8,
      { seedHex: vector.seed_hex },
    );
    assert.equal(
      Buffer.from(ciphertextHex, "hex").length,
      vector.expected_ciphertext_bytes,
      `${vector.name}: ciphertext byte length`,
    );
    assert.equal(
      sha256HexFromHex(ciphertextHex),
      vector.expected_ciphertext_sha256,
      `${vector.name}: ciphertext digest`,
    );
    observedDigests.add(vector.expected_ciphertext_sha256);
  }

  assert.equal(
    observedDigests.size,
    BFV_VECTOR_FIXTURE.vectors.length,
    "fixture vectors must not alias to the same encrypted payload digest",
  );
});

test("encryptDiagnosticIdentifierInputForPolicy matches shared Soracloud BFV operation input vectors", () => {
  const operationVectors = BFV_VECTOR_FIXTURE.operation_vectors;
  assert.equal(operationVectors.vector_set, "soracloud-bfv-operation-v1");
  assertBfvOperationKeyComponentVectors(operationVectors);
  const policy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: "soracloud-operation#fixture",
    owner: ACCOUNT_ID,
    active: true,
    normalization: "exact",
    resolver_public_key: RESOLVER_PUBLIC_KEY,
    backend: "bfv-programmed-v1",
    input_encryption: "bfv-v1",
    input_encryption_public_parameters_decoded:
      operationVectors.public_parameters_decoded,
  };
  const observedDigests = new Set();
  let inputCount = 0;

  for (const vector of operationVectors.vectors) {
    for (const input of vector.inputs) {
      inputCount += 1;
      if (input.packed_slots !== undefined) {
        assert.equal(input.packed_slots.length, operationVectors.public_parameters.polynomial_degree);
        assertBfvUpperSha256(`${vector.name}/${input.seed_utf8}: packed plaintext`, input.expected_packed_plaintext_sha256);
        assert.equal(input.expected_ciphertext_bytes > 0, true);
        assertBfvUpperSha256(`${vector.name}/${input.seed_utf8}: ciphertext`, input.expected_ciphertext_sha256);
        observedDigests.add(input.expected_ciphertext_sha256);
        continue;
      }
      const ciphertextHex = encryptDiagnosticIdentifierInputForPolicy(
        policy,
        Buffer.from(input.input_hex, "hex"),
        { seed: Buffer.from(input.seed_utf8, "utf8") },
      );
      assert.equal(
        Buffer.from(ciphertextHex, "hex").length,
        input.expected_ciphertext_bytes,
        `${vector.name}/${input.seed_utf8}: ciphertext byte length`,
      );
      assert.equal(
        sha256HexFromHex(ciphertextHex),
        input.expected_ciphertext_sha256,
        `${vector.name}/${input.seed_utf8}: ciphertext digest`,
      );
      observedDigests.add(input.expected_ciphertext_sha256);
    }
  }

  assert.equal(inputCount, 10, "fixture should cover all Add/Multiply/Rotate/Bootstrap inputs");
  assert.equal(
    observedDigests.size,
    inputCount,
    "operation input fixture vectors must not alias to the same encrypted payload digest",
  );
});

test("shared Soracloud BFV key-bundle component vectors reject adversarial drift", () => {
  assert.doesNotThrow(() => assertBfvOperationKeyComponentVectors(BFV_VECTOR_FIXTURE.operation_vectors));
  for (const [name, mutate] of [
    [
      "missing relinearization component",
      (operationVectors) => {
        delete operationVectors.evaluation_key_bundle.relinearization_entries[0].b_sha256;
      },
    ],
    [
      "duplicate component digest",
      (operationVectors) => {
        operationVectors.evaluation_key_bundle.relinearization_entries[1].a_sha256 =
          operationVectors.evaluation_key_bundle.relinearization_entries[0].b_sha256;
      },
    ],
    [
      "noncanonical lowercase component digest",
      (operationVectors) => {
        operationVectors.evaluation_key_bundle.relinearization_entries[0].b_sha256 =
          operationVectors.evaluation_key_bundle.relinearization_entries[0].b_sha256.toLowerCase();
      },
    ],
    [
      "missing Galois component",
      (operationVectors) => {
        delete operationVectors.galois_keys[0].entries[0].a_sha256;
      },
    ],
    [
      "zero refresh component digest",
      (operationVectors) => {
        operationVectors.rotation_keys[0].zero_refresh_components.c1_sha256 = "0".repeat(64);
      },
    ],
    [
      "component coefficient-count drift",
      (operationVectors) => {
        operationVectors.bootstrap_key.zero_refresh_components.coefficient_count = 63;
      },
    ],
    [
      "bootstrap refresh bound drift",
      (operationVectors) => {
        operationVectors.bootstrap_key.max_refresh_rounds = 0;
      },
    ],
    [
      "bootstrap refresh component drift",
      (operationVectors) => {
        operationVectors.bootstrap_refresh_vectors[0].output_components.c0_sha256 = "0".repeat(64);
      },
    ],
    [
      "rejected bootstrap refresh input digest drift",
      (operationVectors) => {
        operationVectors.bootstrap_refresh_vectors.find((vector) => vector.expected_error !== undefined)
          .expected_input_ciphertext_sha256 = "0".repeat(64);
      },
    ],
    [
      "rejected bootstrap refresh input slot drift",
      (operationVectors) => {
        operationVectors.bootstrap_refresh_vectors.find((vector) => vector.expected_error !== undefined)
          .input_plaintext_slots = [-1];
      },
    ],
    [
      "rotation key count drift",
      (operationVectors) => {
        operationVectors.evaluation_key_bundle.rotation_key_count += 1;
      },
    ],
    [
      "uppercase RNS chain digest",
      (operationVectors) => {
        operationVectors.rns_modulus_chain.expected_digest_hex =
          operationVectors.rns_modulus_chain.expected_digest_hex.toUpperCase();
      },
    ],
    [
      "RNS sample coefficient-count drift",
      (operationVectors) => {
        operationVectors.rns_modulus_chain.sample_polynomials.lhs_coefficients.pop();
      },
    ],
    [
      "RNS residue limb-count drift",
      (operationVectors) => {
        operationVectors.rns_modulus_chain.sample_polynomials.negacyclic_product.residue_limb_sha256.pop();
      },
    ],
  ]) {
    const operationVectors = clone(BFV_VECTOR_FIXTURE.operation_vectors);
    mutate(operationVectors);
    assert.throws(
      () => assertBfvOperationKeyComponentVectors(operationVectors),
      assert.AssertionError,
      name,
    );
  }
});

test("encryptDiagnosticIdentifierInputForPolicy rejects adversarial BFV operation vector inputs", () => {
  const operationVectors = BFV_VECTOR_FIXTURE.operation_vectors;
  const basePolicy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: "soracloud-operation#fixture",
    owner: ACCOUNT_ID,
    active: true,
    normalization: "exact",
    resolver_public_key: RESOLVER_PUBLIC_KEY,
    backend: "bfv-programmed-v1",
    input_encryption: "bfv-v1",
    input_encryption_public_parameters_decoded:
      operationVectors.public_parameters_decoded,
  };
  const [input] = operationVectors.vectors[0].inputs;
  const inputBytes = Buffer.from(input.input_hex, "hex");
  const seed = Buffer.from(input.seed_utf8, "utf8");
  assert.equal(
    sha256HexFromHex(encryptDiagnosticIdentifierInputForPolicy(basePolicy, inputBytes, { seed })),
    input.expected_ciphertext_sha256,
    "the unchanged operation fixture must encrypt before any single-field mutation",
  );

  assert.throws(
    () =>
      encryptDiagnosticIdentifierInputForPolicy(
        { ...basePolicy, normalization: "lowercase_trimmed" },
        inputBytes,
        { seed },
      ),
    ValidationError,
    "raw byte operation inputs must not bypass non-exact normalization",
  );
  assert.throws(
    () => encryptDiagnosticIdentifierInputForPolicy(basePolicy, Buffer.alloc(0), { seed }),
    ValidationError,
    "empty raw byte operation inputs must be rejected",
  );

  const unsupportedEncoding = JSON.parse(
    JSON.stringify(operationVectors.public_parameters_decoded),
  );
  unsupportedEncoding.norito_length_encoding = "compact-v9";
  assert.throws(
    () =>
      encryptDiagnosticIdentifierInputForPolicy(
        {
          ...basePolicy,
          input_encryption_public_parameters_decoded: unsupportedEncoding,
        },
        inputBytes,
        { seed },
      ),
    ValidationError,
    "unknown BFV Norito length encodings must be rejected",
  );

  const unsafeModulus = JSON.parse(
    JSON.stringify(operationVectors.public_parameters_decoded),
  );
  unsafeModulus.parameters.ciphertext_modulus = Number(
    unsafeModulus.parameters.ciphertext_modulus,
  );
  assert.throws(
    () =>
      encryptDiagnosticIdentifierInputForPolicy(
        {
          ...basePolicy,
          input_encryption_public_parameters_decoded: unsafeModulus,
        },
        inputBytes,
        { seed },
      ),
    ValidationError,
    "unsafe numeric ciphertext moduli must be rejected instead of rounded",
  );

  const unsafePublicKey = JSON.parse(
    JSON.stringify(operationVectors.public_parameters_decoded),
  );
  unsafePublicKey.public_key.b[2] = Number(unsafePublicKey.public_key.b[2]);
  assert.throws(
    () =>
      encryptDiagnosticIdentifierInputForPolicy(
        {
          ...basePolicy,
          input_encryption_public_parameters_decoded: unsafePublicKey,
        },
        inputBytes,
        { seed },
      ),
    ValidationError,
    "unsafe numeric public-key coefficients must be rejected instead of rounded",
  );
});

test("encryptDiagnosticIdentifierInputForPolicy rejects adversarial BFV public parameters", () => {
  const basePolicy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: "string#retail",
    owner: ACCOUNT_ID,
    active: true,
    normalization: "exact",
    resolver_public_key: RESOLVER_PUBLIC_KEY,
    backend: "bfv-affine-v1",
    input_encryption: "bfv-v1",
  };
  const cloneParameters = () => JSON.parse(JSON.stringify(BFV_PUBLIC_PARAMETERS));
  assert.match(
    encryptDiagnosticIdentifierInputForPolicy(
      { ...basePolicy, input_encryption_public_parameters_decoded: cloneParameters() },
      "ab",
      { seedHex: BFV_SEED_HEX },
    ),
    /^[0-9a-f]+$/u,
    "the unchanged policy must encrypt before any single-parameter mutation",
  );
  const cases = [
    {
      name: "non-divisible ciphertext modulus",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.parameters.ciphertext_modulus += 1;
        return params;
      })(),
    },
    {
      name: "non-power-of-two polynomial degree",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.parameters.polynomial_degree = 63;
        return params;
      })(),
    },
    {
      name: "decomposition base outside supported range",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.parameters.decomposition_base_log = 17;
        return params;
      })(),
    },
    {
      name: "public key length mismatch",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.public_key.b = params.public_key.b.slice(1);
        return params;
      })(),
    },
    {
      name: "zero max input byte count",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.max_input_bytes = 0;
        return params;
      })(),
    },
    {
      name: "max input byte count exceeds registered RAM-LFE profile",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.max_input_bytes = 64;
        return params;
      })(),
    },
    {
      name: "public key coefficient outside modulus",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.public_key.a[0] = params.parameters.ciphertext_modulus;
        return params;
      })(),
    },
    {
      name: "max input byte count outside one plaintext slot",
      expected: ValidationError,
      params: (() => {
        const params = cloneParameters();
        params.max_input_bytes = params.parameters.plaintext_modulus;
        return params;
      })(),
    },
    {
      name: "missing decoded public parameters",
      expected: /missing decoded BFV public parameters/,
      params: null,
    },
  ];

  for (const { name, expected, params } of cases) {
    assert.throws(
      () =>
        encryptDiagnosticIdentifierInputForPolicy(
          { ...basePolicy, input_encryption_public_parameters_decoded: params },
          "ab",
          { seedHex: BFV_SEED_HEX },
        ),
      expected,
      name,
    );
  }
});

test("encryptDiagnosticIdentifierInputForPolicy rejects adversarial client encryption inputs", () => {
  const policy = {
    program_id: PROGRAM_ID,
    output_opening_public_key: OUTPUT_OPENING_PUBLIC_KEY,
    policy_id: "string#retail",
    owner: ACCOUNT_ID,
    active: true,
    normalization: "exact",
    resolver_public_key: RESOLVER_PUBLIC_KEY,
    backend: "bfv-affine-v1",
    input_encryption: "bfv-v1",
    input_encryption_public_parameters_decoded: BFV_PUBLIC_PARAMETERS,
  };

  assert.throws(
    () => encryptDiagnosticIdentifierInputForPolicy(policy, "abcd", { seedHex: BFV_SEED_HEX }),
    ValidationError,
    "input longer than max_input_bytes must be rejected before encryption",
  );
  assert.throws(
    () =>
      encryptDiagnosticIdentifierInputForPolicy(policy, "ab", {
        seed: Buffer.alloc(32, 1),
        seedHex: BFV_SEED_HEX,
      }),
    ValidationError,
    "ambiguous deterministic seed inputs must be rejected",
  );
});

test("resolveIdentifier sends exact owner claim fields and returns null on 404", async () => {
  let calls = 0;
  const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (_input, init) => { calls += 1;
      assert.deepEqual(JSON.parse(init.body), { phase: "claim", policy_id: POLICY_ID, normalized_input: NORMALIZED_INPUT,
        input_nonce: INPUT_NONCE, output_opening: ownerOriginalOpening() });
      return jsonResponse(404, {}); } });
  assert.equal(await client.resolveIdentifier({ ...ownerRequestFields(), canonicalAuth: APPLICATION_AUTH }), null);
  assert.equal(calls, 1);
});

test("issueIdentifierClaimReceipt preserves the beneficiary and original owner opening", async () => {
  const receipt = ownerSignedReceiptFixture();
  const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (input, init) => {
      assert.equal(new URL(input).pathname, `/v1/accounts/${encodeURIComponent(ACCOUNT_ID)}/identifiers/claim-receipt`);
      assert.deepEqual(JSON.parse(init.body), { phase: "claim", policy_id: POLICY_ID, normalized_input: NORMALIZED_INPUT,
        input_nonce: INPUT_NONCE, output_opening: ownerOriginalOpening() });
      return jsonResponse(200, { payload: receipt.payload, attestation: receipt.attestation }); } });
  const result = await client.issueIdentifierClaimReceipt(ACCOUNT_ID, { ...ownerRequestFields(), canonicalAuth: APPLICATION_AUTH });
  assert.equal(result.payload.account_id, ACCOUNT_ID);
  assert.deepEqual(result.payload.opening, ownerFlatOpening());
});
test("prepareIdentifierClaimReceipt returns an exact original and independent chosen network", async () => {
  const body = { network_id: "a5".repeat(32), policy_id: POLICY_ID, account_id: ACCOUNT_ID, uaid: UAID,
    output_opening: ownerOriginalOpening() };
  const client = new ToriiClient("https://example.test", { localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (_input, init) => {
      assert.deepEqual(JSON.parse(init.body), { phase: "prepare", policy_id: POLICY_ID, normalized_input: NORMALIZED_INPUT, input_nonce: INPUT_NONCE });
      return jsonResponse(200, body); } });
  assert.deepEqual(await client.prepareIdentifierClaimReceipt(ACCOUNT_ID, { policyId: POLICY_ID, normalizedInput: NORMALIZED_INPUT,
    inputNonce: INPUT_NONCE, canonicalAuth: APPLICATION_AUTH }), body);
  body.network_id = "a7".repeat(32);
  await assert.rejects(() => client.prepareIdentifierClaimReceipt(ACCOUNT_ID, { policyId: POLICY_ID, normalizedInput: NORMALIZED_INPUT,
    inputNonce: INPUT_NONCE, canonicalAuth: APPLICATION_AUTH }), /independently selected network/u);
});

test("issueIdentifierClaimReceipt rejects account aliases before dispatch", async () => {
  const alias = "operator@banka.universal";
  const outputOpening = sampleOutputOpening({ payload: { opened_at_ms: 7, expires_at_ms: null } });
  let dispatched = false;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      dispatched = true;
      return jsonResponse(500, {});
    },
  });
  await assert.rejects(
    () => client.issueIdentifierClaimReceipt(alias, {
      policyId: POLICY_ID,
      encryptedInput: "ABCD",
      outputOpening,
      canonicalAuth: APPLICATION_AUTH,
    }),
    {
      name: "ValidationError",
      code: ValidationErrorCode.INVALID_ACCOUNT_ID,
      path: "issueIdentifierClaimReceipt.accountId",
    },
  );
  assert.equal(dispatched, false);
});

test("buildIdentifierRequestForPolicy requires an active current HKDF policy and selected network", () => {
  const options = { normalizedInput: NORMALIZED_INPUT, inputNonce: INPUT_NONCE, outputOpening: ownerOriginalOpening(), networkId: APPLICATION_NETWORK };
  assert.deepEqual(buildIdentifierRequestForPolicy(ownerPolicyFixture(), options), ownerRequestFields());
  for (const change of [{ backend: "bfv-programmed-v1" }, { active: false }, { program_id: "other" }]) {
    assert.throws(() => buildIdentifierRequestForPolicy({ ...ownerPolicyFixture(), ...change }, options));
  }
  assert.throws(() => buildIdentifierRequestForPolicy(ownerPolicyFixture(), { ...options, networkId: undefined }));
  assert.throws(() => buildIdentifierRequestForPolicy(ownerPolicyFixture(), { ...options, normalizedInput: " ALICE@EXAMPLE.TEST " }));
});

test("buildIdentifierRequestForPolicy rejects retired aliases and incomplete owner originals", () => {
  const options = { normalizedInput: NORMALIZED_INPUT, inputNonce: INPUT_NONCE, outputOpening: ownerOriginalOpening(), networkId: APPLICATION_NETWORK };
  for (const changed of [
    { ...options, encryptedInput: "ABCD" }, { ...options, input: NORMALIZED_INPUT },
    { ...options, seedHex: BFV_SEED_HEX }, { ...options, outputOpening: sampleOutputOpening() },
    { ...options, outputOpening: undefined }, { ...options, inputNonce: undefined },
  ]) assert.throws(() => buildIdentifierRequestForPolicy(ownerPolicyFixture(), changed));
});

test("getIdentifierClaimByReceiptHash returns null on 404", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "GET");
      assert.equal(
        new URL(input).pathname,
        `/v1/identifiers/receipts/${RECEIPT_HASH}`,
      );
      return jsonResponse(404, {});
    },
  });
  const result = await client.getIdentifierClaimByReceiptHash(RECEIPT_HASH);
  assert.equal(result, null);
});

test("getIdentifierClaimByReceiptHash parses exact claim records", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "GET");
      assert.equal(
        new URL(input).pathname,
        `/v1/identifiers/receipts/${RECEIPT_HASH}`,
      );
      return jsonResponse(200, claimRecordFixture());
    },
  });

  const result = await client.getIdentifierClaimByReceiptHash(RECEIPT_HASH);
  assert.deepEqual(result, claimRecordFixture());
});

test("getIdentifierClaimByReceiptHash rejects non-exact claim record fields", async () => {
  const cases = [
    ["policy_id", claimRecordFixture({ policy_id: ` ${POLICY_ID}` })],
    ["opaque_id", claimRecordFixture({ opaque_id: `${OPAQUE_ID} ` })],
    ["receipt_hash", claimRecordFixture({ receipt_hash: ` ${RECEIPT_HASH}` })],
    ["uaid", claimRecordFixture({ uaid: `${UAID} ` })],
    ["account_id", claimRecordFixture({ account_id: ` ${ACCOUNT_ID}` })],
  ];

  for (const [field, body] of cases) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, body),
    });
    await assert.rejects(
      () => client.getIdentifierClaimByReceiptHash(RECEIPT_HASH),
      new RegExp(`identifier claim lookup response\\.${field}`),
      `claim record ${field} exactness`,
    );
  }
});

test("normalizeIdentifierInput normalizes supported identifier forms", () => {
  assert.equal(
    normalizeIdentifierInput(" Alice.Example@Example.COM ", "email_address", "email"),
    "alice.example@example.com",
  );
});

test("identifier receipt encodes a valid multisig account with canonical compact bytes", () => {
  const vectors = JSON.parse(
    readFileSync(new URL("../../../fixtures/account/address_vectors.json", import.meta.url), "utf8"),
  );
  const multisigVector = vectors.cases.positive.find(
    (vector) => vector.case_id === "addr-multisig-council-threshold3",
  );
  assert.ok(multisigVector);
  const address = AccountAddress.fromI105(multisigVector.encodings.i105.string);
  assert.deepEqual(
    Buffer.from(address.canonicalBytes()),
    Buffer.from(multisigVector.encodings.canonical_hex.replace(/^0x/u, ""), "hex"),
  );
  const payload = {
    ...IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload,
    account_id: address.toI105(753),
  };
  const encoded = Buffer.from(encodeIdentifierResolutionReceiptPayload(payload));
  // Independent compact Norito reference: AccountController tag 1; policy
  // version 1, threshold 3, and three Ed25519 members with weights 1, 1, 2.
  // The reference also reproduces the existing Rust single-key receipt digest.
  const expectedAccountField = Buffer.from(
    "820201000000fc010101020300f50103000000000000004e4a21000000000000000100016801f401" +
    "b60101017d010f0187016a015501c8010a018201b80138018a015401aa01d2016401d30167012601" +
    "9e012d01e801be0107019c0193015b015f01960201004e4a21000000000000000100017e01a001e3" +
    "01bd015201e2010701c901d301b001eb01a6015c0107010401e6016f01ca012d018e0116015a0117" +
    "0152011801b1017401fc0141016001e401130201004e4a210000000000000001000188014b018801" +
    "5701f401ea01a10161013c01610150014d01b3014d014b01ea01f301460151017a010e013101de01" +
    "3c01dd01d401d901b40120011d019d010b020200",
    "hex",
  );
  assert.equal(encoded.length, 1054);
  assert.deepEqual(encoded.subarray(794), expectedAccountField);
  assert.equal(sha256Hex(encoded.subarray(33)), "B43BC15554F610D14AF5AD373F23FA7C14CED568217182231783E14CBB717AB8");
  assert.equal(encoded[0], 32);
  assert.equal(encoded.subarray(1, 33).toString("hex"), IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload.network_id);
});

test("current identifier signed payload requires one exact network field first", () => {
  const payload = { ...IDENTIFIER_RECEIPT_VECTOR_FIXTURE.receipt.payload };
  const encoded = encodeIdentifierResolutionReceiptPayload(payload);
  assert.equal(encoded[0], 32);
  assert.equal(Buffer.from(encoded.subarray(1, 33)).toString("hex"), payload.network_id);
  for (const network of [undefined, null, "", "0".repeat(64), "A5".repeat(32), `0x${payload.network_id}`, ` ${payload.network_id}`, "a".repeat(63)]) {
    assert.throws(() => encodeIdentifierResolutionReceiptPayload({ ...payload, network_id: network }));
  }
  const other = { ...payload, network_id: "a5".repeat(32) };
  assert.notDeepEqual(encodeIdentifierResolutionReceiptPayload(other), encoded);
});
