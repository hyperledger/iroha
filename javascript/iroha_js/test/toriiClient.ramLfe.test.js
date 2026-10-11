import assert from "node:assert/strict";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import { readFileSync } from "node:fs";

import { AccountAddress, LocalSigningContext, NetworkId, ToriiClient } from "../src/index.js";

function jsonResponse(status, body) {
  return new Response(body == null ? null : JSON.stringify(body), {
    status,
    headers: body == null ? undefined : { "Content-Type": "application/json" },
  });
}

const ACCOUNT_ID = AccountAddress.fromAccount({ publicKey: ed25519.getPublicKey(Buffer.alloc(32, 0x5a)) }).toI105();
const APPLICATION_SIGNING_CONTEXT = new LocalSigningContext(NetworkId.fromBytes(Buffer.alloc(32, 0xa5)), 753);
const APPLICATION_AUTH = Object.freeze({ accountId: ACCOUNT_ID, privateKey: Buffer.alloc(32, 0x5a) });
const PROGRAM_ID = "identifier_lookup_retail";
const OPAQUE_HASH = "11".repeat(32);
const RECEIPT_HASH = "22".repeat(32);
const OUTPUT_HASH = "44".repeat(32);
const ASSOCIATED_DATA_HASH = "55".repeat(32);
const PROOF_SCHEMA_HASH = "66".repeat(32);
const INPUT_CIPHERTEXT_HASH = "77".repeat(32);
const OUTPUT_CIPHERTEXT_HASH = "88".repeat(32);
const PARAMETER_DIGEST = "99".repeat(32);
const EVALUATION_KEY_DIGEST = "aa".repeat(32);
const OWNER_EXECUTE_DATA = JSON.parse(readFileSync(new URL("../../../fixtures/soracloud/identifier_owner_execute_v1.json", import.meta.url), "utf8"));
assert.equal(OWNER_EXECUTE_DATA.schema, "iroha.identifier.owner-execute.v1");
assert.equal(OWNER_EXECUTE_DATA.classification, "PUBLIC_SOFTWARE_DATA_UNADMITTED");
const OWNER_EXECUTE = OWNER_EXECUTE_DATA.response;
const RECEIPT = {
  payload: {
    program_id: PROGRAM_ID,
    program_digest: "bb".repeat(32),
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
  },
  attestation: { kind: "signed", signature: "AA".repeat(64) },
};

function ramLfeOutputOpening(overrides = {}) {
  return {
    payload: {
      program_id: PROGRAM_ID,
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

function ramLfeExecuteResponse(overrides = {}) {
  return { ...structuredClone(OWNER_EXECUTE), ...overrides };
}

function ramLfeReceiptVerifyResponse(overrides = {}) {
  return {
    valid: true,
    program_id: PROGRAM_ID,
    backend: "bfv-programmed-v1",
    verification_mode: "signed",
    output_hash: OUTPUT_HASH,
    associated_data_hash: ASSOCIATED_DATA_HASH,
    output_hash_matches: true,
    ...overrides,
  };
}

function ramLfeProgramPolicy(overrides = {}) {
  return {
    program_id: PROGRAM_ID,
    owner: ACCOUNT_ID,
    active: true,
    resolver_public_key: "ed25519:resolver-key",
    output_opening_public_key: "ed25519:output-opening-key",
    backend: "bfv-programmed-v1",
    verification_mode: "signed",
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
    },
    proof_verifier: {
      proof_backend: "halo2-ipa",
      circuit_id: "ram-lfe-v1",
      public_inputs_schema_hash: PROOF_SCHEMA_HASH,
      verifying_key_bytes_b64: "AQID",
    },
    note: "retail programmed policy",
    ...overrides,
  };
}

function ramLfeProgramPolicyListResponse(itemOverrides = {}) {
  return {
    total: 1,
    items: [ramLfeProgramPolicy(itemOverrides)],
  };
}

test("listRamLfeProgramPolicies parses exact BFV metadata", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "GET");
      assert.equal(new URL(input).pathname, "/v1/ram-lfe/program-policies");
      return jsonResponse(200, ramLfeProgramPolicyListResponse());
    },
  });

  const result = await client.listRamLfeProgramPolicies();
  assert.equal(result.total, 1);
  assert.equal(result.items[0].program_id, PROGRAM_ID);
  assert.equal(result.items[0].owner, ACCOUNT_ID);
  assert.equal(result.items[0].verification_mode, "signed");
  assert.equal(
    result.items[0].output_opening_public_key,
    "ed25519:output-opening-key",
  );
  assert.equal(result.items[0].input_encryption, "bfv-v1");
  assert.equal(
    result.items[0].input_encryption_public_parameters_decoded.parameters.polynomial_degree,
    64,
  );
  assert.equal(result.items[0].proof_verifier.proof_backend, "halo2-ipa");
  assert.equal(result.items[0].proof_verifier.public_inputs_schema_hash, PROOF_SCHEMA_HASH);
});

test("listRamLfeProgramPolicies rejects non-exact policy metadata", async () => {
  const cases = [
    ["program_id", { program_id: ` ${PROGRAM_ID}` }],
    ["owner", { owner: `${ACCOUNT_ID} ` }],
    ["resolver_public_key", { resolver_public_key: " ed25519:resolver-key" }],
    [
      "output_opening_public_key",
      { output_opening_public_key: " ed25519:output-opening-key" },
    ],
    ["backend", { backend: "BFV-programmed-sha3-256-v1" }],
    ["verification_mode", { verification_mode: " signed" }],
    ["input_encryption", { input_encryption: "bfv-v1 " }],
    ["input_encryption_public_parameters", { input_encryption_public_parameters: " ABCD" }],
  ];

  for (const [field, overrides] of cases) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, ramLfeProgramPolicyListResponse(overrides)),
    });
    await assert.rejects(
      () => client.listRamLfeProgramPolicies(),
      new RegExp(`ram-lfe program policy list response\\.items\\[0\\]\\.${field}`),
      `RAM-LFE program policy ${field} exactness`,
    );
  }
});

test("RAM-LFE response parsers accept only current backend and verification mode tags", async () => {
  async function parseAll(overrides, rejectField = null) {
    const bodies = [
      ramLfeProgramPolicyListResponse(overrides),
      ramLfeExecuteResponse({
        ...overrides,
        receipt: { ...OWNER_EXECUTE.receipt, payload: { ...OWNER_EXECUTE.receipt.payload, ...overrides } },
      }),
      ramLfeReceiptVerifyResponse(overrides),
    ];
    for (const [index, body] of bodies.entries()) {
      const client = new ToriiClient("https://example.test", {
        localSigningContext: APPLICATION_SIGNING_CONTEXT,
        fetchImpl: async () => jsonResponse(200, body),
      });
      const parse = [
        () => client.listRamLfeProgramPolicies(),
        () => client.executeRamLfeProgram(PROGRAM_ID, { normalizedInput: OWNER_EXECUTE_DATA.normalized_input, inputNonce: OWNER_EXECUTE_DATA.input_nonce, canonicalAuth: APPLICATION_AUTH }),
        () => client.verifyRamLfeReceipt({ receipt: RECEIPT, canonicalAuth: APPLICATION_AUTH }),
      ][index];
      if (index === 1 && !rejectField && (overrides.backend !== "hkdf-sha3-512-prf-v1" || overrides.verification_mode !== "signed")) {
        await assert.rejects(parse, /requested signed native HKDF program/u);
      } else if (rejectField) {
        await assert.rejects(parse, new RegExp(`${rejectField} must be one of:`));
      } else {
        const result = await parse();
        const metadata = index === 0 ? result.items[0] : result;
        assert.equal(metadata.backend, overrides.backend);
        assert.equal(metadata.verification_mode, overrides.verification_mode);
      }
    }
  }
  for (const backend of ["hkdf-sha3-512-prf-v1", "bfv-affine-v1", "bfv-programmed-v1"]) {
    for (const verification_mode of ["signed", "proof"]) {
      await parseAll({ backend, verification_mode });
    }
  }
  for (const [field, value] of [
    ["backend", "bfv-affine-sha3-256-v1"],
    ["backend", "bfv-programmed-sha3-256-v1"],
    ["backend", "unknown"],
    ["verification_mode", "signed-v1"],
    ["verification_mode", "unknown"],
  ]) {
    await parseAll({ [field]: value }, field);
    const client = new ToriiClient("https://example.test", {
      localSigningContext: APPLICATION_SIGNING_CONTEXT,
      fetchImpl: async () => jsonResponse(200, ramLfeExecuteResponse({
        receipt: { ...OWNER_EXECUTE.receipt, payload: { ...OWNER_EXECUTE.receipt.payload, [field]: value } },
      })),
    });
    await assert.rejects(
      () => client.executeRamLfeProgram(PROGRAM_ID, { normalizedInput: OWNER_EXECUTE_DATA.normalized_input, inputNonce: OWNER_EXECUTE_DATA.input_nonce, canonicalAuth: APPLICATION_AUTH }),
      new RegExp(`receipt\\.payload\\.${field} must be one of:`),
    );
  }
});

test("listRamLfeProgramPolicies rejects non-exact proof-verifier metadata", async () => {
  const cases = [
    ["proof_backend", { proof_backend: " halo2-ipa" }],
    ["circuit_id", { circuit_id: "ram-lfe-v1 " }],
    ["public_inputs_schema_hash", { public_inputs_schema_hash: ` ${PROOF_SCHEMA_HASH}` }],
    ["verifying_key_bytes_b64", { verifying_key_bytes_b64: "AQID " }],
  ];

  for (const [field, proofOverrides] of cases) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () =>
        jsonResponse(200, ramLfeProgramPolicyListResponse({
          proof_verifier: {
            ...ramLfeProgramPolicy().proof_verifier,
            ...proofOverrides,
          },
        })),
    });
    await assert.rejects(
      () => client.listRamLfeProgramPolicies(),
      new RegExp(
        `ram-lfe program policy list response\\.items\\[0\\]\\.proof_verifier\\.${field}`,
      ),
      `RAM-LFE proof verifier ${field} exactness`,
    );
  }
});

test("executeRamLfeProgram returns the genuine native opaque32 and signed program DATA binding", async () => {
  const client = new ToriiClient("https://example.test", {
    localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "POST");
      assert.equal(
        new URL(input).pathname,
        `/v1/ram-lfe/programs/${encodeURIComponent(PROGRAM_ID)}/execute`,
      );
      const payload = JSON.parse(init.body);
      assert.deepEqual(payload, {
        normalized_input: OWNER_EXECUTE_DATA.normalized_input, input_nonce: OWNER_EXECUTE_DATA.input_nonce,
      });
      return jsonResponse(200, ramLfeExecuteResponse());
    },
  });

  const result = await client.executeRamLfeProgram(PROGRAM_ID, {
    normalizedInput: OWNER_EXECUTE_DATA.normalized_input, inputNonce: OWNER_EXECUTE_DATA.input_nonce,
    canonicalAuth: APPLICATION_AUTH,
  });
  assert.equal(result.program_id, PROGRAM_ID);
  assert.equal(result.opaque_output, OWNER_EXECUTE.opaque_output);
  assert.equal(result.program_id_canonical, OWNER_EXECUTE.program_id_canonical);
  assert.equal(result.output_hash, OWNER_EXECUTE.output_hash);
  assert.equal(result.verification_mode, "signed");
  assert.deepEqual(result.receipt, OWNER_EXECUTE.receipt);
  assert.equal(Object.hasOwn(result, "output_opening"), false);
});

test("executeRamLfeProgram rejects non-exact response fields", async () => {
  const cases = [
    ["program_id", ramLfeExecuteResponse({ program_id: ` ${PROGRAM_ID}` })],
    ["opaque_hash", ramLfeExecuteResponse({ opaque_hash: `${OPAQUE_HASH} ` })],
    ["receipt_hash", ramLfeExecuteResponse({ receipt_hash: ` ${RECEIPT_HASH}` })],
    ["opaque_output", ramLfeExecuteResponse({ opaque_output: ` ${OWNER_EXECUTE.opaque_output}` })],
    ["output_hash", ramLfeExecuteResponse({ output_hash: `${OUTPUT_HASH} ` })],
    [
      "associated_data_hash",
      ramLfeExecuteResponse({ associated_data_hash: ` ${ASSOCIATED_DATA_HASH}` }),
    ],
    ["backend", ramLfeExecuteResponse({ backend: "BFV-programmed-sha3-256-v1" })],
    ["verification_mode", ramLfeExecuteResponse({ verification_mode: " signed" })],
    ["output_opening", ramLfeExecuteResponse({ output_opening: null }), /unsupported fields: output_opening/],
    ["executed_at_ms", ramLfeExecuteResponse({ executed_at_ms: "42" })],
    [
      "receipt.payload.input_ciphertext_hash",
      ramLfeExecuteResponse({
        receipt: {
          ...OWNER_EXECUTE.receipt,
          payload: {
            ...OWNER_EXECUTE.receipt.payload,
            input_ciphertext_hash: `${INPUT_CIPHERTEXT_HASH} `,
          },
        },
      }),
    ],
    [
      "output_hash",
      ramLfeExecuteResponse({
        receipt: { ...OWNER_EXECUTE.receipt, payload: { ...OWNER_EXECUTE.receipt.payload, output_hash: "dd".repeat(32) } },
      }),
    ],
    [
      "receipt",
      ramLfeExecuteResponse({ receipt: { ...OWNER_EXECUTE.receipt, ignored: true } }),
    ],
    [
      "output_opening",
      ramLfeExecuteResponse({
        output_opening: ramLfeOutputOpening({
          payload: { output_ciphertext_hash: "dd".repeat(32) },
        }),
      }),
      /unsupported fields: output_opening/,
    ],
    [
      "ignored",
      ramLfeExecuteResponse({ ignored: true }),
      /ram-lfe execute response contains unsupported fields: ignored/,
    ],
  ];

  for (const [field, body, expectedPattern] of cases) {
    const client = new ToriiClient("https://example.test", {
      localSigningContext: APPLICATION_SIGNING_CONTEXT,
      fetchImpl: async () => jsonResponse(200, body),
    });
    await assert.rejects(
      () => client.executeRamLfeProgram(PROGRAM_ID, { normalizedInput: OWNER_EXECUTE_DATA.normalized_input, inputNonce: OWNER_EXECUTE_DATA.input_nonce, canonicalAuth: APPLICATION_AUTH }),
      expectedPattern ?? new RegExp(`ram-lfe execute response\\.${field}`),
      `RAM-LFE execute response ${field} exactness`,
    );
  }
});

test("executeRamLfeProgram returns null for missing programs", async () => {
  const client = new ToriiClient("https://example.test", {
    localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (_input, init) => {
      const payload = JSON.parse(init.body);
      assert.equal(payload.normalized_input, OWNER_EXECUTE_DATA.normalized_input);
      assert.equal(payload.input_nonce, OWNER_EXECUTE_DATA.input_nonce);
      return jsonResponse(404, {});
    },
  });

  const result = await client.executeRamLfeProgram(PROGRAM_ID, {
    normalizedInput: OWNER_EXECUTE_DATA.normalized_input, inputNonce: OWNER_EXECUTE_DATA.input_nonce,
    canonicalAuth: APPLICATION_AUTH,
  });
  assert.equal(result, null);
});

test("executeRamLfeProgram rejects unsupported inputHex option", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      throw new Error("request should not be sent");
    },
  });

  await assert.rejects(
    () => client.executeRamLfeProgram(PROGRAM_ID, { inputHex: "ABCD", canonicalAuth: APPLICATION_AUTH }),
    (error) => error.name === "ValidationError",
  );
});

test("verifyRamLfeReceipt posts raw receipt payloads", async () => {
  const client = new ToriiClient("https://example.test", {
    localSigningContext: APPLICATION_SIGNING_CONTEXT,
    fetchImpl: async (input, init) => {
      assert.equal(init.method, "POST");
      assert.equal(new URL(input).pathname, "/v1/ram-lfe/receipts/verify");
      const payload = JSON.parse(init.body);
      assert.deepEqual(payload, {
        receipt: RECEIPT,
        output_hex: "C0FFEE",
      });
      return jsonResponse(200, ramLfeReceiptVerifyResponse());
    },
  });

  const result = await client.verifyRamLfeReceipt({
    receipt: RECEIPT,
    outputHex: "C0FFEE",
    canonicalAuth: APPLICATION_AUTH,
  });
  assert.equal(result.valid, true);
  assert.equal(result.program_id, PROGRAM_ID);
  assert.equal(result.output_hash_matches, true);
});

test("verifyRamLfeReceipt rejects non-exact response fields", async () => {
  const cases = [
    ["program_id", ramLfeReceiptVerifyResponse({ program_id: `${PROGRAM_ID} ` })],
    ["backend", ramLfeReceiptVerifyResponse({ backend: " bfv-programmed-v1" })],
    ["verification_mode", ramLfeReceiptVerifyResponse({ verification_mode: "Signed" })],
    ["output_hash", ramLfeReceiptVerifyResponse({ output_hash: ` ${OUTPUT_HASH}` })],
    [
      "associated_data_hash",
      ramLfeReceiptVerifyResponse({ associated_data_hash: `${ASSOCIATED_DATA_HASH} ` }),
    ],
  ];

  for (const [field, body] of cases) {
    const client = new ToriiClient("https://example.test", {
      localSigningContext: APPLICATION_SIGNING_CONTEXT,
      fetchImpl: async () => jsonResponse(200, body),
    });
    await assert.rejects(
      () => client.verifyRamLfeReceipt({ receipt: RECEIPT, outputHex: "C0FFEE", canonicalAuth: APPLICATION_AUTH }),
      new RegExp(`ram-lfe receipt verify response\\.${field}`),
      `RAM-LFE receipt verify response ${field} exactness`,
    );
  }
});
