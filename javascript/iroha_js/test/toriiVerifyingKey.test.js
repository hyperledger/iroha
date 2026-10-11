import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  LocalSigningContext,
  ToriiClient,
} from "../src/toriiClient.js";
import {
  LocalSigningContext as DistLocalSigningContext,
  ToriiClient as DistToriiClient,
} from "../dist/toriiClient.js";
import { AccountAddress } from "../src/address.js";
import { NetworkId } from "../src/networkId.js";
import { normalizeAccountId } from "../src/normalizers.js";
import { NetworkId as DistNetworkId } from "../dist/networkId.js";
import { blake2b256 } from "../src/blake2b.js";
import { buildBrowserVerifyingKeyTransactionPayload } from "../src/transactionCodec.js";

const BASE_URL = "https://localhost:8080";
const VK_SIGNING_NETWORK_ID_LITERAL =
  "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
const VK_SIGNING_NETWORK_ID = NetworkId.parse(
  VK_SIGNING_NETWORK_ID_LITERAL,
);
const VK_LOCAL_SIGNING_CONTEXT = new LocalSigningContext(
  VK_SIGNING_NETWORK_ID, 753,
);
const SAMPLE_ACCOUNT_SIGNATORY =
  "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
const SORA_I105_DISCRIMINANT = 0x2f1;

function expectedProductionBackendRejectionPattern(backend) {
  if (typeof backend !== "string" || backend.trim() === "") {
    return /non-empty string/;
  }
  if (backend.trim() !== backend) {
    return /surrounding whitespace/;
  }
  return /unsupported production verifier backend/;
}

function sampleAccountId() {
  const publicKey = Buffer.from(SAMPLE_ACCOUNT_SIGNATORY.slice(6), "hex");
  const address = AccountAddress.fromAccount({ publicKey });
  return normalizeAccountId(
    address.toI105(SORA_I105_DISCRIMINANT),
    "toriiVerifyingKey.sampleAccountId",
  );
}

const SAMPLE_ACCOUNT_ID = sampleAccountId();

function fixtureAccountId(label) {
  let attempt = 0;
  while (attempt < 1024) {
    const publicKey = crypto
      .createHash("sha256")
      .update(`fixture:${label}@fixture-domain:${attempt}`)
      .digest();
    try {
      return AccountAddress.fromAccount({ publicKey }).toI105(
        SORA_I105_DISCRIMINANT,
      );
    } catch {
      attempt += 1;
    }
  }
  throw new Error(`unable to derive canonical fixture key for ${label}`);
}

const FIXTURE_ALICE_ID = fixtureAccountId("alice");
const FIXTURE_BOB_ID = fixtureAccountId("bob");

function sampleVerifyingKeyRegisterPayload() {
  return {
    authority: SAMPLE_ACCOUNT_ID,
    backend: "pipa-r/pasta",
    name: "vk_main",
    version: 1,
    circuit_id: "pipa-r/pasta::transfer_v1",
    public_inputs_schema_hash_hex: "11".repeat(32),
    gas_schedule_id: "default",
    vk_bytes: Buffer.from("abc"),
  };
}

function normalizedVerifyingKeyRequest(request = sampleVerifyingKeyRegisterPayload()) {
  const vkBytes =
    request.vk_bytes === undefined
      ? null
      : Buffer.isBuffer(request.vk_bytes)
        ? Buffer.from(request.vk_bytes)
        : Buffer.from(request.vk_bytes, "base64");
  return {
    ...request,
    public_inputs_schema_hash_hex: request.public_inputs_schema_hash_hex
      .replace(/^0x/iu, "")
      .toLowerCase(),
    ...(vkBytes === null
      ? {}
      : {
          vk_bytes: vkBytes.toString("base64"),
          vk_len: vkBytes.length,
        }),
    ...(request.status === undefined
      ? {}
      : {
          status:
            request.status[0].toUpperCase() +
            request.status.slice(1).toLowerCase(),
        }),
  };
}

function verifyingKeyInstructionForRequest(
  request,
  operation,
  recordOverrides = {},
) {
  const vkBytes =
    request.vk_bytes === undefined
      ? null
      : Buffer.from(request.vk_bytes, "base64");
  const commitmentHex =
    vkBytes === null
      ? request.commitment_hex
      : verifyingKeyCommitmentHex(request.backend, vkBytes);
  const variant =
    operation === "register"
      ? "RegisterVerifyingKey"
      : "UpdateVerifyingKey";
  return {
    verifying_keys: {
      [variant]: {
        id: {
          backend: request.backend,
          name: request.name,
        },
        record: {
          version: request.version,
          circuit_id: request.circuit_id,
          owner_manifest_id: null,
          namespace: "core",
          backend: request.backend.startsWith("stark/")
            ? "stark"
            : "native-pipa-r-pasta",
          curve: request.curve ?? "unknown",
          public_inputs_schema_hash: Array.from(
            Buffer.from(request.public_inputs_schema_hash_hex, "hex"),
          ),
          commitment: Array.from(Buffer.from(commitmentHex, "hex")),
          vk_len: vkBytes === null ? request.vk_len : vkBytes.length,
          max_proof_bytes: request.max_proof_bytes ?? 0,
          gas_schedule_id: request.gas_schedule_id ?? null,
          metadata_uri_cid: request.metadata_uri_cid ?? null,
          vk_bytes_cid: request.vk_bytes_cid ?? null,
          activation_height: request.activation_height ?? null,
          withdraw_height: request.withdraw_height ?? null,
          key:
            vkBytes === null
              ? null
              : {
                  backend: request.backend,
                  bytes: Array.from(vkBytes),
                },
          status: request.status ?? "Active",
          ...recordOverrides,
        },
      },
    },
  };
}

function verifyingKeyTransactionPayload(
  request,
  operation,
  {
    networkId = VK_SIGNING_NETWORK_ID,
    networkPrefix = 753,
    authority = request.authority,
    recordOverrides = {},
  } = {},
) {
  return buildBrowserVerifyingKeyTransactionPayload(
    {
      networkId,
      networkPrefix,
      authority,
      instructions: [
        verifyingKeyInstructionForRequest(
          request,
          operation,
          recordOverrides,
        ),
      ],
      creationTimeMs: 42,
      ttlMs: 60_000,
      feePayment: { payer: "authority", chargeLimits: [] },
    },
    operation,
  );
}

function sampleVerifyingKeyTransactionDraft(
  overrides = {},
  {
    request = normalizedVerifyingKeyRequest(),
    operation = "register",
    transaction = {},
  } = {},
) {
  const transactionPayload = verifyingKeyTransactionPayload(
    request,
    operation,
    transaction,
  );
  return verifyingKeyDraftForPayload(transactionPayload, overrides);
}

function verifyingKeyDraftForPayload(transactionPayload, overrides = {}) {
  const signingMessage = Buffer.from(blake2b256(transactionPayload));
  signingMessage[signingMessage.length - 1] |= 1;
  return {
    submitted: false,
    transaction_payload_b64: transactionPayload.toString("base64"),
    signing_message_b64: signingMessage.toString("base64"),
    ...overrides,
  };
}

function encodeTestCompactLength(value) {
  let remaining = BigInt(value);
  const output = [];
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining !== 0n) {
      byte |= 0x80;
    }
    output.push(byte);
  } while (remaining !== 0n);
  return Buffer.from(output);
}

function readTestCompactField(payload, start) {
  let offset = start;
  let length = 0n;
  let shift = 0n;
  while (true) {
    const byte = payload[offset];
    offset += 1;
    length |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7n;
  }
  const end = offset + Number(length);
  return { value: payload.subarray(offset, end), end };
}

function encodeTestCompactField(value) {
  return Buffer.concat([encodeTestCompactLength(value.length), value]);
}

function verifyingKeyTransactionPayloadWithExtraInstruction(request) {
  const payload = verifyingKeyTransactionPayload(request, "register");
  const fields = [];
  let offset = 0;
  while (offset < payload.length) {
    const field = readTestCompactField(payload, offset);
    fields.push(field.value);
    offset = field.end;
  }
  const executable = fields[3];
  const instructionsField = readTestCompactField(executable, 4);
  const firstInstruction = readTestCompactField(
    instructionsField.value,
    8,
  ).value;
  const count = Buffer.alloc(8);
  count.writeBigUInt64LE(2n);
  const instructions = Buffer.concat([
    count,
    encodeTestCompactField(firstInstruction),
    encodeTestCompactField(firstInstruction),
  ]);
  fields[3] = Buffer.concat([
    executable.subarray(0, 4),
    encodeTestCompactField(instructions),
  ]);
  return Buffer.concat(fields.map(encodeTestCompactField));
}

function createVerifyingKeyDraftResponse(overrides = {}, options = {}) {
  return createResponse({
    status: 200,
    jsonData: sampleVerifyingKeyTransactionDraft(overrides, options),
    headers: { "content-type": "application/json" },
  });
}

function verifyingKeyCommitmentHex(backend, bytes) {
  const backendBytes = Buffer.from(backend, "utf8");
  return crypto.createHash("sha256")
    .update(Buffer.from("iroha:zk:v1:vk", "utf8"))
    .update(u64BeBuffer(backendBytes.length))
    .update(backendBytes)
    .update(u64BeBuffer(bytes.length))
    .update(bytes)
    .digest("hex");
}

function u64BeBuffer(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value));
  return buffer;
}

function verifyingKeyRecordResponse(overrides = {}) {
  return {
    version: 1,
    circuit_id: "pipa-r/pasta::transfer_v1",
    owner_manifest_id: null,
    namespace: "core",
    backend: "native-pipa-r-pasta",
    curve: "pallas",
    public_inputs_schema_hash: "ab".repeat(32),
    commitment: "cd".repeat(32),
    vk_len: 2,
    max_proof_bytes: 4096,
    gas_schedule_id: "default",
    metadata_uri_cid: null,
    vk_bytes_cid: null,
    activation_height: 10,
    withdraw_height: 20,
    status: "Active",
    key: {
      backend: "pipa-r/pasta",
      bytes_b64: Buffer.from("vk").toString("base64"),
    },
    ...overrides,
  };
}

test("listVerifyingKeys validates canonical records", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return createResponse({
      status: 200,
      jsonData: [
        {
          id: { backend: "pipa-r/pasta", name: "vk_main" },
          record: verifyingKeyRecordResponse({
            version: 2,
            circuit_id: "pipa-r/pasta::transfer_v2",
            owner_manifest_id: "builtin:transfer-v2",
            namespace: "payments",
            vk_len: 5,
            max_proof_bytes: 8192,
            gas_schedule_id: "halo2_default",
            vk_bytes_cid: "ipfs://vk",
            withdraw_height: 30,
            key: {
              backend: "pipa-r/pasta",
              bytes_b64: Buffer.from("hello").toString("base64"),
            },
          }),
        },
      ],
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const list = await client.listVerifyingKeys({
    backend: "pipa-r/pasta",
    status: "Active",
    limit: 5,
    order: "asc",
  });

  assert.equal(list.length, 1);
  const entry = list[0];
  assert.deepEqual(entry.id, { backend: "pipa-r/pasta", name: "vk_main" });
  assert.equal(entry.record?.status, "Active");
  assert.equal(entry.record?.backend, "native-pipa-r-pasta");
  assert.equal(entry.record?.owner_manifest_id, "builtin:transfer-v2");
  assert.equal(entry.record?.namespace, "payments");
  assert.equal(entry.record?.vk_len, 5);
  assert.equal(entry.record?.inline_key?.backend, "pipa-r/pasta");
  assert.equal(entry.record?.inline_key?.bytes_b64, Buffer.from("hello").toString("base64"));

  const invoked = new URL(calls[0].url);
  assert.equal(invoked.pathname, "/v1/zk/vk");
  assert.equal(invoked.searchParams.get("backend"), "pipa-r/pasta");
  assert.equal(invoked.searchParams.get("status"), "Active");
  assert.equal(invoked.searchParams.get("limit"), "5");
  assert.equal(invoked.searchParams.get("order"), "asc");
});

test("verifying key read paths reject unsupported production backends before fetch", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("unexpected fetch");
    },
  });
  for (const backend of [
    "halo2/ipa",
    "halo2/pasta/kaigi-authorization-v1",
    "halo2/pasta/kaigi-usage-v1",
    "pipa-r/ipa/pasta/kaigi-usage-v1",
    "halo2/pasta/kaigi-roster-v1",
    "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
    " halo2/ipa",
    "halo2/ipa ",
    "\thalo2/ipa",
    "halo2/ipa\n",
    "halo2\uFF0Fipa",
    "halo2/\u200Bipa",
    "h\u0430lo2/ipa",
    "stark/fri/miden",
    "stark/fri/latest",
    "stark/fri/attestation",
    "stark/fri/contest",
    "stark/fri/random-profile",
    "stark/fri/sha512-goldilocks",
    "stark/fri/audit-proof-v1",
    "halo2/ipa:production-ready",
    "halo2/ipa:claimed-production",
    "halo2/ipa:mainnet-ready",
    "stark/fri/audit-signoff",
    "stark/fri/externally-audited",
    "stark/fri/security-review-passed",
    "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
    "stark/fri/a-u-d-i-t-c-l-a-i-m",
    "halo2/ipa/penumbra",
    "halo2/ipa/masp",
    "halo2/ipa/monero",
    "halo2/ipa/curve-tree",
    "halo2/pasta/tiny-add",
    "halo2/ipa/tiny-add",
    "halo2/ipa:tiny-add",
    "halo2/pasta/tiny-commit-open",
    "halo2/pasta/anon-transfer-2x2",
    "halo2/ipa/anon-transfer-2x2",
    "halo2/ipa:anon-transfer-2x2",
    "halo2/pasta/anon-transfer-2x2-merkle2",
    "halo2/ipa/anon-transfer-2x2-merkle8",
    "halo2/ipa:anon-transfer-2x2-merkle16",
    "halo2/pasta/vote-bool-commit",
    "halo2/ipa/vote-bool-commit",
    "halo2/ipa:vote-bool-commit",
    "halo2/pasta/vote-bool-commit-merkle2",
    "halo2/ipa/vote-bool-commit-merkle8",
    "halo2/ipa:vote-bool-commit-merkle16",
    "stark/fri/dev-fixture",
    "stark/fri/d-e-v-f-i-x-t-u-r-e",
    "stark/fri/dev",
    "stark/fri/d-e-v",
    "stark/fri/test",
    "stark/fri/t-e-s-t",
    "stark/fri/todo",
    "stark/fri/t-o-d-o",
    "stark/fri/draft-only",
    "stark/fri/d-r-a-f-t",
    "stark/fri/pending-audit",
    "stark/fri/replace-before-mainnet",
    "stark/fri/not-production-ready",
    "stark/fri/placeholder",
    " stark/fri/poseidon-x7-goldilocks-6x64-v1",
    "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
    "halo2/ipa/orchard",
    "halo2/kzg",
    "halo2/ipa\0",
    "halo2/ipa:dev-fixture",
    "halo2/ipa:dev",
    "halo2/ipa:d-e-v",
    "halo2/ipa:todo-proof",
    "halo2/ipa:t-o-d-o-proof",
    "halo2/ipa:draft-proof",
    "halo2/ipa:d-r-a-f-t-proof",
    "halo2/ipa:pending-audit",
    "halo2/ipa:replace-before-production",
    "halo2/ipa:not-for-production",
    "halo2/ipa:dummy",
    "halo2/ipa:f-a-k-e",
    "halo2/ipa:stub",
    "halo2/ipa:s-a-m-p-l-e",
    "mock/dev",
  ]) {
    await assert.rejects(
      () => client.getVerifyingKey(backend, "vk_main"),
      expectedProductionBackendRejectionPattern(backend),
    );
    await assert.rejects(
      () => client.listVerifyingKeys({ backend }),
      expectedProductionBackendRejectionPattern(backend),
    );
  }
  assert.equal(calls, 0);
});

test("verifying key get path rejects padded selector names before fetch", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("unexpected fetch");
    },
  });
  for (const name of [" vk_main", "vk_main "]) {
    await assert.rejects(
      () => client.getVerifyingKey("pipa-r/pasta", name),
      /getVerifyingKey name must not contain surrounding whitespace/,
    );
  }
  assert.equal(calls, 0);
});

test("verifying key read paths reject unstable STARK profile aliases before fetch", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("unexpected fetch");
    },
  });
  for (const backend of ["stark/fri/latest", "stark/fri/attestation", "stark/fri/contest"]) {
    await assert.rejects(
      () => client.getVerifyingKey(backend, "vk_main"),
      /unsupported production verifier backend/,
    );
  }
  assert.equal(calls, 0);
});

test("listVerifyingKeys rejects noncanonical response backends", async () => {
  const baseRecord = verifyingKeyRecordResponse();
  for (const entry of [
    { backend: " halo2/ipa", name: "flat_vk" },
    { id: { backend: "halo2/ipa ", name: "object_vk" } },
    { backend: "halo2\uFF0Fipa", name: "fullwidth_slash_vk" },
    { id: { backend: "h\u0430lo2/ipa", name: "cyrillic_a_vk" } },
    {
      id: { backend: "pipa-r/pasta", name: "record_vk" },
      record: { ...baseRecord, backend: "\thalo2-ipa-pasta" },
    },
    {
      id: { backend: "pipa-r/pasta", name: "inline_vk" },
      record: {
        ...baseRecord,
        key: {
          backend: "halo2/ipa\n",
          bytes_b64: Buffer.from("vk").toString("base64"),
        },
      },
    },
    {
      id: { backend: "pipa-r/pasta", name: "zero_width_vk" },
      record: {
        ...baseRecord,
        key: {
          backend: "halo2/\u200Bipa",
          bytes_b64: Buffer.from("vk").toString("base64"),
        },
      },
    },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: [entry],
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.listVerifyingKeys(),
      /unsupported production verifier backend|surrounding whitespace|native-pipa-r-pasta or stark/,
    );
  }
});

test("listVerifyingKeys rejects padded response selector metadata", async () => {
  const baseRecord = verifyingKeyRecordResponse();
  for (const entry of [
    { backend: "pipa-r/pasta", name: " flat_vk" },
    { id: { backend: "pipa-r/pasta", name: "object_vk " } },
    {
      id: { backend: "pipa-r/pasta", name: "circuit_vk" },
      record: { ...baseRecord, circuit_id: " pipa-r/pasta::transfer_v1" },
    },
    {
      id: { backend: "pipa-r/pasta", name: "gas_vk" },
      record: { ...baseRecord, gas_schedule_id: "default " },
    },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: [entry],
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.listVerifyingKeys(),
      /must not contain surrounding whitespace/,
    );
  }
});

test("iterateVerifyingKeys paginates and forwards filters", async () => {
  const seenOffsets = [];
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    const limit = Number(parsed.searchParams.get("limit") ?? "0");
    seenOffsets.push(offset);
    assert.equal(parsed.searchParams.get("backend"), "pipa-r/pasta");
    assert.equal(parsed.searchParams.get("status"), "Active");
    assert.equal(limit, 1);
    if (offset >= 2) {
      throw new Error("unexpected extra verifier request");
    }
    return createResponse({
      status: 200,
      jsonData: [{ backend: "pipa-r/pasta", name: `vk-${offset}` }],
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const names = [];
  for await (const entry of client.iterateVerifyingKeys({
    backend: "pipa-r/pasta",
    status: "Active",
    pageSize: 1,
    maxItems: 2,
  })) {
    names.push(entry.id.name);
  }
  assert.deepEqual(names, ["vk-0", "vk-1"]);
  assert.deepEqual(seenOffsets, [0, 1]);
});

test("iterateVerifyingKeys rejects unsupported iterator options", () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: [], headers: { "content-type": "application/json" } }),
  });
  assert.throws(
    () => client.iterateVerifyingKeys({ backend: "pipa-r/pasta", extra: true }),
    /iterator options contains unsupported fields: extra/,
  );
});

test("listVerifyingKeys rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  await assert.rejects(
    () => client.listVerifyingKeys({ backend: "pipa-r/pasta", extra: true }),
    /listVerifyingKeys options contains unsupported fields: extra/,
  );
});

test("listVerifyingKeys rejects compatibility option aliases", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("unexpected fetch");
    },
  });
  for (const option of [
    { backend_filter: "pipa-r/pasta" },
    { statusFilter: "Withdrawn" },
    { verifyingKeyStatus: "Withdrawn" },
    { name_contains: "transfer" },
    { sort: "desc" },
    { sortOrder: "desc" },
    { ids_only: true },
  ]) {
    await assert.rejects(
      () => client.listVerifyingKeys(option),
      /unsupported fields/,
    );
  }
  assert.equal(fetchCalls, 0);
});

test("getVerifyingKey validates and returns the canonical payload", async () => {
  const fetchImpl = async (url) => {
    assert.equal(url, `${BASE_URL}/v1/zk/vk/pipa-r%2Fpasta/vk_main`);
    return createResponse({
      status: 200,
      jsonData: {
        id: { backend: "pipa-r/pasta", name: "vk_main" },
        record: verifyingKeyRecordResponse({
          curve: "unknown",
          vk_len: 1024,
          max_proof_bytes: 512,
          gas_schedule_id: null,
          activation_height: 5,
          withdraw_height: 7,
          status: "Proposed",
          key: null,
        }),
        record_norito_base64: Buffer.from("canonical record").toString("base64"),
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const detail = await client.getVerifyingKey("pipa-r/pasta", "vk_main");
  assert.equal(detail.id.backend, "pipa-r/pasta");
  assert.equal(detail.id.name, "vk_main");
  assert.equal(detail.record.status, "Proposed");
  assert.equal(detail.record.vk_len, 1024);
  assert.equal(detail.record.inline_key, null);
  assert.equal(
    detail.record_norito_base64,
    Buffer.from("canonical record").toString("base64"),
  );
});

test("getVerifyingKey rejects withdraw height at or before activation height", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        id: { backend: "pipa-r/pasta", name: "vk_main" },
        record: verifyingKeyRecordResponse({
          activation_height: 10,
          withdraw_height: 10,
          status: "Proposed",
          key: null,
        }),
        record_norito_base64: Buffer.from("canonical record").toString("base64"),
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getVerifyingKey("pipa-r/pasta", "vk_main"),
    /withdraw_height must be > activation_height/,
  );
});

test("registerVerifyingKey canonicalizes payload and returns an unsigned draft", async () => {
  let captured;
  const canonicalAuthority =
    FIXTURE_ALICE_ID;
  const fetchImpl = async (url, init) => {
    captured = { url, init, body: JSON.parse(init.body) };
    return createVerifyingKeyDraftResponse(
      {},
      { request: captured.body, operation: "register" },
    );
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });
  const draft = await client.registerVerifyingKey({
    authority: canonicalAuthority,
    backend: "pipa-r/pasta",
    name: "vk_main",
    version: 3,
    circuit_id: "pipa-r/pasta::transfer_v3",
    public_inputs_schema_hash_hex: "22".repeat(32),
    gas_schedule_id: "halo2_default",
    vk_bytes: Buffer.from("abc"),
    status: "Withdrawn",
    activation_height: 0,
  });

  assert.ok(captured);
  assert.equal(captured.url, `${BASE_URL}/v1/zk/vk/register`);
  assert.equal(captured.init.method, "POST");
  assert.equal(
    captured.init.headers["Content-Type"],
    "application/json",
  );
  const body = captured.body;
  assert.equal(body.authority, normalizeAccountId(canonicalAuthority, "registerVerifyingKey.authority"));
  assert.equal(body.private_key, undefined);
  assert.equal(body.backend, "pipa-r/pasta");
  assert.equal(body.name, "vk_main");
  assert.equal(body.version, 3);
  assert.equal(body.circuit_id, "pipa-r/pasta::transfer_v3");
  assert.equal(body.public_inputs_schema_hash_hex, "22".repeat(32));
  assert.equal(body.public_inputs_schema_hex, undefined);
  assert.equal(body.gas_schedule_id, "halo2_default");
  assert.equal(body.vk_bytes, Buffer.from("abc").toString("base64"));
  assert.equal(body.vk_len, 3);
  assert.equal(body.status, "Withdrawn");
  assert.equal(body.activation_height, 0);
  assert.deepEqual(
    draft,
    sampleVerifyingKeyTransactionDraft(
      {},
      { request: body, operation: "register" },
    ),
  );
});

test("updateVerifyingKey sends metadata only and returns an unsigned draft", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init, body: JSON.parse(init.body) };
    return createVerifyingKeyDraftResponse(
      {},
      { request: captured.body, operation: "update" },
    );
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });

  const draft = await client.updateVerifyingKey({
    ...sampleVerifyingKeyRegisterPayload(),
    version: 2,
    circuit_id: "pipa-r/pasta::transfer_v2",
  });

  assert.equal(captured.url, `${BASE_URL}/v1/zk/vk/update`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.body.private_key, undefined);
  assert.equal(captured.body.public_inputs_schema_hash_hex, "11".repeat(32));
  assert.deepEqual(
    draft,
    sampleVerifyingKeyTransactionDraft(
      {},
      { request: captured.body, operation: "update" },
    ),
  );
});

test("verifying key mutation helpers reject private-key fields before fetch", async () => {
  let fetchCount = 0;
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      fetchCount += 1;
      return createVerifyingKeyDraftResponse();
    },
  });

  for (const method of ["registerVerifyingKey", "updateVerifyingKey"]) {
    for (const field of ["private_key", "privateKey", "private_key_hex", "privateKeyBytes"]) {
      await assert.rejects(
        () =>
          client[method]({
            ...sampleVerifyingKeyRegisterPayload(),
            [field]: field === "privateKeyBytes" ? Buffer.alloc(32) : "secret",
          }),
        /does not accept private-key fields.*sign the returned transaction draft locally/,
        `${method} must reject ${field}`,
      );
    }
  }

  assert.equal(fetchCount, 0);
});

test("verifying key mutation helpers enforce the unsigned-draft response contract", async () => {
  const payload = sampleVerifyingKeyRegisterPayload();
  for (const [label, response, pattern] of [
    [
      "submitted transaction",
      createVerifyingKeyDraftResponse({ submitted: true }),
      /submitted must be false/,
    ],
    [
      "non-canonical transaction payload",
      createVerifyingKeyDraftResponse({ transaction_payload_b64: "AQ" }),
      /transaction_payload_b64 must be exact standard-base64/,
    ],
    [
      "missing signing message",
      createVerifyingKeyDraftResponse({ signing_message_b64: undefined }),
      /signing_message_b64 must be exact standard-base64/,
    ],
    [
      "oversized transaction payload",
      createVerifyingKeyDraftResponse({
        transaction_payload_b64: Buffer.alloc(
          16 * 1024 * 1024 + 1,
        ).toString("base64"),
      }),
      /transaction_payload_b64 exceeds the 16777216-byte transaction payload limit/,
    ],
    [
      "wrong signing message length",
      createVerifyingKeyDraftResponse({
        signing_message_b64: Buffer.alloc(31).toString("base64"),
      }),
      /signing_message_b64 must decode to exactly 32 bytes/,
    ],
    [
      "mismatched signing message",
      createVerifyingKeyDraftResponse({
        signing_message_b64: Buffer.alloc(32).toString("base64"),
      }),
      /signing_message_b64 must equal the canonical Iroha HashOf/,
    ],
    [
      "unexpected response field",
      createVerifyingKeyDraftResponse({ accepted: true }),
      /contains unsupported fields: accepted/,
    ],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async () => response,
    });
    await assert.rejects(
      () => client.registerVerifyingKey(payload),
      pattern,
      label,
    );
  }

  const legacyStatusClient = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () =>
      createResponse({
        status: 202,
        jsonData: sampleVerifyingKeyTransactionDraft(),
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => legacyStatusClient.updateVerifyingKey(payload),
    /HTTP 202 \(expected 200\)/,
  );
});

test("verifying key drafts are bound to NetworkId, authority, operation, count, and full record", async () => {
  const request = normalizedVerifyingKeyRequest();
  const canonical = verifyingKeyTransactionPayload(request, "register");
  const cases = [
    [
      "operation substitution",
      verifyingKeyTransactionPayload(request, "update"),
      /must contain exactly one RegisterVerifyingKey/,
    ],
    [
      "extra instruction",
      verifyingKeyTransactionPayloadWithExtraInstruction(request),
      /must contain exactly one instruction/,
    ],
    [
      "wrong network",
      verifyingKeyTransactionPayload(request, "register", {
        networkId: NetworkId.fromBytes(
          Uint8Array.from({ length: 32 }, () => 0xff),
        ),
      }),
      /changed the configured NetworkId/,
    ],
    [
      "wrong authority",
      verifyingKeyTransactionPayload(request, "register", {
        authority: FIXTURE_BOB_ID,
      }),
      /changed the requested authority/,
    ],
    [
      "noncanonical payload",
      Buffer.concat([canonical, Buffer.of(0)]),
      /contains 1 trailing bytes/,
    ],
    [
      "record field mismatch",
      verifyingKeyTransactionPayload(request, "register", {
        recordOverrides: { max_proof_bytes: 1 },
      }),
      /does not contain the exact requested verifying-key registry record/,
    ],
  ];
  for (const [label, transactionPayload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: verifyingKeyDraftForPayload(transactionPayload),
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.registerVerifyingKey(sampleVerifyingKeyRegisterPayload()),
      pattern,
      label,
    );
  }
});

test("verifying key local-signing APIs fail closed without immutable NetworkId context", async () => {
  let fetchCount = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCount += 1;
      return createVerifyingKeyDraftResponse();
    },
  });
  await assert.rejects(
    () => client.registerVerifyingKey(sampleVerifyingKeyRegisterPayload()),
    /requires immutable ToriiClient options\.localSigningContext/,
  );
  await assert.rejects(
    () => client.updateVerifyingKey(sampleVerifyingKeyRegisterPayload()),
    /requires immutable ToriiClient options\.localSigningContext/,
  );
  assert.equal(fetchCount, 0);

  for (const field of ["chain", "chainId", "chain_id", "networkId"]) {
    assert.throws(
      () =>
        new ToriiClient(BASE_URL, {
          [field]: field === "networkId" ? VK_SIGNING_NETWORK_ID : "vk-test",
          fetchImpl: async () => {
            fetchCount += 1;
            return createVerifyingKeyDraftResponse();
          },
        }),
      new RegExp(
        `options\\.${field} is not supported; use a LocalSigningContext`,
        "u",
      ),
    );
  }
  assert.equal(fetchCount, 0);
});

test("verifying key LocalSigningContext is canonical and immutable", () => {
  const context = new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753);
  assert.equal(context.networkId, VK_SIGNING_NETWORK_ID);
  assert.equal(Object.isFrozen(context), true);
  assert.throws(
    () => {
      context.networkId = NetworkId.fromBytes(
        Uint8Array.from({ length: 32 }, () => 0xfd),
      );
    },
    TypeError,
  );
  for (const invalid of ["vk-test", VK_SIGNING_NETWORK_ID.toBytes(), {}]) {
    assert.throws(() => new LocalSigningContext(invalid, 753), /must be a NetworkId/);
  }
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        localSigningContext: { networkId: VK_SIGNING_NETWORK_ID },
      }),
    /must be a LocalSigningContext/,
  );
});

test("verifying-key payload builder rejects retired ChainId input", () => {
  const request = normalizedVerifyingKeyRequest();
  assert.throws(
    () =>
      buildBrowserVerifyingKeyTransactionPayload(
        {
          chainId: "vk-test",
          authority: request.authority,
          instructions: [
            verifyingKeyInstructionForRequest(request, "register"),
          ],
          creationTimeMs: 42,
          ttlMs: 60_000,
          feePayment: { payer: "authority", chargeLimits: [] },
        },
        "register",
      ),
    /instruction transaction input\.chainId is not supported/,
  );
});

test("registerVerifyingKey posts the canonical Torii schema-hash field", async () => {
  let captured;
  const fetchImpl = async (_url, init) => {
    captured = JSON.parse(init.body);
    return createVerifyingKeyDraftResponse(
      {},
      { request: captured, operation: "register" },
    );
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });
  await client.registerVerifyingKey({
    ...sampleVerifyingKeyRegisterPayload(),
    public_inputs_schema_hash_hex: `0x${"22".repeat(32)}`,
  });

  assert.equal(captured.public_inputs_schema_hash_hex, "22".repeat(32));
  assert.equal(captured.public_inputs_schema_hex, undefined);
});

test("registerVerifyingKey accepts current production backend labels", async () => {
  const captured = [];
  const fetchImpl = async (_url, init) => {
    const request = JSON.parse(init.body);
    captured.push(request);
    return createVerifyingKeyDraftResponse(
      {},
      { request, operation: "register" },
    );
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });
  const backends = [
    "pipa-r/pasta",
    "pipa-r/pasta/kaigi-authorization-v1",
    "pipa-r/pasta/kaigi-usage-v1",
    "pipa-r/pasta/confidential-transfer-v1",
    "pipa-r/pasta/confidential-unshield-full-v1",
    "pipa-r/pasta/confidential-unshield-change-v1",
    "stark/fri/poseidon-x7-goldilocks-6x64-v1",
  ];
  for (const [index, backend] of backends.entries()) {
    await client.registerVerifyingKey({
      ...sampleVerifyingKeyRegisterPayload(),
      backend,
      name: `vk_${index}`,
      circuit_id: `production_circuit_${index}`,
    });
  }

  assert.deepEqual(captured.map((body) => body.backend), backends);
});

test("updateVerifyingKey accepts current production backend labels", async () => {
  const captured = [];
  const fetchImpl = async (_url, init) => {
    const request = JSON.parse(init.body);
    captured.push(request);
    return createVerifyingKeyDraftResponse(
      {},
      { request, operation: "update" },
    );
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });
  const backends = [
    "pipa-r/pasta",
    "pipa-r/pasta/kaigi-authorization-v1",
    "pipa-r/pasta/kaigi-usage-v1",
    "stark/fri/poseidon-x7-goldilocks-6x64-v1",
  ];
  for (const [index, backend] of backends.entries()) {
    await client.updateVerifyingKey({
      ...sampleVerifyingKeyRegisterPayload(),
      backend,
      name: `vk_update_${index}`,
      version: 2,
      circuit_id: `production_update_circuit_${index}`,
    });
  }

  assert.deepEqual(captured.map((body) => body.backend), backends);
});

test("registerVerifyingKey rejects mismatched vk_len", async () => {
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  const payload = {
    ...sampleVerifyingKeyRegisterPayload(),
    vk_bytes: Buffer.from("abc"),
    vk_len: 4,
  };
  await assert.rejects(
    () => client.registerVerifyingKey(payload),
    /vk_len/,
  );
});

test("verifying key registration rejects mismatched inline key commitment", async () => {
  let fetchCount = 0;
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async (_url, init) => {
      fetchCount += 1;
      return createVerifyingKeyDraftResponse(
        {},
        { request: JSON.parse(init.body), operation: "register" },
      );
    },
  });
  const bytes = Buffer.from("abc");
  const matchingCommitment = verifyingKeyCommitmentHex("pipa-r/pasta", bytes);

  await assert.rejects(
    () =>
      client.registerVerifyingKey({
        ...sampleVerifyingKeyRegisterPayload(),
        vk_bytes: bytes,
        commitment_hex: "00".repeat(32),
    }),
    /commitment_hex must match domain-separated SHA-256 of backend and vk_bytes/,
  );
  assert.equal(fetchCount, 0);
  await assert.doesNotReject(() =>
    client.registerVerifyingKey({
      ...sampleVerifyingKeyRegisterPayload(),
      vk_bytes: bytes,
      commitment_hex: matchingCommitment,
    }),
  );
  assert.equal(fetchCount, 1);
});

test("verifying key registration rejects length-only verifier material", async () => {
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  await assert.rejects(
    () =>
      client.registerVerifyingKey({
        ...sampleVerifyingKeyRegisterPayload(),
        vk_bytes: null,
        vk_len: 3,
        commitment_hex: null,
      }),
    /commitment_hex is required when vk_bytes is omitted/,
  );
});

test("verifying key requests reject withdraw height before activation height", async () => {
  let fetchCount = 0;
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      fetchCount += 1;
      throw new Error("unexpected fetch");
    },
  });
  const payload = {
    ...sampleVerifyingKeyRegisterPayload(),
    activation_height: 10,
    withdraw_height: 9,
  };

  await assert.rejects(
    () => client.registerVerifyingKey(payload),
    /withdraw_height must be > activation_height/,
  );
  await assert.rejects(
    () => client.updateVerifyingKey({ ...payload, version: 2 }),
    /withdraw_height must be > activation_height/,
  );
  assert.equal(fetchCount, 0);
});

test("verifying key requests reject padded selector metadata before fetch", async () => {
  let fetchCount = 0;
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      fetchCount += 1;
      throw new Error("unexpected fetch");
    },
  });
  const payload = sampleVerifyingKeyRegisterPayload();

  for (const [label, action, pattern] of [
    [
      "register padded name",
      () => client.registerVerifyingKey({ ...payload, name: " vk_main" }),
      /registerVerifyingKey\.name must not contain surrounding whitespace/,
    ],
    [
      "register padded circuit id",
      () => client.registerVerifyingKey({ ...payload, circuit_id: " pipa-r/pasta::transfer_v1" }),
      /registerVerifyingKey\.circuitId must not contain surrounding whitespace/,
    ],
    [
      "register padded gas schedule id",
      () => client.registerVerifyingKey({ ...payload, gas_schedule_id: "default " }),
      /registerVerifyingKey\.gasScheduleId must not contain surrounding whitespace/,
    ],
    [
      "update padded name",
      () => client.updateVerifyingKey({ ...payload, version: 2, name: "vk_main " }),
      /updateVerifyingKey\.name must not contain surrounding whitespace/,
    ],
    [
      "update padded circuit id",
      () => client.updateVerifyingKey({ ...payload, version: 2, circuit_id: "pipa-r/pasta::transfer_v1 " }),
      /updateVerifyingKey\.circuitId must not contain surrounding whitespace/,
    ],
    [
      "update padded gas schedule id",
      () => client.updateVerifyingKey({ ...payload, version: 2, gas_schedule_id: " default" }),
      /updateVerifyingKey\.gasScheduleId must not contain surrounding whitespace/,
    ],
  ]) {
    await assert.rejects(action, pattern, label);
  }

  assert.equal(fetchCount, 0);
});

test("verifying key registration rejects unsupported production backends before fetch", async () => {
  const client = new ToriiClient(BASE_URL, {
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  const base = sampleVerifyingKeyRegisterPayload();
  const cases = [
    ...[
      "halo2/pasta/ipa/confidential-transfer-2x2-merkle16-axiom-poseidon-v3",
      "halo2/pasta/ipa/confidential-unshield-full-merkle16-axiom-poseidon-v3",
      "halo2/pasta/ipa/confidential-unshield-change-merkle16-axiom-poseidon-v4",
    ].flatMap((backend) => [
      [`register retired confidential ${backend}`, () => client.registerVerifyingKey({ ...base, backend })],
      [`update retired confidential ${backend}`, () => client.updateVerifyingKey({ ...base, backend })],
    ]),
    ["register retired IVM binding backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/ivm-execution-v1" })],
    ["update retired IVM binding backend", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/ivm-execution-v1" })],
    ["register retired IVM replay binding backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/ivm-replay-binding-v1" })],
    ["update retired IVM replay binding backend", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/ivm-replay-binding-v1" })],
    ["register retired Kaigi roster", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/kaigi-roster-v1" })],
    ["update retired Kaigi roster", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/kaigi-roster-v1" })],
    ["register unsupported KAGEMUSHA fold", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1" })],
    ["update unsupported KAGEMUSHA fold", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1" })],
    ["register retired Halo2 engine", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa" })],
    ["update retired Halo2 engine", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa" })],
    ["register unknown native", () => client.registerVerifyingKey({ ...base, backend: "halo2/unknown-native-v1" })],
    ["register unknown IPA suffix", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:unknown-native-v1" })],
    ["register retired IPA cycle alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa-pasta-cycle-v1" })],
    ["register retired IPA profile alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:ivm-replay-binding-v1" })],
    ["register leading-space backend", () => client.registerVerifyingKey({ ...base, backend: " halo2/ipa" })],
    ["register trailing-space backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa " })],
    ["register leading-tab backend", () => client.registerVerifyingKey({ ...base, backend: "\thalo2/ipa" })],
    ["register trailing-newline backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa\n" })],
    ["register fullwidth-slash backend", () => client.registerVerifyingKey({ ...base, backend: "halo2\uFF0Fipa" })],
    ["register zero-width backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/\u200Bipa" })],
    ["register Cyrillic-a backend", () => client.registerVerifyingKey({ ...base, backend: "h\u0430lo2/ipa" })],
    ["register uppercase backend", () => client.registerVerifyingKey({ ...base, backend: "HALO2/IPA" })],
    ["register uppercase STARK backend", () => client.registerVerifyingKey({ ...base, backend: "stark/FRI" })],
    ["register removed generic STARK backend", () => client.registerVerifyingKey({ ...base, backend: "stark/fri" })],
    ["register removed Poseidon2 STARK backend", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/poseidon2-goldilocks" })],
    ["register removed SHA-256 STARK backend", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/sha256_goldilocks.v1" })],
    ["register double-colon native backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa::ivm-replay-binding-v1" })],
    ["register double-slash backend", () => client.registerVerifyingKey({ ...base, backend: "halo2//ipa" })],
    ["register trailing-colon backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:" })],
    ["register trailing-dot backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa." })],
    ["register slash-dot backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/.ivm-replay-binding-v1" })],
    ["register dot-dot backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:ivm..execution-v1" })],
    ["register pending Orchard", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/orchard" })],
    ["register unstable STARK latest alias", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/latest" })],
    ["register unstable STARK attestation alias", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/attestation" })],
    ["register unstable STARK contest alias", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/contest" })],
    ["register unknown STARK profile", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/random-profile" })],
    ["register unknown STARK hash", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/sha512-goldilocks" })],
    ["register claimed audited STARK profile", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/audit-proof-v1" })],
    ["register claimed production IPA", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:production-ready" })],
    ["register claimed mainnet IPA", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:mainnet-ready" })],
    ["register claimed release IPA", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:release-ready" })],
    ["register claimed certified mainnet IPA", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:certified-mainnet" })],
    ["register claimed third-party audited IPA", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:third-party-audited" })],
    ["register claimed audit STARK", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/audit-signoff" })],
    ["register claimed BOI audited STARK", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/boi-audited" })],
    ["register claimed external security review STARK", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/external-security-review" })],
    ["register spliced security review STARK", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/S.e.c.u.r.i.t.yReviewPassed" })],
    ["register spliced security audited STARK", () => client.registerVerifyingKey({ ...base, backend: "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d" })],
    ["register pending Penumbra splice", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/penumbra" })],
    ["register pending MASP splice", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/masp" })],
    ["register toy native Halo2 profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/tiny-add" })],
    ["register toy native Halo2 slash alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/tiny-add" })],
    ["register toy native Halo2 colon alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:tiny-add" })],
    ["register toy native Halo2 helper profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/tiny-commit-open" })],
    ["register legacy anon-transfer native Halo2 profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/anon-transfer-2x2" })],
    ["register legacy anon-transfer native Halo2 slash alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/anon-transfer-2x2" })],
    ["register legacy anon-transfer native Halo2 colon alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:anon-transfer-2x2" })],
    ["register legacy anon-transfer native Halo2 merkle2 profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/anon-transfer-2x2-merkle2" })],
    ["register legacy anon-transfer native Halo2 merkle8 alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/anon-transfer-2x2-merkle8" })],
    ["register legacy anon-transfer native Halo2 merkle16 alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:anon-transfer-2x2-merkle16" })],
    ["register legacy vote native Halo2 profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/vote-bool-commit" })],
    ["register legacy vote native Halo2 slash alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/vote-bool-commit" })],
    ["register legacy vote native Halo2 colon alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:vote-bool-commit" })],
    ["register legacy vote native Halo2 merkle2 profile", () => client.registerVerifyingKey({ ...base, backend: "halo2/pasta/vote-bool-commit-merkle2" })],
    ["register legacy vote native Halo2 merkle8 alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa/vote-bool-commit-merkle8" })],
    ["register legacy vote native Halo2 merkle16 alias", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa:vote-bool-commit-merkle16" })],
    ["register trusted setup", () => client.registerVerifyingKey({ ...base, backend: "halo2/kzg" })],
    ["register NUL-suffixed backend", () => client.registerVerifyingKey({ ...base, backend: "halo2/ipa\0" })],
    ["update pending STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/miden" })],
    ["update unstable STARK latest alias", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/latest" })],
    ["update unstable STARK attestation alias", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/attestation" })],
    ["update unstable STARK contest alias", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/contest" })],
    ["update unknown STARK profile", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/random-profile" })],
    ["update unknown STARK hash", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/sha512-goldilocks" })],
    ["update claimed audited STARK profile", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/audit-proof-v1" })],
    ["update claimed production IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:production-ready" })],
    ["update claimed mainnet IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:mainnet-ready" })],
    ["update claimed release IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:release-ready" })],
    ["update claimed certified mainnet IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:certified-mainnet" })],
    ["update claimed third-party audited IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:third-party-audited" })],
    ["update claimed audit STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/audit-signoff" })],
    ["update claimed BOI audited STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/boi-audited" })],
    ["update claimed external security review STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/external-security-review" })],
    ["update spliced audit claim STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/a-u-d-i-t-c-l-a-i-m" })],
    ["update pending Monero splice", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/monero" })],
    ["update pending curve-tree splice", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/curve-tree" })],
    ["update toy native Halo2 profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/tiny-add" })],
    ["update toy native Halo2 slash alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/tiny-add" })],
    ["update toy native Halo2 colon alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:tiny-add" })],
    ["update toy native Halo2 helper profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/tiny-commit-open" })],
    ["update legacy anon-transfer native Halo2 profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/anon-transfer-2x2" })],
    ["update legacy anon-transfer native Halo2 slash alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/anon-transfer-2x2" })],
    ["update legacy anon-transfer native Halo2 colon alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:anon-transfer-2x2" })],
    ["update legacy anon-transfer native Halo2 merkle2 profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/anon-transfer-2x2-merkle2" })],
    ["update legacy anon-transfer native Halo2 merkle8 alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/anon-transfer-2x2-merkle8" })],
    ["update legacy anon-transfer native Halo2 merkle16 alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:anon-transfer-2x2-merkle16" })],
    ["update legacy vote native Halo2 profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/vote-bool-commit" })],
    ["update legacy vote native Halo2 slash alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/vote-bool-commit" })],
    ["update legacy vote native Halo2 colon alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:vote-bool-commit" })],
    ["update legacy vote native Halo2 merkle2 profile", () => client.updateVerifyingKey({ ...base, backend: "halo2/pasta/vote-bool-commit-merkle2" })],
    ["update legacy vote native Halo2 merkle8 alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa/vote-bool-commit-merkle8" })],
    ["update legacy vote native Halo2 merkle16 alias", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:vote-bool-commit-merkle16" })],
    ["update dev fixture STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/dev-fixture" })],
    ["update spliced dev fixture STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/d-e-v-f-i-x-t-u-r-e" })],
    ["update dev STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/dev" })],
    ["update spliced dev STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/d-e-v" })],
    ["update test STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/test" })],
    ["update spliced test STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/t-e-s-t" })],
    ["update todo STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/todo" })],
    ["update spliced todo STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/t-o-d-o" })],
    ["update draft STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/draft-only" })],
    ["update spliced draft STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/d-r-a-f-t" })],
    ["update pending STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/pending-audit" })],
    ["update replace STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/replace-before-mainnet" })],
    ["update not-production STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/not-production-ready" })],
    ["update placeholder STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/placeholder" })],
    ["update dev fixture IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:dev-fixture" })],
    ["update dev IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:dev" })],
    ["update spliced dev IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:d-e-v" })],
    ["update todo IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:todo-proof" })],
    ["update spliced todo IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:t-o-d-o-proof" })],
    ["update draft IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:draft-proof" })],
    ["update spliced draft IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:d-r-a-f-t-proof" })],
    ["update pending IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:pending-audit" })],
    ["update replace IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:replace-before-production" })],
    ["update not-production IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:not-for-production" })],
    ["update dummy IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:dummy" })],
    ["update spliced fake IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:f-a-k-e" })],
    ["update stub IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:stub" })],
    ["update spliced sample IPA", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa:s-a-m-p-l-e" })],
    ["update unknown STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/unknown-native-v1" })],
    ["update leading-space STARK", () => client.updateVerifyingKey({ ...base, backend: " stark/fri/poseidon-x7-goldilocks-6x64-v1" })],
    ["update trailing-space STARK", () => client.updateVerifyingKey({ ...base, backend: "stark/fri/poseidon-x7-goldilocks-6x64-v1 " })],
    ["update fullwidth-slash backend", () => client.updateVerifyingKey({ ...base, backend: "halo2\uFF0Fipa" })],
    ["update zero-width backend", () => client.updateVerifyingKey({ ...base, backend: "halo2/\u200Bipa" })],
    ["update Cyrillic-a backend", () => client.updateVerifyingKey({ ...base, backend: "h\u0430lo2/ipa" })],
    ["update NUL-suffixed backend", () => client.updateVerifyingKey({ ...base, backend: "halo2/ipa\0" })],
  ];
  for (const [label, action] of cases) {
    await assert.rejects(
      action,
      /unsupported production verifier backend|surrounding whitespace/,
      label,
    );
  }
});

test("verifying key endpoints reject unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });
  await assert.rejects(
    () => client.getVerifyingKey("pipa-r/pasta", "vk_main", { extra: true }),
    /getVerifyingKey options contains unsupported fields: extra/,
  );
  const registerPayload = sampleVerifyingKeyRegisterPayload();
  await assert.rejects(
    () => client.registerVerifyingKey(registerPayload, { extra: "x" }),
    /registerVerifyingKey options contains unsupported fields: extra/,
  );
  await assert.rejects(
    () =>
      client.updateVerifyingKey(
        { ...registerPayload, status: "Active" },
        { extra: 123 },
      ),
    /updateVerifyingKey options contains unsupported fields: extra/,
  );
});

test("source and package clients load the canonical verifying-key decoder lazily", async () => {
  const request = normalizedVerifyingKeyRequest();
  for (const [Client, SigningContext, NetworkIdentity] of [
    [ToriiClient, LocalSigningContext, NetworkId],
    [DistToriiClient, DistLocalSigningContext, DistNetworkId],
  ]) {
    const client = new Client(BASE_URL, {
      fetchImpl: async () =>
        createVerifyingKeyDraftResponse({}, { request }),
      localSigningContext: new SigningContext(
        NetworkIdentity.parse(VK_SIGNING_NETWORK_ID_LITERAL), 753,
      ),
    });
    assert.deepEqual(
      await client.registerVerifyingKey(sampleVerifyingKeyRegisterPayload()),
      sampleVerifyingKeyTransactionDraft({}, { request }),
    );
  }
});

function createResponse({ status, jsonData = {}, arrayData, textBody, headers }) {
  const responseText =
    typeof textBody === "string" ? textBody : JSON.stringify(jsonData ?? {});
  const bodyBytes =
    arrayData instanceof ArrayBuffer
      ? new Uint8Array(arrayData)
      : ArrayBuffer.isView(arrayData)
        ? new Uint8Array(
            arrayData.buffer,
            arrayData.byteOffset,
            arrayData.byteLength,
          )
        : new TextEncoder().encode(responseText);
  return {
    status,
    json: async () => jsonData,
    arrayBuffer: async () => {
      if (arrayData instanceof ArrayBuffer) {
        return arrayData;
      }
      if (ArrayBuffer.isView(arrayData)) {
        return arrayData.buffer.slice(arrayData.byteOffset, arrayData.byteOffset + arrayData.byteLength);
      }
      return bodyBytes.buffer.slice(
        bodyBytes.byteOffset,
        bodyBytes.byteOffset + bodyBytes.byteLength,
      );
    },
    text: async () => responseText,
    body: new ReadableStream({
      start(controller) {
        if (bodyBytes.byteLength > 0) controller.enqueue(bodyBytes);
        controller.close();
      },
    }),
    headers: {
      get(name) {
        if (!headers) {
          return null;
        }
        const normalized = name.toLowerCase();
        for (const [key, value] of Object.entries(headers)) {
          if (key.toLowerCase() === normalized) {
            return value;
          }
        }
        return null;
      },
    },
  };
}
