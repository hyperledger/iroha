import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  _createTransactionApi,
  buildRegisterDomainTransaction,
  buildTransaction,
  buildRegisterPinManifestInstruction,
  buildRegisterPinManifestTransaction,
  buildMintAssetTransaction,
  buildMintAndTransferTransaction,
  buildRegisterAssetDefinitionMintAndTransferTransaction,
  buildTransferAssetTransaction,
  buildTransferRwaTransaction,
  hashSignedTransaction,
  hashSignedTransactionPayload,
  hashInstructionBatch,
  feePaymentIntentToNoritoJson,
} from "../src/transaction.js";
import * as transactionExports from "../src/transaction.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import {
  buildBurnAssetInstruction,
  buildMintAssetInstruction,
  buildRegisterDomainInstruction,
  buildSetAccountKeyValueInstruction,
  buildTransferAssetInstruction,
} from "../src/instructionBuilders.js";
import { AccountAddress } from "../src/address.js";
import { ToriiClient } from "../src/toriiClient.js";
import { NetworkId } from "../src/networkId.js";
import { makeNativeTest } from "./helpers/native.js";

const AUTHORITY_PUBLIC_KEY_HEX =
  "CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const AUTHORITY_ID = i105FromEd25519PublicKeyHex(AUTHORITY_PUBLIC_KEY_HEX);
const AUTHORITY_ID_INPUT = i105FromEd25519PublicKeyHex(
  AUTHORITY_PUBLIC_KEY_HEX,
);
const PRIVATE_KEY = Buffer.from(
  "CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53",
  "hex",
);
const NETWORK_ID = NetworkId.parse(
  "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
);
const NETWORK_ID_BYTES = Buffer.from(NETWORK_ID.toBytes());
const AUTHORITY_FEE_PAYMENT = Object.freeze({
  payer: "authority",
  chargeLimits: Object.freeze([]),
});
const IVM_AUTHORITY_FEE_PAYMENT = Object.freeze({
  payer: "authority",
  chargeLimits: Object.freeze([]),
  gasLimit: 1_000,
});
const ZK_IVM_BYTECODE_BASE64 = Buffer.from([
  0x49, 0x56, 0x4d, 0x00,
  0x01, 0x01, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01,
  ...Array(32).fill(0),
]).toString("base64");
const RELAY_PUBLIC_KEY_HEX =
  "641297079357229F295938A4B5A333DE35069BF47B9D0704E45805713D13C201";
const RELAY_ACCOUNT_ID = i105FromEd25519PublicKeyHex(RELAY_PUBLIC_KEY_HEX);
const RELAY_ACCOUNT_ID_INPUT =
  i105FromEd25519PublicKeyHex(RELAY_PUBLIC_KEY_HEX);
const THIRD_RELAY_ACCOUNT_ID_INPUT = i105FromEd25519PublicKeyHex(
  "D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737",
);
const ASSET_DEFINITION_ID = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
const LILY_ASSET_DEFINITION_ID = "61CtjvNd9T3THAR65GsMVHr82Bjc";
const CANONICAL_ASSET_ID_INPUT = `${ASSET_DEFINITION_ID}#${AUTHORITY_ID}`;
const CANONICAL_LILY_ASSET_ID_INPUT = `${LILY_ASSET_DEFINITION_ID}#${AUTHORITY_ID}`;
const SECOND_CANONICAL_ASSET_ID_INPUT = `${ASSET_DEFINITION_ID}#${RELAY_ACCOUNT_ID}`;
const ASSET_ID = CANONICAL_ASSET_ID_INPUT;
const ASSET_ID_INPUT = CANONICAL_ASSET_ID_INPUT;
const RWA_ID =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.sora";
const test = makeNativeTest(baseTest);

function acceptedAuthorityFeeQuote(payload, intent = payload.fee_payment) {
  assert.equal(intent.payer, "authority");
  return {
    intent,
    observation: {
      ledger_time_ms: 1,
      next_block_height: 1,
      route_dataspace_id: 0,
    },
    components: intent.value.charge_limits.map((limit) => ({ ...limit })),
    capacities: [],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "account", value: payload.authority },
        program_revision: null,
      },
    },
  };
}

function i105FromEd25519PublicKeyHex(publicKeyHex) {
  const publicKey = Buffer.from(publicKeyHex.trim(), "hex");
  return AccountAddress.fromAccount({ publicKey }).toI105();
}

function encodeAssetIdForKnownAccount(assetDefinitionId, accountId) {
  assert.equal(assetDefinitionId, ASSET_DEFINITION_ID);
  if (accountId === AUTHORITY_ID || accountId === AUTHORITY_ID_INPUT) {
    return CANONICAL_ASSET_ID_INPUT;
  }
  throw new Error(
    `unexpected account id for test asset encoding: ${accountId}`,
  );
}

function crc16(tag, body) {
  let crc = 0xffff;
  const processByte = (byte) => {
    crc ^= (byte & 0xff) << 8;
    for (let i = 0; i < 8; i += 1) {
      if ((crc & 0x8000) !== 0) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  };

  for (const byte of Buffer.from(tag, "utf8")) {
    processByte(byte);
  }
  processByte(":".charCodeAt(0));
  for (const byte of Buffer.from(body, "utf8")) {
    processByte(byte);
  }
  return crc & 0xffff;
}

function normalizedHashHex(bytes) {
  const buffer = Buffer.from(bytes);
  if (buffer.length !== 32) {
    throw new TypeError("hash literal test helper requires 32 bytes");
  }
  buffer[buffer.length - 1] |= 1;
  const body = buffer.toString("hex").toUpperCase();
  const checksum = crc16("hash", body)
    .toString(16)
    .toUpperCase()
    .padStart(4, "0");
  return `hash:${body}#${checksum}`;
}

function hex32(byte) {
  return `0x${Buffer.alloc(32, byte).toString("hex")}`;
}

function mutateFirstSignedTransactionSignatureByte(signedTransaction) {
  const bytes = Buffer.from(signedTransaction);
  assert.equal(
    bytes[0],
    1,
    "signed transaction fixture must be VersionedSignedTransaction V1",
  );
  const versionedPayloadOffset = 1;

  const readCompactLength = (offset) => {
    let value = 0;
    let shift = 0;
    for (let index = 0; index < 10; index += 1) {
      const byte = bytes[offset + index];
      assert.notEqual(byte, undefined, "compact length must not be truncated");
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) {
        assert.ok(Number.isSafeInteger(value), "compact length must be safe");
        return { next: offset + index + 1, value };
      }
      shift += 7;
    }
    throw new Error("compact length must terminate within 10 bytes");
  };

  const signatureField = readCompactLength(versionedPayloadOffset);
  const signaturePayload = readCompactLength(signatureField.next);
  assert.ok(
    signaturePayload.next + signaturePayload.value <= bytes.length,
    "signature payload must fit in the transaction",
  );
  assert.equal(
    bytes.readBigUInt64LE(signaturePayload.next),
    64n,
    "fixture must contain one 64-byte Ed25519 signature",
  );
  const firstSignatureByte = readCompactLength(signaturePayload.next + 8);
  assert.equal(firstSignatureByte.value, 1, "signature byte field must contain one byte");
  bytes[firstSignatureByte.next] ^= 0x80;
  return bytes;
}

function toByteArray(bytes) {
  return Array.from(Buffer.from(bytes));
}

function buildSampleRegisterDomain(additionalOptions = {}) {
  return buildRegisterDomainTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    domainId: "garden_of_live_flowers.sora",
    metadata: { key: "value" },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 5_000,
    nonce: 42,
    privateKey: PRIVATE_KEY,
    ...additionalOptions,
  });
}

test("buildRegisterDomainTransaction returns canonical hash", () => {
  const built = buildSampleRegisterDomain();
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  assert.equal(built.signedTransaction[0], 1);
  assert.ok(Buffer.isBuffer(built.hash));
  assert.equal(built.hash.length, 32);

  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("hashSignedTransactionPayload returns the detached scaffold preimage", () => {
  const first = buildSampleRegisterDomain();
  const signatureMutated = mutateFirstSignedTransactionSignatureByte(
    first.signedTransaction,
  );
  const firstPayloadHash = hashSignedTransactionPayload(
    first.signedTransaction,
    { encoding: "buffer" },
  );
  const secondPayloadHash = hashSignedTransactionPayload(
    signatureMutated,
    { encoding: "buffer" },
  );

  assert.equal(firstPayloadHash.length, 32);
  assert.deepEqual(firstPayloadHash, secondPayloadHash);
  assert.deepEqual(
    hashSignedTransaction(first.signedTransaction, { encoding: "buffer" }),
    hashSignedTransaction(signatureMutated, { encoding: "buffer" }),
  );
});

test("hashInstructionBatch binds a settlement batch to its source marker", () => {
  const transfer = buildTransferAssetInstruction({
    sourceAssetHoldingId: CANONICAL_ASSET_ID_INPUT,
    quantity: "2800",
    destinationAccountId: RELAY_ACCOUNT_ID_INPUT,
  });
  const batchFor = (sourceTxHash) => [
    buildSetAccountKeyValueInstruction({
      accountId: AUTHORITY_ID_INPUT,
      key: `pk_cbuae_settlement_${sourceTxHash}`,
      value: {
        protocol: "pk-cbuae-settlement",
        version: 1,
        source_tx_hash: sourceTxHash,
      },
    }),
    transfer,
  ];
  const first = hashInstructionBatch(batchFor("a".repeat(64)), 753, {
    encoding: "buffer",
  });
  const second = hashInstructionBatch(batchFor("b".repeat(64)), 753, {
    encoding: "buffer",
  });

  assert.equal(first.length, 32);
  assert.equal(second.length, 32);
  assert.notDeepEqual(first, second);
});

test("buildRegisterDomainTransaction accepts metadata JSON strings", () => {
  const built = buildSampleRegisterDomain({
    metadata: JSON.stringify({ foo: "bar" }),
  });
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("buildTransaction normalizes instruction objects", () => {
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID_INPUT,
    quantity: "2",
  });
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x01, 0x02]),
    hash: Buffer.alloc(32, 0xaa),
  };

  withTransactionApi(
    {
      buildTransaction: (
        networkId,
        authority,
        instructions,
        feePaymentJson,
        metadataPayload,
        creationTimeMs,
        ttlMs,
        nonce,
        secret,
        privateKeyAlgorithm,
      ) => {
        captures.push({
          networkId,
          authority,
          instructions,
          feePaymentJson,
          metadataPayload,
          creationTimeMs,
          ttlMs,
          nonce,
          secret,
          privateKeyAlgorithm,
        });
        return fakeResult;
      },
    },
    (transaction) => {
      const built = transaction.buildTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        instructions: [instruction],
        metadata: { tag: "value" },
        creationTimeMs: 10,
        ttlMs: 20,
        nonce: 5,
        privateKey: PRIVATE_KEY,
        privateKeyAlgorithm: "secp256k1",
      });
      assert.deepEqual(
        built.signedTransaction,
        Buffer.from(fakeResult.signed_transaction),
      );
      assert.deepEqual(built.hash, Buffer.from(fakeResult.hash));
    },
  );

  assert.equal(captures.length, 1);
  const call = captures[0];
  assert.deepEqual(Buffer.from(call.networkId), NETWORK_ID_BYTES);
  assert.equal(call.authority, AUTHORITY_ID);
  assert.deepEqual(call.instructions, [JSON.stringify(instruction)]);
  assert.deepEqual(JSON.parse(call.feePaymentJson), {
    payer: "authority",
    value: { charge_limits: [], gas_limit: null },
  });
  assert.equal(call.metadataPayload, JSON.stringify({ tag: "value" }));
  assert.equal(call.creationTimeMs, 10);
  assert.equal(call.ttlMs, 20);
  assert.equal(call.nonce, 5);
  assert.equal(call.privateKeyAlgorithm, "secp256k1");
});

test("mixed executable batch builder forwards ordered copied entries", () => {
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID_INPUT,
    quantity: "2",
  });
  const expectedCodeHash = Buffer.alloc(32, 0x41);
  const argumentsBytes = Uint8Array.from([0x4b, 0x4f, 0x54, 0x4f]);
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x04, 0x01]),
    hash: Buffer.alloc(32, 0xab),
  };
  withTransactionApi(
    {
      buildExecutableBatchTransaction: (...args) => {
        captures.push(args);
        return fakeResult;
      },
    },
    (transaction) => {
      const result = transaction.buildExecutableBatchTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        entries: [
          { kind: "instruction", instruction },
          {
            kind: "contractCall",
            contractAddress:
              "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
            expectedCodeHash,
            entrypoint: "run",
            arguments: argumentsBytes,
          },
          { kind: "instruction", instruction },
        ],
        feePayment: IVM_AUTHORITY_FEE_PAYMENT,
        privateKey: PRIVATE_KEY,
      });
      assert.deepEqual(result.signedTransaction, fakeResult.signed_transaction);
      assert.deepEqual(result.hash, fakeResult.hash);
    },
  );
  expectedCodeHash.fill(0);
  argumentsBytes.fill(0);

  assert.equal(captures.length, 1);
  const entries = captures[0][2].map((entry) => JSON.parse(entry));
  assert.deepEqual(entries.map(({ kind }) => kind), [
    "instruction",
    "contractCall",
    "instruction",
  ]);
  assert.equal(entries[1].expectedCodeHash, "41".repeat(32).toUpperCase());
  assert.deepEqual(entries[1].arguments, [0x4b, 0x4f, 0x54, 0x4f]);
  assert.equal(JSON.parse(captures[0][3]).value.gas_limit, 1000);
});

test("mixed executable batch draft and validation reject missing requirements", () => {
  const call = {
    kind: "contractCall",
    contractAddress:
      "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
    expectedCodeHash: Buffer.alloc(32, 0x41),
    entrypoint: "run",
  };
  withTransactionApi(
    {
      buildExecutableBatchTransactionPayload: (...args) => ({
        payload_json: JSON.stringify({ instructions: { Batch: [] } }),
        payload_bytes: Buffer.from([4]),
        payload_hash: Buffer.alloc(32, 5),
        args,
      }),
    },
    (transaction) => {
      assert.throws(
        () =>
          transaction.buildExecutableBatchTransactionPayload({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            entries: [call],
            feePayment: AUTHORITY_FEE_PAYMENT,
          }),
        /gasLimit is required/u,
      );
      assert.throws(
        () =>
          transaction.buildExecutableBatchTransactionPayload({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            entries: [],
            feePayment: IVM_AUTHORITY_FEE_PAYMENT,
          }),
        /non-empty array/u,
      );
      assert.throws(
        () =>
          transaction.buildExecutableBatchTransactionPayload({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            entries: [{ ...call, expectedCodeHash: Buffer.alloc(31) }],
            feePayment: IVM_AUTHORITY_FEE_PAYMENT,
          }),
        /exactly 32 bytes/u,
      );
      for (const contractAddress of [
        "abc",
        call.contractAddress.toUpperCase(),
        `${call.contractAddress.slice(0, -1)}p`,
        "irohac1qyqqqqqqqqqqqzgfpg9scrgwpugpzysnzs23v9ccrydpk8q7ca9ly",
        "irohac1qgqqqqqqqqqqqzgfpg9scrgwpugpzysnzs23v9ccrydpk8qhk43nl",
      ]) {
        assert.throws(
          () =>
            transaction.buildExecutableBatchTransactionPayload({
              networkId: NETWORK_ID,
              authority: AUTHORITY_ID_INPUT,
              entries: [{ ...call, contractAddress }],
              feePayment: IVM_AUTHORITY_FEE_PAYMENT,
            }),
          /contractAddress/u,
        );
      }
    },
  );
});

test("quote-to-sign helpers preserve the exact unsigned payload", () => {
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID_INPUT,
    quantity: "2",
  });
  const payload = {
    domain: { kind: "network", value: NETWORK_ID.literal },
    authority: AUTHORITY_ID,
    creation_time_ms: 10,
    instructions: { Instructions: [instruction] },
    time_to_live_ms: 20,
    nonce: 5,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
    metadata: {},
  };
  const payloadJson = JSON.stringify(payload);
  const draftCaptures = [];
  const signCaptures = [];
  withTransactionApi(
    {
      buildTransactionPayload: (...args) => {
        draftCaptures.push(args);
        return {
          payload_json: payloadJson,
          payload_bytes: Buffer.from([0x10, 0x11]),
          payload_hash: Buffer.alloc(32, 0x12),
        };
      },
      signQuotedTransactionPayload: (...args) => {
        signCaptures.push(args);
        return {
          signed_transaction: Buffer.from([0x20, 0x21]),
          hash: Buffer.alloc(32, 0x22),
        };
      },
    },
    (transaction) => {
      const draft = transaction.buildTransactionPayload({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        instructions: [instruction],
        feePayment: AUTHORITY_FEE_PAYMENT,
        metadata: {},
        creationTimeMs: 10,
        ttlMs: 20,
        nonce: 5,
      });
      assert.deepEqual(draft.payload, payload);
      assert.equal(draft.payloadJson, payloadJson);
      const quotedIntent = {
        payer: "authority",
        value: {
          charge_limits: [
            {
              kind: { kind: "nexus", value: null },
              asset_definition_id: ASSET_DEFINITION_ID,
              max_amount: "3",
            },
          ],
          gas_limit: null,
        },
      };
      const signed = transaction.signQuotedTransactionPayload({
        networkId: NETWORK_ID,
        payload: draft,
        quotedFeePayment: quotedIntent,
        privateKey: PRIVATE_KEY,
        privateKeyAlgorithm: "ed25519",
      });
      assert.deepEqual(signed.signedTransaction, Buffer.from([0x20, 0x21]));
      assert.deepEqual(signed.hash, Buffer.alloc(32, 0x22));
      assert.deepEqual(Buffer.from(signCaptures[0][0]), NETWORK_ID_BYTES);
      assert.equal(signCaptures[0][1], payloadJson);
      assert.deepEqual(JSON.parse(signCaptures[0][2]), quotedIntent);
    },
  );
  assert.equal(draftCaptures.length, 1);
  assert.deepEqual(Buffer.from(draftCaptures[0][0]), NETWORK_ID_BYTES);
  assert.equal(draftCaptures[0][1], AUTHORITY_ID);
  assert.deepEqual(draftCaptures[0][2], [JSON.stringify(instruction)]);
});

test("quoteAndSignTransaction performs the guided exact-payload flow", async () => {
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID_INPUT,
    quantity: "1",
  });
  const payload = {
    domain: { kind: "network", value: NETWORK_ID.literal },
    authority: AUTHORITY_ID,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const quotedIntent = {
    payer: "authority",
    value: {
      charge_limits: [
        {
          kind: { kind: "nexus", value: null },
          asset_definition_id: ASSET_DEFINITION_ID,
          max_amount: "1",
        },
      ],
      gas_limit: null,
    },
  };
  const calls = [];
  await withTransactionApi(
    {
      buildTransactionPayload: () => ({
        payload_json: JSON.stringify(payload),
        payload_bytes: Buffer.from([1]),
        payload_hash: Buffer.alloc(32, 2),
      }),
      signQuotedTransactionPayload: (...args) => {
        calls.push(["sign", ...args]);
        return {
          signed_transaction: Buffer.from([3]),
          hash: Buffer.alloc(32, 4),
        };
      },
    },
    async (transaction) => {
      const client = {
        async quoteFees(draft, options) {
          calls.push(["quote", draft, options]);
          return acceptedAuthorityFeeQuote(payload, quotedIntent);
        },
      };
      const result = await transaction.quoteAndSignTransaction(client, {
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        instructions: [instruction],
        feePayment: AUTHORITY_FEE_PAYMENT,
        privateKey: PRIVATE_KEY,
      });
      assert.deepEqual(result.signedTransaction, Buffer.from([3]));
      assert.deepEqual(result.quote.intent, quotedIntent);
    },
  );
  assert.equal(calls[0][0], "quote");
  assert.equal(calls[0][2].canonicalAuth.accountId, AUTHORITY_ID_INPUT);
  assert.equal(calls[1][0], "sign");
  assert.deepEqual(Buffer.from(calls[1][1]), NETWORK_ID_BYTES);
  assert.equal(calls[1][2], JSON.stringify(payload));
  assert.deepEqual(JSON.parse(calls[1][3]), quotedIntent);
});

baseTest("quoteAndSignTransaction rejects an unbound injectable-client quote before signing", async () => {
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID_INPUT,
    quantity: "1",
  });
  const payload = {
    domain: { kind: "network", value: NETWORK_ID.literal },
    authority: AUTHORITY_ID,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  let signCalls = 0;
  await withTransactionApi(
    {
      buildTransactionPayload: () => ({
        payload_json: JSON.stringify(payload),
        payload_bytes: Buffer.from([1]),
        payload_hash: Buffer.alloc(32, 2),
      }),
      signQuotedTransactionPayload: () => {
        signCalls += 1;
        return {
          signed_transaction: Buffer.from([3]),
          hash: Buffer.alloc(32, 4),
        };
      },
    },
    async (transaction) => {
      const invalidQuote = acceptedAuthorityFeeQuote(payload);
      invalidQuote.observation.next_block_height = 0;
      await assert.rejects(
        () => transaction.quoteAndSignTransaction(
          { async quoteFees() { return invalidQuote; } },
          {
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            instructions: [instruction],
            feePayment: AUTHORITY_FEE_PAYMENT,
            privateKey: PRIVATE_KEY,
          },
        ),
        /next_block_height/u,
      );
    },
  );
  assert.equal(signCalls, 0);
});

baseTest("quoted transaction signers require one nominal NetworkId", () => {
  let nativeCalls = 0;
  const binding = {
    signQuotedTransactionPayload() {
      nativeCalls += 1;
      throw new Error("native signer must not run");
    },
    signQuotedIvmProvedTransactionPayload() {
      nativeCalls += 1;
      throw new Error("native signer must not run");
    },
  };
  withTransactionApi(binding, (transaction) => {
    for (const signer of [
      (networkInput) =>
        transaction.signQuotedTransactionPayload({
          ...networkInput,
          payload: {},
          quotedFeePayment: AUTHORITY_FEE_PAYMENT,
          privateKey: PRIVATE_KEY,
        }),
      (networkInput) =>
        transaction.signQuotedIvmProvedTransactionPayload({
          ...networkInput,
          payload: {},
          attachment: {},
          quotedFeePayment: AUTHORITY_FEE_PAYMENT,
          privateKey: PRIVATE_KEY,
        }),
    ]) {
      assert.throws(
        () => signer({ networkId: NETWORK_ID.literal }),
        /input\.networkId must be a NetworkId/u,
      );
      for (const retired of ["chain", "chainId", "chain_id"]) {
        assert.throws(
          () => signer({ networkId: NETWORK_ID, [retired]: "retired" }),
          /is unsupported; provide the nominal networkId field/u,
        );
      }
    }
  });
  assert.equal(nativeCalls, 0);
});

baseTest("buildRegisterPinManifestInstruction binds the canonical pin fields", () => {
  const successor = Buffer.alloc(32, 0x44);
  const instruction = buildRegisterPinManifestInstruction({
    manifestPayload: Buffer.from("manifest"),
    alias: {
      namespace: "docs",
      name: "main",
      proof: Buffer.from("alias-proof"),
    },
    successorOf: successor,
  });

  assert.deepEqual(instruction, {
    RegisterPinManifest: {
      manifest_payload: Buffer.from("manifest").toString("base64"),
      alias: {
        namespace: "docs",
        name: "main",
        proof: Buffer.from("alias-proof").toString("base64"),
      },
      successor_of: [...successor],
    },
  });
  assert.throws(
    () =>
      buildRegisterPinManifestInstruction({
        manifestPayload: Buffer.alloc(0),
      }),
    /manifestPayload must contain/,
  );
  assert.throws(
    () =>
      buildRegisterPinManifestInstruction({
        manifestPayload: Buffer.from("manifest"),
        successorOf: Buffer.alloc(32),
      }),
    /32 non-zero bytes/,
  );
  for (const retiredField of ["submittedEpoch", "submitted_epoch"]) {
    assert.throws(
      () =>
        buildRegisterPinManifestInstruction({
          manifestPayload: Buffer.from("manifest"),
          [retiredField]: 42,
        }),
      /no longer accepts a submitted epoch/,
    );
  }
});

baseTest("buildRegisterPinManifestTransaction rejects a retired submitted epoch", () => {
  assert.throws(
    () =>
      buildRegisterPinManifestTransaction(null, {
        manifestPayload: Buffer.from("manifest"),
        submittedEpoch: 42,
      }),
    /no longer accepts a submitted epoch/,
  );
});

test("buildRegisterPinManifestTransaction quotes and signs exactly one instruction", async () => {
  const draftCalls = [];
  const payload = {
    domain: { kind: "network", value: NETWORK_ID.literal },
    authority: AUTHORITY_ID,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const quotedIntent = payload.fee_payment;
  await withTransactionApi(
    {
      buildTransactionPayload: (...args) => {
        draftCalls.push(args);
        return {
          payload_json: JSON.stringify(payload),
          payload_bytes: Buffer.from([1]),
          payload_hash: Buffer.alloc(32, 2),
        };
      },
      signQuotedTransactionPayload: () => ({
        signed_transaction: Buffer.from([3]),
        hash: Buffer.alloc(32, 4),
      }),
    },
    async (transaction) => {
      const client = {
        async quoteFees() {
          return acceptedAuthorityFeeQuote(payload, quotedIntent);
        },
      };
      const result = await transaction.buildRegisterPinManifestTransaction(client, {
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        privateKey: PRIVATE_KEY,
        manifestPayload: Buffer.from("manifest"),
      });
      assert.deepEqual(result.signedTransaction, Buffer.from([3]));
    },
  );

  assert.equal(draftCalls.length, 1);
  assert.equal(draftCalls[0][2].length, 1);
  assert.deepEqual(JSON.parse(draftCalls[0][2][0]), {
    RegisterPinManifest: {
      manifest_payload: Buffer.from("manifest").toString("base64"),
      alias: null,
      successor_of: null,
    },
  });

});

test("proved-IVM quote draft preserves the proof attachment through signing", () => {
  const payload = {
    domain: { kind: "network", value: NETWORK_ID.literal },
    authority: AUTHORITY_ID,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: 5000 },
    },
  };
  const proved = { bytecode: "TlJUMAAAAA==", overlay: [] };
  const attachment = {
    backend: "pipa-r/pasta",
    proof: { backend: "pipa-r/pasta", bytes: [1, 2, 3] },
    vk_ref: { backend: "pipa-r/pasta", name: "ivm-exec-v1" },
  };
  const calls = [];
  withTransactionApi(
    {
      buildIvmProvedTransactionPayload: (...args) => {
        calls.push(["draft", ...args]);
        return {
          payload_json: JSON.stringify(payload),
          payload_bytes: Buffer.from([0x10]),
          payload_hash: Buffer.alloc(32, 0x11),
        };
      },
      signQuotedIvmProvedTransactionPayload: (...args) => {
        calls.push(["sign", ...args]);
        return {
          signed_transaction: Buffer.from([0x20]),
          hash: Buffer.alloc(32, 0x21),
        };
      },
    },
    (transaction) => {
      const draft = transaction.buildIvmProvedTransactionPayload({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        proved,
        attachment,
        feePayment: {
          ...AUTHORITY_FEE_PAYMENT,
          gasLimit: 5000,
        },
      });
      const signed = transaction.signQuotedIvmProvedTransactionPayload({
        networkId: NETWORK_ID,
        payload: draft,
        quotedFeePayment: payload.fee_payment,
        privateKey: PRIVATE_KEY,
      });
      assert.deepEqual(draft.attachment, attachment);
      assert.equal(draft.attachmentJson, JSON.stringify(attachment));
      assert.deepEqual(signed.signedTransaction, Buffer.from([0x20]));
    },
  );
  assert.equal(calls[0][0], "draft");
  assert.equal(calls[1][0], "sign");
  assert.deepEqual(Buffer.from(calls[1][1]), NETWORK_ID_BYTES);
  assert.equal(calls[1][2], JSON.stringify(payload));
  assert.equal(calls[1][3], JSON.stringify(attachment));
  assert.deepEqual(JSON.parse(calls[1][4]), payload.fee_payment);
});

test("feePaymentIntentToNoritoJson binds exact sponsor revision and limits", () => {
  const programId = `${AUTHORITY_ID_INPUT}/wallet-onboarding`;
  const parsed = JSON.parse(
    feePaymentIntentToNoritoJson({
      payer: "sponsor",
      programId,
      programRevision: "7",
      chargeLimits: [
        {
          kind: "nexus",
          assetDefinitionId: ASSET_DEFINITION_ID,
          maxAmount: "1.25",
        },
      ],
      gasLimit: "5000",
    }),
  );
  assert.deepEqual(parsed, {
    payer: "sponsor",
    value: {
      program_id: {
        sponsor: AUTHORITY_ID_INPUT,
        name: "wallet-onboarding",
      },
      program_revision: 7,
      charge_limits: [
        {
          kind: { kind: "nexus", value: null },
          asset_definition_id: ASSET_DEFINITION_ID,
          max_amount: "1.25",
        },
      ],
      gas_limit: 5000,
    },
  });
});

test("buildTransaction requires an explicit fee payment intent", () => {
  withTransactionApi(
    {
      buildTransaction: () => {
        throw new Error("native builder should not be called");
      },
    },
    (transaction) => {
      assert.throws(
        () =>
          transaction.buildTransaction({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            instructions: [{ Log: { level: "INFO", message: "hello" } }],
            privateKey: PRIVATE_KEY,
          }),
        /feePayment must be a non-null object/i,
      );
    },
  );
});

test("transaction helper wrappers forward privateKeyAlgorithm", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x03, 0x04]),
    hash: Buffer.alloc(32, 0xbb),
  };

  withTransactionApi(
    {
      buildTransaction: (
        _chainId,
        _authority,
        _instructions,
        _feePaymentJson,
        _metadataPayload,
        _creationTimeMs,
        _ttlMs,
        _nonce,
        _secret,
        privateKeyAlgorithm,
      ) => {
        captures.push(privateKeyAlgorithm);
        return fakeResult;
      },
    },
    (transaction) => {
      transaction.buildMintAssetTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        assetHoldingId: ASSET_ID_INPUT,
        quantity: "2",
        privateKey: PRIVATE_KEY,
        privateKeyAlgorithm: "secp256k1",
      });
    },
  );

  assert.deepEqual(captures, ["secp256k1"]);
});

test("transaction helper wrappers do not omit privateKeyAlgorithm forwarding", () => {
  const source = readFileSync(
    new URL("../src/transaction.js", import.meta.url),
    "utf8",
  );
  assert.equal(
    /privateKey,\n\s*\}\);/u.test(source),
    false,
    "a buildTransaction call forwards privateKey but not privateKeyAlgorithm",
  );
  assert.equal(
    /privateKey,\n\}\) \{/u.test(source),
    false,
    "a transaction helper accepts privateKey without privateKeyAlgorithm",
  );
});

test("buildTransaction rejects empty instruction arrays", () => {
  assert.throws(
    () =>
      buildTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        instructions: [],
        privateKey: PRIVATE_KEY,
      }),
    /non-empty array/i,
  );
});

 test("buildIvmProvedTransaction normalizes proved executable and attachment", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x03, 0x04]),
    hash: Buffer.alloc(32, 0xbb),
  };
  const proved = {
    bytecode: ZK_IVM_BYTECODE_BASE64,
    overlay: [],
    events_commitment: normalizedHashHex(Buffer.alloc(32, 0x01)),
    gas_policy_commitment: normalizedHashHex(Buffer.alloc(32, 0x02)),
  };
  const attachment = {
    backend: "pipa-r/pasta",
    proof: {
      backend: "pipa-r/pasta",
      bytes: [1, 2, 3],
    },
    vk_ref: {
      backend: "pipa-r/pasta",
      name: "ivm-exec-v1",
    },
  };

  withTransactionApi(
    {
      buildIvmProvedTransaction: (
        networkId,
        authority,
        provedPayload,
        attachmentPayload,
        feePaymentJson,
        metadataPayload,
        creationTimeMs,
        ttlMs,
        nonce,
        secret,
      ) => {
        captures.push({
          networkId,
          authority,
          provedPayload,
          attachmentPayload,
          feePaymentJson,
          metadataPayload,
          creationTimeMs,
          ttlMs,
          nonce,
          secret,
        });
        return fakeResult;
      },
    },
    (transaction) => {
      const built = transaction.buildIvmProvedTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: IVM_AUTHORITY_FEE_PAYMENT,
        proved,
        attachment,
        metadata: { purpose: "proof-test" },
        creationTimeMs: 10,
        ttlMs: 20,
        nonce: 5,
        privateKey: PRIVATE_KEY,
      });
      assert.deepEqual(
        built.signedTransaction,
        Buffer.from(fakeResult.signed_transaction),
      );
      assert.deepEqual(built.hash, Buffer.from(fakeResult.hash));
    },
  );

  assert.equal(captures.length, 1);
  const call = captures[0];
  assert.deepEqual(Buffer.from(call.networkId), NETWORK_ID_BYTES);
  assert.equal(call.authority, AUTHORITY_ID);
  assert.deepEqual(JSON.parse(call.provedPayload), proved);
  assert.deepEqual(JSON.parse(call.attachmentPayload), attachment);
  assert.equal(JSON.parse(call.feePaymentJson).value.gas_limit, 1_000);
  assert.equal(call.metadataPayload, JSON.stringify({ purpose: "proof-test" }));
  assert.equal(call.creationTimeMs, 10);
  assert.equal(call.ttlMs, 20);
  assert.equal(call.nonce, 5);
});

test("buildIvmProvedTransaction rejects empty proved payload strings", () => {
  withTransactionApi(
    {
      buildIvmProvedTransaction: () => {
        throw new Error("native builder should not be called");
      },
    },
    (transaction) => {
      assert.throws(
        () =>
          transaction.buildIvmProvedTransaction({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            feePayment: IVM_AUTHORITY_FEE_PAYMENT,
            proved: " ",
            attachment: {},
            privateKey: PRIVATE_KEY,
          }),
        /proved must not be an empty JSON string/i,
      );
    },
  );
});

test("buildMintAssetTransaction returns canonical hash", () => {
  const built = buildMintAssetTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    assetId: CANONICAL_ASSET_ID_INPUT,
    quantity: "10",
    privateKey: PRIVATE_KEY,
  });
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("buildTransferAssetTransaction returns canonical hash", () => {
  const built = buildTransferAssetTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    sourceAssetId: CANONICAL_ASSET_ID_INPUT,
    quantity: "3",
    destinationAccountId: AUTHORITY_ID_INPUT,
    privateKey: PRIVATE_KEY,
  });
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("buildTransferRwaTransaction returns canonical hash", () => {
  const built = buildTransferRwaTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    sourceAccountId: AUTHORITY_ID_INPUT,
    rwaId: RWA_ID,
    quantity: "3",
    destinationAccountId: AUTHORITY_ID_INPUT,
    privateKey: PRIVATE_KEY,
  });
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

baseTest("transaction builders reject padded authority and asset definition IDs before native dispatch", () => {
  const calls = [];
  withTransactionApi(
    {
      buildTransaction: () => {
        calls.push("buildTransaction");
        return {
          signed_transaction: Buffer.from([0x47]),
          hash: Buffer.alloc(32, 0x47),
        };
      },
    },
    (transaction) => {
      assert.throws(
        () =>
          transaction.buildTransaction({
            networkId: NETWORK_ID,
            authority: ` ${AUTHORITY_ID_INPUT}`,
            feePayment: AUTHORITY_FEE_PAYMENT,
            instructions: [{ RegisterDomain: { id: "wonderland" } }],
            privateKey: PRIVATE_KEY,
          }),
        /authority must not contain surrounding whitespace/u,
      );
      assert.throws(
        () =>
          transaction.buildRegisterAssetDefinitionAndMintTransaction({
            networkId: NETWORK_ID,
            authority: AUTHORITY_ID_INPUT,
            feePayment: AUTHORITY_FEE_PAYMENT,
            assetDefinition: {
              assetDefinitionId: `${ASSET_DEFINITION_ID} `,
              name: "Rose",
              owningDomain: null,
              balanceScopePolicy: "Global",
              spec: { scale: 0 },
            },
            privateKey: PRIVATE_KEY,
          }),
        /assetDefinition\.assetDefinitionId must not contain surrounding whitespace/u,
      );
    },
  );
  assert.deepEqual(calls, []);
});

test("buildRegisterRwaTransaction forwards canonical instruction payload", () => {
  const captures = [];
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((json) => JSON.parse(json)),
        });
        return {
          signed_transaction: Buffer.from([0x44]),
          hash: Buffer.alloc(32, 0xdd),
        };
      },
    },
    (transaction) =>
      transaction.buildRegisterRwaTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        rwa: {
          domain: "commodities.sora",
          quantity: "10.5",
          spec: { scale: 1 },
          primaryReference: "vault-cert-001",
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  assert.equal(captures[0].authority, AUTHORITY_ID);
  assert.deepEqual(captures[0].instructions[0], {
    RegisterRwa: {
      rwa: {
        domain: "commodities.sora",
        quantity: "10.5",
        spec: { scale: 1 },
        primary_reference: "vault-cert-001",
        status: null,
        metadata: {},
        parents: [],
        controls: {
          controller_accounts: [],
          controller_roles: [],
          freeze_enabled: false,
          hold_enabled: false,
          force_transfer_enabled: false,
          redeem_enabled: false,
        },
      },
    },
  });
});

test("buildRwaKeyValueTransactions forward canonical instruction payloads", () => {
  const captures = [];
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((json) => JSON.parse(json)),
        });
        return {
          signed_transaction: Buffer.from([0x45]),
          hash: Buffer.alloc(32, 0xee),
        };
      },
    },
    (transaction) => {
      transaction.buildSetRwaKeyValueTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        rwaId: RWA_ID,
        key: "grade",
        value: { origin: "AE", score: BigInt(9) },
        privateKey: PRIVATE_KEY,
      });
      transaction.buildRemoveRwaKeyValueTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        rwaId: RWA_ID,
        key: "grade",
        privateKey: PRIVATE_KEY,
      });
    },
  );
  assert.equal(captures.length, 2);
  assert.equal(captures[0].authority, AUTHORITY_ID);
  assert.deepEqual(captures[0].instructions[0], {
    SetRwaKeyValue: {
      rwa: RWA_ID,
      key: "grade",
      value: { origin: "AE", score: "9" },
    },
  });
  assert.deepEqual(captures[1].instructions[0], {
    RemoveRwaKeyValue: {
      rwa: RWA_ID,
      key: "grade",
    },
  });
});

test("buildMintAndTransferTransaction composes instructions in order", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x10, 0x20]),
    hash: Buffer.alloc(32, 0xbb),
  };
  withTransactionApi(
    {
      buildTransaction: (_, __, instructions) => {
        captures.push(instructions.map((payload) => JSON.parse(payload)));
        return fakeResult;
      },
    },
    (transaction) => {
      const result = transaction.buildMintAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        mint: { assetId: ASSET_ID_INPUT, quantity: "6" },
        transfer: {
          quantity: "2",
          destinationAccountId: AUTHORITY_ID_INPUT,
        },
        privateKey: PRIVATE_KEY,
      });
      assert.deepEqual(result.hash, Buffer.from(fakeResult.hash));
    },
  );
  assert.equal(captures.length, 1);
  const [mintInstruction, transferInstruction] = captures[0];
  assert.deepEqual(mintInstruction, {
    Mint: { Asset: { destination: ASSET_ID, object: "6" } },
  });
  assert.deepEqual(transferInstruction, {
    Transfer: {
      Asset: {
        source: ASSET_ID,
        object: "2",
        destination: AUTHORITY_ID,
      },
    },
  });
});

test("buildRegisterDomainAndMintTransaction supports mint arrays", () => {
  const captures = [];
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((j) => JSON.parse(j)),
        });
        return {
          signed_transaction: Buffer.from([0x30]),
          hash: Buffer.alloc(32, 0xcc),
        };
      },
    },
    (transaction) =>
      transaction.buildRegisterDomainAndMintTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        domain: { domainId: "wonderland.sora" },
        mints: [
          { assetId: ASSET_ID_INPUT, quantity: "4" },
          { assetId: CANONICAL_LILY_ASSET_ID_INPUT, quantity: "1" },
        ],
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const [{ instructions }] = captures;
  assert.equal(instructions.length, 3);
  assert.deepEqual(
    instructions[0],
    buildRegisterDomainInstruction({ domainId: "wonderland.sora" }),
  );
  assert.deepEqual(instructions[1], {
    Mint: { Asset: { destination: ASSET_ID, object: "4" } },
  });
  assert.deepEqual(instructions[2], {
    Mint: {
      Asset: {
        destination: CANONICAL_LILY_ASSET_ID_INPUT,
        object: "1",
      },
    },
  });
});

test("buildRegisterAssetDefinitionMintAndTransferTransaction supports transfer arrays", () => {
  const captures = [];
  const secondAccountIdPublicKeyHex =
    "1AA70BFDE38BFD7CBE6AD29E59F290D4A4B0DD02792C0CE7371477C4E0D62759";
  const secondAccountId = i105FromEd25519PublicKeyHex(
    secondAccountIdPublicKeyHex,
  );
  const secondAccountIdInput = i105FromEd25519PublicKeyHex(
    secondAccountIdPublicKeyHex,
  );
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((j) => JSON.parse(j)),
        });
        return {
          signed_transaction: Buffer.from([0x31]),
          hash: Buffer.alloc(32, 0xdd),
        };
      },
    },
    (transaction) =>
      transaction.buildRegisterAssetDefinitionMintAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        assetDefinition: {
          assetDefinitionId: ASSET_DEFINITION_ID,
          name: "Rose",
          owningDomain: null,
          balanceScopePolicy: "Global",
        },
        mints: [
          { assetId: CANONICAL_ASSET_ID_INPUT, quantity: "7" },
          { assetId: SECOND_CANONICAL_ASSET_ID_INPUT, quantity: "2" },
        ],
        transfers: [
          { quantity: "5", destinationAccountId: AUTHORITY_ID_INPUT },
          {
            sourceAssetId: SECOND_CANONICAL_ASSET_ID_INPUT,
            quantity: "1",
            destinationAccountId: secondAccountIdInput,
          },
        ],
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const [{ instructions }] = captures;
  assert.equal(instructions.length, 5);
  assert.deepEqual(instructions[1], {
    Mint: {
      Asset: {
        destination: CANONICAL_ASSET_ID_INPUT,
        object: "7",
      },
    },
  });
  assert.deepEqual(instructions[2], {
    Mint: {
      Asset: {
        destination: SECOND_CANONICAL_ASSET_ID_INPUT,
        object: "2",
      },
    },
  });
  assert.deepEqual(instructions[3], {
    Transfer: {
      Asset: {
        source: CANONICAL_ASSET_ID_INPUT,
        object: "5",
        destination: AUTHORITY_ID,
      },
    },
  });
  assert.deepEqual(instructions[4], {
    Transfer: {
      Asset: {
        source: SECOND_CANONICAL_ASSET_ID_INPUT,
        object: "1",
        destination: secondAccountId,
      },
    },
  });
});

test("buildRegisterAssetDefinitionMintAndTransferTransaction derives asset ids from accountId", () => {
  const captures = [];
  withTransactionApi(
    {
      encodeAssetId: encodeAssetIdForKnownAccount,
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((j) => JSON.parse(j)),
        });
        return {
          signed_transaction: Buffer.from([0x32]),
          hash: Buffer.alloc(32, 0xee),
        };
      },
    },
    (transaction) =>
      transaction.buildRegisterAssetDefinitionMintAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        assetDefinition: {
          assetDefinitionId: ASSET_DEFINITION_ID,
          name: "Rose",
          owningDomain: null,
          balanceScopePolicy: "Global",
        },
        mints: [
          {
            accountId: AUTHORITY_ID_INPUT,
            assetId: CANONICAL_ASSET_ID_INPUT,
            quantity: "1",
          },
        ],
        transfers: [
          { quantity: "1", destinationAccountId: AUTHORITY_ID_INPUT },
        ],
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  assert.deepEqual(captures[0].instructions[1], {
    Mint: {
      Asset: {
        destination: CANONICAL_ASSET_ID_INPUT,
        object: "1",
      },
    },
  });
});

test("buildMintAndTransferTransaction returns canonical hash", () => {
  const built = buildMintAndTransferTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    mint: { assetId: CANONICAL_ASSET_ID_INPUT, quantity: "8" },
    transfer: {
      sourceAssetId: CANONICAL_ASSET_ID_INPUT,
      quantity: "3",
      destinationAccountId: AUTHORITY_ID_INPUT,
    },
    privateKey: PRIVATE_KEY,
  });
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("buildRegisterAssetDefinitionMintAndTransferTransaction returns canonical hash", () => {
  const built = buildRegisterAssetDefinitionMintAndTransferTransaction({
    networkId: NETWORK_ID,
    authority: AUTHORITY_ID_INPUT,
    feePayment: AUTHORITY_FEE_PAYMENT,
    assetDefinition: {
      assetDefinitionId: ASSET_DEFINITION_ID,
      name: "Rose",
      owningDomain: null,
      balanceScopePolicy: "Global",
    },
    mint: { assetId: CANONICAL_ASSET_ID_INPUT, quantity: "4" },
    transfer: {
      sourceAssetId: CANONICAL_ASSET_ID_INPUT,
      destinationAccountId: AUTHORITY_ID_INPUT,
      quantity: "1",
    },
    privateKey: PRIVATE_KEY,
  });
  assert.ok(Buffer.isBuffer(built.signedTransaction));
  const recomputed = hashSignedTransaction(built.signedTransaction, {
    encoding: "buffer",
  });
  assert.deepEqual(recomputed, built.hash);
});

test("buildCreateKaigiTransaction composes Kaigi create instruction", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x40]),
    hash: Buffer.alloc(32, 0x55),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildCreateKaigiTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        call: {
          id: { domainId: "wonderland.sora", callName: "weekly-sync" },
          host: AUTHORITY_ID_INPUT,
          gasRatePerMinute: 120,
          relayManifest: {
            expiryMs: 1700111000000,
            hops: [
              {
                relayId: RELAY_ACCOUNT_ID_INPUT,
                hpkePublicKey: Buffer.alloc(32, 0x01),
                weight: 2,
              },
              {
                relayId: AUTHORITY_ID_INPUT,
                hpkePublicKey: Buffer.alloc(32, 0x02),
                weight: 3,
              },
              {
                relayId: THIRD_RELAY_ACCOUNT_ID_INPUT,
                hpkePublicKey: Buffer.alloc(32, 0x03),
                weight: 4,
              },
            ],
          },
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const [{ instructions }] = captures;
  assert.equal(instructions.length, 1);
  const created = instructions[0];
  assert.deepEqual(created.Kaigi.CreateKaigi.call.id, {
    domain_id: "wonderland.sora",
    call_name: "weekly-sync",
  });
  assert.equal(created.Kaigi.CreateKaigi.call.gas_rate_per_minute, 120);
  assert.equal(created.Kaigi.CreateKaigi.call.relay_manifest.hops.length, 3);
  assert.deepEqual(created.Kaigi.CreateKaigi.call.relay_manifest.hops[0], {
    relay_id: RELAY_ACCOUNT_ID,
    hpke_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    weight: 2,
  });
  assert.equal(created.Kaigi.CreateKaigi.commitment, null);
});

test("buildCreateKaigiTransaction preserves privacy artifacts", () => {
  const captures = [];
  const commitment = Buffer.alloc(32, 0x33);
  const nullifier = Buffer.alloc(32, 0x24);
  const proof = Buffer.from([0xfa, 0xce]);
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return {
          signed_transaction: Buffer.from([0x40]),
          hash: Buffer.alloc(32, 0x55),
        };
      },
    },
    (transaction) =>
      transaction.buildCreateKaigiTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        call: {
          id: "wonderland.sora:private-room",
          host: AUTHORITY_ID_INPUT,
          privacyMode: "ZkRosterV1",
          commitment: { commitment },
          nullifier: { digest: nullifier },
          proof,
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  const [{ instructions }] = captures;
  const created = instructions[0].Kaigi.CreateKaigi;
  assert.deepEqual(created.commitment.commitment, Array.from(commitment));
  assert.deepEqual(created.nullifier.digest, Array.from(nullifier));
  assert.equal(created.proof, proof.toString("base64"));
});

test("buildJoinKaigiTransaction normalizes binary fields", () => {
  const commitment = Buffer.alloc(32, 0x17);
  const nullifier = Buffer.alloc(32, 0x22);
  const proof = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x41]),
    hash: Buffer.alloc(32, 0x66),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildJoinKaigiTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        join: {
          callId: "wonderland.sora:weekly-sync",
          participant: AUTHORITY_ID_INPUT,
          commitment: { commitment },
          nullifier: { digest: nullifier },
          proof,
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const [{ instructions }] = captures;
  const joinInstruction = instructions[0].Kaigi.JoinKaigi;
  assert.equal(joinInstruction.participant, AUTHORITY_ID);
  assert.deepEqual(
    joinInstruction.commitment.commitment,
    Array.from(commitment),
  );
  assert.deepEqual(joinInstruction.nullifier.digest, Array.from(nullifier));
  assert.deepEqual(Object.keys(joinInstruction.nullifier), ["digest"]);
  assert.equal(joinInstruction.proof, proof.toString("base64"));
});

test("buildRegisterKaigiRelayTransaction encodes hpke key", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x42]),
    hash: Buffer.alloc(32, 0x77),
  };
  const relayId = RELAY_ACCOUNT_ID;
  const relayIdInput = RELAY_ACCOUNT_ID_INPUT;
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildRegisterKaigiRelayTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        relay: {
          relayId: relayIdInput,
          hpkePublicKey: Buffer.alloc(32, 0xaa),
          bandwidthClass: 6,
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const [{ instructions }] = captures;
  const relayInstruction = instructions[0].Kaigi.RegisterKaigiRelay;
  assert.equal(relayInstruction.relay.relay_id, relayId);
  assert.equal(
    relayInstruction.relay.hpke_public_key,
    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
  );
  assert.equal(relayInstruction.relay.bandwidth_class, 6);
});

test("buildUnregisterKaigiRelayTransaction composes relay retirement", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x42]),
    hash: Buffer.alloc(32, 0x77),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildUnregisterKaigiRelayTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        relayId: RELAY_ACCOUNT_ID_INPUT,
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  assert.equal(
    captures[0].instructions[0].Kaigi.UnregisterKaigiRelay.relay_id,
    RELAY_ACCOUNT_ID,
  );
});

test("buildReportKaigiRelayHealthTransaction composes relay feedback", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x42]),
    hash: Buffer.alloc(32, 0x77),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildReportKaigiRelayHealthTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        report: {
          callId: "wonderland.sora:weekly-sync",
          relayId: RELAY_ACCOUNT_ID_INPUT,
          status: "Unavailable",
          reportedAtMs: 1701123456789,
          notes: "relay timeout",
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const report = captures[0].instructions[0].Kaigi.ReportKaigiRelayHealth;
  assert.deepEqual(report, {
    call_id: {
      domain_id: "wonderland.sora",
      call_name: "weekly-sync",
    },
    relay_id: RELAY_ACCOUNT_ID,
    status: { status: "Unavailable", state: null },
    reported_at_ms: 1701123456789,
    notes: "relay timeout",
  });
});

baseTest("buildProposeDeployContractTransaction wraps proposal", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x10]),
    hash: Buffer.alloc(32, 0x10),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push({
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
        });
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildProposeDeployContractTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        proposal: {
          contractAddress:
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          codeHash: "aa".repeat(32),
          abiHash: "bb".repeat(32),
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures.length, 1);
  const propose = captures[0].instructions[0].ProposeDeployContract;
  assert.equal(Object.hasOwn(propose, "proposal_operator"), false);
  assert.equal(
    propose.contract_address,
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
  );
  assert.equal(propose.code_hash, "aa".repeat(32));
  assert.equal(propose.abi_hash, "bb".repeat(32));
  assert.equal(propose.abi_version, 1);
  assert.equal(Object.hasOwn(propose, "window"), false);
  assert.equal(Object.hasOwn(propose, "mode"), false);
});

baseTest("buildProposeDeployContractTransaction rejects the retired operator field", () => {
  let nativeCalls = 0;
  assert.throws(
    () => withTransactionApi(
      {
        buildTransaction: () => {
          nativeCalls += 1;
          throw new Error("mismatched proposal reached transaction construction");
        },
      },
      (transaction) => transaction.buildProposeDeployContractTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        proposal: {
          proposalOperator: RELAY_ACCOUNT_ID_INPUT,
          contractAddress:
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          codeHash: "aa".repeat(32),
          abiHash: "bb".repeat(32),
        },
        privateKey: PRIVATE_KEY,
      }),
    ),
    /proposalOperator/u,
  );
  assert.equal(nativeCalls, 0);
});

baseTest("buildCastZkBallotTransaction encodes ballot", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x11]),
    hash: Buffer.alloc(32, 0x11),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push(JSON.parse(instructions[0]));
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildCastZkBallotTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        ballot: {
          electionId: "ref-1",
          proof: Buffer.alloc(32, 0x01),
          publicInputs: { direction: "Aye" },
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures[0].CastZkBallot.election_id, "ref-1");
});

test("buildCastPlainBallotTransaction normalizes amount", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x12]),
    hash: Buffer.alloc(32, 0x12),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push(JSON.parse(instructions[0]));
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildCastPlainBallotTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        ballot: {
          referendumId: "ref-2",
          owner: AUTHORITY_ID_INPUT,
          amount: "10",
          durationBlocks: 5,
          direction: "aye",
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.equal(captures[0].CastPlainBallot.direction, 0);
});

test("buildUpdatePlainConvictionTransaction signs one choice-free update", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x12]),
    hash: Buffer.alloc(32, 0x12),
  };
  withTransactionApi(
    {
      buildTransaction: (_chain, authority, instructions) => {
        captures.push(JSON.parse(instructions[0]));
        return fakeResult;
      },
    },
    (transaction) =>
      transaction.buildUpdatePlainConvictionTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        update: {
          referendumId: "ref-2",
          owner: AUTHORITY_ID_INPUT,
          amount: "10",
          durationBlocks: 5,
        },
        privateKey: PRIVATE_KEY,
      }),
  );
  assert.deepEqual(Object.keys(captures[0].UpdatePlainConviction), [
    "referendum_id", "owner", "amount", "duration_blocks",
  ]);
  assert.equal(captures[0].UpdatePlainConviction.amount, "10");
});

test("public ballot transaction and batch serializers retain raw max-u64 duration tokens", () => {
  const maximum = 0xffff_ffff_ffff_ffffn;
  const captures = [];
  const result = { signed_transaction: Buffer.from([0x12]), hash: Buffer.alloc(32, 0x12) };
  withTransactionApi({
    buildTransaction: (_network, _authority, instructions) => {
      captures.push(instructions[0]);
      return result;
    },
    buildExecutableBatchTransaction: (_network, _authority, entries) => {
      captures.push(entries[0]);
      return result;
    },
  }, (transaction) => {
    const shared = {
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      privateKey: PRIVATE_KEY,
    };
    const cast = {
      referendumId: "ref-max-cast",
      owner: AUTHORITY_ID_INPUT,
      amount: "10",
      durationBlocks: maximum,
      direction: "aye",
    };
    const update = {
      referendumId: "ref-max-update",
      owner: AUTHORITY_ID_INPUT,
      amount: "10",
      durationBlocks: maximum.toString(10),
    };
    transaction.buildCastPlainBallotTransaction({ ...shared, ballot: cast });
    transaction.buildUpdatePlainConvictionTransaction({ ...shared, update });
    transaction.buildExecutableBatchTransaction({
      ...shared,
      entries: [{ kind: "instruction", instruction: {
        UpdatePlainConviction: {
          referendum_id: update.referendumId,
          owner: AUTHORITY_ID_INPUT,
          amount: update.amount,
          duration_blocks: maximum,
        },
      } }],
    });
  });
  assert.equal(captures.length, 3);
  for (const serialized of captures) {
    assert.match(serialized, /"duration_blocks":18446744073709551615/u);
    assert.doesNotMatch(serialized, /"duration_blocks":"18446744073709551615"/u);
  }
  assert.match(captures[0], /^\{"CastPlainBallot":/u);
  assert.match(captures[1], /^\{"UpdatePlainConviction":/u);
  assert.match(captures[2], /^\{"kind":"instruction","instruction":\{"UpdatePlainConviction":/u);
});

test("buildRegisterSmartContractCodeTransaction wraps manifest instruction", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x01]),
    hash: Buffer.alloc(32, 0xbb),
  };
  withTransactionApi(
    {
      buildTransaction: (
        networkId,
        authority,
        instructions,
        metadataPayload,
        creationTimeMs,
        ttlMs,
        nonce,
        secret,
      ) => {
        captures.push({
          networkId,
          authority,
          instructions,
          metadataPayload,
          creationTimeMs,
          ttlMs,
          nonce,
          secret,
        });
        return fakeResult;
      },
    },
    (transaction) => {
      const result = transaction.buildRegisterSmartContractCodeTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        artifactId: { dataspaceId: "18446744073709551615", codeHash: Buffer.alloc(32, 0xab) },
        manifest: {
          permissions: [], events: [], enum_types: [],
          codeHash: Buffer.alloc(32, 0xab),
          compilerFingerprint: "rustc",
        },
        privateKey: PRIVATE_KEY,
      });
      assert.ok(Buffer.isBuffer(result.hash));
    },
  );
  assert.equal(captures.length, 1);
  const parsed = JSON.parse(captures[0].instructions[0]);
  assert.equal(parsed.RegisterSmartContractCode.artifact_id.dataspace_id, "18446744073709551615");
  assert.equal(Object.hasOwn(parsed.RegisterSmartContractCode, "code_hash"), false);
  assert.equal(parsed.RegisterSmartContractCode.artifact_id.code_hash, parsed.RegisterSmartContractCode.manifest.code_hash);
  assert.equal(
    parsed.RegisterSmartContractCode.manifest.compiler_fingerprint,
    "rustc",
  );
});

test("buildRegisterSmartContractBytesTransaction encodes code payload", () => {
  const codeBytes = Buffer.from([0xde, 0xad]);
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x02]),
    hash: Buffer.alloc(32, 0xcc),
  };
  withTransactionApi(
    {
      buildTransaction: (
        networkId,
        authority,
        instructions,
        metadataPayload,
        creationTimeMs,
        ttlMs,
        nonce,
        secret,
      ) => {
        captures.push({
          networkId,
          authority,
          instructions,
          metadataPayload,
          creationTimeMs,
          ttlMs,
          nonce,
          secret,
        });
        return fakeResult;
      },
    },
    (transaction) => {
      const result = transaction.buildRegisterSmartContractBytesTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        artifactId: { dataspaceId: "18446744073709551615", codeHash: Buffer.alloc(32, 0xdd) },
        code: codeBytes,
        privateKey: PRIVATE_KEY,
      });
      assert.ok(Buffer.isBuffer(result.signedTransaction));
    },
  );
  const parsed = JSON.parse(captures[0].instructions[0]);
  assert.equal(parsed.RegisterSmartContractBytes.artifact_id.dataspace_id, "18446744073709551615");
  assert.equal(Object.hasOwn(parsed.RegisterSmartContractBytes, "code_hash"), false);
  assert.equal(
    parsed.RegisterSmartContractBytes.code,
    codeBytes.toString("base64"),
  );
});

test("buildRemoveSmartContractBytesTransaction wraps removal payload", () => {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0x04]),
    hash: Buffer.alloc(32, 0xee),
  };
  withTransactionApi(
    {
      buildTransaction: (...args) => {
        captures.push(args[2]);
        return fakeResult;
      },
    },
    (transaction) => {
      transaction.buildRemoveSmartContractBytesTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ID_INPUT,
        feePayment: AUTHORITY_FEE_PAYMENT,
        artifactId: { dataspaceId: "18446744073709551615", codeHash: Buffer.alloc(32, 0xab) },
        reason: "cleanup",
        privateKey: PRIVATE_KEY,
      });
    },
  );
  const parsed = JSON.parse(captures[0][0]);
  assert.equal(parsed.RemoveSmartContractBytes.artifact_id.dataspace_id, "18446744073709551615");
  assert.equal(Object.hasOwn(parsed.RemoveSmartContractBytes, "code_hash"), false);
  assert.equal(parsed.RemoveSmartContractBytes.reason, "cleanup");
});

baseTest("retired generic confidential transaction builders are not exported", () => {
  for (const parts of [["Shi", "eld"], ["Zk", "Transfer"], ["Un", "shield"]]) {
    const exportedName = ["build", parts.join(""), "Transaction"].join("");
    assert.equal(transactionExports[exportedName], undefined, exportedName);
  }
});

test("supported confidential transaction builders wrap expected instruction payloads", () => {
  const proof = {
    backend: "pipa-r/pasta",
    proof: Buffer.from("proof"),
    verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_governance" },
  };
  const register = captureInstructionObject((transaction) =>
    transaction.buildRegisterZkAssetTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      registration: {
        assetDefinitionId: ASSET_DEFINITION_ID,
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(register.zk?.RegisterZkAsset);

  const policy = captureInstructionObject((transaction) =>
    transaction.buildScheduleConfidentialPolicyTransitionTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      transition: {
        assetDefinitionId: ASSET_DEFINITION_ID,
        newMode: "TransparentOnly",
        effectiveHeight: 5,
        transitionId: Buffer.alloc(32, 0xaa),
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(policy.zk?.ScheduleConfidentialPolicyTransition);

  const cancel = captureInstructionObject((transaction) =>
    transaction.buildCancelConfidentialPolicyTransitionTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      cancellation: {
        assetDefinitionId: ASSET_DEFINITION_ID,
        transitionId: Buffer.alloc(32, 0xbb),
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(cancel.zk?.CancelConfidentialPolicyTransition);

  const election = captureInstructionObject((transaction) =>
    transaction.buildCreateElectionTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      election: {
        electionId: "election-1",
        options: 2,
        eligibleRoot: Buffer.alloc(32, 0x05),
        startTs: 1,
        endTs: 2,
        ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
        tallyVerifyingKey: { backend: "pipa-r/pasta", name: "vk_tally" },
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(election.zk?.CreateElection);

  const ballot = captureInstructionObject((transaction) =>
    transaction.buildSubmitBallotTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      ballot: {
        electionId: "election-1",
        ciphertext: Buffer.from("encrypted"),
        ballotProof: proof,
        nullifier: Buffer.alloc(32, 0x06),
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(ballot.zk?.SubmitBallot);

  const finalize = captureInstructionObject((transaction) =>
    transaction.buildFinalizeElectionTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ID_INPUT,
      feePayment: AUTHORITY_FEE_PAYMENT,
      finalization: {
        electionId: "election-1",
        tally: [1n, 0n],
        tallyProof: proof,
      },
      privateKey: PRIVATE_KEY,
    }),
  );
  assert.ok(finalize.zk?.FinalizeElection);
});

function captureInstructionObject(buildFn) {
  const captures = [];
  const fakeResult = {
    signed_transaction: Buffer.from([0xff]),
    hash: Buffer.alloc(32, 0xff),
  };
  withTransactionApi(
    {
      buildTransaction: (
        networkId,
        authority,
        instructions,
        metadataPayload,
        creationTimeMs,
        ttlMs,
        nonce,
        secret,
      ) => {
        captures.push({
          networkId,
          authority,
          instructions: instructions.map((payload) => JSON.parse(payload)),
          metadataPayload,
          creationTimeMs,
          ttlMs,
          nonce,
          secret,
        });
        return fakeResult;
      },
    },
    buildFn,
  );
  return captures[0].instructions[0];
}

function withTransactionApi(binding, fn) {
  return fn(_createTransactionApi(createNativeRuntime(binding)));
}
