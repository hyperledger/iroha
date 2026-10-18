import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import { blake2b256 } from "../src/blake2b.js";
import { buildTransferAssetInstruction } from "../src/instructionBuilders.js";
import { NetworkId } from "../src/networkId.js";
import {
  buildTransactionPayload,
  feePaymentFromQuote,
  feePaymentIntentToNoritoJson,
  finalizeSignedTransaction,
  hashSignedTransaction,
  prepareExternalSignerTransactionPayload,
  transactionPayloadSigningHash,
} from "../src/transaction.js";
import { makeNativeTest } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: [
    "buildTransactionPayload",
    "finalizeSignedTransaction",
    "transactionPayloadSigningHash",
    "hashSignedTransaction",
  ],
});

const PREFIX = 369;
const NETWORK_ID = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
const XOR = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

function keyAccount(seed) {
  const privateKey = new Uint8Array(32).fill(seed);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    accountId: AccountAddress.fromAccount({ publicKey, algorithm: "ed25519" }).toI105(PREFIX),
  };
}
const WALLET = keyAccount(0x21);
const SERVICE = keyAccount(0x22);
const PEER = keyAccount(0x23);

function draftFor(authority, feePayment = { payer: "authority", chargeLimits: [] }) {
  return buildTransactionPayload({
    networkId: NETWORK_ID,
    authority,
    instructions: [
      buildTransferAssetInstruction({
        sourceAssetHoldingId: `${XOR}#${authority}`,
        quantity: "1.5",
        destinationAccountId: PEER.accountId,
      }),
    ],
    feePayment,
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 120_000,
    nonce: 42,
  });
}

test("an externally signed payload hash finalizes to the native transaction hash", () => {
  const draft = draftFor(WALLET.accountId);
  const signingHash = transactionPayloadSigningHash(draft.payloadBytes);
  assert.equal(signingHash.length, 32);
  assert.deepEqual(signingHash, draft.payloadHash);
  const marked = Buffer.from(blake2b256(draft.payloadBytes));
  marked[31] |= 1;
  assert.deepEqual(signingHash, marked);

  const signature = ed25519.sign(signingHash, WALLET.privateKey);
  const finalized = finalizeSignedTransaction({
    networkId: NETWORK_ID,
    payloadBytes: draft.payloadBytes,
    signature,
    publicKey: WALLET.publicKey,
    authority: WALLET.accountId,
  });
  assert.equal(finalized.hash.length, 32);
  assert.equal(finalized.hash.toString("hex"), hashSignedTransaction(finalized.signedTransaction));

  assert.throws(
    () => finalizeSignedTransaction({
      networkId: NETWORK_ID,
      payloadBytes: draft.payloadBytes,
      signature: ed25519.sign(signingHash, SERVICE.privateKey),
      publicKey: SERVICE.publicKey,
      authority: WALLET.accountId,
    }),
    /does not control the transaction authority/u,
  );
  const tampered = Uint8Array.from(signature);
  tampered[0] ^= 1;
  assert.throws(() => finalizeSignedTransaction({
    networkId: NETWORK_ID,
    payloadBytes: draft.payloadBytes,
    signature: tampered,
    publicKey: WALLET.publicKey,
    authority: WALLET.accountId,
  }));
  assert.throws(
    () => finalizeSignedTransaction({
      networkId: NetworkId.fromBytes(Buffer.alloc(32, 0x55)),
      payloadBytes: draft.payloadBytes,
      signature,
      publicKey: WALLET.publicKey,
      authority: WALLET.accountId,
    }),
  );
  assert.throws(
    () => finalizeSignedTransaction({
      networkId: NETWORK_ID,
      payloadBytes: draft.payloadBytes,
      signature: signature.subarray(0, 63),
      publicKey: WALLET.publicKey,
      authority: WALLET.accountId,
    }),
    /64 Ed25519 signature bytes/u,
  );
  assert.throws(
    () => transactionPayloadSigningHash(Buffer.concat([draft.payloadBytes, Buffer.from([0])])),
    /invalid canonical transaction payload/u,
  );
});

test("external-signer payloads reuse quoted charge kinds with scaled maxima", async () => {
  const quotedLimits = [
    {
      kind: { kind: "nexus", value: null },
      asset_definition_id: XOR,
      max_amount: "0.000123457",
    },
  ];
  const calls = [];
  const client = {
    async quoteFees(draft, options) {
      calls.push({ authority: draft.payload.authority, options });
      return {
        intent: { payer: "authority", value: { charge_limits: quotedLimits, gas_limit: null } },
        observation: { ledger_time_ms: 1, next_block_height: 2, route_dataspace_id: 0 },
        components: quotedLimits,
        capacities: [],
        decision: {
          status: "accepted",
          value: {
            debit_source: { kind: "account", value: SERVICE.accountId },
            program_revision: null,
          },
        },
      };
    },
  };
  const canonicalAuth = { accountId: SERVICE.accountId, privateKey: SERVICE.privateKey };
  const input = {
    networkId: NETWORK_ID,
    authority: WALLET.accountId,
    instructions: [
      buildTransferAssetInstruction({
        sourceAssetHoldingId: `${XOR}#${WALLET.accountId}`,
        quantity: "1.5",
        destinationAccountId: PEER.accountId,
      }),
    ],
    feePayment: { payer: "authority", chargeLimits: [] },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 120_000,
    nonce: 42,
  };
  const prepared = await prepareExternalSignerTransactionPayload(client, input, { canonicalAuth });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].authority, SERVICE.accountId);
  assert.equal(calls[0].options.canonicalAuth, canonicalAuth);
  assert.deepEqual(prepared.feePayment, {
    payer: "authority",
    chargeLimits: [{ kind: "nexus", assetDefinitionId: XOR, maxAmount: "0.000246914" }],
  });
  assert.equal(prepared.payload.authority, WALLET.accountId);
  assert.deepEqual(prepared.signingHash, transactionPayloadSigningHash(prepared.payloadBytes));
  const finalized = finalizeSignedTransaction({
    networkId: NETWORK_ID,
    payloadBytes: prepared.payloadBytes,
    signature: ed25519.sign(prepared.signingHash, WALLET.privateKey),
    publicKey: WALLET.publicKey,
    authority: WALLET.accountId,
  });
  assert.equal(finalized.hash.toString("hex"), hashSignedTransaction(finalized.signedTransaction));

  const margin = await prepareExternalSignerTransactionPayload(client, input, {
    canonicalAuth,
    feeLimitMarginBps: 15_001,
  });
  assert.equal(margin.feePayment.chargeLimits[0].maxAmount, "0.000185198");
  await assert.rejects(
    prepareExternalSignerTransactionPayload(client, input, { canonicalAuth, feeLimitMarginBps: 9_999 }),
    /feeLimitMarginBps/u,
  );
  await assert.rejects(
    prepareExternalSignerTransactionPayload(client, input, {}),
    /canonicalAuth is required/u,
  );
});

baseTest("feePaymentFromQuote keeps every quoted charge kind and scales maxima", () => {
  const authorityIntent = {
    payer: "authority",
    value: {
      charge_limits: [
        { kind: { kind: "nexus", value: null }, asset_definition_id: XOR, max_amount: "0.000123457" },
        { kind: { kind: "pipeline_gas", value: null }, asset_definition_id: XOR, max_amount: "3" },
      ],
      gas_limit: 50_000,
    },
  };
  assert.deepEqual(feePaymentFromQuote({ intent: authorityIntent }), {
    payer: "authority",
    chargeLimits: [
      { kind: "nexus", assetDefinitionId: XOR, maxAmount: "0.000246914" },
      { kind: "pipelineGas", assetDefinitionId: XOR, maxAmount: "6" },
    ],
    gasLimit: 50_000,
  });
  const exact = feePaymentFromQuote({ intent: authorityIntent }, { marginBps: 10_000 });
  assert.deepEqual(JSON.parse(feePaymentIntentToNoritoJson(exact)), authorityIntent);

  const sponsorIntent = {
    payer: "sponsor",
    value: {
      program_id: { sponsor: SERVICE.accountId, name: "bond_fees" },
      program_revision: 3,
      charge_limits: [
        { kind: { kind: "nexus", value: null }, asset_definition_id: XOR, max_amount: "1" },
      ],
      gas_limit: null,
    },
  };
  const sponsored = feePaymentFromQuote({ intent: sponsorIntent }, { marginBps: 12_500 });
  assert.deepEqual(sponsored, {
    payer: "sponsor",
    // Scaled maxima round up at the quoted decimal scale.
    chargeLimits: [{ kind: "nexus", assetDefinitionId: XOR, maxAmount: "2" }],
    programId: `${SERVICE.accountId}/bond_fees`,
    programRevision: 3,
  });
  assert.deepEqual(
    JSON.parse(feePaymentIntentToNoritoJson(feePaymentFromQuote({ intent: sponsorIntent }, { marginBps: 10_000 }))),
    sponsorIntent,
  );

  assert.throws(() => feePaymentFromQuote({ intent: authorityIntent }, { marginBps: 9_999 }), /marginBps/u);
  assert.throws(() => feePaymentFromQuote({ intent: authorityIntent }, { marginBps: 1.5 }), /marginBps/u);
  assert.throws(() => feePaymentFromQuote({}), /signed authority or sponsor fee intent/u);
  assert.throws(
    () => feePaymentFromQuote({ intent: { payer: "nobody", value: { charge_limits: [] } } }),
    /signed authority or sponsor fee intent/u,
  );
  assert.throws(() =>
    feePaymentFromQuote({
      intent: {
        payer: "authority",
        value: { charge_limits: [{ kind: { kind: "nexus" }, asset_definition_id: XOR, max_amount: "-1" }] },
      },
    }),
  );
});
