import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import {
  buildAttestEscrowConditionInstruction,
  buildGrantSettlementConsentInstruction,
  buildRepoInitiateInstruction,
  buildSetAssetDefinitionKeyValueInstruction,
  buildTransferAssetInstruction,
} from "../src/instructionBuilders.js";
import { NetworkId } from "../src/networkId.js";
import {
  assetDefinitionIdFromSeed,
  newEscrowId,
  newRepoAgreementId,
  newSettlementId,
} from "../src/settlementIdentifiers.js";
import { buildSettleAtomicInstruction, settleAtomicIntentHash } from "../src/settlementIntents.js";
import { buildTransactionPayload, transactionPayloadSigningHash } from "../src/transaction.js";
import {
  reviewTransactionPayload,
  sanitizeReviewText,
  TRANSACTION_REVIEW_MAX_INSTRUCTIONS,
  TRANSACTION_REVIEW_SCHEMA,
} from "../src/transactionReview.js";
import { makeNativeTest } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: ["decodeTransactionPayloadJson", "transactionPayloadSigningHash", "noritoDecodeInstruction"],
});

const PREFIX = 369;
const NETWORK_ID = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
const OTHER_NETWORK = NetworkId.parse(
  "hash:7C485F0A8D12CE1522C64CEBE02CE693A4F6DE697C6F7DFE857EEBDB129065C3#F398",
);
function account(seed) {
  const publicKey = ed25519.getPublicKey(new Uint8Array(32).fill(seed));
  return AccountAddress.fromAccount({ publicKey, algorithm: "ed25519" }).toI105(PREFIX);
}
const ISSUER = account(1);
const BUYER = account(2);
const ORACLE = account(3);
const INVESTOR_B = account(4);
const BOND = assetDefinitionIdFromSeed({ domain: "bondpoc.universal", name: "si_bond_2030" });
const CASH = assetDefinitionIdFromSeed({ domain: "bondpoc.universal", name: "eur_cash" });
const XOR = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

function draftFor(instructions, overrides = {}) {
  return buildTransactionPayload({
    networkId: NETWORK_ID,
    authority: ISSUER,
    instructions,
    feePayment: {
      payer: "authority",
      chargeLimits: [{ kind: "nexus", assetDefinitionId: XOR, maxAmount: "2" }],
    },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 60_000,
    nonce: 9,
    ...overrides,
  });
}

function fieldMap(row) {
  return Object.fromEntries(row.fields.map(({ label, value }) => [label, value]));
}

baseTest("sanitizeReviewText escapes control, bidi and line-separator characters and bounds text", () => {
  assert.equal(sanitizeReviewText("plain"), "plain");
  assert.equal(
    sanitizeReviewText("pay\u202Eevil\u2066x\u2069\nnext\u2028\u0000"),
    "pay\\u{202E}evil\\u{2066}x\\u{2069}\\u{A}next\\u{2028}\\u{0}",
  );
  assert.equal(sanitizeReviewText("\u200Bzero\u061Cwidth"), "\\u{200B}zero\\u{61C}width");
  assert.equal(sanitizeReviewText(42), "42");
  const long = sanitizeReviewText("a".repeat(600));
  assert.equal(long.length, 512);
  assert.ok(long.endsWith("\u2026"));
  assert.equal(sanitizeReviewText("b".repeat(20), 8), "bbbbbbb\u2026");
});

test("reviewTransactionPayload describes bond-poc settlement, escrow, repo and consent rows", () => {
  const leg = (source, beneficiary, label, amount) => ({
    sourceAssetHoldingId: source,
    escrowId: newEscrowId(`bond-escrow:${label}`),
    beneficiary,
    amount,
    conditions: [{ id: "coupon_paid", attestor: ORACLE, equals: true }],
    expiresAtMs: 1_900_000_000_000,
  });
  const settle = buildSettleAtomicInstruction({
    networkId: NETWORK_ID,
    settlementId: newSettlementId("bond-issue-review"),
    movements: [
      { sourceAssetHoldingId: `${BOND}#${ISSUER}`, recipient: BUYER, quantity: "10" },
      { sourceAssetHoldingId: `${BOND}#${ISSUER}`, recipient: INVESTOR_B, quantity: "5" },
    ],
    escrows: [
      leg(`${CASH}#${BUYER}`, ISSUER, "retention-buyer", "1000"),
      leg(`${CASH}#${INVESTOR_B}`, ISSUER, "retention-b", "500"),
      leg(`${BOND}#${ISSUER}`, BUYER, "coupon-buyer", "1"),
      leg(`${CASH}#${ISSUER}`, INVESTOR_B, "refund-b", "25"),
    ],
    expiresAtHeight: 5_000,
  });
  const agreementId = newRepoAgreementId("review-repo");
  const instructions = [
    buildTransferAssetInstruction({
      sourceAssetHoldingId: `${CASH}#${ISSUER}`,
      destinationAccountId: BUYER,
      quantity: "7.5",
    }),
    settle,
    buildGrantSettlementConsentInstruction({
      grantee: ISSUER,
      debitedAssetHoldingId: `${BOND}#${ISSUER}`,
      settlementId: settle.Settlement.Atomic.settlement_id,
      intentHash: settleAtomicIntentHash(settle),
    }),
    buildRepoInitiateInstruction({
      agreementId,
      initiator: ISSUER,
      counterparty: BUYER,
      cashLeg: { assetDefinitionId: CASH, quantity: "1000" },
      collateralLeg: { assetDefinitionId: BOND, quantity: "11" },
      rateBps: 325,
      maturityTimestampMs: 1_900_000_000_000,
      governance: { haircutBps: 1_000, marginFrequencySecs: 0, allowEarlyRepayment: true },
    }),
    buildAttestEscrowConditionInstruction({
      escrowId: newEscrowId("bond-escrow:coupon-buyer"),
      conditionId: "coupon_paid",
      value: true,
    }),
    buildSetAssetDefinitionKeyValueInstruction({ assetDefinitionId: BOND, key: "isin", value: "SI0031234567" }),
  ];
  const draft = draftFor(instructions, { metadata: { memo: "coupon\u202Etxt.exe" } });
  const review = reviewTransactionPayload(draft.payloadBytes, { networkId: NETWORK_ID, authority: ISSUER });

  assert.equal(review.schema, TRANSACTION_REVIEW_SCHEMA);
  assert.equal(review.networkId, NETWORK_ID.toString());
  assert.equal(review.authority, ISSUER);
  assert.equal(review.payloadHashHex, Buffer.from(draft.payloadHash).toString("hex"));
  assert.equal(review.payloadHashHex, Buffer.from(transactionPayloadSigningHash(draft.payloadBytes)).toString("hex"));
  assert.equal(review.payloadByteLength, draft.payloadBytes.length);
  assert.equal(review.creationTimeMs, "1700000000000");
  assert.equal(review.ttlMs, "60000");
  assert.deepEqual(review.feePayment, {
    payer: "authority",
    sponsorProgram: null,
    gasLimit: null,
    chargeLimits: [{ kind: "nexus", assetDefinitionId: XOR, maxAmount: "2" }],
  });
  assert.equal(review.metadata, '{"memo":"coupon\\u{202E}txt.exe"}');
  assert.deepEqual(review.warnings, []);
  assert.deepEqual(
    review.instructions.map(({ index, kind }) => [index, kind]),
    [
      [1, "transfer"],
      [2, "settlement_atomic"],
      [3, "grant_permission"],
      [4, "repo"],
      [5, "escrow"],
      [6, "unknown"],
    ],
  );

  const [transfer, atomic, consent, repo, attest, setKeyValue] = review.instructions;
  assert.deepEqual(fieldMap(transfer), { from: `${CASH}#${ISSUER}`, to: BUYER, quantity: "7.5" });

  const atomicFields = fieldMap(atomic);
  assert.equal(atomic.title, "Atomic settlement");
  assert.equal(atomicFields.settlement, settle.Settlement.Atomic.settlement_id);
  assert.equal(atomicFields.network, NETWORK_ID.toString());
  assert.equal(atomicFields["expires at height"], "5000");
  assert.equal(atomic.fields.filter(({ label }) => label.startsWith("movement ")).length, 2);
  for (const [index, escrow] of settle.Settlement.Atomic.escrows.entries()) {
    const prefix = `leg ${index + 1}`;
    assert.equal(atomicFields[`${prefix} escrow`], escrow.escrow_id);
    assert.equal(atomicFields[`${prefix} from`], escrow.source);
    assert.equal(atomicFields[`${prefix} to`], escrow.beneficiary);
    assert.equal(atomicFields[`${prefix} amount`], escrow.amount);
    assert.equal(atomicFields[`${prefix} conditions`], `1. coupon_paid by ${ORACLE} = true`);
    assert.equal(atomicFields[`${prefix} expires at (ms)`], "1900000000000");
  }
  assert.deepEqual(JSON.parse(atomic.json), settle);

  assert.equal(consent.title, "Grant CanExecuteSettlement");
  assert.equal(fieldMap(consent).to, ISSUER);

  const repoFields = fieldMap(repo);
  assert.equal(repo.title, "Initiate repo");
  assert.equal(repoFields.agreement, agreementId);
  assert.equal(repoFields.cash, `1000 of ${CASH}`);
  assert.equal(repoFields.collateral, `11 of ${BOND}`);
  assert.equal(repoFields["early repayment"], "allowed");
  assert.equal(repoFields.custodian, "none");

  assert.deepEqual(fieldMap(attest), {
    escrow: newEscrowId("bond-escrow:coupon-buyer"),
    condition: "coupon_paid",
    value: "true",
    evidence: "none",
  });
  assert.equal(setKeyValue.title, "SetKeyValue");
  assert.deepEqual(JSON.parse(setKeyValue.json), instructions[5]);
});

test("reviewTransactionPayload fails closed on network, authority and size mismatches", () => {
  const transfer = buildTransferAssetInstruction({
    sourceAssetHoldingId: `${CASH}#${ISSUER}`,
    destinationAccountId: BUYER,
    quantity: "1",
  });
  const draft = draftFor([transfer]);
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, { networkId: OTHER_NETWORK, authority: ISSUER }),
    /NetworkId differs/u,
  );
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, { networkId: NETWORK_ID, authority: BUYER }),
    /authority differs/u,
  );
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, { networkId: NETWORK_ID.toString(), authority: ISSUER }),
    /must be a NetworkId/u,
  );
  const corrupted = Buffer.from(draft.payloadBytes);
  corrupted[corrupted.length - 1] ^= 0xff;
  assert.throws(() => reviewTransactionPayload(Buffer.concat([corrupted, Buffer.from([0])]), {
    networkId: NETWORK_ID,
    authority: ISSUER,
  }));

  const atLimit = draftFor(Array.from({ length: TRANSACTION_REVIEW_MAX_INSTRUCTIONS }, () => transfer));
  assert.equal(
    reviewTransactionPayload(atLimit.payloadBytes, { networkId: NETWORK_ID, authority: ISSUER }).instructions.length,
    TRANSACTION_REVIEW_MAX_INSTRUCTIONS,
  );
  const overLimit = draftFor(Array.from({ length: TRANSACTION_REVIEW_MAX_INSTRUCTIONS + 1 }, () => transfer));
  assert.throws(
    () => reviewTransactionPayload(overLimit.payloadBytes, { networkId: NETWORK_ID, authority: ISSUER }),
    /65 instructions; at most 64/u,
  );
});
