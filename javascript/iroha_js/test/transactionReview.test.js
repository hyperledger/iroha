import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import { buildClaimBondCashflowInstruction, buildFundBondCashflowInstruction, buildRecordBondCashflowInstruction } from "../src/bond.js";
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
    settlementId: newSettlementId(ISSUER, "bond-issue-review"),
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
  // Owner-qualified ids are shown in their canonical `reference$owner` text form.
  assert.equal(
    atomicFields.settlement,
    `${settle.Settlement.Atomic.settlement_id.reference}$${ISSUER}`,
  );
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

/** Rust-generated bond vectors (`iroha_js_codec` bond_instruction_tests.rs). */
const BOND_FIXTURE = JSON.parse(
  readFileSync(new URL("./fixtures/bond-v1-codec.json", import.meta.url), "utf8"),
);

test("reviewTransactionPayload renders every bond instruction, enriched by its record and entitlements", () => {
  const vectors = Object.fromEntries(BOND_FIXTURE.instructions.map(({ name, json }) => [name, json]));
  const agent = BOND_FIXTURE.accounts.paying_agent;
  const holder = BOND_FIXTURE.accounts.holder;
  const bond = BOND_FIXTURE.bond;
  const cash = BOND_FIXTURE.payment_asset;
  const source = vectors.FundCashflow.Bond.FundCashflow.source;
  const instructions = [
    vectors.Register,
    vectors.RecordCashflow,
    vectors.FundCashflow,
    buildFundBondCashflowInstruction({ bondId: bond, index: 1, sourceAssetHoldingId: source }),
    vectors.ClaimCashflow,
    vectors.CloseCashflow,
    vectors.Call,
    vectors.DeclareDefault,
    buildRecordBondCashflowInstruction({ bondId: bond, index: 3 }),
    buildClaimBondCashflowInstruction({ bondId: bond, index: 3, holder }),
    vectors.ReplacePayingAgent,
    vectors.RetireTreasuryUnits,
  ];
  const draft = draftFor(instructions, { authority: agent });
  const expected = { networkId: NETWORK_ID, authority: agent };

  const plain = reviewTransactionPayload(draft.payloadBytes, expected);
  assert.deepEqual(plain.instructions.map(({ kind }) => kind), instructions.map(() => "bond"));
  assert.deepEqual(
    plain.instructions.map(({ title }) => title),
    [
      "Register bond",
      "Record bond cash flow",
      "Fund bond cash flow",
      "Fund bond cash flow",
      "Claim bond cash flow",
      "Close bond cash flow",
      "Call bond",
      "Declare bond default",
      "Record bond cash flow",
      "Claim bond cash flow",
      "Replace bond paying agent",
      "Retire bond treasury units",
    ],
  );
  plain.instructions.forEach((row, index) => {
    assert.deepEqual(JSON.parse(row.json), instructions[index]);
  });
  const register = fieldMap(plain.instructions[0]);
  assert.equal(register.bond, bond);
  assert.equal(register.issuer, BOND_FIXTURE.accounts.issuer);
  assert.equal(register["paying agent"], agent);
  assert.equal(register["payment asset"], cash);
  assert.equal(register.denomination, "50 per unit");
  assert.equal(register.coupon, "650 bps a year, 1 payment(s) a year");
  assert.equal(register["day count"], "ActActIcma");
  assert.equal(register["issue date"], "2026-01-15T00:00:00.000Z");
  assert.equal(register["maturity date"], "2029-01-15T00:00:00.000Z");
  assert.equal(register["redemption price (bps)"], "10000");
  assert.equal(register.call, "from 2027-01-15T00:00:00.000Z at 10100 bps, notice 2592000000 ms");
  assert.equal(register["payment grace"], "604800000 ms");
  assert.equal(register["cash flows"], "4");
  assert.equal(
    register["cash flow #0"],
    "Coupon 3.25 per unit; record 2027-01-14T00:00:00.000Z; pay 2027-01-15T00:00:00.000Z",
  );
  assert.equal(
    register["cash flow #3"],
    "Redemption 50 per unit; record 2029-01-14T00:00:00.000Z; pay 2029-01-15T00:00:00.000Z",
  );
  assert.equal(register.ISIN, "SI0031234567");
  assert.equal(register["issuer LEI"], "5299000DI3047E2LIV03");
  assert.equal(register["terms SHA-256"], "09".repeat(32));
  const plainClaim = fieldMap(plain.instructions[4]);
  assert.equal(plainClaim.holder, holder);
  assert.equal(plainClaim.destination, holder);
  assert.equal(plainClaim.units, "entitled units");
  assert.equal(plainClaim.amount, "the holder's entitlement");
  assert.equal(plainClaim["cash flow kind"], "unknown (bond record not supplied)");
  assert.equal(fieldMap(plain.instructions[2]).to, "bond vault");
  assert.equal(fieldMap(plain.instructions[6])["call date"], "2028-01-15T00:00:00.000Z");
  assert.equal(fieldMap(plain.instructions[7])["evidence SHA-256"], "ab".repeat(32));
  assert.equal(fieldMap(plain.instructions[10])["paying agent"], BOND_FIXTURE.accounts.holder_b);
  assert.equal(fieldMap(plain.instructions[10]).replaces, "the current paying agent");
  const plainRetire = fieldMap(plain.instructions[11]);
  assert.equal(plainRetire.quantity, "250 unit(s)");
  assert.equal(plainRetire.from, "the issuer's own balance (signer must be the issuer)");
  assert.equal(plainRetire.outstanding, undefined);

  const record = structuredClone(BOND_FIXTURE.record);
  const redemption = record.state.cashflows[3];
  redemption.status = "Funded";
  redemption.holders = 1;
  const entitlements = [
    ...BOND_FIXTURE.entitlements.map((row) => ({
      id: `${row.id.index}:${row.id.holder}`,
      bond: row.id.bond,
      index: row.id.index,
      holder: row.id.holder,
      units: row.units,
      amount: row.amount,
      claimed: row.claimed_at_ms !== null,
      claimed_at_ms: row.claimed_at_ms,
    })),
    {
      id: `3:${holder}`,
      bond,
      index: 3,
      holder,
      units: "3",
      amount: "150",
      claimed: false,
      claimed_at_ms: null,
    },
  ];
  const enriched = reviewTransactionPayload(draft.payloadBytes, {
    ...expected,
    bonds: [{ record, entitlements }],
  });
  const [, recordRow, fundedRow, fundRow, claimRow, closeRow, callRow, defaultRow, recordRedemption, claimRedemption, replaceRow, retireRow] =
    enriched.instructions.map(fieldMap);
  assert.equal(recordRow["cash flow kind"], "Coupon");
  assert.equal(recordRow["record date"], "2027-01-14T00:00:00.000Z");
  assert.equal(recordRow["payment date"], "2027-01-15T00:00:00.000Z");
  assert.equal(recordRow["amount per unit"], `3.25 of ${cash}`);
  assert.equal(fundedRow.amount, "the recorded amount due");
  assert.equal(fundRow.to, BOND_FIXTURE.record.vault);
  assert.equal(fundRow.from, source);
  assert.equal(fundRow.amount, `${BOND_FIXTURE.record.state.cashflows[1].amount_due} of ${cash}`);
  assert.equal(fundRow.status, "Recorded");
  assert.equal(enriched.instructions[4].title, "Claim bond coupon");
  assert.equal(claimRow.units, "3");
  assert.equal(claimRow.amount, `9.75 of ${cash}`);
  assert.equal(claimRow.status, "Funded");
  assert.equal(claimRow.warning, "this entitlement was already claimed");
  assert.equal(closeRow.unclaimed, "1 holder(s) stay claimable from the vault");
  assert.equal(callRow["call price (bps)"], "10100");
  assert.equal(defaultRow["cash flow kind"], "Coupon");
  assert.equal(defaultRow["payment grace"], "604800000 ms");
  assert.equal(recordRow.books, "closed from the record date until the recording completes");
  assert.equal(recordRedemption["cash flow kind"], "Redemption");
  assert.equal(recordRedemption.effect, "recording the redemption freezes every transfer of the bond");
  assert.equal(enriched.instructions[9].title, "Claim bond redemption");
  assert.equal(claimRedemption.amount, `150 of ${cash}`);
  assert.equal(claimRedemption.effect, "burns the holder's 3 units of the bond");
  assert.equal(replaceRow.replaces, agent);
  assert.equal(retireRow.from, `the issuer's own balance (${BOND_FIXTURE.accounts.issuer})`);
  assert.equal(retireRow.outstanding, "from 1000 to 750");
  assert.equal(retireRow.effect, "burns the units; the outstanding supply falls by the same amount");
  const cancelling = structuredClone(record);
  cancelling.state.outstanding_units = "250";
  const lastRetire = fieldMap(reviewTransactionPayload(draft.payloadBytes, {
    ...expected,
    bonds: [{ record: cancelling, entitlements }],
  }).instructions[11]);
  assert.equal(lastRetire.outstanding, "from 250 to 0");
  assert.equal(
    lastRetire.effect,
    "no unit remains outstanding: every cash flow not yet recorded is cancelled",
  );

  const withoutRows = reviewTransactionPayload(draft.payloadBytes, { ...expected, bonds: [{ record }] });
  assert.equal(fieldMap(withoutRows.instructions[4]).amount, "the holder's entitlement");
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, { ...expected, bonds: record }),
    /expected.bonds must be an array/u,
  );
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, {
      ...expected,
      bonds: [{ record, paymentAssetScale: 2 }],
    }),
    /paymentAssetScale is not supported/u,
  );
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, {
      ...expected,
      bonds: [{ record, entitlements: [{ ...entitlements[0], bond: cash }] }],
    }),
    /not the requested bond/u,
  );
  assert.throws(
    () => reviewTransactionPayload(draft.payloadBytes, { ...expected, bonds: [{ record: { id: bond } }] }),
    /missing field/u,
  );
});
