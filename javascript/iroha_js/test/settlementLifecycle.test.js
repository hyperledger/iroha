import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import { blake2b256 } from "../src/blake2b.js";
import {
  buildAttestEscrowConditionInstruction,
  buildExpireConditionalEscrowInstruction,
  buildGrantAssetDefinitionAliasScopeInstruction,
  buildGrantSettlementConsentInstruction,
  buildOpenConditionalEscrowInstruction,
  buildRepoInitiateInstruction,
  buildRepoReverseInstruction,
  buildSetAssetDefinitionKeyValueInstruction,
} from "../src/instructionBuilders.js";
import {
  buildSettleAtomicInstruction,
  canonicalSettleAtomicInstruction,
  repoIntentHashes,
  settleAtomicIntentHash,
} from "../src/settlementIntents.js";
import { NetworkId } from "../src/networkId.js";
import {
  noritoDecodeInstruction,
  noritoDecodeInstructionBoxArchive,
  noritoEncodeInstruction,
  noritoEncodeInstructionBoxArchive,
} from "../src/norito.js";
import { normalizeAssetDefinitionId } from "../src/normalizers.js";
import { KotodamaQuantity } from "../src/numericV1.js";
import {
  assetDefinitionIdFromSeed,
  generateAssetDefinitionId,
  newEscrowId,
  newRepoAgreementId,
  newSettlementId,
} from "../src/settlementIdentifiers.js";
import { buildTransactionPayload } from "../src/transaction.js";
import { makeNativeTest } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: [
    "noritoEncodeInstruction",
    "noritoDecodeInstruction",
    "noritoEncodeInstructionBoxArchive",
    "noritoDecodeInstructionBoxArchive",
    "canonicalSettleAtomicInstructionJson",
    "settleAtomicIntentHashJson",
    "repoIntentHashesJson",
  ],
});

const PREFIX = 369;
const NETWORK_ID = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
function account(seed) {
  const publicKey = ed25519.getPublicKey(new Uint8Array(32).fill(seed));
  return AccountAddress.fromAccount({ publicKey, algorithm: "ed25519" }).toI105(PREFIX);
}
const ISSUER = account(1);
const BUYER = account(2);
const ORACLE = account(3);
const BOND = assetDefinitionIdFromSeed({ domain: "bondpoc.universal", name: "si_bond_2030" });
const CASH = assetDefinitionIdFromSeed({ domain: "bondpoc.universal", name: "eur_cash" });
const ESCROW_ID = newEscrowId("bond-escrow");

/** Public frames and the payload archives wallets decode both round-trip exactly. */
function roundtrip(instruction) {
  const frame = noritoEncodeInstruction(instruction, PREFIX);
  assert.deepEqual(noritoDecodeInstruction(frame, PREFIX), instruction);
  const archive = noritoEncodeInstructionBoxArchive(instruction, PREFIX);
  assert.deepEqual(noritoDecodeInstructionBoxArchive(archive, PREFIX), instruction);
  return frame;
}

baseTest("identifier helpers produce the exact native literals", () => {
  for (let index = 0; index < 8; index += 1) {
    const generated = generateAssetDefinitionId();
    assert.equal(normalizeAssetDefinitionId(generated, "generated"), generated);
  }
  assert.notEqual(generateAssetDefinitionId(), generateAssetDefinitionId());
  // Same vector as the Rust `derive_from_components` parity test in iroha_js_codec.
  assert.equal(
    assetDefinitionIdFromSeed({ domain: "wonderland.universal", name: "usd" }),
    "4eaant86faGEgeH21U4qTTfpvwSb",
  );
  assert.equal(
    assetDefinitionIdFromSeed({ domain: "Wonderland.Universal", name: "usd" }),
    "4eaant86faGEgeH21U4qTTfpvwSb",
  );
  assert.equal(assetDefinitionIdFromSeed("usd#wonderland.universal"), "4eaant86faGEgeH21U4qTTfpvwSb");
  assert.throws(() => assetDefinitionIdFromSeed({ domain: "wonderland", name: "usd" }), /domain\.dataspace/u);
  assert.throws(() => assetDefinitionIdFromSeed({ domain: "a.b", name: "has space" }), /Name/u);
  assert.throws(() => assetDefinitionIdFromSeed(""), /non-empty/u);

  assert.equal(
    ESCROW_ID,
    "hash:7C485F0A8D12CE1522C64CEBE02CE693A4F6DE697C6F7DFE857EEBDB129065C3#F398",
  );
  const randomEscrow = newEscrowId();
  assert.match(randomEscrow, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
  assert.equal(Number.parseInt(randomEscrow.slice(68, 69), 16) & 1, 1);

  assert.match(newSettlementId(), /^settlement-[0-9a-f]{32}$/u);
  assert.equal(newSettlementId("trade-1"), newSettlementId("trade-1"));
  assert.notEqual(newSettlementId("trade-1"), newSettlementId("trade-2"));
  assert.match(newRepoAgreementId(), /^repo-[0-9a-f]{32}$/u);
  assert.notEqual(newRepoAgreementId("x").slice(5), newSettlementId("x").slice(11));
  const expectedSuffix = Buffer.from(
    blake2b256(Buffer.concat([Buffer.from("iroha-js:settlement-id:v1\0"), Buffer.from("trade-1")])),
  ).subarray(0, 16).toString("hex");
  assert.equal(newSettlementId("trade-1"), `settlement-${expectedSuffix}`);
});

test("consent, alias scope and metadata builders emit exact native JSON", () => {
  const consent = buildGrantSettlementConsentInstruction({
    grantee: ISSUER,
    debitedAssetHoldingId: `${CASH}#${BUYER}`,
    settlementId: "dvp_bond_1",
    intentHash: ESCROW_ID,
  });
  assert.deepEqual(consent, {
    Grant: {
      Permission: {
        object: {
          name: "CanExecuteSettlement",
          payload: {
            debited_asset: `${CASH}#${BUYER}`,
            settlement_id: "dvp_bond_1",
            intent_hash: ESCROW_ID,
          },
        },
        destination: ISSUER,
      },
    },
  });
  roundtrip(consent);
  assert.throws(
    () => buildGrantSettlementConsentInstruction({
      grantee: ISSUER,
      debitedAssetHoldingId: `${CASH}#${BUYER}`,
      settlementId: "dvp_bond_1",
      intentHash: ESCROW_ID.toLowerCase(),
    }),
    /canonical uppercase hash literal/u,
  );

  const scope = buildGrantAssetDefinitionAliasScopeInstruction({
    grantee: ISSUER,
    domainId: "BondPoc.universal",
  });
  assert.deepEqual(scope.Grant.Permission.object, {
    name: "CanManageAssetDefinitionAlias",
    payload: { scope: { scope: "domain", value: "bondpoc.universal" } },
  });
  roundtrip(scope);

  const metadata = buildSetAssetDefinitionKeyValueInstruction({
    assetDefinitionId: BOND,
    key: "isin",
    value: { isin: "SI0031234567", coupon_bps: 325 },
  });
  assert.deepEqual(metadata, {
    SetKeyValue: {
      AssetDefinition: {
        object: BOND,
        key: "isin",
        value: { isin: "SI0031234567", coupon_bps: 325 },
      },
    },
  });
  roundtrip(metadata);
  assert.throws(
    () => buildSetAssetDefinitionKeyValueInstruction({ assetDefinitionId: BOND, key: "a b", value: 1 }),
    /Name/u,
  );
});

test("conditional escrow builders emit tagged native conditions", () => {
  const open = buildOpenConditionalEscrowInstruction({
    escrowId: ESCROW_ID,
    assetDefinitionId: BOND,
    beneficiary: BUYER,
    amount: "10",
    conditions: [
      { id: "coupon_paid", attestor: ORACLE, equals: true },
      { id: "rating", attestor: ORACLE, equals: "AA" },
      { id: "price", attestor: ORACLE, quantityAtMost: new KotodamaQuantity(1015n, 1) },
      { id: "nominal", attestor: ORACLE, equals: { quantity: "100" } },
      { id: "window", withinMs: 86_400_000 },
    ],
    expiresAtMs: 1_900_000_000_000,
  });
  assert.deepEqual(open, {
    OpenConditionalEscrow: {
      escrow_id: ESCROW_ID,
      asset_definition: BOND,
      beneficiary: BUYER,
      amount: "10",
      conditions: [
        {
          kind: "Oracle",
          value: {
            id: "coupon_paid",
            attestor: ORACLE,
            predicate: { kind: "Equals", value: { kind: "Bool", value: true } },
            sequence: 1,
          },
        },
        {
          kind: "Oracle",
          value: {
            id: "rating",
            attestor: ORACLE,
            predicate: { kind: "Equals", value: { kind: "Text", value: "AA" } },
            sequence: 2,
          },
        },
        {
          kind: "Oracle",
          value: {
            id: "price",
            attestor: ORACLE,
            predicate: { kind: "QuantityAtMost", value: "101.5" },
            sequence: 3,
          },
        },
        {
          kind: "Oracle",
          value: {
            id: "nominal",
            attestor: ORACLE,
            predicate: { kind: "Equals", value: { kind: "Quantity", value: "100" } },
            sequence: 4,
          },
        },
        { kind: "Within", value: { id: "window", duration_ms: 86_400_000 } },
      ],
      expires_at_ms: 1_900_000_000_000,
      evidence_hashes: [],
    },
  });
  roundtrip(open);

  const attest = buildAttestEscrowConditionInstruction({
    escrowId: ESCROW_ID,
    conditionId: "coupon_paid",
    value: true,
    evidenceHash: newEscrowId("coupon-report"),
  });
  assert.deepEqual(attest.AttestEscrowCondition.value, { kind: "Bool", value: true });
  roundtrip(attest);
  const expire = buildExpireConditionalEscrowInstruction({ escrowId: ESCROW_ID });
  assert.deepEqual(expire, { ExpireConditionalEscrow: { escrow_id: ESCROW_ID } });
  roundtrip(expire);

  const base = {
    escrowId: ESCROW_ID,
    assetDefinitionId: BOND,
    beneficiary: BUYER,
    amount: "10",
    expiresAtMs: 1_900_000_000_000,
  };
  for (const [conditions, pattern] of [
    [[], /1\.\.=64/u],
    [[{ id: "w", withinMs: 1 }], /at least one oracle/u],
    [[{ id: "a", attestor: ORACLE, equals: true }, { id: "a", attestor: ORACLE, equals: false }], /duplicates/u],
    [[{ id: "a", attestor: ORACLE, equals: true, quantityAtMost: "1" }], /exactly one/u],
    [[{ id: "a", attestor: ORACLE, equals: true, sequence: 2 }], /contiguous/u],
    [[{ id: "a", attestor: ORACLE, equals: true, sequence: 1 }, { id: "b", attestor: ORACLE, equals: true }], /every oracle sequence or none/u],
    [[{ id: "a", attestor: ORACLE, equals: 1 }], /boolean, text/u],
  ]) {
    assert.throws(() => buildOpenConditionalEscrowInstruction({ ...base, conditions }), pattern);
  }
  assert.throws(
    () => buildOpenConditionalEscrowInstruction({ ...base, amount: "0", conditions: [{ id: "a", attestor: ORACLE, equals: true }] }),
    /amount/u,
  );
});

test("atomic settlement is sorted natively and hashed exactly as consented", () => {
  const movements = [
    { sourceAssetHoldingId: `${CASH}#${BUYER}`, recipient: ISSUER, quantity: "1015.5" },
    { sourceAssetHoldingId: `${BOND}#${ISSUER}`, recipient: BUYER, quantity: "10" },
  ];
  const settlementId = newSettlementId("dvp-1");
  const forward = buildSettleAtomicInstruction({
    networkId: NETWORK_ID,
    settlementId,
    movements,
    expiresAtHeight: 5_000,
    metadata: { isin: "SI0031234567" },
  });
  const reversed = buildSettleAtomicInstruction({
    networkId: NETWORK_ID.toString(),
    settlementId,
    movements: [...movements].reverse(),
    expiresAtHeight: 5_000n,
    metadata: { isin: "SI0031234567" },
  });
  assert.deepEqual(forward, reversed);
  const payload = forward.Settlement.Atomic;
  assert.deepEqual(Object.keys(payload).sort(), [
    "escrows",
    "expires_at_height",
    "metadata",
    "movements",
    "network_id",
    "settlement_id",
  ]);
  assert.deepEqual(payload.escrows, []);
  assert.equal(payload.network_id, NETWORK_ID.toString());
  assert.equal(payload.expires_at_height, 5_000);
  assert.deepEqual(
    payload.movements.map(({ source, recipient, quantity }) => ({ source, recipient, quantity })).sort(
      (left, right) => left.quantity.localeCompare(right.quantity),
    ),
    [
      { source: `${CASH}#${BUYER}`, recipient: ISSUER, quantity: "1015.5" },
      { source: `${BOND}#${ISSUER}`, recipient: BUYER, quantity: "10" },
    ].sort((left, right) => left.quantity.localeCompare(right.quantity)),
  );
  roundtrip(forward);

  const intent = settleAtomicIntentHash(forward);
  assert.match(intent, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
  assert.equal(settleAtomicIntentHash(reversed), intent);
  const changed = buildSettleAtomicInstruction({
    networkId: NETWORK_ID,
    settlementId,
    movements,
    expiresAtHeight: 5_001,
    metadata: { isin: "SI0031234567" },
  });
  assert.notEqual(settleAtomicIntentHash(changed), intent);
  const swapped = structuredClone(forward);
  swapped.Settlement.Atomic.movements.reverse();
  assert.throws(() => settleAtomicIntentHash(swapped), /strictly increasing/u);

  assert.throws(
    () => buildSettleAtomicInstruction({
      networkId: NETWORK_ID,
      settlementId,
      movements: [movements[0], movements[0]],
      expiresAtHeight: 5_000,
    }),
    /strictly increasing/u,
  );
  assert.throws(
    () => buildSettleAtomicInstruction({
      networkId: NETWORK_ID,
      settlementId,
      movements: [{ ...movements[0], recipient: BUYER }, movements[1]],
      expiresAtHeight: 5_000,
    }),
    /non-self/u,
  );
  const consent = buildGrantSettlementConsentInstruction({
    grantee: ISSUER,
    debitedAssetHoldingId: `${CASH}#${BUYER}`,
    settlementId,
    intentHash: intent,
  });
  roundtrip(consent);
});

test("repo lifecycle builders and consent hashes match the native agreement", () => {
  const agreementId = newRepoAgreementId("repo-1");
  const initiate = buildRepoInitiateInstruction({
    agreementId,
    initiator: ISSUER,
    counterparty: BUYER,
    cashLeg: { assetDefinitionId: CASH, quantity: "1000" },
    collateralLeg: { assetDefinitionId: BOND, quantity: "11", metadata: { isin: "SI0031234567" } },
    rateBps: 325,
    maturityTimestampMs: 1_900_000_000_000,
    governance: { haircutBps: 1_000, marginFrequencySecs: 0, allowEarlyRepayment: false },
  });
  assert.deepEqual(initiate, {
    Repo: {
      Initiate: {
        agreement_id: agreementId,
        initiator: ISSUER,
        counterparty: BUYER,
        custodian: null,
        cash_leg: { asset_definition_id: CASH, quantity: "1000" },
        collateral_leg: {
          asset_definition_id: BOND,
          quantity: "11",
          metadata: { isin: "SI0031234567" },
        },
        rate_bps: 325,
        maturity_timestamp_ms: 1_900_000_000_000,
        governance: { haircut_bps: 1_000, margin_frequency_secs: 0, allow_early_repayment: false },
      },
    },
  });
  roundtrip(initiate);
  const hashes = repoIntentHashes(initiate);
  assert.match(hashes.initiation, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
  assert.match(hashes.maturity, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
  assert.notEqual(hashes.initiation, hashes.maturity);
  const custodied = buildRepoInitiateInstruction({
    agreementId,
    initiator: ISSUER,
    counterparty: BUYER,
    custodian: ORACLE,
    cashLeg: { assetDefinitionId: CASH, quantity: "1000" },
    collateralLeg: { assetDefinitionId: BOND, quantity: "11" },
    rateBps: 325,
    maturityTimestampMs: 1_900_000_000_000,
    governance: { haircutBps: 1_000, marginFrequencySecs: 86_400, allowEarlyRepayment: false },
  });
  assert.notEqual(repoIntentHashes(custodied).initiation, hashes.initiation);
  const early = structuredClone(initiate);
  early.Repo.Initiate.governance.allow_early_repayment = true;
  roundtrip(early);
  const earlyHashes = repoIntentHashes(early);
  assert.notEqual(earlyHashes.initiation, hashes.initiation);
  assert.notEqual(earlyHashes.maturity, hashes.maturity);
  assert.throws(
    () => buildRepoInitiateInstruction({
      agreementId,
      initiator: ISSUER,
      counterparty: BUYER,
      cashLeg: { assetDefinitionId: CASH, quantity: "1000" },
      collateralLeg: { assetDefinitionId: BOND, quantity: "11" },
      rateBps: 325,
      maturityTimestampMs: 1_900_000_000_000,
      governance: { haircutBps: 1_000, marginFrequencySecs: 0 },
    }),
    /allowEarlyRepayment/u,
  );

  const reverse = buildRepoReverseInstruction({ agreementId });
  assert.deepEqual(reverse, { Repo: { Reverse: { agreement_id: agreementId } } });
  roundtrip(reverse);
  assert.throws(() => repoIntentHashes(reverse), /Repo: \{ Initiate \}/u);
  assert.throws(
    () => buildRepoInitiateInstruction({
      agreementId,
      initiator: ISSUER,
      counterparty: BUYER,
      cashLeg: { assetDefinitionId: CASH, quantity: "1000" },
      collateralLeg: { assetDefinitionId: BOND, quantity: "11" },
      rateBps: 70_000,
      maturityTimestampMs: 1_900_000_000_000,
      governance: { haircutBps: 1_000, marginFrequencySecs: 0, allowEarlyRepayment: false },
    }),
    /rateBps must not exceed 65535/u,
  );
});

test("atomic settlement escrow legs are normalized, ordered and bound into the intent", () => {
  const INVESTOR_B = account(4);
  const leg = (sourceAssetHoldingId, beneficiary, label, amount) => ({
    sourceAssetHoldingId,
    escrowId: newEscrowId(`bond-escrow:${label}`),
    beneficiary,
    amount,
    conditions: [{ id: "coupon_paid", attestor: ORACLE, equals: true }],
    expiresAtMs: 1_900_000_000_000,
  });
  // Two issuer-owned bond deliveries and four escrow legs (two foreign cash sources).
  const options = {
    networkId: NETWORK_ID,
    settlementId: newSettlementId("bond-issue-escrow"),
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
  };
  const built = buildSettleAtomicInstruction(options);
  const payload = built.Settlement.Atomic;
  assert.equal(payload.escrows.length, 4);
  const escrowIds = payload.escrows.map(({ escrow_id }) => escrow_id);
  const escrowBytes = escrowIds.map((id) => Buffer.from(id.slice(5, 69), "hex"));
  for (let index = 1; index < escrowBytes.length; index += 1) {
    assert.ok(Buffer.compare(escrowBytes[index - 1], escrowBytes[index]) < 0, "escrows sorted by id bytes");
  }
  assert.deepEqual(payload.escrows.find(({ escrow_id }) => escrow_id === newEscrowId("bond-escrow:refund-b")), {
    source: `${CASH}#${ISSUER}`,
    escrow_id: newEscrowId("bond-escrow:refund-b"),
    beneficiary: INVESTOR_B,
    amount: "25",
    conditions: [
      {
        kind: "Oracle",
        value: {
          id: "coupon_paid",
          attestor: ORACLE,
          predicate: { kind: "Equals", value: { kind: "Bool", value: true } },
          sequence: 1,
        },
      },
    ],
    expires_at_ms: 1_900_000_000_000,
    evidence_hashes: [],
  });
  roundtrip(built);
  const intent = settleAtomicIntentHash(built);
  const reordered = buildSettleAtomicInstruction({
    ...options,
    movements: [...options.movements].reverse(),
    escrows: [...options.escrows].reverse(),
  });
  assert.deepEqual(reordered, built);
  assert.equal(settleAtomicIntentHash(reordered), intent);

  // The codec never sorts; the canonical helper restores the admitted order.
  const shuffled = structuredClone(built);
  shuffled.Settlement.Atomic.escrows.reverse();
  shuffled.Settlement.Atomic.movements.reverse();
  assert.throws(() => settleAtomicIntentHash(shuffled), /strictly increasing|escrow/u);
  assert.deepEqual(canonicalSettleAtomicInstruction(shuffled), built);

  const changed = structuredClone(built);
  changed.Settlement.Atomic.escrows[0].amount = "999";
  assert.notEqual(settleAtomicIntentHash(canonicalSettleAtomicInstruction(changed)), intent);

  // Escrow legs alone can satisfy the two-leg minimum; a single leg cannot.
  const escrowOnly = buildSettleAtomicInstruction({ ...options, movements: [], escrows: options.escrows.slice(0, 2) });
  assert.equal(escrowOnly.Settlement.Atomic.movements.length, 0);
  assert.throws(
    () => buildSettleAtomicInstruction({ ...options, movements: [], escrows: options.escrows.slice(0, 1) }),
    /two legs/u,
  );
  assert.throws(
    () => buildSettleAtomicInstruction({
      ...options,
      escrows: [{ ...options.escrows[0], sourceAssetHoldingId: `${CASH}#${BUYER}#dataspace:7` }],
    }),
  );
  roundtrip(buildGrantSettlementConsentInstruction({
    grantee: ISSUER,
    debitedAssetHoldingId: `${CASH}#${BUYER}`,
    settlementId: payload.settlement_id,
    intentHash: intent,
  }));
});

test("every lifecycle instruction assembles into one native transaction payload", () => {
  const settle = buildSettleAtomicInstruction({
    networkId: NETWORK_ID,
    settlementId: newSettlementId("dvp-2"),
    movements: [
      { sourceAssetHoldingId: `${CASH}#${BUYER}`, recipient: ISSUER, quantity: "1000" },
      { sourceAssetHoldingId: `${BOND}#${ISSUER}`, recipient: BUYER, quantity: "10" },
    ],
    expiresAtHeight: 10,
  });
  const draft = buildTransactionPayload({
    networkId: NETWORK_ID,
    authority: ISSUER,
    instructions: [
      buildGrantAssetDefinitionAliasScopeInstruction({ grantee: ISSUER, domainId: "bondpoc.universal" }),
      buildSetAssetDefinitionKeyValueInstruction({ assetDefinitionId: BOND, key: "isin", value: "SI0031234567" }),
      buildOpenConditionalEscrowInstruction({
        escrowId: ESCROW_ID,
        assetDefinitionId: BOND,
        beneficiary: BUYER,
        amount: "1",
        conditions: [{ id: "coupon_paid", attestor: ORACLE, equals: true }],
        expiresAtMs: 1_900_000_000_000,
      }),
      buildAttestEscrowConditionInstruction({ escrowId: ESCROW_ID, conditionId: "coupon_paid", value: true }),
      buildExpireConditionalEscrowInstruction({ escrowId: ESCROW_ID }),
      settle,
      buildRepoReverseInstruction({ agreementId: "repo-x" }),
    ],
    feePayment: { payer: "authority", chargeLimits: [] },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 60_000,
    nonce: 7,
  });
  assert.equal(draft.payloadHash.length, 32);
  assert.equal(draft.payload.instructions.Instructions.length, 7);
});
