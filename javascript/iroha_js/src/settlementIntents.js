// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Native-ordered atomic settlements and exact settlement consent hashes (Node.js).
 *
 * Atomic movements are ordered by the native `(AssetId, AccountId)` ordering and
 * every consent hash commits to the canonical Norito encoding, so both are
 * delegated to the native codec. The returned hash literals are exactly the
 * `intent_hash` values `CanExecuteSettlement` expects.
 */

import { AccountAddress } from "./address.js";
import { assertCanonicalIrohaName } from "./instructionBuilderPrimitives.js";
import {
  buildOpenConditionalEscrowInstruction,
  buildTransferAssetInstruction,
} from "./instructionBuilders.js";
import { normalizeAssetHoldingId } from "./normalizers.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { NetworkId } from "./networkId.js";

const SETTLE_ATOMIC_FIELDS = new Set([
  "networkId",
  "settlementId",
  "movements",
  "escrows",
  "expiresAtHeight",
  "metadata",
]);
const MOVEMENT_FIELDS = ["sourceAssetHoldingId", "recipient", "quantity"];
const ESCROW_LEG_FIELDS = new Set([
  "sourceAssetHoldingId",
  "escrowId",
  "beneficiary",
  "amount",
  "conditions",
  "expiresAtMs",
  "evidenceHashes",
]);

function plainObject(value, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be a plain object`);
  }
  return value;
}

function networkIdLiteral(value, context) {
  const literal = value instanceof NetworkId ? value.toString() : value;
  if (typeof literal !== "string" || NetworkId.parse(literal).toString() !== literal) {
    throw new TypeError(`${context} must be a NetworkId or its canonical literal`);
  }
  return literal;
}

function positiveSafeInteger(value, context) {
  const number = typeof value === "bigint" || typeof value === "string" ? Number(value) : value;
  if (
    !Number.isSafeInteger(number) ||
    number < 1 ||
    (typeof value === "string" && String(number) !== value)
  ) {
    throw new RangeError(`${context} must be a positive safe integer`);
  }
  return number;
}

function metadataObject(value, context) {
  if (value === undefined || value === null) return {};
  const metadata = plainObject(value, context);
  return JSON.parse(JSON.stringify(metadata));
}

/** Resolve the one I105 network prefix shared by every account literal. */
function sharedNetworkPrefix(accountLiterals, context) {
  let prefix = null;
  for (const literal of accountLiterals) {
    const { chainDiscriminant } = AccountAddress.parseEncoded(literal);
    if (typeof chainDiscriminant !== "number") {
      throw new TypeError(`${context} accounts must be I105 literals with a network prefix`);
    }
    if (prefix !== null && prefix !== chainDiscriminant) {
      throw new TypeError(`${context} accounts must share one network prefix`);
    }
    prefix = chainDiscriminant;
  }
  if (prefix === null) {
    throw new TypeError(`${context} must name at least one account`);
  }
  return prefix;
}

function atomicPayload(instruction, context) {
  const payload = instruction?.Settlement?.Atomic;
  if (
    payload === null ||
    typeof payload !== "object" ||
    Object.keys(instruction).length !== 1 ||
    Object.keys(instruction.Settlement).length !== 1
  ) {
    throw new TypeError(`${context} must be a { Settlement: { Atomic } } instruction`);
  }
  return payload;
}

function atomicAccounts(payload) {
  const accounts = [];
  for (const movement of Array.isArray(payload.movements) ? payload.movements : []) {
    accounts.push(movement?.recipient, String(movement?.source ?? "").split("#")[1]);
  }
  for (const escrow of Array.isArray(payload.escrows) ? payload.escrows : []) {
    accounts.push(escrow?.beneficiary, String(escrow?.source ?? "").split("#")[1]);
  }
  return accounts.filter((account) => typeof account === "string" && account.length > 0);
}

/**
 * Normalize one escrow leg with the exact `OpenConditionalEscrow` field rules.
 * The source must be a global-scope bucket; its owner opens the escrow and
 * receives the refund on expiry.
 */
function escrowLeg(leg, path) {
  const entry = plainObject(leg, path);
  for (const key of Object.keys(entry)) {
    if (!ESCROW_LEG_FIELDS.has(key)) throw new TypeError(`${path}.${key} is not supported`);
  }
  const source = normalizeAssetHoldingId(entry.sourceAssetHoldingId, `${path}.sourceAssetHoldingId`);
  const { OpenConditionalEscrow: opened } = buildOpenConditionalEscrowInstruction({
    escrowId: entry.escrowId,
    assetDefinitionId: source.split("#")[0],
    beneficiary: entry.beneficiary,
    amount: entry.amount,
    conditions: entry.conditions,
    expiresAtMs: entry.expiresAtMs,
    evidenceHashes: entry.evidenceHashes,
  });
  return {
    source,
    escrow_id: opened.escrow_id,
    beneficiary: opened.beneficiary,
    amount: opened.amount,
    conditions: opened.conditions,
    expires_at_ms: opened.expires_at_ms,
    evidence_hashes: opened.evidence_hashes,
  };
}

/**
 * Sort a `Settlement::Atomic` instruction JSON into native canonical order.
 *
 * Movements are ordered by the native `(AssetId, AccountId)` ordering and
 * escrow legs by `EscrowId` bytes; the strict codec never sorts, so this is the
 * order it admits. All model rules (leg counts, duplicate keys, global escrow
 * sources, positive amounts) are then validated natively.
 * @param {{Settlement: {Atomic: object}}} instruction
 * @returns {{Settlement: {Atomic: object}}}
 */
export function canonicalSettleAtomicInstruction(instruction) {
  const context = "canonicalSettleAtomicInstruction.instruction";
  const prefix = sharedNetworkPrefix(atomicAccounts(atomicPayload(instruction, context)), context);
  return JSON.parse(
    nativeBinding().canonicalSettleAtomicInstructionJson(JSON.stringify(instruction), prefix),
  );
}

function nativeBinding() {
  return resolveNativeRuntimeBinding(defaultNativeRuntime);
}

/**
 * Build a `Settlement::Atomic` instruction with legs in native canonical order.
 *
 * Each movement is normalized exactly like a transfer leg and each escrow leg
 * exactly like `OpenConditionalEscrow` (plus its global-scope source bucket);
 * {@link canonicalSettleAtomicInstruction} then sorts and validates natively.
 * Movements (0..=255) and escrow legs (0..=16) must total at least two legs.
 * Every foreign source owner (movement or escrow) grants the submitter
 * `CanExecuteSettlement` with {@link settleAtomicIntentHash} of the returned
 * instruction; the submitter's own buckets need no consent.
 * @param {{ networkId: NetworkId | string, settlementId: string, movements: Array<{ sourceAssetHoldingId: string, recipient: string, quantity: import("./numericV1.js").KotodamaQuantity | string | bigint }>, escrows?: Array<{ sourceAssetHoldingId: string, escrowId: string, beneficiary: string, amount: import("./numericV1.js").KotodamaQuantity | string | bigint, conditions: Array<object>, expiresAtMs: number | bigint | string, evidenceHashes?: string[] }>, expiresAtHeight: number | bigint | string, metadata?: object | null }} options
 * @returns {{Settlement: {Atomic: object}}}
 */
export function buildSettleAtomicInstruction(options) {
  const context = "settleAtomic";
  const source = plainObject(options, context);
  for (const key of Object.keys(source)) {
    if (!SETTLE_ATOMIC_FIELDS.has(key)) throw new TypeError(`${context}.${key} is not supported`);
  }
  if (!Array.isArray(source.movements)) {
    throw new TypeError(`${context}.movements must be an array`);
  }
  const escrowInput = source.escrows ?? [];
  if (!Array.isArray(escrowInput)) {
    throw new TypeError(`${context}.escrows must be an array`);
  }
  const movements = source.movements.map((movement, index) => {
    const path = `${context}.movements[${index}]`;
    const entry = plainObject(movement, path);
    const keys = Object.keys(entry).sort();
    if (keys.join(",") !== [...MOVEMENT_FIELDS].sort().join(",")) {
      throw new TypeError(`${path} must contain exactly ${MOVEMENT_FIELDS.join(", ")}`);
    }
    // A settlement movement is one transfer leg; reuse its exact normalization.
    const leg = buildTransferAssetInstruction({
      sourceAssetHoldingId: entry.sourceAssetHoldingId,
      quantity: entry.quantity,
      destinationAccountId: entry.recipient,
    }).Transfer.Asset;
    return { source: leg.source, recipient: leg.destination, quantity: leg.object };
  });
  const instruction = {
    Settlement: {
      Atomic: {
        network_id: networkIdLiteral(source.networkId, `${context}.networkId`),
        settlement_id: assertCanonicalIrohaName(source.settlementId, `${context}.settlementId`),
        movements,
        escrows: escrowInput.map((leg, index) => escrowLeg(leg, `${context}.escrows[${index}]`)),
        expires_at_height: positiveSafeInteger(source.expiresAtHeight, `${context}.expiresAtHeight`),
        metadata: metadataObject(source.metadata, `${context}.metadata`),
      },
    },
  };
  return canonicalSettleAtomicInstruction(instruction);
}

/**
 * Compute the exact `CanExecuteSettlement.intent_hash` literal of a canonical
 * `Settlement::Atomic` instruction (as returned by {@link buildSettleAtomicInstruction}).
 * @param {{Settlement: {Atomic: object}}} instruction
 * @returns {string}
 */
export function settleAtomicIntentHash(instruction) {
  const context = "settleAtomicIntentHash.instruction";
  const prefix = sharedNetworkPrefix(atomicAccounts(atomicPayload(instruction, context)), context);
  return nativeBinding().settleAtomicIntentHashJson(JSON.stringify(instruction), prefix);
}

/**
 * Compute the exact initiation and maturity `CanExecuteSettlement.intent_hash`
 * literals of one `Repo::Initiate` instruction.
 *
 * The counterparty consents to its cash debit with `initiation`; the collateral
 * holder (custodian, else counterparty) consents to the maturity collateral
 * release with `maturity`. Both use `settlementId = agreement_id`.
 * @param {{Repo: {Initiate: object}}} instruction
 * @returns {{ initiation: string, maturity: string }}
 */
export function repoIntentHashes(instruction) {
  const context = "repoIntentHashes.instruction";
  const initiate = instruction?.Repo?.Initiate;
  if (initiate === null || typeof initiate !== "object") {
    throw new TypeError(`${context} must be a { Repo: { Initiate } } instruction`);
  }
  const prefix = sharedNetworkPrefix([initiate.initiator], context);
  const hashes = nativeBinding().repoIntentHashesJson(JSON.stringify(instruction), prefix);
  return { initiation: hashes.initiation, maturity: hashes.maturity };
}
