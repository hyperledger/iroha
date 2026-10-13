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
import { buildTransferAssetInstruction } from "./instructionBuilders.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { NetworkId } from "./networkId.js";

const SETTLE_ATOMIC_FIELDS = new Set([
  "networkId",
  "settlementId",
  "movements",
  "expiresAtHeight",
  "metadata",
]);
const MOVEMENT_FIELDS = ["sourceAssetHoldingId", "recipient", "quantity"];

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
  return accounts.filter((account) => typeof account === "string" && account.length > 0);
}

function nativeBinding() {
  return resolveNativeRuntimeBinding(defaultNativeRuntime);
}

/**
 * Build a `Settlement::Atomic` instruction with movements in native canonical order.
 *
 * Each movement is normalized exactly like a transfer leg and the movements are
 * then sorted by the native `(AssetId, AccountId)` ordering. Movement counts,
 * duplicate keys, positive quantities and self-transfers are enforced natively.
 * Every debited bucket owner grants the submitter `CanExecuteSettlement` with
 * {@link settleAtomicIntentHash} of the returned instruction.
 * @param {{ networkId: NetworkId | string, settlementId: string, movements: Array<{ sourceAssetHoldingId: string, recipient: string, quantity: import("./numericV1.js").KotodamaQuantity | string | bigint }>, expiresAtHeight: number | bigint | string, metadata?: object | null }} options
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
        expires_at_height: positiveSafeInteger(source.expiresAtHeight, `${context}.expiresAtHeight`),
        metadata: metadataObject(source.metadata, `${context}.metadata`),
      },
    },
  };
  const prefix = sharedNetworkPrefix(atomicAccounts(instruction.Settlement.Atomic), context);
  return JSON.parse(
    nativeBinding().canonicalSettleAtomicInstructionJson(JSON.stringify(instruction), prefix),
  );
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
