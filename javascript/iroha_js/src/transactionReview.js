// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Human-readable review of an unsigned transaction payload (Node.js).
 *
 * Wallets that receive a Connect `SignRequestTx` decode the exact payload
 * natively, require its NetworkId and authority to match the session, and show
 * one review row per instruction before signing the payload hash. All rendered
 * text is sanitized (control and bidirectional-control characters are escaped)
 * and bounded; payloads with more than 64 instructions are refused.
 */

import { Buffer } from "buffer";

import { AccountAddress } from "./address.js";
import { NetworkId } from "./networkId.js";
import { normalizeAccountId } from "./normalizers.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { noritoDecodeInstruction } from "./norito.js";

export const TRANSACTION_REVIEW_SCHEMA = "iroha.connect-transaction-review.v1";
export const TRANSACTION_REVIEW_MAX_INSTRUCTIONS = 64;
const MAX_FIELD_CHARS = 512;
const MAX_JSON_CHARS = 16 * 1024;
const UNSAFE_CHARACTERS =
  /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

/** Escape control, format (including bidi) and line-separator characters, then bound the text. */
export function sanitizeReviewText(value, maximum = MAX_FIELD_CHARS) {
  const text = typeof value === "string" ? value : JSON.stringify(value) ?? String(value);
  const escaped = text.replace(
    UNSAFE_CHARACTERS,
    (character) => `\\u{${character.codePointAt(0).toString(16).toUpperCase()}}`,
  );
  return escaped.length > maximum ? `${escaped.slice(0, maximum - 1)}\u2026` : escaped;
}

function field(label, value) {
  return { label, value: sanitizeReviewText(value) };
}

function conditionSummary(conditions) {
  return (Array.isArray(conditions) ? conditions : [])
    .map((condition) => {
      const value = condition?.value ?? {};
      if (condition?.kind === "Within") return `${value.id}: within ${value.duration_ms} ms`;
      const predicate = value.predicate ?? {};
      const expected = predicate.kind === "Equals"
        ? `= ${JSON.stringify(predicate.value?.value)}`
        : `<= ${predicate.value}`;
      return `${value.sequence}. ${value.id} by ${value.attestor} ${expected}`;
    })
    .join("; ");
}

function escrowLegFields(prefix, leg) {
  return [
    field(`${prefix} escrow`, leg.escrow_id),
    field(`${prefix} from`, leg.source),
    field(`${prefix} to`, leg.beneficiary),
    field(`${prefix} amount`, leg.amount),
    field(`${prefix} conditions`, conditionSummary(leg.conditions)),
    field(`${prefix} expires at (ms)`, leg.expires_at_ms),
  ];
}

/** Describe one decoded instruction JSON value. */
function describeInstruction(instruction) {
  const [key] = Object.keys(instruction ?? {});
  const body = instruction?.[key] ?? {};
  switch (key) {
    case "Transfer": {
      const asset = body.Asset;
      if (asset) {
        return {
          kind: "transfer",
          title: "Transfer asset",
          fields: [
            field("from", asset.source),
            field("to", asset.destination),
            field("quantity", asset.object),
          ],
        };
      }
      break;
    }
    case "Mint":
    case "Burn": {
      const asset = body.Asset;
      if (asset) {
        return {
          kind: key.toLowerCase(),
          title: `${key} asset`,
          fields: [field("asset", asset.destination), field("quantity", asset.object)],
        };
      }
      break;
    }
    case "Grant": {
      const permission = body.Permission;
      if (permission) {
        return {
          kind: "grant_permission",
          title: `Grant ${permission.object?.name}`,
          fields: [
            field("to", permission.destination),
            field("permission", permission.object?.name),
            field("payload", permission.object?.payload),
          ],
        };
      }
      break;
    }
    case "Settlement": {
      const atomic = body.Atomic;
      if (atomic) {
        const fields = [
          field("settlement", atomic.settlement_id),
          field("network", atomic.network_id),
          field("expires at height", atomic.expires_at_height),
        ];
        (atomic.movements ?? []).forEach((movement, index) => {
          fields.push(field(`movement ${index + 1}`, `${movement.quantity} from ${movement.source} to ${movement.recipient}`));
        });
        (atomic.escrows ?? []).forEach((leg, index) => {
          fields.push(...escrowLegFields(`leg ${index + 1}`, leg));
        });
        return { kind: "settlement_atomic", title: "Atomic settlement", fields };
      }
      return { kind: "settlement", title: `Settlement ${Object.keys(body)[0]}`, fields: [] };
    }
    case "OpenConditionalEscrow":
      return {
        kind: "escrow",
        title: "Open conditional escrow",
        fields: escrowLegFields("escrow", { ...body, source: `${body.asset_definition} (signer)` }),
      };
    case "AttestEscrowCondition":
      return {
        kind: "escrow",
        title: "Attest escrow condition",
        fields: [
          field("escrow", body.escrow_id),
          field("condition", body.condition_id),
          field("value", body.value?.value),
          field("evidence", body.evidence_hash ?? "none"),
        ],
      };
    case "ExpireConditionalEscrow":
      return { kind: "escrow", title: "Expire conditional escrow", fields: [field("escrow", body.escrow_id)] };
    case "Repo": {
      const [variant] = Object.keys(body);
      const terms = body[variant] ?? {};
      if (variant === "Initiate") {
        return {
          kind: "repo",
          title: "Initiate repo",
          fields: [
            field("agreement", terms.agreement_id),
            field("initiator", terms.initiator),
            field("counterparty", terms.counterparty),
            field("custodian", terms.custodian ?? "none"),
            field("cash", `${terms.cash_leg?.quantity} of ${terms.cash_leg?.asset_definition_id}`),
            field("collateral", `${terms.collateral_leg?.quantity} of ${terms.collateral_leg?.asset_definition_id}`),
            field("rate (bps)", terms.rate_bps),
            field("maturity (ms)", terms.maturity_timestamp_ms),
            field("haircut (bps)", terms.governance?.haircut_bps),
            field("margin frequency (s)", terms.governance?.margin_frequency_secs),
            field("early repayment", terms.governance?.allow_early_repayment === true ? "allowed" : "not allowed"),
          ],
        };
      }
      return { kind: "repo", title: `Repo ${variant}`, fields: [field("agreement", terms.agreement_id)] };
    }
    default:
      break;
  }
  return { kind: "unknown", title: sanitizeReviewText(key ?? "instruction", 128), fields: [] };
}

function instructionFrames(executable, warnings) {
  if (Array.isArray(executable?.Instructions)) return executable.Instructions;
  if (Array.isArray(executable?.Batch)) {
    return executable.Batch.map((entry) => {
      if (entry?.Instruction !== undefined) return entry.Instruction;
      warnings.push("the batch contains a contract call that cannot be reviewed as an instruction");
      return null;
    });
  }
  warnings.push("the executable is not an instruction list and cannot be reviewed");
  return [];
}

/**
 * Decode and review one unsigned transaction payload for a signer.
 *
 * Fails closed when the payload is not canonical, its NetworkId or authority
 * differ from the expected session values, or it has more than 64 instructions.
 * @param {ArrayBufferView | ArrayBuffer | Buffer} payloadBytes
 * @param {{ networkId: NetworkId, authority: string }} expected
 */
export function reviewTransactionPayload(payloadBytes, expected) {
  const bytes = Buffer.from(
    payloadBytes instanceof ArrayBuffer ? new Uint8Array(payloadBytes) : payloadBytes,
  );
  if (!(expected?.networkId instanceof NetworkId)) {
    throw new TypeError("expected.networkId must be a NetworkId");
  }
  const authority = normalizeAccountId(expected.authority, "expected.authority");
  const { chainDiscriminant } = AccountAddress.parseEncoded(authority);
  const native = resolveNativeRuntimeBinding(defaultNativeRuntime);
  const payload = JSON.parse(native.decodeTransactionPayloadJson(bytes, chainDiscriminant));
  const networkLiteral = payload.domain?.kind === "network" ? payload.domain.value : null;
  if (networkLiteral !== expected.networkId.toString()) {
    throw new Error("transaction payload NetworkId differs from the session network");
  }
  if (payload.authority !== authority) {
    throw new Error("transaction payload authority differs from the approved account");
  }
  const warnings = [];
  const frames = instructionFrames(payload.instructions, warnings);
  if (frames.length > TRANSACTION_REVIEW_MAX_INSTRUCTIONS) {
    throw new RangeError(
      `transaction payload has ${frames.length} instructions; at most ${TRANSACTION_REVIEW_MAX_INSTRUCTIONS} can be reviewed`,
    );
  }
  const instructions = frames.map((frame, index) => {
    if (typeof frame !== "string") {
      return { index: index + 1, kind: "undecoded", title: "Contract call", fields: [], json: null };
    }
    const decoded = noritoDecodeInstruction(Buffer.from(frame, "base64"), chainDiscriminant);
    const description = describeInstruction(decoded);
    return {
      index: index + 1,
      ...description,
      json: sanitizeReviewText(JSON.stringify(decoded), MAX_JSON_CHARS),
    };
  });
  const feeValue = payload.fee_payment?.value ?? {};
  return {
    schema: TRANSACTION_REVIEW_SCHEMA,
    networkId: expected.networkId.toString(),
    authority,
    payloadHashHex: Buffer.from(native.transactionPayloadSigningHash(bytes)).toString("hex"),
    payloadByteLength: bytes.length,
    creationTimeMs: String(payload.creation_time_ms),
    ttlMs: payload.time_to_live_ms === null ? null : String(payload.time_to_live_ms),
    feePayment: {
      payer: payload.fee_payment?.payer ?? null,
      sponsorProgram: feeValue.program_id
        ? sanitizeReviewText(
            `${feeValue.program_id.sponsor}/${feeValue.program_id.name}@${feeValue.program_revision}`,
          )
        : null,
      gasLimit: feeValue.gas_limit === null || feeValue.gas_limit === undefined ? null : String(feeValue.gas_limit),
      chargeLimits: (feeValue.charge_limits ?? []).map((limit) => ({
        kind: limit.kind?.kind ?? null,
        assetDefinitionId: limit.asset_definition_id,
        maxAmount: limit.max_amount,
      })),
    },
    metadata: sanitizeReviewText(JSON.stringify(payload.metadata ?? {}), MAX_JSON_CHARS),
    instructions,
    warnings,
  };
}
