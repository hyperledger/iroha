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
import { normalizeBondEntitlement, normalizeBondRecord } from "./bondRecords.js";

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

/** Render an owner-qualified settlement id in its canonical `reference$owner` text form. */
function settlementIdText(id) {
  return id !== null && typeof id === "object" && typeof id.reference === "string"
    ? `${id.reference}$${id.owner}`
    : id;
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

function reviewDate(ms) {
  const date = new Date(Number(ms));
  return Number.isFinite(date.getTime()) ? date.toISOString() : String(ms);
}

function bondCashflowSummary(terms) {
  return `${terms.kind} ${terms.amount_per_unit} per unit; record ${reviewDate(terms.record_date_ms)}; pay ${reviewDate(terms.payment_date_ms)}`;
}

/**
 * Normalize the optional bond review context: native records (for example from
 * `ToriiClient.getBond`) with any entitlement rows of that bond (from
 * `ToriiClient.getBondEntitlements`).
 */
function bondReviewContext(bonds) {
  const context = new Map();
  if (bonds === undefined || bonds === null) return context;
  if (!Array.isArray(bonds)) {
    throw new TypeError("expected.bonds must be an array of { record, entitlements? }");
  }
  bonds.forEach((entry, index) => {
    const name = `expected.bonds[${index}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`${name} must be an object`);
    }
    const unknown = Object.keys(entry).filter((key) => key !== "record" && key !== "entitlements");
    if (unknown.length > 0) throw new TypeError(`${name}.${unknown[0]} is not supported`);
    const record = normalizeBondRecord(entry.record, `${name}.record`);
    const rows = entry.entitlements ?? [];
    if (!Array.isArray(rows)) throw new TypeError(`${name}.entitlements must be an array`);
    const entitlements = rows.map((row, position) => normalizeBondEntitlement(
      row,
      `${name}.entitlements[${position}]`,
      record.id,
    ));
    context.set(record.id, { record, entitlements });
  });
  return context;
}

/** Describe one bond-kernel instruction, enriched by its record and entitlements when supplied. */
function describeBond(body, bonds) {
  const [variant] = Object.keys(body);
  const payload = body[variant] ?? {};
  const known = bonds.get(payload.bond);
  const record = known?.record;
  const cashflow = Number.isInteger(payload.index)
    ? record?.state?.cashflows?.[payload.index]
    : undefined;
  const flowTerms = cashflow?.terms;
  const paymentAsset = record?.terms?.payment_asset;
  const head = [field("bond", payload.bond)];
  if (payload.index !== undefined) head.push(field("cash flow", `#${payload.index}`));
  const flowFields = () => (flowTerms
    ? [
        field("cash flow kind", flowTerms.kind),
        field("record date", reviewDate(flowTerms.record_date_ms)),
        field("payment date", reviewDate(flowTerms.payment_date_ms)),
        field("amount per unit", `${flowTerms.amount_per_unit} of ${paymentAsset}`),
        field("status", cashflow.status),
      ]
    : [field("cash flow kind", record
      ? "unknown (cash flow not in the supplied bond record)"
      : "unknown (bond record not supplied)")]);
  switch (variant) {
    case "Register": {
      const terms = payload.terms ?? {};
      const ids = terms.identifiers ?? {};
      const call = terms.call;
      const schedule = Array.isArray(terms.cashflows) ? terms.cashflows : [];
      return {
        kind: "bond",
        title: "Register bond",
        fields: [
          ...head,
          field("issuer", terms.issuer),
          field("paying agent", terms.paying_agent),
          field("payment asset", terms.payment_asset),
          field("denomination", `${terms.denomination} per unit`),
          field("coupon", terms.coupon_frequency === 0
            ? "zero coupon"
            : `${terms.coupon_rate_bps} bps a year, ${terms.coupon_frequency} payment(s) a year`),
          field("day count", terms.day_count),
          field("issue date", reviewDate(terms.issue_date_ms)),
          field("maturity date", reviewDate(terms.maturity_date_ms)),
          field("redemption price (bps)", terms.redemption_price_bps),
          field("payment grace", `${terms.payment_grace_ms} ms`),
          field("call", call
            ? `from ${reviewDate(call.first_call_date_ms)} at ${call.price_bps} bps, notice ${call.notice_ms} ms`
            : "none"),
          field("cash flows", schedule.length),
          ...schedule.map((entry) => field(`cash flow #${entry.index}`, bondCashflowSummary(entry))),
          field("ISIN", ids.isin ?? "none"),
          field("CFI", ids.cfi ?? "none"),
          field("issuer LEI", ids.issuer_lei ?? "none"),
          field("BDT version", ids.bdt_version),
          field("BDT document SHA-256", ids.bdt_document_sha256 ?? "none"),
          field("terms SHA-256", terms.terms_sha256),
        ],
      };
    }
    case "RecordCashflow": {
      const fields = [...head, ...flowFields()];
      if (cashflow?.status === "Recording") {
        fields.push(field("progress", `${cashflow.holders} holder(s) recorded so far; repeat until Recorded`));
      }
      fields.push(field("books", "closed from the record date until the recording completes"));
      if (flowTerms?.kind === "Redemption") {
        fields.push(field("effect", "recording the redemption freezes every transfer of the bond"));
      }
      return { kind: "bond", title: "Record bond cash flow", fields };
    }
    case "FundCashflow":
      return {
        kind: "bond",
        title: "Fund bond cash flow",
        fields: [
          ...head,
          field("from", payload.source),
          field("to", record?.vault ?? "bond vault"),
          field("amount", cashflow?.status === "Recorded"
            ? `${cashflow.amount_due} of ${paymentAsset}`
            : "the recorded amount due"),
          ...flowFields(),
        ],
      };
    case "ClaimCashflow": {
      const entitlement = known?.entitlements?.find((row) => String(row.index) === String(payload.index)
        && row.holder === payload.holder);
      const units = entitlement?.units;
      const title = flowTerms?.kind === "Redemption"
        ? "Claim bond redemption"
        : flowTerms?.kind === "Coupon" ? "Claim bond coupon" : "Claim bond cash flow";
      const fields = [
        ...head,
        field("holder", payload.holder),
        field("destination", payload.holder),
        field("units", units ?? "entitled units"),
        field("amount", entitlement
          ? `${entitlement.amount} of ${paymentAsset ?? "the payment asset"}`
          : "the holder's entitlement"),
        ...flowFields(),
      ];
      if (entitlement?.claimed) fields.push(field("warning", "this entitlement was already claimed"));
      if (flowTerms?.kind === "Redemption") {
        fields.push(field("effect", `burns the holder's ${units ?? "entitled"} units of the bond`));
      }
      return { kind: "bond", title, fields };
    }
    case "CloseCashflow":
      return {
        kind: "bond",
        title: "Close bond cash flow",
        fields: [
          ...head,
          field("unclaimed", cashflow
            ? `${Number(cashflow.holders) - Number(cashflow.claimed_holders)} holder(s) stay claimable from the vault`
            : "unclaimed entitlements stay claimable from the vault"),
          ...flowFields(),
        ],
      };
    case "Call": {
      const call = record?.terms?.call;
      return {
        kind: "bond",
        title: "Call bond",
        fields: [
          ...head,
          field("call date", reviewDate(payload.call_date_ms)),
          field("call price (bps)", call ? call.price_bps : "per the registered call terms"),
        ],
      };
    }
    case "DeclareDefault":
      return {
        kind: "bond",
        title: "Declare bond default",
        fields: [
          ...head,
          field("evidence SHA-256", payload.evidence_sha256),
          field("payment grace", record ? `${record.terms.payment_grace_ms} ms` : "per the registered terms"),
          ...flowFields(),
        ],
      };
    case "ReplacePayingAgent":
      return {
        kind: "bond",
        title: "Replace bond paying agent",
        fields: [
          ...head,
          field("paying agent", payload.paying_agent),
          field("replaces", record?.terms?.paying_agent ?? "the current paying agent"),
        ],
      };
    case "RetireTreasuryUnits": {
      const fields = [
        ...head,
        field("quantity", `${payload.quantity} unit(s)`),
        field("from", `the issuer's own balance (${record?.terms?.issuer ?? "signer must be the issuer"})`),
        field("effect", "burns the units; the outstanding supply falls by the same amount"),
      ];
      const outstanding = record?.state?.outstanding_units;
      if (typeof outstanding === "string" && /^\d+$/u.test(outstanding)
        && /^\d+$/u.test(String(payload.quantity))) {
        const remaining = BigInt(outstanding) - BigInt(payload.quantity);
        fields.push(field("outstanding", remaining < 0n
          ? `${outstanding} (fewer than the retired quantity)`
          : `from ${outstanding} to ${remaining}`));
        if (remaining === 0n) {
          fields.push(field("effect", "no unit remains outstanding: every cash flow not yet recorded is cancelled"));
        }
      }
      return { kind: "bond", title: "Retire bond treasury units", fields };
    }
    default:
      return { kind: "bond", title: `Bond ${sanitizeReviewText(variant ?? "instruction", 64)}`, fields: head };
  }
}

/** Describe one decoded instruction JSON value. */
function describeInstruction(instruction, bonds) {
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
          field("settlement", settlementIdText(atomic.settlement_id)),
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
    case "Bond":
      return describeBond(body, bonds);
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
 * Bond instructions are described from the payload alone; supplying
 * `expected.bonds` (records from `ToriiClient.getBond` with entitlement rows
 * from `ToriiClient.getBondEntitlements`) adds the cash-flow kind, dates,
 * amounts, entitled units, the holder's exact payment and the vault.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} payloadBytes
 * @param {{ networkId: NetworkId, authority: string, bonds?: Array<{ record: object, entitlements?: object[] }> }} expected
 */
export function reviewTransactionPayload(payloadBytes, expected) {
  const bytes = Buffer.from(
    payloadBytes instanceof ArrayBuffer ? new Uint8Array(payloadBytes) : payloadBytes,
  );
  if (!(expected?.networkId instanceof NetworkId)) {
    throw new TypeError("expected.networkId must be a NetworkId");
  }
  const authority = normalizeAccountId(expected.authority, "expected.authority");
  const bonds = bondReviewContext(expected.bonds);
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
    const description = describeInstruction(decoded, bonds);
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
