// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Shape checks for native `BondRecord` JSON served by Torii
 * (`GET /v1/bonds`, `GET /v1/bonds/{bond_id}`; `specs/finance/bond_ops.md` §6).
 *
 * Records are returned unchanged (snake_case native JSON). The checks fail
 * closed on a payload that is not a bond record so callers never render an
 * unrelated document as authoritative terms or servicing state.
 */

const LIFECYCLES = new Set(["Active", "Called", "Matured", "Defaulted"]);
const STATUSES = new Set(["Scheduled", "Recorded", "Funded", "Closed", "Defaulted", "Cancelled"]);
const RECORD_FIELDS = ["id", "vault", "terms", "state"];
const STATE_FIELDS = ["lifecycle", "outstanding_units", "redeemed_units", "transfers_frozen", "cashflows"];
const CASHFLOW_STATE_FIELDS = [
  "terms",
  "status",
  "snapshot",
  "entitled_units",
  "amount_due",
  "funded",
  "paid",
  "claimed",
  "recorded_at_ms",
  "funded_at_ms",
  "closed_at_ms",
  "evidence_sha256",
];
const TERMS_FIELDS = [
  "issuer",
  "paying_agent",
  "payment_asset",
  "denomination",
  "coupon_rate_bps",
  "coupon_frequency",
  "day_count",
  "issue_date_ms",
  "maturity_date_ms",
  "redemption_price_bps",
  "call",
  "cashflows",
  "identifiers",
  "terms_sha256",
];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireFields(value, fields, context) {
  if (!isObject(value)) throw new TypeError(`${context} must be an object`);
  const missing = fields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) {
    throw new TypeError(`${context} is missing field(s): ${missing.join(", ")}`);
  }
  return value;
}

function requireString(value, context) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${context} must be a non-empty string`);
  }
  return value;
}

/**
 * Validate one native bond record and return it unchanged.
 * @param {unknown} value
 * @param {string} context
 * @returns {object}
 */
export function normalizeBondRecord(value, context = "bond record") {
  const record = requireFields(value, RECORD_FIELDS, context);
  requireString(record.id, `${context}.id`);
  requireString(record.vault, `${context}.vault`);
  requireFields(record.terms, TERMS_FIELDS, `${context}.terms`);
  if (!Array.isArray(record.terms.cashflows)) {
    throw new TypeError(`${context}.terms.cashflows must be an array`);
  }
  const state = requireFields(record.state, STATE_FIELDS, `${context}.state`);
  if (!LIFECYCLES.has(state.lifecycle)) {
    throw new TypeError(`${context}.state.lifecycle must be Active, Called, Matured or Defaulted`);
  }
  if (typeof state.transfers_frozen !== "boolean") {
    throw new TypeError(`${context}.state.transfers_frozen must be a boolean`);
  }
  if (!Array.isArray(state.cashflows)) {
    throw new TypeError(`${context}.state.cashflows must be an array`);
  }
  state.cashflows.forEach((cashflow, position) => {
    const path = `${context}.state.cashflows[${position}]`;
    requireFields(cashflow, CASHFLOW_STATE_FIELDS, path);
    if (!STATUSES.has(cashflow.status)) {
      throw new TypeError(`${path}.status is not a bond cash-flow status`);
    }
    if (!isObject(cashflow.snapshot) || !Array.isArray(cashflow.claimed)) {
      throw new TypeError(`${path} must carry a snapshot object and a claimed array`);
    }
    if (cashflow.terms?.index !== position) {
      throw new TypeError(`${path}.terms.index must equal its position`);
    }
  });
  return record;
}

/**
 * Validate a `GET /v1/bonds` response (an array of records).
 * @param {unknown} value
 * @param {string} context
 * @returns {object[]}
 */
export function normalizeBondRecordList(value, context = "bond list") {
  if (!Array.isArray(value)) throw new TypeError(`${context} must be an array of bond records`);
  return value.map((record, index) => normalizeBondRecord(record, `${context}[${index}]`));
}
