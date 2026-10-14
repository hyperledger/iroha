// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Shape checks for native bond JSON served by Torii (`specs/finance/bond_ops.md` §6):
 * `BondRecord`s (`GET /v1/bonds/{bond_id}` and the `GET /v1/bonds` collection
 * pages) and entitlement rows (`GET /v1/bonds/{bond_id}/entitlements`).
 *
 * Records and rows are returned unchanged (snake_case native JSON). The checks
 * fail closed on a payload that is not a bond record or entitlement, so callers
 * never render an unrelated document as authoritative terms or servicing state.
 */

const LIFECYCLES = new Set(["Active", "Called", "Matured", "Defaulted"]);
const STATUSES = new Set([
  "Scheduled",
  "Recording",
  "Recorded",
  "Funded",
  "Closed",
  "Defaulted",
  "Cancelled",
]);
const RECORD_FIELDS = ["id", "vault", "terms", "state"];
const STATE_FIELDS = [
  "lifecycle",
  "outstanding_units",
  "redeemed_units",
  "retired_units",
  "transfers_frozen",
  "cashflows",
];
const CASHFLOW_STATE_FIELDS = [
  "terms",
  "status",
  "recording",
  "holders",
  "claimed_holders",
  "entitled_units",
  "amount_due",
  "funded",
  "paid",
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
  "payment_grace_ms",
  "call",
  "cashflows",
  "identifiers",
  "terms_sha256",
];
const ENTITLEMENT_FIELDS = ["id", "bond", "index", "holder", "units", "amount", "claimed", "claimed_at_ms"];

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

function requireCount(value, context) {
  const count = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new TypeError(`${context} must be a non-negative integer`);
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
  for (const field of ["outstanding_units", "redeemed_units", "retired_units"]) {
    requireString(state[field], `${context}.state.${field}`);
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
    requireCount(cashflow.holders, `${path}.holders`);
    requireCount(cashflow.claimed_holders, `${path}.claimed_holders`);
    if ((cashflow.status === "Recording") !== isObject(cashflow.recording)) {
      throw new TypeError(`${path}.recording must be present exactly while the cash flow is Recording`);
    }
    if (cashflow.terms?.index !== position) {
      throw new TypeError(`${path}.terms.index must equal its position`);
    }
  });
  return record;
}

/**
 * Validate one bond entitlement row (`GET /v1/bonds/{bond_id}/entitlements`).
 * @param {unknown} value
 * @param {string} context
 * @param {string} [bond] the bond every row must belong to
 * @returns {object}
 */
export function normalizeBondEntitlement(value, context = "bond entitlement", bond) {
  const row = requireFields(value, ENTITLEMENT_FIELDS, context);
  requireString(row.id, `${context}.id`);
  requireString(row.bond, `${context}.bond`);
  requireString(row.holder, `${context}.holder`);
  requireString(row.units, `${context}.units`);
  requireString(row.amount, `${context}.amount`);
  requireCount(row.index, `${context}.index`);
  if (typeof row.claimed !== "boolean") {
    throw new TypeError(`${context}.claimed must be a boolean`);
  }
  if (row.claimed !== (row.claimed_at_ms !== null)) {
    throw new TypeError(`${context}.claimed_at_ms must be present exactly when claimed`);
  }
  if (row.id !== `${row.index}:${row.holder}`) {
    throw new TypeError(`${context}.id must be <index>:<holder>`);
  }
  if (bond !== undefined && row.bond !== bond) {
    throw new TypeError(`${context} belongs to ${row.bond}, not the requested bond ${bond}`);
  }
  return row;
}

function normalizePage(value, context, normalizeItem) {
  const page = requireFields(value, ["items", "next_cursor"], context);
  if (!Array.isArray(page.items)) throw new TypeError(`${context}.items must be an array`);
  if (page.next_cursor !== null) requireString(page.next_cursor, `${context}.next_cursor`);
  const normalized = {
    items: page.items.map((item, index) => normalizeItem(item, `${context}.items[${index}]`)),
    nextCursor: page.next_cursor,
  };
  if (page.total !== undefined) normalized.total = requireCount(page.total, `${context}.total`);
  return normalized;
}

/**
 * Validate a `GET /v1/bonds` collection page.
 * @param {unknown} value
 * @param {string} context
 * @returns {{ items: object[], nextCursor: string | null, total?: number | bigint }}
 */
export function normalizeBondRecordPage(value, context = "bond page") {
  return normalizePage(value, context, normalizeBondRecord);
}

/**
 * Validate a `GET /v1/bonds/{bond_id}/entitlements` collection page.
 * @param {unknown} value
 * @param {string} context
 * @param {string} bond
 * @returns {{ items: object[], nextCursor: string | null, total?: number | bigint }}
 */
export function normalizeBondEntitlementPage(value, context, bond) {
  return normalizePage(value, context, (item, path) => normalizeBondEntitlement(item, path, bond));
}

/** Most bond records one `listBonds` page may request (each record is at most ~400 KiB). */
export const BOND_RECORD_PAGE_MAX_ITEMS = 20;
/** Response cap of one `listBonds` page. */
export const BOND_RECORD_PAGE_MAX_BYTES = 16 * 1024 * 1024;
/** Response cap of one `getBond` record (at most 401 cash flows). */
export const BOND_RECORD_MAX_BYTES = 2 * 1024 * 1024;
/** Most entitlement rows one `getBondEntitlements` page may request. */
export const BOND_ENTITLEMENT_PAGE_MAX_ITEMS = 1000;
/** Response cap of one `getBondEntitlements` page. */
export const BOND_ENTITLEMENT_PAGE_MAX_BYTES = 4 * 1024 * 1024;

function pageLimit(value, maximum, context) {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${context}.limit must be an integer in 1..=${maximum}`);
  }
  return value;
}

function pageCursor(value, context) {
  if (value === undefined || value === null) return undefined;
  return requireString(value, `${context}.cursor`);
}

/**
 * Query parameters of a `GET /v1/bonds` page (`limit`, `cursor`, `filter`).
 * @param {{ limit?: number, cursor?: string | null, filter?: string }} options
 * @param {string} context
 * @returns {Record<string, string>}
 */
export function bondRecordPageParams(options, context) {
  const params = { limit: String(pageLimit(options.limit, BOND_RECORD_PAGE_MAX_ITEMS, context)) };
  const cursor = pageCursor(options.cursor, context);
  if (cursor !== undefined) params.cursor = cursor;
  if (options.filter !== undefined) params.filter = requireString(options.filter, `${context}.filter`);
  return params;
}

/**
 * Query parameters of a `GET /v1/bonds/{bond_id}/entitlements` page; `index` and
 * `holder` (an already canonical account literal) become an exact filter.
 * @param {{ index?: number, holder?: string, limit?: number, cursor?: string | null }} options
 * @param {string} context
 * @returns {Record<string, string>}
 */
export function bondEntitlementPageParams(options, context) {
  const params = {
    limit: String(pageLimit(options.limit, BOND_ENTITLEMENT_PAGE_MAX_ITEMS, context)),
  };
  const cursor = pageCursor(options.cursor, context);
  if (cursor !== undefined) params.cursor = cursor;
  const clauses = [];
  if (options.index !== undefined) {
    if (!Number.isSafeInteger(options.index) || options.index < 0 || options.index > 0xffff) {
      throw new RangeError(`${context}.index must be an integer in 0..=65535`);
    }
    clauses.push(`index = ${options.index}`);
  }
  if (options.holder !== undefined) {
    clauses.push(`holder = ${JSON.stringify(requireString(options.holder, `${context}.holder`))}`);
  }
  if (clauses.length > 0) params.filter = clauses.join(" and ");
  return params;
}
