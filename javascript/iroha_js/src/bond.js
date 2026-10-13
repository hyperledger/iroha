// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Native bond-servicing kernel helpers (`specs/finance/bond_ops.md`).
 *
 * The builders return the closed `{ "Bond": { <Variant>: payload } }` envelopes
 * admitted by the native codec (`BondInstructionBox`, wire id `iroha.bond`).
 * `buildBondSchedule` and `validateBondTerms` mirror the data model's
 * `fixed_rate_bullet_schedule` and `BondTerms::validate` exactly, with integer
 * date arithmetic and exact decimal arithmetic on bigint mantissas (no floating
 * point); their messages equal Core's `bond.invalid_terms: ...` rejections. Core
 * still performs every state-dependent check (signer, ownership, scale 0,
 * minted supply, block time). `bondVaultAccountId` delegates to the native
 * derivation.
 */

import { KotodamaQuantity, NumericV1, NumericV1Error } from "./numericV1.js";
import {
  normalizeAccountId,
  normalizeAssetDefinitionId,
  normalizeAssetHoldingId,
} from "./normalizers.js";
import { createValidationError, ValidationErrorCode } from "./validationError.js";
import { assertAllowedFields, assertExactFields } from "./instructionBuilderPrimitives.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";

/** Maximum number of scheduled cash flows in registered terms. */
export const BOND_MAX_CASHFLOWS = 400;
/** Maximum number of investor holders captured by one record-date snapshot. */
export const BOND_MAX_SNAPSHOT_HOLDERS = 4096;
/** Coupon frequencies (payments per year) admitted by the regular fixed-rate rule. */
export const BOND_COUPON_FREQUENCIES = Object.freeze([0, 1, 2, 4, 12]);
/** Day-count labels recorded with the terms (a legal label; periods are regular). */
export const BOND_DAY_COUNTS = Object.freeze(["ActActIcma", "Thirty360", "Act360", "Act365Fixed"]);
/** Cash-flow kinds of a bond schedule. */
export const BOND_CASHFLOW_KINDS = Object.freeze(["Coupon", "Redemption"]);

const BPS_DENOMINATOR = 10_000n;
const MAX_SCALE = 28;
const MANTISSA_MAX = (1n << 511n) - 1n;
const MS_PER_DAY = 86_400_000;
const U8_MAX = 0xff;
const U16_MAX = 0xffff;
const U32_MAX = 0xffff_ffff;
const ISIN_MAX = 12;
const CFI_MAX = 6;
const LEI_MAX = 20;
const BDT_VERSION_MAX = 32;

const NUMERIC_REPEATING = "Exact quotient is a repeating decimal";
const NUMERIC_EXACT_SCALE = "Exact terminating quotient needs more than 28 fractional digits";
const NUMERIC_SCALE = "Canonical exact result needs a scale greater than 28";
const NUMERIC_MANTISSA = "Canonical result mantissa is outside `-2^511..=2^511-1`";

function fail(code, message, path) {
  throw createValidationError(code, message, path);
}

/** Throw Core's exact `bond.invalid_terms` rejection. */
function invalidTerms(message, path) {
  fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `bond.invalid_terms: ${message}`, path);
}

class ExactDecimalError extends Error {}

function plainObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(ValidationErrorCode.INVALID_OBJECT, `${name} must be a plain object`, name);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(ValidationErrorCode.INVALID_OBJECT, `${name} must be a plain object`, name);
  }
  return value;
}

function present(source, key) {
  return Object.prototype.hasOwnProperty.call(source, key)
    && source[key] !== undefined && source[key] !== null;
}

/** Exact unsigned integer in `0..=maximum` (number, bigint or decimal string). */
function boundedInteger(value, name, maximum) {
  let integer;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${name} must be a non-negative safe integer`, name);
    }
    integer = value;
  } else if (typeof value === "bigint") {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${name} must be a non-negative safe integer`, name);
    }
    integer = Number(value);
  } else if (typeof value === "string" && /^(?:0|[1-9]\d*)$/u.test(value)) {
    const parsed = BigInt(value);
    if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${name} must be a non-negative safe integer`, name);
    }
    integer = Number(parsed);
  } else {
    fail(ValidationErrorCode.INVALID_NUMERIC, `${name} must be a non-negative integer`, name);
  }
  if (integer > maximum) {
    fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${name} must not exceed ${maximum}`, name);
  }
  return integer;
}

const u8 = (value, name) => boundedInteger(value, name, U8_MAX);
const u16 = (value, name) => boundedInteger(value, name, U16_MAX);
const u32 = (value, name) => boundedInteger(value, name, U32_MAX);
/** Unix milliseconds and other u64 values; JSON numbers stay within the safe range. */
const u64 = (value, name) => boundedInteger(value, name, Number.MAX_SAFE_INTEGER);

/** Canonical non-negative quantity text from a KotodamaQuantity, canonical string or bigint. */
function quantityText(value, name) {
  try {
    if (value instanceof KotodamaQuantity) return NumericV1.encodeQuantityJson(value);
    if (typeof value === "string") return NumericV1.decodeQuantityJson(value).toString();
    if (typeof value === "bigint") return new KotodamaQuantity(value, 0).toString();
  } catch (error) {
    if (!(error instanceof NumericV1Error)) throw error;
    fail(
      ValidationErrorCode.INVALID_NUMERIC,
      `${name} must be a canonical non-negative quantity (${error.code})`,
      name,
    );
  }
  fail(
    ValidationErrorCode.INVALID_NUMERIC,
    `${name} must be a KotodamaQuantity, canonical quantity string, or bigint; JavaScript numbers are not lossless quantity inputs`,
    name,
  );
}

function decimal(text) {
  const parsed = NumericV1.decodeQuantityJson(text);
  return { mantissa: parsed.mantissa, scale: parsed.scale };
}

function canonicalDecimal(mantissa, scale) {
  let m = mantissa;
  let s = scale;
  while (s > 0 && m % 10n === 0n) {
    m /= 10n;
    s -= 1;
  }
  if (m === 0n) s = 0;
  return { mantissa: m, scale: s };
}

function decimalText({ mantissa, scale }) {
  const digits = mantissa.toString();
  if (scale === 0) return digits;
  const padded = digits.padStart(scale + 1, "0");
  return `${padded.slice(0, -scale)}.${padded.slice(-scale)}`;
}

function gcd(left, right) {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

/** `value × multiplier / divisor` as an exact canonical decimal (Rust `try_mul_div_decimal_exact`). */
function mulDivExact(value, multiplier, divisor) {
  const numerator = value.mantissa * multiplier;
  const denominator = divisor * 10n ** BigInt(value.scale);
  const common = gcd(numerator, denominator);
  const reducedNumerator = numerator / common;
  let reduced = denominator / common;
  let twos = 0;
  let fives = 0;
  while (reduced > 1n && reduced % 2n === 0n) {
    reduced /= 2n;
    twos += 1;
  }
  while (reduced > 1n && reduced % 5n === 0n) {
    reduced /= 5n;
    fives += 1;
  }
  if (reduced !== 1n) throw new ExactDecimalError(NUMERIC_REPEATING);
  const scale = Math.max(twos, fives);
  if (scale > MAX_SCALE) throw new ExactDecimalError(NUMERIC_EXACT_SCALE);
  const mantissa = reducedNumerator * (10n ** BigInt(scale) / (denominator / common));
  if (mantissa > MANTISSA_MAX) throw new ExactDecimalError(NUMERIC_MANTISSA);
  return canonicalDecimal(mantissa, scale);
}

/** Exact coupon per unit: `denomination × rate_bps / (10_000 × frequency)`. */
function regularCouponAmount(denominationText, couponRateBps, couponFrequency) {
  try {
    return decimalText(mulDivExact(
      decimal(denominationText),
      BigInt(couponRateBps),
      BPS_DENOMINATOR * BigInt(couponFrequency),
    ));
  } catch (error) {
    if (!(error instanceof ExactDecimalError)) throw error;
    return invalidTerms(
      `coupon amount ${denominationText} x ${couponRateBps}bps / ${couponFrequency} is not an exact decimal: ${error.message}`,
    );
  }
}

/** Exact redemption per unit: `denomination × price_bps / 10_000`. */
function redemptionAmount(denominationText, priceBps) {
  try {
    return decimalText(mulDivExact(decimal(denominationText), BigInt(priceBps), BPS_DENOMINATOR));
  } catch (error) {
    if (!(error instanceof ExactDecimalError)) throw error;
    return invalidTerms(
      `redemption amount ${denominationText} x ${priceBps}bps is not an exact decimal: ${error.message}`,
    );
  }
}

// Proleptic Gregorian calendar conversions on whole days since 1970-01-01, ported
// from the data model so schedule dates match Core bit for bit.
function civilFromDays(days) {
  const z = days + 719_468;
  const era = Math.floor(z / 146_097);
  const doe = z - era * 146_097;
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1_460) + Math.floor(doe / 36_524) - Math.floor(doe / 146_096)) / 365,
  );
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp < 10 ? mp + 3 : mp - 9;
  return [month <= 2 ? y + 1 : y, month, day];
}

function daysFromCivil(year, month, day) {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = month > 2 ? month - 3 : month + 9;
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146_097 + doe - 719_468;
}

function daysInMonth(year, month) {
  const [nextYear, nextMonth] = month === 12 ? [year + 1, 1] : [year, month + 1];
  return daysFromCivil(nextYear, nextMonth, 1) - daysFromCivil(year, month, 1);
}

/** Step back whole calendar months with end-of-month clamping, keeping the time of day. */
function monthsBefore(timestampMs, months) {
  const days = Math.floor(timestampMs / MS_PER_DAY);
  const timeOfDay = timestampMs - days * MS_PER_DAY;
  const [year, month, day] = civilFromDays(days);
  const total = year * 12 + month - 1 - months;
  const targetYear = Math.floor(total / 12);
  const targetMonth = total - targetYear * 12 + 1;
  const targetDay = Math.min(day, daysInMonth(targetYear, targetMonth));
  const targetDays = daysFromCivil(targetYear, targetMonth, targetDay);
  if (targetDays < 0) return null;
  const result = targetDays * MS_PER_DAY + timeOfDay;
  return Number.isSafeInteger(result) ? result : null;
}

const SCHEDULE_FIELDS = [
  "denomination",
  "couponRateBps",
  "couponFrequency",
  "issueDateMs",
  "maturityDateMs",
  "redemptionPriceBps",
  "recordOffsetMs",
];

/**
 * Materialise the regular schedule of a fixed-rate bullet bond.
 *
 * Coupon payment dates step back from maturity by `12 / couponFrequency`
 * calendar months (end-of-month clamping, time of day kept) and must land
 * exactly on the issue date, so every period is regular. The final coupon and
 * the redemption share the maturity payment date. Each record date is
 * `paymentDateMs - recordOffsetMs`, clamped to the issue date. Amounts are exact
 * canonical decimal strings; a non-terminating coupon (for example 6.50 %
 * monthly on 50) is refused, as Core refuses it at registration.
 * @param {{ denomination: KotodamaQuantity|string|bigint, couponRateBps: number, couponFrequency: 0|1|2|4|12, issueDateMs: number|bigint|string, maturityDateMs: number|bigint|string, redemptionPriceBps: number, recordOffsetMs: number|bigint|string }} request
 * @returns {Array<{ index: number, kind: "Coupon"|"Redemption", recordDateMs: number, paymentDateMs: number, amountPerUnit: string }>}
 */
export function buildBondSchedule(request) {
  const context = "buildBondSchedule";
  const source = plainObject(request, context);
  assertExactFields(source, SCHEDULE_FIELDS, context);
  const denomination = quantityText(source.denomination, `${context}.denomination`);
  const couponRateBps = u32(source.couponRateBps, `${context}.couponRateBps`);
  const couponFrequency = u8(source.couponFrequency, `${context}.couponFrequency`);
  const issueDateMs = u64(source.issueDateMs, `${context}.issueDateMs`);
  const maturityDateMs = u64(source.maturityDateMs, `${context}.maturityDateMs`);
  const redemptionPriceBps = u32(source.redemptionPriceBps, `${context}.redemptionPriceBps`);
  const recordOffsetMs = u64(source.recordOffsetMs, `${context}.recordOffsetMs`);
  if (!BOND_COUPON_FREQUENCIES.includes(couponFrequency)) {
    invalidTerms("coupon frequency must be 0, 1, 2, 4 or 12", `${context}.couponFrequency`);
  }
  if (issueDateMs >= maturityDateMs) {
    invalidTerms("issue date must precede maturity", `${context}.issueDateMs`);
  }
  const recordDate = (payment) => Math.max(Math.max(payment - recordOffsetMs, 0), issueDateMs);
  const paymentDates = [];
  if (couponFrequency !== 0) {
    const step = 12 / couponFrequency;
    for (let periods = 0; ; periods += 1) {
      const date = monthsBefore(maturityDateMs, step * periods);
      if (date === null) invalidTerms("schedule date out of range", context);
      if (date <= issueDateMs) {
        if (date !== issueDateMs) {
          invalidTerms(
            "the first coupon period is irregular; materialise the schedule explicitly",
            `${context}.issueDateMs`,
          );
        }
        break;
      }
      paymentDates.push(date);
      if (paymentDates.length >= BOND_MAX_CASHFLOWS) {
        invalidTerms("schedule exceeds the cash-flow limit", context);
      }
    }
    paymentDates.reverse();
  }
  const coupon = couponFrequency === 0
    ? null
    : regularCouponAmount(denomination, couponRateBps, couponFrequency);
  const cashflows = paymentDates.map((paymentDateMs, index) => ({
    index,
    kind: "Coupon",
    recordDateMs: recordDate(paymentDateMs),
    paymentDateMs,
    amountPerUnit: coupon,
  }));
  cashflows.push({
    index: cashflows.length,
    kind: "Redemption",
    recordDateMs: recordDate(maturityDateMs),
    paymentDateMs: maturityDateMs,
    amountPerUnit: redemptionAmount(denomination, redemptionPriceBps),
  });
  return cashflows;
}

function digestHex(value, name) {
  if (value instanceof Uint8Array) {
    if (value.length !== 32) {
      fail(ValidationErrorCode.INVALID_HEX, `${name} must contain exactly 32 bytes`, name);
    }
    return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/u.test(value)) {
    fail(ValidationErrorCode.INVALID_HEX, `${name} must be 32 bytes or 64 hexadecimal digits`, name);
  }
  return value.toLowerCase();
}

function optionalText(value, name) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    fail(ValidationErrorCode.INVALID_STRING, `${name} must be a string or null`, name);
  }
  return value;
}

function oneOf(value, allowed, name) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    fail(ValidationErrorCode.INVALID_STRING, `${name} must be one of ${allowed.join(", ")}`, name);
  }
  return value;
}

const TERMS_FIELDS = new Set([
  "issuer",
  "payingAgent",
  "paymentAsset",
  "denomination",
  "couponRateBps",
  "couponFrequency",
  "dayCount",
  "issueDateMs",
  "maturityDateMs",
  "redemptionPriceBps",
  "call",
  "cashflows",
  "identifiers",
  "termsSha256",
]);
const REQUIRED_TERMS_FIELDS = [...TERMS_FIELDS].filter((field) => field !== "call");
const CASHFLOW_FIELDS = ["index", "kind", "recordDateMs", "paymentDateMs", "amountPerUnit"];
const CALL_FIELDS = ["firstCallDateMs", "priceBps", "noticeMs"];
const IDENTIFIER_FIELDS = new Set(["isin", "cfi", "issuerLei", "bdtVersion", "bdtDocumentSha256"]);

function normalizeCashflow(value, name) {
  const source = plainObject(value, name);
  assertExactFields(source, CASHFLOW_FIELDS, name);
  return {
    index: u16(source.index, `${name}.index`),
    kind: oneOf(source.kind, BOND_CASHFLOW_KINDS, `${name}.kind`),
    record_date_ms: u64(source.recordDateMs, `${name}.recordDateMs`),
    payment_date_ms: u64(source.paymentDateMs, `${name}.paymentDateMs`),
    amount_per_unit: quantityText(source.amountPerUnit, `${name}.amountPerUnit`),
  };
}

function normalizeTerms(value, name) {
  const source = plainObject(value, name);
  assertAllowedFields(source, TERMS_FIELDS, name);
  for (const field of REQUIRED_TERMS_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) {
      fail(ValidationErrorCode.INVALID_OBJECT, `${name}.${field} is required`, `${name}.${field}`);
    }
  }
  let call = null;
  if (present(source, "call")) {
    const callSource = plainObject(source.call, `${name}.call`);
    assertExactFields(callSource, CALL_FIELDS, `${name}.call`);
    call = {
      first_call_date_ms: u64(callSource.firstCallDateMs, `${name}.call.firstCallDateMs`),
      price_bps: u32(callSource.priceBps, `${name}.call.priceBps`),
      notice_ms: u64(callSource.noticeMs, `${name}.call.noticeMs`),
    };
  }
  if (!Array.isArray(source.cashflows)) {
    fail(ValidationErrorCode.INVALID_OBJECT, `${name}.cashflows must be an array`, `${name}.cashflows`);
  }
  const identifiers = plainObject(source.identifiers, `${name}.identifiers`);
  assertAllowedFields(identifiers, IDENTIFIER_FIELDS, `${name}.identifiers`);
  if (typeof identifiers.bdtVersion !== "string") {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${name}.identifiers.bdtVersion must be a string`,
      `${name}.identifiers.bdtVersion`,
    );
  }
  return {
    issuer: normalizeAccountId(source.issuer, `${name}.issuer`),
    paying_agent: normalizeAccountId(source.payingAgent, `${name}.payingAgent`),
    payment_asset: normalizeAssetDefinitionId(source.paymentAsset, `${name}.paymentAsset`),
    denomination: quantityText(source.denomination, `${name}.denomination`),
    coupon_rate_bps: u32(source.couponRateBps, `${name}.couponRateBps`),
    coupon_frequency: u8(source.couponFrequency, `${name}.couponFrequency`),
    day_count: oneOf(source.dayCount, BOND_DAY_COUNTS, `${name}.dayCount`),
    issue_date_ms: u64(source.issueDateMs, `${name}.issueDateMs`),
    maturity_date_ms: u64(source.maturityDateMs, `${name}.maturityDateMs`),
    redemption_price_bps: u32(source.redemptionPriceBps, `${name}.redemptionPriceBps`),
    call,
    cashflows: source.cashflows.map((entry, index) => normalizeCashflow(entry, `${name}.cashflows[${index}]`)),
    identifiers: {
      isin: optionalText(identifiers.isin, `${name}.identifiers.isin`),
      cfi: optionalText(identifiers.cfi, `${name}.identifiers.cfi`),
      issuer_lei: optionalText(identifiers.issuerLei, `${name}.identifiers.issuerLei`),
      bdt_version: identifiers.bdtVersion,
      bdt_document_sha256: present(identifiers, "bdtDocumentSha256")
        ? digestHex(identifiers.bdtDocumentSha256, `${name}.identifiers.bdtDocumentSha256`)
        : null,
    },
    terms_sha256: digestHex(source.termsSha256, `${name}.termsSha256`),
  };
}

function validateLabel(label, value, maximum, path) {
  const printable = [...value].every((character) => {
    const code = character.codePointAt(0);
    return code >= 0x21 && code <= 0x7e;
  });
  if (value.length === 0 || value.length > maximum || !printable) {
    invalidTerms(`${label} must be 1..=${maximum} printable ASCII characters`, path);
  }
}

function isZero(text) {
  return text === "0";
}

/** `BondTerms::validate` over normalized native terms, in Core's rule order. */
function assertValidNativeTerms(terms, name) {
  const ids = terms.identifiers;
  if (ids.isin !== null) validateLabel("isin", ids.isin, ISIN_MAX, `${name}.identifiers.isin`);
  if (ids.cfi !== null) validateLabel("cfi", ids.cfi, CFI_MAX, `${name}.identifiers.cfi`);
  if (ids.issuer_lei !== null) {
    validateLabel("issuer_lei", ids.issuer_lei, LEI_MAX, `${name}.identifiers.issuerLei`);
  }
  validateLabel("bdt_version", ids.bdt_version, BDT_VERSION_MAX, `${name}.identifiers.bdtVersion`);
  if (isZero(terms.denomination)) invalidTerms("denomination must be positive", `${name}.denomination`);
  if (terms.redemption_price_bps === 0) {
    invalidTerms("redemption price must be positive", `${name}.redemptionPriceBps`);
  }
  if (!BOND_COUPON_FREQUENCIES.includes(terms.coupon_frequency)) {
    invalidTerms("coupon frequency must be 0, 1, 2, 4 or 12", `${name}.couponFrequency`);
  }
  if ((terms.coupon_frequency === 0) !== (terms.coupon_rate_bps === 0)) {
    invalidTerms(
      "a zero coupon rate requires frequency 0 and a positive rate requires a positive frequency",
      `${name}.couponRateBps`,
    );
  }
  if (terms.issue_date_ms >= terms.maturity_date_ms) {
    invalidTerms("issue date must precede maturity", `${name}.issueDateMs`);
  }
  if (terms.call !== null) {
    if (terms.call.price_bps === 0) invalidTerms("call price must be positive", `${name}.call.priceBps`);
    if (terms.call.first_call_date_ms <= terms.issue_date_ms
      || terms.call.first_call_date_ms >= terms.maturity_date_ms) {
      invalidTerms(
        "first call date must lie strictly between issue and maturity",
        `${name}.call.firstCallDateMs`,
      );
    }
    redemptionAmount(terms.denomination, terms.call.price_bps);
  }
  assertValidSchedule(terms, name);
}

function assertValidSchedule(terms, name) {
  const count = terms.cashflows.length;
  if (count === 0 || count > BOND_MAX_CASHFLOWS) {
    invalidTerms(`schedule must contain 1..=${BOND_MAX_CASHFLOWS} cash flows`, `${name}.cashflows`);
  }
  const coupon = terms.coupon_frequency === 0
    ? null
    : regularCouponAmount(terms.denomination, terms.coupon_rate_bps, terms.coupon_frequency);
  const redemption = redemptionAmount(terms.denomination, terms.redemption_price_bps);
  let previous = null;
  terms.cashflows.forEach((cashflow, position) => {
    const path = `${name}.cashflows[${position}]`;
    if (cashflow.index !== position) {
      invalidTerms("cash-flow indices must be contiguous from zero", `${path}.index`);
    }
    if (cashflow.record_date_ms > cashflow.payment_date_ms) {
      invalidTerms(`cash flow ${cashflow.index} record date follows its payment date`, `${path}.recordDateMs`);
    }
    if (cashflow.record_date_ms < terms.issue_date_ms
      || cashflow.payment_date_ms > terms.maturity_date_ms) {
      invalidTerms(`cash flow ${cashflow.index} lies outside [issue, maturity]`, path);
    }
    const last = position + 1 === count;
    if (cashflow.kind === "Redemption") {
      if (!last) invalidTerms("exactly one redemption is allowed and it must be last", `${path}.kind`);
      if (cashflow.payment_date_ms !== terms.maturity_date_ms) {
        invalidTerms("redemption payment date must equal maturity", `${path}.paymentDateMs`);
      }
      if (cashflow.amount_per_unit !== redemption) {
        invalidTerms(`redemption amount per unit must be ${redemption}`, `${path}.amountPerUnit`);
      }
    } else {
      if (last) invalidTerms("the schedule must end with its redemption", `${path}.kind`);
      if (coupon === null) invalidTerms("zero-coupon bonds cannot schedule coupons", `${path}.kind`);
      if (cashflow.amount_per_unit !== coupon) {
        invalidTerms(
          `coupon ${cashflow.index} amount per unit must be ${coupon}`,
          `${path}.amountPerUnit`,
        );
      }
    }
    if (previous !== null) {
      const sameDayRedemption = previous.kind === "Coupon"
        && cashflow.kind === "Redemption"
        && previous.payment_date_ms === cashflow.payment_date_ms;
      if (cashflow.payment_date_ms <= previous.payment_date_ms && !sameDayRedemption) {
        invalidTerms("payment dates must strictly increase", `${path}.paymentDateMs`);
      }
      if (cashflow.record_date_ms < previous.record_date_ms) {
        invalidTerms("record dates must not decrease", `${path}.recordDateMs`);
      }
    }
    previous = cashflow;
  });
}

/**
 * Normalize builder-style bond terms to their canonical native JSON and apply
 * every state-independent registration rule of `BondTerms::validate`.
 *
 * Rule violations throw a `ValidationError` whose message is Core's exact
 * `bond.invalid_terms: ...` rejection.
 * @param {object} terms camelCase terms (see `buildRegisterBondInstruction`)
 * @returns {object} canonical snake_case `BondTerms` JSON
 */
export function validateBondTerms(terms) {
  return validatedTerms(terms, "bondTerms");
}

function validatedTerms(terms, context) {
  const native = normalizeTerms(terms, context);
  assertValidNativeTerms(native, context);
  return native;
}

/**
 * One holder's payment: `floor(units × amountPerUnit)` at the payment asset's
 * scale, exactly as Core pays a claim and sums `amount_due`. `paymentScale`
 * `null` means an unconstrained payment asset, which receives the exact product.
 * @param {{ units: KotodamaQuantity|string|bigint, amountPerUnit: KotodamaQuantity|string|bigint, paymentScale: number|null }} input
 * @returns {string} canonical decimal amount
 */
export function bondHolderPayment(input) {
  const context = "bondHolderPayment";
  const source = plainObject(input, context);
  assertExactFields(source, ["units", "amountPerUnit", "paymentScale"], context);
  const units = decimal(quantityText(source.units, `${context}.units`));
  const amount = decimal(quantityText(source.amountPerUnit, `${context}.amountPerUnit`));
  const mantissa = units.mantissa * amount.mantissa;
  const scale = units.scale + amount.scale;
  if (source.paymentScale === null) {
    const exact = canonicalDecimal(mantissa, scale);
    if (exact.scale > MAX_SCALE) {
      fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `bond.arithmetic: ${NUMERIC_SCALE}`, context);
    }
    return decimalText(exact);
  }
  const paymentScale = boundedInteger(source.paymentScale, `${context}.paymentScale`, MAX_SCALE);
  const rounded = scale <= paymentScale
    ? mantissa * 10n ** BigInt(paymentScale - scale)
    : mantissa / 10n ** BigInt(scale - paymentScale);
  if (rounded > MANTISSA_MAX) {
    fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `bond.arithmetic: ${NUMERIC_MANTISSA}`, context);
  }
  return decimalText(canonicalDecimal(rounded, paymentScale));
}

/**
 * Deterministic key-less vault account holding a bond's funded payments
 * (`bond_vault_account_id`: a non-signing Ed25519 point derived from the bond id).
 * The derivation is network independent; `networkPrefix` selects the I105 rendering.
 * @param {string} bondId canonical Base58 asset-definition address of the bond
 * @param {number} networkPrefix I105 network prefix (u16)
 * @returns {string}
 */
export function bondVaultAccountId(bondId, networkPrefix) {
  const bond = normalizeAssetDefinitionId(bondId, "bondVaultAccountId.bondId");
  const prefix = u16(networkPrefix, "bondVaultAccountId.networkPrefix");
  const native = resolveNativeRuntimeBinding(defaultNativeRuntime);
  if (typeof native.bondVaultAccountId !== "function") {
    throw new Error("Native binding required; bondVaultAccountId is unavailable");
  }
  return native.bondVaultAccountId(bond, prefix);
}

function bondId(value, name) {
  return normalizeAssetDefinitionId(value, name);
}

/**
 * Build `Bond::Register` for an existing scale-0 bond asset definition.
 *
 * Signed by `terms.issuer`, which must own the definition; intended for the
 * issuer transaction that registers and mints the definition. Terms are
 * validated with {@link validateBondTerms}; the payment asset must differ from the bond.
 * @param {{ bondId: string, terms: object }} options
 * @returns {{ Bond: { Register: { bond: string, terms: object } } }}
 */
export function buildRegisterBondInstruction(options) {
  const context = "registerBond";
  const source = plainObject(options, context);
  assertExactFields(source, ["bondId", "terms"], context);
  const bond = bondId(source.bondId, `${context}.bondId`);
  const terms = validatedTerms(source.terms, `${context}.terms`);
  if (terms.payment_asset === bond) {
    invalidTerms("the payment asset must differ from the bond", `${context}.terms.paymentAsset`);
  }
  return { Bond: { Register: { bond, terms } } };
}

function cashflowInstruction(variant, context, options, extra = {}) {
  const source = plainObject(options, context);
  assertExactFields(source, ["bondId", "index", ...Object.keys(extra)], context);
  const payload = {
    bond: bondId(source.bondId, `${context}.bondId`),
    index: u16(source.index, `${context}.index`),
  };
  for (const [field, [key, normalize]] of Object.entries(extra)) {
    payload[key] = normalize(source[field], `${context}.${field}`);
  }
  return { Bond: { [variant]: payload } };
}

/**
 * Build `Bond::RecordCashflow`: the paying agent snapshots investor holdings at
 * or after the record date. Recording the redemption freezes the bond.
 * @param {{ bondId: string, index: number }} options
 */
export function buildRecordBondCashflowInstruction(options) {
  return cashflowInstruction("RecordCashflow", "recordBondCashflow", options);
}

function globalPaymentSource(value, name) {
  const holding = normalizeAssetHoldingId(value, name);
  if (holding.split("#").length !== 2) {
    fail(ValidationErrorCode.INVALID_ASSET_ID, `${name} must be a global (unscoped) balance`, name);
  }
  return holding;
}

/**
 * Build `Bond::FundCashflow`: the paying agent or issuer moves exactly the
 * recorded amount due from its own global payment-asset balance into the vault.
 * @param {{ bondId: string, index: number, sourceAssetHoldingId: string }} options
 */
export function buildFundBondCashflowInstruction(options) {
  return cashflowInstruction("FundCashflow", "fundBondCashflow", options, {
    sourceAssetHoldingId: ["source", globalPaymentSource],
  });
}

/**
 * Build `Bond::ClaimCashflow` paying one snapshot holder from the vault. The
 * holder signs it, or the paying agent pushes it; the destination is always
 * the holder. A redemption claim also burns the holder's units.
 * @param {{ bondId: string, index: number, holder: string }} options
 */
export function buildClaimBondCashflowInstruction(options) {
  return cashflowInstruction("ClaimCashflow", "claimBondCashflow", options, {
    holder: ["holder", normalizeAccountId],
  });
}

/**
 * Build `Bond::CloseCashflow` (paying agent) once every snapshot holder claimed.
 * @param {{ bondId: string, index: number }} options
 */
export function buildCloseBondCashflowInstruction(options) {
  return cashflowInstruction("CloseCashflow", "closeBondCashflow", options);
}

/**
 * Build `Bond::Call` (issuer) at the payment date of a still scheduled coupon.
 * @param {{ bondId: string, callDateMs: number|bigint|string }} options
 */
export function buildCallBondInstruction(options) {
  const context = "callBond";
  const source = plainObject(options, context);
  assertExactFields(source, ["bondId", "callDateMs"], context);
  return {
    Bond: {
      Call: {
        bond: bondId(source.bondId, `${context}.bondId`),
        call_date_ms: u64(source.callDateMs, `${context}.callDateMs`),
      },
    },
  };
}

/**
 * Build `Bond::DeclareDefault` (paying agent) for an unfunded cash flow after
 * its payment date, with the SHA-256 digest of the default evidence.
 * @param {{ bondId: string, index: number, evidenceSha256: string|Uint8Array }} options
 */
export function buildDeclareBondDefaultInstruction(options) {
  return cashflowInstruction("DeclareDefault", "declareBondDefault", options, {
    evidenceSha256: ["evidence_sha256", digestHex],
  });
}
