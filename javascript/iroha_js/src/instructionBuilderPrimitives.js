import { Buffer } from "buffer";
import { createValidationError, ValidationErrorCode } from "./validationError.js";
import { isCanonicalGovernanceSelectorV1 } from "./governanceSelector.js";

function fail(code, message, path) {
  throw createValidationError(code, message, path);
}

export function assertAllowedFields(source, allowed, name) {
  for (const field of Reflect.ownKeys(source)) {
    const label = typeof field === "symbol" ? field.toString() : field;
    const descriptor = Object.getOwnPropertyDescriptor(source, field);
    if (typeof field !== "string" || !allowed.has(field)) {
      fail(
        ValidationErrorCode.INVALID_OBJECT,
        `${name}.${label} is not supported`,
        `${name}.${label}`,
      );
    }
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      fail(
        ValidationErrorCode.INVALID_OBJECT,
        `${name}.${label} must be an enumerable data field`,
        `${name}.${label}`,
      );
    }
  }
}

export function assertExactFields(source, fields, name) {
  const allowed = new Set(fields);
  assertAllowedFields(source, allowed, name);
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(source, field)) {
      fail(
        ValidationErrorCode.INVALID_OBJECT,
        `${name}.${field} is required`,
        `${name}.${field}`,
      );
    }
  }
}

function crc16(tag, body) {
  let crc = 0xffff;
  const processByte = (byte) => {
    crc ^= (byte & 0xff) << 8;
    for (let i = 0; i < 8; i += 1) {
      if ((crc & 0x8000) !== 0) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  };

  for (const byte of Buffer.from(tag, "utf8")) {
    processByte(byte);
  }
  processByte(":".charCodeAt(0));
  for (const byte of Buffer.from(body, "utf8")) {
    processByte(byte);
  }

  return crc & 0xffff;
}

export function canonicalHashLiteral(buf) {
  const normalized = Buffer.from(buf);
  if (normalized.length !== 32) {
    fail(ValidationErrorCode.INVALID_HEX, "hash must be 32 bytes");
  }
  normalized[normalized.length - 1] |= 1;
  const body = normalized.toString("hex").toUpperCase();
  const checksum = crc16("hash", body).toString(16).toUpperCase().padStart(4, "0");
  return `hash:${body}#${checksum}`;
}

export function parseHashLiteralToBuffer(literal, name) {
  const match = /^hash:([0-9A-Fa-f]{64})#([0-9A-Fa-f]{4})$/.exec(literal.trim());
  if (!match) {
    fail(
      ValidationErrorCode.INVALID_HEX,
      `${name} must be a canonical "hash:<HEX>#<CRC>" literal`,
      name,
    );
  }
  const [, body, checksum] = match;
  const bodyUpper = body.toUpperCase();
  const expected = crc16("hash", bodyUpper).toString(16).toUpperCase().padStart(4, "0");
  if (expected !== checksum.toUpperCase()) {
    fail(
      ValidationErrorCode.INVALID_HEX,
      `${name} has invalid checksum; expected ${expected}`,
      name,
    );
  }
  return Buffer.from(bodyUpper, "hex");
}

export function parseHashLiteral(literal, name) {
  return canonicalHashLiteral(parseHashLiteralToBuffer(literal, name));
}

export function assertString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    fail(ValidationErrorCode.INVALID_STRING, `${name} must be a non-empty string`, name);
  }
  return value;
}

export function assertNonBlankString(value, name) {
  const raw = assertString(value, name);
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    fail(ValidationErrorCode.INVALID_STRING, `${name} must be a non-empty string`, name);
  }
  return trimmed;
}

export function assertExactNonBlankString(value, name) {
  const raw = assertString(value, name);
  if (raw.trim().length === 0) {
    fail(ValidationErrorCode.INVALID_STRING, `${name} must be a non-empty string`, name);
  }
  if (raw.trim() !== raw) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${name} must not contain surrounding whitespace`,
      name,
    );
  }
  return raw;
}

export function normalizeAssetDefinitionName(value, name) {
  const exact = assertExactNonBlankString(value, name);
  assertWellFormedUtf16(exact, name);
  if (
    Buffer.byteLength(exact) > 128 ||
    /[#@\p{Cc}]/u.test(exact)
  ) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be an exact 1-128-byte asset name without control characters, #, or @`,
      name,
    );
  }
  return exact;
}

export function normalizeGovernanceSelectorV1(value, name) {
  const exact = assertString(value, name);
  if (!isCanonicalGovernanceSelectorV1(exact)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${name} must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot`,
      name,
    );
  }
  return exact;
}

export function requireExactLowerHex32String(value, name) {
  const exact = assertExactNonBlankString(value, name);
  if (!/^[0-9a-f]{64}$/u.test(exact)) {
    fail(
      ValidationErrorCode.INVALID_HEX,
      `${name} must contain exactly 64 lowercase hexadecimal characters`,
      name,
    );
  }
  return exact;
}

export function assertWellFormedUtf16(value, name) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail(
          ValidationErrorCode.INVALID_STRING,
          `${name} must not contain unpaired UTF-16 surrogates`,
          name,
        );
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      fail(
        ValidationErrorCode.INVALID_STRING,
        `${name} must not contain unpaired UTF-16 surrogates`,
        name,
      );
    }
  }
}

/**
 * Validate one canonical Iroha `Name` (1-255 UTF-8 bytes, NFC, no whitespace,
 * control or bidirectional-control characters, and none of `@`, `#`, `$`).
 * @param {string} value
 * @param {string} context
 * @returns {string}
 */
export function assertCanonicalIrohaName(value, context) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${context} must be a non-empty canonical Iroha Name`);
  }
  if (
    new TextEncoder().encode(value).length > 255 ||
    value.normalize("NFC") !== value ||
    /[\s@#$\p{Cc}\p{Cs}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)
  ) {
    throw new TypeError(`${context} must be a canonical Iroha Name`);
  }
  return value;
}
