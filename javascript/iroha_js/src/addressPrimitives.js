import { AccountAddressError, AccountAddressErrorCode } from "./addressErrors.js";
import { canonicalCurveAlgorithm, getCurveEntryByAlgorithm, getCurveEntryById } from "./curveRegistry.js";
import { JS_TYPE_NUMBER, JS_TYPE_STRING } from "./commonLiterals.js";

function hexToBytes(body) {
  const out = new Uint8Array(body.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(body.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

export function ensureCurveIdEnabled(curveId, _context) {
  const entry = getCurveEntryById(curveId);
  if (!entry) {
    throw new AccountAddressError(
      AccountAddressErrorCode.UNKNOWN_CURVE,
      `unknown curve id: ${curveId}`,
    );
  }
  return entry;
}

export function normalizeBytes(value) {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    const out = new Uint8Array(value.length);
    for (let index = 0; index < value.length; index += 1) {
      const byte = value[index];
      if (
        typeof byte !== JS_TYPE_NUMBER ||
        !Number.isFinite(byte) ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 0xff
      ) {
        throw new TypeError("byte array entries must be integers between 0 and 255");
      }
      out[index] = byte;
    }
    return out;
  }
  if (typeof value === JS_TYPE_STRING) {
    const trimmed = value.trim();
    const body =
      trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
    if (body.length === 0 || body.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(body)) {
      throw new TypeError("hex string inputs must be even-length and contain only hex digits");
    }
    return hexToBytes(body);
  }
  throw new TypeError(
    "expected Uint8Array, Buffer, ArrayBuffer, ArrayBufferView, number[], or hex string for byte data",
  );
}

export function curveIdFromAlgorithm(algorithm) {
  const entry = getCurveEntryByAlgorithm(algorithm);
  if (!entry) {
    throw new AccountAddressError(
      AccountAddressErrorCode.UNKNOWN_ALGORITHM,
      `unsupported signing algorithm: ${algorithm}`,
      { details: { algorithm } },
    );
  }
  return entry.id;
}

export function curveIdToAlgorithm(curveId) {
  const entry = ensureCurveIdEnabled(curveId, `curve id ${curveId}`);
  return canonicalCurveAlgorithm(entry.id) ?? entry.algorithm;
}
