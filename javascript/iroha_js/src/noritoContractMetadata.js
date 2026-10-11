/** Canonical compact CNTR metadata codecs shared with manifest serialization. */
import { createNoritoContractMetadataCodecs } from "./noritoContractCodecs.js";
import {
  BufferReader,
  assertNonEmptyString,
  assertOnlyObjectKeys,
  decodeAccountIdValue,
  decodeBoolValue,
  decodeEventFilterBoxFramePayload,
  decodeMetadataValue,
  decodeNameValue,
  decodeNoritoVec,
  decodeOptionValue,
  decodeStringValue,
  decodeStructFields,
  decodeU16Value,
  decodeU32Value,
  decodeU8Value,
  encodeAccountIdValue,
  encodeBoolValue,
  encodeEnumTagValue,
  encodeEventFilterBoxFramePayload,
  encodeMetadataValue,
  encodeNameValue,
  encodeNoritoStringValue,
  encodeNoritoVec,
  encodeOptionValue,
  encodeStructValue,
  encodeU16Value,
  encodeU32Value,
  encodeU8Value,
  isPlainObject,
  readNoritoField,
  toBuffer,
  withNoritoCompactLengths,
} from "./noritoValueCodecs.js";

/** One immutable metadata codec binding shared by the compiler and manifest codec. */
export const contractDeclarationCodecsV1 = /* @__PURE__ */ Object.freeze(createNoritoContractMetadataCodecs(
  BufferReader,
  assertNonEmptyString,
  assertOnlyObjectKeys,
  decodeAccountIdValue,
  decodeBoolValue,
  decodeEventFilterBoxFramePayload,
  decodeMetadataValue,
  decodeNameValue,
  decodeNoritoVec,
  decodeOptionValue,
  decodeStringValue,
  decodeStructFields,
  decodeU16Value,
  decodeU32Value,
  decodeU8Value,
  encodeAccountIdValue,
  encodeBoolValue,
  encodeEnumTagValue,
  encodeEventFilterBoxFramePayload,
  encodeMetadataValue,
  encodeNameValue,
  encodeNoritoStringValue,
  encodeNoritoVec,
  encodeOptionValue,
  encodeStructValue,
  encodeU16Value,
  encodeU32Value,
  encodeU8Value,
  isPlainObject,
  readNoritoField,
));
const { values: contractMetadataCodecsV1 } = contractDeclarationCodecsV1;

/** Decode one authenticated CNTR value and reject noncanonical or trailing bytes. */
export function decodeContractMetadataValueV1(kind, input) {
  if (!Object.hasOwn(contractMetadataCodecsV1, kind)) throw new TypeError("unknown contract metadata value");
  const [encode, decode] = contractMetadataCodecsV1[kind];
  const bytes = toBuffer(input);
  return withNoritoCompactLengths(() => {
    const value = decode(bytes, `CNTR.${kind}`);
    if (!encode(value, `CNTR.${kind}`).equals(bytes)) throw new TypeError(`CNTR.${kind} has noncanonical bytes`);
    return value;
  });
}

/** Encode one metadata value with the canonical compact Norito layout. */
export function encodeContractMetadataValueV1(kind, value) {
  if (!Object.hasOwn(contractMetadataCodecsV1, kind)) throw new TypeError("unknown contract metadata value");
  return withNoritoCompactLengths(() => contractMetadataCodecsV1[kind][0](value, `CNTR.${kind}`));
}
