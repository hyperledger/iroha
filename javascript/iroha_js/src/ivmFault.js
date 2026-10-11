/** Closed canonical runtime faults shared by simulation and HTTP error projections. */
import { rejectType } from "./validationThrow.js";

function exactRecord(value, keys, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) rejectType(`${context} must be an object`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((key) => !keys.includes(key))) rejectType(`${context} must contain exactly: ${keys.join(", ")}`);
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) rejectType(`${context}.${key} must be an enumerable data property`);
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}
function unsigned(value, context) {
  if (!Number.isSafeInteger(value) || value < 0) rejectType(`${context} must be an exact unsigned integer`);
  return value;
}
function hash(value, context) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) rejectType(`${context} must be a 32-byte hexadecimal hash`);
  return value.toLowerCase();
}

export function normalizeIvmFault(value, context) {
  const fault = exactRecord(value, ["kind", "site"], context);
  const kind = exactRecord(fault.kind, ["kind", "value"], `${context}.kind`);
  const units = new Set(["OutOfGas", "MemoryLimitExceeded", "MemoryAccessViolation", "MisalignedAccess", "MemoryOutOfBounds", "DecodeError", "InvalidOpcode", "UnknownSyscall", "UnsupportedSyscall", "GasCostOverflow", "AssertionFailed", "ExceededMaxCycles", "InvalidMetadata", "InvalidVectorLength", "MissingHalt", "VectorExtensionDisabled", "ZkExtensionDisabled", "NullifierAlreadyUsed", "PermissionDenied", "PrivacyViolation", "RegisterOutOfBounds", "NoritoInvalid", "AbiTypeNotAllowed", "HostOutputItemsExceeded", "HostOutputBytesExceeded", "AmxBudgetExceeded", "ReentrantCall", "CallDepthExceeded"]);
  if (kind.kind === "Numeric" || kind.kind === "PointerAbi") {
    const code = exactRecord(kind.value, ["kind", "value"], `${context}.kind.value`);
    const allowed = kind.kind === "Numeric" ? ["MantissaOverflow", "ScaleOverflow", "DivisionByZero", "RepeatingDecimal", "ExactDivisionScaleOverflow", "InvalidScale", "InexactConversion", "NegativeQuantity", "QuantityUnderflow", "InvalidRoundingMode", "InvalidFailureMode", "ReservedRegisterNonZero", "NegativeSquareRoot"] : ["InvalidAddress", "UnknownType", "TypeNotAllowed", "WrongType", "InvalidEnvelopeVersion", "OversizedLength", "TruncatedEnvelope", "PayloadHashMismatch", "MalformedFrame", "SchemaMismatch", "NonCanonical"];
    if (!allowed.includes(code.kind) || code.value !== null) {
      rejectType(`${context}.kind.value must be an exact known fault code`);
    }
    kind.value = code;
  } else if (!units.has(kind.kind) || kind.value !== null) {
    rejectType(`${context}.kind must be an exact known fault category`);
  }
  const site = exactRecord(fault.site, ["code_hash", "selector", "position"], `${context}.site`);
  const selector = exactRecord(site.selector, ["kind", "value"], `${context}.site.selector`);
  if (selector.kind === "Generic") {
    if (selector.value !== null) rejectType(`${context}.site.selector.value must be null`);
  } else if (selector.kind === "Entrypoint") {
    selector.value = unsigned(selector.value, `${context}.site.selector.value`, {allowZero: true});
    if (selector.value > 0xffffffff) rejectType(`${context}.site.selector.value exceeds u32`);
  } else rejectType(`${context}.site.selector.kind is unknown`);
  const position = exactRecord(site.position, ["kind", "value"], `${context}.site.position`);
  if (position.kind === "Execute") {
    const location = exactRecord(position.value, ["pc_offset"], `${context}.site.position.value`);
    position.value = {pc_offset: unsigned(location.pc_offset, `${context}.site.position.value.pc_offset`, {allowZero: true})};
  } else if (!["Initialization", "ReturnValidation"].includes(position.kind) || position.value !== null) {
    rejectType(`${context}.site.position must be an exact known stage`);
  }
  return {kind, site: {code_hash: hash(site.code_hash, `${context}.site.code_hash`), selector, position}};
}

