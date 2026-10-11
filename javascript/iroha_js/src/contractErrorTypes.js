const isArray = Array.isArray.bind(Array);
import { isCanonicalKotodamaIdentifier, isCanonicalKotodamaStateTypeName } from "./kotodamaIdentifiers.js";

// Preserve the public diagnostic class and text with one constructor.
function rejectType(message) {
  throw new TypeError(message);
}

function exactKeys(value, keys, context) {
  if (value === null || typeof value !== "object" || isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    rejectType(`${context} must contain exactly ${keys.join(" and ")}`);
  }
}

/** Normalize one finite nominal error schema; variant codes are enum-local. */
function normalizeNominalTypeV1(value, context) {
  exactKeys(value, ["identity", "variants"], context);
  if (typeof value.identity !== "string" || new TextEncoder().encode(value.identity).byteLength > 1024 ||
      !/^[\p{L}\p{N}_:/@.-]+$/u.test(value.identity) || value.identity.includes("__kotodama_link_")) {
    rejectType(`${context}.identity must be a stable package/unit/enum identity`);
  }
  if (!Array.isArray(value.variants) || value.variants.length < 1 || value.variants.length > 256) {
    rejectType(`${context}.variants must contain 1..256 variants`);
  }
  const names = new Set();
  let previous = 0;
  const variants = Array.from(value.variants, (variant, index) => {
    const label = `${context}.variants[${index}]`;
    exactKeys(variant, ["name", "code"], label);
    const name = variant.name;
    if (!(isCanonicalKotodamaIdentifier(name) ||
        (typeof name === "string" && /[^\x00-\x7f]/u.test(name) && /^[\p{L}_][\p{L}\p{N}_]*$/u.test(name))) || names.has(name)) {
      rejectType(`${label}.name must be a unique canonical variant identifier`);
    }
    const code = typeof variant.code === "bigint" || (typeof variant.code === "string" && /^(?:0|[1-9][0-9]*)$/u.test(variant.code)) ? Number(variant.code) : variant.code;
    if (!Number.isSafeInteger(code) || code <= previous || code > 0xffff_ffff) {
      rejectType(`${label}.code must be a nonzero u32 in strictly increasing order`);
    }
    previous = code;
    names.add(name);
    return { name, code };
  });
  return { identity: value.identity, variants };
}

/** Ordinary enums and rejection errors have distinct wire kinds and schema domains. */
export function normalizeContractErrorTypeV1(value, context = "error type") {
  return normalizeNominalTypeV1(value, context);
}
export function normalizeContractEnumTypeV1(value, context = "enum type") {
  return normalizeNominalTypeV1(value, context);
}

/** Required ordinary-enum declaration inventory, sorted by exact UTF-8 identity. */
export function normalizeContractEnumTypesV1(value, context = "enum_types") {
  if (!Array.isArray(value) || value.length > 256) rejectType(`${context} must be a required array of at most 256 enum types`);
  let previous = null;
  return Array.from(value, (entry, index) => {
    const descriptor = normalizeContractEnumTypeV1(entry, `${context}[${index}]`);
    const bytes = new TextEncoder().encode(descriptor.identity);
    if (previous !== null && compareUtf8(previous, bytes) >= 0) rejectType(`${context} must be sorted and unique by identity`);
    previous = bytes;
    return descriptor;
  });
}
function compareUtf8(left, right) {
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

/** Normalize the unique nominal catalog authenticated by the contract manifest. */
export function normalizeContractErrorTypesV1(value, context = "error_types") {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length > 256) {
    rejectType(`${context} must be an array of at most 256 error types`);
  }
  const identities = new Set();
  return Array.from(value, (entry, index) => {
    const error = normalizeContractErrorTypeV1(entry, `${context}[${index}]`);
    if (identities.has(error.identity)) rejectType(`${context} contains a duplicate error identity`);
    identities.add(error.identity);
    return error;
  });
}

/** Require public error schemas and durable state identities to match the signed nominal catalog. */
export function validateManifestErrorTypeBindingsV1(manifest, context = "manifest") {
  normalizeContractErrorMessagesV1(manifest.error_messages, manifest.error_types, `${context}.error_messages`);
  const catalog = new Map((normalizeContractErrorTypesV1(manifest.error_types, `${context}.error_types`) ?? [])
    .map((error) => [error.identity, JSON.stringify(error)]));
  const enums = new Map(normalizeContractEnumTypesV1(manifest.enum_types, `${context}.enum_types`).map((descriptor) => [descriptor.identity, JSON.stringify(descriptor)]));
  if ([...enums.keys()].some((identity) => catalog.has(identity))) rejectType(`${context} enum_types and error_types identities must not overlap`);
  for (const state of manifest.states ?? []) {
    if (!isCanonicalKotodamaStateTypeName(state.type_name, new Map([...catalog, ...enums]))) {
      rejectType(`${context} state nominal identity is not declared in an enum or error catalog`);
    }
  }
  const schemas = (manifest.events ?? []).map((event) => event.payload_type);
  for (const entrypoint of manifest.entrypoints ?? []) {
    schemas.push(...(entrypoint.argument_schema?.fields ?? []).map((field) => field.ty), entrypoint.return_schema);
  }
  for (const schema of schemas) for (const node of schema?.nodes ?? []) {
    if (node.kind === "Error" && catalog.get(node.value.identity) !== JSON.stringify(normalizeContractErrorTypeV1(node.value))) {
      rejectType(`${context} boundary error schema does not match its error_types catalog`);
    }
    if (node.kind === "Enum" && enums.get(node.value.identity) !== JSON.stringify(normalizeContractEnumTypeV1(node.value))) {
      rejectType(`${context} boundary enum schema does not match its enum_types catalog`);
    }
  }
}

/** Validate authenticated presentation text without changing nominal error schemas. */
export function normalizeContractErrorMessagesV1(value, errorTypes, context = "error_messages") {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length > 65_536) rejectType(`${context} must be a bounded array`);
  const catalog = new Map((normalizeContractErrorTypesV1(errorTypes) ?? []).map((error) => [error.identity, error]));
  const utf8 = new TextEncoder();
  let previous = null;
  return Array.from(value, (entry, index) => {
    const label = `${context}[${index}]`;
    exactKeys(entry, ["error_type", "code", "message"], label);
    const descriptor = catalog.get(entry.error_type);
    if (!descriptor || !Number.isSafeInteger(entry.code) || !descriptor.variants.some((variant) => variant.code === entry.code)) {
      rejectType(`${label} must reference a declared nominal error variant`);
    }
    if (typeof entry.message !== "string" || /^\p{White_Space}*$/u.test(entry.message) || /[\uD800-\uDFFF]/u.test(entry.message) || utf8.encode(entry.message).length > 4096) {
      rejectType(`${label}.message must contain 1..4096 UTF-8 bytes of nonblank text`);
    }
    const identity = utf8.encode(entry.error_type);
    if (previous) {
      let order = 0;
      for (let offset = 0; offset < Math.min(previous.identity.length, identity.length); offset += 1) {
        if (previous.identity[offset] !== identity[offset]) { order = previous.identity[offset] - identity[offset]; break; }
      }
      if (order === 0) order = previous.identity.length - identity.length;
      if (order > 0 || (order === 0 && previous.code >= entry.code)) rejectType(`${context} must be sorted and unique by identity and code`);
    }
    previous = { identity, code: entry.code };
    return { error_type: entry.error_type, code: entry.code, message: entry.message };
  });
}
