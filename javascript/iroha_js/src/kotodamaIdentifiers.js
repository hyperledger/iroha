import { isExactDurableBuiltinProduct } from "./kotodamaProducts.js";
// BEGIN GENERATED: kotodama-v1-validator-policy
/** Canonical Kotodama V1 lexical keywords generated from `grammar/v1.lex`. */
export const KOTODAMA_V1_KEYWORDS = Object.freeze([
  "as",
  "permission",
  "authorize",
  "break",
  "const",
  "continue",
  "else",
  "enum",
  "error",
  "export",
  "false",
  "fn",
  "for",
  "hajimari",
  "始まり",
  "if",
  "import",
  "in",
  "include",
  "kaizen",
  "改善",
  "kotoage",
  "言挙げ",
  "let",
  "match",
  "module",
  "return",
  "seiyaku",
  "誓約",
  "state",
  "struct",
  "event",
  "emit",
  "trigger",
  "true",
  "var",
  "view",
]);

// Exact spellings forbidden in every Kotodama V1 identifier position.
const FORBIDDEN_SOURCE_IDENTIFIER_SET = new Set([
  "Amount",
]);

/** Names reserved for non-type source declarations. */
export const KOTODAMA_V1_DECLARATION_RESERVED = Object.freeze([
  "int",
  "decimal",
  "quantity",
  "bool",
  "string",
  "bytes",
  "Json",
  "AccountId",
  "AssetDefinitionId",
  "AssetId",
  "DomainId",
  "Name",
  "NftId",
  "DataSpaceId",
  "Option",
  "Result",
  "List",
  "ListError",
  "NumericError",
  "StateMap",
  "StateCursor",
  "StatePage",
  "Secret",
  "AccountView",
  "AssetView",
  "AssetDefinitionView",
  "DomainView",
  "NftView",
  "QueryPage",
  "AxtDescriptor",
  "AxtAnchoredSpendV1",
  "ProofBlob",
  "SoracloudRequest",
  "SoracloudResponse",
  "state_map_get",
  "__kotodama_state_page",
  "__kotodama_state_take",
  "__kotodama_list_len",
  "__kotodama_list_get",
  "__kotodama_list_set",
  "__kotodama_list_push",
  "__kotodama_list_try_set",
  "__kotodama_list_try_push",
  "__kotodama_list_pop",
  "__kotodama_list_contains",
  "__kotodama_list_take",
  "__kotodama_list_enumerate",
  "__kotodama_decimal_div_round",
  "__kotodama_decimal_mul_div_round",
  "__kotodama_quantity_mul_div_round",
  "__kotodama_quantity_div_round",
  "__kotodama_quantity_ratio_round",
  "__kotodama_decimal_to_int_trunc",
  "__kotodama_decimal_to_int_round",
  "__kotodama_option_ok_or",
  "__kotodama_result_or_err",
]);

/** Retired numeric spellings reserved only for types and source units. */
export const KOTODAMA_V1_RETIRED_TYPE_NAMES = Object.freeze([
  "i8",
  "i16",
  "i32",
  "i64",
  "i128",
  "isize",
  "u8",
  "u16",
  "u32",
  "u64",
  "u128",
  "usize",
  "num",
  "Int",
  "Integer",
  "float",
  "f32",
  "f64",
  "Decimal",
  "Fixed",
  "FixedPoint",
  "Amount",
  "amount",
  "money",
  "Quantity",
  "number",
]);

/** Exact scalar source types accepted as durable `StateMap` keys in V1. */
export const KOTODAMA_V1_STATE_MAP_KEY_TYPES = Object.freeze([
  "int",
  "decimal",
  "quantity",
  "bool",
  "string",
  "bytes",
  "DataSpaceId",
  "AccountId",
  "AssetDefinitionId",
  "AssetId",
  "NftId",
  "DomainId",
  "Name",
]);

/** Exact dynamic-access bound policies emitted by the V1 compiler. */
export const KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS = Object.freeze([
  "page",
  "take",
]);

/** Maximum number of keys one V1 dynamic-access hint may project. */
export const KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS = 64;

const KEYWORD_SET = new Set([
  ...KOTODAMA_V1_KEYWORDS,
  ...FORBIDDEN_SOURCE_IDENTIFIER_SET,
]);
const DECLARATION_RESERVED_SET = new Set(KOTODAMA_V1_DECLARATION_RESERVED);
const RETIRED_TYPE_SET = new Set(KOTODAMA_V1_RETIRED_TYPE_NAMES);
const KOTODAMA_V1_STATE_MAP_KEY_TYPE_SET = new Set(
  KOTODAMA_V1_STATE_MAP_KEY_TYPES,
);
const KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KIND_SET = new Set(
  KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS,
);
// END GENERATED: kotodama-v1-validator-policy

/** Return whether a string is one exact source identifier under V1 resolution rules. */
export function isCanonicalKotodamaIdentifier(
  value,
  { declaration = false, typeDeclaration = false } = {},
) {
  return (
    typeof value === "string" &&
    /^[A-Za-z_][A-Za-z0-9_]*$/u.test(value) &&
    !KEYWORD_SET.has(value) &&
    !value.startsWith("__kotodama_link_") &&
    (!declaration || !DECLARATION_RESERVED_SET.has(value)) &&
    (!typeDeclaration || (
      !DECLARATION_RESERVED_SET.has(value) &&
      !RETIRED_TYPE_SET.has(value)
    ))
  );
}

/** Validate an exact unit-qualified, locked-package, or compiler-owned struct identity. */
export function isCanonicalKotodamaStructName(value) {
  if (typeof value !== "string" || value.length > 1024) return false;
  if (!value.includes("::")) return false;
  if (value.includes("__kotodama_link_")) return false;
  const parts = value.split("::");
  if (parts.length === 2) {
    if (parts[0] === "kotodama") return ["AccountView", "AssetView", "AssetDefinitionView", "DomainView", "NftView", "QueryPage", "StatePage"].includes(parts[1]);
    return parts.every((part) => isCanonicalKotodamaIdentifier(part, { typeDeclaration: true }));
  }
  if (parts.length === 4 && parts[0] === "local") {
    return /^[0-9a-f]{64}$/u.test(parts[1]) &&
      isCanonicalKotodamaIdentifier(parts[2], { typeDeclaration: true }) &&
      isCanonicalKotodamaIdentifier(parts[3], { typeDeclaration: true });
  }
  if (parts.length !== 3 || !isCanonicalKotodamaIdentifier(parts[1], { typeDeclaration: true }) ||
      !isCanonicalKotodamaIdentifier(parts[2], { typeDeclaration: true })) return false;
  const packageParts = parts[0].split("@");
  const component = (text) => /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/u.test(text);
  return packageParts.length <= 2 && packageParts[0].split("/").every(component) &&
    (packageParts.length === 1 || component(packageParts[1]));
}

// Durable scalar values add Json to the same canonical key-scalar vocabulary.
const KOTODAMA_V1_STATE_SCALAR_TYPES = new Set([...KOTODAMA_V1_STATE_MAP_KEY_TYPES, "Json"]);
const KOTODAMA_V1_MAX_TYPE_DEPTH = 256;
const KOTODAMA_V1_MAX_TYPE_NODES = 256;

/** Return whether a string is one canonical durable-state declaration name. */
export function isCanonicalKotodamaStateDeclarationIdentifier(value) {
  return isCanonicalKotodamaIdentifier(value, { declaration: true });
}

/** Return whether a type name is one exact canonical V1 `StateMap` key scalar. */
export function isKotodamaV1StateMapKeyTypeName(value) {
  return typeof value === "string" && stateMapKeyTypePrefix(value)?.end === value.length;
}

/** Parse a bounded canonical scalar/tuple key prefix without accepting aliases. */
export function stateMapKeyTypePrefix(value, start = 0, initialDepth = 1) {
  let cursor = start;
  let nodes = 0;
  const parse = (depth) => {
    if (++nodes > 256 || depth > 256) return false;
    if (value[cursor] === "(") {
      cursor += 1;
      if (!parse(depth + 1) || !value.startsWith(", ", cursor)) return false;
      cursor += 2;
      if (!parse(depth + 1)) return false;
      while (value.startsWith(", ", cursor)) { cursor += 2; if (!parse(depth + 1)) return false; }
      if (value[cursor++] !== ")") return false;
      return true;
    }
    const token = /^[A-Za-z][A-Za-z0-9]*/u.exec(value.slice(cursor))?.[0];
    if (!KOTODAMA_V1_STATE_MAP_KEY_TYPE_SET.has(token)) return false;
    cursor += token.length;
    return true;
  };
  return parse(initialDepth) ? { end: cursor, nodes } : null;
}

/** Return whether a dynamic-access base is exactly `state:` plus one state name. */
export function isCanonicalKotodamaDynamicAccessBaseKey(value) {
  if (typeof value !== "string" || !value.startsWith("state:")) {
    return false;
  }
  return isCanonicalKotodamaStateDeclarationIdentifier(value.slice("state:".length));
}

/** Return whether a dynamic-access bound policy is exactly `take` or `page`. */
export function isKotodamaV1DynamicAccessBoundKind(value) {
  return (
    typeof value === "string" &&
    KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KIND_SET.has(value)
  );
}

/**
 * Return whether a string is the exact canonical V1 spelling of one durable
 * state type.
 *
 * Type and struct-name positions reject retired numeric spellings, while
 * struct field positions remain ordinary value identifiers such as `amount`.
 */
export function isCanonicalKotodamaStateTypeName(value, errorIdentities = null) {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }

  let cursor = 0;
  let nodes = 0;
  const isAsciiLetter = (code) =>
    (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
  const isAsciiDigit = (code) => code >= 0x30 && code <= 0x39;
  const consume = (literal) => {
    if (!value.startsWith(literal, cursor)) {
      return false;
    }
    cursor += literal.length;
    return true;
  };
  const identifier = () => {
    const start = cursor;
    const first = value.charCodeAt(cursor);
    if (first !== 0x5f && !isAsciiLetter(first)) {
      return null;
    }
    cursor += 1;
    while (cursor < value.length) {
      const code = value.charCodeAt(cursor);
      if (code !== 0x5f && !isAsciiLetter(code) && !isAsciiDigit(code)) {
        break;
      }
      cursor += 1;
    }
    return value.slice(start, cursor);
  };
  const listCapacity = () => {
    const start = cursor;
    while (cursor < value.length && isAsciiDigit(value.charCodeAt(cursor))) {
      cursor += 1;
    }
    if (cursor === start) {
      return false;
    }
    const spelling = value.slice(start, cursor);
    if (spelling.length > 1 && spelling[0] === "0") {
      return false;
    }
    const capacity = Number(spelling);
    return Number.isSafeInteger(capacity) && capacity >= 1 && capacity <= 64;
  };

  const parseKey = (depth) => {
    const key = stateMapKeyTypePrefix(value, cursor, depth);
    if (!key || nodes + key.nodes > KOTODAMA_V1_MAX_TYPE_NODES) return null;
    const name = value.slice(cursor, key.end);
    cursor = key.end;
    nodes += key.nodes;
    return name;
  };
  const parseType = (allowStateMap, depth) => {
    nodes += 1;
    if (depth > KOTODAMA_V1_MAX_TYPE_DEPTH || nodes > KOTODAMA_V1_MAX_TYPE_NODES) {
      return null;
    }

    if (consume("()")) return "unit";
    const errorIdentity = /^[\p{L}\p{N}_:/@.-]+/u.exec(value.slice(cursor))?.[0];
    if (errorIdentity?.includes("::") && value[cursor + errorIdentity.length] !== "{" && new TextEncoder().encode(errorIdentity).byteLength <= 1024 && !errorIdentity.includes("__kotodama_link_")) {
      if (errorIdentities !== null && !errorIdentities.has(errorIdentity)) return null;
      cursor += errorIdentity.length;
      return "error";
    }
    if (consume("(")) {
      if (parseType(false, depth + 1) === null || !consume(", ")) {
        return null;
      }
      if (parseType(false, depth + 1) === null) {
        return null;
      }
      while (consume(", ")) {
        if (parseType(false, depth + 1) === null) {
          return null;
        }
      }
      return consume(")") ? "aggregate" : null;
    }

    const qualifiedStruct = /^[A-Za-z0-9_./@:-]+(?=\{)/u.exec(value.slice(cursor))?.[0];
    const name = qualifiedStruct?.includes("::") ? qualifiedStruct : identifier();
    if (qualifiedStruct?.includes("::")) cursor += qualifiedStruct.length;
    if (name === null) {
      return null;
    }
    if (KOTODAMA_V1_STATE_SCALAR_TYPES.has(name)) {
      return name;
    }
    if (name === "Option") {
      if (!consume("<") || parseType(false, depth + 1) === null || !consume(">")) {
        return null;
      }
      return "aggregate";
    }
    if (name === "Result") {
      if (
        !consume("<") ||
        parseType(false, depth + 1) === null ||
        !consume(", ") ||
        parseType(false, depth + 1) === null ||
        !consume(">")
      ) {
        return null;
      }
      return "aggregate";
    }
    if (name === "List") {
      if (
        !consume("<") ||
        parseType(false, depth + 1) === null ||
        !consume(", ") ||
        !listCapacity() ||
        !consume(">")
      ) {
        return null;
      }
      return "aggregate";
    }
    if (name === "StateCursor") {
      if (!consume("<")) return null;
      const key = parseKey(depth + 1);
      return key !== null && consume(">") ? name : null;
    }
    if (name === "StateMap") {
      if (!allowStateMap || !consume("<")) {
        return null;
      }
      const valueNodes = nodes - 1;
      nodes = 0;
      const keyType = parseKey(depth + 1);
      nodes = valueNodes;
      if (
        keyType === null ||
        !consume(", ") ||
        parseType(false, depth + 1) === null ||
        !consume(">")
      ) {
        return null;
      }
      return "aggregate";
    }
    if (name === "kotodama::StatePage") {
      nodes += 4; // List, Tuple, Option, StateCursor; both key occurrences count below.
      if (nodes > KOTODAMA_V1_MAX_TYPE_NODES || depth + 3 > KOTODAMA_V1_MAX_TYPE_DEPTH ||
          !consume("{items: List<(")) return null;
      const key = parseKey(depth + 3);
      if (key === null || !consume(", ") ||
          parseType(false, depth + 3) === null || !consume("), ") || !listCapacity() ||
          !consume(">, next: Option<StateCursor<")) return null;
      return parseKey(depth + 3) === key && consume(">>}") ? "aggregate" : null;
    }
    if (
      !isCanonicalKotodamaStructName(name) ||
      !consume("{")
    ) {
      return null;
    }
    // Empty products retain their validated nominal name and have no fields.
    if (consume("}")) return isExactDurableBuiltinProduct(name, [], []) ? "aggregate" : null;
    const fields = new Set();
    const types = [];
    while (true) {
      const field = identifier();
      if (
        field === null ||
        !isCanonicalKotodamaIdentifier(field) ||
        fields.has(field) ||
        !consume(": ")
      ) {
        return null;
      }
      fields.add(field);
      const childStart = cursor;
      if (parseType(false, depth + 1) === null) {
        return null;
      }
      types.push(value.slice(childStart, cursor));
      if (consume("}")) {
        return isExactDurableBuiltinProduct(name, [...fields], types) ? "aggregate" : null;
      }
      if (!consume(", ")) {
        return null;
      }
    }
  };

  return parseType(true, 1) !== null && cursor === value.length;
}

/**
 * Return the exact key scalar of a canonical top-level V1 `StateMap`, or null
 * when the state type is scalar/aggregate or noncanonical.
 */
export function kotodamaV1StateMapKeyTypeName(value) {
  if (!isCanonicalKotodamaStateTypeName(value)) {
    return null;
  }
  if (!value.startsWith("StateMap<")) return null;
  const key = stateMapKeyTypePrefix(value, "StateMap<".length);
  return key ? value.slice("StateMap<".length, key.end) : null;
}

/** Return whether a string is a normal V1 entrypoint name or branded lifecycle selector. */
export function isCanonicalKotodamaEntrypoint(value) {
  return (
    value === "hajimari" ||
    value === "始まり" ||
    value === "kaizen" ||
    value === "改善" ||
    isCanonicalKotodamaIdentifier(value, { declaration: true })
  );
}
