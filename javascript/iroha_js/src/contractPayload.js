import { blake3 } from "@noble/hashes/blake3";

/** Browser profile for the canonical `IrohaJson` contract payload preimage. */
export const CONTRACT_PAYLOAD_MAX_CANONICAL_BYTES = 1_048_576;
export const CONTRACT_PAYLOAD_MAX_DEPTH = 128;
export const CONTRACT_PAYLOAD_MAX_NODES = 1_000_000;

const encoder = new TextEncoder();

function fail(path, message, ErrorType = TypeError) {
  throw new ErrorType(`contract payload ${path} ${message}`);
}

function isWellFormedUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const low = value.charCodeAt(index + 1);
      if (low < 0xdc00 || low > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function compareUtf8(left, right) {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index] - rightBytes[index];
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function quoteNoritoJsonString(value, path) {
  if (!isWellFormedUnicode(value)) {
    fail(path, "must contain only Unicode scalar values");
  }
  let output = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    switch (character) {
      case '"':
        output += '\\"';
        break;
      case "\\":
        output += "\\\\";
        break;
      case "\n":
        output += "\\n";
        break;
      case "\r":
        output += "\\r";
        break;
      case "\t":
        output += "\\t";
        break;
      case "\b":
        output += "\\b";
        break;
      case "\f":
        output += "\\f";
        break;
      default:
        if (codePoint < 0x20) {
          output += `\\u00${codePoint.toString(16).padStart(2, "0")}`;
        } else {
          output += character;
        }
    }
  }
  return `${output}"`;
}

function canonicalize(value) {
  const state = {
    ancestors: new Set(),
    nodes: 0,
  };

  const encode = (current, depth, path) => {
    state.nodes += 1;
    if (state.nodes > CONTRACT_PAYLOAD_MAX_NODES) {
      fail(path, `exceeds the ${CONTRACT_PAYLOAD_MAX_NODES}-node browser limit`, RangeError);
    }
    if (depth > CONTRACT_PAYLOAD_MAX_DEPTH) {
      fail(path, `exceeds the ${CONTRACT_PAYLOAD_MAX_DEPTH}-level browser limit`, RangeError);
    }
    if (current === null) return "null";
    switch (typeof current) {
      case "boolean":
        return current ? "true" : "false";
      case "string":
        return quoteNoritoJsonString(current, path);
      case "number":
        if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
          fail(path, "numbers must be canonical safe integers; encode decimals as strings");
        }
        return String(current);
      case "object": {
        if (state.ancestors.has(current)) fail(path, "must not contain cycles");
        state.ancestors.add(current);
        try {
          if (Array.isArray(current)) {
            if (Object.getPrototypeOf(current) !== Array.prototype) {
              fail(path, "arrays must use Array.prototype");
            }
            const ownKeys = Reflect.ownKeys(current);
            if (ownKeys.length !== current.length + 1 || !ownKeys.includes("length")) {
              fail(path, "arrays must be dense and contain no custom properties");
            }
            const items = [];
            for (let index = 0; index < current.length; index += 1) {
              const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
              if (
                !descriptor
                || !descriptor.enumerable
                || !Object.prototype.hasOwnProperty.call(descriptor, "value")
              ) {
                fail(`${path}[${index}]`, "must be a dense data element");
              }
              items.push(encode(descriptor.value, depth + 1, `${path}[${index}]`));
            }
            return `[${items.join(",")}]`;
          }

          const prototype = Object.getPrototypeOf(current);
          if (prototype !== Object.prototype && prototype !== null) {
            fail(path, "objects must have the default or null prototype");
          }
          const entries = [];
          for (const key of Reflect.ownKeys(current)) {
            if (typeof key !== "string") {
              fail(path, "must not contain symbol keys");
            }
            if (!isWellFormedUnicode(key)) {
              fail(path, "keys must contain only Unicode scalar values");
            }
            const descriptor = Object.getOwnPropertyDescriptor(current, key);
            if (
              !descriptor
              || !descriptor.enumerable
              || !Object.prototype.hasOwnProperty.call(descriptor, "value")
            ) {
              fail(path, "objects must contain only enumerable data properties");
            }
            entries.push([key, descriptor.value]);
          }
          entries.sort(([left], [right]) => compareUtf8(left, right));
          return `{${entries
            .map(([key, entry]) =>
              `${quoteNoritoJsonString(key, `${path} key`)}:${encode(entry, depth + 1, `${path}.${key}`)}`)
            .join(",")}}`;
        } finally {
          state.ancestors.delete(current);
        }
      }
      default:
        fail(path, `contains unsupported ${typeof current} values`);
    }
  };

  return encode(value, 0, "root");
}

const INT_PATTERN = /^-?(?:0|[1-9][0-9]*)$/u;
const DECIMAL_PATTERN = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/u;
const UNSIGNED_DIGITS_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const HEX_BYTES_PATTERN = /^0x(?:[0-9a-f]{2})*$/u;

function describeFound(value) {
  if (value === null) return "null";
  if (value === undefined) return "no value";
  if (Array.isArray(value)) return `an array of ${value.length} element(s)`;
  switch (typeof value) {
    case "number":
      return `the JSON number ${String(value)}`;
    case "bigint":
      return `the bigint ${value.toString()}n`;
    case "string":
      return value.length <= 48 ? `the string ${JSON.stringify(value)}` : "a long string";
    case "boolean":
      return `the boolean ${value}`;
    case "object":
      return "an object";
    default:
      return `a ${typeof value}`;
  }
}

function argumentFailure(path, expected, value) {
  const location = path === "" ? "arguments" : `argument \`${path}\``;
  throw new TypeError(
    `contract payload ${location} expects ${expected}, found ${describeFound(value)}`,
  );
}

function childPath(parent, field) {
  return parent === "" ? field : `${parent}.${field}`;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireExactObject(value, fields, path, expected) {
  if (!isPlainObject(value)) argumentFailure(path, expected, value);
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      argumentFailure(childPath(path, field), "a value for this declared field", undefined);
    }
  }
  for (const key of Object.keys(value)) {
    if (!fields.includes(key)) {
      throw new TypeError(
        `contract payload argument \`${childPath(path, key)}\` is not declared by the entrypoint argument schema`,
      );
    }
  }
  return value;
}

function schemaFailure(path) {
  throw new TypeError(
    `contract payload ${path === "" ? "arguments" : `argument \`${path}\``} has an invalid V1 argument schema node`,
  );
}

/**
 * Read a schema count (tuple arity or list capacity) published as a number, bigint or canonical
 * unsigned decimal string, as manifest JSON may carry either form.
 */
function schemaCount(value, path) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "bigint" && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  if (typeof value === "string" && UNSIGNED_DIGITS_PATTERN.test(value)) {
    const count = Number(value);
    if (Number.isSafeInteger(count)) return count;
  }
  return schemaFailure(path);
}

/** Return the index just past the preorder subtree rooted at `start`. */
function subtreeEnd(nodes, start, path) {
  let index = start;
  let pending = 1;
  while (pending > 0) {
    const node = nodes[index];
    if (!node || typeof node.kind !== "string") schemaFailure(path);
    pending -= 1;
    index += 1;
    switch (node.kind) {
      case "Struct":
        pending += node.value?.fields?.length ?? schemaFailure(path);
        break;
      case "Tuple":
        pending += schemaCount(node.value, path);
        break;
      case "Option":
      case "List":
        pending += 1;
        break;
      case "Result":
        pending += 2;
        break;
      case "Leaf":
      case "Unit":
      case "Error":
      case "Enum":
      case "StateCursor":
        break;
      default:
        schemaFailure(path);
    }
  }
  return index;
}

function canonicalExactNumber(value, path, expected, pattern) {
  if (typeof value === "string") {
    if (!pattern.test(value) || value === "-0") argumentFailure(path, expected, value);
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0)) {
    return String(value);
  }
  return argumentFailure(path, expected, value);
}

function canonicalLeaf(kind, value, path) {
  switch (kind) {
    case "Int":
      return canonicalExactNumber(
        value,
        path,
        "int as a canonical decimal integer string such as \"5\"",
        INT_PATTERN,
      );
    case "Decimal":
      return canonicalExactNumber(
        value,
        path,
        "decimal as a canonical decimal string such as \"1.25\"; binary floating-point numbers are not exact",
        DECIMAL_PATTERN,
      );
    case "Quantity": {
      const expected = "quantity as a canonical non-negative decimal string such as \"10\"; binary floating-point numbers are not exact";
      const canonical = canonicalExactNumber(value, path, expected, DECIMAL_PATTERN);
      if (canonical.startsWith("-")) argumentFailure(path, expected, value);
      return canonical;
    }
    case "Bool":
      return typeof value === "boolean" ? value : argumentFailure(path, "bool as true or false", value);
    case "DataSpaceId": {
      const expected = "DataSpaceId as a non-negative safe JSON integer";
      if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)) {
        return value;
      }
      if (
        (typeof value === "bigint" && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER))
        || (typeof value === "string" && UNSIGNED_DIGITS_PATTERN.test(value)
          && Number.isSafeInteger(Number(value)))
      ) {
        return Number(value);
      }
      return argumentFailure(path, expected, value);
    }
    case "Blob":
      if (value instanceof Uint8Array) {
        return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
      }
      return typeof value === "string" && HEX_BYTES_PATTERN.test(value)
        ? value
        : argumentFailure(path, "bytes as a 0x-prefixed lowercase hexadecimal string", value);
    case "Json":
      return value;
    case "String":
    case "Name":
    case "AccountId":
    case "AssetDefinitionId":
    case "AssetId":
    case "DomainId":
    case "NftId":
      return typeof value === "string"
        ? value
        : argumentFailure(path, `${kind === "String" ? "string" : kind} as a JSON string`, value);
    default:
      return schemaFailure(path);
  }
}

function canonicalNode(nodes, start, value, path, depth) {
  if (depth > CONTRACT_PAYLOAD_MAX_DEPTH) {
    throw new RangeError(
      `contract payload argument \`${path}\` exceeds the ${CONTRACT_PAYLOAD_MAX_DEPTH}-level browser limit`,
    );
  }
  const node = nodes[start];
  if (!node || typeof node.kind !== "string") schemaFailure(path);
  switch (node.kind) {
    case "Leaf":
      return canonicalLeaf(node.value?.kind, value, path);
    case "Unit":
      return value === null ? null : argumentFailure(path, "unit as null", value);
    case "Error":
    case "Enum": {
      const variants = (node.value?.variants ?? []).map((variant) => variant.name);
      return typeof value === "string" && variants.includes(value)
        ? value
        : argumentFailure(
          path,
          `an ${node.kind === "Enum" ? "enum" : "error"} variant name of \`${node.value?.identity}\` (one of ${variants.map((name) => `\`${name}\``).join(", ")})`,
          value,
        );
    }
    case "StateCursor":
      return typeof value === "string" && HEX_BYTES_PATTERN.test(value)
        ? value
        : argumentFailure(path, "a state cursor as a 0x-prefixed lowercase hexadecimal string", value);
    case "Struct": {
      const fields = node.value?.fields ?? schemaFailure(path);
      requireExactObject(
        value,
        fields,
        path,
        `struct \`${node.value.name}\` as an object with exactly the fields ${fields.map((field) => `\`${field}\``).join(", ")}`,
      );
      const output = {};
      let child = start + 1;
      for (const field of fields) {
        const fieldPath = childPath(path, field);
        output[field] = canonicalNode(nodes, child, value[field], fieldPath, depth + 1);
        child = subtreeEnd(nodes, child, fieldPath);
      }
      return output;
    }
    case "Tuple": {
      const arity = schemaCount(node.value, path);
      if (!Array.isArray(value) || value.length !== arity) {
        argumentFailure(path, `a tuple as a JSON array of exactly ${arity} element(s)`, value);
      }
      const output = [];
      let child = start + 1;
      for (let index = 0; index < arity; index += 1) {
        const elementPath = `${path}[${index}]`;
        output.push(canonicalNode(nodes, child, value[index], elementPath, depth + 1));
        child = subtreeEnd(nodes, child, elementPath);
      }
      return output;
    }
    case "List": {
      const capacity = schemaCount(node.value?.capacity, path);
      if (!Array.isArray(value) || value.length > capacity) {
        argumentFailure(path, `a list as a JSON array of at most ${capacity} element(s)`, value);
      }
      return value.map((element, index) =>
        canonicalNode(nodes, start + 1, element, `${path}[${index}]`, depth + 1));
    }
    case "Option": {
      const expected = "an option as {\"some\": value} or {\"none\": true}";
      if (!isPlainObject(value) || Object.keys(value).length !== 1) {
        argumentFailure(path, expected, value);
      }
      if (Object.prototype.hasOwnProperty.call(value, "some")) {
        return { some: canonicalNode(nodes, start + 1, value.some, childPath(path, "some"), depth + 1) };
      }
      if (value.none === true) return { none: true };
      return argumentFailure(path, expected, value);
    }
    case "Result": {
      const expected = "a result as {\"ok\": value} or {\"err\": value}";
      if (!isPlainObject(value) || Object.keys(value).length !== 1) {
        argumentFailure(path, expected, value);
      }
      if (Object.prototype.hasOwnProperty.call(value, "ok")) {
        return { ok: canonicalNode(nodes, start + 1, value.ok, childPath(path, "ok"), depth + 1) };
      }
      if (Object.prototype.hasOwnProperty.call(value, "err")) {
        const errStart = subtreeEnd(nodes, start + 1, path);
        return { err: canonicalNode(nodes, errStart, value.err, childPath(path, "err"), depth + 1) };
      }
      return argumentFailure(path, expected, value);
    }
    default:
      return schemaFailure(path);
  }
}

function rejectSchemalessNumbers(value, path, depth) {
  if (depth > CONTRACT_PAYLOAD_MAX_DEPTH) {
    throw new RangeError(
      `contract payload argument \`${path}\` exceeds the ${CONTRACT_PAYLOAD_MAX_DEPTH}-level browser limit`,
    );
  }
  if (typeof value === "number" || typeof value === "bigint") {
    throw new TypeError(
      `contract payload ${path === "" ? "arguments" : `argument \`${path}\``} is ${describeFound(value)}; `
        + "without the entrypoint argument schema a number cannot be checked against int, decimal "
        + "or quantity parameters, which take canonical decimal strings such as \"5\". Pass the "
        + "entrypoint's argumentSchema to canonicalize numbers, or pass the canonical string",
    );
  }
  if (Array.isArray(value)) {
    value.forEach((element, index) => rejectSchemalessNumbers(element, `${path}[${index}]`, depth + 1));
  } else if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      rejectSchemalessNumbers(entry, childPath(path, key), depth + 1);
    }
  }
}

/**
 * Canonicalize named contract arguments before they are signed or hashed.
 *
 * With `options.argumentSchema` set to an entrypoint's signed `argument_schema`, every value is
 * checked against its declared type: `int`, `decimal` and `quantity` values given as JavaScript
 * safe integers or bigints become their canonical decimal strings, `DataSpaceId` stays a JSON
 * integer, and mismatches throw with the exact argument path. `argumentSchema: null` declares a
 * zero-parameter entrypoint, which accepts only an absent payload or `{}`.
 *
 * Without an `argumentSchema` option the declared types are unknown, so any JSON number is rejected
 * with its argument path rather than guessed. Returns `null` for an absent payload.
 */
export function canonicalContractArguments(payload, options = {}) {
  if (options === null || typeof options !== "object") {
    throw new TypeError("contract payload options must be an object");
  }
  if (!Object.prototype.hasOwnProperty.call(options, "argumentSchema")) {
    if (payload === undefined || payload === null) return null;
    canonicalize(payload);
    rejectSchemalessNumbers(payload, "", 0);
    return payload;
  }
  const schema = options.argumentSchema;
  if (schema === null || schema === undefined) {
    if (payload === undefined || payload === null) return null;
    if (isPlainObject(payload) && Object.keys(payload).length === 0) return null;
    return argumentFailure("", "no arguments for this zero-parameter entrypoint", payload);
  }
  const fields = Array.isArray(schema.fields) ? schema.fields : schemaFailure("");
  const names = fields.map((field) => field.name);
  requireExactObject(
    payload,
    names,
    "",
    `an object with exactly the named arguments ${names.map((name) => `\`${name}\``).join(", ")}`,
  );
  const output = {};
  for (const field of fields) {
    const nodes = field.ty?.nodes;
    if (!Array.isArray(nodes) || subtreeEnd(nodes, 0, field.name) !== nodes.length) {
      schemaFailure(field.name);
    }
    output[field.name] = canonicalNode(nodes, 0, payload[field.name], field.name, 0);
  }
  canonicalize(output);
  return output;
}

/**
 * Return the exact compact JSON text hashed by Torii for the current browser contract profile.
 *
 * `null` and `undefined` mean that the optional payload is absent. Raw floating-point and unsafe
 * integer values are rejected because the browser does not expose Rust's Ryu formatter.
 *
 * Without options this hashes exactly the JSON that will be sent, so it accepts safe integers that
 * only `Json` and `DataSpaceId` parameters can use. Pass `{ argumentSchema }` to first apply
 * {@link canonicalContractArguments}, which stringifies or rejects numbers for `int`, `decimal` and
 * `quantity` parameters with the argument path.
 */
export function canonicalContractPayloadJson(payload, options) {
  const value = options === undefined ? payload : canonicalContractArguments(payload, options);
  if (value === undefined || value === null) return null;
  const canonical = canonicalize(value);
  const byteLength = encoder.encode(canonical).length;
  if (byteLength > CONTRACT_PAYLOAD_MAX_CANONICAL_BYTES) {
    throw new RangeError(
      `canonical contract payload exceeds ${CONTRACT_PAYLOAD_MAX_CANONICAL_BYTES} UTF-8 bytes`,
    );
  }
  return canonical;
}

/**
 * Compute Torii's lowercase BLAKE3 digest over the exact canonical payload preimage.
 * `options` has the same meaning as for {@link canonicalContractPayloadJson}.
 */
export function contractPayloadDigestHex(payload, options) {
  const canonical = canonicalContractPayloadJson(payload, options);
  const digest = blake3(encoder.encode(canonical ?? ""));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
