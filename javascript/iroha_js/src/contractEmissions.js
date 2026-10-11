// Closed native emission records; ledger admission remains the authority for TLV contents.
import { normalizeContractEventsV1 } from "./contractDeclarations.js";

function exact(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new TypeError(`${label} requires exactly ${keys.join(", ")}`);
  }
}
function unsigned(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new TypeError(`${label} must be an unsigned integer in 0..${maximum}`);
  return value;
}
function bytes(value, maximum, label, exactLength = null) {
  if (!Array.isArray(value) || value.length > maximum || (exactLength !== null && value.length !== exactLength)) throw new TypeError(`${label} has an invalid byte length`);
  return Array.from(value, (byte) => unsigned(byte, 255, label));
}
function text(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) throw new TypeError(`${label} must be a canonical nonempty string`);
  return value;
}

/** Preserve the exact native origin, declaration and typed value record. */
export function normalizeContractEmissionV1(value, label = "emission") {
  exact(value, ["contract", "code_hash", "entrypoint", "event", "caller", "definition", "payload"], label);
  const definition = normalizeContractEventsV1([value.definition], `${label}.definition`)[0];
  exact(value.payload, ["schema_hash", "atoms"], `${label}.payload`);
  const schemaHash = bytes(value.payload.schema_hash, 32, `${label}.payload.schema_hash`, 32);
  if (!Array.isArray(value.payload.atoms) || value.payload.atoms.length > 1_048_576) throw new TypeError(`${label}.payload.atoms exceeds its bound`);
  let retainedPointerBytes = 0;
  const atoms = Array.from(value.payload.atoms, (atom, index) => {
    const path = `${label}.payload.atoms[${index}]`;
    exact(atom, ["kind", "value"], path);
    let payload = atom.value;
    switch (atom.kind) {
      case "Tag": case "Bool":
        if (typeof payload !== "boolean") throw new TypeError(`${path}.value must be boolean`);
        break;
      case "Unit":
        if (payload !== null) throw new TypeError(`${path}.value must be null`);
        break;
      case "Pointer": payload = bytes(payload, 1_048_576, `${path}.value`); retainedPointerBytes += payload.length; break;
      case "List": unsigned(payload, 64, `${path}.value`); break;
      case "ErrorCode": case "EnumCode": unsigned(payload, 0xffff_ffff, `${path}.value`); if (payload === 0) throw new TypeError(`${path}.value cannot be zero`); break;
      default: throw new TypeError(`${path}.kind is not a current value atom`);
    }
    if (retainedPointerBytes > 1_048_576) throw new TypeError(`${label}.payload exceeds the public record bound`);
    return { kind: atom.kind, value: payload };
  });
  // Consume only active Option/Result branches and schema-delimited list items.
  const nodes = definition.payload_type.nodes;
  const ends = new Array(nodes.length);
  const children = new Array(nodes.length);
  for (let index = nodes.length - 1; index >= 0; index -= 1) {
    const node = nodes[index];
    const count = node.kind === "Struct" ? node.value.fields.length : node.kind === "Tuple" ? Number(node.value) : node.kind === "Result" ? 2 : ["Option", "List"].includes(node.kind) ? 1 : 0;
    const indexes = [];
    let next = index + 1;
    for (let child = 0; child < count; child += 1) { indexes.push(next); next = ends[next]; }
    children[index] = indexes;
    ends[index] = next;
  }
  let cursor = 0;
  const pending = [0];
  while (pending.length) {
    const index = pending.pop();
    const node = nodes[index];
    if (node.kind === "Struct" || node.kind === "Tuple") { pending.push(...children[index].slice().reverse()); continue; }
    const atom = atoms[cursor++];
    const expected = node.kind === "Leaf" ? (node.value.kind === "Bool" ? "Bool" : "Pointer") : node.kind === "Option" || node.kind === "Result" ? "Tag" : node.kind === "Enum" ? "EnumCode" : node.kind === "Error" ? "ErrorCode" : node.kind;
    if (!atom || atom.kind !== expected) throw new TypeError(`${label}.payload atom does not match ${node.kind}`);
    if (node.kind === "Option" && atom.value) pending.push(children[index][0]);
    if (node.kind === "Result") pending.push(children[index][atom.value ? 0 : 1]);
    if (node.kind === "List") {
      if (atom.value > Number(node.value.capacity)) throw new TypeError(`${label}.payload list exceeds declared capacity`);
      for (let item = 0; item < atom.value; item += 1) pending.push(children[index][0]);
    }
    if ((node.kind === "Enum" || node.kind === "Error") && !node.value.variants.some((variant) => variant.code === atom.value)) throw new TypeError(`${label}.payload has an undeclared nominal code`);
  }
  if (cursor !== atoms.length) throw new TypeError(`${label}.payload has trailing atoms`);
  return {
    contract: text(value.contract, `${label}.contract`), code_hash: text(value.code_hash, `${label}.code_hash`),
    entrypoint: unsigned(value.entrypoint, 0xffff_ffff, `${label}.entrypoint`), event: unsigned(value.event, 0xffff_ffff, `${label}.event`),
    caller: text(value.caller, `${label}.caller`), definition, payload: { schema_hash: schemaHash, atoms },
  };
}
