// Decode the one V1 durable-state tree and bind every nominal leaf to its declaration.
import { analyzeStateKeyTypeV1 } from "../entrypointSchema.js";
import { decodeContractMetadataValueV1 } from "../noritoContractMetadata.js";
import { isCanonicalKotodamaIdentifier, isCanonicalKotodamaStructName } from "../kotodamaIdentifiers.js";
import { readU64Le, readCompactField, decodeEmbeddedString, visitEmbeddedVector } from "./embeddedNorito.js";

const SCALARS = ["int", "decimal", "quantity", "bool", "string", "bytes", "DataSpaceId", "AccountId", "AssetDefinitionId", "AssetId", "NftId", "DomainId", "Name", "Json"];
const MAX_NODES = 250_000;
function fail(label, reason) { throw new TypeError(`${label} ${reason}`); }
function finish(bytes, state, label) { if (state.offset !== bytes.length) fail(label, "has trailing or missing bytes"); }
function string(bytes, state, label) {
  const start = state.offset;
  readCompactField(bytes, state, label);
  return decodeEmbeddedString(bytes.subarray(start, state.offset), label);
}
function byteVector(bytes, label) {
  const count = readU64Le(bytes, 0, label);
  if (count !== BigInt(bytes.length - 8)) fail(label, "has a noncanonical byte vector");
  return bytes.subarray(8);
}
function tree(bytes, label, catalogs, budget, depth = 1) {
  if (depth > 256 || ++budget.nodes > MAX_NODES) fail(label, "exceeds the state type depth or node budget");
  if (bytes.length === 0) fail(label, "has a missing state type tag");
  const tag = bytes[0];
  const state = { offset: 1 };
  if (tag < 14 || tag === 20) {
    finish(bytes, state, label);
    return { name: tag === 20 ? "()" : SCALARS[tag], scalar: tag < 14 && tag !== 13 };
  }
  if (tag === 21 || tag === 23) {
    const kind = tag === 21 ? "error_type" : "enum_type";
    const descriptor = decodeContractMetadataValueV1(kind, bytes.subarray(1));
    if (catalogs[kind].get(descriptor.identity) !== JSON.stringify(descriptor)) fail(label, "does not match its declared nominal catalog");
    return { name: descriptor.identity, scalar: false };
  }
  if (tag === 22) {
    const key = decodeContractMetadataValueV1("value_type", bytes.subarray(1));
    const analysis = analyzeStateKeyTypeV1(key, label);
    budget.nodes += analysis.nodeCount;
    if (budget.nodes > MAX_NODES || depth + analysis.maxDepth > 256) fail(label, "exceeds cursor key schema budget");
    return { name: `StateCursor<${analysis.canonicalName}>`, scalar: false };
  }
  const child = (value) => tree(value, label, catalogs, budget, depth + 1);
  const ownedChild = () => child(byteVector(readCompactField(bytes, state, label), label));
  let name;
  let scalar = false;
  if (tag === 14 || tag === 15) {
    const structName = tag === 15 ? string(bytes, state, label) : null;
    const children = [];
    const names = new Set();
    visitEmbeddedVector(bytes.subarray(state.offset), label, MAX_NODES, (encoded) => {
      const value = byteVector(encoded, label);
      if (tag === 14) { const item = child(value); children.push(item.name); scalar = children.length === 1 ? item.scalar : scalar && item.scalar; }
      else {
        const fieldState = { offset: 0 };
        const fieldName = string(value, fieldState, label);
        if (!isCanonicalKotodamaIdentifier(fieldName) || names.has(fieldName)) fail(label, "has an invalid or repeated state field");
        names.add(fieldName);
        const fieldType = child(byteVector(value.subarray(fieldState.offset), label));
        children.push(`${fieldName}: ${fieldType.name}`);
      }
    });
    if (tag === 14 && children.length < 2) fail(label, "requires tuple arity of at least two");
    if (tag === 15 && !isCanonicalKotodamaStructName(structName)) fail(label, "has an invalid state struct name");
    name = tag === 14 ? `(${children.join(", ")})` : `${structName}{${children.join(", ")}}`;
    state.offset = bytes.length;
  } else if (tag === 16 || tag === 18) {
    const first = ownedChild();
    const second = ownedChild();
    if (tag === 16 && (depth !== 1 || !first.scalar)) fail(label, "requires a root state map with a scalar or tuple key");
    name = `${tag === 16 ? "StateMap" : "Result"}<${first.name}, ${second.name}>`;
  } else if (tag === 17 || tag === 19) {
    const element = ownedChild();
    if (tag === 17) name = `Option<${element.name}>`;
    else {
      const capacity = bytes[state.offset++];
      if (!(capacity >= 1 && capacity <= 64)) fail(label, "requires List capacity in 1..64");
      name = `List<${element.name}, ${capacity}>`;
    }
  } else fail(label, "has an unknown state type tag");
  finish(bytes, state, label);
  return { name, scalar };
}

/** Validate exact source state projections, including every nested nominal descriptor. */
export function validateEmbeddedStates(bytes, states, errorTypes, enumTypes, label = "CNTR.states") {
  const catalogs = {
    error_type: new Map(errorTypes.map((entry) => [entry.identity, JSON.stringify(entry)])),
    enum_type: new Map(enumTypes.map((entry) => [entry.identity, JSON.stringify(entry)])),
  };
  const budget = { nodes: 0 };
  let index = 0;
  const count = visitEmbeddedVector(bytes, label, MAX_NODES, (entry, itemLabel) => {
    const state = { offset: 0 };
    const name = decodeEmbeddedString(readCompactField(entry, state, itemLabel), itemLabel);
    // EmbeddedStateType serializes its tagged tree as one Norito byte vector.
    const encodedType = byteVector(readCompactField(entry, state, itemLabel), itemLabel);
    const ty = tree(encodedType, itemLabel, catalogs, budget);
    finish(entry, state, itemLabel);
    const expected = states[index++];
    if (!expected || expected.name !== name || expected.type_name !== ty.name) fail(itemLabel, "does not exactly match the manifest state descriptor");
  });
  if (count !== states.length) fail(label, "does not match the manifest state count");
}
