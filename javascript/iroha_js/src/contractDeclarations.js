// Source-declared durable events share the canonical public schema analyzer.
import { Buffer } from "buffer";
import { analyzeEntrypointValueTypeV1 } from "./entrypointSchema.js";
import { isCanonicalKotodamaIdentifier } from "./kotodamaIdentifiers.js";
import { normalizeContractErrorTypeV1, normalizeContractEnumTypeV1 } from "./contractErrorTypes.js";

/** Normalize the required sorted event table without preserving caller-owned storage. */
export function normalizeContractEventsV1(value, context = "events") {
  if (!Array.isArray(value) || value.length > 256) throw new TypeError(`${context} must be a required array of at most 256 events`);
  let previous = null;
  return Array.from(value, (entry, index) => {
    const label = `${context}[${index}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry) || Object.keys(entry).length !== 2 ||
        !Object.hasOwn(entry, "name") || !Object.hasOwn(entry, "payload_type") || !isCanonicalKotodamaIdentifier(entry.name)) {
      throw new TypeError(`${label} requires exactly a canonical name and payload_type`);
    }
    if (previous !== null && Buffer.compare(Buffer.from(previous), Buffer.from(entry.name)) >= 0) throw new TypeError(`${context} must be sorted and unique by name`);
    previous = entry.name;
    const schema = entry.payload_type;
    analyzeEntrypointValueTypeV1(schema, `${label}.payload_type`);
    const root = schema.nodes[0];
    if (root.kind !== "Struct" || root.value.name.split("::").at(-1) !== entry.name || schema.nodes.some((node) =>
      node.kind === "StateCursor" || (node.kind === "Leaf" && node.value.kind === "Json"))) {
      throw new TypeError(`${label}.payload_type must be a matching qualified struct without Json or StateCursor`);
    }
    const nodes = schema.nodes.map((node) => {
      let payload = node.value;
      if (node.kind === "Enum") payload = normalizeContractEnumTypeV1(payload);
      else if (node.kind === "Error") payload = normalizeContractErrorTypeV1(payload);
      else if (node.kind === "Struct") payload = { name: payload.name, fields: [...payload.fields] };
      else if (payload !== null && typeof payload === "object") payload = { ...payload };
      return { kind: node.kind, value: payload };
    });
    return { name: entry.name, payload_type: { nodes } };
  });
}
