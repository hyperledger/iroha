import { normalizeContractEmissionV1 } from "../src/contractEmissions.js";
import assert from "node:assert/strict";
import test from "node:test";
import { normalizeContractEnumTypesV1, validateManifestErrorTypeBindingsV1 } from "../src/contractErrorTypes.js";
import { normalizeContractEventsV1 } from "../src/contractDeclarations.js";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { canonicalContractArguments } from "../src/contractPayload.js";
import { encodeContractMetadataValueV1, decodeContractMetadataValueV1 } from "../src/noritoContractMetadata.js";
import { validateEmbeddedStates } from "../src/kotodamaCompiler/embeddedStateSchema.js";
import { validateEmbeddedCallables } from "../src/kotodamaCompiler/embeddedCallSchema.js";

const descriptor = { identity: "Demo::Status", variants: [{ name: "Open", code: 1 }, { name: "Done", code: 7 }] };
const node = { kind: "Enum", value: descriptor };
const schema = { nodes: [node] };
const event = { name: "Changed", payload_type: { nodes: [{ kind: "Struct", value: { name: "Demo::Changed", fields: ["status"] } }, node] } };
const manifest = () => ({ enum_types: [descriptor], events: [event], error_types: null, error_messages: null, entrypoints: [], states: [{ name: "status", type_name: descriptor.identity }] });
const join = (...parts) => Buffer.concat(parts);
const u32 = (n) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(n); return bytes; };
const u64 = (n) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(n)); return bytes; };
const field = (bytes) => { let length = bytes.length; const prefix = []; do { const byte = length % 128; length = Math.floor(length / 128); prefix.push(byte | (length ? 128 : 0)); } while (length); return join(Buffer.from(prefix), bytes); };
const vector = (items) => join(u64(items.length), ...items.map(field));
const string = (value) => field(Buffer.from(value));
const state = (type) => vector([join(field(string("status")), field(join(u64(type.length), type)))]);
const nominal = (value = descriptor) => join(Buffer.of(23), encodeContractMetadataValueV1("enum_type", value));

test("ordinary enums retain exact symbolic JSON names, independent of error catalogs", () => {
  analyzeEntrypointValueTypeV1(schema);
  const argumentsSchema = { fields: [{ name: "status", ty: schema }] };
  assert.deepEqual(canonicalContractArguments({ status: "Done" }, { argumentSchema: argumentsSchema }), { status: "Done" });
  for (const status of [7, "7", "done", { Done: null }]) assert.throws(() => canonicalContractArguments({ status }, { argumentSchema: argumentsSchema }), /enum variant name/u);
  validateManifestErrorTypeBindingsV1(manifest());
  assert.throws(() => validateManifestErrorTypeBindingsV1({ ...manifest(), enum_types: [] }), /declared|catalog/u);
  assert.throws(() => validateManifestErrorTypeBindingsV1({ ...manifest(), error_types: [descriptor] }), /overlap/u);
  const forged = structuredClone(manifest());
  forged.events[0].payload_type.nodes[1].value = structuredClone(descriptor);
  forged.events[0].payload_type.nodes[1].value.variants[1].code = 8;
  assert.throws(() => validateManifestErrorTypeBindingsV1(forged), /declared|catalog/u);
});

test("required declaration tables reject old, unordered and malformed metadata", () => {
  for (const value of [undefined, null, {}, [descriptor, descriptor], [{ ...descriptor, variants: [{ name: "Open", code: 0 }] }]]) assert.throws(() => normalizeContractEnumTypesV1(value));
  for (const value of [undefined, null, [event, event], [{ ...event, unknown: 1 }]]) assert.throws(() => normalizeContractEventsV1(value));
  for (const badNode of [{ kind: "Leaf", value: { kind: "Json", value: null } }, { kind: "StateCursor", value: { nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }] } }]) {
    assert.throws(() => normalizeContractEventsV1([{ ...event, payload_type: { nodes: [event.payload_type.nodes[0], badNode] } }]), /Json or StateCursor/u);
  }
  assert.throws(() => normalizeContractEventsV1([{ ...event, name: "Other" }]), /matching qualified struct/u);
});

test("canonical enum/event Norito tables roundtrip and enforce encoded byte bounds", () => {
  for (const [kind, value] of [["enum_types", [descriptor]], ["events", [event]]]) {
    const encoded = encodeContractMetadataValueV1(kind, value);
    assert.deepEqual(decodeContractMetadataValueV1(kind, encoded), value);
    assert.throws(() => decodeContractMetadataValueV1(kind, join(encoded, Buffer.of(0))), /trailing|canonical/u);
  }
  const excessive = Array.from({ length: 100 }, (_, index) => ({ ...descriptor, identity: `Demo::${String(index).padStart(3, "0")}${"a".repeat(990)}` }));
  assert.throws(() => encodeContractMetadataValueV1("enum_types", excessive), /64|65536|bound/u);
});

test("embedded state trees authenticate nested ordinary enums and exact state projections", () => {
  validateEmbeddedStates(state(nominal()), manifest().states, [], [descriptor]);
  const option = join(Buffer.of(17), field(join(u64(nominal().length), nominal())));
  validateEmbeddedStates(state(option), [{ name: "status", type_name: `Option<${descriptor.identity}>` }], [], [descriptor]);
  const forged = { ...descriptor, variants: [{ name: "Open", code: 2 }] };
  assert.throws(() => validateEmbeddedStates(state(nominal(forged)), manifest().states, [], [descriptor]), /catalog/u);
  assert.throws(() => validateEmbeddedStates(state(nominal()), [{ name: "status", type_name: "int" }], [], [descriptor]), /descriptor/u);
  assert.throws(() => validateEmbeddedStates(state(join(nominal(), Buffer.of(0))), manifest().states, [], [descriptor]), /trailing|canonical/u);
});

test("private callable enum tapes require their exact signed declaration", () => {
  const tape = (nodes) => join(Buffer.from([0x43, 0x53, 0x31, 0]), u64(nodes.length), ...nodes);
  const callable = (value) => vector([join(field(u64(0)), field(u32(0)), field(tape([join(Buffer.of(12), field(encodeContractMetadataValueV1("enum_type", value)))])), field(tape([Buffer.of(6)])))]);
  assert.equal(validateEmbeddedCallables(callable(descriptor), 0, 1, "callables", [], [descriptor]), 0n);
  assert.throws(() => validateEmbeddedCallables(callable(descriptor), 0, 1, "callables", [], []), /catalog/u);
  const forged = { ...descriptor, variants: [{ name: "Open", code: 2 }] };
  assert.throws(() => validateEmbeddedCallables(callable(forged), 0, 1, "callables", [], [descriptor]), /catalog/u);
});


test("native emissions retain typed nominal atoms and reject retired or malformed records", () => {
  const value = { contract: "contract", code_hash: "hash", entrypoint: 0, event: 0, caller: "caller", definition: event, payload: { schema_hash: Array(32).fill(1), atoms: [{ kind: "EnumCode", value: 7 }] } };
  assert.deepEqual(normalizeContractEmissionV1(value), value);
  for (const mutation of [
    (record) => { record.permission = "retired"; },
    (record) => { record.payload.schema_hash.pop(); },
    (record) => { record.payload.atoms[0].kind = "ErrorCode"; },
    (record) => { record.payload.atoms[0].value = 0; },
    (record) => { record.payload.atoms[0].value = 8; },
    (record) => { record.payload.atoms.push({ kind: "Unit", value: null }); },
    (record) => { record.payload.atoms[0].extra = true; },
  ]) {
    const malformed = structuredClone(value);
    mutation(malformed);
    assert.throws(() => normalizeContractEmissionV1(malformed));
  }
});


test("enum and event declarations use the generated event and emit keyword policy", () => {
  for (const name of ["event", "emit"]) {
    assert.throws(() => normalizeContractEnumTypesV1([{ ...descriptor, variants: [{ name, code: 1 }] }]));
    assert.throws(() => normalizeContractEventsV1([{ name, payload_type: { nodes: [{ kind: "Struct", value: { name, fields: [] } }] } }]));
  }
});
