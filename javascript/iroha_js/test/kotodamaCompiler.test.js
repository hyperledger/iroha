import { encodeContractMetadataValueV1 } from "../src/noritoContractMetadata.js";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

import {
  KotodamaCompilerClient,
  compileKotodamaProgram,
} from "../src/kotodamaCompiler/index.js";
import {
  compileKotodamaProgram as compileKotodamaInBrowser,
} from "../src/kotodamaCompiler/browser.js";
import { compileKotodamaWithNativeBinding } from "../src/kotodamaCompiler/nativeBridge.js";
import { buildCompilerRequest } from "../src/kotodamaCompiler/client.js";
import { validateEmbeddedCallables } from "../src/kotodamaCompiler/embeddedCallSchema.js";
import { normalizeCompilerResult } from "../src/kotodamaCompiler/normalize.js";
import { blake2b256 } from "../src/blake2b.js";
import {
  KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS,
  KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS,
  KOTODAMA_V1_DECLARATION_RESERVED,
  KOTODAMA_V1_KEYWORDS,
  KOTODAMA_V1_RETIRED_TYPE_NAMES,
  KOTODAMA_V1_STATE_MAP_KEY_TYPES,
  isCanonicalKotodamaDynamicAccessBaseKey,
  isCanonicalKotodamaIdentifier,
  isCanonicalKotodamaStateTypeName,
  isKotodamaV1DynamicAccessBoundKind,
  isKotodamaV1StateMapKeyTypeName,
  kotodamaV1StateMapKeyTypeName,
} from "../src/kotodamaIdentifiers.js";

const CRC64_MASK = 0xffff_ffff_ffff_ffffn;
const CRC64_POLYNOMIAL = 0xc96c5795d7870f42n;
const IVM_EXECUTION_HEADER_BYTES = 17;
const IVM_ABI_HASH_BYTES = 32;
const IVM_HEADER_BYTES = IVM_EXECUTION_HEADER_BYTES + IVM_ABI_HASH_BYTES;
const SERVICE_ABI_HASH = "23".repeat(IVM_ABI_HASH_BYTES);
const CRC64_TABLE = Array.from({ length: 256 }, (_, index) => {
  let crc = BigInt(index);
  for (let bit = 0; bit < 8; bit += 1) {
    crc = (crc & 1n) === 0n ? crc >> 1n : (crc >> 1n) ^ CRC64_POLYNOMIAL;
  }
  return crc;
});

test("Kotodama identifier policy forbids exact Amount globally", () => {
  assert.equal(KOTODAMA_V1_DECLARATION_RESERVED.includes("Amount"), false);
  assert.equal(isCanonicalKotodamaIdentifier("Amount"), false);
  assert.equal(isCanonicalKotodamaIdentifier("Amount", { declaration: true }), false);
  assert.equal(isCanonicalKotodamaIdentifier("Amount", { typeDeclaration: true }), false);
  assert.equal(KOTODAMA_V1_RETIRED_TYPE_NAMES.includes("Amount"), true);

  assert.equal(isCanonicalKotodamaIdentifier("amount"), true);
  assert.equal(isCanonicalKotodamaIdentifier("amount", { declaration: true }), true);
  assert.equal(isCanonicalKotodamaIdentifier("amount", { typeDeclaration: true }), false);
  assert.equal(KOTODAMA_V1_RETIRED_TYPE_NAMES.includes("amount"), true);

  for (const name of ["int", "decimal", "quantity"]) {
    assert.equal(isCanonicalKotodamaIdentifier(name), true);
    assert.equal(isCanonicalKotodamaIdentifier(name, { declaration: true }), false);
  }
});

test("Kotodama dynamic-access policy exposes the exact ordered V1 contract", () => {
  assert.deepEqual(KOTODAMA_V1_STATE_MAP_KEY_TYPES, [
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
  assert.deepEqual(KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS, ["page", "take"]);
  assert.equal(KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS, 64);

  for (const keyType of KOTODAMA_V1_STATE_MAP_KEY_TYPES) {
    assert.equal(isKotodamaV1StateMapKeyTypeName(keyType), true, keyType);
  }
  for (const keyType of ["Json", "ReferendumId", "Int", "Quantity", "Amount"]) {
    assert.equal(isKotodamaV1StateMapKeyTypeName(keyType), false, keyType);
  }
  for (const boundKind of KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS) {
    assert.equal(isKotodamaV1DynamicAccessBoundKind(boundKind), true, boundKind);
  }
  for (const boundKind of ["", "Take", "prefix", "range "]) {
    assert.equal(isKotodamaV1DynamicAccessBoundKind(boundKind), false, boundKind);
  }
  for (const baseKey of ["state:Balances", "state:amount", "state:_private2"]) {
    assert.equal(isCanonicalKotodamaDynamicAccessBaseKey(baseKey), true, baseKey);
  }
  for (const baseKey of [
    "",
    "state:",
    "state:*",
    "state:Balances/",
    "state:Balances/suffix",
    "state:Balances:suffix",
    "state:Amount",
    "state:int",
    "state:state",
    "state:__kotodama_link_forged",
    "account:alice",
    " state:Balances",
    "state:Balances ",
  ]) {
    assert.equal(isCanonicalKotodamaDynamicAccessBaseKey(baseKey), false, baseKey);
  }

  assert.equal(
    kotodamaV1StateMapKeyTypeName("StateMap<AccountId, quantity>"),
    "AccountId",
  );
  assert.equal(
    kotodamaV1StateMapKeyTypeName("StateMap<quantity, int>"),
    "quantity",
  );
  for (const typeName of [
    "quantity",
    "Option<StateMap<AccountId, quantity>>",
    "StateMap<AccountId, Amount>",
    "StateMap<AccountId,quantity>",
  ]) {
    assert.equal(kotodamaV1StateMapKeyTypeName(typeName), null, typeName);
  }
});

test("Kotodama state type names reject retired types without poisoning fields", () => {
  for (const canonical of [
    "quantity",
    "(int, decimal)",
    "Option<Result<quantity, string>>",
    "List<Fixture::Transfer{amount: quantity}, 64>",
    "StateMap<AccountId, Fixture::Transfer{amount: quantity, memo: Option<string>}>",
  ]) {
    assert.equal(
      isCanonicalKotodamaStateTypeName(canonical),
      true,
      `${canonical} must be canonical`,
    );
  }
  for (const retiredOrMalformed of [
    "Amount",
    "amount",
    "Amount: quantity",
    "Option<Amount>",
    "List<amount, 1>",
    "StateMap<AccountId, Amount>",
    "StateMap<AccountId, Amount: quantity>",
    "Fixture::Transfer{Amount: quantity}",
    "Fixture::Transfer{amount: amount}",
    "Fixture::Transfer{amount:: quantity}",
    "Amount{amount: quantity}",
    "Fixture::Transfer{amount: quantity, amount: int}",
    "Option<StateMap<AccountId, quantity>>",
    "StateMap<Json, quantity>",
    "List<quantity, 01>",
    "Transfer {amount: quantity}",
  ]) {
    assert.equal(
      isCanonicalKotodamaStateTypeName(retiredOrMalformed),
      false,
      `${retiredOrMalformed} must be rejected`,
    );
  }
});

test("Kotodama state type names enforce the runtime 256-node schema boundary", () => {
  const wideType = (nodes) =>
    `(${Array.from({ length: nodes - 1 }, () => "int").join(", ")})`;
  const deepType = (nodes) =>
    `${"Option<".repeat(nodes - 1)}int${">".repeat(nodes - 1)}`;

  assert.equal(isCanonicalKotodamaStateTypeName(wideType(256)), true);
  assert.equal(isCanonicalKotodamaStateTypeName(deepType(256)), true);
  assert.equal(
    isCanonicalKotodamaStateTypeName(`StateMap<AccountId, ${wideType(256)}>`),
    true,
    "StateMap wrapper and key are outside its stored value node budget",
  );
  assert.equal(
    isCanonicalKotodamaStateTypeName(`StateMap<AccountId, ${deepType(255)}>`),
    true,
    "StateMap wrapper consumes one CNTR descriptor-depth level",
  );
  assert.equal(
    isCanonicalKotodamaStateTypeName(`StateMap<AccountId, ${deepType(256)}>`),
    false,
  );
  for (const overLimit of [wideType(257), deepType(257)]) {
    assert.equal(isCanonicalKotodamaStateTypeName(overLimit), false);
    assert.equal(
      isCanonicalKotodamaStateTypeName(`StateMap<AccountId, ${overLimit}>`),
      false,
    );
  }
});

function u32Le(value) {
  return Uint8Array.from([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

function u32Be(value) {
  return Uint8Array.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function readU32LeForTest(bytes, offset) {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] * 0x1000000)
  ) >>> 0;
}

function u64Le(value) {
  let remaining = BigInt(value);
  return Uint8Array.from({ length: 8 }, () => {
    const byte = Number(remaining & 0xffn);
    remaining >>= 8n;
    return byte;
  });
}

function compactLength(value) {
  let remaining = BigInt(value);
  const bytes = [];
  do {
    const byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    bytes.push(remaining === 0n ? byte : byte | 0x80);
  } while (remaining !== 0n);
  return Uint8Array.from(bytes);
}

function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function field(payload) {
  return concatBytes(compactLength(payload.length), payload);
}

function stringField(value) {
  return field(new TextEncoder().encode(value));
}

function crc64(payload) {
  let crc = CRC64_MASK;
  for (const byte of payload) {
    crc = CRC64_TABLE[Number((crc ^ BigInt(byte)) & 0xffn)] ^ (crc >> 8n);
  }
  return BigInt.asUintN(64, crc ^ CRC64_MASK);
}

function callableFixture({
  entryPc = 0,
  frameBytes = 0,
  argumentNodes = [],
  resultNodes = [Uint8Array.of(6)],
  argumentSchemaBytes,
  resultSchemaBytes,
} = {}) {
  const schema = (items) => concatBytes(Uint8Array.of(0x43, 0x53, 0x31, 0), u64Le(items.length), ...items);
  return concatBytes(
    field(u64Le(entryPc)),
    field(u32Le(frameBytes)),
    field(argumentSchemaBytes ?? schema(argumentNodes)),
    field(resultSchemaBytes ?? schema(resultNodes)),
  );
}

// A callable cursor carries a length-prefixed complete public key schema.
function callableCursorFixture(kind) {
  const kinds = ["Int", "Decimal", "Quantity", "Bool", "String", "Json", "Name", "AccountId", "AssetDefinitionId", "AssetId", "DomainId", "NftId", "DataSpaceId", "Blob"];
  return concatBytes(Uint8Array.of(8), field(encodeContractMetadataValueV1("value_type", {
    nodes: [{ kind: "Leaf", value: { kind: kinds[kind], value: null } }],
  })));
}

function compilerArtifactFixture({
  name = "Demo",
  fingerprint = "kotodama_lang/test",
  features = 0,
  accessHints = false,
  kotoba = 0,
  entrypoints = 1,
  states = 0,
  errorTypes = [],
  permissions = [],
  events = [],
  enumTypes = [],
  manifest = null,
  errorMessages = [],
  omitErrorMessages = false,
  callables = Array.from({ length: entrypoints }, (_, index) => callableFixture({ entryPc: index * 4 })),
  omitCallables = false,
  interfaceAbiByte = 0x23,
  headerAbiByte = 0x23,
} = {}) {
  const vector = (count) => concatBytes(
    u64Le(count),
    ...Array.from({ length: count }, () => field(Uint8Array.from([0]))),
  );
  const interfacePayload = concatBytes(
    field(stringField(name)),
    field(stringField(fingerprint)),
    field(Uint8Array.from({ length: IVM_ABI_HASH_BYTES }, () => interfaceAbiByte)),
    field(u64Le(features)),
    field(accessHints ? Uint8Array.from([1, 1, 0]) : Uint8Array.from([0])),
    field(encodeContractMetadataValueV1("permissions", manifest?.permissions ?? permissions)),
    field(encodeContractMetadataValueV1("events", manifest?.events ?? events)),
    field(vector(kotoba)),
    field(concatBytes(u64Le(entrypoints), ...Array.from({ length: entrypoints }, (_, index) => {
      const entry = manifest?.entrypoints[index] ?? compilerEntrypoint("ping", "View");
      let declaration;
      // Negative tests intentionally use invalid manifests. Their rejection is
      // checked before artifact projection; keep that artifact well formed.
      try { declaration = encodeContractMetadataValueV1("entrypoint", entry); }
      catch { declaration = encodeContractMetadataValueV1("entrypoint", compilerEntrypoint("ping", "View")); }
      return field(concatBytes(declaration, field(u64Le(index * 4))));
    }))),
    ...(omitCallables ? [] : [field(concatBytes(u64Le(callables.length), ...callables.map(field)))]),
    field(concatBytes(u64Le(states), ...Array.from({ length: states }, (_, index) => {
      const descriptor = manifest?.states[index] ?? { name: "state", type_name: "int" };
      const scalars = ["int", "decimal", "quantity", "bool", "string", "bytes", "DataSpaceId", "AccountId", "AssetDefinitionId", "AssetId", "NftId", "DomainId", "Name", "Json"];
      let ty = Uint8Array.of(Math.max(0, scalars.indexOf(descriptor.type_name)));
      const enumType = manifest?.enum_types.find((value) => value.identity === descriptor.type_name);
      if (enumType) ty = concatBytes(Uint8Array.of(23), encodeContractMetadataValueV1("enum_type", enumType));
      if (descriptor.type_name === "Fixture::Transfer{amount: quantity}") {
        const member = concatBytes(stringField("amount"), u64Le(1), Uint8Array.of(2));
        ty = concatBytes(Uint8Array.of(15), stringField("Fixture::Transfer"), u64Le(1), field(concatBytes(u64Le(member.length), member)));
      }
      return field(concatBytes(field(stringField(descriptor.name)), field(concatBytes(u64Le(ty.length), ty))));
    }))),
    field(encodeContractMetadataValueV1("error_types", manifest?.error_types ?? errorTypes)),
    field(encodeContractMetadataValueV1("enum_types", manifest?.enum_types ?? enumTypes)),
    ...(omitErrorMessages ? [] : [field(concatBytes(u64Le(errorMessages.length), ...errorMessages.map((entry) => field(concatBytes(field(stringField(entry.error_type)), field(u32Le(entry.code)), field(stringField(entry.message)))))))]),
  );
  const frame = concatBytes(
    new TextEncoder().encode("NRT0"),
    Uint8Array.from([0, 0]),
    Uint8Array.from([
      0x42, 0x78, 0xc4, 0x14, 0x19, 0x7d, 0x68, 0xd9,
      0xcb, 0xb2, 0xda, 0xde, 0xa7, 0x40, 0x23, 0x87,
    ]),
    Uint8Array.from([0]),
    u64Le(interfacePayload.length),
    u64Le(crc64(interfacePayload)),
    Uint8Array.from([0x02]),
    interfacePayload,
  );
  const header = concatBytes(
    Uint8Array.from([0x49, 0x56, 0x4d, 0x00, 1, 1, features & 0x03, 0]),
    u64Le(1_000_000),
    Uint8Array.from([1]),
    Uint8Array.from({ length: IVM_ABI_HASH_BYTES }, () => headerAbiByte),
  );
  return concatBytes(
    header,
    new TextEncoder().encode("CNTR"),
    u32Le(frame.length),
    frame,
    new Uint8Array(Math.max(1, callables.length) * 4),
  );
}

function pointerLiteralFixture({
  typeId = 0x0006,
  version = 1,
  payload = Uint8Array.from([1, 2, 3]),
  declaredLength = payload.length,
} = {}) {
  const hash = blake2b256(payload);
  hash[hash.length - 1] |= 1;
  return concatBytes(
    Uint8Array.from([(typeId >>> 8) & 0xff, typeId & 0xff, version]),
    u32Be(declaredLength),
    payload,
    hash,
  );
}

function literalSectionStart(artifact) {
  return IVM_HEADER_BYTES + 8 + readU32LeForTest(artifact, IVM_HEADER_BYTES + 4);
}

function literalArtifactFixture(literals, { unindexedData = new Uint8Array() } = {}) {
  const artifact = compilerArtifactFixture();
  const start = literalSectionStart(artifact);
  const entriesLength = literals.length * 8;
  const descriptors = [];
  const payloads = [];
  let relativeOffset = 16 + entriesLength;
  for (const literal of literals) {
    descriptors.push(u64Le((BigInt(literal.kind) << 56n) | BigInt(relativeOffset)));
    payloads.push(literal.bytes);
    relativeOffset += literal.bytes.length;
  }
  const data = concatBytes(...payloads, unindexedData);
  const unpaddedLengthFromHeader =
    start - IVM_HEADER_BYTES + 16 + entriesLength + data.length;
  const padding = (4 - (unpaddedLengthFromHeader % 4)) % 4;
  const section = concatBytes(
    new TextEncoder().encode("LTLB"),
    u32Le(literals.length),
    u32Le(padding),
    u32Le(data.length),
    ...descriptors,
    data,
    new Uint8Array(padding),
  );
  return concatBytes(
    artifact.subarray(0, start),
    section,
    artifact.subarray(start),
  );
}

const SERVICE_ARTIFACT = compilerArtifactFixture();
const CONTRACT_HASH_DOMAIN = new TextEncoder().encode("iroha:ivm:contract-artifact:v1\0");
const SERVICE_HASH_INPUT = new Uint8Array(
  CONTRACT_HASH_DOMAIN.length + SERVICE_ARTIFACT.length,
);
SERVICE_HASH_INPUT.set(CONTRACT_HASH_DOMAIN);
SERVICE_HASH_INPUT.set(SERVICE_ARTIFACT, CONTRACT_HASH_DOMAIN.length);
const SERVICE_CODE_HASH_BYTES = blake2b256(SERVICE_HASH_INPUT);
SERVICE_CODE_HASH_BYTES[SERVICE_CODE_HASH_BYTES.length - 1] |= 1;
const SERVICE_CODE_HASH = Array.from(
  SERVICE_CODE_HASH_BYTES,
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");
function compilerEntrypoint(name, kind, permission = null) {
  return {
    name,
    kind: { kind, value: null },
    params: [],
    argument_schema: null,
    return_type: "()",
    return_schema: { nodes: [{ kind: "Unit", value: null }] },
    authorization: permission === null ? { kind: ["Hajimari", "Kaizen"].includes(kind) ? "RuntimeLifecycle" : "Anyone", value: null } : { kind: "Permission", value: permission },
    read_keys: [],
    write_keys: [],
    access_hints_complete: true,
    access_hints_skipped: [],
    triggers: [],
  };
}

function canonicalHashLiteral(hex) {
  const body = hex.toUpperCase();
  let crc = 0xffff;
  const processByte = (byte) => {
    crc ^= (byte & 0xff) << 8;
    for (let index = 0; index < 8; index += 1) {
      crc =
        (crc & 0x8000) !== 0
          ? ((crc << 1) ^ 0x1021) & 0xffff
          : (crc << 1) & 0xffff;
    }
  };
  for (const byte of new TextEncoder().encode(`hash:${body}`)) {
    processByte(byte);
  }
  return `hash:${body}#${crc.toString(16).toUpperCase().padStart(4, "0")}`;
}

const SERVICE_OUTPUT = {
  artifactBytes: [...SERVICE_ARTIFACT],
  manifestJson: JSON.stringify({
    seiyaku_name: "Demo",
    code_hash: canonicalHashLiteral(SERVICE_CODE_HASH),
    abi_hash: canonicalHashLiteral(SERVICE_ABI_HASH),
    compiler_fingerprint: "kotodama_lang/test",
    features_bitmap: 0,
    access_set_hints: null,
    permissions: [],
    events: [],
    enum_types: [],
    entrypoints: [
      compilerEntrypoint("ping", "View"),
    ],
    states: [],
    error_types: null,
    error_messages: null,
    kotoba: null,
    provenance: null,
  }),
  codeHash: SERVICE_CODE_HASH,
  abiHash: SERVICE_ABI_HASH,
  sourceMapJson: JSON.stringify({
    sidecar_version: 1,
    kind: "source-map",
    artifact_hash: SERVICE_CODE_HASH,
    entries: [{
      source_kind: "function",
      function_name: "ping",
      pc_start: 0,
      pc_end: 4,
      source_path: null,
      source_id: 0,
      byte_start: 0,
      byte_end: 4,
      line: 1,
      column: 1,
    }],
  }),
  budgetReportJson: JSON.stringify({
    sidecar_version: 1,
    kind: "budget",
    artifact_hash: SERVICE_CODE_HASH,
    entries: [{
      function_name: "ping",
      pc_start: 0,
      pc_end: 4,
      bytecode_bytes: 4,
      bytecode_words: 1,
      frame_bytes: 0,
      jump_span_words: 1,
      jump_range_risk: false,
      source_path: null,
      source_id: 0,
      byte_start: 0,
      byte_end: 4,
      line: 1,
      column: 1,
    }],
    access_hint_diagnostics: {
      state_wildcards: 0,
      isi_wildcards: 0,
      literal_trigger_spec_decode_failures: 0,
    },
  }),
};

const SERVICE_SUCCESS = {
  ok: true,
  output: SERVICE_OUTPUT,
  diagnosticsJson: null,
};

test("JavaScript identifier validation consumes the normative V1 keyword table", () => {
  const grammar = readFileSync(
    new URL("../../../crates/kotodama_lang/grammar/v1.lex", import.meta.url),
    "utf8",
  );
  const keywords = grammar
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("keyword\t"))
    .map((line) => line.split("\t")[1]);
  assert.deepEqual(KOTODAMA_V1_KEYWORDS, keywords);
  for (const retired of ["contract", "entry", "init", "upgrade"]) {
    assert.equal(keywords.includes(retired), false);
  }

  const semantic = readFileSync(
    new URL("../../../crates/kotodama_surface/src/source_policy.rs", import.meta.url),
    "utf8",
  );
  const typeTable = /pub const V1_SOURCE_TYPE_NAMES: &\[&str\] = &\[([\s\S]*?)\];/u.exec(
    semantic,
  );
  assert.ok(typeTable, "semantic V1 source-type table is missing");
  const typeNames = [...typeTable[1].matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"/gu)].map(
    (match) => match[1],
  );
  const reservedExtraTable =
    /pub const V1_DECLARATION_RESERVED_EXTRA_NAMES: &\[&str\] = &\[([\s\S]*?)\];/u.exec(
      semantic,
    );
  assert.ok(reservedExtraTable, "semantic V1 reserved-extra table is missing");
  const reservedExtraNames = [
    ...reservedExtraTable[1].matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"/gu),
  ].map((match) => match[1]);
  assert.deepEqual(KOTODAMA_V1_DECLARATION_RESERVED, [
    ...typeNames,
    ...reservedExtraNames,
  ]);
});

const SERVICE_DIAGNOSTICS = [
  {
    code: "K1001",
    alternative_fixes: [{
      span: {
        package_identity: null, source: "契約/送金.ko",
        start: { line: 2, column: 9 }, end: { line: 2, column: 9 },
        byte_range: { start: 20, end: 20 },
      },
      replacement: "quantity amount",
    }],
    localized: { language: "ja", message: "引数名が必要です", help: "型と名前を記述してください" },
    severity: "error",
    phase: "parse",
    message: "expected parameter name",
    primary_span: {
      package_identity: null,
      source: "契約/送金.ko",
      start: { line: 2, column: 9 },
      end: { line: 2, column: 10 },
      byte_range: { start: 20, end: 24 },
    },
    labels: [
      {
        span: {
          package_identity: null,
          source: "契約/送金.ko",
          start: { line: 2, column: 3 },
          end: { line: 2, column: 7 },
          byte_range: { start: 12, end: 16 },
        },
        message: "while parsing this entrypoint",
      },
    ],
    notes: ["the preceding 🙂 occupies one Unicode display column"],
    help: "write Type name",
    fix: {
      span: {
        package_identity: null,
        source: "契約/送金.ko",
        start: { line: 2, column: 9 },
        end: { line: 2, column: 9 },
        byte_range: { start: 20, end: 20 },
      },
      replacement: "int amount",
    },
  },
  {
    code: "K2002",
    alternative_fixes: [],
    localized: null,
    severity: "error",
    phase: "resolve",
    message: "unknown name `missing`",
    primary_span: {
      package_identity: "std/example@1.0.0",
      source: "契約/送金.ko",
      start: { line: 4, column: 5 },
      end: { line: 4, column: 12 },
      byte_range: { start: 48, end: 55 },
    },
    labels: [],
    notes: [],
    help: null,
    fix: null,
  },
];

const SERVICE_FAILURE = {
  ok: false,
  output: null,
  diagnosticsJson: JSON.stringify(SERVICE_DIAGNOSTICS),
};

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

function successfulFetch(calls, value = SERVICE_SUCCESS) {
  return async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(value);
  };
}

async function captureRejection(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected promise to reject");
}

function compileMutatedServiceResponse(mutate, matchArtifact = false) {
  const response = structuredClone(SERVICE_SUCCESS);
  const manifest = JSON.parse(response.output.manifestJson);
  const sourceMap = JSON.parse(response.output.sourceMapJson);
  const budget = JSON.parse(response.output.budgetReportJson);
  mutate({ response, manifest, sourceMap, budget });
  if (matchArtifact) {
    const matched = serviceSuccessWithArtifact(compilerArtifactFixture({ manifest, entrypoints: manifest.entrypoints.length }), (target) => Object.assign(target, manifest));
    Object.assign(response.output, matched.output);
    const hash = response.output.codeHash;
    manifest.code_hash = canonicalHashLiteral(hash);
    sourceMap.artifact_hash = hash;
    budget.artifact_hash = hash;
  }
  response.output.manifestJson = JSON.stringify(manifest);
  response.output.sourceMapJson = JSON.stringify(sourceMap);
  response.output.budgetReportJson = JSON.stringify(budget);
  return compileKotodamaWithNativeBinding(
    { async compileKotodama() { return response; } },
    "seiyaku Demo {}",
  );
}

function serviceSuccessWithArtifact(artifact, mutateManifest = () => {}) {
  const response = structuredClone(SERVICE_SUCCESS);
  const bytes = Uint8Array.from(artifact);
  const hashInput = new Uint8Array(CONTRACT_HASH_DOMAIN.length + bytes.length);
  hashInput.set(CONTRACT_HASH_DOMAIN);
  hashInput.set(bytes, CONTRACT_HASH_DOMAIN.length);
  const hash = blake2b256(hashInput);
  hash[hash.length - 1] |= 1;
  const codeHash = Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const manifest = JSON.parse(response.output.manifestJson);
  mutateManifest(manifest);
  manifest.code_hash = canonicalHashLiteral(codeHash);
  response.output.artifactBytes = [...bytes];
  response.output.codeHash = codeHash;
  response.output.manifestJson = JSON.stringify(manifest);
  for (const key of ["sourceMapJson", "budgetReportJson"]) {
    const sidecar = JSON.parse(response.output[key]);
    sidecar.artifact_hash = codeHash;
    response.output[key] = JSON.stringify(sidecar);
  }
  return response;
}

test("JavaScript ships only adapters to the canonical Rust compiler", () => {
  const expectedFiles = [
    "browser.js",
    "client.js",
    "embeddedCallSchema.js",
    "embeddedNorito.js",
    "embeddedStateSchema.js",
    "index.js",
    "nativeBridge.js",
    "normalize.js",
  ];
  for (const directory of ["../src/kotodamaCompiler/", "../dist/kotodamaCompiler/"]) {
    const actualFiles = readdirSync(new URL(directory, import.meta.url), {
      withFileTypes: true,
    })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();
    assert.deepEqual(
      actualFiles,
      expectedFiles,
      `${directory} must not contain an independent JavaScript compiler`,
    );
  }
  for (const file of expectedFiles) {
    assert.equal(
      readFileSync(new URL(`../src/kotodamaCompiler/${file}`, import.meta.url), "utf8"),
      readFileSync(new URL(`../dist/kotodamaCompiler/${file}`, import.meta.url), "utf8"),
      `dist/kotodamaCompiler/${file} must exactly match src`,
    );
  }
});

test("TypeScript separates bounded request policy from remote transport controls", () => {
  const declarations = readFileSync(
    new URL("../kotodama-compiler.d.ts", import.meta.url),
    "utf8",
  );
  const requestStart = declarations.indexOf(
    "export interface KotodamaCompilerRequestOptions",
  );
  const requestEnd = declarations.indexOf(
    "export interface KotodamaCompilerOutput",
    requestStart,
  );
  assert.ok(requestStart >= 0 && requestEnd > requestStart);
  const requestDeclarations = declarations.slice(requestStart, requestEnd);
  assert.match(requestDeclarations, /sourceName\?: string;/u);
  assert.match(requestDeclarations, /zk\?: boolean;/u);
  assert.match(requestDeclarations, /signal\?: AbortSignal;/u);
  assert.match(requestDeclarations, /timeoutMs\?: number;/u);
  assert.match(requestDeclarations, /source: string;[\s\S]*zk: boolean;/u);
  assert.doesNotMatch(
    requestDeclarations,
    /abiVersion|forceVector|embedDebug|forceZk|testMode/u,
  );
  assert.match(
    declarations,
    /compile\(\s*source: string,\s*options\?: KotodamaCompilerCallOptions,/u,
  );
  assert.match(
    declarations,
    /kind: "Kotoage" \| "View" \| "Hajimari" \| "Kaizen";/u,
  );
  assert.doesNotMatch(
    declarations,
    /kind: "Public" \| "View" \| "Init" \| "Upgrade";/u,
  );
  assert.doesNotMatch(declarations, /kind:\s*\n\s*\| "public"/u);
  assert.match(
    declarations,
    /KotodamaCompiledEntrypointValueKindName\s*=\s*\| "Int"\s*\| "Decimal"\s*\| "Quantity"/u,
  );
  assert.doesNotMatch(declarations, /\| "(?:Amount|U128)"/u);
  const rootDeclarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  assert.match(
    rootDeclarations,
    /ContractEntrypointValueKindName\s*=\s*\| "Int"\s*\| "Decimal"\s*\| "Quantity"/u,
  );
  const rootKindStart = rootDeclarations.indexOf("export type ContractEntrypointValueKindName");
  const rootKindEnd = rootDeclarations.indexOf("export interface", rootKindStart);
  assert.doesNotMatch(rootDeclarations.slice(rootKindStart, rootKindEnd), /"(?:Amount|U128)"/u);
});

test("Node delegates asynchronously to iroha_js_host exactly once", async () => {
  const source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
  const options = { sourceName: "contracts/demo.ko", zk: true };
  let finishCompilation;
  const nativeCompletion = new Promise((resolve) => {
    finishCompilation = resolve;
  });
  const calls = [];
  const native = {
    compileKotodama(receivedSource) {
      calls.push(receivedSource);
      return nativeCompletion;
    },
  };

  let settled = false;
  const resultPromise = compileKotodamaWithNativeBinding(native, source, options);
  resultPromise.then(() => {
    settled = true;
  });
  assert.ok(resultPromise instanceof Promise);
  assert.deepEqual(calls, [{ source, artifacts: [], sourceName: "contracts/demo.ko", zk: true }]);
  await Promise.resolve();
  assert.equal(settled, false, "the adapter must await the asynchronous native task");

  finishCompilation(SERVICE_SUCCESS);
  const result = await resultPromise;
  assert.equal(result.ok, true);
  assert.deepEqual([...result.output.artifactBytes], [...SERVICE_ARTIFACT]);
  assert.equal(result.output.manifest.entrypoints[0].kind.kind, "View");
  assert.deepEqual(
    calls,
    [{ source, artifacts: [], sourceName: "contracts/demo.ko", zk: true }],
    "one SDK request must perform one native compilation",
  );

  await assert.rejects(
    compileKotodamaWithNativeBinding({}, source),
    /native binding is missing compileKotodama/,
  );
});

test("compiler adapters reject retired English manifest entrypoint kinds", async () => {
  for (const retired of ["Public", "public", "Init", "init", "Upgrade", "upgrade"]) {
    const response = structuredClone(SERVICE_SUCCESS);
    const manifest = JSON.parse(response.output.manifestJson);
    manifest.entrypoints[0].kind.kind = retired;
    response.output.manifestJson = JSON.stringify(manifest);
    const native = {
      async compileKotodama() {
        return response;
      },
    };
    await assert.rejects(
      compileKotodamaWithNativeBinding(native, "seiyaku Demo {}"),
      /must be Kotoage, View, Hajimari, or Kaizen/,
    );
  }
});

test("compiler adapters preserve branded selectors and reject forged manifest declarations", async () => {
  const compileResponse = async (mutateManifest) => {
    const response = structuredClone(SERVICE_SUCCESS);
    const manifest = JSON.parse(response.output.manifestJson);
    mutateManifest(manifest);
    const artifact = compilerArtifactFixture({
      name: manifest.seiyaku_name,
      fingerprint: manifest.compiler_fingerprint,
      features: manifest.features_bitmap,
      accessHints: manifest.access_set_hints !== null,
      kotoba: manifest.kotoba?.length ?? 0,
      entrypoints: manifest.entrypoints?.length ?? 0,
      states: manifest.states?.length ?? 0,
      errorTypes: manifest.error_types ?? [],
      manifest,
    });
    const matched = serviceSuccessWithArtifact(artifact, (target) => {
      for (const key of Object.keys(target)) delete target[key];
      Object.assign(target, manifest);
    });
    return compileKotodamaWithNativeBinding(
      { async compileKotodama() { return matched; } },
      "seiyaku Demo {}",
    );
  };

  const branded = await compileResponse((manifest) => {
    manifest.entrypoints = [
      compilerEntrypoint("始まり", "Hajimari"),
      compilerEntrypoint("kaizen", "Kaizen"),
      compilerEntrypoint("mutate", "Kotoage", "Mutate"),
    ];
    manifest.permissions = [{ name: "Mutate", scope: { kind: "Instance", value: null } }];
  });
  assert.deepEqual(
    branded.output.manifest.entrypoints.map((entrypoint) => entrypoint.name),
    ["始まり", "kaizen", "mutate"],
  );

  const contextualAmount = await compileResponse((manifest) => {
    manifest.states = [
      { name: "amount", type_name: "Fixture::Transfer{amount: quantity}" },
    ];
    manifest.error_types = [
      { identity: "LedgerError", variants: [{ name: "amount", code: 7 }] },
    ];
  });
  assert.deepEqual(contextualAmount.output.manifest.states, [
    { name: "amount", type_name: "Fixture::Transfer{amount: quantity}" },
  ]);
  assert.equal(contextualAmount.output.manifest.error_types[0].variants[0].name, "amount");

  const retiredIdentifierCases = [
    ["entrypoint", (manifest) => {
      manifest.entrypoints = [compilerEntrypoint("Amount", "View")];
    }, /entrypoint 0\.name is not a canonical V1 identifier/u],
    ["parameter", (manifest) => {
      const entrypoint = compilerEntrypoint("inspect", "View");
      entrypoint.params = [{ name: "Amount", type_name: "quantity" }];
      entrypoint.argument_schema = {
        fields: [{
          name: "Amount",
          ty: { nodes: [{ kind: "Leaf", value: { kind: "Quantity", value: null } }] },
        }],
      };
      manifest.entrypoints = [entrypoint];
    }, /params\[0\]\.name must be unique and canonical/u],
    ["state", (manifest) => {
      manifest.states = [{ name: "Amount", type_name: "quantity" }];
    }, /state 0\.name is not canonical/u],
    ["struct field", (manifest) => {
      manifest.states = [{ name: "Balances", type_name: "Fixture::Transfer{Amount: quantity}" }];
    }, /state 0\.type_name is not a canonical V1 state type/u],
    ["error variant", (manifest) => {
      manifest.error_types = [{ identity: "LedgerError", variants: [{ name: "Amount", code: 7 }] }];
    }, /canonical variant identifier|stable package\/unit\/enum identity/u],
    ["dynamic state base", (manifest) => {
      manifest.access_set_hints = {
        read_keys: [],
        write_keys: [],
        dynamic_reads: [{
          base_key: "state:Amount",
          key_type: "AccountId",
          bound_kind: "take",
          max_keys: 1,
        }],
        dynamic_writes: [],
      };
    }, /base_key must be state: plus one canonical state declaration identifier/u],
  ];
  for (const [label, mutate, expected] of retiredIdentifierCases) {
    await assert.rejects(
      compileResponse(mutate),
      expected,
      `exact Amount ${label} must be rejected`,
    );
  }

  for (const seiyakuName of [
    "Amount",
    "amount",
    "seiyaku",
    "match",
    "int",
    "decimal",
    "quantity",
    "state_map_get",
    "__kotodama_link_forged",
  ]) {
    await assert.rejects(
      compileResponse((manifest) => {
        manifest.seiyaku_name = seiyakuName;
      }),
      /seiyaku_name must be a canonical V1 type declaration identifier/u,
    );
  }
  for (const typeName of [
    "Amount",
    "amount",
    "StateMap<AccountId, Amount>",
    "Fixture::Transfer{amount: amount}",
  ]) {
    await assert.rejects(
      compileResponse((manifest) => {
        manifest.states = [{ name: "Balances", type_name: typeName }];
      }),
      /state 0\.type_name is not a canonical V1 state type/u,
    );
  }
  for (const namespace of ["Invalid Error", "Error<Injected>"]) {
    await assert.rejects(
      compileResponse((manifest) => {
        manifest.error_types = [
          { identity: namespace, variants: [{ name: "Denied", code: 7 }] },
        ];
      }),
      /canonical variant identifier|stable package\/unit\/enum identity/u,
    );
  }
  await assert.rejects(
    compileResponse((manifest) => {
      manifest.contract_name = manifest.seiyaku_name;
    }),
    /must use seiyaku_name; contract_name is not a V1 field/u,
  );
  await assert.rejects(
    compileResponse((manifest) => {
      manifest.entrypoints = [
        compilerEntrypoint("init", "Hajimari"),
      ];
    }),
    /kind does not match its branded lifecycle selector/u,
  );
  await assert.rejects(
    compileResponse((manifest) => {
      manifest.entrypoints = [
        { ...compilerEntrypoint("run", "Kotoage"), authorization: { kind: "Permission", value: "Missing" } },
      ];
    }),
    /undeclared permission/u,
  );
  await assert.rejects(
    compileResponse((manifest) => {
      manifest.states = [
        { name: "match", type_name: "int" },
      ];
    }),
    /state 0.name is not canonical/u,
  );
  await assert.rejects(
    compileResponse((manifest) => {
      manifest.error_types = [
        { identity: "LedgerError", variants: [{ name: "Denied", code: 7 }] },
        { identity: "LedgerError", variants: [{ name: "Missing", code: 7 }] },
      ];
    }),
    /duplicate error identity/u,
  );
});

test("compiler manifest numeric entrypoint schemas match the canonical V1 leaf set", async () => {
  const result = await compileMutatedServiceResponse(({ manifest }) => {
    const entrypoint = compilerEntrypoint("calculate", "View");
    entrypoint.params = [
      { name: "rate", type_name: "decimal" },
      { name: "amount", type_name: "quantity" },
    ];
    entrypoint.argument_schema = {
      fields: [
        {
          name: "rate",
          ty: { nodes: [{ kind: "Leaf", value: { kind: "Decimal", value: null } }] },
        },
        {
          name: "amount",
          ty: { nodes: [{ kind: "Leaf", value: { kind: "Quantity", value: null } }] },
        },
      ],
    };
    entrypoint.return_type = "decimal";
    entrypoint.return_schema = {
      nodes: [{ kind: "Leaf", value: { kind: "Decimal", value: null } }],
    };
    manifest.entrypoints = [entrypoint];
  }, true);
  assert.equal(result.ok, true);
  assert.deepEqual(
    result.output.manifest.entrypoints[0].argument_schema.fields.map(
      (field) => field.ty.nodes[0].value.kind,
    ),
    ["Decimal", "Quantity"],
  );

  for (const retired of ["Amount", "U128"]) {
    await assert.rejects(
      compileMutatedServiceResponse(({ manifest }) => {
        const entrypoint = compilerEntrypoint("legacy", "View");
        entrypoint.params = [{ name: "value", type_name: retired }];
        entrypoint.argument_schema = {
          fields: [{
            name: "value",
            ty: { nodes: [{ kind: "Leaf", value: { kind: retired, value: null } }] },
          }],
        };
        manifest.entrypoints = [entrypoint];
      }),
      /not a canonical V1 entrypoint value kind/u,
    );
  }
});

test("compiler manifests admit arguments and results beyond the retired register limit", async () => {
  const result = await compileMutatedServiceResponse(({ manifest }) => {
    const entrypoint = manifest.entrypoints[0];
    entrypoint.params = Array.from({ length: 32 }, (_, index) => ({
      name: `value${index}`,
      type_name: "int",
    }));
    const integer = { kind: "Leaf", value: { kind: "Int", value: null } };
    entrypoint.argument_schema = {
      fields: entrypoint.params.map(({ name }) => ({ name, ty: { nodes: [integer] } })),
    };
    entrypoint.return_type = `(${Array.from({ length: 32 }, () => "int").join(", ")})`;
    entrypoint.return_schema = {
      nodes: [{ kind: "Tuple", value: 32 }, ...Array.from({ length: 32 }, () => integer)],
    };
  }, true);
  assert.equal(result.ok, true);
  assert.equal(result.output.manifest.entrypoints[0].params.length, 32);
  assert.equal(result.output.manifest.entrypoints[0].return_schema.nodes.length, 33);
});

test("compiler manifest boundary rejects unknown, inconsistent, and unbounded data", async () => {
  const cases = [
    ["unknown manifest field", ({ manifest }) => { manifest.unknown = true; }, /invalid field set/u],
    ["missing manifest field", ({ manifest }) => { delete manifest.features_bitmap; }, /invalid field set/u],
    ["unsafe features bitmap", ({ manifest }) => {
      manifest.features_bitmap = Number.MAX_SAFE_INTEGER + 1;
    }, /features_bitmap.*unsigned safe integer/u],
    ["unknown features bitmap bit", ({ manifest }) => {
      manifest.features_bitmap = 4;
    }, /features_bitmap.*0\.\.3/u],
    ["unknown entrypoint field", ({ manifest }) => {
      manifest.entrypoints[0].unknown = true;
    }, /entrypoint 0 has an invalid field set/u],
    ["missing argument schema", ({ manifest }) => {
      manifest.entrypoints[0].params = [{ name: "value", type_name: "int" }];
    }, /argument_schema is required/u],
    ["parameter/schema mismatch", ({ manifest }) => {
      const entrypoint = manifest.entrypoints[0];
      entrypoint.params = [{ name: "value", type_name: "int" }];
      entrypoint.argument_schema = {
        fields: [{
          name: "other",
          ty: { nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }] },
        }],
      };
    }, /does not match its declared parameter/u],
    ["too many parameters", ({ manifest }) => {
      const entrypoint = manifest.entrypoints[0];
      entrypoint.params = Array.from({ length: 8193 }, (_, index) => ({
        name: `value${index}`,
        type_name: "int",
      }));
      entrypoint.argument_schema = { fields: [] };
    }, /at most 8192 items/u],
    ["missing Unit return descriptors", ({ manifest }) => {
      manifest.entrypoints[0].return_type = null;
      manifest.entrypoints[0].return_schema = null;
    }, /return_type and return_schema must be present together/u],
    ["missing Unit return type", ({ manifest }) => {
      manifest.entrypoints[0].return_type = null;
    }, /return_type and return_schema must be present together/u],
    ["missing Unit return schema", ({ manifest }) => {
      manifest.entrypoints[0].return_schema = null;
    }, /return_type and return_schema must be present together/u],
    ["return schema mismatch", ({ manifest }) => {
      const entrypoint = manifest.entrypoints[0];
      entrypoint.return_type = "decimal";
      entrypoint.return_schema = {
        nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }],
      };
    }, /return_type does not match return_schema/u],
    ["invalid dynamic bound", ({ manifest }) => {
      manifest.access_set_hints = {
        read_keys: [],
        write_keys: [],
        dynamic_reads: [{
          base_key: "state:Balances",
          key_type: "AccountId",
          bound_kind: "take",
          max_keys: -1,
        }],
        dynamic_writes: [],
      };
    }, /max_keys.*unsigned safe integer/u],
    ["zero dynamic bound", ({ manifest }) => {
      manifest.access_set_hints = {
        read_keys: [],
        write_keys: [],
        dynamic_reads: [{
          base_key: "state:amount",
          key_type: "quantity",
          bound_kind: "page",
          max_keys: 0,
        }],
        dynamic_writes: [],
      };
    }, /max_keys must be in the V1 range 1\.\.64/u],
    ["dynamic bound above V1 maximum", ({ manifest }) => {
      manifest.access_set_hints = {
        read_keys: [],
        write_keys: [],
        dynamic_reads: [{
          base_key: "state:Balances",
          key_type: "Name",
          bound_kind: "take",
          max_keys: 65,
        }],
        dynamic_writes: [],
      };
    }, /max_keys.*0\.\.64/u],
    ...[
      "state:",
      "state:*",
      "state:Balances/suffix",
      "state:Balances:suffix",
      "state:int",
      "account:alice",
    ].map((baseKey) => [
      `noncanonical dynamic base ${baseKey}`,
      ({ manifest }) => {
        manifest.access_set_hints = {
          read_keys: [],
          write_keys: [],
          dynamic_reads: [{
            base_key: baseKey,
            key_type: "AccountId",
            bound_kind: "take",
            max_keys: 1,
          }],
          dynamic_writes: [],
        };
      },
      /base_key must be state: plus one canonical state declaration identifier/u,
    ]),
    ...[
      "Json",
      "ReferendumId",
      "Int",
      "Quantity",
      "Amount",
      "amount",
      "Foo{Amount: quantity}",
      "Foo{Amount:quantity}",
      "StateMap<AccountId, int>",
      "\u0410mount",
    ].map((keyType) => [
      `noncanonical dynamic key type ${keyType}`,
      ({ manifest }) => {
        manifest.access_set_hints = {
          read_keys: [],
          write_keys: [],
          dynamic_reads: [{
            base_key: "state:Balances",
            key_type: keyType,
            bound_kind: "take",
            max_keys: 1,
          }],
          dynamic_writes: [],
        };
      },
      /key_type must be an exact Kotodama V1 StateMap key scalar/u,
    ]),
    ...["Take", "prefix", "range "].map((boundKind) => [
      `noncanonical dynamic bound kind ${boundKind}`,
      ({ manifest }) => {
        manifest.access_set_hints = {
          read_keys: [],
          write_keys: [],
          dynamic_reads: [{
            base_key: "state:Balances",
            key_type: "AccountId",
            bound_kind: boundKind,
            max_keys: 1,
          }],
          dynamic_writes: [],
        };
      },
      /bound_kind must be exactly take or page/u,
    ]),
    ["duplicate kotoba language", ({ manifest }) => {
      manifest.kotoba = [{
        msg_id: "demo.message",
        translations: [{ lang: "en", text: "one" }, { lang: "en", text: "two" }],
      }];
    }, /duplicate language en/u],
    ["unverifiable provenance", ({ manifest }) => {
      manifest.provenance = { signer: "ed0120", signature: "00" };
    }, /provenance must be null until signed provenance is verifiable/u],
  ];
  for (const [label, mutate, expected] of cases) {
    await assert.rejects(compileMutatedServiceResponse(mutate), expected, label);
  }
});

test("compiler manifest dynamic hints resolve declared StateMaps per list", async () => {
  const hint = {
    base_key: "state:Balances",
    key_type: "AccountId",
    bound_kind: "take",
    max_keys: 1,
  };
  const configure = (manifest, field, hints, states) => {
    manifest.states = states;
    manifest.access_set_hints = {
      read_keys: [],
      write_keys: [],
      dynamic_reads: [],
      dynamic_writes: [],
      [field]: hints,
    };
  };

  for (const field of ["dynamic_reads", "dynamic_writes"]) {
    const cases = [
      [
        "exact duplicate",
        [hint, { ...hint }],
        [{ name: "Balances", type_name: "StateMap<AccountId, quantity>" }],
        /contains a duplicate dynamic access hint/u,
      ],
      [
        "unknown state",
        [{ ...hint, base_key: "state:Missing" }],
        [{ name: "Balances", type_name: "StateMap<AccountId, quantity>" }],
        /base_key must reference a declared top-level StateMap/u,
      ],
      [
        "scalar state",
        [hint],
        [{ name: "Balances", type_name: "quantity" }],
        /base_key must reference a declared top-level StateMap/u,
      ],
      [
        "mismatched key scalar",
        [{ ...hint, key_type: "Name" }],
        [{ name: "Balances", type_name: "StateMap<AccountId, quantity>" }],
        /key_type Name does not match declared StateMap key type AccountId/u,
      ],
    ];
    for (const [label, hints, states, expected] of cases) {
      await assert.rejects(
        compileMutatedServiceResponse(({ manifest }) => {
          configure(manifest, field, hints, states);
        }),
        expected,
        `${field}: ${label}`,
      );
    }
  }
});

test("compiler artifact boundary requires bounded canonical V1 callable descriptors", async () => {
  const pointer = (kind, id) => Uint8Array.of(kind, id, 0);
  const leaf = (kind) => Uint8Array.of(5, kind);
  const tuple = (arity) => concatBytes(Uint8Array.of(1), u32Le(arity));
  const cases = [
    ["retired interface layout", { omitCallables: true }],
    ["missing callable root", { callables: [] }],
    ["unaligned root", { callables: [callableFixture({ entryPc: 1 })] }],
    ["out-of-code root", { callables: [callableFixture({ entryPc: 4 })] }],
    ["duplicate roots", { callables: [callableFixture(), callableFixture()] }],
    ["unaligned frame", { callables: [callableFixture({ frameBytes: 8 })] }],
    ["oversized frame", { callables: [callableFixture({ frameBytes: 4 * 1024 * 1024 + 16 })] }],
    ["empty result", { callables: [callableFixture({ resultNodes: [] })] }],
    ["oversized arguments", { callables: [callableFixture({ argumentNodes: Array.from({ length: 8193 }, () => leaf(3)) })] }],
    ["unknown node", { callables: [callableFixture({ resultNodes: [Uint8Array.of(12)] })] }],
    ["unknown pointer type", { callables: [callableFixture({ resultNodes: [pointer(10, 0x14)] })] }],
    ["private role without ZK", { callables: [callableFixture({ argumentNodes: [pointer(11, 0x11)] })] }],
    ["trailing descriptor fields", { callables: [concatBytes(callableFixture(), field(u32Le(0)))] }],
  ];
  for (const [label, options] of cases) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        { async compileKotodama() { return serviceSuccessWithArtifact(compilerArtifactFixture(options)); } },
        "seiyaku Demo {}",
      ),
      /interface|callable/u,
      label,
    );
  }
  const artifact = compilerArtifactFixture({
    features: 1,
    callables: [callableFixture(), callableFixture({
      entryPc: 4,
      frameBytes: 16,
      argumentNodes: [Uint8Array.of(6), leaf(0), leaf(3), pointer(10, 0x0d), Uint8Array.of(9), callableCursorFixture(3), pointer(11, 0x12)],
      resultNodes: [tuple(8192), ...Array.from({ length: 8192 }, () => leaf(3))],
    })],
  });
  const accepted = await compileKotodamaWithNativeBinding(
    { async compileKotodama() { return serviceSuccessWithArtifact(artifact, (manifest) => { manifest.features_bitmap = 1; }); } },
    "seiyaku Demo {}",
  );
  assert.equal(accepted.ok, true);
});

test("compiler output requires a framed self-describing IVM artifact bound to manifest identity", async () => {
  const malformedArtifacts = [
    ["one byte", Uint8Array.from([1])],
    ["bad magic", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[0] ^= 0xff;
      return bytes;
    })()],
    ["wrong ABI", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[16] = 2;
      return bytes;
    })()],
    ["unknown IVM mode bit", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[6] = 0x04;
      return bytes;
    })()],
    ["post-header image beyond IVM code memory", (() => {
      const postHeaderBytes = SERVICE_ARTIFACT.length - IVM_HEADER_BYTES;
      const minimumExtra = 0x0010_0000 - postHeaderBytes + 1;
      const alignedExtra = Math.ceil(minimumExtra / 4) * 4;
      return concatBytes(SERVICE_ARTIFACT, new Uint8Array(alignedExtra));
    })()],
    ["mismatched authenticated ABI hash", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[IVM_EXECUTION_HEADER_BYTES] ^= 1;
      return bytes;
    })()],
    ["retired 17-byte header", concatBytes(
      SERVICE_ARTIFACT.subarray(0, IVM_EXECUTION_HEADER_BYTES),
      SERVICE_ARTIFACT.subarray(IVM_HEADER_BYTES),
    )],
    ["mismatched embedded ABI hash", compilerArtifactFixture({ interfaceAbiByte: 0x25 })],
    ["bad CNTR marker", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[IVM_HEADER_BYTES] ^= 1;
      return bytes;
    })()],
    ["bad CNTR frame CRC", (() => {
      const bytes = SERVICE_ARTIFACT.slice();
      bytes[IVM_HEADER_BYTES + 8 + 31] ^= 1;
      return bytes;
    })()],
    ["noncanonical CNTR frame padding", (() => {
      const frameLength = readU32LeForTest(SERVICE_ARTIFACT, IVM_HEADER_BYTES + 4);
      const payloadOffset = IVM_HEADER_BYTES + 8 + 40;
      const bytes = new Uint8Array(SERVICE_ARTIFACT.length + 1);
      bytes.set(SERVICE_ARTIFACT.subarray(0, payloadOffset), 0);
      bytes[payloadOffset] = 0;
      bytes.set(SERVICE_ARTIFACT.subarray(payloadOffset), payloadOffset + 1);
      bytes.set(u32Le(frameLength + 1), IVM_HEADER_BYTES + 4);
      return bytes;
    })()],
    ["unaligned instruction stream", SERVICE_ARTIFACT.slice(0, -1)],
  ];
  for (const [label, artifact] of malformedArtifacts) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        { async compileKotodama() { return serviceSuccessWithArtifact(artifact); } },
        "seiyaku Demo {}",
      ),
      /artifact|interface|CRC64|instruction stream/u,
      label,
    );
  }

  for (const [label, artifact] of [
    ["seiyaku identity", compilerArtifactFixture({ name: "Substituted" })],
    ["compiler fingerprint", compilerArtifactFixture({ fingerprint: "evil/compiler" })],
    ["entrypoint count", compilerArtifactFixture({ entrypoints: 0 })],
  ]) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        { async compileKotodama() { return serviceSuccessWithArtifact(artifact); } },
        "seiyaku Demo {}",
      ),
      /match the embedded (?:contract )?interface/u,
      label,
    );
  }

  const featureArtifact = compilerArtifactFixture({ features: 1 });
  await assert.rejects(
    compileKotodamaWithNativeBinding(
      {
        async compileKotodama() {
          return serviceSuccessWithArtifact(featureArtifact, (manifest) => {
            manifest.features_bitmap = 0;
          });
        },
      },
      "seiyaku Demo {}",
    ),
    /identity\/capabilities do not match/u,
  );
});

test("compiler literal-table validation matches Rust ABI-v1 framing", async () => {
  const validPointer = pointerLiteralFixture();
  const validArtifact = literalArtifactFixture([
    { kind: 0, bytes: validPointer },
    { kind: 1, bytes: u64Le(42) },
  ]);
  const validResult = await compileKotodamaWithNativeBinding(
    { async compileKotodama() { return serviceSuccessWithArtifact(validArtifact); } },
    "seiyaku Demo {}",
  );
  assert.equal(validResult.ok, true);

  const emptyArtifact = literalArtifactFixture([]);
  const emptyResult = await compileKotodamaWithNativeBinding(
    { async compileKotodama() { return serviceSuccessWithArtifact(emptyArtifact); } },
    "seiyaku Demo {}",
  );
  assert.equal(emptyResult.ok, true);

  const duplicateTargets = literalArtifactFixture([
    { kind: 0, bytes: validPointer },
    { kind: 1, bytes: u64Le(7) },
  ]);
  const duplicateStart = literalSectionStart(duplicateTargets);
  duplicateTargets.set(
    duplicateTargets.subarray(duplicateStart + 16, duplicateStart + 24),
    duplicateStart + 24,
  );

  const skippedFirstByte = literalArtifactFixture([
    { kind: 0, bytes: validPointer },
  ]);
  const skippedStart = literalSectionStart(skippedFirstByte);
  skippedFirstByte.set(u64Le(16 + 8 + 1), skippedStart + 16);

  const badPointerHash = pointerLiteralFixture();
  badPointerHash[badPointerHash.length - 1] ^= 1;

  for (const [label, artifact, expected] of [
    [
      "unindexed data",
      literalArtifactFixture([], { unindexedData: Uint8Array.from([1]) }),
      /unindexed literal data/u,
    ],
    ["duplicate targets", duplicateTargets, /strictly increasing/u],
    ["first target gap", skippedFirstByte, /first descriptor/u],
    [
      "short i64",
      literalArtifactFixture([{ kind: 1, bytes: new Uint8Array(7) }]),
      /exactly 8 bytes/u,
    ],
    [
      "unassigned pointer type",
      literalArtifactFixture([{ kind: 0, bytes: pointerLiteralFixture({ typeId: 0x0014 }) }]),
      /not allowed by ABI v1/u,
    ],
    [
      "pointer version",
      literalArtifactFixture([{ kind: 0, bytes: pointerLiteralFixture({ version: 2 }) }]),
      /must use version 1/u,
    ],
    [
      "pointer declared length",
      literalArtifactFixture([{
        kind: 0,
        bytes: pointerLiteralFixture({ declaredLength: 4 }),
      }]),
      /length does not match/u,
    ],
    [
      "pointer payload hash",
      literalArtifactFixture([{ kind: 0, bytes: badPointerHash }]),
      /payload hash is invalid/u,
    ],
  ]) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        { async compileKotodama() { return serviceSuccessWithArtifact(artifact); } },
        "seiyaku Demo {}",
      ),
      expected,
      label,
    );
  }
});

test("compiler trigger metadata is exact, bounded, and non-recursive beyond policy", async () => {
  const filter = JSON.parse(
    readFileSync(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"),
  ).event_filter_box.norito_frame_hex;
  const canonicalFilter = Buffer.from(filter, "hex").toString("base64");
  const trigger = () => ({
    id: "wake",
    repeats: { Indefinitely: null },
    filter: canonicalFilter,
    authority: null,
    metadata: {},
    callback: { namespace: null, entrypoint: "ping" },
  });

  await assert.doesNotReject(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      value.id = "amount";
      value.callback.namespace = "RemoteLedger";
      manifest.entrypoints[0].triggers = [value];
    }, true),
  );
  await assert.rejects(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      value.id = "Amount";
      manifest.entrypoints[0].triggers = [value];
    }),
    /id must be unique and canonical/u,
  );
  for (const namespace of ["Invalid Error", "Error<Injected>"]) {
    await assert.rejects(
      compileMutatedServiceResponse(({ manifest }) => {
        const value = trigger();
        value.callback.namespace = namespace;
        manifest.entrypoints[0].triggers = [value];
      }),
      /callback\.namespace must be a canonical type declaration/u,
    );
  }
  await assert.rejects(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      value.repeats = { Indefinitely: null, Exactly: 1 };
      manifest.entrypoints[0].triggers = [value];
    }),
    /exactly one canonical repeat policy/u,
  );
  await assert.rejects(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      value.filter = `${canonicalFilter.slice(0, -2)}B=`;
      manifest.entrypoints[0].triggers = [value];
    }),
    /canonical base64 padding bits|exact standard-base64/u,
  );
  await assert.rejects(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      value.callback.entrypoint = "other";
      manifest.entrypoints[0].triggers = [value];
    }),
    /callback must target its declaring entrypoint/u,
  );
  await assert.rejects(
    compileMutatedServiceResponse(({ manifest }) => {
      const value = trigger();
      let cursor = value.metadata;
      for (let depth = 0; depth < 66; depth += 1) {
        cursor.next = {};
        cursor = cursor.next;
      }
      manifest.entrypoints[0].triggers = [value];
    }),
    /JSON depth limit/u,
  );
});

test("compiler sidecar schemas reject malformed fields and cross-sidecar identities", async () => {
  const cases = [
    ["source-map unknown field", ({ sourceMap }) => {
      sourceMap.entries[0].unknown = true;
    }, /source-map sidecar entry 0 has an invalid field set/u],
    ["source-map reversed range", ({ sourceMap }) => {
      sourceMap.entries[0].pc_start = 5;
    }, /forward PC range/u],
    ["source-map unsafe source id", ({ sourceMap }) => {
      sourceMap.entries[0].source_id = 0x1_0000_0000;
    }, /source_id.*unsigned safe integer/u],
    ["budget missing diagnostics", ({ budget }) => {
      delete budget.access_hint_diagnostics;
    }, /budget sidecar has an invalid field set/u],
    ["budget malformed diagnostics", ({ budget }) => {
      budget.access_hint_diagnostics.state_wildcards = -1;
    }, /state_wildcards.*unsigned safe integer/u],
    ["cross-sidecar mismatch", ({ budget }) => {
      budget.entries[0].function_name = "other";
    }, /function identity does not match/u],
  ];
  for (const [label, mutate, expected] of cases) {
    await assert.rejects(compileMutatedServiceResponse(mutate), expected, label);
  }
});

test("compiler result snapshots data descriptors without invoking hostile getters", async () => {
  let getCalls = 0;
  const outputProxy = new Proxy(structuredClone(SERVICE_SUCCESS.output), {
    get() {
      getCalls += 1;
      throw new Error("output get trap must not run");
    },
  });
  const result = await compileKotodamaWithNativeBinding(
    {
      async compileKotodama() {
        return { ok: true, output: outputProxy, diagnosticsJson: null };
      },
    },
    "seiyaku Demo {}",
  );
  assert.equal(result.ok, true);
  assert.equal(getCalls, 0);

  let accessorCalls = 0;
  const accessorResult = { output: SERVICE_SUCCESS.output, diagnosticsJson: null };
  Object.defineProperty(accessorResult, "ok", {
    enumerable: true,
    get() {
      accessorCalls += 1;
      return true;
    },
  });
  await assert.rejects(
    compileKotodamaWithNativeBinding(
      { async compileKotodama() { return accessorResult; } },
      "seiyaku Demo {}",
    ),
    /enumerable data property/u,
  );
  assert.equal(accessorCalls, 0);
});

test("compiler result envelope requires every field and exact null sentinels", async () => {
  for (const response of [
    { ok: true, output: SERVICE_OUTPUT },
    { ok: true, output: SERVICE_OUTPUT, diagnosticsJson: undefined },
    { ok: false, diagnosticsJson: SERVICE_FAILURE.diagnosticsJson },
    { ok: false, output: undefined, diagnosticsJson: SERVICE_FAILURE.diagnosticsJson },
  ]) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        { async compileKotodama() { return response; } },
        "seiyaku Demo {}",
      ),
      /invalid field set|exact null/u,
    );
  }
});

test("compiler result rejects sparse and extra-property artifact arrays before hashing", async () => {
  for (const artifactBytes of [
    Object.assign([1, 2, 3], { extra: true }),
    [1, , 3],
  ]) {
    await assert.rejects(
      compileKotodamaWithNativeBinding(
        {
          async compileKotodama() {
            return {
              ...structuredClone(SERVICE_SUCCESS),
              output: { ...structuredClone(SERVICE_SUCCESS.output), artifactBytes },
            };
          },
        },
        "seiyaku Demo {}",
      ),
      /dense array without extra fields|stable dense data-only array/u,
    );
  }
});

test("compiler result accepts and snapshots genuine cross-realm Uint8Array bytes", () => {
  const crossRealmBytes = runInNewContext(
    `Uint8Array.from(${JSON.stringify([...SERVICE_ARTIFACT])})`,
  );
  const normalized = normalizeCompilerResult({
    ...SERVICE_SUCCESS,
    output: { ...SERVICE_OUTPUT, artifactBytes: crossRealmBytes },
  });

  assert.equal(normalized.ok, true);
  assert.deepEqual([...normalized.output.artifactBytes], [...SERVICE_ARTIFACT]);
  crossRealmBytes[0] ^= 0xff;
  assert.equal(normalized.output.artifactBytes[0], SERVICE_ARTIFACT[0]);
});

test("compiler result rejects non-Uint8 byte views and detached Uint8Array bytes", () => {
  for (const artifactBytes of [
    new Int8Array([1, 2, 3]),
    new Uint8ClampedArray([1, 2, 3]),
    new Uint16Array([1, 2, 3]),
    new DataView(new ArrayBuffer(3)),
    {
      [Symbol.toStringTag]: "Uint8Array",
      buffer: new ArrayBuffer(3),
      byteOffset: 0,
      byteLength: 3,
    },
  ]) {
    assert.throws(
      () =>
        normalizeCompilerResult({
          ...SERVICE_SUCCESS,
          output: { ...SERVICE_OUTPUT, artifactBytes },
        }),
      /artifactBytes/u,
    );
  }

  const buffer = new ArrayBuffer(3);
  const detached = new Uint8Array(buffer);
  structuredClone(buffer, { transfer: [buffer] });
  assert.throws(
    () =>
      normalizeCompilerResult({
        ...SERVICE_SUCCESS,
        output: { ...SERVICE_OUTPUT, artifactBytes: detached },
      }),
    /readable Uint8Array/u,
  );
});

test("compiler adapters require checksummed canonical manifest hash literals", async () => {
  const compileManifestHash = (mutate) => {
    const response = structuredClone(SERVICE_SUCCESS);
    const manifest = JSON.parse(response.output.manifestJson);
    mutate(manifest);
    response.output.manifestJson = JSON.stringify(manifest);
    return compileKotodamaWithNativeBinding(
      { async compileKotodama() { return response; } },
      "seiyaku Demo {}",
    );
  };

  await assert.rejects(
    compileManifestHash((manifest) => {
      manifest.code_hash = manifest.code_hash.toLowerCase();
    }),
    /invalid or noncanonical manifest code_hash/u,
  );
  await assert.rejects(
    compileManifestHash((manifest) => {
      manifest.code_hash = `${manifest.code_hash.slice(0, -4)}0000`;
    }),
    /invalid manifest code_hash checksum/u,
  );
  await assert.rejects(
    compileManifestHash((manifest) => {
      manifest.abi_hash = `hash:${SERVICE_ABI_HASH.toUpperCase()}`;
    }),
    /invalid or noncanonical manifest abi_hash/u,
  );
  const evenMarker = structuredClone(SERVICE_SUCCESS);
  const evenMarkerManifest = JSON.parse(evenMarker.output.manifestJson);
  evenMarkerManifest.abi_hash = canonicalHashLiteral("22".repeat(32));
  evenMarker.output.manifestJson = JSON.stringify(evenMarkerManifest);
  evenMarker.output.abiHash = "22".repeat(32);
  await assert.rejects(
    compileKotodamaWithNativeBinding(
      { async compileKotodama() { return evenMarker; } },
      "seiyaku Demo {}",
    ),
    /invalid abiHash marker bit/u,
  );
});

test("iroha_js_host keeps compilation off the Node event-loop thread", () => {
  const hostSource = readFileSync(
    new URL("../../../crates/iroha_js_host/src/lib.rs", import.meta.url),
    "utf8",
  );
  assert.match(
    hostSource,
    /#\[napi\(js_name = "compileKotodama"\)\]\s*pub async fn compile_kotodama/u,
  );
  assert.match(
    hostSource,
    /pub async fn compile_kotodama[\s\S]*?tokio::task::spawn_blocking/u,
  );
  assert.match(
    hostSource,
    /pub struct JsKotodamaCompileRequest[\s\S]*?pub source: String,[\s\S]*?pub source_name: Option<String>,[\s\S]*?pub zk: bool,/u,
  );
  assert.match(
    hostSource,
    /CompilerOptions\s*\{[\s\S]*?force_zk: request\.zk,[\s\S]*?\.build\(/u,
  );
  assert.match(
    hostSource,
    /source_name: request\.source_name\.as_deref\(\)/u,
  );
});

test("browser condition precedes the Node import condition", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(Object.keys(packageJson.exports["./kotodama-compiler"]), [
    "types",
    "browser",
    "import",
  ]);
  assert.equal(
    packageJson.exports["./kotodama-compiler"].browser,
    "./dist/kotodamaCompiler/browser.js",
  );
});

test("browser compiler client uses the explicit Rust service and normalizes output", async () => {
  const calls = [];
  const client = new KotodamaCompilerClient("https://compiler.example/", {
    fetchImpl: successfulFetch(calls),
  });
  const result = await client.compile(
    "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }",
    { sourceName: "contracts/demo.ko", zk: true },
  );

  assert.equal(result.ok, true);
  assert.deepEqual([...result.output.artifactBytes], [...SERVICE_ARTIFACT]);
  assert.equal(result.output.codeHashHex, SERVICE_OUTPUT.codeHash);
  assert.equal(result.output.abiHashHex, SERVICE_OUTPUT.abiHash);
  assert.equal(result.output.compilerFingerprint, "kotodama_lang/test");
  assert.equal(result.output.sourceMap[0].function_name, "ping");
  assert.equal(result.output.budgetReport[0].bytecode_words, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://compiler.example/v1/kotodama/compile");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.accept, "application/json");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.referrerPolicy, "no-referrer");
  assert.ok(calls[0].init.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    artifacts: [],
    source: "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }",
    sourceName: "contracts/demo.ko",
    zk: true,
  });
});

test("compiler client transport policy cannot be redirected after construction", async () => {
  const calls = [];
  const trustedFetch = successfulFetch(calls);
  const client = new KotodamaCompilerClient("https://trusted.example/base", {
    fetchImpl: trustedFetch,
  });

  client.baseUrl = "http://non-loopback.example";
  client.fetchImpl = () => {
    throw new Error("mutable public fetch override must not run");
  };
  Object.defineProperty(client, "baseUrl", {
    value: "https://other.example",
    configurable: true,
  });

  const result = await client.compile("seiyaku Demo {}", { timeoutMs: 100 });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "https://trusted.example/base/v1/kotodama/compile",
  );
});

test("compiler adapters reject oversized UTF-8 source before native or network dispatch", async () => {
  const calls = [];
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: successfulFetch(calls),
  });
  const maxSourceBytes = 1024 * 1024;

  const boundary = await client.compile("a".repeat(maxSourceBytes));
  assert.equal(boundary.ok, true);
  assert.equal(calls.length, 1, "the exact V1 source-byte limit remains admissible");

  await assert.rejects(
    client.compile("a".repeat(maxSourceBytes + 1)),
    /exceeds the 1048576-byte V1 limit/,
  );
  await assert.rejects(
    client.compile(`${"a".repeat(maxSourceBytes - 1)}🙂`),
    /exceeds the 1048576-byte V1 limit/,
  );
  await assert.rejects(
    client.compile("\ud800"),
    /must contain valid Unicode scalar values/,
  );
  assert.equal(calls.length, 1, "oversized source must not reach the compiler service");

  await assert.rejects(
    compileKotodamaProgram("a".repeat(maxSourceBytes + 1)),
    /exceeds the 1048576-byte V1 limit/,
  );
});

test("compiler requests bound sourceName and expose only the canonical ZK selector", async () => {
  const calls = [];
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: successfulFetch(calls),
  });

  await client.compile("seiyaku Demo {}", { sourceName: "契約/送金.ko", zk: true });
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    artifacts: [],
    source: "seiyaku Demo {}",
    sourceName: "契約/送金.ko",
    zk: true,
  });

  for (const options of [
    { sourceName: "" },
    { sourceName: "contracts/demo\nleak.ko" },
    { sourceName: "x".repeat(4097) },
    { sourceName: "\ud800" },
    { zk: "true" },
    { forceZk: true },
  ]) {
    await assert.rejects(client.compile("seiyaku Demo {}", options));
  }
  assert.equal(calls.length, 1, "invalid compiler policy must fail before network dispatch");
});

test("compiler transport options are exact data and fail before dispatch", async () => {
  const calls = [];
  const fetchImpl = successfulFetch(calls);

  let constructorGetterCalls = 0;
  const constructorAccessor = {};
  Object.defineProperty(constructorAccessor, "fetchImpl", {
    enumerable: true,
    get() {
      constructorGetterCalls += 1;
      return fetchImpl;
    },
  });
  assert.throws(
    () => new KotodamaCompilerClient("https://compiler.example", constructorAccessor),
    /enumerable data property/u,
  );
  assert.equal(constructorGetterCalls, 0);
  for (const constructorOptions of [
    { fetchImpl: null },
    { fetchImpl: undefined },
    { fetchImpl, unknown: true },
    Object.defineProperty({}, "fetchImpl", { value: fetchImpl }),
    { [Symbol("fetch")]: fetchImpl },
  ]) {
    assert.throws(
      () => new KotodamaCompilerClient("https://compiler.example", constructorOptions),
      TypeError,
    );
  }

  let proxyGets = 0;
  const proxiedConstructorOptions = new Proxy(
    { fetchImpl },
    {
      get() {
        proxyGets += 1;
        throw new Error("constructor option get trap must not run");
      },
    },
  );
  const client = new KotodamaCompilerClient(
    "https://compiler.example",
    proxiedConstructorOptions,
  );
  assert.equal(proxyGets, 0);

  for (const timeoutMs of [
    0,
    -1,
    1.5,
    120_001,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    "1000",
    null,
    undefined,
  ]) {
    await assert.rejects(
      client.compile("seiyaku Demo {}", { timeoutMs }),
      /timeoutMs must be an integer from 1 through 120000/u,
    );
  }

  let timeoutGetterCalls = 0;
  const timeoutAccessor = {};
  Object.defineProperty(timeoutAccessor, "timeoutMs", {
    enumerable: true,
    get() {
      timeoutGetterCalls += 1;
      return 100;
    },
  });
  await assert.rejects(
    client.compile("seiyaku Demo {}", timeoutAccessor),
    /enumerable data property/u,
  );
  assert.equal(timeoutGetterCalls, 0);

  let signalGetterCalls = 0;
  const forgedSignal = {};
  Object.defineProperty(forgedSignal, "aborted", {
    enumerable: true,
    get() {
      signalGetterCalls += 1;
      return false;
    },
  });
  await assert.rejects(
    client.compile("seiyaku Demo {}", { signal: forgedSignal }),
    /must be an AbortSignal/u,
  );
  assert.equal(signalGetterCalls, 0);

  const proxiedCallOptions = new Proxy(
    { timeoutMs: 100 },
    {
      get() {
        proxyGets += 1;
        throw new Error("compile option get trap must not run");
      },
    },
  );
  await client.compile("seiyaku Demo {}", proxiedCallOptions);
  assert.equal(proxyGets, 0);
  assert.equal(calls.length, 1, "only valid options may reach Fetch");

  await assert.rejects(
    compileKotodamaProgram("seiyaku Demo {}", { timeoutMs: 100 }),
    /signal and timeoutMs require compilerUrl/u,
  );
});

test("compiler cancellation preserves falsey and intrinsic AbortSignal reasons", async () => {
  for (const reason of [0, false, "", null]) {
    let fetchCalls = 0;
    const controller = new AbortController();
    controller.abort(reason);
    const client = new KotodamaCompilerClient("https://compiler.example", {
      fetchImpl() {
        fetchCalls += 1;
        return new Promise(() => {});
      },
    });
    assert.equal(
      await captureRejection(
        client.compile("seiyaku Demo {}", {
          signal: controller.signal,
          timeoutMs: 100,
        }),
      ),
      reason,
    );
    assert.equal(fetchCalls, 0, "pre-aborted calls must not dispatch Fetch");
  }

  const reason = new Error("intrinsic caller cancellation");
  const controller = new AbortController();
  let reasonGetterCalls = 0;
  Object.defineProperty(controller.signal, "reason", {
    configurable: true,
    get() {
      reasonGetterCalls += 1;
      throw new Error("own reason getter must not run");
    },
  });
  controller.abort(reason);
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl() {
      assert.fail("pre-aborted intrinsic signal reached Fetch");
    },
  });
  assert.equal(
    await captureRejection(
      client.compile("seiyaku Demo {}", {
        signal: controller.signal,
        timeoutMs: 100,
      }),
    ),
    reason,
  );
  assert.equal(reasonGetterCalls, 0);
});

test("compiler abort and deadline terminate an uncooperative Fetch", async () => {
  let fetchInit;
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl(_url, init) {
      fetchInit = init;
      return new Promise(() => {});
    },
  });
  const controller = new AbortController();
  const reason = new Error("stop ignored Fetch");
  const pending = client.compile("seiyaku Demo {}", {
    signal: controller.signal,
    timeoutMs: 1_000,
  });
  await Promise.resolve();
  assert.ok(fetchInit, "Fetch must begin before the mid-flight abort");
  assert.notEqual(fetchInit.signal, controller.signal);
  controller.abort(reason);
  assert.equal(await captureRejection(pending), reason);
  assert.equal(fetchInit.signal.aborted, true);
  assert.equal(fetchInit.signal.reason, reason);

  const conflictingError = new Error("transport replaced the abort reason");
  const cooperativeClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl(_url, init) {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(conflictingError), {
          once: true,
        });
      });
    },
  });
  const cooperativeController = new AbortController();
  const falseyPending = cooperativeClient.compile("seiyaku Demo {}", {
    signal: cooperativeController.signal,
    timeoutMs: 1_000,
  });
  await Promise.resolve();
  cooperativeController.abort(false);
  assert.equal(
    await captureRejection(falseyPending),
    false,
    "the caller reason must win a conflicting transport rejection",
  );

  let deadlineSignal;
  const deadlineClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl(_url, init) {
      deadlineSignal = init.signal;
      return new Promise(() => {});
    },
  });
  const startedAt = Date.now();
  const deadlineError = await captureRejection(
    deadlineClient.compile("seiyaku Demo {}", { timeoutMs: 10 }),
  );
  assert.equal(deadlineError.name, "TimeoutError");
  assert.match(deadlineError.message, /timed out after 10ms/u);
  assert.ok(Date.now() - startedAt < 1_000, "deadline must not await ignored Fetch");
  assert.equal(deadlineSignal.aborted, true);
  assert.equal(deadlineSignal.reason, deadlineError);

  const cooperativeDeadlineError = await captureRejection(
    cooperativeClient.compile("seiyaku Demo {}", { timeoutMs: 10 }),
  );
  assert.equal(
    cooperativeDeadlineError.name,
    "TimeoutError",
    "the deadline must win a conflicting transport rejection",
  );

  let resolveLateFetch;
  let lateCancelCalls = 0;
  const lateClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl() {
      return new Promise((resolve) => {
        resolveLateFetch = resolve;
      });
    },
  });
  const lateController = new AbortController();
  const lateReason = new Error("abandon late compiler response");
  const latePending = lateClient.compile("seiyaku Demo {}", {
    signal: lateController.signal,
    timeoutMs: 1_000,
  });
  await Promise.resolve();
  lateController.abort(lateReason);
  assert.equal(await captureRejection(latePending), lateReason);
  resolveLateFetch(
    new Response(
      new ReadableStream({
        cancel() {
          lateCancelCalls += 1;
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    ),
  );
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(lateCancelCalls, 1, "late response bodies must be cancelled");
});

test("compiler transport cleans listeners and terminates stalled hostile bodies", async () => {
  const successController = new AbortController();
  let successTransportSignal;
  const successClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl(_url, init) {
      successTransportSignal = init.signal;
      return jsonResponse(SERVICE_SUCCESS);
    },
  });
  await successClient.compile("seiyaku Demo {}", {
    signal: successController.signal,
    timeoutMs: 100,
  });
  successController.abort(new Error("after successful cleanup"));
  await Promise.resolve();
  assert.equal(
    successTransportSignal.aborted,
    false,
    "successful cleanup must detach the caller abort listener",
  );

  let cancelCalls = 0;
  const stalledClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      new Response(
        new ReadableStream({
          pull() {
            return new Promise(() => {});
          },
          cancel() {
            cancelCalls += 1;
            return new Promise(() => {});
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  const stalledError = await captureRejection(
    stalledClient.compile("seiyaku Demo {}", { timeoutMs: 10 }),
  );
  assert.equal(stalledError.name, "TimeoutError");
  assert.equal(cancelCalls, 1, "stalled body must be cancelled without awaiting cancel");

  const bodyController = new AbortController();
  const bodyReason = new Error("cancel stalled compiler body");
  const abortedBody = stalledClient.compile("seiyaku Demo {}", {
    signal: bodyController.signal,
    timeoutMs: 1_000,
  });
  await Promise.resolve();
  bodyController.abort(bodyReason);
  assert.equal(await captureRejection(abortedBody), bodyReason);
});

test("compiler failures preserve every canonical diagnostic field", async () => {
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(SERVICE_FAILURE),
  });
  const result = await client.compile("seiyaku Demo { 🙂 }");

  assert.deepEqual(result, { ok: false, diagnostics: SERVICE_DIAGNOSTICS });
  assert.equal(result.diagnostics.length, 2);
  assert.deepEqual(result.diagnostics[0].primary_span, {
    package_identity: null,
    source: "契約/送金.ko",
    start: { line: 2, column: 9 },
    end: { line: 2, column: 10 },
    byte_range: { start: 20, end: 24 },
  });
  assert.deepEqual(result.diagnostics[0].labels, SERVICE_DIAGNOSTICS[0].labels);
  assert.deepEqual(result.diagnostics[0].notes, SERVICE_DIAGNOSTICS[0].notes);
  assert.equal(result.diagnostics[0].help, "write Type name");
  assert.deepEqual(result.diagnostics[0].fix, SERVICE_DIAGNOSTICS[0].fix);
  assert.deepEqual(result.diagnostics[0].alternative_fixes, SERVICE_DIAGNOSTICS[0].alternative_fixes);
  assert.deepEqual(result.diagnostics[0].localized, SERVICE_DIAGNOSTICS[0].localized);
});

test("compiler resolver envelopes accept resolve and reject noncanonical phase names", async () => {
  const validClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(SERVICE_FAILURE),
  });
  const valid = await validClient.compile("seiyaku Demo { view fn run() authorize(anyone) { missing(); } }");
  const resolverDiagnostic = valid.diagnostics.find(({ code }) => code === "K2002");
  assert.equal(resolverDiagnostic?.phase, "resolve");

  const malformedFailure = structuredClone(SERVICE_FAILURE);
  const malformedDiagnostics = JSON.parse(malformedFailure.diagnosticsJson);
  malformedDiagnostics.find(({ code }) => code === "K2002").phase = "resolver";
  malformedFailure.diagnosticsJson = JSON.stringify(malformedDiagnostics);
  const malformedClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(malformedFailure),
  });
  await assert.rejects(
    malformedClient.compile("seiyaku Demo { view fn run() authorize(anyone) { missing(); } }"),
    /Kotodama diagnostic 1\.phase is invalid/,
  );
});

test("compiler sidecars must match the deployable artifact hash", async () => {
  const invalid = {
    ...SERVICE_SUCCESS,
    output: {
      ...SERVICE_OUTPUT,
      sourceMapJson: JSON.stringify({
        sidecar_version: 1,
        kind: "source-map",
        artifact_hash: "ff".repeat(32),
        entries: [],
      }),
    },
  };
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(invalid),
  });
  await assert.rejects(
    client.compile("seiyaku Demo {}"),
    /invalid or mismatched source-map sidecar/,
  );
});

test("compiler wire output cannot substitute bytes behind a claimed hash", async () => {
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      jsonResponse({
        ...SERVICE_SUCCESS,
        output: { ...SERVICE_OUTPUT, artifactBytes: [1, 2, 4] },
      }),
  });
  await assert.rejects(
    client.compile("seiyaku Demo {}"),
    /artifact bytes do not match codeHash/,
  );
});

test("compile helper accepts an explicit browser compiler service", async () => {
  const calls = [];
  const controller = new AbortController();
  const result = await compileKotodamaProgram("seiyaku Demo {}", {
    compilerUrl: "https://compiler.example",
    fetchImpl: successfulFetch(calls),
    sourceName: "contracts/node-service.ko",
    zk: true,
    signal: controller.signal,
    timeoutMs: 100,
  });
  assert.equal(result.ok, true);
  assert.deepEqual([...result.output.artifactBytes], [...SERVICE_ARTIFACT]);
  assert.equal(calls.length, 1);
  assert.notEqual(calls[0].init.signal, controller.signal);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    artifacts: [],
    source: "seiyaku Demo {}",
    sourceName: "contracts/node-service.ko",
    zk: true,
  });
});

test("browser entrypoint forwards the bounded request to its compiler service", async () => {
  const calls = [];
  const result = await compileKotodamaInBrowser("seiyaku Demo {}", {
    compilerUrl: "https://compiler.example",
    fetchImpl: successfulFetch(calls),
    sourceName: "contracts/browser-service.ko",
    zk: true,
  });
  assert.equal(result.ok, true);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    artifacts: [],
    source: "seiyaku Demo {}",
    sourceName: "contracts/browser-service.ko",
    zk: true,
  });
});

test("malformed service JSON and malformed envelopes fail closed", async () => {
  const malformedJson = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      new Response("{", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    malformedJson.compile("seiyaku Demo {}"),
    /returned malformed JSON/,
  );

  const legacyOutput = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(SERVICE_OUTPUT),
  });
  await assert.rejects(
    legacyOutput.compile("seiyaku Demo {}"),
    /result has an invalid field set/,
  );

  const malformedDiagnostic = structuredClone(SERVICE_FAILURE);
  const diagnostics = JSON.parse(malformedDiagnostic.diagnosticsJson);
  diagnostics[0].primary_span.start.column = 0;
  malformedDiagnostic.diagnosticsJson = JSON.stringify(diagnostics);
  const invalidFields = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(malformedDiagnostic),
  });
  await assert.rejects(
    invalidFields.compile("seiyaku Demo {}"),
    /one-based safe-integer line and column/,
  );

  for (const mutate of [
    (span) => delete span.package_identity,
    (span) => {
      span.package_identity = "";
    },
  ]) {
    const malformedPackageIdentity = structuredClone(SERVICE_FAILURE);
    const packageDiagnostics = JSON.parse(
      malformedPackageIdentity.diagnosticsJson,
    );
    mutate(packageDiagnostics[0].primary_span);
    malformedPackageIdentity.diagnosticsJson = JSON.stringify(
      packageDiagnostics,
    );
    const invalidPackageIdentity = new KotodamaCompilerClient(
      "https://compiler.example",
      { fetchImpl: async () => jsonResponse(malformedPackageIdentity) },
    );
    await assert.rejects(
      invalidPackageIdentity.compile("seiyaku Demo {}"),
      /package_identity|invalid field set/u,
    );
  }
});

test("compiler response metadata, framing, and byte streams fail closed", async () => {
  let responseGetterCalls = 0;
  const forgedResponse = {};
  for (const field of ["ok", "status", "headers", "body"]) {
    Object.defineProperty(forgedResponse, field, {
      enumerable: true,
      get() {
        responseGetterCalls += 1;
        throw new Error(`forged ${field} getter must not run`);
      },
    });
  }
  const forgedClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => forgedResponse,
  });
  await assert.rejects(
    forgedClient.compile("seiyaku Demo {}", { timeoutMs: 100 }),
    /invalid Response/u,
  );
  assert.equal(responseGetterCalls, 0);

  let proxyStringGets = 0;
  const proxiedResponse = new Proxy(jsonResponse(SERVICE_SUCCESS), {
    get(target, property, receiver) {
      // Promise resolution performs the unavoidable thenable check. The
      // native Response brand check may consult an implementation-private
      // symbol, but the transport itself must not read public instance fields.
      if (property === "then") return Reflect.get(target, property, receiver);
      if (typeof property === "symbol") return undefined;
      proxyStringGets += 1;
      throw new Error("response get trap must not run");
    },
  });
  const proxiedClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: () => proxiedResponse,
  });
  await assert.rejects(
    proxiedClient.compile("seiyaku Demo {}", { timeoutMs: 100 }),
    /invalid Response/u,
  );
  assert.equal(proxyStringGets, 0);

  for (const response of [
    new Response(JSON.stringify(SERVICE_SUCCESS), {
      status: 201,
      headers: { "content-type": "application/json" },
    }),
    new Response(JSON.stringify(SERVICE_SUCCESS), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    }),
  ]) {
    const client = new KotodamaCompilerClient("https://compiler.example", {
      fetchImpl: async () => response,
    });
    await assert.rejects(client.compile("seiyaku Demo {}", { timeoutMs: 100 }));
  }

  for (const encoding of ["gzip", "br", "deflate", "identity, gzip"]) {
    let cancelCalls = 0;
    const client = new KotodamaCompilerClient("https://compiler.example", {
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode(JSON.stringify(SERVICE_SUCCESS)));
            },
            cancel() {
              cancelCalls += 1;
            },
          }),
          {
            status: 200,
            headers: {
              "content-encoding": encoding,
              "content-type": "application/json",
            },
          },
        ),
    });
    await assert.rejects(
      client.compile("seiyaku Demo {}", { timeoutMs: 100 }),
      /Content-Encoding must be absent or exactly identity/u,
    );
    assert.equal(cancelCalls, 1, `encoded ${encoding} body was not cancelled`);
  }

  const identityClient = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => jsonResponse(SERVICE_SUCCESS, {
      headers: { "content-encoding": "identity" },
    }),
  });
  assert.equal(
    (await identityClient.compile("seiyaku Demo {}", { timeoutMs: 100 })).ok,
    true,
  );

  for (const [body, declared] of [["{}", 1], ["{}", 3], [null, 1]]) {
    const client = new KotodamaCompilerClient("https://compiler.example", {
      fetchImpl: async () =>
        new Response(body, {
          status: 200,
          headers: {
            "content-length": String(declared),
            "content-type": "application/json",
          },
        }),
    });
    await assert.rejects(
      client.compile("seiyaku Demo {}", { timeoutMs: 100 }),
      /body length does not match its Content-Length header/u,
    );
  }

  let proxyGets = 0;
  const hostileChunks = [
    new Uint8Array(),
    { byteLength: 1 },
    new Proxy(new Uint8Array([1]), {
      get() {
        proxyGets += 1;
        throw new Error("chunk get trap must not run");
      },
    }),
  ];
  if (typeof SharedArrayBuffer === "function") {
    hostileChunks.push(new Uint8Array(new SharedArrayBuffer(1)));
  }
  for (const chunk of hostileChunks) {
    let cancelCalls = 0;
    const client = new KotodamaCompilerClient("https://compiler.example", {
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(chunk);
            },
            cancel() {
              cancelCalls += 1;
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });
    await assert.rejects(client.compile("seiyaku Demo {}", { timeoutMs: 100 }));
    assert.equal(cancelCalls, 1, "hostile byte streams must be cancelled");
  }
  assert.equal(proxyGets, 0);
});

test("compiler response and HTTP error bodies are bounded before reading", async () => {
  const oversizedResult = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      new Response("{}", {
        status: 200,
        headers: {
          "content-length": String(16 * 1024 * 1024 + 1),
          "content-type": "application/json",
        },
      }),
  });
  await assert.rejects(
    oversizedResult.compile("seiyaku Demo {}"),
    /exceeds the 16777216-byte response limit/,
  );

  let streamCancelled = false;
  let emittedChunks = 0;
  const chunk = new Uint8Array(1024 * 1024);
  const oversizedStream = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.enqueue(chunk);
            emittedChunks += 1;
          },
          cancel() {
            streamCancelled = true;
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  await assert.rejects(
    oversizedStream.compile("seiyaku Demo {}"),
    /exceeds the 16777216-byte response limit/,
  );
  assert.ok(
    emittedChunks >= 17 && emittedChunks <= 18,
    "stream backpressure may queue at most one chunk beyond the rejected chunk",
  );
  assert.equal(streamCancelled, true, "the reader must cancel an oversized live stream");

  const oversizedError = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () =>
      new Response("failure", {
        status: 500,
        headers: { "content-length": String(64 * 1024 + 1) },
      }),
  });
  await assert.rejects(
    oversizedError.compile("seiyaku Demo {}"),
    /exceeds the 65536-byte response limit/,
  );
});

test("compiler service transport failures surface bounded status details", async () => {
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => new Response("K9000: unavailable", { status: 503 }),
  });
  await assert.rejects(
    client.compile("seiyaku Demo {}"),
    /Kotodama compiler service failed \(503\): K9000: unavailable/,
  );
});

test("browser entrypoint refuses implicit offline compilation", async () => {
  await assert.rejects(
    compileKotodamaInBrowser("seiyaku Demo {}"),
    /requires compilerUrl; offline compilation is unsupported/,
  );
});

test("retired compiler policy options fail closed", async () => {
  for (const options of [
    { abiVersion: 1 },
    { forceVector: true },
    { forceZk: true },
    { embedDebug: true },
    { mode: "test" },
  ]) {
    await assert.rejects(
      compileKotodamaInBrowser("seiyaku Demo {}", options),
      /unknown Kotodama compiler option/,
    );
  }
});

test("compiler transport configuration rejects ambiguous or credential-bearing URLs", async () => {
  for (const options of [
    { compilerUrl: "" },
    { compilerUrl: "compiler.example" },
    { compilerUrl: "http://compiler.example" },
    { compilerUrl: "https://user:secret@compiler.example" },
    { compilerUrl: "https://compiler.example?target=other" },
    { compilerUrl: "https://compiler.example#other" },
    { compilerUrl: "https://compiler.example", fetchImpl: true },
  ]) {
    await assert.rejects(compileKotodamaProgram("seiyaku Demo {}", options), TypeError);
  }
});

test("loopback development compiler services may use HTTP", async () => {
  for (const compilerUrl of [
    "http://localhost:8080",
    "http://worker.localhost:8080",
    "http://127.0.0.1:8080",
    "http://[::1]:8080",
  ]) {
    const calls = [];
    const result = await compileKotodamaProgram("seiyaku Demo {}", {
      compilerUrl,
      fetchImpl: successfulFetch(calls),
    });
    assert.equal(result.ok, true);
    assert.equal(calls.length, 1);
  }
});


test("compiler artifact requires the error-message catalog field even when empty", async () => {
  const emptyCatalog = (manifest) => { manifest.error_messages = []; };
  const complete = serviceSuccessWithArtifact(compilerArtifactFixture(), emptyCatalog);
  const accepted = await compileKotodamaWithNativeBinding(
    { async compileKotodama() { return complete; } },
    "seiyaku Demo {}",
  );
  assert.deepEqual(accepted.output.manifest.error_messages, []);

  // Recompute the frame CRC and artifact hash so the missing field is the
  // structural failure, rather than an unrelated authentication mismatch.
  const incomplete = serviceSuccessWithArtifact(
    compilerArtifactFixture({ omitErrorMessages: true }),
    emptyCatalog,
  );
  await assert.rejects(
    compileKotodamaWithNativeBinding(
      { async compileKotodama() { return incomplete; } },
      "seiyaku Demo {}",
    ),
    /embedded contract interface\.field13\.length contains a truncated or oversized compact length/u,
  );
});

test("compiler output authenticates static error messages against embedded bytes", async () => {
  const error = { identity: "Demo::Failure", variants: [{ name: "Rejected", code: 7 }] };
  const message = { error_type: error.identity, code: 7, message: "残高が不足しています" };
  const artifact = compilerArtifactFixture({ errorTypes: [error], errorMessages: [message] });
  const response = serviceSuccessWithArtifact(artifact, (manifest) => {
    manifest.error_types = [error];
    manifest.error_messages = [message];
  });
  const native = { async compileKotodama() { return response; } };
  const result = await compileKotodamaWithNativeBinding(native, "seiyaku Demo {}");
  assert.deepEqual(result.output.manifest.error_messages, [message]);
  const forged = JSON.parse(response.output.manifestJson);
  forged.error_messages[0].message = "Forged explanation";
  response.output.manifestJson = JSON.stringify(forged);
  await assert.rejects(compileKotodamaWithNativeBinding(native, "seiyaku Demo {}"), /error_messages do not match/u);
});

test("shared compiler sidecar geometry preserves exact diagnostics and validation order", () => {
  const cases = [
    ["sourceMapJson", { pc_start: 5, source_id: -1 }, "source-map sidecar entry 0 must use a forward PC range"],
    ["sourceMapJson", { source_id: -1, byte_start: -1 }, "source-map sidecar entry 0.source_id must be an unsigned safe integer in 0..4294967295"],
    ["budgetReportJson", { pc_start: 5, bytecode_bytes: -1 }, "budget sidecar entry 0.bytecode_bytes must be an unsigned safe integer in 0..4294967295"],
    ["budgetReportJson", { pc_start: 5, jump_range_risk: 0 }, "budget sidecar entry 0.jump_range_risk must be a boolean"],
    ["budgetReportJson", { source_id: null, byte_start: 0 }, "budget sidecar entry 0 must use one consistent nullable source location"],
  ];
  for (const [field, changed, message] of cases) {
    const result = structuredClone(SERVICE_SUCCESS);
    const sidecar = JSON.parse(result.output[field]);
    Object.assign(sidecar.entries[0], changed);
    result.output[field] = JSON.stringify(sidecar);
    assert.throws(() => normalizeCompilerResult(result), { name: "TypeError", message });
  }
  const nullable = structuredClone(SERVICE_SUCCESS);
  const budget = JSON.parse(nullable.output.budgetReportJson);
  for (const key of ["source_path", "source_id", "byte_start", "byte_end", "line", "column"]) {
    budget.entries[0][key] = null;
  }
  nullable.output.budgetReportJson = JSON.stringify(budget);
  assert.equal(normalizeCompilerResult(nullable).output.budgetReport[0].source_id, null);
});

test("shared compiler native invocation preserves the exact metadata failure cause", async () => {
  const client = new KotodamaCompilerClient("https://compiler.example", {
    fetchImpl: async () => ({}),
  });
  await assert.rejects(client.compile("seiyaku Demo {}"), (error) => {
    assert.equal(error.name, "TypeError");
    assert.equal(error.message, "Kotodama compiler fetch returned an invalid Response");
    assert.ok(error.cause instanceof TypeError);
    return true;
  });
});

test("shared compiler Unicode validation accepts scalar pairs and rejects lone surrogates", async () => {
  const calls = [];
  const client = new KotodamaCompilerClient("https://compiler.example", { fetchImpl: successfulFetch(calls) });
  await client.compile("seiyaku Demo {} // \u{1F30F}");
  assert.equal(calls.length, 1);
  for (const source of ["\uD800", "\uDFFF", "\uD800x"]) {
    await assert.rejects(client.compile(source), { name: "TypeError", message: "Kotodama source must contain valid Unicode scalar values" });
  }
  assert.equal(calls.length, 1);
});

test("compact callable tape preserves complete nominal roles and every scalar kind", () => {
  const leaf = (kind) => Uint8Array.of(5, kind);
  const nominal = (name, names) => concatBytes(Uint8Array.of(0), stringField(name), u64Le(names.length), ...names.map((name) => field(stringField(name))));
  const descriptor = { identity: "Demo::Failure", variants: [{ name: "Low", code: 3 }, { name: "High", code: 9 }] };
  const encodedError = concatBytes(field(stringField(descriptor.identity)), field(concatBytes(u64Le(2), ...descriptor.variants.map((variant) => field(concatBytes(field(stringField(variant.name)), field(u32Le(variant.code))))))));
  const argumentNodes = [
    nominal("Fixture::Point", ["text", "bytes"]), leaf(4), leaf(13),
    Uint8Array.of(2, 3, 4, 64), leaf(2), concatBytes(Uint8Array.of(7), field(encodedError)),
    nominal("Fixture::Empty", []), Uint8Array.of(6), Uint8Array.of(9),
    ...Array.from({ length: 14 }, (_, kind) => leaf(kind)),
    ...Array.from({ length: 14 }, (_, kind) => kind).filter((kind) => kind !== 5).map(callableCursorFixture),
    ...[0x0b, 0x0d, 0x0e, 0x0f, 0x13].map((id) => Uint8Array.of(10, id, 0)),
    ...[0x10, 0x11, 0x12].map((id) => Uint8Array.of(11, id, 0)),
  ];
  // The node count counts semantic nodes, not concatenated fixture chunks.
  const flat = argumentNodes.flatMap((bytes, index) => index === 3 ? [bytes.subarray(0, 1), bytes.subarray(1, 2), bytes.subarray(2)] : [bytes]);
  const vector = concatBytes(u64Le(1), field(callableFixture({ argumentNodes: flat })));
  assert.equal(validateEmbeddedCallables(vector, 1, 1, "callables", [descriptor], []), 0n);
  const mismatched = [{ ...descriptor, variants: [{ name: "Low", code: 3 }, { name: "High", code: 10 }] }];
  assert.throws(() => validateEmbeddedCallables(vector, 1, 1, "callables", mismatched, []), /nominal catalog/u);
  assert.throws(() => validateEmbeddedCallables(vector, 0, 1, "callables", [descriptor], []), /private numeric/u);
});

test("compact callable tape rejects retired bodies, truncation, forged shapes and impossible counts", () => {
  const compact = (count, bytes) => concatBytes(Uint8Array.of(0x43, 0x53, 0x31, 0), u64Le(count), bytes);
  const unit = compact(1, Uint8Array.of(6));
  const nominal = (name, names) => concatBytes(Uint8Array.of(0), stringField(name), u64Le(names.length), ...names.map((name) => field(stringField(name))));
  const invalid = [
    ["retired generic vector body", field(concatBytes(u64Le(1), field(u32Le(6))))],
    ["missing magic", concatBytes(Uint8Array.of(0, 0, 0, 0), unit.subarray(4))],
    ["unknown node", compact(1, Uint8Array.of(12))],
    ["unknown scalar", compact(1, Uint8Array.of(5, 14))],
    ["invalid Json cursor key", compact(1, callableCursorFixture(5))],
    ["missing child", compact(1, Uint8Array.of(2))],
    ["List capacity", compact(2, Uint8Array.of(4, 65, 6))],
    ["affine List", compact(2, Uint8Array.of(4, 1, 9))],
    ["duplicate fields", compact(3, concatBytes(nominal("Fixture::Point", ["x", "x"]), Uint8Array.of(6, 6)))],
    ["reserved substitution", compact(3, concatBytes(nominal("kotodama::AccountView", ["id", "metadata"]), Uint8Array.of(5, 13, 5, 5)))],
    ["count underflow", compact(0, Uint8Array.of(6))],
    ["count overflow", compact(2, Uint8Array.of(6))],
    ["node limit", compact(250_001, Uint8Array.of(6))],
    ["u64 count overflow", concatBytes(Uint8Array.of(0x43, 0x53, 0x31, 0), new Uint8Array(8).fill(255), Uint8Array.of(6))],
    ["trailing node", concatBytes(unit, Uint8Array.of(6))],
    ...Array.from({ length: unit.length }, (_, length) => [`truncated ${length}`, unit.subarray(0, length)]),
  ];
  for (const [name, resultSchemaBytes] of invalid) {
    const vector = concatBytes(u64Le(1), field(callableFixture({ resultSchemaBytes })));
    assert.throws(() => validateEmbeddedCallables(vector, 1, 1, "callables", [], []), /callable|nominal|List|query|cursor|scalar/u, name);
  }
});


test("compiler responses bind ordinary enum schemas and event tables to the complete artifact", async () => {
  const manifest = JSON.parse(SERVICE_OUTPUT.manifestJson);
  const descriptor = { identity: "Demo::Status", variants: [{ name: "Open", code: 1 }, { name: "Done", code: 7 }] };
  manifest.enum_types = [descriptor];
  manifest.events = [{ name: "Changed", payload_type: { nodes: [{ kind: "Struct", value: { name: "Demo::Changed", fields: ["status"] } }, { kind: "Enum", value: descriptor }] } }];
  manifest.states = [{ name: "status", type_name: descriptor.identity }];
  manifest.entrypoints[0].return_type = descriptor.identity;
  manifest.entrypoints[0].return_schema = { nodes: [{ kind: "Enum", value: descriptor }] };
  const artifact = compilerArtifactFixture({ manifest, states: 1, callables: [callableFixture({ resultNodes: [concatBytes(Uint8Array.of(12), field(encodeContractMetadataValueV1("enum_type", descriptor)))] })] });
  const response = serviceSuccessWithArtifact(artifact, (target) => Object.assign(target, manifest));
  const accepted = normalizeCompilerResult(response);
  assert.deepEqual(accepted.output.manifest.events, manifest.events);
  for (const key of ["permissions", "events", "enum_types"]) {
    const incomplete = structuredClone(response);
    const body = JSON.parse(incomplete.output.manifestJson);
    delete body[key];
    incomplete.output.manifestJson = JSON.stringify(body);
    assert.throws(() => normalizeCompilerResult(incomplete), /invalid field set/u, key);
  }
  const forged = structuredClone(response);
  const body = JSON.parse(forged.output.manifestJson);
  body.enum_types[0].variants[1].code = 8;
  body.events[0].payload_type.nodes[1].value.variants[1].code = 8;
  body.entrypoints[0].return_schema.nodes[0].value.variants[1].code = 8;
  forged.output.manifestJson = JSON.stringify(body);
  assert.throws(() => normalizeCompilerResult(forged), /does not exactly match/u);
});


test("compiled imports retain exact owner bytes and reject malformed artifact inventories", () => {
  const bytes = [73, 86, 77, 1];
  const request = buildCompilerRequest("seiyaku Caller {}", {
    sourceName: "caller.ko",
    artifacts: [{ sourceName: "./interfaces/pool.to", artifact: bytes }],
    packages: [{ identity: "local/library@1", modules: [{ sourceName: "lib.ko", source: "module Library {}" }], exports: [], artifacts: [{ sourceName: "interfaces/pool.to", artifact: [9] }] }],
  });
  assert.deepEqual(request.artifacts, [{ sourceName: "interfaces/pool.to", artifact: bytes }]);
  bytes[0] = 0;
  assert.equal(request.artifacts[0].artifact[0], 73, "native requests own a byte snapshot");
  assert.deepEqual(request.packages[0].artifacts[0].artifact, [9], "same logical paths in distinct owners remain distinct");
  for (const artifacts of [
    [{ sourceName: "../escape.to", artifact: [1] }],
    [{ sourceName: "pool.json", artifact: [1] }],
    [{ sourceName: "pool.to", artifact: [] }],
    [{ sourceName: "pool.to", artifact: [256] }],
    [{ sourceName: "pool.to", artifact: [1] }, { sourceName: "./pool.to", artifact: [2] }],
  ]) assert.throws(() => buildCompilerRequest("seiyaku Caller {}", { sourceName: "caller.ko", artifacts }));
  let reads = 0;
  const hostile = [];
  Object.defineProperty(hostile, "0", { get() { reads += 1; return 1; } });
  assert.throws(() => buildCompilerRequest("seiyaku Caller {}", { sourceName: "caller.ko", artifacts: [{ sourceName: "pool.to", artifact: hostile }] }), /inert byte/);
  assert.equal(reads, 0);
});


test("compiler statement maps partition physical budgets while retaining inlined source names", () => {
  const response = structuredClone(SERVICE_SUCCESS);
  const map = JSON.parse(response.output.sourceMapJson);
  const original = map.entries[0];
  map.entries = [
    { ...original, pc_end: 1 },
    { ...original, source_kind: "statement", function_name: "inlined_helper", pc_start: 1, pc_end: 3 },
    { ...original, pc_start: 3 },
  ];
  response.output.sourceMapJson = JSON.stringify(map);
  assert.deepEqual(normalizeCompilerResult(response).output.sourceMap, map.entries);
  for (const mutate of [
    (entries) => { delete entries[0].source_kind; },
    (entries) => { entries[0].source_kind = "expression"; },
    (entries) => { entries[1].pc_start = 2; },
    (entries) => { entries[1].pc_start = 0; },
    (entries) => { entries[1].pc_end = 5; },
    (entries) => { entries[1].pc_end = entries[1].pc_start; },
    (entries) => { entries[0].function_name = "wrong_function"; },
    (entries) => { entries.push({ ...entries[2], pc_start: 4, pc_end: 5 }); },
    (entries) => { entries.pop(); },
  ]) {
    const invalidMap = structuredClone(map);
    mutate(invalidMap.entries);
    const invalid = structuredClone(response);
    invalid.output.sourceMapJson = JSON.stringify(invalidMap);
    assert.throws(() => normalizeCompilerResult(invalid), TypeError);
  }
});

test("compiler diagnostic companion fields are required and recursively exact", () => {
  for (const mutate of [
    (diagnostic) => { delete diagnostic.alternative_fixes; },
    (diagnostic) => { delete diagnostic.localized; },
    (diagnostic) => { diagnostic.alternative_fixes = null; },
    (diagnostic) => { diagnostic.alternative_fixes[0].unexpected = true; },
    (diagnostic) => { diagnostic.alternative_fixes[0].span.start.column = 0; },
    (diagnostic) => { diagnostic.alternative_fixes[0].replacement = null; },
    (diagnostic) => { diagnostic.localized.unexpected = true; },
    (diagnostic) => { diagnostic.localized.language = ""; },
    (diagnostic) => { delete diagnostic.localized.help; },
  ]) {
    const diagnostics = structuredClone(SERVICE_DIAGNOSTICS);
    mutate(diagnostics[0]);
    assert.throws(() => normalizeCompilerResult({
      ...SERVICE_FAILURE, diagnosticsJson: JSON.stringify(diagnostics),
    }), TypeError);
  }
  const diagnostics = structuredClone(SERVICE_DIAGNOSTICS);
  diagnostics[1].severity = "warning";
  diagnostics[1].code = "W_PROVER_PRIVATE_INPUT";
  assert.deepEqual(normalizeCompilerResult({
    ...SERVICE_FAILURE, diagnosticsJson: JSON.stringify(diagnostics),
  }).diagnostics, diagnostics);
});
