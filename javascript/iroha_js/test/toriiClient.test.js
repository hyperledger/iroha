import { withArtifactResponseIdentity } from "./contractArtifactReadTestHelpers.js";
import { buildRegisterSmartContractCodeInstruction } from "../src/instructionBuilders.js";
import { canonicalHashLiteral } from "../src/instructionBuilderPrimitives.js";
import { universalArtifactInput } from "./contractArtifactTestHelpers.js";

async function normalizeArtifactManifestFixture(input) {
  // Give transport/type fixtures an explicit policy. Invalid policy tests retain
  // any explicitly supplied field, including undefined, for production validation.
  const manifest = { events: [], enum_types: [], ...input.manifest };
  if (Array.isArray(manifest.entrypoints)) {
    manifest.entrypoints = manifest.entrypoints.map((entry) => {
      if (Object.hasOwn(entry, "authorization")) return entry;
      const kind = typeof entry.kind === "string" ? entry.kind : entry.kind?.kind;
      return {
        ...entry,
        authorization: {
          kind: kind === "Hajimari" || kind === "Kaizen" ? "RuntimeLifecycle" : "Anyone",
          value: null,
        },
      };
    });
  }
  if (!Object.hasOwn(manifest, "permissions")) {
    const names = new Set((manifest.entrypoints ?? [])
      .filter((entry) => entry.authorization?.kind === "Permission")
      .map((entry) => entry.authorization.value));
    manifest.permissions = [...names].sort().map((name) => ({
      name, scope: { kind: "Instance", value: null },
    }));
  }
  return buildRegisterSmartContractCodeInstruction(universalArtifactInput({ ...input, manifest })).RegisterSmartContractCode;
}

import { sorafsReplicationProjectionFixture, sorafsReplicationAttestationFixture } from "./helpers/sorafsReplicationProjection.js";
import { sorafsPinDetailFixture, typedSorafsPinDetailFixture } from "./helpers/sorafsPinDetail.js";
import { sorafsAliasProjectionFixture, sorafsAliasAttestationFixture } from "./helpers/sorafsAliasProjection.js";
import { test as nodeTest } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import fs from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  LocalSigningContext,
  ToriiClient as SourceToriiClient,
  ToriiDataModelMismatchError,
  ToriiHttpError,
  extractPipelineStatusKind,
  decodePdpCommitmentHeader,
  TransactionStatusError,
  TransactionTimeoutError,
  TransactionBatchAdmissionAmbiguousError,
  IsoMessageTimeoutError,
  buildSorafsOrderbookEventsWebSocketUrl,
  statusLivenessElapsedMs,
  isStatusQueueStalled,
} from "../src/toriiClient.js";

import {
  LocalSigningContext as DistLocalSigningContext,
  OperatorSigningContext as DistOperatorSigningContext,
  ToriiClient as DistToriiClient,
} from "../dist/toriiClient.js";
import { NetworkId as DistNetworkId } from "../dist/networkId.js";
import {
  resolveToriiClientConfig,
  extractToriiFeatureConfig,
  extractConfidentialGasConfig,
} from "../src/config.js";
import {
  buildMultisigContractCallProposeRequest,
  buildMultisigProposeRequest,
  canonicalRequestSignatureMessage,
  NetworkId,
  noritoEncodeMultisigContractCallProposeRequest,
  normalizeAccountId,
  signEd25519,
  verifyEd25519,
  ValidationError,
  ValidationErrorCode,
  AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
  field,
} from "../src/index.js";
import {
  AccountAddress,
  AccountAddressError,
  AccountAddressErrorCode,
} from "../src/address.js";
import { sorafsGatewayFetch } from "../src/sorafs.js";
import {
  TORII_TEST_HOOKS,
  TORII_TEST_NATIVE_BINDING,
} from "../src/toriiTestHooks.js";
import { IVM_ARTIFACT_MAX_BYTES } from "../src/ivmArtifact.js";
import { blake2b256 } from "../src/blake2b.js";
import { contractPayloadDigestHex } from "../src/contractPayload.js";
import { buildBrowserVerifyingKeyTransactionPayload } from "../src/transactionCodec.js";
import {
  parseStrictLosslessIntegerJson,
  stringifyStrictLosslessIntegerJson,
} from "../src/strictLosslessJson.js";
import {
  makeNativeTest,
  nativeBinding,
  nativeBindingError,
  nativeUnavailableMessage,
} from "./helpers/native.js";
import { registerToriiClientGovernanceTests } from "./toriiClientGovernanceTests.js";
import { registerToriiClientConnectSessionTests } from "./toriiClientConnectSessionTests.js";
import {
  registerToriiClientBoundedResponseTests,
  registerToriiClientDistributionMemoryTests,
} from "./toriiClientMemoryBoundsTests.js";
import {
  assertFlattenedAliasSelector,
  cloneFixture,
  createSseResponse,
  fileExists,
  makeTestOperatorSigningContext,
  noritoFramePayload,
  readCompactLength,
  readNoritoFieldPayload,
  readU64Length,
  withEnv,
} from "./toriiClientTestHelpers.js";

const test = nodeTest;

function retailAssessmentFixture() {
  return JSON.parse(readFileSync(new URL("./fixtures/retail_fee_codec_v1.json", import.meta.url),"utf8")).assessment;
}

const BASE_URL = "https://localhost:8080";

const UNIT_RETURN_DESCRIPTOR = Object.freeze({
  returnType: "()",
  returnSchema: { nodes: [{ kind: "Unit", value: null }] },
});

function toriiTestHooks(hooks) {
  return { [TORII_TEST_HOOKS]: hooks };
}
const GOVERNANCE_PROPOSAL_ID = "ab".repeat(32);
const VK_SIGNING_NETWORK_ID = NetworkId.parse(
  "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
);
const VK_LOCAL_SIGNING_CONTEXT = new LocalSigningContext(
  VK_SIGNING_NETWORK_ID, 753,
);
const ISO_OPERATOR_SIGNING_CONTEXT =
  makeTestOperatorSigningContext(VK_SIGNING_NETWORK_ID);
const DIST_VK_SIGNING_NETWORK_ID = DistNetworkId.parse(
  "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
);
const DIST_LOCAL_SIGNING_CONTEXT = new DistLocalSigningContext(
  DIST_VK_SIGNING_NETWORK_ID, 753,
);
const DIST_OPERATOR_SIGNING_CONTEXT = new DistOperatorSigningContext(
  DIST_VK_SIGNING_NETWORK_ID,
  {
    publicKey: ISO_OPERATOR_SIGNING_CONTEXT.publicKey,
    sign: (message) => ISO_OPERATOR_SIGNING_CONTEXT.sign(message),
  },
);
class ToriiClient extends SourceToriiClient {
  constructor(baseUrl, options = {}) {
    super(baseUrl, {
      localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
      operatorSigningContext: ISO_OPERATOR_SIGNING_CONTEXT,
      canonicalRequestAuth: APPLICATION_CANONICAL_AUTH,
      ...options,
    });
  }
}

const ARTIFACT_READ_FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/current_rust_contract_artifact.json", import.meta.url), "utf8"));
const ARTIFACT_READ_HASH = ARTIFACT_READ_FIXTURE.artifact_semantics.code_hash_hex;
const ARTIFACT_READ_RESPONSE = withArtifactResponseIdentity({ code_b64: ARTIFACT_READ_FIXTURE.artifact_base64 }, ARTIFACT_READ_HASH);

const IVM_ARTIFACT_MAX_BASE64_LENGTH =
  Math.ceil(IVM_ARTIFACT_MAX_BYTES / 3) * 4;
const CONTRACT_CODE_BYTES_JSON_MAX_BYTES =
  IVM_ARTIFACT_MAX_BASE64_LENGTH + 1024;
const SAMPLE_ACCOUNT_SIGNATORY =
  "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
const SEED_11_ED25519_PUBLIC_KEY_HEX =
  "D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737";
const CANONICAL_ALIAS_MANIFEST_CID_HEX = `01711f20${"aa".repeat(32)}`;
const SAMPLE_ACCOUNT_DOMAIN = "wonderland";
const SORA_I105_DISCRIMINANT = 0x2f1;
const SAMPLE_ACCOUNT_OWNER = AccountAddress.fromAccount({
  publicKey: Buffer.from(SAMPLE_ACCOUNT_SIGNATORY.slice(6), "hex"),
}).toI105(SORA_I105_DISCRIMINANT);
const SEED_11_OWNER = AccountAddress.fromAccount({
  publicKey: Buffer.from(SEED_11_ED25519_PUBLIC_KEY_HEX, "hex"),
}).toI105(SORA_I105_DISCRIMINANT);
const toriiFixtures = JSON.parse(
  readFileSync(new URL("./fixtures/torii_responses.json", import.meta.url), "utf8"),
);
const validationFixtures = JSON.parse(
  readFileSync(new URL("./fixtures/validation_errors.json", import.meta.url), "utf8"),
);


const txStatusErrorMessageContract = JSON.parse(
  readFileSync(
    new URL("../../../fixtures/sdk/tx_status_error_message_contract.json", import.meta.url),
    "utf8",
  ),
);
const nativeTest = makeNativeTest(test);

function assertRequestSignal(actual, caller, label = "request signal") {
  assert.ok(actual, `${label} is present`);
  assert.equal(typeof actual.addEventListener, "function", `${label} is abortable`);
  assert.equal(actual.aborted, caller.aborted, `${label} preserves caller state`);
}

function canonicalTransactionCodecNative(overrides = {}) {
  return {
    encodeSignedTransactionVersioned: (payload) => {
      const bytes = Buffer.from(payload);
      if (bytes.length === 0 || bytes[0] !== 1) {
        throw new Error("test payload is not VersionedSignedTransaction V1");
      }
      return bytes;
    },
    ...overrides,
  };
}

test("governance lossless JSON writer preserves raw u64 tokens", () => {
  const encoded = stringifyStrictLosslessIntegerJson(
    {
      zero: 0,
      maximum: (1n << 64n) - 1n,
      nested: ["value", true, null],
    },
    "governance writer test",
  );
  assert.equal(
    encoded,
    '{"zero":0,"maximum":18446744073709551615,"nested":["value",true,null]}',
  );
  const decoded = parseStrictLosslessIntegerJson(encoded, "governance writer test");
  assert.equal(decoded.maximum, (1n << 64n) - 1n);
  assert.throws(
    () => stringifyStrictLosslessIntegerJson({ unsafe: Number.MAX_SAFE_INTEGER + 1 }, "test"),
    /safe integers/u,
  );
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(
    () => stringifyStrictLosslessIntegerJson(cyclic, "test"),
    /cyclic values/u,
  );
});

function chunkFetchPlan(
  chunkFetchSpecs,
  payloadDigestBlake3Hex = "11".repeat(32),
) {
  return {
    schema: "sorafs.chunk_fetch_plan.v1",
    payload_digest_blake3_hex: payloadDigestBlake3Hex,
    chunk_fetch_specs: chunkFetchSpecs,
  };
}

function canonicalSignatureBase64Fixture() {
  return Buffer.alloc(64, 0x01).toString("base64");
}

function authorityFeePayment(gasLimit = null) {
  return {
    payer: "authority",
    value: { charge_limits: [], gas_limit: gasLimit },
  };
}

function sponsorFeePayment(sponsor, gasLimit, programRevision = 1) {
  return {
    payer: "sponsor",
    value: {
      program_id: { sponsor, name: "contracts" },
      program_revision: programRevision,
      charge_limits: [],
      gas_limit: gasLimit,
    },
  };
}

function authoritativePipelineStatus(
  hash,
  kind,
  {
    resolvedFrom = ["Applied", "Rejected", "Expired"].includes(kind) ? "state" : "queue",
    blockHeight = kind === "Applied" ? 1 : undefined,
  } = {},
) {
  const status = {
    kind,
    ...(blockHeight === undefined ? {} : { block_height: blockHeight }),
  };
  return {
    hash,
    status,
    scope: "global",
    resolved_from: resolvedFrom,
  };
}

function authoritativePipelineStatusResponse(hash, kind, options = {}) {
  return authoritativePipelineStatus(hash, kind, options);
}

function noncanonicalStandardBase64PadBitAlias(encoded) {
  assert.equal(encoded.endsWith("=="), true);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const chars = [...encoded];
  const index = chars.length - 3;
  const value = alphabet.indexOf(chars[index]);
  assert.notEqual(value, -1);
  chars[index] = alphabet[value ^ 0x01];
  return chars.join("");
}

function assertContractCallPayloadJson(body, expected, label) {
  const { flags, payload } = noritoFramePayload(body, label);
  const compactLength = (flags & 0x02) !== 0;
  let offset = 0;
  for (const fieldName of [
    "multisig_account_id",
    "multisig_account_alias",
    "signer_account_id",
    "public_key_hex",
    "signature_b64",
    "creation_time_ms",
    "contract_alias",
    "entrypoint",
  ]) {
    offset = readNoritoFieldPayload(
      payload,
      offset,
      `${label}.${fieldName}`,
      compactLength,
    ).offset;
  }
  const payloadField = readNoritoFieldPayload(
    payload,
    offset,
    `${label}.payload`,
    compactLength,
  );
  const jsonValue = readNoritoFieldPayload(
    payloadField.payload,
    0,
    `${label}.payload.json.value`,
    compactLength,
  );
  assert.equal(jsonValue.offset, payloadField.payload.length);
  const jsonString = readNoritoFieldPayload(
    jsonValue.payload,
    0,
    `${label}.payload.json.value.string`,
    compactLength,
  );
  assert.equal(jsonString.offset, jsonValue.payload.length);
  assert.deepEqual(JSON.parse(jsonString.payload.toString("utf8")), expected);
}

function assertMultisigProposeInstructionWireId(body, expectedWireId, label) {
  const { flags, payload } = noritoFramePayload(body, label);
  const compactLength = (flags & 0x02) !== 0;
  let offset = 0;
  for (const fieldName of [
    "multisig_account_id",
    "multisig_account_alias",
    "signer_account_id",
    "public_key_hex",
    "signature_b64",
    "creation_time_ms",
    "fee_payment",
    "memo",
    "validation_fee_assessment",
  ]) {
    offset = readNoritoFieldPayload(
      payload,
      offset,
      `${label}.${fieldName}`,
      compactLength,
    ).offset;
  }
  const instructions = readNoritoFieldPayload(
    payload,
    offset,
    `${label}.instructions`,
    compactLength,
  );
  const count = readU64Length(instructions.payload, 0, `${label}.instructions.count`);
  assert.equal(count.length, 1);
  const first = readNoritoFieldPayload(
    instructions.payload,
    count.bytes,
    `${label}.instructions[0]`,
    compactLength,
  );
  assert.equal(first.offset, instructions.payload.length);
  const wireId = readNoritoFieldPayload(
    first.payload,
    0,
    `${label}.instructions[0].wire_id`,
    compactLength,
  );
  const wireIdString = readNoritoFieldPayload(
    wireId.payload,
    0,
    `${label}.instructions[0].wire_id.value`,
    compactLength,
  );
  assert.equal(wireIdString.payload.toString("utf8"), expectedWireId);
}

function sampleAccountForms() {
  const publicKeyHex = SAMPLE_ACCOUNT_SIGNATORY.slice(6);
  const publicKey = Buffer.from(publicKeyHex, "hex");
  const address = AccountAddress.fromAccount({
    publicKey,
  });
  const i105Literal = address.toI105(SORA_I105_DISCRIMINANT);
  const malformedI105 = i105Literal.replace(/^sora/u, "ｓｏｒａ");
  const canonical = normalizeAccountId(
    i105Literal,
    "toriiClient.sampleAccountForms",
  );
  const canonicalBytes = Buffer.from(address.canonicalHex().slice(2), "hex");
  const selectorPrefixed = Buffer.concat([
    canonicalBytes.subarray(0, 1),
    Buffer.from([0x01, ...Array.from({ length: 12 }, (_, index) => index + 1)]),
    canonicalBytes.subarray(1),
  ]);
  const selectorPrefixedHex = `0x${selectorPrefixed.toString("hex")}`;
  return Object.freeze({
    canonical,
    i105: i105Literal,
    malformedI105,
    selectorPrefixedHex,
  });
}

const SAMPLE_ACCOUNT_FORMS = sampleAccountForms();
const SAMPLE_ACCOUNT_ID = SAMPLE_ACCOUNT_FORMS.canonical;
const CANONICAL_AUTH_ALIAS = "alice-1@wonderland";
function canonicalReadOptions(options = {}) {
  return {
    ...options,
    canonicalAuth: {
      accountId: CANONICAL_AUTH_ALIAS,
      privateKey: Buffer.alloc(32, 0x0c),
    },
  };
}
const SORAFS_CANONICAL_AUTH = Object.freeze(canonicalReadOptions().canonicalAuth);

const SAMPLE_RWA_ID =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities";
const SAMPLE_RWA_ID_UPPER =
  "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF$commodities";

function fixtureAccountAddress(label, variant = "fixture") {
  let attempt = 0;
  while (attempt < 1024) {
    const hash = crypto
      .createHash("sha256")
      .update(`fixture:${label}:${variant}:${attempt}`)
      .digest();
    try {
      return AccountAddress.fromAccount({ publicKey: hash,
      });
    } catch (error) {
      if (
        !(error instanceof AccountAddressError) ||
        error.code !== AccountAddressErrorCode.INVALID_PUBLIC_KEY
      ) {
        throw error;
      }
      attempt += 1;
    }
  }
  throw new Error(`unable to derive canonical fixture key for ${label}:${variant}`);
}

function fixtureAccountId(label, variant = "fixture") {
  return fixtureAccountAddress(label, variant).toI105(SORA_I105_DISCRIMINANT);
}

function fixtureAccountForms(label, variant = "fixture") {
  const address = fixtureAccountAddress(label, variant);
  return {
    i105: address.toI105(SORA_I105_DISCRIMINANT),
  };
}

const FIXTURE_ALICE_ID = fixtureAccountId("alice");
const FIXTURE_BOB_ID = fixtureAccountId("bob");
const KAIGI_HPKE_PUBLIC_KEY_B64 = "QUJDRA==";
const KAIGI_HPKE_FINGERPRINT_HEX =
  "58c7dab691f514e0bd6f4082852ac0f1e08df24b5864038ff70ecd68419f4a23";
const KAIGI_ALTERNATE_MARKED_HASH_HEX = `${"aa".repeat(31)}ab`;
const KAIGI_SIGNAL_SCHEMA_V1 = "iroha-demo-kaigi-chain-signal/v1";
const FIXTURE_CAROL_ID = fixtureAccountId("carol");
const FIXTURE_ALICE_TEST_ID = fixtureAccountId("alice", "test");
const FIXTURE_VALIDATOR_TEST_ID = fixtureAccountId("validator", "test");
const FIXTURE_BOB_NARNIA_ID = fixtureAccountId("bob", "narnia");
const FIXTURE_VAULT_ID = fixtureAccountId("vault");
const FIXTURE_MERCHANT_ID = fixtureAccountId("merchant");
const FIXTURE_ISSUER_ID = fixtureAccountId("issuer");
const FIXTURE_AUTHORITY_ID = fixtureAccountId("authority");
const APPLICATION_CANONICAL_AUTH = Object.freeze({
  accountId: FIXTURE_AUTHORITY_ID,
  privateKey: Buffer.alloc(32, 0x5a),
});
const FIXTURE_COUNCIL_TEST_ID = fixtureAccountId("council", "test");
const FIXTURE_ALICE_FORMS = fixtureAccountForms("alice");
const FIXTURE_BOB_FORMS = fixtureAccountForms("bob");
const FIXTURE_ASSET_ID_A = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
const FIXTURE_ASSET_ID_B = "61CtjvNd9T3THAR65GsMVHr82Bjc";
const FIXTURE_ASSET_ID_C = "5Pz9SwdN9eXPbiXPX9HRCpzCcE3o";
const FIXTURE_ASSET_ID_D = "7EAD8EFYUx1aVKZPUU1fyKvr8dF1";

function fixtureMultisigAccountId() {
  const members = ["multisig-a", "multisig-b", "multisig-c"].map((label) => {
    const controller = fixtureAccountAddress(label).controllerInfo();
    return {
      curve: controller.curve,
      publicKey: controller.publicKey,
      weight: 1,
    };
  });
  const address = new AccountAddress(
    { version: 0, classId: 1, normVersion: 1, extFlag: false },
    {
      tag: 1,
      version: 1,
      threshold: 2,
      members,
    },
  );
  return address.toI105(SORA_I105_DISCRIMINANT);
}

function assertConcreteMultisigAccountUsesNativeLengths(body, label) {
  const { flags, payload } = noritoFramePayload(body, label);
  const compactLength = (flags & 0x02) !== 0;
  assert.equal(compactLength, true);

  const selector = readNoritoFieldPayload(
    payload,
    0,
    `${label}.multisig_account_id`,
    compactLength,
  );
  assert.equal(selector.payload[0], 1);
  const accountId = readNoritoFieldPayload(
    selector.payload,
    1,
    `${label}.multisig_account_id.some`,
    compactLength,
  );
  assert.equal(accountId.payload.readUInt32LE(0), 1);

  const policy = readNoritoFieldPayload(
    accountId.payload,
    4,
    `${label}.multisig_account_id.policy`,
    compactLength,
  );
  let policyOffset = 0;
  const version = readNoritoFieldPayload(
    policy.payload,
    policyOffset,
    `${label}.policy.version`,
    compactLength,
  );
  policyOffset = version.offset;
  assert.deepEqual([...version.payload], [1]);
  const threshold = readNoritoFieldPayload(
    policy.payload,
    policyOffset,
    `${label}.policy.threshold`,
    compactLength,
  );
  policyOffset = threshold.offset;
  assert.equal(threshold.payload.readUInt16LE(0), 2);
  const members = readNoritoFieldPayload(
    policy.payload,
    policyOffset,
    `${label}.policy.members`,
    compactLength,
  );
  assert.equal(members.offset, policy.payload.length);

  const memberCount = readU64Length(members.payload, 0, `${label}.policy.members.count`);
  assert.equal(memberCount.length, 3);
  const firstMemberLength = readCompactLength(
    members.payload,
    memberCount.bytes,
    `${label}.policy.members[0]`,
  );
  assert.equal(firstMemberLength.bytes, 1);
  const firstMember = readNoritoFieldPayload(
    members.payload,
    memberCount.bytes,
    `${label}.policy.members[0]`,
    compactLength,
  );

  const publicKey = readNoritoFieldPayload(
    firstMember.payload,
    0,
    `${label}.policy.members[0].public_key`,
    compactLength,
  );
  const publicKeyCount = readU64Length(
    publicKey.payload,
    0,
    `${label}.policy.members[0].public_key.count`,
  );
  assert.equal(publicKeyCount.length, 33);
  const algorithm = readNoritoFieldPayload(
    publicKey.payload,
    publicKeyCount.bytes,
    `${label}.policy.members[0].public_key[0]`,
    compactLength,
  );
  assert.equal(algorithm.payload.length, 1);
  assert.equal(algorithm.payload[0], 0);
  const firstKeyByte = readNoritoFieldPayload(
    publicKey.payload,
    algorithm.offset,
    `${label}.policy.members[0].public_key[1]`,
    compactLength,
  );
  assert.equal(firstKeyByte.payload.length, 1);
}

function expectValidationErrorFixture(error, key) {
  assert(error instanceof ValidationError);
  const fixture = validationFixtures[key];
  assert.ok(fixture, `missing validation error fixture: ${key}`);
  assert.equal(error.code, fixture.code);
  assert.equal(error.path, fixture.path);
  assert.equal(error.message, fixture.message);
  return true;
}

const SAMPLE_SNS_GOV_CASE_RESPONSE = Object.freeze({
  case_id: "SNS-2026-00001",
  selector: { suffix_id: 42, label: "alice", global_form: "alice.sora" },
  dispute_type: "ownership",
  priority: "urgent",
  reported_at: "2026-04-01T00:00:00Z",
  acknowledged_at: "2026-04-01T01:00:00Z",
  triage_started_at: "2026-04-01T01:30:00Z",
  hearing_scheduled_at: null,
  resolution_issued_at: null,
  status: "open",
  reporter: { role: "registrar", contact: "ops@example.com", reference_ticket: "SUP-1" },
  respondents: [
    {
      role: "registrant",
      account_id: FIXTURE_ALICE_ID,
      contact: "alice@example.com",
    },
  ],
  allegations: [{ code: "A1", summary: "ownership dispute", policy_reference: "policy-1" }],
  evidence: [
    {
      id: "evidence-1",
      kind: "document",
      uri: "s3://evidence/alice",
      hash: `0x${"aa".repeat(32)}`,
      description: "Initial report",
      sealed: true,
    },
  ],
  sla: {
    acknowledge_by: "2026-04-01T02:00:00Z",
    resolution_by: "2026-04-05T00:00:00Z",
    extensions: [
      {
        approved_by: "council",
        reason: "Awaiting guardian review",
        new_resolution_by: "2026-04-06T00:00:00Z",
      },
    ],
  },
  actions: [
    {
      timestamp: "2026-04-01T00:10:00Z",
      actor: "registrar",
      action: "intake",
      notes: "Initial capture",
    },
  ],
  decision: {
    finding: "upheld",
    remedies: ["refund"],
    effective_at: "2026-04-05T01:00:00Z",
    publication_state: "public",
  },
});

function accountPath(accountId, suffix) {
  const normalized = normalizeAccountId(accountId, "accountId");
  return `/v1/accounts/${encodeURIComponent(normalized)}${suffix}`;
}

function fakeHashHex(byte) {
  return Buffer.alloc(32, byte & 0xff).toString("hex");
}

function fakeSumeragiHash(byte) {
  const bytes = Buffer.alloc(32, byte & 0xff);
  bytes[31] |= 1;
  const body = bytes.toString("hex").toUpperCase();
  let crc = 0xffff;
  for (const value of Buffer.from(`hash:${body}`, "ascii")) {
    crc ^= value << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return `hash:${body}#${crc.toString(16).toUpperCase().padStart(4, "0")}`;
}

const NATIVE_AMX_APPLICATION_MANIFEST_EMPTY_ROOT =
  "hash:45A5D35A09D284480FBA74A402D7F303B82DA0C153FC1E1083AEFC822ED07C2D#7C0F";







function createAutonomousLaneExecution(overrides = {}) {
  return {
    lane_id: 3,
    dataspace_id: 8,
    lane_incarnation: fakeSumeragiHash(0x65),
    lane_block_height: 8,
    lane_block_view: 1,
    proposal_height: 10,
    proposal_view: 2,
    reservation_owner_hash: fakeSumeragiHash(0x66),
    proposal_identity_hash: fakeSumeragiHash(0x67),
    reservation_group_hash: fakeSumeragiHash(0x68),
    proposal_hash: fakeSumeragiHash(0x69),
    descriptor_hash: fakeSumeragiHash(0x73),
    executable_payload_hash: fakeSumeragiHash(0x74),
    source_bundle_hash: fakeSumeragiHash(0x75),
    merge_entry_hash: fakeSumeragiHash(0x76),
    application_block_height: 12,
    application_block_hash: fakeSumeragiHash(0x77),
    reservation_count: 2,
    transaction_count: 2,
    highest_durable_stage: "kura_wsv_application_receipt_durable",
    stuck_reason: "queue_finalization_unverifiable",
    ...overrides,
  };
}

function createLaneSettlementCommitment(overrides = {}) {
  return {
    block_height: 9,
    lane_id: 2,
    lane_incarnation: fakeSumeragiHash(0x51),
    dataspace_id: 7,
    tx_count: 1,
    total_local_amount: "10.25",
    total_xor_due: "5.5",
    total_xor_after_haircut: "4.25",
    total_xor_variance: "1.25",
    swap_metadata: {
      epsilon_bps: 5,
      twap_window_seconds: 60,
      liquidity_profile: { profile: "Tier1", state: null },
      twap_local_per_xor: "2.5",
      volatility_class: { bucket: "Stable", state: null },
    },
    receipts: [
      {
        source_id: fakeHashHex(0x52).toUpperCase(),
        local_amount: "10.25",
        xor_due: "5.5",
        xor_after_haircut: "4.25",
        xor_variance: "1.25",
        timestamp_ms: 1700,
      },
    ],
    nexus_fee_receipts: [],
    native_amx_receipts: [],
    ...overrides,
  };
}

function createNexusFeeReceipt(overrides = {}) {
  return {
    version: 1,
    source_id: "A1".repeat(32),
    dataspace_id: 7,
    lane_id: 2,
    block_height: 9,
    payer_account_id: SAMPLE_ACCOUNT_ID,
    fee_asset_id: "xor#universal",
    fee_amount: "7.5",
    schedule: {
      tx_bytes_len: 128,
      instruction_count: 2,
      gas_used: 3,
      base_fee: "1",
      per_byte_fee: "0.5",
      per_instruction_fee: "2",
      per_gas_unit_fee: "0",
    },
    ...overrides,
  };
}









function createLanePayloadOwnership(overrides = {}) {
  return {
    proposal_height: 10,
    proposal_view: 2,
    lane_id: 2,
    dataspace_id: 7,
    lane_incarnation: fakeSumeragiHash(0x51),
    lane_block_height: 1,
    lane_block_view: 0,
    subject_hash: fakeSumeragiHash(0x53),
    qc_mode_tag: "iroha2-consensus::permissioned-sumeragi@v2",
    accepted_candidate_indices: [0],
    accepted_transaction_hashes: [fakeSumeragiHash(0x54)],
    previous_lane_block_height: 0,
    previous_lane_block_descriptor_hash: null,
    lane_block_descriptor_hash: fakeSumeragiHash(0x55),
    lane_block_descriptor_validator_set: ["alice", "bob", "carol", "dave"],
    lane_block_descriptor_validator_count: 4,
    lane_block_descriptor_min_quorum: 3,
    payload_ownership_hash: fakeSumeragiHash(0x56),
    rbc_instance_hash: fakeSumeragiHash(0x57),
    ...overrides,
  };
}

function createCommittedLaneBlock(overrides = {}) {
  return {
    lane_id: 2,
    dataspace_id: 7,
    lane_incarnation: fakeSumeragiHash(0x51),
    lane_block_height: 1,
    lane_block_view: 0,
    descriptor_hash: fakeSumeragiHash(0x55),
    proposal_hash: fakeSumeragiHash(0x58),
    execution_status: "state_applied_by_canonical_block",
    executable_payload_available: true,
    subject_hash: fakeSumeragiHash(0x53),
    payload_ownership_hash: fakeSumeragiHash(0x56),
    rbc_instance_hash: fakeSumeragiHash(0x57),
    qc_mode_tag: "iroha2-consensus::permissioned-sumeragi@v2",
    validator_count: 4,
    min_quorum: 3,
    prepare_qc_signer_count: 3,
    commit_qc_signer_count: 3,
    ...overrides,
  };
}

function createLaneBlockSession(overrides = {}) {
  return {
    lane_id: 2,
    dataspace_id: 7,
    lane_incarnation: fakeSumeragiHash(0x51),
    lane_block_height: 1,
    lane_block_view: 0,
    proposal_hash: fakeSumeragiHash(0x58),
    has_proposal: true,
    prepare_vote_count: 3,
    commit_vote_count: 3,
    has_prepare_qc: true,
    has_commit_qc: true,
    pending_commit_vote_request: false,
    pending_committed_session_drain: false,
    committed_session_drained: true,
    validator_count: 4,
    min_quorum: 3,
    ...overrides,
  };
}

function sampleVerifyingKeyRegisterPayload() {
  return {
    authority: SAMPLE_ACCOUNT_ID,
    backend: "pipa-r/pasta",
    name: "vk_main",
    version: 1,
    circuit_id: "pipa-r/pasta::transfer_v1",
    public_inputs_schema_hash_hex: "11".repeat(32),
    gas_schedule_id: "default",
    vk_bytes: Buffer.from("abc"),
  };
}

function normalizedVerifyingKeyRequest(request = sampleVerifyingKeyRegisterPayload()) {
  const vkBytes =
    request.vk_bytes === undefined
      ? null
      : Buffer.isBuffer(request.vk_bytes)
        ? Buffer.from(request.vk_bytes)
        : Buffer.from(request.vk_bytes, "base64");
  return {
    ...request,
    public_inputs_schema_hash_hex: request.public_inputs_schema_hash_hex
      .replace(/^0x/iu, "")
      .toLowerCase(),
    ...(vkBytes === null
      ? {}
      : {
          vk_bytes: vkBytes.toString("base64"),
          vk_len: vkBytes.length,
        }),
    ...(request.status === undefined
      ? {}
      : {
          status:
            request.status[0].toUpperCase() +
            request.status.slice(1).toLowerCase(),
        }),
  };
}

function verifyingKeyInstructionForRequest(
  request,
  operation,
  recordOverrides = {},
) {
  const vkBytes =
    request.vk_bytes === undefined
      ? null
      : Buffer.from(request.vk_bytes, "base64");
  const commitmentHex =
    vkBytes === null
      ? request.commitment_hex
      : verifyingKeyCommitmentHex(request.backend, vkBytes);
  const variant =
    operation === "register"
      ? "RegisterVerifyingKey"
      : "UpdateVerifyingKey";
  return {
    verifying_keys: {
      [variant]: {
        id: {
          backend: request.backend,
          name: request.name,
        },
        record: {
          version: request.version,
          circuit_id: request.circuit_id,
          owner_manifest_id: null,
          namespace: "core",
          backend: request.backend.startsWith("stark/")
            ? "stark"
            : "native-pipa-r-pasta",
          curve: request.curve ?? "unknown",
          public_inputs_schema_hash: Array.from(
            Buffer.from(request.public_inputs_schema_hash_hex, "hex"),
          ),
          commitment: Array.from(Buffer.from(commitmentHex, "hex")),
          vk_len: vkBytes === null ? request.vk_len : vkBytes.length,
          max_proof_bytes: request.max_proof_bytes ?? 0,
          gas_schedule_id: request.gas_schedule_id ?? null,
          metadata_uri_cid: request.metadata_uri_cid ?? null,
          vk_bytes_cid: request.vk_bytes_cid ?? null,
          activation_height: request.activation_height ?? null,
          withdraw_height: request.withdraw_height ?? null,
          key:
            vkBytes === null
              ? null
              : {
                  backend: request.backend,
                  bytes: Array.from(vkBytes),
                },
          status: request.status ?? "Active",
          ...recordOverrides,
        },
      },
    },
  };
}

function verifyingKeyTransactionPayload(
  request,
  operation,
  {
    networkId = VK_SIGNING_NETWORK_ID,
    networkPrefix = 753,
    authority = request.authority,
    recordOverrides = {},
    creationTimeMs = 42,
    feePayment = { payer: "authority", chargeLimits: [] },
    metadata = {},
  } = {},
) {
  return buildBrowserVerifyingKeyTransactionPayload(
    {
      networkId,
      networkPrefix,
      authority,
      instructions: [
        verifyingKeyInstructionForRequest(
          request,
          operation,
          recordOverrides,
        ),
      ],
      creationTimeMs,
      ttlMs: 60_000,
      feePayment,
      metadata,
    },
    operation,
  );
}

function browserFeePayment(intent) {
  const chargeLimits = intent.value.charge_limits.map((limit) => ({
    kind: limit.kind.kind === "pipeline_gas" ? "pipelineGas" : limit.kind.kind,
    assetDefinitionId: limit.asset_definition_id,
    maxAmount: limit.max_amount,
  }));
  if (intent.payer === "authority") {
    return {
      payer: "authority",
      chargeLimits,
      gasLimit: intent.value.gas_limit,
    };
  }
  return {
    payer: "sponsor",
    programId: `${intent.value.program_id.sponsor}/${intent.value.program_id.name}`,
    programRevision: intent.value.program_revision,
    chargeLimits,
    gasLimit: intent.value.gas_limit,
  };
}

function multisigDraftForBindings({
  authority = FIXTURE_ALICE_ID,
  feePayment = authorityFeePayment(),
  creationTimeMs = 42,
  metadata = {},
  retiredAdmissionTag = null,
} = {}) {
  const request = {
    ...normalizedVerifyingKeyRequest(),
    authority,
  };
  const original = verifyingKeyTransactionPayload(request, "register", {
    authority,
    creationTimeMs,
    feePayment: browserFeePayment(feePayment),
    metadata,
  });
  const fields = [];
  let offset = 0;
  while (offset < original.length) {
    const field = readTestCompactField(original, offset);
    fields.push(Buffer.from(field.value));
    offset = field.end;
  }
  const ttl = Buffer.alloc(8);
  ttl.writeBigUInt64LE(100_000n);
  fields[4] = Buffer.concat([Buffer.of(1), encodeTestCompactField(ttl)]);
  assert.equal(fields.length, 9);
  if (retiredAdmissionTag !== null) {
    const retired = Buffer.alloc(4);
    retired.writeUInt32LE(retiredAdmissionTag);
    fields.splice(7, 0, retired);
  }
  return verifyingKeyDraftForPayload(
    Buffer.concat(fields.map(encodeTestCompactField)),
  );
}

function contractDraftForBindings(options = {}) {
  return multisigDraftForBindings(options);
}

class ContractToriiClient extends ToriiClient {
  constructor(baseUrl, options = {}) {
    super(baseUrl, {
      canonicalRequestAuth: { ...APPLICATION_CANONICAL_AUTH, accountId: FIXTURE_ALICE_ID },
      ...options,
    });
  }
}

function draftIntentForDraft(draft) {
  const payload = Buffer.from(draft.transaction_payload_b64, "base64");
  const fields = [];
  let offset = 0;
  while (offset < payload.length) {
    const field = readTestCompactField(payload, offset);
    fields.push(field.value);
    offset = field.end;
  }
  return {
    executableB64: fields[3].toString("base64"),
    metadataB64: fields[7].toString("base64"),
  };
}

function contractDraftIntentForDraft(
  draft,
  {
    contractAddress =
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHashHex = "1".repeat(64),
    payload,
  } = {},
) {
  return {
    ...draftIntentForDraft(draft),
    contractAddress,
    codeHashHex,
    payloadDigestHex: contractPayloadDigestHex(payload),
  };
}

function draftWithReplacedTransactionField(draft, fieldIndex, replacement) {
  const payload = Buffer.from(draft.transaction_payload_b64, "base64");
  const fields = [];
  let offset = 0;
  while (offset < payload.length) {
    const field = readTestCompactField(payload, offset);
    fields.push(Buffer.from(field.value));
    offset = field.end;
  }
  fields[fieldIndex] = Buffer.from(replacement);
  return verifyingKeyDraftForPayload(
    Buffer.concat(fields.map(encodeTestCompactField)),
  );
}

function sampleVerifyingKeyTransactionDraft(
  overrides = {},
  {
    request = normalizedVerifyingKeyRequest(),
    operation = "register",
    transaction = {},
  } = {},
) {
  const transactionPayload = verifyingKeyTransactionPayload(
    request,
    operation,
    transaction,
  );
  return verifyingKeyDraftForPayload(transactionPayload, overrides);
}

function verifyingKeyDraftForPayload(transactionPayload, overrides = {}) {
  const signingMessage = Buffer.from(blake2b256(transactionPayload));
  signingMessage[signingMessage.length - 1] |= 1;
  return {
    submitted: false,
    transaction_payload_b64: transactionPayload.toString("base64"),
    signing_message_b64: signingMessage.toString("base64"),
    ...overrides,
  };
}

function encodeTestCompactLength(value) {
  let remaining = BigInt(value);
  const output = [];
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining !== 0n) {
      byte |= 0x80;
    }
    output.push(byte);
  } while (remaining !== 0n);
  return Buffer.from(output);
}

function readTestCompactField(payload, start) {
  let offset = start;
  let length = 0n;
  let shift = 0n;
  while (true) {
    const byte = payload[offset];
    offset += 1;
    length |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7n;
  }
  const end = offset + Number(length);
  return { value: payload.subarray(offset, end), end };
}

function encodeTestCompactField(value) {
  return Buffer.concat([encodeTestCompactLength(value.length), value]);
}

function verifyingKeyTransactionPayloadWithExtraInstruction(request) {
  const payload = verifyingKeyTransactionPayload(request, "register");
  const fields = [];
  let offset = 0;
  while (offset < payload.length) {
    const field = readTestCompactField(payload, offset);
    fields.push(field.value);
    offset = field.end;
  }
  const executable = fields[3];
  const instructionsField = readTestCompactField(executable, 4);
  const firstInstruction = readTestCompactField(
    instructionsField.value,
    8,
  ).value;
  const count = Buffer.alloc(8);
  count.writeBigUInt64LE(2n);
  const instructions = Buffer.concat([
    count,
    encodeTestCompactField(firstInstruction),
    encodeTestCompactField(firstInstruction),
  ]);
  fields[3] = Buffer.concat([
    executable.subarray(0, 4),
    encodeTestCompactField(instructions),
  ]);
  return Buffer.concat(fields.map(encodeTestCompactField));
}

function createVerifyingKeyDraftResponse(overrides = {}, options = {}) {
  return createResponse({
    status: 200,
    jsonData: sampleVerifyingKeyTransactionDraft(overrides, options),
    headers: { "content-type": "application/json" },
  });
}

function verifyingKeyCommitmentHex(backend, bytes) {
  const backendBytes = Buffer.from(backend, "utf8");
  return crypto.createHash("sha256")
    .update(Buffer.from("iroha:zk:v1:vk", "utf8"))
    .update(u64BeBuffer(backendBytes.length))
    .update(backendBytes)
    .update(u64BeBuffer(bytes.length))
    .update(bytes)
    .digest("hex");
}

function u64BeBuffer(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value));
  return buffer;
}

function bufferToBase64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

test("ToriiClient constructor enforces option shapes", () => {
  assert.throws(
    () => new SourceToriiClient(BASE_URL, "invalid"),
    /ToriiClient options must be a plain object/,
  );

  const fetchImpl = async () => createResponse({ status: 200, jsonData: {} });
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl,
        __nativeBinding: {},
      }),
    /options\.__nativeBinding is not a public option/,
  );
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl,
        sorafsGatewayFetch: "not-a-function",
      }),
    /options\.sorafsGatewayFetch is not a public option/,
  );
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl,
        generateDaProofSummary: 42,
      }),
    /options\.generateDaProofSummary is not a public option/,
  );
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl,
        sorafsAliasPolicy: 7,
      }),
    /options\.sorafsAliasPolicy is not a public option/,
  );
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl,
        onSorafsAliasWarning: "not-a-hook",
      }),
    /options\.onSorafsAliasWarning is not a public option/,
  );
});

test("ToriiClient keeps credentials and security state out of its public object shape", () => {
  const privateKey = Buffer.from(APPLICATION_CANONICAL_AUTH.privateKey);
  const expectedPrivateKey = Buffer.from(privateKey);
  const client = new SourceToriiClient(BASE_URL, {
    apiToken: "api-token-secret",
    authToken: "bearer-token-secret",
    canonicalRequestAuth: {
      accountId: APPLICATION_CANONICAL_AUTH.accountId,
      privateKey,
    },
    defaultHeaders: {
      Accept: "application/json",
      "X-Credential": "header-secret",
    },
    fetchImpl: async () => createResponse({ status: 200, jsonData: {} }),
    localSigningContext: VK_LOCAL_SIGNING_CONTEXT,
  });

  privateKey.fill(0);
  assert.deepEqual(
    SourceToriiClient._normalizePrivateKey(expectedPrivateKey),
    expectedPrivateKey,
  );
  assert.deepEqual(Object.keys(client), []);
  assert.equal(client._config, undefined);
  assert.equal(client._allowInsecure, undefined);
  assert.equal(client._canonicalRequestAuth, undefined);
  const serialized = JSON.stringify(client);
  for (const secret of [
    "api-token-secret",
    "bearer-token-secret",
    "header-secret",
    expectedPrivateKey.toString("hex"),
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("ToriiClient copies canonical-auth byte containers", () => {
  const inputs = [
    Buffer.alloc(32, 0x41),
    new Uint8Array(32).fill(0x42),
    new Uint8Array(32).fill(0x43).buffer,
  ];
  for (const input of inputs) {
    const expected = Buffer.from(
      ArrayBuffer.isView(input) ? input : new Uint8Array(input),
    );
    const normalized = SourceToriiClient._normalizePrivateKey(input);
    if (ArrayBuffer.isView(input)) {
      input.fill(0);
    } else {
      new Uint8Array(input).fill(0);
    }
    assert.deepEqual(normalized, expected);
  }
});

function createIsoSubmissionPayload(overrides = {}) {
  return {
    message_id: "iso-msg",
    status: "Accepted",
    pacs002_code: "ACSP",
    transaction_hash: null,
    profile_id: null,
    message_type: null,
    business_service: null,
    business_message_id: null,
    uetr: null,
    payload_hash: null,
    reference_snapshot_id: null,
    embedded_signature_detected: false,
    originator_participant_id: "originator-bank",
    counterparty_participant_id: "counterparty-bank",
    admitting_participant_id: "originator-bank",
    admitting_operator_key: "ed0120fixture",
    pinned_profile_id: "generic-iso20022",
    pinned_signature_policy: "record_only",
    status_history: [],
    hold_reason_code: null,
    change_reason_codes: [],
    rejection_reason_code: null,
    ledger_id: null,
    source_account_id: null,
    source_account_address: null,
    target_account_id: null,
    target_account_address: null,
    asset_definition_id: null,
    asset_id: null,
    settlement_amount: null,
    settlement_currency: null,
    settlement_date: null,
    settlement_quantity: null,
    settlement_movement_type: null,
    settlement_payment_type: null,
    security_instrument_id: null,
    collateral_obligation_id: null,
    collateral_original_amount: null,
    collateral_original_currency: null,
    collateral_original_instrument_id: null,
    collateral_substitute_amount: null,
    collateral_substitute_currency: null,
    collateral_substitute_instrument_id: null,
    collateral_effective_date: null,
    collateral_substitution_type: null,
    collateral_haircut: null,
    collateral_reason_code: null,
    plan_execution_order: null,
    plan_atomicity: null,
    ...overrides,
  };
}

function createIsoStatusPayload(overrides = {}) {
  return {
    ...createIsoSubmissionPayload(),
    detail: null,
    updated_at_ms: 1,
    ...overrides,
  };
}

function createPipelineRecoveryPayload(overrides = {}) {
  const baseTxs =
    overrides.txs ??
    [
      {
        hash: fakeHashHex(0x22),
        reads: ["World.accounts", "World.domains"],
        writes: ["World.accounts"],
      },
    ];
  return {
    format: "dag-json",
    height: 42,
    dag: {
      fingerprint: fakeHashHex(0xaa),
      key_count: 5,
      ...(overrides.dag ?? {}),
    },
    txs: baseTxs,
    ...overrides,
  };
}

function createPipelineRecoveryFastpqProofsPayload(overrides = {}) {
  const baseProofs =
    overrides.proofs ??
    [
      {
        entry_hash: fakeHashHex(0x22),
        batch_index: 0,
        parameter: "fastpq-state-transition-stark-v1",
        transition_count: 2,
        trace_commitment: fakeHashHex(0x33),
        proof_digest: fakeHashHex(0x44),
        batch: "YmF0Y2g=",
        proof: "cHJvb2Y=",
        batch_compact: false,
        batch_reconstructed_from_block: true,
      },
    ];
  return {
    height: 42,
    block_hash: fakeHashHex(0xbb),
    proofs: baseProofs,
    ...overrides,
  };
}

test("uploadAttachment posts bytes with metadata", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return createResponse({
      status: 201,
      jsonData: {
        id: "abc",
        content_type: "text/plain",
        size: 5,
        created_ms: 123,
        tenant: null,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = Buffer.from("hello");
  const meta = await client.uploadAttachment(payload, canonicalReadOptions({ content_type: "text/plain" }));
  assert.deepEqual(meta, {
    id: "abc",
    contentType: "text/plain",
    size: 5,
    createdMs: 123,
    tenant: null,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${BASE_URL}/v1/zk/attachments`);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["Content-Type"], "text/plain");
  assert.strictEqual(calls[0].init.body, payload);
});

test("uploadAttachment rejects malformed metadata responses", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 201,
        jsonData: { id: "", size: "oops" },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.uploadAttachment(Buffer.alloc(0), canonicalReadOptions({ contentType: "text/plain" })),
    /upload attachment response/,
  );
});

test("uploadAttachment rejects non-object metadata", async () => {
  let called = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      called = true;
      throw new Error("uploadAttachment should fail before fetching");
    },
  });
  await assert.rejects(
    () => client.uploadAttachment(Buffer.alloc(1), "text/plain"),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /uploadAttachment options must be a plain object/);
      return true;
    },
  );
  assert.equal(called, false);
});

test("uploadAttachment requires a non-empty content type", async () => {
  let called = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      called = true;
      throw new Error("uploadAttachment should fail before fetching");
    },
  });
  await assert.rejects(
    () => client.uploadAttachment(Buffer.from("hi"), {}),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.message, "uploadAttachment options.contentType must be a string");
      return true;
    },
  );
  await assert.rejects(
    () => client.uploadAttachment(Buffer.from("hi"), { contentType: " " }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.message, "uploadAttachment options.contentType must not be empty");
      return true;
    },
  );
  assert.equal(called, false);
});

test("uploadAttachment rejects unsupported payload types", async () => {
  let called = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      called = true;
      throw new Error("uploadAttachment should fail before fetching");
    },
  });
  await assert.rejects(
    () => client.uploadAttachment(42, { contentType: "application/octet-stream" }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /uploadAttachment data must be a string or binary payload/);
      return true;
    },
  );
  assert.equal(called, false);
});

test("uploadAttachment rejects coercible non-byte array entries", async () => {
  let called = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      called = true;
      throw new Error("uploadAttachment should fail before fetching");
    },
  });
  for (const entry of ["1", true, null]) {
    await assert.rejects(
      () =>
        client.uploadAttachment([entry], {
          contentType: "application/octet-stream",
        }),
      (error) => {
        assert(error instanceof ValidationError);
        assert.equal(error.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
        assert.equal(error.path, "payload[0]");
        return true;
      },
    );
  }
  assert.equal(called, false);
});

test("listAttachments returns attachment metadata", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: [
        {
          id: "a",
          content_type: "application/json",
          size: 10,
          created_ms: 20,
          tenant: null,
        },
        {
          id: "b",
          content_type: "text/plain",
          size: 15,
          created_ms: 25,
          tenant: "tenant-1",
        },
      ],
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listAttachments(canonicalReadOptions());
  assert.deepEqual(result, [
    {
      id: "a",
      contentType: "application/json",
      size: 10,
      createdMs: 20,
      tenant: null,
    },
    {
      id: "b",
      contentType: "text/plain",
      size: 15,
      createdMs: 25,
      tenant: "tenant-1",
    },
  ]);
});

test("listAttachments forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (_url, init) => {
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: [],
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listAttachments(canonicalReadOptions({ signal: controller.signal }));
  assert.deepEqual(result, []);
});

test("listAttachments rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200, jsonData: [] }) });
  await assert.rejects(
    () => client.listAttachments({ signal: new AbortController().signal, extra: true }),
    /listAttachments options contains unsupported fields: extra/,
  );
});

test("getAttachment validates attachmentId", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, arrayData: new ArrayBuffer(0) }),
  });
  await assert.rejects(() => client.getAttachment(""), /attachmentId/);
});

test("getAttachment returns bytes and content type", async () => {
  const data = new Uint8Array([1, 2, 3]).buffer;
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      arrayData: data,
      headers: { "content-type": "application/octet-stream" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getAttachment("att-1", canonicalReadOptions());
  assert.ok(Buffer.isBuffer(result.data));
  assert.deepEqual([...result.data.values()], [1, 2, 3]);
  assert.equal(result.contentType, "application/octet-stream");
});

test("getAttachment forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (_url, init) => {
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      arrayData: new ArrayBuffer(0),
      headers: { "content-type": "application/octet-stream" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getAttachment("att-42", canonicalReadOptions({ signal: controller.signal }));
  assert.ok(Buffer.isBuffer(result.data));
  assert.equal(result.contentType, "application/octet-stream");
});

test("getAttachment rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, arrayData: new ArrayBuffer(0) }),
  });
  await assert.rejects(
    () => client.getAttachment("att-1", { signal: new AbortController().signal, extra: "nope" }),
    /getAttachment options contains unsupported fields: extra/,
  );
});

test("deleteAttachment issues delete request", async () => {
  let called = false;
  const fetchImpl = async (url, init) => {
    called = true;
    assert.equal(init.method, "DELETE");
    assert.equal(url, `${BASE_URL}/v1/zk/attachments/att-2`);
    return createResponse({ status: 202 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.deleteAttachment("att-2", canonicalReadOptions());
  assert.ok(called);
});

test("deleteAttachment tolerates not found responses", async () => {
  const fetchImpl = async () => createResponse({ status: 404 });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.deleteAttachment("missing", canonicalReadOptions());
  await assert.rejects(() => client.deleteAttachment(""), /attachmentId/);
});

const VALID_IBAN = "GB82WEST12345698765432";

test("resolveAlias returns null on 404 and throws on 503", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const unresolved = await client.resolveAlias(VALID_IBAN);
  assert.equal(unresolved, null);

  const failingClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 503 }),
  });
  await assert.rejects(() => failingClient.resolveAlias(VALID_IBAN), /ISO bridge runtime/);
});

test("resolveAliasByIndex posts numeric payload", async () => {
  let body;
  const fetchImpl = async () => {
    return createResponse({
      status: 200,
      jsonData: { alias: VALID_IBAN, account_id: FIXTURE_ALICE_ID },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      body = JSON.parse(init.body);
      return fetchImpl(url, init);
    },
  });
  const resolved = await client.resolveAliasByIndex(0);
  assert.equal(body.index, 0);
  assert.equal(resolved?.account_id, FIXTURE_ALICE_ID);
});

test("resolveAlias parses exact payload fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: "GB82WEST12345698765432",
          account_id: FIXTURE_ALICE_ID,
          index: 5,
          source: "iso_bridge",
        },
        headers: { "content-type": "application/json" },
      }),
  });
  const resolved = await client.resolveAlias(VALID_IBAN);
  assert.deepEqual(resolved, {
    alias: VALID_IBAN,
    account_id: FIXTURE_ALICE_ID,
    index: 5,
    source: "iso_bridge",
  });
});

test("resolveAlias rejects non-canonical IBANs returned by Torii", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: "gb82 west12345698765432",
          account_id: FIXTURE_ALICE_ID,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.resolveAlias(VALID_IBAN),
    /alias resolve response\.alias must be canonical/,
  );
});

test("resolveAlias rejects coercible or unexpected response fields", async () => {
  const cases = [
    [
      "numeric string index",
      { alias: VALID_IBAN, account_id: FIXTURE_ALICE_ID, index: "5" },
      /index must be a non-negative JSON safe integer/,
    ],
    [
      "non-canonical account",
      { alias: VALID_IBAN, account_id: "alice@wonderland" },
      /account_id must not include '@domain'|account_id must be canonical/,
    ],
    [
      "unexpected field",
      { alias: VALID_IBAN, account_id: FIXTURE_ALICE_ID, ignored: true },
      /unsupported fields: ignored/,
    ],
  ];
  for (const [label, jsonData, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(() => client.resolveAlias(VALID_IBAN), pattern, label);
  }
});

test("resolveAlias normalizes IBAN input before issuing the request", async () => {
  let capturedBody;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      capturedBody = JSON.parse(init.body);
      return createResponse({
        status: 200,
        jsonData: { alias: VALID_IBAN, account_id: FIXTURE_ALICE_ID },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.resolveAlias(" gb82 west12345698765432 ");
  assert.equal(capturedBody.alias, VALID_IBAN);
});

test("resolveAlias rejects IBANs that fail checksum validation", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("resolveAlias should have rejected before fetching");
    },
  });
  await assert.rejects(
    () => client.resolveAlias("GB00WEST12345698765432"),
    /mod-97/,
  );
});

test("resolveAlias rejects malformed payloads", async () => {
  const missingAliasClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: "   ",
          account_id: FIXTURE_ALICE_ID,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => missingAliasClient.resolveAlias(VALID_IBAN),
    /alias resolve response\.alias must not be empty/,
  );

  const paddedAliasClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: ` ${VALID_IBAN}`,
          account_id: FIXTURE_ALICE_ID,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => paddedAliasClient.resolveAlias(VALID_IBAN),
    /alias resolve response\.alias must not contain surrounding whitespace/,
  );

  const paddedAccountClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: VALID_IBAN,
          account_id: ` ${FIXTURE_ALICE_ID}`,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => paddedAccountClient.resolveAlias(VALID_IBAN),
    /alias resolve response\.account_id must not contain surrounding whitespace/,
  );

  const invalidSourceClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: VALID_IBAN,
          account_id: FIXTURE_ALICE_ID,
          source: 42,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => invalidSourceClient.resolveAlias(VALID_IBAN),
    /alias resolve response\.source must be a string/,
  );

  const paddedSourceClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: VALID_IBAN,
          account_id: FIXTURE_ALICE_ID,
          source: " iso_bridge",
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => paddedSourceClient.resolveAlias(VALID_IBAN),
    /alias resolve response\.source must not contain surrounding whitespace/,
  );
});

test("resolveAlias rejects responses with invalid IBAN aliases", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          alias: "GB00WEST12345698765432",
          account_id: FIXTURE_ALICE_ID,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.resolveAlias(VALID_IBAN),
    /alias resolve response\.alias.*mod-97/,
  );
});

test("submitIsoPacs008 posts XML payload and returns submission metadata", async () => {
  let captured;
  const submissionPayload = createIsoSubmissionPayload({ message_id: "MSG123" });
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: submissionPayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const xmlPayload = "<pacs.008>ok</pacs.008>";
  const response = await client.submitIsoPacs008(xmlPayload);
  assert.equal(captured.url, `${BASE_URL}/v1/iso20022/pacs008`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["Content-Type"], "application/xml");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.ok(Buffer.isBuffer(captured.init.body));
  assert.equal(captured.init.body.toString("utf8"), xmlPayload);
  assert.deepEqual(response, submissionPayload);
});

test("submitIsoPacs008 enforces message payload", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 202 }) });
  await assert.rejects(
    () => client.submitIsoPacs008(null),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_message_required"),
  );
});

test("submitIsoPacs008 rejects invalid AbortSignal option", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        // @ts-expect-error runtime validation should reject incorrect signal
        signal: {},
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_invalid_signal"),
  );
});

test("submitIsoPacs008 rejects invalid contentType overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        // @ts-expect-error runtime validation should reject incorrect type
        contentType: {},
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_content_type_type"),
  );
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        contentType: "   ",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_content_type_empty"),
  );
});

test("submitIsoPacs008 forwards selected ISO profile query", async () => {
  let captured;
  const submissionPayload = createIsoSubmissionPayload({ message_id: "PROFILE1" });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async (_method, _url, init = {}) => {
    captured = init;
    return createResponse({
      status: 202,
      jsonData: submissionPayload,
      headers: { "content-type": "application/json" },
    });
  };
  await client.submitIsoPacs008("<xml/>", { profile: "swift-cbpr-plus" });
  assert.deepEqual(captured?.params, { profile: "swift-cbpr-plus" });
  assert.equal(captured?.headers["X-Iroha-Iso-Profile"], undefined);
  assert.equal(captured?.requireIsoOperatorAuth, true);
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        profile: " Swift-CBPR-Plus",
      }),
    /canonical lowercase profile id/u,
  );
});

test("submitIsoPacs008 rejects invalid retryProfile overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        // @ts-expect-error runtime validation should reject incorrect type
        retryProfile: 42,
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_retry_profile_type"),
  );
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        retryProfile: "   ",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_retry_profile_empty"),
  );
});

test("submitIsoPacs008 rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs008("<xml/>", {
        contentType: "application/xml",
        extra: "nope",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_unsupported_option"),
  );
});

test("submitIsoPacs009 forwards binary body, custom content type, and signal", async () => {
  let captured;
  const controller = new AbortController();
  const submissionPayload = createIsoSubmissionPayload({ message_id: "MSG777" });
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: submissionPayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const binaryPayload = new Uint8Array([0x3c, 0x70, 0x61, 0x63, 0x73, 0x2e, 0x30, 0x30, 0x39, 0x3e]);
  const response = await client.submitIsoPacs009(binaryPayload, {
    contentType: "application/pain+xml",
    signal: controller.signal,
  });
  assert.equal(captured.url, `${BASE_URL}/v1/iso20022/pacs009`);
  assert.equal(captured.init.headers["Content-Type"], "application/pain+xml");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.ok(captured.init.signal instanceof AbortSignal);
  assert.ok(Buffer.isBuffer(captured.init.body));
  assert.deepEqual([...captured.init.body.values()], [...binaryPayload.values()]);
  assert.deepEqual(response, submissionPayload);
});

test("submitIsoPacs009 enforces contentType overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs009("<xml/>", {
        // @ts-expect-error runtime validation should reject incorrect type
        contentType: 42,
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs009_content_type_type"),
  );
  await assert.rejects(
    () =>
      client.submitIsoPacs009("<xml/>", {
        contentType: "",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs009_content_type_empty"),
  );
});

test("submitIsoPacs009 rejects invalid retryProfile overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not submit");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs009("<xml/>", {
        // @ts-expect-error runtime validation should reject incorrect type
        retryProfile: {},
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs009_retry_profile_type"),
  );
  await assert.rejects(
    () =>
      client.submitIsoPacs009("<xml/>", {
        retryProfile: " ",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs009_retry_profile_empty"),
  );
});

test("getIsoMessageStatus fetches status JSON and validates input", async () => {
  let captured;
  const statusPayload = createIsoStatusPayload({
    message_id: "MSG999",
    status: "Accepted",
    transaction_hash: "abc123",
  });
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: statusPayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getIsoMessageStatus("MSG999", {
    signal: controller.signal,
  });
  assert.equal(captured.url, `${BASE_URL}/v1/iso20022/messages/MSG999`);
  assert.equal(captured.init.method, "GET");
  assert.equal(captured.init.headers.Accept, "application/json");
  assertRequestSignal(captured.init.signal, controller.signal);
  assert.deepEqual(payload, statusPayload);

  await assert.rejects(
    () => client.getIsoMessageStatus("   "),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /messageId must not be empty/);
      return true;
    },
  );
});

test("getIsoMessageStatus rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    // @ts-expect-error exercising runtime validation
    () => client.getIsoMessageStatus("msg-1", 42),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /getIsoMessageStatus\.options must be a plain object/);
      return true;
    },
  );
});

test("getIsoMessageStatus rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () => client.getIsoMessageStatus("msg-1", { extra: true }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        /getIsoMessageStatus\.options contains unsupported fields: extra/,
      );
      return true;
    },
  );
});

test("getIsoMessageStatus normalizes ISO bridge status and pacs002 code", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "iso-normalize",
        status: "pending",
        pacs002_code: "pdng",
      }),
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getIsoMessageStatus("iso-normalize");
  assert.equal(payload?.status, "Pending");
  assert.equal(payload?.pacs002_code, "PDNG");
  assert.equal(payload?.originator_participant_id, "originator-bank");
  assert.equal(payload?.counterparty_participant_id, "counterparty-bank");
  assert.equal(payload?.admitting_participant_id, "originator-bank");
  assert.equal(payload?.admitting_operator_key, "ed0120fixture");
  assert.equal(payload?.pinned_profile_id, "generic-iso20022");
  assert.equal(payload?.pinned_signature_policy, "record_only");
});

test("getIsoMessageStatus rejects unknown ISO status values and pacs002 codes", async () => {
  const badStatusClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: createIsoStatusPayload({ status: "unknown-status" }),
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => badStatusClient.getIsoMessageStatus("iso-bad-status"),
    /must be one of Pending, Accepted, Rejected, Committed/,
  );

  const badPacsClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: createIsoStatusPayload({ pacs002_code: "xxxx" }),
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => badPacsClient.getIsoMessageStatus("iso-bad-pacs"),
    /pacs002_code must be one of ACTC, ACSP, ACSC, ACWC, PDNG, RJCT/,
  );
});

// The native evaluator checks untrusted-signer proof integrity and freshness;
// these results make no assertion about trusted council or manifest authority.
test("native alias evaluator retains fresh proof classification and timestamps", () => {
  const native = requireSorafsNative();
  const policy = native.sorafsAliasPolicyDefaults();
  const now = 1_750_000_000;
  const fixture = native.sorafsAliasProofFixture({
    manifestCidHex: CANONICAL_ALIAS_MANIFEST_CID_HEX,
    generatedAtUnix: now - 60,
    expiresAtUnix: now + 600,
  });
  const result = native.sorafsEvaluateAliasProof(fixture.proofB64, policy, now);
  assert.equal(result.state, "fresh");
  assert.equal(result.statusLabel, "fresh");
  assert.equal(result.servable, true);
  assert.equal(result.ageSeconds, 60);
  assert.equal(result.generatedAtUnix, now - 60);
  assert.equal(result.expiresAtUnix, now + 600);
  assert.equal(result.expiresInSeconds, 600);
  assert.equal(result.rotationDue, 60 >= policy.rotationMaxAgeSecs);
});

test("native alias evaluator rejects stale and hard-expired proof freshness", () => {
  const native = requireSorafsNative();
  const policy = native.sorafsAliasPolicyDefaults();
  const now = 1_750_000_000;
  for (const [age, expiry, state, label] of [
    [policy.positiveTtlSecs, now + 600, "expired", "expired"],
    [policy.hardExpirySecs, now + 600, "hard_expired", "hard-expired"],
    [10_000, now - 1, "hard_expired", "hard-expired"],
  ]) {
    const fixture = native.sorafsAliasProofFixture({
      manifestCidHex: CANONICAL_ALIAS_MANIFEST_CID_HEX,
      generatedAtUnix: now - age,
      expiresAtUnix: expiry,
    });
    const result = native.sorafsEvaluateAliasProof(fixture.proofB64, policy, now);
    assert.equal(result.state, state);
    assert.equal(result.statusLabel, label);
    assert.equal(result.servable, false);
    assert.equal(result.ageSeconds, age);
    assert.equal(result.generatedAtUnix, now - age);
    assert.equal(result.expiresAtUnix, expiry);
    assert.equal(result.expiresInSeconds ?? null, expiry < now ? null : 600);
    assert.equal(result.rotationDue, age >= policy.rotationMaxAgeSecs);
  }
});

test("native alias evaluator retains refresh-window and rotation classification", () => {
  const native = requireSorafsNative();
  const policy = native.sorafsAliasPolicyDefaults();
  const now = 1_750_000_000;
  const age = policy.positiveTtlSecs - policy.refreshWindowSecs + 10;
  const fixture = native.sorafsAliasProofFixture({
    manifestCidHex: CANONICAL_ALIAS_MANIFEST_CID_HEX,
    generatedAtUnix: now - age,
    expiresAtUnix: now + 600,
  });
  const result = native.sorafsEvaluateAliasProof(fixture.proofB64, policy, now);
  assert.equal(result.state, "refresh_window");
  assert.equal(result.servable, true);
  assert.equal(result.ageSeconds, age);
  assert.equal(result.generatedAtUnix, now - age);
  assert.equal(result.expiresAtUnix, now + 600);
  assert.equal(result.expiresInSeconds, 600);
  assert.equal(result.rotationDue, age >= policy.rotationMaxAgeSecs);
  const rotation = native.sorafsEvaluateAliasProof(fixture.proofB64, {
    ...policy, rotationMaxAgeSecs: age,
  }, now);
  assert.equal(rotation.state, "refresh_window");
  assert.equal(rotation.statusLabel, "refresh-rotate");
  assert.equal(rotation.rotationDue, true);
  assert.equal(rotation.servable, true);
});

test("getSorafsPinManifest returns null and cancels unread 404 bodies", async () => {
  let cancelled = 0, reads = 0;
  const response = {
    status: 404, headers: new Headers({ "content-type": "application/json" }),
    body: {
      cancel() { cancelled++; },
      getReader() { reads++; throw new Error("404 body must stay unread"); },
    },
    json() { reads++; throw new Error("404 body must stay unread"); },
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => response });
  assert.equal(await client.getSorafsPinManifest("deadbeef".repeat(8)), null);
  assert.equal(cancelled, 1);
  assert.equal(reads, 0);
});

test("getSorafsPinManifestTyped rejects and cancels unread 404 bodies", async () => {
  let cancelled = 0, reads = 0;
  const response = {
    status: 404, headers: new Headers({ "content-type": "application/json" }),
    body: {
      cancel() { cancelled++; },
      getReader() { reads++; throw new Error("404 body must stay unread"); },
    },
    json() { reads++; throw new Error("404 body must stay unread"); },
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => response });
  await assert.rejects(
    () => client.getSorafsPinManifestTyped("deadbeef".repeat(8)),
    /sorafs pin manifest endpoint returned 404/,
  );
  assert.equal(cancelled, 1);
  assert.equal(reads, 0);
});

test("registerSorafsPinManifest posts only an exact canonical V1 transaction", async () => {
  const signedTransaction = Buffer.from([0x01, 0xde, 0xad, 0xbe, 0xef]);
  const admission = {
    status: "submitted",
    tx_hash_hex: "d".repeat(64),
    manifest_digest_hex: "b".repeat(64),
  };
  let captured = null;
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: validNodeCapabilitiesPayload(),
        headers: { "content-type": "application/json" },
      });
    }
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: admission,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  const result = await client.registerSorafsPinManifestTyped(signedTransaction);

  assert.equal(captured?.url, `${BASE_URL}/v1/sorafs/pin/register`);
  assert.equal(captured?.init?.method, "POST");
  assert.equal(captured?.init?.redirect, "error");
  assert.equal(captured?.init?.headers["Content-Type"], "application/x-norito");
  assert.equal(captured?.init?.headers.Accept, "application/json");
  assert.deepEqual(captured?.init?.body, signedTransaction);
  assert.deepEqual(result, admission);
});

test("registerSorafsPinManifest rejects an unmarked transaction hash", async () => {
  const fetchImpl = async (url) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: validNodeCapabilitiesPayload(),
        headers: { "content-type": "application/json" },
      });
    }
    return createResponse({
      status: 202,
      jsonData: {
        status: "submitted",
        tx_hash_hex: "a".repeat(64),
        manifest_digest_hex: "b".repeat(64),
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.registerSorafsPinManifestTyped(Buffer.from([0x01, 0xaa])),
    /canonical Iroha hash marker/u,
  );
});

test("registerSorafsPinManifest rejects missing or noncanonical V1 codecs before fetch", async () => {
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("invalid pin registration must fail before fetch");
  };
  const withoutCodec = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: {},
  });
  await assert.rejects(
    () => withoutCodec.registerSorafsPinManifest(Buffer.from([0x01, 0xaa])),
    /requires native encodeSignedTransactionVersioned/,
  );

  const framed = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => framed.registerSorafsPinManifest(Buffer.from("NRT0legacy", "ascii")),
    /test payload is not VersionedSignedTransaction V1/,
  );
  assert.equal(fetchCalls, 0);
});

test("registerSorafsPinManifest rejects legacy secret-bearing request objects", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    },
    [TORII_TEST_NATIVE_BINDING]: {},
  });

  await assert.rejects(
    () =>
      client.registerSorafsPinManifest({
        authority: FIXTURE_ALICE_ID,
        private_key: "[redacted]",
        manifest_payload: "bWFuaWZlc3Q=",
        submitted_epoch: 1,
      }),
    /signedTransaction must be a Buffer, ArrayBuffer, or ArrayBuffer view/,
  );
  assert.equal(fetchCalls, 0);
});

test("registerSorafsPinManifestTyped rejects pre-finality fee or custody claims", async () => {
  const fetchImpl = async (url) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: validNodeCapabilitiesPayload(),
        headers: { "content-type": "application/json" },
      });
    }
    return createResponse({
      status: 202,
      jsonData: {
        status: "submitted",
        tx_hash_hex: "d".repeat(64),
        manifest_digest_hex: "b".repeat(64),
        pin_fee: "1",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.registerSorafsPinManifestTyped(Buffer.from([0x01, 0xaa])),
    /unsupported fields.*pin_fee/i,
  );
});

test("getSorafsPinManifestTyped returns the exact finalized native record", async () => {
  const payload = sorafsPinDetailFixture(FIXTURE_CAROL_ID);
  payload.manifest.pin_fee_payment = { paid_by: FIXTURE_ALICE_ID, fee_asset_id: FIXTURE_ASSET_ID_A, treasury_account_id: FIXTURE_BOB_ID, amount: "12.5" };
  payload.manifest.metadata = { note: "demo", fractional: 1.25, nested: [{ score: 1.5 }] };
  const requests = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      requests.push({ url: String(url), init });
      return createResponse({ status: 200, jsonData: payload });
    },
  });
  const options = { expectedFinalizedHeight: 51n, expectedFinalizedBlockHashHex: "42".repeat(32), headers: { "X-Read": "detail" } };
  const detail = await client.getSorafsPinManifestTyped("ee".repeat(32), options);
  assert.deepEqual(detail, typedSorafsPinDetailFixture(payload));
  const url = new URL(requests[0].url);
  assert.equal(url.pathname, "/v1/sorafs/pin/" + "ee".repeat(32));
  assert.deepEqual(Object.fromEntries(url.searchParams), { expected_finalized_height: "51", expected_finalized_block_hash_hex: "42".repeat(32) });
  assert.equal(requests[0].init.headers["X-Read"], "detail");
  const raw = await client.getSorafsPinManifest("ee".repeat(32));
  assert.equal(JSON.stringify(raw), JSON.stringify(payload));
  assert.ok(Array.isArray(raw.manifest.digest));
});

test("getSorafsPinManifest preserves full-u64 numeric tokens and finalized request height", async () => {
  const maximum = (1n << 64n) - 1n;
  const payload = sorafsPinDetailFixture(FIXTURE_CAROL_ID);
  payload.finalized_cursor.height = maximum;
  payload.manifest.content_length = maximum;
  const textBody = JSON.stringify(payload, (_, item) => typeof item === "bigint" ? "__u64__" : item).replaceAll('"__u64__"', String(maximum));
  let request;
  const client = new ToriiClient(BASE_URL, { fetchImpl: async (url) => {
    request = new URL(url);
    return createResponse({ status: 200, textBody, headers: { "content-type": "application/json" } });
  } });
  const detail = await client.getSorafsPinManifestTyped("ee".repeat(32), { expectedFinalizedHeight: maximum, expectedFinalizedBlockHashHex: "42".repeat(32) });
  assert.deepEqual(detail, typedSorafsPinDetailFixture(payload));
  assert.equal(request.searchParams.get("expected_finalized_height"), String(maximum));
});

test("getSorafsPinManifest rejects malformed native records and lexical numeric aliases", async () => {
  const canonical = JSON.stringify(sorafsPinDetailFixture(FIXTURE_CAROL_ID));
  for (const textBody of [
    canonical.replace('"height":51', '"height":51,"height":51'),
    canonical.replace('"height":51', '"height":51,"\\u0068eight":51'),
    canonical.replace('"height":51', '"height":51.0'),
    canonical.replace('"value":45', '"value":4.5e1'),
    canonical.replace('"submitted_epoch":42', '"submitted_epoch":42.5'),
    canonical.replace('"submitted_epoch":42', '"submitted_epoch":"42"'),
    canonical.replace('"content_length":4096', '"content_length":18446744073709551616'),
    canonical.replace('"manifest":{', '"aliases":[],"manifest":{'),
  ]) {
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200, textBody, headers: { "content-type": "application/json" } }) });
    await assert.rejects(() => client.getSorafsPinManifestTyped("ee".repeat(32)), /duplicate|required|unknown|integer|bound|canonical/);
  }
});

test("getSorafsPinManifest rejects digest and cursor mismatches in both public readers", async () => {
  for (const method of ["getSorafsPinManifest", "getSorafsPinManifestTyped"]) {
    for (const [digest, options] of [["ff".repeat(32), {}], ["ee".repeat(32), { expectedFinalizedHeight: 52, expectedFinalizedBlockHashHex: "42".repeat(32) }], ["ee".repeat(32), { expectedFinalizedHeight: 51, expectedFinalizedBlockHashHex: "43".repeat(32) }]]) {
      const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200, jsonData: sorafsPinDetailFixture(FIXTURE_CAROL_ID) }) });
      await assert.rejects(() => client[method](digest, options), /differs/);
    }
  }
});

test("getSorafsPinManifest rejects unbounded, non-JSON, and invalid UTF-8 transport", async () => {
  const payload = sorafsPinDetailFixture(FIXTURE_CAROL_ID);
  for (const response of [
    createResponse({ status: 200, jsonData: payload, headers: { "content-type": "text/plain" } }),
    createResponse({ status: 200, jsonData: payload, headers: { "content-type": "application/json", "content-length": String(64 * 1024 * 1024 + 1) } }),
    createResponse({ status: 200, arrayData: new Uint8Array([0xff]), headers: { "content-type": "application/json" } }),
  ]) {
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => response });
    await assert.rejects(() => client.getSorafsPinManifest("ee".repeat(32)), /media type|limit|exceed|UTF-8/);
  }
});

test("ToriiClient rejects retired alias-header policy options for every value", () => {
  for (const field of ["sorafsAliasPolicy", "onSorafsAliasWarning"]) {
    for (const value of [undefined, null, {}, () => {}]) {
      assert.throws(() => new ToriiClient(BASE_URL, { fetchImpl: async () => {}, [field]: value }), /is not a public option/);
    }
  }
});

test("getSorafsPinManifest rejects noncanonical request inputs before transport", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => { calls++; throw new Error("unexpected transport"); } });
  for (const digest of ["deadbeef", "00".repeat(32), "EE".repeat(32), "0x" + "ee".repeat(32)]) await assert.rejects(() => client.getSorafsPinManifest(digest));
  for (const options of [
    { expectedFinalizedHeight: 51 }, { expectedFinalizedBlockHashHex: "42".repeat(32) }, { extra: true },
    ...[0, -0, -1, null, "51", 51.5, Number.MAX_SAFE_INTEGER + 1, 1n << 64n].map(expectedFinalizedHeight => ({ expectedFinalizedHeight, expectedFinalizedBlockHashHex: "42".repeat(32) })),
    ...[null, "00".repeat(32), "AB".repeat(32), "abcd"].map(expectedFinalizedBlockHashHex => ({ expectedFinalizedHeight: 51, expectedFinalizedBlockHashHex })),
  ]) await assert.rejects(() => client.getSorafsPinManifest("ee".repeat(32), options));
  assert.equal(calls, 0);
});

test("listSorafsAliases signs, normalizes response, and applies filters", async () => {
  let captured;
  const manifestHex = "a".repeat(64);
  const aliasRecord = sorafsAliasProjectionFixture(FIXTURE_ALICE_ID, manifestHex);
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: {
        attestation: sorafsAliasAttestationFixture(),
        total_count: 1,
        returned_count: 1,
        offset: 0,
        limit: 50,
        aliases: [aliasRecord],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listSorafsAliases({
    namespace: "Sora",
    manifestDigestHex: `0x${manifestHex}`,
    limit: "5",
    offset: 10n,
    canonicalAuth: SORAFS_CANONICAL_AUTH,
  });
  assert.ok(captured?.url?.startsWith(`${BASE_URL}/v1/sorafs/aliases`));
  assert.equal(captured?.init?.headers?.["X-Iroha-Account"], CANONICAL_AUTH_ALIAS);
  assert.ok(captured?.init?.headers?.["X-Iroha-Signature"]);
  const parsed = new URL(captured.url);
  assert.equal(parsed.searchParams.get("namespace"), "Sora");
  assert.equal(parsed.searchParams.get("manifest_digest"), manifestHex);
  assert.equal(parsed.searchParams.get("limit"), "5");
  assert.equal(parsed.searchParams.get("offset"), "10");
  assert.equal(result.aliases.length, 1);
  assert.equal(result.aliases[0].alias, aliasRecord.alias);
  assert.equal(result.aliases[0].cache_state, "fresh");
  assert.deepEqual(result.aliases[0].cache_reasons, aliasRecord.cache_reasons);
  assert.equal(result.attestation?.block_height, 1);
});

test("listSorafsPinManifests enforces the finalized bounded keyset contract", async () => {
  let capturedUrl;
  const manifestDigest = Array(32).fill(0xee);
  const parentDigest = Array(32).fill(0xdd);
  const blockHash = Array(32).fill(0x99);
  const summary = {
    digest: manifestDigest,
    submitted_by: FIXTURE_CAROL_ID,
    submitted_epoch: 42,
    approved_epoch: 45,
    content_length: 4096,
    retention_epoch: 900,
    status: { status: "Approved", value: 45 },
    successor_of: parentDigest,
  };
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: {
        finalized_cursor: { height: 7, block_hash: blockHash },
        charged_usage: { manifest_count: 3, content_bytes: 8192 },
        manifests: [summary],
        has_more: false,
        next_after_digest: null,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listSorafsPinManifests({
    status: "approved",
    limit: "10",
    maxBytes: 2048,
    afterDigestHex: "0".repeat(63) + "1",
    expectedFinalizedHeight: 7,
    expectedFinalizedBlockHashHex: "99".repeat(32),
  });
  assert.ok(capturedUrl?.startsWith(`${BASE_URL}/v1/sorafs/pin`));
  const parsed = new URL(capturedUrl);
  assert.equal(parsed.searchParams.get("status"), "approved");
  assert.equal(parsed.searchParams.get("limit"), "10");
  assert.equal(parsed.searchParams.get("max_bytes"), "2048");
  assert.equal(parsed.searchParams.get("after_digest_hex"), "0".repeat(63) + "1");
  assert.equal(parsed.searchParams.get("expected_finalized_height"), "7");
  assert.equal(
    parsed.searchParams.get("expected_finalized_block_hash_hex"),
    "99".repeat(32),
  );
  assert.equal(parsed.searchParams.has("offset"), false);
  assert.equal(result.finalized_cursor.height, 7);
  assert.deepEqual([...result.finalized_cursor.block_hash], blockHash);
  assert.deepEqual(result.charged_usage, {
    manifest_count: 3,
    content_bytes: 8192,
  });
  assert.equal(result.manifests.length, 1);
  const manifest = result.manifests[0];
  assert.deepEqual([...manifest.digest], manifestDigest);
  assert.equal(manifest.approved_epoch, 45);
  assert.deepEqual(manifest.status, { status: "Approved", value: 45 });
  assert.deepEqual([...manifest.successor_of], parentDigest);
  assert.equal("alias" in manifest, false);
  assert.equal("metadata" in manifest, false);
  assert.equal("lineage" in manifest, false);
  assert.equal(result.has_more, false);
  assert.equal(result.next_after_digest, null);
  await assert.rejects(
    () => client.listSorafsPinManifests({ status: "APPROVED" }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.path, "sorafsPinList.status");
      assert.match(error.message, /sorafsPinList\.status/);
      return true;
    },
  );
  await assert.rejects(
    () => client.listSorafsPinManifests({ expectedFinalizedHeight: 7 }),
    /must be supplied together/,
  );
  await assert.rejects(
    () => client.listSorafsPinManifests({ offset: 0 }),
    /unsupported fields: offset/,
  );
  await assert.rejects(
    () => client.listSorafsPinManifests({ limit: 257 }),
    /at most 256/,
  );
  await assert.rejects(
    () => client.listSorafsPinManifests({ maxBytes: 1023 }),
    /at least 1024/,
  );
});

test("listSorafsPinManifests rejects retired shapes and forged page cursors", async () => {
  const digest = Array(32).fill(0x44);
  const basePage = {
    finalized_cursor: { height: 9, block_hash: Array(32).fill(0x55) },
    charged_usage: { manifest_count: 1, content_bytes: 7 },
    manifests: [
      {
        digest,
        submitted_by: FIXTURE_CAROL_ID,
        submitted_epoch: 1,
        approved_epoch: null,
        content_length: 7,
        retention_epoch: 10,
        status: { status: "Pending", value: null },
        successor_of: null,
      },
    ],
    has_more: true,
    next_after_digest: digest,
  };
  let payload = basePage;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
  });

  payload = { ...basePage, attestation: { block_height: 9 } };
  await assert.rejects(
    () => client.listSorafsPinManifests(),
    /contains unknown field attestation/,
  );
  payload = {
    ...basePage,
    manifests: [{ ...basePage.manifests[0], alias: { proof: "retired" } }],
  };
  await assert.rejects(
    () => client.listSorafsPinManifests(),
    /manifests\[0\] contains unknown field alias/,
  );
  payload = { ...basePage, next_after_digest: Array(32).fill(0x45) };
  await assert.rejects(
    () => client.listSorafsPinManifests(),
    /must equal the last returned digest/,
  );
  payload = { ...basePage, has_more: false, next_after_digest: digest };
  await assert.rejects(
    () => client.listSorafsPinManifests(),
    /has_more must agree/,
  );
  payload = {
    ...basePage,
    manifests: [
      { ...basePage.manifests[0], digest: Array(32).fill(0x45) },
      basePage.manifests[0],
    ],
    next_after_digest: digest,
  };
  await assert.rejects(
    () => client.listSorafsPinManifests(),
    /strictly digest-ordered/,
  );
});

test("pin-list readback preserves full-u64 epochs and resource counters", async () => {
  const maximum = (1n << 64n) - 1n;
  const page = {
    finalized_cursor: { height: maximum, block_hash: Array(32).fill(0x42) },
    charged_usage: { manifest_count: maximum, content_bytes: maximum },
    manifests: [{ digest: Array(32).fill(0x44), submitted_by: FIXTURE_CAROL_ID,
      submitted_epoch: maximum - 2n, approved_epoch: maximum - 1n,
      content_length: maximum, retention_epoch: maximum,
      status: { status: "Approved", value: maximum - 1n }, successor_of: null }],
    has_more: false, next_after_digest: null,
  };
  let url;
  const client = new ToriiClient(BASE_URL, { fetchImpl: async (request) => {
    url = new URL(request);
    return createResponse({ status: 200, textBody: stringifyStrictLosslessIntegerJson(page, "pin page"), headers: { "content-type": "application/json" } });
  } });
  const result = await client.listSorafsPinManifests({ expectedFinalizedHeight: maximum, expectedFinalizedBlockHashHex: "42".repeat(32) });
  assert.equal(url.searchParams.get("expected_finalized_height"), String(maximum));
  assert.equal(result.finalized_cursor.height, maximum);
  assert.deepEqual(result.charged_usage, page.charged_usage);
  assert.deepEqual(result.manifests[0], { ...page.manifests[0], digest: Uint8Array.from(page.manifests[0].digest) });
});

test("pin-list typed fields reject numeric token aliases and omitted required nullable fields", async () => {
  const page = {
    finalized_cursor: { height: 51, block_hash: Array(32).fill(0x42) },
    charged_usage: { manifest_count: 1, content_bytes: 10 },
    manifests: [{ digest: Array(32).fill(0x44), submitted_by: FIXTURE_CAROL_ID,
      submitted_epoch: 1, approved_epoch: 2, content_length: 10, retention_epoch: 20,
      status: { status: "Approved", value: 2 }, successor_of: null }],
    has_more: false, next_after_digest: null,
  };
  const paths = [["finalized_cursor", "height"], ["charged_usage", "manifest_count"], ["charged_usage", "content_bytes"],
    ...["submitted_epoch", "approved_epoch", "content_length", "retention_epoch"].map(key => ["manifests", 0, key]), ["manifests", 0, "status", "value"]];
  const read = async (textBody) => {
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200, textBody, headers: { "content-type": "application/json" } }) });
    return client.listSorafsPinManifests();
  };
  for (const path of paths) {
    for (const token of ["1.0", "1e0", "-0", '"1"', "18446744073709551616"]) {
      const value = structuredClone(page);
      const parent = path.slice(0, -1).reduce((node, key) => node[key], value);
      parent[path.at(-1)] = "__token__";
      await assert.rejects(() => read(JSON.stringify(value).replace('"__token__"', token)), /integer|bound|canonical/);
    }
  }
  for (const [container, field] of [[page, "next_after_digest"], [page.manifests[0], "approved_epoch"], [page.manifests[0], "successor_of"]]) {
    const saved = container[field]; delete container[field];
    await assert.rejects(() => read(JSON.stringify(page)), /required field/);
    container[field] = saved;
  }
  await assert.rejects(() => read(JSON.stringify(page).replace('"height":51', '"height":51,"height":51')), /duplicate/);
  await assert.rejects(() => read(JSON.stringify({ ...page, manifests: [{ ...page.manifests[0], submitted_by: ` ${FIXTURE_CAROL_ID} ` }] })), /canonical|account|identity/);
  const overDefaultLimit = { ...page, charged_usage: { manifest_count: 51, content_bytes: 510 },
    manifests: Array.from({ length: 51 }, (_, index) => ({ ...page.manifests[0], digest: Array(32).fill(index + 1) })) };
  await assert.rejects(() => read(JSON.stringify(overDefaultLimit)), /requested limit/);
});

test("listSorafsReplicationOrders signs, normalizes response, and validates status filter", async () => {
  let captured;
  const orderRecord = sorafsReplicationProjectionFixture(FIXTURE_BOB_ID);
  const manifestHex = orderRecord.manifest_digest_hex;
  const orderHex = orderRecord.order_id_hex;
  const providerHex = orderRecord.providers[0];
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: {
        attestation: sorafsReplicationAttestationFixture(),
        total_count: 1,
        returned_count: 1,
        offset: 0,
        limit: 20,
        replication_orders: [orderRecord],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listSorafsReplicationOrders({
    status: "pending",
    manifestDigestHex: manifestHex,
    limit: 20,
    canonicalAuth: SORAFS_CANONICAL_AUTH,
  });
  assert.ok(captured?.url?.startsWith(`${BASE_URL}/v1/sorafs/replication`));
  assert.equal(captured?.init?.headers?.["X-Iroha-Account"], CANONICAL_AUTH_ALIAS);
  assert.ok(captured?.init?.headers?.["X-Iroha-Signature"]);
  const parsed = new URL(captured.url);
  assert.equal(parsed.searchParams.get("status"), "pending");
  assert.equal(parsed.searchParams.get("manifest_digest"), manifestHex);
  assert.equal(parsed.searchParams.get("limit"), "20");
  assert.equal(result.replication_orders[0].order_id_hex, orderHex);
  assert.equal(result.replication_orders[0].provider_completions[0].provider_hex, providerHex);
  assert.deepEqual(result.replication_orders[0], orderRecord);
  await assert.rejects(
    () => client.listSorafsReplicationOrders({
      status: "finished",
      canonicalAuth: SORAFS_CANONICAL_AUTH,
    }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.path, "sorafsReplicationList.status");
      assert.match(error.message, /sorafsReplicationList\.status/i);
      return true;
    },
  );
});

test("replication request filters retain exact cancelled spelling and native query bounds", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, { fetchImpl: async (url) => {
    calls++;
    assert.equal(new URL(url).searchParams.get("status"), "cancelled");
    const row = sorafsReplicationProjectionFixture(FIXTURE_BOB_ID);
    row.status = { state: "cancelled", epoch: row.issued_epoch + 20 };
    return createResponse({ status: 200, jsonData: { attestation: sorafsReplicationAttestationFixture(), total_count: 1, returned_count: 1, offset: 0, limit: 500, replication_orders: [row] } });
  } });
  const page = await client.listSorafsReplicationOrders({ status: "cancelled", limit: 500, canonicalAuth: SORAFS_CANONICAL_AUTH });
  assert.equal(page.replication_orders[0].status.state, "cancelled");
  for (const options of [{ status: "Cancelled" }, { status: " cancelled " }, { status: null }, { limit: 501 }, { limit: "5" }, { offset: 2 ** 32 }, { offset: "1" }, { manifestDigestHex: "00".repeat(32) }, { manifestDigestHex: "AA".repeat(32) }]) {
    await assert.rejects(() => client.listSorafsReplicationOrders({ ...options, canonicalAuth: SORAFS_CANONICAL_AUTH }));
  }
  assert.equal(calls, 1);
});

test("SoraFS reputation helpers fetch REST and SSE endpoints", async () => {
  const snapshotIdHex = "ab".repeat(16);
  const merkleRootHex = "cd".repeat(32);
  const providerId = "provider:alpha";
  const reputationWeights = {
    version: 1,
    por_success_bps: 2200,
    pdp_success_bps: 2000,
    potr_success_bps: 1800,
    latency_bps: 1500,
    dispute_bps: 1000,
    token_violation_bps: 500,
    repair_breach_bps: 1000,
  };
  const providerRecord = {
    provider_id: providerId,
    score_bps: 9800,
    degradation_flags: [],
    raw_metrics: {
      version: 1,
      por_success_bps: 9900,
      pdp_success_bps: 9800,
      potr_success_bps: 9700,
      latency_health_bps: 9600,
      dispute_rate_bps: 100,
      token_violation_rate_bps: 0,
      repair_breach_rate_bps: 0,
    },
    raw_metrics_hash_hex: "ef".repeat(32),
  };
  const snapshotEvent = {
    version: 1,
    sequence: 8,
    snapshot_id_hex: snapshotIdHex,
    generated_at_unix: 1_800_000_000,
    merkle_root_hex: merkleRootHex,
    provider_count: 1,
    previous_snapshot_id_hex: null,
  };
  const privateKey = Buffer.alloc(32, 29);
  const privateKeyObject = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      privateKey,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = Buffer.from(
    crypto
      .createPublicKey(privateKeyObject)
      .export({ format: "der", type: "spki" }),
  ).subarray(-32);
  const canonicalAuth = {
    accountId: "reputation-reader@sora",
    privateKey,
  };
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url.includes("/v1/sorafs/reputation/events/stream")) {
      return createSseResponse([
        "id: 8\n",
        "event: reputation_snapshot\n",
        `data: ${JSON.stringify(snapshotEvent)}\n`,
        "\n",
      ]);
    }
    if (url.includes("/v1/sorafs/reputation/latest")) {
      return createResponse({
        status: 200,
        jsonData: {
          snapshot_id_hex: snapshotIdHex,
          generated_at_unix: 1_800_000_000,
          previous_snapshot_id_hex: null,
          merkle_root_hex: merkleRootHex,
          provider_count: 1,
          returned_provider_count: 1,
          limit: 50,
          truncated_providers: false,
          alpha_bps: 8500,
          current_score_weight_bps: 7000,
          weights: reputationWeights,
          providers: [providerRecord],
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/reputation/providers/")) {
      return createResponse({
        status: 200,
        jsonData: {
          snapshot_id_hex: snapshotIdHex,
          generated_at_unix: 1_800_000_000,
          merkle_root_hex: merkleRootHex,
          provider: providerRecord,
          proof: {
            provider_id: providerId,
            leaf_index: 0,
            leaf_count: 1,
            siblings_hex: [],
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/reputation/snapshots/")) {
      return createResponse({ status: 304, headers: {} });
    }
    if (url.includes("/v1/sorafs/reputation/weights")) {
      return createResponse({
        status: 200,
        jsonData: {
          snapshot_id_hex: snapshotIdHex,
          generated_at_unix: 1_800_000_000,
          alpha_bps: 8500,
          current_score_weight_bps: 7000,
          weights: reputationWeights,
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/reputation/events")) {
      return createResponse({
        status: 200,
        jsonData: {
          since: 0,
          limit: 2,
          count: 1,
          next_since: 8,
          events: [snapshotEvent],
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected URL: ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });

  const latest = await client.getSorafsReputationLatest({
    canonicalAuth,
    ifNoneMatch: '"old"',
  });
  assert.equal(latest?.snapshot_id_hex, snapshotIdHex);
  assert.equal(calls[0]?.url, `${BASE_URL}/v1/sorafs/reputation/latest`);
  assert.equal(calls[0]?.init?.headers?.["If-None-Match"], '"old"');

  const provider = await client.getSorafsReputationProvider(providerId, {
    canonicalAuth,
  });
  assert.equal(provider?.provider?.provider_id, providerId);
  assert.equal(
    calls[1]?.url,
    `${BASE_URL}/v1/sorafs/reputation/providers/${providerId}`,
  );

  const snapshot = await client.getSorafsReputationSnapshot(snapshotIdHex, {
    canonicalAuth,
    ifNoneMatch: '"snapshot-etag"',
  });
  assert.equal(snapshot, null);
  assert.equal(
    calls[2]?.url,
    `${BASE_URL}/v1/sorafs/reputation/snapshots/${snapshotIdHex}`,
  );
  assert.equal(calls[2]?.init?.headers?.["If-None-Match"], '"snapshot-etag"');

  const weights = await client.getSorafsReputationWeights({ canonicalAuth });
  assert.equal(weights?.current_score_weight_bps, 7000);

  const events = await client.listSorafsReputationEvents({
    canonicalAuth,
    since: 0,
    limit: "2",
    ifNoneMatch: '"events-etag"',
  });
  assert.equal(events?.count, 1);
  const eventsUrl = new URL(calls[4]?.url);
  assert.equal(eventsUrl.searchParams.get("since"), "0");
  assert.equal(eventsUrl.searchParams.get("limit"), "2");
  assert.equal(calls[4]?.init?.headers?.["If-None-Match"], '"events-etag"');
  assert.equal(calls[4]?.init?.redirect, "error");
  const eventHeaders = calls[4]?.init?.headers;
  const eventMessage = canonicalRequestSignatureMessage({
    networkId: VK_SIGNING_NETWORK_ID,
    method: "GET",
    path: eventsUrl.pathname,
    query: eventsUrl.search.slice(1),
    body: Buffer.alloc(0),
    timestampMs: Number(eventHeaders?.["X-Iroha-Timestamp-Ms"]),
    nonce: eventHeaders?.["X-Iroha-Nonce"],
  });
  assert.equal(
    verifyEd25519(
      eventMessage,
      Buffer.from(eventHeaders?.["X-Iroha-Signature"], "base64"),
      publicKey,
    ),
    true,
  );

  const iterator = client.streamSorafsReputationEvents({
    canonicalAuth,
    since: 7,
    limit: 1,
  });
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.equal(first.value.event, "reputation_snapshot");
  assert.deepEqual(first.value.data, snapshotEvent);
  const streamUrl = new URL(calls[5]?.url);
  assert.equal(streamUrl.pathname, "/v1/sorafs/reputation/events/stream");
  assert.equal(streamUrl.searchParams.get("since"), "7");
  assert.equal(streamUrl.searchParams.get("limit"), "1");
  assert.equal(calls[5]?.init?.headers?.["Last-Event-ID"], undefined);
  assert.equal(calls[5]?.init?.headers?.Accept, "text/event-stream");
  assert.equal(
    typeof calls[5]?.init?.headers?.["X-Iroha-Signature"],
    "string",
  );
});

test("SoraFS reputation helpers preserve exact u64 values in REST and SSE", async () => {
  const snapshotIdHex = "ab".repeat(16);
  const merkleRootHex = "cd".repeat(32);
  const providerId = "provider:alpha";
  const maxU64 = "18446744073709551615";
  const maxU64Value = 18_446_744_073_709_551_615n;
  const witness = Buffer.from("canonical-witness", "utf8").toString("base64");
  const weights = {
    version: 1,
    por_success_bps: 2200,
    pdp_success_bps: 2000,
    potr_success_bps: 1800,
    latency_bps: 1500,
    dispute_bps: 1000,
    token_violation_bps: 500,
    repair_breach_bps: 1000,
  };
  const provider = {
    provider_id: providerId,
    score_bps: 9800,
    degradation_flags: [],
    raw_metrics: {
      version: 1,
      por_success_bps: 9900,
      pdp_success_bps: 9800,
      potr_success_bps: 9700,
      latency_health_bps: 9600,
      dispute_rate_bps: 100,
      token_violation_rate_bps: 0,
      repair_breach_rate_bps: 0,
    },
    raw_metrics_hash_hex: "ef".repeat(32),
  };
  const eventJson =
    `{"version":1,"sequence":${maxU64},"snapshot_id_hex":"${snapshotIdHex}",` +
    `"generated_at_unix":${maxU64},"merkle_root_hex":"${merkleRootHex}",` +
    `"provider_count":1,"previous_snapshot_id_hex":null}`;
  const latestJson =
    `{"snapshot_id_hex":"${snapshotIdHex}","generated_at_unix":${maxU64},` +
    `"previous_snapshot_id_hex":null,"merkle_root_hex":"${merkleRootHex}",` +
    `"provider_count":1,"returned_provider_count":1,"limit":50,` +
    `"truncated_providers":false,"alpha_bps":8500,` +
    `"current_score_weight_bps":7000,"weights":${JSON.stringify(weights)},` +
    `"providers":[${JSON.stringify(provider)}]}`;
  const eventsJson =
    `{"since":null,"limit":50,"count":1,"next_since":${maxU64},` +
    `"events":[${eventJson}]}`;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url) => {
      if (url.includes("/events/stream")) {
        return createSseResponse([
          `id: ${maxU64}\n`,
          "event: reputation_snapshot\n",
          `data: ${eventJson}\n\n`,
          "event: lagged\n",
          `data: ${maxU64}\n\n`,
        ]);
      }
      return createResponse({
        status: 200,
        textBody: url.endsWith("/events") ? eventsJson : latestJson,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const auth = { headers: { "X-Iroha-Witness": witness } };

  const latest = await client.getSorafsReputationLatest(auth);
  assert.equal(latest?.generated_at_unix, maxU64Value);

  const events = await client.listSorafsReputationEvents(auth);
  assert.equal(events?.since, null);
  assert.equal(events?.limit, 50);
  assert.equal(events?.next_since, maxU64Value);
  assert.equal(events?.events[0]?.sequence, maxU64Value);
  assert.equal(events?.events[0]?.generated_at_unix, maxU64Value);

  const iterator = client.streamSorafsReputationEvents({
    ...auth,
    since: maxU64Value - 1n,
  });
  const streamed = await iterator.next();
  assert.equal(streamed.value?.id, maxU64);
  assert.equal(streamed.value?.data.sequence, maxU64Value);
  assert.equal(streamed.value?.data.generated_at_unix, maxU64Value);
  const lagged = await iterator.next();
  assert.equal(lagged.value?.event, "lagged");
  assert.equal(lagged.value?.data, maxU64Value);
});

test("SoraFS reputation helpers reject noncanonical V1 responses", async () => {
  const snapshotIdHex = "ab".repeat(16);
  const otherSnapshotIdHex = "ac".repeat(16);
  const merkleRootHex = "cd".repeat(32);
  const providerId = "provider:alpha";
  const witness = Buffer.from("canonical-witness", "utf8").toString("base64");
  const auth = { headers: { "X-Iroha-Witness": witness } };
  const weights = () => ({
    version: 1,
    por_success_bps: 2200,
    pdp_success_bps: 2000,
    potr_success_bps: 1800,
    latency_bps: 1500,
    dispute_bps: 1000,
    token_violation_bps: 500,
    repair_breach_bps: 1000,
  });
  const provider = (id = providerId) => ({
    provider_id: id,
    score_bps: 9800,
    degradation_flags: [],
    raw_metrics: {
      version: 1,
      por_success_bps: 9900,
      pdp_success_bps: 9800,
      potr_success_bps: 9700,
      latency_health_bps: 9600,
      dispute_rate_bps: 100,
      token_violation_rate_bps: 0,
      repair_breach_rate_bps: 0,
    },
    raw_metrics_hash_hex: "ef".repeat(32),
  });
  const snapshot = (id = snapshotIdHex) => ({
    snapshot_id_hex: id,
    generated_at_unix: 1_800_000_000,
    previous_snapshot_id_hex: null,
    merkle_root_hex: merkleRootHex,
    provider_count: 1,
    returned_provider_count: 1,
    limit: 50,
    truncated_providers: false,
    alpha_bps: 8500,
    current_score_weight_bps: 7000,
    weights: weights(),
    providers: [provider()],
  });
  const responseClient = (jsonData) =>
    new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
    });

  const missingField = snapshot();
  delete missingField.returned_provider_count;
  await assert.rejects(
    () => responseClient(missingField).getSorafsReputationLatest(auth),
    /fields are not canonical.*returned_provider_count/,
  );

  const extraField = snapshot();
  extraField.compatibility_alias = true;
  await assert.rejects(
    () => responseClient(extraField).getSorafsReputationLatest(auth),
    /fields are not canonical.*compatibility_alias/,
  );

  const wrongAlpha = snapshot();
  wrongAlpha.alpha_bps = 8499;
  await assert.rejects(
    () => responseClient(wrongAlpha).getSorafsReputationLatest(auth),
    /alpha_bps must be between 8500 and 8500/,
  );

  const wrongWeightTotal = snapshot();
  wrongWeightTotal.weights.repair_breach_bps = 999;
  await assert.rejects(
    () => responseClient(wrongWeightTotal).getSorafsReputationLatest(auth),
    /basis-point fields must sum to exactly 10000/,
  );

  const wrongFlagOrder = snapshot();
  wrongFlagOrder.providers[0].degradation_flags = [
    { flag: "low_score", value: null },
    { flag: "reserve_warning", value: null },
  ];
  await assert.rejects(
    () => responseClient(wrongFlagOrder).getSorafsReputationLatest(auth),
    /degradation_flags must use canonical enum order/,
  );

  const providerMismatch = {
    snapshot_id_hex: snapshotIdHex,
    generated_at_unix: 1_800_000_000,
    merkle_root_hex: merkleRootHex,
    provider: provider("provider:other"),
    proof: {
      provider_id: "provider:other",
      leaf_index: 0,
      leaf_count: 1,
      siblings_hex: [],
    },
  };
  await assert.rejects(
    () =>
      responseClient(providerMismatch).getSorafsReputationProvider(
        providerId,
        auth,
      ),
    /does not match the requested provider/,
  );

  const invalidProof = {
    ...providerMismatch,
    provider: provider(),
    proof: {
      provider_id: providerId,
      leaf_index: 0,
      leaf_count: 2,
      siblings_hex: [],
    },
  };
  await assert.rejects(
    () =>
      responseClient(invalidProof).getSorafsReputationProvider(
        providerId,
        auth,
      ),
    /siblings_hex must have the exact Merkle depth/,
  );

  await assert.rejects(
    () =>
      responseClient(snapshot(otherSnapshotIdHex)).getSorafsReputationSnapshot(
        snapshotIdHex,
        auth,
      ),
    /does not match the requested snapshot/,
  );

  const event = {
    version: 1,
    sequence: 8,
    snapshot_id_hex: snapshotIdHex,
    generated_at_unix: 1_800_000_000,
    merkle_root_hex: merkleRootHex,
    provider_count: 1,
    previous_snapshot_id_hex: null,
  };
  const mismatchedPage = {
    since: 6,
    limit: 2,
    count: 1,
    next_since: 8,
    events: [event],
  };
  await assert.rejects(
    () =>
      responseClient(mismatchedPage).listSorafsReputationEvents({
        ...auth,
        since: 7,
        limit: 2,
      }),
    /since does not match the requested cursor/,
  );
  mismatchedPage.since = 7;
  await assert.rejects(
    () =>
      responseClient(mismatchedPage).listSorafsReputationEvents({
        ...auth,
        since: 7,
        limit: 3,
    }),
    /limit does not match the requested limit/,
  );
  const wrongDefaultLimitPage = {
    ...mismatchedPage,
    since: null,
    limit: 500,
  };
  await assert.rejects(
    () =>
      responseClient(wrongDefaultLimitPage).listSorafsReputationEvents(auth),
    /limit does not match the requested limit/,
  );

  const sseClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createSseResponse([
        "id: 9\n",
        "event: reputation_snapshot\n",
        `data: ${JSON.stringify(event)}\n\n`,
      ]),
  });
  const iterator = sseClient.streamSorafsReputationEvents({
    ...auth,
    since: 7,
  });
  await assert.rejects(
    () => iterator.next(),
    /id must equal data.sequence/,
  );

  const staleSseClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createSseResponse([
        "id: 8\n",
        "event: reputation_snapshot\n",
        `data: ${JSON.stringify(event)}\n\n`,
      ]),
  });
  const staleIterator = staleSseClient.streamSorafsReputationEvents({
    ...auth,
    since: 8,
  });
  await assert.rejects(
    () => staleIterator.next(),
    /sequence must be greater than the requested since cursor/,
  );
});

test("SoraFS reputation helpers validate options and identifiers before fetch", async () => {
  const canonicalAuth = {
    accountId: "reputation-reader@sora",
    privateKey: Buffer.alloc(32, 31),
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for invalid reputation inputs");
    },
  });
  await assert.rejects(
    () => client.getSorafsReputationLatest("invalid"),
    /getSorafsReputationLatest options must be an object/,
  );
  await assert.rejects(
    () => client.getSorafsReputationLatest({ unknown: true }),
    /getSorafsReputationLatest options contains unsupported fields: unknown/,
  );
  await assert.rejects(
    () => client.getSorafsReputationLatest({ canonicalAuth, etag: '"b"' }),
    /unsupported fields: etag/,
  );
  await assert.rejects(
    () => client.getSorafsReputationLatest(),
    /requires canonicalAuth or an exact X-Iroha-Witness header/,
  );
  await assert.rejects(
    () => client.getSorafsReputationProvider("bad provider"),
    /unsupported characters/,
  );
  for (const providerId of [".", ".."]) {
    await assert.rejects(
      () =>
        client.getSorafsReputationProvider(providerId, {
          canonicalAuth,
        }),
      /must not be a URL dot segment/,
    );
  }
  await assert.rejects(
    () => client.getSorafsReputationSnapshot("ab".repeat(15)),
    /exactly 32 lowercase hexadecimal characters/,
  );
  await assert.rejects(
    () =>
      client.getSorafsReputationSnapshot("AB".repeat(16), {
        canonicalAuth,
      }),
    /exactly 32 lowercase hexadecimal characters/,
  );
  await assert.rejects(
    () =>
      client.getSorafsReputationSnapshot("0".repeat(32), {
        canonicalAuth,
      }),
    /must be nonzero/,
  );
  await assert.rejects(
    () => client.listSorafsReputationEvents({ limit: 0 }),
    /listSorafsReputationEvents\.limit must be positive/,
  );
  await assert.rejects(
    () =>
      client.listSorafsReputationEvents({
        canonicalAuth,
        limit: 501,
      }),
    /listSorafsReputationEvents\.limit must be at most 500/,
  );
  await assert.rejects(
    () =>
      client.listSorafsReputationEvents({
        canonicalAuth,
        since: "01",
      }),
    /canonical unsigned decimal integer/,
  );
  await assert.rejects(
    () =>
      client.listSorafsReputationEvents({
        canonicalAuth,
        since: 18446744073709551616n,
      }),
    /must be at most 18446744073709551615/,
  );
  assert.throws(
    () => client.streamSorafsReputationEvents({ extra: true }),
    /streamSorafsReputationEvents options contains unsupported fields: extra/,
  );
  assert.throws(
    () =>
      client.streamSorafsReputationEvents({
        canonicalAuth,
        lastEventId: "7",
      }),
    /unsupported fields: lastEventId/,
  );
  assert.throws(
    () =>
      client.streamSorafsReputationEvents({
        canonicalAuth,
        headers: { "Last-Event-ID": "7" },
      }),
    /does not accept Last-Event-ID/,
  );
  const defaultResumeClient = new ToriiClient(BASE_URL, {
    defaultHeaders: { "Last-Event-ID": "7" },
    fetchImpl: async () => {
      throw new Error("fetch should not run for Last-Event-ID");
    },
  });
  assert.throws(
    () => defaultResumeClient.streamSorafsReputationEvents({ canonicalAuth }),
    /does not accept Last-Event-ID/,
  );
  await assert.rejects(
    () =>
      client.getSorafsReputationLatest({
        headers: { "X-Iroha-Signature": "partial" },
      }),
    /cannot supply signature proof fields directly/,
  );
  await assert.rejects(
    () =>
      client.getSorafsReputationLatest({
        canonicalAuth,
        headers: { "X-Iroha-Witness": Buffer.from("witness").toString("base64") },
      }),
    /exactly one canonical authentication mode/,
  );
  const witness = Buffer.from("canonical-witness").toString("base64");
  await assert.rejects(
    () =>
      client.getSorafsReputationLatest({
        headers: { "X-Iroha-Witness": Buffer.from(witness) },
      }),
    /must be exact standard-base64/,
  );
  await assert.rejects(
    () =>
      client.getSorafsReputationLatest({
        headers: {
          "X-Iroha-Witness": witness,
          "X-Iroha-Account": Buffer.from("reputation-reader@sora"),
        },
      }),
    /must be an exact canonical I105 account or ASCII account alias/,
  );
});

test("SoraFS reputation witness auth is exact and signed streams do not replay", async () => {
  const witness = Buffer.from("canonical-witness", "utf8").toString("base64");
  const witnessCalls = [];
  const witnessClient = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      witnessCalls.push({ url, init });
      return createResponse({
        status: 404,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const latest = await witnessClient.getSorafsReputationLatest({
    headers: {
      "X-Iroha-Witness": witness,
      "X-Iroha-Account": SAMPLE_ACCOUNT_ID,
    },
  });
  assert.equal(latest, null);
  assert.deepEqual([witnessCalls[0]?.init?.headers?.["X-Iroha-Witness"], witnessCalls[0]?.init?.headers?.["X-Iroha-Account"]], [witness, AccountAddress.parseEncoded(SAMPLE_ACCOUNT_ID).address.canonicalHex()]);

  await assert.rejects(
    () =>
      witnessClient.getSorafsReputationLatest({
        headers: { "X-Iroha-Witness": ` ${witness}` },
      }),
    /must be exact standard-base64/,
  );

  let insecureAttempts = 0;
  const insecureClient = new ToriiClient("http://torii.example", {
    fetchImpl: async () => {
      insecureAttempts += 1;
      return createResponse({ status: 404 });
    },
  });
  await assert.rejects(
    () =>
      insecureClient.getSorafsReputationLatest({
        headers: { "X-Iroha-Witness": witness },
      }),
    /refusing to send sensitive request material over insecure protocol/,
  );
  assert.equal(insecureAttempts, 0);

  const allowedInsecureClient = new ToriiClient("http://torii.example", {
    allowInsecure: true,
    fetchImpl: async () => {
      insecureAttempts += 1;
      return createResponse({ status: 404 });
    },
  });
  assert.equal(
    await allowedInsecureClient.getSorafsReputationLatest({
      headers: { "X-Iroha-Witness": witness },
    }),
    null,
  );
  assert.equal(insecureAttempts, 1);

  let witnessStreamAttempts = 0;
  const witnessStreamClient = new ToriiClient(BASE_URL, {
    maxRetries: 3,
    fetchImpl: async () => {
      witnessStreamAttempts += 1;
      throw new TypeError("witness stream network failure");
    },
  });
  const witnessIterator = witnessStreamClient.streamSorafsReputationEvents({
    headers: { "X-Iroha-Witness": witness },
  });
  await assert.rejects(
    () => witnessIterator.next(),
    /witness stream network failure/,
  );
  assert.equal(witnessStreamAttempts, 1);

  let attempts = 0;
  const signedClient = new ToriiClient(BASE_URL, {
    maxRetries: 3,
    fetchImpl: async () => {
      attempts += 1;
      throw new TypeError("network failure");
    },
  });
  const iterator = signedClient.streamSorafsReputationEvents({
    canonicalAuth: {
      accountId: "reputation-reader@sora",
      privateKey: Buffer.alloc(32, 32),
    },
  });
  await assert.rejects(() => iterator.next(), /network failure/);
  assert.equal(attempts, 1);
});

function finalizedOrderbookTestFixtures() {
  const finalizedHash = "aa".repeat(32);
  const priorHash = "bb".repeat(32);
  const orderId = "11".repeat(32);
  const tradeId = "22".repeat(32);
  const channelId = "33".repeat(32);
  const receiptId = "44".repeat(32);
  const providerId = "55".repeat(32);
  const finalizedCursor = {
    height: 7,
    block_hash: finalizedHash.toUpperCase(),
  };
  const order = {
    order_id: orderId,
    owner: "alice",
    canonical_order: "AQID",
    admitted_policy_digest: "66".repeat(32),
    admitted_at_unix: 1_800_000_000,
    admission_sequence: 4,
    remaining_gib: 2,
    status: { status: "partially_filled", value: null },
    updated_at_unix: 1_800_000_001,
    canonical_cancel: null,
    cancelled_at_unix: null,
    cancelled_policy_digest: null,
  };
  const trade = {
    trade_id: tradeId,
    maker_order_id: orderId,
    taker_order_id: "77".repeat(32),
    trade_sequence: 3,
    canonical_trade: "BAUG",
    channel_id: channelId,
    book_revision: 9,
    recorded_at_unix: 1_800_000_002,
  };
  const channel = {
    channel_id: channelId,
    trade_id: tradeId,
    buyer: "alice",
    provider: "bob",
    provider_id: providerId,
    settlement_authority: "settlement",
    total_bytes: 2048,
    remaining_bytes: 1024,
    initial_xor_locked: "2.000000000",
    remaining_xor_locked: "1.000000000",
    status: { status: "open", value: null },
    opened_at_unix: 1_800_000_003,
    expires_at_unix: 1_800_003_603,
    updated_at_unix: 1_800_000_004,
  };
  const receipt = {
    receipt_id: receiptId,
    channel_id: channelId,
    trade_id: tradeId,
    canonical_receipt: "BwgJ",
    admitted_policy_digest: "66".repeat(32),
    admitted_at_unix: 1_800_000_005,
    recorded_by: "settlement",
  };
  const event = {
    sequence: 9,
    block_height: 7,
    block_hash: finalizedHash.toUpperCase(),
    event_index: 3,
    event: {
      kind: { kind: "receipt_recorded", detail: null },
      order_id: null,
      trade_id: tradeId,
      channel_id: channelId,
      receipt_id: receiptId,
      provider_id: providerId,
      book_revision: 10,
      authority: "settlement",
      occurred_at_unix_ms: 1_800_000_005_000,
    },
  };
  const status = {
    open_orders: 1,
    partially_filled_orders: 1,
    filled_orders: 2,
    cancelled_orders: 3,
    expired_orders: 4,
    trades: 5,
    settlement_receipts: 6,
    settlement_channels: 7,
    open_settlement_channels: 1,
    book_revision: 10,
    next_admission_sequence: 8,
    next_trade_sequence: 6,
    updated_at_unix: 1_800_000_005,
  };
  return {
    finalizedHash,
    priorHash,
    orderId,
    tradeId,
    channelId,
    receiptId,
    finalizedCursor,
    order,
    trade,
    channel,
    receipt,
    event,
    status,
  };
}

test("SoraFS orderbook helpers use finalized native pages", async () => {
  const fixture = finalizedOrderbookTestFixtures();
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    if (url.includes("/v1/sorafs/orderbook/book")) {
      return createResponse({
        status: 200,
        jsonData: {
          source: "finalized_chain",
          status: fixture.status,
          orders: {
            finalized_cursor: fixture.finalizedCursor,
            orders: [fixture.order],
            has_more: true,
            next_after_order_id: fixture.orderId.toUpperCase(),
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/orderbook/trades")) {
      return createResponse({
        status: 200,
        jsonData: {
          source: "finalized_chain",
          trades: {
            finalized_cursor: fixture.finalizedCursor,
            trades: [fixture.trade],
            has_more: false,
            next_after_trade_id: null,
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/orderbook/channels")) {
      return createResponse({
        status: 200,
        jsonData: {
          source: "finalized_chain",
          channels: {
            finalized_cursor: fixture.finalizedCursor,
            channels: [fixture.channel],
            has_more: false,
            next_after_channel_id: null,
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/orderbook/receipts")) {
      return createResponse({
        status: 200,
        jsonData: {
          source: "finalized_chain",
          receipts: {
            finalized_cursor: fixture.finalizedCursor,
            receipts: [fixture.receipt],
            has_more: false,
            next_after_receipt_id: null,
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/v1/sorafs/orderbook/events/stream")) {
      return createSseResponse([
        "id: 9\n",
        "event: receipt_recorded\n",
        `data: ${JSON.stringify(fixture.event)}\n`,
        "\n",
      ]);
    }
    if (url.includes("/v1/sorafs/orderbook/events")) {
      return createResponse({
        status: 200,
        jsonData: {
          source: "finalized_chain",
          events: {
            finalized_cursor: fixture.finalizedCursor,
            events: [fixture.event],
            has_more: true,
            next_after: {
              sequence: 9,
              block_height: 7,
              block_hash: fixture.finalizedHash.toUpperCase(),
              event_index: 3,
            },
          },
        },
        headers: {
          "content-type": "application/json",
          etag: '"orderbook-events"',
        },
      });
    }
    throw new Error(`unexpected URL: ${url}`);
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
  });

  const book = await client.getSorafsOrderbook({
    limit: 2,
    expectedFinalizedHeight: 7,
    expectedFinalizedBlockHashHex: fixture.finalizedHash.toUpperCase(),
    afterIdHex: fixture.orderId.toUpperCase(),
    headers: { "X-Trace": "book" },
  });
  assert.equal(book.source, "finalized_chain");
  assert.equal(book.status.book_revision, 10);
  assert.equal(book.orders.finalized_cursor.block_hash, fixture.finalizedHash);
  assert.equal(book.orders.orders[0]?.order_id, fixture.orderId);
  assert.equal(book.orders.next_after_order_id, fixture.orderId);
  const bookCall = calls.at(-1);
  const bookUrl = new URL(bookCall.url);
  assert.equal(bookUrl.searchParams.get("limit"), "2");
  assert.equal(bookUrl.searchParams.get("expected_finalized_height"), "7");
  assert.equal(
    bookUrl.searchParams.get("expected_finalized_block_hash_hex"),
    fixture.finalizedHash,
  );
  assert.equal(bookUrl.searchParams.get("after_id_hex"), fixture.orderId);
  assert.equal(bookCall.init.headers["X-Trace"], "book");

  const trades = await client.listSorafsOrderbookTrades({ limit: 1 });
  assert.equal(trades.trades.trades[0]?.trade_id, fixture.tradeId);
  const channels = await client.listSorafsOrderbookChannels();
  assert.equal(channels.channels.channels[0]?.channel_id, fixture.channelId);
  const receipts = await client.listSorafsOrderbookReceipts();
  assert.equal(receipts.receipts.receipts[0]?.receipt_id, fixture.receiptId);

  const cursorOptions = {
    limit: 10,
    expectedFinalizedHeight: 7,
    expectedFinalizedBlockHashHex: fixture.finalizedHash,
    afterSequence: 8,
    afterBlockHeight: 6,
    afterBlockHashHex: fixture.priorHash,
    afterEventIndex: 2,
  };
  const events = await client.listSorafsOrderbookEvents({
    ...cursorOptions,
    ifNoneMatch: '"old-events"',
  });
  assert.equal(events?.events.events[0]?.sequence, 9);
  assert.equal(events?.events.events[0]?.block_hash, fixture.finalizedHash);
  assert.equal(events?.events.events[0]?.event.book_revision, 10);
  assert.equal(events?.events.next_after?.event_index, 3);
  const eventsCall = calls.at(-1);
  const eventsUrl = new URL(eventsCall.url);
  assert.equal(eventsUrl.searchParams.has("since"), false);
  assert.equal(eventsUrl.searchParams.get("after_sequence"), "8");
  assert.equal(eventsUrl.searchParams.get("after_block_height"), "6");
  assert.equal(eventsUrl.searchParams.get("after_block_hash_hex"), fixture.priorHash);
  assert.equal(eventsUrl.searchParams.get("after_event_index"), "2");
  assert.equal(eventsCall.init.headers["If-None-Match"], '"old-events"');

  const stream = client.streamSorafsOrderbookEvents({
    ...cursorOptions,
    limit: 1,
  });
  const first = await stream.next();
  assert.equal(first.done, false);
  assert.equal(first.value.event, "receipt_recorded");
  assert.equal(first.value.id, "9");
  assert.equal(first.value.data.sequence, 9);
  assert.equal(first.value.data.event.receipt_id, fixture.receiptId);
  const streamUrl = new URL(calls.at(-1).url);
  assert.equal(streamUrl.pathname, "/v1/sorafs/orderbook/events/stream");
  assert.equal(streamUrl.searchParams.get("after_sequence"), "8");
  assert.equal(streamUrl.searchParams.has("since"), false);
  assert.equal(calls.at(-1).init.headers["Last-Event-ID"], undefined);

});

test("SoraFS orderbook rejects stale cursors and noncanonical transactions", async () => {
  let fetchCount = 0;
  const rejectingClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCount += 1;
      throw new Error("fetch must not run for invalid orderbook input");
    },
    [TORII_TEST_NATIVE_BINDING]: {
      encodeSignedTransactionVersioned: () => {
        throw new Error("noncanonical signed transaction");
      },
    },
  });
  await assert.rejects(
    () => rejectingClient.getSorafsOrderbook("invalid"),
    /getSorafsOrderbook options must be an object/,
  );
  await assert.rejects(
    () => rejectingClient.listSorafsOrderbookTrades({ since: 1 }),
    /unsupported fields: since/,
  );
  await assert.rejects(
    () =>
      rejectingClient.getSorafsOrderbook({
        expectedFinalizedHeight: 7,
      }),
    /expectedFinalizedHeight and expectedFinalizedBlockHashHex together/,
  );
  await assert.rejects(
    () =>
      rejectingClient.listSorafsOrderbookEvents({
        afterSequence: 8,
        afterBlockHeight: 6,
      }),
    /complete afterSequence\/afterBlockHeight\/afterBlockHashHex\/afterEventIndex cursor/,
  );
  await assert.rejects(
    () => rejectingClient.listSorafsOrderbookEvents({ limit: 501 }),
    /listSorafsOrderbookEvents\.limit/,
  );
  assert.throws(
    () => rejectingClient.streamSorafsOrderbookEvents({ since: 8 }),
    /unsupported fields: since/,
  );
  assert.throws(
    () => rejectingClient.streamSorafsOrderbookEvents({ lastEventId: "8" }),
    /unsupported fields: lastEventId/,
  );
  assert.throws(
    () => rejectingClient.buildSorafsOrderbookEventsWebSocketUrl({ since: 8 }),
    /unsupported fields: since/,
  );
  await assert.rejects(
    () => rejectingClient.listSorafsOrderbookEvents({ etag: '"stale-alias"' }),
    /unsupported fields: etag/,
  );
  assert.equal(fetchCount, 0);

  const cachedClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 304, headers: {} }),
  });
  assert.equal(
    await cachedClient.listSorafsOrderbookEvents({ ifNoneMatch: '"same"' }),
    null,
  );
});

test("SoraFS orderbook WebSocket helpers require and preserve full finalized cursors", async () => {
  class FakeWebSocket {
    static instances = [];

    constructor(url, protocols, options) {
      this.url = url;
      this.protocols = protocols;
      this.options = options;
      this.listeners = new Map();
      this.closed = false;
      FakeWebSocket.instances.push(this);
    }

    addEventListener(event, listener) {
      const listeners = this.listeners.get(event) ?? [];
      listeners.push(listener);
      this.listeners.set(event, listeners);
    }

    removeEventListener(event, listener) {
      const listeners = this.listeners.get(event) ?? [];
      this.listeners.set(
        event,
        listeners.filter((candidate) => candidate !== listener),
      );
    }

    emit(event, payload) {
      for (const listener of this.listeners.get(event) ?? []) {
        listener(payload);
      }
    }

    close() {
      this.closed = true;
      this.emit("close", {});
    }
  }

  const fixture = finalizedOrderbookTestFixtures();
  const cursor = {
    limit: 1,
    expectedFinalizedHeight: 7,
    expectedFinalizedBlockHashHex: fixture.finalizedHash,
    afterSequence: 8,
    afterBlockHeight: 6,
    afterBlockHashHex: fixture.priorHash,
    afterEventIndex: 2,
  };
  const client = new ToriiClient(BASE_URL);
  const websocketUrl = client.buildSorafsOrderbookEventsWebSocketUrl(cursor);
  const parsed = new URL(websocketUrl);
  assert.equal(parsed.protocol, "wss:");
  assert.equal(parsed.pathname, "/v1/sorafs/orderbook/events/ws");
  assert.equal(parsed.searchParams.get("expected_finalized_height"), "7");
  assert.equal(
    parsed.searchParams.get("expected_finalized_block_hash_hex"),
    fixture.finalizedHash,
  );
  assert.equal(parsed.searchParams.get("after_sequence"), "8");
  assert.equal(parsed.searchParams.get("after_block_height"), "6");
  assert.equal(parsed.searchParams.get("after_block_hash_hex"), fixture.priorHash);
  assert.equal(parsed.searchParams.get("after_event_index"), "2");
  assert.equal(parsed.searchParams.has("since"), false);
  assert.equal(
    buildSorafsOrderbookEventsWebSocketUrl(BASE_URL, cursor),
    websocketUrl,
  );

  const stream = client.streamSorafsOrderbookEventsWebSocket({
    ...cursor,
    protocols: "iroha.sorafs.orderbook.v1",
    websocketOptions: { perMessageDeflate: false },
    WebSocketImpl: FakeWebSocket,
  });
  const socket = FakeWebSocket.instances[0];
  assert.equal(socket.url, websocketUrl);
  assert.equal(socket.protocols, "iroha.sorafs.orderbook.v1");
  assert.deepEqual(socket.options, { perMessageDeflate: false });

  const eventPromise = stream.next();
  socket.emit("message", {
    data: JSON.stringify({
      event: "receipt_recorded",
      data: fixture.event,
    }),
  });
  const first = await eventPromise;
  assert.equal(first.done, false);
  assert.equal(first.value.event, "receipt_recorded");
  assert.equal(first.value.data.sequence, 9);
  assert.equal(first.value.data.block_hash, fixture.finalizedHash);
  assert.equal(first.value.data.event.receipt_id, fixture.receiptId);

  await stream.return();
  assert.equal(socket.closed, true);
});

registerToriiClientDistributionMemoryTests({ assert, test });

function canonicalUaidPortfolioFixture() {
  const fixture = cloneFixture(toriiFixtures.uaid.portfolio);
  fixture.totals.accounts = 1;
  fixture.dataspaces[0].accounts[0].account_id = FIXTURE_ALICE_ID;
  fixture.dataspaces[0].accounts[0].assets[0].asset_id =
    `${FIXTURE_ASSET_ID_A}#${FIXTURE_ALICE_ID}`;
  fixture.dataspaces[1].accounts[0].account_id = FIXTURE_ALICE_ID;
  fixture.dataspaces[1].accounts[0].assets[0].asset_id =
    `${FIXTURE_ASSET_ID_B}#${FIXTURE_ALICE_ID}#dataspace:11`;
  fixture.dataspaces[1].accounts[0].assets[1].asset_id =
    `${FIXTURE_ASSET_ID_C}#${FIXTURE_ALICE_ID}#dataspace:11`;
  return fixture;
}

function canonicalUaidBindingsFixture() {
  const fixture = cloneFixture(toriiFixtures.uaid.bindings);
  for (const dataspace of fixture.dataspaces) {
    dataspace.accounts = [FIXTURE_ALICE_ID];
  }
  return fixture;
}

function canonicalUaidManifestsFixture() {
  const fixture = cloneFixture(toriiFixtures.uaid.manifests);
  fixture.manifests[0].accounts = [FIXTURE_ALICE_ID];
  const page = { items: fixture.manifests, next_cursor: null, total: fixture.total };
  Object.defineProperty(page, "uaid", { value: fixture.uaid });
  return page;
}

test("getUaidPortfolio preserves exact UAID literals and parses dataspace payloads", async () => {
  let capturedUrl;
  const fixture = canonicalUaidPortfolioFixture();
  const canonical = fixture.uaid;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: fixture,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getUaidPortfolio(canonical);
  assert.equal(
    capturedUrl,
    `${BASE_URL}/v1/accounts/${encodeURIComponent(canonical)}/portfolio`,
  );
  assert.equal(result.uaid, canonical);
  assert.equal(result.totals.accounts, 1);
  assert.equal(result.dataspaces.length, 2);
  assert.equal(
    result.dataspaces[1].accounts[0].assets[1].asset_definition_id,
    "5Pz9SwdN9eXPbiXPX9HRCpzCcE3o",
  );
  await assert.rejects(() => client.getUaidPortfolio("short"), /uaid/);
});

test("getUaidPortfolio rejects noncanonical UAID spellings before dispatch", async () => {
  let fetchCalled = false;
  const fixture = canonicalUaidPortfolioFixture();
  const canonical = fixture.uaid;
  const rawHex = canonical.slice("uaid:".length);
  const fetchImpl = async () => {
    fetchCalled = true;
    throw new Error("fetch should not run for noncanonical UAID literals");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  for (const value of [rawHex, `UAID:${rawHex}`, `uaid:${rawHex.toUpperCase()}`]) {
    await assert.rejects(
      () => client.getUaidPortfolio(value),
      /exact canonical uaid:<64 lowercase hex>|surrounding whitespace/u,
    );
  }
  assert.equal(fetchCalled, false);
});

test("getUaidPortfolio rejects padded UAID path literals before dispatch", async () => {
  let fetchCalled = false;
  const canonical = toriiFixtures.uaid.portfolio.uaid;
  const rawHex = canonical.slice("uaid:".length);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch should not run for padded UAID path literals");
    },
  });

  for (const value of [
    ` ${canonical}`,
    `${canonical} `,
    `uaid: ${rawHex}`,
  ]) {
    await assert.rejects(
      () => client.getUaidPortfolio(value),
      /exact canonical uaid:<64 lowercase hex>|surrounding whitespace/u,
    );
  }
  assert.equal(fetchCalled, false);
});

test("getUaidPortfolio encodes assetId filters", async () => {
  let capturedUrl;
  const fixture = canonicalUaidPortfolioFixture();
  const assetId = fixture.dataspaces[0].accounts[0].assets[0].asset_id;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: fixture,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.getUaidPortfolio(fixture.uaid, { assetId });
  const parsed = new URL(capturedUrl);
  assert.equal(parsed.pathname, `/v1/accounts/${encodeURIComponent(fixture.uaid)}/portfolio`);
  assert.equal(parsed.searchParams.get("asset_id"), assetId);
});

test("getUaidPortfolio rejects bare asset-definition filters", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch must not run for a bare asset definition");
    },
  });
  await assert.rejects(
    () => client.getUaidPortfolio(toriiFixtures.uaid.portfolio.uaid, {
      assetId: FIXTURE_ASSET_ID_A,
    }),
    /base58-asset-definition-id/u,
  );
  assert.equal(fetchCalled, false);
});

test("getUaidPortfolio rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for option validation");
    },
  });
  await assert.rejects(
    () => client.getUaidPortfolio(toriiFixtures.uaid.portfolio.uaid, { retry: true }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_OBJECT);
      assert.equal(error.path, "getUaidPortfolio.options");
      assert.match(
        error.message,
        /getUaidPortfolio options contains unsupported fields: retry/,
      );
      return true;
    },
  );
});

test("getUaidBindings enforces UAID formats and normalizes entries", async () => {
  let capturedUrl;
  const fixture = canonicalUaidBindingsFixture();
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: fixture,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getUaidBindings(fixture.uaid);
  const parsed = new URL(capturedUrl);
  assert.equal(parsed.origin + parsed.pathname, `${BASE_URL}/v1/space-directory/uaids/${encodeURIComponent(fixture.uaid)}`);
  assert.equal(parsed.search, "");
  assert.equal(result.dataspaces[0].accounts[0], fixture.dataspaces[0].accounts[0]);
  await assert.rejects(
    () => client.getUaidBindings("uaid:xyz"),
    /exact canonical uaid:<64 lowercase hex>/u,
  );
  await assert.rejects(
    () => client.getUaidBindings(`uaid:${"10".repeat(32)}`),
    /least significant bit/i,
  );
  await assert.rejects(
    () => client.getUaidBindings(fixture.uaid, { format: "i105" }),
    /getUaidBindings options contains unsupported fields: format/,
  );
});

test("uaidManifests validates full rows and posts collection filters", async () => {
  let captured;
  const fixture = canonicalUaidManifestsFixture();
  const client = new ToriiClient(BASE_URL, { fetchImpl: async (url, init) => {
    captured = { url, init };
    return createResponse({ status: 200, jsonData: fixture, headers: { "content-type": "application/json" } });
  }});
  const result = await client.uaidManifests(fixture.uaid).list({
    filter: 'dataspace_id = 11 and status = "Active"', limit: 1, includeTotal: true,
  });
  assert.equal(new URL(captured.url).pathname, `/v1/space-directory/uaids/${encodeURIComponent(fixture.uaid)}/manifests/query`);
  assert.equal(captured.init.method, "POST");
  assert.equal(JSON.parse(captured.init.body).include_total, true);
  assert.equal(result.total, 1);
  assert.equal(result.nextCursor, null);
  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].status, "Active");
  assert.equal(result.items[0].lifecycle.activated_epoch, 4097);
  assert.equal(result.items[0].manifest.entries[0].effect.Allow.max_amount, "500000000");
  await assert.rejects(() => client.uaidManifests(fixture.uaid).list({ dataspaceId: 11 }), /dataspaceId/);
});

test("UAID read responses require exact current server fields", async () => {
  const cases = [];

  const portfolioMissingTotals = canonicalUaidPortfolioFixture();
  delete portfolioMissingTotals.totals;
  cases.push(["getUaidPortfolio", portfolioMissingTotals, /exact server fields/]);

  const portfolioLegacyAsset = canonicalUaidPortfolioFixture();
  portfolioLegacyAsset.dataspaces[0].accounts[0].assets[0].asset_id = FIXTURE_ASSET_ID_A;
  cases.push([
    "getUaidPortfolio",
    portfolioLegacyAsset,
    /asset holding id|base58-asset-definition-id/u,
  ]);

  const bindingsDefaultedAccounts = canonicalUaidBindingsFixture();
  delete bindingsDefaultedAccounts.dataspaces[0].accounts;
  cases.push(["getUaidBindings", bindingsDefaultedAccounts, /exact server fields/]);

  const manifestsMissingPageMetadata = canonicalUaidManifestsFixture();
  delete manifestsMissingPageMetadata.next_cursor;
  cases.push(["uaidManifests", manifestsMissingPageMetadata, /next_cursor/]);

  const manifestsLegacyVersion = canonicalUaidManifestsFixture();
  manifestsLegacyVersion.items[0].manifest.version = "V1";
  cases.push(["uaidManifests", manifestsLegacyVersion, /unsigned integer 1/]);

  const manifestsPrefixedHash = canonicalUaidManifestsFixture();
  manifestsPrefixedHash.items[0].manifest_hash =
    `0x${manifestsPrefixedHash.items[0].manifest_hash}`;
  cases.push(["uaidManifests", manifestsPrefixedHash, /exact lowercase 32-byte hex/]);

  const manifestsMissingLifecycleField = canonicalUaidManifestsFixture();
  delete manifestsMissingLifecycleField.items[0].lifecycle.expired_epoch;
  cases.push(["uaidManifests", manifestsMissingLifecycleField, /exact server fields/]);

  const manifestsUnknownRecordField = canonicalUaidManifestsFixture();
  manifestsUnknownRecordField.items[0].legacy_status = "active";
  cases.push(["uaidManifests", manifestsUnknownRecordField, /exact server fields/]);

  const manifestsPaddedAccount = canonicalUaidManifestsFixture();
  manifestsPaddedAccount.items[0].accounts[0] =
    `${manifestsPaddedAccount.items[0].accounts[0]} `;
  cases.push(["uaidManifests", manifestsPaddedAccount, /surrounding whitespace/]);

  const manifestsNullOptional = canonicalUaidManifestsFixture();
  manifestsNullOptional.items[0].manifest.entries[1].notes = null;
  cases.push(["uaidManifests", manifestsNullOptional, /omitted instead of null/]);

  for (const [method, payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    await assert.rejects(() => method === "uaidManifests" ? client.uaidManifests(payload.uaid).list() : client[method](payload.uaid), pattern, method);
  }
});

test("uaidManifests rejects compatibility coercions before dispatch", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch must not run for invalid manifest query options");
    },
  });
  const uaid = toriiFixtures.uaid.manifests.uaid;
  for (const options of [
    { dataspaceId: "11" },
    { status: "Active" },
    { status: " active" },
    { limit: "1" },
    { limit: 0 },
    { offset: "0" },
    { countMode: "Exact" },
    { countMode: null },
  ]) {
    await assert.rejects(
      () => client.uaidManifests(uaid).list(options),
      /unknown|unsupported|positive|limit|status|dataspaceId|offset|countMode/u,
    );
  }
  assert.equal(fetchCalled, false);
});

test("publishSpaceDirectoryManifest posts exact manifest fields", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      headers: { "content-type": "application/json" },
      jsonData: verifyingKeyDraftForPayload(Buffer.from([1, 2, 3])),
    });
  };
  const manifest = cloneFixture(toriiFixtures.uaid.manifests.manifests[0].manifest);
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.publishSpaceDirectoryManifest({
    authority: FIXTURE_AUTHORITY_ID,
    manifest,
    reason: "rotation audit",
  }, { canonicalAuth: APPLICATION_CANONICAL_AUTH });
  assert.equal(captured.url, `${BASE_URL}/v1/space-directory/manifests`);
  assert.equal(captured.init.method, "POST");
  const parsedBody = JSON.parse(captured.init.body.toString());
  assert.equal(parsedBody.authority, FIXTURE_AUTHORITY_ID);
  assert.equal(parsedBody.reason, "rotation audit");
  assert.deepEqual(parsedBody.manifest, manifest);
  assert.equal("private_key" in parsedBody, false);
});

test("publishSpaceDirectoryManifest rejects retired manifest aliases and coercions", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch must not run for noncanonical manifest JSON");
    },
  });
  const manifest = cloneFixture(toriiFixtures.uaid.manifests.manifests[0].manifest);
  const legacyVersion = cloneFixture(manifest);
  legacyVersion.version = "V1";
  const legacyField = cloneFixture(manifest);
  legacyField.issuedMs = legacyField.issued_ms;
  delete legacyField.issued_ms;
  const coercedInteger = cloneFixture(manifest);
  coercedInteger.activation_epoch = String(coercedInteger.activation_epoch);
  const nullOptional = cloneFixture(manifest);
  nullOptional.entries[1].notes = null;

  for (const candidate of [legacyVersion, legacyField, coercedInteger, nullOptional]) {
    await assert.rejects(
      () => client.publishSpaceDirectoryManifest({
        authority: FIXTURE_AUTHORITY_ID,
        manifest: candidate,
      }, { canonicalAuth: APPLICATION_CANONICAL_AUTH }),
      /unsigned integer 1|exact server fields|JSON safe integer|omitted instead of null/u,
    );
  }
  assert.equal(fetchCalled, false);
});

test("publishSpaceDirectoryManifest forwards AbortSignal options", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      headers: { "content-type": "application/json" },
      jsonData: verifyingKeyDraftForPayload(Buffer.from([1, 2, 3])),
    });
  };
  const controller = new AbortController();
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.publishSpaceDirectoryManifest(
    {
      authority: FIXTURE_AUTHORITY_ID,
      manifest: toriiFixtures.uaid.manifests.manifests[0].manifest,
    },
    { signal: controller.signal, canonicalAuth: APPLICATION_CANONICAL_AUTH },
  );
  assertRequestSignal(captured.init.signal, controller.signal);
});

test("publishSpaceDirectoryManifest rejects invalid options payloads", async () => {
  const fetchImpl = async () => {
    throw new Error("fetch should not run for invalid options");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.publishSpaceDirectoryManifest(
        {
          authority: FIXTURE_AUTHORITY_ID,
          manifest: toriiFixtures.uaid.manifests.manifests[0].manifest,
        },
        /** @ts-expect-error */ 42,
      ),
    /publishSpaceDirectoryManifest options must be an object/,
  );
});

test("publishSpaceDirectoryManifest rejects invalid manifest entries", async () => {
  const fetchImpl = async () => {
    throw new Error("publishSpaceDirectoryManifest should not perform fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const base = cloneFixture(toriiFixtures.uaid.manifests.manifests[0].manifest);
  const invalidScope = cloneFixture(base);
  invalidScope.entries[0].scope = "demo";
  const missingWindow = cloneFixture(base);
  delete missingWindow.entries[0].effect.Allow.window;
  const invalidNotes = cloneFixture(base);
  invalidNotes.entries[0].notes = 123;
  const unknownEntryField = cloneFixture(base);
  unknownEntryField.entries[0].legacy = true;

  for (const candidate of [invalidScope, missingWindow, invalidNotes, unknownEntryField]) {
    await assert.rejects(
      () => client.publishSpaceDirectoryManifest({
        authority: FIXTURE_AUTHORITY_ID,
        manifest: candidate,
      }, { canonicalAuth: APPLICATION_CANONICAL_AUTH }),
      /must be an object|exact server fields|notes must be a string/u,
    );
  }
});

test("revokeSpaceDirectoryManifest preserves exact UAIDs and epochs without signing material", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      headers: { "content-type": "application/json" },
      jsonData: verifyingKeyDraftForPayload(Buffer.from([1, 2, 3])),
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.revokeSpaceDirectoryManifest({
    authority: FIXTURE_AUTHORITY_ID,
    uaid: "uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11",
    dataspaceId: 11,
    revokedEpoch: 4096,
  }, { canonicalAuth: APPLICATION_CANONICAL_AUTH });
  assert.equal(
    captured.url,
    `${BASE_URL}/v1/space-directory/manifests/revoke`,
  );
  const parsedBody = JSON.parse(captured.init.body.toString());
  assert.equal(parsedBody.dataspace, 11);
  assert.equal(parsedBody.revoked_epoch, 4096);
  assert.equal(
    parsedBody.uaid,
    "uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11",
  );
  assert.equal("private_key" in parsedBody, false);
});

test("revokeSpaceDirectoryManifest rejects retired field aliases and coercions", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch must not run for a noncanonical revocation request");
    },
  });
  const base = {
    authority: FIXTURE_AUTHORITY_ID,
    uaid: toriiFixtures.uaid.manifests.uaid,
    dataspaceId: 11,
    revokedEpoch: 4096,
  };
  for (const request of [
    { ...base, dataspace: base.dataspaceId, dataspaceId: undefined },
    { ...base, revoked_epoch: base.revokedEpoch, revokedEpoch: undefined },
    { ...base, dataspaceId: "11" },
    { ...base, revokedEpoch: "4096" },
    { ...base, reason: null },
  ]) {
    await assert.rejects(
      () => client.revokeSpaceDirectoryManifest(
        request,
        { canonicalAuth: APPLICATION_CANONICAL_AUTH },
      ),
      /exact server fields|JSON safe integer|omitted instead of null/u,
    );
  }
  assert.equal(fetchCalled, false);
});

test("revokeSpaceDirectoryManifest supports AbortSignal options", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      headers: { "content-type": "application/json" },
      jsonData: verifyingKeyDraftForPayload(Buffer.from([1, 2, 3])),
    });
  };
  const controller = new AbortController();
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.revokeSpaceDirectoryManifest(
    {
      authority: FIXTURE_AUTHORITY_ID,
      uaid: toriiFixtures.uaid.manifests.uaid,
      dataspaceId: 3,
      revokedEpoch: 512,
    },
    { signal: controller.signal, canonicalAuth: APPLICATION_CANONICAL_AUTH },
  );
  assertRequestSignal(captured.init.signal, controller.signal);
});

test("revokeSpaceDirectoryManifest rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("fetch should not run for invalid options");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.revokeSpaceDirectoryManifest(
        {
          authority: FIXTURE_AUTHORITY_ID,
          uaid: toriiFixtures.uaid.manifests.uaid,
          dataspaceId: 5,
          revokedEpoch: 256,
        },
        { signal: new AbortController().signal, canonicalAuth: APPLICATION_CANONICAL_AUTH, extra: "nope" },
      ),
    /revokeSpaceDirectoryManifest options contains unsupported fields: extra/,
  );
});

test("space-directory mutation drafts reject inline private-key fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch must not run for a secret-bearing request");
    },
  });
  await assert.rejects(
    () =>
      client.publishSpaceDirectoryManifest({
        authority: FIXTURE_AUTHORITY_ID,
        privateKeyHex: "11".repeat(32),
        manifest: toriiFixtures.uaid.manifests.manifests[0].manifest,
      }, { canonicalAuth: APPLICATION_CANONICAL_AUTH }),
    /does not accept private-key fields/,
  );
  await assert.rejects(
    () =>
      client.revokeSpaceDirectoryManifest({
        authority: FIXTURE_AUTHORITY_ID,
        private_key: "secret",
        uaid: toriiFixtures.uaid.manifests.uaid,
        dataspaceId: 5,
        revokedEpoch: 256,
      }, { canonicalAuth: APPLICATION_CANONICAL_AUTH }),
    /does not accept private-key fields/,
  );
});

test("iterateSorafsAliases paginates alias listings", async () => {
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    const limit = Number(parsed.searchParams.get("limit") ?? "0");
    if (offset >= 2) {
      return createResponse({
        status: 200,
        jsonData: {
          attestation: sorafsAliasAttestationFixture(),
          total_count: 2,
          returned_count: 0,
          offset,
          limit,
          aliases: [],
        },
        headers: { "content-type": "application/json" },
      });
    }
    const record = sorafsAliasProjectionFixture(
      FIXTURE_ALICE_ID, `${offset}`.repeat(64), `docs-${offset}`,
    );
    return createResponse({
      status: 200,
      jsonData: {
        attestation: sorafsAliasAttestationFixture(),
        total_count: 2,
        returned_count: 1,
        offset,
        limit,
        aliases: [record],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const seen = [];
  for await (const alias of client.iterateSorafsAliases({
    namespace: "sora",
    pageSize: 1,
    canonicalAuth: SORAFS_CANONICAL_AUTH,
  })) {
    seen.push(alias.alias);
  }
  assert.deepEqual(seen, ["sora/docs-0", "sora/docs-1"]);
});

test("iterateSorafsPinManifests locks the first finalized anchor and advances keysets", async () => {
  const blockHash = Array(32).fill(0x77);
  const summary = (byte) => ({
    digest: Array(32).fill(byte),
    submitted_by: FIXTURE_CAROL_ID,
    submitted_epoch: 42,
    approved_epoch: 45,
    content_length: 100,
    retention_epoch: 900,
    status: { status: "Approved", value: 45 },
    successor_of: null,
  });
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    const parsed = new URL(url);
    const after = parsed.searchParams.get("after_digest_hex");
    if (after === null) {
      return createResponse({
        status: 200,
        jsonData: {
          finalized_cursor: { height: 11, block_hash: blockHash },
          charged_usage: { manifest_count: 2, content_bytes: 200 },
          manifests: [summary(0x10)],
          has_more: true,
          next_after_digest: Array(32).fill(0x10),
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(after, "10".repeat(32));
    assert.equal(parsed.searchParams.get("expected_finalized_height"), "11");
    assert.equal(
      parsed.searchParams.get("expected_finalized_block_hash_hex"),
      "77".repeat(32),
    );
    return createResponse({
      status: 200,
      jsonData: {
        finalized_cursor: { height: 11, block_hash: blockHash },
        charged_usage: { manifest_count: 2, content_bytes: 200 },
        manifests: [summary(0x20)],
        has_more: false,
        next_after_digest: null,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const digests = [];
  for await (const manifest of client.iterateSorafsPinManifests({
    status: "approved",
    pageSize: 1,
    maxItems: 2,
  })) {
    digests.push(Buffer.from(manifest.digest).toString("hex"));
  }
  assert.deepEqual(digests, ["10".repeat(32), "20".repeat(32)]);
  assert.equal(urls.length, 2);
  assert.equal(new URL(urls[0]).searchParams.has("offset"), false);
});

test("iterateSorafsReplicationOrders paginates results", async () => {
  const baseOrder = sorafsReplicationProjectionFixture(FIXTURE_BOB_ID);
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    const limit = Number(parsed.searchParams.get("limit") ?? "0");
    if (offset >= 2) {
      return createResponse({
        status: 200,
        jsonData: {
          attestation: sorafsReplicationAttestationFixture(),
          total_count: 2,
          returned_count: 0,
          offset,
          limit,
          replication_orders: [],
        },
        headers: { "content-type": "application/json" },
      });
    }
    const record = {
      ...JSON.parse(JSON.stringify(baseOrder)),
      order_id_hex: `${offset + 1}`.repeat(64),
      order: { ...baseOrder.order, order_id_hex: `${offset + 1}`.repeat(64) },
    };
    return createResponse({
      status: 200,
      jsonData: {
        attestation: sorafsReplicationAttestationFixture(),
        total_count: 2,
        returned_count: 1,
        offset,
        limit,
        replication_orders: [record],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const order of client.iterateSorafsReplicationOrders({
    status: "pending",
    pageSize: 1,
    canonicalAuth: SORAFS_CANONICAL_AUTH,
  })) {
    ids.push(order.order_id_hex);
  }
  assert.deepEqual(ids, ["1".repeat(64), "2".repeat(64)]);
});

test("SoraFS iterators reject unsupported options", () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  assert.throws(
    () =>
      client.iterateSorafsAliases({
        namespace: "sora",
        platformPolicy: "strict",
        canonicalAuth: SORAFS_CANONICAL_AUTH,
      }),
    /iterator options contains unsupported fields: platformPolicy/,
  );
  assert.throws(
    () =>
      client.iterateSorafsPinManifests({
        status: "approved",
        query: "ignored",
      }),
    /iterator options contains unsupported fields: query/,
  );
  assert.throws(
    () =>
      client.iterateSorafsReplicationOrders({
        status: "pending",
        filter: "noop",
        canonicalAuth: SORAFS_CANONICAL_AUTH,
      }),
    /iterator options contains unsupported fields: filter/,
  );
});

test("_iterateOffsetIterable enforces item-key whitelists", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 204 }),
  });
  const iterator = client._iterateOffsetIterable(
    async () => ({ manifests: ["m1", "m2"] }),
    {},
    new Set(["limit"]),
    ["manifests"],
  );
  const seen = [];
  for await (const manifest of iterator) {
    seen.push(manifest);
  }
  assert.deepEqual(seen, ["m1", "m2"]);

  const failingIterator = client._iterateOffsetIterable(
    async () => ({ manifests: ["m1"] }),
    {},
    new Set(["limit"]),
    ["aliases"],
  );
  await assert.rejects(
    async () => {
      await failingIterator.next();
    },
    /offset iterator response is missing iterable items \(expected: aliases\)/,
  );
});

test("getSorafsStorageState returns typed fields", async () => {
  const snapshot = {
    bytes_used: 10,
    bytes_capacity: 100,
    pin_queue_depth: 1,
    fetch_inflight: 2,
    fetch_bytes_per_sec: 4096,
    por_inflight: 3,
    por_samples_success_total: 12,
    por_samples_failed_total: 1,
    fetch_utilisation_bps: 5000,
    pin_queue_utilisation_bps: 3000,
    por_utilisation_bps: 2000,
  };
  let capturedInit;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (_url, init) => {
      capturedInit = init;
      return createResponse({
        status: 200,
        jsonData: snapshot,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const result = await client.getSorafsStorageState();
  assert.deepEqual(result, snapshot);
  assert.ok(capturedInit?.headers?.["X-Iroha-Operator-Public-Key"]);
  assert.ok(capturedInit?.headers?.["X-Iroha-Operator-Signature"]);
});

test("SoraFS local storage diagnostics require operator signing context", async () => {
  const client = new SourceToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run without operator authentication");
    },
  });
  await assert.rejects(
    () => client.getSorafsStorageState(),
    /getSorafsStorageState requires ToriiClient options\.operatorSigningContext/,
  );
});

test("getSorafsManifest normalizes response payload", async () => {
  const manifestHex = "d".repeat(64);
  const payloadDigestHex = "e".repeat(64);
  const manifestDigestHex = "f".repeat(64);
  const manifestB64 = Buffer.from("manifest").toString("base64");
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          manifest_id_hex: manifestHex,
          manifest_b64: manifestB64,
          manifest_digest_hex: manifestDigestHex,
          payload_digest_hex: payloadDigestHex,
          content_length: 42,
          chunk_count: 4,
          chunk_profile_handle: "profile@v1",
          stored_at_unix_secs: 123,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  const result = await client.getSorafsManifest(manifestHex);
  assert.equal(result.manifest_id_hex, manifestHex);
  assert.equal(result.manifest_b64, manifestB64);
  assert.equal(result.chunk_profile_handle, "profile@v1");
});

test("getDaManifest fetches manifest bundle", async () => {
  let captured = null;
  const ticketHex = `0x${"ab".repeat(32)}`;
  const manifestB64 = Buffer.from("manifest-bytes").toString("base64");
  const chunkPlan = chunkFetchPlan([
    { chunk_index: 0, offset: 0, length: 1, digest_blake3: "ff".repeat(32) },
  ], "dd".repeat(32));
  const manifestHashHex = "ff".repeat(32);
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: {
        storage_ticket: ticketHex.slice(2).toUpperCase(),
        client_blob_id: "cc".repeat(32),
        blob_hash: "dd".repeat(32),
        chunk_root: "ee".repeat(32),
        manifest_hash: manifestHashHex,
        lane_id: 7,
        epoch: 9,
        manifest_len: 123,
        manifest_norito: manifestB64,
        manifest: { version: 1 },
        chunk_plan: chunkPlan,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getDaManifest(ticketHex);
  assert.equal(
    captured?.url,
    `${BASE_URL}/v1/da/manifests/${ticketHex.slice(2).toLowerCase()}`,
  );
  assert.equal(
    captured?.init?.headers?.Accept,
    "application/json",
  );
  assert.equal(result.storage_ticket_hex, ticketHex.slice(2).toLowerCase());
  assert.equal(result.manifest_b64, manifestB64);
  assert.equal(result.manifest_hash_hex, manifestHashHex.toLowerCase());
  assert.deepEqual(result.chunk_plan, chunkPlan);
  assert(Buffer.isBuffer(result.manifest_bytes));
  assert.equal(
    result.manifest_bytes.toString("utf8"),
    Buffer.from("manifest-bytes").toString("utf8"),
  );
});

test("getDaManifest rejects retired or unbound chunk plans", async () => {
  const chunkSpecs = [
    { chunk_index: 0, offset: 0, length: 1, digest_blake3: "ff".repeat(32) },
  ];
  const invalidPlans = [
    ["retired bare array", chunkSpecs, /canonical chunk fetch plan object/],
    [
      "missing payload digest",
      {
        schema: "sorafs.chunk_fetch_plan.v1",
        chunk_fetch_specs: chunkSpecs,
      },
      /payload_digest_blake3_hex/,
    ],
    [
      "zero payload digest",
      chunkFetchPlan(chunkSpecs, "00".repeat(32)),
      /non-zero canonical lowercase/,
    ],
    [
      "substituted payload digest",
      chunkFetchPlan(chunkSpecs, "11".repeat(32)),
      /must match blob_hash_hex/,
    ],
  ];

  for (const [label, chunkPlan, expectedError] of invalidPlans) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: {
            storage_ticket: "ab".repeat(32),
            client_blob_id: "cc".repeat(32),
            blob_hash: "dd".repeat(32),
            chunk_root: "ee".repeat(32),
            manifest_hash: "ff".repeat(32),
            lane_id: 7,
            epoch: 9,
            manifest_len: 1,
            manifest_norito: Buffer.from("m").toString("base64"),
            manifest: { version: 1 },
            chunk_plan: chunkPlan,
          },
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.getDaManifest("ab".repeat(32)),
      expectedError,
      label,
    );
  }
});

test("getDaManifestToDir writes manifest and plan artefacts", async () => {
  const ticketHex = `0x${"ab".repeat(32)}`;
  const manifestBytes = Buffer.from("manifest-bytes");
  const manifestB64 = manifestBytes.toString("base64");
  const chunkPlan = chunkFetchPlan([
    { chunk_index: 0, offset: 0, length: 1, digest_blake3: "ff".repeat(32) },
  ], "dd".repeat(32));
  const manifestHashHex = "ff".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        storage_ticket: ticketHex.slice(2).toUpperCase(),
        client_blob_id: "cc".repeat(32),
        blob_hash: "dd".repeat(32),
        chunk_root: "ee".repeat(32),
        manifest_hash: manifestHashHex,
        lane_id: 7,
        epoch: 9,
        manifest_len: 123,
        manifest_norito: manifestB64,
        manifest: { version: 1 },
        chunk_plan: chunkPlan,
      },
      headers: { "content-type": "application/json" },
    });

  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const tmpDir = await fs.mkdtemp(path.join(tmpdir(), "tmp-js-da-manifest-"));
  try {
    const result = await client.getDaManifestToDir(ticketHex, { outputDir: tmpDir });
    const label = manifestHashHex.toLowerCase();
    const manifestPath = path.join(tmpDir, `manifest_${label}.norito`);
    const manifestJsonPath = path.join(tmpDir, `manifest_${label}.json`);
    const chunkPlanPath = path.join(tmpDir, `chunk_plan_${label}.json`);

    assert.equal(result.paths.label, label);
    const persisted = await fs.readFile(manifestPath);
    assert.equal(persisted.toString(), manifestBytes.toString());
    const manifestJson = JSON.parse(await fs.readFile(manifestJsonPath, "utf8"));
    assert.equal(manifestJson.version, 1);
    const planJson = JSON.parse(await fs.readFile(chunkPlanPath, "utf8"));
    assert.equal(planJson.schema, "sorafs.chunk_fetch_plan.v1");
    assert.equal(planJson.chunk_fetch_specs[0].chunk_index, 0);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test("fetchDaPayloadViaGateway fetches manifest bundle and invokes gateway", async (t) => {
  const ticketHex = `0x${"ab".repeat(32)}`;
  const blobHashHex = "dd".repeat(32);
  const manifestHashHex = "11".repeat(32);
  const planValue = chunkFetchPlan([
    { chunk_index: 0, offset: 0, length: 32, digest_blake3: "ff".repeat(32) },
  ], blobHashHex);
  const manifestB64 = Buffer.from("manifest").toString("base64");
  const chunkerHandle = "sorafs.sf1@1.0.0";
  const fetchImpl = async (url, _init) => {
    if (url.endsWith(`/v1/da/manifests/${ticketHex.slice(2)}`)) {
      return createResponse({
        status: 200,
        jsonData: {
          storage_ticket: ticketHex.slice(2),
          client_blob_id: "cc".repeat(32),
          blob_hash: blobHashHex,
          manifest_hash: manifestHashHex,
          chunk_root: "ee".repeat(32),
          lane_id: 1,
          epoch: 2,
          manifest_len: 42,
          manifest: { version: 1 },
          manifest_norito: manifestB64,
          chunk_plan: planValue,
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected request to ${url}`);
  };
  const gatewayResult = {
    manifestIdHex: blobHashHex,
    chunkerHandle: "sorafs.sf1@1.0.0",
    chunkCount: 1,
    assembledBytes: 512,
    payload: Buffer.from([1, 2, 3]),
    telemetryRegion: null,
    anonymity: {
      policy: "anon-guard-pq",
      status: "met",
      reason: "none",
      soranetSelected: 0,
      pqSelected: 0,
      classicalSelected: 0,
      classicalRatio: 0,
      pqRatio: 0,
      candidateRatio: 0,
      deficitRatio: 0,
      supplyDelta: 0,
      brownout: false,
      brownoutEffective: false,
      usesClassical: false,
    },
    providerReports: [],
    chunkReceipts: [],
    localProxyManifest: null,
    carVerification: null,
    metadata: {
      providerCount: 0,
      gatewayProviderCount: 1,
      providerMix: "gateway-only",
      transportPolicy: "soranet-first",
      transportPolicyOverride: false,
      transportPolicyOverrideLabel: null,
      anonymityPolicy: "anon-guard-pq",
      anonymityPolicyOverride: false,
      anonymityPolicyOverrideLabel: null,
      maxParallel: null,
      maxPeers: null,
      retryBudget: null,
      providerFailureThreshold: 1,
      assumeNowUnix: 0,
      telemetrySourceLabel: null,
      gatewayManifestProvided: false,
      gatewayManifestId: manifestHashHex,
      gatewayManifestCid: null,
      allowImplicitMetadata: false,
    },
  };
  const gatewayMock = t.mock.fn(() => gatewayResult);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    ...toriiTestHooks({ sorafsGatewayFetch: gatewayMock }),
  });
  const providers = [
    {
      name: "alpha",
      providerIdHex: "bb".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway.test/",
      streamTokenB64: "dG9rZW4=",
    },
    {
      name: "beta",
      providerIdHex: "cc".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway-two.test/",
      streamTokenB64: "dG9rZW4y",
    },
  ];
  const session = await client.fetchDaPayloadViaGateway({
    storageTicketHex: ticketHex,
    chunkerHandle,
    gatewayProviders: providers,
  });
  assert.equal(session.manifest.storage_ticket_hex, ticketHex.slice(2));
  assert.equal(session.manifestIdHex, manifestHashHex);
  assert.equal(session.chunkerHandle, chunkerHandle);
  assert.deepEqual(session.chunkPlan, planValue);
  assert.equal(session.gatewayResult, gatewayResult);
  assert.equal(gatewayMock.mock.callCount(), 1);
  const [manifestArg, handleArg, planJsonArg, providerArg] =
    gatewayMock.mock.calls[0].arguments;
  assert.equal(manifestArg, manifestHashHex);
  assert.equal(handleArg, chunkerHandle);
  assert.ok(planJsonArg.includes('"chunk_index":0'));
  assert.equal(providerArg.length, 2);
  assert.equal(providerArg[0].gatewayPublicKeyHex, "dd".repeat(32));
});

test("fetchDaPayloadViaGateway validates signal option", async () => {
  const manifestBundle = {
    storage_ticket_hex: "aa".repeat(32),
    client_blob_id_hex: "cc".repeat(32),
    blob_hash_hex: "bb".repeat(32),
    manifest_hash_hex: "99".repeat(32),
    chunk_root_hex: "dd".repeat(32),
    chunk_plan: chunkFetchPlan(
      [
        {
          chunk_index: 0,
          offset: 0,
          length: 1,
          digest_blake3: "ee".repeat(32),
        },
      ],
      "bb".repeat(32),
    ),
    manifest_bytes: Buffer.from("manifest-bytes"),
    manifest_len: 14,
    lane_id: 1,
    epoch: 1,
  };
  const gatewayProviders = [
    {
      name: "alpha",
      providerIdHex: "11".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway.test",
      streamTokenB64: Buffer.from("token").toString("base64"),
    },
    {
      name: "beta",
      providerIdHex: "22".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway-two.test",
      streamTokenB64: Buffer.from("token-2").toString("base64"),
    },
  ];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: {} }),
    ...toriiTestHooks({ sorafsGatewayFetch: () => ({
      manifestIdHex: manifestBundle.manifest_hash_hex,
      chunkerHandle: "sorafs.sf1@1.0.0",
      chunkCount: 1,
      assembledBytes: 1,
      payload: Buffer.alloc(0),
      telemetryRegion: null,
      anonymity: null,
      providerReports: [],
      chunkReceipts: [],
      localProxyManifest: null,
      carVerification: null,
      metadata: {},
    }) }),
  });

  await assert.rejects(
    () =>
      client.fetchDaPayloadViaGateway({
        manifestBundle,
        chunkerHandle: "sorafs.sf1@1.0.0",
        gatewayProviders,
        signal: "not-a-signal",
      }),
    /fetchDaPayloadViaGateway options\.signal must be an AbortSignal/i,
  );
});

test("fetchDaPayloadViaGateway rejects invalid stream tokens", async () => {
  const manifestBundle = {
    storage_ticket_hex: "aa".repeat(32),
    client_blob_id_hex: "bb".repeat(32),
    blob_hash_hex: "cc".repeat(32),
    manifest_hash_hex: "dd".repeat(32),
    chunk_root_hex: "ee".repeat(32),
    chunk_plan: chunkFetchPlan([
      { chunk_index: 0, offset: 0, length: 32, digest_blake3: "ff".repeat(32) },
    ], "cc".repeat(32)),
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: {} }),
    ...toriiTestHooks({ sorafsGatewayFetch: () => {
      throw new Error("unexpected sorafsGatewayFetch call");
    } }),
  });

  await assert.rejects(
    () =>
      client.fetchDaPayloadViaGateway({
        manifestBundle,
        chunkerHandle: "sorafs.sf1@1.0.0",
        gatewayProviders: [
          {
            name: "alpha",
            providerIdHex: "11".repeat(32),
            gatewayPublicKeyHex: "dd".repeat(32),
            baseUrl: "https://gateway.one",
            streamTokenB64: "not-base64!!",
          },
          {
            name: "beta",
            providerIdHex: "22".repeat(32),
            gatewayPublicKeyHex: "dd".repeat(32),
            baseUrl: "https://gateway.two",
            streamTokenB64: "dG9rZW4y",
          },
        ],
      }),
    /streamTokenB64/,
  );
});

test("fetchDaPayloadViaGateway uses custom hooks", async (t) => {
  const manifestBytes = Buffer.from("sample-manifest");
  const manifestBundle = {
    storage_ticket_hex: "aa".repeat(32),
    blob_hash_hex: "bb".repeat(32),
    manifest_hash_hex: "bb".repeat(32),
    client_blob_id_hex: "cc".repeat(32),
    chunk_root_hex: "dd".repeat(32),
    chunk_plan: chunkFetchPlan([
      { chunk_index: 0, offset: 0, length: 1, digest_blake3: "ee".repeat(32) },
    ], "bb".repeat(32)),
    manifest_bytes: manifestBytes,
    manifest_len: manifestBytes.length,
    lane_id: 1,
    epoch: 2,
  };
  const providers = [
    {
      name: "alpha",
      providerIdHex: "ee".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway.test",
      streamTokenB64: Buffer.from("token").toString("base64"),
    },
  ];
  const gatewayMock = t.mock.fn(() => ({
    payload: Buffer.from("payload-bytes"),
  }));
  const summaryMock = t.mock.fn(() => ({ summary: "ok" }));
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: {} }),
    ...toriiTestHooks({
      sorafsGatewayFetch: gatewayMock,
      generateDaProofSummary: summaryMock,
    }),
  });
  const session = await client.fetchDaPayloadViaGateway({
    manifestBundle,
    chunkerHandle: "sorafs.sf1@1.0.0",
    gatewayProviders: providers,
    proofSummary: true,
  });
  assert.equal(session.manifest.blob_hash_hex, manifestBundle.blob_hash_hex);
  assert.equal(gatewayMock.mock.calls[0].arguments[0], manifestBundle.manifest_hash_hex);
  assert.equal(typeof session.proofSummary, "object");
  assert.equal(summaryMock.mock.callCount(), 1);
  const [manifestArg, payloadArg, optionsArg] = summaryMock.mock.calls[0].arguments;
  assert.ok(Buffer.isBuffer(manifestArg));
  assert.ok(Buffer.isBuffer(payloadArg));
  assert.deepEqual(optionsArg, {});
});

test("fetchDaPayloadViaGateway keeps DA and gateway calls on the client runtime", async () => {
  const manifestBytes = Buffer.from("runtime-manifest");
  const manifestBundle = {
    storage_ticket_hex: "aa".repeat(32),
    client_blob_id_hex: "cc".repeat(32),
    blob_hash_hex: "bb".repeat(32),
    manifest_hash_hex: "bb".repeat(32),
    chunk_root_hex: "dd".repeat(32),
    chunk_plan: chunkFetchPlan(
      [
        {
          chunk_index: 0,
          offset: 0,
          length: 1,
          digest_blake3: "ee".repeat(32),
        },
      ],
      "bb".repeat(32),
    ),
    manifest_bytes: manifestBytes,
    manifest_len: manifestBytes.length,
    lane_id: 1,
    epoch: 2,
  };
  const providers = [
    {
      name: "alpha",
      providerIdHex: "11".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway-one.test",
      streamTokenB64: Buffer.from("token-one").toString("base64"),
    },
    {
      name: "beta",
      providerIdHex: "22".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway-two.test",
      streamTokenB64: Buffer.from("token-two").toString("base64"),
    },
  ];
  const binding = {
    label: "original",
    daManifestChunkerHandle() {
      return `chunker-${this.label}`;
    },
    sorafsGatewayFetch(_manifest, chunkerHandle) {
      throw new Error(`gateway-${this.label}:${chunkerHandle}`);
    },
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("manifest fetch should not run");
    },
    [TORII_TEST_NATIVE_BINDING]: binding,
  });
  binding.label = "mutated";
  binding.daManifestChunkerHandle = () => "chunker-mutated";
  binding.sorafsGatewayFetch = () => {
    throw new Error("gateway-mutated");
  };

  await assert.rejects(
    () =>
      client.fetchDaPayloadViaGateway({
        manifestBundle,
        gatewayProviders: providers,
      }),
    /gateway-original:chunker-original/u,
  );
});

test("fetchDaPayloadViaGateway keeps proof generation on the client runtime", async () => {
  const manifestBytes = Buffer.from("proof-runtime-manifest");
  const manifestBundle = {
    storage_ticket_hex: "aa".repeat(32),
    client_blob_id_hex: "cc".repeat(32),
    blob_hash_hex: "bb".repeat(32),
    manifest_hash_hex: "bb".repeat(32),
    chunk_root_hex: "dd".repeat(32),
    chunk_plan: chunkFetchPlan(
      [{ chunk_index: 0, offset: 0, length: 1, digest_blake3: "ee".repeat(32) }],
      "bb".repeat(32),
    ),
    manifest_bytes: manifestBytes,
    manifest_len: manifestBytes.length,
    lane_id: 1,
    epoch: 2,
  };
  const binding = {
    label: "original",
    daGenerateProofs() {
      throw new Error(`proof-${this.label}`);
    },
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("manifest fetch should not run");
    },
    [TORII_TEST_NATIVE_BINDING]: binding,
    ...toriiTestHooks({
      sorafsGatewayFetch: () => ({ payload: Buffer.from("payload") }),
    }),
  });
  binding.label = "mutated";
  binding.daGenerateProofs = () => {
    throw new Error("proof-mutated");
  };

  await assert.rejects(
    () =>
      client.fetchDaPayloadViaGateway({
        manifestBundle,
        chunkerHandle: "sorafs.sf1@1.0.0",
        gatewayProviders: [
          {
            name: "alpha",
            providerIdHex: "11".repeat(32),
            gatewayPublicKeyHex: "dd".repeat(32),
            baseUrl: "https://gateway.test",
            streamTokenB64: Buffer.from("token").toString("base64"),
          },
        ],
        proofSummary: true,
      }),
    /proof-original/u,
  );
});

test("fetchDaPayloadViaGateway reuses provided manifest bundle", async (t) => {
  const gatewayResult = {
    manifestIdHex: "aa".repeat(32),
    chunkerHandle: "sorafs.sf2@2.0.0",
    chunkCount: 2,
    assembledBytes: 256,
    payload: Buffer.from([9]),
    telemetryRegion: "ci",
    anonymity: {
      policy: "anon-guard-pq",
      status: "met",
      reason: "none",
      soranetSelected: 0,
      pqSelected: 0,
      classicalSelected: 0,
      classicalRatio: 0,
      pqRatio: 0,
      candidateRatio: 0,
      deficitRatio: 0,
      supplyDelta: 0,
      brownout: false,
      brownoutEffective: false,
      usesClassical: false,
    },
    providerReports: [],
    chunkReceipts: [],
    localProxyManifest: null,
    carVerification: null,
    metadata: {
      providerCount: 0,
      gatewayProviderCount: 1,
      providerMix: "gateway-only",
      transportPolicy: "soranet-first",
      transportPolicyOverride: false,
      transportPolicyOverrideLabel: null,
      anonymityPolicy: "anon-guard-pq",
      anonymityPolicyOverride: false,
      anonymityPolicyOverrideLabel: null,
      maxParallel: null,
      maxPeers: null,
      retryBudget: null,
      providerFailureThreshold: 1,
      assumeNowUnix: 0,
      telemetrySourceLabel: null,
      gatewayManifestProvided: false,
      gatewayManifestId: "aa".repeat(32),
      gatewayManifestCid: null,
      allowImplicitMetadata: false,
    },
  };
  const gatewayMock = t.mock.fn(() => gatewayResult);
  const manifestBundle = {
    storage_ticket_hex: "ff".repeat(32),
    client_blob_id_hex: "11".repeat(32),
    blob_hash_hex: "aa".repeat(32),
    manifest_hash_hex: "aa".repeat(32),
    chunk_root_hex: "cc".repeat(32),
    lane_id: 1,
    epoch: 1,
    manifest_len: 64,
    manifest_b64: Buffer.from("manifest").toString("base64"),
    manifest_bytes: Buffer.from("manifest"),
    manifest_json: {
      chunking: { namespace: "sorafs", name: "sf2", semver: "2.0.0" },
    },
    chunk_plan: chunkFetchPlan([
      { chunk_index: 0, offset: 0, length: 32, digest_blake3: "ff".repeat(32) },
    ], "aa".repeat(32)),
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("manifest fetch should not be called");
    },
    ...toriiTestHooks({ sorafsGatewayFetch: gatewayMock }),
  });
  const session = await client.fetchDaPayloadViaGateway({
    manifestBundle,
    planJson: JSON.stringify(manifestBundle.chunk_plan),
    chunkerHandle: "sorafs.sf2@2.0.0",
    gatewayProviders: [
      {
        name: "beta",
        providerIdHex: "22".repeat(32),
        gatewayPublicKeyHex: "dd".repeat(32),
        baseUrl: "https://gateway.example/",
        streamTokenB64: "c3R1Yg==",
      },
      {
        name: "gamma",
        providerIdHex: "33".repeat(32),
        gatewayPublicKeyHex: "dd".repeat(32),
        baseUrl: "https://gateway-two.example/",
        streamTokenB64: "c3R1Yi0y",
      },
    ],
  });
  assert.equal(session.chunkerHandle, "sorafs.sf2@2.0.0");
  assert.equal(session.manifestIdHex, "aa".repeat(32));
  assert.equal(gatewayMock.mock.callCount(), 1);
  const [manifestArg] = gatewayMock.mock.calls[0].arguments;
  assert.equal(manifestArg, "aa".repeat(32));
});

test("fetchDaPayloadViaGateway accepts providers alias", async (t) => {
  const manifestBundle = {
    storage_ticket_hex: "12".repeat(32),
    client_blob_id_hex: "34".repeat(32),
    blob_hash_hex: "56".repeat(32),
    manifest_hash_hex: "65".repeat(32),
    chunk_root_hex: "78".repeat(32),
    lane_id: 7,
    epoch: 3,
    manifest_len: 64,
    manifest_b64: Buffer.from("manifest").toString("base64"),
    chunk_plan: chunkFetchPlan([
      { chunk_index: 0, offset: 0, length: 32, digest_blake3: "aa".repeat(32) },
    ], "56".repeat(32)),
  };
  const providers = [
    {
      name: "gamma",
      providerIdHex: "98".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway.test",
      streamTokenB64: Buffer.from("token").toString("base64"),
    },
    {
      name: "delta",
      providerIdHex: "97".repeat(32),
      gatewayPublicKeyHex: "dd".repeat(32),
      baseUrl: "https://gateway-two.test",
      streamTokenB64: Buffer.from("token-2").toString("base64"),
    },
  ];
  const gatewayMock = t.mock.fn(() => ({
    manifestIdHex: manifestBundle.manifest_hash_hex,
    chunkerHandle: "sorafs.sf1@1.0.0",
    chunkCount: 1,
    assembledBytes: 1,
    payload: Buffer.alloc(0),
    telemetryRegion: null,
    anonymity: null,
    providerReports: [],
    chunkReceipts: [],
    localProxyManifest: null,
    carVerification: null,
    metadata: {},
  }));
  const client = new ToriiClient(BASE_URL, {
    ...toriiTestHooks({ sorafsGatewayFetch: gatewayMock }),
  });
  const session = await client.fetchDaPayloadViaGateway({
    manifestBundle,
    chunkerHandle: "sorafs.sf1@1.0.0",
    chunkPlan: manifestBundle.chunk_plan,
    providers,
  });
  assert.equal(session.manifestIdHex, manifestBundle.manifest_hash_hex);
  assert.equal(gatewayMock.mock.callCount(), 1);
  const [, , , providerArg] = gatewayMock.mock.calls[0].arguments;
  const expectedProviders = providers.map((provider) => ({
    ...provider,
    privacyEventsUrl: null,
  }));
  assert.deepEqual(providerArg, expectedProviders);
});

test("fetchDaPayloadViaGateway attaches proof summary when requested", async (t) => {
  const ticketHex = `0x${"ab".repeat(32)}`;
  const blobHashHex = "ee".repeat(32);
  const manifestHashHex = "ff".repeat(32);
  const manifestB64 = Buffer.from("proof-manifest").toString("base64");
  const fetchImpl = async (url, _init) => {
    if (url.endsWith(`/v1/da/manifests/${ticketHex.slice(2)}`)) {
      return createResponse({
        status: 200,
        jsonData: {
        storage_ticket: ticketHex.slice(2),
        client_blob_id: "cc".repeat(32),
        blob_hash: blobHashHex,
        manifest_hash: manifestHashHex,
        chunk_root: "dd".repeat(32),
        lane_id: 1,
        epoch: 2,
        manifest_len: 42,
        manifest: { chunk_profile_handle: "sorafs.sf1@1.0.0" },
          manifest_norito: manifestB64,
          chunk_plan: chunkFetchPlan([
            { chunk_index: 0, offset: 0, length: 32, digest_blake3: "ff".repeat(32) },
          ], blobHashHex),
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected request to ${url}`);
  };
  const gatewayResult = {
    manifestIdHex: manifestHashHex,
    chunkerHandle: "sorafs.sf1@1.0.0",
    chunkCount: 1,
    assembledBytes: 128,
    payload: Buffer.from([5, 6, 7]),
    telemetryRegion: null,
    anonymity: {
      policy: "anon-guard-pq",
      status: "met",
      reason: "none",
      soranetSelected: 0,
      pqSelected: 0,
      classicalSelected: 0,
      classicalRatio: 0,
      pqRatio: 0,
      candidateRatio: 0,
      deficitRatio: 0,
      supplyDelta: 0,
      brownout: false,
      brownoutEffective: false,
      usesClassical: false,
    },
    providerReports: [],
    chunkReceipts: [],
    localProxyManifest: null,
    carVerification: null,
    metadata: {
      providerCount: 0,
      gatewayProviderCount: 1,
      providerMix: "gateway-only",
      transportPolicy: "soranet-first",
      transportPolicyOverride: false,
      transportPolicyOverrideLabel: null,
      anonymityPolicy: "anon-guard-pq",
      anonymityPolicyOverride: false,
      anonymityPolicyOverrideLabel: null,
      maxParallel: null,
      maxPeers: null,
      retryBudget: null,
      providerFailureThreshold: 1,
      assumeNowUnix: 0,
      telemetrySourceLabel: null,
      gatewayManifestProvided: false,
      gatewayManifestId: blobHashHex,
      gatewayManifestCid: null,
      allowImplicitMetadata: false,
    },
  };
  const gatewayMock = t.mock.fn(() => gatewayResult);
  const proofSummary = { blob_hash_hex: blobHashHex, proofs: [] };
  const proofMock = t.mock.fn(() => proofSummary);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    ...toriiTestHooks({
      sorafsGatewayFetch: gatewayMock,
      generateDaProofSummary: proofMock,
    }),
  });
  const providers = [
      {
        name: "alpha",
        providerIdHex: "bb".repeat(32),
        gatewayPublicKeyHex: "dd".repeat(32),
        baseUrl: "https://gateway.test/",
        streamTokenB64: "dG9rZW4=",
      },
      {
        name: "beta",
        providerIdHex: "bc".repeat(32),
        gatewayPublicKeyHex: "dd".repeat(32),
        baseUrl: "https://gateway-two.test/",
        streamTokenB64: "dG9rZW4y",
      },
    ];
  const session = await client.fetchDaPayloadViaGateway({
    storageTicketHex: ticketHex,
    chunkerHandle: "sorafs.sf1@1.0.0",
    gatewayProviders: providers,
    proofSummary: { sampleCount: 2, leafIndexes: [0] },
  });
  assert.equal(session.proofSummary, proofSummary);
  assert.equal(proofMock.mock.callCount(), 1);
  const [manifestArg, payloadArg, optionsArg] = proofMock.mock.calls[0].arguments;
  assert(Buffer.isBuffer(manifestArg));
  assert.equal(manifestArg.toString("base64"), manifestB64);
  assert.equal(payloadArg, gatewayResult.payload);
  assert.deepEqual(optionsArg, { sampleCount: 2, leafIndexes: [0] });
  assert.equal(gatewayMock.mock.callCount(), 1);
});

test("fetchDaPayloadViaGateway rejects invalid manifest_b64 for proof summary", async (t) => {
  const manifestBundle = {
    manifest_hash_hex: "aa".repeat(32),
    manifest_b64: "AAAA====",
    chunk_plan: chunkFetchPlan([
      { chunk_index: 0, offset: 0, length: 1, digest_blake3: "ff".repeat(32) },
    ]),
  };
  const gatewayMock = t.mock.fn(() => ({ payload: Buffer.from([1]) }));
  const client = new ToriiClient(BASE_URL, {
    ...toriiTestHooks({ sorafsGatewayFetch: gatewayMock }),
  });
  await assert.rejects(
    () =>
      client.fetchDaPayloadViaGateway({
        manifestBundle,
        chunkerHandle: "sorafs.sf1@1.0.0",
        gatewayProviders: [
          {
            name: "alpha",
            providerIdHex: "bb".repeat(32),
            gatewayPublicKeyHex: "dd".repeat(32),
            baseUrl: "https://gateway.test/",
            streamTokenB64: "dG9rZW4=",
          },
        ],
        proofSummary: true,
      }),
    /manifest_b64/,
  );
});

const CURRENT_DA_STRIPE_LAYOUT = Object.freeze({
  total_stripes: 1,
  shards_per_stripe: 14,
  row_parity_stripes: 0,
});
const CURRENT_DA_ZERO_RENT_QUOTE = Object.freeze({
  base_rent: "0",
  protocol_reserve: "0",
  provider_reward: "0",
  pdp_bonus: "0",
  potr_bonus: "0",
  egress_credit_per_gib: "0",
});

test("submitDaBlob rejects invalid pdp_commitment payloads", async () => {
  const digest = Array.from({ length: 32 }, (_, index) => index);
  const receipt = {
    client_blob_id: [digest],
    lane_id: 1,
    epoch: 2,
    blob_hash: [digest],
    chunk_root: [digest],
    manifest_hash: [digest],
    storage_ticket: [digest],
    pdp_commitment: "AAAA====",
    stripe_layout: CURRENT_DA_STRIPE_LAYOUT,
    queued_at_unix: 1234,
    operator_signature: "aa".repeat(64),
    rent_quote: CURRENT_DA_ZERO_RENT_QUOTE,
  };
  const fetchImpl = async () =>
    createResponse({
      status: 202,
      jsonData: { status: "accepted", duplicate: false, receipt },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.submitDaBlob({
        networkId: VK_SIGNING_NETWORK_ID,
        owner: SAMPLE_ACCOUNT_OWNER,
        payload: Buffer.from("car-bytes"),
        codec: "nexus_lane_sidecar",
        laneId: 11,
        epoch: 22,
        sequence: 33,
        signerPublicKey: SAMPLE_ACCOUNT_SIGNATORY,
        signatureHex: "aa".repeat(64),
        clientBlobId: Buffer.alloc(32, 0x11),
      }),
    /pdp_commitment/,
  );
});

test("submitDaBlob rejects pre-release receipt omissions and unknown fields", async () => {
  const digest = Array.from({ length: 32 }, (_, index) => index);
  const canonicalReceipt = {
    client_blob_id: [digest],
    lane_id: 1,
    epoch: 2,
    blob_hash: [digest],
    chunk_root: [digest],
    manifest_hash: [digest],
    storage_ticket: [digest],
    pdp_commitment: null,
    stripe_layout: CURRENT_DA_STRIPE_LAYOUT,
    queued_at_unix: 1234,
    operator_signature: "aa".repeat(64),
    rent_quote: CURRENT_DA_ZERO_RENT_QUOTE,
  };
  const cases = [
    ["missing pdp_commitment", (receipt) => delete receipt.pdp_commitment, /pdp_commitment/u],
    ["missing stripe_layout", (receipt) => delete receipt.stripe_layout, /stripe_layout/u],
    ["missing row parity", (receipt) => delete receipt.stripe_layout.row_parity_stripes, /row_parity_stripes/u],
    ["missing rent_quote", (receipt) => delete receipt.rent_quote, /rent_quote/u],
    ["unknown receipt field", (receipt) => { receipt.pre_release_extension = true; }, /unsupported fields.*pre_release_extension/u],
    ["unknown stripe field", (receipt) => { receipt.stripe_layout.pre_release_extension = true; }, /unsupported fields.*pre_release_extension/u],
  ];

  for (const [label, mutate, pattern] of cases) {
    const receipt = structuredClone(canonicalReceipt);
    mutate(receipt);
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 202,
          jsonData: { status: "accepted", duplicate: false, receipt },
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () =>
        client.submitDaBlob({
          networkId: VK_SIGNING_NETWORK_ID,
          owner: SAMPLE_ACCOUNT_OWNER,
          payload: Buffer.from("car-bytes"),
          codec: "nexus_lane_sidecar",
          laneId: 11,
          epoch: 22,
          sequence: 33,
          signerPublicKey: SAMPLE_ACCOUNT_SIGNATORY,
          signatureHex: "aa".repeat(64),
          clientBlobId: Buffer.alloc(32, 0x11),
        }),
      pattern,
      label,
    );
  }

});

test("submitDaBlob rejects coercible non-byte digest entries in responses", async () => {
  const validDigest = Array.from({ length: 32 }, (_, index) => index);
  for (const entry of ["1", true, null]) {
    const clientBlobId = [...validDigest];
    clientBlobId[0] = entry;
    const receipt = {
      client_blob_id: [clientBlobId],
      lane_id: 1,
      epoch: 2,
      blob_hash: [validDigest],
      chunk_root: [validDigest],
      manifest_hash: [validDigest],
      storage_ticket: [validDigest],
      pdp_commitment: null,
      stripe_layout: CURRENT_DA_STRIPE_LAYOUT,
      queued_at_unix: 1234,
      operator_signature: "aa".repeat(64),
      rent_quote: CURRENT_DA_ZERO_RENT_QUOTE,
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 202,
          jsonData: { status: "accepted", duplicate: false, receipt },
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () =>
        client.submitDaBlob({
          networkId: VK_SIGNING_NETWORK_ID,
          owner: SAMPLE_ACCOUNT_OWNER,
          payload: Buffer.from("car-bytes"),
          codec: "nexus_lane_sidecar",
          laneId: 11,
          epoch: 22,
          sequence: 33,
          signerPublicKey: SAMPLE_ACCOUNT_SIGNATORY,
          signatureHex: "aa".repeat(64),
          clientBlobId: Buffer.alloc(32, 0x11),
        }),
      /client_blob_id\[0\]/,
    );
  }
});

nativeTest("submitDaBlob builds ingest payload and normalizes response", async () => {
  let captured = null;
  const digest = Array.from({ length: 32 }, (_, index) => index);
  const receipt = {
    client_blob_id: [digest],
    lane_id: 1,
    epoch: 2,
    blob_hash: [digest.map((value) => (value + 1) & 0xff)],
    chunk_root: [digest.map((value) => (value + 2) & 0xff)],
    manifest_hash: [digest.map((value) => (value + 3) & 0xff)],
    storage_ticket: [digest.map((value) => (value + 4) & 0xff)],
    pdp_commitment: Buffer.from("commitment").toString("base64"),
    stripe_layout: CURRENT_DA_STRIPE_LAYOUT,
    queued_at_unix: 1234,
    operator_signature: "aa".repeat(64),
    rent_quote: {
      base_rent: "100",
      protocol_reserve: "25",
      provider_reward: "75",
      pdp_bonus: "5",
      potr_bonus: "3",
      egress_credit_per_gib: "2",
    },
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: { status: "accepted", duplicate: false, receipt },
      headers: {
        "content-type": "application/json",
        "sora-pdp-commitment": Buffer.from("header").toString("base64"),
      },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.submitDaBlob({
    networkId: VK_SIGNING_NETWORK_ID,
    owner: SEED_11_OWNER,
    payload: Buffer.from("car-bytes"),
    codec: "nexus_lane_sidecar",
    laneId: 11,
    epoch: 22,
    sequence: 33,
    retentionPolicy: { governanceTag: "da.demo", storageClass: "Warm" },
    metadata: [{ key: "content-type", value: "application/car" }],
    privateKeyHex: "11".repeat(32),
  });
  assert.equal(captured?.url, `${BASE_URL}/v1/da/ingest`);
  assert.equal(captured?.init?.method, "POST");
  assert.equal(
    captured?.init?.headers?.["Content-Type"],
    "application/json",
  );
  assert.equal(captured?.init?.headers?.Accept, "application/json");
  const submitted = JSON.parse(captured?.init?.body ?? "{}");
  assert.equal(submitted.blob_class.class, "TaikaiSegment");
  assert.equal(submitted.codec[0], "nexus_lane_sidecar");
  assert.equal(submitted.compression, "Identity");
  assert.equal(submitted.norito_manifest, null);
  assert.equal(submitted.metadata.items[0].key, "content-type");
  assert.equal(
    Buffer.from(submitted.metadata.items[0].value, "base64").toString("utf8"),
    "application/car",
  );
  const requestDigest = Buffer.from(submitted.client_blob_id[0]);
  assert.equal(
    requestDigest.toString("hex").toUpperCase(),
    result.artifacts.clientBlobIdHex,
  );
  assert.equal(result.status, "accepted");
  assert.equal(result.duplicate, false);
  assert.equal(result.pdpCommitmentHeader, Buffer.from("header").toString("base64"));
  assert.ok(result.receipt);
  assert.equal(result.receipt?.lane_id, 1);
  assert.equal(result.receipt?.blob_hash_bytes.length, 32);
  assert.equal(
    result.receipt?.client_blob_id_hex,
    Buffer.from(digest).toString("hex").toUpperCase(),
  );
  assert.deepEqual(result.receipt?.rent_quote, {
    base_rent: "100",
    protocol_reserve: "25",
    provider_reward: "75",
    pdp_bonus: "5",
    potr_bonus: "3",
    egress_credit_per_gib: "2",
  });
});

nativeTest("submitDaBlob writes artefacts when artifactDir is set", async () => {
  const digest = Array.from({ length: 32 }, (_, index) => index);
  const receipt = {
    client_blob_id: [digest],
    lane_id: 1,
    epoch: 2,
    blob_hash: [digest.map((value) => (value + 1) & 0xff)],
    chunk_root: [digest.map((value) => (value + 2) & 0xff)],
    manifest_hash: [digest.map((value) => (value + 3) & 0xff)],
    storage_ticket: [digest.map((value) => (value + 4) & 0xff)],
    pdp_commitment: Buffer.from("commitment").toString("base64"),
    stripe_layout: CURRENT_DA_STRIPE_LAYOUT,
    queued_at_unix: 1234,
    operator_signature: "aa".repeat(64),
    rent_quote: CURRENT_DA_ZERO_RENT_QUOTE,
  };
  const fetchImpl = async () =>
    createResponse({
      status: 202,
      jsonData: { status: "accepted", duplicate: false, receipt },
      headers: {
        "content-type": "application/json",
        "sora-pdp-commitment": Buffer.from("header").toString("base64"),
      },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const dir = await fs.mkdtemp(path.join(tmpdir(), "tmp-js-da-submit-"));
  try {
    const result = await client.submitDaBlob({
      networkId: VK_SIGNING_NETWORK_ID,
      owner: SEED_11_OWNER,
      payload: Buffer.from("car-bytes"),
      codec: "nexus_lane_sidecar",
      laneId: 11,
      epoch: 22,
      sequence: 33,
      retentionPolicy: { governanceTag: "da.demo", storageClass: "Warm" },
      metadata: [{ key: "content-type", value: "application/car" }],
      privateKeyHex: "11".repeat(32),
      artifactDir: dir,
    });
    assert.ok(result.artifactPaths);
    const { artifactPaths } = result;
    const requestJson = JSON.parse(
      await fs.readFile(artifactPaths?.requestJsonPath ?? "", "utf8"),
    );
    assert.equal(requestJson.lane_id, 11);
    const receiptJson = JSON.parse(
      await fs.readFile(artifactPaths?.receiptJsonPath ?? "", "utf8"),
    );
    assert.equal(receiptJson?.queued_at_unix, receipt.queued_at_unix);
    const headersJson = JSON.parse(
      await fs.readFile(artifactPaths?.responseHeadersPath ?? "", "utf8"),
    );
    assert.equal(
      headersJson["sora-pdp-commitment"],
      Buffer.from("header").toString("base64"),
    );
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

nativeTest("submitDaBlob requires signing inputs", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 500 }) });
  await assert.rejects(
    () =>
      client.submitDaBlob({
        networkId: VK_SIGNING_NETWORK_ID,
        owner: SEED_11_OWNER,
        payload: Buffer.from("demo"),
        codec: "application/octet-stream",
      }),
    /privateKey/i,
  );
});

test("proveDaAvailabilityToDir persists CLI artefacts", async () => {
  const ticketHex = `0x${"ab".repeat(32)}`;
  const manifestBytes = Buffer.from("manifest");
  const manifestB64 = manifestBytes.toString("base64");
  const chunkPlan = chunkFetchPlan([
    { chunk_index: 0, offset: 0, length: 4, digest_blake3: "aa".repeat(32) },
  ], "dd".repeat(32));
  const payload = Buffer.from("payload-bytes");
  const proofSummary = {
    blob_hash_hex: "11".repeat(32),
    chunk_root_hex: "22".repeat(32),
    por_root_hex: "33".repeat(32),
    leaf_count: 1,
    segment_count: 1,
    chunk_count: 1,
    sample_count: 1,
    sample_seed: 0,
    proof_count: 1,
    proofs: [
      {
        origin: "sampled",
        leaf_index: 0,
        chunk_index: 0,
        segment_index: 0,
        leaf_offset: 0,
        leaf_length: 1,
        segment_offset: 0,
        segment_length: 1,
        chunk_offset: 0,
        chunk_length: 1,
        payload_len: payload.length,
        chunk_digest_hex: "aa".repeat(32),
        chunk_root_hex: "bb".repeat(32),
        segment_digest_hex: "cc".repeat(32),
        leaf_digest_hex: "dd".repeat(32),
        leaf_bytes_b64: Buffer.from([0]).toString("base64"),
        segment_leaves_hex: [],
        chunk_segments_hex: [],
        chunk_count: 1n,
        chunk_merkle_path_hex: [],
        verified: true,
      },
    ],
  };
  const fetchImpl = async (url) => {
    if (url.endsWith(`/v1/da/manifests/${ticketHex.slice(2).toLowerCase()}`)) {
      return createResponse({
        status: 200,
        jsonData: {
          storage_ticket: ticketHex.slice(2),
          client_blob_id: "cc".repeat(32),
          blob_hash: "dd".repeat(32),
          manifest_hash: "ff".repeat(32),
          chunk_root: "ee".repeat(32),
          lane_id: 7,
          epoch: 9,
          manifest_len: 7,
          manifest_norito: manifestB64,
          manifest: { version: 1 },
          chunk_plan: chunkPlan,
        },
        headers: { "content-type": "application/json" },
      });
    }
    return createResponse({ status: 404 });
  };
  const gatewayResult = {
    manifest_id_hex: "dd".repeat(32),
    chunker_handle: "sorafs.sf1@1.0.0",
    chunk_count: 1,
    assembled_bytes: payload.length,
    payload,
    telemetry_region: "region-x",
    provider_reports: [],
    chunk_receipts: [],
    metadata: {},
    scoreboard: [
      {
        provider_id: "ff".repeat(32),
        alias: "gw-alpha",
        raw_score: 10,
        normalized_weight: 1,
        eligibility: "eligible",
      },
    ],
  };
  const tmpDir = await fs.mkdtemp(path.join(tmpdir(), "tmp-js-da-prove-"));
  let proofCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    ...toriiTestHooks({
      sorafsGatewayFetch: async () => gatewayResult,
      generateDaProofSummary: async () => {
        proofCalls += 1;
        return proofSummary;
      },
    }),
  });
  try {
    const result = await client.proveDaAvailabilityToDir({
      storageTicketHex: ticketHex,
      gatewayProviders: [
        {
          name: "alpha",
          providerIdHex: "bb".repeat(32),
          gatewayPublicKeyHex: "dd".repeat(32),
          baseUrl: "https://gateway.test/",
          streamTokenB64: Buffer.from("token").toString("base64"),
        },
        {
          name: "beta",
          providerIdHex: "bc".repeat(32),
          gatewayPublicKeyHex: "dd".repeat(32),
          baseUrl: "https://gateway-two.test/",
          streamTokenB64: Buffer.from("token-2").toString("base64"),
        },
	      ],
	      chunkerHandle: gatewayResult.chunker_handle,
	      proofSummary: { sampleCount: 1 },
	      outputDir: tmpDir,
	    });
    const label = ticketHex.slice(2).toLowerCase();
    const manifestPath = path.join(tmpDir, `manifest_${label}.norito`);
    const chunkPlanPath = path.join(tmpDir, `chunk_plan_${label}.json`);
    const payloadPath = path.join(tmpDir, `payload_${label}.car`);
    const proofPath = path.join(tmpDir, `proof_summary_${label}.json`);
    const scoreboardPath = path.join(tmpDir, "scoreboard.json");

    assert(result.gatewayResult.scoreboard);
    assert.ok(await fileExists(manifestPath));
    assert.ok(await fileExists(chunkPlanPath));
    assert.ok(await fileExists(payloadPath));
    assert.ok(await fileExists(proofPath));
    assert.ok(await fileExists(scoreboardPath));
    assert.equal(proofCalls, 1);

    const scoreboardJson = JSON.parse(await fs.readFile(scoreboardPath, "utf8"));
    assert.equal(scoreboardJson[0].alias, "gw-alpha");

    const withoutProof = await client.proveDaAvailabilityToDir({
      storageTicketHex: ticketHex,
      gatewayProviders: [
        {
          name: "alpha",
          providerIdHex: "bb".repeat(32),
          gatewayPublicKeyHex: "dd".repeat(32),
          baseUrl: "https://gateway.test/",
          streamTokenB64: Buffer.from("token").toString("base64"),
        },
        {
          name: "beta",
          providerIdHex: "bc".repeat(32),
          gatewayPublicKeyHex: "dd".repeat(32),
          baseUrl: "https://gateway-two.test/",
          streamTokenB64: Buffer.from("token-2").toString("base64"),
        },
      ],
      chunkerHandle: gatewayResult.chunker_handle,
      proofSummary: false,
      outputDir: path.join(tmpDir, "without-proof"),
    });
    assert.equal(withoutProof.proofSummary, null);
    assert.equal(withoutProof.proofSummaryPath, null);
    assert.equal(withoutProof.proofSummaryArtifact, null);
    assert.equal(proofCalls, 1);
    const proofJson = JSON.parse(await fs.readFile(proofPath, "utf8"));
    assert.equal(proofJson.sample_count, 1);
    assert.equal(proofJson.manifest_path, manifestPath);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test("retired PoR challenge and observation SDK methods are absent", () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("retired PoR method must not issue a request");
    },
  });
  assert.equal("recordSorafsPorChallenge" in client, false);
  assert.equal("submitSorafsPorObservation" in client, false);
  assert.equal("submitSorafsUptimeObservation" in client, false);
  assert.equal(typeof client.recordSorafsPorProof, "function");
  assert.equal(typeof client.recordSorafsPorVerdict, "function");
  assert.equal(typeof client.getSorafsPorStatus, "function");
});
test("recordSorafsPorProof rejects unsupported input fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: { status: "accepted" },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () =>
      client.recordSorafsPorProof({
        proof: Buffer.from("ok"),
        trailing: "field",
      }),
    /recordSorafsPorProof input contains unsupported fields: trailing/,
  );
});

test("recordSorafsPorVerdict rejects unsupported input fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: { status: "accepted" },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () =>
      client.recordSorafsPorVerdict({
        verdict: Buffer.from("ok"),
        trailing: "field",
      }),
    /recordSorafsPorVerdict input contains unsupported fields: trailing/,
  );
});

const invalidSorafsSignalCases = [
  {
    label: "recordSorafsPorProof",
    invoke: (client) =>
      client.recordSorafsPorProof({
        proof: Buffer.from("proof"),
        signal: "invalid",
      }),
    path: "recordSorafsPorProof.options.signal",
  },
  {
    label: "recordSorafsPorVerdict",
    invoke: (client) =>
      client.recordSorafsPorVerdict({
        verdict: Buffer.from("verdict"),
        signal: "invalid",
      }),
    path: "recordSorafsPorVerdict.options.signal",
  },
];

for (const { label, invoke, path } of invalidSorafsSignalCases) {
  test(`${label} rejects non-AbortSignal \`signal\` option`, async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run for invalid signal options");
      },
    });
    await assert.rejects(
      () => invoke(client),
      (error) => {
        assert(error instanceof ValidationError);
        assert.equal(error.code, ValidationErrorCode.INVALID_OBJECT);
        assert.equal(error.path, path);
        assert.match(
          error.message,
          new RegExp(`${label} options\\.signal must be an AbortSignal`),
        );
        return true;
      },
    );
  });
}

test("getSorafsPorStatus returns Norito bytes", async () => {
  const responseBytes = Buffer.from([1, 2, 3, 4]);
  let capturedUrl;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      arrayData: responseBytes,
      headers: { "content-type": "application/x-norito" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const buffer = await client.getSorafsPorStatus({
    providerHex: "f".repeat(64),
    limit: 7,
    maxBytes: 8_192,
    cursor: "AA",
  });
  assert(buffer.equals(responseBytes));
  const params = new URL(capturedUrl).searchParams;
  assert.equal(params.get("provider"), "f".repeat(64));
  assert.equal(params.get("limit"), "7");
  assert.equal(params.get("max_bytes"), "8192");
  assert.equal(params.get("cursor"), "AA");
});

test("exportSorafsPorStatus normalizes an exact paired range and opaque cursor", async () => {
  const responseBytes = Buffer.from([5, 6, 7, 8]);
  let capturedUrl;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({ status: 200, arrayData: responseBytes });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const buffer = await client.exportSorafsPorStatus({
    startEpoch: 41,
    endEpoch: 43,
    limit: 9,
    maxBytes: 16_384,
    cursor: "AA",
  });
  assert(buffer.equals(responseBytes));
  const params = new URL(capturedUrl).searchParams;
  assert.equal(params.get("start_epoch"), "41");
  assert.equal(params.get("end_epoch"), "43");
  assert.equal(params.get("limit"), "9");
  assert.equal(params.get("max_bytes"), "16384");
  assert.equal(params.get("cursor"), "AA");

  await assert.rejects(
    () => client.exportSorafsPorStatus({ startEpoch: 41 }),
    /startEpoch and sorafsPorExport\.endEpoch must be supplied together/,
  );
});

test("SoraFS registry helpers reject non-object options", async () => {
  const client = new ToriiClient(BASE_URL);
  await assert.rejects(
    () => client.listSorafsAliases("invalid"),
    /listSorafsAliases options must be an object/,
  );
  await assert.rejects(
    () => client.listSorafsPinManifests("invalid"),
    /listSorafsPinManifests options must be an object/,
  );
  await assert.rejects(
    () => client.listSorafsReplicationOrders("invalid"),
    /listSorafsReplicationOrders options must be an object/,
  );
  await assert.rejects(
    () => client.getSorafsPinManifest("deadbeef".repeat(8), "invalid"),
    /getSorafsPinManifest options must be an object/,
  );
});

test("SoraFS registry helpers reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for option validation");
    },
  });
  const cases = [
    [
      "listSorafsAliases",
      () => client.listSorafsAliases({
        namespace: "sorafs",
        extra: true,
        canonicalAuth: SORAFS_CANONICAL_AUTH,
      }),
      "extra",
    ],
    [
      "listSorafsPinManifests",
      () => client.listSorafsPinManifests({ status: "pending", bogus: true }),
      "bogus",
    ],
    [
      "listSorafsReplicationOrders",
      () =>
        client.listSorafsReplicationOrders({
          status: "pending",
          manifestDigestHex: "a".repeat(64),
          stray: 1,
          canonicalAuth: SORAFS_CANONICAL_AUTH,
        }),
      "stray",
    ],
  ];
  for (const [label, invoke, field] of cases) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(invoke, (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        new RegExp(`${label} options contains unsupported fields: ${field}`),
      );
      return true;
    });
  }
});

test("SoraFS legacy inventory helpers require canonical account authentication", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run without canonical authentication");
    },
  });
  await assert.rejects(
    () => client.listSorafsAliases({ namespace: "sorafs" }),
    /listSorafsAliases options\.canonicalAuth is required/,
  );
  await assert.rejects(
    () => client.listSorafsReplicationOrders({ status: "pending" }),
    /listSorafsReplicationOrders options\.canonicalAuth is required/,
  );
});

test("SoraFS POR helpers reject non-object options", async () => {
  const client = new ToriiClient(BASE_URL);
  await assert.rejects(
    () => client.getSorafsPorStatus("invalid"),
    /getSorafsPorStatus options must be an object/,
  );
  await assert.rejects(
    () => client.exportSorafsPorStatus("invalid"),
    /exportSorafsPorStatus options must be an object/,
  );
  await assert.rejects(
    () => client.getSorafsPorWeeklyReport("2026-W05", "invalid"),
    /getSorafsPorWeeklyReport options must be an object/,
  );
});

test("SoraFS POR helpers reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for option validation");
    },
  });
  const cases = [
    [
      "getSorafsPorStatus",
      () => client.getSorafsPorStatus({ extra: true }),
      "extra",
    ],
    [
      "exportSorafsPorStatus",
      () => client.exportSorafsPorStatus({ extra: true }),
      "extra",
    ],
    [
      "getSorafsPorWeeklyReport",
      () => client.getSorafsPorWeeklyReport("2026-W05", { extra: true }),
      "extra",
    ],
  ];
  for (const [label, invoke, field] of cases) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(invoke, (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        new RegExp(`${label} options contains unsupported fields: ${field}`),
      );
      return true;
    });
  }
});

test("getSorafsPorWeeklyReport validates ISO week input", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for invalid ISO week inputs");
    },
  });
  await assert.rejects(
    () => client.getSorafsPorWeeklyReport(""),
    (error) => expectValidationErrorFixture(error, "getSorafsPorWeeklyReport_iso_week_empty"),
  );
  await assert.rejects(
    () => client.getSorafsPorWeeklyReport("2026W05"),
    (error) => expectValidationErrorFixture(error, "getSorafsPorWeeklyReport_iso_week_format"),
  );
  await assert.rejects(
    // @ts-expect-error intentional invalid input
    () => client.getSorafsPorWeeklyReport(42),
    (error) => expectValidationErrorFixture(error, "getSorafsPorWeeklyReport_iso_week_type"),
  );
  await assert.rejects(
    () => client.getSorafsPorWeeklyReport({ year: 2026, week: 60 }),
    (error) => expectValidationErrorFixture(error, "getSorafsPorWeeklyReport_iso_week_range"),
  );
});

test("getSorafsPorWeeklyReport accepts ISO week objects", async () => {
  const payload = Buffer.from([1, 2, 3]);
  let requestedUrl = null;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url) => {
      requestedUrl = url;
      return createResponse({ status: 200, arrayData: payload });
    },
  });
  const result = await client.getSorafsPorWeeklyReport({ year: 2027, week: 5 });
  assert.equal(requestedUrl, `${BASE_URL}/v1/sorafs/por/report/2027-W05`);
  assert.ok(Buffer.isBuffer(result));
  assert.deepEqual(result, Buffer.from(payload));
});

test("SoraFS storage helpers reject non-object options", async () => {
  const client = new ToriiClient(BASE_URL);
  await assert.rejects(
    () => client.getSorafsStorageState("invalid"),
    /getSorafsStorageState options must be an object/,
  );
  await assert.rejects(
    () => client.getSorafsManifest("ab".repeat(32), "invalid"),
    /getSorafsManifest options must be an object/,
  );
  await assert.rejects(
    () => client.getDaManifest("ff".repeat(32), "invalid"),
    /getDaManifest options must be an object/,
  );
});

test("SoraFS storage helpers reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL);
  const cases = [
    ["getSorafsStorageState", () => client.getSorafsStorageState({ extra: true }), "extra"],
    [
      "getSorafsManifest",
      () => client.getSorafsManifest("ab".repeat(32), { unexpected: "nope" }),
      "unexpected",
    ],
    [
      "getDaManifest",
      () => client.getDaManifest("ff".repeat(32), { blockHashHex: "aa".repeat(32) }),
      "blockHashHex",
    ],
    [
      "getDaManifestToDir",
      () => client.getDaManifestToDir("ff".repeat(32), { blockHashHex: "aa".repeat(32) }),
      "blockHashHex",
    ],
  ];
  for (const [label, invoke, field] of cases) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(invoke, (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        new RegExp(`${label} options contains unsupported fields: ${field}`),
      );
      return true;
    });
  }
});

test("DA and UAID helpers reject non-object options", async () => {
  const client = new ToriiClient(BASE_URL);
  await assert.rejects(
    () => client.submitDaBlob("invalid"),
    /submitDaBlob options must be an object/,
  );
  const uaid = `uaid:${"11".repeat(32)}`;
  await assert.rejects(
    () => client.getUaidPortfolio(uaid, "invalid"),
    /getUaidPortfolio options must be an object/,
  );
  await assert.rejects(
    () => client.getUaidBindings(uaid, "invalid"),
    /getUaidBindings options must be an object/,
  );
  await assert.rejects(
    () => client.uaidManifests(uaid).list("invalid"),
    /query must be an object|JSON object|plain object/,
  );
});

test("submitIsoPacs008 posts XML payload", async () => {
  let captured;
  const payload = createIsoSubmissionPayload({ message_id: "msg-1" });
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const xml = "<Document>hello</Document>";
  const response = await client.submitIsoPacs008(xml);
  assert.equal(captured.url, `${BASE_URL}/v1/iso20022/pacs008`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["Content-Type"], "application/xml");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.ok(Buffer.isBuffer(captured.init.body));
  assert.equal(captured.init.body.toString("utf8"), xml);
  assert.deepEqual(response, payload);
});

test("submitIsoPacs009 posts XML payload", async () => {
  let captured;
  const payload = createIsoSubmissionPayload({ message_id: "msg-2" });
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const xml = "<Document>funding</Document>";
  const response = await client.submitIsoPacs009(xml, {
    contentType: "application/xml",
  });
  assert.equal(captured.url, `${BASE_URL}/v1/iso20022/pacs009`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["Content-Type"], "application/xml");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.ok(Buffer.isBuffer(captured.init.body));
  assert.equal(captured.init.body.toString("utf8"), xml);
  assert.deepEqual(response, payload);
});

test("submitIsoMessage builds pacs.008 XML and posts with defaults", async () => {
  const calls = [];
  const payload = createIsoSubmissionPayload({ message_id: "built-iso" });
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return createResponse({
      status: 202,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const response = await client.submitIsoMessage({
    messageId: "built-iso",
    instructionId: "instr-iso",
    creationDateTime: "2026-02-01T00:00:00Z",
    amount: { currency: "EUR", value: "5.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
  });

  assert.equal(calls.length, 1);
  const [call] = calls;
  assert.equal(call.url, `${BASE_URL}/v1/iso20022/pacs008`);
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.headers["Content-Type"], "application/pacs008+xml");
  assert.equal(call.init.headers.Accept, "application/json");
  const xml = call.init.body?.toString("utf8") ?? "";
  assert.match(xml, /<MsgId>built-iso<\/MsgId>/);
  assert.match(xml, /<CreDtTm>2026-02-01T00:00:00\.000Z<\/CreDtTm>/);
  assert.match(xml, /<InstrId>instr-iso<\/InstrId>/);
  assert.match(xml, /<IntrBkSttlmAmt Ccy="EUR">5\.00<\/IntrBkSttlmAmt>/);
  assert.deepEqual(response, payload);
});

test("submitIsoMessage requires explicit creationDateTime", async () => {
  let fetched = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetched = true;
      throw new Error("submitIsoMessage should reject before fetching");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoMessage({
        messageId: "built-iso",
        instructionId: "instr-iso",
        amount: { currency: "EUR", value: "5.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
      }),
    /creationDateTime is required/,
  );
  assert.equal(fetched, false);
});

test("submitIsoMessage rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("submitIsoMessage should reject before fetching");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoMessage(
        {
          messageId: "built-iso",
          instructionId: "instr-iso",
          amount: { currency: "EUR", value: "5.00" },
          instigatingAgent: { bic: "DEUTDEFF" },
          instructedAgent: { bic: "COBADEFF" },
        },
        { kind: "pacs.008", wait: { maxAttempts: 1 }, extra: true },
      ),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /submitIsoMessage options contains unsupported fields: extra/);
      return true;
    },
  );
});

test("submitIsoMessage rejects mismatched kind aliases", async () => {
  let fetched = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetched = true;
      throw new Error("submitIsoMessage should reject before fetching");
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoMessage(
        {
          messageId: "iso-mismatch",
          instructionId: "instr-iso",
          amount: { currency: "EUR", value: "5.00" },
          instigatingAgent: { bic: "DEUTDEFF" },
          instructedAgent: { bic: "COBADEFF" },
        },
        { kind: "pacs.008", messageKind: "pacs.009" },
      ),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        /submitIsoMessage options\.kind and options\.messageKind must match/,
      );
      return true;
    },
  );
  assert.equal(fetched, false);
});

test("submitIsoMessage rejects unsupported ISO message kinds", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("submitIsoMessage should reject before fetching");
    },
  });
  const messageFields = {
    messageId: "iso-invalid-kind",
    instructionId: "instr-invalid-kind",
    amount: { currency: "EUR", value: "1.23" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
  };
  await assert.rejects(
    () => client.submitIsoMessage(messageFields, { kind: "pacs.007" }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.path, "submitIsoMessage.options.kind");
      assert.match(error.message, /pacs\.008' or 'pacs\.009/);
      return true;
    },
  );
  await assert.rejects(
    () => client.submitIsoMessage(messageFields, { messageKind: " pacs.010 " }),
    (error) => {
      assert(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.path, "submitIsoMessage.options.messageKind");
      assert.match(error.message, /pacs\.008' or 'pacs\.009/);
      return true;
    },
  );
});

test("submitIsoMessage supports pacs.009 wait flow and reuses signals", async () => {
  const calls = [];
  const controller = new AbortController();
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async (_method, url, init = {}) => {
    calls.push({ url, init });
    if (url === "/v1/iso20022/pacs009") {
      return createResponse({
        status: 202,
        jsonData: createIsoSubmissionPayload({ message_id: "flow-009" }),
        headers: { "content-type": "application/json" },
      });
    }
    if (url === "/v1/iso20022/messages/flow-009") {
      return createResponse({
        status: 200,
        jsonData: createIsoStatusPayload({
          message_id: "flow-009",
          status: "Accepted",
          transaction_hash: "h-1",
        }),
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected url ${url}`);
  };
  const status = await client.submitIsoMessage(
    {
      instructionId: "flow-009",
      amount: { currency: "USD", value: "12.5" },
      instigatingAgent: { bic: "BOFAUS3N" },
      instructedAgent: { bic: "DEUTDEFF" },
      creationDateTime: "2026-02-01T00:00:00Z",
    },
    {
      kind: "pacs.009",
      signal: controller.signal,
      retryProfile: "iso-flow",
      wait: { maxAttempts: 1, pollIntervalMs: 0 },
    },
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "/v1/iso20022/pacs009");
  assertRequestSignal(calls[0].init.signal, controller.signal);
  assert.equal(calls[0].init.retryProfile, "iso-flow");
  assert.equal(calls[0].init.headers["Content-Type"], "application/pacs009+xml");
  assert.equal(calls[1].url, "/v1/iso20022/messages/flow-009");
  assertRequestSignal(calls[1].init.signal, controller.signal);
  assert.equal(calls[1].init.retryProfile, "iso-flow");
  assert.equal(status.status, "Accepted");
  assert.equal(status.transaction_hash, "h-1");
});

test("submitIsoMessage resolves accepted status without transaction hash when requested", async () => {
  const calls = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async (_method, url, init = {}) => {
    calls.push({ url, init });
    if (url === "/v1/iso20022/pacs008") {
      return createResponse({
        status: 202,
        jsonData: createIsoSubmissionPayload({ message_id: "accept-no-tx" }),
        headers: { "content-type": "application/json" },
      });
    }
    if (url === "/v1/iso20022/messages/accept-no-tx") {
      return createResponse({
        status: 200,
        jsonData: createIsoStatusPayload({
          message_id: "accept-no-tx",
          status: "Accepted",
          transaction_hash: null,
        }),
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected url ${url}`);
  };

  const status = await client.submitIsoMessage(
    {
      messageId: "accept-no-tx",
      instructionId: "instr-accept-no-tx",
      creationDateTime: "2026-02-01T00:00:00Z",
      amount: { currency: "EUR", value: "1.00" },
      instigatingAgent: { bic: "DEUTDEFF" },
      instructedAgent: { bic: "COBADEFF" },
    },
    {
      kind: "pacs.008",
      wait: {
        maxAttempts: 1,
        pollIntervalMs: 0,
        resolveOnAcceptedWithoutTransaction: true,
      },
    },
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "/v1/iso20022/pacs008");
  assert.equal(calls[1].url, "/v1/iso20022/messages/accept-no-tx");
  assert.equal(status.status, "Accepted");
  assert.equal(status.transaction_hash, null);
});

test("submitIsoPacs008AndWait reuses signal and retryProfile for polling", async () => {
  const calls = [];
  const controller = new AbortController();
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async (_method, url, init = {}) => {
    calls.push({ url, init });
    if (url === "/v1/iso20022/pacs008") {
      return createResponse({
        status: 202,
        jsonData: createIsoSubmissionPayload({ message_id: "reuse-008" }),
        headers: { "content-type": "application/json" },
      });
    }
    if (url === "/v1/iso20022/messages/reuse-008") {
      return createResponse({
        status: 200,
        jsonData: createIsoStatusPayload({
          message_id: "reuse-008",
          status: "Accepted",
          transaction_hash: "0xiso008",
        }),
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected url ${url}`);
  };

  const status = await client.submitIsoPacs008AndWait("<Document/>", {
    signal: controller.signal,
    retryProfile: "iso-wait",
    wait: { maxAttempts: 1, pollIntervalMs: 0 },
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "/v1/iso20022/pacs008");
  assertRequestSignal(calls[0].init.signal, controller.signal);
  assert.equal(calls[0].init.retryProfile, "iso-wait");
  assert.equal(calls[1].url, "/v1/iso20022/messages/reuse-008");
  assertRequestSignal(calls[1].init.signal, controller.signal);
  assert.equal(calls[1].init.retryProfile, "iso-wait");
  assert.equal(status.status, "Accepted");
  assert.equal(status.transaction_hash, "0xiso008");
});

test("getIsoMessageStatus fetches status payload", async () => {
  let requestedUrl;
  const payload = createIsoStatusPayload({
    message_id: "msg-2",
    transaction_hash: "abc",
    detail: "accepted",
    updated_at_ms: 123,
  });
  const fetchImpl = async (url) => {
    requestedUrl = url;
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const status = await client.getIsoMessageStatus("msg-2");
  assert.equal(requestedUrl, `${BASE_URL}/v1/iso20022/messages/msg-2`);
  assert.deepEqual(status, payload);
});

test("getIsoMessageStatus preserves schema-V3 settlement and plan provenance", async () => {
  const payload = createIsoStatusPayload({
    message_id: "msg-v3",
    status: "Committed",
    settlement_amount: "1250.00",
    settlement_currency: "USD",
    settlement_date: "2026-09-02",
    settlement_quantity: "25",
    settlement_movement_type: "DELIVERY",
    settlement_payment_type: "AGAINST_PAYMENT",
    security_instrument_id: "US0378331005",
    collateral_obligation_id: "COLL-42",
    collateral_original_amount: "1000",
    collateral_original_currency: "USD",
    collateral_original_instrument_id: "US0000000001",
    collateral_substitute_amount: "990",
    collateral_substitute_currency: "EUR",
    collateral_substitute_instrument_id: "EU0000000002",
    collateral_effective_date: "2026-09-03",
    collateral_substitution_type: "FULL",
    collateral_haircut: "0.01",
    collateral_reason_code: "SUBS",
    plan_execution_order: "1",
    plan_atomicity: "atomic",
  });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    }),
  });

  assert.deepEqual(await client.getIsoMessageStatus("msg-v3"), payload);
});

test("getIsoMessageStatus forwards retryProfile to _request", async () => {
  let capturedRetryProfile;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  client._request = async (method, url, init = {}) => {
    capturedRetryProfile = init.retryProfile ?? null;
    return createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "rp",
        status: "Committed",
        transaction_hash: "0xabc",
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const status = await client.getIsoMessageStatus("rp", { retryProfile: "iso-status" });
  assert.equal(status?.transaction_hash, "0xabc");
  assert.equal(capturedRetryProfile, "iso-status");
});

test("getIsoMessageStatus rejects invalid retryProfile overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.getIsoMessageStatus("msg-2", {
        // @ts-expect-error runtime validation should reject incorrect type
        retryProfile: 123,
      }),
    (error) => expectValidationErrorFixture(error, "getIsoMessageStatus_retry_profile_type"),
  );
  await assert.rejects(
    () =>
      client.getIsoMessageStatus("msg-2", {
        retryProfile: "   ",
      }),
    (error) => expectValidationErrorFixture(error, "getIsoMessageStatus_retry_profile_empty"),
  );
});

test("waitForIsoMessageStatus polls until a transaction hash arrives", async () => {
  const responses = [
    createIsoStatusPayload({ message_id: "msg-2", status: "Pending", transaction_hash: null }),
    createIsoStatusPayload({ message_id: "msg-2", status: "Accepted", transaction_hash: null }),
    createIsoStatusPayload({
      message_id: "msg-2",
      status: "Accepted",
      transaction_hash: "HASH-1",
      detail: "settled",
    }),
  ];
  let calls = 0;
  const fetchImpl = async (url) => {
    assert.equal(url, `${BASE_URL}/v1/iso20022/messages/msg-2`);
    const payload = responses[Math.min(calls, responses.length - 1)];
    calls += 1;
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const seen = [];
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.waitForIsoMessageStatus("msg-2", {
    pollIntervalMs: 0,
    maxAttempts: 5,
    onPoll: ({ attempt, status }) => seen.push({ attempt, status: status?.status ?? null }),
  });
  assert.equal(result.transaction_hash, "HASH-1");
  assert.equal(calls, 3);
  assert.deepEqual(
    seen.map((entry) => entry.status),
    ["Pending", "Accepted", "Accepted"],
  );
});

test("waitForIsoMessageStatus resolves when accepted state is considered terminal", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "msg-accept",
        status: "Accepted",
        transaction_hash: null,
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.waitForIsoMessageStatus("msg-accept", {
    resolveOnAcceptedWithoutTransaction: true,
    pollIntervalMs: 0,
    maxAttempts: 2,
  });
  assert.equal(calls, 1);
  assert.equal(result.status, "Accepted");
  assert.equal(result.transaction_hash, null);
});

test("waitForIsoMessageStatus surfaces onPoll errors", async () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async () => {
    calls += 1;
    return createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "msg-onpoll-fail",
        status: "Pending",
        transaction_hash: null,
      }),
      headers: { "content-type": "application/json" },
    });
  };

  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-onpoll-fail", {
        pollIntervalMs: 0,
        maxAttempts: 2,
        onPoll: async ({ attempt }) => {
          if (attempt === 1) {
            throw new Error("onPoll failure propagates");
          }
        },
      }),
    (error) => {
      assert(error instanceof Error);
      assert.match(error.message, /onPoll failure propagates/);
      return true;
    },
  );
  assert.equal(calls, 1);
});

test("waitForIsoMessageStatus forwards retryProfile to status polls", async () => {
  let calls = 0;
  const retryProfiles = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should be mocked");
    },
  });
  client._request = async (_method, _url, init = {}) => {
    retryProfiles.push(init.retryProfile ?? null);
    calls += 1;
    const payload =
      calls === 1
        ? createIsoStatusPayload({
            message_id: "msg-retry",
            status: "Pending",
            transaction_hash: null,
          })
        : createIsoStatusPayload({
            message_id: "msg-retry",
            status: "Committed",
            transaction_hash: "HASH-2",
          });
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const status = await client.waitForIsoMessageStatus("msg-retry", {
    pollIntervalMs: 0,
    maxAttempts: 2,
    retryProfile: "iso-wait",
  });
  assert.equal(status.status, "Committed");
  assert.deepEqual(retryProfiles, ["iso-wait", "iso-wait"]);
});

test("waitForIsoMessageStatus throws when no terminal status is observed", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "msg-pending",
        status: "Pending",
        transaction_hash: null,
      }),
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-pending", {
        pollIntervalMs: 0,
        maxAttempts: 2,
      }),
    (error) => {
      assert(error instanceof IsoMessageTimeoutError);
      assert.equal(error.messageId, "msg-pending");
      assert.equal(error.attempts, 2);
      assert.equal(error.lastStatus?.status, "Pending");
      return true;
    },
  );
});

test("waitForIsoMessageStatus rejects invalid AbortSignal option", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-signal", {
        // @ts-expect-error runtime validation should reject incorrect signal
        signal: {},
      }),
    (error) => expectValidationErrorFixture(error, "waitForIsoMessageStatus_invalid_signal"),
  );
});

test("waitForIsoMessageStatus rejects invalid retryProfile overrides", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-retry", {
        // @ts-expect-error runtime validation should reject incorrect type
        retryProfile: 123,
      }),
    (error) => expectValidationErrorFixture(error, "waitForIsoMessageStatus_retry_profile_type"),
  );
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-retry", {
        retryProfile: "",
      }),
    (error) => expectValidationErrorFixture(error, "waitForIsoMessageStatus_retry_profile_empty"),
  );
});

test("waitForIsoMessageStatus rejects non-boolean resolveOnAcceptedWithoutTransaction", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-resolve-invalid", {
        // @ts-expect-error runtime validation should reject non-boolean flag
        resolveOnAcceptedWithoutTransaction: "true",
      }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        /wait\.resolveOnAcceptedWithoutTransaction must be a boolean/,
      );
      return true;
    },
  );
});

test("waitForIsoMessageStatus accepts resolveOnAccepted alias", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "msg-alias",
        status: "Accepted",
        transaction_hash: null,
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.waitForIsoMessageStatus("msg-alias", {
    resolveOnAccepted: true,
    pollIntervalMs: 0,
    maxAttempts: 2,
  });
  assert.equal(calls, 1);
  assert.equal(result.status, "Accepted");
  assert.equal(result.transaction_hash, null);
});

test("waitForIsoMessageStatus rejects mismatched resolveOnAccepted flags", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.waitForIsoMessageStatus("msg-alias-conflict", {
        resolveOnAccepted: true,
        resolveOnAcceptedWithoutTransaction: false,
      }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        /wait\.resolveOnAccepted and wait\.resolveOnAcceptedWithoutTransaction must match when both are provided/,
      );
      return true;
    },
  );
});

test("waitForIsoMessageStatus forwards AbortSignal to status fetches", async () => {
  const controller = new AbortController();
  const signals = [];
  const fetchImpl = async (url, init) => {
    signals.push(init?.signal ?? null);
    return createResponse({
      status: 200,
      jsonData: createIsoStatusPayload({
        message_id: "msg-forward",
        status: "Accepted",
        transaction_hash: "tx-1",
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const status = await client.waitForIsoMessageStatus("msg-forward", {
    signal: controller.signal,
    pollIntervalMs: 0,
    maxAttempts: 1,
  });
  assert.equal(status.transaction_hash, "tx-1");
  assert.equal(signals.length, 1);
  assertRequestSignal(signals[0], controller.signal);
});

test("submitIsoPacs008AndWait submits payload then waits for completion", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === `${BASE_URL}/v1/iso20022/pacs008`) {
      return createResponse({
        status: 202,
        jsonData: { message_id: "msg-submit", status: "Accepted" },
        headers: { "content-type": "application/json" },
      });
    }
    if (url === `${BASE_URL}/v1/iso20022/messages/msg-submit`) {
      return createResponse({
        status: 200,
        jsonData: {
          message_id: "msg-submit",
          status: "Accepted",
          transaction_hash: "hash-final",
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const status = await client.submitIsoPacs008AndWait("<xml/>", {
    wait: { pollIntervalMs: 0, maxAttempts: 1 },
  });
  assert.equal(status.transaction_hash, "hash-final");
  assert.equal(calls.length, 2);
});

test("submitIsoPacs008AndWait rejects non-object options", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      return createResponse({
        status: 202,
        jsonData: { message_id: "msg-opt" },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(
    () => client.submitIsoPacs008AndWait("<xml/>", 42),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_options_invalid"),
  );
  assert.equal(fetchCalled, false);
});

test("submitIsoPacs008AndWait rejects non-object wait overrides", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      return createResponse({
        status: 202,
        jsonData: { message_id: "msg-opt" },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs008AndWait("<xml/>", {
        // @ts-expect-error verifying runtime guards
        wait: "invalid",
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs008_wait_invalid"),
  );
  assert.equal(fetchCalled, false);
});

test("submitIsoPacs008AndWait rejects when submission omits message_id", async () => {
  const calls = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url === `${BASE_URL}/v1/iso20022/pacs008`) {
        return createResponse({
          status: 202,
          jsonData: { status: "Accepted" },
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    },
  });
  await assert.rejects(
    () => client.submitIsoPacs008AndWait("<xml/>"),
    /ISO pacs008 submission did not return a message_id/,
  );
  assert.deepEqual(calls.map((call) => call.url), [`${BASE_URL}/v1/iso20022/pacs008`]);
});

test("submitIsoPacs009AndWait submits payload then waits for completion", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === `${BASE_URL}/v1/iso20022/pacs009`) {
      return createResponse({
        status: 202,
        jsonData: { message_id: "msg-pacs009", status: "Accepted" },
        headers: { "content-type": "application/json" },
      });
    }
    if (url === `${BASE_URL}/v1/iso20022/messages/msg-pacs009`) {
      return createResponse({
        status: 200,
        jsonData: {
          message_id: "msg-pacs009",
          status: "Accepted",
          transaction_hash: "hash-009",
          detail: "queued",
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const status = await client.submitIsoPacs009AndWait("<xml/>", {
    wait: { pollIntervalMs: 0, maxAttempts: 2 },
  });
  assert.equal(status.transaction_hash, "hash-009");
  assert.equal(status.status, "Accepted");
  assert.equal(calls.length, 2);
});

test("submitIsoPacs009AndWait rejects non-object wait overrides", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      return createResponse({
        status: 202,
        jsonData: { message_id: "msg-wait" },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(
    () =>
      client.submitIsoPacs009AndWait("<xml/>", {
        // @ts-expect-error runtime ensures wait payloads are objects
        wait: 5,
      }),
    (error) => expectValidationErrorFixture(error, "submitIsoPacs009_wait_invalid"),
  );
  assert.equal(fetchCalled, false);
});

test("submitIsoPacs009AndWait rejects when submission omits message_id", async () => {
  const calls = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url === `${BASE_URL}/v1/iso20022/pacs009`) {
        return createResponse({
          status: 202,
          jsonData: { status: "Accepted" },
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    },
  });
  await assert.rejects(
    () => client.submitIsoPacs009AndWait("<xml/>"),
    /ISO pacs009 submission did not return a message_id/,
  );
  assert.deepEqual(calls.map((call) => call.url), [`${BASE_URL}/v1/iso20022/pacs009`]);
});

test("submitTransaction posts norito payload and decodes receipt response", async () => {
  const payload = new Uint8Array([0x01, 0xde, 0xad]);
  const receiptJson = JSON.stringify({
    payload: {
      entrypoint_hash: "aa".repeat(32),
      signed_transaction_hash: "aa".repeat(32),
      submitted_at_ms: 1,
      submitted_at_height: 2,
      signer: "ed0120" + "bb".repeat(32),
    },
    signature: "ed25519:" + "cc".repeat(64),
  });
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.method, "POST");
    assert.equal(init.headers["Content-Type"], "application/x-norito");
    assert.equal(init.headers.Accept, "application/x-norito, application/json");
    assert.ok(Buffer.isBuffer(init.body));
    assert.deepEqual([...init.body.values()], [0x01, 0xde, 0xad]);
    return createResponse({
      status: 202,
      arrayData: new Uint8Array([0x01, 0x02, 0x03]),
      headers: { "content-type": "application/x-norito" },
    });
  };
  const nativeBinding = canonicalTransactionCodecNative({
    decodeTransactionReceiptJson: (buffer) => {
      assert.ok(Buffer.isBuffer(buffer));
      return receiptJson;
    },
  });
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  const result = await client.submitTransaction(payload);
  assert.deepEqual(result, JSON.parse(receiptJson));
});

test("non-empty Norito transaction receipts fail closed", async (t) => {
  const receiptResponse = () =>
    createResponse({
      status: 202,
      arrayData: new Uint8Array([0x01, 0x02, 0x03]),
      headers: { "content-type": "application/x-norito" },
    });
  const cases = [
    {
      name: "missing decoder",
      binding: {},
      pattern: /does not expose decodeTransactionReceiptJson/u,
    },
    {
      name: "decoder failure",
      binding: {
        decodeTransactionReceiptJson() {
          throw new Error("malformed receipt bytes");
        },
      },
      pattern: /failed to decode the non-empty Norito transaction receipt/u,
    },
    {
      name: "invalid decoder JSON",
      binding: {
        decodeTransactionReceiptJson() {
          return "not-json";
        },
      },
      pattern: /decoder returned invalid JSON/u,
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const client = new SourceToriiClient(BASE_URL, {
        fetchImpl: async () => receiptResponse(),
        [TORII_TEST_NATIVE_BINDING]: fixture.binding,
      });
      await assert.rejects(
        () => client._decodeTransactionIngressResponse(receiptResponse()),
        fixture.pattern,
      );
    });
  }
});

test("submitTransactionBatch posts a Norito transaction payload vector", async () => {
  const payloads = [Buffer.from([0x01, 0xde, 0xad]), new Uint8Array([0x01, 0xbe, 0xef])];
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers["Content-Type"], "application/x-norito");
    assert.equal(init.headers.Accept, "application/json");
    assert.ok(Buffer.isBuffer(init.body));
    const frame = noritoFramePayload(init.body, "transaction batch");
    assert.equal(frame.flags, 0x02);
    const body = frame.payload;
    let offset = 0;
    const count = readU64Length(body, offset, "batch.count");
    assert.equal(count.length, 2);
    offset += count.bytes;
    for (const [index, payload] of payloads.entries()) {
      const item = readNoritoFieldPayload(body, offset, `batch.item${index}`, true);
      const itemLength = readU64Length(item.payload, 0, `batch.item${index}.bytes`);
      assert.deepEqual(
        [...item.payload.subarray(itemLength.bytes)],
        [...payload],
      );
      assert.equal(itemLength.length, payload.length);
      offset = item.offset;
    }
    assert.equal(offset, body.length);
    return createResponse({
      status: 202,
      headers: {
        "x-iroha-transactions-accepted": "2",
        "x-iroha-route-lane-id": "7",
        "x-iroha-route-dataspace-id": "10",
      },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  const result = await client.submitTransactionBatch(payloads);

  assert.deepEqual(result, {
    acceptedCount: 2,
    route: {
      acceptedBy: BASE_URL,
      laneId: 7,
      dataspaceId: 10,
    },
  });
});

test("submitTransactionBatch uses native framed Norito batch encoder when available", async () => {
  const payloads = [Buffer.from([0x01, 0xde, 0xad]), new Uint8Array([0x01, 0xbe, 0xef])];
  const framedBody = Buffer.concat([
    Buffer.from("NRT0", "ascii"),
    Buffer.alloc(36, 0x42),
  ]);
  let encodedInputs;
  const nativeBinding = canonicalTransactionCodecNative({
    encodeTransactionPayloadBatch: (items) => {
      encodedInputs = items.map((item) => Buffer.from(item));
      return framedBody;
    },
  });
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.method, "POST");
    assert.equal(init.headers["Content-Type"], "application/x-norito");
    assert.equal(init.headers.Accept, "application/json");
    assert.ok(Buffer.isBuffer(init.body));
    assert.deepEqual(Buffer.from(init.body), framedBody);
    return createResponse({
      status: 202,
      headers: {
        "x-iroha-transactions-accepted": "2",
      },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: nativeBinding,
  });

  const result = await client.submitTransactionBatch(payloads);

  assert.deepEqual(
    encodedInputs.map((payload) => [...payload]),
    payloads.map((payload) => [...payload]),
  );
  assert.deepEqual(result, {
    acceptedCount: 2,
  });
});

test("submitTransactionBatch rejects malformed batch inputs before network submit", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("submitTransactionBatch should not issue a request");
    },
    [TORII_TEST_NATIVE_BINDING]: {},
  });

  await assert.rejects(
    () => client.submitTransactionBatch(Buffer.from([0x01])),
    /payloads must be an array/,
  );
  await assert.rejects(
    () => client.submitTransactionBatch([]),
    /requires at least one payload/,
  );
  await assert.rejects(
    () => client.submitTransactionBatch([{}]),
    /payload must be a Buffer or ArrayBuffer view/,
  );
  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xaa])]),
    /requires native encodeSignedTransactionVersioned/,
  );
});

test("submitTransactionBatch rejects native transaction versioning failures before network submit", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("submitTransactionBatch should not issue a request");
    },
    [TORII_TEST_NATIVE_BINDING]: {
      encodeSignedTransactionVersioned: () => {
        throw new Error("native versioning failed");
      },
    },
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    /native versioning failed/,
  );
});

test("submitTransactionBatch rejects an empty canonical encoder result before network submit", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("submitTransactionBatch should not issue a request");
    },
    [TORII_TEST_NATIVE_BINDING]: {
      encodeSignedTransactionVersioned: () => Buffer.alloc(0),
    },
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    /did not return VersionedSignedTransaction V1 bytes/,
  );
});

test("submitTransactionBatch rejects native batch encoder failures without posting the batch", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative({
      encodeTransactionPayloadBatch: () => {
        throw new Error("native batch encoder failed");
      },
    }),
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    /native batch encoder failed/,
  );
  assert.deepEqual(calls.map((call) => call.url), [`${BASE_URL}/v1/node/capabilities`]);
});

test("submitTransactionBatch rejects malformed accepted-count admission headers", async () => {
  const payloads = [Buffer.from([0x01, 0xde, 0xad])];
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.method, "POST");
    return createResponse({
      status: 202,
      headers: {
        "x-iroha-transactions-accepted": "NaN",
      },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.submitTransactionBatch(payloads),
    (error) => {
      assert.ok(error instanceof TransactionBatchAdmissionAmbiguousError);
      assert.equal(error.expectedCount, 1);
      assert.equal(error.acceptedCount, null);
      assert.equal(error.ambiguous, true);
      assert.equal(error.retryable, false);
      assert.match(error.message, /submitTransactionBatch\.acceptedCount/);
      return true;
    },
  );
});

test("submitTransactionBatch requires a canonical accepted-count admission header", async () => {
  for (const header of [null, "", " 1", "01", "+1", "2"]) {
    let batchPosts = 0;
    const fetchImpl = async (url) => {
      if (url === `${BASE_URL}/v1/node/capabilities`) {
        return createBatchCapabilitiesResponse();
      }
      assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
      batchPosts += 1;
      return createResponse({
        status: 202,
        headers: header === null ? {} : { "x-iroha-transactions-accepted": header },
      });
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl,
      [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
    });
    await assert.rejects(
      () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
      TransactionBatchAdmissionAmbiguousError,
      `header ${String(header)}`,
    );
    assert.equal(batchPosts, 1, `header ${String(header)}`);
  }
});

test("submitTransactionBatch never retries a lost POST response", async () => {
  let batchPosts = 0;
  const lostResponse = new TypeError("socket closed after request bytes were sent");
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.redirect, "error");
    batchPosts += 1;
    throw lostResponse;
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 9,
    retryMethods: ["POST"],
    retryStatuses: [503],
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    (error) => {
      assert.ok(error instanceof TransactionBatchAdmissionAmbiguousError);
      assert.equal(error.cause, lostResponse);
      assert.equal(error.retryable, false);
      return true;
    },
  );
  assert.equal(batchPosts, 1);
});

test("submitTransactionBatch never retries retryable HTTP statuses", async () => {
  let batchPosts = 0;
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.redirect, "error");
    batchPosts += 1;
    return createResponse({ status: 503, textBody: "temporarily unavailable" });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 9,
    retryMethods: ["POST"],
    retryStatuses: [503],
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    (error) => error instanceof ToriiHttpError && error.status === 503,
  );
  assert.equal(batchPosts, 1);
});

test("submitTransactionBatch rejects 308 without redirecting or retrying", async () => {
  let batchPosts = 0;
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions/batch`);
    assert.equal(init.redirect, "error");
    batchPosts += 1;
    return createResponse({
      status: 308,
      headers: { location: "https://redirect.example/replayed-batch" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 9,
    retryMethods: ["POST"],
    retryStatuses: [308],
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.submitTransactionBatch([Buffer.from([0x01, 0xde, 0xad])]),
    (error) => error instanceof ToriiHttpError && error.status === 308,
  );
  assert.equal(batchPosts, 1);
});

test("submitTransaction rejects framed signed transactions before any request", async () => {
  const rawPayload = Buffer.from([0x8a, 0x01, 0x88, 0x01]);
  const header = Buffer.alloc(40);
  header.write("NRT0", 0, "ascii");
  header.writeBigUInt64LE(BigInt(rawPayload.length), 23);
  const framedPayload = Buffer.concat([header, rawPayload]);
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("framed transaction must fail before fetch");
    },
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(framedPayload),
    /test payload is not VersionedSignedTransaction V1/,
  );
  assert.equal(fetchCalls, 0);
});

test("submitTransaction requires the canonical native V1 validator before any request", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("unvalidated transaction must fail before fetch");
    },
    [TORII_TEST_NATIVE_BINDING]: {},
  });
  await assert.rejects(
    () => client.submitTransaction(Buffer.from([0x01, 0xaa])),
    /requires native encodeSignedTransactionVersioned/,
  );
  assert.equal(fetchCalls, 0);
});

test("submitTransaction never retries a retryable HTTP status", async () => {
  const payload = new Uint8Array([0x01, 0xaa]);
  let attempts = 0;
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    attempts += 1;
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    return createResponse({ status: 503, jsonData: { error: "busy" } });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 9,
    retryMethods: ["POST"],
    retryStatuses: [503],
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(payload),
    (error) => error instanceof ToriiHttpError && error.status === 503,
  );
  assert.equal(attempts, 1);
});

test("submitTransaction never retries a network failure after dispatch", async () => {
  const payload = new Uint8Array([0x01, 0xab]);
  let attempts = 0;
  const networkError = Object.assign(new TypeError("write EPIPE"), {
    code: "EPIPE",
  });
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createBatchCapabilitiesResponse();
    }
    attempts += 1;
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    throw networkError;
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 9,
    retryMethods: ["POST"],
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(payload),
    (error) => error === networkError,
  );
  assert.equal(attempts, 1);
});

test("submitTransaction stops after its public capability preflight exhausts retries", async () => {
  let capabilityAttempts = 0;
  let submissionAttempts = 0;
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      capabilityAttempts += 1;
      return createResponse({ status: 503, jsonData: { error: "busy" } });
    }
    submissionAttempts += 1;
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.redirect, "error");
    return createResponse({
      status: 202,
      jsonData: { ok: true },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 2,
    backoffInitialMs: 0,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });

  await assert.rejects(
    () => client.submitTransaction(Uint8Array.of(0x01, 0xad)),
    (error) => error instanceof ToriiHttpError && error.status === 503,
  );
  assert.equal(capabilityAttempts, 3);
  assert.equal(submissionAttempts, 0);
});

for (const redirectStatus of [307, 308]) {
  test(`submitTransaction rejects ${redirectStatus} without redirecting or retrying`, async () => {
    let attempts = 0;
    const fetchImpl = async (url, init) => {
      if (url === `${BASE_URL}/v1/node/capabilities`) {
        return createBatchCapabilitiesResponse();
      }
      attempts += 1;
      assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
      assert.equal(init.method, "POST");
      assert.equal(init.redirect, "error");
      return createResponse({
        status: redirectStatus,
        headers: { location: "https://redirect.example/replayed" },
      });
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl,
      maxRetries: 9,
      retryMethods: ["POST"],
      retryStatuses: [redirectStatus],
      [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
    });

    await assert.rejects(
      () => client.submitTransaction(Uint8Array.of(0x01, 0xac)),
      (error) => error instanceof ToriiHttpError && error.status === redirectStatus,
    );
    assert.equal(attempts, 1);
  });
}

test("submitTransaction rejects unavailable pipeline submit", async () => {
  const payload = new Uint8Array([0x01, 0xab, 0xcd]);
  const seenUrls = [];
  let nativeEncodeCalls = 0;
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      nativeEncodeCalls += 1;
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      return Buffer.from(buffer);
    },
  };
  const fetchImpl = async (url, init) => {
    seenUrls.push(url);
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url === `${BASE_URL}/v1/pipeline/transactions`) {
      assert.equal(init.method, "POST");
      assert.deepEqual([...Buffer.from(init.body).values()], [...payload]);
      return createResponse({ status: 405 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  await assert.rejects(() => client.submitTransaction(payload), /405/);
  assert.deepEqual(seenUrls, [
    `${BASE_URL}/v1/node/capabilities`,
    `${BASE_URL}/v1/pipeline/transactions`,
  ]);
  assert.equal(nativeEncodeCalls, 1);
});

test("submitTransaction posts unchanged canonical VersionedSignedTransaction V1 bytes", async () => {
  const payload = new Uint8Array([0x01, 0xab, 0xcd]);
  const controller = new AbortController();
  let nativeEncodeCalls = 0;
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      nativeEncodeCalls += 1;
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      return Buffer.from(buffer);
    },
  };
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.method, "POST");
    assertRequestSignal(init.signal, controller.signal);
    assert.equal(init.headers["Content-Type"], "application/x-norito");
    assert.deepEqual([...Buffer.from(init.body).values()], [...payload]);
    return createResponse({
      status: 202,
      jsonData: { ok: true },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  const response = await client.submitTransaction(payload, {
    signal: controller.signal,
  });
  assert.deepEqual(response, { ok: true });
  assert.equal(nativeEncodeCalls, 1);
});

test("submitTransaction rejects an aborted signal before any fetch", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("aborted transaction must not fetch");
    },
  });
  const controller = new AbortController();
  controller.abort(new Error("caller cancelled final submission"));
  await assert.rejects(
    () =>
      client.submitTransaction(Uint8Array.of(1), {
        signal: controller.signal,
      }),
    /caller cancelled final submission/,
  );
  assert.equal(fetchCalls, 0);
});

test("submitTransaction rejects a native encoder result that changes the input", async () => {
  const payload = new Uint8Array([0x01, 0x8a, 0x01, 0x88, 0x01]);
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      return Buffer.from([0x01, 0xca, 0xfe, 0xba, 0xbe]);
    },
  };
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("mutated signed transaction must fail before fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  await assert.rejects(
    () => client.submitTransaction(payload),
    /not the exact canonical VersionedSignedTransaction V1 encoding/,
  );
  assert.equal(fetchCalls, 0);
});

test("submitTransaction validates canonical versioned transaction payload exactly once", async () => {
  const payload = new Uint8Array([0x01, 0xba, 0xdc]);
  let versionedEncodeCalls = 0;
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      versionedEncodeCalls += 1;
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      return Buffer.from(buffer);
    },
  };
  const fetchImpl = async (url, init) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(url, `${BASE_URL}/v1/pipeline/transactions`);
    assert.equal(init.method, "POST");
    assert.deepEqual([...Buffer.from(init.body).values()], [0x01, 0xba, 0xdc]);
    return createResponse({
      status: 202,
      jsonData: { ok: true },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  const response = await client.submitTransaction(payload);
  assert.deepEqual(response, { ok: true });
  assert.equal(versionedEncodeCalls, 1);
});

test("submitTransaction propagates canonical encoder rejection before any request", async () => {
  const payload = new Uint8Array([0x01, 0xf0, 0x0d]);
  let nativeEncodeCalls = 0;
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      nativeEncodeCalls += 1;
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      throw new Error("schema mismatch");
    },
  };
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("rejected transaction must fail before fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  await assert.rejects(() => client.submitTransaction(payload), /schema mismatch/);
  assert.equal(nativeEncodeCalls, 1);
  assert.equal(fetchCalls, 0);
});

test("submitTransaction does not fall back to removed public submit route", async () => {
  const payload = new Uint8Array([0x01, 0xfa, 0xce]);
  const seenUrls = [];
  let nativeEncodeCalls = 0;
  const nativeBinding = {
    encodeSignedTransactionVersioned: (buffer) => {
      nativeEncodeCalls += 1;
      assert.ok(Buffer.isBuffer(buffer));
      assert.deepEqual([...buffer.values()], [...payload]);
      return Buffer.from(buffer);
    },
  };
  const fetchImpl = async (url, init) => {
    seenUrls.push(url);
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    if (url === `${BASE_URL}/v1/pipeline/transactions`) {
      assert.equal(init.method, "POST");
      assert.deepEqual([...Buffer.from(init.body).values()], [...payload]);
      return createResponse({ status: 405 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl, [TORII_TEST_NATIVE_BINDING]: nativeBinding });
  await assert.rejects(() => client.submitTransaction(payload), /405/);
  assert.deepEqual(seenUrls, [
    `${BASE_URL}/v1/node/capabilities`,
    `${BASE_URL}/v1/pipeline/transactions`,
  ]);
  assert.equal(nativeEncodeCalls, 1);
});

test("submitTransaction rejects missing node capabilities advert", async () => {
  const payload = new Uint8Array([0x01, 0xde, 0xad]);
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 404,
        jsonData: { error: "not found" },
        headers: { "content-type": "application/json" },
      });
    }
    assert.fail(`unexpected transaction submission to ${url} with ${init?.method}`);
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(payload),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 404);
      return true;
    },
  );
  assert.deepEqual(calls.map((call) => call.url), [
    `${BASE_URL}/v1/node/capabilities`,
  ]);
});

test("submitTransaction rejects mismatched data model version", async () => {
  const payload = new Uint8Array([0x01, 0xaa]);
  const fetchImpl = async (url) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 9,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(payload),
    (error) => {
      assert(error instanceof ToriiDataModelMismatchError);
      assert.equal(error.expected, 4);
      assert.equal(error.actual, 9);
      return true;
    },
  );
});

test("getTransactionStatus queries pipeline endpoint", async () => {
  const hashParam = "cd".repeat(32);
  const fetchImpl = async (url) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashParam}&scope=global`,
    );
    return createResponse({
      status: 200,
      jsonData: authoritativePipelineStatusResponse(hashParam, "Committed"),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getTransactionStatus(hashParam);
  assert.deepEqual(result, authoritativePipelineStatusResponse(hashParam, "Committed"));
  const explicitUndefinedResult = await client.getTransactionStatus(hashParam, {
    scope: undefined,
  });
  assert.deepEqual(explicitUndefinedResult, result);
});

test("getTransactionStatus rejects a status envelope for a different transaction", async () => {
  const requestedHash = "cd".repeat(32);
  const returnedHash = "ab".repeat(32);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: authoritativePipelineStatusResponse(returnedHash, "Applied"),
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(
    () => client.getTransactionStatus(requestedHash),
    /does not match requested transaction/,
  );
});

test("pipeline status APIs require exact lowercase full transaction hashes", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      return createResponse({ status: 404 });
    },
  });
  const invalidHashes = [
    "aa".repeat(32),
    "AB".repeat(32),
    `0x${"ab".repeat(32)}`,
    ` ${"ab".repeat(32)}`,
    "ab".repeat(31),
    Buffer.alloc(32, 0xab),
    `hash:${"AB".repeat(32)}#0000`,
  ];

  for (const hash of invalidHashes) {
    const exactHashError =
      /exact lowercase 32-byte hex string|canonical Iroha hash marker|must not contain surrounding whitespace|must be a string/u;
    await assert.rejects(
      () => client.getTransactionStatus(hash),
      exactHashError,
    );
    await assert.rejects(
      () => client.waitForTransactionStatus(hash, { intervalMs: 0, maxAttempts: 1 }),
      exactHashError,
    );
    await assert.rejects(
      () =>
        client.submitTransactionAndWait(Uint8Array.of(1, 0xaa), {
          hashHex: hash,
          intervalMs: 0,
          maxAttempts: 1,
        }),
      exactHashError,
    );
  }
  assert.equal(fetchCalls, 0);
});

test("getTransactionStatus rejects a noncanonical response hash", async () => {
  const requestedHash = "cd".repeat(32);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: authoritativePipelineStatusResponse(
          requestedHash.toUpperCase(),
          "Applied",
        ),
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(
    () => client.getTransactionStatus(requestedHash),
    /exact lowercase 32-byte hex string/u,
  );
});

test("getTransactionStatus rejects coercive response scalar spellings", async () => {
  const requestedHash = "cd".repeat(32);
  const mutations = [
    (payload) => { payload.status.kind = " Applied "; },
    (payload) => { payload.status.block_height = "7"; },
    (payload) => { payload.scope = " global "; },
    (payload) => { payload.resolved_from = " state "; },
  ];

  for (const mutate of mutations) {
    const payload = authoritativePipelineStatusResponse(requestedHash, "Applied", {
      resolvedFrom: "state",
      blockHeight: 7,
    });
    mutate(payload);
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(() => client.getTransactionStatus(requestedHash));
  }
});

test("getTransactionStatus rejects retired diagnostic fields", async () => {
  const requestedHash = "cf".repeat(32);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          ...authoritativePipelineStatusResponse(requestedHash, "Rejected"),
          status: { kind: "Rejected", rejection_reason: "secret" },
          diagnostics: [{ message: "secret" }],
        },
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(
    () => client.getTransactionStatus(requestedHash),
    /diagnostics/,
  );
});

test("getTransactionStatus normalizes typed pipeline status responses", async () => {
  const hashHex = "ef".repeat(32);
  const fetchImpl = async (url) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashHex}&scope=global`,
    );
    return createResponse({
      status: 200,
      jsonData: {
        hash: hashHex,
        resolved_from: "state",
        scope: "global",
        status: {
          kind: "Applied",
          block_height: 7,
        },
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getTransactionStatus(hashHex);
  assert.deepEqual(result, {
    hash: hashHex,
    resolved_from: "state",
    scope: "global",
    status: {
      kind: "Applied",
      block_height: 7,
    },
  });
});

test("getTransactionStatus rejects retired auto response scope", async () => {
  const hashHex = "ef".repeat(32);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          hash: hashHex,
          resolved_from: "state",
          scope: "auto",
          status: { kind: "Applied", block_height: 7 },
        },
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    /scope is unsupported/u,
  );
});

test("getTransactionStatus preserves Torii status provenance", async () => {
  const hashHex = "ef".repeat(32);
  const seenUrls = [];
  const fetchImpl = async (url) => {
    seenUrls.push(url);
    assert.equal(
      url,
      `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashHex}&scope=global`,
    );
    return createResponse({
      status: 200,
      jsonData: authoritativePipelineStatusResponse(hashHex, "Applied", {
        resolvedFrom: "cache",
        blockHeight: 7,
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getTransactionStatus(hashHex);
  assert.equal(seenUrls.length, 1);
  assert.equal(payload?.resolved_from, "cache");
});

test("getTransactionStatus supports raw local reads", async () => {
  const hashHex = "01".repeat(32);
  const seenUrls = [];
  const fetchImpl = async (url) => {
    seenUrls.push(url);
    if (url === `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashHex}&scope=local`) {
      return createResponse({ status: 404 });
    }
    throw new Error(`Unexpected URL ${url}`);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getTransactionStatus(hashHex, { scope: "local" });
  assert.equal(payload, null);
  assert.deepEqual(seenUrls, [
    `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashHex}&scope=local`,
  ]);
});

test("getTransactionStatus forwards signal to fetch", async () => {
  const hashHex = "ab".repeat(32);
  const controller = new AbortController();
  let capturedSignal = null;
  const fetchImpl = async (_url, init = {}) => {
    capturedSignal = init.signal ?? null;
    return createResponse({ status: 404 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.getTransactionStatus(hashHex, { signal: controller.signal });
  assertRequestSignal(capturedSignal, controller.signal);
});

test("getTransactionStatus validates signal option type", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 404 }) });
  await assert.rejects(
    () =>
      client.getTransactionStatus("ab".repeat(32), {
        // @ts-expect-error runtime validation should reject incorrect signal
        signal: {},
      }),
    /getTransactionStatus options\.signal must be an AbortSignal/,
  );
});

test("getTransactionStatus rejects unsupported options", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 404 }) });
  await assert.rejects(
    () =>
      client.getTransactionStatus("ab".repeat(32), {
        extra: true,
      }),
    /getTransactionStatus options contains unsupported fields: extra/,
  );
  await assert.rejects(
    () =>
      client.getTransactionStatus("ab".repeat(32), {
        endpoints: ["https://fallback.example"],
      }),
    /getTransactionStatus options contains unsupported fields: endpoints/,
  );
});

test("getTransactionStatus rejects the retired allowShortHash option", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 404 }) });
  await assert.rejects(
    () =>
      client.getTransactionStatus("ab".repeat(32), {
        allowShortHash: true,
      }),
    /getTransactionStatus options contains unsupported fields: allowShortHash/,
  );
});

test("getTransactionStatus validates scope option", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 404 }) });
  for (const scope of [null, "", "auto", "invalid", "GLOBAL", " global "]) {
    await assert.rejects(
      () =>
        client.getTransactionStatus("ab".repeat(32), {
          scope,
        }),
      /getTransactionStatus options\.scope must be one of: local, global/,
    );
  }
});

  test("getTransactionStatus retries 425 via pipeline profile", async () => {
    const hash = "ab".repeat(32);
    let attempts = 0;
    const fetchImpl = async (url) => {
      attempts += 1;
      assert.equal(
        url,
        `${BASE_URL}/v1/pipeline/transactions/status?hash=${hash}&scope=global`,
      );
      if (attempts === 1) {
        return createResponse({ status: 425, jsonData: { status: "TooEarly" } });
      }
      return createResponse({
        status: 200,
        jsonData: authoritativePipelineStatusResponse(hash, "Committed", {
          resolvedFrom: "cache",
        }),
        headers: { "content-type": "application/json" },
      });
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl, maxRetries: 0 });
    const result = await client.getTransactionStatus(hash);
    assert.equal(attempts, 2);
    assert.equal(result?.status?.kind, "Committed");
  });

test("getTransactionStatus rejects retired pending HTTP responses", async () => {
  for (const status of [202, 204]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status }),
    });
    await assert.rejects(
      () => client.getTransactionStatus("ef".repeat(32)),
      (error) => error instanceof ToriiHttpError && error.status === status,
    );
  }
});

test("getTransactionStatus rejects an empty HTTP 200 payload", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
  });
  await assert.rejects(
    () => client.getTransactionStatus("ef".repeat(32)),
    /pipeline transaction status response|\.hash/u,
  );
});

test("getTransactionStatus returns null when Torii responds with 404", async () => {
  const hashHex = "ab".repeat(32);
  const fetchImpl = async (url) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/pipeline/transactions/status?hash=${hashHex}&scope=global`,
    );
    return createResponse({ status: 404 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getTransactionStatus(hashHex);
  assert.equal(result, null);
});

test("getTransactionStatus matches shared error-message contract fixture", async () => {
  const hashHex = "ab".repeat(32);
  for (const fixtureCase of txStatusErrorMessageContract.cases) {
    const headers = {};
    if (typeof fixtureCase.content_type === "string" && fixtureCase.content_type) {
      headers["content-type"] = fixtureCase.content_type;
    }
    if (
      typeof fixtureCase.reject_code_header === "string" &&
      fixtureCase.reject_code_header
    ) {
      const rejectHeaderName =
        typeof fixtureCase.reject_code_header_name === "string" &&
        fixtureCase.reject_code_header_name
          ? fixtureCase.reject_code_header_name
          : "x-iroha-reject-code";
      headers[rejectHeaderName] = fixtureCase.reject_code_header;
    }
    const fetchImpl = async () =>
      createResponse({
        status: fixtureCase.status_code,
        jsonData: fixtureCase.body_json ?? {},
        textBody: fixtureCase.body_text,
        headers,
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl, maxRetries: 0 });
    await assert.rejects(
      () => client.getTransactionStatus(hashHex),
      (error) => {
        assert(error instanceof ToriiHttpError, `${fixtureCase.id}: expected ToriiHttpError`);
        assert.equal(error.status, fixtureCase.status_code, `${fixtureCase.id}: status mismatch`);
        if (fixtureCase.expected_reject_code) {
          assert.equal(
            error.rejectCode,
            fixtureCase.expected_reject_code,
            `${fixtureCase.id}: reject code mismatch`,
          );
        }
        if (fixtureCase.expected_message) {
          assert.equal(
            error.errorMessage,
            fixtureCase.expected_message,
            `${fixtureCase.id}: message mismatch`,
          );
        }
        if (fixtureCase.expected_message_length) {
          assert.equal(
            error.errorMessage?.length,
            fixtureCase.expected_message_length,
            `${fixtureCase.id}: message length mismatch`,
          );
        }
        if (fixtureCase.expected_message_suffix) {
          assert.equal(
            error.errorMessage?.endsWith(fixtureCase.expected_message_suffix),
            true,
            `${fixtureCase.id}: message suffix mismatch`,
          );
        }
        return true;
      },
      `${fixtureCase.id}: getTransactionStatus should reject`,
    );
  }
});

test("getTransactionStatus surfaces nested JSON error message and reject code", async () => {
  const hashHex = "ab".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 400,
      jsonData: {
        error: {
          detail: "missing build claim for transaction status",
        },
      },
      headers: {
        "content-type": "application/json",
        "x-iroha-reject-code": "build_claim_missing",
      },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 400);
      assert.equal(error.rejectCode, "build_claim_missing");
      assert.equal(error.code, "build_claim_missing");
      assert.equal(error.errorMessage, "missing build claim for transaction status");
      return true;
    },
  );
});

test("getTransactionStatus surfaces ErrorEnvelope details reject code", async () => {
  const hashHex = "ad".repeat(32);
  const details = {
    reject_code: "TX_QUEUE_FULL",
    retry_after_seconds: 1,
    queue: {
      state: "saturated",
      queued: 128,
      capacity: 128,
      saturated: true,
    },
  };
  const fetchImpl = async () =>
    createResponse({
      status: 429,
      jsonData: {
        code: "queue_full",
        message: "transaction queue is at capacity",
        details,
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl, maxRetries: 0 });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 429);
      assert.equal(error.rejectCode, "TX_QUEUE_FULL");
      assert.equal(error.code, "TX_QUEUE_FULL");
      assert.equal(error.errorMessage, "transaction queue is at capacity");
      assert.deepEqual(error.details, details);
      return true;
    },
  );
});

test("getTransactionStatus surfaces errors-array messages", async () => {
  const hashHex = "cd".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 422,
      jsonData: {
        errors: [{ message: "status query validation failed" }, { message: "hash malformed" }],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 422);
      assert.equal(error.errorMessage, "status query validation failed");
      return true;
    },
  );
});

test("getTransactionStatus uses compact JSON for message-less errors", async () => {
  const hashHex = "ef".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 422,
      jsonData: { status: "invalid", code: "E123" },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl, maxRetries: 0 });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 422);
      assert.equal(error.errorMessage, '{"code":"E123","status":"invalid"}');
      return true;
    },
  );
});

test("getTransactionStatus truncates oversized plain-text errors", async () => {
  const hashHex = "11".repeat(32);
  const oversized = "x".repeat(700);
  const fetchImpl = async () =>
    createResponse({
      status: 422,
      textBody: oversized,
      headers: { "content-type": "text/plain" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl, maxRetries: 0 });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 422);
      assert.equal(error.errorMessage.length, 515);
      assert.equal(error.errorMessage.endsWith("..."), true);
      return true;
    },
  );
});

test("getTransactionStatus rejects invalid hashes", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  await assert.rejects(
    () => client.getTransactionStatus("abc123"),
    /getTransactionStatus\.hashHex/,
  );
});

test("getTransactionStatus rejects on malformed payloads", async () => {
  const hashHex = "13".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        status: { kind: "Approved" },
        scope: "global",
        resolved_from: "queue",
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(client.getTransactionStatus(hashHex), /\.hash/);
});

test("getTransactionStatus rejects retired status envelopes", async () => {
  const hashHex = "cd".repeat(32);
  const payload = {
    kind: "Transaction",
    content: {
      hash: hashHex,
      authority: FIXTURE_ALICE_ID,
      status: { kind: "Committed", content: { receipt: "ok" } },
    },
  };
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    /kind|content/,
  );
});

test("getTransactionStatus normalises typed pipeline status responses", async () => {
  const hashHex = "99".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        hash: hashHex,
        resolved_from: "state",
        scope: "global",
        status: {
          kind: "Applied",
          block_height: 11,
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getTransactionStatus(hashHex);
  assert.ok(result, "typed payload should be returned");
  assert.equal(result?.hash, hashHex);
  assert.equal(result?.status?.kind, "Applied");
  assert.equal(result?.status?.block_height, 11);
  assert.equal(result?.scope, "global");
  assert.equal(result?.resolved_from, "state");
  assert.deepEqual(Object.keys(result ?? {}).sort(), [
    "hash",
    "resolved_from",
    "scope",
    "status",
  ]);
});

test("getTransactionStatus rejects retired HTTP 204", async () => {
  const hashHex = "ef".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 204,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getTransactionStatus(hashHex),
    (error) => error instanceof ToriiHttpError && error.status === 204,
  );
});

test("getTransactionStatus rejects on malformed payload", async () => {
  const hashHex = "35".repeat(32);
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: "not-an-object",
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(() => client.getTransactionStatus(hashHex), /must be an object/);
});

test("getPipelineRecovery fetches the recovery sidecar", async () => {
  const fixture = createPipelineRecoveryPayload({ height: 7 });
  let capturedUrl;
  const fetchImpl = async (url, init) => {
    capturedUrl = url;
    assert.equal(init?.method, "GET");
    return createResponse({
      status: 200,
      jsonData: fixture,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getPipelineRecovery(7n);
  assert.equal(capturedUrl, `${BASE_URL}/v1/pipeline/recovery/7`);
  assert.deepEqual(payload, fixture);
});

test("getPipelineRecovery returns null for missing heights", async () => {
  const fetchImpl = async () => createResponse({ status: 404 });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getPipelineRecovery(99);
  assert.equal(payload, null);
});

// Keep bounded-response registrations at the original pipeline-recovery position.
// The diagnostic focus harness filters registrations as they occur in this file,
// so moving this call would change the direct toriiClient.test.js test sequence.
// The sibling module owns implementation only, keeping the main suite navigable.
// These regressions remain registered here rather than becoming a separate suite.
registerToriiClientBoundedResponseTests({
  assert,
  BASE_URL,
  createResponse,
  ISO_OPERATOR_SIGNING_CONTEXT,
  test,
  ToriiClient,
});

test("getPipelineRecoveryTyped normalises dag + transaction snapshots", async () => {
  const payload = createPipelineRecoveryPayload({
    dag: { fingerprint: fakeHashHex(0x10), key_count: 9 },
    txs: [
      { hash: fakeHashHex(0x33), reads: ["  state::foo  "], writes: ["World.bar"] },
      { hash: fakeHashHex(0x44), reads: [], writes: ["ledger.accounts"] },
    ],
    height: 123,
  });
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getPipelineRecoveryTyped(123);
  assert.deepEqual(result, {
    format: "dag-json",
    height: 123,
    dag: {
      fingerprintHex: payload.dag.fingerprint.toLowerCase(),
      keyCount: 9,
    },
    txs: [
      {
        hashHex: payload.txs[0].hash.toLowerCase(),
        reads: ["state::foo"],
        writes: ["World.bar"],
      },
      {
        hashHex: payload.txs[1].hash.toLowerCase(),
        reads: [],
        writes: ["ledger.accounts"],
      },
    ],
  });
});

test("getPipelineRecoveryTyped rejects malformed payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { format: "", height: 1, dag: {}, txs: {} },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getPipelineRecoveryTyped(1),
    /pipeline recovery response\.format/,
  );
});

test("getPipelineRecoveryFastpqProofs fetches committed proof batches", async () => {
  const fixture = createPipelineRecoveryFastpqProofsPayload({ height: 7 });
  const controller = new AbortController();
  let capturedUrl;
  const fetchImpl = async (url, init) => {
    capturedUrl = url;
    assert.equal(init?.method, "GET");
    assertRequestSignal(init?.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: fixture,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getPipelineRecoveryFastpqProofs(7n, {
    signal: controller.signal,
  });
  assert.equal(capturedUrl, `${BASE_URL}/v1/pipeline/recovery/7/fastpq-proofs`);
  assert.deepEqual(payload, fixture);
});

test("getPipelineRecoveryFastpqProofs returns null for missing heights", async () => {
  const fetchImpl = async () => createResponse({ status: 404 });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getPipelineRecoveryFastpqProofs(99);
  assert.equal(payload, null);
});

test("getPipelineRecoveryFastpqProofsTyped normalises proof snapshots", async () => {
  const proof = {
    entry_hash: fakeHashHex(0x55),
    batch_index: 3,
    parameter: "fastpq-state-transition-stark-v1",
    transition_count: 5,
    trace_commitment: fakeHashHex(0x66),
    proof_digest: fakeHashHex(0x77),
    batch: "YmF0Y2gtMg==",
    proof: "",
    batch_compact: false,
    batch_reconstructed_from_block: true,
    batch_reconstruction_error: null,
  };
  const payload = createPipelineRecoveryFastpqProofsPayload({
    height: 123,
    block_hash: fakeHashHex(0x88),
    proofs: [proof],
  });
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getPipelineRecoveryFastpqProofsTyped(123);
  assert.deepEqual(result, {
    height: 123,
    blockHashHex: payload.block_hash.toLowerCase(),
    proofs: [
      {
        entryHash: proof.entry_hash.toLowerCase(),
        batchIndex: 3,
        parameter: "fastpq-state-transition-stark-v1",
        transitionCount: 5,
        traceCommitment: proof.trace_commitment.toLowerCase(),
        proofDigest: proof.proof_digest.toLowerCase(),
        batchBase64: "YmF0Y2gtMg==",
        proofBase64: "",
        batchCompact: false,
        batchReconstructedFromBlock: true,
        batchReconstructionError: null,
        raw: proof,
      },
    ],
  });
});

test("getPipelineRecoveryFastpqProofsTyped rejects malformed payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { height: 1, block_hash: fakeHashHex(0x99), proofs: {} },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getPipelineRecoveryFastpqProofsTyped(1),
    /FASTPQ proofs response\.proofs must be an array/,
  );
});

test("extractPipelineStatusKind returns nested status kind", () => {
  const payload = { status: { kind: "Committed" } };
  assert.equal(extractPipelineStatusKind(payload), "Committed");
});

test("extractPipelineStatusKind ignores retired nested transaction content", () => {
  assert.equal(extractPipelineStatusKind({
    kind: "Transaction",
    content: { status: { kind: "Pending" } },
  }), null);
});

test("extractPipelineStatusKind rejects the retired direct status string", () => {
  const payload = { status: "Rejected" };
  assert.equal(extractPipelineStatusKind(payload), null);
});

test("extractPipelineStatusKind returns null when status missing", () => {
  assert.equal(extractPipelineStatusKind({}), null);
  assert.equal(extractPipelineStatusKind(null), null);
});

test("decodePdpCommitmentHeader decodes base64 payloads", () => {
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const headers = { "sora-pdp-commitment": payload.toString("base64") };
  const decoded = decodePdpCommitmentHeader(headers);
  assert.ok(decoded instanceof Uint8Array);
  assert.deepEqual(Buffer.from(decoded ?? []), payload);
});

test("decodePdpCommitmentHeader handles Headers objects", () => {
  const headers = new Headers();
  headers.set("Sora-PDP-Commitment", Buffer.from([0xcd]).toString("base64"));
  const decoded = decodePdpCommitmentHeader(headers);
  assert.deepEqual(Buffer.from(decoded ?? []), Buffer.from([0xcd]));
});

test("decodePdpCommitmentHeader throws on invalid base64 strings", () => {
  assert.throws(
    () => decodePdpCommitmentHeader({ "sora-pdp-commitment": "###" }),
    /Failed to decode Sora-PDP-Commitment header/,
  );
});

test("decodePdpCommitmentHeader returns null when header absent", () => {
  assert.equal(decodePdpCommitmentHeader(null), null);
  assert.equal(decodePdpCommitmentHeader({}), null);
});

test("waitForTransactionStatus rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const hashHex = "ab".repeat(32);
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, "invalid"),
    /waitForTransactionStatus options must be a plain object/,
  );
});

test("waitForTransactionStatus enforces numeric poll options", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const hashHex = "bb".repeat(32);
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, { intervalMs: -1 }),
    /waitForTransactionStatus options\.intervalMs must be a non-negative integer/,
  );
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, { timeoutMs: -5 }),
    /waitForTransactionStatus options\.timeoutMs must be a non-negative integer/,
  );
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, { maxAttempts: 0 }),
    /waitForTransactionStatus options\.maxAttempts must be a positive integer/,
  );
});

test("waitForTransactionStatus rejects unsupported options", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const hashHex = "cd".repeat(32);
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, { intervalMs: 0, extra: true }),
    /waitForTransactionStatus options contains unsupported fields: extra/,
  );
});

test("waitForTransactionStatus validates signal option type", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const hashHex = "cd".repeat(32);
  await assert.rejects(
    () =>
      client.waitForTransactionStatus(hashHex, {
        // @ts-expect-error runtime validation should reject incorrect signal
        signal: {},
      }),
    /waitForTransactionStatus options\.signal must be an AbortSignal/,
  );
});

test("waitForTransactionStatus rejects the removed scope option", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const hashHex = "cf".repeat(32);
  await assert.rejects(
    () => client.waitForTransactionStatus(hashHex, { scope: "local" }),
    /waitForTransactionStatus options contains unsupported fields: scope/,
  );
});

test("waitForTransactionStatus enforces onStatus callback type", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  await assert.rejects(
    () => client.waitForTransactionStatus("cd".repeat(32), { onStatus: "noop" }),
    /waitForTransactionStatus options\.onStatus must be a function/,
  );
});

test("waitForTransactionStatus rejects invalid hash literals", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  await assert.rejects(
    () => client.waitForTransactionStatus("deadbeef", { maxAttempts: 1 }),
    /waitForTransactionStatus\.hashHex/,
  );
});

test("waitForTransactionStatus keeps polling through Committed until Applied", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });

  const requestHash = "dd".repeat(32);
  const statuses = [
    authoritativePipelineStatus(requestHash, "Queued"),
    authoritativePipelineStatus(requestHash, "Committed", { resolvedFrom: "cache" }),
    authoritativePipelineStatus(requestHash, "Applied", { blockHeight: 7 }),
  ];
  client.getTransactionStatus = async () => statuses.shift();

  const observed = [];
  const result = await client.waitForTransactionStatus(requestHash, {
    intervalMs: 0,
    timeoutMs: 50,
    onStatus: (status, payload, attempt) => observed.push({ status, attempt, payload }),
  });

  assert.equal(observed.length, 3);
  assert.deepEqual(observed.map((entry) => entry.status), ["Queued", "Committed", "Applied"]);
  assert.deepEqual(result, authoritativePipelineStatus(requestHash, "Applied", { blockHeight: 7 }));
});

test("waitForTransactionStatus rejects a terminal status for a different hash", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const requestedHash = "dd".repeat(32);
  client.getTransactionStatus = async () =>
    authoritativePipelineStatus("ef".repeat(32), "Applied");

  await assert.rejects(
    () => client.waitForTransactionStatus(requestedHash, { intervalMs: 0, maxAttempts: 1 }),
    /does not match requested transaction/,
  );
});

test("waitForTransactionStatus rejects a non-authoritative status envelope", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const requestedHash = "dd".repeat(32);
  client.getTransactionStatus = async () => ({
    kind: "Transaction",
    status: { kind: "Applied" },
    content: {
      hash: requestedHash,
      status: { kind: "Pending", content: null },
    },
  });

  await assert.rejects(
    () => client.waitForTransactionStatus(requestedHash, { intervalMs: 0, maxAttempts: 1 }),
    /waitForTransactionStatus response\.hash/u,
  );
});

test("waitForTransactionStatus rejects malformed or non-global Applied evidence", async () => {
  const requestHash = "db".repeat(32);
  for (const [payload, expected] of [
    [
      {
        ...authoritativePipelineStatus(requestHash, "Applied"),
        scope: "local",
      },
      /scope must be global/u,
    ],
    [
      {
        ...authoritativePipelineStatus(requestHash, "Applied"),
        status: { kind: "Applied", block_height: 0 },
      },
      /positive block height/u,
    ],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 200 }),
    });
    client.getTransactionStatus = async () => payload;
    await assert.rejects(
      () =>
        client.waitForTransactionStatus(requestHash, {
          intervalMs: 0,
          maxAttempts: 1,
        }),
      expected,
    );
  }
});

test("waitForTransactionStatus keeps queue and cache Applied pending", async () => {
  const requestHash = "db".repeat(32);
  const queued = authoritativePipelineStatus(requestHash, "Applied", {
    resolvedFrom: "queue",
    blockHeight: 7,
  });
  const cached = authoritativePipelineStatus(requestHash, "Applied", {
    resolvedFrom: "cache",
    blockHeight: 7,
  });
  const resolved = authoritativePipelineStatus(requestHash, "Applied", {
    resolvedFrom: "state",
    blockHeight: 7,
  });
  const statuses = [queued, cached, resolved];
  const observed = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
  });
  client.getTransactionStatus = async () => statuses.shift();

  const result = await client.waitForTransactionStatus(requestHash, {
    intervalMs: 0,
    maxAttempts: 3,
    onStatus: (status, payload, attempt) =>
      observed.push({ status, payload, attempt }),
  });

  assert.strictEqual(result, resolved);
  assert.deepEqual(
    observed.map(({ status, attempt, payload }) => ({
      status,
      attempt,
      resolvedFrom: payload.resolved_from,
    })),
    [
      { status: "Applied", attempt: 1, resolvedFrom: "queue" },
      { status: "Applied", attempt: 2, resolvedFrom: "cache" },
      { status: "Applied", attempt: 3, resolvedFrom: "state" },
    ],
  );
});

test("waitForTransactionStatus retains cached Applied as timeout context", async () => {
  const requestHash = "d9".repeat(32);
  const cached = authoritativePipelineStatus(requestHash, "Applied", {
    resolvedFrom: "cache",
    blockHeight: 9,
  });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
  });
  client.getTransactionStatus = async () => cached;

  await assert.rejects(
    () =>
      client.waitForTransactionStatus(requestHash, {
        intervalMs: 0,
        maxAttempts: 1,
      }),
    (error) =>
      error instanceof TransactionTimeoutError &&
      error.payload === cached,
  );
});

test("waitForTransactionStatus treats Rejected and Expired as fixed failures", async () => {
  for (const failureKind of ["Rejected", "Expired"]) {
    const requestHash = failureKind === "Rejected" ? "d9".repeat(32) : "d7".repeat(32);
    const cachedFailure = authoritativePipelineStatus(requestHash, failureKind, {
      resolvedFrom: "cache",
    });
    const observed = [];
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 200 }),
    });
    client.getTransactionStatus = async () => cachedFailure;

    await assert.rejects(
      () => client.waitForTransactionStatus(requestHash, {
        intervalMs: 0,
        maxAttempts: 2,
        onStatus: (status, payload, attempt) =>
          observed.push({ status, payload, attempt }),
      }),
      (error) =>
        error instanceof TransactionStatusError && error.status === failureKind,
    );
    assert.deepEqual(
      observed.map(({ status, payload, attempt }) => ({
        status,
        resolvedFrom: payload.resolved_from,
        attempt,
      })),
      [
        { status: failureKind, resolvedFrom: "cache", attempt: 1 },
      ],
    );
  }
});

test("waitForTransactionStatus forwards signal and aborts polling", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const txHash = "67".repeat(32);
  const controller = new AbortController();
  let attempts = 0;
  let seenSignal = null;
  let seenScope = null;
  client.getTransactionStatus = async (_hashHex, options = {}) => {
    attempts += 1;
    seenSignal = options.signal ?? null;
    seenScope = options.scope ?? null;
    controller.abort(new Error("stop polling"));
    return {
      ...authoritativePipelineStatus(txHash, "Queued"),
    };
  };

  await assert.rejects(
    () =>
      client.waitForTransactionStatus(txHash, {
        signal: controller.signal,
        intervalMs: 0,
        timeoutMs: null,
        maxAttempts: 10,
      }),
    (error) => error instanceof Error && error.message === "stop polling",
  );
  assert.equal(attempts, 1);
  assert.equal(seenSignal, controller.signal);
  assert.equal(seenScope, "global");
});

test("waitForTransactionStatus always requests global status", async () => {
  const txHash = "69".repeat(32);
  const seenUrls = [];
  const fetchImpl = async (url) => {
    seenUrls.push(url);
    return createResponse({
      status: 200,
      jsonData: authoritativePipelineStatusResponse(txHash, "Applied"),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });

  await client.waitForTransactionStatus(txHash, {
    intervalMs: 0,
    maxAttempts: 1,
  });

  assert.deepEqual(seenUrls, [
    `${BASE_URL}/v1/pipeline/transactions/status?hash=${txHash}&scope=global`,
  ]);
});

test("getTransactionStatus uses a fresh header bag on each retry", async () => {
  const observedHeaders = [];
  let attempts = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (_url, init) => {
      attempts += 1;
      observedHeaders.push(init.headers);
      assert.equal(init.headers.Accept, "application/json");
      assert.deepEqual(
        Object.keys(init.headers).sort(),
        ["Accept"],
      );
      assert.deepEqual(
        Object.getOwnPropertyNames(init.headers).sort(),
        ["Accept"],
      );
      if (attempts < 3) {
        throw new TypeError("fetch failed");
      }
      return createResponse({ status: 404 });
    },
  });

  const result = await client.getTransactionStatus("ab".repeat(32));
  assert.equal(result, null);
  assert.equal(observedHeaders.length, 3);
  assert.notEqual(observedHeaders[0], observedHeaders[1]);
  assert.notEqual(observedHeaders[1], observedHeaders[2]);
});

test("waitForTransactionStatus rejects on failure status", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const rejectionHash = "23".repeat(32);
  client.getTransactionStatus = async () =>
    authoritativePipelineStatus(rejectionHash, "Rejected");

  await assert.rejects(
    () => client.waitForTransactionStatus(rejectionHash, { intervalMs: 0, maxAttempts: 1 }),
    (error) => error instanceof TransactionStatusError && error.status === "Rejected",
  );
});

test("waitForTransactionStatus does not surface retired rejection details", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const rejectionHash = "23".repeat(32);
  const rejectionReason = "build_claim_missing";
  client.getTransactionStatus = async () =>
    authoritativePipelineStatus(rejectionHash, "Rejected");

  await assert.rejects(
    () => client.waitForTransactionStatus(rejectionHash, { intervalMs: 0, maxAttempts: 1 }),
    (error) =>
      error instanceof TransactionStatusError
      && error.status === "Rejected"
      && !("rejectionReason" in error)
      && !String(error.message).includes(rejectionReason),
  );
});

test("waitForTransactionStatus respects maxAttempts", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  let calls = 0;
  const pendingHash = "33".repeat(32);
  client.getTransactionStatus = async () => {
    calls += 1;
    return authoritativePipelineStatus(pendingHash, "Queued");
  };

  await assert.rejects(
    () =>
      client.waitForTransactionStatus(pendingHash, {
        intervalMs: 0,
        maxAttempts: 2,
        timeoutMs: null,
      }),
    (error) => error instanceof TransactionTimeoutError && error.attempts === 2,
  );
  assert.equal(calls, 2);
});

test("waitForTransactionStatus enforces timeoutMs", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200 }) });
  const pendingHash = "45".repeat(32);
  client.getTransactionStatus = async () =>
    authoritativePipelineStatus(pendingHash, "Queued");

  await assert.rejects(
    () =>
      client.waitForTransactionStatus(pendingHash, {
        intervalMs: 0,
        timeoutMs: 0,
      }),
    (error) => error instanceof TransactionTimeoutError,
  );
});

test("submitTransactionAndWait delegates to submitTransaction + waitForTransactionStatus", async () => {
  const finalHash = "55".repeat(32);
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative({
      hashSignedTransaction: () => Buffer.from(finalHash, "hex"),
    }),
  });

  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  let submittedPayload = null;
  let waitArgs = null;
  const expectedResult = {
    kind: "Transaction",
    content: { hash: finalHash, status: { kind: "Applied", content: null } },
  };

  client.submitTransaction = async (body) => {
    submittedPayload = body;
  };
  client.waitForTransactionStatus = async (hashHex, pollOptions) => {
    waitArgs = { hashHex, pollOptions };
    return expectedResult;
  };

  const result = await client.submitTransactionAndWait(payload, { timeoutMs: 500 });

  assert.strictEqual(submittedPayload, payload);
  assert.deepEqual(waitArgs, {
    hashHex: finalHash,
    pollOptions: {
      timeoutMs: 500,
    },
  });
  assert.strictEqual(result, expectedResult);
  await client.submitTransactionAndWait(payload, { hashHex: finalHash });
  assert.equal(waitArgs.hashHex, finalHash, "an asserted hash that matches the bytes is accepted");
});

test("transaction finality policy cannot be overridden", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
  });
  for (const field of ["successStatuses", "failureStatuses", "terminalStatuses"]) {
    await assert.rejects(
      () =>
        client.waitForTransactionStatus("57".repeat(32), {
          [field]: ["Committed"],
        }),
      new RegExp(`unsupported fields.*${field}`, "u"),
    );
  }
});

test("submitTransactionAndWait rejects an asserted hashHex that does not match the signed bytes", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative({
      hashSignedTransaction: () => Buffer.from("55".repeat(32), "hex"),
    }),
  });
  let submissions = 0;
  client.submitTransaction = async () => {
    submissions += 1;
  };
  const dummy = Buffer.from([1]);
  await assert.rejects(
    () => client.submitTransactionAndWait(dummy, "options"),
    /submitTransactionAndWait options must be a plain object/,
  );
  await assert.rejects(
    () => client.submitTransactionAndWait(dummy, { hashHex: "57".repeat(32) }),
    /does not match the signed transaction hash/,
  );
  assert.equal(submissions, 0);
});

test("submitTransactionAndWait validates poll options before submission", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200 }),
  });
  let submissions = 0;
  client.submitTransaction = async () => {
    submissions += 1;
  };

  await assert.rejects(
    () =>
      client.submitTransactionAndWait(Buffer.from([0]), {
        hashHex: "57".repeat(32),
        scope: "local",
      }),
    /submitTransactionAndWait options contains unsupported fields: scope/,
  );
  assert.equal(submissions, 0);
});

test("getHealth reads the plain-text /health probe", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/health`);
    assert.equal(init.headers.Accept, "text/plain");
    return createResponse({
      status: 200,
      textBody: "Healthy\n",
      headers: { "content-type": "text/plain" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getHealth();
  assert.deepEqual(payload, { status: "Healthy" });
});

test("getHealth trims CRLF from the plain-text probe", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      textBody: "Healthy\r\n",
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.deepEqual(await client.getHealth(), { status: "Healthy" });
});

test("getHealth rejects an empty plain-text probe", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      textBody: "",
      headers: { "content-type": "text/plain" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(() => client.getHealth(), {
    name: "ValidationError",
    code: ValidationErrorCode.INVALID_STRING,
    path: "health response",
  });
});

test("getHealth rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(() => client.getHealth("bad-options"), (error) =>
    expectValidationErrorFixture(error, "getHealth_options_invalid"),
  );
});

test("health endpoints reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(() => client.getHealth({ extra: true }), (error) =>
    expectValidationErrorFixture(error, "getHealth_options_extra"),
  );
  await assert.rejects(() => client.getStatusSnapshot({ note: "nope" }), (error) =>
    expectValidationErrorFixture(error, "getStatusSnapshot_options_extra"),
  );
});

test("getStatusSnapshot rejects invalid signals", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () => client.getStatusSnapshot({ signal: "not-a-signal" }),
    (error) => expectValidationErrorFixture(error, "getStatusSnapshot_invalid_signal"),
  );
});

test("getSumeragiStatus validates options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(() => client.getSumeragiStatus(5), (error) =>
    expectValidationErrorFixture(error, "getSumeragiStatus_options_invalid"),
  );
  await assert.rejects(
    () => client.getSumeragiStatus({ signal: "nope" }),
    (error) => expectValidationErrorFixture(error, "getSumeragiStatus_invalid_signal"),
  );
  await assert.rejects(() => client.getSumeragiStatus({ extra: true }), (error) =>
    expectValidationErrorFixture(error, "getSumeragiStatus_options_extra"),
  );
});





function sumeragiClientForPayload(payload, Client = ToriiClient) {
  const useDistContexts = Client === DistToriiClient;
  return new Client(BASE_URL, {
    localSigningContext: useDistContexts
      ? DIST_LOCAL_SIGNING_CONTEXT
      : VK_LOCAL_SIGNING_CONTEXT,
    operatorSigningContext: useDistContexts
      ? DIST_OPERATOR_SIGNING_CONTEXT
      : ISO_OPERATOR_SIGNING_CONTEXT,
    canonicalRequestAuth: APPLICATION_CANONICAL_AUTH,
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
  });
}

function sumeragiDiagnosticsClientForPayload(payload) {
  return new ToriiClient(BASE_URL, {
    fetchImpl: async (url) => {
      assert.equal(url, `${BASE_URL}/v1/sumeragi/diagnostics`);
      return createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      });
    },
  });
}

function sumeragiTypedClientForRawJson(path, textBody, headers = {}) {
  return new ToriiClient(BASE_URL, {
    fetchImpl: async (url) => {
      assert.equal(url, `${BASE_URL}${path}`);
      return createResponse({
        status: 200,
        jsonData: { response_json_must_not_be_used: true },
        textBody,
        headers: {
          "content-type": "application/json",
          ...headers,
        },
      });
    },
  });
}

function replaceJsonStringPlaceholder(text, placeholder, integerToken) {
  const needle = JSON.stringify(placeholder);
  const occurrences = text.split(needle).length - 1;
  assert(occurrences > 0, `expected at least one ${placeholder} placeholder`);
  return text.replaceAll(needle, integerToken);
}

























test("diagnostics declarations exclude retired autonomous execution identities", () => {
  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  assert.doesNotMatch(declarations, /\bToriiSumeragiAutonomousLaneExecution\b/u);
  assert.doesNotMatch(declarations, /\bautonomous_lane_executions\b/u);
  assert.doesNotMatch(declarations, /"awaiting_executable_payload"/u);
});





















test("Sumeragi lane declarations expose the served record and nullable instance", () => {
  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const status = declarations.match(/export interface ToriiSumeragiLaneStatus \{([\s\S]*?)\n\}/u);
  assert.ok(status, "missing ToriiSumeragiLaneStatus declaration");
  assert.ok(status[1].includes("record: ToriiSumeragiLaneRecord;"));
  assert.ok(status[1].includes("instance: ToriiSumeragiStatus | null;"));
  const record = declarations.match(/export interface ToriiSumeragiLaneRecord \{([\s\S]*?)\n\}/u);
  assert.ok(record, "missing ToriiSumeragiLaneRecord declaration");
  for (const field of [
    "lane: number;",
    "incarnation: string;",
    "params: ToriiSumeragiParameters;",
    "committee: ReadonlyArray<ToriiSumeragiLaneMember>;",
    "closing: ToriiU64 | null;",
    "merged: ToriiSumeragiLaneFrontier;",
  ]) {
    assert.ok(record[1].includes(field), `missing declaration: ${field}`);
  }
  assert.doesNotMatch(declarations, /ToriiSumeragiV2/u);
});



















test("retired Sumeragi compatibility helpers are absent", async () => {
  const present = (owner, names) => names.filter((name) => Object.hasOwn(owner, name));
  assert.deepEqual(
    present(ToriiClient.prototype, [
      "getSumeragiTelemetry", "getSumeragiTelemetryTyped",
      "getSumeragiCollectors", "getSumeragiRbc", "getSumeragiRbcSessions",
      "findRbcSamplingCandidate", "getSumeragiRbcDelivered", "sampleRbcChunks",
      "listSumeragiKeyLifecycle",
    ]),
    [],
  );
  assert.deepEqual(present(ToriiClient, ["buildRbcSampleRequest"]), []);
  const publicApi = await import("../src/index.js");
  assert.deepEqual(
    present(publicApi, [
      "buildRbcSampleRequest",
      "captureSumeragiTelemetrySnapshot",
      "appendSumeragiTelemetrySnapshot",
    ]),
    [],
  );
});






































test("getSumeragiBlsKeys returns network map", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/sumeragi/bls-keys`);
    assert.equal(init.headers.Accept, "application/json");
    return createResponse({
      status: 200,
      jsonData: {
        "ed0120...01": null,
        "bls1...ff": "bls1...ff",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const mapping = await client.getSumeragiBlsKeys();
  assert.deepEqual(mapping, {
    "ed0120...01": null,
    "bls1...ff": "bls1...ff",
  });
});

test("getSumeragiBlsKeys rejects malformed payloads", async () => {
  const fetchImpl = async () => {
    return createResponse({
      status: 200,
      jsonData: { "ed0120...01": 42 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(() => client.getSumeragiBlsKeys(), /sumeragi BLS key/);
});

test("getSumeragiParams fetches on-chain parameters", async () => {
  let served = { block_cadence_ms: 1000, max_clock_drift_ms: 50, chain_height: 4200 };
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/sumeragi/params`);
    assert.equal(init.headers.Accept, "application/json");
    return createResponse({
      status: 200,
      jsonData: served,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.deepEqual(await client.getSumeragiParams(), {
    block_cadence_ms: 1000,
    max_clock_drift_ms: 50,
    chain_height: 4200,
  });

  const current = served;
  for (const [label, payload, pattern] of [
    ["retired field", { ...current, collectors_k: 3 }, /unsupported fields: collectors_k/],
    ["retired name", { ...current, block_cadence_ms: undefined, block_time_ms: 1000 }, /unsupported fields: block_time_ms/],
    ["missing field", { block_cadence_ms: 1000, max_clock_drift_ms: 50 }, /chain_height/],
    ["zero cadence", { ...current, block_cadence_ms: 0 }, /must be nonzero/],
    ["negative height", { ...current, chain_height: -1 }, /must be >= 0/],
  ]) {
    served = JSON.parse(JSON.stringify(payload));
    await assert.rejects(() => client.getSumeragiParams(), pattern, label);
  }
});

test("Sumeragi params reject unsupported options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: () => {
      throw new Error("fetch should not be called for validation failures");
    },
  });
  await assert.rejects(
    client.getSumeragiParams({ unexpected: true }),
    /getSumeragiParams options contains unsupported fields: unexpected/,
  );
});

test("getStatusSnapshot normalizes payload and tracks metrics", async () => {
  const payloads = [
    {
      observed_at_ms: 10_000,
      peers: "5",
      queue_size: 3,
      queue_queued: 2,
      queue_inflight: 1,
      last_block_committed_at_ms: 9_900,
      last_non_empty_block_committed_at_ms: 9_000,
      time_since_last_block_ms: 100,
      time_since_last_non_empty_block_ms: 1_000,
      commit_time_ms: 420,
      txs_approved: 100,
      txs_rejected: 2,
      view_changes: 1,
      governance: {
        proposals: { proposed: 4, approved: 2, rejected: 1, enacted: 1 },
        protected_namespace: { total_checks: 3, allowed: 2, rejected: 1 },
        manifest_admission: {
          total_checks: 5,
          allowed: 3,
          missing_manifest: 1,
          non_validator_authority: 0,
          quorum_rejected: 1,
          protected_namespace_rejected: 0,
          runtime_hook_rejected: 0,
        },
        manifest_quorum: { total_checks: 2, satisfied: 1, rejected: 1 },
        recent_manifest_activations: [
          {
            contract_address: "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s",
            code_hash_hex: "deadbeef",
            abi_hash_hex: null,
            height: 10,
            activated_at_ms: 1700,
          },
        ],
      },
      dataspace_catalog: [
        {
          lane_id: 7,
          lane_alias: "lane-archive",
          dataspace_id: 9,
          alias: "archive",
          visibility: "public",
          storage_profile: "full_replica",
          manifest_required: true,
          manifest_ready: false,
          manifest_path: null,
          protected_namespaces: ["finance"],
        },
      ],
      lane_governance: [
        {
          lane_id: 7,
          alias: "archive",
          dataspace_id: 9,
          visibility: "public",
          storage_profile: "full_replica",
          governance: null,
          manifest_required: true,
          manifest_ready: false,
          manifest_path: null,
          validator_ids: ["alice@test"],
          quorum: null,
          protected_namespaces: ["finance"],
        runtime_upgrade: {
          allow: true,
          require_metadata: false,
          metadata_key: null,
          allowed_ids: [],
        },
        privacy_commitments: [
          {
            id: 2,
            scheme: "merkle",
            merkle: { root: "0xabc123", max_depth: 8 },
          },
        ],
      },
    ],
      lane_governance_sealed_total: 2,
      lane_governance_sealed_aliases: ["archive", "payments"],
    },
    {
      observed_at_ms: 11_000,
      peers: 5,
      queue_size: 1,
      queue_queued: 1,
      queue_inflight: 0,
      last_block_committed_at_ms: 10_900,
      last_non_empty_block_committed_at_ms: 10_000,
      time_since_last_block_ms: 100,
      time_since_last_non_empty_block_ms: 1_000,
      commit_time_ms: 250,
      txs_approved: 103,
      txs_rejected: 4,
      view_changes: 2,
      governance: {
        proposals: { proposed: 5, approved: 3, rejected: 1, enacted: 1 },
        protected_namespace: { total_checks: 3, allowed: 2, rejected: 1 },
        manifest_admission: {
          total_checks: 6,
          allowed: 4,
          missing_manifest: 1,
          non_validator_authority: 0,
          quorum_rejected: 1,
          protected_namespace_rejected: 0,
          runtime_hook_rejected: 1,
        },
        manifest_quorum: { total_checks: 3, satisfied: 2, rejected: 1 },
        recent_manifest_activations: [
          {
            contract_address: "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s",
            code_hash_hex: "deadbeef",
            abi_hash_hex: "b16b00b5",
            height: 11,
            activated_at_ms: 1900,
          },
        ],
      },
      dataspace_catalog: [
        {
          lane_id: 8,
          lane_alias: "lane-payments",
          dataspace_id: 4,
          alias: "payments",
          visibility: "public",
          storage_profile: "full_replica",
          manifest_required: true,
          manifest_ready: true,
          sealed: false,
          manifest_path: "/etc/iroha/lanes/payments.json",
          protected_namespaces: ["treasury"],
        },
      ],
      lane_governance: [
        {
          lane_id: 8,
          alias: "payments",
          dataspace_id: 4,
          visibility: "public",
          storage_profile: "full_replica",
          governance: "parliament",
          manifest_required: true,
          manifest_ready: true,
          manifest_path: "/etc/iroha/lanes/payments.json",
          validator_ids: ["bob@test", "carol@test"],
          quorum: 2,
          protected_namespaces: ["treasury"],
        runtime_upgrade: {
          allow: true,
          require_metadata: true,
          metadata_key: "upgrade_id",
          allowed_ids: ["payments-upgrade"],
        },
        privacy_commitments: [
          {
            id: 3,
            scheme: "merkle",
            merkle: { root: "0xdef456", max_depth: 16 },
          },
        ],
      },
    ],
      lane_governance_sealed_total: 0,
      lane_governance_sealed_aliases: [],
    },
  ];
  let callCount = 0;
  const fetchImpl = async (url, init = {}) => {
    assert.equal(url, `${BASE_URL}/status`);
    assert.equal(init.method, "GET");
    assert.equal(init.headers.Accept, "application/json");
    const payload = payloads[callCount] ?? payloads[payloads.length - 1];
    callCount += 1;
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const first = await client.getStatusSnapshot();
  assert.equal(first.status.observed_at_ms, 10_000);
  assert.equal(first.status.peers, 5);
  assert.equal(first.status.queue_size, 3);
  assert.equal(first.status.queue_queued, 2);
  assert.equal(first.status.queue_inflight, 1);
  assert.equal(first.metrics.time_since_last_non_empty_block_ms, 1_000);
  assert.equal(statusLivenessElapsedMs(first.status), 1_000);
  assert.equal(isStatusQueueStalled(first.status, 999), true);
  assert.equal(isStatusQueueStalled(first.status, 1_000), false);
  assert.equal(first.metrics.commit_latency_ms, 420);
  assert.equal(first.metrics.queue_delta, 0);
  assert.equal(first.metrics.tx_approved_delta, 0);
  assert.equal(first.metrics.has_activity, false);
  assert.equal(first.status.raw.commit_time_ms, 420);
  assert.ok(first.status.governance);
  assert.equal(first.status.governance?.manifest_admission.runtime_hook_rejected, 0);
  assert.equal(Object.hasOwn(first.status, "lane_commitments"), false);
  assert.equal(Object.hasOwn(first.status, "dataspace_commitments"), false);
  assert.deepEqual(first.status.dataspace_catalog, [
    {
      lane_id: 7,
      lane_alias: "lane-archive",
      dataspace_id: 9,
      alias: "archive",
      visibility: "public",
      storage_profile: "full_replica",
      manifest_required: true,
      manifest_ready: false,
      sealed: true,
      manifest_path: null,
      protected_namespaces: ["finance"],
    },
  ]);
  assert.deepEqual(first.status.lane_governance, [
    {
      lane_id: 7,
      alias: "archive",
      dataspace_id: 9,
      visibility: "public",
      storage_profile: "full_replica",
      governance: null,
      manifest_required: true,
      manifest_ready: false,
      manifest_path: null,
      validator_ids: ["alice@test"],
      quorum: null,
      protected_namespaces: ["finance"],
      runtime_upgrade: {
        allow: true,
        require_metadata: false,
        metadata_key: null,
        allowed_ids: [],
      },
      privacy_commitments: [
        {
          id: 2,
          scheme: "merkle",
          merkle: { root: "0xabc123", max_depth: 8 },
        },
      ],
    },
  ]);
  assert.equal(first.status.lane_governance_sealed_total, 2);
  assert.deepEqual(first.status.lane_governance_sealed_aliases, ["archive", "payments"]);
  const activation = first.status.governance?.recent_manifest_activations[0];
  assert.equal(
    activation?.contract_address,
    "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s",
  );
  assert.equal(activation?.abi_hash_hex, null);

  const second = await client.getStatusSnapshot();
  assert.equal(second.status.queue_size, 1);
  assert.equal(second.metrics.queue_queued, 1);
  assert.equal(second.metrics.queue_inflight, 0);
  assert.equal(second.metrics.queue_delta, -2);
  assert.equal(second.metrics.tx_approved_delta, 3);
  assert.equal(second.metrics.tx_rejected_delta, 2);
  assert.equal(second.metrics.view_change_delta, 1);
  assert.equal(second.metrics.has_activity, true);
  assert.equal(second.status.governance?.manifest_admission.runtime_hook_rejected, 1);
  assert.equal(second.status.lane_governance_sealed_total, 0);
  assert.deepEqual(second.status.lane_governance_sealed_aliases, []);
  const secondActivation = second.status.governance?.recent_manifest_activations[0];
  assert.equal(secondActivation?.abi_hash_hex, "b16b00b5");
  assert.equal(callCount, 2);
});

test("getStatusSnapshot rejects non-integer counters", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        peers: 1.5,
        queue_size: 0,
        commit_time_ms: 1,
        txs_approved: 0,
        txs_rejected: 0,
        view_changes: 0,
        governance: null,
        lane_governance: [],
        lane_governance_sealed_total: 0,
        lane_governance_sealed_aliases: [],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getStatusSnapshot(),
    (error) => {
      assert(error instanceof RangeError);
      assert.match(error.message, /status\.peers/);
      return true;
    },
  );
});

test("getStatusSnapshot rejects removed SNARK lane commitments", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        peers: 1,
        queue_size: 0,
        commit_time_ms: 1,
        txs_approved: 0,
        txs_rejected: 0,
        view_changes: 0,
        governance: null,
        lane_governance: [
          {
            lane_id: 1,
            dataspace_id: 1,
            manifest_required: true,
            manifest_ready: true,
            validator_ids: [],
            protected_namespaces: [],
            privacy_commitments: [{ id: 1, scheme: "snark", snark: {} }],
          },
        ],
        lane_governance_sealed_total: 0,
        lane_governance_sealed_aliases: [],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getStatusSnapshot(),
    /privacy_commitments\[0\]\.scheme must be "merkle"/,
  );
});

for (const field of ["lane_commitments", "dataspace_commitments", "pipeline_execution"]) {
  test(`getStatusSnapshot rejects retired ${field}`, async () => {
    const fetchImpl = async () => createResponse({
      status: 200,
      jsonData: { peers: 1, queue_size: 0, commit_time_ms: 1, [field]: [] },
      headers: { "content-type": "application/json" },
    });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getStatusSnapshot(),
      (error) => error instanceof TypeError && error.message === `status.${field} is retired and unsupported`,
    );
  });
}

test("getStatusSnapshot forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/status`);
    assert.equal(init.headers.Accept, "application/json");
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: { peers: 1, queue_size: 0, commit_time_ms: 1 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getStatusSnapshot({ signal: controller.signal });
  assert.equal(snapshot.status.peers, 1);
});

test("getNetworkTimeNow normalizes timestamps", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        now: 1_000_000,
        offset_ms: -12,
        confidence_ms: 25,
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getNetworkTimeNow();
  assert.deepEqual(result, {
    timestampMs: 1_000_000,
    offsetMs: -12,
    confidenceMs: 25,
  });
});

test("getNetworkTimeNow rejects non-integer offsets", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        now: 1_000_000,
        offset_ms: 1.5,
        confidence_ms: 25,
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNetworkTimeNow(),
    (error) => {
      assert(error instanceof RangeError);
      assert.match(error.message, /time now response\.offset_ms/);
      return true;
    },
  );
});

test("getNetworkTimeStatus normalizes diagnostics payload", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        peers: 2,
        samples: [
          {
            peer: "peer-a",
            last_offset_ms: -4,
            last_rtt_ms: 7,
            count: 11,
          },
        ],
        rtt: {
          buckets: [
            { le: 5, count: 2 },
            { le: 10, count: 3 },
          ],
          sum_ms: 42,
          count: 5,
        },
        note: "NTS running",
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getNetworkTimeStatus();
  assert.deepEqual(result, {
    peers: 2,
    samples: [{ peer: "peer-a", lastOffsetMs: -4, lastRttMs: 7, count: 11 }],
    rtt: {
      buckets: [
        { le: 5, count: 2 },
        { le: 10, count: 3 },
      ],
      sumMs: 42,
      count: 5,
    },
    note: "NTS running",
  });
});

test("getNetworkTimeStatus rejects malformed samples", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { peers: 1, samples: null, rtt: { buckets: [], sum_ms: 0, count: 0 } },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNetworkTimeStatus(),
    /time status response\.samples must be an array/,
  );
});

test("getNetworkTimeStatus rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNetworkTimeStatus({ signal: new AbortController().signal, extra: "nope" }),
    /getNetworkTimeStatus options contains unsupported fields: extra/,
  );
});

test("getNetworkTimeNow rejects non-object options", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNetworkTimeNow("oops"),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /getNetworkTimeNow options must be an object/);
      return true;
    },
  );
});

test("getNetworkTimeNow rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNetworkTimeNow({ signal: new AbortController().signal, extra: true }),
    /getNetworkTimeNow options contains unsupported fields: extra/,
  );
});

test("getNodeCapabilities normalizes runtime advert", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        abi_version: 1,
        data_model_version: 4,
        crypto: {
          sm: {
            enabled: true,
            default_hash: "sm3",
            allowed_signing: ["sm2"],
            sm2_distid_default: "3132333435363738",
            openssl_preview: false,
            acceleration: {
              scalar: true,
              neon_sm3: true,
              neon_sm4: false,
              policy: "scalar",
            },
          },
          curves: {
            registry_version: 1,
            allowed_curve_ids: [1, 15],
            allowed_curve_bitmap: [32770],
          },
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getNodeCapabilities();
  assert.deepEqual(result, {
    abiVersion: 1,
    dataModelVersion: 4,
    crypto: {
      sm: {
        enabled: true,
        defaultHash: "sm3",
        allowedSigning: ["sm2"],
        sm2DistIdDefault: "3132333435363738",
        opensslPreview: false,
        acceleration: {
          scalar: true,
          neonSm3: true,
          neonSm4: false,
          policy: "scalar",
        },
      },
      curves: {
        registryVersion: 1,
        allowedCurveIds: [1, 15],
        allowedCurveBitmap: [32770],
      },
    },
  });
});

test("getNodeCapabilities rejects non-integer ABI version", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        abi_version: 1.5,
        data_model_version: 4,
        crypto: {
          sm: {
            enabled: true,
            default_hash: "sm3",
            allowed_signing: ["sm2"],
            sm2_distid_default: "3132333435363738",
            openssl_preview: false,
            acceleration: {
              scalar: true,
              neon_sm3: true,
              neon_sm4: false,
              policy: "scalar",
            },
          },
          curves: {
            registry_version: 1,
            allowed_curve_ids: [1, 15],
            allowed_curve_bitmap: [32770],
          },
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNodeCapabilities(),
    (error) => {
      assert.match(error.message, /abi_version/);
      return true;
    },
  );
});

test("getNodeCapabilities rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getNodeCapabilities({ signal: new AbortController().signal, extra: "nope" }),
    /getNodeCapabilities options contains unsupported fields: extra/,
  );
});

test("getRuntimeAbiActive normalizes ABI version", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { abi_version: 1 },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getRuntimeAbiActive(canonicalReadOptions());
  assert.deepEqual(result, {
    abiVersion: 1,
  });
});

test("getRuntimeAbiActive rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getRuntimeAbiActive({ signal: new AbortController().signal, extra: "nope" }),
    /getRuntimeAbiActive options contains unsupported fields: extra/,
  );
});

test("getRuntimeAbiHash enforces hex payload", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { policy: "V1", abi_hash_hex: "aabb".repeat(16) },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getRuntimeAbiHash();
  assert.equal(result.policy, "V1");
  assert.equal(result.abiHashHex, "aabb".repeat(16));
});

test("getRuntimeAbiHash enforces AbortSignal option type", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.getRuntimeAbiHash({
        // @ts-expect-error runtime validation should reject incorrect signal type
        signal: {},
      }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /getRuntimeAbiHash options\.signal must be an AbortSignal/);
      return true;
    },
  );
});

test("getRuntimeMetrics normalizes counters", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        abi_version: 1,
        upgrade_events_total: { proposed: 3, activated: 1, canceled: 1 },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getRuntimeMetrics(canonicalReadOptions());
  assert.deepEqual(result, {
    abiVersion: 1,
    upgradeEventsTotal: { proposed: 3, activated: 1, canceled: 1 },
  });
});

test("listRuntimeUpgrades normalizes manifest and status payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        items: [
          {
            id_hex: "aa".repeat(32),
            record: {
              manifest: {
                name: "ABI v1 refresh",
                description: "scheduled rollout",
                abi_version: 1,
                abi_hash: "11".repeat(32),
                added_syscalls: [],
                added_pointer_types: [],
                start_height: 10,
                end_height: 20,
              },
              status: { ActivatedAt: 12 },
              proposer: FIXTURE_ALICE_ID,
              created_height: 8,
            },
          },
          {
            id_hex: "bb".repeat(32),
            record: {
              manifest: {
                name: "ABI v1 maintenance",
                description: "next window",
                abi_version: 1,
                abi_hash: "22".repeat(32),
                added_syscalls: [],
                added_pointer_types: [],
                start_height: 30,
                end_height: 40,
              },
              status: { Proposed: null },
              proposer: FIXTURE_BOB_ID,
              created_height: 25,
            },
          },
        ],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const upgrades = await client.listRuntimeUpgrades();
  assert.equal(upgrades.length, 2);
  assert.deepEqual(upgrades[0], {
    idHex: "aa".repeat(32),
    record: {
      manifest: {
        name: "ABI v1 refresh",
        description: "scheduled rollout",
        abiVersion: 1,
        abiHashHex: "11".repeat(32),
        addedSyscalls: [],
        addedPointerTypes: [],
        startHeight: 10,
        endHeight: 20,
      },
      status: { kind: "ActivatedAt", activatedHeight: 12 },
      proposer: FIXTURE_ALICE_ID,
      createdHeight: 8,
    },
  });
  assert.deepEqual(upgrades[1].record.status, { kind: "Proposed" });
});

test("proposeRuntimeUpgrade posts manifest and normalizes response", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: {
        ok: true,
        tx_instructions: [{ wire_id: "ProposeRuntimeUpgrade", payload_hex: "aa".repeat(32) }],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const manifest = {
    name: "ABI v1 maintenance",
    description: "roll out refreshed binaries",
    abiVersion: 1,
    abiHash: "11".repeat(32),
    startHeight: 100,
    endHeight: 200,
    addedSyscalls: [],
    addedPointerTypes: [],
  };
  const result = await client.proposeRuntimeUpgrade(manifest);
  assert.equal(captured.url, `${BASE_URL}/v1/runtime/upgrades/propose`);
  assert.equal(captured.init.method, "POST");
  const body = JSON.parse(captured.init.body);
  assert.equal(body.name, "ABI v1 maintenance");
  assert.equal(body.abi_version, 1);
  assert.deepEqual(body.added_syscalls, []);
  assert.deepEqual(result, {
    ok: true,
    tx_instructions: [{ wire_id: "ProposeRuntimeUpgrade", payload_hex: "aa".repeat(32) }],
  });
});

test("listRuntimeUpgrades rejects non-v1 manifest ABI", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        items: [
          {
            id_hex: "aa".repeat(32),
            record: {
              manifest: {
                name: "invalid",
                description: "bad abi",
                abi_version: 2,
                abi_hash: "11".repeat(32),
                added_syscalls: [],
                added_pointer_types: [],
                start_height: 10,
                end_height: 20,
              },
              status: { Proposed: null },
              proposer: FIXTURE_ALICE_ID,
              created_height: 8,
            },
          },
        ],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listRuntimeUpgrades(),
    /abi_version must be 1 in the first release/,
  );
});

test("proposeRuntimeUpgrade rejects added syscall deltas in the first release", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () =>
      client.proposeRuntimeUpgrade({
        name: "invalid",
        description: "bad delta",
        abiVersion: 1,
        abiHash: "11".repeat(32),
        startHeight: 100,
        endHeight: 200,
        addedSyscalls: [600],
      }),
    /added_syscalls must be empty in the first release/,
  );
});

test("activateRuntimeUpgrade posts id and normalizes response", async () => {
  let calledUrl;
  const fetchImpl = async (url) => {
    calledUrl = url;
    return createResponse({
      status: 200,
      jsonData: { ok: true, tx_instructions: [{ wire_id: "ActivateRuntimeUpgrade" }] },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const response = await client.activateRuntimeUpgrade("0x" + "ff".repeat(32));
  assert.equal(
    calledUrl,
    `${BASE_URL}/v1/runtime/upgrades/activate/0x${"ff".repeat(32)}`,
  );
  assert.deepEqual(response, {
    ok: true,
    tx_instructions: [{ wire_id: "ActivateRuntimeUpgrade" }],
  });
});

test("cancelRuntimeUpgrade posts id and normalizes response", async () => {
  let calledUrl;
  const fetchImpl = async (url) => {
    calledUrl = url;
    return createResponse({
      status: 200,
      jsonData: { ok: true, tx_instructions: [{ wire_id: "CancelRuntimeUpgrade" }] },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const response = await client.cancelRuntimeUpgrade("aa".repeat(32));
  assert.equal(
    calledUrl,
    `${BASE_URL}/v1/runtime/upgrades/cancel/0x${"aa".repeat(32)}`,
  );
  assert.deepEqual(response, {
    ok: true,
    tx_instructions: [{ wire_id: "CancelRuntimeUpgrade" }],
  });
});

test("runtime upgrade wrappers reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  for (const [label, invoke, key] of [
    ["getRuntimeAbiHash", () => client.getRuntimeAbiHash({ extra: true }), "extra"],
    ["getRuntimeMetrics", () => client.getRuntimeMetrics({ note: "nope" }), "note"],
    ["listRuntimeUpgrades", () => client.listRuntimeUpgrades({ surprise: 1 }), "surprise"],
    [
      "activateRuntimeUpgrade",
      () => client.activateRuntimeUpgrade("aa".repeat(32), { junk: true }),
      "junk",
    ],
    [
      "proposeRuntimeUpgrade",
      () =>
        client.proposeRuntimeUpgrade(
          {
            name: "upgrade",
            description: "test",
            abi_version: 1,
            abi_hash: "aa".repeat(32),
            start_height: 0,
            end_height: 1,
          },
          { note: "skip" },
        ),
      "note",
    ],
    [
      "cancelRuntimeUpgrade",
      () => client.cancelRuntimeUpgrade("aa".repeat(32), { unsupported: true }),
      "unsupported",
    ],
  ]) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(invoke, (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        new RegExp(`${label} options contains unsupported fields: ${key}`),
      );
      return true;
    });
  }
});

registerToriiClientGovernanceTests({
  assert,
  BASE_URL,
  FIXTURE_ALICE_ID,
  FIXTURE_ALICE_TEST_ID,
  FIXTURE_BOB_ID,
  FIXTURE_BOB_NARNIA_ID,
  FIXTURE_CAROL_ID,
  GOVERNANCE_NETWORK_ID: VK_SIGNING_NETWORK_ID,
  GOVERNANCE_LOCAL_SIGNING_CONTEXT: VK_LOCAL_SIGNING_CONTEXT,
  GOVERNANCE_PROPOSAL_ID,
  LocalSigningContext,
  NetworkId,
  SAMPLE_ACCOUNT_FORMS,
  SEED_11_ED25519_PUBLIC_KEY_HEX,
  ToriiClient,
  ValidationError,
  ValidationErrorCode,
  assertRequestSignal,
  cloneFixture,
  createResponse,
  expectValidationErrorFixture,
  parseStrictLosslessIntegerJson,
  readFileSync,
  test,
  toriiFixtures,
});

test("getMetrics returns the Prometheus text exposition from /metrics", async () => {
  const metrics = "# HELP foo\nfoo 1\n";
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/metrics`);
    assert.equal(init.headers.Accept, "text/plain");
    return createResponse({
      status: 200,
      textBody: metrics,
      headers: { "content-type": "text/plain" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getMetrics();
  assert.equal(payload, metrics);
});

test("getMetrics rejects non-object options", async () => {
  const fetchImpl = async () => {
    throw new Error("should not reach fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(client.getMetrics("nope"), /getMetrics options must be an object/);
});

test("getMetrics rejects unsupported option keys", async () => {
  const fetchImpl = async () => {
    throw new Error("should not reach fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getMetrics({ asText: true }),
    /getMetrics options contains unsupported fields: asText/,
  );
});

test("getMetrics forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/metrics`);
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      textBody: "up 1\n",
      headers: { "content-type": "text/plain" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.getMetrics({ signal: controller.signal });
  assert.equal(payload, "up 1\n");
});

test("getBlock fetches block by height", async () => {
  const fetchImpl = async (url) => {
    assert.equal(url, `${BASE_URL}/v1/explorer/blocks/42`);
    return createResponse({
      status: 200,
      jsonData: {
        hash: "DEADBEEF",
        height: 42,
        created_at: "2026-01-01T00:00:00Z",
        prev_block_hash: null,
        transactions_hash: "ABCD",
        transactions_rejected: 1,
        transactions_total: 5,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const block = await client.getBlock(42);
  assert.deepEqual(block, {
    hash: "DEADBEEF",
    height: 42,
    createdAt: "2026-01-01T00:00:00Z",
    prevBlockHash: null,
    transactionsHash: "ABCD",
    transactionsRejected: 1,
    transactionsTotal: 5,
  });
});

test("getLedgerExecutedBlockWire fetches exact bounded Norito bytes", async () => {
  const expectedWire = Buffer.from([1, 0x4e, 0x52, 0x54, 0x30, 0xaa]);
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      arrayData: expectedWire,
      headers: { "content-type": "application/x-norito" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const actualWire = await client.getLedgerExecutedBlockWire("7");
  assert.equal(captured.url, `${BASE_URL}/v1/ledger/block/7`);
  assert.equal(captured.init.headers.Accept, "application/x-norito");
  assert.deepEqual(actualWire, expectedWire);

  const maximumHeightWire = await client.getLedgerExecutedBlockWire(
    "18446744073709551615",
  );
  assert.equal(
    captured.url,
    `${BASE_URL}/v1/ledger/block/18446744073709551615`,
  );
  assert.deepEqual(maximumHeightWire, expectedWire);
});

test("getLedgerExecutedBlockWire rejects selectors, media, empty bodies, and oversize claims", async () => {
  let fetchCalls = 0;
  const localRejectClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("must not fetch");
    },
  });
  await assert.rejects(
    localRejectClient.getLedgerExecutedBlockWire(0),
    /positive integer/u,
  );
  await assert.rejects(
    localRejectClient.getLedgerExecutedBlockWire(1n << 64n),
    /must be at most 18446744073709551615/u,
  );
  await assert.rejects(
    localRejectClient.getLedgerExecutedBlockWire(1, { offset: 1 }),
    /unsupported fields: offset/u,
  );
  assert.equal(fetchCalls, 0);

  const wrongMediaClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      arrayData: Uint8Array.of(1),
      headers: { "content-type": "application/json" },
    }),
  });
  await assert.rejects(
    wrongMediaClient.getLedgerExecutedBlockWire(1),
    /must use the application\/x-norito media type/u,
  );

  const emptyClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      arrayData: new Uint8Array(),
      headers: { "content-type": "application/x-norito" },
    }),
  });
  await assert.rejects(
    emptyClient.getLedgerExecutedBlockWire(1),
    /must not be empty/u,
  );

  const oversizedClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      arrayData: Uint8Array.of(1),
      headers: {
        "content-type": "application/x-norito",
        "content-length": String(
          AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1 + 1,
        ),
      },
    }),
  });
  await assert.rejects(
    oversizedClient.getLedgerExecutedBlockWire(1),
    /33554432-byte response limit/u,
  );

  const lengthMismatchClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      arrayData: Uint8Array.of(1),
      headers: {
        "content-type": "application/x-norito",
        "content-length": "2",
      },
    }),
  });
  await assert.rejects(
    lengthMismatchClient.getLedgerExecutedBlockWire(1),
    /Content-Length does not match/u,
  );
});

test("getBlock forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/explorer/blocks/7`);
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: {
        hash: "aa",
        height: 7,
        created_at: "now",
        prev_block_hash: null,
        transactions_hash: "bb",
        transactions_rejected: 0,
        transactions_total: 0,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const block = await client.getBlock(7, { signal: controller.signal });
  assert.equal(block.height, 7);
});

test("getBlock returns null when Torii replies 404", async () => {
  const fetchImpl = async () => {
    return createResponse({
      status: 404,
      jsonData: null,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const block = await client.getBlock(9999);
  assert.equal(block, null);
});


test("getBlock rejects empty identifiers", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getBlock("  "),
    /must not be empty/,
  );
});

test("getBlock rejects unsupported option keys", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getBlock(1, { unexpected: true }),
    /getBlock options contains unsupported fields: unexpected/,
  );
});






test("dataspace-visible Explorer reads stay anonymous without a default signer", async () => {
  let capturedInit;
  const client = new ToriiClient(BASE_URL, {
    canonicalRequestAuth: null,
    fetchImpl: async (_url, init) => {
      capturedInit = init;
      return createResponse({
        status: 200,
        jsonData: {
          next_cursor: null,
          items: [],
        },
        headers: { "content-type": "application/json" },
      });
    },
  });

  const page = await client.explorerNfts.list();
  assert.deepEqual(page.items, []);
  assert.equal(capturedInit.headers["X-Iroha-Account"], undefined);
  assert.equal(capturedInit.headers["X-Iroha-Signature"], undefined);
});



test("explorerNfts surfaces permission errors", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 403,
      jsonData: { error: "forbidden" },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.explorerNfts.list(),
    (error) => error instanceof ToriiHttpError && error.status === 403,
  );
});


test("getExplorerRwaDetail encodes path and decodes response", async () => {
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    assert.equal(
      parsed.pathname,
      `/v1/explorer/rwas/${encodeURIComponent(SAMPLE_RWA_ID)}`,
    );
    return createResponse({
      status: 200,
      jsonData: {
        id: SAMPLE_RWA_ID,
        owned_by: SAMPLE_ACCOUNT_ID,
        quantity: "2",
        held_quantity: "0",
        primary_reference: "vault-cert-002",
        status: null,
        is_frozen: true,
        metadata: {},
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const detail = await client.getExplorerRwaDetail(SAMPLE_RWA_ID_UPPER);
  assert.deepEqual(detail, {
    id: SAMPLE_RWA_ID,
    ownedBy: SAMPLE_ACCOUNT_ID,
    quantity: "2",
    heldQuantity: "0",
    primaryReference: "vault-cert-002",
    status: null,
    isFrozen: true,
    metadata: {},
    raw: {
      id: SAMPLE_RWA_ID,
      owned_by: SAMPLE_ACCOUNT_ID,
      quantity: "2",
      held_quantity: "0",
      primary_reference: "vault-cert-002",
      status: null,
      is_frozen: true,
      metadata: {},
    },
  });
});

test("explorer RWA readbacks reject noncanonical quantity fields", async () => {
  for (const record of [
    {
      id: SAMPLE_RWA_ID,
      owned_by: SAMPLE_ACCOUNT_ID,
      quantity: "1.0",
      held_quantity: "0",
      primary_reference: "vault-cert",
      status: null,
      is_frozen: false,
      metadata: {},
    },
    {
      id: SAMPLE_RWA_ID,
      owned_by: SAMPLE_ACCOUNT_ID,
      quantity: "1",
      held_quantity: "-1",
      primary_reference: "vault-cert",
      status: null,
      is_frozen: false,
      metadata: {},
    },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: {
          next_cursor: null,
          items: [record],
        },
        headers: { "content-type": "application/json" },
      }),
    });
    await assert.rejects(
      () => client.explorerRwas.list(),
      /canonical non-negative Kotodama V1 quantity/u,
    );
  }
});


test("accountPermissions uses collection pagination and retains complete permission validation", async () => {
  const calls = [];
  const client = new ToriiClient(BASE_URL, { fetchImpl: async (url, init) => {
    calls.push({ url, init });
    return createResponse({ status: 200, headers: { "content-type": "application/json" },
      jsonData: { items: [{ name: "CanMintAssetToAccount", payload: { account: FIXTURE_ALICE_ID } }], next_cursor: null, total: 1 } });
  }});
  const page = await client.accountPermissions(FIXTURE_ALICE_ID).list({ limit: 5, cursor: "prior", includeTotal: true });
  assert.equal(new URL(calls[0].url).pathname, accountPath(FIXTURE_ALICE_ID, "/permissions/query"));
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].init.body), { limit: 5, cursor: "prior", include_total: true });
  assert.equal(page.items[0].name, "CanMintAssetToAccount");
  assert.deepEqual(page.items[0].payload, { account: FIXTURE_ALICE_ID });
  assert.equal(page.nextCursor, null);
  assert.equal(page.total, 1);
  assert.throws(() => client.accountPermissions(""), /accountId/);
  await assert.rejects(() => client.accountPermissions(FIXTURE_ALICE_ID).list({ offset: 0 }), /offset/);
  await assert.rejects(() => client.accountPermissions(FIXTURE_ALICE_ID).list({}, { signal: 1 }), /signal/);
  assert.equal(calls.length, 1);
});

test("accountPermissions validates full rows while explicit projections preserve selected fields", async () => {
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({
    status: 200, headers: { "content-type": "application/json" },
    jsonData: { items: [{ payload: { account: FIXTURE_ALICE_ID } }], next_cursor: null },
  }) });
  await assert.rejects(() => client.accountPermissions(FIXTURE_ALICE_ID).list(), /name/);
  const page = await client.accountPermissions(FIXTURE_ALICE_ID).list({ select: ["payload"] });
  assert.deepEqual(page.items, [{ payload: { account: FIXTURE_ALICE_ID } }]);
});

test("contract history collections reject retired row fields and preserve block coordinates", async () => {
  const activity = { entrypoint_hash: "tx1", result_ok: true, contract_address: "irohac1router", block_height: 4, block_index: 2 };
  // Canonical Iroha hashes end in an odd nibble (the hash marker bit).
  const blockHash = "11".repeat(32);
  const event = { event_id: `${blockHash}:2:0`, schema_version: 1, provenance: "emitted", execution_hash_hex: `${"aa".repeat(31)}ab`, block_height: 4,
    output_index: 2, emission_index: 0, block_hash_hex: blockHash, result_ok: true, contract_address: "irohac1router", authority: FIXTURE_ALICE_ID, event_kind: "Changed", payload: {},
    emission: { contract: "irohac1router", code_hash: canonicalHashLiteral(Buffer.from(blockHash, "hex")), entrypoint: 0, event: 0, caller: FIXTURE_ALICE_ID,
      definition: { name: "Changed", payload_type: { nodes: [{ kind: "Struct", value: { name: "Fixture::Changed", fields: [] } }] } }, payload: { schema_hash: Array(32).fill(1), atoms: [] } } };

  for (const [property, base] of [["contractActivity", activity], ["contractEvents", event]]) {
    for (const [field, value] of [["gas_asset_id", "xor#universal"], ["fee_sponsor", FIXTURE_ALICE_ID], ["gas_limit", 100000]]) {
      const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200,
        jsonData: { items: [{ ...base, [field]: value }], next_cursor: null }, headers: { "content-type": "application/json" } }) });
      await assert.rejects(() => client[property].list(), new RegExp(`${field} is retired`, "u"));
    }
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200,
      jsonData: { items: [base], next_cursor: "older" }, headers: { "content-type": "application/json" } }) });
    const page = await client[property].list();
    assert.equal(page.items[0].block_height, 4);
    assert.equal(page.items[0][property === "contractEvents" ? "output_index" : "block_index"], 2);
    assert.equal(page.nextCursor, "older");
  }
});

test("contract event rows and stream filters accept only committed emitted provenance", async () => {
  const forged = { provenance: "derived" };
  const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 200,
    jsonData: { items: [forged], next_cursor: null }, headers: { "content-type": "application/json" } }) });
  await assert.rejects(() => client.contractEvents.list(), /contract event row\.provenance must be emitted/u);
  let calls = 0;
  const offline = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("should not fetch");
    },
  });
  assert.throws(() => offline.streamContractEvents({ provenance: "derived" }), /provenance must be emitted/u);
  assert.equal(calls, 0);
});

test("getGovernanceContract reads active and suspended governed bindings", async () => {
  let calledUrl;
  let suspended = false;
  const fetchImpl = async (url) => {
    calledUrl = url;
    return createResponse({
      status: 200,
      jsonData: {
        found: true,
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        contract_subject_account: FIXTURE_ALICE_ID,
        dataspace: "universal",
        active: !suspended,
        lifecycle: {
          version: 1,
          origin: "direct",
          origin_account: FIXTURE_ALICE_ID,
          origin_proposal_content_id_hex: null,
          origin_governance_attempt_id_hex: null,
          owner: FIXTURE_ALICE_ID,
          pending_owner: "parliament",
          parliament_delegated: true,
          active_code_hash_hex: suspended ? null : fakeHashHex(0xaa),
          retained_code_hash_hex: fakeHashHex(0xaa),
          revision: 7,
          emergency_hold: null,
        },
        emergency_hold_active: false,
        ...(suspended ? {} : {
          code_hash_hex: fakeHashHex(0xaa),
          abi_hash_hex: fakeHashHex(0xbb),
          public_entrypoints: ["transfer", "view_balance"],
        }),
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getGovernanceContract(
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    canonicalReadOptions(),
  );
  assert.ok(
    calledUrl?.includes(
      "/v1/gov/contracts/irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    ),
  );
  assert.equal(result.found, true);
  assert.equal(result.dataspace, "universal");
  assert.equal(result.code_hash_hex, fakeHashHex(0xaa));
  assert.equal(result.lifecycle.revision, 7);
  assert.equal(result.lifecycle.active_code_hash_hex, fakeHashHex(0xaa));
  assert.equal(result.lifecycle.pending_owner, "parliament");
  assert.deepEqual(result.public_entrypoints, ["transfer", "view_balance"]);
  suspended = true;
  const inactive = await client.getGovernanceContract(result.contract_address, canonicalReadOptions());
  assert.equal(inactive.lifecycle.active_code_hash_hex, null);
  assert.equal(inactive.lifecycle.retained_code_hash_hex, fakeHashHex(0xaa));
});

test("iterateTriggers paginates list endpoint", async () => {
  let callCount = 0;
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/v1/triggers");
    assert.equal(parsed.searchParams.get("namespace"), "apps");
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    callCount += 1;
    const items =
      offset === 0
        ? [
            { id: "trigger-1", owner: FIXTURE_ALICE_ID },
            { id: "trigger-2", owner: FIXTURE_BOB_ID },
          ]
        : [{ id: "trigger-3", owner: FIXTURE_CAROL_ID }];
    return createResponse({
      status: 200,
      jsonData: { items, total: 3 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const trigger of client.iterateTriggers({ namespace: "apps", pageSize: 2 })) {
    ids.push(trigger.id);
  }
  assert.deepEqual(ids, ["trigger-1", "trigger-2", "trigger-3"]);
  assert.equal(callCount, 2);
});

test("iterateTriggersQuery paginates query payloads", async () => {
  let callCount = 0;
  const fetchImpl = async (url, init) => {
    assert.equal(init.method, "POST");
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/v1/triggers/query");
    const body = JSON.parse(init.body);
    const offset = Number(body.pagination?.offset ?? 0);
    assert.deepEqual(body.filter, { op: "eq", args: ["object.authority", FIXTURE_ALICE_ID] });
    callCount += 1;
    const items =
      offset === 0
        ? [
            { id: "trigger-1", owner: FIXTURE_ALICE_ID },
            { id: "trigger-2", owner: FIXTURE_ALICE_ID },
          ]
        : [{ id: "trigger-3", owner: FIXTURE_ALICE_ID }];
    return createResponse({
      status: 200,
      jsonData: { items, total: 3 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const trigger of client.iterateTriggersQuery({
    filter: { op: "eq", args: ["object.authority", FIXTURE_ALICE_ID] },
    pageSize: 2,
  })) {
    ids.push(trigger.id);
  }
  assert.deepEqual(ids, ["trigger-1", "trigger-2", "trigger-3"]);
  assert.equal(callCount, 2);
});

test("resolveToriiClientConfig merges config, env, and overrides", async () => {
  await withEnv(
    {
      IROHA_TORII_TIMEOUT_MS: "1500",
      IROHA_TORII_RETRY_STATUSES: "500, 503",
    },
    () => {
      const resolved = resolveToriiClientConfig({
        env: process.env,
        config: {
          torii: { apiTokens: ["from-config"] },
          toriiClient: {
            maxRetries: 4,
            retryMethods: ["get", "post"],
            retryProfiles: {
              streaming: { maxRetries: 9 },
            },
          },
        },
        overrides: {
          apiToken: "override-token",
          backoffInitialMs: 250,
          retryProfiles: {
            pipeline: { maxRetries: 6, retryMethods: ["post"] },
          },
        },
      });
      assert.equal(resolved.timeoutMs, 1500);
      assert.equal(resolved.maxRetries, 4);
      assert.equal(resolved.backoffInitialMs, 250);
      assert.ok(resolved.retryMethods.has("POST"));
      assert.ok(resolved.retryStatuses.has(500));
      assert.equal(resolved.apiToken, "override-token");
      assert.deepEqual(resolved.retryProfiles.pipeline.maxRetries, 6);
      assert.ok(resolved.retryProfiles.pipeline.retryMethods.has("POST"));
      assert.equal(resolved.retryProfiles.streaming.maxRetries, 9);
    },
  );
});

test("removed transaction status fallback configuration fails fast", () => {
  assert.throws(
    () =>
      new ToriiClient(BASE_URL, {
        fetchImpl: async () => createResponse({ status: 404 }),
        statusEndpoints: ["https://fallback.example"],
      }),
    /statusEndpoints is no longer supported/,
  );
  assert.throws(
    () =>
      resolveToriiClientConfig({
        config: {
          toriiClient: {
            transactionStatusScope: "local",
          },
        },
      }),
    /transactionStatusScope is no longer supported/,
  );
});

test("explicit Torii configuration wins over opt-in environment fallbacks", () => {
  const resolved = resolveToriiClientConfig({
    env: {
      IROHA_TORII_TIMEOUT_MS: "999",
      IROHA_TORII_AUTH_TOKEN: "ambient-auth",
      IROHA_TORII_API_TOKEN: "ambient-api",
    },
    config: { toriiClient: { timeoutMs: 456, authToken: "config-auth" } },
    overrides: { timeoutMs: 123, apiToken: "explicit-api" },
  });
  assert.equal(resolved.timeoutMs, 123);
  assert.equal(resolved.authToken, "config-auth");
  assert.equal(resolved.apiToken, "explicit-api");
  assert.throws(
    () => resolveToriiClientConfig({ overrides: { backoffMultiplier: 0.5 } }),
    /backoffMultiplier must be at least 1/u,
  );
});

test("retired transaction status environment variables are ignored", async () => {
  await withEnv(
    {
      IROHA_TORII_TX_STATUS_SCOPE: "local",
      IROHA_TORII_STATUS_ENDPOINTS: "https://fallback.example",
    },
    () => {
      const resolved = resolveToriiClientConfig();
      assert.equal("transactionStatusScope" in resolved, false);
      assert.equal("statusEndpoints" in resolved, false);
    },
  );
});

test("extractToriiFeatureConfig omits the retired RBC sampling section", () => {
  const hashedAccountRaw = SAMPLE_ACCOUNT_FORMS.i105;
  const hashedAccountCanonical = normalizeAccountId(
    hashedAccountRaw,
    "hashedAccount",
  );
  const snapshot = extractToriiFeatureConfig({
    config: {
      torii: {
        iso_bridge: {
          enabled: true,
          dedupe_ttl_secs: 30,
          signer: { account_id: hashedAccountRaw, private_key: "ed01" },
          account_aliases: [
            { iban: VALID_IBAN, account_id: hashedAccountRaw },
            { iban: "DE89370400440532013000", account_id: FIXTURE_ALICE_TEST_ID },
          ],
          currency_assets: [
            {
              currency: "USD",
              asset_definition: "usd#bank",
              max_amount: "1000000",
            },
          ],
        },
        [["rbc", "sampling"].join("_")]: {
          enabled: true,
          max_samples_per_request: 4,
          max_bytes_per_request: 1024,
          daily_byte_budget: 2048,
          rate_per_minute: 12,
        },
      },
      connect: {
        enabled: false,
        ws_max_sessions: 10,
        ws_per_ip_max_sessions: 2,
        ws_rate_per_ip_per_min: 60,
        session_ttl_ms: 1000,
        frame_max_bytes: 1024,
        session_buffer_max_bytes: 2048,
        dedupe_ttl_ms: 500,
        dedupe_cap: 16,
        relay_enabled: true,
        relay_strategy: "broadcast",
        p2p_ttl_hops: 1,
      },
    },
  });
  assert.ok(snapshot.isoBridge?.enabled);
  const signerAccountId = snapshot.isoBridge?.signer?.accountId
    ? normalizeAccountId(snapshot.isoBridge.signer.accountId, "isoBridge.signer.accountId")
    : null;
  assert.equal(signerAccountId, hashedAccountCanonical);
  assert.equal(snapshot.isoBridge?.accountAliases.length, 2);
  const aliasAccountId = snapshot.isoBridge?.accountAliases[0]?.accountId
    ? normalizeAccountId(
        snapshot.isoBridge.accountAliases[0].accountId,
        "isoBridge.accountAliases[0].accountId",
      )
    : null;
  assert.equal(aliasAccountId, hashedAccountCanonical);
  assert.equal(snapshot.isoBridge?.accountAliases[1]?.accountId, FIXTURE_ALICE_TEST_ID);
  assert.deepEqual(snapshot.isoBridge?.currencyAssets, [
    {
      currency: "USD",
      assetDefinition: "usd#bank",
      maxAmount: "1000000",
    },
  ]);
  assert.equal(Object.prototype.hasOwnProperty.call(snapshot, "rbcSampling"), false);
  assert.deepEqual(Object.keys(snapshot).sort(), ["connect", "isoBridge"]);
  assert.equal(snapshot.connect?.wsMaxSessions, 10);
});

test("extractConfidentialGasConfig returns normalized schedule", () => {
  const config = {
    confidential: {
      gas: {
        proof_base: 250_000,
        per_public_input: 2_000,
        per_proof_byte: 5,
        per_nullifier: 300,
        per_commitment: 500,
      },
    },
  };
  const gas = extractConfidentialGasConfig({ config });
  assert.deepEqual(gas, {
    proofBase: 250_000,
    perPublicInput: 2_000,
    perProofByte: 5,
    perNullifier: 300,
    perCommitment: 500,
  });
});

test("ToriiClient.getConfidentialGasSchedule fetches schedule", async () => {
  const payload = {
    confidential_gas: {
      proof_base: 111,
      per_public_input: 22,
      per_proof_byte: 3,
      per_nullifier: 4,
      per_commitment: 5,
    },
  };
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const gas = await client.getConfidentialGasSchedule();
  assert.deepEqual(gas, {
    proofBase: 111,
    perPublicInput: 22,
    perProofByte: 3,
    perNullifier: 4,
    perCommitment: 5,
  });
});

test("ToriiClient.getConfigurationTyped normalizes snapshot", async () => {
  const payload = {
    public_key: "ed01",
    logger: {
      level: "info",
      filter: "torii=debug",
    },
    network: {
      block_gossip_size: 512,
      block_gossip_period_ms: 250,
      transaction_gossip_size: 64,
      transaction_gossip_period_ms: 150,
    },
    queue: {
      capacity: 4096,
    },
    confidential_gas: {
      proof_base: 100,
      per_public_input: 10,
      per_proof_byte: 1,
      per_nullifier: 2,
      per_commitment: 3,
    },
    transport: {
      norito_rpc: {
        enabled: true,
        stage: "ga",
        require_mtls: true,
        canary_allowlist_size: 3,
      },
    },
    nexus: {
      axt: {
        slot_length_ms: 1_000,
        max_clock_skew_ms: 250,
        proof_cache_ttl_slots: 3,
        replay_retention_slots: 256,
      },
    },
  };
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getConfigurationTyped();
  assert.deepEqual(snapshot, {
    publicKeyHex: "ed01",
    logger: { level: "info", filter: "torii=debug" },
    network: {
      blockGossipSize: 512,
      blockGossipPeriodMs: 250,
      transactionGossipSize: 64,
      transactionGossipPeriodMs: 150,
    },
    queue: { capacity: 4096 },
    confidentialGas: {
      proofBase: 100,
      perPublicInput: 10,
      perProofByte: 1,
      perNullifier: 2,
      perCommitment: 3,
    },
    transport: {
      noritoRpc: {
        enabled: true,
        stage: "ga",
        requireMtls: true,
        canaryAllowlistSize: 3,
      },
    },
    nexus: {
      axt: {
        slotLengthMs: 1_000,
        maxClockSkewMs: 250,
        proofCacheTtlSlots: 3,
        replayRetentionSlots: 256,
      },
    },
  });
});

test("ToriiClient.getConfigurationTyped returns null on 404", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 404,
      jsonData: null,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getConfigurationTyped();
  assert.strictEqual(snapshot, null);
});

test("ToriiClient ignores ambient credentials unless explicitly configured", async () => {
  await withEnv(
    {
      IROHA_TORII_API_TOKEN: "env-token",
    },
    async () => {
      const captures = [];
      const fetchImpl = async (url, init) => {
        captures.push({ url, init });
        return createResponse({
          status: 200,
          jsonData: [],
          headers: { "content-type": "application/json" },
        });
      };
      const client = new ToriiClient(BASE_URL, {
        fetchImpl,
        defaultHeaders: { "User-Agent": "iroha-js" },
        authToken: "local-auth",
        allowInsecure: true,
      });
      await client.listAttachments(canonicalReadOptions());
      assert.equal(captures.length, 1);
      const headers = captures[0].init.headers;
      assert.equal(headers["User-Agent"], "iroha-js");
      assert.equal(headers["X-API-Token"], undefined);
      assert.equal(headers["X-Iroha-API-Token"], undefined);
      assert.equal(headers.Authorization, "Bearer local-auth");
    },
  );
});

test("ToriiClient requires an exact boolean for insecure credential transport", () => {
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };
  for (const allowInsecure of ["false", "true", 0, 1, {}, []]) {
    assert.throws(
      () =>
        new ToriiClient("http://torii.example", {
          allowInsecure,
          authToken: "secret",
          fetchImpl,
        }),
      /allowInsecure must be a boolean/u,
    );
  }
  assert.equal(fetchCalls, 0);
});

test("ToriiClient retries retryable statuses", async () => {
  let attempt = 0;
  const fetchImpl = async () => {
    attempt += 1;
    if (attempt < 3) {
      return createResponse({ status: 503, jsonData: {} });
    }
    return createResponse({
      status: 200,
      textBody: "OK\n",
      headers: { "content-type": "text/plain" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 3,
    backoffInitialMs: 0,
  });
  const response = await client.getHealth();
  assert.deepEqual(response, { status: "OK" });
  assert.equal(attempt, 3);
});

test("ToriiClient emits retry telemetry events", async () => {
  let attempt = 0;
  const events = [];
  const fetchImpl = async () => {
    attempt += 1;
    if (attempt === 1) {
      return createResponse({ status: 503, jsonData: {} });
    }
    return createResponse({
      status: 200,
      textBody: "OK\n",
      headers: { "content-type": "text/plain" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    maxRetries: 2,
    backoffInitialMs: 0,
    retryTelemetryHook: (event) => events.push(event),
  });
  const response = await client.getHealth();
  assert.equal(response?.status, "OK");
  assert.equal(attempt, 2);
  assert.equal(events.length, 1);
  const event = events[0];
  assert.equal(event.phase, "response");
  assert.equal(event.attempt, 1);
  assert.equal(event.nextAttempt, 2);
  assert.equal(event.maxRetries, 2);
  assert.equal(event.method, "GET");
  assert.equal(event.status, 503);
  assert.equal(typeof event.timestampMs, "number");
  assert.equal(typeof event.durationMs, "number");
  assert.ok(event.durationMs >= 0);
});

test("ToriiClient composes request timeouts with caller cancellation", async () => {
  const fetchImpl = async (_url, init) =>
    new Promise((_, reject) => {
      const abort = () => {
        const abortError =
          typeof DOMException !== "undefined"
            ? new DOMException("Aborted", "AbortError")
            : Object.assign(new Error("Aborted"), { name: "AbortError" });
        reject(abortError);
      };
      if (init.signal?.aborted) {
        abort();
        return;
      }
      init.signal?.addEventListener(
        "abort",
        abort,
        { once: true },
      );
    });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    timeoutMs: 10,
    maxRetries: 0,
  });
  const liveCaller = new AbortController();
  await assert.rejects(
    () =>
      client.listAttachments({
        ...canonicalReadOptions(),
        signal: liveCaller.signal,
      }),
    /AbortError|aborted/i,
  );

  const callerAbort = new AbortController();
  const callerReason = new Error("caller stopped request");
  const slowTimeoutClient = new ToriiClient(BASE_URL, {
    fetchImpl,
    timeoutMs: 1_000,
    maxRetries: 0,
  });
  const pending = slowTimeoutClient.listAttachments({
    ...canonicalReadOptions(),
    signal: callerAbort.signal,
  });
  callerAbort.abort(callerReason);
  await assert.rejects(pending, /AbortError|aborted/i);
});

test("streamEvents signs the exact final path and query with the default identity", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(
      url,
      `${BASE_URL}/v1/events/sse?${new URLSearchParams({ filter: "block_height > 0" })}`,
    );
    assert.equal(init.headers["Last-Event-ID"], undefined);
    assert.equal(init.redirect, "error");
    assert.equal(
      init.headers["X-Iroha-Account"],
      AccountAddress.parseEncoded(
        APPLICATION_CANONICAL_AUTH.accountId,
      ).address.canonicalHex(),
    );
    const requestUrl = new URL(url);
    const signatureMessage = canonicalRequestSignatureMessage({
      networkId: VK_SIGNING_NETWORK_ID,
      method: "GET",
      path: requestUrl.pathname,
      query: requestUrl.searchParams,
      body: "",
      timestampMs: Number(init.headers["X-Iroha-Timestamp-Ms"]),
      nonce: init.headers["X-Iroha-Nonce"],
    });
    assert.deepEqual(
      Buffer.from(init.headers["X-Iroha-Signature"], "base64"),
      signEd25519(signatureMessage, APPLICATION_CANONICAL_AUTH.privateKey),
    );
    return createSseResponse([
      "id: block-1\n",
      "event: pipeline.block\n",
      'data: {"height":1}\n',
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const iterator = client.streamEvents({
    filter: field("block_height").gt(0),
  });
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.deepEqual(first.value, {
    event: "pipeline.block",
    data: { height: 1 },
    id: "block-1",
    retry: null,
    raw: '{"height":1}',
  });
  const second = await iterator.next();
  assert.equal(second.done, true);
});

test("streamEvents stays anonymous when no default signer is configured", async () => {
  let requestInit;
  const client = new ToriiClient(BASE_URL, {
    canonicalRequestAuth: null,
    fetchImpl: async (_url, init) => {
      requestInit = init;
      return createSseResponse([
        "event: pipeline.block\n",
        'data: {"height":1}\n',
        "\n",
      ]);
    },
  });
  const iterator = client.streamEvents();
  assert.equal((await iterator.next()).done, false);
  assert.equal((await iterator.next()).done, true);
  assert.equal(requestInit.headers["X-Iroha-Account"], undefined);
  assert.equal(requestInit.headers["X-Iroha-Signature"], undefined);
  assert.equal(requestInit.headers["X-Iroha-Timestamp-Ms"], undefined);
  assert.equal(requestInit.headers["X-Iroha-Nonce"], undefined);
  assert.equal(requestInit.redirect, undefined);
});

test("streamContractEvents encodes selector params", async () => {
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/v1/contracts/events/sse");
    assert.equal(parsed.searchParams.get("contract_address"), "irohac1router");
    assert.equal(parsed.searchParams.get("event_kind"), "route_swap");
    assert.equal(parsed.searchParams.get("authority"), FIXTURE_ALICE_ID);
    assert.equal(parsed.searchParams.get("asset_id"), "xor#universal");
    assert.equal(init.headers["Last-Event-ID"], undefined);
    return createSseResponse([
      "id: tx1:0\n",
      "event: contract_event\n",
      'data: {"event_id":"tx1:0","event_kind":"route_swap"}\n',
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const iterator = client.streamContractEvents({
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1router",
    eventKind: "route_swap",
    assetId: "xor#universal",
  });
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.deepEqual(first.value, {
    event: "contract_event",
    data: { event_id: "tx1:0", event_kind: "route_swap" },
    id: "tx1:0",
    retry: null,
    raw: '{"event_id":"tx1:0","event_kind":"route_swap"}',
  });
  const second = await iterator.next();
  assert.equal(second.done, true);
});

test("streamEvents retries SSE handshake using streaming profile", async () => {
  let attempts = 0;
  const fetchImpl = async (_url) => {
    attempts += 1;
    if (attempts === 1) {
      return createResponse({ status: 503, jsonData: {} });
    }
    return createSseResponse([
      "id: block-2\n",
      "event: pipeline.block\n",
      'data: {"height":2}\n',
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, {
    canonicalRequestAuth: null,
    fetchImpl,
    maxRetries: 0,
  });
  const iterator = client.streamEvents();
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.equal(first.value?.id, "block-2");
  assert.equal(attempts, 2);
});

test("streamSumeragiStatus signs each one-shot SSE subscription", async () => {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push(init);
    assert.equal(url, `${BASE_URL}/v1/sumeragi/status/sse`);
    assert.equal(init.redirect, "error");
    return createSseResponse([
      "event: sumeragi.status\n",
      'data: {"view":2}\n',
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const iterator = client.streamSumeragiStatus();
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.deepEqual(first.value, {
    event: "sumeragi.status",
    data: { view: 2 },
    id: null,
    retry: null,
    raw: '{"view":2}',
  });
  const next = await iterator.next();
  assert.equal(next.done, true);
  const secondIterator = client.streamSumeragiStatus();
  await secondIterator.next();
  await secondIterator.next();
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.headers.Accept, "text/event-stream");
    assert.ok(request.headers["X-Iroha-Operator-Public-Key"]);
    assert.ok(request.headers["X-Iroha-Operator-Signature"]);
  }
  assert.notEqual(
    requests[0].headers["X-Iroha-Operator-Nonce"],
    requests[1].headers["X-Iroha-Operator-Nonce"],
  );
});

test("streamSumeragiStatus rejects a missing operator signer before fetch", () => {
  let calls = 0;
  const client = new SourceToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("fetch must not run");
    },
  });
  assert.throws(
    () => client.streamSumeragiStatus(),
    /requires an immutable OperatorSigningContext/u,
  );
  assert.equal(calls, 0);
});

test("streamEvents rejects unsupported filter types", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamEvents({ filter: 42 }),
    { name: "ListQueryError", code: "invalid_filter", parameter: "filter" },
  );
});

test("streamEvents enforces option shapes", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamEvents("invalid"),
    /streamEvents options must be an object/,
  );
  assert.throws(
    () => client.streamEvents({ lastEventId: "retired-resume-token" }),
    /streamEvents options contains unsupported fields: lastEventId/,
  );
});

test("canonical contract SSE rejects the unsupported resume option before fetch", () => {
  let calls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("should not fetch");
    },
  });
  assert.throws(
    () => client.streamContractEvents({ lastEventId: "retired-resume-token" }),
    /streamContractEvents options contains unsupported fields: lastEventId/,
  );
  assert.equal(calls, 0);
});

test("streamEvents rejects unsupported options", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamEvents({ filter: {}, extra: true }),
    /streamEvents options contains unsupported fields: extra/,
  );
});

test("streamSumeragiStatus rejects unsupported options", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamSumeragiStatus({ unexpected: "oops" }),
    /streamSumeragiStatus options contains unsupported fields: unexpected/,
  );
});

test("streamKaigiRelayEvents enforces lastEventId strings", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamKaigiRelayEvents({ lastEventId: 42 }),
    /streamKaigiRelayEvents\.lastEventId must be a string/,
  );
});

test("streamKaigiRelayEvents rejects unsupported options", () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  assert.throws(
    () => client.streamKaigiRelayEvents({ domain: "kaigi", extra: true }),
    /streamKaigiRelayEvents options contains unsupported fields: extra/,
  );
});

test("getKaigiCall returns null on 404 and normalizes call views", async () => {
  const callId = "kaigi:demo-room";
  const missingClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const missing = await missingClient.getKaigiCall(callId);
  assert.equal(missing, null);

  let requested;
  const fetchImpl = async (url) => {
    requested = url;
    return createResponse({
      status: 200,
      jsonData: {
        call_id: callId,
        domain: "kaigi",
        call_name: "demo-room",
        title: "Weekly Sync",
        gas_rate_per_minute: 0,
        metadata: {
          kaigi_call: {
            schema: "iroha-demo-kaigi-call/v1",
          },
        },
        scheduled_start_ms: 1700000000000,
        privacy_mode: "private",
        room_policy: "authenticated",
        relay_manifest: {
          expiryMs: 1700000001000,
        },
        roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX,
        commitment_count: 1,
        nullifier_count: 0,
        usage_commitment_count: 0,
        status: "active",
        created_at_ms: 1699999999000,
        total_duration_ms: 0,
        total_billed_gas: 0,
        segments_recorded: 0,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const call = await client.getKaigiCall(callId);
  assert.equal(requested, `${BASE_URL}/v1/kaigi/calls/${encodeURIComponent(callId)}`);
  assert.equal(call?.call_id, callId);
  assert.equal(call?.privacy_mode, "private");
  assert.equal(call?.participant_count, undefined);
  assert.equal(call?.host_account_id, undefined);
  assert.equal(call?.relay_manifest?.expiryMs, 1700000001000);
});

test("listKaigiCallSignals encodes filters and normalizes payloads", async () => {
  const callId = "kaigi:demo-room";
  let requested;
  let requestInit;
  const fetchImpl = async (url, init) => {
    requested = url;
    requestInit = init;
    assert.ok(init.signal === undefined || init.signal instanceof AbortSignal);
    return createResponse({
      status: 200,
      jsonData: {
        has_more: true,
        next_cursor: "Abcd_123",
        items: [
          {
            entrypoint_hash: KAIGI_HPKE_FINGERPRINT_HEX,
            timestamp_ms: 1700000000100,
            call_id: callId,
            signal_kind: "answer",
            created_at_ms: 1700000000000,
            metadata: {
              schema: KAIGI_SIGNAL_SCHEMA_V1,
            },
          },
        ],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const signals = await client.listKaigiCallSignals(callId, {
    afterTimestampMs: 1700000000000,
    limit: 10,
    cursor: "Prev_123",
  });
  assert.ok(requested?.includes(`/v1/kaigi/calls/${encodeURIComponent(callId)}/signals`));
  assert.ok(requested?.includes("after_timestamp_ms=1700000000000"));
  assert.ok(requested?.includes("limit=10"));
  assert.ok(requested?.includes("cursor=Prev_123"));
  assert.equal(requestInit?.redirect, "error");
  assert.equal(
    requestInit?.headers?.["X-Iroha-Account"],
    AccountAddress.parseEncoded(
      APPLICATION_CANONICAL_AUTH.accountId,
    ).address.canonicalHex(),
  );
  const requestUrl = new URL(requested);
  const signatureMessage = canonicalRequestSignatureMessage({
    networkId: VK_SIGNING_NETWORK_ID,
    method: "GET",
    path: requestUrl.pathname,
    query: requestUrl.searchParams,
    body: "",
    timestampMs: Number(requestInit?.headers?.["X-Iroha-Timestamp-Ms"]),
    nonce: requestInit?.headers?.["X-Iroha-Nonce"],
  });
  assert.deepEqual(
    Buffer.from(requestInit?.headers?.["X-Iroha-Signature"], "base64"),
    signEd25519(signatureMessage, APPLICATION_CANONICAL_AUTH.privateKey),
  );
  assert.equal(signals.has_more, true);
  assert.equal(signals.next_cursor, "Abcd_123");
  assert.equal(signals.items[0].signal_kind, "answer");
  assert.equal(signals.items[0].authority, undefined);
  assert.equal(signals.items[0].participant_account_id, undefined);
  assert.equal(signals.items[0].created_at_ms, 1700000000000);
  assert.equal(signals.items[0].metadata.schema, KAIGI_SIGNAL_SCHEMA_V1);
});

test("listKaigiCallSignals rejects malformed required wire fields", async () => {
  const callId = "kaigi:demo-room";
  for (const payload of [
    { has_more: false, items: false },
    { items: [] },
    {
      has_more: false,
      items: [
        {
          entrypoint_hash: "deadbeef",
          call_id: callId,
          signal_kind: "answer",
          metadata: {},
        },
      ],
    },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.listKaigiCallSignals(callId),
      /(?:items must be an array|fields are not canonical)/u,
    );
  }
});

test("listKaigiCallSignals rejects offset and noncanonical cursors before fetch", async () => {
  let fetches = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetches += 1;
      throw new Error("invalid cursor options must fail before fetch");
    },
  });
  await assert.rejects(
    () => client.listKaigiCallSignals("kaigi:demo-room", { offset: 1 }),
    /unsupported fields: offset/u,
  );
  for (const cursor of ["", " padded", "not+padded=", "A"]) {
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(
      () => client.listKaigiCallSignals("kaigi:demo-room", { cursor }),
      /(?:must not be empty|surrounding whitespace|base64url)/u,
    );
  }
  assert.equal(fetches, 0);
});

test("listKaigiCallSignals prefers per-call canonical auth and rejects missing auth", async () => {
  const callId = "kaigi:demo-room";
  const explicitAuth = {
    accountId: FIXTURE_ALICE_ID,
    privateKey: Buffer.alloc(32, 0x3c),
  };
  let captured;
  let fetches = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      fetches += 1;
      captured = { url, init };
      return createResponse({
        status: 200,
        jsonData: { has_more: false, items: [] },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.listKaigiCallSignals(callId, {
    limit: 1,
    canonicalAuth: explicitAuth,
  });
  assert.equal(
    captured?.init?.headers?.["X-Iroha-Account"],
    AccountAddress.parseEncoded(explicitAuth.accountId).address.canonicalHex(),
  );
  const requestUrl = new URL(captured.url);
  const signatureMessage = canonicalRequestSignatureMessage({
    networkId: VK_SIGNING_NETWORK_ID,
    method: "GET",
    path: requestUrl.pathname,
    query: requestUrl.searchParams,
    body: "",
    timestampMs: Number(captured.init.headers["X-Iroha-Timestamp-Ms"]),
    nonce: captured.init.headers["X-Iroha-Nonce"],
  });
  assert.deepEqual(
    Buffer.from(captured.init.headers["X-Iroha-Signature"], "base64"),
    signEd25519(signatureMessage, explicitAuth.privateKey),
  );
  await assert.rejects(
    () => client.listKaigiCallSignals(callId, { canonicalAuth: null }),
    /canonicalAuth is required/u,
  );
  assert.equal(fetches, 1, "explicit null must not fall back to the client signer");

  let unauthenticatedFetches = 0;
  const unauthenticated = new ToriiClient(BASE_URL, {
    canonicalRequestAuth: null,
    fetchImpl: async () => {
      unauthenticatedFetches += 1;
      throw new Error("missing auth must fail before fetch");
    },
  });
  await assert.rejects(
    () => unauthenticated.listKaigiCallSignals(callId),
    /canonicalAuth is required/u,
  );
  assert.equal(unauthenticatedFetches, 0);
});

test("streamKaigiCallEvents encodes filters and normalizes payloads", async () => {
  const callId = "kaigi:demo-room";
  let requested;
  const fetchImpl = async (url, init) => {
    requested = url;
    assert.equal(init.headers["Last-Event-ID"], "cursor");
    return createSseResponse([
      "event: kaigi.call\n",
      `data: {"kind":"roster_updated","call":{"call_id":"${callId}","domain":"kaigi","call_name":"demo-room"},"privacy_mode":"private","commitment_count":1,"nullifier_count":0,"roster_root_hex":"${KAIGI_HPKE_FINGERPRINT_HEX}"}\n`,
      "\n",
      "event: kaigi.call\n",
      `data: {"kind":"ended","call":{"call_id":"${callId}","domain":"kaigi","call_name":"demo-room"},"status":"ended","ended_at_ms":1700000001000}\n`,
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const iterator = client.streamKaigiCallEvents(callId, {
    kind: ["roster_updated", "ended"],
    lastEventId: "cursor",
  });
  const first = await iterator.next();
  assert.equal(first.value?.data?.kind, "roster_updated");
  assert.equal(first.value?.data?.call.call_name, "demo-room");
  const second = await iterator.next();
  assert.equal(second.value?.data?.kind, "ended");
  assert.equal(second.value?.data?.ended_at_ms, 1700000001000);
  assert.ok(requested?.includes("kind=roster_updated%2Cended"));
});

test("listKaigiRelays rejects unsupported option keys", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listKaigiRelays({ extra: true }),
    /listKaigiRelays options contains unsupported fields: extra/,
  );
});

test("listKaigiRelays normalizes summary payloads", async () => {
  let requested;
  const fetchImpl = async (url) => {
    requested = url;
    return createResponse({
      status: 200,
      jsonData: {
        total: 1,
        items: [
          {
            relay_id: FIXTURE_ALICE_ID,
            domain: "kaigi",
            bandwidth_class: 255,
            hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
            status: "healthy",
            reported_at_ms: 42,
          },
        ],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.listKaigiRelays();
  assert.equal(requested, `${BASE_URL}/v1/kaigi/relays`);
  assert.equal(payload.total, 1);
  assert.equal(payload.items.length, 1);
  assert.equal(payload.items[0].bandwidth_class, 255);
  assert.equal(payload.items[0].status, "healthy");
  assert.equal(payload.items[0].reported_at_ms, 42);
});

test("listKaigiRelays rejects invalid bandwidth classes", async () => {
  for (const bandwidthClass of [undefined, 0, 256, true]) {
    const relay = {
      relay_id: FIXTURE_ALICE_ID,
      domain: "kaigi",
      hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
    };
    if (bandwidthClass !== undefined) {
      relay.bandwidth_class = bandwidthClass;
    }
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: { total: 1, items: [relay] },
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.listKaigiRelays(),
      /(?:missing=\[bandwidth_class\]|bandwidth_class must (?:be a canonical unsigned integer|be between 0 and 255|be between 1 and 255))/u,
    );
  }
});

test("listKaigiRelays rejects non-string health status", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          total: 1,
          items: [
            {
              relay_id: FIXTURE_ALICE_ID,
              domain: "kaigi",
              bandwidth_class: 1,
              hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
              status: ["healthy"],
              reported_at_ms: 1,
            },
          ],
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.listKaigiRelays(),
    /status must be a string/u,
  );
});

test("listKaigiRelays rejects malformed and oversized envelopes", async () => {
  const validRelay = {
    relay_id: FIXTURE_ALICE_ID,
    domain: "kaigi",
    bandwidth_class: 1,
    hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
  };
  for (const payload of [
    { total: 0, items: false },
    { items: [] },
    { total: 501, items: Array.from({ length: 501 }, () => validRelay) },
    {
      total: 1,
      items: [{ ...validRelay, hpke_fingerprint_hex: new Array(32).fill(0xaa) }],
    },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.listKaigiRelays(),
      /(?:items must be an array|fields are not canonical|items must not exceed 500 entries|hpke_fingerprint_hex must be a string)/u,
    );
  }
});

test("listKaigiRelays forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/kaigi/relays`);
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: { total: 0, items: [] },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = await client.listKaigiRelays({ signal: controller.signal });
  assert.equal(payload.total, 0);
});
test("getKaigiRelay returns null on 404 and normalizes detail response", async () => {
  const relayId = FIXTURE_ALICE_ID;
  const notFoundClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const missing = await notFoundClient.getKaigiRelay(relayId);
  assert.equal(missing, null);

  let requested;
  const fetchImpl = async (url) => {
    requested = url;
    return createResponse({
      status: 200,
      jsonData: {
        relay: {
          relay_id: relayId,
          domain: "kaigi",
          bandwidth_class: 7,
          hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
          status: "degraded",
          reported_at_ms: 99,
        },
        hpke_public_key_b64: KAIGI_HPKE_PUBLIC_KEY_B64,
        reported_call: { domain_id: "kaigi", call_name: "demo" },
        reported_by: FIXTURE_BOB_ID,
        notes: "staged",
        metrics: {
          domain: "kaigi",
          registrations_total: 3,
          manifest_updates_total: 1,
          failovers_total: 2,
          health_reports_total: 4,
        },
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const detail = await client.getKaigiRelay(relayId);
  assert.equal(requested, `${BASE_URL}/v1/kaigi/relays/${encodeURIComponent(relayId)}`);
  assert.equal(detail?.hpke_public_key_b64, KAIGI_HPKE_PUBLIC_KEY_B64);
  assert.equal(detail?.reported_call?.call_name, "demo");
  assert.equal(detail?.metrics?.registrations_total, 3);
});

test("getKaigiRelay rejects unsupported option keys", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getKaigiRelay(SAMPLE_ACCOUNT_FORMS.i105, { extra: true }),
    /getKaigiRelay options contains unsupported fields: extra/,
  );
});

test("getKaigiRelay rejects non-string health notes", async () => {
  const relayId = FIXTURE_ALICE_ID;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          relay: {
            relay_id: relayId,
            domain: "kaigi",
            bandwidth_class: 1,
            hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
            status: "healthy",
            reported_at_ms: 1,
          },
          hpke_public_key_b64: KAIGI_HPKE_PUBLIC_KEY_B64,
          reported_call: { domain_id: "kaigi", call_name: "demo" },
          reported_by: FIXTURE_BOB_ID,
          notes: 7,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.getKaigiRelay(relayId),
    /kaigi relay detail\.notes must be a string/u,
  );

  const invalidKeyClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          relay: {
            relay_id: relayId,
            domain: "kaigi",
            bandwidth_class: 1,
            hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
          },
          hpke_public_key_b64: "not-base64",
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => invalidKeyClient.getKaigiRelay(relayId),
    /kaigi relay detail\.hpke_public_key_b64 must be exact standard-base64/u,
  );
});

test("getKaigiRelay forwards AbortSignal", async () => {
  const relayId = FIXTURE_BOB_ID;
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/kaigi/relays/${encodeURIComponent(relayId)}`);
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: {
        relay: {
          relay_id: relayId,
          domain: "kaigi",
          bandwidth_class: 1,
          hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
        },
        hpke_public_key_b64: KAIGI_HPKE_PUBLIC_KEY_B64,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const detail = await client.getKaigiRelay(relayId, { signal: controller.signal });
  assert.equal(detail?.relay?.relay_id, relayId);
});

test("getKaigiRelaysHealth parses counters and domain metrics", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        healthy_total: 2,
        degraded_total: 1,
        unavailable_total: 0,
        reports_total: 5,
        registrations_total: 3,
        failovers_total: 1,
        domains: [
          {
            domain: "kaigi",
            registrations_total: 3,
            manifest_updates_total: 2,
            failovers_total: 1,
            health_reports_total: 5,
          },
        ],
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getKaigiRelaysHealth();
  assert.equal(snapshot.healthy_total, 2);
  assert.equal(snapshot.domains[0].manifest_updates_total, 2);
});

test("getKaigiRelaysHealth rejects missing or malformed required fields", async () => {
  const base = {
    healthy_total: 0,
    degraded_total: 0,
    unavailable_total: 0,
    reports_total: 0,
    registrations_total: 0,
    failovers_total: 0,
    domains: [],
  };
  const missingCounter = { ...base };
  delete missingCounter.reports_total;
  for (const payload of [
    { ...base, domains: false },
    missingCounter,
    { ...base, domains: Array.from({ length: 501 }, () => ({})) },
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.getKaigiRelaysHealth(),
      /(?:domains must be an array|fields are not canonical|domains must not exceed 500 entries)/u,
    );
  }
});

test("getKaigiRelaysHealth rejects unsupported option keys", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getKaigiRelaysHealth({ extra: true }),
    /getKaigiRelaysHealth options contains unsupported fields: extra/,
  );
});

test("getKaigiRelaysHealth forwards AbortSignal", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/kaigi/relays/health`);
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: {
        healthy_total: 0,
        degraded_total: 0,
        unavailable_total: 0,
        reports_total: 0,
        registrations_total: 0,
        failovers_total: 0,
        domains: [],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getKaigiRelaysHealth({ signal: controller.signal });
  assert.equal(snapshot.healthy_total, 0);
});

test("streamKaigiRelayEvents encodes filters and normalizes payloads", async () => {
  const relayId = FIXTURE_ALICE_ID;
  let requested;
  const fetchImpl = async (url, init) => {
    requested = url;
    assert.equal(init.headers["Last-Event-ID"], "cursor");
    return createSseResponse([
      'event: kaigi\n',
      `data: {"kind":"registration","domain":"kaigi","relay_id":"${relayId}","bandwidth_class":1,"hpke_fingerprint_hex":"${KAIGI_HPKE_FINGERPRINT_HEX}"}\n`,
      "\n",
      'event: kaigi\n',
      `data: {"kind":"unregistration","domain":"kaigi","relay_id":"${relayId}"}\n`,
      "\n",
      'event: kaigi\n',
      `data: {"kind":"health","domain":"kaigi","relay_id":"${relayId}","status":"degraded","reported_at_ms":5000,"call":{"domain":"kaigi","name":"demo"}}\n`,
      "\n",
    ]);
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const iterator = client.streamKaigiRelayEvents({
    domain: "Kaigi",
    relay: relayId,
    kind: ["registration", "unregistration", "health"],
    lastEventId: "cursor",
  });
  const first = await iterator.next();
  assert.equal(first.value?.data?.kind, "registration");
  const second = await iterator.next();
  assert.equal(second.value?.data?.kind, "unregistration");
  const third = await iterator.next();
  assert.equal(third.value?.data?.status, "degraded");
  assert.equal(third.value?.data?.call.name, "demo");
  assert.ok(requested?.includes("domain=kaigi"));
  assert.ok(requested?.includes(`relay=${encodeURIComponent(relayId)}`));
  assert.ok(requested?.includes("kind=registration%2Cunregistration%2Chealth"));
});

test("streamKaigiRelayEvents rejects extra unregistration fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createSseResponse([
      "event: kaigi\n",
      `data: {"kind":"unregistration","domain":"kaigi","relay_id":"${FIXTURE_ALICE_ID}","status":"healthy"}\n`,
      "\n",
    ]),
  });
  const iterator = client.streamKaigiRelayEvents();
  await assert.rejects(() => iterator.next(), /fields are not canonical/u);
});

test("streamKaigiRelayEvents rejects invalid registration bandwidth classes", async () => {
  for (const bandwidthClass of [undefined, 0, 256, true]) {
    const relayId = FIXTURE_ALICE_ID;
    const event = {
      kind: "registration",
      domain: "kaigi",
      relay_id: relayId,
      hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
    };
    if (bandwidthClass !== undefined) {
      event.bandwidth_class = bandwidthClass;
    }
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createSseResponse([
          "event: kaigi\n",
          `data: ${JSON.stringify(event)}\n`,
          "\n",
        ]),
    });
    const iterator = client.streamKaigiRelayEvents();
    await assert.rejects(
      () => iterator.next(),
      /(?:missing=\[bandwidth_class\]|bandwidth_class must (?:be a canonical unsigned integer|be between 0 and 255|be between 1 and 255))/u,
    );
  }
});

test("streamKaigiRelayEvents rejects non-object and incomplete event payloads", async () => {
  for (const data of [
    "not-json",
    JSON.stringify({
      kind: "health",
      domain: "kaigi",
      relay_id: FIXTURE_ALICE_ID,
      status: "healthy",
      call: { domain: "kaigi", name: "demo" },
    }),
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createSseResponse(["event: kaigi\n", `data: ${data}\n`, "\n"]),
    });
    const iterator = client.streamKaigiRelayEvents();
    await assert.rejects(
      () => iterator.next(),
      /(?:invalid JSON|fields are not canonical)/u,
    );
  }
});

test("Kaigi JSON endpoints preserve literal u64 max values", async () => {
  const callId = "kaigi:full-u64";
  const u64Max = "18446744073709551615";
  const responses = [
    createResponse({
      status: 200,
      textBody: `{"call_id":"${callId}","domain":"kaigi","call_name":"full-u64","gas_rate_per_minute":${u64Max},"metadata":{},"scheduled_start_ms":${u64Max},"privacy_mode":"private","room_policy":"authenticated","relay_manifest":{"expiry_ms":${u64Max}},"roster_root_hex":"${KAIGI_HPKE_FINGERPRINT_HEX}","commitment_count":0,"nullifier_count":0,"usage_commitment_count":0,"status":"active","created_at_ms":${u64Max},"total_duration_ms":${u64Max},"total_billed_gas":${u64Max},"segments_recorded":0}`,
      headers: { "content-type": "application/json" },
    }),
    createResponse({
      status: 200,
      textBody: `{"has_more":false,"items":[{"entrypoint_hash":"${KAIGI_HPKE_FINGERPRINT_HEX}","timestamp_ms":${u64Max},"call_id":"${callId}","signal_kind":"answer","created_at_ms":${u64Max},"metadata":{"schema":"${KAIGI_SIGNAL_SCHEMA_V1}"}}]}`,
      headers: { "content-type": "application/json" },
    }),
    createResponse({
      status: 200,
      textBody: `{"total":1,"items":[{"relay_id":"${FIXTURE_ALICE_ID}","domain":"kaigi","bandwidth_class":1,"hpke_fingerprint_hex":"${KAIGI_HPKE_FINGERPRINT_HEX}","status":"healthy","reported_at_ms":${u64Max}}]}`,
      headers: { "content-type": "application/json" },
    }),
    createResponse({
      status: 200,
      textBody: `{"relay":{"relay_id":"${FIXTURE_ALICE_ID}","domain":"kaigi","bandwidth_class":1,"hpke_fingerprint_hex":"${KAIGI_HPKE_FINGERPRINT_HEX}"},"hpke_public_key_b64":"${KAIGI_HPKE_PUBLIC_KEY_B64}","metrics":{"domain":"kaigi","registrations_total":${u64Max},"manifest_updates_total":${u64Max},"failovers_total":${u64Max},"health_reports_total":${u64Max}}}`,
      headers: { "content-type": "application/json" },
    }),
    createResponse({
      status: 200,
      textBody: `{"healthy_total":1,"degraded_total":0,"unavailable_total":0,"reports_total":${u64Max},"registrations_total":${u64Max},"failovers_total":${u64Max},"domains":[{"domain":"kaigi","registrations_total":${u64Max},"manifest_updates_total":${u64Max},"failovers_total":${u64Max},"health_reports_total":${u64Max}}]}`,
      headers: { "content-type": "application/json" },
    }),
  ];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => responses.shift(),
  });
  const expected = 18_446_744_073_709_551_615n;

  const call = await client.getKaigiCall(callId);
  assert.equal(call.gas_rate_per_minute, expected);
  assert.equal(call.relay_manifest.expiry_ms, expected);
  const signals = await client.listKaigiCallSignals(callId);
  assert.equal(signals.has_more, false);
  assert.equal(signals.items[0].created_at_ms, expected);
  const relays = await client.listKaigiRelays();
  assert.equal(relays.items[0].reported_at_ms, expected);
  const detail = await client.getKaigiRelay(FIXTURE_ALICE_ID);
  assert.equal(detail.metrics.registrations_total, expected);
  assert.equal(detail.relay.hpke_fingerprint_hex, KAIGI_HPKE_FINGERPRINT_HEX);
  const health = await client.getKaigiRelaysHealth();
  assert.equal(health.reports_total, expected);
  assert.equal(health.domains[0].health_reports_total, expected);
});

test("Kaigi SSE endpoints preserve literal u64 max values", async () => {
  const callId = "kaigi:full-u64";
  const u64Max = "18446744073709551615";
  const responses = [
    createSseResponse([
      "event: kaigi.call\n",
      `data: {"kind":"ended","call":{"call_id":"${callId}","domain":"kaigi","call_name":"full-u64"},"status":"ended","ended_at_ms":${u64Max}}\n`,
      "\n",
    ]),
    createSseResponse([
      "event: kaigi\n",
      `data: {"kind":"health","domain":"kaigi","relay_id":"${FIXTURE_ALICE_ID}","status":"healthy","reported_at_ms":${u64Max},"call":{"domain":"kaigi","name":"full-u64"}}\n`,
      "\n",
    ]),
  ];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => responses.shift(),
  });
  const expected = 18_446_744_073_709_551_615n;

  const callEvent = await client.streamKaigiCallEvents(callId).next();
  assert.equal(callEvent.value.data.ended_at_ms, expected);
  const relayEvent = await client.streamKaigiRelayEvents().next();
  assert.equal(relayEvent.value.data.reported_at_ms, expected);
});

test("Kaigi call views enforce exact variants, privacy fields, and requested identity", async () => {
  const callId = "kaigi:strict";
  const base = {
    call_id: callId,
    domain: "kaigi",
    call_name: "strict",
    gas_rate_per_minute: 0,
    metadata: {},
    privacy_mode: "private",
    room_policy: "authenticated",
    roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX,
    commitment_count: 0,
    nullifier_count: 0,
    usage_commitment_count: 0,
    status: "active",
    created_at_ms: 1,
    total_duration_ms: 0,
    total_billed_gas: 0,
    segments_recorded: 0,
  };
  const cases = [
    [{ ...base, extra: true }, /fields are not canonical/u],
    [{ ...base, title: ["not", "text"] }, /title must be a string/u],
    [{ ...base, privacy_mode: "Private" }, /supported exact lowercase/u],
    [{ ...base, room_policy: "Authenticated" }, /supported exact lowercase/u],
    [{ ...base, status: "Active" }, /supported exact lowercase/u],
    [{ ...base, ended_at_ms: 2 }, /present exactly when status is ended/u],
    [{ ...base, status: "ended" }, /present exactly when status is ended/u],
    [{ ...base, max_participants: 0 }, /max_participants must be between 1/u],
    [{ ...base, max_participants: 4_097 }, /max_participants must be between 1 and 4096/u],
    [{ ...base, status: "ended", ended_at_ms: 0 }, /must not precede created_at_ms/u],
    [{ ...base, host_account_id: FIXTURE_ALICE_ID }, /agree with privacy_mode/u],
    [{ ...base, privacy_mode: "transparent" }, /agree with privacy_mode/u],
    [{ ...base, call_id: "kaigi:other" }, /match domain and call_name/u],
    [{ ...base, call_id: "other:strict", domain: "other" }, /requested call id/u],
    [{
      ...base,
      roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX.toUpperCase(),
    }, /exact lowercase 32-byte hex string/u],
    [{
      ...base,
      roster_root_hex: `0x${KAIGI_HPKE_FINGERPRINT_HEX}`,
    }, /exact lowercase 32-byte hex string/u],
    [{
      ...base,
      roster_root_hex: [...Buffer.from(KAIGI_HPKE_FINGERPRINT_HEX, "hex")],
    }, /must be a string/u],
    [{ ...base, roster_root_hex: "aa".repeat(32) }, /Iroha Hash marker bit/u],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(() => client.getKaigiCall(callId), pattern);
  }
});

test("Kaigi call signals enforce exact cursor pages and carrier-time invariants", async () => {
  const callId = "kaigi:strict";
  const signal = {
    entrypoint_hash: KAIGI_HPKE_FINGERPRINT_HEX,
    timestamp_ms: 10,
    call_id: callId,
    signal_kind: "answer",
    created_at_ms: 9,
    metadata: { schema: KAIGI_SIGNAL_SCHEMA_V1 },
  };
  const withoutTimestamp = { ...signal };
  delete withoutTimestamp.timestamp_ms;
  const cases = [
    [{ has_more: false, items: [{ ...signal, extra: true }] }, /fields are not canonical/u],
    [{ has_more: false, items: [withoutTimestamp] }, /fields are not canonical/u],
    [{ has_more: false, items: [{ ...signal, created_at_ms: 11 }] }, /must not exceed timestamp_ms/u],
    [{ has_more: false, items: [{ ...signal, call_id: "kaigi:other" }] }, /requested call id/u],
    [{ has_more: false, items: [{ ...signal, signal_kind: "" }] }, /must not be empty/u],
    [{ has_more: false, items: [{ ...signal, signal_kind: "\u0085answer" }] }, /Unicode whitespace/u],
    [{ has_more: false, items: [{ ...signal, signal_kind: "Answer" }] }, /uppercase ASCII/u],
    [{
      has_more: false,
      items: [{
        ...signal,
        entrypoint_hash: KAIGI_HPKE_FINGERPRINT_HEX.toUpperCase(),
      }],
    }, /exact lowercase 32-byte hex string/u],
    [{
      has_more: false,
      items: [{ ...signal, entrypoint_hash: `0x${KAIGI_HPKE_FINGERPRINT_HEX}` }],
    }, /exact lowercase 32-byte hex string/u],
    [{
      has_more: false,
      items: [{
        ...signal,
        entrypoint_hash: [...Buffer.from(KAIGI_HPKE_FINGERPRINT_HEX, "hex")],
      }],
    }, /must be a string/u],
    [{
      has_more: false,
      items: [{ ...signal, entrypoint_hash: "aa".repeat(32) }],
    }, /Iroha Hash marker bit/u],
    [{ has_more: false, items: [{ ...signal, metadata: {} }] }, /metadata\.schema must be/u],
    [{
      has_more: false,
      items: [{ ...signal, metadata: { schema: "kaigi-signal/v0" } }],
    }, /metadata\.schema must be/u],
    [{ has_more: true, items: [signal] }, /next_cursor must be present/u],
    [{ has_more: false, next_cursor: "Abcd_123", items: [signal] }, /next_cursor must be present/u],
    [{ has_more: true, next_cursor: "not+padded=", items: [signal] }, /base64url/u],
    [{ has_more: false, items: [signal, { ...signal }] }, /unique entrypoint_hash/u],
    [{
      has_more: false,
      items: [
        signal,
        {
          ...signal,
          entrypoint_hash: KAIGI_ALTERNATE_MARKED_HASH_HEX,
          timestamp_ms: 8,
          created_at_ms: 7,
        },
      ],
    }, null],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    if (pattern === null) {
      // Structural cursor order does not depend on carrier timestamps.
      // eslint-disable-next-line no-await-in-loop
      const page = await client.listKaigiCallSignals(callId);
      assert.equal(page.items.length, 2);
    } else {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => client.listKaigiCallSignals(callId), pattern);
    }
  }
});

test("Kaigi call signal kinds retain the open normalized vocabulary", async () => {
  for (const signalKind of [
    "offer",
    "answer",
    "ice",
    "signal",
    "vendor.signal",
    "信号",
    "\0",
    "\uFEFFsignal",
  ]) {
    const callId = "kaigi:open-signal-kind";
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: {
          has_more: false,
          items: [{
            entrypoint_hash: KAIGI_HPKE_FINGERPRINT_HEX,
            timestamp_ms: 10,
            call_id: callId,
            signal_kind: signalKind,
            created_at_ms: 9,
            metadata: { schema: KAIGI_SIGNAL_SCHEMA_V1 },
          }],
        },
        headers: { "content-type": "application/json" },
      }),
    });

    // eslint-disable-next-line no-await-in-loop
    const response = await client.listKaigiCallSignals(callId);
    assert.equal(response.items[0].signal_kind, signalKind);
  }
});

test("Kaigi call SSE variants enforce exact fields and requested identity", async () => {
  const callId = "kaigi:strict";
  const call = { call_id: callId, domain: "kaigi", call_name: "strict" };
  const privateRosterEvent = {
    kind: "roster_updated",
    call,
    privacy_mode: "private",
    commitment_count: 1,
    nullifier_count: 0,
    roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX,
  };
  const cases = [
    [{
      kind: "roster_updated",
      call,
      privacy_mode: "private",
      participant_count: 1,
      commitment_count: 1,
      nullifier_count: 0,
      roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX,
    }, /roster fields must agree/u],
    [{
      ...privateRosterEvent,
      roster_root_hex: KAIGI_HPKE_FINGERPRINT_HEX.toUpperCase(),
    }, /exact lowercase 32-byte hex string/u],
    [{
      ...privateRosterEvent,
      roster_root_hex: `0x${KAIGI_HPKE_FINGERPRINT_HEX}`,
    }, /exact lowercase 32-byte hex string/u],
    [{
      ...privateRosterEvent,
      roster_root_hex: [...Buffer.from(KAIGI_HPKE_FINGERPRINT_HEX, "hex")],
    }, /must be a string/u],
    [{ ...privateRosterEvent, roster_root_hex: "aa".repeat(32) }, /Iroha Hash marker bit/u],
    [{ kind: "ended", call, status: "ended", ended_at_ms: 2, extra: true }, /fields are not canonical/u],
    [{
      kind: "ended",
      call: { call_id: "other:strict", domain: "other", call_name: "strict" },
      status: "ended",
      ended_at_ms: 2,
    }, /requested call id/u],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createSseResponse([
        "event: kaigi.call\n",
        `data: ${JSON.stringify(payload)}\n`,
        "\n",
      ]),
    });
    const iterator = client.streamKaigiCallEvents(callId);
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(() => iterator.next(), pattern);
  }
});

test("Kaigi relay lists reject noncanonical status, pairs, totals, IDs, and duplicates", async () => {
  const relay = {
    relay_id: FIXTURE_ALICE_ID,
    domain: "kaigi",
    bandwidth_class: 1,
    hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
  };
  const cases = [
    [{ total: 1, items: [{ ...relay, status: "Healthy", reported_at_ms: 1 }] }, /exact lowercase/u],
    [{ total: 1, items: [{ ...relay, status: "healthy" }] }, /present together/u],
    [{ total: 2, items: [relay] }, /total must equal items\.length/u],
    [{ total: 2, items: [relay, relay] }, /unique relay_id/u],
    [{ total: 1, items: [{ ...relay, relay_id: "ops@kaigi" }] }, /(?:canonical I105|encoded i105)/u],
    [{ total: 1, items: [{ ...relay, extra: true }] }, /fields are not canonical/u],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(() => client.listKaigiRelays(), pattern);
  }
});

test("Kaigi relay details bind the marked Blake2b-32 HPKE fingerprint and feedback", async () => {
  const marked = Buffer.from(blake2b256(Buffer.from("ABCD")));
  marked[marked.length - 1] |= 1;
  assert.equal(marked.toString("hex"), KAIGI_HPKE_FINGERPRINT_HEX);
  const relay = {
    relay_id: FIXTURE_ALICE_ID,
    domain: "kaigi",
    bandwidth_class: 1,
    hpke_fingerprint_hex: KAIGI_HPKE_FINGERPRINT_HEX,
  };
  const base = {
    relay,
    hpke_public_key_b64: KAIGI_HPKE_PUBLIC_KEY_B64,
    metrics: {
      domain: "kaigi",
      registrations_total: 0,
      manifest_updates_total: 0,
      failovers_total: 0,
      health_reports_total: 0,
    },
  };
  const feedbackRelay = { ...relay, status: "healthy", reported_at_ms: 1 };
  const cases = [
    [{ ...base, relay: { ...relay, hpke_fingerprint_hex: `${"00".repeat(31)}01` } }, /must match the marked/u],
    [{ ...base, relay: feedbackRelay }, /feedback fields must agree/u],
    [{ ...base, reported_call: { domain_id: "kaigi", call_name: "demo" } }, /feedback fields must agree/u],
    [{ ...base, metrics: { ...base.metrics, domain: "other" } }, /metrics\.domain must match/u],
    [{
      ...base,
      relay: feedbackRelay,
      reported_call: { domain_id: "kaigi", call_name: "demo" },
      reported_by: "ops@kaigi",
    }, /(?:canonical I105|encoded i105)/u],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(() => client.getKaigiRelay(FIXTURE_ALICE_ID), pattern);
  }
});

test("Kaigi relay health rejects inconsistent aggregates and domain sets", async () => {
  const domain = {
    domain: "kaigi",
    registrations_total: 1,
    manifest_updates_total: 0,
    failovers_total: 1,
    health_reports_total: 1,
  };
  const base = {
    healthy_total: 1,
    degraded_total: 0,
    unavailable_total: 0,
    reports_total: 1,
    registrations_total: 1,
    failovers_total: 1,
    domains: [domain],
  };
  const cases = [
    [{ ...base, reports_total: 0 }, /reports_total must equal/u],
    [{ ...base, domains: [domain, domain] }, /sorted with unique/u],
    [{ ...base, extra: true }, /fields are not canonical/u],
    [{ ...base, healthy_total: 501 }, /status totals must not exceed 500/u],
  ];
  for (const [payload, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: payload,
        headers: { "content-type": "application/json" },
      }),
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(() => client.getKaigiRelaysHealth(), pattern);
  }
});

test("listProverReports encodes filters", async () => {
  const fetchImpl = async (url) => {
    assert.ok(url.includes("ok_only=true"));
    assert.ok(url.includes("limit=5"));
    return createResponse({
      status: 200,
      jsonData: [
        {
          id: "r-1",
          ok: false,
          error: "decode failed",
          content_type: "application/json",
          size: 10,
          created_ms: 1,
          processed_ms: 2,
          latency_ms: 1,
          zk1_tags: ["PROF"],
        },
      ],
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.listProverReports({ ok_only: true, limit: 5, ignored: null });
  assert.deepEqual(result, {
    kind: "reports",
    reports: [
      {
        id: "r-1",
        ok: false,
        error: "decode failed",
        content_type: "application/json",
        size: 10,
        created_ms: 1,
        processed_ms: 2,
        latency_ms: 1,
        zk1_tags: ["PROF"],
      },
    ],
  });
});

test("listProverReports rejects ids_only projections without filter", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: ["rep-1"],
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.listProverReports({}),
    /ids_only/,
  );
});

test("listProverReports returns ids when ids_only flag set", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: ["rep-1", "rep-2"],
        headers: { "content-type": "application/json" },
      }),
  });
  const result = await client.listProverReports({ ids_only: true });
  assert.deepEqual(result, { kind: "ids", ids: ["rep-1", "rep-2"] });
});

test("listProverReports returns message summaries when messages_only flag set", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: [
          { id: "rep-1", error: "oops" },
          { id: "rep-2", error: null },
        ],
        headers: { "content-type": "application/json" },
      }),
  });
  const result = await client.listProverReports({ messagesOnly: true });
  assert.deepEqual(result, {
    kind: "messages",
    messages: [
      { id: "rep-1", error: "oops" },
      { id: "rep-2", error: null },
    ],
  });
});

test("listProverReports rejects messages_only projection without filter", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: [{ id: "rep-1", error: "oops" }],
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(() => client.listProverReports({}), /messages_only/);
});

test("listProverReports normalizes prover filter inputs", async () => {
  let requestedUrl = "";
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url) => {
      requestedUrl = url;
      return createResponse({
        status: 200,
        jsonData: [],
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.listProverReports({
    okOnly: true,
    contentType: " application/json ",
    hasTag: "PROF",
    limit: "10",
    offset: 4n,
    sinceMs: "123",
    beforeMs: 456n,
    idsOnly: true,
    latest: true,
    order: "DESC",
    id: "rep-42",
  });
  assert.ok(requestedUrl.includes("/v1/zk/prover/reports?"));
  const params = new URL(requestedUrl).searchParams;
  assert.equal(params.get("ok_only"), "true");
  assert.equal(params.get("content_type"), "application/json");
  assert.equal(params.get("has_tag"), "PROF");
  assert.equal(params.get("limit"), "10");
  assert.equal(params.get("offset"), "4");
  assert.equal(params.get("since_ms"), "123");
  assert.equal(params.get("before_ms"), "456");
  assert.equal(params.get("ids_only"), "true");
  assert.equal(params.get("latest"), "true");
  assert.equal(params.get("order"), "desc");
  assert.equal(params.get("id"), "rep-42");
});

test("prover filter validation rejects invalid entries", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  await assert.rejects(
    () => client.listProverReports({ limit: "nope" }),
    /limit must be a positive integer/,
  );
  await assert.rejects(
    () => client.countProverReports({ unknownFilter: true }),
    /unknown prover filter 'unknownFilter'/,
  );
});

test("listProverReports forwards AbortSignal options", async () => {
  const controller = new AbortController();
  let capturedSignal = null;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (_url, init) => {
      capturedSignal = init?.signal ?? null;
      return createResponse({
        status: 200,
        jsonData: [],
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.listProverReports({}, { signal: controller.signal });
  assertRequestSignal(capturedSignal, controller.signal);
});

test("countProverReports rejects invalid AbortSignal option", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: { count: 0 },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.countProverReports({}, { signal: "nope" }),
    /countProverReports options\.signal must be an AbortSignal/,
  );
});

test("getProverReport fetches report by id", async () => {
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/zk/prover/reports/r-1`);
    assertRequestSignal(init?.signal, controller.signal);
    return createResponse({
      status: 200,
      jsonData: {
        id: "r-1",
        ok: true,
        error: null,
        content_type: "text/plain",
        size: 5,
        created_ms: 10,
        processed_ms: 12,
        latency_ms: 2,
        zk1_tags: null,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getProverReport("r-1", { signal: controller.signal });
  assert.deepEqual(result, {
    id: "r-1",
    ok: true,
    error: null,
    content_type: "text/plain",
    size: 5,
    created_ms: 10,
    processed_ms: 12,
    latency_ms: 2,
    zk1_tags: null,
  });
  await assert.rejects(() => client.getProverReport(""), /reportId/);
});

test("deleteProverReport issues delete", async () => {
  let called = false;
  const controller = new AbortController();
  const fetchImpl = async (url, init) => {
    called = true;
    assert.equal(url, `${BASE_URL}/v1/zk/prover/reports/r-2`);
    assert.equal(init.method, "DELETE");
    assertRequestSignal(init.signal, controller.signal);
    return createResponse({ status: 204 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.deleteProverReport("r-2", { signal: controller.signal });
  assert.ok(called);
  const notFoundClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  await notFoundClient.deleteProverReport("missing");
  await assert.rejects(() => client.deleteProverReport(""), /reportId/);
});

test("countProverReports returns parsed count", async () => {
  const controller = new AbortController();
  let capturedSignal = null;
  const fetchImpl = async (url, init) => {
    capturedSignal = init?.signal ?? null;
    assert.ok(url.includes("/v1/zk/prover/reports/count"));
    return createResponse({
      status: 200,
      jsonData: { count: 7 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const count = await client.countProverReports({ failed_only: true }, { signal: controller.signal });
  assert.equal(count, 7);
  assertRequestSignal(capturedSignal, controller.signal);
  const missingPayloadClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 200, jsonData: {} }),
  });
  await assert.rejects(
    () => missingPayloadClient.countProverReports(),
    /invalid prover count payload/,
  );
});

test("iterateProverReports paginates with filters and maxItems", async () => {
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    const limit = Number(parsed.searchParams.get("limit") ?? "0");
    assert.equal(parsed.searchParams.get("failed_only"), "true");
    assert.equal(limit, 1);
    if (offset >= 2) {
      throw new Error("prover iterator requested too many pages");
    }
    return createResponse({
      status: 200,
      jsonData: [
        {
          id: `rep-${offset}`,
          ok: false,
          error: null,
          content_type: "application/json",
          size: 0,
          created_ms: offset,
          processed_ms: offset + 1,
          latency_ms: 1,
          zk1_tags: null,
        },
      ],
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const report of client.iterateProverReports(
    { failedOnly: true },
    { pageSize: 1, maxItems: 2 },
  )) {
    ids.push(typeof report === "string" ? report : report.id);
  }
  assert.deepEqual(ids, ["rep-0", "rep-1"]);
});

test("iterateProverReports rejects unsupported iterator options", () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("unexpected fetch");
    },
  });
  assert.throws(
    () => client.iterateProverReports({ failedOnly: true }, { unexpected: true }),
    /iterator options contains unsupported fields: unexpected/,
  );
});

test("getConnectStatus returns null when disabled", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const status = await client.getConnectStatus();
  assert.equal(status, null);
});

test("getConnectStatus normalizes payload", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          enabled: true,
          sessions_total: 4,
          sessions_active: 2,
          per_ip_sessions: [{ ip: "127.0.0.1", sessions: 2 }],
          buffered_sessions: 1,
          total_buffer_bytes: 256,
          dedupe_size: 3,
          policy: {
            ws_max_sessions: 64,
            ws_per_ip_max_sessions: 4,
            ws_rate_per_ip_per_min: 60,
            session_ttl_ms: 1000,
            frame_max_bytes: 1024,
            session_buffer_max_bytes: 2048,
            relay_enabled: true,
            relay_strategy: "broadcast",
            relay_effective_strategy: "local_only",
            relay_p2p_attached: false,
            p2p_ttl_hops: 3,
            heartbeat_interval_ms: 5000,
            heartbeat_miss_tolerance: 2,
            heartbeat_min_interval_ms: 1000,
          },
          frames_in_total: 10,
          frames_out_total: 20,
          ciphertext_total: 30,
          dedupe_drops_total: 0,
          buffer_drops_total: 1,
          plaintext_control_drops_total: 2,
          monotonic_drops_total: 3,
          sequence_violation_closes_total: 4,
          role_direction_mismatch_total: 5,
          ping_miss_total: 4,
          p2p_rebroadcasts_total: 6,
          p2p_rebroadcast_skipped_total: 7,
          p2p_auth_failures_total: 8,
          p2p_ttl_drops_total: 9,
          p2p_unknown_session_drops_total: 10,
          p2p_session_claims_in_total: 11,
          p2p_session_claims_installed_total: 12,
          p2p_session_claim_conflicts_total: 13,
          p2p_role_consumed_total: 14,
          p2p_session_terminated_total: 15,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  const status = await client.getConnectStatus();
  assert.ok(status);
  assert.equal(status?.sessionsTotal, 4);
  assert.equal(status?.perIpSessions[0]?.ip, "127.0.0.1");
  assert.equal(status?.policy?.wsMaxSessions, 64);
  assert.equal(status?.policy?.relayEnabled, true);
  assert.equal(status?.policy?.relayStrategy, "broadcast");
  assert.equal(status?.policy?.relayEffectiveStrategy, "local_only");
  assert.equal(status?.policy?.relayP2pAttached, false);
  assert.equal(status?.policy?.p2pTtlHops, 3);
  assert.equal(status?.sequenceViolationClosesTotal, 4);
  assert.equal(status?.roleDirectionMismatchTotal, 5);
  assert.equal(status?.p2pRebroadcastsTotal, 6);
  assert.equal(status?.p2pRebroadcastSkippedTotal, 7);
  assert.equal(status?.p2pAuthFailuresTotal, 8);
  assert.equal(status?.p2pTtlDropsTotal, 9);
  assert.equal(status?.p2pUnknownSessionDropsTotal, 10);
  assert.equal(status?.p2pSessionClaimsInTotal, 11);
  assert.equal(status?.p2pSessionClaimsInstalledTotal, 12);
  assert.equal(status?.p2pSessionClaimConflictsTotal, 13);
  assert.equal(status?.p2pRoleConsumedTotal, 14);
  assert.equal(status?.p2pSessionTerminatedTotal, 15);
});

test("getConnectStatus preserves relay-disabled effective local-only fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          enabled: true,
          sessions_total: 1,
          sessions_active: 1,
          per_ip_sessions: [{ ip: "127.0.0.1", sessions: 1 }],
          buffered_sessions: 0,
          total_buffer_bytes: 0,
          dedupe_size: 0,
          policy: {
            ws_max_sessions: 64,
            ws_per_ip_max_sessions: 4,
            ws_rate_per_ip_per_min: 60,
            session_ttl_ms: 1000,
            frame_max_bytes: 1024,
            session_buffer_max_bytes: 2048,
            relay_enabled: false,
            relay_strategy: "broadcast",
            relay_effective_strategy: "local_only",
            relay_p2p_attached: true,
            p2p_ttl_hops: 0,
            heartbeat_interval_ms: 5000,
            heartbeat_miss_tolerance: 2,
            heartbeat_min_interval_ms: 1000,
          },
          frames_in_total: 1,
          frames_out_total: 1,
          ciphertext_total: 1,
          dedupe_drops_total: 0,
          buffer_drops_total: 0,
          plaintext_control_drops_total: 0,
          monotonic_drops_total: 0,
          sequence_violation_closes_total: 0,
          role_direction_mismatch_total: 0,
          ping_miss_total: 0,
          p2p_rebroadcasts_total: 0,
          p2p_rebroadcast_skipped_total: 0,
          p2p_auth_failures_total: 0,
          p2p_ttl_drops_total: 0,
          p2p_unknown_session_drops_total: 0,
          p2p_session_claims_in_total: 0,
          p2p_session_claims_installed_total: 0,
          p2p_session_claim_conflicts_total: 0,
          p2p_role_consumed_total: 0,
          p2p_session_terminated_total: 0,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  const status = await client.getConnectStatus();
  assert.ok(status);
  assert.equal(status?.policy?.relayEnabled, false);
  assert.equal(status?.policy?.relayStrategy, "broadcast");
  assert.equal(status?.policy?.relayEffectiveStrategy, "local_only");
  assert.equal(status?.policy?.relayP2pAttached, true);
  assert.equal(status?.policy?.p2pTtlHops, 0);
  assert.equal(status?.p2pRebroadcastsTotal, 0);
  assert.equal(status?.p2pRebroadcastSkippedTotal, 0);
  assert.equal(status?.p2pAuthFailuresTotal, 0);
  assert.equal(status?.p2pTtlDropsTotal, 0);
  assert.equal(status?.p2pUnknownSessionDropsTotal, 0);
  assert.equal(status?.p2pSessionClaimsInTotal, 0);
  assert.equal(status?.p2pSessionClaimsInstalledTotal, 0);
  assert.equal(status?.p2pSessionClaimConflictsTotal, 0);
  assert.equal(status?.p2pRoleConsumedTotal, 0);
  assert.equal(status?.p2pSessionTerminatedTotal, 0);
});

test("getConnectStatus rejects non-integer policy values", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          enabled: true,
          sessions_total: 1,
          sessions_active: 1,
          per_ip_sessions: [],
          buffered_sessions: 0,
          total_buffer_bytes: 0,
          dedupe_size: 0,
          policy: {
            ws_max_sessions: 64,
            ws_per_ip_max_sessions: 4,
            ws_rate_per_ip_per_min: 60,
            session_ttl_ms: 1000.5,
            frame_max_bytes: 1024,
            session_buffer_max_bytes: 2048,
            relay_enabled: true,
            relay_strategy: "broadcast",
            relay_effective_strategy: "local_only",
            relay_p2p_attached: false,
            p2p_ttl_hops: 0,
            heartbeat_interval_ms: 5000,
            heartbeat_miss_tolerance: 2,
            heartbeat_min_interval_ms: 1000,
          },
          frames_in_total: 0,
          frames_out_total: 0,
          ciphertext_total: 0,
          dedupe_drops_total: 0,
          buffer_drops_total: 0,
          plaintext_control_drops_total: 0,
          monotonic_drops_total: 0,
          sequence_violation_closes_total: 0,
          role_direction_mismatch_total: 0,
          ping_miss_total: 0,
          p2p_rebroadcasts_total: 0,
          p2p_rebroadcast_skipped_total: 0,
          p2p_auth_failures_total: 0,
          p2p_ttl_drops_total: 0,
          p2p_unknown_session_drops_total: 0,
          p2p_session_claims_in_total: 0,
          p2p_session_claims_installed_total: 0,
          p2p_session_claim_conflicts_total: 0,
          p2p_role_consumed_total: 0,
          p2p_session_terminated_total: 0,
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () => client.getConnectStatus(),
    (error) => {
      assert(error instanceof TypeError);
      assert.equal(error.name, "ValidationError");
      assert.match(error.message, /session_ttl_ms/);
      return true;
    },
  );
});

registerToriiClientConnectSessionTests({
  assert,
  BASE_URL,
  NetworkId,
  ToriiClient,
  VK_SIGNING_NETWORK_ID,
  createResponse,
  test,
});

test("listConnectApps normalizes registry payload", async () => {
  let capturedUrl;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: {
        items: [
          {
            app_id: "calc.wallet",
            display_name: "Calc Wallet",
            namespaces: ["apps"],
            metadata: { website: "https://calc.example" },
            policy: { allow_guardian: true },
          },
        ],
        total: 1,
        next_cursor: "abc",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const page = await client.listConnectApps({ limit: "5", cursor: "start" });
  assert.ok(capturedUrl.includes("limit=5"));
  assert.ok(capturedUrl.includes("cursor=start"));
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0].appId, "calc.wallet");
  assert.deepEqual(page.items[0].namespaces, ["apps"]);
  assert.equal(page.nextCursor, "abc");
});

test("listConnectApps rejects invalid AbortSignal option", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not invoke fetch");
    },
  });
  await assert.rejects(
    () =>
      client.listConnectApps({
        // @ts-expect-error runtime validation should reject incorrect signal
        signal: {},
      }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /listConnectApps options\.signal must be an AbortSignal/);
      return true;
    },
  );
});

test("iterateConnectApps paginates using cursors", async () => {
  let callCount = 0;
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/v1/connect/app/apps");
    const limit = Number(parsed.searchParams.get("limit"));
    const cursor = parsed.searchParams.get("cursor");
    callCount += 1;
    if (callCount === 1) {
      assert.equal(limit, 2);
      assert.equal(cursor, null);
      return createResponse({
        status: 200,
        jsonData: {
          items: [
            { app_id: "calc.wallet", namespaces: ["apps"], metadata: {}, policy: {} },
            { app_id: "mint.wallet", namespaces: ["apps"], metadata: {}, policy: {} },
          ],
          next_cursor: "cursor-1",
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(limit, 2);
    assert.equal(cursor, "cursor-1");
    return createResponse({
      status: 200,
      jsonData: {
        items: [{ app_id: "vault.wallet", namespaces: ["apps"], metadata: {}, policy: {} }],
        next_cursor: null,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const app of client.iterateConnectApps({ pageSize: 2 })) {
    ids.push(app.appId);
  }
  assert.deepEqual(ids, ["calc.wallet", "mint.wallet", "vault.wallet"]);
  assert.equal(callCount, 2);
});

test("iterateConnectApps stops once maxItems is reached", async () => {
  let callCount = 0;
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    assert.equal(parsed.pathname, "/v1/connect/app/apps");
    const cursor = parsed.searchParams.get("cursor");
    callCount += 1;
    if (cursor) {
      assert.fail("iterator should not request another page after hitting maxItems");
    }
    return createResponse({
      status: 200,
      jsonData: {
        items: [
          { app_id: "calc.wallet", namespaces: ["apps"], metadata: {}, policy: {} },
          { app_id: "mint.wallet", namespaces: ["apps"], metadata: {}, policy: {} },
        ],
        next_cursor: "cursor-1",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const ids = [];
  for await (const app of client.iterateConnectApps({ pageSize: 5n, maxItems: "1" })) {
    ids.push(app.appId);
  }
  assert.deepEqual(ids, ["calc.wallet"]);
  assert.equal(callCount, 1);
});

test("getConnectApp normalizes record payloads", async () => {
  let capturedUrl;
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: {
        app_id: "calc.wallet",
        display_name: "Calc Wallet",
        metadata: { homepage: "https://calc.example" },
        policy: { relay_enabled: true },
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const record = await client.getConnectApp("calc.wallet");
  assert.equal(
    capturedUrl,
    `${BASE_URL}/v1/connect/app/apps/calc.wallet`,
    "connect app path mismatch",
  );
  assert.equal(record.appId, "calc.wallet");
  assert.equal(record.displayName, "Calc Wallet");
  assert.equal(record.metadata.homepage, "https://calc.example");
  assert.equal(record.policy.relay_enabled, true);
});

test("registerConnectApp posts normalized payload", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 201,
      jsonData: {
        app_id: "calc.wallet",
        namespaces: ["apps"],
        metadata: {},
        policy: {},
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const record = await client.registerConnectApp({
    appId: "calc.wallet",
    displayName: "Calc Wallet",
    namespaces: ["apps"],
    metadata: { website: "https://calc.example" },
    policy: { allow_guardian: true },
  });
  assert.equal(captured.url, `${BASE_URL}/v1/connect/app/apps`);
  const body = JSON.parse(captured.init.body);
  assert.equal(body.app_id, "calc.wallet");
  assert.equal(body.display_name, "Calc Wallet");
  assert.deepEqual(body.namespaces, ["apps"]);
  assert.deepEqual(record.appId, "calc.wallet");
});

test("registerConnectApp rejects invalid server payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 201,
      jsonData: { app: "calc.wallet" },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () =>
      client.registerConnectApp({
        appId: "calc.wallet",
        namespaces: ["apps"],
        metadata: {},
        policy: {},
      }),
    /connect app response/,
  );
});

test("deleteConnectApp returns true when record exists", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({ status: 204 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const removed = await client.deleteConnectApp("calc.wallet");
  assert.equal(removed, true);
  assert.equal(
    captured.url,
    `${BASE_URL}/v1/connect/app/apps/calc.wallet`,
    "delete app path mismatch",
  );
  assert.equal(captured.init.method, "DELETE");
});

test("deleteConnectApp returns false for missing record", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const removed = await client.deleteConnectApp("missing.wallet");
  assert.equal(removed, false);
});

test("getConnectAppPolicy normalizes controls", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        policy: {
          relay_enabled: true,
          ws_max_sessions: 25,
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const policy = await client.getConnectAppPolicy();
  assert.equal(policy.relayEnabled, true);
  assert.equal(policy.wsMaxSessions, 25);
});

test("getConnectAppPolicy rejects non-integer policy controls", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        policy: {
          relay_enabled: true,
          ws_max_sessions: 25.5,
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getConnectAppPolicy(),
    (error) => {
      assert(error instanceof RangeError);
      assert.match(error.message, /ws_max_sessions/);
      return true;
    },
  );
});

test("updateConnectAppPolicy serializes camelCase updates", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: {
        policy: {
          relay_enabled: true,
          ws_max_sessions: 15,
          session_ttl_ms: 60000,
        },
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.updateConnectAppPolicy({
    relayEnabled: true,
    wsMaxSessions: 15,
    sessionTtlMs: 60_000,
  });
  assert.equal(captured.url, `${BASE_URL}/v1/connect/app/policy`);
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    relay_enabled: true,
    ws_max_sessions: 15,
    session_ttl_ms: 60_000,
  });
  assert.equal(result.relayEnabled, true);
  assert.equal(result.wsMaxSessions, 15);
  assert.equal(result.sessionTtlMs, 60_000);
});

test("setConnectAdmissionManifest serializes entries", async () => {
  let capturedBody;
  const fetchImpl = async (url, init) => {
    capturedBody = JSON.parse(init.body);
    return createResponse({
      status: 200,
      jsonData: {
        entries: [
          { app_id: "calc.wallet", namespaces: ["apps"], metadata: {}, policy: {} },
        ],
        version: 1,
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const manifest = await client.setConnectAdmissionManifest({
    entries: [
      {
        appId: "calc.wallet",
        namespaces: ["apps"],
        metadata: {},
        policy: {},
      },
    ],
    version: 1,
  });
  assert.equal(capturedBody.entries[0].app_id, "calc.wallet");
  assert.equal(manifest.entries[0].appId, "calc.wallet");
});

test("getConnectAdmissionManifest normalizes manifest payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        manifest: {
          version: 2,
          entries: [{ app_id: "calc.wallet", namespaces: ["apps"], policy: {} }],
          manifest_hash: "abcd",
        },
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const manifest = await client.getConnectAdmissionManifest();
  assert.equal(manifest.version, 2);
  assert.equal(manifest.entries.length, 1);
  assert.equal(manifest.entries[0].appId, "calc.wallet");
  assert.equal(manifest.manifestHash, "abcd");
});

test("Connect admin wrappers reject non-object options", async () => {
  const noopFetch = async () => {
    throw new Error("fetch should not be invoked");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl: noopFetch });
  await assert.rejects(
    () => client.getConnectApp("calc.wallet", "bad"),
    /getConnectApp options must be an object/,
  );
  await assert.rejects(
    () =>
      client.registerConnectApp(
        { appId: "calc.wallet", namespaces: ["apps"], metadata: {} },
        123,
      ),
    /registerConnectApp options must be an object/,
  );
  await assert.rejects(
    () => client.getConnectAppPolicy(null),
    /getConnectAppPolicy options must be an object/,
  );
  await assert.rejects(
    () =>
      client.updateConnectAppPolicy(
        { relayEnabled: true, wsMaxSessions: 1, sessionTtlMs: 1000 },
        Symbol("options"),
      ),
    /updateConnectAppPolicy options must be an object/,
  );
  const manifestInput = {
    entries: [{ appId: "calc.wallet", namespaces: ["apps"], metadata: {} }],
    version: 1,
  };
  await assert.rejects(
    () => client.getConnectAdmissionManifest("oops"),
    /getConnectAdmissionManifest options must be an object/,
  );
  await assert.rejects(
    () => client.setConnectAdmissionManifest(manifestInput, false),
    /setConnectAdmissionManifest options must be an object/,
  );
});

test("Connect admin wrappers reject unsupported option fields", async () => {
  const noopFetch = async () => {
    throw new Error("fetch should not be invoked");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl: noopFetch });
  await assert.rejects(
    () => client.listConnectApps({ limit: 1, extra: true }),
    /listConnectApps options contains unsupported fields: extra/,
  );
  await assert.rejects(
    () => client.getConnectApp("calc.wallet", { retry: true }),
    /getConnectApp options contains unsupported fields: retry/,
  );
  await assert.rejects(
    () => client.getConnectAppPolicy({ cache: "nope" }),
    /getConnectAppPolicy options contains unsupported fields: cache/,
  );
});

test("local manifest builder normalizes a scoped manifest without forwarding credentials", async () => {

  const signer = `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`;
  const signature = `ed25519:${"22".repeat(64)}`;
  const signerCanonical = signer.split(":")[1];
  const signatureCanonical = signature.split(":")[1].toUpperCase();


  const body = await normalizeArtifactManifestFixture({


    manifest: {
      seiyakuName: "Ledger",
      codeHash: "ab".repeat(32),
      compilerFingerprint: "rustc",
      accessSetHints: {
        readKeys: ["account:alice"],
        writeKeys: ["contract:foo"],
        dynamicReads: [
          {
            baseKey: "state:Balances",
            keyType: "AccountId",
            boundKind: "take",
            maxKeys: 4,
          },
        ],
        dynamicWrites: [
          {
            base_key: "state:Votes",
            key_type: "Name",
            bound_kind: "page",
            max_keys: "2",
          },
        ],
      },
      entrypoints: [
        { name: "kaizen", kind: "Kaizen", ...UNIT_RETURN_DESCRIPTOR },
      ],
      states: [
        { name: "Balances", typeName: "StateMap<AccountId, quantity>" },
        { name: "Votes", typeName: "StateMap<Name, bool>" },
      ],
      kotoba: [
        {
          msg_id: "contract.title",
          translations: [{ lang: "en", text: "Ledger Contract" }],
        },
      ],
      provenance: {
        signer,
        signature,
      },
    },

  });




  assert.deepEqual(body, {
    artifact_id: { dataspace_id: "0", code_hash: canonicalHashLiteral(Buffer.alloc(32, 0xab)) },


    manifest: {
      seiyaku_name: "Ledger",
      code_hash: canonicalHashLiteral(Buffer.alloc(32, 0xab)),
      compiler_fingerprint: "rustc",
      abi_hash: null,
      features_bitmap: null,
      access_set_hints: {
        read_keys: ["account:alice"],
        write_keys: ["contract:foo"],
        dynamic_reads: [
          {
            base_key: "state:Balances",
            key_type: "AccountId",
            bound_kind: "take",
            max_keys: 4,
          },
        ],
        dynamic_writes: [
          {
            base_key: "state:Votes",
            key_type: "Name",
            bound_kind: "page",
            max_keys: 2,
          },
        ],
      },
      permissions: [],
      events: [],
      enum_types: [],
      entrypoints: [
        {
          name: "kaizen",
          kind: { kind: "Kaizen", value: null },
          params: [],
          argument_schema: null,
          return_type: "()",
          return_schema: { nodes: [{ kind: "Unit", value: null }] },
          authorization: { kind: "RuntimeLifecycle", value: null },
          read_keys: [],
          write_keys: [],
          access_hints_complete: null,
          access_hints_skipped: [],
          triggers: [],
        },
      ],
      states: [
        { name: "Balances", type_name: "StateMap<AccountId, quantity>" },
        { name: "Votes", type_name: "StateMap<Name, bool>" },
      ],
      error_types: null,
      error_messages: null,
      kotoba: [
        {
          msg_id: "contract.title",
          translations: [{ lang: "en", text: "Ledger Contract" }],
        },
      ],
      provenance: {
        signer: signerCanonical,
        signature: signatureCanonical,
      },
    },

  });
});

test("local manifest builder enforces exact V1 dynamic access hints", async () => {


  const submit = (hint) =>
    normalizeArtifactManifestFixture({


      manifest: {
        states: [
          { name: "Balances", typeName: "StateMap<AccountId, quantity>" },
          { name: "amount", typeName: "StateMap<AccountId, quantity>" },
        ],
        accessSetHints: {
          dynamicReads: [{
            baseKey: "state:Balances",
            keyType: "AccountId",
            boundKind: "take",
            maxKeys: 1,
            ...hint,
          }],
        },
      },
    });

  for (const baseKey of ["state:Balances", "state:amount"]) {
    await submit({ baseKey });
  }
  for (const [baseKey, expected] of [
    [
      "state:",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:*",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:Balances/",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:Balances/suffix",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:Balances:suffix",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:int",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "account:alice",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      " state:Balances",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
    [
      "state:Balances ",
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    ],
  ]) {
    await assert.rejects(
      submit({ baseKey }),
      expected,
    );
  }
  for (const keyType of ["Json", "ReferendumId", "Int", "Quantity", "Amount"]) {
    await assert.rejects(
      submit({ keyType }),
      /dynamicReads\[0\]\.keyType must be an exact Kotodama V1 StateMap key scalar/u,
    );
  }
  for (const [boundKind, expected] of [
    ["", /dynamicReads\[0\]\.boundKind must be a non-empty string/u],
    ["Take", /dynamicReads\[0\]\.boundKind must be exactly take or page/u],
    ["prefix", /dynamicReads\[0\]\.boundKind must be exactly take or page/u],
    [
      "range ",
      /dynamicReads\[0\]\.boundKind must be exactly take or page/u,
    ],
  ]) {
    await assert.rejects(
      submit({ boundKind }),
      expected,
    );
  }
  await assert.rejects(
    submit({ maxKeys: 0 }),
    /dynamicReads\[0\]\.maxKeys must be positive/u,
  );
  for (const maxKeys of [65, 0xffff_ffff]) {
    await assert.rejects(
      submit({ maxKeys }),
      /dynamicReads\[0\]\.maxKeys must be at most 64/u,
    );
  }
  await submit({ maxKeys: 64 });
  await submit({
    base_key: "state:Balances",
    key_type: "AccountId",
    bound_kind: "take",
    max_keys: 1,
  });
  for (const conflicting of [
    { base_key: "state:Other" },
    { key_type: "Name" },
    { bound_kind: "range" },
    { max_keys: 2 },
  ]) {
    await assert.rejects(
      submit(conflicting),
      /contains conflicting .* aliases/u,
    );
  }

});

test("local manifest builder resolves dynamic hints to declared StateMaps per list", async () => {


  const hint = {
    baseKey: "state:Balances",
    keyType: "AccountId",
    boundKind: "take",
    maxKeys: 1,
  };
  const submit = ({
    dynamicReads = [],
    dynamicWrites = [],
    states = [{ name: "Balances", typeName: "StateMap<AccountId, quantity>" }],
  }) =>
    normalizeArtifactManifestFixture({


      manifest: {
        states,
        accessSetHints: { dynamicReads, dynamicWrites },
      },
    });

  for (const field of ["dynamicReads", "dynamicWrites"]) {
    await submit({
      [field]: [
        hint,
        { ...hint, boundKind: "page", maxKeys: 2 },
      ],
    });
    await assert.rejects(
      submit({ [field]: [hint, { ...hint }] }),
      /duplicates an earlier dynamic access hint/u,
      `${field} must reject an exact duplicate`,
    );
    await assert.rejects(
      submit({ [field]: [{ ...hint, baseKey: "state:Missing" }] }),
      /baseKey must reference a declared top-level StateMap/u,
      `${field} must reject an unknown state`,
    );
    await assert.rejects(
      submit({
        [field]: [hint],
        states: [{ name: "Balances", typeName: "quantity" }],
      }),
      /baseKey must reference a declared top-level StateMap/u,
      `${field} must reject a scalar state`,
    );
    await assert.rejects(
      submit({ [field]: [{ ...hint, keyType: "Name" }] }),
      /keyType Name does not match declared StateMap key type AccountId/u,
      `${field} must reject a mismatched key scalar`,
    );
  }

  await submit({
    dynamicReads: [hint],
    dynamicWrites: [{ ...hint }],
  });
  await submit({
    dynamicWrites: [{
      ...hint,
      baseKey: "state:amount",
      keyType: "quantity",
    }],
    states: [{ name: "amount", typeName: "StateMap<quantity, int>" }],
  });

});

test("local manifest builder rejects retired English entrypoint kinds", async () => {



  for (const retired of ["Public", "public", "Init", "init", "Upgrade", "upgrade"]) {
    await assert.rejects(
      normalizeArtifactManifestFixture({


        manifest: {
          entrypoints: [{ name: "legacy", kind: retired }],
        },
      }),
      /must be one of 'Kotoage', 'View', 'Hajimari', or 'Kaizen'/,
    );
  }

});

test("local manifest builder preserves branded romanized and Japanese lifecycle selectors", async () => {
  let body;


  body = await normalizeArtifactManifestFixture({


    manifest: {
      seiyakuName: "BrandedLedger",
      entrypoints: [
        { name: "hajimari", kind: "Hajimari", ...UNIT_RETURN_DESCRIPTOR },
        { name: "改善", kind: "Kaizen", ...UNIT_RETURN_DESCRIPTOR },
        {
          name: "transfer",
          kind: "Kotoage",
          authorization: { kind: "Permission", value: "TransferAsset" },
          params: [{ name: "amount", typeName: "Option<int>" }],
          argumentSchema: {
            fields: [
              {
                name: "amount",
                ty: {
                  nodes: [
                    { kind: "Option", value: null },
                    { kind: "Leaf", value: { kind: "Int", value: null } },
                  ],
                },
              },
            ],
          },
          returnType: "Result<bool, string>",
          returnSchema: {
            nodes: [
              { kind: "Result", value: null },
              { kind: "Leaf", value: { kind: "Bool", value: null } },
              { kind: "Leaf", value: { kind: "String", value: null } },
            ],
          },
        },
        { name: "balance", kind: "View", ...UNIT_RETURN_DESCRIPTOR },
      ],
      states: [
        { name: "amount", typeName: "Fixture::Transfer{amount: quantity}" },
      ],
      errorTypes: [
        { identity: "LedgerError", variants: [{ name: "amount", code: 7 }] },
      ],
    },
  });

  assert.deepEqual(
    body.manifest.entrypoints.map(({ name, kind }) => [name, kind.kind]),
    [
      ["hajimari", "Hajimari"],
      ["改善", "Kaizen"],
      ["transfer", "Kotoage"],
      ["balance", "View"],
    ],
  );
  assert.deepEqual(body.manifest.states, [
    { name: "amount", type_name: "Fixture::Transfer{amount: quantity}" },
  ]);
  assert.equal(body.manifest.error_types[0].variants[0].name, "amount");
});

test("local manifest builder requires agreeing parameter and state type aliases", async () => {

  const quantity = {
    nodes: [{ kind: "Leaf", value: { kind: "Quantity", value: null } }],
  };
  const submit = (param, state) =>
    normalizeArtifactManifestFixture({


      manifest: {
        entrypoints: [{
          name: "read",
          kind: "View",
          ...UNIT_RETURN_DESCRIPTOR,
          params: [{ name: "amount", ...param }],
          argumentSchema: {
            fields: [{ name: "amount", ty: quantity }],
          },
        }],
        states: [{ name: "amount", ...state }],
      },
    });

  await assert.doesNotReject(
    submit(
      { typeName: "quantity", type_name: "quantity" },
      { typeName: "quantity", type_name: "quantity" },
    ),
  );
  await assert.rejects(
    submit(
      { typeName: "quantity", type_name: "int" },
      { typeName: "quantity" },
    ),
    /params\[0\]\.type_name contains conflicting type_name\/typeName aliases/u,
  );
  await assert.rejects(
    submit(
      { typeName: "quantity" },
      { typeName: "quantity", type_name: "int" },
    ),
    /states\[0\]\.type_name contains conflicting type_name\/typeName aliases/u,
  );
  await assert.rejects(
    submit({}, { typeName: "quantity" }),
    /params\[0\]\.type_name must be a non-empty string/u,
  );
  await assert.rejects(
    submit({ typeName: "quantity" }, {}),
    /states\[0\]\.type_name must be a non-empty string/u,
  );
});

const QUERY_VIEW_LAYOUTS = new Map([
  ["AccountView", { fields: ["id", "metadata"], children: ["AccountId", "Json"] }],
  ["AssetView", { fields: ["id", "amount"], children: ["AssetId", "Quantity"] }],
  [
    "AssetDefinitionView",
    {
      fields: ["id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"],
      children: [
        "AssetDefinitionId",
        "String",
        ["Option", "String"],
        "AccountId",
        "Quantity",
        ["Option", "Int"],
        "Json",
      ],
    },
  ],
  [
    "DomainView",
    { fields: ["id", "owned_by", "metadata"], children: ["DomainId", "AccountId", "Json"] },
  ],
  [
    "NftView",
    { fields: ["id", "owned_by", "content"], children: ["NftId", "AccountId", "Json"] },
  ],
]);

function entrypointLeaf(kind) {
  return { kind: "Leaf", value: { kind, value: null } };
}

function queryViewNodes(name) {
  const layout = QUERY_VIEW_LAYOUTS.get(name);
  assert.notEqual(layout, undefined);
  const children = layout.children.flatMap((child) =>
    Array.isArray(child)
      ? [{ kind: child[0], value: null }, entrypointLeaf(child[1])]
      : [entrypointLeaf(child)],
  );
  return [
    { kind: "Struct", value: { name: `kotodama::${name}`, fields: layout.fields } },
    ...children,
  ];
}

function queryPageNodes(name) {
  return [
    {
      kind: "Struct",
      value: { name: "kotodama::QueryPage", fields: ["items", "next_offset"] },
    },
    { kind: "List", value: { capacity: 64 } },
    ...queryViewNodes(name),
    { kind: "Option", value: null },
    entrypointLeaf("Int"),
  ];
}

test("local manifest builder accepts all exact query views, pages, and ordinary structs", async () => {
  let body;

  const entrypoints = [];
  for (const name of QUERY_VIEW_LAYOUTS.keys()) {
    entrypoints.push(
      {
        name: `get_${name.toLowerCase()}`,
        kind: "View",
        returnType: `Option<${name}>`,
        returnSchema: {
          nodes: [{ kind: "Option", value: null }, ...queryViewNodes(name)],
        },
      },
      {
        name: `page_${name.toLowerCase()}`,
        kind: "View",
        returnType: `QueryPage<${name}>`,
        returnSchema: { nodes: queryPageNodes(name) },
      },
    );
  }
  entrypoints.push({
    name: "pair",
    kind: "View",
    returnType: "struct Fixture::Pair",
    returnSchema: {
      nodes: [
        {
          kind: "Struct",
          value: { name: "Fixture::Pair", fields: ["left", "right"] },
        },
        entrypointLeaf("Int"),
        entrypointLeaf("Bool"),
      ],
    },
  });

  body = await normalizeArtifactManifestFixture({


    manifest: { seiyakuName: "QuerySchemas", entrypoints },
  });

  assert.equal(body.manifest.entrypoints.length, QUERY_VIEW_LAYOUTS.size * 2 + 1);
  assert.deepEqual(
    body.manifest.entrypoints.at(-1).return_schema.nodes[0].value,
    { name: "Fixture::Pair", fields: ["left", "right"] },
  );
});

test("local manifest builder rejects every forged reserved query view and page", async () => {


  const submit = (returnType, nodes) =>
    normalizeArtifactManifestFixture({


      manifest: {
        entrypoints: [
          { name: "read", kind: "View", returnType, returnSchema: { nodes } },
        ],
      },
    });

  for (const name of QUERY_VIEW_LAYOUTS.keys()) {
    const wrongFields = structuredClone(queryViewNodes(name));
    wrongFields[0].value.fields[0] = "forged";
    await assert.rejects(submit(name, wrongFields), /forged reserved query-view/u);

    const wrongLeaf = structuredClone(queryViewNodes(name));
    wrongLeaf[1].value.kind = "Bool";
    await assert.rejects(submit(name, wrongLeaf), /forged reserved query-view/u);

    const wrongPageCapacity = structuredClone(queryPageNodes(name));
    wrongPageCapacity[1].value.capacity = 32;
    await assert.rejects(
      submit(`QueryPage<${name}>`, wrongPageCapacity),
      /forged QueryPage/u,
    );

    const wrongPageOffset = structuredClone(queryPageNodes(name));
    wrongPageOffset.at(-1).value.kind = "String";
    await assert.rejects(
      submit(`QueryPage<${name}>`, wrongPageOffset),
      /forged QueryPage/u,
    );
  }

});

test("local manifest builder accepts the flat List tape at depth 256", async () => {
  let body;

  const listNodes = Array.from({ length: 255 }, () => ({
    kind: "List",
    value: { capacity: 1 },
  }));
  listNodes.push({ kind: "Leaf", value: { kind: "Int", value: null } });
  let returnType = "int";
  for (let depth = 0; depth < 255; depth += 1) {
    returnType = `List<${returnType}, 1>`;
  }

  body = await normalizeArtifactManifestFixture({


    manifest: {
      seiyakuName: "DeepList",
      entrypoints: [
        {
          name: "read",
          kind: "View",
          returnType,
          returnSchema: { nodes: listNodes },
        },
      ],
    },
  });

  assert.equal(body.manifest.entrypoints[0].return_schema.nodes.length, 256);
  assert.deepEqual(body.manifest.entrypoints[0].return_schema.nodes[0].value, {
    capacity: 1,
  });
});

test("local manifest builder rejects malformed and over-depth flat List tapes before encoding", async () => {


  const submit = (nodes, returnType = "List<int, 1>") =>
    normalizeArtifactManifestFixture({


      manifest: {
        entrypoints: [
          { name: "read", kind: "View", returnType, returnSchema: { nodes } },
        ],
      },
    });

  await assert.rejects(
    submit([{ kind: "List", value: { capacity: 1 } }]),
    /not one complete canonical prefix type tree/u,
  );
  await assert.rejects(
    submit([
      { kind: "List", value: { capacity: 1, element: { nodes: [] } } },
      { kind: "Leaf", value: { kind: "Int", value: null } },
    ]),
    /must contain only capacity; the element subtree follows in the enclosing node tape/u,
  );
  await assert.rejects(
    submit([
      ...Array.from({ length: 256 }, () => ({
        kind: "List",
        value: { capacity: 1 },
      })),
      { kind: "Leaf", value: { kind: "Int", value: null } },
    ]),
    /nodes must contain 1\.\.256 canonical type nodes/u,
  );

});

test("local manifest builder rejects forged branded manifest declarations before encoding", async () => {


  const submit = (manifest) =>
    normalizeArtifactManifestFixture({


      manifest,
    });

  for (const seiyakuName of [
    "",
    "Amount",
    "amount",
    "seiyaku",
    "match",
    "int",
    "state_map_get",
    "__kotodama_quantity_ratio_round",
    "__kotodama_decimal_to_int_trunc",
    "__kotodama_decimal_to_int_round",
    "__kotodama_link_forged",
    "９ledger",
  ]) {
    await assert.rejects(
      submit({ seiyakuName }),
      /seiyakuName must be a (?:non-empty string|canonical Kotodama V1 type declaration identifier)/u,
    );
  }
  for (const typeName of [
    "Amount",
    "amount",
    "StateMap<AccountId, Amount>",
    "Transfer{amount: amount}",
  ]) {
    await assert.rejects(
      submit({ states: [{ name: "Balances", typeName }] }),
      /states\[0\]\.type_name must be a canonical Kotodama V1 state type/u,
    );
  }
  for (const namespace of ["Invalid Error", "Error<Injected>"]) {
    await assert.rejects(
      submit({
        errorTypes: [{ identity: namespace, variants: [{ name: "Denied", code: 7 }] }],
      }),
      /errorTypes\[0\]\.identity must be a stable package\/unit\/enum identity/u,
    );
  }
  for (const keyType of [
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
  ]) {
    await assert.rejects(
      submit({
        accessSetHints: {
          readKeys: [],
          writeKeys: [],
          dynamicReads: [{
            baseKey: "state:Balances",
            keyType,
            boundKind: "take",
            maxKeys: 1,
          }],
          dynamicWrites: [],
        },
      }),
      /dynamicReads\[0\]\.keyType must be an exact Kotodama V1 StateMap key scalar/u,
    );
  }
  for (const retired of ["U128", "Amount"]) {
    await assert.rejects(
      submit({
        entrypoints: [{
          name: "legacy_numeric",
          kind: "View",
          returnType: retired,
          returnSchema: {
            nodes: [{ kind: "Leaf", value: { kind: retired, value: null } }],
          },
        }],
      }),
      /not a V1 entrypoint value kind/u,
    );
  }
  await assert.rejects(
    submit({ entrypoints: [{ name: "hajimari", kind: "Kotoage", authorization: { kind: "Permission", value: "Init" } }] }),
    /kind does not match its branded lifecycle selector/u,
  );
  await assert.rejects(
    submit({ entrypoints: [{ name: "setup", kind: "Hajimari" }] }),
    /kind does not match its branded lifecycle selector/u,
  );
  await assert.rejects(
    submit({ entrypoints: [{ name: "kaizen", kind: "Kaizen", authorization: { kind: "Permission", value: "Upgrade" } }] }),
    /authorization must use RuntimeLifecycle exactly for lifecycle hooks/u,
  );
  await assert.rejects(
    submit({ entrypoints: [{ name: "mutate", kind: "Kotoage", authorization: undefined }] }),
    /authorization requires exactly kind, value/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        { name: "same", kind: "View", ...UNIT_RETURN_DESCRIPTOR },
        { name: "same", kind: "Kotoage", authorization: { kind: "Permission", value: "Same" }, ...UNIT_RETURN_DESCRIPTOR },
      ],
    }),
    /entrypoints contains duplicate name same/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        {
          name: "read",
          kind: "View",
          ...UNIT_RETURN_DESCRIPTOR,
          accessHintsComplete: false,
          accessHintsSkipped: [],
        },
      ],
    }),
    /marks access hints incomplete without a reason/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        { name: "read", kind: "View", ...UNIT_RETURN_DESCRIPTOR },
        {
          name: "schedule",
          kind: "Kotoage",
          authorization: { kind: "Permission", value: "Schedule" },
          ...UNIT_RETURN_DESCRIPTOR,
          triggers: [
            {
              id: "bad_callback",
              repeats: { Indefinitely: null },
              filter: "AQ==",
              callback: { entrypoint: "read" },
            },
          ],
        },
      ],
    }),
    /local callback must target kotoage\/言挙げ/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        {
          name: "mutate",
          kind: "Kotoage",
          authorization: { kind: "Permission", value: "Mutate" },
          params: [{ name: "value", typeName: "int" }],
        },
      ],
    }),
    /argument_schema is required for declared parameters/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        {
          name: "mutate",
          kind: "Kotoage",
          authorization: { kind: "Permission", value: "Mutate" },
          params: [{ name: "match", typeName: "int" }],
        },
      ],
    }),
    /params\[0\]\.name must be unique and canonical/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        {
          name: "read",
          kind: "View",
          returnType: "List<int, 0>",
          returnSchema: {
            nodes: [
              {
                kind: "List",
                value: { capacity: 0 },
              },
              { kind: "Leaf", value: { kind: "Int", value: null } },
            ],
          },
        },
      ],
    }),
    /capacity must be in 1\.\.64/u,
  );
  await assert.rejects(
    submit({
      entrypoints: [
        {
          name: "read",
          kind: "View",
          returnType: "int",
          returnSchema: {
            nodes: [
              { kind: "Leaf", value: { kind: "Int", value: null } },
              { kind: "Leaf", value: { kind: "Bool", value: null } },
            ],
          },
        },
      ],
    }),
    /not one complete canonical prefix type tree/u,
  );
  await assert.rejects(
    submit({ contractName: "Legacy" }),
    /contains unsupported fields: contractName/u,
  );
  await assert.rejects(
    submit({ seiyakuName: "Ledger", seiyaku_name: "Other" }),
    /contains conflicting aliases: seiyaku_name, seiyakuName/u,
  );
  await assert.rejects(
    submit({ codeHash: "aa".repeat(32) }),
    /must set the Iroha Hash marker bit/u,
  );

});

test("setContractAlias posts payload and returns response", async () => {
  let captured;
  const responsePayload = verifyingKeyDraftForPayload(Buffer.from([4, 5]), {
    contract_alias: "router::universal",
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    dataspace: "universal",
  });
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.setContractAlias({
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    contractAlias: "router::universal",
    leaseExpiryMs: 1234,
  });
  assert.equal(captured.url, `${BASE_URL}/v1/contracts/aliases`);
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    authority: FIXTURE_ALICE_ID,
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    contract_alias: "router::universal",
    lease_expiry_ms: 1234,
  });
  assert.deepEqual(result, responsePayload);
});

test("setContractAlias supports clear requests and rejects lease expiry without an alias", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: verifyingKeyDraftForPayload(Buffer.from([4, 5]), {
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        dataspace: "universal",
      }),
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.setContractAlias({
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
  });
  assert.equal(captured.url, `${BASE_URL}/v1/contracts/aliases`);
  assert.deepEqual(JSON.parse(captured.init.body), {
    authority: FIXTURE_ALICE_ID,
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    contract_alias: null,
  });
  assert.equal(result.contract_alias, null);

  await assert.rejects(
    () =>
      client.setContractAlias({
        authority: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        leaseExpiryMs: 1234,
      }),
    /setContractAlias\.leaseExpiryMs requires contractAlias/,
  );
});

test("contract mutation drafts reject retired inline private-key fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch must not run for a secret-bearing request");
    },
  });
  await assert.rejects(
    () =>
      client.setContractAlias({
        authority: FIXTURE_ALICE_ID,
        privateKey: "secret",
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      }),
    /does not accept private-key fields/,
  );
  await assert.rejects(
    () =>
      client.prepareContractCall({
        authority: FIXTURE_ALICE_ID,
        private_key: "secret",
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        entrypoint: "increment",
        feePayment: authorityFeePayment(42),
      }),
    /does not accept private-key fields/,
  );
});

test("prepareContractCall posts a secret-free payload and normalizes the draft", async () => {
  let captured;
  const feePayment = sponsorFeePayment(FIXTURE_BOB_ID, 42, 3);
  const payload = { value: "7", labels: ["a", "b"] };
  const argumentSchema = {
    fields: [
      { name: "value", ty: { nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }] } },
      { name: "labels", ty: { nodes: [{ kind: "Leaf", value: { kind: "Json", value: null } }] } },
    ],
  };
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment,
    creationTimeMs: 42,
    metadata: { caller_note: "trusted" },
  });
  const responsePayload = {
    ok: true,
    submitted: false,
    dataspace: "universal",
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    tx_hash_hex: null,
    creation_time_ms: 42,
    transaction_ttl_ms: null,
    entrypoint: "increment",
    entrypoint_hash_hex: null,
    ...draft,
    operation_receipt: {
      operation_kind: "contract_call",
      status: "pending_signature",
      transport: "torii",
      dataspace: "universal",
      contract_alias: null,
      contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      code_hash_hex: "1".repeat(64),
      abi_hash_hex: "2".repeat(64),
      tx_hash_hex: null,
      entrypoint: "increment",
      entrypoint_hash_hex: null,
      gas_limit: 42,
      gas_used: null,
      fee_payment: feePayment,
      payload_digest_hex: contractPayloadDigestHex(payload),
    },
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const result = await client.prepareContractCall({
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    entrypoint: "increment",
    payload: { value: 7n, labels: ["a", "b"] },
    argumentSchema,
    metadata: { caller_note: "trusted" },
    creationTimeMs: 42,
    feePayment,
    draftIntent: contractDraftIntentForDraft(draft, { payload }),
  });
  assert.equal(captured.url, `${BASE_URL}/v1/contracts/call`);
  assert.equal(captured.init.redirect, "error");
  const accountHeader = captured.init.headers["X-Iroha-Account"];
  assert.equal(accountHeader, AccountAddress.parseEncoded(FIXTURE_ALICE_ID).address.canonicalHex());
  const signingMessage = canonicalRequestSignatureMessage({
    networkId: VK_SIGNING_NETWORK_ID,
    method: "POST",
    path: "/v1/contracts/call",
    body: captured.init.body,
    timestampMs: Number(captured.init.headers["X-Iroha-Timestamp-Ms"]),
    nonce: captured.init.headers["X-Iroha-Nonce"],
  });
  assert.deepEqual(
    Buffer.from(captured.init.headers["X-Iroha-Signature"], "base64"),
    signEd25519(signingMessage, APPLICATION_CANONICAL_AUTH.privateKey),
  );
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    authority: FIXTURE_ALICE_ID,
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    entrypoint: "increment",
    payload,
    metadata: { caller_note: "trusted" },
    creation_time_ms: 42,
    fee_payment: feePayment,
  });
  assert.deepEqual(result, {
    ok: true,
    submitted: false,
    dataspace: "universal",
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    tx_hash_hex: null,
    creation_time_ms: 42,
    transaction_ttl_ms: null,
    entrypoint_hash_hex: null,
    entrypoint: "increment",
    transaction_payload_b64: draft.transaction_payload_b64,
    signing_message_b64: draft.signing_message_b64,
    operation_receipt: responsePayload.operation_receipt,
  });
});

test("prepareContractCall validates schema arguments before sending or trusting a digest", async () => {
  let requests = 0;
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => { requests += 1; throw new Error("unexpected request"); },
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const argumentSchema = {
    fields: [{ name: "value", ty: { nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }] } }],
  };
  const draft = contractDraftForBindings({ authority: FIXTURE_ALICE_ID });
  const request = {
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    entrypoint: "increment",
    argumentSchema,
    feePayment: sponsorFeePayment(FIXTURE_BOB_ID, 42, 3),
    draftIntent: contractDraftIntentForDraft(draft, { payload: { value: 7 } }),
  };
  await assert.rejects(
    client.prepareContractCall({ ...request, payload: { value: 0.5 } }),
    /value.*int/iu,
  );
  await assert.rejects(
    client.prepareContractCall({ ...request, payload: { value: 7 } }),
    /payloadDigestHex must match the exact request payload/u,
  );
  assert.equal(requests, 0);
});

test("prepareContractCall rejects submitted and unmarked response state", async () => {
  const txHash = "3".repeat(64);
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment: authorityFeePayment(42),
    creationTimeMs: 42,
  });
  const responsePayload = {
    ok: true,
    submitted: true,
    dataspace: "universal",
    contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    tx_hash_hex: txHash,
    pipeline_status: {
      hash: txHash,
      status: { kind: "Rejected", block_height: 12 },
      scope: "local",
      resolved_from: "state",
    },
    creation_time_ms: 42,
    entrypoint: "increment",
    entrypoint_hash_hex: "5".repeat(64),
    operation_receipt: {
      operation_kind: "contract_call",
      status: "submitted",
      transport: "torii",
      dataspace: "universal",
      contract_alias: null,
      contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      code_hash_hex: "1".repeat(64),
      abi_hash_hex: "2".repeat(64),
      tx_hash_hex: txHash,
      entrypoint: "increment",
      entrypoint_hash_hex: "4".repeat(64),
      gas_limit: 42,
      gas_used: null,
      fee_payment: authorityFeePayment(42),
      payload_digest_hex: "5".repeat(64),
    },
  };
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const prepare = () => client.prepareContractCall({
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    entrypoint: "increment",
    feePayment: authorityFeePayment(42),
    draftIntent: contractDraftIntentForDraft(draft),
  });
  await assert.rejects(
    prepare,
    /contractCall draft must be successful and not submitted/,
  );
  for (const [record, key] of [
    [responsePayload, "tx_hash_hex"],
    [responsePayload, "entrypoint_hash_hex"],
    [responsePayload.operation_receipt, "tx_hash_hex"],
  ]) {
    const original = record[key];
    record[key] = "4".repeat(64);
    await assert.rejects(prepare, /canonical Iroha hash marker/u);
    record[key] = original;
  }
});

test("callContract response requires operation_receipt", async () => {
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment: authorityFeePayment(42),
    creationTimeMs: 42,
  });
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: {
        ok: true,
        submitted: true,
        dataspace: "universal",
        code_hash_hex: "1".repeat(64),
        abi_hash_hex: "2".repeat(64),
        creation_time_ms: 42,
        entrypoint: "increment",
      },
      headers: { "content-type": "application/json" },
    });
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });

  await assert.rejects(
    () =>
      client.prepareContractCall({
        authority: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        entrypoint: "increment",
        feePayment: authorityFeePayment(42),
        draftIntent: contractDraftIntentForDraft(draft),
      }),
    /contractCall response\.operation_receipt must be an object/,
  );
});

test("callContract rejects coercible, non-canonical, or unexpected response fields", async () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment: authorityFeePayment(42),
    creationTimeMs: 42,
  });
  const makePayload = () => ({
    ok: true,
    submitted: false,
    dataspace: "universal",
    contract_address: contractAddress,
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    tx_hash_hex: null,
    creation_time_ms: 42,
    transaction_ttl_ms: null,
    entrypoint: "increment",
    entrypoint_hash_hex: null,
    ...draft,
    operation_receipt: {
      operation_kind: "contract_call",
      status: "pending_signature",
      transport: "torii",
      dataspace: "universal",
      contract_address: contractAddress,
      code_hash_hex: "1".repeat(64),
      abi_hash_hex: "2".repeat(64),
      entrypoint: "increment",
      entrypoint_hash_hex: null,
      gas_limit: 42,
      payload_digest_hex: "5".repeat(64),
    },
  });
  const cases = [
    ["string boolean", (value) => { value.ok = "false"; }, /ok must be a boolean/],
    ["numeric boolean", (value) => { value.submitted = 0; }, /submitted must be a boolean/],
    [
      "numeric string timestamp",
      (value) => { value.creation_time_ms = "42"; },
      /creation_time_ms must be a non-negative JSON safe integer/,
    ],
    [
      "uppercase hash",
      (value) => { value.code_hash_hex = "A".repeat(64); },
      /code_hash_hex must be an exact lowercase 32-byte hex string/,
    ],
    [
      "noncanonical base64",
      (value) => { value.transaction_payload_b64 = "AQ"; },
      /transaction_payload_b64 must be exact standard-base64/,
    ],
    [
      "unexpected response field",
      (value) => { value.ignored = true; },
      /unsupported fields: ignored/,
    ],
    [
      "unexpected receipt field",
      (value) => { value.operation_receipt.ignored = true; },
      /operation_receipt contains unsupported fields: ignored/,
    ],
    [
      "numeric string receipt gas",
      (value) => { value.operation_receipt.gas_limit = "42"; },
      /gas_limit must be a positive JSON safe integer/,
    ],
  ];
  for (const [label, mutate, pattern] of cases) {
    const payload = makePayload();
    mutate(payload);
    const client = new ContractToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: payload,
          headers: { "content-type": "application/json" },
        }),
      localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
    });
    await assert.rejects(
      () =>
        client.prepareContractCall({
          authority: FIXTURE_ALICE_ID,
          contractAddress,
          entrypoint: "increment",
          feePayment: authorityFeePayment(42),
          draftIntent: contractDraftIntentForDraft(draft),
        }),
      pattern,
      label,
    );
  }
});

test("prepareContractCall rejects colluding contract substitutions and receipt tampering", async () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const payload = { value: 7, labels: ["a", "b"] };
  const feePayment = sponsorFeePayment(FIXTURE_BOB_ID, 42, 3);
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment,
    creationTimeMs: 42,
  });
  const draftIntent = contractDraftIntentForDraft(draft, { payload });
  const validResponse = {
    ok: true,
    submitted: false,
    dataspace: "universal",
    contract_address: contractAddress,
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    tx_hash_hex: null,
    creation_time_ms: 42,
    transaction_ttl_ms: null,
    entrypoint: "increment",
    entrypoint_hash_hex: null,
    ...draft,
    operation_receipt: {
      operation_kind: "contract_call",
      status: "pending_signature",
      transport: "torii",
      dataspace: "universal",
      contract_alias: null,
      contract_address: contractAddress,
      code_hash_hex: "1".repeat(64),
      abi_hash_hex: "2".repeat(64),
      tx_hash_hex: null,
      entrypoint: "increment",
      entrypoint_hash_hex: null,
      gas_limit: 42,
      gas_used: null,
      fee_payment: feePayment,
      payload_digest_hex: contractPayloadDigestHex(payload),
    },
  };
  const request = {
    authority: FIXTURE_ALICE_ID,
    contractAddress,
    entrypoint: "increment",
    payload,
    creationTimeMs: 42,
    feePayment,
    draftIntent,
  };
  const cases = [
    ...[1, 2].map((admissionIntent) => [
      `rehashed admission intent ${admissionIntent}`,
      (value) => {
        Object.assign(value, multisigDraftForBindings({
          authority: FIXTURE_ALICE_ID, feePayment, creationTimeMs: 42,
          retiredAdmissionTag: admissionIntent,
        }));
      },
      (error) => {
        assert.match(error.message, /one canonical transaction payload/);
        assert.ok(error.cause instanceof Error);
        return true;
      },
    ]),
    [
      "colluding retired admission",
      (value) => {
        const retired = multisigDraftForBindings({ authority: FIXTURE_ALICE_ID, feePayment, creationTimeMs: 42, retiredAdmissionTag: 1 });
        value.transaction_payload_b64 = retired.transaction_payload_b64;
        value.signing_message_b64 = retired.signing_message_b64;
      },
      /canonical transaction payload bound to the requested signer/,
    ],
    [
      "colluding resolved address",
      (value) => {
        value.contract_address = "colluding-substitution";
        value.operation_receipt.contract_address = "colluding-substitution";
      },
      /resolved address changed the caller-trusted draftIntent/,
    ],
    [
      "colluding code hash",
      (value) => {
        value.code_hash_hex = "a".repeat(64);
        value.operation_receipt.code_hash_hex = "a".repeat(64);
      },
      /code hash changed the caller-trusted draftIntent/,
    ],
    [
      "receipt ABI hash",
      (value) => { value.operation_receipt.abi_hash_hex = "a".repeat(64); },
      /receipt does not match the resolved contract binding/,
    ],
    [
      "receipt transport",
      (value) => { value.operation_receipt.transport = "relay"; },
      /does not match the exact pending draft context/,
    ],
    [
      "receipt dataspace",
      (value) => { value.operation_receipt.dataspace = "private"; },
      /does not match the exact pending draft context/,
    ],
    [
      "receipt gas use",
      (value) => { value.operation_receipt.gas_used = 1; },
      /does not match the exact pending draft context/,
    ],
    [
      "receipt alias",
      (value) => { value.operation_receipt.contract_alias = "call::universal"; },
      /not bound to the requested alias/,
    ],
    [
      "receipt gas limit",
      (value) => { value.operation_receipt.gas_limit = 41; },
      /gas_limit does not match its fee_payment/,
    ],
    [
      "receipt payload digest",
      (value) => { value.operation_receipt.payload_digest_hex = "b".repeat(64); },
      /payload digest changed the caller-trusted draftIntent/,
    ],
    [
      "colluding creation time",
      (value) => {
        const substitutedDraft = contractDraftForBindings({
          authority: FIXTURE_ALICE_ID,
          feePayment,
          creationTimeMs: 43,
        });
        value.creation_time_ms = 43;
        value.transaction_payload_b64 = substitutedDraft.transaction_payload_b64;
        value.signing_message_b64 = substitutedDraft.signing_message_b64;
      },
      /creation_time_ms is not bound to the request/,
    ],
  ];
  for (const [label, mutate, pattern] of cases) {
    const responsePayload = JSON.parse(JSON.stringify(validResponse));
    mutate(responsePayload);
    const client = new ContractToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: responsePayload,
        headers: { "content-type": "application/json" },
      }),
      localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
    });
    await assert.rejects(
      () => client.prepareContractCall(request),
      pattern,
      label,
    );
  }

  const aliasResponse = JSON.parse(JSON.stringify(validResponse));
  aliasResponse.dataspace = "private";
  aliasResponse.operation_receipt.dataspace = "private";
  aliasResponse.operation_receipt.contract_alias = "call::universal";
  const aliasClient = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      jsonData: aliasResponse,
      headers: { "content-type": "application/json" },
    }),
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const { contractAddress: _address, ...aliasRequest } = request;
  await assert.rejects(
    () => aliasClient.prepareContractCall({
      ...aliasRequest,
      contractAlias: "call::universal",
    }),
    /dataspace does not match the requested alias/,
  );
});

test("prepareContractCall validates caller-trusted payload intent before fetch", async () => {
  const payload = { value: 7 };
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment: authorityFeePayment(42),
    creationTimeMs: 42,
  });
  let fetchCalls = 0;
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run for mismatched caller intent");
    },
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  await assert.rejects(
    () => client.prepareContractCall({
      authority: FIXTURE_ALICE_ID,
      contractAddress:
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      entrypoint: "increment",
      payload,
      feePayment: authorityFeePayment(42),
      draftIntent: contractDraftIntentForDraft(draft, {
        payload: { value: 8 },
      }),
    }),
    /payloadDigestHex must match the exact request payload/,
  );
  assert.equal(fetchCalls, 0);
});

test("prepareContractCall rejects a zero explicit creation time before fetch", async () => {
  const draft = contractDraftForBindings({
    authority: FIXTURE_ALICE_ID,
    feePayment: authorityFeePayment(42),
    creationTimeMs: 42,
  });
  let fetchCalls = 0;
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run for an invalid creation time");
    },
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  await assert.rejects(
    () => client.prepareContractCall({
      authority: FIXTURE_ALICE_ID,
      contractAddress:
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      entrypoint: "increment",
      creationTimeMs: 0,
      feePayment: authorityFeePayment(42),
      draftIntent: contractDraftIntentForDraft(draft),
    }),
    /contractCall\.creationTimeMs must be a positive integer/,
  );
  assert.equal(fetchCalls, 0);
});

test("callContract rejects missing feePayment", async () => {
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.prepareContractCall({
        authority: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        entrypoint: "ping",
      }),
    /contractCall\.fee_payment must be an object/,
  );
});

test("callContract rejects a zero feePayment gas limit", async () => {
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.prepareContractCall({
        authority: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        entrypoint: "ping",
        feePayment: authorityFeePayment(0),
      }),
    /fee_payment\.value\.gas_limit must be a positive integer/,
  );
});

test("callContract rejects an implicit entrypoint", async () => {
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.prepareContractCall({
        authority: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        feePayment: authorityFeePayment(42),
      }),
    /contractCall\.entrypoint/,
  );
});

test("callContract rejects non-object options", async () => {
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.prepareContractCall(
        {
          authority: FIXTURE_ALICE_ID,
          contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          entrypoint: "ping",
        },
        "invalid",
      ),
    /prepareContractCall options must be an object/,
  );
});

test("callContract rejects unsupported option fields", async () => {
  const client = new ContractToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.prepareContractCall(
        {
          authority: FIXTURE_ALICE_ID,
          contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          entrypoint: "ping",
        },
        { signal: new AbortController().signal, retry: true },
      ),
    /prepareContractCall options contains unsupported fields: retry/,
  );
});

test("proposeMultisig posts the native Norito request DTO", async () => {
  let captured;
  const instruction = { Custom: { payload: { probe: true } } };
  const draft = multisigDraftForBindings({ creationTimeMs: 123456 });
  const responsePayload = {
    ...draft,
    ok: true,
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    proposal_id: "a".repeat(64),
    instructions_hash: "a".repeat(64),
    tx_hash_hex: null,
    executed_tx_hash_hex: null,
    creation_time_ms: 123456,
    fee_payment: authorityFeePayment(),
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const result = await client.proposeMultisig({
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    instructions: [instruction],
    feePayment: authorityFeePayment(),
    creationTimeMs: 123456,
    validation_fee_assessment: retailAssessmentFixture(),
    draftIntent: draftIntentForDraft(draft),
  });
  assert.equal(captured.url, `${BASE_URL}/v1/multisig/propose`);
  assert.equal(captured.init.headers["Content-Type"], "application/x-norito");
  const body = Buffer.from(captured.init.body);
  assert.equal(body.subarray(0, 4).toString("ascii"), "NRT0");
  assertFlattenedAliasSelector(body, "cbdc@banka", "MultisigProposeDtoV1");
  assertMultisigProposeInstructionWireId(
    body,
    "iroha.custom",
    "MultisigProposeDtoV1",
  );
  assert.deepEqual(result, responsePayload);

  assert.deepEqual(
    buildMultisigProposeRequest({
      multisigAccountAlias: "cbdc@banka",
      signerAccountId: FIXTURE_ALICE_ID,
      instructions: [instruction],
      feePayment: authorityFeePayment(),
      validation_fee_assessment: retailAssessmentFixture(),
    }),
    {
      multisig_account_alias: "cbdc@banka",
      signer_account_id: FIXTURE_ALICE_ID,
      instructions: [instruction],
      fee_payment: authorityFeePayment(),
      validation_fee_assessment: retailAssessmentFixture(),
    },
  );
});

test("proposeMultisig binds every unsigned payload to local caller intent", async () => {
  const trustedDraft = multisigDraftForBindings();
  const trustedIntent = draftIntentForDraft(trustedDraft);
  const request = {
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    instructions: [{ Custom: { payload: { probe: true } } }],
    feePayment: authorityFeePayment(),
  };
  const responseFor = (draft) => ({
    ...draft,
    ok: true,
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    proposal_id: "a".repeat(64),
    instructions_hash: "a".repeat(64),
    tx_hash_hex: null,
    executed_tx_hash_hex: null,
    creation_time_ms: 42,
    fee_payment: authorityFeePayment(),
  });
  const clientFor = (draft, networkId = VK_SIGNING_NETWORK_ID) =>
    new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: responseFor(draft),
        headers: { "content-type": "application/json" },
      }),
      localSigningContext: new LocalSigningContext(networkId, 753),
    });

  await assert.rejects(
    () => clientFor(trustedDraft).proposeMultisig(request),
    /requires a caller-trusted draftIntent/,
  );
  await assert.rejects(
    () => new SourceToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: responseFor(trustedDraft),
        headers: { "content-type": "application\/json" },
      }),
    }).proposeMultisig({ ...request, draftIntent: trustedIntent }),
    /requires ToriiClient options\.localSigningContext/,
  );
  const otherNetworkBytes = Buffer.alloc(32, 3);
  await assert.rejects(
    () => clientFor(
      trustedDraft,
      NetworkId.fromBytes(otherNetworkBytes),
    ).proposeMultisig({ ...request, draftIntent: trustedIntent }),
    /changed caller-trusted networkId/,
  );

  const alternateExecutable = Buffer.from(trustedIntent.executableB64, "base64");
  alternateExecutable[alternateExecutable.length - 1] ^= 1;
  const replacedExecutable = draftWithReplacedTransactionField(
    trustedDraft,
    3,
    alternateExecutable,
  );
  await assert.rejects(
    () => clientFor(replacedExecutable).proposeMultisig({
      ...request,
      draftIntent: trustedIntent,
    }),
    /changed caller-trusted executable/,
  );

  const alternateMetadata = Buffer.from(
    draftIntentForDraft(multisigDraftForBindings({
      metadata: { probe: true },
    })).metadataB64,
    "base64",
  );
  const replacedMetadata = draftWithReplacedTransactionField(
    trustedDraft,
    7,
    alternateMetadata,
  );
  await assert.rejects(
    () => clientFor(replacedMetadata).proposeMultisig({
      ...request,
      draftIntent: trustedIntent,
    }),
    /changed caller-trusted metadata/,
  );
});

test("native multisig contract-call DTO flattens selector fields", () => {
  const payload = { amount: 111 };
  const body = noritoEncodeMultisigContractCallProposeRequest({
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    contractAlias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload,
    feePayment: authorityFeePayment(10_000),
    creationTimeMs: 123456,
  }, 753);

  assertFlattenedAliasSelector(
    body,
    "cbdc@banka",
    "MultisigContractCallProposeDto",
  );
  assertContractCallPayloadJson(body, payload, "MultisigContractCallProposeDto");
});

test("native multisig contract-call DTO encodes concrete multisig IDs canonically", () => {
  const body = noritoEncodeMultisigContractCallProposeRequest({
    multisigAccountId: fixtureMultisigAccountId(),
    signerAccountId: FIXTURE_ALICE_ID,
    contractAlias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    feePayment: authorityFeePayment(10_000),
    creationTimeMs: 123456,
  }, 753);

  assertConcreteMultisigAccountUsesNativeLengths(
    body,
    "MultisigContractCallProposeDto",
  );
});

test("proposeMultisig rejects adversarial request shapes before fetch", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  const request = {
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    instructions: [{ Custom: { payload: { probe: true } } }],
    feePayment: authorityFeePayment(),
  };

  await assert.rejects(
    () => client.proposeMultisig({ ...request, multisigAccountId: FIXTURE_ALICE_ID }),
    /requires exactly one/,
  );
  await assert.rejects(
    () => client.proposeMultisig({ ...request, instructions: [] }),
    /non-empty array/,
  );
  await assert.rejects(
    () => client.proposeMultisig({ ...request, signatureB64: "not base64" }),
    /exact standard-base64/,
  );
  const canonicalSignature = canonicalSignatureBase64Fixture();
  for (const signatureB64 of [
    ` ${canonicalSignature} `,
    canonicalSignature.replace(/=+$/u, ""),
    noncanonicalStandardBase64PadBitAlias(canonicalSignature),
  ]) {
    await assert.rejects(
      () => client.proposeMultisig({ ...request, signatureB64 }),
      /exact standard-base64/,
    );
  }
  await assert.rejects(
    () => client.proposeMultisig({ ...request, creationTimeMs: -1 }),
    /non-negative integer/,
  );
  for (const [fieldName, value] of Object.entries({
    validation_fee_policy_version: 7,
    validation_fee_policy_hash: "ab".repeat(32),
    validation_fee_hijiri_fee_quote_hash: "cd".repeat(32),
    validation_fee_instruction_index: 1,
    validation_fee_transfer_entry_index: 2,
  })) {
    await assert.rejects(
      () => client.proposeMultisig({ ...request, [fieldName]: value }),
      /unsupported fee field/,
    );
    assert.throws(
      () => buildMultisigProposeRequest({ ...request, [fieldName]: value }),
      /unsupported fee field/,
    );
  }
  const invalidAssessments = [
    {}, {...retailAssessmentFixture(), policy_revision: 0},
    {...retailAssessmentFixture(), fee_minor: 1},
    {...retailAssessmentFixture(), expires_at_ms: 0},
    {...retailAssessmentFixture(), state_commitment: Array(32).fill(0)},
    {...retailAssessmentFixture(), exemption: true},
  ];
  for (const assessment of invalidAssessments) {
    await assert.rejects(()=>client.proposeMultisig({...request,validation_fee_assessment:assessment}),/assessment/);
    assert.throws(()=>buildMultisigProposeRequest({...request,validation_fee_assessment:assessment}),/assessment/);
  }
  await assert.rejects(
    () => client.proposeMultisig({ ...request, instructions: [Buffer.from("NRT0")] }),
    { message: "failed to fill whole buffer" },
  );
  await assert.rejects(
    () => client.proposeMultisig(request, { retry: true }),
    /unsupported fields: retry/,
  );
  assert.throws(
    () => buildMultisigProposeRequest({ ...request, instructions: [null] }),
    /multisigPropose\.instructions\[0\]/,
  );

});

test("proposeMultisig rejects malformed success responses", async () => {
  const bindingDraft = multisigDraftForBindings();
  const request = {
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    instructions: [{ Custom: { payload: { probe: true } } }],
    feePayment: authorityFeePayment(),
    draftIntent: draftIntentForDraft(bindingDraft),
  };

  const clientWithResponse = (jsonData) =>
    new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
      localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
    });
  const validDraft = {
    ...bindingDraft,
    ok: true,
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    creation_time_ms: 42,
    fee_payment: authorityFeePayment(),
  };

  await assert.rejects(
    () =>
      clientWithResponse({
        ok: false,
        resolved_multisig_account_id: FIXTURE_ALICE_ID,
      }).proposeMultisig(request),
    /ok/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        instructions_hash: "aa",
      }).proposeMultisig(request),
    /instructions_hash/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        signing_message_b64: "not base64",
      }).proposeMultisig(request),
    /signing_message_b64/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        signing_message_b64: "",
      }).proposeMultisig(request),
    /signing_message_b64/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        creation_time_ms: -1,
      }).proposeMultisig(request),
    /creation_time_ms/,
  );
  const { fee_payment: _omittedFeePayment, ...missingFeePayment } = validDraft;
  await assert.rejects(
    () => clientWithResponse(missingFeePayment).proposeMultisig(request),
    /fee_payment/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        fee_payment: sponsorFeePayment(FIXTURE_BOB_ID, null, 1),
      }).proposeMultisig(request),
    /changed the requested payer, sponsor revision, or gas bound/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        fee_payment: {
          payer: "authority",
          value: {
            charge_limits: [{
              kind: { kind: "nexus", value: null },
              asset_definition_id: "7EAD8EFYUx1aVKZPUU1fyKvr8dF1",
              max_amount: "1",
            }],
            gas_limit: null,
          },
        },
      }).proposeMultisig(request),
    /changed caller-trusted fee_payment/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        ...multisigDraftForBindings({ authority: FIXTURE_BOB_ID }),
      }).proposeMultisig(request),
    /transaction_payload_b64 must contain one canonical transaction payload bound to the requested signer/,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        ...validDraft,
        creation_time_ms: 43,
      }).proposeMultisig(request),
    /creation_time_ms does not match the exact transaction payload/,
  );
});

test("multisig response decoders reject non-exact resolved account ids", async () => {
  const paddedAccountId = `${FIXTURE_ALICE_ID} `;
  const clientWithResponse = (jsonData) =>
    new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
    });
  const selector = { multisigAccountAlias: "cbdc@banka" };
  const proposalId = "f".repeat(64);
  const pattern = /resolved_multisig_account_id must not contain surrounding whitespace/;

  await assert.rejects(
    () =>
      clientWithResponse({
        ok: true,
        resolved_multisig_account_id: paddedAccountId,
      }).proposeMultisig({
        ...selector,
        signerAccountId: FIXTURE_ALICE_ID,
        instructions: [{ Custom: { payload: { probe: true } } }],
        feePayment: authorityFeePayment(),
        signatureB64: "AQ==",
      }),
    pattern,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        resolved_multisig_account_id: paddedAccountId,
        spec: { quorum: 2 },
      }).getMultisigSpec(selector, canonicalReadOptions()),
    pattern,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        resolved_multisig_account_id: paddedAccountId,
        proposals: [],
      }).queryMultisigProposals(selector, canonicalReadOptions()),
    pattern,
  );
  await assert.rejects(
    () =>
      clientWithResponse({
        resolved_multisig_account_id: paddedAccountId,
        proposal_id: proposalId,
        instructions_hash: proposalId,
        proposal: { approvals: [] },
      }).resolveMultisigProposal(
        { ...selector, instructionsHash: proposalId },
        canonicalReadOptions(),
      ),
    pattern,
  );
});

test("proposeMultisigContractCall posts alias selector and normalizes response", async () => {
  let captured;
  const draft = multisigDraftForBindings({
    feePayment: authorityFeePayment(5),
    creationTimeMs: 123456,
  });
  const responsePayload = {
    ...draft,
    ok: true,
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    proposal_id: "a".repeat(64),
    instructions_hash: "a".repeat(64),
    creation_time_ms: 123456,
    fee_payment: authorityFeePayment(5),
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    localSigningContext: new LocalSigningContext(VK_SIGNING_NETWORK_ID, 753),
  });
  const result = await client.proposeMultisigContractCall({
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    contractAlias: "apps_review::universal",
    entrypoint: "execute",
    payload: { amount: "10" },
    feePayment: authorityFeePayment(5),
    draftIntent: draftIntentForDraft(draft),
  });
  assert.equal(captured.url, `${BASE_URL}/v1/contracts/call/multisig/propose`);
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    multisig_account_alias: "cbdc@banka",
    signer_account_id: FIXTURE_ALICE_ID,
    contract_alias: "apps_review::universal",
    entrypoint: "execute",
    payload: { amount: "10" },
    fee_payment: authorityFeePayment(5),
  });
  assert.deepEqual(result, {
    ...responsePayload,
    tx_hash_hex: null,
    executed_tx_hash_hex: null,
  });
});

test("contract-call propose client rejects an unapprovable target", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => { throw new Error("unexpected fetch"); },
  });
  const request = {
    multisigAccountAlias: "treasury@west.test",
    signerAccountId: FIXTURE_ALICE_ID,
    contractAlias: "apps_review::universal",
    entrypoint: "execute",
    payload: { probe: true },
    feePayment: authorityFeePayment(5),
  };
  await assert.rejects(
    () => client.proposeMultisigContractCall({ ...request, contractAlias: null }),
    /contract_alias/,
  );
  await assert.rejects(
    () => client.proposeMultisigContractCall({ ...request, payload: null }),
    /payload/,
  );
});

test("multisig contract call request builders reject retired sponsor aliases", () => {
  assert.throws(
    () => buildMultisigContractCallProposeRequest({
      multisigAccountAlias: "cbdc@hbl.sbp",
      signerAccountId: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      entrypoint: "execute",
      trigger: "probe",
      payload: { amount: "10" },
      feeSponsor: "sponsor@sbp",
      feePayment: authorityFeePayment(5),
    }),
    /feeSponsor is retired/,
  );
});

test("approveMultisigContractCall posts concrete selector and normalizes response", async () => {
  let captured;
  const responsePayload = {
    ok: true,
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    submitted: true,
    proposal_id: "b".repeat(64),
    instructions_hash: "b".repeat(64),
    tx_hash_hex: "d".repeat(64),
    executed_tx_hash_hex: "d".repeat(64),
    fee_payment: authorityFeePayment(),
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.approveMultisigContractCall({
    multisigAccountId: FIXTURE_ALICE_ID,
    signerAccountId: FIXTURE_BOB_ID,
    proposalId: "b".repeat(64),
    signatureB64: "AQ==",
    contract_alias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    feePayment: authorityFeePayment(),
  });
  assert.equal(captured.url, `${BASE_URL}/v1/contracts/call/multisig/approve`);
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body, {
    multisig_account_id: FIXTURE_ALICE_ID,
    signer_account_id: FIXTURE_BOB_ID,
    proposal_id: "b".repeat(64),
    signature_b64: "AQ==",
    contract_alias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    fee_payment: authorityFeePayment(),
  });
  assert.deepEqual(result, {
    ...responsePayload,
    creation_time_ms: null,
    transaction_payload_b64: null,
    signing_message_b64: null,
  });
});

test("approveMultisigContractCall rejects unmarked transaction hashes", async () => {
  for (const field of ["tx_hash_hex", "executed_tx_hash_hex"]) {
    const responsePayload = {
      ok: true,
      resolved_multisig_account_id: FIXTURE_ALICE_ID,
      submitted: true,
      proposal_id: "b".repeat(64),
      instructions_hash: "b".repeat(64),
      tx_hash_hex: "d".repeat(64),
      executed_tx_hash_hex: "d".repeat(64),
      fee_payment: authorityFeePayment(),
      [field]: "c".repeat(64),
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: responsePayload,
        headers: { "content-type": "application/json" },
      }),
    });
    await assert.rejects(
      () => client.approveMultisigContractCall({
        multisigAccountId: FIXTURE_ALICE_ID,
        signerAccountId: FIXTURE_BOB_ID,
        proposalId: "b".repeat(64),
        signatureB64: "AQ==",
        contract_alias: "apps_mint_request::sbp",
        entrypoint: "create_mint_request",
        payload: { amount: 111 },
        feePayment: authorityFeePayment(),
      }),
      /canonical Iroha hash marker/u,
    );
  }
});

test("getMinistryAgendaProposal rejects an unmarked transaction hash", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({
      status: 200,
      jsonData: {
        found: true,
        record: {
          proposal: {},
          authority: FIXTURE_ALICE_ID,
          submitted_tx_hash_hex: "a".repeat(64),
          submitted_height: 1,
        },
      },
      headers: { "content-type": "application/json" },
    }),
  });
  await assert.rejects(
    () => client.getMinistryAgendaProposal("proposal-1", canonicalReadOptions()),
    /canonical Iroha hash marker/u,
  );
});

test("getMultisigSpec posts selector and returns raw spec payload", async () => {
  let captured;
  const responsePayload = {
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    spec: {
      signatories: [FIXTURE_ALICE_ID, FIXTURE_BOB_ID],
      quorum: 2,
      transaction_ttl_ms: 60000,
    },
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getMultisigSpec(
    {
      multisig_account_alias: "cbdc@bankb",
    },
    canonicalReadOptions(),
  );
  assert.equal(captured.url, `${BASE_URL}/v1/multisig/spec`);
  assert.deepEqual(JSON.parse(captured.init.body), {
    multisig_account_alias: "cbdc@bankb",
  });
  assert.deepEqual(result, responsePayload);
});

test("ToriiClient source and dist use only first-release multisig proposal routes", () => {
  for (const relativePath of ["../src/toriiClient.js", "../dist/toriiClient.js"]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(
      source,
      /["']\/v1\/multisig\/proposals\/(?:list|get|search|lookup)["']/,
      `${relativePath} must not retain retired multisig proposal paths`,
    );
    assert.doesNotMatch(
      source,
      /\b(?:listMultisigProposals|getMultisigProposal)\b/,
      `${relativePath} must not retain retired multisig proposal methods`,
    );
    assert.match(source, /["']\/v1\/multisig\/proposals\/query["']/);
    assert.match(source, /["']\/v1\/multisig\/proposals\/resolve["']/);
    assert.match(source, /\bqueryMultisigProposals\b/);
    assert.match(source, /\bresolveMultisigProposal\b/);
  }
});

test("TypeScript declarations expose only first-release multisig proposal names", () => {
  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  assert.doesNotMatch(
    declarations,
    /\b(?:listMultisigProposals|getMultisigProposal|MultisigProposalsList(?:Request|Response)|MultisigProposalGet(?:Request|Response))\b/,
  );
  for (const name of [
    "queryMultisigProposals",
    "resolveMultisigProposal",
    "MultisigProposalsQueryRequest",
    "MultisigProposalsQueryResponse",
    "MultisigProposalsResolveRequest",
    "MultisigProposalResolveResponse",
  ]) {
    assert.match(declarations, new RegExp(`\\b${name}\\b`));
  }
});

test("queryMultisigProposals decodes proposal entries", async () => {
  let captured;
  const responsePayload = {
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    proposals: [
      {
        proposal_id: "d".repeat(64),
        instructions_hash: "d".repeat(64),
        operation_type: "ASSET_TRANSFER",
        intent: {
          amount: "1",
          asset_id: "xor#sora",
        },
        proposal: {
          approvals: [FIXTURE_ALICE_ID],
          proposed_at_ms: 42,
        },
        status: "COLLECTING_SIGNATURES",
        terminal_at_ms: null,
      },
    ],
    next_cursor: "page-2",
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return createResponse({
        status: 200,
        jsonData: responsePayload,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const result = await client.queryMultisigProposals(
    {
      multisigAccountAlias: "cbdc@banka",
      status: ["collecting_signatures"],
      cursor: "page-1",
      limit: 25,
    },
    canonicalReadOptions(),
  );
  assert.equal(captured.url, `${BASE_URL}/v1/multisig/proposals/query`);
  assert.notEqual(captured.url, `${BASE_URL}/v1/multisig/proposals/list`);
  assert.deepEqual(JSON.parse(captured.init.body), {
    multisig_account_alias: "cbdc@banka",
    status: ["COLLECTING_SIGNATURES"],
    cursor: "page-1",
    limit: 25,
  });
  assert.deepEqual(result, responsePayload);
});

test("resolveMultisigProposal resolves by instructions hash", async () => {
  let captured;
  const responsePayload = {
    resolved_multisig_account_id: FIXTURE_ALICE_ID,
    proposal_id: "e".repeat(64),
    instructions_hash: "e".repeat(64),
    operation_type: "ASSET_TRANSFER",
    intent: null,
    proposal: {
      approvals: [FIXTURE_ALICE_ID, FIXTURE_BOB_ID],
      proposed_at_ms: 43,
    },
    status: "CANCELED",
    terminal_at_ms: 44,
  };
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: responsePayload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.resolveMultisigProposal(
    {
      multisigAccountAlias: "cbdc@banka",
      instructionsHash: "e".repeat(64),
    },
    canonicalReadOptions(),
  );
  assert.equal(captured.url, `${BASE_URL}/v1/multisig/proposals/resolve`);
  assert.notEqual(captured.url, `${BASE_URL}/v1/multisig/proposals/get`);
  assert.deepEqual(JSON.parse(captured.init.body), {
    multisig_account_alias: "cbdc@banka",
    instructions_hash: "e".repeat(64),
  });
  assert.deepEqual(result, responsePayload);
});

test("queryMultisigProposals rejects unsupported request and response statuses", async () => {
  const noFetchClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      noFetchClient.queryMultisigProposals(
        {
          multisigAccountAlias: "cbdc@banka",
          status: ["READY_TO_SUBMIT"],
        },
        canonicalReadOptions(),
      ),
    /must be one of COLLECTING_SIGNATURES, FINALIZED, CANCELED, EXPIRED/,
  );
  await assert.rejects(
    () =>
      noFetchClient.queryMultisigProposals(
        {
          multisigAccountId: FIXTURE_ALICE_ID,
          multisigAccountAlias: "cbdc@banka",
        },
        canonicalReadOptions(),
      ),
    /requires exactly one/,
  );
  await assert.rejects(
    () =>
      noFetchClient.resolveMultisigProposal(
        {
          multisigAccountId: FIXTURE_ALICE_ID,
          proposalId: "f".repeat(64),
          instructionsHash: "f".repeat(64),
        },
        canonicalReadOptions(),
      ),
    /requires exactly one/,
  );

  const invalidResponseClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createResponse({
        status: 200,
        jsonData: {
          resolved_multisig_account_id: FIXTURE_ALICE_ID,
          proposals: [
            {
              proposal_id: "f".repeat(64),
              instructions_hash: "f".repeat(64),
              operation_type: "ASSET_TRANSFER",
              intent: null,
              proposal: { approvals: [], proposed_at_ms: 45 },
              status: "READY_TO_SUBMIT",
              terminal_at_ms: null,
            },
          ],
        },
        headers: { "content-type": "application/json" },
      }),
  });
  await assert.rejects(
    () =>
      invalidResponseClient.queryMultisigProposals(
        {
          multisigAccountAlias: "cbdc@banka",
        },
        canonicalReadOptions(),
      ),
    /multisig proposals query response\.proposals\[0\]\.status must be one of/,
  );
});

test("getMultisigSpec rejects selectors that set both account id and alias", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () =>
      client.getMultisigSpec(
        {
          multisigAccountId: FIXTURE_ALICE_ID,
          multisigAccountAlias: "cbdc@banka",
        },
        canonicalReadOptions(),
      ),
    /requires exactly one of multisig_account_id or multisig_account_alias/,
  );
});

test("getMultisigSpec accepts domain-scoped aliases and rejects unsupported alias shapes", async () => {
  let captured;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return createResponse({
        status: 200,
        jsonData: {
          resolved_multisig_account_id: FIXTURE_ALICE_ID,
          spec: { quorum: 2, transaction_ttl_ms: 60000 },
        },
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.getMultisigSpec(
    {
      multisigAccountAlias: "cbdc@banka.universal",
    },
    canonicalReadOptions(),
  );
  assert.deepEqual(JSON.parse(captured.init.body), {
    multisig_account_alias: "cbdc@banka.universal",
  });

  await assert.rejects(
    () =>
      client.getMultisigSpec(
        {
          multisigAccountAlias: "cbdc@banka.universal.extra",
        },
        canonicalReadOptions(),
      ),
    /must use name@dataspace or name@domain.dataspace form/,
  );
});

test("IVM contract simulation returns the bounded typed result", async () => {
  const calls = [];
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return createStreamedJsonResponse({
        status: 200,
        jsonData: {
          ok: true,
          dataspace: "universal",
          contract_address: "irohac1routerfixture",
          code_hash_hex: "11".repeat(32),
          abi_hash_hex: "22".repeat(32),
          entrypoint: "route_swap",
          normalized_payload: { amount: 7 },
          gas_limit: 5000,
          gas_used: 800,
          queued_instructions: [],
          result: null,
          error: null,
          fault: null,
          vm_diagnostic: null,
        },
        headers: { "content-type": "application/json" },
      });
    },
  });
  const simulation = await client.simulateContractCall({
    authority: SAMPLE_ACCOUNT_ID,
    contractAlias: "dlmm_router::dlmm.universal",
    entrypoint: "route_swap",
    payload: { amount: 7 },
    gasLimit: 5000,
  });
  assert.equal(simulation.ok, true);
  assert.deepEqual(simulation.normalized_payload, { amount: 7 });
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).pathname, "/v1/contracts/call/simulate");
});

test("IVM simulation response enforces its cap before reading and forwards signals", async () => {
  const controller = new AbortController();
  let bodyReads = 0;
  let capturedSignal;
  const response = {
    status: 200,
    headers: new Headers({
      "content-type": "application/json",
      "content-length": "1000000000",
    }),
    get body() {
      bodyReads += 1;
      throw new Error("oversized body must not be read");
    },
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (_url, init) => {
      capturedSignal = init.signal;
      return response;
    },
  });
  await assert.rejects(
    () => client.simulateContractCall({
      authority: SAMPLE_ACCOUNT_ID,
      contractAlias: "dlmm_router::dlmm.universal",
      gasLimit: 5000,
    }, { signal: controller.signal }),
    /exceeds the .*response limit/,
  );
  assert.equal(bodyReads, 0);
  assertRequestSignal(capturedSignal, controller.signal, "simulation signal");
});

test("IVM simulation bounded responses reject invalid UTF-8 and malformed JSON", async () => {
  const request = {
    authority: SAMPLE_ACCOUNT_ID,
    contractAlias: "dlmm_router::dlmm.universal",
    gasLimit: 5000,
  };
  for (const [body, expected] of [
    [Uint8Array.of(0xc3, 0x28), /must be valid UTF-8/],
    [new TextEncoder().encode("{"), /must contain valid JSON/],
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => new Response(body, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    });
    await assert.rejects(() => client.simulateContractCall(request), expected);
  }
});

test("simulateContractCall preserves typed fault origin and rejects malformed fault shapes", async () => {
  const fault = {kind: {kind: "Numeric", value: {kind: "DivisionByZero", value: null}}, site: {code_hash: "33".repeat(32), selector: {kind: "Entrypoint", value: 7}, position: {kind: "Execute", value: {pc_offset: 12}}}};
  const response = {ok: false, dataspace: "universal", contract_address: null, code_hash_hex: "11".repeat(32), abi_hash_hex: "22".repeat(32), entrypoint: "call_child", normalized_payload: null, gas_limit: 5000, gas_used: 80, queued_instructions: [], result: null, error: "nested arithmetic failure", vm_diagnostic: null, fault};
  const invoke = (jsonData) => new ToriiClient(BASE_URL, {fetchImpl: async () => createStreamedJsonResponse({status: 200, jsonData, headers: {"content-type": "application/json"}})}).simulateContractCall({authority: SAMPLE_ACCOUNT_ID, contractAlias: "dlmm_router::dlmm.universal", gasLimit: 5000});
  assert.deepEqual((await invoke(response)).fault, fault);
  for (const alter of [
    (value) => { delete value.fault; },
    (value) => { value.fault.kind.kind = "UnknownFault"; },
    (value) => { value.fault.kind.value.kind = "WrongType"; },
    (value) => { value.fault.site.selector.value = 0x100000000; },
    (value) => { value.fault.site.position.value.pc_offset = -1; },
    (value) => { value.fault.site.position.kind = "ReturnValidation"; },
    (value) => { value.fault.site.host_address = 123; },
    (value) => { value.ok = true; value.error = null; },
  ]) {
    const malformed = structuredClone(response);
    alter(malformed);
    await assert.rejects(() => invoke(malformed), /fault|u32/);
  }
});

test("simulateContractCall rejects fail-open ok coercion and inconsistent errors", async () => {
  const baseResponse = {
    dataspace: "universal",
    contract_address: "irohac1routerfixture",
    code_hash_hex: "11".repeat(32),
    abi_hash_hex: "22".repeat(32),
    entrypoint: "route_swap",
    normalized_payload: null,
    gas_limit: 5000,
    gas_used: 0,
    queued_instructions: [],
    result: null,
    fault: null,
    vm_diagnostic: null,
  };
  const request = {
    authority: SAMPLE_ACCOUNT_ID,
    contractAlias: "dlmm_router::dlmm.universal",
    gasLimit: 5000,
  };
  async function rejectsResponse(jsonData, expected) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createStreamedJsonResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(() => client.simulateContractCall(request), expected);
  }

  await rejectsResponse(
    { ...baseResponse, ok: "false", error: "VM failed" },
    /response\.ok must be a boolean/,
  );
  await rejectsResponse(
    { ...baseResponse, ok: 1, error: null },
    /response\.ok must be a boolean/,
  );
  await rejectsResponse(
    { ...baseResponse, ok: true, error: "attacker diagnostic" },
    /successful .* must not contain an error/,
  );
  await rejectsResponse(
    { ...baseResponse, ok: false, error: null },
    /failed .* must contain a non-empty error/,
  );
});

test("getContractManifest returns normalized payload", async () => {
  const signer = `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`;
  const signature = `ed25519:${"22".repeat(64)}`;
  const signerCanonical = signer.split(":")[1];
  const signatureCanonical = signature.split(":")[1].toUpperCase();
  const fetchImpl = async () =>
    createStreamedJsonResponse({
      status: 200,
      jsonData: withArtifactResponseIdentity({
        manifest: { events: [], enum_types: [], permissions: [],
          seiyaku_name: "Ledger",
          code_hash:
            "hash:1111111111111111111111111111111111111111111111111111111111111111#4667",
          abi_hash: null,
          compiler_fingerprint: null,
          features_bitmap: null,
          access_set_hints: null,
          entrypoints: null,
          states: null,
          error_types: null,
          kotoba: [
            {
              msg_id: "contract.title",
              translations: [{ lang: "en", text: "Ledger Contract" }],
            },
          ],
          provenance: {
            signer: signerCanonical,
            signature: signatureCanonical,
          },
        },
        code_hash: "11".repeat(32),
        abi_hash: null,
      }, "11".repeat(32)),
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const manifest = await client.getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, canonicalReadOptions());
  assert.ok(manifest);
  assert.equal(manifest?.manifest.seiyaku_name, "Ledger");
  assert.equal(manifest?.manifest.code_hash, "11".repeat(32));
  assert.equal(manifest?.manifest.abi_hash ?? null, null);
  assert.deepEqual(manifest?.manifest.kotoba, [
    {
      msg_id: "contract.title",
      translations: [{ lang: "en", text: "Ledger Contract" }],
    },
  ]);
  assert.deepEqual(manifest?.manifest.provenance, {
    signer: signerCanonical,
    signature: signatureCanonical,
  });
  assert.equal(manifest?.code_hash, "11".repeat(32));
  assert.equal(manifest?.abi_hash, null);
});

test("getContractManifest rejects noncanonical or inconsistent hash projections", async () => {
  const canonical =
    "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2";
  const makeClient = (payload) =>
    new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: withArtifactResponseIdentity(payload, "bb".repeat(32)),
          headers: { "content-type": "application/json" },
        }),
    });

  await assert.rejects(
    () =>
      makeClient({
        manifest: { events: [], enum_types: [], permissions: [], code_hash: canonical.toLowerCase(), abi_hash: null },
        code_hash: "bb".repeat(32),
        abi_hash: null,
      }).getContractManifest({ dataspaceId: "0", codeHash: "bb".repeat(32) }, canonicalReadOptions()),
    /canonical uppercase Norito Hash literal/u,
  );
  await assert.rejects(
    () =>
      makeClient({
        manifest: { events: [], enum_types: [], permissions: [], code_hash: canonical, abi_hash: null },
        code_hash: "dd".repeat(32),
        abi_hash: null,
      }).getContractManifest({ dataspaceId: "0", codeHash: "bb".repeat(32) }, canonicalReadOptions()),
    /does not match manifest.code_hash/u,
  );
  await assert.rejects(
    () =>
      makeClient({
        manifest: { events: [], enum_types: [], permissions: [], code_hash: canonical, abi_hash: null },
        code_hash: "bb".repeat(32),
        abi_hash: null,
        code_bytes: null,
      }).getContractManifest({ dataspaceId: "0", codeHash: "bb".repeat(32) }, canonicalReadOptions()),
    /code_bytes must be a base64 string/u,
  );
  await assert.rejects(
    () =>
      makeClient({
        manifest: { events: [], enum_types: [], permissions: [],
          code_hash:
            "hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#0E5B",
          abi_hash: null,
        },
        code_hash: "aa".repeat(32),
        abi_hash: null,
      }).getContractManifest({ dataspaceId: "0", codeHash: "bb".repeat(32) }, canonicalReadOptions()),
    /must set the Iroha Hash marker bit/u,
  );
});

test("getContractManifest rejects retired trigger sources, aliases, unknown fields, and unsupported feature bits", async () => {
  const canonicalCodeHash =
    "hash:1111111111111111111111111111111111111111111111111111111111111111#4667";
  const signer = `ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`;
  const base = {
    manifest: {
      seiyaku_name: "Ledger",
      code_hash: canonicalCodeHash,
      abi_hash: null,
      compiler_fingerprint: null,
      features_bitmap: 0,
      access_set_hints: {
        read_keys: [],
        write_keys: [],
        dynamic_reads: [
          {
            base_key: "state:Balances",
            key_type: "AccountId",
            bound_kind: "take",
            max_keys: 1,
          },
        ],
        dynamic_writes: [],
      },
      events: [],
      enum_types: [],
      permissions: [{ name: "CanMutate", scope: { kind: "Instance", value: null } }],
      entrypoints: [
        {
          name: "mutate",
          kind: { kind: "Kotoage", value: null },
          params: [
            { name: "request", type_name: "struct Fixture::Transfer" },
            { name: "tags", type_name: "List<Name, 4>" },
          ],
          argument_schema: {
            fields: [
              {
                name: "request",
                ty: {
                  nodes: [
                    {
                      kind: "Struct",
                      value: { name: "Fixture::Transfer", fields: ["amount"] },
                    },
                    {
                      kind: "Leaf",
                      value: { kind: "Quantity", value: null },
                    },
                  ],
                },
              },
              {
                name: "tags",
                ty: {
                  nodes: [
                    { kind: "List", value: { capacity: 4 } },
                    { kind: "Leaf", value: { kind: "Name", value: null } },
                  ],
                },
              },
            ],
          },
          return_type: "quantity",
          return_schema: {
            nodes: [
              { kind: "Leaf", value: { kind: "Quantity", value: null } },
            ],
          },
          authorization: { kind: "Permission", value: "CanMutate" },
          read_keys: [],
          write_keys: [],
          access_hints_complete: true,
          access_hints_skipped: [],
          triggers: [
            {
              id: "settle",
              repeats: { Indefinitely: null },
              filter: "AA==",
              authority: null,
              metadata: { round: 7 },
              callback: { namespace: null, entrypoint: "mutate" },
            },
          ],
        },
      ],
      states: [
        { name: "Balances", type_name: "StateMap<AccountId, quantity>" },
      ],
      error_types: [{ identity: "LedgerError", variants: [{ name: "Denied", code: 1 }] }],
      kotoba: [
        {
          msg_id: "transfer.denied",
          translations: [{ lang: "en", text: "Denied" }],
        },
      ],
      provenance: {
        signer,
        signature: "22".repeat(64),
      },
    },
    code_hash: "11".repeat(32),
    abi_hash: null,
  };
  const cases = [
    ["unknown top-level field", (payload) => { payload.extra = true; }],
    ["camelCase manifest alias", (payload) => {
      payload.manifest.seiyakuName = payload.manifest.seiyaku_name;
      delete payload.manifest.seiyaku_name;
    }],
    ["unsupported feature bit", (payload) => { payload.manifest.features_bitmap = 4; }],
    ["camelCase access-hint alias", (payload) => {
      payload.manifest.access_set_hints.readKeys = [];
      delete payload.manifest.access_set_hints.read_keys;
    }],
    ["camelCase dynamic-hint alias", (payload) => {
      const hint = payload.manifest.access_set_hints.dynamic_reads[0];
      hint.maxKeys = hint.max_keys;
      delete hint.max_keys;
    }],
    ["zero dynamic-hint bound", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].max_keys = 0;
    }],
    ["wildcard dynamic-hint base", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].base_key = "state:*";
    }],
    ["suffixed dynamic-hint base", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].base_key =
        "state:Balances/suffix";
    }],
    ["non-state dynamic-hint base", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].base_key = "account:alice";
    }],
    ["unsupported dynamic-hint key scalar", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].key_type = "Json";
    }],
    ["unsupported dynamic-hint bound kind", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].bound_kind = "prefix";
    }],
    ["dynamic-hint bound above V1 maximum", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].max_keys = 65;
    }],
    ["duplicate dynamic-read hint", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads.push({
        ...payload.manifest.access_set_hints.dynamic_reads[0],
      });
    }],
    ["duplicate dynamic-write hint", (payload) => {
      const hint = {
        ...payload.manifest.access_set_hints.dynamic_reads[0],
      };
      payload.manifest.access_set_hints.dynamic_writes = [hint, { ...hint }];
    }],
    ["unknown dynamic-read StateMap", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].base_key =
        "state:Missing";
    }],
    ["unknown dynamic-write StateMap", (payload) => {
      payload.manifest.access_set_hints.dynamic_writes = [{
        ...payload.manifest.access_set_hints.dynamic_reads[0],
        base_key: "state:Missing",
      }];
    }],
    ["scalar dynamic-read target", (payload) => {
      payload.manifest.states[0].type_name = "quantity";
    }],
    ["scalar dynamic-write target", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads = [];
      payload.manifest.access_set_hints.dynamic_writes = [{
        base_key: "state:Balances",
        key_type: "AccountId",
        bound_kind: "take",
        max_keys: 1,
      }];
      payload.manifest.states[0].type_name = "quantity";
    }],
    ["mismatched dynamic-read key scalar", (payload) => {
      payload.manifest.access_set_hints.dynamic_reads[0].key_type = "Name";
    }],
    ["mismatched dynamic-write key scalar", (payload) => {
      payload.manifest.access_set_hints.dynamic_writes = [{
        base_key: "state:Balances",
        key_type: "Name",
        bound_kind: "page",
        max_keys: 1,
      }];
    }],
    ["unknown entrypoint field", (payload) => {
      payload.manifest.entrypoints[0].legacy = true;
    }],
    ["unknown entrypoint-kind field", (payload) => {
      payload.manifest.entrypoints[0].kind.legacy = true;
    }],
    ["camelCase parameter alias", (payload) => {
      payload.manifest.entrypoints[0].params[0].typeName = "struct Fixture::Transfer";
    }],
    ["unknown argument-schema field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.legacy = true;
    }],
    ["unknown argument field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[0].legacy = true;
    }],
    ["unknown value-type field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[0].ty.legacy = true;
    }],
    ["unknown type-node field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[0].ty.nodes[0].legacy = true;
    }],
    ["unknown struct-node field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[0]
        .ty.nodes[0].value.legacy = true;
    }],
    ["unknown leaf-kind field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[0]
        .ty.nodes[1].value.legacy = true;
    }],
    ["unknown list-node field", (payload) => {
      payload.manifest.entrypoints[0].argument_schema.fields[1]
        .ty.nodes[0].value.legacy = true;
    }],
    ["unknown trigger field", (payload) => {
      payload.manifest.entrypoints[0].triggers[0].legacy = true;
    }],
    ["unknown repeat variant", (payload) => {
      payload.manifest.entrypoints[0].triggers[0].repeats.Legacy = null;
    }],
    ["retired trigger id", (payload) => {
      payload.manifest.entrypoints[0].triggers[0].id = "Amount";
    }],
    ["retired callback namespace", (payload) => {
      payload.manifest.entrypoints[0].triggers[0].callback.namespace = "Amount";
    }],
    ["camelCase callback alias", (payload) => {
      payload.manifest.entrypoints[0].triggers[0].callback.entryPoint = "mutate";
    }],
    ["unknown provenance field", (payload) => {
      payload.manifest.provenance.algorithm = "ed25519";
    }],
    ["unknown state field", (payload) => {
      payload.manifest.states = [
        { name: "Balances", type_name: "quantity", legacy: true },
      ];
    }],
    ["camelCase error-code alias", (payload) => {
      payload.manifest.error_types[0].errorCode = 1;
    }],
    ["camelCase kotoba alias", (payload) => {
      payload.manifest.kotoba[0].msgId = "transfer.denied";
    }],
    ["unknown translation field", (payload) => {
      payload.manifest.kotoba[0].translations[0].language = "en";
    }],
  ];

  for (const [label, mutate] of cases) {
    const payload = JSON.parse(JSON.stringify(base));
    mutate(payload);
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createStreamedJsonResponse({
          status: 200,
          jsonData: withArtifactResponseIdentity(payload, "11".repeat(32)),
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, canonicalReadOptions()),
      /must contain exactly|unsupported fields|unsupported Kotodama V1 feature bits|positive integer|state declaration identifier|StateMap key scalar|exactly take or page|at most 64|duplicate dynamic access hint|declared top-level StateMap|does not match declared StateMap|canonical Kotodama V1 identifier/u,
      label,
    );
  }

  const lowercaseAmount = JSON.parse(JSON.stringify(base));
  const lowercaseTrigger = lowercaseAmount.manifest.entrypoints[0].triggers[0];
  lowercaseTrigger.id = "amount";
  lowercaseTrigger.callback.namespace = "RemoteLedger";
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () =>
      createStreamedJsonResponse({
        status: 200,
        jsonData: withArtifactResponseIdentity(lowercaseAmount, "11".repeat(32)),
        headers: { "content-type": "application/json" },
      }),
  });
  const accepted = await client.getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, canonicalReadOptions());
  const parsedTrigger = accepted?.manifest.entrypoints[0].triggers[0];
  assert.equal(parsedTrigger?.id, "amount");
  assert.equal(parsedTrigger?.callback.namespace, "RemoteLedger");
});

test("getContractManifest returns null on 404", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => createResponse({ status: 404 }),
  });
  const result = await client.getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, canonicalReadOptions());
  assert.equal(result, null);
});

test("contract code lookups reject hashes without the Iroha marker before fetch", async () => {
  let called = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      called = true;
      return createResponse({ status: 404 });
    },
  });

  await assert.rejects(
    () => client.getContractManifest({ dataspaceId: "0", codeHash: "aa".repeat(32) }, canonicalReadOptions()),
    /must set the Iroha Hash marker bit/u,
  );
  await assert.rejects(
    () =>
      client.getContractCodeBytes({ dataspaceId: "0", codeHash: "22".repeat(32) }, canonicalReadOptions()),
    /must set the Iroha Hash marker bit/u,
  );
  assert.equal(called, false);
});

test("getContractCodeBytes returns a bounded record and forwards AbortSignal", async () => {
  const controller = new AbortController();
  let capturedSignal;
  const fetchImpl = async (_url, init) => {
    capturedSignal = init.signal;
    return new Response(JSON.stringify(ARTIFACT_READ_RESPONSE), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getContractCodeBytes(
    { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
    canonicalReadOptions({ signal: controller.signal }),
  );
  assert.deepEqual(result, ARTIFACT_READ_RESPONSE);
  assertRequestSignal(capturedSignal, controller.signal);
});

test("getContractCodeBytes validates options before fetch", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    },
  });
  await assert.rejects(
    () =>
      client.getContractCodeBytes(
        { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
        canonicalReadOptions({ limit: 1 }),
      ),
    /getContractCodeBytes options contains unsupported fields: limit/,
  );
  await assert.rejects(
    () =>
      client.getContractCodeBytes(
        { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
        canonicalReadOptions({ signal: {} }),
      ),
    /signal.*AbortSignal/i,
  );
  assert.equal(fetchCalls, 0);
});

test("bounded code-byte responses cancel on early rejection and 404", async () => {
  const cases = [
    {
      name: "wrong content type",
      status: 200,
      headers: { "content-type": "text/plain" },
      error: /must use (?:the )?application\/json/,
    },
    {
      name: "oversized Content-Length",
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(CONTRACT_CODE_BYTES_JSON_MAX_BYTES + 1),
      },
      error: /response limit/,
    },
    {
      name: "missing byte stream",
      status: 200,
      headers: { "content-type": "application/json" },
      error: /requires a byte-stream response body/,
    },
    {
      name: "not found",
      status: 404,
      headers: { "content-type": "application/json" },
      expected: null,
    },
  ];
  for (const entry of cases) {
    let cancelCalls = 0;
    const body = {
      cancel() {
        cancelCalls += 1;
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({
        status: entry.status,
        headers: new Headers(entry.headers),
        body,
      }),
    });
    const operation = client.getContractCodeBytes(
      { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
      canonicalReadOptions(),
    );
    if (entry.error) {
      await assert.rejects(operation, entry.error, entry.name);
    } else {
      assert.equal(await operation, entry.expected, entry.name);
    }
    assert.equal(cancelCalls, 1, `${entry.name} cancellation`);
  }
});

test("bounded JSON responses require one exact application/json media type", async () => {
  for (const contentType of [
    "application/json",
    "APPLICATION/JSON",
    " application/json ; charset=utf-8 ",
    'application/json; charset="utf-8"; profile="a,b"',
    'application/json; title="caf\u00e9"',
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        new Response(JSON.stringify(ARTIFACT_READ_RESPONSE), {
          status: 200,
          headers: { "content-type": contentType },
        }),
    });
    assert.deepEqual(
      await client.getContractCodeBytes(
        { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
        canonicalReadOptions(),
      ),
      ARTIFACT_READ_RESPONSE,
      contentType,
    );
  }

  for (const contentType of [
    "text/application/json",
    "application/json-evil",
    "application/json, application/json",
    "application/json, text/plain",
    "application/json; charset=utf-8, application/json",
    "application/json;",
    "application/json; charset",
    "application/json; charset =utf-8",
    "application/j\u017fon",
    "\u0430pplication/json",
    "application/js\u03bfn",
    "application\uff0fjson",
  ]) {
    let bodyReads = 0;
    let cancelCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({
        status: 200,
        headers: {
          get(name) {
            return name.toLowerCase() === "content-type" ? contentType : null;
          },
        },
        body: {
          getReader() {
            bodyReads += 1;
            throw new Error("confused media type body must not be read");
          },
          cancel() {
            cancelCalls += 1;
          },
        },
      }),
    });
    await assert.rejects(
      () => client.getContractCodeBytes(
        { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
        canonicalReadOptions(),
      ),
      /must use (?:the )?application\/json/,
      contentType,
    );
    assert.equal(bodyReads, 0, `${contentType} body reads`);
    assert.equal(cancelCalls, 1, `${contentType} cancellation`);
  }
});

test("bounded code-byte response reads enforce timeout and caller abort", async () => {
  for (const mode of ["timeout", "abort"]) {
    let cancelCalls = 0;
    const reader = {
      read() {
        return new Promise(() => {});
      },
      cancel() {
        cancelCalls += 1;
      },
      releaseLock() {},
    };
    const body = {
      getReader() {
        return reader;
      },
    };
    const controller = new AbortController();
    const client = new ToriiClient(BASE_URL, {
      timeoutMs: mode === "timeout" ? 10 : 1_000,
      fetchImpl: async () => ({
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body,
      }),
    });
    if (mode === "abort") {
      setTimeout(() => controller.abort(new Error("caller stopped body read")), 10);
    }
    const startedAt = Date.now();
    await assert.rejects(
      () =>
        client.getContractCodeBytes(
          { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
          canonicalReadOptions({
            ...(mode === "abort" ? { signal: controller.signal } : {}),
          }),
        ),
      mode === "timeout" ? /body read timed out after 10ms/ : /caller stopped body read/,
    );
    assert.ok(Date.now() - startedAt < 500, `${mode} must terminate promptly`);
    assert.equal(cancelCalls, 1, `${mode} reader cancellation`);
  }
});

test("bounded readers close reentrant abort and hostile signal cleanup races", async () => {
  for (const abortPoint of ["content-length", "getReader"]) {
    const controller = new AbortController();
    const reason = new Error(`abort from ${abortPoint}`);
    let cancelCalls = 0;
    let releaseCalls = 0;
    let reads = 0;
    const reader = {
      async read() {
        reads += 1;
        return reads === 1
          ? {
              done: false,
              value: new TextEncoder().encode(JSON.stringify(ARTIFACT_READ_RESPONSE)),
            }
          : { done: true, value: undefined };
      },
      cancel() {
        cancelCalls += 1;
      },
      releaseLock() {
        releaseCalls += 1;
      },
    };
    const body = {
      getReader() {
        if (abortPoint === "getReader") controller.abort(reason);
        return reader;
      },
    };
    const headers = {
      get(name) {
        if (name.toLowerCase() === "content-type") return "application/json";
        if (name.toLowerCase() === "content-length") {
          if (abortPoint === "content-length") controller.abort(reason);
          return null;
        }
        return null;
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({ status: 200, headers, body }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes(
          { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
          canonicalReadOptions({ signal: controller.signal }),
        ),
      new RegExp(`abort from ${abortPoint}`),
    );
    assert.equal(cancelCalls, 1, abortPoint);
    assert.equal(releaseCalls, 1, abortPoint);
  }

  const shadowedController = new AbortController();
  const shadowedReason = new Error("intrinsic aborted state wins");
  shadowedController.abort(shadowedReason);
  Object.defineProperties(shadowedController.signal, {
    aborted: { value: false },
    reason: { value: undefined },
    addEventListener: { value() {} },
    removeEventListener: { value() {} },
    throwIfAborted: { value() {} },
  });
  let shadowBodyCancels = 0;
  const shadowClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        cancel() {
          shadowBodyCancels += 1;
        },
      },
    }),
  });
  await assert.rejects(
    () =>
      shadowClient.getContractCodeBytes(
        { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
        canonicalReadOptions({ signal: shadowedController.signal }),
      ),
    /intrinsic aborted state wins/,
  );
  assert.equal(shadowBodyCancels, 1);

  for (const mode of ["add throws", "remove throws"]) {
    let readerCancels = 0;
    let releases = 0;
    const customSignal = {
      aborted: false,
      addEventListener() {
        if (mode === "add throws") throw new Error("listener boom");
      },
      removeEventListener() {
        if (mode === "remove throws") throw new Error("cleanup boom");
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body: {
          getReader() {
            return {
              async read() {
                if (mode === "remove throws") {
                  return { done: false, value: "not bytes" };
                }
                return { done: true, value: undefined };
              },
              cancel() {
                readerCancels += 1;
              },
              releaseLock() {
                releases += 1;
              },
            };
          },
        },
      }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes(
          { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
          canonicalReadOptions({ signal: customSignal }),
        ),
      mode === "add throws" ? /listener boom/ : /non-byte chunk/,
    );
    assert.equal(readerCancels, mode === "add throws" ? 0 : 1, mode);
    assert.equal(releases, mode === "add throws" ? 0 : 1, mode);
  }
});

test("bounded readers cancel when custom header methods throw", async () => {
  let cancelCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 200,
      headers: {
        get() {
          throw new Error("hostile header getter");
        },
      },
      body: {
        cancel() {
          cancelCalls += 1;
        },
      },
    }),
  });
  await assert.rejects(
    () => client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
    /hostile header getter/,
  );
  assert.equal(cancelCalls, 1);
});

test("bounded code-byte responses cancel after UTF-8 and JSON rejection", async () => {
  for (const [bytes, expected] of [
    [Uint8Array.of(0xc3, 0x28), /must be valid UTF-8/],
    [new TextEncoder().encode("{"), /contract code bytes response contains invalid JSON at character 1: expected a string/],
  ]) {
    let bodyCancelCalls = 0;
    let reads = 0;
    const body = {
      getReader() {
        return {
          async read() {
            reads += 1;
            return reads === 1
              ? { done: false, value: bytes }
              : { done: true, value: undefined };
          },
          releaseLock() {},
        };
      },
      cancel() {
        bodyCancelCalls += 1;
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body,
      }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      expected,
    );
    assert.equal(bodyCancelCalls, 1);
  }
});

test("bounded contract-code response copies never consult buffer species", async () => {
  const responseChunk = new TextEncoder().encode(JSON.stringify(ARTIFACT_READ_RESPONSE));
  let responseConstructorReads = 0;
  Object.defineProperty(responseChunk.buffer, "constructor", {
    get() {
      responseConstructorReads += 1;
      throw new Error("response buffer constructor must not run");
    },
  });
  let reads = 0;
  const responseClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            async read() {
              reads += 1;
              return reads === 1
                ? { done: false, value: responseChunk }
                : { done: true, value: undefined };
            },
            releaseLock() {},
          };
        },
      },
    }),
  });
  assert.deepEqual(
    await responseClient.getContractCodeBytes(
      { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
      canonicalReadOptions(),
    ),
    ARTIFACT_READ_RESPONSE,
  );
  assert.equal(responseConstructorReads, 0);
});

test("bounded response readers reject accessor read results without invoking them", async () => {
  let getterCalls = 0;
  let cancelCalls = 0;
  const readResult = { value: Uint8Array.of(1) };
  Object.defineProperty(readResult, "done", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return false;
    },
  });
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            async read() {
              return readResult;
            },
            cancel() {
              cancelCalls += 1;
            },
            releaseLock() {},
          };
        },
      },
    }),
  });
  await assert.rejects(
    () => client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
    /done must be an enumerable data property/,
  );
  assert.equal(getterCalls, 0);
  assert.equal(cancelCalls, 1);
});

test("getContractCodeBytes rejects oversized declared bodies before reading", async () => {
  for (const contentLength of [
    String(CONTRACT_CODE_BYTES_JSON_MAX_BYTES + 1),
    "-1",
    "1.5",
    "9007199254740993",
  ]) {
    let bodyReads = 0;
    const response = {
      status: 200,
      headers: new Headers({
        "content-type": "application/json",
        "content-length": contentLength,
      }),
      get body() {
        bodyReads += 1;
        throw new Error("body must not be read");
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => response,
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      /Content-Length|response limit/,
    );
    assert.equal(bodyReads, 0);
  }
});

test("getContractCodeBytes bounds actual streamed bytes with absent or lying headers", async () => {
  for (const contentLength of [null, "1"]) {
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(
          new Uint8Array(CONTRACT_CODE_BYTES_JSON_MAX_BYTES),
        );
        controller.enqueue(Uint8Array.of(0x20));
      },
      cancel() {
        cancelled = true;
      },
    });
    const headers = new Headers({ "content-type": "application/json" });
    if (contentLength !== null) headers.set("content-length", contentLength);
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => new Response(body, { status: 200, headers }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      /exceeds the .*response limit/,
    );
    assert.equal(cancelled, true);
  }
});

test("getContractCodeBytes fails closed without a bounded byte stream", async () => {
  let textCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => (ARTIFACT_READ_RESPONSE),
      text: async () => {
        textCalls += 1;
        return JSON.stringify(ARTIFACT_READ_RESPONSE);
      },
    }),
  });
  await assert.rejects(
    () => client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
    /requires a byte-stream response body/,
  );
  assert.equal(textCalls, 0);
});

test("getContractCodeBytes rejects shared and snapshots reused stream chunks", async () => {
  if (typeof SharedArrayBuffer === "function") {
    let read = false;
    let cancelled = false;
    const sharedChunk = new Uint8Array(new SharedArrayBuffer(1));
    Object.defineProperties(sharedChunk, {
      buffer: { value: new ArrayBuffer(1) },
      byteOffset: { value: 0 },
      byteLength: { value: 1 },
    });
    const sharedResponse = {
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            async read() {
              if (read) return { done: true, value: undefined };
              read = true;
              return {
                done: false,
                value: sharedChunk,
              };
            },
            async cancel() {
              cancelled = true;
            },
            releaseLock() {},
          };
        },
      },
    };
    const sharedClient = new ToriiClient(BASE_URL, {
      fetchImpl: async () => sharedResponse,
    });
    await assert.rejects(
      () =>
        sharedClient.getContractCodeBytes(
          { dataspaceId: "0", codeHash: ARTIFACT_READ_HASH },
          canonicalReadOptions(),
        ),
      /must not use SharedArrayBuffer-backed chunks/,
    );
    assert.equal(cancelled, true);
  }

  const first = new TextEncoder().encode(JSON.stringify(ARTIFACT_READ_RESPONSE).slice(0, 40));
  Object.defineProperties(first, {
    buffer: {
      get() {
        throw new Error("shadow buffer must not be read");
      },
    },
    byteOffset: {
      get() {
        throw new Error("shadow byteOffset must not be read");
      },
    },
    byteLength: {
      get() {
        throw new Error("shadow byteLength must not be read");
      },
    },
  });
  const second = new TextEncoder().encode(JSON.stringify(ARTIFACT_READ_RESPONSE).slice(40));
  let readIndex = 0;
  const response = {
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    body: {
      getReader() {
        return {
          async read() {
            readIndex += 1;
            if (readIndex === 1) return { done: false, value: first };
            if (readIndex === 2) {
              first.fill(0x78);
              return { done: false, value: second };
            }
            return { done: true, value: undefined };
          },
          releaseLock() {},
        };
      },
    },
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => response,
  });
  assert.deepEqual(
    await client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
    ARTIFACT_READ_RESPONSE,
  );
});

test("getContractCodeBytes cancels non-progress and fragmented streams", async () => {
  for (const mode of ["empty", "fragmented"]) {
    let reads = 0;
    let cancelled = false;
    const response = {
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            async read() {
              reads += 1;
              return {
                done: false,
                value:
                  mode === "empty" ? new Uint8Array(0) : Uint8Array.of(0x20),
              };
            },
            async cancel() {
              cancelled = true;
            },
            releaseLock() {},
          };
        },
      },
    };
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => response,
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      mode === "empty" ? /empty non-progress chunk/ : /too many fragmented chunks/,
    );
    assert.equal(cancelled, true);
    assert.equal(
      reads,
      mode === "empty" ? 1 : 64 * 1024 + 1,
      `${mode} stream read bound`,
    );
  }
});

test("getContractCodeBytes rejects oversized base64 before decoding", async () => {
  const attacks = [
    "A".repeat(IVM_ARTIFACT_MAX_BASE64_LENGTH + 1),
    Buffer.alloc(IVM_ARTIFACT_MAX_BYTES + 1).toString("base64"),
  ];
  for (const code_b64 of attacks) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        new Response(JSON.stringify(withArtifactResponseIdentity({ code_b64 }, ARTIFACT_READ_HASH)), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      /exceeds the 4194304-byte artifact limit/,
    );
  }
});

test("getContractCodeBytes rejects non-string code_b64 JSON values", async () => {
  for (const code_b64 of [null, [], {}, [89, 50, 57, 107, 90, 81]]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        new Response(JSON.stringify(withArtifactResponseIdentity({ code_b64 }, ARTIFACT_READ_HASH)), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      /code_b64 must be a base64 string/,
    );
  }
});

test("getContractCodeBytes rejects ambiguous or active DTO shapes", async () => {
  let accessorReads = 0;
  const accessor = {};
  Object.defineProperty(accessor, "code_b64", {
    enumerable: true,
    get() {
      accessorReads += 1;
      return "Y29kZQ==";
    },
  });
  const withSymbol = { ...ARTIFACT_READ_RESPONSE };
  withSymbol[Symbol("attacker")] = true;
  for (const payload of [
    {},
    { code_b64: "Y29kZQ==", extra: true },
    withSymbol,
    accessor,
  ]) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => ({ status: 200 }),
    });
    client._readBoundedLosslessIntegerJson = async () => payload;
    await assert.rejects(
      () =>
        client.getContractCodeBytes({ dataspaceId: "0", codeHash: ARTIFACT_READ_HASH }, canonicalReadOptions()),
      /must contain exactly|enumerable data property/,
    );
  }
  assert.equal(accessorReads, 0, "accessor payload must be rejected without invocation");
});

test("getGovernanceContract mirrors response handling", async () => {
  let calledUrl;
  const owner = FIXTURE_ALICE_ID;
  const fetchImpl = async (url) => {
    calledUrl = url;
    return createResponse({
      status: 200,
      jsonData: {
        found: true,
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        contract_subject_account: owner,
        dataspace: "universal",
        active: true,
        lifecycle: {
          version: 1,
          origin: "direct",
          origin_account: owner,
          origin_proposal_content_id_hex: null,
          origin_governance_attempt_id_hex: null,
          owner,
          pending_owner: null,
          parliament_delegated: false,
          active_code_hash_hex: "1".repeat(64),
          retained_code_hash_hex: "1".repeat(64),
          revision: 1,
          emergency_hold: null,
        },
        emergency_hold_active: false,
        code_hash_hex: "1".repeat(64),
        abi_hash_hex: "2".repeat(64),
        public_entrypoints: ["ping"],
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.getGovernanceContract(
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    canonicalReadOptions(),
  );
  assert.ok(calledUrl?.includes("/v1/gov/contracts/"));
  assert.equal(result.contract_address, "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw");
  assert.equal(result.dataspace, "universal");
  assert.equal(result.code_hash_hex, "1".repeat(64));
});

test("getGovernanceContract preserves u64 lifecycle tokens and rejects lossy wire values", async () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const lifecycleWire = ({
    revision = "18446744073709551615",
    imposedAtHeight = "18446744073709551614",
    expiresAtHeight = "18446744073709551615",
  } = {}) => JSON.stringify({
    found: true,
    contract_address: contractAddress,
    contract_subject_account: FIXTURE_ALICE_ID,
    dataspace: "universal",
    active: true,
    lifecycle: {
      version: 1,
      origin: "direct",
      origin_account: FIXTURE_ALICE_ID,
      origin_proposal_content_id_hex: null,
      origin_governance_attempt_id_hex: null,
      owner: FIXTURE_ALICE_ID,
      pending_owner: null,
      parliament_delegated: false,
      active_code_hash_hex: "1".repeat(64),
      retained_code_hash_hex: "1".repeat(64),
      revision: "__REVISION__",
      emergency_hold: {
        incident_digest_hex: "4".repeat(64),
        proposal_content_id_hex: "5".repeat(64),
        governance_attempt_id_hex: "6".repeat(64),
        reason: "containment",
        imposed_at_height: "__IMPOSED__",
        expires_at_height: "__EXPIRES__",
      },
    },
    emergency_hold_active: true,
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    public_entrypoints: ["ping"],
  })
    .replace('"__REVISION__"', revision)
    .replace('"__IMPOSED__"', imposedAtHeight)
    .replace('"__EXPIRES__"', expiresAtHeight);
  const clientForWire = (body) => new ToriiClient(BASE_URL, {
    fetchImpl: async () => new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });

  const result = await clientForWire(lifecycleWire()).getGovernanceContract(
    contractAddress,
    canonicalReadOptions(),
  );
  assert.equal(result.lifecycle.revision, 18446744073709551615n);
  assert.equal(result.lifecycle.emergency_hold.imposed_at_height, 18446744073709551614n);
  assert.equal(result.lifecycle.emergency_hold.expires_at_height, 18446744073709551615n);

  for (const token of ['"1"', "true", "1.5", "18446744073709551616"]) {
    await assert.rejects(
      () => clientForWire(lifecycleWire({ revision: token })).getGovernanceContract(
        contractAddress,
        canonicalReadOptions(),
      ),
      /integer|unsigned 64-bit|at most/u,
      `revision token ${token}`,
    );
  }
  const duplicate = lifecycleWire({ revision: "1" }).replace(
    '"revision":1',
    '"revision":1,"revision":2',
  );
  await assert.rejects(
    () => clientForWire(duplicate).getGovernanceContract(
      contractAddress,
      canonicalReadOptions(),
    ),
    /duplicate object key/u,
  );

  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  assert.match(declarations, /revision: ToriiU64;/u);
  assert.match(declarations, /imposed_at_height: ToriiU64;/u);
  assert.match(declarations, /expires_at_height: ToriiU64;/u);
});

test("getGovernanceContract rejects coercible, non-canonical, or unexpected fields", async () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const activeResponse = {
    found: true,
    contract_address: contractAddress,
    contract_subject_account: FIXTURE_ALICE_ID,
    dataspace: "universal",
    active: true,
    lifecycle: {
      version: 1,
      origin: "direct",
      origin_account: FIXTURE_ALICE_ID,
      origin_proposal_content_id_hex: null,
      origin_governance_attempt_id_hex: null,
      owner: FIXTURE_ALICE_ID,
      pending_owner: null,
      parliament_delegated: false,
      active_code_hash_hex: "1".repeat(64),
      retained_code_hash_hex: "1".repeat(64),
      revision: 1,
      emergency_hold: null,
    },
    emergency_hold_active: false,
    code_hash_hex: "1".repeat(64),
    abi_hash_hex: "2".repeat(64),
    public_entrypoints: ["ping"],
  };
  const cases = [
    [
      "string boolean",
      {
        found: "false",
        contract_address: contractAddress,
        dataspace: "universal",
      },
      /found must be a boolean/,
    ],
    [
      "uppercase hash",
      { ...activeResponse, code_hash_hex: "A".repeat(64) },
      /code_hash_hex must be an exact lowercase 32-byte hex string/,
    ],
    [
      "unexpected field",
      {
        found: true,
        contract_address: contractAddress,
        dataspace: "universal",
        code_hash_hex: "1".repeat(64),
        ignored: true,
      },
      /unsupported fields: ignored/,
    ],
    [
      "missing retained binding",
      { ...activeResponse, lifecycle: Object.fromEntries(Object.entries(activeResponse.lifecycle).filter(([key]) => key !== "retained_code_hash_hex")) },
      /retained_code_hash_hex/,
    ],
    [
      "mismatched retained binding",
      { ...activeResponse, lifecycle: { ...activeResponse.lifecycle, retained_code_hash_hex: "3".repeat(64) } },
      /retained_code_hash_hex must match active_code_hash_hex/,
    ],
    [
      "mismatched lifecycle code hash",
      {
        ...activeResponse,
        lifecycle: { ...activeResponse.lifecycle, active_code_hash_hex: "3".repeat(64), retained_code_hash_hex: "3".repeat(64) },
      },
      /active_code_hash_hex must match code_hash_hex/,
    ],
    [
      "unsupported lifecycle version",
      {
        ...activeResponse,
        lifecycle: { ...activeResponse.lifecycle, version: 0 },
      },
      /version must be the number 1/,
    ],
    [
      "unsorted public entrypoints",
      { ...activeResponse, public_entrypoints: ["view_balance", "transfer"] },
      /must be sorted and contain no duplicates/,
    ],
    [
      "absent response with active fields",
      { found: false, contract_address: contractAddress, dataspace: "universal", active: null },
      /unsupported fields: active/,
    ],
  ];
  for (const [label, jsonData, pattern] of cases) {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.getGovernanceContract(contractAddress, canonicalReadOptions()),
      pattern,
      label,
    );
  }
});

test("getGovernanceContract rejects unsupported option keys", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked for invalid options");
    },
  });
  await assert.rejects(
    () =>
      client.getGovernanceContract(
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        canonicalReadOptions({ cursor: "abc" }),
      ),
    /getGovernanceContract options contains unsupported fields: cursor/,
  );
});

test("listTriggers encodes query params and normalizes payload", async () => {
  let capturedUrl;
  const authority = normalizeAccountId(
    FIXTURE_AUTHORITY_ID,
    "listTriggers.authority",
  );
  const triggerPayload = {
    id: "apps::mint_rewards",
    action: { Mint: { Asset: { object: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" } } },
    metadata: { label: "demo" },
  };
  const fetchImpl = async (url) => {
    capturedUrl = url;
    return createResponse({
      status: 200,
      jsonData: { items: [triggerPayload], total: "1" },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const page = await client.listTriggers({
    namespace: "apps",
    authority,
    limit: 5,
    offset: 10,
  });
  const parsed = new URL(capturedUrl);
  assert.equal(parsed.pathname, "/v1/triggers");
  assert.equal(parsed.searchParams.get("namespace"), "apps");
  assert.equal(parsed.searchParams.get("authority"), authority);
  assert.equal(parsed.searchParams.get("limit"), "5");
  assert.equal(parsed.searchParams.get("offset"), "10");
  assert.equal(page.total, 1);
  assert.equal(page.items[0].id, triggerPayload.id);
  assert.deepEqual(page.items[0].action, triggerPayload.action);
  assert.deepEqual(page.items[0].metadata, triggerPayload.metadata);
  assert.deepEqual(page.items[0].raw, triggerPayload);
});

test("listTriggers rejects invalid signal values", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listTriggers({ signal: {} }),
    /triggers options\.signal must be an AbortSignal/,
  );
});

test("getTrigger validates options before network access", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.getTrigger("apps::mint_rewards", 123),
    /getTrigger options must be an object/,
  );
  await assert.rejects(
    () => client.getTrigger("apps::mint_rewards", { signal: {} }),
    /getTrigger options\.signal must be an AbortSignal/,
  );
  await assert.rejects(
    () => client.getTrigger("apps::mint_rewards", { extra: "nope" }),
    /getTrigger options contains unsupported fields: extra/,
  );
});

test("getTrigger handles 404 and normalizes metadata", async () => {
  let calls = 0;
  const payload = {
    id: "apps::mint_rewards",
    action: { Mint: { Asset: { object: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" } } },
  };
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) {
      return createResponse({ status: 404 });
    }
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const missing = await client.getTrigger("apps::missing");
  assert.equal(missing, null);
  const record = await client.getTrigger("apps::mint_rewards");
  assert.ok(record);
  assert.equal(record.id, payload.id);
  assert.deepEqual(record.action, payload.action);
  assert.deepEqual(record.metadata, {});
});

test("registerTrigger posts JSON body", async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 202,
      jsonData: { ok: true },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const response = await client.registerTrigger({
    id: "apps::rotate_peer",
    namespace: "apps",
    action: { Mint: {} },
  });
  assert.equal(captured.url, `${BASE_URL}/v1/triggers`);
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["Content-Type"], "application/json");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.deepEqual(JSON.parse(captured.init.body), {
    id: "apps::rotate_peer",
    namespace: "apps",
    action: { Mint: {} },
  });
  assert.deepEqual(response, { ok: true });
});

test("registerTrigger validates options before dispatch", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const payload = { id: "apps::rotate_peer", namespace: "apps", action: { Mint: {} } };
  await assert.rejects(
    () => client.registerTrigger(payload, "oops"),
    /registerTrigger options must be an object/,
  );
  await assert.rejects(
    () => client.registerTrigger(payload, { signal: {} }),
    /registerTrigger options\.signal must be an AbortSignal/,
  );
  await assert.rejects(
    () => client.registerTrigger(payload, { memo: "not-allowed" }),
    /registerTrigger options contains unsupported fields: memo/,
  );
});

test("registerTrigger normalizes base64 actions and metadata", async () => {
  let captured;
  const fetchImpl = async (_url, init) => {
    captured = init;
    return createResponse({ status: 202 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await client.registerTrigger({
    id: "apps::encoded_trigger",
    namespace: "apps",
    action: "  AAECAwQ=  ",
    metadata: { window: 4n, labels: ["demo"] },
  });
  const payload = JSON.parse(captured.body);
  assert.equal(payload.action, "AAECAwQ=");
  assert.deepEqual(payload.metadata, { window: "4", labels: ["demo"] });
  assert.equal(payload.namespace, "apps");
});

test("registerTrigger rejects invalid base64 actions", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not fetch");
    },
  });
  await assert.rejects(
    () =>
      client.registerTrigger({
        id: "apps::bad_action",
        namespace: "apps",
        action: "AAAA====",
      }),
    /registerTrigger\.action must be a valid base64 string/,
  );
});

test("registerTrigger rejects invalid payloads", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("should not reach fetch when validation fails");
    },
  });
  await assert.rejects(
    () => client.registerTrigger({ id: "", action: { Mint: {} } }),
    /registerTrigger\.id/,
  );
  await assert.rejects(
    () =>
      client.registerTrigger({
        id: "apps::bad",
        action: { Mint: {} },
        metadata: "oops",
      }),
    /registerTrigger\.metadata/,
  );
  await assert.rejects(
    () =>
      client.registerTrigger({
        id: "apps::missing_action",
      }),
    /registerTrigger\.action is required/,
  );
});

test("registerTriggerTyped normalizes response payloads", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/triggers`);
    assert.equal(init.method, "POST");
    return createResponse({
      status: 202,
      jsonData: {
        ok: true,
        trigger_id: "apps::mint_rewards",
        tx_instructions: [
          {
            wire_id: "RegisterTrigger",
            payload_hex: "0xDEADBEEF",
          },
        ],
        accepted: true,
        message: "queued",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const draft = await client.registerTriggerTyped({
    id: "apps::mint_rewards",
    namespace: "apps",
    action: { Mint: {} },
  });
  assert(draft);
  assert.equal(draft.trigger_id, "apps::mint_rewards");
  assert.equal(draft.ok, true);
  assert.equal(draft.accepted, true);
  assert.equal(draft.message, "queued");
  assert.deepEqual(draft.tx_instructions, [
    { wire_id: "RegisterTrigger", payload_hex: "deadbeef" },
  ]);
});

test("deleteTriggerTyped returns null when Torii omits payloads", async () => {
  const fetchImpl = async (url, init) => {
    const encoded = encodeURIComponent("apps::archived");
    assert.equal(url, `${BASE_URL}/v1/triggers/${encoded}`);
    assert.equal(init.method, "DELETE");
    return createResponse({ status: 204 });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.deleteTriggerTyped("apps::archived");
  assert.equal(result, null);
});

test("queryTriggers posts iterable envelope", async () => {
  let capturedBody;
  const fetchImpl = async (_url, init) => {
    capturedBody = JSON.parse(init.body);
    return createResponse({
      status: 200,
      jsonData: { items: [], total: 0 },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.queryTriggers({
    filter: { op: "eq", args: ["namespace", "apps"] },
    sort: [{ key: "created_at", order: "desc" }],
    limit: 5,
    offset: 2,
    fetchSize: 25,
    queryName: "recent-triggers",
  });
  assert.deepEqual(capturedBody.pagination, { offset: 2, limit: 5 });
  assert.deepEqual(capturedBody.filter, { op: "eq", args: ["namespace", "apps"] });
  assert.deepEqual(capturedBody.sort, [{ key: "created_at", order: "desc" }]);
  assert.equal(capturedBody.fetch_size, 25);
  assert.equal(capturedBody.query, "recent-triggers");
  assert.deepEqual(result.items, []);
  assert.equal(result.total, 0);
});

test("queryTriggers normalizes alias fields", async () => {
  let capturedBody;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async (_url, init) => {
      capturedBody = JSON.parse(init.body);
      return createResponse({
        status: 200,
        jsonData: { items: [], total: 0 },
        headers: { "content-type": "application/json" },
      });
    },
  });
  const result = await client.queryTriggers({
    fetch_size: 3,
    query_name: "alias-query",
  });
  assert.equal(capturedBody.fetch_size, 3);
  assert.equal(capturedBody.query, "alias-query");
  assert.equal(capturedBody.canonical_i105, undefined);
  assert.deepEqual(result.items, []);
  assert.equal(result.total, 0);
});

test("queryTriggers rejects non-object options", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      return createResponse({
        status: 200,
        jsonData: { items: [], total: 0 },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(
    () => client.queryTriggers(5),
    /trigger query options must be a plain object/,
  );
  assert.equal(fetchCalled, false);
});

test("queryTriggers rejects unsupported option keys", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      return createResponse({
        status: 200,
        jsonData: { items: [], total: 0 },
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(
    () => client.queryTriggers({ limit: 1, extra: true }),
    /trigger query options contains unsupported fields: extra/,
  );
  assert.equal(fetchCalled, false);
});

 test("deleteTrigger tolerates missing records", async () => {
  const fetchImpl = async () => createResponse({ status: 404 });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const result = await client.deleteTrigger("apps::obsolete");
  assert.equal(result, null);
});

test("deleteTrigger validates options before issuing request", async () => {
  const fetchImpl = async () => {
    throw new Error("should not fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.deleteTrigger("apps::obsolete", 123),
    /deleteTrigger options must be an object/,
  );
  await assert.rejects(
    () => client.deleteTrigger("apps::obsolete", { signal: {} }),
    /deleteTrigger options\.signal must be an AbortSignal/,
  );
  await assert.rejects(
    () => client.deleteTrigger("apps::obsolete", { memo: "nope" }),
    /deleteTrigger options contains unsupported fields: memo/,
  );
});

test("listPeers hits Torii endpoint and returns raw payload", async () => {
  let capturedRequest;
  const sample = [
    { address: "10.0.0.4:1337", id: { public_key: "ab".repeat(32) } },
  ];
  const fetchImpl = async (url, init) => {
    capturedRequest = { url, init };
    return createResponse({
      status: 200,
      jsonData: sample,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const peers = await client.listPeers();
  assert.equal(capturedRequest.url, `${BASE_URL}/v1/peers`);
  assert.equal(capturedRequest.init.method, "GET");
  assert.equal(capturedRequest.init.headers.Accept, "application/json");
  assert.deepEqual(peers, sample);
});

test("listPeers enforces options object", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listPeers(null),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /listPeers options must be an object/);
      return true;
    },
  );
});

test("listPeers rejects unsupported option fields", async () => {
  const fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listPeers({ signal: undefined, unexpected: true }),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(
        error.message,
        /listPeers options contains unsupported fields: unexpected/,
      );
      return true;
    },
  );
});

test("listPeersTyped normalizes address and public key", async () => {
  const payload = [
    {
      address: "  192.168.1.12:8080 ",
      id: { public_key: `0X${"AA".repeat(32)}` },
    },
  ];
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const peers = await client.listPeersTyped();
  assert.deepEqual(peers, [
    {
      address: "192.168.1.12:8080",
      public_key_hex: "aa".repeat(32),
    },
  ]);
});

test("listPeersTyped rejects malformed entries", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: [{}],
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listPeersTyped(),
    /peer list response\[0\]\.address/,
  );
});

test("getExplorerMetrics normalizes payload and tolerates telemetry gating", async () => {
  let callCount = 0;
  const fetchImpl = async (url, init = {}) => {
    callCount += 1;
    if (callCount === 1) {
      assert.equal(url, `${BASE_URL}/v1/explorer/metrics`);
      assert.equal(init.method, "GET");
      assert.equal(init.headers.Accept, "application/json");
      return createResponse({
        status: 200,
        jsonData: {
          peers: "5",
          domains: 3,
          accounts: "9",
          assets: 12,
          transactions_accepted: 7,
          transactions_rejected: "2",
          block: 42,
          block_created_at: "2025-01-01T00:00:00Z",
          finalized_block: "41",
          avg_commit_time: { ms: 250 },
          avg_block_time: { ms: 500 },
        },
        headers: { "content-type": "application/json" },
      });
    }
    return createResponse({ status: 403, jsonData: {}, headers: { "content-type": "application/json" } });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getExplorerMetrics();
  assert.deepEqual(snapshot, {
    peers: 5,
    domains: 3,
    accounts: 9,
    assets: 12,
    transactionsAccepted: 7,
    transactionsRejected: 2,
    blockHeight: 42,
    blockCreatedAt: "2025-01-01T00:00:00Z",
    finalizedBlockHeight: 41,
    averageCommitTimeMs: 250,
    averageBlockTimeMs: 500,
  });
  const disabled = await client.getExplorerMetrics();
  assert.equal(disabled, null);
});

test("getExplorerMetrics rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () => client.getExplorerMetrics(123),
    /getExplorerMetrics options must be an object/,
  );
});

test("getExplorerMetrics rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () => client.getExplorerMetrics({ unexpected: "value" }),
    /getExplorerMetrics options contains unsupported fields: unexpected/,
  );
});

test("getExplorerAccountQr normalizes payloads", async () => {
  const accountId = FIXTURE_ALICE_ID;
  let callCount = 0;
  const fetchImpl = async (url, init = {}) => {
    callCount += 1;
    const requestUrl = new URL(url);
    assert.equal(init.method, "GET");
    assert.equal(init.headers.Accept, "application/json");
    assert.equal(
      requestUrl.pathname,
      `/v1/explorer/accounts/${encodeURIComponent(accountId)}/qr`,
    );
    if (callCount === 1) {
      assert.equal(requestUrl.search, "");
      return createResponse({
        status: 200,
        jsonData: {
          canonical_id: accountId,
          literal: "i105testliteral",
          network_prefix: 73,
          error_correction: "M",
          modules: 192,
          qr_version: 5,
          svg: "<svg />",
        },
        headers: { "content-type": "application/json" },
      });
    }
    assert.equal(requestUrl.search, "");
    return createResponse({
      status: 200,
      jsonData: {
        canonical_id: accountId,
        literal: "i105defaultliteral",
        network_prefix: 73,
        error_correction: "M",
        modules: 192,
        qr_version: 5,
        svg: "<svg />",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const firstSnapshot = await client.getExplorerAccountQr(accountId);
  assert.deepEqual(firstSnapshot, {
    canonicalId: accountId,
    literal: "i105testliteral",
    networkPrefix: 73,
    errorCorrection: "M",
    modules: 192,
    qrVersion: 5,
    svg: "<svg />",
  });
  const defaultSnapshot = await client.getExplorerAccountQr(accountId);
  assert.equal(defaultSnapshot.literal, "i105defaultliteral");
  assert.equal(callCount, 2);
});

test("getExplorerAccountQr accepts account aliases on account-id paths", async () => {
  const alias = "operator@banka.universal";
  const fetchImpl = async (url, init = {}) => {
    const requestUrl = new URL(url);
    assert.equal(init.method, "GET");
    assert.equal(
      requestUrl.pathname,
      `/v1/explorer/accounts/${encodeURIComponent(alias)}/qr`,
    );
    return createResponse({
      status: 200,
      jsonData: {
        canonical_id: FIXTURE_ALICE_ID,
        literal: "i105aliasresolved",
        network_prefix: 73,
        error_correction: "M",
        modules: 192,
        qr_version: 5,
        svg: "<svg />",
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const snapshot = await client.getExplorerAccountQr(alias);
  assert.equal(snapshot.canonicalId, FIXTURE_ALICE_ID);
  assert.equal(snapshot.literal, "i105aliasresolved");
});

test("getExplorerAccountQr rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () => client.getExplorerAccountQr(FIXTURE_ALICE_ID, 42),
    /getExplorerAccountQr options must be an object/,
  );
});

test("getExplorerAccountQr rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  await assert.rejects(
    () => client.getExplorerAccountQr(FIXTURE_ALICE_ID, { format: "i105", extra: true }),
    /getExplorerAccountQr options contains unsupported fields: format, extra/,
  );
});

test("getSnsPolicy fetches and normalizes suffix policy", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(url, `${BASE_URL}/v1/sns/policies/2`);
    assert.equal(init.method, "GET");
    return createResponse({
      status: 200,
      jsonData: {
        suffix_id: 2,
        suffix: "SORA",
        steward: SAMPLE_ACCOUNT_ID,
        status: "Active",
        min_term_years: 1,
        max_term_years: 5,
        grace_period_days: 30,
        redemption_period_days: 60,
        referral_cap_bps: 100,
        reserved_labels: [{ normalized_label: "gov", assigned_to: null, release_at_ms: null, note: "reserved" }],
        payment_asset_id: FIXTURE_ASSET_ID_A,
        pricing: [
          {
            tier_id: 1,
            label_regex: ".*",
            base_price: { asset_id: FIXTURE_ASSET_ID_A, amount: "100" },
            auction_kind: "DutchReopen",
            dutch_floor: { asset_id: FIXTURE_ASSET_ID_A, amount: "10" },
            min_duration_years: 1,
            max_duration_years: 5,
          },
        ],
        fee_split: { treasury_bps: 7000, steward_bps: 3000, referral_max_bps: 0, escrow_bps: 0 },
        fund_splitter_account: SAMPLE_ACCOUNT_ID,
        policy_version: 1,
        metadata: { version: "v1" },
      },
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const policy = await client.getSnsPolicy(2);
  assert.equal(policy.suffixId, 2);
  assert.equal(policy.suffix, "sora");
  assert.equal(policy.pricing[0].auctionKind, "DutchReopen");
  assert.equal(policy.reservedLabels[0].normalizedLabel, "gov");
});

test("SNS read helpers reject unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run for option validation");
    },
  });
  await assert.rejects(
    () => client.getSnsPolicy(1, { extra: true }),
    /getSnsPolicy options contains unsupported fields: extra/,
  );
  await assert.rejects(
    () => client.getSnsRegistration("alice.sora", { retry: false }),
    /getSnsRegistration options contains unsupported fields: retry/,
  );
});

test("retired SNS mutation helpers are absent", () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not run");
    },
  });
  for (const method of [
    "registerSnsName",
    "renewSnsRegistration",
    "transferSnsRegistration",
    "freezeSnsRegistration",
    "unfreezeSnsRegistration",
  ]) {
    assert.equal(client[method], undefined, `${method} must not remain on the public client`);
  }
});

test("SNS domain route helpers reject padded selectors before dispatch", async () => {
  let fetchCalled = false;
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("fetch should not run for padded SNS selectors");
    },
  });
  const cases = [
    ["getSnsRegistration", () => client.getSnsRegistration(" alice.sora")],
  ];

  for (const [label, action] of cases) {
    await assert.rejects(
      action,
      /selector must not contain surrounding whitespace/u,
      `${label} should reject padded selectors before dispatch`,
    );
  }
  assert.equal(fetchCalled, false);
});

test("listTelemetryPeersInfo normalizes peer telemetry metadata", async () => {
  let captured;
  const payload = [
    {
      url: "https://peer-1.example",
      connected: true,
      telemetry_unsupported: false,
      config: {
        public_key: SAMPLE_ACCOUNT_SIGNATORY,
        queue_capacity: 16,
        network_block_gossip_size: 32,
        network_block_gossip_period: { ms: 150 },
        network_tx_gossip_size: 8,
        network_tx_gossip_period: { ms: 75 },
      },
      location: { lat: 35.681, lon: 139.767, country: "JP", city: "Tokyo" },
      connected_peers: ["peer-A", "peer-B"],
    },
  ];
  const fetchImpl = async (url, init) => {
    captured = { url, init };
    return createResponse({
      status: 200,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  const peers = await client.listTelemetryPeersInfo();
  assert.equal(captured.url, `${BASE_URL}/v1/telemetry/peers-info`);
  assert.equal(captured.init.method, "GET");
  assert.equal(captured.init.headers.Accept, "application/json");
  assert.deepEqual(peers, [
    {
      url: "https://peer-1.example",
      connected: true,
      telemetryUnsupported: false,
      config: {
        publicKey: SAMPLE_ACCOUNT_SIGNATORY,
        queueCapacity: 16,
        networkBlockGossipSize: 32,
        networkBlockGossipPeriodMs: 150,
        networkTxGossipSize: 8,
        networkTxGossipPeriodMs: 75,
      },
      location: { lat: 35.681, lon: 139.767, country: "JP", city: "Tokyo" },
      connectedPeers: ["peer-A", "peer-B"],
    },
  ]);
});

test("listTelemetryPeersInfo rejects non-object options", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () => client.listTelemetryPeersInfo(Symbol("options")),
    /listTelemetryPeersInfo options must be an object/,
  );
});

test("listTelemetryPeersInfo rejects unsupported option fields", async () => {
  const client = new ToriiClient(BASE_URL, {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });
  await assert.rejects(
    () => client.listTelemetryPeersInfo({ extra: "nope" }),
    /listTelemetryPeersInfo options contains unsupported fields: extra/,
  );
});

test("listTelemetryPeersInfo rejects malformed payloads", async () => {
  const fetchImpl = async () =>
    createResponse({
      status: 200,
      jsonData: { not: "an array" },
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listTelemetryPeersInfo(),
    /telemetry peers response must be an array/,
  );
});

test("submitTransaction bounds node capabilities before any pipeline side effect", async () => {
  for (const mode of ["declared oversized", "stalled"]) {
    let pipelineCalls = 0;
    let cancelCalls = 0;
    const body =
      mode === "stalled"
        ? {
            getReader() {
              return {
                read() {
                  return new Promise(() => {});
                },
                cancel() {
                  cancelCalls += 1;
                },
                releaseLock() {},
              };
            },
          }
        : {
            cancel() {
              cancelCalls += 1;
            },
          };
    const client = new ToriiClient(BASE_URL, {
      timeoutMs: 10,
      [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
      fetchImpl: async (url) => {
        if (url.endsWith("/v1/node/capabilities")) {
          return {
            status: 200,
            headers: new Headers({
              "content-type": "application/json",
              ...(mode === "declared oversized"
                ? { "content-length": String(1024 * 1024 + 1) }
                : {}),
            }),
            body,
          };
        }
        pipelineCalls += 1;
        throw new Error("pipeline must not be reached");
      },
    });
    await assert.rejects(
      () => client.submitTransaction(Uint8Array.of(1, 0xaa)),
      mode === "stalled" ? /body read timed out after 10ms/ : /response limit/,
    );
    assert.equal(pipelineCalls, 0, mode);
    assert.equal(cancelCalls, 1, mode);
  }
});

test("submitTransaction caller abort does not wait for shared capability validation", async () => {
  const controller = new AbortController();
  let pipelineCalls = 0;
  const client = new ToriiClient(BASE_URL, {
    timeoutMs: 30,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
    fetchImpl: async (url) => {
      if (url.endsWith("/v1/node/capabilities")) {
        return {
          status: 200,
          headers: new Headers({ "content-type": "application/json" }),
          body: {
            getReader() {
              return {
                read() {
                  return new Promise(() => {});
                },
                cancel() {},
                releaseLock() {},
              };
            },
          },
        };
      }
      pipelineCalls += 1;
      throw new Error("pipeline must not be reached");
    },
  });
  const reason = new Error("caller abandoned validation");
  setTimeout(() => controller.abort(reason), 5);
  const startedAt = Date.now();
  await assert.rejects(
    () =>
      client.submitTransaction(Uint8Array.of(1, 0xaa), {
        signal: controller.signal,
      }),
    /caller abandoned validation/,
  );
  assert.ok(Date.now() - startedAt < 200);
  assert.equal(pipelineCalls, 0);
});

test("submitTransaction bounds JSON and Norito success receipts after one submit", async () => {
  for (const contentType of ["application/json", "application/x-norito"]) {
    for (const mode of ["declared oversized", "stalled"]) {
      let pipelineCalls = 0;
      let cancelCalls = 0;
      const body =
        mode === "stalled"
          ? {
              getReader() {
                return {
                  read() {
                    return new Promise(() => {});
                  },
                  cancel() {
                    cancelCalls += 1;
                  },
                  releaseLock() {},
                };
              },
            }
          : {
              cancel() {
                cancelCalls += 1;
              },
            };
      const client = new ToriiClient(BASE_URL, {
        timeoutMs: 10,
        [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
        fetchImpl: async (url) => {
          if (url.endsWith("/v1/node/capabilities")) {
            return createResponse({
              status: 200,
              jsonData: validNodeCapabilitiesPayload(),
              headers: { "content-type": "application/json" },
            });
          }
          pipelineCalls += 1;
          return {
            status: 202,
            headers: new Headers({
              "content-type": contentType,
              ...(mode === "declared oversized"
                ? { "content-length": String(1024 * 1024 + 1) }
                : {}),
            }),
            body,
          };
        },
      });
      await assert.rejects(
        () => client.submitTransaction(Uint8Array.of(1, 0xaa)),
        mode === "stalled" ? /body read timed out after 10ms/ : /response limit/,
      );
      assert.equal(pipelineCalls, 1, `${contentType} ${mode}`);
      assert.equal(cancelCalls, 1, `${contentType} ${mode}`);
    }
  }
});

test("transaction status bodies are bounded and 404 bodies are cancelled", async () => {
  const hash = "11".repeat(32);
  for (const mode of ["not found", "declared oversized", "stalled"]) {
    let cancelCalls = 0;
    const body =
      mode === "stalled"
        ? {
            getReader() {
              return {
                read() {
                  return new Promise(() => {});
                },
                cancel() {
                  cancelCalls += 1;
                },
                releaseLock() {},
              };
            },
          }
        : {
            cancel() {
              cancelCalls += 1;
            },
          };
    const client = new ToriiClient(BASE_URL, {
      timeoutMs: 10,
      fetchImpl: async () => ({
        status: mode === "not found" ? 404 : 200,
        headers: new Headers({
          "content-type": "application/json",
          ...(mode === "declared oversized"
            ? { "content-length": String(1024 * 1024 + 1) }
            : {}),
        }),
        body,
      }),
    });
    const operation = client.getTransactionStatus(hash);
    if (mode === "not found") {
      assert.equal(await operation, null);
    } else {
      await assert.rejects(
        operation,
        mode === "stalled" ? /body read timed out after 10ms/ : /response limit/,
      );
    }
    assert.equal(cancelCalls, 1, mode);
  }
});

test("HTTP error diagnostics abort stalled bodies and retry cleanup cancels discarded bodies", async () => {
  const controller = new AbortController();
  let errorBodyCancels = 0;
  const errorClient = new ToriiClient(BASE_URL, {
    fetchImpl: async () => ({
      status: 500,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            read() {
              return new Promise(() => {});
            },
            cancel() {
              errorBodyCancels += 1;
            },
            releaseLock() {},
          };
        },
      },
    }),
  });
  setTimeout(() => controller.abort(new Error("stop stalled error body")), 5);
  await assert.rejects(
    () =>
      errorClient.simulateContractCall(
        {
          authority: SAMPLE_ACCOUNT_ID,
          contractAlias: "dlmm_router::dlmm.universal",
          gasLimit: 5000,
        },
        { signal: controller.signal },
      ),
    /stop stalled error body/,
  );
  assert.equal(errorBodyCancels, 1);

  let requests = 0;
  let retryBodyCancels = 0;
  const retryClient = new ToriiClient(BASE_URL, {
    maxRetries: 1,
    backoffInitialMs: 0,
    fetchImpl: async () => {
      requests += 1;
      if (requests === 1) {
        return {
          status: 503,
          headers: new Headers({ "content-type": "application/json" }),
          body: {
            cancel() {
              retryBodyCancels += 1;
            },
          },
        };
      }
      return createResponse({
        status: 200,
        jsonData: validNodeCapabilitiesPayload(),
        headers: { "content-type": "application/json" },
      });
    },
  });
  // The public capability read is retryable: the discarded 503 body is cancelled
  // before the retry succeeds.
  const advert = await retryClient.getNodeCapabilities();
  assert.equal(advert.dataModelVersion, validNodeCapabilitiesPayload().data_model_version);
  assert.equal(requests, 2);
  assert.equal(retryBodyCancels, 1);
});

test("methods surface HTTP errors with body", async () => {
  const fetchImpl = async () =>
    createResponse({ status: 500, textBody: "boom", jsonData: { error: "boom" } });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.listAttachments(canonicalReadOptions()),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 500);
      assert.equal(error.errorMessage, "boom");
      assert.match(
        error.message,
        /Torii responded with HTTP 500 \(expected 200\): boom/,
      );
      return true;
    },
  );
});

test("http errors expose structured fields", async () => {
  const payload = {
    code: "ERR_ACCOUNT_LITERAL_FORMAT",
    message: "invalid account literal",
  };
  const fetchImpl = async () =>
    createResponse({
      status: 400,
      jsonData: payload,
      headers: { "content-type": "application/json" },
    });
  const client = new ToriiClient(BASE_URL, { fetchImpl });
  await assert.rejects(
    () => client.accounts.list(),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 400);
      assert.deepEqual(error.expected, [200]);
      assert.equal(error.code, payload.code);
      assert.equal(error.errorMessage, payload.message);
      assert.deepEqual(error.bodyJson, payload);
      return true;
    },
  );
});

test("http errors surface reject header codes", async () => {
  const fetchImpl = async (url) => {
    if (url === `${BASE_URL}/v1/node/capabilities`) {
      return createResponse({
        status: 200,
        jsonData: {
          abi_version: 1,
          data_model_version: 4,
          crypto: {
            sm: {
              enabled: false,
              default_hash: "sha2_256",
              allowed_signing: ["ed25519"],
              sm2_distid_default: "",
              openssl_preview: false,
              acceleration: {
                scalar: true,
                neon_sm3: false,
                neon_sm4: false,
                policy: "scalar-only",
              },
            },
            curves: {
              registry_version: 1,
              allowed_curve_ids: [1],
            },
          },
        },
        headers: { "content-type": "application/json" },
      });
    }
    return createResponse({
      status: 400,
      jsonData: { message: "failed to accept transaction" },
      headers: {
        "content-type": "application/json",
        "x-iroha-reject-code": "PRTRY:TX_SIGNATURE_MISSING",
      },
    });
  };
  const client = new ToriiClient(BASE_URL, {
    fetchImpl,
    [TORII_TEST_NATIVE_BINDING]: canonicalTransactionCodecNative(),
  });
  await assert.rejects(
    () => client.submitTransaction(new Uint8Array([0x01, 0x02])),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 400);
      assert.equal(error.rejectCode, "PRTRY:TX_SIGNATURE_MISSING");
      assert.equal(error.code, "PRTRY:TX_SIGNATURE_MISSING");
      return true;
    },
  );
});

function requireSorafsNative() {
  if (!nativeBinding) {
    throw new Error(
      nativeBindingError
        ? `${nativeUnavailableMessage}: ${nativeBindingError.message}`
        : nativeUnavailableMessage,
    );
  }
  const required = [
    "sorafsAliasPolicyDefaults",
    "sorafsAliasProofFixture",
    "sorafsEvaluateAliasProof",
  ];
  const missing = required.filter(
    (method) => typeof nativeBinding[method] !== "function",
  );
  if (missing.length !== 0) {
    throw new Error(
      `native iroha_js_host binding is missing required method(s): ${missing.join(", ")}`,
    );
  }
  return nativeBinding;
}

function validNodeCapabilitiesPayload() {
  return {
    abi_version: 1,
    data_model_version: 4,
    crypto: {
      sm: {
        enabled: false,
        default_hash: "sha2_256",
        allowed_signing: ["ed25519"],
        sm2_distid_default: "",
        openssl_preview: false,
        acceleration: {
          scalar: true,
          neon_sm3: false,
          neon_sm4: false,
          policy: "scalar-only",
        },
      },
      curves: {
        registry_version: 1,
        allowed_curve_ids: [1],
      },
    },
  };
}

function createBatchCapabilitiesResponse() {
  return createResponse({
    status: 200,
    jsonData: validNodeCapabilitiesPayload(),
    headers: { "content-type": "application/json" },
  });
}

function createResponse({ status, jsonData, arrayData, textBody, headers }) {
  const implicitEmptyBody =
    (status === 204 || status === 404) &&
    jsonData === undefined &&
    arrayData === undefined &&
    textBody === undefined;
  const effectiveJsonData = jsonData === undefined
    ? (implicitEmptyBody ? null : {})
    : jsonData;
  const effectiveHeaders = headers ?? (
    arrayData === undefined && textBody === undefined
      ? { "content-type": "application/json" }
      : {}
  );
  const responseText = implicitEmptyBody
    ? ""
    : typeof textBody === "string"
      ? textBody
      : JSON.stringify(effectiveJsonData);
  const bodyBytes =
    arrayData instanceof ArrayBuffer
      ? new Uint8Array(arrayData)
      : ArrayBuffer.isView(arrayData)
        ? new Uint8Array(
            arrayData.buffer,
            arrayData.byteOffset,
            arrayData.byteLength,
          )
        : new TextEncoder().encode(responseText);
  return {
    status,
    json: async () => effectiveJsonData,
    arrayBuffer: async () => {
      if (arrayData instanceof ArrayBuffer) {
        return arrayData;
      }
      if (ArrayBuffer.isView(arrayData)) {
        return arrayData.buffer.slice(arrayData.byteOffset, arrayData.byteOffset + arrayData.byteLength);
      }
      return bodyBytes.buffer.slice(
        bodyBytes.byteOffset,
        bodyBytes.byteOffset + bodyBytes.byteLength,
      );
    },
    text: async () => responseText,
    body: new ReadableStream({
      start(controller) {
        if (bodyBytes.byteLength > 0) controller.enqueue(bodyBytes);
        controller.close();
      },
    }),
    headers: {
      get(name) {
        const normalized = name.toLowerCase();
        for (const [key, value] of Object.entries(effectiveHeaders)) {
          if (key.toLowerCase() === normalized) {
            return value;
          }
        }
        return null;
      },
    },
  };
}

function createStreamedJsonResponse({ status, jsonData, headers = {} }) {
  return new Response(JSON.stringify(jsonData), {
    status,
    headers,
  });
}

test("ToriiClient._normalizeUnsignedInteger enforces integer inputs", () => {
  assert.equal(ToriiClient._normalizeUnsignedInteger("42", "value"), 42);
  assert.equal(ToriiClient._normalizeUnsignedInteger(0, "value", { allowZero: true }), 0);
  assert.equal(ToriiClient._normalizeUnsignedInteger(42n, "value"), 42);
  assert.throws(
    () => ToriiClient._normalizeUnsignedInteger(1.5, "value"),
    /value must be a positive integer/,
  );
  assert.throws(
    () => ToriiClient._normalizeUnsignedInteger("1.5", "value"),
    /value must be a positive integer/,
  );
  assert.throws(
    () => ToriiClient._normalizeUnsignedInteger(Number.MAX_SAFE_INTEGER + 1, "value"),
    /value must be at most/,
  );
});

test("ToriiClient._normalizeOffset rejects fractional offsets", () => {
  assert.throws(
    () => ToriiClient._normalizeOffset(1.25),
    /offset must be a non-negative integer/,
  );
});

test("prepareContractCall requires exact authority authentication before fetch", async () => {
  let fetched = 0;
  const draft = contractDraftForBindings({ feePayment: authorityFeePayment(5000) });
  const request = {
    authority: FIXTURE_ALICE_ID,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    entrypoint: "increment",
    feePayment: authorityFeePayment(5000),
    draftIntent: contractDraftIntentForDraft(draft),
  };
  const client = new ContractToriiClient(BASE_URL, { fetchImpl: async () => { fetched += 1; throw new Error("unexpected fetch"); } });
  await assert.rejects(() => client.prepareContractCall(request, { canonicalAuth: null }), /canonicalAuth is required/);
  await assert.rejects(() => client.prepareContractCall(request, { canonicalAuth: APPLICATION_CANONICAL_AUTH }), /accountId must equal/);
  assert.equal(fetched, 0);
});
