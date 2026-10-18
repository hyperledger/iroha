import { after, test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import * as productionPrivacyCapabilities from "../src/privacyCapabilities.js";
import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";
import {
  LocalSigningContext,
  ToriiClient,
} from "../src/toriiClient.js";
import { NetworkId } from "../src/networkId.js";

const TEST_NATIVE_BINDING = Symbol.for("iroha.test.exact12.native-binding");
const TEST_CANONICAL_AUTH = Object.freeze({
  accountId: "privacy-test@fixture.test",
  privateKey: Buffer.alloc(32, 0x0b),
});
const TEST_LOCAL_SIGNING_CONTEXT = new LocalSigningContext(
  NetworkId.fromBytes(Buffer.alloc(32, 0xa5)), 753,
);
const SUBJECT_ROOT = mkdtempSync(join(tmpdir(), "iroha-exact12-native-authority-"));
writeFileSync(join(SUBJECT_ROOT, "package.json"), '{"type":"module"}\n');

function writeSubjectFile(directory, name, contents) {
  const path = join(directory, name);
  writeFileSync(path, contents, { encoding: "utf8", flag: "wx" });
}

async function loadSubject(name, nativeModuleSource) {
  const directory = join(SUBJECT_ROOT, name);
  const source = readFileSync(
    new URL("../src/privacyCapabilities.js", import.meta.url),
    "utf8",
  );
  mkdirSync(directory, { mode: 0o700 });
  writeSubjectFile(directory, "privacyCapabilities.js", source);
  writeSubjectFile(directory, "native.js", nativeModuleSource);
  for (const dependency of [
    "privacyCapabilityAdmission",
    "privacyCapabilityTransport",
    "strictLosslessJson",
  ]) {
    const target = new URL(`../src/${dependency}.js`, import.meta.url).href;
    writeSubjectFile(
      directory,
      `${dependency}.js`,
      `export * from ${JSON.stringify(target)};\n`,
    );
  }
  return import(`${pathToFileURL(join(directory, "privacyCapabilities.js")).href}?${name}`);
}

const authenticatedTestSubject = await loadSubject(
  "authenticated-test-loader",
  `const key = Symbol.for("iroha.test.exact12.native-binding");
export function getNativeBinding() {
  const binding = globalThis[key];
  if (binding === undefined) throw new Error("test native binding is absent");
  return binding;
}
`,
);
const browserSubject = await loadSubject(
  "browser-loader",
  `export { getNativeBinding } from ${JSON.stringify(
    new URL("../src/native.browser.js", import.meta.url).href,
  )};\n`,
);

after(() => rmSync(SUBJECT_ROOT, { recursive: true, force: true }));

const {
  PRIVACY_PROTOCOL_IDS_V1,
  PrivacyExact12CapabilityManifestError,
  PrivacyExact12CapabilityManifestV1,
  decodePrivacyExact12CapabilityManifestV1,
  getPrivacyExact12CapabilityManifestV1,
  requirePrivacyExact12CapabilityAdmissionV1,
} = authenticatedTestSubject;

const ARCHIVE = Uint8Array.from([0x4e, 0x52, 0x54, 0x30, 1, 2, 3, 4]);
const CATALOG = Uint8Array.from([0x4e, 0x52, 0x54, 0x30, 9, 8, 7, 6]);
const ACTIVE_PROTOCOL = "anonymous-pgc-k-out-of-n-v1";
const OPERATION_TUPLES = Object.freeze([
  ["zk_ace_authorization_action_v1", "authorization_action", 0],
  ["anonymous_pgc_payment_action_v1", "payment_action", 6],
  ["verange_range_proof_v1", "component", 1],
  ["zk_ams_admission_and_provisioning_v1", "admission_action", 2],
  ["vega_credential_presentation_v1", "presentation_action", 2],
  ["zk_x509_identity_presentation_v1", "presentation_action", 2],
  ["jindo_polynomial_evaluation_v1", "component", 0],
  ["bootle_lantern_credential_presentation_v1", "presentation_action", 2],
  ["orchard_note_action_v1", "note_action", 7],
  ["fcmp_membership_payment_v1", "payment_action", 2],
  ["ivm_private_note_action_v1", "note_action", 7],
  ["pq_masp_note_action_v1", "note_action", 31],
]);
const BINDING_TUPLES = Object.freeze([
  ["stark-fri-sha3-384-goldilocks-v1", "native-goldilocks-sha3-384-stark-fri-v1"],
  ["anonymous-pgc-p256", "native-anonymous-pgc-p256"],
  ["iroha-verange-p256", "native-verange-p256"],
  ["zk-ams-masked-relaxed-spartan-t256-ristretto255-sha3-512", "native-zk-ams-masked-relaxed-spartan-t256-ristretto255"],
  ["vega-neutron-nova-spartan-hyrax-t256", "native-vega"],
  ["stark-fri-sha3-384-goldilocks-v1", "native-goldilocks-sha3-384-stark-fri-v1"],
  ["jindo-polynomial-commitment", "native-jindo"],
  ["lantern-lnp22-module-linear-norm", "native-lantern-lnp22"],
  ["halo2-ipa-pasta", "native-halo2-orchard"],
  ["fcmp-plus-plus-curve-tree-bulletproofs", "native-fcmp-plus-plus"],
  ["stark-fri-sha3-384-goldilocks-v1", "native-goldilocks-sha3-384-stark-fri-v1"],
  ["stark-fri-sha3-384-goldilocks-v1", "native-goldilocks-sha3-384-stark-fri-v1"],
]);

function tagged(protocol) {
  return { protocol, value: null };
}

function consensusPolicy() {
  return {
    current_limits: {
      max_actions_per_transaction: 1,
      max_actions_per_block: 2,
      max_proof_bytes_per_action: 9 * 1024 * 1024,
      max_action_bytes: 9 * 1024 * 1024 + 256 * 1024 + 512,
      max_privacy_bytes_per_transaction: 9 * 1024 * 1024 + 256 * 1024 + 512,
      max_privacy_bytes_per_block: 16 * 1024 * 1024 - 64 * 1024,
      max_statement_and_encrypted_output_bytes_per_transaction: 256 * 1024,
      max_nullifiers_per_action: 8,
      max_commitments_per_action: 8,
      retained_root_count: 2048,
    },
    pending_tightening: null,
  };
}

function availablePgcProfile() {
  const binding = releaseBinding(ACTIVE_PROTOCOL, 1);
  return {
    ...binding,
    protocol_limits: {
      protocol: ACTIVE_PROTOCOL,
      limits: { max_anonymity_set_size: 64, max_recipient_count: 8 },
    },
  };
}

function releaseBinding(protocolId, index) {
  const [proofSystem, engine] = BINDING_TUPLES[index];
  return {
    protocol_id: tagged(protocolId),
    proof_system_id: { proof_system: proofSystem, value: null },
    engine_id: { engine, value: null },
    parameter_id: Array(32).fill(index + 1),
    parameter_digest: Array(32).fill(index + 21),
    verifier_digest: Array(32).fill(index + 41),
    statement_schema_digest: Array(32).fill(index + 61),
    engine_manifest_digest: Array(32).fill(index + 81),
  };
}

function qualificationPayload() {
  const releaseDigest = Array(32).fill(0xb1);
  return {
    release_manifest: {
      version: 1,
      catalog_id: "iroha-privacy-exact12-v1",
      catalog_commitment: Array(48).fill(0xc1),
      source: {},
      abi_version: 1,
      abi_hash: Array(32).fill(0xa1),
      syscall_list_digest: Array(32).fill(0xa2),
      executables: [],
      protocols: PRIVACY_PROTOCOL_IDS_V1.map((protocolId, index) => ({
        ...releaseBinding(protocolId, index),
        security_claim: {},
        security_claim_digest: Array(32).fill(index + 101),
      })),
      stage_receipts: [],
      proof_artifacts: [],
      sdk_packages: [],
      hardware_results: [],
      release_artifact_set_digest: Array(32).fill(0xa3),
      audits: [],
      audit_bundle_digest: Array(32).fill(0xa4),
      release_signatures: [],
      manifest_digest: releaseDigest,
    },
    deployment_qualification: {
      version: 1,
      chain_id: "fixture-chain",
      network_id: TEST_LOCAL_SIGNING_CONTEXT.networkId.literal,
      genesis_hash: Array.from(TEST_LOCAL_SIGNING_CONTEXT.networkId.toBytes()),
      release_manifest_digest: [...releaseDigest],
      activation_transaction_digest: Array(32).fill(0xd2),
      activations: PRIVACY_PROTOCOL_IDS_V1.map((protocolId) => ({
        protocol_id: tagged(protocolId),
        activation_height: 2,
      })),
      validator_roster_digest: Array(32).fill(0xd3),
      endpoint_version: "v1",
      convergence_height: 3,
      converged_state_digest: Array(32).fill(0xd4),
      validator_canaries: [],
      validator_signatures: [],
      qualification_digest: Array(32).fill(0xd5),
    },
  };
}

function qualifiedManifestPayload() {
  const payload = manifestPayload();
  payload.qualification = qualificationPayload();
  payload.protocols[1].readiness = {
    readiness: "production-qualified",
    detail: null,
  };
  return payload;
}

function manifestPayload() {
  const unavailable = {
    status: "unavailable",
    value: { reason: "engine-unavailable", detail: null },
  };
  const profile = availablePgcProfile();
  return {
    version: 1,
    committed_height: 42,
    consensus_policy: consensusPolicy(),
    qualification: null,
    protocols: PRIVACY_PROTOCOL_IDS_V1.map((protocolId, index) => {
      const active = protocolId === ACTIVE_PROTOCOL;
      const compiledProfile = active
        ? { status: "available", value: profile }
        : structuredClone(unavailable);
      const activation = active
        ? {
            ...structuredClone(profile),
            lifecycle: {
              state: "active",
              record: {
                proposed_at_height: 1,
                activated_at_height: 2,
                state_since_height: 2,
              },
            },
            pending_protocol_limits_tightening: null,
          }
        : null;
      const [operationSchema, executionMode, featureMask] = OPERATION_TUPLES[index];
      return {
        protocol_id: tagged(protocolId),
        operation_schema: { operation_schema: operationSchema, value: null },
        execution_mode: { execution_mode: executionMode, value: null },
        privacy_feature_mask: featureMask,
        compiled_profile: compiledProfile,
        readiness: active
          ? {
              readiness: "unavailable",
              detail: {
                reason: "missing-production-qualification",
                detail: null,
              },
            }
          : {
              readiness: "unavailable",
              detail: {
                reason: "compiled-profile",
                detail: structuredClone(unavailable.value),
              },
            },
        activation,
      };
    }),
    manifest_digest: Array(32).fill(0xa5),
  };
}

function sameBytes(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}


const TEST_MANIFEST_URL = "https://privacy.example.test/v1/privacy/capabilities";
function manifestResponse(body = ARCHIVE, init = {}, metadata = {}) {
  const response = new Response(body, {
    status: 200,
    headers: { "content-type": "application/x-norito" },
    ...init,
  });
  return {
    body: response.body, headers: response.headers, status: response.status,
    statusText: response.statusText,
    url: metadata.url ?? TEST_MANIFEST_URL,
    redirected: metadata.redirected ?? false,
  };
}
async function fetchTestManifest() {
  return getPrivacyExact12CapabilityManifestV1(new ToriiClient("https://privacy.example.test", {
    localSigningContext: TEST_LOCAL_SIGNING_CONTEXT,
    fetchImpl: async () => manifestResponse(),
  }), { canonicalAuth: TEST_CANONICAL_AUTH });
}

function fakeNative(payload = manifestPayload(), overrides = {}) {
  return {
    connectNoritoBridgeAbiVersion: () => 30,
    privacyCompiledProfileCatalogV1: () => Uint8Array.from(CATALOG),
    privacyValidateCompiledProfileCatalogV1: (bytes) =>
      sameBytes(bytes, CATALOG) ? 0 : 8,
    privacyValidateExact12CapabilityManifestV1: (bytes) =>
      sameBytes(bytes, ARCHIVE) ? 0 : 7,
    privacyExact12CapabilityManifestJsonV1: (bytes) => {
      if (!sameBytes(bytes, ARCHIVE)) throw new Error("noncanonical archive");
      return JSON.stringify(payload);
    },
    privacyRequireExact12CapabilityTupleV1: (bytes, protocolId, expectedNetworkId) => {
      if (!sameBytes(bytes, ARCHIVE) || protocolId !== ACTIVE_PROTOCOL
          || !sameBytes(expectedNetworkId, TEST_LOCAL_SIGNING_CONTEXT.networkId.toBytes())) {
        throw new Error("tuple mismatch");
      }
      return true;
    },
    ...overrides,
  };
}

async function withNative(native, callback) {
  const previous = globalThis[TEST_NATIVE_BINDING];
  globalThis[TEST_NATIVE_BINDING] = native;
  try {
    return await callback();
  } finally {
    if (previous === undefined) {
      delete globalThis[TEST_NATIVE_BINDING];
    } else {
      globalThis[TEST_NATIVE_BINDING] = previous;
    }
  }
}

test("mutable global bindings cannot authorize Exact12 native admission", () => {
  let fakeCalls = 0;
  const fake = fakeNative(manifestPayload(), {
    privacyCompiledProfileCatalogV1: () => {
      fakeCalls += 1;
      return Uint8Array.from(CATALOG);
    },
  });
  const previous = globalThis.__IROHA_NATIVE_BINDING__;
  globalThis.__IROHA_NATIVE_BINDING__ = fake;
  try {
    try {
      productionPrivacyCapabilities.compiledProfileCatalogV1();
    } catch (error) {
      assert.ok(error instanceof Error);
    }
    assert.equal(fakeCalls, 0, "mutable global binding was consulted");
  } finally {
    if (previous === undefined) {
      delete globalThis.__IROHA_NATIVE_BINDING__;
    } else {
      globalThis.__IROHA_NATIVE_BINDING__ = previous;
    }
  }
});

test("browser Exact12 exports fail closed even when a fake global binding exists", () => {
  let fakeCalls = 0;
  const previous = globalThis.__IROHA_NATIVE_BINDING__;
  globalThis.__IROHA_NATIVE_BINDING__ = fakeNative(manifestPayload(), {
    privacyCompiledProfileCatalogV1: () => {
      fakeCalls += 1;
      return Uint8Array.from(CATALOG);
    },
  });
  try {
    assert.throws(
      () => browserSubject.compiledProfileCatalogV1(),
      /no browser or mock fallback is permitted/u,
    );
    assert.equal(fakeCalls, 0, "browser facade consulted a mutable global binding");
  } finally {
    if (previous === undefined) {
      delete globalThis.__IROHA_NATIVE_BINDING__;
    } else {
      globalThis.__IROHA_NATIVE_BINDING__ = previous;
    }
  }
});

test("canonical decoder preserves immutable bytes and the closed Exact12 mapping", async () => {
  await withNative(fakeNative(), () => {
    const input = Uint8Array.from(ARCHIVE);
    const manifest = decodePrivacyExact12CapabilityManifestV1(input);
    input[0] ^= 0xff;
    assert.ok(manifest instanceof PrivacyExact12CapabilityManifestV1);
    assert.equal(manifest.version, 1);
    assert.equal(manifest.committed_height, 42n);
    assert.equal(manifest.qualification, null);
    assert.deepEqual(manifest.canonicalBytes(), ARCHIVE);
    const returned = manifest.canonicalBytes();
    returned[0] ^= 0xff;
    assert.deepEqual(manifest.canonicalBytes(), ARCHIVE);
    assert.equal(Object.isFrozen(manifest), true);
    assert.equal(Object.isFrozen(manifest.protocols), true);
    assert.deepEqual(
      manifest.protocols.map((row) => [
        row.protocol_id.protocol,
        row.operation_schema.operation_schema,
        row.execution_mode.execution_mode,
        row.privacy_feature_mask,
      ]),
      PRIVACY_PROTOCOL_IDS_V1.map((protocol, index) => [
        protocol,
        ...OPERATION_TUPLES[index],
      ]),
    );
    assert.deepEqual(Object.keys(manifest.protocols[0]), [
      "protocol_id",
      "operation_schema",
      "execution_mode",
      "privacy_feature_mask",
      "compiled_profile",
      "readiness",
      "activation",
    ]);
    assert.deepEqual(manifest.protocols[0].readiness, {
      readiness: "unavailable",
      detail: {
        reason: "compiled-profile",
        detail: { reason: "engine-unavailable", detail: null },
      },
    });
    assert.deepEqual(manifest.protocols[1].readiness, {
      readiness: "unavailable",
      detail: {
        reason: "missing-production-qualification",
        detail: null,
      },
    });
  });
});

test("privacy consensus maxima match Rust transport fixtures and reject one over", async () => {
  const limits = JSON.parse(readFileSync(new URL(
    "../../../fixtures/zk/signed_attachments_v1/vectors.json", import.meta.url,
  ), "utf8")).privacy_frame_limits;
  await withNative(fakeNative(), () => {
    const policy = decodePrivacyExact12CapabilityManifestV1(ARCHIVE).consensus_policy.current_limits;
    assert.equal(policy.max_proof_bytes_per_action, 9_437_184);
    assert.equal(policy.max_action_bytes, limits.envelope_bytes);
    assert.equal(policy.max_privacy_bytes_per_transaction, limits.envelope_bytes);
    assert.equal(policy.max_privacy_bytes_per_block, limits.block_privacy_bytes);
  });
  for (const key of ["max_action_bytes", "max_privacy_bytes_per_transaction", "max_privacy_bytes_per_block"]) {
    const payload = manifestPayload();
    payload.consensus_policy.current_limits[key] += 1;
    await withNative(fakeNative(payload), () => {
      assert.throws(() => decodePrivacyExact12CapabilityManifestV1(ARCHIVE), /hard maximum/u);
    });
  }
});

test("only authenticated transport grants admission; archived qualified evidence remains inspection-only", async () => {
  await withNative(fakeNative(qualifiedManifestPayload()), async () => {
    const archived = decodePrivacyExact12CapabilityManifestV1(ARCHIVE);
    assert.throws(() => requirePrivacyExact12CapabilityAdmissionV1(archived, ACTIVE_PROTOCOL), /authenticated Torii-origin/u);
    const manifest = await fetchTestManifest();
    assert.equal(Object.isFrozen(manifest.qualification), true);
    assert.equal(Object.isFrozen(manifest.qualification.release_manifest), true);
    assert.deepEqual(manifest.protocols[1].readiness, {
      readiness: "production-qualified",
      detail: null,
    });
    const admission = requirePrivacyExact12CapabilityAdmissionV1(
      manifest,
      ACTIVE_PROTOCOL,
    );
    assert.equal(admission.readiness, "production-qualified");
    assert.equal(admission.protocol_id, ACTIVE_PROTOCOL);
    assert.deepEqual(admission.network_id, Array.from(TEST_LOCAL_SIGNING_CONTEXT.networkId.toBytes()));
    assert.equal(admission.torii_origin, "https://privacy.example.test");
    const replayedArchive = decodePrivacyExact12CapabilityManifestV1(manifest.canonicalBytes());
    assert.throws(() => requirePrivacyExact12CapabilityAdmissionV1(replayedArchive, ACTIVE_PROTOCOL), /authenticated Torii-origin/u);
  });
});

test("qualification tuple drift derives unavailable and never reaches native admission", async () => {
  const payload = qualifiedManifestPayload();
  payload.qualification.release_manifest.protocols[1].parameter_digest[0] ^= 1;
  payload.protocols[1].readiness = {
    readiness: "unavailable",
    detail: {
      reason: "invalid-production-qualification",
      detail: null,
    },
  };
  let admissionCalls = 0;
  await withNative(fakeNative(payload, {
    privacyRequireExact12CapabilityTupleV1: () => {
      admissionCalls += 1;
      return true;
    },
  }), async () => {
    const manifest = await fetchTestManifest();
    assert.deepEqual(manifest.protocols[1].readiness, payload.protocols[1].readiness);
    assert.throws(
      () => requirePrivacyExact12CapabilityAdmissionV1(manifest, ACTIVE_PROTOCOL),
      /not production-qualified/u,
    );
    assert.equal(admissionCalls, 0);
  });
});

test("native canonical status rejects truncation, suffixes, and text shells", async () => {
  await withNative(fakeNative(), () => {
    for (const hostile of [
      ARCHIVE.slice(0, -1),
      Uint8Array.from([...ARCHIVE, 0]),
      new TextEncoder().encode("digest-shell"),
    ]) {
      assert.throws(
        () => decodePrivacyExact12CapabilityManifestV1(hostile),
        PrivacyExact12CapabilityManifestError,
      );
    }
    assert.throws(
      () => decodePrivacyExact12CapabilityManifestV1("NRT0"),
      /must be canonical Norito bytes/u,
    );
  });
});

test("projection substitutions fail even behind a lying JSON projection helper", async () => {
  const cases = [
    (value) => { value.protocols.reverse(); },
    (value) => { value.protocols[0].operation_schema.operation_schema = "pq_masp_note_action_v1"; },
    (value) => { value.protocols[0].privacy_feature_mask = 31; },
    (value) => { value.protocols[0].readiness = { readiness: "available", detail: null }; },
    (value) => { value.protocols[0].readiness = { readiness: "available-experimental", detail: null }; },
    (value) => { value.protocols[0].readiness = { readiness: "production-qualified", detail: null }; },
    (value) => {
      value.protocols[0].readiness = {
        readiness: "unavailable",
        detail: { reason: "engine-unavailable", detail: null },
      };
    },
    (value) => { value.protocols[0].activation_state = { activation_state: "not-registered", detail: null }; },
    (value) => { value.protocols[6].limitation = null; },
    (value) => {
      value.protocols[1].activation.assurance = {
        assurance: "experimental",
        value: null,
      };
      value.protocols[1].activation.production_qualification = null;
    },
    (value) => { value.manifest_digest = Array(32).fill(0); },
    (value) => { value.unknown = true; },
  ];
  for (const mutate of cases) {
    const payload = manifestPayload();
    mutate(payload);
    await withNative(fakeNative(payload), () => {
      assert.throws(
        () => decodePrivacyExact12CapabilityManifestV1(ARCHIVE),
        /Exact12 capability manifest/u,
      );
    });
  }
});

test("unavailable readiness preserves exact registration and lifecycle reasons", async () => {
  const cases = [
    ["not-registered", null],
    [
      "proposed",
      {
        state: "proposed",
        record: { proposed_at_height: 1 },
      },
    ],
    [
      "suspended",
      {
        state: "suspended",
        record: {
          proposed_at_height: 1,
          activated_at_height: 2,
          state_since_height: 3,
        },
      },
    ],
    [
      "retired",
      {
        state: "retired",
        record: {
          proposed_at_height: 1,
          activated_at_height: 2,
          state_since_height: 3,
        },
      },
    ],
  ];
  for (const [reason, lifecycle] of cases) {
    const payload = manifestPayload();
    const row = payload.protocols[1];
    if (lifecycle === null) {
      row.activation = null;
    } else {
      row.activation.lifecycle = lifecycle;
    }
    row.readiness = {
      readiness: "unavailable",
      detail: { reason, detail: null },
    };
    await withNative(fakeNative(payload), () => {
      const manifest = decodePrivacyExact12CapabilityManifestV1(ARCHIVE);
      assert.deepEqual(manifest.protocols[1].readiness, row.readiness);
    });
  }
});

test("pending tightening accepts next block and rejects invalid snapshot heights", async () => {
  for (const kind of ["consensus", "protocol"]) {
    for (const [scheduled, effective, committed, accepted] of [
      [42, 43, 42, true],
      [42, 44, 42, true],
      ["18446744073709551614", "18446744073709551615", "18446744073709551614", true],
      [0, 43, 42, false],
      [42, 42, 42, false],
      [42, 41, 42, false],
      [43, 44, 42, false],
      [42, 43, 43, false],
      ["18446744073709551615", "18446744073709551615", "18446744073709551615", false],
      ["18446744073709551615", "18446744073709551616", "18446744073709551615", false],
    ]) {
      const payload = manifestPayload();
      payload.committed_height = committed;
      const pending = { scheduled_at_height: scheduled, effective_at_height: effective };
      if (kind === "consensus") {
        pending.next_limits = { ...payload.consensus_policy.current_limits, retained_root_count: 1024 };
        payload.consensus_policy.pending_tightening = pending;
      } else {
        const row = payload.protocols[1];
        pending.next_limits = {
          protocol: ACTIVE_PROTOCOL,
          limits: { max_anonymity_set_size: 32, max_recipient_count: 8 },
        };
        row.activation.pending_protocol_limits_tightening = pending;
      }
      // Native JSON carries uint64 values as integer tokens, never quoted strings.
      const native = fakeNative(payload, {
        privacyExact12CapabilityManifestJsonV1: () =>
          JSON.stringify(payload).replace(
            /"(committed_height|scheduled_at_height|effective_at_height)":"([0-9]+)"/gu,
            '"$1":$2',
          ),
      });
      await withNative(native, () => {
        if (accepted) {
          const manifest = decodePrivacyExact12CapabilityManifestV1(ARCHIVE);
          const actual = kind === "consensus"
            ? manifest.consensus_policy.pending_tightening
            : manifest.protocols[1].activation.pending_protocol_limits_tightening;
          assert.equal(actual.effective_at_height, BigInt(effective));
          assert.throws(() => requirePrivacyExact12CapabilityAdmissionV1(manifest, ACTIVE_PROTOCOL));
        } else {
          assert.throws(() => decodePrivacyExact12CapabilityManifestV1(ARCHIVE), PrivacyExact12CapabilityManifestError);
        }
      });
    }
  }
});

test("proposed remains pending at later heights until explicit activation", async () => {
  for (const committedHeight of [1, 42, 4_000]) {
    const payload = manifestPayload();
    payload.committed_height = committedHeight;
    const row = payload.protocols[1];
    row.activation.lifecycle = { state: "proposed", record: { proposed_at_height: 1 } };
    row.readiness = { readiness: "unavailable", detail: { reason: "proposed", detail: null } };
    await withNative(fakeNative(payload), () => {
      const manifest = decodePrivacyExact12CapabilityManifestV1(ARCHIVE);
      assert.deepEqual(manifest.protocols[1].activation.lifecycle.record, { proposed_at_height: 1n });
      assert.deepEqual(manifest.protocols[1].readiness, row.readiness);
    });
    row.readiness = { readiness: "unavailable", detail: { reason: "missing-production-qualification", detail: null } };
    await withNative(fakeNative(payload), () => {
      assert.throws(() => decodePrivacyExact12CapabilityManifestV1(ARCHIVE), /Exact12 capability manifest/u);
    });
  }
});

test("same-height activation preserves history and qualification requirements", async () => {
  for (const [state, since, reason] of [
    ["active", 1, "missing-production-qualification"],
    ["suspended", 2, "suspended"],
    ["retired", 2, "retired"],
  ]) {
    const payload = manifestPayload();
    const row = payload.protocols[1];
    row.activation.lifecycle = {
      state,
      record: { proposed_at_height: 1, activated_at_height: 1, state_since_height: since },
    };
    row.readiness = { readiness: "unavailable", detail: { reason, detail: null } };
    await withNative(fakeNative(payload), () => {
      const manifest = decodePrivacyExact12CapabilityManifestV1(ARCHIVE);
      assert.equal(manifest.protocols[1].activation.lifecycle.record.activated_at_height, 1n);
      assert.deepEqual(manifest.protocols[1].readiness, row.readiness);
    });
  }
});

test("explicit activation rejects scheduled fields and reversed or future history", async () => {
  const cases = [
    { state: "proposed", record: { proposed_at_height: 1, activate_at_height: 43 } },
    { state: "proposed", record: {} },
    { state: "proposed", record: { proposed_at_height: 0 } },
    { state: "proposed", record: { proposed_at_height: 43 } },
    { state: "active", record: { proposed_at_height: 2, activated_at_height: 1, state_since_height: 2 } },
    { state: "active", record: { proposed_at_height: 1, activated_at_height: 2, state_since_height: 1 } },
    { state: "active", record: { proposed_at_height: 1, activated_at_height: 43, state_since_height: 43 } },
    { state: "suspended", record: { proposed_at_height: 1, activated_at_height: 1, state_since_height: 1 } },
    { state: "retired", record: { proposed_at_height: 1, activated_at_height: 1, state_since_height: 1 } },
    { state: "retired", record: { proposed_at_height: 1, activated_at_height: null, state_since_height: 1 } },
  ];
  for (const lifecycle of cases) {
    const payload = manifestPayload();
    const row = payload.protocols[1];
    row.activation.lifecycle = lifecycle;
    const reason = lifecycle.state === "active" ? "missing-production-qualification" : lifecycle.state;
    row.readiness = { readiness: "unavailable", detail: { reason, detail: null } };
    await withNative(fakeNative(payload), () => {
      assert.throws(() => decodePrivacyExact12CapabilityManifestV1(ARCHIVE), /Exact12 capability manifest/u);
    });
  }
});

test("admission rejects active rows without registered production qualification", async () => {
  let nativeAdmissionCalls = 0;
  await withNative(fakeNative(manifestPayload(), {
    privacyRequireExact12CapabilityTupleV1: () => {
      nativeAdmissionCalls += 1;
      return true;
    },
  }), async () => {
    const manifest = await fetchTestManifest();
    assert.throws(
      () => requirePrivacyExact12CapabilityAdmissionV1(
        manifest,
        ACTIVE_PROTOCOL,
      ),
      /not production-qualified/u,
    );
    assert.equal(nativeAdmissionCalls, 0);
    for (const retired of [
      "jindo-lattice-pcs-zk-v0",
      "sis-with-hints",
      "zk-ams-recursive-admission-v0",
    ]) {
      assert.throws(
        () => requirePrivacyExact12CapabilityAdmissionV1(manifest, retired),
        /retained Exact12 identifier/u,
      );
    }
  });
});

test("legacy snapshot exports and caller-created shells are rejected", async () => {
  for (const name of [
    "getPrivacyCapabilitiesV1",
    "parsePrivacyCapabilitySnapshotV1",
    "PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1",
    "PrivacyCapabilitySnapshotError",
  ]) {
    assert.equal(Object.hasOwn(authenticatedTestSubject, name), false, name);
  }
  await withNative(fakeNative(), () => {
    assert.throws(
      () => new PrivacyExact12CapabilityManifestV1(),
      /no public constructor/u,
    );
    assert.throws(
      () => requirePrivacyExact12CapabilityAdmissionV1({
        manifest_digest: Array(32).fill(0xa5),
      }, ACTIVE_PROTOCOL),
      /authenticated Torii-origin/u,
    );
  });
});

test("N-API Torii fetch requests exact bounded Norito and browser fallback is absent", async () => {
  await withNative(fakeNative(), async () => {
    const calls = [];
    const node = new ToriiClient("https://privacy.example.test", {
      localSigningContext: TEST_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return manifestResponse();
      },
    });
    const manifest = await getPrivacyExact12CapabilityManifestV1(node, {
      canonicalAuth: TEST_CANONICAL_AUTH,
    });
    assert.equal(manifest.committed_height, 42n);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://privacy.example.test/v1/privacy/capabilities");
    assert.equal(new Headers(calls[0].init.headers).get("accept"), "application/x-norito");
    assert.equal(calls[0].init.redirect, "error");
    assert.equal(calls[0].init.cache, "no-store");
    assert.equal(new Headers(calls[0].init.headers).get("cache-control"), "no-store");

    const legacyJsonNode = new ToriiClient("https://privacy.example.test", {
      localSigningContext: TEST_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async () => manifestResponse(JSON.stringify({
        version: 1,
        committed_height: 42,
        consensus_policy: consensusPolicy(),
        protocols: [],
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    });
    await assert.rejects(
      getPrivacyExact12CapabilityManifestV1(legacyJsonNode, {
        canonicalAuth: TEST_CANONICAL_AUTH,
      }),
      /must use exactly application\/x-norito/u,
    );

    let browserCalls = 0;
    const browser = new ToriiBrowserClient("https://privacy.example.test", {
      fetchImpl: async () => {
        browserCalls += 1;
        throw new Error("must not fetch");
      },
    });
    await assert.rejects(
      getPrivacyExact12CapabilityManifestV1(browser),
      /browser and mock transports cannot authorize privacy/u,
    );
    assert.equal(browserCalls, 0);
  });
});


test("forged symbol transports, other-network archives and insecure response origins reject", async () => {
  await withNative(fakeNative(qualifiedManifestPayload()), async () => {
    let forgedCalls = 0;
    const forged = {};
    for (const key of Object.getOwnPropertySymbols(ToriiClient.prototype)) {
      forged[key] = async () => { forgedCalls += 1; return ARCHIVE; };
    }
    await assert.rejects(getPrivacyExact12CapabilityManifestV1(forged, { canonicalAuth: TEST_CANONICAL_AUTH }), /N-API Torii client/u);
    assert.equal(forgedCalls, 0);
    for (const [baseUrl, context, metadata, error] of [
      ["http://privacy.example.test", TEST_LOCAL_SIGNING_CONTEXT, {}, /HTTPS/u],
      ["https://privacy.example.test", undefined, {}, /NetworkId|networkId/u],
      ["https://privacy.example.test", new LocalSigningContext(NetworkId.fromBytes(Buffer.alloc(32, 0xd1)), 753), {}, /different network/u],
      ["https://privacy.example.test", TEST_LOCAL_SIGNING_CONTEXT, {url: "https://other.example.test/v1/privacy/capabilities"}, /exact authenticated URL/u],
      ["https://privacy.example.test", TEST_LOCAL_SIGNING_CONTEXT, {redirected: true}, /exact authenticated URL/u],
    ]) {
      const client = new ToriiClient(baseUrl, {localSigningContext: context, fetchImpl: async () => manifestResponse(ARCHIVE, {}, metadata)});
      await assert.rejects(getPrivacyExact12CapabilityManifestV1(client, {canonicalAuth: TEST_CANONICAL_AUTH}), error);
    }
  });
});


test("transport origin never substitutes for native tuple or network validation", async () => {
  for (const result of [false, "true", null]) {
    await withNative(fakeNative(qualifiedManifestPayload(), {
      privacyRequireExact12CapabilityTupleV1: () => result,
    }), async () => {
      const manifest = await fetchTestManifest();
      assert.throws(() => requirePrivacyExact12CapabilityAdmissionV1(manifest, ACTIVE_PROTOCOL), /sole success value/u);
    });
  }
  await withNative(fakeNative(qualifiedManifestPayload(), {
    privacyRequireExact12CapabilityTupleV1: () => { throw new Error("native network or tuple mismatch"); },
  }), async () => {
    const manifest = await fetchTestManifest();
    assert.throws(() => requirePrivacyExact12CapabilityAdmissionV1(manifest, ACTIVE_PROTOCOL), /native/u);
  });
});

test("unreadable transport origin is rejected without invoking getters and cancels its body", async () => {
  await withNative(fakeNative(), async () => {
    let getterCalls = 0;
    let cancellations = 0;
    const response = manifestResponse();
    response.body = new ReadableStream({ cancel() { cancellations += 1; } });
    Object.defineProperty(response, "url", {
      get() { getterCalls += 1; throw new Error("untrusted origin getter"); },
    });
    const client = new ToriiClient("https://privacy.example.test", {
      localSigningContext: TEST_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async () => response,
    });
    await assert.rejects(getPrivacyExact12CapabilityManifestV1(client, {
      canonicalAuth: TEST_CANONICAL_AUTH,
    }), /URL must be an own data property/u);
    assert.equal(getterCalls, 0);
    assert.equal(cancellations, 1);
  });
});

test("Exact12 transport ignores mutable client and static normalization overrides", async () => {
  await withNative(fakeNative(qualifiedManifestPayload()), async () => {
    let fetchCalls = 0;
    let overrideCalls = 0;
    const client = new ToriiClient("https://privacy.example.test", {
      localSigningContext: TEST_LOCAL_SIGNING_CONTEXT,
      fetchImpl: async (_url, init) => {
        fetchCalls += 1;
        assert.ok(Object.keys(init.headers).some((name) => name.toLowerCase() === "x-iroha-signature"));
        return manifestResponse();
      },
    });
    const failOverride = () => { overrideCalls += 1; throw new Error("mutable client override reached"); };
    for (const name of ["_request", "_createHeaders", "_expectStatus", "_getHeader", "_readBoundedResponseBytes"]) {
      client[name] = failOverride;
    }
    const originalAuth = ToriiClient._normalizeCanonicalAuth;
    const originalKey = ToriiClient._normalizePrivateKey;
    ToriiClient._normalizeCanonicalAuth = failOverride;
    ToriiClient._normalizePrivateKey = failOverride;
    try {
      const manifest = await getPrivacyExact12CapabilityManifestV1(client, {
        canonicalAuth: TEST_CANONICAL_AUTH,
      });
      requirePrivacyExact12CapabilityAdmissionV1(manifest, ACTIVE_PROTOCOL);
      assert.equal(fetchCalls, 1);
      assert.equal(overrideCalls, 0);
    } finally {
      ToriiClient._normalizeCanonicalAuth = originalAuth;
      ToriiClient._normalizePrivateKey = originalKey;
    }
  });
});


test("privacy STARK capability bindings reject a different outer suite", async () => {
  for (const [key, field, label] of [
    ["proof_system_id", "proof_system", "stark-fri-poseidon-x7-goldilocks-6x64-v1"],
    ["engine_id", "engine", "native-goldilocks-poseidon-x7-stark-fri-6x64-v1"],
  ]) {
    const payload = qualifiedManifestPayload();
    payload.qualification.release_manifest.protocols[0][key][field] = label;
    await withNative(fakeNative(payload), async () => {
      assert.throws(() => decodePrivacyExact12CapabilityManifestV1(ARCHIVE), PrivacyExact12CapabilityManifestError);
    });
  }
});
