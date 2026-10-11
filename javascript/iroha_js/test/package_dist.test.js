"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { build as buildWithEsbuild } from "esbuild";

import * as packageExports from "../dist/index.js";
import * as packageTransactionExports from "../dist/transaction.js";
import * as packageCryptoExports from "../dist/public/crypto.js";
import { NexusAppClient as PackageNexusAppClient } from "../dist/nexusApp.js";
import * as packagePrivacyCapabilitiesExports from "../dist/privacyCapabilities.js";
import { _createCryptoApi } from "../dist/crypto.js";
import { createNativeRuntime } from "../dist/nativeRuntime.js";
import {
  findForbiddenBrowserInputs,
  hasForbiddenGlobalBufferMutation,
} from "../scripts/bundle-size-check.mjs";

const packageRootUrl = new URL("../", import.meta.url);
const packageRootPath = fileURLToPath(packageRootUrl);
const RETIRED_STATIC_CRYPTO_CAPABILITY_LIST =
  ["SUPPORTED", "CRYPTO", "ALGORITHMS"].join("_");

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

const nexusFixture = JSON.parse(
  readFileSync(
    new URL("../../../fixtures/sdk/nexus_connect_transfer_v1.json", import.meta.url),
    "utf8",
  ),
);
const nexusFixtureNetworkId = packageExports.NetworkId.parse(
  nexusFixture.transfer_input.network_id,
);

const {
  PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES,
  PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1,
  PRIVACY_REQUIRED_BRIDGE_ABI_VERSION,
} = packageExports;

function withCryptoApi(binding, fn) {
  return fn(_createCryptoApi(createNativeRuntime(binding)));
}

function privacyNoritoFrame(schemaByte) {
  const frame = Buffer.alloc(40);
  frame.write("NRT0", 0, "ascii");
  frame.fill(schemaByte, 6, 22);
  return frame;
}

function privacyNoritoFrameWithPayload(schemaByte) {
  const frame = Buffer.concat([
    privacyNoritoFrame(schemaByte),
    Buffer.from([0x00, 0x00, 0xa5, 0x5a, 0x11]),
  ]);
  frame.writeBigUInt64LE(3n, 23);
  Buffer.from([0xb9, 0xd3, 0xa8, 0x0c, 0xcd, 0x5d, 0x13, 0x24]).copy(frame, 31);
  return frame;
}

function privacyNoritoFrameWithPadding(schemaByte, paddingLength) {
  const frame = Buffer.concat([
    privacyNoritoFrame(schemaByte),
    Buffer.alloc(paddingLength),
    Buffer.from([0xa5, 0x5a, 0x11]),
  ]);
  frame.writeBigUInt64LE(3n, 23);
  Buffer.from([0xb9, 0xd3, 0xa8, 0x0c, 0xcd, 0x5d, 0x13, 0x24]).copy(frame, 31);
  return frame;
}

function privacyNoritoFrameWithSchemaOverride(schemaByte, offset, value) {
  const frame = Buffer.from(privacyNoritoFrameWithPayload(schemaByte));
  frame[offset] = value;
  return frame;
}

function privacyNoritoFrameWithDeclaredPayloadLength(schemaByte, payloadLength) {
  const frame = Buffer.from(privacyNoritoFrameWithPayload(schemaByte));
  frame.writeBigUInt64LE(BigInt(payloadLength), 23);
  return frame;
}

function privacyNoritoFrameWithFlags(schemaByte, flags) {
  const frame = Buffer.from(privacyNoritoFrameWithPayload(schemaByte));
  frame[39] = flags;
  return frame;
}

function slicedPrivacyView(
  archive,
  prefix = [0xff, 0x7f, 0x42],
  suffix = [0x24, 0x13],
) {
  const backing = Uint8Array.from([...prefix, ...archive, ...suffix]);
  return backing.subarray(prefix.length, prefix.length + archive.length);
}

const PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE = privacyNoritoFrameWithPayload(0x50);
const VALID_PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVES = [
  PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE,
  privacyNoritoFrameWithPadding(0x50, 64),
  privacyNoritoFrameWithFlags(0x50, 0x02),
];

function validatePrivacyCompiledProfileCatalogFixture(archive) {
  const candidate = Buffer.from(archive);
  if (candidate.length === 0) {
    return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.EMPTY;
  }
  if (candidate.length > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES) {
    return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.ARCHIVE_TOO_LARGE;
  }
  if (
    candidate.length >= 22 &&
    candidate.subarray(6, 22).some((byte) => byte !== 0x50)
  ) {
    return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.SCHEMA_MISMATCH;
  }
  return VALID_PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVES.some((validArchive) =>
    candidate.equals(validArchive),
  )
    ? PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.VALID
    : PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.MALFORMED_ARCHIVE;
}

function malformedPrivacyNativeOutputArchives(schemaByte) {
  const archive = privacyNoritoFrameWithPayload(schemaByte);
  const badMagic = Buffer.from(archive);
  badMagic[0] = 0x00;
  const badVersion = Buffer.from(archive);
  badVersion[4] = 1;
  const badMinorVersion = Buffer.from(archive);
  badMinorVersion[5] = 1;
  const badCompression = Buffer.from(archive);
  badCompression[22] = 1;
  const badDeclaredPayloadLength = privacyNoritoFrameWithDeclaredPayloadLength(
    schemaByte,
    6n,
  );
  const badOversizedDeclaredPayloadLength = privacyNoritoFrameWithDeclaredPayloadLength(
    schemaByte,
    0x8000000000000000n,
  );
  const badPadding = Buffer.concat([archive, Buffer.from([0x7f])]);
  const badExcessivePadding = privacyNoritoFrameWithPadding(schemaByte, 65);
  const badFlags = Buffer.from(archive);
  badFlags[39] = 0x08;
  const badFieldBitsetFlags = Buffer.from(archive);
  badFieldBitsetFlags[39] = 0x20;
  const badPackedSeqFlags = Buffer.from(archive);
  badPackedSeqFlags[39] = 0x01;
  const badPackedStructFlags = Buffer.from(archive);
  badPackedStructFlags[39] = 0x04;
  const badCompactPackedStructFlags = Buffer.from(archive);
  badCompactPackedStructFlags[39] = 0x06;
  const badCompactFieldBitsetFlags = Buffer.from(archive);
  badCompactFieldBitsetFlags[39] = 0x26;
  const badChecksum = Buffer.from(archive);
  badChecksum[31] ^= 0x01;
  const badPayload = Buffer.from(archive);
  badPayload[44] ^= 0x7f;
  return [
    Buffer.from([1]),
    badMagic,
    badVersion,
    badMinorVersion,
    badCompression,
    badDeclaredPayloadLength,
    badOversizedDeclaredPayloadLength,
    badPadding,
    badExcessivePadding,
    badFlags,
    badFieldBitsetFlags,
    badPackedSeqFlags,
    badPackedStructFlags,
    badCompactPackedStructFlags,
    badCompactFieldBitsetFlags,
    badChecksum,
    badPayload,
  ];
}

function completePrivacyCompiledProfileCatalogBinding(overrides = {}) {
  return {
    connectNoritoBridgeAbiVersion() {
      return PRIVACY_REQUIRED_BRIDGE_ABI_VERSION;
    },
    privacyCompiledProfileCatalogV1() {
      return Uint8Array.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
    },
    privacyValidateCompiledProfileCatalogV1(archive) {
      return validatePrivacyCompiledProfileCatalogFixture(archive);
    },
    ...overrides,
  };
}

function captureThrown(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected function to throw");
}

function hexBytes(value) {
  return Uint8Array.from(
    value.match(/../gu),
    (octet) => Number.parseInt(octet, 16),
  );
}

function mockNexusResponse(status, body = "", headers = {}) {
  const encoded = new TextEncoder().encode(body);
  const normalizedHeaders = new Map(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]),
  );
  return {
    status,
    headers: {
      get(name) {
        return normalizedHeaders.get(String(name).toLowerCase()) ?? null;
      },
    },
    async arrayBuffer() {
      return encoded.buffer.slice(
        encoded.byteOffset,
        encoded.byteOffset + encoded.byteLength,
      );
    },
  };
}

test("package dist exposes the current general-purpose SDK entrypoint", () => {
  for (const name of [
    "AccountAddress",
    "NetworkId",
    "ToriiClient",
    "ToriiBrowserClient",
    "buildTransaction",
    "buildCancelAssetLockInstruction",
    "buildSetAssetTransferAvailabilityInstruction",
    "buildSetAssetTransferBlacklistInstruction",
    "buildSetAssetTransferControlInstruction",
    "CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1",
    "encodeCancelAssetLockV1",
    "decodeCancelAssetLockV1",
    "validateAppealFinanceCancelAssetLock",
    "computeValidationFeePayoutLifecycleProposalFingerprintV1",
    "computeValidationFeePolicyProposalFingerprintV1",
    "noritoEncodeInstruction",
    "privacyCompiledProfileCatalogV1",
  ]) {
    assert.notEqual(packageExports[name], undefined, `${name} is exported`);
  }
});

test("package dist exposes both final Kaigi proof generators through root and crypto", () => {
  for (const surface of [packageExports, packageCryptoExports]) {
    assert.equal(typeof surface.buildKaigiAuthorizationProofV1, "function");
    assert.equal(typeof surface.buildKaigiUsageProofV1, "function");
    assert.equal("buildKaigiRosterJoinProof" in surface, false);
  }
});

test("package dist does not expose Private Kaigi fee proof synthesis", () => {
  for (const [surface, exports] of [
    ["root", packageExports],
    ["transaction", packageTransactionExports],
  ]) {
    assert.equal(
      Object.hasOwn(exports, "buildPrivateKaigiFeeSpend"),
      false,
      `${surface} must not expose fixture-backed fee proof synthesis`,
    );
  }
});

test("package dist quantity builders reject numbers and noncanonical strings", () => {
  assert.equal(typeof packageExports.NumericV1?.decodeQuantityJson, "function");
  assert.equal(typeof packageExports.KotodamaQuantity, "function");
  const account = packageExports.AccountAddress.fromAccount({
    publicKey: Buffer.from(
      "5866666666666666666666666666666666666666666666666666666666666666",
      "hex",
    ),
  }).toI105();
  const assetId = `62Fk4FPcMuLvW5QjDGNF2a4jAmjM#${account}`;
  for (const quantity of [
    1,
    -1,
    "-1",
    "+1",
    "01",
    "1.0",
    "1.2300",
    "1amt",
    "1qty",
    " 1",
    "1e0",
    1n << 511n,
  ]) {
    assert.throws(
      () => packageExports.buildMintAssetInstruction({ assetId, quantity }),
      /canonical|JavaScript numbers/u,
    );
  }
  assert.equal(
    packageExports.buildMintAssetInstruction({ assetId, quantity: 1n }).Mint.Asset.object,
    "1",
  );
  assert.equal(
    packageExports.buildMintAssetInstruction({ assetId, quantity: "1.25" }).Mint.Asset.object,
    "1.25",
  );
});

test("package dist exposes strict CancelAssetLock V1 construction", () => {
  assert.equal(
    packageExports.CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1,
    4_096,
  );
  assert.deepEqual(
    packageExports.buildCancelAssetLockInstruction({
      lockId: "merchant-lock-001",
      expectedRemainingAmount: "1500",
    }),
    {
      CancelAssetLock: {
        escrow_id:
          "hash:996264C84790C64086AAB0EF693A1D33EC18FC0B1C1229774C461A00939A6687#F2BD",
        expected_remaining_amount: "1500",
      },
    },
  );
  assert.throws(
    () =>
      packageExports.buildCancelAssetLockInstruction({
        lockId: "merchant-lock-001",
        expectedRemainingAmount: 1500,
      }),
    /JavaScript numbers/u,
  );
  const exactBound = "🔒".repeat(1_024);
  assert.doesNotThrow(() =>
    packageExports.buildCancelAssetLockInstruction({
      lockId: exactBound,
      expectedRemainingAmount: "1",
    }),
  );
  assert.throws(
    () =>
      packageExports.buildCancelAssetLockInstruction({
        lockId: `${exactBound}a`,
        expectedRemainingAmount: "1",
      }),
    /at most 4096 UTF-8 bytes/u,
  );
});

test("package dist requires a typed NetworkId in validation-fee ledger bindings", () => {
  const binding = {
    schema: "iroha.validation-fee-ledger-binding.v1",
    networkId: Buffer.from("13".repeat(32), "hex"),
    policyChainGenesisHash: "35".repeat(32),
    checkpoint: { checkpointNorito: Buffer.from([100, 57]) },
  };
  assert.throws(
    () => packageExports.normalizeValidationFeeLedgerBindingV1(binding),
    /must be a NetworkId/u,
  );
});

test("package publishes the exact general-purpose subpath inventory", () => {
  assert.deepEqual(Object.keys(packageJson.exports).sort(), [
    ".",
    "./address",
    "./atomic-private-settlement",
    "./blake2b",
    "./bootle-lantern-issuance",
    "./browser",
    "./canonical-request",
    "./classed-race",
    "./connect-browser",
    "./contract-payload",
    "./crypto",
    "./game",
    "./instruction-builders",
    "./ivm-artifact",
    "./kotodama-compiler",
    "./nexus-app",
    "./nft",
    "./norito",
    "./normalizers",
    "./petal",
    "./privacy-capabilities",
    "./race",
    "./smart-contract-deployment",
    "./sorafs",
    "./sumeragi-typed",
    "./torii",
    "./torii-browser",
    "./transaction-codec",
  ]);
});

test("package publishes the typed Sumeragi parser through its lazy subpath", () => {
  assert.deepEqual(packageJson.exports["./sumeragi-typed"], {
    browser: "./dist/sumeragiTyped.js",
    import: "./dist/sumeragiTyped.js",
    types: "./sumeragi-typed.d.ts",
  });
});

test("package publishes the atomic private settlement client through one browser-safe subpath", () => {
  assert.deepEqual(packageJson.exports["./atomic-private-settlement"], {
    browser: "./dist/atomicPrivateSettlement.js",
    import: "./dist/atomicPrivateSettlement.js",
    types: "./atomic-private-settlement.d.ts",
  });
});

test("package privacy capability policy is isolated behind its explicit subpath", () => {
  assert.deepEqual(packageJson.exports["./privacy-capabilities"], {
    browser: "./dist/privacyCapabilities.js",
    import: "./dist/privacyCapabilities.js",
    types: "./privacy-capabilities.d.ts",
  });
  const optionalExports = [
    "compiledProfileCatalogV1",
    "decodePrivacyExact12CapabilityManifestV1",
    "getPrivacyExact12CapabilityManifestV1",
    "PRIVACY_EXACT12_CAPABILITY_MANIFEST_MAX_BYTES_V1",
    "PRIVACY_EXACT12_CAPABILITY_MANIFEST_VERSION_V1",
    "PRIVACY_PROTOCOL_IDS_V1",
    "PrivacyExact12CapabilityManifestError",
    "PrivacyExact12CapabilityManifestV1",
    "requirePrivacyExact12CapabilityAdmissionV1",
    "requirePrivacyExact12CapabilityTupleV1",
  ];
  assert.deepEqual(
    Object.keys(packagePrivacyCapabilitiesExports).sort(),
    optionalExports.slice().sort(),
  );
  for (const name of optionalExports) {
    assert.equal(Object.hasOwn(packageExports, name), false, `root export ${name}`);
    assert.notEqual(
      packagePrivacyCapabilitiesExports[name],
      undefined,
      `optional privacy export ${name}`,
    );
  }
  assert.equal(
    Object.hasOwn(packageExports.ToriiClient.prototype, "getPrivacyCapabilitiesV1"),
    false,
  );
  assert.equal(
    Object.hasOwn(packageExports.ToriiBrowserClient.prototype, "getPrivacyCapabilitiesV1"),
    false,
  );
});

test("package Nexus browser export has an enforced browser-only dependency graph", async () => {
  const configured = packageJson.exports["./nexus-app"];
  assert.deepEqual(configured, {
    browser: "./dist/nexusApp.js",
    import: "./dist/nexusApp.js",
    types: "./nexus-app.d.ts",
  });
  const result = await buildWithEsbuild({
    absWorkingDir: packageRootPath,
    entryPoints: [fileURLToPath(new URL(configured.browser.slice(2), packageRootUrl))],
    bundle: true,
    write: false,
    platform: "browser",
    target: "es2020",
    format: "esm",
    treeShaking: true,
    sourcemap: false,
    minify: true,
    metafile: true,
  });
  const inputs = Object.keys(result.metafile?.inputs ?? {});
  assert.deepEqual(findForbiddenBrowserInputs(inputs), []);
  const forbiddenProbe = [
    "node:crypto",
    "dist/crypto.js",
    "dist/cryptoHash.js",
    "dist/native.js",
    "dist/toriiClient.js",
  ];
  assert.deepEqual(findForbiddenBrowserInputs(forbiddenProbe), forbiddenProbe);
  assert.deepEqual(
    inputs.filter((input) => input.startsWith("dist/")).sort(),
    [
      "dist/address.js",
      "dist/addressErrors.js",
      "dist/addressPrimitives.js",
      "dist/blake2b.js",
      "dist/blockProofVerification.js",
      "dist/commonLiterals.js",
      "dist/connect.browser.js",
      "dist/contractAddress.js",
      "dist/contractDeclarations.js",
      "dist/contractErrorTypes.js",
      "dist/contractManifestRules.js",
      "dist/crc64Xz.js",
      "dist/cryptoAlgorithms.js",
      "dist/curveRegistry.js",
      "dist/domainId.js",
      "dist/ed25519Strict.js",
      "dist/entrypointSchema.js",
      "dist/governanceSelector.js",
      "dist/hashLiteralCrc.js",
      "dist/idnaBidi.js",
      "dist/kotodamaIdentifiers.js",
      "dist/kotodamaProducts.js",
      "dist/multisig.js",
      "dist/native.browser.js",
      "dist/nativeRuntime.js",
      "dist/networkId.js",
      "dist/networkPrefix.js",
      "dist/nexusApp.js",
      "dist/norito.js",
      "dist/noritoClassedRaceSchemas.js",
      "dist/noritoContractCodecs.js",
      "dist/noritoContractMetadata.js",
      "dist/noritoGameCodecs.js",
      "dist/noritoGameEngine.js",
      "dist/noritoGameInstructionCodecs.js",
      "dist/noritoGameRegistry.js",
      "dist/noritoGameResourceEngine.js",
      "dist/noritoGovernanceBoundary.js",
      "dist/noritoNftMarketCodecs.js",
      "dist/noritoRecordDecoder.js",
      "dist/noritoReplicationOrderValidator.js",
      "dist/noritoStakingCodecs.js",
      "dist/noritoValueCodecs.js",
      "dist/normalizers.js",
      "dist/numericV1.js",
      "dist/privacyExact12Network.js",
      "dist/proofAttachment.js",
      "dist/retailFeeAssessment.js",
      "dist/sorafsReplicationProfiles.js",
      "dist/strictLosslessJson.js",
      "dist/transactionCodec.js",
      "dist/validationError.js",
      "dist/validationThrow.js",
    ],
  );
  const output = result.outputFiles?.[0];
  assert.ok(output, "esbuild must produce the packaged Nexus browser bundle");
  assert.equal(hasForbiddenGlobalBufferMutation(output.text), false);
  for (const mutation of [
    "globalThis.Buffer = value",
    "Object.defineProperty(window, 'Buffer', { value })",
  ]) {
    assert.equal(hasForbiddenGlobalBufferMutation(mutation), true);
  }
});

test("package Nexus browser source and dist must remain exact", () => {
  assert.equal(
    readFileSync(new URL("../dist/nexusApp.js", import.meta.url), "utf8"),
    readFileSync(new URL("../src/nexusApp.js", import.meta.url), "utf8"),
    "Nexus browser source and dist must remain exact",
  );
});

test("package lazy browser chunks ship with exact source and dist parity", () => {
  for (const fileName of [
    "smartContractDeploymentSubmit.js",
    "sumeragiTyped.js",
  ]) {
    assert.equal(
      readFileSync(new URL(`../dist/${fileName}`, import.meta.url), "utf8"),
      readFileSync(new URL(`../src/${fileName}`, import.meta.url), "utf8"),
      `${fileName} source and dist must remain exact`,
    );
  }
});

test("package Nexus browser defaults build, finalize, and submit the shared canonical transfer", async () => {
  const submissions = [];
  const client = new PackageNexusAppClient({
    networkId: nexusFixtureNetworkId,
    chainDiscriminant: nexusFixture.transfer_input.account_chain_discriminant,
    authority: nexusFixture.transfer_input.authority,
    signingPublicKey: hexBytes(
      nexusFixture.connect.approval_frame.signing_public_key_hex,
    ),
    toriiBaseUrl: "https://torii.example",
    async fetchImpl(url, init) {
      submissions.push({ url, init, body: Uint8Array.from(init.body) });
      return mockNexusResponse(204);
    },
  });
  const draft = client.buildTransferDraft({
    sourceAssetHoldingId: nexusFixture.transfer_input.source_asset_id,
    quantity: nexusFixture.transfer_input.quantity,
    destinationAccountId: nexusFixture.transfer_input.destination_account_id,
    creationTimeMs: nexusFixture.transfer_input.creation_time_ms,
    ttlMs: nexusFixture.transfer_input.ttl_ms,
    nonce: nexusFixture.transfer_input.nonce,
    feePayment: {
      payer: nexusFixture.transfer_input.fee_payment.payer,
      chargeLimits: [...nexusFixture.transfer_input.fee_payment.value.charge_limits],
      gasLimit: nexusFixture.transfer_input.fee_payment.value.gas_limit,
    },
    metadata: nexusFixture.transfer_input.metadata,
  });
  assert.equal(draft.signable.payloadHashHex, nexusFixture.expected.payload_hash_hex);
  assert.deepEqual(
    Uint8Array.from(draft.signable.payloadBytes),
    hexBytes(nexusFixture.expected.payload_bytes_hex),
  );
  const receipt = await client.finalizeAndSubmit(
    draft.signable,
    hexBytes(nexusFixture.expected.wallet_signature_hex),
    { wait: false },
  );

  assert.equal(
    receipt.signedTransactionHashHex,
    nexusFixture.expected.signed_transaction_hash_hex,
  );
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].url, "https://torii.example/v1/pipeline/transactions");
  assert.equal(submissions[0].init.method, "POST");
  assert.equal(submissions[0].init.headers["Content-Type"], "application/x-norito");
  assert.equal(submissions[0].init.credentials, "omit");
  assert.equal(submissions[0].init.redirect, "error");
  assert.equal(submissions[0].init.referrerPolicy, "no-referrer");
  assert.deepEqual(submissions[0].body, Uint8Array.from(receipt.signedTransaction));
  assert.equal(submissions[0].body[0], 1);

  const tamperedSignature = hexBytes(nexusFixture.expected.wallet_signature_hex);
  tamperedSignature[0] ^= 0x01;
  await assert.rejects(
    client.finalizeAndSubmit(draft.signable, tamperedSignature, { wait: false }),
    (error) => error?.code === "invalid_signature",
  );
  assert.equal(submissions.length, 1, "invalid signatures must fail before Torii I/O");
});

test("package dist entrypoint exports only the canonical local privacy catalog bridge", () => {
  for (const name of ["isPrivacyNativeAvailable", "privacyCompiledProfileCatalogV1"]) {
    assert.equal(typeof packageExports[name], "function", `${name} must be exported`);
  }
  for (const retired of [
    "privacyCapabilitiesV1",
    "privacyProofRequestV1",
    "privacyBuildProofV1",
    "privacyVerifyProofV1",
    "buildZkAceTransferAuthorizationV1",
    "buildRegisterZkAceIdentityCommitmentInstruction",
    "buildRotateZkAceIdentityCommitmentInstruction",
    "buildRevokeZkAceIdentityCommitmentInstruction",
    "buildZkAceAuthorizationProofV1",
    "buildZkAceAuthorizedTransferInstruction",
  ]) {
    assert.equal(retired in packageExports, false, `${retired} must be retired`);
  }
  assert.equal(
    packageExports.PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES,
    256 * 1024,
  );
  assert.equal(Number.isInteger(PRIVACY_REQUIRED_BRIDGE_ABI_VERSION), true);
  for (const surface of [
    packageExports,
    packageExports.Crypto,
    packageCryptoExports,
  ]) {
    assert.equal("_createCryptoApi" in surface, false);
    assert.equal(RETIRED_STATIC_CRYPTO_CAPABILITY_LIST in surface, false);
  }
  assert.equal("_createTransactionApi" in packageExports, false);
  assert.equal("_createNoritoInstructionApi" in packageExports, false);
  assert.equal("_createNoritoInstructionApi" in packageExports.Norito, false);
});

test("package dist privacy native availability clears probed local catalog output", () => {
  const acceptedOutput = Buffer.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return acceptedOutput;
      },
    }),
    (crypto) => assert.equal(crypto.isPrivacyNativeAvailable(), true),
  );
  assert.deepEqual(
    acceptedOutput,
    Buffer.alloc(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE.length),
  );

  const rejectedOutput = Buffer.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  rejectedOutput[0] = 0x00;
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return rejectedOutput;
      },
      privacyValidateCompiledProfileCatalogV1() {
        return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.MALFORMED_ARCHIVE;
      },
    }),
    (crypto) => assert.equal(crypto.isPrivacyNativeAvailable(), false),
  );
  assert.deepEqual(
    rejectedOutput,
    Buffer.alloc(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE.length),
  );
});

test("package dist privacy availability admits the local compiled-profile catalog bridge", () => {
  let catalogCalls = 0;
  const binding = completePrivacyCompiledProfileCatalogBinding({
    privacyCompiledProfileCatalogV1() {
      catalogCalls += 1;
      return Uint8Array.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
    },
  });

  withCryptoApi(binding, (crypto) => {
    assert.equal(crypto.isPrivacyNativeAvailable(), true);
    assert.deepEqual(
      crypto.privacyCompiledProfileCatalogV1(),
      PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE,
    );
  });
  assert.equal(catalogCalls, 2);
  for (const retired of [
    "privacyCapabilitiesV1",
    "privacyProofRequestV1",
    "privacyBuildProofV1",
    "privacyVerifyProofV1",
  ]) {
    assert.equal(retired in binding, false);
    assert.equal(retired in packageExports, false);
  }
});

test("package dist privacy compiled-profile catalog wrapper sanitizes native exceptions", () => {
  const witness = "package-dist-private-witness-never-echo";
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        throw new Error("native panic included " + witness);
      },
    }),
    (crypto) => {
      const error = captureThrown(() => crypto.privacyCompiledProfileCatalogV1());
      assert.equal(error.message, "native privacyCompiledProfileCatalogV1 failed");
      assert.equal(error.cause, undefined);
      assert.equal(String(error).includes(witness), false);
      assert.equal(String(error.stack).includes(witness), false);
      assert.equal(crypto.isPrivacyNativeAvailable(), false);
    },
  );
});

test("package dist privacy compiled-profile catalog bridge rejects invalid ABI versions before dispatch", () => {
  for (const abiVersion of [
    PRIVACY_REQUIRED_BRIDGE_ABI_VERSION - 1,
    String(PRIVACY_REQUIRED_BRIDGE_ABI_VERSION),
    Number.NaN,
    Number.MAX_SAFE_INTEGER,
  ]) {
    let dispatched = false;
    withCryptoApi(
      completePrivacyCompiledProfileCatalogBinding({
        connectNoritoBridgeAbiVersion() {
          return abiVersion;
        },
        privacyCompiledProfileCatalogV1() {
          dispatched = true;
          return Uint8Array.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
        },
      }),
      (crypto) => {
        assert.equal(crypto.isPrivacyNativeAvailable(), false);
        assert.throws(
          () => crypto.privacyCompiledProfileCatalogV1(),
          /requires the iroha_js_host native binding built with privacy FFI support/u,
        );
      },
    );
    assert.equal(dispatched, false);
  }
});

test("package dist privacy compiled-profile catalog wrapper respects sliced native output views", () => {
  const prefixLength = 3;
  const backing = Uint8Array.from([
    0xff,
    0x7f,
    0x50,
    ...PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE,
    0x24,
  ]);
  let published;

  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return new DataView(
          backing.buffer,
          prefixLength,
          PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE.length,
        );
      },
    }),
    (crypto) => {
      published = crypto.privacyCompiledProfileCatalogV1();
    },
  );

  assert.deepEqual(published, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  assert.equal(backing[0], 0xff);
  assert.equal(backing.at(-1), 0x24);
  backing[prefixLength] = 0x00;
  assert.deepEqual(published, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
});

test("package dist privacy compiled-profile catalog wrapper accepts maximum Norito header padding", () => {
  const paddedArchive = privacyNoritoFrameWithPadding(0x50, 64);
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return Buffer.from(paddedArchive);
      },
    }),
    (crypto) => assert.deepEqual(crypto.privacyCompiledProfileCatalogV1(), paddedArchive),
  );
});

test("package dist privacy compiled-profile catalog wrapper accepts compact-length header flags", () => {
  const flaggedArchive = privacyNoritoFrameWithFlags(0x50, 0x02);
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return Buffer.from(flaggedArchive);
      },
    }),
    (crypto) => assert.deepEqual(crypto.privacyCompiledProfileCatalogV1(), flaggedArchive),
  );
});

test("package dist privacy compiled-profile catalog wrapper defensively copies native output", () => {
  const nativeOutput = Buffer.from(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  let published;

  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return nativeOutput;
      },
    }),
    (crypto) => {
      published = crypto.privacyCompiledProfileCatalogV1();
    },
  );

  assert.notEqual(published, nativeOutput);
  assert.deepEqual(published, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  published[0] = 0x7f;
  assert.deepEqual(nativeOutput, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE);
  nativeOutput[1] = 0x7f;
  assert.equal(published[1], PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE[1]);
});

test("package declarations expose the Exact12 manifest without retired privacy types", () => {
  const rootDeclarations = readFileSync(
    new URL("../index.d.ts", import.meta.url),
    "utf8",
  );
  const optionalDeclarations = readFileSync(
    new URL("../privacy-capabilities.d.ts", import.meta.url),
    "utf8",
  );

  for (const retiredPattern of [
    /\bexport function privacyCapabilitiesV1\s*\(/u,
    /\bexport interface PrivacyCapabilities\s*\{/u,
    /\bexport interface PrivacyProductionGate\s*\{/u,
    /\bexport function privacyProofRequestV1\s*\(/u,
    /\bexport function privacyBuildProofV1\s*\(/u,
    /\bexport function privacyVerifyProofV1\s*\(/u,
    /\bexport type PrivacyBackendTag\s*=/u,
    /\bexport interface PrivacyVerifierKey/u,
    /\bexport interface RegisterPrivacyVerifierKeyInstructionInput/u,
    /\bexport function buildRegisterPrivacyVerifierKeyInstruction\s*\(/u,
    /\bexport function buildRetirePrivacyVerifierKeyInstruction\s*\(/u,
    /\bexport function noritoEncodePrivacyProofEnvelope\s*\(/u,
    /\bexport function noritoDecodePrivacyProofEnvelope\s*\(/u,
    /\bexport interface (?:ZkAce(?:TransferAuthorizationV1(?:Options)?|PublicInputsV1Input|AuthorizationProofV1(?:Input)?|WitnessV1Input|AuthorizedTransferInstructionInput)|(?:Register|Rotate|Revoke)ZkAceIdentityCommitmentInstructionInput)\b/u,
    /\bexport function (?:buildZkAceTransferAuthorizationV1|build(?:Register|Rotate|Revoke)ZkAceIdentityCommitmentInstruction|buildZkAceAuthorizationProofV1|buildZkAceAuthorizedTransferInstruction)\s*\(/u,
  ]) {
    assert.doesNotMatch(rootDeclarations, retiredPattern);
    assert.doesNotMatch(optionalDeclarations, retiredPattern);
  }
  for (const retiredPattern of [
    /\bPrivacyCapabilitySnapshotV1\b/u,
    /\bPrivacyCapabilitySnapshotError\b/u,
    /\bparsePrivacyCapabilitySnapshotV1\b/u,
    /\bgetPrivacyCapabilitiesV1\b/u,
    /\bPRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1\b/u,
  ]) {
    assert.doesNotMatch(optionalDeclarations, retiredPattern);
  }
  assert.match(
    optionalDeclarations,
    /export interface PrivacyExact12CapabilityRowV1\s*\{[\s\S]*readonly protocol_id:\s*PrivacyProtocolTagV1;[\s\S]*readonly operation_schema:[\s\S]*readonly execution_mode:[\s\S]*readonly privacy_feature_mask:\s*number;[\s\S]*readonly compiled_profile:\s*PrivacyCompiledProfileResultV1;[\s\S]*readonly readiness:\s*PrivacyCapabilityReadinessV1;[\s\S]*readonly activation:\s*PrivacyProtocolActivationRecordV1 \| null;/u,
  );
  assert.match(
    optionalDeclarations,
    /readiness:\s*"production-qualified";\s*detail:\s*null/u,
  );
  assert.doesNotMatch(
    optionalDeclarations,
    /\bPrivacyProtocolProductionQualificationV1\b|\bproduction_qualification\b/u,
  );
  assert.match(
    optionalDeclarations,
    /readonly qualification:\s*PrivacyExact12QualificationRecordV1 \| null;/u,
  );
  assert.doesNotMatch(
    optionalDeclarations,
    /\b(?:available-experimental|activation_state|limitation|assurance)\b/u,
  );
  assert.match(
    rootDeclarations,
    /export function privacyCompiledProfileCatalogV1\s*\(\): Buffer;/u,
  );
  assert.match(
    rootDeclarations,
    /network readiness requires the native-validated Exact12[\s\S]*authenticated Torii state/u,
  );
  assert.doesNotMatch(
    readFileSync(new URL("../browser.d.ts", import.meta.url), "utf8"),
    /\bprivacyCompiledProfileCatalogV1\b/u,
  );
  assert.match(
    rootDeclarations,
    /export type OpenVerifyBackendTag = "native-pipa-r-pasta" \| "stark";/u,
  );
  assert.doesNotMatch(rootDeclarations, /halo2\/pasta\/kaigi-roster-v1/u);
  assert.doesNotMatch(rootDeclarations, /halo2\/pasta\/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1/u);
  assert.match(
    rootDeclarations,
    /export type ToriiVerifierBackendLabelV1 =\s*\| "pipa-r\/pasta"\s*\| "pipa-r\/pasta\/kaigi-authorization-v1"\s*\| "pipa-r\/pasta\/kaigi-usage-v1"\s*\| "pipa-r\/pasta\/confidential-transfer-v1"\s*\| "pipa-r\/pasta\/confidential-unshield-full-v1"\s*\| "pipa-r\/pasta\/confidential-unshield-change-v1"\s*\| "stark\/fri\/poseidon-x7-goldilocks-6x64-v1";/u,
  );
});

test("package dist privacy compiled-profile catalog wrapper rejects malformed Norito output archives", () => {
  for (const malformedArchive of malformedPrivacyNativeOutputArchives(0x50)) {
    withCryptoApi(
      completePrivacyCompiledProfileCatalogBinding({
        privacyCompiledProfileCatalogV1() {
          return Buffer.from(malformedArchive);
        },
        privacyValidateCompiledProfileCatalogV1() {
          return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.MALFORMED_ARCHIVE;
        },
      }),
      (crypto) => {
        assert.throws(
          () => crypto.privacyCompiledProfileCatalogV1(),
          /native privacyCompiledProfileCatalogV1 returned an invalid typed privacy compiled-profile catalog/u,
        );
      },
    );
  }
});

test("package dist privacy compiled-profile catalog wrapper rejects oversized native output", () => {
  const oversized = Buffer.alloc(
    PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES + 1,
    0x7f,
  );
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return oversized;
      },
    }),
    (crypto) => {
      assert.throws(
        () => crypto.privacyCompiledProfileCatalogV1(),
        /native privacyCompiledProfileCatalogV1 returned oversized output/u,
      );
    },
  );
  assert.equal(oversized[0], 0x7f);
  assert.equal(oversized.at(-1), 0x7f);
});

test("package dist privacy native availability rejects every unsafe local catalog output", () => {
  const overrides = [
    () => "json is not Norito",
    () => new Uint8Array(),
    () => undefined,
    () => [0x50],
    () => Buffer.alloc(PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES + 1, 0x7f),
    ...malformedPrivacyNativeOutputArchives(0x50).map(
      (archive) => () => Buffer.from(archive),
    ),
  ];
  for (const privacyCompiledProfileCatalogOverride of overrides) {
    withCryptoApi(
      completePrivacyCompiledProfileCatalogBinding({
        privacyCompiledProfileCatalogV1: privacyCompiledProfileCatalogOverride,
        privacyValidateCompiledProfileCatalogV1() {
          return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.MALFORMED_ARCHIVE;
        },
      }),
      (crypto) => assert.equal(crypto.isPrivacyNativeAvailable(), false),
    );
  }
});

test("package dist privacy compiled-profile catalog wrapper rejects wrong result schemas", () => {
  const wrongSchemaArchive = privacyNoritoFrameWithSchemaOverride(0x50, 21, 0x42);
  withCryptoApi(
    completePrivacyCompiledProfileCatalogBinding({
      privacyCompiledProfileCatalogV1() {
        return Buffer.from(wrongSchemaArchive);
      },
      privacyValidateCompiledProfileCatalogV1() {
        return PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.SCHEMA_MISMATCH;
      },
    }),
    (crypto) => {
      assert.equal(crypto.isPrivacyNativeAvailable(), false);
      assert.throws(
        () => crypto.privacyCompiledProfileCatalogV1(),
        /native privacyCompiledProfileCatalogV1 returned an invalid typed privacy compiled-profile catalog/u,
      );
    },
  );
});
