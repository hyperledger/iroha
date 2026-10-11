import { universalArtifactInstruction } from "./contractArtifactTestHelpers.js";
import { universalArtifactInput } from "./contractArtifactTestHelpers.js";
import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildBurnAssetInstruction,
  buildMintAssetInstruction,
  buildMintTriggerRepetitionsInstruction,
  buildBurnTriggerRepetitionsInstruction,
  buildRegisterDataspaceAssetDefinitionInstruction,
  buildRegisterDomainInstruction,
  buildRegisterAccountInstruction,
  buildGrantAccountPermissionInstruction,
  buildSetAccountKeyValueInstruction,
  buildSetAssetDefinitionAliasInstruction,
  buildTransferAssetInstruction,
  buildTransferDomainInstruction,
  buildTransferAssetDefinitionInstruction,
  buildTransferNftInstruction,
  buildRegisterRwaInstruction,
  buildTransferRwaInstruction,
  buildMergeRwasInstruction,
  buildRedeemRwaInstruction,
  buildFreezeRwaInstruction,
  buildUnfreezeRwaInstruction,
  buildHoldRwaInstruction,
  buildReleaseRwaInstruction,
  buildForceTransferRwaInstruction,
  buildSetRwaControlsInstruction,
  buildSetRwaKeyValueInstruction,
  buildRemoveRwaKeyValueInstruction,
  buildCreateKaigiInstruction,
  buildJoinKaigiInstruction,
  buildLeaveKaigiInstruction,
  buildEndKaigiInstruction,
  buildRecordKaigiUsageInstruction,
  buildSetKaigiRelayManifestInstruction,
  buildRegisterKaigiRelayInstruction,
  buildUnregisterKaigiRelayInstruction,
  buildReportKaigiRelayHealthInstruction,
  KAIGI_MAX_PARTICIPANTS_V1,
  KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1,
  KAIGI_RELAY_MANIFEST_MAX_HOPS_V1,
  buildRegisterSmartContractCodeInstruction,
  buildRegisterSmartContractBytesInstruction,
  buildUploadSmartContractCodeChunkInstruction,
  buildFinalizeSmartContractCodeUploadInstruction,
  buildCancelSmartContractCodeUploadInstruction,
  buildCommitContractDeploymentInstruction,
  buildRemoveSmartContractBytesInstruction,
  buildProposeDeployContractInstruction,
  buildCastZkBallotInstruction,
  buildCastPlainBallotInstruction,
  buildUpdatePlainConvictionInstruction,
  buildSubmitAgendaProposalInstruction,
  buildClaimTwitterFollowRewardInstruction,
  buildSendToTwitterInstruction,
  buildCancelTwitterEscrowInstruction,
  buildRegisterZkAssetInstruction,
  buildScheduleConfidentialPolicyTransitionInstruction,
  buildCancelConfidentialPolicyTransitionInstruction,
  buildCreateElectionInstruction,
  buildSubmitBallotInstruction,
  buildFinalizeElectionInstruction,
} from "../src/instructionBuilders.js";
import * as instructionBuilderExports from "../src/instructionBuilders.js";
import { blake2b256 } from "../src/blake2b.js";
import { computeHashLiteralCrc } from "../src/hashLiteralCrc.js";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { isCanonicalGovernanceSelectorV1 } from "../src/governanceSelector.js";
import {
  PROOF_BOX_MAX_ENCODED_BYTES,
  proofBoxEncodedLength,
  proofBoxMaxProofBytes,
} from "../src/proofAttachment.js";
import {
  _createNoritoInstructionApi,
  exactPublicPlainBallotJson,
  exactRegisterDataspaceAssetDefinitionJson,
  noritoDecodeInstruction,
  noritoDecodeInstructionBoxArchive,
  noritoEncodeInstruction,
  noritoEncodeInstructionBoxArchive,
  validateNoritoFrame,
} from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { _createTransactionApi } from "../src/transaction.js";
import { NetworkId } from "../src/networkId.js";
import {
  hasNoritoBinding,
  makeNativeTest,
  nativeBinding,
  noritoRequiredMethods,
} from "./helpers/native.js";
import {
  assertNativeInstructionAdapterParity,
  assertPublicInstructionProjection,
  normalizedHashHex,
  toByteArray,
  withNativeInstructionCodec,
} from "./helpers/instructionCodec.js";

const test = makeNativeTest(baseTest, { require: noritoRequiredMethods });
const descriptorTest = baseTest;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UNIT_RETURN_DESCRIPTOR = Object.freeze({
  returnType: "()",
  returnSchema: { nodes: [{ kind: "Unit", value: null }] },
});
const repoRoot = path.resolve(__dirname, "..", "..", "..");
const SORA_I105_DISCRIMINANT = 0x2f1;
const CANCEL_ASSET_LOCK_ESCROW_ID =
  "hash:996264C84790C64086AAB0EF693A1D33EC18FC0B1C1229774C461A00939A6687#F2BD";

baseTest("governance V1 selectors share the exact bounded unreserved grammar", () => {
  assert.equal(isCanonicalGovernanceSelectorV1("referendum-1"), true);
  assert.equal(
    isCanonicalGovernanceSelectorV1(`a${".".repeat(126)}z`),
    true,
  );
  for (const invalid of [
    "",
    ".",
    "..",
    ".hidden",
    "a/b",
    "a%2Fb",
    "has space",
    "a\n",
    "a\0",
    "a\u007f",
    "投票",
    "a".repeat(129),
  ]) {
    assert.equal(isCanonicalGovernanceSelectorV1(invalid), false, invalid);
  }
});

baseTest("all governance instruction builders reject selector aliases", () => {
  const cases = [
    () => buildCastZkBallotInstruction({ electionId: "a/b", proof: "AA==" }),
    () => buildCastPlainBallotInstruction({
      referendumId: ".hidden", owner: ACCOUNT_ID, amount: "1", durationBlocks: 50, direction: "aye",
    }),
    () => buildCreateElectionInstruction({ electionId: "a%2Fb" }),
    () => buildSubmitBallotInstruction({ electionId: "a".repeat(129) }),
    () => buildFinalizeElectionInstruction({ electionId: "..", tally: [0, 0] }),
  ];
  for (const build of cases) {
    assert.throws(build, /must be 1-128 RFC 3986 unreserved ASCII/);
  }
});

function loadInstructionFixture(name) {
  const fixturePath = path.join(repoRoot, "fixtures", "norito_instructions", name);
  return JSON.parse(fs.readFileSync(fixturePath, "utf8"));
}

function decodeFixtureInstruction(name) {
  const fixture = loadInstructionFixture(name);
  const decoded = noritoDecodeInstruction(Buffer.from(fixture.instruction, "base64"), 753);
  return { fixture, decoded: canonicalizeClone(decoded) };
}
import {
  normalizeAccountId as exportedNormalizeAccountId,
  normalizeAssetId as exportedNormalizeAssetId,
  normalizeAssetHoldingId as exportedNormalizeAssetHoldingId,
} from "../src/index.js";
import * as sdkExports from "../src/index.js";
import { ValidationErrorCode } from "../src/validationError.js";
import { AccountAddress } from "../src/address.js";

function hexToBytes(hex) {
  const body = hex.replace(/^0x/i, "");
  if (body.length % 2 !== 0) {
    throw new TypeError("hex string must have even length");
  }
  const out = new Uint8Array(body.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(body.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function mlDsaManifestSigner(keyLength, fill = 0x5a) {
  const lengthVarint = [];
  let remaining = keyLength;
  do {
    const byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 0x80);
    lengthVarint.push(remaining === 0 ? byte : byte | 0x80);
  } while (remaining !== 0);
  const multihash = Buffer.concat([
    Buffer.from([0xee, 0x01, ...lengthVarint]),
    Buffer.alloc(keyLength, fill),
  ]);
  return `ml-dsa:${multihash.toString("hex")}`;
}

function canonicalizeValue(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeValue(entry));
  }
  if (value && typeof value === "object") {
    if ("Zk" in value && !("zk" in value)) {
      value.zk = canonicalizeValue(value.Zk);
      delete value.Zk;
    }
    for (const key of Object.keys(value)) {
      value[key] = canonicalizeValue(value[key]);
    }
    return value;
  }
  if (typeof value === "string") {
    if (!value.startsWith("hash:") && value.includes("#")) {
      try {
        return exportedNormalizeAssetHoldingId(value);
      } catch {
        return value;
      }
    }
    if (value.includes("@")) {
      return exportedNormalizeAccountId(value);
    }
  }
  return value;
}

function canonicalizeClone(value) {
  return canonicalizeValue(JSON.parse(JSON.stringify(value)));
}

function canonicalizeAccountIdUsingNorito(accountId) {
  const encoded = noritoEncodeInstruction({
    Register: {
      Account: {
        id: accountId,
        label: null,
        uaid: null,
        opaque_ids: [],
        metadata: {},
      },
    },
  }, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  return canonicalizeValue(decoded).Register.Account.id;
}

function canonicalizeAssetIdUsingNorito(assetId) {
  const encoded = noritoEncodeInstruction({
    Mint: { Asset: { object: "1", destination: assetId } },
  }, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  return canonicalizeValue(decoded).Mint.Asset.destination;
}

function buildTruncatedCanonicalHexLiteral(address) {
  const canonicalHex = address.canonicalHex();
  const payload = Buffer.from(canonicalHex.slice(2), "hex");
  const digestStart = 2;
  const truncated = Buffer.concat([
    payload.subarray(0, digestStart + 8),
    payload.subarray(digestStart + 12),
  ]);
  return `0x${truncated.toString("hex")}`;
}

const DOMAIN_ID = "wonderland.sora";
const ACCOUNT_SIGNATORY =
  "ED0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const SEED_11_ED25519_PUBLIC_KEY_HEX =
  "D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737";
const ACCOUNT_PUBLIC_KEY = hexToBytes(ACCOUNT_SIGNATORY.slice(6));
const ACCOUNT_ADDRESS = AccountAddress.fromAccount({ publicKey: ACCOUNT_PUBLIC_KEY,
});
const ACCOUNT_ID = ACCOUNT_ADDRESS.toI105(SORA_I105_DISCRIMINANT);
const ACCOUNT_ID_INPUT = ACCOUNT_ID;
const ACCOUNT_ID_CANONICAL = hasNoritoBinding()
  ? canonicalizeAccountIdUsingNorito(ACCOUNT_ID)
  : ACCOUNT_ID;
const ASSET_DEFINITION_ID = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
const ASSET_ID = `${ASSET_DEFINITION_ID}#${ACCOUNT_ID}`;
const ASSET_ID_INPUT = `${ASSET_DEFINITION_ID}#${ACCOUNT_ID_INPUT}`;
const ASSET_ID_CANONICAL = hasNoritoBinding()
  ? canonicalizeAssetIdUsingNorito(ASSET_ID)
  : ASSET_ID;
const NFT_ID = "dragon$wonderland.sora";
const RWA_ID =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.sora";
const RWA_ID_INPUT =
  "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF$commodities.sora";
const SAMPLE_PUBLIC_KEY = hexToBytes(
  "641297079357229F295938A4B5A333DE35069BF47B9D0704E45805713D13C201",
);
const SAMPLE_ACCOUNT_ADDRESS = AccountAddress.fromAccount({ publicKey: SAMPLE_PUBLIC_KEY,
});
const SAMPLE_ACCOUNT_I105_LITERAL = SAMPLE_ACCOUNT_ADDRESS.toI105(SORA_I105_DISCRIMINANT);
const SAMPLE_ACCOUNT_COMPRESSED_LITERAL = SAMPLE_ACCOUNT_ADDRESS.toI105(SORA_I105_DISCRIMINANT);
const SAMPLE_ACCOUNT_CANONICAL = exportedNormalizeAccountId(SAMPLE_ACCOUNT_I105_LITERAL);
const SAMPLE_ACCOUNT_TRUNCATED_HEX_LITERAL =
  buildTruncatedCanonicalHexLiteral(SAMPLE_ACCOUNT_ADDRESS);

function readCompactFieldPayload(buffer, offset, context) {
  let cursor = offset;
  let length = 0n;
  let shift = 0n;
  for (;;) {
    if (cursor >= buffer.length) {
      throw new RangeError(`${context} compact length overruns its buffer`);
    }
    const byte = buffer[cursor];
    cursor += 1;
    length |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7n;
    if (shift >= 64n) {
      throw new RangeError(`${context} compact length exceeds u64`);
    }
  }
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${context} compact length exceeds the safe integer range`);
  }
  const end = cursor + Number(length);
  if (end > buffer.length) {
    throw new RangeError(`${context} payload overruns its buffer`);
  }
  return { payload: buffer.subarray(cursor, end), next: end };
}

function readInstructionEnvelopeWireId(encoded, context) {
  const outer = validateNoritoFrame(encoded);
  const wire = readCompactFieldPayload(outer.payload, 0, `${context}.wire`);
  const wireValue = readCompactFieldPayload(
    wire.payload,
    0,
    `${context}.wire.value`,
  );
  assert.equal(wireValue.next, wire.payload.length);
  const inner = readCompactFieldPayload(
    outer.payload,
    wire.next,
    `${context}.inner`,
  );
  assert.equal(inner.next, outer.payload.length);
  return wireValue.payload.toString("utf8");
}

function readInstructionEnvelopeIdentity(encoded, context) {
  const outer = validateNoritoFrame(encoded);
  const wire = readCompactFieldPayload(outer.payload, 0, `${context}.wire`);
  const wireValue = readCompactFieldPayload(
    wire.payload,
    0,
    `${context}.wire.value`,
  );
  assert.equal(wireValue.next, wire.payload.length);
  const inner = readCompactFieldPayload(
    outer.payload,
    wire.next,
    `${context}.inner`,
  );
  assert.equal(inner.next, outer.payload.length);
  const frameLength = Number(inner.payload.readBigUInt64LE(0));
  const innerFrame = inner.payload.subarray(8);
  assert.equal(innerFrame.length, frameLength);
  return {
    wireId: wireValue.payload.toString("utf8"),
    innerSchemaHash: validateNoritoFrame(innerFrame).schemaHash,
  };
}

function rustTypeSchemaHash(typeName) {
  return createHash("sha256")
    .update(`norito:v1:type-name\0${typeName}`, "utf8")
    .digest()
    .subarray(0, 16);
}

const RUST_PRELUDE_INSTRUCTION_TYPE_NAMES = Object.freeze({
  BurnBox: "iroha_data_model::isi::mint_burn::BurnBox",
  CustomInstruction: "iroha_data_model::isi::transparent::CustomInstruction",
  ExecuteTrigger: "iroha_data_model::isi::transparent::ExecuteTrigger",
  MintBox: "iroha_data_model::isi::mint_burn::MintBox",
  RegisterBox: "iroha_data_model::isi::register::RegisterBox",
  TransferBox: "iroha_data_model::isi::transfer::TransferBox",
});

function rustInstructionTypeName(registryTypeLabel) {
  const preludeType = RUST_PRELUDE_INSTRUCTION_TYPE_NAMES[registryTypeLabel];
  if (preludeType !== undefined) {
    return preludeType;
  }
  if (registryTypeLabel.startsWith("crate::isi::")) {
    return `iroha_data_model::${registryTypeLabel.slice("crate::".length)}`;
  }
  assert.match(
    registryTypeLabel,
    /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+$/u,
    `registry type ${registryTypeLabel} must be module-qualified`,
  );
  return `iroha_data_model::isi::${registryTypeLabel}`;
}

function readRustInstructionRegistryBindings() {
  const source = fs.readFileSync(
    path.join(
      repoRoot,
      "crates",
      "iroha_data_model",
      "src",
      "isi",
      "registry",
      "wire_ids.rs",
    ),
    "utf8",
  );
  const entries = new Map();
  const pattern =
    /\b(?:built_in_wire_id|governance_wire_id)!\(\s*([A-Za-z_][A-Za-z0-9_:]*)\s*=>\s*"([^"]+)"/gu;
  for (const match of source.matchAll(pattern)) {
    const [, typeLabel, outerWireId] = match;
    const existing = entries.get(outerWireId);
    assert.ok(
      existing === undefined || existing === typeLabel,
      `Rust registry wire ID ${outerWireId} has conflicting types ${existing} and ${typeLabel}`,
    );
    entries.set(outerWireId, typeLabel);
  }
  assert.ok(entries.size > 0, "Rust instruction registry must not be empty");
  return entries;
}

function encodeAndDecode(
  instruction,
  {
    noritoEncodeInstruction: encode = noritoEncodeInstruction,
    noritoDecodeInstruction: decode = noritoDecodeInstruction,
  } = {},
) {
  let encoded;
  try {
    encoded = encode(instruction, 753);
  } catch (error) {
    if (
      process?.env?.DEBUG_NORITO_PAYLOAD === "1" &&
      error instanceof Error &&
      /JSON error/i.test(error.message)
    ) {
      console.error("norito encoding failed for payload:", JSON.stringify(instruction));
    }
    throw error;
  }
  try {
    const decoded = decode(encoded, 753);
    return canonicalizeValue(decoded);
  } catch (error) {
    if (
      process?.env?.DEBUG_NORITO_PAYLOAD === "1" &&
      error instanceof Error &&
      /JSON error/i.test(error.message)
    ) {
      console.error("norito encoding failed for payload:", JSON.stringify(instruction));
    }
    const message = error && typeof error.message === "string" ? error.message : "";
    const alignmentIssue = message.includes("alignment");
    const panicDuringDecode =
      message.includes("panic during decode") ||
      message.includes("panic during Norito decode");
    if (!alignmentIssue && !panicDuringDecode) {
      throw error;
    }
    const canonical = canonicalizeClone(instruction);
    const reencoded = encode(canonical, 753);
    assert.deepEqual(toByteArray(encoded), toByteArray(reencoded));
    return canonical;
  }
}

function nativeInstructionDecoder(decoded) {
  return _createNoritoInstructionApi(createNativeRuntime({
    noritoDecodeInstruction() {
      return JSON.stringify(decoded);
    },
  })).noritoDecodeInstruction;
}

const NORITO_CRC64_MASK = 0xffff_ffff_ffff_ffffn;
const NORITO_CRC64_POLY = 0xc96c_5795_d787_0f42n;

function noritoCrc64(payload) {
  let crc = NORITO_CRC64_MASK;
  for (const byte of payload) {
    let tableEntry = (crc ^ BigInt(byte)) & 0xffn;
    for (let bit = 0; bit < 8; bit += 1) {
      tableEntry =
        (tableEntry & 1n) === 0n
          ? tableEntry >> 1n
          : (tableEntry >> 1n) ^ NORITO_CRC64_POLY;
    }
    crc = tableEntry ^ (crc >> 8n);
  }
  return BigInt.asUintN(64, crc ^ NORITO_CRC64_MASK);
}

function rewriteNoritoFrameCrc(buffer, frameStart, frameEnd) {
  const payloadLength = Number(buffer.readBigUInt64LE(frameStart + 23));
  const payloadStart = frameEnd - payloadLength;
  assert.ok(payloadStart >= frameStart + 40, "Norito payload must follow its header");
  buffer.writeBigUInt64LE(
    noritoCrc64(buffer.subarray(payloadStart, frameEnd)),
    frameStart + 31,
  );
}

function rewriteNestedInstructionCrcs(buffer) {
  const innerStart = buffer.indexOf(Buffer.from("NRT0", "ascii"), 4);
  assert.ok(innerStart > 0, "nested Norito instruction frame must be present");
  rewriteNoritoFrameCrc(buffer, innerStart, buffer.length);
  rewriteNoritoFrameCrc(buffer, 0, buffer.length);
}

function encodeCompactTestLength(length) {
  let remaining = length;
  const bytes = [];
  do {
    const chunk = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    bytes.push(remaining === 0 ? chunk : chunk | 0x80);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function rebuildNoritoTestFrame(frame, payload) {
  const oldPayloadLength = Number(frame.readBigUInt64LE(23));
  const payloadStart = frame.length - oldPayloadLength;
  const prefix = Buffer.from(frame.subarray(0, payloadStart));
  prefix.writeBigUInt64LE(BigInt(payload.length), 23);
  prefix.writeBigUInt64LE(noritoCrc64(payload), 31);
  return Buffer.concat([prefix, payload]);
}

function appendFinalizeProofAttachmentTail(encoded, tailPayload) {
  const outer = validateNoritoFrame(encoded);
  const wire = readCompactFieldPayload(outer.payload, 0, "outer.wire");
  const innerField = readCompactFieldPayload(outer.payload, wire.next, "outer.inner");
  assert.equal(innerField.next, outer.payload.length);
  const innerFrameLength = Number(innerField.payload.readBigUInt64LE(0));
  const innerFrame = innerField.payload.subarray(8);
  assert.equal(innerFrame.length, innerFrameLength);
  const inner = validateNoritoFrame(innerFrame);
  const election = readCompactFieldPayload(inner.payload, 0, "finalize.election");
  const tally = readCompactFieldPayload(inner.payload, election.next, "finalize.tally");
  const attachment = readCompactFieldPayload(
    inner.payload,
    tally.next,
    "finalize.attachment",
  );
  assert.equal(attachment.next, inner.payload.length);

  const expandedAttachment = Buffer.concat([
    attachment.payload,
    encodeCompactTestLength(tailPayload.length),
    tailPayload,
  ]);
  const rebuiltInnerPayload = Buffer.concat([
    inner.payload.subarray(0, tally.next),
    encodeCompactTestLength(expandedAttachment.length),
    expandedAttachment,
  ]);
  const rebuiltInnerFrame = rebuildNoritoTestFrame(innerFrame, rebuiltInnerPayload);
  const rebuiltInnerFieldPayload = Buffer.allocUnsafe(8 + rebuiltInnerFrame.length);
  rebuiltInnerFieldPayload.writeBigUInt64LE(BigInt(rebuiltInnerFrame.length), 0);
  rebuiltInnerFrame.copy(rebuiltInnerFieldPayload, 8);
  const rebuiltOuterPayload = Buffer.concat([
    outer.payload.subarray(0, wire.next),
    encodeCompactTestLength(rebuiltInnerFieldPayload.length),
    rebuiltInnerFieldPayload,
  ]);
  return rebuildNoritoTestFrame(Buffer.from(encoded), rebuiltOuterPayload);
}

test("normalizeAccountId exported accepts encoded account IDs", () => {
  const canonical = exportedNormalizeAccountId(ACCOUNT_ID_INPUT);
  assert.equal(canonical, ACCOUNT_ID_CANONICAL);
});

test("normalizeAccountId canonicalizes I105 and i105 (`sora`) encodings", () => {
  const canonicalI105 = exportedNormalizeAccountId(SAMPLE_ACCOUNT_I105_LITERAL);
  assert.equal(canonicalI105, SAMPLE_ACCOUNT_CANONICAL);
  const canonicalCompressed = exportedNormalizeAccountId(SAMPLE_ACCOUNT_COMPRESSED_LITERAL);
  assert.equal(canonicalCompressed, SAMPLE_ACCOUNT_CANONICAL);
});

test("normalizeAccountId rejects truncated canonical-hex inputs", () => {
  assert.throws(
    () => exportedNormalizeAccountId(SAMPLE_ACCOUNT_TRUNCATED_HEX_LITERAL),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_ACCOUNT_ID);
      assert.match(String(error?.message), /canonical I105 account id/i);
      return true;
    },
  );
});

test("normalizeAssetId exported canonicalizes bare Base58 asset ids", () => {
  const canonical = exportedNormalizeAssetId(ASSET_DEFINITION_ID);
  assert.equal(canonical, ASSET_DEFINITION_ID);
});

test("normalizeAssetId rejects malformed asset literals", () => {
  assert.throws(
    () => exportedNormalizeAssetId(ASSET_ID_INPUT),
    /canonical Base58 asset id/,
  );
});

test("normalizeAssetHoldingId exported canonicalizes asset-holding identifiers", () => {
  const canonical = exportedNormalizeAssetHoldingId(ASSET_ID_INPUT);
  assert.equal(canonical, ASSET_ID_CANONICAL);
});


test("buildMintAssetInstruction produces canonical Norito payload", () => {
  const instruction = buildMintAssetInstruction({ assetId: ASSET_ID, quantity: 42n });
  assert.deepEqual(instruction, {
    Mint: { Asset: { object: "42", destination: ASSET_ID_CANONICAL } },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, canonicalizeClone(instruction));
});

test("buildMintAssetInstruction rejects invalid Numeric literals", () => {
  assert.throws(
    () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity: "1e-3" }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_NUMERIC);
      assert.match(String(error?.message), /canonical non-negative Kotodama V1 quantity/i);
      return true;
    },
  );
  const tooManyDecimals = `0.${"1".repeat(29)}`;
  assert.throws(
    () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity: tooManyDecimals }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /canonical non-negative Kotodama V1 quantity/i);
      return true;
    },
  );
  // Numeric is a signed 512-bit domain, so non-negative quantities end at
  // 2^511 - 1 rather than 2^512 - 1.
  const tooLarge = 1n << 511n;
  assert.throws(
    () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity: tooLarge }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /canonical non-negative Kotodama V1 quantity/i);
      return true;
    },
  );
  assert.throws(
    () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity: "-1" }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_NUMERIC);
      assert.match(String(error?.message), /non-negative/i);
      return true;
    },
  );
  assert.throws(
    () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity: "1".repeat(100_000) }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /canonical non-negative Kotodama V1 quantity/i);
      return true;
    },
  );

  for (const quantity of [
    42,
    "+1",
    "01",
    "1.0",
    "1.2300",
    "1amt",
    "1qty",
    " 1",
    "1 ",
    "0.0",
  ]) {
    assert.throws(
      () => buildMintAssetInstruction({ assetId: ASSET_ID, quantity }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_NUMERIC);
        return true;
      },
      `accepted ambiguous quantity ${String(quantity)}`,
    );
  }
});

test("buildMintAssetInstruction accepts the positive signed-Numeric boundary", () => {
  const maximumQuantity = (1n << 511n) - 1n;
  const instruction = buildMintAssetInstruction({
    assetId: ASSET_ID,
    quantity: maximumQuantity,
  });
  assert.equal(instruction.Mint.Asset.object, maximumQuantity.toString());
  assert.deepEqual(encodeAndDecode(instruction), canonicalizeClone(instruction));
});

test("buildBurnAssetInstruction produces canonical Norito payload", () => {
  const instruction = buildBurnAssetInstruction({ assetId: ASSET_ID, quantity: "7" });
  assert.deepEqual(instruction, {
    Burn: { Asset: { object: "7", destination: ASSET_ID_CANONICAL } },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, canonicalizeClone(instruction));
});

test("buildBurnAssetInstruction matches canonical numeric Norito fixture", () => {
  const { fixture, decoded } = decodeFixtureInstruction("burn_asset_quantity.json");
  const { destination, object } = decoded.Burn.Asset;
  const instruction = buildBurnAssetInstruction({ assetId: destination, quantity: object });
  assert.deepEqual(instruction, decoded);
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.equal(
    encoded.toString("hex"),
    Buffer.from(fixture.instruction, "base64").toString("hex"),
    "Burn::Asset numeric fixture diverged from canonical Norito bytes",
  );
});

test("buildBurnAssetInstruction matches canonical fractional Norito fixture", () => {
  const { fixture, decoded } = decodeFixtureInstruction("burn_asset_fractional.json");
  const { destination, object } = decoded.Burn.Asset;
  const instruction = buildBurnAssetInstruction({ assetId: destination, quantity: object });
  assert.deepEqual(instruction, decoded);
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.equal(
    encoded.toString("hex"),
    Buffer.from(fixture.instruction, "base64").toString("hex"),
    "Burn::Asset fractional fixture diverged from canonical Norito bytes",
  );
});

test("buildMintTriggerRepetitionsInstruction validates repetitions", () => {
  const instruction = buildMintTriggerRepetitionsInstruction({
    triggerId: "notify-users",
    repetitions: "3",
  });
  assert.deepEqual(instruction, {
    Mint: { TriggerRepetitions: { object: 3, destination: "notify-users" } },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    Mint: { TriggerRepetitions: { object: 3, destination: "notify-users" } },
  });
  assert.throws(
    () => buildMintTriggerRepetitionsInstruction({ triggerId: "notify-users", repetitions: 0 }),
    /positive integer/i,
  );
});

test("buildBurnTriggerRepetitionsInstruction validates repetitions", () => {
  const instruction = buildBurnTriggerRepetitionsInstruction({
    triggerId: "notify-users",
    repetitions: 2n,
  });
  assert.deepEqual(instruction, {
    Burn: { TriggerRepetitions: { object: 2, destination: "notify-users" } },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, canonicalizeClone(instruction));
  assert.throws(
    () =>
      buildBurnTriggerRepetitionsInstruction({ triggerId: "notify-users", repetitions: 0 }),
    /positive integer/i,
  );
});

test("buildMintTriggerRepetitionsInstruction rejects oversized integers", () => {
  const tooLarge = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
  assert.throws(
    () =>
      buildMintTriggerRepetitionsInstruction({
        triggerId: "notify-users",
        repetitions: tooLarge,
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /safe integer/i);
      return true;
    },
  );
});

test("buildTransferAssetInstruction encodes asset quantity", () => {
  const instruction = buildTransferAssetInstruction({
    sourceAssetId: ASSET_ID,
    quantity: "17",
    destinationAccountId: ACCOUNT_ID,
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    Transfer: {
      Asset: {
        source: ASSET_ID_CANONICAL,
        object: "17",
        destination: ACCOUNT_ID_CANONICAL,
      },
    },
  });
});

test("buildTransferDomainInstruction covers domain transfer", () => {
  const instruction = buildTransferDomainInstruction({
    sourceAccountId: ACCOUNT_ID,
    domainId: DOMAIN_ID,
    destinationAccountId: ACCOUNT_ID,
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    Transfer: {
      Domain: {
        source: ACCOUNT_ID_CANONICAL,
        object: DOMAIN_ID,
        destination: ACCOUNT_ID_CANONICAL,
      },
    },
  });
});

test("buildTransferAssetDefinitionInstruction covers definition transfer", () => {
  const instruction = buildTransferAssetDefinitionInstruction({
    sourceAccountId: ACCOUNT_ID,
    assetDefinitionId: ASSET_DEFINITION_ID,
    destinationAccountId: ACCOUNT_ID,
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    Transfer: {
      AssetDefinition: {
        source: ACCOUNT_ID_CANONICAL,
        object: ASSET_DEFINITION_ID,
        destination: ACCOUNT_ID_CANONICAL,
      },
    },
  });
});

test("buildTransferNftInstruction covers nft transfer", () => {
  const instruction = buildTransferNftInstruction({
    sourceAccountId: ACCOUNT_ID,
    nftId: NFT_ID,
    destinationAccountId: ACCOUNT_ID,
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    Transfer: {
      Nft: {
        source: ACCOUNT_ID_CANONICAL,
        object: NFT_ID,
        destination: ACCOUNT_ID_CANONICAL,
      },
    },
  });
});

test("NftId implicit universal and Name rules match native V1", () => {
  const implicit = buildTransferNftInstruction({
    sourceAccountId: ACCOUNT_ID,
    nftId: "dragon$wonderland",
    destinationAccountId: ACCOUNT_ID,
  });
  const explicit = buildTransferNftInstruction({
    sourceAccountId: ACCOUNT_ID,
    nftId: "dragon$wonderland.universal",
    destinationAccountId: ACCOUNT_ID,
  });
  const adapterImplicit = Buffer.from(
    withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(implicit, 753)),
  );
  const nativeImplicit = Buffer.from(
    nativeBinding.noritoEncodeInstruction(JSON.stringify(implicit), 753),
  );
  const adapterExplicit = Buffer.from(
    withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(explicit, 753)),
  );
  assert.deepEqual(adapterImplicit, nativeImplicit);
  assert.deepEqual(adapterImplicit, adapterExplicit);
  assert.deepEqual(
    JSON.parse(nativeBinding.noritoDecodeInstruction(adapterImplicit, 753)),
    explicit,
  );
  assert.deepEqual(
    withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(nativeImplicit, 753)),
    explicit,
  );

  const composed = buildTransferNftInstruction({
    sourceAccountId: ACCOUNT_ID,
    nftId: "é$wonderland.universal",
    destinationAccountId: ACCOUNT_ID,
  });
  const composedBytes = assertNativeInstructionAdapterParity(composed, "Transfer.Nft NFC");
  assert.deepEqual(encodeAndDecode(composed), composed);
  assert.deepEqual(
    JSON.parse(nativeBinding.noritoDecodeInstruction(composedBytes, 753)),
    composed,
  );
  for (const nftId of ["e\u0301$wonderland", "bad@name$wonderland"]) {
    const invalid = buildTransferNftInstruction({
      sourceAccountId: ACCOUNT_ID,
      nftId,
      destinationAccountId: ACCOUNT_ID,
    });
    assert.throws(
      () => withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
        noritoEncodeInstruction(invalid, 753)),
      /Failed to parse `name` part in `name\$domain`/u,
    );
    assert.throws(
      () => nativeBinding.noritoEncodeInstruction(JSON.stringify(invalid), 753),
      /Failed to parse `name` part in `name\$domain`/u,
    );
  }
});

test("nominal DomainId public adapter frames byte-match native V1", () => {
  const instructions = [
    [
      "Register.Domain",
      {
        Register: {
          Domain: {
            id: DOMAIN_ID,
            logo: null,
            metadata: { purpose: "parity" },
          },
        },
      },
    ],
    [
      "Transfer.Domain",
      buildTransferDomainInstruction({
        sourceAccountId: ACCOUNT_ID,
        domainId: DOMAIN_ID,
        destinationAccountId: ACCOUNT_ID,
      }),
    ],
    [
      "Transfer.Nft",
      buildTransferNftInstruction({
        sourceAccountId: ACCOUNT_ID,
        nftId: NFT_ID,
        destinationAccountId: ACCOUNT_ID,
      }),
    ],
  ];
  for (const [name, instruction] of instructions) {
    const encoded = assertNativeInstructionAdapterParity(instruction, name);
    assert.equal(encoded[39], 0x02, `${name} must use compact Norito framing`);
  }
});

test("buildRegisterRwaInstruction normalizes richer lot payloads", () => {
  const instruction = buildRegisterRwaInstruction({
    rwa: {
      domain: "commodities.sora",
      quantity: "10.5",
      spec: { scale: 1 },
      primaryReference: "vault-cert-001",
      metadata: { origin: "AE", lot: BigInt(3) },
      parents: [{ rwa: RWA_ID, quantity: "1.25" }],
      controls: {
        controllerAccounts: [ACCOUNT_ID],
        controllerRoles: ["auditor"],
        freezeEnabled: true,
        holdEnabled: true,
      },
    },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    RegisterRwa: {
      rwa: {
        domain: "commodities.sora",
        quantity: "10.5",
        spec: { scale: 1 },
        primary_reference: "vault-cert-001",
        status: null,
        metadata: { origin: "AE", lot: "3" },
        parents: [{ rwa: RWA_ID, quantity: "1.25" }],
        controls: {
          controller_accounts: [ACCOUNT_ID_CANONICAL],
          controller_roles: ["auditor"],
          freeze_enabled: true,
          hold_enabled: true,
          force_transfer_enabled: false,
          redeem_enabled: false,
        },
      },
    },
  });
  const encoded = assertNativeInstructionAdapterParity(
    instruction,
    "RegisterRwa",
  );
  assert.equal(encoded[39], 0x02, "RegisterRwa must use compact Norito framing");
});

test("buildTransferRwaInstruction covers rwa transfer", () => {
  const instruction = buildTransferRwaInstruction({
    sourceAccountId: ACCOUNT_ID,
    rwaId: RWA_ID_INPUT,
    quantity: "3.25",
    destinationAccountId: ACCOUNT_ID,
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, {
    TransferRwa: {
      source: ACCOUNT_ID_CANONICAL,
      rwa: RWA_ID,
      quantity: "3.25",
      destination: ACCOUNT_ID_CANONICAL,
    },
  });
});

test("rwa scalar instruction builders cover lifecycle operations", () => {
  const merge = buildMergeRwasInstruction({
    merge: {
      parents: [{ rwa: RWA_ID, quantity: "1.5" }],
      primaryReference: "blend-cert-007",
      status: "blended",
      metadata: { grade: "A" },
    },
  });
  const redeem = buildRedeemRwaInstruction({ rwaId: RWA_ID, quantity: "2" });
  const freeze = buildFreezeRwaInstruction({ rwaId: RWA_ID });
  const unfreeze = buildUnfreezeRwaInstruction({ rwaId: RWA_ID });
  const hold = buildHoldRwaInstruction({ rwaId: RWA_ID, quantity: "3" });
  const release = buildReleaseRwaInstruction({ rwaId: RWA_ID, quantity: "1" });
  const forceTransfer = buildForceTransferRwaInstruction({
    rwaId: RWA_ID,
    quantity: "4",
    destinationAccountId: ACCOUNT_ID,
  });
  const controls = buildSetRwaControlsInstruction({
    rwaId: RWA_ID,
    controls: { redeemEnabled: true },
  });

  assert.deepEqual(encodeAndDecode(merge), {
    MergeRwas: {
      parents: [{ rwa: RWA_ID, quantity: "1.5" }],
      primary_reference: "blend-cert-007",
      status: "blended",
      metadata: { grade: "A" },
    },
  });
  assert.deepEqual(encodeAndDecode(redeem), {
    RedeemRwa: { rwa: RWA_ID, quantity: "2" },
  });
  assert.deepEqual(encodeAndDecode(freeze), {
    FreezeRwa: { rwa: RWA_ID },
  });
  const freezeBytes = assertNativeInstructionAdapterParity(freeze, "FreezeRwa");
  assert.equal(freezeBytes[39], 0x02, "FreezeRwa must use compact Norito framing");
  const evenHashRwaId = RWA_ID.replace(/ef\$/u, "ee$");
  assert.throws(
    () =>
      withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
        noritoEncodeInstruction({
          FreezeRwa: { rwa: evenHashRwaId },
        }, 753),
      ),
    /Failed to parse `hash` part in `hash\$domain`/u,
  );
  assert.throws(
    () =>
      nativeBinding.noritoEncodeInstruction(
        JSON.stringify({
          FreezeRwa: { rwa: evenHashRwaId },
        }), 753,
      ),
    /hash|parse|marker/u,
  );
  assert.deepEqual(encodeAndDecode(unfreeze), {
    UnfreezeRwa: { rwa: RWA_ID },
  });
  assert.deepEqual(encodeAndDecode(hold), {
    HoldRwa: { rwa: RWA_ID, quantity: "3" },
  });
  assert.deepEqual(encodeAndDecode(release), {
    ReleaseRwa: { rwa: RWA_ID, quantity: "1" },
  });
  assert.deepEqual(encodeAndDecode(forceTransfer), {
    ForceTransferRwa: {
      rwa: RWA_ID,
      quantity: "4",
      destination: ACCOUNT_ID_CANONICAL,
    },
  });
  assert.deepEqual(encodeAndDecode(controls), {
    SetRwaControls: {
      rwa: RWA_ID,
      controls: {
        controller_accounts: [],
        controller_roles: [],
        freeze_enabled: false,
        hold_enabled: false,
        force_transfer_enabled: false,
        redeem_enabled: true,
      },
    },
  });

  const setMetadata = buildSetRwaKeyValueInstruction({
    rwaId: RWA_ID,
    key: "grade",
    value: { country: "AE", sequence: BigInt(7) },
  });
  const removeMetadata = buildRemoveRwaKeyValueInstruction({
    rwaId: RWA_ID,
    key: "grade",
  });
  assert.deepEqual(encodeAndDecode(setMetadata), {
    SetRwaKeyValue: {
      rwa: RWA_ID,
      key: "grade",
      value: { country: "AE", sequence: "7" },
    },
  });
  assert.deepEqual(encodeAndDecode(removeMetadata), {
    RemoveRwaKeyValue: {
      rwa: RWA_ID,
      key: "grade",
    },
  });
});

test("buildRegisterDomainInstruction normalizes metadata payloads", () => {
  const instruction = buildRegisterDomainInstruction({
    domainId: DOMAIN_ID,
    metadata: {
      title: "Wonderland",
      attrs: { population: 10, status: true },
      counters: [1, 2, BigInt(3)],
    },
  });
  assert.deepEqual(instruction, {
    Register: {
      Domain: {
        id: DOMAIN_ID,
        logo: null,
        metadata: {
          title: "Wonderland",
          attrs: { population: 10, status: true },
          counters: [1, 2, "3"],
        },
      },
    },
  });
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, canonicalizeClone(instruction));
});

test("buildRegisterDomainInstruction accepts custom logo strings", () => {
  const logoPath = "ipfs://placeholder-logo";
  const instruction = buildRegisterDomainInstruction({
    domainId: DOMAIN_ID,
    logo: logoPath,
  });
  assert.equal(instruction.Register.Domain.logo, logoPath);
});

test("buildRegisterAccountInstruction defaults metadata and validates", () => {
  const instruction = buildRegisterAccountInstruction({
    accountId: ACCOUNT_ID,
  });
  const account = instruction.Register.Account;
  assert.equal(account.id, ACCOUNT_ID_CANONICAL);
  assert.deepEqual(account.metadata, {});
  assert.equal(account.label ?? null, null);
  assert.equal(account.uaid ?? null, null);
  assert.deepEqual(account.opaque_ids, []);
  const decoded = encodeAndDecode(instruction);
  const decodedAccount = decoded.Register.Account;
  assert.equal(decodedAccount.id, ACCOUNT_ID_CANONICAL);
  assert.deepEqual(decodedAccount.metadata, {});
  assert.equal(decodedAccount.label ?? null, null);
  assert.equal(decodedAccount.uaid ?? null, null);
  assert.deepEqual(decodedAccount.opaque_ids, []);
  assert.throws(
    () =>
      buildRegisterAccountInstruction({
        accountId: ACCOUNT_ID,
        domainId: DOMAIN_ID,
      }),
    /domainless/i,
  );
  assert.throws(
    () =>
      buildRegisterAccountInstruction({
        accountId: ACCOUNT_ID,
        metadata: ["invalid"],
      }),
    /plain object/i,
  );
});

test("buildGrantAccountPermissionInstruction defaults payload", () => {
  const instruction = buildGrantAccountPermissionInstruction({
    accountId: ACCOUNT_ID,
    permission: { name: "register_zk_asset" },
  });
  assert.deepEqual(instruction, {
    Grant: {
      Permission: {
        object: {
          name: "register_zk_asset",
          payload: null,
        },
        destination: ACCOUNT_ID_CANONICAL,
      },
    },
  });
  assert.deepEqual(encodeAndDecode(instruction), canonicalizeClone(instruction));
});

test("buildSetAccountKeyValueInstruction produces canonical Norito payload", () => {
  const sourceTxHash = "ab".repeat(32);
  const instruction = buildSetAccountKeyValueInstruction({
    accountId: ACCOUNT_ID,
    key: `pk_cbuae_settlement_${sourceTxHash}`,
    value: {
      protocol: "pk-cbuae-settlement",
      version: 1,
      source_tx_hash: sourceTxHash,
    },
  });
  assert.deepEqual(instruction, {
    SetKeyValue: {
      Account: {
        object: ACCOUNT_ID_CANONICAL,
        key: `pk_cbuae_settlement_${sourceTxHash}`,
        value: {
          protocol: "pk-cbuae-settlement",
          version: 1,
          source_tx_hash: sourceTxHash,
        },
      },
    },
  });
  assert.deepEqual(encodeAndDecode(instruction), canonicalizeClone(instruction));
});

baseTest("buildSetAccountKeyValueInstruction rejects non-JSON marker values", () => {
  assert.throws(
    () =>
      buildSetAccountKeyValueInstruction({
        accountId: ACCOUNT_ID,
        key: "marker",
        value: undefined,
      }),
    /value/i,
  );
});

test("buildSetAssetDefinitionAliasInstruction supports clearing aliases", () => {
  assert.deepEqual(
    buildSetAssetDefinitionAliasInstruction({
      assetDefinitionId: ASSET_DEFINITION_ID,
      alias: null,
    }),
    {
      SetAssetDefinitionAlias: {
        asset_definition_id: ASSET_DEFINITION_ID,
        alias: null,
        lease_expiry_ms: null,
      },
    },
  );
});

const RELAY_ACCOUNT_ID = ACCOUNT_ID_CANONICAL;
const THIRD_RELAY_ACCOUNT_ID = exportedNormalizeAccountId(
  AccountAddress.fromAccount({
    publicKey: hexToBytes(SEED_11_ED25519_PUBLIC_KEY_HEX),
  }).toI105(SORA_I105_DISCRIMINANT),
);
const KAIGI_RELAY_PUBLIC_KEYS_HEX = Object.freeze([
  "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
  "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
  "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
  "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
  "8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17",
  "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
  "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
]);

function kaigiRelayHops() {
  return [
    {
      relayId: RELAY_ACCOUNT_ID,
      hpkePublicKey: Buffer.alloc(32, 0x01),
      weight: 5,
    },
    {
      relayId: SAMPLE_ACCOUNT_CANONICAL,
      hpkePublicKey: Buffer.alloc(32, 0x02),
      weight: 3,
    },
    {
      relayId: THIRD_RELAY_ACCOUNT_ID,
      hpkePublicKey: Buffer.alloc(32, 0x03),
      weight: 4,
    },
  ];
}

function normalizedKaigiRelayHops() {
  return kaigiRelayHops().map((hop) => ({
    relay_id: hop.relayId,
    hpke_public_key: hop.hpkePublicKey.toString("base64"),
    weight: hop.weight,
  }));
}

function maximumKaigiRelayHops() {
  return KAIGI_RELAY_PUBLIC_KEYS_HEX.map((publicKey, index) => ({
    relayId: exportedNormalizeAccountId(
      AccountAddress.fromAccount({ publicKey: hexToBytes(publicKey) }).toI105(
        SORA_I105_DISCRIMINANT,
      ),
    ),
    hpkePublicKey: Buffer.alloc(
      index === 0 ? KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 : 1,
      index + 1,
    ),
    weight: 1,
  }));
}

baseTest("Kaigi relay builders enforce the V1 hop and decoded-key bounds", () => {
  assert.equal(KAIGI_RELAY_MANIFEST_MAX_HOPS_V1, 8);
  assert.equal(KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1, 4_096);

  const hops = maximumKaigiRelayHops();
  const acceptedManifest = buildSetKaigiRelayManifestInstruction({
    callId: "wonderland.sora:bounded-relays",
    relayManifest: { hops, expiryMs: 1 },
  });
  assert.equal(
    acceptedManifest.Kaigi.SetKaigiRelayManifest.relay_manifest.hops.length,
    8,
  );
  assert.equal(
    Buffer.from(
      acceptedManifest.Kaigi.SetKaigiRelayManifest.relay_manifest.hops[0]
        .hpke_public_key,
      "base64",
    ).length,
    4_096,
  );

  assert.throws(
    () =>
      buildSetKaigiRelayManifestInstruction({
        callId: "wonderland.sora:too-many-relays",
        relayManifest: { hops: [...hops, hops[0]], expiryMs: 1 },
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(error?.path, "setKaigiRelayManifest.relayManifest.hops");
      return true;
    },
  );

  const acceptedRegistration = buildRegisterKaigiRelayInstruction({
    relayId: RELAY_ACCOUNT_ID,
    hpkePublicKey: Buffer.alloc(4_096, 0xA5).toString("base64"),
    bandwidthClass: 1,
  });
  assert.equal(
    Buffer.from(
      acceptedRegistration.Kaigi.RegisterKaigiRelay.relay.hpke_public_key,
      "base64",
    ).length,
    4_096,
  );

  const oversizedKey = Buffer.alloc(4_097, 0xA5);
  assert.throws(
    () =>
      buildSetKaigiRelayManifestInstruction({
        callId: "wonderland.sora:oversized-hop-key",
        relayManifest: {
          hops: [
            { ...hops[0], hpkePublicKey: oversizedKey },
            hops[1],
            hops[2],
          ],
          expiryMs: 1,
        },
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(
        error?.path,
        "setKaigiRelayManifest.relayManifest.hops[0].hpkePublicKey",
      );
      return true;
    },
  );
  assert.throws(
    () =>
      buildRegisterKaigiRelayInstruction({
        relayId: RELAY_ACCOUNT_ID,
        hpkePublicKey: oversizedKey.toString("base64"),
        bandwidthClass: 1,
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(error?.path, "registerKaigiRelay.hpkePublicKey");
      return true;
    },
  );
});

test("Kaigi instruction envelopes use the exact V1 registry wire IDs", () => {
  const callId = "wonderland.sora:wire-id";
  const cases = [
    [
      "CreateKaigi",
      buildCreateKaigiInstruction({ id: callId, host: ACCOUNT_ID }),
    ],
    [
      "JoinKaigi",
      buildJoinKaigiInstruction({ callId, participant: ACCOUNT_ID }),
    ],
    [
      "LeaveKaigi",
      buildLeaveKaigiInstruction({ callId, participant: ACCOUNT_ID }),
    ],
    ["EndKaigi", buildEndKaigiInstruction({ callId })],
    [
      "RecordKaigiUsage",
      buildRecordKaigiUsageInstruction({
        callId,
        durationMs: 1,
        billedGas: 2,
      }),
    ],
    [
      "SetKaigiRelayManifest",
      buildSetKaigiRelayManifestInstruction({ callId, relayManifest: null }),
    ],
    [
      "RegisterKaigiRelay",
      buildRegisterKaigiRelayInstruction({
        relayId: RELAY_ACCOUNT_ID,
        hpkePublicKey: Buffer.alloc(32, 0xa5),
        bandwidthClass: 1,
      }),
    ],
    [
      "ReportKaigiRelayHealth",
      buildReportKaigiRelayHealthInstruction({
        callId,
        relayId: RELAY_ACCOUNT_ID,
        status: "Healthy",
        reportedAtMs: 3,
      }),
    ],
  ];

  withNativeInstructionCodec(({
    noritoDecodeInstruction,
    noritoEncodeInstruction,
  }) => {
    for (const [name, instruction] of cases) {
      const encoded = noritoEncodeInstruction(instruction, 753);
      assert.equal(
        readInstructionEnvelopeWireId(encoded, `Kaigi.${name}`),
        `iroha.instruction.v1::kaigi::${name}`,
      );
      assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);
    }
  });
});

function assertKaigiManifestRejected(relayManifest, code, path) {
  assert.throws(
    () =>
      buildCreateKaigiInstruction({
        id: "wonderland.sora:weekly-sync",
        host: ACCOUNT_ID,
        relayManifest,
      }),
    (error) => {
      assert.equal(error?.code, code);
      assert.equal(error?.path, path);
      return true;
    },
  );
}

baseTest("Kaigi relay manifests reject fewer than three hops", () => {
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000 },
    ValidationErrorCode.INVALID_OBJECT,
    "call.relayManifest.hops",
  );
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000, hops: kaigiRelayHops().slice(0, 2) },
    ValidationErrorCode.VALUE_OUT_OF_RANGE,
    "call.relayManifest.hops",
  );
});

baseTest("Kaigi relay manifests reject invalid hop contents", () => {
  const duplicateHops = kaigiRelayHops();
  duplicateHops[2].relayId = duplicateHops[0].relayId;
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000, hops: duplicateHops },
    ValidationErrorCode.INVALID_OBJECT,
    "call.relayManifest.hops[2].relayId",
  );

  const emptyKeyHops = kaigiRelayHops();
  emptyKeyHops[1].hpkePublicKey = Buffer.alloc(0);
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000, hops: emptyKeyHops },
    ValidationErrorCode.INVALID_STRING,
    "call.relayManifest.hops[1].hpkePublicKey",
  );

  const zeroWeightHops = kaigiRelayHops();
  zeroWeightHops[0].weight = 0;
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000, hops: zeroWeightHops },
    ValidationErrorCode.VALUE_OUT_OF_RANGE,
    "call.relayManifest.hops[0].weight",
  );

  const sparseHops = new Array(3);
  sparseHops[0] = kaigiRelayHops()[0];
  sparseHops[2] = kaigiRelayHops()[2];
  assertKaigiManifestRejected(
    { expiryMs: 1700111000000, hops: sparseHops },
    ValidationErrorCode.INVALID_OBJECT,
    "call.relayManifest.hops[1]",
  );
});

test("buildCreateKaigiInstruction normalizes relay manifest and metadata", () => {
  const instruction = buildCreateKaigiInstruction({
    id: { domainId: "wonderland.sora", callName: "weekly-sync" },
    host: ACCOUNT_ID,
    title: "Weekly Sync",
    description: "Roadmap alignment",
    maxParticipants: "16",
    gasRatePerMinute: 120,
    metadata: { topic: "status" },
    scheduledStartMs: "1700000000000",
    billingAccount: ACCOUNT_ID,
    privacyMode: "ZkRosterV1",
    roomPolicy: "public",
    relayManifest: {
      expiryMs: 1700111000000,
      hops: kaigiRelayHops(),
    },
  });
  const expected = {
    Kaigi: {
      CreateKaigi: {
        call: {
          id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
          host: ACCOUNT_ID_CANONICAL,
          title: "Weekly Sync",
          description: "Roadmap alignment",
          max_participants: 16,
          gas_rate_per_minute: 120,
          metadata: { topic: "status" },
          scheduled_start_ms: 1700000000000,
          billing_account: ACCOUNT_ID_CANONICAL,
          privacy_mode: { mode: "ZkRosterV1", state: null },
          room_policy: { policy: "Public", state: null },
          relay_manifest: {
            expiry_ms: 1700111000000,
            hops: normalizedKaigiRelayHops(),
          },
        },
        commitment: null,
        nullifier: null,
        roster_root: null,
        proof: null,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
  const encoded = assertNativeInstructionAdapterParity(
    instruction,
    "Kaigi.CreateKaigi",
  );
  assert.equal(encoded[39], 0x02, "Kaigi.CreateKaigi must use compact Norito framing");
});

test("noritoDecodeInstruction decodes Kaigi manifests", () => {
  const instruction = buildCreateKaigiInstruction({
    id: "wonderland.sora:weekly-sync",
    host: ACCOUNT_ID,
    gasRatePerMinute: 120,
    relayManifest: {
      expiryMs: 1700111000000,
      hops: kaigiRelayHops(),
    },
  });
  const encoded = noritoEncodeInstruction(instruction, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(canonicalizeClone(decoded), canonicalizeClone(instruction));
});

test("buildCreateKaigiInstruction accepts privacy artifacts", () => {
  const commitmentBytes = Buffer.alloc(32, 0x14);
  const nullifierBytes = Buffer.alloc(32, 0x25);
  const rosterRootBytes = Buffer.alloc(32, 0x66);
  const proofBytes = Buffer.from([0xca, 0xfe]);
  const instruction = buildCreateKaigiInstruction({
    id: "wonderland.sora:private-room",
    host: ACCOUNT_ID,
    privacyMode: "ZkRosterV1",
    commitment: { commitment: commitmentBytes },
    nullifier: { digest: nullifierBytes },
    rosterRoot: rosterRootBytes,
    proof: proofBytes,
  });
  const expected = {
    Kaigi: {
      CreateKaigi: {
        call: {
          id: { domain_id: "wonderland.sora", call_name: "private-room" },
          host: ACCOUNT_ID_CANONICAL,
          title: null,
          description: null,
          max_participants: null,
          gas_rate_per_minute: 0,
          metadata: {},
          scheduled_start_ms: null,
          billing_account: null,
          privacy_mode: { mode: "ZkRosterV1", state: null },
          room_policy: { policy: "Authenticated", state: null },
          relay_manifest: null,
        },
        commitment: {
          commitment: Array.from(commitmentBytes),
        },
        nullifier: {
          digest: Array.from(nullifierBytes),
        },
        roster_root: normalizedHashHex(rosterRootBytes),
        proof: proofBytes.toString("base64"),
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("buildJoinKaigiInstruction normalizes buffers and hashes", () => {
  const commitmentBytes = Buffer.alloc(32, 0x11);
  const nullifierBytes = Buffer.alloc(32, 0x22);
  const rosterRootBytes = Buffer.alloc(32, 0x33);
  const proofBytes = Buffer.from([0xaa, 0xbb, 0xcc]);
  const instruction = buildJoinKaigiInstruction({
    callId: "wonderland.sora:weekly-sync",
    participant: ACCOUNT_ID,
    commitment: {
      commitment: commitmentBytes,
    },
    nullifier: {
      digest: nullifierBytes,
    },
    rosterRoot: rosterRootBytes,
    proof: proofBytes,
  });
  const expected = {
    Kaigi: {
      JoinKaigi: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        participant: ACCOUNT_ID_CANONICAL,
        commitment: {
          commitment: Array.from(commitmentBytes),
        },
        nullifier: {
          digest: Array.from(nullifierBytes),
        },
        roster_root: normalizedHashHex(rosterRootBytes),
        proof: proofBytes.toString("base64"),
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("buildLeaveKaigiInstruction accepts minimal payload", () => {
  const instruction = buildLeaveKaigiInstruction({
    callId: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
    participant: ACCOUNT_ID,
  });
  const expected = {
    Kaigi: {
      LeaveKaigi: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        participant: ACCOUNT_ID_CANONICAL,
        commitment: null,
        nullifier: null,
        roster_root: null,
        proof: null,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("final Kaigi V1 instructions match the native scalar wire fixture", () => {
  const fixture = JSON.parse(fs.readFileSync(new URL(
    "./fixtures/kaigi_authorization_scalar_wire_v1.json", import.meta.url,
  ), "utf8"));
  assert.equal(fixture.length, 5);
  withNativeInstructionCodec(({ noritoEncodeInstruction: encode, noritoDecodeInstruction: decode }) => {
    for (const { instruction, wire_base64: wire } of fixture) {
      const bytes = Buffer.from(wire, "base64");
      assert.deepEqual(encode(instruction, 753), bytes);
      assert.deepEqual(decode(bytes, 753), instruction);
    }
  });
});

test("final Kaigi V1 scalar codec preserves every bit and rejects field mutations", () => {
  const modulus = Buffer.from("01000000ed302d991bf94c09fc98462200000000000000000000000000000040", "hex");
  const maximum = Buffer.from(modulus);
  maximum[0] -= 1;
  const commitment = Buffer.alloc(32, 0x12);
  const nullifier = Buffer.alloc(32, 0x24);
  const cases = [
    buildCreateKaigiInstruction({ id: "wonderland.sora:scalars", host: ACCOUNT_ID,
      commitment: { commitment }, nullifier: { digest: nullifier } }),
    buildJoinKaigiInstruction({ callId: "wonderland.sora:scalars", participant: ACCOUNT_ID,
      commitment: { commitment: maximum }, nullifier: { digest: Buffer.alloc(32) } }),
    buildEndKaigiInstruction({ callId: "wonderland.sora:scalars",
      commitment: { commitment }, nullifier: { digest: nullifier } }),
    buildRecordKaigiUsageInstruction({ callId: "wonderland.sora:scalars", durationMs: 1,
      usageCommitment: maximum }),
  ];
  withNativeInstructionCodec(({ noritoEncodeInstruction: encode, noritoDecodeInstruction: decode }) => {
    for (const instruction of cases) {
      assert.deepEqual(decode(encode(instruction, 753), 753), instruction);
    }
    for (const invalid of [modulus, Buffer.alloc(32, 0xff), Buffer.alloc(31),
      Buffer.alloc(33), "12".repeat(32), new Array(32), Array(32).fill(256)]) {
      assert.throws(() => buildJoinKaigiInstruction({ callId: "wonderland.sora:scalars",
        participant: ACCOUNT_ID, commitment: { commitment: invalid } }));
      assert.throws(() => buildEndKaigiInstruction({ callId: "wonderland.sora:scalars",
        nullifier: { digest: invalid } }));
      assert.throws(() => buildRecordKaigiUsageInstruction({ callId: "wonderland.sora:scalars",
        durationMs: 1, usageCommitment: invalid }));
      const malformed = structuredClone(cases[0]);
      malformed.Kaigi.CreateKaigi.commitment.commitment = invalid;
      assert.throws(() => encode(malformed, 753));
    }
    for (const field of ["alias_tag", "aliasTag", "unknown"]) {
      const malformed = structuredClone(cases[0]);
      malformed.Kaigi.CreateKaigi.commitment[field] = null;
      assert.throws(() => encode(malformed, 753), {
        message: `CreateKaigi.commitment: JSON error: unknown field \`${field}\``,
      });
    }
    for (const field of ["issued_at_ms", "issuedAtMs", "issuedAt", "hash"]) {
      assert.throws(() => buildJoinKaigiInstruction({ callId: "wonderland.sora:scalars",
        participant: ACCOUNT_ID, nullifier: { digest: nullifier, [field]: 0 } }),
      /requires only digest/u);
      const malformed = structuredClone(cases[0]);
      malformed.Kaigi.CreateKaigi.nullifier[field] = 0;
      assert.throws(() => encode(malformed, 753), {
        message: `CreateKaigi.nullifier: JSON error: unknown field \`${field}\``,
      });
    }
  });
});

test("final Kaigi V1 leave carries exact authorization artifacts", () => {
  const commitment = Buffer.alloc(32, 0x12);
  const nullifier = Buffer.alloc(32, 0x24);
  const instruction = buildLeaveKaigiInstruction({
    callId: "wonderland.sora:weekly-sync",
    participant: ACCOUNT_ID,
    commitment: { commitment },
    nullifier: { digest: nullifier },
    rosterRoot: Buffer.alloc(32, 0x31),
    proof: Buffer.from([0x01]),
  });
  assert.deepEqual(instruction.Kaigi.LeaveKaigi.commitment, { commitment: Array.from(commitment) });
  assert.deepEqual(instruction.Kaigi.LeaveKaigi.nullifier, { digest: Array.from(nullifier) });
  withNativeInstructionCodec(({ noritoEncodeInstruction: encode, noritoDecodeInstruction: decode }) => {
    assert.deepEqual(decode(encode(instruction, 753), 753), instruction);
  });
});

baseTest("Kaigi builders preserve full-width u64 values and the participant limit", () => {
  const maxU64 = "18446744073709551615";
  const maxParticipants = KAIGI_MAX_PARTICIPANTS_V1;
  assert.equal(maxParticipants, 4_096);
  const create = buildCreateKaigiInstruction({
    id: "wonderland.sora:full-width",
    host: ACCOUNT_ID,
    maxParticipants,
    gasRatePerMinute: BigInt(maxU64),
    scheduledStartMs: maxU64,
    relayManifest: {
      expiryMs: maxU64,
      hops: kaigiRelayHops(),
    },
  });
  assert.equal(create.Kaigi.CreateKaigi.call.max_participants, maxParticipants);
  assert.equal(create.Kaigi.CreateKaigi.call.gas_rate_per_minute, maxU64);
  assert.equal(create.Kaigi.CreateKaigi.call.scheduled_start_ms, maxU64);
  assert.equal(create.Kaigi.CreateKaigi.call.relay_manifest.expiry_ms, maxU64);
  assert.deepEqual(encodeAndDecode(create), create);

  const usage = buildRecordKaigiUsageInstruction({
    callId: "wonderland.sora:full-width",
    durationMs: BigInt(maxU64),
    billedGas: maxU64,
  });
  assert.equal(usage.Kaigi.RecordKaigiUsage.duration_ms, maxU64);
  assert.equal(usage.Kaigi.RecordKaigiUsage.billed_gas, maxU64);
  assert.deepEqual(encodeAndDecode(usage), usage);

  const end = buildEndKaigiInstruction({
    callId: "wonderland.sora:full-width",
    endedAtMs: maxU64,
  });
  assert.equal(end.Kaigi.EndKaigi.ended_at_ms, maxU64);
  assert.deepEqual(encodeAndDecode(end), end);

  const health = buildReportKaigiRelayHealthInstruction({
    callId: "wonderland.sora:full-width",
    relayId: RELAY_ACCOUNT_ID,
    status: "Healthy",
    reportedAtMs: maxU64,
  });
  assert.equal(health.Kaigi.ReportKaigiRelayHealth.reported_at_ms, maxU64);
  assert.deepEqual(encodeAndDecode(health), health);
});

baseTest("Kaigi builders reject values outside their protocol bounds", () => {
  const overflowU64 = "18446744073709551616";
  assert.throws(
    () =>
      buildRecordKaigiUsageInstruction({
        callId: "wonderland.sora:overflow",
        durationMs: overflowU64,
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(error?.path, "recordKaigiUsage.durationMs");
      return true;
    },
  );
  assert.throws(
    () =>
      buildCreateKaigiInstruction({
        id: "wonderland.sora:overflow",
        host: ACCOUNT_ID,
        maxParticipants: 4_097,
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(error?.path, "call.maxParticipants");
      return true;
    },
  );
});

test("buildEndKaigiInstruction normalizes optional timestamp", () => {
  const instruction = buildEndKaigiInstruction({
    callId: "wonderland.sora:weekly-sync",
    endedAtMs: "1700001234567",
  });
  const expected = {
    Kaigi: {
      EndKaigi: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        ended_at_ms: 1700001234567,
        commitment: null,
        nullifier: null,
        roster_root: null,
        proof: null,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("buildEndKaigiInstruction accepts privacy artifacts", () => {
  const commitmentBytes = Buffer.alloc(32, 0x17);
  const nullifierBytes = Buffer.alloc(32, 0x28);
  const rosterRootBytes = Buffer.alloc(32, 0x99);
  const proofBytes = Buffer.from([0xaa, 0xbb, 0xcc]);
  const instruction = buildEndKaigiInstruction({
    callId: "wonderland.sora:weekly-sync",
    commitment: { commitment: commitmentBytes },
    nullifier: { digest: nullifierBytes },
    rosterRoot: rosterRootBytes,
    proof: proofBytes,
  });
  const expected = {
    Kaigi: {
      EndKaigi: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        ended_at_ms: null,
        commitment: {
          commitment: Array.from(commitmentBytes),
        },
        nullifier: {
          digest: Array.from(nullifierBytes),
        },
        roster_root: normalizedHashHex(rosterRootBytes),
        proof: proofBytes.toString("base64"),
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

baseTest("Kaigi privacy builders reject ledger-visible identity hints", () => {
  const commitment = Buffer.alloc(32, 0x77);
  const nullifier = Buffer.alloc(32, 0x88);
  assert.throws(
    () =>
      buildCreateKaigiInstruction({
        id: "wonderland.sora:private-room",
        host: ACCOUNT_ID,
        privacyMode: "ZkRosterV1",
        commitment: { commitment, aliasTag: "host" },
      }),
    /requires only commitment/u,
  );
  assert.throws(
    () =>
      buildEndKaigiInstruction({
        callId: "wonderland.sora:private-room",
        nullifier: { digest: nullifier, issuedAtMs: 1 },
      }),
    /requires only digest/u,
  );
  assert.throws(
    () =>
      buildEndKaigiInstruction({
        callId: "wonderland.sora:private-room",
        nullifier: {
          digest: nullifier,
          issuedAtMs: 1,
        },
      }),
    /requires only digest/u,
  );
  assert.throws(
    () =>
      buildCreateKaigiInstruction({
        id: "wonderland.sora:private-room",
        host: ACCOUNT_ID,
        privacyMode: { mode: "ZkRosterV1", state: { alias: "host" } },
      }),
    /privacyMode\.state must be null/u,
  );
  assert.throws(
    () =>
      buildCreateKaigiInstruction({
        id: "wonderland.sora:private-room",
        host: ACCOUNT_ID,
        roomPolicy: { policy: "Authenticated", state: "hidden" },
      }),
    /roomPolicy\.state must be null/u,
  );
});

test("buildRecordKaigiUsageInstruction handles optional commitment", () => {
  const usageCommitment = Buffer.alloc(32, 0x25);
  const proof = Buffer.from([0xde, 0xad]);
  const instruction = buildRecordKaigiUsageInstruction({
    callId: "wonderland.sora:weekly-sync",
    durationMs: 60000,
    billedGas: "512",
    usageCommitment,
    proof,
  });
  const expected = {
    Kaigi: {
      RecordKaigiUsage: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        duration_ms: 60000,
        billed_gas: 512,
        usage_commitment: Array.from(usageCommitment),
        proof: proof.toString("base64"),
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("buildSetKaigiRelayManifestInstruction allows clearing manifest", () => {
  const instruction = buildSetKaigiRelayManifestInstruction({
    callId: "wonderland.sora:weekly-sync",
    relayManifest: null,
  });
  const expected = {
    Kaigi: {
      SetKaigiRelayManifest: {
        call_id: { domain_id: "wonderland.sora", call_name: "weekly-sync" },
        relay_manifest: null,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
});

test("buildRegisterKaigiRelayInstruction encodes hpke key", () => {
  const instruction = buildRegisterKaigiRelayInstruction({
    relayId: RELAY_ACCOUNT_ID,
    hpkePublicKey: Buffer.alloc(32, 0xaa),
    bandwidthClass: 7,
  });
  const expected = {
    Kaigi: {
      RegisterKaigiRelay: {
        relay: {
          relay_id: RELAY_ACCOUNT_ID,
          hpke_public_key: "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
          bandwidth_class: 7,
        },
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
  assertNativeInstructionAdapterParity(
    instruction,
    "Kaigi.RegisterKaigiRelay",
  );
});

test("buildUnregisterKaigiRelayInstruction encodes the canonical relay id", () => {
  const instruction = buildUnregisterKaigiRelayInstruction({
    relayId: RELAY_ACCOUNT_ID,
  });
  const expected = {
    Kaigi: {
      UnregisterKaigiRelay: {
        relay_id: RELAY_ACCOUNT_ID,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
  assertNativeInstructionAdapterParity(
    instruction,
    "Kaigi.UnregisterKaigiRelay",
  );
});

baseTest("RegisterKaigiRelay requires a non-zero bandwidth class", () => {
  const baseRelay = {
    relayId: RELAY_ACCOUNT_ID,
    hpkePublicKey: Buffer.alloc(32, 0xaa),
  };
  for (const [bandwidthClass, code] of [
    [undefined, ValidationErrorCode.INVALID_NUMERIC],
    [0, ValidationErrorCode.VALUE_OUT_OF_RANGE],
  ]) {
    assert.throws(
      () =>
        buildRegisterKaigiRelayInstruction({
          ...baseRelay,
          ...(bandwidthClass === undefined ? {} : { bandwidthClass }),
        }),
      (error) => {
        assert.equal(error?.code, code);
        assert.equal(error?.path, "registerKaigiRelay.bandwidthClass");
        return true;
      },
    );
  }
});

test("RegisterKaigiRelay encodes its HPKE key as a Norito Vec<u8>", () => {
  const hpkePublicKey = Buffer.alloc(32, 0xaa);
  const instruction = buildRegisterKaigiRelayInstruction({
    relayId: RELAY_ACCOUNT_ID,
    hpkePublicKey,
    bandwidthClass: 7,
  });
  const encoded = Buffer.from(
    withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(instruction, 753)),
  );
  const keyOffset = encoded.indexOf(hpkePublicKey);
  assert.ok(keyOffset >= 8, "encoded HPKE key must have a Vec length prefix");
  const expectedLength = Buffer.alloc(8);
  expectedLength.writeBigUInt64LE(BigInt(hpkePublicKey.length));
  assert.deepEqual(encoded.subarray(keyOffset - 8, keyOffset), expectedLength);
  assert.deepEqual(
    withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(encoded, 753)),
    instruction,
  );
});

test("buildReportKaigiRelayHealthInstruction normalizes relay feedback", () => {
  const instruction = buildReportKaigiRelayHealthInstruction({
    callId: "wonderland.sora:weekly-sync",
    relayId: RELAY_ACCOUNT_ID,
    status: "Degraded",
    reportedAtMs: "1701123456789",
    notes: "latency spike observed",
  });
  const expected = {
    Kaigi: {
      ReportKaigiRelayHealth: {
        call_id: {
          domain_id: "wonderland.sora",
          call_name: "weekly-sync",
        },
        relay_id: RELAY_ACCOUNT_ID,
        status: { status: "Degraded", state: null },
        reported_at_ms: 1701123456789,
        notes: "latency spike observed",
      },
    },
  };
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);
  assertNativeInstructionAdapterParity(
    instruction,
    "Kaigi.ReportKaigiRelayHealth",
  );
});

baseTest("ReportKaigiRelayHealth validates status, timestamp, and notes", () => {
  const report = {
    callId: "wonderland.sora:weekly-sync",
    relayId: RELAY_ACCOUNT_ID,
    status: "Healthy",
    reportedAtMs: 7,
  };
  const accepted = buildReportKaigiRelayHealthInstruction({
    ...report,
    notes: "😀".repeat(512),
  });
  assert.equal(
    Array.from(accepted.Kaigi.ReportKaigiRelayHealth.notes).length,
    512,
  );
  assert.deepEqual(
    buildReportKaigiRelayHealthInstruction({
      ...report,
      callId: "Wonderland.SORA:cafe\u0301",
    }).Kaigi.ReportKaigiRelayHealth.call_id,
    {
      domain_id: "wonderland.sora",
      call_name: "caf\u00e9",
    },
  );

  for (const [override, code, path] of [
    [
      { callId: "wonderland.sora:bad\u0000name" },
      ValidationErrorCode.INVALID_STRING,
      "reportKaigiRelayHealth.callId.call_name",
    ],
    [
      { callId: "wonderland:weekly-sync" },
      ValidationErrorCode.INVALID_STRING,
      "reportKaigiRelayHealth.callId.domain_id",
    ],
    [
      { relayId: "not-an-account" },
      ValidationErrorCode.INVALID_ACCOUNT_ID,
      "reportKaigiRelayHealth.relayId",
    ],
    [
      { status: "healthy" },
      ValidationErrorCode.INVALID_STRING,
      "reportKaigiRelayHealth.status",
    ],
    [
      { reportedAtMs: -1 },
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      "reportKaigiRelayHealth.reportedAtMs",
    ],
    [
      { notes: "😀".repeat(513) },
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      "reportKaigiRelayHealth.notes",
    ],
    [
      { notes: "\ud800" },
      ValidationErrorCode.INVALID_STRING,
      "reportKaigiRelayHealth.notes",
    ],
  ]) {
    assert.throws(
      () => buildReportKaigiRelayHealthInstruction({ ...report, ...override }),
      (error) => {
        assert.equal(error?.code, code);
        assert.equal(error?.path, path);
        return true;
      },
    );
  }
});

baseTest("ReportKaigiRelayHealth native instruction adapter preserves canonical field order", () => {
  const instruction = buildReportKaigiRelayHealthInstruction({
    callId: "wonderland.sora:weekly-sync",
    relayId: RELAY_ACCOUNT_ID,
    status: "Degraded",
    reportedAtMs: 1701123456789,
    notes: "latency spike observed",
  });
  withNativeInstructionCodec(({ noritoEncodeInstruction }) => {
    const encoded = noritoEncodeInstruction(instruction, 753);
    const outer = validateNoritoFrame(encoded);
    assert.equal(outer.flags, 0x02);
    const wire = readCompactFieldPayload(
      outer.payload,
      0,
      "ReportKaigiRelayHealth.wire",
    );
    const wireValue = readCompactFieldPayload(
      wire.payload,
      0,
      "ReportKaigiRelayHealth.wire.value",
    );
    assert.equal(wireValue.next, wire.payload.length);
    assert.equal(
      wireValue.payload.toString("utf8"),
      "iroha.instruction.v1::kaigi::ReportKaigiRelayHealth",
    );
    const innerField = readCompactFieldPayload(
      outer.payload,
      wire.next,
      "ReportKaigiRelayHealth.inner",
    );
    assert.equal(innerField.next, outer.payload.length);
    const innerFrameLength = Number(innerField.payload.readBigUInt64LE(0));
    const innerFrame = innerField.payload.subarray(8);
    assert.equal(innerFrame.length, innerFrameLength);
    const inner = validateNoritoFrame(innerFrame, {
      expectedTypeName:
        "iroha_data_model::isi::kaigi::ReportKaigiRelayHealth",
      expectedPaddingLength: 0,
    });
    const callId = readCompactFieldPayload(
      inner.payload,
      0,
      "ReportKaigiRelayHealth.call_id",
    );
    const relayId = readCompactFieldPayload(
      inner.payload,
      callId.next,
      "ReportKaigiRelayHealth.relay_id",
    );
    const status = readCompactFieldPayload(
      inner.payload,
      relayId.next,
      "ReportKaigiRelayHealth.status",
    );
    const reportedAt = readCompactFieldPayload(
      inner.payload,
      status.next,
      "ReportKaigiRelayHealth.reported_at_ms",
    );
    const notes = readCompactFieldPayload(
      inner.payload,
      reportedAt.next,
      "ReportKaigiRelayHealth.notes",
    );
    assert.equal(notes.next, inner.payload.length);
    assert.deepEqual(status.payload, Buffer.from([1, 0, 0, 0]));
    assert.equal(reportedAt.payload.readBigUInt64LE(0), 1701123456789n);
    assert.equal(notes.payload[0], 1);
    assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);
  });
});

baseTest("buildRegisterSmartContractCodeInstruction normalizes manifest fields", () => {
  const codeHashBytes = Buffer.alloc(32, 0xaa);
  codeHashBytes[31] |= 1;
  const abiHashBytes = Buffer.alloc(32, 0xbb);
  const signer = `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`;
  const signature = `ed25519:${"22".repeat(64)}`;
  const signerCanonical = signer.split(":")[1];
  const signatureCanonical = signature.split(":")[1].toUpperCase();
  const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({
    manifest: {
      permissions: [{ name: "can_upgrade", scope: { kind: "Instance", value: null } }], events: [], enum_types: [],
      seiyakuName: "Ledger",
      codeHash: codeHashBytes,
      abiHash: abiHashBytes,
      compilerFingerprint: "rustc-1.79",
      featuresBitmap: "3",
      accessSetHints: {
        readKeys: ["account:alice", "asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],
        writeKeys: ["contract:foo"],
        dynamicReads: [
          {
            baseKey: "state:Balances",
            keyType: "AccountId",
            boundKind: "take",
            maxKeys: "4",
          },
        ],
        dynamicWrites: [
          {
            base_key: "state:Votes",
            key_type: "Name",
            bound_kind: "page",
            max_keys: 2,
          },
        ],
      },
      entrypoints: [
        {
          name: "upgrade_ledger",
          kind: "Kotoage",
          ...UNIT_RETURN_DESCRIPTOR,
          authorization: { kind: "Permission", value: "can_upgrade" },
        },
      ],
      states: [
        { name: "Balances", typeName: "StateMap<AccountId, quantity>" },
        { name: "Votes", typeName: "StateMap<Name, bool>" },
        { name: "amount", typeName: "Fixture::Transfer{amount: quantity}" },
      ],
      errorTypes: [
        { identity: "LedgerError", variants: [{ name: "amount", code: 7 }] },
      ],
      errorMessages: [
        { error_type: "LedgerError", code: 7, message: "The transfer amount is invalid." },
      ],
      kotoba: [
        {
          msgId: "contract.title",
          translations: [{ lang: "en", text: "Ledger Contract" }],
        },
      ],
      provenance: {
        signer,
        signature,
      },
    },
  }));
  const expected = universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        permissions: [{ name: "can_upgrade", scope: { kind: "Instance", value: null } }], events: [], enum_types: [],
        seiyaku_name: "Ledger",
        code_hash: normalizedHashHex(codeHashBytes),
        abi_hash: normalizedHashHex(abiHashBytes),
        compiler_fingerprint: "rustc-1.79",
        features_bitmap: 3,
        access_set_hints: {
          read_keys: ["account:alice", "asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],
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
        entrypoints: [
          {
            name: "upgrade_ledger",
            kind: { kind: "Kotoage", value: null },
            params: [],
            argument_schema: null,
            return_type: "()",
            return_schema: { nodes: [{ kind: "Unit", value: null }] },
            authorization: { kind: "Permission", value: "can_upgrade" },
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
          { name: "amount", type_name: "Fixture::Transfer{amount: quantity}" },
        ],
        error_types: [
          { identity: "LedgerError", variants: [{ name: "amount", code: 7 }] },
        ],
        error_messages: [
          { error_type: "LedgerError", code: 7, message: "The transfer amount is invalid." },
        ],
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
    },
  });
  const expectedDecoded = universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        permissions: [], events: [], enum_types: [],
        ...expected.RegisterSmartContractCode.manifest,
      },
    },
  });
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expectedDecoded);
});

baseTest("smart-contract manifests reject unknown V1 feature bits", () => {
  assert.throws(
    () =>
      buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: { permissions: [], events: [], enum_types: [], featuresBitmap: 4 },
      })),
    /featuresBitmap contains unsupported Kotodama V1 feature bits/u,
  );
  assert.throws(
    () =>
      buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: { permissions: [], events: [], enum_types: [], features_bitmap: "4" },
      })),
    /featuresBitmap contains unsupported Kotodama V1 feature bits/u,
  );
});

baseTest("smart-contract dynamic access hints enforce the exact V1 contract", () => {
  const buildWithHint = (hint) =>
    buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [], events: [], enum_types: [],
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
    }));

  for (const baseKey of ["state:Balances", "state:amount"]) {
    assert.doesNotThrow(() => buildWithHint({ baseKey }));
  }
  for (const baseKey of [
    "state:",
    "state:*",
    "state:Balances/",
    "state:Balances/suffix",
    "state:Balances:suffix",
    "state:int",
    "account:alice",
    " state:Balances",
    "state:Balances ",
  ]) {
    assert.throws(
      () => buildWithHint({ baseKey }),
      /dynamicReads\[0\]\.baseKey must be state: plus one canonical state declaration identifier/u,
    );
  }
  for (const keyType of [
    "Json",
    "ReferendumId",
    "Int",
    "Quantity",
    "Amount",
    " AccountId",
  ]) {
    assert.throws(
      () => buildWithHint({ keyType }),
      /dynamicReads\[0\]\.keyType must be an exact Kotodama V1 StateMap key scalar/u,
    );
  }
  for (const [boundKind, expected] of [
    ["", /dynamicReads\[0\]\.boundKind must be a non-empty string/u],
    ["Take", /dynamicReads\[0\]\.boundKind must be exactly take or page/u],
    ["prefix", /dynamicReads\[0\]\.boundKind must be exactly take or page/u],
    ["range ", /dynamicReads\[0\]\.boundKind must be exactly take or page/u],
  ]) {
    assert.throws(
      () => buildWithHint({ boundKind }),
      expected,
    );
  }
  for (const maxKeys of [0, 65, 0xffff_ffff]) {
    assert.throws(
      () => buildWithHint({ maxKeys }),
      maxKeys === 0
        ? /dynamicReads\[0\]\.maxKeys must be positive/u
        : /dynamicReads\[0\]\.maxKeys must be at most 64/u,
    );
  }
  assert.doesNotThrow(() => buildWithHint({ maxKeys: 64 }));

  const equalAliases = buildWithHint({
    base_key: "state:Balances",
    key_type: "AccountId",
    bound_kind: "take",
    max_keys: 1,
  });
  assert.equal(
    equalAliases.RegisterSmartContractCode.manifest
      .access_set_hints.dynamic_reads[0].max_keys,
    1,
  );
  for (const conflicting of [
    { base_key: "state:Other" },
    { key_type: "Name" },
    { bound_kind: "range" },
    { max_keys: 2 },
  ]) {
    assert.throws(
      () => buildWithHint(conflicting),
      /contains conflicting .* aliases/u,
    );
  }
});

baseTest("smart-contract dynamic access hints resolve declared StateMaps per list", () => {
  const hint = {
    baseKey: "state:Balances",
    keyType: "AccountId",
    boundKind: "take",
    maxKeys: 1,
  };
  const build = ({
    dynamicReads = [],
    dynamicWrites = [],
    states = [{ name: "Balances", typeName: "StateMap<AccountId, quantity>" }],
  }) =>
    buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [], events: [], enum_types: [],
        states,
        accessSetHints: { dynamicReads, dynamicWrites },
      },
    }));

  for (const field of ["dynamicReads", "dynamicWrites"]) {
    assert.doesNotThrow(() =>
      build({
        [field]: [
          hint,
          { ...hint, boundKind: "page", maxKeys: 2 },
        ],
      }));
    assert.throws(
      () => build({ [field]: [hint, { ...hint }] }),
      /duplicates an earlier dynamic access hint/u,
      `${field} must reject an exact duplicate`,
    );
    assert.throws(
      () => build({
        [field]: [{ ...hint, baseKey: "state:Missing" }],
      }),
      /baseKey must reference a declared top-level StateMap/u,
      `${field} must reject an unknown state`,
    );
    assert.throws(
      () => build({
        [field]: [hint],
        states: [{ name: "Balances", typeName: "quantity" }],
      }),
      /baseKey must reference a declared top-level StateMap/u,
      `${field} must reject a scalar state`,
    );
    assert.throws(
      () => build({
        [field]: [{ ...hint, keyType: "Name" }],
      }),
      /keyType Name does not match declared StateMap key type AccountId/u,
      `${field} must reject a mismatched key scalar`,
    );
  }

  assert.doesNotThrow(() =>
    build({
      dynamicReads: [hint],
      dynamicWrites: [{ ...hint }],
    }));
  assert.doesNotThrow(() =>
    build({
      dynamicReads: [{
        ...hint,
        baseKey: "state:amount",
        keyType: "quantity",
      }],
      states: [{ name: "amount", typeName: "StateMap<quantity, int>" }],
    }));
  assert.throws(
    () =>
      build({
        dynamicReads: [hint],
        states: [
          { name: "Balances", typeName: "StateMap<AccountId, quantity>" },
          { name: "Balances", typeName: "StateMap<AccountId, quantity>" },
        ],
      }),
    /contains duplicate state name Balances/u,
  );
});

baseTest("smart-contract parameter and state type aliases must agree", () => {
  const quantity = {
    nodes: [{ kind: "Leaf", value: { kind: "Quantity", value: null } }],
  };
  const build = (param, state) =>
    buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [], events: [], enum_types: [],
        entrypoints: [{
          name: "read",
          kind: "View",
          authorization: { kind: "Anyone", value: null },
          ...UNIT_RETURN_DESCRIPTOR,
          params: [{ name: "amount", ...param }],
          argumentSchema: {
            fields: [{ name: "amount", ty: quantity }],
          },
        }],
        states: [{ name: "amount", ...state }],
      },
    }));

  assert.doesNotThrow(() =>
    build(
      { typeName: "quantity", type_name: "quantity" },
      { typeName: "quantity", type_name: "quantity" },
    ));
  assert.throws(
    () => build(
      { typeName: "quantity", type_name: "int" },
      { typeName: "quantity" },
    ),
    /params\[0\]\.type_name contains conflicting type_name\/typeName aliases/u,
  );
  assert.throws(
    () => build(
      { typeName: "quantity" },
      { typeName: "quantity", type_name: "int" },
    ),
    /states\[0\]\.type_name contains conflicting type_name\/typeName aliases/u,
  );
  assert.throws(
    () => build({}, { typeName: "quantity" }),
    /params\[0\]\.type_name must be a non-empty string/u,
  );
  assert.throws(
    () => build({ typeName: "quantity" }, {}),
    /states\[0\]\.type_name must be a non-empty string/u,
  );
});

baseTest("smart-contract manifest type declarations reject retired numeric names", () => {
  for (const seiyakuName of ["Amount", "amount"]) {
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: { permissions: [], events: [], enum_types: [], seiyakuName },
        })),
      /seiyakuName must be a canonical Kotodama V1 type declaration identifier/u,
    );
  }
  for (const typeName of [
    "Amount",
    "amount",
    "StateMap<AccountId, Amount>",
    "Transfer{amount: amount}",
  ]) {
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
            states: [{ name: "Balances", typeName }],
          },
        })),
      /states\[0\]\.type_name must be a canonical Kotodama V1 state type/u,
    );
  }
  for (const namespace of ["Invalid Error", "Error<Injected>"]) {
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
            errorTypes: [{ identity: namespace, variants: [{ name: "Denied", code: 7 }] }],
          },
        })),
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
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
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
          },
        })),
      /dynamicReads\[0\]\.keyType must be an exact Kotodama V1 StateMap key scalar/u,
    );
  }
});

baseTest("smart-contract entrypoint schemas exactly bind declared V1 types", () => {
  const quantity = {
    nodes: [{ kind: "Leaf", value: { kind: "Quantity", value: null } }],
  };
  const valid = buildRegisterSmartContractCodeInstruction(universalArtifactInput({
    manifest: {
      permissions: [], events: [], enum_types: [],
      entrypoints: [{
        name: "read",
        kind: "View",
        authorization: { kind: "Anyone", value: null },
        params: [{ name: "amount", typeName: "quantity" }],
        argumentSchema: {
          fields: [{ name: "amount", ty: quantity }],
        },
        returnType: "quantity",
        returnSchema: quantity,
      }],
    },
  }));
  assert.equal(
    valid.RegisterSmartContractCode.manifest.entrypoints[0].params[0].type_name,
    "quantity",
  );

  for (const retired of ["Amount", "amount"]) {
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
            entrypoints: [{
              name: "read",
              kind: "View",
              authorization: { kind: "Anyone", value: null },
              params: [{ name: "value", typeName: retired }],
              argumentSchema: {
                fields: [{ name: "value", ty: quantity }],
              },
            }],
          },
        })),
      /argument_schema\.fields\[0\] does not match its declared parameter/u,
    );
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
            entrypoints: [{
              name: "read",
              kind: "View",
              authorization: { kind: "Anyone", value: null },
              returnType: retired,
              returnSchema: quantity,
            }],
          },
        })),
      /return_schema does not match return_type/u,
    );
  }

  assert.throws(
    () =>
      buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: {
          permissions: [], events: [], enum_types: [],
          entrypoints: [{
            name: "read",
            kind: "View",
            authorization: { kind: "Anyone", value: null },
            params: [{ name: "value", typeName: "quantity" }],
          }],
        },
      })),
    /argument_schema is required for declared parameters/u,
  );
  assert.throws(
    () =>
      buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: {
          permissions: [], events: [], enum_types: [],
          entrypoints: [{
            name: "read",
            kind: "View",
            authorization: { kind: "Anyone", value: null },
            returnType: "quantity",
          }],
        },
      })),
    /return_type and return_schema must be present together/u,
  );
});

baseTest("smart-contract entrypoint kinds use only the V1 interface names", () => {
  for (const canonical of ["Kotoage", "View", "Hajimari", "Kaizen"]) {
    const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [{ name: "can_run", scope: { kind: "Instance", value: null } }], events: [], enum_types: [],
        entrypoints: [{
          name: canonical === "Hajimari" ? "hajimari" : canonical === "Kaizen" ? "kaizen" : "run",
          kind: canonical,
          authorization: {
            kind: canonical === "Kotoage" ? "Permission" : canonical === "View" ? "Anyone" : "RuntimeLifecycle",
            value: canonical === "Kotoage" ? "can_run" : null,
          },
          ...UNIT_RETURN_DESCRIPTOR,
        }],
      },
    }));
    assert.equal(
      instruction.RegisterSmartContractCode.manifest.entrypoints[0].kind.kind,
      canonical,
    );
  }

  for (const retired of ["Public", "public", "Init", "init", "Upgrade", "upgrade"]) {
    assert.throws(
      () =>
        buildRegisterSmartContractCodeInstruction(universalArtifactInput({
          manifest: {
            permissions: [], events: [], enum_types: [],
            entrypoints: [{ name: "legacy", kind: retired, authorization: { kind: "Anyone", value: null } }],
          },
        })),
      /must be one of 'Kotoage', 'View', 'Hajimari', or 'Kaizen'/,
    );
  }
});

baseTest("smart-contract branded entrypoint kinds preserve their Norito tag order", () => {
  for (const canonical of ["Kotoage", "View", "Hajimari", "Kaizen"]) {
    const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [{ name: "can_run", scope: { kind: "Instance", value: null } }], events: [], enum_types: [],
        entrypoints: [{
          name: canonical === "Hajimari" ? "hajimari" : canonical === "Kaizen" ? "kaizen" : "run",
          kind: canonical,
          authorization: {
            kind: canonical === "Kotoage" ? "Permission" : canonical === "View" ? "Anyone" : "RuntimeLifecycle",
            value: canonical === "Kotoage" ? "can_run" : null,
          },
          ...UNIT_RETURN_DESCRIPTOR,
        }],
      },
    }));
    assert.equal(
      encodeAndDecode(instruction).RegisterSmartContractCode.manifest.entrypoints[0].kind.kind,
      canonical,
    );
  }
});

baseTest("smart-contract schema builder enforces canonical flat-preorder V1 tapes", () => {
  const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
  const build = (nodes) =>
    buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: {
        permissions: [], events: [], enum_types: [],
        entrypoints: [
          {
            name: "read",
            kind: "View",
            authorization: { kind: "Anyone", value: null },
            returnType: analyzeEntrypointValueTypeV1({ nodes }).canonicalName,
            returnSchema: { nodes },
          },
        ],
      },
    }));

  const pair = [
    { kind: "Struct", value: { name: "Fixture::Pair", fields: ["left", "right"] } },
    leaf("Int"),
    leaf("Bool"),
  ];
  assert.deepEqual(
    build(pair).RegisterSmartContractCode.manifest.entrypoints[0].return_schema.nodes,
    pair,
  );
  assert.deepEqual(
    build([
      { kind: "List", value: { capacity: 64 } },
      leaf("Name"),
    ]).RegisterSmartContractCode.manifest.entrypoints[0].return_schema.nodes[0].value,
    { capacity: 64 },
  );

  for (const malformed of [
    [],
    [{ kind: "List", value: { capacity: 1 } }],
    [leaf("Int"), leaf("Bool")],
    [
      { kind: "List", value: { capacity: 1, element: { nodes: [leaf("Int")] } } },
      leaf("Int"),
    ],
    [{ kind: "List", value: { capacity: 0 } }, leaf("Int")],
    [{ kind: "List", value: { capacity: 65 } }, leaf("Int")],
    [
      ...Array.from({ length: 256 }, () => ({
        kind: "List",
        value: { capacity: 1 },
      })),
      leaf("Int"),
    ],
  ]) {
    assert.throws(() => build(malformed), /canonical|capacity|complete|only capacity/u);
  }

  for (const retired of ["U128", "Amount"]) {
    assert.throws(
      () => build([leaf(retired)]),
      /not a (?:canonical )?V1 entrypoint value kind/u,
    );
  }

  for (const [name, fields, children] of [
    ["AccountView", ["id", "metadata"], [leaf("AccountId"), leaf("Json")]],
    ["AssetView", ["id", "amount"], [leaf("AssetId"), leaf("Quantity")]],
    [
      "AssetDefinitionView",
      ["id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"],
      [
        leaf("AssetDefinitionId"),
        leaf("String"),
        { kind: "Option", value: null },
        leaf("String"),
        leaf("AccountId"),
        leaf("Quantity"),
        { kind: "Option", value: null },
        leaf("Int"),
        leaf("Json"),
      ],
    ],
    [
      "DomainView",
      ["id", "owned_by", "metadata"],
      [leaf("DomainId"), leaf("AccountId"), leaf("Json")],
    ],
    [
      "NftView",
      ["id", "owned_by", "content"],
      [leaf("NftId"), leaf("AccountId"), leaf("Json")],
    ],
  ]) {
    const canonical = [{ kind: "Struct", value: { name: `kotodama::${name}`, fields } }, ...children];
    assert.doesNotThrow(() => build(canonical));
    const forged = structuredClone(canonical);
    forged[1].value.kind = "Bool";
    assert.throws(() => build(forged), /forged reserved query-view/u);
  }
});

test("buildRegisterSmartContractBytesInstruction encodes bytes deterministically", () => {
  const codeBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const hashBytes = Buffer.alloc(32, 0xcc);
  const instruction = buildRegisterSmartContractBytesInstruction(universalArtifactInput({
    codeHash: hashBytes,
    code: codeBytes,
  }));
  const expected = universalArtifactInstruction({
    RegisterSmartContractBytes: {
      code_hash: normalizedHashHex(hashBytes),
      code: codeBytes.toString("base64"),
    },
  });
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expected);
});

test("buildRegisterSmartContractBytesInstruction rejects empty code bytes", () => {
  assert.throws(
    () =>
      buildRegisterSmartContractBytesInstruction(universalArtifactInput({
        codeHash: Buffer.alloc(32, 0x11),
        code: Buffer.alloc(0),
      })),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_STRING);
      assert.match(String(error?.message), /non-empty base64/i);
      return true;
    },
  );
});

test("buildRemoveSmartContractBytesInstruction accepts reason or null", () => {
  const instruction = buildRemoveSmartContractBytesInstruction(universalArtifactInput({
    codeHash: Buffer.alloc(32, 0x11),
    reason: "cleanup",
  }));
  const expected = universalArtifactInstruction({
    RemoveSmartContractBytes: {
      code_hash: normalizedHashHex(Buffer.alloc(32, 0x11)),
      reason: "cleanup",
    },
  });
  assert.deepEqual(instruction, expected);
  assert.deepEqual(encodeAndDecode(instruction), expected);

  const withoutReason = buildRemoveSmartContractBytesInstruction(universalArtifactInput({
    codeHash: Buffer.alloc(32, 0x22),
  }));
  assert.equal(withoutReason.RemoveSmartContractBytes.reason, undefined);
});

baseTest("every SDK instruction schema binding matches the Rust registry and inner type", () => {
  const rustBindings = readRustInstructionRegistryBindings();
  const jsBindings = _createNoritoInstructionApi(
    Object.freeze({}),
  )._instructionWireSchemaBindings();
  assert.ok(Object.isFrozen(jsBindings));
  assert.ok(jsBindings.length > 0, "JS instruction binding inventory must not be empty");
  assert.equal(
    new Set(jsBindings.map(({ outerWireId }) => outerWireId)).size,
    jsBindings.length,
    "JS instruction outer wire IDs must be unique",
  );

  for (const { outerWireId, innerTypeName } of jsBindings) {
    const registryTypeLabel = rustBindings.get(outerWireId);
    assert.notEqual(
      registryTypeLabel,
      undefined,
      `${outerWireId} must exist in the Rust instruction registry`,
    );
    assert.equal(
      innerTypeName,
      rustInstructionTypeName(registryTypeLabel),
      `${outerWireId} must retain the Rust registry type identity`,
    );
    assert.match(
      innerTypeName,
      /^iroha_data_model::isi::/u,
      `${outerWireId} inner schema must use a Rust data-model type name`,
    );
    assert.notEqual(
      innerTypeName,
      outerWireId,
      `${outerWireId} must not reuse its public wire ID as the inner schema name`,
    );
  }
});

test("smart-contract instructions bind canonical outer ids to Rust payload schemas", () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const hash = `${"aa".repeat(31)}ab`;
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "contract_manifest_v1.json"),
      "utf8",
    ),
  ).manifest;
  const cases = [
    [
      "RegisterSmartContractCode",
      buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest })),
    ],
    [
      "RegisterSmartContractBytes",
      buildRegisterSmartContractBytesInstruction(universalArtifactInput({
        codeHash: hash,
        code: Buffer.of(1),
      })),
    ],
    [
      "DeactivateContractInstance",
      {
        DeactivateContractInstance: {
          contract_address: contractAddress,
          expected_revision: "1",
          reason: null,
        },
      },
    ],
    [
      "ActivateContractInstance",
      {
        ActivateContractInstance: {
          contract_address: contractAddress,
          expected_revision: "2",
          code_hash: `hash:${hash.toUpperCase()}#${computeHashLiteralCrc("hash", hash.toUpperCase())}`,
        },
      },
    ],
    [
      "SetContractParliamentDelegation",
      {
        SetContractParliamentDelegation: {
          contract_address: contractAddress,
          expected_revision: "3",
          delegated: true,
        },
      },
    ],
    [
      "OfferContractOwnership",
      {
        OfferContractOwnership: {
          contract_address: contractAddress,
          expected_revision: "4",
          new_owner: { owner: "Parliament", value: null },
        },
      },
    ],
    [
      "AcceptContractOwnership",
      {
        AcceptContractOwnership: {
          contract_address: contractAddress,
          expected_revision: "5",
        },
      },
    ],
    [
      "CancelContractOwnershipOffer",
      {
        CancelContractOwnershipOffer: {
          contract_address: contractAddress,
          expected_revision: "6",
        },
      },
    ],
    [
      "CommitContractDeployment",
      buildCommitContractDeploymentInstruction({
        expectedDeployNonce: 7,
        contractAddress,
        codeHash: hash,
        contractAlias: "ledger::nexus",
      }),
    ],
    [
      "UploadSmartContractCodeChunk",
      buildUploadSmartContractCodeChunkInstruction(universalArtifactInput({
        codeHash: hash,
        totalSize: 1,
        chunkIndex: 0,
        chunkCount: 1,
        chunk: Buffer.of(1),
      })),
    ],
    [
      "FinalizeSmartContractCodeUpload",
      buildFinalizeSmartContractCodeUploadInstruction(universalArtifactInput({
        codeHash: hash,
        totalSize: 1,
        chunkCount: 1,
      })),
    ],
    [
      "CancelSmartContractCodeUpload",
      buildCancelSmartContractCodeUploadInstruction(universalArtifactInput({ codeHash: hash })),
    ],
    [
      "RemoveSmartContractBytes",
      buildRemoveSmartContractBytesInstruction(universalArtifactInput({ codeHash: hash })),
    ],
  ];

  withNativeInstructionCodec(({ noritoEncodeInstruction }) => {
    assert.throws(
      () => noritoEncodeInstruction(buildCommitContractDeploymentInstruction({
        expectedDeployNonce: 7, contractAddress, codeHash: hash, contractAlias: "ledger",
      }), 753),
      /CommitContractDeployment.contract_alias: invalid contract alias/,
    );
    for (const [name, instruction] of cases) {
      const identity = readInstructionEnvelopeIdentity(
        noritoEncodeInstruction(instruction, 753),
        name,
      );
      assert.equal(
        identity.wireId,
        `iroha.instruction.v1::smart_contract_code::${name}`,
      );
      assert.deepEqual(
        identity.innerSchemaHash,
        rustTypeSchemaHash(
          `iroha_data_model::isi::smart_contract_code::${name}`,
        ),
      );
    }
  });
});

test("buildProposeDeployContractInstruction normalizes the typed V1 payload", () => {
  const instruction = buildProposeDeployContractInstruction({
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: `blake2b32:0x${"AA".repeat(32)}`,
    abiHash: `0X${"BB".repeat(32)}`,
    abiVersion: 1,
  });
  const expected = {
    ProposeDeployContract: {
      contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      code_hash: "aa".repeat(32),
      abi_hash: "bb".repeat(32),
      abi_version: 1,
    },
  };
  assert.deepEqual(instruction, expected);
  const decoded = withNativeInstructionCodec((codec) =>
    encodeAndDecode(instruction, codec));
  assert.deepEqual(decoded, expected);
  withNativeInstructionCodec(({ noritoEncodeInstruction }) => {
    const identity = readInstructionEnvelopeIdentity(
      noritoEncodeInstruction(instruction, 753),
      "ProposeDeployContract",
    );
    assert.equal(
      identity.wireId,
      "iroha.instruction.v1::governance::ProposeDeployContract",
    );
    assert.deepEqual(
      identity.innerSchemaHash,
      rustTypeSchemaHash(
        "iroha_data_model::isi::governance::ProposeDeployContract",
      ),
    );
  });
});

test("buildProposeDeployContractInstruction encodes optional manifest provenance", () => {
  const instruction = buildProposeDeployContractInstruction({
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
    manifestProvenance: {
      signer: `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
      signature: `ed25519:${"22".repeat(64)}`,
    },
  });
  assert.deepEqual(instruction.ProposeDeployContract.manifest_provenance, {
    signer: `ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
    signature: "22".repeat(64).toUpperCase(),
  });
  assert.equal(Object.hasOwn(instruction.ProposeDeployContract, "limits"), false);

  const decoded = withNativeInstructionCodec((codec) =>
    encodeAndDecode(instruction, codec));
  assert.deepEqual(
    decoded.ProposeDeployContract.manifest_provenance,
    instruction.ProposeDeployContract.manifest_provenance,
  );
  assert.equal(Object.hasOwn(decoded.ProposeDeployContract, "limits"), false);
});

baseTest("buildProposeDeployContractInstruction validates ML-DSA manifest signer keys", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  const withSigner = (signer) => ({
    ...base,
    manifestProvenance: {
      signer,
      signature: "22".repeat(64),
    },
  });

  const validSigner = mlDsaManifestSigner(1_952);
  const instruction = buildProposeDeployContractInstruction(withSigner(validSigner));
  assert.equal(
    instruction.ProposeDeployContract.manifest_provenance.signer,
    `ee01a00f${"5A".repeat(1_952)}`,
  );

  for (const [label, signer, errorPattern] of [
    ["one-byte", mlDsaManifestSigner(1), /expected 1952 bytes/u],
    ["short", mlDsaManifestSigner(1_951), /expected 1952 bytes/u],
    ["overlong", mlDsaManifestSigner(1_953), /expected 1952 bytes/u],
    ["all-zero", mlDsaManifestSigner(1_952, 0), /all-zero/u],
  ]) {
    assert.throws(
      () => buildProposeDeployContractInstruction(withSigner(signer)),
      errorPattern,
      `${label} ML-DSA signer must be rejected before instruction emission`,
    );
  }
});

baseTest("buildProposeDeployContractInstruction has a closed canonical local target", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  for (const field of [
    "proposalOperator",
    "contractAlias",
    "contract_address",
    "code_hash",
    "abi_hash",
    "abi_version",
    "window",
    "votingMode",
    "mode",
    "limits",
    "manifest_provenance",
  ]) {
    assert.throws(
      () => buildProposeDeployContractInstruction({ ...base, [field]: "retired" }),
      new RegExp(field, "u"),
    );
  }
  for (const contractAddress of [
    base.contractAddress.toUpperCase(),
    ` ${base.contractAddress}`,
    `${base.contractAddress.slice(0, -1)}p`,
    "merchant@paynet",
  ]) {
    assert.throws(
      () => buildProposeDeployContractInstruction({ ...base, contractAddress }),
      /contractAddress|contract address|Bech32/u,
    );
  }
});

baseTest("buildProposeDeployContractInstruction accepts only numeric ABI V1", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  for (const abiVersion of ["1", "01", "1 ", "2", 0, 2, 1n, null]) {
    assert.throws(
      () => buildProposeDeployContractInstruction({ ...base, abiVersion }),
      /exactly 1/u,
    );
  }
  assert.equal(
    buildProposeDeployContractInstruction({ ...base, abiVersion: 1 })
      .ProposeDeployContract.abi_version,
    1,
  );
});

baseTest("buildProposeDeployContractInstruction enforces the governance hash grammar", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  for (const codeHash of [
    ` ${"aa".repeat(32)}`,
    `${"aa".repeat(32)} `,
    `sha256:${"aa".repeat(32)}`,
    `blake2b32:${"aa".repeat(31)}`,
    `blake2b32:0x${"gg".repeat(32)}`,
  ]) {
    assert.throws(
      () => buildProposeDeployContractInstruction({ ...base, codeHash }),
      /codeHash/u,
    );
  }
});

baseTest("governance proposal builder rejects every private-key alias recursively", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  for (const alias of [
    "private_key",
    "privateKey",
    "private_key_hex",
    "privateKeyHex",
    "private_key_bytes",
    "privateKeyBytes",
    "private_key_seed",
    "privateKeySeed",
    "private_key_multihash",
    "privateKeyMultihash",
    "private_key_algorithm",
    "privateKeyAlgorithm",
  ]) {
    assert.throws(
      () =>
        buildProposeDeployContractInstruction({
          ...base,
          nested: [{ [alias]: "secret" }],
        }),
      new RegExp(alias, "u"),
    );
  }
});

test("buildProposeDeployContractInstruction rejects retired lifecycle controls", () => {
  const base = {
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: "aa".repeat(32),
    abiHash: "bb".repeat(32),
  };
  for (const field of ["window", "votingMode", "mode"]) {
    assert.throws(
      () => buildProposeDeployContractInstruction({ ...base, [field]: null }),
      new RegExp(field, "u"),
    );
  }

  for (const field of [
    "proposal_operator",
    "window",
    "mode",
    "code_hash_hex",
    "abi_hash_hex",
  ]) {
    assert.throws(
      () =>
        noritoEncodeInstruction({
          ProposeDeployContract: {
            contract_address: base.contractAddress,
            code_hash: base.codeHash,
            abi_hash: base.abiHash,
            abi_version: 1,
            [field]: null,
          },
        }, 753),
      new RegExp(field, "u"),
    );
  }
});

baseTest("buildCastZkBallotInstruction encodes proof and closed public inputs", () => {
  const publicInputs = { direction: "Aye" };
  const instruction = buildCastZkBallotInstruction({
    electionId: "ref-1",
    proof: Buffer.from([0x01, 0x02]),
    publicInputs,
  });
  const expected = {
    CastZkBallot: {
      election_id: "ref-1",
      proof_b64: Buffer.from([0x01, 0x02]).toString("base64"),
      public_inputs_json: JSON.stringify(publicInputs),
    },
  };
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expected);
});

baseTest("buildCastZkBallotInstruction defaults public inputs to empty object", () => {
  const instruction = buildCastZkBallotInstruction({
    electionId: "ref-2",
    proof: Buffer.from([0x03]),
  });
  assert.equal(instruction.CastZkBallot.public_inputs_json, "{}");
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, instruction);
});

baseTest("buildCastZkBallotInstruction rejects unsupported public input keys", () => {
  assert.throws(
    () =>
      buildCastZkBallotInstruction({
        electionId: "ref-3",
        proof: Buffer.from([0x04]),
        publicInputs: {
          owner: SAMPLE_ACCOUNT_I105_LITERAL,
          amount: "250",
          durationBlocks: 12,
        },
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
      assert.match(String(error?.message), /durationBlocks/i);
      return true;
    },
  );
});

baseTest("buildCastZkBallotInstruction has a closed camel-case request shape", () => {
  const base = {
    electionId: "ref-closed",
    proof: Buffer.from([0x04]),
  };
  for (const field of [
    "election_id",
    "proofB64",
    "proof_b64",
    "publicInputsJson",
    "public_inputs_json",
  ]) {
    assert.throws(
      () => buildCastZkBallotInstruction({ ...base, [field]: "retired" }),
      new RegExp(field, "u"),
    );
  }
});

baseTest("buildCastZkBallotInstruction canonicalizes all six scalar inputs losslessly", () => {
  const publicInputs = {
    owner: SAMPLE_ACCOUNT_I105_LITERAL,
    amount: "18446744073709551616.25",
    duration_blocks: 0xffff_ffff_ffff_ffffn,
    direction: "Nay",
    root_hint: `0x${"Aa".repeat(32)}`,
    nullifier: `blake2b32:${"BB".repeat(32)}`,
  };
  const snapshot = structuredClone(publicInputs);
  const request = { electionId: "ref-3", proof: Buffer.from([0x04]), publicInputs };
  const instruction = buildCastZkBallotInstruction(request);
  const reordered = buildCastZkBallotInstruction({
    ...request,
    publicInputs: Object.fromEntries(Object.entries(publicInputs).reverse()),
  });
  assert.deepEqual(reordered, instruction);
  assert.deepEqual(publicInputs, snapshot);
  assert.equal(
    instruction.CastZkBallot.public_inputs_json,
    `{"amount":"18446744073709551616.25","direction":"Nay","duration_blocks":18446744073709551615,"nullifier":"${"bb".repeat(32)}","owner":"${SAMPLE_ACCOUNT_I105_LITERAL}","root_hint":"${"aa".repeat(32)}"}`,
  );
  const decoded = withNativeInstructionCodec((codec) =>
    encodeAndDecode(instruction, codec));
  assert.equal(
    decoded.CastZkBallot.public_inputs_json,
    instruction.CastZkBallot.public_inputs_json,
  );
  const wire = assertNativeInstructionAdapterParity(instruction, "canonical ZK ballot");
  assert.deepEqual(noritoEncodeInstruction(reordered, 753), wire);
});

baseTest("buildCastZkBallotInstruction rejects formerly accepted meta and badge fields", () => {
  for (const publicInputs of [
    { meta: { z: 1, a: 2 } },
    { badge: "voter" },
    { direction: "Aye", tally: "aye" },
  ]) {
    assert.throws(
      () =>
        buildCastZkBallotInstruction({
          electionId: "ref-4",
          proof: Buffer.from([0x05]),
          publicInputs,
        }),
      /not supported/u,
    );
  }
});

baseTest("buildCastZkBallotInstruction rejects non-object public inputs", () => {
  assert.throws(
    () =>
      buildCastZkBallotInstruction({
        electionId: "ref-4",
        proof: Buffer.from([0x05]),
        publicInputs: "[1,2]",
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
      assert.match(String(error?.message), /publicInputs/i);
      return true;
    },
  );
});

baseTest("buildCastZkBallotInstruction requires complete lock hints", () => {
  assert.throws(
    () =>
      buildCastZkBallotInstruction({
        electionId: "ref-5",
        proof: Buffer.from([0x06]),
        publicInputs: { owner: SAMPLE_ACCOUNT_I105_LITERAL },
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
      assert.match(String(error?.message), /owner, amount, and duration_blocks/i);
      return true;
    },
  );
});

baseTest("buildCastZkBallotInstruction rejects noncanonical owner", () => {
  const malformedOwner = ACCOUNT_ID.replace(/^sora/u, "ｓｏｒａ");
  assert.throws(
    () =>
      buildCastZkBallotInstruction({
        electionId: "ref-5",
        proof: Buffer.from([0x06]),
        publicInputs: {
          owner: malformedOwner,
          amount: "250",
          duration_blocks: 12,
        },
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_ACCOUNT_ID);
      assert.match(String(error?.message), /canonical .*i105 account id/i);
      return true;
    },
  );
});

baseTest("buildCastZkBallotInstruction rejects noncanonical direction and Quantity", () => {
  const base = {
    electionId: "ref-6",
    proof: Buffer.from([0x07]),
  };
  for (const direction of ["aye", "NAY", "Abstain ", 0]) {
    assert.throws(
      () => buildCastZkBallotInstruction({
        ...base,
        publicInputs: { direction },
      }),
      /exactly Aye, Nay, or Abstain/u,
    );
  }
  for (const amount of [250, "01", "-1", "1.", " 1"] ) {
    assert.throws(
      () => buildCastZkBallotInstruction({
        ...base,
        publicInputs: {
          owner: SAMPLE_ACCOUNT_I105_LITERAL,
          amount,
          duration_blocks: 1,
        },
      }),
      /Quantity|quantity|numeric/u,
    );
  }
});

baseTest("buildCastZkBallotInstruction rejects lossy or out-of-range durations", () => {
  const base = {
    electionId: "ref-duration",
    proof: Buffer.from([0x07]),
  };
  for (const duration_blocks of [
    -1,
    Number.MAX_SAFE_INTEGER + 1,
    "01",
    "1 ",
    0x1_0000_0000_0000_0000n,
  ]) {
    assert.throws(
      () => buildCastZkBallotInstruction({
        ...base,
        publicInputs: {
          owner: SAMPLE_ACCOUNT_I105_LITERAL,
          amount: "1",
          duration_blocks,
        },
      }),
      /duration_blocks/u,
    );
  }
});

baseTest("governance ZK ballot rejects every private-key alias recursively", () => {
  for (const alias of [
    "private_key",
    "privateKey",
    "private_key_hex",
    "privateKeyHex",
    "private_key_bytes",
    "privateKeyBytes",
    "private_key_seed",
    "privateKeySeed",
    "private_key_multihash",
    "privateKeyMultihash",
    "private_key_algorithm",
    "privateKeyAlgorithm",
  ]) {
    assert.throws(
      () => buildCastZkBallotInstruction({
        electionId: "ref-secret",
        proof: Buffer.from([0x08]),
        publicInputs: { meta: [{ [alias]: "secret" }] },
      }),
      new RegExp(alias, "u"),
    );
  }
});

baseTest("direct governance Norito validation runs before native dispatch", () => {
  let nativeCalls = 0;
  const encodeWithNative = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction() {
      nativeCalls += 1;
      return Buffer.from([0]);
    },
  })).noritoEncodeInstruction;
  assert.throws(
      () => encodeWithNative({
        ProposeDeployContract: {
          contract_address:
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          code_hash: "aa".repeat(32),
          abi_hash: "bb".repeat(32),
          abi_version: 1,
          limits: {},
        },
    }, 753),
    /unknown field limits/u,
  );
  assert.throws(
    () => encodeWithNative({
        CastZkBallot: {
          election_id: "ref-direct",
          proof_b64: "AQ==",
          public_inputs_json: '{"meta":{"privateKey":"secret"}}',
        },
    }, 753),
    /privateKey/u,
  );
  assert.equal(nativeCalls, 0);
});

baseTest("direct native adapter CastZkBallot preserves a raw max-u64 JSON token", () => {
  const instructionJson = JSON.stringify({
    CastZkBallot: {
      election_id: "ref-direct",
      proof_b64: "AQ==",
      public_inputs_json:
        '{"duration_blocks":18446744073709551615,"owner":"' +
        SAMPLE_ACCOUNT_I105_LITERAL +
        '","amount":"1","direction":"Abstain"}',
    },
  });
  const decoded = withNativeInstructionCodec(({
    noritoDecodeInstruction,
    noritoEncodeInstruction,
  }) =>
    noritoDecodeInstruction(noritoEncodeInstruction(instructionJson, 753), 753));
  const rawBytes = nativeBinding.noritoEncodeInstruction(instructionJson, 753);
  const rawDecoded = JSON.parse(nativeBinding.noritoDecodeInstruction(rawBytes, 753));
  assert.deepEqual(rawDecoded, decoded);
  assert.deepEqual(noritoEncodeInstruction(instructionJson, 753), Buffer.from(rawBytes));
  assert.equal(
    decoded.CastZkBallot.public_inputs_json,
    `{"amount":"1","direction":"Abstain","duration_blocks":18446744073709551615,"owner":"${SAMPLE_ACCOUNT_I105_LITERAL}"}`,
  );
});

baseTest("direct native adapter deploy proposal roundtrips typed hashes and ABI V1", () => {
  const instructionJson =
    '{"ProposeDeployContract":{' +
    '"contract_address":"irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",' +
    `"code_hash":"${"aa".repeat(32)}",` +
    `"abi_hash":"${"bb".repeat(32)}",` +
    '"abi_version":1}}';
  const decoded = withNativeInstructionCodec(({
    noritoDecodeInstruction,
    noritoEncodeInstruction,
  }) =>
    noritoDecodeInstruction(noritoEncodeInstruction(instructionJson, 753), 753));
  assert.equal(decoded.ProposeDeployContract.code_hash, "aa".repeat(32));
  assert.equal(decoded.ProposeDeployContract.abi_hash, "bb".repeat(32));
  assert.equal(decoded.ProposeDeployContract.abi_version, 1);
});

baseTest("buildCastZkBallotInstruction rejects empty proof bytes", () => {
  assert.throws(
    () =>
      buildCastZkBallotInstruction({
        electionId: "ref-1",
        proof: Buffer.alloc(0),
        publicInputs: {},
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_STRING);
      assert.match(String(error?.message), /non-empty base64/i);
      return true;
    },
  );
});

test("buildCastPlainBallotInstruction maps direction labels", () => {
  const instruction = buildCastPlainBallotInstruction({
    referendumId: "ref-2",
    owner: ACCOUNT_ID,
    amount: "18446744073709551616.25",
    durationBlocks: 50,
    direction: "nay",
  });
  const expected = {
    CastPlainBallot: {
      referendum_id: "ref-2",
      owner: ACCOUNT_ID_CANONICAL,
      amount: "18446744073709551616.25",
      duration_blocks: 50,
      direction: 1,
    },
  };
  assert.deepEqual(instruction, expected);
  for (const extra of ["referendum_id", "duration_blocks", "choice", "action"]) {
    assert.throws(() => buildCastPlainBallotInstruction({
      referendumId: "ref-2", owner: ACCOUNT_ID, amount: "1", durationBlocks: 50,
      direction: "aye", [extra]: 1,
    }), /must contain exactly/u);
  }
  const decoded = encodeAndDecode(instruction);
  assertPublicInstructionProjection(decoded, expected);
});

test("buildUpdatePlainConvictionInstruction retains no choice field", () => {
  assert.deepEqual(
    buildUpdatePlainConvictionInstruction({
      referendumId: "ref-2",
      owner: ACCOUNT_ID,
      amount: "18446744073709551616.25",
      durationBlocks: 50,
    }),
    {
      UpdatePlainConviction: {
        referendum_id: "ref-2",
        owner: ACCOUNT_ID_CANONICAL,
        amount: "18446744073709551616.25",
        duration_blocks: 50,
      },
    },
  );
  assert.throws(
    () => buildUpdatePlainConvictionInstruction({
      referendumId: "ref-2",
      owner: ACCOUNT_ID,
      amount: "10",
      durationBlocks: 50,
      direction: "nay",
    }),
    /must contain exactly/u,
  );
  assert.throws(
    () => buildUpdatePlainConvictionInstruction({
      referendumId: "ref-2",
      owner: ACCOUNT_ID,
      amount: "01",
      durationBlocks: 50,
    }),
    /canonical/u,
  );
});

baseTest("public cast and conviction update preserve the full u64 duration", () => {
  const maximum = 0xffff_ffff_ffff_ffffn;
  const requests = [
    [buildCastPlainBallotInstruction, {
      referendumId: "ref-max-cast",
      owner: ACCOUNT_ID,
      amount: "10",
      durationBlocks: maximum.toString(10),
      direction: "aye",
    }, "CastPlainBallot"],
    [buildUpdatePlainConvictionInstruction, {
      referendumId: "ref-max-update",
      owner: ACCOUNT_ID,
      amount: "10",
      durationBlocks: maximum,
    }, "UpdatePlainConviction"],
  ];
  for (const [build, request, variant] of requests) {
    const instruction = build(request);
    assert.equal(instruction[variant].duration_blocks, maximum);
    const exact = exactPublicPlainBallotJson(instruction);
    assert.match(exact, /"duration_blocks":18446744073709551615/u);
    assert.doesNotMatch(exact, /"duration_blocks":"18446744073709551615"/u);
    assert.match(
      exactPublicPlainBallotJson(build({ ...request, durationBlocks: 50 })),
      /"duration_blocks":50/u,
    );
    assert.equal(exactPublicPlainBallotJson({
      [variant]: { ...instruction[variant], duration_blocks: maximum.toString(10) },
    }), exact);
    assert.match(exactPublicPlainBallotJson({
      [variant]: { ...instruction[variant], duration_blocks: "50" },
    }), /"duration_blocks":50/u);

    const calls = [];
    const codec = _createNoritoInstructionApi(createNativeRuntime({
      noritoEncodeInstruction(json) {
        calls.push(json);
        return Buffer.from([1]);
      },
      noritoDecodeInstruction() {
        return exact;
      },
      noritoDecodeInstructionBoxArchive() {
        return exact;
      },
    }));
    assert.deepEqual(codec.noritoEncodeInstruction(instruction, 753), Buffer.from([1]));
    assert.deepEqual(calls, [exact]);
    assert.equal(codec.noritoDecodeInstruction(Buffer.from([1]), 753)[variant].duration_blocks,
      maximum);
    assert.equal(codec.noritoDecodeInstructionBoxArchive(Buffer.from([1]), 753)[variant].duration_blocks,
      maximum);
    assert.equal(codec.noritoDecodeInstruction(Buffer.from([1]), 753, { parseJson: false }),
      exact);

    for (const bad of [Number.MAX_SAFE_INTEGER + 1, 2n ** 64n, "18446744073709551616", "01", -1]) {
      assert.throws(() => build({ ...request, durationBlocks: bad }),
        /durationBlocks/u);
    }
  }
});

baseTest("public ballot exact duration rejects duplicate and malformed native JSON", () => {
  const fields = (duration) =>
    `{"referendum_id":"ref-strict","owner":${JSON.stringify(ACCOUNT_ID_CANONICAL)},` +
    `"amount":"1","duration_blocks":${duration}}`;
  const body = fields("1");
  const invalid = [
    `{"UpdatePlainConviction":${body},"UpdatePlainConviction":${body}}`,
    `{"UpdatePlainConviction":${body.replace('"duration_blocks":1',
      '"duration_blocks":1,"duration_blocks":2')}}`,
    `{"UpdatePlainConviction":${fields("18446744073709551616")}}`,
    `{"UpdatePlainConviction":${fields("1e0")}}`,
    `{"UpdatePlainConviction":${fields("01")}}`,
  ];
  let encodeCalls = 0;
  let nativeJson = "";
  const codec = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction() {
      encodeCalls += 1;
      return Buffer.from([1]);
    },
    noritoDecodeInstruction() {
      return nativeJson;
    },
    noritoDecodeInstructionBoxArchive() {
      return nativeJson;
    },
  }));
  for (const malformed of invalid) {
    nativeJson = malformed;
    assert.throws(() => codec.noritoEncodeInstruction(malformed, 753));
    assert.throws(() => codec.noritoDecodeInstruction(Buffer.from([1]), 753));
    assert.throws(() => codec.noritoDecodeInstruction(Buffer.from([1]), 753,
      { parseJson: false }));
    assert.throws(() => codec.noritoDecodeInstructionBoxArchive(Buffer.from([1]), 753));
  }
  assert.equal(encodeCalls, 0);
});

baseTest("UpdatePlainConviction uses the registered native Norito frame", () => {
  const instruction = {
    UpdatePlainConviction: {
      referendum_id: "ref-quantity",
      owner: ACCOUNT_ID_CANONICAL,
      amount: "18446744073709551616.25",
      duration_blocks: 50,
    },
  };
  const encoded = assertNativeInstructionAdapterParity(
    instruction,
    "UpdatePlainConviction",
  );
  assert.equal(encoded[39], 0x02);
  withNativeInstructionCodec(({ noritoDecodeInstruction }) => {
    assertPublicInstructionProjection(noritoDecodeInstruction(encoded, 753), instruction);
  });
});

baseTest("UpdatePlainConviction matches the Rust direct-instruction golden", () => {
  const fixture = JSON.parse(fs.readFileSync(
    path.join(repoRoot, "fixtures/governance/plain_v1/update_plain_conviction_instruction_v1.json"),
    "utf8",
  ));
  const inputs = fixture.inputs;
  const instruction = buildUpdatePlainConvictionInstruction({
    referendumId: inputs.referendum_id,
    owner: inputs.owner,
    amount: inputs.amount,
    durationBlocks: inputs.duration_blocks,
  });
  assert.deepEqual(instruction, { UpdatePlainConviction: { ...inputs } });
  assert.equal(fixture.wire_id, "iroha.instruction.v1::governance::UpdatePlainConviction");

  const boxedFrame = assertNativeInstructionAdapterParity(instruction, "UpdatePlainConviction golden");
  const pair = Buffer.from(noritoEncodeInstructionBoxArchive(instruction, 753));
  assert.equal(boxedFrame.toString("hex"), fixture.standalone_instruction_box_frame_hex);
  assert.equal(pair.toString("hex"), fixture.instruction_box_pair_hex);
  const boxed = validateNoritoFrame(boxedFrame, { requireNonEmptyPayload: true });
  assert.equal(boxed.flags, fixture.header_flags);
  assert.deepEqual(boxed.payload, pair);
  assertPublicInstructionProjection(noritoDecodeInstruction(boxedFrame, 753), instruction);
  assertPublicInstructionProjection(noritoDecodeInstructionBoxArchive(pair, 753), instruction);

  const concreteFrame = Buffer.from(fixture.concrete_frame_hex, "hex");
  assert.equal(fixture.concrete_schema_name,
    "iroha_data_model::isi::governance::UpdatePlainConviction");
  const concrete = validateNoritoFrame(concreteFrame, {
    expectedTypeName: fixture.concrete_schema_name,
    expectedSchemaHash: Buffer.from(fixture.concrete_schema_hash, "hex"),
    requireNonEmptyPayload: true,
  });
  assert.equal(concrete.flags, fixture.header_flags);
  assert.equal(concrete.payload.toString("hex"), fixture.bare_payload_hex);
  assert.equal(concreteFrame.length, fixture.framed_instruction_len);
  assert.equal(concreteFrame.toString("base64"), fixture.framed_instruction_base64);
  assert.deepEqual(pair.subarray(pair.length - concreteFrame.length), concreteFrame);
  assert.ok(pair.includes(Buffer.from(fixture.wire_id, "ascii")));

  for (const alias of ["direction", "choice"]) {
    assert.throws(() => buildUpdatePlainConvictionInstruction({
      referendumId: inputs.referendum_id,
      owner: inputs.owner,
      amount: inputs.amount,
      durationBlocks: inputs.duration_blocks,
      [alias]: 1,
    }), /must contain exactly/u);
    const injected = { UpdatePlainConviction: { ...inputs, [alias]: 1 } };
    assert.throws(() => noritoEncodeInstruction(injected, 753));
    assert.throws(() => noritoEncodeInstructionBoxArchive(injected, 753));
  }
  assert.throws(() => noritoDecodeInstruction(Buffer.concat([boxedFrame, Buffer.of(0)]), 753));
  assert.throws(() => noritoDecodeInstructionBoxArchive(Buffer.concat([pair, Buffer.of(0)]), 753));
});

test("buildCastPlainBallotInstruction rejects lossy and noncanonical Quantity inputs", () => {
  const overflowing = "9".repeat(155);
  for (const amount of [
    1,
    "+1",
    "01",
    "1.0",
    "1.2300",
    "1amt",
    "1qty",
    " 1",
    "1 ",
    "-1",
    overflowing,
  ]) {
    assert.throws(
      () =>
        buildCastPlainBallotInstruction({
          referendumId: "ref-2",
          owner: ACCOUNT_ID,
          amount,
          durationBlocks: 50,
          direction: "nay",
        }),
      /canonical|JavaScript numbers are not lossless quantity inputs/u,
      `amount ${String(amount)} must be rejected`,
    );
  }
});

baseTest("CastPlainBallot native Norito adapter preserves strict fractional Quantity", () => {
  const instruction = {
    CastPlainBallot: {
      referendum_id: "ref-quantity",
      owner: ACCOUNT_ID_CANONICAL,
      amount: "18446744073709551616.25",
      duration_blocks: 50,
      direction: 1,
    },
  };
  withNativeInstructionCodec(({
    noritoDecodeInstruction,
    noritoEncodeInstruction,
  }) => {
    const encoded = noritoEncodeInstruction(instruction, 753);
    const outerFrame = validateNoritoFrame(encoded);
    assert.equal(outerFrame.flags, 0x02);
    const wireField = readCompactFieldPayload(
      outerFrame.payload,
      0,
      "CastPlainBallot.wire",
    );
    const innerField = readCompactFieldPayload(
      outerFrame.payload,
      wireField.next,
      "CastPlainBallot.inner",
    );
    assert.equal(innerField.next, outerFrame.payload.length);
    const innerFrameLength = Number(innerField.payload.readBigUInt64LE(0));
    const innerFrame = innerField.payload.subarray(8);
    assert.equal(innerFrame.length, innerFrameLength);
    const validatedInner = validateNoritoFrame(innerFrame, {
      expectedTypeName: "iroha_data_model::isi::governance::CastPlainBallot",
      expectedPaddingLength: 0,
    });
    const expectedSchemaHash = createHash("sha256")
      .update(
        "norito:v1:type-name\0iroha_data_model::isi::governance::CastPlainBallot",
        "utf8",
      )
      .digest()
      .subarray(0, 16);
    assert.equal(expectedSchemaHash.toString("hex"), "62b23313103064bc2c9d528ac3548949");
    assert.deepEqual(validatedInner.schemaHash, expectedSchemaHash);
    assertPublicInstructionProjection(noritoDecodeInstruction(encoded, 753), instruction);

    for (const amount of [
      1,
      "+1",
      "01",
      "1.0",
      "1.2300",
      "1amt",
      "1qty",
      " 1",
      "1 ",
      "-1",
      (1n << 511n).toString(),
      "9".repeat(155),
    ]) {
      assert.throws(
        () =>
          noritoEncodeInstruction({
            CastPlainBallot: {
              ...instruction.CastPlainBallot,
              amount,
            },
          }, 753),
        /canonical|JavaScript numbers are rejected|mantissa|negative/u,
        `amount ${String(amount).slice(0, 32)} must be rejected`,
      );
    }
  });
});

test("CastPlainBallot public adapter bytes match native compact framing", () => {
  const instruction = {
    CastPlainBallot: {
      referendum_id: "ref-quantity",
      owner: ACCOUNT_ID_CANONICAL,
      amount: "18446744073709551616.25",
      duration_blocks: 50,
      direction: 1,
    },
  };
  const encoded = assertNativeInstructionAdapterParity(
    instruction,
    "CastPlainBallot",
  );
  assert.equal(encoded[39], 0x02);
});

test("buildSubmitAgendaProposalInstruction wraps the supplied proposal payload", () => {
  const proposal = {
    version: 1,
    proposal_id: "AC-2026-001",
    submitted_at_unix_ms: 1770000000000,
    language: "en",
    action: "add-to-denylist",
    summary: {
      title: "Blacklist proposal for bafy-test",
      motivation: "Evidence review requested for the published CID.",
      expected_impact: "Participating gateways would restrict delivery during review.",
    },
    tags: ["spam"],
    targets: [
      {
        label: "bafy-test",
        hash_family: "sorafs-root-cid",
        hash_hex: "11".repeat(32),
        reason: "spam moderation report",
      },
    ],
    evidence: [
      {
        kind: "url",
        uri: "https://example.invalid/case/1",
        digest_blake3_hex: "22".repeat(32),
        description: "Captured gateway evidence",
      },
    ],
    submitter: {
      name: "Explorer Moderator",
      contact: "https://example.invalid/moderation",
      organization: null,
      pgp_fingerprint: null,
    },
    duplicates: [],
  };
  const instruction = buildSubmitAgendaProposalInstruction({ proposal });
  assert.deepEqual(instruction, {
    SubmitAgendaProposal: {
      proposal,
    },
  });
  assert.deepEqual(encodeAndDecode(instruction), instruction);
});

test("buildClaimTwitterFollowRewardInstruction wraps keyed hash", () => {
  const digest = normalizedHashHex(Buffer.alloc(32, 0xaa));
  const instruction = buildClaimTwitterFollowRewardInstruction({
    bindingHash: {
      pepper_id: "twitter-follow",
      digest,
    },
  });
  const expected = {
    ClaimTwitterFollowReward: {
      binding_hash: {
        pepper_id: "twitter-follow",
        digest,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expected);
});

test("buildSendToTwitterInstruction encodes keyed hash and amount", () => {
  const digest = normalizedHashHex(Buffer.alloc(32, 0xbb));
  const instruction = buildSendToTwitterInstruction({
    bindingHash: {
      pepper_id: "twitter-follow",
      digest,
    },
    amount: "42",
  });
  const expected = {
    SendToTwitter: {
      binding_hash: {
        pepper_id: "twitter-follow",
        digest,
      },
      amount: "42",
    },
  };
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expected);
});

test("buildCancelTwitterEscrowInstruction wraps keyed hash", () => {
  const digest = normalizedHashHex(Buffer.alloc(32, 0xcc));
  const instruction = buildCancelTwitterEscrowInstruction({
    bindingHash: {
      pepper_id: "twitter-follow",
      digest,
    },
  });
  const expected = {
    CancelTwitterEscrow: {
      binding_hash: {
        pepper_id: "twitter-follow",
        digest,
      },
    },
  };
  assert.deepEqual(instruction, expected);
  const decoded = encodeAndDecode(instruction);
  assert.deepEqual(decoded, expected);
});

test("buildRegisterZkAssetInstruction normalizes verifying key ids", () => {
  const instruction = buildRegisterZkAssetInstruction({
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    unshieldVerifyingKey: { backend: "pipa-r/pasta", name: "vk_unshield" },
  });
  const payload = encodeAndDecode(instruction).zk.RegisterZkAsset;
  assert.deepEqual(payload.vk_unshield, { backend: "pipa-r/pasta", name: "vk_unshield" });
  assert.equal(Object.hasOwn(payload, "vk_shield"), false);
});

test("buildRegisterZkAssetInstruction rejects unknown retired fields", () => {
  const base = { assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" };
  for (const field of ["shieldVerifyingKey", "vkShield", "vk_shield"]) {
    assert.throws(
      () => buildRegisterZkAssetInstruction({
        ...base,
        unshieldVerifyingKey: "pipa-r/pasta:vk_unshield",
        [field]: "pipa-r/pasta:vk_shield",
      }),
      /is not supported/,
      `${field} must be rejected even when an unshield key is provided`,
    );
  }
  assert.throws(
    () => buildRegisterZkAssetInstruction({ ...base, mode: "Hybrid" }),
    /is not supported/,
  );
  assert.throws(
    () =>
      buildRegisterZkAssetInstruction({
        ...base,
        transferVerifyingKey: "halo2\/ipa:vk_transfer",
      }),
    /is not supported/,
  );
  assert.throws(
    () => buildRegisterZkAssetInstruction({ ...base, allowShield: true }),
    /is not supported/,
  );
});

test("buildScheduleConfidentialPolicyTransitionInstruction encodes transition metadata", () => {
  const transitionId = Buffer.alloc(32, 0xaa);
  const instruction = buildScheduleConfidentialPolicyTransitionInstruction({
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    newMode: "ShieldedOnly",
    effectiveHeight: "42",
    transitionId,
    conversionWindow: 10,
  });
  const payload = encodeAndDecode(instruction).zk.ScheduleConfidentialPolicyTransition;
  assert.equal(payload.new_mode, "ShieldedOnly");
  assert.equal(payload.effective_height, 42);
  assert.equal(payload.conversion_window, 10);
  assert.equal(payload.transition_id, normalizedHashHex(transitionId));
});

test("buildCancelConfidentialPolicyTransitionInstruction wraps hash literal", () => {
  const transitionId = Buffer.alloc(32, 0xbb);
  const instruction = buildCancelConfidentialPolicyTransitionInstruction({
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    transitionId,
  });
  const payload = encodeAndDecode(instruction).zk.CancelConfidentialPolicyTransition;
  assert.equal(payload.asset, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM");
  assert.equal(payload.transition_id, normalizedHashHex(transitionId));
});

descriptorTest("retired generic confidential instructions stay absent from builders and codec discriminants", () => {
  const noritoSource = fs.readFileSync(
    path.join(repoRoot, "javascript", "iroha_js", "src", "norito.js"),
    "utf8",
  );
  const retiredVariants = [
    ["Shi", "eld"],
    ["Zk", "Transfer"],
    ["Un", "shield"],
  ].map((parts) => parts.join(""));

  for (const variant of retiredVariants) {
    const builder = ["build", variant, "Instruction"].join("");
    const wireId = ["iroha_data_model::isi::zk::", variant].join("");
    assert.equal(instructionBuilderExports[builder], undefined, builder);
    assert.throws(
      () => noritoEncodeInstruction({ zk: { [variant]: {} } }, 753),
      /retired|does not support|unsupported/u,
      variant,
    );
    assert.equal(noritoSource.includes(wireId), false, wireId);
  }
});

test("buildCreateElectionInstruction normalizes verifying keys", () => {
  const instruction = buildCreateElectionInstruction({
    electionId: "election-1",
    options: 3,
    eligibleRoot: Buffer.alloc(32, 0x09),
    startTs: 100,
    endTs: 200,
    ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
    tallyVerifyingKey: { backend: "pipa-r/pasta", name: "vk_tally" },
    domainTag: "zk",
  });
  const payload = encodeAndDecode(instruction).zk.CreateElection;
  assert.equal(payload.vk_ballot.name, "vk_ballot");
  assert.equal(payload.vk_tally.name, "vk_tally");
  assert.equal(payload.options, 3);
});

test("buildCreateElectionInstruction enforces the 2–64 option boundary", () => {
  const election = (options) => ({
    electionId: "election-boundary",
    options,
    eligibleRoot: Buffer.alloc(32, 0x09),
    startTs: 100,
    endTs: 200,
    ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
    tallyVerifyingKey: "pipa-r/pasta:vk_tally",
    domainTag: "zk",
  });
  for (const options of [2, 64]) {
    const payload = encodeAndDecode(buildCreateElectionInstruction(election(options))).zk.CreateElection;
    assert.equal(payload.options, options);
  }
  for (const options of [1, 65]) {
    assert.throws(
      () => buildCreateElectionInstruction(election(options)),
      (error) => error?.code === ValidationErrorCode.VALUE_OUT_OF_RANGE && /options/u.test(String(error?.message)),
    );
  }
  assert.throws(() => buildCreateElectionInstruction(election(0)));
});

test("buildCreateElectionInstruction accepts byte-array eligibleRoot", () => {
  const instruction = buildCreateElectionInstruction({
    electionId: "election-2",
    options: 2,
    eligibleRoot: Array.from(Buffer.alloc(32, 0x44)),
    startTs: 100,
    endTs: 200,
    ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
    tallyVerifyingKey: "pipa-r/pasta:vk_tally",
    domainTag: "zk",
  });
  const payload = encodeAndDecode(instruction).zk.CreateElection;
  assert.deepEqual(payload.eligible_root, toByteArray(Buffer.alloc(32, 0x44)));
});

test("buildCreateElectionInstruction rejects coercible non-byte eligibleRoot entries", () => {
  for (const entry of ["1", true, null]) {
    const eligibleRoot = new Array(32).fill(0);
    eligibleRoot[0] = entry;
    assert.throws(
      () =>
        buildCreateElectionInstruction({
          electionId: "election-coercible",
          options: 2,
          eligibleRoot,
          startTs: 100,
          endTs: 200,
          ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
          tallyVerifyingKey: "pipa-r/pasta:vk_tally",
          domainTag: "zk",
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
        assert.match(String(error?.message), /eligibleRoot\[0\]/i);
        return true;
      },
    );
  }
});

test("buildCreateElectionInstruction rejects unsafe timestamps", () => {
  const tooLarge = (BigInt(Number.MAX_SAFE_INTEGER) + 1n).toString(10);
  assert.throws(
    () =>
      buildCreateElectionInstruction({
        electionId: "election-unsafe",
        options: 2,
        eligibleRoot: Buffer.alloc(32, 0x09),
        startTs: tooLarge,
        endTs: 100,
        ballotVerifyingKey: "pipa-r/pasta:vk_ballot",
        tallyVerifyingKey: "pipa-r/pasta:vk_tally",
        domainTag: "zk",
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /safe integer/i);
      return true;
    },
  );
});

test("buildSubmitBallotInstruction encodes ciphertext and proof", () => {
  const instruction = buildSubmitBallotInstruction({
    electionId: "ref-1",
    ciphertext: Buffer.from("encrypted"),
    ballotProof: {
      backend: "pipa-r/pasta",
      proof: Buffer.from("proof"),
      verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_ballot" },
      verifyingKeyCommitment: Buffer.alloc(32, 0x44),
    },
    nullifier: Buffer.alloc(32, 0x33),
  });
  const payload = encodeAndDecode(instruction).zk.SubmitBallot;
  const ciphertext = Buffer.from(payload.ciphertext);
  assert.equal(ciphertext.toString("base64"), Buffer.from("encrypted").toString("base64"));
  assert.equal(payload.ballot_proof.backend, "pipa-r/pasta");
});

test("buildSubmitBallotInstruction rejects non-byte nullifier arrays", () => {
  const invalidNullifier = Array.from({ length: 32 }, (_, index) => (index === 0 ? 256 : 0));
  assert.throws(
    () =>
      buildSubmitBallotInstruction({
        electionId: "ref-1",
        ciphertext: Buffer.from("encrypted"),
        ballotProof: {
          backend: "pipa-r/pasta",
          proof: Buffer.from("proof"),
          verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_ballot" },
        },
        nullifier: invalidNullifier,
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.match(String(error?.message), /nullifier\[0\]/i);
      return true;
    },
  );
});

test("buildSubmitBallotInstruction rejects coercible non-byte ciphertext entries", () => {
  for (const entry of ["1", true, null]) {
    assert.throws(
      () =>
        buildSubmitBallotInstruction({
          electionId: "ref-1",
          ciphertext: [entry],
          ballotProof: {
            backend: "pipa-r/pasta",
            proof: Buffer.from("proof"),
            verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_ballot" },
          },
          nullifier: Buffer.alloc(32, 0x33),
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
        assert.match(String(error?.message), /ciphertext\[0\]/i);
        return true;
      },
    );
  }
});

test("buildSubmitBallotInstruction rejects empty ciphertext", () => {
  assert.throws(
    () =>
      buildSubmitBallotInstruction({
        electionId: "ref-1",
        ciphertext: Buffer.alloc(0),
        ballotProof: {
          backend: "pipa-r/pasta",
          proof: Buffer.from("proof"),
          verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_ballot" },
        },
        nullifier: Buffer.alloc(32, 0x33),
      }),
    (error) => {
      assert.equal(error?.code, ValidationErrorCode.INVALID_STRING);
      assert.match(String(error?.message), /non-empty byte array/i);
      return true;
    },
  );
});

test("buildFinalizeElectionInstruction enforces the 2–64 tally boundary", () => {
  const election = (tally) => ({
    electionId: "election-boundary",
    tally,
    tallyProof: {
      backend: "pipa-r/pasta",
      proof: Buffer.from("proof"),
      verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_tally" },
    },
  });
  for (const tally of [[1, 2], new Array(64).fill(0)]) {
    const payload = encodeAndDecode(buildFinalizeElectionInstruction(election(tally))).zk.FinalizeElection;
    assert.deepEqual(payload.tally, tally);
  }
  for (const tally of [[], [1], new Array(65).fill(0)]) {
    assert.throws(
      () => buildFinalizeElectionInstruction(election(tally)),
      (error) => error?.code === ValidationErrorCode.VALUE_OUT_OF_RANGE && /tally/u.test(String(error?.message)),
    );
  }
});

test("buildFinalizeElectionInstruction serializes tally entries", () => {
  const instruction = buildFinalizeElectionInstruction({
    electionId: "ref-1",
    tally: [1, "2"],
    tallyProof: {
      backend: "pipa-r/pasta",
      proof: Buffer.from("proof"),
      verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_tally" },
      verifyingKeyCommitment: Buffer.alloc(32, 0x55),
    },
  });
  const payload = encodeAndDecode(instruction).zk.FinalizeElection;
  assert.deepEqual(payload.tally, [1, 2]);
});

baseTest("proof attachments support lane privacy merkle witnesses", () => {
  const leaf = Buffer.alloc(32, 1);
  const sibling = Buffer.alloc(32, 2);
  const result = buildFinalizeElectionInstruction({
    electionId: "elec-1",
    tally: [1, 0],
    proof: {
      backend: "lane/privacy",
      proof: new Uint8Array([1, 2, 3]),
      verifyingKeyRef: { backend: "lane/privacy", name: "vk_lane_privacy" },
      lanePrivacy: {
        commitmentId: 9,
        merkle: {
          leaf,
          leafIndex: 0,
          auditPath: [sibling],
        },
      },
    },
  });
  const proof = result.zk.FinalizeElection.tally_proof;
  assert.equal(proof.backend, "lane/privacy");
  assert.deepEqual(proof.lane_privacy.commitment_id, [9]);
  assert.equal(proof.lane_privacy.witness.kind, "merkle");
  assert.deepEqual(proof.lane_privacy.witness.payload.leaf, Array.from(leaf));
  const canonicalSibling = Array.from(sibling);
  canonicalSibling[31] |= 1;
  assert.deepEqual(
    proof.lane_privacy.witness.payload.proof.audit_path[0],
    normalizedHashHex(canonicalSibling),
  );
  assert.deepEqual(encodeAndDecode(result), result);
  assert.equal(sibling[31], 2, "builder must not mutate caller-owned sibling bytes");
});

baseTest("lane proof JSON uses exact native tuples and canonical hash literals", () => {
  const build = (commitmentId) => buildFinalizeElectionInstruction({
    electionId: "elec-1",
    tally: [1, 0],
    proof: {
      backend: "lane/privacy",
      proof: Buffer.of(1, 2, 3),
      verifyingKeyRef: { backend: "lane/privacy", name: "vk_lane_privacy" },
      lanePrivacy: {
        commitmentId,
        merkle: {
          leaf: Buffer.alloc(32, 1),
          leafIndex: 0,
          auditPath: [Buffer.alloc(32, 2)],
        },
      },
    },
  });
  const lane = (instruction) => instruction.zk.FinalizeElection.tally_proof.lane_privacy;
  for (const commitmentId of [0, 0xffff]) {
    const instruction = build(commitmentId);
    assert.deepEqual(lane(instruction).commitment_id, [commitmentId]);
    const bytes = assertNativeInstructionAdapterParity(instruction, `lane commitment ${commitmentId}`);
    assert.deepEqual(
      JSON.parse(noritoDecodeInstruction(bytes, 753, { parseJson: false })),
      instruction,
    );
  }
  const canonical = build(9);
  const assertRejectedByEveryBoundary = (instruction) => {
    assert.throws(() => noritoEncodeInstruction(instruction, 753));
    assert.throws(() => nativeBinding.noritoEncodeInstruction(JSON.stringify(instruction), 753));
    for (const options of [undefined, { parseJson: false }]) {
      assert.throws(() => nativeInstructionDecoder(instruction)(Buffer.of(1), options));
    }
  };
  for (const commitmentId of [9, "9", [], [9, 10], [-1], [0x1_0000], [1.5], ["9"]]) {
    const invalid = structuredClone(canonical);
    lane(invalid).commitment_id = commitmentId;
    assertRejectedByEveryBoundary(invalid);
  }
  const sibling = lane(canonical).witness.payload.proof.audit_path[0];
  const siblingBody = sibling.slice(5, 69);
  for (const auditPath of [[], Array(256).fill(sibling)]) {
    const invalid = structuredClone(canonical);
    lane(invalid).witness.payload.proof.audit_path = auditPath;
    assertRejectedByEveryBoundary(invalid);
  }
  for (const invalidSibling of [
    Array.from(Buffer.from(siblingBody, "hex")),
    siblingBody,
    sibling.toLowerCase(),
    `${sibling} `,
    `${sibling.slice(0, -4)}0000`,
  ]) {
    const invalid = structuredClone(canonical);
    lane(invalid).witness.payload.proof.audit_path[0] = invalidSibling;
    assertRejectedByEveryBoundary(invalid);
  }
});

baseTest("proof attachments reject empty lane privacy merkle paths", () => {
  assert.throws(
    () =>
      buildFinalizeElectionInstruction({
        electionId: "elec-1",
        tally: [1, 0],
        proof: {
          backend: "lane/privacy",
          proof: new Uint8Array([1, 2, 3]),
          verifyingKeyRef: { backend: "lane/privacy", name: "vk_lane_privacy" },
          lanePrivacy: {
            commitmentId: 9,
            merkle: {
              leaf: Buffer.alloc(32, 1),
              leafIndex: 0,
              auditPath: [],
            },
          },
        },
      }),
    /must contain 1\.\.=255 siblings/,
  );
});

baseTest("proof attachments reject malformed and impossible lane Merkle witnesses", () => {
  const baseMerkle = {
    leaf: Buffer.alloc(32, 1),
    leafIndex: 0,
    auditPath: [Buffer.alloc(32, 2)],
  };
  const attacks = [
    [{ ...baseMerkle, auditPath: [null] }, /must contain a sibling/],
    [{ ...baseMerkle, auditPath: [undefined] }, /must contain a sibling/],
    [{ ...baseMerkle, auditPath: [Buffer.alloc(31)] }, /must be 32 bytes/],
    [{ ...baseMerkle, auditPath: [Buffer.alloc(33)] }, /must be 32 bytes/],
    [
      { ...baseMerkle, auditPath: Array.from({ length: 256 }, () => Buffer.alloc(32)) },
      /1\.\.=255 siblings/,
    ],
    [{ ...baseMerkle, leafIndex: 2 }, /impossible for the Merkle path depth/],
    [{ ...baseMerkle, leafIndex: 0x1_0000_0000 }, /must fit within a u32/],
  ];
  for (const [merkle, expected] of attacks) {
    assert.throws(
      () =>
        buildFinalizeElectionInstruction({
          electionId: "elec-1",
          tally: [1, 0],
          proof: {
            backend: "lane/privacy",
            proof: new Uint8Array([1, 2, 3]),
            verifyingKeyRef: {
              backend: "lane/privacy",
              name: "vk_lane_privacy",
            },
            lanePrivacy: { commitmentId: 0, merkle },
          },
        }),
      expected,
    );
  }
});

baseTest("native Norito adapter rejects non-canonical lane HashOf markers", () => {
  const instruction = buildFinalizeElectionInstruction({
    electionId: "elec-1",
    tally: [1, 0],
    proof: {
      backend: "lane/privacy",
      proof: new Uint8Array([1, 2, 3]),
      verifyingKeyRef: {
        backend: "lane/privacy",
        name: "vk_lane_privacy",
      },
      lanePrivacy: {
        commitmentId: 9,
        merkle: {
          leaf: Buffer.alloc(32, 1),
          leafIndex: 0,
          auditPath: [Buffer.alloc(32, 2)],
        },
      },
    },
  });
  const encoded = Buffer.from(
    withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(instruction, 753)),
  );
  const decoded = withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
    noritoDecodeInstruction(encoded, 753),
  );
  const decodedSibling =
    decoded.zk.FinalizeElection.tally_proof.lane_privacy.witness.payload.proof
      .audit_path[0];
  assert.match(decodedSibling, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/);
  assert.equal(Number.parseInt(decodedSibling.slice(67, 69), 16) & 1, 1);
  const evenSiblingBody = Buffer.alloc(32, 2).toString("hex").toUpperCase();
  instruction.zk.FinalizeElection.tally_proof.lane_privacy.witness.payload.proof
    .audit_path[0] = `hash:${evenSiblingBody}#${computeHashLiteralCrc("hash", evenSiblingBody)}`;
  assert.throws(
    () => withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(instruction, 753)),
    { message: "JSON error: invalid field `lane_privacy.witness.payload.proof.audit_path`: expect least significant bit of hash to be 1" },
  );

  const canonicalSibling = Buffer.alloc(32, 2);
  canonicalSibling[31] |= 1;
  const siblingOffset = encoded.indexOf(canonicalSibling);
  assert.ok(siblingOffset > 0, "encoded lane sibling must be present");
  const countOffset = siblingOffset - 11;
  const leafIndexOffset = countOffset - 5;
  assert.equal(encoded.readBigUInt64LE(countOffset), 1n);
  assert.equal(encoded.readUInt32LE(leafIndexOffset), 0);

  const missingSibling = Buffer.from(encoded);
  assert.equal(missingSibling[siblingOffset - 2], 1, "sibling option must be Some");
  missingSibling[siblingOffset - 2] = 0;
  rewriteNestedInstructionCrcs(missingSibling);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(missingSibling, 753)),
    { message: "length mismatch" },
  );

  const emptyPath = Buffer.from(encoded);
  emptyPath.writeBigUInt64LE(0n, countOffset);
  rewriteNestedInstructionCrcs(emptyPath);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(emptyPath, 753)),
    { message: "length mismatch" },
  );

  const deepPath = Buffer.from(encoded);
  deepPath.writeBigUInt64LE(256n, countOffset);
  rewriteNestedInstructionCrcs(deepPath);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(deepPath, 753)),
    { message: "length mismatch" },
  );

  const impossibleIndex = Buffer.from(encoded);
  impossibleIndex.writeUInt32LE(2, leafIndexOffset);
  rewriteNestedInstructionCrcs(impossibleIndex);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(impossibleIndex, 753)),
    { message: "lane_privacy must be a complete canonical bounded Merkle witness" },
  );

  encoded[siblingOffset + 31] &= 0xfe;
  rewriteNestedInstructionCrcs(encoded);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(encoded, 753)),
    { message: "invalid hash lsb" },
  );
});

baseTest("native ProofAttachment adapter rejects invalid ids and extra tails", () => {
  const proofBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
  const instruction = buildFinalizeElectionInstruction({
    electionId: "elec-1",
    tally: [1, 0],
    proof: {
      backend: "lane/privacy",
      proof: proofBytes,
      verifyingKeyRef: {
        backend: "lane/privacy",
        name: "unique_vk_name",
      },
      lanePrivacy: {
        commitmentId: 7,
        merkle: {
          leaf: Buffer.alloc(32, 1),
          leafIndex: 0,
          auditPath: [Buffer.alloc(32, 2)],
        },
      },
    },
  });
  const encoded = Buffer.from(
    withNativeInstructionCodec(({ noritoEncodeInstruction }) =>
      noritoEncodeInstruction(instruction, 753)),
  );
  const invalidId = Buffer.from(encoded);
  const nameOffset = invalidId.indexOf(Buffer.from("unique_vk_name", "utf8"));
  assert.ok(nameOffset > 0, "encoded verifying-key name must be present");
  invalidId[nameOffset] = "U".charCodeAt(0);
  rewriteNestedInstructionCrcs(invalidId);
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(invalidId, 753)),
    { message: "vk_ref must use portable registry syntax" },
  );

  const oversizedProof = Buffer.from(encoded);
  const proofOffset = oversizedProof.indexOf(proofBytes);
  assert.ok(proofOffset > 8, "encoded proof bytes must be present");
  const proofLengthOffset = proofOffset - 8;
  assert.equal(
    oversizedProof.readBigUInt64LE(proofLengthOffset),
    BigInt(proofBytes.length),
  );
  oversizedProof.writeBigUInt64LE(
    BigInt(proofBoxMaxProofBytes("lane/privacy") + 1),
    proofLengthOffset,
  );
  rewriteNestedInstructionCrcs(oversizedProof);
  assert.throws(
    () =>
      withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
        noritoDecodeInstruction(oversizedProof, 753),
      ),
    { message: new RegExp(`^sequence length ${proofBoxMaxProofBytes("lane/privacy") + 1} exceeds decode limit \\d+$`, "u") },
  );

  const extraTail = appendFinalizeProofAttachmentTail(encoded, Buffer.of(0));
  assert.throws(
    () => withNativeInstructionCodec(({ noritoDecodeInstruction }) =>
      noritoDecodeInstruction(extraTail, 753)),
    { message: "length mismatch" },
  );

  const invalidNativeResult = JSON.parse(JSON.stringify(instruction));
  invalidNativeResult.zk.FinalizeElection.tally_proof.lane_privacy.witness.payload
    .proof.audit_path = [];
  for (const options of [undefined, { parseJson: false }]) {
    const decodeWithNative = nativeInstructionDecoder(invalidNativeResult);
    assert.throws(
      () => decodeWithNative(Buffer.of(1), 753, options),
      /must contain 1\.\.=255 siblings/,
    );
  }
});

baseTest("direct dataspace registration retains exact namespace independently of balance policy", () => {
  for (const balanceScopePolicy of ["Global", "DataspaceRestricted"]) {
    const result = buildRegisterDataspaceAssetDefinitionInstruction({
      assetDefinitionId: "fixture-definition", name: "Unit", balanceScopePolicy,
      dataspaceId: "18446744073709551615",
    });
    assert.equal(result.RegisterDataspaceAssetDefinition.dataspace_id, 18446744073709551615n);
    assert.equal(result.RegisterDataspaceAssetDefinition.object.owning_domain, null);
    assert.equal(result.RegisterDataspaceAssetDefinition.object.balance_scope_policy, balanceScopePolicy);
  }
});

baseTest("direct dataspace registration rejects inferred, contradictory or lossy homes", () => {
  const base = { assetDefinitionId: "fixture-definition", name: "Unit", balanceScopePolicy: "DataspaceRestricted" };
  for (const dataspaceId of [undefined, null, 0, "0", "01", "1\n", "1\r\n", "1.0", "1e0", "+1", -1, Number.MAX_SAFE_INTEGER + 1, "18446744073709551616"]) {
    assert.throws(() => buildRegisterDataspaceAssetDefinitionInstruction({ ...base, dataspaceId }));
  }
  assert.throws(() => buildRegisterDataspaceAssetDefinitionInstruction({ ...base, dataspaceId: 7, owningDomain: "issuer.paynet" }));
  assert.throws(() => buildRegisterDataspaceAssetDefinitionInstruction({ ...base, dataspaceId: 7, dataspace_id: 8 }));
  assert.throws(() => buildRegisterDataspaceAssetDefinitionInstruction({ ...base, dataspaceId: 1, dataspace_id: "1\n" }));
});


function directDataspaceRegistrationFixture(options = {}) {
  return buildRegisterDataspaceAssetDefinitionInstruction({
    assetDefinitionId: ASSET_DEFINITION_ID,
    name: "Direct unit",
    dataspaceId: 0xffff_ffff_ffff_ffffn,
    balanceScopePolicy: "DataspaceRestricted",
    metadata: { fraction: 1.25, zero: -0 },
    ...options,
  });
}

baseTest("direct dataspace codec preserves full u64 tokens and ordinary metadata", () => {
  assert.equal(exactRegisterDataspaceAssetDefinitionJson({ Log: {} }), null);
  for (const dataspaceId of [1n, 9007199254740993n, 0xffff_ffff_ffff_ffffn]) {
    const instruction = directDataspaceRegistrationFixture({ dataspaceId });
    const exact = exactRegisterDataspaceAssetDefinitionJson(instruction);
    assert.ok(exact.includes(`"dataspace_id":${dataspaceId},`));
    assert.ok(exact.includes('"fraction":1.25'));
    assert.ok(exact.includes('"zero":0'));
    const calls = [];
    const codec = _createNoritoInstructionApi(createNativeRuntime({
      noritoEncodeInstruction(json) { calls.push(json); return Buffer.of(1); },
      noritoDecodeInstruction() { return exact; },
      noritoEncodeInstructionBoxArchive(json) { calls.push(json); return Buffer.of(2); },
      noritoDecodeInstructionBoxArchive() { return exact; },
    }));
    assert.deepEqual(codec.noritoEncodeInstruction(instruction, 753), Buffer.of(1));
    assert.deepEqual(codec.noritoEncodeInstructionBoxArchive(instruction, 753), Buffer.of(2));
    assert.deepEqual(calls, [exact, exact, exact]);
    for (const decoded of [
      codec.noritoDecodeInstruction(Buffer.of(1), 753),
      codec.noritoDecodeInstructionBoxArchive(Buffer.of(2), 753),
    ]) {
      assert.equal(BigInt(decoded.RegisterDataspaceAssetDefinition.dataspace_id), dataspaceId);
      assert.equal(decoded.RegisterDataspaceAssetDefinition.object.metadata.fraction, 1.25);
    }
    assert.equal(codec.noritoDecodeInstruction(Buffer.of(1), 753, { parseJson: false }), exact);
    assert.ok(codec._instructionWireSchemaBindings().some(({ outerWireId, innerTypeName }) =>
      outerWireId === "iroha.asset_definition.dataspace.register.v1" &&
      innerTypeName === "iroha_data_model::isi::register_dataspace_asset_definition::RegisterDataspaceAssetDefinition"));
  }
});

baseTest("direct dataspace codec rejects lossy object numbers and malformed decoded homes", () => {
  const instruction = directDataspaceRegistrationFixture();
  const payload = instruction.RegisterDataspaceAssetDefinition;
  for (const dataspace_id of [0, -1, 2n ** 64n, Number.MAX_SAFE_INTEGER + 1, "1", null]) {
    assert.throws(() => exactRegisterDataspaceAssetDefinitionJson({
      RegisterDataspaceAssetDefinition: { ...payload, dataspace_id },
    }));
  }
  for (const metadata of [{ value: Number.MAX_SAFE_INTEGER + 1 }, { value: 1n }, { value: Infinity }]) {
    assert.throws(() => exactRegisterDataspaceAssetDefinitionJson({
      RegisterDataspaceAssetDefinition: { ...payload, object: { ...payload.object, metadata } },
    }));
  }
  assert.throws(() => exactRegisterDataspaceAssetDefinitionJson({
    RegisterDataspaceAssetDefinition: { ...payload, unexpected: true },
  }));
  assert.throws(() => exactRegisterDataspaceAssetDefinitionJson({
    ...instruction, Register: {},
  }));
  const exact = exactRegisterDataspaceAssetDefinitionJson(instruction);
  let nativeJson;
  const codec = _createNoritoInstructionApi(createNativeRuntime({
    noritoDecodeInstruction() { return nativeJson; },
    noritoDecodeInstructionBoxArchive() { return nativeJson; },
  }));
  const invalid = [
    ...["0", "-1", "18446744073709551616", '"1"', "null", "1e0", "01", "1.0"].map(
      (value) => exact.replace('"dataspace_id":18446744073709551615', `"dataspace_id":${value}`)),
    exact.replace('"dataspace_id":18446744073709551615', '"dataspace_id":1,"dataspace_id":2'),
    exact.replace('"scale":null', '"scale":1.5'),
    exact.replace('"fraction":1.25', '"fraction":9007199254740993'),
  ];
  for (const malformed of invalid) {
    nativeJson = malformed;
    assert.throws(() => codec.noritoDecodeInstruction(Buffer.of(1), 753));
    assert.throws(() => codec.noritoDecodeInstructionBoxArchive(Buffer.of(2), 753));
  }
});

test("direct dataspace frame and archive use the distinct Native schema", () => {
  for (const dataspaceId of [9007199254740993n, 0xffff_ffff_ffff_ffffn]) {
    for (const balanceScopePolicy of ["Global", "DataspaceRestricted"]) {
      const instruction = directDataspaceRegistrationFixture({ dataspaceId, balanceScopePolicy });
      const exact = exactRegisterDataspaceAssetDefinitionJson(instruction);
      const frame = noritoEncodeInstruction(instruction, 753);
      assert.deepEqual(frame, Buffer.from(nativeBinding.noritoEncodeInstruction(exact, 753)));
      assert.equal(readInstructionEnvelopeWireId(frame, "direct dataspace"),
        "iroha.asset_definition.dataspace.register.v1");
      const archive = noritoEncodeInstructionBoxArchive(instruction, 753);
      for (const decoded of [noritoDecodeInstruction(frame, 753), noritoDecodeInstructionBoxArchive(archive, 753)]) {
        const payload = decoded.RegisterDataspaceAssetDefinition;
        assert.equal(payload.dataspace_id, dataspaceId);
        assert.equal(payload.object.owning_domain, null);
        assert.equal(payload.object.balance_scope_policy, balanceScopePolicy);
        assert.equal(payload.object.metadata.fraction, 1.25);
        assert.deepEqual(noritoEncodeInstruction(decoded, 753), frame);
      }
      for (const invalid of [
        exact.replace(`"dataspace_id":${dataspaceId}`, '"dataspace_id":0'),
        exact.replace(`"dataspace_id":${dataspaceId}`, '"dataspace_id":18446744073709551616'),
        exact.replace(`"dataspace_id":${dataspaceId}`, '"dataspace_id":"1"'),
        exact.replace(`"dataspace_id":${dataspaceId}`, '"dataspace_id":1,"dataspace_id":2'),
        exact.replace('"owning_domain":null', '"owning_domain":"issuer.paynet"'),
      ]) {
        assert.throws(() => noritoEncodeInstruction(invalid, 753));
      }
    }
  }
});

baseTest("direct dataspace aggregate transactions scope account-only mints and preserve bilateral buckets", () => {
  const captures = [];
  const transaction = _createTransactionApi(createNativeRuntime({
    buildTransaction(_network, _authority, instructions) {
      captures.push(instructions);
      return { signed_transaction: Buffer.of(1), hash: Buffer.alloc(32, 1) };
    },
  }));
  const common = {
    networkId: NetworkId.fromBytes(Buffer.alloc(32, 1)),
    authority: ACCOUNT_ID,
    feePayment: { payer: "authority", chargeLimits: [] },
    privateKey: Buffer.alloc(32, 1),
  };
  for (const build of [transaction.buildRegisterAssetDefinitionAndMintTransaction,
    transaction.buildRegisterAssetDefinitionMintAndTransferTransaction]) {
    build({ ...common, assetDefinition: {
      assetDefinitionId: ASSET_DEFINITION_ID, name: "Global unit",
      owningDomain: null, balanceScopePolicy: "Global",
    }, mint: { accountId: ACCOUNT_ID, quantity: "1" } });
    const global = captures.at(-1);
    assert.equal(JSON.parse(global[0]).Register.AssetDefinition.owning_domain, null);
    assert.equal(JSON.parse(global[1]).Mint.Asset.destination, ASSET_ID_CANONICAL);
    for (const policy of ["Global", "DataspaceRestricted"]) {
      const home = "18446744073709551615";
      const assetDefinition = {
        assetDefinitionId: ASSET_DEFINITION_ID, name: "Direct unit",
        owningDataspace: home, balanceScopePolicy: policy,
      };
      const transfer = { destinationAccountId: ACCOUNT_ID, quantity: "1" };
      const expected = `${ASSET_DEFINITION_ID}#${ACCOUNT_ID_CANONICAL}` +
        (policy === "DataspaceRestricted" ? `#dataspace:${home}` : "");
      build({ ...common, assetDefinition, mint: { accountId: ACCOUNT_ID, quantity: "2" }, transfer });
      const single = captures.at(-1);
      assert.ok(single[0].includes(`"dataspace_id":${home},`));
      assert.equal(JSON.parse(single[1]).Mint.Asset.destination, expected);
      if (single.length === 3) assert.equal(JSON.parse(single[2]).Transfer.Asset.source, expected);
      if (policy === "DataspaceRestricted") {
        const explicit = `${ASSET_DEFINITION_ID}#${ACCOUNT_ID_CANONICAL}#dataspace:9007199254740993`;
        build({ ...common, assetDefinition, mints: [
          { accountId: ACCOUNT_ID, assetHoldingId: explicit, quantity: "2" },
          { accountId: ACCOUNT_ID, quantity: "3" },
        ], transfer });
        const batch = captures.at(-1);
        assert.equal(JSON.parse(batch[1]).Mint.Asset.destination, explicit);
        assert.equal(JSON.parse(batch[2]).Mint.Asset.destination, expected);
        if (batch.length === 4) assert.equal(JSON.parse(batch[3]).Transfer.Asset.source, explicit);
      }
    }
  }
});

baseTest("mixed executable batches carry the exact direct dataspace numeral", () => {
  const captures = [];
  const transaction = _createTransactionApi(createNativeRuntime({
    buildExecutableBatchTransaction(_network, _authority, entries) {
      captures.push(entries);
      return { signed_transaction: Buffer.of(1), hash: Buffer.alloc(32, 1) };
    },
  }));
  const instruction = directDataspaceRegistrationFixture();
  const exact = exactRegisterDataspaceAssetDefinitionJson(instruction);
  transaction.buildExecutableBatchTransaction({
    networkId: NetworkId.fromBytes(Buffer.alloc(32, 1)),
    authority: ACCOUNT_ID,
    feePayment: { payer: "authority", chargeLimits: [], gasLimit: 100 },
    privateKey: Buffer.alloc(32, 1),
    entries: [
      { kind: "instruction", instruction },
      { kind: "instruction", instruction: exact },
      { kind: "contractCall", contractAddress: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
        expectedCodeHash: Buffer.alloc(32, 1), entrypoint: "apply", arguments: null },
    ],
  });
  assert.equal(captures.length, 1);
  assert.equal(captures[0][0], `{"kind":"instruction","instruction":${exact}}`);
  assert.equal(JSON.parse(captures[0][1]).instruction, exact);
  assert.equal(JSON.parse(captures[0][2]).kind, "contractCall");
});


baseTest("direct homes stay exact through Native draft views, signed inspection, and quote signing", () => {
  const instruction = directDataspaceRegistrationFixture();
  const exact = exactRegisterDataspaceAssetDefinitionJson(instruction);
  const common = {
    networkId: NetworkId.fromBytes(Buffer.alloc(32, 1)), authority: ACCOUNT_ID,
    feePayment: { payer: "authority", chargeLimits: [] },
  };
  for (const batch of [false, true]) {
    const executable = batch ? `{"Batch":[{"Instruction":${exact}}]}` : `{"Instructions":[${exact}]}`;
    const payloadJson = `{"instructions":${executable},"metadata":{"fraction":2.5,` +
      '"RegisterDataspaceAssetDefinition":{"dataspace_id":"ordinary metadata"}}}';
    const signedJson = `{"payload":${payloadJson},"signature":"fixture"}`;
    const captured = [];
    const nativeDraft = { payload_json: payloadJson, payload_bytes: Buffer.of(3),
      payload_hash: Buffer.alloc(32, 1) };
    const transaction = _createTransactionApi(createNativeRuntime({
      buildTransactionPayload(_network, _authority, instructions) {
        assert.equal(instructions[0], exact);
        return nativeDraft;
      },
      buildExecutableBatchTransactionPayload(_network, _authority, entries) {
        assert.equal(entries[0], `{"kind":"instruction","instruction":${exact}}`);
        return nativeDraft;
      },
      decodeSignedTransactionJson() { return signedJson; },
      signQuotedTransactionPayload(_network, json) {
        captured.push(json);
        return { signed_transaction: Buffer.of(1), hash: Buffer.alloc(32, 1) };
      },
    }));
    const draft = batch
      ? transaction.buildExecutableBatchTransactionPayload({ ...common,
          entries: [{ kind: "instruction", instruction }] })
      : transaction.buildTransactionPayload({ ...common, instructions: [instruction] });
    const selectInstruction = (payload) => batch
      ? payload.instructions.Batch[0].Instruction : payload.instructions.Instructions[0];
    assert.equal(draft.payloadJson, payloadJson);
    assert.equal(selectInstruction(draft.payload).RegisterDataspaceAssetDefinition.dataspace_id,
      0xffff_ffff_ffff_ffffn);
    assert.equal(draft.payload.metadata.fraction, 2.5);
    assert.equal(draft.payload.metadata.RegisterDataspaceAssetDefinition.dataspace_id,
      "ordinary metadata");
    const signed = transaction.decodeSignedTransaction(Buffer.of(1), 753);
    assert.equal(selectInstruction(signed.payload).RegisterDataspaceAssetDefinition.dataspace_id,
      0xffff_ffff_ffff_ffffn);
    for (const payload of [draft.payload, draft]) {
      transaction.signQuotedTransactionPayload({ networkId: common.networkId, payload,
        quotedFeePayment: common.feePayment, privateKey: Buffer.alloc(32, 1) });
    }
    assert.deepEqual(captured, [payloadJson, payloadJson]);
    const lossy = structuredClone(draft.payload);
    selectInstruction(lossy).RegisterDataspaceAssetDefinition.dataspace_id = Number.MAX_SAFE_INTEGER + 1;
    assert.throws(() => transaction.signQuotedTransactionPayload({ networkId: common.networkId,
      payload: lossy, quotedFeePayment: common.feePayment, privateKey: Buffer.alloc(32, 1) }));
    const collision = structuredClone(draft.payload);
    collision.metadata.marker = "__iroha-direct-dataspace-instruction-0__";
    assert.throws(() => transaction.signQuotedTransactionPayload({ networkId: common.networkId,
      payload: collision, quotedFeePayment: common.feePayment, privateKey: Buffer.alloc(32, 1) }),
    /marker collision/u);
    assert.equal(captured.length, 2);
  }
});
