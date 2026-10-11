import { universalArtifactInstruction } from "./contractArtifactTestHelpers.js";
import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  encodeQuantityNoritoValue,
  _createNoritoInstructionApi,
  noritoDecodeBlockProofs,
  noritoEncodeInstruction,
  noritoDecodeInstruction,
  noritoDecodeInstructionBoxArchive,
  noritoEncodeInstructionBoxArchive,
  noritoEncodeMultisigProposeRequest,
  encodeRetailFeeAssessmentV1,
  noritoEncodeMultisigContractCallProposeRequest,
  noritoEncodeMultisigContractCallApproveRequest,
  validateNoritoFrame,
  verifyBlockMerkleProof,
  verifyBlockProofs,
} from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import {
  makeNativeTest,
  nativeBinding,
  noritoRequiredMethods,
} from "./helpers/native.js";

const test = makeNativeTest(baseTest, { require: noritoRequiredMethods });
const UNAVAILABLE_NATIVE_BINDING = Object.freeze({
  noritoEncodeInstruction() {
    throw new Error("Native binding required; test override is unavailable");
  },
  noritoDecodeInstruction() {
    throw new Error("Native binding required; test override is unavailable");
  },
});
const UNAVAILABLE_NORITO_API = _createNoritoInstructionApi(
  createNativeRuntime(UNAVAILABLE_NATIVE_BINDING),
);
// Without a loadable native binding, fall back to the verified-loader runtime so
// the hermetic tests still run and native-gated tests report the load failure.
const NATIVE_NORITO_API = _createNoritoInstructionApi(
  createNativeRuntime(nativeBinding ?? undefined),
);
const {
  noritoDecodeInstruction: boundNoritoDecodeInstruction,
  noritoEncodeInstruction: boundNoritoEncodeInstruction,
  noritoEncodeInstructionBoxArchive: boundNoritoEncodeInstructionBoxArchive,
  noritoEncodeMultisigProposeRequest: boundNoritoEncodeMultisigProposeRequest,
} = NATIVE_NORITO_API;
const ACCOUNT_ID = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const SEED_11_ED25519_PUBLIC_KEY_HEX =
  "D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737";
const MULTISIG_SIGNER_ID =
  "sorauﾛ1P738ｷﾈｹｵﾙﾍﾉﾂUｿﾚｹﾑbﾄ1xYﾆｷvWzﾒkﾒ5ﾛﾘuE1ﾌsﾛXB6V1Y";

baseTest("Norito instruction APIs isolate immutable native runtimes", async () => {
  const bindingA = {
    label: "A",
    inspectSubscriptionTriggerAction() {
      return JSON.stringify({ label: this.label });
    },
  };
  const bindingB = {
    label: "B",
    inspectSubscriptionTriggerAction() {
      return JSON.stringify({ label: this.label });
    },
  };
  const apiA = _createNoritoInstructionApi(createNativeRuntime(bindingA));
  const apiB = _createNoritoInstructionApi(createNativeRuntime(bindingB));
  bindingA.label = "mutated";
  bindingB.inspectSubscriptionTriggerAction = () => JSON.stringify({ label: "mutated" });

  const [resultA, resultB] = await Promise.all([
    Promise.resolve().then(() => apiA.inspectSubscriptionTriggerAction("action-a", 753)),
    Promise.resolve().then(() => apiB.inspectSubscriptionTriggerAction("action-b", 753)),
  ]);
  assert.equal(Object.isFrozen(apiA), true);
  assert.deepEqual(resultA, { label: "A" });
  assert.deepEqual(resultB, { label: "B" });
});

baseTest("encodeQuantityNoritoValue enforces the nominal Quantity boundary", () => {
  assert.ok(
    encodeQuantityNoritoValue("18446744073709551616.25") instanceof Uint8Array,
  );
  for (const value of [
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
    1n << 511n,
    "9".repeat(155),
  ]) {
    assert.throws(
      () => encodeQuantityNoritoValue(value),
      /canonical|JavaScript numbers are rejected|mantissa|negative/u,
      `Quantity ${String(value).slice(0, 32)} must be rejected`,
    );
  }
});

baseTest("root entrypoints expose every declared typed Norito value encoder", async () => {
  const [root, browser, norito] = await Promise.all([
    import("../src/index.js"),
    import("../src/browser.js"),
    import("../src/norito.js"),
  ]);
  for (const runtime of [root, browser]) {
    assert.equal(typeof runtime.encodeAccountIdNoritoValue, "function");
    assert.equal(typeof runtime.encodeAssetDefinitionIdNoritoValue, "function");
    assert.equal(typeof runtime.encodeQuantityNoritoValue, "function");
    assert.equal("encodeNumericNoritoValue" in runtime, false);
  }
  assert.equal(typeof norito.encodeQuantityNoritoValue, "function");
  assert.equal("encodeNumericNoritoValue" in norito, false);
  assert.equal("encodeNumericNoritoValue" in root.Norito, false);
});

baseTest("public BlockProofs entrypoints do not fabricate trusted anchors", async () => {
  const [root, browser, norito] = await Promise.all([
    import("../src/index.js"),
    import("../src/browser.js"),
    import("../src/norito.js"),
  ]);
  for (const runtime of [root, browser, norito]) {
    const anchorFactories = Object.keys(runtime).filter((name) =>
      /(?:blockproof.*anchor|anchor.*blockproof)/iu.test(name));
    assert.deepEqual(anchorFactories, []);
    assert.equal(typeof runtime.noritoDecodeBlockProofs, "function");
    assert.equal(typeof runtime.verifyBlockProofs, "function");
  }
});

function canonicalSignatureBase64Fixture() {
  return Buffer.alloc(64, 0x01).toString("base64");
}

function authorityFeePayment(gasLimit = null) {
  return {
    payer: "authority",
    value: { charge_limits: [], gas_limit: gasLimit },
  };
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

function testCrc64Ecma(payload) {
  const mask = 0xffff_ffff_ffff_ffffn;
  const polynomial = 0xc96c_5795_d787_0f42n;
  let crc = mask;
  for (const byte of payload) {
    crc ^= BigInt(byte);
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1n) === 0n ? crc >> 1n : (crc >> 1n) ^ polynomial;
    }
  }
  return BigInt.asUintN(64, crc ^ mask);
}

function compactLength(value) {
  const bytes = [];
  let remaining = value;
  do {
    const byte = remaining & 0x7f;
    remaining >>>= 7;
    bytes.push(remaining === 0 ? byte : byte | 0x80);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function proofField(payload) {
  return Buffer.concat([compactLength(payload.length), payload]);
}

function proofStruct(...fields) {
  return Buffer.concat(fields.map(proofField));
}

function proofU64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
}

function proofU32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

function proofVec(values) {
  return Buffer.concat([proofU64(values.length), ...values.map(proofField)]);
}

function proofOption(value) {
  return value === null ? Buffer.of(0) : Buffer.concat([Buffer.of(1), proofField(value)]);
}

const blockMerkleLeafDomain = Buffer.from("iroha:merkle:leaf:v1\0", "utf8");
const blockMerkleInternalDomain = Buffer.from("iroha:merkle:internal:v1\0", "utf8");

function blockMerkleDigest(preimage) {
  const digest = Buffer.from(blake2b(preimage, { dkLen: 32 }));
  digest[31] |= 1;
  return digest;
}

function blockMerkleLeafNode(rawLeaf) {
  return blockMerkleDigest(Buffer.concat([blockMerkleLeafDomain, rawLeaf]));
}

function blockProofHashLiteralBytes(value) {
  const match = /^hash:([0-9A-Fa-f]{64})#[0-9A-Fa-f]{4}$/u.exec(value);
  assert.ok(match, "expected canonical Iroha hash literal");
  return Buffer.from(match[1], "hex");
}

function blockMerkleParent(left, right) {
  if (right === null) return left;
  return blockMerkleDigest(Buffer.concat([blockMerkleInternalDomain, left, right]));
}

function authenticatedBlockProofAnchorFixture() {
  const entryHash = Buffer.alloc(32, 0x20);
  entryHash[31] |= 1;
  const resultHash = Buffer.alloc(32, 0x50);
  resultHash[31] |= 1;
  const blockHash = Buffer.alloc(32, 0x30);
  blockHash[31] |= 1;
  const executedBlockWireHash = Buffer.alloc(32, 0x40);
  executedBlockWireHash[31] |= 1;
  return {
    block_height: "7",
    block_hash: blockHash.toString("hex"),
    executed_block_wire_hash: executedBlockWireHash.toString("hex"),
    entry_hash: entryHash.toString("hex"),
    entry_index: 0,
    entry_commitment: {
      root: blockMerkleLeafNode(entryHash).toString("hex"),
      leaf_count: "1",
    },
    result_commitment: {
      root: blockMerkleLeafNode(resultHash).toString("hex"),
      leaf_count: "1",
    },
    fastpq_transcripts: {},
  };
}

function blockProofFixture({ nullableResults = false, resultLeafCount = 1 } = {}) {
  const leaf = Buffer.alloc(32, 0x20);
  leaf[31] |= 1;
  const resultLeaf = Buffer.alloc(32, 0x50);
  resultLeaf[31] |= 1;
  const blockHash = Buffer.alloc(32, 0x30);
  blockHash[31] |= 1;
  const executedBlockWireHash = Buffer.alloc(32, 0x40);
  executedBlockWireHash[31] |= 1;
  const merkleProof = proofStruct(proofU32(0), proofVec([]));
  const entryCommitment = proofStruct(blockMerkleLeafNode(leaf), proofU64(1));
  const receipt = proofStruct(leaf, merkleProof);
  const resultCommitment = proofStruct(
    blockMerkleLeafNode(resultLeaf),
    proofU64(resultLeafCount),
  );
  const resultReceipt = proofStruct(resultLeaf, merkleProof);
  const payload = proofStruct(
    proofU64(7),
    blockHash,
    executedBlockWireHash,
    leaf,
    entryCommitment,
    receipt,
    nullableResults ? proofOption(null) : resultCommitment,
    nullableResults ? proofOption(null) : resultReceipt,
    proofU64(0),
  );
  const schemaHash = Buffer.from(
    sha256(Buffer.from(
      "norito:v1:type-name\0iroha_data_model::block::proofs::BlockProofs",
      "utf8",
    )).subarray(0, 16),
  );
  const header = Buffer.concat([
    Buffer.from("NRT0", "ascii"),
    Buffer.of(0, 0),
    schemaHash,
    Buffer.of(0),
    proofU64(payload.length),
    proofU64(testCrc64Ecma(payload)),
    Buffer.of(0x02),
  ]);
  return Buffer.concat([header, payload]);
}

baseTest("Norito BlockProofs decoder binds the exact schema and verifies a canonical receipt", () => {
  const fixture = blockProofFixture();
  const decoded = noritoDecodeBlockProofs(fixture);

  assert.equal(decoded.block_height, "7");
  assert.deepEqual(
    blockProofHashLiteralBytes(decoded.entry_commitment.root),
    blockMerkleLeafNode(blockProofHashLiteralBytes(decoded.entry_hash)),
  );
  assert.equal(decoded.entry_commitment.leaf_count, "1");
  assert.equal(decoded.entry_proof.leaf, decoded.entry_hash);
  assert.deepEqual(decoded.entry_proof.proof, { leaf_index: 0, audit_path: [] });
  assert.equal(decoded.result_commitment.leaf_count, "1");
  assert.deepEqual(
    blockProofHashLiteralBytes(decoded.result_commitment.root),
    blockMerkleLeafNode(blockProofHashLiteralBytes(decoded.result_proof.leaf)),
  );
  assert.deepEqual(decoded.result_proof.proof, { leaf_index: 0, audit_path: [] });
  assert.deepEqual(decoded.fastpq_transcripts, {});
  assert.deepEqual(verifyBlockProofs(decoded, authenticatedBlockProofAnchorFixture()), {
    valid: true,
    anchor_matches: true,
    entry_hash_matches: true,
    entry_proof_valid: true,
    result_pair_consistent: true,
    result_proof_valid: true,
  });

  const corrupted = Buffer.from(fixture);
  corrupted[corrupted.length - 1] ^= 1;
  assert.throws(() => noritoDecodeBlockProofs(corrupted), /CRC64 mismatch/u);
});

baseTest("Norito BlockProofs decoder rejects the retired nullable result layout", () => {
  assert.throws(
    () => noritoDecodeBlockProofs(blockProofFixture({ nullableResults: true })),
    /BlockProofs\.result_commitment/u,
  );
});

baseTest("Norito BlockProofs decoder rejects misaligned entry/result counts", () => {
  assert.throws(
    () => noritoDecodeBlockProofs(blockProofFixture({ resultLeafCount: 2 })),
    /entry\/result commitment leaf counts must match/u,
  );
});

baseTest("validateNoritoFrame accepts only 0x00 and COMPACT_LEN header flags", () => {
  const payload = Buffer.from([1]);
  for (let flags = 0; flags <= 0xff; flags += 1) {
    const frame = Buffer.alloc(41);
    frame.write("NRT0", 0, "ascii");
    frame.fill(0x11, 6, 22);
    frame.writeBigUInt64LE(1n, 23);
    frame.writeBigUInt64LE(testCrc64Ecma(payload), 31);
    frame[39] = flags;
    payload.copy(frame, 40);
    if (flags === 0x00 || flags === 0x02) {
      assert.equal(validateNoritoFrame(frame).flags, flags);
    } else {
      assert.throws(() => validateNoritoFrame(frame), /Norito header flags/u);
    }
  }
});

baseTest("Norito BlockProofs decoder rejects packed header flags", () => {
  for (const flags of [0x01, 0x04, 0x06, 0x20, 0x26]) {
    const frame = blockProofFixture();
    frame[39] = flags;
    assert.throws(() => noritoDecodeBlockProofs(frame), /Norito header flags/u);
  }
});

baseTest("block proof verification rejects direction, root, and result-pair mismatches", () => {
  const left = Buffer.alloc(32, 0x40);
  const right = Buffer.alloc(32, 0x60);
  left[31] |= 1;
  right[31] |= 1;
  const leftNode = blockMerkleLeafNode(left);
  const rightNode = blockMerkleLeafNode(right);
  const root = blockMerkleParent(leftNode, rightNode);
  const commitment = { root: root.toString("hex"), leaf_count: "2" };

  assert.equal(
    verifyBlockMerkleProof(
      left.toString("hex"),
      { leaf_index: 0, audit_path: [rightNode.toString("hex")] },
      commitment,
    ),
    true,
  );
  assert.equal(
    verifyBlockMerkleProof(
      left.toString("hex"),
      { leaf_index: 1, audit_path: [rightNode.toString("hex")] },
      commitment,
    ),
    false,
  );

  const decoded = noritoDecodeBlockProofs(blockProofFixture());
  const mismatchedResult = {
    ...decoded,
    result_commitment: decoded.entry_commitment,
    result_proof: null,
  };
  const verification = verifyBlockProofs(
    mismatchedResult,
    authenticatedBlockProofAnchorFixture(),
  );
  assert.equal(verification.valid, false);
  assert.equal(verification.result_pair_consistent, false);
  assert.equal(verification.result_proof_valid, false);

  const mismatchedIndex = {
    ...decoded,
    result_commitment: decoded.entry_commitment,
    result_proof: {
      leaf: decoded.entry_hash,
      proof: { leaf_index: 1, audit_path: [] },
    },
  };
  const independentlyAuthenticatedAnchor = authenticatedBlockProofAnchorFixture();
  const resultAnchor = {
    ...independentlyAuthenticatedAnchor,
    result_commitment: independentlyAuthenticatedAnchor.entry_commitment,
  };
  const indexVerification = verifyBlockProofs(mismatchedIndex, resultAnchor);
  assert.equal(indexVerification.result_pair_consistent, false);
  assert.equal(indexVerification.valid, false);

  const otherEntry = Buffer.alloc(32, 0x66);
  otherEntry[31] |= 1;
  const entryNode = blockMerkleLeafNode(
    Buffer.from(authenticatedBlockProofAnchorFixture().entry_hash, "hex"),
  );
  const otherEntryNode = blockMerkleLeafNode(otherEntry);
  const twoEntryCommitment = {
    root: blockMerkleParent(entryNode, otherEntryNode).toString("hex"),
    leaf_count: "2",
  };
  const countMisaligned = {
    ...decoded,
    entry_commitment: twoEntryCommitment,
    entry_proof: {
      ...decoded.entry_proof,
      proof: { leaf_index: 0, audit_path: [otherEntryNode.toString("hex")] },
    },
  };
  const countAnchor = {
    ...authenticatedBlockProofAnchorFixture(),
    entry_commitment: twoEntryCommitment,
  };
  const countVerification = verifyBlockProofs(countMisaligned, countAnchor);
  assert.equal(countVerification.entry_proof_valid, true);
  assert.equal(countVerification.result_pair_consistent, false);
  assert.equal(countVerification.valid, false);
});

baseTest("block Merkle proofs enforce exact ragged geometry and domain separation", () => {
  const leaves = Array.from({ length: 5 }, (_, index) => {
    const leaf = Buffer.alloc(32, 0x50 + index);
    leaf[31] |= 1;
    return leaf;
  });
  const proofFor = (target) => {
    const siblings = [];
    let level = leaves.map(blockMerkleLeafNode);
    let index = target;
    while (level.length > 1) {
      const siblingIndex = index ^ 1;
      siblings.push(siblingIndex < level.length ? level[siblingIndex] : null);
      const parents = [];
      for (let offset = 0; offset < level.length; offset += 2) {
        parents.push(blockMerkleParent(level[offset], level[offset + 1] ?? null));
      }
      level = parents;
      index >>= 1;
    }
    return { root: level[0], siblings };
  };
  const last = proofFor(4);
  const commitment = { root: last.root.toString("hex"), leaf_count: "5" };
  const proof = {
    leaf_index: 4,
    audit_path: last.siblings.map((sibling) => sibling?.toString("hex") ?? null),
  };
  assert.equal(verifyBlockMerkleProof(leaves[4].toString("hex"), proof, commitment), true);
  assert.equal(
    verifyBlockMerkleProof(
      leaves[4].toString("hex"),
      { ...proof, audit_path: [leaves[0].toString("hex"), ...proof.audit_path.slice(1)] },
      commitment,
    ),
    false,
  );
  assert.equal(
    verifyBlockMerkleProof(
      leaves[4].toString("hex"),
      { ...proof, audit_path: proof.audit_path.slice(0, -1) },
      commitment,
    ),
    false,
  );
  assert.equal(
    verifyBlockMerkleProof(leaves[4].toString("hex"), proof, { ...commitment, leaf_count: "4" }),
    false,
  );
  assert.equal(
    verifyBlockMerkleProof(leaves[4].toString("hex"), { ...proof, leaf_index: 5 }, commitment),
    false,
  );

  const committedLeft = blockMerkleLeafNode(leaves[0]);
  const committedRight = blockMerkleLeafNode(leaves[1]);
  const missingLeafDomainRoot = blockMerkleParent(leaves[0], leaves[1]);
  assert.equal(
    verifyBlockMerkleProof(
      leaves[0].toString("hex"),
      { leaf_index: 0, audit_path: [leaves[1].toString("hex")] },
      { root: missingLeafDomainRoot.toString("hex"), leaf_count: "2" },
    ),
    false,
  );
  const missingInternalDomainRoot = blockMerkleDigest(
    Buffer.concat([committedLeft, committedRight]),
  );
  assert.equal(
    verifyBlockMerkleProof(
      leaves[0].toString("hex"),
      { leaf_index: 0, audit_path: [committedRight.toString("hex")] },
      { root: missingInternalDomainRoot.toString("hex"), leaf_count: "2" },
    ),
    false,
  );
});

baseTest("BlockProofs verification refuses roots that are not bound to a trusted anchor", () => {
  const decoded = noritoDecodeBlockProofs(blockProofFixture());
  assert.equal(verifyBlockProofs(decoded).valid, false);
  assert.equal(verifyBlockProofs(decoded, decoded).valid, false);

  const forgedLeaf = Buffer.alloc(32, 0x72);
  forgedLeaf[31] |= 1;
  const forgedRoot = blockMerkleLeafNode(forgedLeaf);
  const forged = {
    ...decoded,
    entry_hash: forgedLeaf.toString("hex"),
    entry_commitment: { root: forgedRoot.toString("hex"), leaf_count: "1" },
    entry_proof: {
      leaf: forgedLeaf.toString("hex"),
      proof: { leaf_index: 0, audit_path: [] },
    },
  };
  const verification = verifyBlockProofs(
    forged,
    authenticatedBlockProofAnchorFixture(),
  );
  assert.equal(verification.entry_proof_valid, false);
  assert.equal(verification.anchor_matches, false);
  assert.equal(verification.valid, false);
});

baseTest("BlockProofs verification binds the authenticated FASTPQ transcript projection", () => {
  const decoded = noritoDecodeBlockProofs(blockProofFixture());
  const forged = {
    ...decoded,
    fastpq_transcripts: { forged: [] },
  };

  const verification = verifyBlockProofs(
    forged,
    authenticatedBlockProofAnchorFixture(),
  );
  assert.equal(verification.anchor_matches, false);
  assert.equal(verification.valid, false);

  const missingProjection = { ...decoded };
  delete missingProjection.fastpq_transcripts;
  const missingAnchor = { ...authenticatedBlockProofAnchorFixture() };
  delete missingAnchor.fastpq_transcripts;
  const missingVerification = verifyBlockProofs(missingProjection, missingAnchor);
  assert.equal(missingVerification.anchor_matches, false);
  assert.equal(missingVerification.valid, false);
});

baseTest("BlockProofs verification binds the requested entry hash and execution index", () => {
  const decoded = noritoDecodeBlockProofs(blockProofFixture());
  const left = Buffer.alloc(32, 0x74);
  const right = Buffer.alloc(32, 0x76);
  left[31] |= 1;
  right[31] |= 1;
  const leftNode = blockMerkleLeafNode(left);
  const rightNode = blockMerkleLeafNode(right);
  const commitment = {
    root: blockMerkleParent(leftNode, rightNode).toString("hex"),
    leaf_count: "2",
  };
  const resultLeft = Buffer.alloc(32, 0x50);
  resultLeft[31] |= 1;
  const resultRight = Buffer.alloc(32, 0x78);
  resultRight[31] |= 1;
  const resultLeftNode = blockMerkleLeafNode(resultLeft);
  const resultRightNode = blockMerkleLeafNode(resultRight);
  const resultCommitment = {
    root: blockMerkleParent(resultLeftNode, resultRightNode).toString("hex"),
    leaf_count: "2",
  };
  const anchor = {
    ...authenticatedBlockProofAnchorFixture(),
    entry_hash: left.toString("hex"),
    entry_index: 0,
    entry_commitment: commitment,
    result_commitment: resultCommitment,
  };
  const substituted = {
    ...decoded,
    entry_hash: right.toString("hex"),
    entry_commitment: commitment,
    entry_proof: {
      leaf: right.toString("hex"),
      proof: { leaf_index: 1, audit_path: [leftNode.toString("hex")] },
    },
    result_commitment: resultCommitment,
    result_proof: {
      leaf: resultRight.toString("hex"),
      proof: { leaf_index: 1, audit_path: [resultLeftNode.toString("hex")] },
    },
  };

  const verification = verifyBlockProofs(substituted, anchor);
  assert.equal(verification.entry_proof_valid, true);
  assert.equal(verification.result_pair_consistent, true);
  assert.equal(verification.result_proof_valid, true);
  assert.equal(verification.entry_hash_matches, false);
  assert.equal(verification.anchor_matches, false);
  assert.equal(verification.valid, false);
});

function rewriteNestedInstructionFrameCrcs(buffer) {
  const { length: outerPayloadLength } = readU64Length(
    buffer,
    23,
    "instruction.outer.payload",
  );
  const outerPayload = buffer.subarray(buffer.length - outerPayloadLength);
  const compactLength = (buffer[39] & 0x02) !== 0;
  const wireId = readNoritoFieldPayload(
    outerPayload,
    0,
    "instruction.outer.wire",
    compactLength,
  );
  const innerWrapper = readNoritoFieldPayload(
    outerPayload,
    wireId.offset,
    "instruction.outer.inner",
    compactLength,
  );
  assert.equal(innerWrapper.offset, outerPayload.length);
  const { length: innerFrameLength } = readU64Length(
    innerWrapper.payload,
    0,
    "instruction.inner.frame",
  );
  const innerFrame = innerWrapper.payload.subarray(8);
  assert.equal(innerFrame.length, innerFrameLength);
  const { length: innerPayloadLength } = readU64Length(
    innerFrame,
    23,
    "instruction.inner.payload",
  );
  const innerPayloadStart = innerFrame.length - innerPayloadLength;
  innerFrame.writeBigUInt64LE(
    testCrc64Ecma(
      innerFrame.subarray(innerPayloadStart, innerPayloadStart + innerPayloadLength),
    ),
    31,
  );
  buffer.writeBigUInt64LE(
    testCrc64Ecma(outerPayload),
    31,
  );
}

const REGISTER_DOMAIN = {
  Register: {
    Domain: {
      id: "wonderland.sora",
      logo: null,
      metadata: {
        key: "value",
      },
    },
  },
};

const REGISTER_ACCOUNT = {
  Register: {
    Account: {
      id: ACCOUNT_ID,
      label: null,
      uaid: null,
      opaque_ids: [],
      metadata: { nickname: "alice" },
    },
  },
};

const REGISTER_ASSET = {
  Register: {
    AssetDefinition: {
      id: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
      name: "",
      description: null,
      alias: null,
      logo: null,
      metadata: {},
      mintable: "Infinitely",
      spec: { scale: null },
      balance_scope_policy: "Global",
      owning_domain: null,
    },
  },
};

const REGISTER_ASSET_WITH_OPTIONAL_FIELDS = {
  Register: {
    AssetDefinition: {
      id: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
      name: "demo",
      description: "Demo settlement PoC asset",
      alias: "demo#settlement.main",
      logo: "sorafs://bafybeigdyrztk/logo/demo.png",
      metadata: {
        purpose: "poc",
      },
      mintable: "Limited(5)",
      spec: { scale: 2 },
      balance_scope_policy: "DataspaceRestricted",
      owning_domain: "settlement.main",
    },
  },
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..", "..");

function loadInstructionFixture(name) {
  const fixturePath = path.join(repoRoot, "fixtures", "norito_instructions", name);
  const raw = fs.readFileSync(fixturePath, "utf8");
  return JSON.parse(raw);
}

function loadInstructionBytes(name) {
  const fixture = loadInstructionFixture(name);
  return Buffer.from(fixture.instruction, "base64");
}

function loadAssetIdFromFixture(name) {
  const decoded = noritoDecodeInstruction(loadInstructionBytes(name), 753);
  const destination = decoded?.Mint?.Asset?.destination ?? decoded?.Burn?.Asset?.destination;
  if (typeof destination !== "string" || !destination.includes("#")) {
    throw new Error(`fixture ${name} did not decode to canonical public AssetId literal`);
  }
  return destination;
}



function readU64Length(buffer, offset, label) {
  assert.ok(offset + 8 <= buffer.length, `${label} length prefix is in bounds`);
  const value = buffer.readBigUInt64LE(offset);
  assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} length fits JS number`);
  return { length: Number(value), bytes: 8 };
}

function readCompactLength(buffer, offset, label) {
  let value = 0n;
  let shift = 0n;
  let cursor = offset;
  for (; cursor < buffer.length; cursor += 1) {
    const byte = buffer[cursor];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} length fits JS number`);
      return { length: Number(value), bytes: cursor + 1 - offset };
    }
    shift += 7n;
  }
  assert.fail(`${label} compact length prefix is unterminated`);
}

function readNoritoFieldPayload(buffer, offset, label, compactLength) {
  const { length, bytes } = compactLength
    ? readCompactLength(buffer, offset, label)
    : readU64Length(buffer, offset, label);
  const start = offset + bytes;
  const end = start + length;
  assert.ok(end <= buffer.length, `${label} payload is in bounds`);
  return { payload: buffer.subarray(start, end), offset: end };
}

function noritoFramePayload(body, label) {
  const buffer = Buffer.from(body);
  assert.equal(buffer.subarray(0, 4).toString("ascii"), "NRT0");
  const { length: payloadLength } = readU64Length(buffer, 23, `${label}.payloadLength`);
  assert.equal(buffer.length, 40 + payloadLength);
  return {
    flags: buffer[39],
    payload: buffer.subarray(40),
  };
}

test("noritoEncodeInstruction returns canonical bytes", () => {
  const encoded = noritoEncodeInstruction(REGISTER_DOMAIN, 753);
  assert.ok(Buffer.isBuffer(encoded));
  assert.ok(encoded.length > 32);
});

test("noritoDecodeInstruction round-trips instruction JSON", () => {
  const encoded = noritoEncodeInstruction(REGISTER_DOMAIN, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, REGISTER_DOMAIN);
});

test("contract activation lifecycle instructions retain mandatory CAS revisions", () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  for (const instruction of [
    {
      ActivateContractInstance: {
        contract_address: contractAddress,
        expected_revision: "7",
        code_hash: `hash:${"AB".repeat(32)}#B99E`,
      },
    },
    {
      DeactivateContractInstance: {
        contract_address: contractAddress,
        expected_revision: "8",
        reason: "incident containment",
      },
    },
    {
      SetContractParliamentDelegation: {
        contract_address: contractAddress,
        expected_revision: "9",
        delegated: true,
      },
    },
    {
      OfferContractOwnership: {
        contract_address: contractAddress,
        expected_revision: "10",
        new_owner: { owner: "Account", value: ACCOUNT_ID },
      },
    },
    {
      OfferContractOwnership: {
        contract_address: contractAddress,
        expected_revision: "11",
        new_owner: { owner: "Parliament", value: null },
      },
    },
    {
      AcceptContractOwnership: {
        contract_address: contractAddress,
        expected_revision: "12",
      },
    },
    {
      CancelContractOwnershipOffer: {
        contract_address: contractAddress,
        expected_revision: "13",
      },
    },
  ]) {
    const decoded = boundNoritoDecodeInstruction(boundNoritoEncodeInstruction(instruction, 753), 753);
    assert.deepEqual(decoded, instruction);
  }
});

baseTest("native instruction decoding is deterministic across process history", () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  const instructions = [
    {
      SetContractParliamentDelegation: {
        contract_address: contractAddress,
        expected_revision: "9",
        delegated: true,
      },
    },
    {
      OfferContractOwnership: {
        contract_address: contractAddress,
        expected_revision: "10",
        new_owner: { owner: "Parliament", value: null },
      },
    },
    {
      AcceptContractOwnership: {
        contract_address: contractAddress,
        expected_revision: "12",
      },
    },
    {
      CancelContractOwnershipOffer: {
        contract_address: contractAddress,
        expected_revision: "13",
      },
    },
    {
      Kaigi: {
        UnregisterKaigiRelay: {
          relay_id: ACCOUNT_ID,
        },
      },
    },
  ];
  const cacheSymbol = Symbol.for("iroha.js.noritoInstructionCache");
  const previousCache = globalThis[cacheSymbol];
  const poison = new Map();
  globalThis[cacheSymbol] = poison;
  try {
    for (const instruction of instructions) {
      const encoded = boundNoritoEncodeInstruction(instruction, 753);
      poison.set(encoded.toString("hex"), {
        Log: { level: "ERROR", message: "forged cache entry" },
      });
      assert.deepEqual(
        boundNoritoDecodeInstruction(encoded, 753),
        instruction,
      );
      assert.deepEqual(
        JSON.parse(
          boundNoritoDecodeInstruction(encoded, 753, { parseJson: false }),
        ),
        instruction,
      );

      const archive = boundNoritoEncodeInstructionBoxArchive(instruction, 753);
      assert.deepEqual(
        noritoDecodeInstructionBoxArchive(archive, 753),
        instruction,
      );

      const moduleUrl = pathToFileURL(
        path.join(repoRoot, "javascript", "iroha_js", "src", "norito.js"),
      ).href;
      const script = `
        const { noritoDecodeInstruction } = await import(${JSON.stringify(moduleUrl)});
        const decoded = noritoDecodeInstruction(
          Buffer.from(${JSON.stringify(encoded.toString("base64"))}, "base64"),
          753,
          { parseJson: false },
        );
        process.stdout.write(decoded);
      `;
      const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
        encoding: "utf8",
      });
      assert.equal(child.status, 0, child.stderr);
      assert.deepEqual(JSON.parse(child.stdout), instruction);
    }
    assert.equal(poison.size, instructions.length);
  } finally {
    if (previousCache === undefined) {
      delete globalThis[cacheSymbol];
    } else {
      globalThis[cacheSymbol] = previousCache;
    }
  }
});

test("contract activation lifecycle instructions reject omitted CAS revisions", () => {
  const contractAddress =
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
  for (const instruction of [
    {
      ActivateContractInstance: {
        contract_address: contractAddress,
        code_hash: "ab".repeat(32),
      },
    },
    {
      DeactivateContractInstance: {
        contract_address: contractAddress,
        reason: null,
      },
    },
    {
      SetContractParliamentDelegation: {
        contract_address: contractAddress,
        delegated: true,
      },
    },
    {
      OfferContractOwnership: {
        contract_address: contractAddress,
        new_owner: { owner: "Parliament", value: null },
      },
    },
    {
      AcceptContractOwnership: { contract_address: contractAddress },
    },
    {
      CancelContractOwnershipOffer: { contract_address: contractAddress },
    },
  ]) {
    assert.throws(
      () => boundNoritoEncodeInstruction(instruction, 753),
      /expected_revision/u,
    );
  }
});

test("norito encode/decode supports account registration", () => {
  const encoded = noritoEncodeInstruction(REGISTER_ACCOUNT, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, REGISTER_ACCOUNT);
});

test("norito encode/decode supports asset definition registration", () => {
  const encoded = noritoEncodeInstruction(REGISTER_ASSET, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, REGISTER_ASSET);
});

baseTest("injected native codec roundtrips asset definition registration", () => {
  {
    const encoded = boundNoritoEncodeInstruction(REGISTER_ASSET, 753);
    const decoded = boundNoritoDecodeInstruction(encoded, 753);
    assert.deepEqual(decoded, REGISTER_ASSET);
  }
});

baseTest("native asset definition codec preserves optional registration fields", () => {
  {
    const encoded = boundNoritoEncodeInstruction(REGISTER_ASSET_WITH_OPTIONAL_FIELDS, 753);
    const decoded = boundNoritoDecodeInstruction(encoded, 753);
    assert.deepEqual(decoded, REGISTER_ASSET_WITH_OPTIONAL_FIELDS);
  }
});

test("public native decoder accepts injected native asset definition frames", () => {
  const encoded = boundNoritoEncodeInstruction(REGISTER_ASSET_WITH_OPTIONAL_FIELDS, 753);
  assert.deepEqual(noritoDecodeInstruction(encoded, 753), REGISTER_ASSET_WITH_OPTIONAL_FIELDS);
});

baseTest("native asset definition codec rejects adversarial fields", () => {
  const withAssetPatch = (patch) => ({
    Register: {
      AssetDefinition: {
        ...REGISTER_ASSET.Register.AssetDefinition,
        ...patch,
      },
    },
  });
  {
    const missingOwnership = withAssetPatch({});
    delete missingOwnership.Register.AssetDefinition.owning_domain;
    assert.throws(
      () => boundNoritoEncodeInstruction(missingOwnership, 753),
      /missing field `owning_domain`/u,
    );
    const missingBalancePolicy = withAssetPatch({});
    delete missingBalancePolicy.Register.AssetDefinition.balance_scope_policy;
    assert.throws(
      () => boundNoritoEncodeInstruction(missingBalancePolicy, 753),
      /missing field `balance_scope_policy`/u,
    );
    assert.throws(
      () => boundNoritoEncodeInstruction(withAssetPatch({ mintable: "Limited(0)" }), 753),
      /invalid field `Mintable`: Limited mintability token count `0` is invalid/u,
    );
    assert.throws(
      () =>
        boundNoritoEncodeInstruction(
          withAssetPatch({ mintable: { kind: "Limited", tokens: 5 } }), 753,
        ),
      /JSON error: unexpected character `\{`/u,
    );
    assert.throws(
      () =>
        boundNoritoEncodeInstruction(
          withAssetPatch({ mintable: { kind: "Limited", value: "5" } }), 753,
        ),
      /JSON error: unexpected character `\{`/u,
    );
    assert.throws(
      () =>
        boundNoritoEncodeInstruction(
          withAssetPatch({ balance_scope_policy: "ObserverScoped" }), 753,
        ),
      /invalid field `AssetBalancePolicy`: unknown variant 'ObserverScoped'/u,
    );
    assert.throws(
      () =>
        boundNoritoEncodeInstruction(
          withAssetPatch({
            confidential_policy: { mode: "Convertible" },
          }), 753,
        ),
      /unknown field `confidential_policy`/u,
    );
    assert.throws(
      () => boundNoritoEncodeInstruction(withAssetPatch({ logo: "https://example.invalid/logo.png" }), 753),
      { message: "Logo URI must use `sorafs://` scheme" },
    );
    assert.throws(
      () =>
        boundNoritoEncodeInstruction(
          withAssetPatch({ id: "62Fk4FPcMuLvW5QjDGNF2a4jAmxM" }), 753,
        ),
      /checksum is invalid/,
    );
  }
});

test("norito encode/decode supports mint asset instructions", () => {
  const instruction = {
    Mint: {
      Asset: {
        object: "42",
        destination: loadAssetIdFromFixture("mint_asset_quantity.json"),
      },
    },
  };
  const encoded = noritoEncodeInstruction(instruction, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, instruction);
});

test("norito encode/decode supports transfer asset instructions", () => {
  const instruction = {
    Transfer: {
      Asset: {
        source: loadAssetIdFromFixture("mint_asset_quantity.json"),
        object: "10",
        destination: ACCOUNT_ID,
      },
    },
  };
  const encoded = noritoEncodeInstruction(instruction, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, instruction);
});

baseTest("injected native codec encodes supported instruction JSON", () => {
  const instruction = {
    Transfer: {
      Asset: {
        source: loadAssetIdFromFixture("mint_asset_quantity.json"),
        object: "7",
        destination: ACCOUNT_ID,
      },
    },
  };
  let encoded;
  {
    encoded = Buffer.from(boundNoritoEncodeInstruction(instruction, 753));
  }
  assert.ok(encoded.length > 32);
  assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);

});

test("contract manifest codec preserves the canonical seiyaku name", () => {
  const instruction = universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        permissions: [], events: [], enum_types: [],
        seiyaku_name: "Ledger",
        entrypoints: null,
        kotoba: null,
      },
    },
  });
  let encoded;
  {
    encoded = Buffer.from(boundNoritoEncodeInstruction(instruction, 753));
  }
  assert.deepEqual(noritoDecodeInstruction(encoded, 753), universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        permissions: [], events: [], enum_types: [],
        seiyaku_name: "Ledger",
        code_hash: null,
        abi_hash: null,
        compiler_fingerprint: null,
        features_bitmap: null,
        access_set_hints: null,
        entrypoints: null,
        states: null,
        error_types: null,
        error_messages: null,
        kotoba: null,
        provenance: null,
      },
    },
  }));
});

test("contract manifest codec matches Rust V1 trigger bytes", () => {
  const fixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "contract_manifest_v1.json"), "utf8"),
  );
  const instruction = universalArtifactInstruction({
    RegisterSmartContractCode: { manifest: fixture.manifest },
  });
  const encoded = Buffer.from(boundNoritoEncodeInstruction(instruction, 753));
  const rustManifest = Buffer.from(fixture.manifest_compact_hex, "hex");
  assert.notEqual(
    encoded.indexOf(rustManifest),
    -1,
    "instruction embeds the exact Rust-generated compact manifest payload",
  );
  assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);

  const signedInstruction = universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        ...fixture.manifest,
        provenance: fixture.signed_provenance,
      },
    },
  });
  const signedEncoded = Buffer.from(boundNoritoEncodeInstruction(signedInstruction, 753));
  assert.notEqual(
    signedEncoded.indexOf(Buffer.from(fixture.signed_manifest_compact_hex, "hex")),
    -1,
    "provenance uses the exact Rust PublicKey and Signature wire layout",
  );
  assert.deepEqual(noritoDecodeInstruction(signedEncoded, 753), signedInstruction);
});

test("contract manifest codec roundtrips every V1 descriptor field", () => {
  const filterFixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "contract_manifest_v1.json"), "utf8"),
  ).manifest.entrypoints[0].triggers[0].filter;
  const leaf = (kind) => ({
    nodes: [{ kind: "Leaf", value: { kind, value: null } }],
  });
  const manifest = {
    permissions: [{ name: "TransferAsset", scope: { kind: "Instance", value: null } }], events: [], enum_types: [],
    seiyaku_name: "Ledger",
    code_hash: "hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB#3E38",
    abi_hash: "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
    compiler_fingerprint: "kotodama_lang",
    features_bitmap: 42,
    access_set_hints: {
      read_keys: ["state:Balances"],
      write_keys: ["state:Balances"],
      dynamic_reads: [
        {
          base_key: "state:Balances",
          key_type: "AccountId",
          bound_kind: "take",
          max_keys: 4,
        },
      ],
      dynamic_writes: [],
    },
    entrypoints: [
      {
        name: "transfer",
        kind: { kind: "Kotoage", value: null },
        params: [
          { name: "amount", type_name: "quantity" },
          { name: "tags", type_name: "List<Name, 64>" },
        ],
        argument_schema: {
          fields: [
            { name: "amount", ty: leaf("Quantity") },
            {
              name: "tags",
              ty: {
                nodes: [
                  { kind: "List", value: { capacity: 64 } },
                  { kind: "Leaf", value: { kind: "Name", value: null } },
                ],
              },
            },
          ],
        },
        return_type: "Result<bool, string>",
        return_schema: {
          nodes: [
            { kind: "Result", value: null },
            { kind: "Leaf", value: { kind: "Bool", value: null } },
            { kind: "Leaf", value: { kind: "String", value: null } },
          ],
        },
        authorization: { kind: "Permission", value: "TransferAsset" },
        read_keys: ["state:Balances"],
        write_keys: ["state:Balances"],
        access_hints_complete: true,
        access_hints_skipped: [],
        triggers: [
          {
            id: "settle",
            repeats: { Exactly: 3 },
            filter: filterFixture,
            authority: null,
            metadata: { priority: 7 },
            callback: { namespace: null, entrypoint: "transfer" },
          },
        ],
      },
    ],
    states: [{ name: "Balances", type_name: "StateMap<AccountId, quantity>" }],
    error_types: [{ identity: "LedgerError", variants: [{ name: "Denied", code: 7 }] }],
    error_messages: [
      { error_type: "LedgerError", code: 7, message: "送金が拒否されました" },
    ],
    kotoba: [
      {
        msg_id: "ledger.denied",
        translations: [
          { lang: "en", text: "" },
          { lang: "ja", text: "拒否" },
        ],
      },
    ],
    provenance: {
      signer: `ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
      signature: "22".repeat(64).toUpperCase(),
    },
  };
  const encoded = Buffer.from(
      boundNoritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest } }), 753),
    );
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest, {
    ...manifest,
    code_hash: "hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB#3E38",
    abi_hash: "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
  });
});

test("contract manifest codec rejects noncanonical and retired layouts", () => {
  const fixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "contract_manifest_v1.json"), "utf8"),
  );
  const encodeManifest = (manifest) =>
    boundNoritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest } }), 753);

  assert.throws(
    () => encodeManifest({ ...fixture.manifest, contract_name: "Legacy" }),
    /unknown field `contract_name`/u,
  );
  assert.throws(
    () =>
      encodeManifest({
        ...fixture.manifest,
        entrypoints: [
          { ...fixture.manifest.entrypoints[0], kind: { kind: "Public", value: null } },
        ],
      }),
    { message: "unknown JSON enum variant" },
  );
  assert.throws(
    () =>
      encodeManifest({
        ...fixture.manifest,
        entrypoints: [
          {
            ...fixture.manifest.entrypoints[0],
            argument_schema: {
              fields: [
                {
                  name: "bad",
                  ty: {
                    nodes: [
                      { kind: "Leaf", value: { kind: "Opaque", value: null } },
                    ],
                  },
                },
              ],
            },
          },
        ],
      }),
    { message: "unknown JSON enum variant" },
  );
  assert.throws(
    () =>
      encodeManifest({
        ...fixture.manifest,
        entrypoints: [
          {
            ...fixture.manifest.entrypoints[0],
            argument_schema: {
              fields: [
                {
                  name: "legacy_list",
                  ty: {
                    nodes: [
                      {
                        kind: "List",
                        value: {
                          element: {
                            nodes: [
                              {
                                kind: "Leaf",
                                value: { kind: "Name", value: null },
                              },
                            ],
                          },
                          capacity: 64,
                        },
                      },
                    ],
                  },
                },
              ],
            },
          },
        ],
      }),
    /unknown field `element`/u,
  );

  const badFilter = Buffer.from(
    fixture.event_filter_box.norito_frame_hex,
    "hex",
  );
  badFilter[6] ^= 0x01;
  assert.throws(
    () =>
      encodeManifest({
        ...fixture.manifest,
        entrypoints: [
          {
            ...fixture.manifest.entrypoints[0],
            triggers: [
              {
                ...fixture.manifest.entrypoints[0].triggers[0],
                filter: badFilter.toString("base64"),
              },
            ],
          },
        ],
      }),
    { message: "schema mismatch" },
  );
  assert.throws(
    () =>
      encodeManifest({
        ...fixture.manifest,
        provenance: {
          signer: `ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
          signature: "00".repeat(64),
        },
      }),
    /must not be all zero/u,
  );
});

test("contract manifest codec validates every flat query schema and ordinary structs", () => {
  const fixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "contract_manifest_v1.json"), "utf8"),
  );
  const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
  const layouts = [
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
  ];
  const instruction = (returnType, nodes) => (universalArtifactInstruction({
    RegisterSmartContractCode: {
      manifest: {
        ...fixture.manifest,
        entrypoints: [
          {
            ...fixture.manifest.entrypoints[0],
            name: "read",
            kind: { kind: "View", value: null },
            return_type: returnType,
            return_schema: { nodes },
            authorization: { kind: "Anyone", value: null },
            triggers: [],
          },
        ],
      },
    },
  }));
  const roundtrip = (returnType, nodes) => {
    const value = instruction(returnType, nodes);
    const encoded = boundNoritoEncodeInstruction(value, 753);
    assert.deepEqual(noritoDecodeInstruction(encoded, 753), value);
  };

  for (const [name, fields, children] of layouts) {
    const view = [{ kind: "Struct", value: { name: `kotodama::${name}`, fields } }, ...children];
    roundtrip(name, view);
    roundtrip(`Option<${name}>`, [{ kind: "Option", value: null }, ...view]);
    roundtrip(`QueryPage<${name}>`, [
      {
        kind: "Struct",
        value: { name: "kotodama::QueryPage", fields: ["items", "next_offset"] },
      },
      { kind: "List", value: { capacity: 64 } },
      ...view,
      { kind: "Option", value: null },
      leaf("Int"),
    ]);
  }
  roundtrip("struct Fixture::Pair", [
    { kind: "Struct", value: { name: "Fixture::Pair", fields: ["left", "right"] } },
    leaf("Int"),
    leaf("Bool"),
  ]);
});

test("contract manifest codec rejects malformed and forged flat schema tapes", () => {
  const fixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "contract_manifest_v1.json"), "utf8"),
  );
  const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
  const encodeNodes = (nodes, returnType = "schema-under-test") =>
    boundNoritoEncodeInstruction(universalArtifactInstruction({
        RegisterSmartContractCode: {
          manifest: {
            ...fixture.manifest,
            entrypoints: [
              {
                ...fixture.manifest.entrypoints[0],
                name: "read",
                kind: { kind: "View", value: null },
                return_type: returnType,
                return_schema: { nodes },
                authorization: { kind: "Anyone", value: null },
                triggers: [],
              },
            ],
          },
        },
      }), 753);

  for (const malformed of [
    [],
    [{ kind: "List", value: { capacity: 1 } }],
    [leaf("Int"), leaf("Bool")],
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
    assert.throws(() => encodeNodes(malformed), { message: "invalid V1 entrypoint value schema" });
  }

  assert.throws(
    () => encodeNodes([
      { kind: "List", value: { capacity: 1, element: { nodes: [leaf("Int")] } } },
      leaf("Int"),
    ]),
    { message: "JSON error: unknown field `element`" },
  );

  const reservedViews = [
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
  ];
  for (const [name, fields, children] of reservedViews) {
    const canonical = [
      { kind: "Struct", value: { name: `kotodama::${name}`, fields } },
      ...structuredClone(children),
    ];
    assert.doesNotThrow(() => encodeNodes(canonical, name));
    const forged = structuredClone(canonical);
    forged[1].value.kind = "Bool";
    assert.throws(() => encodeNodes(forged), { message: "invalid V1 entrypoint value schema" });

    const forgedPage = [
      {
        kind: "Struct",
        value: { name: "kotodama::QueryPage", fields: ["items", "next_offset"] },
      },
      { kind: "List", value: { capacity: 32 } },
      { kind: "Struct", value: { name: `kotodama::${name}`, fields } },
      ...children,
      { kind: "Option", value: null },
      leaf("Int"),
    ];
    assert.throws(() => encodeNodes(forgedPage), { message: "invalid V1 entrypoint value schema" });
  }

  const validCapacity = Buffer.from(
    encodeNodes([{ kind: "List", value: { capacity: 63 } }, leaf("Int")], "List<int, 63>"),
  );
  const comparisonCapacity = Buffer.from(
    encodeNodes([{ kind: "List", value: { capacity: 62 } }, leaf("Int")], "List<int, 62>"),
  );
  const capacityOffsets = Array.from(validCapacity.keys()).filter(
    (index) => validCapacity[index] === 63 && comparisonCapacity[index] === 62,
  );
  assert.equal(capacityOffsets.length, 1);
  for (const invalidCapacity of [0, 65]) {
    const forged = Buffer.from(validCapacity);
    forged[capacityOffsets[0]] = invalidCapacity;
    rewriteNestedInstructionFrameCrcs(forged);
    assert.throws(
      () => boundNoritoDecodeInstruction(forged, 753),
      { message: "invalid V1 entrypoint value schema" },
    );
  }

  const forgedViewWire = Buffer.from(
    encodeNodes([
      {
        kind: "Struct",
        value: { name: "FixtureX::AccountViex", fields: ["id", "metadata"] },
      },
      leaf("Bool"),
      leaf("Json"),
    ], "struct FixtureX::AccountViex"),
  );
  const originalName = Buffer.from("FixtureX::AccountViex", "utf8");
  const forgedName = Buffer.from("kotodama::AccountView", "utf8");
  assert.equal(originalName.length, forgedName.length);
  // Forge only the schema's identity into the reserved view; its Bool id is invalid.
  const nameOffset = forgedViewWire.lastIndexOf(originalName);
  assert.notEqual(nameOffset, -1);
  assert.notEqual(nameOffset, forgedViewWire.indexOf(originalName));
  forgedName.copy(forgedViewWire, nameOffset);
  rewriteNestedInstructionFrameCrcs(forgedViewWire);
  assert.throws(
    () => boundNoritoDecodeInstruction(forgedViewWire, 753),
    { message: "invalid V1 entrypoint value schema" },
  );
});

baseTest("native multisig proposal DTO embeds canonical instructions with compact inner frames", () => {
  const sourceAssetId = loadAssetIdFromFixture("mint_asset_quantity.json");
  const instruction = {
    Transfer: {
      Asset: {
        source: sourceAssetId,
        object: "7",
        destination: MULTISIG_SIGNER_ID,
      },
    },
  };
  const request = {
    multisig_account_alias: "cbdc@hbl.sbp",
    signer_account_id: MULTISIG_SIGNER_ID,
    fee_payment: authorityFeePayment(),
    validation_fee_assessment: JSON.parse(fs.readFileSync(
      new URL("./fixtures/retail_fee_codec_v1.json", import.meta.url), "utf8",
    )).assessment,
    instructions: [instruction],
  };
  const nativeBody = Buffer.from(noritoEncodeMultisigProposeRequest(request, 753));
  const body = Buffer.from(boundNoritoEncodeMultisigProposeRequest(request, 753));
  assert.deepEqual(body, nativeBody);

  const outer = noritoFramePayload(body, "MultisigProposeDtoV1");
  const outerUsesCompactLengths = (outer.flags & 0x02) !== 0;
  assert.equal(outerUsesCompactLengths, true);
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
  ]) {
    offset = readNoritoFieldPayload(
      outer.payload,
      offset,
      `MultisigProposeDtoV1.${fieldName}`,
      outerUsesCompactLengths,
    ).offset;
  }
  const assessment = readNoritoFieldPayload(
    outer.payload, offset, "MultisigProposeDtoV1.validation_fee_assessment",
    outerUsesCompactLengths,
  );
  assert.equal(assessment.payload[0], 1, "the typed assessment option is present");
  const assessmentValue = readNoritoFieldPayload(
    assessment.payload, 1, "MultisigProposeDtoV1.validation_fee_assessment.value",
    outerUsesCompactLengths,
  );
  const expectedAssessment = noritoFramePayload(
    encodeRetailFeeAssessmentV1(request.validation_fee_assessment), "RetailFeeAssessmentV1",
  );
  assert.deepEqual(assessmentValue.payload, expectedAssessment.payload,
    "the exact typed assessment archive is retained, without retired fee metadata");
  offset = assessment.offset;
  const instructions = readNoritoFieldPayload(
    outer.payload,
    offset,
    "MultisigProposeDtoV1.instructions",
    outerUsesCompactLengths,
  );
  const count = readU64Length(instructions.payload, 0, "MultisigProposeDtoV1.instructions.count");
  assert.equal(count.length, 1);
  const firstInstruction = readNoritoFieldPayload(
    instructions.payload,
    count.bytes,
    "MultisigProposeDtoV1.instructions[0]",
    outerUsesCompactLengths,
  );
  assert.deepEqual(
    firstInstruction.payload,
    Buffer.from(nativeBinding.noritoEncodeInstructionBoxArchive(JSON.stringify(instruction), 753)),
    "proposal embeds the canonical native instruction archive unchanged",
  );
  const wireId = readNoritoFieldPayload(
    firstInstruction.payload,
    0,
    "MultisigProposeDtoV1.instructions[0].wire_id",
    outerUsesCompactLengths,
  );
  const wireIdValue = readNoritoFieldPayload(
    wireId.payload,
    0,
    "MultisigProposeDtoV1.instructions[0].wire_id.value",
    outerUsesCompactLengths,
  );
  assert.equal(wireIdValue.payload.toString("utf8"), "iroha.transfer");
  const embeddedFrameField = readNoritoFieldPayload(
    firstInstruction.payload,
    wireId.offset,
    "MultisigProposeDtoV1.instructions[0].payload",
    outerUsesCompactLengths,
  );
  const embeddedFrame = readNoritoFieldPayload(
    embeddedFrameField.payload,
    0,
    "MultisigProposeDtoV1.instructions[0].payload.frame",
    false,
  );
  const inner = noritoFramePayload(
    embeddedFrame.payload,
    "MultisigProposeDtoV1.instructions[0].payload.frame",
  );
  assert.equal((inner.flags & 0x02) !== 0, true);
  assert.equal(instructions.offset, outer.payload.length, "V1 instructions are the final field");

  // An absent option is codec DATA and does not establish ledger fee admission.
  const absent = noritoFramePayload(Buffer.from(boundNoritoEncodeMultisigProposeRequest(
    { ...request, validation_fee_assessment: null }, 753)), "MultisigProposeDtoV1");
  let absentOffset = 0;
  for (const fieldName of ["multisig_account_id", "multisig_account_alias", "signer_account_id",
    "public_key_hex", "signature_b64", "creation_time_ms", "fee_payment", "memo"]) {
    absentOffset = readNoritoFieldPayload(absent.payload, absentOffset,
      `MultisigProposeDtoV1.${fieldName}`, outerUsesCompactLengths).offset;
  }
  const absentAssessment = readNoritoFieldPayload(absent.payload, absentOffset,
    "MultisigProposeDtoV1.validation_fee_assessment", outerUsesCompactLengths);
  assert.deepEqual(absentAssessment.payload, Buffer.of(0));
  const absentInstructions = readNoritoFieldPayload(absent.payload, absentAssessment.offset,
    "MultisigProposeDtoV1.instructions", outerUsesCompactLengths);
  assert.deepEqual(absentInstructions.payload, instructions.payload,
    "optional assessment shape does not change canonical embedded instructions");
  assert.equal(absentInstructions.offset, absent.payload.length);

});

test("native multisig DTO encoders reject inline private-key fields", () => {
  assert.throws(
    () =>
      noritoEncodeMultisigProposeRequest({
        instructions: [],
        private_key: "secret",
      }, 753),
    /does not accept private-key fields/,
  );
  assert.throws(
    () =>
      noritoEncodeMultisigContractCallProposeRequest({
        privateKeyHex: "11".repeat(32),
      }, 753),
    /does not accept private-key fields/,
  );
  assert.throws(
    () =>
      noritoEncodeMultisigContractCallApproveRequest({
        private_key_bytes: [1],
      }, 753),
    /does not accept private-key fields/,
  );
});

test("contract-call propose Norito encoder requires alias and object payload", () => {
  const request = {
    multisig_account_alias: "treasury@north.test",
    signer_account_id: MULTISIG_SIGNER_ID,
    contract_alias: "apps_review::universal",
    entrypoint: "execute",
    payload: { probe: true },
    fee_payment: authorityFeePayment(10_000),
  };
  assert.throws(
    () => noritoEncodeMultisigContractCallProposeRequest({
      ...request,
      contract_alias: null,
      contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    }, 753),
    /exact contract_alias/,
  );
  assert.throws(
    () => noritoEncodeMultisigContractCallProposeRequest({ ...request, payload: null }, 753),
    /exact object payload/,
  );
});

baseTest("contract-call approve Norito encoder requires the exact object payload", () => {
  const request = {
    multisig_account_alias: "treasury@north.test",
    signer_account_id: MULTISIG_SIGNER_ID,
    instructions_hash: "aa".repeat(32),
    contract_alias: "apps_review::universal",
    entrypoint: "execute",
    payload: { probe: true },
    fee_payment: authorityFeePayment(10_000),
  };
  assert.ok(noritoEncodeMultisigContractCallApproveRequest(request, 753).length > 0);
  for (const payload of [null, [], "{}", 7]) {
    assert.throws(
      () => noritoEncodeMultisigContractCallApproveRequest({ ...request, payload }, 753),
      /payload must be the exact contract object/,
    );
  }
});



test("native multisig proposal DTO preserves native instruction frames without JS schema entries", () => {
  const request = {
    multisig_account_alias: "cbdc@hbl.sbp",
    signer_account_id: MULTISIG_SIGNER_ID,
    fee_payment: authorityFeePayment(),
    instructions: [
      {
        Unregister: {
          Domain: "wonderland.sora",
        },
      },
    ],
  };

  const body = Buffer.from(noritoEncodeMultisigProposeRequest(request, 753));
  assert.ok(body.length > 32);
});

baseTest("native multisig DTO encoders reject noncanonical signature_b64 text", () => {
  const canonicalSignature = canonicalSignatureBase64Fixture();
  const invalidSignatures = [
    ` ${canonicalSignature} `,
    canonicalSignature.replace(/=+$/u, ""),
    noncanonicalStandardBase64PadBitAlias(canonicalSignature),
  ];
  for (const signature_b64 of invalidSignatures) {
    assert.throws(
      () =>
        noritoEncodeMultisigProposeRequest({
          multisig_account_alias: "cbdc@hbl.sbp",
          signer_account_id: MULTISIG_SIGNER_ID,
          signature_b64,
          fee_payment: authorityFeePayment(),
          instructions: [
            {
              Unregister: {
                Domain: "wonderland.sora",
              },
            },
          ],
        }, 753),
      /exact standard-base64/,
    );
    assert.throws(
      () =>
        noritoEncodeMultisigContractCallProposeRequest({
          multisig_account_alias: "cbdc@hbl.sbp",
          signer_account_id: MULTISIG_SIGNER_ID,
          signature_b64,
          contract_alias: "apps_review::universal",
          entrypoint: "execute",
          payload: { probe: true },
          fee_payment: authorityFeePayment(10_000),
        }, 753),
      /exact standard-base64/,
    );
    assert.throws(
      () =>
        noritoEncodeMultisigContractCallApproveRequest({
          multisig_account_alias: "cbdc@hbl.sbp",
          signer_account_id: MULTISIG_SIGNER_ID,
          signature_b64,
          instructions_hash: "aa".repeat(32),
          fee_payment: authorityFeePayment(),
        }, 753),
      /exact standard-base64/,
    );
  }
});

baseTest("canonical instruction decoding requires the native binding", () => {
  const bytes = loadInstructionBytes("mint_asset_quantity.json");
  assert.throws(() => UNAVAILABLE_NORITO_API.noritoDecodeInstruction(bytes, 753), /Native binding required/u);
  assert.ok(boundNoritoDecodeInstruction(bytes, 753)?.Mint?.Asset);
});

baseTest("pre-encoded instructions require native canonical validation", () => {
  const payload = loadInstructionBytes("mint_asset_quantity.json");
  for (const input of [payload, payload.toString("base64"), `0x${payload.toString("hex")}`]) {
    assert.throws(() => UNAVAILABLE_NORITO_API.noritoEncodeInstruction(input, 753), /Native binding required/u);
    assert.deepEqual(boundNoritoEncodeInstruction(input, 753), payload);
  }
  for (const input of [Buffer.from([1, 2, 3, 4]), "AQIDBA==", "0x01020304"]) {
    assert.throws(() => boundNoritoEncodeInstruction(input, 753));
  }
});

baseTest("pre-encoded instruction representations are exact and unambiguous", () => {
  const payload = loadInstructionBytes("mint_asset_quantity.json");
  const hex = `0x${payload.toString("hex")}`;
  const base64 = payload.toString("base64");
  // The old base64-first dispatch accepted this hex text as base64 and then
  // rejected its bytes even though it carries a valid native instruction frame.
  assert.equal(Buffer.from(hex, "base64").toString("base64"), hex);
  assert.deepEqual(boundNoritoEncodeInstruction(hex, 753), payload);
  assert.deepEqual(boundNoritoEncodeInstruction(base64, 753), payload);
  assert.match(base64, /=+$/u);
  for (const input of [
    ` ${hex}`, `${hex} `, `${hex}\n`,
    `0x${payload.toString("hex").toUpperCase()}`,
    `0X${payload.toString("hex")}`, hex.slice(0, -1), "0x",
    payload.toString("hex"),
    ` ${base64}`, `${base64} `, `${base64}\n`,
    `${base64.slice(0, 4)}\n${base64.slice(4)}`,
    base64.replace(/=+$/u, ""), `${base64}=`,
  ]) {
    assert.throws(() => boundNoritoEncodeInstruction(input, 753), undefined, input);
  }
  for (const frame of [payload.subarray(0, -1), Buffer.concat([payload, Buffer.from([0])])]) {
    for (const input of [frame.toString("base64"), `0x${frame.toString("hex")}`]) {
      assert.throws(() => boundNoritoEncodeInstruction(input, 753));
    }
  }
});

test("norito encode/decode supports ExecuteTrigger instructions", () => {
  const instruction = {
    ExecuteTrigger: {
      trigger: "mint_request_hbl",
      args: {
        action: "create",
        request_id: "mr1",
      },
    },
  };
  const encoded = noritoEncodeInstruction(instruction, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, instruction);
});

test("noritoDecodeInstruction keeps canonical asset-holding ids without @domain rewrites", () => {
  const bytes = loadInstructionBytes("mint_asset_quantity.json");
  const decoded = noritoDecodeInstruction(bytes, 753);
  const assetId = decoded?.Mint?.Asset?.destination;
  assert.equal(typeof assetId, "string");
  assert.equal(assetId.includes("#"), true);
  assert.equal(assetId.includes("@"), false);
});

test("noritoDecodeInstruction preserves nested asset-holding identifiers", () => {
  const bytes = loadInstructionBytes("burn_asset_quantity.json");
  const decoded = noritoDecodeInstruction(bytes, 753);
  const assetId = decoded?.Burn?.Asset?.destination;
  assert.equal(typeof assetId, "string");
  assert.equal(assetId.includes("#"), true);
  assert.equal(assetId.includes("@"), false);
});

test("noritoDecodeInstruction can return raw JSON string", () => {
  const encoded = noritoEncodeInstruction(REGISTER_DOMAIN, 753);
  const json = noritoDecodeInstruction(encoded, 753, { parseJson: false });
  assert.equal(typeof json, "string");
  const parsed = JSON.parse(json);
  assert.deepEqual(parsed, REGISTER_DOMAIN);
});

test("burn asset fixture matches canonical Norito bytes", () => {
  const bytes = loadInstructionBytes("burn_asset_quantity.json");
  const instruction = noritoDecodeInstruction(bytes, 753);
  const expectedHex = bytes.toString("hex");
  assert.equal(typeof expectedHex, "string");
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.ok(Buffer.isBuffer(encoded));
  const encodedHex = encoded.toString("hex");
  assert.equal(encodedHex, expectedHex);
});

test("burn asset fractional fixture matches canonical Norito bytes", () => {
  const bytes = loadInstructionBytes("burn_asset_fractional.json");
  const instruction = noritoDecodeInstruction(bytes, 753);
  const expectedHex = bytes.toString("hex");
  assert.equal(typeof expectedHex, "string");
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.ok(Buffer.isBuffer(encoded));
  const encodedHex = encoded.toString("hex");
  assert.equal(encodedHex, expectedHex);
});

test("mint asset fixture matches canonical Norito bytes", () => {
  const bytes = loadInstructionBytes("mint_asset_quantity.json");
  const instruction = noritoDecodeInstruction(bytes, 753);
  const expectedHex = bytes.toString("hex");
  assert.equal(typeof expectedHex, "string");
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.ok(Buffer.isBuffer(encoded));
  const encodedHex = encoded.toString("hex");
  assert.equal(encodedHex, expectedHex);
});

test("burn trigger fixture matches canonical Norito bytes", () => {
  const bytes = loadInstructionBytes("burn_trigger_repetitions.json");
  const instruction = noritoDecodeInstruction(bytes, 753);
  const expectedHex = bytes.toString("hex");
  assert.equal(typeof expectedHex, "string");
  const encoded = noritoEncodeInstruction(instruction, 753);
  assert.ok(Buffer.isBuffer(encoded));
  const encodedHex = encoded.toString("hex");
  assert.equal(encodedHex, expectedHex);
});

baseTest("instruction encoding never substitutes a codec when native execution is unavailable", () => {
  for (const instruction of [REGISTER_DOMAIN, { Log: { level: "INFO", message: "native codec required" } }]) {
    assert.throws(() => UNAVAILABLE_NORITO_API.noritoEncodeInstruction(instruction, 753), /Native binding required/u);
    assert.throws(() => UNAVAILABLE_NORITO_API.noritoEncodeInstructionBoxArchive(instruction, 753), /Native binding required/u);
  }
});

baseTest("noritoEncodeInstruction propagates native schema rejection exactly", () => {
  const nativeError = new SyntaxError("unknown instruction schema: Log is disabled");
  let calls = 0;
  const api = _createNoritoInstructionApi(
    createNativeRuntime({
      noritoEncodeInstruction() {
        calls += 1;
        throw nativeError;
      },
    }),
  );
  assert.throws(
    () =>
      api.noritoEncodeInstruction({
        Log: { level: "INFO", message: "must not be re-encoded" },
      }, 753),
    (error) => error === nativeError,
  );
  assert.equal(calls, 1);
});

baseTest("native multisig proposal V1 DTO rejects retired fee fields and assessment aliases", () => {
  const request = { instructions: [] };
  for (const fieldName of [
    "validationFeeAssessment",
    "validationFeePolicyVersion", "validationFeePolicyHash", "validationFeeHijiriFeeQuoteHash",
    "validationFeeInstructionIndex", "validationFeeTransferEntryIndex",
    "validation_fee_policy_version", "validation_fee_policy_hash", "validation_fee_hijiri_fee_quote_hash",
    "validation_fee_instruction_index", "validation_fee_transfer_entry_index",
  ]) {
    assert.throws(() => noritoEncodeMultisigProposeRequest({ ...request, [fieldName]: "1" }, 753),
      /unsupported fee field/);
  }
  assert.throws(() => noritoEncodeMultisigProposeRequest({
    ...request, validation_fee_assessment: null, validationFeeAssessment: null,
  }, 753), /unsupported fee field/);
  assert.throws(() => noritoEncodeMultisigProposeRequest({
    ...request, validation_fee_assessment: undefined,
  }, 753), /typed assessment or null/);
});
