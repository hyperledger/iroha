"use strict";

// Independent JavaScript model of the SCCP v1 contract-visible encodings of
// revision 5 (`specs/sccp.md` §2, §3, §5.1.5, §5.2.1, §5.2.2): payloads,
// message ids, transfer and 199-byte control leaves, promote-odd Merkle trees,
// the history accumulator, the 221-byte finality header `X` with X1–X7, `R`,
// the 116-byte `QC_FIXED`, the Commit preimage and its message, committee
// roots, block references, the destination ABI and the CREATE2 address. BLS
// uses `@noble/curves`: the §11.3 test keys, signatures under `DST_SIG`,
// aggregation and the EVM wire forms. A small Taira simulator (`TairaModel`)
// builds blocks, certificates and proofs from these parts. Nothing here reads
// the contract, so the EDR suites check `SccpTairaXor.sol` against a second
// implementation, never against itself.
//
// Before the model signs anything for a test, it reproduces every positive
// certificate of `fixtures/sccp/finality_v1.json` byte for byte
// (`reproduceFinalityFixture`), which the Python and the Rust reference wrote.
//
// Requires the locked EVM runtime dependencies installed under
// `scripts/contract_tooling/evm-runtime` (`npm ci --ignore-scripts`). The smoke
// script points `SCCP_EVM_RUNTIME_DIR` at a private, freshly audited copy of
// that directory instead (test-only convenience).

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const REPO = path.resolve(__dirname, "..", "..", "..", "..");
const RUNTIME_DIR = process.env.SCCP_EVM_RUNTIME_DIR
  ? path.resolve(process.env.SCCP_EVM_RUNTIME_DIR)
  : path.join(REPO, "scripts", "contract_tooling", "evm-runtime");
const runtimeRequire = createRequire(path.join(RUNTIME_DIR, "package.json"));
let ethers;
let bls;
try {
  ethers = runtimeRequire("ethers");
  ({ bls12_381: bls } = runtimeRequire("@noble/curves/bls12-381"));
} catch (error) {
  throw new Error(
    `the locked EVM runtime is not installed; run \`npm ci --ignore-scripts\` in ${RUNTIME_DIR}`,
    { cause: error },
  );
}

const { AbiCoder, concat, dataSlice, getAddress, getBytes, hexlify, keccak256, toBeHex, toUtf8Bytes, zeroPadValue } =
  ethers;
const abi = AbiCoder.defaultAbiCoder();

const ZERO32 = `0x${"00".repeat(32)}`;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const U64_MAX = (1n << 64n) - 1n;

/** §3.9 constants. */
const MAX_VALIDITY_MS = 2_592_000_000n;
const MAX_FAST_PAUSE_MS = 2_592_000_000n;
const MAX_INIT_SLACK_MS = 3_600_000n;
const MAX_CERTIFICATES_PER_CALL = 16;
const MAX_VOID_FROZEN_RANGE = 256;
const MAX_BLOCK_LEAVES = 512n;
const MAX_BLOCK_PATH = 9;
const MAX_HISTORY_PATH = 32;
const MAX_HISTORY_SIZE = 1n << 32n;
const X_LEN = 221;
const QC_FIXED_LEN = 116;
const COMMIT_PREIMAGE_LEN = 165;
const CONTROL_PREIMAGE_LEN = 199;
const FLAG_ACTIVE = 0x01;
const FLAG_ROTATION = 0x02;
const COMMIT_KIND = 0x03;
const TRACK_PARLIAMENT = 1;
const TRACK_FAST_PAUSE = 2;
const DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const TEST_IKM_TAG = "sccp-finality-test-ikm";

/**
 * §3.9, §5.2.1: the keyless deterministic-deployment proxy and its runtime
 * code. Its calldata is `salt ‖ init code`; it runs `CREATE2`, returns the
 * 20-byte address and reverts with empty data when the creation fails.
 */
const SCCP_EVM_DEPLOYER = getAddress("0x4e59b44847b379578588920ca78fbf26c0b4956c");
const SCCP_EVM_DEPLOYER_RUNTIME =
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0" +
  "3601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
const SCCP_EVM_SALT = ZERO32;

const TAIRA_TAG = 0x40;
const CODEC_EVM_ADDRESS20 = 2;
const CODEC_TAIRA_ACCOUNT = 3;

/** §2 destination profiles served by `SccpTairaXor.sol`. */
const PROFILES = Object.freeze({
  ethereum: Object.freeze({
    name: "ethereum",
    network: "ethereum-mainnet",
    tag: 0x41,
    chainId: 1n,
    domain: 1,
    routeId: "taira_eth_xor",
    accountCodec: CODEC_EVM_ADDRESS20,
  }),
  bsc: Object.freeze({
    name: "bsc",
    network: "bsc-mainnet",
    tag: 0x42,
    chainId: 56n,
    domain: 2,
    routeId: "taira_bsc_xor",
    accountCodec: CODEC_EVM_ADDRESS20,
  }),
});

/** The profile of a fixture network name. */
function profileOf(network) {
  const found = Object.values(PROFILES).filter((profile) => profile.network === network);
  assert.equal(found.length, 1, `no EVM profile for network ${network}`);
  return found[0];
}

/** A failed model check; `check` names the violated rule (`Length`, `X1`…`X7`, `BadProof`). */
class ModelError extends Error {
  constructor(check, detail) {
    super(detail ? `${check}: ${detail}` : check);
    this.check = check;
  }
}

// ---------------------------------------------------------------------------
// Bytes and digests
// ---------------------------------------------------------------------------

/** Big-endian unsigned integer of exactly `width` bytes. */
function be(value, width) {
  const number = BigInt(value);
  assert(number >= 0n && number < 1n << BigInt(8 * width), `value does not fit in ${width} bytes`);
  return width === 0 ? "0x" : toBeHex(number, width);
}

/** ASCII bytes of a literal tag. */
function ascii(text) {
  return hexlify(toUtf8Bytes(text));
}

/** 32-byte word of an unsigned integer. */
function word(value) {
  return be(value, 32);
}

/** Left-zero-padded 32-byte word of a 20-byte address. */
function addressWord(address) {
  return zeroPadValue(address, 32);
}

function byteLength(hex) {
  return getBytes(hex).length;
}

/** SHA-256 of the concatenation of `parts`. */
function sha256(...parts) {
  return ethers.sha256(concat(parts));
}

/** Unsigned big-endian integer of `width` bytes at `offset` of `bytes`. */
function readUint(bytes, offset, width) {
  return BigInt(hexlify(bytes.slice(offset, offset + width)));
}

// ---------------------------------------------------------------------------
// Networks, payloads and message ids (§2, §3.1 - §3.3)
// ---------------------------------------------------------------------------

/** §2.1 identity word of a destination profile. */
function identityWord(profile) {
  return word(profile.chainId);
}

/** §2.1 `network_bytes` of Taira and of a destination profile. */
function tairaNetworkBytes(networkId) {
  return concat([be(TAIRA_TAG, 1), networkId]);
}

function profileNetworkBytes(profile) {
  return concat([be(profile.tag, 1), identityWord(profile)]);
}

/** §2.2 `lane_bytes(sora-taira, profile)` and its reverse, 66 bytes each. */
function outboundLaneBytes(networkId, profile) {
  return concat([tairaNetworkBytes(networkId), profileNetworkBytes(profile)]);
}

function inboundLaneBytes(networkId, profile) {
  return concat([profileNetworkBytes(profile), tairaNetworkBytes(networkId)]);
}

/** §3.1 own-account encoding of a 20-byte address (`evm_address20`). */
function accountBytes(profile, address) {
  assert.equal(profile.accountCodec, CODEC_EVM_ADDRESS20, "EVM profiles use evm_address20");
  return hexlify(getBytes(address));
}

/**
 * §3.2 payload encoder. Every field may be overridden (including explicit
 * length prefixes) so that negative tests can build noncanonical payloads.
 */
function encodePayload(fields) {
  const f = {
    kind: 2,
    version: 1,
    assetHomeDomain: 0,
    assetIdCodec: 1,
    assetId: ascii("xor"),
    routeIdCodec: 1,
    trailing: "0x",
    ...fields,
  };
  const parts = [
    be(f.kind, 1),
    be(f.version, 1),
    be(f.sourceDomain, 4),
    be(f.destDomain, 4),
    be(f.nonce, 8),
    be(f.routeRevision, 4),
    be(f.deadlineMs, 8),
    be(f.assetHomeDomain, 4),
    be(f.assetIdCodec, 1),
    be(f.assetIdLen ?? byteLength(f.assetId), 2),
    f.assetId,
    be(f.amount, 16),
    be(f.senderCodec, 1),
    be(f.senderLen ?? byteLength(f.sender), 2),
    f.sender,
    be(f.recipientCodec, 1),
    be(f.recipientLen ?? byteLength(f.recipient), 2),
    f.recipient,
    be(f.routeIdCodec, 1),
    be(f.routeIdLen ?? byteLength(f.routeId), 2),
    f.routeId,
    f.trailing,
  ];
  return concat(parts);
}

/** Canonical Taira -> destination payload fields (codec 3 sender, own-codec recipient). */
function outboundFields(profile, { nonce, revision, deadlineMs, amount, sender, recipient }) {
  return {
    sourceDomain: 0,
    destDomain: profile.domain,
    nonce,
    routeRevision: revision,
    deadlineMs,
    amount,
    senderCodec: CODEC_TAIRA_ACCOUNT,
    sender,
    recipientCodec: profile.accountCodec,
    recipient: accountBytes(profile, recipient),
    routeId: ascii(profile.routeId),
  };
}

/** Canonical destination -> Taira payload built by `transferToTaira` (§5.1.7). */
function inboundPayload(profile, { nonce, revision, amount, sender, tairaRecipient }) {
  return encodePayload({
    sourceDomain: profile.domain,
    destDomain: 0,
    nonce,
    routeRevision: revision,
    deadlineMs: 0,
    amount,
    senderCodec: profile.accountCodec,
    sender: accountBytes(profile, sender),
    recipientCodec: CODEC_TAIRA_ACCOUNT,
    recipient: tairaRecipient,
    routeId: ascii(profile.routeId),
  });
}

/** §3.3 payload hash and message id. */
function payloadHash(payload) {
  return keccak256(concat([ascii("SCCP/PAYLOAD/V1"), payload]));
}

function messageId(laneBytes, payload) {
  assert.equal(byteLength(laneBytes), 66, "lane bytes are 66 bytes");
  return keccak256(concat([ascii("SCCP/MESSAGE/V1"), laneBytes, payloadHash(payload)]));
}

function outboundMessageId(networkId, profile, payload) {
  return messageId(outboundLaneBytes(networkId, profile), payload);
}

function inboundMessageId(networkId, profile, payload) {
  return messageId(inboundLaneBytes(networkId, profile), payload);
}

// ---------------------------------------------------------------------------
// Leaves, trees and the history accumulator (§3.4, §3.5)
// ---------------------------------------------------------------------------

function transferLeaf(id, destinationWord) {
  return keccak256(concat([ascii("SCCP/LEAF/V1"), id, destinationWord]));
}

/**
 * The 199-byte control-leaf preimage (§3.4), laid out field by field without
 * any validity check. The lane is `lane_bytes(sora-taira, profile)` unless
 * `laneBytes` gives it; `parliamentPaused` is the raw byte (a boolean counts as
 * 0 or 1), so that leaves which violate a constraint can be built.
 */
function controlLeafPreimage({
  networkId,
  profile,
  laneBytes,
  destinationWord,
  revision,
  nonce,
  track,
  parliamentPaused,
  fastPauseUntilMs,
  certificateId,
  effectHash,
}) {
  const preimage = concat([
    ascii("SCCP/CONTROL/V1"),
    laneBytes ?? outboundLaneBytes(networkId, profile),
    destinationWord,
    be(revision, 4),
    be(nonce, 8),
    be(track, 1),
    be(Number(parliamentPaused), 1),
    be(fastPauseUntilMs, 8),
    certificateId,
    effectHash,
  ]);
  assert.equal(byteLength(preimage), CONTROL_PREIMAGE_LEN, "control leaf preimage is 199 bytes");
  return preimage;
}

function controlLeaf(fields) {
  return keccak256(controlLeafPreimage(fields));
}

/** Whether control fields satisfy the §3.4 constraints that `BadControl` reports. */
function controlConstraintsHold({ track, parliamentPaused, fastPauseUntilMs, certificateId, effectHash }) {
  const paused = Number(parliamentPaused);
  return (
    (Number(track) === TRACK_PARLIAMENT || Number(track) === TRACK_FAST_PAUSE) &&
    (paused === 0 || paused === 1) &&
    !(Number(track) === TRACK_FAST_PAUSE && BigInt(fastPauseUntilMs) === 0n) &&
    hexlify(certificateId) !== ZERO32 &&
    hexlify(effectHash) !== ZERO32
  );
}

function node(left, right) {
  return keccak256(concat([ascii("SCCP/NODE/V1"), left, right]));
}

/** Promote-odd levels of a leaf list (§3.4); `levels[0]` is the leaf list. */
function merkleLevels(leaves) {
  assert(leaves.length >= 1, "a tree has at least one leaf");
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(i + 1 < current.length ? node(current[i], current[i + 1]) : current[i]);
    }
    levels.push(next);
  }
  return levels;
}

function merkleRoot(leaves) {
  const levels = merkleLevels(leaves);
  return levels[levels.length - 1][0];
}

/** Sibling path of leaf `index`; promoted levels contribute no sibling. */
function merklePath(leaves, index) {
  const levels = merkleLevels(leaves);
  const siblings = [];
  let position = index;
  for (let level = 0; level < levels.length - 1; level += 1) {
    const current = levels[level];
    if (position % 2 === 1) siblings.push(current[position - 1]);
    else if (position + 1 < current.length) siblings.push(current[position + 1]);
    position >>= 1;
  }
  return siblings;
}

/**
 * The spec's positional `merkle_root(leaf, index, count, siblings)` (§3.4).
 * Throws `ModelError("BadProof")` where the spec's `require` fails.
 */
function merkleRootFromPath(leaf, index, count, siblings) {
  let h = leaf;
  let k = 0;
  let i = BigInt(index);
  let c = BigInt(count);
  if (c < 1n || i >= c) throw new ModelError("BadProof", "index out of range");
  while (c > 1n) {
    if (i % 2n === 1n || i + 1n < c) {
      if (k >= siblings.length) throw new ModelError("BadProof", "path too short");
      h = i % 2n === 1n ? node(siblings[k], h) : node(h, siblings[k]);
      k += 1;
    }
    i >>= 1n;
    c = (c + 1n) >> 1n;
  }
  if (k !== siblings.length) throw new ModelError("BadProof", "path too long");
  return h;
}

/** §3.5 history leaf and root (`0x00…00` for an empty history). */
function historyLeaf(height, sccpRoot, messageCount) {
  return keccak256(concat([ascii("SCCP/HISTORY/V1"), be(height, 8), sccpRoot, be(messageCount, 4)]));
}

function historyRoot(leaves) {
  return leaves.length === 0 ? ZERO32 : merkleRoot(leaves);
}

// ---------------------------------------------------------------------------
// Finality header `X`, `R`, `QC_FIXED` and the Commit message (§3.6, §3.7)
// ---------------------------------------------------------------------------

const X_MAGIC = ascii("SCCP/FINALITY/V1");
const RESULT_TAG = ascii("iroha/sumeragi/result/v1");
const SIGNATURE_TAG = ascii("sumeragi/sig");
const COMMITTEE_TAG = ascii("SCCP/COMMITTEE/V1");

/** Header fields of the model from the snake-case `header_fields` of a fixture row. */
function headerFromFixture(fields) {
  return {
    networkId: fields.network_id,
    height: BigInt(fields.height),
    timestampMs: BigInt(fields.timestamp_ms),
    flags: Number(fields.flags),
    messageCount: BigInt(fields.message_count),
    sccpRoot: fields.sccp_root,
    historySize: BigInt(fields.history_size),
    historyRoot: fields.history_root,
    generation: BigInt(fields.generation),
    committeeRoot: fields.committee_root,
    validityMs: BigInt(fields.validity_ms),
    nextCommitteeRoot: fields.next_committee_root,
  };
}

/** The 221 bytes of `X` (§3.6), without checking the invariants. */
function encodeHeader(fields) {
  const f = {
    flags: FLAG_ACTIVE,
    messageCount: 0n,
    sccpRoot: ZERO32,
    historySize: 0n,
    historyRoot: ZERO32,
    generation: 0n,
    committeeRoot: ZERO32,
    validityMs: 0n,
    nextCommitteeRoot: ZERO32,
    ...fields,
  };
  const x = concat([
    X_MAGIC,
    f.networkId,
    be(f.height, 8),
    be(f.timestampMs, 8),
    be(f.flags, 1),
    be(f.messageCount, 4),
    f.sccpRoot,
    be(f.historySize, 8),
    f.historyRoot,
    be(f.generation, 8),
    f.committeeRoot,
    be(f.validityMs, 8),
    f.nextCommitteeRoot,
  ]);
  assert.equal(byteLength(x), X_LEN, "X is 221 bytes");
  return x;
}

/**
 * `SccpFinalityHeaderV1::parse` (§3.6): the exact length, then X1, X2 (inactive)
 * or X3 (active), X4, X5, X6 and X7. Throws `ModelError` naming the first
 * violated check; returns the fields with `active` and `rotation`.
 */
function parseHeader(x) {
  const bytes = getBytes(x);
  if (bytes.length !== X_LEN) throw new ModelError("Length");
  const bytes32 = (offset) => hexlify(bytes.slice(offset, offset + 32));
  const flags = bytes[64];
  const header = {
    networkId: bytes32(16),
    height: readUint(bytes, 48, 8),
    timestampMs: readUint(bytes, 56, 8),
    flags,
    messageCount: readUint(bytes, 65, 4),
    sccpRoot: bytes32(69),
    historySize: readUint(bytes, 101, 8),
    historyRoot: bytes32(109),
    generation: readUint(bytes, 141, 8),
    committeeRoot: bytes32(149),
    validityMs: readUint(bytes, 181, 8),
    nextCommitteeRoot: bytes32(189),
    active: (flags & FLAG_ACTIVE) !== 0,
    rotation: (flags & FLAG_ROTATION) !== 0,
  };
  if (hexlify(bytes.slice(0, 16)) !== X_MAGIC || (flags & 0xfc) !== 0) throw new ModelError("X1");
  if (!header.active) {
    if (header.rotation || bytes.slice(65).some((byte) => byte !== 0)) throw new ModelError("X2");
  } else if (header.generation === 0n || header.committeeRoot === ZERO32) {
    throw new ModelError("X3");
  }
  if ((header.messageCount === 0n) !== (header.sccpRoot === ZERO32) || header.messageCount > MAX_BLOCK_LEAVES) {
    throw new ModelError("X4");
  }
  if ((header.historySize === 0n) !== (header.historyRoot === ZERO32) || header.historySize > MAX_HISTORY_SIZE) {
    throw new ModelError("X5");
  }
  if (header.rotation) {
    if (
      header.nextCommitteeRoot === ZERO32 ||
      header.validityMs === 0n ||
      header.validityMs > MAX_VALIDITY_MS ||
      header.height > U64_MAX - 1n ||
      header.generation > U64_MAX - 1n
    ) {
      throw new ModelError("X6");
    }
  } else if (header.nextCommitteeRoot !== ZERO32 || header.validityMs !== 0n) {
    throw new ModelError("X6");
  }
  if (header.height === 0n) throw new ModelError("X7");
  return header;
}

/** `checkpoint_id(X) = keccak256(X)`. */
function checkpointId(x) {
  return keccak256(x);
}

/** `R = SHA-256(RESULT_TAG ‖ X ‖ D_body)`, a 277-byte input. */
function resultR(x, resultBody) {
  assert.equal(byteLength(x), X_LEN, "R is defined over a 221-byte X");
  return sha256(RESULT_TAG, x, resultBody);
}

/** `signers = Σ 1 << i` over the canonical signer indices (§3.7). */
function signersWord(indices) {
  let signers = 0n;
  for (const index of indices) {
    assert(Number.isInteger(index) && index >= 0 && index < 32, "signer indices are 0..31");
    signers |= 1n << BigInt(index);
  }
  return signers;
}

/** The ascending indices of the set bits of a `signers` word. */
function signerIndices(signers) {
  const indices = [];
  for (let index = 0; index < 32; index += 1) {
    if ((BigInt(signers) >> BigInt(index)) & 1n) indices.push(index);
  }
  return indices;
}

/** The Sumeragi bitmap of §3.7: `ceil(n / 8)` bytes, bit `i` LSB-first in each byte. */
function signerBitmap(indices, n) {
  const bytes = new Uint8Array(Math.ceil(n / 8));
  for (const index of indices) bytes[index >> 3] |= 1 << (index & 7);
  return hexlify(bytes);
}

/** The 116 bytes of `QC_FIXED` (§3.7). */
function encodeQcFixed({ epoch, epochContext, view, blockHash, resultBody, signers }) {
  const qc = concat([be(epoch, 8), epochContext, be(view, 8), blockHash, resultBody, be(signers, 4)]);
  assert.equal(byteLength(qc), QC_FIXED_LEN, "QC_FIXED is 116 bytes");
  return qc;
}

function parseQcFixed(qc) {
  const bytes = getBytes(qc);
  assert.equal(bytes.length, QC_FIXED_LEN, "QC_FIXED is 116 bytes");
  return {
    epoch: readUint(bytes, 0, 8),
    epochContext: hexlify(bytes.slice(8, 40)),
    view: readUint(bytes, 40, 8),
    blockHash: hexlify(bytes.slice(48, 80)),
    resultBody: hexlify(bytes.slice(80, 112)),
    signers: readUint(bytes, 112, 4),
  };
}

/** The 165-byte Commit preimage `P` (§3.7); `kind` is `0x03` for a CommitQC. */
function commitPreimage({ instance, epoch, epochContext, height, view, blockHash, r, kind = COMMIT_KIND }) {
  const preimage = concat([
    SIGNATURE_TAG,
    be(kind, 1),
    instance,
    be(epoch, 8),
    epochContext,
    be(height, 8),
    be(view, 8),
    blockHash,
    r,
  ]);
  assert.equal(byteLength(preimage), COMMIT_PREIMAGE_LEN, "the Commit preimage is 165 bytes");
  return preimage;
}

/** `m = SHA-256(P)`. */
function commitMessage(preimage) {
  return sha256(preimage);
}

/** `R`, `P` and `m` as a verifier derives them from the wire fields of a certificate. */
function wireDigests(instance, qc, x) {
  const fields = parseQcFixed(qc);
  const r = resultR(x, fields.resultBody);
  const preimage = commitPreimage({ ...fields, instance, height: readUint(getBytes(x), 48, 8), r });
  return { r, preimage, m: commitMessage(preimage) };
}

/** `q = n − f` with `f = (n − 1) / 3`, for a committee size `n ∈ {4, 7, …, 31}`. */
function quorum(n) {
  assert(Number.isInteger(n) && n >= 4 && n <= 31 && (n - 1) % 3 === 0, `invalid committee size ${n}`);
  return n - (n - 1) / 3;
}

/** `committee_root = keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ keys)` for 1..=255 keys (§3.7). */
function committeeRoot(keys) {
  assert(keys.length >= 1 && keys.length <= 255, "a committee root is defined for 1..=255 keys");
  for (const key of keys) assert.equal(byteLength(key), 48, "committee keys are 48 bytes");
  return keccak256(concat([COMMITTEE_TAG, be(keys.length, 1), ...keys]));
}

// ---------------------------------------------------------------------------
// Block references (§5.1.5)
// ---------------------------------------------------------------------------

/**
 * `BlockRefV1` against a verified header. Returns the block's root and leaf
 * count, or throws `ModelError("BadProof")`.
 */
function checkBlockRef(header, ref) {
  const height = BigInt(ref.height);
  const messageCount = BigInt(ref.messageCount);
  const sccpRoot = hexlify(ref.sccpRoot);
  const fail = (detail) => {
    throw new ModelError("BadProof", detail);
  };
  if (height === header.height) {
    if (sccpRoot === ZERO32 || sccpRoot !== header.sccpRoot) fail("block root differs from X");
    if (messageCount !== header.messageCount) fail("message count differs from X");
    if (BigInt(ref.historyIndex) !== 0n || ref.historyPath.length !== 0) {
      fail("same-height reference with a history proof");
    }
    return { sccpRoot, messageCount };
  }
  if (height > header.height) fail("reference above the certified height");
  if (messageCount < 1n || messageCount > MAX_BLOCK_LEAVES || sccpRoot === ZERO32) fail("invalid historical block");
  if (ref.historyPath.length > MAX_HISTORY_PATH) fail("history path too long");
  const leaf = historyLeaf(height, sccpRoot, messageCount);
  if (merkleRootFromPath(leaf, ref.historyIndex, header.historySize, ref.historyPath) !== header.historyRoot) {
    fail("history root mismatch");
  }
  return { sccpRoot, messageCount };
}

/** Leaf inclusion in a block of `messageCount` leaves (at most 9 siblings), or `ModelError("BadProof")`. */
function checkLeaf(leaf, leafIndex, messageCount, siblings, sccpRoot) {
  if (siblings.length > MAX_BLOCK_PATH) throw new ModelError("BadProof", "block path too long");
  if (merkleRootFromPath(leaf, leafIndex, messageCount, siblings) !== sccpRoot) {
    throw new ModelError("BadProof", "leaf root mismatch");
  }
}

// ---------------------------------------------------------------------------
// BLS12-381 (§3.7, §3.8, §11.3)
// ---------------------------------------------------------------------------

const FIELD_P = bls.fields.Fp.ORDER;
const HALF_P = (FIELD_P - 1n) / 2n;
const GROUP_ORDER = bls.fields.Fr.ORDER;
const G1 = bls.G1.ProjectivePoint;
const G2 = bls.G2.ProjectivePoint;

function hmacSha256(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

/** draft-irtf-cfrg-bls-signature-05 §2.3 `KeyGen` (HKDF-SHA-256, `L = 48`, empty `key_info`). */
function keyGen(ikm) {
  const material = Buffer.from(getBytes(ikm));
  assert(material.length >= 32, "IKM must be at least 32 bytes");
  let salt = Buffer.from("BLS-SIG-KEYGEN-SALT-", "ascii");
  let secret = 0n;
  while (secret === 0n) {
    salt = crypto.createHash("sha256").update(salt).digest();
    const prk = hmacSha256(salt, Buffer.concat([material, Buffer.from([0])]));
    // HKDF-Expand with info = I2OSP(48, 2) for 48 bytes: two HMAC blocks.
    const info = Buffer.from([0, 48]);
    const first = hmacSha256(prk, Buffer.concat([info, Buffer.from([1])]));
    const second = hmacSha256(prk, Buffer.concat([first, info, Buffer.from([2])]));
    secret = BigInt(hexlify(Buffer.concat([first, second]).subarray(0, 48))) % GROUP_ORDER;
  }
  return secret;
}

const testSecrets = new Map();

/** §11.3 test key `sk_i = KeyGen(SHA-256("sccp-finality-test-ikm" ‖ u8 i))`. Publicly known; never use for value. */
function testSecret(index) {
  if (!testSecrets.has(index)) {
    testSecrets.set(index, keyGen(sha256(ascii(TEST_IKM_TAG), be(index, 1))));
  }
  return testSecrets.get(index);
}

/** The 48-byte compressed public key of a secret (`SkToPk`). */
function publicKey(secret) {
  return hexlify(G1.BASE.multiply(secret).toRawBytes(true));
}

function testPublicKey(index) {
  return publicKey(testSecret(index));
}

/**
 * Affine coordinates of a compressed 48-byte key, computed from the curve
 * equation `y² = x³ + 4` and the sign flag, with no subgroup check: keys
 * outside G1 decompress too. Returns null if the flags are not those of a
 * compressed finite point, if `x ≥ p` or if `x` is on no curve point.
 */
function decompressG1(key) {
  const bytes = getBytes(key);
  assert.equal(bytes.length, 48, "a compressed G1 key is 48 bytes");
  if ((bytes[0] & 0xc0) !== 0x80) return null;
  const x = BigInt(hexlify(bytes)) & ((1n << 381n) - 1n);
  if (x >= FIELD_P) return null;
  const Fp = bls.fields.Fp;
  let y;
  try {
    y = Fp.sqrt(Fp.add(Fp.mul(Fp.mul(x, x), x), 4n));
  } catch {
    return null;
  }
  if (y > HALF_P !== ((bytes[0] & 0x20) !== 0)) y = Fp.neg(y);
  return { x, y };
}

/** 64-byte EIP-2537 field element: 16 zero bytes, then the 48-byte value. */
function fieldElement(value) {
  return concat([`0x${"00".repeat(16)}`, be(value, 48)]);
}

/** 128-byte EIP-2537 form of an affine G1 point (null is the point at infinity). */
function g1Eip2537(point) {
  if (point === null) return `0x${"00".repeat(128)}`;
  return concat([fieldElement(point.x), fieldElement(point.y)]);
}

function g1Affine(point) {
  return point.equals(G1.ZERO) ? null : point.toAffine();
}

/** The four 48-byte limbs `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` of a finite G2 point: the EVM signature form (§3.7). */
function g2Evm192(point) {
  const { x, y } = point.toAffine();
  return concat([be(x.c0, 48), be(x.c1, 48), be(y.c0, 48), be(y.c1, 48)]);
}

/** 256-byte EIP-2537 form of a finite G2 point: each limb zero-extended to 64 bytes. */
function g2Eip2537(point) {
  const { x, y } = point.toAffine();
  return concat([fieldElement(x.c0), fieldElement(x.c1), fieldElement(y.c0), fieldElement(y.c1)]);
}

/** 96-byte ZCash-compressed form of a G2 point (TON and Taira wire form). */
function g2Compressed(point) {
  return hexlify(point.toRawBytes(true));
}

/** RFC 9380 `hash_to_curve` to G2 of a message under `dst`. */
function hashToG2(message, dst = DST_SIG) {
  return bls.G2.hashToCurve(getBytes(message), { DST: dst });
}

/** `σ = sk · hash_to_G2(m, dst)` as a point. */
function sign(secret, message, dst = DST_SIG) {
  return hashToG2(message, dst).multiply(secret);
}

/** The sum of signatures (`Aggregate`). */
function aggregateSignatures(signatures) {
  return signatures.reduce((sum, signature) => sum.add(signature), G2.ZERO);
}

/** `signerYs`: the 48-byte `y` of every signer key, in ascending index order (§3.7). */
function signerYs(keys, indices) {
  const sorted = [...indices].sort((a, b) => a - b);
  return concat(
    sorted.map((index) => {
      const point = decompressG1(keys[index]);
      assert(point, `committee key ${index} is not a compressed curve point`);
      return be(point.y, 48);
    }),
  );
}

/** The aggregate key `Σ PK_i` of the signers as an affine point, or null for the identity. */
function aggregateKey(keys, indices) {
  let sum = G1.ZERO;
  for (const index of indices) {
    const point = decompressG1(keys[index]);
    assert(point, `committee key ${index} is not a compressed curve point`);
    sum = sum.add(G1.fromAffine(point));
  }
  return g1Affine(sum);
}

/** The 768-byte `PAIRING_CHECK` input `apk ‖ Q ‖ (−g1) ‖ σ` (§5.2.4). */
function pairingInput(apk, q, sigma) {
  return concat([g1Eip2537(apk), g2Eip2537(q), g1Eip2537(G1.BASE.negate().toAffine()), g2Eip2537(sigma)]);
}

/**
 * A committee of test keys in canonical order (ascending key bytes): `keys[i]`
 * is `PK_i`, `secrets[i]` its secret and `testKeyIndices[i]` its §11.3 index.
 */
function committee(name, indices) {
  const members = indices.map((index) => ({ index, key: testPublicKey(index), secret: testSecret(index) }));
  members.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const keys = members.map((member) => member.key);
  assert.equal(new Set(keys).size, keys.length, "duplicate committee key");
  return Object.freeze({
    name,
    n: keys.length,
    q: quorum(keys.length),
    keys,
    secrets: members.map((member) => member.secret),
    testKeyIndices: members.map((member) => member.index),
    root: committeeRoot(keys),
    bytes: concat(keys),
  });
}

/** Signs a certificate without the reproduction gate; `buildCertificate` is the public form. */
function mintCertificate({
  committee: signedBy,
  signerIndices: indices,
  header,
  instance,
  epoch,
  epochContext,
  view,
  blockHash,
  resultBody,
  kind = COMMIT_KIND,
  dst = DST_SIG,
}) {
  const sorted = [...(indices ?? Array.from({ length: signedBy.q }, (_, index) => index))].sort((a, b) => a - b);
  const signers = signersWord(sorted);
  const qc = encodeQcFixed({ epoch, epochContext, view, blockHash, resultBody, signers });
  const r = resultR(header, resultBody);
  const height = readUint(getBytes(header), 48, 8);
  const preimage = commitPreimage({ instance, epoch, epochContext, height, view, blockHash, r, kind });
  const m = commitMessage(preimage);
  const hashPoint = hashToG2(m, dst);
  const sigma = aggregateSignatures(sorted.map((index) => hashPoint.multiply(signedBy.secrets[index])));
  return {
    qc,
    header,
    signature: g2Evm192(sigma),
    committee: signedBy.bytes,
    signerYs: signerYs(signedBy.keys, sorted),
    meta: {
      signerIndices: sorted,
      signers,
      r,
      preimage,
      m,
      hashPoint,
      sigma,
      apk: aggregateKey(signedBy.keys, sorted),
    },
  };
}

/**
 * A certificate of `header` in its EVM form (`TairaCertificateV1`), signed by
 * the members `signerIndices` of `committee` (default: the lowest `q`).
 * `epoch`, `epochContext`, `view`, `blockHash` and `resultBody` are the
 * `QC_FIXED` fields a destination takes unverified. `kind` and `dst` build
 * certificates that sign something a destination must refuse. The first call
 * reproduces the fixture certificates (`requireReproduction`).
 */
function buildCertificate(fields) {
  requireReproduction();
  return mintCertificate(fields);
}

// ---------------------------------------------------------------------------
// Reproduction of `fixtures/sccp/finality_v1.json`
// ---------------------------------------------------------------------------

let reproduction = null;

/**
 * Rebuilds, from their inputs, the §11.3 test keys, the committees, the curve
 * constants and every positive certificate of `finality_v1.json` (header,
 * `QC_FIXED`, `R`, `P`, `m`, hash-to-G2 point, aggregate key and signature in
 * every recorded form, pairing input, EVM and TON wire fields), and derives
 * `m` from the wire fields of every other row that records the message its
 * verifier sees. Any difference is an assertion failure. Returns the row
 * counts.
 */
function reproduceFinalityFixture(fixture) {
  const finality =
    fixture ?? JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "sccp", "finality_v1.json"), "utf8"));
  const constants = finality.constants;
  assert.equal(constants.x_len, X_LEN);
  assert.equal(constants.qc_fixed_len, QC_FIXED_LEN);
  assert.equal(constants.commit_preimage_len, COMMIT_PREIMAGE_LEN);
  assert.equal(BigInt(constants.max_validity_ms), MAX_VALIDITY_MS);
  assert.equal(BigInt(constants.max_history_size), MAX_HISTORY_SIZE);
  assert.equal(constants.x_magic.hex, X_MAGIC);
  assert.equal(constants.result_tag.hex, RESULT_TAG);
  assert.equal(constants.tag_sig.hex, SIGNATURE_TAG);
  assert.equal(ascii(constants.committee_tag), COMMITTEE_TAG);
  assert.equal(constants.dst_sig.ascii, DST_SIG);
  const curve = constants.bls12_381;
  assert.equal(BigInt(curve.p), FIELD_P);
  assert.equal(BigInt(curve.half_p), HALF_P);
  assert.equal(BigInt(curve.r), GROUP_ORDER);
  assert.equal(curve.g1.eip2537, g1Eip2537(G1.BASE.toAffine()));
  assert.equal(curve.neg_g1.eip2537, g1Eip2537(G1.BASE.negate().toAffine()));
  assert.equal(BigInt(curve.neg_g1_y), G1.BASE.negate().toAffine().y);
  assert.equal(curve.g2.eip2537, g2Eip2537(G2.BASE));
  assert.equal(curve.g2.evm192, g2Evm192(G2.BASE));
  assert.equal(curve.g2.compressed, g2Compressed(G2.BASE));

  for (const key of finality.test_keys) {
    const what = `test key ${key.index}`;
    assert.equal(sha256(ascii(TEST_IKM_TAG), be(key.index, 1)), key.ikm, `${what}: IKM`);
    assert.equal(be(testSecret(key.index), 32), key.sk, `${what}: secret`);
    assert.equal(testPublicKey(key.index), key.pk, `${what}: public key`);
    const point = decompressG1(key.pk);
    assert.equal(be(point.y, 48), key.pk_y, `${what}: y`);
    assert.equal(g1Eip2537(point), key.pk_eip2537, `${what}: EIP-2537 form`);
  }

  const committees = new Map();
  for (const [name, expected] of Object.entries(finality.committees)) {
    const built = committee(name, expected.test_key_indices);
    assert.deepEqual(built.keys, expected.keys, `committee ${name}: canonical key order`);
    assert.deepEqual(built.testKeyIndices, expected.test_key_indices, `committee ${name}: key indices`);
    assert.equal(built.root, expected.root, `committee ${name}: root`);
    assert.equal(built.n, expected.n);
    assert.equal(built.q, expected.q);
    committees.set(name, built);
  }

  const instance = finality.verification_context.consensus_instance;
  for (const row of finality.certificates) {
    const what = `certificate ${row.label}`;
    const signedBy = committees.get(row.committee);
    const header = encodeHeader(headerFromFixture(row.header_fields));
    const qcFields = row.qc_fixed_fields;
    assert.equal(BigInt(qcFields.signers), signersWord(row.signer_indices), `${what}: signers`);
    assert.equal(signerBitmap(row.signer_indices, signedBy.n), row.bitmap, `${what}: bitmap`);
    assert.equal(row.commit_kind, COMMIT_KIND, `${what}: kind`);
    assert.equal(row.dst, DST_SIG, `${what}: DST`);
    const certificate = mintCertificate({
      committee: signedBy,
      signerIndices: row.signer_indices,
      header,
      instance,
      epoch: qcFields.epoch,
      epochContext: qcFields.epoch_context,
      view: qcFields.view,
      blockHash: qcFields.block_hash,
      resultBody: qcFields.result_body,
    });
    const { meta } = certificate;
    assert.deepEqual(
      {
        qc: certificate.qc,
        header,
        signature: certificate.signature,
        committee: certificate.committee,
        signerYs: certificate.signerYs,
      },
      row.evm,
      `${what}: EVM wire form`,
    );
    assert.equal(meta.r, row.r, `${what}: R`);
    assert.equal(meta.preimage, row.commit_preimage, `${what}: Commit preimage`);
    assert.equal(meta.m, row.m, `${what}: m`);
    assert.equal(checkpointId(header), row.checkpoint_id, `${what}: checkpoint id`);
    assert.deepEqual(
      {
        compressed: g2Compressed(meta.hashPoint),
        eip2537: g2Eip2537(meta.hashPoint),
        evm192: g2Evm192(meta.hashPoint),
      },
      row.hash_to_g2_m,
      `${what}: hash-to-G2 point`,
    );
    assert.deepEqual(
      { compressed: hexlify(G1.fromAffine(meta.apk).toRawBytes(true)), eip2537: g1Eip2537(meta.apk) },
      row.aggregate_public_key,
      `${what}: aggregate key`,
    );
    assert.deepEqual(
      { compressed: g2Compressed(meta.sigma), eip2537: g2Eip2537(meta.sigma), evm192: g2Evm192(meta.sigma) },
      row.aggregate_signature,
      `${what}: aggregate signature`,
    );
    assert.equal(pairingInput(meta.apk, meta.hashPoint, meta.sigma), row.pairing_input, `${what}: pairing input`);
    assert.deepEqual(
      {
        qc_fixed_cell: dataSlice(certificate.qc, 0, QC_FIXED_LEN - 4),
        signature: g2Compressed(meta.sigma),
        signers: Number(meta.signers),
        x_head: dataSlice(header, 0, constants.x_head_len),
        x_tail: dataSlice(header, constants.x_head_len),
      },
      row.ton,
      `${what}: TON wire form`,
    );
    assert.deepEqual(
      parseHeader(header),
      {
        ...headerFromFixture(row.header_fields),
        active: true,
        rotation: (row.header_fields.flags & FLAG_ROTATION) !== 0,
      },
      `${what}: parsed header`,
    );
  }

  let wireDerived = 0;
  const recorded = [
    ...finality.certificates,
    ...finality.negative_certificates,
    ...finality.flavor_specific_certificates,
  ];
  for (const row of recorded) {
    if (row.forgery_evidence_id === undefined) continue;
    const derived = wireDigests(instance, row.evm.qc, row.evm.header);
    assert.equal(derived.m, row.m, `certificate ${row.label}: m from the wire fields`);
    assert.equal(derived.preimage, row.commit_preimage, `certificate ${row.label}: P from the wire fields`);
    assert.equal(derived.r, row.r, `certificate ${row.label}: R from the wire fields`);
    wireDerived += 1;
  }

  return Object.freeze({
    testKeys: finality.test_keys.length,
    committees: committees.size,
    certificates: finality.certificates.length,
    wireDerived,
  });
}

/** Runs `reproduceFinalityFixture` once per process and returns its counts. */
function requireReproduction() {
  if (reproduction === null) reproduction = reproduceFinalityFixture();
  return reproduction;
}

// ---------------------------------------------------------------------------
// Taira simulator
// ---------------------------------------------------------------------------

/** Default Taira sender of model transfers: 34 opaque `taira_account` bytes. */
const DEFAULT_TAIRA_SENDER = `0x01${"5a".repeat(33)}`;

/**
 * Minimal Taira for one destination route: numbered blocks with their
 * commitment trees, the history accumulator, finality headers with the
 * generation bookkeeping of a rotation (the successor starts at `h + 1`), and
 * certificates and proofs over them (§3.4 - §3.7, §5.1.5).
 */
class TairaModel {
  constructor({ networkId, instance, profile, destinationWord, revision = 1 }) {
    this.networkId = networkId;
    this.instance = instance;
    this.profile = profile;
    this.destinationWord = destinationWord;
    this.revision = revision;
    this.history = [];
    this.blocks = new Map();
    this.current = null;
  }

  /** Starts generation `generation` with `committee` at `startHeight`. */
  start(generation, signedBy, startHeight, validityMs) {
    this.current = {
      generation: BigInt(generation),
      committee: signedBy,
      startHeight: BigInt(startHeight),
      validityMs: BigInt(validityMs),
    };
    return this.current;
  }

  /** A transfer leaf of this route with its payload and message id. */
  transfer({ nonce, amount, deadlineMs, recipient, sender = DEFAULT_TAIRA_SENDER }) {
    const payload = encodePayload(
      outboundFields(this.profile, { nonce, revision: this.revision, deadlineMs, amount, sender, recipient }),
    );
    const id = outboundMessageId(this.networkId, this.profile, payload);
    const leaf = transferLeaf(id, this.destinationWord);
    return { kind: "transfer", leaf, payload, nonce: BigInt(nonce), messageId: id };
  }

  /**
   * A control leaf of this route. `fields` are `{controlNonce, track,
   * parliamentPaused, fastPauseUntilMs, certificateId, effectHash}`; the leaf
   * is built as it stands, also when it violates a §3.4 constraint.
   */
  control(fields) {
    const leaf = controlLeaf({
      networkId: this.networkId,
      profile: this.profile,
      destinationWord: this.destinationWord,
      revision: this.revision,
      nonce: fields.controlNonce,
      ...fields,
    });
    return { kind: "control", leaf, control: { ...fields } };
  }

  /** A leaf recorded elsewhere (a fixture), carried with the control fields a proof supplies for it. */
  recordedControl(leaf, fields) {
    return { kind: "control", leaf, control: { ...fields } };
  }

  /**
   * Commits block `height` at `timestampMs` with `leaves` and returns it with
   * its header. `rotate` is `"key"` (with `nextCommittee`) or `"heartbeat"`;
   * the successor generation becomes current.
   */
  block(height, timestampMs, leaves = [], { rotate, nextCommittee, validityMs } = {}) {
    const generation = this.current;
    assert(generation, "start a generation first");
    const count = leaves.length;
    const sccpRoot = count ? merkleRoot(leaves.map((item) => item.leaf)) : ZERO32;
    let historyIndex = null;
    if (count) {
      historyIndex = this.history.length;
      this.history.push(historyLeaf(height, sccpRoot, count));
    }
    let flags = FLAG_ACTIVE;
    let validity = 0n;
    let nextRoot = ZERO32;
    let successor = null;
    if (rotate) {
      assert(rotate === "key" || rotate === "heartbeat", "rotate is \"key\" or \"heartbeat\"");
      flags |= FLAG_ROTATION;
      successor = rotate === "heartbeat" ? generation.committee : nextCommittee;
      validity = validityMs === undefined ? generation.validityMs : BigInt(validityMs);
      nextRoot = successor.root;
    }
    const header = {
      networkId: this.networkId,
      height: BigInt(height),
      timestampMs: BigInt(timestampMs),
      flags,
      messageCount: BigInt(count),
      sccpRoot,
      historySize: BigInt(this.history.length),
      historyRoot: historyRoot(this.history),
      generation: generation.generation,
      committeeRoot: generation.committee.root,
      validityMs: validity,
      nextCommitteeRoot: nextRoot,
    };
    const block = {
      height: BigInt(height),
      header,
      x: encodeHeader(header),
      committee: generation.committee,
      leaves: leaves.slice(),
      historyIndex,
    };
    this.blocks.set(block.height, block);
    if (rotate) this.start(generation.generation + 1n, successor, block.height + 1n, validity);
    return block;
  }

  /** Deterministic `QC_FIXED` inputs; a destination takes them unverified. */
  qcFields(height, x, bodyTag = "0x") {
    const epoch = BigInt(height) / 100n;
    return {
      epoch,
      epochContext: keccak256(concat([ascii("sccp-model/epoch-context"), be(epoch, 8)])),
      view: 0n,
      blockHash: keccak256(concat([ascii("sccp-model/block"), be(height, 8), x])),
      resultBody: keccak256(concat([ascii("sccp-model/result-body"), be(height, 8), bodyTag])),
    };
  }

  /**
   * Certifies `block` with the committee that produced it. `signerIndices`,
   * `bodyTag` (another `result_body` for the same `X`) and the
   * `buildCertificate` overrides are optional.
   */
  certify(block, { signerIndices: indices, bodyTag, ...overrides } = {}) {
    return buildCertificate({
      committee: block.committee,
      signerIndices: indices,
      header: block.x,
      instance: this.instance,
      ...this.qcFields(block.height, block.x, bodyTag),
      ...overrides,
    });
  }

  /** `BlockRefV1` of block `height` under the header of `certified`. */
  blockRef(height, certified) {
    const block = this.blocks.get(BigInt(height));
    assert(block && block.leaves.length > 0, `block ${height} carries no SCCP message`);
    const base = { height: block.height, sccpRoot: block.header.sccpRoot, messageCount: block.header.messageCount };
    if (block.height === certified.height) return { ...base, historyIndex: 0n, historyPath: [] };
    const leaves = this.history.slice(0, Number(certified.header.historySize));
    return { ...base, historyIndex: BigInt(block.historyIndex), historyPath: merklePath(leaves, block.historyIndex) };
  }

  /** `MessageProofV1` of transfer leaf `leafIndex` of block `height` under `certified`. */
  messageProof(height, leafIndex, certified) {
    const block = this.blocks.get(BigInt(height));
    const item = block.leaves[leafIndex];
    assert.equal(item.kind, "transfer", "the leaf is a transfer");
    return {
      payload: item.payload,
      leafIndex,
      path: merklePath(block.leaves.map((leaf) => leaf.leaf), leafIndex),
      block: this.blockRef(height, certified),
    };
  }

  /** `ControlProofV1` of control leaf `leafIndex` of block `height` under `certified`. */
  controlProof(height, leafIndex, certified) {
    const block = this.blocks.get(BigInt(height));
    const item = block.leaves[leafIndex];
    assert.equal(item.kind, "control", "the leaf is a control");
    const { controlNonce, track, parliamentPaused, fastPauseUntilMs, certificateId, effectHash } = item.control;
    return {
      controlNonce,
      track,
      parliamentPaused,
      fastPauseUntilMs,
      certificateId,
      effectHash,
      leafIndex,
      path: merklePath(block.leaves.map((leaf) => leaf.leaf), leafIndex),
      block: this.blockRef(height, certified),
    };
  }
}

// ---------------------------------------------------------------------------
// Destination ABI (§5.2.1, §5.2.2) and the CREATE2 address (§4.14.3 P4)
// ---------------------------------------------------------------------------

const CERTIFICATE_TYPE = "tuple(bytes qc, bytes header, bytes signature, bytes committee, bytes signerYs)";
const CHECKPOINT_TYPE = "tuple(bytes header)";
const BLOCK_TYPE =
  "tuple(uint64 height, bytes32 sccpRoot, uint32 messageCount, uint64 historyIndex, bytes32[] historyPath)";
const MESSAGE_TYPE = `tuple(bytes payload, uint32 leafIndex, bytes32[] path, ${BLOCK_TYPE} block)`;
const CONTROL_TYPE =
  "tuple(uint64 controlNonce, uint8 track, bool parliamentPaused, uint64 fastPauseUntilMs, bytes32 certificateId, " +
  `bytes32 effectHash, uint32 leafIndex, bytes32[] path, ${BLOCK_TYPE} block)`;

/** The 24 functions of the §5.2.2 selector table, written from the specification. */
const SCCP_FUNCTIONS = Object.freeze([
  `function submitCheckpoints(${CERTIFICATE_TYPE}[] certificates)`,
  `function finalizeFromTaira(${CERTIFICATE_TYPE} certificate, ${MESSAGE_TYPE} proof) returns (bytes32)`,
  `function finalizeFromCheckpoint(${CHECKPOINT_TYPE} checkpoint, ${MESSAGE_TYPE} proof) returns (bytes32)`,
  `function applyControl(${CERTIFICATE_TYPE} certificate, ${CONTROL_TYPE} control)`,
  `function applyControlFromCheckpoint(${CHECKPOINT_TYPE} checkpoint, ${CONTROL_TYPE} control)`,
  `function voidExpired(uint64 nonce, ${CERTIFICATE_TYPE} certificate, ${MESSAGE_TYPE} proof)`,
  `function voidExpiredFromCheckpoint(uint64 nonce, ${CHECKPOINT_TYPE} checkpoint, ${MESSAGE_TYPE} proof)`,
  "function voidFrozen(uint64 firstNonce, uint64 count)",
  "function transferToTaira(bytes tairaRecipient, uint256 tokenAmount, uint64 expectedNonce) " +
    "returns (bytes32 messageId)",
  "function committeeState() view returns (bytes32 root, uint64 untilMs, uint64 start, uint64 high, uint64 generation)",
  "function checkpointHeader(uint64) view returns (bytes32)",
  "function pauseState() view " +
    "returns (bool parliamentPaused, uint64 fastPauseUntilMs, uint64 controlNonce, bool effective)",
  "function mintingPaused() view returns (bool)",
  "function consensusInstance() view returns (bytes32)",
  "function initialCommittee() view returns (uint64 generation, bytes32 root, uint64 start, uint64 untilMs)",
  "function equivocated() view returns (bool)",
  "function maxValidityMs() view returns (uint64)",
  "function isConsumed(uint64 nonce) view returns (bool)",
  "function controlNonce() view returns (uint64)",
  "function opCount() view returns (uint64)",
  "function transferNonces(address) view returns (uint64)",
  "function tairaNetworkId() view returns (bytes32)",
  "function routeRevision() view returns (uint32)",
  "function maxWrappedSupply() view returns (uint256)",
]);

const ERC20_FUNCTIONS = Object.freeze([
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address, address) view returns (uint256)",
  "function transfer(address to, uint256 value) returns (bool)",
  "function transferFrom(address from, address to, uint256 value) returns (bool)",
  "function approve(address spender, uint256 value) returns (bool)",
]);

/** The eight SCCP events of §5.2.2. */
const SCCP_EVENTS = Object.freeze([
  "event SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce, bytes payload)",
  "event SccpFinalized(bytes32 indexed messageId, uint64 indexed nonce, address indexed recipient, " +
    "uint256 tokenAmount)",
  "event SccpVoided(bytes32 indexed messageId, uint64 indexed nonce)",
  "event SccpCommitteeRotated(uint64 indexed generation, bytes32 root, uint64 untilMs, uint64 startHeight)",
  "event SccpCheckpointed(uint64 indexed height, bytes32 header)",
  "event SccpLatched(uint8 indexed reason, uint64 generation, uint64 height, bytes32 a, bytes32 b)",
  "event SccpControlApplied(uint64 indexed controlNonce, uint8 track, bool parliamentPaused, " +
    "uint64 fastPauseUntilMs, bytes32 certificateId)",
  "event SccpCertificate(uint64 indexed height, uint64 indexed generation, bytes qc, bytes header, bytes signature)",
]);

const ERC20_EVENTS = Object.freeze([
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "event Approval(address indexed owner, address indexed spender, uint256 value)",
]);

/**
 * The EVM errors of the §5.2.2 table. `NotInitialized` and
 * `AlreadyInitialized` are TON codes only: an EVM destination is initialized
 * by its constructor and can raise neither.
 */
const SCCP_ERRORS = Object.freeze([
  "error WrongChain()",
  "error MintingIsPaused()",
  "error CommitteeNotAccepted()",
  "error BadCommittee()",
  "error BadCertificate()",
  "error BadSignature()",
  "error BadHeader()",
  "error BadProof()",
  "error BadPayload()",
  "error AlreadyConsumed(uint64 nonce)",
  "error SupplyCapExceeded()",
  "error UnknownCheckpoint()",
  "error BadRecipient()",
  "error BadAmount()",
  "error BadNonce(uint64 expected)",
  "error NonCanonicalCalldata()",
  "error DeadlinePassed()",
  "error DeadlineNotReached()",
  "error NotFrozen()",
  "error StaleControl()",
  "error BadControl()",
  "error NothingToDo()",
  "error BadConfig()",
  "error Equivocated()",
  "error LatchRequired()",
  "error TooManyCertificates()",
]);

/** ERC-6093 errors of the token surface. */
const ERC20_ERRORS = Object.freeze([
  "error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)",
  "error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)",
  "error ERC20InvalidSender(address sender)",
  "error ERC20InvalidReceiver(address receiver)",
  "error ERC20InvalidSpender(address spender)",
]);

/** §5.2.1 constructor argument types, in order. */
const CONSTRUCTOR_TYPES = Object.freeze([
  "bytes32",
  "bytes32",
  "uint8",
  "uint32",
  "uint256",
  "uint64",
  "bytes32",
  "uint64",
  "uint64",
]);

/** The destination interface of the model: every encoding of the EDR suites goes through it. */
const iface = new ethers.Interface([
  ...SCCP_FUNCTIONS,
  ...ERC20_FUNCTIONS,
  ...SCCP_EVENTS,
  ...ERC20_EVENTS,
  ...SCCP_ERRORS,
  ...ERC20_ERRORS,
]);

/**
 * The nine §5.2.1 constructor arguments, in order, from
 * `{tairaNetworkId, consensusInstance, networkTag, routeRevision,
 * maxWrappedSupply, initialGeneration, initialCommitteeRoot,
 * initialStartHeight, initialUntilMs}`.
 */
function constructorArgs(deployment) {
  return [
    deployment.tairaNetworkId,
    deployment.consensusInstance,
    deployment.networkTag,
    deployment.routeRevision,
    deployment.maxWrappedSupply,
    deployment.initialGeneration,
    deployment.initialCommitteeRoot,
    deployment.initialStartHeight,
    deployment.initialUntilMs,
  ];
}

/** `abi.encode` of the constructor arguments, the tail of the init code. */
function encodeConstructorArgs(deployment) {
  return abi.encode([...CONSTRUCTOR_TYPES], constructorArgs(deployment));
}

/**
 * The address `SCCP_EVM_DEPLOYER` gives an init code under salt `0^32`:
 * `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(init code))[12..]`.
 */
function create2Address(initCode, salt = SCCP_EVM_SALT) {
  const digest = keccak256(concat(["0xff", SCCP_EVM_DEPLOYER, salt, keccak256(initCode)]));
  return getAddress(dataSlice(digest, 12));
}

/** Function selector and event topic from a canonical signature string. */
function selector(signature) {
  return keccak256(toUtf8Bytes(signature)).slice(0, 10);
}

function topic(signature) {
  return keccak256(toUtf8Bytes(signature));
}

/** The raw log `{topics, data}` of event `name` with `values` in declaration order. */
function eventLog(name, values) {
  const { topics, data } = iface.encodeEventLog(name, values);
  return { topics, data };
}

module.exports = {
  CODEC_EVM_ADDRESS20,
  CODEC_TAIRA_ACCOUNT,
  COMMIT_KIND,
  COMMIT_PREIMAGE_LEN,
  CONSTRUCTOR_TYPES,
  CONTROL_PREIMAGE_LEN,
  DEFAULT_TAIRA_SENDER,
  DST_SIG,
  ERC20_ERRORS,
  ERC20_EVENTS,
  ERC20_FUNCTIONS,
  FIELD_P,
  FLAG_ACTIVE,
  FLAG_ROTATION,
  GROUP_ORDER,
  HALF_P,
  MAX_CERTIFICATES_PER_CALL,
  MAX_FAST_PAUSE_MS,
  MAX_HISTORY_SIZE,
  MAX_INIT_SLACK_MS,
  MAX_VALIDITY_MS,
  MAX_VOID_FROZEN_RANGE,
  ModelError,
  PROFILES,
  QC_FIXED_LEN,
  REPO,
  RUNTIME_DIR,
  SCCP_ERRORS,
  SCCP_EVENTS,
  SCCP_EVM_DEPLOYER,
  SCCP_EVM_DEPLOYER_RUNTIME,
  SCCP_EVM_SALT,
  SCCP_FUNCTIONS,
  TAIRA_TAG,
  TRACK_FAST_PAUSE,
  TRACK_PARLIAMENT,
  TairaModel,
  U64_MAX,
  X_LEN,
  ZERO32,
  ZERO_ADDRESS,
  accountBytes,
  addressWord,
  aggregateKey,
  aggregateSignatures,
  ascii,
  be,
  bls,
  buildCertificate,
  checkBlockRef,
  checkLeaf,
  checkpointId,
  commitMessage,
  commitPreimage,
  committee,
  committeeRoot,
  constructorArgs,
  controlConstraintsHold,
  controlLeaf,
  controlLeafPreimage,
  create2Address,
  decompressG1,
  encodeConstructorArgs,
  encodeHeader,
  encodePayload,
  encodeQcFixed,
  ethers,
  eventLog,
  g1Eip2537,
  g2Compressed,
  g2Eip2537,
  g2Evm192,
  hashToG2,
  headerFromFixture,
  historyLeaf,
  historyRoot,
  identityWord,
  iface,
  inboundLaneBytes,
  inboundMessageId,
  inboundPayload,
  keyGen,
  merklePath,
  merkleRoot,
  merkleRootFromPath,
  messageId,
  node,
  outboundFields,
  outboundLaneBytes,
  outboundMessageId,
  pairingInput,
  parseHeader,
  parseQcFixed,
  payloadHash,
  profileNetworkBytes,
  profileOf,
  publicKey,
  quorum,
  reproduceFinalityFixture,
  requireReproduction,
  resultR,
  runtimeRequire,
  selector,
  sha256,
  sign,
  signerBitmap,
  signerIndices,
  signerYs,
  signersWord,
  tairaNetworkBytes,
  testPublicKey,
  testSecret,
  topic,
  transferLeaf,
  wireDigests,
  word,
};
