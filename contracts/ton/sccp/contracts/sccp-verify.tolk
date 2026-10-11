// SCCP v1 proof primitives shared by the TON minter: commitment and history
// trees (§3.4, §3.5), block references and leaf paths against a verified
// finality header (§5.1.5), message ids, transfer and control leaves with the
// control constraints (§3.3, §3.4, §5.1.6), and the §3.2 transfer payload in
// both directions. Certificates and headers are in `sccp-finality.tolk`.
//
// The proof cells of a message (`MessageProof`, `ControlProof`, `BlockRef`)
// are opened here by hand: each must be an ordinary cell with exactly the bit
// and reference counts of §5.3.2 (`BadSnake`). A well-formed cell whose
// content fails a proof rule is `BadProof`.

import "sccp-cells"
import "sccp-constants"
import "sccp-crypto"
import "sccp-errors"
import "sccp-finality"

// ---------------------------------------------------------------------------
// Commitment and history trees (§3.4, §3.5).

/// `node(l, r) = keccak256("SCCP/NODE/V1" ‖ l ‖ r)`.
@inline
fun sccpNode(left: int, right: int): uint256 {
    return keccak256Builder(
        beginCell()
            .storeUint(SCCP_TAG_NODE_V1, SCCP_TAG_NODE_V1_BITS)
            .storeUint(left, 256)
            .storeUint(right, 256),
    );
}

/// Positional promote-odd Merkle root (§3.4); throws `BadProof`.
fun sccpMerkleRoot(leaf: int, index: int, count: int, siblings: array<int>): int {
    assert ((count >= 1) & (index >= 0) & (index < count)) throw SccpErrors.BadProof;
    var h = leaf;
    var k = 0;
    var i = index;
    var c = count;
    val len = siblings.size();
    while (c > 1) {
        if ((i & 1) != 0) {
            assert (k < len) throw SccpErrors.BadProof;
            h = sccpNode(siblings.get(k), h);
            k += 1;
        } else if (i + 1 < c) {
            assert (k < len) throw SccpErrors.BadProof;
            h = sccpNode(h, siblings.get(k));
            k += 1;
        }
        i = i >> 1;
        c = (c + 1) >> 1;
    }
    assert (k == len) throw SccpErrors.BadProof;
    return h;
}

/// `history_leaf(height, sccp_root, message_count)`.
@pure
fun sccpHistoryLeaf(height: int, sccpRoot: int, messageCount: int): uint256 {
    return keccak256Builder(
        beginCell()
            .storeUint(SCCP_TAG_HISTORY_V1, SCCP_TAG_HISTORY_V1_BITS)
            .storeUint(height, 64)
            .storeUint(sccpRoot, 256)
            .storeUint(messageCount, 32),
    );
}

// ---------------------------------------------------------------------------
// Block references, leaf paths and proof cells (§5.1.5, §5.1.6, §5.3.2).

/// Checks a `^BlockRef` (`BlockRefV1`) against a verified header `x` and
/// returns the `(sccpRoot, messageCount)` of the block it names.
///
/// The cell must be ordinary with exactly 425 bits and its history path in
/// the canonical `HashChunk` shape (`BadSnake`). The reference rules are
/// `BadProof`:
///
/// - `height = X.height`: the certified block itself takes no history proof.
///   `sccpRoot = X.sccp_root ≠ 0`, `messageCount = X.message_count`,
///   `historyIndex = 0` and an empty path.
/// - otherwise `height < X.height`, `1 ≤ messageCount ≤ 512`, `sccpRoot ≠ 0`,
///   a path of at most 32 siblings, and the history leaf of the block proves
///   under `X.history_root` at `(historyIndex, X.history_size)`. X5 bounds
///   `X.history_size` by 2^32.
fun sccpCheckBlockRef(block: cell, x: XHeader): (int, int) {
    var s = sccpBeginParseOrdinary(block);
    assert (s.remainingBitsCount() == SCCP_BLOCK_REF_BITS) throw SccpErrors.BadSnake;
    val height = s.loadUint(64);
    val sccpRoot = s.loadUint(256);
    val messageCount = s.loadUint(32);
    val historyIndex = s.loadUint(64);
    val pathLen = s.loadUint(8);
    val hasPath = s.loadUint(1);
    assert (s.remainingRefsCount() == hasPath) throw SccpErrors.BadSnake;
    val path = hasPath == 0 ? null : s.preloadRef();
    val siblings = sccpLoadHashPath(path, pathLen, SCCP_MAX_HISTORY_PATH);
    if (height == x.height) {
        assert (
            (sccpRoot == x.sccpRoot) & (sccpRoot != 0) & (messageCount == x.messageCount) &
            (historyIndex == 0) &
            (pathLen == 0)
        ) throw SccpErrors.BadProof;
        return (sccpRoot, messageCount);
    }
    assert (
        (height < x.height) & (messageCount >= 1) & (messageCount <= SCCP_MAX_BLOCK_LEAVES) &
        (sccpRoot != 0)
    ) throw SccpErrors.BadProof;
    assert (
        sccpMerkleRoot(
            sccpHistoryLeaf(height, sccpRoot, messageCount),
            historyIndex,
            x.historySize,
            siblings,
        ) ==
        x.historyRoot
    ) throw SccpErrors.BadProof;
    return (sccpRoot, messageCount);
}

/// Verifies `leaf` at `leafIndex` of a block with root `sccpRoot` and `count`
/// leaves, as `sccpCheckBlockRef` returned them. The path holds at most 9
/// siblings in the canonical `HashChunk` shape (`BadSnake`); a path that is
/// too long or does not reproduce the root is `BadProof`.
fun sccpVerifyLeaf(
    leaf: int,
    leafIndex: int,
    pathLen: int,
    path: cell?,
    sccpRoot: int,
    count: int,
) {
    val siblings = sccpLoadHashPath(path, pathLen, SCCP_MAX_BLOCK_PATH);
    assert (sccpMerkleRoot(leaf, leafIndex, count, siblings) == sccpRoot) throw SccpErrors.BadProof;
}

/// A `^MessageProof` opened by `sccpOpenMessageProof`. `payload`, `path` and
/// `block` are still unchecked cells: `sccpParseInboundPayload`,
/// `sccpVerifyLeaf` and `sccpCheckBlockRef` open them.
struct OpenedMessageProof {
    leafIndex: uint32
    pathLen: uint8
    /// `^SnakeBytes` with the §3.2 payload.
    payload: cell
    /// `(Maybe ^HashChunk)`.
    path: cell?
    /// `^BlockRef`.
    block: cell
}

/// Opens a `^MessageProof` (`MessageProofV1`): an ordinary cell of exactly 41
/// bits whose references are the payload, the path iff its Maybe bit is set,
/// and the block reference (`BadSnake`).
fun sccpOpenMessageProof(proof: cell): OpenedMessageProof {
    var s = sccpBeginParseOrdinary(proof);
    assert (s.remainingBitsCount() == SCCP_MESSAGE_PROOF_BITS) throw SccpErrors.BadSnake;
    val leafIndex = s.loadUint(32);
    val pathLen = s.loadUint(8);
    val hasPath = s.loadUint(1);
    assert (s.remainingRefsCount() == 2 + hasPath) throw SccpErrors.BadSnake;
    val payload = s.loadRef();
    val path = hasPath == 0 ? null : s.loadRef();
    return {
        leafIndex,
        pathLen,
        payload,
        path,
        block: s.loadRef(),
    };
}

/// A `^ControlProof` opened by `sccpOpenControlProof`; `path` and `block`
/// are still unchecked cells.
struct OpenedControlProof {
    controlNonce: uint64
    track: uint8
    parliamentPaused: bool
    fastPauseUntilMs: uint64
    certificateId: uint256
    effectHash: uint256
    leafIndex: uint32
    pathLen: uint8
    /// `(Maybe ^HashChunk)`.
    path: cell?
    /// `^BlockRef`.
    block: cell
}

/// Opens a `^ControlProof` (`ControlProofV1`): an ordinary cell of exactly
/// 690 bits whose references are the path iff its Maybe bit is set, and the
/// block reference (`BadSnake`). `parliament_paused` is one bit, so no value
/// other than 0 or 1 reaches the §3.4 constraints.
fun sccpOpenControlProof(proof: cell): OpenedControlProof {
    var s = sccpBeginParseOrdinary(proof);
    assert (s.remainingBitsCount() == SCCP_CONTROL_PROOF_BITS) throw SccpErrors.BadSnake;
    val controlNonce = s.loadUint(64);
    val track = s.loadUint(8);
    val parliamentPaused = s.loadBool();
    val fastPauseUntilMs = s.loadUint(64);
    val certificateId = s.loadUint(256);
    val effectHash = s.loadUint(256);
    val leafIndex = s.loadUint(32);
    val pathLen = s.loadUint(8);
    val hasPath = s.loadUint(1);
    assert (s.remainingRefsCount() == 1 + hasPath) throw SccpErrors.BadSnake;
    val path = hasPath == 0 ? null : s.loadRef();
    return {
        controlNonce,
        track,
        parliamentPaused,
        fastPauseUntilMs,
        certificateId,
        effectHash,
        leafIndex,
        pathLen,
        path,
        block: s.loadRef(),
    };
}

// ---------------------------------------------------------------------------
// Leaves and message ids (§3.3, §3.4).

/// `message_id` of a Taira→TON payload (lane `(sora-taira, ton-mainnet)`).
@pure
fun sccpInboundMessageId(networkId: int, payloadHash: int): uint256 {
    return keccak256Builder(
        beginCell()
            .storeUint(SCCP_TAG_MESSAGE_V1, SCCP_TAG_MESSAGE_V1_BITS)
            .storeUint(SCCP_TAG_TAIRA, 8)
            .storeUint(networkId, 256)
            .storeUint(SCCP_TAG_TON, 8)
            .storeUint(SCCP_TON_IDENTITY_WORD, 256)
            .storeUint(payloadHash, 256),
    );
}

/// `message_id` of a TON→Taira payload (lane `(ton-mainnet, sora-taira)`).
@pure
fun sccpOutboundMessageId(networkId: int, payloadHash: int): uint256 {
    return keccak256Builder(
        beginCell()
            .storeUint(SCCP_TAG_MESSAGE_V1, SCCP_TAG_MESSAGE_V1_BITS)
            .storeUint(SCCP_TAG_TON, 8)
            .storeUint(SCCP_TON_IDENTITY_WORD, 256)
            .storeUint(SCCP_TAG_TAIRA, 8)
            .storeUint(networkId, 256)
            .storeUint(payloadHash, 256),
    );
}

/// `transfer_leaf = keccak256("SCCP/LEAF/V1" ‖ message_id ‖ destination_word)`.
@pure
fun sccpTransferLeaf(messageId: int, destinationWord: int): uint256 {
    return keccak256Builder(
        beginCell()
            .storeUint(SCCP_TAG_LEAF_V1, SCCP_TAG_LEAF_V1_BITS)
            .storeUint(messageId, 256)
            .storeUint(destinationWord, 256),
    );
}

/// Control leaf of §3.4 for `target = ton-mainnet`: the complete pause state
/// of `(network, revision)` after a change, with the authority that made it.
/// The 199-byte preimage exceeds one cell, so it is hashed as two
/// byte-aligned builders: `b1` = tag ‖ lane ‖ destination word ‖ revision ‖
/// nonce (125 bytes) and `b2` = track ‖ `parliament_paused` ‖
/// `fast_pause_until_ms` ‖ `certificate_id` ‖ `effect_hash` (74 bytes).
///
/// The leaf is computed from the supplied fields as they are: its path is
/// checked first and `sccpCheckControl` after it, so a certified leaf of
/// refused fields answers `BadControl`, not `BadProof`.
@pure
fun sccpControlLeaf(
    networkId: int,
    destinationWord: int,
    routeRevision: int,
    controlNonce: int,
    track: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    certificateId: int,
    effectHash: int,
): uint256 {
    return keccak256Builders2(
        beginCell()
            .storeUint(SCCP_TAG_CONTROL_V1, SCCP_TAG_CONTROL_V1_BITS)
            .storeUint(SCCP_TAG_TAIRA, 8)
            .storeUint(networkId, 256)
            .storeUint(SCCP_TAG_TON, 8)
            .storeUint(SCCP_TON_IDENTITY_WORD, 256)
            .storeUint(destinationWord, 256)
            .storeUint(routeRevision, 32)
            .storeUint(controlNonce, 64),
        beginCell()
            .storeUint(track, 8)
            .storeUint(parliamentPaused ? 1 : 0, 8)
            .storeUint(fastPauseUntilMs, 64)
            .storeUint(certificateId, 256)
            .storeUint(effectHash, 256),
    );
}

/// The §3.4 constraints a destination checks on a control leaf (`BadControl`):
/// `track ∈ {1, 2}`, `track = 2 ⇒ fast_pause_until_ms ≠ 0`, `certificate_id ≠
/// 0` and `effect_hash ≠ 0`. They are checked after the leaf path and before
/// the control nonce (§5.1.6).
fun sccpCheckControl(track: int, fastPauseUntilMs: int, certificateId: int, effectHash: int) {
    assert (
        (track == SCCP_TRACK_PARLIAMENT) | (track == SCCP_TRACK_FAST_PAUSE)
    ) throw SccpErrors.BadControl;
    assert ((track != SCCP_TRACK_FAST_PAUSE) | (fastPauseUntilMs != 0)) throw SccpErrors.BadControl;
    assert ((certificateId != 0) & (effectHash != 0)) throw SccpErrors.BadControl;
}

/// `fast_pause_until_ms` as an applied control stores it (§5.1.6 step 5):
/// `min(leaf value, min(now_ms + MAX_FAST_PAUSE_MS, 2^64 − 1))`. The clamp
/// bounds a Byzantine Taira time, and the sum saturates.
@pure
fun sccpAppliedFastPauseUntilMs(fastPauseUntilMs: int, nowMs: int): int {
    return min(fastPauseUntilMs, min(nowMs + SCCP_MAX_FAST_PAUSE_MS, SCCP_MAX_U64));
}

/// The effective pause (§5.1.6): `parliamentPaused ∨ now_ms <
/// fastPauseUntilMs`. It blocks minting only; burns, voids, checkpoints,
/// rotations and controls are never paused.
@pure
fun sccpEffectivePause(parliamentPaused: bool, fastPauseUntilMs: int, nowMs: int): bool {
    return parliamentPaused | (nowMs < fastPauseUntilMs);
}

// ---------------------------------------------------------------------------
// Transfer payloads (§3.2).

/// Fields of a validated Taira→TON payload.
struct InboundPayload {
    nonce: uint64
    deadlineMs: uint64
    amount: int
    /// Account id of the `addr_std` workchain-0 recipient.
    recipientHash: uint256
    payloadHash: uint256
}

/// `payload_hash = keccak256("SCCP/PAYLOAD/V1" ‖ payload)` over chunk parts.
fun sccpPayloadHash(chunks: tuple): uint256 {
    var parts: tuple = [];
    parts.push(beginCell().storeUint(SCCP_TAG_PAYLOAD_V1, SCCP_TAG_PAYLOAD_V1_BITS));
    var i = 0;
    val size = chunks.size();
    while (i < size) {
        parts.push(chunks.get(i));
        i += 1;
    }
    return keccak256Parts(parts);
}

/// Bytes of a Taira→TON payload before the sender bytes (kind … sender_len).
const SCCP_INBOUND_PREFIX_BYTES = 59
/// Bytes after the sender (recipient codec … route id).
const SCCP_INBOUND_SUFFIX_BYTES = 55

/// Parses and validates a Taira→TON payload for this deployment (§3.2 and
/// §5.1.5 step 4): kind, version, domains, revision, nonzero deadline, asset,
/// amount (nonzero, below 2^96), codecs and lengths, the route id and no
/// trailing bytes (`BadPayload`), then the `ton_account36` recipient:
/// workchain 0, a nonzero account id, not the minter itself
/// (`BadRecipient`). `BadRecipient` therefore answers only a payload that is
/// valid in everything else, as the reference models report it. The payload
/// cell is a canonical `SnakeBytes` (`BadSnake`). The deadline itself is
/// checked by the caller.
///
/// The fixed prefix always lies in the first 127-byte chunk; the fixed suffix
/// spans at most the last two chunks and is joined into one slice.
fun sccpParseInboundPayload(payload: cell, routeRevision: int, minterHash: int): InboundPayload {
    val (chunks, total) = sccpParseSnakeBytes(
        payload,
        SCCP_MAX_PAYLOAD_BYTES,
        SccpErrors.BadPayload,
    );
    assert (
        total > SCCP_INBOUND_PREFIX_BYTES + SCCP_INBOUND_SUFFIX_BYTES
    ) throw SccpErrors.BadPayload;
    var s = chunks.get(0);
    assert (s.loadUint(8) == SCCP_PAYLOAD_KIND_TRANSFER) throw SccpErrors.BadPayload;
    assert (s.loadUint(8) == SCCP_PAYLOAD_VERSION) throw SccpErrors.BadPayload;
    assert (s.loadUint(32) == SCCP_DOMAIN_TAIRA) throw SccpErrors.BadPayload;
    assert (s.loadUint(32) == SCCP_DOMAIN_TON) throw SccpErrors.BadPayload;
    val nonce = s.loadUint(64);
    assert (s.loadUint(32) == routeRevision) throw SccpErrors.BadPayload;
    val deadlineMs = s.loadUint(64);
    assert (deadlineMs != 0) throw SccpErrors.BadPayload;
    assert (s.loadUint(32) == SCCP_DOMAIN_TAIRA) throw SccpErrors.BadPayload;
    assert (s.loadUint(8) == SCCP_CODEC_CANONICAL_TEXT) throw SccpErrors.BadPayload;
    assert (s.loadUint(16) == SCCP_ASSET_ID_XOR_LEN) throw SccpErrors.BadPayload;
    assert (s.loadUint(24) == SCCP_ASSET_ID_XOR) throw SccpErrors.BadPayload;
    val amount = s.loadUint(128);
    assert ((amount != 0) & (amount < SCCP_TON_AMOUNT_LIMIT)) throw SccpErrors.BadPayload;
    assert (s.loadUint(8) == SCCP_CODEC_TAIRA_ACCOUNT) throw SccpErrors.BadPayload;
    val senderLen = s.loadUint(16);
    assert (
        (senderLen >= 1) & (senderLen <= SCCP_MAX_TAIRA_ACCOUNT_BYTES)
    ) throw SccpErrors.BadPayload;
    val offset = SCCP_INBOUND_PREFIX_BYTES + senderLen;
    assert (total == offset + SCCP_INBOUND_SUFFIX_BYTES) throw SccpErrors.BadPayload;
    val (index, within) = divMod(offset, SCCP_SNAKE_CHUNK_BYTES);
    var suffix = chunks.get(index);
    suffix.skipBits(within * 8);
    if (index + 1 < chunks.size()) {
        suffix = beginCell().storeSlice(suffix).storeSlice(chunks.get(index + 1)).toSlice();
    }
    assert (suffix.loadUint(8) == SCCP_CODEC_TON_ACCOUNT36) throw SccpErrors.BadPayload;
    assert (suffix.loadUint(16) == SCCP_TON_ACCOUNT36_LEN) throw SccpErrors.BadPayload;
    val workchain = suffix.loadUint(32);
    val recipientHash = suffix.loadUint(256);
    assert (suffix.loadUint(8) == SCCP_CODEC_CANONICAL_TEXT) throw SccpErrors.BadPayload;
    assert (suffix.loadUint(16) == SCCP_ROUTE_ID_TON_LEN) throw SccpErrors.BadPayload;
    assert (
        suffix.loadUint(SCCP_ROUTE_ID_TON_LEN * 8) == SCCP_ROUTE_ID_TON
    ) throw SccpErrors.BadPayload;
    // the recipient's own rules come last: everything else about the payload holds
    assert (
        (workchain == 0) & (recipientHash != 0) & (recipientHash != minterHash)
    ) throw SccpErrors.BadRecipient;
    return {
        nonce,
        deadlineMs,
        amount,
        recipientHash,
        payloadHash: sccpPayloadHash(chunks as tuple),
    };
}

/// A built TON→Taira payload.
struct OutboundPayload {
    /// Canonical `SnakeBytes`.
    cell: cell
    payloadHash: uint256
}

/// Builds the TON→Taira payload of a burn (§5.1.7): `dest_domain 0`,
/// `deadline_ms 0`, sender = `ton_account36` of the owner, recipient = the
/// validated `taira_account` chunks.
fun sccpBuildOutboundPayload(
    nonce: int,
    routeRevision: int,
    amount: int,
    ownerHash: int,
    recipientChunks: array<slice>,
    recipientLen: int,
): OutboundPayload {
    // kind … recipient_len: 98 bytes in the first chunk
    var w: SnakeWriter = {
        done: [],
        cur: beginCell()
            .storeUint(SCCP_PAYLOAD_KIND_TRANSFER, 8)
            .storeUint(SCCP_PAYLOAD_VERSION, 8)
            .storeUint(SCCP_DOMAIN_TON, 32)
            .storeUint(SCCP_DOMAIN_TAIRA, 32)
            .storeUint(nonce, 64)
            .storeUint(routeRevision, 32)
            .storeUint(0, 64)
            .storeUint(SCCP_DOMAIN_TAIRA, 32)
            .storeUint(SCCP_CODEC_CANONICAL_TEXT, 8)
            .storeUint(SCCP_ASSET_ID_XOR_LEN, 16)
            .storeUint(SCCP_ASSET_ID_XOR, 24)
            .storeUint(amount, 128)
            .storeUint(SCCP_CODEC_TON_ACCOUNT36, 8)
            .storeUint(SCCP_TON_ACCOUNT36_LEN, 16)
            .storeUint(0, 32)
            .storeUint(ownerHash, 256)
            .storeUint(SCCP_CODEC_TAIRA_ACCOUNT, 8)
            .storeUint(recipientLen, 16),
    };
    var i = 0;
    while (i < recipientChunks.size()) {
        w.writeSlice(recipientChunks.get(i));
        i += 1;
    }
    // route_id codec ‖ len ‖ "taira_ton_xor" (16 bytes)
    w.writeUint(
        (SCCP_CODEC_CANONICAL_TEXT << 120) | (SCCP_ROUTE_ID_TON_LEN << 104) | SCCP_ROUTE_ID_TON,
        16,
    );
    val chunks = w.chunks();
    return { cell: sccpSnakeCellFromChunks(chunks), payloadHash: sccpPayloadHash(chunks as tuple) };
}
