// Finality of the SCCP v1 TON minter: the finality header `X` (§3.6),
// committees and their root (§3.7), the destination verification relation
// over Taira's Sumeragi `CommitQC` (§3.8, §5.1.3, §5.3.4), the three
// checkpoint slots (§5.1.3) and the predicates of the committee state machine
// (§5.1.2).
//
// A certificate is one BLS12-381 min-pk aggregate of exactly `q = n − f`
// signers of the current generation. Its keys come from storage, and the
// single verdict on keys, aggregate and signature is the native
// `BLS_FASTAGGREGATEVERIFY` opcode. Nothing here changes state: the minter
// applies the outcome (a checkpoint, a raised `high`, a rotation or a latch)
// and sends the events.

import "@stdlib/exotic-cells"
import "sccp-cells"
import "sccp-constants"
import "sccp-crypto"
import "sccp-errors"
import "sccp-storage"

// ---------------------------------------------------------------------------
// Committees (§3.7, §3.8).

/// `q = n − f` with `f = (n − 1)/3` (§3.8 step 1).
@pure
fun sccpQuorum(n: int): int {
    return n - (n - 1) / 3;
}

/// The committee size rule: `n ∈ {4, 7, …, 31}`.
@pure
fun sccpIsCommitteeSize(n: int): bool {
    return (n >= SCCP_MIN_COMMITTEE_SIZE) & (n <= SCCP_MAX_COMMITTEE_SIZE) & ((n - 1) % 3 == 0);
}

/// `committee_root(C) = keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ PK_0 ‖ … ‖
/// PK_{n−1})` (§3.7). `parts` are the data-only key bits of the `KeyChunk`s
/// in order (`ParsedKeys.parts`), so the keys are never copied.
fun sccpCommitteeRoot(n: int, parts: array<slice>): uint256 {
    var preimage: tuple = [];
    preimage.push(
        beginCell().storeUint(SCCP_TAG_COMMITTEE_V1, SCCP_TAG_COMMITTEE_V1_BITS).storeUint(n, 8),
    );
    var i = 0;
    val size = parts.size();
    while (i < size) {
        preimage.push(parts.get(i));
        i += 1;
    }
    return keccak256Parts(preimage);
}

/// True iff the compressed keys are strictly ascending as byte strings
/// (`SDLEXCMP`), the canonical order of §3.7. Strict order excludes duplicates.
@inline_ref
fun sccpKeysAscend(keys: array<slice>): bool {
    var i = 1;
    val size = keys.size();
    while (i < size) {
        if (sccpLexCompare(keys.get(i - 1), keys.get(i)) != -1) {
            return false;
        }
        i += 1;
    }
    return true;
}

/// Requires that `n` parsed keys are a committee with root `root`: a valid
/// size, strictly ascending keys and the keccak committee root (§3.7). Throws
/// `BadCommittee`. The keys are not checked as curve points: their validity
/// rests on Taira's admission and on the root (§3.8).
@inline_ref
fun sccpRequireCommittee(parsed: ParsedKeys, n: int, root: int) {
    assert (sccpIsCommitteeSize(n)) throw SccpErrors.BadCommittee;
    assert (sccpKeysAscend(parsed.keys)) throw SccpErrors.BadCommittee;
    assert (sccpCommitteeRoot(n, parsed.parts) == root) throw SccpErrors.BadCommittee;
}

/// The stored committee of `sccp_init` (§5.3.1): `n` is a committee size
/// (`BadCommittee`), `keys` is the canonical list of exactly `n` keys
/// (`BadSnake`), and the keys are strictly ascending with root `root`
/// (`BadCommittee`).
fun sccpRequireStoredCommittee(keys: cell, n: int, root: int) {
    assert (sccpIsCommitteeSize(n)) throw SccpErrors.BadCommittee;
    sccpRequireCommittee(sccpLoadKeys(keys, n), n, root);
}

/// The `next_keys` of a key-changing rotation (§5.1.2 update 3): the list is
/// required and must hold a valid `n` of strictly ascending keys whose
/// committee root is `nextRoot`. Returns `n`. A missing list, an invalid size
/// or order and another root throw `BadCommittee`; a non-canonical list
/// throws `BadSnake`. The caller asks only when `X.next_committee_root ≠
/// cur.root`: at a heartbeat the stored keys are kept and `next_keys` is not
/// read.
fun sccpRequireSuccessorKeys(nextKeys: cell?, nextRoot: int): int {
    assert (nextKeys != null) throw SccpErrors.BadCommittee;
    val (parsed, n) = sccpLoadKeysCounted(nextKeys);
    sccpRequireCommittee(parsed, n, nextRoot);
    return n;
}

// ---------------------------------------------------------------------------
// Finality header `X` (§3.6).

/// The fields of a finality header that satisfies X1–X7 with `ACTIVE` set,
/// and its checkpoint id. `magic` is checked and `network_id` is returned
/// beside the header by `sccpReadActiveX`.
struct XHeader {
    height: uint64
    timestampMs: uint64
    flags: uint8
    messageCount: uint32
    sccpRoot: uint256
    historySize: uint64
    historyRoot: uint256
    generation: uint64
    committeeRoot: uint256
    validityMs: uint64
    nextCommitteeRoot: uint256
    /// `checkpoint_id(X) = keccak256(X)`.
    id: uint256
}

/// True iff `ROTATION` is set: `X` ends its generation and names the successor.
@pure
fun XHeader.isRotation(self): bool {
    return (self.flags & SCCP_X_FLAG_ROTATION) != 0;
}

/// Opens `^XHead` and its `^XTail` and returns their data bits,
/// `X[0..109)` and `X[109..221)`. Both cells must be ordinary (`BadSnake`)
/// and hold exactly 872 bits with one reference and 896 bits with none: any
/// other shape is an `X` of another length (`BadHeader`, §5.1.3 step 1).
@inline_ref
fun sccpOpenX(x: cell): (slice, slice) {
    val head = sccpBeginParseOrdinary(x);
    assert (
        (head.remainingBitsCount() == SCCP_X_HEAD_BITS) & (head.remainingRefsCount() == 1)
    ) throw SccpErrors.BadHeader;
    val tail = sccpBeginParseOrdinary(head.preloadRef());
    assert (
        (tail.remainingBitsCount() == SCCP_X_TAIL_BITS) & (tail.remainingRefsCount() == 0)
    ) throw SccpErrors.BadHeader;
    return (head.preloadBits(SCCP_X_HEAD_BITS), tail);
}

/// `checkpoint_id(X) = keccak256(X)` over the two byte slices of `X`
/// (`2 PUSHINT 3 HASHEXT`, §5.3.4 item 3).
@pure
fun sccpCheckpointId(headBytes: slice, tailBytes: slice): uint256 {
    return keccak256Slices2(headBytes, tailBytes);
}

/// Reads `X` from its two byte slices and enforces X1–X7 with `ACTIVE` set
/// (§3.6), in the order X1, `ACTIVE`, X3, X4, X5, X6, X7. Every violation is
/// `BadHeader`; an inactive `X` is refused whether or not it satisfies X2.
/// `id` is `sccpCheckpointId` of the same slices. Returns the header and
/// `X.network_id`, which the caller compares when the header is not already
/// authenticated by a stored checkpoint.
@inline_ref
fun sccpReadActiveX(headBytes: slice, tailBytes: slice, id: int): (XHeader, int) {
    var head = headBytes;
    val magic = head.loadUint(128);
    val networkId = head.loadUint(256);
    val height = head.loadUint(64);
    val timestampMs = head.loadUint(64);
    val flags = head.loadUint(8);
    val messageCount = head.loadUint(32);
    val sccpRoot = head.loadUint(256);
    val historySize = head.loadUint(64);
    var tail = tailBytes;
    val historyRoot = tail.loadUint(256);
    val generation = tail.loadUint(64);
    val committeeRoot = tail.loadUint(256);
    val validityMs = tail.loadUint(64);
    val nextCommitteeRoot = tail.loadUint(256);

    // X1
    assert (
        (magic == SCCP_X_MAGIC) & ((flags & SCCP_X_FLAGS_RESERVED) == 0)
    ) throw SccpErrors.BadHeader;
    // destinations reject the inactive form
    assert ((flags & SCCP_X_FLAG_ACTIVE) != 0) throw SccpErrors.BadHeader;
    // X3
    assert ((generation >= 1) & (committeeRoot != 0)) throw SccpErrors.BadHeader;
    // X4
    assert (
        ((messageCount == 0) == (sccpRoot == 0)) & (messageCount <= SCCP_MAX_BLOCK_LEAVES)
    ) throw SccpErrors.BadHeader;
    // X5
    assert (
        ((historySize == 0) == (historyRoot == 0)) & (historySize <= SCCP_MAX_HISTORY_SIZE)
    ) throw SccpErrors.BadHeader;
    // X6: the successor starts at height + 1 as generation + 1, both u64 values
    if ((flags & SCCP_X_FLAG_ROTATION) != 0) {
        assert (
            (nextCommitteeRoot != 0) & (validityMs >= 1) & (validityMs <= SCCP_MAX_VALIDITY_MS) &
            (height <= SCCP_MAX_ROTATION_FIELD) &
            (generation <= SCCP_MAX_ROTATION_FIELD)
        ) throw SccpErrors.BadHeader;
    } else {
        assert ((nextCommitteeRoot == 0) & (validityMs == 0)) throw SccpErrors.BadHeader;
    }
    // X7
    assert (height >= 1) throw SccpErrors.BadHeader;

    val header: XHeader = {
        height,
        timestampMs,
        flags,
        messageCount,
        sccpRoot,
        historySize,
        historyRoot,
        generation,
        committeeRoot,
        validityMs,
        nextCommitteeRoot,
        id,
    };
    return (header, networkId);
}

/// Parses the `X` of a certificate for this deployment (§5.1.3 steps 1 and
/// 2): the cell shapes (`BadSnake`, `BadHeader`), X1–X7 with `ACTIVE` and
/// `X.network_id = tairaNetworkId` (`BadHeader`). There is no skew check.
/// Returns the header and the byte slices `X[0..109)` and `X[109..221)`.
fun sccpParseX(x: cell, tairaNetworkId: int): (XHeader, slice, slice) {
    val (headBytes, tailBytes) = sccpOpenX(x);
    val (header, networkId) = sccpReadActiveX(
        headBytes,
        tailBytes,
        sccpCheckpointId(headBytes, tailBytes),
    );
    assert (networkId == tairaNetworkId) throw SccpErrors.BadHeader;
    return (header, headBytes, tailBytes);
}

// ---------------------------------------------------------------------------
// Checkpoints (§5.1.3): three slots `(height, id)`.

/// The stored checkpoints in ascending height order. Heights are at least 1
/// (X7), and a slot at or above `count` holds height 0 and id 0.
struct Checkpoints {
    count: int
    h0: int
    id0: int
    h1: int
    id1: int
    h2: int
    id2: int
}

/// Reads the `^Checkpoints` cell of the minter storage.
@inline_ref
fun Checkpoints.load(c: cell): Checkpoints {
    var s = c.beginParse();
    val count = s.loadUint(2);
    var cps: Checkpoints = {
        count,
        h0: 0,
        id0: 0,
        h1: 0,
        id1: 0,
        h2: 0,
        id2: 0,
    };
    if (count > 0) {
        cps.h0 = s.loadUint(64);
        cps.id0 = s.loadUint(256);
    }
    if (count > 1) {
        cps.h1 = s.loadUint(64);
        cps.id1 = s.loadUint(256);
    }
    if (count > 2) {
        cps.h2 = s.loadUint(64);
        cps.id2 = s.loadUint(256);
    }
    return cps;
}

/// True iff `c` is the `^Checkpoints` cell of the canonical initial data
/// (§5.3.1): an ordinary cell of exactly the two bits `count = 0`.
@inline
fun Checkpoints.isCanonicalEmpty(c: cell): bool {
    val (s, isExotic) = c.beginParseSpecial();
    if (isExotic | (s.remainingBitsCount() != 2) | (s.remainingRefsCount() != 0)) {
        return false;
    }
    return s.preloadUint(2) == 0;
}

/// The id stored at `height`, or 0 when the height holds no checkpoint.
@pure
@inline_ref
fun Checkpoints.find(self, height: int): int {
    if (height == 0) {
        return 0;
    }
    if (height == self.h0) {
        return self.id0;
    }
    if (height == self.h1) {
        return self.id1;
    }
    if (height == self.h2) {
        return self.id2;
    }
    return 0;
}

/// Records `(height, id)` and returns whether it was recorded (§5.1.3). A
/// height that is already present is never overwritten. With a free slot the
/// entry is added; with three stored it enters only above the lowest stored
/// height, which it evicts. `height` is at least 1.
@inline_ref
fun Checkpoints.insert(mutate self, height: int, id: int): bool {
    if ((height == self.h0) | (height == self.h1) | (height == self.h2)) {
        return false;
    }
    if (self.count == SCCP_CHECKPOINT_SLOTS) {
        if (height < self.h0) {
            return false;
        }
        self.h0 = self.h1;
        self.id0 = self.id1;
        self.h1 = self.h2;
        self.id1 = self.id2;
        self.count = SCCP_CHECKPOINT_SLOTS - 1;
    }
    // the entries below `count` stay in ascending height order
    if ((self.count == 2) & (height > self.h1)) {
        self.h2 = height;
        self.id2 = id;
    } else {
        if (self.count == 2) {
            self.h2 = self.h1;
            self.id2 = self.id1;
        }
        if ((self.count >= 1) & (height > self.h0)) {
            self.h1 = height;
            self.id1 = id;
        } else {
            if (self.count >= 1) {
                self.h1 = self.h0;
                self.id1 = self.id0;
            }
            self.h0 = height;
            self.id0 = id;
        }
    }
    self.count += 1;
    return true;
}

/// Serializes the `^Checkpoints` cell: `count:uint2` then `count × (height:uint64
/// id:bits256)` in ascending height order.
@inline_ref
fun Checkpoints.toCell(self): cell {
    var b = beginCell().storeUint(self.count, 2);
    if (self.count > 0) {
        b.storeUint(self.h0, 64).storeUint(self.id0, 256);
    }
    if (self.count > 1) {
        b.storeUint(self.h1, 64).storeUint(self.id1, 256);
    }
    if (self.count > 2) {
        b.storeUint(self.h2, 64).storeUint(self.id2, 256);
    }
    return b.endCell();
}

// ---------------------------------------------------------------------------
// Certificate verification (§5.1.3, §5.3.4).

/// A certified header and how it was certified.
struct VerifiedX {
    x: XHeader
    /// True when the signature was verified in this call: the caller then
    /// publishes the certificate with `sccp_certificate` (§5.1.3 step 12).
    /// False on the cheap path, where `X` is already stored.
    fullPath: bool
}

/// Number of set bits of a nonnegative integer.
@pure
fun sccpPopCount(bits: int): int {
    var rest = bits;
    var count = 0;
    while (rest != 0) {
        rest &= rest - 1;
        count += 1;
    }
    return count;
}

/// True iff `signature` (768 bits) is the compressed identity of G2: `0xc0`
/// followed by 95 zero bytes (§5.1.3 step 6).
@pure
fun sccpIsIdentitySignature(signature: slice): bool {
    var s = signature;
    val a = s.loadUint(256);
    val b = s.loadUint(256);
    val c = s.loadUint(256);
    return (a == SCCP_IDENTITY_SIGNATURE_HEAD) & (b == 0) & (c == 0);
}

/// `VerifyCertificate(cert)` steps 1–11 of §5.1.3 for TON, in order; the
/// first failure is the call's error:
///
/// 1. Exact lengths, as cell shapes: `QcFixed` (`BadCertificate`), `XHead`
///    and `XTail` (`BadHeader`), then the 800-bit root with the 96-byte
///    signature (`BadCertificate`). An exotic cell is `BadSnake`.
/// 2. X1–X7, `ACTIVE` and `X.network_id = tairaNetworkId` (`BadHeader`).
/// 3. CUR: `X.generation = cur.generation` and `X.committee_root = cur.root`
///    (`CommitteeNotAccepted`), before any signature work.
/// 5. `signers >> n = 0` and `popcount(signers) = q(n)` (`BadCertificate`).
/// 6. The identity signature is refused (`BadSignature`) here, before the
///    cheap path, which never reaches the opcode.
/// 7. `id = keccak256(X)`.
/// 8. Cheap path (mandatory): `checkpoint[X.height] = id` skips steps 9–12.
/// 9. `R = SHA-256(RESULT_TAG ‖ X ‖ result_body)` and `m = SHA-256(P)`, with
///    `P = "sumeragi/sig" ‖ 0x03 ‖ I ‖ be64(epoch) ‖ epoch_context ‖
///    be64(X.height) ‖ be64(view) ‖ block_hash ‖ R` (165 bytes in two
///    builders). `m` is a slice of exactly 256 bits.
/// 10–11. The keys of the set signer bits, read from the stored `KeyChunk`s
///    as 384-bit slices in ascending index order, then `q`, `m` and `σ` form
///    the tuple of `sccpBlsFastAggregateVerify`. Its result is the only
///    verdict on keys, aggregate and signature: false is `BadSignature`.
///
/// `committee` is the current generation, whose stored key list was checked
/// when it was installed, and `instance` is Taira's consensus instance `I`.
/// Nothing is recorded: the caller publishes the certificate when `fullPath`
/// is set (step 12), evaluates `sccpViolation` (step 13) and acts.
@inline_ref
fun sccpVerifyCertificate(
    cert: cell,
    tairaNetworkId: int,
    instance: int,
    committee: CommitteeState,
    cps: Checkpoints,
): VerifiedX {
    // 1. exact lengths: QC_FIXED, X, signature
    var root = sccpBeginParseOrdinary(cert);
    assert (root.remainingRefsCount() == 2) throw SccpErrors.BadCertificate;
    var qc = sccpBeginParseOrdinary(root.loadRef());
    assert (
        (qc.remainingBitsCount() == SCCP_QC_FIXED_CELL_BITS) & (qc.remainingRefsCount() == 0)
    ) throw SccpErrors.BadCertificate;
    val (headBytes, tailBytes) = sccpOpenX(root.loadRef());
    assert (root.remainingBitsCount() == SCCP_TAIRA_CERT_BITS) throw SccpErrors.BadCertificate;

    // 2. X1–X7, ACTIVE, network; 7. the checkpoint id
    val (x, networkId) = sccpReadActiveX(
        headBytes,
        tailBytes,
        sccpCheckpointId(headBytes, tailBytes),
    );
    assert (networkId == tairaNetworkId) throw SccpErrors.BadHeader;

    // 3. only a certificate of the current generation goes on
    assert (
        (x.generation == committee.generation) & (x.committeeRoot == committee.root)
    ) throw SccpErrors.CommitteeNotAccepted;

    // 5. no spare signer bit and exactly q signers
    val signature = root.loadBits(SCCP_SIGNATURE_BITS);
    val signers = root.loadUint(32);
    val q = sccpQuorum(committee.n);
    assert ((signers >> committee.n) == 0) throw SccpErrors.BadCertificate;
    assert (sccpPopCount(signers) == q) throw SccpErrors.BadCertificate;

    // 6. the identity signature, before the cheap path
    assert (!sccpIsIdentitySignature(signature)) throw SccpErrors.BadSignature;

    // 8. cheap path: X is stored, so it is already certified
    val stored = cps.find(x.height);
    if ((stored != 0) & (stored == x.id)) {
        return { x, fullPath: false };
    }

    // 9. R and m
    val epochAndContext = qc.loadBits(64 + 256);
    val view = qc.loadBits(64);
    val blockHash = qc.loadBits(256);
    val r = sha256Parts(
        [beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS), headBytes, tailBytes, qc],
    );
    val m = sha256PartsToSlice(
        [
            beginCell()
                .storeUint(SCCP_SIG_TAG, SCCP_SIG_TAG_BITS)
                .storeUint(SCCP_KIND_COMMIT, 8)
                .storeUint(instance, 256)
                .storeSlice(epochAndContext)
                .storeUint(x.height, 64)
                .storeSlice(view),
            beginCell().storeSlice(blockHash).storeUint(r, 256),
        ],
    );

    // 10–11. signer keys in ascending index order, then q, m and σ; a chunk
    // holds the keys of two signer bits
    var t: tuple = [];
    var chunk = committee.keys.beginParse();
    var pending = signers;
    while (pending != 0) {
        if ((pending & 1) != 0) {
            t.push(chunk.preloadBits(SCCP_KEY_BITS));
        }
        if ((pending & 2) != 0) {
            t.push(chunk.getMiddleBits(SCCP_KEY_BITS, SCCP_KEY_BITS));
        }
        pending = pending >> SCCP_KEYS_PER_CHUNK;
        if (pending != 0) {
            chunk = chunk.preloadRef().beginParse();
        }
    }
    t.push(q);
    t.push(m);
    t.push(signature);
    assert (sccpBlsFastAggregateVerify(t)) throw SccpErrors.BadSignature;
    return { x, fullPath: true };
}

// ---------------------------------------------------------------------------
// Committee state machine predicates (§5.1.2).

/// `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.untilMs`. A minter that is not `Live`
/// is `Frozen`, permanently.
@pure
fun sccpIsLive(equivocated: bool, untilMs: int, nowMs: int): bool {
    return !equivocated & (nowMs <= untilMs);
}

/// The `Live` check of an entry point with its two answers: `Equivocated`
/// when the latch is set, `CommitteeNotAccepted` when only `cur.untilMs` has
/// passed.
fun sccpRequireLive(equivocated: bool, untilMs: int, nowMs: int) {
    assert (!equivocated) throw SccpErrors.Equivocated;
    assert (nowMs <= untilMs) throw SccpErrors.CommitteeNotAccepted;
}

/// Whether `sccp_init` at `nowMs` accepts the pinned `untilMs` (§5.3.1):
/// `now_ms < until_ms ≤ now_ms + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`,
/// compared as a difference so that the sum is never formed (§5.1.2
/// "Arithmetic"). The minter answers `BadConfig` otherwise.
@pure
fun sccpInitUntilMsIsValid(nowMs: int, untilMs: int): bool {
    return (nowMs < untilMs) & (untilMs - nowMs <= SCCP_MAX_VALIDITY_MS + SCCP_MAX_INIT_SLACK_MS);
}

/// The first of the violation predicates V1, V2, V3 that a verified CUR
/// header trips: `(reason, a, b)` with the fields of `sccp_latched`, or
/// `(0, 0, 0)` when there is none.
///
/// - V1 (`SCCP_LATCH_V1`): the checkpoint stored at `X.height` differs from
///   `keccak256(X)`; `a` is the stored id.
/// - V2 (`SCCP_LATCH_V2`): `X.height < cur.start`; `a = X.committee_root`.
/// - V3 (`SCCP_LATCH_V3`): `ROTATION` and `X.height < cur.high`; `a =
///   X.committee_root`.
///
/// `b` is `keccak256(X)`. `sccp_checkpoint` latches on a violation without
/// throwing; an inline entry point throws `LatchRequired` (§5.3.4 item 6).
@inline_ref
fun sccpViolation(x: XHeader, committee: CommitteeState, cps: Checkpoints): (int, int, int) {
    val stored = cps.find(x.height);
    if ((stored != 0) & (stored != x.id)) {
        return (SCCP_LATCH_V1, stored, x.id);
    }
    if (x.height < committee.start) {
        return (SCCP_LATCH_V2, x.committeeRoot, x.id);
    }
    if (x.isRotation() & (x.height < committee.high)) {
        return (SCCP_LATCH_V3, x.committeeRoot, x.id);
    }
    return (0, 0, 0);
}

/// `cur.untilMs` of the successor that the rotation `X` installs at `nowMs`
/// (§5.1.2 update 3): `min(t_eff(X) + X.validity_ms, 2^64 − 1)` with `t_eff(X)
/// = min(X.timestamp_ms, now_ms)`. The sum saturates, so a rotation never
/// aborts for arithmetic, and a future-dated rotation grants no more than
/// `validity_ms` from the minter's own clock.
@pure
fun sccpRotationUntilMs(x: XHeader, nowMs: int): int {
    return min(min(x.timestampMs, nowMs) + x.validityMs, SCCP_MAX_U64);
}

/// Whether a stored checkpoint header may be used by a `*_checkpoint` entry
/// point (§5.1.3 "Using a checkpoint"):
///
/// - U1: `X` is of the current generation (`X.generation = cur.generation`
///   and `X.committee_root = cur.root`); or
/// - U2: `X` is the handoff that installed `cur`: `ROTATION` is set,
///   `X.generation + 1 = cur.generation`, `X.height + 1 = cur.start` and
///   `X.next_committee_root = cur.root`.
///
/// U2 applies to checkpoint references only; it never makes a certificate CUR.
@pure
@inline
fun sccpCheckpointUsable(x: XHeader, committee: CommitteeState): bool {
    if ((x.generation == committee.generation) & (x.committeeRoot == committee.root)) {
        return true;
    }
    return x.isRotation() & (x.generation + 1 == committee.generation) &
        (x.height + 1 == committee.start) &
        (x.nextCommitteeRoot == committee.root);
}

/// The checkpoint use check of a `*_checkpoint` entry point (§5.1.3), in
/// order:
///
/// 1. `ref` is a `CheckpointRef` (`BadSnake`) whose `X` has 221 bytes
///    (`BadHeader`);
/// 2. `checkpoint[X.height] = keccak256(X) ≠ 0` (`UnknownCheckpoint`), which
///    also answers a checkpoint that was evicted;
/// 3. X1–X7 with `ACTIVE` (`BadHeader`); the stored id authenticates the
///    network of `X`;
/// 4. `Live` (`Equivocated` when latched, `CommitteeNotAccepted` when
///    expired);
/// 5. the header is usable under U1 or U2 (`CommitteeNotAccepted`).
///
/// Returns the header. Nothing changes: no checkpoint is recorded and `high`
/// does not rise.
fun sccpUseCheckpoint(
    ref: cell,
    equivocated: bool,
    committee: CommitteeState,
    cps: Checkpoints,
    nowMs: int,
): XHeader {
    val r = sccpBeginParseOrdinary(ref);
    assert (
        (r.remainingBitsCount() == 0) & (r.remainingRefsCount() == 1)
    ) throw SccpErrors.BadSnake;
    val (headBytes, tailBytes) = sccpOpenX(r.preloadRef());
    val id = sccpCheckpointId(headBytes, tailBytes);
    var heightBits = headBytes;
    heightBits.skipBits(SCCP_X_HEIGHT_OFFSET_BITS);
    assert (
        (id != 0) & (cps.find(heightBits.preloadUint(64)) == id)
    ) throw SccpErrors.UnknownCheckpoint;
    val (x, _) = sccpReadActiveX(headBytes, tailBytes, id);
    sccpRequireLive(equivocated, committee.untilMs, nowMs);
    assert (sccpCheckpointUsable(x, committee)) throw SccpErrors.CommitteeNotAccepted;
    return x;
}
