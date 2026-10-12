// The BLS layer of the SCCP v1 TON suite (specs/sccp.md §3.7, §3.8, §5.1.3,
// §5.3.4 item 5, §11.3, §11.4 item 4).
//
// - The test-side signer of `sccp-test-bls.tolk` reproduces the committed
//   fixtures byte for byte, so that scenario suites may certify any `X`.
// - The asm wrappers of `sccp-crypto.tolk` (SHA-256 over builders, `SDLEXCMP`
//   and `BLS_FASTAGGREGATEVERIFY`) are pinned: the hashes of the §11.2 worked
//   examples, the `DUP TLEN UNTUPLEVAR BLS_FASTAGGREGATEVERIFY` shape and the
//   opcode gas 58 000 + 3 000·q at n = 4, 7 and 31.
// - Every certificate row of `finality_v1.json` runs through `sccp_checkpoint`
//   on a fresh minter: the positive rows are accepted and published, and
//   every negative row that pins a TON outcome answers its exit code. The
//   w3f-transcript negative of `finality_rust_v1.json` is refused too.
//
// Each replay counts its rows and compares the count with a pinned number, so
// a regenerated fixture cannot shrink the coverage unnoticed.

import "@stdlib/strings"
import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/bench"
import "@acton/testing/expect"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-cert-vectors.gen"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Rows of `finality_v1.json` this suite replays. A regenerated fixture with
/// other counts fails here until the suite is reviewed against it.
const PINNED_CERTIFICATES = 13
const PINNED_NEGATIVE_CERTIFICATES = 54
/// Negative rows with `expected.ton`, and the rows TON cannot express.
const PINNED_NEGATIVES_WITH_TON_OUTCOME = 35
const PINNED_NEGATIVES_WITHOUT_TON_OUTCOME = 19
/// Negative rows that the opcode decides: `expected.ton = BadSignature`
/// without the identity signature, which the minter refuses before it.
const PINNED_NEGATIVES_DECIDED_BY_THE_OPCODE = 11
const PINNED_HASH_TO_G2_TRACES = 4
const PINNED_TEST_KEYS = 35

/// The 256-bit integer `value` as a slice of 32 bytes.
fun wordSlice(value: int): slice {
    return beginCell().storeUint(value, 256).endCell().beginParse();
}

/// The compressed identity of G2: `0xc0` followed by 95 zero bytes.
fun identitySignature(): slice {
    return beginCell()
        .storeUint(SCCP_IDENTITY_SIGNATURE_HEAD, 256)
        .storeUint(0, 256)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
}

/// `s` followed by one more byte.
fun withExtraByte(s: slice): slice {
    return beginCell().storeSlice(s).storeUint(0xAB, 8).endCell().beginParse();
}

/// The signed message `m = SHA-256(P)` that a verifier derives from the wire
/// fields of a certificate row (§3.7): `QC_FIXED` without `signers`, and
/// `X`. The row must have the canonical cell sizes.
fun derivedMessage(row: VecCertificate): slice {
    var qc = row.qc;
    val fields: TestQc = {
        epoch: qc.loadUint(64),
        epochContext: qc.loadUint(256),
        view: qc.loadUint(64),
        blockHash: qc.loadUint(256),
        resultBody: qc.loadUint(256),
    };
    var head = row.head;
    head.skipBits(SCCP_X_HEIGHT_OFFSET_BITS);
    val height = head.preloadUint(64);
    val r = sha256Parts(
        [
            beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
            row.head,
            row.tail,
            beginCell().storeUint(fields.resultBody, 256),
        ],
    );
    return voteMessage(SCCP_KIND_COMMIT, VEC_CONSENSUS_INSTANCE, height, fields, r);
}

/// The tuple `[k_1 … k_q, q, m, σ]` the minter builds for a certificate row:
/// the pinned keys of the set signer bits in ascending index order.
fun rowTuple(row: VecCertificate, m: slice): tuple {
    var t: tuple = [];
    var count = 0;
    var i = 0;
    repeat (row.pinKeys.size()) {
        if (((row.signers >> i) & 1) != 0) {
            t.push(row.pinKeys.get(i));
            count += 1;
        }
        i += 1;
    }
    t.push(count);
    t.push(m);
    t.push(row.signature);
    return t;
}

/// The tuple `[k_1 … k_q, q, m, σ]` of a positive certificate row, from the
/// test keys of its signers.
fun verifyTuple(row: int): tuple {
    val cert = vecCertificate(row);
    val facts = vecCertificateFacts(row);
    val publics = vecKeyPublics();
    var t: tuple = [];
    var i = 0;
    repeat (facts.signerIndices.size()) {
        t.push(publics.get(facts.committee.get(facts.signerIndices.get(i))));
        i += 1;
    }
    t.push(facts.signerIndices.size());
    t.push(facts.m);
    t.push(cert.signature);
    return t;
}

/// What the wrapper answers for `t`: 1 for true, 0 for false, and the
/// negated exit code when the opcode throws.
fun wrapperVerdict(t: tuple): int {
    try {
        return sccpBlsFastAggregateVerify(t) ? 1 : 0;
    } catch (code) {
        return 0 - code;
    }
}

/// The secret scalars of the signers of a positive certificate row.
fun signerSecrets(facts: VecCertificateFacts): array<int> {
    val secrets = vecKeySecrets();
    var result: array<int> = [];
    var i = 0;
    repeat (facts.signerIndices.size()) {
        result.push(secrets.get(facts.committee.get(facts.signerIndices.get(i))));
        i += 1;
    }
    return result;
}

// ---------------------------------------------------------------------------
// The test-side signer (`sccp-test-bls.tolk`).

get fun `test fixture tables have the pinned row counts`() {
    expect(VEC_CERTIFICATE_COUNT).toEqual(PINNED_CERTIFICATES);
    expect(VEC_NEGATIVE_CERTIFICATE_COUNT).toEqual(PINNED_NEGATIVE_CERTIFICATES);
    expect(VEC_HASH_TO_G2_COUNT).toEqual(PINNED_HASH_TO_G2_TRACES);
    expect(VEC_KEY_COUNT).toEqual(PINNED_TEST_KEYS);
    expect(vecKeySecrets().size()).toEqual(PINNED_TEST_KEYS);
    expect(vecKeyPublics().size()).toEqual(PINNED_TEST_KEYS);
    expect(
        PINNED_NEGATIVES_WITH_TON_OUTCOME + PINNED_NEGATIVES_WITHOUT_TON_OUTCOME,
    ).toEqual(PINNED_NEGATIVE_CERTIFICATES);
}

get fun `test signer reproduces the hash-to-G2 traces under DST_SIG`() {
    var row = 0;
    repeat (VEC_HASH_TO_G2_COUNT) {
        val trace = vecHashToG2(row);
        val blocks = blsExpandMessage(trace.m);
        expect(blocks.size()).toEqual(8);
        var i = 0;
        repeat (8) {
            expect(blocks.get(i)).toEqual(trace.blocks.get(i));
            i += 1;
        }
        val (u0, u1) = blsHashToField(trace.m);
        expect(u0.remainingBitsCount()).toEqual(768);
        expect(u0.bitsEqual(trace.u0)).toBeTrue();
        expect(u1.bitsEqual(trace.u1)).toBeTrue();
        expect(blsHashToG2(trace.m).bitsEqual(trace.q)).toBeTrue();
        row += 1;
    }
    expect(row).toEqual(PINNED_HASH_TO_G2_TRACES);
}

get fun `test field reduction handles the limb boundaries`() {
    // values below p are unchanged
    val (h0, l0) = blsReduceModP(0, 5);
    expect(h0).toEqual(0);
    expect(l0).toEqual(5);
    // p itself reduces to zero
    val (h1, l1) = blsReduceModP(BLS_P_HI, BLS_P_LO);
    expect(h1).toEqual(0);
    expect(l1).toEqual(0);
    // p − 1 stays, p + 1 becomes 1
    val (h2, l2) = blsReduceModP(BLS_P_HI, BLS_P_LO - 1);
    expect(h2).toEqual(BLS_P_HI);
    expect(l2).toEqual(BLS_P_LO - 1);
    val (h3, l3) = blsReduceModP(BLS_P_HI, BLS_P_LO + 1);
    expect(h3).toEqual(0);
    expect(l3).toEqual(1);
    // the largest 512-bit input stays below p after the reduction
    val (h4, l4) = blsReduceModP(BLS_LIMB_MAX, BLS_LIMB_MAX);
    expect((h4 < BLS_P_HI) | ((h4 == BLS_P_HI) & (l4 < BLS_P_LO))).toBeTrue();
    // a borrow across the limbs: 2^256 mod p = 2^256, and (p + 2^256 − 1) mod p
    val (h5, l5) = blsReduceModP(1, 0);
    expect(h5).toEqual(1);
    expect(l5).toEqual(0);
    val (h6, l6) = blsReduceModP(BLS_P_HI + 1, BLS_P_LO - 1);
    expect(h6).toEqual(0);
    expect(l6).toEqual(BLS_LIMB_MAX);
}

get fun `test aggregate secret is the sum modulo r`() {
    expect(blsAggregateSecret([])).toEqual(0);
    expect(blsAggregateSecret([5, 7])).toEqual(12);
    expect(blsAggregateSecret([BLS_SCALAR_ORDER - 1, 2])).toEqual(1);
    expect(blsAggregateSecret([BLS_SCALAR_ORDER - 1, BLS_SCALAR_ORDER - 1, 3])).toEqual(1);
}

get fun `test signer reproduces fixture signatures byte for byte`() {
    var row = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        val cert = vecCertificate(row);
        val facts = vecCertificateFacts(row);
        expect(blsHashToG2(facts.m).bitsEqual(facts.hashToG2)).toBeTrue();
        val signature = blsAggregateSign(signerSecrets(facts), facts.m);
        expect(signature.remainingBitsCount()).toEqual(SCCP_SIGNATURE_BITS);
        expect(signature.bitsEqual(cert.signature)).toBeTrue();
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
}

get fun `test a single signature and the aggregate agree`() {
    val facts = vecCertificateFacts(VEC_CERT_N4_LOWEST_Q);
    val secrets = signerSecrets(facts);
    var sum = blsSign(secrets.get(0), facts.m);
    sum = blsG2Add(sum, blsSign(secrets.get(1), facts.m));
    sum = blsG2Add(sum, blsSign(secrets.get(2), facts.m));
    expect(sum.bitsEqual(vecCertificate(VEC_CERT_N4_LOWEST_Q).signature)).toBeTrue();
}

get fun `test helper verification accepts exactly the signers of a fixture certificate`() {
    var row = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        val cert = vecCertificate(row);
        val facts = vecCertificateFacts(row);
        val committee = makeCommittee(facts.committee);
        expect(signatureVerifies(committee, cert.signers, facts.m, cert.signature)).toBeTrue();
        // the committee's own signing reproduces the fixture bytes
        val signed = blsAggregateSign(committee.secretsOf(cert.signers), facts.m);
        expect(signed.bitsEqual(cert.signature)).toBeTrue();
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
    val cert = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val facts = vecCertificateFacts(VEC_CERT_N4_LOWEST_Q);
    val committee = makeCommittee(facts.committee);
    expect(cert.signers).toEqual(committee.lowestSigners());
    // another signer set, another message and the empty set do not verify
    expect(
        signatureVerifies(committee, committee.highestSigners(), facts.m, cert.signature),
    ).toBeFalse();
    val other = vecCertificateFacts(VEC_CERT_N4_HIGHEST_Q);
    expect(signatureVerifies(committee, cert.signers, other.m, cert.signature)).toBeFalse();
    expect(signatureVerifies(committee, 0, facts.m, cert.signature)).toBeFalse();
}

get fun `test a certificate signed in the test vm is the one the committee would publish`() {
    // `certifyBy` over the fields of a fixture row gives the fixture cell
    val row = vecCertificate(VEC_CERT_N7_SCATTERED_Q);
    val facts = vecCertificateFacts(VEC_CERT_N7_SCATTERED_Q);
    val committee = makeCommittee(facts.committee);
    val message = derivedMessage(row);
    expect(message.bitsEqual(facts.m)).toBeTrue();
    val signature = blsAggregateSign(committee.secretsOf(row.signers), message);
    expect(
        certCell(signature, row.signers, row.qc, row.head, row.tail).hash(),
    ).toEqual(certCell(row.signature, row.signers, row.qc, row.head, row.tail).hash());
}

// ---------------------------------------------------------------------------
// Hash and comparison wrappers (`sccp-crypto.tolk`) and the committee rules.

get fun `test sha256 wrappers reproduce R, P and m of the worked examples`() {
    val r = sha256Parts(
        [
            beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
            vecXRotationHead(),
            vecXRotationTail(),
            beginCell().storeUint(VEC_X_D_BODY, 256),
        ],
    );
    expect(r).toEqual(VEC_X_ROTATION_R);
    expect(r).toEqual(VEC_COMMIT_R);
    expect(
        sha256Parts(
            [
                beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
                vecXHeartbeatHead(),
                vecXHeartbeatTail(),
                beginCell().storeUint(VEC_X_D_BODY, 256),
            ],
        ),
    ).toEqual(VEC_X_HEARTBEAT_R);
    expect(
        sha256Parts(
            [
                beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
                vecXNonRotationHead(),
                vecXNonRotationTail(),
                beginCell().storeUint(VEC_X_D_BODY, 256),
            ],
        ),
    ).toEqual(VEC_X_NON_ROTATION_R);
    expect(
        sha256Parts(
            [
                beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
                vecXInactiveHead(),
                vecXInactiveTail(),
                beginCell().storeUint(VEC_X_D_BODY, 256),
            ],
        ),
    ).toEqual(VEC_X_INACTIVE_R);
    // the 165-byte P spans two builders; m is a slice of exactly 256 bits
    val head = vecCommitPreimageHead();
    val tail = vecCommitPreimageTail();
    expect(
        (head.remainingBitsCount() + tail.remainingBitsCount()) / 8,
    ).toEqual(VEC_COMMIT_PREIMAGE_BYTES);
    val m = sha256PartsToSlice([head, tail]);
    expect(m.remainingBitsCount()).toEqual(256);
    expect(m.remainingRefsCount()).toEqual(0);
    expect(m.bitsEqual(wordSlice(VEC_COMMIT_M))).toBeTrue();
    expect(sha256Parts([head, tail])).toEqual(VEC_COMMIT_M);
    // the helpers build the same preimage from the fields
    val qc: TestQc = {
        epoch: VEC_COMMIT_EPOCH,
        epochContext: VEC_COMMIT_EPOCH_CONTEXT,
        view: VEC_COMMIT_VIEW,
        blockHash: VEC_COMMIT_BLOCK_HASH,
        resultBody: VEC_X_D_BODY,
    };
    val built = voteMessage(
        SCCP_KIND_COMMIT,
        VEC_COMMIT_INSTANCE,
        VEC_COMMIT_HEIGHT,
        qc,
        VEC_COMMIT_R,
    );
    expect(built.bitsEqual(wordSlice(VEC_COMMIT_M))).toBeTrue();
    // QC_FIXED is 116 bytes: the 112 bytes of the cell and the `signers` word
    val qcCell = vecQcFixedCell();
    expect(qcCell.remainingBitsCount()).toEqual(SCCP_QC_FIXED_CELL_BITS);
    expect(SCCP_QC_FIXED_CELL_BITS / 8 + 4).toEqual(VEC_QC_FIXED_BYTES);
    expect(qc.toCell().beginParse().bitsEqual(qcCell)).toBeTrue();
}

get fun `test the signed message of every positive row derives from its wire fields`() {
    var row = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        val cert = vecCertificate(row);
        val facts = vecCertificateFacts(row);
        // R as the contract computes it: tag, the two X slices, result_body
        var qc = cert.qc;
        qc.skipBits(64 + 256 + 64 + 256);
        expect(
            sha256Parts(
                [
                    beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
                    cert.head,
                    cert.tail,
                    qc,
                ],
            ),
        ).toEqual(facts.r);
        expect(derivedMessage(cert).bitsEqual(facts.m)).toBeTrue();
        expect(sccpCheckpointId(cert.head, cert.tail)).toEqual(facts.id);
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
}

get fun `test checkpoint ids and the committee root of the worked examples`() {
    expect(sccpCheckpointId(vecXRotationHead(), vecXRotationTail())).toEqual(VEC_X_ROTATION_ID);
    expect(sccpCheckpointId(vecXHeartbeatHead(), vecXHeartbeatTail())).toEqual(VEC_X_HEARTBEAT_ID);
    expect(sccpCheckpointId(vecXNonRotationHead(), vecXNonRotationTail())).toEqual(
        VEC_X_NON_ROTATION_ID,
    );
    expect(vecXRotationHead().remainingBitsCount()).toEqual(SCCP_X_HEAD_BITS);
    expect(vecXRotationTail().remainingBitsCount()).toEqual(SCCP_X_TAIL_BITS);
    expect((SCCP_X_HEAD_BITS + SCCP_X_TAIL_BITS) / 8).toEqual(VEC_X_BYTES);
    // the split of X and the tags of §3.6 and §3.7, as the fixture states them
    expect(SCCP_X_HEAD_BITS).toEqual(VEC_X_HEAD_BYTES * 8);
    expect(SCCP_X_TAIL_BITS).toEqual(VEC_X_TAIL_BYTES * 8);
    expect(SCCP_X_MAGIC).toEqual(VEC_X_MAGIC);
    expect(SCCP_RESULT_TAG).toEqual(VEC_RESULT_TAG);
    expect(SCCP_SIG_TAG).toEqual(VEC_SIG_TAG);
    expect(SCCP_TAG_COMMITTEE_V1).toEqual(VEC_COMMITTEE_TAG);
    val keys = vecSyntheticCommitteeKeys();
    expect(sccpCommitteeRoot(4, sccpLoadKeys(sccpBuildKeys(keys), 4).parts)).toEqual(
        VEC_SYNTHETIC_COMMITTEE_ROOT,
    );
}

get fun `test committees of the fixtures are the canonical order of their test keys`() {
    val n4 = makeCommittee([0, 1, 2, 3]);
    expect(n4.root()).toEqual(VEC_COMMITTEE_N4_ROOT);
    val publics = vecKeyPublics();
    val order = vecCommitteeN4();
    var i = 0;
    repeat (4) {
        expect(n4.keys.get(i).bitsEqual(publics.get(order.get(i)))).toBeTrue();
        i += 1;
    }
    expect(makeCommittee(vecCommitteeN7()).root()).toEqual(VEC_COMMITTEE_N7_ROOT);
    expect(makeCommittee(vecCommitteeN31()).root()).toEqual(VEC_COMMITTEE_N31_ROOT);
    expect(makeCommittee(vecCommitteeN4Other()).root()).toEqual(VEC_COMMITTEE_N4_OTHER_ROOT);
    expect(testCommittee(7, 0).root()).toEqual(VEC_COMMITTEE_N7_ROOT);
    expect(testCommittee(31, 0).root()).toEqual(VEC_COMMITTEE_N31_ROOT);
    expect(testCommittee(4, 0).q()).toEqual(3);
    expect(testCommittee(4, 0).lowestSigners()).toEqual(7);
    expect(testCommittee(4, 0).highestSigners()).toEqual(14);
    expect(testCommittee(31, 0).q()).toEqual(21);
    // 31 keys fill 15 chunks of two keys and one chunk of one key
    var chunks = 0;
    var chunk = testCommittee(31, 0).keysCell().beginParse();
    var more = true;
    while (more) {
        chunks += 1;
        more = chunk.remainingRefsCount() == 1;
        if (more) {
            expect(chunk.remainingBitsCount()).toEqual(SCCP_KEYS_PER_CHUNK * SCCP_KEY_BITS + 1);
            chunk = chunk.preloadRef().beginParse();
        }
    }
    expect(chunks).toEqual(SCCP_MAX_KEY_CHUNKS);
    expect(chunk.remainingBitsCount()).toEqual(SCCP_KEY_BITS + 1);
}

get fun `test lexicographic comparison orders compressed keys`() {
    val low = "000102".hexToSlice();
    val high = "000103".hexToSlice();
    expect(sccpLexCompare(low, high)).toEqual(-1);
    expect(sccpLexCompare(high, low)).toEqual(1);
    expect(sccpLexCompare(low, low)).toEqual(0);
    // a prefix sorts first, and the comparison is unsigned
    expect(sccpLexCompare("0001".hexToSlice(), low)).toEqual(-1);
    expect(sccpLexCompare("7f".hexToSlice(), "80".hexToSlice())).toEqual(-1);

    val committee = testCommittee(7, 0);
    expect(sccpKeysAscend(committee.keys)).toBeTrue();
    expect(sccpKeysAscend([])).toBeTrue();
    expect(sccpKeysAscend([committee.keys.get(3)])).toBeTrue();
    // a swapped pair and a duplicate are not strictly ascending
    expect(sccpKeysAscend([committee.keys.get(1), committee.keys.get(0)])).toBeFalse();
    expect(sccpKeysAscend([committee.keys.get(0), committee.keys.get(0)])).toBeFalse();
    var swapped = committee.keys;
    swapped.set(committee.keys.get(6), 5);
    swapped.set(committee.keys.get(5), 6);
    expect(sccpKeysAscend(swapped)).toBeFalse();
}

get fun `test quorum, committee sizes and signer bitmaps`() {
    // q = n − f with f = (n − 1)/3
    expect(sccpQuorum(4)).toEqual(3);
    expect(sccpQuorum(7)).toEqual(5);
    expect(sccpQuorum(10)).toEqual(7);
    expect(sccpQuorum(31)).toEqual(21);
    var sizes = 0;
    var n = 0;
    while (n <= 40) {
        if (sccpIsCommitteeSize(n)) {
            expect((n - 1) % 3).toEqual(0);
            expect(sccpQuorum(n)).toEqual(2 * ((n - 1) / 3) + 1);
            sizes += 1;
        }
        n += 1;
    }
    // 4, 7, …, 31
    expect(sizes).toEqual(10);
    expect(sccpIsCommitteeSize(1)).toBeFalse();
    expect(sccpIsCommitteeSize(3)).toBeFalse();
    expect(sccpIsCommitteeSize(5)).toBeFalse();
    expect(sccpIsCommitteeSize(32)).toBeFalse();
    expect(sccpIsCommitteeSize(34)).toBeFalse();

    expect(sccpPopCount(0)).toEqual(0);
    expect(sccpPopCount(1)).toEqual(1);
    expect(sccpPopCount(0x7fffffff)).toEqual(31);
    expect(sccpPopCount(0xffffffff)).toEqual(32);
    // §3.7: n = 31, indices {0, 9, 30} are `signers = 0x40000201`
    expect(VEC_QC_FIXED_SIGNERS).toEqual((1 << 0) | (1 << 9) | (1 << 30));
    expect(sccpPopCount(VEC_QC_FIXED_SIGNERS)).toEqual(3);
    // the signer word of every positive row names exactly q members of its committee
    var row = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        val cert = vecCertificate(row);
        val facts = vecCertificateFacts(row);
        val size = cert.pinKeys.size();
        expect(sccpIsCommitteeSize(size)).toBeTrue();
        expect(cert.signers >> size).toEqual(0);
        expect(sccpPopCount(cert.signers)).toEqual(sccpQuorum(size));
        var bitmap = 0;
        var i = 0;
        repeat (facts.signerIndices.size()) {
            bitmap |= 1 << facts.signerIndices.get(i);
            i += 1;
        }
        expect(bitmap).toEqual(cert.signers);
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
}

get fun `test the identity signature is recognised by all of its 96 bytes`() {
    expect(sccpIsIdentitySignature(identitySignature())).toBeTrue();
    expect(identitySignature().remainingBitsCount()).toEqual(SCCP_SIGNATURE_BITS);
    expect(
        identitySignature().bitsEqual(vecNegativeCertificate(VEC_NEG_SIGMA_ZERO).signature),
    ).toBeTrue();
    // one other bit anywhere is another encoding
    val lastBit = beginCell()
        .storeUint(SCCP_IDENTITY_SIGNATURE_HEAD, 256)
        .storeUint(0, 256)
        .storeUint(1, 256)
        .endCell()
        .beginParse();
    expect(sccpIsIdentitySignature(lastBit)).toBeFalse();
    val middleBit = beginCell()
        .storeUint(SCCP_IDENTITY_SIGNATURE_HEAD, 256)
        .storeUint(1 << 255, 256)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
    expect(sccpIsIdentitySignature(middleBit)).toBeFalse();
    // without the compression flag, and all zero bytes
    val uncompressed = beginCell()
        .storeUint(1 << 254, 256)
        .storeUint(0, 256)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
    expect(sccpIsIdentitySignature(uncompressed)).toBeFalse();
    val zero = beginCell()
        .storeUint(0, 256)
        .storeUint(0, 256)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
    expect(sccpIsIdentitySignature(zero)).toBeFalse();
    var row = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        expect(sccpIsIdentitySignature(vecCertificate(row).signature)).toBeFalse();
        row += 1;
    }
}

// ---------------------------------------------------------------------------
// `BLS_FASTAGGREGATEVERIFY` through the contract's wrapper.

get fun `test bls wrapper verifies fixture certificates at n=4, 7 and 31`() {
    var row = 0;
    var sizes = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        expect(sccpBlsFastAggregateVerify(verifyTuple(row))).toBeTrue();
        // the tuple the minter builds from the pinned keys is the same
        val cert = vecCertificate(row);
        expect(wrapperVerdict(rowTuple(cert, vecCertificateFacts(row).m))).toEqual(1);
        sizes |= 1 << cert.pinKeys.size();
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
    expect(sizes).toEqual((1 << 4) | (1 << 7) | (1 << 31));
}

get fun `test bls wrapper refuses another message, signature or signer set`() {
    val cert = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val facts = vecCertificateFacts(VEC_CERT_N4_LOWEST_Q);
    val publics = vecKeyPublics();
    val k0 = publics.get(facts.committee.get(0));
    val k1 = publics.get(facts.committee.get(1));
    val k2 = publics.get(facts.committee.get(2));
    val k3 = publics.get(facts.committee.get(3));
    val t0: tuple = [
        k0,
        k1,
        k2,
        3,
        facts.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t0)).toBeTrue();
    val other = vecCertificateFacts(VEC_CERT_N4_HIGHEST_Q);
    val t1: tuple = [
        k0,
        k1,
        k2,
        3,
        other.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t1)).toBeFalse();
    val t2: tuple = [
        k0,
        k1,
        k3,
        3,
        facts.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t2)).toBeFalse();
    val t3: tuple = [
        k0,
        k1,
        k2,
        3,
        facts.m,
        vecCertificate(VEC_CERT_N4_HIGHEST_Q).signature,
    ];
    expect(sccpBlsFastAggregateVerify(t3)).toBeFalse();
    // a superset and a subset of the signers, and one key twice
    val t4: tuple = [
        k0,
        k1,
        k2,
        k3,
        4,
        facts.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t4)).toBeFalse();
    val t5: tuple = [k0, k1, 2, facts.m, cert.signature];
    expect(sccpBlsFastAggregateVerify(t5)).toBeFalse();
    val t6: tuple = [
        k0,
        k0,
        k1,
        k2,
        4,
        facts.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t6)).toBeFalse();
    // the aggregate does not depend on the key order
    val t7: tuple = [
        k2,
        k0,
        k1,
        3,
        facts.m,
        cert.signature,
    ];
    expect(sccpBlsFastAggregateVerify(t7)).toBeTrue();
}

get fun `test a tuple of another shape never verifies`() {
    val cert = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val facts = vecCertificateFacts(VEC_CERT_N4_LOWEST_Q);
    val publics = vecKeyPublics();
    val k0 = publics.get(facts.committee.get(0));
    val k1 = publics.get(facts.committee.get(1));
    val k2 = publics.get(facts.committee.get(2));
    val genuine: tuple = [
        k0,
        k1,
        k2,
        3,
        facts.m,
        cert.signature,
    ];
    expect(wrapperVerdict(genuine)).toEqual(1);
    // a key count that differs from the keys, no key, and σ before m
    val fewer: tuple = [
        k0,
        k1,
        k2,
        2,
        facts.m,
        cert.signature,
    ];
    expect(wrapperVerdict(fewer) < 1).toBeTrue();
    val more: tuple = [
        k0,
        k1,
        k2,
        4,
        facts.m,
        cert.signature,
    ];
    expect(wrapperVerdict(more) < 0).toBeTrue();
    val none: tuple = [0, facts.m, cert.signature];
    expect(wrapperVerdict(none)).toEqual(0);
    val swapped: tuple = [
        k0,
        k1,
        k2,
        3,
        cert.signature,
        facts.m,
    ];
    expect(wrapperVerdict(swapped) < 0).toBeTrue();
    // the opcode hashes the whole message slice
    val longMessage: tuple = [
        k0,
        k1,
        k2,
        3,
        withExtraByte(facts.m),
        cert.signature,
    ];
    expect(wrapperVerdict(longMessage)).toEqual(0);
    // a signature shorter than 96 bytes cannot be read
    val shortSignature: tuple = [
        k0,
        k1,
        k2,
        3,
        facts.m,
        cert.signature.getFirstBits(760),
    ];
    expect(wrapperVerdict(shortSignature) < 0).toBeTrue();
}

get fun `test the opcode reads only the first bytes of longer key and signature slices`() {
    // This is why the minter loads keys as exactly 384 bits and requires a
    // `TairaCert` root of exactly 800 bits (§5.3.4 item 4).
    val cert = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val facts = vecCertificateFacts(VEC_CERT_N4_LOWEST_Q);
    val publics = vecKeyPublics();
    val k0 = publics.get(facts.committee.get(0));
    val k1 = publics.get(facts.committee.get(1));
    val k2 = publics.get(facts.committee.get(2));
    val longSignature: tuple = [
        k0,
        k1,
        k2,
        3,
        facts.m,
        withExtraByte(cert.signature),
    ];
    expect(wrapperVerdict(longSignature)).toEqual(1);
    val longKey: tuple = [
        withExtraByte(k0),
        k1,
        k2,
        3,
        facts.m,
        cert.signature,
    ];
    expect(wrapperVerdict(longKey)).toEqual(1);

    // the minter refuses the 97-byte signature by the size of the root cell
    val env = vecDeployCertificate(cert);
    val long = certCell(withExtraByte(cert.signature), cert.signers, cert.qc, cert.head, cert.tail);
    val res = replayCheckpoint(env, long, null);
    expectOutcome(res, SccpErrors.BadCertificate);
    expectEvents(res, []);
    // and every key it stores has exactly 384 bits
    val stored = sccpLoadKeys(env.minter.getSccpCommittee().keys, 4);
    var i = 0;
    repeat (4) {
        expect(stored.keys.get(i).remainingBitsCount()).toEqual(SCCP_KEY_BITS);
        expect(stored.keys.get(i).remainingRefsCount()).toEqual(0);
        i += 1;
    }
}

/// The last four words of TASM text, oldest first, each as its ASCII bytes
/// read as a big-endian integer. White space and the braces of nested
/// continuations separate words; a word longer than 31 bytes keeps its last
/// 31 bytes.
fun lastFourWords(text: string): (int, int, int, int) {
    var a = 0;
    var b = 0;
    var c = 0;
    var d = 0;
    var word = 0;
    var snake = text.beginParse();
    var more = true;
    while (more) {
        repeat (snake.remainingBitsCount() / 8) {
            val byte = snake.loadUint(8);
            if ((byte <= 32) | (byte == 123) | (byte == 125)) {
                if (word != 0) {
                    a = b;
                    b = c;
                    c = d;
                    d = word;
                    word = 0;
                }
            } else {
                word = ((word << 8) | byte) & ((1 << 248) - 1);
            }
        }
        more = snake.remainingRefsCount() != 0;
        if (more) {
            snake = snake.loadRef().beginParse();
        }
    }
    if (word != 0) {
        a = b;
        b = c;
        c = d;
        d = word;
    }
    return (a, b, c, d);
}

/// Checks one wrapper call over a fixture certificate with `q` signers.
///
/// The measured callback ends with the wrapper, so the last four instructions
/// of its TASM are the pinned shape `DUP TLEN UNTUPLEVAR
/// BLS_FASTAGGREGATEVERIFY` (§5.3.4 item 5). The instruction profile holds
/// exactly one `BLS_FASTAGGREGATEVERIFY`, which costs 58 000 + 3 000·q gas,
/// and one `UNTUPLEVAR`.
fun expectWrapperProfile(profile: BenchResult<bool>, n: int, q: int) {
    expect(profile.result).toBeTrue();
    val (dup, tlen, untuple, verify) = lastFourWords(profile.asmCode);
    expect(dup).toEqual("DUP".toBase256());
    expect(tlen).toEqual("TLEN".toBase256());
    expect(untuple).toEqual("UNTUPLEVAR".toBase256());
    expect(verify).toEqual("BLS_FASTAGGREGATEVERIFY".toBase256());
    var verifies = 0;
    var unpacks = 0;
    var entry = profile.instructions.findFirst();
    while (entry.isFound) {
        val info = entry.loadValue();
        if (info.name.equalTo("BLS_FASTAGGREGATEVERIFY")) {
            expect(info.count).toEqual(1);
            // the opcode price of §5.3.4 item 5 plus the 34 gas of any 24-bit instruction
            val price = 58000 + 3000 * q + 34;
            expect(info.totalGas).toEqual(price);
            reportGas(
                StringBuilder.create().append("BLS_FASTAGGREGATEVERIFY n=").appendInt(n).build(),
                info.totalGas,
                price,
            );
            verifies += 1;
        }
        if (info.name.equalTo("UNTUPLEVAR")) {
            // the wrapper unpacks its tuple once; building the tuple uses no UNTUPLEVAR
            expect(info.count).toEqual(1);
            unpacks += 1;
        }
        entry = profile.instructions.iterateNext(entry);
    }
    expect(verifies).toEqual(1);
    expect(unpacks).toEqual(1);
}

get fun `test bls wrapper stack shape and opcode gas at n=4, 7 and 31`() {
    expectWrapperProfile(
        bench.measure(
            "fast aggregate verify n=4",
            fun() {
                return sccpBlsFastAggregateVerify(verifyTuple(VEC_CERT_N4_LOWEST_Q));
            },
        ),
        4,
        3,
    );
    expectWrapperProfile(
        bench.measure(
            "fast aggregate verify n=7",
            fun() {
                return sccpBlsFastAggregateVerify(verifyTuple(VEC_CERT_N7_LOWEST_Q));
            },
        ),
        7,
        5,
    );
    expectWrapperProfile(
        bench.measure(
            "fast aggregate verify n=31",
            fun() {
                return sccpBlsFastAggregateVerify(verifyTuple(VEC_CERT_N31_LOWEST_Q));
            },
        ),
        31,
        21,
    );
    // the tuple has q + 3 entries, at most 24
    expect(verifyTuple(VEC_CERT_N4_LOWEST_Q).size()).toEqual(3 + 3);
    expect(verifyTuple(VEC_CERT_N7_LOWEST_Q).size()).toEqual(5 + 3);
    expect(verifyTuple(VEC_CERT_N31_LOWEST_Q).size()).toEqual(21 + 3);
    // the last four words of a text are found across white space and braces
    val (
        a,
        b,
        c,
        d,
    ) = lastFourWords("NOP\n  PUSHCONT {\n    DUP\n    TLEN\n  }\n UNTUPLEVAR X }\n");
    expect(a).toEqual("DUP".toBase256());
    expect(b).toEqual("TLEN".toBase256());
    expect(c).toEqual("UNTUPLEVAR".toBase256());
    expect(d).toEqual("X".toBase256());
}

get fun `test the opcode refuses signer keys that are no valid G1 keys`() {
    // §5.3.4 item 5: the opcode's result is the minter's only verdict on the
    // keys. Each row pins the exact key bytes under its own committee root.
    val rows: array<int> = [
        // a signer key with the infinity flag and one without the compression flag
        VEC_NEG_KEY_FLAG_INFINITY_0XC0,
        VEC_NEG_KEY_FLAG_UNCOMPRESSED,
        // x ≥ p, and x = 0, which is on no point of the curve
        VEC_NEG_SIGNER_X_GE_P,
        VEC_NEG_SIGNER_ZERO_COORDINATES,
        // a point of the curve outside G1 with the genuine signature
        VEC_NEG_SIGNER_KEY_OUTSIDE_G1,
        // two keys outside G1 whose sum is the genuine aggregate: the opcode
        // checks every key, where an EVM destination sees the aggregate only
        VEC_NEG_SIGNER_KEYS_OUTSIDE_G1_CANCELLING,
        // three keys that sum to the identity
        VEC_NEG_AGGREGATE_KEY_IDENTITY,
        VEC_NEG_AGGREGATE_KEY_IDENTITY_SIGMA_OFF_CURVE,
    ];
    var i = 0;
    repeat (rows.size()) {
        val row = vecNegativeCertificate(rows.get(i));
        expect(wrapperVerdict(rowTuple(row, derivedMessage(row)))).toEqual(0);
        i += 1;
    }
    expect(i).toEqual(8);
    // the identity key alone, with the identity signature: e(O, H(m)) = e(g1, O)
    // holds, and the opcode still answers false
    val cancelling = vecNegativeCertificate(VEC_NEG_AGGREGATE_KEY_IDENTITY);
    val message = derivedMessage(cancelling);
    val identityKey = beginCell()
        .storeUint(0xc0, 8)
        .storeUint(0, 120)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
    expect(identityKey.remainingBitsCount()).toEqual(SCCP_KEY_BITS);
    val onlyIdentity: tuple = [identityKey, 1, message, identitySignature()];
    expect(wrapperVerdict(onlyIdentity)).toEqual(0);
    var identityAggregate = rowTuple(cancelling, message);
    identityAggregate.set(identitySignature(), identityAggregate.size() - 1);
    expect(wrapperVerdict(identityAggregate)).toEqual(0);
    // the genuine keys of the same committee verify the genuine certificate
    expect(wrapperVerdict(verifyTuple(VEC_CERT_N4_LOWEST_Q))).toEqual(1);
}

// ---------------------------------------------------------------------------
// Certificate rows through `sccp_checkpoint` (§11.3).

get fun `test every positive certificate row is accepted, published and stored`() {
    var row = 0;
    var maxGas4 = 0;
    var maxGas7 = 0;
    var maxGas31 = 0;
    repeat (VEC_CERTIFICATE_COUNT) {
        val cert = vecCertificate(row);
        val facts = vecCertificateFacts(row);
        expect(cert.exit).toEqual(0);
        expect(cert.initChecked).toBeTrue();
        val env = vecDeployCertificate(cert);
        val isRotation = (facts.flags & SCCP_X_FLAG_ROTATION) != 0;
        var nextKeys: cell? = null;
        if (facts.nextCommittee.size() > 0) {
            nextKeys = makeCommittee(facts.nextCommittee).keysCell();
        }
        val res = vecSubmitCertificate(env, cert, nextKeys);
        expectOutcome(res, 0);
        // the full path publishes the certificate first (§5.1.3 step 12)
        val body = certCell(cert.signature, cert.signers, cert.qc, cert.head, cert.tail);
        var events: array<cell> = [
            eventCertificate(facts.height, facts.generation, body),
            eventCheckpointed(facts.height, facts.id),
        ];
        val untilMs = min(facts.timestampMs, cert.nowSeconds * 1000) + facts.validityMs;
        if (isRotation) {
            events.push(
                eventRotated(
                    facts.generation + 1,
                    facts.nextCommitteeRoot,
                    untilMs,
                    facts.height + 1,
                ),
            );
        }
        expectEvents(res, events);
        replayExpectCheckpoints(
            env,
            1,
            facts.height,
            facts.id,
            0,
            0,
            0,
            0,
        );
        val state = env.minter.getSccpState();
        expect(state.high).toEqual(facts.height);
        expect(state.opCount).toEqual(0);
        expect(state.equivocated).toBeFalse();
        if (isRotation) {
            expect(state.generation).toEqual(facts.generation + 1);
            expect(state.root).toEqual(facts.nextCommitteeRoot);
            expect(state.start).toEqual(facts.height + 1);
            expect(state.untilMs).toEqual(untilMs);
            if (facts.nextCommittee.size() > 0) {
                replayExpectKeys(env, makeCommittee(facts.nextCommittee).keys);
            } else {
                // a heartbeat keeps the stored keys
                replayExpectKeys(env, cert.pinKeys);
            }
        } else {
            expect(state.generation).toEqual(cert.pin.generation);
            expect(state.root).toEqual(cert.pin.root);
            expect(state.start).toEqual(cert.pin.start);
            expect(state.untilMs).toEqual(cert.pin.untilMs);
            replayExpectKeys(env, cert.pinKeys);
            // stored: the cheap path, and nothing left to do
            val again = vecSubmitCertificate(env, cert, null);
            expectOutcome(again, SccpErrors.NothingToDo);
            expectEvents(again, []);
        }
        val gas = stepGas(res);
        expect(gas <= SCCP_GAS_MINTER_CHECKPOINT).toBeTrue();
        // the opcode alone costs 58 000 + 3 000·q
        expect(gas > 58000 + 3000 * sccpQuorum(cert.pinKeys.size())).toBeTrue();
        if (!isRotation) {
            if (cert.pinKeys.size() == 4) {
                maxGas4 = max(maxGas4, gas);
            }
            if (cert.pinKeys.size() == 7) {
                maxGas7 = max(maxGas7, gas);
            }
            if (cert.pinKeys.size() == 31) {
                maxGas31 = max(maxGas31, gas);
            }
        }
        if (row == VEC_CERT_KEY_CHANGE_ROTATION) {
            reportGas("checkpoint key-change rotation n=4", gas, SCCP_GAS_MINTER_CHECKPOINT);
        }
        if (row == VEC_CERT_HEARTBEAT_ROTATION) {
            reportGas("checkpoint heartbeat rotation n=4", gas, SCCP_GAS_MINTER_CHECKPOINT);
        }
        row += 1;
    }
    expect(row).toEqual(PINNED_CERTIFICATES);
    reportGas("checkpoint n=4", maxGas4, SCCP_GAS_MINTER_CHECKPOINT);
    reportGas("checkpoint n=7", maxGas7, SCCP_GAS_MINTER_CHECKPOINT);
    reportGas("checkpoint n=31", maxGas31, SCCP_GAS_MINTER_CHECKPOINT);
}

get fun `test every negative certificate row with a TON outcome answers its exit code`() {
    var row = 0;
    var pinned = 0;
    var unpinned = 0;
    var decidedByTheOpcode = 0;
    repeat (VEC_NEGATIVE_CERTIFICATE_COUNT) {
        val cert = vecNegativeCertificate(row);
        if (cert.exit == VEC_EXIT_UNPINNED) {
            // the row is one that TON cannot express (`expected.ton` is null)
            unpinned += 1;
        } else {
            expect(cert.exit != 0).toBeTrue();
            val env = vecDeployCertificate(cert);
            val res = vecSubmitCertificate(env, cert, null);
            if (outcomeOf(res) != cert.exit) {
                println("row {} expected {} observed {}", row, cert.exit, outcomeOf(res));
            }
            expectOutcome(res, cert.exit);
            // a refused certificate publishes nothing and changes nothing
            expectEvents(res, []);
            replayExpectCheckpoints(
                env,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            val state = env.minter.getSccpState();
            expect(state.high).toEqual(cert.pin.start - 1);
            expect(state.generation).toEqual(cert.pin.generation);
            expect(state.untilMs).toEqual(cert.pin.untilMs);
            expect(state.equivocated).toBeFalse();
            // BadSignature is the opcode's verdict, except for the identity
            // signature, which the minter refuses before it
            var byTheOpcode = false;
            if (cert.exit == SccpErrors.BadSignature as int) {
                byTheOpcode = !sccpIsIdentitySignature(cert.signature);
            }
            if (byTheOpcode) {
                expect(wrapperVerdict(rowTuple(cert, derivedMessage(cert)))).toEqual(0);
                // a refused signature costs the whole opcode: nothing is skipped
                expect(stepGas(res) > 58000).toBeTrue();
                decidedByTheOpcode += 1;
            } else {
                // every other refusal comes before any signature work
                expect(stepGas(res) < 58000).toBeTrue();
            }
            pinned += 1;
        }
        row += 1;
    }
    expect(row).toEqual(PINNED_NEGATIVE_CERTIFICATES);
    expect(pinned).toEqual(PINNED_NEGATIVES_WITH_TON_OUTCOME);
    expect(unpinned).toEqual(PINNED_NEGATIVES_WITHOUT_TON_OUTCOME);
    expect(decidedByTheOpcode).toEqual(PINNED_NEGATIVES_DECIDED_BY_THE_OPCODE);
}

get fun `test the identity signature is refused before the opcode and before the cheap path`() {
    val cert = vecNegativeCertificate(VEC_NEG_SIGMA_ZERO);
    expect(cert.exit).toEqual(SccpErrors.BadSignature as int);
    expect(sccpIsIdentitySignature(cert.signature)).toBeTrue();
    val env = vecDeployCertificate(cert);
    val res = vecSubmitCertificate(env, cert, null);
    expectOutcome(res, SccpErrors.BadSignature);
    expect(stepGas(res) < 58000).toBeTrue();
    // with X stored the cheap path would skip the opcode; the identity is refused all the same
    var head = cert.head;
    head.skipBits(SCCP_X_HEIGHT_OFFSET_BITS);
    val height = head.preloadUint(64);
    val id = sccpCheckpointId(cert.head, cert.tail);
    seedCheckpointId(env, height, id);
    val stored = vecSubmitCertificate(env, cert, null);
    expectOutcome(stored, SccpErrors.BadSignature);
    expectEvents(stored, []);
    expect(env.minter.getSccpState().high).toEqual(cert.pin.start - 1);
    // Any other signature over the stored X is not checked and not published.
    // The seeded checkpoint did not raise `high`, so the certificate still
    // changes something; replayed, it has nothing left to do.
    val other = certCell(
        vecCertificate(VEC_CERT_N4_LOWEST_Q).signature,
        cert.signers,
        cert.qc,
        cert.head,
        cert.tail,
    );
    val cheap = replayCheckpoint(env, other, null);
    expectOutcome(cheap, 0);
    expectEvents(cheap, []);
    expect(stepGas(cheap) < 58000).toBeTrue();
    expect(env.minter.getSccpState().high).toEqual(height);
    replayExpectCheckpoints(
        env,
        1,
        height,
        id,
        0,
        0,
        0,
        0,
    );
    val again = replayCheckpoint(env, other, null);
    expectOutcome(again, SccpErrors.NothingToDo);
    expect(stepGas(again) < 58000).toBeTrue();
}

get fun `test the minter answers BadSignature for stored keys the opcode refuses`() {
    // The fixtures pin no TON outcome for these rows until a harness confirms
    // the reading of §5.3.4 item 5 (`error_choices.
    // ton_signer_key_refused_by_the_opcode`). This is that confirmation: a
    // stored signer key that is no canonical point, is the identity or lies
    // outside G1, and an identity aggregate, are all `BadSignature`.
    val rows: array<int> = [
        VEC_NEG_KEY_FLAG_INFINITY_0XC0,
        VEC_NEG_KEY_FLAG_UNCOMPRESSED,
        VEC_NEG_SIGNER_X_GE_P,
        VEC_NEG_SIGNER_ZERO_COORDINATES,
        VEC_NEG_AGGREGATE_KEY_IDENTITY_SIGMA_OFF_CURVE,
        VEC_NEG_SIGNER_KEYS_OUTSIDE_G1_CANCELLING,
    ];
    var i = 0;
    repeat (rows.size()) {
        val cert = vecNegativeCertificate(rows.get(i));
        expect(cert.exit).toEqual(VEC_EXIT_UNPINNED);
        val env = vecDeployCertificate(cert);
        val res = vecSubmitCertificate(env, cert, null);
        expectOutcome(res, SccpErrors.BadSignature);
        expectEvents(res, []);
        replayExpectCheckpoints(
            env,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        // the verdict is the opcode's: the minter ran no key check of its own
        expect(stepGas(res) > 58000).toBeTrue();
        i += 1;
    }
    expect(i).toEqual(6);
    // the two rows the fixtures do pin for stored keys agree
    expect(
        vecNegativeCertificate(VEC_NEG_SIGNER_KEY_OUTSIDE_G1).exit,
    ).toEqual(SccpErrors.BadSignature as int);
    expect(
        vecNegativeCertificate(VEC_NEG_AGGREGATE_KEY_IDENTITY).exit,
    ).toEqual(SccpErrors.BadSignature as int);
}

/// The negative certificate of `fixtures/sccp/finality_rust_v1.json`
/// (`w3f_transcript_over_commit_digest`) in its TON form: a full quorum of
/// the n = 4 test committee signs the commit digest `m` through the generic
/// signing API of `iroha_crypto` (the w3f transcript) instead of the
/// consensus API. Every other field is genuine. Its pin, keys and clock are
/// those of the n = 4 rows of `finality_v1.json`.
// TODO: WP-TON (builder): render this row from the fixture file in
// `sccp-cert-vectors.gen.tolk` (`scripts/ton_sccp_builder.py vectors`), so
// that its drift check covers it; the bytes below are copied from the
// committed fixture.
fun rustNegativeCertificate(): VecCertificate {
    val shared = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    return {
        pin: shared.pin,
        pinKeys: shared.pinKeys,
        initChecked: true,
        initSeconds: shared.initSeconds,
        nowSeconds: 1790003600,
        signature: "8b4c2927f65ef62d69f2ebc8bc765ca2abb937d7aa9ba28370549490090327ec5f0d2ee9873fe0f849f36dce8b1eca3a0aa29d3a884a9af4e177a094eb471cbeccf4168dc21528671824cbee92f0dfb4e2247d684f6fd759cac02b79fab02379".hexToSlice(),
        signers: 7,
        qc: "000000000000004a709d7555624c623af6785e6f5dc826d4bc9e231669dae79ebab9a3aefe8829d70000000000000000b69a5d2d3b7bd773aa4ad767a2ebfc27ce7f785d7dbc9a0ca9b92d0e037b4597e4f0a268e11599cfe9840eb442dc9ccaedf53af9cb16053d097ae31a0c361d97".hexToSlice(),
        head: "534343502f46494e414c4954592f563111111111111111111111111111111111111111111111111111111111111111110000000000001ce8000001a0c456868001000000027140b2fe9dbb189037d7c21b676b42cb07c6492d46ea3d9eeb9cfccce4be4ab20000000000000028".hexToSlice(),
        tail: "1c9e4dc240ef4c4c99bdca794e0c649a45754ac755151f8f16961e78907c52ff000000000000000710c02431ff3976732e1b3d2b3f6cc4e488acf60e1fb31094be0a72a855afdc1400000000000000000000000000000000000000000000000000000000000000000000000000000000".hexToSlice(),
        exit: SccpErrors.BadSignature as int,
    };
}

/// `m` and `checkpoint_id` of the row above, as the fixture records them.
const RUST_NEGATIVE_M = 0xa42132a3adb5c5d258d1d8dfe399bd96aaa46506e0fcf2416c4d913c93c445f5
const RUST_NEGATIVE_CHECKPOINT_ID = 0xf949c4c2af8d966d31f7e17ce3e12e3709d677394b4094b0dc0a0109cffa873a
/// Rows of `finality_rust_v1.json`.
const PINNED_RUST_NEGATIVE_CERTIFICATES = 1

get fun `test a w3f transcript signature over the commit digest is refused`() {
    var replayed = 0;
    val cert = rustNegativeCertificate();
    // the row is of the n = 4 deployment of the other rows, and well formed
    expect(cert.pin.root).toEqual(VEC_COMMITTEE_N4_ROOT);
    expect(cert.pin.generation).toEqual(7);
    expect(cert.pin.start).toEqual(7000);
    expect(cert.pin.untilMs).toEqual(1791209600000);
    expect(cert.signature.remainingBitsCount()).toEqual(SCCP_SIGNATURE_BITS);
    expect(cert.qc.remainingBitsCount()).toEqual(SCCP_QC_FIXED_CELL_BITS);
    expect(sccpCheckpointId(cert.head, cert.tail)).toEqual(RUST_NEGATIVE_CHECKPOINT_ID);
    val message = derivedMessage(cert);
    expect(message.bitsEqual(wordSlice(RUST_NEGATIVE_M))).toBeTrue();
    // the same signers under the consensus API give another signature, which verifies
    val committee = makeCommittee(vecCommitteeN4());
    val consensus = blsAggregateSign(committee.secretsOf(cert.signers), message);
    expect(consensus.bitsEqual(cert.signature)).toBeFalse();
    expect(wrapperVerdict(rowTuple(cert, message))).toEqual(0);
    var genuine = rowTuple(cert, message);
    genuine.set(consensus, genuine.size() - 1);
    expect(wrapperVerdict(genuine)).toEqual(1);

    val env = vecDeployCertificate(cert);
    val res = vecSubmitCertificate(env, cert, null);
    expectOutcome(res, cert.exit);
    expectEvents(res, []);
    replayExpectCheckpoints(
        env,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    replayed += 1;
    // the pairing check is the only step the foreign transcript fails
    val accepted = replayCheckpoint(
        env,
        certCell(consensus, cert.signers, cert.qc, cert.head, cert.tail),
        null,
    );
    expectOutcome(accepted, 0);
    replayExpectCheckpoints(
        env,
        1,
        7400,
        RUST_NEGATIVE_CHECKPOINT_ID,
        0,
        0,
        0,
        0,
    );
    expect(replayed).toEqual(PINNED_RUST_NEGATIVE_CERTIFICATES);
}
