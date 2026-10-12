// Golden vectors: the asm wrappers of §5.3.7 (GLOBALID, BLS, HASHEXT
// keccak) and every §3 encoding against values computed by the independent
// Python implementation (`sccp-test-vectors.gen.tolk`), plus the canonical
// cell shapes of §5.3.2 and their negatives.

import "@stdlib/exotic-cells"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-verify"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

get fun `test globalid is ton mainnet in the emulator`() {
    expect(sccpGlobalId()).toEqual(SCCP_TON_GLOBAL_ID);
}

get fun `test keccak256 wrappers match ethereum keccak`() {
    expect(keccak256Parts([])).toEqual(
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470,
    );
    val abc = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45;
    expect(keccak256Builder(beginCell().storeUint(0x616263, 24))).toEqual(abc);
    expect(keccak256Parts(["a".literalSlice(), beginCell().storeUint(0x6263, 16)])).toEqual(abc);
    expect(
        keccak256Builders2(beginCell().storeUint(0x61, 8), beginCell().storeUint(0x6263, 16)),
    ).toEqual(abc);
}

get fun `test native aggregate verifies the selected committee`() {
    val committee = testCommittee(4, 0);
    val x = emptyX(VEC_NETWORK_ID, TEST_GENERATION, committee.root(), TEST_START_HEIGHT);
    val qc = defaultQc(x.height);
    val m = commitMessage(VEC_CONSENSUS_INSTANCE, qc, x);
    val signers = committee.lowestSigners();
    val signature = blsAggregateSign(committee.secretsOf(signers), m);
    expect(signatureVerifies(committee, signers, m, signature)).toBeTrue();
    expect(signatureVerifies(testCommittee(4, 4), signers, m, signature)).toBeFalse();
}

get fun `test native signature binds message and signer set`() {
    val committee = testCommittee(4, 0);
    val x = emptyX(VEC_NETWORK_ID, TEST_GENERATION, committee.root(), TEST_START_HEIGHT);
    val qc = defaultQc(x.height);
    val m = commitMessage(VEC_CONSENSUS_INSTANCE, qc, x);
    val signature = blsAggregateSign(committee.secretsOf(0b0111), m);
    expect(signatureVerifies(committee, 0b1110, m, signature)).toBeFalse();
    expect(
        signatureVerifies(
            committee,
            0b0111,
            commitMessage(VEC_CONSENSUS_INSTANCE ^ 1, qc, x),
            signature,
        ),
    ).toBeFalse();
}

get fun `test every native fixture key signs its matching public key`() {
    val m = beginCell().storeUint(0xA11CE, 256).endCell().beginParse();
    var i = 0;
    while (i < VEC_KEY_COUNT) {
        // Singleton is a primitive-signature test only, never an admitted committee.
        val key = makeCommittee([i]);
        val signature = blsAggregateSign(key.secretsOf(1), m);
        expect(signatureVerifies(key, 1, m, signature)).toBeTrue();
        i += 1;
    }
    expect(sccpKeysAscend(testCommittee(31, 0).keys)).toBeTrue();
}

get fun `test native certificate message binds X result and consensus instance`() {
    val committee = testCommittee(4, 0);
    val x = emptyX(VEC_NETWORK_ID, TEST_GENERATION, committee.root(), TEST_START_HEIGHT);
    val qc = defaultQc(x.height);
    val m = commitMessage(VEC_CONSENSUS_INSTANCE, qc, x);
    var changed = x;
    changed.networkId = changed.networkId ^ 1;
    expect(m.bitsEqual(commitMessage(VEC_CONSENSUS_INSTANCE, qc, changed))).toBeFalse();
    expect(m.bitsEqual(commitMessage(VEC_CONSENSUS_INSTANCE ^ 1, qc, x))).toBeFalse();
    var otherQc = qc;
    otherQc.resultBody = otherQc.resultBody ^ 1;
    expect(m.bitsEqual(commitMessage(VEC_CONSENSUS_INSTANCE, otherQc, x))).toBeFalse();
}

get fun `test committee roots and multiple key chunks`() {
    val sizes: array<int> = [4, 7, 31];
    var i = 0;
    while (i < sizes.size()) {
        val committee = testCommittee(sizes.get(i), 0);
        val parsed = sccpLoadKeys(committee.keysCell(), committee.n());
        expect(parsed.parts.size()).toEqual((committee.n() + 1) / 2);
        expect(parsed.keys.size()).toEqual(committee.n());
        var k = 0;
        while (k < committee.n()) {
            expect(parsed.keys.get(k).bitsEqual(committee.keys.get(k))).toBeTrue();
            k += 1;
        }
        expect(sccpCommitteeRoot(committee.n(), parsed.parts)).toEqual(committee.root());
        sccpRequireStoredCommittee(committee.keysCell(), committee.n(), committee.root());
        i += 1;
    }
}

get fun `test committee rejects invalid size order duplicates and root`() {
    val base = testCommittee(4, 0);
    val invalidSizes: array<int> = [0, 1, 3, 5, 32];
    var i = 0;
    while (i < invalidSizes.size()) {
        try {
            sccpRequireStoredCommittee(base.keysCell(), invalidSizes.get(i), base.root());
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadCommittee as int);
        }
        i += 1;
    }
    val k = base.keys;
    val orders: array<array<slice>> = [
        [k.get(1), k.get(0), k.get(2), k.get(3)],
        [k.get(0), k.get(0), k.get(2), k.get(3)],
    ];
    i = 0;
    while (i < orders.size()) {
        try {
            sccpRequireStoredCommittee(sccpBuildKeys(orders.get(i)), 4, base.root());
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadCommittee as int);
        }
        i += 1;
    }
    try {
        sccpRequireStoredCommittee(base.keysCell(), 4, base.root() ^ 1);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadCommittee as int);
    }
}

get fun `test key chunks reject non-canonical shapes`() {
    val k = testCommittee(4, 0).keys;
    // Four keys split 1+2+1 instead of 2+2.
    val last = beginCell().storeSlice(k.get(3)).storeMaybeRef(null).endCell();
    val middle = beginCell()
        .storeSlice(k.get(1))
        .storeSlice(k.get(2))
        .storeMaybeRef(last)
        .endCell();
    val short = beginCell().storeSlice(k.get(0)).storeMaybeRef(middle).endCell();
    // Canonical first chunk, trailing reference after the final two keys.
    val extra = beginCell()
        .storeSlice(k.get(2))
        .storeSlice(k.get(3))
        .storeMaybeRef(createEmptyCell())
        .endCell();
    val trailing = beginCell()
        .storeSlice(k.get(0))
        .storeSlice(k.get(1))
        .storeMaybeRef(extra)
        .endCell();
    val cases: array<cell> = [short, trailing];
    var i = 0;
    while (i < cases.size()) {
        try {
            sccpLoadKeys(cases.get(i), 4);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
}

/// Four keys in canonical 2+2 chunks, with a library-reference tail.
fun fourKeysWithLibraryTail(): cell {
    val k = testCommittee(4, 0).keys;
    val tail = beginCell().storeSlice(k.get(2)).storeSlice(k.get(3)).storeMaybeRef(null).endCell();
    testing.registerLibrary(tail);
    return beginCell()
        .storeSlice(k.get(0))
        .storeSlice(k.get(1))
        .storeMaybeRef(tail.toLibraryReference())
        .endCell();
}

get fun `test canonical parsers reject library cells with canonical content`() {
    // the ordinary encodings parse
    val members4 = testCommittee(4, 0).keysCell();
    expect(sccpLoadKeys(members4, 4).keys.size()).toEqual(4);
    val hashes: array<int> = [1, 2, 3, 4];
    val path = sccpBuildHashPath(hashes)!;
    expect(sccpLoadHashPath(path, 4, 9)).toEqual(hashes);
    val snake = snakeOfLength(200);
    expect(sccpParseSnakeBytes(snake, 4096, SccpErrors.BadPayload).1).toEqual(200);
    // a published library with the same content is refused at every depth
    testing.registerLibrary(members4);
    testing.registerLibrary(path);
    testing.registerLibrary(snake);
    val pathTail = path.beginParse().preloadRef();
    testing.registerLibrary(pathTail);
    val snakeTail = snake.beginParse().preloadRef();
    testing.registerLibrary(snakeTail);
    val memberCases: array<[cell, int]> = [
        [members4.toLibraryReference(), 4],
        [fourKeysWithLibraryTail(), 4],
    ];
    var i = 0;
    while (i < memberCases.size()) {
        val [c, n] = memberCases.get(i);
        try {
            sccpLoadKeys(c, n);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
    val pathCases: array<cell> = [
        path.toLibraryReference(),
        beginCell()
            .storeUint(1, 256)
            .storeUint(2, 256)
            .storeUint(3, 256)
            .storeMaybeRef(pathTail.toLibraryReference())
            .endCell(),
    ];
    i = 0;
    while (i < pathCases.size()) {
        try {
            sccpLoadHashPath(pathCases.get(i), 4, 9);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
    val snakeCases: array<cell> = [
        snake.toLibraryReference(),
        beginCell()
            .storeSlice(snake.beginParse().preloadBits(SCCP_SNAKE_CHUNK_BITS))
            .storeRef(snakeTail.toLibraryReference())
            .endCell(),
    ];
    i = 0;
    while (i < snakeCases.size()) {
        try {
            sccpParseSnakeBytes(snakeCases.get(i), 4096, SccpErrors.BadPayload);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
}

get fun `test control leaves for the ton target`() {
    var i = 0;
    while (i < VEC_CONTROL_LEAF_COUNT) {
        val c = vecControlLeaf(i);
        expect((c.b1.remainingBitsCount() + c.b2.remainingBitsCount()) / 8).toEqual(199);
        expect(keccak256Slices2(c.b1, c.b2)).toEqual(c.leaf);
        expect(
            sccpControlLeaf(
                VEC_NETWORK_ID,
                VEC_MINTER_ACCOUNT_ID,
                c.routeRevision,
                c.controlNonce,
                c.track,
                c.parliamentPaused,
                c.fastPauseUntilMs,
                c.certificateId,
                c.effectHash,
            ),
        ).toEqual(c.leaf);
        i += 1;
    }
}

get fun `test inbound payload hash, message id and transfer leaf`() {
    val payload = snakeFromPieces(vecInboundPayloadPieces());
    val parsed = sccpParseInboundPayload(payload, VEC_INBOUND_REVISION, 0x1234);
    expect(parsed.nonce).toEqual(VEC_INBOUND_NONCE);
    expect(parsed.deadlineMs).toEqual(VEC_INBOUND_DEADLINE_MS);
    expect(parsed.amount).toEqual(VEC_INBOUND_AMOUNT);
    expect(parsed.recipientHash).toEqual(VEC_INBOUND_RECIPIENT);
    expect(parsed.payloadHash).toEqual(VEC_INBOUND_PAYLOAD_HASH);
    val messageId = sccpInboundMessageId(VEC_NETWORK_ID, parsed.payloadHash);
    expect(messageId).toEqual(VEC_INBOUND_MESSAGE_ID);
    val destination = VEC_MINTER_ACCOUNT_ID;
    // The generated native payload row exports its independent message id.
    // Check the transfer domain and destination preimage using that exact id.
    val expectedLeaf = keccak256Builder(
        beginCell()
            .storeSlice("SCCP/LEAF/V1".literalSlice())
            .storeUint(VEC_INBOUND_MESSAGE_ID, 256)
            .storeUint(destination, 256),
    );
    expect(sccpTransferLeaf(messageId, destination)).toEqual(expectedLeaf);
    expect(sccpTransferLeaf(messageId, destination ^ 1)).toNotEqual(expectedLeaf);
}

get fun `test outbound payload of a burn`() {
    val recipient = snakeFromPieces(vecOutboundRecipientPieces());
    val (chunks, len) = sccpParseSnakeBytes(
        recipient,
        SCCP_MAX_TAIRA_ACCOUNT_BYTES,
        SccpErrors.BadRecipient,
    );
    expect(len).toEqual(35);
    val built = sccpBuildOutboundPayload(
        VEC_OUTBOUND_NONCE,
        VEC_OUTBOUND_REVISION,
        VEC_OUTBOUND_AMOUNT,
        VEC_OUTBOUND_SENDER,
        chunks,
        len,
    );
    expect(built.payloadHash).toEqual(VEC_OUTBOUND_PAYLOAD_HASH);
    expect(built.cell.hash()).toEqual(snakeFromPieces(vecOutboundPayloadPieces()).hash());
    expect(sccpOutboundMessageId(VEC_NETWORK_ID, built.payloadHash)).toEqual(
        VEC_OUTBOUND_MESSAGE_ID,
    );
}

get fun `test merkle roots, promoted nodes and history leaves`() {
    val fixtureLeaves = vecTreeLeaves();
    val leaves: array<int> = [
        fixtureLeaves.get(0),
        fixtureLeaves.get(1),
        fixtureLeaves.get(2),
        fixtureLeaves.get(3),
        fixtureLeaves.get(4),
    ];
    expect(treeRoot(leaves)).toEqual(vecTreeRoots().get(4));
    expect(treePath(leaves, 3)).toEqual(vecTree5Path(3));
    expect(treePath(leaves, 4)).toEqual(vecTree5Path(4));
    expect(sccpMerkleRoot(leaves.get(3), 3, 5, vecTree5Path(3))).toEqual(vecTreeRoots().get(4));
    expect(sccpMerkleRoot(leaves.get(4), 4, 5, vecTree5Path(4))).toEqual(vecTreeRoots().get(4));
    expect(sccpMerkleRoot(leaves.get(0), 0, 1, [])).toEqual(leaves.get(0));
    expect(
        sccpHistoryLeaf(VEC_HISTORY_HEIGHT, VEC_HISTORY_SCCP_ROOT, VEC_HISTORY_MESSAGE_COUNT),
    ).toEqual(VEC_HISTORY_LEAF);
    // every count 1..=17 and every index round-trips
    var count = 1;
    while (count <= 17) {
        var all: array<int> = [];
        var i = 0;
        while (i < count) {
            all.push(fillerLeaf(i));
            i += 1;
        }
        val root = treeRoot(all);
        i = 0;
        while (i < count) {
            expect(sccpMerkleRoot(all.get(i), i, count, treePath(all, i))).toEqual(root);
            i += 1;
        }
        count += 1;
    }
}

get fun `test merkle verification rejects bad index, count and path length`() {
    val fixtureLeaves = vecTreeLeaves();
    val leaves: array<int> = [
        fixtureLeaves.get(0),
        fixtureLeaves.get(1),
        fixtureLeaves.get(2),
        fixtureLeaves.get(3),
        fixtureLeaves.get(4),
    ];
    val path = vecTree5Path(3);
    val bad: array<[int, int]> = [[5, 5], [3, 0], [3, 4], [-1, 5]];
    var i = 0;
    while (i < bad.size()) {
        val [index, count] = bad.get(i);
        try {
            val root = sccpMerkleRoot(leaves.get(3), index, count, path);
            expect(root == vecTreeRoots().get(4)).toBeFalse();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadProof as int);
        }
        i += 1;
    }
    var longer = path;
    longer.push(1);
    try {
        sccpMerkleRoot(leaves.get(3), 3, 5, longer);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadProof as int);
    }
}

get fun `test hash paths are canonical`() {
    val hashes: array<int> = [1, 2, 3, 4, 5];
    val path = sccpBuildHashPath(hashes);
    expect(sccpLoadHashPath(path, 5, 9)).toEqual(hashes);
    expect(sccpLoadHashPath(null, 0, 9)).toEqual([]);
    // wrong length, missing and superfluous cells, over-long paths
    val cases: array<[cell?, int, int]> = [
        [path, 4, 9],
        [path, 6, 9],
        [null, 1, 9],
        [path, 0, 9],
        [path, 5, 4],
    ];
    var i = 0;
    while (i < cases.size()) {
        val [c, len, max] = cases.get(i);
        try {
            sccpLoadHashPath(c, len, max);
            expect(false).toBeTrue();
        } catch (e) {
            expect(
                (e == SccpErrors.BadSnake as int) | (e == SccpErrors.BadProof as int),
            ).toBeTrue();
        }
        i += 1;
    }
    // two hashes in the first chunk instead of three
    val nonMaximal = beginCell()
        .storeUint(1, 256)
        .storeUint(2, 256)
        .storeMaybeRef(
            beginCell().storeUint(3, 256).storeUint(4, 256).storeMaybeRef(null).endCell(),
        )
        .endCell();
    try {
        sccpLoadHashPath(nonMaximal, 4, 9);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadSnake as int);
    }
}

get fun `test snake bytes accept only the canonical shape`() {
    val canonical = snakeOfLength(300);
    val (chunks, len) = sccpParseSnakeBytes(canonical, 4096, SccpErrors.BadPayload);
    expect(len).toEqual(300);
    expect(chunks.size()).toEqual(3);
    // 1 byte and exactly 127 bytes are single chunks
    expect(sccpParseSnakeBytes(snakeOfLength(1), 4096, 1).1).toEqual(1);
    expect(sccpParseSnakeBytes(snakeOfLength(127), 4096, 1).0.size()).toEqual(1);
    val negatives: array<cell> = [
        // empty root
        createEmptyCell(),
        // non-final chunk shorter than 127 bytes
        beginCell().storeUint(0xAB, 8).storeRef(beginCell().storeUint(0xCD, 8).endCell()).endCell(),
        // empty final chunk
        beginCell()
            .storeSlice(snakeOfLength(127).beginParse())
            .storeRef(createEmptyCell())
            .endCell(),
        // non-byte-aligned final chunk
        beginCell().storeUint(1, 9).endCell(),
        // two references
        beginCell()
            .storeUint(0xAB, 8)
            .storeRef(createEmptyCell())
            .storeRef(createEmptyCell())
            .endCell(),
    ];
    var i = 0;
    while (i < negatives.size()) {
        try {
            sccpParseSnakeBytes(negatives.get(i), 4096, SccpErrors.BadPayload);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
    // the length bound uses the caller's error
    try {
        sccpParseSnakeBytes(snakeOfLength(1025), 1024, SccpErrors.BadRecipient);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadRecipient as int);
    }
    expect(sccpParseSnakeBytes(snakeOfLength(1024), 1024, SccpErrors.BadRecipient).1).toEqual(1024);
}

get fun `test inbound payload rules`() {
    val minter = 0x77;
    val good = inboundPayloadCell(1, 1, 5, 10, 0x33);
    expect(sccpParseInboundPayload(good, 1, minter).nonce).toEqual(1);
    // revision mismatch, zero deadline, zero amount, amount 2^96, recipient cases
    val cases: array<[cell, int]> = [
        [inboundPayloadCell(1, 2, 5, 10, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 0, 10, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, 0, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, SCCP_TON_AMOUNT_LIMIT, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, 10, 0), SccpErrors.BadRecipient as int],
        [inboundPayloadCell(1, 1, 5, 10, minter), SccpErrors.BadRecipient as int],
    ];
    var i = 0;
    while (i < cases.size()) {
        val [payload, code] = cases.get(i);
        try {
            sccpParseInboundPayload(payload, 1, minter);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(code);
        }
        i += 1;
    }
    // trailing byte and truncation
    var w = SnakeWriter.create();
    val (chunks, _) = sccpParseSnakeBytes(good, 4096, 1);
    var j = 0;
    while (j < chunks.size()) {
        w.writeSlice(chunks.get(j));
        j += 1;
    }
    w.writeUint(0, 1);
    try {
        sccpParseInboundPayload(sccpSnakeCellFromChunks(w.chunks()), 1, minter);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadPayload as int);
    }
    try {
        sccpParseInboundPayload(snakeOfLength(20), 1, minter);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadPayload as int);
    }
}
