// Complete direct TON replay of contract-visible shared fixture rows. Pinned
// counts are independent of the generated tables: regeneration cannot silently
// delete a payload, path, root, negative, native event or BLS verification row.

import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Reads the table's linked path words without constructing or deriving a path.
fun fixturePath(cur: cell, count: int): array<int> {
    var s = cur.beginParse();
    var words: array<int> = [];
    repeat (count) {
        if (s.remainingBitsCount() == 0) {
            s = s.loadRef().beginParse();
        }
        words.push(s.loadUint(256));
    }
    expect(s.remainingBitsCount()).toEqual(0);
    expect(s.remainingRefsCount()).toEqual(0);
    return words;
}

get fun `test every forgery row binds its source evidence id to the exact native certificate`() {
    expect(VEC_ALL_FORGERY_EVIDENCE).toEqual(19);
    val keys = vecForgeryKeys();
    val committee: CommitteeState = {
        root: VEC_FORGERY_COMMITTEE_ROOT,
        untilMs: SCCP_MAX_U64,
        start: 1,
        high: 0,
        generation: VEC_FORGERY_GENERATION,
        n: keys.size(),
        keys: sccpBuildKeys(keys),
    };
    sccpRequireStoredCommittee(committee.keys, committee.n, committee.root);
    val cps = Checkpoints.load(beginCell().storeUint(0, 2).endCell());
    var row = 0;
    var refusedInactive = 0;
    repeat (VEC_ALL_FORGERY_EVIDENCE) {
        val n = vecForgeryEvidence(row);
        var rawQc = n.qc;
        val qc: TestQc = {
            epoch: rawQc.loadUint(64),
            epochContext: rawQc.loadUint(256),
            view: rawQc.loadUint(64),
            blockHash: rawQc.loadUint(256),
            resultBody: rawQc.loadUint(256),
        };
        var header = n.head;
        header.skipBits(SCCP_X_HEIGHT_OFFSET_BITS);
        val height = header.preloadUint(64);
        val result = sha256Parts(
            [
                beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
                n.head,
                n.tail,
                beginCell().storeUint(qc.resultBody, 256),
            ],
        );
        expect(result).toEqual(n.result);
        val message = voteMessage(SCCP_KIND_COMMIT, VEC_FORGERY_INSTANCE, height, qc, result);
        expect(message.bitsEqual(n.message)).toBeTrue();
        var t: tuple = [];
        var key = 0;
        repeat (keys.size()) {
            if (((n.signers >> key) & 1) != 0) {
                t.push(keys.get(key));
            }
            key += 1;
        }
        expect(sccpPopCount(n.signers)).toEqual(sccpQuorum(keys.size()));
        t.push(sccpPopCount(n.signers));
        t.push(message);
        t.push(n.signature);
        expect(sccpBlsFastAggregateVerify(t)).toBeTrue();
        var exit = 0;
        try {
            val verified = sccpVerifyCertificate(
                certCell(n.signature, n.signers, n.qc, n.head, n.tail),
                VEC_FORGERY_NETWORK_ID,
                VEC_FORGERY_INSTANCE,
                committee,
                cps,
            );
            expect(verified.fullPath).toBeTrue();
            expect(verified.x.height).toEqual(height);
        } catch (code) {
            exit = code;
        }
        if (exit != n.exit) {
            println("forgery certificate row {} evidence id {}: exit {}", row, n.evidenceId, exit);
        }
        expect(exit).toEqual(n.exit);
        if (exit == (SccpErrors.BadHeader as int)) {
            refusedInactive += 1;
        }
        row += 1;
    }
    // All raw signatures verify. Core's E0--E4 and retention verdicts are
    // source accountability decisions; TON refuses inactive X at its own
    // boundary. The launcher checks all 22 BLAKE2b-256 evidence-id rows.
    expect(row).toEqual(19);
    expect(refusedInactive).toEqual(1);
}

/// Checks one exact fixture row against the production Merkle verifier.
fun replayMerkleCell(c: cell, history: bool): int {
    var s = c.beginParse();
    val count = s.loadUint(32);
    val index = s.loadUint(32);
    val leaf = s.loadUint(256);
    val root = s.loadUint(256);
    val pathLength = s.loadUint(8);
    val path = fixturePath(s.loadRef(), pathLength);
    expect(sccpMerkleRoot(leaf, index, count, path)).toEqual(root);
    if (!history) {
        sccpVerifyLeaf(
            leaf,
            index,
            pathLength,
            sccpBuildHashPath(path),
            root,
            count,
        );
    } else {
        val [height, sccpRoot, messageCount, recordedLeaf] = vecAllHistoryLeaf(index);
        expect(leaf).toEqual(recordedLeaf);
        var x = emptyX(VEC_NETWORK_ID, TEST_GENERATION, 1, height + 10000);
        x.historySize = count;
        x.historyRoot = root;
        val (header, _, _) = sccpParseX(x.toCell(), VEC_NETWORK_ID);
        val (provedRoot, provedCount) = sccpCheckBlockRef(
            blockRefCell(height, sccpRoot, messageCount, index, path),
            header,
        );
        expect(provedRoot).toEqual(sccpRoot);
        expect(provedCount).toEqual(messageCount);
    }
    return index == 0 ? 1 : 0;
}

get fun `test every recorded commitment path root and promoted node`() {
    expect(VEC_ALL_TREE_PATHS).toEqual(665);
    expect(VEC_ALL_TREE_ROOTS).toEqual(18);
    var row = 0;
    var roots = 0;
    repeat (VEC_ALL_TREE_PATHS) {
        roots += replayMerkleCell(vecAllTreePath(row), false);
        row += 1;
    }
    expect(row).toEqual(665);
    expect(roots).toEqual(18);
}

get fun `test every recorded history path root and leaf`() {
    expect(VEC_ALL_HISTORY_PATHS).toEqual(820);
    expect(VEC_ALL_HISTORY_ROOTS).toEqual(40);
    expect(VEC_ALL_HISTORY_LEAVES).toEqual(40);
    var row = 0;
    var roots = 0;
    repeat (VEC_ALL_HISTORY_PATHS) {
        roots += replayMerkleCell(vecAllHistoryPath(row), true);
        row += 1;
    }
    expect(row).toEqual(820);
    expect(roots).toEqual(40);
    row = 0;
    repeat (VEC_ALL_HISTORY_LEAVES) {
        val [height, root, count, leaf] = vecAllHistoryLeaf(row);
        expect(sccpHistoryLeaf(height, root, count)).toEqual(leaf);
        row += 1;
    }
    expect(row).toEqual(40);
    var empty = emptyX(VEC_NETWORK_ID, TEST_GENERATION, 1, 10000);
    empty.historySize = 0;
    empty.historyRoot = VEC_ALL_HISTORY_EMPTY_ROOT;
    val (header, _, _) = sccpParseX(empty.toCell(), VEC_NETWORK_ID);
    expect(header.historyRoot).toEqual(0);
    val [height, root, count, _] = vecAllHistoryLeaf(0);
    var exit = 0;
    try {
        sccpCheckBlockRef(blockRefCell(height, root, count, 0, []), header);
    } catch (code) {
        exit = code;
    }
    expect(exit).toEqual(SccpErrors.BadProof as int);
}

get fun `test every shared tree confusion and structural negative`() {
    expect(VEC_ALL_TREE_NEGATIVES).toEqual(6);
    var row = 0;
    repeat (VEC_ALL_TREE_NEGATIVES) {
        val n = vecTreeNegative(row);
        var rootExit = 0;
        try {
            val computed = sccpMerkleRoot(n.leaf, n.index, n.count, n.path);
            expect(computed).toEqual(n.computed);
            expect(computed == n.root).toBeFalse();
        } catch (code) {
            rootExit = code;
        }
        expect(rootExit).toEqual(n.malformed ? SccpErrors.BadProof as int : 0);
        var proofExit = 0;
        try {
            sccpVerifyLeaf(
                n.leaf,
                n.index,
                n.path.size(),
                sccpBuildHashPath(n.path),
                n.root,
                n.count,
            );
        } catch (code) {
            proofExit = code;
        }
        expect(proofExit).toEqual(SccpErrors.BadProof as int);
        row += 1;
    }
    expect(row).toEqual(6);
}

get fun `test every raw refused payload has its exact TON destination error`() {
    expect(VEC_ALL_PAYLOAD_DIRECTIONS).toEqual(2);
    expect(VEC_ALL_PAYLOAD_REJECTIONS).toEqual(33);
    var row = 0;
    repeat (VEC_ALL_PAYLOAD_REJECTIONS) {
        val n = vecRejectedPayload(row);
        var exit = 0;
        try {
            val payload = (n.pieces.size() == 0) ? createEmptyCell() : snakeFromPieces(n.pieces);
            sccpParseInboundPayload(payload, 1, VEC_MINTER_ACCOUNT_ID);
        } catch (code) {
            exit = code;
        }
        expect(exit).toEqual(n.exit);
        row += 1;
    }
    expect(row).toEqual(33);
}

get fun `test every POP signature and fast aggregate fixture through the TON opcode`() {
    expect(VEC_ALL_BLS_VERIFICATIONS).toEqual(187);
    // Independent per-source counts prevent one section from shrinking while
    // another grows: Python sign positives/refusals, fast aggregates,
    // Rust sign/verify/fast, mainnet, Rust negatives, upstream sign/verify/fast,
    // upstream G1/G2 encodings, and additional SCCP G1/G2 boundaries.
    val expected: array<int> = [
        6,
        15,
        10,
        9,
        27,
        9,
        2,
        21,
        9,
        29,
        12,
        13,
        15,
        5,
        5,
    ];
    var executed: array<int> = [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    var row = 0;
    repeat (VEC_ALL_BLS_VERIFICATIONS) {
        val n = vecBlsVerification(row);
        var t: tuple = [];
        var key = 0;
        repeat (n.keys.size()) {
            t.push(n.keys.get(key));
            key += 1;
        }
        t.push(n.keys.size());
        t.push(n.message);
        t.push(n.signature);
        var verdict = 0;
        try {
            verdict = sccpBlsFastAggregateVerify(t) ? 1 : 0;
        } catch (code) {
            verdict = 0 - code;
        }
        expect(verdict).toEqual(n.verdict);
        executed.set(executed.get(n.group) + 1, n.group);
        row += 1;
    }
    expect(row).toEqual(187);
    expect(executed).toEqual(expected);
}

get fun `test every TON native event matches the actual minter ext out body`() {
    expect(VEC_ALL_NATIVE_TRANSFERS).toEqual(1);
    var row = 0;
    repeat (VEC_ALL_NATIVE_TRANSFERS) {
        val n = vecNativeTransfer(row);
        testing.setNow(T0);
        val deployer = testing.treasury("native-event-deployer").address;
        val committee = testCommittee(4, 0);
        val env: Env = {
            minter: deployPinned(
                canonicalStorage(
                    n.networkId,
                    VEC_CONSENSUS_INSTANCE,
                    n.revision,
                    n.amount * 2,
                    defaultPin(committee),
                    committee.keys,
                ),
                deployer,
                grams("10"),
            ),
            deployer,
            networkId: n.networkId,
            instance: VEC_CONSENSUS_INSTANCE,
            generation: TEST_GENERATION,
            committee,
        };
        val owner = address.fromWorkchainAndHash(BASECHAIN, n.owner);
        finalizeOk(env, 0, n.amount, owner);
        var st = minterStorage(env);
        st.outboundNonce = n.nonce;
        setMinterStorage(env, st);
        val res = sendBurn(
            env,
            owner,
            n.amount,
            snakeFromPieces(n.recipient),
            burnValue(env, owner),
        );
        expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
        expectEvents(res, [n.body]);
        row += 1;
    }
    expect(row).toEqual(1);
}
