// Value, fees and storage rent (§5.3.5): the size constants cover the
// compiled contracts, maximal states and messages; every per-step gas limit
// covers the measured worst case (n = 31, t = 21, maximal paths and payloads);
// the floors hold after each flow. Measured values are printed for §5.4.

import "@acton/build"
import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

const MAX_U256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

/// (cells, bits) of a cell tree.
fun treeSize(c: cell): (int, int) {
    val (cells, bits, _) = c.calculateSizeStrict(10000);
    return (cells, bits);
}

fun expectCovered(label: string, cells: int, bits: int, maxCells: int, maxBits: int) {
    println(
        "{}: {} cells, {} bits (bound {} / {})",
        label,
        cells,
        bits,
        maxCells,
        maxBits,
    );
    expect(cells <= maxCells).toBeTrue();
    expect(bits <= maxBits).toBeTrue();
}

get fun `test state size constants cover the compiled contracts`() {
    val minter = testing.treasury("minter").address;
    val owner = testing.treasury("owner").address;
    val bucketData: BucketStorage = {
        minterAddress: minter,
        index: 0xFFFFFFFF,
        activated: true,
        bitsHi: 0,
        bitsLo: 0,
    };
    val (bc, bb) = treeSize(build("SccpConsumedBucket"));
    val (bdc, bdb) = treeSize(bucketData.toCell());
    expectCovered(
        "bucket state",
        bc + bdc,
        bb + bdb,
        SCCP_BUCKET_STATE_CELLS,
        SCCP_BUCKET_STATE_BITS,
    );
    expectCovered(
        "bucket StateInit",
        bc + bdc + 1,
        bb + bdb + 5,
        SCCP_BUCKET_STATE_INIT_CELLS,
        SCCP_BUCKET_STATE_INIT_BITS,
    );

    val walletData: WalletStorage = {
        jettonBalance: SCCP_TON_AMOUNT_LIMIT,
        ownerAddress: owner,
        minterAddress: minter,
    };
    val (wc, wb) = treeSize(build("SccpTairaXorWallet"));
    val (wdc, wdb) = treeSize(walletData.toCell());
    expectCovered(
        "wallet state",
        wc + wdc,
        wb + wdb,
        SCCP_WALLET_STATE_CELLS,
        SCCP_WALLET_STATE_BITS,
    );
    expectCovered(
        "wallet StateInit",
        wc + wdc + 1,
        wb + wdb + 5,
        SCCP_WALLET_STATE_INIT_CELLS,
        SCCP_WALLET_STATE_INIT_BITS,
    );

    // maximal minter: n = 31 current and previous rosters, maximal counters
    val roster = makeRoster(
        7,
        31,
        0,
        0,
        T0 * 1000,
        T0 * 1000 + DAY_MS,
    );
    var storage = canonicalStorage(VEC_NETWORK_ID, TEST_REVISION, SCCP_TON_AMOUNT_LIMIT, roster);
    val state = storage.roster.load();
    val prev: PrevRoster = {
        digest: state.digest,
        validUntilMs: state.validUntilMs,
        n: 31,
        t: 21,
        members: makeRoster(
            8,
            31,
            0,
            0,
            1,
            2,
        ).membersCell(),
    };
    storage.prevRoster = prev.toCell();
    storage.totalSupply = SCCP_TON_AMOUNT_LIMIT;
    storage.pendingSupply = SCCP_TON_AMOUNT_LIMIT;
    val (mc, mb) = treeSize(build("SccpTairaXorMinter"));
    val (mdc, mdb) = treeSize(storage.toCell());
    expectCovered(
        "minter state",
        mc + mdc,
        mb + mdb,
        SCCP_MINTER_STATE_CELLS,
        SCCP_MINTER_STATE_BITS,
    );
}

get fun `test message size constants cover the largest messages`() {
    val a = testing.treasury("a").address;
    val b = testing.treasury("b").address;
    val tail: ConsumeTail = {
        kind: 0,
        recipient: a,
        response: b,
        messageId: MAX_U256,
    };
    val consume = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsume {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            tail: tail.toCell(),
        },
    });
    val (cc, cb) = treeSize(consume.messageCell);
    expectCovered("consume", cc, cb, SCCP_MSG_CONSUME_CELLS, SCCP_MSG_CONSUME_BITS);
    val activate = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: sccpBucketDeployment(a, 0xFFFFFFFF, build("SccpConsumedBucket")),
        body: SccpActivateBucket {
            queryId: (1 << 64) - 1,
            index: 0xFFFFFFFF,
        },
    });
    val (ac, ab) = treeSize(activate.messageCell);
    expectCovered(
        "activate + StateInit",
        ac,
        ab,
        SCCP_MSG_SMALL_CELLS + SCCP_BUCKET_STATE_INIT_CELLS,
        SCCP_MSG_SMALL_BITS + SCCP_BUCKET_STATE_INIT_BITS,
    );
    val smalls: array<cell> = [
        (SccpConsumeReverted {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
        }).toCell(),
        (SccpUnconsume { nonce: (1 << 64) - 1 }).toCell(),
    ];
    var k = 0;
    while (k < smalls.size()) {
        val small = createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: SCCP_TON_AMOUNT_LIMIT,
            dest: a,
            body: smalls.get(k),
        });
        val (sc, sb) = treeSize(small.messageCell);
        expectCovered("small message", sc, sb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
        k += 1;
    }
    val consumed = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsumed {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            tail: tail.toCell(),
        },
    });
    val (dc, db) = treeSize(consumed.messageCell);
    expectCovered("consumed", dc, db, SCCP_MSG_CONSUME_CELLS, SCCP_MSG_CONSUME_BITS);
    val mint = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: sccpWalletDeployment(a, b, build("SccpTairaXorWallet")),
        body: InternalTransferStep {
            queryId: (1 << 64) - 1,
            jettonAmount: SCCP_TON_AMOUNT_LIMIT - 1,
            transferInitiator: null,
            sendExcessesTo: b,
            forwardTonAmount: 0,
            forwardPayload: beginCell().storeUint(0, 1).toSlice(),
        },
    });
    val (ic, ib) = treeSize(mint.messageCell);
    expectCovered(
        "internal_transfer + StateInit",
        ic,
        ib,
        SCCP_MSG_INTERNAL_TRANSFER_CELLS + SCCP_WALLET_STATE_INIT_CELLS,
        SCCP_MSG_INTERNAL_TRANSFER_BITS + SCCP_WALLET_STATE_INIT_BITS,
    );
    val range = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsumeRange {
            queryId: (1 << 64) - 1,
            first: (1 << 64) - 1,
            count: 512,
        },
    });
    val (rc, rb) = treeSize(range.messageCell);
    expectCovered("consume_range", rc, rb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
    val excess = createMessage({
        bounce: BounceMode.NoBounce,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: ReturnExcessesBack { queryId: (1 << 64) - 1 },
    });
    val (ec, eb) = treeSize(excess.messageCell);
    expectCovered("excess", ec, eb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
    val voided = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpVoidedEvent {
            messageId: MAX_U256,
            firstNonce: (1 << 64) - 1,
            count: 512,
        },
    });
    val (vc, vb) = treeSize(voided.messageCell);
    expectCovered("sccp_voided", vc, vb, SCCP_MSG_EXT_EVENT_CELLS, SCCP_MSG_EXT_EVENT_BITS);
    val rotated = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpRosterRotatedEvent {
            generation: (1 << 64) - 1,
            digest: MAX_U256,
            validUntilMs: (1 << 64) - 1,
        },
    });
    val (rrc, rrb) = treeSize(rotated.messageCell);
    expectCovered(
        "sccp_roster_rotated",
        rrc,
        rrb,
        SCCP_MSG_EXT_EVENT_CELLS,
        SCCP_MSG_EXT_EVENT_BITS,
    );
    val (chunks, len) = sccpParseSnakeBytes(snakeOfLength(1024), 1024, 1);
    val payload = sccpBuildOutboundPayload(
        (1 << 64) - 1,
        1,
        SCCP_TON_AMOUNT_LIMIT - 1,
        1,
        chunks,
        len,
    );
    val transfer = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpTransferToTairaEvent {
            messageId: MAX_U256,
            nonce: (1 << 64) - 1,
            sender: a,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            payload: payload.cell,
        },
    });
    val (tc, tb) = treeSize(transfer.messageCell);
    expectCovered(
        "sccp_transfer_to_taira",
        tc,
        tb,
        SCCP_MSG_EXT_TRANSFER_CELLS,
        SCCP_MSG_EXT_TRANSFER_BITS,
    );
    val burn = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: BurnNotificationForMinter {
            queryId: (1 << 64) - 1,
            jettonAmount: SCCP_TON_AMOUNT_LIMIT - 1,
            burnInitiator: a,
            sendExcessesTo: b,
            sccp: (SccpBurnToTaira { recipient: snakeOfLength(1024) }).toCell(),
        },
    });
    val (nc, nb) = treeSize(burn.messageCell);
    expectCovered(
        "burn_notification",
        nc,
        nb,
        SCCP_MSG_BURN_NOTIFICATION_CELLS,
        SCCP_MSG_BURN_NOTIFICATION_BITS,
    );
}

/// Value `value` minus the excess returned to `to` in `res`.
fun consumedValue(res: SendResultList, value: coins, to: address): int {
    val tx = res.findTransaction<ReturnExcessesBack>({ to })!;
    val info = tx.loadInMsg<ReturnExcessesBack>().info;
    if (info is TlbInternalMessage) {
        return value - info.value.grams;
    }
    return value;
}

/// Gas of the first transaction matching `to` and opcode `Msg`.
fun gasOf<Msg>(res: SendResultList, to: address): int {
    return res.getUsedGas<Msg>({ to });
}

fun expectGas(label: string, used: int, limit: int) {
    println("gas {}: {} (limit {})", label, used, limit);
    expect(used <= limit).toBeTrue();
}

/// A worst-case historical delivery: block of 512 leaves (path 9), history of
/// 2^32 blocks (path 32), 1024-byte sender, n = 31 / t = 21 signatures.
fun worstCaseHistorical(env: Env, nonce: int, deadlineMs: int, recipient: address): (
    TestStatement,
    cell,
    HistoryProof,
    MessageProof,
) {
    val payload = inboundPayloadWithSender(
        nonce,
        TEST_REVISION,
        deadlineMs,
        SCCP_TON_AMOUNT_LIMIT - 1,
        recipient.accountId(),
        1024,
    );
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    var blockPath: array<int> = [];
    var i = 0;
    while (i < 9) {
        blockPath.push(fillerLeaf(100 + i));
        i += 1;
    }
    val blockRoot = sccpMerkleRoot(leaf, 511, 512, blockPath);
    var historyPath: array<int> = [];
    i = 0;
    while (i < 32) {
        historyPath.push(fillerLeaf(200 + i));
        i += 1;
    }
    val historyIndex = SCCP_MAX_HISTORY_SIZE - 1;
    val historyRoot = sccpMerkleRoot(
        sccpHistoryLeaf(77, blockRoot, 512),
        historyIndex,
        SCCP_MAX_HISTORY_SIZE,
        historyPath,
    );
    val statement: TestStatement = {
        height: 99,
        epoch: 9,
        timestampMs: T0 * 1000,
        blockHash: 0x99,
        sccpRoot: fillerLeaf(9),
        messageCount: 512,
        historyRoot,
        historySize: SCCP_MAX_HISTORY_SIZE,
        rosterDigest: env.digest(),
        nextRosterDigest: 0,
    };
    return (
        statement,
        signByThreshold(env.roster, statement.digest(env.networkId)),
        {
            height: 77,
            sccpRoot: blockRoot,
            messageCount: 512,
            leafIndex: historyIndex,
            pathLen: 32,
            path: sccpBuildHashPath(historyPath),
        },
        {
            leafIndex: 511,
            pathLen: 9,
            payload,
            path: sccpBuildHashPath(blockPath),
        },
    );
}

get fun `test worst-case finalize gas per step and the floors`() {
    val env = setupEnvWith(31, 0, SCCP_TON_AMOUNT_LIMIT * 4);
    expect(env.roster.t()).toEqual(21);
    val alice = testing.treasury("alice").address;
    val (statement, sigs, history, proof) = worstCaseHistorical(
        env,
        3 * 512 + 7,
        T0 * 1000 + DAY_MS,
        alice,
    );
    val value = finalizeValue(env, 3 * 512 + 7);
    println("finalize_required_value (deploys 4 buckets): {}", value);
    val res = env
        .minter
        .sendSccpFinalizeHistorical(
            env.deployer,
            1,
            env.deployer,
            statement.attestation(),
            sigs,
            history,
            proof,
            { value, bounce: true },
        );
    expect(res).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    println(
        "finalize consumed (4 new buckets, new wallet): {}",
        consumedValue(res, value, env.deployer),
    );
    expectGas(
        "minter finalize historical n=31",
        gasOf<SccpFinalizeHistorical>(res, env.minter.address),
        SCCP_GAS_MINTER_FINALIZE,
    );
    expectGas(
        "bucket consume",
        gasOf<SccpConsume>(res, env.minter.getBucketAddress(3)),
        SCCP_GAS_BUCKET_CONSUME,
    );
    expectGas(
        "bucket activation",
        gasOf<SccpActivateBucket>(res, env.minter.getBucketAddress(0)),
        SCCP_GAS_BUCKET_ACTIVATE,
    );
    expectGas(
        "minter consumed",
        gasOf<SccpConsumed>(res, env.minter.address),
        SCCP_GAS_MINTER_CONSUMED,
    );
    expectGas(
        "wallet receive",
        gasOf<InternalTransferStep>(res, walletOf(env, alice).address),
        SCCP_GAS_WALLET_RECEIVE,
    );
    // floors
    expect(
        testing.getAccountBalance(env.minter.getBucketAddress(3)) >= sccpBucketFloor(),
    ).toBeTrue();
    expect(
        testing.getAccountBalance(env.minter.getBucketAddress(0)) >= sccpBucketFloor(),
    ).toBeTrue();
    expect(testing.getAccountBalance(env.minter.address) >= sccpMinterFloor()).toBeTrue();
    println(
        "BUCKET_FLOOR {} MINTER_FLOOR {} wallet min storage {} gas fee of 100000 gas {}",
        sccpBucketFloor(),
        sccpMinterFloor(),
        sccpWalletMinStorage(),
        sccpGasFee(100000),
    );

    // a second finalize into an existing bucket and wallet
    val d = deliver(
        env,
        env.roster,
        3 * 512 + 8,
        5,
        alice,
        T0 * 1000 + DAY_MS,
        0,
        1,
    );
    val value2 = finalizeValue(env, 3 * 512 + 8);
    val res2 = sendFinalize(env, env.deployer, d, value2);
    expect(res2).toHaveAllSuccessfulTxs();
    println("finalize required value (existing bucket): {}", value2);
    println(
        "finalize consumed (existing bucket and wallet): {}",
        consumedValue(res2, value2, env.deployer),
    );
    expectGas(
        "minter finalize direct n=31",
        gasOf<SccpFinalize>(res2, env.minter.address),
        SCCP_GAS_MINTER_FINALIZE,
    );
}

get fun `test finalize gas with the n=4 roster`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val res = finalizeOk(env, 0, 10, alice);
    expectGas(
        "minter finalize direct n=4",
        gasOf<SccpFinalize>(res, env.minter.address),
        SCCP_GAS_MINTER_FINALIZE,
    );
    val d = deliverDefault(env, 1, 10, alice);
    val value = finalizeValue(env, 1);
    val res1 = sendFinalize(env, env.deployer, d, value);
    expect(res1).toHaveAllSuccessfulTxs();
    println(
        "finalize consumed n=4 (existing bucket and wallet): {}",
        consumedValue(res1, value, env.deployer),
    );
}

get fun `test worst-case void gas`() {
    val env = setupEnvWith(31, 0, SCCP_TON_AMOUNT_LIMIT);
    val alice = testing.treasury("alice").address;
    val (statement, sigs, history, proof) = worstCaseHistorical(env, 5, (T0 + 10) * 1000, alice);
    testing.setNow(T0 + 11);
    val res = env
        .minter
        .sendSccpVoidExpiredHistorical(
            env.deployer,
            1,
            env.deployer,
            5,
            statement.attestation(),
            sigs,
            history,
            proof,
            { value: env.minter.voidRequiredValue(5), bounce: true },
        );
    expect(res).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 5)).toBeTrue();
    expectGas(
        "minter void historical n=31",
        gasOf<SccpVoidExpiredHistorical>(res, env.minter.address),
        SCCP_GAS_MINTER_VOID,
    );
    expectGas(
        "minter consumed (void)",
        gasOf<SccpConsumed>(res, env.minter.address),
        SCCP_GAS_MINTER_CONSUMED,
    );
}

get fun `test rotation and control gas at n=31`() {
    val env = setupEnvWith(31, 0, SCCP_TON_AMOUNT_LIMIT);
    val c = deliverControl(env, 1, true);
    val control = sendApplyControl(env, c);
    expect(control).toHaveAllSuccessfulTxs();
    expectGas(
        "apply control n=31",
        gasOf<SccpApplyControl>(control, env.minter.address),
        SCCP_GAS_MINTER_APPLY_CONTROL,
    );
    // historical worst case: control at leaf 511 of 512, history path 32
    val leaf = sccpControlLeaf(
        env.networkId,
        env.minter.address.accountId(),
        TEST_REVISION,
        2,
        false,
    );
    var blockPath: array<int> = [];
    var i = 0;
    while (i < 9) {
        blockPath.push(fillerLeaf(300 + i));
        i += 1;
    }
    val blockRoot = sccpMerkleRoot(leaf, 511, 512, blockPath);
    var historyPath: array<int> = [];
    i = 0;
    while (i < 32) {
        historyPath.push(fillerLeaf(400 + i));
        i += 1;
    }
    val historyIndex = SCCP_MAX_HISTORY_SIZE - 1;
    val statement: TestStatement = {
        height: 98,
        epoch: 9,
        timestampMs: T0 * 1000,
        blockHash: 0x98,
        sccpRoot: fillerLeaf(8),
        messageCount: 512,
        historyRoot: sccpMerkleRoot(
            sccpHistoryLeaf(76, blockRoot, 512),
            historyIndex,
            SCCP_MAX_HISTORY_SIZE,
            historyPath,
        ),
        historySize: SCCP_MAX_HISTORY_SIZE,
        rosterDigest: env.digest(),
        nextRosterDigest: 0,
    };
    val historical = env
        .minter
        .sendSccpApplyControlHistorical(
            env.deployer,
            1,
            env.deployer,
            statement.attestation(),
            signByThreshold(env.roster, statement.digest(env.networkId)),
            {
                height: 76,
                sccpRoot: blockRoot,
                messageCount: 512,
                leafIndex: historyIndex,
                pathLen: 32,
                path: sccpBuildHashPath(historyPath),
            },
            {
                controlNonce: 2,
                paused: false,
                leafIndex: 511,
                pathLen: 9,
                path: sccpBuildHashPath(blockPath),
            },
            { value: env.minter.applyControlRequiredValue(), bounce: true },
        );
    expect(historical).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().controlNonce).toEqual(2);
    expectGas(
        "apply control historical n=31",
        gasOf<SccpApplyControlHistorical>(historical, env.minter.address),
        SCCP_GAS_MINTER_APPLY_CONTROL,
    );
    val next = makeRoster(
        8,
        31,
        0,
        0,
        T0 * 1000 - 1000,
        T0 * 1000 + 14 * DAY_MS,
    );
    val res = rotateTo(env, next, 400);
    expect(res).toHaveAllSuccessfulTxs();
    expectGas(
        "rotation n=31 -> n=31",
        gasOf<SccpRotate>(res, env.minter.address),
        SCCP_GAS_MINTER_ROTATE,
    );
    val small = setupEnv();
    val controlSmall = sendApplyControl(small, deliverControl(small, 1, true));
    println(
        "gas apply control n=4: {}",
        gasOf<SccpApplyControl>(controlSmall, small.minter.address),
    );
    val rotateSmall = rotateTo(small, nextRoster(small.roster, 4, 4, T0 * 1000 - 1000), 401);
    println("gas rotation n=4 -> n=4: {}", gasOf<SccpRotate>(rotateSmall, small.minter.address));
}

get fun `test burn, void frozen, deploy and unconsume gas`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    val burn = sendBurn(env, alice, 100, snakeOfLength(1024), burnValue(env, alice));
    expect(burn).toHaveAllSuccessfulTxs();
    println("burn required value {}", burnValue(env, alice));
    expectGas(
        "wallet burn",
        gasOf<AskToBurn>(burn, walletOf(env, alice).address),
        SCCP_GAS_WALLET_BURN,
    );
    expectGas(
        "minter burn (1024-byte recipient)",
        gasOf<BurnNotificationForMinter>(burn, env.minter.address),
        SCCP_GAS_MINTER_BURN,
    );

    val deploy = env
        .minter
        .sendSccpDeployBuckets(
            env.deployer,
            0,
            env.deployer,
            16,
            { value: env.minter.deployBucketsRequiredValue(16), bounce: true },
        );
    expect(deploy).toHaveAllSuccessfulTxs();
    expectGas(
        "minter deploy 16 buckets",
        gasOf<SccpDeployBuckets>(deploy, env.minter.address),
        SCCP_GAS_MINTER_DEPLOY_BUCKETS,
    );

    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    val frozen = env
        .minter
        .sendSccpVoidFrozen(
            env.deployer,
            0,
            env.deployer,
            512,
            512,
            { value: env.minter.voidFrozenRequiredValue(512), bounce: true },
        );
    expect(frozen).toHaveAllSuccessfulTxs();
    expectGas(
        "minter void frozen",
        gasOf<SccpVoidFrozen>(frozen, env.minter.address),
        SCCP_GAS_MINTER_VOID_FROZEN,
    );
    // the worst case activates four buckets (deployed = 17 after the deploy above)
    val ahead = env
        .minter
        .sendSccpVoidFrozen(
            env.deployer,
            0,
            env.deployer,
            20 * 512,
            512,
            { value: env.minter.voidFrozenRequiredValue(20 * 512), bounce: true },
        );
    expect(ahead).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(21);
    expectGas(
        "minter void frozen activating 4 buckets",
        gasOf<SccpVoidFrozen>(ahead, env.minter.address),
        SCCP_GAS_MINTER_VOID_FROZEN,
    );
    expectGas(
        "bucket consume range 512",
        gasOf<SccpConsumeRange>(frozen, env.minter.getBucketAddress(1)),
        SCCP_GAS_BUCKET_CONSUME_RANGE,
    );
    expectGas(
        "minter range reply",
        gasOf<SccpRangeConsumed>(frozen, env.minter.address),
        SCCP_GAS_MINTER_RANGE_REPLY,
    );

    // unconsume (via a forged minter sender in the emulator)
    val un = bucketOf(env, 0).sendSccpUnconsume(
        env.minter.address,
        0,
        { value: sccpUnconsumeValue(), bounce: true },
    );
    expect(un).toHaveAllSuccessfulTxs();
    expectGas(
        "bucket unconsume",
        gasOf<SccpUnconsume>(un, env.minter.getBucketAddress(0)),
        SCCP_GAS_BUCKET_UNCONSUME,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
}

get fun `test wallet transfer gas`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 100, alice);
    val res = walletOf(env, alice).sendAskToTransfer(
        alice,
        3,
        40,
        bob,
        alice,
        null,
        grams("0.01"),
        PayloadInRef {
            value: beginCell().storeUint(7, 32).endCell() as Cell<RemainingBitsAndRefs>,
        },
        { value: grams("0.5"), bounce: true },
    );
    expect(res).toHaveAllSuccessfulTxs();
    expectGas(
        "wallet transfer",
        gasOf<AskToTransfer>(res, walletOf(env, alice).address),
        SCCP_GAS_WALLET_TRANSFER,
    );
    expectGas(
        "wallet receive with notification",
        gasOf<InternalTransferStep>(res, walletOf(env, bob).address),
        SCCP_GAS_WALLET_RECEIVE,
    );
}

get fun `test an underfunded minter charges its floor deficit to the next caller`() {
    testing.setNow(T0);
    val deployer = testing.treasury("deployer");
    val roster = defaultRoster(4, 0);
    val (minter, res) = deployWithInit(
        canonicalStorage(VEC_NETWORK_ID, TEST_REVISION, TEST_MAX_SUPPLY, roster),
        deployer.address,
        grams("0.2"),
    );
    expect(res).toHaveSuccessfulDeploy({ to: minter.address });
    val env: Env = {
        minter,
        deployer: deployer.address,
        networkId: VEC_NETWORK_ID,
        roster,
    };
    val balance = testing.getAccountBalance(minter.address);
    expect(balance < sccpMinterFloor()).toBeTrue();
    expect(minter.minterFloor()).toEqual(sccpMinterFloor());
    val required = finalizeValue(env, 0);
    expect(required).toEqual(
        sccpFinalizeRequiredValue(1) + sccpMinterFloor() - balance + sccpMinterStorageGrace(),
    );
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    expect(
        sendFinalize(env, env.deployer, d, sccpFinalizeRequiredValue(1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    // the entry minimum is the quote without the grace
    expect(
        sendFinalize(env, env.deployer, d, required - sccpMinterStorageGrace() - 1),
    ).toHaveFailedTx<SccpFinalize>({
        to: minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    val ok = sendFinalize(env, env.deployer, d, required);
    expect(ok).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(10);
    expect(testing.getAccountBalance(minter.address) >= sccpMinterFloor() - 1000).toBeTrue();
}
