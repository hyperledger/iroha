import "@acton/build"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
// Capacity, identity and receipt-deletion invariants of TON recovery custody.
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/tlb/maybe"
import "@acton/types/big_array"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-addresses"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-recovery"
import "@contracts/sccp-storage"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"

fun testRecoveryOperation(nonce: int): RecoveryOperation {
    return {
        stage: SCCP_RECOVERY_CONSUME,
        phase: SCCP_RECOVERY_WAIT,
        attempt: 1,
        nonce,
        amount: 1000,
        count: 1,
        nextId: 0,
        queryId: nonce,
        result: 0,
        tail: ConsumeTail {
            kind: 0,
            recipient: testing.treasury("recipient").address,
            response: testing.treasury("caller").address,
            messageId: nonce,
        }.toCell(),
    };
}

get fun `test recovery reservation saturates before dispatch and reuses capacity without ids`() {
    var book = RecoveryBook.empty();
    var i = 0;
    while (i < SCCP_RECOVERY_CAPACITY) {
        expect(book.admit(testRecoveryOperation(i))).toEqual(i + 1);
        i += 1;
    }
    expect(book.count).toEqual(512);
    var rejected = false;
    try {
        book.requireRoom(1);
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryFull as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
    book.complete(1);
    expect(book.admit(testRecoveryOperation(600))).toEqual(513);
    expect(book.operations.exists(1)).toBeFalse();
    expect(book.count).toEqual(512);
}

get fun `test recovery lost prepared and deletion acknowledgements retain bounded custody`() {
    var receipts = RecoveryReceipts.empty();
    receipts.record(17, SCCP_RECOVERY_MINT, 1, SCCP_RECEIPT_APPLIED);
    // Losing the first ACK changes nothing. Confirmation returns its effect.
    expect(receipts.confirm(17, SCCP_RECOVERY_MINT, 1)).toEqual(SCCP_RECEIPT_APPLIED);
    expect(receipts.count).toEqual(1);
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.count).toEqual(0);
    // Losing Dropped requires only another Drop, never another mint.
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.count).toEqual(0);
    receipts.record(18, SCCP_RECOVERY_MINT, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.confirm(18, SCCP_RECOVERY_MINT, 1)).toEqual(SCCP_RECEIPT_APPLIED);
    expect(receipts.count).toEqual(1);
}

get fun `test recovery stale stage cannot remove an unconsume receipt`() {
    var receipts = RecoveryReceipts.empty();
    receipts.record(17, SCCP_RECOVERY_CONSUME, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_CONSUME, 1);
    receipts.record(17, SCCP_RECOVERY_UNCONSUME, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_CONSUME, 1);
    expect(receipts.confirm(17, SCCP_RECOVERY_UNCONSUME, 1)).toEqual(SCCP_RECEIPT_APPLIED);
}

get fun `test recovery stale absence cannot authorize a newer attempt`() {
    var operation = testRecoveryOperation(0);
    operation.phase = SCCP_RECOVERY_FAILED;
    operation.retry();
    expect(operation.attempt).toEqual(2);
    expect(operation.matches(SCCP_RECOVERY_CONSUME, 1)).toBeFalse();
    expect(operation.matches(SCCP_RECOVERY_CONSUME, 2)).toBeTrue();
    var rejected = false;
    try {
        operation.retry();
    } catch (code) {
        expect(code).toEqual(SccpErrors.BadRecovery as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
}

get fun `test recovery operation and attempt counters fail before wrapping`() {
    var book = RecoveryBook.empty();
    book.nextId = SCCP_MAX_U64;
    var rejected = false;
    try {
        book.requireRoom(1);
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryExhausted as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
    var operation = testRecoveryOperation(0);
    operation.attempt = SCCP_MAX_U64;
    operation.phase = SCCP_RECOVERY_FAILED;
    rejected = false;
    try {
        operation.retry();
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryExhausted as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
}

get fun `test recovery createMessage enforces ihr disabled for ordered confirmation`() {
    val outbound = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: testing.treasury("recipient").address,
        value: 10000000,
        body: SccpInit { queryId: 1 },
    });
    val parsed = TlbMessageRelaxed<SccpInit>.fromCell(outbound.messageCell);
    expect(parsed.info.ihrDisabled).toBeTrue();
}

get fun `test recovery finalize completes activation consume mint and receipt deletion`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val delivery = deliverDefault(env, 0, 1000, alice);
    val sent = sendFinalize(env, env.deployer, delivery, finalizeValue(env, 0));
    expect(sent).toHaveAllSuccessfulTxs();
    val storage = minterStorage(env);
    expect(storage.totalSupply).toEqual(1000);
    expect(storage.pendingSupply).toEqual(0);
    val book = storage.recovery.load();
    expect(book.count).toEqual(0);
    expect(book.activatedBuckets).toEqual(1);
    expect(book.operations.isEmpty()).toBeTrue();
    val wallet = SccpTairaXorWallet.fromAddress(env.minter.getWalletAddress(alice));
    expect(wallet.getWalletData().jettonBalance).toEqual(1000);
    expect(canonicalBucket(env, 0).isConsumed(0)).toBeTrue();
}

get fun `test recovery lost wallet prepared acknowledgement never credits twice`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1000, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    val received = recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    val ack = received.outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expect(minterStorage(env).recovery.load().count).toEqual(1);
    expect(env.minter.getSccpState().opCount).toEqual(0);
    // Losing or bouncing Prepared cannot erase the destination receipt.
    testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(ack, walletOf(env, alice).address, grams("0.01")),
    );
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    val retry = sendRetry(env, ack.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expectEvents(
        retry,
        [
            SccpFinalizedEvent {
                messageId: d.messageId,
                nonce: 0,
            }.toCell(),
        ],
    );
    expect(retry).toNotHaveTx<SccpRecoveryDispatch>({});
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    // A delayed Prepared ACK after completion cannot recreate a reservation.
    val late = net.send(walletOf(env, alice).address, forwardOut(received, 0));
    expectEvents(late, []);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
}

get fun `test recovery lost wallet deletion acknowledgement retries only deletion`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 77, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    val steps = cursor.executeTill<SccpRecoveryDrop>({ to: walletOf(env, alice).address });
    cursor.close();
    val dropped = steps.at(steps.size() - 1).outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(dropped.result).toEqual(SCCP_RECEIPT_DROPPED);
    expect(minterStorage(env).recovery.load().count).toEqual(1);
    val retry = sendRetry(env, dropped.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toNotHaveTx<SccpRecoveryDispatch>({});
    expect(jettonBalanceOf(env, alice)).toEqual(77);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
}

get fun `test recovery wallet deletion with absent receipt fails closed without remint`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 77, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    val received = recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    val ack = received.outMessages.at<SccpRecoveryAck>(0).loadBody();
    val wallet = walletOf(env, alice);
    // Model deletion/recreation after a possibly successful mint. Absence is
    // not allowed to manufacture an authenticated original failure.
    testing.setShardAccount(wallet.address, null);
    val state = sccpWalletDeployment(alice, env.minter.address, build("SccpTairaXorWallet"));
    net.send(
        env.deployer,
        createMessage({
            bounce: BounceMode.NoBounce,
            dest: state,
            value: sccpWalletRecoveryFloor(),
            body: TopUpTons { queryId: 0 },
        }),
    );
    val retry = sendRetry(env, ack.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toNotHaveTx<SccpRecoveryDispatch>({});
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(77);
    expect(minterStorage(env).recovery.load().count).toEqual(1);
    expect(isConsumedAt(env, 0)).toBeTrue();
}

get fun `test recovery forged prepared and dropped acknowledgements cannot free live custody`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 77, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    val received = recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    var ack = received.outMessages.at<SccpRecoveryAck>(0).loadBody();
    val before = minterStorage(env).toCell().hash();
    repeat (2) {
        val forged = sendToMinter(env, env.deployer, ack, grams("1"));
        expect(forged).toHaveFailedTx<SccpRecoveryAck>({
            to: env.minter.address,
            exitCode: SccpErrors.BadRecovery as int,
        });
        expect(minterStorage(env).toCell().hash()).toEqual(before);
        ack.result = SCCP_RECEIPT_DROPPED;
    }
    expect(jettonBalanceOf(env, alice)).toEqual(77);
}

get fun `test recovery full native minter rejects admission before signature or allocation`() {
    val env = setupEnv();
    var storage = minterStorage(env);
    storage.deployedBuckets = 1 << 55;
    storage.recovery = maximumRecoveryBook().toCell();
    setMinterStorage(env, storage);
    val d = deliverDefault(env, 0, 77, testing.treasury("alice").address);
    val before = minterStorage(env).toCell().hash();
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.RecoveryFull,
    );
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    // Governance maintenance and progress do not allocate operation slots.
    expectOutcome(
        checkpointBy(
            env,
            env.committee,
            emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 1),
            null,
        ),
        0,
    );
    expect(minterStorage(env).recovery.load().count).toEqual(512);
}

get fun `test recovery native state sizes cover all 512 retained rows and receipts`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    var storage = minterStorage(env);
    storage.recovery = maximumRecoveryBook().toCell();
    storage.totalSupply = 0xffffffffffffffffffffffffffffff;
    storage.pendingSupply = 0xffffffffffffffffffffffffffffff;
    var slots = Checkpoints.load(storage.checkpoints);
    expect(slots.insert(1, 1)).toBeTrue();
    expect(slots.insert(2, 2)).toBeTrue();
    expect(slots.insert(3, 3)).toBeTrue();
    storage.checkpoints = slots.toCell();
    val maximumMinter = installPinned(storage, env.deployer, sccpMinterFloor() + grams("10"));
    val (mc, mb) = accountStorageUsed(maximumMinter.address);
    println("maximum recovery minter: {} cells, {} bits", mc, mb);
    expect(mc <= SCCP_MINTER_STATE_CELLS).toBeTrue();
    expect(mb <= SCCP_MINTER_STATE_BITS).toBeTrue();
    expect(mc < 65536).toBeTrue();
    val wallet = WalletStorage {
        jettonBalance: 0xffffffffffffffffffffffffffffff,
        ownerAddress: env.deployer,
        minterAddress: env.minter.address,
        recovery: maximumRecoveryReceipts(SCCP_RECOVERY_MINT).toCell(),
    };
    val bucket = BucketStorage {
        minterAddress: env.minter.address,
        index: SCCP_MAX_U64,
        activated: true,
        bitsHi: 1,
        bitsLo: 2,
        recovery: maximumRecoveryReceipts(SCCP_RECOVERY_CONSUME).toCell(),
    };
    val (wc, wb, _) = beginCell()
        .storeRef(build("SccpTairaXorWallet"))
        .storeRef(wallet.toCell())
        .endCell()
        .calculateSizeStrict(10000);
    val (bc, bb, _) = beginCell()
        .storeRef(build("SccpConsumedBucket"))
        .storeRef(bucket.toCell())
        .endCell()
        .calculateSizeStrict(10000);
    println("maximum recovery wallet: {} cells, {} bits", wc, wb);
    println("maximum recovery bucket: {} cells, {} bits", bc, bb);
    expect(wc <= SCCP_WALLET_STATE_CELLS).toBeTrue();
    expect(wb <= SCCP_WALLET_STATE_BITS).toBeTrue();
    expect(bc <= SCCP_BUCKET_STATE_CELLS).toBeTrue();
    expect(bb <= SCCP_BUCKET_STATE_BITS).toBeTrue();
}

/// Exact account data inspection and replacement for parser/capacity fixtures.
fun recoveryAccountData(target: address): cell {
    val account = testing.getShardAccount(target)!.account.load();
    if (account is TlbAccountInfo) {
        val state = account.storage.state;
        if (state is TlbAccountStateActive) {
            return state.stateInit.data!;
        }
    }
    throw SccpErrors.InvalidMessage;
}

fun replaceRecoveryAccountData(target: address, data: cell) {
    var shard = testing.getShardAccount(target)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        var info = account;
        val state = info.storage.state;
        if (state is TlbAccountStateActive) {
            var active = state;
            active.stateInit.data = data;
            info.storage.state = active;
            shard.account = (info.toCell() as cell) as Cell<TlbAccount>;
            testing.setShardAccount(target, shard);
            return;
        }
    }
    throw SccpErrors.InvalidMessage;
}

get fun `test recovery destination saturation precedes effect and stale deletion cannot erase reused capacity`() {
    val env = setupEnv();
    val wallet = SccpTairaXorWallet.fromStorage({
        jettonBalance: 0,
        ownerAddress: env.deployer,
        minterAddress: env.minter.address,
        recovery: maximumRecoveryReceipts(SCCP_RECOVERY_MINT).toCell(),
    });
    expect(
        net.send(
            env.deployer,
            createMessage({ dest: {
                    workchain: 0,
                    stateInit: wallet.stateInit!,
                }, value: sccpWalletRecoveryFloor() +
                    grams("1"), bounce: BounceMode.NoBounce, body: TopUpTons { queryId: 0 } }),
        ),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    val before = recoveryAccountData(wallet.address).hash();
    val full = wallet.sendSccpRecoveryDispatch(
        env.minter.address,
        SCCP_MAX_U64,
        SCCP_RECOVERY_MINT,
        1,
        0,
        1,
        7,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(full).toHaveFailedTx<SccpRecoveryDispatch>({
        to: wallet.address,
        exitCode: SccpErrors.RecoveryFull as int,
    });
    expect(recoveryAccountData(wallet.address).hash()).toEqual(before);
    expect(wallet.getWalletData().jettonBalance).toEqual(0);
    // Repeating an existing effect is harmless even when all slots are occupied.
    val duplicate = wallet.sendSccpRecoveryDispatch(
        env.minter.address,
        1,
        SCCP_RECOVERY_MINT,
        SCCP_MAX_U64,
        0,
        1,
        7,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(duplicate).toHaveAllSuccessfulTxs();
    expect(wallet.getWalletData().jettonBalance).toEqual(0);
    val walletConfirm = wallet.sendSccpRecoveryConfirm(
        env.minter.address,
        1,
        SCCP_RECOVERY_MINT,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(walletConfirm).toHaveAllSuccessfulTxs();
    reportGas(
        "recovery wallet confirm at 512 receipts",
        walletConfirm.getUsedGas<SccpRecoveryConfirm>({ to: wallet.address }),
        SCCP_GAS_RECOVERY,
    );
    val walletDrop = wallet.sendSccpRecoveryDrop(
        env.minter.address,
        1,
        SCCP_RECOVERY_MINT,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    reportGas(
        "recovery wallet delete at 512 receipts",
        walletDrop.getUsedGas<SccpRecoveryDrop>({ to: wallet.address }),
        SCCP_GAS_RECOVERY,
    );

    val admitted = wallet.sendSccpRecoveryDispatch(
        env.minter.address,
        SCCP_MAX_U64,
        SCCP_RECOVERY_MINT,
        1,
        0,
        1,
        7,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(admitted).toHaveAllSuccessfulTxs();
    reportGas(
        "recovery wallet insert at 512 receipts",
        recoveryGas(admitted, wallet.address, SCCP_RECOVERY_MINT, false),
        SCCP_GAS_RECOVERY,
    );
    expect(wallet.getWalletData().jettonBalance).toEqual(7);
    wallet.sendSccpRecoveryDrop(
        env.minter.address,
        1,
        SCCP_RECOVERY_MINT,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    val receipts = WalletStorage.fromCell(recoveryAccountData(wallet.address)).recovery.load();
    expect(receipts.count).toEqual(512);
    expect(receipts.confirm(SCCP_MAX_U64, SCCP_RECOVERY_MINT, 1)).toEqual(SCCP_RECEIPT_APPLIED);

    val bucket = SccpConsumedBucket.fromStorage({
        minterAddress: env.minter.address,
        index: 0,
        activated: true,
        bitsHi: 0,
        bitsLo: 0,
        recovery: maximumRecoveryReceipts(SCCP_RECOVERY_CONSUME).toCell(),
    });
    expect(
        net.send(
            env.deployer,
            createMessage({ dest: {
                    workchain: 0,
                    stateInit: bucket.stateInit!,
                }, value: sccpBucketFloor() +
                    grams("1"), bounce: BounceMode.NoBounce, body: TopUpTons { queryId: 0 } }),
        ),
    ).toHaveSuccessfulDeploy({ to: bucket.address });
    val bucketBefore = recoveryAccountData(bucket.address).hash();
    val bucketFull = bucket.sendSccpRecoveryDispatch(
        env.minter.address,
        SCCP_MAX_U64,
        SCCP_RECOVERY_CONSUME,
        1,
        0,
        1,
        0,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(bucketFull).toHaveFailedTx<SccpRecoveryDispatch>({
        to: bucket.address,
        exitCode: SccpErrors.RecoveryFull as int,
    });
    expect(recoveryAccountData(bucket.address).hash()).toEqual(bucketBefore);
    expect(bucket.isConsumed(0)).toBeFalse();
    val bucketConfirm = bucket.sendSccpRecoveryConfirm(
        env.minter.address,
        1,
        SCCP_RECOVERY_CONSUME,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(bucketConfirm).toHaveAllSuccessfulTxs();
    reportGas(
        "recovery bucket confirm at 512 receipts",
        bucketConfirm.getUsedGas<SccpRecoveryConfirm>({ to: bucket.address }),
        SCCP_GAS_RECOVERY,
    );
    val bucketDrop = bucket.sendSccpRecoveryDrop(
        env.minter.address,
        1,
        SCCP_RECOVERY_CONSUME,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    reportGas(
        "recovery bucket delete at 512 receipts",
        bucketDrop.getUsedGas<SccpRecoveryDrop>({ to: bucket.address }),
        SCCP_GAS_RECOVERY,
    );

    val consume = bucket.sendSccpRecoveryDispatch(
        env.minter.address,
        SCCP_MAX_U64,
        SCCP_RECOVERY_CONSUME,
        1,
        0,
        1,
        0,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    expect(consume).toHaveAllSuccessfulTxs();
    reportGas(
        "recovery bucket insert at 512 receipts",
        recoveryGas(consume, bucket.address, SCCP_RECOVERY_CONSUME, false),
        SCCP_GAS_RECOVERY,
    );
    expect(bucket.isConsumed(0)).toBeTrue();
    bucket.sendSccpRecoveryDrop(
        env.minter.address,
        1,
        SCCP_RECOVERY_CONSUME,
        SCCP_MAX_U64,
        0,
        env.deployer,
        { value: grams("1"), bounce: true },
    );
    val bucketReceipts = BucketStorage
        .fromCell(recoveryAccountData(bucket.address))
        .recovery
        .load();
    expect(bucketReceipts.count).toEqual(512);
    expect(bucketReceipts.confirm(SCCP_MAX_U64, SCCP_RECOVERY_CONSUME, 1)).toEqual(
        SCCP_RECEIPT_APPLIED,
    );
}

get fun `test recovery destination funding precedes receipt and monetary effect`() {
    val env = setupEnv();
    val wallet = SccpTairaXorWallet.fromStorage({
        jettonBalance: 0,
        ownerAddress: env.deployer,
        minterAddress: env.minter.address,
        recovery: RecoveryReceipts.empty().toCell(),
    });
    expect(
        net.send(
            env.deployer,
            createMessage({ dest: {
                    workchain: 0,
                    stateInit: wallet.stateInit!,
                }, value: grams("0.01"), bounce: BounceMode.NoBounce, body: TopUpTons {
                    queryId: 0,
                } }),
        ),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    val before = recoveryAccountData(wallet.address).hash();
    val poor = wallet.sendSccpRecoveryDispatch(
        env.minter.address,
        1,
        SCCP_RECOVERY_MINT,
        1,
        0,
        1,
        7,
        0,
        env.deployer,
        { value: grams("0.01"), bounce: true },
    );
    expect(poor).toHaveFailedTx<SccpRecoveryDispatch>({
        to: wallet.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(recoveryAccountData(wallet.address).hash()).toEqual(before);
    expect(wallet.getWalletData().jettonBalance).toEqual(0);
    val bucket = SccpConsumedBucket.fromStorage({
        minterAddress: env.minter.address,
        index: 0,
        activated: true,
        bitsHi: 0,
        bitsLo: 0,
        recovery: RecoveryReceipts.empty().toCell(),
    });
    expect(
        net.send(
            env.deployer,
            createMessage({ dest: {
                    workchain: 0,
                    stateInit: bucket.stateInit!,
                }, value: grams("0.01"), bounce: BounceMode.NoBounce, body: TopUpTons {
                    queryId: 0,
                } }),
        ),
    ).toHaveSuccessfulDeploy({ to: bucket.address });
    val bucketBefore = recoveryAccountData(bucket.address).hash();
    val bucketPoor = bucket.sendSccpRecoveryDispatch(
        env.minter.address,
        1,
        SCCP_RECOVERY_CONSUME,
        1,
        0,
        1,
        0,
        0,
        env.deployer,
        { value: grams("0.01"), bounce: true },
    );
    expect(bucketPoor).toHaveFailedTx<SccpRecoveryDispatch>({
        to: bucket.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(recoveryAccountData(bucket.address).hash()).toEqual(bucketBefore);
    expect(bucket.isConsumed(0)).toBeFalse();
}

get fun `test recovery child storage without mandatory receipts reference fails closed`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 7, alice);
    val targets = [walletOf(env, alice).address, bucketOf(env, 0).address];
    var i = 0;
    repeat (2) {
        val target = targets.get(i);
        var data = recoveryAccountData(target).beginParse();
        expect(data.remainingRefsCount()).toEqual(1);
        val missing = beginCell().storeSlice(data.loadBits(data.remainingBitsCount())).endCell();
        replaceRecoveryAccountData(target, missing);
        val sent = net.send(
            env.minter.address,
            createMessage({
                bounce: BounceMode.NoBounce,
                dest: target,
                value: grams("1"),
                body: SccpRecoveryConfirm {
                    operationId: 1,
                    stage: i == 0 ? SCCP_RECOVERY_MINT : SCCP_RECOVERY_CONSUME,
                    attempt: 1,
                    queryId: 0,
                    response: env.deployer,
                },
            }),
        );
        expect(sent).toHaveFailedTx<SccpRecoveryConfirm>({ to: target, exitCode: 9 });
        expect(recoveryAccountData(target).hash()).toEqual(missing.hash());
        i += 1;
    }
}

get fun `test recovery concurrent retry cannot redirect original in flight excess`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val attacker = testing.treasury("racing-retry").address;
    val d = deliverDefault(env, 0, 77, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    val original = recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    val prepared = original.outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(prepared.response).toEqual(env.deployer);
    val originalTail = minterStorage(env)
        .recovery
        .load()
        .operations
        .mustGet(prepared.operationId)
        .load()
        .tail;
    val retryCursor = testing.createTraceIterationCursor(
        attacker,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            dest: env.minter.address,
            value: env.minter.retryRequiredValue(),
            body: SccpRetry {
                queryId: 99,
                response: attacker,
                operationId: prepared.operationId,
            },
        }),
    );
    val retryStep = retryCursor.executeN(1).at(0);
    retryCursor.close();
    expect(retryStep.outMessages.at<SccpRecoveryConfirm>(0).loadBody().response).toEqual(attacker);
    expect(
        minterStorage(env)
            .recovery
            .load()
            .operations
            .mustGet(prepared.operationId)
            .load()
            .tail
            .hash(),
    ).toEqual(originalTail.hash());
    val completed = net.send(walletOf(env, alice).address, forwardOut(original, 0));
    expect(completed).toHaveAllSuccessfulTxs();
    expect(completed).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(completed).toNotHaveTx<ReturnExcessesBack>({ to: attacker });
    expect(jettonBalanceOf(env, alice)).toEqual(77);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    // Delayed confirmation cannot restart a completed mint or allocate another row.
    val late = net.send(env.minter.address, forwardOut(retryStep, 0));
    expect(late).toHaveAllSuccessfulTxs();
    expect(late).toNotHaveTx<SccpRecoveryDispatch>({});
    expect(jettonBalanceOf(env, alice)).toEqual(77);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
}

get fun `test recovery admission and acknowledgements stay funded at 512 retained minter rows`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 7, alice);
    var storage = minterStorage(env);
    var book = maximumRecoveryBook();
    book.complete(1);
    book.nextId = SCCP_MAX_U64 - 1;
    storage.recovery = book.toCell();
    storage.deployedBuckets = book.activatedBuckets;
    setMinterStorage(env, storage);
    val d = deliverDefault(env, 1, 77, alice);
    val result = testing.processSingleTraceStep(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            dest: env.minter.address,
            value: finalizeValue(env, 1),
            body: SccpFinalize {
                queryId: 3,
                response: env.deployer,
                cert: d.cert as Cell<TairaCert>,
                message: d.proof as Cell<MessageProof>,
            },
        }),
    );
    reportGas(
        "recovery minter admission at 512 rows n=31",
        result.gasUsed,
        SCCP_GAS_MINTER_FINALIZE,
    );
    expect(minterStorage(env).recovery.load().count).toEqual(512);
    val cursor = testing.createTraceIterationCursor(
        env.minter.address,
        forwardOut(result, result.outMessages.size() - 1),
    );
    val completed = cursor.executeAllRemaining();
    cursor.close();
    expect(completed).toHaveAllSuccessfulTxs();
    reportGas(
        "recovery minter consume acknowledgement at 512 rows",
        recoveryGas(completed, env.minter.address, SCCP_RECOVERY_CONSUME, true),
        SCCP_GAS_RECOVERY,
    );
    reportGas(
        "recovery minter mint acknowledgement at 512 rows",
        recoveryGas(completed, env.minter.address, SCCP_RECOVERY_MINT, true),
        SCCP_GAS_RECOVERY,
    );
    expect(minterStorage(env).recovery.load().count).toEqual(511);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(84);
    expect(jettonBalanceOf(env, alice)).toEqual(84);
    expect(testing.getAccountBalance(env.minter.address) >= sccpMinterFloor()).toBeTrue();
}

get fun `test recovery failed Finalized event keeps completed mint custody until one funded retry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 77, alice);
    val cursor = testing.createTraceIterationCursor(env.deployer, recoveryFinalizeMessage(env, d));
    val mint = recoverUntilDispatch(cursor, SCCP_RECOVERY_MINT);
    val op = mint.outMessages.at<SccpRecoveryAck>(0).loadBody().operationId;
    cursor.executeTill<SccpRecoveryDrop>({ to: walletOf(env, alice).address });
    expect(
        WalletStorage
            .fromCell(recoveryAccountData(walletOf(env, alice).address))
            .recovery
            .load()
            .count,
    ).toEqual(0);
    expect(minterStorage(env).recovery.load().operations.mustGet(op).load().phase).toEqual(
        SCCP_RECOVERY_DROP,
    );
    expect(env.minter.getSccpState().opCount).toEqual(0);
    val previous = testing.getConfig();
    var expensive = previous;
    var prices = expensive.getMsgForwardPrices(BASECHAIN);
    prices.lumpPrice *= 1000000;
    expensive.setMsgForwardPrices(prices, BASECHAIN);
    expect(testing.setConfig(expensive)).toBeTrue();
    val failed = cursor.executeAllRemaining();
    cursor.close();
    expect(testing.setConfig(previous)).toBeTrue();
    expect(failed).toHaveTx<SccpRecoveryAck>({ to: env.minter.address, success: false });
    expectEvents(failed, []);
    expect(minterStorage(env).recovery.load().operations.mustGet(op).load().phase).toEqual(
        SCCP_RECOVERY_DROP,
    );
    expect(env.minter.getSccpState().opCount).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(77);
    expect(env.minter.getSccpState().totalSupply).toEqual(77);
    val retry = sendRetry(env, op, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toNotHaveTx<SccpRecoveryDispatch>({});
    expectEvents(
        retry,
        [
            SccpFinalizedEvent {
                messageId: d.messageId,
                nonce: 0,
            }.toCell(),
        ],
    );
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(77);
}

get fun `test recovery deepest dictionary path stays bounded at full custody`() {
    val env = setupEnv();
    var storage = minterStorage(env);
    var book = RecoveryBook.empty();
    var i = 0;
    repeat (512) {
        // Key 1 has a different neighbour at every higher bit: 63 successive
        // Patricia forks, unlike the balanced graph that maximizes space.
        val id = i == 0 ? 1 : i < 64 ? (1 << i) | 1 : (1 << 63) | ((i - 63) << 1) | 1;
        var operation = testRecoveryOperation(i);
        operation.queryId = i;
        book.operations.set(id, operation.toCell());
        i += 1;
    }
    book.count = 512;
    book.nextId = SCCP_MAX_U64;
    book.activatedBuckets = 1;
    storage.deployedBuckets = 1;
    storage.pendingSupply = 1000;
    storage.recovery = book.toCell();
    setMinterStorage(env, storage);
    val before = minterStorage(env).toCell().hash();
    val retry = sendRetry(env, 1, env.minter.retryRequiredValue());
    expect(retry).toHaveSuccessfulTx<SccpRetry>({ to: env.minter.address });
    expect(retry).toNotHaveTx<SccpRecoveryDispatch>({});
    reportGas(
        "recovery minter confirm retry at 63 dictionary forks",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    // Authenticated positive ACK writes the same deep key; no destination
    // effect is delivered in this white-box gas fixture.
    val prepared = testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        createMessage({
            dest: env.minter.address,
            value: grams("1"),
            bounce: BounceMode.Only256BitsOfBody,
            body: SccpRecoveryAck {
                operationId: 1,
                stage: SCCP_RECOVERY_CONSUME,
                attempt: 1,
                result: SCCP_RECEIPT_APPLIED,
                queryId: 0,
                response: env.deployer,
            },
        }),
    );
    expect(minterStorage(env).recovery.load().operations.mustGet(1).load().phase).toEqual(
        SCCP_RECOVERY_DROP,
    );
    expect(minterStorage(env).recovery.load().count).toEqual(512);
    reportGas(
        "recovery minter prepared at 63 dictionary forks",
        prepared.gasUsed,
        SCCP_GAS_RECOVERY,
    );

    val dropped = testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        createMessage({
            dest: env.minter.address,
            value: grams("1"),
            bounce: BounceMode.Only256BitsOfBody,
            body: SccpRecoveryAck {
                operationId: 1,
                stage: SCCP_RECOVERY_CONSUME,
                attempt: 1,
                result: SCCP_RECEIPT_DROPPED,
                queryId: 0,
                response: env.deployer,
            },
        }),
    );
    expect(minterStorage(env).recovery.load().operations.mustGet(1).load().stage).toEqual(
        SCCP_RECOVERY_MINT,
    );
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    reportGas(
        "recovery minter consume completion at 63 dictionary forks",
        dropped.gasUsed,
        SCCP_GAS_RECOVERY,
    );
    val wallet = env.minter.getWalletAddress(testRecoveryOperation(0).tail.load().recipient!);
    val dispatched = dropped.outMessages.at<SccpRecoveryDispatch>(0).loadBody();
    val bounced = net.send(wallet, bouncedMessage(dispatched, env.minter.address, grams("0.1")));
    expect(minterStorage(env).recovery.load().operations.mustGet(1).load().phase).toEqual(
        SCCP_RECOVERY_FAILED,
    );
    reportGas(
        "recovery minter original bounce at 63 dictionary forks",
        bounced.getUsedGas({ to: env.minter.address, bounced: true }),
        SCCP_GAS_MINTER_BOUNCE,
    );
    val retryFailed = sendRetry(env, 1, env.minter.retryRequiredValue());
    expect(retryFailed).toHaveSuccessfulTx<SccpRetry>({ to: env.minter.address });
    reportGas(
        "recovery minter failed retry at 63 dictionary forks",
        retryFailed.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
}
