// Bucket activation, replay flags and durable asynchronous recovery. A lost
// Prepared ACK retains the effect and receipt until Confirm/Drop completes;
// only an authenticated original Dispatch bounce proves the effect failed.

import "@stdlib/exotic-cells"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-messages"
import "@contracts/sccp-recovery"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// The inline `sccp_finalize` of `d` as a message from the deployer.
fun finalizeMessage(env: Env, d: Delivery, value: coins): OutMessage {
    return createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value,
        dest: env.minter.address,
        body: SccpFinalize {
            queryId: 1,
            response: env.deployer,
            cert: d.cert as Cell<TairaCert>,
            message: d.proof as Cell<MessageProof>,
        },
    });
}

/// Sets `GLOBALID` of the emulated chain (config parameter 19).
fun setGlobalId(id: int) {
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(id, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
}

/// Sends `sccp_deploy_buckets` for `count` buckets with `value` attached.
fun sendDeployBuckets(env: Env, count: int, value: coins): SendResultList {
    return env
        .minter
        .sendSccpDeployBuckets(env.deployer, 2, env.deployer, count, { value, bounce: true });
}

/// Inject one exact current-stage command from a chosen sender.
fun bucketDispatch(
    env: Env,
    index: int,
    sender: address,
    operationId: int,
    stage: int,
    nonce: int,
    count: int,
): SendResultList {
    return bucketOf(env, index).sendSccpRecoveryDispatch(
        sender,
        operationId,
        stage,
        1,
        nonce,
        count,
        0,
        0,
        env.deployer,
        { value: sccpBucketFloor() + grams("1"), bounce: true },
    );
}

/// Fund canonical StateInit through the explicit top-up entry point.
fun deployCanonicalBucket(env: Env, index: int, sender: address, value: coins): SendResultList {
    val bucket = canonicalBucket(env, index);
    return net.send(
        sender,
        createMessage({
            bounce: BounceMode.NoBounce,
            value,
            dest: { workchain: BASECHAIN, stateInit: bucket.stateInit! },
            body: TopUpTons { queryId: 0 },
        }),
    );
}

/// Observe a retained operation without assuming that its id equals its nonce.
fun bucketOperation(env: Env, operationId: int): RecoveryOperation {
    return minterStorage(env).recovery.load().operations.mustGet(operationId).load();
}

/// Seconds of the default pin: `cur.untilMs` is 14 days after `T0`.
const PIN_VALIDITY_S = 1209600

get fun `test unsolicited consume tails cannot reach recovery forwarding or minting`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    val canonical = ConsumeTail {
        kind: SCCP_CONSUME_KIND_MINT,
        recipient: alice,
        response: alice,
        messageId: 1,
    }.toCell();
    testing.registerLibrary(canonical);
    val malformed: array<cell> = [
        canonical.toLibraryReference(),
        beginCell().storeSlice(canonical.beginParse()).storeUint(0, 1).endCell(),
        beginCell().storeSlice(canonical.beginParse()).storeRef(snakeOfLength(12700)).endCell(),
        beginCell().endCell(),
    ];
    val before = minterStorage(env).toCell().hash();
    var i = 0;
    repeat (malformed.size()) {
        // Current recovery dispatch/ACK contains no untrusted tail at all.
        // Retired tail-bearing opcodes are not accepted, even with valid sender.
        val opcodes: array<int> = [0x53434331, 0x53434332, 0x53434336];
        var j = 0;
        repeat (opcodes.size()) {
            val dest = j == 0 ? env.minter.getBucketAddress(0) : env.minter.address;
            val sender = j == 0 ? env.minter.address : env.minter.getBucketAddress(0);
            val sent = net.send(
                sender,
                createMessage({
                    bounce: BounceMode.NoBounce,
                    dest,
                    value: grams("1"),
                    body: beginCell()
                        .storeUint(opcodes.get(j), 32)
                        .storeRef(malformed.get(i))
                        .endCell(),
                }),
            );
            expect(sent).toHaveTx({ to: dest, success: false });
            expect(
                sent.findTransaction<SccpRecoveryAck>({ to: env.minter.address }) == null,
            ).toBeTrue();
            j += 1;
        }
        expect(isConsumedAt(env, 1)).toBeFalse();
        expect(minterStorage(env).toCell().hash()).toEqual(before);
        expect(jettonBalanceOf(env, alice)).toEqual(100);
        i += 1;
    }
}

get fun `test a bucket deployed early by a stranger stays inactive until the minter activates it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val stranger = testing.treasury("stranger").address;
    val bucket = canonicalBucket(env, 0);
    expect(bucket.address).toEqual(env.minter.getBucketAddress(0));
    expect(
        deployCanonicalBucket(env, 0, stranger, grams("0.5")),
    ).toHaveSuccessfulDeploy({ to: bucket.address });
    expect(bucket.isActivated()).toBeFalse();
    expect(
        bucketDispatch(
            env,
            0,
            stranger,
            100,
            SCCP_RECOVERY_ACTIVATE,
            0,
            0,
        ),
    ).toHaveFailedTx<SccpRecoveryDispatch>({ to: bucket.address, exitCode: SccpErrors.NotMinter as int });
    val stages: array<int> = [SCCP_RECOVERY_CONSUME, SCCP_RECOVERY_RANGE, SCCP_RECOVERY_UNCONSUME];
    var i = 0;
    repeat (stages.size()) {
        expect(
            bucketDispatch(
                env,
                0,
                env.minter.address,
                100 + i,
                stages.get(i),
                0,
                3,
            ),
        ).toHaveFailedTx<SccpRecoveryDispatch>({ to: bucket.address, exitCode: SccpErrors.BucketNotActive as int });
        i += 1;
    }
    val res = finalizeOk(env, 0, 10, alice);
    expect(recoveryStageCount(res, SCCP_RECOVERY_ACTIVATE)).toEqual(1);
    expect(bucket.isActivated()).toBeTrue();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(
        bucketDispatch(
            env,
            0,
            env.minter.address,
            110,
            SCCP_RECOVERY_ACTIVATE,
            1,
            0,
        ),
    ).toHaveFailedTx<SccpRecoveryDispatch>({ to: bucket.address, exitCode: SccpErrors.BadRange as int });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
}

get fun `test a bucket deployed early by a stranger is activated by sccp_deploy_buckets`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    // strangers deploy buckets 0 and 2 ahead of the minter
    expect(
        deployCanonicalBucket(env, 0, stranger, grams("0.5")),
    ).toHaveSuccessfulDeploy({
        to: env.minter.getBucketAddress(0),
    });
    expect(
        deployCanonicalBucket(env, 2, stranger, grams("0.5")),
    ).toHaveSuccessfulDeploy({
        to: env.minter.getBucketAddress(2),
    });
    // anyone may top a bucket up, active or not
    expect(
        bucketOf(env, 2).sendTopUpTons(stranger, 0, { value: grams("1") }),
    ).toHaveSuccessfulTx<TopUpTons>({ to: env.minter.getBucketAddress(2) });
    expect(bucketOf(env, 2).isActivated()).toBeFalse();
    val res = sendDeployBuckets(env, 3, env.minter.deployBucketsRequiredValue(3));
    expect(res).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(3);
    var i = 0;
    repeat (3) {
        val data = bucketOf(env, i).getBucketData();
        expect(data.activated).toBeTrue();
        expect(data.index).toEqual(i);
        expect(data.minterAddress).toEqual(env.minter.address);
        expect(data.bitsHi).toEqual(0);
        expect(data.bitsLo).toEqual(0);
        expect(
            testing.getAccountBalance(env.minter.getBucketAddress(i)) >= sccpBucketFloor(),
        ).toBeTrue();
        i += 1;
    }
    // bucket 3 was not asked for
    expect(testing.isDeployed(env.minter.getBucketAddress(3))).toBeFalse();
}

get fun `test sccp_deploy_buckets takes 1 to 16 buckets on ton mainnet`() {
    val env = setupEnv();
    expectOutcome(sendDeployBuckets(env, 0, grams("20")), SccpErrors.BadRange);
    expectOutcome(
        sendDeployBuckets(env, SCCP_MAX_DEPLOY_BUCKETS_PER_CALL + 1, grams("20")),
        SccpErrors.BadRange,
    );
    setGlobalId(-3);
    expectOutcome(sendDeployBuckets(env, 1, grams("20")), SccpErrors.WrongChain);
    // chain identity comes before the count
    expectOutcome(sendDeployBuckets(env, 0, grams("20")), SccpErrors.WrongChain);
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(0);
    val res = sendDeployBuckets(
        env,
        SCCP_MAX_DEPLOY_BUCKETS_PER_CALL,
        env.minter.deployBucketsRequiredValue(SCCP_MAX_DEPLOY_BUCKETS_PER_CALL),
    );
    expect(res).toHaveAllSuccessfulTxs();
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(SCCP_MAX_DEPLOY_BUCKETS_PER_CALL);
    expect(bucketOf(env, SCCP_MAX_DEPLOY_BUCKETS_PER_CALL - 1).isActivated()).toBeTrue();
    // deployments neither count as operations nor need a Live generation
    expect(env.minter.getSccpState().opCount).toEqual(0);
    testing.setNow(T0 + PIN_VALIDITY_S + 1);
    expect(
        sendDeployBuckets(env, 1, env.minter.deployBucketsRequiredValue(1)),
    ).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(17);
}

get fun `test a bucket holds the flags of its own 512 nonces`() {
    val env = setupEnv();
    expect(
        sendDeployBuckets(env, 2, env.minter.deployBucketsRequiredValue(2)),
    ).toHaveAllSuccessfulTxs();
    val bucket = bucketOf(env, 1);
    val nonces: array<int> = [512, 767, 768, 1023];
    var i = 0;
    repeat (nonces.size()) {
        val nonce = nonces.get(i);
        expect(bucket.isConsumed(nonce)).toBeFalse();
        expect(
            bucketDispatch(
                env,
                1,
                env.minter.address,
                100 + i,
                SCCP_RECOVERY_CONSUME,
                nonce,
                1,
            ),
        ).toHaveSuccessfulTx<SccpRecoveryDispatch>({ to: bucket.address });
        expect(bucket.isConsumed(nonce)).toBeTrue();
        i += 1;
    }
    val (hi, lo) = bucket.getBits();
    expect(lo).toEqual(1 | (1 << 255));
    expect(hi).toEqual(1 | (1 << 255));
    expect(bucket.isConsumed(513)).toBeFalse();
    val outside: array<int> = [511, 1024];
    i = 0;
    repeat (outside.size()) {
        val stages: array<int> = [SCCP_RECOVERY_CONSUME, SCCP_RECOVERY_UNCONSUME];
        var j = 0;
        repeat (stages.size()) {
            expect(
                bucketDispatch(
                    env,
                    1,
                    env.minter.address,
                    200 + i * 2 + j,
                    stages.get(j),
                    outside.get(i),
                    1,
                ),
            ).toHaveFailedTx<SccpRecoveryDispatch>({
                to: bucket.address,
                exitCode: SccpErrors.BadNonce as int,
            });
            j += 1;
        }
        i += 1;
    }
    val (hi2, lo2) = bucket.getBits();
    expect(hi2).toEqual(hi);
    expect(lo2).toEqual(lo);
    val (hi0, lo0) = bucketOf(env, 0).getBits();
    expect(hi0 | lo0).toEqual(0);
}

get fun `test a deleted bucket recreated by a third party never accepts flags again`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val stranger = testing.treasury("stranger").address;
    // nonce 0 is minted
    val minted = deliverDefault(env, 0, 10, alice);
    expect(sendFinalize(env, env.deployer, minted, finalizeValue(env, 0))).toHaveAllSuccessfulTxs();
    val bucket = env.minter.getBucketAddress(0);
    // the bucket is deleted for unpaid rent, and a third party deploys its
    // canonical StateInit again, with clear flags
    testing.setShardAccount(bucket, null);
    expect(deployCanonicalBucket(env, 0, stranger, grams("1"))).toHaveSuccessfulDeploy({
        to: bucket,
    });
    expect(canonicalBucket(env, 0).isActivated()).toBeFalse();
    expect(isConsumedAt(env, 0)).toBeFalse();
    // a fresh nonce of the bucket cannot be finalized: the consume bounces
    val fresh = deliverDefault(env, 1, 10, alice);
    val fin = sendFinalize(env, env.deployer, fresh, finalizeValue(env, 1));
    expect(fin).toHaveFailedTx<SccpRecoveryDispatch>({
        to: bucket,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(recoveryStageCount(fin, SCCP_RECOVERY_ACTIVATE)).toEqual(0);
    expect(recoveryStageCount(fin, SCCP_RECOVERY_MINT)).toEqual(0);
    // the minted nonce cannot be voided after its deadline either
    testing.setNow(T0 + 86400 + 1);
    val void = sendVoidExpired(env, env.deployer, 0, minted, env.minter.voidRequiredValue(0));
    expect(void).toHaveFailedTx<SccpRecoveryDispatch>({
        to: bucket,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(
        void.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    // nor through a frozen void once the generation expired
    testing.setNow(T0 + PIN_VALIDITY_S + 1);
    val frozen = sendVoidFrozen(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
    expect(frozen).toHaveFailedTx<SccpRecoveryDispatch>({
        to: bucket,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(
        frozen.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(10);
    expect(state.opCount).toEqual(1);
    expect(state.deployedBuckets).toEqual(1);
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}

get fun `test a failed prepared acknowledgement retains pending supply until confirmation`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 700, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val consume = recoverUntilDispatch(cursor, SCCP_RECOVERY_CONSUME);
    cursor.close();
    val ack = consume.outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(700);
    // The destination's effect already happened; a failed Prepared delivery
    // cannot authorize supply release, receipt erasure or another consume.
    val bounced = testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(ack, env.minter.getBucketAddress(0), grams("0.01")),
    );
    expect(bounced.outMessages.size()).toEqual(0);
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(700);
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(env.minter.getSccpState().opCount).toEqual(0);
    val retry = sendRetry(env, ack.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(recoveryStageCount(retry, SCCP_RECOVERY_CONSUME)).toEqual(0);
    expect(recoveryStageCount(retry, SCCP_RECOVERY_MINT)).toEqual(1);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(700);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(700);
}

get fun `test a lost rejected consume acknowledgement preserves the old mint and releases only after drop`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 5, 1000, alice);
    val d = deliverDefault(env, 5, 1000, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 5)),
    );
    val consume = recoverUntilDispatch(cursor, SCCP_RECOVERY_CONSUME);
    cursor.close();
    val ack = consume.outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(ack.result).toEqual(SCCP_RECEIPT_REJECTED);
    expect(env.minter.getSccpState().pendingSupply).toEqual(1000);
    testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(ack, env.minter.getBucketAddress(0), grams("0.01")),
    );
    expect(isConsumedAt(env, 5)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(1000);
    val delivered = sendRetry(env, ack.operationId, env.minter.retryRequiredValue());
    expect(delivered).toHaveAllSuccessfulTxs();
    expect(recoveryStageCount(delivered, SCCP_RECOVERY_MINT)).toEqual(0);
    reportGas(
        "minter rejected consume recovery",
        recoveryGas(
            delivered,
            env.minter.address,
            SCCP_RECOVERY_CONSUME,
            true,
        ),
        SCCP_GAS_RECOVERY,
    );
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
}

get fun `test a bounced void acknowledgement retains the flag and reserves no supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 40, alice);
    val expired = deliver(
        env,
        env.committee,
        env.generation,
        1,
        5,
        alice,
        T0 * 1000 + 10000,
        1,
        3,
    );
    testing.setNow(T0 + 11);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: env.minter.voidRequiredValue(1),
            dest: env.minter.address,
            body: SccpVoidExpired {
                queryId: 8,
                response: env.deployer,
                nonce: 1,
                cert: expired.cert as Cell<TairaCert>,
                message: expired.proof as Cell<MessageProof>,
            },
        }),
    );
    val consume = recoverUntilDispatch(cursor, SCCP_RECOVERY_CONSUME);
    cursor.close();
    val ack = consume.outMessages.at<SccpRecoveryAck>(0).loadBody();
    val operation = bucketOperation(env, ack.operationId);
    expect(operation.nonce).toEqual(1);
    expect(operation.amount).toEqual(0);
    expect(operation.tail.load().kind).toEqual(SCCP_CONSUME_KIND_VOID);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(ack, env.minter.getBucketAddress(0), grams("0.01")),
    );
    expect(isConsumedAt(env, 1)).toBeTrue();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().totalSupply).toEqual(40);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    val recovered = sendRetry(env, ack.operationId, env.minter.retryRequiredValue());
    expect(recovered).toHaveAllSuccessfulTxs();
    expect(recovered).toEmitExternalMessage<SccpVoidedEvent>();
    expect(recoveryStageCount(recovered, SCCP_RECOVERY_CONSUME)).toEqual(0);
    expect(env.minter.getSccpState().opCount).toEqual(2);
    val again = sendVoidExpired(env, env.deployer, 1, expired, env.minter.voidRequiredValue(1));
    expect(again).toHaveAllSuccessfulTxs();
    expect(
        again.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().opCount).toEqual(2);
}

get fun `test consume acknowledgements are accepted only from the canonical bucket`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 300, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val consume = recoverUntilDispatch(cursor, SCCP_RECOVERY_CONSUME);
    cursor.close();
    val ack = consume.outMessages.at<SccpRecoveryAck>(0).loadBody();
    val before = minterStorage(env).toCell().hash();
    val strangers: array<address> = [
        testing.treasury("stranger").address,
        env.minter.getBucketAddress(1),
    ];
    var i = 0;
    repeat (strangers.size()) {
        val res = sendToMinter(env, strangers.get(i), ack, grams("1"));
        expect(res).toHaveFailedTx<SccpRecoveryAck>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadRecovery as int });
        expect(minterStorage(env).toCell().hash()).toEqual(before);
        i += 1;
    }
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    val own = net.send(env.minter.getBucketAddress(0), forwardOut(consume, 0));
    expect(own).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(300);
    expect(jettonBalanceOf(env, alice)).toEqual(300);
}

get fun `test a bounced unconsume retains its operation across repeated funded retries`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val (step, index) = recoverBeforeDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    val transfer = step.outMessages.at<SccpRecoveryDispatch>(index).loadBody();
    val operationId = transfer.operationId;
    val bucket = env.minter.getBucketAddress(0);
    val saved = testing.getShardAccount(bucket)!;
    testing.setShardAccount(bucket, null);
    val bounce = net.send(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, grams("0.05")),
    );
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(bucketOperation(env, operationId).stage).toEqual(SCCP_RECOVERY_UNCONSUME);
    expect(bucketOperation(env, operationId).phase).toEqual(SCCP_RECOVERY_FAILED);
    expect(
        sendRetry(env, operationId + 100, env.minter.retryRequiredValue()),
    ).toHaveFailedTx<SccpRetry>({ to: env
            .minter
            .address, exitCode: SccpErrors.NothingToRetry as int });
    expect(
        sendRetry(env, operationId, sccpRetryRequiredValue() - 1),
    ).toHaveFailedTx<SccpRetry>({ to: env
            .minter
            .address, exitCode: SccpErrors.NotEnoughValue as int });
    setGlobalId(-3);
    expectOutcome(
        sendRetry(env, operationId, env.minter.retryRequiredValue()),
        SccpErrors.WrongChain,
    );
    expectOutcome(
        sendRetry(env, operationId + 100, env.minter.retryRequiredValue()),
        SccpErrors.WrongChain,
    );
    setGlobalId(SCCP_TON_GLOBAL_ID);
    val early = sendRetry(env, operationId, env.minter.retryRequiredValue());
    expect(early).toHaveSuccessfulTx<SccpRetry>({ to: env.minter.address });
    expect(early).toHaveTx<SccpRecoveryDispatch>({ to: bucket, success: false });
    expect(bucketOperation(env, operationId).phase).toEqual(SCCP_RECOVERY_FAILED);
    expect(bucketOperation(env, operationId).attempt).toEqual(1);
    testing.setShardAccount(bucket, saved);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val retry = sendRetry(env, operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(recoveryStageCount(retry, SCCP_RECOVERY_UNCONSUME)).toEqual(1);
    reportGas(
        "minter retry unconsume",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expectOutcome(
        sendRetry(env, operationId, env.minter.retryRequiredValue()),
        SccpErrors.NothingToRetry,
    );
    finalizeOk(env, 0, 500, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test a mint in flight across a latch recovers a bounced unconsume without a live generation`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 300, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val consume = recoverUntilDispatch(cursor, SCCP_RECOVERY_CONSUME);
    cursor.close();
    val ack = consume.outMessages.at<SccpRecoveryAck>(0).loadBody();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    // Finish receipt deletion, stopping before the newly authorized unconsume.
    val finish = testing.createTraceIterationCursor(
        env.minter.getBucketAddress(0),
        forwardOut(consume, 0),
    );
    val (step, index) = recoverBeforeDispatch(finish, SCCP_RECOVERY_UNCONSUME);
    finish.close();
    val unconsume = step.outMessages.at<SccpRecoveryDispatch>(index).loadBody();
    val bucket = env.minter.getBucketAddress(0);
    val saved = testing.getShardAccount(bucket)!;
    testing.setShardAccount(bucket, null);
    val bounced = net.send(env.minter.address, forwardOut(step, index));
    expect(bounced).toHaveTx<SccpRecoveryDispatch>({ to: bucket, success: false });
    expect(bucketOperation(env, ack.operationId).phase).toEqual(SCCP_RECOVERY_FAILED);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(env.minter.getSccpState().opCount).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    testing.setShardAccount(bucket, saved);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val refused = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(refused).toHaveAllSuccessfulTxs();
    expectEvents(refused, []);
    val retry = sendRetry(env, unconsume.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.Equivocated,
    );
    val voided = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveAllSuccessfulTxs();
    expect(voided).toEmitExternalMessage<SccpVoidedEvent>();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
}

get fun `test a bounced activation retains the admitted index and is retried once`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val step = testing.processSingleTraceStep(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: env.minter.deployBucketsRequiredValue(1),
            dest: env.minter.address,
            body: SccpDeployBuckets {
                queryId: 2,
                response: env.deployer,
                count: 1,
            },
        }),
    );
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
    val activation = step.outMessages.at<SccpRecoveryDispatch>(0).loadBody();
    expect(activation.nonce).toEqual(0);
    expect(activation.stage).toEqual(SCCP_RECOVERY_ACTIVATE);
    val stranger = testing.treasury("stranger").address;
    testing.processSingleTraceStep(
        stranger,
        bouncedMessage(activation, env.minter.address, grams("0.1")),
    );
    expect(bucketOperation(env, activation.operationId).phase).toEqual(SCCP_RECOVERY_WAIT);
    testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        bouncedMessage(activation, env.minter.address, grams("0.1")),
    );
    expect(bucketOperation(env, activation.operationId).phase).toEqual(SCCP_RECOVERY_FAILED);
    expect(testing.isDeployed(env.minter.getBucketAddress(0))).toBeFalse();
    val d = deliverDefault(env, 3, 40, alice);
    val early = sendFinalize(env, env.deployer, d, finalizeValue(env, 3));
    expectOutcome(early, SccpErrors.BucketNotActive);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    expect(recoveryStageCount(early, SCCP_RECOVERY_ACTIVATE)).toEqual(0);
    val retry = sendRetry(env, activation.operationId, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toHaveSuccessfulDeploy<SccpRecoveryDispatch>({ to: env
            .minter
            .getBucketAddress(0) });
    reportGas(
        "minter retry activation",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
    expect(
        testing.getAccountBalance(env.minter.getBucketAddress(0)) >= sccpBucketFloor(),
    ).toBeTrue();
    expectOutcome(
        sendRetry(env, activation.operationId, env.minter.retryRequiredValue()),
        SccpErrors.NothingToRetry,
    );
    finalizeOk(env, 3, 40, alice);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
}

get fun `test a mint bounce retains prepaid recovery even when balance cannot fund an outgoing message`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val (step, index) = recoverBeforeDispatch(cursor, SCCP_RECOVERY_MINT);
    cursor.close();
    val transfer = step.outMessages.at<SccpRecoveryDispatch>(index).loadBody();
    setAccountBalance(env.minter.address, 0);
    val bounced = testing.processSingleTraceStep(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, sccpGasFee(SCCP_GAS_MINTER_BOUNCE)),
    );
    expect(bounced.outMessages.size()).toEqual(0);
    reportGas("minter failed mint retained", bounced.gasUsed, SCCP_GAS_MINTER_BOUNCE);
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(bucketOperation(env, transfer.operationId).stage).toEqual(SCCP_RECOVERY_UNCONSUME);
    expect(bucketOperation(env, transfer.operationId).phase).toEqual(SCCP_RECOVERY_FAILED);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val quote = env.minter.retryRequiredValue();
    expect(quote > sccpMinterFloor()).toBeTrue();
    expect(sendRetry(env, transfer.operationId, quote)).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(minterStorage(env).recovery.load().count).toEqual(0);
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
    finalizeOk(env, 0, 500, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
}
