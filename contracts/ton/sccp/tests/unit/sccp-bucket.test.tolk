// Bucket activation and asynchronous failure handling (specs/sccp.md §5.3.4
// "Finalize" steps 2–7 and "Retry"): only the minter activates a bucket, once
// per index, so a bucket deployed by anyone else (early, or again after a
// deletion for rent) never accepts flags; a failed `sccp_consumed` or
// `sccp_already_consumed` releases the pending supply through
// `sccp_consume_reverted`; a bounced `sccp_unconsume` or activation is
// recorded in `retries` and re-run by `sccp_retry`, also for a mint that was
// in flight when the minter latched.

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

/// Seconds of the default pin: `cur.untilMs` is 14 days after `T0`.
const PIN_VALIDITY_S = 1209600

get fun `test a bucket deployed early by a stranger stays inactive until the minter activates it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val stranger = testing.treasury("stranger").address;
    val bucket = canonicalBucket(env, 0);
    expect(bucket.address).toEqual(env.minter.getBucketAddress(0));
    expect(bucket.deploy(stranger, { value: grams("0.5") })).toHaveSuccessfulDeploy({
        to: bucket.address,
    });
    expect(bucket.isActivated()).toBeFalse();
    // only the minter activates, and an inactive bucket refuses every flag change
    expect(
        bucket.sendSccpActivateBucket(stranger, 0, 0, { value: grams("0.5"), bounce: true }),
    ).toHaveFailedTx<SccpActivateBucket>({
        to: bucket.address,
        exitCode: SccpErrors.NotMinter as int,
    });
    val tail: ConsumeTail = {
        kind: SCCP_CONSUME_KIND_MINT,
        recipient: alice,
        response: alice,
        messageId: 1,
    };
    expect(
        bucket.sendSccpConsume(
            env.minter.address,
            0,
            0,
            1,
            tail,
            { value: grams("1"), bounce: true },
        ),
    ).toHaveFailedTx<SccpConsume>({
        to: bucket.address,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(
        bucket.sendSccpConsumeRange(
            env.minter.address,
            0,
            0,
            3,
            { value: grams("1"), bounce: true },
        ),
    ).toHaveFailedTx<SccpConsumeRange>({
        to: bucket.address,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(
        bucket.sendSccpUnconsume(env.minter.address, 0, { value: grams("1"), bounce: true }),
    ).toHaveFailedTx<SccpUnconsume>({
        to: bucket.address,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    // the minter's first consume activates it and goes through
    val res = finalizeOk(env, 0, 10, alice);
    expect(res).toHaveSuccessfulTx<SccpActivateBucket>({ to: bucket.address });
    expect(bucket.isActivated()).toBeTrue();
    expect(isConsumedAt(env, 0)).toBeTrue();
    // an activation for another index is refused
    expect(
        bucket.sendSccpActivateBucket(
            env.minter.address,
            0,
            1,
            { value: grams("0.5"), bounce: true },
        ),
    ).toHaveFailedTx<SccpActivateBucket>({
        to: bucket.address,
        exitCode: SccpErrors.BadRange as int,
    });
    // the minter activated the index once and counts it
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
}

get fun `test a bucket deployed early by a stranger is activated by sccp_deploy_buckets`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    // strangers deploy buckets 0 and 2 ahead of the minter
    expect(
        canonicalBucket(env, 0).deploy(stranger, { value: grams("0.5") }),
    ).toHaveSuccessfulDeploy({
        to: env.minter.getBucketAddress(0),
    });
    expect(
        canonicalBucket(env, 2).deploy(stranger, { value: grams("0.5") }),
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
    val alice = testing.treasury("alice").address;
    expect(
        sendDeployBuckets(env, 2, env.minter.deployBucketsRequiredValue(2)),
    ).toHaveAllSuccessfulTxs();
    val tail: ConsumeTail = {
        kind: SCCP_CONSUME_KIND_VOID,
        recipient: null,
        response: alice,
        messageId: 1,
    };
    // the first and last nonce of each half of bucket 1 (minter forged as sender)
    val bucket = bucketOf(env, 1);
    val nonces: array<int> = [512, 767, 768, 1023];
    var i = 0;
    repeat (nonces.size()) {
        val nonce = nonces.get(i);
        expect(bucket.isConsumed(nonce)).toBeFalse();
        val res = bucket.sendSccpConsume(
            env.minter.address,
            0,
            nonce,
            0,
            tail,
            { value: grams("1"), bounce: true },
        );
        expect(res).toHaveSuccessfulTx<SccpConsume>({ to: bucket.address });
        expect(bucket.isConsumed(nonce)).toBeTrue();
        i += 1;
    }
    // flag `i` is bit `i` of `hi ‖ lo`
    val (hi, lo) = bucket.getBits();
    expect(lo).toEqual(1 | (1 << 255));
    expect(hi).toEqual(1 | (1 << 255));
    expect(bucket.isConsumed(513)).toBeFalse();
    // nonces 511 and 1024 belong to the neighbours
    val outside: array<int> = [511, 1024];
    i = 0;
    repeat (outside.size()) {
        val res = bucket.sendSccpConsume(
            env.minter.address,
            0,
            outside.get(i),
            0,
            tail,
            { value: grams("1"), bounce: true },
        );
        expect(res).toHaveFailedTx<SccpConsume>({
            to: bucket.address,
            exitCode: SccpErrors.BadNonce as int,
        });
        expect(
            bucket.sendSccpUnconsume(
                env.minter.address,
                outside.get(i),
                { value: grams("1"), bounce: true },
            ),
        ).toHaveFailedTx<SccpUnconsume>({
            to: bucket.address,
            exitCode: SccpErrors.BadNonce as int,
        });
        i += 1;
    }
    val (hi2, lo2) = bucket.getBits();
    expect(hi2).toEqual(hi);
    expect(lo2).toEqual(lo);
    // bucket 0 saw nothing
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
    expect(canonicalBucket(env, 0).deploy(stranger, { value: grams("1") })).toHaveSuccessfulDeploy({
        to: bucket,
    });
    expect(canonicalBucket(env, 0).isActivated()).toBeFalse();
    expect(isConsumedAt(env, 0)).toBeFalse();
    // a fresh nonce of the bucket cannot be finalized: the consume bounces
    val fresh = deliverDefault(env, 1, 10, alice);
    val fin = sendFinalize(env, env.deployer, fresh, finalizeValue(env, 1));
    expect(fin).toHaveFailedTx<SccpConsume>({
        to: bucket,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(fin).toNotHaveTx<SccpActivateBucket>({});
    expect(fin).toNotHaveTx<InternalTransferStep>({});
    // the minted nonce cannot be voided after its deadline either
    testing.setNow(T0 + 86400 + 1);
    val void = sendVoidExpired(env, env.deployer, 0, minted, env.minter.voidRequiredValue(0));
    expect(void).toHaveFailedTx<SccpConsume>({
        to: bucket,
        exitCode: SccpErrors.BucketNotActive as int,
    });
    expect(
        void.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    // nor through a frozen void once the generation expired
    testing.setNow(T0 + PIN_VALIDITY_S + 1);
    val frozen = sendVoidFrozen(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
    expect(frozen).toHaveFailedTx<SccpConsumeRange>({
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

get fun `test a forced failure of sccp_consumed bounces and releases the pending supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 700, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    // finalize, activation and consume: the flag is set and 700 is pending
    cursor.executeN(3);
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(700);
    // forwarding per cell rises before `sccp_consumed` runs: the minter can no
    // longer pay the multi-cell mint, so its action phase (event and mint) fails
    val previous = raiseCellForwardPrice(10000);
    val rest = cursor.executeAllRemaining();
    cursor.close();
    expect(testing.setConfig(previous)).toBeTrue();
    expect(rest).toHaveTx<SccpConsumed>({ to: env.minter.address, success: false });
    expect(rest).toHaveTx<SccpConsumed>({ to: env.minter.getBucketAddress(0), bounced: true });
    expect(rest).toHaveSuccessfulTx<SccpConsumeReverted>({ to: env.minter.address });
    expect(
        rest.findExternalOutMessage<SccpFinalizedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    expect(rest).toNotHaveTx<InternalTransferStep>({});
    // nothing is consumed or pending, and the message finalizes again
    expect(isConsumedAt(env, 0)).toBeFalse();
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.opCount).toEqual(0);
    finalizeOk(env, 0, 700, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(700);
}

get fun `test a bounced sccp_already_consumed releases the pending supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 5, 1000, alice);
    val d = deliverDefault(env, 5, 1000, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 5)),
    );
    val steps = cursor.executeN(2);
    cursor.close();
    expect(env.minter.getSccpState().pendingSupply).toEqual(1000);
    val reply = steps.at(1).outMessages.at<SccpAlreadyConsumed>(0).loadBody();
    expect(reply.nonce).toEqual(5);
    // the minter fails to handle the reply; the bounce makes the bucket report
    val bounced = testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(reply, env.minter.getBucketAddress(0), grams("0.01")),
    );
    // the flag of the earlier mint stays
    expect(isConsumedAt(env, 5)).toBeTrue();
    val report = bounced.outMessages.at<SccpConsumeReverted>(0).loadBody();
    expect(report.nonce).toEqual(5);
    expect(report.amount).toEqual(1000);
    val delivered = net.send(env.minter.getBucketAddress(0), forwardOut(bounced, 0));
    expect(delivered).toHaveSuccessfulTx<SccpConsumeReverted>({ to: env.minter.address });
    reportGas(
        "step minter consume reverted",
        delivered.getUsedGas<SccpConsumeReverted>({ to: env.minter.address }),
        SCCP_GAS_MINTER_CONSUME_REVERTED,
    );
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(1000);
    expect(state.opCount).toEqual(1);
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
}

get fun `test a bounced sccp_consumed of a void clears the flag and releases nothing`() {
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
    // the minter step and the consume at the bucket
    val steps = cursor.executeN(2);
    cursor.close();
    expect(isConsumedAt(env, 1)).toBeTrue();
    // a void reserves no supply and carries amount 0
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    val reply = steps.at(1).outMessages.at<SccpConsumed>(0).loadBody();
    expect(reply.nonce).toEqual(1);
    expect(reply.amount).toEqual(0);
    expect(reply.tail.load().kind).toEqual(SCCP_CONSUME_KIND_VOID);
    val bounced = testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(reply, env.minter.getBucketAddress(0), grams("0.01")),
    );
    expect(isConsumedAt(env, 1)).toBeFalse();
    expect(isConsumedAt(env, 0)).toBeTrue();
    val report = bounced.outMessages.at<SccpConsumeReverted>(0).loadBody();
    expect(report.nonce).toEqual(1);
    expect(report.amount).toEqual(0);
    val delivered = net.send(env.minter.getBucketAddress(0), forwardOut(bounced, 0));
    expect(delivered).toHaveSuccessfulTx<SccpConsumeReverted>({ to: env.minter.address });
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(40);
    expect(state.opCount).toEqual(1);
    // the message is voidable again
    val again = sendVoidExpired(env, env.deployer, 1, expired, env.minter.voidRequiredValue(1));
    expect(again).toHaveAllSuccessfulTxs();
    expect(again).toEmitExternalMessage<SccpVoidedEvent>();
    expect(isConsumedAt(env, 1)).toBeTrue();
    expect(env.minter.getSccpState().opCount).toEqual(2);
}

get fun `test consume reports are accepted only from the canonical bucket`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val stranger = testing.treasury("stranger").address;
    // 300 is pending: the reply of a mint is in flight
    val d = deliverDefault(env, 0, 300, alice);
    testing.processSingleTraceStep(env.deployer, finalizeMessage(env, d, finalizeValue(env, 0)));
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    val res = env
        .minter
        .sendSccpConsumeReverted(stranger, 0, 0, 300, { value: grams("1"), bounce: true });
    expect(res).toHaveFailedTx<SccpConsumeReverted>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    // the bucket of another index is not the bucket of the nonce
    expect(
        sendDeployBuckets(env, 2, env.minter.deployBucketsRequiredValue(2)),
    ).toHaveAllSuccessfulTxs();
    val other = env
        .minter
        .sendSccpConsumeReverted(
            env.minter.getBucketAddress(1),
            0,
            0,
            300,
            { value: grams("1"), bounce: true },
        );
    expect(other).toHaveFailedTx<SccpConsumeReverted>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // the report of the canonical bucket releases the pending amount
    val own = env
        .minter
        .sendSccpConsumeReverted(
            env.minter.getBucketAddress(0),
            0,
            0,
            300,
            { value: grams("1"), bounce: true },
        );
    expect(own).toHaveSuccessfulTx<SccpConsumeReverted>({ to: env.minter.address });
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
}

get fun `test a bounced unconsume is recorded and re-run by sccp_retry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    // finalize, bucket activation, consume and sccp_consumed at the minter
    val steps = cursor.executeN(4);
    cursor.close();
    // out message 0 is the sccp_finalized external event
    val transfer = steps.at(3).outMessages.at<InternalTransferStep>(1).loadBody();
    val bucket = env.minter.getBucketAddress(0);
    // the bucket is frozen for rent when the wallet bounces the mint
    val saved = testing.getShardAccount(bucket)!;
    testing.setShardAccount(bucket, null);
    val bounce = net.send(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, grams("0.05")),
    );
    // the mint bounced, and the unconsume that followed bounced too
    expect(bounce).toHaveTx<SccpUnconsume>({ to: bucket, success: false });
    reportGas(
        "step minter bounced unconsume",
        bounce.getUsedGas<SccpUnconsume>({ to: env.minter.address, bounced: true }),
        SCCP_GAS_MINTER_BOUNCE,
    );
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);
    // nothing else is recorded, and a retry needs a record and its value
    expect(env.minter.getSccpRetry(1)).toEqual(0);
    expect(sendRetry(env, 1, env.minter.retryRequiredValue())).toHaveFailedTx<SccpRetry>({
        to: env.minter.address,
        exitCode: SccpErrors.NothingToRetry as int,
    });
    expect(sendRetry(env, 0, sccpRetryRequiredValue() - 1)).toHaveFailedTx<SccpRetry>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    // and the mainnet chain id, before anything is looked up
    setGlobalId(-3);
    expectOutcome(sendRetry(env, 0, env.minter.retryRequiredValue()), SccpErrors.WrongChain);
    expectOutcome(sendRetry(env, 1, env.minter.retryRequiredValue()), SccpErrors.WrongChain);
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);

    // While the bucket is still frozen a retry bounces again, and the record
    // returns: each record runs at most once at a time and is never lost.
    val early = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(early).toHaveSuccessfulTx<SccpRetry>({ to: env.minter.address });
    expect(early).toHaveTx<SccpUnconsume>({ to: bucket, success: false });
    expect(early).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);

    // someone unfreezes the bucket with its exact state; the retry clears the flag
    testing.setShardAccount(bucket, saved);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val retry = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toHaveSuccessfulTx<SccpUnconsume>({ to: bucket });
    reportGas(
        "step minter retry unconsume",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    expect(minterStorage(env).retries.isEmpty()).toBeTrue();
    // a record runs once
    expect(sendRetry(env, 0, env.minter.retryRequiredValue())).toHaveFailedTx<SccpRetry>({
        to: env.minter.address,
        exitCode: SccpErrors.NothingToRetry as int,
    });
    // no nonce stays consumed without a mint: the message finalizes again
    finalizeOk(env, 0, 500, alice);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(500);
    // the first mint counted, was undone by its bounce, and the second counted
    expect(state.opCount).toEqual(2);
}

get fun `test a mint in flight across a latch whose unconsume bounces is recovered by sccp_retry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 300, alice);
    val first = testing.processSingleTraceStep(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    // certificate and checkpoint events, the activation of bucket 0 and the consume
    expect(first.outMessages.size()).toEqual(4);
    // the bucket is activated and sets the flag; its reply is in flight
    net.send(env.minter.address, forwardOut(first, 2));
    val consume = testing.processSingleTraceStep(env.minter.address, forwardOut(first, 3));
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // the latch fires: the generation certifies a height below its start (V2)
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    // and the bucket is frozen for rent before the reply is handled
    val bucket = env.minter.getBucketAddress(0);
    val saved = testing.getShardAccount(bucket)!;
    testing.setShardAccount(bucket, null);

    // The reply mints nothing and throws nothing: the pending supply is
    // released, and the unconsume, which bounces, is recorded.
    val res = net.send(bucket, forwardOut(consume, 0));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveTx<SccpUnconsume>({ to: bucket, success: false });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    expectEvents(res, []);
    var state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);

    // the bucket comes back with the flag still set, so the nonce is not voidable yet
    testing.setShardAccount(bucket, saved);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val refused = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(refused).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    expectEvents(refused, []);
    // `sccp_retry` needs no Live generation: it clears the flag on the latched minter
    val retry = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    // the nonce is voidable through the frozen void, and only so
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.Equivocated,
    );
    val voided = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(voided).toEmitExternalMessage<SccpVoidedEvent>();
    expect(isConsumedAt(env, 0)).toBeTrue();
    state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.totalSupply).toEqual(0);
}

get fun `test a bounced activation is recorded and re-run by sccp_retry`() {
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
    val activation = step.outMessages.at<SccpActivateBucket>(0).loadBody();
    expect(activation.index).toEqual(0);
    // the activation bounces (it is never delivered): the bucket stays undeployed
    testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        bouncedMessage(activation, env.minter.address, grams("0.1")),
    );
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_ACTIVATE);
    expect(testing.isDeployed(env.minter.getBucketAddress(0))).toBeFalse();
    // a bounce from anyone but the bucket records nothing
    val stranger = testing.treasury("stranger").address;
    testing.processSingleTraceStep(
        stranger,
        bouncedMessage(
            SccpActivateBucket {
                queryId: 2,
                index: 1,
            },
            env.minter.address,
            grams("0.1"),
        ),
    );
    expect(env.minter.getSccpRetry(512)).toEqual(0);
    // meanwhile a finalize into the bucket bounces and releases its pending supply
    val d = deliverDefault(env, 3, 40, alice);
    val early = sendFinalize(env, env.deployer, d, finalizeValue(env, 3));
    expect(early).toHaveBouncedTx<SccpConsume>({ to: env.minter.address });
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    // the minter counts the index as deployed and does not activate it twice
    expect(early).toNotHaveTx<SccpActivateBucket>({});
    // the retry activates the bucket, and the finalize goes through
    val retry = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env
            .minter
            .getBucketAddress(0) });
    reportGas(
        "step minter retry activation",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
    expect(
        testing.getAccountBalance(env.minter.getBucketAddress(0)) >= sccpBucketFloor(),
    ).toBeTrue();
    // the record ran once
    expectOutcome(
        sendRetry(env, 0, env.minter.retryRequiredValue()),
        SccpErrors.NothingToRetry,
    );
    finalizeOk(env, 3, 40, alice);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
}

get fun `test a mint bounce handler records the unconsume when the balance cannot pay it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    val steps = cursor.executeN(4);
    cursor.close();
    val transfer = steps.at(3).outMessages.at<InternalTransferStep>(1).loadBody();
    // an (impossible in practice) empty minter cannot pay the unconsume
    setAccountBalance(env.minter.address, 0);
    val bounced = testing.processSingleTraceStep(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, sccpGasFee(SCCP_GAS_MINTER_BOUNCE)),
    );
    // nothing is sent: the handler cannot bounce, so it records instead
    expect(bounced.outMessages.size()).toEqual(0);
    reportGas(
        "step minter bounced internal_transfer recorded",
        bounced.gasUsed,
        SCCP_GAS_MINTER_BOUNCE,
    );
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);
    expect(isConsumedAt(env, 0)).toBeTrue();
    // anyone pays the retry, which clears the flag; the caller also tops the
    // empty minter up to its floor
    val quote = env.minter.retryRequiredValue();
    expect(quote > sccpMinterFloor()).toBeTrue();
    expect(sendRetry(env, 0, quote)).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
    finalizeOk(env, 0, 500, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
}
