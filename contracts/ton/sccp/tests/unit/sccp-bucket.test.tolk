// Bucket activation and asynchronous failure handling (§5.3.4): only the
// minter activates a bucket, once per index, so a bucket deployed by anyone
// else (early, or again after a deletion for rent) never accepts flags; a
// failed `sccp_consumed` or `sccp_already_consumed` releases the pending
// supply through `sccp_consume_reverted`; a bounced `sccp_unconsume` or
// activation is recorded and re-run by `sccp_retry`.

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

fun expectGasWithin(label: string, used: int, limit: int) {
    println("gas {}: {} (limit {})", label, used, limit);
    expect(used <= limit).toBeTrue();
}

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
}

/// `sccp_void_frozen` of `[first, first + count)`.
fun sendVoidFrozenRange(env: Env, first: int, count: int, value: coins): SendResultList {
    return env
        .minter
        .sendSccpVoidFrozen(
            env.deployer,
            9,
            env.deployer,
            first,
            count,
            { value, bounce: true },
        );
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
    // nor through a frozen void once both rosters expired
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    val frozen = sendVoidFrozenRange(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
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
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 0),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                attestation: d.statement.toCell(),
                signatures: d.signatures,
                message: d.proof.toCell(),
            },
        }),
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
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 5),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                attestation: d.statement.toCell(),
                signatures: d.signatures,
                message: d.proof.toCell(),
            },
        }),
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
    expect(isConsumedAt(env, 5)).toBeTrue();
    val report = bounced.outMessages.at<SccpConsumeReverted>(0).loadBody();
    expect(report.amount).toEqual(1000);
    val delivered = net.send(env.minter.getBucketAddress(0), forwardOut(bounced, 0));
    expect(delivered).toHaveSuccessfulTx<SccpConsumeReverted>({ to: env.minter.address });
    expectGasWithin(
        "minter consume reverted",
        delivered.getUsedGas<SccpConsumeReverted>({ to: env.minter.address }),
        SCCP_GAS_MINTER_CONSUME_REVERTED,
    );
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(1000);
}

get fun `test consume reports are accepted only from the canonical bucket`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    val res = env
        .minter
        .sendSccpConsumeReverted(stranger, 0, 0, 1, { value: grams("1"), bounce: true });
    expect(res).toHaveFailedTx<SccpConsumeReverted>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
}

get fun `test a bounced unconsume is recorded and re-run by sccp_retry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 0),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                attestation: d.statement.toCell(),
                signatures: d.signatures,
                message: d.proof.toCell(),
            },
        }),
    );
    val steps = cursor.executeN(4);
    cursor.close();
    val transfer = steps.at(3).outMessages.at<InternalTransferStep>(1).loadBody();
    val bucket = env.minter.getBucketAddress(0);
    // the bucket is frozen for rent when the wallet bounces the mint
    val saved = testing.getShardAccount(bucket)!;
    testing.setShardAccount(bucket, null);
    val bounce = net.send(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, grams("0.05")),
    );
    expect(bounce).toHaveTx<SccpUnconsume>({ to: bucket, success: false });
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
    // someone unfreezes the bucket with its exact state; the retry clears the flag
    testing.setShardAccount(bucket, saved);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val retry = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toHaveSuccessfulTx<SccpUnconsume>({ to: bucket });
    expectGasWithin(
        "minter retry",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    // a record runs once
    expect(sendRetry(env, 0, env.minter.retryRequiredValue())).toHaveFailedTx<SccpRetry>({
        to: env.minter.address,
        exitCode: SccpErrors.NothingToRetry as int,
    });
    finalizeOk(env, 0, 500, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
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
    // meanwhile a finalize into the bucket bounces and releases its pending supply
    val d = deliverDefault(env, 3, 40, alice);
    val early = sendFinalize(env, env.deployer, d, finalizeValue(env, 3));
    expect(early).toHaveBouncedTx<SccpConsume>({ to: env.minter.address });
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    // the retry activates the bucket, and the finalize goes through
    val retry = sendRetry(env, 0, env.minter.retryRequiredValue());
    expect(retry).toHaveAllSuccessfulTxs();
    expect(retry).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env
            .minter
            .getBucketAddress(0) });
    expectGasWithin(
        "minter retry (activation)",
        retry.getUsedGas<SccpRetry>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RETRY,
    );
    expect(env.minter.getSccpRetry(0)).toEqual(0);
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
    finalizeOk(env, 3, 40, alice);
}

get fun `test a mint bounce handler records the unconsume when the balance cannot pay it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 500, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 0),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                attestation: d.statement.toCell(),
                signatures: d.signatures,
                message: d.proof.toCell(),
            },
        }),
    );
    val steps = cursor.executeN(4);
    cursor.close();
    val transfer = steps.at(3).outMessages.at<InternalTransferStep>(1).loadBody();
    // an (impossible in practice) empty minter cannot pay the unconsume
    setAccountBalance(env.minter.address, 0);
    testing.processSingleTraceStep(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, sccpGasFee(SCCP_GAS_MINTER_BOUNCE)),
    );
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(env.minter.getSccpRetry(0)).toEqual(SCCP_RETRY_UNCONSUME);
    expect(isConsumedAt(env, 0)).toBeTrue();
    // anyone pays the retry, which clears the flag
    expect(sendRetry(env, 0, env.minter.retryRequiredValue())).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 0)).toBeFalse();
}
