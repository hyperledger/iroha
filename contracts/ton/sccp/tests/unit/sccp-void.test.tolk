// Voids (§5.1.8, §5.3.4 "Void"): `sccp_void_expired` (direct and historical)
// after the deadline with the payload nonce, and `sccp_void_frozen` over one
// bucket once both rosters expired, with the range and revert rules.

import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/big_array"
import "@acton/types/message"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-messages"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

fun expiredDelivery(env: Env, nonce: int, recipient: address): Delivery {
    return deliver(
        env,
        env.roster,
        nonce,
        100,
        recipient,
        (T0 + 100) * 1000,
        1,
        3,
    );
}

get fun `test void expired consumes the nonce and emits sccp_voided`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 3, alice);
    testing.setNow(T0 + 101);
    val res = sendVoidExpired(env, env.deployer, 3, d, env.minter.voidRequiredValue(3));
    expect(res).toHaveSuccessfulTx<SccpVoidExpired>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    val event = res.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address });
    expect(event).toBeNotNull();
    val body = event!.loadBody();
    expect(body.messageId).toEqual(d.messageId);
    expect(body.firstNonce).toEqual(3);
    expect(body.count).toEqual(1);
    expect(isConsumedAt(env, 3)).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.totalSupply).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    // a void is final: the message can no longer be finalized (it is expired
    // anyway) nor voided twice
    val again = sendVoidExpired(env, env.deployer, 3, d, env.minter.voidRequiredValue(3));
    expect(again).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test void deadline edge and nonce argument`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    testing.setNow(T0 + 100);
    expect(sendVoidExpired(env, env.deployer, 0, d, grams("5"))).toHaveFailedTx<SccpVoidExpired>({
        to: env.minter.address,
        exitCode: SccpErrors.DeadlineNotReached as int,
    });
    testing.setNow(T0 + 101);
    expect(sendVoidExpired(env, env.deployer, 1, d, grams("5"))).toHaveFailedTx<SccpVoidExpired>({
        to: env.minter.address,
        exitCode: SccpErrors.BadNonce as int,
    });
    // the entry minimum is the quote minus the storage grace (the minter is above its floor)
    expect(
        sendVoidExpired(
            env,
            env.deployer,
            0,
            d,
            env.minter.voidRequiredValue(0) - sccpMinterStorageGrace() - 1,
        ),
    ).toHaveFailedTx<SccpVoidExpired>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpVoidExpired>({
        to: env.minter.address,
    });
}

get fun `test void of a finalized message is rejected by the bucket`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 2, alice);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 2)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    testing.setNow(T0 + 101);
    val res = sendVoidExpired(env, env.deployer, 2, d, env.minter.voidRequiredValue(2));
    expect(res).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(
        res.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.totalSupply).toEqual(100);
}

get fun `test void expired historical`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(6, TEST_REVISION, (T0 + 100) * 1000, 5, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val blockLeaves = leavesWith(leaf, 0, 1);
    val history = historyLeaves(3, 1, 70, leaf, 1);
    val statement: TestStatement = {
        height: 80,
        epoch: 2,
        timestampMs: T0 * 1000,
        blockHash: 0x1234,
        sccpRoot: fillerLeaf(77),
        messageCount: 1,
        historyRoot: treeRoot(history),
        historySize: 3,
        rosterDigest: env.digest(),
        nextRosterDigest: 0,
    };
    val historyPath = treePath(history, 1);
    testing.setNow(T0 + 101);
    val res = env
        .minter
        .sendSccpVoidExpiredHistorical(
            env.deployer,
            1,
            env.deployer,
            6,
            statement.attestation(),
            signByThreshold(env.roster, statement.digest(env.networkId)),
            {
                height: 70,
                sccpRoot: leaf,
                messageCount: 1,
                leafIndex: 1,
                pathLen: historyPath.size(),
                path: sccpBuildHashPath(historyPath),
            },
            {
                leafIndex: 0,
                pathLen: 0,
                payload,
                path: null,
            },
            { value: env.minter.voidRequiredValue(6), bounce: true },
        );
    expect(res).toHaveSuccessfulTx<SccpVoidExpiredHistorical>({ to: env.minter.address });
    expect(res).toEmitExternalMessage<SccpVoidedEvent>();
    expect(isConsumedAt(env, 6)).toBeTrue();
    expect(blockLeaves.size()).toEqual(1);
}

get fun `test void expired needs an accepted roster`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    expect(sendVoidExpired(env, env.deployer, 0, d, grams("5"))).toHaveFailedTx<SccpVoidExpired>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
}

fun sendVoidFrozen(env: Env, first: int, count: int, value: coins): SendResultList {
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

get fun `test void frozen requires both rosters expired`() {
    val env = setupEnv();
    expect(sendVoidFrozen(env, 0, 1, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
        to: env.minter.address,
        exitCode: SccpErrors.NotFrozen as int,
    });
    // rotate, then let the current roster expire while the previous one is in grace
    val next = makeRoster(
        8,
        4,
        0,
        4,
        T0 * 1000 - 1000,
        T0 * 1000 + 2 * DAY_MS,
    );
    rotateTo(env, next, 200);
    val prevUntil = env.minter.getSccpState().prevValidUntilMs;
    expect(prevUntil).toEqual(T0 * 1000 + SCCP_PREVIOUS_ROSTER_GRACE_MS);
    testing.setNow(T0 + DAY_MS / 1000 - 10);
    expect(sendVoidFrozen(env, 0, 1, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
        to: env.minter.address,
        exitCode: SccpErrors.NotFrozen as int,
    });
    // both expired
    testing.setNow(T0 + 2 * DAY_MS / 1000 + 1);
    val res = sendVoidFrozen(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpVoidFrozen>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    val event = res
        .findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.messageId).toEqual(0);
    expect(event.firstNonce).toEqual(0);
    expect(event.count).toEqual(512);
    val (hi, lo) = bucketOf(env, 0).getBits();
    expect(hi).toEqual(((1 << 255) - 1) * 2 + 1);
    expect(lo).toEqual(((1 << 255) - 1) * 2 + 1);
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test void frozen range rules`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 10, 1, alice);
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    val bad: array<[int, int]> = [[0, 0], [0, 513], [500, 20]];
    var i = 0;
    while (i < bad.size()) {
        val [first, count] = bad.get(i);
        expect(sendVoidFrozen(env, first, count, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
            to: env.minter.address,
            exitCode: SccpErrors.BadRange as int,
        });
        i += 1;
    }
    // a range containing a consumed nonce is rejected as a whole
    val rejected = sendVoidFrozen(env, 5, 10, env.minter.voidFrozenRequiredValue(5));
    expect(rejected).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    expect(
        rejected.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    expect(isConsumedAt(env, 5)).toBeFalse();
    expect(isConsumedAt(env, 10)).toBeTrue();
    // the adjacent free ranges succeed
    expect(
        sendVoidFrozen(env, 0, 10, env.minter.voidFrozenRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({
        to: env.minter.address,
    });
    expect(
        sendVoidFrozen(env, 11, 501, env.minter.voidFrozenRequiredValue(11)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({
        to: env.minter.address,
    });
    val (hi, lo) = bucketOf(env, 0).getBits();
    expect(hi).toEqual(((1 << 255) - 1) * 2 + 1);
    expect(lo).toEqual(((1 << 255) - 1) * 2 + 1);
    // buckets beyond four ahead need sccp_deploy_buckets first
    expect(sendVoidFrozen(env, 5 * 512, 1, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
        to: env.minter.address,
        exitCode: SccpErrors.BucketNotDeployed as int,
    });
    // up to four ahead deploys the missing buckets
    val ahead = sendVoidFrozen(env, 4 * 512, 512, env.minter.voidFrozenRequiredValue(4 * 512));
    expect(ahead).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env
            .minter
            .getBucketAddress(1) });
    expect(ahead).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env
            .minter
            .getBucketAddress(4) });
    expect(ahead).toHaveSuccessfulTx<SccpConsumeRange>({ to: env.minter.getBucketAddress(4) });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(5);
    expect(env.minter.getSccpState().opCount).toEqual(4);
}

get fun `test bounced sccp_range_consumed makes the bucket clear the range`() {
    val env = setupEnv();
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: env.minter.voidFrozenRequiredValue(0),
            dest: env.minter.address,
            body: SccpVoidFrozen {
                queryId: 1,
                response: env.deployer,
                firstNonce: 3,
                count: 4,
            },
        }),
    );
    val steps = cursor.executeTill<SccpConsumeRange>({ to: env.minter.getBucketAddress(0) });
    cursor.close();
    val consumed = steps.at(steps.size() - 1).outMessages.at<SccpRangeConsumed>(0).loadBody();
    expect(isConsumedAt(env, 3)).toBeTrue();
    expect(isConsumedAt(env, 6)).toBeTrue();
    testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(consumed, env.minter.getBucketAddress(0), grams("0.05")),
    );
    expect(isConsumedAt(env, 3)).toBeFalse();
    expect(isConsumedAt(env, 6)).toBeFalse();
}

get fun `test bucket range masks cover both halves`() {
    val env = setupEnv();
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    expect(
        sendVoidFrozen(env, 250, 12, env.minter.voidFrozenRequiredValue(250)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({
        to: env.minter.address,
    });
    val (hi, lo) = bucketOf(env, 0).getBits();
    expect(hi).toEqual(0x3F);
    expect(lo).toEqual(0x3F << 250);
    expect(isConsumedAt(env, 249)).toBeFalse();
    expect(isConsumedAt(env, 250)).toBeTrue();
    expect(isConsumedAt(env, 261)).toBeTrue();
    expect(isConsumedAt(env, 262)).toBeFalse();
}
