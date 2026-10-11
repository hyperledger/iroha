// Taira→TON finalization (§5.1.3, §5.3.4 steps 1–7): direct and historical
// proofs, deadline and cap edges, bucket dispatch and activation (the minter
// never recreates a bucket), duplicate and parallel finalizes, signature and
// proof negatives, and every bounce path (consume, sccp_consumed,
// internal_transfer then unconsume).

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

get fun `test finalize mints, emits and consumes the nonce`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val amount = 123456789;
    val d = deliverDefault(env, 0, amount, alice);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsume>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ from: env.minter.getBucketAddress(0), to: env
            .minter
            .address });
    expect(res).toHaveSuccessfulDeploy<InternalTransferStep>({ to: walletOf(env, alice).address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();

    val event = res.findExternalOutMessage<SccpFinalizedEvent>({ from: env.minter.address });
    expect(event).toBeNotNull();
    val body = event!.loadBody();
    expect(body.messageId).toEqual(d.messageId);
    expect(body.nonce).toEqual(0);

    expect(jettonBalanceOf(env, alice)).toEqual(amount);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(amount);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    expect(state.deployedBuckets).toEqual(1);
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(isConsumedAt(env, 1)).toBeFalse();
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
    val wallet = walletOf(env, alice).getWalletData();
    expect(wallet.ownerAddress).toEqual(alice);
    expect(wallet.minterAddress).toEqual(env.minter.address);
}

get fun `test finalize with a 31-member roster and 21 signatures`() {
    val env = setupEnvWith(31, 3, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 1000, alice);
}

get fun `test finalize historical proves an old block through the history root`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(3, TEST_REVISION, T0 * 1000 + DAY_MS, 777, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val blockLeaves = leavesWith(leaf, 2, 5);
    val blockRoot = treeRoot(blockLeaves);
    val history = historyLeaves(7, 3, 55, blockRoot, 5);
    // a later heartbeat block with no messages attests the history
    val statement: TestStatement = {
        height: 90,
        epoch: 2,
        timestampMs: T0 * 1000 - 1000,
        blockHash: 0xABCDEF,
        sccpRoot: 0,
        messageCount: 0,
        historyRoot: treeRoot(history),
        historySize: 7,
        rosterDigest: env.digest(),
        nextRosterDigest: 0,
    };
    val blockPath = treePath(blockLeaves, 2);
    val historyPath = treePath(history, 3);
    val proof: MessageProof = {
        leafIndex: 2,
        pathLen: blockPath.size(),
        payload,
        path: sccpBuildHashPath(blockPath),
    };
    val historyProof: HistoryProof = {
        height: 55,
        sccpRoot: blockRoot,
        messageCount: 5,
        leafIndex: 3,
        pathLen: historyPath.size(),
        path: sccpBuildHashPath(historyPath),
    };
    val res = env
        .minter
        .sendSccpFinalizeHistorical(
            env.deployer,
            1,
            env.deployer,
            statement.attestation(),
            signByThreshold(env.roster, statement.digest(env.networkId)),
            historyProof,
            proof,
            { value: finalizeValue(env, 3), bounce: true },
        );
    expect(res).toHaveSuccessfulTx<SccpFinalizeHistorical>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(777);

    // a wrong history index is rejected
    val payload2 = inboundPayloadCell(4, TEST_REVISION, T0 * 1000 + DAY_MS, 1, alice.accountId());
    var badHistory = historyProof;
    badHistory.leafIndex = 4;
    val bad = env
        .minter
        .sendSccpFinalizeHistorical(
            env.deployer,
            1,
            env.deployer,
            statement.attestation(),
            signByThreshold(env.roster, statement.digest(env.networkId)),
            badHistory,
            proof,
            { value: finalizeValue(env, 3), bounce: true },
        );
    expect(bad).toHaveFailedTx<SccpFinalizeHistorical>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadProof as int });
}

get fun `test duplicate finalize is rejected by the bucket and releases pending supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 5, 1000, alice);
    val d = deliverDefault(env, 5, 1000, alice);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 5));
    expect(res).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(1000);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
}

get fun `test parallel duplicate finalizes reserve pending supply until the bucket rejects one`() {
    // cap admits one mint of 1000 plus nothing else
    val env = setupEnvWith(4, 0, 1500);
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1000, alice);
    val value = finalizeValue(env, 0);
    val finalizeMsg = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value,
        dest: env.minter.address,
        body: SccpFinalize {
            queryId: 1,
            response: env.deployer,
            attestation: d.statement.toCell(),
            signatures: d.signatures,
            message: d.proof.toCell(),
        },
    });
    val first = testing.processSingleTraceStep(env.deployer, finalizeMsg);
    expect(env.minter.getSccpState().pendingSupply).toEqual(1000);
    // the duplicate is refused by the cap while the first is pending
    val second = sendFinalize(env, env.deployer, d, value);
    expect(second).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.SupplyCapExceeded as int });
    // deliver the first activation and consume; the mint completes
    net.send(env.minter.address, forwardOut(first, 0));
    net.send(env.minter.address, forwardOut(first, 1));
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(1000);
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
}

get fun `test two pending duplicates both reserve and only one mints`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 9, 400, alice);
    val value = finalizeValue(env, 9);
    val msg = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value,
        dest: env.minter.address,
        body: SccpFinalize {
            queryId: 1,
            response: env.deployer,
            attestation: d.statement.toCell(),
            signatures: d.signatures,
            message: d.proof.toCell(),
        },
    });
    val first = testing.processSingleTraceStep(env.deployer, msg);
    // the first entry activates bucket 0, so the duplicate only consumes
    val second = testing.processSingleTraceStep(env.deployer, msg);
    expect(env.minter.getSccpState().pendingSupply).toEqual(800);
    net.send(env.minter.address, forwardOut(first, 0));
    net.send(env.minter.address, forwardOut(first, 1));
    net.send(env.minter.address, forwardOut(second, 0));
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(400);
    expect(jettonBalanceOf(env, alice)).toEqual(400);
}

get fun `test supply cap edges`() {
    val env = setupEnvWith(4, 0, 1000);
    val alice = testing.treasury("alice").address;
    val over = deliverDefault(env, 0, 1001, alice);
    expect(
        sendFinalize(env, env.deployer, over, finalizeValue(env, 0)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.SupplyCapExceeded as int,
    });
    finalizeOk(env, 1, 600, alice);
    val rest = deliverDefault(env, 2, 401, alice);
    expect(
        sendFinalize(env, env.deployer, rest, finalizeValue(env, 2)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.SupplyCapExceeded as int,
    });
    finalizeOk(env, 3, 400, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
}

get fun `test deadline edges`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val deadline = (T0 + 100) * 1000;
    val d = deliver(
        env,
        env.roster,
        0,
        50,
        alice,
        deadline,
        0,
        1,
    );
    val late = deliver(
        env,
        env.roster,
        1,
        60,
        alice,
        deadline,
        0,
        1,
    );
    testing.setNow(T0 + 100);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(50);
    testing.setNow(T0 + 101);
    expect(
        sendFinalize(env, env.deployer, late, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.DeadlinePassed as int,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(50);
}

get fun `test expired roster cannot finalize`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliver(
        env,
        env.roster,
        0,
        50,
        alice,
        env.roster.validUntilMs + DAY_MS,
        0,
        1,
    );
    testing.setNow(env.roster.validUntilMs / 1000);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
    val d2 = deliver(
        env,
        env.roster,
        1,
        50,
        alice,
        env.roster.validUntilMs + DAY_MS,
        0,
        1,
    );
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    expect(
        sendFinalize(env, env.deployer, d2, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
}

get fun `test bucket boundaries and the four-ahead deploy rule`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 511, 1, alice);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
    finalizeOk(env, 512, 1, alice);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(2);
    expect(isConsumedAt(env, 511)).toBeTrue();
    expect(isConsumedAt(env, 512)).toBeTrue();
    // bucket 5 = deployed (2) + 3: deploys buckets 2..=5 in one finalize
    val nonce = 5 * 512 + 17;
    val res = finalizeOk(env, nonce, 1, alice);
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(2) });
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(5) });
    expect(bucketOf(env, 4).isActivated()).toBeTrue();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(6);
    // bucket 10 = deployed (6) + 4 is too far ahead
    val far = deliverDefault(env, 10 * 512, 1, alice);
    expect(sendFinalize(env, env.deployer, far, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BucketNotDeployed as int,
    });
    // after sccp_deploy_buckets it goes through
    val deploy = env
        .minter
        .sendSccpDeployBuckets(
            env.deployer,
            3,
            env.deployer,
            2,
            { value: env.minter.deployBucketsRequiredValue(2), bounce: true },
        );
    expect(deploy).toHaveSuccessfulTx<SccpDeployBuckets>({ to: env.minter.address });
    expect(deploy).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env
            .minter
            .getBucketAddress(7) });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(8);
    finalizeOk(env, 10 * 512, 1, alice);
}

get fun `test the minter never recreates a deleted bucket`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 10, alice);
    val bucket = env.minter.getBucketAddress(0);
    // the bucket account disappears (deleted for rent in the worst case)
    testing.setShardAccount(bucket, null);
    expect(testing.isDeployed(bucket)).toBeFalse();
    val d = deliverDefault(env, 1, 10, alice);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 1));
    // the consume carries no StateInit: it bounces and nothing is recreated
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveBouncedTx<SccpConsume>({ to: env.minter.address });
    expect(testing.isDeployed(bucket)).toBeFalse();
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(10);
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}

get fun `test bounced sccp_consume releases pending supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 300, alice);
    val step = testing.processSingleTraceStep(
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
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // out message 0 activates bucket 0, out message 1 is the consume
    val consume = step.outMessages.at<SccpConsume>(1).loadBody();
    expect(consume.nonce).toEqual(0);
    expect(consume.amount).toEqual(300);
    // a bounce from anyone but the bucket is refused
    val stranger = testing.treasury("stranger").address;
    val forged = testing.processSingleTraceStep(
        stranger,
        bouncedMessage(consume, env.minter.address, grams("0.1")),
    );
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        bouncedMessage(consume, env.minter.address, grams("0.1")),
    );
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
}

get fun `test bounced internal_transfer unconsumes and the message finalizes again`() {
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
    // finalize, bucket activation, consume and sccp_consumed at the minter
    val steps = cursor.executeN(4);
    cursor.close();
    val consumedStep = steps.at(3);
    // out message 0 is the sccp_finalized external event
    val transfer = consumedStep.outMessages.at<InternalTransferStep>(1).loadBody();
    expect(transfer.queryId).toEqual(0);
    expect(transfer.jettonAmount).toEqual(500);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
    expect(isConsumedAt(env, 0)).toBeTrue();
    // the wallet bounces the transfer
    val bounce = net.send(
        walletOf(env, alice).address,
        bouncedMessage(transfer, env.minter.address, grams("0.05")),
    );
    expect(bounce).toHaveSuccessfulTx<SccpUnconsume>({ to: env.minter.getBucketAddress(0) });
    // the handler's gas bound is part of its balance check (§5.3.4 step 7)
    val handlerGas = bounce.getUsedGas({ to: env.minter.address, bounced: true });
    println(
        "gas minter bounced internal_transfer: {} (limit {})",
        handlerGas,
        SCCP_GAS_MINTER_BOUNCE,
    );
    expect(handlerGas <= SCCP_GAS_MINTER_BOUNCE).toBeTrue();
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    expect(isConsumedAt(env, 0)).toBeFalse();
    // the same message finalizes again
    finalizeOk(env, 0, 500, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(500);
}

get fun `test bounced sccp_consumed makes the bucket clear the flag`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 50, alice);
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
    val steps = cursor.executeN(3);
    cursor.close();
    val consumed = steps.at(2).outMessages.at<SccpConsumed>(0).loadBody();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(50);
    // bounces from anyone but the minter are ignored
    val stranger = testing.treasury("stranger").address;
    testing.processSingleTraceStep(
        stranger,
        bouncedMessage(consumed, env.minter.getBucketAddress(0), grams("0.05")),
    );
    expect(isConsumedAt(env, 0)).toBeTrue();
    // a bounce with little value: the bucket pays the rest of the handler and
    // the report from its own balance
    val bounced = testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(consumed, env.minter.getBucketAddress(0), sccpGasFee(2000)),
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
    val report = bounced.outMessages.at<SccpConsumeReverted>(0).loadBody();
    expect(report.nonce).toEqual(0);
    expect(report.amount).toEqual(50);
    // the report releases the pending supply, and the message finalizes again
    net.send(env.minter.getBucketAddress(0), forwardOut(bounced, 0));
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    finalizeOk(env, 0, 50, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(50);
}

get fun `test consume replies are accepted only from the canonical bucket`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    val tail: ConsumeTail = {
        kind: SCCP_CONSUME_KIND_MINT,
        recipient: stranger,
        response: stranger,
        messageId: 1,
    };
    val res = env
        .minter
        .sendSccpConsumed(
            stranger,
            0,
            0,
            1000000,
            tail,
            { value: grams("1"), bounce: true },
        );
    expect(res).toHaveFailedTx<SccpConsumed>({ to: env
            .minter
            .address, exitCode: SccpErrors.NotBucket as int });
    val res2 = env
        .minter
        .sendSccpAlreadyConsumed(
            stranger,
            0,
            0,
            1000000,
            tail,
            { value: grams("1"), bounce: true },
        );
    expect(res2).toHaveFailedTx<SccpAlreadyConsumed>({ to: env
            .minter
            .address, exitCode: SccpErrors.NotBucket as int });
    val res3 = env
        .minter
        .sendSccpRangeConsumed(stranger, 0, 0, 1, { value: grams("1"), bounce: true });
    expect(res3).toHaveFailedTx<SccpRangeConsumed>({ to: env
            .minter
            .address, exitCode: SccpErrors.NotBucket as int });
}

get fun `test buckets accept consume only from the minter`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 1, alice);
    val bucket = bucketOf(env, 0);
    val tail: ConsumeTail = {
        kind: SCCP_CONSUME_KIND_MINT,
        recipient: alice,
        response: alice,
        messageId: 1,
    };
    val res = bucket.sendSccpConsume(
        alice,
        0,
        1,
        1,
        tail,
        { value: grams("1"), bounce: true },
    );
    expect(
        res,
    ).toHaveFailedTx<SccpConsume>({ to: bucket.address, exitCode: SccpErrors.NotMinter as int });
    val res2 = bucket.sendSccpUnconsume(alice, 0, { value: grams("1"), bounce: true });
    expect(
        res2,
    ).toHaveFailedTx<SccpUnconsume>({ to: bucket.address, exitCode: SccpErrors.NotMinter as int });
    expect(isConsumedAt(env, 0)).toBeTrue();
    val data = bucket.getBucketData();
    expect(data.minterAddress).toEqual(env.minter.address);
    expect(data.index).toEqual(0);
    expect(data.activated).toBeTrue();
    expect(data.bitsLo).toEqual(1);
    expect(data.bitsHi).toEqual(0);
}

get fun `test finalize requires the required value`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    // the minter is above its floor: the entry minimum is the quote minus the grace
    val required = finalizeValue(env, 0);
    expect(required).toEqual(sccpFinalizeRequiredValue(1) + sccpMinterStorageGrace());
    val minimum = required - sccpMinterStorageGrace();
    expect(sendFinalize(env, env.deployer, d, minimum - 1)).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(sendFinalize(env, env.deployer, d, minimum)).toHaveSuccessfulTx<SccpFinalize>({ to: env
            .minter
            .address });
    expect(jettonBalanceOf(env, alice)).toEqual(1);
}

get fun `test signature set negatives`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    val digest = d.statement.digest(env.networkId);
    val t = env.roster.t();
    // too few signatures
    var cases: array<[cell, int]> = [
        [signBySlots(env.roster, digest, [0, 1]), SccpErrors.TooFewSignatures as int],
    ];
    // a bit beyond n
    val (r0, s0, v0) = testSign(0, digest);
    val (r1, s1, v1) = testSign(1, digest);
    val (r2, s2, v2) = testSign(2, digest);
    val (r3, s3, v3) = testSign(3, digest);
    cases.push(
        [
            signatureCellsFromRows(0b10011, [[r0, s0, v0], [r1, s1, v1], [r2, s2, v2]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    // signatures in the wrong order (slot 1 signature under slot 0)
    cases.push(
        [
            signatureCellsFromRows(0b0111, [[r1, s1, v1], [r0, s0, v0], [r2, s2, v2]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    // high-S twin
    val flipped = v0 == 27 ? 28 : 27;
    cases.push(
        [
            signatureCellsFromRows(
                0b0111,
                [[r0, SECP256K1_N - s0, flipped], [r1, s1, v1], [r2, s2, v2]],
            ),
            SccpErrors.BadSignatures as int,
        ],
    );
    // v = 29
    cases.push(
        [
            signatureCellsFromRows(0b0111, [[r0, s0, 29], [r1, s1, v1], [r2, s2, v2]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    // more signature cells than set bits
    cases.push(
        [
            signatureCellsFromRows(0b0011, [[r0, s0, v0], [r1, s1, v1], [r2, s2, v2]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    // fewer signature cells than set bits
    cases.push(
        [
            signatureCellsFromRows(0b1111, [[r0, s0, v0], [r1, s1, v1], [r2, s2, v2]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    // a key outside the roster signing for slot 3
    val (r9, s9, v9) = testSign(9, digest);
    cases.push(
        [
            signatureCellsFromRows(0b1011, [[r0, s0, v0], [r1, s1, v1], [r9, s9, v9]]),
            SccpErrors.BadSignatures as int,
        ],
    );
    var i = 0;
    while (i < cases.size()) {
        val [sigs, code] = cases.get(i);
        var bad = d;
        bad.signatures = sigs;
        expect(sendFinalize(env, env.deployer, bad, grams("5"))).toHaveFailedTx<SccpFinalize>({
            to: env.minter.address,
            exitCode: code,
        });
        i += 1;
    }
    // all four signatures are fine too
    var all = d;
    all.signatures = signatureCellsFromRows(
        0b1111,
        [[r0, s0, v0], [r1, s1, v1], [r2, s2, v2], [r3, s3, v3]],
    );
    expect(t).toEqual(3);
    expect(
        sendFinalize(env, env.deployer, all, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
}

get fun `test a keyless slot can never sign`() {
    val env = setupEnvWith(7, 2, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    val digest = d.statement.digest(env.networkId);
    // slot 0 is keyless: any signature under it is rejected
    val (r, s, v) = testSign(0, digest);
    var rows: array<[int, int, int]> = [[r, s, v]];
    var slot = 2;
    while (slot < 6) {
        val (rs, ss, vs) = testSign(env.roster.keys.get(slot), digest);
        rows.push([rs, ss, vs]);
        slot += 1;
    }
    var bad = d;
    bad.signatures = signatureCellsFromRows(0b111101, rows);
    expect(sendFinalize(env, env.deployer, bad, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadSignatures as int,
    });
    // t = 5 keyed signers finalize
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
}

get fun `test proof negatives`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    // wrong leaf index
    var wrongIndex = d;
    wrongIndex.proof.leafIndex = 2;
    expect(sendFinalize(env, env.deployer, wrongIndex, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadProof as int,
    });
    // truncated path
    var shortPath = d;
    shortPath.proof.pathLen = 1;
    shortPath.proof.path = sccpBuildHashPath([1]);
    expect(sendFinalize(env, env.deployer, shortPath, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadProof as int,
    });
    // a path longer than the block limit
    var longPath = d;
    longPath.proof.pathLen = 10;
    longPath.proof.path = sccpBuildHashPath(
        [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
        ],
    );
    expect(sendFinalize(env, env.deployer, longPath, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadProof as int,
    });
    // an attestation whose count/root invariants do not hold
    var broken = d;
    broken.statement.messageCount = 0;
    broken.signatures = signByThreshold(env.roster, broken.statement.digest(env.networkId));
    expect(sendFinalize(env, env.deployer, broken, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadAttestation as int,
    });
}

get fun `test a leaf for another destination word is rejected`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(0, TEST_REVISION, T0 * 1000 + DAY_MS, 1, alice.accountId());
    val parsed = sccpParseInboundPayload(payload, TEST_REVISION, 0);
    val otherLeaf = sccpTransferLeaf(sccpInboundMessageId(env.networkId, parsed.payloadHash), 0x99);
    val leaves = leavesWith(otherLeaf, 0, 2);
    val statement = blockStatement(10, leaves, env.digest());
    val path = treePath(leaves, 0);
    val d: Delivery = {
        payload,
        statement,
        signatures: signByThreshold(env.roster, statement.digest(env.networkId)),
        proof: {
            leafIndex: 0,
            pathLen: path.size(),
            payload,
            path: sccpBuildHashPath(path),
        },
        messageId: 0,
    };
    expect(sendFinalize(env, env.deployer, d, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadProof as int,
    });
}

get fun `test payload targeting another revision or the minter itself is rejected`() {
    val env = setupEnv();
    val payload = inboundPayloadCell(0, 2, T0 * 1000 + DAY_MS, 1, 0x55);
    val statement = blockStatement(10, [fillerLeaf(1)], env.digest());
    val d: Delivery = {
        payload,
        statement,
        signatures: signByThreshold(env.roster, statement.digest(env.networkId)),
        proof: {
            leafIndex: 0,
            pathLen: 0,
            payload,
            path: null,
        },
        messageId: 0,
    };
    expect(sendFinalize(env, env.deployer, d, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadPayload as int,
    });
    val selfPayload = inboundPayloadCell(
        0,
        TEST_REVISION,
        T0 * 1000 + DAY_MS,
        1,
        env.minter.address.accountId(),
    );
    var selfDelivery = d;
    selfDelivery.payload = selfPayload;
    selfDelivery.proof.payload = selfPayload;
    expect(sendFinalize(env, env.deployer, selfDelivery, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRecipient as int,
    });
}

get fun `test finalize requires the ton mainnet global id`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(-3, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
    expect(sendFinalize(env, env.deployer, d, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.WrongChain as int,
    });
}
