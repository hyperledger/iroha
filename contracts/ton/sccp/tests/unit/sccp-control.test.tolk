// Parliament controls (§5.1.6, §5.3.4 "apply control"): pause and resume,
// stale, equal and gapped nonces, historical block references, foreign leaves (network,
// destination, revision, Taira network, transfer leaf), and burns, rotations
// and voids staying open while minting is paused.

import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-verify"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

get fun `test pause blocks finalization and resume re-enables it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val res = applyControlOk(env, 1, true);
    val event = res
        .findExternalOutMessage<SccpControlAppliedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.controlNonce).toEqual(1);
    expect(event.parliamentPaused).toBeTrue();
    expect(event.track).toEqual(SCCP_TRACK_PARLIAMENT);
    expect(event.fastPauseUntilMs).toEqual(0);
    expect(event.certificateId).toEqual(parliamentControl(1, true).certificateId);
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(env.minter.getSccpState().opCount).toEqual(1);
    val d = deliverDefault(env, 0, 10, alice);
    expect(sendFinalize(env, env.deployer, d, finalizeValue(env, 0))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.MintingIsPaused as int,
    });
    applyControlOk(env, 2, false);
    expect(env.minter.getSccpState().opCount).toEqual(2);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}

get fun `test stale and equal control nonces are rejected and gaps are accepted`() {
    val env = setupEnv();
    applyControlOk(env, 2, true);
    // Replay the exact certified block so the equal nonce reaches StaleControl.
    expect(sendApplyControl(env, deliverControl(env, 2, true))).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.StaleControl as int,
    });
    expect(sendApplyControl(env, deliverControl(env, 1, false))).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.StaleControl as int,
    });
    applyControlOk(env, 7, false);
    // pause, resume and pause again as three distinct controls
    applyControlOk(env, 8, true);
    expect(env.minter.getSccpState().opCount).toEqual(3);
    // a zero nonce can never apply
    expect(sendApplyControl(env, deliverControl(env, 0, false))).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.StaleControl as int,
    });
}

get fun `test apply control historical block reference and stored checkpoint`() {
    val env = setupEnv();
    val control = parliamentControl(3, true);
    val leaf = controlLeafOf(env, control);
    val blockLeaves = leavesWith(leaf, 1, 2);
    val blockRoot = treeRoot(blockLeaves);
    val history = historyLeaves(4, 2, 1044, blockRoot, 2);
    var x = emptyX(env.networkId, env.generation, env.committee.root(), 1090);
    x.historyRoot = treeRoot(history);
    x.historySize = 4;
    val proof = controlProofCell(
        control.nonce,
        control.track,
        control.parliamentPaused,
        control.fastPauseUntilMs,
        control.certificateId,
        control.effectHash,
        1,
        treePath(blockLeaves, 1),
        blockRefCell(1044, blockRoot, 2, 2, treePath(history, 2)),
    );
    expect(checkpointBy(env, env.committee, x, null)).toHaveSuccessfulTx<SccpCheckpoint>({ to: env
            .minter
            .address });
    val res = sendApplyControlCells(
        env,
        env.deployer,
        null,
        x.ref(),
        proof,
        grams("1"),
    );
    expect(res).toHaveSuccessfulTx<SccpApplyControlCheckpoint>({ to: env.minter.address });
    expect(env.minter.getSccpState().parliamentPaused).toBeTrue();
    expect(env.minter.getSccpState().controlNonce).toEqual(3);
}

get fun `test foreign control leaves and altered cause fields are rejected`() {
    val env = setupEnv();
    val own = env.minter.address.accountId();
    val c = parliamentControl(1, true);
    val leaves: array<int> = [
        controlLeafFor(
            env.networkId,
            0x41,
            1,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            c.parliamentPaused,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own ^ 1,
            TEST_REVISION,
            c.nonce,
            c.track,
            c.parliamentPaused,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION + 1,
            c.nonce,
            c.track,
            c.parliamentPaused,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId ^ 1,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            c.parliamentPaused,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            false,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            SCCP_TRACK_FAST_PAUSE,
            true,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            true,
            1,
            c.certificateId,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            true,
            c.fastPauseUntilMs,
            c.certificateId ^ 1,
            c.effectHash,
        ),
        controlLeafFor(
            env.networkId,
            SCCP_TAG_TON,
            SCCP_TON_IDENTITY_WORD,
            own,
            TEST_REVISION,
            c.nonce,
            c.track,
            true,
            c.fastPauseUntilMs,
            c.certificateId,
            c.effectHash ^ 1,
        ),
    ];
    var i = 0;
    while (i < leaves.size()) {
        expect(
            sendApplyControl(env, deliverControlLeaf(env, leaves.get(i), c, 3)),
        ).toHaveFailedTx<SccpApplyControl>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadProof as int });
        i += 1;
    }
    applyControlOk(env, 1, true);
}

get fun `test a transfer leaf offered as a control is rejected`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(0, TEST_REVISION, T0 * 1000 + DAY_MS, 1, alice.accountId());
    val transferLeaf = inboundLeaf(env.networkId, payload, env.minter.address);
    var nonce = 0;
    while (nonce < 3) {
        val c = deliverControlLeaf(env, transferLeaf, parliamentControl(nonce, nonce == 1), 2);
        expect(sendApplyControl(env, c)).toHaveFailedTx<SccpApplyControl>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadProof as int });
        nonce += 1;
    }
    val leaves = leavesWith(controlLeafOf(env, parliamentControl(1, true)), 0, 2);
    val x = blockX(env.networkId, env.generation, env.committee.root(), 1100, leaves);
    val d: Delivery = {
        payload,
        x,
        cert: certifyFor(env, env.committee, x),
        proof: messageProofCell(0, treePath(leaves, 0), payload, ownBlockRef(x)),
        messageId: 0,
    };
    expect(sendFinalize(env, env.deployer, d, grams("5"))).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadProof as int });
}

get fun `test burns checkpoints rotations and voids stay open while paused`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 1000, alice);
    // Retain the original expiring transfer through the handoff's history.
    val expiring = deliver(
        env,
        env.committee,
        env.generation,
        1,
        5,
        alice,
        (T0 + 50) * 1000,
        0,
        1,
    );
    applyControlOk(env, 1, true);
    val burn = sendBurn(env, alice, 400, snakeOfLength(32), burnValue(env, alice));
    expect(burn).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(600);
    val next = testCommittee(4, 4);
    var x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    x.historySize = 1;
    x.historyRoot = sccpHistoryLeaf(expiring.x.height, expiring.x.sccpRoot, 1);
    expect(
        checkpointBy(env, env.committee, x, next.keysCell()),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    testing.setNow(T0 + 51);
    val proof = messageProofCell(
        0,
        [],
        expiring.payload,
        blockRefCell(expiring.x.height, expiring.x.sccpRoot, 1, 0, []),
    );
    expect(
        sendVoidExpiredCells(
            env,
            env.deployer,
            1,
            null,
            x.ref(),
            proof,
            env.minter.voidRequiredValue(1),
        ),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    // Controls themselves remain available under the successor's real source.
    val control = parliamentControl(2, false);
    val leaves = leavesWith(controlLeafOf(env, control), 0, 2);
    val resumeX = blockX(env.networkId, 8, next.root(), 1201, leaves);
    val resume: ControlDelivery = {
        x: resumeX,
        cert: certifyFor(env, next, resumeX),
        proof: controlProofCell(
            control.nonce,
            control.track,
            control.parliamentPaused,
            control.fastPauseUntilMs,
            control.certificateId,
            control.effectHash,
            0,
            treePath(leaves, 0),
            ownBlockRef(resumeX),
        ),
    };
    expect(sendApplyControl(env, resume)).toHaveSuccessfulTx<SccpApplyControl>({ to: env
            .minter
            .address });
    expect(env.minter.getSccpState().parliamentPaused).toBeFalse();
    expect(env.minter.getSccpState().controlNonce).toEqual(2);
    expect(env.minter.getSccpState().opCount).toEqual(5);
}

get fun `test a frozen destination cannot apply controls`() {
    val env = setupEnv();
    val c = deliverControl(env, 1, true);
    testing.setNow(defaultPin(env.committee).untilMs / 1000 + 1);
    expect(sendApplyControl(env, c)).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.CommitteeNotAccepted as int,
    });
}

get fun `test apply control needs exact quorum and the mainnet global id`() {
    val env = setupEnv();
    var c = deliverControl(env, 1, true);
    c.cert = certifyBy(env.committee, 0b1000, env.instance, defaultQc(c.x.height), c.x);
    expect(sendApplyControl(env, c)).toHaveFailedTx<SccpApplyControl>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadCertificate as int });
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(-3, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
    expect(
        sendApplyControl(env, deliverControl(env, 1, true)),
    ).toHaveFailedTx<SccpApplyControl>({ to: env
            .minter
            .address, exitCode: SccpErrors.WrongChain as int });
}

get fun `test fast pause expires without clearing Parliament state`() {
    val env = setupEnv();
    val until = (T0 + 50) * 1000;
    expect(
        sendApplyControl(env, deliverFastPause(env, 1, false, until)),
    ).toHaveSuccessfulTx<SccpApplyControl>({ to: env.minter.address });
    expect(env.minter.getSccpState().fastPauseUntilMs).toEqual(until);
    expect(env.minter.getSccpState().effectivePaused).toBeTrue();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.MintingIsPaused as int });
    testing.setNow(T0 + 51);
    expect(env.minter.getSccpState().effectivePaused).toBeFalse();
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    applyControlOk(env, 2, true);
    expect(
        sendApplyControl(env, deliverFastPause(env, 3, true, (T0 + 60) * 1000)),
    ).toHaveSuccessfulTx<SccpApplyControl>({ to: env.minter.address });
    testing.setNow(T0 + 61);
    expect(env.minter.getSccpState().parliamentPaused).toBeTrue();
    expect(env.minter.getSccpState().effectivePaused).toBeTrue();
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}
