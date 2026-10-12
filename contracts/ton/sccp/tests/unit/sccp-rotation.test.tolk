// Native committee rotation (§5.1.2–§5.1.3): current-generation CommitQC,
// exact handoff checkpoint reuse, sequential heights, expiry and key custody.

import "@stdlib/exotic-cells"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

get fun `test rotation installs the successor and retains the initial pin`() {
    val env = setupEnv();
    val next = testCommittee(7, 4);
    val res = rotateTo(env, next, 1200);
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    val event = res
        .findExternalOutMessage<SccpCommitteeRotatedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.generation).toEqual(8);
    expect(event.root).toEqual(next.root());
    expect(event.untilMs).toEqual(T0 * 1000 + TEST_VALIDITY_MS);
    expect(event.start).toEqual(1201);
    val state = env.minter.getSccpState();
    expect(state.root).toEqual(next.root());
    expect(state.generation).toEqual(8);
    expect(state.untilMs).toEqual(T0 * 1000 + TEST_VALIDITY_MS);
    expect(state.start).toEqual(1201);
    expect(state.high).toEqual(1200);
    expect(state.opCount).toEqual(0);
    expect(state.initialRoot).toEqual(env.committee.root());
    expect(state.initialGeneration).toEqual(7);
    expect(state.initialStart).toEqual(TEST_START_HEIGHT);
    expect(env.minter.getSccpCommittee().keys.hash()).toEqual(next.keysCell().hash());
}

get fun `test successor expiry is clamped to the local clock`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000 + DAY_MS,
        next.root(),
        2 * HOUR_MS,
    );
    expect(
        checkpointBy(env, env.committee, x, next.keysCell()),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    expect(env.minter.getSccpState().untilMs).toEqual(T0 * 1000 + 2 * HOUR_MS);
    testing.setNow(T0 + 2 * HOUR_MS / 1000 + 1);
    val expired = rotationX(
        env.networkId,
        8,
        next.root(),
        1201,
        testing.getNow() * 1000,
        next.root(),
        DAY_MS,
    );
    expect(checkpointBy(env, next, expired, null)).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
}

get fun `test only the exact handoff checkpoint remains usable after rotation`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val next = testCommittee(4, 4);
    val stale = deliverAt(
        env,
        env.committee,
        env.generation,
        1199,
        1,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    // Retain a genuine non-handoff predecessor before the current committee changes.
    expect(
        sendCheckpoint(env, env.deployer, stale.cert, null, grams("1")),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    var handoff = deliverAt(
        env,
        env.committee,
        env.generation,
        1200,
        0,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    handoff.x.flags = SCCP_X_FLAG_ACTIVE | SCCP_X_FLAG_ROTATION;
    handoff.x.timestampMs = T0 * 1000;
    handoff.x.validityMs = TEST_VALIDITY_MS;
    handoff.x.nextCommitteeRoot = next.root();
    handoff.cert = certifyFor(env, env.committee, handoff.x);
    // The proof still names the same block root and height.
    expect(
        sendCheckpoint(env, env.deployer, handoff.cert, next.keysCell(), grams("1")),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    expect(
        sendFinalize(env, env.deployer, handoff, finalizeValue(env, 0)),
    ).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
    expect(
        sendFinalizeCheckpoint(env, env.deployer, handoff, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalizeCheckpoint>({ to: env.minter.address });
    expect(
        sendFinalize(env, env.deployer, stale, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
    // Both original checkpoints fit; this reaches U1/U2, not UnknownCheckpoint.
    expect(
        sendFinalizeCheckpoint(env, env.deployer, stale, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalizeCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
    val fresh = deliverAt(
        env,
        next,
        8,
        1201,
        1,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    expect(
        sendFinalize(env, env.deployer, fresh, finalizeValue(env, 1)),
    ).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(20);
}

get fun `test sequential rotations advance one generation and height`() {
    val env = setupEnv();
    val g8 = testCommittee(4, 4);
    rotateTo(env, g8, 1200);
    val g9 = testCommittee(31, 0);
    rotateFrom(env, g8, 8, g9, 1201);
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(9);
    expect(state.root).toEqual(g9.root());
    expect(state.start).toEqual(1202);
    expect(state.high).toEqual(1201);
    val alice = testing.treasury("alice").address;
    val stale = deliverDefault(env, 0, 1, alice);
    expect(
        sendFinalize(env, env.deployer, stale, grams("5")),
    ).toHaveFailedTx<SccpFinalize>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
    val skipped = rotationX(
        env.networkId,
        10,
        g9.root(),
        1202,
        T0 * 1000,
        testCommittee(4, 8).root(),
        DAY_MS,
    );
    expect(
        checkpointBy(env, g9, skipped, testCommittee(4, 8).keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
}

get fun `test only the current committee may sign a rotation`() {
    val env = setupEnv();
    val g8 = testCommittee(4, 4);
    rotateTo(env, g8, 1200);
    val g9 = testCommittee(4, 8);
    val stale = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1201,
        T0 * 1000,
        g9.root(),
        DAY_MS,
    );
    expect(
        checkpointBy(env, env.committee, stale, g9.keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
    // Claiming the current root with old keys does not authenticate it.
    var forged = stale;
    forged.generation = 8;
    forged.committeeRoot = g8.root();
    expect(
        checkpointBy(env, env.committee, forged, g9.keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadSignature as int });
}

get fun `test rotation binds the announced root timestamp and exact quorum`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000,
        next.root(),
        DAY_MS,
    );
    var zero = x;
    zero.nextCommitteeRoot = 0;
    expect(
        checkpointBy(env, env.committee, zero, next.keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadHeader as int });
    expect(
        checkpointBy(env, env.committee, x, testCommittee(4, 5).keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadCommittee as int });
    // A timestamp change without a new QC is a signature failure.
    val qc = defaultQc(x.height);
    val signature = blsAggregateSign(
        env.committee.secretsOf(0b0111),
        commitMessage(env.instance, qc, x),
    );
    var shifted = x;
    shifted.timestampMs += 1;
    expect(
        sendCheckpoint(
            env,
            env.deployer,
            certOf(signature, 0b0111, qc, shifted),
            next.keysCell(),
            grams("1"),
        ),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.BadSignature as int });
    val bitmaps: array<int> = [0b0011, 0b1111];
    var i = 0;
    while (i < bitmaps.size()) {
        val cert = certifyBy(env.committee, bitmaps.get(i), env.instance, qc, x);
        expect(
            sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1")),
        ).toHaveFailedTx<SccpCheckpoint>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadCertificate as int });
        i += 1;
    }
}

get fun `test rotation validity bounds and already expired successor`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val bad: array<int> = [0, SCCP_MAX_VALIDITY_MS + 1];
    var i = 0;
    while (i < bad.size()) {
        val x = rotationX(
            env.networkId,
            env.generation,
            env.committee.root(),
            1200,
            T0 * 1000,
            next.root(),
            bad.get(i),
        );
        expect(
            checkpointBy(env, env.committee, x, next.keysCell()),
        ).toHaveFailedTx<SccpCheckpoint>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadHeader as int });
        i += 1;
    }
    // A genuine old handoff persists even when its successor is already expired.
    val expired = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000 - 2 * DAY_MS,
        next.root(),
        DAY_MS,
    );
    expect(
        checkpointBy(env, env.committee, expired, next.keysCell()),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    expect(env.minter.getSccpState().generation).toEqual(8);
    expect(env.minter.getSccpState().untilMs).toEqual(T0 * 1000 - DAY_MS);
    expect(env.minter.getSccpState().equivocated).toBeFalse();
    val fresh = setupEnv();
    val edge = rotationX(
        fresh.networkId,
        fresh.generation,
        fresh.committee.root(),
        1200,
        T0 * 1000 + DAY_MS,
        next.root(),
        SCCP_MAX_VALIDITY_MS,
    );
    expect(
        checkpointBy(fresh, fresh.committee, edge, next.keysCell()),
    ).toHaveSuccessfulTx<SccpCheckpoint>({ to: fresh.minter.address });
    expect(fresh.minter.getSccpState().untilMs).toEqual(T0 * 1000 + SCCP_MAX_VALIDITY_MS);
}

get fun `test rotation rejects missing malformed and unordered next keys`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000,
        next.root(),
        DAY_MS,
    );
    val k = next.keys;
    val cases: array<cell?> = [
        null,
        sccpBuildKeys([k.get(0), k.get(1), k.get(2)]),
        sccpBuildKeys([k.get(1), k.get(0), k.get(2), k.get(3)]),
        sccpBuildKeys([k.get(0), k.get(0), k.get(2), k.get(3)]),
    ];
    var i = 0;
    while (i < cases.size()) {
        expect(
            checkpointBy(env, env.committee, x, cases.get(i)),
        ).toHaveFailedTx<SccpCheckpoint>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadCommittee as int });
        i += 1;
    }
}

get fun `test rotation rejects library keys and retains an ordinary list`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val canonical = next.keysCell();
    testing.registerLibrary(canonical);
    val tail = canonical.beginParse().preloadRef();
    testing.registerLibrary(tail);
    val k = next.keys;
    val tailLibrary = beginCell()
        .storeSlice(k.get(0))
        .storeSlice(k.get(1))
        .storeMaybeRef(tail.toLibraryReference())
        .endCell();
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        T0 * 1000,
        next.root(),
        DAY_MS,
    );
    val cases: array<cell> = [canonical.toLibraryReference(), tailLibrary];
    var i = 0;
    while (i < cases.size()) {
        expect(
            checkpointBy(env, env.committee, x, cases.get(i)),
        ).toHaveFailedTx<SccpCheckpoint>({ to: env
                .minter
                .address, exitCode: SccpErrors.BadSnake as int });
        i += 1;
    }
    expect(env.minter.getSccpState().generation).toEqual(7);
    rotateTo(env, next, 1200);
    expect(env.minter.getSccpState().generation).toEqual(8);
    val installed = minterStorage(env).committee.load();
    val (_, isExotic) = installed.keys.beginParseSpecial();
    expect(isExotic).toBeFalse();
    expect(installed.keys.hash()).toEqual(canonical.hash());
}

get fun `test an expired destination cannot rotate`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    testing.setNow(defaultPin(env.committee).untilMs / 1000 + 1);
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        1200,
        testing.getNow() * 1000,
        next.root(),
        DAY_MS,
    );
    expect(
        checkpointBy(env, env.committee, x, next.keysCell()),
    ).toHaveFailedTx<SccpCheckpoint>({ to: env
            .minter
            .address, exitCode: SccpErrors.CommitteeNotAccepted as int });
}
