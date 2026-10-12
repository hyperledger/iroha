// Minter value safety (§5.3.5): quotes and entry checks share the stored
// balance basis, so exact quotes stay valid while time passes; entry values
// are checked before signatures; burns never pay toward MINTER_FLOOR; every
// external-out event bounces its step when it cannot be sent; under-floor
// controls need their quote instead of failing silently.

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

const DAY_S = 86400

/// A minter deployed with 0.2 TON whose first finalize (nonce 0, 1000 to
/// `alice`) paid the floor deficit: it then holds exactly MINTER_FLOOR.
fun envAtFloor(alice: address): Env {
    val env = setupEnvFunded(4, TEST_MAX_SUPPLY, grams("0.2"));
    expect(testing.getAccountBalance(env.minter.address) < sccpMinterFloor()).toBeTrue();
    val d = deliverDefault(env, 0, 1000, alice);
    expect(sendFinalize(env, env.deployer, d, finalizeValue(env, 0))).toHaveAllSuccessfulTxs();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
    return env;
}

/// Native certificate and full-state control proof with explicit entry value.
fun sendControlWith(env: Env, c: ControlDelivery, value: coins): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        c.cert,
        null,
        c.proof,
        value,
    );
}

fun sendRotateWith(env: Env, next: TestCommittee, height: int, value: coins): SendResultList {
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        height,
        testing.getNow() * 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    return sendCheckpoint(
        env,
        env.deployer,
        certifyFor(env, env.committee, x),
        next.keysCell(),
        value,
    );
}

get fun `test exact quotes taken before time advances still pass at the floor`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);

    // finalize: quote now, send five days later
    val d1 = deliver(
        env,
        env.committee,
        env.generation,
        1,
        10,
        alice,
        (T0 + 12 * DAY_S) * 1000,
        1,
        3,
    );
    val q1 = finalizeValue(env, 1);
    testing.setNow(T0 + 5 * DAY_S);
    expect(sendFinalize(env, env.deployer, d1, q1)).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(1010);

    // apply control
    val c = deliverControl(env, 1, false);
    val q2 = env.minter.applyControlRequiredValue();
    testing.setNow(T0 + 6 * DAY_S);
    expect(sendControlWith(env, c, q2)).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().controlNonce).toEqual(1);

    // rotate
    val next = testCommittee(4, 4);
    val q3 = env.minter.checkpointRequiredValue();
    testing.setNow(T0 + 7 * DAY_S);
    expect(sendRotateWith(env, next, 1104, q3)).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().generation).toEqual(8);
    val env8: Env = {
        minter: env.minter,
        deployer: env.deployer,
        networkId: env.networkId,
        instance: env.instance,
        generation: env.generation + 1,
        committee: next,
    };

    // deploy buckets
    val q4 = env.minter.deployBucketsRequiredValue(2);
    testing.setNow(T0 + 8 * DAY_S);
    expect(
        env
            .minter
            .sendSccpDeployBuckets(env.deployer, 1, env.deployer, 2, { value: q4, bounce: true }),
    ).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(3);

    // void an expired message, signed by the new committee
    val expired = deliverAt(
        env8,
        next,
        env8.generation,
        1105,
        2,
        5,
        alice,
        (T0 + DAY_S) * 1000,
        1,
        3,
    );
    val q5 = env.minter.voidRequiredValue(2);
    testing.setNow(T0 + 9 * DAY_S);
    expect(sendVoidExpired(env8, env.deployer, 2, expired, q5)).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 2)).toBeTrue();

    // void frozen once the current committee expired
    testing.setNow(env.minter.getSccpState().untilMs / 1000 + 1);
    val q6 = env.minter.voidFrozenRequiredValue(512);
    testing.setNow(env.minter.getSccpState().untilMs / 1000 + 4 * DAY_S);
    expect(
        env
            .minter
            .sendSccpVoidFrozen(
                env.deployer,
                2,
                env.deployer,
                512,
                7,
                { value: q6, bounce: true },
            ),
    ).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 518)).toBeTrue();

    // a month later a burn completes; the burner's value adds nothing to the
    // minter (the range reply above left its value in the minter)
    testing.setNow(env.minter.getSccpState().untilMs / 1000 + 34 * DAY_S);
    val before = testing.getAccountBalance(env.minter.address);
    val burn = sendBurn(env, alice, 10, snakeOfLength(8), burnValue(env, alice));
    expect(burn).toHaveAllSuccessfulTxs();
    expect(burn).toEmitExternalMessage<SccpTransferToTairaEvent>();
    expect(testing.getAccountBalance(env.minter.address) < before).toBeTrue();
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
}

get fun `test the quote is the entry minimum plus the storage grace`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);
    testing.setNow(T0 + 3 * DAY_S);
    // the stored balance is still exactly the floor: no deficit
    val quote = env.minter.applyControlRequiredValue();
    expect(quote).toEqual(sccpApplyControlRequiredValue() + sccpMinterStorageGrace());
    expect(env.minter.checkpointRequiredValue()).toEqual(
        sccpCheckpointRequiredValue() + sccpMinterStorageGrace(),
    );
    expect(env.minter.retryRequiredValue()).toEqual(
        sccpRetryRequiredValue() + sccpMinterStorageGrace(),
    );
    expect(env.minter.minterFloor()).toEqual(sccpMinterFloor());
    val c = deliverControl(env, 1, true);
    val poor = sendControlWith(env, c, sccpApplyControlRequiredValue() - 1);
    expect(poor).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(poor).toHaveTx({ to: env.deployer, bounced: true });
    expect(env.minter.getSccpState().parliamentPaused).toBeFalse();
    // the failed call collected three days of storage, which the grace of the
    // earlier quote covers; the floor is topped up again from the grace
    expect(testing.getAccountBalance(env.minter.address) < sccpMinterFloor()).toBeTrue();
    val ok = sendControlWith(env, c, quote);
    expect(ok).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().parliamentPaused).toBeTrue();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());

    // a quote goes stale only when another transaction collects more storage
    // than the grace: here a burn after five idle weeks
    testing.setNow(T0 + 40 * DAY_S);
    val stale = env.minter.deployBucketsRequiredValue(1);
    expect(stale).toEqual(sccpDeployBucketsRequiredValue(1) + sccpMinterStorageGrace());
    expect(
        sendBurn(env, alice, 1, snakeOfLength(8), burnValue(env, alice)),
    ).toHaveAllSuccessfulTxs();
    val rejected = env
        .minter
        .sendSccpDeployBuckets(env.deployer, 1, env.deployer, 1, { value: stale, bounce: true });
    expect(rejected).toHaveFailedTx<SccpDeployBuckets>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    val fresh = env.minter.deployBucketsRequiredValue(1);
    expect(fresh > stale).toBeTrue();
    expect(
        env
            .minter
            .sendSccpDeployBuckets(
                env.deployer,
                1,
                env.deployer,
                1,
                { value: fresh, bounce: true },
            ),
    ).toHaveAllSuccessfulTxs();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
}

get fun `test an underfunded call fails before any signature is verified`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    val poor = sendFinalize(env, env.deployer, d, sccpFinalizeRequiredValue(1) - 1);
    expect(poor).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    val cheap = poor.getUsedGas<SccpFinalize>({ to: env.minter.address });
    println("gas of an underfunded n=31 finalize: {}", cheap);
    // The native aggregate opcode alone costs 58000 + 3000*q gas
    expect(cheap < 30000).toBeTrue();
    val c = deliverControl(env, 1, true);
    val control = sendControlWith(env, c, sccpApplyControlRequiredValue() - 1);
    expect(control).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(control.getUsedGas<SccpApplyControl>({ to: env.minter.address }) < 30000).toBeTrue();
    val next = testCommittee(4, 4);
    val rotate = sendRotateWith(env, next, 1104, sccpCheckpointRequiredValue() - 1);
    expect(rotate).toHaveFailedTx<SccpCheckpoint>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(rotate.getUsedGas<SccpCheckpoint>({ to: env.minter.address }) < 30000).toBeTrue();
}

get fun `test burns below the floor complete without paying toward it`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);
    // storage drift or a storage-price increase left the minter far below its floor
    val low = sccpMinterFloor() / 2;
    setAccountBalance(env.minter.address, low);
    val burn = sendBurn(env, alice, 400, snakeOfLength(1024), burnValue(env, alice));
    expect(burn).toHaveAllSuccessfulTxs();
    val event = burn
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.amount).toEqual(400);
    expect(event.nonce).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(600);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(600);
    expect(state.outboundNonce).toEqual(1);
    // the prior balance is kept, nothing more
    expect(testing.getAccountBalance(env.minter.address)).toEqual(low);
}

get fun `test a burn whose event cannot be sent bounces and restores the wallet`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);
    val payload: SccpBurnToTaira = { recipient: snakeOfLength(1024) };
    val cursor = testing.createTraceIterationCursor(
        alice,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: burnValue(env, alice),
            dest: walletOf(env, alice).address,
            body: AskToBurn {
                queryId: 3,
                jettonAmount: 250,
                sendExcessesTo: alice,
                customPayload: payload.toCell(),
            },
        }),
    );
    // the wallet debits and sends burn_notification
    cursor.executeN(1);
    expect(jettonBalanceOf(env, alice)).toEqual(750);
    // forwarding per bit rises before the minter runs: the 9-cell event can no
    // longer be paid, while the single-cell bounce still can
    val previous = raiseBitForwardPrice(100);
    val rest = cursor.executeAllRemaining();
    cursor.close();
    expect(testing.setConfig(previous)).toBeTrue();
    expect(rest).toHaveTx<BurnNotificationForMinter>({ to: env.minter.address, success: false });
    expect(rest).toHaveTx({ to: walletOf(env, alice).address, bounced: true });
    expect(
        rest.findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    // the bounce restored the wallet; the minter state never changed
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(1000);
    expect(state.outboundNonce).toEqual(0);
    expect(state.opCount).toEqual(1);
}

get fun `test apply control on an under-floor minter needs its quote`() {
    // a fresh deployment below the floor: a Parliament pause before any finalize
    val env = setupEnvFunded(4, TEST_MAX_SUPPLY, grams("0.2"));
    val balance = testing.getAccountBalance(env.minter.address);
    val quote = env.minter.applyControlRequiredValue();
    expect(quote).toEqual(
        sccpApplyControlRequiredValue() + sccpMinterFloor() - balance + sccpMinterStorageGrace(),
    );
    val c = deliverControl(env, 1, true);
    // without the deficit: rejected and bounced, nothing applied or absorbed
    val poor = sendControlWith(env, c, sccpApplyControlRequiredValue());
    expect(poor).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(poor).toHaveBouncedTx({ to: env.deployer });
    expect(env.minter.getSccpState().parliamentPaused).toBeFalse();
    val ok = sendControlWith(env, c, quote);
    expect(ok).toHaveAllSuccessfulTxs();
    expect(ok).toEmitExternalMessage<SccpControlAppliedEvent>();
    expect(env.minter.getSccpState().parliamentPaused).toBeTrue();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
}
