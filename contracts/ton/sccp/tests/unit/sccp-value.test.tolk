// Minter value safety (specs/sccp.md §5.3.5, §5.3.4 item 7): quotes and entry
// checks share the stored balance basis, so an exact quote stays valid while
// time passes; entry values are checked before any signature work; a minter
// below its floor charges the deficit to the next entry call, also when that
// call latches; burns and bucket replies never pay toward MINTER_FLOOR; an
// event that cannot be sent aborts its step and bounces the inbound message.

import "@stdlib/gas-payments"
import "@acton/io"
import "@acton/emulation/config"
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
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

const DAY_S = 86400
/// Seconds of the default pin: `cur.untilMs` is 14 days after `T0`.
const PIN_VALIDITY_S = 1209600

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

/// Inline `sccp_apply_control` of `c` with `value` attached.
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

/// The handoff of generation `generation` of `current` to `next` at `height`,
/// dated one second ago and valid for 14 days, with its `CommitQC`.
fun handoffCert(
    env: Env,
    current: TestCommittee,
    generation: int,
    next: TestCommittee,
    height: int,
): cell {
    return certifyFor(
        env,
        current,
        rotationX(
            env.networkId,
            generation,
            current.root(),
            height,
            testing.getNow() * 1000 - 1000,
            next.root(),
            TEST_VALIDITY_MS,
        ),
    );
}

/// Sends `sccp_deploy_buckets` for `count` buckets with `value` attached.
fun sendDeployBuckets(env: Env, count: int, value: coins): SendResultList {
    return env
        .minter
        .sendSccpDeployBuckets(env.deployer, 1, env.deployer, count, { value, bounce: true });
}

/// Value of the excess that `res` returned to `to`.
fun excessTo(res: SendResultList, to: address): coins {
    val tx = res.findTransaction<ReturnExcessesBack>({ to })!;
    val info = tx.loadInMsg<ReturnExcessesBack>().info;
    if (info is TlbInternalMessage) {
        return info.value.grams;
    }
    return 0;
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

    // a checkpoint that rotates the keys
    val next = testCommittee(4, 4);
    val q3 = env.minter.checkpointRequiredValue();
    testing.setNow(T0 + 7 * DAY_S);
    val handoffHeight = TEST_START_HEIGHT + 150;
    expect(
        sendCheckpoint(
            env,
            env.deployer,
            handoffCert(env, env.committee, env.generation, next, handoffHeight),
            next.keysCell(),
            q3,
        ),
    ).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);
    // the successor is valid for 14 days from the handoff
    val successorUntilS = T0 + 7 * DAY_S - 1 + PIN_VALIDITY_S;
    expect(env.minter.getSccpState().untilMs).toEqual(successorUntilS * 1000);
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
    expect(sendDeployBuckets(env, 2, q4)).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(3);

    // void an expired message, certified by the new committee
    val expired = deliverAt(
        env8,
        next,
        env8.generation,
        handoffHeight + 50,
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

    // void frozen once the generation expired
    testing.setNow(successorUntilS + 1);
    val q6 = env.minter.voidFrozenRequiredValue(512);
    testing.setNow(successorUntilS + 4 * DAY_S);
    expect(sendVoidFrozen(env, 512, 7, q6)).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 518)).toBeTrue();

    // a month later a burn completes; the burner's value adds nothing to the
    // minter (the range reply above left its value in the minter)
    testing.setNow(successorUntilS + 34 * DAY_S);
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
    expect(env.minter.voidRequiredValue(1)).toEqual(
        sccpVoidRequiredValue(0) + sccpMinterStorageGrace(),
    );
    expect(env.minter.voidFrozenRequiredValue(512)).toEqual(
        sccpVoidFrozenRequiredValue(1) + sccpMinterStorageGrace(),
    );
    expect(env.minter.minterFloor()).toEqual(sccpMinterFloor());
    // the grace is seven days of storage of the largest minter
    expect(sccpMinterStorageGrace()).toEqual(
        calculateStorageFee(
            BASECHAIN,
            7 * DAY_S,
            SCCP_MINTER_STATE_BITS,
            SCCP_MINTER_STATE_CELLS,
        ),
    );
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
    val rejected = sendDeployBuckets(env, 1, stale);
    expect(rejected).toHaveFailedTx<SccpDeployBuckets>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(rejected).toHaveTx({ to: env.deployer, bounced: true });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(1);
    val fresh = env.minter.deployBucketsRequiredValue(1);
    expect(fresh > stale).toBeTrue();
    expect(sendDeployBuckets(env, 1, fresh)).toHaveAllSuccessfulTxs();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
}

get fun `test an underfunded call fails before any signature is verified`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    // `BLS_FASTAGGREGATEVERIFY` alone costs 58 000 + 3 000 · 21 gas at n = 31
    val beforeTheOpcode = 30000;
    val d = deliverDefault(env, 0, 10, alice);
    val poor = sendFinalize(env, env.deployer, d, sccpFinalizeRequiredValue(1) - 1);
    expect(poor).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    println("gas of an underfunded n=31 finalize: {}", stepGas(poor));
    expect(stepGas(poor) < beforeTheOpcode).toBeTrue();
    testing.setNow(T0 + DAY_S + 1);
    val void = sendVoidExpired(env, env.deployer, 0, d, sccpVoidRequiredValue(1) - 1);
    expectOutcome(void, SccpErrors.NotEnoughValue);
    expect(stepGas(void) < beforeTheOpcode).toBeTrue();
    val c = deliverControl(env, 1, true);
    val control = sendControlWith(env, c, sccpApplyControlRequiredValue() - 1);
    expect(control).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(stepGas(control) < beforeTheOpcode).toBeTrue();
    val next = testCommittee(31, 4);
    val rotation = sendCheckpoint(
        env,
        env.deployer,
        handoffCert(env, env.committee, env.generation, next, TEST_START_HEIGHT + 300),
        next.keysCell(),
        sccpCheckpointRequiredValue() - 1,
    );
    expect(rotation).toHaveFailedTx<SccpCheckpoint>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    expect(stepGas(rotation) < beforeTheOpcode).toBeTrue();
    // nothing was verified, recorded or published, and every value bounced
    expectEvents(rotation, []);
    expect(rotation).toHaveTx({ to: env.deployer, bounced: true });
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(env.generation);
    expect(state.high).toEqual(TEST_START_HEIGHT - 1);
    expect(state.controlNonce).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(env.minter.getSccpCheckpoints().count).toEqual(0);
    // the steps without a certificate check their value too
    expectOutcome(
        sendDeployBuckets(env, 2, sccpDeployBucketsRequiredValue(2) - 1),
        SccpErrors.NotEnoughValue,
    );
    expectOutcome(sendRetry(env, 0, sccpRetryRequiredValue() - 1), SccpErrors.NotEnoughValue);
    testing.setNow(T0 + PIN_VALIDITY_S + 1);
    expectOutcome(
        sendVoidFrozen(env, 0, 1, sccpVoidFrozenRequiredValue(1) - 1),
        SccpErrors.NotEnoughValue,
    );
    expect(env.minter.getSccpState().deployedBuckets).toEqual(0);
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

get fun `test a bucket reply at a minter below its floor completes without paying toward it`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);
    val d = deliverDefault(env, 1, 300, alice);
    val cursor = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 1),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                cert: d.cert as Cell<TairaCert>,
                message: d.proof as Cell<MessageProof>,
            },
        }),
    );
    // the minter step and the consume at the bucket: the reply is in flight
    cursor.executeN(2);
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // storage drift or a storage-price increase leaves the minter far below its floor
    val low = sccpMinterFloor() / 2;
    setAccountBalance(env.minter.address, low);
    val rest = cursor.executeAllRemaining();
    cursor.close();
    expect(rest).toHaveAllSuccessfulTxs();
    expect(rest).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(rest).toEmitExternalMessage<SccpFinalizedEvent>();
    expect(jettonBalanceOf(env, alice)).toEqual(1300);
    // the reply kept the prior balance and paid nothing toward the floor
    expect(testing.getAccountBalance(env.minter.address)).toEqual(low);

    // `sccp_already_consumed` does the same. The entry call of the duplicate
    // pays the deficit; then the balance drops again before the reply.
    val duplicate = testing.createTraceIterationCursor(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: finalizeValue(env, 1),
            dest: env.minter.address,
            body: SccpFinalize {
                queryId: 1,
                response: env.deployer,
                cert: d.cert as Cell<TairaCert>,
                message: d.proof as Cell<MessageProof>,
            },
        }),
    );
    duplicate.executeN(2);
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    setAccountBalance(env.minter.address, low);
    val refused = duplicate.executeAllRemaining();
    duplicate.close();
    expect(refused).toHaveAllSuccessfulTxs();
    expect(refused).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(refused).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(testing.getAccountBalance(env.minter.address)).toEqual(low);
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(1300);
}

get fun `test storage a caller did not pay for stays a deficit for the next caller`() {
    val alice = testing.treasury("alice").address;
    val env = envAtFloor(alice);
    val floor = sccpMinterFloor();
    testing.setNow(T0 + 3 * DAY_S);
    // the stored balance is the floor, so the entry minimum is the step alone
    val c = deliverControl(env, 1, true);
    val step = sccpApplyControlRequiredValue();
    val res = sendControlWith(env, c, step);
    expect(res).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().parliamentPaused).toBeTrue();
    // The reserve never takes from the part the step needs: the three days
    // of storage that this transaction collected are not topped up.
    val after = testing.getAccountBalance(env.minter.address);
    val deficit = floor - after;
    expect(deficit > 0).toBeTrue();
    // seven days of the largest state cover three days of the actual one
    expect(deficit < sccpMinterStorageGrace()).toBeTrue();
    // the next caller is quoted the deficit and closes it
    val quote = env.minter.applyControlRequiredValue();
    expect(quote).toEqual(step + deficit + sccpMinterStorageGrace());
    val next = deliverControl(env, 2, false);
    expectOutcome(sendControlWith(env, next, step + deficit - 1), SccpErrors.NotEnoughValue);
    expect(sendControlWith(env, next, step + deficit)).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().controlNonce).toEqual(2);
    expect(testing.getAccountBalance(env.minter.address)).toEqual(floor);
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

get fun `test a latch at a minter below its floor keeps the deficit and refunds the rest`() {
    val env = setupEnvFunded(4, TEST_MAX_SUPPLY, grams("0.2"));
    val floor = sccpMinterFloor();
    val balance = testing.getAccountBalance(env.minter.address);
    val deficit = floor - balance;
    expect(deficit > 0).toBeTrue();
    // a certificate below the start of its generation: V2
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    val cert = certifyFor(env, env.committee, below);
    // the value is checked before the certificate, whatever the certificate does
    val step = sccpCheckpointRequiredValue();
    val poor = sendCheckpoint(env, env.deployer, cert, null, step + deficit - 1);
    expectOutcome(poor, SccpErrors.NotEnoughValue);
    expect(poor).toHaveBouncedTx({ to: env.deployer });
    expect(env.minter.getSccpState().equivocated).toBeFalse();
    // with the quote and a surplus the latch is persisted and nothing is thrown
    val surplus = grams("3");
    val value = env.minter.checkpointRequiredValue() + surplus;
    val res = sendCheckpoint(env, env.deployer, cert, null, value);
    expectOutcome(res, 0);
    expect(res).toHaveAllSuccessfulTxs();
    expectEvents(
        res,
        [
            eventCertificate(below.height, env.generation, cert),
            eventLatched(
                SCCP_LATCH_V2,
                env.generation,
                below.height,
                env.committee.root(),
                below.id(),
            ),
        ],
    );
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    // the minter kept exactly its floor; the caller got back everything but
    // the deficit and what the step spent, which is less than the step value
    expect(testing.getAccountBalance(env.minter.address)).toEqual(floor);
    val refund = excessTo(res, env.deployer);
    expect(refund < value - deficit).toBeTrue();
    expect(refund > value - deficit - step).toBeTrue();
    expect(refund > surplus).toBeTrue();
}

get fun `test a top-up closes the floor deficit for the next caller`() {
    val env = setupEnvFunded(4, TEST_MAX_SUPPLY, grams("0.2"));
    val stranger = testing.treasury("stranger").address;
    val floor = sccpMinterFloor();
    val deficit = floor - testing.getAccountBalance(env.minter.address);
    expect(env.minter.deployBucketsRequiredValue(1)).toEqual(
        sccpDeployBucketsRequiredValue(1) + deficit + sccpMinterStorageGrace(),
    );
    // anyone may add to the floor (§5.3.5)
    expect(
        env.minter.sendTopUpTons(stranger, 0, { value: deficit + grams("1") }),
    ).toHaveSuccessfulTx<TopUpTons>({ to: env.minter.address });
    val topped = testing.getAccountBalance(env.minter.address);
    expect(topped > floor).toBeTrue();
    val quote = env.minter.deployBucketsRequiredValue(1);
    expect(quote).toEqual(sccpDeployBucketsRequiredValue(1) + sccpMinterStorageGrace());
    // the step keeps the balance above the floor and takes nothing from it
    expect(sendDeployBuckets(env, 1, quote)).toHaveAllSuccessfulTxs();
    expect(testing.getAccountBalance(env.minter.address)).toEqual(topped);
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
}
