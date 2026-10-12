// Voids (specs/sccp.md §5.1.8, §5.3.4 "Void"): `sccp_void_expired` in its
// inline and its checkpoint form after the deadline, with the nonce argument,
// and `sccp_void_frozen` over one bucket once the minter is `Frozen` by
// expiry or by a latch, with the range and reject rules.

import "@acton/io"
import "@acton/emulation/config"
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
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Destination clock at which every test of this suite starts, in ms.
const NOW_MS = 1800000000000
/// `cur.untilMs` of the default pin: 14 days after `NOW_MS`.
const PIN_UNTIL_MS = 1801209600000
/// Deadline of the transfers of this suite: 100 seconds after the start.
const DEADLINE_MS = 1800000100000
/// Taira→TON rows of `directions` in `payload_v1.json` that this suite voids.
const PINNED_INBOUND_PAYLOAD_VECTORS = 1
/// All 256 bits of a bucket half.
const ALL_BITS = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

/// A transfer of 100 units to `recipient` that expires at `DEADLINE_MS`:
/// leaf 1 of 3 of its block.
fun expiredDelivery(env: Env, nonce: int, recipient: address): Delivery {
    return deliver(
        env,
        env.committee,
        env.generation,
        nonce,
        100,
        recipient,
        DEADLINE_MS,
        1,
        3,
    );
}

/// Body of `sccp_voided`.
fun eventVoided(messageId: int, firstNonce: int, count: int): cell {
    return SccpVoidedEvent { messageId, firstNonce, count }.toCell();
}

/// Sends `sccp_void_expired` from the deployer with the nonce argument
/// `nonce`, the `^TairaCert` `cert` and the `^MessageProof` `proof`.
fun voidInline(env: Env, nonce: int, cert: cell, proof: cell, value: coins): SendResultList {
    return sendVoidExpiredCells(
        env,
        env.deployer,
        nonce,
        cert,
        null,
        proof,
        value,
    );
}

/// Sends `sccp_void_expired_checkpoint` from the deployer with the nonce
/// argument `nonce`, the `^CheckpointRef` `ref` and the `^MessageProof`
/// `proof`.
fun voidStored(env: Env, nonce: int, ref: cell, proof: cell, value: coins): SendResultList {
    return sendVoidExpiredCells(
        env,
        env.deployer,
        nonce,
        null,
        ref,
        proof,
        value,
    );
}

/// Sets `GLOBALID` of the emulated chain (config parameter 19).
fun setGlobalId(id: int) {
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(id, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
}

/// Latches the minter with a certificate of its generation below its start.
fun latch(env: Env) {
    val below = emptyX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT - 1,
    );
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
}

/// Expects a refused void: its exit code, no event, nothing consumed and
/// nothing counted.
fun expectRefused(env: Env, res: SendResultList, exitCode: int) {
    if (outcomeOf(res) != exitCode) {
        println("expected {} observed {}", exitCode, outcomeOf(res));
    }
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(state.deployedBuckets).toEqual(0);
}

// ---------------------------------------------------------------------------
// `sccp_void_expired` and `sccp_void_expired_checkpoint`.

get fun `test void expired consumes the nonce and emits sccp_voided`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 3, alice);
    testing.setNow(T0 + 101);
    val res = sendVoidExpired(env, env.deployer, 3, d, env.minter.voidRequiredValue(3));
    expect(res).toHaveSuccessfulTx<SccpVoidExpired>({ to: env.minter.address });
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsume>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    expect(res).toHaveAllSuccessfulTxs();
    // the inline certificate is published and its checkpoint recorded
    expectEvents(
        res,
        [
            eventCertificate(d.x.height, env.generation, d.cert),
            eventCheckpointed(d.x.height, d.x.id()),
            eventVoided(d.messageId, 3, 1),
        ],
    );
    val event = res.findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address });
    expect(event).toBeNotNull();
    val body = event!.loadBody();
    expect(body.messageId).toEqual(d.messageId);
    expect(body.firstNonce).toEqual(3);
    expect(body.count).toEqual(1);
    // sccp_voided#5343564f message_id:uint256 first_nonce:uint64 count:uint16 (§5.3.3)
    val raw = eventVoided(d.messageId, 3, 1).beginParse();
    expect(raw.preloadUint(32)).toEqual(0x5343564f);
    expect(raw.remainingBitsCount()).toEqual(32 + 256 + 64 + 16);
    expect(raw.remainingRefsCount()).toEqual(0);
    expect(isConsumedAt(env, 3)).toBeTrue();
    expect(isConsumedAt(env, 2)).toBeFalse();
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.totalSupply).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(state.high).toEqual(d.x.height);
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    replayExpectCheckpoints(
        env,
        1,
        d.x.height,
        d.x.id(),
        0,
        0,
        0,
        0,
    );
    reportGas("void inline n=4", stepGas(res), SCCP_GAS_MINTER_VOID);
    reportGas(
        "minter sccp_consumed void",
        res.getUsedGas<SccpConsumed>({ to: env.minter.address }),
        SCCP_GAS_MINTER_CONSUMED,
    );
    // a void is final: the message can no longer be finalized (it is expired
    // anyway) nor voided twice
    val again = sendVoidExpired(env, env.deployer, 3, d, env.minter.voidRequiredValue(3));
    expect(again).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(again).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expectEvents(again, []);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 3)),
        SccpErrors.DeadlinePassed,
    );
}

get fun `test the Taira to TON payload vector of the fixture is voided under its message id`() {
    // `directions` of `payload_v1.json` holds one payload of this lane
    var replayed = 0;
    val env = setupEnv();
    val payload = snakeFromPieces(vecInboundPayloadPieces());
    val leaves = leavesWith(sccpTransferLeaf(VEC_INBOUND_MESSAGE_ID, VEC_MINTER_ACCOUNT_ID), 1, 3);
    val x = blockX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 10,
        leaves,
    );
    val cert = certifyFor(env, env.committee, x);
    val proof = messageProofCell(1, treePath(leaves, 1), payload, ownBlockRef(x));
    // at its deadline the transfer can still be minted
    expect(VEC_INBOUND_DEADLINE_MS % 1000).toEqual(0);
    testing.setNow(VEC_INBOUND_DEADLINE_MS / 1000);
    expectRefused(
        env,
        voidInline(env, VEC_INBOUND_NONCE, cert, proof, grams("5")),
        SccpErrors.DeadlineNotReached,
    );
    testing.setNow(VEC_INBOUND_DEADLINE_MS / 1000 + 1);
    val res = voidInline(
        env,
        VEC_INBOUND_NONCE,
        cert,
        proof,
        env.minter.voidRequiredValue(VEC_INBOUND_NONCE),
    );
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(
        res,
        [
            eventCertificate(x.height, env.generation, cert),
            eventCheckpointed(x.height, x.id()),
            eventVoided(VEC_INBOUND_MESSAGE_ID, VEC_INBOUND_NONCE, 1),
        ],
    );
    expect(isConsumedAt(env, VEC_INBOUND_NONCE)).toBeTrue();
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
    replayed += 1;
    expect(replayed).toEqual(PINNED_INBOUND_PAYLOAD_VECTORS);
}

get fun `test void against a stored checkpoint`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    testing.setNow(T0 + 101);
    expectRefused(
        env,
        sendVoidExpiredCheckpoint(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
        SccpErrors.UnknownCheckpoint,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val res = sendVoidExpiredCheckpoint(env, env.deployer, 0, d, env.minter.voidRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpVoidExpiredCheckpoint>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(res, [eventVoided(d.messageId, 0, 1)]);
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(env.minter.getSccpState().opCount).toEqual(1);
    reportGas("void checkpoint", stepGas(res), SCCP_GAS_MINTER_VOID);
    expect(stepGas(res) < 58000).toBeTrue();
}

get fun `test void deadline edge and nonce argument`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    // at now_ms = deadline_ms the message can still be minted: the void is early
    testing.setNow(T0 + 100);
    expectRefused(
        env,
        sendVoidExpired(env, env.deployer, 0, d, grams("5")),
        SccpErrors.DeadlineNotReached,
    );
    testing.setNow(T0 + 101);
    // the nonce argument must be the payload nonce
    expectRefused(
        env,
        sendVoidExpired(env, env.deployer, 1, d, grams("5")),
        SccpErrors.BadNonce,
    );
    expectRefused(
        env,
        sendVoidExpired(env, env.deployer, SCCP_MAX_U64, d, grams("5")),
        SccpErrors.BadNonce,
    );
    // the entry minimum is the quote minus the storage grace (the minter is above its floor)
    val poor = sendVoidExpired(
        env,
        env.deployer,
        0,
        d,
        env.minter.voidRequiredValue(0) - sccpMinterStorageGrace() - 1,
    );
    expectRefused(env, poor, SccpErrors.NotEnoughValue);
    expect(stepGas(poor) < 58000).toBeTrue();
    expect(
        env.minter.voidRequiredValue(0),
    ).toEqual(sccpVoidRequiredValue(1) + sccpMinterStorageGrace());
    expect(
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    expect(isConsumedAt(env, 0)).toBeTrue();
}

get fun `test a deadline ending in 999 ms is probed at the whole seconds on both sides`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliver(
        env,
        env.committee,
        env.generation,
        0,
        100,
        alice,
        (T0 + 200) * 1000 + 999,
        1,
        3,
    );
    testing.setNow(T0 + 200);
    expectRefused(
        env,
        sendVoidExpired(env, env.deployer, 0, d, grams("5")),
        SccpErrors.DeadlineNotReached,
    );
    testing.setNow(T0 + 201);
    expect(
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
}

get fun `test void checks run in the order of the specification`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    val minimum = env.minter.voidRequiredValue(0) - sccpMinterStorageGrace();
    val unknownRef = emptyX(env.networkId, env.generation, env.committee.root(), 77).ref();
    val leaves = leavesWith(inboundLeaf(env.networkId, d.payload, env.minter.address), 1, 3);
    val path = treePath(leaves, 1);
    val wrongLeaf = messageProofCell(2, path, d.payload, ownBlockRef(d.x));
    val badBlock = messageProofCell(
        1,
        path,
        d.payload,
        blockRefCell(d.x.height, d.x.sccpRoot, d.x.messageCount, 1, []),
    );
    // the payload before the bucket, the value and X; the nonce argument is not looked at
    val badPayload = inboundPayloadCell(
        9 * 512,
        TEST_REVISION + 1,
        DEADLINE_MS,
        100,
        alice.accountId(),
    );
    expectRefused(
        env,
        voidStored(
            env,
            5,
            unknownRef,
            messageProofCell(0, [], badPayload, ownBlockRef(d.x)),
            minimum - 1,
        ),
        SccpErrors.BadPayload,
    );
    val toSelf = inboundPayloadCell(
        0,
        TEST_REVISION,
        DEADLINE_MS,
        100,
        env.minter.address.accountId(),
    );
    expectRefused(
        env,
        voidStored(
            env,
            5,
            unknownRef,
            messageProofCell(0, [], toSelf, ownBlockRef(d.x)),
            minimum - 1,
        ),
        SccpErrors.BadRecipient,
    );
    // the bucket of the payload nonce before the value
    val far = inboundPayloadCell(9 * 512, TEST_REVISION, DEADLINE_MS, 100, alice.accountId());
    expectRefused(
        env,
        voidStored(env, 0, unknownRef, messageProofCell(0, [], far, ownBlockRef(d.x)), minimum - 1),
        SccpErrors.BucketNotDeployed,
    );
    // the value before X
    expectRefused(
        env,
        voidStored(env, 5, unknownRef, d.proof, minimum - 1),
        SccpErrors.NotEnoughValue,
    );
    expectRefused(
        env,
        voidStored(env, 5, unknownRef, d.proof, minimum),
        SccpErrors.UnknownCheckpoint,
    );
    // early, with a wrong block reference: the reference answers
    expectRefused(
        env,
        voidInline(env, 5, d.cert, badBlock, minimum),
        SccpErrors.BadProof,
    );
    // early, with a wrong leaf path and a wrong nonce argument: the deadline answers
    expectRefused(
        env,
        voidInline(env, 5, d.cert, wrongLeaf, minimum),
        SccpErrors.DeadlineNotReached,
    );
    testing.setNow(T0 + 101);
    // the leaf path before the nonce argument
    expectRefused(
        env,
        voidInline(env, 5, d.cert, wrongLeaf, minimum),
        SccpErrors.BadProof,
    );
    expectRefused(
        env,
        voidInline(env, 5, d.cert, d.proof, minimum),
        SccpErrors.BadNonce,
    );
    // none of the refused inline calls stored its checkpoint
    replayExpectCheckpoints(
        env,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    expect(
        voidInline(env, 0, d.cert, d.proof, minimum),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    // the nonce argument is judged before the consumed set: a wrong one for
    // the consumed payload answers BadNonce, not the bucket
    val consumed = voidInline(env, 5, d.cert, d.proof, minimum);
    expectOutcome(consumed, SccpErrors.BadNonce);
    expectEvents(consumed, []);
    expect(env.minter.getSccpState().opCount).toEqual(1);
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
    expect(state.pendingSupply).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(100);
}

get fun `test void expired proves an old block through the history root`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(6, TEST_REVISION, DEADLINE_MS, 5, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    // the block of the transfer holds one leaf and is entry 1 of a history of 3
    val oldHeight = TEST_START_HEIGHT + 70;
    val history = historyLeaves(3, 1, oldHeight, leaf, 1);
    var x = blockX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 80,
        [fillerLeaf(77)],
    );
    x.historySize = 3;
    x.historyRoot = treeRoot(history);
    val proof = messageProofCell(
        0,
        [],
        payload,
        blockRefCell(oldHeight, leaf, 1, 1, treePath(history, 1)),
    );
    val cert = certifyFor(env, env.committee, x);
    testing.setNow(T0 + 101);
    val res = voidInline(env, 6, cert, proof, env.minter.voidRequiredValue(6));
    expect(res).toHaveSuccessfulTx<SccpVoidExpired>({ to: env.minter.address });
    expect(res).toEmitExternalMessage<SccpVoidedEvent>();
    expect(isConsumedAt(env, 6)).toBeTrue();
    // the leaf of the old block is not a leaf of the certified block
    val direct = messageProofCell(0, [], payload, ownBlockRef(x));
    expectOutcome(
        voidInline(env, 6, cert, direct, grams("5")),
        SccpErrors.BadProof,
    );
    // another history index
    val wrong = messageProofCell(
        0,
        [],
        payload,
        blockRefCell(oldHeight, leaf, 1, 2, treePath(history, 1)),
    );
    expectOutcome(
        voidInline(env, 6, cert, wrong, grams("5")),
        SccpErrors.BadProof,
    );
}

get fun `test void expired needs a Live generation`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expect(sendVoidExpired(env, env.deployer, 0, d, grams("5"))).toHaveFailedTx<SccpVoidExpired>({
        to: env.minter.address,
        exitCode: SccpErrors.CommitteeNotAccepted as int,
    });
    expectOutcome(
        sendVoidExpiredCheckpoint(env, env.deployer, 0, d, grams("5")),
        SccpErrors.CommitteeNotAccepted,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
    // the frozen void takes over
    val res = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(isConsumedAt(env, 0)).toBeTrue();
}

get fun `test voids are not blocked by the pause`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    val second = expiredDelivery(env, 1, alice);
    // a Parliament pause and a fast pause together
    expectOutcome(sendApplyControl(env, deliverFastPause(env, 1, true, NOW_MS + DAY_MS)), 0);
    expect(env.minter.getSccpState().effectivePaused).toBeTrue();
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.MintingIsPaused,
    );
    testing.setNow(T0 + 101);
    expect(
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectOutcome(sendCheckpoint(env, env.deployer, second.cert, null, grams("1")), 0);
    expect(
        sendVoidExpiredCheckpoint(env, env.deployer, 1, second, env.minter.voidRequiredValue(1)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    val state = env.minter.getSccpState();
    // the control and two voids
    expect(state.opCount).toEqual(3);
    expect(state.effectivePaused).toBeTrue();
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(isConsumedAt(env, 1)).toBeTrue();
}

get fun `test void after a rotation proves under the installing handoff`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val next = testCommittee(4, 4);
    val d = deliverAt(
        env,
        env.committee,
        env.generation,
        TEST_START_HEIGHT + 20,
        0,
        100,
        alice,
        DEADLINE_MS,
        1,
        3,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    var handoff = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 30,
        NOW_MS - 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    handoff.historySize = 1;
    handoff.historyRoot = sccpHistoryLeaf(d.x.height, d.x.sccpRoot, d.x.messageCount);
    expectOutcome(
        sendCheckpoint(
            env,
            env.deployer,
            certifyFor(env, env.committee, handoff),
            next.keysCell(),
            grams("1"),
        ),
        0,
    );
    testing.setNow(T0 + 101);
    // the non-handoff checkpoint of the retired generation is not usable
    expectRefused(
        env,
        sendVoidExpiredCheckpoint(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
        SccpErrors.CommitteeNotAccepted,
    );
    expectRefused(
        env,
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
        SccpErrors.CommitteeNotAccepted,
    );
    // the installing handoff proves the leaf through its history root
    val leaves = leavesWith(inboundLeaf(env.networkId, d.payload, env.minter.address), 1, 3);
    val proof = messageProofCell(
        1,
        treePath(leaves, 1),
        d.payload,
        blockRefCell(d.x.height, d.x.sccpRoot, d.x.messageCount, 0, []),
    );
    val res = voidStored(env, 0, handoff.ref(), proof, env.minter.voidRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(res, [eventVoided(d.messageId, 0, 1)]);
    expect(isConsumedAt(env, 0)).toBeTrue();
}

get fun `test void expired requires the ton mainnet global id`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    testing.setNow(T0 + 101);
    setGlobalId(-3);
    expectOutcome(sendVoidExpired(env, env.deployer, 0, d, grams("5")), SccpErrors.WrongChain);
    expectOutcome(
        sendVoidExpiredCheckpoint(env, env.deployer, 0, d, grams("5")),
        SccpErrors.WrongChain,
    );
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectOutcome(sendVoidFrozen(env, 0, 1, grams("5")), SccpErrors.WrongChain);
    // chain identity comes before the range
    expectOutcome(sendVoidFrozen(env, 0, 0, grams("5")), SccpErrors.WrongChain);
    expect(env.minter.getSccpState().opCount).toEqual(0);
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expect(
        sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
}

get fun `test bounced sccp_consume of a void leaves the supply untouched`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 7, 40, alice);
    val d = expiredDelivery(env, 0, alice);
    testing.setNow(T0 + 101);
    val step = testing.processSingleTraceStep(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: env.minter.voidRequiredValue(0),
            dest: env.minter.address,
            body: SccpVoidExpired {
                queryId: 1,
                response: env.deployer,
                nonce: 0,
                cert: d.cert as Cell<TairaCert>,
                message: d.proof as Cell<MessageProof>,
            },
        }),
    );
    // a void reserves no pending supply and carries amount 0
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    val consume = step.outMessages.at<SccpConsume>(step.outMessages.size() - 1).loadBody();
    expect(consume.nonce).toEqual(0);
    expect(consume.amount).toEqual(0);
    val tail = consume.tail.load();
    expect(tail.kind).toEqual(SCCP_CONSUME_KIND_VOID);
    expect(tail.recipient == null).toBeTrue();
    expect(tail.response).toEqual(env.deployer);
    expect(tail.messageId).toEqual(d.messageId);
    testing.processSingleTraceStep(
        env.minter.getBucketAddress(0),
        bouncedMessage(consume, env.minter.address, grams("0.1")),
    );
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(40);
    expect(state.opCount).toEqual(1);
    expect(isConsumedAt(env, 0)).toBeFalse();
}

get fun `test a void in flight when the latch fires still completes`() {
    // §5.3.4 item 6 cancels a mint in flight only: the bucket reply of a void
    // is counted and published whatever happened to the minter meanwhile
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    testing.setNow(T0 + 101);
    val step = testing.processSingleTraceStep(
        env.deployer,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: env.minter.voidRequiredValue(0),
            dest: env.minter.address,
            body: SccpVoidExpired {
                queryId: 1,
                response: env.deployer,
                nonce: 0,
                cert: d.cert as Cell<TairaCert>,
                message: d.proof as Cell<MessageProof>,
            },
        }),
    );
    // after the two events: the activation of bucket 0, then the consume
    val outs = step.outMessages.size();
    expect(outs).toEqual(4);
    latch(env);
    net.send(env.minter.address, forwardOut(step, outs - 2));
    val res = net.send(env.minter.address, forwardOut(step, outs - 1));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();
    expectEvents(res, [eventVoided(d.messageId, 0, 1)]);
    expect(isConsumedAt(env, 0)).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.equivocated).toBeTrue();
    expect(state.opCount).toEqual(1);
    expect(state.pendingSupply).toEqual(0);
    // a new expired void is refused at its `Live` check
    val second = expiredDelivery(env, 1, alice);
    expectOutcome(
        sendVoidExpired(env, env.deployer, 1, second, env.minter.voidRequiredValue(1)),
        SccpErrors.Equivocated,
    );
}

get fun `test opCount saturates at the top of u64 under a void`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = expiredDelivery(env, 0, alice);
    val second = expiredDelivery(env, 1, alice);
    var st = minterStorage(env);
    st.opCount = SCCP_MAX_U64 - 1;
    setMinterStorage(env, st);
    testing.setNow(T0 + 101);
    expect(
        sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    // at the bound the void still succeeds and the counter stays
    val res = sendVoidExpired(env, env.deployer, 1, second, env.minter.voidRequiredValue(1));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toEmitExternalMessage<SccpVoidedEvent>();
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    // and so does a frozen void
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    val frozen = sendVoidFrozen(env, 2, 3, env.minter.voidFrozenRequiredValue(2));
    expect(frozen).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(frozen).toEmitExternalMessage<SccpVoidedEvent>();
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    expect(isConsumedAt(env, 4)).toBeTrue();
}

// ---------------------------------------------------------------------------
// `sccp_void_frozen`.

get fun `test void frozen requires an expired generation`() {
    val env = setupEnv();
    expect(sendVoidFrozen(env, 0, 1, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
        to: env.minter.address,
        exitCode: SccpErrors.NotFrozen as int,
    });
    // a rotation moves the deadline: the minter stays Live past the pinned one
    val next = testCommittee(4, 4);
    testing.setNow(T0 + 86400);
    rotateTo(env, next, TEST_START_HEIGHT + 200);
    val until = (T0 + 86400) * 1000 + TEST_VALIDITY_MS;
    expect(env.minter.getSccpState().untilMs).toEqual(until);
    testing.setNow(PIN_UNTIL_MS / 1000 + 10);
    expectOutcome(sendVoidFrozen(env, 0, 1, grams("5")), SccpErrors.NotFrozen);
    // at the successor's deadline still Live, one second later Frozen
    testing.setNow(until / 1000);
    expectOutcome(sendVoidFrozen(env, 0, 1, grams("5")), SccpErrors.NotFrozen);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(0);
    testing.setNow(until / 1000 + 1);
    val res = sendVoidFrozen(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpVoidFrozen>({ to: env.minter.address });
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsumeRange>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();
    // one external-out message for the range, with message id 0
    expectEvents(res, [eventVoided(0, 0, 512)]);
    val event = res
        .findExternalOutMessage<SccpVoidedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.messageId).toEqual(0);
    expect(event.firstNonce).toEqual(0);
    expect(event.count).toEqual(512);
    val (hi, lo) = bucketOf(env, 0).getBits();
    expect(hi).toEqual(ALL_BITS);
    expect(lo).toEqual(ALL_BITS);
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.equivocated).toBeFalse();
    reportGas("void_frozen", stepGas(res), SCCP_GAS_MINTER_VOID_FROZEN);
    reportGas(
        "minter range reply",
        res.getUsedGas<SccpRangeConsumed>({ to: env.minter.address }),
        SCCP_GAS_MINTER_RANGE_REPLY,
    );
}

get fun `test void frozen after a latch`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 10, 1, alice);
    expectOutcome(sendVoidFrozen(env, 0, 1, grams("5")), SccpErrors.NotFrozen);
    latch(env);
    // the latch freezes the minter although the deadline is far away
    expect(env.minter.getSccpState().untilMs).toEqual(0);
    val res = sendVoidFrozen(env, 0, 10, env.minter.voidFrozenRequiredValue(0));
    expect(res).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expectEvents(res, [eventVoided(0, 0, 10)]);
    expect(isConsumedAt(env, 9)).toBeTrue();
    // a minted nonce stays minted: its range is rejected as a whole
    val rejected = sendVoidFrozen(env, 10, 2, env.minter.voidFrozenRequiredValue(10));
    expect(rejected).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    expectEvents(rejected, []);
    expect(isConsumedAt(env, 11)).toBeFalse();
    val state = env.minter.getSccpState();
    // the mint and one frozen void
    expect(state.opCount).toEqual(2);
    expect(state.totalSupply).toEqual(1);
    // the expired void needs Live and answers for the latch
    val d = expiredDelivery(env, 20, alice);
    testing.setNow(T0 + 101);
    expectOutcome(
        sendVoidExpired(env, env.deployer, 20, d, env.minter.voidRequiredValue(20)),
        SccpErrors.Equivocated,
    );
}

get fun `test void frozen range rules`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 10, 1, alice);
    // `max_void_frozen_range_ton` of the fixture: one bucket
    expect(SCCP_MAX_VOID_FROZEN_RANGE).toEqual(VEC_MAX_VOID_FROZEN_RANGE);
    expect(SCCP_MAX_VOID_FROZEN_RANGE).toEqual(SCCP_BUCKET_BITS);
    // The range is judged first, on a Live minter too: no nonce, more than a
    // bucket, and ranges that cross a bucket boundary.
    val bad: array<[int, int]> = [
        [0, 0],
        [5, 0],
        [512, 0],
        [0, 513],
        [500, 20],
        [511, 2],
        [1, 512],
        [1024 - 1, 2],
        [SCCP_MAX_U64, 2],
        [SCCP_MAX_U64 - 511, 513],
        [0, 65535],
    ];
    var i = 0;
    while (i < bad.size()) {
        val [first, count] = bad.get(i);
        expect(sendVoidFrozen(env, first, count, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
            to: env.minter.address,
            exitCode: SccpErrors.BadRange as int,
        });
        i += 1;
    }
    expect(i).toEqual(11);
    // a valid range on a Live minter is NotFrozen, whatever its bucket
    val live: array<[int, int]> = [[0, 1], [0, 512], [511, 1], [512, 512], [9 * 512, 1]];
    i = 0;
    while (i < live.size()) {
        val [first, count] = live.get(i);
        expectOutcome(sendVoidFrozen(env, first, count, grams("5")), SccpErrors.NotFrozen);
        i += 1;
    }
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    // frozen: the range failures answer as before
    i = 0;
    while (i < bad.size()) {
        val [first, count] = bad.get(i);
        expectOutcome(sendVoidFrozen(env, first, count, grams("5")), SccpErrors.BadRange);
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
    expect(env.minter.getSccpState().opCount).toEqual(1);
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
    expect(hi).toEqual(ALL_BITS);
    expect(lo).toEqual(ALL_BITS);
    // a second void of voided nonces is rejected
    val twice = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(twice).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    // buckets beyond four ahead need sccp_deploy_buckets first
    expect(sendVoidFrozen(env, 5 * 512, 1, grams("5"))).toHaveFailedTx<SccpVoidFrozen>({
        to: env.minter.address,
        exitCode: SccpErrors.BucketNotDeployed as int,
    });
    // up to four ahead deploys the missing buckets
    val ahead = sendVoidFrozen(env, 4 * 512, 512, env.minter.voidFrozenRequiredValue(4 * 512));
    expect(ahead).toHaveSuccessfulDeploy<SccpActivateBucket>({
        to: env.minter.getBucketAddress(1),
    });
    expect(ahead).toHaveSuccessfulDeploy<SccpActivateBucket>({
        to: env.minter.getBucketAddress(4),
    });
    expect(ahead).toHaveSuccessfulTx<SccpConsumeRange>({ to: env.minter.getBucketAddress(4) });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(5);
    // the mint and three frozen voids
    expect(env.minter.getSccpState().opCount).toEqual(4);
}

get fun `test void frozen requires its value after the range and the Frozen check`() {
    val env = setupEnv();
    val quote = env.minter.voidFrozenRequiredValue(0);
    expect(quote).toEqual(sccpVoidFrozenRequiredValue(1) + sccpMinterStorageGrace());
    val minimum = quote - sccpMinterStorageGrace();
    // Live: a bad range and a valid one answer before the value
    expectOutcome(sendVoidFrozen(env, 0, 0, minimum - 1), SccpErrors.BadRange);
    expectOutcome(sendVoidFrozen(env, 0, 1, minimum - 1), SccpErrors.NotFrozen);
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    // Frozen: the bucket rule, then the value
    expectOutcome(sendVoidFrozen(env, 9 * 512, 1, minimum - 1), SccpErrors.BucketNotDeployed);
    expectOutcome(sendVoidFrozen(env, 0, 1, minimum - 1), SccpErrors.NotEnoughValue);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(0);
    val res = sendVoidFrozen(env, 0, 1, minimum);
    expect(res).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(res).toHaveAllSuccessfulTxs();
    // an existing bucket needs no activation value
    expect(
        env.minter.voidFrozenRequiredValue(1),
    ).toEqual(sccpVoidFrozenRequiredValue(0) + sccpMinterStorageGrace());
}

get fun `test void frozen accepts the last nonce of u64`() {
    val env = setupEnv();
    // storage injection: every bucket below the last one counts as deployed
    val lastBucket = SCCP_MAX_U64 >> SCCP_BUCKET_SHIFT;
    var st = minterStorage(env);
    st.deployedBuckets = lastBucket;
    setMinterStorage(env, st);
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    // first + count = 2^64: the last nonce is 2^64 − 1
    val first = SCCP_MAX_U64 - 511;
    expect(first % 512).toEqual(0);
    // one nonce more would leave the bucket and the u64 range
    expectOutcome(sendVoidFrozen(env, first + 1, 512, grams("5")), SccpErrors.BadRange);
    expectOutcome(sendVoidFrozen(env, SCCP_MAX_U64, 2, grams("5")), SccpErrors.BadRange);
    // the last nonce alone
    val last = sendVoidFrozen(
        env,
        SCCP_MAX_U64,
        1,
        env.minter.voidFrozenRequiredValue(SCCP_MAX_U64),
    );
    expect(last).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expectEvents(last, [eventVoided(0, SCCP_MAX_U64, 1)]);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(lastBucket + 1);
    expect(isConsumedAt(env, SCCP_MAX_U64)).toBeTrue();
    expect(isConsumedAt(env, SCCP_MAX_U64 - 1)).toBeFalse();
    // the whole last bucket is one valid range; here its last nonce is taken
    val whole = sendVoidFrozen(env, first, 512, env.minter.voidFrozenRequiredValue(first));
    expect(whole).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    // the 511 nonces before it
    val rest = sendVoidFrozen(env, first, 511, env.minter.voidFrozenRequiredValue(first));
    expect(rest).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expectEvents(rest, [eventVoided(0, first, 511)]);
    val (hi, lo) = bucketOf(env, lastBucket).getBits();
    expect(hi).toEqual(ALL_BITS);
    expect(lo).toEqual(ALL_BITS);
    expect(env.minter.getSccpState().opCount).toEqual(2);
}

get fun `test bounced sccp_range_consumed makes the bucket clear the range`() {
    val env = setupEnv();
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
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
    expect(consumed.first).toEqual(3);
    expect(consumed.count).toEqual(4);
    expect(isConsumedAt(env, 3)).toBeTrue();
    expect(isConsumedAt(env, 6)).toBeTrue();
    testing.processSingleTraceStep(
        env.minter.address,
        bouncedMessage(consumed, env.minter.getBucketAddress(0), grams("0.05")),
    );
    expect(isConsumedAt(env, 3)).toBeFalse();
    expect(isConsumedAt(env, 6)).toBeFalse();
    // the reply never reached the minter: nothing was counted or emitted
    expect(env.minter.getSccpState().opCount).toEqual(0);
    // the range can be voided again
    expect(
        sendVoidFrozen(env, 3, 4, env.minter.voidFrozenRequiredValue(3)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test range replies are accepted only from the canonical bucket`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expect(
        sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    val value: SendParams = { value: grams("1"), bounce: true };
    // a stranger, and the bucket of another index
    expect(
        env.minter.sendSccpRangeConsumed(stranger, 0, 5, 1, value),
    ).toHaveFailedTx<SccpRangeConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    expect(
        env.minter.sendSccpRangeConsumed(env.minter.getBucketAddress(0), 0, 512, 1, value),
    ).toHaveFailedTx<SccpRangeConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    expect(
        env.minter.sendSccpRangeRejected(stranger, 0, 5, 1, value),
    ).toHaveFailedTx<SccpRangeRejected>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    // no forged reply was counted or emitted
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test bucket range masks cover both halves`() {
    val env = setupEnv();
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
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
    // single nonces at the ends of the bucket
    expect(
        sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(
        sendVoidFrozen(env, 511, 1, env.minter.voidFrozenRequiredValue(511)),
    ).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    val (hi2, lo2) = bucketOf(env, 0).getBits();
    expect(hi2).toEqual(0x3F | (1 << 255));
    expect(lo2).toEqual((0x3F << 250) | 1);
}
