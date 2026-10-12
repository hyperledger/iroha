// Taira→TON finalization (specs/sccp.md §5.1.5, §5.3.4 "Finalize" steps 1–7):
// the inline form with its certificate and the checkpoint form, the check
// order of the minter step, block references and leaf paths, payload and
// recipient rules, deadline and cap edges, the pause, bucket dispatch and
// activation (the minter never recreates a bucket), duplicate and parallel
// finalizes, the bounce paths of the consume round trip, and a mint in flight
// when the minter latches or expires (§5.3.4 item 6).

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
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Destination clock at which every test of this suite starts, in ms.
const NOW_MS = 1800000000000
/// `cur.untilMs` of the default pin: 14 days after `NOW_MS`.
const PIN_UNTIL_MS = 1801209600000
/// Taira→TON rows of `directions` in `payload_v1.json` that this suite mints.
const PINNED_INBOUND_PAYLOAD_VECTORS = 1

// ---------------------------------------------------------------------------
// Builders of this suite.

/// Body of `sccp_finalized`.
fun eventFinalized(messageId: int, nonce: int): cell {
    return SccpFinalizedEvent { messageId, nonce }.toCell();
}

/// Body of `sccp_voided`.
fun eventVoided(messageId: int, firstNonce: int, count: int): cell {
    return SccpVoidedEvent { messageId, firstNonce, count }.toCell();
}

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

/// Sends `sccp_finalize` from the deployer with the `^TairaCert` `cert` and
/// the `^MessageProof` `proof`.
fun finalizeInline(env: Env, cert: cell, proof: cell, value: coins): SendResultList {
    return sendFinalizeCells(
        env,
        env.deployer,
        cert,
        null,
        proof,
        value,
    );
}

/// Sends `sccp_finalize_checkpoint` from the deployer with the
/// `^CheckpointRef` `ref` and the `^MessageProof` `proof`.
fun finalizeStored(env: Env, ref: cell, proof: cell, value: coins): SendResultList {
    return sendFinalizeCells(
        env,
        env.deployer,
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

/// Registers `c` as a library and returns the library reference cell that
/// `CTOS` alone would resolve to it.
fun asLibrary(c: cell): cell {
    testing.registerLibrary(c);
    return c.toLibraryReference();
}

/// A well-formed compressed G2 point that signs nothing here and is not the
/// identity.
fun foreignSignature(): slice {
    return vecHashToG2(0).q;
}

/// Expects a refused finalize in the check-order test: its exit code, no
/// event and no pending supply.
fun expectOrder(env: Env, res: SendResultList, exitCode: int) {
    if (outcomeOf(res) != exitCode) {
        println("expected {} observed {}", exitCode, outcomeOf(res));
    }
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
}

/// Expects a refused finalize: its exit code, no event, no pending supply
/// and no bucket deployed.
fun expectRefused(env: Env, res: SendResultList, exitCode: int) {
    if (outcomeOf(res) != exitCode) {
        println("expected {} observed {}", exitCode, outcomeOf(res));
    }
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(state.deployedBuckets).toEqual(0);
}

/// A transfer of an older block of generation `env.generation` and the
/// later block whose history proves it.
struct OldBlock {
    payload: cell
    messageId: int
    /// Height, root and leaves of the block that commits the transfer.
    height: int
    leaves: array<int>
    leafIndex: int
    /// The history: `historyIndex` is the entry of the block.
    history: array<int>
    historyIndex: int
    /// The later certified header whose history root covers the block.
    x: TestX
}

/// Builds the transfer `nonce` as leaf 2 of 5 of the block at `height`, which
/// is entry 3 of a history of 7 blocks, under the later empty block at
/// `laterHeight`.
fun oldBlock(
    env: Env,
    nonce: int,
    amount: int,
    recipient: address,
    height: int,
    laterHeight: int,
): OldBlock {
    val payload = inboundPayloadCell(
        nonce,
        TEST_REVISION,
        NOW_MS + DAY_MS,
        amount,
        recipient.accountId(),
    );
    val leaves = leavesWith(inboundLeaf(env.networkId, payload, env.minter.address), 2, 5);
    val history = historyLeaves(7, 3, height, treeRoot(leaves), 5);
    var x = emptyX(env.networkId, env.generation, env.committee.root(), laterHeight);
    x.historySize = 7;
    x.historyRoot = treeRoot(history);
    return {
        payload,
        messageId: inboundMessageId(env.networkId, payload, env.minter.address),
        height,
        leaves,
        leafIndex: 2,
        history,
        historyIndex: 3,
        x,
    };
}

/// The `^BlockRef` of an old block through its history path.
fun OldBlock.blockRef(self): cell {
    return blockRefCell(
        self.height,
        treeRoot(self.leaves),
        self.leaves.size(),
        self.historyIndex,
        treePath(self.history, self.historyIndex),
    );
}

/// The `^MessageProof` of the transfer of an old block.
fun OldBlock.proof(self): cell {
    return messageProofCell(
        self.leafIndex,
        treePath(self.leaves, self.leafIndex),
        self.payload,
        self.blockRef(),
    );
}

// ---------------------------------------------------------------------------
// The two forms.

get fun `test inline finalize records the checkpoint, mints, emits and consumes the nonce`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val amount = 123456789;
    val d = deliverDefault(env, 0, amount, alice);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveSuccessfulDeploy<SccpActivateBucket>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsume>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({
        from: env.minter.getBucketAddress(0),
        to: env.minter.address,
    });
    expect(res).toHaveSuccessfulDeploy<InternalTransferStep>({ to: walletOf(env, alice).address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();

    // The minter step publishes the certificate and the checkpoint; the
    // bucket's reply emits `sccp_finalized`.
    expectEvents(
        res,
        [
            eventCertificate(d.x.height, env.generation, d.cert),
            eventCheckpointed(d.x.height, d.x.id()),
            eventFinalized(d.messageId, 0),
        ],
    );
    val event = res.findExternalOutMessage<SccpFinalizedEvent>({ from: env.minter.address });
    expect(event).toBeNotNull();
    val body = event!.loadBody();
    expect(body.messageId).toEqual(d.messageId);
    expect(body.nonce).toEqual(0);
    // sccp_finalized#5343464e message_id:uint256 nonce:uint64 (§5.3.3)
    val raw = eventFinalized(d.messageId, 0).beginParse();
    expect(raw.preloadUint(32)).toEqual(0x5343464e);
    expect(raw.remainingBitsCount()).toEqual(32 + 256 + 64);
    expect(raw.remainingRefsCount()).toEqual(0);

    expect(jettonBalanceOf(env, alice)).toEqual(amount);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(amount);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    expect(state.deployedBuckets).toEqual(1);
    // the inline certificate recorded its checkpoint and raised `high`
    expect(state.high).toEqual(d.x.height);
    expect(state.generation).toEqual(env.generation);
    expect(state.untilMs).toEqual(PIN_UNTIL_MS);
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
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(isConsumedAt(env, 1)).toBeFalse();
    expect(bucketOf(env, 0).isActivated()).toBeTrue();
    val wallet = walletOf(env, alice).getWalletData();
    expect(wallet.ownerAddress).toEqual(alice);
    expect(wallet.minterAddress).toEqual(env.minter.address);
    reportGas("finalize inline n=4", stepGas(res), SCCP_GAS_MINTER_FINALIZE);
    reportGas(
        "minter sccp_consumed mint",
        res.getUsedGas<SccpConsumed>({ to: env.minter.address }),
        SCCP_GAS_MINTER_CONSUMED,
    );
}

get fun `test the Taira to TON payload vector of the fixture mints under its message id`() {
    // `directions` of `payload_v1.json` holds one payload of this lane
    var replayed = 0;
    val env = setupEnvWith(4, SCCP_TON_AMOUNT_LIMIT);
    val payload = snakeFromPieces(vecInboundPayloadPieces());
    // the contract reads the fixture's fields from the bytes
    val parsed = sccpParseInboundPayload(
        payload,
        VEC_INBOUND_REVISION,
        env.minter.address.accountId(),
    );
    expect(parsed.nonce).toEqual(VEC_INBOUND_NONCE);
    expect(parsed.deadlineMs).toEqual(VEC_INBOUND_DEADLINE_MS);
    expect(parsed.amount).toEqual(VEC_INBOUND_AMOUNT);
    expect(parsed.recipientHash).toEqual(VEC_INBOUND_RECIPIENT);
    expect(parsed.payloadHash).toEqual(VEC_INBOUND_PAYLOAD_HASH);
    expect(
        sccpInboundMessageId(env.networkId, parsed.payloadHash),
    ).toEqual(VEC_INBOUND_MESSAGE_ID);
    expect(VEC_INBOUND_AMOUNT).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    // Taira's leaf for the minter account id the fixtures commit to
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
    val res = finalizeInline(env, cert, proof, finalizeValue(env, VEC_INBOUND_NONCE));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(
        res,
        [
            eventCertificate(x.height, env.generation, cert),
            eventCheckpointed(x.height, x.id()),
            eventFinalized(VEC_INBOUND_MESSAGE_ID, VEC_INBOUND_NONCE),
        ],
    );
    val recipient = address.fromWorkchainAndHash(BASECHAIN, VEC_INBOUND_RECIPIENT);
    expect(jettonBalanceOf(env, recipient)).toEqual(VEC_INBOUND_AMOUNT);
    expect(isConsumedAt(env, VEC_INBOUND_NONCE)).toBeTrue();
    expect(env.minter.getSccpState().totalSupply).toEqual(VEC_INBOUND_AMOUNT);
    replayed += 1;
    expect(replayed).toEqual(PINNED_INBOUND_PAYLOAD_VECTORS);
}

get fun `test finalize with a committee of 31 and 21 signers`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    expect(env.committee.q()).toEqual(21);
    val alice = testing.treasury("alice").address;
    val res = finalizeOk(env, 0, 1000, alice);
    reportGas("finalize inline n=31", stepGas(res), SCCP_GAS_MINTER_FINALIZE);
    // the highest 21 members certify the next message
    val d = deliverDefault(env, 1, 5, alice);
    val cert = certifyBy(
        env.committee,
        env.committee.highestSigners(),
        env.instance,
        defaultQc(d.x.height),
        d.x,
    );
    val second = finalizeInline(env, cert, d.proof, finalizeValue(env, 1));
    expect(second).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(1005);
}

get fun `test finalize against a stored checkpoint changes nothing in the committee state`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 700, alice);
    // not stored yet
    expectRefused(
        env,
        sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.UnknownCheckpoint,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val before = env.minter.getSccpState();
    val res = sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpFinalizeCheckpoint>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    // no certificate is published and nothing is recorded
    expectEvents(res, [eventFinalized(d.messageId, 0)]);
    expect(jettonBalanceOf(env, alice)).toEqual(700);
    val state = env.minter.getSccpState();
    expect(state.high).toEqual(before.high);
    expect(state.generation).toEqual(before.generation);
    expect(state.opCount).toEqual(1);
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
    reportGas("finalize checkpoint", stepGas(res), SCCP_GAS_MINTER_FINALIZE);
    // no signature work on this path
    expect(stepGas(res) < 58000).toBeTrue();
}

get fun `test using a checkpoint records nothing and raises nothing`() {
    // a checkpoint that was seeded (white box) did not raise `high`, and its
    // use does not either
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 3, 9, alice);
    seedCheckpoint(env, d.x);
    val before = env.minter.getSccpCommittee();
    expect(before.high).toEqual(TEST_START_HEIGHT - 1);
    val res = sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 3));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(res, [eventFinalized(d.messageId, 3)]);
    val after = env.minter.getSccpCommittee();
    expect(after.high).toEqual(TEST_START_HEIGHT - 1);
    expect(after.untilMs).toEqual(before.untilMs);
    expect(after.generation).toEqual(before.generation);
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
    expect(jettonBalanceOf(env, alice)).toEqual(9);
}

get fun `test an evicted checkpoint bounces with UnknownCheckpoint and the inline form succeeds`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 40, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    // three higher checkpoints evict it
    var i = 1;
    repeat (3) {
        val x = emptyX(env.networkId, env.generation, env.committee.root(), d.x.height + 10 * i);
        expectOutcome(checkpointBy(env, env.committee, x, null), 0);
        i += 1;
    }
    expect(env.minter.getSccpCheckpoints().height0).toEqual(d.x.height + 10);
    val evicted = sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0));
    expectRefused(env, evicted, SccpErrors.UnknownCheckpoint);
    // the message bounces with its value
    expect(evicted).toHaveBouncedTx<SccpFinalizeCheckpoint>({ to: env.deployer });

    // The inline form is the fallback for the current generation: the
    // certificate is verified again, and its height no longer fits a slot.
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(
        res,
        [eventCertificate(d.x.height, env.generation, d.cert), eventFinalized(d.messageId, 0)],
    );
    expect(jettonBalanceOf(env, alice)).toEqual(40);
    expect(env.minter.getSccpState().high).toEqual(d.x.height + 30);
    expect(env.minter.getSccpCheckpoints().height0).toEqual(d.x.height + 10);
}

get fun `test inline finalize under a handoff installs no successor`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val next = testCommittee(4, 4);
    val payload = inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 250, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    var x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 60,
        NOW_MS - 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    x.messageCount = 1;
    x.sccpRoot = leaf;
    x.historySize = 1;
    x.historyRoot = sccpHistoryLeaf(x.height, leaf, 1);
    val cert = certifyFor(env, env.committee, x);
    val proof = messageProofCell(0, [], payload, ownBlockRef(x));
    val res = finalizeInline(env, cert, proof, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(250);
    // recorded and raised, and the committee is unchanged
    var state = env.minter.getSccpState();
    expect(state.generation).toEqual(env.generation);
    expect(state.root).toEqual(env.committee.root());
    expect(state.high).toEqual(x.height);
    expect(state.untilMs).toEqual(PIN_UNTIL_MS);
    replayExpectKeys(env, env.committee.keys);
    replayExpectCheckpoints(
        env,
        1,
        x.height,
        x.id(),
        0,
        0,
        0,
        0,
    );
    // `sccp_checkpoint` then installs the successor: a handoff at height = high is no V3
    val installed = sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1"));
    expectOutcome(installed, 0);
    expectEvents(
        installed,
        [
            eventRotated(
                env.generation + 1,
                next.root(),
                NOW_MS - 1000 + TEST_VALIDITY_MS,
                x.height + 1,
            ),
        ],
    );
    state = env.minter.getSccpState();
    expect(state.generation).toEqual(env.generation + 1);
    expect(state.totalSupply).toEqual(250);
}

get fun `test finalize proves an old block through the history root`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val old = oldBlock(
        env,
        3,
        777,
        alice,
        TEST_START_HEIGHT + 55,
        TEST_START_HEIGHT + 90,
    );
    val cert = certifyFor(env, env.committee, old.x);
    // a later block without messages certifies the history
    expect(old.x.messageCount).toEqual(0);
    val res = finalizeInline(env, cert, old.proof(), finalizeValue(env, 3));
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(777);
    expect(isConsumedAt(env, 3)).toBeTrue();
    // the checkpoint recorded is that of the certified block, not of the old one
    replayExpectCheckpoints(
        env,
        1,
        old.x.height,
        old.x.id(),
        0,
        0,
        0,
        0,
    );

    // the stored checkpoint proves another message of the same old block
    val second = oldBlock(
        env,
        4,
        5,
        alice,
        TEST_START_HEIGHT + 55,
        TEST_START_HEIGHT + 91,
    );
    val secondCert = certifyFor(env, env.committee, second.x);
    expectOutcome(sendCheckpoint(env, env.deployer, secondCert, null, grams("1")), 0);
    val viaCheckpoint = finalizeStored(env, second.x.ref(), second.proof(), finalizeValue(env, 4));
    expect(viaCheckpoint).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(782);
}

get fun `test a block reference through history must reproduce the certified history root`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val old = oldBlock(
        env,
        3,
        777,
        alice,
        TEST_START_HEIGHT + 55,
        TEST_START_HEIGHT + 90,
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, certifyFor(env, env.committee, old.x), null, grams("1")),
        0,
    );
    val root = treeRoot(old.leaves);
    val path = treePath(old.history, old.historyIndex);
    val leafPath = treePath(old.leaves, old.leafIndex);
    var longPath: array<int> = [];
    repeat (33) {
        longPath.push(fillerLeaf(900 + longPath.size()));
    }
    var withExtra = path;
    withExtra.push(fillerLeaf(77));
    var shorter: array<int> = [];
    var i = 1;
    repeat (path.size() - 1) {
        shorter.push(path.get(i));
        i += 1;
    }
    val blocks: array<cell> = [
        // another history index, height, root or count
        blockRefCell(old.height, root, 5, 4, path),
        blockRefCell(old.height, root, 5, 2, path),
        blockRefCell(old.height + 1, root, 5, 3, path),
        blockRefCell(old.height, root ^ 1, 5, 3, path),
        blockRefCell(old.height, root, 4, 3, path),
        // an index outside the history
        blockRefCell(old.height, root, 5, 7, path),
        // a path with a sibling too many or too few, and more than 32 siblings
        blockRefCell(old.height, root, 5, 3, withExtra),
        blockRefCell(old.height, root, 5, 3, shorter),
        blockRefCell(old.height, root, 5, 3, longPath),
        // a block without messages, with more than 512, or with a zero root
        blockRefCell(old.height, root, 0, 3, path),
        blockRefCell(old.height, root, 513, 3, path),
        blockRefCell(old.height, 0, 5, 3, path),
        // a block above the certified one
        blockRefCell(old.x.height + 1, root, 5, 3, path),
        // the certified block itself has no messages to prove
        blockRefCell(old.x.height, old.x.sccpRoot, old.x.messageCount, 0, []),
        blockRefCell(old.x.height, root, 5, 3, path),
    ];
    i = 0;
    repeat (blocks.size()) {
        val proof = messageProofCell(old.leafIndex, leafPath, old.payload, blocks.get(i));
        val res = finalizeStored(env, old.x.ref(), proof, finalizeValue(env, 3));
        expectRefused(env, res, SccpErrors.BadProof);
        i += 1;
    }
    expect(i).toEqual(15);
    // the unchanged reference is accepted
    val res = finalizeStored(env, old.x.ref(), old.proof(), finalizeValue(env, 3));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(777);
}

get fun `test a reference to the certified block itself takes no history proof`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val payload = d.payload;
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val leaves = leavesWith(leaf, 1, 3);
    val path = treePath(leaves, 1);
    val x = d.x;
    val blocks: array<cell> = [
        // historyIndex 1, a history path, another root, another count
        blockRefCell(x.height, x.sccpRoot, x.messageCount, 1, []),
        blockRefCell(x.height, x.sccpRoot, x.messageCount, 0, [fillerLeaf(1)]),
        blockRefCell(x.height, x.sccpRoot ^ 1, x.messageCount, 0, []),
        blockRefCell(x.height, x.sccpRoot, x.messageCount + 1, 0, []),
        blockRefCell(x.height, x.sccpRoot, x.messageCount - 1, 0, []),
    ];
    var i = 0;
    repeat (blocks.size()) {
        val proof = messageProofCell(1, path, payload, blocks.get(i));
        // under the stored checkpoint and inline alike
        expectRefused(
            env,
            finalizeStored(env, x.ref(), proof, finalizeValue(env, 0)),
            SccpErrors.BadProof,
        );
        expectRefused(
            env,
            finalizeInline(env, d.cert, proof, finalizeValue(env, 0)),
            SccpErrors.BadProof,
        );
        i += 1;
    }
    expect(i).toEqual(5);
    expect(
        sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
}

get fun `test a block reference cannot name another tree for the certified height`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val mallory = testing.treasury("mallory").address;
    val d = deliverDefault(env, 0, 10, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    // A transfer Taira never recorded, in a tree of the forger's own with
    // the certified leaf count: its path verifies under the forged root.
    val forged = inboundPayloadCell(1, TEST_REVISION, NOW_MS + DAY_MS, 999, mallory.accountId());
    val leaves = leavesWith(inboundLeaf(env.networkId, forged, env.minter.address), 1, 3);
    val root = treeRoot(leaves);
    expect(root != d.x.sccpRoot).toBeTrue();
    expect(
        sccpMerkleRoot(leaves.get(1), 1, 3, treePath(leaves, 1)),
    ).toEqual(root);
    val proof = messageProofCell(
        1,
        treePath(leaves, 1),
        forged,
        blockRefCell(d.x.height, root, d.x.messageCount, 0, []),
    );
    // the root of the certified block is the one X carries
    expectRefused(
        env,
        finalizeStored(env, d.x.ref(), proof, finalizeValue(env, 1)),
        SccpErrors.BadProof,
    );
    expectRefused(
        env,
        finalizeInline(env, d.cert, proof, finalizeValue(env, 1)),
        SccpErrors.BadProof,
    );
    expect(jettonBalanceOf(env, mallory)).toEqual(0);
    expect(isConsumedAt(env, 1)).toBeFalse();
}

get fun `test an index outside a single-leaf block or a single-entry history is refused`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    // a block of one leaf: its root is the leaf, and only index 0 exists
    val payload = inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 10, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val x = blockX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 10,
        [leaf],
    );
    expect(x.sccpRoot).toEqual(leaf);
    val cert = certifyFor(env, env.committee, x);
    val indices: array<int> = [1, 2, 0xffffffff];
    var i = 0;
    repeat (indices.size()) {
        expectRefused(
            env,
            finalizeInline(
                env,
                cert,
                messageProofCell(indices.get(i), [], payload, ownBlockRef(x)),
                finalizeValue(env, 0),
            ),
            SccpErrors.BadProof,
        );
        i += 1;
    }
    // a history of one entry: only history index 0 exists
    var later = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 20);
    later.historySize = 1;
    later.historyRoot = sccpHistoryLeaf(x.height, leaf, 1);
    val laterCert = certifyFor(env, env.committee, later);
    val historyIndices: array<int> = [1, 2, SCCP_MAX_U64];
    i = 0;
    repeat (historyIndices.size()) {
        expectRefused(
            env,
            finalizeInline(
                env,
                laterCert,
                messageProofCell(
                    0,
                    [],
                    payload,
                    blockRefCell(x.height, leaf, 1, historyIndices.get(i), []),
                ),
                finalizeValue(env, 0),
            ),
            SccpErrors.BadProof,
        );
        i += 1;
    }
    // index 0 of both proves the transfer
    val res = finalizeInline(
        env,
        laterCert,
        messageProofCell(0, [], payload, blockRefCell(x.height, leaf, 1, 0, [])),
        finalizeValue(env, 0),
    );
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}

get fun `test a certified history entry that breaks the block rules proves nothing`() {
    // Taira never records such an entry. A quorum that signs a history
    // with one still cannot use it: the rules of §5.1.5 bind the reference.
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 10, alice.accountId());
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val root = env.committee.root();

    // an entry for a block above the certified one
    var first = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 20);
    first.historySize = 1;
    first.historyRoot = sccpHistoryLeaf(first.height + 5, leaf, 1);
    expectRefused(
        env,
        finalizeInline(
            env,
            certifyFor(env, env.committee, first),
            messageProofCell(0, [], payload, blockRefCell(first.height + 5, leaf, 1, 0, [])),
            finalizeValue(env, 0),
        ),
        SccpErrors.BadProof,
    );

    // An entry for a block of 513 leaves: its last leaf is promoted to the
    // top, where it meets the root of the other 512. Its path has one
    // sibling and would pass the path bound.
    val others = fillerLeaf(512);
    val widePath: array<int> = [others];
    val wideRoot = sccpNode(others, leaf);
    expect(
        sccpMerkleRoot(leaf, SCCP_MAX_BLOCK_LEAVES, SCCP_MAX_BLOCK_LEAVES + 1, widePath),
    ).toEqual(wideRoot);
    var second = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 30);
    second.historySize = 1;
    second.historyRoot = sccpHistoryLeaf(
        TEST_START_HEIGHT + 25,
        wideRoot,
        SCCP_MAX_BLOCK_LEAVES + 1,
    );
    expectRefused(
        env,
        finalizeInline(
            env,
            certifyFor(env, env.committee, second),
            messageProofCell(
                SCCP_MAX_BLOCK_LEAVES,
                widePath,
                payload,
                blockRefCell(
                    TEST_START_HEIGHT + 25,
                    wideRoot,
                    SCCP_MAX_BLOCK_LEAVES + 1,
                    0,
                    [],
                ),
            ),
            finalizeValue(env, 0),
        ),
        SccpErrors.BadProof,
    );

    // entries without messages and with a zero root
    var third = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 40);
    third.historySize = 1;
    third.historyRoot = sccpHistoryLeaf(TEST_START_HEIGHT + 35, leaf, 0);
    expectRefused(
        env,
        finalizeInline(
            env,
            certifyFor(env, env.committee, third),
            messageProofCell(0, [], payload, blockRefCell(TEST_START_HEIGHT + 35, leaf, 0, 0, [])),
            finalizeValue(env, 0),
        ),
        SccpErrors.BadProof,
    );
    var fourth = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 50);
    fourth.historySize = 1;
    fourth.historyRoot = sccpHistoryLeaf(TEST_START_HEIGHT + 45, 0, 1);
    expectRefused(
        env,
        finalizeInline(
            env,
            certifyFor(env, env.committee, fourth),
            messageProofCell(0, [], payload, blockRefCell(TEST_START_HEIGHT + 45, 0, 1, 0, [])),
            finalizeValue(env, 0),
        ),
        SccpErrors.BadProof,
    );
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

    // the last leaf of a block of 512 leaves under a genuine entry is proven
    var narrowPath: array<int> = [];
    repeat (SCCP_MAX_BLOCK_PATH) {
        narrowPath.push(fillerLeaf(600 + narrowPath.size()));
    }
    val narrowRoot = sccpMerkleRoot(
        leaf,
        SCCP_MAX_BLOCK_LEAVES - 1,
        SCCP_MAX_BLOCK_LEAVES,
        narrowPath,
    );
    var fifth = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 60);
    fifth.historySize = 1;
    fifth.historyRoot = sccpHistoryLeaf(TEST_START_HEIGHT + 55, narrowRoot, SCCP_MAX_BLOCK_LEAVES);
    val res = finalizeInline(
        env,
        certifyFor(env, env.committee, fifth),
        messageProofCell(
            SCCP_MAX_BLOCK_LEAVES - 1,
            narrowPath,
            payload,
            blockRefCell(
                TEST_START_HEIGHT + 55,
                narrowRoot,
                SCCP_MAX_BLOCK_LEAVES,
                0,
                [],
            ),
        ),
        finalizeValue(env, 0),
    );
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(10);
}

/// An inline finalize with proofs at the largest sizes under a committee of
/// `n`: the last leaf of a 512-leaf block (9 siblings), the last entry of a
/// history of 2^32 blocks (32 siblings), a 1024-byte sender, the largest
/// amount, and four bucket activations.
fun finalizeLargestProofs(n: int, label: string) {
    val env = setupEnvWith(n, SCCP_TON_AMOUNT_LIMIT * 4);
    val alice = testing.treasury("alice").address;
    val nonce = 3 * 512 + 7;
    val payload = inboundPayloadWithSender(
        nonce,
        TEST_REVISION,
        NOW_MS + DAY_MS,
        SCCP_TON_AMOUNT_LIMIT - 1,
        alice.accountId(),
        1024,
    );
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    // the last leaf of a 512-leaf block: nine siblings
    var blockPath: array<int> = [];
    repeat (SCCP_MAX_BLOCK_PATH) {
        blockPath.push(fillerLeaf(100 + blockPath.size()));
    }
    val blockRoot = sccpMerkleRoot(leaf, 511, SCCP_MAX_BLOCK_LEAVES, blockPath);
    // the last entry of a history of 2^32 blocks: 32 siblings
    expect(SCCP_MAX_HISTORY_SIZE).toEqual(VEC_MAX_HISTORY_SIZE);
    var historyPath: array<int> = [];
    repeat (SCCP_MAX_HISTORY_PATH) {
        historyPath.push(fillerLeaf(200 + historyPath.size()));
    }
    val historyIndex = SCCP_MAX_HISTORY_SIZE - 1;
    var x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 99);
    x.messageCount = SCCP_MAX_BLOCK_LEAVES;
    x.sccpRoot = fillerLeaf(9);
    x.historySize = SCCP_MAX_HISTORY_SIZE;
    x.historyRoot = sccpMerkleRoot(
        sccpHistoryLeaf(TEST_START_HEIGHT + 77, blockRoot, SCCP_MAX_BLOCK_LEAVES),
        historyIndex,
        SCCP_MAX_HISTORY_SIZE,
        historyPath,
    );
    val proof = messageProofCell(
        511,
        blockPath,
        payload,
        blockRefCell(
            TEST_START_HEIGHT + 77,
            blockRoot,
            SCCP_MAX_BLOCK_LEAVES,
            historyIndex,
            historyPath,
        ),
    );
    val res = finalizeInline(
        env,
        certifyFor(env, env.committee, x),
        proof,
        finalizeValue(env, nonce),
    );
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(4);
    reportGas(label, stepGas(res), SCCP_GAS_MINTER_FINALIZE);
}

get fun `test proofs at the largest sizes are accepted at n=4`() {
    finalizeLargestProofs(4, "finalize inline worst case n=4");
}

get fun `test proofs at the largest sizes are accepted at n=31`() {
    finalizeLargestProofs(31, "finalize inline worst case n=31");
}

get fun `test finalize after a rotation proves under the installing handoff`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val next = testCommittee(4, 4);
    // generation 7: a block with the transfer, stored as a checkpoint
    val d = deliverAt(
        env,
        env.committee,
        env.generation,
        TEST_START_HEIGHT + 20,
        0,
        600,
        alice,
        NOW_MS + DAY_MS,
        1,
        3,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    // the handoff of generation 7 carries the history with that block
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
    val handoffCert = certifyFor(env, env.committee, handoff);
    expectOutcome(sendCheckpoint(env, env.deployer, handoffCert, next.keysCell(), grams("1")), 0);
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);

    // the non-handoff checkpoint of generation 7 is no longer usable
    expectRefused(
        env,
        sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.CommitteeNotAccepted,
    );
    // and its certificate is not CUR for the inline form
    expectRefused(
        env,
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.CommitteeNotAccepted,
    );
    // the installing handoff proves the same leaf through its history root
    val leaf = inboundLeaf(env.networkId, d.payload, env.minter.address);
    val leaves = leavesWith(leaf, 1, 3);
    val proof = messageProofCell(
        1,
        treePath(leaves, 1),
        d.payload,
        blockRefCell(d.x.height, d.x.sccpRoot, d.x.messageCount, 0, []),
    );
    val res = finalizeStored(env, handoff.ref(), proof, finalizeValue(env, 0));
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expectEvents(res, [eventFinalized(d.messageId, 0)]);
    expect(jettonBalanceOf(env, alice)).toEqual(600);
    // A certificate of the successor proves the block too, inline, through
    // the history root it carries. The nonce is consumed by now, so the
    // minter step passes and the bucket rejects the duplicate.
    var later = emptyX(env.networkId, env.generation + 1, next.root(), TEST_START_HEIGHT + 40);
    later.historySize = 1;
    later.historyRoot = handoff.historyRoot;
    val duplicate = finalizeInline(env, certifyFor(env, next, later), proof, finalizeValue(env, 0));
    expect(duplicate).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(duplicate).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(600);
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

// ---------------------------------------------------------------------------
// Check order of the minter step (§5.1.2 "Check order and errors", §5.3.4).

get fun `test finalize checks run in the order of the specification`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 100, alice);
    val minimum = finalizeValue(env, 0) - sccpMinterStorageGrace();
    val unknownRef = emptyX(env.networkId, env.generation, env.committee.root(), 77).ref();
    val badPayload = inboundPayloadCell(
        0,
        TEST_REVISION + 1,
        NOW_MS + DAY_MS,
        100,
        alice.accountId(),
    );
    val forged = certOf(foreignSignature(), 7, defaultQc(d.x.height), d.x);

    // a malformed proof cell before the payload
    expectRefused(
        env,
        finalizeStored(
            env,
            unknownRef,
            beginCell().storeUint(0, 40).storeRef(badPayload).storeRef(ownBlockRef(d.x)).endCell(),
            minimum - 1,
        ),
        SccpErrors.BadSnake,
    );
    // the payload before the bucket, the value and the checkpoint
    val far = inboundPayloadCell(
        9 * 512,
        TEST_REVISION + 1,
        NOW_MS + DAY_MS,
        100,
        alice.accountId(),
    );
    expectRefused(
        env,
        finalizeStored(
            env,
            unknownRef,
            messageProofCell(0, [], far, ownBlockRef(d.x)),
            minimum - 1,
        ),
        SccpErrors.BadPayload,
    );
    // the bucket of the nonce before the value
    val farGood = inboundPayloadCell(
        9 * 512,
        TEST_REVISION,
        NOW_MS + DAY_MS,
        100,
        alice.accountId(),
    );
    expectRefused(
        env,
        finalizeStored(
            env,
            unknownRef,
            messageProofCell(0, [], farGood, ownBlockRef(d.x)),
            minimum - 1,
        ),
        SccpErrors.BucketNotDeployed,
    );
    // the value before any certificate: a forged certificate is not looked at
    val poor = finalizeInline(env, forged, d.proof, minimum - 1);
    expectRefused(env, poor, SccpErrors.NotEnoughValue);
    expect(stepGas(poor) < 58000).toBeTrue();
    expectRefused(
        env,
        finalizeStored(env, unknownRef, d.proof, minimum - 1),
        SccpErrors.NotEnoughValue,
    );
    // with the value: the certificate, then the checkpoint
    expectRefused(
        env,
        finalizeInline(env, forged, d.proof, minimum),
        SccpErrors.BadSignature,
    );
    expectRefused(
        env,
        finalizeStored(env, unknownRef, d.proof, minimum),
        SccpErrors.UnknownCheckpoint,
    );

    // From here the block of another transfer is certified: its amount is
    // above the cap and its deadline is one second ahead.
    val late = deliver(
        env,
        env.committee,
        env.generation,
        1,
        TEST_MAX_SUPPLY + 1,
        alice,
        NOW_MS + 1000,
        1,
        3,
    );
    val leaves = leavesWith(inboundLeaf(env.networkId, late.payload, env.minter.address), 1, 3);
    val path = treePath(leaves, 1);
    val x = late.x;
    val wrongLeaf = messageProofCell(2, path, late.payload, ownBlockRef(x));
    val badBlock = messageProofCell(
        1,
        path,
        late.payload,
        blockRefCell(x.height, x.sccpRoot, x.messageCount, 1, []),
    );
    val value = finalizeValue(env, 1);
    // the cap is the last check: a valid proof of an amount above it
    expectOrder(
        env,
        finalizeInline(env, late.cert, late.proof, value),
        SccpErrors.SupplyCapExceeded,
    );
    // the leaf path before the cap
    expectOrder(env, finalizeInline(env, late.cert, wrongLeaf, value), SccpErrors.BadProof);
    // the pause before the block reference
    applyControlOk(env, 1, true);
    expectOrder(env, finalizeInline(env, late.cert, badBlock, value), SccpErrors.MintingIsPaused);
    applyControlOk(env, 2, false);

    testing.setNow(T0 + 2);
    // the deadline before the leaf path and the cap
    expectOrder(env, finalizeInline(env, late.cert, wrongLeaf, value), SccpErrors.DeadlinePassed);
    expectOrder(env, finalizeInline(env, late.cert, late.proof, value), SccpErrors.DeadlinePassed);
    // the block reference before the deadline
    expectOrder(env, finalizeInline(env, late.cert, badBlock, value), SccpErrors.BadProof);
    // the pause before the deadline
    applyControlOk(env, 3, true);
    expectOrder(env, finalizeInline(env, late.cert, late.proof, value), SccpErrors.MintingIsPaused);
    // a certificate that does not verify answers before the pause
    val forgedLate = certOf(
        foreignSignature(),
        7,
        defaultQc(x.height + 500),
        blockX(
            env.networkId,
            env.generation,
            env.committee.root(),
            x.height + 500,
            leaves,
        ),
    );
    val elsewhere = messageProofCell(
        1,
        path,
        late.payload,
        blockRefCell(x.height + 500, x.sccpRoot, 3, 0, []),
    );
    expectOrder(env, finalizeInline(env, forgedLate, elsewhere, value), SccpErrors.BadSignature);

    // `Live` before the pause: expired and paused answers for the expiry
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectOrder(
        env,
        finalizeInline(env, late.cert, late.proof, value),
        SccpErrors.CommitteeNotAccepted,
    );
    // and a certificate that does not verify still answers for itself first
    expectOrder(env, finalizeInline(env, forgedLate, elsewhere, value), SccpErrors.BadSignature);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(0);
}

get fun `test finalize refuses a certificate that does not verify`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    val x = d.x;
    val qc = defaultQc(x.height);
    val signers = env.committee.lowestSigners();
    val genuine = blsAggregateSign(
        env.committee.secretsOf(signers),
        commitMessage(env.instance, qc, x),
    );
    var certs: array<cell> = [];
    var codes: array<int> = [];
    // the signature of another quorum under this bitmap, and of another instance
    certs.push(
        certOf(
            blsAggregateSign(
                env.committee.secretsOf(env.committee.highestSigners()),
                commitMessage(env.instance, qc, x),
            ),
            signers,
            qc,
            x,
        ),
    );
    codes.push(SccpErrors.BadSignature);
    certs.push(
        certOf(
            blsAggregateSign(
                env.committee.secretsOf(signers),
                commitMessage(env.instance ^ 1, qc, x),
            ),
            signers,
            qc,
            x,
        ),
    );
    codes.push(SccpErrors.BadSignature);
    // a PrepareQC over the same block
    certs.push(
        certOf(
            blsAggregateSign(
                env.committee.secretsOf(signers),
                voteMessage(0x02, env.instance, x.height, qc, resultOf(x, qc.resultBody)),
            ),
            signers,
            qc,
            x,
        ),
    );
    codes.push(SccpErrors.BadSignature);
    // the identity signature
    certs.push(
        certOf(
            beginCell()
                .storeUint(SCCP_IDENTITY_SIGNATURE_HEAD, 256)
                .storeUint(0, 256)
                .storeUint(0, 256)
                .endCell()
                .beginParse(),
            signers,
            qc,
            x,
        ),
    );
    codes.push(SccpErrors.BadSignature);
    // two signers, all four, and a bit beyond n
    certs.push(certOf(genuine, 0b0011, qc, x));
    codes.push(SccpErrors.BadCertificate);
    certs.push(certOf(genuine, 0b1111, qc, x));
    codes.push(SccpErrors.BadCertificate);
    certs.push(certOf(genuine, 0b10011, qc, x));
    codes.push(SccpErrors.BadCertificate);
    // a certificate cell behind a library reference
    certs.push(asLibrary(d.cert));
    codes.push(SccpErrors.BadSnake);
    var i = 0;
    repeat (certs.size()) {
        expectRefused(
            env,
            finalizeInline(env, certs.get(i), d.proof, grams("5")),
            codes.get(i),
        );
        i += 1;
    }
    expect(i).toEqual(8);
    // headers that are no certified header of this generation, validly signed
    var headers: array<TestX> = [];
    var headerCodes: array<int> = [];
    var other = x;
    other.generation = env.generation - 1;
    headers.push(other);
    headerCodes.push(SccpErrors.CommitteeNotAccepted);
    other = x;
    other.generation = env.generation + 1;
    headers.push(other);
    headerCodes.push(SccpErrors.CommitteeNotAccepted);
    other = x;
    other.committeeRoot = testCommittee(4, 4).root();
    headers.push(other);
    headerCodes.push(SccpErrors.CommitteeNotAccepted);
    other = x;
    other.networkId = env.networkId ^ 1;
    headers.push(other);
    headerCodes.push(SccpErrors.BadHeader);
    // the count and root invariant X4 does not hold
    other = x;
    other.messageCount = 0;
    headers.push(other);
    headerCodes.push(SccpErrors.BadHeader);
    other = x;
    other.flags = 0;
    headers.push(other);
    headerCodes.push(SccpErrors.BadHeader);
    i = 0;
    repeat (headers.size()) {
        val cert = certifyFor(env, env.committee, headers.get(i));
        val proof = messageProofCell(1, [], d.payload, ownBlockRef(headers.get(i)));
        expectRefused(
            env,
            finalizeInline(env, cert, proof, grams("5")),
            headerCodes.get(i),
        );
        i += 1;
    }
    expect(i).toEqual(6);
    // nothing was recorded, and the genuine certificate mints
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
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(1);
}

// ---------------------------------------------------------------------------
// Leaf paths and proof cells (§5.1.5, §5.3.2).

get fun `test leaf path negatives`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val leaf = inboundLeaf(env.networkId, d.payload, env.minter.address);
    val leaves = leavesWith(leaf, 1, 3);
    val path = treePath(leaves, 1);
    expect(path.size()).toEqual(2);
    val block = ownBlockRef(d.x);
    var ten: array<int> = [];
    repeat (10) {
        ten.push(fillerLeaf(300 + ten.size()));
    }
    val proofs: array<cell> = [
        // another index, also the index of the promoted leaf and one outside the block
        messageProofCell(0, path, d.payload, block),
        messageProofCell(2, path, d.payload, block),
        messageProofCell(3, path, d.payload, block),
        // a truncated path, no path, a path with a sibling too many
        messageProofCell(1, [path.get(0)], d.payload, block),
        messageProofCell(1, [], d.payload, block),
        messageProofCell(1, [path.get(0), path.get(1), fillerLeaf(9)], d.payload, block),
        // the siblings in the other order
        messageProofCell(1, [path.get(1), path.get(0)], d.payload, block),
        // more than nine siblings
        messageProofCell(1, ten, d.payload, block),
    ];
    var i = 0;
    repeat (proofs.size()) {
        expectRefused(
            env,
            finalizeStored(env, d.x.ref(), proofs.get(i), finalizeValue(env, 0)),
            SccpErrors.BadProof,
        );
        i += 1;
    }
    expect(i).toEqual(8);
    // another payload under the path of this one
    val otherPayload = inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 2, alice.accountId());
    expectRefused(
        env,
        finalizeStored(
            env,
            d.x.ref(),
            messageProofCell(1, path, otherPayload, block),
            finalizeValue(env, 0),
        ),
        SccpErrors.BadProof,
    );
    expect(
        sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
}

get fun `test a leaf for another destination word or another lane is rejected`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val payload = inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 1, alice.accountId());
    val parsed = sccpParseInboundPayload(payload, TEST_REVISION, 0);
    val leaves: array<int> = [
        // the same message for another minter
        sccpTransferLeaf(sccpInboundMessageId(env.networkId, parsed.payloadHash), 0x99),
        // the message id of another Taira network, and of the opposite lane
        sccpTransferLeaf(
            sccpInboundMessageId(env.networkId ^ 1, parsed.payloadHash),
            env.minter.address.accountId(),
        ),
        sccpTransferLeaf(
            sccpOutboundMessageId(env.networkId, parsed.payloadHash),
            env.minter.address.accountId(),
        ),
        // the payload hash itself, and the message id, as leaves
        parsed.payloadHash,
        sccpInboundMessageId(env.networkId, parsed.payloadHash),
    ];
    var i = 0;
    repeat (leaves.size()) {
        val block = leavesWith(leaves.get(i), 0, 2);
        val x = blockX(
            env.networkId,
            env.generation,
            env.committee.root(),
            TEST_START_HEIGHT + 10 + i,
            block,
        );
        val proof = messageProofCell(0, treePath(block, 0), payload, ownBlockRef(x));
        expectRefused(
            env,
            finalizeInline(env, certifyFor(env, env.committee, x), proof, grams("5")),
            SccpErrors.BadProof,
        );
        i += 1;
    }
    expect(i).toEqual(5);
}

get fun `test proof cells of another shape are BadSnake`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val leaf = inboundLeaf(env.networkId, d.payload, env.minter.address);
    val path = treePath(leavesWith(leaf, 1, 3), 1);
    val block = ownBlockRef(d.x);
    val pathCell = sccpBuildHashPath(path)!;
    val x = d.x;
    val blockBits = beginCell()
        .storeUint(x.height, 64)
        .storeUint(x.sccpRoot, 256)
        .storeUint(x.messageCount, 32)
        .storeUint(0, 64)
        .storeUint(0, 8);
    val proofs: array<cell> = [
        // MessageProof: 40 and 49 bits, a missing and an extra reference,
        // the Maybe bit against the references, and a library cell
        beginCell().storeUint(1, 32).storeUint(2, 7).storeRef(d.payload).storeRef(block).endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeUint(0, 8)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(0, 1)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .storeRef(block)
            .endCell(),
        asLibrary(d.proof),
        // the path: a length without a path, a path without a length, one
        // hash too few, and a library chunk
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(0, 1)
            .storeRef(d.payload)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(0, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(3, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(asLibrary(pathCell))
            .storeRef(block)
            .endCell(),
        // a last chunk with a stray reference, and a first chunk of a path
        // of four hashes whose Maybe bit is set without a next chunk
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(
                beginCell()
                    .storeUint(path.get(0), 256)
                    .storeUint(path.get(1), 256)
                    .storeUint(0, 1)
                    .storeRef(block)
                    .endCell(),
            )
            .storeRef(block)
            .endCell(),
        beginCell()
            .storeUint(1, 32)
            .storeUint(4, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(
                beginCell()
                    .storeUint(path.get(0), 256)
                    .storeUint(path.get(1), 256)
                    .storeUint(fillerLeaf(7), 256)
                    .storeUint(1, 1)
                    .endCell(),
            )
            .storeRef(block)
            .endCell(),
        // BlockRef: 424 and 433 bits, a path bit without a path, a stray
        // reference, and a library cell
        messageProofCell(
            1,
            path,
            d.payload,
            beginCell()
                .storeUint(x.height, 64)
                .storeUint(x.sccpRoot, 256)
                .storeUint(x.messageCount, 32)
                .storeUint(0, 64)
                .storeUint(0, 7)
                .storeUint(0, 1)
                .endCell(),
        ),
        messageProofCell(
            1,
            path,
            d.payload,
            beginCell().storeBuilder(blockBits).storeUint(0, 1).storeUint(0, 8).endCell(),
        ),
        messageProofCell(
            1,
            path,
            d.payload,
            beginCell().storeBuilder(blockBits).storeUint(1, 1).endCell(),
        ),
        messageProofCell(
            1,
            path,
            d.payload,
            beginCell().storeBuilder(blockBits).storeUint(0, 1).storeRef(pathCell).endCell(),
        ),
        messageProofCell(1, path, d.payload, asLibrary(block)),
    ];
    var i = 0;
    repeat (proofs.size()) {
        val res = finalizeStored(env, x.ref(), proofs.get(i), finalizeValue(env, 0));
        if (outcomeOf(res) != SccpErrors.BadSnake as int) {
            println("proof shape {} observed {}", i, outcomeOf(res));
        }
        expectRefused(env, res, SccpErrors.BadSnake);
        i += 1;
    }
    expect(i).toEqual(17);
    // the hand-built canonical cells are the ones the helpers build
    expect(beginCell().storeBuilder(blockBits).storeUint(0, 1).endCell().hash()).toEqual(
        block.hash(),
    );
    expect(
        beginCell()
            .storeUint(1, 32)
            .storeUint(2, 8)
            .storeUint(1, 1)
            .storeRef(d.payload)
            .storeRef(pathCell)
            .storeRef(block)
            .endCell()
            .hash(),
    ).toEqual(d.proof.hash());
    expect(
        sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
}

// ---------------------------------------------------------------------------
// Payloads and recipients (§3.2, §5.1.5 step 4).

/// `route_id = "taira_eth_xor"`, the route of another destination (13 bytes).
const OTHER_ROUTE_ID = 0x74616972615f6574685f786f72

/// The fields of a Taira→TON payload; `inboundFields` gives the valid ones.
struct PayloadFields {
    kind: int
    version: int
    sourceDomain: int
    destDomain: int
    nonce: int
    revision: int
    deadlineMs: int
    assetHome: int
    assetCodec: int
    assetLen: int
    asset: int
    amount: int
    senderCodec: int
    senderLen: int
    recipientCodec: int
    recipientLen: int
    workchain: int
    recipientHash: int
    routeCodec: int
    routeLen: int
    route: int
    trailingBytes: int
}

/// The fields of a valid transfer of 1000 units to `recipientHash`.
fun inboundFields(recipientHash: int): PayloadFields {
    return {
        kind: SCCP_PAYLOAD_KIND_TRANSFER,
        version: SCCP_PAYLOAD_VERSION,
        sourceDomain: SCCP_DOMAIN_TAIRA,
        destDomain: SCCP_DOMAIN_TON,
        nonce: 0,
        revision: TEST_REVISION,
        deadlineMs: NOW_MS + DAY_MS,
        assetHome: SCCP_DOMAIN_TAIRA,
        assetCodec: SCCP_CODEC_CANONICAL_TEXT,
        assetLen: SCCP_ASSET_ID_XOR_LEN,
        asset: SCCP_ASSET_ID_XOR,
        amount: 1000,
        senderCodec: SCCP_CODEC_TAIRA_ACCOUNT,
        senderLen: TEST_SENDER_LEN,
        recipientCodec: SCCP_CODEC_TON_ACCOUNT36,
        recipientLen: SCCP_TON_ACCOUNT36_LEN,
        workchain: 0,
        recipientHash,
        routeCodec: SCCP_CODEC_CANONICAL_TEXT,
        routeLen: SCCP_ROUTE_ID_TON_LEN,
        route: SCCP_ROUTE_ID_TON,
        trailingBytes: 0,
    };
}

/// The payload bytes of the fields as they are, in a canonical snake cell.
/// The asset id is written in 3 bytes and the route id in 13 whatever their
/// length fields say.
fun PayloadFields.toCell(self): cell {
    var w = SnakeWriter.create();
    w.writeUint(self.kind, 1);
    w.writeUint(self.version, 1);
    w.writeUint(self.sourceDomain, 4);
    w.writeUint(self.destDomain, 4);
    w.writeUint(self.nonce, 8);
    w.writeUint(self.revision, 4);
    w.writeUint(self.deadlineMs, 8);
    w.writeUint(self.assetHome, 4);
    w.writeUint(self.assetCodec, 1);
    w.writeUint(self.assetLen, 2);
    w.writeUint(self.asset, 3);
    w.writeUint(self.amount, 16);
    w.writeUint(self.senderCodec, 1);
    w.writeUint(self.senderLen, 2);
    var i = 1;
    while (i <= self.senderLen) {
        w.writeUint(i & 0xFF, 1);
        i += 1;
    }
    w.writeUint(self.recipientCodec, 1);
    w.writeUint(self.recipientLen, 2);
    w.writeUint(self.workchain, 4);
    w.writeUint(self.recipientHash, 32);
    w.writeUint(self.routeCodec, 1);
    w.writeUint(self.routeLen, 2);
    w.writeUint(self.route, 13);
    repeat (self.trailingBytes) {
        w.writeUint(0, 1);
    }
    return sccpSnakeCellFromChunks(w.chunks());
}

/// Sends a finalize of `payload` against a checkpoint that is not stored.
/// The payload and its recipient are judged before `X`, so a valid payload
/// answers `UnknownCheckpoint`.
fun sendPayloadProbe(env: Env, payload: cell): SendResultList {
    val unknown = emptyX(env.networkId, env.generation, env.committee.root(), 77);
    return finalizeStored(
        env,
        unknown.ref(),
        messageProofCell(0, [], payload, ownBlockRef(unknown)),
        grams("5"),
    );
}

get fun `test a payload that violates the transfer rules is BadPayload`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val good = inboundFields(alice.accountId());
    // the writer of this suite builds the payload the helpers build
    expect(good.toCell().hash()).toEqual(
        inboundPayloadCell(0, TEST_REVISION, NOW_MS + DAY_MS, 1000, alice.accountId()).hash(),
    );
    expectRefused(env, sendPayloadProbe(env, good.toCell()), SccpErrors.UnknownCheckpoint);

    var cases: array<PayloadFields> = [];
    var f = good;
    f.kind = 0x01;
    cases.push(f);
    f = good;
    f.version = 0x02;
    cases.push(f);
    // a payload of the opposite direction, of another destination, and Taira to Taira
    f = good;
    f.sourceDomain = SCCP_DOMAIN_TON;
    f.destDomain = SCCP_DOMAIN_TAIRA;
    cases.push(f);
    f = good;
    f.destDomain = 1;
    cases.push(f);
    f = good;
    f.destDomain = SCCP_DOMAIN_TAIRA;
    cases.push(f);
    f = good;
    f.sourceDomain = 1;
    cases.push(f);
    // another route revision, and revision 0
    f = good;
    f.revision = TEST_REVISION + 1;
    cases.push(f);
    f = good;
    f.revision = 0;
    cases.push(f);
    // no deadline
    f = good;
    f.deadlineMs = 0;
    cases.push(f);
    // another asset
    f = good;
    f.assetHome = 1;
    cases.push(f);
    f = good;
    f.assetCodec = 2;
    cases.push(f);
    f = good;
    f.assetLen = 4;
    cases.push(f);
    f = good;
    f.asset = 0x786f73;
    cases.push(f);
    // amount 0, 2^96 and the largest u128
    f = good;
    f.amount = 0;
    cases.push(f);
    f = good;
    f.amount = SCCP_TON_AMOUNT_LIMIT;
    cases.push(f);
    f = good;
    f.amount = (1 << 128) - 1;
    cases.push(f);
    // sender: another codec, no bytes, 1025 bytes
    f = good;
    f.senderCodec = 2;
    cases.push(f);
    f = good;
    f.senderLen = 0;
    cases.push(f);
    f = good;
    f.senderLen = 1025;
    cases.push(f);
    // recipient: an EVM codec, and another length
    f = good;
    f.recipientCodec = 2;
    cases.push(f);
    f = good;
    f.recipientLen = 35;
    cases.push(f);
    f = good;
    f.recipientLen = 32;
    cases.push(f);
    // route id: another codec, length and route
    f = good;
    f.routeCodec = 2;
    cases.push(f);
    f = good;
    f.routeLen = 12;
    cases.push(f);
    f = good;
    f.route = OTHER_ROUTE_ID;
    cases.push(f);
    // trailing bytes
    f = good;
    f.trailingBytes = 1;
    cases.push(f);
    f = good;
    f.trailingBytes = 200;
    cases.push(f);
    var i = 0;
    repeat (cases.size()) {
        val res = sendPayloadProbe(env, cases.get(i).toCell());
        if (outcomeOf(res) != SccpErrors.BadPayload as int) {
            println("payload case {} observed {}", i, outcomeOf(res));
        }
        expectRefused(env, res, SccpErrors.BadPayload);
        i += 1;
    }
    expect(i).toEqual(27);
    // the largest amount and the longest sender are valid
    f = good;
    f.amount = SCCP_TON_AMOUNT_LIMIT - 1;
    f.senderLen = 1024;
    expectRefused(env, sendPayloadProbe(env, f.toCell()), SccpErrors.UnknownCheckpoint);
    f = good;
    f.senderLen = 1;
    expectRefused(env, sendPayloadProbe(env, f.toCell()), SccpErrors.UnknownCheckpoint);
    // fewer bytes than the fixed fields, and more than 4096
    expectRefused(env, sendPayloadProbe(env, snakeOfLength(114)), SccpErrors.BadPayload);
    expectRefused(env, sendPayloadProbe(env, snakeOfLength(4097)), SccpErrors.BadPayload);
    // the valid payload cut short is refused as a payload wherever it ends:
    // inside the fixed prefix, at the sender length, inside the sender and
    // inside the suffix
    val whole = good.toCell().beginParse();
    expect(whole.remainingBitsCount()).toEqual(SCCP_SNAKE_CHUNK_BITS);
    val lengths: array<int> = [
        1,
        2,
        10,
        18,
        30,
        58,
        59,
        60,
        94,
        114,
        115,
        127,
    ];
    i = 0;
    repeat (lengths.size()) {
        val cut = snakeFromPieces([whole.getFirstBits(lengths.get(i) * 8)]);
        val res = sendPayloadProbe(env, cut);
        if (outcomeOf(res) != SccpErrors.BadPayload as int) {
            println("payload cut at {} observed {}", lengths.get(i), outcomeOf(res));
        }
        expectRefused(env, res, SccpErrors.BadPayload);
        i += 1;
    }
    expect(i).toEqual(12);
}

get fun `test a recipient the minter cannot mint to is BadRecipient`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val good = inboundFields(alice.accountId());
    var cases: array<PayloadFields> = [];
    // the masterchain and another workchain
    var f = good;
    f.workchain = 0xffffffff;
    cases.push(f);
    f = good;
    f.workchain = 1;
    cases.push(f);
    // the zero account id, and the minter itself
    f = good;
    f.recipientHash = 0;
    cases.push(f);
    f = good;
    f.recipientHash = env.minter.address.accountId();
    cases.push(f);
    var i = 0;
    repeat (cases.size()) {
        expectRefused(env, sendPayloadProbe(env, cases.get(i).toCell()), SccpErrors.BadRecipient);
        i += 1;
    }
    expect(i).toEqual(4);
    // BadRecipient answers only a payload that is valid in everything else
    f = good;
    f.recipientHash = env.minter.address.accountId();
    f.revision = TEST_REVISION + 1;
    expectRefused(env, sendPayloadProbe(env, f.toCell()), SccpErrors.BadPayload);
    f = good;
    f.workchain = 1;
    f.route = OTHER_ROUTE_ID;
    expectRefused(env, sendPayloadProbe(env, f.toCell()), SccpErrors.BadPayload);
    // a wallet, a bucket and any other account are valid recipients
    f = good;
    f.recipientHash = env.minter.getBucketAddress(0).accountId();
    expectRefused(env, sendPayloadProbe(env, f.toCell()), SccpErrors.UnknownCheckpoint);
}

get fun `test a payload cell that is no canonical snake is BadSnake`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    // a valid payload of 150 bytes: one full chunk and a last chunk of 23 bytes
    var f = inboundFields(alice.accountId());
    f.senderLen = 36;
    val payload = f.toCell();
    var first = payload.beginParse();
    val second = first.loadRef();
    expect(first.remainingBitsCount()).toEqual(SCCP_SNAKE_CHUNK_BITS);
    expect(second.beginParse().remainingBitsCount()).toEqual(23 * 8);
    expectRefused(env, sendPayloadProbe(env, payload), SccpErrors.UnknownCheckpoint);
    val shapes: array<cell> = [
        // the same bytes split after 100 bytes, and with an empty last chunk
        beginCell()
            .storeSlice(first.getFirstBits(800))
            .storeRef(
                beginCell()
                    .storeSlice(first.getMiddleBits(800, SCCP_SNAKE_CHUNK_BITS - 800))
                    .storeSlice(second.beginParse())
                    .endCell(),
            )
            .endCell(),
        beginCell()
            .storeSlice(first)
            .storeRef(
                beginCell()
                    .storeSlice(second.beginParse())
                    .storeRef(beginCell().endCell())
                    .endCell(),
            )
            .endCell(),
        // a chunk with two references, and a last chunk that is not whole bytes
        beginCell().storeSlice(first).storeRef(second).storeRef(second).endCell(),
        beginCell()
            .storeSlice(first)
            .storeRef(beginCell().storeSlice(second.beginParse()).storeUint(0, 1).endCell())
            .endCell(),
        // an empty cell
        beginCell().endCell(),
        // library cells: the root, and the continuation
        asLibrary(payload),
        beginCell().storeSlice(first).storeRef(asLibrary(second)).endCell(),
    ];
    var i = 0;
    repeat (shapes.size()) {
        expectRefused(env, sendPayloadProbe(env, shapes.get(i)), SccpErrors.BadSnake);
        i += 1;
    }
    expect(i).toEqual(7);
}

// ---------------------------------------------------------------------------
// Replay, cap, deadline and `Live`.

get fun `test duplicate finalize is rejected by the bucket and releases pending supply`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 5, 1000, alice);
    val d = deliverDefault(env, 5, 1000, alice);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, 5));
    expect(res).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    // the block is stored: the cheap path publishes nothing
    expectEvents(res, []);
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(1000);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    // the checkpoint form is rejected the same way
    val again = sendFinalizeCheckpoint(env, env.deployer, d, finalizeValue(env, 5));
    expect(again).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(env.minter.getSccpState().opCount).toEqual(1);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
}

get fun `test parallel duplicate finalizes reserve pending supply until the bucket rejects one`() {
    // cap admits one mint of 1000 plus nothing else
    val env = setupEnvWith(4, 1500);
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1000, alice);
    val value = finalizeValue(env, 0);
    val first = testing.processSingleTraceStep(env.deployer, finalizeMessage(env, d, value));
    expect(env.minter.getSccpState().pendingSupply).toEqual(1000);
    // the duplicate is refused by the cap while the first is pending
    val second = sendFinalize(env, env.deployer, d, value);
    expect(second).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.SupplyCapExceeded as int,
    });
    // The first step sent its two events, the activation of bucket 0 and the
    // consume. Deliver the last two; the mint completes.
    val outs = first.outMessages.size();
    expect(outs).toEqual(4);
    net.send(env.minter.address, forwardOut(first, outs - 2));
    net.send(env.minter.address, forwardOut(first, outs - 1));
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
    val first = testing.processSingleTraceStep(env.deployer, finalizeMessage(env, d, value));
    // the first entry stored X and activates bucket 0, so the duplicate
    // takes the cheap path and only consumes
    val second = testing.processSingleTraceStep(env.deployer, finalizeMessage(env, d, value));
    expect(env.minter.getSccpState().pendingSupply).toEqual(800);
    expect(first.outMessages.size()).toEqual(4);
    expect(second.outMessages.size()).toEqual(1);
    net.send(env.minter.address, forwardOut(first, 2));
    net.send(env.minter.address, forwardOut(first, 3));
    net.send(env.minter.address, forwardOut(second, 0));
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(400);
    expect(state.opCount).toEqual(1);
    expect(jettonBalanceOf(env, alice)).toEqual(400);
}

get fun `test supply cap edges`() {
    val env = setupEnvWith(4, 1000);
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
    // a refused mint reserves nothing
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    finalizeOk(env, 3, 400, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
    // the cap is reached: a single unit is refused
    val one = deliverDefault(env, 4, 1, alice);
    expect(
        sendFinalize(env, env.deployer, one, finalizeValue(env, 4)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.SupplyCapExceeded as int,
    });
    // At the full cap the duplicate of a minted message is refused by the cap
    // as well. The consumed set is the bucket's: the minter asks it after its
    // own checks (§5.3.4 finalize steps 1 and 2), where an EVM destination
    // answers `AlreadyConsumed` before the cap (§5.1.5 steps 6 and 7).
    val minted = deliverDefault(env, 3, 400, alice);
    val duplicate = sendFinalize(env, env.deployer, minted, finalizeValue(env, 3));
    expectOutcome(duplicate, SccpErrors.SupplyCapExceeded);
    expect(duplicate).toNotHaveTx<SccpConsume>({});
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(1000);
    expect(state.opCount).toEqual(2);
}

get fun `test the largest amount mints under a cap above it`() {
    val env = setupEnvWith(4, SCCP_TON_AMOUNT_LIMIT * 2);
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, SCCP_TON_AMOUNT_LIMIT - 1, alice);
    finalizeOk(env, 1, SCCP_TON_AMOUNT_LIMIT - 1, bob);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(2 * (SCCP_TON_AMOUNT_LIMIT - 1));
    expect(state.maxSupply).toEqual(SCCP_TON_AMOUNT_LIMIT * 2);
    // two units are left under the cap
    val three = deliverDefault(env, 2, 3, alice);
    expectOutcome(
        sendFinalize(env, env.deployer, three, finalizeValue(env, 2)),
        SccpErrors.SupplyCapExceeded,
    );
    finalizeOk(env, 3, 2, bob);
    expect(env.minter.getSccpState().totalSupply).toEqual(SCCP_TON_AMOUNT_LIMIT * 2);
}

get fun `test deadline edges`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val deadline = (T0 + 100) * 1000;
    val d = deliver(
        env,
        env.committee,
        env.generation,
        0,
        50,
        alice,
        deadline,
        0,
        1,
    );
    val late = deliver(
        env,
        env.committee,
        env.generation,
        1,
        60,
        alice,
        deadline,
        0,
        1,
    );
    // a deadline ending in 999 ms
    val subSecond = deliver(
        env,
        env.committee,
        env.generation,
        2,
        70,
        alice,
        (T0 + 200) * 1000 + 999,
        0,
        1,
    );
    val lateSubSecond = deliver(
        env,
        env.committee,
        env.generation,
        3,
        80,
        alice,
        (T0 + 200) * 1000 + 999,
        0,
        1,
    );
    // at now_ms = deadline_ms the mint is accepted
    testing.setNow(T0 + 100);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(50);
    // one second later it is refused
    testing.setNow(T0 + 101);
    expect(
        sendFinalize(env, env.deployer, late, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.DeadlinePassed as int,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(50);
    // the whole seconds on both sides of the sub-second deadline
    testing.setNow(T0 + 200);
    expect(
        sendFinalize(env, env.deployer, subSecond, finalizeValue(env, 2)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    testing.setNow(T0 + 201);
    expectOutcome(
        sendFinalize(env, env.deployer, lateSubSecond, finalizeValue(env, 3)),
        SccpErrors.DeadlinePassed,
    );
    expect(jettonBalanceOf(env, alice)).toEqual(120);
    expect(env.minter.getSccpState().opCount).toEqual(2);
}

get fun `test an expired generation cannot finalize`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliver(
        env,
        env.committee,
        env.generation,
        0,
        50,
        alice,
        PIN_UNTIL_MS + DAY_MS,
        0,
        1,
    );
    // at untilMs the minter is still Live
    testing.setNow(PIN_UNTIL_MS / 1000);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    val d2 = deliver(
        env,
        env.committee,
        env.generation,
        1,
        50,
        alice,
        PIN_UNTIL_MS + DAY_MS,
        0,
        1,
    );
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    val res = sendFinalize(env, env.deployer, d2, finalizeValue(env, 1));
    expect(res).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.CommitteeNotAccepted as int,
    });
    // the refused call stores no checkpoint
    expectEvents(res, []);
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
    expect(jettonBalanceOf(env, alice)).toEqual(50);
}

get fun `test the pause blocks finalization only while it is in force`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    // a Parliament pause
    applyControlOk(env, 1, true);
    val paused = sendFinalize(env, env.deployer, d, finalizeValue(env, 0));
    expectOutcome(paused, SccpErrors.MintingIsPaused);
    expectEvents(paused, []);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    // the refused call recorded nothing of its certificate
    expect(env.minter.getSccpCheckpoints().count).toEqual(1);
    applyControlOk(env, 2, false);
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(10);

    // a fast pause until T0 + 600 s: paused while now_ms < fastPauseUntilMs
    val until = (T0 + 600) * 1000;
    expectOutcome(sendApplyControl(env, deliverFastPause(env, 3, false, until)), 0);
    val next = deliverAt(
        env,
        env.committee,
        env.generation,
        TEST_START_HEIGHT + 300,
        1,
        20,
        alice,
        NOW_MS + DAY_MS,
        1,
        3,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, next.cert, null, grams("1")), 0);
    testing.setNow(T0 + 599);
    expectOutcome(
        sendFinalizeCheckpoint(env, env.deployer, next, finalizeValue(env, 1)),
        SccpErrors.MintingIsPaused,
    );
    // at the expiry minting resumes with no relay
    testing.setNow(T0 + 600);
    expect(
        sendFinalizeCheckpoint(env, env.deployer, next, finalizeValue(env, 1)),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(30);
}

// ---------------------------------------------------------------------------
// Buckets (§5.3.4 step 2).

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
    expect(deploy).toHaveSuccessfulDeploy<SccpActivateBucket>({
        to: env.minter.getBucketAddress(7),
    });
    expect(env.minter.getSccpState().deployedBuckets).toEqual(8);
    finalizeOk(env, 10 * 512, 1, alice);
    expect(env.minter.getSccpState().opCount).toEqual(4);
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
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // after the two events: the activation of bucket 0, then the consume
    val outs = step.outMessages.size();
    expect(outs).toEqual(4);
    val activate = step.outMessages.at<SccpActivateBucket>(outs - 2).loadBody();
    expect(activate.index).toEqual(0);
    val consume = step.outMessages.at<SccpConsume>(outs - 1).loadBody();
    expect(consume.nonce).toEqual(0);
    expect(consume.amount).toEqual(300);
    val tail = consume.tail.load();
    expect(tail.kind).toEqual(SCCP_CONSUME_KIND_MINT);
    expect(tail.recipient!).toEqual(alice);
    expect(tail.response).toEqual(env.deployer);
    expect(tail.messageId).toEqual(d.messageId);
    // a bounce from anyone but the bucket is refused
    val stranger = testing.treasury("stranger").address;
    testing.processSingleTraceStep(
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
        finalizeMessage(env, d, finalizeValue(env, 0)),
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
    reportGas(
        "minter bounced internal_transfer",
        bounce.getUsedGas({ to: env.minter.address, bounced: true }),
        SCCP_GAS_MINTER_BOUNCE,
    );
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
        finalizeMessage(env, d, finalizeValue(env, 0)),
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
    expect(res).toHaveFailedTx<SccpConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
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
    expect(res2).toHaveFailedTx<SccpAlreadyConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    val res3 = env
        .minter
        .sendSccpRangeConsumed(stranger, 0, 0, 1, { value: grams("1"), bounce: true });
    expect(res3).toHaveFailedTx<SccpRangeConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    // the bucket of another index is not the bucket of the nonce
    finalizeOk(env, 600, 5, stranger);
    val res4 = env
        .minter
        .sendSccpConsumed(
            env.minter.getBucketAddress(1),
            0,
            0,
            1000000,
            tail,
            { value: grams("1"), bounce: true },
        );
    expect(res4).toHaveFailedTx<SccpConsumed>({
        to: env.minter.address,
        exitCode: SccpErrors.NotBucket as int,
    });
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(5);
    expect(state.opCount).toEqual(1);
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

// ---------------------------------------------------------------------------
// A mint in flight (§5.3.4 item 6, finalize step 4).

get fun `test a mint in flight when the latch fires is not minted and its nonce stays voidable`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 300, alice);
    // the minter step ran: the activation of bucket 0 and the consume are in flight
    val first = testing.processSingleTraceStep(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    expect(first.outMessages.size()).toEqual(4);
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // the latch fires: the generation certifies a height below its start (V2)
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);

    // The bucket sets the flag and replies `sccp_consumed`. The minter mints
    // nothing: it releases the pending supply and has the bucket clear the flag.
    net.send(env.minter.address, forwardOut(first, 2));
    val res = net.send(env.minter.address, forwardOut(first, 3));
    expect(res).toHaveSuccessfulTx<SccpConsume>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpUnconsume>({ to: env.minter.getBucketAddress(0) });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toNotHaveTx<InternalTransferStep>({});
    expect(res).toHaveAllSuccessfulTxs();
    // the reply throws nothing, neither 433 nor any other code, and emits nothing
    expectEvents(res, []);
    var state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    expect(isConsumedAt(env, 0)).toBeFalse();
    expect(env.minter.getSccpRetry(0)).toEqual(0);

    // the message cannot be finalized any more, and the frozen void takes its nonce
    expectOutcome(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
        SccpErrors.Equivocated,
    );
    val voided = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expectEvents(voided, [eventVoided(0, 0, 1)]);
    expect(isConsumedAt(env, 0)).toBeTrue();
    state = env.minter.getSccpState();
    expect(state.opCount).toEqual(1);
    expect(state.totalSupply).toEqual(0);
}

get fun `test expiry alone does not cancel a mint in flight`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliver(
        env,
        env.committee,
        env.generation,
        0,
        300,
        alice,
        PIN_UNTIL_MS + DAY_MS,
        0,
        1,
    );
    // the minter step runs at untilMs, the last clock value at which it is Live
    testing.setNow(PIN_UNTIL_MS / 1000);
    val first = testing.processSingleTraceStep(
        env.deployer,
        finalizeMessage(env, d, finalizeValue(env, 0)),
    );
    expect(first.outMessages.size()).toEqual(4);
    expect(env.minter.getSccpState().pendingSupply).toEqual(300);
    // the generation expires while the bucket messages are in flight: no latch
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    var state = env.minter.getSccpState();
    expect(state.equivocated).toBeFalse();
    expect(sccpIsLive(state.equivocated, state.untilMs, PIN_UNTIL_MS + 1000)).toBeFalse();
    net.send(env.minter.address, forwardOut(first, 2));
    val res = net.send(env.minter.address, forwardOut(first, 3));
    // the admitted mint completes
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(res).toHaveSuccessfulDeploy<InternalTransferStep>({ to: walletOf(env, alice).address });
    expect(res).toNotHaveTx<SccpUnconsume>({});
    expectEvents(res, [eventFinalized(d.messageId, 0)]);
    expect(jettonBalanceOf(env, alice)).toEqual(300);
    state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(300);
    expect(state.opCount).toEqual(1);
    expect(isConsumedAt(env, 0)).toBeTrue();

    // nothing new is admitted, and the minted nonce is not voidable
    val late = deliver(
        env,
        env.committee,
        env.generation,
        1,
        5,
        alice,
        PIN_UNTIL_MS + DAY_MS,
        0,
        1,
    );
    expectOutcome(
        sendFinalize(env, env.deployer, late, finalizeValue(env, 1)),
        SccpErrors.CommitteeNotAccepted,
    );
    val rejected = sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0));
    expect(rejected).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    expectEvents(rejected, []);
    expect(env.minter.getSccpState().totalSupply).toEqual(300);
}

// ---------------------------------------------------------------------------
// Value, chain identity and the operation counter.

get fun `test finalize requires the required value`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    // the minter is above its floor: the entry minimum is the quote minus the grace
    val required = finalizeValue(env, 0);
    expect(required).toEqual(sccpFinalizeRequiredValue(1) + sccpMinterStorageGrace());
    val minimum = required - sccpMinterStorageGrace();
    val poor = sendFinalize(env, env.deployer, d, minimum - 1);
    expect(poor).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    // refused before any signature work, and nothing is stored
    expect(stepGas(poor) < 58000).toBeTrue();
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
    val res = sendFinalize(env, env.deployer, d, minimum);
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(1);
    // a nonce whose bucket exists needs no activation
    expect(
        env.minter.finalizeRequiredValue(1),
    ).toEqual(sccpFinalizeRequiredValue(0) + sccpMinterStorageGrace());
    expect(sccpFinalizeRequiredValue(0) < sccpFinalizeRequiredValue(1)).toBeTrue();
}

get fun `test finalize requires the ton mainnet global id`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 1, alice);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    setGlobalId(-3);
    expect(sendFinalize(env, env.deployer, d, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.WrongChain as int,
    });
    expectOutcome(sendFinalizeCheckpoint(env, env.deployer, d, grams("5")), SccpErrors.WrongChain);
    // chain identity comes before the payload
    val badPayload = inboundPayloadCell(
        0,
        TEST_REVISION + 1,
        NOW_MS + DAY_MS,
        1,
        alice.accountId(),
    );
    expectOutcome(
        finalizeStored(
            env,
            d.x.ref(),
            messageProofCell(0, [], badPayload, ownBlockRef(d.x)),
            grams("5"),
        ),
        SccpErrors.WrongChain,
    );
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expect(
        sendFinalizeCheckpoint(env, env.deployer, d, grams("5")),
    ).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
}

get fun `test opCount saturates at the top of u64 under a mint`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    expect(sccpBumpedOpCount(0)).toEqual(1);
    expect(sccpBumpedOpCount(SCCP_MAX_U64 - 1)).toEqual(SCCP_MAX_U64);
    expect(sccpBumpedOpCount(SCCP_MAX_U64)).toEqual(SCCP_MAX_U64);
    // storage injection: one operation below the bound
    var st = minterStorage(env);
    st.opCount = SCCP_MAX_U64 - 1;
    setMinterStorage(env, st);
    finalizeOk(env, 0, 10, alice);
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    // the operation that meets the bound still succeeds, and the counter stays
    finalizeOk(env, 1, 10, alice);
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(SCCP_MAX_U64);
    expect(state.totalSupply).toEqual(20);
    expect(jettonBalanceOf(env, alice)).toEqual(20);
}
