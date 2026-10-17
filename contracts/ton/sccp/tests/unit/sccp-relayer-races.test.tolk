// SCCP v1 three-checkpoint measurement (specs/sccp.md §13 item 6).
// Deterministic message ordering, not a destination latency guarantee: a real
// checkpoint-use message is queued before 0–4 higher, genuinely signed
// checkpoints overtake it. No checkpoint or committee state is seeded.
// Separate tests reset the emulator so every row starts with the same custody.

import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/big_array"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-bls"
import "sccp-test-helpers"

/// The exact checkpoint-reference message retained before overtaking traffic.
fun raceMessage(env: Env, relayer: address, d: Delivery, value: coins): OutMessage {
    return createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value,
        dest: env.minter.address,
        body: SccpFinalizeCheckpoint {
            queryId: 77,
            response: relayer,
            ref: d.x.ref() as Cell<CheckpointRef>,
            message: d.proof as Cell<MessageProof>,
        },
    });
}

/// Actual trace totals and returned value; retained value also includes funded
/// contract reserves and is deliberately not labelled a transaction fee.
fun raceMeasure(
    stage: string,
    n: int,
    overtakes: int,
    res: SendResultList,
    value: coins,
    relayer: address,
    bounced: bool,
): int {
    var traceGas = 0;
    var fees = 0;
    var i = 0;
    repeat (res.size()) {
        traceGas += res.at(i).gasUsed;
        fees += res.at(i).tx.load().totalFees.grams;
        i += 1;
    }
    val returned = bounced
        ? res.findTransaction({ to: relayer, bounced: true })!
        : res.findTransaction<ReturnExcessesBack>({ to: relayer })!;
    val info = returned.loadInMsg<RemainingBitsAndRefs>().info;
    expect(info is TlbInternalMessage).toBeTrue();
    if (info is TlbInternalMessage) {
        expect(info.value.grams > 0).toBeTrue();
        expect(info.value.grams < value).toBeTrue();
        println("relayer-race stage={} n={} overtakes={}", stage, n, overtakes);
        println("  gas minter={} trace={} txs={}", stepGas(res), traceGas, res.size());
        println("  nanoton fees={} attached={} returned={}", fees, value, info.value.grams);
    }
    expect(stepGas(res) <= SCCP_GAS_MINTER_FINALIZE).toBeTrue();
    return fees;
}

/// A refusal must preserve the full minter data and create no child custody.
fun raceRefused(env: Env, res: SendResultList, exitCode: int, before: int) {
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    val state = env.minter.getSccpState();
    expect(state.pendingSupply).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(state.deployedBuckets).toEqual(0);
    expect(minterStorage(env).recovery.load().count).toEqual(0);
}

/// Exactly one completed transfer, with all transient custody released.
fun raceMinted(env: Env, recipient: address, amount: int) {
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(amount);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    expect(jettonBalanceOf(env, recipient)).toEqual(amount);
    expect(isConsumedAt(env, 0)).toBeTrue();
    expect(minterStorage(env).recovery.load().count).toEqual(0);
}

/// Measures the exact 2/3-overtake boundary for one current-generation message.
fun measureRelayerRace(n: int, overtakes: int) {
    val env = setupEnvWith(n, TEST_MAX_SUPPLY);
    val relayer = testing.treasury("delayed-relayer").address;
    val competing = testing.treasury("checkpoint-relayer").address;
    val recipient = testing.treasury("race-recipient").address;
    val d = deliverDefault(env, 0, 40, recipient);
    expectOutcome(sendCheckpoint(env, competing, d.cert, null, grams("1")), 0);
    val value = finalizeValue(env, 0);
    val original = raceMessage(env, relayer, d, value);
    val originalHash = original.messageCell.hash();
    val delayed = testing.createTraceIterationCursor(relayer, original);
    var i = 1;
    repeat (overtakes) {
        val x = emptyX(env.networkId, env.generation, env.committee.root(), d.x.height + i);
        val cert = certifyFor(env, env.committee, x);
        val sent = sendCheckpoint(env, competing, cert, null, grams("1"));
        expectOutcome(sent, 0);
        expectEvents(
            sent,
            [eventCertificate(x.height, env.generation, cert), eventCheckpointed(x.height, x.id())],
        );
        i += 1;
    }
    expect(original.messageCell.hash()).toEqual(originalHash);
    val slots = env.minter.getSccpCheckpoints();
    expect(slots.count).toEqual(min(overtakes + 1, 3));
    expect(slots.height0).toEqual(d.x.height + max(overtakes - 2, 0));
    val before = minterStorage(env).toCell().hash();
    val attempt = delayed.executeAllRemaining();
    delayed.close();
    var retries = 0;
    var totalFees = 0;
    if (overtakes < 3) {
        expect(attempt).toHaveAllSuccessfulTxs();
        expectEvents(attempt, [replayEventFinalized(d.messageId, 0)]);
        totalFees = raceMeasure(
            "hit",
            n,
            overtakes,
            attempt,
            value,
            relayer,
            false,
        );
    } else {
        raceRefused(env, attempt, SccpErrors.UnknownCheckpoint, before);
        expect(attempt).toHaveBouncedTx<SccpFinalizeCheckpoint>({ to: relayer });
        totalFees = raceMeasure(
            "evicted",
            n,
            overtakes,
            attempt,
            value,
            relayer,
            true,
        );
        val recovered = sendFinalize(env, relayer, d, value);
        expect(recovered).toHaveAllSuccessfulTxs();
        expectEvents(
            recovered,
            [
                eventCertificate(d.x.height, env.generation, d.cert),
                replayEventFinalized(d.messageId, 0),
            ],
        );
        expect(env.minter.getSccpCheckpoints().height0).toEqual(d.x.height + overtakes - 2);
        totalFees += raceMeasure(
            "inline",
            n,
            overtakes,
            recovered,
            value,
            relayer,
            false,
        );
        retries = 1;
    }
    raceMinted(env, recipient, 40);
    // A competing replay after recovery must not mint or emit Finalized again.
    val duplicate = sendFinalize(env, competing, d, finalizeValue(env, 0));
    expect(duplicate).toHaveAllSuccessfulTxs();
    expect(
        duplicate.findExternalOutMessage<SccpFinalizedEvent>({ from: env.minter.address }),
    ).toBeNull();
    raceMinted(env, recipient, 40);
    println(
        "relayer-race summary n={} overtakes={} recovery_submissions={} flow_fees_nanoton={}",
        n,
        overtakes,
        retries,
        totalFees,
    );
}

get fun `test relayer race n4 zero overtakes`() {
    measureRelayerRace(4, 0);
}

get fun `test relayer race n4 one overtake`() {
    measureRelayerRace(4, 1);
}

get fun `test relayer race n4 two overtakes`() {
    measureRelayerRace(4, 2);
}

get fun `test relayer race n4 three overtakes`() {
    measureRelayerRace(4, 3);
}

get fun `test relayer race n4 four overtakes`() {
    measureRelayerRace(4, 4);
}

get fun `test relayer race n7 zero overtakes`() {
    measureRelayerRace(7, 0);
}

get fun `test relayer race n7 one overtake`() {
    measureRelayerRace(7, 1);
}

get fun `test relayer race n7 two overtakes`() {
    measureRelayerRace(7, 2);
}

get fun `test relayer race n7 three overtakes`() {
    measureRelayerRace(7, 3);
}

get fun `test relayer race n7 four overtakes`() {
    measureRelayerRace(7, 4);
}

get fun `test relayer race n31 zero overtakes`() {
    measureRelayerRace(31, 0);
}

get fun `test relayer race n31 one overtake`() {
    measureRelayerRace(31, 1);
}

get fun `test relayer race n31 two overtakes`() {
    measureRelayerRace(31, 2);
}

get fun `test relayer race n31 three overtakes`() {
    measureRelayerRace(31, 3);
}

get fun `test relayer race n31 four overtakes`() {
    measureRelayerRace(31, 4);
}

get fun `test retired generation eviction requires current signed history recovery`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    val relayer = testing.treasury("retired-relayer").address;
    val recipient = testing.treasury("history-recipient").address;
    val d = deliverDefault(env, 0, 40, recipient);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    val value = finalizeValue(env, 0);
    val original = raceMessage(env, relayer, d, value);
    val originalHash = original.messageCell.hash();
    val delayed = testing.createTraceIterationCursor(relayer, original);
    val next = testCommittee(31, 4);
    rotateTo(env, next, d.x.height + 1);
    var i = 2;
    repeat (2) {
        val x = emptyX(env.networkId, env.generation + 1, next.root(), d.x.height + i);
        expectOutcome(checkpointBy(env, next, x, null), 0);
        i += 1;
    }
    expect(original.messageCell.hash()).toEqual(originalHash);
    expect(env.minter.getSccpCheckpoints().height0).toEqual(d.x.height + 1);
    val before = minterStorage(env).toCell().hash();
    val attempt = delayed.executeAllRemaining();
    delayed.close();
    raceRefused(env, attempt, SccpErrors.UnknownCheckpoint, before);
    var fees = raceMeasure(
        "retired-evicted",
        31,
        3,
        attempt,
        value,
        relayer,
        true,
    );
    val oldInline = sendFinalize(env, relayer, d, value);
    raceRefused(env, oldInline, SccpErrors.CommitteeNotAccepted, before);
    fees += raceMeasure(
        "retired-inline-refused",
        31,
        3,
        oldInline,
        value,
        relayer,
        true,
    );

    // The original payload/leaf is now authenticated through a newer header's
    // history, genuinely certified by the installed successor committee.
    val history = historyLeaves(7, 3, d.x.height, d.x.sccpRoot, d.x.messageCount);
    var current = emptyX(env.networkId, env.generation + 1, next.root(), d.x.height + 4);
    current.historySize = history.size();
    current.historyRoot = treeRoot(history);
    val leaves = leavesWith(inboundLeaf(env.networkId, d.payload, env.minter.address), 1, 3);
    val proof = messageProofCell(
        1,
        treePath(leaves, 1),
        d.payload,
        blockRefCell(d.x.height, d.x.sccpRoot, d.x.messageCount, 3, treePath(history, 3)),
    );
    val cert = certifyFor(env, next, current);
    val recovered = sendFinalizeCells(
        env,
        relayer,
        cert,
        null,
        proof,
        value,
    );
    expect(recovered).toHaveAllSuccessfulTxs();
    expectEvents(
        recovered,
        [
            eventCertificate(current.height, env.generation + 1, cert),
            eventCheckpointed(current.height, current.id()),
            replayEventFinalized(d.messageId, 0),
        ],
    );
    fees += raceMeasure(
        "current-history",
        31,
        3,
        recovered,
        value,
        relayer,
        false,
    );
    raceMinted(env, recipient, 40);
    val duplicate = sendFinalizeCells(
        env,
        env.deployer,
        cert,
        null,
        proof,
        finalizeValue(env, 0),
    );
    expect(duplicate).toHaveAllSuccessfulTxs();
    expectEvents(duplicate, []);
    raceMinted(env, recipient, 40);
    println(
        "relayer-race retired-summary n=31 overtakes=3 refused_old_inline=1 history_recovery_submissions=1 measured_flow_fees_nanoton={}",
        fees,
    );
}
