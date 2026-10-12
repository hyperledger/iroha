// The committee state machine of the SCCP v1 TON minter through
// `sccp_checkpoint` and the certified headers its other entry points obtain
// (specs/sccp.md §5.1.2, §5.1.3, §5.3.3, §5.3.4 item 6, §11.1).
//
// - Every TON scenario of `committee_transitions_v1.json`, and every EVM
//   scenario it marks `ton_replayable`, is replayed step by step on the minter
//   at `0:35…35`: the exit code, the external-out events in order and the
//   state after each step. Each replay pins its number of steps.
// - The required rows of §11.1 that the fixtures give for the EVM flavour
//   only are built here with certificates signed in the test VM: an expired
//   successor, sixteen rotations, K→K′→K, future-dated certificates, forged
//   heights and the V3 latch, retired generations, V1 and V2, the handoff
//   used inline first, expiry, and `LatchRequired` on inline conflicts.
// - The rules that only TON has: the three checkpoint slots, `next_keys`, the
//   cell shapes of a certificate and of a checkpoint reference, and the use
//   of a stored checkpoint after a rotation (U1, U2).
// - The exit codes of the contracts are the shared table of the fixture
//   (§5.2.2), which the generated replays compare by number.

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
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-cert-vectors.gen"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Destination clock at which every test of this suite starts, in ms.
const NOW_MS = 1800000000000
/// `cur.untilMs` of the default pin: 14 days after `NOW_MS`.
const PIN_UNTIL_MS = 1801209600000
/// Scenario rows of `committee_transitions_v1.json` this suite replays: the
/// TON scenarios, the EVM scenarios marked `ton_replayable`, and their steps.
const PINNED_TON_SCENARIOS = 8
const PINNED_TON_SCENARIO_STEPS = 51
const PINNED_REPLAYABLE_SCENARIOS = 12
const PINNED_REPLAYABLE_SCENARIO_STEPS = 24
/// Header rows of `finality_v1.json`.
const PINNED_VALID_HEADERS = 8
const PINNED_INVALID_HEADERS = 33

// ---------------------------------------------------------------------------
// Fixture scenarios.

/// Runs one generated scenario replay and expects it to have compared the
/// state after its deployment and after each of its `steps` steps.
fun expectScenario(replay: () -> void, steps: int) {
    val before = replayedStates();
    replay();
    expect(replayedStates() - before).toEqual(steps + 1);
}

/// Steps of each TON scenario, in the order of the fixture.
const STEPS_TON_ROTATION_NEXT_KEYS = 4
const STEPS_TON_CHECKPOINT_EVICTION = 9
const STEPS_TON_CHEAP_PATH_IDENTITY_SIGNATURE = 4
const STEPS_TON_CHECKPOINT_USE_AFTER_ROTATION = 9
const STEPS_TON_VOID_FROZEN_RANGE_BEFORE_FROZEN = 5
const STEPS_TON_FINALIZE_TWO_FAULTS = 5
const STEPS_TON_SAME_HEIGHT_BLOCK_REF_WITH_HISTORY = 9
const STEPS_TON_INLINE_CALLS_AFTER_EXPIRY = 6
/// Steps of each EVM scenario marked `ton_replayable`, in the order of the fixture.
const STEPS_INITIAL_PIN = 1
const STEPS_CHECKPOINT_RAISES_HIGH = 3
const STEPS_ROTATION_KEY_CHANGE = 2
const STEPS_HEARTBEAT_ROTATION = 1
const STEPS_ROTATION_LOWERED_VALIDITY = 3
const STEPS_V1_NEIGHBOUR_SAME_X_OTHER_RESULT_BODY = 2
const STEPS_V2_BELOW_START = 1
const STEPS_V2_NEIGHBOUR_AT_START = 1
const STEPS_V3_ROTATION_BELOW_HIGH = 2
const STEPS_FUTURE_DATED_ROTATION_T_EFF = 1
const STEPS_ROTATION_SUB_SECOND_DEADLINE = 3
const STEPS_CHEAP_PATH_IDENTITY_SIGNATURE = 4

get fun `test scenario ton_rotation_next_keys`() {
    expectScenario(vecScenarioTonRotationNextKeys, STEPS_TON_ROTATION_NEXT_KEYS);
}

get fun `test scenario ton_checkpoint_eviction`() {
    expectScenario(vecScenarioTonCheckpointEviction, STEPS_TON_CHECKPOINT_EVICTION);
}

get fun `test scenario ton_cheap_path_identity_signature`() {
    expectScenario(
        vecScenarioTonCheapPathIdentitySignature,
        STEPS_TON_CHEAP_PATH_IDENTITY_SIGNATURE,
    );
}

get fun `test scenario ton_checkpoint_use_after_rotation`() {
    expectScenario(
        vecScenarioTonCheckpointUseAfterRotation,
        STEPS_TON_CHECKPOINT_USE_AFTER_ROTATION,
    );
}

get fun `test scenario ton_void_frozen_range_before_frozen`() {
    expectScenario(
        vecScenarioTonVoidFrozenRangeBeforeFrozen,
        STEPS_TON_VOID_FROZEN_RANGE_BEFORE_FROZEN,
    );
}

get fun `test scenario ton_finalize_two_faults`() {
    expectScenario(vecScenarioTonFinalizeTwoFaults, STEPS_TON_FINALIZE_TWO_FAULTS);
}

get fun `test scenario ton_same_height_block_ref_with_history`() {
    expectScenario(
        vecScenarioTonSameHeightBlockRefWithHistory,
        STEPS_TON_SAME_HEIGHT_BLOCK_REF_WITH_HISTORY,
    );
}

get fun `test scenario ton_inline_calls_after_expiry`() {
    expectScenario(vecScenarioTonInlineCallsAfterExpiry, STEPS_TON_INLINE_CALLS_AFTER_EXPIRY);
}

get fun `test scenario initial_pin`() {
    expectScenario(vecScenarioInitialPin, STEPS_INITIAL_PIN);
}

get fun `test scenario checkpoint_raises_high`() {
    expectScenario(vecScenarioCheckpointRaisesHigh, STEPS_CHECKPOINT_RAISES_HIGH);
}

get fun `test scenario rotation_key_change`() {
    expectScenario(vecScenarioRotationKeyChange, STEPS_ROTATION_KEY_CHANGE);
}

get fun `test scenario heartbeat_rotation`() {
    expectScenario(vecScenarioHeartbeatRotation, STEPS_HEARTBEAT_ROTATION);
}

get fun `test scenario rotation_lowered_validity`() {
    expectScenario(vecScenarioRotationLoweredValidity, STEPS_ROTATION_LOWERED_VALIDITY);
}

get fun `test scenario v1_neighbour_same_x_other_result_body`() {
    expectScenario(
        vecScenarioV1NeighbourSameXOtherResultBody,
        STEPS_V1_NEIGHBOUR_SAME_X_OTHER_RESULT_BODY,
    );
}

get fun `test scenario v2_below_start`() {
    expectScenario(vecScenarioV2BelowStart, STEPS_V2_BELOW_START);
}

get fun `test scenario v2_neighbour_at_start`() {
    expectScenario(vecScenarioV2NeighbourAtStart, STEPS_V2_NEIGHBOUR_AT_START);
}

get fun `test scenario v3_rotation_below_high`() {
    expectScenario(vecScenarioV3RotationBelowHigh, STEPS_V3_ROTATION_BELOW_HIGH);
}

get fun `test scenario future_dated_rotation_t_eff`() {
    expectScenario(vecScenarioFutureDatedRotationTEff, STEPS_FUTURE_DATED_ROTATION_T_EFF);
}

get fun `test scenario rotation_sub_second_deadline`() {
    expectScenario(vecScenarioRotationSubSecondDeadline, STEPS_ROTATION_SUB_SECOND_DEADLINE);
}

get fun `test scenario cheap_path_identity_signature`() {
    expectScenario(vecScenarioCheapPathIdentitySignature, STEPS_CHEAP_PATH_IDENTITY_SIGNATURE);
}

get fun `test the scenario replays cover the pinned rows of the fixture`() {
    // The tests above run one generated replay each, and a replay runs every
    // step of its fixture row. A scenario that leaves the fixture no longer
    // compiles, and one that loses a step fails its own test.
    val tonSteps: array<int> = [
        STEPS_TON_ROTATION_NEXT_KEYS,
        STEPS_TON_CHECKPOINT_EVICTION,
        STEPS_TON_CHEAP_PATH_IDENTITY_SIGNATURE,
        STEPS_TON_CHECKPOINT_USE_AFTER_ROTATION,
        STEPS_TON_VOID_FROZEN_RANGE_BEFORE_FROZEN,
        STEPS_TON_FINALIZE_TWO_FAULTS,
        STEPS_TON_SAME_HEIGHT_BLOCK_REF_WITH_HISTORY,
        STEPS_TON_INLINE_CALLS_AFTER_EXPIRY,
    ];
    val replayableSteps: array<int> = [
        STEPS_INITIAL_PIN,
        STEPS_CHECKPOINT_RAISES_HIGH,
        STEPS_ROTATION_KEY_CHANGE,
        STEPS_HEARTBEAT_ROTATION,
        STEPS_ROTATION_LOWERED_VALIDITY,
        STEPS_V1_NEIGHBOUR_SAME_X_OTHER_RESULT_BODY,
        STEPS_V2_BELOW_START,
        STEPS_V2_NEIGHBOUR_AT_START,
        STEPS_V3_ROTATION_BELOW_HIGH,
        STEPS_FUTURE_DATED_ROTATION_T_EFF,
        STEPS_ROTATION_SUB_SECOND_DEADLINE,
        STEPS_CHEAP_PATH_IDENTITY_SIGNATURE,
    ];
    expect(tonSteps.size()).toEqual(PINNED_TON_SCENARIOS);
    expect(replayableSteps.size()).toEqual(PINNED_REPLAYABLE_SCENARIOS);
    var total = 0;
    var i = 0;
    repeat (tonSteps.size()) {
        total += tonSteps.get(i);
        i += 1;
    }
    expect(total).toEqual(PINNED_TON_SCENARIO_STEPS);
    total = 0;
    i = 0;
    repeat (replayableSteps.size()) {
        total += replayableSteps.get(i);
        i += 1;
    }
    expect(total).toEqual(PINNED_REPLAYABLE_SCENARIO_STEPS);
}

// ---------------------------------------------------------------------------
// Builders of this suite.

/// Expects the committee state of the minter at the current clock, with no
/// control applied and no operation counted.
fun expectCommittee(
    env: Env,
    generation: int,
    root: int,
    start: int,
    high: int,
    untilMs: int,
    equivocated: bool,
) {
    val nowMs = testing.getNow() * 1000;
    replayExpectState(
        env,
        nowMs,
        generation,
        root,
        start,
        high,
        untilMs,
        equivocated,
        !equivocated & (nowMs <= untilMs),
        0,
        false,
        0,
        false,
        0,
    );
}

/// Expects a refused call: its exit code, no event, and the committee state
/// of the default deployment unchanged.
fun expectRefusedUnchanged(env: Env, res: SendResultList, exitCode: int) {
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    expectCommittee(
        env,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT,
        TEST_START_HEIGHT - 1,
        PIN_UNTIL_MS,
        false,
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
    replayExpectKeys(env, env.committee.keys);
}

/// The handoff header of generation `generation` of `current` at `height`
/// that names `next`, dated one second ago and valid for 14 days.
fun handoffX(
    env: Env,
    current: TestCommittee,
    generation: int,
    next: TestCommittee,
    height: int,
): TestX {
    return rotationX(
        env.networkId,
        generation,
        current.root(),
        height,
        testing.getNow() * 1000 - 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
}

/// `header` as the header of a block whose only leaf is `leaf`, with a
/// history of that block alone.
fun withLeaf(header: TestX, leaf: int): TestX {
    var x = header;
    x.messageCount = 1;
    x.sccpRoot = leaf;
    x.historySize = 1;
    x.historyRoot = sccpHistoryLeaf(x.height, leaf, 1);
    return x;
}

/// A genuine control of `env.minter` as the only leaf of the block of
/// `header`, certified by `committee`.
fun controlIn(
    env: Env,
    committee: TestCommittee,
    header: TestX,
    control: TestControl,
): ControlDelivery {
    val x = withLeaf(header, controlLeafOf(env, control));
    return {
        x,
        cert: certifyFor(env, committee, x),
        proof: controlProofCell(
            control.nonce,
            control.track,
            control.parliamentPaused,
            control.fastPauseUntilMs,
            control.certificateId,
            control.effectHash,
            0,
            [],
            ownBlockRef(x),
        ),
    };
}

/// A genuine transfer to `recipient` as the only leaf of the block of
/// `header`, certified by `committee`, with its deadline one day ahead.
fun deliveryIn(
    env: Env,
    committee: TestCommittee,
    header: TestX,
    nonce: int,
    recipient: address,
): Delivery {
    val payload = inboundPayloadCell(
        nonce,
        TEST_REVISION,
        NOW_MS + DAY_MS,
        1000,
        recipient.accountId(),
    );
    val x = withLeaf(header, inboundLeaf(env.networkId, payload, env.minter.address));
    return {
        payload,
        x,
        cert: certifyFor(env, committee, x),
        proof: messageProofCell(0, [], payload, ownBlockRef(x)),
        messageId: inboundMessageId(env.networkId, payload, env.minter.address),
    };
}

/// Sends `sccp_apply_control_checkpoint` from the deployer with the
/// `^CheckpointRef` `ref` and the `^ControlProof` `proof`.
fun controlStored(env: Env, ref: cell, proof: cell, value: coins): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        null,
        ref,
        proof,
        value,
    );
}

/// A well-formed compressed G2 point that signs nothing here and is not the
/// identity.
fun foreignSignature(): slice {
    return vecHashToG2(0).q;
}

/// The committee root of `keys` as they are listed, in any order and number.
fun rootOfListedKeys(keys: array<slice>): int {
    val n = keys.size();
    return sccpCommitteeRoot(n, sccpLoadKeys(sccpBuildKeys(keys), n).parts);
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

// ---------------------------------------------------------------------------
// Rotations (§5.1.2 updates).

get fun `test a rotation whose successor is already expired is applied and freezes the minter`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val height = TEST_START_HEIGHT + 50;
    // certified ten days ago with three days of validity
    val timestampMs = NOW_MS - 10 * DAY_MS;
    val untilMs = timestampMs + 3 * DAY_MS;
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        height,
        timestampMs,
        next.root(),
        3 * DAY_MS,
    );
    val cert = certifyFor(env, env.committee, x);
    val res = sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1"));
    // the rotation is applied, the state persists and nothing reverts
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(height, env.generation, cert),
            eventCheckpointed(height, x.id()),
            eventRotated(env.generation + 1, next.root(), untilMs, height + 1),
        ],
    );
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expectCommittee(
        env,
        env.generation + 1,
        next.root(),
        height + 1,
        height,
        untilMs,
        false,
    );
    replayExpectKeys(env, next.keys);
    replayExpectCheckpoints(
        env,
        1,
        height,
        x.id(),
        0,
        0,
        0,
        0,
    );
    val state = env.minter.getSccpState();
    expect(sccpIsLive(state.equivocated, state.untilMs, NOW_MS)).toBeFalse();

    // Frozen by expiry, without a latch: neither generation is accepted
    val successor = emptyX(env.networkId, env.generation + 1, next.root(), height + 5);
    val late = checkpointBy(env, next, successor, null);
    expectOutcome(late, SccpErrors.CommitteeNotAccepted);
    expectEvents(late, []);
    val old = emptyX(env.networkId, env.generation, env.committee.root(), height + 5);
    expectOutcome(checkpointBy(env, env.committee, old, null), SccpErrors.CommitteeNotAccepted);
    expectCommittee(
        env,
        env.generation + 1,
        next.root(),
        height + 1,
        height,
        untilMs,
        false,
    );

    // voids drain it
    val voided = sendVoidFrozen(env, 0, 3, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveSuccessfulTx<SccpVoidFrozen>({ to: env.minter.address });
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    expect(isConsumedAt(env, 2)).toBeTrue();
}

get fun `test sixteen rotations apply one per message`() {
    val env = setupEnv();
    val a = env.committee;
    val b = testCommittee(4, 4);
    var generation = env.generation;
    var height = TEST_START_HEIGHT + 10;
    var i = 0;
    repeat (16) {
        val fromA = (i & 1) == 0;
        val current = fromA ? a : b;
        val next = fromA ? b : a;
        val x = handoffX(env, current, generation, next, height);
        val cert = certifyFor(env, current, x);
        val res = sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1"));
        expectOutcome(res, 0);
        // one message installs exactly one successor
        expectEvents(
            res,
            [
                eventCertificate(height, generation, cert),
                eventCheckpointed(height, x.id()),
                eventRotated(
                    generation + 1,
                    next.root(),
                    NOW_MS - 1000 + TEST_VALIDITY_MS,
                    height + 1,
                ),
            ],
        );
        generation += 1;
        expect(env.minter.getSccpState().generation).toEqual(generation);
        height += 7;
        i += 1;
    }
    val last = height - 7;
    expectCommittee(
        env,
        env.generation + 16,
        a.root(),
        last + 1,
        last,
        NOW_MS - 1000 + TEST_VALIDITY_MS,
        false,
    );
    replayExpectKeys(env, a.keys);
    // the three slots hold the three latest handoffs
    val slots = env.minter.getSccpCheckpoints();
    expect(slots.count).toEqual(SCCP_CHECKPOINT_SLOTS);
    expect(slots.height0).toEqual(last - 14);
    expect(slots.height1).toEqual(last - 7);
    expect(slots.height2).toEqual(last);
    expect(
        slots.id2,
    ).toEqual(
        rotationX(
            env.networkId,
            generation - 1,
            b.root(),
            last,
            NOW_MS - 1000,
            a.root(),
            TEST_VALIDITY_MS,
        ).id(),
    );
}

get fun `test K to K' to K: a certificate of the first generation is refused under its own root`() {
    val env = setupEnv();
    val a = env.committee;
    val b = testCommittee(4, 4);
    rotateTo(env, b, TEST_START_HEIGHT + 10);
    rotateFrom(env, b, env.generation + 1, a, TEST_START_HEIGHT + 20);
    val until = NOW_MS + TEST_VALIDITY_MS;
    // generation 9 has the root of generation 7 again
    expectCommittee(
        env,
        env.generation + 2,
        a.root(),
        TEST_START_HEIGHT + 21,
        TEST_START_HEIGHT + 20,
        until,
        false,
    );
    replayExpectKeys(env, a.keys);
    // a genuine certificate of generation 7 names the same root and is refused
    val heights: array<int> = [TEST_START_HEIGHT + 5, TEST_START_HEIGHT + 25];
    var i = 0;
    repeat (heights.size()) {
        val old = emptyX(env.networkId, env.generation, a.root(), heights.get(i));
        val res = checkpointBy(env, a, old, null);
        expectOutcome(res, SccpErrors.CommitteeNotAccepted);
        expectEvents(res, []);
        // refused before any signature work
        expect(stepGas(res) < 58000).toBeTrue();
        i += 1;
    }
    expectCommittee(
        env,
        env.generation + 2,
        a.root(),
        TEST_START_HEIGHT + 21,
        TEST_START_HEIGHT + 20,
        until,
        false,
    );
    // the same keys certify generation 9
    val current = emptyX(env.networkId, env.generation + 2, a.root(), TEST_START_HEIGHT + 25);
    expectOutcome(checkpointBy(env, a, current, null), 0);
    expect(env.minter.getSccpState().high).toEqual(TEST_START_HEIGHT + 25);
}

get fun `test a future-dated certificate never extends trust`() {
    val env = setupEnv();
    var x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    // there is no skew check: a header dated 20 days ahead is accepted
    x.timestampMs = NOW_MS + 20 * DAY_MS;
    val cert = certifyFor(env, env.committee, x);
    val res = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [eventCertificate(x.height, env.generation, cert), eventCheckpointed(x.height, x.id())],
    );
    expectCommittee(
        env,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT,
        x.height,
        PIN_UNTIL_MS,
        false,
    );
    // replays change nothing, up to the deadline itself
    testing.setNow(T0 + 7 * 86400);
    expectOutcome(
        sendCheckpoint(env, env.deployer, cert, null, grams("1")),
        SccpErrors.NothingToDo,
    );
    testing.setNow(PIN_UNTIL_MS / 1000);
    expectOutcome(
        sendCheckpoint(env, env.deployer, cert, null, grams("1")),
        SccpErrors.NothingToDo,
    );
    expect(env.minter.getSccpState().untilMs).toEqual(PIN_UNTIL_MS);
    // one second later the generation has expired, whatever the header says
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectOutcome(
        sendCheckpoint(env, env.deployer, cert, null, grams("1")),
        SccpErrors.CommitteeNotAccepted,
    );
    expect(env.minter.getSccpState().untilMs).toEqual(PIN_UNTIL_MS);
    val voided = sendVoidFrozen(env, 7, 1, env.minter.voidFrozenRequiredValue(7));
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
}

get fun `test a future-dated handoff grants its validity from the minter's clock and no replay extends it`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val height = TEST_START_HEIGHT + 5;
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        height,
        NOW_MS + 10 * DAY_MS,
        next.root(),
        5 * DAY_MS,
    );
    val cert = certifyFor(env, env.committee, x);
    expectOutcome(sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1")), 0);
    // t_eff = min(X.timestamp_ms, now_ms)
    val until = NOW_MS + 5 * DAY_MS;
    expectCommittee(
        env,
        env.generation + 1,
        next.root(),
        height + 1,
        height,
        until,
        false,
    );
    // replayed inside and after the granted validity: no longer CUR
    testing.setNow(T0 + 4 * 86400);
    val replay = sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1"));
    expectOutcome(replay, SccpErrors.CommitteeNotAccepted);
    expectEvents(replay, []);
    expectCommittee(
        env,
        env.generation + 1,
        next.root(),
        height + 1,
        height,
        until,
        false,
    );
    testing.setNow(T0 + 5 * 86400 + 1);
    expectOutcome(
        sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1")),
        SccpErrors.CommitteeNotAccepted,
    );
    expect(env.minter.getSccpState().untilMs).toEqual(until);
}

get fun `test forged heights above the genuine end are accepted and the genuine handoff latches through V3`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val root = env.committee.root();
    // a departed quorum of generation 7 signs heights above its genuine end
    val forged1 = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 500);
    val forged2 = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 600);
    expectOutcome(checkpointBy(env, env.committee, forged1, null), 0);
    expectOutcome(checkpointBy(env, env.committee, forged2, null), 0);
    expectCommittee(
        env,
        env.generation,
        root,
        TEST_START_HEIGHT,
        TEST_START_HEIGHT + 600,
        PIN_UNTIL_MS,
        false,
    );
    // the genuine handoff is below `high`
    val handoff = handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 100);
    val cert = certifyFor(env, env.committee, handoff);
    val before = testing.getAccountBalance(env.minter.address);
    val res = sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1"));
    // the latch is an outcome: nothing is thrown and the excess returns
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(handoff.height, env.generation, cert),
            eventLatched(SCCP_LATCH_V3, env.generation, handoff.height, root, handoff.id()),
        ],
    );
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();
    expect(testing.getAccountBalance(env.minter.address) >= before).toBeTrue();
    // equivocated, untilMs zeroed; no successor, and the handoff is not recorded
    expectCommittee(
        env,
        env.generation,
        root,
        TEST_START_HEIGHT,
        TEST_START_HEIGHT + 600,
        0,
        true,
    );
    replayExpectKeys(env, env.committee.keys);
    replayExpectCheckpoints(
        env,
        2,
        forged1.height,
        forged1.id(),
        forged2.height,
        forged2.id(),
        0,
        0,
    );
    reportGas("checkpoint latch n=4", stepGas(res), SCCP_GAS_MINTER_CHECKPOINT);

    // the latch opens the frozen void and closes the checkpoint entry
    val voided = sendVoidFrozen(env, 0, 2, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    val another = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 700);
    val refused = checkpointBy(env, env.committee, another, null);
    expectOutcome(refused, SccpErrors.Equivocated);
    expectEvents(refused, []);
    // the latch never clears, also after the pinned deadline
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectOutcome(checkpointBy(env, env.committee, another, null), SccpErrors.Equivocated);
}

get fun `test certificates of retired generations are refused without effect`() {
    val env = setupEnv();
    val a = env.committee;
    val b = testCommittee(4, 4);
    val c = testCommittee(4, 8);
    rotateTo(env, b, TEST_START_HEIGHT + 10);
    rotateFrom(env, b, env.generation + 1, c, TEST_START_HEIGHT + 20);
    val g = env.generation;
    val until = NOW_MS + TEST_VALIDITY_MS;
    // genuine and forged certificates of generations 7 and 8, at any height,
    // handoffs or not
    val old: array<cell> = [
        certifyFor(env, a, emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT + 5)),
        certifyFor(env, a, handoffX(env, a, g, c, TEST_START_HEIGHT + 15)),
        certifyFor(env, a, emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT + 900)),
        certifyFor(env, b, emptyX(env.networkId, g + 1, b.root(), TEST_START_HEIGHT + 15)),
        certifyFor(env, b, handoffX(env, b, g + 1, a, TEST_START_HEIGHT + 30)),
        // the installed handoff of generation 8 itself
        certifyFor(env, b, handoffX(env, b, g + 1, c, TEST_START_HEIGHT + 20)),
        // generation 9 under the root of generation 8, and the reverse
        certifyFor(env, b, emptyX(env.networkId, g + 2, b.root(), TEST_START_HEIGHT + 25)),
        certifyFor(env, c, emptyX(env.networkId, g + 1, c.root(), TEST_START_HEIGHT + 25)),
        // a generation that does not exist yet
        certifyFor(env, c, emptyX(env.networkId, g + 3, c.root(), TEST_START_HEIGHT + 25)),
    ];
    var i = 0;
    repeat (old.size()) {
        val res = sendCheckpoint(env, env.deployer, old.get(i), a.keysCell(), grams("1"));
        expectOutcome(res, SccpErrors.CommitteeNotAccepted);
        expectEvents(res, []);
        expect(stepGas(res) < 58000).toBeTrue();
        i += 1;
    }
    // nothing was recorded, raised, rotated or latched
    expectCommittee(
        env,
        g + 2,
        c.root(),
        TEST_START_HEIGHT + 21,
        TEST_START_HEIGHT + 20,
        until,
        false,
    );
    replayExpectKeys(env, c.keys);
    expect(env.minter.getSccpCheckpoints().count).toEqual(2);
}

// ---------------------------------------------------------------------------
// Latches (§5.1.2 V1–V3, §5.3.4 item 6).

get fun `test V1 two different headers at one height latch with both ids`() {
    val env = setupEnv();
    val root = env.committee.root();
    val x = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    expectOutcome(checkpointBy(env, env.committee, x, null), 0);
    // another X at the recorded height, signed by the current generation
    var y = x;
    y.timestampMs = x.timestampMs + 1;
    expect(y.id() != x.id()).toBeTrue();
    val cert = certifyFor(env, env.committee, y);
    val res = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(y.height, env.generation, cert),
            eventLatched(SCCP_LATCH_V1, env.generation, y.height, x.id(), y.id()),
        ],
    );
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expectCommittee(
        env,
        env.generation,
        root,
        TEST_START_HEIGHT,
        x.height,
        0,
        true,
    );
    // the stored checkpoint is the first one
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
}

get fun `test V2 a certificate below the start of its generation latches`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    rotateTo(env, next, TEST_START_HEIGHT + 10);
    val g = env.generation + 1;
    // at the start it is accepted
    val atStart = emptyX(env.networkId, g, next.root(), TEST_START_HEIGHT + 11);
    expectOutcome(checkpointBy(env, next, atStart, null), 0);
    // below it, at a height that holds no checkpoint: V2
    val below = emptyX(env.networkId, g, next.root(), TEST_START_HEIGHT + 9);
    val cert = certifyFor(env, next, below);
    val res = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(below.height, g, cert),
            eventLatched(SCCP_LATCH_V2, g, below.height, next.root(), below.id()),
        ],
    );
    val state = env.minter.getSccpState();
    expect(state.equivocated).toBeTrue();
    expect(state.untilMs).toEqual(0);
    expect(state.generation).toEqual(g);
    expect(state.high).toEqual(TEST_START_HEIGHT + 11);
}

get fun `test V1 is reported before V2 at the height of the installing handoff`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val handoff = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 10,
        NOW_MS,
        next.root(),
        TEST_VALIDITY_MS,
    );
    rotateTo(env, next, TEST_START_HEIGHT + 10);
    replayExpectCheckpoints(
        env,
        1,
        handoff.height,
        handoff.id(),
        0,
        0,
        0,
        0,
    );
    // the successor signs the handoff height: a stored id differs (V1) and
    // the height is below its start (V2)
    val g = env.generation + 1;
    val conflicting = emptyX(env.networkId, g, next.root(), TEST_START_HEIGHT + 10);
    val cert = certifyFor(env, next, conflicting);
    val res = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(conflicting.height, g, cert),
            eventLatched(SCCP_LATCH_V1, g, conflicting.height, handoff.id(), conflicting.id()),
        ],
    );
}

get fun `test a handoff used inline first installs through the cheap path`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val root = env.committee.root();
    val control = parliamentControl(1, true);
    val c = controlIn(
        env,
        env.committee,
        handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 40),
        control,
    );
    // an inline entry point records the handoff and raises `high`, and
    // installs no successor
    val res = sendApplyControl(env, c);
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(c.x.height, env.generation, c.cert),
            eventCheckpointed(c.x.height, c.x.id()),
            eventControlApplied(1, SCCP_TRACK_PARLIAMENT, true, 0, control.certificateId),
        ],
    );
    replayExpectState(
        env,
        NOW_MS,
        env.generation,
        root,
        TEST_START_HEIGHT,
        c.x.height,
        PIN_UNTIL_MS,
        false,
        true,
        1,
        true,
        0,
        true,
        1,
    );
    replayExpectKeys(env, env.committee.keys);
    replayExpectCheckpoints(
        env,
        1,
        c.x.height,
        c.x.id(),
        0,
        0,
        0,
        0,
    );

    // submitted: a ROTATION at height = high is no V3. X is stored, so the
    // signature is not checked again and nothing is published again.
    val unsigned = certOf(foreignSignature(), 7, defaultQc(c.x.height), c.x);
    val installed = sendCheckpoint(env, env.deployer, unsigned, next.keysCell(), grams("1"));
    expectOutcome(installed, 0);
    val until = NOW_MS - 1000 + TEST_VALIDITY_MS;
    expectEvents(
        installed,
        [eventRotated(env.generation + 1, next.root(), until, c.x.height + 1)],
    );
    expect(stepGas(installed) < 58000).toBeTrue();
    reportGas("checkpoint cheap path rotation n=4", stepGas(installed), SCCP_GAS_MINTER_CHECKPOINT);
    replayExpectState(
        env,
        NOW_MS,
        env.generation + 1,
        next.root(),
        c.x.height + 1,
        c.x.height,
        until,
        false,
        true,
        1,
        true,
        0,
        true,
        1,
    );
    replayExpectKeys(env, next.keys);
}

get fun `test a handoff stored inline latches through V3 without a second signature check`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val root = env.committee.root();
    val c = controlIn(
        env,
        env.committee,
        handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 40),
        parliamentControl(1, true),
    );
    expectOutcome(sendApplyControl(env, c), 0);
    // the generation then certifies a height above its handoff
    val above = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 45);
    expectOutcome(checkpointBy(env, env.committee, above, null), 0);
    // the stored handoff, under any signature, now trips V3
    val unsigned = certOf(foreignSignature(), 7, defaultQc(c.x.height), c.x);
    val res = sendCheckpoint(env, env.deployer, unsigned, next.keysCell(), grams("1"));
    expectOutcome(res, 0);
    // the cheap path publishes no certificate
    expectEvents(
        res,
        [eventLatched(SCCP_LATCH_V3, env.generation, c.x.height, root, c.x.id())],
    );
    expect(stepGas(res) < 58000).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.equivocated).toBeTrue();
    expect(state.untilMs).toEqual(0);
    expect(state.generation).toEqual(env.generation);
    // the applied control survives the latch
    expect(state.controlNonce).toEqual(1);
    expect(state.parliamentPaused).toBeTrue();
}

/// The three inline messages over one header `header` that trips a violation
/// on `env`: each must throw `LatchRequired` and change nothing. Returns the
/// certificate of the control, which `sccp_checkpoint` then latches on.
fun expectInlineLatchRequired(env: Env, committee: TestCommittee, header: TestX): ControlDelivery {
    val before = minterStorage(env).toCell().hash();
    val alice = testing.treasury("alice").address;
    val c = controlIn(env, committee, header, parliamentControl(1, true));
    val control = sendApplyControl(env, c);
    expectOutcome(control, SccpErrors.LatchRequired);
    expectEvents(control, []);
    val d = deliveryIn(env, committee, header, 0, alice);
    val finalize = sendFinalize(env, env.deployer, d, finalizeValue(env, 0));
    expectOutcome(finalize, SccpErrors.LatchRequired);
    expectEvents(finalize, []);
    val voided = sendVoidExpired(env, env.deployer, 0, d, env.minter.voidRequiredValue(0));
    expectOutcome(voided, SccpErrors.LatchRequired);
    expectEvents(voided, []);
    // nothing is latched, recorded or raised
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    expect(env.minter.getSccpState().equivocated).toBeFalse();
    return c;
}

get fun `test an inline certificate that meets V1 is LatchRequired and sccp_checkpoint then latches`() {
    val env = setupEnv();
    val root = env.committee.root();
    val stored = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    expectOutcome(checkpointBy(env, env.committee, stored, null), 0);
    // inline: another X at the stored height
    val c = expectInlineLatchRequired(env, env.committee, stored);
    expect(c.x.id() != stored.id()).toBeTrue();
    // the relayer resubmits the certificate through `sccp_checkpoint`
    val res = sendCheckpoint(env, env.deployer, c.cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(c.x.height, env.generation, c.cert),
            eventLatched(SCCP_LATCH_V1, env.generation, c.x.height, stored.id(), c.x.id()),
        ],
    );
    expect(env.minter.getSccpState().equivocated).toBeTrue();
}

get fun `test an inline certificate that meets V2 is LatchRequired and sccp_checkpoint then latches`() {
    val env = setupEnv();
    val root = env.committee.root();
    val below = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT - 1);
    val c = expectInlineLatchRequired(env, env.committee, below);
    val res = sendCheckpoint(env, env.deployer, c.cert, null, grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(c.x.height, env.generation, c.cert),
            eventLatched(SCCP_LATCH_V2, env.generation, c.x.height, root, c.x.id()),
        ],
    );
    expect(env.minter.getSccpState().equivocated).toBeTrue();
}

get fun `test an inline certificate that meets V3 is LatchRequired and sccp_checkpoint then latches`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val root = env.committee.root();
    val high = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 50);
    expectOutcome(checkpointBy(env, env.committee, high, null), 0);
    // inline: a handoff below `high`
    val handoff = handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 40);
    val c = expectInlineLatchRequired(env, env.committee, handoff);
    val res = sendCheckpoint(env, env.deployer, c.cert, next.keysCell(), grams("1"));
    expectOutcome(res, 0);
    expectEvents(
        res,
        [
            eventCertificate(c.x.height, env.generation, c.cert),
            eventLatched(SCCP_LATCH_V3, env.generation, c.x.height, root, c.x.id()),
        ],
    );
    val state = env.minter.getSccpState();
    expect(state.equivocated).toBeTrue();
    expect(state.generation).toEqual(env.generation);
}

// ---------------------------------------------------------------------------
// `Live` and its two answers (§5.1.2 "Check order and errors").

/// A transfer and a control of the pinned generation with their blocks.
struct LiveProbe {
    d: Delivery
    c: ControlDelivery
}

/// Stores the blocks of a transfer and of a control as checkpoints, so that
/// every `*_checkpoint` message has a stored header to name.
fun storeLiveProbe(env: Env): LiveProbe {
    val alice = testing.treasury("alice").address;
    val d = deliverAt(
        env,
        env.committee,
        env.generation,
        TEST_START_HEIGHT + 20,
        0,
        1000,
        alice,
        PIN_UNTIL_MS + 30 * DAY_MS,
        0,
        1,
    );
    val c = deliverControl(env, 1, true);
    expectOutcome(sendCheckpoint(env, env.deployer, d.cert, null, grams("1")), 0);
    expectOutcome(sendCheckpoint(env, env.deployer, c.cert, null, grams("1")), 0);
    return { d, c };
}

/// Sends every message that requires `Live` and expects `exitCode` from each,
/// with no event: `sccp_checkpoint` with a new and with a stored certificate,
/// and the inline and the checkpoint form of finalize, void and control. The
/// inline certificates are genuine and new, so the answer is the `Live`
/// check's own.
fun expectEveryLiveEntryPoint(env: Env, probe: LiveProbe, exitCode: int) {
    val alice = testing.treasury("alice").address;
    val root = env.committee.root();
    val fresh = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 300);
    var calls: array<SendResultList> = [];
    calls.push(checkpointBy(env, env.committee, fresh, null));
    val d = deliveryIn(
        env,
        env.committee,
        emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 301),
        1,
        alice,
    );
    calls.push(sendFinalize(env, env.deployer, d, grams("5")));
    calls.push(sendVoidExpired(env, env.deployer, 1, d, grams("5")));
    calls.push(
        sendApplyControl(
            env,
            controlIn(
                env,
                env.committee,
                emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 302),
                parliamentControl(2, false),
            ),
        ),
    );
    calls.push(sendFinalizeCheckpoint(env, env.deployer, probe.d, grams("5")));
    calls.push(sendVoidExpiredCheckpoint(env, env.deployer, 0, probe.d, grams("5")));
    calls.push(sendApplyControlCheckpoint(env, probe.c));
    var i = 0;
    repeat (calls.size()) {
        expectOutcome(calls.get(i), exitCode);
        expectEvents(calls.get(i), []);
        i += 1;
    }
    expect(i).toEqual(7);
    // an already stored certificate is refused as well
    expectOutcome(sendCheckpoint(env, env.deployer, probe.c.cert, null, grams("1")), exitCode);
    // `sccp_checkpoint` checks `Live` before its certificate, an inline entry
    // point after it: a certificate that does not verify answers for itself
    // inline, and for the minter through `sccp_checkpoint`
    val forged = certOf(foreignSignature(), 7, defaultQc(fresh.height), fresh);
    expectOutcome(sendCheckpoint(env, env.deployer, forged, null, grams("1")), exitCode);
    val inline = sendFinalizeCells(
        env,
        env.deployer,
        certOf(foreignSignature(), 7, defaultQc(d.x.height), d.x),
        null,
        d.proof,
        grams("5"),
    );
    expectOutcome(inline, SccpErrors.BadSignature);
    expectEvents(inline, []);
}

get fun `test the minter is Live at untilMs and answers CommitteeNotAccepted one second later`() {
    val env = setupEnv();
    val probe = storeLiveProbe(env);
    val root = env.committee.root();
    // at untilMs exactly the minter is still Live
    testing.setNow(PIN_UNTIL_MS / 1000);
    expectOutcome(
        sendVoidFrozen(env, 0, 1, env.minter.voidFrozenRequiredValue(0)),
        SccpErrors.NotFrozen,
    );
    val last = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 200);
    expectOutcome(checkpointBy(env, env.committee, last, null), 0);
    expect(env.minter.getSccpState().high).toEqual(TEST_START_HEIGHT + 200);

    // the next clock value is past it: expired, not latched
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    val before = minterStorage(env).toCell().hash();
    expectEveryLiveEntryPoint(env, probe, SccpErrors.CommitteeNotAccepted);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    val state = env.minter.getSccpState();
    expect(state.equivocated).toBeFalse();
    expect(state.untilMs).toEqual(PIN_UNTIL_MS);

    // the frozen void opens; a second void of the same nonces is rejected by the bucket
    val voided = sendVoidFrozen(env, 0, 2, env.minter.voidFrozenRequiredValue(0));
    expect(voided).toHaveSuccessfulTx<SccpRangeConsumed>({ to: env.minter.address });
    val again = sendVoidFrozen(env, 1, 1, env.minter.voidFrozenRequiredValue(1));
    expect(again).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
}

get fun `test a latched minter answers Equivocated at every Live check`() {
    val env = setupEnv();
    val probe = storeLiveProbe(env);
    val root = env.committee.root();
    val below = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    val before = minterStorage(env).toCell().hash();
    expectEveryLiveEntryPoint(env, probe, SccpErrors.Equivocated);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    // the latch answers before the expiry does
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectEveryLiveEntryPoint(env, probe, SccpErrors.Equivocated);
    // An inline certificate answers for itself first: another header at a
    // stored height is LatchRequired, also on a latched and expired minter.
    val conflicting = controlIn(env, env.committee, probe.d.x, parliamentControl(3, true));
    expect(conflicting.x.id() != probe.d.x.id()).toBeTrue();
    expectOutcome(sendApplyControl(env, conflicting), SccpErrors.LatchRequired);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
}

get fun `test checkpoints and rotations work while paused and are not counted`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    applyControlOk(env, 1, true);
    expect(env.minter.getSccpState().opCount).toEqual(1);
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 200);
    expectOutcome(checkpointBy(env, env.committee, x, null), 0);
    rotateTo(env, next, TEST_START_HEIGHT + 300);
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(env.generation + 1);
    // the pause state and the counter are untouched
    expect(state.opCount).toEqual(1);
    expect(state.controlNonce).toEqual(1);
    expect(state.parliamentPaused).toBeTrue();
    expect(state.effectivePaused).toBeTrue();
    expect(state.outboundNonce).toEqual(0);
}

// ---------------------------------------------------------------------------
// `next_keys` (§5.1.2 update 3, §5.3.3).

/// Sends the handoff of the pinned generation that names `nextRoot` with
/// `nextKeys`, at a height that grows with `attempt`.
fun sendHandoffNaming(env: Env, nextRoot: int, nextKeys: cell?, attempt: int): SendResultList {
    val x = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 10 + attempt,
        NOW_MS - 1000,
        nextRoot,
        TEST_VALIDITY_MS,
    );
    return checkpointBy(env, env.committee, x, nextKeys);
}

get fun `test next_keys of a key-changing rotation must be the committee of the announced root`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val other = testCommittee(4, 8);
    var attempt = 0;

    // missing, and the keys of another committee
    expectRefusedUnchanged(
        env,
        sendHandoffNaming(env, next.root(), null, attempt),
        SccpErrors.BadCommittee,
    );
    attempt += 1;
    expectRefusedUnchanged(
        env,
        sendHandoffNaming(env, next.root(), other.keysCell(), attempt),
        SccpErrors.BadCommittee,
    );
    attempt += 1;
    // the stored keys themselves
    expectRefusedUnchanged(
        env,
        sendHandoffNaming(env, next.root(), env.committee.keysCell(), attempt),
        SccpErrors.BadCommittee,
    );
    attempt += 1;

    // The announced root commits to a list that is no committee: keys out of
    // order, a key twice, and sizes that are not 3f + 1 or exceed 31.
    val swapped: array<slice> = [
        next.keys.get(1),
        next.keys.get(0),
        next.keys.get(2),
        next.keys.get(3),
    ];
    val twice: array<slice> = [
        next.keys.get(0),
        next.keys.get(1),
        next.keys.get(1),
        next.keys.get(3),
    ];
    val lists: array<array<slice>> = [
        swapped,
        twice,
        testCommittee(1, 4).keys,
        testCommittee(3, 4).keys,
        testCommittee(5, 4).keys,
        testCommittee(6, 4).keys,
        testCommittee(32, 0).keys,
        testCommittee(33, 0).keys,
        testCommittee(34, 0).keys,
    ];
    var i = 0;
    repeat (lists.size()) {
        val keys = lists.get(i);
        val res = sendHandoffNaming(env, rootOfListedKeys(keys), sccpBuildKeys(keys), attempt);
        expectRefusedUnchanged(env, res, SccpErrors.BadCommittee);
        // the certificate was verified first: the keys are read after V1–V3
        expect(stepGas(res) > 58000).toBeTrue();
        attempt += 1;
        i += 1;
    }
    expect(i).toEqual(9);

    // A list of more than 16 chunks holds more keys than any committee. It is
    // refused before its seventeenth chunk is loaded, so the walk is bounded:
    // 40 chunks cost what 17 cost.
    val all = testCommittee(35, 0).keys;
    var eighty: array<slice> = [];
    repeat (80) {
        eighty.push(all.get(eighty.size() % 35));
    }
    val seventeen = testCommittee(33, 0).keys;
    val short = sendHandoffNaming(
        env,
        rootOfListedKeys(seventeen),
        sccpBuildKeys(seventeen),
        attempt,
    );
    expectRefusedUnchanged(env, short, SccpErrors.BadCommittee);
    attempt += 1;
    val long = sendHandoffNaming(env, rootOfListedKeys(eighty), sccpBuildKeys(eighty), attempt);
    expectRefusedUnchanged(env, long, SccpErrors.BadCommittee);
    attempt += 1;
    expect(stepGas(long) <= stepGas(short) + 1000).toBeTrue();

    // the genuine list is installed
    val res = sendHandoffNaming(env, next.root(), next.keysCell(), attempt);
    expectOutcome(res, 0);
    replayExpectKeys(env, next.keys);
    expect(env.minter.getSccpCommittee().n).toEqual(4);
    expect(attempt).toEqual(14);
}

get fun `test next_keys in a non-canonical cell shape is BadSnake`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val k0 = next.keys.get(0);
    val k1 = next.keys.get(1);
    val k2 = next.keys.get(2);
    val k3 = next.keys.get(3);
    val lastTwo = beginCell().storeSlice(k2).storeSlice(k3).storeUint(0, 1).endCell();
    val lastOne = beginCell().storeSlice(k3).storeUint(0, 1).endCell();
    val shapes: array<cell> = [
        // one key in a chunk that has a next chunk
        beginCell()
            .storeSlice(k0)
            .storeMaybeRef(beginCell().storeSlice(k1).storeMaybeRef(lastTwo).endCell())
            .endCell(),
        // the Maybe bit set without a reference, and clear with one
        beginCell().storeSlice(k0).storeSlice(k1).storeUint(1, 1).endCell(),
        beginCell().storeSlice(k0).storeSlice(k1).storeUint(0, 1).storeRef(lastTwo).endCell(),
        // two references
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(lastTwo)
            .storeRef(lastOne)
            .endCell(),
        // a byte after the keys, and a chunk without keys
        beginCell().storeSlice(k0).storeSlice(k1).storeUint(0, 8).storeMaybeRef(lastTwo).endCell(),
        beginCell().storeUint(0, 1).endCell(),
        // a key of 383 bits
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(beginCell().storeSlice(k2.getFirstBits(383)).storeUint(0, 1).endCell())
            .endCell(),
        // the canonical list behind a library reference, in the root and in a later chunk
        asLibrary(next.keysCell()),
        beginCell().storeSlice(k0).storeSlice(k1).storeMaybeRef(asLibrary(lastTwo)).endCell(),
    ];
    var i = 0;
    repeat (shapes.size()) {
        expectRefusedUnchanged(
            env,
            sendHandoffNaming(env, next.root(), shapes.get(i), i),
            SccpErrors.BadSnake,
        );
        i += 1;
    }
    expect(i).toEqual(9);
    // the canonical list holds the same keys and is accepted
    expect(
        beginCell().storeSlice(k0).storeSlice(k1).storeMaybeRef(lastTwo).endCell().hash(),
    ).toEqual(
        next.keysCell().hash(),
    );
    expectOutcome(sendHandoffNaming(env, next.root(), next.keysCell(), i), 0);
    replayExpectKeys(env, next.keys);
}

get fun `test next_keys is not read when no key change applies`() {
    val env = setupEnv();
    val other = testCommittee(4, 8);
    val root = env.committee.root();
    // any cell, even one the parser would refuse
    val garbage = asLibrary(other.keysCell());
    // a non-rotation certificate
    val x = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    expectOutcome(checkpointBy(env, env.committee, x, garbage), 0);
    replayExpectKeys(env, env.committee.keys);
    // a heartbeat keeps the stored keys
    val heartbeat = handoffX(
        env,
        env.committee,
        env.generation,
        env.committee,
        TEST_START_HEIGHT + 10,
    );
    val cert = certifyFor(env, env.committee, heartbeat);
    val res = sendCheckpoint(env, env.deployer, cert, garbage, grams("1"));
    expectOutcome(res, 0);
    val until = NOW_MS - 1000 + TEST_VALIDITY_MS;
    expectEvents(
        res,
        [
            eventCertificate(heartbeat.height, env.generation, cert),
            eventCheckpointed(heartbeat.height, heartbeat.id()),
            eventRotated(env.generation + 1, root, until, heartbeat.height + 1),
        ],
    );
    expectCommittee(
        env,
        env.generation + 1,
        root,
        heartbeat.height + 1,
        heartbeat.height,
        until,
        false,
    );
    replayExpectKeys(env, env.committee.keys);
    expect(env.minter.getSccpCommittee().keys.hash()).toEqual(env.committee.keysCell().hash());
    // and without next_keys as well
    val second = rotationX(
        env.networkId,
        env.generation + 1,
        root,
        TEST_START_HEIGHT + 20,
        NOW_MS - 1000,
        root,
        TEST_VALIDITY_MS,
    );
    expectOutcome(checkpointBy(env, env.committee, second, null), 0);
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 2);
    // a violating key-changing handoff latches whatever next_keys holds
    val late = rotationX(
        env.networkId,
        env.generation + 2,
        root,
        TEST_START_HEIGHT + 15,
        NOW_MS - 1000,
        other.root(),
        TEST_VALIDITY_MS,
    );
    val latched = checkpointBy(env, env.committee, late, garbage);
    expectOutcome(latched, 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    replayExpectKeys(env, env.committee.keys);
}

get fun `test key-changing rotations at n=31`() {
    // 4 → 31 → 31 → 7: the stored chain is replaced each time
    val env = setupEnv();
    val big = testCommittee(31, 0);
    val other = testCommittee(31, 4);
    val small = testCommittee(7, 20);
    expect(big.root() != other.root()).toBeTrue();
    val first = rotateTo(env, big, TEST_START_HEIGHT + 10);
    reportGas(
        "checkpoint key-change rotation n=4 to n=31",
        stepGas(first),
        SCCP_GAS_MINTER_CHECKPOINT,
    );
    expect(env.minter.getSccpCommittee().n).toEqual(31);
    replayExpectKeys(env, big.keys);
    // 21 of 31 sign the next handoff
    val second = rotateFrom(env, big, env.generation + 1, other, TEST_START_HEIGHT + 20);
    reportGas("checkpoint key-change rotation n=31", stepGas(second), SCCP_GAS_MINTER_CHECKPOINT);
    replayExpectKeys(env, other.keys);
    // the highest 21 members sign as well as the lowest
    val x = emptyX(env.networkId, env.generation + 2, other.root(), TEST_START_HEIGHT + 25);
    val byHighest = certifyBy(other, other.highestSigners(), env.instance, defaultQc(x.height), x);
    expectOutcome(sendCheckpoint(env, env.deployer, byHighest, null, grams("1")), 0);
    // 20 signers are not a quorum of 31
    val y = emptyX(env.networkId, env.generation + 2, other.root(), TEST_START_HEIGHT + 26);
    val twenty = (1 << 20) - 1;
    val short = certifyBy(other, twenty, env.instance, defaultQc(y.height), y);
    expectOutcome(
        sendCheckpoint(env, env.deployer, short, null, grams("1")),
        SccpErrors.BadCertificate,
    );
    val third = rotateFrom(env, other, env.generation + 2, small, TEST_START_HEIGHT + 30);
    reportGas(
        "checkpoint key-change rotation n=31 to n=7",
        stepGas(third),
        SCCP_GAS_MINTER_CHECKPOINT,
    );
    expect(env.minter.getSccpCommittee().n).toEqual(7);
    replayExpectKeys(env, small.keys);
    val z = emptyX(env.networkId, env.generation + 3, small.root(), TEST_START_HEIGHT + 35);
    expectOutcome(checkpointBy(env, small, z, null), 0);
}

// ---------------------------------------------------------------------------
// Entry checks of `sccp_checkpoint` (§5.1.3, §5.3.5).

get fun `test sccp_checkpoint checks its value before any signature work`() {
    val env = setupEnv();
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    val cert = certifyFor(env, env.committee, x);
    // the minter is above its floor: the entry minimum is the quote minus the grace
    val quote = env.minter.checkpointRequiredValue();
    expect(quote).toEqual(sccpCheckpointRequiredValue() + sccpMinterStorageGrace());
    val minimum = quote - sccpMinterStorageGrace();
    val poor = sendCheckpoint(env, env.deployer, cert, null, minimum - 1);
    expectRefusedUnchanged(env, poor, SccpErrors.NotEnoughValue);
    expect(stepGas(poor) < 58000).toBeTrue();
    // an underfunded forgery fails the same way, before its signature is looked at
    val forged = certOf(foreignSignature(), 7, defaultQc(x.height), x);
    expectOutcome(
        sendCheckpoint(env, env.deployer, forged, null, minimum - 1),
        SccpErrors.NotEnoughValue,
    );
    val res = sendCheckpoint(env, env.deployer, cert, null, minimum);
    expectOutcome(res, 0);
    expect(res).toHaveAllSuccessfulTxs();
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
    // The entry value comes before `Live` too (§5.3.4 "Checkpoint and apply
    // control"): an expired minter answers an underfunded call for its value.
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    val y = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 6);
    val late = certifyFor(env, env.committee, y);
    val lateMinimum = env.minter.checkpointRequiredValue() - sccpMinterStorageGrace();
    expectOutcome(
        sendCheckpoint(env, env.deployer, late, null, lateMinimum - 1),
        SccpErrors.NotEnoughValue,
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, late, null, lateMinimum),
        SccpErrors.CommitteeNotAccepted,
    );
}

get fun `test sccp_checkpoint requires the ton mainnet global id`() {
    val env = setupEnv();
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    val cert = certifyFor(env, env.committee, x);
    val minimum = env.minter.checkpointRequiredValue() - sccpMinterStorageGrace();
    setGlobalId(-3);
    // chain identity comes first: before the value, `Live` and the certificate
    expectRefusedUnchanged(
        env,
        sendCheckpoint(env, env.deployer, cert, null, minimum - 1),
        SccpErrors.WrongChain,
    );
    expectRefusedUnchanged(
        env,
        sendCheckpoint(env, env.deployer, cert, null, grams("1")),
        SccpErrors.WrongChain,
    );
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expectOutcome(sendCheckpoint(env, env.deployer, cert, null, grams("1")), 0);
}

get fun `test a certificate that changes nothing bounces with NothingToDo`() {
    val env = setupEnv();
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    val cert = certifyFor(env, env.committee, x);
    expectOutcome(sendCheckpoint(env, env.deployer, cert, null, grams("1")), 0);
    val again = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
    expectOutcome(again, SccpErrors.NothingToDo);
    expectEvents(again, []);
    // the message bounces with its value
    expect(again).toHaveBouncedTx<SccpCheckpoint>({ to: env.deployer });
    // the same X under another QC (another result body, validly signed)
    // takes the cheap path too: nothing is recorded and nothing latches
    var qc = defaultQc(x.height);
    qc.resultBody = qc.resultBody ^ 1;
    val other = certifyBy(env.committee, env.committee.lowestSigners(), env.instance, qc, x);
    expectOutcome(
        sendCheckpoint(env, env.deployer, other, null, grams("1")),
        SccpErrors.NothingToDo,
    );
    expect(env.minter.getSccpState().equivocated).toBeFalse();
}

get fun `test a stored header still passes steps 1 to 6 before the cheap path`() {
    // §5.1.3 step 8: the lengths, the signer set and the identity check hold
    // for a certificate whose X is stored. The classification as CUR does too:
    // `certificates of retired generations are refused without effect` sends
    // the stored handoff of a retired generation.
    val env = setupEnv();
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    val qc = defaultQc(x.height);
    val signers = env.committee.lowestSigners();
    val genuine = blsAggregateSign(
        env.committee.secretsOf(signers),
        commitMessage(env.instance, qc, x),
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, certOf(genuine, signers, qc, x), null, grams("1")),
        0,
    );
    val before = minterStorage(env).toCell().hash();
    val head = x.headBits().endCell().beginParse();
    val tail = x.tailBits().endCell().beginParse();
    val qcBytes = qc.toCell().beginParse();

    var certs: array<cell> = [];
    var codes: array<int> = [];
    // step 1: a signature of 95 bytes, a QC_FIXED of 113 bytes, a library cell
    certs.push(certCell(genuine.getFirstBits(760), signers, qcBytes, head, tail));
    codes.push(SccpErrors.BadCertificate);
    certs.push(
        certCell(
            genuine,
            signers,
            beginCell().storeSlice(qcBytes).storeUint(0, 8).endCell().beginParse(),
            head,
            tail,
        ),
    );
    codes.push(SccpErrors.BadCertificate);
    certs.push(asLibrary(certOf(genuine, signers, qc, x)));
    codes.push(SccpErrors.BadSnake);
    // step 5: two signers, all four, a bit at index n, and none
    certs.push(certOf(genuine, 0b0011, qc, x));
    codes.push(SccpErrors.BadCertificate);
    certs.push(certOf(genuine, 0b1111, qc, x));
    codes.push(SccpErrors.BadCertificate);
    certs.push(certOf(genuine, 0b10011, qc, x));
    codes.push(SccpErrors.BadCertificate);
    certs.push(certOf(genuine, 0, qc, x));
    codes.push(SccpErrors.BadCertificate);
    // step 6: the identity signature
    val identity = beginCell()
        .storeUint(SCCP_IDENTITY_SIGNATURE_HEAD, 256)
        .storeUint(0, 256)
        .storeUint(0, 256)
        .endCell()
        .beginParse();
    certs.push(certOf(identity, signers, qc, x));
    codes.push(SccpErrors.BadSignature);
    var i = 0;
    repeat (certs.size()) {
        val res = sendCheckpoint(env, env.deployer, certs.get(i), null, grams("1"));
        if (outcomeOf(res) != codes.get(i)) {
            println("stored case {} expected {} observed {}", i, codes.get(i), outcomeOf(res));
        }
        expectOutcome(res, codes.get(i));
        expectEvents(res, []);
        expect(stepGas(res) < 58000).toBeTrue();
        i += 1;
    }
    expect(i).toEqual(8);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    // Past step 6 the signature is not looked at: the bitmap of another
    // quorum with a signature that signs nothing takes the cheap path, and
    // the stored X leaves nothing to do.
    val unsigned = certOf(foreignSignature(), env.committee.highestSigners(), qc, x);
    val cheap = sendCheckpoint(env, env.deployer, unsigned, null, grams("1"));
    expectOutcome(cheap, SccpErrors.NothingToDo);
    expect(stepGas(cheap) < 58000).toBeTrue();
    // the same certificate over a header that is not stored is BadSignature
    val fresh = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 6);
    expectOutcome(
        sendCheckpoint(
            env,
            env.deployer,
            certOf(foreignSignature(), signers, defaultQc(fresh.height), fresh),
            null,
            grams("1"),
        ),
        SccpErrors.BadSignature,
    );
    expect(minterStorage(env).toCell().hash()).toEqual(before);
}

get fun `test the signer set must be exactly a quorum of the stored committee`() {
    val env = setupEnvWith(7, TEST_MAX_SUPPLY);
    val root = env.committee.root();
    val x = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    val qc = defaultQc(x.height);
    // q = 5 of 7: four, six and seven signers, five with a bit at index n, and none
    val sets: array<int> = [0b0001111, 0b0111111, 0b1111111, 0b10001111, 0];
    var i = 0;
    repeat (sets.size()) {
        var signature = foreignSignature();
        if (sets.get(i) != 0) {
            // genuinely signed by exactly the named members of the committee
            signature = blsAggregateSign(
                env.committee.secretsOf(sets.get(i) & 0x7f),
                commitMessage(env.instance, qc, x),
            );
        }
        val cert = certOf(signature, sets.get(i), qc, x);
        val res = sendCheckpoint(env, env.deployer, cert, null, grams("1"));
        expectOutcome(res, SccpErrors.BadCertificate);
        expectEvents(res, []);
        expect(stepGas(res) < 58000).toBeTrue();
        i += 1;
    }
    // any five members are a quorum
    val scattered = 0b1010111;
    val cert = certifyBy(env.committee, scattered, env.instance, qc, x);
    expectOutcome(sendCheckpoint(env, env.deployer, cert, null, grams("1")), 0);
    // the bitmap names the signers: the same signature under another set fails
    val y = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 6);
    val qcY = defaultQc(y.height);
    val signature = blsAggregateSign(
        env.committee.secretsOf(scattered),
        commitMessage(env.instance, qcY, y),
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, certOf(signature, 0b0011111, qcY, y), null, grams("1")),
        SccpErrors.BadSignature,
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, certOf(signature, scattered, qcY, y), null, grams("1")),
        0,
    );
}

get fun `test what the signature covers`() {
    val env = setupEnv();
    val root = env.committee.root();
    val x = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    val qc = defaultQc(x.height);
    val signers = env.committee.lowestSigners();
    val secrets = env.committee.secretsOf(signers);
    val r = resultOf(x, qc.resultBody);
    // a PrepareQC, another instance, another height and another committee
    val messages: array<slice> = [
        voteMessage(0x02, env.instance, x.height, qc, r),
        voteMessage(SCCP_KIND_COMMIT, env.instance ^ 1, x.height, qc, r),
        voteMessage(SCCP_KIND_COMMIT, env.instance, x.height + 1, qc, r),
        voteMessage(SCCP_KIND_COMMIT, env.instance, x.height, qc, r ^ 1),
    ];
    var i = 0;
    repeat (messages.size()) {
        val cert = certOf(blsAggregateSign(secrets, messages.get(i)), signers, qc, x);
        expectRefusedUnchanged(
            env,
            sendCheckpoint(env, env.deployer, cert, null, grams("1")),
            SccpErrors.BadSignature,
        );
        i += 1;
    }
    // every QC field is signed: the genuine signature with one changed field
    val genuine = blsAggregateSign(secrets, commitMessage(env.instance, qc, x));
    var fields: array<TestQc> = [qc, qc, qc, qc, qc];
    var changed = qc;
    changed.epoch = qc.epoch + 1;
    fields.set(changed, 0);
    changed = qc;
    changed.epochContext = qc.epochContext ^ 1;
    fields.set(changed, 1);
    changed = qc;
    changed.view = qc.view + 1;
    fields.set(changed, 2);
    changed = qc;
    changed.blockHash = qc.blockHash ^ 1;
    fields.set(changed, 3);
    changed = qc;
    changed.resultBody = qc.resultBody ^ 1;
    fields.set(changed, 4);
    i = 0;
    repeat (fields.size()) {
        expectRefusedUnchanged(
            env,
            sendCheckpoint(
                env,
                env.deployer,
                certOf(genuine, signers, fields.get(i), x),
                null,
                grams("1"),
            ),
            SccpErrors.BadSignature,
        );
        i += 1;
    }
    // and every field of X: the genuine signature over a changed header
    var headers: array<TestX> = [x, x, x, x];
    var other = x;
    other.timestampMs = x.timestampMs + 1;
    headers.set(other, 0);
    other = withLeaf(x, 0x1234);
    headers.set(other, 1);
    other = x;
    other.height = x.height + 1;
    headers.set(other, 2);
    other = x;
    other.historySize = 3;
    other.historyRoot = 0x5678;
    headers.set(other, 3);
    i = 0;
    repeat (headers.size()) {
        expectRefusedUnchanged(
            env,
            sendCheckpoint(
                env,
                env.deployer,
                certOf(genuine, signers, qc, headers.get(i)),
                null,
                grams("1"),
            ),
            SccpErrors.BadSignature,
        );
        i += 1;
    }
    // another committee of the same size signs under the pinned root
    val strangers = testCommittee(4, 4);
    val foreign = certOf(
        blsAggregateSign(strangers.secretsOf(signers), commitMessage(env.instance, qc, x)),
        signers,
        qc,
        x,
    );
    expectRefusedUnchanged(
        env,
        sendCheckpoint(env, env.deployer, foreign, null, grams("1")),
        SccpErrors.BadSignature,
    );
    expectOutcome(
        sendCheckpoint(env, env.deployer, certOf(genuine, signers, qc, x), null, grams("1")),
        0,
    );
}

// ---------------------------------------------------------------------------
// Cell shapes of a certificate (§5.1.3 step 1, §5.3.2).

get fun `test certificate cells of another shape are refused by their kind`() {
    val row = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val env = vecDeployCertificate(row);
    val qc = beginCell().storeSlice(row.qc).endCell();
    val tail = beginCell().storeSlice(row.tail).endCell();
    val x = xCell(row.head, row.tail);
    val root = beginCell().storeSlice(row.signature).storeUint(row.signers, 32);
    val extra = beginCell().storeUint(0, 8).endCell();
    val headWith = beginCell().storeSlice(row.head);

    var cells: array<cell> = [];
    var codes: array<int> = [];
    // TairaCert: one or three references, and a root of another size
    cells.push(beginCell().storeBuilder(root).storeRef(qc).endCell());
    codes.push(SccpErrors.BadCertificate);
    cells.push(beginCell().storeBuilder(root).storeRef(qc).storeRef(x).storeRef(extra).endCell());
    codes.push(SccpErrors.BadCertificate);
    cells.push(
        beginCell()
            .storeSlice(row.signature)
            .storeUint(row.signers, 24)
            .storeRef(qc)
            .storeRef(x)
            .endCell(),
    );
    codes.push(SccpErrors.BadCertificate);
    cells.push(beginCell().storeBuilder(root).storeUint(0, 8).storeRef(qc).storeRef(x).endCell());
    codes.push(SccpErrors.BadCertificate);
    // QcFixed: a reference, 111 bytes and 113 bytes
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(beginCell().storeSlice(row.qc).storeRef(extra).endCell())
            .storeRef(x)
            .endCell(),
    );
    codes.push(SccpErrors.BadCertificate);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(beginCell().storeSlice(row.qc.getFirstBits(888)).endCell())
            .storeRef(x)
            .endCell(),
    );
    codes.push(SccpErrors.BadCertificate);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(beginCell().storeSlice(row.qc).storeUint(0, 8).endCell())
            .storeRef(x)
            .endCell(),
    );
    codes.push(SccpErrors.BadCertificate);
    // XHead: no tail, two references, 108 bytes
    cells.push(beginCell().storeBuilder(root).storeRef(qc).storeRef(headWith.endCell()).endCell());
    codes.push(SccpErrors.BadHeader);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(qc)
            .storeRef(beginCell().storeSlice(row.head).storeRef(tail).storeRef(extra).endCell())
            .endCell(),
    );
    codes.push(SccpErrors.BadHeader);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(qc)
            .storeRef(beginCell().storeSlice(row.head.getFirstBits(864)).storeRef(tail).endCell())
            .endCell(),
    );
    codes.push(SccpErrors.BadHeader);
    // XTail: a reference, and 113 bytes
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(qc)
            .storeRef(
                beginCell()
                    .storeSlice(row.head)
                    .storeRef(beginCell().storeSlice(row.tail).storeRef(extra).endCell())
                    .endCell(),
            )
            .endCell(),
    );
    codes.push(SccpErrors.BadHeader);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(qc)
            .storeRef(
                beginCell()
                    .storeSlice(row.head)
                    .storeRef(beginCell().storeSlice(row.tail).storeUint(0, 8).endCell())
                    .endCell(),
            )
            .endCell(),
    );
    codes.push(SccpErrors.BadHeader);
    // the lengths are checked in the order QC_FIXED, X, signature
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(beginCell().storeSlice(row.qc).storeUint(0, 8).endCell())
            .storeRef(headWith.endCell())
            .endCell(),
    );
    codes.push(SccpErrors.BadCertificate);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeUint(0, 8)
            .storeRef(qc)
            .storeRef(headWith.endCell())
            .endCell(),
    );
    codes.push(SccpErrors.BadHeader);
    // a cell that is not ordinary, wherever it is, although its content is canonical
    val genuine = certCell(row.signature, row.signers, row.qc, row.head, row.tail);
    cells.push(asLibrary(genuine));
    codes.push(SccpErrors.BadSnake);
    cells.push(beginCell().storeBuilder(root).storeRef(asLibrary(qc)).storeRef(x).endCell());
    codes.push(SccpErrors.BadSnake);
    cells.push(beginCell().storeBuilder(root).storeRef(qc).storeRef(asLibrary(x)).endCell());
    codes.push(SccpErrors.BadSnake);
    cells.push(
        beginCell()
            .storeBuilder(root)
            .storeRef(qc)
            .storeRef(beginCell().storeSlice(row.head).storeRef(asLibrary(tail)).endCell())
            .endCell(),
    );
    codes.push(SccpErrors.BadSnake);

    var i = 0;
    repeat (cells.size()) {
        val res = replayCheckpoint(env, cells.get(i), null);
        if (outcomeOf(res) != codes.get(i)) {
            println("shape {} expected {} observed {}", i, codes.get(i), outcomeOf(res));
        }
        expectOutcome(res, codes.get(i));
        expectEvents(res, []);
        expect(stepGas(res) < 58000).toBeTrue();
        i += 1;
    }
    expect(i).toEqual(18);
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
    // the same cells in their canonical shape are accepted
    expectOutcome(replayCheckpoint(env, genuine, null), 0);
}

// ---------------------------------------------------------------------------
// Header rows of `finality_v1.json` (§3.6, §5.1.3 step 2).

/// The header fields of a row as a test header.
fun headerOf(row: VecHeader): TestX {
    return {
        networkId: row.networkId,
        height: row.height,
        timestampMs: row.timestampMs,
        flags: row.flags,
        messageCount: row.messageCount,
        sccpRoot: row.sccpRoot,
        historySize: row.historySize,
        historyRoot: row.historyRoot,
        generation: row.generation,
        committeeRoot: row.committeeRoot,
        validityMs: row.validityMs,
        nextCommitteeRoot: row.nextCommitteeRoot,
    };
}

/// The exit code of `sccpParseX` for the cells of a header, 0 when it parses.
fun parseOutcome(x: cell): int {
    try {
        sccpParseX(x, VEC_NETWORK_ID);
        return 0;
    } catch (code) {
        return code;
    }
}

get fun `test every valid header row parses to its fields and its checkpoint id`() {
    var row = 0;
    var accepted = 0;
    repeat (VEC_VALID_HEADER_COUNT) {
        val header = vecValidHeader(row);
        val x = headerOf(header);
        // the test headers of this suite serialize as the fixture does
        expect(x.toCell().hash()).toEqual(xCell(header.head, header.tail).hash());
        expect(x.id()).toEqual(header.id);
        expect(sccpCheckpointId(header.head, header.tail)).toEqual(header.id);
        expect(parseOutcome(x.toCell())).toEqual(header.exit);
        if (header.exit == 0) {
            val (parsed, headBytes, tailBytes) = sccpParseX(x.toCell(), VEC_NETWORK_ID);
            expect(headBytes.bitsEqual(header.head)).toBeTrue();
            expect(tailBytes.bitsEqual(header.tail)).toBeTrue();
            expect(parsed.height).toEqual(header.height);
            expect(parsed.timestampMs).toEqual(header.timestampMs);
            expect(parsed.flags).toEqual(header.flags);
            expect(parsed.messageCount).toEqual(header.messageCount);
            expect(parsed.sccpRoot).toEqual(header.sccpRoot);
            expect(parsed.historySize).toEqual(header.historySize);
            expect(parsed.historyRoot).toEqual(header.historyRoot);
            expect(parsed.generation).toEqual(header.generation);
            expect(parsed.committeeRoot).toEqual(header.committeeRoot);
            expect(parsed.validityMs).toEqual(header.validityMs);
            expect(parsed.nextCommitteeRoot).toEqual(header.nextCommitteeRoot);
            expect(parsed.id).toEqual(header.id);
            expect(parsed.isRotation()).toEqual((header.flags & SCCP_X_FLAG_ROTATION) != 0);
            // another network is refused for the same bytes
            try {
                sccpParseX(x.toCell(), VEC_NETWORK_ID ^ 1);
                expect(false).toBeTrue();
            } catch (code) {
                expect(code).toEqual(SccpErrors.BadHeader as int);
            }
            accepted += 1;
        } else {
            expect(header.exit).toEqual(SccpErrors.BadHeader as int);
        }
        row += 1;
    }
    expect(row).toEqual(PINNED_VALID_HEADERS);
    // two rows are the inactive form, which a destination refuses
    expect(accepted).toEqual(6);
}

get fun `test a certificate that carries a valid header row answers as the row records`() {
    // The rows name a synthetic committee root. A deployment that pins that
    // root is installed with test keys (white box), and they sign the header.
    val committee = testCommittee(4, 0);
    var row = 0;
    var accepted = 0;
    var refused = 0;
    repeat (VEC_VALID_HEADER_COUNT) {
        val header = vecValidHeader(row);
        val x = headerOf(header);
        val pin: InitialPin = {
            generation: max(header.generation, 1),
            root: header.committeeRoot == 0 ? 1 : header.committeeRoot,
            start: 1,
            untilMs: PIN_UNTIL_MS,
        };
        val env = replayDeployUnchecked(pin, committee.keys, TEST_MAX_SUPPLY, T0);
        val cert = certifyBy(
            committee,
            committee.lowestSigners(),
            env.instance,
            defaultQc(x.height),
            x,
        );
        val res = replayCheckpoint(env, cert, null);
        if (header.exit != 0) {
            expectOutcome(res, header.exit);
            expectEvents(res, []);
            refused += 1;
        } else if (
            (x.nextCommitteeRoot == x.committeeRoot) | ((x.flags & SCCP_X_FLAG_ROTATION) == 0)
        ) {
            // a non-rotation header and a heartbeat are applied
            expectOutcome(res, 0);
            replayExpectCheckpoints(
                env,
                1,
                x.height,
                header.id,
                0,
                0,
                0,
                0,
            );
            accepted += 1;
        } else {
            // A key-changing handoff is verified, then waits for the keys of
            // its synthetic successor root, which no list can have.
            expectOutcome(res, SccpErrors.BadCommittee);
            expect(stepGas(res) > 58000).toBeTrue();
            accepted += 1;
        }
        row += 1;
    }
    expect(row).toEqual(PINNED_VALID_HEADERS);
    expect(accepted).toEqual(6);
    expect(refused).toEqual(2);
}

get fun `test every invalid header row is BadHeader`() {
    val good = vecCertificate(VEC_CERT_N4_LOWEST_Q);
    val env = vecDeployCertificate(good);
    var row = 0;
    repeat (VEC_INVALID_HEADER_COUNT) {
        val header = vecInvalidHeader(row);
        expect(header.exit).toEqual(SccpErrors.BadHeader as int);
        expect(parseOutcome(xCell(header.head, header.tail))).toEqual(header.exit);
        // through the minter, whatever signs it: the header is refused first
        val res = replayCheckpoint(
            env,
            certCell(good.signature, good.signers, good.qc, header.head, header.tail),
            null,
        );
        if (outcomeOf(res) != header.exit) {
            println("header row {} expected {} observed {}", row, header.exit, outcomeOf(res));
        }
        expectOutcome(res, header.exit);
        expectEvents(res, []);
        expect(stepGas(res) < 58000).toBeTrue();
        row += 1;
    }
    expect(row).toEqual(PINNED_INVALID_HEADERS);
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
}

get fun `test a header without ACTIVE is refused whatever its other fields hold`() {
    // The inactive rows of the fixture hold zero fields, which X3 refuses as
    // well. A destination refuses the missing flag itself (§5.1.3 step 2):
    // here every other field is that of a valid header, genuinely signed.
    val env = setupEnv();
    val next = testCommittee(4, 4);
    var plain = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    var handoff = handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 6);
    expect(parseOutcome(plain.toCell())).toEqual(0);
    expect(parseOutcome(handoff.toCell())).toEqual(0);
    plain.flags = 0;
    handoff.flags = SCCP_X_FLAG_ROTATION;
    val headers: array<TestX> = [plain, handoff];
    var i = 0;
    repeat (headers.size()) {
        expect(parseOutcome(headers.get(i).toCell())).toEqual(SccpErrors.BadHeader as int);
        expectRefusedUnchanged(
            env,
            checkpointBy(env, env.committee, headers.get(i), next.keysCell()),
            SccpErrors.BadHeader,
        );
        i += 1;
    }
    expect(i).toEqual(2);
    // a stored id does not make such a header usable either (white box)
    seedCheckpoint(env, plain);
    expectOutcome(
        controlStored(
            env,
            plain.ref(),
            controlProofCell(
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                1,
                1,
                0,
                [],
                ownBlockRef(plain),
            ),
            grams("1"),
        ),
        SccpErrors.BadHeader,
    );
}

get fun `test a handoff at the top of u64 is refused by X6`() {
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val root = env.committee.root();
    // height 2^64 − 1: the successor's start would not be a u64
    var x = handoffX(env, env.committee, env.generation, next, SCCP_MAX_U64);
    expectRefusedUnchanged(
        env,
        checkpointBy(env, env.committee, x, next.keysCell()),
        SccpErrors.BadHeader,
    );
    // the same height without ROTATION is a valid header
    val top = emptyX(env.networkId, env.generation, root, SCCP_MAX_U64);
    expect(parseOutcome(top.toCell())).toEqual(0);
    // 2^64 − 2 is the last height a handoff can have
    x = handoffX(env, env.committee, env.generation, next, SCCP_MAX_ROTATION_FIELD);
    expect(parseOutcome(x.toCell())).toEqual(0);
    val res = checkpointBy(env, env.committee, x, next.keysCell());
    expectOutcome(res, 0);
    val state = env.minter.getSccpState();
    expect(state.start).toEqual(SCCP_MAX_U64);
    expect(state.high).toEqual(SCCP_MAX_ROTATION_FIELD);
    expect(state.generation).toEqual(env.generation + 1);
    // generation 2^64 − 1 cannot hand off either
    var last = handoffX(env, env.committee, SCCP_MAX_U64, next, TEST_START_HEIGHT);
    expect(parseOutcome(last.toCell())).toEqual(SccpErrors.BadHeader as int);
    last.generation = SCCP_MAX_ROTATION_FIELD;
    expect(parseOutcome(last.toCell())).toEqual(0);
}

// ---------------------------------------------------------------------------
// Using a stored checkpoint (§5.1.3 "Using a checkpoint").

get fun `test a stored checkpoint is usable under U1 or as the installing handoff only`() {
    val env = setupEnv();
    val a = env.committee;
    val b = testCommittee(4, 4);
    val c = testCommittee(4, 8);
    val g = env.generation;
    // generation 7: a block with control 1, a handoff used inline that will
    // not install (control 2), and the handoff that installs (control 3)
    val block = controlIn(
        env,
        a,
        emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT + 20),
        parliamentControl(1, true),
    );
    val stray = controlIn(
        env,
        a,
        handoffX(env, a, g, b, TEST_START_HEIGHT + 25),
        parliamentControl(2, false),
    );
    val handoff = controlIn(
        env,
        a,
        handoffX(env, a, g, b, TEST_START_HEIGHT + 30),
        parliamentControl(3, true),
    );
    expectOutcome(sendCheckpoint(env, env.deployer, block.cert, null, grams("1")), 0);
    // while generation 7 is current, its checkpoint is usable (U1)
    expectOutcome(sendApplyControlCheckpoint(env, block), 0);
    expect(env.minter.getSccpState().controlNonce).toEqual(1);
    expectOutcome(sendApplyControl(env, stray), 0);
    expect(env.minter.getSccpState().controlNonce).toEqual(2);
    expect(env.minter.getSccpState().generation).toEqual(g);
    expectOutcome(sendCheckpoint(env, env.deployer, handoff.cert, b.keysCell(), grams("1")), 0);
    expect(env.minter.getSccpState().generation).toEqual(g + 1);
    replayExpectCheckpoints(
        env,
        3,
        block.x.height,
        block.x.id(),
        stray.x.height,
        stray.x.id(),
        handoff.x.height,
        handoff.x.id(),
    );

    // generation 8: the non-handoff checkpoint of generation 7 is refused
    val refusedBlock = sendApplyControlCheckpoint(env, block);
    expectOutcome(refusedBlock, SccpErrors.CommitteeNotAccepted);
    expectEvents(refusedBlock, []);
    // A handoff of generation 7 that names the installed root but is not the
    // one that installed it (its height + 1 is not cur.start) is refused too
    expectOutcome(sendApplyControlCheckpoint(env, stray), SccpErrors.CommitteeNotAccepted);
    // the installing handoff is usable (U2)
    val applied = sendApplyControlCheckpoint(env, handoff);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventControlApplied(
                3,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                parliamentControl(3, true).certificateId,
            ),
        ],
    );
    expect(env.minter.getSccpState().controlNonce).toEqual(3);

    // generation 9: the handoff of generation 7 is two generations old
    val next = controlIn(
        env,
        b,
        handoffX(env, b, g + 1, c, TEST_START_HEIGHT + 40),
        parliamentControl(4, false),
    );
    expectOutcome(sendCheckpoint(env, env.deployer, next.cert, c.keysCell(), grams("1")), 0);
    expect(env.minter.getSccpState().generation).toEqual(g + 2);
    // the three slots now hold heights 25, 30 and 40
    expect(env.minter.getSccpCheckpoints().height0).toEqual(stray.x.height);
    val old = sendApplyControlCheckpoint(env, handoff);
    expectOutcome(old, SccpErrors.CommitteeNotAccepted);
    expectEvents(old, []);
    expectOutcome(sendApplyControlCheckpoint(env, stray), SccpErrors.CommitteeNotAccepted);
    // the evicted block is unknown
    expectOutcome(sendApplyControlCheckpoint(env, block), SccpErrors.UnknownCheckpoint);
    // the handoff of generation 8 is usable
    expectOutcome(sendApplyControlCheckpoint(env, next), 0);
    val state = env.minter.getSccpState();
    expect(state.controlNonce).toEqual(4);
    expect(state.parliamentPaused).toBeFalse();
    // using a checkpoint records nothing and raises nothing
    expect(state.high).toEqual(next.x.height);
    expect(state.opCount).toEqual(4);
}

get fun `test a checkpoint of the generation before a heartbeat is not usable after it`() {
    val env = setupEnv();
    val a = env.committee;
    val g = env.generation;
    val block = controlIn(
        env,
        a,
        emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT + 20),
        parliamentControl(1, true),
    );
    expectOutcome(sendCheckpoint(env, env.deployer, block.cert, null, grams("1")), 0);
    val heartbeat = controlIn(
        env,
        a,
        handoffX(env, a, g, a, TEST_START_HEIGHT + 30),
        parliamentControl(2, true),
    );
    expectOutcome(sendCheckpoint(env, env.deployer, heartbeat.cert, null, grams("1")), 0);
    expect(env.minter.getSccpState().generation).toEqual(g + 1);
    expect(env.minter.getSccpState().root).toEqual(a.root());
    // the same root, another generation: not U1
    expectOutcome(sendApplyControlCheckpoint(env, block), SccpErrors.CommitteeNotAccepted);
    // the heartbeat handoff installed the generation: U2
    expectOutcome(sendApplyControlCheckpoint(env, heartbeat), 0);
    expect(env.minter.getSccpState().controlNonce).toEqual(2);
}

get fun `test the checkpoint use check runs in the order of the specification`() {
    val env = setupEnv();
    val a = env.committee;
    val g = env.generation;
    val control = parliamentControl(1, true);
    val stored = controlIn(
        env,
        a,
        emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT + 20),
        control,
    );
    expectOutcome(sendCheckpoint(env, env.deployer, stored.cert, null, grams("1")), 0);
    val before = minterStorage(env).toCell().hash();
    val proof = stored.proof;

    // 1. the reference cell (BadSnake) and the length of X (BadHeader)
    val head = stored.x.headBits();
    val tail = stored.x.tailBits();
    val shapes: array<cell> = [
        beginCell().storeUint(0, 1).storeRef(stored.x.toCell()).endCell(),
        beginCell().storeRef(stored.x.toCell()).storeRef(stored.x.toCell()).endCell(),
        beginCell().endCell(),
        asLibrary(stored.x.ref()),
    ];
    var i = 0;
    repeat (shapes.size()) {
        val res = controlStored(env, shapes.get(i), proof, grams("1"));
        expectOutcome(res, SccpErrors.BadSnake);
        i += 1;
    }
    expectOutcome(
        controlStored(
            env,
            beginCell().storeRef(asLibrary(stored.x.toCell())).endCell(),
            proof,
            grams("1"),
        ),
        SccpErrors.BadSnake,
    );
    val lengths: array<cell> = [
        beginCell()
            .storeRef(
                beginCell()
                    .storeBuilder(head)
                    .storeRef(beginCell().storeBuilder(tail).storeUint(0, 8).endCell())
                    .endCell(),
            )
            .endCell(),
        beginCell().storeRef(beginCell().storeBuilder(head).endCell()).endCell(),
        beginCell()
            .storeRef(
                beginCell().storeBuilder(head).storeUint(0, 8).storeRef(tail.endCell()).endCell(),
            )
            .endCell(),
    ];
    i = 0;
    repeat (lengths.size()) {
        val res = controlStored(env, lengths.get(i), proof, grams("1"));
        expectOutcome(res, SccpErrors.BadHeader);
        i += 1;
    }

    // 2. the stored id, before X1–X7: an invalid header that is not stored
    // is unknown, and so are another header at a stored height and a header
    // at a free height
    var invalid = stored.x;
    invalid.flags = 0x05;
    invalid.height = stored.x.height + 3;
    var conflicting = stored.x;
    conflicting.timestampMs = stored.x.timestampMs + 1;
    val free = emptyX(env.networkId, g, a.root(), stored.x.height + 1);
    val unknown: array<TestX> = [invalid, conflicting, free];
    i = 0;
    repeat (unknown.size()) {
        val res = controlStored(env, unknown.get(i).ref(), proof, grams("1"));
        expectOutcome(res, SccpErrors.UnknownCheckpoint);
        expectEvents(res, []);
        i += 1;
    }
    expect(minterStorage(env).toCell().hash()).toEqual(before);

    // 3. X1–X7 of a stored id, and 5. the eligibility of a valid stored
    // header of another generation (white box: no certificate stores them)
    seedCheckpoint(env, invalid);
    val foreign = emptyX(env.networkId, g + 1, a.root(), stored.x.height + 4);
    seedCheckpoint(env, foreign);
    expect(env.minter.getSccpCheckpoints().count).toEqual(3);
    expectOutcome(
        controlStored(env, invalid.ref(), proof, grams("1")),
        SccpErrors.BadHeader,
    );
    expectOutcome(
        controlStored(env, foreign.ref(), proof, grams("1")),
        SccpErrors.CommitteeNotAccepted,
    );
    // the stored header of the current generation applies its control
    expectOutcome(sendApplyControlCheckpoint(env, stored), 0);

    // 4. `Live` comes after X1–X7 and before the eligibility: on a latched
    // minter the unknown and the invalid header answer as before, and the
    // header of another generation answers Equivocated
    val below = emptyX(env.networkId, g, a.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, a, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    expectOutcome(
        controlStored(env, free.ref(), proof, grams("1")),
        SccpErrors.UnknownCheckpoint,
    );
    expectOutcome(
        controlStored(env, invalid.ref(), proof, grams("1")),
        SccpErrors.BadHeader,
    );
    expectOutcome(
        controlStored(env, foreign.ref(), proof, grams("1")),
        SccpErrors.Equivocated,
    );
    expectOutcome(sendApplyControlCheckpoint(env, stored), SccpErrors.Equivocated);
}

// ---------------------------------------------------------------------------
// Messages and events of the certificate entry points (§5.3.3).
//
// TODO: WP-TON-RUST (map step T8, suite T7m): replay the golden bodies of
// `fixtures/sccp/ton_boc_v1.json` once the Rust body encoders write that
// file. Until then the test below pins the tags and the data-bit layouts.

/// The 32-bit tag and the data bits of a serialized body.
fun tagAndBits(body: cell): (int, int) {
    val s = body.beginParse();
    return (s.preloadUint(32), s.remainingBitsCount());
}

get fun `test the certificate messages and events carry the tags and layouts of the specification`() {
    val env = setupEnv();
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 5);
    val cert = certifyFor(env, env.committee, x);
    // TairaCert: signature:bits768 signers:uint32 qc:^QcFixed x:^XHead
    val root = cert.beginParse();
    expect(root.remainingBitsCount()).toEqual(SCCP_TAIRA_CERT_BITS);
    expect(root.remainingRefsCount()).toEqual(2);
    // query_id:uint64 response:MsgAddressInt follow the op: 32 + 64 + 267 bits
    val header = 32 + 64 + 267;
    val (checkpointOp, checkpointBits) = tagAndBits(
        SccpCheckpoint {
            queryId: 1,
            response: env.deployer,
            cert: cert as Cell<TairaCert>,
            nextKeys: null,
        }.toCell(),
    );
    expect(checkpointOp).toEqual(0x53434b31);
    // next_keys:(Maybe ^KeyChunk) is one bit
    expect(checkpointBits).toEqual(header + 1);
    val proof = messageProofCell(0, [], inboundPayloadCell(0, 1, 1, 1, 1), ownBlockRef(x));
    val (finalizeOp, finalizeBits) = tagAndBits(
        SccpFinalize {
            queryId: 1,
            response: env.deployer,
            cert: cert as Cell<TairaCert>,
            message: proof as Cell<MessageProof>,
        }.toCell(),
    );
    expect(finalizeOp).toEqual(0x53434631);
    expect(finalizeBits).toEqual(header);
    val (finalizeCheckpointOp, _) = tagAndBits(
        SccpFinalizeCheckpoint {
            queryId: 1,
            response: env.deployer,
            ref: x.ref() as Cell<CheckpointRef>,
            message: proof as Cell<MessageProof>,
        }.toCell(),
    );
    expect(finalizeCheckpointOp).toEqual(0x53434632);
    val (voidOp, voidBits) = tagAndBits(
        SccpVoidExpired {
            queryId: 1,
            response: env.deployer,
            nonce: 0,
            cert: cert as Cell<TairaCert>,
            message: proof as Cell<MessageProof>,
        }.toCell(),
    );
    expect(voidOp).toEqual(0x53435631);
    expect(voidBits).toEqual(header + 64);
    val (voidCheckpointOp, _) = tagAndBits(
        SccpVoidExpiredCheckpoint {
            queryId: 1,
            response: env.deployer,
            nonce: 0,
            ref: x.ref() as Cell<CheckpointRef>,
            message: proof as Cell<MessageProof>,
        }.toCell(),
    );
    expect(voidCheckpointOp).toEqual(0x53435632);
    val (voidFrozenOp, voidFrozenBits) = tagAndBits(
        SccpVoidFrozen {
            queryId: 1,
            response: env.deployer,
            firstNonce: 0,
            count: 1,
        }.toCell(),
    );
    expect(voidFrozenOp).toEqual(0x53435633);
    expect(voidFrozenBits).toEqual(header + 64 + 16);
    val control = controlIn(env, env.committee, x, parliamentControl(1, true));
    val (controlOp, _) = tagAndBits(
        SccpApplyControl {
            queryId: 1,
            response: env.deployer,
            cert: control.cert as Cell<TairaCert>,
            control: control.proof as Cell<ControlProof>,
        }.toCell(),
    );
    expect(controlOp).toEqual(0x53434d31);
    val (controlCheckpointOp, _) = tagAndBits(
        SccpApplyControlCheckpoint {
            queryId: 1,
            response: env.deployer,
            ref: x.ref() as Cell<CheckpointRef>,
            control: control.proof as Cell<ControlProof>,
        }.toCell(),
    );
    expect(controlCheckpointOp).toEqual(0x53434d32);
    val (initOp, initBits) = tagAndBits(SccpInit { queryId: 1 }.toCell());
    expect(initOp).toEqual(0x53434930);
    expect(initBits).toEqual(32 + 64);

    // external-out events
    val (certificateTag, certificateBits) = tagAndBits(eventCertificate(1, 2, cert));
    expect(certificateTag).toEqual(0x53434346);
    expect(certificateBits).toEqual(32 + 64 + 64);
    expect(eventCertificate(1, 2, cert).beginParse().remainingRefsCount()).toEqual(1);
    val (checkpointedTag, checkpointedBits) = tagAndBits(eventCheckpointed(1, 2));
    expect(checkpointedTag).toEqual(0x53434b4e);
    expect(checkpointedBits).toEqual(32 + 64 + 256);
    val (rotatedTag, rotatedBits) = tagAndBits(eventRotated(1, 2, 3, 4));
    expect(rotatedTag).toEqual(0x53435252);
    expect(rotatedBits).toEqual(32 + 64 + 256 + 64 + 64);
    val (latchedTag, latchedBits) = tagAndBits(eventLatched(1, 2, 3, 4, 5));
    expect(latchedTag).toEqual(0x53434c54);
    expect(latchedBits).toEqual(32 + 8 + 64 + 64 + 256 + 256);
    val (appliedTag, appliedBits) = tagAndBits(eventControlApplied(1, 2, true, 3, 4));
    expect(appliedTag).toEqual(0x5343434e);
    expect(appliedBits).toEqual(32 + 64 + 8 + 1 + 64 + 256);
    // the latch reasons and the tracks
    expect(SCCP_LATCH_V1).toEqual(1);
    expect(SCCP_LATCH_V2).toEqual(2);
    expect(SCCP_LATCH_V3).toEqual(3);
    expect(SCCP_TRACK_PARLIAMENT).toEqual(1);
    expect(SCCP_TRACK_FAST_PAUSE).toEqual(2);
    expect(SCCP_CHECKPOINT_SLOTS).toEqual(VEC_CHECKPOINT_SLOTS);
    expect(SCCP_MAX_VALIDITY_MS).toEqual(VEC_MAX_VALIDITY_MS);
    expect(SCCP_X_MAGIC).toEqual(VEC_X_MAGIC);
}

get fun `test the deleted evidence and rotation ops are unknown messages`() {
    // §5.3.3: `sccp_evidence` and `sccp_rotate` are deleted. A committee
    // changes through a handoff certificate in `sccp_checkpoint` only.
    val env = setupEnv();
    val next = testCommittee(4, 4);
    val handoff = handoffX(env, env.committee, env.generation, next, TEST_START_HEIGHT + 10);
    val cert = certifyFor(env, env.committee, handoff);
    val before = minterStorage(env).toCell().hash();
    val ops: array<int> = [0x53434531, 0x53435231];
    var i = 0;
    repeat (ops.size()) {
        // the op with the fields of `sccp_checkpoint` behind it
        val body = beginCell()
            .storeUint(ops.get(i), 32)
            .storeUint(1, 64)
            .storeAddress(env.deployer)
            .storeRef(cert)
            .storeMaybeRef(next.keysCell())
            .endCell();
        val res = env.minter.sendAny(env.deployer, body, { value: grams("1"), bounce: true });
        expectOutcome(res, SccpErrors.InvalidMessage);
        expectEvents(res, []);
        i += 1;
    }
    expect(i).toEqual(2);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    // the same certificate and keys under the checkpoint op rotate
    expectOutcome(sendCheckpoint(env, env.deployer, cert, next.keysCell(), grams("1")), 0);
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);
}

/// Exit codes of the shared table (`error_codes` of
/// `committee_transitions_v1.json`).
const PINNED_EXIT_CODES = 33

get fun `test the exit codes are the shared table of the fixture`() {
    // §5.2.2: every harness keys on the error names, and the generated
    // replays compare the numbers of this table. `VEC_EXIT_*` are its rows.
    val codes: array<[int, int]> = [
        [SccpErrors.WrongChain as int, VEC_EXIT_WRONG_CHAIN],
        [SccpErrors.MintingIsPaused as int, VEC_EXIT_MINTING_IS_PAUSED],
        [SccpErrors.CommitteeNotAccepted as int, VEC_EXIT_COMMITTEE_NOT_ACCEPTED],
        [SccpErrors.BadCommittee as int, VEC_EXIT_BAD_COMMITTEE],
        [SccpErrors.BadCertificate as int, VEC_EXIT_BAD_CERTIFICATE],
        [SccpErrors.BadSignature as int, VEC_EXIT_BAD_SIGNATURE],
        [SccpErrors.BadHeader as int, VEC_EXIT_BAD_HEADER],
        [SccpErrors.BadProof as int, VEC_EXIT_BAD_PROOF],
        [SccpErrors.BadPayload as int, VEC_EXIT_BAD_PAYLOAD],
        [SccpErrors.SupplyCapExceeded as int, VEC_EXIT_SUPPLY_CAP_EXCEEDED],
        [SccpErrors.UnknownCheckpoint as int, VEC_EXIT_UNKNOWN_CHECKPOINT],
        [SccpErrors.BadRecipient as int, VEC_EXIT_BAD_RECIPIENT],
        [SccpErrors.BadAmount as int, VEC_EXIT_BAD_AMOUNT],
        [SccpErrors.DeadlinePassed as int, VEC_EXIT_DEADLINE_PASSED],
        [SccpErrors.DeadlineNotReached as int, VEC_EXIT_DEADLINE_NOT_REACHED],
        [SccpErrors.NotFrozen as int, VEC_EXIT_NOT_FROZEN],
        [SccpErrors.StaleControl as int, VEC_EXIT_STALE_CONTROL],
        [SccpErrors.NotInitialized as int, VEC_EXIT_NOT_INITIALIZED],
        [SccpErrors.AlreadyInitialized as int, VEC_EXIT_ALREADY_INITIALIZED],
        [SccpErrors.BadControl as int, VEC_EXIT_BAD_CONTROL],
        [SccpErrors.BadSnake as int, VEC_EXIT_BAD_SNAKE],
        [SccpErrors.BucketNotDeployed as int, VEC_EXIT_BUCKET_NOT_DEPLOYED],
        [SccpErrors.NotMinter as int, VEC_EXIT_NOT_MINTER],
        [SccpErrors.NotBucket as int, VEC_EXIT_NOT_BUCKET],
        [SccpErrors.BadNonce as int, VEC_EXIT_BAD_NONCE],
        [SccpErrors.BadRange as int, VEC_EXIT_BAD_RANGE],
        [SccpErrors.BadBurnPayload as int, VEC_EXIT_BAD_BURN_PAYLOAD],
        [SccpErrors.NothingToDo as int, VEC_EXIT_NOTHING_TO_DO],
        [SccpErrors.BadConfig as int, VEC_EXIT_BAD_CONFIG],
        [SccpErrors.BucketNotActive as int, VEC_EXIT_BUCKET_NOT_ACTIVE],
        [SccpErrors.NothingToRetry as int, VEC_EXIT_NOTHING_TO_RETRY],
        [SccpErrors.Equivocated as int, VEC_EXIT_EQUIVOCATED],
        [SccpErrors.LatchRequired as int, VEC_EXIT_LATCH_REQUIRED],
    ];
    var i = 0;
    var previous = 0;
    repeat (codes.size()) {
        val [contractCode, fixtureCode] = codes.get(i);
        if (contractCode != fixtureCode) {
            println("exit code row {}: contract {} fixture {}", i, contractCode, fixtureCode);
        }
        expect(contractCode).toEqual(fixtureCode);
        // the rows are listed in ascending order, so no code is listed twice
        expect(contractCode > previous).toBeTrue();
        previous = contractCode;
        i += 1;
    }
    expect(i).toEqual(PINNED_EXIT_CODES);
    // the numbers as §5.2.2, §5.3.3 and §5.3.4 item 6 write them
    expect(SccpErrors.CommitteeNotAccepted as int).toEqual(402);
    expect(SccpErrors.BadProof as int).toEqual(407);
    expect(SccpErrors.BadControl as int).toEqual(420);
    expect(SccpErrors.BadSnake as int).toEqual(421);
    expect(SccpErrors.BadNonce as int).toEqual(425);
    expect(SccpErrors.NothingToRetry as int).toEqual(431);
    expect(SccpErrors.Equivocated as int).toEqual(433);
    expect(SccpErrors.LatchRequired as int).toEqual(434);
}

// ---------------------------------------------------------------------------
// The functions of `sccp-finality.tolk` behind the state machine.

get fun `test the three checkpoint slots keep the highest heights in ascending order`() {
    val empty = beginCell().storeUint(0, 2).endCell();
    expect(Checkpoints.isCanonicalEmpty(empty)).toBeTrue();
    var slots = Checkpoints.load(empty);
    expect(slots.count).toEqual(0);
    expect(slots.find(5)).toEqual(0);
    expect(slots.find(0)).toEqual(0);
    // any insertion order ends in ascending height order
    expect(slots.insert(20, 0x20)).toBeTrue();
    expect(slots.insert(10, 0x10)).toBeTrue();
    expect(slots.count).toEqual(2);
    expect(slots.h0).toEqual(10);
    expect(slots.h1).toEqual(20);
    expect(slots.insert(15, 0x15)).toBeTrue();
    expect(slots.count).toEqual(3);
    expect(slots.h0).toEqual(10);
    expect(slots.id0).toEqual(0x10);
    expect(slots.h1).toEqual(15);
    expect(slots.id1).toEqual(0x15);
    expect(slots.h2).toEqual(20);
    expect(slots.id2).toEqual(0x20);
    // a present height is never overwritten, with an equal or another id
    expect(slots.insert(15, 0x15)).toBeFalse();
    expect(slots.insert(15, 0x99)).toBeFalse();
    expect(slots.find(15)).toEqual(0x15);
    // full: a height below the lowest is not stored
    expect(slots.insert(9, 0x09)).toBeFalse();
    expect(slots.find(9)).toEqual(0);
    expect(slots.count).toEqual(3);
    // a higher height evicts the lowest, wherever it lands
    expect(slots.insert(12, 0x12)).toBeTrue();
    expect(slots.h0).toEqual(12);
    expect(slots.h1).toEqual(15);
    expect(slots.h2).toEqual(20);
    expect(slots.find(10)).toEqual(0);
    expect(slots.insert(17, 0x17)).toBeTrue();
    expect(slots.h0).toEqual(15);
    expect(slots.h1).toEqual(17);
    expect(slots.h2).toEqual(20);
    expect(slots.insert(30, 0x30)).toBeTrue();
    expect(slots.h0).toEqual(17);
    expect(slots.id0).toEqual(0x17);
    expect(slots.h1).toEqual(20);
    expect(slots.id1).toEqual(0x20);
    expect(slots.h2).toEqual(30);
    expect(slots.id2).toEqual(0x30);
    expect(slots.count).toEqual(3);
    // the cell: count:uint2 then count × (height:uint64 id:bits256), at most 962 bits
    val stored = slots.toCell();
    val s = stored.beginParse();
    expect(s.remainingBitsCount()).toEqual(2 + 3 * 320);
    expect(s.remainingRefsCount()).toEqual(0);
    expect(Checkpoints.isCanonicalEmpty(stored)).toBeFalse();
    val loaded = Checkpoints.load(stored);
    expect(loaded.count).toEqual(3);
    expect(loaded.h0).toEqual(17);
    expect(loaded.id1).toEqual(0x20);
    expect(loaded.h2).toEqual(30);
    expect(loaded.toCell().hash()).toEqual(stored.hash());
    // one and two entries
    var one = Checkpoints.load(empty);
    expect(one.insert(7, 0x77)).toBeTrue();
    expect(one.toCell().beginParse().remainingBitsCount()).toEqual(2 + 320);
    expect(Checkpoints.load(one.toCell()).find(7)).toEqual(0x77);
    expect(one.insert(3, 0x33)).toBeTrue();
    expect(one.h0).toEqual(3);
    expect(one.h1).toEqual(7);
    expect(Checkpoints.load(one.toCell()).h1).toEqual(7);
    // the empty cell is exactly two zero bits and no reference
    expect(Checkpoints.isCanonicalEmpty(beginCell().storeUint(0, 3).endCell())).toBeFalse();
    expect(Checkpoints.isCanonicalEmpty(beginCell().storeUint(1, 2).endCell())).toBeFalse();
    expect(
        Checkpoints.isCanonicalEmpty(beginCell().storeUint(0, 2).storeRef(empty).endCell()),
    ).toBeFalse();
    expect(Checkpoints.isCanonicalEmpty(asLibrary(empty))).toBeFalse();
}

/// A parsed header for the predicate tests.
fun parsedHeader(height: int, generation: int, root: int, nextRoot: int): XHeader {
    return {
        height,
        timestampMs: NOW_MS,
        flags: nextRoot == 0 ? SCCP_X_FLAG_ACTIVE : SCCP_X_FLAG_ACTIVE | SCCP_X_FLAG_ROTATION,
        messageCount: 0,
        sccpRoot: 0,
        historySize: 0,
        historyRoot: 0,
        generation,
        committeeRoot: root,
        validityMs: nextRoot == 0 ? 0 : TEST_VALIDITY_MS,
        nextCommitteeRoot: nextRoot,
        id: (height << 8) | 1,
    };
}

get fun `test the violation predicates and the checkpoint eligibility`() {
    val keys = testCommittee(4, 0).keysCell();
    val cur: CommitteeState = {
        root: 0xAA,
        untilMs: PIN_UNTIL_MS,
        start: 100,
        high: 150,
        generation: 9,
        n: 4,
        keys,
    };
    var slots = Checkpoints.load(beginCell().storeUint(0, 2).endCell());
    expect(slots.insert(120, 0x120)).toBeTrue();

    // no violation: a height in the tenure, a handoff at and above `high`
    val (none, a0, b0) = sccpViolation(parsedHeader(130, 9, 0xAA, 0), cur, slots);
    expect(none).toEqual(0);
    expect(a0).toEqual(0);
    expect(b0).toEqual(0);
    val (atHigh, _, _) = sccpViolation(parsedHeader(150, 9, 0xAA, 0xBB), cur, slots);
    expect(atHigh).toEqual(0);
    val (atStart, _, _) = sccpViolation(parsedHeader(100, 9, 0xAA, 0), cur, slots);
    expect(atStart).toEqual(0);
    // the stored header itself is no conflict
    var same = parsedHeader(120, 9, 0xAA, 0);
    same.id = 0x120;
    val (stored, _, _) = sccpViolation(same, cur, slots);
    expect(stored).toEqual(0);
    // V1: a = the stored id, b = the new id
    val other = parsedHeader(120, 9, 0xAA, 0);
    val (v1, a1, b1) = sccpViolation(other, cur, slots);
    expect(v1).toEqual(SCCP_LATCH_V1);
    expect(a1).toEqual(0x120);
    expect(b1).toEqual(other.id);
    // V2: a = X.committee_root, b = keccak256(X)
    val early = parsedHeader(99, 9, 0xAA, 0);
    val (v2, a2, b2) = sccpViolation(early, cur, slots);
    expect(v2).toEqual(SCCP_LATCH_V2);
    expect(a2).toEqual(0xAA);
    expect(b2).toEqual(early.id);
    // V3: a handoff below `high`; a non-handoff there is none
    val low = parsedHeader(149, 9, 0xAA, 0xBB);
    val (v3, a3, b3) = sccpViolation(low, cur, slots);
    expect(v3).toEqual(SCCP_LATCH_V3);
    expect(a3).toEqual(0xAA);
    expect(b3).toEqual(low.id);
    val (belowHigh, _, _) = sccpViolation(parsedHeader(149, 9, 0xAA, 0), cur, slots);
    expect(belowHigh).toEqual(0);
    // V2 is reported before V3
    val (both, _, _) = sccpViolation(parsedHeader(50, 9, 0xAA, 0xBB), cur, slots);
    expect(both).toEqual(SCCP_LATCH_V2);

    // U1: generation and root of cur
    expect(sccpCheckpointUsable(parsedHeader(120, 9, 0xAA, 0), cur)).toBeTrue();
    expect(sccpCheckpointUsable(parsedHeader(120, 9, 0xAB, 0), cur)).toBeFalse();
    expect(sccpCheckpointUsable(parsedHeader(120, 8, 0xAA, 0), cur)).toBeFalse();
    expect(sccpCheckpointUsable(parsedHeader(120, 10, 0xAA, 0), cur)).toBeFalse();
    // U2: the handoff of generation 8 at height 99 naming the root of cur
    expect(sccpCheckpointUsable(parsedHeader(99, 8, 0xCC, 0xAA), cur)).toBeTrue();
    expect(sccpCheckpointUsable(parsedHeader(98, 8, 0xCC, 0xAA), cur)).toBeFalse();
    expect(sccpCheckpointUsable(parsedHeader(99, 7, 0xCC, 0xAA), cur)).toBeFalse();
    expect(sccpCheckpointUsable(parsedHeader(99, 8, 0xCC, 0xAB), cur)).toBeFalse();
    // a non-handoff at the same place is not U2
    expect(sccpCheckpointUsable(parsedHeader(99, 8, 0xCC, 0), cur)).toBeFalse();
    // The predicate itself requires ROTATION: fields of a handoff without
    // the flag (which X6 refuses in a header) are not U2.
    var unflagged = parsedHeader(99, 8, 0xCC, 0xAA);
    unflagged.flags = SCCP_X_FLAG_ACTIVE;
    expect(sccpCheckpointUsable(unflagged, cur)).toBeFalse();
}

get fun `test Live, the rotation deadline and its saturation`() {
    // Live ⇔ ¬equivocated ∧ now_ms ≤ untilMs
    expect(sccpIsLive(false, 1000, 999)).toBeTrue();
    expect(sccpIsLive(false, 1000, 1000)).toBeTrue();
    expect(sccpIsLive(false, 1000, 1001)).toBeFalse();
    expect(sccpIsLive(true, 1000, 999)).toBeFalse();
    expect(sccpIsLive(true, 0, 0)).toBeFalse();
    // untilMs = min(t_eff + validity_ms, 2^64 − 1), t_eff = min(X.timestamp_ms, now_ms)
    var x = parsedHeader(120, 9, 0xAA, 0xBB);
    x.timestampMs = 5000;
    x.validityMs = 700;
    expect(sccpRotationUntilMs(x, 9000)).toEqual(5700);
    expect(sccpRotationUntilMs(x, 5000)).toEqual(5700);
    expect(sccpRotationUntilMs(x, 4000)).toEqual(4700);
    // the sum saturates instead of leaving the u64 range
    x.timestampMs = SCCP_MAX_U64;
    x.validityMs = SCCP_MAX_VALIDITY_MS;
    expect(sccpRotationUntilMs(x, SCCP_MAX_U64)).toEqual(SCCP_MAX_U64);
    expect(sccpRotationUntilMs(x, SCCP_MAX_U64 - SCCP_MAX_VALIDITY_MS)).toEqual(SCCP_MAX_U64);
    expect(
        sccpRotationUntilMs(x, SCCP_MAX_U64 - SCCP_MAX_VALIDITY_MS - 1),
    ).toEqual(SCCP_MAX_U64 - 1);
    // TON's clock is a 32-bit unixtime in seconds, far below that
    expect(sccpNowMs()).toEqual(testing.getNow() * 1000);
}
