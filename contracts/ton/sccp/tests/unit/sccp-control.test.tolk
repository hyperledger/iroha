// Parliament and fast-pause controls (specs/sccp.md §3.4, §5.1.6, §5.3.4
// "Checkpoint and apply control"): the control leaf of the TON lane, both
// tracks, the nonce rule, the fast-pause expiry and clamp, leaves of another
// lane, destination or revision, the §3.4 constraints, the check order of the
// minter step, and what stays open while minting is paused.
//
// `control_v1.json` gives the TON control leaves, which this suite replays
// row by row, and the `applyControl` scenarios (`destination_effects`), whose
// rows are of the EVM flavour: their leaves commit to an EVM destination
// word. Each of those scenarios is rebuilt here for the minter at `0:35…35`
// with the same clock values, heights, nonces and expiries, under
// certificates signed in the test VM.
// TODO: WP-TON (reference fixtures): replay the TON rows of
// `destination_effects` from the generated vectors once the reference
// emits them (`control_v1.json` carries that TODO).

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
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Destination clock at which every test of this suite starts, in ms.
const NOW_MS = 1800000000000
/// `cur.untilMs` of the default pin: 14 days after `NOW_MS`.
const PIN_UNTIL_MS = 1801209600000
/// TON rows of `controls` in `control_v1.json`, and the rows of
/// `destination_effects` that this suite rebuilds.
const PINNED_CONTROL_LEAVES = 12
const PINNED_CONTROL_SCENARIOS = 10
/// The certificate id and the effect hash of the `rejected` rows.
const REJECTED_CERTIFICATE_ID = 0x3333333333333333333333333333333333333333333333333333333333333333
const REJECTED_EFFECT_HASH = 0x4444444444444444444444444444444444444444444444444444444444444444

// ---------------------------------------------------------------------------
// Builders of this suite.

/// A control with its fields given one by one, and deterministic nonzero
/// certificate id and effect hash.
fun controlOf(nonce: int, track: int, parliamentPaused: bool, fastPauseUntilMs: int): TestControl {
    var control = parliamentControl(nonce, parliamentPaused);
    control.track = track;
    control.fastPauseUntilMs = fastPauseUntilMs;
    return control;
}

/// A Taira block of the pinned generation at `height` with its leaves.
struct TestBlock {
    leaves: array<int>
    x: TestX
    cert: cell
}

/// Certifies the block of `leaves` at `height` by the pinned generation.
fun blockAt(env: Env, height: int, leaves: array<int>): TestBlock {
    val x = blockX(env.networkId, env.generation, env.committee.root(), height, leaves);
    return {
        leaves,
        x,
        cert: certifyFor(env, env.committee, x),
    };
}

/// The `^ControlProof` of `control` at leaf `index` of the block.
fun TestBlock.controlProof(self, control: TestControl, index: int): cell {
    return controlProofCell(
        control.nonce,
        control.track,
        control.parliamentPaused,
        control.fastPauseUntilMs,
        control.certificateId,
        control.effectHash,
        index,
        treePath(self.leaves, index),
        ownBlockRef(self.x),
    );
}

/// Applies `control` at leaf `index` of the block inline, with its certificate.
fun TestBlock.applyInline(self, env: Env, control: TestControl, index: int): SendResultList {
    return controlInline(env, self.cert, self.controlProof(control, index), grams("1"));
}

/// Applies `control` at leaf `index` of the block against its stored checkpoint.
fun TestBlock.applyStored(self, env: Env, control: TestControl, index: int): SendResultList {
    return controlStored(env, self.x.ref(), self.controlProof(control, index), grams("1"));
}

/// A transfer of `amount` to `recipient` and its leaf for `env.minter`.
struct TestTransfer {
    payload: cell
    leaf: int
    messageId: int
}

fun transferOf(
    env: Env,
    nonce: int,
    amount: int,
    recipient: address,
    deadlineMs: int,
): TestTransfer {
    val payload = inboundPayloadCell(
        nonce,
        TEST_REVISION,
        deadlineMs,
        amount,
        recipient.accountId(),
    );
    return {
        payload,
        leaf: inboundLeaf(env.networkId, payload, env.minter.address),
        messageId: inboundMessageId(env.networkId, payload, env.minter.address),
    };
}

/// The `^MessageProof` of `transfer` at leaf `index` of the block.
fun TestBlock.transferProof(self, transfer: TestTransfer, index: int): cell {
    return messageProofCell(
        index,
        treePath(self.leaves, index),
        transfer.payload,
        ownBlockRef(self.x),
    );
}

/// Expects the control nonce and the pause state of the minter at the
/// current clock.
fun expectPause(
    env: Env,
    controlNonce: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    effectivePaused: bool,
) {
    val state = env.minter.getSccpState();
    expect(state.controlNonce).toEqual(controlNonce);
    expect(state.parliamentPaused).toEqual(parliamentPaused);
    expect(state.fastPauseUntilMs).toEqual(fastPauseUntilMs);
    expect(state.effectivePaused).toEqual(effectivePaused);
    // the getter's verdict is the rule of §5.1.6 at the clock of the call
    expect(
        sccpEffectivePause(parliamentPaused, fastPauseUntilMs, testing.getNow() * 1000),
    ).toEqual(effectivePaused);
}

/// Expects the operation counter of the minter.
fun expectOps(env: Env, opCount: int) {
    expect(env.minter.getSccpState().opCount).toEqual(opCount);
}

/// Expects a refused control: its exit code, no event and no control applied.
fun expectRefused(env: Env, res: SendResultList, exitCode: int) {
    if (outcomeOf(res) != exitCode) {
        println("expected {} observed {}", exitCode, outcomeOf(res));
    }
    expectOutcome(res, exitCode);
    expectEvents(res, []);
    val state = env.minter.getSccpState();
    expect(state.controlNonce).toEqual(0);
    expect(state.parliamentPaused).toBeFalse();
    expect(state.fastPauseUntilMs).toEqual(0);
    expect(state.opCount).toEqual(0);
}

/// Body of `sccp_control_applied` for `control` with the stored expiry.
fun eventApplied(control: TestControl, fastPauseUntilMs: int): cell {
    return eventControlApplied(
        control.nonce,
        control.track,
        control.parliamentPaused,
        fastPauseUntilMs,
        control.certificateId,
    );
}

/// The control leaf of the TON lane of `env.minter` for arbitrary fields.
fun leafOfFields(
    env: Env,
    revision: int,
    nonce: int,
    track: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    certificateId: int,
    effectHash: int,
): int {
    return controlLeafFor(
        env.networkId,
        SCCP_TAG_TON,
        SCCP_TON_IDENTITY_WORD,
        env.minter.address.accountId(),
        revision,
        nonce,
        track,
        parliamentPaused,
        fastPauseUntilMs,
        certificateId,
        effectHash,
    );
}

/// Sends `sccp_apply_control` from the deployer with the `^TairaCert` `cert`
/// and the `^ControlProof` `proof`.
fun controlInline(env: Env, cert: cell, proof: cell, value: coins): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        cert,
        null,
        proof,
        value,
    );
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

/// A deployed and initialized pinned minter of route revision `revision`
/// with a committee of the first four test keys.
fun setupEnvOfRevision(revision: int): Env {
    testing.setNow(T0);
    val deployer = testing.treasury("deployer");
    val committee = testCommittee(4, 0);
    val minter = deployPinned(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            revision,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        ),
        deployer.address,
        grams("10"),
    );
    return {
        minter,
        deployer: deployer.address,
        networkId: VEC_NETWORK_ID,
        instance: VEC_CONSENSUS_INSTANCE,
        generation: TEST_GENERATION,
        committee,
    };
}

// ---------------------------------------------------------------------------
// The control leaf of the TON lane (`controls` of `control_v1.json`).

get fun `test every TON control leaf of the fixture is the leaf the contract computes`() {
    expect(VEC_CONTROL_LEAF_COUNT).toEqual(PINNED_CONTROL_LEAVES);
    var row = 0;
    var tracks = 0;
    repeat (VEC_CONTROL_LEAF_COUNT) {
        val leaf = vecControlLeaf(row);
        // the two HASHEXT builders of the 199-byte preimage: 125 and 74 bytes
        expect(leaf.b1.remainingBitsCount()).toEqual(125 * 8);
        expect(leaf.b2.remainingBitsCount()).toEqual(74 * 8);
        expect(keccak256Slices2(leaf.b1, leaf.b2)).toEqual(leaf.leaf);
        expect(
            sccpControlLeaf(
                VEC_NETWORK_ID,
                VEC_MINTER_ACCOUNT_ID,
                leaf.routeRevision,
                leaf.controlNonce,
                leaf.track,
                leaf.parliamentPaused,
                leaf.fastPauseUntilMs,
                leaf.certificateId,
                leaf.effectHash,
            ),
        ).toEqual(leaf.leaf);
        // the lane is (sora-taira, ton-mainnet): tag 0x44, identity word int256(−239)
        expect(
            controlLeafFor(
                VEC_NETWORK_ID,
                SCCP_TAG_TON,
                SCCP_TON_IDENTITY_WORD,
                VEC_MINTER_ACCOUNT_ID,
                leaf.routeRevision,
                leaf.controlNonce,
                leaf.track,
                leaf.parliamentPaused,
                leaf.fastPauseUntilMs,
                leaf.certificateId,
                leaf.effectHash,
            ),
        ).toEqual(leaf.leaf);
        // every field enters the leaf
        expect(
            sccpControlLeaf(
                VEC_NETWORK_ID,
                VEC_MINTER_ACCOUNT_ID,
                leaf.routeRevision,
                leaf.controlNonce,
                leaf.track,
                !leaf.parliamentPaused,
                leaf.fastPauseUntilMs,
                leaf.certificateId,
                leaf.effectHash,
            ) ==
                leaf.leaf,
        ).toBeFalse();
        tracks |= 1 << leaf.track;
        row += 1;
    }
    expect(row).toEqual(PINNED_CONTROL_LEAVES);
    // both tracks are among the rows
    expect(tracks).toEqual((1 << SCCP_TRACK_PARLIAMENT) | (1 << SCCP_TRACK_FAST_PAUSE));
    // int256(−239) as a word: 2^256 − 239
    expect(
        SCCP_TON_IDENTITY_WORD,
    ).toEqual(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - 238);
}

get fun `test every TON control leaf of the fixture applies on the minter of its revision`() {
    var row = 0;
    var revisions = 0;
    repeat (VEC_CONTROL_LEAF_COUNT) {
        val leaf = vecControlLeaf(row);
        // a fresh minter of the row's revision at the account id the leaf commits to
        val env = setupEnvOfRevision(leaf.routeRevision);
        expect(env.minter.address.accountId()).toEqual(VEC_MINTER_ACCOUNT_ID);
        expect(env.minter.getSccpState().routeRevision).toEqual(leaf.routeRevision);
        // Taira certifies a block with the recorded leaf, as the fixture gives it
        val block = blockAt(env, TEST_START_HEIGHT + 10, [leaf.leaf, fillerLeaf(1)]);
        val control: TestControl = {
            nonce: leaf.controlNonce,
            track: leaf.track,
            parliamentPaused: leaf.parliamentPaused,
            fastPauseUntilMs: leaf.fastPauseUntilMs,
            certificateId: leaf.certificateId,
            effectHash: leaf.effectHash,
        };
        val res = block.applyInline(env, control, 0);
        if (outcomeOf(res) != 0) {
            println("control leaf row {} observed {}", row, outcomeOf(res));
        }
        expectOutcome(res, 0);
        // no expiry of the rows is beyond the clamp
        expect(leaf.fastPauseUntilMs <= NOW_MS + SCCP_MAX_FAST_PAUSE_MS).toBeTrue();
        expectEvents(
            res,
            [
                eventCertificate(block.x.height, env.generation, block.cert),
                eventCheckpointed(block.x.height, block.x.id()),
                eventApplied(control, leaf.fastPauseUntilMs),
            ],
        );
        expectPause(
            env,
            leaf.controlNonce,
            leaf.parliamentPaused,
            leaf.fastPauseUntilMs,
            leaf.parliamentPaused | (NOW_MS < leaf.fastPauseUntilMs),
        );
        expectOps(env, 1);
        // the leaf of another revision does not apply here
        val other = setupEnvOfRevision(leaf.routeRevision + 1);
        val refused = blockAt(
            other,
            TEST_START_HEIGHT + 10,
            [leaf.leaf, fillerLeaf(1)],
        ).applyInline(other, control, 0);
        expectRefused(other, refused, SccpErrors.BadProof);
        revisions |= 1 << leaf.routeRevision;
        row += 1;
    }
    expect(row).toEqual(PINNED_CONTROL_LEAVES);
    // the rows are of revisions 1 and 7
    expect(revisions).toEqual((1 << 1) | (1 << 7));
}

// ---------------------------------------------------------------------------
// The `applyControl` scenarios of `control_v1.json`, in the TON flavour.

get fun `test control scenario parliament_pause_then_fast_pause_then_lapse`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val until = (T0 + 7200) * 1000;
    val fast = controlOf(2, SCCP_TRACK_FAST_PAUSE, true, until);
    val transfer = transferOf(env, 0, 1000, alice, NOW_MS + DAY_MS);
    val first = blockAt(env, 1010, [controlLeafOf(env, pause)]);
    val second = blockAt(env, 1020, [controlLeafOf(env, fast), transfer.leaf]);

    testing.setNow(T0 + 600);
    val applied = first.applyInline(env, pause, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1010, env.generation, first.cert),
            eventCheckpointed(1010, first.x.id()),
            eventApplied(pause, 0),
        ],
    );
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);

    testing.setNow(T0 + 1200);
    val fastApplied = second.applyInline(env, fast, 0);
    expectOutcome(fastApplied, 0);
    expectEvents(
        fastApplied,
        [
            eventCertificate(1020, env.generation, second.cert),
            eventCheckpointed(1020, second.x.id()),
            eventApplied(fast, until),
        ],
    );
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);

    testing.setNow(T0 + 3600);
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);
    // after the lapse of the fast pause the Parliament pause stays in force
    testing.setNow(T0 + 10800);
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);
    val refused = finalizeStored(
        env,
        second.x.ref(),
        second.transferProof(transfer, 1),
        finalizeValue(env, 0),
    );
    expectOutcome(refused, SccpErrors.MintingIsPaused);
    expectEvents(refused, []);
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);
}

get fun `test control scenario fast_pause_then_parliament_pause_then_lapse`() {
    val env = setupEnv();
    val until = (T0 + 7200) * 1000;
    val fast = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, until);
    // the Parliament leaf carries the live fast pause
    val pause = controlOf(2, SCCP_TRACK_PARLIAMENT, true, until);
    val block = blockAt(env, 1030, [controlLeafOf(env, fast), controlLeafOf(env, pause)]);

    testing.setNow(T0 + 600);
    val applied = block.applyInline(env, fast, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1030, env.generation, block.cert),
            eventCheckpointed(1030, block.x.id()),
            eventApplied(fast, until),
        ],
    );
    expectPause(env, 1, false, until, true);
    expectOps(env, 1);

    testing.setNow(T0 + 1200);
    val paused = block.applyStored(env, pause, 1);
    expectOutcome(paused, 0);
    expectEvents(paused, [eventApplied(pause, until)]);
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);

    testing.setNow(T0 + 10800);
    expectPause(env, 2, true, until, true);
    expectOps(env, 2);
}

get fun `test control scenario track2_leaf_after_expiry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    // a fast-pause leaf delivered after its expiry
    val until = (T0 + 3600) * 1000;
    val fast = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, until);
    val transfer = transferOf(env, 0, 1000, alice, NOW_MS + DAY_MS);
    val block = blockAt(env, 1040, [controlLeafOf(env, fast), transfer.leaf]);

    testing.setNow(T0 + 7200);
    val applied = block.applyInline(env, fast, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1040, env.generation, block.cert),
            eventCheckpointed(1040, block.x.id()),
            eventApplied(fast, until),
        ],
    );
    // it consumes its nonce and does not pause
    expectPause(env, 1, false, until, false);
    expectOps(env, 1);
    val res = finalizeStored(
        env,
        block.x.ref(),
        block.transferProof(transfer, 1),
        finalizeValue(env, 0),
    );
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expectPause(env, 1, false, until, false);
    expectOps(env, 2);
}

get fun `test control scenario stale_equal_and_gap_nonces`() {
    val env = setupEnv();
    val three = controlOf(3, SCCP_TRACK_PARLIAMENT, true, 0);
    val two = controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0);
    val five = controlOf(5, SCCP_TRACK_PARLIAMENT, false, 0);
    val block = blockAt(
        env,
        1050,
        [controlLeafOf(env, three), controlLeafOf(env, two), controlLeafOf(env, five)],
    );

    testing.setNow(T0 + 600);
    val applied = block.applyInline(env, three, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1050, env.generation, block.cert),
            eventCheckpointed(1050, block.x.id()),
            eventApplied(three, 0),
        ],
    );
    expectPause(env, 3, true, 0, true);
    expectOps(env, 1);

    // an older nonce and the equal nonce are stale
    testing.setNow(T0 + 660);
    val older = block.applyStored(env, two, 1);
    expectOutcome(older, SccpErrors.StaleControl);
    expectEvents(older, []);
    expectPause(env, 3, true, 0, true);
    expectOps(env, 1);
    testing.setNow(T0 + 720);
    val equal = block.applyStored(env, three, 0);
    expectOutcome(equal, SccpErrors.StaleControl);
    expectEvents(equal, []);
    expectPause(env, 3, true, 0, true);
    expectOps(env, 1);

    // 5 is accepted across the gap
    testing.setNow(T0 + 780);
    val newest = block.applyStored(env, five, 2);
    expectOutcome(newest, 0);
    expectEvents(newest, [eventApplied(five, 0)]);
    expectPause(env, 5, false, 0, false);
    expectOps(env, 2);
}

get fun `test control scenario max_fast_pause_clamp`() {
    val env = setupEnv();
    // an expiry 40 days ahead
    val leafUntil = 1803456360000;
    val fast = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, leafUntil);
    val block = blockAt(env, 1060, [controlLeafOf(env, fast)]);

    testing.setNow(T0 + 600);
    val clamped = (T0 + 600) * 1000 + SCCP_MAX_FAST_PAUSE_MS;
    expect(clamped).toEqual(1802592600000);
    expect(leafUntil > clamped).toBeTrue();
    val applied = block.applyInline(env, fast, 0);
    expectOutcome(applied, 0);
    // the event carries the stored, clamped expiry
    expectEvents(
        applied,
        [
            eventCertificate(1060, env.generation, block.cert),
            eventCheckpointed(1060, block.x.id()),
            eventApplied(fast, clamped),
        ],
    );
    expectPause(env, 1, false, clamped, true);
    expectOps(env, 1);

    testing.setNow(clamped / 1000 - 1);
    expectPause(env, 1, false, clamped, true);
    expectOps(env, 1);
    testing.setNow(clamped / 1000);
    expectPause(env, 1, false, clamped, false);
    expectOps(env, 1);
}

get fun `test control scenario fast_pause_local_expiry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val until = (T0 + 7200) * 1000;
    val fast = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, until);
    val minted = transferOf(env, 0, 1000, alice, NOW_MS + DAY_MS);
    val voided = transferOf(env, 1, 500, alice, (T0 + 1800) * 1000);
    val block = blockAt(env, 1070, [controlLeafOf(env, fast), minted.leaf, voided.leaf]);

    testing.setNow(T0 + 600);
    val applied = block.applyInline(env, fast, 0);
    expectOutcome(applied, 0);
    expectPause(env, 1, false, until, true);
    expectOps(env, 1);

    // minting is paused while now < fastPauseUntilMs
    testing.setNow(T0 + 1200);
    expectOutcome(
        finalizeStored(env, block.x.ref(), block.transferProof(minted, 1), finalizeValue(env, 0)),
        SccpErrors.MintingIsPaused,
    );
    // checkpoints work while paused
    val other = emptyX(env.networkId, env.generation, env.committee.root(), 1071);
    val otherCert = certifyFor(env, env.committee, other);
    val stored = sendCheckpoint(env, env.deployer, otherCert, null, grams("1"));
    expectOutcome(stored, 0);
    expectEvents(
        stored,
        [eventCertificate(1071, env.generation, otherCert), eventCheckpointed(1071, other.id())],
    );
    expectPause(env, 1, false, until, true);
    expectOps(env, 1);

    // voids work while paused: early at the deadline, accepted after it
    testing.setNow(T0 + 1800);
    expectOutcome(
        voidStored(
            env,
            1,
            block.x.ref(),
            block.transferProof(voided, 2),
            env.minter.voidRequiredValue(1),
        ),
        SccpErrors.DeadlineNotReached,
    );
    testing.setNow(T0 + 3600);
    val void = voidStored(
        env,
        1,
        block.x.ref(),
        block.transferProof(voided, 2),
        env.minter.voidRequiredValue(1),
    );
    expect(void).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(void).toEmitExternalMessage<SccpVoidedEvent>();
    expectPause(env, 1, false, until, true);
    expectOps(env, 2);

    // paused at the last clock value below the expiry, minting at the expiry with no relay
    testing.setNow(T0 + 7199);
    expectOutcome(
        finalizeStored(env, block.x.ref(), block.transferProof(minted, 1), finalizeValue(env, 0)),
        SccpErrors.MintingIsPaused,
    );
    testing.setNow(T0 + 7200);
    val mint = finalizeStored(
        env,
        block.x.ref(),
        block.transferProof(minted, 1),
        finalizeValue(env, 0),
    );
    expect(mint).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expectPause(env, 1, false, until, false);
    expectOps(env, 3);
}

get fun `test control scenario pause_then_resume`() {
    val env = setupEnv();
    // a Parliament pause and its resume in one block
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val resume = controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0);
    val block = blockAt(env, 1080, [controlLeafOf(env, pause), controlLeafOf(env, resume)]);

    testing.setNow(T0 + 600);
    val applied = block.applyInline(env, pause, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1080, env.generation, block.cert),
            eventCheckpointed(1080, block.x.id()),
            eventApplied(pause, 0),
        ],
    );
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);

    testing.setNow(T0 + 660);
    val resumed = block.applyStored(env, resume, 1);
    expectOutcome(resumed, 0);
    expectEvents(resumed, [eventApplied(resume, 0)]);
    expectPause(env, 2, false, 0, false);
    expectOps(env, 2);
}

get fun `test control scenario historical_control_proof`() {
    val env = setupEnv();
    // a control of block 1010 proven through the history path of X_1100
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val leaf = controlLeafOf(env, pause);
    // entry 0 of a history of 12 blocks: four siblings
    val history = historyLeaves(12, 0, 1010, leaf, 1);
    val path = treePath(history, 0);
    expect(path.size()).toEqual(4);
    var x = emptyX(env.networkId, env.generation, env.committee.root(), 1100);
    x.historySize = 12;
    x.historyRoot = treeRoot(history);
    val cert = certifyFor(env, env.committee, x);
    val proof = controlProofCell(
        pause.nonce,
        pause.track,
        pause.parliamentPaused,
        pause.fastPauseUntilMs,
        pause.certificateId,
        pause.effectHash,
        0,
        [],
        blockRefCell(1010, leaf, 1, 0, path),
    );

    testing.setNow(T0 + 900);
    val applied = controlInline(env, cert, proof, grams("1"));
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1100, env.generation, cert),
            eventCheckpointed(1100, x.id()),
            eventApplied(pause, 0),
        ],
    );
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);
    // the checkpoint recorded is that of the certified block
    replayExpectCheckpoints(
        env,
        1,
        1100,
        x.id(),
        0,
        0,
        0,
        0,
    );
}

get fun `test control scenario foreign_and_malformed_controls`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val own = env.minter.address.accountId();
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    // the fields of a leaf whose track is not a track
    var malformed = controlOf(1, 3, false, 0);
    val transfer = transferOf(env, 0, 1000, alice, NOW_MS + DAY_MS);
    val block = blockAt(
        env,
        1090,
        [
            // another target network (ethereum-mainnet), with this destination word
            controlLeafFor(
                env.networkId,
                0x41,
                1,
                own,
                TEST_REVISION,
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                pause.certificateId,
                pause.effectHash,
            ),
            // another Taira network
            controlLeafFor(
                env.networkId ^ 1,
                SCCP_TAG_TON,
                SCCP_TON_IDENTITY_WORD,
                own,
                TEST_REVISION,
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                pause.certificateId,
                pause.effectHash,
            ),
            // another revision
            leafOfFields(
                env,
                TEST_REVISION + 1,
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                pause.certificateId,
                pause.effectHash,
            ),
            // another destination
            controlLeafFor(
                env.networkId,
                SCCP_TAG_TON,
                SCCP_TON_IDENTITY_WORD,
                own ^ 1,
                TEST_REVISION,
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                pause.certificateId,
                pause.effectHash,
            ),
            // a recorded leaf that violates a §3.4 constraint
            controlLeafOf(env, malformed),
            // a transfer leaf
            transfer.leaf,
        ],
    );

    testing.setNow(T0 + 900);
    var index = 0;
    repeat (4) {
        expectRefused(env, block.applyInline(env, pause, index), SccpErrors.BadProof);
        index += 1;
    }
    // a transfer leaf offered as a control
    expectRefused(env, block.applyInline(env, pause, 5), SccpErrors.BadProof);
    // the certified leaf of refused fields answers BadControl
    expectRefused(env, block.applyInline(env, malformed, 4), SccpErrors.BadControl);
    // a checkpoint that is not stored
    expectRefused(env, block.applyStored(env, pause, 0), SccpErrors.UnknownCheckpoint);
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

    // after the deadline of the generation a genuine control is refused
    val genuine = blockAt(env, 1010, [controlLeafOf(env, pause)]);
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expectRefused(env, genuine.applyInline(env, pause, 0), SccpErrors.CommitteeNotAccepted);
}

get fun `test control scenario fast_pause_sub_second_expiry`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    // an expiry ending in 001 ms
    val until = (T0 + 7200) * 1000 + 1;
    val fast = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, until);
    val transfer = transferOf(env, 0, 1000, alice, NOW_MS + DAY_MS);
    val block = blockAt(env, 1110, [controlLeafOf(env, fast), transfer.leaf]);

    testing.setNow(T0 + 1200);
    val applied = block.applyInline(env, fast, 0);
    expectOutcome(applied, 0);
    expectEvents(
        applied,
        [
            eventCertificate(1110, env.generation, block.cert),
            eventCheckpointed(1110, block.x.id()),
            eventApplied(fast, until),
        ],
    );
    expectPause(env, 1, false, until, true);
    expectOps(env, 1);

    // paused at the last clock value below the expiry (1 ms earlier)
    testing.setNow(T0 + 7200);
    expectPause(env, 1, false, until, true);
    expectOps(env, 1);
    expectOutcome(
        finalizeStored(env, block.x.ref(), block.transferProof(transfer, 1), finalizeValue(env, 0)),
        SccpErrors.MintingIsPaused,
    );
    // minting at the next one (999 ms later)
    testing.setNow(T0 + 7201);
    expectPause(env, 1, false, until, false);
    expectOps(env, 1);
    val mint = finalizeStored(
        env,
        block.x.ref(),
        block.transferProof(transfer, 1),
        finalizeValue(env, 0),
    );
    expect(mint).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    expectPause(env, 1, false, until, false);
    expectOps(env, 2);
}

get fun `test the control scenarios cover the pinned rows of the fixture`() {
    // one test above per row of `destination_effects`, by the row's name
    val scenarios: array<string> = [
        "parliament_pause_then_fast_pause_then_lapse",
        "fast_pause_then_parliament_pause_then_lapse",
        "track2_leaf_after_expiry",
        "stale_equal_and_gap_nonces",
        "max_fast_pause_clamp",
        "fast_pause_local_expiry",
        "pause_then_resume",
        "historical_control_proof",
        "foreign_and_malformed_controls",
        "fast_pause_sub_second_expiry",
    ];
    expect(scenarios.size()).toEqual(PINNED_CONTROL_SCENARIOS);
    expect(VEC_MAX_FAST_PAUSE_MS).toEqual(SCCP_MAX_FAST_PAUSE_MS);
}

// ---------------------------------------------------------------------------
// The §3.4 constraints (`rejected` of `control_v1.json`).

get fun `test a certified leaf that violates a constraint is BadControl`() {
    val env = setupEnv();
    // the rows of `rejected` that a destination can be offered, for this lane
    var rows: array<TestControl> = [];
    val base: TestControl = {
        nonce: 1,
        track: SCCP_TRACK_PARLIAMENT,
        parliamentPaused: true,
        fastPauseUntilMs: 0,
        certificateId: REJECTED_CERTIFICATE_ID,
        effectHash: REJECTED_EFFECT_HASH,
    };
    // track_0, track_3
    var row = base;
    row.track = 0;
    rows.push(row);
    row = base;
    row.track = 3;
    rows.push(row);
    // fast_pause_track_zero_expiry
    row = base;
    row.track = SCCP_TRACK_FAST_PAUSE;
    row.parliamentPaused = false;
    rows.push(row);
    // zero_certificate_id, zero_effect_hash
    row = base;
    row.certificateId = 0;
    rows.push(row);
    row = base;
    row.effectHash = 0;
    rows.push(row);
    // a track that is no small integer, and a fast pause with both pause flags
    row = base;
    row.track = 255;
    rows.push(row);
    row = base;
    row.track = SCCP_TRACK_FAST_PAUSE;
    rows.push(row);
    var leaves: array<int> = [];
    var i = 0;
    repeat (rows.size()) {
        leaves.push(controlLeafOf(env, rows.get(i)));
        i += 1;
    }
    val block = blockAt(env, 1010, leaves);
    i = 0;
    repeat (rows.size()) {
        // the leaf is certified and its path verifies: the fields are refused
        expectRefused(env, block.applyInline(env, rows.get(i), i), SccpErrors.BadControl);
        expect(
            sccpMerkleRoot(leaves.get(i), i, leaves.size(), treePath(leaves, i)),
        ).toEqual(block.x.sccpRoot);
        i += 1;
    }
    expect(i).toEqual(7);
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

    // zero_revision: the leaf of revision 0 is not a leaf of this lane
    val zeroRevision = blockAt(
        env,
        1011,
        [
            leafOfFields(
                env,
                0,
                1,
                SCCP_TRACK_PARLIAMENT,
                true,
                0,
                REJECTED_CERTIFICATE_ID,
                REJECTED_EFFECT_HASH,
            ),
        ],
    );
    expectRefused(env, zeroRevision.applyInline(env, base, 0), SccpErrors.BadProof);
    // zero_control_nonce: a valid leaf whose nonce is not above the stored 0
    var zeroNonce = base;
    zeroNonce.nonce = 0;
    val zeroNonceBlock = blockAt(env, 1012, [controlLeafOf(env, zeroNonce)]);
    expectRefused(env, zeroNonceBlock.applyInline(env, zeroNonce, 0), SccpErrors.StaleControl);
    // the fields of the rows that are valid apply
    val valid = blockAt(env, 1013, [controlLeafOf(env, base)]);
    expectOutcome(valid.applyInline(env, base, 0), 0);
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);
}

get fun `test the constraints are checked after the leaf path and before the nonce`() {
    val env = setupEnv();
    applyControlOk(env, 5, false);
    // a leaf with track 3 and a nonce below the stored one is BadControl, not StaleControl
    var malformed = controlOf(2, 3, false, 0);
    val block = blockAt(env, 1200, [controlLeafOf(env, malformed), fillerLeaf(1)]);
    val refused = block.applyInline(env, malformed, 0);
    expectOutcome(refused, SccpErrors.BadControl);
    expectEvents(refused, []);
    // the same fields against a leaf that is not in the block: the path answers first
    expectOutcome(block.applyInline(env, malformed, 1), SccpErrors.BadProof);
    // valid fields with a stale nonce
    val stale = controlOf(2, SCCP_TRACK_PARLIAMENT, true, 0);
    val staleBlock = blockAt(env, 1201, [controlLeafOf(env, stale)]);
    expectOutcome(staleBlock.applyInline(env, stale, 0), SccpErrors.StaleControl);
    expectPause(env, 5, false, 0, false);
    expectOps(env, 1);

    // the function: each constraint on its own
    val cases: array<[int, int, int, int]> = [
        [0, 0, 1, 1],
        [3, 0, 1, 1],
        [SCCP_TRACK_FAST_PAUSE, 0, 1, 1],
        [SCCP_TRACK_PARLIAMENT, 0, 0, 1],
        [SCCP_TRACK_PARLIAMENT, 0, 1, 0],
        [SCCP_TRACK_FAST_PAUSE, 5, 0, 1],
    ];
    var i = 0;
    repeat (cases.size()) {
        val [track, until, certificateId, effectHash] = cases.get(i);
        var code = 0;
        try {
            sccpCheckControl(track, until, certificateId, effectHash);
        } catch (thrown) {
            code = thrown;
        }
        expect(code).toEqual(SccpErrors.BadControl as int);
        i += 1;
    }
    expect(i).toEqual(6);
    // a Parliament control may carry an expiry, and a fast pause must
    sccpCheckControl(SCCP_TRACK_PARLIAMENT, 0, 1, 1);
    sccpCheckControl(SCCP_TRACK_PARLIAMENT, 5, 1, 1);
    sccpCheckControl(SCCP_TRACK_FAST_PAUSE, 1, 1, 1);
}

// ---------------------------------------------------------------------------
// Applying controls.

get fun `test pause blocks finalization and resume re-enables it`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val res = applyControlOk(env, 1, true);
    val event = res
        .findExternalOutMessage<SccpControlAppliedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.controlNonce).toEqual(1);
    expect(event.track).toEqual(SCCP_TRACK_PARLIAMENT);
    expect(event.parliamentPaused).toBeTrue();
    expect(event.fastPauseUntilMs).toEqual(0);
    expect(event.certificateId).toEqual(parliamentControl(1, true).certificateId);
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    expect(res).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().opCount).toEqual(1);
    reportGas("apply control inline n=4", stepGas(res), SCCP_GAS_MINTER_APPLY_CONTROL);
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

get fun `test apply control with a committee of 31`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    val res = applyControlOk(env, 1, true);
    reportGas("apply control inline n=31", stepGas(res), SCCP_GAS_MINTER_APPLY_CONTROL);
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);
}

get fun `test stale and equal control nonces are rejected and gaps are accepted`() {
    val env = setupEnv();
    // every control is certified in a block of its own
    var height = 1200;
    val first = controlOf(2, SCCP_TRACK_PARLIAMENT, true, 0);
    expectOutcome(blockAt(env, height, [controlLeafOf(env, first)]).applyInline(env, first, 0), 0);
    expectPause(env, 2, true, 0, true);
    expectOps(env, 1);
    // the equal nonce with another value, and an older nonce
    val stale: array<TestControl> = [
        controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0),
        controlOf(1, SCCP_TRACK_PARLIAMENT, false, 0),
        controlOf(1, SCCP_TRACK_FAST_PAUSE, false, NOW_MS + DAY_MS),
    ];
    var i = 0;
    repeat (stale.size()) {
        height += 1;
        val res = blockAt(env, height, [controlLeafOf(env, stale.get(i))]).applyInline(
            env,
            stale.get(i),
            0,
        );
        expect(res).toHaveFailedTx<SccpApplyControl>({
            to: env.minter.address,
            exitCode: SccpErrors.StaleControl as int,
        });
        expectEvents(res, []);
        expectPause(env, 2, true, 0, true);
        expectOps(env, 1);
        i += 1;
    }
    // a gap is accepted: only the newest control needs to be applied
    height += 1;
    val resume = controlOf(7, SCCP_TRACK_PARLIAMENT, false, 0);
    expectOutcome(
        blockAt(env, height, [controlLeafOf(env, resume)]).applyInline(env, resume, 0),
        0,
    );
    expectPause(env, 7, false, 0, false);
    expectOps(env, 2);
    // pause, resume and pause again as three distinct controls
    height += 1;
    val again = controlOf(8, SCCP_TRACK_PARLIAMENT, true, 0);
    expectOutcome(blockAt(env, height, [controlLeafOf(env, again)]).applyInline(env, again, 0), 0);
    expectPause(env, 8, true, 0, true);
    expectOps(env, 3);
    // a zero nonce can never apply
    height += 1;
    val zero = controlOf(0, SCCP_TRACK_PARLIAMENT, false, 0);
    expectOutcome(
        blockAt(env, height, [controlLeafOf(env, zero)]).applyInline(env, zero, 0),
        SccpErrors.StaleControl,
    );
    // a refused control changed nothing
    expectPause(env, 8, true, 0, true);
    expectOps(env, 3);
}

get fun `test the largest control nonce applies and nothing applies after it`() {
    val env = setupEnv();
    applyControlOk(env, 1, true);
    val last = controlOf(SCCP_MAX_U64, SCCP_TRACK_PARLIAMENT, false, 0);
    val block = blockAt(env, 1200, [controlLeafOf(env, last)]);
    expectOutcome(block.applyInline(env, last, 0), 0);
    expectPause(env, SCCP_MAX_U64, false, 0, false);
    expectOps(env, 2);
    // every later control is stale, whatever its nonce
    val later = controlOf(SCCP_MAX_U64 - 1, SCCP_TRACK_PARLIAMENT, true, 0);
    val laterBlock = blockAt(env, 1201, [controlLeafOf(env, later), controlLeafOf(env, last)]);
    expectOutcome(laterBlock.applyInline(env, later, 0), SccpErrors.StaleControl);
    expectOutcome(laterBlock.applyInline(env, last, 1), SccpErrors.StaleControl);
    expectPause(env, SCCP_MAX_U64, false, 0, false);
    expectOps(env, 2);
}

get fun `test apply control against a stored checkpoint`() {
    val env = setupEnv();
    val c = deliverControl(env, 3, true);
    // not stored yet
    expectRefused(env, sendApplyControlCheckpoint(env, c), SccpErrors.UnknownCheckpoint);
    expectOutcome(sendCheckpoint(env, env.deployer, c.cert, null, grams("1")), 0);
    val before = env.minter.getSccpCommittee();
    val res = sendApplyControlCheckpoint(env, c);
    expect(res).toHaveSuccessfulTx<SccpApplyControlCheckpoint>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    // no certificate is published and nothing is recorded
    expectEvents(res, [eventApplied(parliamentControl(3, true), 0)]);
    expectPause(env, 3, true, 0, true);
    expectOps(env, 1);
    expect(env.minter.getSccpCommittee().high).toEqual(before.high);
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
    reportGas("apply control checkpoint", stepGas(res), SCCP_GAS_MINTER_APPLY_CONTROL);
    expect(stepGas(res) < 58000).toBeTrue();
    // the same control again is stale
    expectOutcome(sendApplyControlCheckpoint(env, c), SccpErrors.StaleControl);
}

get fun `test the supplied fields must be those of the certified leaf`() {
    val env = setupEnv();
    val until = (T0 + 7200) * 1000;
    val genuine = controlOf(1, SCCP_TRACK_FAST_PAUSE, true, until);
    val block = blockAt(env, 1010, [controlLeafOf(env, genuine), fillerLeaf(1)]);
    var cases: array<TestControl> = [];
    // the opposite pause value, another expiry, another track, another nonce,
    // another certificate id and another effect hash
    var changed = genuine;
    changed.parliamentPaused = false;
    cases.push(changed);
    changed = genuine;
    changed.fastPauseUntilMs = until + 1;
    cases.push(changed);
    changed = genuine;
    changed.fastPauseUntilMs = 0;
    changed.track = SCCP_TRACK_PARLIAMENT;
    cases.push(changed);
    changed = genuine;
    changed.track = SCCP_TRACK_PARLIAMENT;
    cases.push(changed);
    changed = genuine;
    changed.nonce = 2;
    cases.push(changed);
    changed = genuine;
    changed.certificateId = genuine.certificateId ^ 1;
    cases.push(changed);
    changed = genuine;
    changed.effectHash = genuine.effectHash ^ 1;
    cases.push(changed);
    var i = 0;
    repeat (cases.size()) {
        expectRefused(env, block.applyInline(env, cases.get(i), 0), SccpErrors.BadProof);
        i += 1;
    }
    expect(i).toEqual(7);
    // another leaf index
    expectRefused(env, block.applyInline(env, genuine, 1), SccpErrors.BadProof);
    val res = block.applyInline(env, genuine, 0);
    expectOutcome(res, 0);
    expectPause(env, 1, true, until, true);
    expectOps(env, 1);
}

get fun `test a control leaf never finalizes as a transfer`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val transfer = transferOf(env, 0, 1, alice, NOW_MS + DAY_MS);
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    // a block with the control leaf, offered with the transfer payload
    val controlBlock = blockAt(env, 1009, [controlLeafOf(env, pause), fillerLeaf(1)]);
    val res = finalizeInline(
        env,
        controlBlock.cert,
        controlBlock.transferProof(transfer, 0),
        grams("5"),
    );
    expectOutcome(res, SccpErrors.BadProof);
    expectEvents(res, []);
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    // and a transfer leaf is no control, under any nonce and pause value
    val transferBlock = blockAt(env, 1010, [transfer.leaf, fillerLeaf(1)]);
    var nonce = 0;
    repeat (3) {
        expectRefused(
            env,
            transferBlock.applyInline(
                env,
                controlOf(nonce, SCCP_TRACK_PARLIAMENT, nonce == 1, 0),
                0,
            ),
            SccpErrors.BadProof,
        );
        nonce += 1;
    }
}

get fun `test the fast pause expiry is clamped to now + MAX_FAST_PAUSE_MS`() {
    val env = setupEnv();
    // exactly at the bound the leaf value is stored
    val atBound = controlOf(1, SCCP_TRACK_FAST_PAUSE, false, NOW_MS + SCCP_MAX_FAST_PAUSE_MS);
    val block = blockAt(env, 1010, [controlLeafOf(env, atBound)]);
    val res = block.applyInline(env, atBound, 0);
    expectOutcome(res, 0);
    expectPause(env, 1, false, NOW_MS + SCCP_MAX_FAST_PAUSE_MS, true);
    expectOps(env, 1);
    // one millisecond beyond it is clamped, also for a Parliament control that carries an expiry
    val beyond = controlOf(2, SCCP_TRACK_PARLIAMENT, false, NOW_MS + SCCP_MAX_FAST_PAUSE_MS + 1);
    val second = blockAt(env, 1011, [controlLeafOf(env, beyond)]);
    val clamped = second.applyInline(env, beyond, 0);
    expectOutcome(clamped, 0);
    expect(
        clamped
            .findExternalOutMessage<SccpControlAppliedEvent>({ from: env.minter.address })!
            .loadBody()
            .fastPauseUntilMs,
    ).toEqual(NOW_MS + SCCP_MAX_FAST_PAUSE_MS);
    expectPause(env, 2, false, NOW_MS + SCCP_MAX_FAST_PAUSE_MS, true);
    expectOps(env, 2);
    // the largest u64 expiry
    val largest = controlOf(3, SCCP_TRACK_FAST_PAUSE, false, SCCP_MAX_U64);
    val third = blockAt(env, 1012, [controlLeafOf(env, largest)]);
    testing.setNow(T0 + 60);
    expectOutcome(third.applyInline(env, largest, 0), 0);
    expectPause(env, 3, false, NOW_MS + 60000 + SCCP_MAX_FAST_PAUSE_MS, true);
    expectOps(env, 3);
    // a later control with expiry 0 lifts the fast pause
    val lift = controlOf(4, SCCP_TRACK_PARLIAMENT, false, 0);
    val fourth = blockAt(env, 1013, [controlLeafOf(env, lift)]);
    expectOutcome(fourth.applyInline(env, lift, 0), 0);
    expectPause(env, 4, false, 0, false);
    expectOps(env, 4);

    // the function: min(leaf value, min(now + MAX_FAST_PAUSE_MS, 2^64 − 1))
    expect(sccpAppliedFastPauseUntilMs(0, NOW_MS)).toEqual(0);
    expect(sccpAppliedFastPauseUntilMs(NOW_MS - 1, NOW_MS)).toEqual(NOW_MS - 1);
    expect(
        sccpAppliedFastPauseUntilMs(SCCP_MAX_U64, NOW_MS),
    ).toEqual(NOW_MS + SCCP_MAX_FAST_PAUSE_MS);
    // the bound saturates at the top of u64
    expect(sccpAppliedFastPauseUntilMs(SCCP_MAX_U64, SCCP_MAX_U64)).toEqual(SCCP_MAX_U64);
    expect(
        sccpAppliedFastPauseUntilMs(SCCP_MAX_U64, SCCP_MAX_U64 - SCCP_MAX_FAST_PAUSE_MS - 1),
    ).toEqual(SCCP_MAX_U64 - 1);
    expect(sccpAppliedFastPauseUntilMs(5, SCCP_MAX_U64)).toEqual(5);
    // the effective pause: parliamentPaused ∨ now_ms < fastPauseUntilMs
    expect(sccpEffectivePause(false, 0, 0)).toBeFalse();
    expect(sccpEffectivePause(true, 0, NOW_MS)).toBeTrue();
    expect(sccpEffectivePause(false, NOW_MS, NOW_MS - 1)).toBeTrue();
    expect(sccpEffectivePause(false, NOW_MS, NOW_MS)).toBeFalse();
    expect(sccpEffectivePause(false, NOW_MS, NOW_MS + 1)).toBeFalse();
}

// ---------------------------------------------------------------------------
// The minter step: order, shapes, value and chain identity.

get fun `test control checks run in the order of the specification`() {
    val env = setupEnv();
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val block = blockAt(env, 1010, [controlLeafOf(env, pause), fillerLeaf(1)]);
    val proof = block.controlProof(pause, 0);
    val quote = env.minter.applyControlRequiredValue();
    expect(quote).toEqual(sccpApplyControlRequiredValue() + sccpMinterStorageGrace());
    val minimum = quote - sccpMinterStorageGrace();
    val forged = certOf(foreignSignature(), 7, defaultQc(block.x.height), block.x);
    val unknownRef = emptyX(env.networkId, env.generation, env.committee.root(), 77).ref();

    // a malformed proof cell before the value
    val malformedProof = beginCell()
        .storeUint(0, 256)
        .storeUint(0, 256)
        .storeRef(ownBlockRef(block.x))
        .endCell();
    expectRefused(
        env,
        controlInline(env, forged, malformedProof, minimum - 1),
        SccpErrors.BadSnake,
    );
    // the value before any certificate
    val poor = controlInline(env, forged, proof, minimum - 1);
    expectRefused(env, poor, SccpErrors.NotEnoughValue);
    expect(stepGas(poor) < 58000).toBeTrue();
    expectRefused(
        env,
        controlStored(env, unknownRef, proof, minimum - 1),
        SccpErrors.NotEnoughValue,
    );
    // the certificate and the checkpoint before the proof
    val wrongLeaf = block.controlProof(pause, 1);
    expectRefused(
        env,
        controlInline(env, forged, wrongLeaf, minimum),
        SccpErrors.BadSignature,
    );
    expectRefused(
        env,
        controlStored(env, unknownRef, wrongLeaf, minimum),
        SccpErrors.UnknownCheckpoint,
    );
    // the block reference and the leaf path
    val badBlock = controlProofCell(
        pause.nonce,
        pause.track,
        pause.parliamentPaused,
        pause.fastPauseUntilMs,
        pause.certificateId,
        pause.effectHash,
        0,
        treePath(block.leaves, 0),
        blockRefCell(block.x.height, block.x.sccpRoot, block.x.messageCount, 1, []),
    );
    expectRefused(
        env,
        controlInline(env, block.cert, badBlock, minimum),
        SccpErrors.BadProof,
    );
    expectRefused(
        env,
        controlInline(env, block.cert, wrongLeaf, minimum),
        SccpErrors.BadProof,
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
    // at the minimum the genuine control applies and its excess returns
    val res = controlInline(env, block.cert, proof, minimum);
    expectOutcome(res, 0);
    expect(res).toHaveAllSuccessfulTxs();
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);
    // `Live` before the proof: an expired minter answers for the expiry
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    val later = blockAt(
        env,
        1020,
        [controlLeafOf(env, controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0))],
    );
    expectOutcome(
        controlInline(
            env,
            later.cert,
            later.controlProof(controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0), 5),
            minimum,
        ),
        SccpErrors.CommitteeNotAccepted,
    );
}

get fun `test a control proof cell of another shape is BadSnake`() {
    val env = setupEnv();
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val block = blockAt(env, 1010, [controlLeafOf(env, pause), fillerLeaf(1)]);
    val proof = block.controlProof(pause, 0);
    val path = sccpBuildHashPath(treePath(block.leaves, 0))!;
    val blockRef = ownBlockRef(block.x);
    // the 689 bits before the Maybe bit of the path
    val fields = beginCell()
        .storeUint(pause.nonce, 64)
        .storeUint(pause.track, 8)
        .storeBool(pause.parliamentPaused)
        .storeUint(pause.fastPauseUntilMs, 64)
        .storeUint(pause.certificateId, 256)
        .storeUint(pause.effectHash, 256)
        .storeUint(0, 32)
        .storeUint(1, 8);
    expect(fields.bitsCount()).toEqual(SCCP_CONTROL_PROOF_BITS - 1);
    expect(
        beginCell()
            .storeBuilder(fields)
            .storeUint(1, 1)
            .storeRef(path)
            .storeRef(blockRef)
            .endCell()
            .hash(),
    ).toEqual(proof.hash());
    val shapes: array<cell> = [
        // 689 and 698 bits
        beginCell().storeBuilder(fields).storeRef(path).storeRef(blockRef).endCell(),
        beginCell()
            .storeBuilder(fields)
            .storeUint(1, 1)
            .storeUint(0, 8)
            .storeRef(path)
            .storeRef(blockRef)
            .endCell(),
        // the Maybe bit against the references, a missing block and a stray reference
        beginCell().storeBuilder(fields).storeUint(1, 1).storeRef(blockRef).endCell(),
        beginCell()
            .storeBuilder(fields)
            .storeUint(0, 1)
            .storeRef(path)
            .storeRef(blockRef)
            .endCell(),
        beginCell().storeBuilder(fields).storeUint(0, 1).endCell(),
        beginCell()
            .storeBuilder(fields)
            .storeUint(1, 1)
            .storeRef(path)
            .storeRef(blockRef)
            .storeRef(blockRef)
            .endCell(),
        // a library cell with the canonical content
        asLibrary(proof),
        // the path and the block reference behind library references
        beginCell()
            .storeBuilder(fields)
            .storeUint(1, 1)
            .storeRef(asLibrary(path))
            .storeRef(blockRef)
            .endCell(),
        beginCell()
            .storeBuilder(fields)
            .storeUint(1, 1)
            .storeRef(path)
            .storeRef(asLibrary(blockRef))
            .endCell(),
    ];
    var i = 0;
    repeat (shapes.size()) {
        expectRefused(
            env,
            controlInline(env, block.cert, shapes.get(i), grams("1")),
            SccpErrors.BadSnake,
        );
        i += 1;
    }
    expect(i).toEqual(9);
    expectOutcome(controlInline(env, block.cert, proof, grams("1")), 0);
}

get fun `test apply control needs a genuine certificate and the mainnet global id`() {
    val env = setupEnv();
    val pause = controlOf(1, SCCP_TRACK_PARLIAMENT, true, 0);
    val block = blockAt(env, 1010, [controlLeafOf(env, pause)]);
    val proof = block.controlProof(pause, 0);
    val qc = defaultQc(block.x.height);
    // one signer, and a quorum of another committee
    val single = certOf(
        blsAggregateSign(env.committee.secretsOf(0b1000), commitMessage(env.instance, qc, block.x)),
        0b1000,
        qc,
        block.x,
    );
    expectRefused(
        env,
        controlInline(env, single, proof, grams("1")),
        SccpErrors.BadCertificate,
    );
    val strangers = testCommittee(4, 4);
    val foreign = certOf(
        blsAggregateSign(strangers.secretsOf(0b0111), commitMessage(env.instance, qc, block.x)),
        0b0111,
        qc,
        block.x,
    );
    expectRefused(
        env,
        controlInline(env, foreign, proof, grams("1")),
        SccpErrors.BadSignature,
    );
    setGlobalId(-3);
    expectRefused(
        env,
        controlInline(env, block.cert, proof, grams("1")),
        SccpErrors.WrongChain,
    );
    // chain identity comes before the proof cell and the checkpoint
    expectRefused(
        env,
        controlStored(env, block.x.ref(), beginCell().endCell(), grams("1")),
        SccpErrors.WrongChain,
    );
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expectOutcome(controlInline(env, block.cert, proof, grams("1")), 0);
    expectPause(env, 1, true, 0, true);
    expectOps(env, 1);
}

// ---------------------------------------------------------------------------
// What the pause does not block, and `Live`.

get fun `test burns, checkpoints, rotations and voids stay open while paused`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 1000, alice);
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
    // a Parliament pause and a fast pause together
    val until = NOW_MS + DAY_MS;
    expectOutcome(sendApplyControl(env, deliverFastPause(env, 1, true, until)), 0);
    expectPause(env, 1, true, until, true);
    expectOps(env, 2);
    // burn
    val burn = sendBurn(env, alice, 400, snakeOfLength(32), burnValue(env, alice));
    expect(burn).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(600);
    // checkpoint
    val x = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT + 250);
    expectOutcome(checkpointBy(env, env.committee, x, null), 0);
    // void
    val next = testCommittee(4, 4);
    testing.setNow(T0 + 51);
    expect(
        sendVoidExpired(env, env.deployer, 1, expiring, env.minter.voidRequiredValue(1)),
    ).toHaveSuccessfulTx<SccpConsumed>({
        to: env.minter.address,
    });
    // rotation
    rotateTo(env, next, TEST_START_HEIGHT + 300);
    // controls themselves are not blocked by the pause: resume under the new generation
    var successor = env;
    successor.generation = env.generation + 1;
    successor.committee = next;
    val resume = controlOf(2, SCCP_TRACK_PARLIAMENT, false, 0);
    var header = blockX(
        env.networkId,
        successor.generation,
        next.root(),
        TEST_START_HEIGHT + 310,
        [controlLeafOf(env, resume)],
    );
    val cert = certifyFor(env, next, header);
    val resumed = controlInline(
        env,
        cert,
        controlProofCell(
            resume.nonce,
            resume.track,
            resume.parliamentPaused,
            resume.fastPauseUntilMs,
            resume.certificateId,
            resume.effectHash,
            0,
            [],
            ownBlockRef(header),
        ),
        grams("1"),
    );
    expectOutcome(resumed, 0);
    // opCount: finalize, pause, burn, void, resume
    expectPause(env, 2, false, 0, false);
    expectOps(env, 5);
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);
}

get fun `test a frozen destination cannot apply controls`() {
    val env = setupEnv();
    val c = deliverControl(env, 1, true);
    expectOutcome(sendCheckpoint(env, env.deployer, c.cert, null, grams("1")), 0);
    // expired
    testing.setNow(PIN_UNTIL_MS / 1000 + 1);
    expect(sendApplyControl(env, c)).toHaveFailedTx<SccpApplyControl>({
        to: env.minter.address,
        exitCode: SccpErrors.CommitteeNotAccepted as int,
    });
    expectRefused(env, sendApplyControlCheckpoint(env, c), SccpErrors.CommitteeNotAccepted);
}

get fun `test a latched destination cannot apply controls`() {
    val env = setupEnv();
    val c = deliverControl(env, 1, true);
    expectOutcome(sendCheckpoint(env, env.deployer, c.cert, null, grams("1")), 0);
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    expectRefused(env, sendApplyControl(env, c), SccpErrors.Equivocated);
    expectRefused(env, sendApplyControlCheckpoint(env, c), SccpErrors.Equivocated);
}

get fun `test opCount saturates at the top of u64 under a control`() {
    val env = setupEnv();
    var st = minterStorage(env);
    st.opCount = SCCP_MAX_U64 - 1;
    setMinterStorage(env, st);
    val first = sendApplyControl(env, deliverControl(env, 1, true));
    expectOutcome(first, 0);
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    // at the bound the control still applies and the counter stays
    val second = sendApplyControl(env, deliverControl(env, 2, false));
    expectOutcome(second, 0);
    expect(second).toEmitExternalMessage<SccpControlAppliedEvent>();
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(SCCP_MAX_U64);
    expect(state.controlNonce).toEqual(2);
    expect(state.parliamentPaused).toBeFalse();
}
