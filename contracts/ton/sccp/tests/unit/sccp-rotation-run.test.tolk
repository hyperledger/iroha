// The rotation-count run of the SCCP v1 TON minter (specs/sccp.md §5.3.1
// "State size is constant", §11.4 item 4, §11.5): 10 000 rotations through
// `sccp_checkpoint`, one per message, after which the layout holds the same
// cells as deployment, with three populated checkpoint slots. Physical DAG
// counts account exactly for equal cells shared between code and data.
//
// The split. The first 1 000 rotations (`RUN_SIGNED_ROTATIONS`) carry a
// `CommitQC` signed in the test VM and take the full verification path: about
// 6 ms each on the reference host, which is what the test VM carries without
// the run dominating the suite. The other 9 000 take the mandatory cheap path
// of §5.1.3 step 8, about 1.7 ms each: the checkpoint of the handoff header
// is seeded into the three slots (white box), exactly as a full-path
// verification would have recorded it, and the certificate then carries a
// signature that verifies nothing. Both parts run the same rotation code of
// the minter (§5.1.2 update 3) and reach the same state; the seeded part
// skips only the signature check. The whole run takes about 25 s.
//
// Every fourth rotation is a heartbeat, which keeps the stored `KeyChunk`
// chain; the others change the keys between two committees of n = 4. The
// clock advances one hour per rotation, so the run spans 416 days and the
// storage phase runs in every transaction. A second test rotates through
// every committee size with signed handoffs: the layout cell count is a
// function of the committee size alone, after correcting code/data sharing.

import "@acton/build"
import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-bls"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Rotations of the run (§11.4 item 4).
const RUN_ROTATIONS = 10000
/// Rotations of the run that carry a genuine `CommitQC` (the full path); the
/// rest take the cheap path over a seeded checkpoint.
const RUN_SIGNED_ROTATIONS = 1000
/// Destination seconds between two rotations.
const RUN_STEP_SECONDS = 3600
/// Blocks between two handoffs.
const RUN_HEIGHT_STEP = 7
/// Bits of one stored checkpoint: `height:uint64 id:bits256` (§5.3.1).
const CHECKPOINT_ENTRY_BITS = 320

/// A well-formed compressed G2 point that signs nothing here and is not the
/// identity.
fun foreignSignature(): slice {
    return vecHashToG2(0).q;
}

/// Expects `gas` to be `steady`, the gas of the earlier rotations of its
/// kind; the first one sets it.
fun expectSteadyGas(mutate steady: int, gas: int) {
    if (steady == 0) {
        steady = gas;
    }
    expect(gas).toEqual(steady);
}

/// `KeyChunk`s of a committee of `n`: two keys per chunk.
fun keyChunksOf(n: int): int {
    return (n + SCCP_KEYS_PER_CHUNK - 1) / SCCP_KEYS_PER_CHUNK;
}

/// Exact cells/bits shared between account code and data. The compiler can
/// embed a constant identical to the empty checkpoints cell, so its first
/// replacement changes physical deduplication without growing the layout.
fun codeDataSharing(env: Env): (int, int) {
    val code = build("SccpTairaXorMinter");
    val data = minterStorage(env).toCell();
    val (cc, cb, _) = code.calculateSizeStrict(10000);
    val (dc, db, _) = data.calculateSizeStrict(10000);
    val (uc, ub, _) = beginCell()
        .storeRef(code)
        .storeRef(data)
        .endCell()
        .calculateSizeStrict(10000);
    return (cc + dc - (uc - 1), cb + db - ub);
}

get fun `test ten thousand rotations preserve the exact account layout and DAG sharing`() {
    val env = setupEnv();
    val committees: array<TestCommittee> = [env.committee, testCommittee(4, 4)];
    val roots: array<int> = [committees.get(0).root(), committees.get(1).root()];
    val keyCells: array<cell> = [committees.get(0).keysCell(), committees.get(1).keysCell()];
    val signers = env.committee.lowestSigners();
    val unsigned = foreignSignature();

    val (cells0, bits0) = accountStorageUsed(env.minter.address);
    val (sharedCells0, sharedBits0) = codeDataSharing(env);
    expect(minterStorage(env).recovery.load().operations.isEmpty()).toBeTrue();

    var current = 0;
    var generation = env.generation;
    var height = TEST_START_HEIGHT;
    var signedKeyChangeGas = 0;
    var signedHeartbeatGas = 0;
    var cheapKeyChangeGas = 0;
    var cheapHeartbeatGas = 0;
    var keyChanges = 0;
    var heartbeats = 0;
    var i = 0;
    repeat (RUN_ROTATIONS) {
        val nowSeconds = T0 + i * RUN_STEP_SECONDS;
        testing.setNow(nowSeconds);
        height += RUN_HEIGHT_STEP;
        val isHeartbeat = (i % 4) == 3;
        val next = isHeartbeat ? current : 1 - current;
        val x = rotationX(
            env.networkId,
            generation,
            roots.get(current),
            height,
            nowSeconds * 1000 - 1000,
            roots.get(next),
            TEST_VALIDITY_MS,
        );
        val isSigned = i < RUN_SIGNED_ROTATIONS;
        if (!isSigned) {
            // the checkpoint a full-path verification of `x` would have recorded
            seedCheckpoint(env, x);
        }
        val cert = isSigned
            ? certifyFor(env, committees.get(current), x)
            : certOf(unsigned, signers, defaultQc(height), x);
        val res = sendCheckpoint(
            env,
            env.deployer,
            cert,
            isHeartbeat ? null : keyCells.get(next),
            grams("1"),
        );
        expectOutcome(res, 0);
        val untilMs = nowSeconds * 1000 - 1000 + TEST_VALIDITY_MS;
        val rotated = eventRotated(generation + 1, roots.get(next), untilMs, height + 1);
        val gas = stepGas(res);
        // once the three slots are full, a rotation of each kind costs the
        // same gas whatever came before it
        val isSteady = i >= SCCP_CHECKPOINT_SLOTS;
        if (isSigned) {
            expectEvents(
                res,
                [
                    eventCertificate(height, generation, cert),
                    eventCheckpointed(height, x.id()),
                    rotated,
                ],
            );
            if (isSteady & isHeartbeat) {
                expectSteadyGas(mutate signedHeartbeatGas, gas);
            }
            if (isSteady & !isHeartbeat) {
                expectSteadyGas(mutate signedKeyChangeGas, gas);
            }
        } else {
            // the cheap path publishes no certificate and records nothing anew
            expectEvents(res, [rotated]);
            expect(gas < 58000).toBeTrue();
            if (isHeartbeat) {
                expectSteadyGas(mutate cheapHeartbeatGas, gas);
            } else {
                expectSteadyGas(mutate cheapKeyChangeGas, gas);
            }
        }
        if (isHeartbeat) {
            heartbeats += 1;
        } else {
            keyChanges += 1;
        }
        current = next;
        generation += 1;

        // the successor is installed with the keys of its root ...
        val committee = env.minter.getSccpCommittee();
        expect(committee.generation).toEqual(generation);
        expect(committee.root).toEqual(roots.get(current));
        expect(committee.start).toEqual(height + 1);
        expect(committee.high).toEqual(height);
        expect(committee.untilMs).toEqual(untilMs);
        expect(committee.n).toEqual(4);
        expect(committee.keys.hash()).toEqual(keyCells.get(current).hash());
        // ... and the layout holds the deployment cells plus only the three
        // checkpoint entries, 320 bits each. Physical counts deduplicate
        // identical code/data cells, including the empty checkpoints cell.
        val (cells, bits) = accountStorageUsed(env.minter.address);
        val (sharedCells, sharedBits) = codeDataSharing(env);
        expect(cells).toEqual(cells0 + sharedCells0 - sharedCells);
        expect(bits).toEqual(
            bits0 + sharedBits0 - sharedBits +
                CHECKPOINT_ENTRY_BITS * min(i + 1, SCCP_CHECKPOINT_SLOTS),
        );
        i += 1;
    }

    expect(generation).toEqual(env.generation + RUN_ROTATIONS);
    expect(heartbeats).toEqual(RUN_ROTATIONS / 4);
    expect(keyChanges).toEqual(RUN_ROTATIONS - RUN_ROTATIONS / 4);
    // nothing but the committee and the checkpoints moved
    val st = minterStorage(env);
    expect(st.recovery.load().operations.isEmpty()).toBeTrue();
    expect(st.recovery.load().count).toEqual(0);
    expect(st.recovery.load().nextId).toEqual(1);
    expect(st.recovery.load().activatedBuckets).toEqual(0);
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(env.generation + RUN_ROTATIONS);
    expect(state.equivocated).toBeFalse();
    expect(state.opCount).toEqual(0);
    expect(state.deployedBuckets).toEqual(0);
    expect(state.totalSupply).toEqual(0);
    expect(state.initialGeneration).toEqual(env.generation);
    // the three slots hold the three latest handoffs
    val slots = env.minter.getSccpCheckpoints();
    expect(slots.count).toEqual(SCCP_CHECKPOINT_SLOTS);
    expect(slots.height0).toEqual(height - 2 * RUN_HEIGHT_STEP);
    expect(slots.height1).toEqual(height - RUN_HEIGHT_STEP);
    expect(slots.height2).toEqual(height);
    // the state stays below the bound that MINTER_FLOOR is computed for
    val (cellsEnd, bitsEnd) = accountStorageUsed(env.minter.address);
    println(
        "rotation run: {} rotations ({} signed, {} cheap path), {} cells, {} bits",
        RUN_ROTATIONS,
        RUN_SIGNED_ROTATIONS,
        RUN_ROTATIONS - RUN_SIGNED_ROTATIONS,
        cellsEnd,
        bitsEnd,
    );
    expect(cellsEnd <= SCCP_MINTER_STATE_CELLS).toBeTrue();
    expect(bitsEnd <= SCCP_MINTER_STATE_BITS).toBeTrue();
    reportGas("rotation run signed key change n=4", signedKeyChangeGas, SCCP_GAS_MINTER_CHECKPOINT);
    reportGas("rotation run signed heartbeat n=4", signedHeartbeatGas, SCCP_GAS_MINTER_CHECKPOINT);
    reportGas(
        "rotation run cheap path key change n=4",
        cheapKeyChangeGas,
        SCCP_GAS_MINTER_CHECKPOINT,
    );
    reportGas(
        "rotation run cheap path heartbeat n=4",
        cheapHeartbeatGas,
        SCCP_GAS_MINTER_CHECKPOINT,
    );
}

get fun `test exact account layout depends only on committee size with DAG sharing`() {
    // signed rotations through every committee size and back: the account
    // gains and loses exactly the `KeyChunk`s of the size change
    val env = setupEnv();
    val (cells0, _) = accountStorageUsed(env.minter.address);
    val (sharedCells0, _) = codeDataSharing(env);
    val sizes: array<int> = [
        31,
        7,
        4,
        10,
        28,
        13,
        25,
        16,
        22,
        19,
        31,
        4,
    ];
    var current = env.committee;
    var generation = env.generation;
    var height = TEST_START_HEIGHT;
    var largestCells = 0;
    var largestBits = 0;
    var i = 0;
    repeat (sizes.size()) {
        val n = sizes.get(i);
        // disjoint key ranges, so that every rotation changes the keys
        val next = testCommittee(n, (i & 1) == 0 ? 4 : 0);
        height += RUN_HEIGHT_STEP;
        rotateFrom(env, current, generation, next, height);
        current = next;
        generation += 1;
        val (cells, bits) = accountStorageUsed(env.minter.address);
        val (sharedCells, _) = codeDataSharing(env);
        expect(cells).toEqual(
            cells0 + sharedCells0 - sharedCells + keyChunksOf(n) - keyChunksOf(4),
        );
        largestCells = max(largestCells, cells);
        largestBits = max(largestBits, bits);
        expect(env.minter.getSccpCommittee().n).toEqual(n);
        i += 1;
    }
    // Back at n = 4 the layout is the deployment layout; its checkpoints
    // may no longer share an identical cell with compiled code.
    val (cellsEnd, _) = accountStorageUsed(env.minter.address);
    val (sharedCellsEnd, _) = codeDataSharing(env);
    expect(cellsEnd).toEqual(cells0 + sharedCells0 - sharedCellsEnd);
    // the largest committee is the largest state: 16 `KeyChunk`s
    expect(keyChunksOf(SCCP_MAX_COMMITTEE_SIZE)).toEqual(SCCP_MAX_KEY_CHUNKS);
    expect(largestCells).toEqual(
        cells0 + sharedCells0 - sharedCellsEnd + SCCP_MAX_KEY_CHUNKS - keyChunksOf(4),
    );
    println("largest minter state: {} cells, {} bits", largestCells, largestBits);
    expect(largestCells <= SCCP_MINTER_STATE_CELLS).toBeTrue();
    expect(largestBits <= SCCP_MINTER_STATE_BITS).toBeTrue();
}
