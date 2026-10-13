// Value, fees and storage rent (specs/sccp.md §5.3.5) and the measured costs
// of §5.4.
//
// - The size constants cover the compiled contracts, the largest minter
//   state (n = 31, three checkpoints, the largest supplies and counters, room
//   for recorded retries) and the largest message of each kind.
// - Every per-step gas limit covers its step at the largest inputs: n = 31
//   with the 21 highest signers, full checkpoint slots, the last leaf of a
//   512-leaf block under a history of 2^32 blocks, a 1024-byte sender or
//   recipient and four bucket activations.
// - Every row of the §5.4 TON table is measured at n = 4, 7 and 31. The
//   measured steps are reported with `reportGas`; `scripts/ton_sccp_builder.py
//   test` collects them and compares them with `gas-baseline.json` at 1.1 x.
// - The floors hold after each flow.

import "@stdlib/gas-payments"
import "@stdlib/strings"
import "@acton/build"
import "@acton/io"
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

const MAX_U256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
/// The largest `Coins` value: a `VarUInteger 16` holds 15 bytes.
const MAX_COINS = 0xffffffffffffffffffffffffffffff
/// Recorded retries that the bound of the minter state leaves room for. A
/// record exists only after a bounce of a message the minter sent (§5.3.4).
const RETRY_ROOM = 8

/// (cells, bits) of a cell tree.
fun treeSize(c: cell): (int, int) {
    val (cells, bits, _) = c.calculateSizeStrict(10000);
    return (cells, bits);
}

fun expectCovered(label: string, cells: int, bits: int, maxCells: int, maxBits: int) {
    println(
        "{}: {} cells, {} bits (bound {} / {})",
        label,
        cells,
        bits,
        maxCells,
        maxBits,
    );
    expect(cells <= maxCells).toBeTrue();
    expect(bits <= maxBits).toBeTrue();
}

get fun `test state size constants cover the compiled contracts`() {
    val minter = testing.treasury("minter").address;
    val owner = testing.treasury("owner").address;
    val bucketData: BucketStorage = {
        minterAddress: minter,
        index: 0xFFFFFFFF,
        activated: true,
        bitsHi: 0,
        bitsLo: 0,
    };
    val (bc, bb) = treeSize(build("SccpConsumedBucket"));
    val (bdc, bdb) = treeSize(bucketData.toCell());
    expectCovered(
        "bucket state",
        bc + bdc,
        bb + bdb,
        SCCP_BUCKET_STATE_CELLS,
        SCCP_BUCKET_STATE_BITS,
    );
    expectCovered(
        "bucket StateInit",
        bc + bdc + 1,
        bb + bdb + 5,
        SCCP_BUCKET_STATE_INIT_CELLS,
        SCCP_BUCKET_STATE_INIT_BITS,
    );

    val walletData: WalletStorage = {
        jettonBalance: SCCP_TON_AMOUNT_LIMIT,
        ownerAddress: owner,
        minterAddress: minter,
    };
    val (wc, wb) = treeSize(build("SccpTairaXorWallet"));
    val (wdc, wdb) = treeSize(walletData.toCell());
    expectCovered(
        "wallet state",
        wc + wdc,
        wb + wdb,
        SCCP_WALLET_STATE_CELLS,
        SCCP_WALLET_STATE_BITS,
    );
    expectCovered(
        "wallet StateInit",
        wc + wdc + 1,
        wb + wdb + 5,
        SCCP_WALLET_STATE_INIT_CELLS,
        SCCP_WALLET_STATE_INIT_BITS,
    );

    // The largest minter: the 16 `KeyChunk`s of n = 31, three checkpoints,
    // the largest supplies and counters and `RETRY_ROOM` recorded retries.
    // It is installed as an account, because the storage phase charges for
    // the storage statistics of the account, which count its own cells too.
    testing.setNow(T0);
    val deployer = testing.treasury("deployer").address;
    val committee = testCommittee(SCCP_MAX_COMMITTEE_SIZE, 0);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        0xFFFFFFFF,
        MAX_COINS,
        defaultPin(committee),
        committee.keys,
    );
    storage.initialized = true;
    storage.equivocated = true;
    storage.totalSupply = MAX_COINS;
    storage.pendingSupply = MAX_COINS;
    storage.outboundNonce = SCCP_MAX_U64;
    storage.opCount = SCCP_MAX_U64;
    storage.controlNonce = SCCP_MAX_U64;
    storage.parliamentPaused = true;
    storage.fastPauseUntilMs = SCCP_MAX_U64;
    storage.deployedBuckets = SCCP_MAX_U64;
    var slots = Checkpoints.load(storage.checkpoints);
    expect(slots.insert(SCCP_MAX_U64 - 2, MAX_U256 - 2)).toBeTrue();
    expect(slots.insert(SCCP_MAX_U64 - 1, MAX_U256 - 1)).toBeTrue();
    expect(slots.insert(SCCP_MAX_U64, MAX_U256)).toBeTrue();
    storage.checkpoints = slots.toCell();
    // Retries under keys that differ in their first and in their last bits:
    // every record then has its own leaf and no two forks are one cell, so
    // the dictionary of `RETRY_ROOM` records has `2 · RETRY_ROOM − 1` cells.
    var k = 0;
    repeat (RETRY_ROOM) {
        storage.retries.set((k << 61) | (k * SCCP_BUCKET_BITS + 1), SCCP_RETRY_UNCONSUME);
        k += 1;
    }
    val largest = installPinned(storage, deployer, grams("20"));
    val (mc, mb) = accountStorageUsed(largest.address);
    expectCovered("minter state", mc, mb, SCCP_MINTER_STATE_CELLS, SCCP_MINTER_STATE_BITS);
    // the bounds are not loose: less than 5 % above the largest state
    expect(SCCP_MINTER_STATE_CELLS * 100 <= mc * 105).toBeTrue();
    expect(SCCP_MINTER_STATE_BITS * 100 <= mb * 105).toBeTrue();
    // TON deduplicates equal cells across code and data (which includes wallet
    // and bucket code). Count their exact DAG union, not their separate sums.
    val (cc, cb) = treeSize(build("SccpTairaXorMinter"));
    val (dc, db) = treeSize(storage.toCell());
    val (unionCells, unionBits) = treeSize(
        beginCell().storeRef(build("SccpTairaXorMinter")).storeRef(storage.toCell()).endCell(),
    );
    println("minter code: {} cells, {} bits; largest data: {} cells, {} bits", cc, cb, dc, db);
    // The union's zero-bit root stands in for the account's own storage cell.
    expect(mc).toEqual(unionCells);
    expect(mb >= unionBits).toBeTrue();
    // the same data without retries, as a deployment holds it in practice
    storage.retries = [];
    val plain = installPinned(storage, deployer, grams("20"));
    val (pc, pb) = accountStorageUsed(plain.address);
    println("largest minter state without retries: {} cells, {} bits", pc, pb);
    expect(mc - pc).toEqual(2 * RETRY_ROOM - 1);
}

get fun `test message size constants cover the largest messages`() {
    val a = testing.treasury("a").address;
    val b = testing.treasury("b").address;
    val tail: ConsumeTail = {
        kind: 0,
        recipient: a,
        response: b,
        messageId: MAX_U256,
    };
    val consume = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsume {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            tail: tail.toCell(),
        },
    });
    val (cc, cb) = treeSize(consume.messageCell);
    expectCovered("consume", cc, cb, SCCP_MSG_CONSUME_CELLS, SCCP_MSG_CONSUME_BITS);
    val activate = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: sccpBucketDeployment(a, 0xFFFFFFFF, build("SccpConsumedBucket")),
        body: SccpActivateBucket {
            queryId: (1 << 64) - 1,
            index: 0xFFFFFFFF,
        },
    });
    val (ac, ab) = treeSize(activate.messageCell);
    expectCovered(
        "activate + StateInit",
        ac,
        ab,
        SCCP_MSG_SMALL_CELLS + SCCP_BUCKET_STATE_INIT_CELLS,
        SCCP_MSG_SMALL_BITS + SCCP_BUCKET_STATE_INIT_BITS,
    );
    val smalls: array<cell> = [
        (SccpConsumeReverted {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
        }).toCell(),
        (SccpUnconsume { nonce: (1 << 64) - 1 }).toCell(),
    ];
    var k = 0;
    while (k < smalls.size()) {
        val small = createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: SCCP_TON_AMOUNT_LIMIT,
            dest: a,
            body: smalls.get(k),
        });
        val (sc, sb) = treeSize(small.messageCell);
        expectCovered("small message", sc, sb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
        k += 1;
    }
    val consumed = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsumed {
            queryId: (1 << 64) - 1,
            nonce: (1 << 64) - 1,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            tail: tail.toCell(),
        },
    });
    val (dc, db) = treeSize(consumed.messageCell);
    expectCovered("consumed", dc, db, SCCP_MSG_CONSUME_CELLS, SCCP_MSG_CONSUME_BITS);
    val mint = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: sccpWalletDeployment(a, b, build("SccpTairaXorWallet")),
        body: InternalTransferStep {
            queryId: (1 << 64) - 1,
            jettonAmount: SCCP_TON_AMOUNT_LIMIT - 1,
            transferInitiator: null,
            sendExcessesTo: b,
            forwardTonAmount: 0,
            forwardPayload: beginCell().storeUint(0, 1).toSlice(),
        },
    });
    val (ic, ib) = treeSize(mint.messageCell);
    expectCovered(
        "internal_transfer + StateInit",
        ic,
        ib,
        SCCP_MSG_INTERNAL_TRANSFER_CELLS + SCCP_WALLET_STATE_INIT_CELLS,
        SCCP_MSG_INTERNAL_TRANSFER_BITS + SCCP_WALLET_STATE_INIT_BITS,
    );
    val range = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: SccpConsumeRange {
            queryId: (1 << 64) - 1,
            first: (1 << 64) - 1,
            count: 512,
        },
    });
    val (rc, rb) = treeSize(range.messageCell);
    expectCovered("consume_range", rc, rb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
    val excess = createMessage({
        bounce: BounceMode.NoBounce,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: ReturnExcessesBack { queryId: (1 << 64) - 1 },
    });
    val (ec, eb) = treeSize(excess.messageCell);
    expectCovered("excess", ec, eb, SCCP_MSG_SMALL_CELLS, SCCP_MSG_SMALL_BITS);
    val voided = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpVoidedEvent {
            messageId: MAX_U256,
            firstNonce: (1 << 64) - 1,
            count: 512,
        },
    });
    val (vc, vb) = treeSize(voided.messageCell);
    expectCovered("sccp_voided", vc, vb, SCCP_MSG_EXT_EVENT_CELLS, SCCP_MSG_EXT_EVENT_BITS);
    // the other events of §5.3.3, each with its largest fields
    val events: array<cell> = [
        createExternalLogMessage({
            dest: createAddressNone(),
            body: SccpFinalizedEvent {
                messageId: MAX_U256,
                nonce: SCCP_MAX_U64,
            },
        }).messageCell,
        createExternalLogMessage({
            dest: createAddressNone(),
            body: SccpCommitteeRotatedEvent {
                generation: SCCP_MAX_U64,
                root: MAX_U256,
                untilMs: SCCP_MAX_U64,
                start: SCCP_MAX_U64,
            },
        }).messageCell,
        createExternalLogMessage({
            dest: createAddressNone(),
            body: SccpCheckpointedEvent {
                height: SCCP_MAX_U64,
                id: MAX_U256,
            },
        }).messageCell,
        createExternalLogMessage({
            dest: createAddressNone(),
            body: SccpLatchedEvent {
                reason: SCCP_LATCH_V3,
                generation: SCCP_MAX_U64,
                height: SCCP_MAX_U64,
                a: MAX_U256,
                b: MAX_U256,
            },
        }).messageCell,
        createExternalLogMessage({
            dest: createAddressNone(),
            body: SccpControlAppliedEvent {
                controlNonce: SCCP_MAX_U64,
                track: SCCP_TRACK_FAST_PAUSE,
                parliamentPaused: true,
                fastPauseUntilMs: SCCP_MAX_U64,
                certificateId: MAX_U256,
            },
        }).messageCell,
    ];
    var e = 0;
    repeat (events.size()) {
        val (evc, evb) = treeSize(events.get(e));
        expectCovered("event", evc, evb, SCCP_MSG_EXT_EVENT_CELLS, SCCP_MSG_EXT_EVENT_BITS);
        e += 1;
    }
    // `sccp_certificate` re-references the four cells of the certificate
    val committee = testCommittee(SCCP_MAX_COMMITTEE_SIZE, 0);
    var certified = emptyX(MAX_U256, SCCP_MAX_U64, MAX_U256, SCCP_MAX_U64);
    certified.timestampMs = SCCP_MAX_U64;
    val certificate = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpCertificateEvent {
            height: SCCP_MAX_U64,
            generation: SCCP_MAX_U64,
            cert: certify(committee, certified) as Cell<TairaCert>,
        },
    });
    val (qcc, qcb) = treeSize(certificate.messageCell);
    expectCovered(
        "sccp_certificate",
        qcc,
        qcb,
        SCCP_MSG_EXT_CERTIFICATE_CELLS,
        SCCP_MSG_EXT_CERTIFICATE_BITS,
    );
    val (chunks, len) = sccpParseSnakeBytes(snakeOfLength(1024), 1024, 1);
    val payload = sccpBuildOutboundPayload(
        (1 << 64) - 1,
        1,
        SCCP_TON_AMOUNT_LIMIT - 1,
        1,
        chunks,
        len,
    );
    val transfer = createExternalLogMessage({
        dest: createAddressNone(),
        body: SccpTransferToTairaEvent {
            messageId: MAX_U256,
            nonce: (1 << 64) - 1,
            sender: a,
            amount: SCCP_TON_AMOUNT_LIMIT - 1,
            payload: payload.cell,
        },
    });
    val (tc, tb) = treeSize(transfer.messageCell);
    expectCovered(
        "sccp_transfer_to_taira",
        tc,
        tb,
        SCCP_MSG_EXT_TRANSFER_CELLS,
        SCCP_MSG_EXT_TRANSFER_BITS,
    );
    val burn = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        value: SCCP_TON_AMOUNT_LIMIT,
        dest: a,
        body: BurnNotificationForMinter {
            queryId: (1 << 64) - 1,
            jettonAmount: SCCP_TON_AMOUNT_LIMIT - 1,
            burnInitiator: a,
            sendExcessesTo: b,
            sccp: (SccpBurnToTaira { recipient: snakeOfLength(1024) }).toCell(),
        },
    });
    val (nc, nb) = treeSize(burn.messageCell);
    expectCovered(
        "burn_notification",
        nc,
        nb,
        SCCP_MSG_BURN_NOTIFICATION_CELLS,
        SCCP_MSG_BURN_NOTIFICATION_BITS,
    );
}

/// Value `value` minus the excess returned to `to` in `res`.
fun consumedValue(res: SendResultList, value: coins, to: address): int {
    val tx = res.findTransaction<ReturnExcessesBack>({ to })!;
    val info = tx.loadInMsg<ReturnExcessesBack>().info;
    if (info is TlbInternalMessage) {
        return value - info.value.grams;
    }
    return value;
}

/// Gas of the first transaction matching `to` and opcode `Msg`.
fun gasOf<Msg>(res: SendResultList, to: address): int {
    return res.getUsedGas<Msg>({ to });
}

/// `"<row> n=<n>"`: the label of a row measured under a committee of `n`.
fun rowLabel(row: string, n: int): string {
    return StringBuilder.create().append(row).append(" n=").appendInt(n).build();
}

/// Fills the three checkpoint slots with entries below every header of this
/// suite (white box). A checkpoint recorded afterwards evicts the lowest
/// entry, which is the costliest shape of the slots.
fun fillCheckpointSlots(env: Env) {
    seedCheckpointId(env, TEST_START_HEIGHT + 1, 1);
    seedCheckpointId(env, TEST_START_HEIGHT + 2, 2);
    seedCheckpointId(env, TEST_START_HEIGHT + 3, 3);
}

/// The `CommitQC` over `x` by the `q` members with the highest canonical
/// indices: the verification then walks every stored `KeyChunk`.
fun certifyHighest(env: Env, committee: TestCommittee, x: TestX): cell {
    return certifyBy(committee, committee.highestSigners(), env.instance, defaultQc(x.height), x);
}

/// A certified header and the proof of one leaf under it at the largest
/// sizes: the last leaf of a 512-leaf block (9 siblings), which is the last
/// entry of a history of 2^32 blocks (32 siblings).
struct LargestProof {
    x: TestX
    leafIndex: int
    path: array<int>
    /// `^BlockRef` of the 512-leaf block through its history path.
    block: cell
}

/// The largest proof of `leaf` under a header of the pinned generation at
/// `height`; the block of the leaf is 22 blocks older.
fun largestProof(env: Env, leaf: int, height: int): LargestProof {
    var blockPath: array<int> = [];
    repeat (SCCP_MAX_BLOCK_PATH) {
        blockPath.push(fillerLeaf(100 + blockPath.size()));
    }
    val leafIndex = SCCP_MAX_BLOCK_LEAVES - 1;
    val blockRoot = sccpMerkleRoot(leaf, leafIndex, SCCP_MAX_BLOCK_LEAVES, blockPath);
    var historyPath: array<int> = [];
    repeat (SCCP_MAX_HISTORY_PATH) {
        historyPath.push(fillerLeaf(200 + historyPath.size()));
    }
    val historyIndex = SCCP_MAX_HISTORY_SIZE - 1;
    val blockHeight = height - 22;
    var x = emptyX(env.networkId, env.generation, env.committee.root(), height);
    x.messageCount = SCCP_MAX_BLOCK_LEAVES;
    x.sccpRoot = fillerLeaf(9);
    x.historySize = SCCP_MAX_HISTORY_SIZE;
    x.historyRoot = sccpMerkleRoot(
        sccpHistoryLeaf(blockHeight, blockRoot, SCCP_MAX_BLOCK_LEAVES),
        historyIndex,
        SCCP_MAX_HISTORY_SIZE,
        historyPath,
    );
    return {
        x,
        leafIndex,
        path: blockPath,
        block: blockRefCell(
            blockHeight,
            blockRoot,
            SCCP_MAX_BLOCK_LEAVES,
            historyIndex,
            historyPath,
        ),
    };
}

/// A Taira→TON payload of the largest size: a 1024-byte sender and the
/// largest amount.
fun largestPayload(nonce: int, deadlineMs: int, recipient: address): cell {
    return inboundPayloadWithSender(
        nonce,
        TEST_REVISION,
        deadlineMs,
        SCCP_TON_AMOUNT_LIMIT - 1,
        recipient.accountId(),
        SCCP_MAX_TAIRA_ACCOUNT_BYTES,
    );
}

// ---------------------------------------------------------------------------
// The §5.4 TON rows at n = 4, 7 and 31.

/// Measures the rows of the §5.4 TON table on a minter with a committee of
/// `n`, each at its usual inputs: empty checkpoint slots, the lowest `q`
/// signers, a block of three leaves certified itself and an active bucket.
///
/// - Certificate check: `sccp_checkpoint` with one plain certificate.
/// - Rotation extra: what a heartbeat and a key-changing rotation add to it.
/// - Inline finalize: the minter step, and the value the whole flow consumes
///   with its bucket and wallet round trips.
/// - `voidFrozen`: the minter step for a range in an active bucket. It
///   verifies no certificate, so its gas does not depend on `n`.
///
/// The inline void and control are measured beside them, because they price
/// two more gas limits.
fun measureRows(n: int) {
    val env = setupEnvWith(n, TEST_MAX_SUPPLY);
    val alice = testing.treasury("alice").address;
    val root = env.committee.root();
    val opcodeGas = 58000 + 3000 * env.committee.q();

    val plain = emptyX(env.networkId, env.generation, root, TEST_START_HEIGHT + 5);
    val check = checkpointBy(env, env.committee, plain, null);
    expectOutcome(check, 0);
    val checkGas = stepGas(check);
    reportGas(rowLabel("5.4 certificate check", n), checkGas, SCCP_GAS_MINTER_CHECKPOINT);

    // the first finalize activates bucket 0 and deploys the wallet
    finalizeOk(env, 0, 10, alice);
    val d = deliverDefault(env, 1, 10, alice);
    val value = finalizeValue(env, 1);
    val fin = sendFinalize(env, env.deployer, d, value);
    expect(fin).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(20);
    reportGas(rowLabel("5.4 inline finalize", n), stepGas(fin), SCCP_GAS_MINTER_FINALIZE);
    val finalizeConsumed = consumedValue(fin, value, env.deployer);

    val expired = deliver(
        env,
        env.committee,
        env.generation,
        2,
        5,
        alice,
        T0 * 1000 + 10000,
        1,
        3,
    );
    testing.setNow(T0 + 11);
    val voidValue = env.minter.voidRequiredValue(2);
    val void = sendVoidExpired(env, env.deployer, 2, expired, voidValue);
    expect(void).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 2)).toBeTrue();
    reportGas(rowLabel("5.4 inline void", n), stepGas(void), SCCP_GAS_MINTER_VOID);

    val c = deliverControl(env, 1, false);
    val control = sendApplyControlCells(
        env,
        env.deployer,
        c.cert,
        null,
        c.proof,
        env.minter.applyControlRequiredValue(),
    );
    expect(control).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().controlNonce).toEqual(1);
    reportGas(rowLabel("5.4 inline control", n), stepGas(control), SCCP_GAS_MINTER_APPLY_CONTROL);

    // a heartbeat keeps the keys; the rotation after it changes them
    val heartbeatX = rotationX(
        env.networkId,
        env.generation,
        root,
        TEST_START_HEIGHT + 200,
        T0 * 1000,
        root,
        TEST_VALIDITY_MS,
    );
    val heartbeat = checkpointBy(env, env.committee, heartbeatX, null);
    expectOutcome(heartbeat, 0);
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);
    replayExpectKeys(env, env.committee.keys);
    val heartbeatGas = stepGas(heartbeat);
    reportGas(rowLabel("5.4 rotation heartbeat", n), heartbeatGas, SCCP_GAS_MINTER_CHECKPOINT);
    val next = testCommittee(n, 4);
    val rotation = rotateFrom(
        env,
        env.committee,
        env.generation + 1,
        next,
        TEST_START_HEIGHT + 300,
    );
    replayExpectKeys(env, next.keys);
    val rotationGas = stepGas(rotation);
    reportGas(rowLabel("5.4 rotation key change", n), rotationGas, SCCP_GAS_MINTER_CHECKPOINT);

    // the successor expires: the upper half of bucket 0 is voided
    testing.setNow(T0 + 11 + TEST_VALIDITY_MS / 1000 + 1);
    val frozen = sendVoidFrozen(env, 256, 256, env.minter.voidFrozenRequiredValue(256));
    expect(frozen).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 511)).toBeTrue();
    reportGas(rowLabel("5.4 void frozen", n), stepGas(frozen), SCCP_GAS_MINTER_VOID_FROZEN);

    // the opcode is 58 000 + 3 000·q of every full-path step
    expect(checkGas > opcodeGas).toBeTrue();
    expect(heartbeatGas > checkGas).toBeTrue();
    expect(rotationGas > heartbeatGas).toBeTrue();
    println(
        "n={}: certificate check {} gas, of which the opcode {}; heartbeat +{}; key change +{}",
        n,
        checkGas,
        opcodeGas,
        heartbeatGas - checkGas,
        rotationGas - checkGas,
    );
    println(
        "n={}: inline finalize is the check + {} gas; the flow consumes {} nanoton of {} attached",
        n,
        stepGas(fin) - checkGas,
        finalizeConsumed,
        value,
    );
    println(
        "n={}: inline void is the check + {} gas; inline control is the check + {} gas",
        n,
        stepGas(void) - checkGas,
        stepGas(control) - checkGas,
    );
}

get fun `test the cost rows of the specification at n=4`() {
    measureRows(4);
}

get fun `test the cost rows of the specification at n=7`() {
    measureRows(7);
}

get fun `test the cost rows of the specification at n=31`() {
    measureRows(31);
}

// ---------------------------------------------------------------------------
// The four steps that verify a certificate, at their largest inputs.

/// Runs `sccp_finalize`, `sccp_void_expired`, `sccp_apply_control` and
/// `sccp_checkpoint` on a minter with a committee of `n` at the largest
/// inputs of each, and reports their gas against the limits that price them:
/// the `q` highest signers, full checkpoint slots, proofs of the largest
/// sizes, a 1024-byte sender, four bucket activations, and a key-changing
/// rotation to another committee of `n`.
fun measureLimits(n: int) {
    val env = setupEnvWith(n, SCCP_TON_AMOUNT_LIMIT * 4);
    val alice = testing.treasury("alice").address;
    fillCheckpointSlots(env);

    // sccp_finalize: bucket 3 is four past the deployed ones
    val mintNonce = (SCCP_MAX_DEPLOY_AHEAD - 1) * SCCP_BUCKET_BITS + 7;
    val minted = largestPayload(mintNonce, T0 * 1000 + DAY_MS, alice);
    val mintProof = largestProof(
        env,
        inboundLeaf(env.networkId, minted, env.minter.address),
        TEST_START_HEIGHT + 100,
    );
    val fin = sendFinalizeCells(
        env,
        env.deployer,
        certifyHighest(env, env.committee, mintProof.x),
        null,
        messageProofCell(mintProof.leafIndex, mintProof.path, minted, mintProof.block),
        finalizeValue(env, mintNonce),
    );
    expect(fin).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(SCCP_MAX_DEPLOY_AHEAD);
    // the recorded checkpoint evicted the lowest of three
    var slots = env.minter.getSccpCheckpoints();
    expect(slots.count).toEqual(SCCP_CHECKPOINT_SLOTS);
    expect(slots.height0).toEqual(TEST_START_HEIGHT + 2);
    expect(slots.height2).toEqual(mintProof.x.height);
    reportGas(rowLabel("limit finalize", n), stepGas(fin), SCCP_GAS_MINTER_FINALIZE);

    // sccp_void_expired: bucket 7 is again four past the deployed ones
    val voidNonce = (2 * SCCP_MAX_DEPLOY_AHEAD - 1) * SCCP_BUCKET_BITS + 7;
    val expired = largestPayload(voidNonce, T0 * 1000 + 10000, alice);
    val voidProof = largestProof(
        env,
        inboundLeaf(env.networkId, expired, env.minter.address),
        TEST_START_HEIGHT + 200,
    );
    testing.setNow(T0 + 11);
    val void = sendVoidExpiredCells(
        env,
        env.deployer,
        voidNonce,
        certifyHighest(env, env.committee, voidProof.x),
        null,
        messageProofCell(voidProof.leafIndex, voidProof.path, expired, voidProof.block),
        env.minter.voidRequiredValue(voidNonce),
    );
    expect(void).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, voidNonce)).toBeTrue();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(2 * SCCP_MAX_DEPLOY_AHEAD);
    reportGas(rowLabel("limit void", n), stepGas(void), SCCP_GAS_MINTER_VOID);

    // sccp_apply_control: a fast pause, whose expiry is clamped
    val control = fastPauseControl(SCCP_MAX_U64, true, SCCP_MAX_U64);
    val controlProof = largestProof(env, controlLeafOf(env, control), TEST_START_HEIGHT + 300);
    val applied = sendApplyControlCells(
        env,
        env.deployer,
        certifyHighest(env, env.committee, controlProof.x),
        null,
        controlProofCell(
            control.nonce,
            control.track,
            control.parliamentPaused,
            control.fastPauseUntilMs,
            control.certificateId,
            control.effectHash,
            controlProof.leafIndex,
            controlProof.path,
            controlProof.block,
        ),
        env.minter.applyControlRequiredValue(),
    );
    expect(applied).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().controlNonce).toEqual(SCCP_MAX_U64);
    reportGas(rowLabel("limit apply control", n), stepGas(applied), SCCP_GAS_MINTER_APPLY_CONTROL);

    // sccp_checkpoint: a key-changing rotation to another committee of `n`
    val next = testCommittee(n, 4);
    val handoff = rotationX(
        env.networkId,
        env.generation,
        env.committee.root(),
        TEST_START_HEIGHT + 400,
        T0 * 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    val rotated = sendCheckpoint(
        env,
        env.deployer,
        certifyHighest(env, env.committee, handoff),
        next.keysCell(),
        env.minter.checkpointRequiredValue(),
    );
    expect(rotated).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().generation).toEqual(env.generation + 1);
    replayExpectKeys(env, next.keys);
    slots = env.minter.getSccpCheckpoints();
    expect(slots.height0).toEqual(voidProof.x.height);
    expect(slots.height2).toEqual(handoff.height);
    reportGas(rowLabel("limit checkpoint", n), stepGas(rotated), SCCP_GAS_MINTER_CHECKPOINT);

    // every step left the minter at its floor or above
    expect(testing.getAccountBalance(env.minter.address) >= sccpMinterFloor()).toBeTrue();
}

get fun `test the certificate steps stay within their gas limits at the largest inputs, n=4`() {
    measureLimits(4);
}

get fun `test the certificate steps stay within their gas limits at the largest inputs, n=7`() {
    measureLimits(7);
}

get fun `test the certificate steps stay within their gas limits at the largest inputs, n=31`() {
    measureLimits(31);
}

// ---------------------------------------------------------------------------
// The other steps.

get fun `test the bucket and wallet round trip of a finalize and the floors`() {
    val env = setupEnvWith(4, SCCP_TON_AMOUNT_LIMIT * 4);
    val alice = testing.treasury("alice").address;
    // a mint of the largest amount that activates four buckets and deploys the wallet
    val nonce = (SCCP_MAX_DEPLOY_AHEAD - 1) * SCCP_BUCKET_BITS + 7;
    val d = deliver(
        env,
        env.committee,
        env.generation,
        nonce,
        SCCP_TON_AMOUNT_LIMIT - 1,
        alice,
        T0 * 1000 + DAY_MS,
        1,
        3,
    );
    val value = finalizeValue(env, nonce);
    val res = sendFinalize(env, env.deployer, d, value);
    expect(res).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    val bucket = env.minter.getBucketAddress(SCCP_MAX_DEPLOY_AHEAD - 1);
    reportGas(
        "step bucket activation",
        gasOf<SccpActivateBucket>(res, env.minter.getBucketAddress(0)),
        SCCP_GAS_BUCKET_ACTIVATE,
    );
    reportGas("step bucket consume", gasOf<SccpConsume>(res, bucket), SCCP_GAS_BUCKET_CONSUME);
    reportGas(
        "step minter consumed mint",
        gasOf<SccpConsumed>(res, env.minter.address),
        SCCP_GAS_MINTER_CONSUMED,
    );
    reportGas(
        "step wallet receive",
        gasOf<InternalTransferStep>(res, walletOf(env, alice).address),
        SCCP_GAS_WALLET_RECEIVE,
    );
    // floors: the bucket of the nonce, a bucket that was only activated, the minter
    expect(testing.getAccountBalance(bucket) >= sccpBucketFloor()).toBeTrue();
    expect(
        testing.getAccountBalance(env.minter.getBucketAddress(0)) >= sccpBucketFloor(),
    ).toBeTrue();
    expect(testing.getAccountBalance(env.minter.address) >= sccpMinterFloor()).toBeTrue();
    // the accounts are within the sizes their floors are computed for
    val (bc, bb) = accountStorageUsed(bucket);
    expectCovered("bucket account", bc, bb, SCCP_BUCKET_STATE_CELLS, SCCP_BUCKET_STATE_BITS);
    val (wc, wb) = accountStorageUsed(walletOf(env, alice).address);
    expectCovered("wallet account", wc, wb, SCCP_WALLET_STATE_CELLS, SCCP_WALLET_STATE_BITS);
    // The floors are `GETSTORAGEFEE` of those sizes at the current prices:
    // 100 years for the minter and a bucket, five for a new wallet (§5.3.5).
    val year = 365 * 86400;
    expect(sccpMinterFloor()).toEqual(
        calculateStorageFee(
            BASECHAIN,
            100 * year,
            SCCP_MINTER_STATE_BITS,
            SCCP_MINTER_STATE_CELLS,
        ),
    );
    expect(sccpBucketFloor()).toEqual(
        calculateStorageFee(
            BASECHAIN,
            100 * year,
            SCCP_BUCKET_STATE_BITS,
            SCCP_BUCKET_STATE_CELLS,
        ),
    );
    expect(sccpWalletMinStorage()).toEqual(
        calculateStorageFee(
            BASECHAIN,
            5 * year,
            SCCP_WALLET_STATE_BITS,
            SCCP_WALLET_STATE_CELLS,
        ),
    );
    println(
        "BUCKET_FLOOR {} MINTER_FLOOR {} wallet min storage {} gas fee of 100000 gas {}",
        sccpBucketFloor(),
        sccpMinterFloor(),
        sccpWalletMinStorage(),
        sccpGasFee(100000),
    );
    println(
        "finalize_required_value with 4 new buckets: {}; consumed with a new wallet: {}",
        value,
        consumedValue(res, value, env.deployer),
    );

    // the same message again: the bucket answers `sccp_already_consumed`
    val again = sendFinalize(env, env.deployer, d, finalizeValue(env, nonce));
    expect(again).toHaveAllSuccessfulTxs();
    expect(again).toHaveSuccessfulTx<SccpAlreadyConsumed>({ to: env.minter.address });
    expect(env.minter.getSccpState().pendingSupply).toEqual(0);
    reportGas(
        "step bucket already consumed",
        gasOf<SccpConsume>(again, bucket),
        SCCP_GAS_BUCKET_CONSUME,
    );
    reportGas(
        "step minter already consumed",
        gasOf<SccpAlreadyConsumed>(again, env.minter.address),
        SCCP_GAS_MINTER_CONSUMED,
    );

    // a second finalize into the active bucket and the existing wallet
    val second = deliver(
        env,
        env.committee,
        env.generation,
        nonce + 1,
        5,
        alice,
        T0 * 1000 + DAY_MS,
        0,
        1,
    );
    val value2 = finalizeValue(env, nonce + 1);
    val res2 = sendFinalize(env, env.deployer, second, value2);
    expect(res2).toHaveAllSuccessfulTxs();
    println(
        "finalize_required_value into an active bucket: {}; consumed with an existing wallet: {}",
        value2,
        consumedValue(res2, value2, env.deployer),
    );
    reportGas(
        "step wallet receive existing",
        gasOf<InternalTransferStep>(res2, walletOf(env, alice).address),
        SCCP_GAS_WALLET_RECEIVE,
    );

    // a void of an expired message
    val expired = deliver(
        env,
        env.committee,
        env.generation,
        nonce + 2,
        5,
        alice,
        T0 * 1000 + 10000,
        1,
        3,
    );
    testing.setNow(T0 + 11);
    val voidValue = env.minter.voidRequiredValue(nonce + 2);
    val void = sendVoidExpired(env, env.deployer, nonce + 2, expired, voidValue);
    expect(void).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, nonce + 2)).toBeTrue();
    reportGas(
        "step minter consumed void",
        gasOf<SccpConsumed>(void, env.minter.address),
        SCCP_GAS_MINTER_CONSUMED,
    );
    println(
        "void_required_value: {}; consumed: {}",
        voidValue,
        consumedValue(void, voidValue, env.deployer),
    );
}

get fun `test burn, deploy, void frozen and unconsume gas`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    val burn = sendBurn(env, alice, 100, snakeOfLength(1024), burnValue(env, alice));
    expect(burn).toHaveAllSuccessfulTxs();
    println(
        "burn_required_value: {}; consumed: {}",
        burnValue(env, alice),
        consumedValue(burn, burnValue(env, alice), alice),
    );
    reportGas(
        "step wallet burn",
        gasOf<AskToBurn>(burn, walletOf(env, alice).address),
        SCCP_GAS_WALLET_BURN,
    );
    // a 1024-byte recipient: the largest payload the minter builds and hashes
    reportGas(
        "step minter burn",
        gasOf<BurnNotificationForMinter>(burn, env.minter.address),
        SCCP_GAS_MINTER_BURN,
    );

    val deploy = env
        .minter
        .sendSccpDeployBuckets(
            env.deployer,
            0,
            env.deployer,
            SCCP_MAX_DEPLOY_BUCKETS_PER_CALL,
            {
                value: env.minter.deployBucketsRequiredValue(SCCP_MAX_DEPLOY_BUCKETS_PER_CALL),
                bounce: true,
            },
        );
    expect(deploy).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(17);
    reportGas(
        "step minter deploy 16 buckets",
        gasOf<SccpDeployBuckets>(deploy, env.minter.address),
        SCCP_GAS_MINTER_DEPLOY_BUCKETS,
    );

    // the generation expires: the minter is Frozen
    testing.setNow(T0 + TEST_VALIDITY_MS / 1000 + 1);
    val frozenValue = env.minter.voidFrozenRequiredValue(512);
    val frozen = sendVoidFrozen(env, 512, 512, frozenValue);
    expect(frozen).toHaveAllSuccessfulTxs();
    expect(isConsumedAt(env, 1023)).toBeTrue();
    reportGas("5.4 void frozen", stepGas(frozen), SCCP_GAS_MINTER_VOID_FROZEN);
    reportGas(
        "step bucket consume range 512",
        gasOf<SccpConsumeRange>(frozen, env.minter.getBucketAddress(1)),
        SCCP_GAS_BUCKET_CONSUME_RANGE,
    );
    reportGas(
        "step minter range consumed",
        gasOf<SccpRangeConsumed>(frozen, env.minter.address),
        SCCP_GAS_MINTER_RANGE_REPLY,
    );
    // the range reply keeps its value in the minter, so the caller's cost is
    // what the request did not return
    println(
        "void_frozen_required_value: {}; consumed for 512 nonces: {}",
        frozenValue,
        consumedValue(frozen, frozenValue, env.deployer),
    );
    // four bucket activations (deployed = 17 after the deploy above)
    val ahead = sendVoidFrozen(env, 20 * 512, 512, env.minter.voidFrozenRequiredValue(20 * 512));
    expect(ahead).toHaveAllSuccessfulTxs();
    expect(env.minter.getSccpState().deployedBuckets).toEqual(21);
    reportGas(
        "5.4 void frozen activating 4 buckets",
        stepGas(ahead),
        SCCP_GAS_MINTER_VOID_FROZEN,
    );
    // a range that holds a consumed nonce is rejected by the bucket
    val rejected = sendVoidFrozen(env, 0, 512, env.minter.voidFrozenRequiredValue(0));
    expect(rejected).toHaveAllSuccessfulTxs();
    expect(rejected).toHaveSuccessfulTx<SccpRangeRejected>({ to: env.minter.address });
    reportGas(
        "step bucket consume range rejected",
        gasOf<SccpConsumeRange>(rejected, env.minter.getBucketAddress(0)),
        SCCP_GAS_BUCKET_CONSUME_RANGE,
    );
    reportGas(
        "step minter range rejected",
        gasOf<SccpRangeRejected>(rejected, env.minter.address),
        SCCP_GAS_MINTER_RANGE_REPLY,
    );

    // unconsume (via a forged minter sender in the emulator)
    val un = bucketOf(env, 0).sendSccpUnconsume(
        env.minter.address,
        0,
        { value: sccpUnconsumeValue(), bounce: true },
    );
    expect(un).toHaveAllSuccessfulTxs();
    reportGas(
        "step bucket unconsume",
        gasOf<SccpUnconsume>(un, env.minter.getBucketAddress(0)),
        SCCP_GAS_BUCKET_UNCONSUME,
    );
    expect(isConsumedAt(env, 0)).toBeFalse();
}

get fun `test wallet transfer gas`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 100, alice);
    val res = walletOf(env, alice).sendAskToTransfer(
        alice,
        3,
        40,
        bob,
        alice,
        null,
        grams("0.01"),
        PayloadInRef {
            value: beginCell().storeUint(7, 32).endCell() as Cell<RemainingBitsAndRefs>,
        },
        { value: grams("0.5"), bounce: true },
    );
    expect(res).toHaveAllSuccessfulTxs();
    reportGas(
        "step wallet transfer",
        gasOf<AskToTransfer>(res, walletOf(env, alice).address),
        SCCP_GAS_WALLET_TRANSFER,
    );
    reportGas(
        "step wallet receive with notification",
        gasOf<InternalTransferStep>(res, walletOf(env, bob).address),
        SCCP_GAS_WALLET_RECEIVE,
    );
}

get fun `test an underfunded minter charges its floor deficit to the next caller`() {
    val env = setupEnvFunded(4, TEST_MAX_SUPPLY, grams("0.2"));
    val balance = testing.getAccountBalance(env.minter.address);
    expect(balance < sccpMinterFloor()).toBeTrue();
    expect(env.minter.minterFloor()).toEqual(sccpMinterFloor());
    val required = finalizeValue(env, 0);
    expect(required).toEqual(
        sccpFinalizeRequiredValue(1) + sccpMinterFloor() - balance + sccpMinterStorageGrace(),
    );
    val alice = testing.treasury("alice").address;
    val d = deliverDefault(env, 0, 10, alice);
    expect(
        sendFinalize(env, env.deployer, d, sccpFinalizeRequiredValue(1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    // the entry minimum is the quote without the grace
    expect(
        sendFinalize(env, env.deployer, d, required - sccpMinterStorageGrace() - 1),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.NotEnoughValue as int,
    });
    // refused before any signature work, and nothing was recorded
    expect(env.minter.getSccpCheckpoints().count).toEqual(0);
    val ok = sendFinalize(env, env.deployer, d, required);
    expect(ok).toHaveAllSuccessfulTxs();
    expect(jettonBalanceOf(env, alice)).toEqual(10);
    // the caller topped the minter up to its floor: nothing above it is kept
    expect(testing.getAccountBalance(env.minter.address)).toEqual(sccpMinterFloor());
    // the next caller pays no deficit
    expect(
        finalizeValue(env, 1),
    ).toEqual(sccpFinalizeRequiredValue(0) + sccpMinterStorageGrace());
}
