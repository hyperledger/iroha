// Actual Rust wallet BoCs are imported intact, independently re-encoded by
// native Tolk types and replayed through the compiled destination contracts.

import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-recovery"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-boc-vectors.gen"
import "sccp-test-helpers"

/// The wallet fixtures use their own native committee and route revision.
fun bocEnv(initialized: bool): Env {
    testing.setNow(VEC_BOC_NOW_MS / 1000);
    val deployer = testing.treasury("deployer").address;
    val keys = sccpLoadKeys(vecBocCell(VEC_BOC_KEYS), 4).keys;
    val pin: InitialPin = {
        generation: VEC_BOC_GENERATION,
        root: VEC_BOC_ROOT,
        start: VEC_BOC_START,
        untilMs: VEC_BOC_UNTIL_MS,
    };
    val storage = canonicalStorage(
        VEC_BOC_NETWORK_ID,
        VEC_BOC_CONSENSUS_INSTANCE,
        VEC_BOC_REVISION,
        TEST_MAX_SUPPLY,
        pin,
        keys,
    );
    val minter = initialized
        ? deployPinned(storage, deployer, REPLAY_VALUE)
        : installPinned(storage, deployer, REPLAY_VALUE);
    expect(minter.address.accountId()).toEqual(VEC_BOC_DESTINATION);
    return {
        minter,
        deployer,
        networkId: VEC_BOC_NETWORK_ID,
        instance: VEC_BOC_CONSENSUS_INSTANCE,
        generation: VEC_BOC_GENERATION,
        committee: { keys, secrets: [] },
    };
}

/// Sends the imported root bits and references without rebuilding its body.
fun sendBoc(env: Env, index: int): SendResultList {
    return sendToMinter(
        env,
        env.deployer,
        vecBocCell(index).beginParse() as RemainingBitsAndRefs,
        REPLAY_VALUE,
    );
}

fun prepareBocCheckpoint(env: Env, index: int) {
    expectOutcome(sendCheckpoint(env, env.deployer, vecBocCell(index), null, REPLAY_VALUE), 0);
}

fun replayBocFinalize(index: int, cert: int?) {
    val env = bocEnv(true);
    if (cert != null) {
        prepareBocCheckpoint(env, cert);
    }
    val result = sendBoc(env, index);
    expectOutcome(result, 0);
    expect(
        result.findExternalOutMessage<SccpFinalizedEvent>({ from: env.minter.address }) != null,
    ).toBeTrue();
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(1000);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    expect(isConsumedAt(env, 1)).toBeTrue();
    val recipient = address.fromWorkchainAndHash(0, VEC_BOC_RECIPIENT);
    expect(jettonBalanceOf(env, recipient)).toEqual(1000);
}

fun replayBocVoid(index: int, cert: int?) {
    val env = bocEnv(true);
    if (cert != null) {
        prepareBocCheckpoint(env, cert);
    }
    testing.setNow(VEC_BOC_DEADLINE_MS / 1000 + 1);
    expectOutcome(sendBoc(env, index), 0);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(state.opCount).toEqual(1);
    expect(isConsumedAt(env, 1)).toBeTrue();
}

fun replayBocControl(index: int, stored: bool) {
    val env = bocEnv(true);
    if (stored) {
        prepareBocCheckpoint(env, VEC_BOC_CERTIFICATE_CONTROL);
    }
    expectOutcome(sendBoc(env, index), 0);
    val state = env.minter.getSccpState();
    expect(state.controlNonce).toEqual(4);
    expect(state.parliamentPaused).toBeTrue();
    expect(state.opCount).toEqual(1);
}

fun replayBocRotation(index: int, keys: int) {
    val env = bocEnv(true);
    expectOutcome(sendBoc(env, index), 0);
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(2);
    expect(state.start).toEqual(102);
    expect(state.root).toEqual(sccpCommitteeRoot(4, sccpLoadKeys(vecBocCell(keys), 4).parts));
}

get fun `test all 28 Rust wallet BoCs match native Tolk graphs`() {
    expect(VEC_BOC_COUNT).toEqual(28);
    var i = 0;
    repeat (VEC_BOC_COUNT) {
        val imported = vecBocCell(i);
        expect(imported.hash()).toEqual(vecBocHashes().get(i));
        expect(imported.depth()).toEqual(vecBocDepths().get(i));
        expect(imported.beginParse().remainingBitsCount()).toEqual(vecBocBits().get(i));
        expect(vecBocReencoded(i).hash()).toEqual(imported.hash());
        i += 1;
    }
}

get fun `test Rust direct inline finalize BoC`() {
    replayBocFinalize(VEC_BOC_FINALIZE_DIRECT_INLINE, null);
}

get fun `test Rust historical inline finalize BoC`() {
    replayBocFinalize(VEC_BOC_FINALIZE_HISTORICAL_INLINE, null);
}

get fun `test Rust direct checkpoint finalize BoC`() {
    replayBocFinalize(VEC_BOC_FINALIZE_DIRECT_CHECKPOINT, VEC_BOC_CERTIFICATE_DIRECT);
}

get fun `test Rust historical checkpoint finalize BoC`() {
    replayBocFinalize(VEC_BOC_FINALIZE_HISTORICAL_CHECKPOINT, VEC_BOC_CERTIFICATE_HISTORICAL);
}

get fun `test Rust direct inline void BoC`() {
    replayBocVoid(VEC_BOC_VOID_DIRECT_INLINE, null);
}

get fun `test Rust historical inline void BoC`() {
    replayBocVoid(VEC_BOC_VOID_HISTORICAL_INLINE, null);
}

get fun `test Rust direct checkpoint void BoC`() {
    replayBocVoid(VEC_BOC_VOID_DIRECT_CHECKPOINT, VEC_BOC_CERTIFICATE_DIRECT);
}

get fun `test Rust historical checkpoint void BoC`() {
    replayBocVoid(VEC_BOC_VOID_HISTORICAL_CHECKPOINT, VEC_BOC_CERTIFICATE_HISTORICAL);
}

get fun `test Rust inline control BoC`() {
    replayBocControl(VEC_BOC_CONTROL_INLINE, false);
}

get fun `test Rust checkpoint control BoC`() {
    replayBocControl(VEC_BOC_CONTROL_CHECKPOINT, true);
}

get fun `test Rust heartbeat checkpoint BoC`() {
    replayBocRotation(VEC_BOC_CHECKPOINT_HEARTBEAT, VEC_BOC_KEYS);
}

get fun `test Rust key change checkpoint BoC`() {
    replayBocRotation(VEC_BOC_CHECKPOINT_KEY_CHANGE, VEC_BOC_NEXT_KEYS);
}

get fun `test Rust init BoC`() {
    val env = bocEnv(false);
    expect(env.minter.getSccpState().initialized).toBeFalse();
    expectOutcome(sendBoc(env, VEC_BOC_INIT), 0);
    expect(env.minter.getSccpState().initialized).toBeTrue();
}

get fun `test Rust bucket deployment BoC`() {
    val env = bocEnv(true);
    expectOutcome(sendBoc(env, VEC_BOC_DEPLOY_BUCKETS), 0);
    expect(env.minter.getSccpState().deployedBuckets).toEqual(3);
    expect(testing.isDeployed(bucketOf(env, 2).address)).toBeTrue();
}

get fun `test Rust retry BoC clears the recorded activation`() {
    val env = bocEnv(true);
    var storage = minterStorage(env);
    storage.deployedBuckets = 3;
    val retry = SccpRetry.fromCell(vecBocCell(VEC_BOC_RETRY));
    var recovery = RecoveryBook.empty();
    recovery.nextId = retry.operationId + 1;
    recovery.count = 1;
    recovery.activatedBuckets = 2;
    recovery
        .operations
        .set(
            retry.operationId,
            RecoveryOperation {
                stage: SCCP_RECOVERY_ACTIVATE,
                phase: SCCP_RECOVERY_FAILED,
                attempt: 1,
                nonce: 2,
                amount: 0,
                count: 0,
                nextId: 0,
                queryId: retry.queryId,
                result: 0,
                tail: ConsumeTail {
                    kind: 0,
                    recipient: null,
                    response: retry.response,
                    messageId: 0,
                }.toCell(),
            }.toCell(),
        );
    storage.recovery = recovery.toCell();
    setMinterStorage(env, storage);
    expectOutcome(
        sendToMinter(
            env,
            env.deployer,
            vecBocCell(VEC_BOC_RETRY).beginParse() as RemainingBitsAndRefs,
            env.minter.retryRequiredValue(),
        ),
        0,
    );
    expect(env.minter.getSccpRecovery(retry.operationId) == null).toBeTrue();
    val after = minterStorage(env).recovery.load();
    expect(after.count).toEqual(0);
    expect(after.operations.isEmpty()).toBeTrue();
    expect(after.nextId).toEqual(retry.operationId + 1);
    expect(after.activatedBuckets).toEqual(3);
    expect(testing.isDeployed(bucketOf(env, 2).address)).toBeTrue();
}

get fun `test Rust frozen range BoC consumes a complete bucket`() {
    val env = bocEnv(true);
    testing.setNow(VEC_BOC_UNTIL_MS / 1000 + 1);
    expectOutcome(sendBoc(env, VEC_BOC_VOID_FROZEN), 0);
    var nonce = 512;
    repeat (512) {
        expect(isConsumedAt(env, nonce)).toBeTrue();
        nonce += 1;
    }
    expect(isConsumedAt(env, 511)).toBeFalse();
    expect(isConsumedAt(env, 1024)).toBeFalse();
    expect(env.minter.getSccpState().opCount).toEqual(1);
}

get fun `test Rust burn BoCs preserve every canonical snake boundary`() {
    val env = bocEnv(true);
    expectOutcome(sendBoc(env, VEC_BOC_FINALIZE_DIRECT_INLINE), 0);
    val owner = address.fromWorkchainAndHash(0, VEC_BOC_RECIPIENT);
    val lengths = [1, 127, 128, 1024];
    var i = 0;
    repeat (4) {
        val body = vecBocCell(VEC_BOC_BURN_1 + i);
        val (_, length) = sccpParseBurnToTaira(body);
        expect(length).toEqual(lengths.get(i));
        val res = net.send(
            owner,
            createMessage({
                bounce: BounceMode.Only256BitsOfBody,
                value: REPLAY_VALUE,
                dest: walletOf(env, owner).address,
                body: AskToBurn {
                    queryId: 7,
                    jettonAmount: 10,
                    sendExcessesTo: owner,
                    customPayload: body,
                },
            }),
        );
        expect(res).toHaveSuccessfulTx<AskToBurn>({ to: walletOf(env, owner).address });
        expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
        expect(jettonBalanceOf(env, owner)).toEqual(990 - 10 * i);
        expect(env.minter.getSccpState().outboundNonce).toEqual(i + 1);
        i += 1;
    }
    expect(env.minter.getSccpState().totalSupply).toEqual(960);
}

get fun `test all five Rust rejected snake graphs fail before wallet debit`() {
    expect(VEC_BOC_NEGATIVE_COUNT).toEqual(5);
    val env = bocEnv(true);
    expectOutcome(sendBoc(env, VEC_BOC_FINALIZE_DIRECT_INLINE), 0);
    val owner = address.fromWorkchainAndHash(0, VEC_BOC_RECIPIENT);
    var i = 0;
    repeat (VEC_BOC_NEGATIVE_COUNT) {
        val res = net.send(
            owner,
            createMessage({
                bounce: BounceMode.Only256BitsOfBody,
                value: REPLAY_VALUE,
                dest: walletOf(env, owner).address,
                body: AskToBurn {
                    queryId: 7,
                    jettonAmount: 10,
                    sendExcessesTo: owner,
                    customPayload: vecBocNegativeCell(i),
                },
            }),
        );
        expect(res).toHaveFailedTx<AskToBurn>({
            to: walletOf(env, owner).address,
            exitCode: vecBocNegativeExits().get(i),
        });
        expect(
            res.findTransaction<BurnNotificationForMinter>({ to: env.minter.address }) == null,
        ).toBeTrue();
        expect(jettonBalanceOf(env, owner)).toEqual(1000);
        expect(env.minter.getSccpState().outboundNonce).toEqual(0);
        expect(env.minter.getSccpState().totalSupply).toEqual(1000);
        i += 1;
    }
}
