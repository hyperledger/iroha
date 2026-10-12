// Deployment with canonical initial data and `sccp_init` (§5.3.1): the
// recomputed root, generation and validity bounds, the chain identity, the
// initial immutables and counters, and every operation throwing before init.

import "@stdlib/exotic-cells"
import "@acton/build"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Deploys `storage` without init (plain top-up) and returns the wrapper.
fun deployUninitialized(storage: MinterStorage): SccpTairaXorMinter {
    val deployer = testing.treasury("deployer");
    val minter = SccpTairaXorMinter.fromStorage(storage);
    val res = net.send(
        deployer.address,
        createMessage({
            bounce: BounceMode.NoBounce,
            value: grams("5"),
            dest: { workchain: BASECHAIN, stateInit: minter.stateInit! },
            body: TopUpTons { queryId: 0 },
        }),
    );
    expect(res).toHaveSuccessfulDeploy({ to: minter.address });
    return minter;
}

fun sendInit(minter: SccpTairaXorMinter): SendResultList {
    val deployer = testing.treasury("deployer");
    return minter.sendSccpInit(deployer.address, 0, { value: grams("1"), bounce: true });
}

get fun `test init records immutables and zero counters`() {
    val env = setupEnv();
    val state = env.minter.getSccpState();
    expect(state.initialized).toBeTrue();
    expect(state.tairaNetworkId).toEqual(VEC_NETWORK_ID);
    expect(state.routeRevision).toEqual(TEST_REVISION);
    expect(state.initialGeneration).toEqual(7);
    expect(state.initialRoot).toEqual(env.committee.root());
    expect(state.root).toEqual(env.committee.root());
    expect(state.generation).toEqual(7);
    expect(state.untilMs).toEqual(defaultPin(env.committee).untilMs);
    expect(state.consensusInstance).toEqual(VEC_CONSENSUS_INSTANCE);
    expect(state.initialStart).toEqual(TEST_START_HEIGHT);
    expect(state.initialUntilMs).toEqual(defaultPin(env.committee).untilMs);
    expect(state.start).toEqual(TEST_START_HEIGHT);
    expect(state.high).toEqual(TEST_START_HEIGHT - 1);
    expect(state.equivocated).toBeFalse();
    expect(state.fastPauseUntilMs).toEqual(0);
    expect(state.effectivePaused).toBeFalse();
    expect(env.minter.getSccpCheckpoints().count).toEqual(0);
    expect(state.outboundNonce).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(state.controlNonce).toEqual(0);
    expect(state.parliamentPaused).toBeFalse();
    expect(state.totalSupply).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(state.maxSupply).toEqual(TEST_MAX_SUPPLY);
    expect(state.deployedBuckets).toEqual(0);
    expect(env.minter.getSccpCommittee().keys.hash()).toEqual(env.committee.keysCell().hash());
    val jetton = env.minter.getJettonData();
    expect(jetton.totalSupply).toEqual(0);
    expect(jetton.mintable).toBeTrue();
    expect(jetton.adminAddress == null).toBeTrue();
    expect(jetton.jettonWalletCode.hash()).toEqual(build("SccpTairaXorWallet").hash());
}

get fun `test init works for a 31-member native committee`() {
    val env = setupEnvWith(31, TEST_MAX_SUPPLY);
    expect(env.minter.getSccpCommittee().keys.hash()).toEqual(env.committee.keysCell().hash());
}

get fun `test init is permissionless and runs once`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    val minter = deployUninitialized(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        ),
    );
    expect(minter.getSccpState().initialized).toBeFalse();
    val stranger = testing.treasury("stranger");
    val first = minter.sendSccpInit(stranger.address, 1, { value: grams("1"), bounce: true });
    expect(first).toHaveSuccessfulTx<SccpInit>({ to: minter.address });
    expect(minter.getSccpState().initialized).toBeTrue();
    val second = sendInit(minter);
    expect(
        second,
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.AlreadyInitialized as int });
}

get fun `test operations throw before init`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    val minter = deployUninitialized(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        ),
    );
    val user = testing.treasury("user");
    val value: SendParams = { value: grams("2"), bounce: true };
    val notInitialized = SccpErrors.NotInitialized as int;
    expect(
        minter.sendSccpDeployBuckets(user.address, 0, user.address, 1, value),
    ).toHaveFailedTx<SccpDeployBuckets>({ to: minter.address, exitCode: notInitialized });
    expect(
        minter.sendSccpVoidFrozen(
            user.address,
            0,
            user.address,
            0,
            1,
            value,
        ),
    ).toHaveFailedTx<SccpVoidFrozen>({ to: minter.address, exitCode: notInitialized });
    expect(
        minter.sendSccpRetry(user.address, 0, user.address, 0, value),
    ).toHaveFailedTx<SccpRetry>({ to: minter.address, exitCode: notInitialized });
    val env: Env = {
        minter,
        deployer: user.address,
        networkId: VEC_NETWORK_ID,
        instance: VEC_CONSENSUS_INSTANCE,
        generation: TEST_GENERATION,
        committee,
    };
    val d = deliverDefault(env, 0, 1000, user.address);
    expect(
        sendFinalize(env, user.address, d, grams("2")),
    ).toHaveFailedTx<SccpFinalize>({ to: minter.address, exitCode: notInitialized });
    expect(
        sendFinalizeCheckpoint(env, user.address, d, grams("2")),
    ).toHaveFailedTx<SccpFinalizeCheckpoint>({ to: minter.address, exitCode: notInitialized });
    expect(
        sendVoidExpired(env, user.address, 0, d, grams("2")),
    ).toHaveFailedTx<SccpVoidExpired>({ to: minter.address, exitCode: notInitialized });
    expect(
        sendVoidExpiredCheckpoint(env, user.address, 0, d, grams("2")),
    ).toHaveFailedTx<SccpVoidExpiredCheckpoint>({ to: minter.address, exitCode: notInitialized });
    val c = deliverControl(env, 1, true);
    expect(
        sendApplyControl(env, c),
    ).toHaveFailedTx<SccpApplyControl>({ to: minter.address, exitCode: notInitialized });
    expect(
        sendApplyControlCheckpoint(env, c),
    ).toHaveFailedTx<SccpApplyControlCheckpoint>({ to: minter.address, exitCode: notInitialized });
    expect(
        sendCheckpoint(env, user.address, d.cert, null, grams("2")),
    ).toHaveFailedTx<SccpCheckpoint>({ to: minter.address, exitCode: notInitialized });
    // A forged notification from the owner's canonical wallet is still refused.
    val wallet = minter.getWalletAddress(user.address);
    expect(
        minter.sendBurnNotificationForMinter(
            wallet,
            0,
            10,
            user.address,
            user.address,
            { recipient: snakeOfLength(8) },
            value,
        ),
    ).toHaveFailedTx<BurnNotificationForMinter>({ to: minter.address, exitCode: notInitialized });
    expect(minter.getSccpState().initialized).toBeFalse();
    expect(
        minter.sendTopUpTons(user.address, 0, { value: grams("1") }),
    ).toHaveSuccessfulTx<TopUpTons>({ to: minter.address });
}

get fun `test init rejects a pinned root that differs from the stored committee`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    var config = storage.config.load();
    var pin = config.initial.load();
    pin.root = pin.root ^ 1;
    config.initial = pin.toCell();
    storage.config = config.toCell();
    val minter = deployUninitialized(storage);
    expect(
        sendInit(minter),
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadCommittee as int });
}

get fun `test init rejects keys that differ from the pinned committee root`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    var state = storage.committee.load();
    state.keys = testCommittee(4, 4).keysCell();
    storage.committee = state.toCell();
    val minter = deployUninitialized(storage);
    expect(
        sendInit(minter),
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadCommittee as int });
}

get fun `test init rejects a library-cell key list`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    var state = storage.committee.load();
    testing.registerLibrary(state.keys);
    state.keys = state.keys.toLibraryReference();
    storage.committee = state.toCell();
    val minter = deployUninitialized(storage);
    expect(
        sendInit(minter),
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadSnake as int });
}

get fun `test init rejects committee fields that differ from the initial pin`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var i = 0;
    while (i < 4) {
        var storage = canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        );
        var state = storage.committee.load();
        if (i == 0) {
            state.generation += 1;
        }
        if (i == 1) {
            state.start += 1;
        }
        if (i == 2) {
            state.high += 1;
        }
        if (i == 3) {
            state.untilMs += 1;
        }
        storage.committee = state.toCell();
        val minter = deployUninitialized(storage);
        expect(
            sendInit(minter),
        ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadConfig as int });
        i += 1;
    }
}

get fun `test init rejects bad committee size and key order`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var i = 0;
    while (i < 3) {
        var storage = canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        );
        var state = storage.committee.load();
        if (i == 0) {
            state.n = 5;
        }
        if (i == 1) {
            val k = committee.keys;
            state.keys = sccpBuildKeys([k.get(1), k.get(0), k.get(2), k.get(3)]);
        }
        if (i == 2) {
            val k = committee.keys;
            state.keys = sccpBuildKeys([k.get(0), k.get(0), k.get(2), k.get(3)]);
        }
        storage.committee = state.toCell();
        val minter = deployUninitialized(storage);
        expect(
            sendInit(minter),
        ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadCommittee as int });
        i += 1;
    }
}

get fun `test init applies the pinned validity bounds`() {
    testing.setNow(T0);
    val now = T0 * 1000;
    val committee = testCommittee(4, 0);
    val bounds: array<int> = [
        now - 1,
        now,
        now + SCCP_MAX_VALIDITY_MS + SCCP_MAX_INIT_SLACK_MS + 1,
    ];
    var i = 0;
    while (i < bounds.size()) {
        var pin = defaultPin(committee);
        pin.untilMs = bounds.get(i);
        val minter = deployUninitialized(
            canonicalStorage(
                VEC_NETWORK_ID,
                VEC_CONSENSUS_INSTANCE,
                TEST_REVISION,
                TEST_MAX_SUPPLY,
                pin,
                committee.keys,
            ),
        );
        expect(
            sendInit(minter),
        ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadConfig as int });
        i += 1;
    }
    val edges: array<int> = [now + 1, now + SCCP_MAX_VALIDITY_MS + SCCP_MAX_INIT_SLACK_MS];
    i = 0;
    while (i < edges.size()) {
        var pin = defaultPin(committee);
        pin.untilMs = edges.get(i);
        val minter = deployUninitialized(
            canonicalStorage(
                VEC_NETWORK_ID,
                VEC_CONSENSUS_INSTANCE,
                TEST_REVISION,
                TEST_MAX_SUPPLY,
                pin,
                committee.keys,
            ),
        );
        expect(sendInit(minter)).toHaveSuccessfulTx<SccpInit>({ to: minter.address });
        i += 1;
    }
}

get fun `test init rejects non-canonical initial data`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    storage.totalSupply = 5;
    val minter = deployUninitialized(storage);
    expect(
        sendInit(minter),
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.BadConfig as int });

    var paused = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    paused.parliamentPaused = true;
    val minter2 = deployUninitialized(paused);
    expect(
        sendInit(minter2),
    ).toHaveFailedTx<SccpInit>({ to: minter2.address, exitCode: SccpErrors.BadConfig as int });

    val zeroRevision = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        0,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    val minter3 = deployUninitialized(zeroRevision);
    expect(
        sendInit(minter3),
    ).toHaveFailedTx<SccpInit>({ to: minter3.address, exitCode: SccpErrors.BadConfig as int });
}

get fun `test init requires the ton mainnet global id`() {
    testing.setNow(T0);
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(-3, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
    val committee = testCommittee(4, 0);
    val minter = deployUninitialized(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            TEST_MAX_SUPPLY,
            defaultPin(committee),
            committee.keys,
        ),
    );
    expect(
        sendInit(minter),
    ).toHaveFailedTx<SccpInit>({ to: minter.address, exitCode: SccpErrors.WrongChain as int });
}

get fun `test canonical storage matches the documented bit layout`() {
    val committee = testCommittee(4, 0);
    val storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
    val root = storage.toCell().beginParse();
    // initialized(1) equivocated(1) total(4) pending(4) outbound(64) op(64)
    // control(64) parliamentPaused(1) fastPauseUntilMs(64) deployed(64) retries-dict(1)
    expect(root.remainingBitsCount()).toEqual(332);
    expect(root.remainingRefsCount()).toEqual(3);
}
