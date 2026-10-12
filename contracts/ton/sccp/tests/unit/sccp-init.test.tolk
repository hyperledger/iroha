// Deployment with the canonical initial data and `sccp_init` (specs/sccp.md
// §5.1.1, §5.3.1, §5.3.6): the pinned committee and its keys, the canonical
// counters, the bound on the pinned `untilMs` (`init_bounds` of
// `committee_transitions_v1.json`), chain identity, the state the get
// methods report afterwards, and every operation throwing before init.

import "@stdlib/exotic-cells"
import "@acton/build"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Destination clock at which every test of this suite starts, in ms.
const NOW_MS = 1800000000000
/// Rows of `init_bounds` this suite replays.
const PINNED_INIT_BOUNDS = 5

/// The canonical initial data of a deployment pinned to `committee` with the
/// default pin.
fun canonicalFor(committee: TestCommittee): MinterStorage {
    return canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        defaultPin(committee),
        committee.keys,
    );
}

/// The canonical initial data of the default deployment: the first four
/// test keys, generation 7 from height 1000, valid for 14 days.
fun canonicalDefault(): MinterStorage {
    return canonicalFor(testCommittee(4, 0));
}

/// Deploys `storage` without init (a plain top-up) and returns the wrapper.
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

/// Deploys `storage` and sends `sccp_init`: the exit code of the init step,
/// 0 when the minter is initialized afterwards.
fun initOutcome(storage: MinterStorage): int {
    val minter = deployUninitialized(storage);
    expect(minter.getSccpState().initialized).toBeFalse();
    val res = sendInit(minter);
    val code = outcomeOf(res);
    // the flag is set exactly by a successful init
    expect(minter.getSccpState().initialized).toEqual(code == 0);
    return code;
}

/// `storage` with its committee state replaced.
fun withCommittee(storage: MinterStorage, committee: CommitteeState): MinterStorage {
    var changed = storage;
    changed.committee = committee.toCell();
    return changed;
}

/// `storage` with its configuration replaced.
fun withConfig(storage: MinterStorage, config: MinterConfig): MinterStorage {
    var changed = storage;
    changed.config = config.toCell();
    return changed;
}

/// `storage` pinned to `pin` in the configuration and in the committee
/// state, with the keys unchanged.
fun withPin(storage: MinterStorage, pin: InitialPin): MinterStorage {
    var config = storage.config.load();
    config.initial = pin.toCell();
    var committee = storage.committee.load();
    committee.root = pin.root;
    committee.untilMs = pin.untilMs;
    committee.start = pin.start;
    committee.high = pin.start - 1;
    committee.generation = pin.generation;
    return withCommittee(withConfig(storage, config), committee);
}

/// The canonical initial data whose stored key list is `keys` as listed,
/// pinned to the committee root of exactly that list.
fun canonicalWithListedKeys(keys: array<slice>): MinterStorage {
    val n = keys.size();
    val list = sccpBuildKeys(keys);
    var pin = defaultPin(testCommittee(4, 0));
    pin.root = sccpCommitteeRoot(n, sccpLoadKeys(list, n).parts);
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        TEST_MAX_SUPPLY,
        pin,
        keys,
    );
    return storage;
}

/// Sets `GLOBALID` of the emulated chain (config parameter 19).
fun setGlobalId(id: int) {
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(id, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
}

// ---------------------------------------------------------------------------
// A successful init and the state it leaves.

get fun `test init records immutables, zero counters and controlNonce 0`() {
    val env = setupEnv();
    val root = env.committee.root();
    val until = NOW_MS + TEST_VALIDITY_MS;
    val state = env.minter.getSccpState();
    expect(state.initialized).toBeTrue();
    expect(state.equivocated).toBeFalse();
    // immutables
    expect(state.tairaNetworkId).toEqual(VEC_NETWORK_ID);
    expect(state.consensusInstance).toEqual(VEC_CONSENSUS_INSTANCE);
    expect(state.routeRevision).toEqual(TEST_REVISION);
    expect(state.maxSupply).toEqual(TEST_MAX_SUPPLY);
    expect(state.initialGeneration).toEqual(TEST_GENERATION);
    expect(state.initialRoot).toEqual(root);
    expect(state.initialStart).toEqual(TEST_START_HEIGHT);
    expect(state.initialUntilMs).toEqual(until);
    // cur from the pin, with high = start − 1
    expect(state.generation).toEqual(TEST_GENERATION);
    expect(state.root).toEqual(root);
    expect(state.start).toEqual(TEST_START_HEIGHT);
    expect(state.high).toEqual(TEST_START_HEIGHT - 1);
    expect(state.untilMs).toEqual(until);
    // counters, supply and pause state
    expect(state.outboundNonce).toEqual(0);
    expect(state.opCount).toEqual(0);
    expect(state.controlNonce).toEqual(0);
    expect(state.parliamentPaused).toBeFalse();
    expect(state.fastPauseUntilMs).toEqual(0);
    expect(state.effectivePaused).toBeFalse();
    expect(state.totalSupply).toEqual(0);
    expect(state.pendingSupply).toEqual(0);
    expect(state.deployedBuckets).toEqual(0);

    val committee = env.minter.getSccpCommittee();
    expect(committee.root).toEqual(root);
    expect(committee.untilMs).toEqual(until);
    expect(committee.start).toEqual(TEST_START_HEIGHT);
    expect(committee.high).toEqual(TEST_START_HEIGHT - 1);
    expect(committee.generation).toEqual(TEST_GENERATION);
    expect(committee.n).toEqual(4);
    expect(committee.keys.hash()).toEqual(env.committee.keysCell().hash());
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
    expect(env.minter.getSccpRetry(0)).toEqual(0);

    // TEP-74: no admin, and the wallet code of the configuration
    val jetton = env.minter.getJettonData();
    expect(jetton.totalSupply).toEqual(0);
    expect(jetton.mintable).toBeTrue();
    expect(jetton.adminAddress == null).toBeTrue();
    expect(jetton.jettonWalletCode.hash()).toEqual(build("SccpTairaXorWallet").hash());
    // the minter of this suite sits at the account id the fixtures commit to
    expect(env.minter.address.accountId()).toEqual(VEC_MINTER_ACCOUNT_ID);
}

get fun `test init accepts every committee size from 4 to 31`() {
    var n = SCCP_MIN_COMMITTEE_SIZE;
    var sizes = 0;
    while (n <= SCCP_MAX_COMMITTEE_SIZE) {
        testing.setNow(T0);
        val committee = testCommittee(n, 0);
        val minter = deployUninitialized(canonicalFor(committee));
        val res = sendInit(minter);
        expectOutcome(res, 0);
        val stored = minter.getSccpCommittee();
        expect(stored.n).toEqual(n);
        expect(stored.root).toEqual(committee.root());
        expect(stored.keys.hash()).toEqual(committee.keysCell().hash());
        expect(minter.getSccpState().initialized).toBeTrue();
        if (n == SCCP_MAX_COMMITTEE_SIZE) {
            println("sccp_init n=31: {} gas", stepGas(res));
        }
        sizes += 1;
        n += 3;
    }
    expect(sizes).toEqual(10);
    expect(testCommittee(31, 0).root()).toEqual(VEC_COMMITTEE_N31_ROOT);
    expect(testCommittee(7, 0).root()).toEqual(VEC_COMMITTEE_N7_ROOT);
    expect(testCommittee(4, 0).root()).toEqual(VEC_COMMITTEE_N4_ROOT);
}

get fun `test init is permissionless and runs once`() {
    testing.setNow(T0);
    val minter = deployUninitialized(canonicalDefault());
    expect(minter.getSccpState().initialized).toBeFalse();
    val stranger = testing.treasury("stranger");
    val first = minter.sendSccpInit(stranger.address, 1, { value: grams("1"), bounce: true });
    expect(first).toHaveSuccessfulTx<SccpInit>({ to: minter.address });
    expect(minter.getSccpState().initialized).toBeTrue();
    val before = minter.getSccpState();
    val second = sendInit(minter);
    expect(second).toHaveFailedTx<SccpInit>({
        to: minter.address,
        exitCode: SccpErrors.AlreadyInitialized as int,
    });
    // the refusal comes before the chain identity check, and changes nothing
    setGlobalId(-3);
    expectOutcome(sendInit(minter), SccpErrors.AlreadyInitialized);
    val after = minter.getSccpState();
    expect(after.initialized).toBeTrue();
    expect(after.untilMs).toEqual(before.untilMs);
    expect(after.opCount).toEqual(0);
}

get fun `test init in the deploy message completes the deployment`() {
    testing.setNow(T0);
    val deployer = testing.treasury("deployer");
    val (minter, res) = deployWithInit(canonicalDefault(), deployer.address, grams("5"));
    expect(res).toHaveSuccessfulDeploy({ to: minter.address });
    expect(minter.getSccpState().initialized).toBeTrue();
    // the address is the one the canonical initial data gives
    expect(minter.address).toEqual(SccpTairaXorMinter.fromStorage(canonicalDefault()).address);
    // another pin, key list, revision or cap gives another address
    var pin = defaultPin(testCommittee(4, 0));
    pin.untilMs = pin.untilMs + 1;
    expect(
        SccpTairaXorMinter.fromStorage(withPin(canonicalDefault(), pin)).address == minter.address,
    ).toBeFalse();
    expect(
        SccpTairaXorMinter.fromStorage(canonicalFor(testCommittee(4, 4))).address == minter.address,
    ).toBeFalse();
    var config = canonicalDefault().config.load();
    config.routeRevision = TEST_REVISION + 1;
    expect(
        SccpTairaXorMinter.fromStorage(withConfig(canonicalDefault(), config)).address ==
            minter.address,
    ).toBeFalse();
}

get fun `test init requires the ton mainnet global id`() {
    testing.setNow(T0);
    setGlobalId(-3);
    val minter = deployUninitialized(canonicalDefault());
    expectOutcome(sendInit(minter), SccpErrors.WrongChain);
    expect(minter.getSccpState().initialized).toBeFalse();
    // the testnet id, and a non-canonical deployment on another chain
    setGlobalId(-217);
    expectOutcome(sendInit(minter), SccpErrors.WrongChain);
    var paused = canonicalDefault();
    paused.parliamentPaused = true;
    expectOutcome(sendInit(deployUninitialized(paused)), SccpErrors.WrongChain);
    setGlobalId(SCCP_TON_GLOBAL_ID);
    expectOutcome(sendInit(minter), 0);
    expect(minter.getSccpState().initialized).toBeTrue();
}

// ---------------------------------------------------------------------------
// The bound on the pinned `untilMs` (§5.1.2 "Arithmetic", `init_bounds`).

get fun `test init applies the bound on the pinned untilMs at both ends`() {
    expect(VEC_INIT_BOUND_COUNT).toEqual(PINNED_INIT_BOUNDS);
    val nowMs = vecInitBoundNowMs();
    val untilMs = vecInitBoundUntilMs();
    val exits = vecInitBoundExits();
    expect(nowMs.size()).toEqual(PINNED_INIT_BOUNDS);
    expect(untilMs.size()).toEqual(PINNED_INIT_BOUNDS);
    expect(exits.size()).toEqual(PINNED_INIT_BOUNDS);
    val committee = testCommittee(4, 0);
    var row = 0;
    var accepted = 0;
    repeat (PINNED_INIT_BOUNDS) {
        expect(nowMs.get(row) % 1000).toEqual(0);
        testing.setNow(nowMs.get(row) / 1000);
        var pin = defaultPin(committee);
        pin.untilMs = untilMs.get(row);
        val code = initOutcome(withPin(canonicalFor(committee), pin));
        if (code != exits.get(row)) {
            println("init bound row {} expected {} observed {}", row, exits.get(row), code);
        }
        expect(code).toEqual(exits.get(row));
        // the contract function gives the same verdict
        expect(
            sccpInitUntilMsIsValid(nowMs.get(row), untilMs.get(row)),
        ).toEqual(exits.get(row) == 0);
        if (code == 0) {
            accepted += 1;
        } else {
            expect(code).toEqual(SccpErrors.BadConfig as int);
        }
        row += 1;
    }
    expect(row).toEqual(PINNED_INIT_BOUNDS);
    expect(accepted).toEqual(2);
}

get fun `test the init bound is now < until <= now + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`() {
    expect(SCCP_MAX_VALIDITY_MS).toEqual(VEC_MAX_VALIDITY_MS);
    expect(SCCP_MAX_INIT_SLACK_MS).toEqual(VEC_MAX_INIT_SLACK_MS);
    val bound = SCCP_MAX_VALIDITY_MS + SCCP_MAX_INIT_SLACK_MS;
    expect(sccpInitUntilMsIsValid(NOW_MS, NOW_MS - 1)).toBeFalse();
    expect(sccpInitUntilMsIsValid(NOW_MS, NOW_MS)).toBeFalse();
    expect(sccpInitUntilMsIsValid(NOW_MS, NOW_MS + 1)).toBeTrue();
    expect(sccpInitUntilMsIsValid(NOW_MS, NOW_MS + bound)).toBeTrue();
    expect(sccpInitUntilMsIsValid(NOW_MS, NOW_MS + bound + 1)).toBeFalse();
    expect(sccpInitUntilMsIsValid(0, 0)).toBeFalse();
    expect(sccpInitUntilMsIsValid(0, bound)).toBeTrue();
    // the difference is compared, so no sum leaves the u64 range
    expect(sccpInitUntilMsIsValid(SCCP_MAX_U64 - 1, SCCP_MAX_U64)).toBeTrue();
    expect(sccpInitUntilMsIsValid(SCCP_MAX_U64 - bound, SCCP_MAX_U64)).toBeTrue();
    expect(sccpInitUntilMsIsValid(SCCP_MAX_U64 - bound - 1, SCCP_MAX_U64)).toBeFalse();
    expect(sccpInitUntilMsIsValid(SCCP_MAX_U64, SCCP_MAX_U64)).toBeFalse();

    // Through the minter: a pin one second beyond the bound is refused, and
    // the same deployment is accepted one second later.
    val committee = testCommittee(4, 0);
    var pin = defaultPin(committee);
    pin.untilMs = NOW_MS + bound + 1000;
    testing.setNow(T0);
    val early = deployUninitialized(withPin(canonicalFor(committee), pin));
    val late = deployUninitialized(canonicalFor(committee));
    val inTime = deployUninitialized(canonicalFor(testCommittee(4, 4)));
    expectOutcome(sendInit(early), SccpErrors.BadConfig);
    expect(early.getSccpState().initialized).toBeFalse();
    testing.setNow(T0 + 1);
    expectOutcome(sendInit(early), 0);
    expect(early.getSccpState().initialized).toBeTrue();
    // a deployment that waits until its deadline can no longer be initialized
    testing.setNow(T0 + TEST_VALIDITY_MS / 1000 - 1);
    expectOutcome(sendInit(inTime), 0);
    testing.setNow(T0 + TEST_VALIDITY_MS / 1000);
    expectOutcome(sendInit(late), SccpErrors.BadConfig);
    expect(late.getSccpState().initialized).toBeFalse();
}

// ---------------------------------------------------------------------------
// Canonical initial data (§5.3.1).

get fun `test init rejects initial data that is not canonical`() {
    testing.setNow(T0);
    var cases: array<MinterStorage> = [];
    var s = canonicalDefault();
    s.equivocated = true;
    cases.push(s);
    s = canonicalDefault();
    s.totalSupply = 5;
    cases.push(s);
    s = canonicalDefault();
    s.pendingSupply = 5;
    cases.push(s);
    s = canonicalDefault();
    s.outboundNonce = 1;
    cases.push(s);
    s = canonicalDefault();
    s.opCount = 1;
    cases.push(s);
    s = canonicalDefault();
    s.controlNonce = 1;
    cases.push(s);
    s = canonicalDefault();
    s.parliamentPaused = true;
    cases.push(s);
    s = canonicalDefault();
    s.fastPauseUntilMs = 1;
    cases.push(s);
    s = canonicalDefault();
    s.deployedBuckets = 1;
    cases.push(s);
    // a recorded retry
    s = canonicalDefault();
    s.retries.set(5, SCCP_RETRY_UNCONSUME);
    cases.push(s);
    // checkpoints: an entry, another empty encoding, a reference, a library cell
    val empty = beginCell().storeUint(0, 2).endCell();
    s = canonicalDefault();
    s.checkpoints = beginCell().storeUint(1, 2).storeUint(1000, 64).storeUint(7, 256).endCell();
    cases.push(s);
    s = canonicalDefault();
    s.checkpoints = beginCell().storeUint(0, 3).endCell();
    cases.push(s);
    s = canonicalDefault();
    s.checkpoints = beginCell().storeUint(0, 2).storeRef(empty).endCell();
    cases.push(s);
    s = canonicalDefault();
    testing.registerLibrary(empty);
    s.checkpoints = empty.toLibraryReference();
    cases.push(s);
    var i = 0;
    repeat (cases.size()) {
        val code = initOutcome(cases.get(i));
        if (code != SccpErrors.BadConfig as int) {
            println("non-canonical case {} observed {}", i, code);
        }
        expect(code).toEqual(SccpErrors.BadConfig as int);
        i += 1;
    }
    expect(i).toEqual(14);
    // the canonical data itself is accepted
    expect(initOutcome(canonicalDefault())).toEqual(0);
}

get fun `test init rejects a configuration or pin that cannot be deployed`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    var cases: array<MinterStorage> = [];
    var config = canonicalDefault().config.load();
    config.tairaNetworkId = 0;
    cases.push(withConfig(canonicalDefault(), config));
    config = canonicalDefault().config.load();
    config.consensusInstance = 0;
    cases.push(withConfig(canonicalDefault(), config));
    config = canonicalDefault().config.load();
    config.routeRevision = 0;
    cases.push(withConfig(canonicalDefault(), config));
    config = canonicalDefault().config.load();
    config.maxSupply = 0;
    cases.push(withConfig(canonicalDefault(), config));
    // a pin of generation 0, with a zero root, or starting at height 0
    var pin = defaultPin(committee);
    pin.generation = 0;
    cases.push(withPin(canonicalDefault(), pin));
    pin = defaultPin(committee);
    pin.root = 0;
    cases.push(withPin(canonicalDefault(), pin));
    // `high = start − 1` has no value for a start of 0
    pin = defaultPin(committee);
    pin.start = 0;
    config = canonicalDefault().config.load();
    config.initial = pin.toCell();
    var zeroStart = canonicalDefault().committee.load();
    zeroStart.start = 0;
    zeroStart.high = 0;
    cases.push(withCommittee(withConfig(canonicalDefault(), config), zeroStart));
    var i = 0;
    repeat (cases.size()) {
        val code = initOutcome(cases.get(i));
        if (code != SccpErrors.BadConfig as int) {
            println("configuration case {} observed {}", i, code);
        }
        expect(code).toEqual(SccpErrors.BadConfig as int);
        i += 1;
    }
    expect(i).toEqual(7);
    // the smallest pin: generation 1 from height 1
    pin = defaultPin(committee);
    pin.generation = 1;
    pin.start = 1;
    val minter = deployUninitialized(withPin(canonicalDefault(), pin));
    expectOutcome(sendInit(minter), 0);
    val state = minter.getSccpState();
    expect(state.generation).toEqual(1);
    expect(state.start).toEqual(1);
    expect(state.high).toEqual(0);
}

// ---------------------------------------------------------------------------
// The stored committee is the committee of the pinned root.

get fun `test init rejects a root that differs from the stored keys`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    val other = testCommittee(4, 4);
    // the pin names another root than the committee state
    var config = canonicalDefault().config.load();
    var pin = defaultPin(committee);
    pin.root = other.root();
    config.initial = pin.toCell();
    expect(initOutcome(withConfig(canonicalDefault(), config))).toEqual(
        SccpErrors.BadCommittee as int,
    );
    // the committee state names another root than the pin
    var state = canonicalDefault().committee.load();
    state.root = other.root();
    expect(
        initOutcome(withCommittee(canonicalDefault(), state)),
    ).toEqual(SccpErrors.BadCommittee as int);
    // pin and committee state agree, and the keys are those of another committee
    expect(
        initOutcome(withPin(canonicalDefault(), defaultPin(other))),
    ).toEqual(SccpErrors.BadCommittee as int);
    // one key replaced
    state = canonicalDefault().committee.load();
    state.keys = sccpBuildKeys(
        [committee.keys.get(0), committee.keys.get(1), committee.keys.get(2), other.keys.get(3)],
    );
    expect(
        initOutcome(withCommittee(canonicalDefault(), state)),
    ).toEqual(SccpErrors.BadCommittee as int);
    // the right keys under their root are accepted
    expect(initOutcome(canonicalFor(other))).toEqual(0);
}

get fun `test init rejects unordered or duplicate keys under their own root`() {
    testing.setNow(T0);
    val keys = testCommittee(7, 0).keys;
    // the lists hash to the pinned root, and are no committees
    var swapped = keys;
    swapped.set(keys.get(1), 0);
    swapped.set(keys.get(0), 1);
    var swappedLast = keys;
    swappedLast.set(keys.get(6), 5);
    swappedLast.set(keys.get(5), 6);
    var twice = keys;
    twice.set(keys.get(2), 3);
    var descending: array<slice> = [];
    var i = 6;
    while (i >= 0) {
        descending.push(keys.get(i));
        i -= 1;
    }
    val lists: array<array<slice>> = [swapped, swappedLast, twice, descending];
    i = 0;
    repeat (lists.size()) {
        expect(sccpKeysAscend(lists.get(i))).toBeFalse();
        expect(
            initOutcome(canonicalWithListedKeys(lists.get(i))),
        ).toEqual(SccpErrors.BadCommittee as int);
        i += 1;
    }
    expect(i).toEqual(4);
    // the same construction with the canonical order is accepted
    expect(sccpKeysAscend(keys)).toBeTrue();
    expect(initOutcome(canonicalWithListedKeys(keys))).toEqual(0);
}

get fun `test init rejects a committee size that is not 3f + 1 between 4 and 31`() {
    testing.setNow(T0);
    // the keys are in canonical order and the pinned root is theirs
    val sizes: array<int> = [
        1,
        2,
        3,
        5,
        6,
        8,
        30,
        32,
        33,
        34,
    ];
    var i = 0;
    repeat (sizes.size()) {
        val keys = testCommittee(sizes.get(i), 0).keys;
        expect(sccpIsCommitteeSize(sizes.get(i))).toBeFalse();
        expect(
            initOutcome(canonicalWithListedKeys(keys)),
        ).toEqual(SccpErrors.BadCommittee as int);
        i += 1;
    }
    expect(i).toEqual(10);
    // `n` must be the number of keys in the list: a canonical list of another length
    val seven = testCommittee(7, 0);
    var state = canonicalFor(seven).committee.load();
    state.n = 4;
    expect(
        initOutcome(withCommittee(canonicalFor(seven), state)),
    ).toEqual(SccpErrors.BadSnake as int);
    state.n = 10;
    expect(
        initOutcome(withCommittee(canonicalFor(seven), state)),
    ).toEqual(SccpErrors.BadSnake as int);
    // an invalid `n` is refused before the list is read
    state.n = 5;
    expect(
        initOutcome(withCommittee(canonicalFor(seven), state)),
    ).toEqual(SccpErrors.BadCommittee as int);
    state.n = 0;
    expect(
        initOutcome(withCommittee(canonicalFor(seven), state)),
    ).toEqual(SccpErrors.BadCommittee as int);
}

get fun `test init rejects a key list that is not the canonical ordinary chain`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    val k0 = committee.keys.get(0);
    val k1 = committee.keys.get(1);
    val k2 = committee.keys.get(2);
    val k3 = committee.keys.get(3);
    val lastTwo = beginCell().storeSlice(k2).storeSlice(k3).storeUint(0, 1).endCell();
    // a published library with the canonical chain: CTOS alone would resolve it
    testing.registerLibrary(committee.keysCell());
    testing.registerLibrary(lastTwo);
    val lists: array<cell> = [
        committee.keysCell().toLibraryReference(),
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(lastTwo.toLibraryReference())
            .endCell(),
        // 1 + 2 + 1 keys: not maximally packed
        beginCell()
            .storeSlice(k0)
            .storeMaybeRef(
                beginCell()
                    .storeSlice(k1)
                    .storeSlice(k2)
                    .storeMaybeRef(beginCell().storeSlice(k3).storeUint(0, 1).endCell())
                    .endCell(),
            )
            .endCell(),
        // a trailing byte in the last chunk
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(
                beginCell().storeSlice(k2).storeSlice(k3).storeUint(0, 1).storeUint(0, 8).endCell(),
            )
            .endCell(),
        // the Maybe bit set on the last chunk
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(beginCell().storeSlice(k2).storeSlice(k3).storeUint(1, 1).endCell())
            .endCell(),
        // the Maybe bit set on the first chunk without a next chunk
        beginCell().storeSlice(k0).storeSlice(k1).storeUint(1, 1).endCell(),
        // a stray reference on the last chunk
        beginCell()
            .storeSlice(k0)
            .storeSlice(k1)
            .storeMaybeRef(
                beginCell()
                    .storeSlice(k2)
                    .storeSlice(k3)
                    .storeUint(0, 1)
                    .storeRef(lastTwo)
                    .endCell(),
            )
            .endCell(),
    ];
    var i = 0;
    repeat (lists.size()) {
        var state = canonicalDefault().committee.load();
        state.keys = lists.get(i);
        val code = initOutcome(withCommittee(canonicalDefault(), state));
        if (code != SccpErrors.BadSnake as int) {
            println("key list case {} observed {}", i, code);
        }
        expect(code).toEqual(SccpErrors.BadSnake as int);
        i += 1;
    }
    expect(i).toEqual(7);
}

get fun `test init rejects committee fields that differ from the pin`() {
    testing.setNow(T0);
    var cases: array<CommitteeState> = [];
    var state = canonicalDefault().committee.load();
    state.generation = TEST_GENERATION + 1;
    cases.push(state);
    state = canonicalDefault().committee.load();
    state.start = TEST_START_HEIGHT + 1;
    cases.push(state);
    // high must be start − 1
    state = canonicalDefault().committee.load();
    state.high = TEST_START_HEIGHT;
    cases.push(state);
    state = canonicalDefault().committee.load();
    state.high = TEST_START_HEIGHT - 2;
    cases.push(state);
    state = canonicalDefault().committee.load();
    state.untilMs = state.untilMs + 1;
    cases.push(state);
    state = canonicalDefault().committee.load();
    state.untilMs = 0;
    cases.push(state);
    var i = 0;
    repeat (cases.size()) {
        val code = initOutcome(withCommittee(canonicalDefault(), cases.get(i)));
        if (code != SccpErrors.BadConfig as int) {
            println("committee field case {} observed {}", i, code);
        }
        expect(code).toEqual(SccpErrors.BadConfig as int);
        i += 1;
    }
    expect(i).toEqual(6);
    // the keys are judged before these fields
    state = canonicalDefault().committee.load();
    state.generation = TEST_GENERATION + 1;
    state.keys = testCommittee(4, 4).keysCell();
    expect(
        initOutcome(withCommittee(canonicalDefault(), state)),
    ).toEqual(SccpErrors.BadCommittee as int);
    // and non-canonical counters before the keys
    var storage = withCommittee(canonicalDefault(), state);
    storage.opCount = 1;
    expect(initOutcome(storage)).toEqual(SccpErrors.BadConfig as int);
}

// ---------------------------------------------------------------------------
// Before init.

/// Sends every operation that requires an initialized minter from `user`,
/// with well-formed bodies: the certificate `cert`, the transfer `d` and the
/// control `c` are genuinely certified. Returns the eleven results.
fun sendEveryOperation(
    env: Env,
    user: address,
    cert: cell,
    d: Delivery,
    c: ControlDelivery,
): array<SendResultList> {
    val minter = env.minter;
    val value: SendParams = { value: grams("2"), bounce: true };
    return [
        sendCheckpoint(env, user, cert, null, grams("2")),
        sendFinalize(env, user, d, grams("2")),
        sendFinalizeCheckpoint(env, user, d, grams("2")),
        sendVoidExpired(env, user, 0, d, grams("2")),
        sendVoidExpiredCheckpoint(env, user, 0, d, grams("2")),
        sendApplyControl(env, c),
        sendApplyControlCheckpoint(env, c),
        sendVoidFrozen(env, 0, 1, grams("2")),
        minter.sendSccpDeployBuckets(user, 0, user, 1, value),
        minter.sendSccpRetry(user, 0, user, 0, value),
        // a burn notification from the owner's canonical wallet (forged sender)
        minter.sendBurnNotificationForMinter(
            minter.getWalletAddress(user),
            0,
            10,
            user,
            user,
            { recipient: snakeOfLength(8) },
            value,
        ),
    ];
}

/// Expects every call to end with `NotInitialized` and without an event;
/// returns their number.
fun expectAllNotInitialized(calls: array<SendResultList>): int {
    val notInitialized = SccpErrors.NotInitialized as int;
    var i = 0;
    repeat (calls.size()) {
        if (outcomeOf(calls.get(i)) != notInitialized) {
            println("call {} observed {}", i, outcomeOf(calls.get(i)));
        }
        expectOutcome(calls.get(i), notInitialized);
        expectEvents(calls.get(i), []);
        i += 1;
    }
    return i;
}

get fun `test operations throw before init`() {
    testing.setNow(T0);
    val committee = testCommittee(4, 0);
    val minter = deployUninitialized(canonicalFor(committee));
    val user = testing.treasury("user");
    val env: Env = {
        minter,
        deployer: user.address,
        networkId: VEC_NETWORK_ID,
        instance: VEC_CONSENSUS_INSTANCE,
        generation: TEST_GENERATION,
        committee,
    };
    // well-formed, genuinely certified bodies
    val d = deliverDefault(env, 0, 1000, user.address);
    val c = deliverControl(env, 1, true);
    val x = emptyX(env.networkId, env.generation, committee.root(), TEST_START_HEIGHT + 5);
    val cert = certifyFor(env, committee, x);
    expect(
        expectAllNotInitialized(sendEveryOperation(env, user.address, cert, d, c)),
    ).toEqual(11);
    // on another chain every one of them answers NotInitialized first
    setGlobalId(-3);
    expect(
        expectAllNotInitialized(sendEveryOperation(env, user.address, cert, d, c)),
    ).toEqual(11);
    setGlobalId(SCCP_TON_GLOBAL_ID);
    val state = minter.getSccpState();
    expect(state.initialized).toBeFalse();
    expect(state.high).toEqual(TEST_START_HEIGHT - 1);
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

    // top-ups and wallet address requests are served before init
    val topUp = minter.sendTopUpTons(user.address, 0, { value: grams("1") });
    expect(topUp).toHaveSuccessfulTx<TopUpTons>({ to: minter.address });
    expect(
        minter.getWalletAddress(user.address),
    ).toEqual(sccpWalletAddress(user.address, minter.address, build("SccpTairaXorWallet")));
    // after init the same checkpoint is accepted
    expectOutcome(sendInit(minter), 0);
    expectOutcome(
        sendCheckpoint(env, user.address, certifyFor(env, committee, x), null, grams("2")),
        0,
    );
}

// ---------------------------------------------------------------------------
// Layout of the canonical initial data and of the get methods (§5.3.1, §5.3.6).

get fun `test canonical storage matches the TL-B bit layout`() {
    val committee = testCommittee(31, 0);
    val storage = canonicalFor(committee);
    // minter_data: initialized(1) equivocated(1) total(4) pending(4) outbound(64)
    // op(64) control(64) paused(1) fast_pause(64) deployed(64) retries(1)
    var root = storage.toCell().beginParse();
    expect(root.remainingBitsCount()).toEqual(332);
    expect(root.remainingRefsCount()).toEqual(3);
    // every counter is zero and `retries` is the empty dictionary
    expect(root.loadUint(256)).toEqual(0);
    expect(root.loadUint(76)).toEqual(0);
    // minter_config: network(256) instance(256) revision(32) cap(Coins)
    val config = storage.config.beginParse();
    expect(config.remainingBitsCount()).toEqual(256 + 256 + 32 + 4 + 64);
    expect(config.remainingRefsCount()).toEqual(3);
    // initial_pin: generation(64) root(256) start(64) until_ms(64)
    val pin = storage.config.load().initial.beginParse();
    expect(pin.remainingBitsCount()).toEqual(448);
    expect(pin.remainingRefsCount()).toEqual(0);
    // committee_state: root(256) until_ms(64) start(64) high(64) generation(64) n(8)
    val state = storage.committee.beginParse();
    expect(state.remainingBitsCount()).toEqual(520);
    expect(state.remainingRefsCount()).toEqual(1);
    // checkpoints: count(2) = 0
    val checkpoints = storage.checkpoints.beginParse();
    expect(checkpoints.remainingBitsCount()).toEqual(2);
    expect(checkpoints.remainingRefsCount()).toEqual(0);
    expect(Checkpoints.isCanonicalEmpty(storage.checkpoints)).toBeTrue();
    // key_chunk: two keys and a Maybe bit; the last chunk of 31 keys holds one
    var chunk = storage.committee.load().keys.beginParse();
    var chunks = 1;
    while (chunk.remainingRefsCount() == 1) {
        expect(chunk.remainingBitsCount()).toEqual(769);
        chunk = chunk.preloadRef().beginParse();
        chunks += 1;
    }
    expect(chunk.remainingBitsCount()).toEqual(385);
    expect(chunks).toEqual(SCCP_MAX_KEY_CHUNKS);
    // a cap of 2^120 − 1 is the widest Coins value: 668 bits of configuration
    var widest = storage.config.load();
    widest.maxSupply = (1 << 120) - 1;
    expect(widest.toCell().beginParse().remainingBitsCount()).toEqual(668);
}

get fun `test get methods return their fields in the order of the specification`() {
    // every field holds a value of its own (white box)
    testing.setNow(T0);
    val deployer = testing.treasury("deployer").address;
    val committee = testCommittee(7, 0);
    var storage = canonicalFor(committee);
    storage.initialized = true;
    storage.totalSupply = 20;
    storage.pendingSupply = 21;
    storage.outboundNonce = 14;
    storage.opCount = 15;
    storage.controlNonce = 19;
    storage.fastPauseUntilMs = 17;
    storage.deployedBuckets = 23;
    var state = storage.committee.load();
    state.untilMs = NOW_MS + 10;
    state.start = 1011;
    state.high = 1012;
    state.generation = 13;
    storage.committee = state.toCell();
    var slots = Checkpoints.load(storage.checkpoints);
    expect(slots.insert(1001, 0xA1)).toBeTrue();
    expect(slots.insert(1002, 0xA2)).toBeTrue();
    expect(slots.insert(1003, 0xA3)).toBeTrue();
    storage.checkpoints = slots.toCell();
    storage.retries.set(77, SCCP_RETRY_ACTIVATE);
    val minter = installPinned(storage, deployer, grams("5"));

    val reply = net.runGetMethod<tuple>(minter.address, "get_sccp_state");
    val root = committee.root();
    val expected: array<int> = [
        // initialized, equivocated
        -1,
        0,
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        // the initial pin
        TEST_GENERATION,
        root,
        TEST_START_HEIGHT,
        NOW_MS + TEST_VALIDITY_MS,
        // cur: root, until_ms, start, high, generation
        root,
        NOW_MS + 10,
        1011,
        1012,
        13,
        // outbound_nonce, op_count, parliament_paused, fast_pause_until_ms
        14,
        15,
        0,
        17,
        // effective_paused, control_nonce
        0,
        19,
        // total_supply, pending_supply, max_supply, deployed_buckets
        20,
        21,
        TEST_MAX_SUPPLY,
        23,
    ];
    expect(reply.size()).toEqual(24);
    var i = 0;
    repeat (24) {
        if ((reply.get(i) as int) != expected.get(i)) {
            println("get_sccp_state field {} differs", i);
        }
        expect(reply.get(i) as int).toEqual(expected.get(i));
        i += 1;
    }

    val current = net.runGetMethod<tuple>(minter.address, "get_sccp_committee");
    expect(current.size()).toEqual(7);
    expect(current.get(0) as int).toEqual(root);
    expect(current.get(1) as int).toEqual(NOW_MS + 10);
    expect(current.get(2) as int).toEqual(1011);
    expect(current.get(3) as int).toEqual(1012);
    expect(current.get(4) as int).toEqual(13);
    expect(current.get(5) as int).toEqual(7);
    expect((current.get(6) as cell).hash()).toEqual(committee.keysCell().hash());

    val stored = net.runGetMethod<tuple>(minter.address, "get_sccp_checkpoints");
    expect(stored.size()).toEqual(7);
    expect(stored.get(0) as int).toEqual(3);
    expect(stored.get(1) as int).toEqual(1001);
    expect(stored.get(2) as int).toEqual(0xA1);
    expect(stored.get(3) as int).toEqual(1002);
    expect(stored.get(4) as int).toEqual(0xA2);
    expect(stored.get(5) as int).toEqual(1003);
    expect(stored.get(6) as int).toEqual(0xA3);

    expect(minter.getSccpRetry(77)).toEqual(SCCP_RETRY_ACTIVATE);
    expect(minter.getSccpRetry(78)).toEqual(0);
    expect(minter.getJettonData().totalSupply).toEqual(20);
    expect(minter.getBucketAddress(3)).toEqual(
        sccpBucketAddress(minter.address, 3, build("SccpConsumedBucket")),
    );
    // the effective pause follows the clock of the call
    expect(minter.getSccpState().effectivePaused).toBeFalse();
    var paused = storage;
    paused.fastPauseUntilMs = NOW_MS + 1;
    val later = installPinned(paused, deployer, grams("5"));
    expect(later.getSccpState().effectivePaused).toBeTrue();
    testing.setNow(T0 + 1);
    expect(later.getSccpState().effectivePaused).toBeFalse();
    paused.parliamentPaused = true;
    expect(installPinned(paused, deployer, grams("5")).getSccpState().effectivePaused).toBeTrue();
}
