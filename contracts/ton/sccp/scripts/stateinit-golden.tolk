// Emits the canonical minter StateInit vectors of `fixtures/sccp/ton_stateinit_v1.json`
// computed with the contracts' own types and compiled code (§5.3.1).
//
// Run by `scripts/generate_ton_sccp_stateinit_golden.py`, which recomputes
// every value independently in Python and fails on any difference. Output
// lines are `sccp-stateinit <vector> <key>=<value>` with lowercase hex.
//
// The pinned committees are `n4` and `n31` of `fixtures/sccp/finality_v1.json`,
// read from the generated test vectors; the Taira `NetworkId` and the
// consensus instance are the fixture's verification context.

import "@acton/build"
import "@acton/io"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-finality"
import "@contracts/sccp-recovery"
import "@contracts/sccp-storage"
import "@tests/unit/sccp-test-vectors.gen"

/// Compressed keys of the committee whose members are the test keys
/// `indices`, in the given (canonical) order.
fun committeeKeys(indices: array<int>): array<slice> {
    val publics = vecKeyPublics();
    var keys: array<slice> = [];
    var i = 0;
    while (i < indices.size()) {
        keys.push(publics.get(indices.get(i)));
        i += 1;
    }
    return keys;
}

fun printCode(name: string, key: string) {
    val code = build(name);
    println("sccp-stateinit code {}_code_hash={:064x}", key, code.hash());
    println("sccp-stateinit code {}_code_depth={}", key, code.depth());
}

fun emitVector(
    label: string,
    revision: int,
    maxSupply: int,
    generation: int,
    start: int,
    untilMs: int,
    keys: array<slice>,
) {
    val n = keys.size();
    val keysCell = sccpBuildKeys(keys);
    // the stored list passes the checks of `sccp_init`: a committee size,
    // strictly ascending keys and their committee root
    val root = sccpCommitteeRoot(n, sccpLoadKeys(keysCell, n).parts);
    sccpRequireStoredCommittee(keysCell, n, root);
    val pin: InitialPin = {
        generation,
        root,
        start,
        untilMs,
    };
    val config: MinterConfig = {
        tairaNetworkId: VEC_NETWORK_ID,
        consensusInstance: VEC_CONSENSUS_INSTANCE,
        routeRevision: revision,
        maxSupply,
        initial: pin.toCell(),
        walletCode: build("SccpTairaXorWallet"),
        bucketCode: build("SccpConsumedBucket"),
    };
    val committee: CommitteeState = {
        root,
        untilMs,
        start,
        high: start - 1,
        generation,
        n,
        keys: keysCell,
    };
    val noCheckpoints: Checkpoints = {
        count: 0,
        h0: 0,
        id0: 0,
        h1: 0,
        id1: 0,
        h2: 0,
        id2: 0,
    };
    val checkpoints = noCheckpoints.toCell();
    val storage: MinterStorage = {
        initialized: false,
        equivocated: false,
        totalSupply: 0,
        pendingSupply: 0,
        outboundNonce: 0,
        opCount: 0,
        controlNonce: 0,
        parliamentPaused: false,
        fastPauseUntilMs: 0,
        deployedBuckets: 0,
        config: config.toCell(),
        committee: committee.toCell(),
        checkpoints,
        recovery: RecoveryBook.empty().toCell(),
    };
    val data = storage.toCell();
    val code = build("SccpTairaXorMinter");
    val stateInitHash = StateInit.calcHashCodeData(code, data);
    val deployment: AutoDeployAddress = { workchain: BASECHAIN, stateInit: { code, data } };
    val (workchain, accountId) = deployment.calculateAddress().getWorkchainAndHash();
    println("sccp-stateinit {} committee_root={:064x}", label, root);
    println("sccp-stateinit {} pin_hash={:064x}", label, pin.toCell().hash());
    println("sccp-stateinit {} config_hash={:064x}", label, config.toCell().hash());
    println("sccp-stateinit {} committee_hash={:064x}", label, committee.toCell().hash());
    println("sccp-stateinit {} keys_hash={:064x}", label, keysCell.hash());
    println("sccp-stateinit {} checkpoints_hash={:064x}", label, checkpoints.hash());
    println("sccp-stateinit {} recovery_hash={:064x}", label, storage.recovery.hash());
    println("sccp-stateinit {} data_hash={:064x}", label, data.hash());
    println("sccp-stateinit {} data_depth={}", label, (data as cell).depth());
    println("sccp-stateinit {} state_init_hash={:064x}", label, stateInitHash);
    println("sccp-stateinit {} workchain={}", label, workchain);
    println("sccp-stateinit {} account_id={:064x}", label, accountId);

    // derived child addresses under this minter
    val minter = address.fromWorkchainAndHash(workchain, accountId);
    val owner = address.fromWorkchainAndHash(
        0,
        0xabababababababababababababababababababababababababababababababab,
    );
    val (_, walletId) = sccpWalletAddress(
        owner,
        minter,
        build("SccpTairaXorWallet"),
    ).getWorkchainAndHash();
    val (_, bucket0) = sccpBucketAddress(
        minter,
        0,
        build("SccpConsumedBucket"),
    ).getWorkchainAndHash();
    val (_, bucket1) = sccpBucketAddress(
        minter,
        1,
        build("SccpConsumedBucket"),
    ).getWorkchainAndHash();
    println("sccp-stateinit {} wallet_of_abab={:064x}", label, walletId);
    println("sccp-stateinit {} bucket_0={:064x}", label, bucket0);
    println("sccp-stateinit {} bucket_1={:064x}", label, bucket1);
}

fun main() {
    printCode("SccpTairaXorMinter", "minter");
    printCode("SccpTairaXorWallet", "wallet");
    printCode("SccpConsumedBucket", "bucket");
    emitVector(
        "n4",
        1,
        1000000000000000000,
        7,
        7000,
        1791209600000,
        committeeKeys(vecCommitteeN4()),
    );
    emitVector(
        "n31",
        2,
        0xffffffffffffffffffffffff,
        12,
        86400,
        1801209600000,
        committeeKeys(vecCommitteeN31()),
    );
}
