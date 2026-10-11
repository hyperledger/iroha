// Shared fixtures of the SCCP v1 TON emulator suite: committees of the
// fixture test keys, finality headers and certificates signed in the test VM
// (`sccp-test-bls.tolk`), commitment and history trees, payloads, the minter
// deployment pinned at account id `0:35…35`, message senders and the replay
// harness that the generated fixture rows drive
// (`sccp-cert-vectors.gen.tolk`).
//
// The fixtures of `fixtures/sccp/` commit their TON rows to the placeholder
// minter account id `0x35…35` (the destination word of control and transfer
// leaves), so every helper here deploys the minter and then places it at that
// address in the emulator (`deployPinned`).

import "@acton/build"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/big_array"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-bls"
import "sccp-test-vectors.gen"

/// Fixed emulator time (seconds) at which every test starts.
const T0 = 1800000000
const DAY_MS = 86400000
const HOUR_MS = 3600000
const TEST_REVISION = 1
const TEST_MAX_SUPPLY = 1000000000000000000
const TEST_SENDER_LEN = 35
/// Pin of the default test deployment: generation, start height and validity.
const TEST_GENERATION = 7
const TEST_START_HEIGHT = 1000
const TEST_VALIDITY_MS = 1209600000
/// Value attached to a replayed fixture call: far above every step value, so
/// a replayed outcome never depends on fees.
const REPLAY_VALUE = 50000000000

// ---------------------------------------------------------------------------
// Committees (§3.7).

/// A committee generation in canonical order: the compressed G1 keys,
/// strictly ascending as byte strings, and the secret scalar of each member.
/// The committee of a replayed fixture deployment has no secrets.
struct TestCommittee {
    keys: array<slice>
    secrets: array<int>
}

/// The committee of the fixture test keys `indices` (`vecKeyPublics`), put
/// into canonical order.
fun makeCommittee(indices: array<int>): TestCommittee {
    val publics = vecKeyPublics();
    val allSecrets = vecKeySecrets();
    var order = indices;
    // insertion sort by the compressed key bytes
    var i = 1;
    while (i < order.size()) {
        var j = i;
        while (
            (j > 0) &&
            (sccpLexCompare(publics.get(order.get(j)), publics.get(order.get(j - 1))) < 0)
        ) {
            val moved = order.get(j);
            order.set(order.get(j - 1), j);
            order.set(moved, j - 1);
            j -= 1;
        }
        i += 1;
    }
    var keys: array<slice> = [];
    var secrets: array<int> = [];
    i = 0;
    while (i < order.size()) {
        keys.push(publics.get(order.get(i)));
        secrets.push(allSecrets.get(order.get(i)));
        i += 1;
    }
    return { keys, secrets };
}

/// The committee of the `n` test keys `firstKey .. firstKey + n − 1`.
/// Committees with disjoint key ranges have different roots.
fun testCommittee(n: int, firstKey: int): TestCommittee {
    var indices: array<int> = [];
    var i = 0;
    while (i < n) {
        indices.push(firstKey + i);
        i += 1;
    }
    return makeCommittee(indices);
}

fun TestCommittee.n(self): int {
    return self.keys.size();
}

/// `q = n − f` (§3.8).
fun TestCommittee.q(self): int {
    return sccpQuorum(self.keys.size());
}

/// The canonical `^KeyChunk` list of the committee.
fun TestCommittee.keysCell(self): cell {
    return sccpBuildKeys(self.keys);
}

/// `committee_root` of §3.7, computed as the contract computes it.
fun TestCommittee.root(self): int {
    val n = self.keys.size();
    return sccpCommitteeRoot(n, sccpLoadKeys(self.keysCell(), n).parts);
}

/// The signer bitmap of the `q` members with the lowest canonical indices.
fun TestCommittee.lowestSigners(self): int {
    return (1 << self.q()) - 1;
}

/// The signer bitmap of the `q` members with the highest canonical indices.
fun TestCommittee.highestSigners(self): int {
    return ((1 << self.q()) - 1) << (self.n() - self.q());
}

/// Secret scalars of the members whose bit is set in `signers`, in ascending
/// index order.
fun TestCommittee.secretsOf(self, signers: int): array<int> {
    var secrets: array<int> = [];
    var i = 0;
    while (i < self.secrets.size()) {
        if (((signers >> i) & 1) != 0) {
            secrets.push(self.secrets.get(i));
        }
        i += 1;
    }
    return secrets;
}

// ---------------------------------------------------------------------------
// Finality headers and certificates (§3.6–§3.8, §5.3.2).

/// The fields of a finality header `X` (§3.6). Nothing is validated, so a
/// test builds a header that breaks X1–X7 as easily as a genuine one.
struct TestX {
    networkId: int
    height: int
    timestampMs: int
    flags: int
    messageCount: int
    sccpRoot: int
    historySize: int
    historyRoot: int
    generation: int
    committeeRoot: int
    validityMs: int
    nextCommitteeRoot: int
}

/// `X[0..109)`: the 872 data bits of `XHead`.
fun TestX.headBits(self): builder {
    return beginCell()
        .storeUint(SCCP_X_MAGIC, 128)
        .storeUint(self.networkId, 256)
        .storeUint(self.height, 64)
        .storeUint(self.timestampMs, 64)
        .storeUint(self.flags, 8)
        .storeUint(self.messageCount, 32)
        .storeUint(self.sccpRoot, 256)
        .storeUint(self.historySize, 64);
}

/// `X[109..221)`: the 896 data bits of `XTail`.
fun TestX.tailBits(self): builder {
    return beginCell()
        .storeUint(self.historyRoot, 256)
        .storeUint(self.generation, 64)
        .storeUint(self.committeeRoot, 256)
        .storeUint(self.validityMs, 64)
        .storeUint(self.nextCommitteeRoot, 256);
}

/// The `^XHead` cell with its `^XTail`.
fun TestX.toCell(self): cell {
    return self.headBits().storeRef(self.tailBits().endCell()).endCell();
}

/// `checkpoint_id(X) = keccak256(X)`.
fun TestX.id(self): int {
    return keccak256Builders2(self.headBits(), self.tailBits());
}

/// The `^CheckpointRef` that names this header.
fun TestX.ref(self): cell {
    return beginCell().storeRef(self.toCell()).endCell();
}

/// The fields of `QC_FIXED` without its `signers` word (§3.7).
struct TestQc {
    epoch: int
    epochContext: int
    view: int
    blockHash: int
    resultBody: int
}

/// The `^QcFixed` cell (896 bits).
fun TestQc.toCell(self): cell {
    return beginCell()
        .storeUint(self.epoch, 64)
        .storeUint(self.epochContext, 256)
        .storeUint(self.view, 64)
        .storeUint(self.blockHash, 256)
        .storeUint(self.resultBody, 256)
        .endCell();
}

/// Deterministic `QC_FIXED` fields for the block at `height`.
fun defaultQc(height: int): TestQc {
    return {
        epoch: 1,
        epochContext: keccak256Builder(beginCell().storeUint(0xEC, 8).storeUint(height, 64)),
        view: 0,
        blockHash: keccak256Builder(beginCell().storeUint(0xB0, 8).storeUint(height, 64)),
        resultBody: keccak256Builder(beginCell().storeUint(0xDB, 8).storeUint(height, 64)),
    };
}

/// `R = SHA-256(RESULT_TAG ‖ X ‖ result_body)` (§3.6).
fun resultOf(x: TestX, resultBody: int): int {
    return sha256Parts(
        [
            beginCell().storeUint(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
            x.headBits(),
            x.tailBits(),
            beginCell().storeUint(resultBody, 256),
        ],
    );
}

/// `m = SHA-256(P)` of a consensus vote (§3.7) as the 256-bit slice that is
/// signed: `P = "sumeragi/sig" ‖ kind ‖ I ‖ be64(epoch) ‖ epoch_context ‖
/// be64(height) ‖ be64(view) ‖ block_hash ‖ R`. A test passes another `kind`,
/// instance or height to build a signature the minter must refuse.
fun voteMessage(kind: int, instance: int, height: int, qc: TestQc, r: int): slice {
    return sha256PartsToSlice(
        [
            beginCell()
                .storeUint(SCCP_SIG_TAG, SCCP_SIG_TAG_BITS)
                .storeUint(kind, 8)
                .storeUint(instance, 256)
                .storeUint(qc.epoch, 64)
                .storeUint(qc.epochContext, 256)
                .storeUint(height, 64)
                .storeUint(qc.view, 64),
            beginCell().storeUint(qc.blockHash, 256).storeUint(r, 256),
        ],
    );
}

/// The Commit message of `qc` over `x` under the consensus instance `instance`.
fun commitMessage(instance: int, qc: TestQc, x: TestX): slice {
    return voteMessage(SCCP_KIND_COMMIT, instance, x.height, qc, resultOf(x, qc.resultBody));
}

/// A `^TairaCert` from the contents of its four cells, as the fixtures give
/// them. No shape is enforced, so a row of another length yields the malformed
/// cell it describes.
fun certCell(signature: slice, signers: int, qc: slice, head: slice, tail: slice): cell {
    return beginCell()
        .storeSlice(signature)
        .storeUint(signers, 32)
        .storeRef(beginCell().storeSlice(qc).endCell())
        .storeRef(xCell(head, tail))
        .endCell();
}

/// A `^XHead` with its `^XTail` from the two byte strings of `X`.
fun xCell(head: slice, tail: slice): cell {
    return beginCell().storeSlice(head).storeRef(beginCell().storeSlice(tail).endCell()).endCell();
}

/// A `^CheckpointRef` from the two byte strings of `X`.
fun checkpointRefCell(head: slice, tail: slice): cell {
    return beginCell().storeRef(xCell(head, tail)).endCell();
}

/// A `^TairaCert` over `x` and `qc` with the given signature and signer bitmap.
fun certOf(signature: slice, signers: int, qc: TestQc, x: TestX): cell {
    return beginCell()
        .storeSlice(signature)
        .storeUint(signers, 32)
        .storeRef(qc.toCell())
        .storeRef(x.toCell())
        .endCell();
}

/// The genuine `CommitQC` over `x`: the aggregate signature of the members of
/// `committee` whose bit is set in `signers`, under the instance `instance`.
fun certifyBy(committee: TestCommittee, signers: int, instance: int, qc: TestQc, x: TestX): cell {
    val signature = blsAggregateSign(committee.secretsOf(signers), commitMessage(instance, qc, x));
    return certOf(signature, signers, qc, x);
}

/// The `CommitQC` over `x` by the lowest `q` members of `committee` under the
/// fixture consensus instance, with `defaultQc`.
fun certify(committee: TestCommittee, x: TestX): cell {
    return certifyBy(
        committee,
        committee.lowestSigners(),
        VEC_CONSENSUS_INSTANCE,
        defaultQc(x.height),
        x,
    );
}

// ---------------------------------------------------------------------------
// Trees.

/// Promote-odd root (§3.4) of `leaves`.
fun treeRoot(leaves: array<int>): int {
    var level = leaves;
    while (level.size() > 1) {
        var next: array<int> = [];
        var i = 0;
        while (i + 1 < level.size()) {
            next.push(sccpNode(level.get(i), level.get(i + 1)));
            i += 2;
        }
        if (level.size() % 2 == 1) {
            next.push(level.get(level.size() - 1));
        }
        level = next;
    }
    return level.get(0);
}

/// Sibling path of leaf `index`.
fun treePath(leaves: array<int>, index: int): array<int> {
    var path: array<int> = [];
    var level = leaves;
    var i = index;
    while (level.size() > 1) {
        val sibling = i ^ 1;
        if (sibling < level.size()) {
            path.push(level.get(sibling));
        }
        var next: array<int> = [];
        var j = 0;
        while (j + 1 < level.size()) {
            next.push(sccpNode(level.get(j), level.get(j + 1)));
            j += 2;
        }
        if (level.size() % 2 == 1) {
            next.push(level.get(level.size() - 1));
        }
        level = next;
        i = i >> 1;
    }
    return path;
}

/// Deterministic filler leaf `i`.
fun fillerLeaf(i: int): int {
    return keccak256Builder(beginCell().storeUint(0xF1, 8).storeUint(i, 32));
}

/// `count` filler leaves with `leaf` at `index`.
fun leavesWith(leaf: int, index: int, count: int): array<int> {
    var leaves: array<int> = [];
    var i = 0;
    while (i < count) {
        leaves.push(i == index ? leaf : fillerLeaf(i));
        i += 1;
    }
    return leaves;
}

// ---------------------------------------------------------------------------
// Headers of test blocks.

/// The header of a block of generation `generation` under the committee root
/// `committeeRoot` whose own leaves are `leaves`; the history is just this
/// block (size 1).
fun blockX(
    networkId: int,
    generation: int,
    committeeRoot: int,
    height: int,
    leaves: array<int>,
): TestX {
    val root = treeRoot(leaves);
    return {
        networkId,
        height,
        timestampMs: T0 * 1000 - 60000,
        flags: SCCP_X_FLAG_ACTIVE,
        messageCount: leaves.size(),
        sccpRoot: root,
        historySize: 1,
        historyRoot: sccpHistoryLeaf(height, root, leaves.size()),
        generation,
        committeeRoot,
        validityMs: 0,
        nextCommitteeRoot: 0,
    };
}

/// The header of a block without SCCP messages and with an empty history.
fun emptyX(networkId: int, generation: int, committeeRoot: int, height: int): TestX {
    return {
        networkId,
        height,
        timestampMs: T0 * 1000 - 60000,
        flags: SCCP_X_FLAG_ACTIVE,
        messageCount: 0,
        sccpRoot: 0,
        historySize: 0,
        historyRoot: 0,
        generation,
        committeeRoot,
        validityMs: 0,
        nextCommitteeRoot: 0,
    };
}

/// The handoff header at `height` that ends `generation` and names the
/// successor root `nextRoot`, valid for `validityMs` from `timestampMs`. With
/// `nextRoot = committeeRoot` it is a heartbeat.
fun rotationX(
    networkId: int,
    generation: int,
    committeeRoot: int,
    height: int,
    timestampMs: int,
    nextRoot: int,
    validityMs: int,
): TestX {
    var x = emptyX(networkId, generation, committeeRoot, height);
    x.timestampMs = timestampMs;
    x.flags = SCCP_X_FLAG_ACTIVE | SCCP_X_FLAG_ROTATION;
    x.validityMs = validityMs;
    x.nextCommitteeRoot = nextRoot;
    return x;
}

/// History of `blocks` SCCP-bearing blocks where block `index` carries
/// `(root, count)` and the others are fillers; returns the history leaves.
fun historyLeaves(blocks: int, index: int, height: int, root: int, count: int): array<int> {
    var leaves: array<int> = [];
    var i = 0;
    while (i < blocks) {
        leaves.push(
            i == index
                ? sccpHistoryLeaf(height, root, count)
                : sccpHistoryLeaf(1000 + i, fillerLeaf(5000 + i), 1),
        );
        i += 1;
    }
    return leaves;
}

// ---------------------------------------------------------------------------
// Payloads.

/// Taira→TON payload (§3.2) with a 35-byte sender.
fun inboundPayloadCell(
    nonce: int,
    revision: int,
    deadlineMs: int,
    amount: int,
    recipientHash: int,
): cell {
    return inboundPayloadWithSender(
        nonce,
        revision,
        deadlineMs,
        amount,
        recipientHash,
        TEST_SENDER_LEN,
    );
}

/// Taira→TON payload (§3.2) with a `senderLen`-byte sender (1..=1024).
fun inboundPayloadWithSender(
    nonce: int,
    revision: int,
    deadlineMs: int,
    amount: int,
    recipientHash: int,
    senderLen: int,
): cell {
    var w = SnakeWriter.create();
    w.writeUint(SCCP_PAYLOAD_KIND_TRANSFER, 1);
    w.writeUint(SCCP_PAYLOAD_VERSION, 1);
    w.writeUint(SCCP_DOMAIN_TAIRA, 4);
    w.writeUint(SCCP_DOMAIN_TON, 4);
    w.writeUint(nonce, 8);
    w.writeUint(revision, 4);
    w.writeUint(deadlineMs, 8);
    w.writeUint(SCCP_DOMAIN_TAIRA, 4);
    w.writeUint(SCCP_CODEC_CANONICAL_TEXT, 1);
    w.writeUint(SCCP_ASSET_ID_XOR_LEN, 2);
    w.writeUint(SCCP_ASSET_ID_XOR, SCCP_ASSET_ID_XOR_LEN);
    w.writeUint(amount, 16);
    w.writeUint(SCCP_CODEC_TAIRA_ACCOUNT, 1);
    w.writeUint(senderLen, 2);
    var i = 1;
    while (i <= senderLen) {
        w.writeUint(i & 0xFF, 1);
        i += 1;
    }
    w.writeUint(SCCP_CODEC_TON_ACCOUNT36, 1);
    w.writeUint(SCCP_TON_ACCOUNT36_LEN, 2);
    w.writeUint(0, 4);
    w.writeUint(recipientHash, 32);
    w.writeUint(SCCP_CODEC_CANONICAL_TEXT, 1);
    w.writeUint(SCCP_ROUTE_ID_TON_LEN, 2);
    w.writeUint(SCCP_ROUTE_ID_TON, SCCP_ROUTE_ID_TON_LEN);
    return sccpSnakeCellFromChunks(w.chunks());
}

/// Snake cell of the concatenation of byte pieces.
fun snakeFromPieces(pieces: array<slice>): cell {
    var w = SnakeWriter.create();
    var i = 0;
    while (i < pieces.size()) {
        w.writeSlice(pieces.get(i));
        i += 1;
    }
    return sccpSnakeCellFromChunks(w.chunks());
}

/// Snake cell of `len` bytes `0x5A`.
fun snakeOfLength(len: int): cell {
    var w = SnakeWriter.create();
    repeat (len) {
        w.writeUint(0x5A, 1);
    }
    return sccpSnakeCellFromChunks(w.chunks());
}

/// `message_id`, leaf and parsed fields of an inbound payload for `minter`.
fun inboundLeaf(networkId: int, payload: cell, minter: address): int {
    val parsed = sccpParseInboundPayload(payload, TEST_REVISION, minter.accountId());
    return sccpTransferLeaf(
        sccpInboundMessageId(networkId, parsed.payloadHash),
        minter.accountId(),
    );
}

fun inboundMessageId(networkId: int, payload: cell, minter: address): int {
    val parsed = sccpParseInboundPayload(payload, TEST_REVISION, minter.accountId());
    return sccpInboundMessageId(networkId, parsed.payloadHash);
}

// ---------------------------------------------------------------------------
// Deployment.

/// A deployed minter with what a test needs to drive it.
struct Env {
    /// The minter at the pinned account id `0:35…35`.
    minter: SccpTairaXorMinter
    deployer: address
    networkId: int
    /// Taira's consensus instance `I` of the deployment.
    instance: int
    /// The pinned generation and its committee.
    generation: int
    committee: TestCommittee
}

/// Canonical initial data (§5.3.1) of a deployment pinned to `pin`, whose
/// committee has the keys `keys` in canonical order. Nothing ties `keys` to
/// `pin.root` here: `sccp_init` checks that.
fun canonicalStorage(
    networkId: int,
    instance: int,
    revision: int,
    maxSupply: int,
    pin: InitialPin,
    keys: array<slice>,
): MinterStorage {
    val config: MinterConfig = {
        tairaNetworkId: networkId,
        consensusInstance: instance,
        routeRevision: revision,
        maxSupply,
        initial: pin.toCell(),
        walletCode: build("SccpTairaXorWallet"),
        bucketCode: build("SccpConsumedBucket"),
    };
    val committee: CommitteeState = {
        root: pin.root,
        untilMs: pin.untilMs,
        start: pin.start,
        high: pin.start - 1,
        generation: pin.generation,
        n: keys.size(),
        keys: sccpBuildKeys(keys),
    };
    return {
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
        checkpoints: beginCell().storeUint(0, 2).endCell(),
        retries: [],
    };
}

/// The default pin of `committee`: generation 7 from height 1000, valid for
/// 14 days from `T0`.
fun defaultPin(committee: TestCommittee): InitialPin {
    return {
        generation: TEST_GENERATION,
        root: committee.root(),
        start: TEST_START_HEIGHT,
        untilMs: T0 * 1000 + TEST_VALIDITY_MS,
    };
}

/// Deploys `storage` with `sccp_init` in the deploy message, at the address
/// its `StateInit` gives.
fun deployWithInit(
    storage: MinterStorage,
    deployer: address,
    value: coins,
): (SccpTairaXorMinter, SendResultList) {
    val minter = SccpTairaXorMinter.fromStorage(storage);
    val res = net.send(
        deployer,
        createMessage({
            bounce: BounceMode.NoBounce,
            value,
            dest: { workchain: BASECHAIN, stateInit: minter.stateInit! },
            body: SccpInit { queryId: 0 },
        }),
    );
    return (minter, res);
}

/// The account id `0:35…35` that the TON rows of the fixtures commit to.
fun pinnedMinterAddress(): address {
    return address.fromWorkchainAndHash(BASECHAIN, VEC_MINTER_ACCOUNT_ID);
}

/// Moves the deployed account `from` to the pinned minter address with its
/// code, data and balance, and removes it at `from` (white box). The minter
/// derives every child address from its own address at run time, so wallets
/// and buckets follow the pinned address.
fun relocateToPinned(from: address) {
    var shard = testing.getShardAccount(from)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        var info = account;
        info.addr = pinnedMinterAddress();
        // `TlbAccountInfo` carries its own `0b1` union prefix
        shard.account = (info.toCell() as cell) as Cell<TlbAccount>;
        testing.setShardAccount(pinnedMinterAddress(), shard);
        testing.setShardAccount(from, null);
        return;
    }
    throw SccpErrors.InvalidMessage;
}

/// Deploys `storage`, completes it with `sccp_init` and places the
/// initialized minter at the pinned account id `0:35…35`.
fun deployPinned(storage: MinterStorage, deployer: address, value: coins): SccpTairaXorMinter {
    val (minter, res) = deployWithInit(storage, deployer, value);
    expect(res).toHaveSuccessfulDeploy({ to: minter.address });
    relocateToPinned(minter.address);
    val pinned = SccpTairaXorMinter.fromAddress(pinnedMinterAddress());
    expect(pinned.getSccpState().initialized).toBeTrue();
    return pinned;
}

/// Places `storage` at the pinned account id exactly as given, without
/// `sccp_init` (white box): for data that `sccp_init` refuses or that models
/// a later state.
fun installPinned(storage: MinterStorage, deployer: address, value: coins): SccpTairaXorMinter {
    val minter = SccpTairaXorMinter.fromStorage(storage);
    val res = minter.deploy(deployer, { value, bounce: false });
    expect(res).toHaveSuccessfulDeploy({ to: minter.address });
    relocateToPinned(minter.address);
    return SccpTairaXorMinter.fromAddress(pinnedMinterAddress());
}

/// Deployed and initialized pinned minter with a committee of the first `n`
/// test keys.
fun setupEnvWith(n: int, maxSupply: int): Env {
    return setupEnvFunded(n, maxSupply, grams("10"));
}

/// [setupEnvWith] deployed with `value` (below `MINTER_FLOOR` when small).
fun setupEnvFunded(n: int, maxSupply: int, value: coins): Env {
    testing.setNow(T0);
    val deployer = testing.treasury("deployer");
    val committee = testCommittee(n, 0);
    val minter = deployPinned(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            maxSupply,
            defaultPin(committee),
            committee.keys,
        ),
        deployer.address,
        value,
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

fun setupEnv(): Env {
    return setupEnvWith(4, TEST_MAX_SUPPLY);
}

/// The stored data of the minter (white box).
fun minterStorage(env: Env): MinterStorage {
    val shard = testing.getShardAccount(env.minter.address)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        val state = account.storage.state;
        if (state is TlbAccountStateActive) {
            return MinterStorage.fromCell(state.stateInit.data!);
        }
    }
    throw SccpErrors.InvalidMessage;
}

/// Overwrites the stored data of the minter (white box).
fun setMinterStorage(env: Env, storage: MinterStorage) {
    var shard = testing.getShardAccount(env.minter.address)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        var info = account;
        val state = info.storage.state;
        if (state is TlbAccountStateActive) {
            var active = state;
            active.stateInit.data = storage.toCell();
            info.storage.state = active;
            shard.account = (info.toCell() as cell) as Cell<TlbAccount>;
            testing.setShardAccount(env.minter.address, shard);
            return;
        }
    }
    throw SccpErrors.InvalidMessage;
}

/// Writes the checkpoint `(height, id)` into the minter's `^Checkpoints` as
/// `sccp_checkpoint` would record it (white box, no signature). It raises
/// neither `high` nor any other field.
fun seedCheckpointId(env: Env, height: int, id: int) {
    var st = minterStorage(env);
    var slots = Checkpoints.load(st.checkpoints);
    expect(slots.insert(height, id)).toBeTrue();
    st.checkpoints = slots.toCell();
    setMinterStorage(env, st);
}

/// Seeds the checkpoint of the header `x` (white box, no signature).
fun seedCheckpoint(env: Env, x: TestX) {
    seedCheckpointId(env, x.height, x.id());
}

/// Cells and bits of the account at `addr` as its storage statistics record
/// them after its last transaction.
fun accountStorageUsed(addr: address): (int, int) {
    val shard = testing.getShardAccount(addr)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        return (account.storageStat.used.cells, account.storageStat.used.bits);
    }
    throw SccpErrors.InvalidMessage;
}

/// Overwrites the balance of the deployed account `addr` in the emulator
/// (storage statistics unchanged), e.g. to model storage drift or a
/// storage-price increase.
fun setAccountBalance(addr: address, balance: coins) {
    var shard = testing.getShardAccount(addr)!;
    val account = shard.account.load();
    if (account is TlbAccountInfo) {
        var info = account;
        info.storage.balance.grams = balance;
        // `TlbAccountInfo` carries its own `0b1` union prefix
        shard.account = (info.toCell() as cell) as Cell<TlbAccount>;
        testing.setShardAccount(addr, shard);
        return;
    }
    throw SccpErrors.InvalidMessage;
}

/// Multiplies the basechain forwarding price per cell by `factor` (and
/// returns the previous config), so that messages with many cells cannot be
/// paid while single-cell messages, such as bounces, still can.
fun raiseCellForwardPrice(factor: int): BlockchainConfigMap {
    val previous = testing.getConfig();
    var config = previous;
    var prices = config.getMsgForwardPrices(BASECHAIN);
    prices.cellPrice = prices.cellPrice * factor;
    config.setMsgForwardPrices(prices, BASECHAIN);
    expect(testing.setConfig(config)).toBeTrue();
    return previous;
}

/// Multiplies the basechain forwarding price per bit by `factor` (and
/// returns the previous config).
fun raiseBitForwardPrice(factor: int): BlockchainConfigMap {
    val previous = testing.getConfig();
    var config = previous;
    var prices = config.getMsgForwardPrices(BASECHAIN);
    prices.bitPrice = prices.bitPrice * factor;
    config.setMsgForwardPrices(prices, BASECHAIN);
    expect(testing.setConfig(config)).toBeTrue();
    return previous;
}

/// The canonical (not activated, flags clear) bucket `index` of `env.minter`.
fun canonicalBucket(env: Env, index: int): SccpConsumedBucket {
    return SccpConsumedBucket.fromStorage({
        minterAddress: env.minter.address,
        index,
        activated: false,
        bitsHi: 0,
        bitsLo: 0,
    });
}

/// Sends `sccp_retry` for `nonce` with `value`.
fun sendRetry(env: Env, nonce: int, value: coins): SendResultList {
    return env.minter.sendSccpRetry(env.deployer, 12, env.deployer, nonce, { value, bounce: true });
}

// ---------------------------------------------------------------------------
// Finalize / void scenarios.

/// A `^BlockRef` (`BlockRefV1`, §5.1.5) from its fields.
fun blockRefCell(
    height: int,
    sccpRoot: int,
    messageCount: int,
    historyIndex: int,
    historyPath: array<int>,
): cell {
    return beginCell()
        .storeUint(height, 64)
        .storeUint(sccpRoot, 256)
        .storeUint(messageCount, 32)
        .storeUint(historyIndex, 64)
        .storeUint(historyPath.size(), 8)
        .storeMaybeRef(sccpBuildHashPath(historyPath))
        .endCell();
}

/// The `^BlockRef` that names the certified block of `x` itself.
fun ownBlockRef(x: TestX): cell {
    return blockRefCell(x.height, x.sccpRoot, x.messageCount, 0, []);
}

/// A `^MessageProof` (`MessageProofV1`, §5.1.5) from its fields.
fun messageProofCell(leafIndex: int, path: array<int>, payload: cell, block: cell): cell {
    return beginCell()
        .storeUint(leafIndex, 32)
        .storeUint(path.size(), 8)
        .storeRef(payload)
        .storeMaybeRef(sccpBuildHashPath(path))
        .storeRef(block)
        .endCell();
}

/// The `CommitQC` over `x` by the lowest `q` members of `committee` under the
/// consensus instance of `env`.
fun certifyFor(env: Env, committee: TestCommittee, x: TestX): cell {
    return certifyBy(committee, committee.lowestSigners(), env.instance, defaultQc(x.height), x);
}

/// A Taira→TON transfer with the block that commits it.
struct Delivery {
    payload: cell
    /// Header of the block that commits the transfer leaf.
    x: TestX
    /// `^TairaCert`: the `CommitQC` over `x`.
    cert: cell
    /// `^MessageProof` whose block reference is the certified block itself.
    proof: cell
    messageId: int
}

/// Height of the block of the default delivery of `nonce`: above the pinned
/// start, and never the height of a default control block (`controlHeight`).
fun deliveryHeight(nonce: int): int {
    return TEST_START_HEIGHT + 100 + 2 * nonce;
}

/// Builds a delivery of a Taira→TON transfer at `leafIndex` of a block of
/// `leafCount` leaves at `height`, certified by generation `generation` of
/// `committee`.
fun deliverAt(
    env: Env,
    committee: TestCommittee,
    generation: int,
    height: int,
    nonce: int,
    amount: int,
    recipient: address,
    deadlineMs: int,
    leafIndex: int,
    leafCount: int,
): Delivery {
    val payload = inboundPayloadCell(
        nonce,
        TEST_REVISION,
        deadlineMs,
        amount,
        recipient.accountId(),
    );
    val leaf = inboundLeaf(env.networkId, payload, env.minter.address);
    val leaves = leavesWith(leaf, leafIndex, leafCount);
    val x = blockX(env.networkId, generation, committee.root(), height, leaves);
    return {
        payload,
        x,
        cert: certifyFor(env, committee, x),
        proof: messageProofCell(leafIndex, treePath(leaves, leafIndex), payload, ownBlockRef(x)),
        messageId: inboundMessageId(env.networkId, payload, env.minter.address),
    };
}

/// [deliverAt] the default height of `nonce`.
fun deliver(
    env: Env,
    committee: TestCommittee,
    generation: int,
    nonce: int,
    amount: int,
    recipient: address,
    deadlineMs: int,
    leafIndex: int,
    leafCount: int,
): Delivery {
    return deliverAt(
        env,
        committee,
        generation,
        deliveryHeight(nonce),
        nonce,
        amount,
        recipient,
        deadlineMs,
        leafIndex,
        leafCount,
    );
}

/// Default delivery by the pinned generation: leaf 1 of 3, deadline one day
/// after `T0`.
fun deliverDefault(env: Env, nonce: int, amount: int, recipient: address): Delivery {
    return deliver(
        env,
        env.committee,
        env.generation,
        nonce,
        amount,
        recipient,
        T0 * 1000 + DAY_MS,
        1,
        3,
    );
}

/// Sends `message` to the minter from `from` as a relayer does: bounceable.
fun sendToMinter<TBody>(env: Env, from: address, body: TBody, value: coins): SendResultList {
    return net.send(
        from,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value,
            dest: env.minter.address,
            body,
        }),
    );
}

/// Sends `sccp_checkpoint` with the `^TairaCert` `cert` and `nextKeys`.
fun sendCheckpoint(
    env: Env,
    from: address,
    cert: cell,
    nextKeys: cell?,
    value: coins,
): SendResultList {
    return sendToMinter(
        env,
        from,
        SccpCheckpoint {
            queryId: 4,
            response: from,
            cert: cert as Cell<TairaCert>,
            nextKeys,
        },
        value,
    );
}

/// Sends a finalize: `sccp_finalize` with the `^TairaCert` `cert` when it is
/// given, otherwise `sccp_finalize_checkpoint` with the `^CheckpointRef` `ref`.
fun sendFinalizeCells(
    env: Env,
    from: address,
    cert: cell?,
    ref: cell?,
    proof: cell,
    value: coins,
): SendResultList {
    val message = proof as Cell<MessageProof>;
    if (cert != null) {
        return sendToMinter(
            env,
            from,
            SccpFinalize {
                queryId: 7,
                response: from,
                cert: cert as Cell<TairaCert>,
                message,
            },
            value,
        );
    }
    return sendToMinter(
        env,
        from,
        SccpFinalizeCheckpoint {
            queryId: 7,
            response: from,
            ref: ref! as Cell<CheckpointRef>,
            message,
        },
        value,
    );
}

/// Sends a void: `sccp_void_expired` with the `^TairaCert` `cert` when it is
/// given, otherwise `sccp_void_expired_checkpoint` with the `^CheckpointRef`
/// `ref`.
fun sendVoidExpiredCells(
    env: Env,
    from: address,
    nonce: int,
    cert: cell?,
    ref: cell?,
    proof: cell,
    value: coins,
): SendResultList {
    val message = proof as Cell<MessageProof>;
    if (cert != null) {
        return sendToMinter(
            env,
            from,
            SccpVoidExpired {
                queryId: 8,
                response: from,
                nonce,
                cert: cert as Cell<TairaCert>,
                message,
            },
            value,
        );
    }
    return sendToMinter(
        env,
        from,
        SccpVoidExpiredCheckpoint {
            queryId: 8,
            response: from,
            nonce,
            ref: ref! as Cell<CheckpointRef>,
            message,
        },
        value,
    );
}

/// Sends `sccp_void_frozen` for `count` nonces from `first` from the deployer.
fun sendVoidFrozen(env: Env, first: int, count: int, value: coins): SendResultList {
    return sendToMinter(
        env,
        env.deployer,
        SccpVoidFrozen {
            queryId: 9,
            response: env.deployer,
            firstNonce: first,
            count,
        },
        value,
    );
}

/// Inline finalize of `d` with its certificate.
fun sendFinalize(env: Env, from: address, d: Delivery, value: coins): SendResultList {
    return sendFinalizeCells(
        env,
        from,
        d.cert,
        null,
        d.proof,
        value,
    );
}

/// Finalize of `d` against the stored checkpoint of its block.
fun sendFinalizeCheckpoint(env: Env, from: address, d: Delivery, value: coins): SendResultList {
    return sendFinalizeCells(
        env,
        from,
        null,
        d.x.ref(),
        d.proof,
        value,
    );
}

fun finalizeValue(env: Env, nonce: int): coins {
    return env.minter.finalizeRequiredValue(nonce);
}

/// Inline void of `d` with its certificate and the nonce argument `nonce`.
fun sendVoidExpired(
    env: Env,
    from: address,
    nonce: int,
    d: Delivery,
    value: coins,
): SendResultList {
    return sendVoidExpiredCells(
        env,
        from,
        nonce,
        d.cert,
        null,
        d.proof,
        value,
    );
}

/// Void of `d` against the stored checkpoint of its block.
fun sendVoidExpiredCheckpoint(
    env: Env,
    from: address,
    nonce: int,
    d: Delivery,
    value: coins,
): SendResultList {
    return sendVoidExpiredCells(
        env,
        from,
        nonce,
        null,
        d.x.ref(),
        d.proof,
        value,
    );
}

/// Wallet of `owner` under `env.minter`.
fun walletOf(env: Env, owner: address): SccpTairaXorWallet {
    return SccpTairaXorWallet.fromAddress(env.minter.getWalletAddress(owner));
}

fun jettonBalanceOf(env: Env, owner: address): int {
    val wallet = walletOf(env, owner);
    if (!testing.isDeployed(wallet.address)) {
        return 0;
    }
    return wallet.getWalletData().jettonBalance;
}

fun bucketOf(env: Env, index: int): SccpConsumedBucket {
    return SccpConsumedBucket.fromAddress(env.minter.getBucketAddress(index));
}

fun isConsumedAt(env: Env, nonce: int): bool {
    val bucket = bucketOf(env, nonce >> SCCP_BUCKET_SHIFT);
    if (!testing.isDeployed(bucket.address)) {
        return false;
    }
    return bucket.isConsumed(nonce);
}

// ---------------------------------------------------------------------------
// Checkpoints and rotations.

/// Sends `sccp_checkpoint` with the `CommitQC` of `committee` over `x`.
fun checkpointBy(env: Env, committee: TestCommittee, x: TestX, nextKeys: cell?): SendResultList {
    return sendCheckpoint(env, env.deployer, certifyFor(env, committee, x), nextKeys, grams("1"));
}

/// Rotates the minter from generation `generation` of `current` to `next`
/// with a handoff at `height` that is dated now and valid for 14 days, and
/// expects the rotation to apply. The successor is generation `generation +
/// 1` and starts at `height + 1`.
fun rotateFrom(
    env: Env,
    current: TestCommittee,
    generation: int,
    next: TestCommittee,
    height: int,
): SendResultList {
    val x = rotationX(
        env.networkId,
        generation,
        current.root(),
        height,
        testing.getNow() * 1000,
        next.root(),
        TEST_VALIDITY_MS,
    );
    val res = checkpointBy(env, current, x, next.keysCell());
    expect(res).toHaveSuccessfulTx<SccpCheckpoint>({ to: env.minter.address });
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(generation + 1);
    expect(state.root).toEqual(next.root());
    return res;
}

/// Rotates the minter from its pinned generation to `next` at `height`.
fun rotateTo(env: Env, next: TestCommittee, height: int): SendResultList {
    return rotateFrom(env, env.committee, env.generation, next, height);
}

// ---------------------------------------------------------------------------
// Controls.

/// §3.4 control leaf for an arbitrary target, destination and network, in
/// the two builders of the 199-byte preimage.
fun controlLeafFor(
    networkId: int,
    targetTag: int,
    targetWord: int,
    destination: int,
    revision: int,
    nonce: int,
    track: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    certificateId: int,
    effectHash: int,
): int {
    return keccak256Builders2(
        beginCell()
            .storeUint(SCCP_TAG_CONTROL_V1, SCCP_TAG_CONTROL_V1_BITS)
            .storeUint(SCCP_TAG_TAIRA, 8)
            .storeUint(networkId, 256)
            .storeUint(targetTag, 8)
            .storeUint(targetWord, 256)
            .storeUint(destination, 256)
            .storeUint(revision, 32)
            .storeUint(nonce, 64),
        beginCell()
            .storeUint(track, 8)
            .storeUint(parliamentPaused ? 1 : 0, 8)
            .storeUint(fastPauseUntilMs, 64)
            .storeUint(certificateId, 256)
            .storeUint(effectHash, 256),
    );
}

/// A `^ControlProof` (`ControlProofV1`, §5.1.6) from its fields.
fun controlProofCell(
    controlNonce: int,
    track: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    certificateId: int,
    effectHash: int,
    leafIndex: int,
    path: array<int>,
    block: cell,
): cell {
    return beginCell()
        .storeUint(controlNonce, 64)
        .storeUint(track, 8)
        .storeBool(parliamentPaused)
        .storeUint(fastPauseUntilMs, 64)
        .storeUint(certificateId, 256)
        .storeUint(effectHash, 256)
        .storeUint(leafIndex, 32)
        .storeUint(path.size(), 8)
        .storeMaybeRef(sccpBuildHashPath(path))
        .storeRef(block)
        .endCell();
}

/// The control fields of a leaf and of its `ControlProof`.
struct TestControl {
    nonce: int
    track: int
    parliamentPaused: bool
    fastPauseUntilMs: int
    certificateId: int
    effectHash: int
}

/// A Parliament-track control `(nonce, paused)` with deterministic nonzero
/// certificate id and effect hash.
fun parliamentControl(nonce: int, paused: bool): TestControl {
    return {
        nonce,
        track: SCCP_TRACK_PARLIAMENT,
        parliamentPaused: paused,
        fastPauseUntilMs: 0,
        certificateId: keccak256Builder(beginCell().storeUint(0xC1, 8).storeUint(nonce, 64)),
        effectHash: keccak256Builder(beginCell().storeUint(0xE1, 8).storeUint(nonce, 64)),
    };
}

/// A fast-pause-track control that leaves the Parliament pause at
/// `parliamentPaused` and sets the fast pause until `fastPauseUntilMs`.
fun fastPauseControl(nonce: int, parliamentPaused: bool, fastPauseUntilMs: int): TestControl {
    var control = parliamentControl(nonce, parliamentPaused);
    control.track = SCCP_TRACK_FAST_PAUSE;
    control.fastPauseUntilMs = fastPauseUntilMs;
    return control;
}

/// The leaf Taira records for `control` on the lane to `env.minter`.
fun controlLeafOf(env: Env, control: TestControl): int {
    return sccpControlLeaf(
        env.networkId,
        env.minter.address.accountId(),
        TEST_REVISION,
        control.nonce,
        control.track,
        control.parliamentPaused,
        control.fastPauseUntilMs,
        control.certificateId,
        control.effectHash,
    );
}

/// A control proof with the block that commits its leaf.
struct ControlDelivery {
    /// Header of the block that commits the control leaf.
    x: TestX
    /// `^TairaCert`: the `CommitQC` over `x`.
    cert: cell
    /// `^ControlProof` whose block reference is the certified block itself.
    proof: cell
}

/// Height of the block of the default control delivery of `nonce`: never the
/// height of a default transfer block (`deliveryHeight`).
fun controlHeight(nonce: int): int {
    return TEST_START_HEIGHT + 101 + 2 * nonce;
}

/// The proof of `control` whose committed leaf is `leaf`, at leaf 0 of a
/// block of `count` leaves certified by the pinned generation. A test passes
/// a leaf other than `controlLeafOf(env, control)` to commit to another lane,
/// destination or field.
fun deliverControlLeaf(env: Env, leaf: int, control: TestControl, count: int): ControlDelivery {
    val leaves = leavesWith(leaf, 0, count);
    val x = blockX(
        env.networkId,
        env.generation,
        env.committee.root(),
        controlHeight(control.nonce),
        leaves,
    );
    return {
        x,
        cert: certifyFor(env, env.committee, x),
        proof: controlProofCell(
            control.nonce,
            control.track,
            control.parliamentPaused,
            control.fastPauseUntilMs,
            control.certificateId,
            control.effectHash,
            0,
            treePath(leaves, 0),
            ownBlockRef(x),
        ),
    };
}

/// A genuine Parliament-track control `(nonce, paused)` for `env.minter`.
fun deliverControl(env: Env, nonce: int, paused: bool): ControlDelivery {
    val control = parliamentControl(nonce, paused);
    return deliverControlLeaf(env, controlLeafOf(env, control), control, 2);
}

/// A genuine fast-pause-track control for `env.minter`.
fun deliverFastPause(
    env: Env,
    nonce: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
): ControlDelivery {
    val control = fastPauseControl(nonce, parliamentPaused, fastPauseUntilMs);
    return deliverControlLeaf(env, controlLeafOf(env, control), control, 2);
}

/// Sends a control: `sccp_apply_control` with the `^TairaCert` `cert` when it
/// is given, otherwise `sccp_apply_control_checkpoint` with the
/// `^CheckpointRef` `ref`.
fun sendApplyControlCells(
    env: Env,
    from: address,
    cert: cell?,
    ref: cell?,
    proof: cell,
    value: coins,
): SendResultList {
    val control = proof as Cell<ControlProof>;
    if (cert != null) {
        return sendToMinter(
            env,
            from,
            SccpApplyControl {
                queryId: 5,
                response: from,
                cert: cert as Cell<TairaCert>,
                control,
            },
            value,
        );
    }
    return sendToMinter(
        env,
        from,
        SccpApplyControlCheckpoint {
            queryId: 5,
            response: from,
            ref: ref! as Cell<CheckpointRef>,
            control,
        },
        value,
    );
}

/// Inline control with the certificate of `c`.
fun sendApplyControl(env: Env, c: ControlDelivery): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        c.cert,
        null,
        c.proof,
        grams("1"),
    );
}

/// Control of `c` against the stored checkpoint of its block.
fun sendApplyControlCheckpoint(env: Env, c: ControlDelivery): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        null,
        c.x.ref(),
        c.proof,
        grams("1"),
    );
}

fun applyControlOk(env: Env, nonce: int, paused: bool): SendResultList {
    val res = sendApplyControl(env, deliverControl(env, nonce, paused));
    expect(res).toHaveSuccessfulTx<SccpApplyControl>({ to: env.minter.address });
    val state = env.minter.getSccpState();
    expect(state.parliamentPaused).toEqual(paused);
    expect(state.controlNonce).toEqual(nonce);
    return res;
}

// ---------------------------------------------------------------------------
// Burns.

/// Sends an SCCP burn of `amount` from `owner`'s wallet to `recipient` bytes.
fun sendBurn(env: Env, owner: address, amount: int, recipient: cell, value: coins): SendResultList {
    val payload: SccpBurnToTaira = { recipient };
    return walletOf(env, owner).sendAskToBurn(
        owner,
        11,
        amount,
        owner,
        payload.toCell(),
        { value, bounce: true },
    );
}

fun burnValue(env: Env, owner: address): coins {
    return walletOf(env, owner).burnRequiredValue() + 1;
}

/// The body a `BounceMode.Only256BitsOfBody` bounce of `body` carries.
fun bouncedBodyOf<T>(body: T): cell {
    val s = body.toCell().beginParse();
    val bits = min(256, s.remainingBitsCount());
    return beginCell().storeUint(0xFFFFFFFF, 32).storeSlice(s.preloadBits(bits)).endCell();
}

/// A bounced message with `body`'s bounce body, delivered to `dest`.
fun bouncedMessage<T>(body: T, dest: address, value: coins): OutMessage {
    return createMessage({
        bounce: BounceMode.NoBounce,
        value,
        dest,
        body: bouncedBodyOf(body),
    }).bounced();
}

/// Re-sends the `index`-th out message of a single processed step.
fun forwardOut(step: SendResult, index: int): OutMessage {
    return { messageCell: step.outMessages.atCell(index) };
}

/// Finalizes nonce `nonce` for `recipient` and checks the mint.
fun finalizeOk(env: Env, nonce: int, amount: int, recipient: address): SendResultList {
    val before = jettonBalanceOf(env, recipient);
    val d = deliverDefault(env, nonce, amount, recipient);
    val res = sendFinalize(env, env.deployer, d, finalizeValue(env, nonce));
    expect(res).toHaveSuccessfulTx<SccpFinalize>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, recipient)).toEqual(before + amount);
    return res;
}

// ---------------------------------------------------------------------------
// Outcomes and events of a call.

/// `outcomeOf` of a step whose compute phase succeeded but whose action
/// phase failed.
const OUTCOME_ACTION_FAILED = -2
/// `outcomeOf` of a step whose compute phase was skipped.
const OUTCOME_COMPUTE_SKIPPED = -3

/// The outcome of the first transaction of a trace, which is the minter's
/// step for a message sent to the minter: 0 when it succeeded, otherwise the
/// exit code of its compute phase, `OUTCOME_ACTION_FAILED` or
/// `OUTCOME_COMPUTE_SKIPPED`.
fun outcomeOf(res: SendResultList): int {
    val description = res.at(0).tx.load().description.load();
    if (description is TlbTransOrd) {
        val compute = description.computePh;
        if (compute is TlbTrComputeVm) {
            val code = compute.data.load().exitCode;
            if ((code != 0) & (code != 1)) {
                return code;
            }
            return description.aborted ? OUTCOME_ACTION_FAILED : 0;
        }
    }
    return OUTCOME_COMPUTE_SKIPPED;
}

/// Expects the minter's step of `res` to end with `exitCode` (0: success).
fun expectOutcome(res: SendResultList, exitCode: int) {
    expect(outcomeOf(res)).toEqual(exitCode);
}

/// Gas used by the first transaction of a trace (the minter's step).
fun stepGas(res: SendResultList): int {
    return res.at(0).gasUsed;
}

/// Reports a measured step and expects it to stay within `limit`, the gas
/// constant the contracts price that step with. The line it prints is the one
/// `scripts/ton_sccp_builder.py test` collects into `gas-current.json` and
/// compares with the recorded baseline (specs/sccp.md §5.4); labels are unique
/// per measured step.
fun reportGas(label: string, used: int, limit: int) {
    println("gas {}: {} (limit {})", label, used, limit);
    expect(used <= limit).toBeTrue();
}

/// Hashes of the bodies of every external-out message of a trace, in order.
fun eventHashes(res: SendResultList): array<int> {
    var hashes: array<int> = [];
    var t = 0;
    repeat (res.size()) {
        val externals = res.at(t).externals;
        var i = 0;
        repeat (externals.size()) {
            val message = externals.get(i) as Cell<
                TlbMessage<RemainingBitsAndRefs, TlbExternalOutMessageInfo>,
            >;
            val body: slice = message.load().loadBody();
            hashes.push(body.hash());
            i += 1;
        }
        t += 1;
    }
    return hashes;
}

/// Expects the external-out messages of a trace to be exactly the bodies
/// `events`, in order (`eventCertificate`, `eventCheckpointed`, …).
fun expectEvents(res: SendResultList, events: array<cell>) {
    val hashes = eventHashes(res);
    expect(hashes.size()).toEqual(events.size());
    var i = 0;
    repeat (events.size()) {
        expect(hashes.get(i)).toEqual(events.get(i).beginParse().hash());
        i += 1;
    }
}

/// Body of `sccp_certificate` for the published `^TairaCert` `cert`.
fun eventCertificate(height: int, generation: int, cert: cell): cell {
    return SccpCertificateEvent {
        height,
        generation,
        cert: cert as Cell<TairaCert>,
    }.toCell();
}

/// Body of `sccp_checkpointed`.
fun eventCheckpointed(height: int, id: int): cell {
    return SccpCheckpointedEvent { height, id }.toCell();
}

/// Body of `sccp_committee_rotated` for the installed successor.
fun eventRotated(generation: int, root: int, untilMs: int, start: int): cell {
    return SccpCommitteeRotatedEvent { generation, root, untilMs, start }.toCell();
}

/// Body of `sccp_latched`.
fun eventLatched(reason: int, generation: int, height: int, a: int, b: int): cell {
    return SccpLatchedEvent { reason, generation, height, a, b }.toCell();
}

/// Body of `sccp_control_applied`.
fun eventControlApplied(
    controlNonce: int,
    track: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    certificateId: int,
): cell {
    return SccpControlAppliedEvent {
        controlNonce,
        track,
        parliamentPaused,
        fastPauseUntilMs,
        certificateId,
    }.toCell();
}

// ---------------------------------------------------------------------------
// Replay of fixture rows (`sccp-cert-vectors.gen.tolk`).
//
// A fixture row deploys a fresh destination from a pin and runs calls at
// given clock values. The deployment context is the fixtures' own:
// `VEC_NETWORK_ID`, `VEC_CONSENSUS_INSTANCE`, revision 1 and the minter at
// `0:35…35`. Every replayed call carries `REPLAY_VALUE`.

/// The environment of a replayed deployment. Its committee has the pinned
/// keys and no secrets: a fixture row brings its own certificates.
fun replayEnvOf(
    minter: SccpTairaXorMinter,
    deployer: address,
    pin: InitialPin,
    keys: array<slice>,
): Env {
    return {
        minter,
        deployer,
        networkId: VEC_NETWORK_ID,
        instance: VEC_CONSENSUS_INSTANCE,
        generation: pin.generation,
        committee: { keys, secrets: [] },
    };
}

/// Deploys the fresh pinned minter of a fixture row at clock `initSeconds`
/// through `sccp_init`, pinned to `pin` with the committee keys `keys`.
fun replayDeploy(pin: InitialPin, keys: array<slice>, maxSupply: int, initSeconds: int): Env {
    testing.setNow(initSeconds);
    val deployer = testing.treasury("deployer").address;
    val minter = deployPinned(
        canonicalStorage(
            VEC_NETWORK_ID,
            VEC_CONSENSUS_INSTANCE,
            TEST_REVISION,
            maxSupply,
            pin,
            keys,
        ),
        deployer,
        grams("1000"),
    );
    return replayEnvOf(minter, deployer, pin, keys);
}

/// [replayDeploy] for a row whose keys `sccp_init` refuses: the same data is
/// installed already initialized (white box). Such a row probes what the
/// verification answers for keys that no deployment can hold.
fun replayDeployUnchecked(
    pin: InitialPin,
    keys: array<slice>,
    maxSupply: int,
    initSeconds: int,
): Env {
    testing.setNow(initSeconds);
    val deployer = testing.treasury("deployer").address;
    var storage = canonicalStorage(
        VEC_NETWORK_ID,
        VEC_CONSENSUS_INSTANCE,
        TEST_REVISION,
        maxSupply,
        pin,
        keys,
    );
    storage.initialized = true;
    return replayEnvOf(installPinned(storage, deployer, grams("1000")), deployer, pin, keys);
}

/// One `sccp_checkpoint` of a fixture step.
fun replayCheckpoint(env: Env, cert: cell, nextKeys: cell?): SendResultList {
    return sendCheckpoint(env, env.deployer, cert, nextKeys, REPLAY_VALUE);
}

/// One finalize of a fixture step: inline with `cert`, or against the
/// checkpoint `ref` when `cert` is null.
fun replayFinalize(env: Env, cert: cell?, ref: cell?, proof: cell): SendResultList {
    return sendFinalizeCells(
        env,
        env.deployer,
        cert,
        ref,
        proof,
        REPLAY_VALUE,
    );
}

/// One void of a fixture step with the nonce argument `nonce`: inline with
/// `cert`, or against the checkpoint `ref` when `cert` is null.
fun replayVoidExpired(env: Env, nonce: int, cert: cell?, ref: cell?, proof: cell): SendResultList {
    return sendVoidExpiredCells(
        env,
        env.deployer,
        nonce,
        cert,
        ref,
        proof,
        REPLAY_VALUE,
    );
}

/// One control of a fixture step: inline with `cert`, or against the
/// checkpoint `ref` when `cert` is null.
fun replayApplyControl(env: Env, cert: cell?, ref: cell?, proof: cell): SendResultList {
    return sendApplyControlCells(
        env,
        env.deployer,
        cert,
        ref,
        proof,
        REPLAY_VALUE,
    );
}

/// One `sccp_void_frozen` of a fixture step.
fun replayVoidFrozen(env: Env, firstNonce: int, count: int): SendResultList {
    return sendVoidFrozen(env, firstNonce, count, REPLAY_VALUE);
}

/// Expects the committee, latch, pause and operation counter of the minter
/// at clock `nowMs` (`state_after` of a fixture step).
fun replayExpectState(
    env: Env,
    nowMs: int,
    generation: int,
    root: int,
    start: int,
    high: int,
    untilMs: int,
    equivocated: bool,
    live: bool,
    controlNonce: int,
    parliamentPaused: bool,
    fastPauseUntilMs: int,
    effectivePaused: bool,
    opCount: int,
) {
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(generation);
    expect(state.root).toEqual(root);
    expect(state.start).toEqual(start);
    expect(state.high).toEqual(high);
    expect(state.untilMs).toEqual(untilMs);
    expect(state.equivocated).toEqual(equivocated);
    expect(sccpIsLive(state.equivocated, state.untilMs, nowMs)).toEqual(live);
    expect(state.controlNonce).toEqual(controlNonce);
    expect(state.parliamentPaused).toEqual(parliamentPaused);
    expect(state.fastPauseUntilMs).toEqual(fastPauseUntilMs);
    expect(state.effectivePaused).toEqual(effectivePaused);
    expect(state.opCount).toEqual(opCount);
    val committee = env.minter.getSccpCommittee();
    expect(committee.generation).toEqual(generation);
    expect(committee.root).toEqual(root);
    expect(committee.start).toEqual(start);
    expect(committee.high).toEqual(high);
    expect(committee.untilMs).toEqual(untilMs);
}

/// Expects the stored committee keys to be exactly `keys`.
fun replayExpectKeys(env: Env, keys: array<slice>) {
    val committee = env.minter.getSccpCommittee();
    expect(committee.n).toEqual(keys.size());
    expect(committee.keys.hash()).toEqual(sccpBuildKeys(keys).hash());
}

/// Expects the three checkpoint slots in ascending height order; an unused
/// slot is `(0, 0)`.
fun replayExpectCheckpoints(
    env: Env,
    count: int,
    height0: int,
    id0: int,
    height1: int,
    id1: int,
    height2: int,
    id2: int,
) {
    val slots = env.minter.getSccpCheckpoints();
    expect(slots.count).toEqual(count);
    expect(slots.height0).toEqual(height0);
    expect(slots.id0).toEqual(id0);
    expect(slots.height1).toEqual(height1);
    expect(slots.id1).toEqual(id1);
    expect(slots.height2).toEqual(height2);
    expect(slots.id2).toEqual(id2);
}

/// Expects the immutable pin that `get_sccp_state` reports.
fun replayExpectPin(env: Env, generation: int, root: int, start: int, untilMs: int) {
    val state = env.minter.getSccpState();
    expect(state.initialGeneration).toEqual(generation);
    expect(state.initialRoot).toEqual(root);
    expect(state.initialStart).toEqual(start);
    expect(state.initialUntilMs).toEqual(untilMs);
}
