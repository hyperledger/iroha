// Persistent layouts of the SCCP v1 TON contracts (§5.3.1, §5.3.3) and the
// rules of the minter's two counters (§5.1.1, §5.1.7).
//
// Field order is serialization order and matches the TL-B of the spec
// exactly; `scripts/generate_ton_sccp_stateinit_golden.py` rebuilds the
// canonical initial minter data independently and pins it in
// `fixtures/sccp/ton_stateinit_v1.json`.

import "@stdlib/strings"
import "sccp-constants"
import "sccp-errors"
import "sccp-recovery"

/// `initial_pin#_` — the Parliament-pinned generation of this deployment.
struct InitialPin {
    generation: uint64
    root: uint256
    start: uint64
    untilMs: uint64
}

/// `minter_config#_` — immutable deployment configuration.
struct MinterConfig {
    tairaNetworkId: uint256
    /// Taira's Sumeragi instance id `I` (§0), bound into every Commit preimage.
    consensusInstance: uint256
    routeRevision: uint32
    maxSupply: coins
    initial: Cell<InitialPin>
    walletCode: cell
    bucketCode: cell
}

/// `committee_state#_` — the current generation only (§5.1.1); there is no
/// record of past generations, so the state size is constant.
struct CommitteeState {
    root: uint256
    untilMs: uint64
    start: uint64
    high: uint64
    generation: uint64
    n: uint8
    /// `^KeyChunk`: `n` compressed G1 keys in canonical order, two per chunk.
    keys: cell
}

/// `minter_data#_` (MinterData of §5.3.1).
struct MinterStorage {
    initialized: bool
    equivocated: bool
    totalSupply: coins
    pendingSupply: coins
    outboundNonce: uint64
    opCount: uint64
    controlNonce: uint64
    parliamentPaused: bool
    fastPauseUntilMs: uint64
    deployedBuckets: uint64
    config: Cell<MinterConfig>
    committee: Cell<CommitteeState>
    /// `^Checkpoints`: `count:uint2` then `count × (height:uint64 id:bits256)`
    /// in ascending height order (§5.1.3); read and written through
    /// `Checkpoints` of `sccp-finality.tolk`.
    checkpoints: cell
    /// All dispatched and queued operations, bounded before allocation.
    recovery: Cell<RecoveryBook>
}

fun MinterStorage.load(): MinterStorage {
    return MinterStorage.fromCell(contract.getData());
}

fun MinterStorage.save(self) {
    contract.setData(self.toCell());
}

/// `op_count` after one more counted operation (a finalization, void, burn
/// or applied control, §5.1.1): `min(opCount + 1, 2^64 − 1)`. The counter
/// never wraps, and the operation that reaches the bound, like every one
/// after it, still succeeds.
@pure
fun sccpBumpedOpCount(opCount: int): int {
    return min(opCount + 1, SCCP_MAX_U64);
}

/// The `outbound_nonce` to store after a burn that uses the source nonce
/// `stored` (§5.1.7). Source nonces are `0 ..= 2^64 − 2`: a stored value of
/// `2^64 − 1` is exhausted and throws `BadNonce`. The minter calls this
/// before any state change, so the bounce restores the wallet balance and no
/// nonce is used twice.
fun sccpNextOutboundNonce(stored: int): int {
    assert (stored < SCCP_MAX_U64) throw SccpErrors.BadNonce;
    return stored + 1;
}

/// TEP-74 wallet storage.
struct WalletStorage {
    jettonBalance: coins
    ownerAddress: address
    minterAddress: address
    recovery: Cell<RecoveryReceipts>
}

fun WalletStorage.load(): WalletStorage {
    return WalletStorage.fromCell(contract.getData());
}

fun WalletStorage.save(self) {
    contract.setData(self.toCell());
}

/// `bucket_data#_ minter:MsgAddressInt index:uint64 activated:Bool
/// bits:uint512`; the 512 flags are stored as their high and low 256-bit
/// halves, so flag `i` is bit `i` of the 512-bit big-endian integer
/// `bitsHi ‖ bitsLo`. The canonical `StateInit` has `activated = false` and
/// clear flags; only the minter's `sccp_activate_bucket` sets `activated`.
struct BucketStorage {
    minterAddress: address
    index: uint64
    activated: bool
    bitsHi: uint256
    bitsLo: uint256
    recovery: Cell<RecoveryReceipts>
}

fun BucketStorage.load(): BucketStorage {
    return BucketStorage.fromCell(contract.getData());
}

fun BucketStorage.save(self) {
    contract.setData(self.toCell());
}

/// TEP-74 `get_wallet_data` reply.
struct JettonWalletDataReply {
    jettonBalance: coins
    ownerAddress: address
    minterAddress: address
    jettonWalletCode: cell
}

/// TEP-64 on-chain content: `onchain#00 data:(HashmapE 256 ^ContentData)`.
struct (0x00) OnchainMetadataReply {
    contentDict: map<uint256, string_prefixed0x>
}

/// TEP-74 `get_jetton_data` reply.
struct JettonDataReply {
    totalSupply: int
    mintable: bool
    adminAddress: address?
    jettonContent: Cell<OnchainMetadataReply>
    jettonWalletCode: cell
}

/// `get_sccp_state` reply (§5.3.6), in the order of the spec.
struct SccpStateReply {
    initialized: bool
    equivocated: bool
    tairaNetworkId: uint256
    consensusInstance: uint256
    routeRevision: uint32
    initialGeneration: uint64
    initialRoot: uint256
    initialStart: uint64
    initialUntilMs: uint64
    root: uint256
    untilMs: uint64
    start: uint64
    high: uint64
    generation: uint64
    outboundNonce: uint64
    opCount: uint64
    parliamentPaused: bool
    fastPauseUntilMs: uint64
    effectivePaused: bool
    controlNonce: uint64
    totalSupply: coins
    pendingSupply: coins
    maxSupply: coins
    deployedBuckets: uint64
}

/// `get_sccp_committee` reply: the current generation and its keys.
struct SccpCommitteeReply {
    root: uint256
    untilMs: uint64
    start: uint64
    high: uint64
    generation: uint64
    n: uint8
    /// `^KeyChunk` in canonical order.
    keys: cell
}

/// `get_sccp_checkpoints` reply: `count` stored `(height, id)` slots in
/// ascending height order; unused slots are zero.
struct SccpCheckpointsReply {
    count: uint8
    height0: uint64
    id0: uint256
    height1: uint64
    id1: uint256
    height2: uint64
    id2: uint256
}

/// `get_bucket_data` reply of a consumption bucket.
struct BucketDataReply {
    minterAddress: address
    index: uint64
    activated: bool
    bitsHi: uint256
    bitsLo: uint256
}
