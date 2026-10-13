// Value, fees and storage rent of the SCCP v1 TON contracts (§5.3.5).
//
// Required values are computed at entry from the current price config with
// `GETGASFEE`, `GETFORWARDFEE` and `GETSTORAGEFEE`; there is no fixed TON
// amount anywhere, so price-config changes cannot break a flow. The gas
// limits are the per-step maxima (n = 31, q = 21, the largest paths and
// payloads) with headroom, and the size constants cover the largest message
// and state of each kind. `tests/unit/sccp-fees.test.tolk` pins every
// constant against measured gas and actual cell sizes.
//
// Minter floor accounting. Every entry step (checkpoint, finalize, void,
// void_frozen, deploy_buckets, apply_control, retry) requires
// `value ≥ step + max(0, MINTER_FLOOR − stored)`, where `stored` is the
// balance the minter had when the transaction started, before its storage
// phase. A get method sees exactly that balance, so a quote does not go
// stale while time passes. The quote adds `sccpMinterStorageGrace()` for
// storage that other minter transactions collect between the quote and the
// send. The entry reserve tops the minter up to `MINTER_FLOOR` but never
// takes more than `value − step`, so the step always keeps the value it was
// checked for. Burns and the bucket replies reserve only the prior balance:
// they never pay toward the floor.

import "@stdlib/gas-payments"
import "sccp-constants"
import "sccp-errors"
import "sccp-recovery"

/// 100 years (§5.3.5 minter and bucket floors).
const SCCP_FLOOR_SECONDS = 3153600000
/// 5 years: TEP-74 reference wallet minimum storage.
const SCCP_WALLET_MIN_STORAGE_SECONDS = 157680000
/// 7 days: storage grace added to every minter quote (§5.3.5). It covers the
/// storage that other minter transactions collect between a quote and the
/// send, which accrued over the minter's idle time before the quote.
const SCCP_STORAGE_GRACE_SECONDS = 604800

// Per-step gas limits: the measured maxima (Acton 1.2.0 emulator) plus
// headroom. `tests/unit/sccp-fees.test.tolk` runs every step at its largest
// inputs and fails when one exceeds its limit; the measured values are
// recorded in `gas-baseline.json` (specs/sccp.md §5.4).
//
// The four steps that verify a certificate are measured at n = 31 with the
// 21 highest signers, full checkpoint slots, the last leaf of a 512-leaf
// block under a history of 2^32 blocks, a 1024-byte sender and four bucket
// activations: `sccp_checkpoint` (a key-changing rotation to another
// committee of 31) 208 942, `sccp_finalize` 251 280, `sccp_void_expired`
// 250 412 and `sccp_apply_control` 224 746. One plain certificate through
// `sccp_checkpoint` costs 97 564 gas at n = 4, 104 668 at n = 7 and 161 644
// at n = 31, of which `BLS_FASTAGGREGATEVERIFY` is 58 000 + 3 000·q; a
// heartbeat adds 3 665 and a key change 10 598, 14 988 and 44 828.
const SCCP_GAS_MINTER_CHECKPOINT = 250000
const SCCP_GAS_MINTER_FINALIZE = 300000
const SCCP_GAS_MINTER_VOID = 285000
const SCCP_GAS_MINTER_APPLY_CONTROL = 260000
const SCCP_GAS_MINTER_VOID_FROZEN = 30000
const SCCP_GAS_MINTER_DEPLOY_BUCKETS = 60000
const SCCP_GAS_MINTER_RETRY = 14000
const SCCP_GAS_MINTER_CONSUMED = 14000
const SCCP_GAS_MINTER_CONSUME_REVERTED = 6000
const SCCP_GAS_MINTER_RANGE_REPLY = 8000
const SCCP_GAS_MINTER_BURN = 48000
/// The minter's handling of a bounced `internal_transfer` (unconsume or record).
const SCCP_GAS_MINTER_BOUNCE = 20000
const SCCP_GAS_BUCKET_CONSUME = 8000
const SCCP_GAS_BUCKET_CONSUME_RANGE = 9000
const SCCP_GAS_BUCKET_ACTIVATE = 3000
const SCCP_GAS_BUCKET_UNCONSUME = 5000
const SCCP_GAS_WALLET_RECEIVE = 8000
const SCCP_GAS_WALLET_TRANSFER = 8000
/// Full 1024-byte recipient validation measures 12573 gas at the wallet.
const SCCP_GAS_WALLET_BURN = 15000

// Account state sizes including code, data and the account's own cell.
// The sampled minter state contains the compiled code, the 16 `KeyChunk`s of n = 31,
// three checkpoints, the largest supplies and counters, the wallet and bucket
// code, and eight `retries` records, which only bounced steps create: 222
// cells and 113 633 bits.
// TODO: establish a bound or funded storage policy for arbitrary retained
// retry history; this eight-retry sample does not prove such a bound.
// `TON_MINTER_STATE_BITS` and `TON_MINTER_STATE_CELLS` in the Rust mirror
// `crates/iroha_sccp/src/v1/ton_cell.rs` use these same measured bounds.
// TODO: tighten these conservative analytical bounds against the completed
// 512-row native maximum-state fixtures before release qualification.
const SCCP_BUCKET_STATE_BITS = 130000
const SCCP_BUCKET_STATE_CELLS = 1100
const SCCP_WALLET_STATE_BITS = 130000
const SCCP_WALLET_STATE_CELLS = 1100
const SCCP_MINTER_STATE_BITS = 950000
const SCCP_MINTER_STATE_CELLS = 2600

// StateInit sizes attached to deployments (code + data + root), upper bounds.
const SCCP_BUCKET_STATE_INIT_BITS = 30000
const SCCP_BUCKET_STATE_INIT_CELLS = 70
const SCCP_WALLET_STATE_INIT_BITS = 30000
const SCCP_WALLET_STATE_INIT_CELLS = 70

// Message sizes (header and body cells), upper bounds.
const SCCP_MSG_CONSUME_BITS = 1800
const SCCP_MSG_CONSUME_CELLS = 3
const SCCP_MSG_SMALL_BITS = 1000
const SCCP_MSG_SMALL_CELLS = 2
const SCCP_MSG_INTERNAL_TRANSFER_BITS = 1600
const SCCP_MSG_INTERNAL_TRANSFER_CELLS = 2
const SCCP_MSG_EXT_EVENT_BITS = 1200
const SCCP_MSG_EXT_EVENT_CELLS = 2
/// `sccp_certificate`: the external-out header, the 160-bit body and the four
/// certificate cells it references (800 + 896 + 872 + 896 bits).
const SCCP_MSG_EXT_CERTIFICATE_BITS = 4200
const SCCP_MSG_EXT_CERTIFICATE_CELLS = 6
/// `sccp_transfer_to_taira` with a 1138-byte payload in 10 snake cells.
const SCCP_MSG_EXT_TRANSFER_BITS = 11000
const SCCP_MSG_EXT_TRANSFER_CELLS = 13
/// `burn_notification` with a 1024-byte recipient in 9 snake cells.
const SCCP_MSG_BURN_NOTIFICATION_BITS = 10000
const SCCP_MSG_BURN_NOTIFICATION_CELLS = 13

@inline
fun sccpGasFee(gas: int): coins {
    return calculateGasFee(SCCP_WORKCHAIN, gas);
}

@inline
fun sccpForwardFee(bits: int, cells: int): coins {
    return calculateForwardFee(SCCP_WORKCHAIN, bits, cells);
}

/// `BUCKET_FLOOR`: 100 years of a bucket's storage at current prices.
fun sccpBucketFloor(): coins {
    return calculateStorageFee(
        SCCP_WORKCHAIN,
        SCCP_FLOOR_SECONDS,
        SCCP_BUCKET_STATE_BITS,
        SCCP_BUCKET_STATE_CELLS,
    );
}

/// `MINTER_FLOOR`: 100 years of the minter's maximal storage at current prices.
fun sccpMinterFloor(): coins {
    return calculateStorageFee(
        SCCP_WORKCHAIN,
        SCCP_FLOOR_SECONDS,
        SCCP_MINTER_STATE_BITS,
        SCCP_MINTER_STATE_CELLS,
    );
}

/// Storage a freshly deployed wallet keeps (TEP-74 reference: 5 years).
fun sccpWalletMinStorage(): coins {
    return calculateStorageFee(
        SCCP_WORKCHAIN,
        SCCP_WALLET_MIN_STORAGE_SECONDS,
        SCCP_WALLET_STATE_INIT_BITS,
        SCCP_WALLET_STATE_INIT_CELLS,
    );
}

/// A wallet holding bridge receipts prepays the same 100-year custody horizon
/// as the minter and buckets, before it credits any minted tokens.
fun sccpWalletRecoveryFloor(): coins {
    return calculateStorageFee(SCCP_WORKCHAIN, SCCP_FLOOR_SECONDS,
        SCCP_WALLET_STATE_BITS, SCCP_WALLET_STATE_CELLS);
}

/// Dispatch, Prepared, Drop and Dropped: each side has a bounded dictionary
/// operation. This also funds the most expensive recovery confirmation step.
fun sccpRecoveryRoundTrip(): coins {
    return 4 * (sccpGasFee(60000) +
        sccpForwardFee(SCCP_MSG_CONSUME_BITS, SCCP_MSG_CONSUME_CELLS));
}

/// Value attached to `sccp_activate_bucket`: the bucket's gas and its floor.
fun sccpBucketActivationValue(): coins {
    return sccpGasFee(SCCP_GAS_BUCKET_ACTIVATE) + sccpBucketFloor();
}

/// Cost of one bucket activation sent by the minter (value plus forwarding
/// with the bucket StateInit, paid separately).
fun sccpBucketActivationCost(): coins {
    return sccpBucketActivationValue() + sccpRecoveryRoundTrip() +
        sccpForwardFee(
            SCCP_MSG_SMALL_BITS + SCCP_BUCKET_STATE_INIT_BITS,
            SCCP_MSG_SMALL_CELLS + SCCP_BUCKET_STATE_INIT_CELLS,
        );
}

/// Bucket round trip of one consume (`sccp_consume` never carries a
/// StateInit): forwarding there and back, bucket gas and the bucket floor
/// top-up.
fun sccpConsumeRoundTrip(): coins {
    return sccpRecoveryRoundTrip() +
        sccpForwardFee(SCCP_MSG_CONSUME_BITS, SCCP_MSG_CONSUME_CELLS) +
        sccpGasFee(SCCP_GAS_BUCKET_CONSUME) +
        sccpBucketFloor() +
        sccpForwardFee(SCCP_MSG_CONSUME_BITS, SCCP_MSG_CONSUME_CELLS);
}

/// Excess return to `response`.
fun sccpExcessForwardFee(): coins {
    return sccpForwardFee(SCCP_MSG_SMALL_BITS, SCCP_MSG_SMALL_CELLS);
}

/// External-out event of the minter.
fun sccpEventForwardFee(): coins {
    return sccpForwardFee(SCCP_MSG_EXT_EVENT_BITS, SCCP_MSG_EXT_EVENT_CELLS);
}

/// The `sccp_certificate` external-out message of a full-path verification
/// (§5.1.3 step 12).
fun sccpCertificateForwardFee(): coins {
    return sccpForwardFee(SCCP_MSG_EXT_CERTIFICATE_BITS, SCCP_MSG_EXT_CERTIFICATE_CELLS);
}

/// Events an inline certificate can add to its step: `sccp_certificate` and
/// `sccp_checkpointed`. The `*_checkpoint` forms send neither and get the
/// difference back with the excess.
fun sccpInlineCertificateFees(): coins {
    return sccpCertificateForwardFee() + sccpEventForwardFee();
}

/// Step value of `sccp_checkpoint`: the minter step with a key-changing
/// rotation, `sccp_certificate`, two events (`sccp_checkpointed` and
/// `sccp_committee_rotated`, or `sccp_latched` alone) and the excess return.
fun sccpCheckpointRequiredValue(): coins {
    return sccpGasFee(SCCP_GAS_MINTER_CHECKPOINT) + sccpCertificateForwardFee() +
        2 * sccpEventForwardFee() +
        sccpExcessForwardFee();
}

/// Step value of a finalize that activates `deployCount` buckets (0 when the
/// nonce's bucket is active).
fun sccpFinalizeRequiredValue(deployCount: int): coins {
    return sccpGasFee(SCCP_GAS_MINTER_FINALIZE) + sccpInlineCertificateFees() +
        sccpConsumeRoundTrip() +
        sccpGasFee(SCCP_GAS_MINTER_CONSUMED) +
        sccpEventForwardFee() +
        sccpForwardFee(
            SCCP_MSG_INTERNAL_TRANSFER_BITS + SCCP_WALLET_STATE_INIT_BITS,
            SCCP_MSG_INTERNAL_TRANSFER_CELLS + SCCP_WALLET_STATE_INIT_CELLS,
        ) +
        sccpGasFee(SCCP_GAS_WALLET_RECEIVE) +
        sccpWalletRecoveryFloor() + sccpRecoveryRoundTrip() +
        sccpExcessForwardFee() +
        deployCount * sccpBucketActivationCost();
}

/// Step value of a void that activates `deployCount` buckets.
fun sccpVoidRequiredValue(deployCount: int): coins {
    return sccpGasFee(SCCP_GAS_MINTER_VOID) + sccpInlineCertificateFees() + sccpConsumeRoundTrip() +
        sccpGasFee(SCCP_GAS_MINTER_CONSUMED) +
        sccpEventForwardFee() +
        sccpExcessForwardFee() +
        deployCount * sccpBucketActivationCost();
}

/// Value the minter attaches to `sccp_consume_range`: bucket gas and floor,
/// the reply and the minter's handling of it.
fun sccpRangeConsumeValue(): coins {
    return sccpRecoveryRoundTrip() + sccpGasFee(SCCP_GAS_BUCKET_CONSUME_RANGE) + sccpBucketFloor() +
        sccpForwardFee(SCCP_MSG_SMALL_BITS, SCCP_MSG_SMALL_CELLS) +
        sccpGasFee(SCCP_GAS_MINTER_RANGE_REPLY) +
        sccpEventForwardFee();
}

/// Step value of `sccp_void_frozen` activating `deployCount` buckets.
fun sccpVoidFrozenRequiredValue(deployCount: int): coins {
    return sccpGasFee(SCCP_GAS_MINTER_VOID_FROZEN) +
        sccpForwardFee(SCCP_MSG_SMALL_BITS, SCCP_MSG_SMALL_CELLS) +
        sccpRangeConsumeValue() +
        sccpExcessForwardFee() +
        deployCount * sccpBucketActivationCost();
}

/// Step value of `sccp_deploy_buckets` for `count` buckets.
fun sccpDeployBucketsRequiredValue(count: int): coins {
    return sccpGasFee(SCCP_GAS_MINTER_DEPLOY_BUCKETS) + count * sccpBucketActivationCost() +
        sccpExcessForwardFee();
}

/// Step value of `sccp_apply_control*`: the minter step, the events of an
/// inline certificate, the `sccp_control_applied` event and the excess return.
fun sccpApplyControlRequiredValue(): coins {
    return sccpGasFee(SCCP_GAS_MINTER_APPLY_CONTROL) + sccpInlineCertificateFees() +
        sccpEventForwardFee() +
        sccpExcessForwardFee();
}

/// Value the minter attaches to `sccp_unconsume` (forwarding paid separately).
fun sccpUnconsumeValue(): coins {
    return sccpGasFee(SCCP_GAS_BUCKET_UNCONSUME);
}

/// Cost of one `sccp_unconsume` sent by the minter (value plus forwarding).
fun sccpUnconsumeCost(): coins {
    return sccpUnconsumeValue() + sccpForwardFee(SCCP_MSG_SMALL_BITS, SCCP_MSG_SMALL_CELLS);
}

/// Step value of `sccp_retry`: the minter step, the costlier of the two
/// retried messages and the excess return.
fun sccpRetryRequiredValue(): coins {
    // Any recovery stage can finish its receipt handshake and then dispatch
    // the next stage. A complete maximum activation batch is a safe bound.
    return sccpFinalizeRequiredValue(SCCP_MAX_DEPLOY_BUCKETS_PER_CALL);
}

/// Value a bucket attaches to `sccp_consume_reverted` from its own balance.
fun sccpConsumeRevertedValue(): coins {
    return sccpGasFee(SCCP_GAS_MINTER_CONSUME_REVERTED);
}

/// Minimal value of an SCCP burn sent to a wallet: the wallet step, the
/// `burn_notification` with a maximal recipient, the minter step, the
/// `sccp_transfer_to_taira` external message and the excess return. The burn
/// never pays toward the minter floor.
fun sccpBurnRequiredValue(): coins {
    return sccpGasFee(SCCP_GAS_WALLET_BURN) +
        sccpForwardFee(SCCP_MSG_BURN_NOTIFICATION_BITS, SCCP_MSG_BURN_NOTIFICATION_CELLS) +
        sccpGasFee(SCCP_GAS_MINTER_BURN) +
        sccpForwardFee(SCCP_MSG_EXT_TRANSFER_BITS, SCCP_MSG_EXT_TRANSFER_CELLS) +
        sccpExcessForwardFee();
}

/// Minimal value of a wallet-to-wallet transfer (TEP-74 reference formula).
fun sccpTransferRequiredValue(forwardTonAmount: int, fwdFee: int): coins {
    val forwardCount = forwardTonAmount != 0 ? 2 : 1;
    return forwardTonAmount + forwardCount * fwdFee +
        calculateForwardFeeWithoutLumpPrice(
            SCCP_WORKCHAIN,
            SCCP_WALLET_STATE_INIT_BITS,
            SCCP_WALLET_STATE_INIT_CELLS,
        ) +
        sccpGasFee(SCCP_GAS_WALLET_TRANSFER) +
        sccpGasFee(SCCP_GAS_WALLET_RECEIVE) +
        sccpWalletMinStorage();
}

/// Reserves `max(floor, balance before this message)` (mode 2): the account
/// never drops below its floor or its prior balance, and every later
/// "carry all balance" send forwards only the incoming value. Buckets only.
fun sccpReserveFloor(floor: coins, incomingValue: coins) {
    val before = contract.getOriginalBalance() - incomingValue;
    reserveGramsOnBalance(max(floor, before), RESERVE_MODE_AT_MOST);
}

/// Reserves the balance before this message (mode 2): the incoming value pays
/// the whole step and nothing goes toward a floor (burns and bucket replies).
fun sccpReservePriorBalance(incomingValue: coins) {
    reserveGramsOnBalance(contract.getOriginalBalance() - incomingValue, RESERVE_MODE_AT_MOST);
}

/// Storage the minter would pay for `SCCP_STORAGE_GRACE_SECONDS` at its
/// maximal size: the slack every quote adds (§5.3.5).
fun sccpMinterStorageGrace(): coins {
    return calculateStorageFee(
        SCCP_WORKCHAIN,
        SCCP_STORAGE_GRACE_SECONDS,
        SCCP_MINTER_STATE_BITS,
        SCCP_MINTER_STATE_CELLS,
    );
}

/// Part of `MINTER_FLOOR` that a caller pays when the minter's balance is
/// `stored`.
fun sccpMinterFloorDeficit(stored: coins): coins {
    val floor = sccpMinterFloor();
    return stored >= floor ? 0 : floor - stored;
}

/// The minter's balance when this transaction started, before its storage
/// phase: the balance a get method sees, so entry checks and quotes agree.
fun sccpMinterStoredBalance(incomingValue: coins): coins {
    return contract.getOriginalBalance() - incomingValue + contract.getStoragePaidPayment();
}

/// Entry value check of a minter step worth `step` (§5.3.5); it runs before
/// any signature is verified, so an underfunded call fails cheaply.
fun sccpCheckEntryValue(incomingValue: coins, step: coins) {
    assert (
        incomingValue >= step + sccpMinterFloorDeficit(sccpMinterStoredBalance(incomingValue))
    ) throw SccpErrors.NotEnoughValue;
}

/// Entry reserve of the minter: `max(MINTER_FLOOR, before)`, but never more
/// than `before + value − step`, so the step keeps the value it was checked
/// for; storage drift beyond what the caller attached stays a deficit for the
/// next caller.
fun sccpReserveMinterFloor(incomingValue: coins, step: coins) {
    val before = contract.getOriginalBalance() - incomingValue;
    reserveGramsOnBalance(
        min(max(sccpMinterFloor(), before), before + incomingValue - step),
        RESERVE_MODE_AT_MOST,
    );
}

/// Quote of a minter step worth `step` for get methods: the step, the floor
/// deficit at the stored balance and the storage grace.
fun sccpMinterQuote(step: coins): coins {
    return step + sccpMinterFloorDeficit(contract.getOriginalBalance()) + sccpMinterStorageGrace();
}
