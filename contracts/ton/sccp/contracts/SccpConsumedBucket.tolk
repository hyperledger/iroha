// SccpConsumedBucket: 512 replay flags of the SCCP v1 TON minter (§5.3.3,
// §5.3.4). Bucket `index` holds the flags of outbound nonces
// `index·512 .. index·512 + 511`. Only its minter may set or clear flags, and
// only after the minter activated the bucket with `sccp_activate_bucket`. The
// minter activates each index exactly once, so a bucket that someone else
// deploys (before the minter, or again after a deletion for rent) stays
// inactive until that activation, and a deleted bucket can never come back
// with clear flags that accept consumes.

import "@stdlib/gas-payments"
import "sccp-cells"
import "sccp-constants"
import "sccp-errors"
import "sccp-fees"
import "sccp-messages"
import "sccp-storage"
import "sccp-recovery"
import "sccp-recovery-wire"

contract SccpConsumedBucket {
    author: "Hyperledger Iroha"
    version: "1.0.0"
    description: "SCCP v1 consumption bucket: 512 outbound-nonce flags of one Taira XOR minter"
    storage: BucketStorage
    incomingMessages: BucketMessage
}

type BucketMessage = SccpRecoveryDispatch | SccpRecoveryConfirm | SccpRecoveryDrop | TopUpTons

/// `2^width − 1` for `0 ≤ width ≤ 256` (2^256 itself overflows int257).
@pure
fun bucketOnes(width: int): int {
    if (width == 256) {
        return ((1 << 255) - 1) * 2 + 1;
    }
    return (1 << width) - 1;
}

/// Mask of flags `[offset, offset + count)` of a 512-bit bitmap as (hi, lo),
/// for `0 ≤ offset` and `offset + count ≤ 512`.
@pure
fun bucketRangeMask(offset: int, count: int): (int, int) {
    val end = offset + count;
    var lo = 0;
    var hi = 0;
    if (offset < 256) {
        val loEnd = min(end, 256);
        lo = bucketOnes(loEnd - offset) << offset;
    }
    if (end > 256) {
        val hiStart = max(offset, 256) - 256;
        hi = bucketOnes(end - 256 - hiStart) << hiStart;
    }
    return (hi, lo);
}

/// Flag of `nonce` within this bucket as (hi, lo) single-bit masks.
fun BucketStorage.flagMask(self, nonce: int): (int, int) {
    assert ((nonce >> SCCP_BUCKET_SHIFT) == self.index) throw SccpErrors.BadNonce;
    return bucketRangeMask(nonce & SCCP_BUCKET_MASK, 1);
}

/// Requires the minter as sender and an activated bucket.
fun BucketStorage.requireActiveFromMinter(self, sender: address) {
    assert (sender == self.minterAddress) throw SccpErrors.NotMinter;
    assert (self.activated) throw SccpErrors.BucketNotActive;
}

fun onInternalMessage(in: InMessage) {
    val msg = BucketMessage.fromSlice(in.body);
    if (msg is TopUpTons) {
        return;
    }
    var storage = BucketStorage.load();
    assert (in.senderAddress == storage.minterAddress) throw SccpErrors.NotMinter;
    var receipts = storage.recovery.load();
    sccpReserveFloor(sccpBucketFloor(), in.valueCoins);
    match (msg) {
        SccpRecoveryDispatch => {
            assert (msg.operationId > 0) throw SccpErrors.BadRecovery;
            val existing = receipts.existing(msg.operationId, msg.stage, msg.attempt);
            var result = SCCP_RECEIPT_APPLIED;
            if (existing != null) {
                result = existing;
            } else {
                // Admission and funding precede the replay flag mutation.
                assert (contract.getOriginalBalance() >= sccpBucketFloor() +
                    sccpGasFee(SCCP_GAS_BUCKET_CONSUME_RANGE)) throw SccpErrors.NotEnoughValue;
                if (msg.stage == SCCP_RECOVERY_ACTIVATE) {
                    assert (msg.nonce == storage.index) throw SccpErrors.BadRange;
                    storage.activated = true;
                } else {
                    assert (storage.activated) throw SccpErrors.BucketNotActive;
                    if ((msg.stage == SCCP_RECOVERY_CONSUME) |
                        (msg.stage == SCCP_RECOVERY_UNCONSUME)) {
                        val (hi, lo) = storage.flagMask(msg.nonce);
                        if (msg.stage == SCCP_RECOVERY_UNCONSUME) {
                            storage.bitsHi &= ~hi;
                            storage.bitsLo &= ~lo;
                        } else if (((storage.bitsHi & hi) | (storage.bitsLo & lo)) == 0) {
                            storage.bitsHi |= hi;
                            storage.bitsLo |= lo;
                        } else {
                            result = SCCP_RECEIPT_REJECTED;
                        }
                    } else {
                        assert (msg.stage == SCCP_RECOVERY_RANGE) throw SccpErrors.BadRecovery;
                        assert ((msg.count >= 1) & (msg.count <= SCCP_BUCKET_BITS))
                            throw SccpErrors.BadRange;
                        assert ((msg.nonce >> SCCP_BUCKET_SHIFT) == storage.index)
                            throw SccpErrors.BadRange;
                        assert (((msg.nonce + msg.count - 1) >> SCCP_BUCKET_SHIFT) == storage.index)
                            throw SccpErrors.BadRange;
                        val (hi, lo) = bucketRangeMask(msg.nonce & SCCP_BUCKET_MASK, msg.count);
                        if (((storage.bitsHi & hi) | (storage.bitsLo & lo)) == 0) {
                            storage.bitsHi |= hi;
                            storage.bitsLo |= lo;
                        } else {
                            result = SCCP_RECEIPT_REJECTED;
                        }
                    }
                }
                receipts.record(msg.operationId, msg.stage, msg.attempt, result);
                storage.recovery = receipts.toCell();
                storage.save();
            }
            sccpSendRecoveryAck(storage.minterAddress, msg.operationId, msg.stage, msg.attempt, result);
        }
        SccpRecoveryConfirm => {
            val result = receipts.confirm(msg.operationId, msg.stage, msg.attempt);
            sccpSendRecoveryAck(storage.minterAddress, msg.operationId, msg.stage, msg.attempt, result);
        }
        SccpRecoveryDrop => {
            receipts.drop(msg.operationId, msg.stage, msg.attempt);
            storage.recovery = receipts.toCell();
            storage.save();
            sccpSendRecoveryAck(storage.minterAddress, msg.operationId, msg.stage, msg.attempt,
                SCCP_RECEIPT_DROPPED);
        }
    }
}

/// ACK failure never reverts a completed effect or deletes its receipt. The
/// minter's still-reserved operation can recover it with Confirm or Drop.
fun onBouncedMessage(in: InMessageBounced) {}

/// `(minter, index, activated, bits_hi, bits_lo)`; flag `i` is bit `i` of
/// `hi ‖ lo`.
get fun get_bucket_data(): BucketDataReply {
    val storage = lazy BucketStorage.load();
    return {
        minterAddress: storage.minterAddress,
        index: storage.index,
        activated: storage.activated,
        bitsHi: storage.bitsHi,
        bitsLo: storage.bitsLo,
    };
}

/// The 512 flags as `(bits_hi, bits_lo)` (§5.3.6).
get fun get_bits(): (int, int) {
    val storage = lazy BucketStorage.load();
    return (storage.bitsHi, storage.bitsLo);
}

/// Whether `nonce` (which must belong to this bucket) is consumed.
get fun is_consumed(nonce: int): bool {
    val storage = lazy BucketStorage.load();
    val (hi, lo) = storage.flagMask(nonce);
    return ((storage.bitsHi & hi) | (storage.bitsLo & lo)) != 0;
}

/// Whether the minter activated this bucket.
get fun is_activated(): bool {
    val storage = lazy BucketStorage.load();
    return storage.activated;
}
