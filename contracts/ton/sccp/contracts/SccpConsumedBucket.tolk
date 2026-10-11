// SccpConsumedBucket: 512 replay flags of the SCCP v1 TON minter (§5.3.3,
// §5.3.4). Bucket `index` holds the flags of outbound nonces
// `index·512 .. index·512 + 511`. Only its minter may set or clear flags, and
// only after the minter activated the bucket with `sccp_activate_bucket`. The
// minter activates each index exactly once, so a bucket that someone else
// deploys (before the minter, or again after a deletion for rent) stays
// inactive until that activation, and a deleted bucket can never come back
// with clear flags that accept consumes.

import "@stdlib/gas-payments"
import "sccp-constants"
import "sccp-errors"
import "sccp-fees"
import "sccp-messages"
import "sccp-storage"

contract SccpConsumedBucket {
    author: "Hyperledger Iroha"
    version: "1.0.0"
    description: "SCCP v1 consumption bucket: 512 outbound-nonce flags of one Taira XOR minter"
    storage: BucketStorage
    incomingMessages: BucketMessage
}

type BucketMessage =
    | SccpActivateBucket
    | SccpConsume
    | SccpConsumeRange
    | SccpUnconsume
    | TopUpTons

/// Replies of the bucket that the minter may bounce back.
type BucketBounce = SccpConsumed | SccpAlreadyConsumed | SccpRangeConsumed | SccpConsumeReverted

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

/// Tells the minter to release the pending `amount` of `nonce` (§5.3.4
/// step 4); paid from the bucket's own balance.
fun sendConsumeReverted(minter: address, queryId: int, nonce: int, amount: int) {
    val report = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: minter,
        value: sccpConsumeRevertedValue(),
        body: SccpConsumeReverted { queryId, nonce, amount },
    });
    report.send(SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_IGNORE_ERRORS);
}

fun onInternalMessage(in: InMessage) {
    val msg = lazy BucketMessage.fromSlice(in.body);

    match (msg) {
        SccpActivateBucket => {
            // §5.3.4 step 2: sent only by the minter, once per index, with the
            // canonical StateInit; the attached value is the bucket floor.
            var storage = lazy BucketStorage.load();
            assert (in.senderAddress == storage.minterAddress) throw SccpErrors.NotMinter;
            assert (msg.index == storage.index) throw SccpErrors.BadRange;
            storage.activated = true;
            storage.save();
        }

        SccpConsume => {
            var storage = lazy BucketStorage.load();
            storage.requireActiveFromMinter(in.senderAddress);
            val (hi, lo) = storage.flagMask(msg.nonce);
            sccpReserveFloor(sccpBucketFloor(), in.valueCoins);
            if (((storage.bitsHi & hi) | (storage.bitsLo & lo)) == 0) {
                storage.bitsHi |= hi;
                storage.bitsLo |= lo;
                storage.save();
                val reply = createMessage({
                    bounce: BounceMode.Only256BitsOfBody,
                    dest: storage.minterAddress,
                    value: 0,
                    body: SccpConsumed {
                        queryId: msg.queryId,
                        nonce: msg.nonce,
                        amount: msg.amount,
                        tail: msg.tail,
                    },
                });
                reply.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
            } else {
                val reply = createMessage({
                    bounce: BounceMode.Only256BitsOfBody,
                    dest: storage.minterAddress,
                    value: 0,
                    body: SccpAlreadyConsumed {
                        queryId: msg.queryId,
                        nonce: msg.nonce,
                        amount: msg.amount,
                        tail: msg.tail,
                    },
                });
                reply.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
            }
        }

        SccpConsumeRange => {
            var storage = lazy BucketStorage.load();
            storage.requireActiveFromMinter(in.senderAddress);
            val first = msg.first;
            val count = msg.count;
            assert ((count >= 1) & (count <= SCCP_BUCKET_BITS)) throw SccpErrors.BadRange;
            assert ((first >> SCCP_BUCKET_SHIFT) == storage.index) throw SccpErrors.BadRange;
            assert (
                ((first + count - 1) >> SCCP_BUCKET_SHIFT) == storage.index
            ) throw SccpErrors.BadRange;
            val (hi, lo) = bucketRangeMask(first & SCCP_BUCKET_MASK, count);
            sccpReserveFloor(sccpBucketFloor(), in.valueCoins);
            if (((storage.bitsHi & hi) | (storage.bitsLo & lo)) == 0) {
                storage.bitsHi |= hi;
                storage.bitsLo |= lo;
                storage.save();
                val reply = createMessage({
                    bounce: BounceMode.Only256BitsOfBody,
                    dest: storage.minterAddress,
                    value: 0,
                    body: SccpRangeConsumed {
                        queryId: msg.queryId,
                        first,
                        count,
                    },
                });
                reply.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
            } else {
                val reply = createMessage({
                    bounce: BounceMode.NoBounce,
                    dest: storage.minterAddress,
                    value: 0,
                    body: SccpRangeRejected {
                        queryId: msg.queryId,
                        first,
                        count,
                    },
                });
                reply.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
            }
        }

        SccpUnconsume => {
            var storage = lazy BucketStorage.load();
            storage.requireActiveFromMinter(in.senderAddress);
            val (hi, lo) = storage.flagMask(msg.nonce);
            storage.bitsHi &= ~hi;
            storage.bitsLo &= ~lo;
            storage.save();
        }

        TopUpTons => {
            // anyone may extend the bucket's storage floor
        }

        else => {
            assert (in.body.isEmpty()) throw SccpErrors.InvalidMessage;
        }
    }
}

/// The minter failed to handle a reply (§5.3.4 step 4). A bounced
/// `sccp_consumed` clears the flag again and a bounced `sccp_already_consumed`
/// leaves it; both report `sccp_consume_reverted` so the minter releases the
/// pending amount. A bounced `sccp_range_consumed` clears the range. The
/// handler pays its gas and the report from the bucket's own balance, since
/// a bounce may carry little value; the next consume tops the floor up again.
fun onBouncedMessage(in: InMessageBounced) {
    var storage = lazy BucketStorage.load();
    if (in.senderAddress != storage.minterAddress) {
        return;
    }
    setGasLimitToMaximum();
    in.bouncedBody.skipBouncedPrefix();
    val msg = lazy BucketBounce.fromSlice(in.bouncedBody);
    match (msg) {
        SccpConsumed => {
            val (hi, lo) = storage.flagMask(msg.nonce);
            storage.bitsHi &= ~hi;
            storage.bitsLo &= ~lo;
            storage.save();
            sendConsumeReverted(storage.minterAddress, msg.queryId, msg.nonce, msg.amount);
        }
        SccpAlreadyConsumed => {
            sendConsumeReverted(storage.minterAddress, msg.queryId, msg.nonce, msg.amount);
        }
        SccpRangeConsumed => {
            val first = msg.first;
            val count = msg.count;
            if ((first >> SCCP_BUCKET_SHIFT) != storage.index) {
                return;
            }
            val (hi, lo) = bucketRangeMask(first & SCCP_BUCKET_MASK, count);
            storage.bitsHi &= ~hi;
            storage.bitsLo &= ~lo;
            storage.save();
        }
        SccpConsumeReverted => {
            // the minter could not process the report (a residual case in
            // SECURITY.md: the amount stays pending); the flags are already
            // final, so there is nothing to undo here
        }
    }
}

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
