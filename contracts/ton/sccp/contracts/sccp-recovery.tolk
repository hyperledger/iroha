// Bounded asynchronous operation custody. A row is admitted before dispatch
// and survives both successful delivery and bounce until authenticated receipt
// deletion completes. Operation ids never repeat, including after slot reuse.

import "sccp-constants"
import "sccp-errors"
import "sccp-messages"

/// Bound applies independently to minter rows and each destination's receipts.
const SCCP_RECOVERY_CAPACITY = 512
const SCCP_RECOVERY_ACTIVATE = 1
const SCCP_RECOVERY_CONSUME = 2
const SCCP_RECOVERY_MINT = 3
const SCCP_RECOVERY_UNCONSUME = 4
const SCCP_RECOVERY_RANGE = 5
const SCCP_RECOVERY_WAIT = 0
const SCCP_RECOVERY_DROP = 1
const SCCP_RECOVERY_FAILED = 2
const SCCP_RECOVERY_QUEUED = 3
const SCCP_RECEIPT_MISSING = 0
const SCCP_RECEIPT_APPLIED = 1
const SCCP_RECEIPT_REJECTED = 2
const SCCP_RECEIPT_DROPPED = 3

/// Everything needed to complete or undo an original operation. `nextId` is
/// the next activation or consume in one prepaid activation chain; zero ends
/// it. The original caller's query id and response remain in custody.
struct RecoveryOperation {
    stage: uint3
    phase: uint2
    attempt: uint64
    nonce: uint64
    amount: uint96
    count: uint10
    nextId: uint64
    queryId: uint64
    result: uint2
    tail: Cell<ConsumeTail>
}

/// Fixed scalars and a capacity-bounded dictionary, in one minter reference.
struct RecoveryBook {
    nextId: uint64
    count: uint10
    /// Contiguous prefix whose activation receipt deletion is confirmed.
    activatedBuckets: uint64
    operations: map<uint64, Cell<RecoveryOperation>>
}

fun RecoveryBook.empty(): RecoveryBook {
    return {
        nextId: 1,
        count: 0,
        activatedBuckets: 0,
        operations: [],
    };
}

/// Check the complete batch before proof verification or any state mutation.
fun RecoveryBook.requireRoom(self, additional: int) {
    assert (
        (additional > 0) & (self.count + additional <= SCCP_RECOVERY_CAPACITY)
    ) throw SccpErrors.RecoveryFull;
    assert (self.nextId + additional <= SCCP_MAX_U64) throw SccpErrors.RecoveryExhausted;
}

fun RecoveryBook.admit(mutate self, operation: RecoveryOperation): int {
    self.requireRoom(1);
    val operationId = self.nextId;
    self.nextId += 1;
    self.count += 1;
    self.operations.set(operationId, operation.toCell());
    return operationId;
}

/// Only the authenticated completion handler calls this after a Dropped ACK.
fun RecoveryBook.complete(mutate self, operationId: int) {
    assert (self.operations.delete(operationId)) throw SccpErrors.NothingToRetry;
    self.count -= 1;
}

/// Stage is part of the key: a delayed Drop for consumption must never erase
/// the same operation's later unconsume receipt at the same bucket.
@pure
fun sccpReceiptKey(operationId: int, stage: int): uint72 {
    return (operationId << 8) | stage;
}

struct RecoveryReceipt {
    attempt: uint64
    result: uint2
}

struct RecoveryReceipts {
    count: uint10
    receipts: map<uint72, RecoveryReceipt>
}

fun RecoveryReceipts.empty(): RecoveryReceipts {
    return { count: 0, receipts: [] };
}

/// Called before the destination effect. An existing matching receipt means
/// the original effect already happened; the caller must only resend its ACK.
fun RecoveryReceipts.existing(self, operationId: int, stage: int, attempt: int): int? {
    val found = self.receipts.get(sccpReceiptKey(operationId, stage));
    if (found.isFound) {
        val receipt = found.loadValue();
        assert (receipt.attempt == attempt) throw SccpErrors.BadRecovery;
        return receipt.result;
    }
    assert (self.count < SCCP_RECOVERY_CAPACITY) throw SccpErrors.RecoveryFull;
    return null;
}

fun RecoveryReceipts.record(mutate self, operationId: int, stage: int, attempt: int, result: int) {
    assert (self.existing(operationId, stage, attempt) == null) throw SccpErrors.BadRecovery;
    assert (
        (result == SCCP_RECEIPT_APPLIED) | (result == SCCP_RECEIPT_REJECTED)
    ) throw SccpErrors.BadRecovery;
    self.receipts.set(sccpReceiptKey(operationId, stage), { attempt, result });
    self.count += 1;
}

/// A confirmation is observational: absence never creates a receipt.
fun RecoveryReceipts.confirm(self, operationId: int, stage: int, attempt: int): int {
    val found = self.receipts.get(sccpReceiptKey(operationId, stage));
    if (!found.isFound) {
        return SCCP_RECEIPT_MISSING;
    }
    val receipt = found.loadValue();
    assert (receipt.attempt == attempt) throw SccpErrors.BadRecovery;
    return receipt.result;
}

/// Repeated deletion ACKs absence. A different attempt's receipt is retained.
fun RecoveryReceipts.drop(mutate self, operationId: int, stage: int, attempt: int) {
    val key = sccpReceiptKey(operationId, stage);
    val found = self.receipts.get(key);
    if (found.isFound) {
        assert (found.loadValue().attempt == attempt) throw SccpErrors.BadRecovery;
        self.receipts.delete(key);
        self.count -= 1;
    }
}

/// An ACK can act only on the exact currently dispatched attempt. In
/// particular, an old Missing response cannot authorize a newer mint retry.
@pure
fun RecoveryOperation.matches(self, stage: int, attempt: int): bool {
    return (self.stage == stage) & (self.attempt == attempt);
}

/// An authenticated failed attempt is the sole route to a new dispatch.
fun RecoveryOperation.retry(mutate self) {
    assert (self.phase == SCCP_RECOVERY_FAILED) throw SccpErrors.BadRecovery;
    assert (self.attempt < SCCP_MAX_U64) throw SccpErrors.RecoveryExhausted;
    self.attempt += 1;
    self.phase = SCCP_RECOVERY_WAIT;
}
