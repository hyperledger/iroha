// Capacity, identity and receipt-deletion invariants of TON recovery custody.
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-recovery"

fun testRecoveryOperation(nonce: int): RecoveryOperation {
    return {
        stage: SCCP_RECOVERY_CONSUME,
        phase: SCCP_RECOVERY_WAIT,
        attempt: 1,
        nonce,
        amount: 1000,
        count: 1,
        nextId: 0,
        queryId: nonce,
        result: 0,
        tail: ConsumeTail {
            kind: 0,
            recipient: testing.treasury("recipient").address,
            response: testing.treasury("caller").address,
            messageId: nonce,
        }.toCell(),
    };
}

get fun `test recovery reservation saturates before dispatch and reuses capacity without ids`() {
    var book = RecoveryBook.empty();
    var i = 0;
    while (i < SCCP_RECOVERY_CAPACITY) {
        expect(book.admit(testRecoveryOperation(i))).toEqual(i + 1);
        i += 1;
    }
    expect(book.count).toEqual(512);
    var rejected = false;
    try {
        book.requireRoom(1);
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryFull as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
    book.complete(1);
    expect(book.admit(testRecoveryOperation(600))).toEqual(513);
    expect(book.operations.exists(1)).toBeFalse();
    expect(book.count).toEqual(512);
}

get fun `test recovery lost prepared and deletion acknowledgements retain bounded custody`() {
    var receipts = RecoveryReceipts.empty();
    receipts.record(17, SCCP_RECOVERY_MINT, 1, SCCP_RECEIPT_APPLIED);
    // Losing the first ACK changes nothing. Confirmation returns its effect.
    expect(receipts.confirm(17, SCCP_RECOVERY_MINT, 1)).toEqual(SCCP_RECEIPT_APPLIED);
    expect(receipts.count).toEqual(1);
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.count).toEqual(0);
    // Losing Dropped requires only another Drop, never another mint.
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.count).toEqual(0);
    receipts.record(18, SCCP_RECOVERY_MINT, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_MINT, 1);
    expect(receipts.confirm(18, SCCP_RECOVERY_MINT, 1)).toEqual(SCCP_RECEIPT_APPLIED);
    expect(receipts.count).toEqual(1);
}

get fun `test recovery stale stage cannot remove an unconsume receipt`() {
    var receipts = RecoveryReceipts.empty();
    receipts.record(17, SCCP_RECOVERY_CONSUME, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_CONSUME, 1);
    receipts.record(17, SCCP_RECOVERY_UNCONSUME, 1, SCCP_RECEIPT_APPLIED);
    receipts.drop(17, SCCP_RECOVERY_CONSUME, 1);
    expect(receipts.confirm(17, SCCP_RECOVERY_UNCONSUME, 1)).toEqual(SCCP_RECEIPT_APPLIED);
}

get fun `test recovery stale absence cannot authorize a newer attempt`() {
    var operation = testRecoveryOperation(0);
    operation.phase = SCCP_RECOVERY_FAILED;
    operation.retry();
    expect(operation.attempt).toEqual(2);
    expect(operation.matches(SCCP_RECOVERY_CONSUME, 1)).toBeFalse();
    expect(operation.matches(SCCP_RECOVERY_CONSUME, 2)).toBeTrue();
    var rejected = false;
    try {
        operation.retry();
    } catch (code) {
        expect(code).toEqual(SccpErrors.BadRecovery as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
}

get fun `test recovery operation and attempt counters fail before wrapping`() {
    var book = RecoveryBook.empty();
    book.nextId = SCCP_MAX_U64;
    var rejected = false;
    try {
        book.requireRoom(1);
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryExhausted as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
    var operation = testRecoveryOperation(0);
    operation.attempt = SCCP_MAX_U64;
    operation.phase = SCCP_RECOVERY_FAILED;
    rejected = false;
    try {
        operation.retry();
    } catch (code) {
        expect(code).toEqual(SccpErrors.RecoveryExhausted as int);
        rejected = true;
    }
    expect(rejected).toBeTrue();
}

get fun `test recovery createMessage enforces ihr disabled for ordered confirmation`() {
    val outbound = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: testing.treasury("recipient").address,
        value: 10000000,
        body: SccpInit { queryId: 1 },
    });
    val parsed = TlbMessageRelaxed<SccpInit>.fromCell(outbound.messageCell);
    expect(parsed.info.ihrDisabled).toBeTrue();
}
