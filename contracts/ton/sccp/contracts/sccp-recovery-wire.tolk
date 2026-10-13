// Receipt responses share one strict, bounded wire layout at both destinations.
import "sccp-messages"

fun sccpSendRecoveryAck(minter: address, operationId: int, stage: int, attempt: int, result: int) {
    val ack = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: minter,
        value: 0,
        body: SccpRecoveryAck { operationId, stage, attempt, result },
    });
    ack.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
}
