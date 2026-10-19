// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * Transport-neutral NFC card: the host card emulation endpoint of the receiver's phone under one
 * application identifier (`specs/kagemusha_wallet_wire_v1.md` §6, NFC). It hosts the receiver's open
 * Request from the moment the receiver confirms the amount, or a receiver session restored from its
 * durable records ([direct]); there is no payer message before the Request.
 *
 * GET_INTAKE answers the session's `IOI1` record; GET_INFO, READ_REQUEST, BEGIN_PAYMENT, WRITE,
 * COMMIT, READ_ACK, CONFIRM_ACK and GET_STATUS go to the receiver session. Thread-safe.
 */
class IrohaPeerNfcCardEndpointV1 private constructor(
    @JvmField val applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
    /** The receiver session hosting the Request. */
    @JvmField val receiver: IrohaPeerNfcReceiverSessionV1,
) {
    /** Session identifier `s`; a defensive copy. */
    val sessionId: ByteArray get() = receiver.sessionId

    /** The current `IOI1` record. */
    fun intakeRecord(): IrohaPeerNfcIntakeRecordV1 = receiver.intakeRecord()

    /** Answers every command except BEGIN_PAYMENT and COMMIT (see [preparePaymentAdmission] and [prepareCommit]). */
    fun handle(command: IrohaPeerNfcCommandV1): ByteArray {
        if (command is IrohaPeerNfcCommandV1.SelectApplication && command.applicationIdentifier != applicationIdentifier) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
        }
        return receiver.handle(command)
    }

    fun preparePaymentAdmission(command: IrohaPeerNfcCommandV1): IrohaPeerNfcPaymentAdmissionDispositionV1 =
        receiver.preparePaymentAdmission(command)

    fun installPaymentAdmission(record: IrohaPeerNfcDurablePaymentAdmissionV1) {
        receiver.installPaymentAdmission(record)
    }

    fun prepareCommit(command: IrohaPeerNfcCommandV1): IrohaPeerNfcCommitDispositionV1 =
        receiver.prepareCommit(command)

    fun installDurableAcknowledgement(record: IrohaPeerNfcDurableAcknowledgementV1) {
        receiver.installDurableAcknowledgement(record)
    }

    /**
     * Decodes and executes one raw APDU synchronously (tests, in-memory carriers). BEGIN_PAYMENT and
     * COMMIT succeed only after [admitPayment] or [durableCommit] returned an exact persisted record.
     */
    @JvmOverloads
    fun process(
        apdu: ByteArray,
        admitPayment: IrohaPeerNfcReceiverSessionV1.DurableAdmissionHandler? = null,
        durableCommit: IrohaPeerNfcReceiverSessionV1.DurableCommitHandler? = null,
    ): IrohaPeerNfcAPDUResponseV1 = receiver.process(apdu, applicationIdentifier, admitPayment, durableCommit)

    companion object {
        /**
         * A card hosting [receiver]: the receiver's open Request from the moment the receiver confirms
         * the amount, or a session restored from its durable records.
         */
        @JvmStatic
        fun direct(
            applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
            receiver: IrohaPeerNfcReceiverSessionV1,
        ): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1(applicationIdentifier, receiver)
    }
}
