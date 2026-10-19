// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Request → Payment → Credited over one in-memory card connection, crossing the canonical APDU
 * codec, with loss of every value-phase response and receiver restoration. The card hosts the
 * receiver's open Request from the start; tap 1 only reads it.
 */
class IrohaPeerNfcExchangeV1Test {
    private val fixtures = IrohaPeerNfcTestFixturesV1
    private val readerLimits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes = 240, maximumWriteChunkBytes = 200)

    private fun tap1(reader: IrohaPeerNfcLoopbackV1, limits: IrohaPeerNfcLimitsV1 = readerLimits): IrohaPeerNfcRequestReadV1 =
        IrohaPeerNfcReaderExchangeV1.readRequest(fixtures.BPNG_AID, fixtures.POLICY, limits, reader)

    private fun tap2(
        reader: IrohaPeerNfcLoopbackV1,
        checkpoint: ByteArray?,
        limits: IrohaPeerNfcLimitsV1 = readerLimits,
    ): IrohaPeerNfcReaderExchangeResultV1 = IrohaPeerNfcReaderExchangeV1.run(
        checkpoint,
        fixtures.BPNG_AID,
        fixtures.POLICY,
        limits,
        transceive = reader,
        loadOrCreateDurableCheckpoint = IrohaPeerNfcReaderExchangeV1.LoadOrCreateDurableCheckpoint { _, _ ->
            fail("a restored two-tap exchange never creates a checkpoint")
        },
        updateDurableCheckpoint = reader.updateCheckpoint,
    )

    @Test
    fun `one connection reads the request then carries approval payment and credited`() {
        val card = fixtures.card()
        val reader = IrohaPeerNfcLoopbackV1(card)

        val read = tap1(reader)
        assertEquals(fixtures.request, read.request)
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, read.intake.state)
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, read.info.phase)
        assertContentEquals(card.sessionId, read.intake.sessionId)
        assertContentEquals(card.sessionId, read.info.identity.sessionId)
        // Tap 1 only reads: SELECT, IOI1, INF1, then Request chunks of min(local 240, card 4096).
        assertEquals(listOf("SELECT_APPLICATION", "GET_INTAKE", "GET_INFO"), reader.log.take(3))
        assertTrue(reader.log.drop(3).all { it == "READ_REQUEST" })
        assertTrue(reader.readSizes.all { it <= 240 } && reader.readSizes.sum() == fixtures.request.byteCount)
        assertTrue(reader.writeSizes.isEmpty())

        // Approval and checkpoint persistence happen while the same card connection stays open.
        // These are application markers, not hardware authentication or physical RF evidence.
        reader.log += "approve:payment"
        val checkpoint = read.senderCheckpoint(fixtures.payment.encode()).encode()
        reader.log += "persist:payment"
        val requestReads = reader.count(IrohaPeerNfcOperationV1.READ_REQUEST)
        reader.readSizes.clear()
        val result = tap2(reader, checkpoint)
        assertEquals(fixtures.credited, result.acknowledgement)
        assertEquals(IrohaPeerNfcConfirmationStateV1.CONFIRMED, result.confirmationState)
        assertEquals(fixtures.credited, result.checkpoint.durableAcknowledgement)
        assertEquals(1, reader.durableCommits)
        assertEquals(1, reader.admissionRecords.size)
        assertEquals(1, reader.persistedCheckpoints.size)
        assertEquals(result.checkpoint, IrohaPeerNfcSenderCheckpointV1.decode(reader.persistedCheckpoints.single()))
        assertTrue(reader.log.indexOf("READ_REQUEST") < reader.log.indexOf("approve:payment"))
        assertTrue(reader.log.indexOf("approve:payment") < reader.log.indexOf("persist:payment"))
        assertTrue(reader.log.indexOf("persist:payment") < reader.log.indexOf("BEGIN_PAYMENT"))
        // The acknowledgement-bearing checkpoint is durable before CONFIRM_ACK is sent.
        assertTrue(reader.log.indexOf("persist:checkpoint") < reader.log.indexOf("CONFIRM_ACKNOWLEDGEMENT"))
        assertEquals("CONFIRM_ACKNOWLEDGEMENT", reader.log.last())
        // The Payment carrier with its payer companion crosses the card whole.
        assertTrue(reader.writeSizes.all { it <= 200 } && reader.writeSizes.sum() == fixtures.payment.byteCount)
        assertEquals(IrohaPeerNfcPhaseV1.COMPLETE, card.receiver.phase)
        assertEquals(requestReads, reader.count(IrohaPeerNfcOperationV1.READ_REQUEST))

        // Recovery with the final checkpoint observes COMPLETE without another debit.
        val again = tap2(reader, result.checkpoint.encode())
        assertEquals(fixtures.credited, again.acknowledgement)
        assertEquals(1, reader.durableCommits)
    }

    @Test
    fun `a card hosting the open request accepts only the payment completing it`() {
        val open = fixtures.openRequest
        val reader = IrohaPeerNfcLoopbackV1(
            IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, IrohaPeerNfcReceiverSessionV1(ByteArray(16) { 0x4d }, open.encode())),
        )
        val read = tap1(reader)
        assertEquals(open, read.request)
        val result = tap2(reader, read.senderCheckpoint(fixtures.payment.encode()).encode())
        assertEquals(fixtures.credited, result.acknowledgement)
        assertEquals(1, reader.durableCommits)
        // A Request completed for another payer, wallet or ordinal is not the Payment's Request.
        val foreign = fixtures.requestWithPayerFields(1)
        val error = assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcSenderCheckpointV1(ByteArray(16) { 0x4e }, foreign.encode(), fixtures.payment.encode())
        }
        assertEquals(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH, error.error)
    }

    @Test
    fun `chunks are the intersection of local and card limits`() {
        val cardLimits = IrohaPeerNfcLimitsV1(maximumReadChunkBytes = 128, maximumWriteChunkBytes = 96)
        val reader = IrohaPeerNfcLoopbackV1(fixtures.card(limits = cardLimits))
        val read = tap1(reader, IrohaPeerNfcLimitsV1.DEFAULT)
        assertEquals(96, read.intake.maximumWriteChunkBytes)
        assertEquals(128, read.info.maximumReadChunkBytes)
        assertTrue(reader.readSizes.all { it <= 128 } && reader.readSizes.size > 1)

        reader.readSizes.clear()
        val result = tap2(reader, read.senderCheckpoint(fixtures.payment.encode()).encode(), IrohaPeerNfcLimitsV1.DEFAULT)
        assertEquals(fixtures.credited, result.acknowledgement)
        assertTrue(reader.writeSizes.all { it <= 96 } && reader.writeSizes.size > 1)
        assertTrue(reader.readSizes.all { it <= 128 })
    }

    @Test
    fun `tap 1 is read-only so a lost response is recovered by reading again`() {
        for (lost in listOf(
            IrohaPeerNfcOperationV1.GET_INTAKE,
            IrohaPeerNfcOperationV1.GET_INFO,
            IrohaPeerNfcOperationV1.READ_REQUEST,
        )) {
            val card = fixtures.card()
            val reader = IrohaPeerNfcLoopbackV1(card)
            reader.loseResponseFor = lost
            assertFailsWith<IrohaPeerNfcLostResponseV1>(lost.name) { tap1(reader) }
            assertEquals(fixtures.request, tap1(reader).request, lost.name)
            assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, card.receiver.phase, lost.name)
            assertTrue(reader.writeSizes.isEmpty(), lost.name)
        }
    }

    @Test
    fun `tap 1 refuses another identifier and a card whose exchange is under way`() {
        val reader = IrohaPeerNfcLoopbackV1(fixtures.card())
        val wrongAid = assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcReaderExchangeV1.readRequest(IrohaPeerNfcApplicationIdentifierV1.PROTOCOL, fixtures.POLICY, transceive = reader)
        }
        assertEquals(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER, wrongAid.error)
        assertEquals(listOf("SELECT_APPLICATION"), reader.log)

        // A card already receiving a Payment resumes only from the payer's checkpoint, never as a new Request.
        val session = ByteArray(16) { 0x2c }
        val receiver = IrohaPeerNfcReceiverSessionV1(session, fixtures.request.encode())
        admitAndWrite(receiver, session, fixtures.payment.encode())
        val busy = IrohaPeerNfcLoopbackV1(IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, receiver))
        assertEquals(IrohaPeerNfcErrorV1.STATE_MISMATCH, assertFailsWith<IrohaPeerNfcExceptionV1> { tap1(busy) }.error)
        assertEquals(0, busy.count(IrohaPeerNfcOperationV1.READ_REQUEST))
    }

    @Test
    fun `tap 2 resumes every value phase after a lost response`() {
        for (lost in listOf(
            IrohaPeerNfcOperationV1.BEGIN_PAYMENT,
            IrohaPeerNfcOperationV1.WRITE,
            IrohaPeerNfcOperationV1.COMMIT,
            IrohaPeerNfcOperationV1.READ_ACKNOWLEDGEMENT,
            IrohaPeerNfcOperationV1.CONFIRM_ACKNOWLEDGEMENT,
        )) {
            val card = fixtures.card()
            val reader = IrohaPeerNfcLoopbackV1(card)
            val initial = tap1(reader).senderCheckpoint(fixtures.payment.encode()).encode()
            reader.loseResponseFor = lost
            if (lost == IrohaPeerNfcOperationV1.CONFIRM_ACKNOWLEDGEMENT) {
                // The acknowledgement is durable on both wallets: a lost confirmation completes.
                val result = tap2(reader, initial)
                assertEquals(IrohaPeerNfcConfirmationStateV1.RESPONSE_UNKNOWN, result.confirmationState, lost.name)
                assertEquals(fixtures.credited, result.acknowledgement)
                assertEquals(1, reader.durableCommits)
                assertEquals(1, reader.persistedCheckpoints.size)
                continue
            }
            assertFailsWith<IrohaPeerNfcLostResponseV1>(lost.name) { tap2(reader, initial) }
            // Resume exclusively from GET_STATUS and the latest durable checkpoint.
            val retry = reader.persistedCheckpoints.lastOrNull() ?: initial
            val result = tap2(reader, retry)
            assertEquals(fixtures.credited, result.acknowledgement, lost.name)
            assertEquals(IrohaPeerNfcConfirmationStateV1.CONFIRMED, result.confirmationState, lost.name)
            assertEquals(1, reader.durableCommits, lost.name)
            assertEquals(1, reader.admissionRecords.size, lost.name)
            assertEquals(1, reader.persistedCheckpoints.size, lost.name)
            assertEquals(IrohaPeerNfcPhaseV1.COMPLETE, card.receiver.phase, lost.name)
        }
    }

    @Test
    fun `a receiver restored from IPA1 and IDA1 completes the same exchange`() {
        val session = ByteArray(16) { 0x3c }
        val requestBytes = fixtures.request.encode()
        val checkpoint = IrohaPeerNfcSenderCheckpointV1(session, requestBytes, fixtures.payment.encode()).encode()

        // Lose the first WRITE: the card holds the durable admission and the first chunk.
        val first = IrohaPeerNfcReceiverSessionV1(session, requestBytes)
        val reader = IrohaPeerNfcLoopbackV1(IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, first))
        reader.loseResponseFor = IrohaPeerNfcOperationV1.WRITE
        assertFailsWith<IrohaPeerNfcLostResponseV1> { tap2(reader, checkpoint) }
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, first.phase)
        val admission = IrohaPeerNfcDurablePaymentAdmissionV1.decode(reader.admissionRecords.single())
        assertContentEquals(reader.admissionRecords.single(), admission.encode())

        // Relaunch: the restored admission resumes PAYMENT_RECEIVING at offset zero.
        val restored = IrohaPeerNfcReceiverSessionV1(session, requestBytes, restoredPaymentAdmission = admission)
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, restored.phase)
        assertEquals(0, restored.status().receivedPaymentBytes)
        reader.endpoint = IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, restored)
        reader.loseResponseFor = IrohaPeerNfcOperationV1.READ_ACKNOWLEDGEMENT
        assertFailsWith<IrohaPeerNfcLostResponseV1> { tap2(reader, checkpoint) }
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, restored.phase)
        assertEquals(1, reader.durableCommits)

        // Relaunch again from IDA1 (and IPA1): ACKNOWLEDGEMENT_READY without a second commit.
        val acknowledgement = IrohaPeerNfcDurableAcknowledgementV1.decode(reader.acknowledgementRecords.single())
        assertContentEquals(reader.acknowledgementRecords.single(), acknowledgement.encode())
        val final = IrohaPeerNfcReceiverSessionV1(
            session,
            requestBytes,
            durableAcknowledgement = acknowledgement,
            restoredPaymentAdmission = admission,
        )
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, final.phase)
        assertEquals(final.status(), IrohaPeerNfcStatusV1.decode(final.status().encode()))
        assertTrue(final.info().flags.contains(IrohaPeerNfcFlagsV1.DURABLE_ACKNOWLEDGEMENT))
        reader.endpoint = IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, final)
        val result = tap2(reader, checkpoint)
        assertEquals(fixtures.credited, result.acknowledgement)
        assertEquals(1, reader.durableCommits)
        assertEquals(IrohaPeerNfcPhaseV1.COMPLETE, final.phase)

        // Records restore only for their own identity and are byte-exact.
        assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcReceiverSessionV1(ByteArray(16) { 0x3d }, requestBytes, durableAcknowledgement = acknowledgement)
        }
        assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcDurablePaymentAdmissionV1.decode(admission.encode().also { it[95] = (it[95].toInt() xor 1).toByte() })
        }
        assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcDurableAcknowledgementV1.decode(acknowledgement.encode().copyOf(acknowledgement.encode().size - 1))
        }
    }

    @Test
    fun `a single tap reads the request and creates the checkpoint once`() {
        val session = ByteArray(16) { 0x2b }
        val receiver = IrohaPeerNfcReceiverSessionV1(session, fixtures.request.encode())
        val reader = IrohaPeerNfcLoopbackV1(IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, receiver))
        var created = 0
        val result = IrohaPeerNfcReaderExchangeV1.run(
            null,
            fixtures.BPNG_AID,
            fixtures.POLICY,
            readerLimits,
            transceive = reader,
            loadOrCreateDurableCheckpoint = IrohaPeerNfcReaderExchangeV1.LoadOrCreateDurableCheckpoint { info, request ->
                created += 1
                assertEquals(fixtures.request, request)
                IrohaPeerNfcSenderCheckpointV1(info.identity.sessionId, request.encode(), fixtures.payment.encode())
            },
            updateDurableCheckpoint = reader.updateCheckpoint,
        )
        assertEquals(1, created)
        assertEquals(fixtures.credited, result.acknowledgement)
        assertTrue(reader.readSizes.isNotEmpty())
        // Without a checkpoint a reader never creates value for an exchange already under way.
        val error = assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcReaderExchangeV1.run(
                null,
                fixtures.BPNG_AID,
                fixtures.POLICY,
                transceive = reader,
                loadOrCreateDurableCheckpoint = IrohaPeerNfcReaderExchangeV1.LoadOrCreateDurableCheckpoint { _, _ ->
                    fail("no value may be created for a COMPLETE card")
                },
                updateDurableCheckpoint = reader.updateCheckpoint,
            )
        }
        assertEquals(IrohaPeerNfcErrorV1.STATE_MISMATCH, error.error)
    }

    @Test
    fun `a payment for another request and a foreign credited acknowledgement are refused`() {
        val session = ByteArray(16) { 1 }
        val request = fixtures.request.encode()
        val payment = fixtures.payment.encode()
        val credited = fixtures.credited.encode()

        // A structurally valid Request (other signature bytes) that the Payment does not carry.
        val otherRequest = IrohaPeerNfcTestFixturesV1.rewrap(request, IrohaPeerPayloadKind.REQUEST, field = 4)
        val foreign = IrohaPeerNfcReceiverSessionV1(session, otherRequest)
        admitAndWrite(foreign, session, payment)
        val commit = IrohaPeerNfcCommandV1.Commit(
            session,
            IrohaPeerWireMessageV1.decode(otherRequest).canonicalHash,
            fixtures.payment.wireHash,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH,
            assertFailsWith<IrohaPeerNfcExceptionV1> { foreign.prepareCommit(commit) }.error,
        )
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, foreign.phase)
        assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcSenderCheckpointV1(session, otherRequest, payment)
        }

        // A structurally valid Credited under another scheme cannot complete.
        val receiver = IrohaPeerNfcReceiverSessionV1(session, request)
        admitAndWrite(receiver, session, payment)
        val context = (
            receiver.prepareCommit(
                IrohaPeerNfcCommandV1.Commit(session, fixtures.request.canonicalHash, fixtures.payment.wireHash),
            ) as IrohaPeerNfcCommitDispositionV1.RequiresDurableCommit
            ).context
        val otherCredited = IrohaPeerNfcTestFixturesV1.rewrap(credited, IrohaPeerPayloadKind.CREDITED, field = 1)
        assertEquals(
            IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcDurableAcknowledgementV1(context, otherCredited) }.error,
        )
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.phase)
        val record = IrohaPeerNfcDurableAcknowledgementV1(context, credited)
        receiver.installDurableAcknowledgement(record)
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, receiver.phase)
        // The exact replay is idempotent; COMMIT is already committed.
        receiver.installDurableAcknowledgement(IrohaPeerNfcDurableAcknowledgementV1.decode(record.encode()))
        assertTrue(
            receiver.prepareCommit(
                IrohaPeerNfcCommandV1.Commit(session, fixtures.request.canonicalHash, fixtures.payment.wireHash),
            ) is IrohaPeerNfcCommitDispositionV1.AlreadyCommitted,
        )
        assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcSenderCheckpointV1(session, request, payment, otherCredited)
        }
    }

    @Test
    fun `durable boundaries answer storage failures and never expose an unpersisted acknowledgement`() {
        val session = ByteArray(16) { 7 }
        val receiver = IrohaPeerNfcReceiverSessionV1(session, fixtures.request.encode())
        val header = fixtures.payment.encode().copyOfRange(0, 84)
        val begin = IrohaPeerNfcAPDUCodecV1.encode(
            IrohaPeerNfcCommandV1.BeginPayment(session, fixtures.request.canonicalHash, header),
        )
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, receiver.process(begin, fixtures.BPNG_AID).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.STORAGE_FAILURE,
            receiver.process(begin, fixtures.BPNG_AID, { error("disk full") }).statusWord,
        )
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, receiver.phase)
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            receiver.process(begin, fixtures.BPNG_AID, { IrohaPeerNfcDurablePaymentAdmissionV1(it) }).statusWord,
        )
        // The exact BEGIN_PAYMENT replay is idempotent without another admission.
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            receiver.process(begin, fixtures.BPNG_AID, { fail("already admitted") }).statusWord,
        )
        val payment = fixtures.payment.encode()
        var offset = 0
        while (offset < payment.size) {
            val count = minOf(4096, payment.size - offset)
            val write = IrohaPeerNfcCommandV1.Write(
                session,
                fixtures.payment.wireHash,
                offset.toLong(),
                payment.copyOfRange(offset, offset + count),
            )
            assertEquals(
                IrohaPeerNfcStatusWordV1.SUCCESS,
                receiver.process(IrohaPeerNfcAPDUCodecV1.encode(write), fixtures.BPNG_AID).statusWord,
            )
            offset += count
        }
        val commit = IrohaPeerNfcAPDUCodecV1.encode(
            IrohaPeerNfcCommandV1.Commit(session, fixtures.request.canonicalHash, fixtures.payment.wireHash),
        )
        assertEquals(
            IrohaPeerNfcStatusWordV1.STORAGE_FAILURE,
            receiver.process(commit, fixtures.BPNG_AID, durableCommit = { error("native refused") }).statusWord,
        )
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.phase)
        assertNull(receiver.durableAcknowledgement)
        val readAck = IrohaPeerNfcAPDUCodecV1.encode(
            IrohaPeerNfcCommandV1.ReadAcknowledgement(session, fixtures.payment.wireHash, 0, 100),
        )
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, receiver.process(readAck, fixtures.BPNG_AID).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            receiver.process(
                commit,
                fixtures.BPNG_AID,
                durableCommit = { IrohaPeerNfcDurableAcknowledgementV1(it, fixtures.credited.encode()) },
            ).statusWord,
        )
        assertNotNull(receiver.durableAcknowledgement)
        val chunk = receiver.process(readAck, fixtures.BPNG_AID)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, chunk.statusWord)
        assertContentEquals(fixtures.credited.encode().copyOfRange(0, 100), chunk.data())
        // BEGIN_PAYMENT after the commit is refused.
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            receiver.process(begin, fixtures.BPNG_AID, { fail("never") }).statusWord,
        )
    }

    private fun admitAndWrite(receiver: IrohaPeerNfcReceiverSessionV1, session: ByteArray, payment: ByteArray) {
        val begin = IrohaPeerNfcCommandV1.BeginPayment(
            session,
            receiver.identity.requestCanonicalHash,
            payment.copyOfRange(0, 84),
        )
        val disposition = receiver.preparePaymentAdmission(begin)
            as IrohaPeerNfcPaymentAdmissionDispositionV1.RequiresDurableAdmission
        receiver.installPaymentAdmission(IrohaPeerNfcDurablePaymentAdmissionV1(disposition.context))
        receiver.handle(IrohaPeerNfcCommandV1.Write(session, IrohaPeerWireMessageV1.decode(payment).wireHash, 0, payment))
    }
}
