// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The card-side Offer intake of tap 1 (`specs/kagemusha_wallet_wire_v1.md` §6, NFC). */
class IrohaPeerNfcOfferIntakeV1Test {
    private val fixtures = IrohaPeerNfcTestFixturesV1
    private val session = ByteArray(16) { 0x5a }
    private val offerBytes = fixtures.offer.encode()
    private val offerHeader = offerBytes.copyOfRange(0, 84)
    private val offerHash = fixtures.offer.wireHash

    private fun card(): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1.intake(
        fixtures.BPNG_AID,
        IrohaPeerNfcOfferIntakeV1(fixtures.POLICY, IrohaPeerNfcLimitsV1.DEFAULT, session),
    )

    private fun IrohaPeerNfcCardEndpointV1.send(
        command: IrohaPeerNfcCommandV1,
        submitted: MutableList<IrohaPeerWireMessageV1>? = null,
    ): IrohaPeerNfcAPDUResponseV1 = process(
        IrohaPeerNfcAPDUCodecV1.encode(command),
        IrohaPeerNfcCardEndpointV1.OfferSubmittedHandler { submitted?.add(it) },
    )

    private fun IrohaPeerNfcCardEndpointV1.readIntake(): IrohaPeerNfcIntakeRecordV1 {
        val response = send(IrohaPeerNfcCommandV1.GetIntake)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, response.statusWord)
        return IrohaPeerNfcIntakeRecordV1.decode(response.data()).also { assertEquals(intakeRecord(), it) }
    }

    private fun write(offset: Int, count: Int, source: ByteArray = offerBytes, hash: ByteArray = offerHash) =
        IrohaPeerNfcCommandV1.WriteOffer(session, hash, offset.toLong(), source.copyOfRange(offset, offset + count))

    private fun IrohaPeerNfcCardEndpointV1.writeAll(source: ByteArray = offerBytes, hash: ByteArray = offerHash) {
        var offset = 0
        while (offset < source.size) {
            val count = minOf(500, source.size - offset)
            assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, send(write(offset, count, source, hash)).statusWord)
            offset += count
        }
    }

    @Test
    fun `awaiting intake answers only BEGIN_OFFER for its session`() {
        val card = card()
        val awaiting = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.AWAITING_OFFER, awaiting.state)
        assertContentEquals(session, awaiting.sessionId)
        assertFalse(awaiting.hasOffer)
        assertEquals(4096, awaiting.maximumWriteChunkBytes)
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(write(0, 100)).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash)).statusWord,
        )
        val otherSession = ByteArray(16) { 0x5b }
        assertEquals(
            IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.BeginOffer(otherSession, offerHeader)).statusWord,
        )
        assertEquals(IrohaPeerNfcIntakeStateV1.AWAITING_OFFER, card.readIntake().state)
    }

    @Test
    fun `an unfinished offer is resumed by its header and replaced by another`() {
        val card = card()
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader)).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(write(0, 300)).statusWord)
        var record = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER, record.state)
        assertEquals(offerBytes.size, record.offerLength)
        assertEquals(300, record.receivedOfferBytes)
        assertContentEquals(offerHash, record.offerWireHash)

        // The identical header is an idempotent no-op that keeps the received bytes.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader)).statusWord)
        assertEquals(300, card.readIntake().receivedOfferBytes)

        // Overlapping replays must be byte-identical; gaps and foreign hashes are refused.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(write(100, 300)).statusWord)
        assertEquals(400, card.readIntake().receivedOfferBytes)
        val conflicting = offerBytes.copyOf().also { it[150] = (it[150].toInt() xor 1).toByte() }
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(write(100, 100, conflicting)).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.WRONG_DATA, card.send(write(401, 10)).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED,
            card.send(write(400, 10, hash = ByteArray(32) { 9 })).statusWord,
        )
        assertEquals(400, card.readIntake().receivedOfferBytes)
        // SUBMIT_OFFER requires every byte.
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash)).statusWord,
        )

        // A different header replaces the unfinished Offer.
        val otherOffer = IrohaPeerNfcTestFixturesV1.rewrap(offerBytes, IrohaPeerPayloadKind.OFFER, field = 3)
        val otherHeader = otherOffer.copyOfRange(0, 84)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, otherHeader)).statusWord)
        record = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER, record.state)
        assertEquals(0, record.receivedOfferBytes)
        assertFalse(record.offerHashEquals(offerHash))
    }

    @Test
    fun `submit binds the intake and request commands wait for request ready`() {
        val card = card()
        val submitted = mutableListOf<IrohaPeerWireMessageV1>()
        for (command in requestCommands()) {
            assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(command).statusWord, command.toString())
        }
        card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader))
        card.writeAll()
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash), submitted).statusWord,
        )
        assertEquals(listOf(fixtures.offer), submitted)
        assertEquals(fixtures.offer, card.pendingOffer)
        val preparing = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST, preparing.state)
        assertEquals(preparing.offerLength, preparing.receivedOfferBytes)

        // The bound Offer's commands are idempotent no-ops; every other Offer command answers 6985.
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader)).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(write(0, 200)).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash), submitted).statusWord,
        )
        assertEquals(1, submitted.size)
        val otherOffer = IrohaPeerNfcTestFixturesV1.rewrap(offerBytes, IrohaPeerPayloadKind.OFFER, field = 3)
        val otherHash = IrohaPeerWireMessageV1.decode(otherOffer).wireHash
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.BeginOffer(session, otherOffer.copyOfRange(0, 84))).statusWord,
        )
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(write(0, 100, otherOffer, otherHash)).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, otherHash)).statusWord,
        )
        assertEquals(preparing, card.readIntake())
        for (command in requestCommands()) {
            assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(command).statusWord, command.toString())
        }

        // An invalid Request leaves the intake preparing; the wallet's Request makes it ready.
        assertFailsWith<IrohaPeerNfcExceptionV1> { card.installRequest(offerHash, fixtures.payment.encode()) }
        assertFailsWith<IrohaPeerNfcExceptionV1> { card.installRequest(otherHash, fixtures.request.encode()) }
        assertEquals(IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST, card.readIntake().state)
        val receiver = card.installRequest(offerHash, fixtures.request.encode())
        assertContentEquals(session, receiver.sessionId)
        assertNull(card.pendingOffer)
        val ready = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, ready.state)
        assertTrue(ready.hasOffer)
        assertContentEquals(offerHash, ready.offerWireHash)
        val info = IrohaPeerNfcInfoV1.decode(card.send(IrohaPeerNfcCommandV1.GetInfo).data())
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, info.phase)
        assertContentEquals(session, info.identity.sessionId)
        assertContentEquals(fixtures.request.canonicalHash, info.identity.requestCanonicalHash)
        // GET_INTAKE stays answered and the bound commands stay idempotent after REQUEST_READY.
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash), submitted).statusWord,
        )
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, card.readIntake().state)
        assertFailsWith<IrohaPeerNfcExceptionV1> { card.installRequest(offerHash, fixtures.request.encode()) }
    }

    @Test
    fun `an offer failing verification resets the intake with 6982`() {
        val card = card()
        val corrupted = offerBytes.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader))
        card.writeAll(corrupted)
        val submitted = mutableListOf<IrohaPeerWireMessageV1>()
        assertEquals(
            IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash), submitted).statusWord,
        )
        assertTrue(submitted.isEmpty())
        assertEquals(IrohaPeerNfcIntakeStateV1.AWAITING_OFFER, card.readIntake().state)
        // The payer may begin again.
        card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader))
        card.writeAll()
        assertEquals(
            IrohaPeerNfcStatusWordV1.SUCCESS,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash), submitted).statusWord,
        )
        assertEquals(1, submitted.size)
    }

    @Test
    fun `a declined offer reports its reason and stays bound`() {
        val card = card()
        card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader))
        card.writeAll()
        card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash))
        assertFailsWith<IllegalArgumentException> { card.declineRequest(offerHash, 0) }
        assertFailsWith<IllegalArgumentException> { card.declineRequest(offerHash, 0x10000) }
        card.declineRequest(offerHash, 7)
        val declined = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.DECLINED, declined.state)
        assertEquals(7, declined.reason)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader)).statusWord)
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(IrohaPeerNfcCommandV1.GetInfo).statusWord)
        assertFailsWith<IrohaPeerNfcExceptionV1> { card.installRequest(offerHash, fixtures.request.encode()) }

        val reader = IrohaPeerNfcLoopbackV1(card)
        val error = assertFailsWith<IrohaPeerNfcExceptionV1> {
            IrohaPeerNfcOfferExchangeV1.run(
                fixtures.offer,
                fixtures.BPNG_AID,
                fixtures.POLICY,
                transceive = reader,
                sleeper = reader.sleeper,
            )
        }
        assertEquals(IrohaPeerNfcErrorV1.OFFER_DECLINED, error.error)
        assertEquals(7, error.declineReason)
    }

    @Test
    fun `direct mode answers GET_INTAKE with zero offer fields`() {
        val receiver = IrohaPeerNfcReceiverSessionV1(session, fixtures.request.encode())
        val card = IrohaPeerNfcCardEndpointV1.direct(fixtures.BPNG_AID, receiver)
        assertTrue(card.isDirect)
        val record = card.readIntake()
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, record.state)
        assertFalse(record.hasOffer)
        assertEquals(0, record.offerLength)
        assertContentEquals(ByteArray(32), record.offerWireHash)
        assertContentEquals(session, record.sessionId)
        assertEquals(IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED, card.send(IrohaPeerNfcCommandV1.BeginOffer(session, offerHeader)).statusWord)
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash)).statusWord,
        )
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.send(IrohaPeerNfcCommandV1.GetInfo).statusWord)

        // A tap-1 reader reads the direct-mode Request without uploading its Offer.
        val reader = IrohaPeerNfcLoopbackV1(card)
        val read = IrohaPeerNfcOfferExchangeV1.run(
            fixtures.offer,
            fixtures.BPNG_AID,
            fixtures.POLICY,
            transceive = reader,
            sleeper = reader.sleeper,
        )
        assertEquals(fixtures.request, read.request)
        assertFalse(read.intake.hasOffer)
        assertEquals(0, reader.count(IrohaPeerNfcOperationV1.BEGIN_OFFER))
        assertEquals(0, reader.count(IrohaPeerNfcOperationV1.SUBMIT_OFFER))
    }

    @Test
    fun `intake sessions are fresh random nonzero identifiers`() {
        val first = IrohaPeerNfcOfferIntakeV1(fixtures.POLICY)
        val second = IrohaPeerNfcOfferIntakeV1(fixtures.POLICY)
        assertEquals(16, first.sessionId.size)
        assertFalse(first.sessionId.all { it.toInt() == 0 })
        assertFalse(first.sessionId.contentEquals(second.sessionId))
        assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcOfferIntakeV1(fixtures.POLICY, sessionId = ByteArray(16)) }
        assertNotNull(IrohaPeerNfcCardEndpointV1.intake(fixtures.BPNG_AID, fixtures.POLICY).intake)
    }

    private fun requestCommands(): List<IrohaPeerNfcCommandV1> {
        val requestHash = fixtures.request.canonicalHash
        val paymentHash = fixtures.payment.wireHash
        return listOf(
            IrohaPeerNfcCommandV1.GetInfo,
            IrohaPeerNfcCommandV1.ReadRequest(session, requestHash, 0, 100),
            IrohaPeerNfcCommandV1.BeginPayment(session, requestHash, fixtures.payment.encode().copyOfRange(0, 84)),
            IrohaPeerNfcCommandV1.Write(session, paymentHash, 0, byteArrayOf(1)),
            IrohaPeerNfcCommandV1.Commit(session, requestHash, paymentHash),
            IrohaPeerNfcCommandV1.ReadAcknowledgement(session, paymentHash, 0, 100),
            IrohaPeerNfcCommandV1.ConfirmAcknowledgement(session, paymentHash, fixtures.credited.wireHash),
            IrohaPeerNfcCommandV1.GetStatus(session, requestHash),
        )
    }
}
