// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * The receiver's card hosts its open Request from the moment the receiver confirms the amount
 * (`specs/kagemusha_wallet_wire_v1.md` §6, NFC); no payer message precedes the Request.
 */
class IrohaPeerNfcCardEndpointV1Test {
    private val fixtures = IrohaPeerNfcTestFixturesV1
    private val session = ByteArray(16) { 0x5a }
    private val requestHash = fixtures.request.canonicalHash

    private fun IrohaPeerNfcCardEndpointV1.send(command: IrohaPeerNfcCommandV1): IrohaPeerNfcAPDUResponseV1 =
        process(IrohaPeerNfcAPDUCodecV1.encode(command))

    @Test
    fun `GET_INTAKE answers REQUEST_READY with zero retired offer fields`() {
        val card = fixtures.card(session)
        val response = card.send(IrohaPeerNfcCommandV1.GetIntake)
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, response.statusWord)
        val bytes = response.data()
        assertEquals(IrohaPeerNfcV1.INTAKE_BYTES, bytes.size)
        val record = IrohaPeerNfcIntakeRecordV1.decode(bytes)
        assertEquals(card.intakeRecord(), record)
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, record.state)
        assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY.code, bytes[5].toInt())
        assertContentEquals(session, record.sessionId)
        assertContentEquals(session, card.sessionId)
        assertEquals(IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES, record.maximumWriteChunkBytes)
        assertContentEquals(ByteArray(40), bytes.copyOfRange(24, 64))
        assertContentEquals(ByteArray(2), bytes.copyOfRange(66, 68))
        assertContentEquals(bytes, record.encode())
    }

    @Test
    fun `request commands are answered from the start and bound to the hosted request`() {
        val card = fixtures.card(session)
        val info = IrohaPeerNfcInfoV1.decode(card.send(IrohaPeerNfcCommandV1.GetInfo).data())
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, info.phase)
        assertContentEquals(session, info.identity.sessionId)
        assertContentEquals(requestHash, info.identity.requestCanonicalHash)
        assertEquals(fixtures.request.byteCount, info.requestLength)
        val slice = card.send(IrohaPeerNfcCommandV1.ReadRequest(session, requestHash, 0, 100))
        assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, slice.statusWord)
        assertContentEquals(fixtures.request.encode().copyOfRange(0, 100), slice.data())
        val status = IrohaPeerNfcStatusV1.decode(card.send(IrohaPeerNfcCommandV1.GetStatus(session, requestHash)).data())
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, status.phase)
        // Another session or Request hash is a continuity mismatch; acknowledgement commands wait for COMMIT.
        assertEquals(
            IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.ReadRequest(ByteArray(16) { 0x5b }, requestHash, 0, 100)).statusWord,
        )
        assertEquals(
            IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.GetStatus(session, ByteArray(32) { 9 })).statusWord,
        )
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.ReadAcknowledgement(session, fixtures.payment.wireHash, 0, 100)).statusWord,
        )
        assertEquals(
            IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED,
            card.send(IrohaPeerNfcCommandV1.Commit(session, requestHash, fixtures.payment.wireHash)).statusWord,
        )
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, card.receiver.phase)
    }

    @Test
    fun `retired offer and ask instructions are unknown to the card`() {
        val card = fixtures.card(session)
        for (instruction in listOf(0x31, 0x32, 0x33, 0x34)) {
            assertNull(IrohaPeerNfcInstructionV1.fromCode(instruction))
            val apdu = byteArrayOf(0x80.toByte(), instruction.toByte(), 0, 0, 0x38)
            val error = assertFailsWith<IrohaPeerNfcExceptionV1>("$instruction") {
                IrohaPeerNfcAPDUCodecV1.decode(apdu, fixtures.BPNG_AID)
            }
            assertEquals(IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION, error.error)
            assertEquals(instruction, error.detail)
            assertEquals(IrohaPeerNfcStatusWordV1.INSTRUCTION_NOT_SUPPORTED, card.process(apdu).statusWord)
        }
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, card.receiver.phase)
        assertEquals(IrohaPeerNfcInstructionV1.GET_INTAKE, IrohaPeerNfcInstructionV1.fromCode(0x30))
    }

    @Test
    fun `a card hosts only a valid Request carrier of its profile`() {
        val payment = fixtures.payment.encode()
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_KIND,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcReceiverSessionV1(session, payment) }.error,
        )
        assertEquals(
            IrohaPeerNfcErrorV1.INVALID_SESSION,
            assertFailsWith<IrohaPeerNfcExceptionV1> { IrohaPeerNfcReceiverSessionV1(ByteArray(16), fixtures.request.encode()) }.error,
        )
        // The open Request a receiver issues is hosted exactly as any Request carrier.
        val open = IrohaPeerNfcCardEndpointV1.direct(
            fixtures.BPNG_AID,
            IrohaPeerNfcReceiverSessionV1(session, fixtures.openRequest.encode()),
        )
        assertContentEquals(fixtures.openRequest.canonicalHash, IrohaPeerNfcInfoV1.decode(open.send(IrohaPeerNfcCommandV1.GetInfo).data())
            .identity.requestCanonicalHash)
    }
}
