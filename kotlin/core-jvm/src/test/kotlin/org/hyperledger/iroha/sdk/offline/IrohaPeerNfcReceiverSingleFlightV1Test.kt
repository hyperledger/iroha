package org.hyperledger.iroha.sdk.offline

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.Varint

class IrohaPeerNfcReceiverSingleFlightV1Test {
    @Test
    fun `two pending commits cannot stage twice and a late failure cannot erase the ack`() {
        val fixture = fixture()
        val request = message(fixture, "Request", IrohaPeerPayloadKind.REQUEST)
        val payment = message(fixture, "Payment", IrohaPeerPayloadKind.PAYMENT)
        val acknowledgement = message(fixture, "Credited::Receive", IrohaPeerPayloadKind.CREDITED)
        val receiver = receiver(request)
        writePayment(receiver, payment)

        val first = receiver.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
            as IrohaPeerNfcPaymentAdmissionDispositionV1.Persist
        assertFailsWith<IllegalArgumentException> { receiver.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT) }
        assertFailsWith<IllegalArgumentException> { receiver.handle(IrohaPeerNfcCommandV1.RESET_SESSION) }
        receiver.completePayment(first.context, IrohaPeerNfcDurablePaymentAdmissionV1(first.context, acknowledgement))
        receiver.rejectPayment(first.context)
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, receiver.status().phase)
        assertContentEquals(
            acknowledgement,
            receiver.handle(IrohaPeerNfcCommandV1.readAcknowledgement(0, acknowledgement.size)) as ByteArray,
        )
    }

    @Test
    fun `deactivation permits exact retry while stale context cannot reject it`() {
        val fixture = fixture()
        val request = message(fixture, "Request", IrohaPeerPayloadKind.REQUEST)
        val payment = message(fixture, "Payment", IrohaPeerPayloadKind.PAYMENT)
        val acknowledgement = message(fixture, "Credited::Receive", IrohaPeerPayloadKind.CREDITED)
        val receiver = receiver(request)
        writePayment(receiver, payment)
        val old = (receiver.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
            as IrohaPeerNfcPaymentAdmissionDispositionV1.Persist).context
        receiver.abandonPendingPayment()
        assertEquals(IrohaPeerNfcPhaseV1.REQUEST_READY, receiver.status().phase)
        assertFailsWith<IllegalArgumentException> { receiver.handle(IrohaPeerNfcCommandV1.RESET_SESSION) }

        val exactDescriptor = IrohaPeerNfcPaymentDescriptorV1(IrohaPeerWireMessageV1.decode(payment))
        val changedDescriptor = IrohaPeerNfcPaymentDescriptorV1.decode(
            exactDescriptor.encode().copyOf().apply { this[7] = (this[7].toInt() xor 1).toByte() },
        )
        assertFailsWith<IllegalArgumentException> {
            receiver.handle(IrohaPeerNfcCommandV1.beginPayment(changedDescriptor))
        }
        receiver.handle(IrohaPeerNfcCommandV1.beginPayment(exactDescriptor))
        assertFailsWith<IllegalArgumentException> {
            receiver.handle(IrohaPeerNfcCommandV1.writePayment(0, payment.copyOf().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }))
        }
        assertEquals(0, receiver.status().receivedPaymentBytes)

        receiver.handle(IrohaPeerNfcCommandV1.writePayment(0, payment))
        val retry = (receiver.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
            as IrohaPeerNfcPaymentAdmissionDispositionV1.Persist).context
        receiver.rejectPayment(old)
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.status().phase)
        receiver.completePayment(retry, IrohaPeerNfcDurablePaymentAdmissionV1(retry, acknowledgement))
        receiver.rejectPayment(old)
        receiver.rejectPayment(retry)
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, receiver.status().phase)
    }

    private fun receiver(request: ByteArray) = IrohaPeerNfcReceiverSessionV1(
        request,
        ByteArray(IrohaPeerNfcV1.SESSION_ID_BYTES) { 1 },
        IrohaPeerNfcProfilePolicyV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1),
    )

    private fun writePayment(receiver: IrohaPeerNfcReceiverSessionV1, payment: ByteArray) {
        receiver.handle(IrohaPeerNfcCommandV1.beginPayment(IrohaPeerNfcPaymentDescriptorV1(
            IrohaPeerWireMessageV1.decode(payment),
        )))
        receiver.handle(IrohaPeerNfcCommandV1.writePayment(0, payment))
    }

    private fun message(fixture: JsonObject, variant: String, kind: IrohaPeerPayloadKind): ByteArray {
        val vector = fixture.getValue("envelopes").jsonArray.map { it.jsonObject }
            .firstOrNull { it.getValue("variant").jsonPrimitive.content == variant }
            ?: error("wallet envelope vector $variant was not found")
        val hex = vector.getValue("canonical_hex").jsonPrimitive.content
        val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return IrohaPeerWireMessageV1(IrohaPeerCanonicalPayload(
            IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
            kind,
            IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1.requiredSchemaVersion,
            IrohaPeerRequestFixtureV1.payload(kind, bytes),
        )).encode()
    }

    @Test
    fun `a payment for another request and a foreign credited acknowledgement are refused`() {
        val fixture = fixture()
        val request = message(fixture, "Request", IrohaPeerPayloadKind.REQUEST)
        val payment = message(fixture, "Payment", IrohaPeerPayloadKind.PAYMENT)
        val credited = message(fixture, "Credited::Receive", IrohaPeerPayloadKind.CREDITED)

        // A structurally valid Request (other signature bytes) that the Payment does not carry.
        val otherRequest = rewrap(request, IrohaPeerPayloadKind.REQUEST, field = 4)
        val foreign = receiver(otherRequest)
        writePayment(foreign, payment)
        assertFailsWith<IllegalArgumentException> { foreign.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT) }
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, foreign.status().phase)

        // A structurally valid Credited under another scheme (its `scheme_id` field) cannot complete.
        val receiver = receiver(request)
        writePayment(receiver, payment)
        val context = (receiver.handle(IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
            as IrohaPeerNfcPaymentAdmissionDispositionV1.Persist).context
        val otherCredited = rewrap(credited, IrohaPeerPayloadKind.CREDITED, field = 1)
        assertFailsWith<IllegalArgumentException> {
            receiver.completePayment(context, IrohaPeerNfcDurablePaymentAdmissionV1(context, otherCredited))
        }
        assertEquals(IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING, receiver.status().phase)
        receiver.completePayment(context, IrohaPeerNfcDurablePaymentAdmissionV1(context, credited))
        assertEquals(IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY, receiver.status().phase)
    }

    /**
     * Re-wrap an IPM1 wallet message after flipping the last byte of top-level message field
     * [field]; the envelope CRC64 is refreshed so the frame stays structurally valid.
     */
    private fun rewrap(encoded: ByteArray, kind: IrohaPeerPayloadKind, field: Int): ByteArray {
        val frame = IrohaPeerKagemushaWalletAdapterV1.decode(IrohaPeerWireMessageV1.decode(encoded))
        val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
        var cursor = Varint.decode(frame, payloadOffset).nextOffset + 2
        cursor = Varint.decode(frame, cursor).nextOffset + 4
        cursor = Varint.decode(frame, cursor).nextOffset
        var end = cursor
        for (index in 0..field) {
            val length = Varint.decode(frame, cursor)
            end = length.nextOffset + length.value.toInt()
            if (index < field) cursor = end
        }
        frame[end - 1] = (frame[end - 1].toInt() xor 1).toByte()
        val crc = CRC64.compute(frame.copyOfRange(payloadOffset, frame.size))
        for (index in 0 until 8) frame[31 + index] = (crc ushr (8 * index)).toByte()
        assertEquals(kind.walletMessageKind, KagemushaWalletWireV1.inspectEnvelope(frame).kind)
        return IrohaPeerWireMessageV1(IrohaPeerCanonicalPayload(
            IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
            kind,
            1,
            IrohaPeerRequestFixtureV1.payload(kind, frame),
        )).encode()
    }

    private fun fixture(): JsonObject {
        var current = Paths.get("").toAbsolutePath().normalize()
        while (current != null) {
            val candidate = current.resolve("fixtures/kagemusha/wallet_v1_vectors.json")
            if (Files.isRegularFile(candidate)) {
                return Json.parseToJsonElement(
                    String(Files.readAllBytes(candidate), StandardCharsets.UTF_8),
                ).jsonObject
            }
            current = current.parent
        }
        error("fixtures/kagemusha/wallet_v1_vectors.json was not found")
    }
}
