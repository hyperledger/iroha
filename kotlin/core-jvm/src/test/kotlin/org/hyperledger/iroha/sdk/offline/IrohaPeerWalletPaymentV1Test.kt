// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `KWPYPC1` Payment carrier: the unchanged Payment envelope of
 * `fixtures/kagemusha/wallet_v1_vectors.json` beside a synthetic payer companion. Structural
 * transport DATA only: Native alone checks the companion against the Payment.
 */
class IrohaPeerWalletPaymentV1Test {
    private val profile = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
    private val envelope = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.PAYMENT)
    private val companion = IrohaPeerRequestFixtureV1.companion()

    @Test fun exactOriginalsAndBigEndianLengthsSurviveDefensiveCopies() {
        val sourceEnvelope = envelope.copyOf()
        val sourceCompanion = companion.copyOf()
        val carrier = IrohaPeerWalletPaymentV1(sourceEnvelope, sourceCompanion)
        sourceEnvelope.fill(0)
        sourceCompanion.fill(0)
        val encoded = carrier.encode()
        assertEquals(IrohaPeerWalletPaymentV1.HEADER_BYTES + envelope.size + companion.size, encoded.size)
        assertContentEquals("KWPYPC1\u0000".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(0, 8))
        assertEquals(envelope.size, ByteBuffer.wrap(encoded, 8, 4).int)
        assertEquals(companion.size, ByteBuffer.wrap(encoded, 12, 4).int)
        assertContentEquals(envelope, encoded.copyOfRange(16, 16 + envelope.size))
        assertContentEquals(companion, encoded.copyOfRange(16 + envelope.size, encoded.size))
        val decoded = IrohaPeerWalletPaymentV1.decode(encoded)
        assertContentEquals(envelope, decoded.paymentEnvelope())
        assertContentEquals(companion, decoded.payerCompanion())
        decoded.paymentEnvelope().fill(0)
        decoded.payerCompanion().fill(0)
        encoded.fill(0)
        assertContentEquals(carrier.encode(), decoded.encode())
        assertTrue(carrier.toString().contains("[REDACTED]"))
    }

    @Test fun boundsAreTheEnvelopeAndCompanionLimits() {
        assertEquals(16, IrohaPeerWalletPaymentV1.HEADER_BYTES)
        assertEquals(2_048, IrohaPeerWalletPaymentV1.MAXIMUM_COMPANION_BYTES)
        assertEquals(KagemushaWalletWireV1.PAYER_COMPANION_MAX_BYTES, IrohaPeerWalletPaymentV1.MAXIMUM_COMPANION_BYTES)
        assertEquals(12_098, IrohaPeerWalletPaymentV1.MAXIMUM_BYTES)
        assertEquals(IrohaPeerWalletPaymentV1.MAXIMUM_BYTES, IrohaPeerPayloadKind.PAYMENT.maximumWalletFrameBytes)
        assertEquals(84 + 12_098, IrohaPeerNfcV1.MAXIMUM_PAYMENT_BYTES)
        assertEquals(2_048, IrohaPeerWalletPaymentV1(envelope, ByteArray(2_048) { 1 }).payerCompanion().size)
        assertEquals(1, IrohaPeerWalletPaymentV1(envelope, byteArrayOf(1)).payerCompanion().size)
        for (size in listOf(0, 2_049)) {
            assertFailsWith<IllegalArgumentException>("$size") { IrohaPeerWalletPaymentV1(envelope, ByteArray(size)) }
        }
        assertFailsWith<IllegalArgumentException> { IrohaPeerWalletPaymentV1(byteArrayOf(), companion) }
        assertFailsWith<IllegalArgumentException> { IrohaPeerWalletPaymentV1(ByteArray(10_035), companion) }
        // The carrier holds exactly a Payment envelope.
        for (kind in listOf(IrohaPeerPayloadKind.REQUEST, IrohaPeerPayloadKind.CREDITED)) {
            assertFailsWith<IllegalArgumentException>(kind.name) {
                IrohaPeerWalletPaymentV1(IrohaPeerRequestFixtureV1.envelope(kind), companion)
            }
        }
    }

    @Test fun truncatedOversizedAndForeignCarriersAreRefused() {
        val valid = IrohaPeerWalletPaymentV1(envelope, companion).encode()
        val requestCarrier = IrohaPeerWalletRequestV1(
            IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST),
            IrohaPeerRequestFixtureV1.account(),
        ).encode()
        val bad = listOf(
            envelope,
            requestCarrier,
            valid.copyOf(IrohaPeerWalletPaymentV1.HEADER_BYTES + 1),
            valid.copyOf(valid.size - 1),
            valid + byteArrayOf(0),
            valid.copyOf().also { it[0] = 0 },
            valid.copyOf().also { it[7] = 1 },
            valid.copyOf().also { ByteBuffer.wrap(it, 8, 4).putInt(0) },
            valid.copyOf().also { ByteBuffer.wrap(it, 8, 4).putInt(10_035) },
            valid.copyOf().also { ByteBuffer.wrap(it, 8, 4).putInt(-1) },
            valid.copyOf().also { ByteBuffer.wrap(it, 12, 4).putInt(0) },
            valid.copyOf().also { ByteBuffer.wrap(it, 12, 4).putInt(2_049) },
            valid.copyOf().also { ByteBuffer.wrap(it, 12, 4).putInt(companion.size + 1) },
            ByteArray(IrohaPeerWalletPaymentV1.MAXIMUM_BYTES + 1),
        )
        for ((index, bytes) in bad.withIndex()) {
            assertFailsWith<IllegalArgumentException>("case $index") { IrohaPeerWalletPaymentV1.decode(bytes) }
        }
    }

    @Test fun bothOriginalsAreCoveredByIpm1Hashes() {
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion = companion)
        assertEquals(IrohaPeerPayloadKind.PAYMENT, message.canonicalPayload.kind)
        assertContentEquals(IrohaPeerWalletPaymentV1(envelope, companion).encode(), message.canonicalPayload.bytes)
        assertContentEquals(envelope, IrohaPeerKagemushaWalletAdapterV1.decode(message))
        assertContentEquals(companion, IrohaPeerKagemushaWalletAdapterV1.payerCompanion(message))
        assertEquals(message, IrohaPeerWireMessageV1.decode(message.encode(), profile, IrohaPeerPayloadKind.PAYMENT))
        // Another companion, or another structurally valid Payment beside the same companion, changes both hashes.
        val otherCompanion = IrohaPeerKagemushaWalletAdapterV1.wrap(
            envelope,
            payerCompanion = companion.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
        )
        val otherPayment = IrohaPeerWireMessageV1.decode(
            IrohaPeerNfcTestFixturesV1.rewrap(message.encode(), IrohaPeerPayloadKind.PAYMENT, field = 1),
        )
        assertContentEquals(companion, IrohaPeerKagemushaWalletAdapterV1.payerCompanion(otherPayment))
        for (other in listOf(otherCompanion, otherPayment)) {
            assertFalse(message.canonicalHash.contentEquals(other.canonicalHash))
            assertFalse(message.wireHash.contentEquals(other.wireHash))
        }
        val tampered = message.encode().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<IllegalArgumentException> { IrohaPeerWireMessageV1.decode(tampered) }
    }

    @Test fun aPaymentTravelsOnlyAsItsCarrierAndEachCompanionOnlyBesideItsKind() {
        val carrier = IrohaPeerWalletPaymentV1(envelope, companion).encode()
        assertFailsWith<IllegalArgumentException> { IrohaPeerCanonicalPayload(profile, IrohaPeerPayloadKind.PAYMENT, 1, envelope) }
        for (kind in IrohaPeerPayloadKind.entries.filter { it != IrohaPeerPayloadKind.PAYMENT }) {
            assertFailsWith<IllegalArgumentException>(kind.name) { IrohaPeerCanonicalPayload(profile, kind, 1, carrier) }
        }
        val request = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST)
        val credited = IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.CREDITED)
        val account = IrohaPeerRequestFixtureV1.account()
        assertFailsWith<IllegalArgumentException> { IrohaPeerKagemushaWalletAdapterV1.wrap(envelope) }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal = account)
        }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal = account, payerCompanion = companion)
        }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(request, destinationAccountOriginal = account, payerCompanion = companion)
        }
        assertFailsWith<IllegalArgumentException> { IrohaPeerKagemushaWalletAdapterV1.wrap(credited, payerCompanion = companion) }
        val requestMessage = IrohaPeerKagemushaWalletAdapterV1.wrap(request, destinationAccountOriginal = account)
        val paymentMessage = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion = companion)
        assertFailsWith<IllegalArgumentException> { IrohaPeerKagemushaWalletAdapterV1.payerCompanion(requestMessage) }
        assertFailsWith<IllegalArgumentException> { IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(paymentMessage) }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerWireMessageV1.decode(paymentMessage.encode(), expectedKind = IrohaPeerPayloadKind.CREDITED)
        }
        // IPM1 kinds 1 and 7 (the former Offer and Lineage hint) are unknown.
        for (code in listOf(1, 7)) {
            assertNull(IrohaPeerPayloadKind.fromCode(code))
            val relabelled = paymentMessage.encode().also { it[8] = code.toByte() }
            assertFailsWith<IllegalArgumentException>("$code") { IrohaPeerWireMessageV1.decode(relabelled) }
        }
    }

    @Test fun theCarrierRoundTripsThroughQrAndAScannerForPaymentsRefusesARequest() {
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, payerCompanion = companion)
        val scan = IrohaPeerQRScanSessionV1(profile, IrohaPeerPayloadKind.PAYMENT, 1)
        val restored = assertNotNull(
            IrohaPeerQRCodecV1.encode(message).asSequence().map { scan.ingestAt(it, 0) }.first { it.isComplete }.message,
        )
        assertContentEquals(envelope, IrohaPeerKagemushaWalletAdapterV1.decode(restored))
        assertContentEquals(companion, IrohaPeerKagemushaWalletAdapterV1.payerCompanion(restored))
        // The receiver scanning for the Payment meets the payer's screen showing the Request: a role mix-up.
        val requestTexts = IrohaPeerQRCodecV1.encode(
            IrohaPeerKagemushaWalletAdapterV1.wrap(
                IrohaPeerRequestFixtureV1.envelope(IrohaPeerPayloadKind.REQUEST),
                destinationAccountOriginal = IrohaPeerRequestFixtureV1.account(),
            ),
        )
        val mixUp = assertFailsWith<IllegalArgumentException> {
            IrohaPeerQRScanSessionV1(profile, IrohaPeerPayloadKind.PAYMENT, 1).ingestAt(requestTexts.first(), 0)
        }
        assertTrue(mixUp.message.orEmpty().contains("IRQR kind mismatch"), mixUp.message)
    }
}
