package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Test

class KagemushaWalletSetupV1Test {
    @Test fun `collection result equality binds status and full sequence without rendering it`() {
        val sequence = KagemushaWalletUInt128V1(-1, -1)
        val same = KagemushaWalletUInt128V1(-1, -1)
        val progress = KagemushaWalletCollectionStatusV1.Progress(sequence)
        val collected = KagemushaWalletCollectionStatusV1.Collected(sequence)
        assertEquals(progress, KagemushaWalletCollectionStatusV1.Progress(same))
        assertEquals(progress.hashCode(), KagemushaWalletCollectionStatusV1.Progress(same).hashCode())
        assertEquals(collected, KagemushaWalletCollectionStatusV1.Collected(same))
        assertEquals(collected.hashCode(), KagemushaWalletCollectionStatusV1.Collected(same).hashCode())
        for (other in listOf<Any?>(null, KagemushaWalletCollectionStatusV1.Idle, collected,
            KagemushaWalletCollectionStatusV1.Progress(KagemushaWalletUInt128V1(0, -1)),
            KagemushaWalletCollectionStatusV1.Progress(KagemushaWalletUInt128V1(-1, 0)))) {
            assertEquals(false, progress.equals(other))
        }
        assertEquals(false, collected.equals(progress))
        assertEquals(false, collected.equals(KagemushaWalletCollectionStatusV1.Collected(KagemushaWalletUInt128V1(0, -1))))
        assertEquals(false, collected.equals(KagemushaWalletCollectionStatusV1.Collected(KagemushaWalletUInt128V1(-1, 0))))
        assertEquals(2, setOf<KagemushaWalletCollectionStatusV1>(progress, collected,
            KagemushaWalletCollectionStatusV1.Progress(same), KagemushaWalletCollectionStatusV1.Collected(same)).size)
        assertEquals("Progress(sequence=[REDACTED])", progress.toString())
        assertEquals("Collected(sequence=[REDACTED])", collected.toString())
    }

    @Test fun `collection carries only exact unsigned sequence and separate outcomes`() {
        for (sequence in listOf(KagemushaWalletUInt128V1(0, 0), KagemushaWalletUInt128V1(-1, -1))) {
            val input = KagemushaWalletSetupInputV1(47, amount = sequence)
            assertEquals(sequence, input.amount)
            assertContentEquals(ByteArray(32), input.identity())
            for (status in 50..52) {
                val call = KagemushaWalletCallV1(status, -1, 0, if (status == 50) 0 else sequence.low,
                    if (status == 50) 0 else sequence.high, 0, byteArrayOf())
                val expected = when (status) {
                    50 -> KagemushaWalletCollectionStatusV1.Idle
                    51 -> KagemushaWalletCollectionStatusV1.Progress(sequence)
                    else -> KagemushaWalletCollectionStatusV1.Collected(sequence)
                }
                assertEquals(expected, KagemushaWalletCollectionStatusV1.from(call, sequence))
                assertFailsWith<KagemushaWalletExceptionV1> { call.completion() }
                assertFailsWith<KagemushaWalletExceptionV1> { call.original() }
                assertFailsWith<KagemushaWalletExceptionV1> { call.unloadClaimOriginal() }
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 1, byteArrayOf()) }
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, byteArrayOf(1)) }
            }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(47, identity = ByteArray(32) { 1 }) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(47, token = 1) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(47, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(47, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(47, third = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(56) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(50, -1, 0, 1, 0, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(53, -1, 0, 0, 0, 0, byteArrayOf()) }
        val progress = KagemushaWalletCallV1(51, -1, 0, 1, 0, 0, byteArrayOf())
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCollectionStatusV1.from(progress, KagemushaWalletUInt128V1(2, 0)) }
        val fold = KagemushaWalletCallV1(9, -1, 0, 1, 0, 0, byteArrayOf())
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCollectionStatusV1.from(fold, KagemushaWalletUInt128V1(1, 0)) }
    }

    @Test fun `Unload claim requires retained identity and preserves native DATA`() {
        val id = ByteArray(32) { 7 }
        KagemushaWalletSetupInputV1(45, identity = id)
        KagemushaWalletSetupInputV1(45, identity = id, first = ByteArray(16_384) { 1 })
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(45) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(45, identity = id, first = ByteArray(16_385)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(45, identity = id, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(45, identity = id, token = 1) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(45, identity = id, amount = KagemushaWalletUInt128V1(1, 0)) }
        val bytes = ByteArray(16_384) { -1 }
        val result = KagemushaWalletCallV1(48, -1, 0, 0, 0, 0, bytes)
        val enrollment = KagemushaWalletCallV1(37, -1, 0, 1, 0, 0, byteArrayOf(1))
        assertFailsWith<KagemushaWalletExceptionV1> { enrollment.unloadClaimOriginal() }
        val projection = KagemushaWalletCallV1(47, -1, 0, 0, 0, 0, byteArrayOf(1))
        assertFailsWith<KagemushaWalletExceptionV1> { projection.unloadClaimOriginal() }
        val activation = KagemushaWalletCallV1(62, -1, 0, 2, 0, 0, ByteArray(32) { 1 })
        assertFailsWith<KagemushaWalletExceptionV1> { activation.unloadClaimOriginal() }
        assertContentEquals(bytes, result.unloadClaimOriginal())
        result.unloadClaimOriginal().fill(0)
        assertContentEquals(bytes, result.unloadClaimOriginal())
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        assertFailsWith<KagemushaWalletExceptionV1> { result.feeClaimOriginal() }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(48, -1, 0, 1, 0, 0, byteArrayOf(1)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(48, -1, 0, 0, 0, 0, ByteArray(16_385)) }
    }

    @Test fun `fee transport preserves native bytes and rejects authority fields`() {
        val retained = KagemushaWalletCallV1(31, -1, 0, 0, 0, 0, byteArrayOf(0, -1, 7))
        val beneficiary = byteArrayOf(3, 0, -1)
        val input = retained.feeClaimInput(beneficiary)
        assertEquals(26, input.selector); assertContentEquals(retained.bytes(), input.first())
        assertContentEquals(beneficiary, input.second()); beneficiary[0] = 8
        assertEquals(3, input.second()[0].toInt())
        assertFailsWith<IllegalArgumentException> { retained.feeClaimInput(byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { retained.feeClaimInput(ByteArray(16_385)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(26, identity = ByteArray(32) { 1 }, first = retained.bytes(), second = beneficiary) }
        val bytes = ByteArray(16_384) { -1 }
        val result = KagemushaWalletCallV1(36, -1, 0, 0, 0, 0, bytes)
        assertContentEquals(bytes, result.feeClaimOriginal())
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        assertFailsWith<KagemushaWalletExceptionV1> { result.original() }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(36, -1, 0, 0, 0, 0, ByteArray(16_385)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(36, -1, 0, 1, 0, 0, byteArrayOf(1)) }
    }

    @Test fun `fee and ledger originals are bounded separate from payout acknowledgement`() {
        val id = ByteArray(32) { 7 }
        KagemushaWalletSetupInputV1(20, identity = id)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(20) }
        for (selector in 21..23) {
            KagemushaWalletSetupInputV1(selector, first = byteArrayOf(1))
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id, first = byteArrayOf(1)) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(21, first = ByteArray(21_093)) }
        KagemushaWalletSetupInputV1(24)
        KagemushaWalletSetupInputV1(25, identity = id, first = byteArrayOf(1), second = byteArrayOf(2))
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(25, identity = id, first = byteArrayOf(1)) }
        for (status in 31..35) {
            val bytes = if (status == 31) ByteArray(21_092) { 1 } else if (status == 33) id else byteArrayOf()
            val result = KagemushaWalletCallV1(status, -1, 0, if (status == 33) -1 else 0, 0, 0, bytes)
            assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
            if (status == 33) assertEquals(-1L, KagemushaWalletLedgerProgressV1(result).heightBits)
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(31, -1, 0, 1, 0, 0, byteArrayOf(1)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(33, -1, 0, 0, 0, 0, id) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(35, -1, 0, 0, 0, 0, id) }
        val claim = KagemushaWalletFeeClaimV1(id, byteArrayOf(2)); id[0] = 1
        assertEquals(7, claim.payment()[0].toInt()); assertContentEquals(byteArrayOf(2), claim.request())
    }

    @Test fun `credited projection selects only Receive or Status bytes`() {
        for ((status, selector) in listOf(1 to 16, 10 to 17)) {
            val result = KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, byteArrayOf(0, -1, 1))
            val input = result.creditedInput()
            assertEquals(selector, input.selector)
            assertContentEquals(result.bytes(), input.first())
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = ByteArray(10_035)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, token = 1, first = result.bytes()) }
        }
        for (status in listOf(0, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12)) {
            val call = KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, if (status == 12) byteArrayOf(1) else byteArrayOf())
            assertFailsWith<IllegalArgumentException> { call.creditedInput() }
        }
    }
    @Test fun `background status is separate from completion with unsigned backlog`() {
        KagemushaWalletSetupInputV1(18)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(18, first = byteArrayOf(1)) }
        for (phase in 0..2) {
            val call = KagemushaWalletCallV1(29, -1, 0, -1, 2, phase or 12, byteArrayOf())
            val status = KagemushaWalletBackgroundStatusV1(call)
            assertEquals(phase, status.phase.ordinal)
            assertEquals(true, status.eligible)
            assertEquals(KagemushaWalletUInt128V1(-1, 2), status.observedBacklog)
            assertFailsWith<KagemushaWalletExceptionV1> { call.completion() }
        }
        assertEquals(null, KagemushaWalletBackgroundStatusV1(KagemushaWalletCallV1(29, -1, 0, 0, 0, 0, byteArrayOf())).observedBacklog)
        for (detail in listOf(3, 16)) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletBackgroundStatusV1(KagemushaWalletCallV1(29, -1, 0, 0, 0, detail, byteArrayOf())) }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletBackgroundStatusV1(KagemushaWalletCallV1(29, -1, 0, 1, 0, 0, byteArrayOf())) }
    }
    @Test fun `closure transport has no foreign body and separate result`() {
        KagemushaWalletSetupInputV1(19, identity = ByteArray(32) { 1 })
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(19, identity = ByteArray(32) { 1 }, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(19) }
        val valid = KagemushaWalletCallV1(30, -1, 0, 0, 0, 0, ByteArray(16_384))
        assertFailsWith<KagemushaWalletExceptionV1> { valid.completion() }
        for (count in listOf(0, 16_385)) assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(30, -1, 0, 0, 0, 0, ByteArray(count)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(30, -1, 0, 1, 0, 0, byteArrayOf(1)) }
    }
    @Test fun `activation transport has its own bound and no foreign inputs`() {
        KagemushaWalletSetupInputV1(15)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(15, token = 1) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(15, first = byteArrayOf(1)) }
        KagemushaWalletCallV1(17, -1, 0, 0, 0, 0, ByteArray(16_384))
        for (count in listOf(0, 16_385)) assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(17, -1, 0, 0, 0, 0, ByteArray(count)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(17, -1, 0, 1, 0, 0, byteArrayOf(1)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(1, -1, 0, 0, 0, 0, ByteArray(10_035)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(17, -1, 0, 0, 0, 0, byteArrayOf(1)).completion() }
    }
    @Test fun `setup fields are bounded copied and cannot inject time`() {
        val id = ByteArray(32) { 7 }
        val amount = KagemushaWalletUInt128V1(-1, -1)
        val schedule = byteArrayOf(1, 2, 3)
        val value = KagemushaWalletSetupInputV1(2, id, amount, second = schedule, third = byteArrayOf(4))
        id[0] = 4; schedule[0] = 5
        assertEquals(7, value.identity()[0].toInt())
        assertEquals(amount, value.amount)
        assertContentEquals(byteArrayOf(1, 2, 3), value.second())
        val envelope = byteArrayOf(1, 2, 3)
        for (selector in listOf(8, 9, 10, 12, 13, 14)) {
            KagemushaWalletSetupInputV1(selector, first = envelope)
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = ByteArray(10_035)) }
        }
        // The Offer setup (1) and its transport selectors (7, 11) are retired.
        for (selector in listOf(1, 7, 11)) {
            assertFailsWith<IllegalArgumentException>("$selector") { KagemushaWalletSetupInputV1(selector, first = envelope) }
            assertFailsWith<IllegalArgumentException>("$selector") { KagemushaWalletSetupInputV1(selector, id, amount) }
        }
        KagemushaWalletSetupInputV1(0)
        KagemushaWalletSetupInputV1(4)
        KagemushaWalletSetupInputV1(6, token = 1)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(6) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(6, token = 1, first = envelope) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(4, id) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id, amount, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id, amount, second = byteArrayOf(1), third = ByteArray(513)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(5, token = 0, first = envelope, second = envelope) }
    }

    @Test fun `the open Request takes only an amount and optional paired fee originals`() {
        val id = ByteArray(32) { 1 }
        val amount = KagemushaWalletUInt128V1(1, 0)
        KagemushaWalletSetupInputV1(2, id, amount)
        KagemushaWalletSetupInputV1(2, id, amount, second = ByteArray(1_024), third = ByteArray(512))
        // No first original (the retired Offer), a nonzero amount, a retry identity and paired fee originals.
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id, amount, first = byteArrayOf(7)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, ByteArray(32), amount) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id, amount, third = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, id, amount, second = ByteArray(1_025), third = byteArrayOf(1)) }
        // RequestWithFeePolicy: first the schedule envelope, second the certificates envelope, both or neither.
        KagemushaWalletSetupInputV1(39, id, amount)
        KagemushaWalletSetupInputV1(39, id, amount, first = ByteArray(10_034), second = ByteArray(10_034))
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, id, amount, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, id, amount, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletSetupInputV1(39, id, amount, first = byteArrayOf(1), second = byteArrayOf(1), third = byteArrayOf(1))
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, id, first = byteArrayOf(1), second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, ByteArray(32), amount) }
    }

    @Test fun `the payment companion takes exactly one Payment original and no identity`() {
        val payment = ByteArray(10_034) { 7 }
        val input = KagemushaWalletSetupInputV1(55, first = payment)
        payment[0] = 0
        assertEquals(7, input.first()[0].toInt())
        assertContentEquals(ByteArray(32), input.identity())
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55, first = ByteArray(10_035)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55, ByteArray(32) { 1 }, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55, amount = KagemushaWalletUInt128V1(1, 0), first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55, token = 1, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(55, first = byteArrayOf(1), second = byteArrayOf(1)) }
        assertEquals(listOf(2, 3, 4), KagemushaWalletTransportKindV1.values().map { it.tag })
    }
    @Test fun `time challenge has nonce and native token distinct from completion`() {
        val nonce = ByteArray(32) { 1 }
        val value = KagemushaWalletCallV1(13, -1, 0, 7, 0, 0, nonce)
        val owner = Any()
        val token = value.exchange(owner)
        assertEquals(7L, token.tokenFor(owner))
        nonce[0] = 2
        assertEquals(1, token.nonce()[0].toInt())
        KagemushaWalletCallV1(12, -1, 0, 0, 0, 0, byteArrayOf(1))
        KagemushaWalletCallV1(14, -1, 0, 0, 0, 0, byteArrayOf())
        for (count in listOf(0, 31, 33)) assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(13, -1, 0, 7, 0, 0, ByteArray(count)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(13, -1, 0, 0, 0, 0, ByteArray(32)) }
    }
    @Test fun `native time token can be consumed by only one racing caller`() {
        val owner = Any()
        val exchange = KagemushaWalletTimeExchangeV1(owner, 7, ByteArray(32) { 1 })
        val ready = java.util.concurrent.CountDownLatch(2)
        val start = java.util.concurrent.CountDownLatch(1)
        val accepted = java.util.concurrent.atomic.AtomicInteger()
        val refused = java.util.concurrent.atomic.AtomicInteger()
        val workers = List(2) {
            Thread {
                ready.countDown()
                start.await()
                try {
                    exchange.consume(owner)
                    accepted.incrementAndGet()
                } catch (_: IllegalArgumentException) {
                    refused.incrementAndGet()
                }
            }.apply { start() }
        }
        ready.await()
        start.countDown()
        workers.forEach { it.join() }
        assertEquals(1, accepted.get())
        assertEquals(1, refused.get())
        assertFailsWith<IllegalArgumentException> { exchange.tokenFor(owner) }
    }

}
