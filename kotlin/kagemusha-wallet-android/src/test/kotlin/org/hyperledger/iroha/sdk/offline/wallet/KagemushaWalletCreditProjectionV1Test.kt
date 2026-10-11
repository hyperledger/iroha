package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletCreditProjectionV1Test {
    private fun frame(evidence: Int = 1, archive: Int = 0, pending: Int = 0,
        original: ByteArray = byteArrayOf(9)): ByteArray = ByteBuffer.allocate(92 + original.size)
        .order(ByteOrder.LITTLE_ENDIAN).putShort(1).put(evidence.toByte()).put(archive.toByte())
        .put(pending.toByte()).put(ByteArray(3)).put(ByteArray(32) { 1 }).put(ByteArray(32) { 2 })
        .putLong(-1).putLong(Long.MIN_VALUE).putInt(original.size).put(original).array()
    private fun decode(bytes: ByteArray) = KagemushaWalletCreditProjectionV1(KagemushaWalletCallV1(47, -1, 0, 0, 0, 0, bytes))
    @Test fun `receiver original and unsigned amount are lossless defensive copies`() {
        val bytes = frame(original = ByteArray(10_000) { 9 }); val value = decode(bytes); bytes.fill(0)
        assertEquals(KagemushaWalletCreditProjectionV1.Evidence.UNFOLDED, value.evidence)
        assertEquals(KagemushaWalletCreditProjectionV1.Archive.RECEIVER, value.archive)
        assertEquals(KagemushaWalletUInt128V1(-1, Long.MIN_VALUE), value.amount)
        value.creditId().fill(0); value.paymentDigest().fill(0); value.creditedOriginal()!!.fill(0)
        assertContentEquals(ByteArray(32) { 1 }, value.creditId())
        assertContentEquals(ByteArray(32) { 2 }, value.paymentDigest())
        assertContentEquals(ByteArray(10_000) { 9 }, value.creditedOriginal())
    }
    @Test fun `payer evidence and Archive branch remain separate`() {
        for (evidence in 1..3) for (archive in 1..3) for (pending in 0..1) {
            val value = decode(frame(evidence, archive, pending, byteArrayOf()))
            assertEquals(evidence - 1, value.evidence.ordinal)
            assertEquals(archive, value.archive.ordinal)
            assertEquals(pending == 1, value.corePending)
            assertNull(value.creditedOriginal())
        }
    }
    @Test fun `malformed or ambiguous projections never become a credit verdict`() {
        assertFailsWith<KagemushaWalletExceptionV1> { decode(ByteArray(10_093)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(12, -1, 0, 0, 0, 0, ByteArray(10_001)) }
        val bad = listOf(frame(evidence = 0), frame(evidence = 4), frame(archive = 4), frame(pending = 2),
            frame(pending = 1), frame(original = byteArrayOf()), frame(archive = 1),
            frame().copyOf(91), frame() + 0, frame().also { it[0] = 2 }, frame().also { it[5] = 1 },
            frame().also { it.fill(0, 8, 40) }, frame().also { it.fill(0, 40, 72) },
            frame().also { it.fill(0, 72, 88) }, frame().also { it[88] = 2 })
        bad.forEach { assertFailsWith<KagemushaWalletExceptionV1> { decode(it) } }
        assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCreditProjectionV1(KagemushaWalletCallV1(1, -1, 0, 0, 0, 0, frame()))
        }
        assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCreditProjectionV1(KagemushaWalletCallV1(47, -1, 0, 1, 0, 0, frame()))
        }
        assertFailsWith<KagemushaWalletExceptionV1> { decode(frame()).requirePayer() }
        assertFailsWith<KagemushaWalletExceptionV1> { decode(frame(archive = 2, original = byteArrayOf())).requireReceiver() }
    }
    @Test fun `projection selectors require exact request binding and bounded originals`() {
        val id = ByteArray(32) { 1 }; val original = byteArrayOf(7)
        KagemushaWalletSetupInputV1(43, id)
        KagemushaWalletSetupInputV1(44, id, first = original)
        KagemushaWalletSetupInputV1(44, id, first = original, second = original)
        for (selector in listOf(43, 44)) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, id, token = 1, first = original) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(43, id, first = original) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(44, id) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(44, id, first = original, third = original) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(44, id, first = original, second = ByteArray(10_001)) }
    }
}
