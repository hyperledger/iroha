// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** Unadmitted managed DATA fixtures only; no Native, keys, proof or custody invocation. */
class KagemushaWalletCurrentReviewIntegrationV1Test {
    private fun projection(selector: Int = 1): ByteArray = ByteBuffer.allocate(if(selector==1)498 else 495).order(ByteOrder.LITTLE_ENDIAN).apply {
        put(byteArrayOf(75, 87, 79, 82, 86, 49, 0, 0)); put(selector.toByte())
        repeat(4) { putLong(-1); putLong(-1) }
        put(if (selector == 1) 1.toByte() else 0.toByte())
        put(ByteArray(32) { (if (selector == 1) 7 else 0).toByte() })
        repeat(10) { index -> put(ByteArray(32) { (if(index==2 && selector==1 || index==1 && selector==8)0 else index+1).toByte() }) }
        put(4.toByte()); put(ByteArray(64) { 9 })
        putInt(if(selector==1)3 else 0)
        if(selector==1)put(byteArrayOf(0xa1.toByte(),0xb2.toByte(),0xc3.toByte()))
    }.array()

    private fun reply(bytes: ByteArray = projection(), status: Int = 18, token: Long = 19,
        high: Long = 0, detail: Int = 0, reason: Int = -1, platform: Int = 0) =
        KagemushaWalletReviewReplyV1(status, reason, platform, token, high, detail, bytes)

    @Test fun `review DATA preserves all unsigned bits and defensive byte copies`() {
        val original = projection()
        val holder = reply(original)
        original.fill(0)
        val value = holder.review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND).projection
        assertEquals(KagemushaWalletReviewedKindV1.SEND, value.kind)
        for (scalar in listOf(value.amount, value.fee, value.grossDebit, value.netDestinationAmount)) {
            assertEquals(KagemushaWalletUInt128V1(-1, -1), scalar)
        }
        value.receiverWalletId()!![0] = 0; value.destinationAccountDigest()[0] = 0; value.paymentKey()[0] = 0
        assertContentEquals(ByteArray(32) { 7 }, value.receiverWalletId())
        assertContentEquals(ByteArray(32) { 1 }, value.destinationAccountDigest())
        assertEquals(4.toByte(), value.paymentKey()[0])
        value.destinationAccountOriginal()!![0] = 0
        assertContentEquals(byteArrayOf(0xa1.toByte(),0xb2.toByte(),0xc3.toByte()),value.destinationAccountOriginal())
        assertContentEquals(ByteArray(32) { 10 }, value.artifactManifestDigest())
        assertTrue(value.toString().contains("[REDACTED]"))
        assertTrue(holder.toString().contains("[REDACTED]"))
    }
    @Test fun `wrong owner does not consume review while aliases never permit replay`() {
        val owner = Any(); val another = Any()
        val review = reply().review(owner,KagemushaWalletReviewProjectionV1.Kind.SEND)
        assertFailsWith<IllegalStateException> { review.consume(another) }
        val alias = review
        assertEquals(19L, alias.consume(owner))
        assertFailsWith<KagemushaWalletExceptionV1> { review.consume(owner) }
        assertTrue(review.toString().contains("[REDACTED]"))
    }
    @Test fun `concurrent managed consumption has exactly one winner`() {
        val owner = Any(); val review = reply().review(owner,KagemushaWalletReviewProjectionV1.Kind.SEND)
        val start = CountDownLatch(1); val executor = Executors.newFixedThreadPool(2)
        try {
            val attempts = List(2) {
                executor.submit(Callable { start.await(); runCatching { review.consume(owner) }.getOrNull() })
            }
            start.countDown()
            assertEquals(listOf(19L), attempts.mapNotNull { it.get() })
        } finally { executor.shutdownNow() }
    }
    @Test fun `review is never ordinary completion and malformed reply is refused`() {
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(18, -1, 0, 19, 0, 0, projection()) }
        for (value in listOf(reply(status = 1), reply(token = 0), reply(token = -1), reply(high = 1),
            reply(detail = 1), reply(reason = 0), reply(platform = 1))) {
            assertFailsWith<KagemushaWalletExceptionV1> { value.review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND) }
        }
        for (count in listOf(0, 490, 491, 494, 4_592)) {
            assertFailsWith<KagemushaWalletExceptionV1> { reply(ByteArray(count)).review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND) }
        }
        for ((offset, byte) in listOf(0 to 0, 8 to 2, 73 to 2, 73 to 0, 426 to 3)) {
            val changed = projection(); changed[offset] = byte.toByte()
            assertFailsWith<KagemushaWalletExceptionV1> { reply(changed).review(Any(),if(changed.getOrNull(8)==8.toByte())KagemushaWalletReviewProjectionV1.Kind.UNLOAD else KagemushaWalletReviewProjectionV1.Kind.SEND) }
        }
        val unload = reply(projection(8)).review(Any(),KagemushaWalletReviewProjectionV1.Kind.UNLOAD).projection
        assertEquals(KagemushaWalletReviewedKindV1.UNLOAD, unload.kind)
        assertEquals(null, unload.receiverWalletId())
        assertEquals(null, unload.destinationAccountOriginal())
        val changed = projection(8); changed[74] = 1
        assertFailsWith<KagemushaWalletExceptionV1> { reply(changed).review(Any(),if(changed.getOrNull(8)==8.toByte())KagemushaWalletReviewProjectionV1.Kind.UNLOAD else KagemushaWalletReviewProjectionV1.Kind.SEND) }
    }
    @Test fun `review input bounds both originals without foreign financial authority`() {
        val request = ByteArray(10_000) { 7 }
        val account = ByteArray(4_096) { 9 }
        val send = KagemushaWalletReviewInputV1(1, first = request, second = account)
        request.fill(0); account.fill(0); send.first()[0] = 0; send.second()[0] = 0
        assertEquals(7.toByte(), send.first()[0])
        assertContentEquals(ByteArray(4_096){9},send.second())
        KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(-1, -1))
        KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), ByteArray(1_024),
            KagemushaWalletUnloadChargeReviewV1.encode(ByteArray(10_000), ByteArray(4_096)))
        for (make in listOf<() -> KagemushaWalletReviewInputV1>(
            { KagemushaWalletReviewInputV1(2, first = byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(1) },
            { KagemushaWalletReviewInputV1(1, first = ByteArray(10_001), second = byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(1, KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(1, first = byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(1, second = byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(1, first = byteArrayOf(1), second = ByteArray(4_097)) },
            { KagemushaWalletReviewInputV1(8) },
            { KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), second = byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), ByteArray(1_025), byteArrayOf(1)) },
            { KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), ByteArray(10_001)) },
        )) assertFailsWith<IllegalArgumentException> { make() }
        assertTrue(send.toString().contains("[REDACTED]"))
    }
    @Test fun `invalid public review calls never dispatch Native or consume another owner`() {
        // An unadmitted managed holder for local refusal tests only. No JNI invocation.
        val wallet = KagemushaWalletV1(1)
        assertFailsWith<IllegalArgumentException> { wallet.reviewSend(byteArrayOf(),byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewSend(byteArrayOf(1),byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewSend(byteArrayOf(1),ByteArray(4_097)) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewUnload(KagemushaWalletUInt128V1(0, 0)) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewUnload(KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), null) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewUnload(KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewUnload(KagemushaWalletUInt128V1(1, 0), null, null, byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { wallet.reviewUnload(KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), byteArrayOf(1), byteArrayOf()) }
        val origin = Any(); val review = reply().review(origin,KagemushaWalletReviewProjectionV1.Kind.SEND)
        assertFailsWith<IllegalArgumentException> { wallet.executeReviewed(review, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { wallet.executeReviewed(review, ByteArray(32)) }
        assertFailsWith<IllegalStateException> { wallet.executeReviewed(review, ByteArray(32) { 1 }) }
        assertFailsWith<IllegalStateException> { wallet.cancelReview(review) }
        assertEquals(19L, review.consume(origin))
    }
}
