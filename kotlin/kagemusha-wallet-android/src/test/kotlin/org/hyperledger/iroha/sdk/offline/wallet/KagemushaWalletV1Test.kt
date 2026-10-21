// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.hyperledger.iroha.sdk.testing.JvmApiInventory

/** Managed ownership/value contracts; real authenticated artifact execution is a separate gate. */
class KagemushaWalletV1Test {
    @TempDir lateinit var directory: File

    @Test fun `retained output and callback bytes are defensive and redacted`() {
        val bytes = byteArrayOf(0, -1, 0, 7)
        val result = KagemushaWalletCallV1(1, -1, 0, 7, 2, 0, bytes)
        val callback = KagemushaWalletNativeReplyV1(0, bytes = bytes)
        bytes[0] = 9
        result.bytes()[1] = 9
        callback.bytes()[1] = 9
        assertContentEquals(byteArrayOf(0, -1, 0, 7), result.bytes())
        assertContentEquals(result.bytes(), callback.bytes())
        assertTrue(result.toString().contains("[REDACTED]"))
        for (status in 0..11) {
            val value = KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, if (status == 1 || status == 10) byteArrayOf(1) else byteArrayOf())
            assertEquals(status, value.status)
            assertEquals(value, value.completion())
        }
    }
    @Test fun `malformed native output never becomes completion`() {
        for ((status, bytes) in listOf(
            1 to byteArrayOf(), 10 to byteArrayOf(), 2 to byteArrayOf(1),
            12 to byteArrayOf(), -4 to byteArrayOf(1), 1 to ByteArray(10_035),
        )) {
            val error = assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, bytes)
            }
            assertEquals(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT, error.status)
        }
        for (status in 0..11) {
            if (status != 1 && status != 10) {
                assertFailsWith<KagemushaWalletExceptionV1> {
                    KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, byteArrayOf(1))
                }
            }
        }
        assertEquals(10_034, KagemushaWalletCallV1(1, -1, 0, 0, 0, 0, ByteArray(10_034)).bytes().size)
    }
    @Test fun `native failure metadata remains distinct from a completion`() {
        val failure = KagemushaWalletCallV1(-4, 3, 5, 0, 0, 0, byteArrayOf())
        assertEquals(-4, failure.status)
        assertEquals(3, failure.reason)
        assertEquals(5, failure.platformCode)
        assertTrue(failure.bytes().isEmpty())
    }
    @Test fun `native callback reasons retain their distinction`() {
        val values = listOf(KagemushaWalletAndroidUnavailableV1.LOCKED, KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK,
            KagemushaWalletAndroidUnavailableV1.BUSY, KagemushaWalletAndroidUnavailableV1.io(5), KagemushaWalletAndroidUnavailableV1.platform(8),
            KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, KagemushaWalletAndroidUnavailableV1.PERMANENTLY_INVALIDATED)
        values.forEachIndexed { index, reason ->
            val unavailable = KagemushaWalletNativeReplyV1.unavailable(reason)
            val uncertain = KagemushaWalletNativeReplyV1.unavailable(reason, 4)
            assertEquals(index, unavailable.reason); assertEquals(reason.code, unavailable.code)
            assertEquals(2, unavailable.tag); assertEquals(4, uncertain.tag)
        }
    }
    @Test fun `original open inputs reject empty or oversized roles before native loading`() {
        val one = byteArrayOf(1)
        KagemushaWalletOpenOriginalsV1(one, one, one, one)
        for (role in 0..3) {
            val values = MutableList(4) { one }
            values[role] = ByteArray(listOf(1024, 10034, 4096, 1024)[role] + 1)
            assertFailsWith<IllegalArgumentException> { KagemushaWalletOpenOriginalsV1(values[0], values[1], values[2], values[3]) }
            values[role] = byteArrayOf()
            assertFailsWith<IllegalArgumentException> { KagemushaWalletOpenOriginalsV1(values[0], values[1], values[2], values[3]) }
        }
        val value = KagemushaWalletOpenOriginalsV1(one, one, one, one)
        one[0] = 2
        assertEquals(1, value.frames()[0][0].toInt())
        value.frames()[0][0] = 3
        assertEquals(1, value.frames()[0][0].toInt())
        assertFailsWith<IllegalArgumentException> { KagemushaWalletRuntimeV1(0, Any()) }
    }
    @Test fun `account challenge and opened handle keep fixed reply shapes`() {
        KagemushaWalletCallV1(15, -1, 0, 1, 0, 0, ByteArray(32))
        KagemushaWalletCallV1(16, -1, 0, 1, 0, 0, byteArrayOf())
        for (count in listOf(0, 31, 33)) assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(15, -1, 0, 1, 0, 0, ByteArray(count))
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(16, -1, 0, 0, 0, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(16, -1, 0, 1, 1, 0, byteArrayOf()) }
    }
    @Test fun `native API contains only opaque state machine calls`() {
        val type = JvmApiInventory.read(KagemushaWalletNativeV1::class.java)
        assertEquals(setOf("revision", "openBegin", "openFinish", "openCancel", "close", "activity", "call", "snapshot", "execute", "setup", "enrollment", "enrollmentRefusal", "review", "executeReviewed", "discardReview"), type.methods.filter { it.flags and 0x0100 != 0 }.map { it.name }.toSet())
        assertEquals(-4, KagemushaWalletExceptionV1.ARTIFACTS_UNAVAILABLE)
    }
    @Test fun `typed lifecycle inputs bound originals and preserve unsigned scalar bits`() {
        for (selector in (0..10).filter { it != 1 && it != 8 }) {
            // Only the local list install (selector 5) has no retry identity.
            val id = ByteArray(32) { if (selector == 5) 0 else 1 }
            val limits = when (selector) {
                0 -> intArrayOf(512, 256 * 1024, 0)
                2 -> intArrayOf(10_034, 1_024, 10_034)
                5 -> intArrayOf(65_536 * 34 + 512, 10_034, 0)
                6 -> intArrayOf(512, 10_034, 0)
                7 -> intArrayOf(8_192, 10_034, 0)
                9 -> intArrayOf(0, 0, 0)
                10 -> intArrayOf(10_034, 2_048, 0)
                else -> intArrayOf(1_024, 10_034, 0)
            }
            val original = limits.map { if (it == 0) byteArrayOf() else byteArrayOf(7) }
            val amount = KagemushaWalletUInt128V1(0, 0)
            val input = KagemushaWalletOperationInputV1(id, selector, amount, original[0], original[1], original[2])
            assertEquals(selector, input.selector)
            assertEquals(amount, input.amount)
            assertContentEquals(id, input.requestId())
            assertContentEquals(original[0], input.first())
            assertContentEquals(original[1], input.second())
            assertContentEquals(original[2], input.third())
            input.requestId()[0] = 0
            assertContentEquals(id, input.requestId())
            assertTrue(input.toString().contains("[REDACTED]"))
            for (index in 0..2) {
                val changed = original.toMutableList()
                changed[index] = ByteArray(limits[index] + 1)
                assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, selector, amount, changed[0], changed[1], changed[2]) }
            }
            for (bytes in original) if (bytes.isNotEmpty()) bytes[0] = 0
            if (limits[0] != 0) assertContentEquals(byteArrayOf(7), input.first())
            if (limits[1] != 0) assertContentEquals(byteArrayOf(7), input.second())
            if (limits[2] != 0) assertContentEquals(byteArrayOf(7), input.third())
        }
        val id = ByteArray(32) { 1 }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(ByteArray(32), 9) }
        assertFailsWith<IllegalArgumentException> {
            KagemushaWalletOperationInputV1(id, 5, first = byteArrayOf(1), second = byteArrayOf(1))
        }
        assertEquals(-15, KagemushaWalletExceptionV1.BLOCKED)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 10) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 11) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 8) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 8, KagemushaWalletUInt128V1(1, 0), byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 8, KagemushaWalletUInt128V1(1, 0)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletOperationInputV1(id, 1, first = byteArrayOf(1)) }
        // Selector 5 is the local blacklist install (installBlacklist), not a policy refresh.
        assertEquals(listOf(3, 4, 6, 7), KagemushaWalletRefreshKindV1.values().map { it.selector })
    }

    @Test fun `receive with companion bounds both exact originals and never accepts foreign fields`() {
        val id = ByteArray(32) { 1 }
        val payment = ByteArray(10_034) { 7 }
        val companion = ByteArray(2_048) { 9 }
        val input = KagemushaWalletOperationInputV1(id, 10, first = payment, second = companion)
        id[0] = 0; payment[0] = 0; companion[0] = 0
        input.requestId()[1] = 0; input.first()[1] = 0; input.second()[1] = 0
        assertEquals(10, input.selector)
        assertContentEquals(ByteArray(32) { 1 }, input.requestId())
        assertContentEquals(ByteArray(10_034) { 7 }, input.first())
        assertContentEquals(ByteArray(2_048) { 9 }, input.second())
        assertContentEquals(byteArrayOf(), input.third())
        val one = byteArrayOf(1)
        for (invalidId in listOf(ByteArray(31), ByteArray(32), ByteArray(33))) {
            assertFailsWith<IllegalArgumentException> {
                KagemushaWalletOperationInputV1(invalidId, 10, first = one, second = one)
            }
        }
        for ((a, b, c) in listOf(
            Triple(byteArrayOf(), one, byteArrayOf()), Triple(one, byteArrayOf(), byteArrayOf()),
            Triple(ByteArray(10_035), one, byteArrayOf()), Triple(one, ByteArray(2_049), byteArrayOf()),
            Triple(one, one, one),
        )) {
            assertFailsWith<IllegalArgumentException> {
                KagemushaWalletOperationInputV1(ByteArray(32) { 1 }, 10, first = a, second = b, third = c)
            }
        }
        for (amount in listOf(KagemushaWalletUInt128V1(1, 0), KagemushaWalletUInt128V1(0, 1), KagemushaWalletUInt128V1(-1, -1))) {
            assertFailsWith<IllegalArgumentException> {
                KagemushaWalletOperationInputV1(ByteArray(32) { 1 }, 10, amount, one, one)
            }
        }
        assertTrue(input.toString().contains("[REDACTED]"))
    }

    @Test fun `setup originals never become monetary completion or time authority`() {
        val bytes = byteArrayOf(1, 2, 3)
        val setup = KagemushaWalletCallV1(12, -1, 0, 0, 0, 0, bytes)
        bytes[0] = 9
        val first = setup.original(); first[1] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), setup.original())
        assertFailsWith<KagemushaWalletExceptionV1> { setup.completion() }
        assertFailsWith<KagemushaWalletExceptionV1> { setup.exchange(Any()) }
        assertFailsWith<KagemushaWalletExceptionV1> { setup.timeRetained() }
        assertTrue(setup.toString().contains("[REDACTED]"))
        for (reply in listOf(
            KagemushaWalletCallV1(13, -1, 0, 1, 0, 0, ByteArray(32) { 1 }),
            KagemushaWalletCallV1(14, -1, 0, 0, 0, 0, byteArrayOf()),
            KagemushaWalletCallV1(15, -1, 0, 1, 0, 0, ByteArray(32) { 1 }),
            KagemushaWalletCallV1(16, -1, 0, 1, 0, 0, byteArrayOf()),
        )) assertFailsWith<KagemushaWalletExceptionV1> { reply.completion() }
    }
    @Test fun `time challenge is exact one use and bound to its originating wallet`() {
        val owner = Any(); val another = Any(); val nonce = ByteArray(32) { 7 }
        val exchange = KagemushaWalletCallV1(13, -1, 0, 19, 0, 0, nonce).exchange(owner)
        nonce[0] = 0; exchange.nonce()[1] = 0
        assertContentEquals(ByteArray(32) { 7 }, exchange.nonce())
        assertFailsWith<IllegalArgumentException> { exchange.consume(another) }
        assertEquals(19L, exchange.tokenFor(owner))
        exchange.consume(owner)
        assertFailsWith<IllegalArgumentException> { exchange.consume(owner) }
        assertFailsWith<IllegalArgumentException> { exchange.tokenFor(owner) }
        assertTrue(exchange.toString().contains("[REDACTED]"))
    }
    @Test fun `malformed setup status payload and token cannot publish`() {
        val invalidOriginals = listOf<() -> KagemushaWalletCallV1>(
            { KagemushaWalletCallV1(12, -1, 0, 0, 0, 0, byteArrayOf()) },
            { KagemushaWalletCallV1(12, -1, 0, 1, 0, 0, byteArrayOf(1)) },
            { KagemushaWalletCallV1(12, -1, 0, 0, 0, 1, byteArrayOf(1)) },
            { KagemushaWalletCallV1(1, -1, 0, 0, 0, 0, byteArrayOf(1)) },
        )
        for (reply in invalidOriginals) assertFailsWith<KagemushaWalletExceptionV1> { reply().original() }
        val invalidChallenges = listOf<() -> KagemushaWalletCallV1>(
            { KagemushaWalletCallV1(13, -1, 0, 0, 0, 0, ByteArray(32) { 1 }) },
            { KagemushaWalletCallV1(13, -1, 0, 1, 1, 0, ByteArray(32) { 1 }) },
            { KagemushaWalletCallV1(13, -1, 0, 1, 0, 1, ByteArray(32) { 1 }) },
            { KagemushaWalletCallV1(13, -1, 0, 1, 0, 0, ByteArray(32)) },
            { KagemushaWalletCallV1(13, -1, 0, 1, 0, 0, ByteArray(31) { 1 }) },
        )
        for (reply in invalidChallenges) assertFailsWith<KagemushaWalletExceptionV1> { reply().exchange(Any()) }
        assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(14, -1, 0, 0, 0, 0, byteArrayOf(1)).timeRetained()
        }
        for ((sequence, detail) in listOf(1L to 0, 0L to 1)) {
            assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletCallV1(14, -1, 0, sequence, 0, detail, byteArrayOf()).timeRetained()
            }
            assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletCallV1(6, -1, 0, sequence, 0, detail, byteArrayOf()).idle()
            }
        }
        KagemushaWalletCallV1(14, -1, 0, 0, 0, 0, byteArrayOf()).timeRetained()
        KagemushaWalletCallV1(6, -1, 0, 0, 0, 0, byteArrayOf()).idle()
        assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(14, -1, 0, 0, 0, 0, byteArrayOf()).idle()
        }
    }
    @Test fun `setup inputs reject foreign fields and oversized originals before JNI`() {
        val id = ByteArray(32) { 1 }; val one = KagemushaWalletUInt128V1(1, 0)
        val schedule = byteArrayOf(7); val input = KagemushaWalletSetupInputV1(2, id, one, second = schedule, third = byteArrayOf(8))
        id[0] = 0; schedule[0] = 0; input.second()[0] = 0
        assertContentEquals(byteArrayOf(7), input.second()); assertEquals(1, input.identity()[0].toInt())
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(0, ByteArray(32) { 1 }) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(1, ByteArray(32) { 1 }, one) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, ByteArray(32) { 1 }, one, first = byteArrayOf(7)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, ByteArray(32) { 1 }, second = byteArrayOf(7), third = byteArrayOf(7)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, ByteArray(32) { 1 }, one, second = ByteArray(1_025), third = byteArrayOf(7)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(2, ByteArray(32) { 1 }, one, second = byteArrayOf(7), third = ByteArray(513)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(3) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(4, token = 1) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(5, token = -1, first = byteArrayOf(7), second = byteArrayOf(7)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(5, token = 1, first = byteArrayOf(7), second = byteArrayOf(7), third = byteArrayOf(7)) }
        assertEquals(-1L, KagemushaWalletSetupInputV1(2, ByteArray(32) { 1 }, KagemushaWalletUInt128V1(-1, -1)).amount.low)
        assertTrue(input.toString().contains("[REDACTED]"))
        val wallet = KagemushaWalletV1(1)
        assertFailsWith<IllegalArgumentException> {
            wallet.request(ByteArray(32) { 1 }, one, byteArrayOf(), byteArrayOf())
        }
        assertFailsWith<IllegalArgumentException> { wallet.request(ByteArray(32) { 1 }, one, byteArrayOf(7), null) }
        assertFailsWith<IllegalArgumentException> { wallet.requestWithFeePolicy(ByteArray(32) { 1 }, one, byteArrayOf(7), null) }
        assertFailsWith<IllegalArgumentException> { wallet.requestWithFeePolicy(ByteArray(32) { 1 }, one, byteArrayOf(), byteArrayOf(7)) }
    }
}
