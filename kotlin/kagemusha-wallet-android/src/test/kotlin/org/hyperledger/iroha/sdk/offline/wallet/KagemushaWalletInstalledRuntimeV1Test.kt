// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.testing.JvmApiInventory
import org.junit.jupiter.api.Test

/** Managed installation transport only; does not qualify Native signatures, sources or phones. */
class KagemushaWalletInstalledRuntimeV1Test {
    @Test fun `relocation bounds reject before native loading`() {
        for (source in listOf(byteArrayOf(), ByteArray(8193))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletInstallationOriginalsV1.relocateRegistrationSource(source, "/private") }
        }
        for (root in listOf("", "relative", "/nul\u0000root", "/" + "x".repeat(4096))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletInstallationOriginalsV1.relocateRegistrationSource(byteArrayOf(1), root) }
        }
    }
    private fun originals(values: List<ByteArray>) = KagemushaWalletInstallationOriginalsV1(
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7])

    @Test fun `all eight exact originals retain native role order and defensive copies`() {
        val values = List(8) { byteArrayOf(it.toByte(), 0, -1) }
        val retained = originals(values)
        values.forEach { it.fill(19) }
        val firstRead = retained.frames()
        firstRead.forEachIndexed { index, bytes ->
            assertContentEquals(byteArrayOf(index.toByte(), 0, -1), bytes)
            bytes.fill(23)
        }
        retained.frames().forEachIndexed { index, bytes ->
            assertContentEquals(byteArrayOf(index.toByte(), 0, -1), bytes)
        }
        assertTrue(retained.toString().contains("[REDACTED]"))
    }

    @Test fun `four signed base originals are mandatory and financial trio is all present or all absent`() {
        for (role in 0..6) {
            val values = MutableList(8) { byteArrayOf(1) }
            values[role] = byteArrayOf()
            assertFailsWith<IllegalArgumentException> { originals(values) }
        }
        for (presence in 0..7) {
            val values = MutableList(8) { byteArrayOf(1) }
            listOf(3, 4, 6).forEachIndexed { bit, role ->
                if (presence and (1 shl bit) == 0) values[role] = byteArrayOf()
            }
            if (presence == 0 || presence == 7) {
                // Retaining these bytes conveys no authentication or readiness.
                val retained = originals(values).frames()
                values.forEachIndexed { role, bytes -> assertContentEquals(bytes, retained[role]) }
            } else assertFailsWith<IllegalArgumentException> { originals(values) }
        }
    }

    @Test fun `admission attempt blocks concurrent admission`() {
        val admission = KagemushaWalletInstalledAdmissionV1 { }
        admission.start(List(4) { byteArrayOf(1) })
        assertFailsWith<IllegalStateException> { admission.start(List(4) { byteArrayOf(1) }) }
    }

    @Test fun `ordinary refusal retries only exact original frames`() {
        val admission = KagemushaWalletInstalledAdmissionV1 { }
        val original = List(4) { byteArrayOf(it.toByte(), 7) }
        admission.start(original)
        original.forEach { it.fill(99) }
        admission.failed()
        val same = List(4) { byteArrayOf(it.toByte(), 7) }
        assertFailsWith<IllegalStateException> { admission.start(List(4) { byteArrayOf(2) }) }
        admission.start(same)
        assertFailsWith<IllegalStateException> { admission.start(same) }
        admission.failed()
        admission.start(same)
        admission.completed()
        assertFailsWith<IllegalStateException> { admission.start(same) }
        assertFailsWith<IllegalStateException> { admission.failed() }
    }

    @Test fun `persisted result retry cannot switch account or intake representation`() {
        val admission = KagemushaWalletInstalledAdmissionV1 { }
        val frames = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))
        admission.start(frames)
        admission.failed()
        assertFalse(admission.canTransferToEnrollment())
        assertFailsWith<IllegalStateException> { admission.start(listOf(frames[0], byteArrayOf(4, 6))) }
        assertFailsWith<IllegalStateException> { admission.start(frames + listOf(byteArrayOf(7), byteArrayOf(8))) }
        admission.start(frames)
        admission.completed()
        assertFailsWith<IllegalStateException> { admission.start(frames) }
    }
    @Test fun `retired installed owner cannot start admission`() {
        var retired = false
        val admission = KagemushaWalletInstalledAdmissionV1 { check(!retired) { "retired" } }
        retired = true
        assertFailsWith<IllegalStateException> { admission.start(List(4) { byteArrayOf(1) }) }
    }

    @Test fun `each role is bounded before originals are retained`() {
        val bounds = intArrayOf(8 * 1024 * 1024, 2048, 128 * 1024,
            16 * 1024 * 1024 + 65536, 16 * 1024 * 1024, 64 * 1024 * 1024, 4096, 8192)
        bounds.forEachIndexed { role, bound ->
            val values = MutableList(8) { byteArrayOf(1) }
            values[role] = ByteArray(bound + 1)
            assertFailsWith<IllegalArgumentException> { originals(values) }
        }
    }

    @Test fun `native refusal is preserved and malformed handles cannot create runtime ownership`() {
        for (status in listOf(-1, -2, -3, -4, -7, Int.MIN_VALUE)) {
            assertEquals(status, assertFailsWith<KagemushaWalletExceptionV1> {
                installationRuntimeHandle(status.toLong())
            }.status)
        }
        for (invalid in listOf(0L, Int.MIN_VALUE.toLong() - 1, Long.MIN_VALUE)) {
            assertEquals(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT,
                assertFailsWith<KagemushaWalletExceptionV1> { installationRuntimeHandle(invalid) }.status)
        }
        assertEquals(1L, installationRuntimeHandle(1))
        assertEquals(Long.MAX_VALUE, installationRuntimeHandle(Long.MAX_VALUE))
    }

    @Test fun `compiled JNI declarations require the exact move-only installation corridor`() {
        val methods = JvmApiInventory.read(KagemushaWalletInstalledRuntimeNativeV1::class.java)
            .methods.filter { it.isNative }
        val expected = mapOf(
            "relocateRegistrationSource" to "([B[B)Lorg/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletCallV1;",
            "beginInstallation" to "(Lorg/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletAndroidPlatformV1;[B[B[B[B[B[B[B[B)J",
            "registerInstallation" to "(J)J",
            "closeInstallation" to "(J)I",
        )
        assertEquals(expected.size, methods.size)
        assertEquals(expected, methods.associate { it.name to it.descriptor })
        assertTrue(methods.all { it.isStatic })
    }

    @Test fun `bare exceptional cancellation really activates a cancellation observer`() {
        val result = CompletableFuture<String>()
        var observations = 0
        result.whenComplete { _, _ -> if (result.isCancelled) observations++ }
        assertTrue(result.completeExceptionally(CancellationException("ordinary producer refusal")))
        assertTrue(result.isCancelled)
        assertEquals(1, observations)
    }

    @Test fun `ordinary cancellation preserves exact failure and permits the same admission sequence`() {
        val frames = List(4) { byteArrayOf(it.toByte(), 7) }
        val admission = KagemushaWalletInstalledAdmissionV1 { }
        admission.start(frames)
        val original = CancellationException("ordinary producer refusal")
        val evidence = IllegalStateException("original diagnostic")
        original.addSuppressed(evidence)
        val result = CompletableFuture<String>()
        var observations = 0
        result.whenComplete { _, _ -> if (result.isCancelled) observations++ }
        admission.failed()
        assertTrue(completeInstalledOpenFailureV1(result, original))
        assertFalse(result.isCancelled)
        assertTrue(result.isCompletedExceptionally)
        assertEquals(0, observations)
        assertSame(original, assertFailsWith<CompletionException> { result.join() }.cause)
        assertSame(evidence, original.suppressed.single())
        admission.start(frames)
        admission.completed()
        assertFailsWith<IllegalStateException> { admission.start(frames) }
    }

    @Test fun `cancelled producer future does not cancel the returned admission future`() {
        val producer = CompletableFuture<ByteArray>()
        assertTrue(producer.cancel(false))
        val ordinary = assertFailsWith<CancellationException> { producer.join() }
        val result = CompletableFuture<String>()
        var observations = 0
        result.whenComplete { _, _ -> if (result.isCancelled) observations++ }
        assertTrue(completeInstalledOpenFailureV1(result, ordinary))
        assertFalse(result.isCancelled)
        assertEquals(0, observations)
        assertSame(ordinary, assertFailsWith<CompletionException> { result.join() }.cause)
    }

    @Test fun `explicit returned future cancellation still wins over queued ordinary refusal`() {
        val result = CompletableFuture<String>()
        var observations = 0
        result.whenComplete { _, _ -> if (result.isCancelled) observations++ }
        assertTrue(result.cancel(false))
        assertTrue(result.isCancelled)
        assertEquals(1, observations)
        assertFalse(completeInstalledOpenFailureV1(result, CancellationException("late producer refusal")))
        assertTrue(result.isCancelled)
        assertEquals(1, observations)
        assertFailsWith<CancellationException> { result.join() }
    }

    @Test fun `completed ordinary refusal cannot later become explicit cancellation`() {
        val result = CompletableFuture<String>()
        assertTrue(completeInstalledOpenFailureV1(result, CancellationException("ordinary guard refusal")))
        assertFalse(result.cancel(false))
        assertFalse(result.isCancelled)
        val other = IllegalStateException("ordinary Native refusal")
        val failed = CompletableFuture<String>()
        assertTrue(completeInstalledOpenFailureV1(failed, other))
        assertSame(other, assertFailsWith<CompletionException> { failed.join() }.cause)
    }
}
