package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletEpochSyncV1Test {
    private fun progress(epoch: Long, first: Long, last: Long): KagemushaWalletEpochProgressV1 {
        val bytes = listOf(first, last).flatMap { value -> (0..7).map { (value ushr (it * 8)).toByte() } }.toByteArray()
        return KagemushaWalletEpochProgressV1(KagemushaWalletCallV1(57, -1, 0, epoch, 0, 0, bytes))
    }
    private fun n(value: Long) = BigInteger.valueOf(value)

    @Test fun `epoch input and output are bounded DATA`() {
        KagemushaWalletSetupInputV1(52)
        KagemushaWalletSetupInputV1(53, amount = KagemushaWalletUInt128V1(-1, 0), first = ByteArray(262_144))
        for (bytes in listOf(byteArrayOf(), ByteArray(262_145))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(53, first = bytes) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(53, amount = KagemushaWalletUInt128V1(0, 1), first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(52, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(53, identity = ByteArray(32) { 1 }, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(53, first = byteArrayOf(1), second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(53, token = 1, first = byteArrayOf(1)) }
        assertEquals(BigInteger("18446744073709551615"), progress(-1, 1, -1).boundaryHeight)
        assertFailsWith<KagemushaWalletExceptionV1> { progress(0, 0, 3) }
        assertFailsWith<KagemushaWalletExceptionV1> { progress(0, 4, 3) }
        for (size in listOf(0, 15, 17)) assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(57, -1, 0, 0, 0, 0, ByteArray(size))
        }
    }

    @Test fun `sync uses native boundaries and old receipts skip transport`() {
        var selected = progress(0, 1, 3)
        val fetched = mutableListOf<BigInteger>()
        val result = synchronizeKagemushaEpochsV1(n(7), 2, Runnable {}, { selected },
            { height -> fetched.add(height); CompletableFuture.completedFuture(byteArrayOf(7)) },
            { epoch, bytes ->
                assertEquals(selected.epoch, epoch); assertContentEquals(byteArrayOf(7), bytes)
                selected = progress(epoch.toLong() + 1, selected.boundaryHeight.toLong() + 1, selected.boundaryHeight.toLong() + 3)
                selected
            }).join()
        assertEquals(listOf(n(3), n(6)), fetched); assertEquals(n(2), result.epoch)
        assertSame(selected, synchronizeKagemushaEpochsV1(n(2), 1, Runnable {}, { selected },
            { error("old receipt fetched history") }, { _, _ -> error("old receipt ingested history") }).join())
    }

    @Test fun `limits owner loss and stalled progress fail closed`() {
        var selected = progress(0, 1, 3)
        var fetched = 0
        val partial = synchronizeKagemushaEpochsV1(n(9), 1, Runnable {}, { selected },
                { fetched++; CompletableFuture.completedFuture(byteArrayOf(1)) },
                { _, _ -> selected = progress(1, 4, 6); selected }).join()
        assertEquals(1, fetched); assertEquals(n(1), partial.epoch)
        var validOwner = true
        assertFailsWith<CompletionException> {
            synchronizeKagemushaEpochsV1(n(9), 1, Runnable { check(validOwner) }, { selected },
                { validOwner = false; CompletableFuture.completedFuture(byteArrayOf(1)) },
                { _, _ -> error("owner loss ingested") }).join()
        }
        val failure = assertFailsWith<CompletionException> {
            synchronizeKagemushaEpochsV1(n(9), 1, Runnable {}, { selected },
                { CompletableFuture.completedFuture(byteArrayOf(1)) }, { _, _ -> selected }).join()
        }
        assertEquals(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT, (failure.cause as KagemushaWalletExceptionV1).status)
    }

    @Test fun `cancellation propagates without native ingestion`() {
        val request = CompletableFuture<ByteArray>()
        val result = synchronizeKagemushaEpochsV1(n(4), 1, Runnable {}, { progress(0, 1, 3) },
            { request }, { _, _ -> error("cancelled request ingested") })
        assertTrue(result.cancel(false)); assertTrue(request.isCancelled)
    }

    @Test fun `more than 64 epochs resumes from durable progress`() {
        var selected = progress(0, 1, 3)
        var fetched = 0
        fun sync() = synchronizeKagemushaEpochsV1(n(198), 64, Runnable {}, { selected },
            { height -> assertEquals(selected.boundaryHeight, height); fetched++; CompletableFuture.completedFuture(byteArrayOf(1)) },
            { epoch, _ -> selected = progress(epoch.toLong() + 1, selected.boundaryHeight.toLong() + 1, selected.boundaryHeight.toLong() + 3); selected }).join()
        assertEquals(n(64), sync().epoch); assertEquals(64, fetched); assertEquals(n(195), selected.boundaryHeight)
        assertEquals(n(65), sync().epoch); assertEquals(65, fetched); assertEquals(n(198), selected.boundaryHeight)
    }
}
