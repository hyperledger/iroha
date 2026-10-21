package org.hyperledger.iroha.sdk.offline.wallet

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class KagemushaWalletWorkerMetricsV1Test {
    @Test fun `joined returned and thrown work keeps actual phase boundaries and error identity`() {
        val metrics = KagemushaWalletWorkerRecorderV1()
        val worker = KagemushaWalletNativeWorkerV1(metrics)
        val original = Any()
        assertSame(original, worker.run { original })
        val poison = object : Error() {
            override val message: String get() = error("private")
            // FutureTask's existing ExecutionException constructor describes its cause.
            override fun toString(): String = "test error"
        }
        assertSame(poison, assertThrows(Error::class.java) { worker.snapshot { throw poison } })
        val report = metrics.snapshot()
        assertEquals("iroha.kagemusha.worker-metrics.v1", report.schema)
        assertEquals(2, report.totalRecords)
        assertEquals(0, report.evictedRecords)
        assertEquals(listOf(KagemushaWalletWorkerOutcomeV1.RETURNED, KagemushaWalletWorkerOutcomeV1.THREW), report.records.map { it.outcome })
        assertEquals(listOf(KagemushaWalletWorkerLaneV1.FOREGROUND, KagemushaWalletWorkerLaneV1.SNAPSHOT), report.records.map { it.lane })
        for (row in report.records) {
            assertTrue(row.startedWorkerMicros <= row.endedWorkerMicros && row.endedWorkerMicros <= report.sampledWorkerMicros)
            listOf(row.queueMicros, row.startMicros, row.executeMicros, row.joinMicros).forEach {
                assertNotNull(it); assertTrue(it!! in 0..row.endedWorkerMicros - row.startedWorkerMicros + 2)
            }
        }
        assertThrows(UnsupportedOperationException::class.java) { (report.records as MutableList).clear() }
    }

    @Test fun `nested inline work has no invented queue start or join and ring loss is visible`() {
        val metrics = KagemushaWalletWorkerRecorderV1()
        val worker = KagemushaWalletNativeWorkerV1(metrics)
        assertEquals(8, worker.run { worker.snapshot { worker.run(fold = true) { 8 } } })
        val nested = metrics.snapshot().records
        assertEquals(listOf(KagemushaWalletWorkerPathV1.INLINE, KagemushaWalletWorkerPathV1.INLINE,
            KagemushaWalletWorkerPathV1.WORKER), nested.map { it.path })
        nested.take(2).forEach { assertNull(it.queueMicros); assertNull(it.startMicros); assertNull(it.joinMicros); assertNotNull(it.executeMicros) }
        repeat(35) { worker.run { it } }
        val report = metrics.snapshot()
        assertEquals(38, report.totalRecords); assertEquals(6, report.evictedRecords)
        assertEquals((7L..38L).toList(), report.records.map { it.ordinal })
        assertEquals(3, nested.size, "Previously returned immutable snapshots do not grow")
    }

    @Test fun `thread creation refusal is startFailed and observation clock errors cannot change work`() {
        val metrics = KagemushaWalletWorkerRecorderV1()
        val failure = SecurityException("private")
        val worker = KagemushaWalletNativeWorkerV1(metrics) { _, _, _ -> throw failure }
        val actual = assertThrows(KagemushaWalletNativeWorkerExceptionV1::class.java) { worker.run { error("must not enter") } }
        assertSame(failure, actual.cause)
        val row = metrics.snapshot().records.single()
        assertEquals(KagemushaWalletWorkerOutcomeV1.START_FAILED, row.outcome)
        assertNotNull(row.queueMicros); assertNotNull(row.startMicros); assertNull(row.executeMicros); assertNull(row.joinMicros)
        val failedClock = KagemushaWalletWorkerRecorderV1({ throw AssertionError("private clock") })
        assertEquals(7, KagemushaWalletNativeWorkerV1(failedClock).run { 7 })
        assertThrows(IllegalStateException::class.java) { failedClock.snapshot() }
        val exhausted = KagemushaWalletWorkerRecorderV1(initialTotal = Long.MAX_VALUE)
        assertEquals(9, KagemushaWalletNativeWorkerV1(exhausted).run { 9 })
        assertThrows(IllegalStateException::class.java) { exhausted.snapshot() }
    }

    @Test fun `contended lane records waiting while interrupted caller still joins`() {
        val metrics = KagemushaWalletWorkerRecorderV1()
        val worker = KagemushaWalletNativeWorkerV1(metrics)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val waiting = CountDownLatch(1); val completed = CountDownLatch(1)
        val interrupted = AtomicBoolean()
        val pool = Executors.newSingleThreadExecutor()
        val first = pool.submit<Int> { worker.snapshot { entered.countDown(); release.await(); 1 } }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        val second = Thread {
            waiting.countDown()
            try { assertEquals(2, worker.snapshot { 2 }); interrupted.set(Thread.currentThread().isInterrupted) }
            finally { completed.countDown() }
        }
        try {
            second.start(); assertTrue(waiting.await(10, TimeUnit.SECONDS))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (second.state != Thread.State.WAITING && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.WAITING, second.state)
            second.interrupt()
            assertEquals(0, metrics.snapshot().totalRecords, "No unjoined row is published")
        } finally { release.countDown() }
        try {
            assertEquals(1, first.get(10, TimeUnit.SECONDS))
            assertTrue(completed.await(10, TimeUnit.SECONDS)); second.join(10_000)
            assertTrue(interrupted.get())
            assertEquals(2, metrics.snapshot().totalRecords)
            assertTrue(metrics.snapshot().records.all { it.queueMicros != null })
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `diagnostic allocation failure at every clock boundary preserves primary return and failure`() {
        for (failureAt in 1..6) for (throws in listOf(false, true)) {
            val ticks = AtomicInteger()
            val metrics = KagemushaWalletWorkerRecorderV1({
                if (ticks.incrementAndGet() == failureAt) throw OutOfMemoryError("diagnostic only")
                System.nanoTime()
            })
            val worker = KagemushaWalletNativeWorkerV1(metrics)
            val original = Any()
            val primary = IllegalArgumentException("primary")
            if (throws) assertSame(primary, assertThrows(IllegalArgumentException::class.java) { worker.run { throw primary } })
            else assertSame(original, worker.run { original })
            assertThrows(IllegalStateException::class.java) { metrics.snapshot() }
            // Failure after the operation does not leak a permit or poison subsequent primary work.
            assertSame(original, worker.run { original })
        }
    }
}
