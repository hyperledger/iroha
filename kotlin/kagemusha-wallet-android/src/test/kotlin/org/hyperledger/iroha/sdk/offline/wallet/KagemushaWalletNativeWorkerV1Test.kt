package org.hyperledger.iroha.sdk.offline.wallet

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class KagemushaWalletNativeWorkerV1Test {
    private fun CountDownLatch.awaitReady() = assertTrue(await(10, TimeUnit.SECONDS))

    @Test fun `small caller uses explicitly sized worker and joins callbacks`() {
        val requested = AtomicReference<Long>()
        val worker = KagemushaWalletNativeWorkerV1 { task, name, stack ->
            requested.set(stack)
            Thread(null, task, name, stack)
        }
        val failure = AtomicReference<Throwable>()
        val completed = AtomicBoolean()
        val caller = Thread(null, {
            try {
                val original = Thread.currentThread()
                val result = worker.run {
                    assertNotSame(original, Thread.currentThread())
                    assertSame(Thread.currentThread(), worker.run { Thread.currentThread() })
                    try { 42 } finally { completed.set(true) }
                }
                assertEquals(42, result)
                assertTrue(completed.get())
            } catch (error: Throwable) { failure.set(error) }
        }, "small-native-caller", 544L * 1024)
        caller.start(); caller.join(10_000)
        assertFalse(caller.isAlive)
        failure.get()?.let { throw it }
        assertEquals(8L * 1024 * 1024, requested.get())
    }

    @Test fun `native error identity and cleanup survive worker handoff`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val expected = KagemushaWalletExceptionV1(-2, 7, 3)
        var cleanup = false
        val actual = assertThrows(KagemushaWalletExceptionV1::class.java) {
            worker.run { try { throw expected } finally { cleanup = true } }
        }
        assertSame(expected, actual)
        assertTrue(cleanup)
        assertEquals(9, worker.run { 9 })
    }

    @Test fun `fold reservation cannot consume foreground capacity`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pool = Executors.newSingleThreadExecutor()
        try {
            val fold = pool.submit<Int> { worker.run(fold = true) { entered.countDown(); release.await(); 1 } }
            entered.awaitReady()
            assertEquals(2, worker.run { 2 })
            release.countDown()
            assertEquals(1, fold.get(10, TimeUnit.SECONDS))
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `foreground concurrency is bounded and releases capacity`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val twoEntered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val thirdEntered = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(3)
        try {
            val first = (1..2).map { pool.submit<Int> { worker.run { twoEntered.countDown(); release.await(); 1 } } }
            twoEntered.awaitReady()
            val third = pool.submit<Int> { worker.run { thirdEntered.countDown(); 3 } }
            assertFalse(thirdEntered.await(100, TimeUnit.MILLISECONDS))
            release.countDown()
            first.forEach { assertEquals(1, it.get(10, TimeUnit.SECONDS)) }
            assertEquals(3, third.get(10, TimeUnit.SECONDS))
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `collection and queued snapshots leave payment preemption available`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val collectionEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val snapshotCallers = CountDownLatch(2)
        val snapshotThreads = List(2) { AtomicReference<Thread>() }
        val pool = Executors.newFixedThreadPool(4)
        try {
            val collection = pool.submit<Int> {
                worker.setup(47) { collectionEntered.countDown(); release.await(); 47 }
            }
            collectionEntered.awaitReady()
            val snapshots = snapshotThreads.map { thread ->
                pool.submit<Int> {
                    thread.set(Thread.currentThread()); snapshotCallers.countDown()
                    worker.snapshot { release.await(); 1 }
                }
            }
            snapshotCallers.awaitReady()
            // Both callers must already be waiting, either for their lane or for the mocked
            // wallet mutex. Otherwise a fast payment could race ahead and mask starvation.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (snapshotThreads.any { it.get().state != Thread.State.WAITING } && System.nanoTime() < deadline) Thread.yield()
            assertTrue(snapshotThreads.all { it.get().state == Thread.State.WAITING })
            val payment = pool.submit<Int> { worker.setup(43) { release.countDown(); 43 } }
            assertEquals(43, payment.get(10, TimeUnit.SECONDS))
            assertEquals(47, collection.get(10, TimeUnit.SECONDS))
            snapshots.forEach { assertEquals(1, it.get(10, TimeUnit.SECONDS)) }
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `snapshot enters during an explicit fold without using foreground capacity`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val foldEntered = CountDownLatch(1)
        val snapshotEntered = CountDownLatch(1)
        val foregroundEntered = CountDownLatch(2)
        val releaseFold = CountDownLatch(1)
        val releaseSnapshot = CountDownLatch(1)
        val releaseForeground = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        try {
            val fold = pool.submit<Int> {
                worker.run(fold = true) { foldEntered.countDown(); releaseFold.await(); 1 }
            }
            foldEntered.awaitReady()
            val snapshot = pool.submit<Int> {
                worker.snapshot { snapshotEntered.countDown(); releaseSnapshot.await(); 2 }
            }
            // This is the RED boundary: the old shared fold reservation cannot enter here.
            snapshotEntered.awaitReady()
            val foreground = (1..2).map {
                pool.submit<Int> {
                    worker.run { foregroundEntered.countDown(); releaseForeground.await(); 3 }
                }
            }
            foregroundEntered.awaitReady()
            releaseSnapshot.countDown()
            assertEquals(2, snapshot.get(10, TimeUnit.SECONDS))
            assertFalse(fold.isDone, "snapshot must finish while the explicit proof is still held")
            releaseForeground.countDown()
            foreground.forEach { assertEquals(3, it.get(10, TimeUnit.SECONDS)) }
            releaseFold.countDown()
            assertEquals(1, fold.get(10, TimeUnit.SECONDS))
        } finally {
            releaseFold.countDown(); releaseSnapshot.countDown(); releaseForeground.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun `only one snapshot enters while later reads wait without occupying foreground capacity`() {
        val workersCreated = AtomicInteger()
        val worker = KagemushaWalletNativeWorkerV1 { task, name, stack ->
            workersCreated.incrementAndGet()
            Thread(null, task, name, stack)
        }
        val firstEntered = CountDownLatch(1)
        val secondCallerStarted = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val releaseSecond = CountDownLatch(1)
        val secondCaller = AtomicReference<Thread>()
        val pool = Executors.newFixedThreadPool(3)
        try {
            val first = pool.submit<Int> {
                worker.snapshot { firstEntered.countDown(); releaseFirst.await(); 1 }
            }
            firstEntered.awaitReady()
            val second = pool.submit<Int> {
                secondCaller.set(Thread.currentThread()); secondCallerStarted.countDown()
                worker.snapshot { secondEntered.countDown(); releaseSecond.await(); 2 }
            }
            secondCallerStarted.awaitReady()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (secondCaller.get().state != Thread.State.WAITING && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.WAITING, secondCaller.get().state)
            // Count construction before worker.start: a delayed second worker cannot make
            // this pass merely because it has not reached its action yet.
            assertEquals(1, workersCreated.get(), "the second snapshot must not reserve another worker")
            assertEquals(1L, secondEntered.count)
            val payment = pool.submit<Int> { worker.run { 3 } }
            assertEquals(3, payment.get(10, TimeUnit.SECONDS))
            releaseFirst.countDown()
            assertEquals(1, first.get(10, TimeUnit.SECONDS))
            secondEntered.awaitReady()
            releaseSecond.countDown()
            assertEquals(2, second.get(10, TimeUnit.SECONDS))
        } finally {
            releaseFirst.countDown(); releaseSecond.countDown(); pool.shutdownNow()
        }
    }

    @Test fun `nested snapshot fold and foreground work reuse the entered worker`() {
        // Daemon test threads let the timeout report a reservation deadlock without hanging
        // the whole test JVM if a regression moves the nested-call guard after acquisition.
        val worker = KagemushaWalletNativeWorkerV1 { task, name, stack ->
            Thread(null, task, name, stack).apply { isDaemon = true }
        }
        val pool = Executors.newSingleThreadExecutor { task ->
            Thread(task, "nested-native-caller").apply { isDaemon = true }
        }
        try {
            val result = pool.submit<Int> {
                worker.snapshot {
                    val current = Thread.currentThread()
                    assertSame(current, worker.snapshot { Thread.currentThread() })
                    assertSame(current, worker.run(fold = true) { Thread.currentThread() })
                    assertSame(current, worker.setup(47) { Thread.currentThread() })
                    assertSame(current, worker.run { Thread.currentThread() })
                    4
                }
            }
            assertEquals(4, result.get(10, TimeUnit.SECONDS))
        } finally { pool.shutdownNow() }
    }

    @Test fun `interrupt cannot abandon native result and is restored`() {
        val worker = KagemushaWalletNativeWorkerV1()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val interrupted = AtomicBoolean()
        val failure = AtomicReference<Throwable>()
        val caller = Thread {
            try {
                assertEquals(7, worker.run { entered.countDown(); release.await(); 7 })
                interrupted.set(Thread.currentThread().isInterrupted)
            } catch (error: Throwable) { failure.set(error) }
            finally { returned.countDown() }
        }
        caller.start()
        try {
            entered.awaitReady(); caller.interrupt()
            assertFalse(returned.await(100, TimeUnit.MILLISECONDS))
        } finally { release.countDown() }
        returned.awaitReady(); caller.join()
        failure.get()?.let { throw it }
        assertTrue(interrupted.get())
    }

    @Test fun `worker creation refusal precedes side effects and releases capacity`() {
        val refuse = AtomicBoolean(true)
        val worker = KagemushaWalletNativeWorkerV1 { task, name, stack ->
            if (refuse.get()) throw OutOfMemoryError("worker reservation")
            Thread(null, task, name, stack)
        }
        var invoked = false
        repeat(3) {
            assertThrows(KagemushaWalletNativeWorkerExceptionV1::class.java) {
                worker.run { invoked = true }
            }
        }
        assertFalse(invoked)
        refuse.set(false)
        assertEquals(4, worker.run { 4 })
    }
}
