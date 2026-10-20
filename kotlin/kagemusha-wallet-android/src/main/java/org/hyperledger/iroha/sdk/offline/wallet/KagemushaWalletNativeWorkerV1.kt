// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.Semaphore

/** Local worker creation failed before entering Native; no wallet operation was attempted. */
class KagemushaWalletNativeWorkerExceptionV1 internal constructor(cause: Throwable) :
    IllegalStateException("KAGEMUSHA native execution worker is unavailable", cause)

/**
 * Native proof verification must not inherit an arbitrary UI/coroutine thread's small stack.
 * Two foreground slots, one fold slot and one snapshot slot bound stack reservations while
 * allowing payment arrival to preempt folding and snapshots to enter during an unlocked proof.
 * At most four workers reserve eight MiB each. Activity and owner close bypass these queues. Platform
 * callbacks already permit native worker threads and prohibit same-wallet reentry.
 */
internal class KagemushaWalletNativeWorkerV1(
    private val metrics: KagemushaWalletWorkerRecorderV1 = KagemushaWalletWorkerMetricsV1.recorder,
    private val threadFactory: (Runnable, String, Long) -> Thread = { task, name, stack ->
        Thread(null, task, name, stack)
    },
) {
    private val foreground = Semaphore(2, true)
    private val folding = Semaphore(1, true)
    private val snapshots = Semaphore(1, true)
    private val entered = ThreadLocal<Boolean>()

    // Native collection/snapshot wait for the wallet mutex without requesting preemption.
    // Neither may occupy the slots needed by a payment to cancel and join that work.
    // A separate snapshot slot also avoids waiting through an explicit fold's unlocked proof.
    fun <T> setup(selector: Int, action: () -> T): T = run(fold = selector == 47, action = action)
    fun <T> snapshot(action: () -> T): T = run(snapshots, "iroha-wallet-snapshot", KagemushaWalletWorkerLaneV1.SNAPSHOT, action)

    fun <T> run(fold: Boolean = false, action: () -> T): T =
        run(if (fold) folding else foreground, if (fold) "iroha-wallet-fold" else "iroha-wallet-native",
            if (fold) KagemushaWalletWorkerLaneV1.FOLD else KagemushaWalletWorkerLaneV1.FOREGROUND, action)

    private fun <T> run(slots: Semaphore, name: String, lane: KagemushaWalletWorkerLaneV1, action: () -> T): T {
        // Nested work already owns this worker and stack. Never acquire another reservation:
        // same-slot nesting would deadlock, and crossing slots could invert their order.
        if (entered.get() == true) {
            val observation = metrics.begin(lane, KagemushaWalletWorkerPathV1.INLINE)
            var returned = false
            observation?.actionEntered()
            try { return action().also { returned = true } }
            finally {
                observation?.actionEnded()
                observation?.finish(if (returned) KagemushaWalletWorkerOutcomeV1.RETURNED else KagemushaWalletWorkerOutcomeV1.THREW)
            }
        }
        // Once selected, a native monetary operation must complete before its caller can unwind.
        // Waiting and joining preserve interruption without abandoning an unknown native outcome.
        val observation = metrics.begin(lane, KagemushaWalletWorkerPathV1.WORKER)
        slots.acquireUninterruptibly()
        observation?.acquired()
        var outcome = KagemushaWalletWorkerOutcomeV1.START_FAILED
        var executionEntered = false // Read only after join establishes worker visibility.
        try {
            val task = FutureTask(Callable {
                observation?.workerEntered()
                entered.set(true)
                observation?.actionEntered()
                executionEntered = true
                try { action() } finally { observation?.actionEnded(); entered.remove() }
            })
            val worker = try {
                threadFactory(task, name, STACK_BYTES)
                    .also { it.start() }
            } catch (failure: OutOfMemoryError) {
                throw KagemushaWalletNativeWorkerExceptionV1(failure)
            } catch (failure: SecurityException) {
                throw KagemushaWalletNativeWorkerExceptionV1(failure)
            }
            var interrupted = false
            try {
                while (true) {
                    try { worker.join(); observation?.joined(); break }
                    catch (_: InterruptedException) { interrupted = true }
                }
                outcome = if (executionEntered) KagemushaWalletWorkerOutcomeV1.THREW else KagemushaWalletWorkerOutcomeV1.START_FAILED
                return try { task.get().also { outcome = KagemushaWalletWorkerOutcomeV1.RETURNED } }
                catch (failure: ExecutionException) { throw checkNotNull(failure.cause) }
            } finally {
                if (interrupted) Thread.currentThread().interrupt()
            }
        } finally {
            slots.release()
            observation?.finish(outcome)
        }
    }

    companion object {
        // Matches the existing native catalogue worker. This is reserved virtual stack space;
        // touched pages, rather than the entire reservation, contribute to resident memory.
        internal const val STACK_BYTES = 8L * 1024 * 1024
        internal val shared = KagemushaWalletNativeWorkerV1()
    }
}
