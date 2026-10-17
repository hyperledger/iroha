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
 * Two foreground slots and a separate fold slot bound stack reservations while allowing payment
 * arrival to preempt folding. Activity and owner close remain outside these queues. Platform
 * callbacks already permit native worker threads and prohibit same-wallet reentry.
 */
internal class KagemushaWalletNativeWorkerV1(
    private val threadFactory: (Runnable, String, Long) -> Thread = { task, name, stack ->
        Thread(null, task, name, stack)
    },
) {
    private val foreground = Semaphore(2, true)
    private val folding = Semaphore(1, true)
    private val entered = ThreadLocal<Boolean>()

    // Native collection/snapshot wait for the wallet mutex without requesting preemption.
    // They must not occupy the slots needed by a payment to cancel and join that work.
    fun <T> setup(selector: Int, action: () -> T): T = run(fold = selector == 47, action = action)
    fun <T> snapshot(action: () -> T): T = run(fold = true, action = action)

    fun <T> run(fold: Boolean = false, action: () -> T): T {
        if (entered.get() == true) return action()
        val slots = if (fold) folding else foreground
        // Once selected, a native monetary operation must complete before its caller can unwind.
        // Waiting and joining preserve interruption without abandoning an unknown native outcome.
        slots.acquireUninterruptibly()
        try {
            val task = FutureTask(Callable {
                entered.set(true)
                try { action() } finally { entered.remove() }
            })
            val worker = try {
                threadFactory(task, if (fold) "iroha-wallet-fold" else "iroha-wallet-native", STACK_BYTES)
                    .also { it.start() }
            } catch (failure: OutOfMemoryError) {
                throw KagemushaWalletNativeWorkerExceptionV1(failure)
            } catch (failure: SecurityException) {
                throw KagemushaWalletNativeWorkerExceptionV1(failure)
            }
            var interrupted = false
            try {
                while (true) {
                    try { worker.join(); break }
                    catch (_: InterruptedException) { interrupted = true }
                }
                return try { task.get() }
                catch (failure: ExecutionException) { throw checkNotNull(failure.cause) }
            } finally {
                if (interrupted) Thread.currentThread().interrupt()
            }
        } finally {
            slots.release()
        }
    }

    companion object {
        // Matches the existing native catalogue worker. This is reserved virtual stack space;
        // touched pages, rather than the entire reservation, contribute to resident memory.
        internal const val STACK_BYTES = 8L * 1024 * 1024
        internal val shared = KagemushaWalletNativeWorkerV1()
    }
}
