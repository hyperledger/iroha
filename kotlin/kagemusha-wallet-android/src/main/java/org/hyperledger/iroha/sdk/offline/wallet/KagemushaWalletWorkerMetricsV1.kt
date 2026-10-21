// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.util.ArrayDeque
import java.util.Collections

/** Closed worker lanes. A lane never identifies a wallet or a monetary operation. */
enum class KagemushaWalletWorkerLaneV1 { FOREGROUND, FOLD, SNAPSHOT }
/** Nested calls run on the already entered worker without acquiring or joining another thread. */
enum class KagemushaWalletWorkerPathV1 { WORKER, INLINE }
/** Return/throw observations only; RETURNED never establishes monetary completion. */
enum class KagemushaWalletWorkerOutcomeV1 { RETURNED, THREW, START_FAILED }

/** One bounded metadata record, with microseconds on the SDK's process-local monotonic clock.
 * Unentered phases are null, not measured zero. Nested durations overlap their enclosing call. */
data class KagemushaWalletWorkerRecordV1(
    val ordinal: Long,
    val lane: KagemushaWalletWorkerLaneV1,
    val path: KagemushaWalletWorkerPathV1,
    val outcome: KagemushaWalletWorkerOutcomeV1,
    val startedWorkerMicros: Long,
    val endedWorkerMicros: Long,
    val queueMicros: Long?,
    val startMicros: Long?,
    val executeMicros: Long?,
    val joinMicros: Long?,
)

/** Immutable oldest-first ring snapshot. Counters are nonnegative; exhaustion refuses observation
 * rather than reusing an ordinal. Sampling never acquires worker permits or wallet custody. */
class KagemushaWalletWorkerSnapshotV1(
    val sampledWorkerMicros: Long,
    val totalRecords: Long,
    val evictedRecords: Long,
    records: List<KagemushaWalletWorkerRecordV1>,
) {
    val schema: String get() = "iroha.kagemusha.worker-metrics.v1"
    val records: List<KagemushaWalletWorkerRecordV1> = Collections.unmodifiableList(records.toList())
}

/** Process-wide diagnostic ring, sampled explicitly at an existing application observation boundary.
 * No callback, timer, mutable enable switch or private operation data is exposed. */
object KagemushaWalletWorkerMetricsV1 {
    internal val recorder = KagemushaWalletWorkerRecorderV1()
    @JvmStatic fun snapshot(): KagemushaWalletWorkerSnapshotV1 = recorder.snapshot()
}

internal class KagemushaWalletWorkerRecorderV1(
    private val clock: () -> Long = System::nanoTime,
    initialTotal: Long = 0,
) {
    private val origin = System.nanoTime()
    // Allocate capacity before dispatch and remove the oldest before adding, so recording never
    // grows the ring. Record allocation and every append remain inside finish's isolated catch.
    private val records = ArrayDeque<KagemushaWalletWorkerRecordV1>(32)
    private var total = initialTotal
    private var invalid = initialTotal < 0

    internal fun begin(lane: KagemushaWalletWorkerLaneV1, path: KagemushaWalletWorkerPathV1): Capture? = try {
        Capture(lane, path, clock())
    } catch (_: Throwable) { markInvalid(); null }

    @Synchronized private fun markInvalid() { invalid = true }

    @Synchronized fun snapshot(): KagemushaWalletWorkerSnapshotV1 {
        check(!invalid) { "Worker diagnostics unavailable" }
        return KagemushaWalletWorkerSnapshotV1(micros(clock()), total, total - records.size, records.toList())
    }

    private fun micros(nanos: Long): Long = ((nanos - origin) / 1_000L).also { require(it >= 0) }

    internal inner class Capture(private val lane: KagemushaWalletWorkerLaneV1,
        private val path: KagemushaWalletWorkerPathV1, private val started: Long) {
        private var permit: Long? = null
        private var worker: Long? = null
        private var execution: Long? = null
        private var executed: Long? = null
        private var joined: Long? = null
        private var failedClock = false
        private fun tick(): Long? = try { clock() } catch (_: Throwable) { failedClock = true; null }
        fun acquired() { permit = tick() }
        fun workerEntered() { worker = tick() }
        fun actionEntered() { execution = tick() }
        fun actionEnded() { executed = tick() }
        fun joined() { joined = tick() }

        /** Called only after the original join, or on inline return/start failure. Every diagnostic
         * failure is isolated from the original action, result, interrupt state and permit release. */
        fun finish(outcome: KagemushaWalletWorkerOutcomeV1) {
            try {
                val ended = joined ?: tick() ?: error("Clock unavailable")
                check(!failedClock && ended >= started)
                fun duration(before: Long?, after: Long?): Long? = if (before == null || after == null) null
                    else ((after - before) / 1_000L).also { require(after >= before && it >= 0) }
                val inline = path == KagemushaWalletWorkerPathV1.INLINE
                val row = KagemushaWalletWorkerRecordV1(0, lane, path, outcome, micros(started), micros(ended),
                    if (inline) null else duration(started, permit),
                    if (inline) null else duration(permit, worker ?: ended.takeIf { outcome == KagemushaWalletWorkerOutcomeV1.START_FAILED }),
                    duration(execution, executed), if (inline) null else duration(executed, joined))
                synchronized(this@KagemushaWalletWorkerRecorderV1) {
                    if (invalid) return
                    if (total == Long.MAX_VALUE) { invalid = true; return }
                    total++
                    val numbered = row.copy(ordinal = total)
                    if (records.size == 32) records.removeFirst()
                    records.addLast(numbered)
                }
            } catch (_: Throwable) { markInvalid() }
        }
    }
}
