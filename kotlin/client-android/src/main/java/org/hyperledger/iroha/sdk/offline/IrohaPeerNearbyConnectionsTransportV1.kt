package org.hyperledger.iroha.sdk.offline

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import java.io.Closeable
import java.util.concurrent.Executor
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Google Nearby P2P adapter state. IPN1 authentication remains mandatory above this rail. */
enum class IrohaPeerNearbyConnectionsStateV1 {
    IDLE,
    ADVERTISING,
    DISCOVERING,
    CONNECTING,
    VERIFICATION_REQUIRED,
    CONNECTED,
    STOPPED,
    FAILED,
}

enum class IrohaPeerNearbyConnectionsErrorV1 {
    BUSY,
    INVALID_DISCOVERY_CONTEXT,
    VERIFICATION_REJECTED,
    CONNECTION_FAILED,
    DISCONNECTED,
    INVALID_MESSAGE,
    MESSAGE_TOO_LARGE,
    TIMED_OUT,
    CANCELLED,
}

internal enum class IrohaPeerNearbyConnectionsModeV1 {
    ADVERTISING,
    DISCOVERING,
}

internal fun configureIrohaPeerNearbySchedulerV1(
    scheduler: ScheduledThreadPoolExecutor,
): ScheduledThreadPoolExecutor = scheduler.apply {
    removeOnCancelPolicy = true
    setExecuteExistingDelayedTasksAfterShutdownPolicy(false)
    setContinueExistingPeriodicTasksAfterShutdownPolicy(false)
}

@Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
private fun waitForIrohaPeerSchedulingV1(
    monitor: Any,
    isScheduling: () -> Boolean,
) {
    var interrupted = false
    while (isScheduling()) {
        try {
            (monitor as java.lang.Object).wait()
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    if (interrupted) Thread.currentThread().interrupt()
}

@Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
private fun notifyIrohaPeerSchedulingV1(monitor: Any) {
    (monitor as java.lang.Object).notifyAll()
}

/** Converts application exceptions on protocol-essential callbacks into failure. */
internal fun runIrohaPeerEssentialCallbackV1(
    onFailure: () -> Unit,
    block: () -> Unit,
) {
    try {
        block()
    } catch (_: Throwable) {
        onFailure()
    }
}

internal fun irohaPeerVerificationAdmissionErrorV1(
    digits: String,
    verificationOpen: Boolean,
): IrohaPeerNearbyConnectionsErrorV1? =
    if (!IrohaPeerNearbyVerificationCodeV1.isValid(digits) || verificationOpen) {
        IrohaPeerNearbyConnectionsErrorV1.VERIFICATION_REJECTED
    } else {
        null
    }

/**
 * Collects callback submissions while state is locked, then flushes them FIFO
 * after releasing the lifecycle monitor. Even an injected direct executor
 * therefore cannot run application code inside a transport critical section.
 */
internal class IrohaPeerNearbyLifecycleCallbackDeferrerV1 {
    private val lock = Any()
    private val deferred = ThreadLocal<MutableList<() -> Unit>?>()

    fun <T> withLock(block: () -> T): T {
        if (deferred.get() != null) return synchronized(lock) { block() }
        val submissions = mutableListOf<() -> Unit>()
        deferred.set(submissions)
        try {
            return synchronized(lock) { block() }
        } finally {
            deferred.remove()
            submissions.forEach { submission ->
                try { submission() } catch (_: Throwable) { }
            }
        }
    }

    fun defer(submission: () -> Unit): Boolean {
        val submissions = deferred.get() ?: return false
        submissions += submission
        return true
    }
}

internal enum class IrohaPeerNearbyStartDecisionV1 {
    START,
    KEEP_ACTIVE_REPLAY,
    KEEP_ACTIVE_CONFLICT,
}

internal enum class IrohaPeerNearbyTransferDecisionV1 {
    IGNORE,
    SUCCESS,
    FAILURE,
}

/** Pure lifecycle and delivery decisions shared by the Google callback adapter and tests. */
internal object IrohaPeerNearbyConnectionsReducerV1 {
    fun decideStart(
        activeMode: IrohaPeerNearbyConnectionsModeV1?,
        activeContext: IrohaPeerNearbyDiscoveryContextV1?,
        requestedMode: IrohaPeerNearbyConnectionsModeV1,
        requestedContext: IrohaPeerNearbyDiscoveryContextV1,
    ): IrohaPeerNearbyStartDecisionV1 = if (activeMode == null) {
        IrohaPeerNearbyStartDecisionV1.START
    } else if (activeMode == requestedMode && activeContext == requestedContext) {
        IrohaPeerNearbyStartDecisionV1.KEEP_ACTIVE_REPLAY
    } else {
        // Callers must explicitly stop before changing mode/context.
        IrohaPeerNearbyStartDecisionV1.KEEP_ACTIVE_CONFLICT
    }

    fun decideTransfer(status: Int): IrohaPeerNearbyTransferDecisionV1 = when (status) {
        PayloadTransferUpdate.Status.SUCCESS -> IrohaPeerNearbyTransferDecisionV1.SUCCESS
        PayloadTransferUpdate.Status.FAILURE,
        PayloadTransferUpdate.Status.CANCELED -> IrohaPeerNearbyTransferDecisionV1.FAILURE
        PayloadTransferUpdate.Status.IN_PROGRESS -> IrohaPeerNearbyTransferDecisionV1.IGNORE
        else -> IrohaPeerNearbyTransferDecisionV1.IGNORE
    }

    fun matchesAttempt(
        pendingEpoch: Long,
        callbackEpoch: Long,
        pendingPeerId: String,
        callbackPeerId: String,
    ): Boolean = pendingEpoch == callbackEpoch && pendingPeerId == callbackPeerId
}

/** A duplicate payload ID can never replace and orphan an earlier completion. */
internal class IrohaPeerNearbyPendingDeliveryRegistryV1<T> {
    private val records = LinkedHashMap<Long, T>()

    val size: Int
        @Synchronized get() = records.size

    @Synchronized
    fun add(payloadId: Long, value: T): Boolean {
        if (records.containsKey(payloadId)) return false
        records[payloadId] = value
        return true
    }

    @Synchronized
    fun removeIf(payloadId: Long, predicate: (T) -> Boolean): T? {
        val value = records[payloadId] ?: return null
        if (!predicate(value)) return null
        records.remove(payloadId)
        return value
    }

    @Synchronized
    fun drain(): List<T> {
        val values = records.values.toList()
        records.clear()
        return values
    }
}

/**
 * Linearizes callback admission with lifecycle invalidation. Application code
 * runs after releasing this lock so a callback can synchronously stop without
 * forming a gate/lifecycle ABBA. Already-admitted work may finish; work not yet
 * admitted is suppressed.
 */
internal class IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: Long = 0) {
    private val lock = Any()
    private var currentEpoch = initialEpoch

    fun update(epoch: Long) {
        synchronized(lock) {
            currentEpoch = epoch
        }
    }

    fun performIfCurrent(epoch: Long, action: () -> Unit): Boolean {
        if (!synchronized(lock) { currentEpoch == epoch }) return false
        action()
        return true
    }
}

internal class IrohaPeerNearbyWorkAdmissionV1(private val maximumPendingCount: Int) {
    private val lock = Any()
    private var pendingCountStorage = 0

    init { require(maximumPendingCount > 0) }

    val pendingCount: Int get() = synchronized(lock) { pendingCountStorage }

    fun tryAcquire(): Boolean = synchronized(lock) {
        if (pendingCountStorage >= maximumPendingCount) return@synchronized false
        pendingCountStorage += 1
        true
    }

    fun release() = synchronized(lock) {
        if (pendingCountStorage > 0) pendingCountStorage -= 1
    }

    fun reset() = synchronized(lock) { pendingCountStorage = 0 }
}

internal class IrohaPeerNearbyCallbackAdmissionV1(private val maximumPendingCount: Int) {
    private val admission = IrohaPeerNearbyWorkAdmissionV1(maximumPendingCount)
    val pendingCount: Int get() = admission.pendingCount
    fun tryAcquire(): Boolean = admission.tryAcquire()
    fun release() = admission.release()
}

/** Process-wide bounded serial fallback used only for terminal completions. */
internal class IrohaPeerNearbyCompletionFallbackV1(capacity: Int = 64) : Executor {
    private val queue = ArrayBlockingQueue<Runnable>(capacity)
    private val maximumPendingCount = capacity
    private val pendingCountStorage = AtomicInteger(0)

    val pendingCount: Int get() = pendingCountStorage.get()

    init {
        Thread({
            while (true) {
                try {
                    val next = queue.take()
                    try {
                        next.run()
                    } catch (_: Throwable) {
                        // Application completion failures are isolated to the
                        // offending callback. They must never terminate the
                        // process-wide exact-completion consumer.
                    } finally {
                        pendingCountStorage.decrementAndGet()
                    }
                } catch (_: InterruptedException) {
                    // This daemon is process-scoped and intentionally remains available.
                }
            }
        }, "iroha-peer-nearby-completions").apply {
            isDaemon = true
            start()
        }
    }

    override fun execute(command: Runnable) {
        var admitted = false
        while (!admitted) {
            val pending = pendingCountStorage.get()
            if (pending >= maximumPendingCount) break
            admitted = pendingCountStorage.compareAndSet(pending, pending + 1)
        }
        if (admitted && queue.offer(command)) return
        if (admitted) pendingCountStorage.decrementAndGet()
        runInline(command)
    }

    private fun runInline(command: Runnable) {
            // Exact + bounded + nonblocking leaves inline execution as the
            // overload fallback. This exceptional path may run on an
            // arbitrary producer context and cannot promise global FIFO order,
            // but it cannot deadlock lifecycle stop.
            try { command.run() } catch (_: Throwable) { }
    }

    companion object {
        @JvmField val SHARED = IrohaPeerNearbyCompletionFallbackV1()
    }
}

/**
 * One-runnable callback FIFO. Listener work is dropped on saturation or
 * executor rejection; terminal completions have a reserved lane and move to a
 * dedicated serial fallback if the configured executor cannot accept them.
 */
internal class IrohaPeerNearbyCallbackDispatcherV1(
    private val executor: Executor,
    private val completionFallback: Executor,
    private val maximumPendingListenerCount: Int,
    private val maximumPendingCompletionCount: Int,
) {
    private data class Pending(
        val completion: Boolean,
        val action: () -> Unit,
        val onDropped: () -> Unit,
    )
    private val lock = Any()
    private val pending = ArrayDeque<Pending>()
    private var pendingListeners = 0
    private var pendingCompletions = 0
    private var drainScheduled = false
    private var scheduling = false
    private var executorRejected = false

    init {
        require(maximumPendingListenerCount > 0)
        require(maximumPendingCompletionCount > 0)
    }

    val pendingCount: Int get() = synchronized(lock) {
        pendingListeners + pendingCompletions
    }

    fun execute(block: () -> Unit): Boolean = enqueue(false, {}, block)

    fun execute(onDropped: () -> Unit, block: () -> Unit): Boolean =
        enqueue(false, onDropped, block)

    fun executeCritical(block: () -> Unit) {
        if (!enqueue(true, {}, block)) executeFallback(block)
    }

    private fun enqueue(
        completion: Boolean,
        onDropped: () -> Unit,
        block: () -> Unit,
    ): Boolean {
        var shouldSchedule = false
        synchronized(lock) {
            waitForIrohaPeerSchedulingV1(lock) { scheduling }
            if (executorRejected) return false
            if (completion) {
                if (pendingCompletions >= maximumPendingCompletionCount) return false
                pendingCompletions += 1
            } else {
                if (pendingListeners >= maximumPendingListenerCount) return false
                pendingListeners += 1
            }
            pending.addLast(Pending(completion, block, onDropped))
            if (!drainScheduled) {
                drainScheduled = true
                scheduling = true
                shouldSchedule = true
            }
        }
        if (!shouldSchedule) return true

        return try {
            executor.execute {
                markSchedulingAccepted()
                drainOne()
            }
            markSchedulingAccepted()
            true
        } catch (_: RejectedExecutionException) {
            val completions = synchronized(lock) {
                executorRejected = true
                scheduling = false
                drainScheduled = false
                val critical = pending.filter(Pending::completion).map(Pending::action)
                pending.clear()
                pendingListeners = 0
                pendingCompletions = 0
                notifyIrohaPeerSchedulingV1(lock)
                critical
            }
            completions.forEach(::executeFallback)
            completion
        }
    }

    private fun markSchedulingAccepted() = synchronized(lock) {
        if (scheduling) {
            scheduling = false
            notifyIrohaPeerSchedulingV1(lock)
        }
    }

    private fun drainOne() {
        val next = synchronized(lock) {
            if (pending.isEmpty()) {
                drainScheduled = false
                null
            } else {
                pending.removeFirst()
            }
        } ?: return
        try {
            next.action()
        } catch (_: Throwable) {
            // One application callback cannot kill the sole drain and
            // strand every later listener or terminal completion.
        }

        val shouldReschedule = synchronized(lock) {
            if (next.completion) pendingCompletions -= 1 else pendingListeners -= 1
            if (pending.isEmpty()) {
                drainScheduled = false
                false
            } else {
                scheduling = true
                true
            }
        }
        if (!shouldReschedule) return

        try {
            executor.execute {
                markSchedulingAccepted()
                drainOne()
            }
            markSchedulingAccepted()
        } catch (_: RejectedExecutionException) {
            val dropped = synchronized(lock) {
                executorRejected = true
                scheduling = false
                drainScheduled = false
                val records = pending.toList()
                pending.clear()
                pendingListeners = 0
                pendingCompletions = 0
                notifyIrohaPeerSchedulingV1(lock)
                records
            }
            dropped.forEach {
                if (it.completion) executeFallback(it.action)
                else try { it.onDropped() } catch (_: Throwable) { }
            }
        }
    }

    private fun executeFallback(block: () -> Unit) {
        try {
            completionFallback.execute(block)
        } catch (_: RejectedExecutionException) {
            IrohaPeerNearbyCompletionFallbackV1.SHARED.execute(block)
        }
    }
}

internal class IrohaPeerNearbyWorkGenerationV1(initialGeneration: Long = 1) {
    private val value = AtomicLong(initialGeneration)
    fun current(): Long = value.get()
    fun isCurrent(generation: Long): Boolean = value.get() == generation
    fun invalidate(): Long = value.updateAndGet { if (it == Long.MAX_VALUE) 1 else it + 1 }
}

internal class IrohaPeerNearbyDropOnceV1(private val action: () -> Unit) {
    private val performed = AtomicBoolean(false)
    fun perform() {
        if (performed.compareAndSet(false, true)) action()
    }
}

internal class IrohaPeerNearbySendCompletionOnceV1(
    private val action: (IrohaPeerNearbyConnectionsErrorV1?) -> Unit,
) : IrohaPeerNearbySendCompletionV1 {
    private val performed = AtomicBoolean(false)

    override fun complete(error: IrohaPeerNearbyConnectionsErrorV1?) {
        if (performed.compareAndSet(false, true)) action(error)
    }
}

internal enum class IrohaPeerNearbyActionAdmissionV1 {
    ACCEPTED,
    FULL,
    SCHEDULER_REJECTED,
}

/** Bounded FIFO with at most one runnable submitted to the injected worker. */
internal class IrohaPeerNearbySerialActionPumpV1(
    private val maximumPendingCount: Int,
    private val schedule: (() -> Unit) -> Boolean,
) {
    private data class Pending(
        val action: () -> Unit,
        val onDropped: () -> Unit,
    )
    private val lock = Any()
    private val pending = ArrayDeque<Pending>()
    private var drainScheduled = false
    private var scheduling = false
    private var executing = false

    init { require(maximumPendingCount > 0) }

    val pendingCount: Int get() = synchronized(lock) {
        pending.size + if (executing) 1 else 0
    }

    fun enqueue(
        onDropped: () -> Unit = {},
        action: () -> Unit,
    ): IrohaPeerNearbyActionAdmissionV1 {
        var shouldSchedule = false
        synchronized(lock) {
            waitForIrohaPeerSchedulingV1(lock) { scheduling }
            if (pending.size + (if (executing) 1 else 0) >= maximumPendingCount) {
                return IrohaPeerNearbyActionAdmissionV1.FULL
            }
            pending.addLast(Pending(action, onDropped))
            if (!drainScheduled) {
                drainScheduled = true
                scheduling = true
                shouldSchedule = true
            }
        }
        if (!shouldSchedule) return IrohaPeerNearbyActionAdmissionV1.ACCEPTED

        val accepted = try {
            schedule {
                markSchedulingAccepted()
                drainOne()
            }
        } catch (_: Throwable) {
            false
        }
        if (accepted) {
            markSchedulingAccepted()
            return IrohaPeerNearbyActionAdmissionV1.ACCEPTED
        }
        synchronized(lock) {
            scheduling = false
            pending.clear()
            drainScheduled = false
            notifyIrohaPeerSchedulingV1(lock)
        }
        return IrohaPeerNearbyActionAdmissionV1.SCHEDULER_REJECTED
    }

    private fun markSchedulingAccepted() = synchronized(lock) {
        if (scheduling) {
            scheduling = false
            notifyIrohaPeerSchedulingV1(lock)
        }
    }

    fun clear(): List<() -> Unit> = synchronized(lock) {
            val actions = pending.map(Pending::onDropped)
            pending.clear()
            actions
    }

    private fun drainOne() {
        val action = synchronized(lock) {
            if (pending.isEmpty()) {
                drainScheduled = false
                null
            } else {
                executing = true
                pending.removeFirst()
            }
        } ?: return
        try {
            action.action()
        } catch (_: Throwable) {
            try { action.onDropped() } catch (_: Throwable) { }
        }

        val shouldReschedule = synchronized(lock) {
            executing = false
            if (pending.isEmpty()) {
                drainScheduled = false
                false
            } else {
                scheduling = true
                true
            }
        }
        if (!shouldReschedule) return

        val accepted = try {
            schedule {
                markSchedulingAccepted()
                drainOne()
            }
        } catch (_: Throwable) {
            false
        }
        if (accepted) {
            markSchedulingAccepted()
            return
        }
        val dropped = synchronized(lock) {
            scheduling = false
            drainScheduled = false
            val actions = pending.map(Pending::onDropped)
            pending.clear()
            notifyIrohaPeerSchedulingV1(lock)
            actions
        }
        dropped.forEach { try { it() } catch (_: Throwable) { } }
    }
}

internal enum class IrohaPeerNearbyReceiveAdmissionV1 {
    ACCEPTED,
    INACTIVE,
    FULL,
    BUDGET_EXCEEDED,
}

/** One-runnable, bounded record pump tied to the exact connection epoch and peer. */
internal class IrohaPeerNearbyReceiveCallbackPumpV1(
    private val maximumPendingCount: Int,
    private val maximumRecordsPerPhase: Int,
    private val schedule: (() -> Unit) -> Boolean,
) {
    private data class Phase(val epoch: Long, val peerId: String)
    private data class Pending(val phase: Phase, val action: () -> Unit)

    private val lock = Any()
    private val pending = ArrayDeque<Pending>()
    private var activePhase: Phase? = null
    private var drainScheduled = false
    private var scheduling = false
    private var delivering = false
    private var admittedRecordCount = 0

    init { require(maximumPendingCount > 0 && maximumRecordsPerPhase >= maximumPendingCount) }

    val pendingCount: Int get() = synchronized(lock) {
        pending.size + if (delivering) 1 else 0
    }

    fun activate(epoch: Long, peerId: String) = synchronized(lock) {
        val phase = Phase(epoch, peerId)
        if (activePhase != phase) {
            pending.clear()
            admittedRecordCount = 0
        }
        activePhase = phase
    }

    fun deactivate() = synchronized(lock) {
        activePhase = null
        pending.clear()
        admittedRecordCount = 0
    }

    fun enqueue(epoch: Long, peerId: String, action: () -> Unit):
        IrohaPeerNearbyReceiveAdmissionV1 {
        val phase = Phase(epoch, peerId)
        var shouldSchedule = false
        synchronized(lock) {
            waitForIrohaPeerSchedulingV1(lock) { scheduling }
            if (activePhase != phase) {
                return IrohaPeerNearbyReceiveAdmissionV1.INACTIVE
            }
            if (admittedRecordCount >= maximumRecordsPerPhase) {
                return IrohaPeerNearbyReceiveAdmissionV1.BUDGET_EXCEEDED
            }
            if (pending.size + (if (delivering) 1 else 0) >= maximumPendingCount) {
                return IrohaPeerNearbyReceiveAdmissionV1.FULL
            }
            pending.addLast(Pending(phase, action))
            admittedRecordCount += 1
            if (!drainScheduled) {
                drainScheduled = true
                scheduling = true
                shouldSchedule = true
            }
        }
        if (!shouldSchedule) return IrohaPeerNearbyReceiveAdmissionV1.ACCEPTED

        val accepted = try {
            schedule {
                markSchedulingAccepted()
                drain()
            }
        } catch (_: Throwable) {
            false
        }
        if (accepted) {
            markSchedulingAccepted()
            return IrohaPeerNearbyReceiveAdmissionV1.ACCEPTED
        }
        synchronized(lock) {
            scheduling = false
            pending.clear()
            drainScheduled = false
            delivering = false
            notifyIrohaPeerSchedulingV1(lock)
        }
        return IrohaPeerNearbyReceiveAdmissionV1.FULL
    }

    private fun markSchedulingAccepted() = synchronized(lock) {
        if (scheduling) {
            scheduling = false
            notifyIrohaPeerSchedulingV1(lock)
        }
    }

    private fun drain() {
        while (true) {
            val next = synchronized(lock) {
                if (pending.isEmpty()) {
                    delivering = false
                    drainScheduled = false
                    null
                } else {
                    delivering = true
                    pending.removeFirst()
                }
            } ?: return
            val current = synchronized(lock) { activePhase == next.phase }
            if (current) next.action()
            synchronized(lock) { delivering = false }
        }
    }
}

class IrohaPeerNearbyConnectionsConfigurationV1 @JvmOverloads constructor(
    val operationTimeoutMillis: Long = 90_000,
    val maximumRecordBytes: Int = IrohaPeerNearbyV1.MAXIMUM_MESSAGE_BYTES + 64,
    val maximumPendingSends: Int = 8,
    val maximumPendingWorkerActions: Int = 64,
    val maximumPendingCallbacks: Int = 16,
    val maximumPendingReceiveCallbacks: Int = 4,
    /** A payer receives five records: HELLO, AUTHENTICATION, the receiver's ask, Request and Credited. */
    val maximumReceiveRecordsPerConnection: Int = 5,
) {
    init {
        require(operationTimeoutMillis in 1..300_000)
        require(maximumRecordBytes in 1..(32 * 1_024))
        require(maximumPendingSends in 1..64)
        require(maximumPendingWorkerActions in 1..256)
        require(maximumPendingCallbacks in 1..64)
        require(maximumPendingReceiveCallbacks in 1..4)
        require(maximumReceiveRecordsPerConnection in maximumPendingReceiveCallbacks..5)
    }
}

fun interface IrohaPeerNearbyVerificationDecisionV1 {
    fun decide(accepted: Boolean)
}

fun interface IrohaPeerNearbySendCompletionV1 {
    /** `error == null` means the exact BYTES payload reached terminal SUCCESS. */
    fun complete(error: IrohaPeerNearbyConnectionsErrorV1?)
}

/**
 * Application callbacks. Verification has no default acceptance path: if the
 * listener is absent or does not answer before the timeout, pairing fails.
 */
interface IrohaPeerNearbyConnectionsListenerV1 {
    fun onStateChanged(
        state: IrohaPeerNearbyConnectionsStateV1,
        peerId: String?,
        error: IrohaPeerNearbyConnectionsErrorV1?,
    ) = Unit

    /**
     * Pair by picture: derive the picture from [authenticationDigits] with
     * [IrohaPeerNearbyPictureCodeV1.targetIndex] and never display the digits.
     */
    fun verifyPeer(
        peerId: String,
        authenticationDigits: String,
        decision: IrohaPeerNearbyVerificationDecisionV1,
    )

    /** Receives one radio record. Feed it only to the IPN1 state machine. */
    fun onRecord(peerId: String, record: ByteArray)

    /** Reports the receiver's nonzero IPD1 context selected from bootstrap discovery. */
    fun onPeerContext(peerId: String, context: IrohaPeerNearbyDiscoveryContextV1)
}

/**
 * Android Google Nearby Connections point-to-point rail for IPN1 records.
 *
 * Discovery uses the exact V1 service ID and canonical Base64URL-no-padding
 * ASCII of the 56-byte IPD1 context.
 * It accepts only BYTES payloads. A send completes only after the framework's
 * terminal `PayloadTransferUpdate.SUCCESS`, never after queue acceptance.
 */
class IrohaPeerNearbyConnectionsTransportV1 @JvmOverloads constructor(
    context: Context,
    private val configuration: IrohaPeerNearbyConnectionsConfigurationV1 =
        IrohaPeerNearbyConnectionsConfigurationV1(),
    private val callbackExecutor: Executor = mainExecutor(),
    private val worker: ScheduledExecutorService = defaultWorker(),
) : Closeable {
    private class PendingSend(
        val payloadId: Long,
        val epoch: Long,
        val peerId: String,
        val completion: IrohaPeerNearbySendCompletionV1,
        var timeout: ScheduledFuture<*>? = null,
    )

    @Volatile var listener: IrohaPeerNearbyConnectionsListenerV1? = null
    @Volatile var state: IrohaPeerNearbyConnectionsStateV1 =
        IrohaPeerNearbyConnectionsStateV1.IDLE
        private set

    private val client: ConnectionsClient = Nearby.getConnectionsClient(context.applicationContext)
    private var mode: IrohaPeerNearbyConnectionsModeV1? = null
    private var epoch = 0L
    private var localContext: IrohaPeerNearbyDiscoveryContextV1? = null
    private var activePeerId: String? = null
    private var connectionTimeout: ScheduledFuture<*>? = null
    private val pendingSends = IrohaPeerNearbyPendingDeliveryRegistryV1<PendingSend>()
    private var verificationOpen = false
    private val closed = AtomicBoolean(false)
    private val workGeneration = IrohaPeerNearbyWorkGenerationV1()
    private val callbackEpochGate = IrohaPeerNearbyCallbackEpochGateV1()
    private val lifecycleCallbacks = IrohaPeerNearbyLifecycleCallbackDeferrerV1()
    private val callbackDispatcher = IrohaPeerNearbyCallbackDispatcherV1(
        callbackExecutor,
        IrohaPeerNearbyCompletionFallbackV1.SHARED,
        configuration.maximumPendingCallbacks,
        configuration.maximumPendingSends,
    )
    private val receiveCallbackPump = IrohaPeerNearbyReceiveCallbackPumpV1(
        configuration.maximumPendingReceiveCallbacks,
        configuration.maximumReceiveRecordsPerConnection,
        { action -> dispatchEssentialCallback(::failCurrentCallbackRail, action) },
    )
    private val actionPump = IrohaPeerNearbySerialActionPumpV1(
        configuration.maximumPendingWorkerActions,
    ) { action ->
        try {
            worker.execute(action)
            true
        } catch (_: RejectedExecutionException) {
            false
        }
    }

    init {
        (worker as? ScheduledThreadPoolExecutor)?.let(::configureIrohaPeerNearbySchedulerV1)
    }

    fun startAdvertising(context: IrohaPeerNearbyDiscoveryContextV1) {
        dispatch { start(IrohaPeerNearbyConnectionsModeV1.ADVERTISING, context) }
    }

    fun startDiscovering(context: IrohaPeerNearbyDiscoveryContextV1) {
        dispatch { start(IrohaPeerNearbyConnectionsModeV1.DISCOVERING, context) }
    }

    @JvmOverloads
    fun send(record: ByteArray, completion: IrohaPeerNearbySendCompletionV1? = null) {
        if (record.isEmpty() || record.size > configuration.maximumRecordBytes) {
            complete(completion, IrohaPeerNearbyConnectionsErrorV1.MESSAGE_TOO_LARGE)
            return
        }
        val bytes = record.copyOf()
        val completionOnce = IrohaPeerNearbySendCompletionOnceV1 { error ->
            bytes.fill(0)
            complete(completion, error)
        }
        if (!dispatch(onDropped = {
            completionOnce.complete(IrohaPeerNearbyConnectionsErrorV1.CANCELLED)
        }, block = send@{
            val peerId = activePeerId
            if (state != IrohaPeerNearbyConnectionsStateV1.CONNECTED || peerId == null) {
                completionOnce.complete(IrohaPeerNearbyConnectionsErrorV1.DISCONNECTED)
                return@send
            }
            if (pendingSends.size >= configuration.maximumPendingSends) {
                completionOnce.complete(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                return@send
            }
            val payload = Payload.fromBytes(bytes)
            val send = PendingSend(
                payload.id,
                epoch,
                peerId,
                completionOnce,
            )
            if (!pendingSends.add(payload.id, send)) {
                completionOnce.complete(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                return@send
            }
            try {
                send.timeout = worker.schedule(
                    {
                        runScheduled {
                            resolveSend(
                                payload.id,
                                send.epoch,
                                peerId,
                                IrohaPeerNearbyConnectionsErrorV1.TIMED_OUT,
                                true,
                            )
                        }
                    },
                    configuration.operationTimeoutMillis,
                    TimeUnit.MILLISECONDS,
                )
            } catch (_: RejectedExecutionException) {
                resolveSend(
                    payload.id,
                    send.epoch,
                    peerId,
                    IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED,
                    true,
                )
                return@send
            }
            client.sendPayload(peerId, payload).addOnFailureListener { failure ->
                @Suppress("UNUSED_VARIABLE") val ignored = failure
                dispatch {
                    resolveSend(
                        payload.id,
                        send.epoch,
                        send.peerId,
                        IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED,
                        true,
                    )
                }
            }
        })) {
            completionOnce.complete(
                if (closed.get()) IrohaPeerNearbyConnectionsErrorV1.CANCELLED
                else IrohaPeerNearbyConnectionsErrorV1.BUSY,
            )
        }
    }

    fun stop() {
        terminateImmediately(IrohaPeerNearbyConnectionsStateV1.STOPPED, null)
    }

    fun suspend() {
        terminateImmediately(
            IrohaPeerNearbyConnectionsStateV1.FAILED,
            IrohaPeerNearbyConnectionsErrorV1.CANCELLED,
        )
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        terminateImmediately(
            IrohaPeerNearbyConnectionsStateV1.STOPPED,
            IrohaPeerNearbyConnectionsErrorV1.CANCELLED,
        )
        worker.shutdownNow()
    }

    private fun terminateImmediately(
        finalState: IrohaPeerNearbyConnectionsStateV1,
        error: IrohaPeerNearbyConnectionsErrorV1?,
        expectedGeneration: Long? = null,
    ) {
        val droppedActions = lifecycleCallbacks.withLock {
            if (expectedGeneration != null &&
                (closed.get() || !workGeneration.isCurrent(expectedGeneration))) {
                return@withLock null
            }
            workGeneration.invalidate()
            val dropped = actionPump.clear()
            receiveCallbackPump.deactivate()
            callbackEpochGate.update(Long.MIN_VALUE)
            stopLocked(finalState, error)
            dropped
        } ?: return
        droppedActions.forEach { it() }
    }

    private fun start(
        requestedMode: IrohaPeerNearbyConnectionsModeV1,
        context: IrohaPeerNearbyDiscoveryContextV1,
    ) {
        val startDecision = IrohaPeerNearbyConnectionsReducerV1.decideStart(
            mode,
            localContext,
            requestedMode,
            context,
        )
        if (startDecision != IrohaPeerNearbyStartDecisionV1.START) {
            // Lifecycle observers may repeat the same start request. Treat it
            // as idempotent, and leave a live operation untouched for a
            // conflicting request. Publishing FAILED/BUSY here previously
            // poisoned `state` while Google kept the connection active.
            return
        }
        val validRole = when (requestedMode) {
            IrohaPeerNearbyConnectionsModeV1.ADVERTISING ->
                context.role == IrohaPeerNearbyRoleV1.RECEIVER
            IrohaPeerNearbyConnectionsModeV1.DISCOVERING ->
                context.role == IrohaPeerNearbyRoleV1.SENDER
        }
        if (!validRole) {
            publish(IrohaPeerNearbyConnectionsStateV1.FAILED, null,
                IrohaPeerNearbyConnectionsErrorV1.INVALID_DISCOVERY_CONTEXT)
            return
        }
        advanceEpoch()
        mode = requestedMode
        localContext = context
        activePeerId = null
        val currentEpoch = epoch
        try {
            connectionTimeout = worker.schedule(
                {
                    runScheduled {
                        if (epoch == currentEpoch && mode != null) {
                            fail(IrohaPeerNearbyConnectionsErrorV1.TIMED_OUT)
                        }
                    }
                },
                configuration.operationTimeoutMillis,
                TimeUnit.MILLISECONDS,
            )
        } catch (_: RejectedExecutionException) {
            fail(IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED)
            return
        }
        val endpointName = context.encodeRadioDiscovery()
        when (requestedMode) {
            IrohaPeerNearbyConnectionsModeV1.ADVERTISING -> {
                publish(IrohaPeerNearbyConnectionsStateV1.ADVERTISING, null, null)
                val options = AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build()
                client.startAdvertising(
                    endpointName,
                    IrohaPeerNearbyV1.SERVICE_ID,
                    lifecycleCallback(currentEpoch),
                    options,
                ).addOnFailureListener { dispatch { if (epoch == currentEpoch) fail(
                    IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED) } }
            }
            IrohaPeerNearbyConnectionsModeV1.DISCOVERING -> {
                publish(IrohaPeerNearbyConnectionsStateV1.DISCOVERING, null, null)
                val options = DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build()
                client.startDiscovery(
                    IrohaPeerNearbyV1.SERVICE_ID,
                    discoveryCallback(currentEpoch),
                    options,
                ).addOnFailureListener { dispatch { if (epoch == currentEpoch) fail(
                    IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED) } }
            }
        }
    }

    private fun lifecycleCallback(callbackEpoch: Long) = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            if (!dispatch initiated@{
                if (callbackEpoch != epoch || !matchesContext(info.endpointName, expectedPeerRole())) {
                    client.rejectConnection(endpointId)
                    return@initiated
                }
                if (activePeerId != null && activePeerId != endpointId) {
                    client.rejectConnection(endpointId)
                    return@initiated
                }
                val digits = info.authenticationDigits
                val verificationError = irohaPeerVerificationAdmissionErrorV1(
                    digits,
                    verificationOpen,
                )
                if (verificationError != null) {
                    client.rejectConnection(endpointId)
                    fail(verificationError)
                    return@initiated
                }
                activePeerId = endpointId
                verificationOpen = true
                publish(IrohaPeerNearbyConnectionsStateV1.VERIFICATION_REQUIRED, endpointId, null)
                val callback = listener
                if (callback == null) {
                    decideVerification(callbackEpoch, endpointId, false)
                    return@initiated
                }
                val once = AtomicBoolean(false)
                if (!dispatchEssentialCallback(
                    onDropped = {
                        dispatch {
                            decideVerification(callbackEpoch, endpointId, false)
                        }
                    },
                    block = {
                    callbackEpochGate.performIfCurrent(callbackEpoch) {
                        runIrohaPeerEssentialCallbackV1(onFailure = {
                            if (once.compareAndSet(false, true)) {
                                dispatch {
                                    decideVerification(callbackEpoch, endpointId, false)
                                }
                            }
                        }) {
                            callback.verifyPeer(
                                endpointId,
                                digits,
                                IrohaPeerNearbyVerificationDecisionV1 { accepted ->
                                    if (once.compareAndSet(false, true)) {
                                        dispatch {
                                            decideVerification(callbackEpoch, endpointId, accepted)
                                        }
                                    }
                                },
                            )
                        }
                    }
                })) {
                    decideVerification(callbackEpoch, endpointId, false)
                }
            }) client.rejectConnection(endpointId)
        }

        override fun onConnectionResult(endpointId: String, resolution: ConnectionResolution) {
            dispatch result@{
                if (callbackEpoch != epoch || activePeerId != endpointId) return@result
                if (resolution.status.isSuccess) {
                    verificationOpen = false
                    client.stopAdvertising()
                    client.stopDiscovery()
                    receiveCallbackPump.activate(callbackEpoch, endpointId)
                    if (!publish(IrohaPeerNearbyConnectionsStateV1.CONNECTED, endpointId, null)) {
                        fail(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                        return@result
                    }
                    connectionTimeout?.cancel(false)
                    connectionTimeout = null
                } else {
                    fail(IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED)
                }
            }
        }

        override fun onDisconnected(endpointId: String) {
            dispatch received@{
                if (callbackEpoch == epoch && activePeerId == endpointId) {
                    fail(IrohaPeerNearbyConnectionsErrorV1.DISCONNECTED)
                }
            }
        }
    }

    private fun discoveryCallback(callbackEpoch: Long) = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            dispatch action@{
                if (callbackEpoch != epoch ||
                    mode != IrohaPeerNearbyConnectionsModeV1.DISCOVERING ||
                    activePeerId != null ||
                    info.serviceId != IrohaPeerNearbyV1.SERVICE_ID) return@action
                val remote = decodeContextRecord(info.endpointName) ?: return@action
                val currentLocal = localContext ?: return@action
                val selectedLocal = IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(
                    currentLocal,
                    remote,
                    IrohaPeerNearbyRoleV1.RECEIVER,
                ) ?: return@action
                localContext = selectedLocal
                activePeerId = endpointId
                val callback = listener
                if (callback == null) {
                    fail(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                    return@action
                }
                if (!dispatchEssentialCallback(
                    onDropped = { failEssentialCallback(callbackEpoch, endpointId) },
                    block = {
                    callbackEpochGate.performIfCurrent(callbackEpoch) {
                        runIrohaPeerEssentialCallbackV1(
                            onFailure = { failEssentialCallback(callbackEpoch, endpointId) },
                        ) {
                            callback.onPeerContext(endpointId, remote)
                        }
                    }
                })) {
                    fail(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                    return@action
                }
                publish(IrohaPeerNearbyConnectionsStateV1.CONNECTING, endpointId, null)
                client.requestConnection(
                    selectedLocal.encodeRadioDiscovery(),
                    endpointId,
                    lifecycleCallback(callbackEpoch),
                ).addOnFailureListener { dispatch { if (epoch == callbackEpoch) fail(
                    IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED) } }
            }
        }

        override fun onEndpointLost(endpointId: String) {
            dispatch received@{
                if (callbackEpoch == epoch && activePeerId == endpointId &&
                    state == IrohaPeerNearbyConnectionsStateV1.CONNECTING) {
                    activePeerId = null
                    publish(IrohaPeerNearbyConnectionsStateV1.DISCOVERING, null, null)
                }
            }
        }
    }

    private fun payloadCallback(callbackEpoch: Long) = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            val copy = lifecycleCallbacks.withLock {
                if (closed.get() || callbackEpoch != epoch) return@withLock null
                if (activePeerId != endpointId ||
                    state != IrohaPeerNearbyConnectionsStateV1.CONNECTED ||
                    payload.type != Payload.Type.BYTES) {
                    fail(IrohaPeerNearbyConnectionsErrorV1.INVALID_MESSAGE)
                    return@withLock null
                }
                val bytes = payload.asBytes()
                if (bytes == null || bytes.isEmpty() || bytes.size > configuration.maximumRecordBytes) {
                    fail(if (bytes != null && bytes.size > configuration.maximumRecordBytes)
                        IrohaPeerNearbyConnectionsErrorV1.MESSAGE_TOO_LARGE
                    else IrohaPeerNearbyConnectionsErrorV1.INVALID_MESSAGE)
                    return@withLock null
                }
                bytes.copyOf()
            } ?: return
            when (receiveCallbackPump.enqueue(callbackEpoch, endpointId) {
                callbackEpochGate.performIfCurrent(callbackEpoch) {
                    val callback = listener
                    if (callback == null) {
                        failEssentialCallback(callbackEpoch, endpointId)
                    } else {
                        runIrohaPeerEssentialCallbackV1(
                            onFailure = { failEssentialCallback(callbackEpoch, endpointId) },
                        ) {
                            callback.onRecord(endpointId, copy)
                        }
                    }
                }
            }) {
                IrohaPeerNearbyReceiveAdmissionV1.ACCEPTED,
                IrohaPeerNearbyReceiveAdmissionV1.INACTIVE -> Unit
                IrohaPeerNearbyReceiveAdmissionV1.FULL,
                IrohaPeerNearbyReceiveAdmissionV1.BUDGET_EXCEEDED -> lifecycleCallbacks.withLock {
                    if (!closed.get() && callbackEpoch == epoch && activePeerId == endpointId) {
                        fail(IrohaPeerNearbyConnectionsErrorV1.BUSY)
                    }
                }
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {
            dispatch update@{
                when (IrohaPeerNearbyConnectionsReducerV1.decideTransfer(update.status)) {
                    IrohaPeerNearbyTransferDecisionV1.IGNORE -> return@update
                    IrohaPeerNearbyTransferDecisionV1.SUCCESS -> resolveSend(
                        update.payloadId,
                        callbackEpoch,
                        endpointId,
                        null,
                        false,
                    )
                    IrohaPeerNearbyTransferDecisionV1.FAILURE -> resolveSend(
                        update.payloadId,
                        callbackEpoch,
                        endpointId,
                        IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED,
                        true,
                    )
                }
            }
        }
    }

    private fun decideVerification(callbackEpoch: Long, endpointId: String, accepted: Boolean) {
        if (callbackEpoch != epoch || activePeerId != endpointId || !verificationOpen) return
        verificationOpen = false
        if (!accepted) {
            client.rejectConnection(endpointId)
            fail(IrohaPeerNearbyConnectionsErrorV1.VERIFICATION_REJECTED)
            return
        }
        client.acceptConnection(endpointId, payloadCallback(callbackEpoch)).addOnFailureListener {
            dispatch { if (epoch == callbackEpoch) fail(
                IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED) }
        }
    }

    private fun expectedPeerRole(): IrohaPeerNearbyRoleV1 = when (mode) {
        IrohaPeerNearbyConnectionsModeV1.ADVERTISING -> IrohaPeerNearbyRoleV1.SENDER
        IrohaPeerNearbyConnectionsModeV1.DISCOVERING -> IrohaPeerNearbyRoleV1.RECEIVER
        null -> throw IllegalStateException("Nearby transport is not running")
    }

    private fun matchesContext(encoded: String, role: IrohaPeerNearbyRoleV1): Boolean {
        val local = localContext ?: return false
        val remote = decodeContextRecord(encoded) ?: return false
        return IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(local, remote, role) != null
    }

    private fun resolveSend(
        payloadId: Long,
        callbackEpoch: Long,
        peerId: String,
        error: IrohaPeerNearbyConnectionsErrorV1?,
        failTransport: Boolean,
    ) {
        val pending = pendingSends.removeIf(payloadId) {
            IrohaPeerNearbyConnectionsReducerV1.matchesAttempt(
                it.epoch,
                callbackEpoch,
                it.peerId,
                peerId,
            )
        } ?: return
        pending.timeout?.cancel(false)
        if (error != null) client.cancelPayload(payloadId)
        pending.completion.complete(error)
        if (failTransport) fail(error ?: IrohaPeerNearbyConnectionsErrorV1.CONNECTION_FAILED)
    }

    private fun fail(error: IrohaPeerNearbyConnectionsErrorV1) {
        workGeneration.invalidate()
        val droppedActions = actionPump.clear()
        receiveCallbackPump.deactivate()
        callbackEpochGate.update(Long.MIN_VALUE)
        stopLocked(IrohaPeerNearbyConnectionsStateV1.FAILED, error)
        droppedActions.forEach { it() }
    }

    private fun stopLocked(
        finalState: IrohaPeerNearbyConnectionsStateV1,
        error: IrohaPeerNearbyConnectionsErrorV1?,
    ) {
        if (mode == null && state == IrohaPeerNearbyConnectionsStateV1.STOPPED) return
        val pendingError = error ?: IrohaPeerNearbyConnectionsErrorV1.CANCELLED
        val sends = pendingSends.drain()
        advanceEpoch()
        connectionTimeout?.cancel(false)
        connectionTimeout = null
        verificationOpen = false
        client.stopAdvertising()
        client.stopDiscovery()
        client.stopAllEndpoints()
        localContext = null
        activePeerId = null
        mode = null
        publish(finalState, null, error)
        sends.forEach {
            it.timeout?.cancel(false)
            client.cancelPayload(it.payloadId)
            it.completion.complete(pendingError)
        }
    }

    private fun publish(
        newState: IrohaPeerNearbyConnectionsStateV1,
        peerId: String?,
        error: IrohaPeerNearbyConnectionsErrorV1?,
    ): Boolean {
        state = newState
        val callbackEpoch = epoch
        val callback = listener
        val connected = newState == IrohaPeerNearbyConnectionsStateV1.CONNECTED
        if (connected && callback == null) return false
        val block: () -> Unit = {
            callbackEpochGate.performIfCurrent(callbackEpoch) {
                runIrohaPeerEssentialCallbackV1(onFailure = {
                    if (connected && peerId != null) {
                        failEssentialCallback(callbackEpoch, peerId)
                    }
                }) {
                    callback?.onStateChanged(newState, peerId, error)
                }
            }
            Unit
        }
        return if (connected && peerId != null) {
            dispatchEssentialCallback(
                onDropped = { failEssentialCallback(callbackEpoch, peerId) },
                block = block,
            )
        } else {
            dispatchCallback(block)
        }
    }

    private fun failEssentialCallback(callbackEpoch: Long, peerId: String) {
        dispatch essential@{
            if (epoch == callbackEpoch && activePeerId == peerId) {
                fail(IrohaPeerNearbyConnectionsErrorV1.BUSY)
            }
        }
    }

    private fun complete(
        completion: IrohaPeerNearbySendCompletionV1?,
        error: IrohaPeerNearbyConnectionsErrorV1?,
    ) {
        if (completion == null) return
        val submission = {
            callbackDispatcher.executeCritical { completion.complete(error) }
        }
        if (!lifecycleCallbacks.defer(submission)) submission()
    }

    private fun advanceEpoch() {
        receiveCallbackPump.deactivate()
        epoch += 1
        if (epoch == 0L) epoch = 1
        callbackEpochGate.update(epoch)
    }

    private fun decodeContextRecord(encoded: String): IrohaPeerNearbyDiscoveryContextV1? = try {
        IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(encoded)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun dispatch(
        onDropped: () -> Unit = {},
        block: () -> Unit,
    ): Boolean {
        return lifecycleCallbacks.withLock {
            if (closed.get()) return@withLock false
            val generation = workGeneration.current()
            val dropOnce = IrohaPeerNearbyDropOnceV1(onDropped)
            val failDroppedGeneration = {
                dropOnce.perform()
                failActionGeneration(generation)
            }
            val admission = actionPump.enqueue(onDropped = failDroppedGeneration, action = {
                var dropped = false
                var failed = false
                lifecycleCallbacks.withLock {
                    if (!closed.get() && workGeneration.isCurrent(generation)) {
                        try {
                            block()
                        } catch (_: Throwable) {
                            dropped = true
                            failed = true
                        }
                    } else {
                        dropped = true
                    }
                }
                if (dropped) dropOnce.perform()
                if (failed) failActionGeneration(generation)
            })
            when (admission) {
                IrohaPeerNearbyActionAdmissionV1.ACCEPTED -> true
                IrohaPeerNearbyActionAdmissionV1.FULL,
                IrohaPeerNearbyActionAdmissionV1.SCHEDULER_REJECTED -> {
                    failActionGeneration(generation)
                    false
                }
            }
        }
    }

    private fun failActionGeneration(generation: Long) {
        terminateImmediately(
            IrohaPeerNearbyConnectionsStateV1.FAILED,
            IrohaPeerNearbyConnectionsErrorV1.BUSY,
            expectedGeneration = generation,
        )
    }

    private fun runScheduled(block: () -> Unit) {
        dispatch(block = block)
    }

    /** Listener callbacks never change executor; they may be suppressed under overload. */
    private fun dispatchCallback(block: () -> Unit): Boolean {
        if (lifecycleCallbacks.defer { callbackDispatcher.execute(block) }) return true
        return callbackDispatcher.execute(block)
    }

    private fun dispatchEssentialCallback(
        onDropped: () -> Unit,
        block: () -> Unit,
    ): Boolean {
        if (lifecycleCallbacks.defer {
            if (!callbackDispatcher.execute(onDropped, block)) onDropped()
        }) return true
        return callbackDispatcher.execute(onDropped, block)
    }

    private fun failCurrentCallbackRail() {
        val callbackEpoch = epoch
        val peerId = activePeerId ?: return
        failEssentialCallback(callbackEpoch, peerId)
    }

    companion object {
        private fun defaultWorker(): ScheduledThreadPoolExecutor =
            configureIrohaPeerNearbySchedulerV1(ScheduledThreadPoolExecutor(1))

        private fun mainExecutor(): Executor {
            val handler = Handler(Looper.getMainLooper())
            return irohaPeerPostingExecutorV1(handler::post)
        }
    }
}

internal fun irohaPeerPostingExecutorV1(post: (Runnable) -> Boolean): Executor = Executor { command ->
    if (!post(command)) {
        throw RejectedExecutionException("callback looper rejected Nearby delivery")
    }
}
