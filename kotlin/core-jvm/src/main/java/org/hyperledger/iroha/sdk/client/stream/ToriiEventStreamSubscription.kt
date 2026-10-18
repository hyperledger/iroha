package org.hyperledger.iroha.sdk.client.stream

import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Convenience helper that keeps a Torii SSE stream alive by reconnecting when the underlying
 * connection drops. Reconnection delays honour `retry:` hints emitted by the server and use
 * exponential backoff.
 */
class ToriiEventStreamSubscription private constructor(builder: Builder) : AutoCloseable {

    /** Factory used to open event streams (allows dependency injection in tests). */
    fun interface StreamOpener {
        fun open(listener: ToriiEventStreamListener): ToriiEventStream
    }

    private val opener: StreamOpener = builder.opener
    private val delegate: ToriiEventStreamListener = builder.listener
    private val executor: ScheduledExecutorService = builder.executor!!
    private val ownsExecutor: Boolean = builder.ownsExecutor
    private val initialBackoffMs: Long = builder.initialBackoffMs
    private val maxBackoffMs: Long = builder.maxBackoffMs
    private val started = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val nextBackoffMs = AtomicLong(builder.initialBackoffMs)
    private val lastRetryHintMs = AtomicLong(-1)
    private val connectedAtMs = AtomicLong(-1)
    private val streamGeneration = AtomicLong(0)
    private val currentStream = AtomicReference<ToriiEventStream?>(null)
    private val scheduledTask = AtomicReference<ScheduledFuture<*>?>(null)
    private val observers: List<ToriiEventStreamObserver> = builder.observers.toList()

    /** Starts the subscription, initiating the first stream immediately. */
    @Synchronized
    fun start(): ToriiEventStreamSubscription {
        check(started.compareAndSet(false, true)) { "subscription already started" }
        scheduleReconnect(0, ToriiEventStreamObserver.ReconnectReason.INITIAL)
        return this
    }

    /** Returns `true` when the subscription is actively running. */
    val isRunning: Boolean get() = started.get() && !closed.get()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        scheduledTask.getAndSet(null)?.cancel(true)
        currentStream.getAndSet(null)?.close()
        if (ownsExecutor) executor.shutdownNow()
    }

    private fun scheduleReconnect(delayMs: Long, reason: ToriiEventStreamObserver.ReconnectReason) {
        if (closed.get()) return
        val existing = scheduledTask.get()
        if (existing != null && !existing.isDone && !existing.isCancelled) return
        val clampedDelay = maxOf(0, delayMs)
        notifyReconnectScheduled(clampedDelay, reason)
        val future = executor.schedule(::openStream, clampedDelay, TimeUnit.MILLISECONDS)
        scheduledTask.set(future)
    }

    private fun notifyReconnectScheduled(delayMs: Long, reason: ToriiEventStreamObserver.ReconnectReason) {
        if (observers.isEmpty()) return
        val duration = Duration.ofMillis(maxOf(0L, delayMs))
        for (observer in observers) observer.onReconnectScheduled(duration, reason)
    }

    private fun notifyStreamOpened() { for (observer in observers) observer.onStreamOpened() }
    private fun notifyStreamClosed() { for (observer in observers) observer.onStreamClosed() }
    private fun notifyStreamFailure(error: Throwable) { for (observer in observers) observer.onStreamFailure(error) }

    private fun openStream() {
        // This task is running now; a failure reported while it opens must schedule the next one.
        scheduledTask.set(null)
        if (closed.get()) return
        connectedAtMs.set(-1)
        val generation = streamGeneration.incrementAndGet()
        val listener = ManagedListener(generation)
        try {
            val stream = opener.open(listener)
            currentStream.set(stream)
            notifyStreamOpened()
        } catch (ex: RuntimeException) {
            handleFailure(generation, ex)
        }
    }

    private fun handleFailure(generation: Long, error: Throwable) {
        if (closed.get()) return
        if (generation != streamGeneration.get()) return
        resetBackoffAfterStableConnection()
        delegate.onError(error)
        notifyStreamFailure(error)
        val retryHint = lastRetryHintMs.getAndSet(-1)
        val delay = if (retryHint >= 0) retryHint else nextBackoffMs.getAndUpdate(::computeNextBackoff)
        scheduleReconnect(delay, ToriiEventStreamObserver.ReconnectReason.STREAM_FAILURE)
    }

    /** A connection that stayed open [STABLE_CONNECTION_MS] restarts the backoff schedule. */
    private fun resetBackoffAfterStableConnection() {
        val connectedAt = connectedAtMs.getAndSet(-1)
        if (connectedAt >= 0 && System.currentTimeMillis() - connectedAt >= STABLE_CONNECTION_MS) {
            nextBackoffMs.set(initialBackoffMs)
        }
    }

    private fun computeNextBackoff(current: Long): Long {
        val doubled = minOf(maxBackoffMs, current * 2)
        return if (doubled <= 0) maxBackoffMs else doubled
    }

    private fun pickBackoffDelay(): Long {
        val retryHint = lastRetryHintMs.getAndSet(-1)
        if (retryHint >= 0) return retryHint
        return nextBackoffMs.getAndUpdate(::computeNextBackoff)
    }

    private inner class ManagedListener(private val generation: Long) : ToriiEventStreamListener {
        private fun isCurrent(): Boolean = generation == streamGeneration.get()

        override fun onOpen() {
            if (!isCurrent()) return
            connectedAtMs.set(System.currentTimeMillis())
            delegate.onOpen()
        }
        override fun onEvent(event: ServerSentEvent) { if (isCurrent()) delegate.onEvent(event) }
        override fun onRetryHint(duration: Duration) {
            if (!isCurrent()) return
            lastRetryHintMs.set(maxOf(0L, duration.toMillis()))
            delegate.onRetryHint(duration)
        }
        override fun onClosed() {
            if (!isCurrent()) return
            resetBackoffAfterStableConnection()
            delegate.onClosed()
            notifyStreamClosed()
            scheduleReconnect(pickBackoffDelay(), ToriiEventStreamObserver.ReconnectReason.STREAM_CLOSED)
        }
        override fun onError(error: Throwable) { handleFailure(generation, error) }
    }

    /** Builder for [ToriiEventStreamSubscription]. */
    class Builder internal constructor(
        internal val listener: ToriiEventStreamListener,
        internal val opener: StreamOpener
    ) {
        internal var executor: ScheduledExecutorService? = null
        internal var ownsExecutor = false
        internal var initialBackoffMs = 1_000L
        internal var maxBackoffMs = 30_000L
        internal val observers = ArrayList<ToriiEventStreamObserver>()

        fun setExecutor(executor: ScheduledExecutorService): Builder {
            this.executor = executor
            this.ownsExecutor = false
            return this
        }

        fun setInitialBackoff(duration: Duration?): Builder {
            if (duration != null) this.initialBackoffMs = maxOf(0L, duration.toMillis())
            return this
        }

        fun setMaxBackoff(duration: Duration?): Builder {
            if (duration != null) this.maxBackoffMs = maxOf(0L, duration.toMillis())
            return this
        }

        fun addObserver(observer: ToriiEventStreamObserver): Builder {
            observers.add(observer)
            return this
        }

        fun observers(values: List<ToriiEventStreamObserver>?): Builder {
            observers.clear()
            values?.forEach { addObserver(it) }
            return this
        }

        fun build(): ToriiEventStreamSubscription {
            if (executor == null) {
                executor = Executors.newSingleThreadScheduledExecutor { r ->
                    Thread(r, "torii-event-stream-subscription").apply { isDaemon = true }
                }
                ownsExecutor = true
            }
            if (initialBackoffMs == 0L) initialBackoffMs = 1_000L
            if (maxBackoffMs < initialBackoffMs) maxBackoffMs = initialBackoffMs
            return ToriiEventStreamSubscription(this)
        }
    }

    companion object {
        /** How long a connection must stay open before a later failure restarts the backoff. */
        const val STABLE_CONNECTION_MS: Long = 30_000

        /** Returns a builder that opens streams via the provided client/path/options triple. */
        @JvmStatic
        fun builder(
            client: ToriiEventStreamClient,
            path: String,
            options: ToriiEventStreamOptions?,
            listener: ToriiEventStreamListener
        ): Builder {
            val resolved = options ?: ToriiEventStreamOptions.defaultOptions()
            return Builder(listener) { delegate -> client.openSseStream(path, resolved, delegate) }
        }

        /** Returns a builder that uses a custom [StreamOpener]. */
        @JvmStatic
        fun builder(opener: StreamOpener, listener: ToriiEventStreamListener): Builder =
            Builder(listener, opener)
    }
}
