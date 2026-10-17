package org.hyperledger.iroha.sdk.client.stream

import org.hyperledger.iroha.sdk.client.ClientObserver
import org.hyperledger.iroha.sdk.client.ClientResponse
import org.hyperledger.iroha.sdk.client.CanonicalRequestSigner
import org.hyperledger.iroha.sdk.client.LocalSigningContext
import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope
import org.hyperledger.iroha.sdk.client.ToriiApiException
import org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth
import org.hyperledger.iroha.sdk.client.TransportSecurity
import org.hyperledger.iroha.sdk.client.transport.StreamingTransportExecutor
import org.hyperledger.iroha.sdk.client.transport.TransportExecutor
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.client.transport.TransportStreamResponse
import org.hyperledger.iroha.sdk.query.Filter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.LinkedHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val EVENT_STREAM_CONTENT_TYPE = "text/event-stream"
private const val DEFAULT_EVENT_NAME = "message"
private const val MAX_LINE_BYTES = 1024 * 1024
private const val MAX_EVENT_CHARS = 8 * 1024 * 1024
private const val MAX_ERROR_BODY_BYTES = 64 * 1024
private const val EVENTS_SSE_PATH = "/v1/events/sse"

/**
 * Minimal streaming client used to consume Torii server-sent event (SSE) feeds. The implementation
 * shares the same configuration surface as `HttpClientTransport`
 * so telemetry observers and authentication headers behave consistently across transports.
 */
class ToriiEventStreamClient private constructor(
    @JvmField val baseUri: URI,
    transport: TransportExecutor?,
    defaultHeaders: Map<String, String> = emptyMap(),
    observers: List<ClientObserver> = emptyList(),
    private val localSigningContext: LocalSigningContext? = null,
    private val canonicalRequestAuth: ToriiCanonicalRequestAuth? = null,
    readerExecutor: Executor? = null,
    private val allowPlaintextLoopback: Boolean = false,
) : AutoCloseable {
    private val transport = HttpTransportScope.create(transport)
    private val ownsReaderExecutor = readerExecutor == null
    private val readerExecutor = readerExecutor ?: Executors.newCachedThreadPool { task ->
        Thread(task, "iroha-sse-reader").apply { isDaemon = true }
    }
    private val lifecycleLock = Any()
    private var closed = false
    private val streams = LinkedHashSet<ActiveStream>()

    /** Cancels this client's streams; an injected backend remains application-owned. */
    override fun close() {
        val active = synchronized(lifecycleLock) {
            if (closed) return
            closed = true
            streams.toList().also { streams.clear() }
        }
        active.forEach { it.close() }
        try { transport.close() } finally {
            if (ownsReaderExecutor) (readerExecutor as ExecutorService).shutdownNow()
        }
    }

    private val defaultHeaders: Map<String, String> = defaultHeaders.toMap()
    private val observers: List<ClientObserver> = observers.toList()

    init {
        require((localSigningContext == null) == (canonicalRequestAuth == null)) {
            "localSigningContext and canonicalRequestAuth must be configured together"
        }
    }

    constructor(
        baseUri: URI,
        transport: TransportExecutor,
        defaultHeaders: Map<String, String> = emptyMap(),
        observers: List<ClientObserver> = emptyList(),
    ) : this(baseUri, transport, defaultHeaders, observers, null, null)

    /**
     * Opens the live `/v1/events/sse` feed, keeping only events matching [filter] (`null` streams
     * every visible event). The filter uses the collection-query text grammar over event fields,
     * e.g. `(EventFields.TX_HASH eq hash) and EventFields.TX_STATUS.isIn("Approved", "Rejected")`.
     */
    @JvmOverloads
    fun openEventStream(
        filter: Filter?,
        listener: ToriiEventStreamListener,
        options: ToriiEventStreamOptions = ToriiEventStreamOptions.defaultOptions(),
    ): ToriiEventStream {
        val resolved = if (filter == null) options else options.toBuilder().setFilter(filter).build()
        return openSseStream(EVENTS_SSE_PATH, resolved, listener)
    }

    /**
     * Subscribes to `/v1/events/sse` with typed events: each payload is decoded with
     * [ToriiEvent.parse] (unknown payloads arrive as [ToriiEvent.Unknown]) and a terminal
     * `stream_error` frame is reported through [ToriiEventListener.onStreamError].
     */
    @JvmOverloads
    fun subscribe(
        filter: Filter?,
        listener: ToriiEventListener,
        options: ToriiEventStreamOptions = ToriiEventStreamOptions.defaultOptions(),
    ): ToriiEventStream = openEventStream(
        filter,
        object : ToriiEventStreamListener {
            override fun onOpen() = listener.onOpen()

            override fun onEvent(event: ServerSentEvent) {
                val terminal = event.terminalStreamError()
                if (terminal != null) listener.onStreamError(terminal) else listener.onEvent(ToriiEvent.parse(event.data))
            }

            override fun onClosed() = listener.onClosed()

            override fun onError(error: Throwable) = listener.onError(error)
        },
        options,
    )

    /**
     * Opens `/v1/accounts/{accountId}/history/sse`: every account-history row of each height
     * published after the stream opens, oldest first, as [org.hyperledger.iroha.sdk.client.collections.AccountHistoryRow]s
     * (`specs/torii/streaming.md`). The feed is live-only; after
     * [AccountHistoryStreamListener.onOpen] read the first history page and deduplicate by row id.
     * [filter] narrows rows with the account-history collection grammar, e.g.
     * `Filter.field("direction").eq("incoming")`.
     */
    @JvmOverloads
    fun streamAccountHistory(
        accountId: String,
        filter: Filter?,
        listener: AccountHistoryStreamListener,
        options: ToriiEventStreamOptions = ToriiEventStreamOptions.defaultOptions(),
    ): ToriiEventStream {
        val resolved = if (filter == null) options else options.toBuilder().setFilter(filter).build()
        return openSseStream(accountHistoryStreamPath(accountId), resolved, accountHistoryFrames(listener))
    }

    /**
     * A reconnecting [streamAccountHistory]: failures, terminal stream errors and normal closes
     * reopen the stream with backoff (and Torii `retry:` hints), and
     * [AccountHistoryStreamListener.onOpen] runs for every connection so the caller re-reads the
     * first history page each time. Configure the returned builder, then `build().start()`.
     */
    @JvmOverloads
    fun accountHistorySubscription(
        accountId: String,
        filter: Filter?,
        listener: AccountHistoryStreamListener,
        options: ToriiEventStreamOptions = ToriiEventStreamOptions.defaultOptions(),
    ): ToriiEventStreamSubscription.Builder {
        val path = accountHistoryStreamPath(accountId)
        val resolved = if (filter == null) options else options.toBuilder().setFilter(filter).build()
        return ToriiEventStreamSubscription.builder(
            { delegate -> openSseStream(path, resolved, delegate) },
            accountHistoryFrames(listener),
        )
    }

    /**
     * Opens an SSE stream against `path` using the supplied options.
     *
     * Callers must close the returned `ToriiEventStream` or this client. Caller-initiated closure
     * completes the stream without a terminal listener notification. New streams are rejected
     * after this client is closed.
     *
     * When the configured transport supports streaming responses, frames are parsed as they
     * arrive; otherwise, the response body is buffered before parsing.
     */
    fun openSseStream(
        path: String?,
        options: ToriiEventStreamOptions?,
        listener: ToriiEventStreamListener,
    ): ToriiEventStream {
        synchronized(lifecycleLock) { check(!closed) { "Torii event stream client is closed" } }
        val resolved = options ?: ToriiEventStreamOptions.defaultOptions()
        val request = buildRequest(path, resolved)
        val stream = ActiveStream()
        synchronized(lifecycleLock) {
            check(!closed) { "Torii event stream client is closed" }
            streams.add(stream)
        }
        stream.completion().whenComplete { _, _ ->
            synchronized(lifecycleLock) { streams.remove(stream) }
            if (stream.completion().isCancelled) stream.close()
        }
        try {
            notifyRequest(request)
            if (stream.closed()) return stream
            if (transport is StreamingTransportExecutor) {
                val responseFuture = transport.openStream(request)
                stream.attachResponse(responseFuture)
                responseFuture.whenComplete { response, throwable ->
                    try {
                        handleStreamResponse(request, listener, stream, response, throwable)
                    } catch (failure: Exception) {
                        failStream(request, listener, stream, failure)
                    }
                }
            } else {
                val responseFuture = transport.execute(request)
                stream.attachResponse(responseFuture)
                responseFuture.whenComplete { response, throwable ->
                    try {
                        handleBufferedResponse(request, listener, stream, response, throwable)
                    } catch (failure: Exception) {
                        failStream(request, listener, stream, failure)
                    }
                }
            }
        } catch (failure: Exception) {
            failStream(request, listener, stream, failure)
        }
        return stream
    }

    private fun buildRequest(path: String?, options: ToriiEventStreamOptions): TransportRequest {
        val target = appendQueryParameters(resolvePath(path), streamQueryParameters(options))
        val headers = LinkedHashMap(defaultHeaders)
        headers.putIfAbsent("Accept", EVENT_STREAM_CONTENT_TYPE)
        headers.putIfAbsent("Cache-Control", "no-cache")
        headers.putIfAbsent("Connection", "keep-alive")
        options.headers.forEach { (k, v) -> headers[k] = v }
        rejectUnsupportedCanonicalResume(path, target, headers)
        requireCanonicalHeadersUnset(headers)
        canonicalRequestAuth?.let { auth ->
            buildCanonicalHeaders(target, localSigningContext!!, auth)
                .forEach { (name, value) -> headers[name] = value }
        }
        TransportSecurity.requireHttpRequestAllowed(
            "ToriiEventStreamClient",
            baseUri,
            target,
            headers,
            null,
            allowPlaintextLoopback,
        )
        val builder = TransportRequest.builder().setUri(target).setMethod("GET")
        val timeout = options.timeout
        if (timeout != null) {
            builder.setTimeout(timeout)
        }
        headers.forEach { (k, v) -> builder.addHeader(k, v) }
        return builder.build()
    }

    private fun buildCanonicalHeaders(
        target: URI,
        signingContext: LocalSigningContext,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): Map<String, String> = canonicalAuth.headers(signingContext.networkId(), "GET", target, null)

    private fun resolvePath(path: String?): URI {
        if (path.isNullOrBlank()) return baseUri
        if (path.startsWith("http://") || path.startsWith("https://")) return URI.create(path)
        val normalized = if (path.startsWith("/")) path.substring(1) else path
        val base = baseUri.toString()
        val joined = if (base.endsWith("/")) "$base$normalized" else "$base/$normalized"
        return URI.create(joined)
    }

    /**
     * Parse `text/event-stream` frames per the SSE specification: lines end with CRLF, LF or CR;
     * an event is dispatched at a blank line only when it carried `data`; an event cut off by the
     * end of the stream is discarded. Lines are limited to [MAX_LINE_BYTES] and events to
     * [MAX_EVENT_CHARS] characters.
     */
    private fun parseEventStream(
        stream: java.io.InputStream,
        listener: ToriiEventStreamListener,
        activeStream: ActiveStream,
    ) {
        try {
            stream.use { input ->
                val reader = SseLineReader(input, MAX_LINE_BYTES)
                val data = StringBuilder()
                var hasData = false
                var eventName: String? = null
                var eventId: String? = null
                var firstLine = true
                while (!activeStream.closed()) {
                    var line = reader.readLine() ?: break
                    if (firstLine) {
                        firstLine = false
                        if (line.startsWith("\uFEFF")) line = line.substring(1)
                    }
                    if (line.isEmpty()) {
                        if (hasData) dispatchEvent(listener, data, eventName, eventId)
                        data.setLength(0)
                        hasData = false
                        eventName = null
                        eventId = null
                        continue
                    }
                    if (line.startsWith(":")) continue
                    val colon = line.indexOf(':')
                    val field = if (colon == -1) line else line.substring(0, colon)
                    val value = if (colon == -1) {
                        ""
                    } else {
                        val raw = line.substring(colon + 1)
                        if (raw.startsWith(" ")) raw.substring(1) else raw
                    }
                    when (field) {
                        "data" -> {
                            if (data.length + value.length + 1 > MAX_EVENT_CHARS) {
                                throw IOException("Torii SSE event exceeds $MAX_EVENT_CHARS characters")
                            }
                            data.append(value).append('\n')
                            hasData = true
                        }
                        "event" -> eventName = value
                        "id" -> if (value.indexOf('\u0000') < 0) eventId = value
                        "retry" -> if (value.isNotEmpty() && value.all { it in '0'..'9' }) {
                            value.toLongOrNull()?.let { listener.onRetryHint(Duration.ofMillis(it)) }
                        }
                    }
                }
            }
        } catch (ex: IOException) {
            if (!activeStream.closed()) {
                throw java.io.UncheckedIOException("Failed to parse Torii SSE stream", ex)
            }
        }
    }

    private fun handleBufferedResponse(
        request: TransportRequest,
        listener: ToriiEventStreamListener,
        stream: ActiveStream,
        response: TransportResponse?,
        throwable: Throwable?,
    ) {
        if (stream.closed()) return
        if (throwable != null) {
            failStream(request, listener, stream, unwrapCompletion(throwable))
            return
        }
        response!!
        if (response.statusCode < 200 || response.statusCode >= 300) {
            val error = ToriiApiException.fromResponse(response.statusCode, response.headers, response.body)
            failStream(request, listener, stream, error)
            return
        }

        val clientResponse = ClientResponse(response.statusCode, ByteArray(0))
        notifyResponse(request, clientResponse)
        if (stream.closed()) return
        listener.onOpen()
        if (stream.closed()) return

        val readerFuture = CompletableFuture.runAsync({
            parseEventStream(ByteArrayInputStream(response.body), listener, stream)
        }, readerExecutor)
        stream.attach(readerFuture)
        readerFuture.whenComplete { _, parseError ->
            handleParseCompletion(request, listener, stream, parseError)
        }
    }

    private fun handleStreamResponse(
        request: TransportRequest,
        listener: ToriiEventStreamListener,
        stream: ActiveStream,
        response: TransportStreamResponse?,
        throwable: Throwable?,
    ) {
        response?.let { stream.attachStream(it) }
        if (stream.closed()) return
        if (throwable != null) {
            failStream(request, listener, stream, unwrapCompletion(throwable))
            return
        }
        response!!
        if (response.statusCode < 200 || response.statusCode >= 300) {
            val error = ToriiApiException.fromResponse(response.statusCode, response.headers, readBody(response))
            failStream(request, listener, stream, error)
            return
        }

        val clientResponse = ClientResponse(response.statusCode, ByteArray(0))
        notifyResponse(request, clientResponse)
        if (stream.closed()) return
        listener.onOpen()
        if (stream.closed()) return

        val readerFuture = CompletableFuture.runAsync({
            parseEventStream(response.body, listener, stream)
        }, readerExecutor)
        stream.attach(readerFuture)
        readerFuture.whenComplete { _, parseError ->
            handleParseCompletion(request, listener, stream, parseError)
        }
    }

    private fun handleParseCompletion(
        request: TransportRequest,
        listener: ToriiEventStreamListener,
        stream: ActiveStream,
        parseError: Throwable?,
    ) {
        val cleanupError = stream.closeStreamResponse()
        val cause = parseError?.let(::unwrapCompletion) ?: cleanupError
        if (parseError != null && cleanupError != null && cause !== cleanupError) {
            cause!!.addSuppressed(cleanupError)
        }
        if (stream.closed()) return
        if (cause != null) {
            failStream(request, listener, stream, cause)
            return
        }
        try {
            listener.onClosed()
            stream.signalSuccess()
        } catch (failure: Exception) {
            failStream(request, listener, stream, failure)
        }
    }

    private fun failStream(
        request: TransportRequest,
        listener: ToriiEventStreamListener,
        stream: ActiveStream,
        failure: Throwable,
    ) {
        stream.closeStreamResponse()?.let { if (it !== failure) failure.addSuppressed(it) }
        if (stream.signalFailure(failure)) {
            try { notifyFailure(request, failure) } finally { listener.onError(failure) }
        }
    }

    private fun notifyRequest(request: TransportRequest) {
        for (observer in observers) {
            observer.onRequest(request)
        }
    }

    private fun notifyResponse(request: TransportRequest, response: ClientResponse) {
        for (observer in observers) {
            observer.onResponse(request, response)
        }
    }

    private fun notifyFailure(request: TransportRequest, error: Throwable) {
        for (observer in observers) {
            observer.onFailure(request, error)
        }
    }

    companion object {
        private val CANONICAL_AUTH_HEADERS = listOf(
            CanonicalRequestSigner.HEADER_ACCOUNT,
            CanonicalRequestSigner.HEADER_SIGNATURE,
            CanonicalRequestSigner.HEADER_TIMESTAMP_MS,
            CanonicalRequestSigner.HEADER_NONCE,
        )

        @JvmStatic
        fun builder(): Builder = Builder()

        private fun appendQueryParameters(target: URI, params: Map<String, String>): URI {
            if (params.isEmpty()) return target
            val targetText = target.toString()
            val fragmentIndex = targetText.indexOf('#').let { if (it >= 0) it else targetText.length }
            val builder = StringBuilder(targetText.length + 1)
                .append(targetText, 0, fragmentIndex)
            val query = encodeQuery(params)
            if (target.query.isNullOrEmpty()) {
                builder.append(if (builder.indexOf("?") >= 0) "&" else "?")
            } else {
                builder.append("&")
            }
            builder.append(query)
            builder.append(targetText, fragmentIndex, targetText.length)
            return URI.create(builder.toString())
        }

        private fun rejectUnsupportedCanonicalResume(
            requestedPath: String?,
            target: URI,
            headers: Map<String, String>,
        ) {
            if (!isCanonicalLiveSsePath(requestedPath, target)) return
            if (headers.keys.none { it.equals("Last-Event-ID", ignoreCase = true) }) return
            throw IllegalArgumentException(
                "Last-Event-ID is unsupported for canonical live SSE streams because they have no replay log",
            )
        }

        private fun requireCanonicalHeadersUnset(headers: Map<String, String>) {
            require(headers.keys.none { candidate ->
                CANONICAL_AUTH_HEADERS.any { it.equals(candidate, ignoreCase = true) }
            }) {
                "canonical request headers must be supplied only through canonicalRequestAuth"
            }
        }

        private fun isCanonicalLiveSsePath(requestedPath: String?, target: URI): Boolean {
            val requestedRawPath = requestedPath
                ?.takeIf { it.isNotBlank() }
                ?.let { runCatching { URI.create(it).rawPath }.getOrNull() }
            return isCanonicalLiveSseRawPath(requestedRawPath) ||
                isCanonicalLiveSseRawPath(target.rawPath)
        }

        private fun isCanonicalLiveSseRawPath(rawPath: String?): Boolean =
            rawPath == "/v1/events/sse" || rawPath == "/v1/contracts/events/sse" ||
                isAccountHistoryStreamRawPath(rawPath)

        /** Option query parameters plus the canonical `filter` text, which may be given only once. */
        private fun streamQueryParameters(options: ToriiEventStreamOptions): Map<String, String> {
            val filter = options.filter ?: return options.queryParameters
            require(options.queryParameters.keys.none { it == "filter" }) {
                "pass the event filter either with setFilter or as the `filter` query parameter, not both"
            }
            return LinkedHashMap(options.queryParameters).also { it["filter"] = filter }
        }

        private fun encodeQuery(params: Map<String, String>): String {
            val sb = StringBuilder()
            var first = true
            for ((key, value) in params) {
                if (!first) sb.append('&')
                sb.append(URLEncoder.encode(key, "UTF-8"))
                    .append('=')
                    .append(URLEncoder.encode(value, "UTF-8"))
                first = false
            }
            return sb.toString()
        }

        private fun dispatchEvent(
            listener: ToriiEventStreamListener,
            data: StringBuilder,
            eventName: String?,
            eventId: String?,
        ) {
            if (data.isNotEmpty() && data[data.length - 1] == '\n') {
                data.deleteCharAt(data.length - 1)
            }
            val payload = data.toString()
            data.setLength(0)
            val name = if (eventName.isNullOrEmpty()) DEFAULT_EVENT_NAME else eventName
            listener.onEvent(ServerSentEvent(name, payload, eventId))
        }

        private fun unwrapCompletion(error: Throwable): Throwable {
            if (error is CompletionException && error.cause != null) {
                return error.cause!!
            }
            return error
        }

        /** Read at most [MAX_ERROR_BODY_BYTES] of an error response for diagnostics. */
        private fun readBody(response: TransportStreamResponse): ByteArray {
            val data: ByteArray
            try {
                response.body.use { body ->
                    ByteArrayOutputStream().use { buffer ->
                        val chunk = ByteArray(4096)
                        while (buffer.size() < MAX_ERROR_BODY_BYTES) {
                            val read = body.read(chunk, 0, minOf(chunk.size, MAX_ERROR_BODY_BYTES - buffer.size()))
                            if (read == -1) break
                            buffer.write(chunk, 0, read)
                        }
                        data = buffer.toByteArray()
                    }
                }
            } catch (_: IOException) {
                return ByteArray(0)
            }
            return data
        }
    }

    class Builder {
        private var baseUri: URI = URI.create("http://localhost:8080")
        private var transport: TransportExecutor? = null
        private val defaultHeaders: MutableMap<String, String> = LinkedHashMap()
        private val observers: MutableList<ClientObserver> = ArrayList()
        private var localSigningContext: LocalSigningContext? = null
        private var canonicalRequestAuth: ToriiCanonicalRequestAuth? = null
        private var readerExecutor: Executor? = null
        private var allowPlaintextLoopback: Boolean = false

        /** Allow canonical signing over plain `http` to loopback hosts (local development only). */
        fun allowPlaintextLoopback(allow: Boolean): Builder {
            allowPlaintextLoopback = allow
            return this
        }

        fun setBaseUri(baseUri: URI): Builder {
            this.baseUri = baseUri
            return this
        }

        fun setTransportExecutor(transport: TransportExecutor): Builder {
            this.transport = transport
            return this
        }

        /** Borrows an executor for blocking SSE reads; this client never shuts it down. */
        fun setReaderExecutor(executor: Executor): Builder {
            readerExecutor = executor
            return this
        }

        fun putDefaultHeader(name: String, value: String): Builder {
            defaultHeaders[name] = value
            return this
        }

        fun defaultHeaders(headers: Map<String, String>?): Builder {
            defaultHeaders.clear()
            headers?.forEach { (k, v) -> putDefaultHeader(k, v) }
            return this
        }

        fun addObserver(observer: ClientObserver): Builder {
            observers.add(observer)
            return this
        }

        fun observers(values: List<ClientObserver>?): Builder {
            observers.clear()
            values?.forEach { addObserver(it) }
            return this
        }

        /** Configures canonical account signing for every stream request opened by this client. */
        fun canonicalRequestAuth(
            localSigningContext: LocalSigningContext,
            canonicalRequestAuth: ToriiCanonicalRequestAuth,
        ): Builder {
            this.localSigningContext = localSigningContext
            this.canonicalRequestAuth = canonicalRequestAuth
            return this
        }

        fun build(): ToriiEventStreamClient {
            return ToriiEventStreamClient(
                baseUri,
                transport,
                defaultHeaders,
                observers,
                localSigningContext,
                canonicalRequestAuth,
                readerExecutor,
                allowPlaintextLoopback,
            )
        }
    }

    private class ActiveStream : ToriiEventStream {

        private val lifecycleLock = Any()
        private val completion = CompletableFuture<Void>()
        private val closed = AtomicBoolean(false)
        private val streamResponse = AtomicReference<TransportStreamResponse?>(null)
        private val responseFuture = AtomicReference<CompletableFuture<*>?>(null)
        private val readerFuture = AtomicReference<CompletableFuture<Void>?>(null)

        fun attachResponse(future: CompletableFuture<*>) {
            responseFuture.set(future)
            if (closed()) future.cancel(false)
        }

        fun attach(future: CompletableFuture<Void>) {
            readerFuture.set(future)
            if (closed()) future.cancel(false)
        }

        fun attachStream(response: TransportStreamResponse) {
            streamResponse.set(response)
            if (closed()) closeStreamResponse()
        }

        fun closeStreamResponse(): Exception? = try {
            streamResponse.getAndSet(null)?.close()
            null
        } catch (failure: Exception) { failure }

        fun signalFailure(error: Throwable): Boolean = synchronized(lifecycleLock) {
            !closed() && completion.completeExceptionally(error)
        }

        fun signalSuccess() {
            completion.complete(null)
        }

        fun closed(): Boolean = closed.get()

        override fun isOpen(): Boolean = !closed.get() && !completion.isDone

        override fun completion(): CompletableFuture<Void> = completion

        override fun close() {
            synchronized(lifecycleLock) {
                if (!closed.compareAndSet(false, true)) return
            }
            val cleanupError = closeStreamResponse()
            readerFuture.getAndSet(null)?.cancel(false)
            responseFuture.getAndSet(null)?.cancel(false)
            if (cleanupError == null) completion.complete(null)
            else completion.completeExceptionally(cleanupError)
        }
    }
}

/**
 * Reads SSE lines (terminated by CRLF, LF or CR) as UTF-8 with replacement, bounding each line.
 * Returns `null` at the end of the stream; a final unterminated line is discarded, as the SSE
 * specification requires for an event cut off by the end of the stream.
 */
internal class SseLineReader(private val input: java.io.InputStream, private val maxLineBytes: Int) {
    private val buffer = ByteArray(8192)
    private var position = 0
    private var limit = 0
    private var skipLineFeed = false
    private val line = ByteArrayOutputStream()

    fun readLine(): String? {
        line.reset()
        while (true) {
            if (position == limit) {
                limit = input.read(buffer, 0, buffer.size)
                position = 0
                if (limit <= 0) {
                    limit = 0
                    return null
                }
            }
            val byte = buffer[position++]
            if (skipLineFeed) {
                skipLineFeed = false
                if (byte == '\n'.code.toByte()) continue
            }
            when (byte) {
                '\n'.code.toByte() -> return String(line.toByteArray(), StandardCharsets.UTF_8)
                '\r'.code.toByte() -> {
                    skipLineFeed = true
                    return String(line.toByteArray(), StandardCharsets.UTF_8)
                }
                else -> {
                    if (line.size() >= maxLineBytes) {
                        throw IOException("Torii SSE line exceeds $maxLineBytes bytes")
                    }
                    line.write(byte.toInt())
                }
            }
        }
    }
}
