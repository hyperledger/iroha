package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope

import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.LinkedHashMap
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.tx.norito.NoritoCodecAdapter
import org.hyperledger.iroha.sdk.tx.norito.NoritoException
import org.hyperledger.iroha.sdk.telemetry.DeviceProfile
import org.hyperledger.iroha.sdk.telemetry.DeviceProfileProvider
import org.hyperledger.iroha.sdk.telemetry.NetworkContext
import org.hyperledger.iroha.sdk.telemetry.NetworkContextProvider
import org.hyperledger.iroha.sdk.telemetry.TelemetryObserver
import org.hyperledger.iroha.sdk.telemetry.TelemetryOptions
import org.hyperledger.iroha.sdk.telemetry.TelemetrySink
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse

/**
 * Minimal HTTP client that speaks the Torii Norito RPC surface.
 *
 * The client reuses a configurable [HttpTransportExecutor] (defaulting to the platform
 * implementation) and exposes helper builders for per-request overrides so SDK consumers can issue
 * binary Norito RPC payloads alongside the REST pipeline flows.
 */
class NoritoRpcClient private constructor(builder: Builder) : AutoCloseable {
    /** Cancels this client's calls; an injected executor remains application-owned. */
    override fun close() { transportExecutor.close() }


    private val baseUri: URI = builder.baseUri
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp
    private val timeout: Duration? = builder.timeout
    private val defaultHeaders: Map<String, String> = LinkedHashMap(builder.defaultHeaders).toMap()
    private val telemetryOptions: TelemetryOptions = builder.telemetryOptions ?: TelemetryOptions.disabled()
    private val telemetrySink: TelemetrySink? = builder.telemetrySink
    private val networkContextProvider: NetworkContextProvider = builder.networkContextProvider ?: NetworkContextProvider.disabled()
    private val deviceProfileProvider: DeviceProfileProvider = builder.deviceProfileProvider ?: DeviceProfileProvider.disabled()
    private val transportExecutor: HttpTransportExecutor = HttpTransportScope.create(builder.transportExecutor)
    private val observers: List<ClientObserver>
    private val flowController: NoritoRpcFlowController = builder.flowController ?: NoritoRpcFlowController.unlimited()
    private val wireFormatPreference: WireFormatPreference = builder.wireFormatPreference
    private val deviceProfileEmitted = AtomicBoolean(false)

    init {
        val observerList = ArrayList(builder.observers)
        if (telemetryOptions.enabled && telemetrySink != null && observerList.none { it is TelemetryObserver }) {
            observerList.add(TelemetryObserver(telemetryOptions, telemetrySink))
        }
        observers = observerList.toList()
    }

    fun baseUri(): URI = baseUri

    fun wireFormatPreference(): WireFormatPreference = wireFormatPreference

    fun call(path: String, payload: ByteArray?): ByteArray = call(path, payload, null)

    fun call(path: String, payload: ByteArray?, options: NoritoRpcRequestOptions?): ByteArray {
        val resolved = options ?: NoritoRpcRequestOptions.defaultOptions()
        val target = appendQueryParameters(resolvePath(path), resolved.queryParameters)
        val mergedHeaders = mergeHeaders(resolved)
        TransportSecurity.requireHttpRequestAllowed(
            "NoritoRpcClient",
            baseUri,
            target,
            mergedHeaders,
            payload,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val requestBuilder = TransportRequest.builder().setUri(target).setMethod(resolved.method)
        val requestTimeout = pickTimeout(resolved.timeout)
        requestBuilder.setTimeout(requestTimeout)
        mergedHeaders.forEach { (k, v) -> requestBuilder.addHeader(k, v) }
        val requestPayload = payload?.clone()
        requestBuilder.setBody(requestPayload)
        val request = requestBuilder.build()
        val startNano = System.nanoTime()
        emitDeviceProfileTelemetry()
        emitNetworkContextTelemetry()
        notifyRequest(request)
        try {
            flowController.acquire()
            try {
                val response = executeRequest(request)
                val elapsedMillis = elapsedMillis(startNano)
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    val message = "Norito RPC request failed with status ${response.statusCode}" +
                        responseBodyDetail(response.body)
                    val error = NoritoRpcException(message)
                    notifyFailure(request, error)
                    emitRpcCallTelemetry(request, response.statusCode, "failure", error.javaClass.simpleName, elapsedMillis)
                    throw error
                }
                val clientResponse = ClientResponse(response.statusCode, response.body)
                notifyResponse(request, clientResponse)
                emitRpcCallTelemetry(request, response.statusCode, "success", null, elapsedMillis)
                return response.body
            } finally {
                flowController.release()
            }
        } catch (ex: InterruptedException) {
            Thread.currentThread().interrupt()
            val error = NoritoRpcException("Norito RPC request interrupted", ex)
            notifyFailure(request, error)
            emitRpcCallTelemetry(request, null, "failure", error.javaClass.simpleName, elapsedMillis(startNano))
            throw error
        } catch (ex: IOException) {
            val error = NoritoRpcException("Norito RPC request failed", ex)
            notifyFailure(request, error)
            emitRpcCallTelemetry(request, null, "failure", error.javaClass.simpleName, elapsedMillis(startNano))
            throw error
        }
    }

    @Throws(NoritoException::class)
    fun callTransaction(path: String, payload: TransactionPayload, codec: NoritoCodecAdapter, options: NoritoRpcRequestOptions?): TransactionPayload {
        val encoded = codec.encodeTransaction(payload)
        val response = call(path, encoded, options)
        return codec.decodeTransaction(response)
    }

    private fun emitDeviceProfileTelemetry() {
        if (!telemetryOptions.enabled) return
        if (!deviceProfileEmitted.compareAndSet(false, true)) return
        if (telemetrySink == null) return
        val profile = deviceProfileProvider.snapshot().orElse(null) ?: return
        telemetrySink.emitSignal("android.telemetry.device_profile", mapOf("profile_bucket" to profile.bucket))
    }

    private fun emitNetworkContextTelemetry() {
        if (!telemetryOptions.enabled || telemetrySink == null) return
        val context = networkContextProvider.snapshot().orElse(null) ?: return
        telemetrySink.emitSignal("android.telemetry.network_context", context.toTelemetryFields())
    }

    private fun emitRpcCallTelemetry(request: TransportRequest, statusCode: Int?, outcome: String?, errorKind: String?, latencyMillis: Long) {
        if (!telemetryOptions.enabled || telemetrySink == null) return
        val fields = LinkedHashMap<String, Any>()
        maybePutAuthorityHash(fields, request)
        fields["route"] = resolveRoute(request)
        fields["method"] = resolveMethod(request)
        fields["outcome"] = outcome ?: ""
        if (statusCode != null) fields["status_code"] = statusCode
        if (!errorKind.isNullOrBlank()) fields["error_kind"] = errorKind
        fields["latency_ms"] = latencyMillis
        telemetrySink.emitSignal(RPC_CALL_SIGNAL, fields)
    }

    private fun maybePutAuthorityHash(fields: MutableMap<String, Any>, request: TransportRequest) {
        val redaction = telemetryOptions.redaction
        if (!redaction.enabled) return
        val authority = resolveAuthority(request)
        if (authority.isBlank()) { emitRedactionFailure("blank_authority"); return }
        val authorityHash = redaction.hashAuthority(authority)
        if (authorityHash.isPresent) {
            fields["authority_hash"] = authorityHash.get()
        } else {
            emitRedactionFailure("hash_failed")
        }
    }

    private fun emitRedactionFailure(reason: String) {
        telemetrySink?.emitSignal(REDACTION_FAILURE_SIGNAL, mapOf("signal_id" to RPC_CALL_SIGNAL, "reason" to reason))
    }

    @Throws(IOException::class, InterruptedException::class)
    private fun executeRequest(request: TransportRequest): TransportResponse {
        val future: CompletableFuture<TransportResponse>
        try { future = transportExecutor.execute(request) } catch (ex: RuntimeException) { throw IOException("Norito RPC executor rejected request", ex) }
        try { return future.get() } catch (ex: InterruptedException) { Thread.currentThread().interrupt(); throw ex }
        catch (ex: ExecutionException) {
            val cause = ex.cause
            if (cause is IOException) throw cause
            if (cause is InterruptedException) { Thread.currentThread().interrupt(); throw cause }
            throw IOException("Norito RPC executor failed", cause)
        } catch (ex: CancellationException) { throw IOException("Norito RPC executor cancelled request", ex) }
    }

    private fun pickTimeout(override: Duration?): Duration? {
        if (override != null) return if (override.isNegative) Duration.ZERO else override
        return timeout
    }

    private fun mergeHeaders(options: NoritoRpcRequestOptions): Map<String, String> {
        val merged = LinkedHashMap(defaultHeaders)
        options.headers.forEach { (k, v) -> merged[k] = v }
        if (findHeader(merged, "Content-Type") == null) merged["Content-Type"] = DEFAULT_CONTENT_TYPE
        applyAcceptHeader(merged, options, wireFormatPreference)
        return merged
    }

    private fun resolvePath(path: String?): URI {
        if (path.isNullOrBlank()) return baseUri
        if (path.startsWith("http://") || path.startsWith("https://")) return URI.create(path)
        val normalized = if (path.startsWith("/")) path.substring(1) else path
        val base = baseUri.toString()
        return URI.create(if (base.endsWith("/")) base + normalized else "$base/$normalized")
    }

    private fun notifyRequest(request: TransportRequest) { for (observer in observers) observer.onRequest(request) }
    private fun notifyResponse(request: TransportRequest, response: ClientResponse) { for (observer in observers) observer.onResponse(request, response) }
    private fun notifyFailure(request: TransportRequest, error: RuntimeException) { for (observer in observers) observer.onFailure(request, error) }

    class Builder internal constructor() {
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var allowLocalDevelopmentHttp: Boolean = false
        internal var timeout: Duration? = Duration.ofSeconds(10)
        internal val defaultHeaders = LinkedHashMap<String, String>()
        internal var telemetryOptions: TelemetryOptions? = TelemetryOptions.disabled()
        internal var telemetrySink: TelemetrySink? = null
        internal var networkContextProvider: NetworkContextProvider? = NetworkContextProvider.disabled()
        internal var deviceProfileProvider: DeviceProfileProvider? = DeviceProfileProvider.disabled()
        internal var transportExecutor: HttpTransportExecutor? = null
        internal val observers = ArrayList<ClientObserver>()
        internal var flowController: NoritoRpcFlowController? = NoritoRpcFlowController.unlimited()
        internal var wireFormatPreference: WireFormatPreference = WireFormatPreference.NORITO_PREFERRED

        fun setBaseUri(baseUri: URI): Builder { this.baseUri = baseUri; return this }

        /**
         * Allow credentialed HTTP to the same loopback or private IPv4 origin; disabled by default.
         * See [ClientConfig.Builder.setAllowLocalDevelopmentHttp] for the allowed address ranges.
         */
        fun setAllowLocalDevelopmentHttp(allow: Boolean): Builder = apply {
            this.allowLocalDevelopmentHttp = allow
        }
        fun setTimeout(timeout: Duration?): Builder { this.timeout = if (timeout == null) null else if (timeout.isNegative) Duration.ZERO else timeout; return this }
        fun putDefaultHeader(name: String, value: String): Builder { defaultHeaders[name] = value; return this }
        fun defaultHeaders(headers: Map<String, String>?): Builder { defaultHeaders.clear(); headers?.forEach { (k, v) -> putDefaultHeader(k, v) }; return this }
        fun setTelemetryOptions(telemetryOptions: TelemetryOptions): Builder { this.telemetryOptions = telemetryOptions; return this }
        fun setTelemetrySink(telemetrySink: TelemetrySink?): Builder { this.telemetrySink = telemetrySink; return this }
        fun setNetworkContextProvider(provider: NetworkContextProvider): Builder { this.networkContextProvider = provider; return this }
        fun setDeviceProfileProvider(provider: DeviceProfileProvider): Builder { this.deviceProfileProvider = provider; return this }
        fun setTransportExecutor(executor: HttpTransportExecutor?): Builder { this.transportExecutor = executor; return this }
        fun addObserver(observer: ClientObserver): Builder { observers.add(observer); return this }
        fun observers(observers: List<ClientObserver>?): Builder { this.observers.clear(); observers?.forEach { addObserver(it) }; return this }
        fun setFlowController(flowController: NoritoRpcFlowController): Builder { this.flowController = flowController; return this }
        fun setMaxConcurrentRequests(maxConcurrentRequests: Int): Builder { this.flowController = NoritoRpcFlowController.semaphore(maxConcurrentRequests); return this }
        fun setWireFormatPreference(preference: WireFormatPreference): Builder { this.wireFormatPreference = preference; return this }
        fun build(): NoritoRpcClient = NoritoRpcClient(this)
    }

    companion object {
        @JvmField val DEFAULT_ACCEPT: String = WireFormatPreference.NORITO_PREFERRED.acceptHeader()
        private const val DEFAULT_CONTENT_TYPE = "application/x-norito"
        private const val RPC_CALL_SIGNAL = "android.norito_rpc.call"
        private const val REDACTION_FAILURE_SIGNAL = "android.telemetry.redaction.failure"

        @JvmStatic fun builder(): Builder = Builder()

        private fun elapsedMillis(startNano: Long): Long = (System.nanoTime() - startNano) / 1_000_000L
        private fun resolveRoute(request: TransportRequest?): String = request?.uri?.rawPath ?: ""
        private fun resolveMethod(request: TransportRequest?): String = request?.method ?: ""
        private fun resolveAuthority(request: TransportRequest?): String {
            if (request == null) return ""
            val authority = request.uri.authority
            if (authority != null) return authority.trim()
            val hosts = request.headers["Host"]
            return if (hosts.isNullOrEmpty()) "" else hosts[0].trim()
        }

        private fun responseBodyDetail(body: ByteArray): String {
            if (body.isEmpty()) return ""
            val text = String(body, StandardCharsets.UTF_8).trim()
            if (text.isNotEmpty() && text.all { !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }) {
                return ": $text"
            }
            val limit = minOf(body.size, 256)
            val hex = body.copyOfRange(0, limit).joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return if (body.size > limit) ": body_hex=$hex..." else ": body_hex=$hex"
        }

        private fun findHeader(headers: Map<String, String>, needle: String): String? {
            for (name in headers.keys) if (name.equals(needle, ignoreCase = true)) return name
            return null
        }

        private fun applyAcceptHeader(
            headers: MutableMap<String, String>,
            options: NoritoRpcRequestOptions,
            wireFormatPreference: WireFormatPreference
        ) {
            if (options.acceptConfigured) {
                val currentKey = findHeader(headers, "Accept")
                if (options.accept == null) { if (currentKey != null) headers.remove(currentKey) }
                else { if (currentKey != null) headers[currentKey] = options.accept else headers["Accept"] = options.accept }
                return
            }
            if (findHeader(headers, "Accept") == null) headers["Accept"] = wireFormatPreference.acceptHeader()
        }

        private fun appendQueryParameters(target: URI, params: Map<String, String>): URI {
            if (params.isEmpty()) return target
            val targetText = target.toString()
            val fragmentIndex = targetText.indexOf('#').let { if (it >= 0) it else targetText.length }
            val builder = StringBuilder(targetText.length + 1)
                .append(targetText, 0, fragmentIndex)
            val query = encodeQuery(params)
            if (target.query == null || target.query.isEmpty()) builder.append(if (builder.indexOf("?") >= 0) "&" else "?")
            else builder.append("&")
            builder.append(query)
            builder.append(targetText, fragmentIndex, targetText.length)
            return URI.create(builder.toString())
        }

        private fun encodeQuery(params: Map<String, String>): String =
            params.entries.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}" }
    }
}
