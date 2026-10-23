package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope

import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.subscriptions.*

/** Lightweight HTTP client for Torii subscription endpoints (`/v1/subscriptions/`). */
class SubscriptionToriiClient private constructor(builder: Builder) : AutoCloseable {
    /** Cancels this client's calls; an injected executor remains application-owned. */
    override fun close() { executor.close() }


    private val executor: HttpTransportExecutor = HttpTransportScope.create(builder.executor)
    private val baseUri: URI = builder.baseUri
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp
    private val timeout: Duration? = builder.timeout
    private val defaultHeaders: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(builder.defaultHeaders))
    private val observers: List<ClientObserver> = builder.observers.toList()

    fun createSubscriptionPlan(request: SubscriptionPlanCreateRequest): CompletableFuture<SubscriptionPlanCreateResponse> {
        return unsupportedServerSideSigning("/v1/subscriptions/plans")
    }

    fun createSubscription(request: SubscriptionCreateRequest): CompletableFuture<SubscriptionCreateResponse> {
        return unsupportedServerSideSigning("/v1/subscriptions")
    }

    fun getSubscription(subscriptionId: String): CompletableFuture<SubscriptionRecord?> {
        val normalizedId = requireNonBlank(subscriptionId, "subscription_id")
        val path = "$SUBSCRIPTIONS_PATH/${urlEncode(normalizedId)}"
        val request = buildGetRequest(path, emptyMap())
        notifyRequest(request)
        return executeHttpRequestAllowingNotFound(request, SubscriptionJsonParser::parseSubscriptionRecord)
    }

    fun pauseSubscription(subscriptionId: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> = unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/pause")
    fun resumeSubscription(subscriptionId: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> = unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/resume")
    fun cancelSubscription(subscriptionId: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> = unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/cancel")
    fun keepSubscription(subscriptionId: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> = unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/keep")
    fun chargeSubscriptionNow(subscriptionId: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> = unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/charge-now")

    fun recordSubscriptionUsage(subscriptionId: String, request: SubscriptionUsageRequest): CompletableFuture<SubscriptionActionResponse> {
        return unsupportedServerSideSigning("/v1/subscriptions/{subscription_id}/usage")
    }

    fun executor(): HttpTransportExecutor = executor

    private fun executeSubscriptionAction(subscriptionId: String, action: String, request: SubscriptionActionRequest): CompletableFuture<SubscriptionActionResponse> {
        val normalizedId = requireNonBlank(subscriptionId, "subscription_id")
        val path = "$SUBSCRIPTIONS_PATH/${urlEncode(normalizedId)}/$action"
        val transport = buildPostRequest(path, request.toJsonBytes())
        notifyRequest(transport)
        return executeHttpRequest(transport, SubscriptionJsonParser::parseActionResponse)
    }

    private fun buildGetRequest(path: String, query: Map<String, String>): TransportRequest {
        val target = appendQuery(resolvePath(path), query)
        val headers = mergeHeaders()
        TransportSecurity.requireHttpRequestAllowed(
            "SubscriptionToriiClient",
            baseUri,
            target,
            headers,
            null,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder().setUri(target).setMethod("GET").setTimeout(timeout)
        headers.forEach { (k, v) -> builder.addHeader(k, v) }
        return builder.build()
    }

    private fun buildPostRequest(path: String, body: ByteArray): TransportRequest {
        val target = resolvePath(path)
        val headers = mergeHeaders()
        TransportSecurity.requireHttpRequestAllowed(
            "SubscriptionToriiClient",
            baseUri,
            target,
            headers,
            body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder().setUri(target).setMethod("POST").setTimeout(timeout).setBody(body)
        headers.forEach { (k, v) -> builder.addHeader(k, v) }
        builder.addHeader("Content-Type", "application/json")
        return builder.build()
    }

    private fun mergeHeaders(): Map<String, String> {
        val headers = LinkedHashMap(defaultHeaders)
        ensureHeader(headers, "Accept", "application/json")
        return headers
    }

    private fun ensureHeader(headers: MutableMap<String, String>, name: String, value: String) {
        val existing = findHeader(headers, name)
        headers[existing ?: name] = value
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
    private fun notifyFailure(request: TransportRequest, error: Throwable) { for (observer in observers) observer.onFailure(request, error) }

    private fun <T> unsupportedServerSideSigning(endpoint: String): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        future.completeExceptionally(
            SubscriptionToriiException(
                "$endpoint no longer accepts server-side signing inputs; submit a locally signed transaction instead.",
            ),
        )
        return future
    }

    private fun <T> executeHttpRequest(request: TransportRequest, parser: (ByteArray) -> T): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        executor.execute(request).whenComplete { response, throwable ->
            if (throwable != null) {
                val cause = if (throwable is CompletionException) throwable.cause else throwable
                val error = SubscriptionToriiException("Subscription request failed", cause ?: throwable)
                notifyFailure(request, error); future.completeExceptionally(error); return@whenComplete
            }
            val clientResponse = ClientResponse(response.statusCode, response.body)
            if (response.statusCode < 200 || response.statusCode >= 300) {
                val error = SubscriptionToriiException("Subscription request failed with status ${response.statusCode}")
                notifyFailure(request, error); future.completeExceptionally(error); return@whenComplete
            }
            try { val parsed = parser(response.body); notifyResponse(request, clientResponse); future.complete(parsed) }
            catch (ex: RuntimeException) { val error = SubscriptionToriiException("Failed to parse subscription response", ex); notifyFailure(request, error); future.completeExceptionally(error) }
        }
        return future
    }

    private fun <T> executeHttpRequestAllowingNotFound(request: TransportRequest, parser: (ByteArray) -> T): CompletableFuture<T?> {
        val future = CompletableFuture<T?>()
        executor.execute(request).whenComplete { response, throwable ->
            if (throwable != null) {
                val cause = if (throwable is CompletionException) throwable.cause else throwable
                val error = SubscriptionToriiException("Subscription request failed", cause ?: throwable)
                notifyFailure(request, error); future.completeExceptionally(error); return@whenComplete
            }
            val clientResponse = ClientResponse(response.statusCode, response.body)
            if (response.statusCode == 404) { notifyResponse(request, clientResponse); future.complete(null); return@whenComplete }
            if (response.statusCode < 200 || response.statusCode >= 300) {
                val error = SubscriptionToriiException("Subscription request failed with status ${response.statusCode}")
                notifyFailure(request, error); future.completeExceptionally(error); return@whenComplete
            }
            try { val parsed = parser(response.body); notifyResponse(request, clientResponse); future.complete(parsed) }
            catch (ex: RuntimeException) { val error = SubscriptionToriiException("Failed to parse subscription response", ex); notifyFailure(request, error); future.completeExceptionally(error) }
        }
        return future
    }

    class Builder internal constructor() {
        internal var executor: HttpTransportExecutor? = null
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var allowLocalDevelopmentHttp: Boolean = false
        internal var timeout: Duration? = Duration.ofSeconds(15)
        internal val defaultHeaders = LinkedHashMap<String, String>()
        internal val observers = ArrayList<ClientObserver>()

        fun executor(executor: HttpTransportExecutor): Builder { this.executor = executor; return this }
        fun baseUri(baseUri: URI): Builder { this.baseUri = baseUri; return this }

        /**
         * Allow credentialed HTTP to the same loopback or private IPv4 origin; disabled by default.
         * See [ClientConfig.Builder.setAllowLocalDevelopmentHttp] for the allowed address ranges.
         */
        fun setAllowLocalDevelopmentHttp(allow: Boolean): Builder = apply {
            this.allowLocalDevelopmentHttp = allow
        }
        fun timeout(timeout: Duration?): Builder { this.timeout = timeout; return this }
        fun addHeader(name: String, value: String): Builder { defaultHeaders[name] = value; return this }
        fun defaultHeaders(headers: Map<String, String>?): Builder { defaultHeaders.clear(); headers?.forEach { (key, value) -> defaultHeaders[key] = value }; return this }
        fun addObserver(observer: ClientObserver?): Builder { if (observer != null) observers.add(observer); return this }
        fun observers(observers: List<ClientObserver>?): Builder { this.observers.clear(); observers?.forEach { addObserver(it) }; return this }
        fun build(): SubscriptionToriiClient = SubscriptionToriiClient(this)
    }

    companion object {
        private const val PLANS_PATH = "/v1/subscriptions/plans"
        private const val SUBSCRIPTIONS_PATH = "/v1/subscriptions"

        @JvmStatic fun builder(): Builder = Builder()

        private fun requireNonBlank(value: String?, field: String): String {
            check(!value.isNullOrBlank()) { "$field is required" }
            return value.trim()
        }

        private fun findHeader(headers: Map<String, String>, name: String): String? {
            for (key in headers.keys) if (key.equals(name, ignoreCase = true)) return key
            return null
        }

        private fun appendQuery(target: URI, params: Map<String, String>?): URI {
            if (params.isNullOrEmpty()) return target
            val targetText = target.toString()
            val fragmentIndex = targetText.indexOf('#').let { if (it >= 0) it else targetText.length }
            val builder = StringBuilder(targetText.length + 1)
                .append(targetText, 0, fragmentIndex)
            builder.append(if (builder.indexOf("?") >= 0) "&" else "?")
            builder.append(encodeQuery(params))
            builder.append(targetText, fragmentIndex, targetText.length)
            return URI.create(builder.toString())
        }

        private fun encodeQuery(params: Map<String, String>): String =
            params.entries.joinToString("&") { (k, v) -> "${urlEncode(k)}=${urlEncode(v)}" }

        private fun urlEncode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8.name())
    }
}
