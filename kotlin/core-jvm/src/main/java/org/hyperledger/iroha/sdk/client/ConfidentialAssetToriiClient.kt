package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope

import java.net.URI
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.hyperledger.iroha.sdk.client.transport.TransportRequest

/**
 * Exact-network Torii client for authenticated confidential-asset query endpoints.
 *
 * Every request is signed over its POST method, resolved path, and exact JSON body, and is marked
 * one-shot so transports cannot redirect or retry the signature.
 */
class ConfidentialAssetToriiClient private constructor(builder: Builder) : AutoCloseable {
    /** Cancels this client's calls; an injected executor remains application-owned. */
    override fun close() { executor.close() }


    private val executor: HttpTransportExecutor = HttpTransportScope.create(builder.executor)
    private val baseUri: URI = builder.baseUri
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp
    private val localSigningContext: LocalSigningContext = checkNotNull(builder.localSigningContext) {
        "localSigningContext must be configured before building a confidential asset client"
    }
    private val timeout: Duration? = builder.timeout
    private val defaultHeaders: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(builder.defaultHeaders))
    private val observers: List<ClientObserver> = builder.observers.toList()

    fun getZkAssetRoots(
        request: ZkRootsRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ZkRootsResponse> =
        executePost(ZK_ROOTS_PATH, request.toJsonBytes(), canonicalAuth, ZkRootsResponse::parse)

    fun getZkAssetMerklePaths(
        request: ZkMerklePathRequest,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ZkMerklePathResponse> =
        executePost(
            ZK_MERKLE_PATH_PATH,
            request.toJsonBytes(),
            canonicalAuth,
            ZkMerklePathResponse::parse,
        )

    fun getLatestZkAssetRoot(
        assetId: String,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): CompletableFuture<ByteArray?> =
        getZkAssetRoots(ZkRootsRequest(assetId, 1), canonicalAuth)
            .thenApply { it.getLatestRootBytes() }

    fun executor(): HttpTransportExecutor = executor

    private fun <T> executePost(
        path: String,
        body: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
        parser: (ByteArray) -> T,
    ): CompletableFuture<T> {
        val request = buildPostRequest(path, body, canonicalAuth)
        notifyRequest(request)
        return executeHttpRequest(request, parser)
    }

    private fun buildPostRequest(
        path: String,
        body: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): TransportRequest {
        val target = resolvePath(path)
        val headers = LinkedHashMap(mergeHeaders())
        requireCanonicalHeadersUnset(headers)
        headers.putAll(buildCanonicalHeaders(target, body, canonicalAuth))
        TransportSecurity.requireHttpRequestAllowed(
            "ConfidentialAssetToriiClient",
            baseUri,
            target,
            headers,
            body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .setBody(body)
            .setTimeout(timeout)
        headers.forEach { (name, value) -> builder.addHeader(name, value) }
        return builder.build()
    }

    private fun mergeHeaders(): Map<String, String> {
        val headers = LinkedHashMap(defaultHeaders)
        ensureHeader(headers, "Accept", "application/json")
        ensureHeader(headers, "Content-Type", "application/json")
        return headers
    }

    private fun buildCanonicalHeaders(
        target: URI,
        body: ByteArray,
        canonicalAuth: ToriiCanonicalRequestAuth,
    ): Map<String, String> = canonicalAuth.headers(localSigningContext.networkId(), "POST", target, body)

    private fun requireCanonicalHeadersUnset(headers: Map<String, String>) {
        require(headers.keys.none { candidate ->
            CANONICAL_AUTH_HEADERS.any { it.equals(candidate, ignoreCase = true) }
        }) { "canonical request headers must be supplied only through canonicalAuth" }
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

    private fun <T> executeHttpRequest(request: TransportRequest, parser: (ByteArray) -> T): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        executor.execute(request).whenComplete { response, throwable ->
            if (throwable != null) {
                val cause = if (throwable is CompletionException) throwable.cause else throwable
                val error = ConfidentialAssetToriiException("Confidential asset request failed: ${summarizeCauseMessage(cause)}", cause, null, null, null)
                notifyFailure(request, error)
                future.completeExceptionally(error)
                return@whenComplete
            }
            val rejectCode = HttpErrorMessageExtractor.extractRejectCode(response.headers, "x-iroha-reject-code", response.body)
            val bodyPreview = HttpErrorMessageExtractor.extractMessage(response.body)
            val clientResponse = ClientResponse(response.statusCode, response.body, response.message, null, rejectCode)
            if (response.statusCode < 200 || response.statusCode >= 300) {
                val error = ConfidentialAssetToriiException(buildHttpFailureMessage(request, response.statusCode, response.message, rejectCode, bodyPreview), response.statusCode, rejectCode, bodyPreview)
                notifyFailure(request, error)
                future.completeExceptionally(error)
                return@whenComplete
            }
            try {
                val parsed = parser(response.body)
                notifyResponse(request, clientResponse)
                future.complete(parsed)
            } catch (ex: RuntimeException) {
                val error = ConfidentialAssetToriiException(buildParseFailureMessage(request, response.statusCode, bodyPreview), ex, response.statusCode, rejectCode, bodyPreview)
                notifyFailure(request, error)
                future.completeExceptionally(error)
            }
        }
        return future
    }

    class Builder internal constructor() {
        internal var executor: HttpTransportExecutor? = null
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var allowLocalDevelopmentHttp: Boolean = false
        internal var localSigningContext: LocalSigningContext? = null
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
        fun localSigningContext(localSigningContext: LocalSigningContext): Builder {
            this.localSigningContext = localSigningContext
            return this
        }
        fun timeout(timeout: Duration?): Builder { this.timeout = timeout; return this }
        fun addHeader(name: String, value: String): Builder { defaultHeaders[name] = value; return this }
        fun defaultHeaders(headers: Map<String, String>?): Builder { defaultHeaders.clear(); headers?.forEach { (k, v) -> defaultHeaders[k] = v }; return this }
        fun addObserver(observer: ClientObserver?): Builder { if (observer != null) observers.add(observer); return this }
        fun observers(observers: List<ClientObserver>?): Builder { this.observers.clear(); observers?.forEach { addObserver(it) }; return this }
        fun build(): ConfidentialAssetToriiClient = ConfidentialAssetToriiClient(this)
    }

    companion object {
        private const val ZK_ROOTS_PATH = "/v1/zk/roots"
        private const val ZK_MERKLE_PATH_PATH = "/v1/zk/merkle-path"
        private val CANONICAL_AUTH_HEADERS = setOf(
            CanonicalRequestSigner.HEADER_ACCOUNT,
            CanonicalRequestSigner.HEADER_SIGNATURE,
            CanonicalRequestSigner.HEADER_TIMESTAMP_MS,
            CanonicalRequestSigner.HEADER_NONCE,
        )

        @JvmStatic fun builder(): Builder = Builder()
        private fun ensureHeader(headers: MutableMap<String, String>, name: String, value: String) {
            headers[findHeader(headers, name) ?: name] = value
        }
        private fun findHeader(headers: Map<String, String>, name: String): String? {
            for (key in headers.keys) if (key.equals(name, ignoreCase = true)) return key
            return null
        }
        private fun summarizeCauseMessage(cause: Throwable?): String = cause?.message?.takeIf { it.isNotBlank() } ?: cause?.javaClass?.simpleName ?: "unknown transport error"
        private fun buildHttpFailureMessage(request: TransportRequest?, statusCode: Int, statusMessage: String?, rejectCode: String?, bodyPreview: String?): String {
            val sb = StringBuilder("Confidential asset request failed with HTTP $statusCode")
            if (!statusMessage.isNullOrBlank()) sb.append(" ($statusMessage)")
            request?.uri?.path?.let { sb.append(" on $it") }
            if (!rejectCode.isNullOrBlank()) sb.append(". reject_code=$rejectCode")
            if (!bodyPreview.isNullOrBlank()) sb.append(". body=$bodyPreview")
            return sb.toString()
        }
        private fun buildParseFailureMessage(request: TransportRequest?, statusCode: Int, bodyPreview: String?): String {
            val sb = StringBuilder("Failed to parse confidential asset response (HTTP $statusCode)")
            request?.uri?.path?.let { sb.append(" for $it") }
            if (!bodyPreview.isNullOrBlank()) sb.append(". body=$bodyPreview")
            return sb.toString()
        }
    }
}
