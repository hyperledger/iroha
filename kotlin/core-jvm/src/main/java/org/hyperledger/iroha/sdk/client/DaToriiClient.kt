package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.transport.HttpTransportScope

import java.net.URI
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.hyperledger.iroha.sdk.client.transport.TransportRequest

/** Typed HTTP client for DA proof-policy, commitment, and pin-intent routes. */
class DaToriiClient private constructor(builder: Builder) : AutoCloseable {
    /** Cancels this client's calls; an injected executor remains application-owned. */
    override fun close() { executor.close() }

    private val executor: HttpTransportExecutor =
        HttpTransportScope.create(builder.executor)
    private val baseUri: URI = builder.baseUri
    private val allowLocalDevelopmentHttp: Boolean = builder.allowLocalDevelopmentHttp
    private val timeout: Duration? = builder.timeout
    private val defaultHeaders: Map<String, String> =
        Collections.unmodifiableMap(LinkedHashMap(builder.defaultHeaders))
    private val observers: List<ClientObserver> = builder.observers.toList()

    fun getProofPolicies(): CompletableFuture<DaModels.ProofPolicyBundle> =
        executeGet(PROOF_POLICIES_PATH) {
            DaJson.parsePolicyBundle(DaJson.parse(it, "DA proof-policy response"), "response")
        }

    fun listCommitments(
        request: DaModels.CommitmentListRequest = DaModels.CommitmentListRequest(),
    ): CompletableFuture<DaModels.CommitmentListResponse> =
        executePost(COMMITMENTS_PATH, request.toJsonBytes()) {
            DaJson.parseCommitmentList(DaJson.parse(it, "DA commitment response"), "response")
        }

    fun proveCommitment(
        request: DaModels.CommitmentProofRequest = DaModels.CommitmentProofRequest(),
    ): CompletableFuture<DaModels.CommitmentProofResponse?> =
        executePost(COMMITMENTS_PROVE_PATH, request.toJsonBytes()) {
            DaJson.parseCommitmentProofResponse(
                DaJson.parse(it, "DA commitment proof response"),
                "response",
            )
        }

    fun verifyCommitment(
        proof: DaModels.CommitmentProof,
    ): CompletableFuture<DaModels.VerifyResponse> =
        executePost(COMMITMENTS_VERIFY_PATH, proof.toJsonBytes()) {
            DaJson.parseVerifyResponse(
                DaJson.parse(it, "DA commitment verification response"),
                "response",
            )
        }

    fun listPinIntents(
        request: DaModels.PinIntentListRequest = DaModels.PinIntentListRequest(),
    ): CompletableFuture<DaModels.PinIntentListResponse> =
        executePost(PIN_INTENTS_PATH, request.toJsonBytes()) {
            DaJson.parsePinIntentList(DaJson.parse(it, "DA pin-intent response"), "response")
        }

    fun provePinIntent(
        request: DaModels.PinIntentQueryRequest = DaModels.PinIntentQueryRequest(),
    ): CompletableFuture<DaModels.PinIntentProof?> =
        executePost(PIN_INTENTS_PROVE_PATH, request.toJsonBytes()) {
            DaJson.parsePinIntentProof(
                DaJson.parse(it, "DA pin-intent proof response"),
                "response",
            )
        }

    fun verifyPinIntent(
        proof: DaModels.PinIntentProof,
    ): CompletableFuture<DaModels.VerifyResponse> =
        executePost(PIN_INTENTS_VERIFY_PATH, proof.toJsonBytes()) {
            DaJson.parseVerifyResponse(
                DaJson.parse(it, "DA pin-intent verification response"),
                "response",
            )
        }

    fun executor(): HttpTransportExecutor = executor

    private fun <T> executeGet(
        path: String,
        parser: (ByteArray) -> T,
    ): CompletableFuture<T> = execute(buildRequest("GET", path, null), parser)

    private fun <T> executePost(
        path: String,
        body: ByteArray,
        parser: (ByteArray) -> T,
    ): CompletableFuture<T> {
        require(body.size <= REQUEST_MAX_BYTES) {
            "DA request exceeds the $REQUEST_MAX_BYTES-byte route limit"
        }
        return execute(buildRequest("POST", path, body), parser)
    }

    private fun buildRequest(method: String, path: String, body: ByteArray?): TransportRequest {
        val target = resolvePath(path)
        val headers = LinkedHashMap(defaultHeaders)
        ensureHeader(headers, "Accept", "application/json")
        if (body != null) ensureHeader(headers, "Content-Type", "application/json")
        TransportSecurity.requireHttpRequestAllowed(
            "DaToriiClient",
            baseUri,
            target,
            headers,
            body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod(method)
            .setTimeout(timeout)
            .setMaximumResponseBytes(RESPONSE_MAX_BYTES.toLong())
        if (body != null) builder.setBody(body)
        headers.forEach { (name, value) -> builder.addHeader(name, value) }
        return builder.build()
    }

    private fun <T> execute(
        request: TransportRequest,
        parser: (ByteArray) -> T,
    ): CompletableFuture<T> {
        notifyRequest(request)
        return executor.execute(request).handle { response, throwable ->
            if (throwable != null) {
                val cause = if (throwable is CompletionException) throwable.cause else throwable
                val error = DaToriiException("DA request failed", cause ?: throwable)
                notifyFailure(request, error)
                throw CompletionException(error)
            }

            try {
                parseResponse(request, response, parser)
            } catch (error: RuntimeException) {
                val wrapped =
                    if (error is DaToriiException) {
                        error
                    } else {
                        DaToriiException("Failed to parse DA response", error)
                    }
                notifyFailure(request, wrapped)
                throw CompletionException(wrapped)
            }
        }
    }

    private fun <T> parseResponse(
        request: TransportRequest,
        response: org.hyperledger.iroha.sdk.client.transport.TransportResponse,
        parser: (ByteArray) -> T,
    ): T {
        val body = response.body
        val clientResponse = ClientResponse(
            response.statusCode,
            body,
            response.message,
            null,
            HttpErrorMessageExtractor.extractRejectCode(
                response.headers,
                "x-iroha-reject-code",
                body,
            ),
        )
        if (response.statusCode !in 200..299) {
            throw DaToriiException(
                "DA request failed with HTTP ${response.statusCode}: " +
                    (HttpErrorMessageExtractor.extractMessage(body) ?: response.message),
            )
        }
        if (body.size > RESPONSE_MAX_BYTES) {
            throw DaToriiException(
                "DA response exceeds the $RESPONSE_MAX_BYTES-byte client limit",
            )
        }
        if (!hasJsonContentType(response.headers)) {
            throw DaToriiException("DA response must use application/json")
        }
        val parsed = parser(body)
        notifyResponse(request, clientResponse)
        return parsed
    }

    private fun resolvePath(path: String): URI {
        val normalized = if (path.startsWith("/")) path.substring(1) else path
        val base = baseUri.toString()
        return URI.create(if (base.endsWith("/")) base + normalized else "$base/$normalized")
    }

    private fun notifyRequest(request: TransportRequest) {
        observers.forEach { it.onRequest(request) }
    }

    private fun notifyResponse(request: TransportRequest, response: ClientResponse) {
        observers.forEach { it.onResponse(request, response) }
    }

    private fun notifyFailure(request: TransportRequest, error: Throwable) {
        observers.forEach { it.onFailure(request, error) }
    }

    class Builder internal constructor() {
        internal var executor: HttpTransportExecutor? = null
        internal var baseUri: URI = URI.create("http://localhost:8080")
        internal var allowLocalDevelopmentHttp: Boolean = false
        internal var timeout: Duration? = Duration.ofSeconds(15)
        internal val defaultHeaders = LinkedHashMap<String, String>()
        internal val observers = ArrayList<ClientObserver>()

        fun executor(executor: HttpTransportExecutor): Builder {
            this.executor = executor
            return this
        }

        fun baseUri(baseUri: URI): Builder {
            this.baseUri = baseUri
            return this
        }

        /**
         * Allow credentialed HTTP to the same loopback or private IPv4 origin; disabled by default.
         * See [ClientConfig.Builder.setAllowLocalDevelopmentHttp] for the allowed address ranges.
         */
        fun setAllowLocalDevelopmentHttp(allow: Boolean): Builder = apply {
            this.allowLocalDevelopmentHttp = allow
        }

        fun timeout(timeout: Duration?): Builder {
            this.timeout = timeout
            return this
        }

        fun addHeader(name: String, value: String): Builder {
            defaultHeaders[name] = value
            return this
        }

        fun defaultHeaders(headers: Map<String, String>?): Builder {
            defaultHeaders.clear()
            if (headers != null) defaultHeaders.putAll(headers)
            return this
        }

        fun addObserver(observer: ClientObserver?): Builder {
            if (observer != null) observers.add(observer)
            return this
        }

        fun observers(observers: List<ClientObserver>?): Builder {
            this.observers.clear()
            observers?.forEach(::addObserver)
            return this
        }

        fun build(): DaToriiClient = DaToriiClient(this)
    }

    companion object {
        private const val PROOF_POLICIES_PATH = "/v1/da/proof-policies"
        private const val COMMITMENTS_PATH = "/v1/da/commitments"
        private const val COMMITMENTS_PROVE_PATH = "/v1/da/commitments/prove"
        private const val COMMITMENTS_VERIFY_PATH = "/v1/da/commitments/verify"
        private const val PIN_INTENTS_PATH = "/v1/da/pin-intents"
        private const val PIN_INTENTS_PROVE_PATH = "/v1/da/pin-intents/prove"
        private const val PIN_INTENTS_VERIFY_PATH = "/v1/da/pin-intents/verify"
        private const val REQUEST_MAX_BYTES = 64 * 1024
        private const val RESPONSE_MAX_BYTES = 8 * 1024 * 1024

        @JvmStatic
        fun builder(): Builder = Builder()

        private fun ensureHeader(
            headers: MutableMap<String, String>,
            name: String,
            value: String,
        ) {
            val existing = headers.keys.firstOrNull { it.equals(name, ignoreCase = true) }
            headers[existing ?: name] = value
        }

        private fun hasJsonContentType(headers: Map<String, List<String>>): Boolean =
            headers.entries
                .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
                ?.value
                ?.any { it.substringBefore(';').trim().equals("application/json", true) }
                ?: false
    }
}

/** Failure returned by [DaToriiClient]. */
class DaToriiException : RuntimeException {
    constructor(message: String) : super(message)
    constructor(message: String, cause: Throwable) : super(message, cause)
}
