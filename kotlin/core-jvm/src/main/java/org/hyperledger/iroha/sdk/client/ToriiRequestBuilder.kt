package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.time.Duration
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.tx.SignedTransaction
import org.hyperledger.iroha.sdk.tx.norito.NoritoException
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder

/** Builds Torii HTTP requests for submitting signed transactions. */
internal object ToriiRequestBuilder {
    private const val SUBMIT_PATH = "/v1/pipeline/transactions"
    private const val SUBMIT_ENTRYPOINT_PATH = "/v1/pipeline/transaction-entrypoints"
    private const val STATUS_PATH = "/v1/pipeline/transactions/status"
    private val TRANSACTION_HASH = Regex("[0-9a-f]{63}[13579bdf]")

    @JvmStatic
    fun buildSubmitRequest(
        baseUri: URI,
        transaction: SignedTransaction,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        acceptHeader: String = WireFormatPreference.NORITO_PREFERRED.acceptHeader(),
        allowLocalDevelopmentHttp: Boolean = false,
    ): TransportRequest {
        val target = resolve(baseUri, SUBMIT_PATH)
        val norito: ByteArray
        try {
            norito = SignedTransactionEncoder.encodeVersioned(transaction)
        } catch (ex: NoritoException) {
            throw IllegalStateException("Failed to encode signed transaction", ex)
        }
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            baseUri,
            target,
            extraHeaders,
            norito,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .addHeader("Content-Type", "application/x-norito")
            .addHeader("Accept", acceptHeader)
            .setBody(norito)
        applyHeaders(builder, extraHeaders)
        applyTimeout(builder, timeout)
        return builder.build()
    }

    @JvmStatic
    fun buildSubmitJsonRequest(
        baseUri: URI,
        encodedVersionedTransactionJson: ByteArray,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        acceptHeader: String = WireFormatPreference.NORITO_PREFERRED.acceptHeader(),
        allowLocalDevelopmentHttp: Boolean = false,
    ): TransportRequest =
        buildJsonIngressRequest(
            baseUri,
            SUBMIT_PATH,
            encodedVersionedTransactionJson,
            timeout,
            extraHeaders,
            acceptHeader,
            "encodedVersionedTransactionJson",
            allowLocalDevelopmentHttp,
        )

    @JvmStatic
    fun buildSubmitEntrypointRequest(
        baseUri: URI,
        encodedVersionedEntrypoint: ByteArray,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        acceptHeader: String = WireFormatPreference.NORITO_PREFERRED.acceptHeader(),
        allowLocalDevelopmentHttp: Boolean = false,
    ): TransportRequest {
        require(encodedVersionedEntrypoint.isNotEmpty()) {
            "encodedVersionedEntrypoint must not be empty"
        }
        val target = resolve(baseUri, SUBMIT_ENTRYPOINT_PATH)
        val body = encodedVersionedEntrypoint.copyOf()
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            baseUri,
            target,
            extraHeaders,
            body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .addHeader("Content-Type", "application/x-norito")
            .addHeader("Accept", acceptHeader)
            .setBody(body)
        applyHeaders(builder, extraHeaders)
        applyTimeout(builder, timeout)
        return builder.build()
    }

    @JvmStatic
    fun buildSubmitEntrypointJsonRequest(
        baseUri: URI,
        encodedVersionedEntrypointJson: ByteArray,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        acceptHeader: String = WireFormatPreference.NORITO_PREFERRED.acceptHeader(),
        allowLocalDevelopmentHttp: Boolean = false,
    ): TransportRequest =
        buildJsonIngressRequest(
            baseUri,
            SUBMIT_ENTRYPOINT_PATH,
            encodedVersionedEntrypointJson,
            timeout,
            extraHeaders,
            acceptHeader,
            "encodedVersionedEntrypointJson",
            allowLocalDevelopmentHttp,
        )

    @JvmStatic
    fun buildStatusRequest(
        baseUri: URI,
        hashHex: String,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        allowLocalDevelopmentHttp: Boolean = false,
    ): TransportRequest {
        requireTransactionHash(hashHex)
        val target = resolve(baseUri, "$STATUS_PATH?hash=$hashHex&scope=global")
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            baseUri,
            target,
            extraHeaders,
            null,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("GET")
            .addHeader("Accept", "application/json")
        applyHeaders(builder, extraHeaders)
        applyTimeout(builder, timeout)
        return builder.build()
    }

    private fun buildJsonIngressRequest(
        baseUri: URI,
        path: String,
        bodyBytes: ByteArray,
        timeout: Duration?,
        extraHeaders: Map<String, String>?,
        acceptHeader: String,
        bodyName: String,
        allowLocalDevelopmentHttp: Boolean,
    ): TransportRequest {
        require(bodyBytes.isNotEmpty()) { "$bodyName must not be empty" }
        val target = resolve(baseUri, path)
        val body = bodyBytes.copyOf()
        TransportSecurity.requireHttpRequestAllowed(
            "HttpClientTransport",
            baseUri,
            target,
            extraHeaders,
            body,
            allowLocalDevelopmentHttp = allowLocalDevelopmentHttp,
        )
        val builder = TransportRequest.builder()
            .setUri(target)
            .setMethod("POST")
            .addHeader("Content-Type", "application/json")
            .addHeader("Accept", acceptHeader)
            .setBody(body)
        applyHeaders(builder, extraHeaders)
        applyTimeout(builder, timeout)
        return builder.build()
    }

    /** Reject anything but a canonical lowercase marked 32-byte transaction hash. */
    fun requireTransactionHash(hashHex: String) {
        require(TRANSACTION_HASH.matches(hashHex)) {
            "hashHex must be a canonical lowercase marked 32-byte transaction hash"
        }
    }

    private fun resolve(baseUri: URI, path: String): URI {
        val base = baseUri.toString()
        val normalizedPath = if (path.startsWith("/")) path.substring(1) else path
        val joined = if (base.endsWith("/")) base + normalizedPath else "$base/$normalizedPath"
        return URI.create(joined)
    }

    private fun applyHeaders(builder: TransportRequest.Builder, headers: Map<String, String>?) {
        if (headers.isNullOrEmpty()) return
        for ((key, value) in headers) {
            builder.addHeader(key, value)
        }
    }

    private fun applyTimeout(builder: TransportRequest.Builder, timeout: Duration?) {
        if (timeout == null || timeout.isZero || timeout.isNegative) return
        builder.setTimeout(timeout)
    }
}
