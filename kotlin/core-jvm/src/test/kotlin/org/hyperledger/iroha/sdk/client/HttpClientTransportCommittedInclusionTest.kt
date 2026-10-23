package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse

class HttpClientTransportCommittedInclusionTest {
    private class RecordingExecutor(
        private val status: Int,
        private val responseBody: ByteArray,
        private val contentType: String,
        private val redirect: Boolean = false,
        private val finalUriOverride: URI? = null,
    ) : HttpTransportExecutor {
        lateinit var request: TransportRequest
        var count = 0

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            this.request = request
            count += 1
            return CompletableFuture.completedFuture(
                TransportResponse.builder()
                    .setStatusCode(status)
                    .setBody(responseBody)
                    .addHeader("Content-Type", contentType)
                    .addHeader("Content-Encoding", "identity")
                    .setNetworkProvenance(finalUriOverride ?: request.uri, redirect)
                    .build(),
            )
        }
    }

    private fun transport(executor: RecordingExecutor, url: String = "https://torii.example/boi", allowLocalHttp: Boolean = false): HttpClientTransport =
        HttpClientTransport(
            executor = executor,
            config = ClientConfig.builder()
                .setBaseUri(URI.create(url))
                .setAllowLocalDevelopmentHttp(allowLocalHttp)
                .putDefaultHeader("X-Dataspace-Id", "is2")
                .build(),
        )

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example/boi", "http://127.0.0.1/boi", "http://10.0.2.2/boi"])
    fun signedSelectiveQueryIsOneShotAndRetainsUrlPrefixAndTenantHeader(baseUri: String) {
        val wire = byteArrayOf(0x11, 0x22, 0x33)
        val response = byteArrayOf(0x44, 0x55)
        val executor = RecordingExecutor(200, response, "application/x-norito")

        assertContentEquals(response, transport(executor, baseUri, baseUri.startsWith("http:")).postSignedCommittedTransactionQuery(wire).join())

        assertEquals(1, executor.count)
        assertEquals("$baseUri/v1/query", executor.request.uri.toASCIIString())
        assertEquals("POST", executor.request.method)
        assertContentEquals(wire, executor.request.body)
        assertEquals(RequestReplayPolicy.ONE_SHOT, executor.request.replayPolicy)
        assertEquals("application/x-norito", executor.request.headers["Content-Type"]?.single())
        assertEquals("application/x-norito", executor.request.headers["Accept"]?.single())
        assertEquals("identity", executor.request.headers["Accept-Encoding"]?.single())
        assertEquals("no-store", executor.request.headers["Cache-Control"]?.single())
        assertEquals("is2", executor.request.headers["X-Dataspace-Id"]?.single())
    }

    @Test
    fun signedSelectiveQueryRejectsRedirectAndDifferentResponseUrl() {
        for (executor in listOf(
            RecordingExecutor(200, byteArrayOf(1), "application/x-norito", redirect = true),
            RecordingExecutor(200, byteArrayOf(1), "application/x-norito", finalUriOverride = URI.create("https://other.example/query")),
        )) {
            val error = assertFailsWith<CompletionException> {
                transport(executor).postSignedCommittedTransactionQuery(byteArrayOf(1)).join()
            }
            assertTrue(error.cause?.message?.contains("exact signed URL") == true)
            assertEquals(1, executor.count)
        }
    }

    @Test
    fun signedSelectiveQueryRejectsInsecureBaseBeforeDispatch() {
        val executor = RecordingExecutor(200, byteArrayOf(1), "application/x-norito")
        assertFailsWith<IllegalArgumentException> {
            transport(executor, "http://torii.example/boi")
                .postSignedCommittedTransactionQuery(byteArrayOf(1))
        }
        assertEquals(0, executor.count)
    }

    @Test
    fun opaqueSignedRequestsAndFinalityReadsKeepTheDefaultAndRemoteHttpRefusal() {
        for ((url, enabled) in listOf(
            "http://localhost" to false,
            "http://192.168.1.2" to false,
            "http://torii.example" to true,
            "http://203.0.113.1" to true,
        )) {
            val executor = RecordingExecutor(200, byteArrayOf(1), "application/x-norito")
            val client = transport(executor, url, enabled)
            assertFailsWith<IllegalArgumentException> {
                client.postSignedCommittedTransactionQuery(byteArrayOf(1))
            }
            assertFailsWith<IllegalArgumentException> { client.getBridgeFinalityBundleJson(42) }
            assertEquals(0, executor.count)
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example/boi", "http://127.0.0.1/boi", "http://192.168.1.2/boi"])
    fun finalityBundleReadPreservesPrefixAndRequiresExactUrl(baseUri: String) {
        val bundle = "{\"commitment\":{}}".toByteArray()
        val executor = RecordingExecutor(200, bundle, "application/json")

        assertContentEquals(bundle, transport(executor, baseUri, baseUri.startsWith("http:")).getBridgeFinalityBundleJson(42).join())
        assertEquals("$baseUri/v1/bridge/finality/bundle/42", executor.request.uri.toASCIIString())
        assertEquals("GET", executor.request.method)
        assertEquals(RequestReplayPolicy.RETRY_SAFE, executor.request.replayPolicy)
        assertEquals("application/json", executor.request.headers["Accept"]?.single())

        val redirected = RecordingExecutor(200, bundle, "application/json", redirect = true)
        assertFailsWith<CompletionException> {
            transport(redirected, baseUri, baseUri.startsWith("http:")).getBridgeFinalityBundleJson(42).join()
        }
        assertEquals(1, redirected.count)
    }
}
