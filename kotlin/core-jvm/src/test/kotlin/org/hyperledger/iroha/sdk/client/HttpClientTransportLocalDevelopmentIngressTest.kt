package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse

/** Credentialed ingress and status calls inherit the explicit local HTTP policy. */
class HttpClientTransportLocalDevelopmentIngressTest {
    @Test
    fun localHttpOptInPropagatesToEveryEncodedIngressAndItsCapabilityProbe() {
        for (baseUri in listOf("http://localhost:8080", "http://192.168.1.20:8080")) {
            for (operation in Ingress.values()) {
                val executor = RecordingExecutor()
                HttpClientTransport(executor, config(baseUri, true)).use { client ->
                    assertEquals(202, operation.submit(client, BODY).join().statusCode)
                }
                assertEquals(2, executor.requests.size)
                assertEquals("/v1/node/capabilities", executor.requests.first().uri.path)
                val submission = executor.requests.last()
                assertEquals(baseUri + operation.path, submission.uri.toString())
                assertEquals(operation.contentType, submission.headers["Content-Type"]?.single())
                assertContentEquals(BODY, submission.body)
                for (request in executor.requests) {
                    assertEquals("Bearer dev-token", request.headers["Authorization"]?.single())
                    assertEquals(
                        if (request.method == "POST") RequestReplayPolicy.ONE_SHOT else RequestReplayPolicy.RETRY_SAFE,
                        request.replayPolicy,
                    )
                }
            }
        }
    }

    @Test
    fun credentialedIngressRequiresOptInAndStillRejectsPublicHttp() {
        for ((baseUri, optIn) in listOf(
            "http://localhost:8080" to false,
            "http://192.168.1.20:8080" to false,
            "http://example.com:8080" to true,
            "http://8.8.8.8:8080" to true,
        )) {
            for (operation in Ingress.values()) {
                val executor = RecordingExecutor()
                HttpClientTransport(executor, config(baseUri, optIn)).use { client ->
                    assertFailsWith<IllegalArgumentException> { operation.submit(client, BODY) }
                }
                assertTrue(executor.requests.isEmpty(), "rejected ingress must not reach the executor")
            }
        }
    }

    @Test
    fun credentialedStatusPollingInheritsLocalHttpOptIn() {
        val executor = RecordingExecutor()
        HttpClientTransport(executor, config("http://127.0.0.1:8080", true)).use { client ->
            val payload = client.waitForTransactionStatus(HASH, null).join()
            assertEquals("state", payload["resolved_from"])
        }
        val request = executor.requests.single()
        assertEquals("http://127.0.0.1:8080/v1/pipeline/transactions/status?hash=$HASH&scope=global", request.uri.toString())
        assertEquals("Bearer dev-token", request.headers["Authorization"]?.single())
        assertEquals(RequestReplayPolicy.RETRY_SAFE, request.replayPolicy)
    }

    @Test
    fun credentialedStatusPollingRejectsDefaultLocalAndOptedInPublicHttp() {
        for ((baseUri, optIn) in listOf(
            "http://127.0.0.1:8080" to false,
            "http://example.com:8080" to true,
        )) {
            val executor = RecordingExecutor()
            HttpClientTransport(executor, config(baseUri, optIn)).use { client ->
                val error = assertFailsWith<CompletionException> {
                    client.waitForTransactionStatus(HASH, null).join()
                }
                assertTrue(error.cause is IllegalArgumentException)
            }
            assertTrue(executor.requests.isEmpty())
        }
    }

    private enum class Ingress(val path: String, val contentType: String) {
        TRANSACTION_JSON("/v1/pipeline/transactions", "application/json"),
        ENTRYPOINT_JSON("/v1/pipeline/transaction-entrypoints", "application/json"),
        ENTRYPOINT_NORITO("/v1/pipeline/transaction-entrypoints", "application/x-norito");

        fun submit(client: HttpClientTransport, body: ByteArray): CompletableFuture<ClientResponse> = when (this) {
            TRANSACTION_JSON -> client.submitTransactionJson(body)
            ENTRYPOINT_JSON -> client.submitTransactionEntrypointJson(body)
            ENTRYPOINT_NORITO -> client.submitTransactionEntrypoint(body)
        }
    }

    private class RecordingExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            val (status, body) = when (request.uri.path) {
                "/v1/node/capabilities" -> 200 to
                    """{"data_model_version":${ToriiTransactionCompatibility.EXPECTED_DATA_MODEL_VERSION},"signed_transaction_schema_hash_hex":"${ToriiTransactionCompatibility.EXPECTED_SIGNED_TRANSACTION_SCHEMA_HASH_HEX}"}"""
                "/v1/pipeline/transactions/status" -> 200 to
                    """{"hash":"$HASH","status":{"kind":"Applied","block_height":7},"scope":"global","resolved_from":"state"}"""
                else -> 202 to ""
            }
            return CompletableFuture.completedFuture(
                TransportResponse.builder().setStatusCode(status).setBody(body.toByteArray()).build(),
            )
        }
    }

    private companion object {
        val HASH = "1".repeat(64)
        val BODY = """{"version":1,"content":{}}""".toByteArray()

        fun config(baseUri: String, optIn: Boolean): ClientConfig = ClientConfig.builder()
            .setBaseUri(URI.create(baseUri))
            .setAllowLocalDevelopmentHttp(optIn)
            .putDefaultHeader("Authorization", "Bearer dev-token")
            .build()
    }
}
