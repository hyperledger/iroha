package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse

/** Generic and onboarding routes enforce the same explicit local HTTP exception as signed routes. */
class HttpClientTransportCredentialAdmissionTest {
    @Test
    fun credentialedGenericAndOnboardingRequestsRequireOptIn() {
        for (operation in Operation.values()) {
            for (baseUri in listOf("http://localhost:8080/api", "http://192.168.1.2:8080/api")) {
                val executor = RecordingExecutor()
                HttpClientTransport(executor, config(baseUri, null, operation)).use { client ->
                    assertFailsWith<IllegalArgumentException>(operation.name) { operation.dispatch(client) }
                }
                assertTrue(executor.requests.isEmpty(), "${operation.name} must fail before dispatch")
            }
        }
    }

    @Test
    fun credentialedGenericAndOnboardingRequestsAllowOnlyOptedInLocalHttpOrHttps() {
        for (operation in Operation.values()) {
            for ((baseUri, optIn) in listOf(
                "http://localhost:8080/api" to true,
                "http://192.168.1.2:8080/api" to true,
                "https://torii.example/api" to false,
            )) {
                val executor = RecordingExecutor()
                HttpClientTransport(executor, config(baseUri, optIn, operation)).use { client ->
                    assertFalse(operation.dispatch(client).isDone)
                    val request = executor.requests.single()
                    assertEquals(baseUri + operation.path, request.uri.toString())
                    assertEquals(operation.method, request.method)
                    if (operation == Operation.ONBOARDING_GET) {
                        assertEquals(TOKEN, request.headers["X-Iroha-Onboarding-Token"]?.single())
                        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
                    } else {
                        assertEquals("Bearer development", request.headers["Authorization"]?.single())
                        assertEquals(
                            if (operation.method == "POST") RequestReplayPolicy.ONE_SHOT else RequestReplayPolicy.RETRY_SAFE,
                            request.replayPolicy,
                        )
                    }
                }
            }
        }
    }

    @Test
    fun credentialedGenericAndOnboardingRequestsRejectPublicHttpDespiteOptIn() {
        for (operation in Operation.values()) {
            for (baseUri in listOf("http://torii.example/api", "http://203.0.113.1/api")) {
                val executor = RecordingExecutor()
                HttpClientTransport(executor, config(baseUri, true, operation)).use { client ->
                    assertFailsWith<IllegalArgumentException>(operation.name) { operation.dispatch(client) }
                }
                assertTrue(executor.requests.isEmpty(), "${operation.name} must fail before dispatch")
            }
        }
    }

    @Test
    fun configuredOnboardingTokenIsSensitiveRegardlessOfHeaderCase() {
        val executor = RecordingExecutor()
        val config = ClientConfig.builder()
            .setBaseUri(URI.create("http://localhost:8080"))
            .putDefaultHeader("x-IROHA-onboarding-TOKEN", TOKEN)
            .build()
        HttpClientTransport(executor, config).use { client ->
            assertFailsWith<IllegalArgumentException> { client.listIdentifierPolicies() }
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun anonymousGenericReadsKeepTheirExistingHttpBehavior() {
        val executor = RecordingExecutor()
        HttpClientTransport(
            executor,
            ClientConfig.builder().setBaseUri(URI.create("http://torii.example")).build(),
        ).use { client ->
            assertFalse(client.listIdentifierPolicies().isDone)
            assertEquals("http://torii.example/v1/identifier-policies", executor.requests.single().uri.toString())
        }
    }

    private fun config(baseUri: String, optIn: Boolean?, operation: Operation): ClientConfig =
        ClientConfig.builder().setBaseUri(URI.create(baseUri))
            .apply {
                if (optIn != null) setAllowLocalDevelopmentHttp(optIn)
                if (operation != Operation.ONBOARDING_GET) putDefaultHeader("Authorization", "Bearer development")
            }.build()

    private enum class Operation(val method: String, val path: String) {
        JSON_GET("GET", "/v1/identifier-policies"),
        JSON_POST("POST", "/v1/aliases/resolve"),
        NORITO_GET("GET", "/v1/ledger/block/1"),
        ONBOARDING_GET("GET", "/v1/accounts/onboarding/readiness");

        fun dispatch(client: HttpClientTransport): CompletableFuture<*> = when (this) {
            JSON_GET -> client.listIdentifierPolicies()
            JSON_POST -> client.resolveAccountAlias("alice@universal")
            NORITO_GET -> client.getLedgerExecutedBlockWire(1L)
            ONBOARDING_GET -> client.getAccountOnboardingReadiness(TOKEN)
        }
    }

    /** Leave admitted requests pending so assertions isolate admission from response parsing. */
    private class RecordingExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            return CompletableFuture()
        }
    }

    private companion object {
        val TOKEN = "development-onboarding-token-12345678"
    }
}
