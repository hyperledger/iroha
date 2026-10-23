package org.hyperledger.iroha.sdk.client.stream

import java.net.URI
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.CanonicalRequestSigner
import org.hyperledger.iroha.sdk.client.ClientConfig
import org.hyperledger.iroha.sdk.client.HttpClientTransport
import org.hyperledger.iroha.sdk.client.HttpTransportExecutor
import org.hyperledger.iroha.sdk.client.LocalSigningContext
import org.hyperledger.iroha.sdk.client.RequestSigner
import org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Local HTTP opt-in preserves canonical signing, authority confinement, and live-stream rules. */
class ToriiEventStreamLocalDevelopmentHttpTest {
    @Test
    fun optedInStandaloneStreamsRetainExactCanonicalSigning() {
        for (baseUri in listOf("http://localhost:8080", "http://172.16.0.2:8080")) {
            val executor = RecordingExecutor()
            val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            streamBuilder(baseUri, executor, keys)
                .setAllowLocalDevelopmentHttp(true)
                .build().use { client ->
                    client.openSseStream(
                        "/v1/contracts/events/sse?z=last",
                        ToriiEventStreamOptions.builder().putQueryParameter("kind", "applied").build(),
                        listener(),
                    ).completion().get(1, TimeUnit.SECONDS)
                }
            val request = executor.requests.single()
            assertEquals("$baseUri/v1/contracts/events/sse?z=last&kind=applied", request.uri.toString())
            assertSignedRequest(request, keys)
        }
    }

    @Test
    fun signedStreamsCreatedFromHttpClientInheritItsLocalHttpOptIn() {
        val executor = RecordingExecutor()
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val config = ClientConfig.builder()
            .setBaseUri(URI.create("http://127.0.0.1:8080"))
            .setAllowLocalDevelopmentHttp(true)
            .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical()))
            .build()
        HttpClientTransport(executor, config).use { transport ->
            transport.newEventStreamClient(auth(keys)).use { client ->
                client.openSseStream("/v1/events/sse", null, listener())
                    .completion().get(1, TimeUnit.SECONDS)
            }
        }
        assertSignedRequest(executor.requests.single(), keys)
    }

    @Test
    fun credentialedStreamsCreatedFromHttpClientInheritItsLocalHttpOptIn() {
        val executor = RecordingExecutor()
        val config = ClientConfig.builder()
            .setBaseUri(URI.create("http://192.168.1.2:8080"))
            .setAllowLocalDevelopmentHttp(true)
            .putDefaultHeader("Authorization", "Bearer dev-token")
            .build()
        HttpClientTransport(executor, config).use { transport ->
            transport.newEventStreamClient().use { client ->
                client.openSseStream("/v1/events/sse", null, listener())
                    .completion().get(1, TimeUnit.SECONDS)
            }
        }
        val request = executor.requests.single()
        assertEquals("Bearer dev-token", request.headers["Authorization"]?.single())
        assertEquals(RequestReplayPolicy.RETRY_SAFE, request.replayPolicy)
    }

    @Test
    fun signedStreamsRequireOptInAndStayConfinedToConfiguredLocalAuthority() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        for ((baseUri, path, optIn) in listOf(
            Triple("http://localhost:8080", "/v1/events/sse", false),
            Triple("http://example.com:8080", "/v1/events/sse", true),
            Triple("http://localhost:8080", "http://127.0.0.1:8080/v1/events/sse", true),
            Triple("http://localhost:8080", "http://localhost:8081/v1/events/sse", true),
            Triple("https://localhost:8080", "http://localhost:8080/v1/events/sse", true),
        )) {
            val executor = RecordingExecutor()
            streamBuilder(baseUri, executor, keys)
                .apply { if (optIn) setAllowLocalDevelopmentHttp(true) }
                .build().use { client ->
                    assertFailsWith<IllegalArgumentException> {
                        client.openSseStream(path, null, listener())
                    }
                }
            assertTrue(executor.requests.isEmpty(), "rejected signed stream must not reach the executor")
        }
    }

    @Test
    fun localOptInPreservesCanonicalReplayAndPrecomputedHeaderRejections() {
        val executor = RecordingExecutor()
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        streamBuilder("http://localhost:8080", executor, keys)
            .setAllowLocalDevelopmentHttp(true)
            .build().use { client ->
                for ((header, value, message) in listOf(
                    Triple("Last-Event-ID", "previous-event", "no replay log"),
                    Triple("x-iroha-signature", "precomputed", "canonicalRequestAuth"),
                )) {
                    val options = ToriiEventStreamOptions.builder().putHeader(header, value).build()
                    val failure = assertFailsWith<IllegalArgumentException> {
                        client.openSseStream("/v1/events/sse", options, listener())
                    }
                    assertContains(failure.message.orEmpty(), message)
                }
            }
        assertTrue(executor.requests.isEmpty())
    }

    private fun streamBuilder(baseUri: String, executor: RecordingExecutor, keys: KeyPair) =
        ToriiEventStreamClient.builder()
            .setBaseUri(URI.create(baseUri))
            .setTransportExecutor(executor)
            .canonicalRequestAuth(LocalSigningContext(TestNetworkIds.canonical()), auth(keys))

    private fun auth(keys: KeyPair) = ToriiCanonicalRequestAuth(
        "alice@universal",
        RequestSigner.ed25519(keys.private),
        TIMESTAMP_MS,
        NONCE,
    )

    private fun assertSignedRequest(request: TransportRequest, keys: KeyPair) {
        assertEquals("alice@universal", request.headers[CanonicalRequestSigner.HEADER_ACCOUNT]?.single())
        assertEquals(TIMESTAMP_MS.toString(), request.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]?.single())
        assertEquals(NONCE, request.headers[CanonicalRequestSigner.HEADER_NONCE]?.single())
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        val signature = assertNotNull(request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]?.single())
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keys.public)
        verifier.update(CanonicalRequestSigner.canonicalRequestSignatureMessage(
            TestNetworkIds.canonical(), "GET", request.uri, null, TIMESTAMP_MS, NONCE,
        ))
        assertTrue(verifier.verify(Base64.getDecoder().decode(signature)))
    }

    private fun listener() = object : ToriiEventStreamListener {
        override fun onEvent(event: ServerSentEvent) {}
    }

    private class RecordingExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            return CompletableFuture.completedFuture(
                TransportResponse.builder().setStatusCode(200).setBody(ByteArray(0)).build(),
            )
        }
    }

    private companion object {
        const val TIMESTAMP_MS = 1_700_000_000_000L
        const val NONCE = "local-development-stream"
    }
}
