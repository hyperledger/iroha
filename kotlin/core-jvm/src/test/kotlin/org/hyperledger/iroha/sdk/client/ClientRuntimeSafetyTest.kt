package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicInteger
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.telemetry.CrashTelemetryHandler
import org.hyperledger.iroha.sdk.telemetry.TelemetryOptions
import org.hyperledger.iroha.sdk.telemetry.TelemetryRecord
import org.hyperledger.iroha.sdk.telemetry.TelemetrySink
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Regression tests for client lifecycle and transport-safety defects. */
class ClientRuntimeSafetyTest {
    @Test
    fun crashTelemetryInstallsOneHandlerNoMatterHowOftenConfigsAreBuilt() {
        val original = Thread.getDefaultUncaughtExceptionHandler()
        val delegateCalls = AtomicInteger()
        Thread.setDefaultUncaughtExceptionHandler { _, _ -> delegateCalls.incrementAndGet() }
        try {
            val captures = AtomicInteger()
            val sink = object : TelemetrySink {
                override fun onRequest(record: TelemetryRecord) = Unit
                override fun onResponse(record: TelemetryRecord, response: ClientResponse) = Unit
                override fun onFailure(record: TelemetryRecord, error: Throwable) = Unit
                override fun emitSignal(signalId: String, fields: Map<String, Any>) {
                    if (signalId == "android.crash.report.capture") captures.incrementAndGet()
                }
            }
            val config = ClientConfig.builder()
                .setTelemetryOptions(TelemetryOptions(true))
                .setTelemetrySink(sink)
                .enableCrashTelemetryHandler()
                .build()
            config.toBuilder().build()
            HttpClientTransport.withDirectoryPendingQueue(config, java.nio.file.Files.createTempDirectory("queue"))

            val handler = assertIs<CrashTelemetryHandler>(Thread.getDefaultUncaughtExceptionHandler())
            handler.uncaughtException(Thread.currentThread(), IllegalStateException("boom"))

            assertEquals(1, captures.get(), "one crash is reported once")
            assertEquals(1, delegateCalls.get(), "the application handler still runs exactly once")
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(original)
        }
    }

    @Test
    fun plaintextIsOnlyAllowedToLocalDevelopmentHostsAfterOptIn() {
        val credentials = mapOf(CanonicalRequestSigner.HEADER_ACCOUNT to "alice@wonderland")
        for (host in listOf("localhost", "LOCALHOST", "node.localhost", "127.0.0.1", "127.255.0.9", "[::1]", "10.0.0.1")) {
            assertTrue(TransportSecurity.isLocalDevelopmentHost(host), host)
            val uri = URI("http://$host:8080/v1/domains/query")
            TransportSecurity.requireHttpRequestAllowed("test", uri, uri, credentials, null, allowLocalDevelopmentHttp = true)
            assertFailsWith<IllegalArgumentException>(host) {
                TransportSecurity.requireHttpRequestAllowed("test", uri, uri, credentials, null)
            }
        }
        for (host in listOf("torii.example", "127.0.0.1.example", "128.0.0.1", "11.0.0.1", "localhost.example")) {
            assertFalse(TransportSecurity.isLocalDevelopmentHost(host), host)
            val uri = URI("http://$host/v1/domains/query")
            assertFailsWith<IllegalArgumentException>(host) {
                TransportSecurity.requireHttpRequestAllowed("test", uri, uri, credentials, null, allowLocalDevelopmentHttp = true)
            }
        }
        val anonymous = URI("http://torii.example/v1/domains/query")
        TransportSecurity.requireHttpRequestAllowed("test", anonymous, anonymous, emptyMap(), null)
    }

    @Test
    fun explicitCanonicalNoncesAreSingleUse() {
        val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signer = RequestSigner.ed25519(keys.private)
        val uri = URI("https://torii.example/v1/domains/query")
        val networkId = TestNetworkIds.canonical()

        val fixed = ToriiCanonicalRequestAuth("alice@wonderland", signer, 1_700_000_000_000L, "nonce-1")
        assertTrue(fixed.hasExplicitFreshness)
        assertEquals("nonce-1", fixed.headers(networkId, "POST", uri, ByteArray(0))[CanonicalRequestSigner.HEADER_NONCE])
        assertFailsWith<IllegalStateException> { fixed.headers(networkId, "POST", uri, ByteArray(0)) }

        val fresh = ToriiCanonicalRequestAuth("alice@wonderland", signer)
        val first = fresh.headers(networkId, "POST", uri, ByteArray(0))
        val second = fresh.headers(networkId, "POST", uri, ByteArray(0))
        assertNotEquals(first[CanonicalRequestSigner.HEADER_NONCE], second[CanonicalRequestSigner.HEADER_NONCE])

        assertFailsWith<IllegalArgumentException> { ToriiCanonicalRequestAuth("alice@wonderland", signer, 1L, null) }
        assertFailsWith<IllegalArgumentException> { ToriiCanonicalRequestAuth("alice@wonderland", signer, -1L, "n") }
    }

    @Test
    fun statusPollingWithZeroIntervalAndSynchronousTransportDoesNotRecurse() {
        val hash = "a".repeat(63) + "b"
        val pending = 20_000
        val polls = AtomicInteger()
        val executor = object : HttpTransportExecutor {
            override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
                val poll = polls.incrementAndGet()
                val response = if (poll <= pending) {
                    TransportResponse.builder().setStatusCode(404).build()
                } else {
                    TransportResponse.builder()
                        .setStatusCode(200)
                        .setBody(
                            """{"hash":"$hash","status":{"kind":"Applied","block_height":5},"scope":"global","resolved_from":"state"}"""
                                .toByteArray(StandardCharsets.UTF_8),
                        )
                        .build()
                }
                return CompletableFuture.completedFuture(response)
            }
        }
        val client = HttpClientTransport(executor, ClientConfig.builder().setBaseUri(URI("https://torii.example")).build())

        val status = client.waitForTransactionStatus(hash, PipelineStatusOptions(0L, null, null, null)).join()

        assertEquals(pending + 1, polls.get())
        assertEquals("state", status["resolved_from"])
    }
}
