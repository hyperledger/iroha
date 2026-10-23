package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Exercises the local HTTP exception through public derived-client APIs and factories. */
class DerivedHttpClientsLocalDevelopmentTest {
    private val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val context = LocalSigningContext(TestNetworkIds.canonical())
    private val identifier = AtomicPrivateSettlementIdentifierV1.fromBytes(ByteArray(32) { 1 })
    private val auth = ToriiCanonicalRequestAuth(
        "alice@universal",
        RequestSigner.ed25519(keyPair.private),
    )

    @Test
    fun configOptInReachesEveryDerivedHttpClient() {
        for (base in listOf("http://127.0.0.1:8080", "http://192.168.1.2:8080")) {
            for (client in ClientKind.values()) {
                val executor = CapturingExecutor(identifier)
                dispatchConfigured(client, base, true, executor)
                assertEquals(1, executor.requests.size, "$client at $base")
                val request = executor.requests.single()
                assertEquals(URI.create(base).host, request.uri.host)
                assertEquals(8080, request.uri.port)
                assertEquals("http", request.uri.scheme)
                if (client.signed) assertCanonicalSignature(request)
                else assertEquals(listOf("Bearer local-test"), request.headers["Authorization"])
            }
        }
    }

    @Test
    fun noExecutorConfigFactoriesUseTheLocalHttpOptIn() {
        MockWebServer().use { server ->
            server.start()
            val config = ClientConfig.builder()
                .setBaseUri(server.url("/").toUri())
                .setAllowLocalDevelopmentHttp(true)
                .putDefaultHeader("Authorization", "Bearer local-test")
                .build()
            server.enqueue(MockResponse().setResponseCode(404))
            config.toSubscriptionToriiClient().use { assertNull(it.getSubscription("subscription-1").join()) }
            assertEquals("/v1/subscriptions/subscription-1", server.takeRequest().path)
            server.enqueue(MockResponse().setBody("rpc-response"))
            config.toNoritoRpcClient().use {
                assertContentEquals("rpc-response".toByteArray(), it.call("/rpc", byteArrayOf(1)))
            }
            assertEquals("/rpc", server.takeRequest().path)
        }
    }

    @Test
    fun configDefaultsRejectCredentialedLocalHttpForEveryDerivedClient() {
        for (client in ClientKind.values()) {
            val executor = CapturingExecutor(identifier)
            assertFailsWith<IllegalArgumentException>(client.name) {
                dispatchConfigured(client, "http://127.0.0.1:8080", null, executor)
            }
            assertTrue(executor.requests.isEmpty(), client.name)
        }
    }

    @Test
    fun optInNeverAllowsPublicHttpForDerivedClients() {
        for (client in ClientKind.values()) {
            val executor = CapturingExecutor(identifier)
            assertFailsWith<IllegalArgumentException>(client.name) {
                dispatchConfigured(client, "http://8.8.8.8:8080", true, executor)
            }
            assertTrue(executor.requests.isEmpty(), client.name)
        }
    }

    @Test
    fun standaloneBuildersKeepTheExceptionOffByDefault() {
        for (client in ClientKind.values()) {
            val executor = CapturingExecutor(identifier)
            assertFailsWith<IllegalArgumentException>(client.name) {
                dispatchStandalone(client, null, executor)
            }
            assertTrue(executor.requests.isEmpty(), client.name)
        }
    }

    @Test
    fun standaloneBuildersSupportExplicitLocalOptIn() {
        for (client in ClientKind.values()) {
            val executor = CapturingExecutor(identifier)
            dispatchStandalone(client, true, executor)
            assertEquals(1, executor.requests.size, client.name)
            if (client.signed) assertCanonicalSignature(executor.requests.single())
        }
    }

    @Test
    fun noritoRpcOptInRetainsSchemeHostAndPortBoundaries() {
        val executor = CapturingExecutor(identifier)
        ClientConfig.builder()
            .setBaseUri(URI.create("http://127.0.0.1:8080"))
            .setAllowLocalDevelopmentHttp(true)
            .putDefaultHeader("Authorization", "Bearer local-test")
            .build()
            .toNoritoRpcClient(executor).use { client ->
                for (target in listOf(
                    "http://127.0.0.2:8080/rpc",
                    "http://127.0.0.1:8081/rpc",
                    "https://127.0.0.1:8080/rpc",
                    "http://8.8.8.8:8080/rpc",
                )) {
                    assertFailsWith<IllegalArgumentException>(target) {
                        client.call(target, byteArrayOf(1))
                    }
                }
            }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun localToriiOptInPreservesTheSorafsGatewayOriginContract() {
        val executor = CapturingExecutor(identifier)
        val config = ClientConfig.builder()
            .setBaseUri(URI.create("http://127.0.0.1:8080"))
            .setAllowLocalDevelopmentHttp(true)
            .build()
        HttpClientTransport(executor, config).use { transport ->
            assertFailsWith<IllegalArgumentException> { transport.newSorafsGatewayClient() }
        }
        assertTrue(executor.requests.isEmpty())
    }

    private fun dispatchConfigured(
        kind: ClientKind,
        base: String,
        allow: Boolean?,
        executor: CapturingExecutor,
    ) {
        val builder = ClientConfig.builder()
            .setBaseUri(URI.create(base))
            .setLocalSigningContext(context)
        if (allow != null) builder.setAllowLocalDevelopmentHttp(allow)
        if (!kind.signed) builder.putDefaultHeader("Authorization", "Bearer local-test")
        val config = builder.build()
        when (kind) {
            ClientKind.NORITO -> config.toNoritoRpcClient(executor).use {
                assertContentEquals(byteArrayOf(1), it.call("/rpc", byteArrayOf(1)))
            }
            ClientKind.CONFIDENTIAL -> config.toConfidentialAssetToriiClient(executor).use {
                it.getZkAssetRoots(ZkRootsRequest("usd#bank", 1), auth).join()
            }
            ClientKind.SUBSCRIPTION -> config.toSubscriptionToriiClient(executor).use {
                assertNull(it.getSubscription("subscription-1").join())
            }
            ClientKind.DA -> HttpClientTransport(executor, config).use { transport ->
                transport.newDaToriiClient().use { it.getProofPolicies().join() }
            }
            ClientKind.SETTLEMENT -> HttpClientTransport(executor, config).use { transport ->
                transport.newAtomicPrivateSettlementToriiClientV1().use {
                    it.getPhaseCertificates(identifier, auth).join()
                }
            }
        }
    }

    private fun dispatchStandalone(kind: ClientKind, allow: Boolean?, executor: CapturingExecutor) {
        val base = URI.create("http://127.0.0.1:8080")
        when (kind) {
            ClientKind.NORITO -> NoritoRpcClient.builder()
                .setBaseUri(base).setTransportExecutor(executor)
                .putDefaultHeader("Authorization", "Bearer local-test")
                .apply { if (allow != null) setAllowLocalDevelopmentHttp(allow) }
                .build().use { it.call("/rpc", byteArrayOf(1)) }
            ClientKind.CONFIDENTIAL -> ConfidentialAssetToriiClient.builder()
                .baseUri(base).executor(executor).localSigningContext(context)
                .apply { if (allow != null) setAllowLocalDevelopmentHttp(allow) }
                .build().use { it.getZkAssetRoots(ZkRootsRequest("usd#bank", 1), auth).join() }
            ClientKind.SUBSCRIPTION -> SubscriptionToriiClient.builder()
                .baseUri(base).executor(executor).addHeader("Authorization", "Bearer local-test")
                .apply { if (allow != null) setAllowLocalDevelopmentHttp(allow) }
                .build().use { assertNull(it.getSubscription("subscription-1").join()) }
            ClientKind.DA -> DaToriiClient.builder()
                .baseUri(base).executor(executor).addHeader("Authorization", "Bearer local-test")
                .apply { if (allow != null) setAllowLocalDevelopmentHttp(allow) }
                .build().use { it.getProofPolicies().join() }
            ClientKind.SETTLEMENT -> AtomicPrivateSettlementToriiClientV1.builder()
                .baseUri(base).executor(executor).localSigningContext(context)
                .apply { if (allow != null) setAllowLocalDevelopmentHttp(allow) }
                .build().use { it.getPhaseCertificates(identifier, auth).join() }
        }
    }

    private fun assertCanonicalSignature(request: TransportRequest) {
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        val signature = Signature.getInstance("Ed25519")
        signature.initVerify(keyPair.public)
        signature.update(CanonicalRequestSigner.canonicalRequestSignatureMessage(
            context.networkId(), request.method, request.uri, request.body,
            request.headers.getValue(CanonicalRequestSigner.HEADER_TIMESTAMP_MS).single().toLong(),
            request.headers.getValue(CanonicalRequestSigner.HEADER_NONCE).single(),
        ))
        assertTrue(signature.verify(Base64.getDecoder().decode(
            request.headers.getValue(CanonicalRequestSigner.HEADER_SIGNATURE).single(),
        )))
    }

    private enum class ClientKind(val signed: Boolean) {
        NORITO(false), CONFIDENTIAL(true), SUBSCRIPTION(false), DA(false), SETTLEMENT(true),
    }

    private class CapturingExecutor(private val identifier: AtomicPrivateSettlementIdentifierV1) : HttpTransportExecutor {
        val requests = mutableListOf<TransportRequest>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            val body = when {
                request.uri.path == "/rpc" -> byteArrayOf(1)
                request.uri.path.endsWith("/zk/roots") ->
                    """{"latest":"","roots":[],"evaluated_block_height":0,"evaluated_block_hash":"${"00".repeat(32)}"}""".toByteArray()
                request.uri.path.endsWith("/subscriptions/subscription-1") -> ByteArray(0)
                request.uri.path.endsWith("/da/proof-policies") ->
                    """{"version":1,"policy_hash":"${identifier.jsonLiteral()}","policies":[]}""".toByteArray()
                request.uri.path.endsWith("/phase-certificates") -> JsonEncoder.encode(mapOf(
                    "bundle_id" to identifier.jsonLiteral(),
                    "payload_digest" to identifier.jsonLiteral(),
                    "leg_ordinal" to 0,
                    "lifecycle" to "prepared",
                    "prepare_certificate" to null,
                    "commit_certificate" to null,
                )).toByteArray()
                else -> error("unexpected request ${request.uri}")
            }
            return CompletableFuture.completedFuture(TransportResponse(
                if (request.uri.path.endsWith("/subscriptions/subscription-1")) 404 else 200,
                body, "OK", mapOf("Content-Type" to listOf("application/json")), request.uri, false,
            ))
        }
    }
}
