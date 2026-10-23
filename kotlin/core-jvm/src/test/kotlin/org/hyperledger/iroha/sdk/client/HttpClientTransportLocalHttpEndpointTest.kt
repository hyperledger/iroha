package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.security.KeyPairGenerator
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Explicit endpoint guards share the same default-off local HTTP policy. */
class HttpClientTransportLocalHttpEndpointTest {
    @Test
    fun authenticatedEndpointGuardsRejectDefaultLocalAndOptedInPublicHttp() {
        val auth = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().private),
        )
        for ((base, optIn) in listOf(
            "http://localhost:8080" to false,
            "http://10.0.2.2:8080" to false,
            "http://torii.example:8080" to true,
            "http://203.0.113.1:8080" to true,
        )) {
            var dispatches = 0
            val executor = object : HttpTransportExecutor {
                override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
                    dispatches++
                    error("disallowed endpoint must not be dispatched")
                }
            }
            val config = ClientConfig.builder()
                .setBaseUri(URI.create(base))
                .setAllowLocalDevelopmentHttp(optIn)
                .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical()))
                .build()
            HttpClientTransport(executor, config).use { client ->
                assertFailsWith<IllegalArgumentException> { client.getElectionTally("election-1", auth) }
                assertFailsWith<IllegalArgumentException> { client.getPrivacyCapabilities(auth) }
                assertFailsWith<IllegalArgumentException> { client.getVpnProfile() }
                assertFailsWith<IllegalArgumentException> { client.getVpnSession("ab".repeat(16), auth) }
                assertFailsWith<IllegalArgumentException> { client.postSignedCommittedTransactionQuery(byteArrayOf(1)) }
                assertFailsWith<IllegalArgumentException> { client.getBridgeFinalityBundleJson(1) }
            }
            assertEquals(0, dispatches, "$base with opt-in $optIn")
        }
    }
}
