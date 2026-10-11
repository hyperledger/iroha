package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertNotEquals
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId

class ApplicationPostAuthenticationTest {
    @Test
    fun ramLfeSignatureSeparatesSameAccountAcrossForeignGenesis() {
        val canonical = NetworkId.parse(
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
        )
        val foreign = NetworkId.parse(
            "hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22",
        )
        fun auth() = applicationAuth()
        val requests = mutableListOf<TransportRequest>()
        val executor = object : HttpTransportExecutor {
            override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
                requests.add(request)
                return CompletableFuture.completedFuture(
                    TransportResponse.builder().setStatusCode(404).setBody(byteArrayOf()).build(),
                )
            }
        }

        for (networkId in listOf(canonical, foreign)) {
            val config = ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build()
            HttpClientTransport(executor, config)
                .executeRamLfeProgram("lookup", RamLfeExecuteRequest.ownerInput("private@example.org", "12".repeat(32)), auth())
                .join()
        }

        assertNotEquals(
            requests[0].headers[CanonicalRequestSigner.HEADER_SIGNATURE]?.single(),
            requests[1].headers[CanonicalRequestSigner.HEADER_SIGNATURE]?.single(),
        )
    }
}
