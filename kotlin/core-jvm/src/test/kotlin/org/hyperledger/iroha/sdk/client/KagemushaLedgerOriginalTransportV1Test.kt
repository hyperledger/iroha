package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.net.URI
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Public HTTP DATA only; no fake Native verifier or monetary success. */
class KagemushaLedgerOriginalTransportV1Test {
    private class Executor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()
        var reply: (TransportRequest) -> CompletableFuture<TransportResponse> = { r ->
            CompletableFuture.completedFuture(TransportResponse(200, byteArrayOf(1, 2), "",
                mapOf("Content-Type" to listOf("application/x-norito")), r.uri, false))
        }
        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> { requests += request; return reply(request) }
    }
    private fun client(executor: Executor) = HttpClientTransport(executor, ClientConfig.builder()
        .setBaseUri(URI.create("https://example.test/torii/"))
        .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical())).build())

    @Test fun finalityUsesOneBoundedIdentityGetAndReturnsOnlyOriginalData() {
        val executor = Executor(); val client = client(executor)
        assertContentEquals(byteArrayOf(1, 2), client.getKagemushaWalletLedgerFinalityOriginalV1(BigInteger.ONE, Runnable {}).join())
        val request = executor.requests.single()
        assertEquals("https://example.test/torii/v1/bridge/finality/1", request.uri.toString())
        assertEquals(36L * 1024 * 1024, request.maximumResponseBytes)
        assertEquals("GET", request.method)
    }
    @Test fun invalidHeightAndChangedOwnerRefuseBeforeAnyDispatchOrSigner() {
        val executor = Executor(); val client = client(executor)
        for (height in listOf(BigInteger.ZERO, BigInteger.valueOf(-1), BigInteger.ONE.shiftLeft(64))) {
            assertFailsWith<IllegalArgumentException> { client.getKagemushaWalletLedgerFinalityOriginalV1(height, Runnable {}) }
        }
        assertFailsWith<IllegalStateException> { client.getKagemushaWalletLedgerFinalityOriginalV1(BigInteger.ONE, Runnable { error("retired") }) }
        val selection = ToriiKagemushaWalletLoadSelectionV1(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
        assertFailsWith<IllegalStateException> { client.getKagemushaWalletLoadFinalityOriginalV1(selection,
            ToriiCanonicalRequestAuth("unadmitted", RequestSigner { error("must not sign") }), Runnable { error("retired") }) }
        assertTrue(executor.requests.isEmpty())
    }
    @Test fun retiredOwnerOrRedirectOrWrongEncodingCannotDeliverLedgerData() {
        for (mode in 0..3) {
            val executor = Executor(); var live = true
            executor.reply = { r ->
                if (mode == 0) live = false
                val headers = mapOf("Content-Type" to listOf(if (mode == 2) "application/json" else "application/x-norito")) +
                    if (mode == 3) mapOf("Content-Encoding" to listOf("gzip")) else emptyMap()
                CompletableFuture.completedFuture(TransportResponse(200, byteArrayOf(1), "", headers,
                    if (mode == 1) URI.create("https://other.test/") else r.uri, mode == 1))
            }
            assertFailsWith<CompletionException> { client(executor).getKagemushaWalletLedgerFinalityOriginalV1(
                BigInteger.ONE, Runnable { check(live) }).join() }
            assertEquals(1, executor.requests.size)
        }
    }
    @Test fun cancellationJoinsTheActualReadAndSuppressesLateDelivery() {
        val executor = Executor(); val upstream = CompletableFuture<TransportResponse>()
        executor.reply = { upstream }
        val result = client(executor).getKagemushaWalletLedgerFinalityOriginalV1(BigInteger.ONE, Runnable {})
        result.cancel(false)
        assertTrue(upstream.isCancelled); assertTrue(result.isCancelled)
    }
}
