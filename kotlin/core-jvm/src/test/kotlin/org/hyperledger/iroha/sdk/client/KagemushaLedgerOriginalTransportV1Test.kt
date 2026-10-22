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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Public HTTP DATA only; no fake Native verifier or monetary success. */
class KagemushaLedgerOriginalTransportV1Test {
    private val network = TestNetworkIds.canonical()
    // RFC8032's public test vector, never application account material.
    private val seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    private val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    // Existing RFC8032 vector: python/iroha_torii_client/tests/client_test_support.py.
    private val account = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"

    private fun selection() = ToriiKagemushaWalletLedgerSelectionV1(
        ByteArray(32) { 0xab.toByte() }, ByteArray(32) { 0xcd.toByte() }, ByteArray(32) { 0x0f })

    private fun auth(): ToriiCanonicalRequestAuth = ToriiCanonicalRequestAuth(account, RequestSigner { message ->
        Ed25519Signer().run {
            init(true, Ed25519PrivateKeyParameters(seed, 0))
            update(message, 0, message.size)
            generateSignature()
        }
    })

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
        .setLocalSigningContext(LocalSigningContext(network)).build())

    @Test fun selectorsAreExactNonzero32BytesOnTheAttemptRoute() {
        val valid = ByteArray(32) { 1 }
        for (bad in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLedgerSelectionV1(bad, valid, valid) }
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLedgerSelectionV1(valid, bad, valid) }
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLedgerSelectionV1(valid, valid, bad) }
        }
        assertEquals("/v1/kagemusha/" + "ab".repeat(32) + "/wallets/" + "cd".repeat(32) + "/ledger/" + "0f".repeat(32),
            selection().path)
    }

    @Test fun attemptReadsSignTheirExactRouteWithTheDerivedBounds() {
        val executor = Executor(); val client = client(executor)
        assertEquals(KagemushaWalletLedgerReadV1.Original(byteArrayOf(1, 2)),
            client.getKagemushaWalletLedgerAttemptFinalityV1(selection(), auth(), Runnable {}).join())
        assertEquals(KagemushaWalletLedgerReadV1.Original(byteArrayOf(1, 2)),
            client.getKagemushaWalletLedgerAttemptEpochV1(selection(), BigInteger.TEN, auth(), Runnable {}).join())
        val (finality, epoch) = executor.requests
        assertEquals(selection().path + "/finality", finality.uri.path.removePrefix("/torii"))
        assertEquals(1_327_104L, finality.maximumResponseBytes)
        assertEquals(selection().path + "/epochs/10", epoch.uri.path.removePrefix("/torii"))
        assertEquals(262_144L, epoch.maximumResponseBytes)
        for (request in executor.requests) {
            assertEquals("GET", request.method); assertTrue(request.body.isEmpty())
            val timestamp = request.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]!!.single().toLong()
            val nonce = request.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single()
            val signature = java.util.Base64.getDecoder().decode(request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]!!.single())
            val message = CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "GET", request.uri, request.body, timestamp, nonce)
            assertTrue(Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(publicKey, 0)); update(message, 0, message.size); verifySignature(signature)
            })
        }
        for (height in listOf(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.shiftLeft(64))) {
            assertFailsWith<IllegalArgumentException> {
                client.getKagemushaWalletLedgerAttemptEpochV1(selection(), height, auth(), Runnable {})
            }
        }
        assertEquals(2, executor.requests.size)
    }

    @Test fun onlyTheTypedRejectCodeHeaderMakesAWait() {
        val cases: List<Triple<Int, String?, KagemushaWalletLedgerReadV1?>> = listOf(
            Triple(404, "kagemusha_ledger_entry_not_committed", KagemushaWalletLedgerReadV1.NotCommitted),
            Triple(503, "kagemusha_ledger_finality_unavailable", KagemushaWalletLedgerReadV1.Unavailable),
            Triple(404, null, null), Triple(404, "kagemusha_ledger_finality_unavailable", null),
            Triple(503, null, null), Triple(503, "kagemusha_load_finality_unavailable", null),
            Triple(401, null, null), Triple(406, null, null), Triple(202, null, null),
        )
        for ((status, code, expected) in cases) {
            for (epoch in listOf(false, true)) {
                val executor = Executor()
                executor.reply = { r ->
                    val headers = mapOf("Content-Type" to listOf("application/x-norito")) +
                        (code?.let { mapOf("X-Iroha-Reject-Code" to listOf(it)) } ?: emptyMap())
                    CompletableFuture.completedFuture(TransportResponse(status, byteArrayOf(9), "", headers, r.uri, false))
                }
                val read = if (epoch) client(executor).getKagemushaWalletLedgerAttemptEpochV1(selection(), BigInteger.TEN, auth(), Runnable {})
                    else client(executor).getKagemushaWalletLedgerAttemptFinalityV1(selection(), auth(), Runnable {})
                if (expected == null) assertFailsWith<CompletionException>("status $status code $code") { read.join() }
                else assertEquals(expected, read.join(), "status $status code $code")
            }
        }
    }

    @Test fun boundRedirectEncodingAndRetiredOwnerCannotDeliverAttemptData() {
        for (mode in 0..4) {
            val executor = Executor(); var live = true
            executor.reply = { r ->
                if (mode == 0) live = false
                val headers = mapOf("Content-Type" to listOf(if (mode == 2) "application/json" else "application/x-norito")) +
                    if (mode == 3) mapOf("Content-Encoding" to listOf("gzip")) else emptyMap()
                val body = if (mode == 4) ByteArray(1_327_105) else byteArrayOf(1)
                CompletableFuture.completedFuture(TransportResponse(200, body, "", headers,
                    if (mode == 1) URI.create("https://other.test/") else r.uri, mode == 1))
            }
            assertFailsWith<CompletionException> { client(executor).getKagemushaWalletLedgerAttemptFinalityV1(
                selection(), auth(), Runnable { check(live) }).join() }
            assertEquals(1, executor.requests.size)
        }
        val executor = Executor()
        assertFailsWith<IllegalStateException> {
            client(executor).getKagemushaWalletLedgerAttemptFinalityV1(selection(),
                ToriiCanonicalRequestAuth("unadmitted", RequestSigner { error("must not sign") }), Runnable { error("retired") })
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test fun cancellationJoinsTheActualReadAndSuppressesLateDelivery() {
        val executor = Executor(); val upstream = CompletableFuture<TransportResponse>()
        executor.reply = { upstream }
        val result = client(executor).getKagemushaWalletLedgerAttemptFinalityV1(selection(), auth(), Runnable {})
        result.cancel(false)
        assertTrue(upstream.isCancelled); assertTrue(result.isCancelled)
    }

    @Test fun originalBytesAreOwnedCopies() {
        val bytes = byteArrayOf(4, 5)
        val original = KagemushaWalletLedgerReadV1.Original(bytes)
        bytes.fill(0); original.bytes().fill(0)
        assertContentEquals(byteArrayOf(4, 5), original.bytes())
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
