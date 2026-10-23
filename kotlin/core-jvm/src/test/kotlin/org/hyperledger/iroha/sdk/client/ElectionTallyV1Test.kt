package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Exact V1 standalone-election tally query and lossless JSON tests. */
class ElectionTallyV1Test {
    private val network = NetworkId.fromBytes(ByteArray(32) { 7 })
    private val hash = "ab".repeat(32)
    private val u128Max = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
    private val highWeight = BigInteger.ONE.shiftLeft(53).add(BigInteger.ONE)

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example/api", "http://127.0.0.1/api", "http://192.168.1.2/api"])
    fun signedQueryPreservesLargeWeightsAndExactBody(baseUri: String) {
        val response = json(
            height = "18446744073709551615",
            tally = "[$highWeight,${u128Max - highWeight}]",
        )
        val executor = CapturingExecutor(response)
        val config = ClientConfig.builder()
            .setBaseUri(URI.create(baseUri))
            .setAllowLocalDevelopmentHttp(baseUri.startsWith("http:"))
            .setLocalSigningContext(LocalSigningContext(network))
            .build()
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val auth = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            1_700_000_000_100L,
            "election-tally-1",
        )
        val result = HttpClientTransport(executor, config).getElectionTally("election-1", auth).join()

        assertEquals(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE), result.evaluatedBlockHeight)
        assertEquals(hash, result.evaluatedBlockHash)
        assertEquals(true, result.finalized)
        assertEquals(listOf(highWeight, u128Max - highWeight), result.tally)
        val request = assertNotNull(executor.lastRequest)
        assertEquals("POST", request.method)
        assertEquals("$baseUri/v1/zk/vote/tally", request.uri.toString())
        assertContentEquals(
            "{\"election_id\":\"election-1\"}".toByteArray(StandardCharsets.UTF_8),
            request.body,
        )
        assertEquals(listOf("application/json"), request.headers["Accept"])
        assertEquals(listOf("application/json"), request.headers["Content-Type"])
        assertEquals(ElectionTallyV1.MAX_RESPONSE_BYTES.toLong(), request.maximumResponseBytes)
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        val signature = Base64.getDecoder().decode(
            assertNotNull(request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]).single(),
        )
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keyPair.public)
        verifier.update(
            CanonicalRequestSigner.canonicalRequestSignatureMessage(
                network, "POST", request.uri, request.body,
                1_700_000_000_100L, "election-tally-1",
            ),
        )
        assertEquals(true, verifier.verify(signature))
        assertEquals(1, executor.calls)
    }

    @Test
    fun parserRejectsShapeNumericIdentityAndAggregateSubstitutions() {
        val valid = json(height = "7", tally = "[1,2]")
        val malformed = listOf(
            valid.replace("\"finalized\":true,", ""),
            valid.replace("\"finalized\":true", "\"finalized\":true,\"extra\":0"),
            valid.replace("\"finalized\":true", "\"finalized\":\"true\""),
            valid.replace("\"evaluated_block_height\":7", "\"evaluated_block_height\":18446744073709551616"),
            valid.replace("\"evaluated_block_height\":7", "\"evaluated_block_height\":-1"),
            valid.replace("\"evaluated_block_height\":7", "\"evaluated_block_height\":7.0"),
            valid.replace("\"evaluated_block_height\":7", "\"evaluated_block_height\":٧"),
            valid.replace(hash, hash.uppercase()),
            valid.replace(hash, "00".repeat(32)),
            valid.replace("[1,2]", "[1]"),
            valid.replace("[1,2]", "[1,${u128Max},0]"),
            valid.replace("[1,2]", "[340282366920938463463374607431768211456,0]"),
            valid.replace("[1,2]", "[-1,2]"),
            valid.replace("[1,2]", "[1.0,2]"),
            valid.replace("[1,2]", "[١,2]"),
            valid.replace("[1,2]", "[1.١,2]"),
            valid.replace("[1,2]", "[1e١,2]"),
            valid.replace("[1,2]", "[true,2]"),
            valid.replace("[1,2]", "[\"1\",2]"),
            valid.replace("[1,2]", "[${List(65) { "0" }.joinToString(",")}]"),
            valid.replace("\"finalized\":true", "\"finalized\":true,\"finalized\":true"),
        )
        malformed.forEachIndexed { index, payload ->
            assertFailsWith<Exception>("malformed case $index") {
                ElectionTallyV1.parse(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }
        assertFailsWith<Exception> { ElectionTallyV1.parse(byteArrayOf(0xc3.toByte(), 0x28)) }
        assertFailsWith<Exception> { ElectionTallyV1.parse(ByteArray(ElectionTallyV1.MAX_RESPONSE_BYTES + 1)) }
        assertEquals(BigInteger.ZERO, ElectionTallyV1.parse(
            json("0", "[0,0]", "0".repeat(64)).toByteArray(StandardCharsets.UTF_8),
        ).evaluatedBlockHeight)
    }

    @Test
    fun selectorAndExactHttpResponseFailuresDoNotYieldATally() {
        val config = ClientConfig.builder()
            .setBaseUri(URI.create("https://torii.example/api"))
            .setLocalSigningContext(LocalSigningContext(network))
            .build()
        fun auth() = ToriiCanonicalRequestAuth(
            "alice@universal", RequestSigner.ed25519(
                KeyPairGenerator.getInstance("Ed25519").generateKeyPair().private,
            ), 1_700_000_000_100L, "election-tally-2",
        )
        val executor = CapturingExecutor(json("7", "[1,2]"))
        val client = HttpClientTransport(executor, config)
        listOf("", ".hidden", "bad/id", "a".repeat(129)).forEach { selector ->
            assertFailsWith<IllegalArgumentException> { client.getElectionTally(selector, auth()) }
        }
        assertEquals(0, executor.calls)

        val wrongMedia = CapturingExecutor(json("7", "[1,2]"), contentType = "text/plain")
        assertFailsWith<CompletionException> {
            HttpClientTransport(wrongMedia, config).getElectionTally("election-1", auth()).join()
        }
        val oversized = CapturingExecutor(json("7", "[1,2]") + " ".repeat(8192))
        assertFailsWith<CompletionException> {
            HttpClientTransport(oversized, config).getElectionTally("election-1", auth()).join()
        }
        assertEquals(1, wrongMedia.calls)
        assertEquals(1, oversized.calls)
    }

    private fun json(height: String, tally: String, blockHash: String = hash) =
        "{\"evaluated_block_height\":$height,\"evaluated_block_hash\":\"$blockHash\"," +
            "\"finalized\":true,\"tally\":$tally}"

    private class CapturingExecutor(
        private val payload: String,
        private val contentType: String = "application/json",
    ) : HttpTransportExecutor {
        var calls = 0
        var lastRequest: TransportRequest? = null

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            calls++
            lastRequest = request
            return CompletableFuture.completedFuture(
                TransportResponse(
                    200, payload.toByteArray(StandardCharsets.UTF_8), "OK",
                    mapOf("Content-Type" to listOf(contentType)), request.uri, false,
                ),
            )
        }
    }
}
