// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.net.URI
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/**
 * Transport-only tests: fake HTTP responses establish no server authentication or Native Load.
 * Valid canonical-account signing cases use the existing account-address ABI29 admission;
 * missing that ordinary dependency must fail rather than manufacture an account controller.
 */
class ToriiKagemushaWalletLoadIssuanceV1Test {
    private val scheme = ByteArray(32) { 0xab.toByte() }
    private val wallet = ByteArray(32) { 0xcd.toByte() }
    private val requestId = ByteArray(32) { 0xef.toByte() }
    private val network = TestNetworkIds.canonical()
    // RFC8032's public test vector, never application account material.
    private val seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    private val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    // Existing RFC8032 vector: python/iroha_torii_client/tests/client_test_support.py.
    private val payer = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
    private val canonicalPayerHeader = "0x02000120d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

    private fun selection() = ToriiKagemushaWalletLoadSelectionV1(scheme, wallet, requestId)

    private fun auth(): ToriiCanonicalRequestAuth = ToriiCanonicalRequestAuth(payer, RequestSigner { message ->
        Ed25519Signer().run {
            init(true, Ed25519PrivateKeyParameters(seed, 0))
            update(message, 0, message.size)
            generateSignature()
        }
    })

    private class RecordingExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()
        var response: (TransportRequest) -> CompletableFuture<TransportResponse> = { request ->
            CompletableFuture.completedFuture(
                TransportResponse(200, byteArrayOf(0, -1, 7), "", mapOf("Content-Type" to listOf("application/x-norito")), request.uri, false),
            )
        }
        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            return response(request)
        }
    }

    private fun client(
        executor: RecordingExecutor,
        base: String = "https://example.test/torii/",
        networkConfigured: Boolean = true,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration = Duration.ofSeconds(15),
    ): HttpClientTransport = HttpClientTransport(executor, ClientConfig.builder()
        .setBaseUri(URI.create(base)).setRequestTimeout(timeout)
        .apply {
            if (networkConfigured) setLocalSigningContext(LocalSigningContext(network))
            headers.forEach { (name, value) -> putDefaultHeader(name, value) }
        }.build())

    @Test
    fun selectorsRejectZeroAndWrongLengthsForEveryIdentity() {
        for (bad in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLoadSelectionV1(bad, wallet, requestId) }
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLoadSelectionV1(scheme, bad, requestId) }
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLoadSelectionV1(scheme, wallet, bad) }
        }
    }

    @Test
    fun selectorsSnapshotInputsAndReturnOwnedCopiesWithLowercaseRoute() {
        val source = scheme.copyOf()
        val selected = ToriiKagemushaWalletLoadSelectionV1(source, wallet, requestId)
        source.fill(0)
        selected.schemeId.fill(0)
        selected.walletId.fill(0)
        selected.requestId.fill(0)
        assertContentEquals(scheme, selected.schemeId)
        assertContentEquals(wallet, selected.walletId)
        assertContentEquals(requestId, selected.requestId)
        assertEquals("/v1/kagemusha/${"ab".repeat(32)}/wallets/${"cd".repeat(32)}/loads/${"ef".repeat(32)}", selected.path)
    }

    @Test
    fun originalSnapshotsOpaqueMalformedBinaryWithoutAnyMoneyVerdict() {
        val bytes = byteArrayOf(0, -1, 7)
        val original = ToriiKagemushaWalletLoadIssuanceOriginalV1(selection(), payer, network, bytes)
        bytes.fill(0)
        original.unverifiedResponseOriginal.fill(0)
        assertContentEquals(byteArrayOf(0, -1, 7), original.unverifiedResponseOriginal)
        assertEquals(payer, original.payerAccountId)
        assertEquals(network, original.networkId)
    }

    @Test
    fun originalRejectsEmptyAndOversizedBytesButAcceptsInclusiveBound() {
        for (bytes in listOf(ByteArray(0), ByteArray(ToriiKagemushaWalletLoadIssuanceOriginalV1.MAXIMUM_BYTES + 1))) {
            assertFailsWith<IllegalArgumentException> { ToriiKagemushaWalletLoadIssuanceOriginalV1(selection(), payer, network, bytes) }
        }
        assertEquals(ToriiKagemushaWalletLoadIssuanceOriginalV1.MAXIMUM_BYTES,
            ToriiKagemushaWalletLoadIssuanceOriginalV1(selection(), payer, network,
                ByteArray(ToriiKagemushaWalletLoadIssuanceOriginalV1.MAXIMUM_BYTES)).unverifiedResponseOriginal.size)
    }

    @Test
    fun changedOwnerRejectsBeforeSigningOrNetworkContextAdmission() {
        val executor = RecordingExecutor()
        val signer = RequestSigner { error("must not sign") }
        assertFailsWith<IllegalStateException> {
            client(executor, networkConfigured = false).getKagemushaWalletLoadIssuanceOriginalV1(
                selection(), ToriiCanonicalRequestAuth(payer, signer), Runnable { error("owner changed") },
            )
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun missingNetworkRejectsBeforeSigningOrDispatch() {
        val executor = RecordingExecutor()
        assertFailsWith<IllegalStateException> {
            client(executor, networkConfigured = false).getKagemushaWalletLoadIssuanceOriginalV1(
                selection(), ToriiCanonicalRequestAuth(payer, RequestSigner { error("must not sign") }), Runnable {},
            )
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun aliasesOfferedAuthWitnessOperatorAndTransportHeadersRejectBeforeSigning() {
        val executor = RecordingExecutor()
        val neverSign = RequestSigner { error("must not sign") }
        assertFailsWith<IllegalArgumentException> {
            client(executor).buildKagemushaWalletLoadIssuanceRequestV1(selection(), ToriiCanonicalRequestAuth("alice@universal", neverSign))
        }
        for (header in listOf("x-iroha-account", "X-Iroha-Signature", "x-iroha-timestamp-ms", "X-Iroha-Nonce",
            "x-iroha-witness", "x-iroha-operator-public-key", "X-Iroha-Operator-Signature", "x-iroha-operator-timestamp-ms",
            "X-Iroha-Operator-Nonce", "Accept", "Accept-Encoding", "Cache-Control", "Content-Type", "Content-Encoding")) {
            assertFailsWith<IllegalArgumentException> {
                client(executor, headers = mapOf(header to "offered")).buildKagemushaWalletLoadIssuanceRequestV1(
                    selection(), ToriiCanonicalRequestAuth(payer, neverSign),
                )
            }
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun insecureOrAmbiguousBaseAndZeroTimeoutRejectBeforeSigning() {
        val executor = RecordingExecutor()
        val neverSign = ToriiCanonicalRequestAuth(payer, RequestSigner { error("must not sign") })
        for (base in listOf("http://example.test", "https://user@example.test", "https://example.test?query=1", "https://example.test#fragment")) {
            assertFailsWith<IllegalArgumentException> { client(executor, base).buildKagemushaWalletLoadIssuanceRequestV1(selection(), neverSign) }
        }
        assertFailsWith<IllegalArgumentException> {
            client(executor, timeout = Duration.ZERO).buildKagemushaWalletLoadIssuanceRequestV1(selection(), neverSign)
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun exactGetSignsPathBodyAndNetworkAndRetainsExpectedPayerWithFreshNonce() {
        val executor = RecordingExecutor()
        val transport = client(executor, headers = mapOf("X-Dataspace-Id" to "is2"))
        val first = transport.buildKagemushaWalletLoadIssuanceRequestV1(selection(), auth())
        val second = transport.buildKagemushaWalletLoadIssuanceRequestV1(selection(), auth())
        assertEquals("GET", first.method)
        assertEquals("https://example.test/torii" + selection().path, first.uri.toASCIIString())
        assertTrue(first.body.isEmpty())
        assertEquals(RequestReplayPolicy.ONE_SHOT, first.replayPolicy)
        assertEquals(64L * 1024, first.maximumResponseBytes)
        assertEquals("application/x-norito", first.headers["Accept"]?.single())
        assertEquals("identity", first.headers["Accept-Encoding"]?.single())
        assertEquals("no-store", first.headers["Cache-Control"]?.single())
        assertEquals("is2", first.headers["X-Dataspace-Id"]?.single())
        assertEquals(canonicalPayerHeader, first.headers[CanonicalRequestSigner.HEADER_ACCOUNT]?.single())
        val nonce = first.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single()
        assertFalse(nonce == second.headers[CanonicalRequestSigner.HEADER_NONCE]?.single())
        val timestamp = first.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]!!.single().toLong()
        val signature = java.util.Base64.getDecoder().decode(first.headers[CanonicalRequestSigner.HEADER_SIGNATURE]!!.single())
        fun valid(message: ByteArray): Boolean = Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(publicKey, 0)); update(message, 0, message.size); verifySignature(signature)
        }
        assertTrue(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "GET", first.uri, first.body, timestamp, nonce)))
        assertFalse(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(TestNetworkIds.fromSeed(42), "GET", first.uri, first.body, timestamp, nonce)))
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun exactSuccessfulReadRetainsUnverifiedOriginalAndExpectedOwnerContext() {
        val executor = RecordingExecutor()
        val value = client(executor).getKagemushaWalletLoadIssuanceOriginalV1(selection(), auth(), Runnable {}).join()
        assertEquals(1, executor.requests.size)
        assertContentEquals(byteArrayOf(0, -1, 7), value.unverifiedResponseOriginal)
        assertEquals(payer, value.payerAccountId)
        assertEquals(network, value.networkId)
        assertContentEquals(requestId, value.selection.requestId)
    }

    @Test
    fun compactFinalityUsesExactSignedSiblingAndIndependentProofBound() {
        val executor = RecordingExecutor()
        val proof = client(executor).getKagemushaWalletLoadFinalityOriginalV1(selection(), auth(), Runnable {}).join()
        assertContentEquals(byteArrayOf(0, -1, 7), proof)
        val request = executor.requests.single()
        assertEquals(selection().path + "/finality", request.uri.path.removePrefix("/torii"))
        assertEquals(256L * 1024, request.maximumResponseBytes)
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        assertEquals("GET", request.method)
        assertTrue(request.body.isEmpty())
        val timestamp = request.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]!!.single().toLong()
        val nonce = request.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single()
        val signature = java.util.Base64.getDecoder().decode(request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]!!.single())
        val message = CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "GET", request.uri, request.body, timestamp, nonce)
        assertTrue(Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(publicKey, 0)); update(message, 0, message.size); verifySignature(signature)
        })
    }

    @Test
    fun compactFinalityRejectsOversizeWrongTransportAndUnavailableWithoutFallback() {
        for (failure in 0..6) for (epoch in listOf(false, true)) {
            val executor = RecordingExecutor()
            executor.response = { request -> CompletableFuture.completedFuture(TransportResponse(
                if (failure == 0) 503 else if (failure == 6) 202 else 200,
                if (failure == 1) ByteArray(256 * 1024 + 1) else byteArrayOf(1), "",
                mapOf("Content-Type" to listOf(if (failure == 2) "application/json" else "application/x-norito")) +
                    if (failure == 3) mapOf("Content-Encoding" to listOf("gzip")) else emptyMap(),
                if (failure == 4) URI.create("https://other.test/") else request.uri, failure == 5)) }
            assertFailsWith<CompletionException> {
                if (epoch) {
                    client(executor).getKagemushaWalletLoadEpochOriginalV1(
                        selection(), BigInteger.TEN, auth(), Runnable {}).join()
                } else {
                    client(executor).getKagemushaWalletLoadFinalityOriginalV1(selection(), auth(), Runnable {}).join()
                }
            }
            assertEquals(1, executor.requests.size)
            assertTrue(executor.requests.single().uri.path.endsWith(if (epoch) "/epochs/10" else "/finality"))
        }
    }

    @Test
    fun epochReadSignsExactBoundaryAndUsesBoundedOneShotTransport() {
        val executor = RecordingExecutor()
        val data = client(executor).getKagemushaWalletLoadEpochOriginalV1(
            selection(), BigInteger.TEN, auth(), Runnable {}).join()
        assertContentEquals(byteArrayOf(0, -1, 7), data)
        val request = executor.requests.single()
        assertEquals(selection().path + "/epochs/10", request.uri.path.removePrefix("/torii"))
        assertEquals(256L * 1024, request.maximumResponseBytes)
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        assertEquals("GET", request.method)
        assertTrue(request.body.isEmpty())
        val timestamp = request.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]!!.single().toLong()
        val nonce = request.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single()
        val signature = java.util.Base64.getDecoder().decode(request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]!!.single())
        for (height in listOf(10, 11)) {
            val uri = URI.create(request.uri.toASCIIString().replace("/epochs/10", "/epochs/$height"))
            val message = CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "GET", uri, request.body, timestamp, nonce)
            assertEquals(height == 10, Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(publicKey, 0))
                update(message, 0, message.size)
                verifySignature(signature)
            })
        }
    }

    @Test
    fun epochReadRejectsInvalidU64BoundaryBeforeSigning() {
        val executor = RecordingExecutor()
        val signer = ToriiCanonicalRequestAuth(payer, RequestSigner { error("must not sign") })
        for (height in listOf(BigInteger.valueOf(-1), BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.shiftLeft(64))) {
            assertFailsWith<IllegalArgumentException> {
                client(executor).getKagemushaWalletLoadEpochOriginalV1(selection(), height, signer, Runnable {})
            }
        }
        assertTrue(executor.requests.isEmpty())
        val largest = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        client(executor).getKagemushaWalletLoadEpochOriginalV1(selection(), largest, auth(), Runnable {}).join()
        assertTrue(executor.requests.single().uri.path.endsWith("/epochs/18446744073709551615"))
    }

    @Test
    fun epochReadRechecksOwnerAndPropagatesCancellation() {
        val executor = RecordingExecutor()
        assertFailsWith<IllegalStateException> {
            client(executor).getKagemushaWalletLoadEpochOriginalV1(selection(), BigInteger.TEN,
                ToriiCanonicalRequestAuth(payer, RequestSigner { error("must not sign") }), Runnable { error("retired") })
        }
        assertTrue(executor.requests.isEmpty())
        var current = true
        val pending = CompletableFuture<TransportResponse>()
        executor.response = { pending }
        val result = client(executor).getKagemushaWalletLoadEpochOriginalV1(
            selection(), BigInteger.TEN, auth(), Runnable { check(current) })
        current = false
        pending.complete(TransportResponse(200, byteArrayOf(1), "", mapOf("Content-Type" to listOf("application/x-norito")),
            executor.requests.single().uri, false))
        assertFailsWith<CompletionException> { result.join() }
        val cancelled = CompletableFuture<TransportResponse>()
        executor.response = { cancelled }
        val cancelling = client(executor).getKagemushaWalletLoadEpochOriginalV1(
            selection(), BigInteger.TEN, auth(), Runnable {})
        cancelling.cancel(false)
        assertTrue(cancelled.isCancelled)
    }

    @Test
    fun compactFinalityChecksOwnerBeforeSigningAndAgainBeforeDelivering() {
        val executor = RecordingExecutor()
        assertFailsWith<IllegalStateException> {
            client(executor).getKagemushaWalletLoadFinalityOriginalV1(selection(),
                ToriiCanonicalRequestAuth(payer, RequestSigner { error("must not sign") }), Runnable { error("retired") })
        }
        assertTrue(executor.requests.isEmpty())
        var current = true
        val pending = CompletableFuture<TransportResponse>()
        executor.response = { pending }
        val result = client(executor).getKagemushaWalletLoadFinalityOriginalV1(selection(), auth(), Runnable { check(current) })
        current = false
        pending.complete(TransportResponse(200, byteArrayOf(1), "", mapOf("Content-Type" to listOf("application/x-norito")),
            executor.requests.single().uri, false))
        assertFailsWith<CompletionException> { result.join() }
    }

    @Test
    fun compactFinalityCancellationCancelsItsSingleUpstreamRead() {
        val executor = RecordingExecutor()
        val pending = CompletableFuture<TransportResponse>()
        executor.response = { pending }
        val result = client(executor).getKagemushaWalletLoadFinalityOriginalV1(selection(), auth(), Runnable {})
        result.cancel(false)
        assertTrue(pending.isCancelled)
        assertEquals(1, executor.requests.size)
    }

    @Test
    fun redirectedMissingOrDifferentResponseProvenanceNeverProducesOriginal() {
        for ((uri, redirected) in listOf(null to false, URI.create("https://other.test/") to false,
            URI.create("https://example.test/torii" + selection().path) to true)) {
            assertResponseRejected { request -> TransportResponse(200, byteArrayOf(1), "",
                mapOf("Content-Type" to listOf("application/x-norito")), uri, redirected) }
        }
    }

    @Test
    fun jsonParameterizedOrAmbiguousMediaAndCompressedResponseReject() {
        for (type in listOf(emptyList(), listOf("application/json"), listOf("application/x-norito; charset=binary"),
            listOf("application/x-norito", "application/x-norito"))) {
            assertResponseRejected { request -> TransportResponse(200, byteArrayOf(1), "", mapOf("Content-Type" to type), request.uri, false) }
        }
        for (encoding in listOf(listOf("gzip"), listOf("identity", "identity"))) {
            assertResponseRejected { request -> TransportResponse(200, byteArrayOf(1), "",
                mapOf("Content-Type" to listOf("application/x-norito"), "Content-Encoding" to encoding), request.uri, false) }
        }
    }

    @Test
    fun unavailableAndOtherStatusesNeverMeanFreshIssuanceOrAbsentWallet() {
        for (status in listOf(202, 301, 401, 404, 406, 503)) {
            assertResponseRejected { request -> TransportResponse(status, byteArrayOf(1), "",
                mapOf("Content-Type" to listOf("application/x-norito")), request.uri, false) }
        }
    }

    @Test
    fun bodyAndDeclaredLengthBoundsRejectWithoutRetry() {
        for (body in listOf(ByteArray(0), ByteArray(64 * 1024 + 1))) {
            assertResponseRejected { request -> TransportResponse(200, body, "",
                mapOf("Content-Type" to listOf("application/x-norito")), request.uri, false) }
        }
        for (length in listOf("0", "2", "-1", "+1", "01", "1,1", "9".repeat(40))) {
            assertResponseRejected { request -> TransportResponse(200, byteArrayOf(1), "",
                mapOf("Content-Type" to listOf("application/x-norito"), "Content-Length" to listOf(length)), request.uri, false) }
        }
    }

    @Test
    fun ownerChangeDuringSigningPreventsDispatch() {
        val executor = RecordingExecutor()
        var owner = true
        val realSigner = auth().signer
        val changingAuth = ToriiCanonicalRequestAuth(payer, RequestSigner { message -> realSigner.sign(message).also { owner = false } })
        val result = client(executor).getKagemushaWalletLoadIssuanceOriginalV1(selection(), changingAuth, Runnable { check(owner) })
        assertFailsWith<CompletionException> { result.join() }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun ownerChangeWhileRequestIsPendingRejectsLateResponse() {
        val executor = RecordingExecutor()
        val upstream = CompletableFuture<TransportResponse>()
        executor.response = { upstream }
        var owner = true
        val result = client(executor).getKagemushaWalletLoadIssuanceOriginalV1(selection(), auth(), Runnable { check(owner) })
        owner = false
        upstream.complete(TransportResponse(200, byteArrayOf(1), "", mapOf("Content-Type" to listOf("application/x-norito")), executor.requests.single().uri, false))
        assertFailsWith<CompletionException> { result.join() }
        assertEquals(1, executor.requests.size)
    }

    @Test
    fun cancellationAndClientCloseCancelBorrowedCallWithoutClosingBackend() {
        for (closeClient in listOf(false, true)) {
            val executor = RecordingExecutor()
            val upstream = CompletableFuture<TransportResponse>()
            executor.response = { upstream }
            val transport = client(executor)
            val result = transport.getKagemushaWalletLoadIssuanceOriginalV1(selection(), auth(), Runnable {})
            if (closeClient) transport.close() else result.cancel(false)
            assertTrue(upstream.isCancelled)
            assertTrue(result.isCancelled)
            assertEquals(1, executor.requests.size)
        }
    }

    @Test
    fun originalTransportFailureIsNotRetriedOrConvertedToAnOriginal() {
        val executor = RecordingExecutor()
        val failure = IllegalStateException("source unavailable")
        executor.response = { CompletableFuture<TransportResponse>().also { it.completeExceptionally(failure) } }
        val error = assertFailsWith<CompletionException> {
            client(executor).getKagemushaWalletLoadIssuanceOriginalV1(selection(), auth(), Runnable {}).join()
        }
        assertTrue(error.cause === failure)
        assertEquals(1, executor.requests.size)
    }

    private fun assertResponseRejected(response: (TransportRequest) -> TransportResponse) {
        val executor = RecordingExecutor()
        executor.response = { request -> CompletableFuture.completedFuture(response(request)) }
        assertFailsWith<CompletionException> {
            client(executor).getKagemushaWalletLoadIssuanceOriginalV1(selection(), auth(), Runnable {}).join()
        }
        assertEquals(1, executor.requests.size)
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
