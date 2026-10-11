// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.MultisigMemberPayload
import org.hyperledger.iroha.sdk.address.MultisigPolicyPayload
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletEnrollmentRequestV1 as Request
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletEnrollmentResponseV1 as Response
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/** Mock HTTP plus real canonical account signing; no native enrollment or bank authorization claim. */
class ToriiKagemushaWalletEnrollmentTransportV1Test {
    private val network = TestNetworkIds.canonical()
    // Public RFC8032 test key, never application account material.
    private val seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    private val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    private val account = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
    private val dispatch = byteArrayOf(1, 2, 3)
    private val evidence = byteArrayOf(4, 5, 6)
    private fun auth() = ToriiCanonicalRequestAuth(account, RequestSigner { message ->
        Ed25519Signer().run {
            init(true, Ed25519PrivateKeyParameters(seed, 0)); update(message, 0, message.size); generateSignature()
        }
    })
    private class RecordingExecutor : HttpTransportExecutor {
        val requests = ArrayList<TransportRequest>()
        var response: (TransportRequest) -> CompletableFuture<TransportResponse> = { request ->
            CompletableFuture.completedFuture(ok(request, Response.Pending.canonicalWire()))
        }
        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests.add(request)
            return response(request)
        }
    }
    private fun client(executor: RecordingExecutor, base: String = "https://example.test/torii/",
        headers: Map<String, String> = emptyMap(), networkConfigured: Boolean = true,
        timeout: Duration = Duration.ofSeconds(15)) = HttpClientTransport(executor, ClientConfig.builder()
        .setBaseUri(URI.create(base)).setRequestTimeout(timeout).apply {
            if (networkConfigured) setLocalSigningContext(LocalSigningContext(network))
            headers.forEach { (name, value) -> putDefaultHeader(name, value) }
        }.build())

    @Test
    fun exactBodyPathAccountAndNetworkAreSignedFreshOnExplicitRecovery() {
        val executor = RecordingExecutor()
        val transport = client(executor, headers = mapOf("X-Dataspace-Id" to "is2"))
        val original = Request.evidence(dispatch, evidence)
        val recovered = Request.decodeCanonical(original.canonicalWire())
        val authentication = auth()
        assertSame(Response.Pending, transport.enrollKagemushaWalletV1(original, authentication, Runnable {}).join())
        assertSame(Response.Pending, transport.enrollKagemushaWalletV1(recovered, authentication, Runnable {}).join())
        assertEquals(2, executor.requests.size)
        val first = executor.requests[0]; val second = executor.requests[1]
        assertEquals("POST", first.method)
        assertEquals("https://example.test/torii/v1/kagemusha/enrollment", first.uri.toASCIIString())
        assertContentEquals(original.canonicalWire(), first.body)
        assertContentEquals(first.body, second.body)
        assertEquals(RequestReplayPolicy.ONE_SHOT, first.replayPolicy)
        assertEquals(Response.MAXIMUM_BYTES.toLong(), first.maximumResponseBytes)
        assertEquals(Duration.ofSeconds(15), first.timeout)
        for (header in listOf("Accept", "Content-Type")) assertEquals("application/x-norito", first.headers[header]?.single())
        assertEquals("identity", first.headers["Accept-Encoding"]?.single())
        assertEquals("no-store", first.headers["Cache-Control"]?.single())
        assertEquals("is2", first.headers["X-Dataspace-Id"]?.single())
        assertEquals("0x02000120d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            first.headers[CanonicalRequestSigner.HEADER_ACCOUNT]?.single())
        val nonce = first.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single()
        assertFalse(nonce == second.headers[CanonicalRequestSigner.HEADER_NONCE]!!.single())
        val timestamp = first.headers[CanonicalRequestSigner.HEADER_TIMESTAMP_MS]!!.single().toLong()
        val signature = java.util.Base64.getDecoder().decode(first.headers[CanonicalRequestSigner.HEADER_SIGNATURE]!!.single())
        fun valid(message: ByteArray): Boolean = Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(publicKey, 0)); update(message, 0, message.size); verifySignature(signature)
        }
        assertTrue(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "POST", first.uri, first.body, timestamp, nonce)))
        assertFalse(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "GET", first.uri, first.body, timestamp, nonce)))
        assertFalse(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "POST", first.uri,
            Request.issue(dispatch).canonicalWire(), timestamp, nonce)))
        assertFalse(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(network, "POST", URI.create("https://example.test/other"),
            first.body, timestamp, nonce)))
        assertFalse(valid(CanonicalRequestSigner.canonicalRequestSignatureMessage(TestNetworkIds.fromSeed(42), "POST", first.uri,
            first.body, timestamp, nonce)))
    }

    @Test
    fun transportBindsEveryResponseVariantToItsRequestedAction() {
        val requests = listOf(Request.preKey(dispatch), Request.evidence(dispatch, evidence), Request.issue(dispatch), Request.deliver(dispatch))
        val responses = listOf(Response.Permit(byteArrayOf(7, 8)), Response.EvidenceReady, Response.Pending,
            Response.CredentialReady, Response.Credential(byteArrayOf(9, 10)))
        requests.forEachIndexed { action, request -> responses.forEachIndexed { tag, response ->
            val executor = RecordingExecutor().apply {
                this.response = { CompletableFuture.completedFuture(ok(it, response.canonicalWire())) }
            }
            val call = client(executor).enrollKagemushaWalletV1(request, auth(), Runnable {})
            val accepted = (action == 0 && tag == 0) || (action == 1 && tag in 1..2) || (action == 2 && tag == 3) || (action == 3 && tag == 4)
            if (accepted) assertContentEquals(response.canonicalWire(), call.join().canonicalWire())
            else assertFailsWith<CompletionException> { call.join() }
            assertEquals(1, executor.requests.size)
        } }
    }

    @Test
    fun unsafeAuthConfigurationRejectsBeforeSigningOrDispatch() {
        val executor = RecordingExecutor()
        val neverSign = ToriiCanonicalRequestAuth(account, RequestSigner { error("must not sign") })
        val request = Request.preKey(dispatch)
        for (base in listOf("http://example.test", "http://localhost", "https://user@example.test", "https://example.test?q=1", "https://example.test#f")) {
            assertFailsWith<IllegalArgumentException> { client(executor, base).buildKagemushaWalletEnrollmentRequestV1(request, neverSign) }
        }
        assertFailsWith<IllegalArgumentException> {
            client(executor, timeout = Duration.ZERO).buildKagemushaWalletEnrollmentRequestV1(request, neverSign)
        }
        assertFailsWith<IllegalStateException> {
            client(executor, networkConfigured = false).buildKagemushaWalletEnrollmentRequestV1(request, neverSign)
        }
        assertFailsWith<IllegalArgumentException> {
            client(executor).buildKagemushaWalletEnrollmentRequestV1(request, ToriiCanonicalRequestAuth("alice@universal", neverSign.signer))
        }
        for (header in listOf("x-iroha-account", "X-Iroha-Signature", "x-iroha-timestamp-ms", "X-Iroha-Nonce", "X-Iroha-Witness",
            "X-Iroha-Operator-Public-Key", "X-Iroha-Operator-Signature", "X-Iroha-Operator-Timestamp-Ms", "X-Iroha-Operator-Nonce",
            "Content-Type", "Accept", "Content-Encoding", "Accept-Encoding", "Cache-Control")) {
            assertFailsWith<IllegalArgumentException> {
                client(executor, headers = mapOf(header to "override")).buildKagemushaWalletEnrollmentRequestV1(request, neverSign)
            }
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun multisigAndForeignOrMalformedSignerRefuseBeforeHttpDispatch() {
        val executor = RecordingExecutor()
        val transport = client(executor)
        val request = Request.preKey(dispatch)
        val multisig = AccountAddress.fromMultisigPolicy(MultisigPolicyPayload.of(1, 1,
            listOf(MultisigMemberPayload(1, 1, publicKey)))).toI105Default()
        assertFailsWith<IllegalArgumentException> {
            transport.enrollKagemushaWalletV1(request,
                ToriiCanonicalRequestAuth(multisig, RequestSigner { error("must not sign") }), Runnable {})
        }
        val foreignSigner = RequestSigner { message -> Ed25519Signer().run {
            init(true, Ed25519PrivateKeyParameters(ByteArray(32) { 42 }, 0))
            update(message, 0, message.size); generateSignature()
        } }
        for (signer in listOf(foreignSigner, RequestSigner { byteArrayOf(1) }, RequestSigner { ByteArray(64) { 1 } })) {
            assertFailsWith<IllegalArgumentException> {
                transport.enrollKagemushaWalletV1(request, ToriiCanonicalRequestAuth(account, signer), Runnable {})
            }
        }
        assertTrue(executor.requests.isEmpty())
    }

    @Test
    fun elapsedDeadlineDuringSigningOrResponsePreventsDeliveryAndRetry() {
        val executor = RecordingExecutor()
        val signing = auth().signer
        val slowAuth = ToriiCanonicalRequestAuth(account, RequestSigner { message -> Thread.sleep(20); signing.sign(message) })
        val transport = client(executor, timeout = Duration.ofMillis(5))
        val delayedSign = assertFailsWith<CompletionException> {
            transport.enrollKagemushaWalletV1(Request.evidence(dispatch, evidence), slowAuth, Runnable {}).join()
        }
        assertTrue(delayedSign.cause is java.util.concurrent.TimeoutException)
        assertTrue(executor.requests.isEmpty())

        val upstream = CompletableFuture<TransportResponse>()
        executor.response = { upstream }
        val pending = client(executor, timeout = Duration.ofMillis(100)).enrollKagemushaWalletV1(
            Request.evidence(dispatch, evidence), auth(), Runnable {})
        Thread.sleep(110)
        upstream.complete(ok(executor.requests.single(), Response.Pending.canonicalWire()))
        val delayedResponse = assertFailsWith<CompletionException> { pending.join() }
        assertTrue(delayedResponse.cause is java.util.concurrent.TimeoutException)
        assertEquals(1, executor.requests.size)
    }

    @Test
    fun invalidHttpAndMalformedNoritoFailWithoutRetryOrFallback() {
        for (failure in 0..15) {
            val executor = RecordingExecutor()
            executor.response = { request -> CompletableFuture.completedFuture(TransportResponse(
                when (failure) { 0 -> 202; 1 -> 302; 2 -> 401; 3 -> 404; 4 -> 503; else -> 200 },
                when (failure) { 5 -> ByteArray(0); 6 -> ByteArray(Response.MAXIMUM_BYTES + 1); 7 -> byteArrayOf(1, 2); else -> Response.Pending.canonicalWire() }, "",
                mapOf("Content-Type" to if (failure == 8) listOf("application/json") else if (failure == 9)
                    listOf("application/x-norito", "application/x-norito") else listOf("application/x-norito")) +
                    when (failure) { 10 -> mapOf("Content-Encoding" to listOf("gzip"));
                        11 -> mapOf("Content-Length" to listOf("1")); else -> emptyMap() },
                when (failure) { 12 -> null; 13 -> URI.create("https://other.test/v1/kagemusha/enrollment"); else -> request.uri },
                failure == 14)) }
            if (failure == 15) executor.response = { CompletableFuture<TransportResponse>().apply {
                completeExceptionally(java.io.IOException("delivery interrupted")) } }
            assertFailsWith<CompletionException> {
                client(executor).enrollKagemushaWalletV1(Request.evidence(dispatch, evidence), auth(), Runnable {}).join()
            }
            assertEquals(1, executor.requests.size)
        }
    }

    @Test
    fun ownerChangesBeforeSigningAfterSigningAndBeforeDeliveryReject() {
        for (failAt in 1..5) {
            val executor = RecordingExecutor()
            var checks = 0
            val owner = Runnable { checks++; check(checks < failAt) { "owner changed" } }
            if (failAt == 1) assertFailsWith<IllegalStateException> {
                client(executor).enrollKagemushaWalletV1(Request.evidence(dispatch, evidence), auth(), owner)
            } else assertFailsWith<CompletionException> {
                client(executor).enrollKagemushaWalletV1(Request.evidence(dispatch, evidence), auth(), owner).join()
            }
            assertEquals(if (failAt <= 3) 0 else 1, executor.requests.size)
        }
    }

    @Test
    fun cancellationPropagatesBothDirectionsWithoutRetry() {
        for (cancelClient in listOf(true, false)) {
            val upstream = CompletableFuture<TransportResponse>()
            val executor = RecordingExecutor().apply { response = { upstream } }
            val result = client(executor).enrollKagemushaWalletV1(Request.evidence(dispatch, evidence), auth(), Runnable {})
            if (cancelClient) result.cancel(false) else upstream.cancel(false)
            assertTrue(upstream.isCancelled); assertTrue(result.isCancelled)
            assertEquals(1, executor.requests.size)
        }
    }

    @Test
    fun explicitNonceCannotBeReusedForRecovery() {
        val executor = RecordingExecutor()
        val transport = client(executor)
        val request = Request.evidence(dispatch, evidence)
        val authentication = ToriiCanonicalRequestAuth(account, auth().signer, 1_700_000_000_000L, "0123456789abcdef0123456789abcdef")
        assertSame(Response.Pending, transport.enrollKagemushaWalletV1(request, authentication, Runnable {}).join())
        assertFailsWith<IllegalStateException> { transport.enrollKagemushaWalletV1(request, authentication, Runnable {}) }
        assertEquals(1, executor.requests.size)
    }

    companion object {
        private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun ok(request: TransportRequest, body: ByteArray) = TransportResponse(200, body, "",
            mapOf("Content-Type" to listOf("application/x-norito"), "Content-Length" to listOf(body.size.toString())), request.uri, false)
    }
}
