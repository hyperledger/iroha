package org.hyperledger.iroha.sdk.privacy

import org.hyperledger.iroha.sdk.client.RequestSigner

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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.ClientConfig
import org.hyperledger.iroha.sdk.client.CanonicalRequestSigner
import org.hyperledger.iroha.sdk.client.HttpClientTransport
import org.hyperledger.iroha.sdk.client.HttpTransportExecutor
import org.hyperledger.iroha.sdk.client.LocalSigningContext
import org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId

class PrivacyCapabilitiesV1Test {
    private val networkId = NetworkId.parse(
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
    )
    private val otherNetworkId = NetworkId.parse(
        "hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22",
    )
    private val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    @Test
    fun catalogOwnerPinsRaw32AndRetainsIndependentBytes() {
        val canonical = "5bcf366fb18d2e4361486c015da5b41a3fb00edf05611042ccc452120d176eb0".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val source = canonical.copyOf()
        val owner = PrivacyExact12CatalogCommitmentV1(source)
        source[0] = 0
        val exported = owner.bytes()
        exported[31] = 0
        assertTrue(owner.bytes().contentEquals(canonical))
        assertEquals(32, owner.bytes().size)
        val hostile = listOf(
            canonical.copyOf(31), canonical + byteArrayOf(0), canonical.copyOf(48),
            "e037f13904a0307c00db15d85cfb406bd79772d20144a949def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff".chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        ) + canonical.indices.map { index ->
            canonical.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
        }
        for (bytes in hostile) {
            assertFailsWith<IllegalArgumentException> { PrivacyExact12CatalogCommitmentV1(bytes) }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example", "http://localhost", "http://192.168.1.2"])
    fun configuredClientUsesExactNoritoRouteAndRejectsLegacySnapshot(baseUri: String) {
        val response = TransportResponse.builder()
            .setStatusCode(200)
            .setNetworkProvenance(URI.create("$baseUri/v1/privacy/capabilities"), false)
            .setBody(unavailableSnapshot("42").toByteArray(StandardCharsets.UTF_8))
            .addHeader("Content-Type", "application/x-norito")
            .build()
        val executor = OneResponseExecutor(response)
        val client = HttpClientTransport(
            executor,
            signedConfig().toBuilder()
                .setBaseUri(URI.create(baseUri))
                .setAllowLocalDevelopmentHttp(baseUri.startsWith("http:"))
                .build(),
        )
        val legacy = assertFailsWith<CompletionException> {
            client.getPrivacyCapabilities(canonicalAuth()).join()
        }
        assertTrue(legacy.cause is RuntimeException)
        assertEquals("/v1/privacy/capabilities", executor.request.uri.rawPath)
        assertEquals(listOf("application/x-norito"), executor.request.headers["Accept"])
        assertEquals(listOf("no-store"), executor.request.headers["Cache-Control"])
        assertEquals(listOf("identity"), executor.request.headers["Accept-Encoding"])
        assertEquals(RequestReplayPolicy.ONE_SHOT, executor.request.replayPolicy)
        assertEquals(1, executor.requestCount)
        assertEquals(0, executor.request.body.size)
        assertCanonicalSignature(executor.request, networkId, true)
        assertCanonicalSignature(executor.request, otherNetworkId, false)
        assertCanonicalSignature(executor.request, networkId, false, method = "POST")
        assertCanonicalSignature(
            executor.request,
            networkId,
            false,
            uri = URI.create("$baseUri/v1/privacy/other"),
        )
        assertCanonicalSignature(executor.request, networkId, false, body = byteArrayOf(0))
        assertEquals(
            PrivacyExact12CapabilityManifestV1.MAX_ARCHIVE_BYTES.toLong(),
            executor.request.maximumResponseBytes,
        )

        val wrongMedia = response.let {
            TransportResponse.builder()
                .setStatusCode(200)
                .setBody(it.body)
                .addHeader("Content-Type", "application/json; charset=utf-8")
                .build()
        }
        val error = assertFailsWith<CompletionException> {
            HttpClientTransport(
                OneResponseExecutor(wrongMedia),
                signedConfig().toBuilder().setBaseUri(URI.create(baseUri))
                    .setAllowLocalDevelopmentHttp(baseUri.startsWith("http:")).build(),
            ).getPrivacyCapabilities(canonicalAuth()).join()
        }
        assertTrue(error.cause is RuntimeException)
    }

    @Test
    fun exactTransportRejectsHeaderAmbiguityLengthSmugglingAndHostileBodies() {
        val body = unavailableSnapshot("42").toByteArray(StandardCharsets.UTF_8)
        val canonicalHeaders = mapOf(
            "Content-Type" to listOf("application/x-norito"),
            "Content-Length" to listOf(body.size.toString()),
        )
        val legacy = assertFailsWith<CompletionException> {
            clientFor(response(body = body, headers = canonicalHeaders))
                .getPrivacyCapabilities(canonicalAuth())
                .join()
        }
        assertTrue(legacy.cause is RuntimeException)

        val hostile = buildList {
            add(response(statusCode = 206, body = body, headers = canonicalHeaders))
            add(response(body = body, headers = mapOf("Content-Type" to listOf("application/json; charset=utf-8"))))
            add(response(body = body, headers = mapOf("Content-Type" to listOf("application/x-norito", "application/x-norito"))))
            add(response(body = body, headers = mapOf("Content-Type" to listOf("application/x-norito"), "Content-Length" to listOf(body.size.toString(), body.size.toString()))))
            add(response(body = body, headers = mapOf("Content-Type" to listOf("application/x-norito"), "Content-Length" to listOf((body.size + 1).toString()))))
            for (length in listOf("+${body.size}", "0${body.size}", "${body.size} ", "-1", "9".repeat(1_024))) {
                add(response(body = body, headers = mapOf("Content-Type" to listOf("application/x-norito"), "Content-Length" to listOf(length))))
            }
            add(response(body = ByteArray(0), headers = mapOf("Content-Type" to listOf("application/x-norito"))))
            add(
                response(
                    body = ByteArray(PrivacyExact12CapabilityManifestV1.MAX_ARCHIVE_BYTES + 1) { 0x20 },
                    headers = mapOf("Content-Type" to listOf("application/x-norito")),
                ),
            )
        }
        hostile.forEachIndexed { index, candidate ->
            val error = assertFailsWith<CompletionException>("hostile response $index must fail closed") {
                clientFor(candidate).getPrivacyCapabilities(canonicalAuth()).join()
            }
            assertTrue(error.cause is RuntimeException, "unexpected hostile response $index cause: ${error.cause}")
        }
    }

    @Test
    fun exactTransportRejectsCaseVariantDefaultAcceptBeforeDispatch() {
        val body = unavailableSnapshot("42").toByteArray(StandardCharsets.UTF_8)
        val executor = OneResponseExecutor(
            response(body = body, headers = mapOf("Content-Type" to listOf("application/x-norito"))),
        )
        val client = HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .putDefaultHeader("aCcEpT", "application/x-norito")
                .build(),
        )
        assertFailsWith<IllegalArgumentException> {
            client.getPrivacyCapabilities(canonicalAuth())
        }
    }

    @Test
    fun privacyAdmissionRequiresNetworkContextAndCanonicalHeaderOwnership() {
        val body = unavailableSnapshot("42").toByteArray(StandardCharsets.UTF_8)
        val response = response(
            body = body,
            headers = mapOf("Content-Type" to listOf("application/x-norito")),
        )
        val missingContextExecutor = OneResponseExecutor(response)
        val missingContextClient = HttpClientTransport(
            missingContextExecutor,
            ClientConfig.builder().setBaseUri(URI.create("https://torii.example")).build(),
        )
        assertFailsWith<IllegalStateException> {
            missingContextClient.getPrivacyCapabilities(canonicalAuth())
        }
        assertEquals(0, missingContextExecutor.requestCount)

        val forgedHeaderExecutor = OneResponseExecutor(response)
        val forgedHeaderClient = HttpClientTransport(
            forgedHeaderExecutor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .putDefaultHeader("x-IROHA-signature", "forged")
                .build(),
        )
        assertFailsWith<IllegalArgumentException> {
            forgedHeaderClient.getPrivacyCapabilities(canonicalAuth())
        }
        assertEquals(0, forgedHeaderExecutor.requestCount)

        val admissionExecutor = OneResponseExecutor(response)
        val admissionClient = HttpClientTransport(admissionExecutor, signedConfig())
        assertFailsWith<CompletionException> {
            admissionClient.requirePrivacyExact12CapabilityAdmission(
                PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1,
                canonicalAuth(),
            ).join()
        }
        assertEquals(1, admissionExecutor.requestCount)
        assertEquals(RequestReplayPolicy.ONE_SHOT, admissionExecutor.request.replayPolicy)
    }

    @Test
    fun privacyCapabilityResponseRequiresExactOriginBeforeNativeDecoding() {
        for ((uri, redirected) in listOf(
            null to false,
            URI.create("https://other.example/v1/privacy/capabilities") to false,
            URI.create("https://torii.example/v1/privacy/capabilities") to true,
        )) {
            val response = TransportResponse.builder()
                .setStatusCode(200)
                .setBody(byteArrayOf(1))
                .addHeader("Content-Type", "application/x-norito")
                .apply { if (uri != null) setNetworkProvenance(uri, redirected) }
                .build()
            val error = assertFailsWith<CompletionException> {
                clientFor(response).getPrivacyCapabilities(canonicalAuth()).join()
            }
            assertTrue(error.cause?.message.orEmpty().contains("exact signed URL"))
        }
    }

    @Test
    fun privacyCapabilityFetchRejectsHttpBeforeDispatch() {
        val executor = OneResponseExecutor(response(
            body = byteArrayOf(1), headers = mapOf("Content-Type" to listOf("application/x-norito")),
        ))
        val client = HttpClientTransport(executor, ClientConfig.builder()
            .setBaseUri(URI.create("http://localhost"))
            .setLocalSigningContext(LocalSigningContext(networkId)).build())
        val error = assertFailsWith<IllegalArgumentException> {
            client.getPrivacyCapabilities(canonicalAuth())
        }
        assertTrue(error.message.orEmpty().contains("HTTPS"))
        assertEquals(0, executor.requestCount)
    }

    private fun unavailableSnapshot(height: String): String =
        """{"version":1,"committed_height":$height,"consensus_policy":{"current_limits":${consensusLimits()},"pending_tightening":null},"protocols":[${PrivacyProtocolIdV1.values().joinToString(",") { unavailableRow(it) }}]}"""

    private fun unavailableRow(protocol: PrivacyProtocolIdV1): String =
        """{"protocol_id":{"protocol":"${protocol.canonicalLabel}","value":null},"compiled_profile":{"status":"unavailable","value":{"reason":"engine-unavailable","detail":null}},"activation":null}"""

    private fun consensusLimits(): String =
        """{"max_actions_per_transaction":1,"max_actions_per_block":2,"max_proof_bytes_per_action":9437184,"max_action_bytes":9699840,"max_privacy_bytes_per_transaction":9699840,"max_privacy_bytes_per_block":16711680,"max_statement_and_encrypted_output_bytes_per_transaction":262144,"max_nullifiers_per_action":8,"max_commitments_per_action":8,"retained_root_count":2048}"""

    private fun response(
        statusCode: Int = 200,
        body: ByteArray,
        headers: Map<String, List<String>>,
    ): TransportResponse = TransportResponse.builder()
        .setStatusCode(statusCode)
        .setNetworkProvenance(URI.create("https://torii.example/v1/privacy/capabilities"), false)
        .setBody(body)
        .setHeaders(headers)
        .build()

    private fun clientFor(response: TransportResponse): HttpClientTransport =
        HttpClientTransport(
            OneResponseExecutor(response),
            signedConfig(),
        )

    private fun signedConfig(): ClientConfig = ClientConfig.builder()
        .setBaseUri(URI.create("https://torii.example"))
        .setLocalSigningContext(LocalSigningContext(networkId))
        .build()

    private fun canonicalAuth(): ToriiCanonicalRequestAuth = ToriiCanonicalRequestAuth(
        "alice@universal",
        RequestSigner.ed25519(keyPair.private),
        1_700_000_000_000L,
        "privacy-capabilities-1",
    )

    private fun assertCanonicalSignature(
        request: TransportRequest,
        expectedNetworkId: NetworkId,
        expected: Boolean,
        method: String = request.method,
        uri: URI = request.uri,
        body: ByteArray = request.body,
    ) {
        val encoded = assertNotNull(
            request.headers[CanonicalRequestSigner.HEADER_SIGNATURE]?.singleOrNull(),
        )
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(keyPair.public)
        verifier.update(
            CanonicalRequestSigner.canonicalRequestSignatureMessage(
                expectedNetworkId,
                method,
                uri,
                body,
                1_700_000_000_000L,
                "privacy-capabilities-1",
            ),
        )
        if (expected) {
            assertTrue(verifier.verify(Base64.getDecoder().decode(encoded)))
        } else {
            assertFalse(verifier.verify(Base64.getDecoder().decode(encoded)))
        }
    }

    private class OneResponseExecutor(
        private val response: TransportResponse,
    ) : HttpTransportExecutor {
        lateinit var request: TransportRequest
        var requestCount: Int = 0

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            this.request = request
            requestCount++
            return CompletableFuture.completedFuture(response)
        }
    }
}
