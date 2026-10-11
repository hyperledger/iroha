// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.client.RequestSigner

import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.RequestReplayPolicy
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader

class HttpClientTransportGovernanceTest {
    private val networkId = NetworkId.parse(
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
    )

    @Test
    fun getGovernanceContractParsesResponse() {
        val contractAddress = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
        val owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        val u64Max = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
        val executor = StubResponseExecutor(
            statusCode = 200,
            body = """
                {
                  "found": true,
                  "contract_address": "$contractAddress",
                  "contract_subject_account": "$owner",
                  "dataspace": "router",
                  "active": true,
                  "lifecycle": {
                    "version": 1,
                    "origin": "direct",
                    "origin_account": "$owner",
                    "origin_proposal_content_id_hex": null,
                    "origin_governance_attempt_id_hex": null,
                    "owner": "$owner",
                    "pending_owner": "parliament",
                    "parliament_delegated": true,
                    "active_code_hash_hex": "${"77".repeat(32)}",
                    "retained_code_hash_hex": "${"77".repeat(32)}",
                    "revision": $u64Max,
                    "emergency_hold": {
                      "incident_digest_hex": "${"11".repeat(32)}",
                      "proposal_content_id_hex": "${"22".repeat(32)}",
                      "governance_attempt_id_hex": "${"33".repeat(32)}",
                      "reason": "incident response",
                      "imposed_at_height": ${u64Max - BigInteger.ONE},
                      "expires_at_height": $u64Max
                    }
                  },
                  "emergency_hold_active": true,
                  "code_hash_hex": "${"77".repeat(32)}",
                  "abi_hash_hex": "${"88".repeat(32)}",
                  "public_entrypoints": ["transfer", "view_balance"]
                }
            """.trimIndent().toByteArray(StandardCharsets.UTF_8),
        )
        val transport = HttpClientTransport(
            executor = executor,
            config = ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example/api"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )

        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val auth = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            1_700_000_000_100L,
            "governance-read",
        )
        val response = transport.getGovernanceContract(contractAddress, auth).join()

        assertTrue(response.found)
        assertEquals(contractAddress, response.contractAddress)
        assertEquals("router", response.dataspace)
        assertEquals("77".repeat(32), response.codeHashHex)
        assertEquals(1, response.lifecycle?.version)
        assertEquals(u64Max, response.lifecycle?.revision)
        assertEquals("parliament", response.lifecycle?.pendingOwner)
        assertEquals("77".repeat(32), response.lifecycle?.activeCodeHashHex)
        assertEquals("77".repeat(32), response.lifecycle?.retainedCodeHashHex)
        assertEquals(u64Max - BigInteger.ONE, response.lifecycle?.emergencyHold?.imposedAtHeight)
        assertEquals(u64Max, response.lifecycle?.emergencyHold?.expiresAtHeight)
        assertEquals(listOf("transfer", "view_balance"), response.publicEntrypoints)

        val request = assertNotNull(executor.lastRequest)
        assertEquals("GET", request.method)
        assertEquals(
            "https://torii.example/api/v1/gov/contracts/$contractAddress",
            request.uri.toString(),
        )
        assertTrue(request.body.isEmpty())
    }

    @Test
    fun governanceContractResponseRejectsShapeAndCrossFieldDrift() {
        val contractAddress = "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
        val owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        val active = """
            {
              "found": true,
              "contract_address": "$contractAddress",
              "contract_subject_account": "$owner",
              "dataspace": "router",
              "active": true,
              "lifecycle": {
                "version": 1,
                "origin": "direct",
                "origin_account": "$owner",
                "origin_proposal_content_id_hex": null,
                "origin_governance_attempt_id_hex": null,
                "owner": "$owner",
                "pending_owner": null,
                "parliament_delegated": false,
                "active_code_hash_hex": "${"77".repeat(32)}",
                "retained_code_hash_hex": "${"77".repeat(32)}",
                "revision": 7,
                "emergency_hold": null
              },
              "emergency_hold_active": false,
              "code_hash_hex": "${"77".repeat(32)}",
              "abi_hash_hex": "${"88".repeat(32)}",
              "public_entrypoints": ["transfer", "view_balance"]
            }
        """.trimIndent()
        val invalid = listOf(
            active.replace("\"retained_code_hash_hex\": \"${"77".repeat(32)}\",", ""),
            active.replace("\"retained_code_hash_hex\": \"${"77".repeat(32)}\"", "\"retained_code_hash_hex\": null"),
            active.replace(
                "\"active_code_hash_hex\": \"${"77".repeat(32)}\"",
                "\"active_code_hash_hex\": \"${"66".repeat(32)}\"",
            ),
            active.replace(
                "[\"transfer\", \"view_balance\"]",
                "[\"view_balance\", \"transfer\"]",
            ),
            active.replace("\"version\": 1", "\"version\": 2"),
            active.replace("\"revision\": 7", "\"revision\": 18446744073709551616"),
            """{"found":false,"contract_address":"$contractAddress","dataspace":"router","active":null}""",
        )
        for (payload in invalid) {
            assertFailsWith<IllegalStateException> {
                ContractJsonParser.parseGovernanceContractResponse(
                    payload.toByteArray(StandardCharsets.UTF_8),
                )
            }
        }
    }

    @Test
    fun parliamentCastingProofPostIsExactAuthenticatedBoundedAndOneShot() {
        val responsePayload = byteArrayOf(2, 1, 0, 1)
        val responseHeader = NoritoHeader(
            decodeHex(ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            responsePayload.size,
            CRC64.compute(responsePayload),
            NoritoHeader.COMPACT_LEN,
            NoritoHeader.COMPRESSION_NONE,
        )
        val responseFrame = responseHeader.encode() + responsePayload
        val executor = StubResponseExecutor(
            statusCode = 200,
            body = responseFrame,
            headers = mapOf(
                "Content-Type" to listOf("application/x-norito"),
                "Content-Length" to listOf(responseFrame.size.toString()),
            ),
        )
        val transport = HttpClientTransport(
            executor = executor,
            config = ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example/api"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        fun auth() = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            1_700_000_000_100L,
            "parliament-casting-proof",
        )
        val ballotId = "33".repeat(32)
        val response = transport.getParliamentTimedOvnCastingProofPageV1(
            ballotId,
            BigInteger.valueOf(17),
            auth(),
        ).join()

        assertContentEquals(responseFrame, response.canonicalNorito())
        val request = assertNotNull(executor.lastRequest)
        assertEquals("POST", request.method)
        assertEquals(
            "/api/v1/gov/parliament/ballots/$ballotId/casting-proof",
            request.uri.rawPath,
        )
        assertContentEquals(
            ParliamentApiV1.timedOvnCastingProofRequestNorito(17),
            request.body,
        )
        assertEquals(listOf("application/x-norito"), request.headers["Content-Type"])
        assertEquals(listOf("application/x-norito"), request.headers["Accept"])
        assertEquals(listOf("identity"), request.headers["Accept-Encoding"])
        assertEquals(
            ParliamentApiV1.MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES.toLong(),
            request.maximumResponseBytes,
        )
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        assertEquals(1, executor.requestCount)
        assertTrue(request.headers.keys.any { it.equals("X-Iroha-Signature", true) })

        val encodedExecutor = StubResponseExecutor(
            statusCode = 200,
            body = responseFrame,
            headers = mapOf(
                "Content-Type" to listOf("application/x-norito"),
                "Content-Encoding" to listOf("gzip"),
            ),
        )
        val encodedTransport = HttpClientTransport(
            encodedExecutor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )
        assertFailsWith<CompletionException> {
            encodedTransport.requestParliamentTimedOvnCastingProofV1(
                ballotId,
                17,
                auth(),
            ).join()
        }
        assertEquals(1, encodedExecutor.requestCount)
    }

    @Test
    fun parliamentCastingContextGetIsAuthenticatedAndBounded() {
        val executor = StubResponseExecutor(
            statusCode = 404,
            body = ByteArray(0),
        )
        val transport = HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example/api"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val auth = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            1_700_000_000_100L,
            "parliament-casting-context",
        )
        val ballotId = "44".repeat(32)

        assertFailsWith<CompletionException> {
            transport.getParliamentTimedOvnCastingContextV1(ballotId, auth).join()
        }
        val request = assertNotNull(executor.lastRequest)
        assertEquals("GET", request.method)
        assertEquals(
            "/api/v1/gov/parliament/ballots/$ballotId/casting-context",
            request.uri.rawPath,
        )
        assertContentEquals(ByteArray(0), request.body)
        assertEquals(ParliamentApiV1.MAX_STATE_BYTES.toLong(), request.maximumResponseBytes)
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        assertTrue(request.headers.keys.any { it.equals("X-Iroha-Signature", true) })
        assertEquals(1, executor.requestCount)
    }

    @Test
    fun parliamentCastingProofPagingDurablyAdvancesStaleAnchorBeyondSixtyThreeHeights() {
        val responseFrame = castingProofResponseFrame()
        val executor = SequenceResponseExecutor(responseFrame)
        val transport = HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example/api"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val auth = ToriiCanonicalRequestAuth("alice@universal", RequestSigner.ed25519(keyPair.private))
        val firstContext = ByteArray(32) { 0x11 }
        val secondContext = ByteArray(32) { 0x22 }
        val terminalContext = ByteArray(32) { 0x33 }
        val verifierCalls = AtomicInteger()
        val persisted = mutableListOf<ParliamentTimedOvnCastingProofPageVerificationV1>()
        val firstPersistence = CompletableFuture<Void>()

        val future = transport.requestParliamentTimedOvnCastingProofUntilTerminalV1(
            "55".repeat(32),
            7,
            firstContext,
            auth,
            ParliamentTimedOvnCastingProofPageVerifierV1 { _, height, context ->
                when (verifierCalls.getAndIncrement()) {
                    0 -> {
                        assertEquals(BigInteger.valueOf(7), height)
                        assertContentEquals(firstContext, context)
                        ParliamentTimedOvnCastingProofPageVerificationV1(
                            BigInteger.valueOf(70),
                            secondContext,
                            true,
                            secondContext,
                        )
                    }
                    1 -> {
                        assertEquals(BigInteger.valueOf(70), height)
                        assertContentEquals(secondContext, context)
                        ParliamentTimedOvnCastingProofPageVerificationV1(
                            BigInteger.valueOf(75),
                            terminalContext,
                            false,
                            terminalContext,
                        )
                    }
                    else -> error("unexpected casting-proof page")
                }
            },
            ParliamentTimedOvnCastingCheckpointPersisterV1 { verification ->
                persisted += verification
                if (persisted.size == 1) firstPersistence
                else CompletableFuture.completedFuture(null)
            },
        )

        assertEquals(1, executor.requests.size)
        assertTrue(!future.isDone)
        firstPersistence.complete(null)
        val terminal = future.join()

        assertEquals(2, executor.requests.size)
        assertEquals(2, persisted.size)
        assertEquals(2, terminal.verifiedPageCount)
        assertEquals(BigInteger.valueOf(70), terminal.verificationAnchorHeight)
        assertContentEquals(secondContext, terminal.verificationAnchorCheckpointNorito())
        assertEquals(BigInteger.valueOf(75), terminal.verification.evaluatedBlockHeight)
        assertTrue(!terminal.verification.moreAvailable)
        assertContentEquals(
            ParliamentApiV1.timedOvnCastingProofRequestNorito(7),
            executor.requests[0].body,
        )
        assertContentEquals(
            ParliamentApiV1.timedOvnCastingProofRequestNorito(70),
            executor.requests[1].body,
        )
    }

    @Test
    fun parliamentCastingProofPagingRejectsNativeAdvancePastPageBound() {
        val executor = SequenceResponseExecutor(castingProofResponseFrame())
        val transport = HttpClientTransport(
            executor,
            ClientConfig.builder()
                .setBaseUri(URI.create("https://torii.example"))
                .setLocalSigningContext(LocalSigningContext(networkId))
                .build(),
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        var persistCalls = 0
        val failure = assertFailsWith<CompletionException> {
            transport.requestParliamentTimedOvnCastingProofUntilTerminalV1(
                "66".repeat(32),
                7,
                ByteArray(32) { 0x11 },
                ToriiCanonicalRequestAuth("alice@universal", RequestSigner.ed25519(keyPair.private)),
                ParliamentTimedOvnCastingProofPageVerifierV1 { _, _, _ ->
                    ParliamentTimedOvnCastingProofPageVerificationV1(
                        BigInteger.valueOf(71),
                        ByteArray(32) { 0x22 },
                        true,
                        ByteArray(113) { 0x44 },
                    )
                },
                ParliamentTimedOvnCastingCheckpointPersisterV1 {
                    persistCalls += 1
                    CompletableFuture.completedFuture(null)
                },
            ).join()
        }
        assertTrue(failure.cause is IllegalArgumentException)
        assertEquals(0, persistCalls)
        assertEquals(1, executor.requests.size)
    }

    private fun castingProofResponseFrame(): ByteArray {
        val responsePayload = byteArrayOf(2, 1, 0, 1)
        return NoritoHeader(
            decodeHex(ParliamentApiV1.TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            responsePayload.size,
            CRC64.compute(responsePayload),
            NoritoHeader.COMPACT_LEN,
            NoritoHeader.COMPRESSION_NONE,
        ).encode() + responsePayload
    }

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private class StubResponseExecutor(
        private val statusCode: Int,
        private val body: ByteArray,
        private val headers: Map<String, List<String>> = emptyMap(),
    ) : HttpTransportExecutor {
        var lastRequest: TransportRequest? = null
        var requestCount: Int = 0

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            lastRequest = request
            requestCount += 1
            if (request.uri.path.endsWith("/v1/node/capabilities")) {
                return CompletableFuture.completedFuture(
                    TransportResponse.builder()
                        .setStatusCode(200)
                        .setBody(
                            (
                                "{\"data_model_version\":4,\"signed_transaction_schema_hash_hex\":" +
                                    "\"7ab5ff9c572efb316deac478f19209c5\"}"
                                ).toByteArray(StandardCharsets.UTF_8),
                        )
                        .build(),
                )
            }
            return CompletableFuture.completedFuture(
                TransportResponse.builder()
                    .setStatusCode(statusCode)
                    .setBody(body)
                    .setHeaders(headers)
                    .build(),
            )
        }
    }

    private class SequenceResponseExecutor(
        private val body: ByteArray,
    ) : HttpTransportExecutor {
        val requests = mutableListOf<TransportRequest>()

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            requests += request
            return CompletableFuture.completedFuture(
                TransportResponse.builder()
                    .setStatusCode(200)
                    .setBody(body)
                    .setHeaders(
                        mapOf(
                            "Content-Type" to listOf("application/x-norito"),
                            "Content-Length" to listOf(body.size.toString()),
                        ),
                    )
                    .build(),
            )
        }
    }
}
