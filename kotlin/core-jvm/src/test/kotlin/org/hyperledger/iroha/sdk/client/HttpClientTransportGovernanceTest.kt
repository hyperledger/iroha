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
    fun parliamentAttemptReadGetIsAuthenticatedAndBounded() {
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
            "parliament-attempt-read",
        )
        val attemptId = "44".repeat(32)

        assertFailsWith<CompletionException> {
            transport.getParliamentAttemptV1(attemptId, auth).join()
        }
        val request = assertNotNull(executor.lastRequest)
        assertEquals("GET", request.method)
        assertEquals("/api/v1/gov/parliament/attempts/$attemptId", request.uri.rawPath)
        assertContentEquals(ByteArray(0), request.body)
        assertEquals(
            2L * ParliamentApiV1.MAX_STATE_BYTES + 2L * 1024L * 1024L,
            request.maximumResponseBytes,
        )
        assertEquals(RequestReplayPolicy.ONE_SHOT, request.replayPolicy)
        assertTrue(request.headers.keys.any { it.equals("X-Iroha-Signature", true) })
        assertEquals(1, executor.requestCount)
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
}
