package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.concurrent.CompletableFuture
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.testing.TestNetworkIds

/**
 * Strict VPN response-schema and successful-status contract coverage.
 */
class HttpClientTransportVpnParserTest {
    private val validEd25519PublicKeyHex = TestEd25519Keys.publicKeyHex(0x22)
    private val validMldsa65PublicKeyHex = "a5".repeat(1_952)

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example", "http://localhost", "http://172.16.1.2"])
    fun getVpnProfileDeserializesNativeLeaseFields(baseUri: String) {
        val responseJson =
            """
                {
                  "available": true,
                  "relay_endpoint": "/dns/relay.example/udp/9443/quic",
                  "supported_exit_classes": ["standard", "low-latency", "high-security"],
                  "default_exit_class": "standard",
                  "lease_secs": 600,
                  "dns_push_interval_secs": 60,
                  "meter_family": "soranet.vpn.standard",
                  "route_pushes": ["0.0.0.0/0"],
                  "excluded_routes": ["10.0.0.0/8"],
                  "dns_servers": ["1.1.1.1"],
                  "tunnel_addresses": ["10.208.0.2/32"],
                  "mtu_bytes": 1280,
                  "display_billing_label": "standard XOR",
                  "operator_account_id": "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT",
                  "lease_fee": "1000000.25",
                  "settlement_grace_secs": 120,
                  "flow_label_bits": 24,
                  "padding_budget_ms": 15,
                  "relay_id_hex": "$validEd25519PublicKeyHex",
                  "relay_mldsa65_public_key_hex": "$validMldsa65PublicKeyHex",
                  "descriptor_commit_hex": "${"cd".repeat(32)}",
                  "tls_server_name": "relay.example",
                  "relay_tls_spki_sha256_hex": "${"ab".repeat(32)}",
                  "relay_certificate_sha256_hex": "${"ef".repeat(32)}",
                  "directory_snapshot_digest_hex": "${"42".repeat(32)}"
                }
            """.trimIndent()
        val executor = StubResponseExecutor(
            statusCode = 200,
            body = responseJson.toByteArray(StandardCharsets.UTF_8),
        )
        val transport = HttpClientTransport(
            executor = executor,
            config = ClientConfig.builder().setBaseUri(URI.create(baseUri))
            .setAllowLocalDevelopmentHttp(baseUri.startsWith("http:")).build(),
        )

        val profile = transport.getVpnProfile().join()

        assertTrue(profile.available)
        assertEquals("sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT", profile.operatorAccountId)
        assertEquals("1000000.25", profile.leaseFee)
        assertEquals(60L, profile.dnsPushIntervalSecs)
        assertEquals(120L, profile.settlementGraceSecs)
        assertEquals(validEd25519PublicKeyHex, profile.relayIdHex)
        assertEquals(validMldsa65PublicKeyHex, profile.relayMldsa65PublicKeyHex)
        assertEquals("cd".repeat(32), profile.descriptorCommitHex)
        assertEquals("relay.example", profile.tlsServerName)
        assertEquals("ab".repeat(32), profile.relayTlsSpkiSha256Hex)
        assertEquals("ef".repeat(32), profile.relayCertificateSha256Hex)
        assertEquals("42".repeat(32), profile.directorySnapshotDigestHex)
        assertEquals("GET", executor.lastRequest.method)
        assertEquals("$baseUri/v1/vpn/profile", executor.lastRequest.uri.toString())

        val shortMldsaIdentity = responseJson.replace(
            "\"relay_mldsa65_public_key_hex\": \"$validMldsa65PublicKeyHex\"",
            "\"relay_mldsa65_public_key_hex\": \"55\"",
        )
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseProfile(shortMldsaIdentity.toByteArray(StandardCharsets.UTF_8))
        }

        val belowMinimum = responseJson.replace("\"dns_push_interval_secs\": 60", "\"dns_push_interval_secs\": 29")
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseProfile(belowMinimum.toByteArray(StandardCharsets.UTF_8))
        }
        val missing = responseJson.lineSequence()
            .filterNot { it.contains("\"dns_push_interval_secs\"") }
            .joinToString("\n")
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseProfile(missing.toByteArray(StandardCharsets.UTF_8))
        }
        val unknown = responseJson.replaceFirst("{", "{\"unexpected\":true,")
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseProfile(unknown.toByteArray(StandardCharsets.UTF_8))
        }
        val uppercaseTlsPin = responseJson.replace("ab".repeat(32), "AB".repeat(32))
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseProfile(uppercaseTlsPin.toByteArray(StandardCharsets.UTF_8))
        }
    }

    @Test
    fun vpnTrustTupleRequiresCanonicalNonZeroMldsaIdentity() {
        val quoteId = "ab".repeat(32)
        val sessionId = "de".repeat(16)
        val paymentTxHash = "cd".repeat(32)
        val payloads: List<Pair<() -> String, (ByteArray) -> Any>> = listOf(
            { vpnProfileJson() } to { VpnJsonParser.parseProfile(it) },
            { vpnQuoteJson(quoteId, validEd25519PublicKeyHex) } to { VpnJsonParser.parseQuote(it) },
            { vpnSessionJson(sessionId, quoteId, paymentTxHash) } to { VpnJsonParser.parseSession(it) },
        )

        payloads.forEach { (payload, parse) ->
            val valid = payload()
            val decoded = parse(valid.toByteArray(StandardCharsets.UTF_8))
            val decodedKey = when (decoded) {
                is VpnProfile -> decoded.relayMldsa65PublicKeyHex
                is VpnQuote -> decoded.relayMldsa65PublicKeyHex
                is VpnSession -> decoded.relayMldsa65PublicKeyHex
                else -> error("unexpected VPN response type")
            }
            assertEquals(validMldsa65PublicKeyHex, decodedKey)

            listOf(
                validMldsa65PublicKeyHex.uppercase(),
                "0".repeat(3_904),
                validMldsa65PublicKeyHex.dropLast(2),
                "${validMldsa65PublicKeyHex}00",
            ).forEach { invalid ->
                val mutated = valid.replace(validMldsa65PublicKeyHex, invalid)
                assertFailsWith<IllegalStateException> {
                    parse(mutated.toByteArray(StandardCharsets.UTF_8))
                }
            }
        }
    }

    @Test
    fun vpnSessionParserRejectsNonCanonicalHelperTicketHex() {
        val sessionId = "33".repeat(16)
        val quoteId = "34".repeat(32)
        val paymentTxHash = "44".repeat(32)
        val valid = vpnHelperTicketHex()
        val invalidValues = listOf(
            "0x$valid",
            valid.uppercase(),
            valid.take(1_456),
            valid.dropLast(2),
        )

        invalidValues.forEach { invalid ->
            val payload = vpnSessionJson(sessionId, quoteId, paymentTxHash).replace(valid, invalid)
            assertFailsWith<IllegalStateException> {
                VpnJsonParser.parseSession(payload.toByteArray(StandardCharsets.UTF_8))
            }
        }
    }

    @Test
    fun vpnReceiptParserRetainsExactLifecycleStatuses() {
        @Suppress("UNCHECKED_CAST")
        val receipt = (JsonParser.parse(
            vpnReceiptJson(
                sessionId = "33".repeat(16),
                quoteId = "34".repeat(32),
                leaseId = "35".repeat(32),
                paymentTxHash = "44".repeat(32),
                settled = true,
            ),
        ) as Map<String, Any?>).toMutableMap()
        listOf("disconnected", "expired", "replaced", "settlement_pending", "settled")
            .forEach { status ->
                receipt["status"] = status
                val payload = JsonEncoder.encode(receipt).toByteArray(StandardCharsets.UTF_8)
                assertEquals(
                    status,
                    VpnJsonParser.parseReceipt(payload).status,
                )
            }

        receipt["status"] = "settlement_pending "
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(
                JsonEncoder.encode(receipt).toByteArray(StandardCharsets.UTF_8),
            )
        }
    }

    @Test
    fun vpnResponseParsersRejectNonCanonicalIdsHashesAndUnknownFields() {
        val quoteId = "ab".repeat(32)
        val leaseId = "bc".repeat(32)
        val sessionId = "de".repeat(16)
        val paymentTxHash = "cd".repeat(32)
        val meteringKey = validEd25519PublicKeyHex
        fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

        val quote = vpnQuoteJson(quoteId, meteringKey)
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseQuote(bytes(quote.replace("\"quote_id\": \"$quoteId\"", "\"quote_id\": \"0x$quoteId\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseQuote(bytes(quote.replace("aa".repeat(16), "AA".repeat(16))))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseQuote(bytes(quote.replaceFirst("{", "{\"unexpected\":true,")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseQuote(
                bytes(quote.replaceFirst("\"payload_hex\": \"cafe\"", "\"payload_hex\": \"cafe\", \"unexpected\": true")),
            )
        }

        val session = vpnSessionJson(sessionId, quoteId, paymentTxHash)
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(bytes(session.replace("\"session_id\": \"$sessionId\"", "\"session_id\": \"${sessionId.uppercase()}\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(bytes(session.replace("\"session_id\": \"$sessionId\"", "\"session_id\": \"${"de".repeat(32)}\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(bytes(session.replace("\"payment_tx_hash\": \"$paymentTxHash\"", "\"payment_tx_hash\": \"0x$paymentTxHash\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(bytes(session.replaceFirst("{", "{\"unexpected\":true,")))
        }

        val receipt = vpnReceiptJson(sessionId, quoteId, leaseId, paymentTxHash, settled = true)
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(bytes(receipt.replace("\"lease_id_hex\": \"$leaseId\"", "\"lease_id_hex\": \"${leaseId.uppercase()}\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(bytes(receipt.replace("\"session_id\": \"$sessionId\"", "\"session_id\": \"${"de".repeat(32)}\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(bytes(receipt.replace("\"payment_tx_hash\": \"$paymentTxHash\"", "\"payment_tx_hash\": \"0x$paymentTxHash\"")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(bytes(receipt.replaceFirst("{", "{\"unexpected\":true,")))
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceiptList(bytes("""{"items":[$receipt],"total":1,"unexpected":true}"""))
        }
    }

    @Test
    fun vpnResponseParsersRejectMissingRequiredFieldsAndSchemaBounds() {
        val quoteId = "ab".repeat(32)
        val leaseId = "bc".repeat(32)
        val sessionId = "de".repeat(16)
        val paymentTxHash = "cd".repeat(32)
        val meteringKey = validEd25519PublicKeyHex
        val profile = vpnProfileJson()
        val quote = vpnQuoteJson(quoteId, meteringKey)
        val session = vpnSessionJson(sessionId, quoteId, paymentTxHash)
        val receipt = vpnReceiptJson(sessionId, quoteId, leaseId, paymentTxHash, settled = true)
        val receiptList = """{"items":[$receipt],"total":1}"""

        @Suppress("UNCHECKED_CAST")
        fun jsonObject(json: String): MutableMap<String, Any?> =
            (JsonParser.parse(json) as Map<String, Any?>).toMutableMap()

        fun mutated(json: String, field: String, value: Any?): ByteArray {
            val root = jsonObject(json)
            root[field] = value
            return JsonEncoder.encode(root).toByteArray(StandardCharsets.UTF_8)
        }

        fun missing(json: String, field: String): ByteArray {
            val root = jsonObject(json)
            root.remove(field)
            return JsonEncoder.encode(root).toByteArray(StandardCharsets.UTF_8)
        }

        val missingCases = listOf(
            { VpnJsonParser.parseProfile(missing(profile, "relay_mldsa65_public_key_hex")) },
            { VpnJsonParser.parseProfile(missing(profile, "relay_tls_spki_sha256_hex")) },
            { VpnJsonParser.parseQuote(missing(quote, "relay_mldsa65_public_key_hex")) },
            { VpnJsonParser.parseQuote(missing(quote, "open_lease_instruction")) },
            { VpnJsonParser.parseSession(missing(session, "relay_mldsa65_public_key_hex")) },
            { VpnJsonParser.parseSession(missing(session, "route_pushes")) },
            { VpnJsonParser.parseReceipt(missing(receipt, "settle_lease_instruction")) },
            { VpnJsonParser.parseReceiptList(missing(receiptList, "items")) },
        )
        missingCases.forEach { decode -> assertFailsWith<IllegalStateException> { decode() } }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(mutated(session, "route_pushes", null))
        }

        val profileViolations = listOf(
            "supported_exit_classes" to listOf("standard", "low-latency"),
            "supported_exit_classes" to listOf("standard", "standard", "high-security"),
            "default_exit_class" to "unsupported",
            "lease_secs" to 0,
            "lease_secs" to 4_294_967_296L,
            "mtu_bytes" to 1_279,
            "settlement_grace_secs" to 0,
            "flow_label_bits" to 23,
            "padding_budget_ms" to 0,
        )
        profileViolations.forEach { (field, value) ->
            assertFailsWith<IllegalStateException> {
                VpnJsonParser.parseProfile(mutated(profile, field, value))
            }
        }

        val instruction = jsonObject(quote)["open_lease_instruction"]
        listOf(emptyList<Any>(), listOf(instruction, instruction)).forEach { instructions ->
            assertFailsWith<IllegalStateException> {
                VpnJsonParser.parseQuote(mutated(quote, "tx_instructions", instructions))
            }
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseSession(mutated(session, "status", "settled"))
        }
        listOf("status" to "active", "receipt_source" to "operator").forEach { (field, value) ->
            assertFailsWith<IllegalStateException> {
                VpnJsonParser.parseReceipt(mutated(receipt, field, value))
            }
        }
        val receiptInstruction = mapOf("wire_id" to "SettleVpnLease", "payload_hex" to "abcd")
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceipt(
                mutated(receipt, "tx_instructions", listOf(receiptInstruction, receiptInstruction)),
            )
        }

        val receiptObject = jsonObject(receipt)
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceiptList(
                mutated(receiptList, "items", List(25) { receiptObject }),
            )
        }
        assertFailsWith<IllegalStateException> {
            VpnJsonParser.parseReceiptList(mutated(receiptList, "total", 25))
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["https://torii.example", "http://localhost", "http://172.16.1.2"])
    fun vpnRoutesRejectWrongSuccessfulStatusCodes(baseUri: String) {
        val sessionId = "33".repeat(16)
        val quoteId = "34".repeat(32)
        val leaseId = "35".repeat(32)
        val paymentTxHash = "44".repeat(32)
        val meteringKey = validEd25519PublicKeyHex
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        fun auth() = ToriiCanonicalRequestAuth(
            "alice@universal",
            RequestSigner.ed25519(keyPair.private),
            1_700_000_000_050L,
            "vpn-status-nonce",
        )
        val config = ClientConfig.builder()
            .setBaseUri(URI.create(baseUri))
            .setAllowLocalDevelopmentHttp(baseUri.startsWith("http:"))
            .setLocalSigningContext(LocalSigningContext(TestNetworkIds.canonical()))
            .build()

        fun assertRejected(status: Int, body: String, call: (HttpClientTransport) -> Unit) {
            val transport = HttpClientTransport(
                executor = StubResponseExecutor(status, body.toByteArray(StandardCharsets.UTF_8)),
                config = config,
            )
            val error = assertFailsWith<java.util.concurrent.CompletionException> { call(transport) }
            assertTrue(error.cause?.message?.contains("status $status") == true)
        }

        assertRejected(201, vpnProfileJson()) { it.getVpnProfile().join() }
        assertRejected(200, vpnQuoteJson(quoteId, meteringKey)) {
            it.createVpnQuote(VpnQuoteCreateRequest("standard", "0x$meteringKey"), auth()).join()
        }
        assertRejected(200, vpnSessionJson(sessionId, quoteId, paymentTxHash)) {
            it.createVpnSession(VpnSessionCreateRequest("standard", quoteId, "0x$paymentTxHash", meteringKey), auth()).join()
        }
        assertRejected(201, vpnSessionJson(sessionId, quoteId, paymentTxHash)) {
            it.getVpnSession(sessionId, auth()).join()
        }
        assertRejected(200, vpnReceiptJson(sessionId, quoteId, leaseId, paymentTxHash, settled = true)) {
            it.submitVpnReceipt(VpnReceiptSubmitRequest("0xCAFE", "BEEF", "0x$leaseId"), auth()).join()
        }
        val receipt = vpnReceiptJson(sessionId, quoteId, leaseId, paymentTxHash, settled = true)
        assertRejected(201, """{"items":[$receipt],"total":1}""") {
            it.listVpnReceipts(auth()).join()
        }
    }

    private fun vpnProfileJson(): String =
        """
            {
              "available": true,
              "relay_endpoint": "/dns/relay.example/udp/9443/quic",
              "supported_exit_classes": ["standard", "low-latency", "high-security"],
              "default_exit_class": "standard",
              "lease_secs": 600,
              "dns_push_interval_secs": 60,
              "meter_family": "soranet.vpn.standard",
              "route_pushes": ["0.0.0.0/0"],
              "excluded_routes": ["10.0.0.0/8"],
              "dns_servers": ["1.1.1.1"],
              "tunnel_addresses": ["10.208.0.2/32"],
              "mtu_bytes": 1280,
              "display_billing_label": "standard XOR",
              "operator_account_id": "sorauOperator",
              "lease_fee": "1000000.25",
              "settlement_grace_secs": 120,
              "flow_label_bits": 24,
              "padding_budget_ms": 15,
              "relay_id_hex": "$validEd25519PublicKeyHex",
              "relay_mldsa65_public_key_hex": "$validMldsa65PublicKeyHex",
              "descriptor_commit_hex": "${"cd".repeat(32)}",
              "tls_server_name": "relay.example",
              "relay_tls_spki_sha256_hex": "${"ab".repeat(32)}",
              "relay_certificate_sha256_hex": "${"ef".repeat(32)}",
              "directory_snapshot_digest_hex": "${"42".repeat(32)}"
            }
        """.trimIndent()

    private fun vpnQuoteJson(quoteId: String, meteringKey: String): String =
        """
            {
              "quote_id": "$quoteId",
              "lease_id_hex": "$quoteId",
              "session_id_hex": "${"aa".repeat(16)}",
              "payment_reference": "$quoteId",
              "account_id": "alice",
              "exit_class": "low-latency",
              "relay_endpoint": "/dns/relay.example/udp/9443/quic",
              "lease_secs": 600,
              "quote_expires_at_ms": 1700000600000,
              "fee_asset_id": "xor#universal.universal",
              "escrow_account_id": "sorauEscrow",
              "operator_account_id": "sorauOperator",
              "lease_fee": "1000000.25",
              "route_pushes": ["0.0.0.0/0"],
              "excluded_routes": [],
              "dns_servers": ["1.1.1.1"],
              "tunnel_addresses": ["10.208.0.2/32"],
              "mtu_bytes": 1280,
              "meter_family": "soranet.vpn.standard",
              "flow_label_bits": 24,
              "padding_budget_ms": 15,
              "relay_id_hex": "$validEd25519PublicKeyHex",
              "relay_mldsa65_public_key_hex": "$validMldsa65PublicKeyHex",
              "descriptor_commit_hex": "${"cd".repeat(32)}",
              "tls_server_name": "relay.example",
              "relay_tls_spki_sha256_hex": "${"ab".repeat(32)}",
              "relay_certificate_sha256_hex": "${"ef".repeat(32)}",
              "directory_snapshot_digest_hex": "${"42".repeat(32)}",
              "metering_public_key_hex": "$meteringKey",
              "open_lease_instruction": {
"wire_id": "iroha.instruction.v1::vpn::OpenVpnLeaseEscrow",
                "payload_hex": "cafe"
              }
            }
        """.trimIndent()

    private fun vpnHelperTicketHex(): String = "5356504e48543100" + "00".repeat(780)

    private fun vpnSessionJson(sessionId: String, quoteId: String, paymentTxHash: String): String =
        """
            {
              "session_id": "$sessionId",
              "account_id": "alice",
              "exit_class": "standard",
              "relay_endpoint": "/dns/relay.example/udp/9443/quic",
              "lease_secs": 600,
              "expires_at_ms": 1700000600000,
              "connected_at_ms": 1700000000000,
              "meter_family": "soranet.vpn.standard",
              "quote_id": "$quoteId",
              "payment_reference": "$quoteId",
              "payment_tx_hash": "$paymentTxHash",
              "fee_asset_id": "xor#universal.universal",
              "escrow_account_id": "sorauEscrow",
              "operator_account_id": "sorauOperator",
              "lease_fee": "1000000.25",
              "flow_label_bits": 24,
              "padding_budget_ms": 15,
              "relay_id_hex": "$validEd25519PublicKeyHex",
              "relay_mldsa65_public_key_hex": "$validMldsa65PublicKeyHex",
              "descriptor_commit_hex": "${"cd".repeat(32)}",
              "tls_server_name": "relay.example",
              "relay_tls_spki_sha256_hex": "${"ab".repeat(32)}",
              "relay_certificate_sha256_hex": "${"ef".repeat(32)}",
              "directory_snapshot_digest_hex": "${"42".repeat(32)}",
              "route_pushes": ["0.0.0.0/0"],
              "excluded_routes": [],
              "dns_servers": ["1.1.1.1"],
              "tunnel_addresses": ["10.208.0.2/32"],
              "mtu_bytes": 1280,
              "helper_ticket_hex": "${vpnHelperTicketHex()}",
              "bytes_in": 0,
              "bytes_out": 0,
              "status": "active"
            }
        """.trimIndent()

    private fun vpnReceiptJson(
        sessionId: String,
        quoteId: String,
        leaseId: String,
        paymentTxHash: String,
        settled: Boolean,
    ): String {
        val status = if (settled) "settled" else "disconnected"
        val source = if (settled) "relay" else "torii"
        val earned = if (settled) "750000.125" else "0"
        val refunded = if (settled) "250000.125" else "1000000.25"
        val settle = if (settled) {
            """,
              "settle_lease_instruction": {
                "wire_id": "iroha.instruction.v1::vpn::SettleVpnLease",
                "payload_hex": "f00d"
              }"""
        } else {
            """,
              "settle_lease_instruction": null"""
        }
        return """
            {
              "session_id": "$sessionId",
              "account_id": "alice",
              "exit_class": "standard",
              "relay_endpoint": "/dns/relay.example/udp/9443/quic",
              "meter_family": "soranet.vpn.standard",
              "connected_at_ms": 1700000000000,
              "disconnected_at_ms": 1700000010000,
              "duration_ms": 10000,
              "bytes_in": 1024,
              "bytes_out": 2048,
              "status": "$status",
              "receipt_source": "$source",
              "quote_id": "$quoteId",
              "payment_tx_hash": "$paymentTxHash",
              "fee_asset_id": "xor#universal.universal",
              "escrow_account_id": "sorauEscrow",
              "operator_account_id": "sorauOperator",
              "lease_fee": "1000000.25",
              "earned_fee": "$earned",
              "refunded_fee": "$refunded",
              "lease_id_hex": "$leaseId"$settle
            }
        """.trimIndent()
    }

    private class StubResponseExecutor(
        private val statusCode: Int,
        private val body: ByteArray,
    ) : HttpTransportExecutor {
        lateinit var lastRequest: TransportRequest

        override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
            lastRequest = request
            if (request.uri.path.endsWith("/v1/node/capabilities")) {
                return CompletableFuture.completedFuture(compatibleCapabilitiesResponse())
            }
            return CompletableFuture.completedFuture(
                TransportResponse.builder().setStatusCode(statusCode).setBody(body).build(),
            )
        }
    }

    private companion object {
        fun compatibleCapabilitiesResponse(): TransportResponse =
            TransportResponse.builder()
                .setStatusCode(200)
                .setBody(
                    (
                        "{\"data_model_version\":4,\"signed_transaction_schema_hash_hex\":" +
                            "\"7ab5ff9c572efb316deac478f19209c5\"}"
                        ).toByteArray(StandardCharsets.UTF_8),
                )
                .build()
    }
}
