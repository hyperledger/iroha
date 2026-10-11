package org.hyperledger.iroha.sdk.client

import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Structural and request-signing DATA controls; these fixtures grant no ledger authority. */
class CurrentIdentifierOwnerContractTest {
    private val network = NetworkId.parse("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
    private val foreign = NetworkId.parse("hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22")
    private val beneficiary = AccountAddress.fromAccount(TestEd25519Keys.publicKey(0x41), "ed25519").toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT)
    private val hash = "11".repeat(32)
    private val uaid = "uaid:$hash"
    private fun opening() = RamLfeOutputOpening(RamLfeOutputOpeningPayload("phone_retail", hash, hash, hash, hash, hash, 42, 142), "aa".repeat(64))
    private fun phone() = PhoneRetailCanonicalityPayloadV1(network, "phone#retail", "phone_retail", hash, hash, hash, hash, uaid, beneficiary, 42, 142)
    private fun prepare(selected: NetworkId = network): ByteArray = JsonEncoder.encode(linkedMapOf(
        "network_id" to IdentifierOwnerInputV1.rawNetworkHex(selected), "policy_id" to "phone#retail", "account_id" to beneficiary,
        "uaid" to uaid, "output_opening" to opening().toJsonMap(), "phone_retail_canonicality_payload" to phone().toJsonMap(),
    )).toByteArray(StandardCharsets.UTF_8)

    @Test
    fun currentNormalizationMatchesAsciiModelAndRefusesWireAliases() {
        assertEquals("Äab", IdentifierNormalization.LOWERCASE_TRIMMED.normalize(" ÄAB "))
        assertEquals("Ä@example.org", IdentifierNormalization.EMAIL_ADDRESS.normalize(" Ä@EXAMPLE.ORG "))
        assertEquals("+819012345678", IdentifierNormalization.PHONE_E164.normalize("00 81 (90) 1234-5678"))
        for (input in listOf("+0", "+01", "+1", "+1234567890123456", "+１２")) {
            assertFailsWith<IllegalArgumentException> { IdentifierNormalization.PHONE_E164.normalize(input) }
        }
        for (wire in listOf(" exact", "EXACT", "phone_e164 ")) {
            assertFailsWith<IllegalArgumentException> { IdentifierNormalization.fromWireValue(wire) }
        }
        assertFailsWith<IllegalArgumentException> { IdentifierNormalization.ACCOUNT_NUMBER.normalize("Ä1") }
    }

    @Test
    fun ownerRequestsContainOnlyCurrentExactFields() {
        val request = IdentifierResolveRequest.prepare("phone#retail", "+819012345678", "12".repeat(32))
        assertEquals(setOf("phase", "policy_id", "normalized_input", "input_nonce"), request.toJsonMap().keys)
        assertEquals("prepare", request.phase)
        assertNull(request.outputOpening)
        assertNull(request.phoneRetailCanonicality)
        assertFalse(request.toJsonMap().containsKey("encrypted_input"))
        val statement = PhoneRetailCanonicalityAttestationV1(phone(), "bb".repeat(64))
        val claim = IdentifierResolveRequest.claim("phone#retail", "+819012345678", "12".repeat(32), opening(), statement)
        assertEquals(statement.toJsonMap(), claim.toJsonMap()["phone_retail_canonicality"])
        assertEquals(opening().toJsonMap(), claim.toJsonMap()["output_opening"])
    }

    @Test
    fun typedOriginalsUseExactModelGrammarAndPreserveOriginalSignatureBytes() {
        val original = opening().toJsonMap()
        val payload = original["payload"] as Map<*, *>
        assertEquals(mapOf("name" to "phone_retail"), payload["program_id"])
        assertEquals(IdentifierOwnerInputV1.modelHashLiteral(hash), payload["input_ciphertext_hash"])
        assertEquals("AA".repeat(64), original["signature"])
        val projected = phone().toJsonMap()
        assertEquals(network.literal, projected["network_id"])
        assertEquals(mapOf("kind" to "phone", "business_rule" to "retail"), projected["policy_id"])
        assertEquals(listOf(IdentifierOwnerInputV1.modelHashLiteral(hash)), projected["uaid"])
        val parsed = IdentifierJsonParser.parsePrepareResponse(prepare())
        assertEquals(network, parsed.networkId)
        assertEquals(original, parsed.outputOpening.toJsonMap())
        assertEquals(projected, assertNotNull(parsed.phoneRetailCanonicalityPayload).toJsonMap())
    }

    @Test
    fun prepareRejectsNetworkAliasesAndAlternateOriginalLayouts() {
        val source = String(prepare(), StandardCharsets.UTF_8)
        val rawNetwork = IdentifierOwnerInputV1.rawNetworkHex(network)
        for (replacement in listOf(network.literal, rawNetwork.uppercase(), " $rawNetwork", rawNetwork.dropLast(2))) {
            assertFailsWith<RuntimeException> { IdentifierJsonParser.parsePrepareResponse(source.replace(rawNetwork, replacement).toByteArray(StandardCharsets.UTF_8)) }
        }
        val alternateProgram = source.replace("\"program_id\":{\"name\":\"phone_retail\"}", "\"program_id\":\"phone_retail\"")
        assertNotEquals(source, alternateProgram)
        assertFailsWith<RuntimeException> { IdentifierJsonParser.parsePrepareResponse(alternateProgram.toByteArray(StandardCharsets.UTF_8)) }
        val alternateUaid = source.replace("\"uaid\":[\"${IdentifierOwnerInputV1.modelHashLiteral(hash)}\"]", "\"uaid\":\"$uaid\"")
        assertNotEquals(source, alternateUaid)
        assertFailsWith<RuntimeException> { IdentifierJsonParser.parsePrepareResponse(alternateUaid.toByteArray(StandardCharsets.UTF_8)) }
        val alternateClock = source.replace("\"expires_at_ms\":142", "\"expires_at_ms\":\"142\"")
        assertNotEquals(source, alternateClock)
        assertFailsWith<RuntimeException> { IdentifierJsonParser.parsePrepareResponse(alternateClock.toByteArray(StandardCharsets.UTF_8)) }
    }

    @Test
    fun receiptPayloadStartsWithItsRequiredRawNetworkField() {
        val execution = IdentifierResolutionExecutionPayload("phone_retail", hash, IdentifierOwnerInputV1.BACKEND, "signed", hash, hash, hash, hash, hash, hash, 42, 142)
        val payload = IdentifierResolutionPayload(network, "phone#retail", execution, opening(), "opaque:$hash", hash, uaid, beneficiary)
        val encoded = IdentifierReceiptCanonicalEncoder.encodePayload(payload)
        val decoder = NoritoDecoder(encoded, NoritoCodec.DEFAULT_FLAGS)
        val length = decoder.readLength((decoder.flags and NoritoHeader.COMPACT_LEN) != 0)
        assertEquals(32L, length)
        assertContentEquals(network.bytes(), decoder.readBytes(32))
        val changed = IdentifierResolutionPayload(foreign, payload.policyId, execution, payload.opening, payload.opaqueId, payload.receiptHash, payload.uaid, payload.accountId)
        assertFalse(encoded.contentEquals(IdentifierReceiptCanonicalEncoder.encodePayload(changed)))
    }

    @Test
    fun originalLeaseCannotBeRenewedOrUnbounded() {
        for ((opened, expires) in listOf(0L to 100L, 42L to 42L, 42L to 41L, 42L to 120_043L)) {
            assertFailsWith<IllegalArgumentException> { IdentifierOwnerInputV1.originalLease(opened, expires) }
        }
        assertFailsWith<IllegalArgumentException> { IdentifierOwnerInputV1.originalLease(42, null) }
        IdentifierOwnerInputV1.originalLease(42, 120_042)
    }

    @Test
    fun phoneStatementCannotReplaceAnyOriginalOpeningField() {
        val signed = PhoneRetailCanonicalityAttestationV1(phone(), "aa".repeat(64))
        val original = opening().payload
        val substituted = RamLfeOutputOpening(RamLfeOutputOpeningPayload(original.programId, original.inputCiphertextHash, original.outputCiphertextHash, original.parameterDigest, original.evaluationKeyDigest, original.openedOutputHash, original.openedAtMs, 143), "aa".repeat(64))
        assertFailsWith<IllegalArgumentException> { signed.requireOriginalOpening(substituted) }
    }

    @Test
    fun executeRejectsRetiredOutputAndEveryWrongOpaqueWidth() {
        val source = ramLfeExecuteResponseJson()
        val value = currentOwnerExecuteResponseField("opaque_output")
        for (replacement in listOf("abcd", value + "AB", "hash:$value", value.lowercase())) {
            assertFailsWith<RuntimeException> { RamLfeJsonParser.parseExecuteResponse(source.replace("\"opaque_output\": \"$value\"", "\"opaque_output\": \"$replacement\"").toByteArray(StandardCharsets.UTF_8)) }
        }
        assertFailsWith<RuntimeException> { RamLfeJsonParser.parseExecuteResponse(source.replace("opaque_output", "output_ciphertext").toByteArray(StandardCharsets.UTF_8)) }
    }

    @Test
    fun receiptJsonSnapshotCopiesNestedCollectionsAndRejectsMutableNonJsonValues() {
        val parsed = RamLfeJsonParser.parseExecuteResponse(ramLfeExecuteResponseJson().toByteArray(StandardCharsets.UTF_8))
        val original = parsed.receipt.toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val nested = (original["payload"] as Map<String, Any>).toMutableMap()
        original["payload"] = nested
        fun copied(receipt: Map<String, Any>) = RamLfeExecuteResponse(parsed.programId, parsed.programIdCanonicalHex, parsed.opaqueHash, parsed.receiptHash, parsed.opaqueOutputHex, parsed.outputHash, parsed.associatedDataHash, parsed.executedAtMs, parsed.expiresAtMs, parsed.backend, parsed.verificationMode, receipt)
        val response = copied(original)
        val before = nested["input_ciphertext_hash"]
        nested["input_ciphertext_hash"] = hash
        assertEquals(before, (response.receipt["payload"] as Map<*, *>)["input_ciphertext_hash"])
        val frame = response.programIdCanonicalBytes()
        frame[0] = (frame[0].toInt() xor 1).toByte()
        assertFalse(frame.contentEquals(response.programIdCanonicalBytes()))
        assertFailsWith<IllegalArgumentException> { copied(mapOf("mutable" to byteArrayOf(1))) }
    }

    @Test
    fun prepareBindsSelectedNetworkAndIndependentBeneficiary() {
        val requests = mutableListOf<TransportRequest>()
        fun transport(response: ByteArray, selected: NetworkId): HttpClientTransport {
            val executor = object : HttpTransportExecutor {
                override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> {
                    requests.add(request)
                    return CompletableFuture.completedFuture(TransportResponse.builder().setStatusCode(200).setBody(response).build())
                }
            }
            val config = ClientConfig.builder().setBaseUri(URI.create("https://torii.example/api")).setLocalSigningContext(LocalSigningContext(selected)).build()
            return HttpClientTransport(executor, config)
        }
        val body = IdentifierResolveRequest.prepare("phone#retail", "+819012345678", "12".repeat(32))
        val accepted = transport(prepare(), network).prepareIdentifierClaim(beneficiary, body, applicationAuth()).join()
        assertEquals(beneficiary, assertNotNull(accepted).accountId)
        assertEquals("/api/v1/accounts/$beneficiary/identifiers/claim-receipt", requests.last().uri.path)
        assertNotEquals(applicationAuth().accountId, beneficiary)
        assertFailsWith<RuntimeException> { transport(prepare(), foreign).prepareIdentifierClaim(beneficiary, body, applicationAuth()).join() }
    }

    @Test
    fun actualOwnerSignatureBindsRawNetworkMethodUriAndCompleteBody() {
        val supplied = URI.create("https://torii.example/api/v1/accounts/$beneficiary/identifiers/claim-receipt")
        // I105 contains Unicode checksum characters; the owner signs the ASCII percent-encoded wire URI.
        val uri = URI.create(supplied.toASCIIString())
        assertNotEquals(supplied.rawPath, uri.rawPath)
        assertTrue(uri.rawPath.all { it.code in 0x21..0x7e })
        assertTrue(uri.rawPath.contains('%'))
        val body = JsonEncoder.encode(IdentifierResolveRequest.prepare("phone#retail", "+819012345678", "12".repeat(32)).toJsonMap()).toByteArray(StandardCharsets.UTF_8)
        fun signature(selected: NetworkId, method: String, target: URI, bytes: ByteArray) = applicationAuth().headers(selected, method, target, bytes).getValue(CanonicalRequestSigner.HEADER_SIGNATURE)
        assertFailsWith<IllegalArgumentException> { signature(network, "POST", supplied, body) }
        val exact = signature(network, "POST", uri, body)
        assertNotEquals(exact, signature(foreign, "POST", uri, body))
        assertNotEquals(exact, signature(network, "GET", uri, body))
        assertNotEquals(exact, signature(network, "POST", URI.create(uri.toString() + "?other=1"), body))
        assertNotEquals(exact, signature(network, "POST", uri, body + byteArrayOf(32)))
        assertEquals(exact, signature(network, "POST", uri, body))
    }

    private fun executePolicy(key: String, active: Boolean = true) = RamLfeProgramPolicySummary(
        "identifier_lookup_retail", beneficiary, active, key, IdentifierOwnerInputV1.BACKEND, "signed",
        null, null, null, null, key,
    )
    @Suppress("UNCHECKED_CAST")
    private fun executeResponseMap() = (currentOwnerExecuteFixture()["response"] as Map<String, Any?>).toMutableMap()
    private fun decodeExecute(value: Map<String, Any?>) = RamLfeJsonParser.parseExecuteResponse(JsonEncoder.encode(value).toByteArray(StandardCharsets.UTF_8))
    private fun dataBytes(value: String) = ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }

    @Test
    fun genuineExecuteFixtureMatchesNativeFullPayloadPrehashAndIndependentResolver() {
        val fixture = currentOwnerExecuteFixture()
        val response = decodeExecute(executeResponseMap())
        val encoded = IdentifierReceiptCanonicalEncoder.encodeExecution(response.execution)
        assertContentEquals(dataBytes(fixture["canonical_execution_payload_hex"] as String), encoded)
        assertContentEquals(dataBytes(fixture["execution_prehash_hex"] as String), org.hyperledger.iroha.sdk.crypto.IrohaHash.prehash(encoded))
        val policy = executePolicy(fixture["resolver_public_key"] as String)
        assertTrue(response.verifyResolverSignature(policy))
        assertFailsWith<IllegalArgumentException> { response.verifyResolverSignature(executePolicy(policy.resolverPublicKey, false)) }
    }

    @Test
    fun executeRejectsAlteredNativeFrameOpaqueAndEveryDomainCommitment() {
        val original = executeResponseMap()
        for (field in listOf("output_hash", "opaque_hash", "receipt_hash", "associated_data_hash", "opaque_output")) {
            val changed = original.toMutableMap()
            changed[field] = if (field == "opaque_output") "AB".repeat(32) else hash
            assertNotEquals(original[field], changed[field])
            assertFailsWith<IllegalArgumentException>(field) { decodeExecute(changed) }
        }
        val frame = original["program_id_canonical"] as String
        for (bad in listOf("", frame.lowercase(), "0X" + frame, "AB", "AB".repeat(4097))) {
            val changed = original.toMutableMap(); changed["program_id_canonical"] = bad
            assertFailsWith<RuntimeException> { decodeExecute(changed) }
        }
    }

    @Test
    fun executeRejectsReceiptOutputDisagreementAndRetiredAttestationMetadata() {
        for (mutation in listOf("output_ciphertext_hash", "algorithm")) {
            val changed = executeResponseMap()
            @Suppress("UNCHECKED_CAST")
            val receipt = (changed["receipt"] as Map<String, Any?>).toMutableMap()
            val field = if (mutation == "algorithm") "attestation" else "payload"
            @Suppress("UNCHECKED_CAST")
            val nested = (receipt[field] as Map<String, Any?>).toMutableMap()
            nested[mutation] = if (mutation == "algorithm") "ed25519" else hash
            receipt[field] = nested; changed["receipt"] = receipt
            assertFailsWith<RuntimeException> { decodeExecute(changed) }
        }
    }

    @Test
    fun completeExecutionSignatureRejectsChangedPrivateInputCommitment() {
        val fixture = currentOwnerExecuteFixture()
        val changed = executeResponseMap()
        @Suppress("UNCHECKED_CAST")
        val receipt = (changed["receipt"] as Map<String, Any?>).toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val payload = (receipt["payload"] as Map<String, Any?>).toMutableMap()
        payload["input_ciphertext_hash"] = hash; receipt["payload"] = payload; changed["receipt"] = receipt
        assertFalse(decodeExecute(changed).verifyResolverSignature(executePolicy(fixture["resolver_public_key"] as String)))
    }
}
