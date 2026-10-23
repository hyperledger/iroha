package org.hyperledger.iroha.sdk.tx

import java.math.BigInteger
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.NetworkId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs

class DetachedTransactionInspectionTest {
    private val network = NetworkId.fromBytes(ByteArray(32) { 0x11 })
    private val leg = """{"leg_id":"first","source_account_id":"owner","destination_account_id":"israel","asset_definition_id":"ds","amount":"20"}"""
    private val secondLeg = leg.replace("first", "second").replace("israel", "roman").replace("\"20\"", "\"60\"")
    private val batch = """{"kind":"asset_transfer_batch","mode":"independent","entries":[$leg,$secondLeg]}"""
    private val product = """{"kind":"oracle","id":"product","attestor":"product-asp","sequence":1,"predicate":{"kind":"equals","value":{"kind":"text","value":"i7"}}}"""
    private val delivery = """{"kind":"oracle","id":"delivery","attestor":"delivery-asp","sequence":2,"predicate":{"kind":"quantity_at_most","value":"3"}}"""
    private val window = """{"kind":"within","id":"confirmation","duration_ms":604800000}"""
    private val escrow = """{"kind":"conditional_escrow_open","escrow_id":"lock","asset_definition_id":"ds","beneficiary":"intel","amount":"20","conditions":[$product,$delivery,$window],"expires_at_ms":1700604800000,"evidence_hashes":["document-digest"]}"""

    private fun review(executable: String): String = """
        {"schema":"iroha.detached_transaction_scaffold.v1","payload_signing_hash_hex":"${"11".repeat(32)}",
        "payload_hash_hex":"${"22".repeat(32)}","authority":"owner","network_id":"${network.literal}",
        "creation_time_ms":18446744073709551615,"time_to_live_ms":60000,
        "fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
        "metadata":{"nested":{"exact":18446744073709551615}},"entrypoint_hash_hex":"${"33".repeat(32)}",
        "executable":$executable}
    """.trimIndent()

    private fun parse(text: String): DetachedTransactionInspection =
        DetachedTransactionInspection.fromNativeJSON(text.toByteArray(Charsets.UTF_8))

    @Test fun nativeBatchRetainsOrderedLegsModeFeesAndUnsignedHash() {
        val result = parse(review(batch))
        assertEquals("11".repeat(32), result.payloadSigningHashHex)
        assertEquals("22".repeat(32), result.payloadHashHex)
        assertEquals(BigInteger("18446744073709551615"), result.creationTimeMs)
        assertIs<FeePaymentIntent.Authority>(result.feePayment)
        val instruction = assertIs<DetachedExecutableInspection.AssetTransferBatch>(result.executable)
        assertEquals(DetachedTransferBatchMode.INDEPENDENT, instruction.mode)
        assertEquals(listOf("first", "second"), instruction.entries.map { it.legId })
        assertEquals(listOf("israel", "roman"), instruction.entries.map { it.destinationAccountId })
        assertEquals(listOf("20", "60"), instruction.entries.map { it.amount })
        val atomic = assertIs<DetachedExecutableInspection.AssetTransferBatch>(
            parse(review(batch.replace("independent", "atomic"))).executable,
        )
        assertEquals(DetachedTransferBatchMode.ATOMIC, atomic.mode)
    }

    @Test fun escrowRetainsIndependentAttestorsPredicatesAndDistinctWindows() {
        val instruction = assertIs<DetachedExecutableInspection.ConditionalEscrowOpen>(parse(review(escrow)).executable)
        val first = assertIs<DetachedEscrowCondition.Oracle>(instruction.conditions[0])
        val second = assertIs<DetachedEscrowCondition.Oracle>(instruction.conditions[1])
        assertEquals("product-asp", first.attestor)
        assertEquals("delivery-asp", second.attestor)
        assertEquals(1L, first.sequence)
        assertEquals(2L, second.sequence)
        assertEquals("i7", assertIs<DetachedEscrowValue.TextValue>(assertIs<DetachedEscrowPredicate.Equals>(first.predicate).value).value)
        assertEquals("3", assertIs<DetachedEscrowPredicate.QuantityAtMost>(second.predicate).value)
        assertEquals(BigInteger("604800000"), assertIs<DetachedEscrowCondition.Within>(instruction.conditions[2]).durationMs)
        assertEquals(BigInteger("1700604800000"), instruction.expiresAtMs)
        assertEquals(listOf("document-digest"), instruction.evidenceHashes)
    }

    @Test fun instructionSequencesAreBoundedAndCannotMasqueradeAsIndependentBatches() {
        val transfer = """{"kind":"asset_transfer","asset_definition_id":"ds","asset_scope":{"kind":"global"},"source_asset_id":"owned-ds","source_account_id":"owner","destination_account_id":"payee","amount":"20"}"""
        val sequence = """{"kind":"transfer_instruction_sequence","transfers":[$transfer,$transfer]}"""
        assertEquals(2, assertIs<DetachedExecutableInspection.TransferInstructionSequence>(parse(review(sequence)).executable).transfers.size)
        for (count in listOf(0, 1, 17)) {
            val invalid = """{"kind":"transfer_instruction_sequence","transfers":[${List(count) { transfer }.joinToString(",")}]}"""
            assertFails { parse(review(invalid)) }
        }
        assertFails { parse(review(sequence.replace("transfer_instruction_sequence", "asset_transfer_batch"))) }
    }

    private val fiLink = """{"kind":"asset_fi_link_set","asset_definition_id":"ds","account_id":"owner","fi_account_id":"fi","reference_digest":"42d0bab39490854dd81ea51610e83141952bd0c4c06224a5f1cc41745459f7b8","fi_revision":18446744073709551615,"attestation_revision":18446744073709551614,"revision":18446744073709551613,"enabled":true,"controller":"irohac1controller","waterfall":true,"reverse_waterfall":false,"expected_policy_revision":18446744073709551612}"""

    private val fiTransfer = """{"kind":"asset_fi_link_transfer","asset_definition_id":"ds","account_id":"owner","amount":"184467440737095516.15","expected_link_revision":18446744073709551615,"expected_policy_revision":18446744073709551614}"""

    @Test fun linkedFiTransferRetainsExactFieldsWithoutDestinationEvidence() {
        val value = assertIs<DetachedExecutableInspection.AssetFiLinkTransfer>(parse(review(fiTransfer)).executable)
        assertEquals("ds", value.assetDefinitionId)
        assertEquals("owner", value.accountId)
        assertEquals("184467440737095516.15", value.amount)
        assertEquals(BigInteger("18446744073709551615"), value.expectedLinkRevision)
        assertEquals(BigInteger("18446744073709551614"), value.expectedPolicyRevision)
        val zero = fiTransfer.replace("18446744073709551615", "0")
        assertEquals(BigInteger.ZERO, assertIs<DetachedExecutableInspection.AssetFiLinkTransfer>(parse(review(zero)).executable).expectedLinkRevision)
    }

    @Test fun linkedFiTransferRejectsMissingDuplicateWrongAndUnsignedDisplayFields() {
        val fields = listOf(
            "asset_definition_id" to "\"ds\"", "account_id" to "\"owner\"",
            "amount" to "\"184467440737095516.15\"",
            "expected_link_revision" to "18446744073709551615",
            "expected_policy_revision" to "18446744073709551614",
        )
        for ((key, value) in fields) {
            val field = "\"$key\":$value"
            for (replacement in listOf("\"unknown_$key\":$value", "$field,$field", "\"$key\":[]")) {
                assertFails(key) { parse(review(fiTransfer.replace(field, replacement))) }
            }
            if (key.endsWith("revision")) {
                for (wrong in listOf("-1", "-0", "1.0", "1e0", "\"1\"", "true", "null", "18446744073709551616")) {
                    assertFails(key + wrong) { parse(review(fiTransfer.replace(field, "\"$key\":$wrong"))) }
                }
            }
        }
        for (extra in listOf("fi_account_id", "destination_account_id", "reference_digest", "fi_revision", "attestation_revision", "purpose", "waterfall")) {
            assertFails(extra) { parse(review(fiTransfer.replace("\"kind\":", "\"$extra\":\"untrusted\",\"kind\":"))) }
        }
        for (hostile in listOf(
            fiTransfer.replace("asset_fi_link_transfer", "asset_transfer"),
            fiTransfer.replace("\"amount\":\"184467440737095516.15\"", "\"amount\":184467440737095516.15"),
            fiTransfer.replace("\"account_id\":\"owner\"", "\"account_id\":\"\""),
            fiTransfer.replace("\"asset_definition_id\":\"ds\"", "\"asset_definition_id\":\"\""),
            fiTransfer.replace("\"amount\":\"184467440737095516.15\"", "\"amount\":\"\""),
            """{"kind":"transfer_instruction_sequence","transfers":[$fiTransfer,$fiTransfer]}""",
            """{"kind":"atomic_transfer_sequence","transfers":[$fiTransfer,$fiTransfer]}""",
        )) { assertFails { parse(review(hostile)) } }
    }

    @Test fun fiLinkRetainsAllFieldsRawReferenceAndFullUnsignedRevisions() {
        val maximum = BigInteger("18446744073709551615")
        for (enabled in listOf(false, true)) {
            for (controller in listOf("null", "\"irohac1controller\"")) {
                val json = fiLink.replace("\"enabled\":true", "\"enabled\":$enabled")
                    .replace("\"controller\":\"irohac1controller\"", "\"controller\":$controller")
                val link = assertIs<DetachedExecutableInspection.AssetFiLinkSet>(parse(review(json)).executable)
                assertEquals("ds", link.assetDefinitionId)
                assertEquals("owner", link.accountId)
                assertEquals("fi", link.fiAccountId)
                assertEquals("42d0bab39490854dd81ea51610e83141952bd0c4c06224a5f1cc41745459f7b8", link.referenceDigestHex)
                assertEquals(maximum, link.fiRevision)
                assertEquals(maximum - BigInteger.ONE, link.attestationRevision)
                assertEquals(maximum - BigInteger.valueOf(2), link.revision)
                assertEquals(maximum - BigInteger.valueOf(3), link.expectedPolicyRevision)
                assertEquals(enabled, link.enabled)
                assertEquals(if (controller == "null") null else "irohac1controller", link.controller)
                assertEquals(true, link.waterfall)
                assertEquals(false, link.reverseWaterfall)
            }
        }
        val flipped = fiLink.replace("\"waterfall\":true", "\"waterfall\":false")
            .replace("\"reverse_waterfall\":false", "\"reverse_waterfall\":true")
        val link = assertIs<DetachedExecutableInspection.AssetFiLinkSet>(parse(review(flipped)).executable)
        assertEquals(false, link.waterfall)
        assertEquals(true, link.reverseWaterfall)
    }

    @Test fun fiLinkRejectsHiddenMissingDuplicateAndWrongScalarFields() {
        val fields = mapOf(
            "asset_definition_id" to "\"ds\"", "account_id" to "\"owner\"", "fi_account_id" to "\"fi\"",
            "reference_digest" to "\"42d0bab39490854dd81ea51610e83141952bd0c4c06224a5f1cc41745459f7b8\"",
            "fi_revision" to "18446744073709551615", "attestation_revision" to "18446744073709551614",
            "revision" to "18446744073709551613", "enabled" to "true", "controller" to "\"irohac1controller\"",
            "waterfall" to "true", "reverse_waterfall" to "false", "expected_policy_revision" to "18446744073709551612",
        )
        for ((key, value) in fields) {
            val field = "\"$key\":$value"
            for (hostile in listOf(
                fiLink.replace(field, "\"unknown_$key\":$value"),
                fiLink.replace(field, "$field,$field"),
                fiLink.replace(field, "\"$key\":[]"),
            )) assertFails(key) { parse(review(hostile)) }
        }
        for ((key, value) in fields.filterKeys { it.endsWith("revision") }) {
            for (wrong in listOf("-1", "1.0", "1e0", "\"1\"", "true", "null", "18446744073709551616")) {
                assertFails("$key=$wrong") { parse(review(fiLink.replace("\"$key\":$value", "\"$key\":$wrong"))) }
            }
        }
        for (hostile in listOf(
            fiLink.replace("\"kind\":", "\"hidden_transfer\":true,\"kind\":"),
            fiLink.replace("asset_fi_link_set", "asset_fi_link_attestation_set"),
            fiLink.replace("42d0bab39490854dd81ea51610e83141952bd0c4c06224a5f1cc41745459f7b8", "AB"),
            fiLink.replace("\"controller\":\"irohac1controller\"", "\"controller\":\"\""),
            fiLink.replace("\"enabled\":true", "\"enabled\":1"),
            """{"kind":"transfer_instruction_sequence","transfers":[$fiLink,$fiLink]}""",
        )) assertFails { parse(review(hostile)) }
    }

    @Test fun unknownInstructionsMissingBindingsAndNestedSubstitutionsAreUnreviewable() {
        for (text in listOf(
            review(batch.replace("independent", "best_effort")),
            review(batch.replace("\"second\"", "\"first\"")),
            review(batch.replace("\"amount\":\"60\"", "\"amount\":\"60\",\"hidden_transfer\":true")),
            review(batch.replace("\"asset_transfer_batch\"", "\"other\"")),
            review(escrow.replace("\"sequence\":2", "\"sequence\":0")),
            review(escrow.replace("\"quantity_at_most\"", "\"approve_any\"")),
            review(escrow.replace("\"duration_ms\":604800000", "\"duration_ms\":604800000,\"cancel_anytime\":true")),
            review(batch).replace("\"payload_hash_hex\":", "\"retired_payload_hash\":"),
            review(batch).replace("\"gas_limit\":null", "\"gas_limit\":null,\"fallback_payer\":true"),
            review(batch).replace("\"time_to_live_ms\":60000", "\"time_to_live_ms\":null"),
            review(batch).replace("\"authority\":\"owner\"", "\"authority\":\"other\",\"authority\":\"owner\""),
        )) assertFails(text) { parse(text) }
    }
}
