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
