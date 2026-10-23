package org.hyperledger.iroha.sdk.tx

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import org.hyperledger.iroha.sdk.client.FeePaymentJson
import org.hyperledger.iroha.sdk.client.JsonEncoder
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Exact native scaffold review. The signing digest and canonical unsigned wire hash are distinct. */
class DetachedTransactionInspection private constructor(
    val payloadSigningHashHex: String,
    val payloadHashHex: String,
    val authority: String,
    val networkId: NetworkId,
    val creationTimeMs: BigInteger,
    val timeToLiveMs: BigInteger,
    val feePayment: FeePaymentIntent,
    val metadataJson: String,
    val entrypointHashHex: String,
    val executable: DetachedExecutableInspection,
) {
    companion object {
        internal const val MAX_BYTES: Int = 16 * 1024 * 1024

        internal fun fromNativeJSON(bytes: ByteArray): DetachedTransactionInspection {
            require(bytes.isNotEmpty() && bytes.size <= MAX_BYTES) { "Invalid native inspection size" }
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
            val root = obj(JsonParser.parse(text))
            root.exact(
                "schema", "payload_signing_hash_hex", "payload_hash_hex", "authority", "network_id",
                "creation_time_ms", "time_to_live_ms", "fee_payment", "metadata", "entrypoint_hash_hex", "executable",
            )
            require(root.text("schema") == "iroha.detached_transaction_scaffold.v1") { "Unknown inspection schema" }
            return DetachedTransactionInspection(
                root.hash("payload_signing_hash_hex"), root.hash("payload_hash_hex"),
                root.text("authority"), NetworkId.parse(root.text("network_id")),
                root.uint("creation_time_ms"), root.uint("time_to_live_ms", positive = true),
                FeePaymentJson.parse(root["fee_payment"], "fee_payment"),
                JsonEncoder.encode(obj(root["metadata"])), root.hash("entrypoint_hash_hex"),
                executable(obj(root["executable"])),
            )
        }

        private fun executable(value: Map<String, Any?>): DetachedExecutableInspection =
            when (value.text("kind")) {
                "contract_call" -> {
                    value.exact("kind", "contract_address", "expected_code_hash", "entrypoint", "arguments_b64")
                    val arguments = value["arguments_b64"]?.let {
                        require(it is String) { "Invalid contract arguments" }
                        val decoded = Base64.getDecoder().decode(it)
                        require(Base64.getEncoder().encodeToString(decoded) == it) { "Noncanonical contract arguments" }
                        it
                    }
                    DetachedExecutableInspection.ContractCall(
                        value.text("contract_address"), value.text("expected_code_hash"),
                        value.text("entrypoint"), arguments,
                    )
                }
                "asset_transfer" -> transfer(value)
                "atomic_transfer_sequence" -> {
                    value.exact("kind", "transfers")
                    val transfers = value.list("transfers").map { transfer(obj(it)) }
                    require(transfers.size == 2) { "Atomic transfer sequence must contain two exact transfers" }
                    DetachedExecutableInspection.AtomicTransferSequence(transfers)
                }
                "transfer_instruction_sequence" -> {
                    value.exact("kind", "transfers")
                    val transfers = value.list("transfers").map { transfer(obj(it)) }
                    require(transfers.size in 2..16) { "Transfer instruction sequence exceeds its review bound" }
                    DetachedExecutableInspection.TransferInstructionSequence(transfers)
                }
                "asset_transfer_batch" -> {
                    value.exact("kind", "mode", "entries")
                    val mode = when (value.text("mode")) {
                        "atomic" -> DetachedTransferBatchMode.ATOMIC
                        "independent" -> DetachedTransferBatchMode.INDEPENDENT
                        else -> throw IllegalArgumentException("Unknown native batch mode")
                    }
                    val entries = value.list("entries").map {
                        val leg = obj(it)
                        leg.exact("leg_id", "source_account_id", "destination_account_id", "asset_definition_id", "amount")
                        DetachedTransferBatchLeg(
                            leg.text("leg_id"), leg.text("source_account_id"), leg.text("destination_account_id"),
                            leg.text("asset_definition_id"), leg.text("amount"),
                        )
                    }
                    require(entries.isNotEmpty() && entries.map { it.legId }.toSet().size == entries.size) {
                        "Native batch legs must have distinct identities"
                    }
                    DetachedExecutableInspection.AssetTransferBatch(mode, entries)
                }
                "asset_fi_link_transfer" -> {
                    value.exact("kind", "asset_definition_id", "account_id", "amount",
                        "expected_link_revision", "expected_policy_revision")
                    DetachedExecutableInspection.AssetFiLinkTransfer(
                        value.text("asset_definition_id"), value.text("account_id"), value.text("amount"),
                        value.uint("expected_link_revision"), value.uint("expected_policy_revision"),
                    )
                }
                "asset_fi_link_set" -> {
                    value.exact(
                        "kind", "asset_definition_id", "account_id", "fi_account_id", "reference_digest",
                        "fi_revision", "attestation_revision", "revision", "enabled", "controller",
                        "waterfall", "reverse_waterfall", "expected_policy_revision",
                    )
                    val controller = value["controller"]?.let {
                        require(it is String && it.isNotEmpty()) { "Invalid FI link controller" }
                        it
                    }
                    DetachedExecutableInspection.AssetFiLinkSet(
                        value.text("asset_definition_id"), value.text("account_id"), value.text("fi_account_id"),
                        // Syntax only: the reference is raw32, never an Iroha Hash.
                        value.hash("reference_digest"), value.uint("fi_revision"),
                        value.uint("attestation_revision"), value.uint("revision"), value.bool("enabled"),
                        controller, value.bool("waterfall"), value.bool("reverse_waterfall"),
                        value.uint("expected_policy_revision"),
                    )
                }
                "conditional_escrow_open" -> {
                    value.exact("kind", "escrow_id", "asset_definition_id", "beneficiary", "amount", "conditions", "expires_at_ms", "evidence_hashes")
                    val conditions = value.list("conditions").map { condition(obj(it)) }
                    require(conditions.isNotEmpty()) { "Conditional escrow requires conditions" }
                    val evidence = value.list("evidence_hashes").map {
                        require(it is String && it.isNotEmpty()) { "Invalid evidence hash" }
                        it
                    }
                    DetachedExecutableInspection.ConditionalEscrowOpen(
                        value.text("escrow_id"), value.text("asset_definition_id"), value.text("beneficiary"),
                        value.text("amount"), conditions, value.uint("expires_at_ms", positive = true), evidence,
                    )
                }
                else -> throw IllegalArgumentException("Unsupported native instruction")
            }

        private fun transfer(value: Map<String, Any?>): DetachedExecutableInspection.AssetTransfer {
            value.exact("kind", "asset_definition_id", "asset_scope", "source_asset_id", "source_account_id", "destination_account_id", "amount")
            require(value.text("kind") == "asset_transfer") { "Unknown transfer instruction" }
            val scope = obj(value["asset_scope"])
            val dataSpace = when (scope.text("kind")) {
                "global" -> { scope.exact("kind"); null }
                "dataspace" -> { scope.exact("kind", "dataspace_id"); scope.uint("dataspace_id") }
                else -> throw IllegalArgumentException("Unknown balance scope")
            }
            return DetachedExecutableInspection.AssetTransfer(
                value.text("asset_definition_id"), dataSpace, value.text("source_asset_id"),
                value.text("source_account_id"), value.text("destination_account_id"), value.text("amount"),
            )
        }

        private fun condition(value: Map<String, Any?>): DetachedEscrowCondition =
            when (value.text("kind")) {
                "oracle" -> {
                    value.exact("kind", "id", "attestor", "sequence", "predicate")
                    val sequence = value.uint("sequence", positive = true)
                    require(sequence.bitLength() <= 32) { "Invalid condition sequence" }
                    DetachedEscrowCondition.Oracle(
                        value.text("id"), value.text("attestor"), sequence.toLong(), predicate(obj(value["predicate"])),
                    )
                }
                "within" -> {
                    value.exact("kind", "id", "duration_ms")
                    DetachedEscrowCondition.Within(value.text("id"), value.uint("duration_ms", positive = true))
                }
                else -> throw IllegalArgumentException("Unknown escrow condition")
            }

        private fun predicate(value: Map<String, Any?>): DetachedEscrowPredicate {
            value.exact("kind", "value")
            return when (value.text("kind")) {
                "quantity_at_most" -> DetachedEscrowPredicate.QuantityAtMost(value.text("value"))
                "equals" -> {
                    val fact = obj(value["value"])
                    fact.exact("kind", "value")
                    val typed = when (fact.text("kind")) {
                        "bool" -> DetachedEscrowValue.BooleanValue(
                            fact["value"] as? Boolean ?: throw IllegalArgumentException("Expected boolean fact"),
                        )
                        "text" -> DetachedEscrowValue.TextValue(
                            fact["value"] as? String ?: throw IllegalArgumentException("Expected text fact"),
                        )
                        "quantity" -> DetachedEscrowValue.QuantityValue(fact.text("value"))
                        else -> throw IllegalArgumentException("Unknown escrow value")
                    }
                    DetachedEscrowPredicate.Equals(typed)
                }
                else -> throw IllegalArgumentException("Unknown escrow predicate")
            }
        }

        private fun obj(value: Any?): Map<String, Any?> {
            require(value is Map<*, *> && value.keys.all { it is String }) { "Expected JSON object" }
            @Suppress("UNCHECKED_CAST")
            return value as Map<String, Any?>
        }
        private fun Map<String, Any?>.exact(vararg fields: String) {
            require(keys == fields.toSet()) { "Unknown or missing native inspection fields" }
        }
        private fun Map<String, Any?>.text(key: String): String =
            (get(key) as? String)?.takeIf { it.isNotEmpty() }
                ?: throw IllegalArgumentException("Missing native inspection text")
        private fun Map<String, Any?>.list(key: String): List<*> =
            get(key) as? List<*> ?: throw IllegalArgumentException("Missing native inspection array")
        private fun Map<String, Any?>.hash(key: String): String = text(key).also {
            require(Regex("[0-9a-f]{64}").matches(it)) { "Invalid native inspection hash" }
        }
        private fun Map<String, Any?>.bool(key: String): Boolean =
            get(key) as? Boolean ?: throw IllegalArgumentException("Invalid native inspection boolean")

        private fun Map<String, Any?>.uint(key: String, positive: Boolean = false): BigInteger {
            val value = get(key)
            val number = when (value) {
                is BigInteger -> value
                is Long, is Int -> BigInteger.valueOf((value as Number).toLong())
                else -> throw IllegalArgumentException("Invalid native inspection integer")
            }
            require(number.signum() >= (if (positive) 1 else 0) && number.bitLength() <= 64) { "Native inspection integer outside u64" }
            return number
        }
    }
}

/** Only these decoded native executable shapes may reach a wallet review. */
sealed class DetachedExecutableInspection private constructor() {
    class ContractCall internal constructor(
        val contractAddress: String, val expectedCodeHash: String, val entrypoint: String, val argumentsBase64: String?,
    ) : DetachedExecutableInspection()
    class AssetTransfer internal constructor(
        val assetDefinitionId: String, val dataSpaceId: BigInteger?, val sourceAssetId: String,
        val sourceAccountId: String, val destinationAccountId: String, val amount: String,
    ) : DetachedExecutableInspection()
    class AtomicTransferSequence internal constructor(transfers: List<AssetTransfer>) : DetachedExecutableInspection() {
        private val owned = transfers.toList()
        val transfers: List<AssetTransfer> get() = owned.toList()
    }
    class TransferInstructionSequence internal constructor(transfers: List<AssetTransfer>) : DetachedExecutableInspection() {
        private val owned = transfers.toList()
        val transfers: List<AssetTransfer> get() = owned.toList()
    }
    class AssetTransferBatch internal constructor(
        val mode: DetachedTransferBatchMode, entries: List<DetachedTransferBatchLeg>,
    ) : DetachedExecutableInspection() {
        private val owned = entries.toList()
        val entries: List<DetachedTransferBatchLeg> get() = owned.toList()
    }
    /** Exact signed fields only: no destination evidence, current link or execution proof. */
    class AssetFiLinkTransfer internal constructor(
        val assetDefinitionId: String, val accountId: String, val amount: String,
        val expectedLinkRevision: BigInteger, val expectedPolicyRevision: BigInteger,
    ) : DetachedExecutableInspection()
    /** Lossless owner-approved FI link fields; these do not prove current ledger policy. */
    class AssetFiLinkSet internal constructor(
        val assetDefinitionId: String, val accountId: String, val fiAccountId: String,
        val referenceDigestHex: String, val fiRevision: BigInteger, val attestationRevision: BigInteger,
        val revision: BigInteger, val enabled: Boolean, val controller: String?,
        val waterfall: Boolean, val reverseWaterfall: Boolean, val expectedPolicyRevision: BigInteger,
    ) : DetachedExecutableInspection()
    class ConditionalEscrowOpen internal constructor(
        val escrowId: String, val assetDefinitionId: String, val beneficiary: String, val amount: String,
        conditions: List<DetachedEscrowCondition>, val expiresAtMs: BigInteger, evidenceHashes: List<String>,
    ) : DetachedExecutableInspection() {
        private val ownedConditions = conditions.toList()
        private val ownedEvidence = evidenceHashes.toList()
        val conditions: List<DetachedEscrowCondition> get() = ownedConditions.toList()
        val evidenceHashes: List<String> get() = ownedEvidence.toList()
    }
}

/** Native semantics; independent execution may refuse some legs while committing others. */
enum class DetachedTransferBatchMode { ATOMIC, INDEPENDENT }

class DetachedTransferBatchLeg internal constructor(
    val legId: String, val sourceAccountId: String, val destinationAccountId: String,
    val assetDefinitionId: String, val amount: String,
)

sealed class DetachedEscrowCondition private constructor() {
    class Oracle internal constructor(
        val id: String, val attestor: String, val sequence: Long, val predicate: DetachedEscrowPredicate,
    ) : DetachedEscrowCondition()
    class Within internal constructor(val id: String, val durationMs: BigInteger) : DetachedEscrowCondition()
}

sealed class DetachedEscrowPredicate private constructor() {
    class Equals internal constructor(val value: DetachedEscrowValue) : DetachedEscrowPredicate()
    class QuantityAtMost internal constructor(val value: String) : DetachedEscrowPredicate()
}

sealed class DetachedEscrowValue private constructor() {
    class BooleanValue internal constructor(val value: Boolean) : DetachedEscrowValue()
    class TextValue internal constructor(val value: String) : DetachedEscrowValue()
    class QuantityValue internal constructor(val value: String) : DetachedEscrowValue()
}
