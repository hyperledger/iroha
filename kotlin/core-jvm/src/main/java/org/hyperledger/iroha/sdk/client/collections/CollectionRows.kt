package org.hyperledger.iroha.sdk.client.collections

import org.hyperledger.iroha.sdk.client.ContractManifestJsonParser
import org.hyperledger.iroha.sdk.client.ContractEventDescriptor
import java.math.BigDecimal
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonArray
import org.hyperledger.iroha.sdk.json.JsonBoolean
import org.hyperledger.iroha.sdk.json.JsonNull
import org.hyperledger.iroha.sdk.json.JsonNumber
import org.hyperledger.iroha.sdk.json.JsonObject
import org.hyperledger.iroha.sdk.json.JsonString

/**
 * A typed collection row. Every row keeps its complete JSON object in [json] (rows may gain
 * fields; unknown members are kept there and otherwise ignored). Equality compares [json].
 */
abstract class CollectionRow internal constructor(
    /** The complete row as returned by Torii. */
    @JvmField val json: JsonObject,
) {
    override fun equals(other: Any?): Boolean =
        other != null && other.javaClass == javaClass && (other as CollectionRow).json == json

    override fun hashCode(): Int = json.hashCode()

    override fun toString(): String = "${javaClass.simpleName}$json"
}

/** One effective permission; payload remains structured JSON. */
class AccountPermissionRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val name: String = row.string("name")
    @JvmField val payload: Json = requireNotNull(json["payload"]) { "payload is required" }
}

/** A subscription plan, keyed by its asset definition id. */
class SubscriptionPlanRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val id: String = row.string("id")
    @JvmField val provider: String? = row.stringOrNull("provider")
    @JvmField val billing: Json? = row.value("billing")
    @JvmField val pricing: Json? = row.value("pricing")
}

/** A flattened subscription, keyed by its NFT id. */
class SubscriptionRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val id: String = row.string("id")
    @JvmField val ownedBy: String? = row.stringOrNull("owned_by")
    @JvmField val planId: String? = row.stringOrNull("plan_id")
    @JvmField val provider: String? = row.stringOrNull("provider")
    @JvmField val subscriber: String? = row.stringOrNull("subscriber")
    @JvmField val status: String? = row.stringOrNull("status")
    @JvmField val currentPeriodStartMs: Long? = row.unsignedLongOrNull("current_period_start_ms")
    @JvmField val currentPeriodEndMs: Long? = row.unsignedLongOrNull("current_period_end_ms")
    @JvmField val nextChargeMs: Long? = row.unsignedLongOrNull("next_charge_ms")
    @JvmField val cancelAtPeriodEnd: Boolean? = row.booleanOrNull("cancel_at_period_end")
    @JvmField val cancelAtMs: Long? = row.unsignedLongOrNull("cancel_at_ms")
    @JvmField val failureCount: Long? = row.unsignedLongOrNull("failure_count")
    @JvmField val usageAccumulated: Json? = row.value("usage_accumulated")
    @JvmField val billingTriggerId: String? = row.stringOrNull("billing_trigger_id")
    @JvmField val invoice: JsonObject? = row.objectOrNull("invoice")
    @JvmField val plan: JsonObject? = row.objectOrNull("plan")
}

/** A contract transaction with its committed ledger position. */
class ContractActivityRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val blockHeight: Long = row.unsignedLong("block_height")
    @JvmField val blockIndex: Long = row.unsignedLong("block_index")
    @JvmField val entrypointHash: String = row.string("entrypoint_hash")
    @JvmField val timestampMs: Long? = row.unsignedLongOrNull("timestamp_ms")
    @JvmField val contractAlias: String? = row.stringOrNull("contract_alias")
    @JvmField val contractEntrypoint: String? = row.stringOrNull("contract_entrypoint")
    @JvmField val resultOk: Boolean? = row.booleanOrNull("result_ok")
}

/** One closed native value atom. Pointer contents remain canonical native TLV bytes. */
class ContractValueAtomV1 internal constructor(json: JsonObject) {
    /** Exact current tagged model kind. */
    enum class Kind { Tag, Bool, Pointer, List, Unit, ErrorCode, EnumCode }
    @JvmField val kind: Kind
    @JvmField val value: Json
    init {
        require(json.keys == setOf("kind", "value")) { "value atom requires exactly kind and value" }
        kind = Kind.valueOf(RowReader(json).string("kind"))
        value = requireNotNull(json["value"])
        when (kind) {
            Kind.Tag, Kind.Bool -> require(value is JsonBoolean) { "boolean atom requires bool" }
            Kind.Unit -> require(value === JsonNull) { "Unit atom requires null" }
            Kind.Pointer -> requireByteArray(value, 1_048_576, "pointer")
            Kind.List, Kind.ErrorCode, Kind.EnumCode -> {
                val code = (value as? JsonNumber)?.toLongExact() ?: error("atom code requires integer")
                require(if (kind == Kind.List) code in 0..64 else code in 1..0xffff_ffffL) { "atom code is outside its range" }
            }
        }
    }
}

private fun requireByteArray(value: Json, maximum: Int, context: String): List<Int> {
    val array = value as? JsonArray ?: error("$context requires byte array")
    require(array.size <= maximum) { "$context exceeds byte limit" }
    return java.util.Collections.unmodifiableList(array.items.map {
        val byte = (it as? JsonNumber)?.toLongExact() ?: error("$context requires integer bytes")
        require(byte in 0..255) { "$context requires bytes in 0..255" }
        byte.toInt()
    })
}

/** Exact native schema hash and preorder atom tape. */
class ContractValueRecordV1 internal constructor(json: JsonObject) {
    @JvmField val schemaHash: List<Int>
    @JvmField val atoms: List<ContractValueAtomV1>
    init {
        require(json.keys == setOf("schema_hash", "atoms")) { "value record requires exactly schema_hash and atoms" }
        schemaHash = requireByteArray(requireNotNull(json["schema_hash"]), 32, "schema_hash")
        require(schemaHash.size == 32) { "schema_hash must contain 32 bytes" }
        val values = json["atoms"] as? JsonArray ?: error("atoms must be array")
        require(values.size <= 1_048_576) { "atom tape exceeds public record bound" }
        atoms = java.util.Collections.unmodifiableList(values.items.map { ContractValueAtomV1(it as? JsonObject ?: error("atom must be object")) })
    }
}

/** Native host-authenticated origin and source definition retained in each event row. */
class ContractEmissionV1 internal constructor(json: JsonObject) {
    private val row = RowReader(json)
    @JvmField val contract: String = row.string("contract")
    @JvmField val codeHash: String = row.string("code_hash")
    @JvmField val entrypoint: Long = row.unsignedLong("entrypoint")
    @JvmField val event: Long = row.unsignedLong("event")
    @JvmField val caller: String = row.string("caller")
    @JvmField val definition: ContractEventDescriptor = ContractManifestJsonParser.parseEventDescriptor(requireNotNull(json["definition"]).toJsonBytes())
    @JvmField val payload: ContractValueRecordV1 = ContractValueRecordV1(json["payload"] as? JsonObject ?: error("native payload must be object"))
    init {
        require(json.keys == setOf("contract", "code_hash", "entrypoint", "event", "caller", "definition", "payload")) { "unknown or missing native emission field" }
        require(entrypoint <= 0xffff_ffffL && event <= 0xffff_ffffL) { "native event ordinals must be u32" }
    }
}

/** A committed emission at exact root-output and emission coordinates. */
class ContractEventRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val blockHeight: Long = row.unsignedLong("block_height")
    @JvmField val blockHashHex: String = row.string("block_hash_hex")
    @JvmField val eventId: String = row.string("event_id")
    @JvmField val executionHashHex: String = row.string("execution_hash_hex")
    @JvmField val outputIndex: Long = row.unsignedLong("output_index")
    @JvmField val emissionIndex: Long = row.unsignedLong("emission_index")
    @JvmField val provenance: String = row.string("provenance")
    @JvmField val authority: String = row.string("authority")
    @JvmField val contractAddress: String = row.string("contract_address")
    @JvmField val eventKind: String = row.string("event_kind")
    @JvmField val payload: Json = requireNotNull(json["payload"]) { "event payload is required" }
    @JvmField val emission: ContractEmissionV1 = ContractEmissionV1(json["emission"] as? JsonObject ?: error("native emission is required"))
    init {
        val allowed = setOf("event_id", "schema_version", "provenance", "authority", "timestamp_ms", "execution_hash_hex", "block_height", "block_hash_hex", "output_index", "emission_index", "result_ok", "contract_address", "event_kind", "participants", "asset_ids", "numeric_fields", "payload", "emission", "fee_payment")
        require(allowed.containsAll(json.keys)) { "unknown or retired contract event field" }
        require(row.unsignedLong("schema_version") == 1L && provenance == "emitted" && row.booleanOrNull("result_ok") == true) { "event must be a committed native emission" }
        require(eventId == "$blockHashHex:$outputIndex:$emissionIndex") { "event_id does not match committed coordinates" }
        require(contractAddress == emission.contract && authority == emission.caller && eventKind == emission.definition.name) { "event row does not match native origin" }
    }
}

/** One account movement and its committed ledger position. */
class AccountHistoryRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)
    @JvmField val id: String = row.string("id")
    @JvmField val blockHeight: Long = row.unsignedLong("block_height")
    @JvmField val blockIndex: Long = row.unsignedLong("block_index")
    @JvmField val movementIndex: Long = row.unsignedLong("movement_index")
    @JvmField val source: String? = row.stringOrNull("source")
    @JvmField val type: String? = row.stringOrNull("type")
    @JvmField val status: String? = row.stringOrNull("status")
    @JvmField val direction: String? = row.stringOrNull("direction")
    @JvmField val accountId: String? = row.stringOrNull("account_id")
    @JvmField val counterpartyAccountId: String? = row.stringOrNull("counterparty_account_id")
    @JvmField val assetId: String? = row.stringOrNull("asset_id")
    @JvmField val assetDefinitionId: String? = row.stringOrNull("asset_definition_id")
    @JvmField val amount: String? = row.stringOrNull("amount")
    @JvmField val txHash: String? = row.stringOrNull("tx_hash")
    @JvmField val timestampMs: Long? = row.unsignedLongOrNull("timestamp_ms")
    @JvmField val resultOk: Boolean? = row.booleanOrNull("result_ok")
}

/** A domain. Only [id] is always present. */
class DomainRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val ownedBy: String? = row.stringOrNull("owned_by")
    @JvmField val logo: String? = row.stringOrNull("logo")

    /** Metadata entries (`metadata.<key>` in filters). */
    @JvmField val metadata: JsonObject = row.metadata()
}

/** An account (`id` is the canonical I105 literal). Only [id] is always present. */
class AccountRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val label: String? = row.stringOrNull("label")
    @JvmField val uaid: String? = row.stringOrNull("uaid")
    @JvmField val metadata: JsonObject = row.metadata()
}

/**
 * An asset definition: the complete definition record plus [aliasBinding] when an alias is bound.
 * Ids are Base58 literals. Only [id] is always present.
 */
class AssetDefinitionRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val name: String? = row.stringOrNull("name")
    @JvmField val alias: String? = row.stringOrNull("alias")
    @JvmField val ownedBy: String? = row.stringOrNull("owned_by")
    @JvmField val owningDomain: String? = row.stringOrNull("owning_domain")
    /** Immutable direct definition home, independent of concrete balance buckets. */
    @JvmField val owningDataspace: String? = row.stringOrNull("owning_dataspace")?.also { home ->
        require(owningDomain == null && home.length <= 20 && home.matches(Regex("[1-9][0-9]*")) &&
            java.math.BigInteger(home) <= java.math.BigInteger("18446744073709551615")) {
            "owning_dataspace must be canonical nonzero u64 text without owning_domain"
        }
    }
    @JvmField val mintable: String? = row.stringOrNull("mintable")
    @JvmField val description: String? = row.stringOrNull("description")
    @JvmField val logo: String? = row.stringOrNull("logo")

    /** The numeric spec record, as JSON. */
    @JvmField val spec: Json? = row.value("spec")

    /** The balance-scope policy record, as JSON. */
    @JvmField val balanceScopePolicy: Json? = row.value("balance_scope_policy")
    @JvmField val aliasBinding: AliasBinding? = row.objectOrNull("alias_binding")?.let(::AliasBinding)
    @JvmField val metadata: JsonObject = row.metadata()

    /** The bound alias of an asset definition. */
    class AliasBinding internal constructor(json: JsonObject) {
        private val row = RowReader(json)

        @JvmField val alias: String? = row.stringOrNull("alias")
        @JvmField val status: String? = row.stringOrNull("status")
        @JvmField val leaseExpiryMs: Long? = row.longOrNull("lease_expiry_ms")
        @JvmField val graceUntilMs: Long? = row.longOrNull("grace_until_ms")
        @JvmField val boundAtMs: Long? = row.longOrNull("bound_at_ms")
    }
}

/** An NFT and its content in [metadata]. Only [id] is always present. */
class NftRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val ownedBy: String? = row.stringOrNull("owned_by")

    /** The NFT content. */
    @JvmField val metadata: JsonObject = row.metadata()
}

/** A real-world-asset lot; [quantity] is exact. Only [id] is always present. */
class RwaLotRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val ownedBy: String? = row.stringOrNull("owned_by")
    @JvmField val primaryReference: String? = row.stringOrNull("primary_reference")
    @JvmField val status: String? = row.stringOrNull("status")
    @JvmField val quantity: BigDecimal? = row.decimalOrNull("quantity")
    @JvmField val isFrozen: Boolean? = row.booleanOrNull("is_frozen")
    @JvmField val metadata: JsonObject = row.metadata()
}

/** One balance of an account; [asset], [scope], [accountId] and [quantity] are always present. */
class AccountAssetRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    /** Asset definition id. */
    @JvmField val asset: String = row.string("asset")
    @JvmField val assetName: String? = row.stringOrNull("asset_name")
    @JvmField val assetAlias: String? = row.stringOrNull("asset_alias")

    /** Balance scope: `global` or `dataspace:<id>`. */
    @JvmField val scope: String = row.string("scope")
    @JvmField val accountId: String = row.string("account_id")
    @JvmField val quantity: BigDecimal = row.decimal("quantity")
}

/** One holder of an asset definition; [accountId], [asset], [scope] and [quantity] are always present. */
class AssetHolderRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val accountId: String = row.string("account_id")
    @JvmField val asset: String = row.string("asset")
    @JvmField val assetAlias: String? = row.stringOrNull("asset_alias")
    @JvmField val scope: String = row.string("scope")
    @JvmField val quantity: BigDecimal = row.decimal("quantity")
}

/**
 * One committed transaction from a history collection (global `transactions` or one account's
 * transactions), newest first by ([blockHeight], [blockIndex]). [entrypointHash], [blockHeight]
 * and [blockIndex] are always present.
 */
class TransactionRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val entrypointHash: String = row.string("entrypoint_hash")
    @JvmField val blockHeight: Long = row.unsignedLong("block_height")

    /** Position of the transaction within its block. */
    @JvmField val blockIndex: Long = row.unsignedLong("block_index")
    @JvmField val blockHash: String? = row.stringOrNull("block_hash")
    @JvmField val authority: String? = row.stringOrNull("authority")
    @JvmField val timestampMs: Long? = row.unsignedLongOrNull("timestamp_ms")
    @JvmField val entrypointKind: String? = row.stringOrNull("entrypoint_kind")
    @JvmField val resultOk: Boolean? = row.booleanOrNull("result_ok")

    /** Assets the transaction touched; filters match element-wise. */
    @JvmField val assetIds: List<String> = row.stringList("asset_ids")

    /** Asset definitions the transaction touched; filters match element-wise. */
    @JvmField val assetDefinitionIds: List<String> = row.stringList("asset_definition_ids")
    @JvmField val metadata: JsonObject = row.metadata()
}

/** A repo agreement; leg quantities are exact. Only [id] is always present. */
class RepoAgreementRow internal constructor(json: JsonObject) : CollectionRow(json) {
    private val row = RowReader(json)

    @JvmField val id: String = row.string("id")
    @JvmField val initiator: String? = row.stringOrNull("initiator")
    @JvmField val counterparty: String? = row.stringOrNull("counterparty")
    @JvmField val custodian: String? = row.stringOrNull("custodian")
    @JvmField val status: String? = row.stringOrNull("status")
    @JvmField val cashSource: String? = row.stringOrNull("cash_source")
    @JvmField val cashLeg: Leg? = row.objectOrNull("cash_leg")?.let(::Leg)
    @JvmField val collateralLeg: Leg? = row.objectOrNull("collateral_leg")?.let(::Leg)
    @JvmField val collateralCustodyAsset: String? = row.stringOrNull("collateral_custody_asset")
    @JvmField val rateBps: Long? = row.longOrNull("rate_bps")
    @JvmField val maturityTimestampMs: Long? = row.longOrNull("maturity_timestamp_ms")
    @JvmField val initiatedTimestampMs: Long? = row.longOrNull("initiated_timestamp_ms")
    @JvmField val lastMarginCheckTimestampMs: Long? = row.longOrNull("last_margin_check_timestamp_ms")
    @JvmField val settlementTimestampMs: Long? = row.longOrNull("settlement_timestamp_ms")
    @JvmField val governance: Governance? = row.objectOrNull("governance")?.let(::Governance)

    /** One leg of the agreement. */
    class Leg internal constructor(json: JsonObject) {
        private val row = RowReader(json)

        @JvmField val assetDefinitionId: String? = row.stringOrNull("asset_definition_id")
        @JvmField val quantity: BigDecimal? = row.decimalOrNull("quantity")
    }

    /** Governance terms of the agreement. */
    class Governance internal constructor(json: JsonObject) {
        private val row = RowReader(json)

        @JvmField val haircutBps: Long? = row.longOrNull("haircut_bps")
        @JvmField val marginFrequencySecs: Long? = row.longOrNull("margin_frequency_secs")
    }
}

/** Typed member access for row decoding; failures become [IllegalArgumentException]. */
internal class RowReader(private val row: JsonObject) {
    fun value(name: String): Json? = row[name]?.takeUnless { it === JsonNull }

    fun string(name: String): String = stringOrNull(name) ?: missing(name, "a string")

    fun stringOrNull(name: String): String? = when (val value = value(name)) {
        null -> null
        is JsonString -> value.value
        else -> wrongType(name, "a string")
    }

    fun decimal(name: String): BigDecimal = decimalOrNull(name) ?: missing(name, "an exact decimal")

    fun decimalOrNull(name: String): BigDecimal? = when (val value = value(name)) {
        null -> null
        is JsonString -> parseDecimal(name, value.value)
        is JsonNumber -> value.toBigDecimal()
        else -> wrongType(name, "an exact decimal")
    }

    fun long(name: String): Long = longOrNull(name) ?: missing(name, "an integer")

    /** A `u64` member (within the signed 64-bit range). */
    fun unsignedLong(name: String): Long = unsignedLongOrNull(name) ?: missing(name, "an unsigned integer")

    fun unsignedLongOrNull(name: String): Long? = longOrNull(name)?.also {
        require(it >= 0) { "`$name` must be an unsigned integer, got $it" }
    }

    fun longOrNull(name: String): Long? = when (val value = value(name)) {
        null -> null
        is JsonNumber -> try {
            value.toLongExact()
        } catch (error: IllegalStateException) {
            throw IllegalArgumentException("`$name` must be a 64-bit integer, got ${value.text}", error)
        }
        else -> wrongType(name, "an integer")
    }

    fun booleanOrNull(name: String): Boolean? = when (val value = value(name)) {
        null -> null
        is JsonBoolean -> value.value
        else -> wrongType(name, "a boolean")
    }

    /** A list of strings; absent or `null` reads as empty. */
    fun stringList(name: String): List<String> = when (val value = value(name)) {
        null -> emptyList()
        is JsonArray -> java.util.Collections.unmodifiableList(
            value.items.map { item -> (item as? JsonString)?.value ?: wrongType(name, "an array of strings") },
        )
        else -> wrongType(name, "an array of strings")
    }

    fun objectOrNull(name: String): JsonObject? = when (val value = value(name)) {
        null -> null
        is JsonObject -> value
        else -> wrongType(name, "an object")
    }

    fun metadata(): JsonObject = objectOrNull("metadata") ?: JsonObject.EMPTY

    private fun parseDecimal(name: String, text: String): BigDecimal = try {
        BigDecimal(text)
    } catch (error: NumberFormatException) {
        throw IllegalArgumentException("`$name` must be an exact decimal, got `$text`", error)
    }

    private fun missing(name: String, type: String): Nothing =
        throw IllegalArgumentException("required member `$name` (expected $type) is missing")

    private fun wrongType(name: String, type: String): Nothing =
        throw IllegalArgumentException("`$name` must be $type")
}
