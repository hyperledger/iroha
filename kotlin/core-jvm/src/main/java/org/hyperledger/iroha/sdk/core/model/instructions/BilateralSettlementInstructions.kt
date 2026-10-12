// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.core.model.instructions

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.text.Normalizer
import java.util.Collections
import java.util.LinkedHashMap
import java.util.Optional
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.crypto.Blake2b
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.TypeAdapter
import org.hyperledger.iroha.sdk.numeric.KotodamaQuantity

/**
 * Typed, first-release constructors for bilateral DvP/PvP and repo instructions.
 *
 * Partial settlement is deliberately not represented: both settlement variants always encode
 * `SettlementAtomicity::AllOrNothing`. Every constructor validates the same static economic
 * invariants enforced by core before producing consent-bound canonical Norito bytes.
 */
object BilateralSettlementInstructions {
    /** Ordering used for the two legs of an atomic settlement. */
    enum class ExecutionOrder(internal val wireTag: Long) {
        /** Deliver the first asset before applying the reciprocal payment. */
        DELIVERY_THEN_PAYMENT(0),

        /** Apply the payment leg before delivering the reciprocal asset. */
        PAYMENT_THEN_DELIVERY(1),
    }

    /** An immutable payer-scoped business reference, shared by all carriers of one intent. */
    class SettlementId(owner: String, reference: String) {
        /** Canonical default-network spelling of the actual account identity. */
        val owner: String = AccountAddress.fromI105(
            requireCanonicalI105Address(owner, "settlementId.owner"),
            null,
        ).toI105Default()

        /** Exact canonical customer reference within this payer's namespace. */
        val reference: String = requireName(reference, "settlementId.reference")

        override fun equals(other: Any?): Boolean =
            this === other || other is SettlementId && owner == other.owner && reference == other.reference

        override fun hashCode(): Int = 31 * owner.hashCode() + reference.hashCode()

        /** Human input form; native JSON and binary encoders retain both typed fields. */
        override fun toString(): String = "$reference\$$owner"

        companion object {
            /** Parse exactly REFERENCE$CANONICAL_ACCOUNT; bare references are never accepted. */
            @JvmStatic
            fun parse(value: String): SettlementId {
                val separator = value.indexOf('$')
                require(separator > 0 && separator == value.lastIndexOf('$')) {
                    "settlementId must use REFERENCE\$CANONICAL_ACCOUNT"
                }
                val id = SettlementId(value.substring(separator + 1), value.substring(0, separator))
                require(id.toString() == value) { "settlementId must use canonical spelling" }
                return id
            }
        }
    }

    /** One exact debit and credit leg in a bilateral settlement. */
    class SettlementLeg(
        assetDefinitionId: String,
        quantity: String,
        from: String,
        to: String,
        metadata: Map<String, JsonValue> = emptyMap(),
    ) {
        /** Canonical Base58 asset-definition identifier. */
        val assetDefinitionId: String = requireAssetDefinitionId(assetDefinitionId, "assetDefinitionId")

        /** Positive, canonically spelled V1 quantity. */
        val quantity: String = requirePositiveQuantity(quantity, "quantity")

        /** Canonical I105 account debited by this leg. */
        val from: String = requireCanonicalI105Address(from, "from")

        /** Canonical I105 account credited by this leg. */
        val to: String = requireCanonicalI105Address(to, "to")

        /** Immutable metadata committed by the settlement intent. */
        val metadata: Map<String, JsonValue> = immutableMetadata(metadata)

        init {
            require(!sameAccount(this.from, this.to)) {
                "settlement leg sender and recipient must be distinct accounts"
            }
        }

        /** Constructs a leg from a lossless validated quantity. */
        constructor(
            assetDefinitionId: String,
            quantity: KotodamaQuantity,
            from: String,
            to: String,
            metadata: Map<String, JsonValue> = emptyMap(),
        ) : this(assetDefinitionId, quantity.toString(), from, to, metadata)
    }

    /** Atomic delivery-versus-payment instruction. */
    class Dvp(
        val settlementId: SettlementId,
        val deliveryLeg: SettlementLeg,
        val paymentLeg: SettlementLeg,
        val order: ExecutionOrder = ExecutionOrder.DELIVERY_THEN_PAYMENT,
        metadata: Map<String, JsonValue> = emptyMap(),
    ) : InstructionTemplate {
        /** Immutable metadata included in the exact consent commitment. */
        val metadata: Map<String, JsonValue> = immutableMetadata(metadata)

        init {
            requireReciprocalLegs(deliveryLeg, paymentLeg, "DvP")
            requireSettlementOwner(settlementId, deliveryLeg, paymentLeg)
        }

        override val kind: InstructionKind = InstructionKind.CUSTOM

        override val arguments: Map<String, String> = mapOf(
            "settlement_id" to this.settlementId.toString(),
            "delivery_asset_definition_id" to deliveryLeg.assetDefinitionId,
            "payment_asset_definition_id" to paymentLeg.assetDefinitionId,
            "order" to order.name,
            "atomicity" to "ALL_OR_NOTHING",
        )

        /** Returns the canonical boxed instruction accepted by the native registry. */
        override fun toInstructionBox(): InstructionBox = BilateralSettlementWire.encodeDvp(this)

        /** Returns the bare canonical `DvpIsi` bytes covered by counterparty consent. */
        fun canonicalInstructionBytes(): ByteArray = BilateralSettlementWire.encodeDvpConcrete(this)

        /** Returns the marked Blake2b-256 exact-intent hash required by `CanExecuteSettlement`. */
        fun intentHash(): ByteArray = BilateralSettlementWire.dvpIntentHash(this)
    }

    /** Atomic payment-versus-payment instruction. */
    class Pvp(
        val settlementId: SettlementId,
        val primaryLeg: SettlementLeg,
        val counterLeg: SettlementLeg,
        val order: ExecutionOrder = ExecutionOrder.PAYMENT_THEN_DELIVERY,
        metadata: Map<String, JsonValue> = emptyMap(),
    ) : InstructionTemplate {
        /** Immutable metadata included in the exact consent commitment. */
        val metadata: Map<String, JsonValue> = immutableMetadata(metadata)

        init {
            requireReciprocalLegs(primaryLeg, counterLeg, "PvP")
            requireSettlementOwner(settlementId, primaryLeg, counterLeg)
        }

        override val kind: InstructionKind = InstructionKind.CUSTOM

        override val arguments: Map<String, String> = mapOf(
            "settlement_id" to this.settlementId.toString(),
            "primary_asset_definition_id" to primaryLeg.assetDefinitionId,
            "counter_asset_definition_id" to counterLeg.assetDefinitionId,
            "order" to order.name,
            "atomicity" to "ALL_OR_NOTHING",
        )

        /** Returns the canonical boxed instruction accepted by the native registry. */
        override fun toInstructionBox(): InstructionBox = BilateralSettlementWire.encodePvp(this)

        /** Returns the bare canonical `PvpIsi` bytes covered by counterparty consent. */
        fun canonicalInstructionBytes(): ByteArray = BilateralSettlementWire.encodePvpConcrete(this)

        /** Returns the marked Blake2b-256 exact-intent hash required by `CanExecuteSettlement`. */
        fun intentHash(): ByteArray = BilateralSettlementWire.pvpIntentHash(this)
    }

    /** Immutable exact cash terms for a repo agreement. */
    class RepoCashLeg(assetDefinitionId: String, quantity: String) {
        /** Canonical cash asset definition. */
        val assetDefinitionId: String = requireAssetDefinitionId(assetDefinitionId, "cashLeg.assetDefinitionId")

        /** Positive canonical cash quantity. */
        val quantity: String = requirePositiveQuantity(quantity, "cashLeg.quantity")

        /** Constructs a cash leg from a lossless validated quantity. */
        constructor(assetDefinitionId: String, quantity: KotodamaQuantity) :
            this(assetDefinitionId, quantity.toString())
    }

    /** Immutable exact collateral terms for a repo agreement. */
    class RepoCollateralLeg(
        assetDefinitionId: String,
        quantity: String,
        metadata: Map<String, JsonValue> = emptyMap(),
    ) {
        /** Canonical collateral asset definition. */
        val assetDefinitionId: String =
            requireAssetDefinitionId(assetDefinitionId, "collateralLeg.assetDefinitionId")

        /** Positive canonical collateral quantity. */
        val quantity: String = requirePositiveQuantity(quantity, "collateralLeg.quantity")

        /** Immutable admission metadata. */
        val metadata: Map<String, JsonValue> = immutableMetadata(metadata)

        /** Constructs a collateral leg from a lossless validated quantity. */
        constructor(
            assetDefinitionId: String,
            quantity: KotodamaQuantity,
            metadata: Map<String, JsonValue> = emptyMap(),
        ) : this(assetDefinitionId, quantity.toString(), metadata)
    }

    /** Governance terms fixed for the lifetime of a repo agreement. */
    class RepoGovernance(haircutBps: Int, marginFrequencySecs: BigInteger) {
        /** Collateral haircut in basis points. */
        val haircutBps: Int = requireU16(haircutBps, "haircutBps").also {
            require(it <= 10_000) { "haircutBps must not exceed 10000" }
        }

        /** Margin-check cadence in seconds; zero disables scheduled margin checks. */
        val marginFrequencySecs: BigInteger = requireU64(marginFrequencySecs, "marginFrequencySecs")

        /** Convenience constructor for non-negative signed-long cadence values. */
        constructor(haircutBps: Int, marginFrequencySecs: Long) :
            this(haircutBps, requireNonNegativeLong(marginFrequencySecs, "marginFrequencySecs"))
    }

    /** Atomic repo-open instruction with complete, consent-bound economic terms. */
    class Repo(
        agreementId: String,
        initiator: String,
        counterparty: String,
        custodian: String?,
        val cashLeg: RepoCashLeg,
        val collateralLeg: RepoCollateralLeg,
        rateBps: Int,
        maturityTimestampMs: BigInteger,
        val governance: RepoGovernance,
    ) : InstructionTemplate {
        /** Canonical one-shot repo agreement identifier. */
        val agreementId: String = requireName(agreementId, "agreementId")

        /** Canonical I105 account that must sign the repo-open transaction. */
        val initiator: String = requireCanonicalI105Address(initiator, "initiator")

        /** Canonical I105 counterparty providing exact cash consent. */
        val counterparty: String = requireCanonicalI105Address(counterparty, "counterparty")

        /** Optional distinct tri-party collateral custodian. */
        val custodian: String? = custodian?.let { requireCanonicalI105Address(it, "custodian") }

        /** Fixed interest rate in basis points. */
        val rateBps: Int = requireU16(rateBps, "rateBps")

        /** Exact positive maturity timestamp in Unix milliseconds. */
        val maturityTimestampMs: BigInteger = requireU64(maturityTimestampMs, "maturityTimestampMs").also {
            require(it.signum() > 0) { "maturityTimestampMs must be positive" }
        }

        init {
            require(!sameAccount(this.initiator, this.counterparty)) {
                "repo initiator and counterparty must be distinct accounts"
            }
            this.custodian?.let {
                require(!sameAccount(it, this.initiator) && !sameAccount(it, this.counterparty)) {
                    "repo custodian must be distinct from both counterparties"
                }
            }
            require(cashLeg.assetDefinitionId != collateralLeg.assetDefinitionId) {
                "repo cash and collateral must use distinct asset definitions"
            }
        }

        /** Convenience constructor for non-negative signed-long maturity timestamps. */
        constructor(
            agreementId: String,
            initiator: String,
            counterparty: String,
            custodian: String?,
            cashLeg: RepoCashLeg,
            collateralLeg: RepoCollateralLeg,
            rateBps: Int,
            maturityTimestampMs: Long,
            governance: RepoGovernance,
        ) : this(
            agreementId,
            initiator,
            counterparty,
            custodian,
            cashLeg,
            collateralLeg,
            rateBps,
            requireNonNegativeLong(maturityTimestampMs, "maturityTimestampMs"),
            governance,
        )

        override val kind: InstructionKind = InstructionKind.CUSTOM

        override val arguments: Map<String, String> = mapOf(
            "agreement_id" to this.agreementId,
            "initiator" to this.initiator,
            "counterparty" to this.counterparty,
            "custodian" to (this.custodian ?: ""),
            "cash_asset_definition_id" to cashLeg.assetDefinitionId,
            "collateral_asset_definition_id" to collateralLeg.assetDefinitionId,
            "rate_bps" to this.rateBps.toString(),
            "maturity_timestamp_ms" to this.maturityTimestampMs.toString(),
        )

        /** Returns the canonical boxed instruction accepted by the native registry. */
        override fun toInstructionBox(): InstructionBox = BilateralSettlementWire.encodeRepo(this)

        /** Returns the bare canonical `RepoIsi` bytes covered by both repo consents. */
        fun canonicalInstructionBytes(): ByteArray = BilateralSettlementWire.encodeRepoConcrete(this)

        /** The one-shot settlement id used by both repo permission grants. */
        fun settlementId(): SettlementId = SettlementId(initiator, agreementId)

        /** Exact hash authorizing the counterparty cash debit at repo initiation. */
        fun initiationIntentHash(): ByteArray = BilateralSettlementWire.repoInitiationIntentHash(this)

        /** Exact hash authorizing release of the collateral balance at maturity. */
        fun maturityIntentHash(): ByteArray = BilateralSettlementWire.repoMaturityIntentHash(this)
    }

    /** ID-only, fixed-maturity reverse-repo settlement instruction. */
    class ReverseRepo(agreementId: String) : InstructionTemplate {
        /** Existing agreement to settle at its immutable on-chain maturity. */
        val agreementId: String = requireName(agreementId, "agreementId")

        override val kind: InstructionKind = InstructionKind.CUSTOM
        override val arguments: Map<String, String> = mapOf("agreement_id" to this.agreementId)

        /** Returns the canonical boxed instruction accepted by the native registry. */
        override fun toInstructionBox(): InstructionBox = BilateralSettlementWire.encodeReverseRepo(this)
    }

    private fun requireSettlementOwner(id: SettlementId, first: SettlementLeg, second: SettlementLeg) {
        require(sameAccount(id.owner, first.from) || sameAccount(id.owner, second.from)) {
            "settlement identity owner must authorize an actual debit"
        }
    }

    private fun requireReciprocalLegs(first: SettlementLeg, second: SettlementLeg, label: String) {
        require(sameAccount(first.from, second.to) && sameAccount(first.to, second.from)) {
            "$label legs must exchange assets between the same two accounts in opposite directions"
        }
        require(first.assetDefinitionId != second.assetDefinitionId) {
            "$label legs must use distinct asset definitions"
        }
    }

    private fun sameAccount(left: String, right: String): Boolean =
        TransferWirePayloadEncoder.encodeAccountIdPayload(left)
            .contentEquals(TransferWirePayloadEncoder.encodeAccountIdPayload(right))

    private fun requireAssetDefinitionId(value: String, field: String): String {
        try {
            TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(value)
        } catch (ex: IllegalArgumentException) {
            throw IllegalArgumentException("$field must be a canonical Base58 AssetDefinitionId", ex)
        }
        return value
    }

    private fun requirePositiveQuantity(value: String, field: String): String {
        val parsed = try {
            KotodamaQuantity.parseCanonical(value)
        } catch (ex: IllegalArgumentException) {
            throw IllegalArgumentException("$field must be a canonically spelled V1 quantity", ex)
        }
        require(parsed.mantissa.signum() > 0) { "$field must be positive" }
        return parsed.toString()
    }

    private fun immutableMetadata(value: Map<String, JsonValue>): Map<String, JsonValue> {
        val copy = LinkedHashMap<String, JsonValue>(value.size)
        for ((key, json) in value) {
            val canonicalKey = requireName(key, "metadata key")
            require(json.canonicalJson.isNotEmpty() && json.canonicalJson == json.canonicalJson.trim()) {
                "metadata value for '$canonicalKey' must be an exact non-empty JSON literal"
            }
            copy[canonicalKey] = json
        }
        return Collections.unmodifiableMap(copy)
    }

    private fun requireName(value: String, field: String): String {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        require(value.isNotEmpty() && bytes.size <= 255) { "$field must contain 1..255 UTF-8 bytes" }
        require(Normalizer.isNormalized(value, Normalizer.Form.NFC)) { "$field must use NFC form" }
        var offset = 0
        while (offset < value.length) {
            val codePoint = value.codePointAt(offset)
            require(Character.getType(codePoint) != Character.SURROGATE.toInt()) {
                "$field must contain valid Unicode scalar values"
            }
            require(
                !Character.isISOControl(codePoint) &&
                    !Character.isWhitespace(codePoint) && !Character.isSpaceChar(codePoint),
            ) {
                "$field must not contain controls or whitespace"
            }
            require(!isBidiControl(codePoint)) { "$field must not contain bidirectional controls" }
            require(codePoint != '@'.code && codePoint != '#'.code && codePoint != '$'.code) {
                "$field contains a reserved identifier separator"
            }
            offset += Character.charCount(codePoint)
        }
        return value
    }

    private fun isBidiControl(codePoint: Int): Boolean =
        codePoint == 0x061C || codePoint == 0x200E || codePoint == 0x200F ||
            codePoint in 0x202A..0x202E || codePoint in 0x2066..0x2069

    private fun requireU16(value: Int, field: String): Int {
        require(value in 0..0xFFFF) { "$field must fit u16" }
        return value
    }

    private fun requireU64(value: BigInteger, field: String): BigInteger {
        require(value.signum() >= 0 && value <= U64_MAX) { "$field must fit u64" }
        return value
    }

    private fun requireNonNegativeLong(value: Long, field: String): BigInteger {
        require(value >= 0) { "$field must be non-negative" }
        return BigInteger.valueOf(value)
    }

    private val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
}

private object BilateralSettlementWire {
    private const val SETTLEMENT_WIRE_NAME = "iroha.settlement"
    private const val SETTLEMENT_SCHEMA = "iroha_data_model::isi::settlement::SettlementInstructionBox"
    private const val REPO_WIRE_NAME = "iroha.repo"
    private const val REPO_SCHEMA = "iroha_data_model::isi::repo::RepoInstructionBox"
    private val DVP_INTENT_DOMAIN = "iroha:settlement:dvp-intent:v1\u0000".toByteArray()
    private val PVP_INTENT_DOMAIN = "iroha:settlement:pvp-intent:v1\u0000".toByteArray()
    private val REPO_INITIATION_INTENT_DOMAIN = "iroha:repo:initiation-intent:v1\u0000".toByteArray()
    private val REPO_MATURITY_INTENT_DOMAIN = "iroha:repo:maturity-intent:v1\u0000".toByteArray()
    private val U16 = NoritoAdapters.uint(16)
    private val U32 = NoritoAdapters.uint(32)
    private val STRING = NoritoAdapters.stringAdapter()
    private val OPTIONAL_RAW = NoritoAdapters.option(RawAdapter)
    private val METADATA = MetadataAdapter()

    fun encodeDvp(value: BilateralSettlementInstructions.Dvp): InstructionBox =
        InstructionBox.fromWirePayload(
            SETTLEMENT_WIRE_NAME,
            NoritoCodec.encode(value, SETTLEMENT_SCHEMA, DvpBoxAdapter),
        )

    fun encodePvp(value: BilateralSettlementInstructions.Pvp): InstructionBox =
        InstructionBox.fromWirePayload(
            SETTLEMENT_WIRE_NAME,
            NoritoCodec.encode(value, SETTLEMENT_SCHEMA, PvpBoxAdapter),
        )

    fun encodeRepo(value: BilateralSettlementInstructions.Repo): InstructionBox =
        InstructionBox.fromWirePayload(
            REPO_WIRE_NAME,
            NoritoCodec.encode(value, REPO_SCHEMA, RepoBoxAdapter),
        )

    fun encodeReverseRepo(value: BilateralSettlementInstructions.ReverseRepo): InstructionBox =
        InstructionBox.fromWirePayload(
            REPO_WIRE_NAME,
            NoritoCodec.encode(value, REPO_SCHEMA, ReverseRepoBoxAdapter),
        )

    fun encodeDvpConcrete(value: BilateralSettlementInstructions.Dvp): ByteArray =
        bare { encodeDvpStruct(it, value) }

    fun encodePvpConcrete(value: BilateralSettlementInstructions.Pvp): ByteArray =
        bare { encodePvpStruct(it, value) }

    fun encodeRepoConcrete(value: BilateralSettlementInstructions.Repo): ByteArray =
        bare { encodeRepoStruct(it, value) }

    fun dvpIntentHash(value: BilateralSettlementInstructions.Dvp): ByteArray =
        markedHash(DVP_INTENT_DOMAIN, encodeDvpConcrete(value))

    fun pvpIntentHash(value: BilateralSettlementInstructions.Pvp): ByteArray =
        markedHash(PVP_INTENT_DOMAIN, encodePvpConcrete(value))

    fun repoInitiationIntentHash(value: BilateralSettlementInstructions.Repo): ByteArray =
        markedHash(REPO_INITIATION_INTENT_DOMAIN, encodeRepoConcrete(value))

    fun repoMaturityIntentHash(value: BilateralSettlementInstructions.Repo): ByteArray =
        markedHash(REPO_MATURITY_INTENT_DOMAIN, encodeRepoConcrete(value))

    private object DvpBoxAdapter : TypeAdapter<BilateralSettlementInstructions.Dvp> {
        override fun encode(encoder: NoritoEncoder, value: BilateralSettlementInstructions.Dvp) {
            U32.encode(encoder, 0)
            sizedRaw(encoder, encodeDvpConcrete(value))
        }

        override fun decode(decoder: NoritoDecoder): BilateralSettlementInstructions.Dvp = unsupportedDecode()
    }

    private object PvpBoxAdapter : TypeAdapter<BilateralSettlementInstructions.Pvp> {
        override fun encode(encoder: NoritoEncoder, value: BilateralSettlementInstructions.Pvp) {
            U32.encode(encoder, 1)
            sizedRaw(encoder, encodePvpConcrete(value))
        }

        override fun decode(decoder: NoritoDecoder): BilateralSettlementInstructions.Pvp = unsupportedDecode()
    }

    private object RepoBoxAdapter : TypeAdapter<BilateralSettlementInstructions.Repo> {
        override fun encode(encoder: NoritoEncoder, value: BilateralSettlementInstructions.Repo) {
            U32.encode(encoder, 0)
            sizedRaw(encoder, encodeRepoConcrete(value))
        }

        override fun decode(decoder: NoritoDecoder): BilateralSettlementInstructions.Repo = unsupportedDecode()
    }

    private object ReverseRepoBoxAdapter : TypeAdapter<BilateralSettlementInstructions.ReverseRepo> {
        override fun encode(encoder: NoritoEncoder, value: BilateralSettlementInstructions.ReverseRepo) {
            U32.encode(encoder, 1)
            sizedRaw(encoder, bare { sizedRaw(it, encodeNameId(value.agreementId)) })
        }

        override fun decode(decoder: NoritoDecoder): BilateralSettlementInstructions.ReverseRepo = unsupportedDecode()
    }

    private fun encodeDvpStruct(
        encoder: NoritoEncoder,
        value: BilateralSettlementInstructions.Dvp,
    ) {
        sizedRaw(encoder, encodeSettlementId(value.settlementId))
        sizedRaw(encoder, encodeSettlementLeg(value.deliveryLeg))
        sizedRaw(encoder, encodeSettlementLeg(value.paymentLeg))
        sizedRaw(encoder, encodePlan(value.order))
        sized(encoder, METADATA, value.metadata)
    }

    private fun encodePvpStruct(
        encoder: NoritoEncoder,
        value: BilateralSettlementInstructions.Pvp,
    ) {
        sizedRaw(encoder, encodeSettlementId(value.settlementId))
        sizedRaw(encoder, encodeSettlementLeg(value.primaryLeg))
        sizedRaw(encoder, encodeSettlementLeg(value.counterLeg))
        sizedRaw(encoder, encodePlan(value.order))
        sized(encoder, METADATA, value.metadata)
    }

    private fun encodeSettlementLeg(value: BilateralSettlementInstructions.SettlementLeg): ByteArray = bare {
        sizedRaw(it, TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(value.assetDefinitionId))
        sizedRaw(it, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity))
        sizedRaw(it, TransferWirePayloadEncoder.encodeAccountIdPayload(value.from))
        sizedRaw(it, TransferWirePayloadEncoder.encodeAccountIdPayload(value.to))
        sized(it, METADATA, value.metadata)
    }

    private fun encodePlan(order: BilateralSettlementInstructions.ExecutionOrder): ByteArray = bare {
        sized(it, U32, order.wireTag)
        sized(it, U32, 0L)
    }

    private fun encodeRepoStruct(
        encoder: NoritoEncoder,
        value: BilateralSettlementInstructions.Repo,
    ) {
        sizedRaw(encoder, encodeNameId(value.agreementId))
        sizedRaw(encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.initiator))
        sizedRaw(encoder, TransferWirePayloadEncoder.encodeAccountIdPayload(value.counterparty))
        val custodian = value.custodian?.let { TransferWirePayloadEncoder.encodeAccountIdPayload(it) }
        sized(encoder, OPTIONAL_RAW, Optional.ofNullable(custodian))
        sizedRaw(encoder, encodeRepoCashLeg(value.cashLeg))
        sizedRaw(encoder, encodeRepoCollateralLeg(value.collateralLeg))
        sized(encoder, U16, value.rateBps.toLong())
        sized(encoder, U64Adapter, value.maturityTimestampMs)
        sizedRaw(encoder, encodeRepoGovernance(value.governance))
    }

    private fun encodeRepoCashLeg(value: BilateralSettlementInstructions.RepoCashLeg): ByteArray = bare {
        sizedRaw(it, TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(value.assetDefinitionId))
        sizedRaw(it, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity))
    }

    private fun encodeRepoCollateralLeg(value: BilateralSettlementInstructions.RepoCollateralLeg): ByteArray = bare {
        sizedRaw(it, TransferWirePayloadEncoder.encodeAssetDefinitionIdPayload(value.assetDefinitionId))
        sizedRaw(it, TransferWirePayloadEncoder.encodeQuantityPayload(value.quantity))
        sized(it, METADATA, value.metadata)
    }

    private fun encodeRepoGovernance(value: BilateralSettlementInstructions.RepoGovernance): ByteArray = bare {
        sized(it, U16, value.haircutBps.toLong())
        sized(it, U64Adapter, value.marginFrequencySecs)
    }

    private fun encodeSettlementId(value: BilateralSettlementInstructions.SettlementId): ByteArray = bare {
        sizedRaw(it, TransferWirePayloadEncoder.encodeAccountIdPayload(value.owner))
        sized(it, STRING, value.reference)
    }

    private fun encodeNameId(value: String): ByteArray = bare { sized(it, STRING, value) }

    private object RawAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) = encoder.writeBytes(value)
        override fun decode(decoder: NoritoDecoder): ByteArray = unsupportedDecode()
    }

    private object U64Adapter : TypeAdapter<BigInteger> {
        override fun encode(encoder: NoritoEncoder, value: BigInteger) = encoder.writeUInt(value.toLong(), 64)
        override fun decode(decoder: NoritoDecoder): BigInteger = unsupportedDecode()
    }

    private data class MetadataEntry(val key: String, val value: JsonValue)

    private class MetadataAdapter : TypeAdapter<Map<String, JsonValue>> {
        private val sequence = NoritoAdapters.sequence(MetadataEntryAdapter)

        override fun encode(encoder: NoritoEncoder, value: Map<String, JsonValue>) {
            val keys = value.keys.sortedWith { left, right -> compareUtf8(left, right) }
            sequence.encode(encoder, keys.map { MetadataEntry(it, value.getValue(it)) })
        }

        override fun decode(decoder: NoritoDecoder): Map<String, JsonValue> = unsupportedDecode()
    }

    private object MetadataEntryAdapter : TypeAdapter<MetadataEntry> {
        override fun encode(encoder: NoritoEncoder, value: MetadataEntry) {
            sized(encoder, STRING, value.key)
            sized(encoder, STRING, value.value.canonicalJson)
        }

        override fun decode(decoder: NoritoDecoder): MetadataEntry = unsupportedDecode()
    }

    private fun bare(write: (NoritoEncoder) -> Unit): ByteArray {
        val encoder = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
        write(encoder)
        return encoder.toByteArray()
    }

    private fun <T> sized(encoder: NoritoEncoder, adapter: TypeAdapter<T>, value: T) {
        val child = encoder.childEncoder()
        adapter.encode(child, value)
        sizedRaw(encoder, child.toByteArray())
    }

    private fun sizedRaw(encoder: NoritoEncoder, payload: ByteArray) {
        encoder.writeLength(payload.size.toLong(), (encoder.flags and NoritoHeader.COMPACT_LEN) != 0)
        encoder.writeBytes(payload)
    }

    private fun markedHash(domain: ByteArray, concrete: ByteArray): ByteArray =
        Blake2b.digest256(domain + concrete).also { it[it.lastIndex] = (it.last().toInt() or 1).toByte() }

    private fun compareUtf8(left: String, right: String): Int {
        val leftBytes = left.toByteArray(StandardCharsets.UTF_8)
        val rightBytes = right.toByteArray(StandardCharsets.UTF_8)
        for (index in 0 until minOf(leftBytes.size, rightBytes.size)) {
            val comparison = (leftBytes[index].toInt() and 0xFF) - (rightBytes[index].toInt() and 0xFF)
            if (comparison != 0) return comparison
        }
        return leftBytes.size - rightBytes.size
    }

    private fun <T> unsupportedDecode(): T =
        throw UnsupportedOperationException("bilateral settlement instruction decoding is not exposed")
}
