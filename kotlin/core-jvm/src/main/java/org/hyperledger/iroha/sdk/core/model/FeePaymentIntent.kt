package org.hyperledger.iroha.sdk.core.model

import java.nio.charset.StandardCharsets
import java.text.Normalizer
import java.util.LinkedHashMap
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.numeric.KotodamaQuantity

/** Fee component constrained by a signature-bound maximum charge. */
enum class FeeChargeKind {
    NEXUS,
    PIPELINE_GAS,
}

/** Exact asset and maximum amount authorized for one fee component. */
class FeeChargeLimit(
    @JvmField val kind: FeeChargeKind,
    @JvmField val assetDefinitionId: String,
    @JvmField val maxAmount: String,
) {
    init {
        require(AssetDefinitionIdEncoder.isCanonicalAddress(assetDefinitionId)) {
            "assetDefinitionId must be a canonical unprefixed Base58 asset definition id"
        }
        val amount = KotodamaQuantity.parseCanonical(maxAmount)
        require(amount.mantissa.signum() > 0) { "maxAmount must be positive" }
    }

    override fun equals(other: Any?): Boolean =
        other is FeeChargeLimit &&
            kind == other.kind &&
            assetDefinitionId == other.assetDefinitionId &&
            maxAmount == other.maxAmount

    override fun hashCode(): Int {
        var result = kind.hashCode()
        result = 31 * result + assetDefinitionId.hashCode()
        result = 31 * result + maxAmount.hashCode()
        return result
    }
}

/** Exact immutable sponsor-program identifier. */
class FeeSponsorProgramId(
    @JvmField val sponsor: String,
    @JvmField val name: String,
) {
    init {
        require('/' !in sponsor) { "sponsor must not contain `/`" }
        requireCanonicalI105Address(sponsor, "sponsor")
        validateProgramName(name)
    }

    private val sponsorIdentity =
        AccountAddress.parseEncoded(sponsor, null).canonicalBytes

    /** Canonical `sponsor/program` selector used by Torii routes. */
    fun literal(): String = "$sponsor/$name"

    override fun toString(): String = literal()

    override fun equals(other: Any?): Boolean =
        other is FeeSponsorProgramId &&
            sponsorIdentity.contentEquals(other.sponsorIdentity) &&
            name == other.name

    override fun hashCode(): Int = 31 * sponsorIdentity.contentHashCode() + name.hashCode()

    companion object {
        private const val MAX_PROGRAM_NAME_UTF8_BYTES = 255

        private fun validateProgramName(name: String) {
            require(name.isNotEmpty()) { "program name must not be empty" }
            require(name.toByteArray(StandardCharsets.UTF_8).size <= MAX_PROGRAM_NAME_UTF8_BYTES) {
                "program name exceeds the 255-byte UTF-8 limit"
            }
            var offset = 0
            while (offset < name.length) {
                val first = name[offset]
                val codePoint = when {
                    Character.isHighSurrogate(first) -> {
                        require(
                            offset + 1 < name.length && Character.isLowSurrogate(name[offset + 1]),
                        ) { "program name must contain only Unicode scalar values" }
                        Character.toCodePoint(first, name[offset + 1])
                    }
                    Character.isLowSurrogate(first) ->
                        throw IllegalArgumentException(
                            "program name must contain only Unicode scalar values",
                        )
                    else -> first.code
                }
                require(!Character.isISOControl(codePoint)) {
                    "program name must not contain Unicode control characters"
                }
                require(!isBidiControl(codePoint)) {
                    "program name must not contain Unicode bidirectional control characters"
                }
                require(!isUnicodeWhitespace(codePoint)) {
                    "program name must not contain whitespace"
                }
                require(codePoint != '@'.code && codePoint != '#'.code && codePoint != '$'.code) {
                    "program name contains a reserved character"
                }
                require(codePoint != '/'.code) { "program name must not contain `/`" }
                offset += Character.charCount(codePoint)
            }
            require(Normalizer.normalize(name, Normalizer.Form.NFC) == name) {
                "program name must use NFC normalization"
            }
        }

        private fun isBidiControl(codePoint: Int): Boolean =
            codePoint == 0x061C ||
                codePoint == 0x200E ||
                codePoint == 0x200F ||
                codePoint in 0x202A..0x202E ||
                codePoint in 0x2066..0x2069

        private fun isUnicodeWhitespace(codePoint: Int): Boolean =
            codePoint in 0x0009..0x000D ||
                codePoint == 0x0020 ||
                codePoint == 0x0085 ||
                codePoint == 0x00A0 ||
                codePoint == 0x1680 ||
                codePoint in 0x2000..0x200A ||
                codePoint == 0x2028 ||
                codePoint == 0x2029 ||
                codePoint == 0x202F ||
                codePoint == 0x205F ||
                codePoint == 0x3000

        /** Parse an exact `sponsor/program` selector without trimming or rewriting it. */
        @JvmStatic
        fun parse(literal: String): FeeSponsorProgramId {
            require(literal.trim() == literal) { "programId must not contain surrounding whitespace" }
            val slash = literal.indexOf('/')
            require(slash > 0 && slash == literal.lastIndexOf('/') && slash < literal.length - 1) {
                "programId must use sponsor/program"
            }
            return FeeSponsorProgramId(literal.substring(0, slash), literal.substring(slash + 1))
        }
    }
}

/** Required signature-bound choice of fee payer, charge maxima, and executable gas bound. */
sealed class FeePaymentIntent private constructor(
    chargeLimits: List<FeeChargeLimit>,
    @JvmField val gasLimit: Long?,
) {
    private val _chargeLimits = chargeLimits.toList()

    /** Canonically ordered component maxima. */
    val chargeLimits: List<FeeChargeLimit> get() = _chargeLimits.toList()

    init {
        if (gasLimit != null) require(gasLimit > 0) { "gasLimit must be positive when present" }
        var previous = -1
        _chargeLimits.forEach { limit ->
            val current = when (limit.kind) {
                FeeChargeKind.NEXUS -> 0
                FeeChargeKind.PIPELINE_GAS -> 1
            }
            require(current > previous) {
                "chargeLimits must be unique and ordered nexus before pipeline gas"
            }
            previous = current
        }
    }

    /** Authority-paid intent. */
    class Authority(
        chargeLimits: List<FeeChargeLimit>,
        gasLimit: Long? = null,
    ) : FeePaymentIntent(chargeLimits, gasLimit) {
        override fun equals(other: Any?): Boolean =
            other is Authority && chargeLimits == other.chargeLimits && gasLimit == other.gasLimit

        override fun hashCode(): Int = 31 * chargeLimits.hashCode() + (gasLimit?.hashCode() ?: 0)
    }

    /** Exact sponsor-program revision intent. */
    class Sponsor(
        @JvmField val programId: FeeSponsorProgramId,
        @JvmField val programRevision: Long,
        chargeLimits: List<FeeChargeLimit>,
        gasLimit: Long? = null,
    ) : FeePaymentIntent(chargeLimits, gasLimit) {
        init {
            require(programRevision > 0) { "programRevision must be positive" }
        }

        override fun equals(other: Any?): Boolean =
            other is Sponsor &&
                programId == other.programId &&
                programRevision == other.programRevision &&
                chargeLimits == other.chargeLimits &&
                gasLimit == other.gasLimit

        override fun hashCode(): Int {
            var result = programId.hashCode()
            result = 31 * result + programRevision.hashCode()
            result = 31 * result + chargeLimits.hashCode()
            result = 31 * result + (gasLimit?.hashCode() ?: 0)
            return result
        }
    }

    /** Payer, exact sponsor revision and gas bound without quote-populated charge maxima. */
    fun payerSelection(): FeePaymentIntent = when (this) {
        is Authority -> Authority(emptyList(), gasLimit)
        is Sponsor -> Sponsor(programId, programRevision, emptyList(), gasLimit)
    }

    /** True only when a quote preserves the exact payer, revision, and signed gas bound. */
    fun hasSamePayerAndGasBound(other: FeePaymentIntent): Boolean {
        if (gasLimit != other.gasLimit) return false
        return when {
            this is Authority && other is Authority -> true
            this is Sponsor && other is Sponsor ->
                programId == other.programId && programRevision == other.programRevision
            else -> false
        }
    }

    /** Exact Norito JSON object used by Torii request bodies and native bridges. */
    fun toJsonMap(): Map<String, Any?> {
        val value = LinkedHashMap<String, Any?>()
        if (this is Sponsor) {
            value["program_id"] = linkedMapOf("sponsor" to programId.sponsor, "name" to programId.name)
            value["program_revision"] = programRevision
        }
        value["charge_limits"] = chargeLimits.map { limit ->
            linkedMapOf(
                "kind" to linkedMapOf(
                    "kind" to when (limit.kind) {
                        FeeChargeKind.NEXUS -> "nexus"
                        FeeChargeKind.PIPELINE_GAS -> "pipeline_gas"
                    },
                    "value" to null,
                ),
                "asset_definition_id" to limit.assetDefinitionId,
                "max_amount" to limit.maxAmount,
            )
        }
        value["gas_limit"] = gasLimit
        return linkedMapOf(
            "payer" to if (this is Authority) "authority" else "sponsor",
            "value" to value,
        )
    }

    companion object {
        /** Construct an authority-paid intent. */
        @JvmStatic
        @JvmOverloads
        fun authority(chargeLimits: List<FeeChargeLimit>, gasLimit: Long? = null): FeePaymentIntent =
            Authority(chargeLimits, gasLimit)

        /** Construct an exact sponsor-program revision intent. */
        @JvmStatic
        @JvmOverloads
        fun sponsor(
            programId: FeeSponsorProgramId,
            programRevision: Long,
            chargeLimits: List<FeeChargeLimit>,
            gasLimit: Long? = null,
        ): FeePaymentIntent = Sponsor(programId, programRevision, chargeLimits, gasLimit)
    }
}
