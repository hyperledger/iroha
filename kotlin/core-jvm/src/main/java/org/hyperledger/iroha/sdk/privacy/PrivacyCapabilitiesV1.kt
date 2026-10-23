// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import java.util.Collections
import java.util.LinkedHashMap
import org.hyperledger.iroha.sdk.norito.Varint

private val U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
// Mirrors the governed envelope ceiling. SubmitPrivacyProofV1 adds one canonical compact
// field length. Derive its width from the codec, as the Rust frame-bound owner does.
// The 512 bytes cover the closed envelope metadata/framing, not additional proof bytes.
internal const val PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1: Int = 9 * 1024 * 1024 + 256 * 1024 + 512
internal val PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1: Int = PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1 +
    Varint.encode(PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1.toLong()).size
internal const val PRIVACY_BLOCK_MAX_BYTES_V1: Int = 16 * 1024 * 1024 - 64 * 1024
private val CONSENSUS_LIMIT_MAXIMA_V1 = linkedMapOf(
    "max_actions_per_transaction" to 1,
    "max_actions_per_block" to 2,
    "max_proof_bytes_per_action" to 9 * 1024 * 1024,
    "max_action_bytes" to PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1,
    "max_privacy_bytes_per_transaction" to PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1,
    "max_privacy_bytes_per_block" to PRIVACY_BLOCK_MAX_BYTES_V1,
    "max_statement_and_encrypted_output_bytes_per_transaction" to 256 * 1024,
    "max_nullifiers_per_action" to 8,
    "max_commitments_per_action" to 8,
    "retained_root_count" to 2048,
)

internal data class PrivacyProtocolLimitRuleV1(
    val name: String,
    val maximum: Int,
    val permitted: Set<Int>? = null,
)

internal fun privacyProtocolLimitRulesV1(
    protocol: PrivacyProtocolIdV1,
): List<PrivacyProtocolLimitRuleV1> = when (protocol) {
    PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 -> listOf(
        PrivacyProtocolLimitRuleV1("max_anonymity_set_size", 64, setOf(16, 32, 64)),
        PrivacyProtocolLimitRuleV1("max_recipient_count", 8),
    )
    PrivacyProtocolIdV1.VERANGE_TRANSPARENT_RANGE_V1 ->
        listOf(PrivacyProtocolLimitRuleV1("max_aggregation_count", 8))
    PrivacyProtocolIdV1.IROHA_ZK_AMS_V1 -> listOf(
        PrivacyProtocolLimitRuleV1("max_batch_size", 8),
        PrivacyProtocolLimitRuleV1("max_ring_size", 64, setOf(16, 32, 64)),
    )
    PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1 ->
        listOf(PrivacyProtocolLimitRuleV1("max_polynomial_count", 4))
    PrivacyProtocolIdV1.ORCHARD_HALO2_ACTIONS_V1 ->
        listOf(PrivacyProtocolLimitRuleV1("max_action_count", 2))
    PrivacyProtocolIdV1.MONERO_FCMP_PLUS_PLUS_V1 -> listOf(
        PrivacyProtocolLimitRuleV1("max_input_count", 2),
        PrivacyProtocolLimitRuleV1("max_output_count", 4),
    )
    PrivacyProtocolIdV1.IROHA_IVM_PRIVATE_NOTE_STARK_V1,
    PrivacyProtocolIdV1.PQ_MASP_STARK_V1,
    -> listOf(
        PrivacyProtocolLimitRuleV1("max_input_count", 2),
        PrivacyProtocolLimitRuleV1("max_output_count", 2),
    )
    else -> emptyList()
}

/** Immutable exact 32-byte non-zero privacy binding. */
class PrivacyFixed32V1(bytes: ByteArray) {
    private val value = bytes.copyOf()

    init {
        require(value.size == 32) { "privacy binding must contain exactly 32 bytes" }
        require(value.any { it.toInt() != 0 }) { "privacy binding must not be all zero" }
    }

    fun bytes(): ByteArray = value.copyOf()

    override fun equals(other: Any?): Boolean =
        other is PrivacyFixed32V1 && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = value.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Chain-wide first-release admission limits. */
class PrivacyConsensusLimitsV1(
    @JvmField val maxActionsPerTransaction: Int,
    @JvmField val maxActionsPerBlock: Int,
    @JvmField val maxProofBytesPerAction: Int,
    @JvmField val maxActionBytes: Int,
    @JvmField val maxPrivacyBytesPerTransaction: Int,
    @JvmField val maxPrivacyBytesPerBlock: Int,
    @JvmField val maxStatementAndEncryptedOutputBytesPerTransaction: Int,
    @JvmField val maxNullifiersPerAction: Int,
    @JvmField val maxCommitmentsPerAction: Int,
    @JvmField val retainedRootCount: Int,
) {
    init {
        requireValidPrivacyConsensusLimitsV1(this)
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyConsensusLimitsV1 &&
            maxActionsPerTransaction == other.maxActionsPerTransaction &&
            maxActionsPerBlock == other.maxActionsPerBlock &&
            maxProofBytesPerAction == other.maxProofBytesPerAction &&
            maxActionBytes == other.maxActionBytes &&
            maxPrivacyBytesPerTransaction == other.maxPrivacyBytesPerTransaction &&
            maxPrivacyBytesPerBlock == other.maxPrivacyBytesPerBlock &&
            maxStatementAndEncryptedOutputBytesPerTransaction ==
            other.maxStatementAndEncryptedOutputBytesPerTransaction &&
            maxNullifiersPerAction == other.maxNullifiersPerAction &&
            maxCommitmentsPerAction == other.maxCommitmentsPerAction &&
            retainedRootCount == other.retainedRootCount

    override fun hashCode(): Int {
        var result = maxActionsPerTransaction
        result = 31 * result + maxActionsPerBlock
        result = 31 * result + maxProofBytesPerAction
        result = 31 * result + maxActionBytes
        result = 31 * result + maxPrivacyBytesPerTransaction
        result = 31 * result + maxPrivacyBytesPerBlock
        result = 31 * result + maxStatementAndEncryptedOutputBytesPerTransaction
        result = 31 * result + maxNullifiersPerAction
        result = 31 * result + maxCommitmentsPerAction
        return 31 * result + retainedRootCount
    }
}

class PrivacyConsensusPolicyTighteningV1(
    @JvmField val scheduledAtHeight: BigInteger,
    @JvmField val effectiveAtHeight: BigInteger,
    @JvmField val nextLimits: PrivacyConsensusLimitsV1,
) {
    init {
        requireValidPrivacyPolicyScheduleV1(
            scheduledAtHeight,
            effectiveAtHeight,
            "privacy consensus-policy tightening",
        )
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyConsensusPolicyTighteningV1 &&
            scheduledAtHeight == other.scheduledAtHeight &&
            effectiveAtHeight == other.effectiveAtHeight &&
            nextLimits == other.nextLimits

    override fun hashCode(): Int {
        var result = scheduledAtHeight.hashCode()
        result = 31 * result + effectiveAtHeight.hashCode()
        return 31 * result + nextLimits.hashCode()
    }
}

class PrivacyConsensusPolicyV1(
    @JvmField val currentLimits: PrivacyConsensusLimitsV1,
    @JvmField val pendingTightening: PrivacyConsensusPolicyTighteningV1?,
) {
    init {
        pendingTightening?.let { pending ->
            requireStrictConsensusTighteningV1(
                currentLimits,
                pending.nextLimits,
                "privacy consensus-policy tightening",
            )
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyConsensusPolicyV1 &&
            currentLimits == other.currentLimits &&
            pendingTightening == other.pendingTightening

    override fun hashCode(): Int =
        31 * currentLimits.hashCode() + (pendingTightening?.hashCode() ?: 0)
}

/** Closed protocol-tagged verifier ceilings. */
class PrivacyProtocolLimitsV1(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    values: Map<String, Int>?,
) {
    @JvmField
    val values: Map<String, Int>? = values?.let {
        Collections.unmodifiableMap(LinkedHashMap(it))
    }

    init {
        val rules = privacyProtocolLimitRulesV1(protocolId)
        if (rules.isEmpty()) {
            require(this.values == null) {
                "fixed privacy protocol limits must not carry fields"
            }
        } else {
            val actual = requireNotNull(this.values) {
                "privacy protocol limits must carry their closed fields"
            }
            require(actual.keys == rules.mapTo(linkedSetOf()) { it.name }) {
                "privacy protocol limits contain missing or unknown fields"
            }
            for (rule in rules) {
                val value = requireNotNull(actual[rule.name]) {
                    "privacy protocol limit ${rule.name} is missing"
                }
                require(value > 0 && value <= rule.maximum) {
                    "privacy protocol limit ${rule.name} is outside its first-release bound"
                }
                require(rule.permitted == null || value in rule.permitted) {
                    "privacy protocol limit ${rule.name} is outside its closed first-release set"
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyProtocolLimitsV1 &&
            protocolId == other.protocolId &&
            values == other.values

    override fun hashCode(): Int = 31 * protocolId.hashCode() + (values?.hashCode() ?: 0)
}

class PrivacyCompiledProfileV1(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val proofSystemId: PrivacyProofSystemIdV1,
    @JvmField val engineId: PrivacyEngineIdV1,
    @JvmField val parameterId: PrivacyFixed32V1,
    @JvmField val parameterDigest: PrivacyFixed32V1,
    @JvmField val verifierDigest: PrivacyFixed32V1,
    @JvmField val statementSchemaDigest: PrivacyFixed32V1,
    @JvmField val engineManifestDigest: PrivacyFixed32V1,
    @JvmField val protocolLimits: PrivacyProtocolLimitsV1,
) {
    init {
        require(proofSystemId == protocolId.expectedProofSystem) {
            "privacy compiled profile proof system does not match its protocol"
        }
        require(engineId == protocolId.expectedEngine) {
            "privacy compiled profile engine does not match its protocol"
        }
        require(protocolLimits.protocolId == protocolId) {
            "privacy compiled profile limits do not match its protocol"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyCompiledProfileV1 &&
            protocolId == other.protocolId &&
            proofSystemId == other.proofSystemId &&
            engineId == other.engineId &&
            parameterId == other.parameterId &&
            parameterDigest == other.parameterDigest &&
            verifierDigest == other.verifierDigest &&
            statementSchemaDigest == other.statementSchemaDigest &&
            engineManifestDigest == other.engineManifestDigest &&
            protocolLimits == other.protocolLimits

    override fun hashCode(): Int {
        var result = protocolId.hashCode()
        result = 31 * result + proofSystemId.hashCode()
        result = 31 * result + engineId.hashCode()
        result = 31 * result + parameterId.hashCode()
        result = 31 * result + parameterDigest.hashCode()
        result = 31 * result + verifierDigest.hashCode()
        result = 31 * result + statementSchemaDigest.hashCode()
        result = 31 * result + engineManifestDigest.hashCode()
        return 31 * result + protocolLimits.hashCode()
    }
}

enum class PrivacyCompiledProfileUnavailableReasonV1 {
    ENGINE_UNAVAILABLE,
    PROFILE_INITIALIZATION_FAILED,
    STATEMENT_SCHEMA_INVALID,
}

enum class PrivacyCompiledStatementSchemaErrorV1 {
    CONFLICTING_STABLE_TYPE_ID,
    MISSING_TYPE_REFERENCE,
}

sealed class PrivacyCompiledProfileResultV1 {
    class Available(@JvmField val profile: PrivacyCompiledProfileV1) :
        PrivacyCompiledProfileResultV1() {
        override fun equals(other: Any?): Boolean =
            other is Available && profile == other.profile

        override fun hashCode(): Int = profile.hashCode()
    }

    class Unavailable(
        @JvmField val reason: PrivacyCompiledProfileUnavailableReasonV1,
        @JvmField val statementSchemaError: PrivacyCompiledStatementSchemaErrorV1?,
    ) : PrivacyCompiledProfileResultV1() {
        init {
            require(
                (reason == PrivacyCompiledProfileUnavailableReasonV1.STATEMENT_SCHEMA_INVALID) ==
                    (statementSchemaError != null),
            ) {
                "statement-schema detail must be present exactly for statement-schema-invalid"
            }
        }

        override fun equals(other: Any?): Boolean =
            other is Unavailable &&
                reason == other.reason &&
                statementSchemaError == other.statementSchemaError

        override fun hashCode(): Int =
            31 * reason.hashCode() + (statementSchemaError?.hashCode() ?: 0)
    }
}

/** Weakest security model in a complete first-release privacy protocol composition. */
enum class PrivacySecurityModelV1(val canonicalLabel: String) {
    POST_QUANTUM_QROM("pq-qrom"),
    CLASSICAL_ROM("classical-rom"),
    ;

    companion object {
        @JvmStatic
        fun fromCanonicalLabel(label: String): PrivacySecurityModelV1 =
            values().firstOrNull { it.canonicalLabel == label }
                ?: throw IllegalArgumentException("unknown canonical privacy security model")
    }
}

/** Pinned full 32-byte native BLAKE3 commitment to the sole first-release Exact12 catalog. */
class PrivacyExact12CatalogCommitmentV1 internal constructor(bytes: ByteArray) {
    private val value = bytes.copyOf()

    init {
        require(value.contentEquals(CANONICAL_BYTES)) {
            "unknown first-release Exact12 catalog commitment"
        }
    }

    fun bytes(): ByteArray = value.copyOf()

    override fun equals(other: Any?): Boolean =
        other is PrivacyExact12CatalogCommitmentV1 && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    private companion object {
        val CANONICAL_BYTES: ByteArray = byteArrayOf(
            0x5b, 0xcf.toByte(), 0x36, 0x6f, 0xb1.toByte(), 0x8d.toByte(), 0x2e, 0x43,
            0x61, 0x48, 0x6c, 0x01, 0x5d, 0xa5.toByte(), 0xb4.toByte(), 0x1a,
            0x3f, 0xb0.toByte(), 0x0e, 0xdf.toByte(), 0x05, 0x61, 0x10, 0x42,
            0xcc.toByte(), 0xc4.toByte(), 0x52, 0x12, 0x0d, 0x17, 0x6e, 0xb0.toByte(),
        )
    }
}

/** Final independently reviewable security claim for one retained protocol. */
class PrivacySecurityClaimV1 internal constructor(
    @JvmField val catalogCommitment: PrivacyExact12CatalogCommitmentV1,
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val securityModel: PrivacySecurityModelV1,
    @JvmField val targetSecurityBits: Int,
    @JvmField val achievedSecurityBits: Int,
    @JvmField val parameterDigest: PrivacyFixed32V1,
    @JvmField val verifierDigest: PrivacyFixed32V1,
    @JvmField val reductionDigest: PrivacyFixed32V1,
    @JvmField val auditBundleDigest: PrivacyFixed32V1,
) {
    init {
        require(targetSecurityBits == MINIMUM_SECURITY_BITS) {
            "privacy security target must be exactly $MINIMUM_SECURITY_BITS bits"
        }
        require(achievedSecurityBits in targetSecurityBits..U16_MAX) {
            "privacy achieved security must meet the target and fit uint16"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacySecurityClaimV1 &&
            catalogCommitment == other.catalogCommitment &&
            protocolId == other.protocolId &&
            securityModel == other.securityModel &&
            targetSecurityBits == other.targetSecurityBits &&
            achievedSecurityBits == other.achievedSecurityBits &&
            parameterDigest == other.parameterDigest &&
            verifierDigest == other.verifierDigest &&
            reductionDigest == other.reductionDigest &&
            auditBundleDigest == other.auditBundleDigest

    override fun hashCode(): Int {
        var result = catalogCommitment.hashCode()
        result = 31 * result + protocolId.hashCode()
        result = 31 * result + securityModel.hashCode()
        result = 31 * result + targetSecurityBits
        result = 31 * result + achievedSecurityBits
        result = 31 * result + parameterDigest.hashCode()
        result = 31 * result + verifierDigest.hashCode()
        result = 31 * result + reductionDigest.hashCode()
        return 31 * result + auditBundleDigest.hashCode()
    }

    private companion object {
        const val MINIMUM_SECURITY_BITS: Int = 128
        const val U16_MAX: Int = 0xffff
    }
}

enum class PrivacyProtocolLifecycleStateV1 {
    PROPOSED,
    ACTIVE,
    SUSPENDED,
    RETIRED,
}

class PrivacyProtocolLifecycleV1(
    @JvmField val state: PrivacyProtocolLifecycleStateV1,
    @JvmField val proposedAtHeight: BigInteger,
    @JvmField val activatedAtHeight: BigInteger?,
    @JvmField val stateSinceHeight: BigInteger?,
) {
    init {
        requirePositivePrivacyHeightV1(proposedAtHeight, "privacy proposal height")
        when (state) {
            PrivacyProtocolLifecycleStateV1.PROPOSED -> {
                require(activatedAtHeight == null && stateSinceHeight == null) {
                    "proposed privacy lifecycle must not carry activated-at or state-since heights"
                }
            }
            PrivacyProtocolLifecycleStateV1.ACTIVE -> {
                val activated = requireNotNull(activatedAtHeight) {
                    "active privacy lifecycle must carry activated-at height"
                }
                val since = requireNotNull(stateSinceHeight) {
                    "active privacy lifecycle must carry state-since height"
                }
                requirePositivePrivacyHeightV1(activated, "privacy activated-at height")
                requirePositivePrivacyHeightV1(since, "privacy state-since height")
                require(activated >= proposedAtHeight && since >= activated) {
                    "active privacy lifecycle heights are out of order"
                }
            }
            PrivacyProtocolLifecycleStateV1.SUSPENDED -> {
                val activated = requireNotNull(activatedAtHeight) {
                    "suspended privacy lifecycle must carry activated-at height"
                }
                val since = requireNotNull(stateSinceHeight) {
                    "suspended privacy lifecycle must carry state-since height"
                }
                requirePositivePrivacyHeightV1(activated, "privacy activated-at height")
                requirePositivePrivacyHeightV1(since, "privacy state-since height")
                require(activated >= proposedAtHeight && since > activated) {
                    "suspended privacy lifecycle heights are out of order"
                }
            }
            PrivacyProtocolLifecycleStateV1.RETIRED -> {
                val since = requireNotNull(stateSinceHeight) {
                    "retired privacy lifecycle must carry state-since height"
                }
                requirePositivePrivacyHeightV1(since, "privacy state-since height")
                activatedAtHeight?.let { activated ->
                    requirePositivePrivacyHeightV1(activated, "privacy activated-at height")
                    require(activated >= proposedAtHeight && since > activated) {
                        "retired privacy lifecycle heights are out of order"
                    }
                } ?: require(since > proposedAtHeight) {
                    "unactivated retired privacy lifecycle must retire after proposal"
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyProtocolLifecycleV1 &&
            state == other.state &&
            proposedAtHeight == other.proposedAtHeight &&
            activatedAtHeight == other.activatedAtHeight &&
            stateSinceHeight == other.stateSinceHeight

    override fun hashCode(): Int {
        var result = state.hashCode()
        result = 31 * result + proposedAtHeight.hashCode()
        result = 31 * result + (activatedAtHeight?.hashCode() ?: 0)
        return 31 * result + (stateSinceHeight?.hashCode() ?: 0)
    }
}

class PrivacyProtocolLimitsTighteningV1(
    @JvmField val scheduledAtHeight: BigInteger,
    @JvmField val effectiveAtHeight: BigInteger,
    @JvmField val nextLimits: PrivacyProtocolLimitsV1,
) {
    init {
        requireValidPrivacyPolicyScheduleV1(
            scheduledAtHeight,
            effectiveAtHeight,
            "privacy protocol-limit tightening",
        )
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyProtocolLimitsTighteningV1 &&
            scheduledAtHeight == other.scheduledAtHeight &&
            effectiveAtHeight == other.effectiveAtHeight &&
            nextLimits == other.nextLimits

    override fun hashCode(): Int {
        var result = scheduledAtHeight.hashCode()
        result = 31 * result + effectiveAtHeight.hashCode()
        return 31 * result + nextLimits.hashCode()
    }
}

class PrivacyProtocolActivationRecordV1(
    @JvmField val profileBindings: PrivacyCompiledProfileV1,
    @JvmField val lifecycle: PrivacyProtocolLifecycleV1,
    @JvmField val pendingProtocolLimitsTightening: PrivacyProtocolLimitsTighteningV1?,
) {
    init {
        pendingProtocolLimitsTightening?.let { pending ->
            require(pending.nextLimits.protocolId == profileBindings.protocolId) {
                "privacy protocol-limit tightening does not match its activation protocol"
            }
            requireStrictProtocolTighteningV1(
                profileBindings.protocolLimits,
                pending.nextLimits,
                "privacy protocol-limit tightening",
            )
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyProtocolActivationRecordV1 &&
            profileBindings == other.profileBindings &&
            lifecycle == other.lifecycle &&
            pendingProtocolLimitsTightening == other.pendingProtocolLimitsTightening

    override fun hashCode(): Int {
        var result = profileBindings.hashCode()
        result = 31 * result + lifecycle.hashCode()
        return 31 * result + (pendingProtocolLimitsTightening?.hashCode() ?: 0)
    }
}

private fun requireValidPrivacyConsensusLimitsV1(limits: PrivacyConsensusLimitsV1) {
    val values = privacyConsensusLimitValuesV1(limits)
    for ((name, value) in values) {
        require(value > 0) { "privacy consensus limit $name must be non-zero" }
        require(value <= CONSENSUS_LIMIT_MAXIMA_V1.getValue(name)) {
            "privacy consensus limit $name exceeds its first-release hard maximum"
        }
    }
    require(limits.maxActionsPerTransaction <= limits.maxActionsPerBlock) {
        "privacy actions-per-transaction limit exceeds actions-per-block limit"
    }
    require(limits.maxProofBytesPerAction <= limits.maxActionBytes) {
        "privacy proof-bytes-per-action limit exceeds action-bytes limit"
    }
    require(limits.maxActionBytes <= limits.maxPrivacyBytesPerTransaction) {
        "privacy action-bytes limit exceeds privacy-bytes-per-transaction limit"
    }
    require(limits.maxPrivacyBytesPerTransaction <= limits.maxPrivacyBytesPerBlock) {
        "privacy bytes-per-transaction limit exceeds privacy-bytes-per-block limit"
    }
    require(
        limits.maxStatementAndEncryptedOutputBytesPerTransaction <= limits.maxActionBytes,
    ) {
        "privacy statement-and-output limit exceeds action-bytes limit"
    }
}

private fun privacyConsensusLimitValuesV1(limits: PrivacyConsensusLimitsV1): Map<String, Int> =
    linkedMapOf(
        "max_actions_per_transaction" to limits.maxActionsPerTransaction,
        "max_actions_per_block" to limits.maxActionsPerBlock,
        "max_proof_bytes_per_action" to limits.maxProofBytesPerAction,
        "max_action_bytes" to limits.maxActionBytes,
        "max_privacy_bytes_per_transaction" to limits.maxPrivacyBytesPerTransaction,
        "max_privacy_bytes_per_block" to limits.maxPrivacyBytesPerBlock,
        "max_statement_and_encrypted_output_bytes_per_transaction" to
            limits.maxStatementAndEncryptedOutputBytesPerTransaction,
        "max_nullifiers_per_action" to limits.maxNullifiersPerAction,
        "max_commitments_per_action" to limits.maxCommitmentsPerAction,
        "retained_root_count" to limits.retainedRootCount,
    )

private fun requireStrictConsensusTighteningV1(
    current: PrivacyConsensusLimitsV1,
    next: PrivacyConsensusLimitsV1,
    subject: String,
) {
    val currentValues = privacyConsensusLimitValuesV1(current)
    val nextValues = privacyConsensusLimitValuesV1(next)
    require(currentValues.keys == nextValues.keys) { "$subject fields do not match" }
    var changed = false
    for ((name, currentValue) in currentValues) {
        val nextValue = nextValues.getValue(name)
        require(nextValue <= currentValue) { "$subject cannot increase $name" }
        changed = changed || nextValue != currentValue
    }
    require(changed) { "$subject must be a strict tightening" }
}

private fun requirePrivacyHeightV1(height: BigInteger, subject: String) {
    require(height.signum() >= 0 && height <= U64_MAX) {
        "$subject must be within the uint64 range"
    }
}

private fun requirePositivePrivacyHeightV1(height: BigInteger, subject: String) {
    requirePrivacyHeightV1(height, subject)
    require(height.signum() > 0) { "$subject must be non-zero" }
}

internal fun requireValidPrivacyPolicyScheduleV1(
    scheduledAtHeight: BigInteger,
    effectiveAtHeight: BigInteger,
    subject: String,
) {
    requirePositivePrivacyHeightV1(scheduledAtHeight, "$subject scheduled-at height")
    requirePositivePrivacyHeightV1(effectiveAtHeight, "$subject effective-at height")
    require(effectiveAtHeight > scheduledAtHeight) {
        "$subject effective-at height must be after scheduled-at height"
    }
}

internal fun requireProtocolLimitsAtMostV1(
    actual: PrivacyProtocolLimitsV1,
    ceiling: PrivacyProtocolLimitsV1,
    subject: String,
) {
    require(actual.protocolId == ceiling.protocolId) {
        "$subject protocol tag does not match its ceiling"
    }
    require((actual.values == null) == (ceiling.values == null)) {
        "$subject shape does not match its ceiling"
    }
    val actualValues = actual.values ?: return
    val ceilingValues = requireNotNull(ceiling.values)
    for ((name, value) in actualValues) {
        require(value <= ceilingValues.getValue(name)) { "$subject exceeds $name ceiling" }
    }
}

private fun requireStrictProtocolTighteningV1(
    current: PrivacyProtocolLimitsV1,
    next: PrivacyProtocolLimitsV1,
    subject: String,
) {
    requireProtocolLimitsAtMostV1(next, current, subject)
    require(next != current) { "$subject must be strict" }
}

internal fun requirePrivacyProfileBindingsEqualV1(
    actual: PrivacyCompiledProfileV1,
    expected: PrivacyCompiledProfileV1,
    subject: String,
) {
    require(
        actual.protocolId == expected.protocolId &&
            actual.proofSystemId == expected.proofSystemId &&
            actual.engineId == expected.engineId &&
            actual.parameterId == expected.parameterId &&
            actual.parameterDigest == expected.parameterDigest &&
            actual.verifierDigest == expected.verifierDigest &&
            actual.statementSchemaDigest == expected.statementSchemaDigest &&
            actual.engineManifestDigest == expected.engineManifestDigest,
    ) { "$subject bindings do not match the compiled profile" }
}

internal fun requirePrivacyConsensusPolicyAtHeightV1(
    policy: PrivacyConsensusPolicyV1,
    committedHeight: BigInteger,
) {
    policy.pendingTightening?.let { pending ->
        require(pending.scheduledAtHeight <= committedHeight) {
            "privacy consensus-policy tightening was scheduled after the committed height"
        }
        require(pending.effectiveAtHeight > committedHeight) {
            "privacy consensus-policy tightening is already due at the committed height"
        }
    }
}

internal fun expectedSecurityModelV1(protocolId: PrivacyProtocolIdV1): PrivacySecurityModelV1 =
    when (protocolId) {
        PrivacyProtocolIdV1.ZK_ACE_PQ_AUTHORIZATION_V1,
        PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1,
        PrivacyProtocolIdV1.IROHA_BOOTLE_LANTERN_ANONCRED_V1,
        PrivacyProtocolIdV1.IROHA_IVM_PRIVATE_NOTE_STARK_V1,
        PrivacyProtocolIdV1.PQ_MASP_STARK_V1,
        -> PrivacySecurityModelV1.POST_QUANTUM_QROM
        PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1,
        PrivacyProtocolIdV1.VERANGE_TRANSPARENT_RANGE_V1,
        PrivacyProtocolIdV1.IROHA_ZK_AMS_V1,
        PrivacyProtocolIdV1.VEGA_EXISTING_CREDENTIAL_ZK_V1,
        PrivacyProtocolIdV1.IROHA_ZK_X509_STARK_P256_V1,
        PrivacyProtocolIdV1.ORCHARD_HALO2_ACTIONS_V1,
        PrivacyProtocolIdV1.MONERO_FCMP_PLUS_PLUS_V1,
        -> PrivacySecurityModelV1.CLASSICAL_ROM
    }
