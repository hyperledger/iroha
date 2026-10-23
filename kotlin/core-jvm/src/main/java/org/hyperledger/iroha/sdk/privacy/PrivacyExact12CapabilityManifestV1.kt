// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.NetworkId
import java.util.Collections
import java.util.LinkedHashMap
import org.hyperledger.iroha.sdk.client.JsonParser

/** Closed public operation schema carried by one Exact12 capability row. */
enum class PrivacyOperationSchemaV1(val canonicalLabel: String) {
    ZK_ACE_AUTHORIZATION_ACTION_V1("zk_ace_authorization_action_v1"),
    ANONYMOUS_PGC_PAYMENT_ACTION_V1("anonymous_pgc_payment_action_v1"),
    VERANGE_RANGE_PROOF_V1("verange_range_proof_v1"),
    ZK_AMS_ADMISSION_AND_PROVISIONING_V1("zk_ams_admission_and_provisioning_v1"),
    VEGA_CREDENTIAL_PRESENTATION_V1("vega_credential_presentation_v1"),
    ZK_X509_IDENTITY_PRESENTATION_V1("zk_x509_identity_presentation_v1"),
    JINDO_POLYNOMIAL_EVALUATION_V1("jindo_polynomial_evaluation_v1"),
    BOOTLE_LANTERN_CREDENTIAL_PRESENTATION_V1(
        "bootle_lantern_credential_presentation_v1",
    ),
    ORCHARD_NOTE_ACTION_V1("orchard_note_action_v1"),
    FCMP_MEMBERSHIP_PAYMENT_V1("fcmp_membership_payment_v1"),
    IVM_PRIVATE_NOTE_ACTION_V1("ivm_private_note_action_v1"),
    PQ_MASP_NOTE_ACTION_V1("pq_masp_note_action_v1"),
    ;

    companion object {
        @JvmStatic
        fun fromCanonicalLabel(label: String): PrivacyOperationSchemaV1 =
            values().firstOrNull { it.canonicalLabel == label }
                ?: throw IllegalArgumentException("unknown Exact12 operation schema")
    }
}

/** Closed execution classification carried by one Exact12 capability row. */
enum class PrivacyExecutionModeV1(val canonicalLabel: String) {
    AUTHORIZATION_ACTION("authorization_action"),
    PAYMENT_ACTION("payment_action"),
    COMPONENT("component"),
    ADMISSION_ACTION("admission_action"),
    PRESENTATION_ACTION("presentation_action"),
    NOTE_ACTION("note_action"),
    ;

    companion object {
        @JvmStatic
        fun fromCanonicalLabel(label: String): PrivacyExecutionModeV1 =
            values().firstOrNull { it.canonicalLabel == label }
                ?: throw IllegalArgumentException("unknown Exact12 execution mode")
    }
}

/** Evidence-derived reason that one exact protocol is not production-qualified. */
sealed class PrivacyCapabilityUnavailableReasonV1 {
    class CompiledProfile(
        @JvmField val failure: PrivacyCompiledProfileResultV1.Unavailable,
    ) : PrivacyCapabilityUnavailableReasonV1() {
        override fun equals(other: Any?): Boolean =
            other is CompiledProfile && failure == other.failure

        override fun hashCode(): Int = failure.hashCode()
    }

    object NotRegistered : PrivacyCapabilityUnavailableReasonV1()

    object Proposed : PrivacyCapabilityUnavailableReasonV1()

    object Suspended : PrivacyCapabilityUnavailableReasonV1()

    object Retired : PrivacyCapabilityUnavailableReasonV1()

    object MissingProductionQualification : PrivacyCapabilityUnavailableReasonV1()

    object InvalidProductionQualification : PrivacyCapabilityUnavailableReasonV1()
}

/** Exact release tuple for one retained protocol. */
class PrivacyReleaseProtocolBindingV1 internal constructor(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val proofSystemId: PrivacyProofSystemIdV1,
    @JvmField val engineId: PrivacyEngineIdV1,
    @JvmField val parameterId: PrivacyFixed32V1,
    @JvmField val parameterDigest: PrivacyFixed32V1,
    @JvmField val verifierDigest: PrivacyFixed32V1,
    @JvmField val statementSchemaDigest: PrivacyFixed32V1,
    @JvmField val engineManifestDigest: PrivacyFixed32V1,
    @JvmField val securityClaim: PrivacySecurityClaimV1,
    @JvmField val securityClaimDigest: PrivacyFixed32V1,
)

/** One immutable protocol activation height from the qualified deployment. */
class PrivacyDeploymentActivationV1 internal constructor(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val activationHeight: BigInteger,
)

/** Full portable release evidence retained from the native-validated archive. */
class PrivacyExact12ReleaseManifestV1 internal constructor(
    @JvmField val version: Int,
    @JvmField val catalogId: String,
    @JvmField val catalogCommitment: PrivacyExact12CatalogCommitmentV1,
    @JvmField val source: Map<String, Any?>,
    @JvmField val abiVersion: Int,
    @JvmField val abiHash: PrivacyFixed32V1,
    @JvmField val syscallListDigest: PrivacyFixed32V1,
    @JvmField val executables: List<Any?>,
    protocols: List<PrivacyReleaseProtocolBindingV1>,
    @JvmField val stageReceipts: List<Any?>,
    @JvmField val proofArtifacts: List<Any?>,
    @JvmField val sdkPackages: List<Any?>,
    @JvmField val hardwareResults: List<Any?>,
    @JvmField val releaseArtifactSetDigest: PrivacyFixed32V1,
    @JvmField val audits: List<Any?>,
    @JvmField val auditBundleDigest: PrivacyFixed32V1,
    @JvmField val releaseSignatures: List<Any?>,
    @JvmField val manifestDigest: PrivacyFixed32V1,
) {
    @JvmField
    val protocols: List<PrivacyReleaseProtocolBindingV1> =
        Collections.unmodifiableList(protocols.toList())
}

/** Full network-bound deployment evidence retained from the native-validated archive. */
class PrivacyExact12DeploymentQualificationV1 internal constructor(
    @JvmField val version: Int,
    @JvmField val chainId: Any?,
    @JvmField val networkId: NetworkId,
    @JvmField val genesisHash: PrivacyFixed32V1,
    @JvmField val releaseManifestDigest: PrivacyFixed32V1,
    @JvmField val activationTransactionDigest: PrivacyFixed32V1,
    activations: List<PrivacyDeploymentActivationV1>,
    @JvmField val validatorRosterDigest: PrivacyFixed32V1,
    @JvmField val endpointVersion: String,
    @JvmField val convergenceHeight: BigInteger,
    @JvmField val convergedStateDigest: PrivacyFixed32V1,
    @JvmField val validatorCanaries: List<Any?>,
    @JvmField val validatorSignatures: List<Any?>,
    @JvmField val qualificationDigest: PrivacyFixed32V1,
) {
    @JvmField
    val activations: List<PrivacyDeploymentActivationV1> =
        Collections.unmodifiableList(activations.toList())

    init {
        require(networkId.bytes().contentEquals(genesisHash.bytes())) {
            "Exact12 deployment network identity must equal its genesis hash"
        }
    }
}

/** Singleton release plus target-network evidence from committed state. */
class PrivacyExact12QualificationRecordV1 internal constructor(
    @JvmField val releaseManifest: PrivacyExact12ReleaseManifestV1,
    @JvmField val deploymentQualification: PrivacyExact12DeploymentQualificationV1,
)

/** Evidence-derived readiness projected from compiled and committed governance state. */
sealed class PrivacyCapabilityReadinessV1 {
    object ProductionQualified : PrivacyCapabilityReadinessV1()

    class Unavailable(
        @JvmField val reason: PrivacyCapabilityUnavailableReasonV1,
    ) : PrivacyCapabilityReadinessV1() {
        override fun equals(other: Any?): Boolean =
            other is Unavailable && reason == other.reason

        override fun hashCode(): Int = reason.hashCode()
    }
}

/** One canonical committed Exact12 capability row. */
class PrivacyExact12CapabilityRowV1 internal constructor(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val operationSchema: PrivacyOperationSchemaV1,
    @JvmField val executionMode: PrivacyExecutionModeV1,
    @JvmField val privacyFeatureMask: Int,
    @JvmField val compiledProfile: PrivacyCompiledProfileResultV1,
    @JvmField val readiness: PrivacyCapabilityReadinessV1,
    @JvmField val activation: PrivacyProtocolActivationRecordV1?,
    /** True only when native Rust compared the complete committed tuple with this binary. */
    @JvmField val localCompiledTupleMatches: Boolean,
    qualification: PrivacyExact12QualificationRecordV1?,
    committedHeight: BigInteger,
) {
    init {
        require(operationSchema == expectedOperationSchema(protocolId)) {
            "Exact12 operation schema does not match its protocol"
        }
        require(executionMode == expectedExecutionMode(protocolId)) {
            "Exact12 execution mode does not match its protocol"
        }
        require(privacyFeatureMask == expectedFeatureMask(protocolId)) {
            "Exact12 privacy feature mask does not match its protocol"
        }
        val available = compiledProfile as? PrivacyCompiledProfileResultV1.Available
        require(available == null || available.profile.protocolId == protocolId) {
            "Exact12 compiled profile does not match its protocol"
        }
        require(activation == null || available != null) {
            "Exact12 unavailable compiled profile cannot carry an activation"
        }
        activation?.let { governed ->
            val compiled = requireNotNull(available).profile
            require(governed.profileBindings.protocolId == protocolId) {
                "Exact12 activation does not match its protocol"
            }
            requirePrivacyProfileBindingsEqualV1(
                governed.profileBindings,
                compiled,
                "Exact12 capability activation",
            )
            requireProtocolLimitsAtMostV1(
                governed.profileBindings.protocolLimits,
                compiled.protocolLimits,
                "Exact12 capability activation limits",
            )
        }
        require(
            readiness == projectedReadinessV1(
                compiledProfile,
                activation,
                qualification,
                committedHeight,
            ),
        ) {
            "Exact12 readiness was not derived from compiled and committed governance state"
        }
    }

    /** Network availability is exactly committed production qualification. */
    fun isNetworkAvailable(): Boolean = readiness is PrivacyCapabilityReadinessV1.ProductionQualified

    override fun equals(other: Any?): Boolean =
        other is PrivacyExact12CapabilityRowV1 &&
            protocolId == other.protocolId &&
            operationSchema == other.operationSchema &&
            executionMode == other.executionMode &&
            privacyFeatureMask == other.privacyFeatureMask &&
            compiledProfile == other.compiledProfile &&
            readiness == other.readiness &&
            activation == other.activation &&
            localCompiledTupleMatches == other.localCompiledTupleMatches

    override fun hashCode(): Int {
        var result = protocolId.hashCode()
        result = 31 * result + operationSchema.hashCode()
        result = 31 * result + executionMode.hashCode()
        result = 31 * result + privacyFeatureMask
        result = 31 * result + compiledProfile.hashCode()
        result = 31 * result + readiness.hashCode()
        result = 31 * result + (activation?.hashCode() ?: 0)
        return 31 * result + localCompiledTupleMatches.hashCode()
    }
}

/**
 * Native-validated canonical Torii Exact12 capability manifest.
 *
 * Public decoding provides inspection only. Admission also requires the private origin binding
 * issued by the configured Torii transport after an authenticated response for its exact network.
 */
class PrivacyExact12CapabilityManifestV1 private constructor(
    @JvmField val version: Int,
    @JvmField val committedHeight: BigInteger,
    @JvmField val consensusPolicy: PrivacyConsensusPolicyV1,
    @JvmField val qualification: PrivacyExact12QualificationRecordV1?,
    protocols: List<PrivacyExact12CapabilityRowV1>,
    @JvmField val manifestDigest: PrivacyFixed32V1,
    canonicalArchive: ByteArray,
    private val authenticatedNetworkId: NetworkId? = null,
) {
    @JvmField
    val protocols: List<PrivacyExact12CapabilityRowV1>
    private val archive = canonicalArchive.copyOf()

    init {
        require(version == VERSION) { "Exact12 capability manifest version must be $VERSION" }
        require(committedHeight.signum() >= 0 && committedHeight.bitLength() <= 64) {
            "Exact12 committed height must fit u64"
        }
        requirePrivacyConsensusPolicyAtHeightV1(consensusPolicy, committedHeight)
        val expected = PrivacyProtocolIdV1.values()
        require(protocols.size == expected.size) {
            "Exact12 capability manifest must contain exactly ${expected.size} rows"
        }
        protocols.forEachIndexed { index, row ->
            require(row.protocolId == expected[index]) {
                "Exact12 capability row $index is out of canonical order"
            }
            require(
                row.readiness == projectedReadinessV1(
                    row.compiledProfile,
                    row.activation,
                    qualification,
                    committedHeight,
                ),
            ) {
                "Exact12 readiness differs from registered release and deployment evidence"
            }
        }
        require(archive.isNotEmpty() && archive.size <= MAX_ARCHIVE_BYTES) {
            "Exact12 canonical archive length is outside its bound"
        }
        this.protocols = Collections.unmodifiableList(protocols.toList())
    }

    /** Return a defensive copy of the exact Torii Norito response bytes. */
    fun canonicalBytes(): ByteArray = archive.copyOf()

    /** Return the canonical row for [protocolId]. */
    fun rowFor(protocolId: PrivacyProtocolIdV1): PrivacyExact12CapabilityRowV1 =
        protocols[protocolId.ordinal].also {
            check(it.protocolId == protocolId) { "Exact12 protocol registry order drifted" }
        }

    internal fun requireAuthenticatedNetwork(): NetworkId =
        requireNotNull(authenticatedNetworkId) {
            "Exact12 admission requires an authenticated Torii response; decoded archives are inspection-only"
        }

    override fun equals(other: Any?): Boolean =
        other is PrivacyExact12CapabilityManifestV1 && archive.contentEquals(other.archive)

    override fun hashCode(): Int = archive.contentHashCode()

    companion object {
        const val VERSION: Int = 1
        const val MAX_ARCHIVE_BYTES: Int = 256 * 1024

        @JvmSynthetic
        internal fun inspection(
            version: Int,
            committedHeight: BigInteger,
            consensusPolicy: PrivacyConsensusPolicyV1,
            qualification: PrivacyExact12QualificationRecordV1?,
            protocols: List<PrivacyExact12CapabilityRowV1>,
            manifestDigest: PrivacyFixed32V1,
            canonicalArchive: ByteArray,
        ): PrivacyExact12CapabilityManifestV1 = PrivacyExact12CapabilityManifestV1(
            version, committedHeight, consensusPolicy, qualification, protocols,
            manifestDigest, canonicalArchive,
        )

        /** Only the SDK's authenticated Torii transport may issue this origin binding. */
        @JvmSynthetic
        internal fun fromAuthenticatedTorii(
            archive: ByteArray,
            expectedNetworkId: NetworkId,
        ): PrivacyExact12CapabilityManifestV1 {
            val decoded = PrivacyNativeBridge.requireExact12CapabilityManifest(
                archive, expectedNetworkId,
            )
            require(decoded.qualification?.deploymentQualification?.networkId.let {
                it == null || it == expectedNetworkId
            }) { "Exact12 deployment qualification belongs to a different network" }
            return PrivacyExact12CapabilityManifestV1(
                decoded.version, decoded.committedHeight, decoded.consensusPolicy,
                decoded.qualification, decoded.protocols, decoded.manifestDigest,
                decoded.archive, expectedNetworkId,
            )
        }
    }
}

/** Opaque admission token issued only after committed/native tuple agreement. */
class PrivacyExact12CapabilityTupleAdmissionV1 private constructor(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    @JvmField val committedHeight: BigInteger,
    @JvmField val manifestDigest: PrivacyFixed32V1,
    @JvmField val operationSchema: PrivacyOperationSchemaV1,
    canonicalManifestArchive: ByteArray,
    private val expectedNetworkId: NetworkId,
    private val seal: Any,
) {
    private val manifestArchive = canonicalManifestArchive.copyOf()

    internal fun requireNetwork(networkId: NetworkId) {
        require(expectedNetworkId == networkId) {
            "Exact12 capability admission belongs to a different transaction network"
        }
    }

    companion object {
        private val SEAL = Any()

        internal fun issue(
            manifest: PrivacyExact12CapabilityManifestV1,
            row: PrivacyExact12CapabilityRowV1,
        ): PrivacyExact12CapabilityTupleAdmissionV1 {
            val archive = manifest.canonicalBytes()
            val networkId = manifest.requireAuthenticatedNetwork()
            PrivacyNativeBridge.requireExact12CapabilityTuple(archive, row.protocolId, networkId)
            return PrivacyExact12CapabilityTupleAdmissionV1(
                row.protocolId,
                manifest.committedHeight,
                manifest.manifestDigest,
                row.operationSchema,
                archive,
                networkId,
                SEAL,
            )
        }

        internal fun requireAuthentic(
            admission: PrivacyExact12CapabilityTupleAdmissionV1,
            protocolId: PrivacyProtocolIdV1,
        ) {
            require(admission.seal === SEAL && admission.protocolId == protocolId) {
                "Exact12 capability admission token is absent, invalid, or protocol-substituted"
            }
            PrivacyNativeBridge.requireExact12CapabilityTuple(
                admission.manifestArchive,
                protocolId,
                admission.expectedNetworkId,
            )
        }

        internal fun requireSubmitProofConstruction(
            admission: PrivacyExact12CapabilityTupleAdmissionV1,
            protocolId: PrivacyProtocolIdV1,
            instructionArchive: ByteArray,
        ) {
            requireAuthentic(admission, protocolId)
            PrivacyNativeBridge.requireExact12SubmitProofConstruction(
                admission.manifestArchive,
                protocolId,
                instructionArchive,
                admission.expectedNetworkId,
            )
        }
    }
}

/** Fail-closed bridge from a committed manifest to retained privacy construction. */
object PrivacyExact12CapabilityAdmissionV1 {
    /**
     * Require committed availability and an exact native local compiled-profile tuple match.
     *
     * A local catalog is used only for equality. It never creates network availability.
     */
    @JvmStatic
    fun requireExact12CapabilityTupleV1(
        manifest: PrivacyExact12CapabilityManifestV1,
        protocolId: PrivacyProtocolIdV1,
    ): PrivacyExact12CapabilityTupleAdmissionV1 {
        manifest.requireAuthenticatedNetwork()
        val row = manifest.rowFor(protocolId)
        require(row.isNetworkAvailable()) {
            "Exact12 protocol ${protocolId.canonicalLabel} is not active and ready in committed state"
        }
        require(row.localCompiledTupleMatches) {
            "Exact12 committed profile tuple differs from compiledProfileCatalogTypedV1"
        }
        return PrivacyExact12CapabilityTupleAdmissionV1.issue(manifest, row)
    }

    /** Verify a token immediately before constructing a retained privacy action. */
    @JvmStatic
    fun requireForConstruction(
        admission: PrivacyExact12CapabilityTupleAdmissionV1,
        protocolId: PrivacyProtocolIdV1,
    ) {
        PrivacyExact12CapabilityTupleAdmissionV1.requireAuthentic(admission, protocolId)
    }

    /** Bind one canonical retained submit-proof instruction to its admitted committed tuple. */
    @JvmStatic
    fun requireForConstruction(
        admission: PrivacyExact12CapabilityTupleAdmissionV1,
        protocolId: PrivacyProtocolIdV1,
        instructionArchive: ByteArray,
    ) {
        PrivacyExact12CapabilityTupleAdmissionV1.requireSubmitProofConstruction(
            admission,
            protocolId,
            instructionArchive,
        )
    }
}

internal object PrivacyExact12CapabilityManifestInspectionV1 {
    private const val MAX_INSPECTION_BYTES = 1024 * 1024
    private const val CATALOG_COMMITMENT_BYTES = 32
    private val U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

    fun parse(
        canonicalArchive: ByteArray,
        nativeInspection: ByteArray,
    ): PrivacyExact12CapabilityManifestV1 {
        require(nativeInspection.isNotEmpty() && nativeInspection.size <= MAX_INSPECTION_BYTES) {
            "native Exact12 capability inspection length is outside its bound"
        }
        val decoded = try {
            JsonParser.parse(String(nativeInspection, StandardCharsets.UTF_8))
        } catch (error: RuntimeException) {
            throw IllegalArgumentException("native Exact12 capability inspection is malformed", error)
        }
        val wrapper = exactObject(
            decoded,
            setOf("manifest", "local_compiled_tuple_matches"),
            "Exact12 native inspection",
        )
        val matches = list(
            wrapper["local_compiled_tuple_matches"],
            "Exact12 native inspection.local_compiled_tuple_matches",
        )
        val expected = PrivacyProtocolIdV1.values()
        require(matches.size == expected.size) {
            "native Exact12 tuple comparison must contain exactly ${expected.size} rows"
        }
        val manifest = exactObject(
            wrapper["manifest"],
            setOf(
                "version",
                "committed_height",
                "consensus_policy",
                "qualification",
                "protocols",
                "manifest_digest",
            ),
            "Exact12 capability manifest",
        )
        val version = uint32(manifest["version"], "Exact12 capability manifest.version")
        require(version == PrivacyExact12CapabilityManifestV1.VERSION) {
            "Exact12 capability manifest version must be 1"
        }
        val committedHeight = uint64(
            manifest["committed_height"],
            "Exact12 capability manifest.committed_height",
        )
        val consensusPolicy = parseConsensusPolicy(
            manifest["consensus_policy"],
            committedHeight,
            "Exact12 capability manifest.consensus_policy",
        )
        val qualification = manifest["qualification"]?.let {
            parseQualification(it, "Exact12 capability manifest.qualification")
        }
        val rawRows = list(manifest["protocols"], "Exact12 capability manifest.protocols")
        require(rawRows.size == expected.size) {
            "Exact12 capability manifest must contain exactly ${expected.size} rows"
        }
        val rows = rawRows.mapIndexed { index, value ->
            val tupleMatch = matches[index] as? Boolean
                ?: throw IllegalArgumentException(
                    "Exact12 native tuple match $index must be boolean",
                )
            parseRow(
                value,
                expected[index],
                tupleMatch,
                committedHeight,
                qualification,
                "Exact12 capability manifest.protocols[$index]",
            )
        }
        val manifestDigest = fixed32(
            manifest["manifest_digest"],
            "Exact12 capability manifest.manifest_digest",
        )
        return PrivacyExact12CapabilityManifestV1.inspection(
            version,
            committedHeight,
            consensusPolicy,
            qualification,
            rows,
            manifestDigest,
            canonicalArchive,
        )
    }

    private fun parseRow(
        value: Any?,
        expected: PrivacyProtocolIdV1,
        tupleMatch: Boolean,
        committedHeight: BigInteger,
        qualification: PrivacyExact12QualificationRecordV1?,
        path: String,
    ): PrivacyExact12CapabilityRowV1 {
        val row = exactObject(
            value,
            setOf(
                "protocol_id",
                "operation_schema",
                "execution_mode",
                "privacy_feature_mask",
                "compiled_profile",
                "readiness",
                "activation",
            ),
            path,
        )
        val protocol = protocolTag(row["protocol_id"], "$path.protocol_id")
        require(protocol == expected) { "$path is out of canonical protocol order" }
        val operation = PrivacyOperationSchemaV1.fromCanonicalLabel(
            taggedUnit(
                row["operation_schema"],
                "operation_schema",
                "value",
                "$path.operation_schema",
            ),
        )
        val execution = PrivacyExecutionModeV1.fromCanonicalLabel(
            taggedUnit(
                row["execution_mode"],
                "execution_mode",
                "value",
                "$path.execution_mode",
            ),
        )
        val featureMask = uint32(row["privacy_feature_mask"], "$path.privacy_feature_mask")
        require(featureMask <= 0xff) { "$path.privacy_feature_mask must fit uint8" }
        val compiled = parseCompiledProfile(row["compiled_profile"], protocol, "$path.compiled_profile")
        val readiness = parseReadiness(row["readiness"], "$path.readiness")
        val activation = row["activation"]?.let {
            parseActivation(it, protocol, compiled, committedHeight, "$path.activation")
        }
        return PrivacyExact12CapabilityRowV1(
            protocol,
            operation,
            execution,
            featureMask,
            compiled,
            readiness,
            activation,
            tupleMatch,
            qualification,
            committedHeight,
        )
    }

    private fun parseCompiledProfile(
        value: Any?,
        protocol: PrivacyProtocolIdV1,
        path: String,
    ): PrivacyCompiledProfileResultV1 {
        val result = exactObject(value, setOf("status", "value"), path)
        return when (text(result["status"], "$path.status")) {
            "available" -> PrivacyCompiledProfileResultV1.Available(
                parseProfile(result["value"], protocol, "$path.value"),
            )
            "unavailable" -> parseUnavailable(result["value"], "$path.value")
            else -> throw IllegalArgumentException("$path.status is not a closed V1 status")
        }
    }

    private fun parseProfile(
        value: Any?,
        protocol: PrivacyProtocolIdV1,
        path: String,
    ): PrivacyCompiledProfileV1 {
        val profile = exactObject(value, PROFILE_KEYS, path)
        return parseProfileBindings(
            profile,
            protocol,
            parseProtocolLimits(profile["protocol_limits"], protocol, "$path.protocol_limits"),
            path,
        )
    }

    private fun parseProfileBindings(
        profile: Map<String, Any?>,
        protocol: PrivacyProtocolIdV1,
        protocolLimits: PrivacyProtocolLimitsV1,
        path: String,
    ): PrivacyCompiledProfileV1 {
        require(protocolTag(profile["protocol_id"], "$path.protocol_id") == protocol) {
            "$path protocol binding differs from its row"
        }
        val proof = PrivacyProofSystemIdV1.fromCanonicalLabel(
            taggedUnit(profile["proof_system_id"], "proof_system", "value", "$path.proof_system_id"),
        )
        val engine = PrivacyEngineIdV1.fromCanonicalLabel(
            taggedUnit(profile["engine_id"], "engine", "value", "$path.engine_id"),
        )
        return PrivacyCompiledProfileV1(
            protocol,
            proof,
            engine,
            fixed32(profile["parameter_id"], "$path.parameter_id"),
            fixed32(profile["parameter_digest"], "$path.parameter_digest"),
            fixed32(profile["verifier_digest"], "$path.verifier_digest"),
            fixed32(profile["statement_schema_digest"], "$path.statement_schema_digest"),
            fixed32(profile["engine_manifest_digest"], "$path.engine_manifest_digest"),
            protocolLimits,
        )
    }

    private fun parseProtocolLimits(
        value: Any?,
        protocol: PrivacyProtocolIdV1,
        path: String,
    ): PrivacyProtocolLimitsV1 {
        val tagged = exactObject(value, setOf("protocol", "limits"), path)
        val encodedProtocol = PrivacyProtocolIdV1.fromCanonicalLabel(
            text(tagged["protocol"], "$path.protocol"),
        )
        require(encodedProtocol == protocol) { "$path protocol tag differs from its row" }
        val rules = privacyProtocolLimitRulesV1(protocol)
        if (rules.isEmpty()) {
            require(tagged["limits"] == null) { "$path fixed limits must be null" }
            return PrivacyProtocolLimitsV1(protocol, null)
        }
        val limits = exactObject(tagged["limits"], rules.map { it.name }.toSet(), "$path.limits")
        val values = LinkedHashMap<String, Int>()
        for (rule in rules) {
            values[rule.name] = uint32(limits[rule.name], "$path.limits.${rule.name}")
        }
        return PrivacyProtocolLimitsV1(protocol, values)
    }

    private fun parseUnavailable(
        value: Any?,
        path: String,
    ): PrivacyCompiledProfileResultV1.Unavailable {
        val unavailable = exactObject(value, setOf("reason", "detail"), path)
        return when (text(unavailable["reason"], "$path.reason")) {
            "engine-unavailable" -> {
                require(unavailable["detail"] == null) { "$path.detail must be null" }
                PrivacyCompiledProfileResultV1.Unavailable(
                    PrivacyCompiledProfileUnavailableReasonV1.ENGINE_UNAVAILABLE,
                    null,
                )
            }
            "profile-initialization-failed" -> {
                require(unavailable["detail"] == null) { "$path.detail must be null" }
                PrivacyCompiledProfileResultV1.Unavailable(
                    PrivacyCompiledProfileUnavailableReasonV1.PROFILE_INITIALIZATION_FAILED,
                    null,
                )
            }
            "statement-schema-invalid" -> {
                val detail = taggedUnit(
                    unavailable["detail"],
                    "schema_error",
                    "detail",
                    "$path.detail",
                )
                PrivacyCompiledProfileResultV1.Unavailable(
                    PrivacyCompiledProfileUnavailableReasonV1.STATEMENT_SCHEMA_INVALID,
                    when (detail) {
                        "conflicting-stable-type-id" ->
                            PrivacyCompiledStatementSchemaErrorV1.CONFLICTING_STABLE_TYPE_ID
                        "missing-type-reference" ->
                            PrivacyCompiledStatementSchemaErrorV1.MISSING_TYPE_REFERENCE
                        else -> throw IllegalArgumentException("$path.detail is not a closed schema error")
                    },
                )
            }
            else -> throw IllegalArgumentException("$path.reason is not a closed unavailable reason")
        }
    }

    private fun parseReadiness(value: Any?, path: String): PrivacyCapabilityReadinessV1 {
        val readiness = exactObject(value, setOf("readiness", "detail"), path)
        return when (text(readiness["readiness"], "$path.readiness")) {
            "production-qualified" -> {
                require(readiness["detail"] == null) { "$path.detail must be null" }
                PrivacyCapabilityReadinessV1.ProductionQualified
            }
            "unavailable" -> PrivacyCapabilityReadinessV1.Unavailable(
                parseCapabilityUnavailableReason(readiness["detail"], "$path.detail"),
            )
            else -> throw IllegalArgumentException("$path.readiness is not a closed readiness")
        }
    }

    private fun parseCapabilityUnavailableReason(
        value: Any?,
        path: String,
    ): PrivacyCapabilityUnavailableReasonV1 {
        val unavailable = exactObject(value, setOf("reason", "detail"), path)
        return when (text(unavailable["reason"], "$path.reason")) {
            "compiled-profile" -> PrivacyCapabilityUnavailableReasonV1.CompiledProfile(
                parseUnavailable(unavailable["detail"], "$path.detail"),
            )
            "not-registered" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.NotRegistered,
                path,
            )
            "proposed" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.Proposed,
                path,
            )
            "suspended" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.Suspended,
                path,
            )
            "retired" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.Retired,
                path,
            )
            "missing-production-qualification" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
                path,
            )
            "invalid-production-qualification" -> unitUnavailableReason(
                unavailable,
                PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
                path,
            )
            else -> throw IllegalArgumentException("$path.reason is not a closed unavailable reason")
        }
    }

    private fun unitUnavailableReason(
        value: Map<String, Any?>,
        reason: PrivacyCapabilityUnavailableReasonV1,
        path: String,
    ): PrivacyCapabilityUnavailableReasonV1 {
        require(value["detail"] == null) { "$path.detail must be null" }
        return reason
    }

    private fun parseConsensusPolicy(
        value: Any?,
        committedHeight: BigInteger,
        path: String,
    ): PrivacyConsensusPolicyV1 {
        val policy = exactObject(value, setOf("current_limits", "pending_tightening"), path)
        val current = parseConsensusLimits(policy["current_limits"], "$path.current_limits")
        val pending = policy["pending_tightening"]?.let { candidate ->
            val pendingPath = "$path.pending_tightening"
            val tightening = exactObject(
                candidate,
                setOf("scheduled_at_height", "effective_at_height", "next_limits"),
                pendingPath,
            )
            val scheduled = integer(
                tightening["scheduled_at_height"],
                "$pendingPath.scheduled_at_height",
            )
            val effective = integer(
                tightening["effective_at_height"],
                "$pendingPath.effective_at_height",
            )
            requireCommittedSchedule(scheduled, effective, committedHeight, pendingPath)
            PrivacyConsensusPolicyTighteningV1(
                scheduled,
                effective,
                parseConsensusLimits(tightening["next_limits"], "$pendingPath.next_limits"),
            )
        }
        return PrivacyConsensusPolicyV1(current, pending)
    }

    private fun parseConsensusLimits(value: Any?, path: String): PrivacyConsensusLimitsV1 {
        val limits = exactObject(value, CONSENSUS_LIMIT_KEYS, path)
        fun field(name: String): Int = uint32(limits[name], "$path.$name")
        return PrivacyConsensusLimitsV1(
            field("max_actions_per_transaction"),
            field("max_actions_per_block"),
            field("max_proof_bytes_per_action"),
            field("max_action_bytes"),
            field("max_privacy_bytes_per_transaction"),
            field("max_privacy_bytes_per_block"),
            field("max_statement_and_encrypted_output_bytes_per_transaction"),
            field("max_nullifiers_per_action"),
            field("max_commitments_per_action"),
            field("retained_root_count"),
        )
    }

    private fun parseActivation(
        value: Any?,
        protocol: PrivacyProtocolIdV1,
        compiled: PrivacyCompiledProfileResultV1,
        committedHeight: BigInteger,
        path: String,
    ): PrivacyProtocolActivationRecordV1 {
        val record = exactObject(value, ACTIVATION_KEYS, path)
        val limits = parseProtocolLimits(
            record["protocol_limits"],
            protocol,
            "$path.protocol_limits",
        )
        val activationProfile = parseProfileBindings(record, protocol, limits, path)
        val compiledProfile = (compiled as? PrivacyCompiledProfileResultV1.Available)?.profile
        if (compiledProfile != null) {
            requirePrivacyProfileBindingsEqualV1(
                activationProfile,
                compiledProfile,
                "Exact12 capability activation",
            )
            requireProtocolLimitsAtMostV1(
                limits,
                compiledProfile.protocolLimits,
                "Exact12 capability activation limits",
            )
        }
        val lifecycle = parseLifecycle(record["lifecycle"], committedHeight, "$path.lifecycle")
        val pending = parseProtocolTightening(
            record["pending_protocol_limits_tightening"],
            limits,
            committedHeight,
            "$path.pending_protocol_limits_tightening",
        )
        return PrivacyProtocolActivationRecordV1(
            activationProfile,
            lifecycle,
            pending,
        )
    }

    private fun parseLifecycle(
        value: Any?,
        committedHeight: BigInteger,
        path: String,
    ): PrivacyProtocolLifecycleV1 {
        val lifecycle = exactObject(value, setOf("state", "record"), path)
        val state = when (text(lifecycle["state"], "$path.state")) {
            "proposed" -> PrivacyProtocolLifecycleStateV1.PROPOSED
            "active" -> PrivacyProtocolLifecycleStateV1.ACTIVE
            "suspended" -> PrivacyProtocolLifecycleStateV1.SUSPENDED
            "retired" -> PrivacyProtocolLifecycleStateV1.RETIRED
            else -> throw IllegalArgumentException("$path.state is not a closed lifecycle state")
        }
        val keys = if (state == PrivacyProtocolLifecycleStateV1.PROPOSED) {
            setOf("proposed_at_height")
        } else {
            setOf("proposed_at_height", "activated_at_height", "state_since_height")
        }
        val record = exactObject(lifecycle["record"], keys, "$path.record")
        val proposed = positiveUint64(
            record["proposed_at_height"],
            "$path.record.proposed_at_height",
        )
        require(proposed <= committedHeight) { "$path proposal is after committed height" }
        if (state == PrivacyProtocolLifecycleStateV1.PROPOSED) {
            return PrivacyProtocolLifecycleV1(state, proposed, null, null)
        }
        val activated = if (
            state == PrivacyProtocolLifecycleStateV1.RETIRED &&
            record["activated_at_height"] == null
        ) {
            null
        } else {
            positiveUint64(
                record["activated_at_height"],
                "$path.record.activated_at_height",
            )
        }
        val stateSince = positiveUint64(
            record["state_since_height"],
            "$path.record.state_since_height",
        )
        require(stateSince <= committedHeight && (activated == null || activated <= committedHeight)) {
            "$path lifecycle state is after committed height"
        }
        return PrivacyProtocolLifecycleV1(state, proposed, activated, stateSince)
    }

    private fun parseProtocolTightening(
        value: Any?,
        current: PrivacyProtocolLimitsV1,
        committedHeight: BigInteger,
        path: String,
    ): PrivacyProtocolLimitsTighteningV1? {
        if (value == null) return null
        val tightening = exactObject(
            value,
            setOf("scheduled_at_height", "effective_at_height", "next_limits"),
            path,
        )
        val scheduled = integer(
            tightening["scheduled_at_height"],
            "$path.scheduled_at_height",
        )
        val effective = integer(
            tightening["effective_at_height"],
            "$path.effective_at_height",
        )
        requireCommittedSchedule(scheduled, effective, committedHeight, path)
        val next = parseProtocolLimits(tightening["next_limits"], current.protocolId, "$path.next_limits")
        requireProtocolLimitsAtMostV1(next, current, "$path.next_limits")
        require(next != current) { "$path must be a strict tightening" }
        return PrivacyProtocolLimitsTighteningV1(scheduled, effective, next)
    }

    private fun requireCommittedSchedule(
        scheduled: BigInteger,
        effective: BigInteger,
        committedHeight: BigInteger,
        path: String,
    ) {
        requireValidPrivacyPolicyScheduleV1(scheduled, effective, path)
        require(
            scheduled <= committedHeight &&
                effective > committedHeight,
        ) { "$path has an invalid committed-height schedule" }
    }

    private fun parseQualification(
        value: Any?,
        path: String,
    ): PrivacyExact12QualificationRecordV1 {
        val record = exactObject(
            value,
            setOf("release_manifest", "deployment_qualification"),
            path,
        )
        val releasePath = "$path.release_manifest"
        val release = exactObject(
            record["release_manifest"],
            RELEASE_MANIFEST_KEYS,
            releasePath,
        )
        val releaseVersion = uint32(release["version"], "$releasePath.version")
        require(releaseVersion == 1) { "$releasePath.version must be exactly 1" }
        val catalogId = text(release["catalog_id"], "$releasePath.catalog_id")
        require(catalogId == EXACT12_CATALOG_ID) {
            "$releasePath.catalog_id is not the first-release Exact12 catalog"
        }
        val catalogCommitment = PrivacyExact12CatalogCommitmentV1(
            fixedBytes(
                release["catalog_commitment"],
                CATALOG_COMMITMENT_BYTES,
                "$releasePath.catalog_commitment",
            ),
        )
        val source = immutableJsonObject(
            exactObject(release["source"], RELEASE_SOURCE_KEYS, "$releasePath.source"),
        )
        val abiVersion = uint32(release["abi_version"], "$releasePath.abi_version")
        require(abiVersion == 1) { "$releasePath.abi_version must be exactly 1" }
        val abiHash = fixed32(release["abi_hash"], "$releasePath.abi_hash")
        val syscallListDigest = fixed32(
            release["syscall_list_digest"],
            "$releasePath.syscall_list_digest",
        )
        val auditBundleDigest = fixed32(
            release["audit_bundle_digest"],
            "$releasePath.audit_bundle_digest",
        )
        val rawBindings = list(release["protocols"], "$releasePath.protocols")
        val expected = PrivacyProtocolIdV1.values()
        require(rawBindings.size == expected.size) {
            "$releasePath.protocols must contain exactly ${expected.size} bindings"
        }
        val bindings = rawBindings.mapIndexed { index, rawBinding ->
            parseReleaseBinding(
                rawBinding,
                expected[index],
                catalogCommitment,
                auditBundleDigest,
                "$releasePath.protocols[$index]",
            )
        }
        val releaseManifest = PrivacyExact12ReleaseManifestV1(
            releaseVersion,
            catalogId,
            catalogCommitment,
            source,
            abiVersion,
            abiHash,
            syscallListDigest,
            immutableJsonList(list(release["executables"], "$releasePath.executables")),
            bindings,
            immutableJsonList(list(release["stage_receipts"], "$releasePath.stage_receipts")),
            immutableJsonList(list(release["proof_artifacts"], "$releasePath.proof_artifacts")),
            immutableJsonList(list(release["sdk_packages"], "$releasePath.sdk_packages")),
            immutableJsonList(list(release["hardware_results"], "$releasePath.hardware_results")),
            fixed32(
                release["release_artifact_set_digest"],
                "$releasePath.release_artifact_set_digest",
            ),
            immutableJsonList(list(release["audits"], "$releasePath.audits")),
            auditBundleDigest,
            immutableJsonList(
                list(release["release_signatures"], "$releasePath.release_signatures"),
            ),
            fixed32(release["manifest_digest"], "$releasePath.manifest_digest"),
        )

        val deploymentPath = "$path.deployment_qualification"
        val deployment = exactObject(
            record["deployment_qualification"],
            DEPLOYMENT_QUALIFICATION_KEYS,
            deploymentPath,
        )
        val deploymentVersion = uint32(deployment["version"], "$deploymentPath.version")
        require(deploymentVersion == 1) { "$deploymentPath.version must be exactly 1" }
        val deployedReleaseDigest = fixed32(
            deployment["release_manifest_digest"],
            "$deploymentPath.release_manifest_digest",
        )
        require(deployedReleaseDigest == releaseManifest.manifestDigest) {
            "$deploymentPath.release_manifest_digest must name the embedded release manifest"
        }
        val rawActivations = list(deployment["activations"], "$deploymentPath.activations")
        require(rawActivations.size == expected.size) {
            "$deploymentPath.activations must contain exactly ${expected.size} bindings"
        }
        val activations = rawActivations.mapIndexed { index, rawActivation ->
            val activationPath = "$deploymentPath.activations[$index]"
            val activation = exactObject(
                rawActivation,
                setOf("protocol_id", "activation_height"),
                activationPath,
            )
            val protocolId = protocolTag(activation["protocol_id"], "$activationPath.protocol_id")
            require(protocolId == expected[index]) {
                "$activationPath is out of canonical protocol order"
            }
            PrivacyDeploymentActivationV1(
                protocolId,
                positiveUint64(activation["activation_height"], "$activationPath.activation_height"),
            )
        }
        val convergenceHeight = positiveUint64(
            deployment["convergence_height"],
            "$deploymentPath.convergence_height",
        )
        require(activations.all { it.activationHeight < convergenceHeight }) {
            "$deploymentPath.activations must all precede convergence"
        }
        val deploymentQualification = PrivacyExact12DeploymentQualificationV1(
            deploymentVersion,
            immutableJsonValue(deployment["chain_id"]),
            NetworkId.parse(text(deployment["network_id"], "$deploymentPath.network_id")),
            fixed32(deployment["genesis_hash"], "$deploymentPath.genesis_hash"),
            deployedReleaseDigest,
            fixed32(
                deployment["activation_transaction_digest"],
                "$deploymentPath.activation_transaction_digest",
            ),
            activations,
            fixed32(
                deployment["validator_roster_digest"],
                "$deploymentPath.validator_roster_digest",
            ),
            text(deployment["endpoint_version"], "$deploymentPath.endpoint_version"),
            convergenceHeight,
            fixed32(
                deployment["converged_state_digest"],
                "$deploymentPath.converged_state_digest",
            ),
            immutableJsonList(
                list(deployment["validator_canaries"], "$deploymentPath.validator_canaries"),
            ),
            immutableJsonList(
                list(deployment["validator_signatures"], "$deploymentPath.validator_signatures"),
            ),
            fixed32(deployment["qualification_digest"], "$deploymentPath.qualification_digest"),
        )
        return PrivacyExact12QualificationRecordV1(releaseManifest, deploymentQualification)
    }

    private fun parseReleaseBinding(
        value: Any?,
        expected: PrivacyProtocolIdV1,
        catalogCommitment: PrivacyExact12CatalogCommitmentV1,
        auditBundleDigest: PrivacyFixed32V1,
        path: String,
    ): PrivacyReleaseProtocolBindingV1 {
        val binding = exactObject(value, RELEASE_PROTOCOL_BINDING_KEYS, path)
        val protocolId = protocolTag(binding["protocol_id"], "$path.protocol_id")
        require(protocolId == expected) { "$path is out of canonical protocol order" }
        val proofSystemId = PrivacyProofSystemIdV1.fromCanonicalLabel(
            taggedUnit(
                binding["proof_system_id"],
                "proof_system",
                "value",
                "$path.proof_system_id",
            ),
        )
        val engineId = PrivacyEngineIdV1.fromCanonicalLabel(
            taggedUnit(binding["engine_id"], "engine", "value", "$path.engine_id"),
        )
        require(proofSystemId == protocolId.expectedProofSystem) {
            "$path.proof_system_id differs from the final Exact12 tuple"
        }
        require(engineId == protocolId.expectedEngine) {
            "$path.engine_id differs from the final Exact12 tuple"
        }
        val parameterId = fixed32(binding["parameter_id"], "$path.parameter_id")
        val parameterDigest = fixed32(binding["parameter_digest"], "$path.parameter_digest")
        val verifierDigest = fixed32(binding["verifier_digest"], "$path.verifier_digest")
        val claim = parseSecurityClaim(binding["security_claim"], protocolId, "$path.security_claim")
        require(claim.catalogCommitment == catalogCommitment) {
            "$path.security_claim catalog differs from the release"
        }
        require(claim.securityModel == expectedSecurityModelV1(protocolId)) {
            "$path.security_claim overstates its composed security model"
        }
        require(claim.parameterDigest == parameterDigest && claim.verifierDigest == verifierDigest) {
            "$path.security_claim differs from the release tuple"
        }
        require(claim.auditBundleDigest == auditBundleDigest) {
            "$path.security_claim audit bundle differs from the release"
        }
        return PrivacyReleaseProtocolBindingV1(
            protocolId,
            proofSystemId,
            engineId,
            parameterId,
            parameterDigest,
            verifierDigest,
            fixed32(binding["statement_schema_digest"], "$path.statement_schema_digest"),
            fixed32(binding["engine_manifest_digest"], "$path.engine_manifest_digest"),
            claim,
            fixed32(binding["security_claim_digest"], "$path.security_claim_digest"),
        )
    }

    private fun parseSecurityClaim(
        value: Any?,
        protocol: PrivacyProtocolIdV1,
        path: String,
    ): PrivacySecurityClaimV1 {
        val claim = exactObject(value, SECURITY_CLAIM_KEYS, path)
        require(protocolTag(claim["protocol_id"], "$path.protocol_id") == protocol) {
            "$path protocol differs from its activation"
        }
        val securityModel = PrivacySecurityModelV1.fromCanonicalLabel(
            taggedUnit(
                claim["security_model"],
                "security_model",
                "value",
                "$path.security_model",
            ),
        )
        return PrivacySecurityClaimV1(
            PrivacyExact12CatalogCommitmentV1(
                fixedBytes(claim["catalog_commitment"], CATALOG_COMMITMENT_BYTES, "$path.catalog_commitment"),
            ),
            protocol,
            securityModel,
            uint32(claim["target_security_bits"], "$path.target_security_bits"),
            uint32(claim["achieved_security_bits"], "$path.achieved_security_bits"),
            fixed32(claim["parameter_digest"], "$path.parameter_digest"),
            fixed32(claim["verifier_digest"], "$path.verifier_digest"),
            fixed32(claim["reduction_digest"], "$path.reduction_digest"),
            fixed32(claim["audit_bundle_digest"], "$path.audit_bundle_digest"),
        )
    }

    private fun protocolTag(value: Any?, path: String): PrivacyProtocolIdV1 =
        PrivacyProtocolIdV1.fromCanonicalLabel(taggedUnit(value, "protocol", "value", path))

    private fun taggedUnit(value: Any?, tag: String, content: String, path: String): String {
        val tagged = exactObject(value, setOf(tag, content), path)
        require(tagged[content] == null) { "$path.$content must be null" }
        return text(tagged[tag], "$path.$tag")
    }

    private fun fixed32(value: Any?, path: String): PrivacyFixed32V1 {
        return PrivacyFixed32V1(fixedBytes(value, 32, path))
    }

    private fun fixedBytes(value: Any?, size: Int, path: String): ByteArray {
        val bytes = list(value, path)
        require(bytes.size == size) { "$path must contain exactly $size bytes" }
        return ByteArray(size) { index ->
            val byte = uint32(bytes[index], "$path[$index]")
            require(byte <= 255) { "$path[$index] must fit uint8" }
            byte.toByte()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun exactObject(value: Any?, keys: Set<String>, path: String): Map<String, Any?> {
        val objectValue = value as? Map<*, *>
            ?: throw IllegalArgumentException("$path must be an object")
        require(objectValue.keys.all { it is String }) { "$path contains a non-string field" }
        val actual = objectValue.keys.map { it as String }.toSet()
        require(actual == keys && objectValue.size == keys.size) {
            "$path must contain exactly ${keys.sorted().joinToString()}"
        }
        return objectValue as Map<String, Any?>
    }

    private fun list(value: Any?, path: String): List<Any?> =
        value as? List<Any?> ?: throw IllegalArgumentException("$path must be an array")

    private fun immutableJsonObject(value: Map<String, Any?>): Map<String, Any?> {
        val copy = LinkedHashMap<String, Any?>(value.size)
        value.forEach { (key, item) -> copy[key] = immutableJsonValue(item) }
        return Collections.unmodifiableMap(copy)
    }

    private fun immutableJsonList(value: List<Any?>): List<Any?> =
        Collections.unmodifiableList(value.map(::immutableJsonValue))

    private fun immutableJsonValue(value: Any?): Any? = when (value) {
        is Map<*, *> -> {
            require(value.keys.all { it is String }) { "qualification evidence has non-string keys" }
            @Suppress("UNCHECKED_CAST")
            immutableJsonObject(value as Map<String, Any?>)
        }
        is List<*> -> immutableJsonList(value)
        else -> value
    }

    private fun text(value: Any?, path: String): String =
        value as? String ?: throw IllegalArgumentException("$path must be a string")

    private fun uint32(value: Any?, path: String): Int {
        val number = integer(value, path)
        require(number.signum() >= 0 && number.bitLength() <= 31) {
            "$path must fit the supported uint32 range"
        }
        return number.intValueExact()
    }

    private fun uint64(value: Any?, path: String): BigInteger {
        val number = integer(value, path)
        require(number.signum() >= 0 && number <= U64_MAX) { "$path must fit uint64" }
        return number
    }

    private fun positiveUint64(value: Any?, path: String): BigInteger =
        uint64(value, path).also { require(it.signum() > 0) { "$path must be non-zero" } }

    private fun integer(value: Any?, path: String): BigInteger = when (value) {
        is Long -> BigInteger.valueOf(value)
        is BigInteger -> value
        else -> throw IllegalArgumentException("$path must be an integer")
    }

    private val PROFILE_KEYS = setOf(
        "protocol_id",
        "proof_system_id",
        "engine_id",
        "parameter_id",
        "parameter_digest",
        "verifier_digest",
        "statement_schema_digest",
        "engine_manifest_digest",
        "protocol_limits",
    )
    private val ACTIVATION_KEYS = PROFILE_KEYS + setOf(
        "lifecycle",
        "pending_protocol_limits_tightening",
    )
    private val RELEASE_SOURCE_KEYS = setOf(
        "source_tree_digest",
        "source_tree_clean",
        "toolchain_id",
        "toolchain_digest",
        "cargo_lock_digest",
    )
    private val RELEASE_MANIFEST_KEYS = setOf(
        "version",
        "catalog_id",
        "catalog_commitment",
        "source",
        "abi_version",
        "abi_hash",
        "syscall_list_digest",
        "executables",
        "protocols",
        "stage_receipts",
        "proof_artifacts",
        "sdk_packages",
        "hardware_results",
        "release_artifact_set_digest",
        "audits",
        "audit_bundle_digest",
        "release_signatures",
        "manifest_digest",
    )
    private val RELEASE_PROTOCOL_BINDING_KEYS = setOf(
        "protocol_id",
        "proof_system_id",
        "engine_id",
        "parameter_id",
        "parameter_digest",
        "verifier_digest",
        "statement_schema_digest",
        "engine_manifest_digest",
        "security_claim",
        "security_claim_digest",
    )
    private val DEPLOYMENT_QUALIFICATION_KEYS = setOf(
        "version",
        "chain_id",
        "network_id",
        "genesis_hash",
        "release_manifest_digest",
        "activation_transaction_digest",
        "activations",
        "validator_roster_digest",
        "endpoint_version",
        "convergence_height",
        "converged_state_digest",
        "validator_canaries",
        "validator_signatures",
        "qualification_digest",
    )
    private val SECURITY_CLAIM_KEYS = setOf(
        "catalog_commitment",
        "protocol_id",
        "security_model",
        "target_security_bits",
        "achieved_security_bits",
        "parameter_digest",
        "verifier_digest",
        "reduction_digest",
        "audit_bundle_digest",
    )
    private val CONSENSUS_LIMIT_KEYS = setOf(
        "max_actions_per_transaction",
        "max_actions_per_block",
        "max_proof_bytes_per_action",
        "max_action_bytes",
        "max_privacy_bytes_per_transaction",
        "max_privacy_bytes_per_block",
        "max_statement_and_encrypted_output_bytes_per_transaction",
        "max_nullifiers_per_action",
        "max_commitments_per_action",
        "retained_root_count",
    )

    private const val EXACT12_CATALOG_ID = "iroha-privacy-exact12-v1"
}

private fun projectedReadinessV1(
    compiledProfile: PrivacyCompiledProfileResultV1,
    activation: PrivacyProtocolActivationRecordV1?,
    qualification: PrivacyExact12QualificationRecordV1?,
    committedHeight: BigInteger,
): PrivacyCapabilityReadinessV1 {
    if (compiledProfile is PrivacyCompiledProfileResultV1.Unavailable) {
        return PrivacyCapabilityReadinessV1.Unavailable(
            PrivacyCapabilityUnavailableReasonV1.CompiledProfile(compiledProfile),
        )
    }
    if (activation == null) {
        return PrivacyCapabilityReadinessV1.Unavailable(
            PrivacyCapabilityUnavailableReasonV1.NotRegistered,
        )
    }
    return when (activation.lifecycle.state) {
        PrivacyProtocolLifecycleStateV1.PROPOSED -> PrivacyCapabilityReadinessV1.Unavailable(
            PrivacyCapabilityUnavailableReasonV1.Proposed,
        )
        PrivacyProtocolLifecycleStateV1.SUSPENDED -> PrivacyCapabilityReadinessV1.Unavailable(
            PrivacyCapabilityUnavailableReasonV1.Suspended,
        )
        PrivacyProtocolLifecycleStateV1.RETIRED -> PrivacyCapabilityReadinessV1.Unavailable(
            PrivacyCapabilityUnavailableReasonV1.Retired,
        )
        PrivacyProtocolLifecycleStateV1.ACTIVE -> {
            if (qualification == null) {
                PrivacyCapabilityReadinessV1.Unavailable(
                    PrivacyCapabilityUnavailableReasonV1.MissingProductionQualification,
                )
            } else if (
                !qualificationMatchesCapabilityRowV1(
                    qualification,
                    compiledProfile,
                    activation,
                    committedHeight,
                )
            ) {
                PrivacyCapabilityReadinessV1.Unavailable(
                    PrivacyCapabilityUnavailableReasonV1.InvalidProductionQualification,
                )
            } else {
                PrivacyCapabilityReadinessV1.ProductionQualified
            }
        }
    }
}

private fun qualificationMatchesCapabilityRowV1(
    qualification: PrivacyExact12QualificationRecordV1,
    compiledProfile: PrivacyCompiledProfileResultV1,
    activation: PrivacyProtocolActivationRecordV1,
    committedHeight: BigInteger,
): Boolean {
    if (qualification.deploymentQualification.convergenceHeight > committedHeight) return false
    val compiled = (compiledProfile as? PrivacyCompiledProfileResultV1.Available)?.profile
        ?: return false
    if (activation.lifecycle.state != PrivacyProtocolLifecycleStateV1.ACTIVE) return false
    val index = compiled.protocolId.ordinal
    val release = qualification.releaseManifest.protocols.getOrNull(index) ?: return false
    val deployment = qualification.deploymentQualification.activations.getOrNull(index)
        ?: return false
    return release.protocolId == compiled.protocolId &&
        deployment.protocolId == compiled.protocolId &&
        release.proofSystemId == compiled.proofSystemId &&
        release.proofSystemId == activation.profileBindings.proofSystemId &&
        release.engineId == compiled.engineId &&
        release.engineId == activation.profileBindings.engineId &&
        release.parameterId == compiled.parameterId &&
        release.parameterId == activation.profileBindings.parameterId &&
        release.parameterDigest == compiled.parameterDigest &&
        release.parameterDigest == activation.profileBindings.parameterDigest &&
        release.verifierDigest == compiled.verifierDigest &&
        release.verifierDigest == activation.profileBindings.verifierDigest &&
        release.statementSchemaDigest == compiled.statementSchemaDigest &&
        release.statementSchemaDigest == activation.profileBindings.statementSchemaDigest &&
        release.engineManifestDigest == compiled.engineManifestDigest &&
        release.engineManifestDigest == activation.profileBindings.engineManifestDigest &&
        deployment.activationHeight == activation.lifecycle.activatedAtHeight
}

internal fun expectedOperationSchema(protocol: PrivacyProtocolIdV1): PrivacyOperationSchemaV1 =
    when (protocol) {
        PrivacyProtocolIdV1.ZK_ACE_PQ_AUTHORIZATION_V1 ->
            PrivacyOperationSchemaV1.ZK_ACE_AUTHORIZATION_ACTION_V1
        PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 ->
            PrivacyOperationSchemaV1.ANONYMOUS_PGC_PAYMENT_ACTION_V1
        PrivacyProtocolIdV1.VERANGE_TRANSPARENT_RANGE_V1 ->
            PrivacyOperationSchemaV1.VERANGE_RANGE_PROOF_V1
        PrivacyProtocolIdV1.IROHA_ZK_AMS_V1 ->
            PrivacyOperationSchemaV1.ZK_AMS_ADMISSION_AND_PROVISIONING_V1
        PrivacyProtocolIdV1.VEGA_EXISTING_CREDENTIAL_ZK_V1 ->
            PrivacyOperationSchemaV1.VEGA_CREDENTIAL_PRESENTATION_V1
        PrivacyProtocolIdV1.IROHA_ZK_X509_STARK_P256_V1 ->
            PrivacyOperationSchemaV1.ZK_X509_IDENTITY_PRESENTATION_V1
        PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1 ->
            PrivacyOperationSchemaV1.JINDO_POLYNOMIAL_EVALUATION_V1
        PrivacyProtocolIdV1.IROHA_BOOTLE_LANTERN_ANONCRED_V1 ->
            PrivacyOperationSchemaV1.BOOTLE_LANTERN_CREDENTIAL_PRESENTATION_V1
        PrivacyProtocolIdV1.ORCHARD_HALO2_ACTIONS_V1 ->
            PrivacyOperationSchemaV1.ORCHARD_NOTE_ACTION_V1
        PrivacyProtocolIdV1.MONERO_FCMP_PLUS_PLUS_V1 ->
            PrivacyOperationSchemaV1.FCMP_MEMBERSHIP_PAYMENT_V1
        PrivacyProtocolIdV1.IROHA_IVM_PRIVATE_NOTE_STARK_V1 ->
            PrivacyOperationSchemaV1.IVM_PRIVATE_NOTE_ACTION_V1
        PrivacyProtocolIdV1.PQ_MASP_STARK_V1 -> PrivacyOperationSchemaV1.PQ_MASP_NOTE_ACTION_V1
    }

internal fun expectedExecutionMode(protocol: PrivacyProtocolIdV1): PrivacyExecutionModeV1 =
    when (protocol) {
        PrivacyProtocolIdV1.ZK_ACE_PQ_AUTHORIZATION_V1 ->
            PrivacyExecutionModeV1.AUTHORIZATION_ACTION
        PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1,
        PrivacyProtocolIdV1.MONERO_FCMP_PLUS_PLUS_V1,
        -> PrivacyExecutionModeV1.PAYMENT_ACTION
        PrivacyProtocolIdV1.VERANGE_TRANSPARENT_RANGE_V1,
        PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1,
        -> PrivacyExecutionModeV1.COMPONENT
        PrivacyProtocolIdV1.IROHA_ZK_AMS_V1 -> PrivacyExecutionModeV1.ADMISSION_ACTION
        PrivacyProtocolIdV1.VEGA_EXISTING_CREDENTIAL_ZK_V1,
        PrivacyProtocolIdV1.IROHA_ZK_X509_STARK_P256_V1,
        PrivacyProtocolIdV1.IROHA_BOOTLE_LANTERN_ANONCRED_V1,
        -> PrivacyExecutionModeV1.PRESENTATION_ACTION
        PrivacyProtocolIdV1.ORCHARD_HALO2_ACTIONS_V1,
        PrivacyProtocolIdV1.IROHA_IVM_PRIVATE_NOTE_STARK_V1,
        PrivacyProtocolIdV1.PQ_MASP_STARK_V1,
        -> PrivacyExecutionModeV1.NOTE_ACTION
    }

internal fun expectedFeatureMask(protocol: PrivacyProtocolIdV1): Int = when (protocol) {
    PrivacyProtocolIdV1.ZK_ACE_PQ_AUTHORIZATION_V1,
    PrivacyProtocolIdV1.IROHA_JINDO_POLYNOMIAL_COMMITMENT_V1,
    -> 0
    PrivacyProtocolIdV1.ANONYMOUS_PGC_K_OUT_OF_N_V1 -> (1 shl 1) or (1 shl 2)
    PrivacyProtocolIdV1.VERANGE_TRANSPARENT_RANGE_V1 -> 1
    PrivacyProtocolIdV1.IROHA_ZK_AMS_V1,
    PrivacyProtocolIdV1.VEGA_EXISTING_CREDENTIAL_ZK_V1,
    PrivacyProtocolIdV1.IROHA_ZK_X509_STARK_P256_V1,
    PrivacyProtocolIdV1.IROHA_BOOTLE_LANTERN_ANONCRED_V1,
    PrivacyProtocolIdV1.MONERO_FCMP_PLUS_PLUS_V1,
    -> 1 shl 1
    PrivacyProtocolIdV1.ORCHARD_HALO2_ACTIONS_V1,
    PrivacyProtocolIdV1.IROHA_IVM_PRIVATE_NOTE_STARK_V1,
    -> 1 or (1 shl 1) or (1 shl 2)
    PrivacyProtocolIdV1.PQ_MASP_STARK_V1 ->
        1 or (1 shl 1) or (1 shl 2) or (1 shl 3) or (1 shl 4)
}
