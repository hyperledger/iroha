package org.hyperledger.iroha.sdk.client

import java.math.BigInteger

/** Governance binding emitted by `GET /v1/gov/contracts/{contract_address}`. */
class GovernanceContractResponse(
    @JvmField val found: Boolean,
    @JvmField val contractAddress: String,
    @JvmField val contractSubjectAccount: String?,
    @JvmField val dataspace: String?,
    @JvmField val active: Boolean?,
    @JvmField val lifecycle: GovernanceContractLifecycle?,
    @JvmField val emergencyHoldActive: Boolean?,
    @JvmField val codeHashHex: String?,
    @JvmField val abiHashHex: String?,
    publicEntrypoints: List<String>?,
) {
    @JvmField val publicEntrypoints: List<String>? = publicEntrypoints?.toList()
}

/** Complete retained ownership and lifecycle projection for one contract. */
class GovernanceContractLifecycle(
    /** Exact first-release lifecycle schema version. */
    @JvmField val version: Int,
    @JvmField val origin: String,
    @JvmField val originAccount: String,
    @JvmField val originProposalContentIdHex: String?,
    @JvmField val originGovernanceAttemptIdHex: String?,
    @JvmField val owner: String,
    @JvmField val pendingOwner: String?,
    @JvmField val parliamentDelegated: Boolean,
    @JvmField val activeCodeHashHex: String?,
    /** Last bound complete artifact, retained while inactive. */
    @JvmField val retainedCodeHashHex: String?,
    /** Full unsigned lifecycle CAS revision. */
    @JvmField val revision: BigInteger,
    @JvmField val emergencyHold: GovernanceContractEmergencyHold?,
)

/** Retained bounded Parliament emergency-hold projection. */
class GovernanceContractEmergencyHold(
    @JvmField val incidentDigestHex: String,
    @JvmField val proposalContentIdHex: String,
    @JvmField val governanceAttemptIdHex: String,
    @JvmField val reason: String,
    /** Full unsigned height at which Parliament imposed the hold. */
    @JvmField val imposedAtHeight: BigInteger,
    /** Full unsigned height after which the hold no longer suspends execution. */
    @JvmField val expiresAtHeight: BigInteger,
)
