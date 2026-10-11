package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Canonical RAM-LFE execution payload nested inside an identifier-resolution receipt. */
class IdentifierResolutionExecutionPayload(
    @JvmField val programId: String,
    @JvmField val programDigest: String,
    @JvmField val backend: String,
    @JvmField val verificationMode: String,
    @JvmField val inputCiphertextHash: String,
    @JvmField val outputCiphertextHash: String,
    @JvmField val parameterDigest: String,
    @JvmField val evaluationKeyDigest: String,
    @JvmField val outputHash: String,
    @JvmField val associatedDataHash: String,
    @JvmField val executedAtMs: Long,
    @JvmField val expiresAtMs: Long?,
)

/** Canonical payload covered by an identifier-resolution receipt attestation. */
class IdentifierResolutionPayload(
    @JvmField val networkId: NetworkId,
    @JvmField val policyId: String,
    @JvmField val execution: IdentifierResolutionExecutionPayload,
    @JvmField val opening: RamLfeOutputOpening,
    @JvmField val opaqueId: String,
    @JvmField val receiptHash: String,
    @JvmField val uaid: String,
    @JvmField val accountId: String,
)
