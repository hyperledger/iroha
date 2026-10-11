package org.hyperledger.iroha.sdk.client

/** Summary entry returned by `GET /v1/identifier-policies`. */
class IdentifierPolicySummary @JvmOverloads constructor(
    @JvmField val policyId: String,
    @JvmField val programId: String,
    @JvmField val owner: String,
    @JvmField val active: Boolean,
    @JvmField val normalization: IdentifierNormalization,
    @JvmField val resolverPublicKey: String,
    @JvmField val backend: String,
    @JvmField val inputEncryption: String?,
    @JvmField val inputEncryptionPublicParameters: String?,
    @JvmField val inputEncryptionPublicParametersDecoded: IdentifierBfvPublicParameters?,
    @JvmField val note: String?,
    @JvmField val outputOpeningPublicKey: String,
    @JvmField val proofVerifier: RamLfeProofVerifierMetadata? = null,
    @JvmField val phoneRetailAttestorPublicKey: String? = null,
    /** Present for programmed RAM-FHE policies; the initializer identity is required within it. */
    @JvmField val ramFheProfile: RamFheProfile? = null,
) {
    init {
        require(programId.isNotBlank()) { "programId must not be blank" }
        requirePublicKeyLiteral(resolverPublicKey, "resolverPublicKey")
        requirePublicKeyLiteral(outputOpeningPublicKey, "outputOpeningPublicKey")
        if (phoneRetailAttestorPublicKey != null) {
            requirePublicKeyLiteral(phoneRetailAttestorPublicKey, "phoneRetailAttestorPublicKey")
        }
    }

    fun prepareRequest(normalizedInput: String, inputNonceHex: String): IdentifierResolveRequest {
        IdentifierOwnerInputV1.policy(this, normalizedInput)
        return IdentifierResolveRequest.prepare(policyId, normalizedInput, inputNonceHex)
    }
    @JvmOverloads
    fun claimRequest(normalizedInput: String, inputNonceHex: String, opening: RamLfeOutputOpening, phone: PhoneRetailCanonicalityAttestationV1? = null): IdentifierResolveRequest {
        IdentifierOwnerInputV1.policy(this, normalizedInput)
        require(opening.payload.programId == programId) { "opening program differs from selected policy" }
        return IdentifierResolveRequest.claim(policyId, normalizedInput, inputNonceHex, opening, phone)
    }
}
