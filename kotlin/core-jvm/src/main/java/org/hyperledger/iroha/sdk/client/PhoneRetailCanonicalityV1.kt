package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.nexus.UaidLiteral
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Original signed phone statement carrier; construction/parsing grants no signature authority. */
class PhoneRetailCanonicalityPayloadV1(
    @JvmField val networkId: NetworkId,
    @JvmField val policyId: String,
    @JvmField val programId: String,
    @JvmField val inputCiphertextHash: String,
    @JvmField val outputCiphertextHash: String,
    @JvmField val openedOutputHash: String,
    @JvmField val canonicalPhoneNullifier: String,
    @JvmField val uaid: String,
    @JvmField val accountId: String,
    @JvmField val issuedAtMs: Long,
    @JvmField val expiresAtMs: Long,
) {
    init {
        require(policyId == "phone#retail" && programId == "phone_retail") { "exact phone#retail statement required" }
        IdentifierOwnerInputV1.originalLease(issuedAtMs, expiresAtMs)
        requireCanonicalI105Address(accountId, "phone.accountId")
        require(UaidLiteral.canonicalize(uaid, "phone.uaid") == uaid) { "phone UAID must be canonical" }
        for (hash in listOf(inputCiphertextHash, outputCiphertextHash, openedOutputHash, canonicalPhoneNullifier)) require(IdentifierOwnerInputV1.rawHash32(hash, "phone.hash") == hash) { "phone hashes must be canonical lower hex" }
        require(canonicalPhoneNullifier == openedOutputHash && openedOutputHash == outputCiphertextHash) { "phone nullifier differs from native opaque output hash" }
    }
    internal fun toJsonMap(): Map<String, Any> = linkedMapOf(
        "network_id" to networkId.literal, "policy_id" to linkedMapOf("kind" to "phone", "business_rule" to "retail"), "program_id" to linkedMapOf("name" to programId),
        "input_ciphertext_hash" to IdentifierOwnerInputV1.modelHashLiteral(inputCiphertextHash), "output_ciphertext_hash" to IdentifierOwnerInputV1.modelHashLiteral(outputCiphertextHash),
        "opened_output_hash" to IdentifierOwnerInputV1.modelHashLiteral(openedOutputHash), "canonical_phone_nullifier" to IdentifierOwnerInputV1.modelHashLiteral(canonicalPhoneNullifier),
        "uaid" to listOf(IdentifierOwnerInputV1.modelHashLiteral(uaid.removePrefix("uaid:"))), "account_id" to accountId, "issued_at_ms" to issuedAtMs, "expires_at_ms" to expiresAtMs,
    )
}

/** Separate original attestor signature; Torii/Core verify the independently pinned key. */
class PhoneRetailCanonicalityAttestationV1(
    @JvmField val payload: PhoneRetailCanonicalityPayloadV1,
    @JvmField val signature: String,
) {
    init { require(IdentifierOwnerInputV1.rawSignature(signature, "phone.signature") == signature) { "phone signature must be exact lower hex" } }
    internal fun toJsonMap(): Map<String, Any> = linkedMapOf("payload" to payload.toJsonMap(), "signature" to signature.uppercase())
    internal fun requireOriginalOpening(opening: RamLfeOutputOpening) = requireOpeningFields(payload, opening)
    companion object {
        internal fun requireOpeningFields(payload: PhoneRetailCanonicalityPayloadV1, opening: RamLfeOutputOpening) {
            val original = opening.payload
            require(payload.programId == original.programId && payload.inputCiphertextHash == original.inputCiphertextHash && payload.outputCiphertextHash == original.outputCiphertextHash && payload.openedOutputHash == original.openedOutputHash && payload.issuedAtMs == original.openedAtMs && payload.expiresAtMs == original.expiresAtMs) { "phone statement differs from exact original opening" }
        }
    }
}
