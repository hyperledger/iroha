package org.hyperledger.iroha.sdk.client

/** Exact prepare/claim DATA carrier. Torii independently performs signature/ledger admission. */
class IdentifierResolveRequest private constructor(
    @JvmField val phase: String,
    @JvmField val policyId: String,
    @JvmField val normalizedInput: String,
    @JvmField val inputNonceHex: String,
    @JvmField val outputOpening: RamLfeOutputOpening?,
    @JvmField val phoneRetailCanonicality: PhoneRetailCanonicalityAttestationV1?,
) {
    internal fun toJsonMap(): Map<String, Any> {
        val fields = linkedMapOf<String, Any>("phase" to phase, "policy_id" to policyId, "normalized_input" to normalizedInput, "input_nonce" to inputNonceHex)
        outputOpening?.let { fields["output_opening"] = it.toJsonMap() }
        phoneRetailCanonicality?.let { fields["phone_retail_canonicality"] = it.toJsonMap() }
        return fields
    }
    companion object {
        @JvmStatic
        fun prepare(policyId: String, normalizedInput: String, inputNonceHex: String): IdentifierResolveRequest =
            IdentifierResolveRequest("prepare", IdentifierOwnerInputV1.exactText(policyId, "policyId"), IdentifierOwnerInputV1.normalizedInput(normalizedInput), IdentifierOwnerInputV1.privateNonce(inputNonceHex), null, null)
        @JvmStatic
        @JvmOverloads
        fun claim(policyId: String, normalizedInput: String, inputNonceHex: String, outputOpening: RamLfeOutputOpening, phoneRetailCanonicality: PhoneRetailCanonicalityAttestationV1? = null): IdentifierResolveRequest {
            IdentifierOwnerInputV1.originalLease(outputOpening.payload.openedAtMs, outputOpening.payload.expiresAtMs)
            val exactPolicyId = IdentifierOwnerInputV1.exactText(policyId, "policyId")
            if (exactPolicyId == "phone#retail") requireNotNull(phoneRetailCanonicality) { "phone#retail requires the exact independent signed phone carrier" }.requireOriginalOpening(outputOpening)
            else require(phoneRetailCanonicality == null) { "phone statement is only valid for phone#retail" }
            return IdentifierResolveRequest("claim", exactPolicyId, IdentifierOwnerInputV1.normalizedInput(normalizedInput), IdentifierOwnerInputV1.privateNonce(inputNonceHex), outputOpening, phoneRetailCanonicality)
        }
    }
}
