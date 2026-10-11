package org.hyperledger.iroha.sdk.client

import java.util.LinkedHashMap

/** Canonical payload signed by an external RAM-LFE output-opening authority. */
class RamLfeOutputOpeningPayload(
    @JvmField val programId: String,
    @JvmField val inputCiphertextHash: String,
    @JvmField val outputCiphertextHash: String,
    @JvmField val parameterDigest: String,
    @JvmField val evaluationKeyDigest: String,
    @JvmField val openedOutputHash: String,
    @JvmField val openedAtMs: Long,
    @JvmField val expiresAtMs: Long?,
) {
    fun toJsonMap(): Map<String, Any> {
        val payload = LinkedHashMap<String, Any>()
        payload["program_id"] = linkedMapOf("name" to IdentifierOwnerInputV1.exactText(programId, "opening.payload.programId"))
        payload["input_ciphertext_hash"] =
            IdentifierOwnerInputV1.modelHashLiteral(inputCiphertextHash)
        payload["output_ciphertext_hash"] =
            IdentifierOwnerInputV1.modelHashLiteral(outputCiphertextHash)
        payload["parameter_digest"] =
            IdentifierOwnerInputV1.modelHashLiteral(parameterDigest)
        payload["evaluation_key_digest"] =
            IdentifierOwnerInputV1.modelHashLiteral(evaluationKeyDigest)
        payload["opened_output_hash"] =
            IdentifierOwnerInputV1.modelHashLiteral(openedOutputHash)
        payload["opened_at_ms"] = openedAtMs
        if (expiresAtMs != null) {
            payload["expires_at_ms"] = expiresAtMs
        }
        return payload
    }
}

/** Original externally signed opening; JSON uses the exact typed Model grammar. */
class RamLfeOutputOpening(
    @JvmField val payload: RamLfeOutputOpeningPayload,
    @JvmField val signature: String,
) {
    fun toJsonMap(): Map<String, Any> {
        val opening = LinkedHashMap<String, Any>()
        opening["payload"] = payload.toJsonMap()
        opening["signature"] = IdentifierOwnerInputV1.rawSignature(signature, "opening.signature").uppercase()
        return opening
    }
}
