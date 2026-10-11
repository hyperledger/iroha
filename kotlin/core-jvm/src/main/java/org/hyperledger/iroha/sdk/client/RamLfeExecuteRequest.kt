package org.hyperledger.iroha.sdk.client

/** Exact owner input; Strings/transport copies have no JVM total-memory erasure claim. */
class RamLfeExecuteRequest private constructor(
    @JvmField val normalizedInput: String,
    @JvmField val inputNonceHex: String,
) {
    internal fun toJsonMap(): Map<String, Any> = linkedMapOf("normalized_input" to normalizedInput, "input_nonce" to inputNonceHex)
    companion object {
        @JvmStatic
        fun ownerInput(normalizedInput: String, inputNonceHex: String): RamLfeExecuteRequest =
            RamLfeExecuteRequest(IdentifierOwnerInputV1.normalizedInput(normalizedInput), IdentifierOwnerInputV1.privateNonce(inputNonceHex))
    }
}
