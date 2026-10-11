package org.hyperledger.iroha.sdk.client

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.util.HashLiteral
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral

/** Structural request checks only; Torii owns ledger/signature admission. */
internal object IdentifierOwnerInputV1 {
    const val BACKEND = "hkdf-sha3-512-prf-v1"
    fun exactText(value: String, field: String): String {
        require(value.isNotBlank() && value.trim() == value) { "$field must be exact nonblank text" }
        return value
    }
    fun normalizedInput(value: String): String {
        var index = 0
        while (index < value.length) {
            val ch = value[index++]
            if (Character.isHighSurrogate(ch)) {
                require(index < value.length && Character.isLowSurrogate(value[index++])) { "normalizedInput must contain valid Unicode" }
            } else require(!Character.isLowSurrogate(ch)) { "normalizedInput must contain valid Unicode" }
        }
        val encoded = value.toByteArray(StandardCharsets.UTF_8)
        try { require(encoded.size in 1..512) { "normalizedInput must contain 1..512 UTF-8 bytes" } }
        finally { encoded.fill(0) }
        return value
    }
    fun privateNonce(value: String): String {
        require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' } && value.any { it != '0' }) {
            "inputNonceHex must be exact lowercase nonzero 32-byte hex"
        }
        return value
    }
    fun policy(policy: IdentifierPolicySummary, input: String) {
        require(policy.active && policy.backend == BACKEND) { "current owner requests require an active HKDF policy" }
        require(policy.normalization.normalize(input) == input) { "normalizedInput differs from current policy normalization" }
        if (policy.policyId == "phone#retail") {
            require(policy.programId == "phone_retail" && policy.normalization == IdentifierNormalization.PHONE_E164) { "exact phone#retail policy required" }
            val key = requireNotNull(policy.phoneRetailAttestorPublicKey) { "independent phone attestor pin is required" }
            require(!sameKey(key, policy.resolverPublicKey) && !sameKey(key, policy.outputOpeningPublicKey)) { "phone attestor must differ from resolver and opener" }
        }
    }
    private fun sameKey(a: String, b: String): Boolean {
        val first = requireNotNull(decodePublicKeyLiteral(a))
        val second = requireNotNull(decodePublicKeyLiteral(b))
        return first.curveId == second.curveId && first.keyBytes.contentEquals(second.keyBytes)
    }
    fun modelHashLiteral(value: String): String {
        require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) { "Model hash must retain exact raw32 lower hex" }
        val bytes = ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        require((bytes.last().toInt() and 1) == 1) { "Model hash marker must already be set" }
        return HashLiteral.canonicalize(bytes)
    }
    fun rawModelHash(value: String): String {
        val bytes = HashLiteral.decode(value)
        require((bytes.last().toInt() and 1) == 1 && HashLiteral.canonicalize(bytes) == value) { "Model hash must be its exact checked literal" }
        return bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    fun rawHash32(value: String, path: String): String {
        require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) { "$path must be exact lower raw32 hex" }
        require(value.last() in "13579bdf") { "$path requires the existing Model hash marker" }
        return value
    }
    fun rawSignature(value: String, path: String): String {
        require(value.isNotEmpty() && value.length <= 2 * CanonicalRequestSigner.CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 && value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' }) { "$path must be exact lower signature hex" }
        return value
    }
    fun rawNetworkId(value: String): NetworkId {
        require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) { "network_id must be exact lowercase raw32 hex" }
        return NetworkId.fromBytes(ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() })
    }
    fun rawNetworkHex(value: NetworkId): String = value.bytes().joinToString("") { "%02x".format(it.toInt() and 255) }
    fun originalLease(opened: Long, expires: Long?) {
        require(opened > 0 && expires != null && expires > opened && expires - opened <= 120_000) { "original owner opening requires its exact bounded lease" }
    }
}
