package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral
import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm

/** Client-side verification helper for identifier-resolution receipts. */
object IdentifierReceiptVerifier {
    @JvmStatic
    fun verifyResolverSignature(receipt: IdentifierResolutionReceipt, policy: IdentifierPolicySummary, intendedNetworkId: NetworkId): Boolean {
        require(receipt.payload.networkId == intendedNetworkId) { "receipt network differs from the independently intended network" }
        requireExactPolicyId(policy.policyId)
        require(receipt.policyId == policy.policyId) {
            "receipt policyId does not match the supplied policy"
        }
        require(receipt.attestation.kind == "signed") {
            "only signed identifier receipt attestations can be verified with a resolver public key"
        }
        val payloadBytes = IdentifierReceiptCanonicalEncoder.encodePayload(receipt.payload)
        val message = IrohaHash.prehash(payloadBytes)
        val signatureBytes = hexToBytes(
            requireNotNull(receipt.attestation.signature) {
                "signed attestation is missing signature"
            },
            "attestation.signature",
        )
        val keyPayload = decodePublicKeyLiteral(requireExactResolverPublicKey(policy.resolverPublicKey))
            ?: throw IllegalArgumentException("resolverPublicKey is not a valid multihash literal")
        return when (keyPayload.curveId) {
            0x01 -> verifyEd25519(keyPayload.keyBytes, message, signatureBytes)
            else -> verifyNativeBacked(keyPayload.curveId, keyPayload.keyBytes, message, signatureBytes)
        }
    }

    internal fun verifyExecutionResolverSignature(response: RamLfeExecuteResponse, policy: RamLfeProgramPolicySummary): Boolean {
        require(policy.active && policy.programId == response.programId && policy.backend == IdentifierOwnerInputV1.BACKEND && policy.verificationMode == "signed") { "Execute receipt differs from the independently selected current program policy" }
        val key = requireNotNull(decodePublicKeyLiteral(requireExactResolverPublicKey(policy.resolverPublicKey))) { "resolverPublicKey is not its current canonical multihash" }
        val message = IrohaHash.prehash(IdentifierReceiptCanonicalEncoder.encodeExecution(response.execution))
        val signature = hexToBytes(
            IdentifierOwnerInputV1.rawSignature(requireNotNull(response.attestation.signature), "attestation.signature"),
            "attestation.signature",
        )
        return when (key.curveId) {
            0x01 -> signature.size == 64 && verifyEd25519(key.keyBytes, message, signature)
            0x02 -> signature.size == 3309 && verifyNativeBacked(key.curveId, key.keyBytes, message, signature)
            else -> false
        }
    }

    private fun requireExactResolverPublicKey(literal: String): String {
        require(literal.isNotBlank()) { "resolverPublicKey must not be empty" }
        require(literal.trim() == literal) { "resolverPublicKey must not contain surrounding whitespace" }
        return literal
    }

    private fun requireExactPolicyId(literal: String): String {
        require(literal.isNotBlank()) { "policy.policy_id must not be empty" }
        require(literal.trim() == literal) { "policy.policy_id must not contain surrounding whitespace" }
        return literal
    }

    private fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (!Ed25519PublicKeyAdmission.isValid(publicKey)) return false
        try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            return verifier.verifySignature(signature)
        } catch (ex: Exception) {
            return false
        }
    }

    private fun verifyNativeBacked(
        curveId: Int,
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val algorithm = signingAlgorithmForCurveId(curveId) ?: return false
        if (!NativeSignerBridge.isNativeAvailable()) return false
        return try {
            NativeSignerBridge.verifyDetached(algorithm, publicKey, message, signature)
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun signingAlgorithmForCurveId(curveId: Int): SigningAlgorithm? = when (curveId) {
        0x02 -> SigningAlgorithm.ML_DSA
        0x03 -> SigningAlgorithm.BLS_NORMAL
        0x04 -> SigningAlgorithm.SECP256K1
        0x05 -> SigningAlgorithm.BLS_SMALL
        0x0A -> SigningAlgorithm.GOST_2012_256_A
        0x0B -> SigningAlgorithm.GOST_2012_256_B
        0x0C -> SigningAlgorithm.GOST_2012_256_C
        0x0D -> SigningAlgorithm.GOST_2012_512_A
        0x0E -> SigningAlgorithm.GOST_2012_512_B
        0x0F -> SigningAlgorithm.SM2
        else -> null
    }

    private fun hexToBytes(hex: String, field: String): ByteArray {
        // Model Signature JSON and the shared Rust receipt vectors use uppercase
        // hex. Owner execution carriers retain their separate lowercase grammar.
        require(hex.isNotEmpty() &&
            hex.length <= 2 * CanonicalRequestSigner.CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 &&
            hex.length % 2 == 0 &&
            hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            "$field must be exact signature hex"
        }
        return ByteArray(hex.length / 2) { index -> hex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
