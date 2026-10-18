package org.hyperledger.iroha.sdk.crypto

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeSignerBridgeSignatureAdmissionTest {
    @Test
    fun mldsaVerifyRejectsMalformedSignatureMaterial() {
        assertTrue(
            NativeSignerBridge.isNativeAvailable(),
            "connect_norito_bridge ABI 30 is required",
        )

        val seed = ByteArray(32) { 0x44.toByte() }
        val (privateKey, publicKey) =
            NativeSignerBridge.keypairFromSeed(SigningAlgorithm.ML_DSA, seed)
        val message = IrohaHash.prehash("kotlin-ml-dsa-signature-admission".toByteArray())
        val signature = NativeSignerBridge.signDetached(SigningAlgorithm.ML_DSA, privateKey, message)

        assertTrue(
            NativeSignerBridge.verifyDetached(SigningAlgorithm.ML_DSA, publicKey, message, signature),
            "valid ML-DSA signature must verify",
        )

        val malformed = listOf(
            "short" to signature.copyOf(signature.size - 1),
            "overlong" to (signature + 0x42.toByte()),
            "all-zero" to ByteArray(signature.size),
        )
        for ((label, candidate) in malformed) {
            assertFalse(
                NativeSignerBridge.verifyDetached(SigningAlgorithm.ML_DSA, publicKey, message, candidate),
                "$label ML-DSA signature must not verify",
            )
        }
    }
}
