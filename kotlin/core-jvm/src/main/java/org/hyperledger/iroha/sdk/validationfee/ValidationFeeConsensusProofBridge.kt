package org.hyperledger.iroha.sdk.validationfee

import org.hyperledger.iroha.sdk.core.model.NetworkId

/**
 * Native boundary for the Parliament-governed validation-fee consensus proof.
 * Independently select the complete checkpoint and persist every verified page's
 * projection and promoted checkpoint atomically before requesting another page.
 */
class ValidationFeeConsensusProofBridge private constructor() {
    /** One verified projection and its complete native checkpoint, retained together. */
    class VerifiedPolicyPage internal constructor(
        val projectionJson: String,
        promotedCheckpoint: ByteArray,
    ) {
        private val checkpoint = promotedCheckpoint.copyOf()

        init {
            require(projectionJson.isNotEmpty()) { "native proof projection must not be empty" }
            requireCheckpoint(checkpoint)
        }

        /** Return an independent copy for durable storage and the next request. */
        fun promotedCheckpoint(): ByteArray = checkpoint.copyOf()

        override fun equals(other: Any?): Boolean =
            other is VerifiedPolicyPage && projectionJson == other.projectionJson &&
                checkpoint.contentEquals(other.checkpoint)

        override fun hashCode(): Int = 31 * projectionJson.hashCode() + checkpoint.contentHashCode()
    }

    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private const val REQUIRED_BRIDGE_ABI_VERSION = 30
        private const val HASH_BYTES = 32
        private const val MAX_PROOF_BYTES = 4 * 1024 * 1024
        // Matches the canonical native checkpoint's two 32 MiB frames and 4 MiB metadata bound.
        private const val MAX_CHECKPOINT_BYTES = 68 * 1024 * 1024

        private val nativeLoadResult: Result<Unit> by lazy {
            runCatching {
                System.loadLibrary(LIBRARY_NAME)
                val actualAbi = nativeBridgeAbiVersion()
                check(actualAbi == REQUIRED_BRIDGE_ABI_VERSION) {
                    "native validation-fee consensus verifier ABI mismatch: " +
                        "expected $REQUIRED_BRIDGE_ABI_VERSION, found $actualAbi"
                }
            }
        }

        /** Encode a bounded page request using the height in the complete native checkpoint. */
        @JvmStatic
        fun encodeCurrentPolicyProofRequestV1(trustedCheckpoint: ByteArray): ByteArray {
            requireCheckpoint(trustedCheckpoint)
            requireNative()
            return nativeEncodeCurrentPolicyProofRequestV1(trustedCheckpoint.copyOf()).copyOf()
        }

        /** Verify native finality and immutable deployment pins and retain the promoted checkpoint. */
        @JvmStatic
        fun verifyCurrentPolicyProofV1(
            proofNorito: ByteArray,
            networkId: NetworkId,
            policyChainGenesisHash: ByteArray,
            trustedCheckpoint: ByteArray,
        ): VerifiedPolicyPage {
            require(proofNorito.isNotEmpty() && proofNorito.size <= MAX_PROOF_BYTES) {
                "proofNorito must contain 1..$MAX_PROOF_BYTES bytes"
            }
            requireIrohaHash(policyChainGenesisHash, "policyChainGenesisHash")
            requireCheckpoint(trustedCheckpoint)
            requireNative()
            val pair = nativeVerifyCurrentPolicyProofV1(
                proofNorito.copyOf(),
                networkId.bytes(),
                policyChainGenesisHash.copyOf(),
                trustedCheckpoint.copyOf(),
            )
            require(pair.size == 2) { "native proof verifier must return a projection and checkpoint" }
            return VerifiedPolicyPage(pair[0].toString(Charsets.UTF_8), pair[1])
        }

        internal fun requireIrohaHash(value: ByteArray, label: String) {
            require(value.size == HASH_BYTES && (value[HASH_BYTES - 1].toInt() and 1) == 1) {
                "$label must contain one canonical 32-byte Iroha hash"
            }
        }

        internal fun requireCheckpoint(value: ByteArray) {
            require(value.size in 4..MAX_CHECKPOINT_BYTES &&
                value[0] == 0x4e.toByte() && value[1] == 0x52.toByte() &&
                value[2] == 0x54.toByte() && value[3] == 0x30.toByte()) {
                "trustedCheckpoint must contain one bounded canonical native checkpoint"
            }
            // This framing preflight grants no authority; the native decoder/verifier checks all fields.
        }

        private fun requireNative() {
            nativeLoadResult.getOrElse { failure ->
                throw IllegalStateException("native validation-fee consensus verifier is unavailable", failure)
            }
        }

        @JvmStatic
        private external fun nativeBridgeAbiVersion(): Int

        @JvmStatic
        private external fun nativeEncodeCurrentPolicyProofRequestV1(trustedCheckpoint: ByteArray): ByteArray

        @JvmStatic
        private external fun nativeVerifyCurrentPolicyProofV1(
            proofNorito: ByteArray,
            networkId: ByteArray,
            policyChainGenesisHash: ByteArray,
            trustedCheckpoint: ByteArray,
        ): Array<ByteArray>
    }
}
