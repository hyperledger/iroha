package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Native-imported Global checkpoint selection, authenticated by independently selected pins. */
class VerifiedFiCheckpointSelection private constructor(
    val height: BigInteger,
    val contextIdHex: String,
    val blockHashHex: String,
) {
    val contextIdBytes: ByteArray get() = decodeHex(contextIdHex)
    val blockHashBytes: ByteArray get() = decodeHex(blockHashHex)
    override fun toString(): String = "VerifiedFiCheckpointSelection(redacted)"

    companion object {
        internal fun fromNativeJSON(bytes: ByteArray): VerifiedFiCheckpointSelection {
            require(bytes.isNotEmpty() && bytes.size <= 1024) { "Invalid native checkpoint metadata size" }
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
            val fields = JsonParser.parse(text) as? Map<*, *>
                ?: throw IllegalArgumentException("Native checkpoint metadata must be an object")
            require(fields.keys == setOf("height", "context_id", "block_hash")) {
                "Invalid native checkpoint metadata fields"
            }
            val heightText = fields["height"] as? String
                ?: throw IllegalArgumentException("Native checkpoint height must be decimal text")
            require(Regex("[1-9][0-9]{0,19}").matches(heightText)) { "Noncanonical native checkpoint height" }
            val height = BigInteger(heightText)
            require(height.signum() > 0 && height < BigInteger.ONE.shiftLeft(64) - BigInteger.ONE) {
                "Invalid native checkpoint height"
            }
            fun hash(name: String): String {
                val value = fields[name] as? String
                    ?: throw IllegalArgumentException("Native checkpoint hash must be text")
                require(Regex("[0-9a-f]{64}").matches(value) &&
                    (value.last().digitToInt(16) and 1) == 1 && value != "0".repeat(63) + "1") {
                    "Invalid native checkpoint hash"
                }
                return value
            }
            return VerifiedFiCheckpointSelection(height, hash("context_id"), hash("block_hash"))
        }

        private fun decodeHex(value: String): ByteArray = ByteArray(32) {
            value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }
}

/** Native checkpoint import for an independently admitted manifest's exact byte/height/context pins. */
class NativeFinalityCheckpointBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private val nativeAvailable: Boolean = try {
            System.loadLibrary(LIBRARY_NAME)
            nativeBridgeAbiVersion() == 31 && nativeVerifierContractVersion() == 1
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }

        @JvmStatic fun isNativeAvailable(): Boolean = nativeAvailable

        /**
         * [expectedSha256], [expectedHeight], [expectedContextId], network and chain must come from
         * independently authenticated local state. Native verifies SHA-256 over the original bytes
         * before decoding them, imports the canonical checkpoint, and requires certified Global
         * scope plus exact selected height/context. The result does not authorize a wallet action.
         */
        @JvmStatic
        fun verifyFiCheckpointSelectionV1(
            checkpointBytes: ByteArray,
            networkId: NetworkId,
            expectedChain: String,
            expectedSha256: ByteArray,
            expectedHeight: BigInteger,
            expectedContextId: ByteArray,
        ): VerifiedFiCheckpointSelection {
            require(checkpointBytes.isNotEmpty() && checkpointBytes.size <= 68 * 1024 * 1024)
            require(expectedChain.isNotBlank() && expectedChain == expectedChain.trim() &&
                expectedChain.none { it.isISOControl() } && expectedChain.toByteArray(StandardCharsets.UTF_8).size <= 1024)
            require(expectedSha256.size == 32 && expectedSha256.any { it != 0.toByte() })
            require(expectedHeight.signum() > 0 && expectedHeight < BigInteger.ONE.shiftLeft(64) - BigInteger.ONE)
            require(expectedContextId.size == 32 && (expectedContextId[31].toInt() and 1) == 1 &&
                !(expectedContextId.take(31).all { it == 0.toByte() } && expectedContextId[31] == 1.toByte()))
            val checkpoint = checkpointBytes.copyOf()
            val digest = expectedSha256.copyOf()
            val context = expectedContextId.copyOf()
            check(nativeAvailable) { "$LIBRARY_NAME checkpoint selection verifier is unavailable" }
            val result = checkNotNull(nativeVerifyFiCheckpointSelectionV1(checkpoint,
                networkId.literal.toByteArray(StandardCharsets.UTF_8), expectedChain.toByteArray(StandardCharsets.UTF_8),
                digest, expectedHeight.toString().toByteArray(StandardCharsets.UTF_8), context)) {
                "Native checkpoint selection verifier returned no result"
            }
            return VerifiedFiCheckpointSelection.fromNativeJSON(result).also {
                require(it.height == expectedHeight && it.contextIdBytes.contentEquals(context)) {
                    "Native checkpoint selection differs from the selected pins"
                }
            }
        }

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeVerifierContractVersion(): Int
        @JvmStatic private external fun nativeVerifyFiCheckpointSelectionV1(
            checkpoint: ByteArray, networkId: ByteArray, expectedChain: ByteArray,
            expectedSha256: ByteArray, expectedHeight: ByteArray, expectedContextId: ByteArray,
        ): ByteArray?
    }
}
