package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Authenticated historical Global successor; persistence remains guarded by the caller's owner/runtime lease. */
class VerifiedFiCheckpointAdvance private constructor(
    val networkId: NetworkId,
    val chainId: String,
    val anchorHeight: BigInteger,
    val height: BigInteger,
    val proofCount: Int,
    val checkpointSha256Hex: String,
    val contextIdHex: String,
    val blockHashHex: String,
    checkpoint: ByteArray,
) {
    private val retainedCheckpoint = checkpoint.copyOf()
    val checkpointBytes: ByteArray get() = retainedCheckpoint.copyOf()
    val checkpointSha256: ByteArray get() = AdvanceWire.decodeHex(checkpointSha256Hex)
    val contextId: ByteArray get() = AdvanceWire.decodeHex(contextIdHex)
    val blockHash: ByteArray get() = AdvanceWire.decodeHex(blockHashHex)
    override fun toString(): String = "VerifiedFiCheckpointAdvance(redacted)"

    companion object {
        internal fun fromNativeResult(checkpoint: ByteArray, metadata: ByteArray,
            expectedNetwork: NetworkId, expectedChain: String, expectedHeight: BigInteger,
            expectedProofCount: Int): VerifiedFiCheckpointAdvance {
            require(checkpoint.isNotEmpty() && checkpoint.size <= 68 * 1024 * 1024)
            val fields = JsonParser.parse(AdvanceWire.utf8(metadata, 4096)) as? Map<*, *>
                ?: throw IllegalArgumentException("Native checkpoint advance metadata must be an object")
            require(fields.keys == setOf("schema", "networkId", "chainId", "anchorHeight", "height",
                "proofCount", "checkpointSha256", "contextId", "blockHash"))
            fun text(key: String): String = fields[key] as? String
                ?: throw IllegalArgumentException("Native checkpoint advance fields must be text")
            require(text("schema") == "iroha.fi-checkpoint-advance.verified.v1")
            require(text("networkId") == expectedNetwork.literal && text("chainId") == expectedChain)
            val anchor = AdvanceWire.u64(text("anchorHeight")); val height = AdvanceWire.u64(text("height"))
            require(anchor == expectedHeight && expectedProofCount in 2..4096)
            require(height > anchor && height < AdvanceWire.U64_MAX &&
                height == anchor + BigInteger.valueOf(expectedProofCount.toLong() - 1))
            require(text("proofCount") == expectedProofCount.toString())
            val digest = text("checkpointSha256").also(AdvanceWire::hex32)
            require(digest == AdvanceWire.raw32(MessageDigest.getInstance("SHA-256").digest(checkpoint)))
            val context = text("contextId").also { AdvanceWire.marked32(AdvanceWire.decodeHex(it)) }
            val block = text("blockHash").also { AdvanceWire.marked32(AdvanceWire.decodeHex(it)) }
            return VerifiedFiCheckpointAdvance(expectedNetwork, expectedChain, anchor, height,
                expectedProofCount, digest, context, block, checkpoint)
        }
    }
}

/** Reuses native consecutive-page verification; no network, persistence or current FI evidence grant. */
class NativeFinalityCheckpointAdvanceBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private val nativeAvailable: Boolean = try {
            System.loadLibrary(LIBRARY_NAME)
            nativeBridgeAbiVersion() == 31 && nativeVerifierContractVersion() == 1
        } catch (_: UnsatisfiedLinkError) { false } catch (_: SecurityException) { false }
        @JvmStatic fun isNativeAvailable(): Boolean = nativeAvailable

        /**
         * [proofFrames] are exact canonical SumeragiFinalityProof originals, beginning with the
         * retained checkpoint decision and containing at least one consecutive successor. Keep
         * earlier original-request floors/challenges/keys unchanged across this independent advance.
         * Compare owner/runtime lease again before persisting the returned verified checkpoint.
         */
        @JvmStatic
        fun advanceFiCheckpointV1(
            checkpointBytes: ByteArray,
            proofFrames: List<ByteArray>,
            networkId: NetworkId,
            expectedChain: String,
            expectedSha256: ByteArray,
            expectedHeight: BigInteger,
            expectedContextId: ByteArray,
        ): VerifiedFiCheckpointAdvance {
            require(checkpointBytes.isNotEmpty() && checkpointBytes.size <= 68 * 1024 * 1024)
            require(proofFrames.size in 2..4096)
            AdvanceWire.text(expectedChain, 1024)
            val sha = AdvanceWire.raw32(expectedSha256)
            val context = AdvanceWire.marked32(expectedContextId)
            require(expectedHeight.signum() > 0 && expectedHeight < AdvanceWire.U64_MAX)
            val selectedFrames = proofFrames.toList()
            require(selectedFrames.size in 2..4096)
            var total = 0L
            selectedFrames.forEach {
                require(it.isNotEmpty()); total += it.size.toLong()
                require(total <= 16 * 1024 * 1024) { "Native proof frames exceed the existing page limit" }
            }
            val capturedFrames = selectedFrames.map { it.copyOf() }.toTypedArray()
            val checkpoint = checkpointBytes.copyOf()
            require(AdvanceWire.raw32(MessageDigest.getInstance("SHA-256").digest(checkpoint)) == sha)
            check(nativeAvailable) { "$LIBRARY_NAME checkpoint advance verifier is unavailable" }
            val result = checkNotNull(nativeAdvanceFiCheckpointV1(checkpoint, capturedFrames,
                networkId.literal.toByteArray(StandardCharsets.UTF_8), expectedChain.toByteArray(StandardCharsets.UTF_8),
                AdvanceWire.decodeHex(sha), expectedHeight.toString().toByteArray(StandardCharsets.UTF_8),
                AdvanceWire.decodeHex(context))) { "Native checkpoint advance returned no result" }
            require(result.size == 2) { "Native checkpoint advance output arity differs" }
            return VerifiedFiCheckpointAdvance.fromNativeResult(result[0], result[1], networkId,
                expectedChain, expectedHeight, capturedFrames.size)
        }

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeVerifierContractVersion(): Int
        @JvmStatic private external fun nativeAdvanceFiCheckpointV1(
            checkpoint: ByteArray, proofFrames: Array<ByteArray>, networkId: ByteArray,
            expectedChain: ByteArray, expectedSha256: ByteArray, expectedHeight: ByteArray,
            expectedContextId: ByteArray,
        ): Array<ByteArray>?
    }
}

private object AdvanceWire {
    val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64) - BigInteger.ONE
    fun u64(text: String): BigInteger {
        require(Regex("[1-9][0-9]{0,19}").matches(text))
        return BigInteger(text).also { require(it.signum() > 0 && it <= U64_MAX) }
    }
    fun text(value: String, maximum: Int) {
        require(value.isNotEmpty() && value.length <= maximum && value == value.trim() && value.none { it.isISOControl() })
        val encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value))
        require(encoded.remaining() <= maximum)
    }
    fun utf8(bytes: ByteArray, maximum: Int): String {
        require(bytes.isNotEmpty() && bytes.size <= maximum)
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
    fun raw32(bytes: ByteArray): String {
        require(bytes.size == 32); val captured = bytes.copyOf()
        require(captured.any { it != 0.toByte() })
        val alphabet = "0123456789abcdef"
        return buildString(64) { captured.forEach { byte ->
            val n = byte.toInt() and 255; append(alphabet[n ushr 4]); append(alphabet[n and 15])
        } }
    }
    fun hex32(value: String) { require(Regex("[0-9a-f]{64}").matches(value) && value != "0".repeat(64)) }
    fun marked32(bytes: ByteArray): String = raw32(bytes).also {
        require((it.last().digitToInt(16) and 1) == 1 && it != "0".repeat(63) + "1")
    }
    fun decodeHex(value: String): ByteArray {
        hex32(value)
        return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
