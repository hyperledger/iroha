package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.security.MessageDigest
import org.hyperledger.iroha.sdk.core.model.NetworkId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Metadata fixtures authenticate no proof. Genuine page positives are in the native C suite. */
class NativeFinalityCheckpointAdvanceBridgeTest {
    private val network = NetworkId.fromBytes(ByteArray(32) { 0x11 })
    private val checkpoint = byteArrayOf(1, 2, 3)
    private val sha = MessageDigest.getInstance("SHA-256").digest(checkpoint)
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun metadata(): Map<String, Any?> = mapOf(
        "schema" to "iroha.fi-checkpoint-advance.verified.v1", "networkId" to network.literal,
        "chainId" to "chain", "anchorHeight" to "9007199254740993", "height" to "9007199254740995",
        "proofCount" to "3", "checkpointSha256" to hex(sha), "contextId" to "33".repeat(32), "blockHash" to "55".repeat(32))
    private fun decode(fields: Map<String, Any?> = metadata(), bytes: ByteArray = checkpoint) =
        VerifiedFiCheckpointAdvance.fromNativeResult(bytes, JsonEncoder.encode(fields).toByteArray(),
            network, "chain", BigInteger("9007199254740993"), 3)

    @Test fun typedAdvanceRetainsExactCheckpointAndLosslessMetadataWithDefensiveCopies() {
        val bytes = checkpoint.copyOf(); val value = decode(bytes = bytes); bytes.fill(0)
        value.checkpointBytes.fill(0); value.contextId.fill(0); value.blockHash.fill(0); value.checkpointSha256.fill(0)
        assertContentEquals(checkpoint, value.checkpointBytes); assertContentEquals(sha, value.checkpointSha256)
        assertEquals(BigInteger("9007199254740995"), value.height)
        assertEquals(BigInteger("9007199254740993"), value.anchorHeight)
        assertEquals(3, value.proofCount); assertEquals(network, value.networkId)
    }

    @Test fun typedAdvanceRejectsSubstitutedCheckpointUnknownFieldsAndMismatchedLocalPins() {
        for (fields in listOf(metadata() + ("unknown" to null), metadata() - "contextId",
            metadata() + ("height" to "9007199254740994"), metadata() + ("proofCount" to 3),
            metadata() + ("chainId" to "other"), metadata() + ("anchorHeight" to "2"),
            metadata() + ("contextId" to "22".repeat(32)), metadata() + ("checkpointSha256" to "AA".repeat(32)))) {
            assertFails { decode(fields) }
        }
        assertFails { decode(bytes = byteArrayOf(4, 5, 6)) }
        assertFails { VerifiedFiCheckpointAdvance.fromNativeResult(checkpoint, ByteArray(4097), network, "chain", BigInteger.TEN, 3) }
    }

    @Test fun inputBoundsSingleFrameAndWrongOriginalDigestFailBeforeNativeCall() {
        fun verify(frames: List<ByteArray> = listOf(byteArrayOf(1), byteArrayOf(2)),
            bytes: ByteArray = checkpoint, digest: ByteArray = sha) =
            NativeFinalityCheckpointAdvanceBridge.advanceFiCheckpointV1(bytes, frames, network, "chain",
                digest, BigInteger.valueOf(2), ByteArray(32) { 0x33 })
        assertFailsWith<IllegalArgumentException> { verify(frames = emptyList()) }
        assertFailsWith<IllegalArgumentException> { verify(frames = listOf(byteArrayOf(1))) }
        assertFailsWith<IllegalArgumentException> { verify(frames = List(4097) { byteArrayOf(1) }) }
        assertFailsWith<IllegalArgumentException> { verify(frames = listOf(ByteArray(16 * 1024 * 1024), byteArrayOf(1))) }
        assertFailsWith<IllegalArgumentException> { verify(frames = listOf(byteArrayOf(), byteArrayOf(1))) }
        assertFailsWith<IllegalArgumentException> { verify(bytes = byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { verify(digest = ByteArray(32) { 0x55 }) }
    }

    @Test fun realJniRejectsMalformedFramesUnderMatchingRetainedCheckpointDigest() {
        assertTrue(NativeFinalityCheckpointAdvanceBridge.isNativeAvailable(), "Requires qualified checkpoint advance JNI producer")
        assertFailsWith<IllegalArgumentException> {
            NativeFinalityCheckpointAdvanceBridge.advanceFiCheckpointV1(checkpoint,
                listOf(byteArrayOf(1), byteArrayOf(2)), network, "chain", sha,
                BigInteger.valueOf(2), ByteArray(32) { 0x33 })
        }
    }
}
