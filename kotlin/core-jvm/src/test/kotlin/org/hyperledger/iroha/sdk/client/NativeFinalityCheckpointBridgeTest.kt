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

class NativeFinalityCheckpointBridgeTest {
    private val network = NetworkId.fromBytes(ByteArray(32) { 0x11 })
    private val digest = ByteArray(32) { 0x22 }
    private val context = ByteArray(32) { 0x33 }
    private val contextHex = "33".repeat(32)
    private val blockHex = "55".repeat(32)
    private val metadata = """{"height":"2","context_id":"$contextHex","block_hash":"$blockHex"}"""

    @Test fun verifiedMetadataUsesExactUnsignedHeightAndDefensiveHashCopies() {
        val value = VerifiedFiCheckpointSelection.fromNativeJSON(metadata.toByteArray())
        assertEquals(BigInteger.valueOf(2), value.height)
        assertEquals(contextHex, value.contextIdHex); assertEquals(blockHex, value.blockHashHex)
        value.contextIdBytes[0] = 0; value.blockHashBytes[0] = 0
        assertContentEquals(context, value.contextIdBytes)
        assertContentEquals(ByteArray(32) { 0x55 }, value.blockHashBytes)
        assertEquals(BigInteger.ONE, VerifiedFiCheckpointSelection.fromNativeJSON(
            metadata.replace("\"2\"", "\"1\"").toByteArray()).height)
        assertEquals(BigInteger("18446744073709551614"), VerifiedFiCheckpointSelection.fromNativeJSON(
            metadata.replace("\"2\"", "\"18446744073709551614\"").toByteArray()).height)
    }

    @Test fun metadataRejectsUnknownMissingDuplicateAndMistypedFields() {
        for (invalid in listOf(metadata.replace("{", "{\"unknown\":1,"),
            metadata.replace("\"height\":", "\"height\":\"2\",\"height\":"),
            metadata.replace("\"height\":\"2\"", "\"height\":2"),
            metadata.replace(",\"block_hash\":\"$blockHex\"", ""),
            metadata.replace(contextHex, "AA".repeat(32)), metadata.replace(contextHex, "22".repeat(32)),
            metadata.replace(blockHex, "0".repeat(63) + "1"))) {
            assertFails { VerifiedFiCheckpointSelection.fromNativeJSON(invalid.toByteArray()) }
        }
        for (height in listOf("0", "02", "+2", "2.0", "18446744073709551615", "18446744073709551616")) {
            assertFails { VerifiedFiCheckpointSelection.fromNativeJSON(metadata.replace("\"2\"", "\"$height\"").toByteArray()) }
        }
        for (invalid in listOf(byteArrayOf(), ByteArray(1025), byteArrayOf(0xc3.toByte(), 0x28))) {
            assertFails { VerifiedFiCheckpointSelection.fromNativeJSON(invalid) }
        }
    }

    @Test fun invalidSelectionBoundsFailBeforeJni() {
        fun verify(bytes: ByteArray = byteArrayOf(1), chain: String = "chain", sha: ByteArray = digest,
            height: BigInteger = BigInteger.valueOf(2), ctx: ByteArray = context) =
            NativeFinalityCheckpointBridge.verifyFiCheckpointSelectionV1(bytes, network, chain, sha, height, ctx)
        assertFailsWith<IllegalArgumentException> { verify(bytes = byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { verify(bytes = ByteArray(68 * 1024 * 1024 + 1)) }
        for (chain in listOf("", " chain", "chain\nlabel", "x".repeat(1025))) {
            assertFailsWith<IllegalArgumentException> { verify(chain = chain) }
        }
        for (sha in listOf(ByteArray(31), ByteArray(33), ByteArray(32))) {
            assertFailsWith<IllegalArgumentException> { verify(sha = sha) }
        }
        for (height in listOf(BigInteger.ZERO, BigInteger.ONE.shiftLeft(64) - BigInteger.ONE, BigInteger.ONE.shiftLeft(64))) {
            assertFailsWith<IllegalArgumentException> { verify(height = height) }
        }
        for (ctx in listOf(ByteArray(31), ByteArray(33), ByteArray(32) { 2 }, ByteArray(32).also { it[31] = 1 })) {
            assertFailsWith<IllegalArgumentException> { verify(ctx = ctx) }
        }
    }

    @Test fun nativeImportRejectsMalformedCheckpointWithBothWrongAndMatchingRawDigest() {
        assertTrue(NativeFinalityCheckpointBridge.isNativeAvailable(), "Requires the qualified checkpoint JNI producer")
        val malformed = byteArrayOf(1, 2, 3)
        for (sha in listOf(digest, MessageDigest.getInstance("SHA-256").digest(malformed))) {
            assertFailsWith<IllegalArgumentException> {
                NativeFinalityCheckpointBridge.verifyFiCheckpointSelectionV1(malformed, network, "chain", sha,
                    BigInteger.valueOf(2), context)
            }
        }
    }
}
