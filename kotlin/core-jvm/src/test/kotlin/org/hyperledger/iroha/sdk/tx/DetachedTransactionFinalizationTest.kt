package org.hyperledger.iroha.sdk.tx

import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

class DetachedTransactionFinalizationTest {
    private val payload = "11".repeat(32)
    private val transaction = "33".repeat(32)
    private val json = """{"schema":"iroha.detached_transaction_finalization.v1","payload_signing_hash_hex":"$payload","transaction_hash_hex":"$transaction","entrypoint_hash_hex":"$transaction"}"""

    @Test fun exactNativeMetadataAndSignedWireAreRetainedDefensively() {
        val signed = byteArrayOf(1, 2, 3)
        val value = DetachedTransactionFinalization.fromNative(signed, json.toByteArray())
        signed[0] = 9
        value.signedTransactionBytes[1] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), value.signedTransactionBytes)
        assertEquals(payload, value.payloadSigningHashHex)
        assertEquals(transaction, value.transactionHashHex)
        assertEquals(transaction, value.entrypointHashHex)
        assertEquals("DetachedTransactionFinalization(redacted)", value.toString())
    }

    @Test fun nativeMetadataRejectsUnknownMissingDuplicateOrMistypedFields() {
        for (invalid in listOf(
            json.replace(".v1", ".v2"),
            json.replace("{", "{\"unknown\":1,"),
            json.replace("\"schema\":", "\"schema\":\"duplicate\",\"schema\":"),
            json.replace("\"entrypoint_hash_hex\":\"$transaction\"", "\"entrypoint_hash_hex\":12"),
            json.replace(",\"entrypoint_hash_hex\":\"$transaction\"", ""),
        )) assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(1), invalid.toByteArray()) }
    }

    @Test fun hashesMustBeCanonicalMarkedAndConsistent() {
        for (invalid in listOf(
            json.replace(payload, "AA".repeat(32)),
            json.replace(payload, "22".repeat(32)),
            json.replace(payload, "11"),
            json.replace("\"entrypoint_hash_hex\":\"$transaction\"", "\"entrypoint_hash_hex\":\"${"55".repeat(32)}\""),
        )) assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(1), invalid.toByteArray()) }
    }

    @Test fun outputBoundsAndMalformedUtf8AreRejected() {
        assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(), json.toByteArray()) }
        assertFails { DetachedTransactionFinalization.fromNative(ByteArray(16 * 1024 * 1024 + 1), json.toByteArray()) }
        assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(1), byteArrayOf()) }
        assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(1), ByteArray(4097)) }
        assertFails { DetachedTransactionFinalization.fromNative(byteArrayOf(1), byteArrayOf(0xc3.toByte(), 0x28)) }
    }

    @Test fun finalizerRejectsInvalidInputBoundsBeforeEnteringJni() {
        val publicKey = ByteArray(32)
        val signature = ByteArray(64)
        assertFailsWith<IllegalArgumentException> { NativeSignerBridge.finalizeDetachedTransactionScaffold(byteArrayOf(), publicKey, signature) }
        assertFailsWith<IllegalArgumentException> { NativeSignerBridge.finalizeDetachedTransactionScaffold(ByteArray(16 * 1024 * 1024 + 1), publicKey, signature) }
        for (length in listOf(0, 31, 33)) assertFailsWith<IllegalArgumentException> {
            NativeSignerBridge.finalizeDetachedTransactionScaffold(byteArrayOf(1), ByteArray(length), signature)
        }
        for (length in listOf(0, 63, 65)) assertFailsWith<IllegalArgumentException> {
            NativeSignerBridge.finalizeDetachedTransactionScaffold(byteArrayOf(1), publicKey, ByteArray(length))
        }
    }
}
