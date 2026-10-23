package org.hyperledger.iroha.sdk.client

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.hyperledger.iroha.sdk.core.model.NetworkId

class CommittedTransactionInclusionBridgeTest {
    private val network = NetworkId.fromBytes(ByteArray(32) { if (it == 31) 1 else 0 })
    private val transaction = ByteArray(32) { if (it == 31) 1 else 0 }
    private val nonce = ByteArray(32) { 7 }

    @Test
    fun verifiedProjectionDefensivelyCopiesExactCanonicalRowAndHashes() {
        val row = byteArrayOf(0x01, 0xab.toByte(), 0xcd.toByte())
        val output = ByteArray(32) { 1 }
        val block = ByteArray(32) { 3 }
        val checkpoint = byteArrayOf(5, 7)
        val verified = VerifiedCommittedTransaction(row, output, block, 2, true, checkpoint)
        row[0] = 0
        output[0] = 0
        block[0] = 0
        checkpoint[0] = 0
        assertContentEquals(byteArrayOf(5, 7), verified.promotedCheckpointBytes)
        verified.promotedCheckpointBytes[0] = 0
        assertContentEquals(byteArrayOf(5, 7), verified.promotedCheckpointBytes)
        assertEquals("01abcd", verified.canonicalRowHex)
        assertEquals(1, verified.outputHashBytes[0].toInt())
        assertEquals(3, verified.blockHashBytes[0].toInt())
        val copy = verified.canonicalRowBytes
        copy[0] = 0
        assertContentEquals(byteArrayOf(0x01, 0xab.toByte(), 0xcd.toByte()), verified.canonicalRowBytes)
    }

    @Test
    fun malformedWalletQueryAndUntrustedVerifierInputsFailBeforeNativeCall() {
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.committedTransactionQueryPayloadHash(
                network, "wallet", transaction, 1, ByteArray(32),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.finalizeCommittedTransactionQuery(
                network, "wallet", transaction, 1, nonce, ByteArray(63),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.verify(
                byteArrayOf(1), byteArrayOf(1), network, "chain", byteArrayOf(1), ByteArray(31),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.verify(
                byteArrayOf(1), byteArrayOf(1), network, "chain", byteArrayOf(), transaction,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.verify(
                byteArrayOf(1), byteArrayOf(1), network, "", byteArrayOf(1), transaction,
            )
        }
    }

    @Test
    fun exactSuccessfulVerificationRejectsMissingAndOversizedRetainedOriginalBeforeNativeCall() {
        for (wire in listOf(byteArrayOf(), ByteArray(4 * 1024 * 1024 + 1))) {
            assertFailsWith<IllegalArgumentException> {
                CommittedTransactionInclusionBridge.verifyExactSuccessful(
                    byteArrayOf(1), byteArrayOf(1), network, "chain", byteArrayOf(1), wire,
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.verifyExactSuccessful(
                byteArrayOf(1), byteArrayOf(1), network, "chain", byteArrayOf(), byteArrayOf(1),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CommittedTransactionInclusionBridge.verifyExactSuccessful(
                byteArrayOf(1), byteArrayOf(1), network, "", byteArrayOf(1), byteArrayOf(1),
            )
        }
    }
}
