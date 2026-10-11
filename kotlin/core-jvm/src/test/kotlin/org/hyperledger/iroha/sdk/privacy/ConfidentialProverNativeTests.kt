package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.examples.ConfidentialRedemptionExample
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Requires the same-source rebuilt JNI library; missing exports fail rather than skip. */
class ConfidentialProverNativeTests {
    @Test fun realNativeWalletProofUsesTheCanonicalFullRedemptionRelation() {
        assertTrue(PrivacyNativeBridge.isNativeAvailable(), "rebuilt native privacy bridge is required")
        assertEquals(1, ConfidentialProverNative.revision())
        val proof = ConfidentialRedemptionExample.generateLocalProof()
        assertEquals(ConfidentialProof.Relation.FULL_REDEMPTION, proof.relation)
        assertEquals("pipa-r/pasta", proof.backend)
        assertTrue(proof.proof.isNotEmpty())
        assertEquals(1, proof.nullifiers.size)
        assertTrue(proof.outputCommitments.isEmpty())
    }
    @Test fun nativeRevisionAndMalformedHandleErrorsAreStable() {
        assertTrue(PrivacyNativeBridge.isNativeAvailable(), "rebuilt native privacy bridge is required")
        assertEquals(1, ConfidentialProverNative.revision())
        assertEquals(-2, ConfidentialProverNative.close(0))
        assertEquals(-2, ConfidentialProverNative.jobClose(0))
        val failure = assertThrows(ConfidentialProverException::class.java) { ConfidentialProverNative.jobProve(0) }
        assertEquals(-2, failure.code)
    }
    @Test fun actualNativeDefaultConvertsRetainedChangeWithoutLosingItsOpening() {
        assertTrue(PrivacyNativeBridge.isNativeAvailable(), "rebuilt native privacy bridge is required")
        val key = ByteArray(32) { 91 }
        val expected = ConfidentialOwnerTag.defaultDiversifier()
        try {
            ConfidentialChangeNote(BigInteger.valueOf(7), ByteArray(32) { 92 }).use { change ->
                change.toInput(65_535).use { input ->
                    val backend = ConfidentialProverTests.Backend()
                    input.append(backend, 2)
                    assertEquals(listOf(Triple(7L, 0L, 65_535L)), backend.inputValues)
                    assertArrayEquals(ByteArray(32) { 92 }, backend.noteArrays[0])
                    assertArrayEquals(expected, backend.noteArrays[1])
                    assertArrayEquals(
                        ConfidentialOwnerTag.deriveFromSpendKey(key),
                        ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, backend.noteArrays[1]),
                    )
                }
            }
        } finally { key.fill(0); expected.fill(0) }
    }

    @Test fun retainedChangeFromANondefaultInputCanBeRedeemed() {
        assertTrue(PrivacyNativeBridge.isNativeAvailable(), "rebuilt native privacy bridge is required")
        val asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        val network = NetworkId.fromBytes(ByteArray(32) { 93 })
        val key = ByteArray(32) { 94 }
        val rho = ByteArray(32) { 95 }
        val diversifier = ByteArray(32) { 7 }
        // A real wallet securely persists this opening before proving consumes the owner.
        val retainedChangeRho = ByteArray(32) { 96 }
        val defaultDiversifier = ConfidentialOwnerTag.defaultDiversifier()
        try {
            assertFalse(defaultDiversifier.contentEquals(diversifier))
            val owner = ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, diversifier)
            val commitment = ConfidentialNoteCommitment.derive(asset, "7", rho, owner)
            val path = LocalZkAssetMerklePathProvider(emptyList(), listOf(commitment))
                .getMerklePathForCommitment(asset, commitment).join()
            ConfidentialProver.create(network, asset, key).use { prover ->
                val change = ConfidentialChangeNote(BigInteger.valueOf(3), retainedChangeRho)
                val partial = prover.proveUnshield(
                    ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                    listOf(ConfidentialInputNote(BigInteger.valueOf(7), rho, diversifier, 0)),
                    BigInteger.valueOf(4),
                    change,
                )
                assertEquals(ConfidentialProof.Relation.REDEMPTION_WITH_CHANGE, partial.relation)
                assertEquals(1, partial.outputCommitments.size)
                val consumed = assertThrows(ConfidentialProverException::class.java) { change.toInput(0) }
                assertEquals(-2, consumed.code)
                val changeOwner = ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, defaultDiversifier)
                val expected = ConfidentialNoteCommitment.derive(asset, "3", retainedChangeRho, changeOwner)
                assertArrayEquals(expected, partial.outputCommitments.single())
                // These fixtures use a local tree. Production callers authenticate its index/root.
                val nextPath = LocalZkAssetMerklePathProvider(emptyList(), listOf(expected))
                    .getMerklePathForCommitment(asset, expected).join()
                ConfidentialChangeNote(BigInteger.valueOf(3), retainedChangeRho).use { restored ->
                    val redeemed = prover.proveUnshield(
                        ConfidentialTreeEvidence.Paths(nextPath.rootAtHeight, listOf(nextPath)),
                        listOf(restored.toInput(0)),
                        BigInteger.valueOf(3),
                    )
                    assertEquals(ConfidentialProof.Relation.FULL_REDEMPTION, redeemed.relation)
                    assertArrayEquals(nextPath.rootAtHeight, redeemed.root)
                    assertEquals(1, redeemed.nullifiers.size)
                    assertFalse(partial.nullifiers.single().contentEquals(redeemed.nullifiers.single()))
                    assertTrue(redeemed.outputCommitments.isEmpty())
                }
            }
        } finally {
            key.fill(0); rho.fill(0); diversifier.fill(0)
            retainedChangeRho.fill(0); defaultDiversifier.fill(0)
        }
    }

}
