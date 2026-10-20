// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Actual host JNI wallet proofs through public Kotlin APIs.
 *
 * All keys and openings are fixed disposable test material, never wallet secrets.
 * These local histories do not assert ledger finality or authorize transactions.
 * The host runner binds the actual loaded JNI image and integrated source.
 * These tests do not qualify a physical device, KAGEMUSHA custody or signing.
 */
class ConfidentialFullTreeNativeTests {
    @BeforeEach
    fun requireNativeBridge() {
        assertTrue(PrivacyNativeBridge.isNativeAvailable(), "The same-source ABI-31 native bridge is required")
    }

    @Test
    fun oneInputAtFullTreeBoundaryProvesWithBothEvidenceFormats() {
        withWalletMaterial { network, key, diversifier, owner ->
            // Every occupied leaf is a genuine commitment to a disposable note.
            // The proving request below contains exactly one actual input.
            val leaves = List(TREE_CAPACITY) { index ->
                val leafRho = nonce(index)
                try { ConfidentialNoteCommitment.derive(ASSET, "7", leafRho, owner) }
                finally { leafRho.fill(0) }
            }
            val rho = nonce(LAST_INDEX)
            try {
                val selected = leaves[LAST_INDEX]
                val path = pathFor(leaves, selected)
                assertEquals(TREE_CAPACITY, leaves.size)
                assertEquals(LAST_INDEX.toLong(), path.leafIndex)
                assertEquals(TREE_CAPACITY.toLong(), path.heightOrIndex)
                assertEquals(16, path.siblings.size)
                assertTrue(path.directions.all { it.toInt() == 1 })
                assertTrue(path.verify(selected, path.rootAtHeight))
                ConfidentialProver.create(network, ASSET, key).use { prover ->
                    val complete = prover.proveUnshield(
                        ConfidentialTreeEvidence.Commitments(path.rootAtHeight, leaves),
                        listOf(ConfidentialInputNote(SEVEN, rho, diversifier, LAST_INDEX)),
                        SEVEN,
                    )
                    assertProof(complete, ConfidentialProof.Relation.FULL_REDEMPTION, path.rootAtHeight, 0)
                    val paths = prover.proveUnshield(
                        ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                        listOf(ConfidentialInputNote(SEVEN, rho, diversifier, LAST_INDEX)),
                        SEVEN,
                    )
                    assertProof(paths, ConfidentialProof.Relation.FULL_REDEMPTION, path.rootAtHeight, 0)
                    assertArrayEquals(complete.nullifiers.single(), paths.nullifiers.single())
                }
            } finally {
                rho.fill(0)
                leaves.forEach { it.fill(0) }
            }
        }
    }

    @Test
    fun retainedDefaultDiversifierChangeCanBeRedeemed() {
        withWalletMaterial { network, key, diversifier, owner ->
            val rho = nonce(0)
            val retainedChangeRho = nonce(1)
            val defaultDiversifier = ConfidentialOwnerTag.defaultDiversifier()
            try {
                assertFalse(diversifier.contentEquals(defaultDiversifier))
                val commitment = ConfidentialNoteCommitment.derive(ASSET, "7", rho, owner)
                val path = pathFor(listOf(commitment), commitment)
                ConfidentialProver.create(network, ASSET, key).use { prover ->
                    ConfidentialChangeNote(THREE, retainedChangeRho).use { change ->
                        val partial = prover.proveUnshield(
                            ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                            listOf(ConfidentialInputNote(SEVEN, rho, diversifier, 0)),
                            FOUR,
                            change,
                        )
                        assertProof(partial, ConfidentialProof.Relation.REDEMPTION_WITH_CHANGE, path.rootAtHeight, 1)
                        assertFailure(-2) { change.toInput(1) }
                        val defaultOwner = ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, defaultDiversifier)
                        val expectedChange = try {
                            ConfidentialNoteCommitment.derive(ASSET, "3", retainedChangeRho, defaultOwner)
                        } finally { defaultOwner.fill(0) }
                        assertArrayEquals(expectedChange, partial.outputCommitments.single())
                        // Retain the original leaf: the actual change is the new leaf at index 1.
                        val history = listOf(commitment, expectedChange)
                        val changePath = pathFor(history, expectedChange)
                        assertEquals(1L, changePath.leafIndex)
                        ConfidentialChangeNote(THREE, retainedChangeRho).use { restored ->
                            val redeemed = prover.proveUnshield(
                                ConfidentialTreeEvidence.Commitments(changePath.rootAtHeight, history),
                                listOf(restored.toInput(1)),
                                THREE,
                            )
                            assertProof(redeemed, ConfidentialProof.Relation.FULL_REDEMPTION, changePath.rootAtHeight, 0)
                            assertFalse(partial.nullifiers.single().contentEquals(redeemed.nullifiers.single()))
                        }
                    }
                }
            } finally {
                rho.fill(0)
                retainedChangeRho.fill(0)
                defaultDiversifier.fill(0)
            }
        }
    }

    @Test
    fun wrongRootFailsAndConsumesTheInputWithoutClosingTheProver() {
        withWalletMaterial { network, key, diversifier, owner ->
            val rho = nonce(0)
            val otherRho = nonce(1)
            try {
                val commitment = ConfidentialNoteCommitment.derive(ASSET, "7", rho, owner)
                val other = ConfidentialNoteCommitment.derive(ASSET, "7", otherRho, owner)
                val path = pathFor(listOf(commitment), commitment)
                val wrongRoot = pathFor(listOf(other), other).rootAtHeight
                assertFalse(path.rootAtHeight.contentEquals(wrongRoot))
                ConfidentialProver.create(network, ASSET, key).use { prover ->
                    ConfidentialInputNote(SEVEN, rho, diversifier, 0).use { consumed ->
                        assertFailure(-24) {
                            prover.proveUnshield(
                                ConfidentialTreeEvidence.Commitments(wrongRoot, listOf(commitment)),
                                listOf(consumed), SEVEN,
                            )
                        }
                        assertFailure(-2) {
                            prover.proveUnshield(
                                ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                                listOf(consumed), SEVEN,
                            )
                        }
                    }
                    val recovered = prover.proveUnshield(
                        ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                        listOf(ConfidentialInputNote(SEVEN, rho, diversifier, 0)),
                        SEVEN,
                    )
                    assertProof(recovered, ConfidentialProof.Relation.FULL_REDEMPTION, path.rootAtHeight, 0)
                }
            } finally { rho.fill(0); otherRho.fill(0) }
        }
    }

    @Test
    fun duplicateActualInputIsRejected() {
        withWalletMaterial { network, key, diversifier, owner ->
            val rho = nonce(0)
            try {
                val commitment = ConfidentialNoteCommitment.derive(ASSET, "7", rho, owner)
                val path = pathFor(listOf(commitment), commitment)
                ConfidentialProver.create(network, ASSET, key).use { prover ->
                    assertFailure(-17) {
                        prover.proveUnshield(
                            ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path, path)),
                            listOf(
                                ConfidentialInputNote(SEVEN, rho, diversifier, 0),
                                ConfidentialInputNote(SEVEN, rho, diversifier, 0),
                            ),
                            BigInteger.valueOf(14),
                        )
                    }
                }
            } finally { rho.fill(0) }
        }
    }

    @Test
    fun invalidPublicAmountAndChangeConservationAreRejected() {
        withWalletMaterial { network, key, diversifier, owner ->
            val rho = nonce(0)
            val changeRho = nonce(1)
            try {
                val commitment = ConfidentialNoteCommitment.derive(ASSET, "7", rho, owner)
                val path = pathFor(listOf(commitment), commitment)
                ConfidentialProver.create(network, ASSET, key).use { prover ->
                    assertFailure(-21) {
                        prover.proveUnshield(
                            ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                            listOf(ConfidentialInputNote(SEVEN, rho, diversifier, 0)),
                            BigInteger.valueOf(8),
                        )
                    }
                    ConfidentialChangeNote(BigInteger.valueOf(2), changeRho).use { change ->
                        assertFailure(-22) {
                            prover.proveUnshield(
                                ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                                listOf(ConfidentialInputNote(SEVEN, rho, diversifier, 0)),
                                FOUR, change,
                            )
                        }
                        assertFailure(-2) { change.toInput(0) }
                    }
                }
            } finally { rho.fill(0); changeRho.fill(0) }
        }
    }

    @Test
    fun closedProverRejectsARealJobAndConsumesOwnedInput() {
        withWalletMaterial { network, key, diversifier, owner ->
            val rho = nonce(0)
            try {
                val commitment = ConfidentialNoteCommitment.derive(ASSET, "7", rho, owner)
                val path = pathFor(listOf(commitment), commitment)
                ConfidentialInputNote(SEVEN, rho, diversifier, 0).use { input ->
                    ConfidentialProver.create(network, ASSET, key).use { closed ->
                        closed.close()
                        closed.close()
                        assertFailure(-2) {
                            closed.proveUnshield(
                                ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                                listOf(input), SEVEN,
                            )
                        }
                    }
                    ConfidentialProver.create(network, ASSET, key).use { live ->
                        assertFailure(-2) {
                            live.proveUnshield(
                                ConfidentialTreeEvidence.Paths(path.rootAtHeight, listOf(path)),
                                listOf(input), SEVEN,
                            )
                        }
                    }
                }
            } finally { rho.fill(0) }
        }
    }

    private fun withWalletMaterial(action: (NetworkId, ByteArray, ByteArray, ByteArray) -> Unit) {
        val key = ByteArray(32) { 94 }
        val seed = ByteArray(32) { 97 }
        var diversifier: ByteArray? = null
        var owner: ByteArray? = null
        try {
            val derivedDiversifier = ConfidentialOwnerTag.deriveDiversifier(seed)
            diversifier = derivedDiversifier
            val derivedOwner = ConfidentialOwnerTag.deriveFromSpendKeyWithDiversifier(key, derivedDiversifier)
            owner = derivedOwner
            action(NetworkId.fromBytes(ByteArray(32) { 93 }), key, derivedDiversifier, derivedOwner)
        } finally {
            key.fill(0); seed.fill(0); diversifier?.fill(0); owner?.fill(0)
        }
    }

    private fun nonce(index: Int): ByteArray = ByteArray(32).also { bytes ->
        val value = index + 1
        for (offset in 0 until 4) bytes[offset] = (value ushr (8 * offset)).toByte()
    }

    private fun pathFor(history: List<ByteArray>, selected: ByteArray): ZkAssetMerklePath =
        LocalZkAssetMerklePathProvider(emptyList(), history)
            .getMerklePathForCommitment(ASSET, selected).join()

    private fun assertProof(proof: ConfidentialProof, relation: ConfidentialProof.Relation, root: ByteArray, outputs: Int) {
        assertEquals(relation, proof.relation)
        assertEquals("pipa-r/pasta", proof.backend)
        assertTrue(proof.proof.isNotEmpty(), "A real locally verified proof is required")
        assertArrayEquals(root, proof.root)
        assertEquals(1, proof.nullifiers.size)
        assertEquals(32, proof.nullifiers.single().size)
        assertTrue(proof.nullifiers.single().any { it.toInt() != 0 })
        assertEquals(outputs, proof.outputCommitments.size)
        assertTrue(proof.outputCommitments.all { it.size == 32 })
    }

    private fun assertFailure(expectedCode: Int, operation: () -> Unit) {
        val failure = assertThrows(ConfidentialProverException::class.java) { operation() }
        assertEquals(expectedCode, failure.code)
    }

    private companion object {
        const val ASSET = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        const val TREE_CAPACITY = 65_536
        const val LAST_INDEX = 65_535
        val THREE: BigInteger = BigInteger.valueOf(3)
        val FOUR: BigInteger = BigInteger.valueOf(4)
        val SEVEN: BigInteger = BigInteger.valueOf(7)
    }
}
