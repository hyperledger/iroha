package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ConfidentialProverTests {
    internal class Backend : ConfidentialProverBackend {
        var created = 0
        var closed = false
        var jobsClosed = 0
        val noteArrays = mutableListOf<ByteArray>()
        val inputValues = mutableListOf<Triple<Long, Long, Long>>()
        var entered: CountDownLatch? = null
        var resume: CountDownLatch? = null
        var inputStatus = 0
        override fun create(network: ByteArray, asset: ByteArray, key: ByteArray) = 1L
        override fun close(handle: Long): Int { closed = true; return 0 }
        override fun jobCreate(handle: Long, operation: Int, root: ByteArray, low: Long, high: Long): Long { created++; return 2L }
        override fun jobInput(job: Long, low: Long, high: Long, rho: ByteArray, diversifier: ByteArray, index: Long): Int { noteArrays.add(rho); noteArrays.add(diversifier); inputValues.add(Triple(low, high, index)); return inputStatus }
        override fun jobOutput(job: Long, low: Long, high: Long, rho: ByteArray, owner: ByteArray): Int { noteArrays.add(rho); noteArrays.add(owner); return 0 }
        override fun jobCommitments(job: Long, leaves: ByteArray) = 0
        override fun jobPaths(job: Long, siblings: ByteArray, directions: ByteArray) = 0
        override fun jobProve(job: Long): ByteArray {
            entered?.countDown()
            check(resume?.await(5, TimeUnit.SECONDS) != false)
            return result()
        }
        override fun jobClose(job: Long): Int { jobsClosed++; return 0 }
    }
    private fun input() = ConfidentialInputNote(BigInteger.valueOf(42), ByteArray(32) { 7 }, ByteArray(32) { 9 }, 0)
    private fun tree() = ConfidentialTreeEvidence.Commitments(ByteArray(32) { 1 }, listOf(ByteArray(32) { 2 }))
    companion object {
        private fun result(): ByteArray {
            val word = "01".repeat(32)
            return """{"relation":"confidential_full_unshield","backend":"pipa-r/pasta","proof_hex":"abcd","root_hex":"$word","nullifiers_hex":["$word"],"output_commitments_hex":[]}""".toByteArray(StandardCharsets.UTF_8)
        }
    }
    @Test fun acceptedBackgroundWorkSurvivesCloseAndClearsConsumedInputs() {
        val backend = Backend()
        backend.entered = CountDownLatch(1); backend.resume = CountDownLatch(1)
        val prover = ConfidentialProver(1, backend)
        val output = AtomicReference<ConfidentialProof>()
        val failure = AtomicReference<Throwable>()
        val worker = Thread {
            try { output.set(prover.proveUnshield(tree(), listOf(input()), BigInteger.valueOf(42))) }
            catch (error: Throwable) { failure.set(error) }
        }
        worker.start()
        assertTrue(backend.entered!!.await(5, TimeUnit.SECONDS))
        prover.close()
        assertTrue(backend.closed)
        backend.resume!!.countDown(); worker.join(5000)
        assertFalse(worker.isAlive); assertNull(failure.get())
        assertEquals(ConfidentialProof.Relation.FULL_REDEMPTION, output.get().relation)
        assertTrue(backend.noteArrays.all { bytes -> bytes.all { it == 0.toByte() } })
        val error = assertThrows(ConfidentialProverException::class.java) { prover.proveUnshield(tree(), listOf(input()), BigInteger.ONE) }
        assertEquals(-2, error.code); assertEquals(1, backend.created)
        prover.close()
    }
    @Test fun malformedCountsRejectBeforeNativeJobAndConsumeNotes() {
        val backend = Backend(); val prover = ConfidentialProver(1, backend)
        val note = input()
        val error = assertThrows(ConfidentialProverException::class.java) {
            prover.proveTransfer(tree(), listOf(note), emptyList())
        }
        assertEquals(-18, error.code); assertEquals(0, backend.created)
        assertThrows(ConfidentialProverException::class.java) { note.append(backend, 2) }
        prover.close()
    }
    @Test fun nativeFailureClosesJobAndClearsEveryCopiedNoteField() {
        val backend = Backend(); backend.inputStatus = -16
        val prover = ConfidentialProver(1, backend)
        val error = assertThrows(ConfidentialProverException::class.java) {
            prover.proveUnshield(tree(), listOf(input()), BigInteger.ONE)
        }
        assertEquals(-16, error.code); assertEquals(1, backend.jobsClosed)
        assertTrue(error.message!!.contains("directions do not match"))
        assertTrue(backend.noteArrays.all { bytes -> bytes.all { it == 0.toByte() } })
        prover.close()
    }
    @Test fun typedInputsEnforceU128AndPublicOutputsCopyTheirArrays() {
        assertThrows(IllegalArgumentException::class.java) { ConfidentialInputNote(BigInteger.ONE.shiftLeft(128), ByteArray(32), ByteArray(32), 0) }
        assertThrows(IllegalArgumentException::class.java) { ConfidentialInputNote(BigInteger.ONE, ByteArray(32), ByteArray(32), 65_536) }
        val output = ConfidentialProof.decode(result())
        val proof = output.proof; proof[0] = 0
        assertEquals(0xab.toByte(), output.proof[0])
        val nullifier = output.nullifiers[0]; nullifier[0] = 0
        assertEquals(1.toByte(), output.nullifiers[0][0])
        assertEquals("ConfidentialInputNote([REDACTED])", input().use { it.toString() })
    }
    @Test fun fullCapacityTreeAndOnePathUseOnlyActualInputs() {
        ConfidentialTreeEvidence.Commitments(ByteArray(32), List(65_536) { ByteArray(32) }).use { }
        assertThrows(IllegalArgumentException::class.java) {
            ConfidentialTreeEvidence.Commitments(ByteArray(32), List(65_537) { ByteArray(32) })
        }
        val path = ZkAssetMerklePath(0, List(16) { ByteArray(32) }, ByteArray(16), ByteArray(32), 0)
        ConfidentialTreeEvidence.Paths(ByteArray(32), listOf(path)).use { evidence ->
            val backend = Backend(); evidence.append(backend, 2, 1)
            assertEquals(-13, assertThrows(ConfidentialProverException::class.java) { evidence.append(backend, 2, 2) }.code)
        }
    }
    @Test fun missingOrMismatchedNativeContractHasStableErrorWithoutInitializationPoison() {
        assertEquals(-101, assertThrows(ConfidentialProverException::class.java) {
            requireConfidentialNativeContract(false) { error("revision must not be read") }
        }.code)
        assertEquals(-101, assertThrows(ConfidentialProverException::class.java) {
            requireConfidentialNativeContract(true) { throw UnsatisfiedLinkError("missing symbol") }
        }.code)
        assertEquals(-101, assertThrows(ConfidentialProverException::class.java) {
            requireConfidentialNativeContract(true) { 2 }
        }.code)
        requireConfidentialNativeContract(true) { 1 }
    }

    @Test fun changeConversionPreservesUnsignedLimbsAndIndependentOwnedCopies() {
        val amount = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
        val rho = ByteArray(32) { 7 }
        val change = ConfidentialChangeNote(amount, rho)
        val suppliedDefault = ByteArray(32) { 3 }
        val first = change.toInputWithDefault(65_535) { suppliedDefault }
        assertTrue(suppliedDefault.all { it == 0.toByte() })
        rho.fill(0)
        val firstBackend = Backend()
        first.append(firstBackend, 2)
        assertEquals(listOf(Triple(-1L, -1L, 65_535L)), firstBackend.inputValues)
        assertArrayEquals(ByteArray(32) { 7 }, firstBackend.noteArrays[0])
        assertArrayEquals(ByteArray(32) { 3 }, firstBackend.noteArrays[1])
        first.close()
        assertTrue(firstBackend.noteArrays.all { bytes -> bytes.all { it == 0.toByte() } })
        val second = change.toInputWithDefault(0) { ByteArray(32) { 3 } }
        change.close()
        val secondBackend = Backend()
        second.append(secondBackend, 2)
        assertEquals(listOf(Triple(-1L, -1L, 0L)), secondBackend.inputValues)
        assertArrayEquals(ByteArray(32) { 7 }, secondBackend.noteArrays[0])
        assertArrayEquals(ByteArray(32) { 3 }, secondBackend.noteArrays[1])
        second.close()
        assertTrue(secondBackend.noteArrays.all { bytes -> bytes.all { it == 0.toByte() } })
        assertEquals(-2, assertThrows(ConfidentialProverException::class.java) {
            change.toInputWithDefault(0) { error("closed opening must not call native") }
        }.code)
    }
    @Test fun changeConversionRejectsIndexBeforeNativeAndClearsMalformedNativeResult() {
        ConfidentialChangeNote(BigInteger.ONE, ByteArray(32)).use { change ->
            for (index in listOf(-1, 65_536)) {
                assertThrows(IllegalArgumentException::class.java) {
                    change.toInputWithDefault(index) { error("invalid index must not call native") }
                }
            }
            val malformed = ByteArray(31) { 9 }
            assertThrows(IllegalArgumentException::class.java) { change.toInputWithDefault(0) { malformed } }
            assertTrue(malformed.all { it == 0.toByte() })
        }
    }

    @Test fun nativeResultRejectsRetiredOrAlternateBackend() {
        val word = "11".repeat(32)
        val valid = """{"relation":"confidential_full_unshield","backend":"pipa-r/pasta","proof_hex":"01","root_hex":"$word","nullifiers_hex":["$word"],"output_commitments_hex":[]}""".toByteArray()
        assertEquals("pipa-r/pasta", ConfidentialProof.decode(valid).backend)
        for (backend in listOf("halo2/ipa", "halo2/pasta/confidential-unshield-full-merkle16-axiom-poseidon-v3", "pipa-r/pasta/confidential-unshield-full-v1", " pipa-r/pasta")) {
            val changed = String(valid, Charsets.UTF_8).replace("pipa-r/pasta", backend).toByteArray()
            assertThrows(IllegalArgumentException::class.java) { ConfidentialProof.decode(changed) }
        }
    }

}
