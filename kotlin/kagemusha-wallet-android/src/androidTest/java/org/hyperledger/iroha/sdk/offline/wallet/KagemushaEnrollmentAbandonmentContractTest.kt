// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** SDK projection contracts against an explicit fake; no Native, device, issuer or ledger evidence. */
class KagemushaEnrollmentAbandonmentContractTest {
    private class Driver(private val response: (Int) -> KagemushaWalletCallV1) : KagemushaWalletEnrollmentDriverV1 {
        val selectors = mutableListOf<Int>()
        var proof = byteArrayOf()
        override fun call(handle: Long, selector: Int, first: ByteArray, second: ByteArray,
            third: ByteArray, certificates: Array<ByteArray>): KagemushaWalletCallV1 {
            assertEquals(7L, handle)
            assertTrue(second.isEmpty() && third.isEmpty() && certificates.isEmpty())
            selectors.add(selector); proof = first.copyOf()
            return response(selector)
        }
        override fun close(handle: Long) = 0
    }
    private fun owner(driver: Driver) = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1), Any(), 2)
    private fun reply(status: Int, bytes: ByteArray = byteArrayOf()) =
        KagemushaWalletCallV1(status, -1, 0, 7, 0, 0, bytes)
    private fun refused(body: () -> Unit) {
        var caught = false
        try { body() } catch (_: Exception) { caught = true }
        assertTrue("expected refusal", caught)
    }
    @Test fun localAbandonmentExportsNoLedgerOriginal() {
        val driver = Driver { reply(58) }
        val outputs = linkedMapOf<String, ByteArray>()
        owner(driver).use { selected ->
            assertEquals("native-local-abandoned", exportEnrollmentAbandonment(selected) { name, bytes -> outputs[name] = bytes })
        }
        assertEquals(listOf(10, 20), driver.selectors)
        assertEquals(setOf("abandonment.json"), outputs.keys)
        assertEquals("local", probeObject(outputs.getValue("abandonment.json")).text("form"))
        assertEquals("false", probeObject(outputs.getValue("abandonment.json")).text("ledgerFinalityClaimed"))
    }
    @Test fun signedAbandonmentPublishesExactFrameBeforeLedgerInstructionAndReplaysExactly() {
        val frame = byteArrayOf(1, 2, 3)
        val instruction = byteArrayOf(4, 5, 6)
        val driver = Driver { selector -> if (selector == 10) reply(28, frame) else reply(59, instruction) }
        val first = linkedMapOf<String, ByteArray>()
        val second = linkedMapOf<String, ByteArray>()
        owner(driver).use { selected ->
            assertEquals("native-signed-abandonment-exported", exportEnrollmentAbandonment(selected) { name, bytes -> first[name] = bytes })
            assertEquals("native-signed-abandonment-exported", exportEnrollmentAbandonment(selected) { name, bytes -> second[name] = bytes })
        }
        assertEquals(listOf("abandonment.norito", "abandonment-ledger-instruction.norito", "abandonment.json"), first.keys.toList())
        assertArrayEquals(frame, first.getValue("abandonment.norito"))
        assertArrayEquals(instruction, first.getValue("abandonment-ledger-instruction.norito"))
        first.forEach { (name, bytes) -> assertArrayEquals(bytes, second.getValue(name)) }
        assertEquals(listOf(10, 20, 10, 20), driver.selectors)
    }
    @Test fun publicationFailureStopsBeforeRequestingLedgerWrapper() {
        val driver = Driver { reply(28, byteArrayOf(1)) }
        owner(driver).use { selected ->
            refused { exportEnrollmentAbandonment(selected) { _, _ -> throw EnrollmentProbeFailure("publication") } }
        }
        assertEquals(listOf(10), driver.selectors)
    }
    @Test fun mismatchedFormKeepsSignedOriginalAndDoesNotClaimTerminalStage() {
        val driver = Driver { selector -> if (selector == 10) reply(28, byteArrayOf(1)) else reply(58) }
        val names = mutableListOf<String>()
        owner(driver).use { selected ->
            refused { exportEnrollmentAbandonment(selected) { name, _ -> names.add(name) } }
        }
        assertEquals(listOf("abandonment.norito"), names)
    }
    @Test fun nativeRefusalExportsNothing() {
        val driver = Driver { KagemushaWalletCallV1(-5, 17, 23, 0, 0, 0, byteArrayOf()) }
        val names = mutableListOf<String>()
        owner(driver).use { selected ->
            refused { exportEnrollmentAbandonment(selected) { name, _ -> names.add(name) } }
        }
        assertTrue(names.isEmpty())
        assertEquals(listOf(10), driver.selectors)
    }
    @Test fun expiredAbandonmentForwardsExactProofWithoutLedgerCallOrTimeInference() {
        val proof = byteArrayOf(7, 8, 9)
        val driver = Driver { reply(58) }
        val outputs = linkedMapOf<String, ByteArray>()
        owner(driver).use { selected ->
            assertEquals("native-expired-local-abandoned", exportExpiredEnrollmentAbandonment(selected, proof) { name, bytes -> outputs[name] = bytes })
        }
        assertEquals(listOf(21), driver.selectors)
        assertArrayEquals(proof, driver.proof)
        assertEquals(setOf("abandonment.json"), outputs.keys)
        assertEquals("expired-local", probeObject(outputs.getValue("abandonment.json")).text("form"))
        val refusedDriver = Driver { KagemushaWalletCallV1(-5, 17, 23, 0, 0, 0, byteArrayOf()) }
        owner(refusedDriver).use { selected ->
            refused { exportExpiredEnrollmentAbandonment(selected, proof) { _, _ -> throw AssertionError("Native refusal published success") } }
        }
    }
}
