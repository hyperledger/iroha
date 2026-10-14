// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.Assert.*
import org.junit.Test

/** Deterministic worker boundary contracts; no clock sleeps, Native calls or device claims. */
class KagemushaEnrollmentDeadlineContractTest {
    private fun refused(code: String, body: () -> Unit) {
        try { body(); fail("expected refusal") }
        catch (failure: EnrollmentProbeFailure) { assertEquals(code, failure.code) }
    }
    @Test fun alreadyReadyInputCannotBeSelectedAtExpiry() {
        var reads = 0
        val deadline = EnrollmentProbeDeadline(100, 20, { 120 })
        refused("timeout") { deadline.select { reads++; byteArrayOf(1) } }
        assertEquals(0, reads)
    }
    @Test fun selectionThatCompletesAfterExpiryCannotReturnReadyBytes() {
        var clock = 119L
        val deadline = EnrollmentProbeDeadline(100, 20, { clock })
        refused("timeout") { deadline.select { clock = 120; byteArrayOf(1) } }
    }
    @Test fun lifecycleCancellationDuringSelectionRemainsDistinct() {
        var live = true
        val deadline = EnrollmentProbeDeadline(100, 20, { 101 }, { probeRequire(live, "lifecycle") })
        refused("lifecycle") { deadline.select { live = false; byteArrayOf(1) } }
    }
    @Test fun interruptedWorkerRefusesBeforeReadingAndPreservesFlag() {
        var reads = 0
        val deadline = EnrollmentProbeDeadline(100, 20, { 101 })
        Thread.currentThread().interrupt()
        try {
            refused("cancelled") { deadline.select { reads++; byteArrayOf(1) } }
            assertEquals(0, reads)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
    @Test fun interruptionDuringSelectionCannotReturnReadyBytes() {
        val deadline = EnrollmentProbeDeadline(100, 20, { 101 })
        try {
            refused("cancelled") { deadline.select { Thread.currentThread().interrupt(); byteArrayOf(1) } }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
    @Test fun retentionPastExpiryPreventsDispatchOrCallbackCompletion() {
        var clock = 101L
        val deadline = EnrollmentProbeDeadline(100, 20, { clock })
        val ready = byteArrayOf(1)
        assertSame(ready, deadline.select { ready })
        // The caller retains command/signature bytes after intake, before the final boundary.
        clock = 120
        var dispatched = false
        refused("timeout") { deadline.check(); dispatched = true }
        assertFalse(dispatched)
    }
    @Test fun absentPollAndReadyInputUseOneDeadlineWithoutResettingIt() {
        var clock = 101L
        val deadline = EnrollmentProbeDeadline(100, 20, { clock })
        assertNull(deadline.select<ByteArray?> { null })
        clock = 119
        val ready = byteArrayOf(1)
        assertSame(ready, deadline.select { ready })
        clock = 120
        refused("timeout") { deadline.select { ready } }
    }
    @Test fun invalidBoundsAndRegressedClockFailClosed() {
        refused("input") { EnrollmentProbeDeadline(-1, 20, { 101 }) }
        refused("input") { EnrollmentProbeDeadline(100, 0, { 101 }) }
        refused("timeout") { EnrollmentProbeDeadline(100, 20, { 99 }).check() }
    }
}
