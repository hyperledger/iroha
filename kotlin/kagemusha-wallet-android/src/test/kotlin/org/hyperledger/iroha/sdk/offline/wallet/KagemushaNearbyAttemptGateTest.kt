// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame

/** Component controls only: no native completion, radio, keystore or physical-device claim. */
class KagemushaNearbyAttemptGateTest {
    @Test fun acknowledgmentNeedsNativeAdmissionAndPreservesSlowSamples() {
        val gate = KagemushaNearbyAttemptGate(false)
        assertFailsWith<IllegalStateException> { gate.dispatchMarked() }
        assertFailsWith<IllegalStateException> { gate.sendReleased() }
        gate.authorized(100); gate.dispatchMarked(); gate.sendReleased()
        assertFailsWith<IllegalStateException> { gate.creditedArrived(99) }
        gate.creditedArrived(3_000_000_100)
        assertNull(gate.elapsedNanos()); assertNull(gate.arrivalElapsedNanos())
        assertFailsWith<IllegalStateException> { gate.creditedAdmitted(200) }
        gate.creditedAdmitted(4_000_000_100)
        assertEquals(4_000_000_000, gate.elapsedNanos()); assertEquals(3_000_000_000, gate.arrivalElapsedNanos())
        assertFailsWith<IllegalStateException> { gate.creditedArrived(5_000_000_100) }
        assertFailsWith<IllegalStateException> { gate.creditedAdmitted(5_000_000_100) }
    }
    @Test fun recoveryCannotInventAuthorizationOrDispatchAgain() {
        val gate = KagemushaNearbyAttemptGate(true)
        assertFailsWith<IllegalStateException> { gate.authorized(1) }
        assertFailsWith<IllegalStateException> { gate.dispatchMarked() }
        gate.sendReleased(); gate.creditedArrived(10); gate.creditedAdmitted(20)
        assertNull(gate.elapsedNanos()); assertNull(gate.arrivalElapsedNanos())
    }
    @Test fun receiveRejectsOtherStatusesBeforeReadingRetainedOrProjectedData() {
        val requestId = ByteArray(32) { 0x31 }
        val statuses = listOf(Int.MIN_VALUE, -15, -1) + (0..59).toList() + Int.MAX_VALUE
        for (recovery in listOf(false, true)) {
            val gate = KagemushaNearbyAttemptGate(recovery)
            for (status in statuses.filter { it != 1 && !(recovery && it == 10) }) {
                var callbacks = 0
                assertFailsWith<IllegalStateException>("status $status, recovery $recovery") {
                    gate.receivedCredit(status, requestId,
                        retainedOutput = { callbacks++ },
                        projection = {
                            callbacks++
                            KagemushaNearbyAttemptGate.ReceivedCredit(true, false, byteArrayOf(0x71))
                        })
                }
                assertEquals(0, callbacks, "status must be admitted before evidence lookup")
            }
        }
    }
    @Test fun collectedReceiveRecoverySkipsRetainedOutputAndReturnsExactFreshBytes() {
        val requestId = ByteArray(32) { 0x32 }
        val fresh = byteArrayOf(0, 0x7f, 0x80.toByte(), 0xff.toByte(), 0)
        val requests = mutableListOf<ByteArray>()
        val actual = KagemushaNearbyAttemptGate(true).receivedCredit(10, requestId,
            retainedOutput = { error("collected Receive no longer has retained output") },
            projection = { selected ->
                requests.add(selected.copyOf())
                KagemushaNearbyAttemptGate.ReceivedCredit(true, false, fresh)
            })
        assertEquals(1, requests.size)
        assertContentEquals(requestId, requests.single())
        assertContentEquals(fresh, actual)
    }
    @Test fun completeReceiveCapturesOriginalReleaseBeforeReadingFreshCredit() {
        val requestId = ByteArray(32) { 0x33 }
        val retainedReceipt = byteArrayOf(0x81.toByte(), 0x82.toByte())
        val fresh = byteArrayOf(0x91.toByte(), 0x92.toByte(), 0x93.toByte())
        for (recovery in listOf(false, true)) {
            val callbacks = mutableListOf<String>()
            var captured: ByteArray? = null
            val actual = KagemushaNearbyAttemptGate(recovery).receivedCredit(1, requestId,
                retainedOutput = { selected ->
                    assertContentEquals(requestId, selected)
                    callbacks.add("retained")
                    captured = retainedReceipt.copyOf()
                },
                projection = { selected ->
                    assertContentEquals(requestId, selected)
                    callbacks.add("projection")
                    KagemushaNearbyAttemptGate.ReceivedCredit(true, false, fresh)
                })
            assertEquals(listOf("retained", "projection"), callbacks)
            assertContentEquals(retainedReceipt, captured)
            assertContentEquals(fresh, actual)
            assertFalse(actual.contentEquals(requireNotNull(captured)), "acknowledgment must use fresh native evidence")
        }
    }
    @Test fun receiveRejectsMissingBurnedAndPayerEvidence() {
        val requestId = ByteArray(32) { 0x34 }
        val invalid = listOf(
            KagemushaNearbyAttemptGate.ReceivedCredit(true, false, null),
            KagemushaNearbyAttemptGate.ReceivedCredit(true, false, byteArrayOf()),
            KagemushaNearbyAttemptGate.ReceivedCredit(true, true, byteArrayOf(0x71)),
            KagemushaNearbyAttemptGate.ReceivedCredit(false, false, byteArrayOf(0x71)),
        )
        for ((status, recovery) in listOf(1 to false, 1 to true, 10 to true)) {
            for (value in invalid) {
                var retainedCalls = 0
                var projectionCalls = 0
                assertFailsWith<IllegalStateException> {
                    KagemushaNearbyAttemptGate(recovery).receivedCredit(status, requestId,
                        retainedOutput = { retainedCalls++ },
                        projection = { selected ->
                            assertContentEquals(requestId, selected)
                            projectionCalls++
                            value
                        })
                }
                assertEquals(if (status == 1) 1 else 0, retainedCalls)
                assertEquals(1, projectionCalls)
            }
        }
    }
    @Test fun receivePropagatesProjectionAndRetainedFailuresWithoutFallback() {
        val requestId = ByteArray(32) { 0x35 }
        val projectionFailure = IllegalArgumentException("projection")
        for ((status, recovery) in listOf(1 to false, 1 to true, 10 to true)) {
            var retainedCalls = 0
            var projectionCalls = 0
            val failure = assertFailsWith<IllegalArgumentException> {
                KagemushaNearbyAttemptGate(recovery).receivedCredit(status, requestId,
                    retainedOutput = { retainedCalls++ },
                    projection = { projectionCalls++; throw projectionFailure })
            }
            assertSame(projectionFailure, failure)
            assertEquals(if (status == 1) 1 else 0, retainedCalls)
            assertEquals(1, projectionCalls)
        }
        val retainedFailure = IllegalArgumentException("retained")
        var projectionCalled = false
        val failure = assertFailsWith<IllegalArgumentException> {
            KagemushaNearbyAttemptGate(false).receivedCredit(1, requestId,
                retainedOutput = { throw retainedFailure },
                projection = {
                    projectionCalled = true
                    KagemushaNearbyAttemptGate.ReceivedCredit(true, false, byteArrayOf(0x71))
                })
        }
        assertSame(retainedFailure, failure)
        assertFalse(projectionCalled, "failed release capture cannot become a successful diagnostic")
    }
    @Test fun receiveSelectionAndNativeOriginalRemainDefensiveCopies() {
        val requestId = ByteArray(32) { 0x36 }
        val expected = requestId.copyOf()
        val original = byteArrayOf(0, 1, 0xff.toByte())
        val expectedOriginal = original.copyOf()
        val evidence = KagemushaNearbyAttemptGate.ReceivedCredit(true, false, original)
        original.fill(0)
        evidence.original()!!.fill(0)
        val actual = KagemushaNearbyAttemptGate(false).receivedCredit(1, requestId,
            retainedOutput = { selected ->
                selected.fill(0)
                requestId.fill(0)
            },
            projection = { selected ->
                assertContentEquals(expected, selected)
                evidence
            })
        assertContentEquals(expectedOriginal, actual)
        actual.fill(0)
        assertContentEquals(expectedOriginal, evidence.original())
    }
}
