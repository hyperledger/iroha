// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

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
}
