// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Actor stage bookkeeping only; these synthetic outcomes confer no Native or device evidence. */
class KagemushaEnrollmentProbeStageTest {
    @Test fun existingObservedStagesRemainDistinct() {
        val expected = mapOf(
            "native-installation-registered" to "installed",
            "installed-owner-retained" to "installed",
            "live-dispatch-exported" to "dispatch",
            "retained-e5-exported" to "e5",
            "native-durable-e5-exported" to "e5",
            "retained-e6-exported" to "e6",
            "native-durable-e6-exported-not-activated" to "e6",
            "native-wallet-opened" to "opened",
            "native-local-abandoned" to "abandoned",
            "native-signed-abandonment-exported" to "abandoned",
            "native-expired-local-abandoned" to "abandoned",
            "native-activation-confirmed" to "activated",
            "native-complete-load" to "loaded",
            "native-complete-send" to "sent",
            "native-exact-send-delivery-admitted-over-nearby" to "sent",
            "native-complete-receive" to "received",
            "native-durable-receive-acknowledged-over-nearby" to "received",
            "native-current-head-folded" to "folded",
            "native-unload-confirmed" to "unloaded",
        )
        for ((outcome, stage) in expected) assertEquals(stage, enrollmentProbeStage(outcome), outcome)
    }

    @Test fun collectedReceiveNeedsFreshUnburnedCreditObservation() {
        for (evidence in listOf("UNFOLDED", "CREDITED")) {
            val achieved = mutableSetOf<String>()
            enrollmentProbeStage("native-call-status-10")?.let { achieved.add(it) }
            assertTrue(achieved.isEmpty(), "collected output status alone does not establish credit")
            enrollmentProbeStage("native-credit-evidence-$evidence")?.let { achieved.add(it) }
            assertEquals(setOf("received"), achieved, "fold backlog does not erase durable credit")
        }
    }

    @Test fun rawStatusesBurnedPendingAndExportsNeverEstablishReceived() {
        val outcomes = listOf(
            "native-credit-evidence-BURNED", "native-credit-evidence-PENDING",
            "native-credit-evidence-UNKNOWN", "native-credit-evidence-ARCHIVED",
            "native-credit-evidence-credited", "native-credit-evidence-CREDITED ",
            "native-credit-evidence-1", "native-credit-evidence-2", "native-credit-evidence-3",
            "native-activation-exported-not-submitted", "native-activation-rejected",
            "native-load-plan-retained", "native-review-awaiting-explicit-decision",
            "native-peer-envelope-decoded-not-admitted", "native-unload-claim-exported-not-settled",
            "native-activation-unconfirmed", "native-activation-epoch-required", "native-unload-unconfirmed",
            "native-unload-rejected", "native-unload-epoch-required", "native-current-head-not-folded",
        ) + (0..60).map { "native-call-status-$it" }
        for (outcome in outcomes) assertNull(enrollmentProbeStage(outcome), outcome)
        val recoveredBurned = listOf("native-call-status-10", "native-credit-evidence-BURNED")
        assertTrue(recoveredBurned.mapNotNull(::enrollmentProbeStage).isEmpty())
    }
}
