// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** JNI/status and managed sequencing DATA only; no fake Native owner or registration callback. */
class KagemushaWalletInstallationAttemptV1Test {
    @Test fun opaquePointerDataIsNotRestrictedToPositiveRegistryIds() {
        for(value in listOf(1L,Int.MAX_VALUE.toLong(),Long.MAX_VALUE,Int.MIN_VALUE.toLong()-1,Long.MIN_VALUE)) {
            assertEquals(value,installationAttemptPointerV1(value))
        }
        assertFailsWith<KagemushaWalletExceptionV1>{installationAttemptPointerV1(0)}
        for(value in listOf(-1L,-2L,-5L,-6L,Int.MIN_VALUE.toLong())) {
            assertFailsWith<KagemushaWalletExceptionV1>{installationAttemptPointerV1(value)}
        }
        for(value in listOf(Long.MIN_VALUE,Int.MIN_VALUE.toLong()-1,0L)) {
            assertFailsWith<KagemushaWalletExceptionV1>{installationRuntimeHandle(value)}
        }
    }
    @Test fun registrationRefusalDoesNotTransferManagedCustody() {
        val state=KagemushaWalletInstallationSequenceV1()
        repeat(3){state.requireRegistration();assertFalse(state.isReleased)}
        state.transferred();assertTrue(state.isReleased)
        assertFailsWith<IllegalStateException>{state.requireRegistration()}
        assertFailsWith<IllegalStateException>{state.transferred()}
        assertFalse(state.startClose())
    }
    @Test fun ordinaryCloseRefusalRetainsRetiringStateAndBlocksRegistration() {
        val state=KagemushaWalletInstallationSequenceV1()
        assertTrue(state.startClose());assertFalse(state.isReleased)
        assertFailsWith<IllegalStateException>{state.requireRegistration()}
        assertFailsWith<IllegalStateException>{state.transferred()}
        for(status in listOf(-1,-2,-5,-6,1,15,16)) {
            assertFailsWith<KagemushaWalletExceptionV1>{checkInstallationCloseStatusV1(status)}
            assertFalse(state.isReleased);assertTrue(state.startClose())
        }
        checkInstallationCloseStatusV1(0);state.acknowledgedClose()
        assertTrue(state.isReleased);assertFalse(state.startClose())
        assertFailsWith<IllegalStateException>{state.requireRegistration()}
        assertFailsWith<IllegalStateException>{state.acknowledgedClose()}
    }
    @Test fun closeCannotAcknowledgeBeforeRetirementBegins() {
        val state=KagemushaWalletInstallationSequenceV1()
        assertFailsWith<IllegalStateException>{state.acknowledgedClose()}
        assertFalse(state.isReleased);state.requireRegistration()
    }
}
