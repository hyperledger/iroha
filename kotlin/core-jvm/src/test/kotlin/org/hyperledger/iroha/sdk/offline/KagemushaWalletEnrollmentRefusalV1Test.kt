// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1.HolderClass
import org.junit.jupiter.api.Test

/** The closed design §2.4 table, relayed unchanged; never admission. */
class KagemushaWalletEnrollmentRefusalV1Test {
    @Test fun `the closed table matches design section 2 point 4 code by code`() {
        val expected = listOf(
            Triple(1, true, HolderClass.PHONE), Triple(2, true, HolderClass.PHONE), Triple(3, true, HolderClass.PHONE),
            Triple(4, true, HolderClass.PHONE), Triple(5, false, HolderClass.PHONE), Triple(6, true, HolderClass.PHONE),
            Triple(7, false, HolderClass.APP), Triple(8, true, HolderClass.APP), Triple(9, false, HolderClass.ATTEMPT),
            Triple(10, false, HolderClass.ATTEMPT), Triple(11, false, HolderClass.ACCOUNT), Triple(12, false, HolderClass.ACCOUNT),
        )
        assertEquals(expected, KagemushaWalletEnrollmentRefusalV1.entries.map { Triple(it.code, it.androidOnly, it.holderClass) })
        for (reason in KagemushaWalletEnrollmentRefusalV1.entries) {
            assertSame(reason, KagemushaWalletEnrollmentRefusalV1.fromCode(reason.code))
            assertSame(reason, KagemushaWalletEnrollmentRefusalV1.relayed(reason.code, android = true))
            if (reason.androidOnly) {
                assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentRefusalV1.relayed(reason.code, android = false) }
            } else {
                assertSame(reason, KagemushaWalletEnrollmentRefusalV1.relayed(reason.code, android = false))
            }
        }
        for (code in listOf(0, 13, 255, 65_535, -1)) {
            assertNull(KagemushaWalletEnrollmentRefusalV1.fromCode(code))
            assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentRefusalV1.relayed(code, android = true) }
        }
        assertEquals(listOf(11, 12), KagemushaWalletEnrollmentRefusalV1.entries.filter { it.isEligibility }.map { it.code })
    }

    @Test fun `outcome headers distinguish terminal refusal withheld delivery and unknown`() {
        val refused = assertIs<KagemushaWalletEnrollmentOutcomeV1.Refused>(KagemushaWalletEnrollmentOutcomeV1.fromHeaders(403,
            listOf("Content-Type" to "application/x-norito", "X-Iroha-Kagemusha-Refusal-Code" to "2")))
        assertSame(KagemushaWalletEnrollmentRefusalV1.ATTESTATION_WITHOUT_APP_IDENTITY, refused.reason)
        val withheld = assertIs<KagemushaWalletEnrollmentOutcomeV1.DeliveryWithheld>(KagemushaWalletEnrollmentOutcomeV1.fromHeaders(403,
            listOf("x-iroha-kagemusha-delivery-withheld-code" to "12")))
        assertSame(KagemushaWalletEnrollmentRefusalV1.ACCOUNT_FROZEN, withheld.reason)
        // The same eligibility code is terminal at E5 and only withholding at E6 delivery.
        assertSame(KagemushaWalletEnrollmentRefusalV1.ACCOUNT_FROZEN, assertIs<KagemushaWalletEnrollmentOutcomeV1.Refused>(
            KagemushaWalletEnrollmentOutcomeV1.fromHeaders(403, listOf("x-iroha-kagemusha-refusal-code" to "12"))).reason)
        assertSame(KagemushaWalletEnrollmentOutcomeV1.OutcomeUnknown,
            KagemushaWalletEnrollmentOutcomeV1.fromHeaders(409, listOf("x-iroha-kagemusha-outcome" to "unknown")))
        assertNull(KagemushaWalletEnrollmentOutcomeV1.fromHeaders(200, listOf("Content-Type" to "application/x-norito")))
        assertNull(KagemushaWalletEnrollmentOutcomeV1.fromHeaders(500, emptyList()))
    }

    @Test fun `malformed duplicated or mismatched outcomes are protocol errors`() {
        val bad = listOf(
            403 to listOf("x-iroha-kagemusha-refusal-code" to "0"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "13"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "02"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "+2"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to ""),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "100000"),
            403 to listOf("x-iroha-kagemusha-delivery-withheld-code" to "9"),
            409 to listOf("x-iroha-kagemusha-outcome" to "Unknown"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "2", "x-iroha-kagemusha-refusal-code" to "2"),
            403 to listOf("x-iroha-kagemusha-refusal-code" to "2", "x-iroha-kagemusha-delivery-withheld-code" to "11"),
            409 to listOf("x-iroha-kagemusha-refusal-code" to "2"),
            200 to listOf("x-iroha-kagemusha-delivery-withheld-code" to "11"),
            403 to listOf("x-iroha-kagemusha-outcome" to "unknown"),
        )
        for ((status, headers) in bad) {
            assertFailsWith<IllegalArgumentException>("$status $headers") { KagemushaWalletEnrollmentOutcomeV1.fromHeaders(status, headers) }
        }
    }
}
