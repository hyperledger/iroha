// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** One-use review cleanup transport fixtures only; no Native admission or payment is simulated. */
class KagemushaWalletReviewedExecutionV1Test {
    @Test fun consumedReviewDoesNotCloseWalletOrReplaceExecutionFailure() {
        for (status in listOf(-1, -5, -6, -9, KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)) {
            val primary = KagemushaWalletExceptionV1(status)
            var tokenPresent = true
            val trace = mutableListOf<String>()
            val actual = assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletReviewedExecutionV1.run(execute = {
                    trace += "execute"
                    assertTrue(tokenPresent)
                    tokenPresent = false // Native consumes before its source recheck and execution.
                    throw primary
                }, discard = {
                    trace += "discard"
                    if (tokenPresent) { tokenPresent = false; 0 } else -1
                }, close = { trace += "close" })
            }
            assertSame(primary, actual)
            assertTrue(actual.suppressed.isEmpty())
            assertEquals(listOf("execute", "discard"), trace)
            assertFalse(tokenPresent)
        }
    }

    @Test fun refusedDispatchDiscardsUnusedReviewWithoutClosing() {
        val primary = KagemushaWalletExceptionV1(-5)
        var tokenPresent = true
        var closes = 0
        val actual = assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletReviewedExecutionV1.run(execute = { throw primary }, discard = {
                assertTrue(tokenPresent)
                tokenPresent = false
                0
            }, close = { closes++ })
        }
        assertSame(primary, actual)
        assertFalse(tokenPresent)
        assertEquals(0, closes)
        assertTrue(actual.suppressed.isEmpty())
    }

    @Test fun alreadyClosedReviewDoesNotRetryOwnerClose() {
        val primary = KagemushaWalletExceptionV1(-2)
        var closes = 0
        val actual = assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletReviewedExecutionV1.run(execute = { throw primary }, discard = { -2 }, close = { closes++ })
        }
        assertSame(primary, actual)
        assertEquals(0, closes)
        assertTrue(actual.suppressed.isEmpty())
    }

    @Test fun unresolvedCleanupRetiresOwnerAndRetainsExecutionFailure() {
        for (status in listOf(-3, -4, -5, -6, -7, -9, -13, -100, 1)) {
            val primary = KagemushaWalletExceptionV1(-1)
            var closes = 0
            val actual = assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletReviewedExecutionV1.run(execute = { throw primary }, discard = { status }, close = { closes++ })
            }
            assertSame(primary, actual)
            assertEquals(1, closes)
            assertEquals(status, (actual.suppressed.single() as KagemushaWalletExceptionV1).status)
        }
    }

    @Test fun failedCleanupAndOwnerRetirementRemainAttachedToPrimaryFailure() {
        val primary = KagemushaWalletExceptionV1(-9)
        val cleanup = IllegalStateException("discard transport")
        val retirement = IllegalStateException("close transport")
        val actual = assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletReviewedExecutionV1.run(execute = { throw primary }, discard = { throw cleanup },
                close = { throw retirement })
        }
        assertSame(primary, actual)
        assertEquals(listOf(cleanup, retirement), actual.suppressed.toList())
    }

    @Test fun sameFailureObjectNeverSuppressesItself() {
        val primary = KagemushaWalletExceptionV1(-9)
        val actual = assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletReviewedExecutionV1.run(execute = { throw primary }, discard = { throw primary },
                close = { throw primary })
        }
        assertSame(primary, actual)
        assertTrue(actual.suppressed.isEmpty())
    }

    @Test fun completedDispatchReturnsExactResultWithoutCleanup() {
        val expected = Any()
        val actual = KagemushaWalletReviewedExecutionV1.run(execute = { expected },
            discard = { error("successful execution must not discard") },
            close = { error("successful execution must not close") })
        assertSame(expected, actual)
    }
}
