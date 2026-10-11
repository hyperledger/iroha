// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import org.junit.jupiter.api.Test

/** Actual managed lifetime with controlled call failures; no Native or monetary qualification. */
class KagemushaWalletAdmissionLifetimeV1Test {
    private val challenge = ByteArray(32) { 7 }

    @Test fun `finish refusal preserves the same pending owner for successful retry`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val pending = lifetime.select(challenge) { Any() }
        val failure = KagemushaWalletExceptionV1(-3, 2, 9)
        assertSame(failure, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.finish(pending) { throw failure }
        })
        assertSame(pending, lifetime.select(challenge) { error("must retain the existing pending owner") })
        val opened = Any()
        assertSame(opened, lifetime.finish(pending) { opened })
        assertEquals(-2, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.finish(pending) { error("completed pending owner must not invoke Native") }
        }.status)
    }

    @Test fun `cancellation failure retains the pending owner and permits cancellation retry`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val pending = lifetime.select(challenge) { Any() }
        val failure = KagemushaWalletExceptionV1(-7)
        var cancellations = 0
        assertSame(failure, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.abandon(pending) { cancellations++; throw failure }
        })
        assertSame(pending, lifetime.select(challenge) { error("failed cancellation cannot clear ownership") })
        lifetime.abandon(pending) { cancellations++ }
        lifetime.abandon(pending) { error("successful cancellation must be idempotent") }
        assertEquals(2, cancellations)
    }

    @Test fun `repeated begin returns the same identity and protects the retained challenge bytes`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val supplied = challenge.copyOf()
        val pending = lifetime.select(supplied) { Any() }
        supplied[0] = 8
        assertSame(pending, lifetime.select(challenge.copyOf()) { error("duplicate begin cannot create an alias") })
        assertEquals(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT,
            assertFailsWith<KagemushaWalletExceptionV1> {
                lifetime.select(supplied) { error("different challenge cannot replace a retained owner") }
            }.status)
        assertSame(pending, lifetime.select(challenge) { error("rejected output must retain the original") })
    }

    @Test fun `stale pending wrapper cannot finish or cancel the replacement challenge`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val old = lifetime.select(challenge) { Any() }
        lifetime.complete { Unit } // Explicit runtime cancellation succeeded.
        val replacement = lifetime.select(ByteArray(32) { 9 }) { Any() }
        assertNotSame(old, replacement)
        lifetime.abandon(old) { error("stale wrapper must not cancel a replacement") }
        assertEquals(-2, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.finish(old) { error("stale wrapper must not finish a replacement") }
        }.status)
        assertSame(replacement, lifetime.select(ByteArray(32) { 9 }) { error("replacement must remain owned") })
        assertEquals("opened", lifetime.finish(replacement) { "opened" })
    }

    @Test fun `runtime completion failure retains pending ownership until recovery succeeds`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val pending = lifetime.select(challenge) { Any() }
        assertFailsWith<IllegalStateException> { lifetime.complete { error("interrupted output") } }
        assertSame(pending, lifetime.select(challenge) { error("runtime retry must retain ownership") })
        assertEquals("opened", lifetime.complete { "opened" })
        lifetime.abandon(pending) { error("recovered completion must not cancel Native") }
        assertEquals(-2, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.finish(pending) { error("recovered completion must not finish again") }
        }.status)
    }

    @Test fun `runtime close invalidates pending callbacks without reopening Native`() {
        val lifetime = KagemushaWalletAdmissionLifetimeV1<Any>()
        val pending = lifetime.select(challenge) { Any() }
        lifetime.clear()
        lifetime.abandon(pending) { error("closed runtime must not be called") }
        assertEquals(-2, assertFailsWith<KagemushaWalletExceptionV1> {
            lifetime.finish(pending) { error("closed runtime must not be called") }
        }.status)
    }
}
