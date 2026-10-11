// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** Typed ABI projections; no Native monetary proof or physical device qualification. */
class KagemushaWalletSnapshotV1Test {
    @Test fun `unsigned scalar has explicit value equality and redacted rendering`() {
        val value = KagemushaWalletUInt128V1(-1, Long.MIN_VALUE)
        val equal = KagemushaWalletUInt128V1(-1, Long.MIN_VALUE)
        assertEquals(value, equal)
        assertEquals(value.hashCode(), equal.hashCode())
        assertFalse(value == KagemushaWalletUInt128V1(0, Long.MIN_VALUE))
        assertTrue(value > KagemushaWalletUInt128V1(0, Long.MIN_VALUE))
        assertTrue(value > KagemushaWalletUInt128V1(-1, Long.MAX_VALUE))
        assertTrue(value.toString().contains("[REDACTED]"))
    }
    private fun reply(flags: Int = 0, lifecycle: Int = 1, sequence: Long = 0,
        numbers: LongArray? = null, credential: ByteArray = ByteArray(32) { 4 }): KagemushaWalletSnapshotReplyV1 {
        val scalars = numbers ?: LongArray(18).also {
            it[0] = sequence; it[2] = 20; it[8] = 20; it[12] = if (flags and 2 == 0) 1 else 0
            if (flags and 2 != 0) it[10] = 20
        }
        return KagemushaWalletSnapshotReplyV1(0, -1, 0, lifecycle, flags,
            ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 }, credential,
            ByteArray(32) { if (flags and 1 != 0) 3 else 0 },
            ByteArray(32) { if (flags and 1 != 0) 4 else 0 }, scalars)
    }
    @Test fun `owned unfolded value differs from a valid folded zero`() {
        val unfolded = KagemushaWalletSnapshotV1(reply())
        assertEquals(KagemushaWalletUInt128V1(20, 0), unfolded.ownedBalance)
        assertFalse(unfolded.headIsFolded); assertNull(unfolded.foldedBalance)
        assertEquals(KagemushaWalletUInt128V1(1, 0), unfolded.foldBacklog)
        val zero = KagemushaWalletSnapshotV1(reply(flags = 3, numbers = LongArray(18)))
        assertTrue(zero.headIsFolded); assertEquals(KagemushaWalletUInt128V1(0, 0), zero.foldedBalance)
    }
    @Test fun `retiring preserves folded value and all unsigned128 bits`() {
        val numbers = LongArray(18)
        numbers[2] = -1; numbers[3] = -1; numbers[8] = -1; numbers[9] = -1
        numbers[10] = -1; numbers[11] = -1
        val value = KagemushaWalletSnapshotV1(reply(flags = 3, lifecycle = 2, numbers = numbers))
        assertEquals(KagemushaWalletLifecycleV1.RETIRING, value.lifecycle)
        assertEquals(KagemushaWalletUInt128V1(-1, -1), value.foldedBalance)
        assertTrue(KagemushaWalletUInt128V1(-1, 0) < KagemushaWalletUInt128V1(0, 1))
        assertTrue(KagemushaWalletUInt128V1(0, Long.MAX_VALUE) < KagemushaWalletUInt128V1(0, Long.MIN_VALUE))
    }
    @Test fun `typed arrays are defensive and ancestor fold keeps its credential`() {
        val numbers = LongArray(18); numbers[0] = 1; numbers[2] = 20; numbers[8] = 20; numbers[12] = 1
        val credential = ByteArray(32) { 5 }
        val raw = reply(flags = 1, sequence = 1, numbers = numbers, credential = credential)
        numbers.fill(9); credential.fill(9)
        val value = KagemushaWalletSnapshotV1(raw)
        value.head().fill(9); value.verifiedFold!!.credentialDigest().fill(9)
        assertContentEquals(ByteArray(32) { 3 }, value.head())
        assertContentEquals(ByteArray(32) { 5 }, value.credentialDigest())
        assertContentEquals(ByteArray(32) { 4 }, value.verifiedFold!!.credentialDigest())
        assertFalse(value.headIsFolded); assertNull(value.foldedBalance)
        assertTrue(value.toString().contains("[REDACTED]"))
    }
    @Test fun `malformed tags arrays or source identity cannot project money`() {
        for (raw in listOf(reply(flags = 2), reply(flags = 4), reply(lifecycle = 0),
            reply(flags = 1), reply(numbers = LongArray(17)))) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletSnapshotV1(raw) }
        }
        val raw = KagemushaWalletSnapshotReplyV1(-5, 3, 5, 0, 0,
            ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), ByteArray(32), LongArray(18))
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletSnapshotV1(raw) }
    }
}
