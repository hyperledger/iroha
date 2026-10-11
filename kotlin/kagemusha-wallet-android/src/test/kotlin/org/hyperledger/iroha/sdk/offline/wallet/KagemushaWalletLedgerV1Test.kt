// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Test

class KagemushaWalletLedgerV1Test {
    @Test fun `Unload settlement absence and prefix never imply confirmation`() {
        val absent = KagemushaWalletUnloadFinalityV1(KagemushaWalletCallV1(34, -1, 0, 0, 0, 0, byteArrayOf()))
        assertEquals(null, absent.confirmation); assertEquals(null, absent.verifiedHeightBits)
        assertEquals(null, absent.blockHash())
        val progress = KagemushaWalletUnloadFinalityV1(KagemushaWalletCallV1(33, -1, 0, 1, 0, 0, ByteArray(32) { 8 }))
        assertEquals(null, progress.confirmation); assertEquals(1L, progress.verifiedHeightBits)
        assertContentEquals(ByteArray(32) { 8 }, progress.blockHash())
        for (status in listOf(0, 1, 2, 44, 45, 46)) {
            val bytes = if (status in listOf(1, 44, 45)) ByteArray(32) { 8 } else byteArrayOf()
            val height = if (status in listOf(44, 45)) 2L else 0L
            assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletUnloadFinalityV1(KagemushaWalletCallV1(status, -1, 0, height, 0, 0, bytes))
            }
        }
    }

    @Test fun `Unload settlement confirmation retains exact immutable Native evidence`() {
        val hash = ByteArray(32) { 7 }
        val result = KagemushaWalletCallV1(42, -1, 0, -1L, 0, 0, hash)
        hash.fill(0)
        val state = KagemushaWalletUnloadFinalityV1(result)
        assertEquals(-1L, state.verifiedHeightBits)
        assertEquals(-1L, state.confirmation!!.heightBits)
        state.blockHash()!!.fill(0); state.confirmation.blockHash().fill(0)
        assertContentEquals(ByteArray(32) { 7 }, state.blockHash())
        assertContentEquals(ByteArray(32) { 7 }, state.confirmation.blockHash())
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(42, -1, 0, 1, 0, 0, ByteArray(32) { 7 }) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(34, -1, 0, 0, 0, 0, byteArrayOf(1)) }
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
    }
    @Test fun `Activate history accepts only exact bounded wire with no caller authority`() {
        val wire = ByteArray(65_536) { 9 }; val proof = byteArrayOf(7)
        val read = KagemushaWalletSetupInputV1(37, first = wire)
        val confirm = KagemushaWalletSetupInputV1(35, first = wire)
        val retained = KagemushaWalletSetupInputV1(46, first = wire)
        val ingest = KagemushaWalletSetupInputV1(36, first = wire, second = proof)
        wire.fill(0); proof.fill(0)
        assertContentEquals(ByteArray(65_536) { 9 }, read.first())
        assertContentEquals(read.first(), confirm.first())
        assertContentEquals(read.first(), retained.first())
        retained.first().fill(0)
        assertContentEquals(read.first(), retained.first())
        assertContentEquals(byteArrayOf(7), ingest.second())
        for (selector in listOf(35, 36, 37, 46)) {
            val second = if (selector == 36) byteArrayOf(1) else byteArrayOf()
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, second = second) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = ByteArray(65_537), second = second) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = wire, second = second, identity = ByteArray(32) { 1 }) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = wire, second = second, token = 1) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = wire, second = second, amount = KagemushaWalletUInt128V1(1, 0)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = wire, second = second, third = byteArrayOf(1)) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(46, first = wire, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(36, first = wire) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(36, first = wire, second = ByteArray(36 * 1024 * 1024 + 1)) }
    }

    @Test fun `Activate progress and not started never imply confirmation`() {
        val absent = KagemushaWalletActivationFinalityV1(KagemushaWalletCallV1(46, -1, 0, 0, 0, 0, byteArrayOf()))
        assertEquals(null, absent.confirmation); assertEquals(null, absent.verifiedHeightBits)
        val result = KagemushaWalletCallV1(45, -1, 0, -1, 0, 0, ByteArray(32) { 3 })
        val progress = KagemushaWalletActivationFinalityV1(result)
        assertEquals(-1L, progress.verifiedHeightBits); assertEquals(null, progress.confirmation)
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletActivationConfirmationV1(result) }
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
    }

    @Test fun `Only exact typed Native rejection skips one outer without confirming its family`() {
        val hash = ByteArray(32) { 7 }
        val result = KagemushaWalletCallV1(49, -1, 0, 2, 0, 0, hash)
        hash.fill(0)
        val rejected = KagemushaWalletActivationFinalityV1(result)
        assertEquals(true, rejected.rejected); assertEquals(null, rejected.confirmation)
        assertEquals(2L, rejected.verifiedHeightBits)
        rejected.blockHash()!!.fill(0)
        assertContentEquals(ByteArray(32) { 7 }, rejected.blockHash())
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletActivationConfirmationV1(result) }
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        for (height in listOf(0L, 1L)) assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(49, -1, 0, height, 0, 0, ByteArray(32) { 7 })
        }
        for (hashBytes in listOf(ByteArray(0), ByteArray(31), ByteArray(32), ByteArray(33))) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(49, -1, 0, 2, 0, 0, hashBytes) }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(49, -1, 0, 2, 1, 0, ByteArray(32) { 7 }) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(49, -1, 0, 2, 0, 1, ByteArray(32) { 7 }) }
        val confirmed = KagemushaWalletActivationFinalityV1(KagemushaWalletCallV1(44, -1, 0, 3, 0, 0, ByteArray(32) { 8 }))
        assertEquals(false, confirmed.rejected); assertEquals(3L, confirmed.confirmation!!.heightBits)
        for (status in listOf(46, 45)) {
            val call = if (status == 46) KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, byteArrayOf())
                else KagemushaWalletCallV1(status, -1, 0, 1, 0, 0, ByteArray(32) { 3 })
            assertEquals(false, KagemushaWalletActivationFinalityV1(call).rejected)
        }
    }

    @Test fun `Activate confirmation retains the Native hash and rejects malformed result authority`() {
        val hash = ByteArray(32) { 4 }
        val result = KagemushaWalletCallV1(44, -1, 0, 2, 0, 0, hash)
        hash.fill(0)
        val confirmation = KagemushaWalletActivationFinalityV1(result).confirmation!!
        assertContentEquals(ByteArray(32) { 4 }, confirmation.blockHash())
        confirmation.blockHash().fill(0)
        assertContentEquals(ByteArray(32) { 4 }, confirmation.blockHash())
        for (status in listOf(44, 45)) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, ByteArray(32) { 1 }) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 1, 0, 0, ByteArray(32)) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 1, 1, 0, ByteArray(32) { 1 }) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 1, 0, 1, ByteArray(32) { 1 }) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 1, 0, 0, ByteArray(33) { 1 }) }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(44, -1, 0, 1, 0, 0, ByteArray(32) { 1 }) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(46, -1, 0, 1, 0, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(46, -1, 0, 0, 0, 0, byteArrayOf(1)) }
    }

    @Test fun `Unload history retains exact hash claim and bounded ordinary proof without a caller height`() {
        val hash = ByteArray(32) { 7 }; val claim = ByteArray(65_536) { 3 }; val proof = byteArrayOf(4, 5)
        val read = KagemushaWalletSetupInputV1(33, identity = hash, first = claim)
        val ingest = KagemushaWalletSetupInputV1(34, identity = hash, first = claim, second = proof)
        hash.fill(0); claim.fill(0); proof.fill(0)
        assertContentEquals(ByteArray(32) { 7 }, read.identity())
        assertContentEquals(ByteArray(65_536) { 3 }, ingest.first())
        assertContentEquals(byteArrayOf(4, 5), ingest.second())
        for (selector in listOf(33, 34)) {
            val second = if (selector == 34) byteArrayOf(1) else byteArrayOf()
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = claim, second = second) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = read.identity(), second = second) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = read.identity(), first = ByteArray(65_537), second = second) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = read.identity(), first = claim, second = second, token = 9) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = read.identity(), first = claim, second = second, amount = KagemushaWalletUInt128V1(1, 0)) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(33, identity = read.identity(), first = claim, second = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(34, identity = read.identity(), first = claim) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(34, identity = read.identity(), first = claim, second = ByteArray(36 * 1024 * 1024 + 1)) }
    }

    @Test fun `retired wallet server proving selectors and results are refused`() {
        for (selector in listOf(28, 31, 32)) {
            for ((first, second) in listOf(byteArrayOf() to byteArrayOf(), byteArrayOf(1) to byteArrayOf(), byteArrayOf(1) to byteArrayOf(2))) {
                assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = first, second = second) }
            }
        }
        for (status in listOf(41, 43)) {
            for (bytes in listOf(byteArrayOf(), byteArrayOf(1), ByteArray(8) { 2 })) {
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, bytes) }
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 3, 0, 0, bytes) }
            }
        }
    }

    @Test fun `Unload confirmation binds exact transaction hash and positive native inclusion`() {
        val hash = ByteArray(32) { 6 }; val original = ByteArray(65_536) { 5 }
        val input = KagemushaWalletSetupInputV1(30, identity = hash, first = original)
        hash.fill(0); original.fill(0)
        assertContentEquals(ByteArray(32) { 6 }, input.identity())
        assertContentEquals(ByteArray(65_536) { 5 }, input.first())
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(30, first = original) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(30, identity = input.identity()) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(30, identity = input.identity(), first = ByteArray(65_537)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(30, identity = input.identity(), first = original, token = 1) }
        val result = KagemushaWalletCallV1(42, -1, 0, -1, 0, 0, ByteArray(32) { 7 })
        assertEquals(-1L, KagemushaWalletUnloadConfirmationV1(result).heightBits)
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(42, -1, 0, 0, 0, 0, ByteArray(32) { 1 }) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(42, -1, 0, 1, 0, 0, ByteArray(32)) }
    }

    @Test fun `Load preparation binds only nonzero identity and unsigned amount`() {
        val request = ByteArray(32) { 7 }
        val input = KagemushaWalletSetupInputV1(27, identity = request, amount = KagemushaWalletUInt128V1(-1, -1))
        request.fill(0)
        assertContentEquals(ByteArray(32) { 7 }, input.identity())
        assertEquals(KagemushaWalletUInt128V1(-1, -1), input.amount)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(27, identity = request, amount = input.amount) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(27, identity = input.identity()) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(27, identity = input.identity(), amount = input.amount, first = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(27, identity = input.identity(), amount = input.amount, token = 1) }
    }

    @Test fun `ledger transport selects a closed purpose and cannot carry proof or time authority`() {
        for (kind in KagemushaWalletLedgerTransportV1.values()) {
            val original = ByteArray(65_536) { 4 }
            val input = KagemushaWalletSetupInputV1(29, token = kind.tag, first = original)
            original.fill(0)
            assertContentEquals(ByteArray(65_536) { 4 }, input.first())
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(29, token = kind.tag) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(29, token = kind.tag, first = ByteArray(65_537)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(29, token = kind.tag, first = original, second = byteArrayOf(1)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(29, token = kind.tag, first = original, identity = ByteArray(32) { 1 }) }
        }
        for (tag in listOf(-1L, 0L, 4L, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(29, token = tag, first = byteArrayOf(1)) }
        }
    }

    @Test fun `ledger instruction is a bounded original never monetary completion`() {
        for ((status, bound) in listOf(40 to 65_536)) {
            val original = ByteArray(bound) { 8 }
            val result = KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, original)
            original.fill(0)
            assertContentEquals(ByteArray(bound) { 8 }, result.bytes())
            assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
            assertFailsWith<KagemushaWalletExceptionV1> { result.original() }
            for (size in listOf(0, bound + 1)) assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, ByteArray(size)) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 1, 0, 0, byteArrayOf(1)) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 1, 0, byteArrayOf(1)) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 1, byteArrayOf(1)) }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(53, -1, 0, 0, 0, 0, byteArrayOf()) }
    }
}
