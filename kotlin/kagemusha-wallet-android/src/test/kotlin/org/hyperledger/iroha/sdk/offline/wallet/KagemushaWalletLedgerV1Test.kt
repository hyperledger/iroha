// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.KagemushaWalletLedgerReadV1
import org.junit.jupiter.api.Test

class KagemushaWalletLedgerV1Test {
    private val entrypoint = ByteArray(32) { 0x0f }
    private val commit = KagemushaWalletLedgerCommitV1(7, ByteArray(32) { 9 })

    @Test fun `Awaiting carries only the Native-derived entrypoint and never implies confirmation`() {
        val bytes = ByteArray(32) { 3 }
        val result = KagemushaWalletCallV1(KagemushaWalletCallV1.LEDGER_AWAITING, -1, 0, 0, 0, 0, bytes)
        bytes.fill(0)
        val awaiting = KagemushaWalletLedgerOutcomeV1.of(result) as KagemushaWalletLedgerOutcomeV1.Awaiting
        awaiting.entrypoint().fill(0)
        assertContentEquals(ByteArray(32) { 3 }, awaiting.entrypoint())
        // An offered original decides the attempt or names an epoch; it never answers Awaiting.
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletLedgerIngestV1.of(result) }
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        for (size in listOf(0, 31, 33)) assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletCallV1(KagemushaWalletCallV1.LEDGER_AWAITING, -1, 0, 0, 0, 0, ByteArray(size) { 3 })
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(KagemushaWalletCallV1.LEDGER_AWAITING, -1, 0, 0, 0, 0, ByteArray(32)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(KagemushaWalletCallV1.LEDGER_AWAITING, -1, 0, 1, 0, 0, ByteArray(32) { 3 }) }
        // The global ledger tip is not an attempt outcome.
        assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletLedgerOutcomeV1.of(KagemushaWalletCallV1(33, -1, 0, 1, 0, 0, ByteArray(32) { 3 }))
        }
    }

    @Test fun `Confirmed and Rejected carry the certified height and native commit hash`() {
        for (status in listOf(KagemushaWalletCallV1.LEDGER_CONFIRMED, KagemushaWalletCallV1.LEDGER_REJECTED)) {
            val hash = ByteArray(32) { 7 }
            val result = KagemushaWalletCallV1(status, -1, 0, -1L, 0, 0, hash)
            hash.fill(0)
            val expected = KagemushaWalletLedgerCommitV1(-1L, ByteArray(32) { 7 })
            val outcome = KagemushaWalletLedgerOutcomeV1.of(result)
            assertEquals(if (status == KagemushaWalletCallV1.LEDGER_CONFIRMED) KagemushaWalletLedgerOutcomeV1.Confirmed(expected)
                else KagemushaWalletLedgerOutcomeV1.Rejected(expected), outcome)
            assertEquals(KagemushaWalletLedgerIngestV1.Outcome(outcome), KagemushaWalletLedgerIngestV1.of(result))
            assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
            for (height in listOf(0L, 1L)) assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, height, 0, 0, ByteArray(32) { 1 }) }
            for (bytes in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(32), ByteArray(33) { 1 })) {
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 2, 0, 0, bytes) }
            }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 2, 1, 0, ByteArray(32) { 1 }) }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 2, 0, 1, ByteArray(32) { 1 }) }
        }
    }

    @Test fun `EpochRequired is a bare untrusted target height`() {
        val epoch = KagemushaWalletCallV1.LEDGER_EPOCH_REQUIRED
        val result = KagemushaWalletCallV1(epoch, -1, 0, 3_601, 0, 0, byteArrayOf())
        assertEquals(KagemushaWalletLedgerIngestV1.EpochRequired(3_601), KagemushaWalletLedgerIngestV1.of(result))
        assertEquals(KagemushaWalletLedgerIngestV1.EpochRequired(-1L),
            KagemushaWalletLedgerIngestV1.of(KagemushaWalletCallV1(epoch, -1, 0, -1L, 0, 0, byteArrayOf())))
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletLedgerOutcomeV1.of(result) }
        assertFailsWith<KagemushaWalletExceptionV1> { result.completion() }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(epoch, -1, 0, 0, 0, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(epoch, -1, 0, 1, 1, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(epoch, -1, 0, 1, 0, 1, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(epoch, -1, 0, 1, 0, 0, byteArrayOf(1)) }
    }

    @Test fun `Activate attempt accepts only an exact bounded wire and the derived finality frame`() {
        val wire = ByteArray(65_536) { 9 }; val proof = byteArrayOf(7)
        val read = KagemushaWalletSetupInputV1(37, first = wire)
        val retained = KagemushaWalletSetupInputV1(46, first = wire)
        val ingest = KagemushaWalletSetupInputV1(36, first = wire, second = proof)
        wire.fill(0); proof.fill(0)
        assertContentEquals(ByteArray(65_536) { 9 }, read.first())
        assertContentEquals(read.first(), retained.first())
        assertContentEquals(byteArrayOf(7), ingest.second())
        KagemushaWalletSetupInputV1(36, first = wire, second = ByteArray(1_327_104))
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(36, first = wire, second = ByteArray(1_327_105)) }
        for (selector in listOf(36, 37, 46)) {
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
    }

    @Test fun `Unload attempt carries the exact claim and signed wire with no caller hash`() {
        val claim = ByteArray(16_384) { 3 }; val wire = ByteArray(65_536) { 5 }; val proof = byteArrayOf(4, 5)
        val read = KagemushaWalletSetupInputV1(33, first = claim, second = wire)
        val ingest = KagemushaWalletSetupInputV1(34, first = claim, second = wire, third = proof)
        claim.fill(0); wire.fill(0); proof.fill(0)
        assertContentEquals(ByteArray(16_384) { 3 }, read.first())
        assertContentEquals(ByteArray(65_536) { 5 }, ingest.second())
        assertContentEquals(byteArrayOf(4, 5), ingest.third())
        KagemushaWalletSetupInputV1(34, first = read.first(), second = read.second(), third = ByteArray(1_327_104))
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(34, first = read.first(), second = read.second(), third = ByteArray(1_327_105)) }
        for (selector in listOf(33, 34)) {
            val third = if (selector == 34) byteArrayOf(1) else byteArrayOf()
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = ByteArray(32) { 7 }, first = read.first(), second = read.second(), third = third) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, second = read.second(), third = third) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = read.first(), third = third) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = ByteArray(16_385), second = read.second(), third = third) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = read.first(), second = ByteArray(65_537), third = third) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = read.first(), second = read.second(), third = third, token = 9) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = read.first(), second = read.second(), third = third, amount = KagemushaWalletUInt128V1(1, 0)) }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(33, first = read.first(), second = read.second(), third = byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(34, first = read.first(), second = read.second()) }
    }

    @Test fun `retired walk and server proving selectors and results are refused`() {
        for (selector in listOf(28, 30, 31, 32, 35)) {
            for ((first, second) in listOf(byteArrayOf() to byteArrayOf(), byteArrayOf(1) to byteArrayOf(), byteArrayOf(1) to byteArrayOf(2))) {
                assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = first, second = second) }
                assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = ByteArray(32) { 6 }, first = first, second = second) }
            }
        }
        // 44/49 were the walk's Confirmed/Rejected: height plus the Iroha header hash, the shape of
        // 61/62. A Native from before direct finality cannot hand this SDK a terminal outcome.
        for (status in listOf(41, 42, 43, 44, 45, 49)) {
            for (bytes in listOf(byteArrayOf(), byteArrayOf(1), ByteArray(8) { 2 }, ByteArray(32) { 2 })) {
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 0, 0, 0, bytes) }
                assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(status, -1, 0, 3, 0, 0, bytes) }
            }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(63, -1, 0, 1, 0, 0, byteArrayOf()) }
    }

    private class Counts { var outcomes = 0; var fetches = 0; var ingests = 0; var syncs = 0; val fetched = ArrayList<ByteArray>() }

    private fun confirm(
        counts: Counts, retained: KagemushaWalletLedgerOutcomeV1, read: KagemushaWalletLedgerReadV1,
        replies: List<KagemushaWalletLedgerIngestV1>, sync: KagemushaWalletLedgerEpochSyncV1 = KagemushaWalletLedgerEpochSyncV1(true, true),
        owner: Runnable = Runnable {},
    ): CompletableFuture<KagemushaWalletLedgerConfirmationV1> {
        val pending = ArrayDeque(replies)
        return confirmKagemushaLedgerAttemptV1(owner,
            { counts.outcomes++; retained },
            { value -> counts.fetches++; counts.fetched.add(value); CompletableFuture.completedFuture(read) },
            { _ -> counts.ingests++; pending.removeFirstOrNull() ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT) },
            { _, target -> counts.syncs++; assertEquals(BigInteger.valueOf(3_601), target); CompletableFuture.completedFuture(sync) })
    }

    @Test fun `a retained outcome needs no network and is not an advance`() {
        for (retained in listOf(KagemushaWalletLedgerOutcomeV1.Confirmed(commit), KagemushaWalletLedgerOutcomeV1.Rejected(commit))) {
            val counts = Counts()
            assertEquals(KagemushaWalletLedgerConfirmationV1(retained, false),
                confirm(counts, retained, KagemushaWalletLedgerReadV1.Original(byteArrayOf(1)), emptyList()).join())
            assertEquals(listOf(1, 0, 0, 0), listOf(counts.outcomes, counts.fetches, counts.ingests, counts.syncs))
        }
    }

    @Test fun `Awaiting makes one read by the Native entrypoint and one ingest`() {
        val counts = Counts()
        val result = confirm(counts, KagemushaWalletLedgerOutcomeV1.Awaiting(entrypoint),
            KagemushaWalletLedgerReadV1.Original(byteArrayOf(1, 2)),
            listOf(KagemushaWalletLedgerIngestV1.Outcome(KagemushaWalletLedgerOutcomeV1.Confirmed(commit)))).join()
        assertEquals(KagemushaWalletLedgerConfirmationV1(KagemushaWalletLedgerOutcomeV1.Confirmed(commit), true), result)
        assertEquals(listOf(1, 1, 1, 0), listOf(counts.outcomes, counts.fetches, counts.ingests, counts.syncs))
        assertContentEquals(entrypoint, counts.fetched.single())
    }

    @Test fun `typed waits return Awaiting without ingest`() {
        for (read in listOf(KagemushaWalletLedgerReadV1.NotCommitted, KagemushaWalletLedgerReadV1.Unavailable)) {
            val counts = Counts()
            val awaiting = KagemushaWalletLedgerOutcomeV1.Awaiting(entrypoint)
            assertEquals(KagemushaWalletLedgerConfirmationV1(awaiting, false), confirm(counts, awaiting, read, emptyList()).join())
            assertEquals(listOf(1, 0, 0), listOf(counts.fetches, counts.ingests, counts.syncs))
        }
    }

    @Test fun `EpochRequired synchronizes then reingests the same original exactly once`() {
        val counts = Counts()
        val awaiting = KagemushaWalletLedgerOutcomeV1.Awaiting(entrypoint)
        val result = confirm(counts, awaiting, KagemushaWalletLedgerReadV1.Original(byteArrayOf(5)),
            listOf(KagemushaWalletLedgerIngestV1.EpochRequired(3_601),
                KagemushaWalletLedgerIngestV1.Outcome(KagemushaWalletLedgerOutcomeV1.Confirmed(commit)))).join()
        assertEquals(KagemushaWalletLedgerConfirmationV1(KagemushaWalletLedgerOutcomeV1.Confirmed(commit), true), result)
        assertEquals(listOf(1, 2, 1), listOf(counts.fetches, counts.ingests, counts.syncs))
        val twice = confirm(Counts(), awaiting, KagemushaWalletLedgerReadV1.Original(byteArrayOf(5)),
            listOf(KagemushaWalletLedgerIngestV1.EpochRequired(3_601), KagemushaWalletLedgerIngestV1.EpochRequired(3_601)))
        assertTrue(runCatching { twice.join() }.exceptionOrNull()?.cause is KagemushaWalletExceptionV1)
        for (selected in listOf(false, true)) {
            val uncovered = Counts()
            assertEquals(KagemushaWalletLedgerConfirmationV1(awaiting, selected),
                confirm(uncovered, awaiting, KagemushaWalletLedgerReadV1.Original(byteArrayOf(5)),
                    listOf(KagemushaWalletLedgerIngestV1.EpochRequired(3_601)),
                    KagemushaWalletLedgerEpochSyncV1(false, selected)).join())
            assertEquals(1, uncovered.ingests)
        }
    }

    @Test fun `owner loss stops before ingest and Native refusals never become outcomes`() {
        var checks = 0
        val counts = Counts()
        val lost = confirm(counts, KagemushaWalletLedgerOutcomeV1.Awaiting(entrypoint), KagemushaWalletLedgerReadV1.Original(byteArrayOf(1)),
            listOf(KagemushaWalletLedgerIngestV1.Outcome(KagemushaWalletLedgerOutcomeV1.Confirmed(commit))),
            owner = Runnable { checks++; check(checks < 2) { "owner changed" } })
        assertTrue(runCatching { lost.join() }.exceptionOrNull()?.cause is IllegalStateException)
        assertEquals(listOf(1, 0), listOf(counts.fetches, counts.ingests))
        val refused = confirmKagemushaLedgerAttemptV1(Runnable {},
            { throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT) },
            { error("must not read") }, { error("must not ingest") }, { _, _ -> error("must not synchronize") })
        assertTrue(runCatching { refused.join() }.exceptionOrNull()?.cause is KagemushaWalletExceptionV1)
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
