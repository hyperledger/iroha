// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.Varint

/** QR carries exact wallet envelopes, the mandatory Request account companion and the mandatory Payment payer companion. */
class IrohaPeerQRWalletV1Test {
    @Test
    fun `same-index header data and parity conflicts quarantine only that stream`() {
        val original = envelope(KagemushaWalletMessageKindV1.CREDITED, 1_024)
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(original)
        val frames = IrohaPeerQRCodecV1.animatedFrameTexts(message).map(IrohaPeerQRCodecV1::decodeFrame)
        val header = frames.first { it.frameKind == IrohaPeerQRFrameKindV1.HEADER }
        val unrelated = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope(KagemushaWalletMessageKindV1.CREDITED, 1_025))
        val unrelatedTexts = IrohaPeerQRCodecV1.animatedFrameTexts(unrelated)
        val limits = IrohaPeerQRScanLimitsV1(idleTimeoutMillis = 2_000, absoluteTimeoutMillis = 3_000)
        for (kind in listOf(IrohaPeerQRFrameKindV1.HEADER, IrohaPeerQRFrameKindV1.DATA, IrohaPeerQRFrameKindV1.PARITY)) {
            for (hasHeader in if (kind == IrohaPeerQRFrameKindV1.HEADER) listOf(false) else listOf(false, true)) {
                val session = IrohaPeerQRScanSessionV1(scanLimits = limits)
                assertNull(session.ingestAt(unrelatedTexts.first(), 0).message)
                if (hasHeader) assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 0).message)
                val first = frames.first { it.frameKind == kind }
                assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(first), 0).message)
                val payload = first.payload.also { it[0] = (it[0].toInt() xor 1).toByte() }
                // Re-encode the frame checksum: this is a conflicting valid frame, not CRC noise.
                val conflict = IrohaPeerQRFrameV1(kind, first.profile, first.payloadKind, first.streamId,
                    first.index, first.total, payload)
                assertEquals("Conflicting duplicate IRQR frame", assertFailsWith<IllegalArgumentException> {
                    session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(conflict), 0)
                }.message)
                assertEquals(1, session.activeStreamCount)
                assertEquals("IRQR stream is quarantined", assertFailsWith<IllegalArgumentException> {
                    session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 0)
                }.message)
                val other = unrelatedTexts.asSequence().map { session.ingestAt(it, 0) }.first { it.isComplete }
                assertContentEquals(unrelated.encode(), assertNotNull(other.message).encode())
                assertEquals(0, session.activeStreamCount)
                val retry = frames.asSequence().map { session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(it), 3_000) }
                    .first { it.isComplete }
                val retried = assertNotNull(retry.message)
                assertContentEquals(original, IrohaPeerKagemushaWalletAdapterV1.decode(retried))
                assertContentEquals(message.encode(), retried.encode())
            }
        }
    }

    @Test
    fun `reordered duplicated frames recover lost Payment shards without changing either original`() {
        val message = IrohaPeerNfcTestFixturesV1.payment
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val frames = texts.map(IrohaPeerQRCodecV1::decodeFrame)
        val header = frames.first { it.frameKind == IrohaPeerQRFrameKindV1.HEADER }
        val shards = frames.filter { it.frameKind != IrohaPeerQRFrameKindV1.HEADER }
        val total = header.total
        // All parity plus the last data shards: lose the maximum recoverable data prefix.
        val retained = (shards.filter { it.frameKind == IrohaPeerQRFrameKindV1.PARITY } +
            shards.filter { it.frameKind == IrohaPeerQRFrameKindV1.DATA }.takeLast(total / 2))
            .shuffled(kotlin.random.Random(31))
        assertEquals(total, retained.size)
        val session = IrohaPeerQRScanSessionV1(expectedKind = IrohaPeerPayloadKind.PAYMENT)
        val preheader = IrohaPeerQRCodecV1.encodeFrame(retained.first())
        assertNull(session.ingestAt(preheader, 0).message)
        assertNull(session.ingestAt(preheader, 0).message)
        assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 0).message)
        retained.dropLast(1).forEach { frame ->
            val text = IrohaPeerQRCodecV1.encodeFrame(frame)
            val first = session.ingestAt(text, 0)
            val duplicate = session.ingestAt(text, 0)
            assertNull(first.message)
            assertNull(duplicate.message)
            assertEquals(first.usableFrames, duplicate.usableFrames)
            assertEquals(first.receivedDataFrames, duplicate.receivedDataFrames)
        }
        val result = session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(retained.last()), 0)
        val decoded = assertNotNull(result.message)
        assertEquals((total + 1) / 2, result.recoveredDataFrames)
        assertEquals(0, session.activeStreamCount)
        assertContentEquals(message.encode(), decoded.encode())
        assertContentEquals(IrohaPeerKagemushaWalletAdapterV1.decode(message), IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
        assertContentEquals(IrohaPeerKagemushaWalletAdapterV1.payerCompanion(message), IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded))
        assertEquals(texts, IrohaPeerQRCodecV1.animatedFrameTexts(decoded))
    }

    @Test
    fun `valid frame checksums cannot substitute a corrupted canonical message`() {
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope(KagemushaWalletMessageKindV1.CREDITED, 1_024))
        val frames = IrohaPeerQRCodecV1.animatedFrameTexts(message).map(IrohaPeerQRCodecV1::decodeFrame)
        val header = frames.first { it.frameKind == IrohaPeerQRFrameKindV1.HEADER }
        val data = frames.filter { it.frameKind == IrohaPeerQRFrameKindV1.DATA }
        val session = IrohaPeerQRScanSessionV1()
        assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 0).message)
        data.dropLast(1).forEach { frame ->
            val payload = frame.payload
            if (frame.index == 0) payload[0] = (payload[0].toInt() xor 1).toByte()
            val changed = IrohaPeerQRFrameV1(frame.frameKind, frame.profile, frame.payloadKind,
                frame.streamId, frame.index, frame.total, payload)
            assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(changed), 0).message)
        }
        assertFailsWith<IllegalArgumentException> {
            session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(data.last()), 0)
        }
        assertEquals(0, session.activeStreamCount)
        assertEquals("IRQR stream is quarantined", assertFailsWith<IllegalArgumentException> {
            session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 0)
        }.message)
    }

    @Test
    fun `concurrent streams respect capacity and rejected streams can retry after completion`() {
        val messages = (0..3).map {
            IrohaPeerKagemushaWalletAdapterV1.wrap(envelope(KagemushaWalletMessageKindV1.CREDITED, 1_024 + it))
        }
        val frames = messages.map { message ->
            IrohaPeerQRCodecV1.animatedFrameTexts(message).map(IrohaPeerQRCodecV1::decodeFrame)
        }
        for (capacity in 1..3) {
            val session = IrohaPeerQRScanSessionV1(scanLimits = IrohaPeerQRScanLimitsV1(maximumActiveStreams = capacity))
            val executor = Executors.newFixedThreadPool(messages.size)
            val entered = CountDownLatch(messages.size)
            val start = CountDownLatch(1)
            val accepted = try {
                val submissions = frames.map { stream -> executor.submit(Callable {
                    entered.countDown()
                    check(start.await(5, TimeUnit.SECONDS))
                    try {
                        assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(stream.first()), 0).message)
                        true
                    } catch (failure: IllegalArgumentException) {
                        assertEquals("Too many active IRQR streams", failure.message)
                        false
                    }
                }) }
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                start.countDown()
                submissions.map { it.get(5, TimeUnit.SECONDS) }
            } finally {
                start.countDown()
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            }
            assertEquals(capacity, accepted.count { it })
            assertEquals(capacity, session.activeStreamCount)
            val order = accepted.indices.filter { accepted[it] } + accepted.indices.filter { !accepted[it] }
            for (index in order) {
                val result = frames[index].asSequence()
                    .map { session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(it), 0) }.first { it.isComplete }
                assertContentEquals(messages[index].encode(), assertNotNull(result.message).encode())
                assertTrue(session.activeStreamCount <= capacity)
            }
            assertEquals(0, session.activeStreamCount)
        }
    }

    @Test
    fun `every wallet envelope vector round trips through QR under its own kind`() {
        val envelopes = vectors().getValue("envelopes").jsonArray.map { it.jsonObject }
        for (vector in envelopes) {
            val frame = hex(vector.getValue("canonical_hex").jsonPrimitive.content)
            val kind = requireNotNull(IrohaPeerPayloadKind.fromCode(vector.getValue("tag").jsonPrimitive.int))
            val message = IrohaPeerKagemushaWalletAdapterV1.wrap(
                frame,
                IrohaPeerWireCompressionPolicyV1.PEER_OPTIMIZED,
                destinationAccountOriginal = if (kind == IrohaPeerPayloadKind.REQUEST) IrohaPeerRequestFixtureV1.account() else null,
                payerCompanion = if (kind == IrohaPeerPayloadKind.PAYMENT) IrohaPeerRequestFixtureV1.companion() else null,
            )
            assertEquals(kind, message.canonicalPayload.kind)
            val session = IrohaPeerQRScanSessionV1(
                IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
                kind,
                1,
            )
            val result = IrohaPeerQRCodecV1.encode(message).asSequence()
                .map { session.ingestAt(it, 0) }
                .first { it.isComplete }
            val decoded = assertNotNull(result.message)
            assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
            if (kind == IrohaPeerPayloadKind.PAYMENT) {
                assertContentEquals(IrohaPeerRequestFixtureV1.companion(), IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded))
            }
        }
    }

    @Test
    fun `a maximum Payment carrier uses forty eight data shards and survives one lost shard`() {
        val frame = envelope(KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        val companion = ByteArray(IrohaPeerWalletPaymentV1.MAXIMUM_COMPANION_BYTES) { (it % 239).toByte() } // Bounded transport DATA.
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(frame, payerCompanion = companion)
        assertEquals(12_064, message.encodedBody.size)
        assertNull(IrohaPeerQRCodecV1.staticCompleteTextCandidate(message))
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val frames = texts.map { IrohaPeerQRCodecV1.decodeFrame(it) }
        assertEquals(79, texts.size)
        assertEquals(7, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.HEADER })
        assertEquals(48, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.DATA })
        assertEquals(24, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.PARITY })
        assertEquals(setOf(48), frames.map { it.total }.toSet())
        val lost = frames.indexOfFirst { it.frameKind == IrohaPeerQRFrameKindV1.DATA && it.index == 45 }
        val session = IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, IrohaPeerPayloadKind.PAYMENT, 1)
        val result = texts.filterIndexed { index, _ -> index != lost }.asSequence()
            .map { session.ingestAt(it, 0) }.first { it.isComplete }
        // Any 48 of the 72 shards complete it: 32 data and 16 parity, two thirds into the loop.
        assertEquals(16, result.recoveredDataFrames)
        val decoded = assertNotNull(result.message)
        assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
        assertContentEquals(companion, IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded))
    }

    @Test
    fun `a maximum envelope-only message uses forty data shards and recovers one lost shard`() {
        val frame = envelope(KagemushaWalletMessageKindV1.CREDITED, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(frame)
        assertEquals(10_000, message.encodedBody.size)
        assertNull(IrohaPeerQRCodecV1.staticCompleteTextCandidate(message))
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val frames = texts.map { IrohaPeerQRCodecV1.decodeFrame(it) }
        assertEquals(66, texts.size)
        assertEquals(6, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.HEADER })
        assertEquals(40, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.DATA })
        assertEquals(20, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.PARITY })
        assertEquals(setOf(40), frames.map { it.total }.toSet())

        val session = IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1)
        val lost = frames.indexOfFirst { it.frameKind == IrohaPeerQRFrameKindV1.DATA && it.index == 7 }
        val result = texts.filterIndexed { index, _ -> index != lost }.asSequence()
            .map { session.ingestAt(it, 0) }
            .first { it.isComplete }
        // Any 40 of the 60 shards complete it: 27 data and 13 parity, before the loop ends.
        assertEquals(13, result.recoveredDataFrames)
        assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(assertNotNull(result.message)))
    }

    @Test
    fun `any forty of the sixty data and parity frames recover a maximum message`() {
        val frame = envelope(KagemushaWalletMessageKindV1.CREDITED, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(IrohaPeerKagemushaWalletAdapterV1.wrap(frame))
        val frames = texts.map { IrohaPeerQRCodecV1.decodeFrame(it) }
        val shardFrames = frames.indices.filter { frames[it].frameKind != IrohaPeerQRFrameKindV1.HEADER }
        assertEquals(60, shardFrames.size)
        fun scan(lost: Set<Int>): IrohaPeerQRScanResultV1? {
            val session = IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1)
            // One pass of the loop only: completion may not wait for a repeat of a lost frame.
            return texts.indices.filter { it !in lost }.asSequence()
                .map { session.ingestAt(texts[it], 0) }
                .firstOrNull { it.isComplete }
        }
        val dataFrames = shardFrames.filter { frames[it].frameKind == IrohaPeerQRFrameKindV1.DATA }
        val patterns = listOf(
            dataFrames.take(20).toSet(), // Half the data: every parity row is needed.
            dataFrames.take(2).toSet(), // Both shards of one pair, which pair parity could not recover.
        ) + (1..3).map { seed -> shardFrames.shuffled(kotlin.random.Random(seed)).take(20).toSet() }
        for (lost in patterns) {
            val result = assertNotNull(scan(lost), "lost frames $lost")
            // Completion needs only forty distinct shards, so frames still to come are solved for too.
            val lostData = lost.count { frames[it].frameKind == IrohaPeerQRFrameKindV1.DATA }
            assertTrue(result.recoveredDataFrames in lostData..20, "recovered ${result.recoveredDataFrames}")
            assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(assertNotNull(result.message)))
        }
        // Twenty-one lost leaves thirty-nine shards, one too few: the scan waits for the next loop.
        assertNull(scan(shardFrames.take(21).toSet()))
    }

    @Test
    fun `Reed-Solomon parity rows match the shared cross-platform vector`() {
        // Shard i byte b = (73 i + 31 b + 7) mod 256; Swift pins the same digests.
        fun digest(count: Int): String {
            val shards = List(count) { i -> ByteArray(IrohaPeerQRCodecV1.SHARD_BYTES) { b -> (73 * i + 31 * b + 7).toByte() } }
            val sha = java.security.MessageDigest.getInstance("SHA-256")
            repeat((count + 1) / 2) { row -> sha.update(IrohaPeerQRParityV1.parity(shards, row)) }
            return sha.digest().joinToString("") { "%02x".format(it) }
        }
        assertEquals("d218dc10e7482f1afb8753f100542879651bc6e2f0641a94bb2d33a11e433dd8", digest(3))
        assertEquals("85f3a1490a000f345272c2fb1b4dc449bafd07e95a1c694d58c5a341f07f375c", digest(40))
    }

    @Test
    fun `a scan that misses the first header it meets still completes`() {
        // Unchanged Rust vectors share a checked payer binding; this tests transport, not proof admission.
        val source = vectors()
        val paymentVector = source.getValue("envelopes").jsonArray.map { it.jsonObject }
            .single { it.getValue("tag").jsonPrimitive.int == KagemushaWalletMessageKindV1.PAYMENT.wireTag }
        val frame = hex(paymentVector.getValue("canonical_hex").jsonPrimitive.content)
        val companionVector = source.getValue("objects").jsonArray.map { it.jsonObject }
            .single { it.getValue("type").jsonPrimitive.content == "KagemushaWalletPayerCompanionV1" }
        val companion = hex(companionVector.getValue("canonical_hex").jsonPrimitive.content)
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(frame, payerCompanion = companion)
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val kinds = texts.map { IrohaPeerQRCodecV1.decodeFrame(it).frameKind }
        val missed = kinds.indices.first { it > 0 && kinds[it] == IrohaPeerQRFrameKindV1.HEADER }
        assertEquals(13, missed)
        val session = IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, IrohaPeerPayloadKind.PAYMENT, 1)
        // The camera opens just after the first header and misses the next one, so the twelve
        // frames between them and one more arrive before any header.
        (1 until missed).forEach { assertNull(session.ingestAt(texts[it], 0).message) }
        val beyondBound = session.ingestAt(texts[missed + 1], 0)
        assertNull(beyondBound.message)
        assertEquals(0, beyondBound.totalDataFrames)
        assertEquals(1, session.activeStreamCount)
        // Frames beyond the bound are dropped unbuffered, not refused: the next loop supplies them.
        val result = ((missed + 2 until texts.size) + texts.indices).asSequence()
            .map { session.ingestAt(texts[it], 0) }
            .first { it.isComplete }
        val decoded = assertNotNull(result.message)
        assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
        assertContentEquals(companion, IrohaPeerKagemushaWalletAdapterV1.payerCompanion(decoded))
    }

    @Test
    fun `dropped preheader retains total for data and header conflicts`() {
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope(KagemushaWalletMessageKindV1.CREDITED, 1_024))
        val frames = IrohaPeerQRCodecV1.animatedFrameTexts(message).map { IrohaPeerQRCodecV1.decodeFrame(it) }
        val data = frames.first { it.frameKind == IrohaPeerQRFrameKindV1.DATA }
        val header = frames.first { it.frameKind == IrohaPeerQRFrameKindV1.HEADER }
        val changedTotal = IrohaPeerQRFrameV1(
            data.frameKind, data.profile, data.payloadKind, data.streamId,
            data.index, data.total + 1, data.payload,
        )
        val limits = IrohaPeerQRScanLimitsV1(
            maximumPreheaderPayloadBytesPerStream = 1, idleTimeoutMillis = 2_000, absoluteTimeoutMillis = 3_000,
        )
        for ((first, conflicting) in listOf(data to changedTotal, changedTotal to header)) {
            val session = IrohaPeerQRScanSessionV1(scanLimits = limits)
            val dropped = session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(first), 100_000)
            assertNull(dropped.message)
            assertEquals(0, dropped.receivedDataFrames)
            assertEquals(1, session.activeStreamCount)
            val conflict = assertFailsWith<IllegalArgumentException> {
                session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(conflicting), 100_000)
            }
            assertEquals("Conflicting IRQR frame total", conflict.message)
            assertEquals(0, session.activeStreamCount)
            val quarantined = assertFailsWith<IllegalArgumentException> {
                session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 102_999)
            }
            assertEquals("IRQR stream is quarantined", quarantined.message)
            assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(header), 103_000).message)
            assertEquals(1, session.activeStreamCount)
        }
    }

    @Test
    fun `dropped preheaders do not refresh idle and stream completes after expiry`() {
        val frame = envelope(KagemushaWalletMessageKindV1.CREDITED, 1_024)
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(frame)
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val data = texts.filter { IrohaPeerQRCodecV1.decodeFrame(it).frameKind == IrohaPeerQRFrameKindV1.DATA }
        val limits = IrohaPeerQRScanLimitsV1(
            maximumPreheaderPayloadBytesPerStream = 1, idleTimeoutMillis = 2_000, absoluteTimeoutMillis = 3_000,
        )
        val session = IrohaPeerQRScanSessionV1(scanLimits = limits)
        for ((index, now) in listOf(0 to 100_000L, 1 to 101_500L)) {
            val dropped = session.ingestAt(data[index], now)
            assertNull(dropped.message)
            assertEquals(0, dropped.receivedDataFrames)
            assertEquals(0, dropped.totalDataFrames)
        }
        val expired = session.expire(102_000)
        assertEquals(1, expired.size)
        assertContentEquals(message.streamId, expired.single())
        assertEquals(0, session.activeStreamCount)
        val completed = texts.asSequence().map { session.ingestAt(it, 102_000) }.first { it.isComplete }
        assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(assertNotNull(completed.message)))
    }

    @Test
    fun `maximum Request companion uses fifty six data shards and survives one lost shard`() {
        val envelope = envelope(KagemushaWalletMessageKindV1.REQUEST, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
        val account = ByteArray(4_096) { (it % 251).toByte() } // Bounded transport DATA, no account admission.
        val message = IrohaPeerKagemushaWalletAdapterV1.wrap(envelope, destinationAccountOriginal = account)
        assertEquals(14_112, message.encodedBody.size)
        val texts = IrohaPeerQRCodecV1.animatedFrameTexts(message)
        val frames = texts.map { IrohaPeerQRCodecV1.decodeFrame(it) }
        assertEquals(56, frames.count { it.frameKind == IrohaPeerQRFrameKindV1.DATA })
        assertEquals(setOf(56), frames.map { it.total }.toSet())
        val lost = frames.indexOfFirst { it.frameKind == IrohaPeerQRFrameKindV1.DATA && it.index == 53 }
        val session = IrohaPeerQRScanSessionV1(IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, IrohaPeerPayloadKind.REQUEST, 1)
        val result = texts.filterIndexed { index, _ -> index != lost }.asSequence()
            .map { session.ingestAt(it, 0) }.first { it.isComplete }
        // Any 56 of the 84 shards complete it: 38 data and 18 parity.
        assertEquals(18, result.recoveredDataFrames)
        val decoded = assertNotNull(result.message)
        assertContentEquals(envelope, IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
        assertContentEquals(account, IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded))
    }

    @Test
    fun `envelopes above their kind bound or under another kind are refused`() {
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(
                envelope(KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1),
                payerCompanion = byteArrayOf(1),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(
                envelope(KagemushaWalletMessageKindV1.SESSION_CONTROL, KagemushaWalletWireV1.SESSION_MAX_BYTES + 1),
            )
        }
        val control = envelope(KagemushaWalletMessageKindV1.SESSION_CONTROL, KagemushaWalletWireV1.SESSION_MAX_BYTES)
        assertEquals(IrohaPeerPayloadKind.SESSION_CONTROL, IrohaPeerKagemushaWalletAdapterV1.wrap(control).canonicalPayload.kind)
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerCanonicalPayload(
                IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
                IrohaPeerPayloadKind.REQUEST,
                1,
                control,
            )
        }
    }

    @Test
    fun `QR adapter refuses invalid message versions and scheme lengths for every kind`() {
        val covered = HashSet<KagemushaWalletMessageKindV1>()
        for (vector in vectors().getValue("envelopes").jsonArray.map { it.jsonObject }) {
            val frame = hex(vector.getValue("canonical_hex").jsonPrimitive.content)
            val kind = requireNotNull(KagemushaWalletMessageKindV1.fromWireTag(vector.getValue("tag").jsonPrimitive.int))
            covered.add(kind)
            val versionPath = when (kind) {
                KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 0)
                else -> listOf(0)
            }
            val schemePath = when (kind) {
                KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 1)
                KagemushaWalletMessageKindV1.PAYMENT -> listOf(2, 1, 1)
                else -> listOf(1)
            }
            for ((label, path, bytes) in listOf(
                Triple("message version", versionPath, byteArrayOf(2, 0)),
                Triple("scheme length", schemePath, ByteArray(31)),
            )) {
                val changed = withReplacedMessageField(frame, kind, path, bytes)
                val rejected = assertFailsWith<IllegalArgumentException>("${kind.label} $label") {
                    IrohaPeerKagemushaWalletAdapterV1.wrap(changed)
                }
                assertTrue(rejected.message.orEmpty().contains(if (label == "message version") "message version" else "scheme field"), rejected.message)
            }
        }
        assertEquals(KagemushaWalletMessageKindV1.entries.toSet(), covered)
    }

    private companion object {
        fun vectors() = Json.parseToJsonElement(
            String(Files.readAllBytes(fixturePath()), StandardCharsets.UTF_8),
        ).jsonObject

        fun fixturePath(): java.nio.file.Path {
            var current: java.nio.file.Path? = Paths.get("").toAbsolutePath().normalize()
            while (current != null) {
                val candidate = current.resolve("fixtures/kagemusha/wallet_v1_vectors.json")
                if (Files.isRegularFile(candidate)) return candidate
                current = current.parent
            }
            error("fixtures/kagemusha/wallet_v1_vectors.json was not found above the test working directory")
        }

        fun hex(text: String): ByteArray =
            ByteArray(text.length / 2) { index -> text.substring(2 * index, 2 * index + 2).toInt(16).toByte() }

        /**
         * Pad an authentic Rust vector's last message field to [frameLength], preserving its
         * own version and scheme path. Added filler tests transport limits only and does not
         * claim a valid typed message, signature, financial proof or monetary outcome.
         */
        fun envelope(kind: KagemushaWalletMessageKindV1, frameLength: Int): ByteArray {
            val vector = vectors().getValue("envelopes").jsonArray.map { it.jsonObject }
                .first { it.getValue("tag").jsonPrimitive.int == kind.wireTag }
            val fields = recordFields(envelopeMessage(hex(vector.getValue("canonical_hex").jsonPrimitive.content))).toMutableList()
            // Keep Payment proof-bearing Send fields exact; its unique Request field is opaque here.
            val paddingIndex = if (kind == KagemushaWalletMessageKindV1.PAYMENT) 1 else fields.lastIndex
            val last = fields[paddingIndex]
            val overhead = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val prefixBytes = fields.filterIndexed { index, _ -> index != paddingIndex }
                .sumOf { Varint.encode(it.size.toLong()).size + it.size }
            var padding = 0
            while (true) {
                val lastLength = last.size + padding
                val variantLength = prefixBytes + Varint.encode(lastLength.toLong()).size + lastLength
                val messageLength = 4 + Varint.encode(variantLength.toLong()).size + variantLength
                val total = overhead + 3 + Varint.encode(messageLength.toLong()).size + messageLength
                if (total == frameLength) break
                check(total < frameLength) { "no envelope of exactly $frameLength bytes" }
                padding += 1
            }
            fields[paddingIndex] = last + ByteArray(padding) { 0x5a }
            return envelopeWithMessage(kind, encodeRecord(fields))
        }

        fun envelopeMessage(frame: ByteArray): ByteArray {
            val offset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val payload = frame.copyOfRange(offset, frame.size)
            var cursor = Varint.decode(payload, 0).nextOffset + 2
            cursor = Varint.decode(payload, cursor).nextOffset + 4
            cursor = Varint.decode(payload, cursor).nextOffset
            return payload.copyOfRange(cursor, payload.size)
        }

        fun recordFields(record: ByteArray): List<ByteArray> {
            val fields = ArrayList<ByteArray>()
            var cursor = 0
            while (cursor < record.size) {
                val length = Varint.decode(record, cursor)
                check(length.value in 0L..(record.size - length.nextOffset).toLong())
                cursor = length.nextOffset + length.value.toInt()
                fields.add(record.copyOfRange(length.nextOffset, cursor))
            }
            return fields
        }

        fun encodeRecord(fields: List<ByteArray>): ByteArray =
            fields.fold(ByteArray(0)) { all, field -> all + Varint.encode(field.size.toLong()) + field }

        /** Rebuild every containing length and CRC, without inspecting the rejected result. */
        fun withReplacedMessageField(
            frame: ByteArray,
            kind: KagemushaWalletMessageKindV1,
            path: List<Int>,
            replacement: ByteArray,
        ): ByteArray {
            fun changed(record: ByteArray, remaining: List<Int>): ByteArray {
                val fields = recordFields(record).toMutableList()
                val index = remaining.first()
                fields[index] = if (remaining.size == 1) replacement else changed(fields[index], remaining.drop(1))
                return encodeRecord(fields)
            }
            return envelopeWithMessage(kind, changed(envelopeMessage(frame), path))
        }

        fun envelopeWithMessage(kind: KagemushaWalletMessageKindV1, record: ByteArray): ByteArray {
            val message = byteArrayOf(kind.wireTag.toByte(), 0, 0, 0) + Varint.encode(record.size.toLong()) + record
            val payload = byteArrayOf(2, 1, 0) + Varint.encode(message.size.toLong()) + message
            return NoritoHeader(
                KagemushaWalletWireV1.envelopeSchemaHash(),
                payload.size,
                CRC64.compute(payload),
                NoritoHeader.COMPACT_LEN,
                NoritoHeader.COMPRESSION_NONE,
            ).encode() + ByteArray(KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES) + payload
        }
    }
}
