// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
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

/** QR carries exact wallet envelopes and the mandatory Request account companion. */
class IrohaPeerQRWalletV1Test {
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
        }
    }

    @Test
    fun `a maximum wallet message uses forty data shards and recovers one lost shard`() {
        val frame = envelope(KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletWireV1.MESSAGE_MAX_BYTES)
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
        assertEquals(1, result.recoveredDataFrames)
        assertContentEquals(frame, IrohaPeerKagemushaWalletAdapterV1.decode(assertNotNull(result.message)))
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
        assertEquals(1, result.recoveredDataFrames)
        val decoded = assertNotNull(result.message)
        assertContentEquals(envelope, IrohaPeerKagemushaWalletAdapterV1.decode(decoded))
        assertContentEquals(account, IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded))
    }

    @Test
    fun `envelopes above their kind bound or under another kind are refused`() {
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(
                envelope(KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletWireV1.MESSAGE_MAX_BYTES + 1),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerKagemushaWalletAdapterV1.wrap(
                envelope(KagemushaWalletMessageKindV1.OFFER, KagemushaWalletWireV1.SESSION_MAX_BYTES + 1),
            )
        }
        val offer = envelope(KagemushaWalletMessageKindV1.OFFER, KagemushaWalletWireV1.SESSION_MAX_BYTES)
        assertEquals(IrohaPeerPayloadKind.OFFER, IrohaPeerKagemushaWalletAdapterV1.wrap(offer).canonicalPayload.kind)
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerCanonicalPayload(
                IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
                IrohaPeerPayloadKind.REQUEST,
                1,
                offer,
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
                KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 0)
                else -> listOf(0)
            }
            val schemePath = when (kind) {
                KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> listOf(0, 1)
                KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletMessageKindV1.LINEAGE -> listOf(1, 0, 1)
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
            val last = fields.last()
            val overhead = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
            val prefixBytes = fields.dropLast(1).sumOf { Varint.encode(it.size.toLong()).size + it.size }
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
            fields[fields.lastIndex] = last + ByteArray(padding) { 0x5a }
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
