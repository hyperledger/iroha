package org.hyperledger.iroha.sdk.offline

import java.io.ByteArrayOutputStream

enum class IrohaPeerQRFrameKindV1(val code: Int) {
    COMPLETE(0), HEADER(1), DATA(2), PARITY(3);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerQRFrameKindV1? =
            entries.firstOrNull { it.code == code }
    }
}

/** One immutable, CRC32C-protected IRQR frame. */
class IrohaPeerQRFrameV1(
    val frameKind: IrohaPeerQRFrameKindV1,
    val profile: IrohaPeerPayloadProfile,
    val payloadKind: IrohaPeerPayloadKind,
    streamId: ByteArray,
    val index: Int,
    val total: Int,
    payload: ByteArray,
) {
    private val stream = streamId.copyOf()
    private val framePayload = payload.copyOf()
    val streamId: ByteArray get() = stream.copyOf()
    val payload: ByteArray get() = framePayload.copyOf()

    init {
        require(stream.size == 16) { "Malformed IRQR stream identifier" }
        require(total in 1..MAXIMUM_DATA_SHARDS && index in 0..0xffff) {
            "Malformed IRQR frame index"
        }
        require(framePayload.size <= 0xffff) { "Malformed IRQR frame payload" }
        when (frameKind) {
            IrohaPeerQRFrameKindV1.COMPLETE -> require(
                index == 0 && total == 1 &&
                    framePayload.size > IrohaPeerWireMessageV1.HEADER_LENGTH &&
                    framePayload.size <= IrohaPeerWireMessageV1.HEADER_LENGTH +
                    IrohaPeerWireMessageV1.MAXIMUM_WALLET_ENCODED_BYTES,
            ) { "Malformed complete IRQR frame" }
            IrohaPeerQRFrameKindV1.HEADER -> require(
                index == 0 && framePayload.size == IrohaPeerWireMessageV1.HEADER_LENGTH,
            ) { "Malformed header IRQR frame" }
            IrohaPeerQRFrameKindV1.DATA -> require(
                index < total && framePayload.size == IrohaPeerQRCodecV1.SHARD_BYTES,
            ) {
                "Malformed data IRQR frame"
            }
            IrohaPeerQRFrameKindV1.PARITY -> require(
                index < (total + 1) / 2 && framePayload.size == IrohaPeerQRCodecV1.SHARD_BYTES,
            ) {
                "Malformed parity IRQR frame"
            }
        }
    }

    fun encode(): ByteArray {
        val payloadEnd = PAYLOAD_OFFSET + framePayload.size
        return ByteArray(payloadEnd + 4).also { out ->
            MAGIC.copyInto(out, 0)
            out[4] = VERSION.toByte()
            out[5] = frameKind.code.toByte()
            out.writeU16(6, profile.code)
            out[8] = payloadKind.code.toByte()
            out[9] = 0
            stream.copyInto(out, 10)
            out.writeU16(26, index)
            out.writeU16(28, total)
            out.writeU16(30, framePayload.size)
            framePayload.copyInto(out, PAYLOAD_OFFSET)
            out.writeU32(payloadEnd, crc32c(out, 0, payloadEnd))
        }
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerQRFrameV1 &&
        frameKind == other.frameKind && profile == other.profile && payloadKind == other.payloadKind &&
        index == other.index && total == other.total && stream.contentEquals(other.stream) &&
        framePayload.contentEquals(other.framePayload)

    override fun hashCode(): Int = 31 * frameKind.hashCode() + framePayload.contentHashCode()

    companion object {
        const val VERSION = 1
        const val PAYLOAD_OFFSET = 32
        const val FIXED_OVERHEAD = 36
        private const val MAXIMUM_DATA_SHARDS =
            (IrohaPeerWireMessageV1.MAXIMUM_WALLET_ENCODED_BYTES + 255) / 256
        private val MAGIC = "IRQR".toByteArray(Charsets.US_ASCII)

        @JvmStatic
        fun decode(data: ByteArray): IrohaPeerQRFrameV1 {
            require(data.size >= FIXED_OVERHEAD &&
                data.copyOfRange(0, 4).contentEquals(MAGIC) &&
                (data[4].toInt() and 0xff) == VERSION
            ) { "Malformed IRQR frame" }
            val frameKind = IrohaPeerQRFrameKindV1.fromCode(data[5].toInt() and 0xff)
                ?: throw IllegalArgumentException("Malformed IRQR frame kind")
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16(6))
                ?: throw IllegalArgumentException("Malformed IRQR profile")
            val payloadKind = IrohaPeerPayloadKind.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Malformed IRQR payload kind")
            require(data[9].toInt() == 0) { "Malformed IRQR flags" }
            val payloadLength = data.readU16(30)
            val payloadEnd = PAYLOAD_OFFSET + payloadLength
            require(payloadEnd + 4 == data.size) { "Malformed IRQR frame length" }
            require(data.readU32(payloadEnd) == crc32c(data, 0, payloadEnd)) {
                "IRQR frame checksum mismatch"
            }
            return IrohaPeerQRFrameV1(
                frameKind,
                profile,
                payloadKind,
                data.copyOfRange(10, 26),
                data.readU16(26),
                data.readU16(28),
                data.copyOfRange(PAYLOAD_OFFSET, payloadEnd),
            )
        }

    }
}

/** Canonical RFC 9285 Base45 IQR1 codec and fixed 256-byte shard encoder. */
object IrohaPeerQRCodecV1 {
    const val TEXT_PREFIX = "IQR1:"
    const val TEXT_SUFFIX = ":"
    const val MAXIMUM_FRAME_TEXT_BYTES = 700
    const val SHARD_BYTES = 256
    const val PARITY_GROUP = 2
    const val HEADER_REPEAT_INTERVAL = 12

    @JvmStatic
    fun encode(payload: IrohaPeerCanonicalPayload): List<String> =
        encode(IrohaPeerWireMessageV1(
            payload,
            IrohaPeerWireCompressionPolicyV1.PEER_OPTIMIZED,
        ))

    @JvmStatic
    fun encode(message: IrohaPeerWireMessageV1): List<String> {
        val complete = staticCompleteTextCandidate(message)
        return if (complete == null) animatedFrameTexts(message) else listOf(complete)
    }

    /** Character-bounded static candidate; the renderer must also enforce QR version 17-M. */
    @JvmStatic
    fun staticCompleteTextCandidate(message: IrohaPeerWireMessageV1): String? {
        val encodedMessage = message.encode()
        return try {
            val frame = IrohaPeerQRFrameV1(
                IrohaPeerQRFrameKindV1.COMPLETE,
                message.canonicalPayload.profile,
                message.canonicalPayload.kind,
                message.streamId,
                0,
                1,
                encodedMessage,
            )
            encodeFrame(frame).takeIf {
                it.toByteArray(Charsets.UTF_8).size <= MAXIMUM_FRAME_TEXT_BYTES
            }
        } finally {
            encodedMessage.fill(0)
        }
    }

    /** Header,D0,D1,P0,... with the identical header repeated every 12 non-header frames. */
    @JvmStatic
    fun animatedFrameTexts(message: IrohaPeerWireMessageV1): List<String> {
        val body = message.encodedBody
        val encodedMessage = message.encode()
        try {
            val dataCount = (body.size + SHARD_BYTES - 1) / SHARD_BYTES
            require(dataCount in 1..0xffff) { "Peer message cannot be represented as QR" }
            val shards = ArrayList<ByteArray>(dataCount)
            repeat(dataCount) { index ->
                val shard = ByteArray(SHARD_BYTES)
                val start = index * SHARD_BYTES
                body.copyInto(shard, 0, start, minOf(start + SHARD_BYTES, body.size))
                shards += shard
            }
            val header = IrohaPeerQRFrameV1(
                IrohaPeerQRFrameKindV1.HEADER,
                message.canonicalPayload.profile,
                message.canonicalPayload.kind,
                message.streamId,
                0,
                dataCount,
                encodedMessage.copyOfRange(0, IrohaPeerWireMessageV1.HEADER_LENGTH),
            )
            val frames = ArrayList<IrohaPeerQRFrameV1>()
            frames += header
            var nonHeaderCount = 0
            fun append(frame: IrohaPeerQRFrameV1) {
                frames += frame
                nonHeaderCount += 1
                if (nonHeaderCount % HEADER_REPEAT_INTERVAL == 0) frames += header
            }
            repeat((dataCount + 1) / 2) { pairIndex ->
                val firstIndex = pairIndex * 2
                append(IrohaPeerQRFrameV1(
                    IrohaPeerQRFrameKindV1.DATA,
                    message.canonicalPayload.profile,
                    message.canonicalPayload.kind,
                    message.streamId,
                    firstIndex,
                    dataCount,
                    shards[firstIndex],
                ))
                if (firstIndex + 1 < dataCount) {
                    append(IrohaPeerQRFrameV1(
                        IrohaPeerQRFrameKindV1.DATA,
                        message.canonicalPayload.profile,
                        message.canonicalPayload.kind,
                        message.streamId,
                        firstIndex + 1,
                        dataCount,
                        shards[firstIndex + 1],
                    ))
                }
                val parity = shards[firstIndex].copyOf()
                if (firstIndex + 1 < dataCount) {
                    repeat(SHARD_BYTES) { byteIndex ->
                        parity[byteIndex] = (parity[byteIndex].toInt() xor
                            shards[firstIndex + 1][byteIndex].toInt()).toByte()
                    }
                }
                append(IrohaPeerQRFrameV1(
                    IrohaPeerQRFrameKindV1.PARITY,
                    message.canonicalPayload.profile,
                    message.canonicalPayload.kind,
                    message.streamId,
                    pairIndex,
                    dataCount,
                    parity,
                ))
                parity.fill(0)
            }
            val result = frames.map(::encodeFrame)
            shards.forEach { it.fill(0) }
            return result
        } finally {
            body.fill(0)
            encodedMessage.fill(0)
        }
    }

    @JvmStatic
    fun encodeFrame(frame: IrohaPeerQRFrameV1): String {
        val bytes = frame.encode()
        try {
            val text = TEXT_PREFIX + PeerBase45.encode(bytes) + TEXT_SUFFIX
            return text
        } finally {
            bytes.fill(0)
        }
    }

    @JvmStatic
    fun decodeFrame(value: String): IrohaPeerQRFrameV1 {
        require(value.toByteArray(Charsets.UTF_8).size <= MAXIMUM_FRAME_TEXT_BYTES &&
            value.startsWith(TEXT_PREFIX) && value.endsWith(TEXT_SUFFIX) &&
            value.length > TEXT_PREFIX.length + TEXT_SUFFIX.length
        ) { "Malformed IQR1 text" }
        val body = value.substring(TEXT_PREFIX.length, value.length - TEXT_SUFFIX.length)
        val bytes = PeerBase45.decode(body)
            ?: throw IllegalArgumentException("IQR1 body is not canonical Base45")
        try {
            require(TEXT_PREFIX + PeerBase45.encode(bytes) + TEXT_SUFFIX == value) {
                "IQR1 body is not canonical Base45"
            }
            return IrohaPeerQRFrameV1.decode(bytes)
        } finally {
            bytes.fill(0)
        }
    }

}

class IrohaPeerQRScanResultV1 internal constructor(
    val message: IrohaPeerWireMessageV1?,
    val profile: IrohaPeerPayloadProfile?,
    val payloadKind: IrohaPeerPayloadKind?,
    val receivedDataFrames: Int,
    val totalDataFrames: Int,
    val recoveredDataFrames: Int,
) {
    val isComplete: Boolean get() = message != null
    val progress: Double get() = when {
        totalDataFrames > 0 -> minOf(1.0, receivedDataFrames.toDouble() / totalDataFrames.toDouble())
        isComplete -> 1.0
        else -> 0.0
    }
}

/** Bounded resource and lifetime policy for animated QR scanning. */
class IrohaPeerQRScanLimitsV1 @JvmOverloads constructor(
    val maximumActiveStreams: Int = 3,
    val maximumPreheaderFramesPerStream: Int = 12,
    val maximumPreheaderPayloadBytesPerStream: Int = 3_072,
    val idleTimeoutMillis: Long = 30_000,
    val absoluteTimeoutMillis: Long = 180_000,
) {
    init {
        require(maximumActiveStreams in 1..3)
        require(maximumPreheaderFramesPerStream in 1..12)
        require(maximumPreheaderPayloadBytesPerStream in 1..3_072)
        require(idleTimeoutMillis in 1..30_000)
        require(absoluteTimeoutMillis in idleTimeoutMillis..180_000)
    }

    companion object { @JvmField val STANDARD = IrohaPeerQRScanLimitsV1() }
}

fun interface IrohaPeerQRClockV1 {
    fun nowMillis(): Long
}

/**
 * Process-local monotonic time for scanner lifetimes.
 *
 * [System.nanoTime] has an arbitrary origin and its raw value is permitted to
 * be negative. Capturing our own origin keeps the scanner's public clock
 * domain non-negative while preserving monotonic elapsed-time semantics.
 */
internal object IrohaPeerQRMonotonicClockV1 : IrohaPeerQRClockV1 {
    private val originNanos = System.nanoTime()

    override fun nowMillis(): Long {
        val elapsedNanos = System.nanoTime() - originNanos
        return if (elapsedNanos <= 0L) 0L else elapsedNanos / 1_000_000L
    }
}

/**
 * Thread-safe bounded multi-stream decoder. Unique progress extends only the
 * idle deadline; every stream also has an absolute lifetime.
 */
class IrohaPeerQRScanSessionV1 @JvmOverloads constructor(
    private val expectedProfile: IrohaPeerPayloadProfile? = null,
    private val expectedKind: IrohaPeerPayloadKind? = null,
    private val expectedSchemaVersion: Int? = null,
    private val scanLimits: IrohaPeerQRScanLimitsV1 = IrohaPeerQRScanLimitsV1.STANDARD,
    private val clock: IrohaPeerQRClockV1 = IrohaPeerQRMonotonicClockV1,
) {
    init {
        require(expectedSchemaVersion == null || expectedSchemaVersion in 1..0xffff) {
            "Expected IRQR schema version is invalid"
        }
    }

    private class StreamKey(bytes: ByteArray) {
        private val value = bytes.copyOf()
        val bytes: ByteArray get() = value.copyOf()
        override fun equals(other: Any?): Boolean =
            other is StreamKey && value.contentEquals(other.value)
        override fun hashCode(): Int = value.contentHashCode()
    }

    private class FrameKey(
        val kind: IrohaPeerQRFrameKindV1,
        val index: Int,
    ) {
        override fun equals(other: Any?): Boolean =
            other is FrameKey && kind == other.kind && index == other.index
        override fun hashCode(): Int = 31 * kind.hashCode() + index
    }

    private class Candidate(
        val streamId: ByteArray,
        val profile: IrohaPeerPayloadProfile,
        val payloadKind: IrohaPeerPayloadKind,
        val firstSeenMillis: Long,
        var lastProgressMillis: Long,
    ) {
        var header: IrohaPeerWireMessageV1.Header? = null
        var declaredTotal: Int? = null
        val encodedFrames = linkedMapOf<FrameKey, ByteArray>()
        val dataFrames = linkedMapOf<Int, ByteArray>()
        val parityFrames = linkedMapOf<Int, ByteArray>()
        val recovered = linkedSetOf<Int>()
        var preheaderFrameCount = 0
        var preheaderPayloadBytes = 0

        fun clear() {
            encodedFrames.values.forEach { it.fill(0) }
            dataFrames.values.forEach { it.fill(0) }
            parityFrames.values.forEach { it.fill(0) }
            streamId.fill(0)
        }
    }

    private val candidates = linkedMapOf<StreamKey, Candidate>()
    private val quarantinedUntil = linkedMapOf<StreamKey, Long>()
    private var lastObservedMillis: Long? = null

    val activeStreamCount: Int
        @Synchronized get() = candidates.size

    @Synchronized
    fun reset() {
        candidates.values.forEach(Candidate::clear)
        candidates.clear()
        quarantinedUntil.clear()
        lastObservedMillis = null
    }

    @Synchronized
    fun expire(): List<ByteArray> = expire(clock.nowMillis())

    @Synchronized
    fun expire(nowMillis: Long): List<ByteArray> {
        require(nowMillis >= 0)
        observeTime(nowMillis)
        val expired = candidates.filterValues { candidate ->
            nowMillis - candidate.lastProgressMillis >= scanLimits.idleTimeoutMillis ||
                nowMillis - candidate.firstSeenMillis >= scanLimits.absoluteTimeoutMillis
        }.keys.toList()
        expired.forEach { key -> candidates.remove(key)?.clear() }
        quarantinedUntil.entries.removeAll {
            it.value != Long.MAX_VALUE && it.value <= nowMillis
        }
        return expired.map(StreamKey::bytes)
    }

    /**
     * Quarantines a structurally valid stream rejected by application-domain
     * validation after IPM1 completion. The table is capped and uses the same
     * absolute lifetime as scanner-detected conflicts.
     */
    @Synchronized
    fun quarantine(streamId: ByteArray) = quarantine(streamId, clock.nowMillis())

    @Synchronized
    fun quarantine(streamId: ByteArray, nowMillis: Long) {
        require(streamId.size == 16) { "IRQR stream ID must be 16 bytes" }
        require(nowMillis >= 0)
        expire(nowMillis)
        quarantine(StreamKey(streamId), nowMillis)
    }

    @Synchronized
    fun ingest(value: String): IrohaPeerQRScanResultV1 =
        ingestAt(value, clock.nowMillis())

    @Synchronized
    fun ingestAt(
        value: String,
        nowMillis: Long,
    ): IrohaPeerQRScanResultV1 {
        require(nowMillis >= 0)
        val frame = IrohaPeerQRCodecV1.decodeFrame(value)
        expire(nowMillis)
        val key = StreamKey(frame.streamId)
        val quarantineDeadline = quarantinedUntil[key]
        require(quarantineDeadline == null ||
            (quarantineDeadline != Long.MAX_VALUE && quarantineDeadline <= nowMillis)) {
            "IRQR stream is quarantined"
        }
        if (expectedProfile != null && frame.profile != expectedProfile) {
            quarantine(key, nowMillis)
            throw IllegalArgumentException(
                "IRQR profile mismatch: expected $expectedProfile, received ${frame.profile}",
            )
        }
        if (expectedKind != null && frame.payloadKind != expectedKind) {
            quarantine(key, nowMillis)
            throw IllegalArgumentException(
                "IRQR kind mismatch: expected $expectedKind, received ${frame.payloadKind}",
            )
        }

        if (frame.frameKind == IrohaPeerQRFrameKindV1.COMPLETE) {
            return try {
                val messageBytes = frame.payload
                val message = try {
                    val headerBytes = messageBytes.copyOfRange(
                        0,
                        IrohaPeerWireMessageV1.HEADER_LENGTH,
                    )
                    try {
                        requireExpectedSchema(
                            IrohaPeerWireMessageV1.decodeHeader(headerBytes).schemaVersion,
                            expectedSchemaVersion,
                        )
                    } finally {
                        headerBytes.fill(0)
                    }
                    IrohaPeerWireMessageV1.decode(
                        messageBytes,
                        frame.profile,
                        frame.payloadKind,
                    )
                } finally {
                    messageBytes.fill(0)
                }
                require(message.streamId.contentEquals(frame.streamId)) { "IRQR stream mismatch" }
                candidates.remove(key)?.clear()
                IrohaPeerQRScanResultV1(
                    message,
                    frame.profile,
                    frame.payloadKind,
                    0,
                    0,
                    0,
                )
            } catch (failure: RuntimeException) {
                quarantine(key, nowMillis)
                throw failure
            }
        }

        var candidate = candidates[key]
        if (candidate == null) {
            require(candidates.size < scanLimits.maximumActiveStreams) {
                "Too many active IRQR streams"
            }
            candidate = Candidate(
                frame.streamId,
                frame.profile,
                frame.payloadKind,
                nowMillis,
                nowMillis,
            )
        } else if (candidate.profile != frame.profile || candidate.payloadKind != frame.payloadKind) {
            quarantine(key, nowMillis)
            throw IllegalArgumentException("Conflicting IRQR stream metadata")
        }

        val frameKey = FrameKey(frame.frameKind, frame.index)
        val encoded = frame.encode()
        val previous = candidate.encodedFrames[frameKey]
        if (previous != null) {
            try {
                if (!previous.contentEquals(encoded)) {
                    quarantine(key, nowMillis)
                    throw IllegalArgumentException("Conflicting duplicate IRQR frame")
                }
            } finally {
                encoded.fill(0)
            }
            candidates[key] = candidate
            return result(candidate)
        }

        try {
            val maximumShards =
                (IrohaPeerWireMessageV1.MAXIMUM_WALLET_ENCODED_BYTES +
                    IrohaPeerQRCodecV1.SHARD_BYTES - 1) / IrohaPeerQRCodecV1.SHARD_BYTES
            require(frame.total <= maximumShards) { "IRQR total exceeds profile bound" }
            candidate.declaredTotal?.let {
                require(it == frame.total) { "Conflicting IRQR frame total" }
            } ?: run { candidate.declaredTotal = frame.total }

            if (candidate.header == null && frame.frameKind != IrohaPeerQRFrameKindV1.HEADER) {
                require(candidate.preheaderFrameCount < scanLimits.maximumPreheaderFramesPerStream &&
                    frame.payload.size <=
                    scanLimits.maximumPreheaderPayloadBytesPerStream - candidate.preheaderPayloadBytes) {
                    "IRQR preheader limit exceeded"
                }
                candidate.preheaderFrameCount += 1
                candidate.preheaderPayloadBytes += frame.payload.size
            }
            candidate.encodedFrames[frameKey] = encoded
            when (frame.frameKind) {
                IrohaPeerQRFrameKindV1.HEADER -> {
                    val headerBytes = frame.payload
                    val decoded = try {
                        IrohaPeerWireMessageV1.decodeHeader(headerBytes)
                    } finally {
                        headerBytes.fill(0)
                    }
                    require(decoded.streamId.contentEquals(frame.streamId) &&
                        decoded.profile == frame.profile && decoded.kind == frame.payloadKind &&
                        dataCount(decoded) == frame.total) { "Invalid IRQR header" }
                    requireExpectedSchema(decoded.schemaVersion, expectedSchemaVersion)
                    candidate.header = decoded
                }
                IrohaPeerQRFrameKindV1.DATA -> {
                    val payload = frame.payload
                    candidate.dataFrames[frame.index]?.let { recovered ->
                        require(recovered.contentEquals(payload)) { "Conflicting recovered IRQR data" }
                        recovered.fill(0)
                        candidate.recovered.remove(frame.index)
                    }
                    candidate.dataFrames[frame.index] = payload
                }
                IrohaPeerQRFrameKindV1.PARITY ->
                    candidate.parityFrames[frame.index] = frame.payload
                IrohaPeerQRFrameKindV1.COMPLETE ->
                    throw IllegalStateException("Complete IRQR frame reached candidate path")
            }
            candidate.lastProgressMillis = nowMillis
            candidate.header?.let { header ->
                validateBuffered(candidate, header)
                recover(candidate, dataCount(header))
                if (candidate.dataFrames.size == dataCount(header)) {
                    val message = finish(candidate, header)
                    candidates.remove(key)
                    candidate.clear()
                    quarantinedUntil.remove(key)
                    return IrohaPeerQRScanResultV1(
                        message,
                        frame.profile,
                        frame.payloadKind,
                        dataCount(header),
                        dataCount(header),
                        candidate.recovered.size,
                    )
                }
            }
            candidates[key] = candidate
            return result(candidate)
        } catch (failure: RuntimeException) {
            encoded.fill(0)
            candidate.clear()
            quarantine(key, nowMillis)
            throw failure
        }
    }

    private fun validateBuffered(
        candidate: Candidate,
        header: IrohaPeerWireMessageV1.Header,
    ) {
        val total = dataCount(header)
        require(candidate.declaredTotal == total)
        candidate.dataFrames.forEach { (index, payload) ->
            require(index in 0 until total && payload.size == IrohaPeerQRCodecV1.SHARD_BYTES)
        }
        candidate.parityFrames.forEach { (index, payload) ->
            require(index in 0 until (total + 1) / 2 &&
                payload.size == IrohaPeerQRCodecV1.SHARD_BYTES)
        }
    }

    private fun requireExpectedSchema(actual: Int, expected: Int?) {
        require(expected == null || expected == actual) {
            "IRQR schema mismatch: expected $expected, received $actual"
        }
    }

    private fun recover(candidate: Candidate, total: Int) {
        repeat((total + 1) / 2) { pair ->
            val parity = candidate.parityFrames[pair] ?: return@repeat
            val first = pair * 2
            val end = minOf(first + 2, total)
            val missing = (first until end).filter { candidate.dataFrames[it] == null }
            if (missing.size != 1) return@repeat
            val recovered = parity.copyOf()
            for (index in first until end) {
                if (index == missing.single()) continue
                val present = candidate.dataFrames[index] ?: continue
                present.indices.forEach { offset ->
                    recovered[offset] =
                        (recovered[offset].toInt() xor present[offset].toInt()).toByte()
                }
            }
            candidate.dataFrames[missing.single()] = recovered
            candidate.recovered += missing.single()
        }
    }

    private fun finish(
        candidate: Candidate,
        header: IrohaPeerWireMessageV1.Header,
    ): IrohaPeerWireMessageV1 {
        val total = dataCount(header)
        val output = ByteArrayOutputStream(
            IrohaPeerWireMessageV1.HEADER_LENGTH + total * IrohaPeerQRCodecV1.SHARD_BYTES,
        )
        val headerBytes = header.bytes()
        output.write(headerBytes)
        headerBytes.fill(0)
        repeat(total) { output.write(candidate.dataFrames[it] ?: error("Missing IRQR shard")) }
        val padded = output.toByteArray()
        val messageEnd = IrohaPeerWireMessageV1.HEADER_LENGTH + header.encodedLength
        require(padded.copyOfRange(messageEnd, padded.size).all { it.toInt() == 0 }) {
            "Nonzero IRQR padding"
        }
        val messageBytes = padded.copyOf(messageEnd)
        padded.fill(0)
        return try {
            IrohaPeerWireMessageV1.decode(
                messageBytes,
                candidate.profile,
                candidate.payloadKind,
            ).also {
                require(it.streamId.contentEquals(candidate.streamId)) { "IRQR stream mismatch" }
            }
        } finally {
            messageBytes.fill(0)
        }
    }

    private fun dataCount(header: IrohaPeerWireMessageV1.Header): Int =
        ((header.encodedLength + IrohaPeerQRCodecV1.SHARD_BYTES - 1) /
            IrohaPeerQRCodecV1.SHARD_BYTES).also {
            require(it in 1..0xffff)
        }

    private fun result(candidate: Candidate) = IrohaPeerQRScanResultV1(
        null,
        candidate.profile,
        candidate.payloadKind,
        candidate.dataFrames.size,
        candidate.header?.let(::dataCount) ?: 0,
        candidate.recovered.size,
    )

    private fun quarantine(key: StreamKey, nowMillis: Long) {
        candidates.remove(key)?.clear()
        quarantinedUntil[key] = saturatingDeadline(
            nowMillis,
            scanLimits.absoluteTimeoutMillis,
        )
        if (quarantinedUntil.size > 12) {
            quarantinedUntil.minByOrNull { it.value }?.key?.let(quarantinedUntil::remove)
        }
    }

    private fun saturatingDeadline(nowMillis: Long, lifetimeMillis: Long): Long =
        if (nowMillis > Long.MAX_VALUE - lifetimeMillis) {
            Long.MAX_VALUE
        } else {
            nowMillis + lifetimeMillis
        }

    private fun observeTime(nowMillis: Long) {
        require(lastObservedMillis == null || nowMillis >= checkNotNull(lastObservedMillis)) {
            "IRQR scanner time must be monotonic until reset"
        }
        lastObservedMillis = nowMillis
    }
}

internal object PeerBase45 {
    private val alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \$%*+-./:".toByteArray(Charsets.US_ASCII)
    private val reverse = IntArray(128) { -1 }.also { table ->
        alphabet.forEachIndexed { index, byte -> table[byte.toInt()] = index }
    }

    fun encode(data: ByteArray): String {
        val output = ByteArray((data.size / 2) * 3 + (data.size % 2) * 2)
        var source = 0
        var target = 0
        while (source + 1 < data.size) {
            var value = (data[source].toInt() and 0xff) * 256 + (data[source + 1].toInt() and 0xff)
            output[target++] = alphabet[value % 45]
            value /= 45
            output[target++] = alphabet[value % 45]
            output[target++] = alphabet[value / 45]
            source += 2
        }
        if (source < data.size) {
            val value = data[source].toInt() and 0xff
            output[target++] = alphabet[value % 45]
            output[target] = alphabet[value / 45]
        }
        return output.toString(Charsets.US_ASCII)
    }

    fun decode(value: String): ByteArray? {
        val input = value.toByteArray(Charsets.US_ASCII)
        if (input.isEmpty() || input.size % 3 == 1 || input.size != value.length) return null
        val output = ByteArray((input.size / 3) * 2 + if (input.size % 3 == 2) 1 else 0)
        var source = 0
        var target = 0
        while (source + 2 < input.size) {
            val a = digit(input[source]) ?: return null
            val b = digit(input[source + 1]) ?: return null
            val c = digit(input[source + 2]) ?: return null
            val decoded = a + b * 45 + c * 2025
            if (decoded > 0xffff) return null
            output[target++] = (decoded / 256).toByte()
            output[target++] = decoded.toByte()
            source += 3
        }
        if (source < input.size) {
            val a = digit(input[source]) ?: return null
            val b = digit(input[source + 1]) ?: return null
            val decoded = a + b * 45
            if (decoded > 0xff) return null
            output[target] = decoded.toByte()
        }
        return output
    }

    private fun digit(byte: Byte): Int? {
        val code = byte.toInt() and 0xff
        if (code >= reverse.size || reverse[code] < 0) return null
        return reverse[code]
    }
}

private fun crc32c(value: ByteArray, start: Int, endExclusive: Int): Long {
    var crc = -1
    for (index in start until endExclusive) {
        crc = crc xor (value[index].toInt() and 0xff)
        repeat(8) { crc = if ((crc and 1) == 0) crc ushr 1 else (crc ushr 1) xor 0x82f63b78.toInt() }
    }
    return (crc xor -1).toLong() and 0xffff_ffffL
}

private fun ByteArray.writeU16(offset: Int, value: Int) {
    this[offset] = (value ushr 8).toByte()
    this[offset + 1] = value.toByte()
}

private fun ByteArray.writeU32(offset: Int, value: Long) {
    this[offset] = (value ushr 24).toByte()
    this[offset + 1] = (value ushr 16).toByte()
    this[offset + 2] = (value ushr 8).toByte()
    this[offset + 3] = value.toByte()
}

private fun ByteArray.readU16(offset: Int): Int =
    ((this[offset].toInt() and 0xff) shl 8) or (this[offset + 1].toInt() and 0xff)

private fun ByteArray.readU32(offset: Int): Long =
    ((this[offset].toLong() and 0xff) shl 24) or
        ((this[offset + 1].toLong() and 0xff) shl 16) or
        ((this[offset + 2].toLong() and 0xff) shl 8) or
        (this[offset + 3].toLong() and 0xff)

private fun ByteArray?.contentEqualsNullable(other: ByteArray): Boolean =
    this != null && contentEquals(other)

private fun copyMap(source: Map<Int, ByteArray>): LinkedHashMap<Int, ByteArray> =
    LinkedHashMap<Int, ByteArray>().also { copy -> source.forEach { (key, value) -> copy[key] = value.copyOf() } }

private fun clearMap(map: Map<Int, ByteArray>) = map.values.forEach { it.fill(0) }
