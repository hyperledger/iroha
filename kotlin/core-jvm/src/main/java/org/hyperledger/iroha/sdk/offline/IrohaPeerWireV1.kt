package org.hyperledger.iroha.sdk.offline

import org.hyperledger.iroha.sdk.crypto.Blake2b
import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater

/** Stable application profile identifiers carried by IPM1. */
enum class IrohaPeerPayloadProfile(
    val code: Int,
    val requiredSchemaVersion: Int,
) {
    /**
     * KAGEMUSHA wallet V1 peer messages: Request carries its unchanged complete envelope and required account companion;
     * other canonical payloads are one complete `KagemushaWalletEnvelopeV1` frame (`specs/kagemusha_wallet_wire_v1.md` sections 2 and 3.4).
     */
    KAGEMUSHA_WALLET_V1(1, KagemushaWalletWireV1.VERSION);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerPayloadProfile? =
            entries.firstOrNull { it.code == code }
    }
}

/**
 * Message kinds carried by IPM1. Each code equals the KAGEMUSHA wallet V1 envelope message tag
 * ([KagemushaWalletMessageKindV1.wireTag]) of the frame the message carries.
 */
enum class IrohaPeerPayloadKind(
    val code: Int,
    /** Wallet envelope message kind carried under this IPM1 kind. */
    val walletMessageKind: KagemushaWalletMessageKindV1,
) {
    OFFER(1, KagemushaWalletMessageKindV1.OFFER),
    REQUEST(2, KagemushaWalletMessageKindV1.REQUEST),
    PAYMENT(3, KagemushaWalletMessageKindV1.PAYMENT),
    CREDITED(4, KagemushaWalletMessageKindV1.CREDITED),
    SESSION_CONTROL(5, KagemushaWalletMessageKindV1.SESSION_CONTROL),
    POLICY_DATA(6, KagemushaWalletMessageKindV1.POLICY_DATA),
    LINEAGE(7, KagemushaWalletMessageKindV1.LINEAGE);

    /** Exact complete-frame cap of a wallet envelope of this kind, header and padding included. */
    val maximumWalletFrameBytes: Int get() = if (this == REQUEST) IrohaPeerWalletRequestV1.MAXIMUM_BYTES else walletMessageKind.maximumFrameBytes

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerPayloadKind? =
            entries.firstOrNull { it.code == code }

        /** IPM1 kind that carries a wallet envelope of [kind]. */
        @JvmStatic fun of(kind: KagemushaWalletMessageKindV1): IrohaPeerPayloadKind =
            entries.first { it.walletMessageKind == kind }
    }
}

enum class IrohaPeerContentEncodingV1(val code: Int) {
    NONE(0),
    ZLIB(1);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerContentEncodingV1? =
            entries.firstOrNull { it.code == code }
    }
}

/** Cross-rail V1 compression is canonical only when it saves 32 bytes and a 256-byte shard. */
enum class IrohaPeerWireCompressionPolicyV1 {
    DISABLED,
    PEER_OPTIMIZED,
}

/** Allocation limits shared byte-for-byte by all peer V1 transports. */
class IrohaPeerWireLimitsV1 @JvmOverloads constructor(
    val maximumCanonicalBytes: Int = IrohaPeerWalletRequestV1.MAXIMUM_BYTES,
    val maximumWalletEncodedBytes: Int = IrohaPeerWalletRequestV1.MAXIMUM_BYTES,
) {
    init {
        require(maximumCanonicalBytes in 1..IrohaPeerWalletRequestV1.MAXIMUM_BYTES)
        require(maximumWalletEncodedBytes in 1..IrohaPeerWalletRequestV1.MAXIMUM_BYTES)
    }

    companion object {
        @JvmField val PEER_V1 = IrohaPeerWireLimitsV1()
    }
}

/** Exact canonical profile bytes. This class never re-serializes them. */
class IrohaPeerCanonicalPayload(
    val profile: IrohaPeerPayloadProfile,
    val kind: IrohaPeerPayloadKind,
    val schemaVersion: Int,
    bytes: ByteArray,
) {
    private val canonicalBytes = bytes.boundedCanonicalCopy()
    val bytes: ByteArray get() = canonicalBytes.copyOf()
    val byteCount: Int get() = canonicalBytes.size

    init {
        require(schemaVersion in 1..0xffff) { "Peer payload schema version is invalid" }
        require(schemaVersion == profile.requiredSchemaVersion) {
            "Peer payload profile ${profile.name} requires schema " +
                "${profile.requiredSchemaVersion}, received $schemaVersion"
        }
        require(canonicalBytes.size <= kind.maximumWalletFrameBytes) {
            "${profile.name} ${kind.name} payload exceeds its frozen protocol bound"
        }
        validateTypedCanonicalPayload(profile, kind, canonicalBytes)
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerCanonicalPayload &&
        profile == other.profile && kind == other.kind && schemaVersion == other.schemaVersion &&
        canonicalBytes.contentEquals(other.canonicalBytes)

    override fun hashCode(): Int {
        var result = profile.hashCode()
        result = 31 * result + kind.hashCode()
        result = 31 * result + schemaVersion
        return 31 * result + canonicalBytes.contentHashCode()
    }

}

private fun ByteArray.boundedCanonicalCopy(): ByteArray {
    require(isNotEmpty()) { "Peer payload is empty" }
    require(size <= IrohaPeerWireMessageV1.MAXIMUM_CANONICAL_BYTES) {
        "Peer payload exceeds its bound"
    }
    return copyOf()
}

/**
 * A wallet-profile Request contains the required account companion and one unchanged canonical
 * `KagemushaWalletEnvelopeV1`; other kinds contain only that envelope within
 * its kind's bound whose message tag is this IPM1 kind. The check is structural
 * ([KagemushaWalletWireV1.inspectEnvelope]): the wallet still decodes, validates and verifies the
 * message, and decides its scheme, before acting on it.
 */
private fun validateTypedCanonicalPayload(
    profile: IrohaPeerPayloadProfile,
    kind: IrohaPeerPayloadKind,
    bytes: ByteArray,
) {
    when (profile) {
        IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1 -> {
            val envelope = try {
                KagemushaWalletWireV1.inspectEnvelope(if (kind == IrohaPeerPayloadKind.REQUEST)
                    IrohaPeerWalletRequestV1.decode(bytes).requestEnvelope() else bytes)
            } catch (failure: RuntimeException) {
                throw IllegalArgumentException(
                    "Invalid KAGEMUSHA wallet V1 envelope for ${kind.name.lowercase()}",
                    failure,
                )
            }
            require(envelope.kind == kind.walletMessageKind) {
                "KAGEMUSHA wallet V1 ${envelope.kind.label} envelope cannot travel as " +
                    kind.name.lowercase()
            }
        }
    }
}

/** Immutable and fully verified transport-neutral IPM1 message. */
class IrohaPeerWireMessageV1 private constructor(
    val canonicalPayload: IrohaPeerCanonicalPayload,
    val encoding: IrohaPeerContentEncodingV1,
    canonicalHash: ByteArray,
    wireHash: ByteArray,
    encodedBody: ByteArray,
) {
    private val canonicalDigest = canonicalHash.copyOf()
    private val messageDigest = wireHash.copyOf()
    private val body = encodedBody.copyOf()

    val canonicalHash: ByteArray get() = canonicalDigest.copyOf()
    val wireHash: ByteArray get() = messageDigest.copyOf()
    val encodedBody: ByteArray get() = body.copyOf()
    /** Complete encoded IPM1 byte count, available without copying its body. */
    val byteCount: Int get() = HEADER_LENGTH + body.size
    val streamId: ByteArray get() = messageDigest.copyOfRange(0, 16)

    @JvmOverloads
    constructor(
        canonicalPayload: IrohaPeerCanonicalPayload,
        compressionPolicy: IrohaPeerWireCompressionPolicyV1 = IrohaPeerWireCompressionPolicyV1.DISABLED,
        limits: IrohaPeerWireLimitsV1 = IrohaPeerWireLimitsV1.PEER_V1,
    ) : this(
        encodedParts(canonicalPayload, compressionPolicy, limits),
    )

    private constructor(parts: EncodedParts) : this(
        parts.payload,
        parts.encoding,
        parts.canonicalHash,
        parts.wireHash,
        parts.body,
    )

    fun encode(): ByteArray {
        val prefix = headerPrefix(
            encoding,
            canonicalPayload,
            body.size,
            canonicalDigest,
        )
        return ByteArray(HEADER_LENGTH + body.size).also { out ->
            prefix.copyInto(out, 0)
            messageDigest.copyInto(out, 52)
            body.copyInto(out, HEADER_LENGTH)
        }
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerWireMessageV1 &&
        canonicalPayload == other.canonicalPayload && encoding == other.encoding &&
        canonicalDigest.contentEquals(other.canonicalDigest) &&
        messageDigest.contentEquals(other.messageDigest) && body.contentEquals(other.body)

    override fun hashCode(): Int = 31 * canonicalPayload.hashCode() + messageDigest.contentHashCode()

    internal class Header(
        val encoding: IrohaPeerContentEncodingV1,
        val profile: IrohaPeerPayloadProfile,
        val kind: IrohaPeerPayloadKind,
        val schemaVersion: Int,
        val canonicalLength: Int,
        val encodedLength: Int,
        canonicalHash: ByteArray,
        wireHash: ByteArray,
        bytes: ByteArray,
    ) {
        private val canonicalDigest = canonicalHash.copyOf()
        private val messageDigest = wireHash.copyOf()
        private val headerBytes = bytes.copyOf()
        val canonicalHash: ByteArray get() = canonicalDigest.copyOf()
        val wireHash: ByteArray get() = messageDigest.copyOf()
        val streamId: ByteArray get() = messageDigest.copyOfRange(0, 16)
        fun bytes(): ByteArray = headerBytes.copyOf()

        override fun equals(other: Any?): Boolean = other is Header &&
            encoding == other.encoding && profile == other.profile && kind == other.kind &&
            schemaVersion == other.schemaVersion && canonicalLength == other.canonicalLength &&
            encodedLength == other.encodedLength &&
            canonicalDigest.contentEquals(other.canonicalDigest) &&
            messageDigest.contentEquals(other.messageDigest)

        override fun hashCode(): Int = 31 * profile.hashCode() + messageDigest.contentHashCode()
    }

    companion object {
        const val VERSION = 1
        const val HEADER_LENGTH = 84
        const val MAXIMUM_CANONICAL_BYTES = IrohaPeerWalletRequestV1.MAXIMUM_BYTES
        const val MAXIMUM_WALLET_ENCODED_BYTES = IrohaPeerWalletRequestV1.MAXIMUM_BYTES
        private val MAGIC = "IPM1".toByteArray(Charsets.US_ASCII)
        private val CANONICAL_DOMAIN = "IROHA-PEER-PAYLOAD-V1\u0000".toByteArray(Charsets.UTF_8)
        private val MESSAGE_DOMAIN = "IROHA-PEER-MESSAGE-V1\u0000".toByteArray(Charsets.UTF_8)

        @JvmStatic
        @JvmOverloads
        fun decode(
            data: ByteArray,
            expectedProfile: IrohaPeerPayloadProfile? = null,
            expectedKind: IrohaPeerPayloadKind? = null,
            limits: IrohaPeerWireLimitsV1 = IrohaPeerWireLimitsV1.PEER_V1,
        ): IrohaPeerWireMessageV1 {
            require(data.size >= HEADER_LENGTH && data.copyOfRange(0, 4).contentEquals(MAGIC)) {
                "Malformed IPM1 peer message"
            }
            require(data[4].toInt() and 0xff == VERSION) { "Unsupported peer message version" }
            val encoding = IrohaPeerContentEncodingV1.fromCode(data[5].toInt() and 0xff)
                ?: throw IllegalArgumentException("Unsupported peer content encoding")
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16(6))
                ?: throw IllegalArgumentException("Invalid peer payload profile")
            val kind = IrohaPeerPayloadKind.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Invalid peer payload kind")
            require(data[9].toInt() == 0) { "Invalid peer message flags" }
            val schemaVersion = data.readU16(10)
            require(schemaVersion != 0) { "Invalid peer schema version" }
            require(schemaVersion == profile.requiredSchemaVersion) {
                "Peer payload profile ${profile.name} requires schema " +
                    "${profile.requiredSchemaVersion}, received $schemaVersion"
            }
            val canonicalLength = checkedLength(data.readU32(12), minOf(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes))
            val encodedLength = checkedLength(
                data.readU32(16),
                minOf(limits.maximumWalletEncodedBytes, kind.maximumWalletFrameBytes),
            )
            require(data.size == HEADER_LENGTH + encodedLength) { "Peer message length mismatch" }
            require(encoding != IrohaPeerContentEncodingV1.ZLIB ||
                canonicalZlibLength(canonicalLength, encodedLength)
            ) { "Non-canonical zlib peer body" }
            require(expectedProfile == null || expectedProfile == profile) {
                "Unexpected peer payload profile"
            }
            require(expectedKind == null || expectedKind == kind) { "Unexpected peer payload kind" }

            val canonicalDigest = data.copyOfRange(20, 52)
            val messageDigest = data.copyOfRange(52, 84)
            val encodedBody = data.copyOfRange(84, data.size)
            try {
                val computedWire = Blake2b.digest256(MESSAGE_DOMAIN + data.copyOfRange(0, 52) + encodedBody)
                require(computedWire.contentEquals(messageDigest)) { "Peer message wire hash mismatch" }

                val canonicalBytes = when (encoding) {
                    IrohaPeerContentEncodingV1.NONE -> {
                        require(encodedLength == canonicalLength) { "Peer message length mismatch" }
                        encodedBody.copyOf()
                    }
                    IrohaPeerContentEncodingV1.ZLIB -> inflateBounded(encodedBody, canonicalLength)
                }
                val payload = try {
                    IrohaPeerCanonicalPayload(profile, kind, schemaVersion, canonicalBytes)
                } finally {
                    canonicalBytes.fill(0)
                }
                require(canonicalHash(payload).contentEquals(canonicalDigest)) {
                    "Peer canonical payload hash mismatch"
                }
                val message = IrohaPeerWireMessageV1(
                    payload,
                    encoding,
                    canonicalDigest,
                    messageDigest,
                    encodedBody,
                )
                return message
            } finally {
                encodedBody.fill(0)
            }
        }

        internal fun decodeHeader(
            data: ByteArray,
            limits: IrohaPeerWireLimitsV1 = IrohaPeerWireLimitsV1.PEER_V1,
        ): Header {
            require(data.size == HEADER_LENGTH && data.copyOfRange(0, 4).contentEquals(MAGIC)) {
                "Malformed IPM1 header"
            }
            require(data[4].toInt() and 0xff == VERSION) { "Malformed IPM1 header" }
            val encoding = IrohaPeerContentEncodingV1.fromCode(data[5].toInt() and 0xff)
                ?: throw IllegalArgumentException("Malformed IPM1 header")
            val profile = IrohaPeerPayloadProfile.fromCode(data.readU16(6))
                ?: throw IllegalArgumentException("Malformed IPM1 header")
            val kind = IrohaPeerPayloadKind.fromCode(data[8].toInt() and 0xff)
                ?: throw IllegalArgumentException("Malformed IPM1 header")
            require(data[9].toInt() == 0 && data.readU16(10) != 0) { "Malformed IPM1 header" }
            val schemaVersion = data.readU16(10)
            require(schemaVersion == profile.requiredSchemaVersion) {
                "Peer payload profile ${profile.name} requires schema " +
                    "${profile.requiredSchemaVersion}, received $schemaVersion"
            }
            val canonicalLength = checkedLength(data.readU32(12), minOf(limits.maximumCanonicalBytes, kind.maximumWalletFrameBytes))
            val encodedLength = checkedLength(
                data.readU32(16),
                minOf(limits.maximumWalletEncodedBytes, kind.maximumWalletFrameBytes),
            )
            require(encoding != IrohaPeerContentEncodingV1.NONE || canonicalLength == encodedLength) {
                "Malformed IPM1 header"
            }
            require(encoding != IrohaPeerContentEncodingV1.ZLIB ||
                canonicalZlibLength(canonicalLength, encodedLength)
            ) { "Malformed IPM1 header" }
            return Header(
                encoding,
                profile,
                kind,
                schemaVersion,
                canonicalLength,
                encodedLength,
                data.copyOfRange(20, 52),
                data.copyOfRange(52, 84),
                data,
            )
        }

        private fun canonicalHash(payload: IrohaPeerCanonicalPayload): ByteArray {
            val metadata = ByteArray(5)
            metadata.writeU16(0, payload.profile.code)
            metadata[2] = payload.kind.code.toByte()
            metadata.writeU16(3, payload.schemaVersion)
            val bytes = payload.bytes
            return try {
                Blake2b.digest256(CANONICAL_DOMAIN + metadata + bytes)
            } finally {
                bytes.fill(0)
            }
        }

        private fun encodedParts(
            payload: IrohaPeerCanonicalPayload,
            policy: IrohaPeerWireCompressionPolicyV1,
            limits: IrohaPeerWireLimitsV1,
        ): EncodedParts {
            require(payload.byteCount <= limits.maximumCanonicalBytes) {
                "Peer canonical payload exceeds its bound"
            }
            val maximumEncoded = limits.maximumWalletEncodedBytes
            val digest = canonicalHash(payload)
            val canonical = payload.bytes
            val compressed = if (policy == IrohaPeerWireCompressionPolicyV1.PEER_OPTIMIZED) {
                deflateZlib(canonical)
            } else {
                null
            }
            val useCompressed = compressed != null &&
                canonical.size - compressed.size >= 32 &&
                shardCount(compressed.size) < shardCount(canonical.size) &&
                compressed.size <= maximumEncoded
            val encoding = if (useCompressed) {
                IrohaPeerContentEncodingV1.ZLIB
            } else {
                IrohaPeerContentEncodingV1.NONE
            }
            val body = if (useCompressed) compressed else canonical.copyOf()
            if (!useCompressed) compressed?.fill(0)
            canonical.fill(0)
            require(body.size <= maximumEncoded) { "Peer encoded payload exceeds its profile bound" }
            val prefix = headerPrefix(
                encoding,
                payload,
                body.size,
                digest,
            )
            return EncodedParts(
                payload,
                encoding,
                digest,
                Blake2b.digest256(MESSAGE_DOMAIN + prefix + body),
                body,
            )
        }

        private fun headerPrefix(
            encoding: IrohaPeerContentEncodingV1,
            payload: IrohaPeerCanonicalPayload,
            encodedLength: Int,
            canonicalHash: ByteArray,
        ): ByteArray = ByteArray(52).also { out ->
            MAGIC.copyInto(out, 0)
            out[4] = VERSION.toByte()
            out[5] = encoding.code.toByte()
            out.writeU16(6, payload.profile.code)
            out[8] = payload.kind.code.toByte()
            out[9] = 0
            out.writeU16(10, payload.schemaVersion)
            out.writeU32(12, payload.byteCount.toLong())
            out.writeU32(16, encodedLength.toLong())
            canonicalHash.copyInto(out, 20)
        }

        private fun checkedLength(value: Long, maximum: Int): Int {
            require(value in 1..maximum.toLong()) { "Peer payload exceeds its bound" }
            return value.toInt()
        }

        private fun canonicalZlibLength(canonicalLength: Int, encodedLength: Int): Boolean =
            canonicalLength > 0 && encodedLength > 0 &&
                canonicalLength - encodedLength >= 32 &&
                (encodedLength + 255) / 256 < (canonicalLength + 255) / 256

        private fun shardCount(byteCount: Int): Int = (byteCount + 255) / 256

        private fun deflateZlib(canonical: ByteArray): ByteArray {
            val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, false)
            val output = ByteArrayOutputStream(canonical.size)
            val buffer = ByteArray(16 * 1024)
            try {
                deflater.setInput(canonical)
                deflater.finish()
                while (!deflater.finished()) {
                    val count = deflater.deflate(buffer)
                    require(count > 0) { "Unable to encode zlib peer body" }
                    output.write(buffer, 0, count)
                }
                return output.toByteArray()
            } finally {
                buffer.fill(0)
                deflater.end()
            }
        }

        private fun inflateBounded(encoded: ByteArray, expectedLength: Int): ByteArray {
            require(encoded.size >= 6 && encoded[0] == 0x78.toByte() && encoded[1] == 0x9c.toByte()) {
                "Invalid zlib peer body"
            }
            val inflater = Inflater(false)
            val output = ByteArrayOutputStream(expectedLength)
            val buffer = ByteArray(minOf(16 * 1024, maxOf(1, expectedLength)))
            try {
                inflater.setInput(encoded)
                while (!inflater.finished()) {
                    val count = try {
                        inflater.inflate(buffer)
                    } catch (failure: DataFormatException) {
                        throw IllegalArgumentException("Invalid zlib peer body", failure)
                    }
                    if (count == 0) {
                        require(!inflater.needsDictionary() && !inflater.needsInput()) {
                            "Invalid zlib peer body"
                        }
                    } else {
                        require(output.size() <= expectedLength - count) { "Invalid zlib peer body" }
                        output.write(buffer, 0, count)
                    }
                }
                require(inflater.remaining == 0 && output.size() == expectedLength) {
                    "Invalid zlib peer body"
                }
                return output.toByteArray()
            } finally {
                buffer.fill(0)
                inflater.end()
            }
        }
    }

    private class EncodedParts(
        val payload: IrohaPeerCanonicalPayload,
        val encoding: IrohaPeerContentEncodingV1,
        val canonicalHash: ByteArray,
        val wireHash: ByteArray,
        val body: ByteArray,
    )
}

/**
 * Bounded handoff adapter for KAGEMUSHA wallet V1 envelopes: the IPM1 kind is the envelope's own
 * message tag, so a caller never chooses it separately.
 */
object IrohaPeerKagemushaWalletAdapterV1 {
    /** Wrap one canonical wallet envelope frame in IPM1 under the kind its message tag names. */
    @JvmStatic
    @JvmOverloads
    fun wrap(
        envelope: ByteArray,
        compressionPolicy: IrohaPeerWireCompressionPolicyV1 =
            IrohaPeerWireCompressionPolicyV1.DISABLED,
        limits: IrohaPeerWireLimitsV1 = IrohaPeerWireLimitsV1.PEER_V1,
        destinationAccountOriginal: ByteArray? = null,
    ): IrohaPeerWireMessageV1 {
        val bytes = envelope.copyOf()
        return try {
            val kind = IrohaPeerPayloadKind.of(KagemushaWalletWireV1.inspectEnvelope(bytes).kind)
            val payload = if (kind == IrohaPeerPayloadKind.REQUEST) {
                IrohaPeerWalletRequestV1(bytes, requireNotNull(destinationAccountOriginal) {
                    "Request account companion is mandatory"
                }).encode()
            } else {
                require(destinationAccountOriginal == null) { "Account companion belongs only to Request" }
                bytes
            }
            IrohaPeerWireMessageV1(IrohaPeerCanonicalPayload(
                IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1,
                kind,
                IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1.requiredSchemaVersion,
                payload,
            ), compressionPolicy, limits)
        } finally {
            bytes.fill(0)
        }
    }

    /** Canonical wallet envelope frame carried by a verified wallet-profile IPM1 message. */
    @JvmStatic
    fun decode(message: IrohaPeerWireMessageV1): ByteArray {
        val payload = message.canonicalPayload
        require(payload.profile == IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1) {
            "Unexpected peer payload profile"
        }
        return if (payload.kind == IrohaPeerPayloadKind.REQUEST)
            IrohaPeerWalletRequestV1.decode(payload.bytes).requestEnvelope() else payload.bytes
    }

    /** Exact companion DATA; submit it with the extracted Request to Native review. */
    @JvmStatic fun destinationAccountOriginal(message: IrohaPeerWireMessageV1): ByteArray {
        require(message.canonicalPayload.profile == IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1 &&
            message.canonicalPayload.kind == IrohaPeerPayloadKind.REQUEST)
        return IrohaPeerWalletRequestV1.decode(message.canonicalPayload.bytes).destinationAccountOriginal()
    }
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
