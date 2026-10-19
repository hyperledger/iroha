// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.Varint

/**
 * Transport-neutral Iroha peer NFC V1 constants (`specs/kagemusha_wallet_wire_v1.md` §6, NFC).
 *
 * The receiver's phone is the card (host card emulation) and the payer's phone is the reader.
 * The card hosts the receiver's open Request from the moment the receiver confirms the amount
 * ([IrohaPeerNfcCardEndpointV1], [IrohaPeerNfcReceiverSessionV1]). One continuous hold reads it
 * ([IrohaPeerNfcReaderExchangeV1.readRequest]), carries the payer's approved Payment with its payer
 * companion and returns the receiver's durable acknowledgement, the wallet's Credited envelope
 * ([IrohaPeerNfcReaderExchangeV1.run]). Every value matches the Swift `IrohaPeerNfcV1` byte for
 * byte. TODO(G4): SessionControl over NFC.
 */
object IrohaPeerNfcV1 {
    /** Proprietary ISO/IEC 7816-4 class of every command except SELECT. */
    const val COMMAND_CLASS = 0x80
    const val WIRE_VERSION = 1
    const val SESSION_ID_BYTES = 16
    const val HASH_BYTES = 32
    const val MAXIMUM_CHUNK_BYTES = 4_096

    /** The 84-byte IPM1 header plus the maximum Request carrier (14,112 bytes). */
    const val MAXIMUM_MESSAGE_BYTES =
        IrohaPeerWireMessageV1.HEADER_LENGTH + IrohaPeerWireMessageV1.MAXIMUM_WALLET_ENCODED_BYTES

    /** The 84-byte IPM1 header plus the maximum Payment carrier with its payer companion (12,064 bytes). */
    const val MAXIMUM_PAYMENT_BYTES =
        IrohaPeerWireMessageV1.HEADER_LENGTH + IrohaPeerWalletPaymentV1.MAXIMUM_BYTES

    /** Length of the `IOI1` record returned by GET_INTAKE. */
    const val INTAKE_BYTES = 68

    /** Length of the `INF1` record returned by GET_INFO. */
    const val INFO_BYTES = 98

    /** Length of the `NST1` record returned by GET_STATUS. */
    const val STATUS_BYTES = 174

    /** Length of the receiver's local `IPA1` durable payment admission record. */
    const val PAYMENT_ADMISSION_BYTES = 244

    internal val INTAKE_MAGIC = "IOI1".toByteArray(Charsets.US_ASCII)
    internal val INFO_MAGIC = "INF1".toByteArray(Charsets.US_ASCII)
    internal val STATUS_MAGIC = "NST1".toByteArray(Charsets.US_ASCII)
    internal val PAYMENT_ADMISSION_MAGIC = "IPA1".toByteArray(Charsets.US_ASCII)
    internal val DURABLE_ACKNOWLEDGEMENT_MAGIC = "IDA1".toByteArray(Charsets.US_ASCII)
    internal val SENDER_CHECKPOINT_MAGIC = "ISC1".toByteArray(Charsets.US_ASCII)
}

/**
 * ISO/IEC 7816-4 application identifier (5–16 bytes) under which an application registers its
 * card: the Android `HostApduService` aid-filter, or the iOS HCE and reader entitlements. Both
 * phones of an exchange use the same identifier. An application without its own registration uses
 * [PROTOCOL]. The identifier only routes the card; it grants no authority.
 */
class IrohaPeerNfcApplicationIdentifierV1(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        if (value.size !in MINIMUM_BYTES..MAXIMUM_BYTES) {
            throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
        }
    }

    /** Identifier length in bytes. */
    val byteCount: Int get() = value.size

    /** Identifier bytes; a defensive copy. */
    fun bytes(): ByteArray = value.copyOf()

    /** Uppercase hexadecimal form, as written in an Android aid-filter. */
    fun hex(): String {
        val output = StringBuilder(value.size * 2)
        for (byte in value) {
            val unsigned = byte.toInt() and 0xff
            output.append(HEX_DIGITS[unsigned ushr 4]).append(HEX_DIGITS[unsigned and 0x0f])
        }
        return output.toString()
    }

    /** Whether [candidate] is exactly this identifier. */
    fun matches(candidate: ByteArray): Boolean = candidate.contentEquals(value)

    override fun equals(other: Any?): Boolean =
        other is IrohaPeerNfcApplicationIdentifierV1 && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = hex()

    companion object {
        const val MINIMUM_BYTES = 5
        const val MAXIMUM_BYTES = 16
        const val PROTOCOL_HEX = "F0504B45504B524E464301"
        private const val HEX_DIGITS = "0123456789ABCDEF"

        /** The protocol identifier `F0504B45504B524E464301` for applications without their own. */
        @JvmField val PROTOCOL: IrohaPeerNfcApplicationIdentifierV1 = fromHex(PROTOCOL_HEX)

        /** Parse an even-length hexadecimal identifier of 5–16 bytes (either letter case). */
        @JvmStatic
        fun fromHex(hex: String): IrohaPeerNfcApplicationIdentifierV1 {
            if (hex.length % 2 != 0 || hex.length !in (2 * MINIMUM_BYTES)..(2 * MAXIMUM_BYTES)) {
                throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
            }
            val bytes = ByteArray(hex.length / 2)
            for (index in bytes.indices) {
                val high = Character.digit(hex[2 * index], 16)
                val low = Character.digit(hex[2 * index + 1], 16)
                if (high < 0 || low < 0) {
                    throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
                }
                bytes[index] = ((high shl 4) or low).toByte()
            }
            return IrohaPeerNfcApplicationIdentifierV1(bytes)
        }
    }
}

/** The proprietary instructions of Iroha peer NFC V1; SELECT is the only other command. */
enum class IrohaPeerNfcInstructionV1(val code: Int) {
    GET_INFO(0x10),
    READ_REQUEST(0x11),
    BEGIN_PAYMENT(0x20),
    WRITE(0x21),
    COMMIT(0x22),
    READ_ACKNOWLEDGEMENT(0x23),
    CONFIRM_ACKNOWLEDGEMENT(0x24),
    GET_STATUS(0x25),
    GET_INTAKE(0x30);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcInstructionV1? =
            entries.firstOrNull { it.code == code }
    }
}

/** Receiver phases exposed by GET_INFO and GET_STATUS. */
enum class IrohaPeerNfcPhaseV1(val code: Int) {
    REQUEST_READY(1),
    PAYMENT_RECEIVING(2),
    ACKNOWLEDGEMENT_READY(3),
    COMPLETE(4);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcPhaseV1? =
            entries.firstOrNull { it.code == code }
    }
}

/**
 * Card state exposed by GET_INTAKE (`IOI1`). The card hosts its open Request from the start, so
 * REQUEST_READY (4) is the only state; codes 1, 2, 3 and 5 of the retired Offer intake are unused.
 */
enum class IrohaPeerNfcIntakeStateV1(val code: Int) {
    REQUEST_READY(4);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcIntakeStateV1? =
            entries.firstOrNull { it.code == code }
    }
}

/** Capabilities and durability boundaries advertised in `INF1` and `NST1`. */
class IrohaPeerNfcFlagsV1(@JvmField val rawValue: Int) {
    init {
        require(rawValue in 0..0xff) { "NFC flags are one byte" }
    }

    fun contains(flags: IrohaPeerNfcFlagsV1): Boolean = rawValue and flags.rawValue == flags.rawValue

    /** Whether every set bit is a V1 flag. */
    val isKnown: Boolean get() = rawValue and KNOWN.rawValue.inv() == 0

    fun union(flags: IrohaPeerNfcFlagsV1): IrohaPeerNfcFlagsV1 = IrohaPeerNfcFlagsV1(rawValue or flags.rawValue)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcFlagsV1 && rawValue == other.rawValue

    override fun hashCode(): Int = rawValue

    override fun toString(): String = "IrohaPeerNfcFlagsV1(0x" + Integer.toHexString(rawValue) + ")"

    companion object {
        /**
         * Replayed or partially overlapping WRITE commands are accepted only when every
         * already-received byte is identical. Always set.
         */
        @JvmField val IDEMPOTENT_WRITES = IrohaPeerNfcFlagsV1(0x01)

        /** The acknowledgement was persisted before COMMIT returned success (phases 3 and 4). */
        @JvmField val DURABLE_ACKNOWLEDGEMENT = IrohaPeerNfcFlagsV1(0x02)

        @JvmField val KNOWN = IrohaPeerNfcFlagsV1(0x03)
    }
}

/** Bounded message and APDU chunk sizes of one NFC endpoint. */
class IrohaPeerNfcLimitsV1 @JvmOverloads constructor(
    @JvmField val maximumMessageBytes: Int = IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES,
    @JvmField val maximumReadChunkBytes: Int = IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES,
    @JvmField val maximumWriteChunkBytes: Int = IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES,
) {
    init {
        require(maximumMessageBytes in IrohaPeerWireMessageV1.HEADER_LENGTH..IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES) {
            "NFC message limit is outside its V1 bound"
        }
        require(maximumReadChunkBytes in 1..IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) { "invalid NFC read chunk limit" }
        require(maximumWriteChunkBytes in 1..IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) { "invalid NFC write chunk limit" }
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcLimitsV1 &&
        maximumMessageBytes == other.maximumMessageBytes &&
        maximumReadChunkBytes == other.maximumReadChunkBytes &&
        maximumWriteChunkBytes == other.maximumWriteChunkBytes

    override fun hashCode(): Int =
        (maximumMessageBytes * 31 + maximumReadChunkBytes) * 31 + maximumWriteChunkBytes

    override fun toString(): String = "IrohaPeerNfcLimitsV1(message=$maximumMessageBytes, " +
        "read=$maximumReadChunkBytes, write=$maximumWriteChunkBytes)"

    companion object {
        @JvmField val DEFAULT = IrohaPeerNfcLimitsV1()
    }
}

/** One immutable application profile for every IPM1 message of an NFC exchange. */
class IrohaPeerNfcProfilePolicyV1(@JvmField val profile: IrohaPeerPayloadProfile) {
    fun accepts(candidate: IrohaPeerPayloadProfile): Boolean = profile == candidate

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcProfilePolicyV1 && profile == other.profile

    override fun hashCode(): Int = profile.hashCode()

    override fun toString(): String = "IrohaPeerNfcProfilePolicyV1(${profile.name})"

    companion object {
        /** Spelling equivalent to the constructor. */
        @JvmStatic fun sameProfile(profile: IrohaPeerPayloadProfile): IrohaPeerNfcProfilePolicyV1 =
            IrohaPeerNfcProfilePolicyV1(profile)
    }
}

/** Typed failure of the Iroha peer NFC V1 carrier, the Swift `IrohaPeerNfcErrorV1` cases. */
enum class IrohaPeerNfcErrorV1 {
    INVALID_APPLICATION_IDENTIFIER,
    INVALID_COMMAND_CLASS,
    UNSUPPORTED_INSTRUCTION,
    INVALID_APDU,
    INVALID_LENGTH,
    MESSAGE_TOO_LARGE,
    INVALID_OFFSET,
    INVALID_SESSION,
    INVALID_HASH,
    INVALID_PROFILE,
    INVALID_KIND,
    INVALID_FLAGS,
    INVALID_IPM1,
    CONTINUITY_MISMATCH,
    CONFLICTING_REPLAY,
    STATE_MISMATCH,
    DURABLE_ADMISSION_REQUIRED,
    DURABLE_COMMIT_REQUIRED,
    ACKNOWLEDGEMENT_NOT_DURABLE,

    /** The card answered `6985` to [IrohaPeerNfcExceptionV1.operation]. */
    PEER_REJECTED,

    /** The card answered `6581` (it could not persist) to [IrohaPeerNfcExceptionV1.operation]. */
    PEER_PERSISTENCE_FAILURE,
}

/**
 * Stable command names used by typed peer failures without exposing APDU bytes or collapsing
 * persistence failures into generic state errors.
 */
enum class IrohaPeerNfcOperationV1 {
    SELECT_APPLICATION,
    GET_INTAKE,
    GET_INFO,
    READ_REQUEST,
    BEGIN_PAYMENT,
    WRITE,
    COMMIT,
    READ_ACKNOWLEDGEMENT,
    CONFIRM_ACKNOWLEDGEMENT,
    GET_STATUS,
}

/**
 * Typed NFC carrier failure. [detail] is the class byte of [IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS],
 * the instruction byte of [IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION] or the actual length of
 * [IrohaPeerNfcErrorV1.MESSAGE_TOO_LARGE] (whose bound is [maximum]); it is `0` otherwise. [operation]
 * names the command a peer rejected ([IrohaPeerNfcErrorV1.PEER_REJECTED],
 * [IrohaPeerNfcErrorV1.PEER_PERSISTENCE_FAILURE]).
 */
class IrohaPeerNfcExceptionV1 @JvmOverloads constructor(
    @JvmField val error: IrohaPeerNfcErrorV1,
    @JvmField val operation: IrohaPeerNfcOperationV1? = null,
    @JvmField val detail: Int = 0,
    @JvmField val maximum: Int = 0,
    cause: Throwable? = null,
) : IllegalArgumentException(describe(error, operation, detail, maximum), cause) {
    init {
        val peerFailure = error == IrohaPeerNfcErrorV1.PEER_REJECTED ||
            error == IrohaPeerNfcErrorV1.PEER_PERSISTENCE_FAILURE
        require((operation != null) == peerFailure) { "NFC peer failures name exactly their operation" }
    }

    private companion object {
        fun describe(
            error: IrohaPeerNfcErrorV1,
            operation: IrohaPeerNfcOperationV1?,
            detail: Int,
            maximum: Int,
        ): String = when (error) {
            IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER -> "The Iroha peer NFC application identifier is invalid."
            IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS -> "Unsupported NFC command class ${hexByte(detail)}."
            IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION -> "Unsupported NFC instruction ${hexByte(detail)}."
            IrohaPeerNfcErrorV1.INVALID_APDU -> "The NFC command APDU is malformed."
            IrohaPeerNfcErrorV1.INVALID_LENGTH -> "The NFC record length is invalid."
            IrohaPeerNfcErrorV1.MESSAGE_TOO_LARGE -> "The NFC message is $detail bytes; the limit is $maximum."
            IrohaPeerNfcErrorV1.INVALID_OFFSET -> "The NFC chunk offset is invalid."
            IrohaPeerNfcErrorV1.INVALID_SESSION -> "The NFC session identifier is invalid."
            IrohaPeerNfcErrorV1.INVALID_HASH -> "The NFC message hash is invalid."
            IrohaPeerNfcErrorV1.INVALID_PROFILE -> "The NFC payload profile is invalid."
            IrohaPeerNfcErrorV1.INVALID_KIND -> "The NFC IPM1 message kind is invalid."
            IrohaPeerNfcErrorV1.INVALID_FLAGS -> "The NFC status flags are invalid."
            IrohaPeerNfcErrorV1.INVALID_IPM1 -> "The NFC payload is not a valid IPM1 message."
            IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH -> "The NFC transfer continuity does not match."
            IrohaPeerNfcErrorV1.CONFLICTING_REPLAY -> "The NFC retry conflicts with already-received bytes."
            IrohaPeerNfcErrorV1.STATE_MISMATCH -> "The NFC command is not valid in the current phase."
            IrohaPeerNfcErrorV1.DURABLE_ADMISSION_REQUIRED ->
                "BEGIN_PAYMENT requires application-provided durable admission."
            IrohaPeerNfcErrorV1.DURABLE_COMMIT_REQUIRED ->
                "COMMIT requires an application-provided durable acknowledgement."
            IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE ->
                "The acknowledgement must be durable before it can be confirmed."
            IrohaPeerNfcErrorV1.PEER_REJECTED -> "The nearby NFC peer rejected ${operation?.name}."
            IrohaPeerNfcErrorV1.PEER_PERSISTENCE_FAILURE ->
                "The nearby NFC peer could not durably persist ${operation?.name}."
        }

        fun hexByte(value: Int): String {
            val text = Integer.toHexString(value and 0xff).uppercase()
            return if (text.length == 1) "0$text" else text
        }
    }
}

/**
 * Marker for a transport error that makes delivery of a command's response unknowable. Other
 * errors remain deterministic failures.
 */
interface IrohaPeerNfcAmbiguousResponseErrorV1

/** ISO/IEC 7816 status words of the NFC V1 card. */
enum class IrohaPeerNfcStatusWordV1(val code: Int) {
    SUCCESS(0x9000),
    STORAGE_FAILURE(0x6581),
    WRONG_LENGTH(0x6700),
    SECURITY_STATUS_NOT_SATISFIED(0x6982),
    CONDITIONS_NOT_SATISFIED(0x6985),
    WRONG_DATA(0x6a80),
    NOT_FOUND(0x6a82),
    INSTRUCTION_NOT_SUPPORTED(0x6d00),
    CLASS_NOT_SUPPORTED(0x6e00);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcStatusWordV1? =
            entries.firstOrNull { it.code == code }

        /** The card's answer to a command that failed with [error] (Swift `failureResponse(for:)`). */
        @JvmStatic fun forError(error: IrohaPeerNfcErrorV1): IrohaPeerNfcStatusWordV1 = when (error) {
            IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS -> CLASS_NOT_SUPPORTED
            IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION -> INSTRUCTION_NOT_SUPPORTED
            IrohaPeerNfcErrorV1.INVALID_LENGTH,
            IrohaPeerNfcErrorV1.MESSAGE_TOO_LARGE,
            -> WRONG_LENGTH
            IrohaPeerNfcErrorV1.INVALID_SESSION,
            IrohaPeerNfcErrorV1.INVALID_HASH,
            IrohaPeerNfcErrorV1.INVALID_PROFILE,
            IrohaPeerNfcErrorV1.INVALID_KIND,
            IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH,
            IrohaPeerNfcErrorV1.INVALID_IPM1,
            -> SECURITY_STATUS_NOT_SATISFIED
            IrohaPeerNfcErrorV1.STATE_MISMATCH,
            IrohaPeerNfcErrorV1.DURABLE_ADMISSION_REQUIRED,
            IrohaPeerNfcErrorV1.DURABLE_COMMIT_REQUIRED,
            IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE,
            IrohaPeerNfcErrorV1.CONFLICTING_REPLAY,
            IrohaPeerNfcErrorV1.PEER_REJECTED,
            IrohaPeerNfcErrorV1.PEER_PERSISTENCE_FAILURE,
            -> CONDITIONS_NOT_SATISFIED
            IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER -> NOT_FOUND
            IrohaPeerNfcErrorV1.INVALID_APDU,
            IrohaPeerNfcErrorV1.INVALID_OFFSET,
            IrohaPeerNfcErrorV1.INVALID_FLAGS,
            -> WRONG_DATA
        }
    }
}

/** APDU response data and its ISO/IEC 7816 status word. */
class IrohaPeerNfcAPDUResponseV1 @JvmOverloads constructor(
    data: ByteArray = ByteArray(0),
    @JvmField val statusWord: IrohaPeerNfcStatusWordV1,
) {
    private val body: ByteArray = data.copyOf()

    /** Response data; a defensive copy. */
    fun data(): ByteArray = body.copyOf()

    val dataLength: Int get() = body.size

    /** Card-emulation response bytes (`data || SW1 || SW2`). */
    fun encode(): ByteArray = ByteArray(body.size + 2).also { output ->
        body.copyInto(output)
        output[body.size] = (statusWord.code ushr 8).toByte()
        output[body.size + 1] = statusWord.code.toByte()
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcAPDUResponseV1 &&
        statusWord == other.statusWord && body.contentEquals(other.body)

    override fun hashCode(): Int = 31 * statusWord.hashCode() + body.contentHashCode()

    override fun toString(): String = "IrohaPeerNfcAPDUResponseV1(${statusWord.name}, ${body.size} bytes)"

    companion object {
        /**
         * Strictly decode a reader-side response: at most [IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES] of data
         * and one of the V1 status words.
         */
        @JvmStatic
        fun decode(raw: ByteArray): IrohaPeerNfcAPDUResponseV1 {
            if (raw.size < 2 || raw.size > IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES + 2) {
                throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val code = ((raw[raw.size - 2].toInt() and 0xff) shl 8) or (raw[raw.size - 1].toInt() and 0xff)
            val statusWord = IrohaPeerNfcStatusWordV1.fromCode(code)
                ?: throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_APDU)
            return IrohaPeerNfcAPDUResponseV1(raw.copyOfRange(0, raw.size - 2), statusWord)
        }

        /** A data-free response with [statusWord]. */
        @JvmStatic fun of(statusWord: IrohaPeerNfcStatusWordV1): IrohaPeerNfcAPDUResponseV1 =
            IrohaPeerNfcAPDUResponseV1(ByteArray(0), statusWord)

        /** The card's answer to a command that failed with [error]. */
        @JvmStatic fun failure(error: IrohaPeerNfcErrorV1): IrohaPeerNfcAPDUResponseV1 =
            of(IrohaPeerNfcStatusWordV1.forError(error))
    }
}

/** Stable Request identity shared by the NFC reader and card. */
class IrohaPeerNfcRequestIdentityV1(
    @JvmField val profile: IrohaPeerPayloadProfile,
    sessionId: ByteArray,
    requestCanonicalHash: ByteArray,
    requestWireHash: ByteArray,
) {
    private val session: ByteArray = nfcRequireSession(sessionId)
    private val canonical: ByteArray = nfcRequireHash(requestCanonicalHash)
    private val wire: ByteArray = nfcRequireHash(requestWireHash)

    /** 16-byte nonzero session identifier `s` chosen by the card; a defensive copy. */
    val sessionId: ByteArray get() = session.copyOf()

    /** Request canonical hash `h_r`; a defensive copy. */
    val requestCanonicalHash: ByteArray get() = canonical.copyOf()

    /** Request wire hash `w_r`; a defensive copy. */
    val requestWireHash: ByteArray get() = wire.copyOf()

    internal fun sessionEquals(candidate: ByteArray): Boolean = session.contentEquals(candidate)

    internal fun canonicalEquals(candidate: ByteArray): Boolean = canonical.contentEquals(candidate)

    internal fun writeTo(output: NfcRecordWriter, includeWireHash: Boolean = true) {
        output.bytes(session)
        output.bytes(canonical)
        if (includeWireHash) output.bytes(wire)
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcRequestIdentityV1 &&
        profile == other.profile && session.contentEquals(other.session) &&
        canonical.contentEquals(other.canonical) && wire.contentEquals(other.wire)

    override fun hashCode(): Int = (profile.hashCode() * 31 + session.contentHashCode()) * 31 +
        canonical.contentHashCode()

    override fun toString(): String = "IrohaPeerNfcRequestIdentityV1(${profile.name})"
}

/**
 * Fixed 68-byte `IOI1` response to GET_INTAKE: `"IOI1" ‖ 1 ‖ state ‖ BE16 profile ‖ s ‖ 40 zero
 * bytes ‖ BE16 max_write_chunk ‖ BE16 0`.
 *
 * The card hosts its open Request from the start, so [state] is always
 * [IrohaPeerNfcIntakeStateV1.REQUEST_READY]. The 40 bytes where the retired Offer intake reported
 * `BE32 offer_length ‖ BE32 received_offer_bytes ‖ w_o` are zero, and so is the retired reason.
 */
class IrohaPeerNfcIntakeRecordV1(
    @JvmField val profile: IrohaPeerPayloadProfile,
    sessionId: ByteArray,
    @JvmField val maximumWriteChunkBytes: Int,
) {
    private val session: ByteArray = nfcRequireSession(sessionId)

    init {
        nfcRequireChunkLimit(maximumWriteChunkBytes)
    }

    /** Always [IrohaPeerNfcIntakeStateV1.REQUEST_READY]. */
    @JvmField val state: IrohaPeerNfcIntakeStateV1 = IrohaPeerNfcIntakeStateV1.REQUEST_READY

    /** Session identifier `s` of the hosted Request; a defensive copy. */
    val sessionId: ByteArray get() = session.copyOf()

    internal fun sessionEquals(candidate: ByteArray): Boolean = session.contentEquals(candidate)

    fun encode(): ByteArray = NfcRecordWriter(IrohaPeerNfcV1.INTAKE_BYTES).apply {
        bytes(IrohaPeerNfcV1.INTAKE_MAGIC)
        u8(IrohaPeerNfcV1.WIRE_VERSION)
        u8(state.code)
        u16(profile.code)
        bytes(session)
        bytes(ByteArray(RETIRED_OFFER_BYTES))
        u16(maximumWriteChunkBytes)
        u16(0)
    }.finish(IrohaPeerNfcV1.INTAKE_BYTES)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcIntakeRecordV1 &&
        profile == other.profile && session.contentEquals(other.session) &&
        maximumWriteChunkBytes == other.maximumWriteChunkBytes

    override fun hashCode(): Int = (profile.hashCode() * 31 + session.contentHashCode()) * 31 + maximumWriteChunkBytes

    override fun toString(): String = "IrohaPeerNfcIntakeRecordV1(${state.name}, write=$maximumWriteChunkBytes)"

    companion object {
        /** The retired `BE32 offer_length ‖ BE32 received_offer_bytes ‖ w_o`, always zero. */
        private const val RETIRED_OFFER_BYTES = 40

        /**
         * Strictly decode one `IOI1` record: another length is [IrohaPeerNfcErrorV1.INVALID_LENGTH], another
         * magic, version, state or profile [IrohaPeerNfcErrorV1.INVALID_APDU], and a nonzero retired
         * Offer field or reason [IrohaPeerNfcErrorV1.INVALID_LENGTH].
         */
        @JvmStatic
        fun decode(data: ByteArray): IrohaPeerNfcIntakeRecordV1 {
            if (data.size != IrohaPeerNfcV1.INTAKE_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            if (!nfcHasMagic(data, IrohaPeerNfcV1.INTAKE_MAGIC) || data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            }
            IrohaPeerNfcIntakeStateV1.fromCode(data.nfcU8(5)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(6))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            if (!nfcIsZero(data.copyOfRange(24, 24 + RETIRED_OFFER_BYTES)) || data.nfcU16(66) != 0) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            return IrohaPeerNfcIntakeRecordV1(profile, data.copyOfRange(8, 24), data.nfcU16(64))
        }
    }
}

/** Fixed 98-byte `INF1` response to GET_INFO. */
class IrohaPeerNfcInfoV1(
    @JvmField val phase: IrohaPeerNfcPhaseV1,
    @JvmField val flags: IrohaPeerNfcFlagsV1,
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val requestLength: Int,
    @JvmField val maximumReadChunkBytes: Int,
    @JvmField val maximumWriteChunkBytes: Int,
) {
    init {
        if (!flags.isKnown) nfcFail(IrohaPeerNfcErrorV1.INVALID_FLAGS)
        if (requestLength <= IrohaPeerWireMessageV1.HEADER_LENGTH || requestLength > IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
        nfcRequireChunkLimit(maximumReadChunkBytes)
        nfcRequireChunkLimit(maximumWriteChunkBytes)
        val mustBeDurable = phase == IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY || phase == IrohaPeerNfcPhaseV1.COMPLETE
        if (!flags.contains(IrohaPeerNfcFlagsV1.IDEMPOTENT_WRITES) ||
            flags.contains(IrohaPeerNfcFlagsV1.DURABLE_ACKNOWLEDGEMENT) != mustBeDurable
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_FLAGS)
        }
    }

    fun encode(): ByteArray = NfcRecordWriter(IrohaPeerNfcV1.INFO_BYTES).apply {
        bytes(IrohaPeerNfcV1.INFO_MAGIC)
        u8(IrohaPeerNfcV1.WIRE_VERSION)
        u8(phase.code)
        u16(identity.profile.code)
        u8(flags.rawValue)
        u8(0)
        bytes(identity.sessionId)
        u32(requestLength.toLong())
        bytes(identity.requestCanonicalHash)
        bytes(identity.requestWireHash)
        u16(maximumReadChunkBytes)
        u16(maximumWriteChunkBytes)
    }.finish(IrohaPeerNfcV1.INFO_BYTES)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcInfoV1 && phase == other.phase &&
        flags == other.flags && identity == other.identity && requestLength == other.requestLength &&
        maximumReadChunkBytes == other.maximumReadChunkBytes && maximumWriteChunkBytes == other.maximumWriteChunkBytes

    override fun hashCode(): Int = (identity.hashCode() * 31 + phase.hashCode()) * 31 + requestLength

    override fun toString(): String = "IrohaPeerNfcInfoV1(${phase.name}, request=$requestLength)"

    companion object {
        @JvmStatic
        fun decode(data: ByteArray): IrohaPeerNfcInfoV1 {
            if (data.size != IrohaPeerNfcV1.INFO_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            if (!nfcHasMagic(data, IrohaPeerNfcV1.INFO_MAGIC) || data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            }
            val phase = IrohaPeerNfcPhaseV1.fromCode(data.nfcU8(5)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(6))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            if (data[9].toInt() != 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            val identity = IrohaPeerNfcRequestIdentityV1(
                profile,
                data.copyOfRange(10, 26),
                data.copyOfRange(30, 62),
                data.copyOfRange(62, 94),
            )
            return IrohaPeerNfcInfoV1(
                phase,
                IrohaPeerNfcFlagsV1(data.nfcU8(8)),
                identity,
                nfcLength(data.nfcU32(26)),
                data.nfcU16(94),
                data.nfcU16(96),
            )
        }
    }
}

/** Fixed 174-byte `NST1` response to GET_STATUS. */
class IrohaPeerNfcStatusV1(
    @JvmField val phase: IrohaPeerNfcPhaseV1,
    @JvmField val flags: IrohaPeerNfcFlagsV1,
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val paymentProfile: IrohaPeerPayloadProfile?,
    @JvmField val paymentLength: Int,
    @JvmField val receivedPaymentBytes: Int,
    paymentWireHash: ByteArray,
    @JvmField val acknowledgementProfile: IrohaPeerPayloadProfile?,
    @JvmField val acknowledgementLength: Int,
    acknowledgementWireHash: ByteArray,
    @JvmField val maximumReadChunkBytes: Int,
    @JvmField val maximumWriteChunkBytes: Int,
) {
    private val paymentHash: ByteArray = paymentWireHash.copyOf()
    private val acknowledgementHash: ByteArray = acknowledgementWireHash.copyOf()

    init {
        if (!flags.isKnown || !flags.contains(IrohaPeerNfcFlagsV1.IDEMPOTENT_WRITES)) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_FLAGS)
        }
        nfcRequireChunkLimit(maximumReadChunkBytes)
        nfcRequireChunkLimit(maximumWriteChunkBytes)
        val durable = flags.contains(IrohaPeerNfcFlagsV1.DURABLE_ACKNOWLEDGEMENT)
        val noAcknowledgement = acknowledgementProfile == null && acknowledgementLength == 0 &&
            nfcIsZeroHash(acknowledgementHash)
        val paymentBounds = paymentProfile != null &&
            paymentLength > IrohaPeerWireMessageV1.HEADER_LENGTH &&
            paymentLength <= IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES &&
            nfcIsNonzeroHash(paymentHash)
        val valid = when (phase) {
            IrohaPeerNfcPhaseV1.REQUEST_READY -> paymentLength == 0 && paymentProfile == null &&
                receivedPaymentBytes == 0 && nfcIsZeroHash(paymentHash) && noAcknowledgement && !durable
            IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING -> paymentBounds &&
                receivedPaymentBytes in 0..paymentLength && noAcknowledgement && !durable
            IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY,
            IrohaPeerNfcPhaseV1.COMPLETE,
            -> paymentBounds && receivedPaymentBytes == paymentLength &&
                acknowledgementProfile != null &&
                acknowledgementLength > IrohaPeerWireMessageV1.HEADER_LENGTH &&
                acknowledgementLength <= IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES &&
                nfcIsNonzeroHash(acknowledgementHash) && durable
        }
        if (!valid) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    }

    /** Payment wire hash `w_p` (zero before BEGIN_PAYMENT); a defensive copy. */
    val paymentWireHash: ByteArray get() = paymentHash.copyOf()

    /** Acknowledgement wire hash `w_a` (zero before COMMIT); a defensive copy. */
    val acknowledgementWireHash: ByteArray get() = acknowledgementHash.copyOf()

    internal fun paymentHashEquals(candidate: ByteArray): Boolean = paymentHash.contentEquals(candidate)

    internal fun acknowledgementHashEquals(candidate: ByteArray): Boolean = acknowledgementHash.contentEquals(candidate)

    fun encode(): ByteArray = NfcRecordWriter(IrohaPeerNfcV1.STATUS_BYTES).apply {
        bytes(IrohaPeerNfcV1.STATUS_MAGIC)
        u8(IrohaPeerNfcV1.WIRE_VERSION)
        u8(phase.code)
        u16(identity.profile.code)
        u8(flags.rawValue)
        u8(0)
        identity.writeTo(this)
        u16(paymentProfile?.code ?: 0)
        u32(paymentLength.toLong())
        u32(receivedPaymentBytes.toLong())
        bytes(paymentHash)
        u16(acknowledgementProfile?.code ?: 0)
        u32(acknowledgementLength.toLong())
        bytes(acknowledgementHash)
        u16(maximumReadChunkBytes)
        u16(maximumWriteChunkBytes)
    }.finish(IrohaPeerNfcV1.STATUS_BYTES)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcStatusV1 && phase == other.phase &&
        flags == other.flags && identity == other.identity && paymentProfile == other.paymentProfile &&
        paymentLength == other.paymentLength && receivedPaymentBytes == other.receivedPaymentBytes &&
        paymentHash.contentEquals(other.paymentHash) && acknowledgementProfile == other.acknowledgementProfile &&
        acknowledgementLength == other.acknowledgementLength &&
        acknowledgementHash.contentEquals(other.acknowledgementHash) &&
        maximumReadChunkBytes == other.maximumReadChunkBytes && maximumWriteChunkBytes == other.maximumWriteChunkBytes

    override fun hashCode(): Int = ((identity.hashCode() * 31 + phase.hashCode()) * 31 + receivedPaymentBytes) * 31 +
        paymentHash.contentHashCode()

    override fun toString(): String = "IrohaPeerNfcStatusV1(${phase.name}, payment=$receivedPaymentBytes/" +
        "$paymentLength, acknowledgement=$acknowledgementLength)"

    companion object {
        @JvmStatic
        fun decode(data: ByteArray): IrohaPeerNfcStatusV1 {
            if (data.size != IrohaPeerNfcV1.STATUS_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            if (!nfcHasMagic(data, IrohaPeerNfcV1.STATUS_MAGIC) || data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            }
            val phase = IrohaPeerNfcPhaseV1.fromCode(data.nfcU8(5)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(6))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            if (data[9].toInt() != 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            val identity = IrohaPeerNfcRequestIdentityV1(
                profile,
                data.copyOfRange(10, 26),
                data.copyOfRange(26, 58),
                data.copyOfRange(58, 90),
            )
            val rawPaymentProfile = data.nfcU16(90)
            val paymentProfile = if (rawPaymentProfile == 0) null else IrohaPeerPayloadProfile.fromCode(rawPaymentProfile)
            val rawAcknowledgementProfile = data.nfcU16(132)
            val acknowledgementProfile = if (rawAcknowledgementProfile == 0) {
                null
            } else {
                IrohaPeerPayloadProfile.fromCode(rawAcknowledgementProfile)
            }
            if ((rawPaymentProfile != 0 && paymentProfile == null) ||
                (rawAcknowledgementProfile != 0 && acknowledgementProfile == null)
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
            }
            return IrohaPeerNfcStatusV1(
                phase,
                IrohaPeerNfcFlagsV1(data.nfcU8(8)),
                identity,
                paymentProfile,
                nfcLength(data.nfcU32(92)),
                nfcLength(data.nfcU32(96)),
                data.copyOfRange(100, 132),
                acknowledgementProfile,
                nfcLength(data.nfcU32(134)),
                data.copyOfRange(138, 170),
                data.nfcU16(170),
                data.nfcU16(172),
            )
        }
    }
}

// Shared helpers of the NFC carrier files. Names carry an `nfc` prefix because file-private
// helpers of other carriers in this package use the plain names.

internal fun nfcFail(error: IrohaPeerNfcErrorV1): Nothing = throw IrohaPeerNfcExceptionV1(error)

internal fun nfcMessageTooLarge(actual: Int, maximum: Int): Nothing =
    throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.MESSAGE_TOO_LARGE, detail = actual, maximum = maximum)

/** A defensive copy of a 16-byte nonzero session identifier. */
internal fun nfcRequireSession(value: ByteArray): ByteArray {
    if (value.size != IrohaPeerNfcV1.SESSION_ID_BYTES || nfcIsZero(value)) nfcFail(IrohaPeerNfcErrorV1.INVALID_SESSION)
    return value.copyOf()
}

/** A defensive copy of a 32-byte nonzero hash. */
internal fun nfcRequireHash(value: ByteArray): ByteArray {
    if (value.size != IrohaPeerNfcV1.HASH_BYTES || nfcIsZero(value)) nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
    return value.copyOf()
}

internal fun nfcRequireChunkLimit(value: Int) {
    if (value !in 1..IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
}

internal fun nfcIsZero(value: ByteArray): Boolean = value.all { it.toInt() == 0 }

internal fun nfcIsZeroHash(value: ByteArray): Boolean = value.size == IrohaPeerNfcV1.HASH_BYTES && nfcIsZero(value)

internal fun nfcIsNonzeroHash(value: ByteArray): Boolean = value.size == IrohaPeerNfcV1.HASH_BYTES && !nfcIsZero(value)

private val NFC_RANDOM = SecureRandom()

/** A fresh random [count]-byte value with at least one nonzero byte. */
internal fun nfcRandomNonzero(count: Int): ByteArray {
    while (true) {
        val candidate = ByteArray(count)
        synchronized(NFC_RANDOM) { NFC_RANDOM.nextBytes(candidate) }
        if (!nfcIsZero(candidate)) return candidate
    }
}

internal fun nfcHasMagic(data: ByteArray, magic: ByteArray): Boolean =
    data.size >= magic.size && magic.indices.all { data[it] == magic[it] }

internal fun ByteArray.nfcU8(offset: Int): Int = this[offset].toInt() and 0xff

internal fun ByteArray.nfcU16(offset: Int): Int = (nfcU8(offset) shl 8) or nfcU8(offset + 1)

internal fun ByteArray.nfcU32(offset: Int): Long =
    (nfcU8(offset).toLong() shl 24) or (nfcU8(offset + 1).toLong() shl 16) or
        (nfcU8(offset + 2).toLong() shl 8) or nfcU8(offset + 3).toLong()

/** A BE32 length field as an `Int`; lengths beyond every V1 bound are invalid. */
internal fun nfcLength(value: Long): Int {
    if (value > Int.MAX_VALUE.toLong()) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    return value.toInt()
}

/** Exact-size big-endian record builder. */
internal class NfcRecordWriter(capacity: Int) {
    private val output = ByteArrayOutputStream(capacity)

    fun u8(value: Int) {
        output.write(value and 0xff)
    }

    fun u16(value: Int) {
        require(value in 0..0xffff) { "NFC u16 field out of range" }
        output.write(value ushr 8)
        output.write(value and 0xff)
    }

    fun u32(value: Long) {
        require(value in 0..0xffff_ffffL) { "NFC u32 field out of range" }
        output.write((value ushr 24).toInt() and 0xff)
        output.write((value ushr 16).toInt() and 0xff)
        output.write((value ushr 8).toInt() and 0xff)
        output.write(value.toInt() and 0xff)
    }

    fun bytes(value: ByteArray) {
        output.write(value, 0, value.size)
    }

    fun finish(expectedSize: Int = -1): ByteArray {
        val result = output.toByteArray()
        check(expectedSize < 0 || result.size == expectedSize) { "NFC record has an invalid length" }
        return result
    }
}

/** Kind of a verified IPM1 message. */
internal val IrohaPeerWireMessageV1.nfcKind: IrohaPeerPayloadKind get() = canonicalPayload.kind

/** Profile of a verified IPM1 message. */
internal val IrohaPeerWireMessageV1.nfcProfile: IrohaPeerPayloadProfile get() = canonicalPayload.profile

/** The exact 84-byte IPM1 header of a verified message. */
internal fun IrohaPeerWireMessageV1.nfcHeaderBytes(): ByteArray =
    encode().copyOfRange(0, IrohaPeerWireMessageV1.HEADER_LENGTH)

/**
 * Inspect an 84-byte IPM1 header of [expectedKind] before any body byte is buffered; every
 * header failure is [IrohaPeerNfcErrorV1.INVALID_IPM1], as in Swift `inspectHeader`.
 */
internal fun nfcInspectHeader(header: ByteArray, expectedKind: IrohaPeerPayloadKind): IrohaPeerWireMessageV1.Header {
    val inspected = try {
        IrohaPeerWireMessageV1.decodeHeader(header)
    } catch (failure: IllegalArgumentException) {
        throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_IPM1, cause = failure)
    }
    if (inspected.kind != expectedKind) nfcFail(IrohaPeerNfcErrorV1.INVALID_IPM1)
    return inspected
}

/**
 * Decode a complete IPM1 message of [expectedKind] within [limits], classifying failures as Swift
 * `nfcDecodeMessage` does: profile, kind, length, hash and other IPM1 failures.
 */
internal fun nfcDecodeMessage(
    data: ByteArray,
    expectedProfile: IrohaPeerPayloadProfile?,
    expectedKind: IrohaPeerPayloadKind,
    limits: IrohaPeerNfcLimitsV1,
): IrohaPeerWireMessageV1 {
    val headerLength = IrohaPeerWireMessageV1.HEADER_LENGTH
    if (data.size <= headerLength) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    if (data.size > limits.maximumMessageBytes) nfcMessageTooLarge(data.size, limits.maximumMessageBytes)
    if (!nfcHasMagic(data, IPM1_MAGIC) || data.nfcU8(4) != IrohaPeerWireMessageV1.VERSION ||
        IrohaPeerContentEncodingV1.fromCode(data.nfcU8(5)) == null
    ) {
        nfcFail(IrohaPeerNfcErrorV1.INVALID_IPM1)
    }
    val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(6)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
    val kind = IrohaPeerPayloadKind.fromCode(data.nfcU8(8)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_KIND)
    if (expectedProfile != null && profile != expectedProfile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
    if (kind != expectedKind) nfcFail(IrohaPeerNfcErrorV1.INVALID_KIND)
    if (data.nfcU8(9) != 0 || data.nfcU16(10) != profile.requiredSchemaVersion) {
        nfcFail(IrohaPeerNfcErrorV1.INVALID_IPM1)
    }
    val canonicalLength = data.nfcU32(12)
    val encodedLength = data.nfcU32(16)
    if (canonicalLength == 0L || encodedLength == 0L) nfcFail(IrohaPeerNfcErrorV1.INVALID_IPM1)
    val bound = minOf(IrohaPeerWireLimitsV1.PEER_V1.maximumCanonicalBytes, kind.maximumWalletFrameBytes).toLong()
    if (canonicalLength > bound || encodedLength > bound) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    if (data.nfcU8(5) == IrohaPeerContentEncodingV1.NONE.code && canonicalLength != encodedLength) {
        nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    }
    if (data.size.toLong() != headerLength + encodedLength) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    return try {
        IrohaPeerWireMessageV1.decode(data, expectedProfile, expectedKind)
    } catch (failure: IllegalArgumentException) {
        val hashFailure = failure.message?.contains("hash mismatch") == true
        throw IrohaPeerNfcExceptionV1(
            if (hashFailure) IrohaPeerNfcErrorV1.INVALID_HASH else IrohaPeerNfcErrorV1.INVALID_IPM1,
            cause = failure,
        )
    }
}

private val IPM1_MAGIC = "IPM1".toByteArray(Charsets.US_ASCII)

/**
 * The Payment must carry a completion of the hosted open Request (its terms and signature), and
 * Credited must name that Request's scheme ([KagemushaWalletWireV1.requireExchangeBinding]). Carrier
 * checks preserve exact bytes; only Native authenticates monetary effects and the payer companion.
 */
internal fun nfcRequireWalletExchange(
    request: IrohaPeerWireMessageV1,
    payment: IrohaPeerWireMessageV1,
    credited: IrohaPeerWireMessageV1? = null,
) {
    var requestFrame: ByteArray? = null
    var paymentFrame: ByteArray? = null
    var creditedFrame: ByteArray? = null
    try {
        requestFrame = IrohaPeerKagemushaWalletAdapterV1.decode(request)
        paymentFrame = IrohaPeerKagemushaWalletAdapterV1.decode(payment)
        creditedFrame = credited?.let { IrohaPeerKagemushaWalletAdapterV1.decode(it) }
        KagemushaWalletWireV1.requireExchangeBinding(requestFrame, paymentFrame, creditedFrame)
    } catch (failure: RuntimeException) {
        throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH, cause = failure)
    } finally {
        requestFrame?.fill(0)
        paymentFrame?.fill(0)
        creditedFrame?.fill(0)
    }
}

/**
 * A restored Credited acknowledgement must name the hosted Request's scheme: the Request body's
 * `scheme_id` field equals the Credited `scheme_id` field (wire record §3.4). This is the
 * Payment-free half of [KagemushaWalletWireV1.requireExchangeBinding], used where the receiver
 * restores its durable acknowledgement without the Payment.
 */
internal fun nfcRequireCreditedScheme(request: IrohaPeerWireMessageV1, credited: IrohaPeerWireMessageV1) {
    var requestFrame: ByteArray? = null
    var creditedFrame: ByteArray? = null
    try {
        requestFrame = IrohaPeerKagemushaWalletAdapterV1.decode(request)
        creditedFrame = IrohaPeerKagemushaWalletAdapterV1.decode(credited)
        val requestFields = nfcWalletMessageFields(requestFrame, KagemushaWalletMessageKindV1.REQUEST, 5)
        val body = nfcWalletRecordFields(requestFields[0], 17)
        val creditedFields = nfcWalletMessageFields(creditedFrame, KagemushaWalletMessageKindV1.CREDITED, 3)
        if (!creditedFields[1].contentEquals(body[1])) {
            throw IllegalArgumentException("KAGEMUSHA wallet V1 Credited does not name this Request's scheme")
        }
    } catch (failure: RuntimeException) {
        throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH, cause = failure)
    } finally {
        requestFrame?.fill(0)
        creditedFrame?.fill(0)
    }
}

/** Top-level record fields of an envelope's message: `[len] version [len] (tag [len] message)`. */
private fun nfcWalletMessageFields(
    frame: ByteArray,
    kind: KagemushaWalletMessageKindV1,
    count: Int,
): List<ByteArray> {
    require(KagemushaWalletWireV1.inspectEnvelope(frame).kind == kind) { "unexpected wallet message kind" }
    val payloadOffset = NoritoHeader.HEADER_LENGTH + KagemushaWalletWireV1.ENVELOPE_PADDING_BYTES
    var cursor = Varint.decode(frame, payloadOffset).nextOffset + 2
    cursor = Varint.decode(frame, cursor).nextOffset + 4
    val messageStart = Varint.decode(frame, cursor).nextOffset
    return nfcWalletRecordFields(frame.copyOfRange(messageStart, frame.size), count)
}

/** Exactly [count] compact-length fields that make up [record] completely. */
private fun nfcWalletRecordFields(record: ByteArray, count: Int): List<ByteArray> {
    val fields = ArrayList<ByteArray>(count)
    var offset = 0
    while (offset < record.size) {
        require(fields.size < count) { "wallet record has too many fields" }
        val field = Varint.decode(record, offset)
        require(field.value in 0L..(record.size - field.nextOffset).toLong()) { "wallet field exceeds its record" }
        offset = field.nextOffset + field.value.toInt()
        fields += record.copyOfRange(field.nextOffset, offset)
    }
    require(fields.size == count) { "wallet record has ${fields.size} of $count fields" }
    return fields
}
