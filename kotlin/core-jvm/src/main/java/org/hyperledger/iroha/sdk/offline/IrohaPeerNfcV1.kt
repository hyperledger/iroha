// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.ByteArrayOutputStream

// TODO(G4): carry the payer's Offer and SessionControl envelopes over NFC. Until then the receiver
// obtains the Offer before it builds the Request, over another carrier of the same envelope.

/**
 * Transport-neutral NFC constants. One session carries the KAGEMUSHA wallet Request (hosted by the
 * receiver), the payer's Payment and the receiver's durable acknowledgement, which is the wallet's
 * Credited envelope (IPM1 kind [IrohaPeerPayloadKind.CREDITED]).
 */
object IrohaPeerNfcV1 {
    private val applicationIdentifierBytes = byteArrayOf(
        0xf0.toByte(), 0x50, 0x4b, 0x45, 0x50, 0x4b, 0x52, 0x4e, 0x46, 0x43, 0x01,
    )

    const val APPLICATION_IDENTIFIER_HEX = "F0504B45504B524E464301"
    const val APPLICATION_IDENTIFIER_SIZE = 11
    const val COMMAND_CLASS = 0x80
    const val WIRE_VERSION = 1
    const val SESSION_ID_BYTES = 16
    const val HASH_BYTES = 32
    const val MAXIMUM_CHUNK_BYTES = 4_096
    const val MAXIMUM_MESSAGE_BYTES =
        IrohaPeerWireMessageV1.HEADER_LENGTH + IrohaPeerWireMessageV1.MAXIMUM_WALLET_ENCODED_BYTES

    @JvmStatic fun applicationIdentifier(): ByteArray = applicationIdentifierBytes.copyOf()

    @JvmStatic fun matchesApplicationIdentifier(candidate: ByteArray): Boolean =
        candidate.contentEquals(applicationIdentifierBytes)
}

/** Closed APDU instruction inventory for Request -> Payment -> Acknowledgement (Credited). */
enum class IrohaPeerNfcInstructionV1(val code: Int) {
    GET_INFO(0x10),
    READ_REQUEST(0x11),
    BEGIN_PAYMENT(0x20),
    WRITE_PAYMENT(0x21),
    COMMIT_PAYMENT(0x22),
    READ_ACKNOWLEDGEMENT(0x23),
    CONFIRM_ACKNOWLEDGEMENT(0x24),
    GET_STATUS(0x25),
    RESET_SESSION(0x7f);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcInstructionV1? =
            values().firstOrNull { it.code == code }
    }
}

/** Monotonic receiver phases for the direct three-message exchange. */
enum class IrohaPeerNfcPhaseV1(val code: Int) {
    REQUEST_READY(1),
    PAYMENT_RECEIVING(2),
    ACKNOWLEDGEMENT_READY(3),
    COMPLETE(4);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcPhaseV1? =
            values().firstOrNull { it.code == code }
    }
}

/** NFC status flags. Durable is set only after irreversible hardware staging. */
class IrohaPeerNfcFlagsV1(@JvmField val rawValue: Int) {
    init { require(rawValue in 0..KNOWN) { "invalid NFC flags" } }
    fun contains(flag: Int): Boolean = rawValue and flag == flag
    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcFlagsV1 && rawValue == other.rawValue
    override fun hashCode(): Int = rawValue

    companion object {
        const val IDEMPOTENT_WRITES = 1
        const val DURABLE_STATE = 2
        const val KNOWN = IDEMPOTENT_WRITES or DURABLE_STATE
        @JvmField val REQUEST = IrohaPeerNfcFlagsV1(IDEMPOTENT_WRITES)
        @JvmField val DURABLE = IrohaPeerNfcFlagsV1(KNOWN)
    }
}

/** Allocation and chunk bounds shared by reader and receiver. */
class IrohaPeerNfcLimitsV1 @JvmOverloads constructor(
    @JvmField val maximumMessageBytes: Int = IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES,
    @JvmField val maximumReadChunkBytes: Int = IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES,
    @JvmField val maximumWriteChunkBytes: Int = IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES,
) {
    init {
        require(maximumMessageBytes in
            (IrohaPeerWireMessageV1.HEADER_LENGTH + 1)..IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES)
        requireNfcChunk(maximumReadChunkBytes)
        requireNfcChunk(maximumWriteChunkBytes)
    }

    companion object { @JvmField val DEFAULT = IrohaPeerNfcLimitsV1() }
}

/** The one peer profile accepted throughout a session. */
class IrohaPeerNfcProfilePolicyV1(@JvmField val profile: IrohaPeerPayloadProfile) {
    fun accepts(candidate: IrohaPeerPayloadProfile): Boolean = profile == candidate
}

/** Stable session identity bound to the exact request. */
class IrohaPeerNfcRequestIdentityV1(
    @JvmField val profile: IrohaPeerPayloadProfile,
    sessionId: ByteArray,
    requestCanonicalHash: ByteArray,
    requestWireHash: ByteArray,
) {
    private val session = fixedNfc(sessionId, IrohaPeerNfcV1.SESSION_ID_BYTES, "sessionId", true)
    private val canonical = fixedNfc(requestCanonicalHash, 32, "requestCanonicalHash", true)
    private val wire = fixedNfc(requestWireHash, 32, "requestWireHash", true)
    fun sessionId(): ByteArray = session.copyOf()
    fun requestCanonicalHash(): ByteArray = canonical.copyOf()
    fun requestWireHash(): ByteArray = wire.copyOf()
}

/** Session descriptor returned by GET_INFO. */
class IrohaPeerNfcInfoV1(
    @JvmField val phase: IrohaPeerNfcPhaseV1,
    @JvmField val flags: IrohaPeerNfcFlagsV1,
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val requestLength: Int,
    @JvmField val maximumReadChunkBytes: Int,
    @JvmField val maximumWriteChunkBytes: Int,
) {
    init {
        require(requestLength in 1..IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES)
        requireNfcChunk(maximumReadChunkBytes)
        requireNfcChunk(maximumWriteChunkBytes)
    }

    fun encode(): ByteArray = ByteArrayOutputStream().also { out ->
        out.write("INF1".toByteArray(Charsets.US_ASCII))
        out.write(IrohaPeerNfcV1.WIRE_VERSION)
        out.write(phase.code)
        out.write(flags.rawValue)
        out.write(identity.profile.code)
        out.write(identity.sessionId())
        out.write(identity.requestCanonicalHash())
        out.write(identity.requestWireHash())
        out.writeU32(requestLength)
        out.writeU16(maximumReadChunkBytes)
        out.writeU16(maximumWriteChunkBytes)
    }.toByteArray()

    companion object {
        @JvmStatic fun decode(bytes: ByteArray): IrohaPeerNfcInfoV1 {
            val reader = NfcReader(bytes)
            require(reader.read(4).contentEquals("INF1".toByteArray(Charsets.US_ASCII)))
            require(reader.u8() == 1)
            val phase = requireNotNull(IrohaPeerNfcPhaseV1.fromCode(reader.u8()))
            val flags = IrohaPeerNfcFlagsV1(reader.u8())
            val profile = requireNotNull(IrohaPeerPayloadProfile.fromCode(reader.u8()))
            val identity = IrohaPeerNfcRequestIdentityV1(
                profile,
                reader.read(16),
                reader.read(32),
                reader.read(32),
            )
            return IrohaPeerNfcInfoV1(
                phase,
                flags,
                identity,
                reader.u32(),
                reader.u16(),
                reader.u16(),
            ).also { reader.finish() }
        }
    }
}

/** Compact restart/status projection. */
class IrohaPeerNfcStatusV1(
    @JvmField val phase: IrohaPeerNfcPhaseV1,
    @JvmField val flags: IrohaPeerNfcFlagsV1,
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val receivedPaymentBytes: Int,
    paymentWireHash: ByteArray?,
    @JvmField val acknowledgementLength: Int,
    acknowledgementWireHash: ByteArray?,
) {
    private val paymentHash = paymentWireHash?.let { fixedNfc(it, 32, "paymentWireHash", true) }
    private val acknowledgementHash = acknowledgementWireHash?.let {
        fixedNfc(it, 32, "acknowledgementWireHash", true)
    }
    fun paymentWireHash(): ByteArray? = paymentHash?.copyOf()
    fun acknowledgementWireHash(): ByteArray? = acknowledgementHash?.copyOf()

    fun encode(): ByteArray = ByteArrayOutputStream().also { out ->
        out.write("NST1".toByteArray(Charsets.US_ASCII))
        out.write(1)
        out.write(phase.code)
        out.write(flags.rawValue)
        out.write(identity.profile.code)
        out.write(identity.sessionId())
        out.write(identity.requestCanonicalHash())
        out.write(identity.requestWireHash())
        out.writeU32(receivedPaymentBytes)
        out.writeOptionalHash(paymentHash)
        out.writeU32(acknowledgementLength)
        out.writeOptionalHash(acknowledgementHash)
    }.toByteArray()

    companion object {
        @JvmStatic fun decode(bytes: ByteArray): IrohaPeerNfcStatusV1 {
            val reader = NfcReader(bytes)
            require(reader.read(4).contentEquals("NST1".toByteArray(Charsets.US_ASCII)))
            require(reader.u8() == 1)
            val phase = requireNotNull(IrohaPeerNfcPhaseV1.fromCode(reader.u8()))
            val flags = IrohaPeerNfcFlagsV1(reader.u8())
            val profile = requireNotNull(IrohaPeerPayloadProfile.fromCode(reader.u8()))
            val session = reader.read(16)
            val requestCanonicalHash = reader.read(32)
            val requestWireHash = reader.read(32)
            val received = reader.u32()
            val paymentHash = reader.optionalHash()
            val acknowledgementLength = reader.u32()
            val acknowledgementHash = reader.optionalHash()
            reader.finish()
            return IrohaPeerNfcStatusV1(
                phase,
                flags,
                IrohaPeerNfcRequestIdentityV1(profile, session, requestCanonicalHash, requestWireHash),
                received,
                paymentHash,
                acknowledgementLength,
                acknowledgementHash,
            )
        }
    }
}

enum class IrohaPeerNfcCommandTypeV1 {
    GET_INFO,
    READ_REQUEST,
    BEGIN_PAYMENT,
    WRITE_PAYMENT,
    COMMIT_PAYMENT,
    READ_ACKNOWLEDGEMENT,
    CONFIRM_ACKNOWLEDGEMENT,
    GET_STATUS,
    RESET_SESSION,
}

/** Immutable, strictly bounded APDU command. */
class IrohaPeerNfcCommandV1 private constructor(
    @JvmField val type: IrohaPeerNfcCommandTypeV1,
    @JvmField val offset: Int = 0,
    @JvmField val length: Int = 0,
    bytes: ByteArray = byteArrayOf(),
) {
    private val body = bytes.copyOf()
    fun bytes(): ByteArray = body.copyOf()

    companion object {
        @JvmField val GET_INFO = IrohaPeerNfcCommandV1(IrohaPeerNfcCommandTypeV1.GET_INFO)
        @JvmField val COMMIT_PAYMENT = IrohaPeerNfcCommandV1(IrohaPeerNfcCommandTypeV1.COMMIT_PAYMENT)
        @JvmField val CONFIRM_ACKNOWLEDGEMENT =
            IrohaPeerNfcCommandV1(IrohaPeerNfcCommandTypeV1.CONFIRM_ACKNOWLEDGEMENT)
        @JvmField val GET_STATUS = IrohaPeerNfcCommandV1(IrohaPeerNfcCommandTypeV1.GET_STATUS)
        @JvmField val RESET_SESSION = IrohaPeerNfcCommandV1(IrohaPeerNfcCommandTypeV1.RESET_SESSION)

        @JvmStatic fun readRequest(offset: Int, length: Int) = read(
            IrohaPeerNfcCommandTypeV1.READ_REQUEST,
            offset,
            length,
        )

        @JvmStatic fun readAcknowledgement(offset: Int, length: Int) = read(
            IrohaPeerNfcCommandTypeV1.READ_ACKNOWLEDGEMENT,
            offset,
            length,
        )

        @JvmStatic fun beginPayment(descriptor: IrohaPeerNfcPaymentDescriptorV1) =
            IrohaPeerNfcCommandV1(
                IrohaPeerNfcCommandTypeV1.BEGIN_PAYMENT,
                bytes = descriptor.encode(),
            )

        @JvmStatic fun writePayment(offset: Int, bytes: ByteArray): IrohaPeerNfcCommandV1 {
            require(offset >= 0 && bytes.isNotEmpty() && bytes.size <= IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES)
            return IrohaPeerNfcCommandV1(
                IrohaPeerNfcCommandTypeV1.WRITE_PAYMENT,
                offset,
                bytes.size,
                bytes,
            )
        }

        private fun read(type: IrohaPeerNfcCommandTypeV1, offset: Int, length: Int): IrohaPeerNfcCommandV1 {
            require(offset >= 0)
            requireNfcChunk(length)
            return IrohaPeerNfcCommandV1(type, offset, length)
        }
    }
}

/** ISO-7816-compatible envelope for the closed Iroha peer NFC command inventory. */
object IrohaPeerNfcAPDUCodecV1 {
    @JvmStatic fun encode(command: IrohaPeerNfcCommandV1): ByteArray {
        val instruction = when (command.type) {
            IrohaPeerNfcCommandTypeV1.GET_INFO -> IrohaPeerNfcInstructionV1.GET_INFO
            IrohaPeerNfcCommandTypeV1.READ_REQUEST -> IrohaPeerNfcInstructionV1.READ_REQUEST
            IrohaPeerNfcCommandTypeV1.BEGIN_PAYMENT -> IrohaPeerNfcInstructionV1.BEGIN_PAYMENT
            IrohaPeerNfcCommandTypeV1.WRITE_PAYMENT -> IrohaPeerNfcInstructionV1.WRITE_PAYMENT
            IrohaPeerNfcCommandTypeV1.COMMIT_PAYMENT -> IrohaPeerNfcInstructionV1.COMMIT_PAYMENT
            IrohaPeerNfcCommandTypeV1.READ_ACKNOWLEDGEMENT -> IrohaPeerNfcInstructionV1.READ_ACKNOWLEDGEMENT
            IrohaPeerNfcCommandTypeV1.CONFIRM_ACKNOWLEDGEMENT -> IrohaPeerNfcInstructionV1.CONFIRM_ACKNOWLEDGEMENT
            IrohaPeerNfcCommandTypeV1.GET_STATUS -> IrohaPeerNfcInstructionV1.GET_STATUS
            IrohaPeerNfcCommandTypeV1.RESET_SESSION -> IrohaPeerNfcInstructionV1.RESET_SESSION
        }
        val data = when (command.type) {
            IrohaPeerNfcCommandTypeV1.READ_REQUEST,
            IrohaPeerNfcCommandTypeV1.READ_ACKNOWLEDGEMENT,
            -> ByteArrayOutputStream(6).also {
                it.writeU32(command.offset)
                it.writeU16(command.length)
            }.toByteArray()
            IrohaPeerNfcCommandTypeV1.WRITE_PAYMENT -> ByteArrayOutputStream(4 + command.length).also {
                it.writeU32(command.offset)
                it.write(command.bytes())
            }.toByteArray()
            IrohaPeerNfcCommandTypeV1.BEGIN_PAYMENT -> command.bytes()
            else -> byteArrayOf()
        }
        require(data.size <= 0xffff)
        return ByteArrayOutputStream(7 + data.size).also {
            it.write(IrohaPeerNfcV1.COMMAND_CLASS)
            it.write(instruction.code)
            it.write(0)
            it.write(0)
            it.writeU16(data.size)
            it.write(data)
            it.write(0)
        }.toByteArray()
    }

    @JvmStatic fun decode(apdu: ByteArray): IrohaPeerNfcCommandV1 {
        val reader = NfcReader(apdu)
        require(reader.u8() == IrohaPeerNfcV1.COMMAND_CLASS)
        val instruction = requireNotNull(IrohaPeerNfcInstructionV1.fromCode(reader.u8()))
        require(reader.u8() == 0 && reader.u8() == 0)
        val length = reader.u16()
        val data = reader.read(length)
        require(reader.u8() == 0)
        reader.finish()
        return when (instruction) {
            IrohaPeerNfcInstructionV1.GET_INFO -> noData(data, IrohaPeerNfcCommandV1.GET_INFO)
            IrohaPeerNfcInstructionV1.COMMIT_PAYMENT -> noData(data, IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
            IrohaPeerNfcInstructionV1.CONFIRM_ACKNOWLEDGEMENT ->
                noData(data, IrohaPeerNfcCommandV1.CONFIRM_ACKNOWLEDGEMENT)
            IrohaPeerNfcInstructionV1.GET_STATUS -> noData(data, IrohaPeerNfcCommandV1.GET_STATUS)
            IrohaPeerNfcInstructionV1.RESET_SESSION -> noData(data, IrohaPeerNfcCommandV1.RESET_SESSION)
            IrohaPeerNfcInstructionV1.BEGIN_PAYMENT ->
                IrohaPeerNfcCommandV1.beginPayment(IrohaPeerNfcPaymentDescriptorV1.decode(data))
            IrohaPeerNfcInstructionV1.READ_REQUEST,
            IrohaPeerNfcInstructionV1.READ_ACKNOWLEDGEMENT,
            -> {
                val body = NfcReader(data)
                val offset = body.u32()
                val count = body.u16()
                body.finish()
                if (instruction == IrohaPeerNfcInstructionV1.READ_REQUEST) {
                    IrohaPeerNfcCommandV1.readRequest(offset, count)
                } else {
                    IrohaPeerNfcCommandV1.readAcknowledgement(offset, count)
                }
            }
            IrohaPeerNfcInstructionV1.WRITE_PAYMENT -> {
                val body = NfcReader(data)
                val offset = body.u32()
                val chunk = body.remaining()
                require(chunk.isNotEmpty())
                IrohaPeerNfcCommandV1.writePayment(offset, chunk)
            }
        }
    }

    private fun noData(data: ByteArray, command: IrohaPeerNfcCommandV1): IrohaPeerNfcCommandV1 {
        require(data.isEmpty())
        return command
    }
}

/** Header-derived immutable descriptor for one payment transfer. */
class IrohaPeerNfcPaymentDescriptorV1 private constructor(
    @JvmField val profile: IrohaPeerPayloadProfile,
    @JvmField val schemaVersion: Int,
    @JvmField val messageLength: Int,
    canonicalHash: ByteArray,
    wireHash: ByteArray,
) {
    private val canonical = fixedNfc(canonicalHash, 32, "canonicalHash", true)
    private val wire = fixedNfc(wireHash, 32, "wireHash", true)

    constructor(message: IrohaPeerWireMessageV1) : this(
        message.canonicalPayload.profile,
        message.canonicalPayload.schemaVersion,
        message.encode().size,
        message.canonicalHash,
        message.wireHash,
    ) {
        require(message.canonicalPayload.kind == IrohaPeerPayloadKind.PAYMENT)
    }

    init {
        require(schemaVersion == profile.requiredSchemaVersion)
        require(messageLength in 1..IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES)
    }
    fun canonicalHash(): ByteArray = canonical.copyOf()
    fun wireHash(): ByteArray = wire.copyOf()
    fun encode(): ByteArray = ByteArrayOutputStream(72).also {
        it.write(profile.code)
        it.writeU16(schemaVersion)
        it.writeU32(messageLength)
        it.write(canonical)
        it.write(wire)
    }.toByteArray()

    companion object {
        @JvmStatic fun decode(bytes: ByteArray): IrohaPeerNfcPaymentDescriptorV1 {
            val reader = NfcReader(bytes)
            val profile = requireNotNull(IrohaPeerPayloadProfile.fromCode(reader.u8()))
            val schema = reader.u16()
            val length = reader.u32()
            val canonical = reader.read(32)
            val wire = reader.read(32)
            reader.finish()
            return IrohaPeerNfcPaymentDescriptorV1(profile, schema, length, canonical, wire)
        }
    }
}

/** Public inputs handed to the irreversible hardware staging callback. */
class IrohaPeerNfcPaymentAdmissionContextV1 internal constructor(
    canonicalRequest: ByteArray,
    canonicalPayment: ByteArray,
) {
    private val request = canonicalRequest.copyOf()
    private val payment = canonicalPayment.copyOf()
    fun canonicalRequest(): ByteArray = request.copyOf()
    fun canonicalPayment(): ByteArray = payment.copyOf()
}

/** Durable result: exact payment plus the byte-identical Credited acknowledgement. */
class IrohaPeerNfcDurablePaymentAdmissionV1(
    @JvmField val context: IrohaPeerNfcPaymentAdmissionContextV1,
    canonicalAcknowledgement: ByteArray,
) {
    private val acknowledgement = canonicalAcknowledgement.copyOf()
    init { require(acknowledgement.isNotEmpty()) }
    fun canonicalAcknowledgement(): ByteArray = acknowledgement.copyOf()
}

sealed class IrohaPeerNfcPaymentAdmissionDispositionV1 {
    object Immediate : IrohaPeerNfcPaymentAdmissionDispositionV1()
    class Persist(@JvmField val context: IrohaPeerNfcPaymentAdmissionContextV1) :
        IrohaPeerNfcPaymentAdmissionDispositionV1()
}

/** Receiver session which never exposes an ACK before durable hardware staging. */
class IrohaPeerNfcReceiverSessionV1(
    canonicalRequest: ByteArray,
    sessionId: ByteArray,
    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1,
    @JvmField val limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    private val requestBytes = canonicalRequest.copyOf()
    private val request = decodeNfcMessage(requestBytes, profilePolicy.profile, IrohaPeerPayloadKind.REQUEST, limits)
    private val identity = IrohaPeerNfcRequestIdentityV1(
        request.canonicalPayload.profile,
        sessionId,
        request.canonicalHash,
        request.wireHash,
    )
    private var phase = IrohaPeerNfcPhaseV1.REQUEST_READY
    private var descriptor: IrohaPeerNfcPaymentDescriptorV1? = null
    private var paymentBuffer: ByteArray? = null
    private var received = 0
    private var paymentBytes: ByteArray? = null
    private var acknowledgementBytes: ByteArray? = null
    private var pendingPaymentContext: IrohaPeerNfcPaymentAdmissionContextV1? = null

    @Synchronized fun handle(command: IrohaPeerNfcCommandV1): Any = when (command.type) {
        IrohaPeerNfcCommandTypeV1.GET_INFO -> info().encode()
        IrohaPeerNfcCommandTypeV1.GET_STATUS -> status().encode()
        IrohaPeerNfcCommandTypeV1.READ_REQUEST -> readRange(requestBytes, command.offset, command.length)
        IrohaPeerNfcCommandTypeV1.BEGIN_PAYMENT -> beginPayment(command)
        IrohaPeerNfcCommandTypeV1.WRITE_PAYMENT -> writePayment(command)
        IrohaPeerNfcCommandTypeV1.COMMIT_PAYMENT -> commitPayment()
        IrohaPeerNfcCommandTypeV1.READ_ACKNOWLEDGEMENT -> {
            require(phase == IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY || phase == IrohaPeerNfcPhaseV1.COMPLETE)
            readRange(requireNotNull(acknowledgementBytes), command.offset, command.length)
        }
        IrohaPeerNfcCommandTypeV1.CONFIRM_ACKNOWLEDGEMENT -> {
            require(phase == IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY || phase == IrohaPeerNfcPhaseV1.COMPLETE)
            phase = IrohaPeerNfcPhaseV1.COMPLETE
            byteArrayOf()
        }
        IrohaPeerNfcCommandTypeV1.RESET_SESSION -> {
            require(phase == IrohaPeerNfcPhaseV1.REQUEST_READY || phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING)
            require(pendingPaymentContext == null) { "payment admission is pending" }
            require(paymentBytes == null) { "committed payment identity cannot be reset" }
            descriptor = null
            paymentBuffer = null
            received = 0
            phase = IrohaPeerNfcPhaseV1.REQUEST_READY
            byteArrayOf()
        }
    }

    @Synchronized fun completePayment(
        context: IrohaPeerNfcPaymentAdmissionContextV1,
        durable: IrohaPeerNfcDurablePaymentAdmissionV1,
    ) {
        require(durable.context === context)
        require(pendingPaymentContext === context) { "payment admission context changed" }
        require(phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING)
        val payment = requireNotNull(paymentBytes)
        require(context.canonicalRequest().contentEquals(requestBytes))
        require(context.canonicalPayment().contentEquals(payment))
        val acknowledgement = decodeNfcMessage(
            durable.canonicalAcknowledgement(),
            profilePolicy.profile,
            IrohaPeerPayloadKind.CREDITED,
            limits,
        )
        validateWalletExchange(request, decodeNfcMessage(payment, profilePolicy.profile, IrohaPeerPayloadKind.PAYMENT, limits), acknowledgement)
        acknowledgementBytes = durable.canonicalAcknowledgement()
        phase = IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY
        pendingPaymentContext = null
    }

    @Synchronized fun rejectPayment(context: IrohaPeerNfcPaymentAdmissionContextV1) {
        if (phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING && pendingPaymentContext === context) {
            pendingPaymentContext = null
            paymentBuffer = null
            // The native transition may have happened before its response was lost.
            // Retain the first committed payment and admit only its exact replay.
            received = 0
            phase = IrohaPeerNfcPhaseV1.REQUEST_READY
        }
    }

    /** An interrupted RF activation cannot retain an in-flight admission as a second COMMIT. */
    @Synchronized fun abandonPendingPayment() {
        pendingPaymentContext?.let { rejectPayment(it) }
    }

    @Synchronized fun info(): IrohaPeerNfcInfoV1 = IrohaPeerNfcInfoV1(
        phase,
        if (phase == IrohaPeerNfcPhaseV1.REQUEST_READY || phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING) {
            IrohaPeerNfcFlagsV1.REQUEST
        } else {
            IrohaPeerNfcFlagsV1.DURABLE
        },
        identity,
        requestBytes.size,
        limits.maximumReadChunkBytes,
        limits.maximumWriteChunkBytes,
    )

    @Synchronized fun status(): IrohaPeerNfcStatusV1 {
        val payment = paymentBytes?.let { IrohaPeerWireMessageV1.decode(it) }
        val acknowledgement = acknowledgementBytes?.let { IrohaPeerWireMessageV1.decode(it) }
        return IrohaPeerNfcStatusV1(
            phase,
            info().flags,
            identity,
            received,
            payment?.wireHash,
            acknowledgementBytes?.size ?: 0,
            acknowledgement?.wireHash,
        )
    }

    private fun beginPayment(command: IrohaPeerNfcCommandV1): ByteArray {
        val next = IrohaPeerNfcPaymentDescriptorV1.decode(command.bytes())
        if (phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING) {
            require(requireNotNull(descriptor).encode().contentEquals(next.encode())) {
                "resume requires the exact retained payment descriptor"
            }
            return byteArrayOf()
        }
        require(phase == IrohaPeerNfcPhaseV1.REQUEST_READY)
        require(profilePolicy.accepts(next.profile))
        require(next.schemaVersion == profilePolicy.profile.requiredSchemaVersion)
        require(next.messageLength in 1..limits.maximumMessageBytes)
        paymentBytes?.let {
            require(next.encode().contentEquals(requireNotNull(descriptor).encode())) {
                "uncertain payment must retain its exact descriptor"
            }
        }
        descriptor = next
        paymentBuffer = ByteArray(next.messageLength)
        received = 0
        phase = IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING
        return byteArrayOf()
    }

    private fun writePayment(command: IrohaPeerNfcCommandV1): ByteArray {
        require(phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING)
        require(pendingPaymentContext == null) { "payment admission is pending" }
        require(command.offset == received) { "payment chunks must be exact and contiguous" }
        val chunk = command.bytes()
        require(chunk.size <= limits.maximumWriteChunkBytes)
        val buffer = requireNotNull(paymentBuffer)
        require(received + chunk.size <= buffer.size)
        paymentBytes?.let {
            require(chunk.contentEquals(it.copyOfRange(received, received + chunk.size))) {
                "uncertain payment must retain its exact bytes"
            }
        }
        chunk.copyInto(buffer, received)
        received += chunk.size
        return byteArrayOf()
    }

    private fun commitPayment(): IrohaPeerNfcPaymentAdmissionDispositionV1 {
        require(phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING)
        require(pendingPaymentContext == null) { "payment admission is pending" }
        val buffer = requireNotNull(paymentBuffer)
        require(received == buffer.size)
        val message = decodeNfcMessage(buffer, profilePolicy.profile, IrohaPeerPayloadKind.PAYMENT, limits)
        val expected = requireNotNull(descriptor)
        require(message.canonicalHash.contentEquals(expected.canonicalHash()))
        require(message.wireHash.contentEquals(expected.wireHash()))
        validateWalletExchange(request, message, null)
        paymentBytes?.let { require(buffer.contentEquals(it)) { "uncertain payment changed" } }
        if (paymentBytes == null) paymentBytes = buffer.copyOf()
        val context = IrohaPeerNfcPaymentAdmissionContextV1(requestBytes, buffer)
        pendingPaymentContext = context
        return IrohaPeerNfcPaymentAdmissionDispositionV1.Persist(
            context,
        )
    }
}

enum class IrohaPeerNfcReaderStatusV1(val code: Int) {
    SUCCESS(0x9000),
    WRONG_DATA(0x6a80),
    NOT_FOUND(0x6a82),
    WRONG_LENGTH(0x6700),
    CONDITIONS_NOT_SATISFIED(0x6985),
    SECURITY_STATUS_NOT_SATISFIED(0x6982),
    STORAGE_FAILURE(0x6581),
    INSTRUCTION_NOT_SUPPORTED(0x6d00),
    CLASS_NOT_SUPPORTED(0x6e00);

    companion object {
        @JvmStatic fun fromCode(code: Int): IrohaPeerNfcReaderStatusV1? =
            values().firstOrNull { it.code == code }
    }
}

class IrohaPeerNfcReaderResponseV1(
    bytes: ByteArray = byteArrayOf(),
    @JvmField val status: IrohaPeerNfcReaderStatusV1 = IrohaPeerNfcReaderStatusV1.SUCCESS,
) {
    private val body = bytes.copyOf()
    fun bytes(): ByteArray = body.copyOf()
}

class IrohaPeerNfcReaderStatusExceptionV1(@JvmField val peerStatus: IrohaPeerNfcReaderStatusV1) :
    IllegalStateException("NFC peer returned ${peerStatus.name}")

interface IrohaPeerNfcAmbiguousResponseErrorV1

fun interface IrohaPeerNfcReaderTransceiverV1 {
    fun transceive(command: IrohaPeerNfcCommandV1): IrohaPeerNfcReaderResponseV1
}

class IrohaPeerNfcReaderExchangeResultV1(
    @JvmField val request: IrohaPeerWireMessageV1,
    @JvmField val payment: IrohaPeerWireMessageV1,
    @JvmField val acknowledgement: IrohaPeerWireMessageV1,
)

/** Synchronous transport-neutral reader flow for exactly three messages. */
object IrohaPeerNfcReaderExchangeV1 {
    fun interface PreparePayment {
        fun prepare(request: IrohaPeerWireMessageV1): IrohaPeerWireMessageV1
    }

    /**
     * Accept the exact ACK in the native wallet and durably retain the exchange
     * before returning. This callback must be idempotent across process restarts.
     * Throw on persistence/native-acceptance failure; no confirmation is sent.
     * Shape validation here does not replace native signature/receipt verification.
     */
    fun interface PersistAcknowledgement {
        fun persist(exchange: IrohaPeerNfcReaderExchangeResultV1)
    }

    @JvmStatic fun run(
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1,
        transceiver: IrohaPeerNfcReaderTransceiverV1,
        preparePayment: PreparePayment,
        persistAcknowledgement: PersistAcknowledgement,
    ): IrohaPeerNfcReaderExchangeResultV1 {
        fun send(command: IrohaPeerNfcCommandV1): ByteArray {
            val response = transceiver.transceive(command)
            if (response.status != IrohaPeerNfcReaderStatusV1.SUCCESS) {
                throw IrohaPeerNfcReaderStatusExceptionV1(response.status)
            }
            return response.bytes()
        }

        val info = IrohaPeerNfcInfoV1.decode(send(IrohaPeerNfcCommandV1.GET_INFO))
        require(profilePolicy.accepts(info.identity.profile))
        val requestBytes = readChunks(info.requestLength, info.maximumReadChunkBytes) { offset, count ->
            send(IrohaPeerNfcCommandV1.readRequest(offset, count))
        }
        val request = decodeNfcMessage(requestBytes, profilePolicy.profile, IrohaPeerPayloadKind.REQUEST, limits)
        require(info.identity.requestCanonicalHash().contentEquals(request.canonicalHash))
        require(info.identity.requestWireHash().contentEquals(request.wireHash))
        // For this request the host must recover its retained payment, never
        // create another debit merely because transport confirmation was lost.
        val payment = preparePayment.prepare(request)
        require(payment.canonicalPayload.profile == profilePolicy.profile)
        require(payment.canonicalPayload.kind == IrohaPeerPayloadKind.PAYMENT)
        validateWalletExchange(request, payment, null)
        val paymentBytes = payment.encode()
        require(paymentBytes.size <= limits.maximumMessageBytes)
        fun readStatus(): IrohaPeerNfcStatusV1 =
            IrohaPeerNfcStatusV1.decode(send(IrohaPeerNfcCommandV1.GET_STATUS)).also {
                require(it.identity.profile == info.identity.profile)
                require(it.identity.sessionId().contentEquals(info.identity.sessionId()))
                require(it.identity.requestCanonicalHash().contentEquals(request.canonicalHash))
                require(it.identity.requestWireHash().contentEquals(request.wireHash))
            }
        if (info.phase == IrohaPeerNfcPhaseV1.REQUEST_READY ||
            info.phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING) {
            // BEGIN is idempotent only for the byte-identical descriptor. It
            // authenticates which partial buffer a resumed offset belongs to.
            send(IrohaPeerNfcCommandV1.beginPayment(IrohaPeerNfcPaymentDescriptorV1(payment)))
            val partial = readStatus()
            require(partial.phase == IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING)
            require(partial.receivedPaymentBytes in 0..paymentBytes.size)
            var offset = partial.receivedPaymentBytes
            while (offset < paymentBytes.size) {
                val end = minOf(paymentBytes.size, offset + info.maximumWriteChunkBytes)
                send(IrohaPeerNfcCommandV1.writePayment(offset, paymentBytes.copyOfRange(offset, end)))
                offset = end
            }
            send(IrohaPeerNfcCommandV1.COMMIT_PAYMENT)
        }
        val status = readStatus()
        require(status.phase == IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY || status.phase == IrohaPeerNfcPhaseV1.COMPLETE)
        require(status.flags.contains(IrohaPeerNfcFlagsV1.DURABLE_STATE))
        require(status.receivedPaymentBytes == paymentBytes.size)
        require(requireNotNull(status.paymentWireHash()).contentEquals(payment.wireHash))
        require(status.acknowledgementLength in 1..limits.maximumMessageBytes)
        val acknowledgementBytes = readChunks(
            status.acknowledgementLength,
            info.maximumReadChunkBytes,
        ) { readOffset, count ->
            send(IrohaPeerNfcCommandV1.readAcknowledgement(readOffset, count))
        }
        val acknowledgement = decodeNfcMessage(
            acknowledgementBytes,
            profilePolicy.profile,
            IrohaPeerPayloadKind.CREDITED,
            limits,
        )
        validateWalletExchange(request, payment, acknowledgement)
        require(requireNotNull(status.acknowledgementWireHash()).contentEquals(acknowledgement.wireHash))
        val exchange = IrohaPeerNfcReaderExchangeResultV1(request, payment, acknowledgement)
        persistAcknowledgement.persist(exchange)
        send(IrohaPeerNfcCommandV1.CONFIRM_ACKNOWLEDGEMENT)
        return exchange
    }
}

private fun decodeNfcMessage(
    bytes: ByteArray,
    expectedProfile: IrohaPeerPayloadProfile,
    expectedKind: IrohaPeerPayloadKind,
    limits: IrohaPeerNfcLimitsV1,
): IrohaPeerWireMessageV1 {
    require(bytes.size in 1..limits.maximumMessageBytes)
    return IrohaPeerWireMessageV1.decode(bytes, expectedProfile, expectedKind)
}

/**
 * The Payment must carry exactly this session's signed Request and the Credited acknowledgement
 * must name its scheme ([KagemushaWalletWireV1.requireExchangeBinding]); typed verification of the
 * Credited evidence stays with the wallet.
 */
private fun validateWalletExchange(
    request: IrohaPeerWireMessageV1,
    payment: IrohaPeerWireMessageV1,
    credited: IrohaPeerWireMessageV1?,
) {
    val requestBytes = IrohaPeerKagemushaWalletAdapterV1.decode(request)
    val paymentBytes = payment.canonicalPayload.bytes
    val creditedBytes = credited?.canonicalPayload?.bytes
    try {
        KagemushaWalletWireV1.requireExchangeBinding(requestBytes, paymentBytes, creditedBytes)
    } finally {
        requestBytes.fill(0)
        paymentBytes.fill(0)
        creditedBytes?.fill(0)
    }
}

private fun readChunks(length: Int, chunkSize: Int, read: (Int, Int) -> ByteArray): ByteArray {
    require(length > 0)
    val output = ByteArray(length)
    var offset = 0
    while (offset < length) {
        val count = minOf(chunkSize, length - offset)
        val chunk = read(offset, count)
        require(chunk.size == count)
        chunk.copyInto(output, offset)
        offset += count
    }
    return output
}

private fun readRange(bytes: ByteArray, offset: Int, length: Int): ByteArray {
    require(offset >= 0 && length > 0 && offset + length <= bytes.size)
    return bytes.copyOfRange(offset, offset + length)
}

private fun fixedNfc(value: ByteArray, size: Int, name: String, nonzero: Boolean): ByteArray {
    require(value.size == size) { "$name must be $size bytes" }
    require(!nonzero || value.any { it.toInt() != 0 }) { "$name must be nonzero" }
    return value.copyOf()
}

private fun requireNfcChunk(value: Int) {
    require(value in 1..IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) { "invalid NFC chunk size" }
}

private fun ByteArrayOutputStream.writeU16(value: Int) {
    require(value in 0..0xffff)
    write(value ushr 8)
    write(value)
}

private fun ByteArrayOutputStream.writeU32(value: Int) {
    require(value >= 0)
    write(value ushr 24)
    write(value ushr 16)
    write(value ushr 8)
    write(value)
}

private fun ByteArrayOutputStream.writeOptionalHash(value: ByteArray?) {
    write(if (value == null) 0 else 1)
    if (value != null) write(value)
}

private class NfcReader(private val bytes: ByteArray) {
    private var offset = 0
    fun u8(): Int = read(1)[0].toInt() and 0xff
    fun u16(): Int = (u8() shl 8) or u8()
    fun u32(): Int {
        val value = (u8().toLong() shl 24) or (u8().toLong() shl 16) or
            (u8().toLong() shl 8) or u8().toLong()
        require(value <= Int.MAX_VALUE.toLong())
        return value.toInt()
    }
    fun optionalHash(): ByteArray? = when (u8()) {
        0 -> null
        1 -> read(32).also { require(it.any { byte -> byte.toInt() != 0 }) }
        else -> throw IllegalArgumentException("invalid optional hash")
    }
    fun read(count: Int): ByteArray {
        require(count >= 0 && count <= bytes.size - offset) { "truncated NFC data" }
        return bytes.copyOfRange(offset, offset + count).also { offset += count }
    }
    fun remaining(): ByteArray = read(bytes.size - offset)
    fun finish() { require(offset == bytes.size) { "trailing NFC data" } }
}
