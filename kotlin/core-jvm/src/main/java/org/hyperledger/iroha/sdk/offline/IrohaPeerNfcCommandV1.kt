// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * Typed Iroha peer NFC V1 command, one case per Swift `IrohaPeerNfcCommandV1` case. Construction
 * validates every field (16-byte nonzero session `s`, 32-byte nonzero hashes, BE32 offsets,
 * 1–4,096-byte chunks and the IPM1 headers of BEGIN_OFFER and BEGIN_PAYMENT), so a command always
 * has exactly one canonical APDU ([IrohaPeerNfcAPDUCodecV1]).
 */
sealed class IrohaPeerNfcCommandV1 {
    abstract val operation: IrohaPeerNfcOperationV1

    /** `00 A4 04 00 ‖ Lc ‖ AID ‖ 00`. */
    class SelectApplication(@JvmField val applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1) :
        IrohaPeerNfcCommandV1() {
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.SELECT_APPLICATION

        override fun equals(other: Any?): Boolean =
            other is SelectApplication && applicationIdentifier == other.applicationIdentifier

        override fun hashCode(): Int = applicationIdentifier.hashCode()

        override fun toString(): String = "SELECT($applicationIdentifier)"
    }

    /** GET_INTAKE (`30`), Le 68: the card's `IOI1` record. */
    object GetIntake : IrohaPeerNfcCommandV1() {
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.GET_INTAKE

        override fun toString(): String = "GET_INTAKE"
    }

    /** BEGIN_OFFER (`31`): `s ‖` Offer IPM1 header (84). */
    class BeginOffer(sessionId: ByteArray, offerHeader: ByteArray) : IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val header = offerHeader.copyOf().also { nfcInspectHeader(it, IrohaPeerPayloadKind.OFFER) }
        val sessionId: ByteArray get() = session.copyOf()
        val offerHeader: ByteArray get() = header.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.BEGIN_OFFER

        internal fun sessionEquals(candidate: ByteArray): Boolean = session.contentEquals(candidate)

        internal fun headerEquals(candidate: ByteArray): Boolean = header.contentEquals(candidate)

        override fun equals(other: Any?): Boolean = other is BeginOffer &&
            session.contentEquals(other.session) && header.contentEquals(other.header)

        override fun hashCode(): Int = 31 * session.contentHashCode() + header.contentHashCode()

        override fun toString(): String = "BEGIN_OFFER"
    }

    /** WRITE_OFFER (`32`): `s ‖ w_o ‖ BE32 offset ‖` 1–4,096 bytes. */
    class WriteOffer(sessionId: ByteArray, offerWireHash: ByteArray, @JvmField val offset: Long, bytes: ByteArray) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(offerWireHash)
        private val chunk = nfcRequireChunk(offset, bytes)
        val sessionId: ByteArray get() = session.copyOf()
        val offerWireHash: ByteArray get() = hash.copyOf()
        val bytes: ByteArray get() = chunk.copyOf()
        val byteCount: Int get() = chunk.size
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.WRITE_OFFER

        internal fun sessionEquals(candidate: ByteArray): Boolean = session.contentEquals(candidate)

        internal fun hashEquals(candidate: ByteArray): Boolean = hash.contentEquals(candidate)

        internal fun chunkView(): ByteArray = chunk

        override fun equals(other: Any?): Boolean = other is WriteOffer && offset == other.offset &&
            session.contentEquals(other.session) && hash.contentEquals(other.hash) && chunk.contentEquals(other.chunk)

        override fun hashCode(): Int = (31 * hash.contentHashCode() + offset.hashCode()) * 31 + chunk.contentHashCode()

        override fun toString(): String = "WRITE_OFFER(offset=$offset, bytes=${chunk.size})"
    }

    /** SUBMIT_OFFER (`33`): `s ‖ w_o`. */
    class SubmitOffer(sessionId: ByteArray, offerWireHash: ByteArray) : IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(offerWireHash)
        val sessionId: ByteArray get() = session.copyOf()
        val offerWireHash: ByteArray get() = hash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.SUBMIT_OFFER

        internal fun sessionEquals(candidate: ByteArray): Boolean = session.contentEquals(candidate)

        internal fun hashEquals(candidate: ByteArray): Boolean = hash.contentEquals(candidate)

        override fun equals(other: Any?): Boolean = other is SubmitOffer &&
            session.contentEquals(other.session) && hash.contentEquals(other.hash)

        override fun hashCode(): Int = 31 * session.contentHashCode() + hash.contentHashCode()

        override fun toString(): String = "SUBMIT_OFFER"
    }

    /** GET_INFO (`10`), Le 98: the card's `INF1` record. */
    object GetInfo : IrohaPeerNfcCommandV1() {
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.GET_INFO

        override fun toString(): String = "GET_INFO"
    }

    /** READ_REQUEST (`11`): `s ‖ h_r ‖ BE32 offset`, Le 1–4,096. */
    class ReadRequest(sessionId: ByteArray, requestCanonicalHash: ByteArray, @JvmField val offset: Long, @JvmField val length: Int) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(requestCanonicalHash)

        init {
            nfcRequireChunkLimit(length)
            nfcRequireOffset(offset)
        }

        val sessionId: ByteArray get() = session.copyOf()
        val requestCanonicalHash: ByteArray get() = hash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.READ_REQUEST

        internal fun sessionView(): ByteArray = session

        internal fun hashView(): ByteArray = hash

        override fun equals(other: Any?): Boolean = other is ReadRequest && offset == other.offset &&
            length == other.length && session.contentEquals(other.session) && hash.contentEquals(other.hash)

        override fun hashCode(): Int = (31 * hash.contentHashCode() + offset.hashCode()) * 31 + length

        override fun toString(): String = "READ_REQUEST(offset=$offset, length=$length)"
    }

    /** BEGIN_PAYMENT (`20`): `s ‖ h_r ‖` Payment IPM1 header (84). */
    class BeginPayment(sessionId: ByteArray, requestCanonicalHash: ByteArray, paymentHeader: ByteArray) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(requestCanonicalHash)
        private val header = paymentHeader.copyOf().also { nfcInspectHeader(it, IrohaPeerPayloadKind.PAYMENT) }
        val sessionId: ByteArray get() = session.copyOf()
        val requestCanonicalHash: ByteArray get() = hash.copyOf()
        val paymentHeader: ByteArray get() = header.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.BEGIN_PAYMENT

        internal fun sessionView(): ByteArray = session

        internal fun hashView(): ByteArray = hash

        override fun equals(other: Any?): Boolean = other is BeginPayment && session.contentEquals(other.session) &&
            hash.contentEquals(other.hash) && header.contentEquals(other.header)

        override fun hashCode(): Int = 31 * hash.contentHashCode() + header.contentHashCode()

        override fun toString(): String = "BEGIN_PAYMENT"
    }

    /** WRITE (`21`): `s ‖ w_p ‖ BE32 offset ‖` 1–4,096 bytes. */
    class Write(sessionId: ByteArray, paymentWireHash: ByteArray, @JvmField val offset: Long, bytes: ByteArray) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(paymentWireHash)
        private val chunk = nfcRequireChunk(offset, bytes)
        val sessionId: ByteArray get() = session.copyOf()
        val paymentWireHash: ByteArray get() = hash.copyOf()
        val bytes: ByteArray get() = chunk.copyOf()
        val byteCount: Int get() = chunk.size
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.WRITE

        internal fun sessionView(): ByteArray = session

        internal fun hashView(): ByteArray = hash

        internal fun chunkView(): ByteArray = chunk

        override fun equals(other: Any?): Boolean = other is Write && offset == other.offset &&
            session.contentEquals(other.session) && hash.contentEquals(other.hash) && chunk.contentEquals(other.chunk)

        override fun hashCode(): Int = (31 * hash.contentHashCode() + offset.hashCode()) * 31 + chunk.contentHashCode()

        override fun toString(): String = "WRITE(offset=$offset, bytes=${chunk.size})"
    }

    /** COMMIT (`22`): `s ‖ h_r ‖ w_p`. */
    class Commit(sessionId: ByteArray, requestCanonicalHash: ByteArray, paymentWireHash: ByteArray) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val requestHash = nfcRequireHash(requestCanonicalHash)
        private val paymentHash = nfcRequireHash(paymentWireHash)
        val sessionId: ByteArray get() = session.copyOf()
        val requestCanonicalHash: ByteArray get() = requestHash.copyOf()
        val paymentWireHash: ByteArray get() = paymentHash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.COMMIT

        internal fun sessionView(): ByteArray = session

        internal fun requestHashView(): ByteArray = requestHash

        internal fun paymentHashView(): ByteArray = paymentHash

        override fun equals(other: Any?): Boolean = other is Commit && session.contentEquals(other.session) &&
            requestHash.contentEquals(other.requestHash) && paymentHash.contentEquals(other.paymentHash)

        override fun hashCode(): Int = 31 * requestHash.contentHashCode() + paymentHash.contentHashCode()

        override fun toString(): String = "COMMIT"
    }

    /** READ_ACK (`23`): `s ‖ w_p ‖ BE32 offset`, Le 1–4,096. */
    class ReadAcknowledgement(
        sessionId: ByteArray,
        paymentWireHash: ByteArray,
        @JvmField val offset: Long,
        @JvmField val length: Int,
    ) : IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(paymentWireHash)

        init {
            nfcRequireChunkLimit(length)
            nfcRequireOffset(offset)
        }

        val sessionId: ByteArray get() = session.copyOf()
        val paymentWireHash: ByteArray get() = hash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.READ_ACKNOWLEDGEMENT

        internal fun sessionView(): ByteArray = session

        internal fun hashView(): ByteArray = hash

        override fun equals(other: Any?): Boolean = other is ReadAcknowledgement && offset == other.offset &&
            length == other.length && session.contentEquals(other.session) && hash.contentEquals(other.hash)

        override fun hashCode(): Int = (31 * hash.contentHashCode() + offset.hashCode()) * 31 + length

        override fun toString(): String = "READ_ACK(offset=$offset, length=$length)"
    }

    /** CONFIRM_ACK (`24`): `s ‖ w_p ‖ w_a`. */
    class ConfirmAcknowledgement(sessionId: ByteArray, paymentWireHash: ByteArray, acknowledgementWireHash: ByteArray) :
        IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val paymentHash = nfcRequireHash(paymentWireHash)
        private val acknowledgementHash = nfcRequireHash(acknowledgementWireHash)
        val sessionId: ByteArray get() = session.copyOf()
        val paymentWireHash: ByteArray get() = paymentHash.copyOf()
        val acknowledgementWireHash: ByteArray get() = acknowledgementHash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.CONFIRM_ACKNOWLEDGEMENT

        internal fun sessionView(): ByteArray = session

        internal fun paymentHashView(): ByteArray = paymentHash

        internal fun acknowledgementHashView(): ByteArray = acknowledgementHash

        override fun equals(other: Any?): Boolean = other is ConfirmAcknowledgement &&
            session.contentEquals(other.session) && paymentHash.contentEquals(other.paymentHash) &&
            acknowledgementHash.contentEquals(other.acknowledgementHash)

        override fun hashCode(): Int = 31 * paymentHash.contentHashCode() + acknowledgementHash.contentHashCode()

        override fun toString(): String = "CONFIRM_ACK"
    }

    /** GET_STATUS (`25`): `s ‖ h_r`, Le 174: the card's `NST1` record. */
    class GetStatus(sessionId: ByteArray, requestCanonicalHash: ByteArray) : IrohaPeerNfcCommandV1() {
        private val session = nfcRequireSession(sessionId)
        private val hash = nfcRequireHash(requestCanonicalHash)
        val sessionId: ByteArray get() = session.copyOf()
        val requestCanonicalHash: ByteArray get() = hash.copyOf()
        override val operation: IrohaPeerNfcOperationV1 get() = IrohaPeerNfcOperationV1.GET_STATUS

        internal fun sessionView(): ByteArray = session

        internal fun hashView(): ByteArray = hash

        override fun equals(other: Any?): Boolean = other is GetStatus &&
            session.contentEquals(other.session) && hash.contentEquals(other.hash)

        override fun hashCode(): Int = 31 * session.contentHashCode() + hash.contentHashCode()

        override fun toString(): String = "GET_STATUS"
    }
}

/**
 * Strict ISO/IEC 7816-4 APDU codec. Commands use the short case whenever Lc ≤ 255 and Le ≤ 256
 * and the extended case otherwise; decoding rejects every other encoding of the same command, so
 * readers and cards on different NFC stacks never parse one APDU differently.
 */
object IrohaPeerNfcAPDUCodecV1 {
    @JvmStatic
    fun encode(command: IrohaPeerNfcCommandV1): ByteArray = when (command) {
        is IrohaPeerNfcCommandV1.SelectApplication -> encodeEnvelope(
            0x00, 0xa4, 0x04, 0x00, command.applicationIdentifier.bytes(), 256,
        )
        is IrohaPeerNfcCommandV1.GetIntake ->
            encodeProprietary(IrohaPeerNfcInstructionV1.GET_INTAKE, ByteArray(0), IrohaPeerNfcV1.INTAKE_BYTES)
        is IrohaPeerNfcCommandV1.BeginOffer ->
            encodeProprietary(IrohaPeerNfcInstructionV1.BEGIN_OFFER, command.sessionId + command.offerHeader)
        is IrohaPeerNfcCommandV1.WriteOffer -> encodeProprietary(
            IrohaPeerNfcInstructionV1.WRITE_OFFER,
            command.sessionId + command.offerWireHash + nfcU32Bytes(command.offset) + command.chunkView(),
        )
        is IrohaPeerNfcCommandV1.SubmitOffer ->
            encodeProprietary(IrohaPeerNfcInstructionV1.SUBMIT_OFFER, command.sessionId + command.offerWireHash)
        is IrohaPeerNfcCommandV1.GetInfo ->
            encodeProprietary(IrohaPeerNfcInstructionV1.GET_INFO, ByteArray(0), IrohaPeerNfcV1.INFO_BYTES)
        is IrohaPeerNfcCommandV1.ReadRequest -> encodeProprietary(
            IrohaPeerNfcInstructionV1.READ_REQUEST,
            command.sessionView() + command.hashView() + nfcU32Bytes(command.offset),
            command.length,
        )
        is IrohaPeerNfcCommandV1.BeginPayment -> encodeProprietary(
            IrohaPeerNfcInstructionV1.BEGIN_PAYMENT,
            command.sessionView() + command.hashView() + command.paymentHeader,
        )
        is IrohaPeerNfcCommandV1.Write -> encodeProprietary(
            IrohaPeerNfcInstructionV1.WRITE,
            command.sessionView() + command.hashView() + nfcU32Bytes(command.offset) + command.chunkView(),
        )
        is IrohaPeerNfcCommandV1.Commit -> encodeProprietary(
            IrohaPeerNfcInstructionV1.COMMIT,
            command.sessionView() + command.requestHashView() + command.paymentHashView(),
        )
        is IrohaPeerNfcCommandV1.ReadAcknowledgement -> encodeProprietary(
            IrohaPeerNfcInstructionV1.READ_ACKNOWLEDGEMENT,
            command.sessionView() + command.hashView() + nfcU32Bytes(command.offset),
            command.length,
        )
        is IrohaPeerNfcCommandV1.ConfirmAcknowledgement -> encodeProprietary(
            IrohaPeerNfcInstructionV1.CONFIRM_ACKNOWLEDGEMENT,
            command.sessionView() + command.paymentHashView() + command.acknowledgementHashView(),
        )
        is IrohaPeerNfcCommandV1.GetStatus -> encodeProprietary(
            IrohaPeerNfcInstructionV1.GET_STATUS,
            command.sessionView() + command.hashView(),
            IrohaPeerNfcV1.STATUS_BYTES,
        )
    }

    /**
     * Strictly decode one command APDU. A SELECT for any identifier other than
     * [applicationIdentifier], or in any form other than `00 A4 04 00 ‖ Lc ‖ AID ‖ 00`, fails with
     * [IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER] (`6A82`).
     */
    @JvmStatic
    fun decode(apdu: ByteArray, applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1): IrohaPeerNfcCommandV1 {
        val envelope = decodeEnvelope(apdu)
        if (envelope.cla == 0x00 && envelope.instruction == 0xa4) {
            if (envelope.p1 != 0x04 || envelope.p2 != 0x00 || !applicationIdentifier.matches(envelope.data) ||
                envelope.expectedResponseLength != 256
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
            }
            return IrohaPeerNfcCommandV1.SelectApplication(applicationIdentifier)
        }
        if (envelope.cla != IrohaPeerNfcV1.COMMAND_CLASS) {
            throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS, detail = envelope.cla)
        }
        if (envelope.p1 != 0 || envelope.p2 != 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
        val instruction = IrohaPeerNfcInstructionV1.fromCode(envelope.instruction)
            ?: throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION, detail = envelope.instruction)
        val data = envelope.data
        val le = envelope.expectedResponseLength
        return when (instruction) {
            IrohaPeerNfcInstructionV1.GET_INTAKE -> {
                if (data.isNotEmpty() || le != IrohaPeerNfcV1.INTAKE_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                IrohaPeerNfcCommandV1.GetIntake
            }
            IrohaPeerNfcInstructionV1.BEGIN_OFFER -> {
                if (le != null || data.size != SESSION + IrohaPeerWireMessageV1.HEADER_LENGTH) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                }
                IrohaPeerNfcCommandV1.BeginOffer(data.copyOfRange(0, SESSION), data.copyOfRange(SESSION, data.size))
            }
            IrohaPeerNfcInstructionV1.WRITE_OFFER -> {
                if (le != null || data.size <= CHUNK_PREFIX || data.size > CHUNK_PREFIX + IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                }
                IrohaPeerNfcCommandV1.WriteOffer(
                    data.copyOfRange(0, SESSION),
                    data.copyOfRange(SESSION, SESSION_HASH),
                    data.nfcU32(SESSION_HASH),
                    data.copyOfRange(CHUNK_PREFIX, data.size),
                )
            }
            IrohaPeerNfcInstructionV1.SUBMIT_OFFER -> {
                if (le != null || data.size != SESSION_HASH) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                IrohaPeerNfcCommandV1.SubmitOffer(data.copyOfRange(0, SESSION), data.copyOfRange(SESSION, SESSION_HASH))
            }
            IrohaPeerNfcInstructionV1.GET_INFO -> {
                if (data.isNotEmpty() || le != IrohaPeerNfcV1.INFO_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                IrohaPeerNfcCommandV1.GetInfo
            }
            IrohaPeerNfcInstructionV1.READ_REQUEST,
            IrohaPeerNfcInstructionV1.READ_ACKNOWLEDGEMENT,
            -> {
                if (data.size != CHUNK_PREFIX || le == null) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                val session = data.copyOfRange(0, SESSION)
                val hash = data.copyOfRange(SESSION, SESSION_HASH)
                val offset = data.nfcU32(SESSION_HASH)
                if (instruction == IrohaPeerNfcInstructionV1.READ_REQUEST) {
                    IrohaPeerNfcCommandV1.ReadRequest(session, hash, offset, le)
                } else {
                    IrohaPeerNfcCommandV1.ReadAcknowledgement(session, hash, offset, le)
                }
            }
            IrohaPeerNfcInstructionV1.BEGIN_PAYMENT -> {
                if (le != null || data.size != SESSION_HASH + IrohaPeerWireMessageV1.HEADER_LENGTH) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                }
                IrohaPeerNfcCommandV1.BeginPayment(
                    data.copyOfRange(0, SESSION),
                    data.copyOfRange(SESSION, SESSION_HASH),
                    data.copyOfRange(SESSION_HASH, data.size),
                )
            }
            IrohaPeerNfcInstructionV1.WRITE -> {
                if (le != null || data.size <= CHUNK_PREFIX || data.size > CHUNK_PREFIX + IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                }
                IrohaPeerNfcCommandV1.Write(
                    data.copyOfRange(0, SESSION),
                    data.copyOfRange(SESSION, SESSION_HASH),
                    data.nfcU32(SESSION_HASH),
                    data.copyOfRange(CHUNK_PREFIX, data.size),
                )
            }
            IrohaPeerNfcInstructionV1.COMMIT,
            IrohaPeerNfcInstructionV1.CONFIRM_ACKNOWLEDGEMENT,
            -> {
                if (le != null || data.size != SESSION_HASH + IrohaPeerNfcV1.HASH_BYTES) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                }
                val session = data.copyOfRange(0, SESSION)
                val first = data.copyOfRange(SESSION, SESSION_HASH)
                val second = data.copyOfRange(SESSION_HASH, data.size)
                if (instruction == IrohaPeerNfcInstructionV1.COMMIT) {
                    IrohaPeerNfcCommandV1.Commit(session, first, second)
                } else {
                    IrohaPeerNfcCommandV1.ConfirmAcknowledgement(session, first, second)
                }
            }
            IrohaPeerNfcInstructionV1.GET_STATUS -> {
                if (data.size != SESSION_HASH || le != IrohaPeerNfcV1.STATUS_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
                IrohaPeerNfcCommandV1.GetStatus(data.copyOfRange(0, SESSION), data.copyOfRange(SESSION, SESSION_HASH))
            }
        }
    }

    private const val SESSION = IrohaPeerNfcV1.SESSION_ID_BYTES
    private const val SESSION_HASH = IrohaPeerNfcV1.SESSION_ID_BYTES + IrohaPeerNfcV1.HASH_BYTES
    private const val CHUNK_PREFIX = SESSION_HASH + 4

    private class Envelope(
        val cla: Int,
        val instruction: Int,
        val p1: Int,
        val p2: Int,
        val data: ByteArray,
        val expectedResponseLength: Int?,
    )

    private fun encodeProprietary(
        instruction: IrohaPeerNfcInstructionV1,
        data: ByteArray,
        expectedResponseLength: Int? = null,
    ): ByteArray = encodeEnvelope(IrohaPeerNfcV1.COMMAND_CLASS, instruction.code, 0, 0, data, expectedResponseLength)

    private fun encodeEnvelope(
        cla: Int,
        instruction: Int,
        p1: Int,
        p2: Int,
        data: ByteArray,
        expectedResponseLength: Int?,
    ): ByteArray {
        if (data.size > 0xffff || (expectedResponseLength != null && expectedResponseLength !in 1..65_536)) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
        val output = NfcRecordWriter(9 + data.size)
        output.u8(cla)
        output.u8(instruction)
        output.u8(p1)
        output.u8(p2)
        if (data.isEmpty()) {
            if (expectedResponseLength == null) return output.finish()
            if (expectedResponseLength <= 256) {
                output.u8(if (expectedResponseLength == 256) 0 else expectedResponseLength)
            } else {
                output.u8(0)
                output.u16(if (expectedResponseLength == 65_536) 0 else expectedResponseLength)
            }
            return output.finish()
        }
        val extended = data.size > 0xff || (expectedResponseLength != null && expectedResponseLength > 256)
        if (extended) {
            output.u8(0)
            output.u16(data.size)
            output.bytes(data)
            if (expectedResponseLength != null) {
                output.u16(if (expectedResponseLength == 65_536) 0 else expectedResponseLength)
            }
        } else {
            output.u8(data.size)
            output.bytes(data)
            if (expectedResponseLength != null) {
                output.u8(if (expectedResponseLength == 256) 0 else expectedResponseLength)
            }
        }
        return output.finish()
    }

    private fun decodeEnvelope(apdu: ByteArray): Envelope {
        if (apdu.size < 4) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
        val cla = apdu.nfcU8(0)
        val instruction = apdu.nfcU8(1)
        val p1 = apdu.nfcU8(2)
        val p2 = apdu.nfcU8(3)
        if (apdu.size == 4) return Envelope(cla, instruction, p1, p2, ByteArray(0), null)
        val firstLength = apdu.nfcU8(4)
        if (firstLength != 0) {
            return when (apdu.size) {
                5 -> Envelope(cla, instruction, p1, p2, ByteArray(0), firstLength)
                5 + firstLength -> Envelope(cla, instruction, p1, p2, apdu.copyOfRange(5, apdu.size), null)
                6 + firstLength -> {
                    val rawLe = apdu.nfcU8(apdu.size - 1)
                    Envelope(cla, instruction, p1, p2, apdu.copyOfRange(5, 5 + firstLength), if (rawLe == 0) 256 else rawLe)
                }
                else -> nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            }
        }
        if (apdu.size == 5) return Envelope(cla, instruction, p1, p2, ByteArray(0), 256)
        if (apdu.size < 7) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
        val extendedLength = apdu.nfcU16(5)
        if (apdu.size == 7) {
            // Case 2E is canonical only when Case 2S cannot represent the response length.
            if (extendedLength != 0 && extendedLength <= 256) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            return Envelope(cla, instruction, p1, p2, ByteArray(0), if (extendedLength == 0) 65_536 else extendedLength)
        }
        if (extendedLength == 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
        if (apdu.size == 7 + extendedLength) {
            if (extendedLength <= 0xff) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            return Envelope(cla, instruction, p1, p2, apdu.copyOfRange(7, apdu.size), null)
        }
        if (apdu.size == 9 + extendedLength) {
            val rawLe = apdu.nfcU16(7 + extendedLength)
            val expectedResponseLength = if (rawLe == 0) 65_536 else rawLe
            if (extendedLength <= 0xff && expectedResponseLength <= 256) nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
            return Envelope(
                cla, instruction, p1, p2, apdu.copyOfRange(7, 7 + extendedLength), expectedResponseLength,
            )
        }
        nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
    }
}

/** A defensive copy of a 1–4,096-byte chunk at a BE32 offset. */
internal fun nfcRequireChunk(offset: Long, bytes: ByteArray): ByteArray {
    nfcRequireOffset(offset)
    if (bytes.isEmpty() || bytes.size > IrohaPeerNfcV1.MAXIMUM_CHUNK_BYTES) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    return bytes.copyOf()
}

internal fun nfcRequireOffset(offset: Long) {
    if (offset !in 0L..0xffff_ffffL) nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
}

internal fun nfcU32Bytes(value: Long): ByteArray = NfcRecordWriter(4).apply { u32(value) }.finish(4)
