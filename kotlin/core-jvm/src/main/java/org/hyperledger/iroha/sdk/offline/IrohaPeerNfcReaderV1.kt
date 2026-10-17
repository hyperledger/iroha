// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.IOException

/**
 * Sends one typed command and returns the card's response without hiding non-success status
 * words, so the reader can reconcile RF loss from GET_STATUS. A transport error whose response is
 * unknowable implements [IrohaPeerNfcAmbiguousResponseErrorV1].
 */
fun interface IrohaPeerNfcReaderTransceiverV1 {
    @Throws(IOException::class)
    fun transceive(command: IrohaPeerNfcCommandV1): IrohaPeerNfcAPDUResponseV1
}

/** Helpers for the Request-reading phase before a Payment checkpoint exists. */
object IrohaPeerNfcReaderPlanningV1 {
    @JvmStatic
    fun getStatusCommand(info: IrohaPeerNfcInfoV1): IrohaPeerNfcCommandV1.GetStatus =
        IrohaPeerNfcCommandV1.GetStatus(info.identity.sessionId, info.identity.requestCanonicalHash)

    /** READ_REQUEST at [offset] for min(local, peer) read chunk bytes. */
    @JvmStatic
    @JvmOverloads
    fun readRequestCommand(
        info: IrohaPeerNfcInfoV1,
        offset: Int,
        localLimits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ): IrohaPeerNfcCommandV1.ReadRequest {
        if (info.requestLength > localLimits.maximumMessageBytes) {
            nfcMessageTooLarge(info.requestLength, localLimits.maximumMessageBytes)
        }
        if (offset < 0 || offset >= info.requestLength) nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
        return IrohaPeerNfcCommandV1.ReadRequest(
            info.identity.sessionId,
            info.identity.requestCanonicalHash,
            offset.toLong(),
            minOf(localLimits.maximumReadChunkBytes, info.maximumReadChunkBytes, info.requestLength - offset),
        )
    }

    /** The complete Request read under [info]: its length, profile, kind and both hashes. */
    @JvmStatic
    @JvmOverloads
    fun validateReceiveRequest(
        data: ByteArray,
        info: IrohaPeerNfcInfoV1,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ): IrohaPeerWireMessageV1 {
        if (data.size != info.requestLength || data.size > limits.maximumMessageBytes) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
        val message = nfcDecodeMessage(data, info.identity.profile, IrohaPeerPayloadKind.REQUEST, limits)
        if (!info.identity.canonicalEquals(message.canonicalHash) ||
            !info.identity.requestWireHash.contentEquals(message.wireHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
        }
        return message
    }
}

/**
 * Sender state (`ISC1`) that must be durable before the first Payment byte is written. Restoring
 * the encoded checkpoint reuses the exact IPM1 Payment and can never create or debit a
 * replacement Payment. The payer builds it from the Request read
 * ([IrohaPeerNfcRequestReadV1.senderCheckpoint]) and the approved Payment, persists [encode] and
 * continues on the same connection with it ([IrohaPeerNfcReaderExchangeV1.run]).
 */
class IrohaPeerNfcSenderCheckpointV1 @JvmOverloads constructor(
    sessionId: ByteArray,
    receiveRequest: ByteArray,
    payment: ByteArray,
    durableAcknowledgement: ByteArray? = null,
    profilePolicy: IrohaPeerNfcProfilePolicyV1? = null,
    limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    private val session: ByteArray = nfcRequireSession(sessionId)

    @JvmField val receiveRequest: IrohaPeerWireMessageV1 =
        nfcDecodeMessage(receiveRequest, null, IrohaPeerPayloadKind.REQUEST, limits)

    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1 =
        (profilePolicy ?: IrohaPeerNfcProfilePolicyV1(this.receiveRequest.nfcProfile)).also {
            if (it.profile != this.receiveRequest.nfcProfile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }

    @JvmField val payment: IrohaPeerWireMessageV1 =
        nfcDecodeMessage(payment, null, IrohaPeerPayloadKind.PAYMENT, limits).also {
            if (!this.profilePolicy.accepts(it.nfcProfile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }

    /** The receiver's Credited acknowledgement, once it was persisted with this checkpoint. */
    @JvmField val durableAcknowledgement: IrohaPeerWireMessageV1? = durableAcknowledgement?.let { bytes ->
        nfcDecodeMessage(bytes, null, IrohaPeerPayloadKind.CREDITED, limits).also {
            if (!this.profilePolicy.accepts(it.nfcProfile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }
    }

    init {
        nfcRequireWalletExchange(this.receiveRequest, this.payment, this.durableAcknowledgement)
    }

    @JvmField val identity: IrohaPeerNfcRequestIdentityV1 = IrohaPeerNfcRequestIdentityV1(
        this.receiveRequest.nfcProfile,
        session,
        this.receiveRequest.canonicalHash,
        this.receiveRequest.wireHash,
    )

    internal val requestBytes: ByteArray = this.receiveRequest.encode()
    internal val paymentBytes: ByteArray = this.payment.encode()
    internal val acknowledgementBytes: ByteArray? = this.durableAcknowledgement?.encode()

    fun encode(): ByteArray {
        val acknowledgement = acknowledgementBytes ?: ByteArray(0)
        val size = FIXED_BYTES + requestBytes.size + paymentBytes.size + acknowledgement.size
        return NfcRecordWriter(size).apply {
            bytes(IrohaPeerNfcV1.SENDER_CHECKPOINT_MAGIC)
            u8(IrohaPeerNfcV1.WIRE_VERSION)
            u16(identity.profile.code)
            u8(0)
            bytes(session)
            u32(requestBytes.size.toLong())
            u32(paymentBytes.size.toLong())
            u32(acknowledgement.size.toLong())
            bytes(requestBytes)
            bytes(paymentBytes)
            bytes(acknowledgement)
        }.finish(size)
    }

    internal fun addingDurableAcknowledgement(
        acknowledgement: ByteArray,
        limits: IrohaPeerNfcLimitsV1,
    ): IrohaPeerNfcSenderCheckpointV1 =
        IrohaPeerNfcSenderCheckpointV1(session, requestBytes, paymentBytes, acknowledgement, profilePolicy, limits)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcSenderCheckpointV1 &&
        identity == other.identity && profilePolicy == other.profilePolicy &&
        receiveRequest == other.receiveRequest && payment == other.payment &&
        durableAcknowledgement == other.durableAcknowledgement

    override fun hashCode(): Int = (31 * identity.hashCode() + payment.hashCode()) * 31 +
        (durableAcknowledgement?.hashCode() ?: 0)

    override fun toString(): String = "IrohaPeerNfcSenderCheckpointV1(payment=${paymentBytes.size} bytes, " +
        "acknowledgement=${acknowledgementBytes?.size ?: 0} bytes)"

    companion object {
        private const val FIXED_BYTES = 36

        @JvmStatic
        @JvmOverloads
        fun decode(
            data: ByteArray,
            profilePolicy: IrohaPeerNfcProfilePolicyV1? = null,
            limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
        ): IrohaPeerNfcSenderCheckpointV1 {
            if (data.size <= FIXED_BYTES || !nfcHasMagic(data, IrohaPeerNfcV1.SENDER_CHECKPOINT_MAGIC) ||
                data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION || data.nfcU8(7) != 0
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(5)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            val requestLength = data.nfcU32(24)
            val paymentLength = data.nfcU32(28)
            val acknowledgementLength = data.nfcU32(32)
            val header = IrohaPeerWireMessageV1.HEADER_LENGTH.toLong()
            val maximum = limits.maximumMessageBytes.toLong()
            if (requestLength <= header || paymentLength <= header ||
                (acknowledgementLength != 0L && acknowledgementLength <= header) ||
                requestLength > maximum || paymentLength > maximum || acknowledgementLength > maximum ||
                FIXED_BYTES + requestLength + paymentLength + acknowledgementLength != data.size.toLong()
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val requestStart = FIXED_BYTES
            val paymentStart = requestStart + requestLength.toInt()
            val acknowledgementStart = paymentStart + paymentLength.toInt()
            val checkpoint = IrohaPeerNfcSenderCheckpointV1(
                data.copyOfRange(8, 24),
                data.copyOfRange(requestStart, paymentStart),
                data.copyOfRange(paymentStart, acknowledgementStart),
                if (acknowledgementLength == 0L) null else data.copyOfRange(acknowledgementStart, data.size),
                profilePolicy,
                limits,
            )
            if (checkpoint.identity.profile != profile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
            return checkpoint
        }
    }
}

/** One deterministic next step of a status-reconciled sender. */
sealed class IrohaPeerNfcSenderActionV1 {
    class Send(@JvmField val command: IrohaPeerNfcCommandV1) : IrohaPeerNfcSenderActionV1() {
        override fun equals(other: Any?): Boolean = other is Send && command == other.command

        override fun hashCode(): Int = command.hashCode()

        override fun toString(): String = "Send($command)"
    }

    /** Persist the complete, validated acknowledgement via [IrohaPeerNfcTwoTapReducerV1.persistAcknowledgement]. */
    class PersistAcknowledgement(acknowledgement: ByteArray) : IrohaPeerNfcSenderActionV1() {
        private val bytes = acknowledgement.copyOf()
        val acknowledgement: ByteArray get() = bytes.copyOf()

        override fun equals(other: Any?): Boolean = other is PersistAcknowledgement && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /** The card is complete and this exact acknowledgement was already durable locally. */
    class Complete(acknowledgement: ByteArray) : IrohaPeerNfcSenderActionV1() {
        private val bytes = acknowledgement.copyOf()
        val acknowledgement: ByteArray get() = bytes.copyOf()

        override fun equals(other: Any?): Boolean = other is Complete && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }
}

/**
 * Status-driven sender reducer designed for RF loss between any two APDUs. On reconnect, read
 * GET_INFO, require the same identity ([requireSamePeer]), then pass each GET_STATUS here. The
 * card's progress is authoritative; the exact durable checkpoint supplies bytes for replay without
 * creating a new debit.
 */
class IrohaPeerNfcTwoTapReducerV1 @JvmOverloads constructor(
    checkpoint: IrohaPeerNfcSenderCheckpointV1,
    @JvmField val limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    /** Persists a complete checkpoint (`ISC1` bytes). */
    fun interface AcknowledgementPersistenceHandler {
        fun persist(checkpoint: ByteArray)
    }

    var checkpoint: IrohaPeerNfcSenderCheckpointV1 = checkpoint
        private set

    private var acknowledgementBuffer: ByteArray = ByteArray(0)
    private var acknowledgementReceived = 0
    private var expectedAcknowledgementLength: Int? = null
    private var expectedAcknowledgementHash: ByteArray? = null

    fun requireSamePeer(info: IrohaPeerNfcInfoV1) {
        if (info.identity != checkpoint.identity || info.requestLength != checkpoint.requestBytes.size) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
    }

    fun nextAction(status: IrohaPeerNfcStatusV1): IrohaPeerNfcSenderActionV1 {
        if (status.identity != checkpoint.identity) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        val payment = checkpoint.payment
        val paymentBytes = checkpoint.paymentBytes
        val session = checkpoint.identity.sessionId
        return when (status.phase) {
            IrohaPeerNfcPhaseV1.REQUEST_READY -> {
                if (checkpoint.durableAcknowledgement != null) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                resetAcknowledgementBuffer()
                IrohaPeerNfcSenderActionV1.Send(
                    IrohaPeerNfcCommandV1.BeginPayment(
                        session,
                        checkpoint.identity.requestCanonicalHash,
                        paymentBytes.copyOfRange(0, IrohaPeerWireMessageV1.HEADER_LENGTH),
                    ),
                )
            }
            IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING -> {
                if (checkpoint.durableAcknowledgement != null || status.paymentProfile != payment.nfcProfile ||
                    status.paymentLength != paymentBytes.size || !status.paymentHashEquals(payment.wireHash)
                ) {
                    nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                }
                resetAcknowledgementBuffer()
                if (status.receivedPaymentBytes < status.paymentLength) {
                    val offset = status.receivedPaymentBytes
                    val count = minOf(
                        limits.maximumWriteChunkBytes,
                        status.maximumWriteChunkBytes,
                        status.paymentLength - offset,
                    )
                    IrohaPeerNfcSenderActionV1.Send(
                        IrohaPeerNfcCommandV1.Write(
                            session,
                            payment.wireHash,
                            offset.toLong(),
                            paymentBytes.copyOfRange(offset, offset + count),
                        ),
                    )
                } else {
                    IrohaPeerNfcSenderActionV1.Send(
                        IrohaPeerNfcCommandV1.Commit(session, checkpoint.identity.requestCanonicalHash, payment.wireHash),
                    )
                }
            }
            IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY -> {
                requirePaymentAndAcknowledgementMetadata(status)
                val durable = checkpoint.durableAcknowledgement
                if (durable != null) {
                    if (status.acknowledgementProfile != durable.nfcProfile ||
                        checkpoint.acknowledgementBytes?.size != status.acknowledgementLength ||
                        !status.acknowledgementHashEquals(durable.wireHash)
                    ) {
                        nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                    }
                    return IrohaPeerNfcSenderActionV1.Send(
                        IrohaPeerNfcCommandV1.ConfirmAcknowledgement(session, payment.wireHash, durable.wireHash),
                    )
                }
                configureAcknowledgementBuffer(status)
                if (acknowledgementReceived == status.acknowledgementLength) {
                    return IrohaPeerNfcSenderActionV1.PersistAcknowledgement(
                        acknowledgementBuffer.copyOf(acknowledgementReceived),
                    )
                }
                val offset = acknowledgementReceived
                val count = minOf(
                    limits.maximumReadChunkBytes,
                    status.maximumReadChunkBytes,
                    status.acknowledgementLength - offset,
                )
                IrohaPeerNfcSenderActionV1.Send(
                    IrohaPeerNfcCommandV1.ReadAcknowledgement(session, payment.wireHash, offset.toLong(), count),
                )
            }
            IrohaPeerNfcPhaseV1.COMPLETE -> {
                requirePaymentAndAcknowledgementMetadata(status)
                val durable = checkpoint.durableAcknowledgement
                val durableBytes = checkpoint.acknowledgementBytes
                if (durable == null || durableBytes == null || status.acknowledgementProfile != durable.nfcProfile ||
                    durableBytes.size != status.acknowledgementLength ||
                    !status.acknowledgementHashEquals(durable.wireHash)
                ) {
                    nfcFail(IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE)
                }
                IrohaPeerNfcSenderActionV1.Complete(durableBytes)
            }
        }
    }

    /**
     * Supplies the response to the last READ_ACK action and returns whether the acknowledgement is
     * complete. Partial acknowledgement bytes are restartable, never durable state.
     */
    fun consumeAcknowledgementChunk(bytes: ByteArray): Boolean {
        val expectedLength = expectedAcknowledgementLength
        val expectedHash = expectedAcknowledgementHash
        if (expectedLength == null || expectedHash == null || bytes.isEmpty() ||
            bytes.size > limits.maximumReadChunkBytes || acknowledgementReceived >= expectedLength ||
            bytes.size > expectedLength - acknowledgementReceived
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
        bytes.copyInto(acknowledgementBuffer, acknowledgementReceived)
        acknowledgementReceived += bytes.size
        if (acknowledgementReceived != expectedLength) return false
        val acknowledgement = nfcDecodeMessage(acknowledgementBuffer, null, IrohaPeerPayloadKind.CREDITED, limits)
        if (!checkpoint.profilePolicy.accepts(acknowledgement.nfcProfile) ||
            !acknowledgement.wireHash.contentEquals(expectedHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
        }
        nfcRequireWalletExchange(checkpoint.receiveRequest, checkpoint.payment, acknowledgement)
        return true
    }

    /**
     * Persists the full sender checkpoint including the acknowledgement before CONFIRM_ACK may be
     * sent. If persistence throws, the reducer stays acknowledgement-pending.
     */
    fun persistAcknowledgement(persist: AcknowledgementPersistenceHandler) {
        val candidate = acknowledgementCheckpointCandidate()
        persist.persist(candidate.encode())
        installPersistedCheckpoint(candidate)
    }

    /** The exact checkpoint that includes the complete validated acknowledgement. */
    fun acknowledgementCheckpointCandidate(): IrohaPeerNfcSenderCheckpointV1 {
        val expectedLength = expectedAcknowledgementLength
        val expectedHash = expectedAcknowledgementHash
        if (expectedLength == null || expectedHash == null || acknowledgementReceived != expectedLength) {
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        val candidate = checkpoint.addingDurableAcknowledgement(acknowledgementBuffer.copyOf(acknowledgementReceived), limits)
        if (candidate.durableAcknowledgement?.wireHash?.contentEquals(expectedHash) != true) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
        }
        return candidate
    }

    /**
     * Installs only the byte-identical checkpoint previously returned by
     * [acknowledgementCheckpointCandidate], after it was persisted.
     */
    fun installPersistedCheckpoint(candidate: IrohaPeerNfcSenderCheckpointV1) {
        if (candidate != acknowledgementCheckpointCandidate()) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        checkpoint = candidate
        resetAcknowledgementBuffer()
    }

    private fun requirePaymentAndAcknowledgementMetadata(status: IrohaPeerNfcStatusV1) {
        val acknowledgementProfile = status.acknowledgementProfile
        if (acknowledgementProfile == null || !checkpoint.profilePolicy.accepts(acknowledgementProfile) ||
            status.paymentLength != checkpoint.paymentBytes.size ||
            status.paymentProfile != checkpoint.payment.nfcProfile ||
            !status.paymentHashEquals(checkpoint.payment.wireHash) ||
            status.acknowledgementLength <= IrohaPeerWireMessageV1.HEADER_LENGTH ||
            status.acknowledgementLength > limits.maximumMessageBytes
        ) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
    }

    private fun configureAcknowledgementBuffer(status: IrohaPeerNfcStatusV1) {
        val expectedHash = expectedAcknowledgementHash
        if (expectedAcknowledgementLength != status.acknowledgementLength || expectedHash == null ||
            !status.acknowledgementHashEquals(expectedHash)
        ) {
            acknowledgementBuffer = ByteArray(status.acknowledgementLength)
            acknowledgementReceived = 0
            expectedAcknowledgementLength = status.acknowledgementLength
            expectedAcknowledgementHash = status.acknowledgementWireHash
        }
    }

    private fun resetAcknowledgementBuffer() {
        acknowledgementBuffer = ByteArray(0)
        acknowledgementReceived = 0
        expectedAcknowledgementLength = null
        expectedAcknowledgementHash = null
    }
}

/** Whether the final CONFIRM_ACK response was observed. */
enum class IrohaPeerNfcConfirmationStateV1 {
    CONFIRMED,

    /**
     * The CONFIRM_ACK response was lost after the acknowledgement was durable on both wallets;
     * the exchange is financially complete.
     */
    RESPONSE_UNKNOWN,
}

/**
 * Complete sender-side result. [checkpoint] contains the durable acknowledgement and is safe to
 * reload if the final CONFIRM_ACK response was lost.
 */
class IrohaPeerNfcReaderExchangeResultV1 @JvmOverloads constructor(
    @JvmField val checkpoint: IrohaPeerNfcSenderCheckpointV1,
    @JvmField val acknowledgement: IrohaPeerWireMessageV1,
    @JvmField val confirmationState: IrohaPeerNfcConfirmationStateV1 = IrohaPeerNfcConfirmationStateV1.CONFIRMED,
) {
    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcReaderExchangeResultV1 &&
        checkpoint == other.checkpoint && acknowledgement == other.acknowledgement &&
        confirmationState == other.confirmationState

    override fun hashCode(): Int = (31 * checkpoint.hashCode() + acknowledgement.hashCode()) * 31 +
        confirmationState.hashCode()

    override fun toString(): String = "IrohaPeerNfcReaderExchangeResultV1(${confirmationState.name})"
}

/**
 * Transport-neutral, status-reconciled Payment phase, the Swift
 * `IrohaPeerNfcReaderExchangeV1`. Blocking; Android reader mode runs it on its binder thread.
 *
 * With [run]'s `restoredCheckpoint` (the `ISC1` the payer persisted after approving the Payment,
 * or after an interrupted exchange) the reader resumes from the card's GET_STATUS and replays the
 * exact Payment. Without it, the card must be REQUEST_READY: the reader reads the Request and
 * `loadOrCreateDurableCheckpoint` is the sole fresh-value boundary, which atomically returns an
 * already-durable exact checkpoint before the first BEGIN_PAYMENT. `updateDurableCheckpoint`
 * persists the later acknowledgement-bearing checkpoint before CONFIRM_ACK is sent.
 */
object IrohaPeerNfcReaderExchangeV1 {
    /** Load the request-bound checkpoint or atomically create and persist it. */
    fun interface LoadOrCreateDurableCheckpoint {
        fun loadOrCreate(info: IrohaPeerNfcInfoV1, request: IrohaPeerWireMessageV1): IrohaPeerNfcSenderCheckpointV1
    }

    /** Durably replace the stored checkpoint with these `ISC1` bytes. */
    fun interface UpdateDurableCheckpoint {
        fun update(checkpoint: ByteArray)
    }

    /**
     * Covers three protocol-maximum messages at the minimum one-byte chunk, plus SELECT/INFO,
     * phase probes, controls and durable transitions.
     */
    const val DEFAULT_MAXIMUM_ACTIONS = 3 * IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES + 16

    private class ActionBudget(var remaining: Int) {
        fun consume() {
            if (remaining <= 0) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            remaining -= 1
        }
    }

    @JvmStatic
    @JvmOverloads
    fun run(
        restoredCheckpoint: ByteArray?,
        applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
        maximumActions: Int = DEFAULT_MAXIMUM_ACTIONS,
        transceive: IrohaPeerNfcReaderTransceiverV1,
        loadOrCreateDurableCheckpoint: LoadOrCreateDurableCheckpoint,
        updateDurableCheckpoint: UpdateDurableCheckpoint,
    ): IrohaPeerNfcReaderExchangeResultV1 {
        require(maximumActions > 0) { "NFC reader action budget must be positive" }
        val budget = ActionBudget(maximumActions)

        budget.consume()
        nfcRequireEmptySuccess(
            transceive.transceive(IrohaPeerNfcCommandV1.SelectApplication(applicationIdentifier)),
            IrohaPeerNfcOperationV1.SELECT_APPLICATION,
        )
        budget.consume()
        val info = IrohaPeerNfcInfoV1.decode(
            nfcRequireSuccess(transceive.transceive(IrohaPeerNfcCommandV1.GetInfo), IrohaPeerNfcOperationV1.GET_INFO).data(),
        )
        if (info.identity.profile != profilePolicy.profile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        if (info.requestLength > limits.maximumMessageBytes) {
            nfcMessageTooLarge(info.requestLength, limits.maximumMessageBytes)
        }
        // Only a newly advertised Request may authorize value creation. Other phases belong to an
        // already-started exchange and require its exact durable checkpoint to resume without a
        // second debit.
        if (restoredCheckpoint == null && info.phase != IrohaPeerNfcPhaseV1.REQUEST_READY) {
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }

        val checkpoint = if (restoredCheckpoint != null) {
            IrohaPeerNfcSenderCheckpointV1.decode(restoredCheckpoint, profilePolicy, limits).also {
                IrohaPeerNfcTwoTapReducerV1(it, limits).requireSamePeer(info)
            }
        } else {
            val request = readRequest(info, limits, budget, transceive)
            // Loading or atomically creating the mandatory pre-BEGIN_PAYMENT checkpoint is one
            // application transition. Charge it before invoking application code, so a hostile
            // one-byte peer cannot exhaust the budget only after value has been created.
            budget.consume()
            loadOrCreateDurableCheckpoint.loadOrCreate(info, request).also {
                if (it.profilePolicy != profilePolicy || it.receiveRequest != request) {
                    nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                }
                IrohaPeerNfcTwoTapReducerV1(it, limits).requireSamePeer(info)
            }
        }

        val reducer = IrohaPeerNfcTwoTapReducerV1(checkpoint, limits)
        while (true) {
            val statusCommand = IrohaPeerNfcReaderPlanningV1.getStatusCommand(info)
            budget.consume()
            val status = IrohaPeerNfcStatusV1.decode(
                nfcRequireSuccess(transceive.transceive(statusCommand), statusCommand.operation).data(),
            )
            val action = reducer.nextAction(status)
            budget.consume()
            when (action) {
                is IrohaPeerNfcSenderActionV1.Send -> {
                    val command = action.command
                    val rawResponse = try {
                        transceive.transceive(command)
                    } catch (failure: Exception) {
                        val acknowledgement = reducer.checkpoint.durableAcknowledgement
                        if (failure is IrohaPeerNfcAmbiguousResponseErrorV1 &&
                            command is IrohaPeerNfcCommandV1.ConfirmAcknowledgement && acknowledgement != null
                        ) {
                            // The Payment and its acknowledgement are already durable on both
                            // wallets. CONFIRM_ACK is cleanup only; its response is ambiguous.
                            return IrohaPeerNfcReaderExchangeResultV1(
                                reducer.checkpoint,
                                acknowledgement,
                                IrohaPeerNfcConfirmationStateV1.RESPONSE_UNKNOWN,
                            )
                        }
                        throw failure
                    }
                    val response = nfcRequireSuccess(rawResponse, command.operation)
                    if (command !is IrohaPeerNfcCommandV1.ReadAcknowledgement && response.dataLength != 0) {
                        nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
                    }
                    when (command) {
                        is IrohaPeerNfcCommandV1.Write -> {
                            streamPaymentAndCommit(command, reducer, status, limits, budget, transceive)
                        }
                        is IrohaPeerNfcCommandV1.ReadAcknowledgement -> {
                            if (response.dataLength > command.length) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
                            reducer.consumeAcknowledgementChunk(response.data())
                            val result = streamAcknowledgementAndConfirm(
                                reducer, status, limits, budget, transceive, updateDurableCheckpoint,
                            )
                            return result
                        }
                        is IrohaPeerNfcCommandV1.ConfirmAcknowledgement -> {
                            val acknowledgement = reducer.checkpoint.durableAcknowledgement
                                ?: nfcFail(IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE)
                            return IrohaPeerNfcReaderExchangeResultV1(reducer.checkpoint, acknowledgement)
                        }
                        else -> {
                            // BEGIN_PAYMENT and COMMIT are phase boundaries. Re-enter through
                            // GET_STATUS so the card stays authoritative before the next phase.
                        }
                    }
                }
                is IrohaPeerNfcSenderActionV1.PersistAcknowledgement -> {
                    val candidate = reducer.acknowledgementCheckpointCandidate()
                    updateDurableCheckpoint.update(candidate.encode())
                    reducer.installPersistedCheckpoint(candidate)
                }
                is IrohaPeerNfcSenderActionV1.Complete -> {
                    val acknowledgement = reducer.checkpoint.durableAcknowledgement
                        ?: nfcFail(IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE)
                    return IrohaPeerNfcReaderExchangeResultV1(reducer.checkpoint, acknowledgement)
                }
            }
        }
    }

    private fun readRequest(
        info: IrohaPeerNfcInfoV1,
        limits: IrohaPeerNfcLimitsV1,
        budget: ActionBudget,
        transceive: IrohaPeerNfcReaderTransceiverV1,
    ): IrohaPeerWireMessageV1 = IrohaPeerNfcReaderPlanningV1.validateReceiveRequest(
        nfcReadRequestBytes(info, limits, transceive) { budget.consume() },
        info,
        limits,
    )

    /**
     * A successful WRITE proves that exact contiguous range was accepted: continue from the next
     * local offset without a status round trip, then COMMIT once every byte has a successful
     * response. Any later loss throws; the next run resumes from GET_STATUS.
     */
    private fun streamPaymentAndCommit(
        first: IrohaPeerNfcCommandV1.Write,
        reducer: IrohaPeerNfcTwoTapReducerV1,
        status: IrohaPeerNfcStatusV1,
        limits: IrohaPeerNfcLimitsV1,
        budget: ActionBudget,
        transceive: IrohaPeerNfcReaderTransceiverV1,
    ) {
        val checkpoint = reducer.checkpoint
        val paymentBytes = checkpoint.paymentBytes
        val paymentHash = checkpoint.payment.wireHash
        val session = checkpoint.identity.sessionId
        if (first.offset > paymentBytes.size || first.byteCount > paymentBytes.size - first.offset) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
        }
        var offset = first.offset.toInt() + first.byteCount
        while (offset < paymentBytes.size) {
            val count = minOf(limits.maximumWriteChunkBytes, status.maximumWriteChunkBytes, paymentBytes.size - offset)
            if (count <= 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
            val next = IrohaPeerNfcCommandV1.Write(
                session,
                paymentHash,
                offset.toLong(),
                paymentBytes.copyOfRange(offset, offset + count),
            )
            budget.consume()
            nfcRequireEmptySuccess(transceive.transceive(next), next.operation)
            offset += count
        }
        budget.consume()
        val commit = IrohaPeerNfcCommandV1.Commit(session, checkpoint.identity.requestCanonicalHash, paymentHash)
        nfcRequireEmptySuccess(transceive.transceive(commit), commit.operation)
    }

    private fun streamAcknowledgementAndConfirm(
        reducer: IrohaPeerNfcTwoTapReducerV1,
        status: IrohaPeerNfcStatusV1,
        limits: IrohaPeerNfcLimitsV1,
        budget: ActionBudget,
        transceive: IrohaPeerNfcReaderTransceiverV1,
        updateDurableCheckpoint: UpdateDurableCheckpoint,
    ): IrohaPeerNfcReaderExchangeResultV1 {
        var action = reducer.nextAction(status)
        while (true) {
            budget.consume()
            when (action) {
                is IrohaPeerNfcSenderActionV1.Send -> when (val command = action.command) {
                    is IrohaPeerNfcCommandV1.ReadAcknowledgement -> {
                        val response = nfcRequireSuccess(transceive.transceive(command), command.operation)
                        if (response.dataLength > command.length) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
                        reducer.consumeAcknowledgementChunk(response.data())
                    }
                    is IrohaPeerNfcCommandV1.ConfirmAcknowledgement -> {
                        // The acknowledgement-bearing checkpoint was persisted and installed before
                        // this command was produced; a lost response is recovered from COMPLETE.
                        val acknowledgement = reducer.checkpoint.durableAcknowledgement
                            ?: nfcFail(IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE)
                        val confirmResponse = try {
                            transceive.transceive(command)
                        } catch (failure: Exception) {
                            if (failure is IrohaPeerNfcAmbiguousResponseErrorV1) {
                                return IrohaPeerNfcReaderExchangeResultV1(
                                    reducer.checkpoint,
                                    acknowledgement,
                                    IrohaPeerNfcConfirmationStateV1.RESPONSE_UNKNOWN,
                                )
                            }
                            throw failure
                        }
                        nfcRequireEmptySuccess(confirmResponse, command.operation)
                        return IrohaPeerNfcReaderExchangeResultV1(reducer.checkpoint, acknowledgement)
                    }
                    else -> nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
                }
                is IrohaPeerNfcSenderActionV1.PersistAcknowledgement -> {
                    val candidate = reducer.acknowledgementCheckpointCandidate()
                    updateDurableCheckpoint.update(candidate.encode())
                    reducer.installPersistedCheckpoint(candidate)
                }
                is IrohaPeerNfcSenderActionV1.Complete -> nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            }
            action = reducer.nextAction(status)
        }
    }
}

/**
 * Offer phase result: the card's final `IOI1` [intake], its `INF1` [info] and the verified [request] it
 * hosts under the intake's session identifier.
 */
class IrohaPeerNfcRequestReadV1(
    @JvmField val intake: IrohaPeerNfcIntakeRecordV1,
    @JvmField val info: IrohaPeerNfcInfoV1,
    @JvmField val request: IrohaPeerWireMessageV1,
) {
    init {
        if (!intake.sessionEquals(info.identity.sessionId)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        if (!info.identity.canonicalEquals(request.canonicalHash) ||
            !info.identity.requestWireHash.contentEquals(request.wireHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
        }
    }

    /**
     * The sender checkpoint for the approved [payment] (complete Payment IPM1 bytes) of this
     * Request. Persist its [IrohaPeerNfcSenderCheckpointV1.encode] before sending any Payment byte.
     */
    @JvmOverloads
    fun senderCheckpoint(
        payment: ByteArray,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ): IrohaPeerNfcSenderCheckpointV1 = IrohaPeerNfcSenderCheckpointV1(
        info.identity.sessionId,
        request.encode(),
        payment,
        null,
        IrohaPeerNfcProfilePolicyV1(info.identity.profile),
        limits,
    )

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcRequestReadV1 && intake == other.intake &&
        info == other.info && request == other.request

    override fun hashCode(): Int = (31 * intake.hashCode() + info.hashCode()) * 31 + request.hashCode()

    override fun toString(): String = "IrohaPeerNfcRequestReadV1(request=${request.byteCount} bytes)"
}

/**
 * Offer phase: carries the payer's Offer to the card and reads back the receiver's Request.
 * Keep the transceiver connected during approval, then run [IrohaPeerNfcReaderExchangeV1] on it
 * with the durable checkpoint to finish the payment in the same hold.
 *
 * SELECT, then GET_INTAKE. Awaiting an Offer, or receiving another Offer, the reader sends
 * BEGIN_OFFER; receiving this Offer, it resumes at the received offset. It writes contiguous chunks
 * of min(local, card) write bytes and submits, then polls GET_INTAKE until REQUEST_READY (this
 * Offer, or a direct-mode Request with zero Offer fields) or DECLINED
 * ([IrohaPeerNfcErrorV1.OFFER_DECLINED]). A card bound to another Offer is a continuity mismatch.
 * Finally it reads `INF1` (REQUEST_READY, the intake's session identifier) and the Request, checked
 * against `INF1` exactly as [IrohaPeerNfcReaderPlanningV1.validateReceiveRequest] does.
 * Blocking; Android reader mode runs it on its binder thread.
 */
object IrohaPeerNfcOfferExchangeV1 {
    /** Waits between GET_INTAKE polls while the card prepares the Request. */
    fun interface Sleeper {
        @Throws(InterruptedException::class)
        fun sleep(millis: Long)
    }

    const val DEFAULT_PREPARATION_TIMEOUT_MILLIS = 8_000L
    const val DEFAULT_POLL_INTERVAL_MILLIS = 50L

    /** Sleeps on the calling thread. */
    @JvmField val THREAD_SLEEPER: Sleeper = Sleeper { millis -> Thread.sleep(millis) }

    /**
     * [preparationTimeoutMillis] bounds the total [pollIntervalMillis] waits spent polling a card
     * that is preparing the Request; the reader then fails with
     * [IrohaPeerNfcErrorV1.REQUEST_PREPARATION_TIMED_OUT].
     */
    @JvmStatic
    @JvmOverloads
    fun run(
        offer: IrohaPeerWireMessageV1,
        applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
        transceive: IrohaPeerNfcReaderTransceiverV1,
        preparationTimeoutMillis: Long = DEFAULT_PREPARATION_TIMEOUT_MILLIS,
        pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS,
        sleeper: Sleeper = THREAD_SLEEPER,
    ): IrohaPeerNfcRequestReadV1 {
        require(preparationTimeoutMillis >= 0) { "NFC preparation timeout must not be negative" }
        require(pollIntervalMillis > 0) { "NFC poll interval must be positive" }
        if (offer.nfcKind != IrohaPeerPayloadKind.OFFER) nfcFail(IrohaPeerNfcErrorV1.INVALID_KIND)
        if (!profilePolicy.accepts(offer.nfcProfile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        val offerBytes = offer.encode()
        val offerMaximum = minOf(limits.maximumMessageBytes, IrohaPeerNfcV1.MAXIMUM_OFFER_BYTES)
        if (offerBytes.size > offerMaximum) nfcMessageTooLarge(offerBytes.size, offerMaximum)
        val offerHash = offer.wireHash

        nfcRequireEmptySuccess(
            transceive.transceive(IrohaPeerNfcCommandV1.SelectApplication(applicationIdentifier)),
            IrohaPeerNfcOperationV1.SELECT_APPLICATION,
        )
        var intake = readIntake(transceive, profilePolicy)
        val session = intake.sessionId
        val ours = intake.offerHashEquals(offerHash)
        when (intake.state) {
            IrohaPeerNfcIntakeStateV1.AWAITING_OFFER,
            IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER,
            -> {
                var offset = if (intake.state == IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER && ours) {
                    if (intake.offerLength != offerBytes.size) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                    intake.receivedOfferBytes
                } else {
                    nfcRequireEmptySuccess(
                        transceive.transceive(
                            IrohaPeerNfcCommandV1.BeginOffer(
                                session,
                                offerBytes.copyOfRange(0, IrohaPeerWireMessageV1.HEADER_LENGTH),
                            ),
                        ),
                        IrohaPeerNfcOperationV1.BEGIN_OFFER,
                    )
                    0
                }
                while (offset < offerBytes.size) {
                    val count = minOf(limits.maximumWriteChunkBytes, intake.maximumWriteChunkBytes, offerBytes.size - offset)
                    nfcRequireEmptySuccess(
                        transceive.transceive(
                            IrohaPeerNfcCommandV1.WriteOffer(
                                session,
                                offerHash,
                                offset.toLong(),
                                offerBytes.copyOfRange(offset, offset + count),
                            ),
                        ),
                        IrohaPeerNfcOperationV1.WRITE_OFFER,
                    )
                    offset += count
                }
                nfcRequireEmptySuccess(
                    transceive.transceive(IrohaPeerNfcCommandV1.SubmitOffer(session, offerHash)),
                    IrohaPeerNfcOperationV1.SUBMIT_OFFER,
                )
            }
            IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST,
            IrohaPeerNfcIntakeStateV1.REQUEST_READY,
            IrohaPeerNfcIntakeStateV1.DECLINED,
            -> if (intake.hasOffer && !ours) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }

        var waitedMillis = 0L
        while (true) {
            intake = readIntake(transceive, profilePolicy)
            if (!intake.sessionEquals(session)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            val boundToOurs = intake.offerHashEquals(offerHash)
            when (intake.state) {
                IrohaPeerNfcIntakeStateV1.REQUEST_READY -> {
                    if (intake.hasOffer && !boundToOurs) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                    break
                }
                IrohaPeerNfcIntakeStateV1.DECLINED -> {
                    if (!boundToOurs) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                    throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.OFFER_DECLINED, detail = intake.reason)
                }
                IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST -> {
                    if (!boundToOurs) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                    if (waitedMillis >= preparationTimeoutMillis) {
                        nfcFail(IrohaPeerNfcErrorV1.REQUEST_PREPARATION_TIMED_OUT)
                    }
                    sleeper.sleep(pollIntervalMillis)
                    waitedMillis += pollIntervalMillis
                }
                IrohaPeerNfcIntakeStateV1.AWAITING_OFFER,
                IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER,
                -> nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            }
        }

        val info = IrohaPeerNfcInfoV1.decode(
            nfcRequireSuccess(transceive.transceive(IrohaPeerNfcCommandV1.GetInfo), IrohaPeerNfcOperationV1.GET_INFO).data(),
        )
        if (!info.identity.sessionEquals(session)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        if (info.phase != IrohaPeerNfcPhaseV1.REQUEST_READY) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (info.identity.profile != profilePolicy.profile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        if (info.requestLength > limits.maximumMessageBytes) {
            nfcMessageTooLarge(info.requestLength, limits.maximumMessageBytes)
        }
        val request = IrohaPeerNfcReaderPlanningV1.validateReceiveRequest(
            nfcReadRequestBytes(info, limits, transceive) {},
            info,
            limits,
        )
        return IrohaPeerNfcRequestReadV1(intake, info, request)
    }

    private fun readIntake(
        transceive: IrohaPeerNfcReaderTransceiverV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
    ): IrohaPeerNfcIntakeRecordV1 {
        val record = IrohaPeerNfcIntakeRecordV1.decode(
            nfcRequireSuccess(
                transceive.transceive(IrohaPeerNfcCommandV1.GetIntake),
                IrohaPeerNfcOperationV1.GET_INTAKE,
            ).data(),
        )
        if (record.profile != profilePolicy.profile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        return record
    }
}

/** Read the complete Request advertised by [info] in min(local, card) chunks. */
private inline fun nfcReadRequestBytes(
    info: IrohaPeerNfcInfoV1,
    limits: IrohaPeerNfcLimitsV1,
    transceive: IrohaPeerNfcReaderTransceiverV1,
    beforeEachRead: () -> Unit,
): ByteArray {
    val requestBytes = ByteArray(info.requestLength)
    var received = 0
    while (received < info.requestLength) {
        val command = IrohaPeerNfcReaderPlanningV1.readRequestCommand(info, received, limits)
        beforeEachRead()
        val response = nfcRequireSuccess(transceive.transceive(command), command.operation)
        if (response.dataLength == 0 || response.dataLength > command.length ||
            response.dataLength > info.requestLength - received
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
        response.data().copyInto(requestBytes, received)
        received += response.dataLength
    }
    return requestBytes
}

/** The card's answer as a typed failure, unless it is `9000`. */
internal fun nfcRequireSuccess(
    response: IrohaPeerNfcAPDUResponseV1,
    operation: IrohaPeerNfcOperationV1,
): IrohaPeerNfcAPDUResponseV1 = when (response.statusWord) {
    IrohaPeerNfcStatusWordV1.SUCCESS -> response
    IrohaPeerNfcStatusWordV1.STORAGE_FAILURE ->
        throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.PEER_PERSISTENCE_FAILURE, operation)
    IrohaPeerNfcStatusWordV1.WRONG_LENGTH -> nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED -> nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
    IrohaPeerNfcStatusWordV1.CONDITIONS_NOT_SATISFIED ->
        throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.PEER_REJECTED, operation)
    IrohaPeerNfcStatusWordV1.WRONG_DATA -> nfcFail(IrohaPeerNfcErrorV1.INVALID_APDU)
    IrohaPeerNfcStatusWordV1.NOT_FOUND -> nfcFail(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
    IrohaPeerNfcStatusWordV1.INSTRUCTION_NOT_SUPPORTED -> nfcFail(IrohaPeerNfcErrorV1.UNSUPPORTED_INSTRUCTION)
    IrohaPeerNfcStatusWordV1.CLASS_NOT_SUPPORTED -> nfcFail(IrohaPeerNfcErrorV1.INVALID_COMMAND_CLASS)
}

internal fun nfcRequireEmptySuccess(response: IrohaPeerNfcAPDUResponseV1, operation: IrohaPeerNfcOperationV1) {
    if (nfcRequireSuccess(response, operation).dataLength != 0) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
}
