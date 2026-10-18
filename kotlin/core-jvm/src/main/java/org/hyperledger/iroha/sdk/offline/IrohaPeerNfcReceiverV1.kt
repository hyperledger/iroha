// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * Metadata accepted by BEGIN_PAYMENT. The complete IPM1 header travels in that command, so
 * profile, kind, lengths and both IPM1 hashes are checked before the first Payment byte is
 * buffered.
 */
class IrohaPeerNfcPaymentDescriptorV1 @JvmOverloads constructor(
    paymentHeader: ByteArray,
    limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    private val headerBytes: ByteArray = paymentHeader.copyOf()
    private val inspected = nfcInspectHeader(headerBytes, IrohaPeerPayloadKind.PAYMENT)

    @JvmField val profile: IrohaPeerPayloadProfile = inspected.profile
    @JvmField val schemaVersion: Int = inspected.schemaVersion

    /** Complete IPM1 message length: the header plus the encoded body. */
    @JvmField val messageLength: Int = IrohaPeerWireMessageV1.HEADER_LENGTH + inspected.encodedLength

    init {
        if (inspected.canonicalLength <= 0 || inspected.encodedLength <= 0 ||
            messageLength > limits.maximumMessageBytes
        ) {
            nfcMessageTooLarge(messageLength, limits.maximumMessageBytes)
        }
    }

    val canonicalHash: ByteArray get() = inspected.canonicalHash
    val wireHash: ByteArray get() = inspected.wireHash

    /** The exact 84-byte Payment IPM1 header; a defensive copy. */
    val header: ByteArray get() = headerBytes.copyOf()

    internal fun wireHashEquals(candidate: ByteArray): Boolean = inspected.wireHash.contentEquals(candidate)

    internal fun headerView(): ByteArray = headerBytes

    override fun equals(other: Any?): Boolean =
        other is IrohaPeerNfcPaymentDescriptorV1 && headerBytes.contentEquals(other.headerBytes)

    override fun hashCode(): Int = headerBytes.contentHashCode()

    override fun toString(): String = "IrohaPeerNfcPaymentDescriptorV1(${profile.name}, $messageLength bytes)"
}

/** Validated BEGIN_PAYMENT metadata that must be durable before any Payment byte is accepted. */
class IrohaPeerNfcPaymentAdmissionContextV1(
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1,
    @JvmField val descriptor: IrohaPeerNfcPaymentDescriptorV1,
) {
    init {
        if (profilePolicy.profile != identity.profile || !profilePolicy.accepts(descriptor.profile)) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }
    }

    @JvmOverloads
    constructor(
        identity: IrohaPeerNfcRequestIdentityV1,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        paymentHeader: ByteArray,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ) : this(identity, profilePolicy, IrohaPeerNfcPaymentDescriptorV1(paymentHeader, limits))

    val paymentHeader: ByteArray get() = descriptor.header

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcPaymentAdmissionContextV1 &&
        identity == other.identity && profilePolicy == other.profilePolicy && descriptor == other.descriptor

    override fun hashCode(): Int = 31 * identity.hashCode() + descriptor.hashCode()

    override fun toString(): String = "IrohaPeerNfcPaymentAdmissionContextV1($descriptor)"
}

/**
 * Fixed 244-byte `IPA1` record returned by durable admission storage. The callback's input
 * context is separate from this persistable output, so BEGIN_PAYMENT cannot succeed merely
 * because validation ran. Persist [encode] before returning the record; reloading it restores
 * PAYMENT_RECEIVING at offset zero after RF loss or relaunch.
 */
class IrohaPeerNfcDurablePaymentAdmissionV1 @JvmOverloads constructor(
    context: IrohaPeerNfcPaymentAdmissionContextV1,
    limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    @JvmField val context: IrohaPeerNfcPaymentAdmissionContextV1 = IrohaPeerNfcPaymentAdmissionContextV1(
        context.identity,
        context.profilePolicy,
        context.descriptor.header,
        limits,
    ).also { if (it != context) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH) }

    val identity: IrohaPeerNfcRequestIdentityV1 get() = context.identity
    val profilePolicy: IrohaPeerNfcProfilePolicyV1 get() = context.profilePolicy
    val descriptor: IrohaPeerNfcPaymentDescriptorV1 get() = context.descriptor
    val paymentHeader: ByteArray get() = context.paymentHeader

    fun encode(): ByteArray = NfcRecordWriter(IrohaPeerNfcV1.PAYMENT_ADMISSION_BYTES).apply {
        bytes(IrohaPeerNfcV1.PAYMENT_ADMISSION_MAGIC)
        u8(IrohaPeerNfcV1.WIRE_VERSION)
        u16(identity.profile.code)
        u8(0)
        identity.writeTo(this)
        u16(descriptor.profile.code)
        u16(descriptor.schemaVersion)
        u32(descriptor.messageLength.toLong())
        bytes(descriptor.canonicalHash)
        bytes(descriptor.wireHash)
        bytes(descriptor.headerView())
    }.finish(IrohaPeerNfcV1.PAYMENT_ADMISSION_BYTES)

    override fun equals(other: Any?): Boolean =
        other is IrohaPeerNfcDurablePaymentAdmissionV1 && context == other.context

    override fun hashCode(): Int = context.hashCode()

    override fun toString(): String = "IrohaPeerNfcDurablePaymentAdmissionV1(${context.descriptor})"

    companion object {
        @JvmStatic
        @JvmOverloads
        fun decode(
            data: ByteArray,
            profilePolicy: IrohaPeerNfcProfilePolicyV1? = null,
            limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
        ): IrohaPeerNfcDurablePaymentAdmissionV1 {
            if (data.size != IrohaPeerNfcV1.PAYMENT_ADMISSION_BYTES ||
                !nfcHasMagic(data, IrohaPeerNfcV1.PAYMENT_ADMISSION_MAGIC) ||
                data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION || data.nfcU8(7) != 0
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val requestProfile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(5))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            val paymentProfile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(88))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            val effectivePolicy = profilePolicy ?: IrohaPeerNfcProfilePolicyV1(requestProfile)
            val identity = IrohaPeerNfcRequestIdentityV1(
                requestProfile,
                data.copyOfRange(8, 24),
                data.copyOfRange(24, 56),
                data.copyOfRange(56, 88),
            )
            val context = IrohaPeerNfcPaymentAdmissionContextV1(
                identity,
                effectivePolicy,
                data.copyOfRange(160, 244),
                limits,
            )
            if (effectivePolicy.profile != requestProfile ||
                context.descriptor.profile != paymentProfile ||
                context.descriptor.schemaVersion != data.nfcU16(90) ||
                context.descriptor.messageLength.toLong() != data.nfcU32(92) ||
                !context.descriptor.canonicalHash.contentEquals(data.copyOfRange(96, 128)) ||
                !context.descriptor.wireHash.contentEquals(data.copyOfRange(128, 160))
            ) {
                nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            }
            return IrohaPeerNfcDurablePaymentAdmissionV1(context, limits)
        }
    }
}

/**
 * A structurally bound exchange presented to application persistence at COMMIT. Native
 * authentication and monetary admission remain required before acknowledging receipt.
 */
class IrohaPeerNfcCommitContextV1(
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1,
    @JvmField val receiveRequest: IrohaPeerWireMessageV1,
    @JvmField val payment: IrohaPeerWireMessageV1,
) {
    init {
        if (profilePolicy.profile != identity.profile || !profilePolicy.accepts(receiveRequest.nfcProfile) ||
            !profilePolicy.accepts(payment.nfcProfile)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }
        if (receiveRequest.nfcKind != IrohaPeerPayloadKind.REQUEST || payment.nfcKind != IrohaPeerPayloadKind.PAYMENT) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_KIND)
        }
        if (!identity.canonicalEquals(receiveRequest.canonicalHash) ||
            !identity.requestWireHash.contentEquals(receiveRequest.wireHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
        nfcRequireWalletExchange(receiveRequest, payment)
    }

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcCommitContextV1 && identity == other.identity &&
        profilePolicy == other.profilePolicy && receiveRequest == other.receiveRequest && payment == other.payment

    override fun hashCode(): Int = 31 * identity.hashCode() + payment.hashCode()

    override fun toString(): String = "IrohaPeerNfcCommitContextV1(payment=${payment.byteCount} bytes)"
}

/**
 * Opaque, persistable `IDA1` receiver record proving that Payment ingest and its exact IPM1
 * acknowledgement (the wallet's Credited envelope) crossed the application's durability boundary.
 * A COMMIT handler stores [encode] durably before returning this value; reloading it reconstructs
 * ACKNOWLEDGEMENT_READY after RF loss or relaunch.
 */
class IrohaPeerNfcDurableAcknowledgementV1 private constructor(
    @JvmField val identity: IrohaPeerNfcRequestIdentityV1,
    @JvmField val paymentProfile: IrohaPeerPayloadProfile,
    @JvmField val paymentLength: Int,
    paymentWireHash: ByteArray,
    @JvmField val acknowledgement: IrohaPeerWireMessageV1,
    limits: IrohaPeerNfcLimitsV1,
) {
    init {
        if (paymentLength <= IrohaPeerWireMessageV1.HEADER_LENGTH || paymentLength > limits.maximumMessageBytes) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        }
    }

    private val paymentHash: ByteArray = nfcRequireHash(paymentWireHash)
    private val acknowledgementBytes: ByteArray = acknowledgement.encode()

    init {
        if (acknowledgement.nfcKind != IrohaPeerPayloadKind.CREDITED) nfcFail(IrohaPeerNfcErrorV1.INVALID_KIND)
        if (acknowledgementBytes.size > limits.maximumMessageBytes) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
    }

    /**
     * The durable record of [acknowledgement] (complete Credited IPM1 bytes) for the Payment of
     * [context]. Credited must name the hosted Request's scheme.
     */
    @JvmOverloads
    constructor(
        context: IrohaPeerNfcCommitContextV1,
        acknowledgement: ByteArray,
        limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    ) : this(
        context.identity,
        context.payment.nfcProfile,
        requireCommitPayment(context, limits),
        context.payment.wireHash,
        decodeAcknowledgement(context, acknowledgement, limits),
        limits,
    )

    /** Payment wire hash `w_p`; a defensive copy. */
    val paymentWireHash: ByteArray get() = paymentHash.copyOf()

    internal fun paymentHashEquals(candidate: ByteArray): Boolean = paymentHash.contentEquals(candidate)

    internal fun acknowledgementView(): ByteArray = acknowledgementBytes

    fun encode(): ByteArray = NfcRecordWriter(FIXED_BYTES + acknowledgementBytes.size).apply {
        bytes(IrohaPeerNfcV1.DURABLE_ACKNOWLEDGEMENT_MAGIC)
        u8(IrohaPeerNfcV1.WIRE_VERSION)
        u16(identity.profile.code)
        u8(0)
        identity.writeTo(this)
        u16(paymentProfile.code)
        u32(paymentLength.toLong())
        bytes(paymentHash)
        u32(acknowledgementBytes.size.toLong())
        bytes(acknowledgementBytes)
    }.finish(FIXED_BYTES + acknowledgementBytes.size)

    override fun equals(other: Any?): Boolean = other is IrohaPeerNfcDurableAcknowledgementV1 &&
        identity == other.identity && paymentProfile == other.paymentProfile && paymentLength == other.paymentLength &&
        paymentHash.contentEquals(other.paymentHash) && acknowledgement == other.acknowledgement

    override fun hashCode(): Int = (31 * identity.hashCode() + paymentHash.contentHashCode()) * 31 +
        acknowledgement.hashCode()

    override fun toString(): String =
        "IrohaPeerNfcDurableAcknowledgementV1(acknowledgement=${acknowledgementBytes.size} bytes)"

    companion object {
        private const val FIXED_BYTES = 130

        private fun requireCommitPayment(context: IrohaPeerNfcCommitContextV1, limits: IrohaPeerNfcLimitsV1): Int {
            val length = context.payment.byteCount
            if (length > limits.maximumMessageBytes) nfcMessageTooLarge(length, limits.maximumMessageBytes)
            return length
        }

        private fun decodeAcknowledgement(
            context: IrohaPeerNfcCommitContextV1,
            acknowledgement: ByteArray,
            limits: IrohaPeerNfcLimitsV1,
        ): IrohaPeerWireMessageV1 {
            val decoded = nfcDecodeMessage(acknowledgement, null, IrohaPeerPayloadKind.CREDITED, limits)
            if (!context.profilePolicy.accepts(decoded.nfcProfile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
            nfcRequireWalletExchange(context.receiveRequest, context.payment, decoded)
            return decoded
        }

        @JvmStatic
        @JvmOverloads
        fun decode(
            data: ByteArray,
            profilePolicy: IrohaPeerNfcProfilePolicyV1? = null,
            limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
        ): IrohaPeerNfcDurableAcknowledgementV1 {
            if (data.size <= FIXED_BYTES || !nfcHasMagic(data, IrohaPeerNfcV1.DURABLE_ACKNOWLEDGEMENT_MAGIC) ||
                data.nfcU8(4) != IrohaPeerNfcV1.WIRE_VERSION || data.nfcU8(7) != 0
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val profile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(5)) ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            val paymentProfile = IrohaPeerPayloadProfile.fromCode(data.nfcU16(88))
                ?: nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
            val acknowledgementLength = data.nfcU32(126)
            if (acknowledgementLength <= IrohaPeerWireMessageV1.HEADER_LENGTH ||
                acknowledgementLength > limits.maximumMessageBytes ||
                FIXED_BYTES + acknowledgementLength != data.size.toLong()
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
            }
            val identity = IrohaPeerNfcRequestIdentityV1(
                profile,
                data.copyOfRange(8, 24),
                data.copyOfRange(24, 56),
                data.copyOfRange(56, 88),
            )
            val acknowledgement = nfcDecodeMessage(
                data.copyOfRange(FIXED_BYTES, data.size),
                null,
                IrohaPeerPayloadKind.CREDITED,
                limits,
            )
            val effectivePolicy = profilePolicy ?: IrohaPeerNfcProfilePolicyV1(profile)
            if (effectivePolicy.profile != profile || !effectivePolicy.accepts(paymentProfile) ||
                !effectivePolicy.accepts(acknowledgement.nfcProfile)
            ) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
            }
            return IrohaPeerNfcDurableAcknowledgementV1(
                identity,
                paymentProfile,
                nfcLength(data.nfcU32(90)),
                data.copyOfRange(94, 126),
                acknowledgement,
                limits,
            )
        }
    }
}

/** BEGIN_PAYMENT outcome of [IrohaPeerNfcReceiverSessionV1.preparePaymentAdmission]. */
sealed class IrohaPeerNfcPaymentAdmissionDispositionV1 {
    /** Durably admit [context], then install the returned record before answering `9000`. */
    class RequiresDurableAdmission(@JvmField val context: IrohaPeerNfcPaymentAdmissionContextV1) :
        IrohaPeerNfcPaymentAdmissionDispositionV1()

    /** The exact BEGIN_PAYMENT was already durably admitted; the replay is idempotent. */
    object AlreadyAdmitted : IrohaPeerNfcPaymentAdmissionDispositionV1()
}

/** COMMIT outcome of [IrohaPeerNfcReceiverSessionV1.prepareCommit]. */
sealed class IrohaPeerNfcCommitDispositionV1 {
    /**
     * The application must atomically ingest the Payment and persist the acknowledgement, then
     * install the returned durable record before answering `9000`.
     */
    class RequiresDurableCommit(@JvmField val context: IrohaPeerNfcCommitContextV1) :
        IrohaPeerNfcCommitDispositionV1()

    /** The exact COMMIT was already durably accepted; the replay is idempotent. */
    object AlreadyCommitted : IrohaPeerNfcCommitDispositionV1()
}

/**
 * Transport-neutral receiver state of one Request-hosting NFC session (the Swift
 * `IrohaPeerNfcReceiverSessionV1`). BEGIN_PAYMENT is answered only after the application durably
 * admitted the Payment header ([preparePaymentAdmission], [installPaymentAdmission]) and COMMIT
 * only after it ingested the Payment and persisted the Credited acknowledgement ([prepareCommit],
 * [installDurableAcknowledgement]). Restoring [IrohaPeerNfcDurablePaymentAdmissionV1] and
 * [IrohaPeerNfcDurableAcknowledgementV1] reconstructs those phases after RF loss or relaunch.
 * Thread-safe.
 */
class IrohaPeerNfcReceiverSessionV1 @JvmOverloads constructor(
    sessionId: ByteArray,
    receiveRequest: ByteArray,
    durableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1? = null,
    restoredPaymentAdmission: IrohaPeerNfcDurablePaymentAdmissionV1? = null,
    profilePolicy: IrohaPeerNfcProfilePolicyV1? = null,
    @JvmField val limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
) {
    /** Durably admits a Payment header; persist the returned record before returning it. */
    fun interface DurableAdmissionHandler {
        fun admit(context: IrohaPeerNfcPaymentAdmissionContextV1): IrohaPeerNfcDurablePaymentAdmissionV1
    }

    /** Ingests the Payment and persists the returned acknowledgement record before returning it. */
    fun interface DurableCommitHandler {
        fun commit(context: IrohaPeerNfcCommitContextV1): IrohaPeerNfcDurableAcknowledgementV1
    }

    private class PendingPayment(val descriptor: IrohaPeerNfcPaymentDescriptorV1) {
        val buffer = ByteArray(descriptor.messageLength)
        var received = 0
    }

    private val session: ByteArray = nfcRequireSession(sessionId)

    /** The hosted Request (IPM1 kind `request`). */
    @JvmField val receiveRequest: IrohaPeerWireMessageV1 =
        nfcDecodeMessage(receiveRequest, null, IrohaPeerPayloadKind.REQUEST, limits)
    private val requestBytes: ByteArray = this.receiveRequest.encode()

    @JvmField val identity: IrohaPeerNfcRequestIdentityV1 = IrohaPeerNfcRequestIdentityV1(
        this.receiveRequest.nfcProfile,
        session,
        this.receiveRequest.canonicalHash,
        this.receiveRequest.wireHash,
    )

    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1 =
        (profilePolicy ?: IrohaPeerNfcProfilePolicyV1(this.receiveRequest.nfcProfile)).also {
            if (it.profile != this.receiveRequest.nfcProfile) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }

    private var pendingPayment: PendingPayment? = null
    private var acknowledgementRecord: IrohaPeerNfcDurableAcknowledgementV1? = null
    private var acknowledgementConfirmed = false

    init {
        if (durableAcknowledgement != null) {
            if (durableAcknowledgement.identity != identity ||
                !this.profilePolicy.accepts(durableAcknowledgement.paymentProfile) ||
                !this.profilePolicy.accepts(durableAcknowledgement.acknowledgement.nfcProfile)
            ) {
                nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            }
            nfcRequireCreditedScheme(this.receiveRequest, durableAcknowledgement.acknowledgement)
        }
        if (restoredPaymentAdmission != null) {
            val validated = IrohaPeerNfcDurablePaymentAdmissionV1.decode(
                restoredPaymentAdmission.encode(),
                this.profilePolicy,
                limits,
            )
            if (validated != restoredPaymentAdmission || validated.identity != identity ||
                validated.profilePolicy != this.profilePolicy
            ) {
                nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            }
            if (durableAcknowledgement != null) {
                if (validated.descriptor.profile != durableAcknowledgement.paymentProfile ||
                    validated.descriptor.messageLength != durableAcknowledgement.paymentLength ||
                    !durableAcknowledgement.paymentHashEquals(validated.descriptor.wireHash)
                ) {
                    nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
                }
            } else {
                pendingPayment = PendingPayment(validated.descriptor)
            }
        }
        acknowledgementRecord = durableAcknowledgement
    }

    /** Session identifier `s`; a defensive copy. */
    val sessionId: ByteArray get() = session.copyOf()

    val phase: IrohaPeerNfcPhaseV1
        @Synchronized get() = when {
            acknowledgementConfirmed -> IrohaPeerNfcPhaseV1.COMPLETE
            acknowledgementRecord != null -> IrohaPeerNfcPhaseV1.ACKNOWLEDGEMENT_READY
            pendingPayment != null -> IrohaPeerNfcPhaseV1.PAYMENT_RECEIVING
            else -> IrohaPeerNfcPhaseV1.REQUEST_READY
        }

    /** The installed durable acknowledgement, once COMMIT succeeded or it was restored. */
    val durableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1?
        @Synchronized get() = acknowledgementRecord

    @Synchronized
    fun info(): IrohaPeerNfcInfoV1 = IrohaPeerNfcInfoV1(
        phase,
        currentFlags(),
        identity,
        requestBytes.size,
        limits.maximumReadChunkBytes,
        limits.maximumWriteChunkBytes,
    )

    @Synchronized
    fun status(): IrohaPeerNfcStatusV1 {
        val acknowledgement = acknowledgementRecord
        val pending = pendingPayment
        val zeroHash = ByteArray(IrohaPeerNfcV1.HASH_BYTES)
        return IrohaPeerNfcStatusV1(
            phase,
            currentFlags(),
            identity,
            acknowledgement?.paymentProfile ?: pending?.descriptor?.profile,
            acknowledgement?.paymentLength ?: pending?.descriptor?.messageLength ?: 0,
            acknowledgement?.paymentLength ?: pending?.received ?: 0,
            acknowledgement?.paymentWireHash ?: pending?.descriptor?.wireHash ?: zeroHash,
            acknowledgement?.acknowledgement?.nfcProfile,
            acknowledgement?.acknowledgementView()?.size ?: 0,
            acknowledgement?.acknowledgement?.wireHash ?: zeroHash,
            limits.maximumReadChunkBytes,
            limits.maximumWriteChunkBytes,
        )
    }

    /**
     * The direct-mode `IOI1` record: REQUEST_READY with zero Offer fields, because this session
     * hosts a Request built from an Offer that arrived over another carrier.
     */
    fun intakeRecord(): IrohaPeerNfcIntakeRecordV1 = IrohaPeerNfcIntakeRecordV1(
        IrohaPeerNfcIntakeStateV1.REQUEST_READY,
        identity.profile,
        session,
        0,
        0,
        ByteArray(IrohaPeerNfcV1.HASH_BYTES),
        limits.maximumWriteChunkBytes,
        0,
    )

    /**
     * Handles every command except BEGIN_PAYMENT and COMMIT, whose durable boundaries use
     * [preparePaymentAdmission]/[installPaymentAdmission] and [prepareCommit]/
     * [installDurableAcknowledgement], or the [process] convenience. In this direct mode GET_INTAKE
     * answers [intakeRecord] and the Offer commands answer [IrohaPeerNfcErrorV1.STATE_MISMATCH].
     */
    @Synchronized
    fun handle(command: IrohaPeerNfcCommandV1): ByteArray = when (command) {
        is IrohaPeerNfcCommandV1.SelectApplication -> ByteArray(0)
        is IrohaPeerNfcCommandV1.GetIntake -> intakeRecord().encode()
        is IrohaPeerNfcCommandV1.BeginOffer -> {
            requireSession(command.sessionId)
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        is IrohaPeerNfcCommandV1.WriteOffer -> {
            requireSession(command.sessionId)
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        is IrohaPeerNfcCommandV1.SubmitOffer -> {
            requireSession(command.sessionId)
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        is IrohaPeerNfcCommandV1.GetInfo -> info().encode()
        is IrohaPeerNfcCommandV1.ReadRequest -> {
            requireRequestContinuity(command.sessionView(), command.hashView())
            readSlice(requestBytes, command.offset, command.length)
        }
        is IrohaPeerNfcCommandV1.BeginPayment -> nfcFail(IrohaPeerNfcErrorV1.DURABLE_ADMISSION_REQUIRED)
        is IrohaPeerNfcCommandV1.Write -> {
            writePayment(command)
            ByteArray(0)
        }
        is IrohaPeerNfcCommandV1.Commit -> nfcFail(IrohaPeerNfcErrorV1.DURABLE_COMMIT_REQUIRED)
        is IrohaPeerNfcCommandV1.ReadAcknowledgement -> {
            val acknowledgement = acknowledgementRecord ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            requireSession(command.sessionView())
            if (!acknowledgement.paymentHashEquals(command.hashView())) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            readSlice(acknowledgement.acknowledgementView(), command.offset, command.length)
        }
        is IrohaPeerNfcCommandV1.ConfirmAcknowledgement -> {
            confirmAcknowledgement(command)
            ByteArray(0)
        }
        is IrohaPeerNfcCommandV1.GetStatus -> {
            requireRequestContinuity(command.sessionView(), command.hashView())
            status().encode()
        }
    }

    @Synchronized
    fun preparePaymentAdmission(command: IrohaPeerNfcCommandV1): IrohaPeerNfcPaymentAdmissionDispositionV1 {
        if (command !is IrohaPeerNfcCommandV1.BeginPayment) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        requireRequestContinuity(command.sessionView(), command.hashView())
        val descriptor = IrohaPeerNfcPaymentDescriptorV1(command.paymentHeader, limits)
        if (!profilePolicy.accepts(descriptor.profile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        if (acknowledgementRecord != null) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        val pending = pendingPayment
        if (pending != null) {
            if (pending.descriptor != descriptor) nfcFail(IrohaPeerNfcErrorV1.CONFLICTING_REPLAY)
            return IrohaPeerNfcPaymentAdmissionDispositionV1.AlreadyAdmitted
        }
        return IrohaPeerNfcPaymentAdmissionDispositionV1.RequiresDurableAdmission(
            IrohaPeerNfcPaymentAdmissionContextV1(identity, profilePolicy, descriptor),
        )
    }

    @Synchronized
    fun installPaymentAdmission(record: IrohaPeerNfcDurablePaymentAdmissionV1) {
        val validated = IrohaPeerNfcDurablePaymentAdmissionV1.decode(record.encode(), profilePolicy, limits)
        if (validated != record || validated.identity != identity || validated.profilePolicy != profilePolicy) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
        if (acknowledgementRecord != null) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        val pending = pendingPayment
        if (pending != null) {
            if (pending.descriptor != validated.descriptor) nfcFail(IrohaPeerNfcErrorV1.CONFLICTING_REPLAY)
            return
        }
        pendingPayment = PendingPayment(validated.descriptor)
    }

    @Synchronized
    fun prepareCommit(command: IrohaPeerNfcCommandV1): IrohaPeerNfcCommitDispositionV1 {
        if (command !is IrohaPeerNfcCommandV1.Commit) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        requireRequestContinuity(command.sessionView(), command.requestHashView())
        val acknowledgement = acknowledgementRecord
        if (acknowledgement != null) {
            if (!acknowledgement.paymentHashEquals(command.paymentHashView())) {
                nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
            }
            return IrohaPeerNfcCommitDispositionV1.AlreadyCommitted
        }
        val pending = pendingPayment ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (!pending.descriptor.wireHashEquals(command.paymentHashView())) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        if (pending.received != pending.descriptor.messageLength) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        val payment = nfcDecodeMessage(pending.buffer, null, IrohaPeerPayloadKind.PAYMENT, limits)
        if (!profilePolicy.accepts(payment.nfcProfile) ||
            !payment.nfcHeaderBytes().contentEquals(pending.descriptor.headerView()) ||
            !pending.descriptor.wireHashEquals(payment.wireHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
        }
        return IrohaPeerNfcCommitDispositionV1.RequiresDurableCommit(
            IrohaPeerNfcCommitContextV1(identity, profilePolicy, receiveRequest, payment),
        )
    }

    /**
     * Installs only a record for the exact pending Payment. Call this after the application has
     * atomically persisted the Payment outcome and its acknowledgement.
     */
    @Synchronized
    fun installDurableAcknowledgement(record: IrohaPeerNfcDurableAcknowledgementV1) {
        if (record.identity != identity) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        if (!profilePolicy.accepts(record.paymentProfile) || !profilePolicy.accepts(record.acknowledgement.nfcProfile)) {
            nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        }
        nfcRequireCreditedScheme(receiveRequest, record.acknowledgement)
        val installed = acknowledgementRecord
        if (installed != null) {
            if (installed != record) nfcFail(IrohaPeerNfcErrorV1.CONFLICTING_REPLAY)
            return
        }
        val pending = pendingPayment
        if (pending == null || record.paymentProfile != pending.descriptor.profile ||
            record.paymentLength != pending.descriptor.messageLength ||
            !pending.descriptor.wireHashEquals(record.paymentWireHash)
        ) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
        acknowledgementRecord = record
        pendingPayment = null
    }

    /**
     * Decodes and executes one raw APDU addressed to [applicationIdentifier]. A successful
     * BEGIN_PAYMENT or COMMIT response is produced only after [admitPayment] or [durableCommit]
     * returned an exact persisted record.
     */
    @JvmOverloads
    fun process(
        apdu: ByteArray,
        applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1 = IrohaPeerNfcApplicationIdentifierV1.PROTOCOL,
        admitPayment: DurableAdmissionHandler? = null,
        durableCommit: DurableCommitHandler? = null,
    ): IrohaPeerNfcAPDUResponseV1 {
        val command = try {
            IrohaPeerNfcAPDUCodecV1.decode(apdu, applicationIdentifier)
        } catch (failure: IrohaPeerNfcExceptionV1) {
            return IrohaPeerNfcAPDUResponseV1.failure(failure.error)
        } catch (_: RuntimeException) {
            return IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.WRONG_DATA)
        }
        return processCommand(command, admitPayment, durableCommit)
    }

    internal fun processCommand(
        command: IrohaPeerNfcCommandV1,
        admitPayment: DurableAdmissionHandler?,
        durableCommit: DurableCommitHandler?,
    ): IrohaPeerNfcAPDUResponseV1 = when (command) {
        is IrohaPeerNfcCommandV1.BeginPayment -> nfcRespond(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE) {
            when (val disposition = preparePaymentAdmission(command)) {
                is IrohaPeerNfcPaymentAdmissionDispositionV1.AlreadyAdmitted -> SUCCESS
                is IrohaPeerNfcPaymentAdmissionDispositionV1.RequiresDurableAdmission -> {
                    val handler = admitPayment ?: nfcFail(IrohaPeerNfcErrorV1.DURABLE_ADMISSION_REQUIRED)
                    val record = try {
                        handler.admit(disposition.context)
                    } catch (_: Exception) {
                        return@nfcRespond IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE)
                    }
                    if (record.context != disposition.context) {
                        return@nfcRespond IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SECURITY_STATUS_NOT_SATISFIED)
                    }
                    installPaymentAdmission(record)
                    SUCCESS
                }
            }
        }
        is IrohaPeerNfcCommandV1.Commit -> nfcRespond(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE) {
            when (val disposition = prepareCommit(command)) {
                is IrohaPeerNfcCommitDispositionV1.AlreadyCommitted -> SUCCESS
                is IrohaPeerNfcCommitDispositionV1.RequiresDurableCommit -> {
                    val handler = durableCommit ?: nfcFail(IrohaPeerNfcErrorV1.DURABLE_COMMIT_REQUIRED)
                    val record = try {
                        handler.commit(disposition.context)
                    } catch (_: Exception) {
                        return@nfcRespond IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.STORAGE_FAILURE)
                    }
                    installDurableAcknowledgement(record)
                    SUCCESS
                }
            }
        }
        else -> nfcRespond(IrohaPeerNfcStatusWordV1.WRONG_DATA) {
            IrohaPeerNfcAPDUResponseV1(handle(command), IrohaPeerNfcStatusWordV1.SUCCESS)
        }
    }

    private fun currentFlags(): IrohaPeerNfcFlagsV1 = if (acknowledgementRecord != null) {
        IrohaPeerNfcFlagsV1.KNOWN
    } else {
        IrohaPeerNfcFlagsV1.IDEMPOTENT_WRITES
    }

    private fun writePayment(command: IrohaPeerNfcCommandV1.Write) {
        requireSession(command.sessionView())
        val bytes = command.chunkView()
        if (bytes.isEmpty() || bytes.size > limits.maximumWriteChunkBytes) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        val pending = pendingPayment ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (!pending.descriptor.wireHashEquals(command.hashView())) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        pending.received = nfcWriteContiguous(pending.buffer, pending.received, command.offset, bytes)
    }

    private fun confirmAcknowledgement(command: IrohaPeerNfcCommandV1.ConfirmAcknowledgement) {
        requireSession(command.sessionView())
        val acknowledgement = acknowledgementRecord ?: nfcFail(IrohaPeerNfcErrorV1.ACKNOWLEDGEMENT_NOT_DURABLE)
        if (!acknowledgement.paymentHashEquals(command.paymentHashView()) ||
            !acknowledgement.acknowledgement.wireHash.contentEquals(command.acknowledgementHashView())
        ) {
            nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        }
        acknowledgementConfirmed = true
    }

    private fun requireSession(candidate: ByteArray) {
        nfcRequireSession(candidate)
        if (!session.contentEquals(candidate)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
    }

    private fun requireRequestContinuity(sessionId: ByteArray, requestHash: ByteArray) {
        requireSession(sessionId)
        nfcRequireHash(requestHash)
        if (!identity.canonicalEquals(requestHash)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
    }

    private fun readSlice(message: ByteArray, offset: Long, requestedLength: Int): ByteArray {
        if (requestedLength <= 0 || requestedLength > limits.maximumReadChunkBytes) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        if (offset < 0 || offset >= message.size) nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
        val start = offset.toInt()
        return message.copyOfRange(start, start + minOf(requestedLength, message.size - start))
    }

    private companion object {
        val SUCCESS = IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SUCCESS)
    }
}

/**
 * Append a contiguous chunk at [offset] to [buffer] holding [received] bytes. An overlapping
 * replay must be byte-identical; an offset beyond the received bytes or a chunk past the end is
 * [IrohaPeerNfcErrorV1.INVALID_OFFSET]. Returns the new received count.
 */
internal fun nfcWriteContiguous(buffer: ByteArray, received: Int, offset: Long, bytes: ByteArray): Int {
    if (offset < 0 || offset > received || offset > (buffer.size - bytes.size).toLong()) {
        nfcFail(IrohaPeerNfcErrorV1.INVALID_OFFSET)
    }
    val start = offset.toInt()
    val overlap = minOf(received - start, bytes.size)
    for (index in 0 until overlap) {
        if (buffer[start + index] != bytes[index]) nfcFail(IrohaPeerNfcErrorV1.CONFLICTING_REPLAY)
    }
    if (overlap < bytes.size) bytes.copyInto(buffer, start + overlap, overlap, bytes.size)
    return maxOf(received, start + bytes.size)
}

/**
 * Run [body], answering an [IrohaPeerNfcExceptionV1] with its status word and any other
 * exception with [otherFailure], as Swift `process` does.
 */
internal inline fun nfcRespond(
    otherFailure: IrohaPeerNfcStatusWordV1,
    body: () -> IrohaPeerNfcAPDUResponseV1,
): IrohaPeerNfcAPDUResponseV1 = try {
    body()
} catch (failure: IrohaPeerNfcExceptionV1) {
    IrohaPeerNfcAPDUResponseV1.failure(failure.error)
} catch (_: RuntimeException) {
    IrohaPeerNfcAPDUResponseV1.of(otherFailure)
}
