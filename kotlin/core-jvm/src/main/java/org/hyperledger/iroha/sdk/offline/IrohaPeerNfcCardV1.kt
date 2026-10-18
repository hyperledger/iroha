// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * Card-side Offer intake (`specs/kagemusha_wallet_wire_v1.md` §6, NFC). A card started
 * without a Request awaits the payer's Offer under the session identifier `s` it chose at intake
 * start; the Request it later hosts uses the same `s`.
 *
 * AWAITING_OFFER → BEGIN_OFFER → RECEIVING_OFFER. Before SUBMIT_OFFER the identical header is an
 * idempotent no-op and a different header replaces the unfinished Offer; WRITE_OFFER appends
 * contiguous chunks whose overlapping replays must be byte-identical. SUBMIT_OFFER requires every
 * byte and verifies the complete IPM1 Offer (its profile and kind, both hashes): success enters
 * PREPARING_REQUEST and hands the Offer to the receiver's wallet ([pendingOffer]); failure resets
 * to AWAITING_OFFER and answers `6982`. Afterwards the intake is bound to that Offer: its BEGIN,
 * WRITE and SUBMIT commands are idempotent no-ops and every other Offer command answers `6985`.
 * The wallet either supplies a Request ([installRequest], then REQUEST_READY) or declines with a
 * reason ([decline], then DECLINED). A command whose `s` is not this intake's answers `6982`.
 *
 * GET_ASK answers the receiver's [ask] while no Offer is bound (AWAITING_OFFER, RECEIVING_OFFER), so
 * the payer builds its Offer for the asked amount inside the same contact; without an ask, or once
 * an Offer is bound, it answers `6985`. GET_ASK carries no session identifier and changes no state.
 * Thread-safe.
 */
class IrohaPeerNfcOfferIntakeV1 @JvmOverloads constructor(
    @JvmField val profilePolicy: IrohaPeerNfcProfilePolicyV1,
    @JvmField val limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
    sessionId: ByteArray = nfcRandomNonzero(IrohaPeerNfcV1.SESSION_ID_BYTES),
    /** The receiver's ask answered by GET_ASK; `null` for an intake that does not ask. */
    @JvmField val ask: IrohaPeerAskV1? = null,
) {
    private class OfferTransfer(val header: ByteArray, val length: Int, val wireHash: ByteArray) {
        val buffer = ByteArray(length)
        var received = 0
    }

    private val session: ByteArray = nfcRequireSession(sessionId)
    private var currentState = IrohaPeerNfcIntakeStateV1.AWAITING_OFFER
    private var transfer: OfferTransfer? = null
    private var submittedOffer: IrohaPeerWireMessageV1? = null
    private var preparedRequest: IrohaPeerWireMessageV1? = null
    private var declineReason = 0

    /** Session identifier `s` chosen at intake start; a defensive copy. */
    val sessionId: ByteArray get() = session.copyOf()

    val state: IrohaPeerNfcIntakeStateV1
        @Synchronized get() = currentState

    /** The verified Offer awaiting the wallet's Request, while PREPARING_REQUEST. */
    val pendingOffer: IrohaPeerWireMessageV1?
        @Synchronized get() = if (currentState == IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST) submittedOffer else null

    /** The verified Offer this intake is bound to after SUBMIT_OFFER. */
    val offer: IrohaPeerWireMessageV1?
        @Synchronized get() = submittedOffer

    /** The Request installed for the bound Offer, once REQUEST_READY. */
    val request: IrohaPeerWireMessageV1?
        @Synchronized get() = preparedRequest

    /** The current `IOI1` record. */
    @Synchronized
    fun record(): IrohaPeerNfcIntakeRecordV1 {
        val current = transfer
        return IrohaPeerNfcIntakeRecordV1(
            currentState,
            profilePolicy.profile,
            session,
            current?.length ?: 0,
            current?.received ?: 0,
            current?.wireHash ?: ByteArray(IrohaPeerNfcV1.HASH_BYTES),
            limits.maximumWriteChunkBytes,
            if (currentState == IrohaPeerNfcIntakeStateV1.DECLINED) declineReason else 0,
        )
    }

    /**
     * GET_INTAKE, GET_ASK, BEGIN_OFFER, WRITE_OFFER and SUBMIT_OFFER. A newly submitted Offer is then
     * [pendingOffer]; [submitOffer] returns it directly.
     */
    @Synchronized
    fun handle(command: IrohaPeerNfcCommandV1): ByteArray {
        when (command) {
            is IrohaPeerNfcCommandV1.GetIntake -> return record().encode()
            is IrohaPeerNfcCommandV1.GetAsk -> {
                val current = ask
                if (current == null || isBound()) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
                return current.encode()
            }
            is IrohaPeerNfcCommandV1.BeginOffer -> beginOffer(command)
            is IrohaPeerNfcCommandV1.WriteOffer -> writeOffer(command)
            is IrohaPeerNfcCommandV1.SubmitOffer -> submitOffer(command)
            else -> nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        return ByteArray(0)
    }

    /**
     * SUBMIT_OFFER. Returns the verified Offer when this command moved the intake to
     * PREPARING_REQUEST; the caller answers `9000` at once and hands the Offer to the wallet
     * asynchronously. Returns `null` for an idempotent replay of the bound Offer's SUBMIT.
     */
    @Synchronized
    fun submitOffer(command: IrohaPeerNfcCommandV1.SubmitOffer): IrohaPeerWireMessageV1? {
        requireSession(command.sessionId)
        if (isBound()) {
            if (!requireTransfer().wireHash.contentEquals(command.offerWireHash)) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            return null
        }
        val current = transfer ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (!command.hashEquals(current.wireHash)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        if (current.received != current.length) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        val decoded = try {
            nfcDecodeMessage(current.buffer, profilePolicy.profile, IrohaPeerPayloadKind.OFFER, limits).also {
                if (!it.nfcHeaderBytes().contentEquals(current.header) || !it.wireHash.contentEquals(current.wireHash)) {
                    nfcFail(IrohaPeerNfcErrorV1.INVALID_HASH)
                }
            }
        } catch (failure: RuntimeException) {
            reset()
            throw IrohaPeerNfcExceptionV1(IrohaPeerNfcErrorV1.INVALID_IPM1, cause = failure)
        }
        submittedOffer = decoded
        currentState = IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST
        return decoded
    }

    /**
     * Install the wallet's [request] (complete Request IPM1 bytes of this intake's profile) for the
     * bound Offer whose wire hash is [offerWireHash]: PREPARING_REQUEST → REQUEST_READY.
     */
    @Synchronized
    fun installRequest(offerWireHash: ByteArray, request: ByteArray): IrohaPeerWireMessageV1 {
        requirePreparing(offerWireHash)
        val decoded = nfcDecodeMessage(request, profilePolicy.profile, IrohaPeerPayloadKind.REQUEST, limits)
        preparedRequest = decoded
        currentState = IrohaPeerNfcIntakeStateV1.REQUEST_READY
        return decoded
    }

    /** The wallet declined the bound Offer with [reason] (1–65,535): PREPARING_REQUEST → DECLINED. */
    @Synchronized
    fun decline(offerWireHash: ByteArray, reason: Int) {
        require(reason in 1..0xffff) { "An Offer decline reason is 1..65535" }
        requirePreparing(offerWireHash)
        declineReason = reason
        currentState = IrohaPeerNfcIntakeStateV1.DECLINED
    }

    private fun beginOffer(command: IrohaPeerNfcCommandV1.BeginOffer) {
        requireSession(command.sessionId)
        if (isBound()) {
            if (!command.headerEquals(requireTransfer().header)) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            return
        }
        val header = command.offerHeader
        val inspected = nfcInspectHeader(header, IrohaPeerPayloadKind.OFFER)
        if (!profilePolicy.accepts(inspected.profile)) nfcFail(IrohaPeerNfcErrorV1.INVALID_PROFILE)
        val length = IrohaPeerWireMessageV1.HEADER_LENGTH + inspected.encodedLength
        val maximum = minOf(limits.maximumMessageBytes, IrohaPeerNfcV1.MAXIMUM_OFFER_BYTES)
        if (length > maximum) nfcMessageTooLarge(length, maximum)
        val current = transfer
        if (current != null && current.header.contentEquals(header)) return
        transfer = OfferTransfer(header, length, inspected.wireHash)
        currentState = IrohaPeerNfcIntakeStateV1.RECEIVING_OFFER
    }

    private fun writeOffer(command: IrohaPeerNfcCommandV1.WriteOffer) {
        requireSession(command.sessionId)
        if (isBound()) {
            if (!command.hashEquals(requireTransfer().wireHash)) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            return
        }
        val bytes = command.chunkView()
        if (bytes.isEmpty() || bytes.size > limits.maximumWriteChunkBytes) nfcFail(IrohaPeerNfcErrorV1.INVALID_LENGTH)
        val current = transfer ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (!command.hashEquals(current.wireHash)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
        current.received = nfcWriteContiguous(current.buffer, current.received, command.offset, bytes)
    }

    private fun requirePreparing(offerWireHash: ByteArray) {
        val current = transfer
        if (currentState != IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST || current == null) {
            nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        }
        if (!current.wireHash.contentEquals(offerWireHash)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
    }

    private fun isBound(): Boolean = currentState == IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST ||
        currentState == IrohaPeerNfcIntakeStateV1.REQUEST_READY ||
        currentState == IrohaPeerNfcIntakeStateV1.DECLINED

    private fun requireTransfer(): OfferTransfer = transfer ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)

    private fun requireSession(candidate: ByteArray) {
        nfcRequireSession(candidate)
        if (!session.contentEquals(candidate)) nfcFail(IrohaPeerNfcErrorV1.CONTINUITY_MISMATCH)
    }

    private fun reset() {
        transfer?.buffer?.fill(0)
        transfer = null
        submittedOffer = null
        currentState = IrohaPeerNfcIntakeStateV1.AWAITING_OFFER
    }
}

/**
 * Transport-neutral NFC card: the host card emulation endpoint of the receiver's phone under one
 * application identifier. In intake mode ([intake]) it awaits the payer's Offer and, once
 * the wallet's Request is installed, hosts it with the same session identifier and connection. In
 * direct mode ([direct]) it hosts a Request built from an Offer that arrived over another carrier,
 * or a receiver session restored from its durable records.
 *
 * GET_INTAKE is answered in every state. GET_ASK and the Offer commands go to the intake (in direct
 * mode they answer `6985`); the Request-session commands (GET_INFO, READ_REQUEST, BEGIN_PAYMENT,
 * WRITE, COMMIT, READ_ACK, CONFIRM_ACK, GET_STATUS) go to the receiver session and answer `6985`
 * before REQUEST_READY. Thread-safe.
 */
class IrohaPeerNfcCardEndpointV1 private constructor(
    @JvmField val applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
    /** The Offer intake (intake mode); `null` in direct mode. */
    @JvmField val intake: IrohaPeerNfcOfferIntakeV1?,
    receiver: IrohaPeerNfcReceiverSessionV1?,
) {
    /** Notified when SUBMIT_OFFER hands a newly verified Offer to the wallet. */
    fun interface OfferSubmittedHandler {
        fun offerSubmitted(offer: IrohaPeerWireMessageV1)
    }

    private var hostedReceiver: IrohaPeerNfcReceiverSessionV1? = receiver

    /** The receiver session hosting the Request: installed after REQUEST_READY in intake mode. */
    val receiver: IrohaPeerNfcReceiverSessionV1?
        @Synchronized get() = hostedReceiver

    /** Whether this card hosts a Request built from an Offer that arrived over another carrier. */
    val isDirect: Boolean get() = intake == null

    /** Session identifier `s`; a defensive copy. */
    val sessionId: ByteArray
        get() = intake?.sessionId ?: requireNotNull(hostedReceiver).sessionId

    /** The current `IOI1` record. */
    @Synchronized
    fun intakeRecord(): IrohaPeerNfcIntakeRecordV1 = intake?.record() ?: requireNotNull(hostedReceiver).intakeRecord()

    /** The verified Offer awaiting the wallet's Request (intake mode, PREPARING_REQUEST). */
    val pendingOffer: IrohaPeerWireMessageV1? get() = intake?.pendingOffer

    /**
     * Answers every command except BEGIN_PAYMENT and COMMIT (see [preparePaymentAdmission] and
     * [prepareCommit]). SUBMIT_OFFER is executed here too; [submitOffer] also returns the Offer.
     */
    @Synchronized
    fun handle(command: IrohaPeerNfcCommandV1): ByteArray {
        if (command is IrohaPeerNfcCommandV1.SelectApplication) {
            if (command.applicationIdentifier != applicationIdentifier) {
                nfcFail(IrohaPeerNfcErrorV1.INVALID_APPLICATION_IDENTIFIER)
            }
            return ByteArray(0)
        }
        val offerIntake = intake
        if (offerIntake != null && command.isIntakeCommand()) return offerIntake.handle(command)
        return requireReceiver().handle(command)
    }

    /**
     * SUBMIT_OFFER: returns the verified Offer when this command moved the intake to
     * PREPARING_REQUEST, or `null` for an idempotent replay. In direct mode it answers `6985`.
     */
    @Synchronized
    fun submitOffer(command: IrohaPeerNfcCommandV1.SubmitOffer): IrohaPeerWireMessageV1? {
        val offerIntake = intake ?: run {
            requireNotNull(hostedReceiver).handle(command)
            return null
        }
        return offerIntake.submitOffer(command)
    }

    /**
     * Install the wallet's Request for the bound Offer [offerWireHash] and host it with the intake's
     * session identifier: PREPARING_REQUEST → REQUEST_READY.
     */
    @Synchronized
    fun installRequest(offerWireHash: ByteArray, request: ByteArray): IrohaPeerNfcReceiverSessionV1 {
        val offerIntake = intake ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        if (offerIntake.state != IrohaPeerNfcIntakeStateV1.PREPARING_REQUEST) nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        val session = IrohaPeerNfcReceiverSessionV1(
            offerIntake.sessionId,
            request,
            profilePolicy = offerIntake.profilePolicy,
            limits = offerIntake.limits,
        )
        offerIntake.installRequest(offerWireHash, request)
        hostedReceiver = session
        return session
    }

    /** The wallet declined the bound Offer [offerWireHash] with [reason] (1–65,535). */
    @Synchronized
    fun declineRequest(offerWireHash: ByteArray, reason: Int) {
        val offerIntake = intake ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)
        offerIntake.decline(offerWireHash, reason)
    }

    @Synchronized
    fun preparePaymentAdmission(command: IrohaPeerNfcCommandV1): IrohaPeerNfcPaymentAdmissionDispositionV1 =
        requireReceiver().preparePaymentAdmission(command)

    @Synchronized
    fun installPaymentAdmission(record: IrohaPeerNfcDurablePaymentAdmissionV1) {
        requireReceiver().installPaymentAdmission(record)
    }

    @Synchronized
    fun prepareCommit(command: IrohaPeerNfcCommandV1): IrohaPeerNfcCommitDispositionV1 =
        requireReceiver().prepareCommit(command)

    @Synchronized
    fun installDurableAcknowledgement(record: IrohaPeerNfcDurableAcknowledgementV1) {
        requireReceiver().installDurableAcknowledgement(record)
    }

    /**
     * Decodes and executes one raw APDU synchronously (tests, in-memory carriers). A newly submitted
     * Offer goes to [offerSubmitted]; the wallet later calls [installRequest] or [declineRequest].
     * BEGIN_PAYMENT and COMMIT succeed only after [admitPayment] or [durableCommit] returned an
     * exact persisted record.
     */
    @JvmOverloads
    fun process(
        apdu: ByteArray,
        offerSubmitted: OfferSubmittedHandler? = null,
        admitPayment: IrohaPeerNfcReceiverSessionV1.DurableAdmissionHandler? = null,
        durableCommit: IrohaPeerNfcReceiverSessionV1.DurableCommitHandler? = null,
    ): IrohaPeerNfcAPDUResponseV1 {
        val command = try {
            IrohaPeerNfcAPDUCodecV1.decode(apdu, applicationIdentifier)
        } catch (failure: IrohaPeerNfcExceptionV1) {
            return IrohaPeerNfcAPDUResponseV1.failure(failure.error)
        } catch (_: RuntimeException) {
            return IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.WRONG_DATA)
        }
        if (command is IrohaPeerNfcCommandV1.SubmitOffer) {
            var submitted: IrohaPeerWireMessageV1? = null
            val response = nfcRespond(IrohaPeerNfcStatusWordV1.WRONG_DATA) {
                submitted = submitOffer(command)
                IrohaPeerNfcAPDUResponseV1.of(IrohaPeerNfcStatusWordV1.SUCCESS)
            }
            submitted?.let { offerSubmitted?.offerSubmitted(it) }
            return response
        }
        if (command is IrohaPeerNfcCommandV1.BeginPayment || command is IrohaPeerNfcCommandV1.Commit) {
            val session = receiver ?: return IrohaPeerNfcAPDUResponseV1.failure(IrohaPeerNfcErrorV1.STATE_MISMATCH)
            return session.processCommand(command, admitPayment, durableCommit)
        }
        return nfcRespond(IrohaPeerNfcStatusWordV1.WRONG_DATA) {
            IrohaPeerNfcAPDUResponseV1(handle(command), IrohaPeerNfcStatusWordV1.SUCCESS)
        }
    }

    private fun requireReceiver(): IrohaPeerNfcReceiverSessionV1 =
        hostedReceiver ?: nfcFail(IrohaPeerNfcErrorV1.STATE_MISMATCH)

    companion object {
        /**
         * A tap-1 card that awaits the payer's Offer under a fresh random session identifier and, with
         * an [ask], answers GET_ASK with it until an Offer is bound.
         */
        @JvmStatic
        @JvmOverloads
        fun intake(
            applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
            profilePolicy: IrohaPeerNfcProfilePolicyV1,
            limits: IrohaPeerNfcLimitsV1 = IrohaPeerNfcLimitsV1.DEFAULT,
            ask: IrohaPeerAskV1? = null,
        ): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1(
            applicationIdentifier,
            IrohaPeerNfcOfferIntakeV1(profilePolicy, limits, ask = ask),
            null,
        )

        /** A tap-1 card around an existing [intake]. */
        @JvmStatic
        fun intake(
            applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
            intake: IrohaPeerNfcOfferIntakeV1,
        ): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1(applicationIdentifier, intake, null)

        /**
         * A card hosting [receiver]: a Request built from an Offer that arrived over another carrier,
         * or a session restored from its durable records.
         */
        @JvmStatic
        fun direct(
            applicationIdentifier: IrohaPeerNfcApplicationIdentifierV1,
            receiver: IrohaPeerNfcReceiverSessionV1,
        ): IrohaPeerNfcCardEndpointV1 = IrohaPeerNfcCardEndpointV1(applicationIdentifier, null, receiver)
    }
}

private fun IrohaPeerNfcCommandV1.isIntakeCommand(): Boolean = this is IrohaPeerNfcCommandV1.GetIntake ||
    this is IrohaPeerNfcCommandV1.GetAsk || this is IrohaPeerNfcCommandV1.BeginOffer ||
    this is IrohaPeerNfcCommandV1.WriteOffer || this is IrohaPeerNfcCommandV1.SubmitOffer
