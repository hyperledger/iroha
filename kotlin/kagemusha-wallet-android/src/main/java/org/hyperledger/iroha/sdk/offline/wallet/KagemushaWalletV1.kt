// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong

/** Native failure; -4 means the authenticated operation/Λ/Ω artifact loader is unavailable. */
class KagemushaWalletExceptionV1(
    @JvmField val status: Int,
    @JvmField val reason: Int = -1,
    @JvmField val platformCode: Int = 0,
) : IllegalStateException("KAGEMUSHA native status $status (reason $reason, platform $platformCode)") {
    companion object {
        /** There is deliberately no structural verifier or software-key fallback. */
        const val ARTIFACTS_UNAVAILABLE = -4
        /**
         * Design §5.3 runtime capacity refusal: free custody storage does not cover the operation.
         * Refused before commit; nothing debited or credited. Retry after freeing storage.
         */
        const val NOT_ENOUGH_STORAGE = -12
        /**
         * Design §5.3 runtime capacity refusal: available memory does not cover the installed
         * relations' peak proving memory. Refused before commit; never a device verdict.
         */
        const val NOT_ENOUGH_MEMORY = -14
        /**
         * The wallet's locally installed blacklist lists the counterparty: a payer refusing to pay
         * a listed receiver, or a receiver refusing to request or accept money from a listed payer.
         * Refused before any mutation; nothing debited, issued or credited.
         */
        const val BLOCKED = -15
        /** Native output violates the fixed status/payload contract. */
        const val INVALID_NATIVE_OUTPUT = -100
        /** Missing, stale or unauthenticated native bridge library. */
        const val BRIDGE_UNAVAILABLE = -101
    }
}

/** Native outcome with operation-specific projections; setup originals never establish monetary completion. */
class KagemushaWalletCallV1 internal constructor(
    @JvmField val status: Int,
    @JvmField val reason: Int,
    @JvmField val platformCode: Int,
    @JvmField val sequenceLow: Long,
    @JvmField val sequenceHigh: Long,
    @JvmField val detail: Int,
    bytes: ByteArray,
) {
    init {
        val carriesBytes = status == EPOCH_PROGRESS || status == DELETION_REVIEW || status == DELETED || status == CREDIT_PROJECTION || status == UNLOAD_CLAIM || status == COMPLETE || status == CREDIT_STATUS || status == SETUP || status == TIME_CHALLENGE || status == ACCOUNT_CHALLENGE || status == ACTIVATION || status == CLOSE_LOADS || status == 31 || status == 33 || status == 36 || status == LEDGER_INSTRUCTION || status == ENROLLMENT_LEDGER_INSTRUCTION || status == UNLOAD_CONFIRMATION || status == ACTIVATION_CONFIRMATION || status == ACTIVATION_PROGRESS || status == ACTIVATION_REJECTED || status in listOf(18, 19, 23, 24, 25, 27, 28, 37, 38)
        if (status in listOf(41, 43) || (status >= 0 && status !in UNKNOWN..ENROLLMENT_LEDGER_INSTRUCTION) || bytes.size > when (status) { EPOCH_PROGRESS -> 16; DELETION_REVIEW -> 254; DELETED -> 32; DELETION_REVIEW_DISCARDED, NOT_DELETED -> 0; CREDIT_PROJECTION -> 10_092; ACTIVATION, ENROLLMENT_DISPATCH, CLOSE_LOADS, 36, UNLOAD_CLAIM -> 16_384; LEDGER_INSTRUCTION, ENROLLMENT_LEDGER_INSTRUCTION -> 65_536; 24 -> KagemushaWalletEnrollmentV1.REQUEST_MAX_BYTES; 25 -> 262_144; 28 -> 1024; 37 -> 1028; 38 -> 73_740; 31 -> 21_024; 33, UNLOAD_CONFIRMATION, ACTIVATION_CONFIRMATION, ACTIVATION_PROGRESS, ACTIVATION_REJECTED -> 32; else -> 10_000 } ||
            (if (carriesBytes) bytes.isEmpty() else bytes.isNotEmpty()) ||
            ((status == TIME_CHALLENGE || status == ACCOUNT_CHALLENGE) && (bytes.size != 32 || sequenceLow <= 0 || sequenceHigh != 0L)) ||
            (status in listOf(ACTIVATION, CLOSE_LOADS, 31, 32, 34, 35, 36, ACTIVATION_NOT_STARTED, LEDGER_INSTRUCTION, UNLOAD_CLAIM, COLLECTION_IDLE, DELETED, DELETION_REVIEW_DISCARDED, NOT_DELETED) && (sequenceLow != 0L || sequenceHigh != 0L || detail != 0)) ||
            (status in COLLECTION_IDLE..COLLECTED && detail != 0) ||
            (status == EPOCH_PROGRESS && (sequenceHigh != 0L || detail != 0 || bytes.size != 16)) ||
            (status == DELETION_REVIEW && (sequenceLow <= 0 || sequenceHigh != 0L || detail != 0 || bytes.size != 254)) ||
            (status == DELETED && (bytes.size != 32 || bytes.all { it == 0.toByte() })) ||
            (status == OPENED && (sequenceLow <= 0 || sequenceHigh != 0L)) ||
            ((status in 18..28 || status in 37..39 || status in ENROLLMENT_LOCAL_ABANDONED..ENROLLMENT_LEDGER_INSTRUCTION) && (sequenceLow <= 0 || sequenceHigh != 0L || detail != 0)) ||
            (status in listOf(UNLOAD_CONFIRMATION, ACTIVATION_CONFIRMATION, ACTIVATION_REJECTED) && java.lang.Long.compareUnsigned(sequenceLow, 2L) < 0) ||
            (status in listOf(18, 23) && bytes.size != 32) || (status == 19 && bytes.size != 161) ||
            (status in listOf(33, UNLOAD_CONFIRMATION, ACTIVATION_CONFIRMATION, ACTIVATION_PROGRESS, ACTIVATION_REJECTED) && (sequenceLow == 0L || sequenceHigh != 0L || detail != 0 || bytes.size != 32 || bytes.all { it == 0.toByte() }))) {
            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
    }
    private val retainedBytes = bytes.copyOf()
    /** Exact canonical bytes returned by Rust; this accessor never assembles or signs again. */
    fun bytes(): ByteArray = retainedBytes.copyOf()
    private fun invalid(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    /** Only ordinary operation outcomes can be returned from Bootstrap or Archive. */
    internal fun completion(): KagemushaWalletCallV1 {
        if (status !in UNKNOWN..PREPARING) invalid()
        return this
    }
    /** Setup originals are transport bytes, never a monetary completion. */
    internal fun original(): ByteArray {
        if (status != SETUP || sequenceLow != 0L || sequenceHigh != 0L || detail != 0 || retainedBytes.isEmpty()) invalid()
        return retainedBytes.copyOf()
    }
    internal fun feeClaimInput(beneficiary: ByteArray): KagemushaWalletSetupInputV1 {
        if (status != 31) invalid()
        return KagemushaWalletSetupInputV1(26, first = retainedBytes, second = beneficiary)
    }
    internal fun feeClaimOriginal(): ByteArray {
        if (status != 36) invalid()
        return retainedBytes.copyOf()
    }
    internal fun unloadClaimOriginal(): ByteArray {
        if (status != UNLOAD_CLAIM) invalid()
        return retainedBytes.copyOf()
    }
    internal fun creditedInput(): KagemushaWalletSetupInputV1 {
        require(status == COMPLETE || status == CREDIT_STATUS) { "Receive or CreditStatus required" }
        return KagemushaWalletSetupInputV1(if (status == CREDIT_STATUS) 17 else 16, first = retainedBytes)
    }
    internal fun exchange(owner: Any): KagemushaWalletTimeExchangeV1 {
        if (status != TIME_CHALLENGE || sequenceLow <= 0 || sequenceHigh != 0L || detail != 0 ||
            retainedBytes.size != 32 || retainedBytes.all { it == 0.toByte() }) invalid()
        return KagemushaWalletTimeExchangeV1(owner, sequenceLow, retainedBytes)
    }
    internal fun timeRetained() {
        if (status != TIME_RETAINED || sequenceLow != 0L || sequenceHigh != 0L || detail != 0 || retainedBytes.isNotEmpty()) invalid()
    }
    internal fun idle() {
        if (status != IDLE || sequenceLow != 0L || sequenceHigh != 0L || detail != 0 || retainedBytes.isNotEmpty()) invalid()
    }
    override fun toString(): String = "KagemushaWalletCallV1(status=$status, bytes=[REDACTED])"
    companion object {
        const val EPOCH_PROGRESS = 57
        /**
         * Design §3.2 no-marker abandonment: the slot is abandoned locally and there is nothing
         * to submit. It never carries bytes. The marker form is [ENROLLMENT_ABANDONMENT].
         */
        const val ENROLLMENT_LOCAL_ABANDONED = 58
        /** Exact ledger instruction for the enrollment owner's retained signed abandonment. */
        const val ENROLLMENT_LEDGER_INSTRUCTION = 59
        const val UNKNOWN = 0
        const val COMPLETE = 1
        const val PENDING = 2
        const val NOT_PERFORMED = 3
        const val ARCHIVED = 4
        const val DELIVERY_DATA_LOSS = 5
        const val IDLE = 6
        const val CAUGHT_UP = 7
        const val CHECKPOINT = 8
        const val FOLDED = 9
        const val CREDIT_STATUS = 10
        /** Durable intent exists, but irreversible Advance has not selected it. */
        const val PREPARING = 11
        const val SETUP = 12
        const val TIME_CHALLENGE = 13
        const val TIME_RETAINED = 14
        const val ACCOUNT_CHALLENGE = 15
        const val OPENED = 16
        const val ACTIVATION = 17
        const val ENROLLMENT_READY = 26
        const val ENROLLMENT_DISPATCH = 27
        /** Design §3.2 marker abandonment: the exact retained signed Abandonment frame to submit. */
        const val ENROLLMENT_ABANDONMENT = 28
        const val BACKGROUND_STATUS = 29
        const val CLOSE_LOADS = 30
        const val LEDGER_INSTRUCTION = 40
        const val UNLOAD_CONFIRMATION = 42
        const val ACTIVATION_CONFIRMATION = 44
        const val ACTIVATION_PROGRESS = 45
        const val ACTIVATION_NOT_STARTED = 46
        const val CREDIT_PROJECTION = 47
        const val UNLOAD_CLAIM = 48
        const val ACTIVATION_REJECTED = 49
        const val COLLECTION_IDLE = 50
        const val COLLECTION_PROGRESS = 51
        const val COLLECTED = 52
        const val DELETION_REVIEW = 53
        const val DELETED = 54
        const val DELETION_REVIEW_DISCARDED = 55
        const val NOT_DELETED = 56
    }
}

/**
 * One exclusive native wallet owner. Calls may run on workers; activity and payment arrival
 * can preempt folding because this wrapper does not hold a managed lock across a native call.
 * Closing joins cooperative folding and retains every already committed payment in custody.
 *
 * Created only after account admission through an independently provisioned native runtime.
 */
class KagemushaWalletV1 internal constructor(handle: Long) : Closeable, KagemushaWalletCleanupResourceV1 {
    private val owner = AtomicLong(handle)
    private val deletionGate = KagemushaWalletDeletionGateV1()
    private val closeGate = Any()
    private val retired = java.util.concurrent.atomic.AtomicBoolean(false)
    @Volatile private var closeFailure: Throwable? = null
    private fun handle(): Long { deletionGate.requireOrdinary(); return custodyHandle() }
    private fun custodyHandle(): Long {
        closeFailure?.let { throw it }
        check(!retired.get()) { "Native wallet owner is retired" }
        return owner.get().takeIf { it > 0 } ?: throw KagemushaWalletExceptionV1(-2)
    }
    /** Copy exact admitted account/asset originals from the same Native owner. */
    fun metadata(): KagemushaWalletMetadataV1 = KagemushaWalletMetadataV1(observeProjection(0))
    /** Observe a released request without repeating preparation, proving or signing. */
    fun releasedOutputForRequest(requestId: ByteArray): KagemushaWalletReleasedOutputV1 =
        KagemushaWalletReleasedOutputV1(observeProjection(1, requestId))
    /** Read the exact retained output for an already known operation identity. */
    fun releasedOutputForOperation(operationId: ByteArray): KagemushaWalletReleasedOutputV1 =
        KagemushaWalletReleasedOutputV1(observeProjection(2, operationId))
    /** True absence never reserves a replacement Load ordinal or constructs an instruction. */
    fun preparedLedgerLoad(requestId: ByteArray): KagemushaWalletPreparedLoadV1? {
        val retained = requestId.copyOf()
        return KagemushaWalletPreparedLoadV1.observation(observeProjection(3, retained), retained)
    }
    /** Read bounded Native fold/work diagnostics as exact UTF-8 JSON, without advancing custody.
     * Diagnostics confer no readiness, completion or payment authority. Bracket this observation
     * with the caller's monotonic clock before mapping Native's process-local timing fields. */
    fun foldMetricsJSON(): String = KagemushaWalletFoldMetricsV1.decode(observeProjection(4))

    private fun observeProjection(selector: Int, identity: ByteArray = byteArrayOf()): ByteArray {
        val input = identity.copyOf()
        require(selector in 0..4 && if (selector == 0 || selector == 4) input.isEmpty() else input.size == 32 && input.any { it != 0.toByte() })
        val owner = handle() // same close/deletion fence as every ordinary owner operation
        val result = try { KagemushaWalletNativeWorkerV1.shared.run { KagemushaWalletObservationNativeV1.observe(owner, selector, input) } }
            catch (_: LinkageError) { throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE) }
            ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return result.original(intArrayOf(5268, 20_066, 20_066, 65_756,
            KagemushaWalletFoldMetricsV1.MAX_ORIGINAL_BYTES)[selector])
    }
    private fun call(operation: Int, first: ByteArray = byteArrayOf(), second: ByteArray = byteArrayOf()): KagemushaWalletCallV1 {
        val value = KagemushaWalletNativeCallsV1.call(handle(), operation, first.copyOf(), second.copyOf())
            ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (value.status < 0) throw KagemushaWalletExceptionV1(value.status, value.reason, value.platformCode)
        return value.completion()
    }
    private fun execute(input: KagemushaWalletOperationInputV1): KagemushaWalletCallV1 {
        val value = KagemushaWalletNativeCallsV1.execute(handle(), input.requestId(), input.selector,
            input.amount.low, input.amount.high, input.first(), input.second(), input.third())
            ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (value.status < 0) throw KagemushaWalletExceptionV1(value.status, value.reason, value.platformCode)
        return value.completion()
    }
    private fun setup(input: KagemushaWalletSetupInputV1): KagemushaWalletCallV1 {
        val value = KagemushaWalletNativeCallsV1.setup(handle(), input.identity(), input.selector,
            input.amount.low, input.amount.high, input.token, input.first(), input.second(), input.third())
            ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (value.status < 0) throw KagemushaWalletExceptionV1(value.status, value.reason, value.platformCode)
        return value
    }
    /** Display native-selected review DATA before explicit destructive confirmation. */
    fun reviewCustodyDeletion(): KagemushaWalletDeletionReviewV1 = deletionGate.review { setup(KagemushaWalletSetupInputV1(48)) }
    /** Permanently destroy payment-key custody. Display the review warning first.
     * Any error freezes ordinary calls until recovery proves a definitive outcome. */
    fun destructivelyDeleteCustody(review: KagemushaWalletDeletionReviewV1): ByteArray =
        deletionGate.confirm(review) { token -> deletionSetup(KagemushaWalletSetupInputV1(49, token = token)) }
    /** Recover the retained owner’s attempted deletion; restart cleanup belongs to native custody reconciliation. */
    fun resumeCustodyDeletion(): KagemushaWalletDeletionStatusV1 =
        deletionGate.resume { deletionSetup(KagemushaWalletSetupInputV1(50)) }
    /** Discard an unused review; this cannot undo an attempted deletion. */
    fun discardCustodyDeletionReview(review: KagemushaWalletDeletionReviewV1) =
        deletionGate.discard(review) { token -> setup(KagemushaWalletSetupInputV1(51, token = token)) }
    private fun deletionSetup(input: KagemushaWalletSetupInputV1): KagemushaWalletCallV1 {
        val value = KagemushaWalletNativeCallsV1.setup(custodyHandle(), input.identity(), input.selector,
            input.amount.low, input.amount.high, input.token, input.first(), input.second(), input.third())
            ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (value.status < 0) throw KagemushaWalletExceptionV1(value.status, value.reason, value.platformCode)
        return value
    }
    /** Complete restart-safe native enrollment Bootstrap. */
    fun bootstrap(): KagemushaWalletCallV1 = setup(KagemushaWalletSetupInputV1(0)).completion()
    /** Freeze the exact next Load instruction under durable Native request custody.
     * Retry the same request ID and amount after uncertain delivery. */
    fun prepareLedgerLoad(requestId: ByteArray, amount: KagemushaWalletUInt128V1): ByteArray {
        val result = setup(KagemushaWalletSetupInputV1(27, identity = requestId, amount = amount))
        if (result.status != KagemushaWalletCallV1.LEDGER_INSTRUCTION) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return result.bytes()
    }
    /** Canonical instruction framing; ledger execution still validates every authority. */
    fun ledgerInstruction(kind: KagemushaWalletLedgerTransportV1, original: ByteArray): ByteArray {
        val result = setup(KagemushaWalletSetupInputV1(29, token = kind.tag, first = original))
        if (result.status != KagemushaWalletCallV1.LEDGER_INSTRUCTION) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return result.bytes()
    }
    /** Native authenticates this exact Unload in the selected committed block's successful transaction. */
    fun confirmLedgerUnload(transactionHash: ByteArray, original: ByteArray): KagemushaWalletUnloadConfirmationV1 =
        KagemushaWalletUnloadConfirmationV1(setup(KagemushaWalletSetupInputV1(30, identity = transactionHash, first = original)))
    /** Native's exact retained confirmation or verified history for this transaction and claim.
     * Absent inclusion is explicit; malformed or mismatched custody remains an error. */
    fun unloadFinalityProgress(transactionHash: ByteArray, original: ByteArray): KagemushaWalletUnloadFinalityV1 =
        KagemushaWalletUnloadFinalityV1(setup(KagemushaWalletSetupInputV1(33, identity = transactionHash, first = original)))
    /** Verify the next contiguous ordinary proof for this exact Unload's independent cursor. */
    fun ingestUnloadFinality(transactionHash: ByteArray, original: ByteArray,
        finality: ByteArray): KagemushaWalletLedgerProgressV1 = KagemushaWalletLedgerProgressV1(
        setup(KagemushaWalletSetupInputV1(34, identity = transactionHash, first = original, second = finality)))
    /** Durably admit this exact existing-account-signed outer Activate before its first POST.
     * Intake is DATA only. An already retained attempt may report family confirmation from
     * another retained same-Activation transaction; this is not this outer's execution result. */
    fun retainActivationAttempt(signedWire: ByteArray): KagemushaWalletActivationFinalityV1 =
        KagemushaWalletActivationFinalityV1(setup(KagemushaWalletSetupInputV1(46, first = signedWire)))
    /** Recover Native's durable same-Activation family confirmation for a retained attempt. */
    fun confirmLedgerActivation(signedWire: ByteArray): KagemushaWalletActivationConfirmationV1 =
        KagemushaWalletActivationConfirmationV1(setup(KagemushaWalletSetupInputV1(35, first = signedWire)))
    /** Verify one contiguous original for this Activate's independent Native history. */
    fun ingestActivationFinality(signedWire: ByteArray, original: ByteArray): KagemushaWalletActivationFinalityV1 =
        KagemushaWalletActivationFinalityV1(setup(KagemushaWalletSetupInputV1(36, first = signedWire, second = original)))
    /** Exact retained attempt's independent progress, or genuine same-Activation family
     * confirmation. Family confirmation does not assert this particular outer succeeded. */
    fun activationFinalityProgress(signedWire: ByteArray): KagemushaWalletActivationFinalityV1 =
        KagemushaWalletActivationFinalityV1(setup(KagemushaWalletSetupInputV1(37, first = signedWire)))
    /** Exact retained Activate frame for ledger submission; this is not activation confirmation. */
    fun activation(): ByteArray {
        val result = setup(KagemushaWalletSetupInputV1(15))
        if (result.status != KagemushaWalletCallV1.ACTIVATION) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return result.bytes()
    }
    /** Exact native signed CloseLoads frame for ledger submission, not closure confirmation.
     * Reuse requestId for exact retries; use a fresh id after a preissued Load and new complete consumer. */
    fun closeLoads(requestId: ByteArray): ByteArray {
        val result = setup(KagemushaWalletSetupInputV1(19, identity = requestId))
        if (result.status != KagemushaWalletCallV1.CLOSE_LOADS) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        return result.bytes()
    }
    /** Canonical ledger claim for a completed Unload request, never settlement confirmation.
     * Native selects the admitted account and exact retained package/quote. A charged Unload
     * requires the quote's canonical beneficiary; uncharged Unload requires absence. */
    @JvmOverloads
    fun unloadClaimTransport(requestId: ByteArray, chargeBeneficiary: ByteArray? = null): ByteArray {
        require(chargeBeneficiary == null || chargeBeneficiary.isNotEmpty()) { "charge beneficiary original" }
        return setup(KagemushaWalletSetupInputV1(45, identity = requestId,
            first = chargeBeneficiary ?: ByteArray(0))).unloadClaimOriginal()
    }
    /** One bounded native collection turn. No foreign path or acknowledgement is accepted.
     * Keys, permanent replay records and required fee/activation originals remain retained.
     * Repeat the same sequence after interruption until Collected. */
    fun collectRetainedStep(sequence: KagemushaWalletUInt128V1): KagemushaWalletCollectionStatusV1 =
        KagemushaWalletCollectionStatusV1.from(setup(KagemushaWalletSetupInputV1(47, amount = sequence)), sequence)

    /** Read both exact originals from one native-retained fee claim; null means no pending claim. */
    fun feeClaim(creditId: ByteArray): KagemushaWalletFeeClaimV1? {
        val result = setup(KagemushaWalletSetupInputV1(20, identity = creditId))
        if (result.status == 32) return null
        if (result.status != 31) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        val original = result.bytes()
        return KagemushaWalletFeeClaimV1(
            setup(KagemushaWalletSetupInputV1(21, first = original)).original(),
            setup(KagemushaWalletSetupInputV1(22, first = original)).original(),
        )
    }
    /** Canonical ledger FeeClaim; beneficiary is an original AccountId checked by Native
     * against the retained schedule. Null means no pending retained claim. */
    fun feeClaimTransport(creditId: ByteArray, beneficiary: ByteArray): ByteArray? {
        val retained = setup(KagemushaWalletSetupInputV1(20, identity = creditId))
        if (retained.status == 32) return null
        return setup(retained.feeClaimInput(beneficiary)).feeClaimOriginal()
    }
    /** Verify one bounded next native Sumeragi proof and durably select its prefix. */
    fun ingestLedgerFinality(original: ByteArray): KagemushaWalletLedgerProgressV1 =
        KagemushaWalletLedgerProgressV1(setup(KagemushaWalletSetupInputV1(23, first = original)))
    /** Protected native Load epoch, retaining older committees for delayed receipts. */
    fun epochProgress(): KagemushaWalletEpochProgressV1 =
        KagemushaWalletEpochProgressV1(setup(KagemushaWalletSetupInputV1(52)))
    /** Verify one exact incumbent boundary and durably retain its successor. */
    fun ingestEpochBoundary(expectedEpoch: java.math.BigInteger, original: ByteArray): KagemushaWalletEpochProgressV1 {
        require(expectedEpoch.signum() >= 0 && expectedEpoch.bitLength() <= 64) { "u64 epoch required" }
        return KagemushaWalletEpochProgressV1(setup(KagemushaWalletSetupInputV1(53,
            amount = KagemushaWalletUInt128V1(expectedEpoch.toLong(), 0), first = original)))
    }
    /** Synchronize at most 64 durable epoch boundaries for the exact receipt, without crediting value.
     * Cancellation and limits preserve progress. Repeat while boundaryHeight is below the receipt
     * height; ordinary load independently verifies and refuses a missing epoch afterward. */
    fun synchronizeLoadEpochs(original: KagemushaWalletLoadOriginalV1,
        transport: org.hyperledger.iroha.sdk.client.HttpClientTransport,
        canonicalAuth: org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth,
        requireCurrentOwner: Runnable, maximumBoundaries: Int = 64,
    ): java.util.concurrent.CompletableFuture<KagemushaWalletEpochProgressV1> =
        synchronizeKagemushaEpochsV1(original.blockHeight, maximumBoundaries, requireCurrentOwner,
            { epochProgress() },
            { height -> transport.getKagemushaWalletLoadEpochOriginalV1(original.selection, height,
                canonicalAuth, requireCurrentOwner) },
            { epoch, bytes -> ingestEpochBoundary(epoch, bytes) })
    /** Selected native progress, or null before any checkpoint has been selected. */
    fun ledgerProgress(): KagemushaWalletLedgerProgressV1? {
        val result = setup(KagemushaWalletSetupInputV1(24))
        return if (result.status == 34) null else KagemushaWalletLedgerProgressV1(result)
    }
    /** Native authenticates exact World and payout-row originals against its selected tip. */
    fun acknowledgeFeePayout(creditId: ByteArray, world: ByteArray, payout: ByteArray) {
        val result = setup(KagemushaWalletSetupInputV1(25, identity = creditId, first = world, second = payout))
        if (result.status != 35) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    }
    /** Native issues the open Request for [amount] from its selected policy and retains it by digest;
     * a retry of this identity returns its exact original bytes. Payer wallet, payer account and send
     * ordinal are zero: the receiver signature covers only the terms, and the payer completes them. */
    fun request(setupId: ByteArray, amount: KagemushaWalletUInt128V1, feeSchedule: ByteArray? = null, feeCertificate: ByteArray? = null): ByteArray {
        require((feeSchedule == null) == (feeCertificate == null)) { "fee originals must be paired" }
        if (feeSchedule != null) require(feeSchedule.isNotEmpty() && feeCertificate!!.isNotEmpty()) { "fee originals must not be empty" }
        return setup(KagemushaWalletSetupInputV1(2, setupId, amount,
            second = feeSchedule ?: byteArrayOf(), third = feeCertificate ?: byteArrayOf())).original()
    }
    /** Native-selected asset and fee digest for local original lookup; no operation authority. */
    fun requestFeeSelection(): KagemushaWalletRequestFeeSelectionV1 =
        KagemushaWalletRequestFeeSelectionV1(setup(KagemushaWalletSetupInputV1(38)))
    /** Authenticate two full PolicyData envelopes against the currently selected fee policy. */
    fun validateRequestFeePolicy(scheduleEnvelope: ByteArray, certificatesEnvelope: ByteArray): KagemushaWalletRequestFeeSelectionV1 =
        KagemushaWalletRequestFeeSelectionV1(setup(KagemushaWalletSetupInputV1(40,
            first = scheduleEnvelope, second = certificatesEnvelope)))
    /** Exact signed fee DATA feeds the ordinary Native open Request for [amount]. Null is accepted only
     * by Native's zero-fee rule; never retry a failed nonzero-fee Request with missing originals. */
    fun requestWithFeePolicy(setupId: ByteArray, amount: KagemushaWalletUInt128V1, scheduleEnvelope: ByteArray?, certificatesEnvelope: ByteArray?): ByteArray {
        require((scheduleEnvelope == null) == (certificatesEnvelope == null)) { "fee PolicyData must be paired" }
        if (scheduleEnvelope != null) require(scheduleEnvelope.isNotEmpty() && certificatesEnvelope!!.isNotEmpty())
        return setup(KagemushaWalletSetupInputV1(39, setupId, amount,
            first = scheduleEnvelope ?: byteArrayOf(), second = certificatesEnvelope ?: byteArrayOf())).original()
    }
    /** The payer companion of this wallet's own [payment] (its exact Payment original): canonical
     * `KagemushaWalletPayerCompanionV1` bytes of the retained Send's historical credential and exact
     * issuer certificate set. Native verifies exact Payment ownership against that Send's durable
     * custody, so recovery also works after credential renewal. Carry it beside the Payment
     * (`IrohaPeerWalletPaymentV1`) and retain both for exact-byte retries; it grants no authority. */
    fun paymentCompanion(payment: ByteArray): ByteArray =
        setup(KagemushaWalletSetupInputV1(55, first = payment)).original()
    /** Convert durable Receive/Status bytes to canonical peer evidence, without granting a proof verdict. */
    fun credited(received: KagemushaWalletCallV1): ByteArray {
        return setup(received.creditedInput()).original()
    }
    /** Native verifies delivery evidence and derives its private Archive operation. */
    fun acceptCredited(original: ByteArray): KagemushaWalletCallV1 =
        setup(KagemushaWalletSetupInputV1(3, first = original)).completion()
    /** Verify delivery for this exact local Send; result belongs to its private Archive intent. */
    fun acceptCreditedForSend(sendRequestId: ByteArray, original: ByteArray): KagemushaWalletCallV1 =
        setup(KagemushaWalletSetupInputV1(41, identity = sendRequestId, first = original)).completion()
    /** Read exact bound Archive completion, including after original Send witness collection. */
    fun creditedStatusForSend(sendRequestId: ByteArray, original: ByteArray): KagemushaWalletCallV1 =
        setup(KagemushaWalletSetupInputV1(42, identity = sendRequestId, first = original)).completion()
    /** Observe one exact durable Receive, using fresh covering evidence before or after collection. */
    fun receivedCredit(receiveRequestId: ByteArray): KagemushaWalletCreditProjectionV1 =
        KagemushaWalletCreditProjectionV1(setup(KagemushaWalletSetupInputV1(43, identity = receiveRequestId))).requireReceiver()
    /** Verify a later receipt against the exact completed Archive anchor, without another Advance. */
    fun deliveredCredit(sendRequestId: ByteArray, anchor: ByteArray, newer: ByteArray? = null): KagemushaWalletCreditProjectionV1 {
        require(newer == null || newer.isNotEmpty()) { "new Credited original" }
        return KagemushaWalletCreditProjectionV1(setup(KagemushaWalletSetupInputV1(44,
            identity = sendRequestId, first = anchor, second = newer ?: byteArrayOf()))).requirePayer()
    }
    /**
     * Verify the receiver's receipt for one exact committed Send before any Archive: the same binding
     * and verifier as [acceptCreditedForSend], with no Advance, so the Send's fold keeps running. Call
     * [acceptCreditedForSend] later with the same original to Archive it. A completed Archive of that
     * original returns its [deliveredCredit] projection.
     */
    fun verifiedDelivery(sendRequestId: ByteArray, credited: ByteArray): KagemushaWalletCreditProjectionV1 =
        KagemushaWalletCreditProjectionV1(setup(KagemushaWalletSetupInputV1(54,
            identity = sendRequestId, first = credited))).requirePayer()
    /** Only the native nonce leaves clock custody; this token has no serialized form. */
    fun beginTimeExchange(): KagemushaWalletTimeExchangeV1 =
        setup(KagemushaWalletSetupInputV1(4)).exchange(this)
    /** Consume the native token and retain the verified response before TimeAnchor refresh. */
    fun finishTimeExchange(exchange: KagemushaWalletTimeExchangeV1, anchor: ByteArray, certificate: ByteArray) {
        // Copy and bound the originals before consuming this owner's one-use challenge.
        val input = KagemushaWalletSetupInputV1(5, token = exchange.tokenFor(this), first = anchor, second = certificate)
        handle()
        exchange.consume(this)
        setup(input).timeRetained()
    }
    /** Discard an unanswered native exchange without accepting or refreshing an anchor. */
    fun cancelTimeExchange(exchange: KagemushaWalletTimeExchangeV1) {
        val input = KagemushaWalletSetupInputV1(6, token = exchange.tokenFor(this))
        handle()
        exchange.consume(this)
        setup(input).idle()
    }
    /** Frame exact original bytes for peer transport, without monetary admission. */
    fun envelope(kind: KagemushaWalletTransportKindV1, original: ByteArray): ByteArray =
        setup(KagemushaWalletSetupInputV1(6 + kind.tag, first = original)).original()
    /** Extract an expected original kind under this native wallet's scheme, without accepting value. */
    fun original(kind: KagemushaWalletTransportKindV1, envelope: ByteArray): ByteArray =
        setup(KagemushaWalletSetupInputV1(10 + kind.tag, first = envelope)).original()
    /** Load the exact ordinary-ledger receipt and native BLS finality evidence. */
    fun load(requestId: ByteArray, receipt: ByteArray, finality: ByteArray): KagemushaWalletCallV1 =
        execute(KagemushaWalletOperationInputV1(requestId, 0, first = receipt, second = finality))
    /** Authenticate Send and its fully folded source before fresh hardware UI confirmation. */
    fun reviewSend(request: ByteArray, destinationAccountOriginal: ByteArray): KagemushaWalletReviewV1 {
        require(request.isNotEmpty() && request.size <= 10_000)
        require(destinationAccountOriginal.isNotEmpty() && destinationAccountOriginal.size <= 4_096)
        return review(1, KagemushaWalletUInt128V1(0, 0), request, destinationAccountOriginal, KagemushaWalletReviewProjectionV1.Kind.SEND)
    }
    /** Receive selects the durably issued Request locally by the Payment's digest. */
    fun receive(requestId: ByteArray, payment: ByteArray, payerCredential: ByteArray, certificates: ByteArray): KagemushaWalletCallV1 =
        execute(KagemushaWalletOperationInputV1(requestId, 2, first = payment, second = payerCredential, third = certificates))
    /** Receive the exact Payment and payer companion of one carrier (`IrohaPeerWalletPaymentV1`). Native
     * checks the companion against the Payment, completes the durably issued open Request from it and
     * performs ordinary Receive authentication; the companion is never payment authority.
     */
    fun receiveWithCompanion(requestId: ByteArray, payment: ByteArray, companion: ByteArray): KagemushaWalletCallV1 =
        execute(KagemushaWalletOperationInputV1(requestId, 10, first = payment, second = companion))

    /** Refresh from exact signed originals; Native derives maps and all effective values. */
    fun refresh(requestId: ByteArray, kind: KagemushaWalletRefreshKindV1, update: ByteArray, certificates: ByteArray): KagemushaWalletCallV1 =
        execute(KagemushaWalletOperationInputV1(requestId, kind.selector, first = update, second = certificates))
    /** Install a signed blacklist locally; a replacement's list version must increase and
     * reinstalling the held list is idempotent. The wallet then refuses to pay a listed receiver
     * and to request or accept money from a listed payer ([KagemushaWalletExceptionV1.BLOCKED]).
     * Nothing is sent to peers or proved; this is no wallet operation and has no retry identity.
     * COMPLETE carries the held list's 32-byte object digest.
     */
    fun installBlacklist(list: ByteArray, certificates: ByteArray): KagemushaWalletCallV1 =
        execute(KagemushaWalletOperationInputV1(ByteArray(32), 5, first = list, second = certificates))
    /** Authenticate the exact payout, signed charge and canonical beneficiary before confirmation. */
    fun reviewUnload(amount: KagemushaWalletUInt128V1, quote: ByteArray? = null, certificates: ByteArray? = null,
        chargeBeneficiary: ByteArray? = null): KagemushaWalletReviewV1 {
        require((quote == null) == (certificates == null) && (quote == null) == (chargeBeneficiary == null)) {
            "quote, certificates and beneficiary must be supplied together"
        }
        if (quote != null) require(quote.isNotEmpty())
        require(amount.low != 0L || amount.high != 0L)
        require((quote?.size ?: 0) <= 1_024)
        val companion = if (quote == null) byteArrayOf()
            else KagemushaWalletUnloadChargeReviewV1.encode(checkNotNull(certificates), checkNotNull(chargeBeneficiary))
        return review(8, amount, quote ?: byteArrayOf(), companion, KagemushaWalletReviewProjectionV1.Kind.UNLOAD)
    }
    private fun review(selector: Int, amount: KagemushaWalletUInt128V1, first: ByteArray, second: ByteArray, expected: KagemushaWalletReviewProjectionV1.Kind): KagemushaWalletReviewV1 {
        val wallet = handle()
        var reply: KagemushaWalletReviewReplyV1? = null
        try {
            reply = KagemushaWalletNativeCallsV1.review(wallet, selector, amount.low, amount.high, first.copyOf(), second.copyOf())
            return (reply ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)).review(this, expected)
        } catch (failure: KagemushaWalletExceptionV1) {
            if (failure.status == KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT) {
                val token = reply?.cleanupToken()
                try {
                    if (token == null) close()
                    else checked(KagemushaWalletNativeCallsV1.discardReview(wallet, token))
                } catch (cleanup: Throwable) {
                    if(failure !== cleanup)failure.addSuppressed(cleanup)
                    try { close() } catch (retirement: Throwable) { if(failure !== retirement)failure.addSuppressed(retirement) }
                }
            }
            throw failure
        }
    }
    /** Consume the exact reviewed Native operation after fresh hardware confirmation. Native rechecks its whole source. */
    fun executeReviewed(review: KagemushaWalletReviewV1, requestId: ByteArray): KagemushaWalletCallV1 {
        word(requestId); require(requestId.any { it != 0.toByte() })
        val value = handle()
        val token = review.consume(this)
        try {
            val reply = KagemushaWalletNativeCallsV1.executeReviewed(value, token, requestId.copyOf())
                ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            if (reply.status < 0) throw KagemushaWalletExceptionV1(reply.status, reply.reason, reply.platformCode)
            return reply.completion()
        } catch (failure: Throwable) {
            // Native may have consumed this token before failure. Closed then means no unused
            // review remains; it is never treated as acknowledgement of owner release.
            try {
                val status=KagemushaWalletNativeCallsV1.discardReview(value,token)
                if(status!=0 && status!=-2)checked(status)
            }catch(cleanup:Throwable){
                if(failure !== cleanup)failure.addSuppressed(cleanup)
                try{close()}catch(retirement:Throwable){if(failure !== retirement)failure.addSuppressed(retirement)}
            }
            throw failure
        }
    }
    /** Discard an unused review on a worker without creating intent, payment or monetary authority. */
    fun discardReview(review: KagemushaWalletReviewV1) {
        val value = handle(); val token = review.consume(this)
        checked(KagemushaWalletNativeCallsV1.discardReview(value, token))
    }
    /** Same actual one-use discard operation, retained for the current managed integration. */
    fun cancelReview(review:KagemushaWalletReviewV1)=discardReview(review)
    /** Enter Retiring under native folded-state checks. */
    fun retire(requestId: ByteArray): KagemushaWalletCallV1 = execute(KagemushaWalletOperationInputV1(requestId, 9))
    /** Resolve the local request identity, including distinct Preparing and irreversible Pending. */
    fun requestStatus(requestId: ByteArray): KagemushaWalletCallV1 {
        word(requestId); require(requestId.any { it != 0.toByte() }); return call(5, requestId)
    }
    /** Retrieve exact retained bytes; unknown, pending and delivery loss remain distinct. */
    fun retry(operationId: ByteArray): KagemushaWalletCallV1 { word(operationId); return call(1, operationId) }
    /** Reconcile and finish the selected operation without a second debit. */
    fun resume(): KagemushaWalletCallV1 = call(2)
    /** Observe the native worker without waiting for its proof or preempting it.
     * A retained failure is thrown; later activity/payment can resume after observation. */
    fun foldStatus(): KagemushaWalletBackgroundStatusV1 =
        KagemushaWalletBackgroundStatusV1(setup(KagemushaWalletSetupInputV1(18)))
    /** Compute at most one checkpoint. Run off the UI thread; activity enables background work. */
    fun foldOnce(): KagemushaWalletCallV1 = call(3)
    /** Native ownership and proof backlog, without operation readiness. Call on a worker. */
    fun snapshot(): KagemushaWalletSnapshotV1 {
        val reply = KagemushaWalletNativeCallsV1.snapshot(handle()) ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (reply.status < 0) throw KagemushaWalletExceptionV1(reply.status, reply.reason, reply.platformCode)
        return KagemushaWalletSnapshotV1(reply)
    }
    /** Canonical CreditStatus for the immutable first Payment identity. */
    fun creditStatus(creditId: ByteArray, paymentDigest: ByteArray): KagemushaWalletCallV1 {
        word(creditId); word(paymentDigest); return call(4, creditId, paymentDigest)
    }
    /** Foreground or charging enables folding; leaving both cancels at a cooperative boundary. */
    fun setActivity(foreground: Boolean, charging: Boolean) {
        checked(KagemushaWalletNativeCallsV1.activity(handle(), if (foreground) 1 else 0, if (charging) 1 else 0))
    }
    /** Release exclusive native custody. Never deletes key material, markers or retained bytes. */
    override fun close() = synchronized(closeGate) { closeFailure?.let{throw it}; closeAttempt() }
    /** Explicit retry retains the same Native ID and permanently fences every operation. */
    override fun retryCleanup() = synchronized(closeGate) { closeAttempt() }
    override fun cleanupReleased():Boolean = owner.get()==0L
    private fun closeAttempt() {
        retired.set(true)
        val handle=owner.get()
        if(handle>0) {
            try{checked(KagemushaWalletNativeCallsV1.close(handle));owner.set(0);closeFailure=null}
            catch(failure:Throwable){
                closeFailure=failure
                KagemushaWalletInstalledRuntimeV1.retainFailure(this,failure)
                throw failure
            }
        }
    }

    override fun toString(): String = "KagemushaWalletV1(owner=[REDACTED])"
    companion object {
        private fun word(bytes: ByteArray) { require(bytes.size == 32) { "identity must be exactly32 bytes" } }
        private fun checked(status: Int) { if (status != 0) throw KagemushaWalletExceptionV1(status) }

    }
}

/** JNI declarations share the current authenticated native library loader. */
internal object KagemushaWalletNativeV1 {
    @JvmStatic external fun revision(): Int
    @JvmStatic external fun openBegin(runtime: Long, credential: ByteArray, certificates: ByteArray, account: ByteArray, asset: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun openFinish(runtime: Long, signature: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun openCancel(runtime: Long): Int
    @JvmStatic external fun close(handle: Long): Int
    @JvmStatic external fun activity(handle: Long, foreground: Int, charging: Int): Int
    @JvmStatic external fun call(handle: Long, operation: Int, first: ByteArray, second: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun enrollment(runtime: Long, selector: Int, first: ByteArray, second: ByteArray, third: ByteArray, certificates: Array<ByteArray>): KagemushaWalletCallV1?
    /** Native closed E1 refusal table: holder class 1 Phone, 2 App, 3 Attempt, 4 Account, or -1. */
    @JvmStatic external fun enrollmentRefusal(code: Int, android: Boolean): Int
    @JvmStatic external fun setup(handle: Long, setupId: ByteArray, selector: Int, amountLow: Long, amountHigh: Long, token: Long, first: ByteArray, second: ByteArray, third: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun execute(handle: Long, requestId: ByteArray, selector: Int, amountLow: Long, amountHigh: Long, first: ByteArray, second: ByteArray, third: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun snapshot(handle: Long): KagemushaWalletSnapshotReplyV1?
    @JvmStatic external fun review(handle: Long, selector: Int, amountLow: Long, amountHigh: Long, first: ByteArray, second: ByteArray): KagemushaWalletReviewReplyV1?
    @JvmStatic external fun executeReviewed(handle: Long, token: Long, requestId: ByteArray): KagemushaWalletCallV1?
    @JvmStatic external fun discardReview(handle: Long, token: Long): Int
}

/** Existing signed policy classes; these selectors never choose proof keys or state roots. */
enum class KagemushaWalletRefreshKindV1(internal val selector: Int) {
    CREDENTIAL(3), SCHEME_POLICY(4), TIME_ANCHOR(6), QUOTA_SHARE(7),
}

/** Allocation-bounded copies for the fixed JNI request. Validation is not monetary admission. */
internal class KagemushaWalletOperationInputV1(
    requestId: ByteArray,
    val selector: Int,
    val amount: KagemushaWalletUInt128V1 = KagemushaWalletUInt128V1(0, 0),
    first: ByteArray = byteArrayOf(), second: ByteArray = byteArrayOf(), third: ByteArray = byteArrayOf(),
) {
    private val identity: ByteArray
    private val originals: List<ByteArray>
    init {
        val limits = when (selector) {
            0 -> intArrayOf(512, 256 * 1024, 0)
            2 -> intArrayOf(10_000, 1_024, 10_000)
            3, 4 -> intArrayOf(1_024, 10_000, 0)
            5 -> intArrayOf(65_536 * 34 + 512, 10_000, 0)
            6 -> intArrayOf(512, 10_000, 0)
            7 -> intArrayOf(8_192, 10_000, 0)
            9 -> intArrayOf(0, 0, 0)
            10 -> intArrayOf(10_000, 2_048, 0)
            else -> throw IllegalArgumentException("unknown lifecycle operation")
        }
        require(requestId.size == 32 && requestId.any { it != 0.toByte() } != (selector == 5)) {
            "request identity must be exactly 32 bytes, nonzero except for the local list install"
        }
        val nonzero = amount.low != 0L || amount.high != 0L
        require(!nonzero) { "ordinary operations have no caller amount" }
        val inputs = listOf(first, second, third)
        for (index in inputs.indices) {
            require(inputs[index].size <= limits[index]) { "original exceeds operation bound" }
            if ((selector < 8 || selector == 10) && limits[index] != 0) require(inputs[index].isNotEmpty()) { "required original is empty" }
        }
        identity = requestId.copyOf()
        originals = inputs.map { it.copyOf() }
    }
    fun requestId(): ByteArray = identity.copyOf()
    fun first(): ByteArray = originals[0].copyOf()
    fun second(): ByteArray = originals[1].copyOf()
    fun third(): ByteArray = originals[2].copyOf()
    override fun toString(): String = "KagemushaWalletOperationInputV1(originals=[REDACTED])"
}
