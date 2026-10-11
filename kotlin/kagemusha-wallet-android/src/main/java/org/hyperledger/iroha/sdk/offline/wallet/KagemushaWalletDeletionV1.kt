package org.hyperledger.iroha.sdk.offline.wallet

/** Display DATA selected by Native. Gross value and core burns are not fully folded spendable value. */
class KagemushaWalletDeletionProjectionV1 internal constructor(original: ByteArray) {
    val pending: Boolean
    val lifecycle: KagemushaWalletLifecycleV1
    /** Bootstrap1, Load2, Send3, Receive4, ArchiveSent5, Unload6, RefreshPolicy7, Retiring8. */
    val operationKind: Int
    val pendingOutgoing: Boolean
    val feeClaims: Boolean
    val loadRedeem: Boolean
    private val identities: Array<ByteArray>
    val sequence: KagemushaWalletUInt128V1
    val grossBalance: KagemushaWalletUInt128V1
    val coreBurnedTotal: KagemushaWalletUInt128V1
    init {
        if (original.size != 254) invalidDeletionOutput()
        val bytes = original.copyOf()
        if (!bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(75, 87, 67, 68, 86, 49, 0, 0)) ||
            bytes[8].toInt() !in 1..2 || bytes[9].toInt() !in 1..2 || bytes[10].toInt() !in 1..8 ||
            (11..13).any { bytes[it].toInt() !in 0..1 }) invalidDeletionOutput()
        identities = arrayOf(14, 46, 78, 110, 142, 174).map { bytes.copyOfRange(it, it + 32) }.toTypedArray()
        if (identities.any { value -> value.all { it == 0.toByte() } }) invalidDeletionOutput()
        fun limb(offset: Int): Long = (0 until 8).fold(0L) { value, i -> value or ((bytes[offset+i].toLong() and 255L) shl (8*i)) }
        fun scalar(offset: Int) = KagemushaWalletUInt128V1(limb(offset), limb(offset+8))
        pending = bytes[8].toInt() == 1
        lifecycle = if (bytes[9].toInt() == 1) KagemushaWalletLifecycleV1.ACTIVE else KagemushaWalletLifecycleV1.RETIRING
        operationKind = bytes[10].toInt(); pendingOutgoing = bytes[11].toInt() == 1
        feeClaims = bytes[12].toInt() == 1; loadRedeem = bytes[13].toInt() == 1
        sequence = scalar(206); grossBalance = scalar(222); coreBurnedTotal = scalar(238)
        val high = java.lang.Long.compareUnsigned(coreBurnedTotal.high, grossBalance.high)
        if (high > 0 || (high == 0 && java.lang.Long.compareUnsigned(coreBurnedTotal.low, grossBalance.low) > 0)) invalidDeletionOutput()
    }
    fun slot(): ByteArray = identities[0].copyOf()
    fun markerFileDigest(): ByteArray = identities[1].copyOf()
    fun schemeId(): ByteArray = identities[2].copyOf()
    fun assetDigest(): ByteArray = identities[3].copyOf()
    fun walletId(): ByteArray = identities[4].copyOf()
    fun head(): ByteArray = identities[5].copyOf()
    override fun toString(): String = "KagemushaWalletDeletionProjectionV1(state=[REDACTED])"
    companion object {
        /** Explicit warning to display before destructive confirmation. */
        const val WARNING = "Permanently delete the payment key and lose offline-value recovery, pending delivery and unpaid late claims. Gross value and core burns are not a fully folded spendable balance."
    }
}

/** One-use review tied to the owning wallet instance; DATA cannot authorize another owner. */
class KagemushaWalletDeletionReviewV1 internal constructor(
    private val origin: KagemushaWalletDeletionGateV1,
    private val epoch: Long,
    private val token: Long,
    val projection: KagemushaWalletDeletionProjectionV1,
) {
    private var consumed = false
    @Synchronized internal fun consume(owner: KagemushaWalletDeletionGateV1, expectedEpoch: Long): Long {
        require(owner === origin && expectedEpoch == epoch && !consumed) { "Deletion review is closed or belongs to another wallet" }
        consumed = true
        return token
    }
    override fun toString(): String = "KagemushaWalletDeletionReviewV1(review=[REDACTED])"
}

/** Definitive native recovery result, without any ledger settlement claim. */
sealed class KagemushaWalletDeletionStatusV1 {
    class Deleted internal constructor(marker: ByteArray) : KagemushaWalletDeletionStatusV1() {
        private val retainedMarker = marker.copyOf()
        fun marker(): ByteArray = retainedMarker.copyOf()
        override fun toString(): String = "Deleted(marker=[REDACTED])"
    }
    /** Definitively nonterminal; ordinary calls may resume, but another attempt needs a fresh review. */
    object NotDeleted : KagemushaWalletDeletionStatusV1()
}

/** Dispatch guard only; no monitor spans native calls, and Native retains all authority. */
internal class KagemushaWalletDeletionGateV1 {
    private var frozen = false
    private var inFlight = false
    private var terminalMarker: ByteArray? = null
    private var epoch = 0L
    @Synchronized fun requireOrdinary() { check(!frozen) { "Custody deletion requires recovery or is terminal" } }
    fun review(call: () -> KagemushaWalletCallV1): KagemushaWalletDeletionReviewV1 {
        val issuedEpoch = synchronized(this) { requireOrdinary(); epoch }
        val result = call()
        if (result.status != 53) invalidDeletionOutput()
        val projection = KagemushaWalletDeletionProjectionV1(result.bytes())
        return synchronized(this) {
            requireOrdinary(); check(epoch == issuedEpoch) { "Deletion review became stale" }
            KagemushaWalletDeletionReviewV1(this, epoch, result.sequenceLow, projection)
        }
    }
    private fun consume(review: KagemushaWalletDeletionReviewV1): Long {
        require(!frozen && !inFlight) { "Deletion review cannot be consumed while recovery is required" }
        return review.consume(this, epoch)
    }
    fun confirm(review: KagemushaWalletDeletionReviewV1, call: (Long) -> KagemushaWalletCallV1): ByteArray {
        val token = synchronized(this) { val value = consume(review); frozen = true; inFlight = true; epoch++; value }
        try {
            val result = call(token)
            if (result.status != 54) invalidDeletionOutput()
            synchronized(this) { terminalMarker = result.bytes() }
            return result.bytes()
        } finally { synchronized(this) { inFlight = false } }
    }
    fun resume(call: () -> KagemushaWalletCallV1): KagemushaWalletDeletionStatusV1 {
        synchronized(this) { check(frozen && !inFlight) { "No retained deletion attempt is available for recovery" }; frozen = true; inFlight = true; epoch++ }
        try {
            val result = call()
            return synchronized(this) {
                when (result.status) {
                    54 -> {
                        val marker = result.bytes()
                        if (terminalMarker?.contentEquals(marker) == false) invalidDeletionOutput()
                        terminalMarker = marker
                        KagemushaWalletDeletionStatusV1.Deleted(marker)
                    }
                    56 -> { if (terminalMarker != null) invalidDeletionOutput(); frozen = false; KagemushaWalletDeletionStatusV1.NotDeleted }
                    else -> invalidDeletionOutput()
                }
            }
        } finally { synchronized(this) { inFlight = false } }
    }
    fun discard(review: KagemushaWalletDeletionReviewV1, call: (Long) -> KagemushaWalletCallV1) {
        val token = synchronized(this) { consume(review) }
        if (call(token).status != 55) invalidDeletionOutput()
    }
}

private fun invalidDeletionOutput(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
