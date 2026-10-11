// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong

/** Exact authenticated Native review DATA. This projection cannot construct an operation. */
class KagemushaWalletReviewProjectionV1 internal constructor(original: ByteArray) {
    private val retained = original.takeIf { it.size in FIXED_BYTES..MAXIMUM_BYTES }?.copyOf()
        ?: throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    val kind: Kind
    val amount: KagemushaWalletUInt128V1
    val fee: KagemushaWalletUInt128V1
    val grossDebit: KagemushaWalletUInt128V1
    val netDestinationAmount: KagemushaWalletUInt128V1
    enum class Kind { SEND, UNLOAD }
    internal companion object {
        const val FIXED_BYTES = 495
        const val MAXIMUM_BYTES = FIXED_BYTES + 4_096
    }
    init {
        fun invalid(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (!retained.copyOfRange(0, 8).contentEquals(byteArrayOf(75,87,79,82,86,49,0,0))) invalid()
        kind = when (retained[8].toInt()) { 1 -> Kind.SEND; 8 -> Kind.UNLOAD; else -> invalid() }
        var accountLength = 0L
        for (i in 0..3) accountLength = accountLength or ((retained[491+i].toLong() and 255) shl (8*i))
        if (accountLength > 4_096 || retained.size.toLong() != FIXED_BYTES + accountLength ||
            (if (kind == Kind.SEND) accountLength == 0L else accountLength != 0L)) invalid()
        amount = scalar(9); fee = scalar(25); grossDebit = scalar(41); netDestinationAmount = scalar(57)
        fun word(offset: Int) = retained.copyOfRange(offset, offset + 32).any { it != 0.toByte() }
        if (amount == KagemushaWalletUInt128V1(0, 0) || retained[426] != 4.toByte() ||
            retained.copyOfRange(427, 491).all { it == 0.toByte() } ||
            listOf(106, 202, 234, 266, 298, 330, 362, 394).any { !word(it) }) invalid()
        if (kind == Kind.SEND) {
            if (retained[73] != 1.toByte() || !word(74) || !word(138) || word(170)) invalid()
        } else if (retained[73] != 0.toByte() || word(74) || word(138)) invalid()
    }
    private fun scalar(offset: Int): KagemushaWalletUInt128V1 {
        fun limb(at: Int): Long { var value=0L; for (i in 0..7) value = value or ((retained[at+i].toLong() and 255) shl (8*i)); return value }
        return KagemushaWalletUInt128V1(limb(offset), limb(offset + 8))
    }
    private fun word(index: Int) = retained.copyOfRange(106 + index * 32, 138 + index * 32)
    /** Exact bytes bind a fresh hardware confirmation; no local frame is reassembled. */
    fun bytes(): ByteArray = retained.copyOf()
    fun receiverWalletId(): ByteArray? = if (kind == Kind.SEND) retained.copyOfRange(74,106) else null
    fun destinationAccountDigest() = word(0)
    /** Exact Native-authenticated canonical AccountId original; null for Unload.
     * Render only under independently authenticated installed network presentation selection. */
    fun destinationAccountOriginal(): ByteArray? =
        if (kind == Kind.SEND) retained.copyOfRange(FIXED_BYTES, retained.size) else null
    fun requestDigest() = word(1)
    fun chargeQuoteDigest() = word(2)
    fun schemeId() = word(3)
    fun walletId() = word(4)
    fun currentHead() = word(5)
    fun sourceStateCommitment() = word(6)
    fun sourceCapsuleDigest() = word(7)
    fun credentialDigest() = word(8)
    fun artifactManifestDigest() = word(9)
    fun paymentPublicKey() = retained.copyOfRange(426,491)
    fun paymentKey() = paymentPublicKey()
    override fun toString() = "KagemushaWalletReviewProjectionV1(kind=$kind, source=[REDACTED])"
}

/** JNI result has a separate parser; review18 is never an ordinary monetary completion. */
internal class KagemushaWalletReviewReplyV1(
    @JvmField val status: Int, @JvmField val reason: Int, @JvmField val platformCode: Int,
    private val sequenceLow: Long, private val sequenceHigh: Long, private val detail: Int, original: ByteArray,
) {
    private val retained = original.copyOf()
    internal fun review(owner: Any, expected: KagemushaWalletReviewProjectionV1.Kind): KagemushaWalletReviewV1 {
        if (status < 0) {
            if (sequenceLow != 0L || sequenceHigh != 0L || detail != 0 || retained.isNotEmpty()) invalid()
            throw KagemushaWalletExceptionV1(status, reason, platformCode)
        }
        if (status != 18 || reason != -1 || platformCode != 0 || sequenceLow <= 0 || sequenceHigh != 0L || detail != 0) invalid()
        val projection = KagemushaWalletReviewProjectionV1(retained)
        if (projection.kind != expected) invalid()
        return KagemushaWalletReviewV1.fromNative(owner, sequenceLow, projection)
    }
    internal fun cleanupToken(): Long? = sequenceLow.takeIf { it > 0 }
    private fun invalid(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    override fun toString() = "KagemushaWalletReviewReplyV1(status=$status, source=[REDACTED])"
}

/** Owner-local move-only capability. Only a genuine Native reply creates it; projection DATA cannot. */
class KagemushaWalletReviewV1 private constructor(
    private val origin: Any, token: Long, val projection: KagemushaWalletReviewProjectionV1,
) {
    private val selected = AtomicLong(token)
    internal fun consume(owner: Any): Long {
        check(owner === origin) { "review belongs to another wallet" }
        return selected.getAndSet(0).takeIf { it > 0 } ?: throw KagemushaWalletExceptionV1(-2)
    }
    internal companion object {
        internal fun fromNative(owner: Any, token: Long, projection: KagemushaWalletReviewProjectionV1) =
            KagemushaWalletReviewV1(owner, token, projection)
    }
    override fun toString() = "KagemushaWalletReviewV1(owner=[REDACTED])"
}

/** Current integration uses the same Native kind; no second display codec. */
typealias KagemushaWalletReviewedKindV1 = KagemushaWalletReviewProjectionV1.Kind
/** Copy/bounds only. Native authenticates all financial originals and retains the review. */
internal class KagemushaWalletReviewInputV1(
    val selector: Int,
    val amount: KagemushaWalletUInt128V1 = KagemushaWalletUInt128V1(0, 0),
    first: ByteArray = byteArrayOf(), second: ByteArray = byteArrayOf(),
) {
    private val originals: List<ByteArray>
    init {
        val nonzero = amount.low != 0L || amount.high != 0L
        when (selector) {
            1 -> require(!nonzero && first.isNotEmpty() && first.size <= 10_000 &&
                second.isNotEmpty() && second.size <= 4_096)
            8 -> {
                require(nonzero && first.size <= 1_024 && first.isEmpty() == second.isEmpty())
                if (second.isNotEmpty()) KagemushaWalletUnloadChargeReviewV1.validate(second)
            }
            else -> throw IllegalArgumentException("unknown review operation")
        }
        originals = listOf(first.copyOf(), second.copyOf())
    }
    fun first(): ByteArray = originals[0].copyOf()
    fun second(): ByteArray = originals[1].copyOf()
    override fun toString(): String = "KagemushaWalletReviewInputV1(originals=[REDACTED])"
}
