package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Native-authenticated state of one exact credit. These observations grant no operation permission. */
class KagemushaWalletCreditProjectionV1 internal constructor(value: KagemushaWalletCallV1) {
    enum class Evidence { UNFOLDED, CREDITED, BURNED }
    enum class Archive { RECEIVER, AWAITING_FOLD, REMOVED, RETAINED }
    val evidence: Evidence
    val archive: Archive
    val corePending: Boolean
    val amount: KagemushaWalletUInt128V1
    private val credit: ByteArray
    private val payment: ByteArray
    private val original: ByteArray
    init {
        fun invalid(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        if (value.status != KagemushaWalletCallV1.CREDIT_PROJECTION || value.reason != -1 ||
            value.platformCode != 0 || value.sequenceLow != 0L || value.sequenceHigh != 0L || value.detail != 0) invalid()
        val bytes = value.bytes()
        if (bytes.size !in 92..10_092) invalid()
        val input = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if (input.short.toInt() != 1) invalid()
        evidence = when (input.get().toInt()) { 1 -> Evidence.UNFOLDED; 2 -> Evidence.CREDITED; 3 -> Evidence.BURNED; else -> invalid() }
        archive = when (input.get().toInt()) { 0 -> Archive.RECEIVER; 1 -> Archive.AWAITING_FOLD; 2 -> Archive.REMOVED; 3 -> Archive.RETAINED; else -> invalid() }
        corePending = when (input.get().toInt()) { 0 -> false; 1 -> true; else -> invalid() }
        repeat(3) { if (input.get().toInt() != 0) invalid() }
        credit = ByteArray(32).also(input::get)
        payment = ByteArray(32).also(input::get)
        amount = KagemushaWalletUInt128V1(input.long, input.long)
        val size = input.int
        if (credit.all { it == 0.toByte() } || payment.all { it == 0.toByte() } ||
            amount.low == 0L && amount.high == 0L || size !in 0..10_000 || input.remaining() != size ||
            (archive == Archive.RECEIVER && (corePending || size == 0)) ||
            (archive != Archive.RECEIVER && size != 0)) invalid()
        original = ByteArray(size).also(input::get)
    }
    fun creditId(): ByteArray = credit.copyOf()
    fun paymentDigest(): ByteArray = payment.copyOf()
    internal fun requireReceiver(): KagemushaWalletCreditProjectionV1 = also {
        if (archive != Archive.RECEIVER) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    }
    internal fun requirePayer(): KagemushaWalletCreditProjectionV1 = also {
        if (archive == Archive.RECEIVER) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    }
    /** Exact fresh Native-generated receiver evidence; absent on payer observations. */
    fun creditedOriginal(): ByteArray? = original.takeIf { it.isNotEmpty() }?.copyOf()
    override fun toString() = "KagemushaWalletCreditProjectionV1(evidence=$evidence, archive=$archive, originals=[REDACTED])"
}
