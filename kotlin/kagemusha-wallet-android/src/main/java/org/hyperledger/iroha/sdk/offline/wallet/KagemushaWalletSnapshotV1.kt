// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Lossless unsigned 128-bit Native scalar; signed Longs hold bit patterns only. */
class KagemushaWalletUInt128V1(val low: Long, val high: Long) : Comparable<KagemushaWalletUInt128V1> {
    override fun equals(other: Any?): Boolean =
        other is KagemushaWalletUInt128V1 && low == other.low && high == other.high
    override fun hashCode(): Int = 31 * high.hashCode() + low.hashCode()
    override fun toString(): String = "KagemushaWalletUInt128V1(value=[REDACTED])"
    override fun compareTo(other: KagemushaWalletUInt128V1): Int {
        val upper = (high xor Long.MIN_VALUE).compareTo(other.high xor Long.MIN_VALUE)
        return if (upper != 0) upper else (low xor Long.MIN_VALUE).compareTo(other.low xor Long.MIN_VALUE)
    }
}

/** Actual retained lifecycle; Retiring can Send/Unload remaining value under Native rules. */
enum class KagemushaWalletLifecycleV1 { ACTIVE, RETIRING }

/** Exact verified source-indexed fold, including the credential selected by that folded head. */
class KagemushaWalletSnapshotFoldV1 internal constructor(
    val sequence: KagemushaWalletUInt128V1,
    head: ByteArray,
    credential: ByteArray,
    val burnedTotal: KagemushaWalletUInt128V1,
) {
    private val retainedHead = head.copyOf()
    private val retainedCredential = credential.copyOf()
    fun head(): ByteArray = retainedHead.copyOf()
    fun credentialDigest(): ByteArray = retainedCredential.copyOf()
    override fun toString(): String = "KagemushaWalletSnapshotFoldV1(source=[REDACTED])"
}

/**
 * Native ownership and local proof progress (§PC/P1a/P1b/P4), with no operation permission.
 * Owned value excludes known burns. An unfinished Receive fold can discover the sole P4
 * exception. [foldedBalance] exists only for Ω of this exact current head; every Native
 * operation still checks its lifecycle, controls, authentication and other prerequisites.
 */
class KagemushaWalletSnapshotV1 internal constructor(reply: KagemushaWalletSnapshotReplyV1) {
    private val scheme = reply.scheme()
    private val wallet = reply.wallet()
    private val currentHead = reply.head()
    private val credential = reply.credential()
    val sequence: KagemushaWalletUInt128V1
    val lifecycle: KagemushaWalletLifecycleV1
    val grossBalance: KagemushaWalletUInt128V1
    val coreBurnedTotal: KagemushaWalletUInt128V1
    val knownBurnedTotal: KagemushaWalletUInt128V1
    val ownedBalance: KagemushaWalletUInt128V1
    val foldedBalance: KagemushaWalletUInt128V1?
    val foldBacklog: KagemushaWalletUInt128V1
    val verifiedFold: KagemushaWalletSnapshotFoldV1?
    val headIsFolded: Boolean get() = foldedBalance != null
    init {
        val numbers = reply.scalars()
        fun invalid(): Nothing = throw KagemushaWalletExceptionV1(-100)
        fun scalar(index: Int) = KagemushaWalletUInt128V1(numbers[index * 2], numbers[index * 2 + 1])
        fun word(value: ByteArray) = value.size == 32 && value.any { it != 0.toByte() }
        if (reply.status != 0 || reply.reason != -1 || reply.platformCode != 0 ||
            reply.flags !in 0..3 || reply.lifecycle !in 1..2 || numbers.size != 18 ||
            !listOf(scheme, wallet, currentHead, credential).all(::word)) invalid()
        lifecycle = if (reply.lifecycle == 1) KagemushaWalletLifecycleV1.ACTIVE else KagemushaWalletLifecycleV1.RETIRING
        sequence = scalar(0); grossBalance = scalar(1); coreBurnedTotal = scalar(2)
        knownBurnedTotal = scalar(3); ownedBalance = scalar(4); foldBacklog = scalar(6)
        val folded = scalar(5); val foldedSequence = scalar(7); val foldedBurns = scalar(8)
        val foldHead = reply.foldedHead(); val foldCredential = reply.foldedCredential()
        val hasFold = reply.flags and 1 != 0; val headFolded = reply.flags and 2 != 0
        val zero = KagemushaWalletUInt128V1(0, 0)
        if (headFolded && !hasFold) invalid()
        if (hasFold) {
            if (!word(foldHead) || !word(foldCredential) || foldedSequence > sequence || foldedBurns != knownBurnedTotal) invalid()
        } else if (foldHead.size != 32 || foldCredential.size != 32 ||
            foldHead.any { it != 0.toByte() } || foldCredential.any { it != 0.toByte() } ||
            foldedSequence != zero || foldedBurns != zero) invalid()
        if (headFolded) {
            if (foldedSequence != sequence || !foldHead.contentEquals(currentHead) ||
                !foldCredential.contentEquals(credential) || foldBacklog != zero || folded != ownedBalance) invalid()
        } else if (folded != zero || foldBacklog <= zero || hasFold && foldedSequence >= sequence) invalid()
        foldedBalance = if (headFolded) folded else null
        verifiedFold = if (hasFold) KagemushaWalletSnapshotFoldV1(foldedSequence, foldHead, foldCredential, foldedBurns) else null
    }
    fun schemeId(): ByteArray = scheme.copyOf()
    fun walletId(): ByteArray = wallet.copyOf()
    fun head(): ByteArray = currentHead.copyOf()
    fun credentialDigest(): ByteArray = credential.copyOf()
    override fun toString(): String = "KagemushaWalletSnapshotV1(source=[REDACTED])"
}

/** Fixed typed JNI holder. This is scalar/array ABI transport, not a financial binary codec. */
internal class KagemushaWalletSnapshotReplyV1(
    @JvmField val status: Int,
    @JvmField val reason: Int,
    @JvmField val platformCode: Int,
    @JvmField val lifecycle: Int,
    @JvmField val flags: Int,
    scheme: ByteArray, wallet: ByteArray, head: ByteArray, credential: ByteArray,
    foldedHead: ByteArray, foldedCredential: ByteArray, scalars: LongArray,
) {
    private val retainedScheme = scheme.copyOf()
    private val retainedWallet = wallet.copyOf()
    private val retainedHead = head.copyOf()
    private val retainedCredential = credential.copyOf()
    private val retainedFoldedHead = foldedHead.copyOf()
    private val retainedFoldedCredential = foldedCredential.copyOf()
    // Exact9 scalars in C field order, each as low64/high64. Optional zeros require flags.
    private val retainedScalars = scalars.copyOf()
    fun scheme() = retainedScheme.copyOf()
    fun wallet() = retainedWallet.copyOf()
    fun head() = retainedHead.copyOf()
    fun credential() = retainedCredential.copyOf()
    fun foldedHead() = retainedFoldedHead.copyOf()
    fun foldedCredential() = retainedFoldedCredential.copyOf()
    fun scalars() = retainedScalars.copyOf()
}
