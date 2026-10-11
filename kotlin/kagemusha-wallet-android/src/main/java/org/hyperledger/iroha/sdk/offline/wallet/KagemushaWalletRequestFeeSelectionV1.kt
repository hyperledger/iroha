package org.hyperledger.iroha.sdk.offline.wallet

/** Native DATA projection for fee-original lookup. Reusing it never authorizes a Request. */
class KagemushaWalletRequestFeeSelectionV1 internal constructor(value: KagemushaWalletCallV1) {
    private val original = value.original()
    init {
        if (original.size != 64 || original.take(32).all { it == 0.toByte() })
            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
    }
    fun assetDigest(): ByteArray = original.copyOfRange(0, 32)
    fun feeScheduleDigest(): ByteArray = original.copyOfRange(32, 64)
    val isZeroFee: Boolean get() = original.copyOfRange(32, 64).all { it == 0.toByte() }
    override fun toString() = "KagemushaWalletRequestFeeSelectionV1(selection=[REDACTED])"
}
