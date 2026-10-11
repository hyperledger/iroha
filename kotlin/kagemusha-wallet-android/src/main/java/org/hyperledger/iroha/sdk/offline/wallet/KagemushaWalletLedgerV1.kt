// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Closed original Native transports accepted by the current ledger instruction. */
enum class KagemushaWalletLedgerTransportV1(internal val tag: Long) {
    ACTIVATE(1), UNLOAD(2), CLOSE_LOADS(3),
}

/** Native-verified successful inclusion of the exact account's retained Unload instruction. */
class KagemushaWalletUnloadConfirmationV1 internal constructor(result: KagemushaWalletCallV1) {
    val heightBits: Long
    private val block: ByteArray
    init {
        if (result.status != KagemushaWalletCallV1.UNLOAD_CONFIRMATION) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        heightBits = result.sequenceLow
        block = result.bytes()
    }
    fun blockHash(): ByteArray = block.copyOf()
}

/** Native-owned Unload history. Only a confirmation establishes successful settlement. */
class KagemushaWalletUnloadFinalityV1 internal constructor(result: KagemushaWalletCallV1) {
    val confirmation: KagemushaWalletUnloadConfirmationV1?
    val verifiedHeightBits: Long?
    private val block: ByteArray?
    init {
        when (result.status) {
            KagemushaWalletCallV1.UNLOAD_CONFIRMATION -> {
                confirmation = KagemushaWalletUnloadConfirmationV1(result)
                verifiedHeightBits = result.sequenceLow
                block = result.bytes()
            }
            33 -> {
                confirmation = null
                verifiedHeightBits = result.sequenceLow
                block = result.bytes()
            }
            34 -> {
                confirmation = null
                verifiedHeightBits = null
                block = null
            }
            else -> throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
    }
    fun blockHash(): ByteArray? = block?.copyOf()
}

/** Native-verified successful inclusion of a registered same-Activation family member.
 * This does not assert execution success of every other outer transaction in that family. */
class KagemushaWalletActivationConfirmationV1 internal constructor(result: KagemushaWalletCallV1) {
    val heightBits: Long
    private val block: ByteArray
    init {
        if (result.status != KagemushaWalletCallV1.ACTIVATION_CONFIRMATION)
            throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        heightBits = result.sequenceLow
        block = result.bytes()
    }
    fun blockHash(): ByteArray = block.copyOf()
}

/** Native-owned Activate history. Only confirmation proves activation; height is unsigned u64. */
class KagemushaWalletActivationFinalityV1 internal constructor(result: KagemushaWalletCallV1) {
    val confirmation: KagemushaWalletActivationConfirmationV1?
    /** Native authenticated rejected execution of this exact retained outer transaction;
     * never a conversion of transport, clock, proof-verification or custody failure. */
    val rejected: Boolean = result.status == KagemushaWalletCallV1.ACTIVATION_REJECTED
    val verifiedHeightBits: Long?
    private val block: ByteArray?
    init {
        when (result.status) {
            KagemushaWalletCallV1.ACTIVATION_CONFIRMATION -> {
                confirmation = KagemushaWalletActivationConfirmationV1(result)
                verifiedHeightBits = result.sequenceLow
                block = result.bytes()
            }
            KagemushaWalletCallV1.ACTIVATION_PROGRESS, KagemushaWalletCallV1.ACTIVATION_REJECTED -> {
                confirmation = null
                verifiedHeightBits = result.sequenceLow
                block = result.bytes()
            }
            KagemushaWalletCallV1.ACTIVATION_NOT_STARTED -> {
                confirmation = null
                verifiedHeightBits = null
                block = null
            }
            else -> throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
        }
    }
    fun blockHash(): ByteArray? = block?.copyOf()
}
