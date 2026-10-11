// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Closed review DATA only. Native verifies the exact quote, certificates and beneficiary. */
internal object KagemushaWalletUnloadChargeReviewV1 {
    const val MAXIMUM_BYTES = 14_112
    private val magic = byteArrayOf(75, 87, 85, 67, 86, 49, 0, 0)

    fun encode(certificates: ByteArray, beneficiary: ByteArray): ByteArray {
        require(certificates.size in 1..10_000 && beneficiary.size in 1..4_096)
        return ByteBuffer.allocate(16 + certificates.size + beneficiary.size).order(ByteOrder.LITTLE_ENDIAN)
            .put(magic).putInt(certificates.size).put(certificates).putInt(beneficiary.size).put(beneficiary).array()
    }

    fun validate(original: ByteArray) {
        require(original.size in 18..MAXIMUM_BYTES && original.copyOfRange(0, 8).contentEquals(magic))
        val input = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN)
        input.position(8)
        val certificates = input.int
        require(certificates in 1..10_000 && input.remaining() >= certificates + 4)
        input.position(12 + certificates)
        val beneficiary = input.int
        require(beneficiary in 1..4_096 && input.remaining() == beneficiary)
    }
}
