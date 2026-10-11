// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Test

class KagemushaWalletUnloadChargeReviewV1Test {
    @Test fun `charged review encodes exact bounded companion DATA`() {
        val certificates = ByteArray(10_000) { 7 }; val beneficiary = ByteArray(4_096) { 8 }
        val frame = KagemushaWalletUnloadChargeReviewV1.encode(certificates, beneficiary)
        assertEquals(14_112, frame.size)
        assertContentEquals(byteArrayOf(75, 87, 85, 67, 86, 49, 0, 0, 16, 39, 0, 0), frame.copyOfRange(0, 12))
        assertContentEquals(byteArrayOf(0, 16, 0, 0), frame.copyOfRange(10_012, 10_016))
        certificates.fill(0); beneficiary.fill(0)
        KagemushaWalletUnloadChargeReviewV1.validate(frame)
        val input = KagemushaWalletReviewInputV1(8, KagemushaWalletUInt128V1(1, 0), byteArrayOf(1), frame)
        frame.fill(0)
        assertContentEquals(ByteArray(10_000) { 7 }, input.second().copyOfRange(12, 10_012))
        assertContentEquals(ByteArray(4_096) { 8 }, input.second().copyOfRange(10_016, 14_112))
    }

    @Test fun `charged review refuses retired raw certificates and malformed framing`() {
        val exact = KagemushaWalletUnloadChargeReviewV1.encode(byteArrayOf(7), byteArrayOf(8))
        val mutations = mutableListOf(ByteArray(10_000), exact.copyOf(exact.size - 1), exact + byteArrayOf(0))
        for (offset in listOf(0, 8, 13)) mutations += exact.copyOf().also { it[offset] = 0 }
        for (bytes in mutations) assertFailsWith<IllegalArgumentException> { KagemushaWalletUnloadChargeReviewV1.validate(bytes) }
        for ((cert, beneficiary) in listOf(byteArrayOf() to byteArrayOf(1), byteArrayOf(1) to byteArrayOf(),
            ByteArray(10_001) to byteArrayOf(1), byteArrayOf(1) to ByteArray(4_097))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletUnloadChargeReviewV1.encode(cert, beneficiary) }
        }
    }
}
