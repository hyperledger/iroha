package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletRequestFeeSelectionV1Test {
    private fun selected(bytes: ByteArray) = KagemushaWalletRequestFeeSelectionV1(KagemushaWalletCallV1(12, -1, 0, 0, 0, 0, bytes))
    @Test fun `fee projection preserves exact unsigned digests and copies`() {
        val bytes = ByteArray(64) { (it + 1).toByte() }
        val projection = selected(bytes); bytes.fill(0)
        assertEquals(false, projection.isZeroFee)
        assertContentEquals(ByteArray(32) { (it + 1).toByte() }, projection.assetDigest())
        val fee = projection.feeScheduleDigest(); fee.fill(0)
        assertContentEquals(ByteArray(32) { (it + 33).toByte() }, projection.feeScheduleDigest())
        assertTrue(selected(ByteArray(32) { 1 } + ByteArray(32)).isZeroFee)
    }
    @Test fun `unknown absent malformed fee projection never means zero`() {
        for (size in listOf(1, 63, 65)) assertFailsWith<KagemushaWalletExceptionV1> { selected(ByteArray(size) { 1 }) }
        assertFailsWith<KagemushaWalletExceptionV1> { selected(ByteArray(64)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletRequestFeeSelectionV1(KagemushaWalletCallV1(1, -1, 0, 0, 0, 0, ByteArray(64) { 1 })) }
    }
    @Test fun `fee PolicyData setup enforces pair and full envelope bounds`() {
        val id = ByteArray(32) { 1 }; val frame = byteArrayOf(7)
        KagemushaWalletSetupInputV1(38)
        KagemushaWalletSetupInputV1(39, id, first = frame)
        KagemushaWalletSetupInputV1(39, id, first = frame, second = frame, third = frame)
        KagemushaWalletSetupInputV1(40, first = frame, second = frame)
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(38, first = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, id, first = frame, second = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, first = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(40, first = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(40, id, first = frame, second = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(39, id, first = frame, second = ByteArray(10_001), third = frame) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(40, first = frame, second = ByteArray(10_001)) }
    }
}
