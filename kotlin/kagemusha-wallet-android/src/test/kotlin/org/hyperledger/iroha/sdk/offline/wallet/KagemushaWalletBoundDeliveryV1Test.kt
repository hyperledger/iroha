package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.*
import org.junit.jupiter.api.Test

/** Intake shape only. No local object or test original establishes a Native delivery. */
class KagemushaWalletBoundDeliveryV1Test {
    @Test fun boundReceiptRequiresSendIdentityAndExactBoundedOriginal() {
        for (selector in listOf(41, 42)) {
            val id = ByteArray(32) { 7 }; val receipt = ByteArray(10_000) { 5 }
            val input = KagemushaWalletSetupInputV1(selector, identity = id, first = receipt)
            id[0] = 8; receipt[0] = 9
            assertEquals(7, input.identity()[0].toInt()); assertEquals(5, input.first()[0].toInt())
            input.identity()[0] = 9; input.first()[0] = 8
            assertEquals(7, input.identity()[0].toInt()); assertEquals(5, input.first()[0].toInt())
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, first = receipt) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id, first = ByteArray(10_001)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id, first = receipt, second = byteArrayOf(1)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id, first = receipt, token = 1) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, identity = id, first = receipt, amount = KagemushaWalletUInt128V1(1, 0)) }
        }
    }
}
