package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** Actual JNI request boundary, with no admitted wallet, deletion or platform qualification. */
@Tag("host-native")
class KagemushaWalletDeletionHostNativeV1Test {
    @Test fun exactDeletionRequestsRefuseUnknownOwnerAndInvalidInputsRefuseBeforeLookup() {
        assertTrue(NativeSignerBridge.isNativeAvailable(), "The supplied current native bridge must load")
        for (selector in 48..51) {
            val expectedToken = if (selector == 49 || selector == 51) 1L else 0L
            fun call(token: Long = expectedToken, first: ByteArray = byteArrayOf()) =
                assertNotNull(KagemushaWalletNativeV1.setup(0, ByteArray(32), selector, 0, 0, token,
                    first, byteArrayOf(), byteArrayOf()))
            val unknown = call()
            assertEquals(-2, unknown.status)
            assertTrue(unknown.bytes().isEmpty())
            for (invalid in listOf(call(if (expectedToken == 0L) 1 else 0), call(first = byteArrayOf(1)))) {
                assertEquals(-1, invalid.status)
                assertTrue(invalid.bytes().isEmpty())
            }
        }
    }
}
