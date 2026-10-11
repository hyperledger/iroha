package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.*
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** Actual JNI refusals without an installed monetary owner; no proof or platform claim. */
@Tag("host-native")
class KagemushaWalletObservationHostNativeV1Test {
    @Test fun exactObservationRequestsReachUnknownOwnerAndMalformedInputsRefuse() {
        assertTrue(NativeSignerBridge.isNativeAvailable(), "current original JNI artifact is required")
        for (selector in 0..3) {
            val identity = if (selector == 0) byteArrayOf() else ByteArray(32) { 1 }
            val reply = assertNotNull(KagemushaWalletObservationNativeV1.observe(0,selector,identity))
            assertEquals(-2,assertFailsWith<KagemushaWalletExceptionV1> { reply.original(65_756) }.status)
        }
        for ((selector,identity) in listOf(0 to ByteArray(32),1 to ByteArray(32),2 to ByteArray(31),3 to ByteArray(33),4 to byteArrayOf(),-1 to byteArrayOf())) {
            val reply = assertNotNull(KagemushaWalletObservationNativeV1.observe(0,selector,identity))
            assertEquals(-1,assertFailsWith<KagemushaWalletExceptionV1> { reply.original(65_756) }.status)
        }
    }
}
