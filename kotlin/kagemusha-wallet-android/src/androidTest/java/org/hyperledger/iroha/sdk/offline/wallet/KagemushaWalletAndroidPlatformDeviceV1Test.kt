// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayInputStream
import java.io.File
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device coverage of the production AndroidKeyStore, KeyInfo, resource and storage paths of the
 * wallet platform adapter (G2 design rev 2 test plan, Android instrumented). JVM unit tests cover
 * the decisions against fakes; this suite runs only on an emulator or device.
 */
@RunWith(AndroidJUnit4::class)
class KagemushaWalletAndroidPlatformDeviceV1Test {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val random = SecureRandom()

    private fun nonzero32(): ByteArray {
        val bytes = ByteArray(32)
        do random.nextBytes(bytes) while (bytes.all { it == 0.toByte() })
        return bytes
    }

    private fun adapter() = KagemushaWalletAndroidPlatformAdapterV1(
        KagemushaWalletAndroidSystemEnvironmentV1(context),
        KagemushaWalletAndroidSystemKeyStoreV1(),
    )

    @Test
    fun creationIsRefusedBelowApi31() {
        assumeTrue(Build.VERSION.SDK_INT < KAGEMUSHA_WALLET_ANDROID_MIN_API_V1)
        try {
            KagemushaWalletAndroidPlatformV1.create(context)
            fail("keystore1 must be refused")
        } catch (expected: IllegalStateException) {
        }
    }

    @Test
    fun theMergedRulesAndStorageFactsAllowCustody() {
        assumeTrue(Build.VERSION.SDK_INT >= KAGEMUSHA_WALLET_ANDROID_MIN_API_V1)
        val environment = KagemushaWalletAndroidSystemEnvironmentV1(context)
        assertNull(kagemushaWalletAndroidBackupRulesRefusalV1(environment.dataExtractionRules(), environment.fullBackupContentRules()))
        assertNull(kagemushaWalletAndroidCustodyRefusalV1(environment))
        assertFalse(environment.isDeviceProtectedStorage())
        assertTrue(environment.isUserUnlocked())
        val adapter = adapter()
        assertNull(adapter.storageState())
        val root = adapter.custodyRoot() as KagemushaWalletAndroidCustodyRootV1.Present
        assertEquals(File(context.noBackupFilesDir.canonicalPath, KAGEMUSHA_WALLET_ANDROID_CUSTODY_DIR_NAME_V1).path, root.path)
        KagemushaWalletAndroidPlatformV1.create(context)
    }

    @Test
    fun thePaymentKeyLifecycleUsesTheRealKeystore() {
        assumeTrue(Build.VERSION.SDK_INT >= KAGEMUSHA_WALLET_ANDROID_MIN_API_V1)
        val adapter = adapter()
        val slot = nonzero32()
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, adapter.keyProbe(slot))
        val result = adapter.keyGenerate(slot, nonzero32(), KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE.tag)
        try {
            when (result) {
                is KagemushaWalletAndroidKeyGenerationV1.Generated -> {
                    val probed = adapter.keyProbe(slot) as KagemushaWalletAndroidKeyProbeV1.Present
                    assertTrue(result.publicKeySec1().contentEquals(probed.publicKeySec1()))
                    val chain = adapter.attestationChain(slot) as KagemushaWalletAndroidAttestationChainV1.Present
                    val leaf = CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(chain.certificatesDer().first()))
                    val message = ByteArray(32) { 7 }
                    val der = (adapter.keySign(slot, message) as KagemushaWalletAndroidSignatureV1.Der).der()
                    assertTrue(Signature.getInstance("SHA256withECDSA").run {
                        initVerify(leaf.publicKey)
                        update(message)
                        verify(der)
                    })
                    assertSame(
                        KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
                        adapter.keyGenerate(slot, nonzero32(), KagemushaWalletAndroidKeyProfileV1.SECURE_ELEMENT_OR_TEE.tag),
                    )
                }
                is KagemushaWalletAndroidKeyGenerationV1.Unavailable -> {
                    // A software-only Keystore (an emulator) is refused and its key left in place.
                    assertEquals(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, result.reason)
                    assertTrue(adapter.keyProbe(slot) is KagemushaWalletAndroidKeyProbeV1.Present)
                }
                KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent -> fail("a fresh slot had a key")
            }
        } finally {
            assertSame(KagemushaWalletAndroidRemoveV1.Removed, adapter.keyDelete(slot))
        }
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, adapter.keyProbe(slot))
    }
}
