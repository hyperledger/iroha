// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyPair
import java.security.PrivateKey
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
    fun creationIsRefusedBelowApi26() {
        assumeTrue(Build.VERSION.SDK_INT < KAGEMUSHA_WALLET_ANDROID_MIN_API_V1)
        try {
            KagemushaWalletAndroidPlatformV1.create(context)
            fail("wallet custody requires API 26 or later")
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
    fun api26Through30DoNotInferCustodyAuthorityFromANullLookup() {
        assumeTrue(Build.VERSION.SDK_INT in
            KAGEMUSHA_WALLET_ANDROID_MIN_API_V1 until KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1)
        // Reads use the real AndroidKeyStore. A regression must fail before it can mutate a
        // key: null is unknown on these APIs, and this test has no Native fresh-slot grant.
        val keyStore = object : KagemushaWalletAndroidKeyStoreV1 by KagemushaWalletAndroidSystemKeyStoreV1() {
            var generationCalls = 0
            var signCalls = 0
            var deleteCalls = 0

            override fun generate(spec: KagemushaWalletAndroidKeySpecV1): KeyPair {
                generationCalls += 1
                error("ordinary generation must not reach AndroidKeyStore on API 26–30")
            }

            override fun sign(key: PrivateKey, message: ByteArray): ByteArray {
                signCalls += 1
                error("unknown key lookup must not reach signing")
            }

            override fun deleteEntry(alias: String) {
                deleteCalls += 1
                error("unknown key lookup must not reach destructive cleanup")
            }
        }
        val adapter = KagemushaWalletAndroidPlatformAdapterV1(
            KagemushaWalletAndroidSystemEnvironmentV1(context), keyStore,
        )
        val slot = nonzero32()
        val unknown = KagemushaWalletAndroidUnavailableV1.platform(
            KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENCE_UNKNOWN,
        )
        assertEquals(1, adapter.keyGenerationMode())
        assertEquals(unknown, (adapter.keyProbe(slot) as KagemushaWalletAndroidKeyProbeV1.Unavailable).reason)
        assertEquals(
            unknown,
            (adapter.keyGenerate(slot, nonzero32(), KAGEMUSHA_WALLET_ANDROID_KEY_PROFILE_TAG_V1)
                as KagemushaWalletAndroidKeyGenerationV1.Unavailable).reason,
        )
        assertEquals(unknown, (adapter.attestationChain(slot) as KagemushaWalletAndroidAttestationChainV1.Unavailable).reason)
        assertEquals(unknown, (adapter.keySign(slot, nonzero32()) as KagemushaWalletAndroidSignatureV1.Unavailable).reason)
        assertEquals(
            KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED),
            (adapter.keyDelete(slot) as KagemushaWalletAndroidRemoveV1.Uncertain).reason,
        )
        assertEquals(0, keyStore.generationCalls)
        assertEquals(0, keyStore.signCalls)
        assertEquals(0, keyStore.deleteCalls)
        assertEquals(unknown, (adapter.keyProbe(slot) as KagemushaWalletAndroidKeyProbeV1.Unavailable).reason)
        // Genuine API 26–30 generation/signing needs installed Native enrollment and its
        // consumed one-shot grant. Never call the internal fresh-generation hook to fake it.
    }

    @Test
    fun thePaymentKeyLifecycleUsesTheRealKeystoreOnApi31AndLater() {
        assumeTrue(Build.VERSION.SDK_INT >= KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1)
        val adapter = adapter()
        val slot = nonzero32()
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, adapter.keyProbe(slot))
        val result = adapter.keyGenerate(slot, nonzero32(), KAGEMUSHA_WALLET_ANDROID_KEY_PROFILE_TAG_V1)
        try {
            when (result) {
                is KagemushaWalletAndroidKeyGenerationV1.Generated -> {
                    val probed = adapter.keyProbe(slot) as KagemushaWalletAndroidKeyProbeV1.Present
                    assertTrue(result.publicKeySec1().contentEquals(probed.publicKeySec1()))
                    val chain = adapter.attestationChain(slot) as KagemushaWalletAndroidAttestationChainV1.Present
                    val leaf = CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(chain.certificatesDer().first()))
                    // A 32-byte signing message; KeyMint hashes it with SHA-256 (DIGEST_SHA256).
                    val message = nonzero32()
                    val der = (adapter.keySign(slot, message) as KagemushaWalletAndroidSignatureV1.Der).der()
                    assertTrue(Signature.getInstance("SHA256withECDSA").run {
                        initVerify(leaf.publicKey)
                        update(message)
                        verify(der)
                    })
                    assertSame(
                        KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent,
                        adapter.keyGenerate(slot, nonzero32(), KAGEMUSHA_WALLET_ANDROID_KEY_PROFILE_TAG_V1),
                    )
                }
                is KagemushaWalletAndroidKeyGenerationV1.Unavailable -> {
                    // A retained but unusable key may exercise refusal, never a successful
                    // hardware lifecycle. Other provider/StrongBox failures remain failures;
                    // the TEE hint for a fresh slot under a new challenge belongs to enrollment.
                    assertEquals(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE, result.reason)
                    assertTrue(adapter.keyProbe(slot) is KagemushaWalletAndroidKeyProbeV1.Present)
                    assumeTrue("The provider refused the key; hardware lifecycle was not exercised", false)
                }
                KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent -> fail("a fresh slot had a key")
            }
        } finally {
            assertSame(KagemushaWalletAndroidRemoveV1.Removed, adapter.keyDelete(slot))
        }
        assertSame(KagemushaWalletAndroidKeyProbeV1.Absent, adapter.keyProbe(slot))
    }
}
