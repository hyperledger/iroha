// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.Context
import java.io.File
import java.io.IOException

// TODO(G2-bridge): implement the Rust `KagemushaWalletPlatformV1` JNI adapter in
// `crates/connect_norito_bridge/src/platform_jni/kagemusha_wallet_advance.rs` over the private
// upcalls of [KagemushaWalletAndroidPlatformV1] (upcalls run on attached worker threads; a
// thrown upcall exception maps to `Unavailable(Platform(0))`), and add the native provider open
// call that takes this handle. `boot_id` and `monotonic_ms` keep their native Rust defaults.
// TODO(G2-android): declare `android:manageSpaceActivity` with a custody warning screen so
// Settings > Storage offers "Manage space" instead of silently clearing custody (device test).

/**
 * Opaque Android platform handle of the KAGEMUSHA wallet `Advance` provider (spec §§1.2, 2.2,
 * 2.3, 4.2; G2 design rev 2).
 *
 * The handle has no public operation. Its private methods are the JNI upcalls of the Rust
 * `KagemushaWalletPlatformV1` adapter (JNI ignores Kotlin visibility; `consumer-rules.pro` keeps
 * them): the tri-state payment-key probe, generation bound to the issuer challenge digest and the
 * enrollment's hardware profile, `SHA256withECDSA` signing that returns the platform DER, key
 * deletion for custody deletion, attestation-chain export, the anchor policy (Android keeps no
 * rollback anchor), storage state and the custody root path. Only the Rust role-checked signers
 * reach the signing upcall, so app code holding the handle cannot sign arbitrary bytes with the
 * payment key through this module. Every custody file, marker and decision stays in Rust.
 *
 * [create] refuses (`IllegalStateException`) unless all of these hold:
 * - API level 31 or higher: only keystore2 `getKey` tells "no key" apart from an error;
 * - `android:allowBackup="false"` and no `android:backupAgent` in the merged host manifest;
 * - both backup-rule resources of this library, as resolved in the host app, exclude every
 *   domain for cloud backup, device transfer and legacy full backup (a host resource of the same
 *   name that adds files is refused);
 * - the context is the credential-encrypted application context.
 *
 * A full-data restore stream that reaches an app without its own backup agent clears all of its
 * data, including `no_backup`, and its Keystore namespace, so the backup and transfer set must
 * be empty. A host manifest that replaces `android:dataExtractionRules` or
 * `android:fullBackupContent` with its own resource cannot be detected through public APIs; host
 * apps must not do that (kotlin/README.md).
 */
class KagemushaWalletAndroidPlatformV1 private constructor(
    private val adapter: KagemushaWalletAndroidPlatformAdapterV1,
) {
    // JNI upcalls. Names and signatures are the bridge contract and are pinned by tests.

    @Suppress("unused")
    private fun keyProbe(slot: ByteArray): KagemushaWalletAndroidKeyProbeV1 = adapter.keyProbe(slot)

    @Suppress("unused")
    private fun keyGenerate(slot: ByteArray, challengeDigest: ByteArray, profileTag: Int): KagemushaWalletAndroidKeyGenerationV1 =
        adapter.keyGenerate(slot, challengeDigest, profileTag)

    @Suppress("unused")
    private fun keySign(slot: ByteArray, message: ByteArray): KagemushaWalletAndroidSignatureV1 =
        adapter.keySign(slot, message)

    @Suppress("unused")
    private fun keyDelete(slot: ByteArray): KagemushaWalletAndroidRemoveV1 = adapter.keyDelete(slot)

    @Suppress("unused")
    private fun attestationChain(slot: ByteArray): KagemushaWalletAndroidAttestationChainV1 = adapter.attestationChain(slot)

    @Suppress("unused")
    private fun anchorPolicyTag(): Int = adapter.anchorPolicyTag()

    @Suppress("unused")
    private fun storageState(): KagemushaWalletAndroidUnavailableV1? = adapter.storageState()

    @Suppress("unused")
    private fun custodyRoot(): KagemushaWalletAndroidCustodyRootV1 = adapter.custodyRoot()

    companion object {
        /**
         * Create the handle over the application's credential-encrypted context and
         * AndroidKeyStore.
         *
         * @throws IllegalStateException when the device is below API 31, the application allows
         * backup, declares a backup agent or carries backup rules that are not exclude-only, or
         * [context] is a device-protected storage context.
         */
        @JvmStatic
        fun create(context: Context): KagemushaWalletAndroidPlatformV1 = create(
            KagemushaWalletAndroidSystemEnvironmentV1(context),
            KagemushaWalletAndroidSystemKeyStoreV1(),
        )

        internal fun create(
            environment: KagemushaWalletAndroidEnvironmentV1,
            keyStore: KagemushaWalletAndroidKeyStoreV1,
        ): KagemushaWalletAndroidPlatformV1 =
            KagemushaWalletAndroidPlatformV1(KagemushaWalletAndroidPlatformAdapterV1(environment, keyStore))
    }
}

/** Implementation of the platform upcalls; see [KagemushaWalletAndroidPlatformV1]. */
internal class KagemushaWalletAndroidPlatformAdapterV1(
    private val environment: KagemushaWalletAndroidEnvironmentV1,
    keyStore: KagemushaWalletAndroidKeyStoreV1,
) {
    private val paymentKey: KagemushaWalletAndroidPaymentKeyV1

    init {
        check(environment.apiLevel >= KAGEMUSHA_WALLET_ANDROID_MIN_API_V1) {
            "KAGEMUSHA wallet custody requires API 31 (keystore2); keystore1 masks errors as absent keys"
        }
        kagemushaWalletAndroidCustodyRefusalV1(environment)?.let { throw IllegalStateException(it) }
        check(!environment.isDeviceProtectedStorage()) {
            "KAGEMUSHA wallet custody requires the credential-encrypted application context"
        }
        paymentKey = KagemushaWalletAndroidPaymentKeyV1(keyStore, environment)
    }

    /** Probe the payment key of [slot] (32 nonzero bytes). */
    fun keyProbe(slot: ByteArray): KagemushaWalletAndroidKeyProbeV1 = paymentKey.probe(slot)

    /**
     * Generate the payment key of [slot] with [challengeDigest] as the attestation challenge
     * under the Rust `KagemushaWalletKeyProfileV1` tag [profileTag]. Never replaces an entry.
     */
    fun keyGenerate(slot: ByteArray, challengeDigest: ByteArray, profileTag: Int): KagemushaWalletAndroidKeyGenerationV1 {
        val profile = requireNotNull(KagemushaWalletAndroidKeyProfileV1.fromTag(profileTag)) { "unknown key profile tag" }
        return paymentKey.generate(slot, challengeDigest, profile)
    }

    /** Sign the exact digest [message] with the payment key of [slot]. */
    fun keySign(slot: ByteArray, message: ByteArray): KagemushaWalletAndroidSignatureV1 = paymentKey.sign(slot, message)

    /** Delete the payment key of [slot]; the Rust provider calls this only at custody deletion. */
    fun keyDelete(slot: ByteArray): KagemushaWalletAndroidRemoveV1 = paymentKey.delete(slot)

    /** Export the attestation chain of the payment key of [slot], leaf first. */
    fun attestationChain(slot: ByteArray): KagemushaWalletAndroidAttestationChainV1 = paymentKey.attestationChain(slot)

    /** Rust `KagemushaWalletAnchorPolicyV1` tag: Android keeps no rollback anchor. */
    fun anchorPolicyTag(): Int = KAGEMUSHA_WALLET_ANDROID_ANCHOR_NOT_REQUIRED_TAG_V1

    /** Null when credential-encrypted storage is available; otherwise why it is not. */
    fun storageState(): KagemushaWalletAndroidUnavailableV1? = try {
        if (environment.isUserUnlocked()) null else KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK
    } catch (error: Throwable) {
        KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE)
    }

    /**
     * The custody root: `<canonical noBackupFilesDir>/kagemusha-wallet-v1` of the
     * credential-encrypted context. It is available only after the user unlocked the device; the
     * Rust provider creates and syncs the directory itself.
     */
    fun custodyRoot(): KagemushaWalletAndroidCustodyRootV1 {
        storageState()?.let { return KagemushaWalletAndroidCustodyRootV1.Unavailable(it) }
        val parent = try {
            environment.noBackupFilesDir().canonicalPath
        } catch (error: IOException) {
            return KagemushaWalletAndroidCustodyRootV1.Unavailable(KagemushaWalletAndroidUnavailableV1.io(0))
        } catch (error: Throwable) {
            return KagemushaWalletAndroidCustodyRootV1.Unavailable(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE),
            )
        }
        if (!File(parent).isAbsolute) {
            return KagemushaWalletAndroidCustodyRootV1.Unavailable(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE),
            )
        }
        return KagemushaWalletAndroidCustodyRootV1.Present(File(parent, KAGEMUSHA_WALLET_ANDROID_CUSTODY_DIR_NAME_V1).path)
    }
}

/** Rust `KagemushaWalletAnchorPolicyV1::NotRequired` tag. */
internal const val KAGEMUSHA_WALLET_ANDROID_ANCHOR_NOT_REQUIRED_TAG_V1: Int = 0

/** Rust `KAGEMUSHA_WALLET_ROOT_DIR_NAME_V1`. */
internal const val KAGEMUSHA_WALLET_ANDROID_CUSTODY_DIR_NAME_V1: String = "kagemusha-wallet-v1"
