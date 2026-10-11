// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.Context
import java.io.File
import java.io.IOException
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1PolicyV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1ResultV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidKeyAttestationOriginalV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AttestationResult
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1

// Rust JNI retains this opaque object and calls nativeCall from attached worker threads.
// TODO(G3/G4): authenticated operation/Λ/Ω artifact loading still gates native wallet open.
// TODO(G2-android): declare `android:manageSpaceActivity` with a custody warning screen so
// Settings > Storage offers "Manage space" instead of silently clearing custody (device test).

/**
 * Opaque Android platform handle of the KAGEMUSHA wallet `Advance` provider (spec §§1.2, 2.2,
 * 2.3, 4.2; G2 design rev 2).
 *
 * The only public operation exports the E5 evidence of a native-selected enrollment target,
 * with the adapter's own pre-E5 admission check ([enrollmentEvidence]).
 * Its private methods are the JNI upcalls of the Rust
 * `KagemushaWalletPlatformV1` adapter (JNI ignores Kotlin visibility; `consumer-rules.pro` keeps
 * them): the tri-state payment-key probe, generation bound to the issuer challenge digest under
 * the one StrongBox-then-TEE plan, `SHA256withECDSA` signing of the exact 32-byte Poseidon signing
 * message (KeyMint hashes it with SHA-256; never a no-digest mode) that returns the platform DER, key
 * deletion for custody deletion, attestation-chain export, the anchor policy (Android keeps no
 * rollback anchor), storage state and the custody root path. Only the Rust role-checked signers
 * reach the signing upcall, so app code holding the handle cannot sign arbitrary bytes with the
 * payment key through this module. Every custody file, marker and decision stays in Rust.
 *
 * [create] refuses (`IllegalStateException`) unless all of these hold:
 * - API level 26 or higher; API 26–30 initial generation requires Native's one-shot fresh grant;
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
    /**
     * E5 evidence of the exact native-selected payment key, right after its generation: the
     * original leaf-first KeyMint chain and this adapter's own check of it (design §2.4). The
     * check applies the Phone and App steps of the enrollment policy's Android admission to the
     * chain, under the Android admission inputs of the selected app and enrollment policies
     * ([AndroidAttestationE1PolicyV1.fromPolicyOriginals]), and reports the first failure as
     * its closed refusal reason. On [KagemushaWalletAndroidEnrollmentEvidenceV1.Ineligible]
     * the app abandons the attempt ([KagemushaWalletEnrollmentV1.abandon]) and words the
     * refusal by its holder class; it never submits that chain. The issuer stays authoritative:
     * [KagemushaWalletAndroidEnrollmentEvidenceV1.Eligible] admits nothing.
     *
     * @throws KagemushaWalletExceptionV1 -5 when storage or the key is unavailable now (retry),
     * -7 when the key differs from the target and -13 when it is definitively absent.
     */
    fun enrollmentEvidence(
        target: KagemushaWalletEnrollmentTargetV1,
        policy: AndroidAttestationE1PolicyV1,
    ): KagemushaWalletAndroidEnrollmentEvidenceV1 {
        val certificates = adapter.enrollmentCertificates(target)
        return when (val checked = AndroidKeyAttestationOriginalV1.e1Admission(certificates, target.challengeDigest(), target.paymentKey(), policy)) {
            is AndroidAttestationE1ResultV1.Eligible -> KagemushaWalletAndroidEnrollmentEvidenceV1.Eligible(
                certificates, checked.securityLevel == AttestationResult.SecurityLevel.STRONG_BOX,
            )
            is AndroidAttestationE1ResultV1.Ineligible -> KagemushaWalletAndroidEnrollmentEvidenceV1.Ineligible(checked.refusal, checked.detail)
        }
    }

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

    // One typed JNI handoff keeps result decoding independent of Kotlin sealed-class names.
    // It is private: Rust owns signing (2) and consumes its fresh-enrollment grant before (11).
    @Suppress("unused")
    private fun nativeCall(operation: Int, slot: ByteArray, input: ByteArray, auxiliary: Int): KagemushaWalletNativeReplyV1 =
        when (operation) {
            0 -> when (val result = keyProbe(slot)) {
                is KagemushaWalletAndroidKeyProbeV1.Present -> KagemushaWalletNativeReplyV1(0, bytes = result.publicKeySec1())
                KagemushaWalletAndroidKeyProbeV1.Absent -> KagemushaWalletNativeReplyV1(1)
                is KagemushaWalletAndroidKeyProbeV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            1 -> when (val result = keyGenerate(slot, input, auxiliary)) {
                is KagemushaWalletAndroidKeyGenerationV1.Generated -> KagemushaWalletNativeReplyV1(0, bytes = result.publicKeySec1())
                KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent -> KagemushaWalletNativeReplyV1(3)
                is KagemushaWalletAndroidKeyGenerationV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            2 -> when (val result = keySign(slot, input)) {
                is KagemushaWalletAndroidSignatureV1.Der -> KagemushaWalletNativeReplyV1(0, bytes = result.der())
                is KagemushaWalletAndroidSignatureV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            3 -> when (val result = keyDelete(slot)) {
                KagemushaWalletAndroidRemoveV1.Removed -> KagemushaWalletNativeReplyV1(0)
                is KagemushaWalletAndroidRemoveV1.NotRemoved -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
                is KagemushaWalletAndroidRemoveV1.Uncertain -> KagemushaWalletNativeReplyV1.unavailable(result.reason, 4)
            }
            7 -> storageState()?.let { KagemushaWalletNativeReplyV1.unavailable(it) } ?: KagemushaWalletNativeReplyV1(0)
            9 -> when (val result = custodyRoot()) {
                is KagemushaWalletAndroidCustodyRootV1.Present -> KagemushaWalletNativeReplyV1(0, bytes = result.path.toByteArray(Charsets.UTF_8))
                is KagemushaWalletAndroidCustodyRootV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            10 -> storageState()?.let { KagemushaWalletNativeReplyV1.unavailable(it) }
                ?: KagemushaWalletNativeReplyV1(0, reason = 0, code = adapter.keyGenerationMode())
            11 -> when (val result = adapter.keyGenerateFreshFromNative(slot, input, auxiliary)) {
                is KagemushaWalletAndroidKeyGenerationV1.Generated -> KagemushaWalletNativeReplyV1(0, bytes = result.publicKeySec1())
                KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent -> KagemushaWalletNativeReplyV1(3)
                is KagemushaWalletAndroidKeyGenerationV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            12 -> when(val result=attestationChain(slot)) {
                is KagemushaWalletAndroidAttestationChainV1.Present -> KagemushaWalletNativeReplyV1(0,chain=result.certificatesDer().toTypedArray())
                KagemushaWalletAndroidAttestationChainV1.Absent -> KagemushaWalletNativeReplyV1(1)
                is KagemushaWalletAndroidAttestationChainV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
            }
            13 -> when (val result = adapter.keyGenerationRecovery(slot, input, auxiliary)) {
                null -> KagemushaWalletNativeReplyV1(3) // No actual return held; never an absence verdict.
                is KagemushaWalletAndroidKeyGenerationV1.Generated -> KagemushaWalletNativeReplyV1(0, bytes = result.publicKeySec1())
                is KagemushaWalletAndroidKeyGenerationV1.Unavailable -> KagemushaWalletNativeReplyV1.unavailable(result.reason)
                KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent -> KagemushaWalletNativeReplyV1(2)
            }
            else -> KagemushaWalletNativeReplyV1(2)
        }

    companion object {
        /**
         * Create the handle over the application's credential-encrypted context and
         * AndroidKeyStore.
         *
         * @throws IllegalStateException when the device is below API 26, the application allows
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

private fun enrollmentCertificatesUnavailable(reason: KagemushaWalletAndroidUnavailableV1): Nothing =
    throw KagemushaWalletExceptionV1(-5, reason.kind.tag, reason.code)

/**
 * E5 evidence of one freshly generated payment key with the Android adapter's own pre-E5 check
 * (design §2.4). Neither form is an admission or a device verdict beyond its closed reason.
 */
sealed class KagemushaWalletAndroidEnrollmentEvidenceV1 {
    /** Every client-checkable admission step passed; submit exactly these certificates at E5. */
    class Eligible internal constructor(certificates: List<ByteArray>, @JvmField val strongBox: Boolean) :
        KagemushaWalletAndroidEnrollmentEvidenceV1() {
        private val chain = certificates.map { it.copyOf() }

        /** Copies of the original leaf-first DER certificates for `prepareRequest`. */
        fun certificatesDer(): List<ByteArray> = chain.map { it.copyOf() }

        override fun toString(): String = "Eligible(${chain.size} certificates, strongBox=$strongBox)"
    }

    /**
     * The first failing check as its closed §2.4 reason. Abandon the attempt; the holder class
     * says whether to start again (App, Attempt) or not on this phone (Phone).
     */
    class Ineligible internal constructor(
        @JvmField val refusal: KagemushaWalletEnrollmentRefusalV1,
        @JvmField val detail: String,
    ) : KagemushaWalletAndroidEnrollmentEvidenceV1() {
        override fun toString(): String = "Ineligible(${refusal.name})"
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
            "KAGEMUSHA wallet custody requires API 26 or later"
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
     * Generate the payment key of [slot] with [challengeDigest] as the attestation challenge.
     * [profileTag] must be the Android platform's only Rust `KagemushaWalletKeyProfileV1` tag
     * (SecureElementOrTee, 2); any other tag fails closed. Never replaces an entry.
     */
    fun keyGenerate(slot: ByteArray, challengeDigest: ByteArray, profileTag: Int): KagemushaWalletAndroidKeyGenerationV1 {
        kagemushaWalletAndroidRequireKeyProfileV1(profileTag)
        return paymentKey.generate(slot, challengeDigest)
    }

    /** Recover only a positive generate return held by this same platform owner; never generates. */
    fun keyGenerationRecovery(slot: ByteArray, challengeDigest: ByteArray, profileTag: Int): KagemushaWalletAndroidKeyGenerationV1? {
        kagemushaWalletAndroidRequireKeyProfileV1(profileTag)
        return paymentKey.recoverGeneration(slot, challengeDigest)
    }

    /** Actual JNI generation mode: 1 needs Native fresh provenance; 0 has definitive absence. */
    fun keyGenerationMode(): Int = if (environment.apiLevel < KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1) 1 else 0

    /** Only nativeCall operation 11 reaches this after consuming Native's bound fresh grant. */
    fun keyGenerateFreshFromNative(slot: ByteArray, challengeDigest: ByteArray, profileTag: Int): KagemushaWalletAndroidKeyGenerationV1 {
        kagemushaWalletAndroidRequireKeyProfileV1(profileTag)
        storageState()?.let { return KagemushaWalletAndroidKeyGenerationV1.Unavailable(it) }
        return paymentKey.generateFreshFromNative(slot, challengeDigest)
    }

    /**
     * Sign the exact 32-byte signing [message] (the Rust `KagemushaWalletSignMessageV1` bytes)
     * with the payment key of [slot] through `SHA256withECDSA`.
     */
    fun keySign(slot: ByteArray, message: ByteArray): KagemushaWalletAndroidSignatureV1 = paymentKey.sign(slot, message)

    /** Delete the payment key of [slot]; the Rust provider calls this only at custody deletion. */
    fun keyDelete(slot: ByteArray): KagemushaWalletAndroidRemoveV1 = paymentKey.delete(slot)

    /** Export the attestation chain of the payment key of [slot], leaf first. */
    fun attestationChain(slot: ByteArray): KagemushaWalletAndroidAttestationChainV1 = paymentKey.attestationChain(slot)

    fun enrollmentAttestationChain(slot: ByteArray, expectedPaymentKey: ByteArray): KagemushaWalletAndroidAttestationChainV1 =
        paymentKey.enrollmentAttestationChain(slot, expectedPaymentKey)

    /** Original DER for the exact native-selected payment key, with no attestation verdict. */
    fun enrollmentCertificates(target: KagemushaWalletEnrollmentTargetV1): List<ByteArray> {
        storageState()?.let { enrollmentCertificatesUnavailable(it) }
        when (val key = keyProbe(target.slot())) {
            is KagemushaWalletAndroidKeyProbeV1.Present ->
                if (!key.publicKeySec1().contentEquals(target.paymentKey())) throw KagemushaWalletExceptionV1(-7)
            KagemushaWalletAndroidKeyProbeV1.Absent -> throw KagemushaWalletExceptionV1(-13)
            is KagemushaWalletAndroidKeyProbeV1.Unavailable -> enrollmentCertificatesUnavailable(key.reason)
        }
        val result = when (val chain = attestationChain(target.slot())) {
            is KagemushaWalletAndroidAttestationChainV1.Present -> chain.certificatesDer()
            KagemushaWalletAndroidAttestationChainV1.Absent -> throw KagemushaWalletExceptionV1(-13)
            is KagemushaWalletAndroidAttestationChainV1.Unavailable -> enrollmentCertificatesUnavailable(chain.reason)
        }
        storageState()?.let { enrollmentCertificatesUnavailable(it) }
        return result
    }

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
