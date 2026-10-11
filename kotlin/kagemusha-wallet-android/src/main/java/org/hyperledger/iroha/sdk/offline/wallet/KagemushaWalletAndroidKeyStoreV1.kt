// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Exact payment-key generation request (spec §§2.2, 2.3; G2 design rev 2 E3).
 *
 * Only [alias], [challengeDigest] and [strongBox] vary. The key is always EC secp256r1 with
 * `PURPOSE_SIGN` and `DIGEST_SHA256` only, never `DIGEST_NONE`: every signature of the protocol
 * is standard ECDSA-P256-SHA256 over a 32-byte Poseidon signing message, so KeyMint itself hashes
 * the message (owner answer A1). [kagemushaWalletAndroidConfigureKeyGenV1] applies it
 * through [KagemushaWalletAndroidKeyGenBuilderV1], which offers no user-authentication,
 * unlocked-device, usage-count, user-presence or user-confirmation setter: removing the screen
 * lock would otherwise invalidate the key and destroy the balance (spec §2.3).
 */
internal class KagemushaWalletAndroidKeySpecV1(
    val alias: String,
    challengeDigest: ByteArray,
    val strongBox: Boolean,
) {
    private val challenge = challengeDigest.copyOf()

    init {
        require(alias.startsWith(KAGEMUSHA_WALLET_ANDROID_ALIAS_PREFIX_V1)) { "payment-key alias is not a slot alias" }
        require(challenge.size == 32) { "attestation challenge must be the 32-byte challenge digest" }
    }

    /** The attestation challenge: the issuer challenge digest. */
    fun challengeDigest(): ByteArray = challenge.copyOf()

    val curve: String get() = "secp256r1"
    val purposes: Int get() = KeyProperties.PURPOSE_SIGN
    val digests: List<String> get() = listOf(KeyProperties.DIGEST_SHA256)
}

/**
 * The only `KeyGenParameterSpec.Builder` setters payment-key generation may reach. The builder
 * is created with the spec's alias and purposes; nothing else can be set through this interface.
 */
internal interface KagemushaWalletAndroidKeyGenBuilderV1 {
    /** `setAlgorithmParameterSpec(ECGenParameterSpec(curve))`. */
    fun algorithmParameterSpec(curve: String)

    /** `setDigests(*digests)`. */
    fun digests(digests: List<String>)

    /** `setAttestationChallenge(challenge)`. */
    fun attestationChallenge(challenge: ByteArray)

    /** `setIsStrongBoxBacked(true)` (API 28+). */
    fun strongBoxBacked()
}

/** Apply [spec] to [builder]: curve, digests, attestation challenge and, if requested, StrongBox. */
internal fun kagemushaWalletAndroidConfigureKeyGenV1(
    spec: KagemushaWalletAndroidKeySpecV1,
    builder: KagemushaWalletAndroidKeyGenBuilderV1,
) {
    builder.algorithmParameterSpec(spec.curve)
    builder.digests(spec.digests)
    builder.attestationChallenge(spec.challengeDigest())
    if (spec.strongBox) builder.strongBoxBacked()
}

/** Actual `KeyInfo` readback; null means the field does not exist on this Android API. */
internal class KagemushaWalletAndroidKeyFactsV1(
    val insideSecureHardware: Boolean,
    /** `KeyInfo.getSecurityLevel` on API 31+, otherwise unavailable. */
    val securityLevel: Int?,
    /** `KeyInfo.getRemainingUsageCount` on API 31+, otherwise unavailable. */
    val remainingUsageCount: Int?,
    val origin: Int,
    val purposes: Int,
    digests: Set<String>,
    val keySize: Int,
    val userAuthenticationRequired: Boolean,
    /** `KeyInfo.isTrustedUserPresenceRequired` on API 28+, otherwise unavailable. */
    val userPresenceRequired: Boolean?,
    /** `KeyInfo.isUserConfirmationRequired` on API 28+, otherwise unavailable. */
    val userConfirmationRequired: Boolean?,
) {
    val digests: Set<String> = digests.toSet()
}

/** Thrown by [KagemushaWalletAndroidKeyStoreV1.generate] for `StrongBoxUnavailableException`. */
internal class KagemushaWalletAndroidStrongBoxUnavailableV1(cause: Throwable?) :
    Exception("StrongBox is unavailable", cause)

/**
 * Narrow AndroidKeyStore access used by [KagemushaWalletAndroidPaymentKeyV1].
 *
 * Every method reports errors by throwing; none of them turns an error into absence.
 * A non-null [getKey] proves an occupied entry; null proves absence only on keystore2
 * (API 31+), and is unknown on API 26–30. `containsAlias`,
 * `aliases`, `size`, `isKeyEntry` and `getCertificate*` swallow Keystore errors as "absent"
 * (AOSP `AndroidKeyStoreSpi`), so they are not offered for existence decisions:
 * [getCertificateChain] is read only after [getKey] returned a key, and a null there is never
 * absence.
 */
internal interface KagemushaWalletAndroidKeyStoreV1 {
    /** `KeyStore.getKey(alias, null)`: an occupied key, an API-dependent null, or a throw. */
    fun getKey(alias: String): Key?

    /** Attestation chain (leaf first) of an entry [getKey] reported present; null is an error. */
    fun getCertificateChain(alias: String): List<Certificate>?

    /** Return the actual generated key pair under [spec]; throws [KagemushaWalletAndroidStrongBoxUnavailableV1] when StrongBox is unavailable. */
    fun generate(spec: KagemushaWalletAndroidKeySpecV1): KeyPair

    /** `KeyInfo` readback of a present key. */
    fun facts(key: PrivateKey): KagemushaWalletAndroidKeyFactsV1

    /**
     * [KAGEMUSHA_WALLET_ANDROID_SIGNATURE_ALGORITHM_V1] (`SHA256withECDSA`) over the exact 32-byte
     * signing [message]: KeyMint hashes it with SHA-256 under the key's `DIGEST_SHA256`. Returns the
     * platform's DER.
     */
    fun sign(key: PrivateKey, message: ByteArray): ByteArray

    /** `KeyStore.deleteEntry(alias)`. */
    fun deleteEntry(alias: String)

    /** Whether [error] or one of its causes reports a permanently invalidated key. */
    fun isPermanentlyInvalidated(error: Throwable): Boolean
}

/** Keystore alias prefix of payment keys: `kgm-w1-<64 lowercase hex slot digits>`. */
internal const val KAGEMUSHA_WALLET_ANDROID_ALIAS_PREFIX_V1: String = "kgm-w1-"

/**
 * JCA algorithm of every payment-key signature: ECDSA-P256 with SHA-256 over the 32-byte signing
 * message (owner answer A1). The no-digest `NONEwithECDSA` is never used.
 */
internal const val KAGEMUSHA_WALLET_ANDROID_SIGNATURE_ALGORITHM_V1: String = "SHA256withECDSA"

/** Production AndroidKeyStore access. */
internal class KagemushaWalletAndroidSystemKeyStoreV1 : KagemushaWalletAndroidKeyStoreV1 {
    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun getKey(alias: String): Key? = keyStore().getKey(alias, null)

    override fun getCertificateChain(alias: String): List<Certificate>? =
        keyStore().getCertificateChain(alias)?.toList()

    override fun generate(spec: KagemushaWalletAndroidKeySpecV1): KeyPair {
        val builder = KagemushaWalletAndroidSystemKeyGenBuilderV1(KeyGenParameterSpec.Builder(spec.alias, spec.purposes))
        kagemushaWalletAndroidConfigureKeyGenV1(spec, builder)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        return if (spec.strongBox) {
            KagemushaWalletAndroidStrongBoxApi28V1.generate(generator, builder.build())
        } else {
            generator.initialize(builder.build())
            generator.generateKeyPair()
        }
    }

    @Suppress("DEPRECATION")
    override fun facts(key: PrivateKey): KagemushaWalletAndroidKeyFactsV1 {
        val apiLevel = Build.VERSION.SDK_INT
        check(apiLevel >= KAGEMUSHA_WALLET_ANDROID_MIN_API_V1) { "KeyInfo readback requires API 26" }
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return KagemushaWalletAndroidKeyFactsV1(
            insideSecureHardware = info.isInsideSecureHardware,
            securityLevel = if (apiLevel >= 31) KagemushaWalletAndroidKeyInfoApi31V1.securityLevel(info) else null,
            remainingUsageCount = if (apiLevel >= 31) KagemushaWalletAndroidKeyInfoApi31V1.remainingUsageCount(info) else null,
            origin = info.origin,
            purposes = info.purposes,
            digests = info.digests.toSet(),
            keySize = info.keySize,
            userAuthenticationRequired = info.isUserAuthenticationRequired,
            userPresenceRequired = if (apiLevel >= 28) KagemushaWalletAndroidKeyInfoApi28V1.userPresenceRequired(info) else null,
            userConfirmationRequired = if (apiLevel >= 28) KagemushaWalletAndroidKeyInfoApi28V1.userConfirmationRequired(info) else null,
        )
    }

    override fun sign(key: PrivateKey, message: ByteArray): ByteArray {
        require(message.size == KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1) {
            "signing message must be exactly $KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1 bytes"
        }
        return Signature.getInstance(KAGEMUSHA_WALLET_ANDROID_SIGNATURE_ALGORITHM_V1).run {
            initSign(key)
            update(message)
            sign()
        }
    }

    override fun deleteEntry(alias: String) {
        keyStore().deleteEntry(alias)
    }

    override fun isPermanentlyInvalidated(error: Throwable): Boolean =
        generateSequence(error) { it.cause }.take(8).any { it is KeyPermanentlyInvalidatedException }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

/** The four permitted setters over the platform builder; see [KagemushaWalletAndroidKeyGenBuilderV1]. */
private class KagemushaWalletAndroidSystemKeyGenBuilderV1(
    private val builder: KeyGenParameterSpec.Builder,
) : KagemushaWalletAndroidKeyGenBuilderV1 {
    override fun algorithmParameterSpec(curve: String) {
        builder.setAlgorithmParameterSpec(ECGenParameterSpec(curve))
    }

    override fun digests(digests: List<String>) {
        builder.setDigests(*digests.toTypedArray())
    }

    override fun attestationChallenge(challenge: ByteArray) {
        builder.setAttestationChallenge(challenge)
    }

    override fun strongBoxBacked() {
        KagemushaWalletAndroidStrongBoxApi28V1.request(builder)
    }

    fun build(): KeyGenParameterSpec = builder.build()
}

/** Keeps API 28 method and exception linkage out of classes loaded on older devices. */
@android.annotation.TargetApi(28)
private object KagemushaWalletAndroidStrongBoxApi28V1 {
    fun request(builder: KeyGenParameterSpec.Builder) {
        builder.setIsStrongBoxBacked(true)
    }

    fun generate(generator: KeyPairGenerator, spec: KeyGenParameterSpec): KeyPair {
        return try {
            generator.initialize(spec)
            generator.generateKeyPair()
        } catch (unavailable: StrongBoxUnavailableException) {
            throw KagemushaWalletAndroidStrongBoxUnavailableV1(unavailable)
        }
    }
}

/** Keep API 28 getters out of classes loaded on API 26–27. */
@android.annotation.TargetApi(28)
private object KagemushaWalletAndroidKeyInfoApi28V1 {
    fun userPresenceRequired(info: KeyInfo): Boolean = info.isTrustedUserPresenceRequired
    fun userConfirmationRequired(info: KeyInfo): Boolean = info.isUserConfirmationRequired
}

/** Keep API 31 getters out of classes loaded on API 26–30. */
@android.annotation.TargetApi(31)
private object KagemushaWalletAndroidKeyInfoApi31V1 {
    fun securityLevel(info: KeyInfo): Int = info.securityLevel
    fun remainingUsageCount(info: KeyInfo): Int = info.remainingUsageCount
}
