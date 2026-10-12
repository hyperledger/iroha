// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import android.content.pm.ApplicationInfo
import android.security.keystore.KeyProperties
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.SignatureException
import java.security.cert.X509Certificate
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidKeyAttestationOriginalV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AttestationResult

/**
 * Android payment key of one wallet slot (spec §§2.2, 2.3, 4.2; G2 design rev 2 E3).
 *
 * The Keystore alias is `kgm-w1-<slot hex>`. API 31+ [generate] requires definitive absence.
 * On API 26–30, a null lookup is unknown. Only Native's original fresh-slot enrollment may
 * reach [generateFreshFromNative], once, after publishing its intent. Native consumes its
 * non-reconstitutable grant before that private JNI upcall; no restored file or retry can
 * authorize another call. This adapter records the alias used before touching the provider.
 *
 * A positive lookup is usable on API 26+, but no error or API 26–30 null is absence. No path
 * deletes or regenerates a key in response to an error. There is one hardware plan and no
 * policy-driven selector or refusal plan: StrongBox where the phone declares it, otherwise the
 * TEE (design §2.2). A StrongBox failure before key creation never falls back on the same
 * slot, alias, grant or challenge: the slot is spent and abandoned locally (§3.2), and only an
 * in-memory hardware-choice hint carries into a freshly authorized slot under a new challenge,
 * on API 26–30 and API 31+ alike. Neither the hint nor the alias set is persistent freshness
 * or rollback authority.
 */
internal class KagemushaWalletAndroidPaymentKeyV1(
    private val keyStore: KagemushaWalletAndroidKeyStoreV1,
    private val environment: KagemushaWalletAndroidEnvironmentV1,
) {
    private val lock = Any()

    /** Aliases this process generated under, saw occupied or deleted; never generated under again. */
    private val usedAliases = HashSet<String>()
    // Actual positive vendor returns belong to this platform owner before any readback can fail.
    // Keeping a return never grants generation or treats an existing alias as a generated key.
    private val generationReturns = HashMap<String, GenerationReturn>()
    private class GenerationReturn(val pair: KeyPair, challenge: ByteArray, val level: KagemushaWalletAndroidSecurityLevelV1) {
        val challenge = challenge.copyOf()
    }

    /** Read-only recovery of this owner's actual positive return, bound to the original request. */
    fun recoverGeneration(slot: ByteArray, challengeDigest: ByteArray): KagemushaWalletAndroidKeyGenerationV1? = synchronized(lock) {
        val alias = kagemushaWalletAndroidAliasV1(slot)
        val challenge = challengeDigest.copyOf()
        require(challenge.size == 32 && challenge.any { it != 0.toByte() })
        val returned = generationReturns[alias] ?: return@synchronized null
        if (!returned.challenge.contentEquals(challenge)) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        }
        if (kagemushaWalletAndroidCustodyRefusalV1(environment) != null) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED))
        }
        try {
            if (!environment.isUserUnlocked()) return@synchronized unavailableGeneration(
                KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK)
        } catch (error: Throwable) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE))
        }
        readBack(alias, challenge, returned.level)
    }

    // A definitive StrongBox failure before key creation spends its slot. The next generation on
    // a different, freshly authorized slot under a different (new) challenge uses the TEE. This
    // is a one-shot hardware-choice hint: never a generation grant, durable record or retry token.
    private var teeHint: TeeHint? = null

    private class TeeHint(val failedAlias: String, failedChallenge: ByteArray) {
        private val challenge = failedChallenge.copyOf()

        fun appliesTo(alias: String, challengeDigest: ByteArray): Boolean =
            alias != failedAlias && !challenge.contentEquals(challengeDigest)
    }

    /** API 31+ aliases whose StrongBox attempt definitively failed; they answer the same refusal. */
    private val strongBoxFailedAliases = HashSet<String>()

    /** Tri-state probe through `KeyStore.getKey`; the public key comes from the attested leaf. */
    fun probe(slot: ByteArray): KagemushaWalletAndroidKeyProbeV1 = synchronized(lock) {
        when (val probed = probeEntry(kagemushaWalletAndroidAliasV1(slot))) {
            is Probed.Present -> KagemushaWalletAndroidKeyProbeV1.Present(probed.chain.publicKeySec1)
            Probed.Absent -> KagemushaWalletAndroidKeyProbeV1.Absent
            is Probed.Unavailable -> KagemushaWalletAndroidKeyProbeV1.Unavailable(probed.reason)
        }
    }

    /**
     * Generate the payment key of [slot] under [challengeDigest] (design E3). Only a definitive
     * absence (API 31+) reaches the provider; an API 26–30 null stays unknown.
     *
     * Order: custody guard, spent aliases, in-process alias reuse, definitive absence, hardware
     * plan, generation, then readback. StrongBox is used where the phone declares it; a StrongBox
     * failure spends this slot (its alias is never generated again and answers the same refusal)
     * and leaves the TEE hint for a fresh slot under a new challenge. A generated key that does
     * not match the request is reported `KEY_UNUSABLE` and left in place: the provider then
     * abandons the slot.
     */
    fun generate(
        slot: ByteArray,
        challengeDigest: ByteArray,
    ): KagemushaWalletAndroidKeyGenerationV1 = synchronized(lock) { generateLocked(slot, challengeDigest) }

    /**
     * Private Native enrollment upcall on API 26–30 only. Native has already consumed the
     * one-shot grant bound to this platform owner, fresh slot and challenge. Calling this
     * internal adapter is not itself evidence of freshness; only nativeCall operation 11 may
     * reach it in production. There is no caller-supplied "fresh" flag or replayable grant.
     */
    fun generateFreshFromNative(
        slot: ByteArray,
        challengeDigest: ByteArray,
    ): KagemushaWalletAndroidKeyGenerationV1 = synchronized(lock) {
        val alias = kagemushaWalletAndroidAliasV1(slot)
        val challenge = challengeDigest.copyOf()
        require(challenge.size == 32 && challenge.any { it != 0.toByte() }) {
            "attestation challenge must be the nonzero 32-byte challenge digest"
        }
        if (environment.apiLevel !in (KAGEMUSHA_WALLET_ANDROID_MIN_API_V1 until KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1)) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED,
            ))
        }
        if (kagemushaWalletAndroidCustodyRefusalV1(environment) != null) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED,
            ))
        }
        try {
            if (!environment.isUserUnlocked()) {
                return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.BEFORE_FIRST_UNLOCK)
            }
        } catch (error: Throwable) {
            return@synchronized unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_STORAGE,
            ))
        }
        // Burn the alias before even probing. Any provider exception ends this grant's attempt.
        if (!usedAliases.add(alias)) return@synchronized KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent
        val useTeeHint = teeHint?.appliesTo(alias, challenge) == true
        // Spend the hint before the new slot's probe: even a probe failure cannot retry it.
        if (useTeeHint) teeHint = null
        val occupied = try {
            // Inspect the raw entry: a non-private key or malformed chain is still occupied.
            keyStore.getKey(alias) != null
        } catch (error: Throwable) {
            return@synchronized unavailableGeneration(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE))
        }
        if (occupied) return@synchronized KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent
        // Null is still unknown. Only the already-consumed Native grant authorizes creation.
        val level = when (val planned = plannedLevel(useTeeHint)) {
            is Planned.Level -> planned.level
            is Planned.Unavailable -> return@synchronized unavailableGeneration(planned.reason)
        }
        when (val generated = attempt(alias, challenge, level == KagemushaWalletAndroidSecurityLevelV1.STRONGBOX)) {
            Attempt.Generated -> readBack(alias, challenge, level)
            Attempt.StrongBoxUnavailable -> strongBoxFailed(alias, challenge, level)
            is Attempt.Failed -> unavailableGeneration(generated.reason)
        }
    }

    private fun generateLocked(
        slot: ByteArray,
        challengeDigest: ByteArray,
    ): KagemushaWalletAndroidKeyGenerationV1 {
        val alias = kagemushaWalletAndroidAliasV1(slot)
        val challenge = challengeDigest.copyOf()
        require(challenge.size == 32 && challenge.any { it != 0.toByte() }) {
            "attestation challenge must be the nonzero 32-byte challenge digest"
        }
        if (kagemushaWalletAndroidCustodyRefusalV1(environment) != null) {
            return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_BACKUP_ENABLED,
            ))
        }
        // A slot whose StrongBox attempt failed is spent: same answer, no Keystore access.
        if (alias in strongBoxFailedAliases) return strongBoxUnavailable()
        if (alias in usedAliases) return KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent
        when (val probed = probeEntry(alias)) {
            Probed.Absent -> {}
            is Probed.Present -> return occupied(alias)
            is Probed.Unavailable -> return unavailableGeneration(probed.reason)
        }
        val useTeeHint = teeHint?.appliesTo(alias, challenge) == true
        val level = when (val planned = plannedLevel(useTeeHint)) {
            is Planned.Level -> planned.level
            is Planned.Unavailable -> return unavailableGeneration(planned.reason)
        }
        // The hint is spent by the attempt it selects, after definitive absence.
        if (useTeeHint) teeHint = null
        return when (val generated = attempt(alias, challenge, level == KagemushaWalletAndroidSecurityLevelV1.STRONGBOX)) {
            Attempt.Generated -> readBack(alias, challenge, level)
            Attempt.StrongBoxUnavailable -> strongBoxFailed(alias, challenge, level)
            is Attempt.Failed -> unavailableGeneration(generated.reason)
        }
    }

    /** The one hardware plan's level for this attempt; the TEE hint selects the TEE. */
    private fun plannedLevel(useTeeHint: Boolean): Planned {
        if (useTeeHint) return Planned.Level(KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT)
        val plan = try {
            kagemushaWalletAndroidHardwarePlanV1(environment.apiLevel, environment.apiLevel >= 28 && environment.hasStrongBox())
        } catch (error: Throwable) {
            return Planned.Unavailable(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE))
        }
        return Planned.Level(when (plan) {
            KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_THEN_TEE -> KagemushaWalletAndroidSecurityLevelV1.STRONGBOX
            KagemushaWalletAndroidHardwarePlanV1.TEE_ONLY -> KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT
        })
    }

    /**
     * StrongBox definitively failed before creating a key. A TEE request never reports this, so
     * it is then an unknown generation failure. Otherwise the slot is spent and the hint is left
     * for a fresh slot under a new challenge.
     */
    private fun strongBoxFailed(
        alias: String,
        challenge: ByteArray,
        level: KagemushaWalletAndroidSecurityLevelV1,
    ): KagemushaWalletAndroidKeyGenerationV1 {
        if (level != KagemushaWalletAndroidSecurityLevelV1.STRONGBOX) {
            return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.platform(
                KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED,
            ))
        }
        usedAliases += alias
        strongBoxFailedAliases += alias
        teeHint = TeeHint(alias, challenge)
        return strongBoxUnavailable()
    }

    private fun strongBoxUnavailable(): KagemushaWalletAndroidKeyGenerationV1 = unavailableGeneration(
        KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_STRONGBOX_UNAVAILABLE),
    )

    /**
     * Sign the exact 32-byte signing [message] with `SHA256withECDSA` (owner answer A1): the
     * message is the canonical encoding of the Poseidon value `P_bytes(d, transcript)` that the
     * Rust domain-checked signer computed, and KeyMint hashes it once with SHA-256. Nothing here
     * prefixes, hashes or truncates it. The platform's DER is returned unmodified; Rust normalizes
     * it to low S and verifies it under the payment key.
     *
     * @throws IllegalArgumentException for a message that is not exactly 32 bytes.
     */
    fun sign(slot: ByteArray, message: ByteArray): KagemushaWalletAndroidSignatureV1 =
        synchronized(lock) { signLocked(slot, message) }

    private fun signLocked(slot: ByteArray, signingMessage: ByteArray): KagemushaWalletAndroidSignatureV1 {
        val alias = kagemushaWalletAndroidAliasV1(slot)
        val message = signingMessage.copyOf()
        require(message.size == KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1) {
            "signing message must be exactly $KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1 bytes"
        }
        val key = when (val loaded = loadKey(alias)) {
            is Loaded.Key -> loaded.key
            Loaded.Absent -> return KagemushaWalletAndroidSignatureV1.Unavailable(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENT),
            )
            is Loaded.Unavailable -> return KagemushaWalletAndroidSignatureV1.Unavailable(loaded.reason)
        }
        return try {
            KagemushaWalletAndroidSignatureV1.Der(keyStore.sign(key, message))
        } catch (error: Throwable) {
            KagemushaWalletAndroidSignatureV1.Unavailable(
                when {
                    permanentlyInvalidated(error) -> KagemushaWalletAndroidUnavailableV1.PERMANENTLY_INVALIDATED
                    error is InvalidKeyException || error is SignatureException -> KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE
                    else -> KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_SIGN_FAILED)
                },
            )
        }
    }

    /** Delete the key of [slot] (custody deletion step D3 only); the outcome comes from a fresh probe. */
    fun delete(slot: ByteArray): KagemushaWalletAndroidRemoveV1 = synchronized(lock) { deleteLocked(slot) }

    private fun deleteLocked(slot: ByteArray): KagemushaWalletAndroidRemoveV1 {
        val alias = kagemushaWalletAndroidAliasV1(slot)
        usedAliases += alias
        // Below API 31 deletion cannot establish definitive absence, so it does not touch Keystore.
        if (!environment.keystore2()) {
            return KagemushaWalletAndroidRemoveV1.Uncertain(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED),
            )
        }
        val failure = try {
            keyStore.deleteEntry(alias)
            null
        } catch (error: Throwable) {
            error
        }
        return when (val after = loadKey(alias)) {
            Loaded.Absent -> KagemushaWalletAndroidRemoveV1.Removed
            is Loaded.Key -> KagemushaWalletAndroidRemoveV1.NotRemoved(
                failure?.let { classify(it, KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE) }
                    ?: KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE),
            )
            is Loaded.Unavailable -> KagemushaWalletAndroidRemoveV1.Uncertain(after.reason)
        }
    }

    /** Export the attestation chain (leaf first) of a present key; never absence from a null chain. */
    fun attestationChain(slot: ByteArray): KagemushaWalletAndroidAttestationChainV1 = synchronized(lock) {
        when (val probed = probeEntry(kagemushaWalletAndroidAliasV1(slot))) {
            is Probed.Present -> KagemushaWalletAndroidAttestationChainV1.Present(probed.chain.der)
            Probed.Absent -> KagemushaWalletAndroidAttestationChainV1.Absent
            is Probed.Unavailable -> KagemushaWalletAndroidAttestationChainV1.Unavailable(probed.reason)
        }
    }

    /** Read-only original chain intake, bound to the exact public key reconciled by Native. */
    fun enrollmentAttestationChain(slot: ByteArray, expectedPaymentKey: ByteArray): KagemushaWalletAndroidAttestationChainV1 = synchronized(lock) {
        when (val probed = probeEntry(kagemushaWalletAndroidAliasV1(slot))) {
            is Probed.Present -> if (probed.chain.publicKeySec1.contentEquals(expectedPaymentKey)) {
                KagemushaWalletAndroidAttestationChainV1.Present(probed.chain.der)
            } else KagemushaWalletAndroidAttestationChainV1.Unavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
            Probed.Absent -> KagemushaWalletAndroidAttestationChainV1.Absent
            is Probed.Unavailable -> KagemushaWalletAndroidAttestationChainV1.Unavailable(probed.reason)
        }
    }

    /**
     * One provider generation call. The fresh-only caller already burned the alias; the API
     * 31+ caller may retry a generic failure only after definitive absence, never a StrongBox
     * failure. Success marks the alias used.
     */
    private fun attempt(alias: String, challenge: ByteArray, strongBox: Boolean): Attempt = try {
        val pair = keyStore.generate(KagemushaWalletAndroidKeySpecV1(alias, challenge, strongBox))
        generationReturns[alias] = GenerationReturn(pair, challenge,
            if (strongBox) KagemushaWalletAndroidSecurityLevelV1.STRONGBOX
            else KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT)
        usedAliases += alias
        Attempt.Generated
    } catch (unavailable: KagemushaWalletAndroidStrongBoxUnavailableV1) {
        Attempt.StrongBoxUnavailable
    } catch (error: Throwable) {
        Attempt.Failed(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED))
    }

    /**
     * Readback of a generated key: every available `KeyInfo` field must match the request; the
     * attestation's signed `KeyDescription` must carry the challenge, matching
     * TEE or StrongBox attestation and Keymaster levels equal to the planned level, hardware-
     * enforced SIGN / EC / 256 / SHA-256 / P-256 / GENERATED, and no usage limit (tag 405).
     */
    private fun readBack(
        alias: String,
        challenge: ByteArray,
        level: KagemushaWalletAndroidSecurityLevelV1,
    ): KagemushaWalletAndroidKeyGenerationV1 {
        val present = when (val probed = probeEntry(alias)) {
            is Probed.Present -> probed
            Probed.Absent -> return unavailableGeneration(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_GENERATION_FAILED),
            )
            is Probed.Unavailable -> return unavailableGeneration(probed.reason)
        }
        val returned = generationReturns[alias]
            ?: return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        // Validate the original vendor public key against the independently read attested leaf.
        // Even a replacement key with a valid chain for the same challenge cannot be adopted.
        val matches = try {
            val original = returned.pair.public as? ECPublicKey
            val current = present.chain.certificates.first().publicKey as? ECPublicKey
            original != null && current != null && returned.pair.private.encoded == null &&
                original.w == current.w &&
                original.params.curve == current.params.curve &&
                original.params.generator == current.params.generator &&
                original.params.order == current.params.order &&
                original.params.cofactor == current.params.cofactor &&
                returned.challenge.contentEquals(challenge) && returned.level == level
        } catch (error: Throwable) { false }
        if (!matches) return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        val facts = try {
            keyStore.facts(present.key)
        } catch (error: Throwable) {
            return unavailableGeneration(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE))
        }
        if (!kagemushaWalletAndroidFactsMatchV1(facts, level, exportable = present.key.encoded != null, apiLevel = environment.apiLevel)) {
            return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        }
        val attested = try {
            AndroidKeyAttestationOriginalV1.persistentAppHardwareSecurityLevel(present.chain.certificates, challenge)
        } catch (error: Throwable) {
            return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        }
        if (attested != kagemushaWalletAndroidAttestedLevelV1(level)) {
            return unavailableGeneration(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        }
        return KagemushaWalletAndroidKeyGenerationV1.Generated(present.chain.publicKeySec1, level)
    }

    private fun readChain(alias: String): Chain {
        val certificates = try {
            keyStore.getCertificateChain(alias)
        } catch (error: Throwable) {
            return Chain.Invalid(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE))
        } ?: return Chain.Invalid(
            KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE),
        )
        val x509 = certificates.map {
            it as? X509Certificate ?: return Chain.Invalid(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE),
            )
        }
        val der = try {
            x509.map { it.encoded }
        } catch (error: Throwable) {
            return Chain.Invalid(KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE))
        }
        if (der.size !in 2..KAGEMUSHA_WALLET_ANDROID_CHAIN_MAX_CERTIFICATES_V1 ||
            der.any { it.size !in 1..KAGEMUSHA_WALLET_ANDROID_CERTIFICATE_MAX_BYTES_V1 }
        ) {
            return Chain.Invalid(KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_CERTIFICATE))
        }
        // The attested leaf key: the leaf's exact P-256 point, which must equal the key the
        // root-nearest KeyDescription certificate describes.
        val point = try {
            AndroidKeyAttestationOriginalV1.publicKeySec1(x509)
        } catch (error: Throwable) {
            return Chain.Invalid(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        }
        return Chain.Valid(x509, der, point)
    }

    private fun probeEntry(alias: String): Probed {
        val key = when (val loaded = loadKey(alias)) {
            is Loaded.Key -> loaded.key
            Loaded.Absent -> return Probed.Absent
            is Loaded.Unavailable -> return Probed.Unavailable(loaded.reason)
        }
        return when (val chain = readChain(alias)) {
            is Chain.Valid -> Probed.Present(key, chain)
            is Chain.Invalid -> Probed.Unavailable(chain.reason)
        }
    }

    /** Positive keys are usable on API 26+; only keystore2 null is definitive absence. */
    private fun loadKey(alias: String): Loaded {
        if (environment.apiLevel < KAGEMUSHA_WALLET_ANDROID_MIN_API_V1) {
            return Loaded.Unavailable(
                KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE_UNSUPPORTED),
            )
        }
        val key = try {
            keyStore.getKey(alias)
        } catch (error: Throwable) {
            return Loaded.Unavailable(classify(error, KagemushaWalletAndroidUnavailableV1.PLATFORM_KEYSTORE))
        } ?: return if (environment.keystore2()) Loaded.Absent else Loaded.Unavailable(
            KagemushaWalletAndroidUnavailableV1.platform(KagemushaWalletAndroidUnavailableV1.PLATFORM_KEY_ABSENCE_UNKNOWN),
        )
        if (!environment.keystore2()) usedAliases += alias
        val privateKey = key as? PrivateKey ?: return Loaded.Unavailable(KagemushaWalletAndroidUnavailableV1.KEY_UNUSABLE)
        return Loaded.Key(privateKey)
    }

    private fun occupied(alias: String): KagemushaWalletAndroidKeyGenerationV1 {
        usedAliases += alias
        return KagemushaWalletAndroidKeyGenerationV1.AlreadyPresent
    }

    private fun unavailableGeneration(reason: KagemushaWalletAndroidUnavailableV1) =
        KagemushaWalletAndroidKeyGenerationV1.Unavailable(reason)

    private fun permanentlyInvalidated(error: Throwable): Boolean = try {
        keyStore.isPermanentlyInvalidated(error)
    } catch (classification: Throwable) {
        false
    }

    private fun classify(error: Throwable, platformCode: Int): KagemushaWalletAndroidUnavailableV1 =
        if (permanentlyInvalidated(error)) {
            KagemushaWalletAndroidUnavailableV1.PERMANENTLY_INVALIDATED
        } else {
            KagemushaWalletAndroidUnavailableV1.platform(platformCode)
        }

    private sealed class Loaded {
        class Key(val key: PrivateKey) : Loaded()
        object Absent : Loaded()
        class Unavailable(val reason: KagemushaWalletAndroidUnavailableV1) : Loaded()
    }

    private sealed class Probed {
        class Present(val key: PrivateKey, val chain: Chain.Valid) : Probed()
        object Absent : Probed()
        class Unavailable(val reason: KagemushaWalletAndroidUnavailableV1) : Probed()
    }

    private sealed class Attempt {
        object Generated : Attempt()
        object StrongBoxUnavailable : Attempt()
        class Failed(val reason: KagemushaWalletAndroidUnavailableV1) : Attempt()
    }

    private sealed class Planned {
        class Level(val level: KagemushaWalletAndroidSecurityLevelV1) : Planned()
        class Unavailable(val reason: KagemushaWalletAndroidUnavailableV1) : Planned()
    }

    private sealed class Chain {
        class Valid(val certificates: List<X509Certificate>, val der: List<ByteArray>, val publicKeySec1: ByteArray) : Chain()
        class Invalid(val reason: KagemushaWalletAndroidUnavailableV1) : Chain()
    }
}

/** Lowest supported Android API; initial key creation below 31 needs Native's fresh grant. */
internal const val KAGEMUSHA_WALLET_ANDROID_MIN_API_V1: Int = 26

/** Lowest API with a definitive null result from `getKey`. */
internal const val KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1: Int = 31

private fun KagemushaWalletAndroidEnvironmentV1.keystore2(): Boolean = apiLevel >= KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1

/** Exact length of every signing message the payment key signs: one canonical σ-field value. */
internal const val KAGEMUSHA_WALLET_ANDROID_SIGNING_MESSAGE_BYTES_V1: Int = 32

/** Attestation chain bounds, as in `AndroidKeyAttestationOriginalV1`. */
internal const val KAGEMUSHA_WALLET_ANDROID_CHAIN_MAX_CERTIFICATES_V1: Int = 8
internal const val KAGEMUSHA_WALLET_ANDROID_CERTIFICATE_MAX_BYTES_V1: Int = 16 * 1024

/** Keystore alias of [slot]: `kgm-w1-` and 64 lowercase hex digits. The slot must be nonzero. */
internal fun kagemushaWalletAndroidAliasV1(slot: ByteArray): String {
    require(slot.size == 32 && slot.any { it != 0.toByte() }) { "wallet slot must be 32 nonzero bytes" }
    val hex = StringBuilder(KAGEMUSHA_WALLET_ANDROID_ALIAS_PREFIX_V1.length + 64)
    hex.append(KAGEMUSHA_WALLET_ANDROID_ALIAS_PREFIX_V1)
    for (byte in slot) {
        val value = byte.toInt() and 0xff
        hex.append(HEX_DIGITS[value ushr 4]).append(HEX_DIGITS[value and 0x0f])
    }
    return hex.toString()
}

private const val HEX_DIGITS = "0123456789abcdef"

/**
 * The one Android hardware plan (design §2.2): StrongBox where the phone declares it, otherwise
 * the TEE. [STRONGBOX_THEN_TEE] generates in StrongBox on this slot; a definitive StrongBox
 * failure spends the slot and only a fresh slot under a new challenge generates in the TEE.
 * There is no policy-driven selector and no refusal plan: a TEE-only phone enrolls in its TEE.
 */
internal enum class KagemushaWalletAndroidHardwarePlanV1 { STRONGBOX_THEN_TEE, TEE_ONLY }

/** StrongBox (API 28+) when the device declares it; otherwise the TEE. */
internal fun kagemushaWalletAndroidHardwarePlanV1(
    apiLevel: Int,
    hasStrongBox: Boolean,
): KagemushaWalletAndroidHardwarePlanV1 =
    if (apiLevel >= 28 && hasStrongBox) KagemushaWalletAndroidHardwarePlanV1.STRONGBOX_THEN_TEE
    else KagemushaWalletAndroidHardwarePlanV1.TEE_ONLY

/** Rust `KagemushaWalletKeyProfileV1::SecureElementOrTee`: the Android platform's only key profile tag. */
internal const val KAGEMUSHA_WALLET_ANDROID_KEY_PROFILE_TAG_V1: Int = 2

/** Native passes the key profile tag on every generation upcall; any other tag fails closed. */
internal fun kagemushaWalletAndroidRequireKeyProfileV1(tag: Int) {
    require(tag == KAGEMUSHA_WALLET_ANDROID_KEY_PROFILE_TAG_V1) { "unknown key profile tag" }
}

/** Attested `SecurityLevel` the planned [level] requires. */
internal fun kagemushaWalletAndroidAttestedLevelV1(level: KagemushaWalletAndroidSecurityLevelV1): AttestationResult.SecurityLevel =
    when (level) {
        KagemushaWalletAndroidSecurityLevelV1.STRONGBOX -> AttestationResult.SecurityLevel.STRONG_BOX
        KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT -> AttestationResult.SecurityLevel.TRUSTED_ENVIRONMENT
    }

/**
 * Check actual `KeyInfo` fields at their API boundary. Unavailable getters must remain null;
 * they are not inferred security levels or unlimited-use claims. The separate signed
 * attestation check is mandatory on every API, including for level and usage-limit policy.
 */
internal fun kagemushaWalletAndroidFactsMatchV1(
    facts: KagemushaWalletAndroidKeyFactsV1,
    level: KagemushaWalletAndroidSecurityLevelV1,
    exportable: Boolean,
    apiLevel: Int,
): Boolean {
    if (apiLevel < KAGEMUSHA_WALLET_ANDROID_MIN_API_V1) return false
    val expectedLevel = when (level) {
        KagemushaWalletAndroidSecurityLevelV1.STRONGBOX -> KeyProperties.SECURITY_LEVEL_STRONGBOX
        KagemushaWalletAndroidSecurityLevelV1.TRUSTED_ENVIRONMENT -> KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    }
    val newerFactsMatch = if (apiLevel >= KAGEMUSHA_WALLET_ANDROID_KEYSTORE2_API_V1) {
        facts.securityLevel == expectedLevel && facts.remainingUsageCount == KeyProperties.UNRESTRICTED_USAGE_COUNT
    } else {
        facts.securityLevel == null && facts.remainingUsageCount == null
    }
    val presenceFactsMatch = if (apiLevel >= 28) {
        facts.userPresenceRequired == false && facts.userConfirmationRequired == false
    } else {
        facts.userPresenceRequired == null && facts.userConfirmationRequired == null
    }
    return newerFactsMatch && presenceFactsMatch &&
        facts.insideSecureHardware &&
        facts.origin == KeyProperties.ORIGIN_GENERATED &&
        facts.purposes == KeyProperties.PURPOSE_SIGN &&
        facts.digests == setOf(KeyProperties.DIGEST_SHA256) &&
        facts.keySize == 256 &&
        !facts.userAuthenticationRequired &&
        !exportable
}

/** The nine full-backup domains; every one must be excluded wholesale. */
internal val KAGEMUSHA_WALLET_ANDROID_BACKUP_DOMAINS_V1: Set<String> = setOf(
    "root", "file", "database", "sharedpref", "external",
    "device_root", "device_file", "device_database", "device_sharedpref",
)

/**
 * Why this application may not hold wallet custody, or null when it may (G2 design rev 2: a
 * full-data restore stream that reaches an app without its own agent clears its data, including
 * `no_backup`, and its Keystore namespace, so the backup and transfer set must be empty).
 *
 * Checked at runtime: `FLAG_ALLOW_BACKUP` is clear, no backup agent is declared, and both rule
 * resources, as resolved in the host app (so a same-name resource override is caught), exclude
 * every domain with no include rule. Not checkable through public APIs: a host manifest that
 * replaces `android:dataExtractionRules` or `android:fullBackupContent` with another resource
 * (`tools:replace` / `tools:remove`); that stays a documented host obligation.
 */
internal fun kagemushaWalletAndroidCustodyRefusalV1(environment: KagemushaWalletAndroidEnvironmentV1): String? = try {
    when {
        environment.applicationFlags() and ApplicationInfo.FLAG_ALLOW_BACKUP != 0 ->
            "KAGEMUSHA wallet custody requires android:allowBackup=\"false\"; do not override the library manifest"
        environment.backupAgentName() != null ->
            "KAGEMUSHA wallet custody forbids an application backup agent"
        else -> kagemushaWalletAndroidBackupRulesRefusalV1(
            environment.dataExtractionRules(),
            environment.fullBackupContentRules(),
        )
    }
} catch (error: Throwable) {
    "KAGEMUSHA wallet backup configuration is unreadable: ${error.javaClass.name}"
}

/**
 * Why the parsed rule resources do not keep the backup set empty, or null when they do: the
 * data-extraction rules have exactly one `cloud-backup` and one `device-transfer` section, and
 * each section and the full-backup content exclude every domain with path `.` and nothing else.
 */
internal fun kagemushaWalletAndroidBackupRulesRefusalV1(
    dataExtraction: KagemushaWalletAndroidXmlElementV1,
    fullBackup: KagemushaWalletAndroidXmlElementV1,
): String? {
    if (dataExtraction.name != "data-extraction-rules") return "data-extraction rules have an unexpected root"
    val sections = dataExtraction.children.map { it.name }
    if (sections.sorted() != listOf("cloud-backup", "device-transfer")) {
        return "data-extraction rules must have exactly one cloud-backup and one device-transfer section"
    }
    for (section in dataExtraction.children) {
        kagemushaWalletAndroidExcludesEveryDomainV1(section)?.let { return it }
    }
    if (fullBackup.name != "full-backup-content") return "full-backup rules have an unexpected root"
    return kagemushaWalletAndroidExcludesEveryDomainV1(fullBackup)
}

private fun kagemushaWalletAndroidExcludesEveryDomainV1(section: KagemushaWalletAndroidXmlElementV1): String? {
    val rules = section.children
    val wholeDomainExcludes = rules.all {
        it.name == "exclude" && it.children.isEmpty() &&
            it.attributes.keys == setOf("domain", "path") && it.attributes["path"] == "."
    }
    if (!wholeDomainExcludes) return "${section.name} may only exclude whole domains"
    val domains = rules.map { it.attributes.getValue("domain") }
    if (domains.size != KAGEMUSHA_WALLET_ANDROID_BACKUP_DOMAINS_V1.size || domains.toSet() != KAGEMUSHA_WALLET_ANDROID_BACKUP_DOMAINS_V1) {
        return "${section.name} must exclude every domain exactly once"
    }
    return null
}
