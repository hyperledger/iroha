// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

// Upcall results of the KAGEMUSHA wallet platform adapter. They are internal: only the Rust
// JNI adapter reads them (by name, so `consumer-rules.pro` keeps them), and app code has no
// route to the payment key through this module.

/**
 * Reason an Android platform answer is not definitive. It is never absence.
 *
 * The kinds mirror the Rust `KagemushaWalletUnavailableV1` of
 * `crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/platform.rs` one to one, so the
 * bridge maps [kind] and [code] without interpretation. [code] is the OS error for [Kind.IO] and
 * one of the `PLATFORM_*` constants for [Kind.PLATFORM]; it is 0 for every other kind.
 */
internal class KagemushaWalletAndroidUnavailableV1 private constructor(
    @JvmField val kind: Kind,
    @JvmField val code: Int,
) {
    /** Kind of an unavailable answer; [tag] is the stable bridge value. */
    enum class Kind(@JvmField val tag: Int) {
        /** Protected storage or the key store is locked. */
        LOCKED(0),

        /** The user has not unlocked the device since boot (credential-encrypted storage). */
        BEFORE_FIRST_UNLOCK(1),

        /** Another opener holds the custody lock, or a concurrent change was observed. */
        BUSY(2),

        /** An I/O error. */
        IO(3),

        /** A platform API error; [code] names it. */
        PLATFORM(4),

        /** The key exists but refused to sign, or does not match what was generated. */
        KEY_UNUSABLE(5),

        /** The platform reports the key as permanently invalidated; it is never regenerated. */
        PERMANENTLY_INVALIDATED(6),
    }

    override fun equals(other: Any?): Boolean =
        other is KagemushaWalletAndroidUnavailableV1 && other.kind == kind && other.code == code

    override fun hashCode(): Int = kind.hashCode() * 31 + code

    override fun toString(): String = "KagemushaWalletAndroidUnavailableV1($kind, $code)"

    // The Rust `KagemushaWalletKeyGenerationV1` has no non-retryable refusal: every answer below
    // reaches enrollment as `Unavailable`. PLATFORM_STRONGBOX_UNAVAILABLE is answered for the same
    // spent slot on every retry, and the app abandons that attempt locally (§3.2) and starts a
    // fresh enrollment. PLATFORM_BACKUP_ENABLED and PLATFORM_KEYSTORE_UNSUPPORTED are holder- or
    // build-fixable preconditions, not E1 refusals (design §2.4).
    companion object {
        /**
         * Keystore access threw; the entry state is unknown. On keystore2 a permanently
         * invalidated key also lands here when it is read through `getKey`, because AOSP rethrows
         * `KeyPermanentlyInvalidatedException` as an `UnrecoverableKeyException` without a cause;
         * only signing reports [PERMANENTLY_INVALIDATED].
         */
        const val PLATFORM_KEYSTORE: Int = 1

        /** A present key's attestation chain could not be read or is malformed. */
        const val PLATFORM_CERTIFICATE: Int = 2

        /** The key to sign with is definitively absent; reconcile classifies the loss. */
        const val PLATFORM_KEY_ABSENT: Int = 3

        /** Key generation failed with an unknown outcome; probe again before acting. */
        const val PLATFORM_GENERATION_FAILED: Int = 4

        /**
         * StrongBox definitively failed before creating a key (design §2.2). This slot is spent:
         * its alias is never generated again, so abandon the attempt locally (§3.2). A fresh
         * enrollment, with a new slot and challenge, generates in the TEE. Never a device verdict.
         */
        const val PLATFORM_STRONGBOX_UNAVAILABLE: Int = 5

        /** Permanent: the app's backup or device-transfer set is not provably empty. */
        const val PLATFORM_BACKUP_ENABLED: Int = 6

        /** Signing failed for a reason other than the key itself. */
        const val PLATFORM_SIGN_FAILED: Int = 7

        /** `UserManager` or the no-backup directory could not be queried. */
        const val PLATFORM_STORAGE: Int = 8

        /** The requested operation needs a platform capability this API does not expose. */
        const val PLATFORM_KEYSTORE_UNSUPPORTED: Int = 9

        /**
         * API 26–30 `getKey` returned null, which can hide a Keystore daemon error. This is
         * unknown, never absence and never permission to generate, replace or delete a key.
         */
        const val PLATFORM_KEY_ABSENCE_UNKNOWN: Int = 10

        @JvmField val LOCKED = KagemushaWalletAndroidUnavailableV1(Kind.LOCKED, 0)
        @JvmField val BEFORE_FIRST_UNLOCK = KagemushaWalletAndroidUnavailableV1(Kind.BEFORE_FIRST_UNLOCK, 0)
        @JvmField val BUSY = KagemushaWalletAndroidUnavailableV1(Kind.BUSY, 0)
        @JvmField val KEY_UNUSABLE = KagemushaWalletAndroidUnavailableV1(Kind.KEY_UNUSABLE, 0)
        @JvmField val PERMANENTLY_INVALIDATED = KagemushaWalletAndroidUnavailableV1(Kind.PERMANENTLY_INVALIDATED, 0)

        /** An I/O error with its OS error code, or 0 when none is available. */
        @JvmStatic fun io(code: Int): KagemushaWalletAndroidUnavailableV1 =
            KagemushaWalletAndroidUnavailableV1(Kind.IO, code)

        /** A platform error named by one of the `PLATFORM_*` constants. */
        @JvmStatic fun platform(code: Int): KagemushaWalletAndroidUnavailableV1 =
            KagemushaWalletAndroidUnavailableV1(Kind.PLATFORM, code)
    }
}

/** Hardware that holds a generated payment key. */
internal enum class KagemushaWalletAndroidSecurityLevelV1 {
    /** Android StrongBox. */
    STRONGBOX,

    /** The trusted execution environment. */
    TRUSTED_ENVIRONMENT,
}

/** Tri-state probe of one slot's payment key. */
internal sealed class KagemushaWalletAndroidKeyProbeV1 {
    /** The key exists; its public key is the canonical 65-byte uncompressed P-256 point. */
    class Present(publicKeySec1: ByteArray) : KagemushaWalletAndroidKeyProbeV1() {
        private val point = publicKeySec1.copyOf()

        /** The canonical uncompressed SEC1 public key. */
        fun publicKeySec1(): ByteArray = point.copyOf()

        override fun toString(): String = "Present"
    }

    /** `KeyStore.getKey` (keystore2) definitively reported no key under the slot's alias. */
    object Absent : KagemushaWalletAndroidKeyProbeV1() {
        override fun toString(): String = "Absent"
    }

    /** No definitive answer; retry. Never absence. */
    class Unavailable(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidKeyProbeV1() {
        override fun toString(): String = "Unavailable($reason)"
    }
}

/** Outcome of one payment-key generation request. */
internal sealed class KagemushaWalletAndroidKeyGenerationV1 {
    /** A new key was generated under the slot's alias and checked against the request. */
    class Generated(
        publicKeySec1: ByteArray,
        @JvmField val securityLevel: KagemushaWalletAndroidSecurityLevelV1,
    ) : KagemushaWalletAndroidKeyGenerationV1() {
        private val point = publicKeySec1.copyOf()

        /** The canonical uncompressed SEC1 public key. */
        fun publicKeySec1(): ByteArray = point.copyOf()

        override fun toString(): String = "Generated($securityLevel)"
    }

    /** A key exists or existed under the alias, or the alias is spent; nothing was generated and the slot is used up. */
    object AlreadyPresent : KagemushaWalletAndroidKeyGenerationV1() {
        override fun toString(): String = "AlreadyPresent"
    }

    /** No key was generated, or the outcome is unknown; a fresh-only attempt must never retry. */
    class Unavailable(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidKeyGenerationV1() {
        override fun toString(): String = "Unavailable($reason)"
    }
}

/** Outcome of one payment-key signature. */
internal sealed class KagemushaWalletAndroidSignatureV1 {
    /** The platform's strict DER `SHA256withECDSA` signature, unmodified; Rust freezes it. */
    class Der(der: ByteArray) : KagemushaWalletAndroidSignatureV1() {
        private val bytes = der.copyOf()

        /** The DER signature. */
        fun der(): ByteArray = bytes.copyOf()

        override fun toString(): String = "Der(${bytes.size} bytes)"
    }

    /** The key did not sign; the operation stays pending. */
    class Unavailable(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidSignatureV1() {
        override fun toString(): String = "Unavailable($reason)"
    }
}

/** Outcome of one payment-key deletion (custody deletion only). */
internal sealed class KagemushaWalletAndroidRemoveV1 {
    /** The key is definitively absent. */
    object Removed : KagemushaWalletAndroidRemoveV1() {
        override fun toString(): String = "Removed"
    }

    /** The key is still present. */
    class NotRemoved(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidRemoveV1() {
        override fun toString(): String = "NotRemoved($reason)"
    }

    /** Whether the key is gone is unknown. */
    class Uncertain(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidRemoveV1() {
        override fun toString(): String = "Uncertain($reason)"
    }
}

/** Tri-state export of one payment key's attestation chain, leaf first. */
internal sealed class KagemushaWalletAndroidAttestationChainV1 {
    /** The DER certificates of the attestation chain, leaf first. */
    class Present(chainDer: List<ByteArray>) : KagemushaWalletAndroidAttestationChainV1() {
        private val chain = chainDer.map { it.copyOf() }

        /** Copies of the DER certificates, leaf first. */
        fun certificatesDer(): List<ByteArray> = chain.map { it.copyOf() }

        override fun toString(): String = "Present(${chain.size} certificates)"
    }

    /** The key is definitively absent. */
    object Absent : KagemushaWalletAndroidAttestationChainV1() {
        override fun toString(): String = "Absent"
    }

    /** No definitive answer; retry. Never absence. */
    class Unavailable(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidAttestationChainV1() {
        override fun toString(): String = "Unavailable($reason)"
    }
}

/** Custody root path, or why it is not available now. */
internal sealed class KagemushaWalletAndroidCustodyRootV1 {
    /** Absolute validated path of the prepared custody root; Native opens existing custody. */
    class Present(@JvmField val path: String) : KagemushaWalletAndroidCustodyRootV1() {
        override fun toString(): String = "Present($path)"
    }

    /** Credential-encrypted storage is not available; retry. */
    class Unavailable(@JvmField val reason: KagemushaWalletAndroidUnavailableV1) : KagemushaWalletAndroidCustodyRootV1() {
        override fun toString(): String = "Unavailable($reason)"
    }
}
