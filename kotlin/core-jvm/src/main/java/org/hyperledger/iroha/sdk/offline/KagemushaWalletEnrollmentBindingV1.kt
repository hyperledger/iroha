// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * Current E1 enrollment hashes for one retained challenge transcript and Native payment key.
 *
 * The transcript is exactly `LE16(1)` followed by six nonzero 32-byte bindings: scheme, asset,
 * account, app policy, enrollment policy and issuer nonce. It is the transcript, not its Norito
 * frame or an authentication-device challenge. The payment key is the existing Native-selected
 * uncompressed P-256 SEC1 public key. Inputs are copied and structurally checked; this class
 * authenticates neither the issuer's selection nor hardware evidence and grants no custody.
 *
 * Uses the canonical [KagemushaWalletWireV1.digest] SHA-256 domains from wallet wire section 3.1
 * and the server's `WalletEnrollmentScope`, without an extra hash of either result.
 */
class KagemushaWalletEnrollmentBindingV1(challengeTranscript: ByteArray, paymentKeySec1: ByteArray) {
    private val challenge: ByteArray
    private val binding: ByteArray

    init {
        require(challengeTranscript.size == 194) { "E1 challenge transcript must be exactly 194 bytes" }
        val transcript = challengeTranscript.copyOf()
        require(transcript[0] == 1.toByte() && transcript[1] == 0.toByte()) {
            "E1 challenge version must be 1"
        }
        require((2 until transcript.size step 32).all { start ->
            (start until start + 32).any { transcript[it] != 0.toByte() }
        }) { "E1 challenge bindings must be nonzero" }
        require(paymentKeySec1.size == KagemushaP256Codec.PUBLIC_KEY_BYTES) {
            "E1 payment key must be exactly 65-byte uncompressed P-256 SEC1"
        }
        val key = KagemushaP256Codec.requireUncompressedPublicKey(paymentKeySec1)
        challenge = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ENROLLMENT_CHALLENGE, transcript)
        binding = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ENROLLMENT_KEY_BINDING, challenge + key)
    }

    /** Exact KeyMint enrollment attestation challenge `H("enrollment-challenge", transcript)`. */
    fun challengeDigest(): ByteArray = challenge.copyOf()

    /** `H("enrollment-key-binding", challengeDigest || paymentKeySec1)`, exactly 32 bytes. */
    fun enrollmentKeyBinding(): ByteArray = binding.copyOf()

    override fun toString(): String = "KagemushaWalletEnrollmentBindingV1(binding=[REDACTED])"
}
