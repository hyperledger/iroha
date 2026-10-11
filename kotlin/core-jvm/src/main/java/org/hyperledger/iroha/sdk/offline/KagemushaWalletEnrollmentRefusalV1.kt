// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

/**
 * One closed E1 refusal reason (design §2.4). [code] is the stable `u16` wire code that every
 * component reports and relays unchanged: Native owns the table (bridge
 * `connect_norito_kagemusha_wallet_enrollment_refusal_v1`), the issuer reports exactly one code
 * with each refusal, and Core and the SDKs relay it without substituting free text. Zero and
 * unknown codes are protocol errors, never admission. A refusal never states that a phone is
 * compromised; it names the first admission check that failed. The app owns the wording.
 *
 * This mirrors the Rust `KagemushaWalletEnrollmentRefusalV1` exactly; the host-native SDK test
 * compares every code against the Native table.
 */
enum class KagemushaWalletEnrollmentRefusalV1(
    @JvmField val code: Int,
    @JvmField val androidOnly: Boolean,
    @JvmField val holderClass: HolderClass,
) {
    /** The attestation or KeyMint security level is Software, the two levels differ, or attestation version 2 is not TEE. */
    KEY_NOT_IN_SECURE_HARDWARE(1, true, HolderClass.PHONE),

    /** The attestation carries no application identity: attestation version 1 (Keymaster 2), or no `attestationApplicationId`. */
    ATTESTATION_WITHOUT_APP_IDENTITY(2, true, HolderClass.PHONE),

    /** The RootOfTrust records an unlocked bootloader. */
    BOOTLOADER_UNLOCKED(3, true, HolderClass.PHONE),

    /** Boot state is not Verified, the verified-boot key is zero, or a KeyMint boot hash is not 32 nonzero bytes. */
    BOOT_NOT_VERIFIED(4, true, HolderClass.PHONE),

    /** The chain does not validate to a root of the policy's root set (Android) or to Apple's App Attestation root. */
    UNTRUSTED_ATTESTATION_ROOT(5, false, HolderClass.PHONE),

    /** A chain certificate is listed by its root's revocation source or by the operator denylist. */
    ATTESTATION_REVOKED(6, true, HolderClass.PHONE),

    /** The package, a signer, the App ID or the App Attest environment differs from the app policy. */
    APP_IDENTITY_MISMATCH(7, false, HolderClass.APP),

    /** The attested package version is below the app policy minimum. */
    APP_VERSION_BELOW_MINIMUM(8, true, HolderClass.APP),

    /** The evidence is malformed or does not match this attempt. A repeat is a defect report. */
    EVIDENCE_INVALID(9, false, HolderClass.ATTEMPT),

    /** E5 verification began after the E1 challenge lifetime. */
    CHALLENGE_EXPIRED(10, false, HolderClass.ATTEMPT),

    /** The eligibility provider reports `NotApproved`. */
    ACCOUNT_NOT_APPROVED(11, false, HolderClass.ACCOUNT),

    /** The eligibility provider reports `Frozen`. */
    ACCOUNT_FROZEN(12, false, HolderClass.ACCOUNT),
    ;

    /** What the holder can do; the app owns the wording (design §2.4). */
    enum class HolderClass {
        /** This phone cannot hold offline value. Abandon and do not start again on this phone; online payments are unaffected. */
        PHONE,

        /** Install or update the released app from an official channel, then start again. */
        APP,

        /** Abandon and start again with a new challenge. A repeat is a defect report, not a device verdict. */
        ATTEMPT,

        /** The account's status, not the phone, blocks enrollment (codes 11 and 12). */
        ACCOUNT,
    }

    /** Whether this reason can occur for evidence of the given platform. */
    fun appliesTo(android: Boolean): Boolean = android || !androidOnly

    /** Codes 11 and 12: the only codes that can withhold delivery of an Issued outcome. */
    val isEligibility: Boolean get() = holderClass == HolderClass.ACCOUNT

    companion object {
        /** The reason of a wire code, or null for zero and unknown codes. */
        @JvmStatic
        fun fromCode(code: Int): KagemushaWalletEnrollmentRefusalV1? = entries.firstOrNull { it.code == code }

        /**
         * The reason of a relayed code for evidence of the given platform. Zero, unknown and
         * platform-inapplicable codes are protocol errors.
         *
         * @throws IllegalArgumentException for such a code; never an admission.
         */
        @JvmStatic
        fun relayed(code: Int, android: Boolean): KagemushaWalletEnrollmentRefusalV1 {
            val reason = fromCode(code)
            require(reason != null && reason.appliesTo(android)) { "E1 refusal code $code is not in the closed table" }
            return reason
        }
    }
}

/**
 * Closed non-success outcome of one E1 enrollment service operation (design §2.4), read from the
 * single outcome header of an Iroha enrollment service response. Identical HTTP statuses carry
 * different outcomes, so a client reads the header on every response. Mirrors the Rust
 * `iroha_torii_shared::kagemusha_enrollment::EnrollmentServiceOutcomeV1`.
 *
 * Only [Refused] is a terminal outcome. [DeliveryWithheld] keeps the Issued outcome, its exact
 * E6 and the quota share: the wallet keeps its slot, marker and retained E5 and retries
 * delivery later, without abandoning or starting again. [OutcomeUnknown] is a recovery state.
 */
sealed class KagemushaWalletEnrollmentOutcomeV1 {
    /** HTTP 403: the terminal refusal of this attempt, returned unchanged on every retry. */
    class Refused internal constructor(@JvmField val reason: KagemushaWalletEnrollmentRefusalV1) : KagemushaWalletEnrollmentOutcomeV1() {
        override fun toString(): String = "Refused(${reason.code})"
    }

    /** HTTP 403: delivery of an Issued outcome is withheld by code 11 or 12; retry delivery later. */
    class DeliveryWithheld internal constructor(@JvmField val reason: KagemushaWalletEnrollmentRefusalV1) : KagemushaWalletEnrollmentOutcomeV1() {
        override fun toString(): String = "DeliveryWithheld(${reason.code})"
    }

    /** HTTP 409: an effect may have taken place without a retained outcome; recover, never restart as fresh. */
    object OutcomeUnknown : KagemushaWalletEnrollmentOutcomeV1() {
        override fun toString(): String = "OutcomeUnknown"
    }

    /** Exact HTTP status that carries this outcome. */
    val status: Int get() = if (this is OutcomeUnknown) 409 else 403

    companion object {
        /** Header relaying a terminal refusal's closed reason code (1–12, canonical decimal). */
        const val REFUSAL_CODE_HEADER: String = "x-iroha-kagemusha-refusal-code"

        /** Header relaying the closed code (11 or 12) that withholds delivery of an Issued outcome. */
        const val DELIVERY_WITHHELD_HEADER: String = "x-iroha-kagemusha-delivery-withheld-code"

        /** Header marking an outcome that is unknown after a possible effect. */
        const val OUTCOME_HEADER: String = "x-iroha-kagemusha-outcome"

        /** The only value of [OUTCOME_HEADER]. */
        const val OUTCOME_UNKNOWN: String = "unknown"

        /**
         * Strictly read the outcome of one response from its [status] and [headers] (names
         * compared case-insensitively; each pair is one header line, as OkHttp `Headers`
         * iterates). Returns null when no outcome header is present.
         *
         * @throws IllegalArgumentException for more than one outcome header (a repeated one
         * included), a noncanonical, zero or unknown code, a withholding code other than 11 or
         * 12, another outcome value, or a status that does not carry the outcome.
         */
        @JvmStatic
        fun fromHeaders(status: Int, headers: Iterable<Pair<String, String>>): KagemushaWalletEnrollmentOutcomeV1? {
            var outcome: KagemushaWalletEnrollmentOutcomeV1? = null
            for ((name, value) in headers) {
                val parsed = when {
                    name.equals(REFUSAL_CODE_HEADER, ignoreCase = true) -> Refused(code(value))
                    name.equals(DELIVERY_WITHHELD_HEADER, ignoreCase = true) -> {
                        val reason = code(value)
                        require(reason.isEligibility) { "invalid enrollment service outcome" }
                        DeliveryWithheld(reason)
                    }
                    name.equals(OUTCOME_HEADER, ignoreCase = true) -> {
                        require(value == OUTCOME_UNKNOWN) { "invalid enrollment service outcome" }
                        OutcomeUnknown
                    }
                    else -> continue
                }
                require(outcome == null) { "invalid enrollment service outcome" }
                outcome = parsed
            }
            require(outcome == null || outcome.status == status) { "invalid enrollment service outcome" }
            return outcome
        }

        private fun code(text: String): KagemushaWalletEnrollmentRefusalV1 {
            require(text.isNotEmpty() && text.length <= 5 && !text.startsWith('0') && text.all { it in '0'..'9' }) {
                "invalid enrollment service outcome"
            }
            return KagemushaWalletEnrollmentRefusalV1.fromCode(text.toInt())
                ?: throw IllegalArgumentException("invalid enrollment service outcome")
        }
    }
}
