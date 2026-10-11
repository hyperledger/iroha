package org.hyperledger.iroha.sdk.crypto.keystore.attestation

import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import java.math.BigInteger

/**
 * Original-evidence parsing. [persistentAppHardwareSecurityLevel] is the payment-key custody
 * readback; [e1Admission] is the adapter's pre-E5 E1 check. Neither grants admission: PKIX
 * trust, revocation and issuer policy remain the issuer's.
 */
object AndroidKeyAttestationOriginalV1 {
    const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    @JvmStatic fun certificate(chain: List<X509Certificate>): X509Certificate {
        require(chain.size in 2..8) { "Android attestation chain is outside bounds" }
        val selected = chain.asReversed().firstOrNull { it.getExtensionValue(KEY_DESCRIPTION_OID) != null }
            ?: throw AttestationVerificationException("Android attestation extension is missing")
        if (!MessageDigest.isEqual(selected.publicKey.encoded, chain.first().publicKey.encoded)) {
            throw AttestationVerificationException("Android attestation does not describe the alias-held leaf key")
        }
        return selected
    }
    @JvmStatic fun challenge(chain: List<X509Certificate>): ByteArray {
        val extension = certificate(chain).getExtensionValue(KEY_DESCRIPTION_OID)
        val description = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(
            ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension)).octets))
        require(description.size() == 8) { "Unsupported original KeyDescription layout" }
        return ASN1OctetString.getInstance(description.getObjectAt(4)).octets.copyOf()
    }
    /**
     * Parse the original signed extension's persistent P-256 app-key metadata. This does not
     * authenticate roots, revocation, package/Play policy or issuer admission. The app-key adapter
     * combines this exact leaf/challenge correlation with keystore2 (API 31+) KeyInfo custody.
     */
    @JvmStatic fun persistentAppHardwareSecurityLevel(chain: List<X509Certificate>, expectedChallenge: ByteArray): AttestationResult.SecurityLevel =
        parsePersistentAppDescriptionOriginal(chain, expectedChallenge).securityLevel

    /**
     * The Android adapter's own E1 check of a fresh payment-key attestation, before E5 (design
     * §2.4, enrollment policy "Android admission" steps 1, 2 and 4-8, in order). It returns the
     * first failing check as its closed refusal reason: attestation version 1 (Keymaster 2) and
     * a missing `attestationApplicationId` (709, accepted in either authorization list) are
     * [org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1.ATTESTATION_WITHOUT_APP_IDENTITY];
     * the attested package version is checked against the policy floor and every attested
     * signer against the policy signer set. Revocation and trusted-time validity stay with the
     * issuer, which remains authoritative. The result grants nothing.
     *
     * @throws IllegalArgumentException when the challenge digest or payment key is not well formed.
     */
    @JvmStatic fun e1Admission(
        chainDer: List<ByteArray>,
        challengeDigest: ByteArray,
        paymentKeySec1: ByteArray,
        policy: AndroidAttestationE1PolicyV1,
    ): AndroidAttestationE1ResultV1 = AndroidAttestationE1EvaluatorV1.evaluate(chainDer, challengeDigest, paymentKeySec1, policy)

    /** Documented attestation/KeyMint pairs plus (1, 2): a Keymaster 2 key is hardware custody, not E1-admissible. */
    private val CUSTODY_VERSION_PAIRS: Set<Pair<Int, Int>> = AndroidAttestationE1EvaluatorV1.VERSION_PAIRS + (1 to 2)

    private fun parsePersistentAppDescriptionOriginal(
        chain: List<X509Certificate>,
        expectedChallenge: ByteArray,
    ): PersistentAppDescriptionV1 {
        require(expectedChallenge.size == 32 && expectedChallenge.any { it != 0.toByte() })
        require(chain.size in 2..8 && chain.all { it.encoded.size in 1..16_384 })
        val extension = certificate(chain).getExtensionValue(KEY_DESCRIPTION_OID)
        val payload = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension)).octets
        val description = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(payload))
        require(payload.contentEquals(description.getEncoded("DER")) && description.size() == 8) {
            "Original KeyDescription is not the exact canonical layout"
        }
        fun integer(index: Int) = (description.getObjectAt(index) as? ASN1Integer)?.value
            ?: throw AttestationVerificationException("Malformed original KeyDescription version")
        // Custody readback accepts every documented hardware pair, including attestation version 1
        // (Keymaster 2): that key is still a hardware key, and only E1 admission refuses it for
        // carrying no app identity (typed by [e1Admission] right after generation).
        val version = integer(0)
        val keyMintVersion = integer(2)
        require(version.bitLength() < 32 && keyMintVersion.bitLength() < 32 &&
            (version.toInt() to keyMintVersion.toInt()) in CUSTODY_VERSION_PAIRS) { "Undocumented attestation version pair" }
        val attestation = (description.getObjectAt(1) as? ASN1Enumerated)?.value
        val key = (description.getObjectAt(3) as? ASN1Enumerated)?.value
        require(attestation == key && key in setOf(BigInteger.ONE, BigInteger.valueOf(2))) {
            "Original app key lacks matching TEE or StrongBox levels"
        }
        require(MessageDigest.isEqual(ASN1OctetString.getInstance(description.getObjectAt(4)).octets, expectedChallenge)) {
            "Original persistent app-key challenge differs"
        }
        ASN1OctetString.getInstance(description.getObjectAt(5))
        fun tags(index: Int): Map<Int, ASN1TaggedObject> {
            val sequence = description.getObjectAt(index) as? ASN1Sequence
                ?: throw AttestationVerificationException("Malformed original app-key authorizations")
            require(sequence.size() <= 128)
            val parsed = linkedMapOf<Int, ASN1TaggedObject>(); var prior = 0
            for (item in sequence) {
                val tagged = item as? ASN1TaggedObject
                    ?: throw AttestationVerificationException("App-key authorization is not context-tagged")
                require(tagged.hasContextTag(tagged.tagNo) && tagged.tagNo > prior) {
                    "Duplicate or unsorted original app-key authorization"
                }
                prior = tagged.tagNo; parsed[tagged.tagNo] = tagged
            }
            return parsed
        }
        val software = tags(6); val hardware = tags(7)
        require(405 !in software && 405 !in hardware) { "Finite-use key cannot be a persistent app identity" }
        require(software.keys.intersect(setOf(1, 2, 3, 5, 10, 303, 702, 704)).isEmpty()) {
            "Original app-key hardware authorization is software-enforced"
        }
        fun exactInteger(tag: Int, expected: Long) {
            val value = hardware[tag]?.getBaseUniversal(true, BERTags.INTEGER) as? ASN1Integer
            require(value?.value == BigInteger.valueOf(expected)) { "Original app-key hardware integer differs" }
        }
        fun exactSet(tag: Int, expected: Long) {
            val value = hardware[tag]?.getBaseUniversal(true, BERTags.SET) as? ASN1Set
            require(value?.size() == 1 && (value.getObjectAt(0) as? ASN1Integer)?.value == BigInteger.valueOf(expected)) {
                "Original app-key hardware purpose or digest differs"
            }
        }
        exactSet(1, 2); exactInteger(2, 3); exactInteger(3, 256); exactSet(5, 4)
        exactInteger(10, 1); exactInteger(702, 0)
        val actualPublicKey = publicKeySec1(chain) // Enforce actual leaf-key equality and exact P-256 parameters.
        val level = if (key == BigInteger.ONE) AttestationResult.SecurityLevel.TRUSTED_ENVIRONMENT else AttestationResult.SecurityLevel.STRONG_BOX
        return PersistentAppDescriptionV1(software, hardware, level, actualPublicKey)
    }

    private class PersistentAppDescriptionV1(
        software: Map<Int, ASN1TaggedObject>,
        hardware: Map<Int, ASN1TaggedObject>,
        val securityLevel: AttestationResult.SecurityLevel,
        publicKeySec1: ByteArray,
    ) {
        val software: Map<Int, ASN1TaggedObject> = software.toMap()
        val hardware: Map<Int, ASN1TaggedObject> = hardware.toMap()
        private val publicKey = publicKeySec1.copyOf()
        fun publicKeySec1(): ByteArray = publicKey.copyOf()
    }

    @JvmStatic fun publicKeySec1(chain: List<X509Certificate>): ByteArray {
        val key = certificate(chain).publicKey as? ECPublicKey
            ?: throw AttestationVerificationException("Android attested app key is not EC")
        val p256 = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        require(key.params.curve == p256.curve && key.params.generator == p256.generator &&
            key.params.order == p256.order && key.params.cofactor == p256.cofactor) { "Android app key is not P-256" }
        fun coordinate(value: java.math.BigInteger): ByteArray {
            require(value.signum() >= 0 && value.bitLength() <= 256)
            val encoded = value.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it }
            require(encoded.size <= 32); return ByteArray(32 - encoded.size) + encoded
        }
        return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
    }
}
