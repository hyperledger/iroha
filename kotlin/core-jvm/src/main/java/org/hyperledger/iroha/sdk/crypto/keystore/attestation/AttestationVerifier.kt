package org.hyperledger.iroha.sdk.crypto.keystore.attestation

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date
import org.hyperledger.iroha.sdk.crypto.keystore.KeyAttestation

private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
private val INT_MIN_BIG_INTEGER = BigInteger.valueOf(Int.MIN_VALUE.toLong())
private val INT_MAX_BIG_INTEGER = BigInteger.valueOf(Int.MAX_VALUE.toLong())

/** Sole original certificate parser shared by evidence DERs and independently selected roots. */
private fun decodeExactOriginalCertificateV1(factory: CertificateFactory, originalDer: ByteArray): X509Certificate {
    val original = ByteArrayInputStream(originalDer)
    val certificate = factory.generateCertificate(original) as X509Certificate
    // A provider must neither ignore a tail nor normalize the original certificate bytes.
    if (original.available() != 0 || !certificate.encoded.contentEquals(originalDer)) {
        throw AttestationVerificationException("Attestation certificate is not exact original DER")
    }
    return certificate
}


/**
 * Validates Android key attestation certificate chains and extracts metadata required by higher
 * level policy checks.
 */
class AttestationVerifier private constructor(
    trustAnchors: Set<TrustAnchor>,
    private val requireStrongBox: Boolean,
    private val revocationPolicy: AndroidAttestationRevocationPolicyV1,
    private val evaluationTimeEpochMillis: Long,
) {
    private val trustAnchors: Set<TrustAnchor> = trustAnchors.toSet()

    /**
     * Validates `attestation` and checks that the embedded challenge matches the required,
     * non-empty `expectedChallenge`.
     */
    @Throws(AttestationVerificationException::class)
    fun verify(attestation: KeyAttestation, expectedChallenge: ByteArray?): AttestationResult {
        if (expectedChallenge == null || expectedChallenge.isEmpty()) {
            throw AttestationVerificationException(
                "Expected attestation challenge must be non-empty"
            )
        }
        val challenge = expectedChallenge.copyOf()
        revocationPolicy.validateAt(evaluationTimeEpochMillis)
        val chain = decodeChain(attestation)
        if (chain.isEmpty()) {
            throw AttestationVerificationException("Attestation certificate chain is empty")
        }
        val leaf = chain[0]

        val activeTrustAnchors = validateRevocationStatus(chain)
        validateCertificatePath(chain, activeTrustAnchors)

        // Android attestation can include a subsequently issued leaf extension. The first
        // extension encountered from the root is the attested original, after PKIX validation.
        val attested = AndroidKeyAttestationOriginalV1.certificate(chain)
        val description = parseKeyDescription(attested)
        if (!MessageDigest.isEqual(challenge, description.attestationChallenge)) {
            throw AttestationVerificationException("Attestation challenge mismatch")
        }
        if (requireStrongBox
            && (description.attestationSecurityLevel != AttestationResult.SecurityLevel.STRONG_BOX ||
                description.keymasterSecurityLevel != AttestationResult.SecurityLevel.STRONG_BOX)
        ) {
            throw AttestationVerificationException("StrongBox attestation required by policy")
        }

        return AttestationResult(
            alias = attestation.alias,
            certificateChain = chain,
            attestationCertificate = attested,
            attestationSecurityLevel = description.attestationSecurityLevel,
            keymasterSecurityLevel = description.keymasterSecurityLevel,
            attestationChallenge = description.attestationChallenge,
            uniqueId = description.uniqueId,
            softwareAuthorisationsPresent = description.softwareAuthorisationsLength > 0,
            teeAuthorisationsPresent = description.teeAuthorisationsLength > 0,
            strongBoxAuthorisationsPresent = description.strongBoxAuthorisationsLength > 0,
        )
    }

    private fun decodeChain(attestation: KeyAttestation): List<X509Certificate> {
        val factory: CertificateFactory
        try {
            factory = CertificateFactory.getInstance("X.509")
        } catch (ex: CertificateException) {
            throw AttestationVerificationException("Unable to acquire X.509 CertificateFactory", ex)
        }

        return attestation.certificateChain().map { certificateDer ->
            try {
                decodeExactOriginalCertificateV1(factory, certificateDer)
            } catch (ex: CertificateException) {
                throw AttestationVerificationException("Failed to decode attestation certificate", ex)
            }
        }
    }

    private fun validateRevocationStatus(
        chain: List<X509Certificate>
    ): Set<TrustAnchor> {
        for (certificate in chain) {
            if (isRevoked(certificate)) {
                throw AttestationVerificationException(
                    "Attestation certificate is rejected by the governed revocation status"
                )
            }
        }
        val activeAnchors = trustAnchors.filterTo(linkedSetOf()) { anchor ->
            val certificate = anchor.trustedCert
            certificate == null || !isRevoked(certificate)
        }
        if (activeAnchors.isEmpty()) {
            throw AttestationVerificationException(
                "All configured attestation trust anchors are revoked"
            )
        }
        return activeAnchors
    }

    private fun isRevoked(certificate: X509Certificate): Boolean {
        val tbsDigest = try {
            MessageDigest.getInstance("SHA-256").digest(certificate.tbsCertificate)
        } catch (ex: Exception) {
            throw AttestationVerificationException(
                "Unable to hash attestation certificate TBS bytes",
                ex,
            )
        }
        return revocationPolicy.rejects(certificate.serialNumber, tbsDigest)
    }

    private fun validateCertificatePath(
        chain: List<X509Certificate>,
        activeTrustAnchors: Set<TrustAnchor>,
    ) {
        val factory: CertificateFactory
        try {
            factory = CertificateFactory.getInstance("X.509")
        } catch (ex: CertificateException) {
            throw AttestationVerificationException("Unable to acquire X.509 CertificateFactory", ex)
        }

        val certPath = try {
            factory.generateCertPath(certificatesForPath(chain, activeTrustAnchors))
        } catch (ex: CertificateException) {
            throw AttestationVerificationException("Failed to construct attestation CertPath", ex)
        }

        val validator = try {
            CertPathValidator.getInstance("PKIX")
        } catch (ex: Exception) {
            throw AttestationVerificationException("Unable to acquire PKIX CertPathValidator", ex)
        }

        val parameters = try {
            PKIXParameters(activeTrustAnchors)
        } catch (ex: Exception) {
            throw AttestationVerificationException("Invalid PKIX parameters", ex)
        }
        // The governed, freshness-checked offline snapshot above is the sole revocation source.
        parameters.isRevocationEnabled = false
        parameters.date = Date(evaluationTimeEpochMillis)

        try {
            validator.validate(certPath, parameters)
        } catch (ex: CertPathValidatorException) {
            throw AttestationVerificationException(
                "Attestation certificate path validation failed", ex
            )
        } catch (ex: Exception) {
            throw AttestationVerificationException(
                "Unexpected failure validating attestation certificate path", ex
            )
        }
    }

    private fun certificatesForPath(
        chain: List<X509Certificate>,
        activeTrustAnchors: Set<TrustAnchor>,
    ): List<X509Certificate> {
        if (chain.size < 2) {
            return chain
        }
        val trailingCertificate = chain[chain.size - 1]
        for (anchor in activeTrustAnchors) {
            val trusted = anchor.trustedCert
            if (trusted != null && sameTrustAnchorCertificate(trailingCertificate, trusted)) {
                // The configured trust anchor is not part of the PKIX CertPath. Android
                // attestation exports often include it as the final chain entry.
                return chain.dropLast(1)
            }
        }
        return chain
    }

    private fun sameTrustAnchorCertificate(
        certificate: X509Certificate,
        trusted: X509Certificate,
    ): Boolean =
        certificate.subjectX500Principal == trusted.subjectX500Principal &&
            certificate.publicKey == trusted.publicKey

    private fun parseKeyDescription(attested: X509Certificate): KeyDescription {
        val extension = attested.getExtensionValue(ATTESTATION_OID)
            ?: throw AttestationVerificationException(
                "Selected certificate does not contain Android attestation extension"
            )

        val outer = DerReader(extension)
        val octetString = outer.readOctetString()
        if (outer.hasRemaining()) {
            throw AttestationVerificationException("Unexpected data after attestation extension")
        }

        val reader = DerReader.sequence(octetString)
        val attestationVersion = reader.readInteger()
        if (attestationVersion <= 0) {
            throw AttestationVerificationException(
                "Invalid attestation version: $attestationVersion"
            )
        }

        val attestationLevel =
            AttestationResult.SecurityLevel.fromEncoded(reader.readEnumerated())
        val keymasterVersion = reader.readInteger()
        if (keymasterVersion < 0) {
            throw AttestationVerificationException(
                "Invalid keymaster version: $keymasterVersion"
            )
        }
        val keymasterLevel =
            AttestationResult.SecurityLevel.fromEncoded(reader.readEnumerated())
        val challenge = reader.readOctetString()
        val uniqueId = reader.readOctetString()
        val softwareEnforced = reader.readSequenceBytes()
        val teeEnforced = reader.readSequenceBytes()
        var strongBoxEnforced = ByteArray(0)
        if (reader.hasRemaining()) {
            strongBoxEnforced = reader.readSequenceBytes()
        }
        if (reader.hasRemaining()) {
            throw AttestationVerificationException("Unexpected trailing data in attestation")
        }

        return KeyDescription(
            attestationSecurityLevel = attestationLevel,
            keymasterSecurityLevel = keymasterLevel,
            attestationChallenge = challenge,
            uniqueId = uniqueId,
            softwareAuthorisationsLength = softwareEnforced.size,
            teeAuthorisationsLength = teeEnforced.size,
            strongBoxAuthorisationsLength = strongBoxEnforced.size,
        )
    }

    /** Builder used to configure `AttestationVerifier` instances. */
    class Builder internal constructor(
        private val revocationPolicy: AndroidAttestationRevocationPolicyV1,
        private val evaluationTimeEpochMillis: Long,
    ) {
        private val trustedRoots = linkedSetOf<X509Certificate>()
        private var requireStrongBox = false

        /** Adds a trusted root certificate in DER form. */
        @Throws(AttestationVerificationException::class)
        fun addTrustedRoot(certificateDer: ByteArray): Builder = apply {
            try {
                val factory = CertificateFactory.getInstance("X.509")
                trustedRoots.add(
                    decodeExactOriginalCertificateV1(factory, certificateDer)
                )
            } catch (ex: CertificateException) {
                throw AttestationVerificationException("Failed to decode trusted root certificate", ex)
            }
        }

        /** Adds a trusted root certificate. */
        fun addTrustedRoot(certificate: X509Certificate): Builder = apply {
            trustedRoots.add(certificate)
        }

        /** Requires StrongBox-backed attestation when `enabled` is `true`. */
        fun requireStrongBox(enabled: Boolean): Builder = apply {
            this.requireStrongBox = enabled
        }

        fun build(): AttestationVerifier {
            check(trustedRoots.isNotEmpty()) {
                "At least one trusted root certificate is required"
            }
            val anchors = trustedRoots.mapTo(linkedSetOf()) { TrustAnchor(it, null) }
            return AttestationVerifier(
                anchors,
                requireStrongBox,
                revocationPolicy,
                evaluationTimeEpochMillis,
            )
        }
    }

    private class KeyDescription(
        val attestationSecurityLevel: AttestationResult.SecurityLevel,
        val keymasterSecurityLevel: AttestationResult.SecurityLevel,
        val attestationChallenge: ByteArray,
        val uniqueId: ByteArray,
        val softwareAuthorisationsLength: Int,
        val teeAuthorisationsLength: Int,
        val strongBoxAuthorisationsLength: Int,
    )

    private class DerReader(private val buffer: ByteArray) {
        private var offset = 0

        fun hasRemaining(): Boolean = offset < buffer.size

        fun readInteger(): Int = readIntegerWithTag(TAG_INTEGER)

        fun readEnumerated(): Int = readIntegerWithTag(TAG_ENUMERATED)

        fun readOctetString(): ByteArray = readWithExpectedTag(TAG_OCTET_STRING)

        fun readSequenceBytes(): ByteArray = readWithExpectedTag(TAG_SEQUENCE)

        private fun readIntegerWithTag(expectedTag: Int): Int {
            val value = readWithExpectedTag(expectedTag)
            val integer = BigInteger(value)
            if (integer < INT_MIN_BIG_INTEGER || integer > INT_MAX_BIG_INTEGER) {
                throw AttestationVerificationException("Integer value out of range")
            }
            return integer.toInt()
        }

        private fun readWithExpectedTag(expectedTag: Int): ByteArray {
            val tag = readTag()
            if (tag != expectedTag) {
                throw AttestationVerificationException(
                    "Unexpected DER tag. expected=0x%02X actual=0x%02X".format(expectedTag, tag)
                )
            }
            val length = readLength()
            if (length < 0) {
                throw AttestationVerificationException("Invalid DER length")
            }
            if (offset + length > buffer.size) {
                throw AttestationVerificationException("DER value overruns buffer")
            }
            val value = buffer.copyOfRange(offset, offset + length)
            offset += length
            return value
        }

        private fun readTag(): Int {
            if (offset >= buffer.size) {
                throw AttestationVerificationException("Unexpected end of DER input")
            }
            return buffer[offset++].toInt() and 0xFF
        }

        private fun readLength(): Int {
            if (offset >= buffer.size) {
                throw AttestationVerificationException("Unexpected end of DER input")
            }
            val lengthByte = buffer[offset++].toInt() and 0xFF
            if (lengthByte and 0x80 == 0) return lengthByte
            val lengthOctets = lengthByte and 0x7F
            if (lengthOctets == 0 || lengthOctets > 4) {
                throw AttestationVerificationException("Unsupported DER length encoding")
            }
            var length = 0
            for (i in 0 until lengthOctets) {
                if (offset >= buffer.size) {
                    throw AttestationVerificationException("Invalid DER length encoding")
                }
                length = (length shl 8) or (buffer[offset++].toInt() and 0xFF)
            }
            return length
        }

        companion object {
            private const val TAG_SEQUENCE = 0x30
            private const val TAG_INTEGER = 0x02
            private const val TAG_ENUMERATED = 0x0A
            private const val TAG_OCTET_STRING = 0x04

            fun sequence(data: ByteArray): DerReader {
                val reader = DerReader(data)
                return DerReader(reader.readWithExpectedTag(TAG_SEQUENCE))
            }
        }
    }

    companion object {
        /** Creates a verifier builder bound to its required revocation policy and evaluation time. */
        @JvmStatic
        fun builder(
            revocationPolicy: AndroidAttestationRevocationPolicyV1,
            evaluationTimeEpochMillis: Long,
        ): Builder = Builder(revocationPolicy, evaluationTimeEpochMillis)
    }
}
