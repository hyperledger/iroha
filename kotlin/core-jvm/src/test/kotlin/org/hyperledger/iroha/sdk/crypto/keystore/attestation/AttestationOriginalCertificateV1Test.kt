package org.hyperledger.iroha.sdk.crypto.keystore.attestation

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.hyperledger.iroha.sdk.crypto.keystore.KeyAttestation
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Synthetic signed PKIX chains exercise selection; they grant no device qualification. */
class AttestationOriginalCertificateV1Test {
    private val challenge = ByteArray(32) { 7 }
    private val time = 1_800_000_000_000L
    private val oid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

    @Test fun rootNearestDescriptionWinsOverANewerLeafDescription() {
        val f = fixture(original = description(challenge), leaf = description(ByteArray(32) { 8 }, 0, 0))
        val result = f.verifier.verify(f.attestation, challenge)
        assertEquals(AttestationResult.SecurityLevel.STRONG_BOX, result.attestationSecurityLevel)
        assertArrayEquals(challenge, result.attestationChallenge())
        assertEquals("CN=Original Attestation", result.attestationCertificate.subjectX500Principal.name)
        assertEquals("CN=Alias Leaf", result.leafCertificate.subjectX500Principal.name)
    }

    @Test fun validLeafCannotOverrideWrongOriginalChallenge() {
        val f = fixture(original = description(ByteArray(32) { 8 }), leaf = description(challenge))
        assertThrows(AttestationVerificationException::class.java) { f.verifier.verify(f.attestation, challenge) }
    }

    @Test fun rootNearestCertificateMustDescribeTheAliasLeafPublicKey() {
        val f = fixture(original = description(challenge), leaf = description(challenge), differentOriginalKey = true)
        assertThrows(AttestationVerificationException::class.java) { f.verifier.verify(f.attestation, challenge) }
    }

    @Test fun strongBoxPolicyRequiresBothKeyAndAttestationLevelTwo() {
        for ((attestation, key) in listOf(2 to 1, 1 to 2, 1 to 1, 0 to 2)) {
            val f = fixture(original = description(challenge, attestation, key))
            assertThrows(AttestationVerificationException::class.java) { f.verifier.verify(f.attestation, challenge) }
        }
    }

    @Test fun leafOnlyOriginalRemainsBoundToTheSameAliasKey() {
        val f = fixture(original = null, leaf = description(challenge))
        val result = f.verifier.verify(f.attestation, challenge)
        assertEquals(result.leafCertificate, result.attestationCertificate)
    }

    @Test fun missingOriginalOrMalformedOriginalCannotBeReplacedByLeafEvidence() {
        for (f in listOf(fixture(original = null), fixture(original = byteArrayOf(0), leaf = description(challenge)))) {
            assertThrows(Exception::class.java) { f.verifier.verify(f.attestation, challenge) }
        }
    }

    @Test fun completeOriginalCertificateRejectsEachRetiredDerShapeNegative() {
        val f = fixture(original = description(challenge))
        f.verifier.verify(f.attestation, challenge) // Real signed positive precedes mutation.
        val chain = f.attestation.certificateChain()
        val leaf = chain[0]
        // All eight former archive-parser negatives now exercise the sole actual verifier.
        val malformed = listOf(leaf + 0, leaf.copyOfRange(0, 4), byteArrayOf(0x31, 0),
            byteArrayOf(0x30, 0x80.toByte(), 0, 0), byteArrayOf(0x30, 0x81.toByte(), 0),
            byteArrayOf(0x30, 0x82.toByte(), 0, 1, 0), byteArrayOf(0x30, 0x81.toByte(), 1, 0),
            ByteArray(16 * 1024 + 1))
        for (bad in malformed) assertThrows(AttestationVerificationException::class.java) {
            f.verifier.verify(KeyAttestation("original-alias", listOf(bad, chain[1], chain[2])), challenge)
        }
    }

    @Test fun independentlySelectedRootRejectsAppendedOriginalDer() {
        val f = fixture(original = description(challenge))
        f.verifier.verify(f.attestation, challenge)
        val root = f.attestation.certificateChain().last()
        AttestationVerifier.builder(f.policy, time).addTrustedRoot(root).build()
        for (bad in listOf(root + 0, root + root)) {
            assertThrows(AttestationVerificationException::class.java) {
                AttestationVerifier.builder(f.policy, time).addTrustedRoot(bad)
            }
        }
    }

    private fun description(challenge: ByteArray, attestation: Int = 2, key: Int = 2) = DERSequence(arrayOf(
        ASN1Integer(100), ASN1Enumerated(attestation), ASN1Integer(100), ASN1Enumerated(key),
        DEROctetString(challenge), DEROctetString(ByteArray(0)), DERSequence(), DERSequence(),
    )).encoded

    private class Fixture(val verifier: AttestationVerifier, val attestation: KeyAttestation,
        val policy: AndroidAttestationRevocationPolicyV1)
    private fun fixture(original: ByteArray?, leaf: ByteArray? = null, differentOriginalKey: Boolean = false): Fixture {
        val root = key(); val alias = key(); val originalKey = if (differentOriginalKey) key() else alias
        val rootDer = certificate(root, root, "CN=Root", "CN=Root", true, 1, null)
        val originalDer = certificate(originalKey, root, "CN=Original Attestation", "CN=Root", true, 2, original)
        val leafDer = certificate(alias, originalKey, "CN=Alias Leaf", "CN=Original Attestation", false, 3, leaf)
        val snapshot = (AndroidAttestationRevocationPolicyV1.SNAPSHOT_DOMAIN + "\n" +
            "payload_sha256=" + "11".repeat(32) + "\nresponse_date_ms=$time\nlast_modified_ms=-\n" +
            "cache_max_age_seconds=86400\nserial_count=0\ntbs_sha256_count=0\n").toByteArray(Charsets.US_ASCII)
        val policy = AndroidAttestationRevocationPolicyV1.fromCanonicalSnapshot(snapshot,
            MessageDigest.getInstance("SHA-256").digest(snapshot))
        return Fixture(AttestationVerifier.builder(policy, time).addTrustedRoot(rootDer).requireStrongBox(true).build(),
            KeyAttestation("original-alias", listOf(leafDer, originalDer, rootDer)), policy)
    }
    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun certificate(subject: KeyPair, issuer: KeyPair, subjectName: String, issuerName: String,
        ca: Boolean, serial: Long, description: ByteArray?): ByteArray {
        val algorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val extensions = mutableListOf(
            Extension(Extension.basicConstraints, true, DEROctetString(BasicConstraints(ca).encoded)),
            Extension(Extension.keyUsage, true, DEROctetString(KeyUsage(if (ca) KeyUsage.keyCertSign else KeyUsage.digitalSignature).encoded)),
        )
        description?.let { extensions += Extension(oid, false, DEROctetString(it)) }
        val tbs = DERSequence(arrayOf<ASN1Encodable>(DERTaggedObject(true, 0, ASN1Integer(2)), ASN1Integer(serial),
            algorithm, X500Name(issuerName), DERSequence(arrayOf(ASN1UTCTime("250101000000Z"), ASN1UTCTime("300101000000Z"))),
            X500Name(subjectName), SubjectPublicKeyInfo.getInstance(subject.public.encoded), DERTaggedObject(true, 3, Extensions(extensions.toTypedArray()))))
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(issuer.private); update(tbs.encoded); sign() }
        return DERSequence(arrayOf(tbs, algorithm, DERBitString(signature))).encoded
    }
}
