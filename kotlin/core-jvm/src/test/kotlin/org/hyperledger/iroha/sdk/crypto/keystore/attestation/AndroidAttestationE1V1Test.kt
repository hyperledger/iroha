// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.crypto.keystore.attestation

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1UTCTime
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1 as Refusal
import org.junit.jupiter.api.Test

/**
 * Synthetic signed KeyMint-shaped chains under test roots. They exercise the adapter's pre-E5
 * E1 check in the enrollment policy's admission order; they qualify no device, root or profile.
 */
class AndroidAttestationE1V1Test {
    private val challenge = ByteArray(32) { (0x30 + it).toByte() }
    private val packageName = "org.example.wallet"
    private val signer = ByteArray(32) { 0x22 }
    private val root = p256()
    private val intermediate = p256()
    private val leaf = p256()

    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun policy(
        signers: List<ByteArray> = listOf(signer),
        minimum: Long = 7,
        family: AndroidAttestationE1RootV1.Family = AndroidAttestationE1RootV1.Family.GOOGLE_RSA,
        rootKey: KeyPair = root,
    ) = AndroidAttestationE1PolicyV1(packageName, BigInteger.valueOf(minimum), signers, listOf(
        AndroidAttestationE1RootV1(family, sha256(rootKey.public.encoded), if (family == AndroidAttestationE1RootV1.Family.VENDOR) "huawei" else null),
    ))

    // KeyDescription ------------------------------------------------------------------------

    private fun tag(number: Int, value: ASN1Encodable): ASN1Encodable = DERTaggedObject(true, number, value)

    private fun applicationId(
        packages: List<Pair<String, Long>> = listOf(packageName to 9L),
        signers: List<ByteArray> = listOf(signer),
    ): ASN1Encodable = DEROctetString(DERSequence(arrayOf<ASN1Encodable>(
        DERSet(packages.map { (name, version) -> DERSequence(arrayOf<ASN1Encodable>(DEROctetString(name.toByteArray()), ASN1Integer(version))) }.toTypedArray()),
        DERSet(signers.map { DEROctetString(it) }.toTypedArray()),
    )).encoded)

    private fun rootOfTrust(
        version: Int,
        locked: Boolean = true,
        state: Int = 0,
        bootKey: ByteArray = ByteArray(32) { 0x11 },
        bootHash: ByteArray? = ByteArray(32) { 0x12 },
        fields: Int = if (version == 2) 3 else 4,
    ): ASN1Encodable {
        val items = mutableListOf<ASN1Encodable>(DEROctetString(bootKey), ASN1Boolean.getInstance(locked), ASN1Enumerated(state))
        if (fields == 4) items += DEROctetString(bootHash ?: ByteArray(0))
        return DERSequence(items.toTypedArray())
    }

    private inner class Description(
        var version: Int = 200,
        var keyMintVersion: Int = 200,
        var level: Int = 1,
        var keyMintLevel: Int = 1,
        var attestedChallenge: ByteArray = challenge,
        val software: MutableList<Pair<Int, ASN1Encodable>> = mutableListOf(709 to applicationId()),
        val hardware: MutableList<Pair<Int, ASN1Encodable>> = mutableListOf(
            1 to DERSet(ASN1Integer(2)), 2 to ASN1Integer(3), 3 to ASN1Integer(256), 5 to DERSet(ASN1Integer(4)),
            10 to ASN1Integer(1), 702 to ASN1Integer(0), 704 to rootOfTrust(200),
        ),
        var sort: Boolean = true,
    ) {
        fun list(items: List<Pair<Int, ASN1Encodable>>) =
            DERSequence((if (sort) items.sortedBy { it.first } else items).map { tag(it.first, it.second) }.toTypedArray())

        fun encoded(): ByteArray = DERSequence(arrayOf<ASN1Encodable>(
            ASN1Integer(version.toLong()), ASN1Enumerated(level), ASN1Integer(keyMintVersion.toLong()),
            ASN1Enumerated(keyMintLevel), DEROctetString(attestedChallenge), DEROctetString(ByteArray(0)),
            list(software), list(hardware),
        )).encoded

        fun replace(tag: Int, value: ASN1Encodable?) {
            hardware.removeAll { it.first == tag }
            if (value != null) hardware += tag to value
        }
    }

    // Certificates --------------------------------------------------------------------------

    private val keyDescriptionOid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    private val provisioningOid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")

    private fun certificate(
        subject: KeyPair, issuer: KeyPair, subjectName: String, issuerName: String, ca: Boolean, serial: Long,
        extra: List<Extension> = emptyList(), rsa: Boolean = false,
    ): ByteArray {
        val algorithm = if (rsa) AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE)
            else AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val extensions = listOf(
            Extension(Extension.basicConstraints, true, DEROctetString(BasicConstraints(ca).encoded)),
            Extension(Extension.keyUsage, true, DEROctetString(KeyUsage(if (ca) KeyUsage.keyCertSign else KeyUsage.digitalSignature).encoded)),
        ) + extra
        val tbs = DERSequence(arrayOf<ASN1Encodable>(DERTaggedObject(true, 0, ASN1Integer(2)), ASN1Integer(serial), algorithm,
            X500Name(issuerName), DERSequence(arrayOf<ASN1Encodable>(ASN1UTCTime("250101000000Z"), ASN1UTCTime("300101000000Z"))),
            X500Name(subjectName), SubjectPublicKeyInfo.getInstance(subject.public.encoded),
            DERTaggedObject(true, 3, Extensions(extensions.toTypedArray()))))
        val signature = Signature.getInstance(if (rsa) "SHA256withRSA" else "SHA256withECDSA").run {
            initSign(issuer.private); update(tbs.encoded); sign()
        }
        return DERSequence(arrayOf<ASN1Encodable>(tbs, algorithm, DERBitString(signature))).encoded
    }

    private fun kd(description: Description) = Extension(keyDescriptionOid, false, DEROctetString(description.encoded()))
    private fun provisioning() = Extension(provisioningOid, false, DEROctetString(DERSequence().encoded))

    /** Leaf (key description) <- intermediate <- self-signed root. */
    private fun chain(
        description: Description = Description(),
        leafExtra: List<Extension> = emptyList(),
        intermediateExtra: List<Extension> = emptyList(),
        rootExtra: List<Extension> = emptyList(),
        rootKey: KeyPair = root,
        leafKey: KeyPair = leaf,
        leafCa: Boolean = false,
        rsaRoot: Boolean = false,
    ): List<ByteArray> = listOf(
        certificate(leafKey, intermediate, "CN=Android Keystore Key", "CN=Intermediate", leafCa, 1, listOf(kd(description)) + leafExtra),
        certificate(intermediate, rootKey, "CN=Intermediate", "CN=Root", true, 2, intermediateExtra, rsa = rsaRoot),
        certificate(rootKey, rootKey, "CN=Root", "CN=Root", true, 3, rootExtra, rsa = rsaRoot),
    )

    private val paymentKey: ByteArray get() = sec1(leaf)

    private fun sec1(pair: KeyPair): ByteArray = pair.public.encoded.let { it.copyOfRange(it.size - 65, it.size) }

    private fun evaluate(
        chain: List<ByteArray>,
        policy: AndroidAttestationE1PolicyV1 = policy(),
        key: ByteArray = paymentKey,
    ) = AndroidKeyAttestationOriginalV1.e1Admission(chain, challenge, key, policy)

    private fun refusal(chain: List<ByteArray>, policy: AndroidAttestationE1PolicyV1 = policy(), key: ByteArray = paymentKey): Refusal =
        assertIs<AndroidAttestationE1ResultV1.Ineligible>(evaluate(chain, policy, key), "expected an ineligible result").refusal

    // Tests ---------------------------------------------------------------------------------

    @Test fun `a hardware KeyMint key with app identity in either list is eligible as TEE or StrongBox`() {
        val tee = assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain()))
        assertEquals(AttestationResult.SecurityLevel.TRUSTED_ENVIRONMENT, tee.securityLevel)
        assertEquals(200, tee.attestationVersion)
        assertEquals(BigInteger.valueOf(9), tee.packageVersion)
        val strong = Description(level = 2, keyMintLevel = 2).apply {
            software.clear(); hardware += 709 to applicationId()
        }
        assertEquals(AttestationResult.SecurityLevel.STRONG_BOX, assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(strong))).securityLevel)
    }

    @Test fun `Keymaster 2 attestation version 1 is ineligible for carrying no app identity`() {
        val km2 = Description(version = 1, keyMintVersion = 2).apply { replace(704, rootOfTrust(1, fields = 4)) }
        assertEquals(Refusal.ATTESTATION_WITHOUT_APP_IDENTITY, refusal(chain(km2)))
        // Version 1 is refused before any later step, even with an unlocked bootloader.
        val unlocked = Description(version = 1, keyMintVersion = 2).apply { replace(704, rootOfTrust(1, locked = false)) }
        assertEquals(Refusal.ATTESTATION_WITHOUT_APP_IDENTITY, refusal(chain(unlocked)))
        // A later attestation without attestationApplicationId is the same Phone reason.
        assertEquals(Refusal.ATTESTATION_WITHOUT_APP_IDENTITY, refusal(chain(Description().apply { software.clear() })))
        assertEquals(Refusal.HolderClass.PHONE, Refusal.ATTESTATION_WITHOUT_APP_IDENTITY.holderClass)
    }

    @Test fun `software keys and mismatched levels are not in secure hardware`() {
        for ((attestation, keyMint) in listOf(0 to 0, 2 to 1, 1 to 2, 3 to 3)) {
            assertEquals(Refusal.KEY_NOT_IN_SECURE_HARDWARE, refusal(chain(Description(level = attestation, keyMintLevel = keyMint))), "$attestation/$keyMint")
        }
        // Attestation version 2 is TEE only.
        val version2 = Description(version = 2, keyMintVersion = 3, level = 2, keyMintLevel = 2).apply { replace(704, rootOfTrust(2)) }
        assertEquals(Refusal.KEY_NOT_IN_SECURE_HARDWARE, refusal(chain(version2)))
    }

    @Test fun `bootloader and verified boot are checked from the hardware RootOfTrust`() {
        assertEquals(Refusal.BOOTLOADER_UNLOCKED, refusal(chain(Description().apply { replace(704, rootOfTrust(200, locked = false)) })))
        for (state in listOf(1, 2, 3)) {
            assertEquals(Refusal.BOOT_NOT_VERIFIED, refusal(chain(Description().apply { replace(704, rootOfTrust(200, state = state)) })))
        }
        assertEquals(Refusal.BOOT_NOT_VERIFIED, refusal(chain(Description().apply { replace(704, rootOfTrust(200, bootKey = ByteArray(32))) })))
        // KeyMint requires a 32-byte nonzero boot hash; versions 3 and 4 only record it.
        assertEquals(Refusal.BOOT_NOT_VERIFIED, refusal(chain(Description().apply { replace(704, rootOfTrust(200, bootHash = ByteArray(32))) })))
        assertEquals(Refusal.BOOT_NOT_VERIFIED, refusal(chain(Description().apply { replace(704, rootOfTrust(200, bootHash = ByteArray(31) { 1 })) })))
        for ((version, keyMint) in listOf(3 to 4, 4 to 41)) {
            val relaxed = Description(version = version, keyMintVersion = keyMint).apply { replace(704, rootOfTrust(version, bootHash = ByteArray(0))) }
            assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(relaxed)), "$version")
        }
    }

    @Test fun `RootOfTrust keeps its version's exact DER shape`() {
        val version2 = { fields: Int -> Description(version = 2, keyMintVersion = 3).apply { replace(704, rootOfTrust(2, fields = fields)) } }
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(version2(3))))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(version2(4))))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { replace(704, rootOfTrust(200, fields = 3)) })))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { replace(704, null) })))
    }

    @Test fun `every documented version pair is accepted and any other pair is evidence invalid`() {
        for ((version, keyMint) in listOf(2 to 3, 3 to 4, 4 to 41, 100 to 100, 200 to 200, 300 to 300, 400 to 400, 500 to 500)) {
            val description = Description(version = version, keyMintVersion = keyMint).apply { replace(704, rootOfTrust(version)) }
            assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(description)), "$version/$keyMint")
        }
        for ((version, keyMint) in listOf(200 to 100, 600 to 600, 3 to 3, 101 to 101, 1 to 3)) {
            val description = Description(version = version, keyMintVersion = keyMint).apply { replace(704, rootOfTrust(version)) }
            val expected = if (version == 1) Refusal.ATTESTATION_WITHOUT_APP_IDENTITY else Refusal.EVIDENCE_INVALID
            assertEquals(expected, refusal(chain(description)), "$version/$keyMint")
        }
    }

    @Test fun `the version floor and the signer set decide the App reasons`() {
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(), policy(minimum = 9)))
        assertEquals(Refusal.APP_VERSION_BELOW_MINIMUM, refusal(chain(), policy(minimum = 10)))
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(), policy(minimum = 0)))
        // One signer and four signers in the policy set; every attested signer must be listed.
        val four = listOf(ByteArray(32) { 0x11 }, signer, ByteArray(32) { 0x33 }, ByteArray(32) { 0x44 })
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(), policy(signers = four)))
        assertEquals(Refusal.APP_IDENTITY_MISMATCH, refusal(chain(), policy(signers = listOf(ByteArray(32) { 0x55 }))))
        val rotated = Description().apply { software[0] = 709 to applicationId(signers = listOf(signer, ByteArray(32) { 0x33 })) }
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(rotated), policy(signers = four)))
        assertEquals(Refusal.APP_IDENTITY_MISMATCH, refusal(chain(rotated)))
        val other = Description().apply { software[0] = 709 to applicationId(packages = listOf("org.example.other" to 9L)) }
        assertEquals(Refusal.APP_IDENTITY_MISMATCH, refusal(chain(other)))
        val shared = Description().apply { software[0] = 709 to applicationId(packages = listOf(packageName to 9L, "org.example.other" to 9L)) }
        assertEquals(Refusal.APP_IDENTITY_MISMATCH, refusal(chain(shared)))
        val unsigned = Description().apply { software[0] = 709 to applicationId(signers = emptyList()) }
        assertEquals(Refusal.APP_IDENTITY_MISMATCH, refusal(chain(unsigned)))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { hardware += 709 to applicationId() })))
    }

    @Test fun `the chain must validate to a pinned root under the profile constraints`() {
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(chain(), policy(rootKey = p256())))
        // A software-rooted emulator chain is refused at the root, before its software level.
        val emulatorRoot = p256()
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(chain(Description(level = 0, keyMintLevel = 0), rootKey = emulatorRoot)))
        // A broken link: the intermediate is not signed by the root it names.
        val forged = chain().toMutableList().also { it[1] = certificate(intermediate, p256(), "CN=Intermediate", "CN=Root", true, 2) }
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(forged))
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(chain(leafCa = true)))
        val unknownCritical = Extension(ASN1ObjectIdentifier("1.2.3.4"), true, DEROctetString(byteArrayOf(5, 0)))
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(chain(intermediateExtra = listOf(unknownCritical))))
        val notSelfSigned = chain().toMutableList().also { it[2] = certificate(root, intermediate, "CN=Root", "CN=Other", true, 3) }
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(notSelfSigned))
        val duplicated = chain().let { listOf(it[0], it[1], it[1], it[2]) }
        assertEquals(Refusal.UNTRUSTED_ATTESTATION_ROOT, refusal(duplicated))
    }

    @Test fun `an RSA-rooted chain verifies with NULL signature parameters`() {
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(rootKey = rsa, rsaRoot = true), policy(rootKey = rsa)))
    }

    @Test fun `key description placement and provisioning adjacency follow the google profile`() {
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(intermediateExtra = listOf(provisioning()))))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(rootExtra = listOf(provisioning()))))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(leafExtra = listOf(provisioning()))))
        // Vendor profiles do not permit Google's provisioning information extension.
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(intermediateExtra = listOf(provisioning())),
            policy(family = AndroidAttestationE1RootV1.Family.VENDOR)))
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(), policy(family = AndroidAttestationE1RootV1.Family.VENDOR)))
        // An injected key description nearer the root is the one trusted, and it is not the leaf.
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(intermediateExtra = listOf(kd(Description())))))
        val missing = chain().toMutableList().also { it[0] = certificate(leaf, intermediate, "CN=Android Keystore Key", "CN=Intermediate", false, 1) }
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(missing))
    }

    @Test fun `challenge payment key and key properties bind the attempt`() {
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description(attestedChallenge = ByteArray(32) { 9 }))))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(), key = sec1(p256())))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { hardware += 405 to ASN1Integer(1) })))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { software += 405 to ASN1Integer(1) })))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { software += 600 to DERNull.INSTANCE })))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { software += 1 to DERSet(ASN1Integer(2)) })))
        for ((tag, value) in listOf(1 to DERSet(ASN1Integer(3)), 2 to ASN1Integer(1), 3 to ASN1Integer(384), 5 to DERSet(ASN1Integer(5)),
            10 to ASN1Integer(2), 702 to ASN1Integer(2))) {
            assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(Description().apply { replace(tag, value) })), "tag $tag")
        }
        // Unknown context tags are ignored; duplicated or unsorted tags are not.
        assertIs<AndroidAttestationE1ResultV1.Eligible>(evaluate(chain(Description().apply { hardware += 9999 to ASN1Integer(1) })))
        val duplicate = Description(sort = false).apply { hardware.add(0, 1 to DERSet(ASN1Integer(2))) }
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(duplicate)))
        val unsorted = Description(sort = false).apply { hardware.add(0, 702 to ASN1Integer(0)) }
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(chain(unsorted)))
    }

    @Test fun `shape is checked first and malformed inputs are refused or rejected`() {
        val valid = chain()
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(listOf(valid[0])))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(List(9) { valid[it % 3] }))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(listOf(valid[0] + 0, valid[1], valid[2])))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(listOf(byteArrayOf(0x30, 0), valid[1], valid[2])))
        assertEquals(Refusal.EVIDENCE_INVALID, refusal(listOf(ByteArray(16_385), valid[1], valid[2])))
        // Caller inputs that are not an E1 digest or a P-256 point are programming errors.
        assertFailsWith<IllegalArgumentException> { AndroidKeyAttestationOriginalV1.e1Admission(valid, ByteArray(32), paymentKey, policy()) }
        assertFailsWith<IllegalArgumentException> { AndroidKeyAttestationOriginalV1.e1Admission(valid, challenge, ByteArray(64), policy()) }
    }

    @Test fun `policy inputs follow the Model grammar`() {
        val pin = AndroidAttestationE1RootV1(AndroidAttestationE1RootV1.Family.GOOGLE_CA1, ByteArray(32) { 1 }, null)
        for (bad in listOf<() -> Any>(
            { AndroidAttestationE1PolicyV1("wallet", BigInteger.ONE, listOf(signer), listOf(pin)) },
            { AndroidAttestationE1PolicyV1("org.1example", BigInteger.ONE, listOf(signer), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.valueOf(-1), listOf(signer), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE.shiftLeft(64), listOf(signer), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, emptyList(), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, List(5) { ByteArray(32) { i -> (it + 1 + i * 0).toByte() } }, listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, listOf(signer, signer), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, listOf(ByteArray(32)), listOf(pin)) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, listOf(signer), emptyList()) },
            { AndroidAttestationE1PolicyV1(packageName, BigInteger.ONE, listOf(signer), listOf(pin, pin)) },
            { AndroidAttestationE1RootV1(AndroidAttestationE1RootV1.Family.VENDOR, ByteArray(32) { 1 }, null) },
            { AndroidAttestationE1RootV1(AndroidAttestationE1RootV1.Family.VENDOR, ByteArray(32) { 1 }, "Huawei") },
            { AndroidAttestationE1RootV1(AndroidAttestationE1RootV1.Family.GOOGLE_RSA, ByteArray(32) { 1 }, "google") },
            { AndroidAttestationE1RootV1(AndroidAttestationE1RootV1.Family.GOOGLE_RSA, ByteArray(32), null) },
        )) assertFailsWith<IllegalArgumentException> { bad() }
    }
}
