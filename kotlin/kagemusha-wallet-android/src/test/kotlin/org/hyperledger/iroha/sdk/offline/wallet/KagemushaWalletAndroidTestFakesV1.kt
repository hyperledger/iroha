// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline.wallet

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/** Thrown by fakes where AndroidKeyStore signing throws `KeyPermanentlyInvalidatedException`. */
internal class TestPermanentlyInvalidatedKeyV1 : InvalidKeyException("key permanently invalidated")

/** A Keystore-like private key: usable for signing through its owner, never exportable. */
internal class TestNonExportableKeyV1(val delegate: PrivateKey) : PrivateKey {
    override fun getAlgorithm(): String = delegate.algorithm
    override fun getFormat(): String? = null
    override fun getEncoded(): ByteArray? = null
}

/** Independent test encoding of a P-256 key: the 65-byte point that ends its X.509 SPKI. */
internal fun testSec1V1(publicKey: PublicKey): ByteArray {
    val spki = publicKey.encoded
    return spki.copyOfRange(spki.size - 65, spki.size).also { check(it[0] == 4.toByte()) }
}

/** Minimal DER writer for synthetic Android attestation chains (JDK 8 APIs only). */
internal object TestDerV1 {
    fun tlv(tag: Int, content: ByteArray): ByteArray = tlv(byteArrayOf(tag.toByte()), content)

    private fun tlv(identifier: ByteArray, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(identifier)
        val size = content.size
        when {
            size < 0x80 -> out.write(size)
            size < 0x100 -> { out.write(0x81); out.write(size) }
            else -> { out.write(0x82); out.write(size ushr 8); out.write(size and 0xff) }
        }
        out.write(content)
        return out.toByteArray()
    }

    fun sequence(vararg items: ByteArray): ByteArray = tlv(0x30, concat(items))
    fun set(vararg items: ByteArray): ByteArray = tlv(0x31, concat(items))
    fun integer(value: Long): ByteArray = tlv(0x02, BigInteger.valueOf(value).toByteArray())
    fun enumerated(value: Int): ByteArray = tlv(0x0a, BigInteger.valueOf(value.toLong()).toByteArray())
    fun octets(value: ByteArray): ByteArray = tlv(0x04, value)
    fun utf8(value: String): ByteArray = tlv(0x0c, value.toByteArray(Charsets.UTF_8))
    fun utcTime(value: String): ByteArray = tlv(0x17, value.toByteArray(Charsets.US_ASCII))
    fun bitString(value: ByteArray): ByteArray = tlv(0x03, byteArrayOf(0) + value)
    fun boolean(value: Boolean): ByteArray = tlv(0x01, byteArrayOf(if (value) -1 else 0))

    /** Constructed context-specific `[tagNumber] EXPLICIT`, with the high-tag form above 30. */
    fun explicit(tagNumber: Int, content: ByteArray): ByteArray {
        if (tagNumber < 31) return tlv(0xa0 or tagNumber, content)
        val groups = ArrayList<Int>()
        var rest = tagNumber
        do {
            groups.add(rest and 0x7f)
            rest = rest ushr 7
        } while (rest != 0)
        val identifier = ByteArrayOutputStream()
        identifier.write(0xbf)
        for (index in groups.indices.reversed()) identifier.write(groups[index] or (if (index == 0) 0 else 0x80))
        return tlv(identifier.toByteArray(), content)
    }

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        val out = ByteArrayOutputStream()
        out.write((arcs[0] * 40 + arcs[1]).toInt())
        for (arc in arcs.drop(2)) {
            val groups = ArrayList<Int>()
            var rest = arc
            do {
                groups.add((rest and 0x7f).toInt())
                rest = rest ushr 7
            } while (rest != 0L)
            for (index in groups.indices.reversed()) {
                out.write(groups[index] or (if (index == 0) 0 else 0x80))
            }
        }
        return tlv(0x06, out.toByteArray())
    }

    private fun concat(items: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        items.forEach { out.write(it) }
        return out.toByteArray()
    }
}

/** Synthetic app identity of the test app policy: package, attested version and signer. */
internal object TestAppV1 {
    const val PACKAGE = "org.example.wallet"
    const val VERSION = 9L
    val SIGNER: ByteArray get() = ByteArray(32) { 0x22 }

    /** `attestationApplicationId` (709) content: one package and its signer digests. */
    fun applicationId(packageName: String = PACKAGE, version: Long = VERSION, signers: List<ByteArray> = listOf(SIGNER)): ByteArray =
        TestDerV1.octets(TestDerV1.sequence(
            TestDerV1.set(TestDerV1.sequence(TestDerV1.octets(packageName.toByteArray(Charsets.UTF_8)), TestDerV1.integer(version))),
            TestDerV1.set(*signers.map { TestDerV1.octets(it) }.toTypedArray()),
        ))

    /** Locked, Verified RootOfTrust in the KeyMint (four-field) shape. */
    fun rootOfTrust(locked: Boolean = true, state: Int = 0): ByteArray = TestDerV1.sequence(
        TestDerV1.octets(ByteArray(32) { 0x11 }), TestDerV1.boolean(locked), TestDerV1.enumerated(state),
        TestDerV1.octets(ByteArray(32) { 0x12 }),
    )
}

/**
 * Original Android `KeyDescription` content of a synthetic attestation. Authorization lists map
 * a KeyMint tag to the DER of its explicit content.
 */
internal data class TestKeyDescriptionV1(
    val attestationLevel: Int,
    val keymasterLevel: Int,
    val software: Map<Int, ByteArray>,
    val hardware: Map<Int, ByteArray>,
    val attestationVersion: Int = 200,
    val keymasterVersion: Int = 200,
) {
    companion object {
        /**
         * Hardware-enforced SIGN, EC, 256 bits, SHA-256, P-256, GENERATED and a locked Verified
         * RootOfTrust, with the test app's identity in the software list, as KeyMint attests them.
         */
        fun hardwareKey(level: Int) = TestKeyDescriptionV1(
            attestationLevel = level,
            keymasterLevel = level,
            software = mapOf(709 to TestAppV1.applicationId()),
            hardware = mapOf(
                1 to TestDerV1.set(TestDerV1.integer(2)),
                2 to TestDerV1.integer(3),
                3 to TestDerV1.integer(256),
                5 to TestDerV1.set(TestDerV1.integer(4)),
                10 to TestDerV1.integer(1),
                503 to TestDerV1.tlv(0x05, ByteArray(0)),
                702 to TestDerV1.integer(0),
                704 to TestAppV1.rootOfTrust(),
            ),
        )
    }
}

/** Synthetic attestation certificates carrying the original `KeyDescription`. */
internal object TestAttestationV1 {
    private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val ECDSA_SHA256_OID = "1.2.840.10045.4.3.2"

    fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun authorizations(tags: Map<Int, ByteArray>): ByteArray =
        TestDerV1.sequence(*tags.toSortedMap().map { (tag, content) -> TestDerV1.explicit(tag, content) }.toTypedArray())

    /** Leaf first: the attested key's certificate, then the self-signed root. */
    fun chain(
        subject: PublicKey,
        root: KeyPair,
        challenge: ByteArray,
        serial: Long,
        description: TestKeyDescriptionV1,
    ): List<X509Certificate> {
        val keyDescription = TestDerV1.sequence(
            TestDerV1.integer(description.attestationVersion.toLong()),
            TestDerV1.enumerated(description.attestationLevel),
            TestDerV1.integer(description.keymasterVersion.toLong()),
            TestDerV1.enumerated(description.keymasterLevel),
            TestDerV1.octets(challenge),
            TestDerV1.octets(ByteArray(0)),
            authorizations(description.software),
            authorizations(description.hardware),
        )
        val extension = TestDerV1.sequence(TestDerV1.oid(KEY_DESCRIPTION_OID), TestDerV1.octets(keyDescription))
        val leaf = certificate(serial, "attested key", "attestation root", subject, root.private, listOf(extension))
        // The root is a CA permitted to sign certificates, as the google adapter profile requires.
        val rootCertificate = certificate(1, "attestation root", "attestation root", root.public, root.private, listOf(
            TestDerV1.sequence(TestDerV1.oid("2.5.29.19"), TestDerV1.boolean(true), TestDerV1.octets(TestDerV1.sequence(TestDerV1.boolean(true)))),
            TestDerV1.sequence(TestDerV1.oid("2.5.29.15"), TestDerV1.boolean(true), TestDerV1.octets(TestDerV1.tlv(0x03, byteArrayOf(2, 4)))),
        ))
        return listOf(leaf, rootCertificate)
    }

    /** SHA-256 of a root key's DER `SubjectPublicKeyInfo`: the enrollment policy's pin form. */
    fun spkiSha256(root: KeyPair): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(root.public.encoded)

    private fun certificate(
        serial: Long,
        subject: String,
        issuer: String,
        publicKey: PublicKey,
        signer: PrivateKey,
        extensions: List<ByteArray>,
    ): X509Certificate {
        val algorithm = TestDerV1.sequence(TestDerV1.oid(ECDSA_SHA256_OID))
        val parts = ArrayList<ByteArray>()
        parts.add(TestDerV1.explicit(0, TestDerV1.integer(2)))
        parts.add(TestDerV1.integer(serial))
        parts.add(algorithm)
        parts.add(name(issuer))
        parts.add(TestDerV1.sequence(TestDerV1.utcTime("260101000000Z"), TestDerV1.utcTime("491231235959Z")))
        parts.add(name(subject))
        parts.add(publicKey.encoded)
        if (extensions.isNotEmpty()) parts.add(TestDerV1.explicit(3, TestDerV1.sequence(*extensions.toTypedArray())))
        val tbs = TestDerV1.sequence(*parts.toTypedArray())
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signer)
            update(tbs)
            sign()
        }
        val der = TestDerV1.sequence(tbs, algorithm, TestDerV1.bitString(signature))
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun name(commonName: String): ByteArray =
        TestDerV1.sequence(TestDerV1.set(TestDerV1.sequence(TestDerV1.oid("2.5.4.3"), TestDerV1.utf8(commonName))))
}

/**
 * AndroidKeyStore (keystore2) model with error injection. Generating under an occupied alias
 * replaces the entry and loses the old key, as keystore2 `rebind_alias` does, so a test fails if
 * the adapter ever generates over an existing key.
 */
internal class TestKeyStoreV1 : KagemushaWalletAndroidKeyStoreV1 {
    class Entry(
        val pair: KeyPair,
        val key: TestNonExportableKeyV1,
        var chain: List<X509Certificate>?,
        var facts: KagemushaWalletAndroidKeyFactsV1,
        val strongBox: Boolean,
    )

    private val root = TestAttestationV1.p256()
    private var serial = 2L

    /** E1 Android admission inputs that admit this store's synthetic chains. */
    fun policy(minimumVersion: Long = 7, signers: List<ByteArray> = listOf(TestAppV1.SIGNER)) =
        org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1PolicyV1(
            TestAppV1.PACKAGE, java.math.BigInteger.valueOf(minimumVersion), signers, listOf(
                org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1RootV1(
                    org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1RootV1.Family.GOOGLE_RSA,
                    TestAttestationV1.spkiSha256(root), null,
                ),
            ),
        )
    val entries = LinkedHashMap<String, Entry>()
    val generated = ArrayList<KagemushaWalletAndroidKeySpecV1>()
    var deleteCalls = 0
    var signCalls = 0

    /** Exact messages handed to [sign], in call order. */
    val signedMessages = ArrayList<ByteArray>()
    var getKeyCalls = 0

    var apiLevel = 33
    var strongBoxAvailable = true
    var getKeyFailure: Throwable? = null
    var getKeyFailureAfterGenerations: Int = Int.MAX_VALUE
    var getKeyResult: Key? = null
    var getKeyReturnsNull = false
    var chainFailure: Throwable? = null
    var nullChain = false
    var generateFailure: Throwable? = null
    var generateFailureAfterWrite: Throwable? = null
    var attestedChallenge: ByteArray? = null
    var descriptionEdit: (TestKeyDescriptionV1) -> TestKeyDescriptionV1 = { it }
    var factsEdit: (KagemushaWalletAndroidKeyFactsV1) -> KagemushaWalletAndroidKeyFactsV1 = { it }
    var factsFailure: Throwable? = null
    var signFailure: Throwable? = null
    var deleteFailure: Throwable? = null
    var deleteRemoves = true

    fun facts(strongBox: Boolean): KagemushaWalletAndroidKeyFactsV1 = KagemushaWalletAndroidKeyFactsV1(
        insideSecureHardware = true,
        securityLevel = if (apiLevel >= 31) (if (strongBox) 2 else 1) else null,
        remainingUsageCount = if (apiLevel >= 31) -1 else null,
        origin = 1,
        purposes = 4,
        digests = setOf("SHA-256"),
        keySize = 256,
        userAuthenticationRequired = false,
        userPresenceRequired = if (apiLevel >= 28) false else null,
        userConfirmationRequired = if (apiLevel >= 28) false else null,
    )

    private fun chain(pair: KeyPair, challenge: ByteArray, strongBox: Boolean) = TestAttestationV1.chain(
        pair.public, root, challenge, serial++,
        descriptionEdit(TestKeyDescriptionV1.hardwareKey(if (strongBox) 2 else 1)),
    )

    /** Seed an entry the adapter did not generate (for example from an earlier incarnation). */
    fun seed(alias: String, challenge: ByteArray = ByteArray(32) { 9 }): Entry {
        val pair = TestAttestationV1.p256()
        val entry = Entry(pair, TestNonExportableKeyV1(pair.private), chain(pair, challenge, false), facts(false), false)
        entries[alias] = entry
        return entry
    }

    override fun getKey(alias: String): Key? {
        getKeyCalls += 1
        if (generated.size >= getKeyFailureAfterGenerations) throw IllegalStateException("keystore2 binder failure")
        getKeyFailure?.let { throw it }
        if (getKeyReturnsNull) return null
        getKeyResult?.let { return it }
        return entries[alias]?.key
    }

    override fun getCertificateChain(alias: String): List<Certificate>? {
        chainFailure?.let { throw it }
        if (nullChain) return null
        return entries[alias]?.chain
    }

    override fun generate(spec: KagemushaWalletAndroidKeySpecV1): KeyPair {
        generated += spec
        generateFailure?.let { throw it }
        if (spec.strongBox && !strongBoxAvailable) throw KagemushaWalletAndroidStrongBoxUnavailableV1(null)
        val pair = TestAttestationV1.p256()
        val challenge = attestedChallenge ?: spec.challengeDigest()
        entries[spec.alias] = Entry(pair, TestNonExportableKeyV1(pair.private),
            chain(pair, challenge, spec.strongBox), factsEdit(facts(spec.strongBox)), spec.strongBox)
        generateFailureAfterWrite?.let { throw it }
        return KeyPair(pair.public, entries.getValue(spec.alias).key)
    }

    override fun facts(key: PrivateKey): KagemushaWalletAndroidKeyFactsV1 {
        factsFailure?.let { throw it }
        return entries.values.first { it.key === key }.facts
    }

    override fun sign(key: PrivateKey, message: ByteArray): ByteArray {
        signCalls += 1
        signedMessages += message.copyOf()
        signFailure?.let { throw it }
        val delegate = (key as TestNonExportableKeyV1).delegate
        return Signature.getInstance(KAGEMUSHA_WALLET_ANDROID_SIGNATURE_ALGORITHM_V1).run {
            initSign(delegate)
            update(message)
            sign()
        }
    }

    override fun deleteEntry(alias: String) {
        deleteCalls += 1
        deleteFailure?.let { throw it }
        if (deleteRemoves) entries.remove(alias)
    }

    override fun isPermanentlyInvalidated(error: Throwable): Boolean =
        generateSequence(error) { it.cause }.take(8).any { it is TestPermanentlyInvalidatedKeyV1 }
}

/** Parse the library's backup-rule XML sources into the adapter's element tree. */
internal object TestRulesV1 {
    private val xml = File("src/main/res/xml")

    fun element(file: File): KagemushaWalletAndroidXmlElementV1 {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }
        return convert(factory.newDocumentBuilder().parse(file).documentElement)
    }

    private fun convert(element: Element): KagemushaWalletAndroidXmlElementV1 {
        val attributes = LinkedHashMap<String, String>()
        val nodes = element.attributes
        for (index in 0 until nodes.length) {
            val attribute = nodes.item(index)
            if (attribute.nodeName.startsWith("xmlns")) continue
            val namespace = attribute.namespaceURI.orEmpty()
            attributes[if (namespace.isEmpty()) attribute.localName else "{$namespace}${attribute.localName}"] = attribute.nodeValue
        }
        val children = element.childNodes
        return KagemushaWalletAndroidXmlElementV1(
            element.tagName,
            attributes,
            (0 until children.length).mapNotNull { children.item(it) as? Element }.map(::convert),
        )
    }

    fun dataExtraction(): KagemushaWalletAndroidXmlElementV1 = element(File(xml, "kagemusha_wallet_v1_data_extraction_rules.xml"))

    fun fullBackup(): KagemushaWalletAndroidXmlElementV1 = element(File(xml, "kagemusha_wallet_v1_full_backup_content.xml"))
}

/** Process and storage facts with error injection; the rules default to the shipped resources. */
internal class TestEnvironmentV1(private val directory: File) : KagemushaWalletAndroidEnvironmentV1 {
    override var apiLevel: Int = 33
    var flags = 0
    var agent: String? = null
    var dataExtraction: KagemushaWalletAndroidXmlElementV1 = TestRulesV1.dataExtraction()
    var fullBackup: KagemushaWalletAndroidXmlElementV1 = TestRulesV1.fullBackup()
    var rulesFailure: Throwable? = null
    var deviceProtected = false
    var strongBox = true
    var unlocked = true
    var unlockFailure: Throwable? = null
    var directoryFailure: Throwable? = null

    override fun applicationFlags(): Int = flags
    override fun backupAgentName(): String? = agent

    override fun dataExtractionRules(): KagemushaWalletAndroidXmlElementV1 {
        rulesFailure?.let { throw it }
        return dataExtraction
    }

    override fun fullBackupContentRules(): KagemushaWalletAndroidXmlElementV1 {
        rulesFailure?.let { throw it }
        return fullBackup
    }

    override fun isDeviceProtectedStorage(): Boolean = deviceProtected
    override fun hasStrongBox(): Boolean = strongBox

    override fun isUserUnlocked(): Boolean {
        unlockFailure?.let { throw it }
        return unlocked
    }

    override fun noBackupFilesDir(): File {
        directoryFailure?.let { throw it }
        return directory
    }
}
