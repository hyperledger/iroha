// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.crypto.keystore

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
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

/** A Keystore-like private key: usable for signing through its owner, never exportable. */
internal class TestKeystorePrivateKeyV1(val delegate: PrivateKey) : PrivateKey {
    override fun getAlgorithm(): String = delegate.algorithm
    override fun getFormat(): String? = null
    override fun getEncoded(): ByteArray? = null
}

/**
 * Read-only AndroidKeyStore (keystore2) entry model with error injection for the tri-state alias
 * probe. Seeded keys carry a synthetic two-certificate chain: the leaf over the entry public key,
 * then a self-signed root.
 */
internal class TestAndroidKeystoreV1(override var apiLevel: Int = 31) : AndroidKeystoreEntriesV1 {
    class Entry(
        val pair: KeyPair,
        val key: TestKeystorePrivateKeyV1,
        val chain: List<X509Certificate>,
    )

    private val root = TestKeystoreAttestationV1.p256()
    private var serial = 2L
    val entries = LinkedHashMap<String, Entry>()
    var getKeyCalls = 0

    /** Thrown by every `getKey`, as keystore2 does for a binder or daemon failure. */
    var getKeyFailure: Throwable? = null

    /** Seed an entry no adapter generated in this test (for example from an earlier process). */
    fun seed(alias: String): Entry {
        val pair = TestKeystoreAttestationV1.p256()
        val chain = TestKeystoreAttestationV1.chain(pair.public, root, serial++)
        return Entry(pair, TestKeystorePrivateKeyV1(pair.private), chain).also { entries[alias] = it }
    }

    override fun getKey(alias: String): Key? {
        getKeyCalls += 1
        getKeyFailure?.let { throw it }
        return entries[alias]?.key
    }

    override fun getCertificateChain(alias: String): List<Certificate>? = entries[alias]?.chain
}

/** Synthetic P-256 X.509 certificates for the entry model (JDK 8 APIs only). */
internal object TestKeystoreAttestationV1 {
    private const val ECDSA_SHA256_OID = "1.2.840.10045.4.3.2"

    fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    /** Leaf first: the certificate over [subject] issued by [root], then the self-signed root. */
    fun chain(subject: PublicKey, root: KeyPair, serial: Long): List<X509Certificate> {
        val leaf = certificate(serial, "attested key", "attestation root", subject, root.private)
        val rootCertificate = certificate(1, "attestation root", "attestation root", root.public, root.private)
        return listOf(leaf, rootCertificate)
    }

    private fun certificate(
        serial: Long,
        subject: String,
        issuer: String,
        publicKey: PublicKey,
        signer: PrivateKey,
    ): X509Certificate {
        val algorithm = sequence(oid(ECDSA_SHA256_OID))
        val tbs = sequence(
            tlv(0xa0, integer(2)), integer(serial), algorithm, name(issuer),
            sequence(tlv(0x17, "260101000000Z".toByteArray(Charsets.US_ASCII)),
                tlv(0x17, "491231235959Z".toByteArray(Charsets.US_ASCII))),
            name(subject), publicKey.encoded,
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signer)
            update(tbs)
            sign()
        }
        val der = sequence(tbs, algorithm, tlv(0x03, byteArrayOf(0) + signature))
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun name(commonName: String): ByteArray =
        sequence(set(sequence(oid("2.5.4.3"), tlv(0x0c, commonName.toByteArray(Charsets.UTF_8)))))

    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        val size = content.size
        when {
            size < 0x80 -> out.write(size)
            size < 0x100 -> { out.write(0x81); out.write(size) }
            else -> { out.write(0x82); out.write(size ushr 8); out.write(size and 0xff) }
        }
        out.write(content)
        return out.toByteArray()
    }

    private fun sequence(vararg items: ByteArray): ByteArray = tlv(0x30, concat(items))
    private fun set(vararg items: ByteArray): ByteArray = tlv(0x31, concat(items))
    private fun integer(value: Long): ByteArray = tlv(0x02, BigInteger.valueOf(value).toByteArray())

    private fun oid(dotted: String): ByteArray {
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
            for (index in groups.indices.reversed()) out.write(groups[index] or (if (index == 0) 0 else 0x80))
        }
        return tlv(0x06, out.toByteArray())
    }

    private fun concat(items: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        items.forEach { out.write(it) }
        return out.toByteArray()
    }
}
