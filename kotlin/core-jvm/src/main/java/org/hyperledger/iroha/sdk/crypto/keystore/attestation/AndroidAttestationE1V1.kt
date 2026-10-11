// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.crypto.keystore.attestation

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.hyperledger.iroha.sdk.offline.KagemushaWalletAppPolicyV1
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentPolicyV1
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1 as Refusal

/**
 * Android admission inputs of one E1 app and enrollment policy pair (enrollment policy
 * "Android admission"): the app package, the minimum package version, the 1–4 signer digests
 * and the 1–8 pinned roots. This is selected policy DATA, never an approval; build it with
 * [fromPolicyOriginals] from the exact policy originals the signed runtime carries.
 */
class AndroidAttestationE1PolicyV1(
    packageName: String,
    minimumPackageVersion: BigInteger,
    signerSet: List<ByteArray>,
    roots: List<AndroidAttestationE1RootV1>,
) {
    /** Dotted ASCII package name, at most 255 bytes. */
    val packageName: String = packageName

    /** An attested `versionCode` at or above this passes; unsigned 64-bit, zero allowed. */
    val minimumPackageVersion: BigInteger = minimumPackageVersion

    private val signers: List<ByteArray> = signerSet.map { it.copyOf() }
    private val rootSet: List<AndroidAttestationE1RootV1> = roots.toList()

    init {
        require(kagemushaAndroidPackageValid(packageName)) { "invalid Android app policy package" }
        require(minimumPackageVersion.signum() >= 0 && minimumPackageVersion.bitLength() <= 64) {
            "Android minimum package version must be an unsigned 64-bit value"
        }
        require(signers.size in 1..4 && signers.all { it.size == 32 && it.any { byte -> byte != 0.toByte() } } &&
            signers.zipWithNext().all { (low, high) -> unsignedCompare(low, high) < 0 }) {
            "Android signer set must hold 1-4 nonzero SHA-256 digests in strictly ascending order"
        }
        require(rootSet.size in 1..8 && rootSet.zipWithNext().all { (low, high) ->
            unsignedCompare(low.spkiSha256Original(), high.spkiSha256Original()) < 0
        }) { "Android root set must hold 1-8 roots strictly ascending by SPKI digest" }
    }

    /** Copies of the signer-set digests, ascending. */
    fun signerSet(): List<ByteArray> = signers.map { it.copyOf() }

    /** The pinned roots, ascending by SPKI digest. */
    fun roots(): List<AndroidAttestationE1RootV1> = rootSet.toList()

    internal fun signerAdmitted(digest: ByteArray): Boolean = signers.any { MessageDigest.isEqual(it, digest) }

    internal fun root(spkiSha256: ByteArray): AndroidAttestationE1RootV1? =
        rootSet.firstOrNull { MessageDigest.isEqual(it.spkiSha256Original(), spkiSha256) }

    override fun toString(): String = "AndroidAttestationE1PolicyV1($packageName, ${signers.size} signers, ${rootSet.size} roots)"

    companion object {
        /**
         * The Android admission inputs of the exact canonical app and enrollment policy
         * originals (Norito frames). The enrollment policy must name this app policy's digest
         * and scheme, and both must be Android policies.
         *
         * @throws IllegalArgumentException for a noncanonical, invalid or mismatched original.
         */
        @JvmStatic
        fun fromPolicyOriginals(appPolicyOriginal: ByteArray, enrollmentPolicyOriginal: ByteArray): AndroidAttestationE1PolicyV1 {
            val app = KagemushaWalletAppPolicyV1.decodeCanonical(appPolicyOriginal)
            return KagemushaWalletEnrollmentPolicyV1.decodeCanonical(enrollmentPolicyOriginal).androidAdmission(app)
        }
    }
}

/** One pinned Android root: its family (and Vendor adapter) and SHA-256 of its DER SPKI. */
class AndroidAttestationE1RootV1(
    @JvmField val family: Family,
    spkiSha256: ByteArray,
    @JvmField val adapterId: String?,
) {
    /** Root families of the enrollment policy; GoogleRsa and GoogleCa1 use the `google` profile. */
    enum class Family(@JvmField val tag: Int) { GOOGLE_RSA(1), GOOGLE_CA1(2), VENDOR(3) }

    private val spki = spkiSha256.copyOf()

    init {
        require(spki.size == 32 && spki.any { it != 0.toByte() }) { "root SPKI pin must be a nonzero SHA-256 digest" }
        require(if (family == Family.VENDOR) adapterId != null && kagemushaAdapterIdValid(adapterId) else adapterId == null) {
            "only a Vendor root names an adapter identifier ([a-z][a-z0-9-]*, 1-16 bytes)"
        }
    }

    /** SHA-256 of the root certificate's DER `SubjectPublicKeyInfo`. */
    fun spkiSha256(): ByteArray = spki.copyOf()

    internal fun spkiSha256Original(): ByteArray = spki

    /** The `google` profile permits the provisioning information extension; Vendor profiles do not. */
    internal val provisioningInformationPermitted: Boolean get() = family != Family.VENDOR

    override fun toString(): String = "AndroidAttestationE1RootV1($family${adapterId?.let { ", $it" } ?: ""})"
}

/**
 * The Android adapter's own check of its fresh attestation before E5 (design §2.4). It applies
 * the Phone and App checks of the enrollment policy's Android admission steps 1, 2 and 4–8 in
 * order and reports the first failing step's closed refusal reason. Revocation (step 3) and
 * trusted-time certificate validity are issuer-only: the issuer stays authoritative and may
 * report a different first failure. [Eligible] is no admission and grants nothing.
 */
sealed class AndroidAttestationE1ResultV1 {
    /** Every client-checkable step passed. */
    class Eligible internal constructor(
        @JvmField val securityLevel: AttestationResult.SecurityLevel,
        @JvmField val attestationVersion: Int,
        @JvmField val keyMintVersion: Int,
        @JvmField val packageVersion: BigInteger,
    ) : AndroidAttestationE1ResultV1() {
        override fun toString(): String = "Eligible($securityLevel, $attestationVersion/$keyMintVersion)"
    }

    /** The first failing check, as its closed §2.4 reason; [detail] is diagnostic text only. */
    class Ineligible internal constructor(
        @JvmField val refusal: Refusal,
        @JvmField val detail: String,
    ) : AndroidAttestationE1ResultV1() {
        override fun toString(): String = "Ineligible(${refusal.name}: $detail)"
    }
}

/** Android admission order of the enrollment policy, client side. */
internal object AndroidAttestationE1EvaluatorV1 {
    private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val PROVISIONING_INFORMATION_OID = "1.3.6.1.4.1.11129.2.1.30"
    private const val BASIC_CONSTRAINTS_OID = "2.5.29.19"
    private const val KEY_USAGE_OID = "2.5.29.15"
    private const val APPLICATION_ID_TAG = 709
    private const val ROOT_OF_TRUST_TAG = 704
    private const val USAGE_COUNT_LIMIT_TAG = 405
    private const val ALL_APPLICATIONS_TAG = 600
    private val HARDWARE_KEY_PROPERTY_TAGS = setOf(1, 2, 3, 5, 10, 702, 704)

    /** The documented attestation/KeyMint version pairs; version 1 is refused with its own reason. */
    val VERSION_PAIRS: Set<Pair<Int, Int>> = setOf(
        2 to 3, 3 to 4, 4 to 41, 100 to 100, 200 to 200, 300 to 300, 400 to 400, 500 to 500,
    )

    private val SIGNATURE_ALGORITHMS = setOf(
        "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
        "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",
    )
    private val RSA_SIGNATURE_ALGORITHMS = setOf("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13")
    private val AUTH_SET_OF_INTEGER = setOf(1, 5, 6, 203)
    private val AUTH_INTEGER = setOf(2, 3, 10, 200, 400, 401, 402, 405, 504, 505, 701, 702, 705, 706, 718, 719)
    private val AUTH_NULL = setOf(303, 305, 503, 506, 507, 508, 509, 600, 720)
    private val AUTH_OCTET_STRING = setOf(601, 709, 710, 711, 712, 713, 714, 715, 716, 717, 723, 724)

    private class Refused(val refusal: Refusal, message: String) : Exception(message)

    private fun refuse(refusal: Refusal, message: String): Nothing = throw Refused(refusal, message)

    private inline fun <T> stage(refusal: Refusal, block: () -> T): T = try {
        block()
    } catch (refused: Refused) {
        throw refused
    } catch (error: Exception) {
        throw Refused(refusal, error.message ?: error.javaClass.simpleName)
    }

    private fun demand(condition: Boolean, refusal: Refusal, message: String) {
        if (!condition) refuse(refusal, message)
    }

    fun evaluate(
        chainDer: List<ByteArray>,
        challengeDigest: ByteArray,
        paymentKeySec1: ByteArray,
        policy: AndroidAttestationE1PolicyV1,
    ): AndroidAttestationE1ResultV1 {
        require(challengeDigest.size == 32 && challengeDigest.any { it != 0.toByte() }) {
            "E1 challenge digest must be 32 nonzero bytes"
        }
        require(paymentKeySec1.size == 65 && paymentKeySec1[0] == 4.toByte()) {
            "payment key must be an uncompressed 65-byte P-256 point"
        }
        val chain = chainDer.map { it.copyOf() }
        val challenge = challengeDigest.copyOf()
        val paymentKey = paymentKeySec1.copyOf()
        return try {
            evaluateLocked(chain, challenge, paymentKey, policy)
        } catch (refused: Refused) {
            AndroidAttestationE1ResultV1.Ineligible(refused.refusal, refused.message ?: refused.refusal.name)
        }
    }

    private fun evaluateLocked(
        chain: List<ByteArray>,
        challenge: ByteArray,
        paymentKey: ByteArray,
        policy: AndroidAttestationE1PolicyV1,
    ): AndroidAttestationE1ResultV1 {
        // Step 1, shape: 2-8 DER certificates, leaf first, each 1-16,384 bytes, at most 65,536.
        val certificates = stage(Refusal.EVIDENCE_INVALID) {
            require(chain.size in 2..8 && chain.all { it.size in 1..16_384 } && chain.sumOf { it.size } <= 65_536) {
                "Android certificate chain outside shape"
            }
            chain.map(::parseCertificate)
        }

        // Step 2, root and path. Trusted-time validity is the issuer's alone.
        val root = stage(Refusal.UNTRUSTED_ATTESTATION_ROOT) {
            val last = certificates.last()
            require(last.subject.contentEquals(last.issuer)) { "chain does not end at a self-signed root" }
            val anchor = policy.root(last.spkiSha256) ?: throw IllegalArgumentException("chain root is not in the pinned root set")
            require(chain.map { it.toList() }.toSet().size == chain.size) { "duplicate certificate in chain" }
            path(certificates)
            anchor
        }

        // Step 4, key description of the trusted attestation certificate.
        val description = stage(Refusal.EVIDENCE_INVALID) {
            val described = certificates.indices.filter { certificates[it].extensions.containsKey(KEY_DESCRIPTION_OID) }
            require(described.isNotEmpty()) { "missing KeyMint key description" }
            require(described.max() == 0) { "key description outside the trusted attestation certificate" }
            val provisioned = certificates.indices.filter {
                certificates[it].extensions.containsKey(PROVISIONING_INFORMATION_OID)
            }
            if (provisioned.isNotEmpty()) {
                require(root.provisioningInformationPermitted) { "provisioning information outside adapter profile" }
                require(provisioned == listOf(1)) { "provisioning information is not immediately above the key description" }
            }
            require(MessageDigest.isEqual(certificates[0].p256Point(), paymentKey)) {
                "attestation certificate key differs from payment key"
            }
            val fields = Der.one(certificates[0].extensions.getValue(KEY_DESCRIPTION_OID).value).children()
            require(fields.size == 8) { "invalid KeyMint key description" }
            val version = fields[0].nonNegativeInteger()
            val level = fields[1].nonNegativeInteger(Der.ENUMERATED)
            val keyMintVersion = fields[2].nonNegativeInteger()
            val keyMintLevel = fields[3].nonNegativeInteger(Der.ENUMERATED)
            require(MessageDigest.isEqual(fields[4].primitive(Der.OCTET_STRING), challenge)) {
                "attestation challenge differs from E1"
            }
            fields[5].primitive(Der.OCTET_STRING)
            Description(version, level, keyMintVersion, keyMintLevel, fields[6], fields[7])
        }
        val version = description.version
        demand(version != BigInteger.ONE, Refusal.ATTESTATION_WITHOUT_APP_IDENTITY,
            "attestation version 1 carries no application identity")
        val (software, hardware) = stage(Refusal.EVIDENCE_INVALID) {
            require(version.bitLength() < 32 && description.keyMintVersion.bitLength() < 32 &&
                (version.toInt() to description.keyMintVersion.toInt()) in VERSION_PAIRS) { "undocumented attestation version pair" }
            authorizationList(description.software) to authorizationList(description.hardware)
        }

        // Step 5, secure hardware.
        val level = description.level
        demand(level == description.keyMintLevel && (level == BigInteger.ONE || level == BigInteger.valueOf(2)) &&
            (version != BigInteger.valueOf(2) || level == BigInteger.ONE),
            Refusal.KEY_NOT_IN_SECURE_HARDWARE, "key is not in secure hardware")

        // Step 6, hardware-enforced key properties and forbidden authorizations.
        stage(Refusal.EVIDENCE_INVALID) {
            require(USAGE_COUNT_LIMIT_TAG !in software && USAGE_COUNT_LIMIT_TAG !in hardware) { "usage-count-limited key" }
            require(ALL_APPLICATIONS_TAG !in software && ALL_APPLICATIONS_TAG !in hardware) { "key usable by all applications" }
            require(HARDWARE_KEY_PROPERTY_TAGS.none { it in software } && HARDWARE_KEY_PROPERTY_TAGS.all { it in hardware }) {
                "key properties are not hardware-enforced"
            }
            require(integerSet(hardware.getValue(1)) == setOf(BigInteger.valueOf(2)) &&
                hardware.getValue(2).nonNegativeInteger() == BigInteger.valueOf(3) &&
                hardware.getValue(3).nonNegativeInteger() == BigInteger.valueOf(256) &&
                integerSet(hardware.getValue(5)) == setOf(BigInteger.valueOf(4)) &&
                hardware.getValue(10).nonNegativeInteger() == BigInteger.ONE &&
                hardware.getValue(702).nonNegativeInteger() == BigInteger.ZERO) {
                "key is not a generated P-256 SIGN/SHA-256 key"
            }
        }

        // Step 7, application identity, in either authorization list.
        demand(APPLICATION_ID_TAG in software || APPLICATION_ID_TAG in hardware,
            Refusal.ATTESTATION_WITHOUT_APP_IDENTITY, "attestation carries no application identity")
        val identity = stage(Refusal.EVIDENCE_INVALID) {
            require(!(APPLICATION_ID_TAG in software && APPLICATION_ID_TAG in hardware)) { "application identity appears twice" }
            val value = (software[APPLICATION_ID_TAG] ?: hardware.getValue(APPLICATION_ID_TAG)).primitive(Der.OCTET_STRING)
            val fields = Der.one(value).children()
            require(fields.size == 2) { "invalid attestation application identity" }
            val packages = fields[0].children(Der.SET).map { it.children() }
            require(packages.all { it.size == 2 }) { "invalid attested package" }
            AppIdentity(
                packages.map { it[0].primitive(Der.OCTET_STRING) },
                packages.map { it[1].nonNegativeInteger() },
                fields[1].children(Der.SET).map { it.primitive(Der.OCTET_STRING) },
            )
        }
        demand(identity.packageNames.size == 1 && identity.packageNames[0].contentEquals(policy.packageName.toByteArray(Charsets.UTF_8)),
            Refusal.APP_IDENTITY_MISMATCH, "attested package differs from app policy")
        demand(identity.signers.isNotEmpty() && identity.signers.all(policy::signerAdmitted),
            Refusal.APP_IDENTITY_MISMATCH, "attested signer outside the signer set")
        demand(identity.packageVersions[0] >= policy.minimumPackageVersion,
            Refusal.APP_VERSION_BELOW_MINIMUM, "attested package version below minimum")

        // Step 8, hardware-enforced RootOfTrust in its version's exact DER shape.
        val boot = stage(Refusal.EVIDENCE_INVALID) {
            val fields = hardware.getValue(ROOT_OF_TRUST_TAG).children()
            require(fields.size == (if (version == BigInteger.valueOf(2)) 3 else 4)) { "RootOfTrust shape differs from its version" }
            Boot(
                fields[0].primitive(Der.OCTET_STRING),
                fields[1].boolean(),
                fields[2].nonNegativeInteger(Der.ENUMERATED),
                if (version == BigInteger.valueOf(2)) null else fields[3].primitive(Der.OCTET_STRING),
            )
        }
        demand(boot.locked, Refusal.BOOTLOADER_UNLOCKED, "bootloader is unlocked")
        demand(boot.state == BigInteger.ZERO && boot.key.any { it != 0.toByte() }, Refusal.BOOT_NOT_VERIFIED,
            "verified boot state is not Verified")
        demand(version < BigInteger.valueOf(100) || (boot.hash != null && boot.hash.size == 32 && boot.hash.any { it != 0.toByte() }),
            Refusal.BOOT_NOT_VERIFIED, "KeyMint verified boot hash is invalid")

        // Step 9 records patch levels only; the floor never refuses a phone.
        return AndroidAttestationE1ResultV1.Eligible(
            if (level == BigInteger.ONE) AttestationResult.SecurityLevel.TRUSTED_ENVIRONMENT else AttestationResult.SecurityLevel.STRONG_BOX,
            version.toInt(), description.keyMintVersion.toInt(), identity.packageVersions[0],
        )
    }

    private class Description(
        val version: BigInteger,
        val level: BigInteger,
        val keyMintVersion: BigInteger,
        val keyMintLevel: BigInteger,
        val software: Der,
        val hardware: Der,
    )

    private class AppIdentity(val packageNames: List<ByteArray>, val packageVersions: List<BigInteger>, val signers: List<ByteArray>)

    private class Boot(val key: ByteArray, val locked: Boolean, val state: BigInteger, val hash: ByteArray?)

    private class Extension(val critical: Boolean, val value: ByteArray)

    private class Certificate(
        val certificate: X509Certificate,
        val signatureAlgorithm: ByteArray,
        val outerSignatureAlgorithm: ByteArray,
        val signatureAlgorithmOid: String,
        val signatureAlgorithmFields: List<Der>,
        val issuer: ByteArray,
        val subject: ByteArray,
        val spki: Der,
        val spkiSha256: ByteArray,
        val extensions: Map<String, Extension>,
    ) {
        /** The 65-byte uncompressed point of a P-256 `SubjectPublicKeyInfo`. */
        fun p256Point(): ByteArray {
            val fields = spki.children()
            require(fields.size == 2) { "invalid subject public key" }
            val algorithm = fields[0].children()
            require(algorithm.size == 2 && algorithm[0].oid() == "1.2.840.10045.2.1" && algorithm[1].oid() == "1.2.840.10045.3.1.7") {
                "not P-256 EC public key"
            }
            val bits = fields[1].primitive(Der.BIT_STRING)
            require(bits.size == 66 && bits[0] == 0.toByte() && bits[1] == 4.toByte()) { "invalid P-256 point" }
            return bits.copyOfRange(1, 66)
        }
    }

    /** One certificate, parsed strictly as the issuer verifier does, plus its JCA form for signatures. */
    private fun parseCertificate(der: ByteArray): Certificate {
        val outer = Der.one(der).children()
        require(outer.size == 3) { "invalid X.509 certificate" }
        val tbs = outer[0].children()
        require(tbs.isNotEmpty()) { "truncated X.509 TBS" }
        val start = if (tbs[0].tagClass == Der.CONTEXT && tbs[0].number == 0) 1 else 0
        var version = 0
        if (start == 1) {
            val encoded = tbs[0].children(0, Der.CONTEXT)
            require(encoded.size == 1) { "invalid X.509 version" }
            version = encoded[0].nonNegativeInteger().toInt()
            require(version == 1 || version == 2) { "invalid X.509 version" }
        }
        require(tbs.size >= start + 6) { "truncated X.509 TBS" }
        val serial = tbs[start].nonNegativeInteger()
        require(serial.signum() > 0 && serial.bitLength() <= 160) { "X.509 serial outside bound" }
        val algorithm = tbs[start + 1].children()
        require(algorithm.size in 1..2) { "invalid X.509 signature algorithm" }
        val algorithmOid = algorithm[0].oid()
        outer[2].primitive(Der.BIT_STRING)
        tbs[start + 5].children()
        val extensions = LinkedHashMap<String, Extension>()
        var priorOptional = 0
        for (field in tbs.drop(start + 6)) {
            require(field.tagClass == Der.CONTEXT && field.number in 1..3 && field.number > priorOptional) {
                "duplicate or misplaced X.509 optional field"
            }
            priorOptional = field.number
            if (field.number != 3) continue
            require(version == 2) { "X.509 extensions require v3" }
            val enclosing = field.children(3, Der.CONTEXT)
            require(enclosing.size == 1) { "invalid X.509 extensions" }
            val listed = enclosing[0].children()
            require(listed.isNotEmpty()) { "empty X.509 extensions" }
            for (extension in listed) {
                val parts = extension.children()
                require(parts.size == 2 || parts.size == 3) { "invalid X.509 extension" }
                val name = parts[0].oid()
                if (parts.size == 3) require(parts[1].primitive(Der.BOOLEAN).contentEquals(byteArrayOf(-1))) { "invalid X.509 extension critical flag" }
                require(name !in extensions) { "duplicate X.509 extension" }
                extensions[name] = Extension(parts.size == 3, parts.last().primitive(Der.OCTET_STRING))
            }
        }
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        return Certificate(
            certificate, tbs[start + 1].encoded(), outer[1].encoded(), algorithmOid, algorithm,
            tbs[start + 2].encoded(), tbs[start + 4].encoded(), tbs[start + 5],
            MessageDigest.getInstance("SHA-256").digest(tbs[start + 5].encoded()), extensions,
        )
    }

    /** Signature algorithms, critical extensions, constraints and every link's signature. */
    private fun path(certificates: List<Certificate>) {
        for ((index, certificate) in certificates.withIndex()) {
            require(certificate.signatureAlgorithm.contentEquals(certificate.outerSignatureAlgorithm) &&
                certificate.signatureAlgorithmOid in SIGNATURE_ALGORITHMS) { "certificate signature algorithm outside adapter profile" }
            val fields = certificate.signatureAlgorithmFields
            if (certificate.signatureAlgorithmOid in RSA_SIGNATURE_ALGORITHMS) {
                require(fields.size == 1 || fields[1].primitive(Der.NULL).isEmpty()) { "invalid RSA signature parameters" }
            } else {
                require(fields.size == 1) { "invalid ECDSA signature parameters" }
            }
            require(certificate.extensions.filterValues { it.critical }.keys.all { it == BASIC_CONSTRAINTS_OID || it == KEY_USAGE_OID }) {
                "critical extension outside adapter profile"
            }
            val constraints = certificate.extensions[BASIC_CONSTRAINTS_OID]?.let { basicConstraints(it.value) }
            val usage = certificate.extensions[KEY_USAGE_OID]?.let { keyUsage(it.value) }
            if (index == 0) {
                require(constraints == null || !constraints.first) { "attestation certificate is a CA" }
                require(usage == null || usage and 0x8000 != 0) { "attestation certificate key usage forbids signatures" }
            } else {
                require(constraints != null && constraints.first) { "issuing certificate is not a CA" }
                require(constraints.second == null || BigInteger.valueOf((index - 1).toLong()) <= constraints.second) {
                    "path length constraint exceeded"
                }
                require(usage == null || usage and 0x0400 != 0) { "issuing certificate key usage forbids certificate signing" }
            }
        }
        // Each link, and the root's own signature, verifies under the next certificate's key.
        for (index in certificates.indices) {
            val issuer = certificates[minOf(index + 1, certificates.size - 1)].certificate
            certificates[index].certificate.verify(issuer.publicKey)
        }
    }

    private fun basicConstraints(value: ByteArray): Pair<Boolean, BigInteger?> {
        val fields = Der.one(value).children()
        require(fields.size <= 2) { "invalid basic constraints" }
        var ca = false
        var pathLength: BigInteger? = null
        for ((index, field) in fields.withIndex()) {
            if (field.tagClass == Der.UNIVERSAL && field.number == Der.BOOLEAN && index == 0) {
                ca = field.boolean()
            } else {
                require(pathLength == null) { "invalid basic constraints" }
                pathLength = field.nonNegativeInteger()
            }
        }
        return ca to pathLength
    }

    private fun keyUsage(value: ByteArray): Int {
        val raw = Der.one(value).primitive(Der.BIT_STRING)
        require(raw.isNotEmpty() && (raw[0].toInt() and 0xff) <= 7 && (raw.size > 1 || raw[0] == 0.toByte())) { "invalid key usage" }
        var bits = 0
        for ((index, byte) in raw.drop(1).take(2).withIndex()) bits = bits or ((byte.toInt() and 0xff) shl (8 * (1 - index)))
        return bits
    }

    /** One AuthorizationList: documented fields are type-checked; unknown tags are ignored. */
    private fun authorizationList(value: Der): Map<Int, Der> {
        val result = LinkedHashMap<Int, Der>()
        var prior = -1
        for (field in value.children()) {
            require(field.tagClass == Der.CONTEXT && field.constructed) { "KeyMint authorization is not an explicit context tag" }
            require(field.number > prior) { "duplicate or out-of-order KeyMint authorization tag" }
            prior = field.number
            val item = Der.one(field.value)
            when (field.number) {
                in AUTH_SET_OF_INTEGER -> item.children(Der.SET).forEach { it.nonNegativeInteger() }
                in AUTH_INTEGER -> item.nonNegativeInteger()
                in AUTH_NULL -> require(item.primitive(Der.NULL).isEmpty()) { "invalid KeyMint NULL authorization" }
                in AUTH_OCTET_STRING -> item.primitive(Der.OCTET_STRING)
                ROOT_OF_TRUST_TAG -> item.children()
                else -> continue
            }
            result[field.number] = item
        }
        return result
    }

    private fun integerSet(value: Der): Set<BigInteger> = value.children(Der.SET).map { it.nonNegativeInteger() }.toSet()

    /** Minimal-length DER element, exactly as the issuer's reader admits it (no BER, ≤ 64 children). */
    private class Der(val tagClass: Int, val constructed: Boolean, val number: Int, val value: ByteArray) {
        fun encoded(): ByteArray {
            val head = (tagClass shl 6) or (if (constructed) 0x20 else 0)
            val tag = if (number < 31) byteArrayOf((head or number).toByte()) else {
                val parts = ArrayList<Int>()
                var rest = number
                parts.add(rest and 0x7f)
                rest = rest ushr 7
                while (rest != 0) { parts.add(0, 0x80 or (rest and 0x7f)); rest = rest ushr 7 }
                byteArrayOf((head or 31).toByte()) + parts.map { it.toByte() }.toByteArray()
            }
            val size = value.size
            val length = if (size < 128) byteArrayOf(size.toByte()) else {
                val raw = BigInteger.valueOf(size.toLong()).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
                byteArrayOf((0x80 or raw.size).toByte()) + raw
            }
            return tag + length + value
        }

        fun children(expected: Int = SEQUENCE, expectedClass: Int = UNIVERSAL): List<Der> {
            require(tagClass == expectedClass && number == expected && constructed) { "unexpected DER container" }
            val result = ArrayList<Der>()
            var offset = 0
            while (offset < value.size) {
                val (child, end) = at(value, offset)
                result.add(child)
                require(result.size <= 64) { "too many DER children" }
                offset = end
            }
            return result
        }

        fun primitive(expected: Int): ByteArray {
            require(tagClass == UNIVERSAL && number == expected && !constructed) { "unexpected DER primitive" }
            return value
        }

        fun nonNegativeInteger(expected: Int = INTEGER): BigInteger {
            val raw = primitive(expected)
            require(raw.isNotEmpty() && (raw[0].toInt() and 0xff) < 128 &&
                (raw.size == 1 || raw[0] != 0.toByte() || (raw[1].toInt() and 0xff) >= 128)) { "invalid DER integer" }
            return BigInteger(1, raw)
        }

        fun boolean(): Boolean {
            val raw = primitive(BOOLEAN)
            require(raw.size == 1 && (raw[0] == 0.toByte() || raw[0] == (-1).toByte())) { "invalid DER boolean" }
            return raw[0] == (-1).toByte()
        }

        fun oid(): String {
            val raw = primitive(OBJECT_IDENTIFIER)
            require(raw.isNotEmpty()) { "empty DER OID" }
            val numbers = ArrayList<Long>()
            var current = 0L
            var componentStart = true
            for (byte in raw) {
                val unsigned = byte.toInt() and 0xff
                require(!(componentStart && unsigned == 0x80)) { "nonminimal DER OID component" }
                current = (current shl 7) or (unsigned and 0x7f).toLong()
                require(current < (1L shl 40)) { "DER OID component too large" }
                if (unsigned < 128) { numbers.add(current); current = 0; componentStart = true } else componentStart = false
            }
            require((raw.last().toInt() and 0xff) < 128 && numbers.isNotEmpty()) { "truncated DER OID" }
            val first = numbers.removeAt(0)
            val head = when { first < 40 -> listOf(0L, first); first < 80 -> listOf(1L, first - 40); else -> listOf(2L, first - 80) }
            return (head + numbers).joinToString(".")
        }

        companion object {
            const val UNIVERSAL = 0
            const val CONTEXT = 2
            const val BOOLEAN = 1
            const val INTEGER = 2
            const val BIT_STRING = 3
            const val OCTET_STRING = 4
            const val NULL = 5
            const val OBJECT_IDENTIFIER = 6
            const val ENUMERATED = 10
            const val SEQUENCE = 16
            const val SET = 17

            fun one(data: ByteArray): Der {
                val (value, end) = at(data, 0)
                require(end == data.size) { "trailing DER bytes" }
                return value
            }

            fun at(data: ByteArray, start: Int): Pair<Der, Int> {
                var offset = start
                require(offset < data.size) { "truncated DER tag" }
                val first = data[offset++].toInt() and 0xff
                val tagClass = first ushr 6
                val constructed = first and 0x20 != 0
                var number = first and 0x1f
                if (number == 31) {
                    number = 0
                    var done = false
                    for (index in 0 until 4) {
                        require(offset < data.size) { "truncated DER tag number" }
                        val part = data[offset++].toInt() and 0xff
                        require(index != 0 || part != 0x80) { "nonminimal DER tag number" }
                        number = (number shl 7) or (part and 0x7f)
                        if (part < 128) { done = true; break }
                    }
                    require(done) { "DER tag number too large" }
                    require(number >= 31) { "nonminimal DER tag number" }
                }
                require(offset < data.size) { "truncated DER length" }
                val firstLength = data[offset++].toInt() and 0xff
                val length: Int
                if (firstLength < 128) {
                    length = firstLength
                } else {
                    val count = firstLength and 0x7f
                    require(count in 1..4 && offset + count <= data.size) { "invalid DER length" }
                    require(data[offset] != 0.toByte()) { "nonminimal DER length" }
                    var parsed = 0L
                    for (index in 0 until count) parsed = (parsed shl 8) or (data[offset + index].toLong() and 0xff)
                    offset += count
                    require(parsed >= 128 && parsed <= Int.MAX_VALUE) { "nonminimal DER length" }
                    length = parsed.toInt()
                }
                require(offset.toLong() + length <= data.size) { "truncated DER value" }
                return Der(tagClass, constructed, number, data.copyOfRange(offset, offset + length)) to offset + length
            }
        }
    }
}

/** Rust `package_valid`: dotted ASCII identifiers, at least two parts, at most 255 bytes. */
internal fun kagemushaAndroidPackageValid(value: String): Boolean =
    value.length <= 255 && value.all { it.code < 128 } && value.split('.').let { parts ->
        parts.size >= 2 && parts.all { part ->
            part.isNotEmpty() && (part[0].isAsciiLetter() || part[0] == '_') &&
                part.all { it.isAsciiLetter() || it in '0'..'9' || it == '_' }
        }
    }

/** Rust `adapter_id_valid`: 1-16 bytes of `[a-z][a-z0-9-]*`. */
internal fun kagemushaAdapterIdValid(value: String): Boolean =
    value.length in 1..16 && value[0] in 'a'..'z' && value.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }

private fun Char.isAsciiLetter(): Boolean = this in 'a'..'z' || this in 'A'..'Z'

private fun unsignedCompare(left: ByteArray, right: ByteArray): Int {
    for (index in 0 until minOf(left.size, right.size)) {
        val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
        if (difference != 0) return difference
    }
    return left.size - right.size
}
