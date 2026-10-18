// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import java.security.MessageDigest
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1PolicyV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1RootV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.kagemushaAdapterIdValid
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.kagemushaAndroidPackageValid
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import org.hyperledger.iroha.sdk.norito.Varint

/**
 * The exact canonical `KagemushaWalletAppPolicyV1` original (enrollment policy spec): the app
 * identity an E1 challenge names by its `H("app-policy", transcript)` digest. Decoding checks
 * the 1,024-byte frame cap, the canonical Norito frame (re-encoded byte for byte), version 1 and
 * the structural rules of the Rust Model. A decoded policy is selected DATA, never an approval:
 * only the issuer's authenticated selection, and Native's installation of the signed runtime
 * that carries it, make it the policy in force.
 */
class KagemushaWalletAppPolicyV1 private constructor(schemeId: ByteArray, @JvmField val identity: Identity) {
    private val scheme = schemeId.copyOf()

    /** Exactly one platform app identity. */
    sealed class Identity {
        /** Package, minimum package version and the released signer set (transcript tag 1). */
        class Android internal constructor(
            @JvmField val packageName: String,
            @JvmField val minimumPackageVersion: BigInteger,
            signerSet: List<ByteArray>,
        ) : Identity() {
            private val signers = signerSet.map { it.copyOf() }

            /** Copies of the 1-4 signer digests, strictly ascending. */
            fun signerSet(): List<ByteArray> = signers.map { it.copyOf() }

            internal fun signersOriginal(): List<ByteArray> = signers
        }

        /** Exact App ID of the production App Attest verifier (transcript tag 2). */
        class Apple internal constructor(@JvmField val appId: String) : Identity()
    }

    /** The nonzero scheme identity. */
    fun schemeId(): ByteArray = scheme.copyOf()

    /** Exact policy transcript: Android is `48 + package + 32 × signers` bytes, Apple `39 + app_id`. */
    fun transcript(): ByteArray {
        val out = PolicyTranscript().u16(VERSION).bytes(scheme)
        when (val selected = identity) {
            is Identity.Android -> {
                out.u8(1).text(selected.packageName).u64(selected.minimumPackageVersion).u8(selected.signersOriginal().size)
                selected.signersOriginal().forEach { out.bytes(it) }
            }
            is Identity.Apple -> out.u8(2).text(selected.appId)
        }
        return out.finish()
    }

    /** `H("app-policy", transcript)`, the digest an E1 challenge names. Grants no authority. */
    fun policyDigest(): ByteArray = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.APP_POLICY, transcript())

    /** The canonical Norito frame of this policy. */
    fun encodeCanonical(): ByteArray {
        val payload = NoritoFields()
        payload.field { it.u16(VERSION) }
        payload.field { it.raw(scheme) }
        payload.field { variant ->
            when (val selected = identity) {
                is Identity.Android -> {
                    variant.u32(1)
                    variant.field { it.string(selected.packageName) }
                    variant.field { it.u64(selected.minimumPackageVersion) }
                    variant.field { list ->
                        list.u64(BigInteger.valueOf(selected.signersOriginal().size.toLong()))
                        selected.signersOriginal().forEach { signer -> list.field { it.byteArray(signer) } }
                    }
                }
                is Identity.Apple -> {
                    variant.u32(2)
                    variant.field { it.string(selected.appId) }
                }
            }
        }
        return frame(APP_POLICY_SCHEMA, payload.finish())
    }

    override fun toString(): String = "KagemushaWalletAppPolicyV1(${identity.javaClass.simpleName})"

    companion object {
        /** Canonical Rust type name; its Norito schema hash heads every frame. */
        const val SCHEMA_NAME: String = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAppPolicyV1"
        private val APP_POLICY_SCHEMA: ByteArray = SchemaHash.hash16(SCHEMA_NAME)

        /**
         * Decode one canonical original under the 1,024-byte frame cap.
         *
         * @throws IllegalArgumentException for an oversized, noncanonical, wrong-version or
         * structurally invalid original.
         */
        @JvmStatic
        fun decodeCanonical(original: ByteArray): KagemushaWalletAppPolicyV1 {
            val frame = original.copyOf()
            val reader = NoritoReader(payload(APP_POLICY_SCHEMA, frame))
            reader.field { require(it.u16() == VERSION) { "app policy version must be 1" } }
            val scheme = reader.field { it.raw(32) }
            val identity = reader.field { variant ->
                when (variant.u32()) {
                    1L -> {
                        val name = variant.field { it.string() }
                        val minimum = variant.field { it.u64() }
                        val signers = variant.field { list ->
                            val count = list.u64()
                            require(count in BigInteger.ONE..BigInteger.valueOf(4)) { "app policy signer set must hold 1-4 digests" }
                            List(count.toInt()) { list.field { it.byteArray(32) } }
                        }
                        Identity.Android(name, minimum, signers)
                    }
                    2L -> Identity.Apple(variant.field { it.string() })
                    else -> throw IllegalArgumentException("unknown app identity discriminant")
                }
            }
            reader.finish()
            val policy = KagemushaWalletAppPolicyV1(scheme, identity)
            policy.validate()
            require(policy.encodeCanonical().contentEquals(frame)) { "app policy original is not canonical" }
            return policy
        }
    }

    private fun validate() {
        require(scheme.any { it != 0.toByte() }) { "app policy scheme must be nonzero" }
        when (val selected = identity) {
            is Identity.Android -> {
                require(kagemushaAndroidPackageValid(selected.packageName)) { "invalid app policy package name" }
                val signers = selected.signersOriginal()
                require(signers.size in 1..4 && signers.all { signer -> signer.any { it != 0.toByte() } } &&
                    signers.zipWithNext().all { (low, high) -> unsignedCompare(low, high) < 0 }) { "invalid app policy signer set" }
            }
            is Identity.Apple -> {
                val bytes = selected.appId.toByteArray(Charsets.UTF_8).size
                require(bytes in 1..255) { "invalid app policy App ID" }
            }
        }
    }
}

/**
 * The exact canonical `KagemushaWalletEnrollmentPolicyV1` original: the platform verification
 * inputs an E1 challenge names by its `H("enrollment-policy", transcript)` digest. The Android
 * arm pins a root set whose entries each name a revocation source and the patch floor; no arm
 * carries a hardware selector or a vendor online verdict. Selected DATA only, never an approval.
 */
class KagemushaWalletEnrollmentPolicyV1 private constructor(
    schemeId: ByteArray,
    assetDigest: ByteArray,
    appPolicyDigest: ByteArray,
    @JvmField val platform: Platform,
    @JvmField val permittedControls: Long,
    @JvmField val timeAnchorMaxResponseMs: BigInteger,
    @JvmField val challengeLifetimeMs: BigInteger,
    @JvmField val attestationLeaseLifetimeMs: BigInteger,
) {
    private val scheme = schemeId.copyOf()
    private val asset = assetDigest.copyOf()
    private val app = appPolicyDigest.copyOf()

    /** Exactly one platform verifier input set. */
    sealed class Platform {
        /** Pinned roots, strictly ascending by SPKI digest, and the patch floor (tag 1). */
        class Android internal constructor(roots: List<Root>, @JvmField val patchFloorYyyymm: Long) : Platform() {
            private val rootSet = roots.toList()

            /** The 1-8 pinned roots. */
            fun roots(): List<Root> = rootSet.toList()
        }

        /** SHA-256 pin of the genuine selected Apple App Attestation root DER (tag 2). */
        class Apple internal constructor(attestationRootSha256: ByteArray) : Platform() {
            private val pin = attestationRootSha256.copyOf()

            /** The nonzero root DER pin. */
            fun attestationRootSha256(): ByteArray = pin.copyOf()

            internal fun pinOriginal(): ByteArray = pin
        }
    }

    /** One pinned Android root and the revocation source it names. */
    class Root internal constructor(
        @JvmField val family: AndroidAttestationE1RootV1.Family,
        @JvmField val adapterId: String?,
        spkiSha256: ByteArray,
        @JvmField val revocationSource: RevocationSource,
    ) {
        private val spki = spkiSha256.copyOf()

        /** SHA-256 of the root certificate's DER `SubjectPublicKeyInfo`. */
        fun spkiSha256(): ByteArray = spki.copyOf()

        internal fun spkiOriginal(): ByteArray = spki
    }

    /** Revocation source of one root; the operator denylist is checked for every root. */
    enum class RevocationSource(@JvmField val tag: Int) {
        /** Google's attestation status list; required by both Google families. */
        GOOGLE_ATTESTATION_STATUS(1),

        /** The operator denylist only; required by Vendor roots. */
        OPERATOR_DENYLIST(2),
    }

    fun schemeId(): ByteArray = scheme.copyOf()

    fun assetDigest(): ByteArray = asset.copyOf()

    /** The exact app-policy digest this enrollment policy selects. */
    fun appPolicyDigest(): ByteArray = app.copyOf()

    /** Exact transcript: Android is `132 + Σ root entries` bytes, Apple exactly 159. */
    fun transcript(): ByteArray {
        val out = PolicyTranscript().u16(VERSION).bytes(scheme).bytes(asset).bytes(app)
        when (val selected = platform) {
            is Platform.Android -> {
                out.u8(1).u8(selected.roots().size)
                for (root in selected.roots()) {
                    out.u8(root.family.tag)
                    root.adapterId?.let { out.text(it) }
                    out.bytes(root.spkiOriginal()).u8(root.revocationSource.tag)
                }
                out.u32(selected.patchFloorYyyymm)
            }
            is Platform.Apple -> out.u8(2).bytes(selected.pinOriginal())
        }
        return out.u32(permittedControls).u64(timeAnchorMaxResponseMs)
            .u64(challengeLifetimeMs).u64(attestationLeaseLifetimeMs).finish()
    }

    /** `H("enrollment-policy", transcript)`, the digest an E1 challenge names. Grants no authority. */
    fun policyDigest(): ByteArray = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ENROLLMENT_POLICY, transcript())

    /**
     * The Android admission inputs of this enrollment policy paired with [appPolicy]: the scheme
     * and app-policy digest must match and both policies must be Android policies.
     *
     * @throws IllegalArgumentException for any substitution.
     */
    fun androidAdmission(appPolicy: KagemushaWalletAppPolicyV1): AndroidAttestationE1PolicyV1 {
        require(MessageDigest.isEqual(scheme, appPolicy.schemeId())) { "enrollment and app policy schemes differ" }
        require(MessageDigest.isEqual(app, appPolicy.policyDigest())) { "enrollment policy names a different app policy" }
        val identity = appPolicy.identity as? KagemushaWalletAppPolicyV1.Identity.Android
            ?: throw IllegalArgumentException("app policy is not an Android policy")
        val android = platform as? Platform.Android ?: throw IllegalArgumentException("enrollment policy is not an Android policy")
        return AndroidAttestationE1PolicyV1(
            identity.packageName, identity.minimumPackageVersion, identity.signerSet(),
            android.roots().map { AndroidAttestationE1RootV1(it.family, it.spkiOriginal(), it.adapterId) },
        )
    }

    /** The canonical Norito frame of this policy. */
    fun encodeCanonical(): ByteArray {
        val payload = NoritoFields()
        payload.field { it.u16(VERSION) }
        payload.field { it.raw(scheme) }
        payload.field { it.raw(asset) }
        payload.field { it.raw(app) }
        payload.field { variant ->
            when (val selected = platform) {
                is Platform.Android -> {
                    variant.u32(1)
                    variant.field { list ->
                        list.u64(BigInteger.valueOf(selected.roots().size.toLong()))
                        for (root in selected.roots()) list.field { entry ->
                            entry.field { family ->
                                family.u32(root.family.tag.toLong())
                                root.adapterId?.let { id -> family.field { it.string(id) } }
                            }
                            entry.field { it.raw(root.spkiOriginal()) }
                            entry.field { it.u32(root.revocationSource.tag.toLong()) }
                        }
                    }
                    variant.field { it.u32(selected.patchFloorYyyymm) }
                }
                is Platform.Apple -> {
                    variant.u32(2)
                    variant.field { it.raw(selected.pinOriginal()) }
                }
            }
        }
        payload.field { regulatory ->
            regulatory.field { it.u32(permittedControls) }
            regulatory.field { it.u64(timeAnchorMaxResponseMs) }
        }
        payload.field { it.u64(challengeLifetimeMs) }
        payload.field { it.u64(attestationLeaseLifetimeMs) }
        return frame(ENROLLMENT_POLICY_SCHEMA, payload.finish())
    }

    override fun toString(): String = "KagemushaWalletEnrollmentPolicyV1(${platform.javaClass.simpleName})"

    private fun validate() {
        require(scheme.any { it != 0.toByte() } && asset.any { it != 0.toByte() } && app.any { it != 0.toByte() }) {
            "enrollment policy scheme, asset and app policy must be nonzero"
        }
        // Regulatory consistency (Rust KagemushaWalletRegulatoryPolicyV1::validate).
        require(permittedControls and DEFINED_CONTROLS.inv() == 0L) { "undefined regulatory control" }
        val timeDependent = permits(CONTROL_QUOTAS) || permits(CONTROL_ATTESTATION_LEASE)
        require((timeAnchorMaxResponseMs.signum() > 0) == timeDependent) { "time-anchor bound inconsistent with permitted rules" }
        require(challengeLifetimeMs.signum() > 0) { "challenge lifetime must be positive" }
        require((attestationLeaseLifetimeMs.signum() > 0) == permits(CONTROL_ATTESTATION_LEASE)) {
            "lease lifetime is positive exactly when the lease control is permitted"
        }
        when (val selected = platform) {
            is Platform.Android -> {
                val roots = selected.roots()
                require(roots.size in 1..8 && roots.zipWithNext().all { (low, high) ->
                    unsignedCompare(low.spkiOriginal(), high.spkiOriginal()) < 0
                }) { "invalid Android root set" }
                for (root in roots) {
                    require(root.spkiOriginal().any { it != 0.toByte() }) { "root SPKI pin must be nonzero" }
                    val vendor = root.family == AndroidAttestationE1RootV1.Family.VENDOR
                    require(!vendor || kagemushaAdapterIdValid(root.adapterId ?: "")) { "invalid Vendor adapter identifier" }
                    require(root.revocationSource == if (vendor) RevocationSource.OPERATOR_DENYLIST else RevocationSource.GOOGLE_ATTESTATION_STATUS) {
                        "root revocation source does not match its family"
                    }
                }
                val year = selected.patchFloorYyyymm / 100
                val month = selected.patchFloorYyyymm % 100
                require(year in 1900..9999 && month in 1..12) { "invalid patch floor" }
            }
            is Platform.Apple -> require(selected.pinOriginal().any { it != 0.toByte() }) { "Apple root pin must be nonzero" }
        }
    }

    private fun permits(control: Long): Boolean = permittedControls and control == control

    companion object {
        /** Canonical Rust type name; its Norito schema hash heads every frame. */
        const val SCHEMA_NAME: String = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnrollmentPolicyV1"
        private val ENROLLMENT_POLICY_SCHEMA: ByteArray = SchemaHash.hash16(SCHEMA_NAME)
        private const val CONTROL_QUOTAS = 1L
        private const val CONTROL_ATTESTATION_LEASE = 2L
        private const val DEFINED_CONTROLS = CONTROL_QUOTAS or CONTROL_ATTESTATION_LEASE

        /**
         * Decode one canonical original under the 1,024-byte frame cap.
         *
         * @throws IllegalArgumentException for an oversized, noncanonical, wrong-version or
         * structurally invalid original.
         */
        @JvmStatic
        fun decodeCanonical(original: ByteArray): KagemushaWalletEnrollmentPolicyV1 {
            val frame = original.copyOf()
            val reader = NoritoReader(payload(ENROLLMENT_POLICY_SCHEMA, frame))
            reader.field { require(it.u16() == VERSION) { "enrollment policy version must be 1" } }
            val scheme = reader.field { it.raw(32) }
            val asset = reader.field { it.raw(32) }
            val app = reader.field { it.raw(32) }
            val platform = reader.field { variant ->
                when (variant.u32()) {
                    1L -> {
                        val roots = variant.field { list ->
                            val count = list.u64()
                            require(count in BigInteger.ONE..BigInteger.valueOf(8)) { "Android root set must hold 1-8 roots" }
                            List(count.toInt()) {
                                list.field { entry ->
                                    var adapter: String? = null
                                    val family = entry.field { family ->
                                        when (family.u32()) {
                                            1L -> AndroidAttestationE1RootV1.Family.GOOGLE_RSA
                                            2L -> AndroidAttestationE1RootV1.Family.GOOGLE_CA1
                                            3L -> { adapter = family.field { it.string() }; AndroidAttestationE1RootV1.Family.VENDOR }
                                            else -> throw IllegalArgumentException("unknown Android root family")
                                        }
                                    }
                                    val spki = entry.field { it.raw(32) }
                                    val source = entry.field { source ->
                                        val tag = source.u32()
                                        RevocationSource.entries.firstOrNull { it.tag.toLong() == tag }
                                            ?: throw IllegalArgumentException("unknown revocation source")
                                    }
                                    Root(family, adapter, spki, source)
                                }
                            }
                        }
                        Platform.Android(roots, variant.field { it.u32() })
                    }
                    2L -> Platform.Apple(variant.field { it.raw(32) })
                    else -> throw IllegalArgumentException("unknown enrollment platform discriminant")
                }
            }
            val permitted = reader.field { regulatory ->
                Pair(regulatory.field { it.u32() }, regulatory.field { it.u64() })
            }
            val challengeLifetime = reader.field { it.u64() }
            val leaseLifetime = reader.field { it.u64() }
            reader.finish()
            val policy = KagemushaWalletEnrollmentPolicyV1(
                scheme, asset, app, platform, permitted.first, permitted.second, challengeLifetime, leaseLifetime,
            )
            policy.validate()
            require(policy.encodeCanonical().contentEquals(frame)) { "enrollment policy original is not canonical" }
            return policy
        }
    }
}

/** Version of both NEW policies. */
private const val VERSION = 1

/** NEW complete-frame cap of both policies. */
private const val POLICY_FRAME_MAX_BYTES = 1024
private val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

/** Header checks of one canonical policy frame: cap, magic, version, schema, no compression, CRC64, COMPACT_LEN. */
private fun payload(schema: ByteArray, frame: ByteArray): ByteArray {
    require(frame.size in NoritoHeader.HEADER_LENGTH..POLICY_FRAME_MAX_BYTES) { "policy frame outside the 1024-byte cap" }
    val decoded = NoritoHeader.decode(frame, schema)
    require(decoded.header.compression == NoritoHeader.COMPRESSION_NONE && decoded.header.flags == NoritoHeader.COMPACT_LEN &&
        decoded.payload.size == frame.size - NoritoHeader.HEADER_LENGTH) { "policy frame header is not canonical" }
    decoded.header.validateChecksum(decoded.payload)
    return decoded.payload
}

private fun frame(schema: ByteArray, payload: ByteArray): ByteArray {
    val header = NoritoHeader(schema, payload.size, CRC64.compute(payload), NoritoHeader.COMPACT_LEN, NoritoHeader.COMPRESSION_NONE)
    val frame = header.encode() + payload
    check(frame.size <= POLICY_FRAME_MAX_BYTES) { "policy frame exceeds the 1024-byte cap" }
    return frame
}

/** Strict reader of the COMPACT_LEN struct layout: every field is a canonical varint length and its exact bytes. */
private class NoritoReader(private val data: ByteArray) {
    private var offset = 0

    fun <T> field(read: (NoritoReader) -> T): T {
        val decoded = Varint.decode(data, offset)
        require(decoded.value in 0..(data.size - decoded.nextOffset).toLong()) { "policy field overruns its container" }
        val end = decoded.nextOffset + decoded.value.toInt()
        val inner = NoritoReader(data.copyOfRange(decoded.nextOffset, end))
        val value = read(inner)
        inner.finish()
        offset = end
        return value
    }

    private fun take(count: Int): ByteArray {
        require(count in 0..(data.size - offset)) { "truncated policy field" }
        return data.copyOfRange(offset, offset + count).also { offset += count }
    }

    private fun little(count: Int): BigInteger = BigInteger(1, take(count).reversedArray())

    fun u16(): Int = little(2).toInt()

    fun u32(): Long = little(4).toLong()

    fun u64(): BigInteger = little(8)

    fun raw(count: Int): ByteArray = take(count)

    /** `[u8; N]` inside a sequence: every element is a length-1 field. */
    fun byteArray(count: Int): ByteArray = ByteArray(count) { field { it.raw(1)[0] } }

    fun string(): String {
        val decoded = Varint.decode(data, offset)
        require(decoded.value in 0..(data.size - decoded.nextOffset).toLong()) { "policy text overruns its field" }
        offset = decoded.nextOffset
        val bytes = take(decoded.value.toInt())
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    }

    fun finish() = require(offset == data.size) { "trailing policy bytes" }
}

/** Writer of the same COMPACT_LEN struct layout. */
private class NoritoFields {
    private val out = ByteArrayOutputStream()

    fun field(write: (NoritoFields) -> Unit) {
        val inner = NoritoFields()
        write(inner)
        val bytes = inner.finish()
        out.write(Varint.encode(bytes.size.toLong()))
        out.write(bytes)
    }

    private fun little(value: BigInteger, count: Int) {
        require(value.signum() >= 0 && value.bitLength() <= count * 8)
        for (index in 0 until count) out.write(value.shiftRight(8 * index).toInt() and 0xff)
    }

    fun u16(value: Int) = little(BigInteger.valueOf(value.toLong()), 2)

    fun u32(value: Long) = little(BigInteger.valueOf(value), 4)

    fun u64(value: BigInteger) = little(value, 8)

    fun raw(bytes: ByteArray) = out.write(bytes)

    fun byteArray(bytes: ByteArray) = bytes.forEach { byte -> field { it.raw(byteArrayOf(byte)) } }

    fun string(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        out.write(Varint.encode(bytes.size.toLong()))
        out.write(bytes)
    }

    fun finish(): ByteArray = out.toByteArray()
}

/** Little-endian policy transcript writer (`WalletTranscriptV1`). */
private class PolicyTranscript {
    private val out = ByteArrayOutputStream()

    private fun little(value: BigInteger, count: Int): PolicyTranscript {
        require(value.signum() >= 0 && value.bitLength() <= count * 8)
        for (index in 0 until count) out.write(value.shiftRight(8 * index).toInt() and 0xff)
        return this
    }

    fun u8(value: Int) = little(BigInteger.valueOf(value.toLong()), 1)

    fun u16(value: Int) = little(BigInteger.valueOf(value.toLong()), 2)

    fun u32(value: Long) = little(BigInteger.valueOf(value), 4)

    fun u64(value: BigInteger): PolicyTranscript {
        require(value <= U64_MAX)
        return little(value, 8)
    }

    fun bytes(value: ByteArray): PolicyTranscript = apply { out.write(value) }

    /** `LE32(UTF-8 byte length) || UTF-8 bytes`. */
    fun text(value: String): PolicyTranscript {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return u32(bytes.size.toLong()).bytes(bytes)
    }

    fun finish(): ByteArray = out.toByteArray()
}

private fun unsignedCompare(left: ByteArray, right: ByteArray): Int {
    for (index in 0 until minOf(left.size, right.size)) {
        val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
        if (difference != 0) return difference
    }
    return left.size - right.size
}
