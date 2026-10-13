package org.hyperledger.iroha.sdk.core.model.instructions

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Arrays
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.numeric.KotodamaQuantity
import org.hyperledger.iroha.sdk.numeric.NumericV1Codec

private const val PROOF_BOX_MAX_ENCODED_BYTES: Long = 64L * 1024L * 1024L
private val LOW_ORDER_X25519_CHECK_PRIVATE_KEY = ByteArray(32) { 1 }

/**
 * X25519/XChaCha20-Poly1305 encrypted confidential-note payload.
 *
 * Ciphertext is capped at [MAX_CIPHERTEXT_BYTES] because the encrypted payload
 * is a compact note descriptor, not an arbitrary attachment channel.
 */
class ConfidentialEncryptedPayload @JvmOverloads constructor(
    version: Int = VERSION_V1,
    ephemeralPublicKey: ByteArray,
    nonce: ByteArray,
    ciphertext: ByteArray,
) {
    private val _ephemeralPublicKey = fixedBytes(ephemeralPublicKey, 32, "ephemeralPublicKey")
    private val _nonce = fixedBytes(nonce, 24, "nonce")
    private val _ciphertext = copyNonEmpty(ciphertext, "ciphertext")

    @JvmField
    val version: Int = version

    init {
        require(version == VERSION_V1) { "version must be $VERSION_V1" }
        require(_ciphertext.size <= MAX_CIPHERTEXT_BYTES) {
            "ciphertext must not exceed $MAX_CIPHERTEXT_BYTES bytes"
        }
        require(!isLowOrderX25519PublicKey(_ephemeralPublicKey)) {
            "ephemeralPublicKey must not be low-order"
        }
    }

    val ephemeralPublicKey: ByteArray get() = _ephemeralPublicKey.copyOf()

    val nonce: ByteArray get() = _nonce.copyOf()

    val ciphertext: ByteArray get() = _ciphertext.copyOf()

    fun ephemeralPublicKeyBytes(): ByteArray = ephemeralPublicKey

    fun nonceBytes(): ByteArray = nonce

    fun ciphertextBytes(): ByteArray = ciphertext

    fun toWireBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(version)
        out.write(_ephemeralPublicKey)
        out.write(_nonce)
        writeCompactVarint(_ciphertext.size, out)
        out.write(_ciphertext)
        return out.toByteArray()
    }

    fun wireBytes(): ByteArray = toWireBytes()

    override fun equals(other: Any?): Boolean =
        other is ConfidentialEncryptedPayload &&
            version == other.version &&
            _ephemeralPublicKey.contentEquals(other._ephemeralPublicKey) &&
            _nonce.contentEquals(other._nonce) &&
            _ciphertext.contentEquals(other._ciphertext)

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + _ephemeralPublicKey.contentHashCode()
        result = 31 * result + _nonce.contentHashCode()
        result = 31 * result + _ciphertext.contentHashCode()
        return result
    }

    companion object {
        const val VERSION_V1: Int = 1
        const val MAX_CIPHERTEXT_BYTES: Int = 64 * 1024

        @JvmStatic
        fun fromWireBytes(bytes: ByteArray?): ConfidentialEncryptedPayload {
            require(bytes != null) { "bytes must be provided" }
            require(bytes.size >= 1 + 32 + 24) { "confidential encrypted payload is truncated" }
            val version = bytes[0].toInt() and 0xff
            val ephemeral = bytes.copyOfRange(1, 33)
            val nonce = bytes.copyOfRange(33, 57)
            val (ciphertextLength, lengthBytes) = readCompactVarint(bytes, 57)
            require(ciphertextLength <= MAX_CIPHERTEXT_BYTES) {
                "ciphertext must not exceed $MAX_CIPHERTEXT_BYTES bytes"
            }
            val ciphertextStart = 57 + lengthBytes
            val ciphertextEnd = ciphertextStart + ciphertextLength
            require(ciphertextEnd <= bytes.size) { "confidential encrypted payload ciphertext is truncated" }
            require(ciphertextEnd == bytes.size) { "confidential encrypted payload has trailing bytes" }
            return ConfidentialEncryptedPayload(
                version,
                ephemeral,
                nonce,
                bytes.copyOfRange(ciphertextStart, ciphertextEnd),
            )
        }

        @JvmStatic
        fun decodeWire(bytes: ByteArray?): ConfidentialEncryptedPayload = fromWireBytes(bytes)
    }
}

/** Reference to a registered verifier key used by a proof attachment. */
class ProofVerifierKeyRef(
    backend: String,
    name: String,
) {
    @JvmField
    val backend: String = requirePortableComponent(backend, "backend")

    @JvmField
    val name: String = requirePortableComponent(name, "name")

    fun wireId(): String = "$backend:$name"

    override fun equals(other: Any?): Boolean =
        other is ProofVerifierKeyRef && backend == other.backend && name == other.name

    override fun hashCode(): Int = 31 * backend.hashCode() + name.hashCode()

    companion object {
        @JvmStatic
        fun fromWireId(wireId: String?): ProofVerifierKeyRef {
            val normalized = requireText(wireId, "verifyingKeyId")
            val split = normalized.indexOf(':')
            require(split > 0 && split < normalized.length - 1) {
                "verifyingKeyId must use backend:name syntax"
            }
            return ProofVerifierKeyRef(
                normalized.substring(0, split),
                normalized.substring(split + 1),
            )
        }
    }
}

/** Complete Merkle witness used by a Nexus lane privacy proof. */
class LanePrivacyMerkleWitness(
    leaf: ByteArray,
    @JvmField val leafIndex: Long,
    auditPath: List<ByteArray>,
) {
    private val _leaf = fixedBytes(leaf, 32, "leaf")
    private val _auditPath: List<ByteArray>

    init {
        require(leafIndex in 0L..0xffff_ffffL) { "leafIndex must fit in u32" }
        require(auditPath.size in 1..MAX_DEPTH) {
            "auditPath must contain between 1 and $MAX_DEPTH siblings"
        }
        require(auditPath.size >= 32 || leafIndex < (1L shl auditPath.size)) {
            "leafIndex cannot fit the supplied Merkle path depth"
        }
        _auditPath = auditPath.mapIndexed { index, sibling ->
            val canonical = fixedBytes(sibling, 32, "auditPath[$index]")
            canonical[canonical.lastIndex] = (canonical.last().toInt() or 1).toByte()
            canonical
        }
    }

    val leaf: ByteArray get() = _leaf.copyOf()

    val auditPath: List<ByteArray> get() = _auditPath.map { it.copyOf() }

    fun leafBytes(): ByteArray = leaf

    fun auditPathBytes(): List<ByteArray> = auditPath

    override fun equals(other: Any?): Boolean =
        other is LanePrivacyMerkleWitness &&
            leafIndex == other.leafIndex &&
            _leaf.contentEquals(other._leaf) &&
            _auditPath.size == other._auditPath.size &&
            _auditPath.indices.all { _auditPath[it].contentEquals(other._auditPath[it]) }

    override fun hashCode(): Int {
        var result = _leaf.contentHashCode()
        result = 31 * result + leafIndex.hashCode()
        for (sibling in _auditPath) result = 31 * result + sibling.contentHashCode()
        return result
    }

    companion object {
        /** Maximum first-release Merkle audit-path depth. */
        const val MAX_DEPTH: Int = 255
    }
}

/** Canonical first-release lane privacy witness variants. */
sealed class LanePrivacyWitness private constructor() {
    /** Merkle membership witness. */
    class Merkle(@JvmField val value: LanePrivacyMerkleWitness) : LanePrivacyWitness() {
        override fun equals(other: Any?): Boolean = other is Merkle && value == other.value

        override fun hashCode(): Int = value.hashCode()
    }

    companion object {
        @JvmStatic
        fun merkle(value: LanePrivacyMerkleWitness): LanePrivacyWitness = Merkle(value)
    }
}

/** Proof payload bound to a registered Nexus lane commitment. */
class LanePrivacyProof(
    @JvmField val commitmentId: Int,
    @JvmField val witness: LanePrivacyWitness,
) {
    init {
        require(commitmentId in 0..0xffff) { "commitmentId must fit in u16" }
    }

    override fun equals(other: Any?): Boolean =
        other is LanePrivacyProof && commitmentId == other.commitmentId && witness == other.witness

    override fun hashCode(): Int = 31 * commitmentId + witness.hashCode()
}

/** JSON-serializable proof attachment accepted by native zk transaction encoders. */
class ProofAttachment(
    backend: String,
    proofBytes: ByteArray,
    verifyingKeyRef: ProofVerifierKeyRef,
    verifyingKeyCommitment: ByteArray? = null,
    envelopeHash: ByteArray? = null,
    @JvmField val lanePrivacy: LanePrivacyProof? = null,
) {
    @JvmField
    val backend: String = requirePortableComponent(backend, "backend")

    private val _proofBytes: ByteArray

    @JvmField
    val verifyingKeyRef: ProofVerifierKeyRef = verifyingKeyRef

    private val _verifyingKeyCommitment = verifyingKeyCommitment?.let {
        fixedNonZeroBytes(it, 32, "verifyingKeyCommitment")
    }
    private val _envelopeHash = envelopeHash?.let { fixedBytes(it, 32, "envelopeHash") }

    init {
        require(proofBytes.isNotEmpty()) { "proofBytes must not be empty" }
        val proofBoxLength = canonicalProofBoxEncodedLength(
            this.backend.toByteArray(StandardCharsets.UTF_8).size.toLong(),
            proofBytes.size.toLong(),
        )
        require(proofBoxLength <= PROOF_BOX_MAX_ENCODED_BYTES) {
            "encoded ProofBox must not exceed $PROOF_BOX_MAX_ENCODED_BYTES bytes"
        }
        _proofBytes = proofBytes.copyOf()
        require(verifyingKeyRef.backend == this.backend) {
            "verifyingKeyRef.backend must match backend"
        }
        require(
            _envelopeHash == null ||
                _envelopeHash.contentEquals(IrohaHash.prehash(_proofBytes)),
        ) {
            "envelopeHash must match proofBytes"
        }
    }

    internal val proofByteCount: Int get() = _proofBytes.size

    val proofBytes: ByteArray get() = _proofBytes.copyOf()

    val verifyingKeyCommitment: ByteArray? get() = _verifyingKeyCommitment?.copyOf()

    val envelopeHash: ByteArray? get() = _envelopeHash?.copyOf()

    fun proofBytes(): ByteArray = proofBytes

    fun verifyingKeyCommitmentBytes(): ByteArray? = verifyingKeyCommitment

    fun envelopeHashBytes(): ByteArray? = envelopeHash

    fun toNativeJson(): String = buildString {
        append('{')
        append("\"backend\":")
        appendJsonString(backend)
        append(",\"proof_b64\":")
        appendJsonString(Base64.getEncoder().encodeToString(_proofBytes))
        append(",\"vk_ref\":{\"backend\":")
        appendJsonString(verifyingKeyRef.backend)
        append(",\"name\":")
        appendJsonString(verifyingKeyRef.name)
        append('}')
        _verifyingKeyCommitment?.let {
            append(",\"vk_commitment_hex\":")
            appendJsonString(hexLower(it))
        }
        append(",\"envelope_hash_hex\":")
        appendJsonString(hexLower(_envelopeHash ?: IrohaHash.prehash(_proofBytes)))
        lanePrivacy?.let {
            append(",\"lane_privacy\":")
            appendLanePrivacyJson(it)
        }
        append('}')
    }

    override fun equals(other: Any?): Boolean =
        other is ProofAttachment &&
            backend == other.backend &&
            _proofBytes.contentEquals(other._proofBytes) &&
            verifyingKeyRef == other.verifyingKeyRef &&
            nullableContentEquals(_verifyingKeyCommitment, other._verifyingKeyCommitment) &&
            nullableContentEquals(_envelopeHash, other._envelopeHash) &&
            lanePrivacy == other.lanePrivacy

    override fun hashCode(): Int {
        var result = backend.hashCode()
        result = 31 * result + _proofBytes.contentHashCode()
        result = 31 * result + verifyingKeyRef.hashCode()
        result = 31 * result + (_verifyingKeyCommitment?.contentHashCode() ?: 0)
        result = 31 * result + (_envelopeHash?.contentHashCode() ?: 0)
        result = 31 * result + (lanePrivacy?.hashCode() ?: 0)
        return result
    }

    companion object {
        /** Maximum canonical encoded size of the nested Rust `ProofBox`. */
        const val MAXIMUM_ENCODED_PROOF_BOX_BYTES: Long = PROOF_BOX_MAX_ENCODED_BYTES

        /** Calculate the complete encoded `ProofBox` length without allocating proof bytes. */
        @JvmStatic
        fun canonicalProofBoxEncodedLength(
            backendUtf8ByteCount: Long,
            proofByteCount: Long,
        ): Long {
            require(backendUtf8ByteCount >= 0L) { "backendUtf8ByteCount must be non-negative" }
            require(proofByteCount >= 0L) { "proofByteCount must be non-negative" }
            return try {
                val backendValueLength = Math.addExact(
                    compactLengthPrefixBytes(backendUtf8ByteCount),
                    backendUtf8ByteCount,
                )
                val backendFieldLength = Math.addExact(
                    compactLengthPrefixBytes(backendValueLength),
                    backendValueLength,
                )
                val proofValueLength = Math.addExact(8L, proofByteCount)
                val proofFieldLength = Math.addExact(
                    compactLengthPrefixBytes(proofValueLength),
                    proofValueLength,
                )
                Math.addExact(backendFieldLength, proofFieldLength)
            } catch (error: ArithmeticException) {
                throw IllegalArgumentException(
                    "encoded ProofBox length overflows the supported range",
                    error,
                )
            }
        }

        private fun compactLengthPrefixBytes(value: Long): Long {
            var remaining = value
            var bytes = 1L
            while (remaining >= 0x80L) {
                remaining = remaining ushr 7
                bytes++
            }
            return bytes
        }
    }
}

/** Typed representation of `zk::RegisterZkAsset`. */
class RegisterZkAssetInstruction private constructor(
    @JvmField val asset: String,
    @JvmField val unshieldVerifyingKey: String?,
    override val arguments: Map<String, String>,
) : InstructionTemplate {
    override val kind: InstructionKind get() = InstructionKind.REGISTER

    class Builder internal constructor() {
        private var asset: String? = null
        private var unshieldVerifyingKey: String? = null

        fun setAsset(asset: String?) = apply {
            this.asset = requireText(asset, "asset")
        }

        fun setUnshieldVerifyingKey(verifyingKey: String?) = apply {
            this.unshieldVerifyingKey = optionalVerifyingKeyId(verifyingKey, "unshieldVerifyingKey")
        }

        fun build(): RegisterZkAssetInstruction {
            val selectedAsset = checkNotNull(asset) { "asset must be provided" }
            return RegisterZkAssetInstruction(
                selectedAsset,
                unshieldVerifyingKey,
                linkedMapOf(
                    "action" to "RegisterZkAsset",
                    "asset" to selectedAsset,
                    "vk_unshield" to (unshieldVerifyingKey ?: ""),
                ),
            )
        }
    }

    companion object {
        @JvmStatic
        fun builder(): Builder = Builder()

        @JvmStatic
        fun fromArguments(arguments: Map<String, String>): RegisterZkAssetInstruction {
            val allowedArguments = setOf(
                "action",
                "asset",
                "vk_unshield",
            )
            val unknownArguments = arguments.keys - allowedArguments
            require(unknownArguments.isEmpty()) {
                "Unknown instruction argument(s): ${unknownArguments.sorted().joinToString()}"
            }
            val builder = builder()
                .setAsset(requireArgument(arguments, "asset"))
            optionalArgument(arguments, "vk_unshield")?.let { builder.setUnshieldVerifyingKey(it) }
            return builder.build()
        }

        private fun requireArgument(arguments: Map<String, String>, key: String): String {
            val value = arguments[key]
            require(!value.isNullOrBlank()) { "Instruction argument '$key' is required" }
            return value
        }

        private fun optionalArgument(arguments: Map<String, String>, key: String): String? =
            arguments[key]?.takeIf { it.isNotBlank() }

    }
}

internal fun requireText(value: String?, name: String): String {
    require(value != null) { "$name must be provided" }
    val trimmed = value.trim()
    require(trimmed.isNotEmpty()) { "$name must not be blank" }
    require(trimmed == value) { "$name must not contain surrounding whitespace" }
    require(trimmed.indexOf('\u0000') < 0) { "$name must not contain NUL" }
    return trimmed
}

private fun requirePortableComponent(value: String?, name: String): String {
    val text = requireText(value, name)
    val bytes = text.toByteArray(StandardCharsets.UTF_8)
    require(bytes.size <= 256) { "$name must not exceed 256 UTF-8 bytes" }
    require(bytes.first().isPortableVerifierEndpoint() && bytes.last().isPortableVerifierEndpoint()) {
        "$name must start and end with a lowercase ASCII letter or digit"
    }
    require(bytes.all { it.isPortableVerifierByte() }) {
        "$name must use lowercase ASCII letters, digits, '-', '_', '/', ':', or '.'"
    }
    require(PORTABLE_VERIFIER_FORBIDDEN_SEPARATORS.none { separator -> text.contains(separator) }) {
        "$name contains a non-canonical separator sequence"
    }
    return text
}

private val PORTABLE_VERIFIER_FORBIDDEN_SEPARATORS =
    listOf("..", "//", ":::", "/:", ":/", "/.", "./", ":.", ".:")

private fun Byte.isPortableVerifierEndpoint(): Boolean {
    val value = toInt() and 0xff
    return value in 'a'.code..'z'.code || value in '0'.code..'9'.code
}

private fun Byte.isPortableVerifierByte(): Boolean {
    val value = toInt() and 0xff
    return isPortableVerifierEndpoint() ||
        value == '-'.code || value == '_'.code || value == '/'.code ||
        value == ':'.code || value == '.'.code
}

private fun optionalVerifyingKeyId(value: String?, name: String): String? {
    if (value == null) return null
    val text = requireText(value, name)
    ProofVerifierKeyRef.fromWireId(text)
    return text
}

private fun canonicalQuantity(value: String?, name: String): String {
    val text = requireText(value, name)
    return try {
        NumericV1Codec.decodeQuantityJson(text).toString()
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("$name must be a canonical non-negative V1 quantity", error)
    }
}

private fun fixedBytes(value: ByteArray?, expected: Int, name: String): ByteArray {
    require(value != null) { "$name must be provided" }
    require(value.size == expected) { "$name must be exactly $expected bytes" }
    return value.copyOf()
}

private fun fixedNonZeroBytes(value: ByteArray?, expected: Int, name: String): ByteArray {
    val bytes = fixedBytes(value, expected, name)
    require(!isAllZero(bytes)) { "$name must not be all zero" }
    return bytes
}

private fun copyNonEmpty(value: ByteArray?, name: String): ByteArray {
    require(value != null) { "$name must be provided" }
    require(value.isNotEmpty()) { "$name must not be empty" }
    return value.copyOf()
}

private fun isAllZero(bytes: ByteArray): Boolean = bytes.all { it.toInt() == 0 }

private fun isLowOrderX25519PublicKey(publicKey: ByteArray): Boolean {
    val peer = X25519PublicKeyParameters(fixedBytes(publicKey, 32, "ephemeralPublicKey"), 0)
    val probe = X25519PrivateKeyParameters(LOW_ORDER_X25519_CHECK_PRIVATE_KEY, 0)
    val agreement = X25519Agreement()
    val shared = ByteArray(32)
    return try {
        agreement.init(probe)
        agreement.calculateAgreement(peer, shared, 0)
        isAllZero(shared)
    } catch (_: IllegalStateException) {
        true
    } finally {
        Arrays.fill(shared, 0.toByte())
    }
}

internal fun flattenFixed32(values: List<ByteArray>): ByteArray {
    val out = ByteArray(values.size * 32)
    values.forEachIndexed { index, value ->
        require(value.size == 32) { "value[$index] must be exactly 32 bytes" }
        System.arraycopy(value, 0, out, index * 32, 32)
    }
    return out
}

internal fun optionalBytes(value: ByteArray?): ByteArray = value?.copyOf() ?: ByteArray(0)

private fun writeCompactVarint(value: Int, out: ByteArrayOutputStream) {
    require(value >= 0) { "compact varint value must be non-negative" }
    var remaining = value
    while (true) {
        var byte = remaining and 0x7f
        remaining = remaining ushr 7
        if (remaining != 0) byte = byte or 0x80
        out.write(byte)
        if (remaining == 0) return
    }
}

private fun readCompactVarint(bytes: ByteArray, offset: Int): Pair<Int, Int> {
    var value = 0
    var shift = 0
    var cursor = offset
    while (cursor < bytes.size && shift < 28) {
        val byte = bytes[cursor].toInt() and 0xff
        value = value or ((byte and 0x7f) shl shift)
        cursor += 1
        if (byte and 0x80 == 0) {
            val encodedBytes = cursor - offset
            require(encodedBytes == 1 || value >= (1 shl (7 * (encodedBytes - 1)))) {
                "non-canonical confidential encrypted payload length"
            }
            return value to encodedBytes
        }
        shift += 7
    }
    throw IllegalArgumentException("invalid confidential encrypted payload length")
}

private fun StringBuilder.appendJsonString(value: String) {
    append('"')
    for (ch in value) {
        when (ch) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000C' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> {
                if (ch < ' ') {
                    append("\\u00")
                    append(HEX[(ch.code ushr 4) and 0x0F])
                    append(HEX[ch.code and 0x0F])
                } else {
                    append(ch)
                }
            }
        }
    }
    append('"')
}

private fun StringBuilder.appendLanePrivacyJson(lanePrivacy: LanePrivacyProof) {
    append("{\"commitment_id\":")
    append(lanePrivacy.commitmentId)
    append(",\"witness\":{\"kind\":\"merkle\",\"payload\":")
    when (val witness = lanePrivacy.witness) {
        is LanePrivacyWitness.Merkle -> {
            append("{\"leaf\":")
            appendJsonByteArray(witness.value.leafBytes())
            append(",\"proof\":{\"leaf_index\":")
            append(witness.value.leafIndex)
            append(",\"audit_path\":[")
            witness.value.auditPathBytes().forEachIndexed { index, sibling ->
                if (index != 0) append(',')
                appendJsonByteArray(sibling)
            }
            append("]}}")
        }
    }
    append("}}")
}

private fun StringBuilder.appendJsonByteArray(bytes: ByteArray) {
    append('[')
    bytes.forEachIndexed { index, byte ->
        if (index != 0) append(',')
        append(byte.toInt() and 0xff)
    }
    append(']')
}

private fun hexLower(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (byte in bytes) {
        val value = byte.toInt() and 0xff
        append(HEX[value ushr 4])
        append(HEX[value and 0x0f])
    }
}

private fun nullableContentEquals(left: ByteArray?, right: ByteArray?): Boolean =
    when {
        left === null && right === null -> true
        left === null || right === null -> false
        else -> left.contentEquals(right)
    }

private val HEX = charArrayOf(
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
)
