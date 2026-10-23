// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.privacy

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import org.hyperledger.iroha.sdk.norito.TypeAdapter

/** One byte-complete row of the canonical first-release exact-12 fixture. */
class PrivacyExact12TypedFixtureRowV1(
    @JvmField val protocolId: PrivacyProtocolIdV1,
    statementNorito: ByteArray,
    envelopeNorito: ByteArray,
    @JvmField val submitProofWireId: String,
    submitProofInstructionNorito: ByteArray,
    transactionIntentProjectionNorito: ByteArray,
    transactionIntentDigest: ByteArray,
    unsignedTransactionPayloadNorito: ByteArray,
    signedTransactionVersionedNorito: ByteArray,
    signedTransactionHash: ByteArray,
) {
    private val _statementNorito = boundedBytes(
        statementNorito,
        PrivacyExact12FixtureCodecV1.MAX_STATEMENT_BYTES,
        "statementNorito",
    )
    private val _envelopeNorito = boundedBytes(
        envelopeNorito,
        PrivacyExact12FixtureCodecV1.MAX_ENVELOPE_BYTES,
        "envelopeNorito",
    )
    private val _submitProofInstructionNorito = boundedBytes(
        submitProofInstructionNorito,
        PrivacyExact12FixtureCodecV1.MAX_INSTRUCTION_BYTES,
        "submitProofInstructionNorito",
    )
    private val _transactionIntentProjectionNorito = boundedBytes(
        transactionIntentProjectionNorito,
        PrivacyExact12FixtureCodecV1.MAX_INTENT_PROJECTION_BYTES,
        "transactionIntentProjectionNorito",
    )
    private val _transactionIntentDigest = fixedBytes(
        transactionIntentDigest,
        PrivacyExact12FixtureCodecV1.HASH_BYTES,
        "transactionIntentDigest",
    )
    private val _unsignedTransactionPayloadNorito = boundedBytes(
        unsignedTransactionPayloadNorito,
        PrivacyExact12FixtureCodecV1.MAX_UNSIGNED_TRANSACTION_BYTES,
        "unsignedTransactionPayloadNorito",
    )
    private val _signedTransactionVersionedNorito = boundedBytes(
        signedTransactionVersionedNorito,
        PrivacyExact12FixtureCodecV1.MAX_SIGNED_TRANSACTION_BYTES,
        "signedTransactionVersionedNorito",
    )
    private val _signedTransactionHash = fixedBytes(
        signedTransactionHash,
        PrivacyExact12FixtureCodecV1.HASH_BYTES,
        "signedTransactionHash",
    )

    init {
        require(submitProofWireId == PrivacyExact12FixtureCodecV1.SUBMIT_PROOF_WIRE_ID) {
            "submitProofWireId must be the canonical first-release wire id"
        }
        require(nestedByteCount() <= PrivacyExact12FixtureCodecV1.MAX_AGGREGATE_NESTED_BYTES) {
            "exact-12 row exceeds the aggregate nested-byte limit"
        }
    }

    val statementNorito: ByteArray get() = _statementNorito.copyOf()
    val envelopeNorito: ByteArray get() = _envelopeNorito.copyOf()
    val submitProofInstructionNorito: ByteArray get() = _submitProofInstructionNorito.copyOf()
    val transactionIntentProjectionNorito: ByteArray
        get() = _transactionIntentProjectionNorito.copyOf()
    val transactionIntentDigest: ByteArray get() = _transactionIntentDigest.copyOf()
    val unsignedTransactionPayloadNorito: ByteArray
        get() = _unsignedTransactionPayloadNorito.copyOf()
    val signedTransactionVersionedNorito: ByteArray
        get() = _signedTransactionVersionedNorito.copyOf()
    val signedTransactionHash: ByteArray get() = _signedTransactionHash.copyOf()

    fun statementNoritoBytes(): ByteArray = statementNorito
    fun envelopeNoritoBytes(): ByteArray = envelopeNorito
    fun submitProofInstructionNoritoBytes(): ByteArray = submitProofInstructionNorito
    fun transactionIntentProjectionNoritoBytes(): ByteArray = transactionIntentProjectionNorito
    fun transactionIntentDigestBytes(): ByteArray = transactionIntentDigest
    fun unsignedTransactionPayloadNoritoBytes(): ByteArray = unsignedTransactionPayloadNorito
    fun signedTransactionVersionedNoritoBytes(): ByteArray = signedTransactionVersionedNorito
    fun signedTransactionHashBytes(): ByteArray = signedTransactionHash

    internal fun nestedByteCount(): Long {
        var total = submitProofWireId.toByteArray(StandardCharsets.UTF_8).size.toLong()
        for (bytes in listOf(
            _statementNorito,
            _envelopeNorito,
            _submitProofInstructionNorito,
            _transactionIntentProjectionNorito,
            _transactionIntentDigest,
            _unsignedTransactionPayloadNorito,
            _signedTransactionVersionedNorito,
            _signedTransactionHash,
        )) {
            total = Math.addExact(total, bytes.size.toLong())
        }
        return total
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyExact12TypedFixtureRowV1 &&
            protocolId == other.protocolId &&
            submitProofWireId == other.submitProofWireId &&
            _statementNorito.contentEquals(other._statementNorito) &&
            _envelopeNorito.contentEquals(other._envelopeNorito) &&
            _submitProofInstructionNorito.contentEquals(other._submitProofInstructionNorito) &&
            _transactionIntentProjectionNorito.contentEquals(other._transactionIntentProjectionNorito) &&
            _transactionIntentDigest.contentEquals(other._transactionIntentDigest) &&
            _unsignedTransactionPayloadNorito.contentEquals(other._unsignedTransactionPayloadNorito) &&
            _signedTransactionVersionedNorito.contentEquals(other._signedTransactionVersionedNorito) &&
            _signedTransactionHash.contentEquals(other._signedTransactionHash)

    override fun hashCode(): Int {
        var result = protocolId.hashCode()
        result = 31 * result + _statementNorito.contentHashCode()
        result = 31 * result + _envelopeNorito.contentHashCode()
        result = 31 * result + submitProofWireId.hashCode()
        result = 31 * result + _submitProofInstructionNorito.contentHashCode()
        result = 31 * result + _transactionIntentProjectionNorito.contentHashCode()
        result = 31 * result + _transactionIntentDigest.contentHashCode()
        result = 31 * result + _unsignedTransactionPayloadNorito.contentHashCode()
        result = 31 * result + _signedTransactionVersionedNorito.contentHashCode()
        result = 31 * result + _signedTransactionHash.contentHashCode()
        return result
    }
}

/** Typed outer bundle containing exactly the twelve canonical privacy rows. */
class PrivacyExact12FixtureBundleV1(
    @JvmField val version: Int,
    rows: List<PrivacyExact12TypedFixtureRowV1>,
) {
    @JvmField
    val rows: List<PrivacyExact12TypedFixtureRowV1>

    init {
        require(version == PrivacyExact12FixtureCodecV1.VERSION) {
            "exact-12 fixture version must be ${PrivacyExact12FixtureCodecV1.VERSION}"
        }
        require(rows.size == PrivacyExact12FixtureCodecV1.ROW_COUNT) {
            "exact-12 fixture must contain exactly ${PrivacyExact12FixtureCodecV1.ROW_COUNT} rows"
        }
        val expected = PrivacyProtocolIdV1.values()
        require(expected.size == PrivacyExact12FixtureCodecV1.ROW_COUNT) {
            "privacy protocol registry must contain exactly ${PrivacyExact12FixtureCodecV1.ROW_COUNT} entries"
        }
        var aggregate = 0L
        rows.forEachIndexed { index, row ->
            require(row.protocolId == expected[index]) {
                "exact-12 row $index is out of canonical protocol order"
            }
            aggregate = Math.addExact(aggregate, row.nestedByteCount())
            require(aggregate <= PrivacyExact12FixtureCodecV1.MAX_AGGREGATE_NESTED_BYTES) {
                "exact-12 bundle exceeds the aggregate nested-byte limit"
            }
        }
        this.rows = Collections.unmodifiableList(rows.toList())
    }

    override fun equals(other: Any?): Boolean =
        other is PrivacyExact12FixtureBundleV1 && version == other.version && rows == other.rows

    override fun hashCode(): Int = 31 * version + rows.hashCode()
}

/** Strict native-independent codec for the canonical exact-12 outer fixture bundle. */
object PrivacyExact12FixtureCodecV1 {
    const val SCHEMA_NAME: String = "iroha.privacy.exact12-typed-fixture-bundle.v1"
    const val SUBMIT_PROOF_WIRE_ID: String = "iroha.privacy.submit_proof.v1"
    const val CANONICAL_ARCHIVE_SHA256_HEX: String =
        "d7f1755b8145a1e18af5ffc315d6517ec68b16f1b67cf1aae58865e7c41f912b"
    const val VERSION: Int = 1
    const val ROW_COUNT: Int = 12
    const val HASH_BYTES: Int = 32
    const val MAX_ARCHIVE_BYTES: Int = 2 * 1024 * 1024
    const val MAX_AGGREGATE_NESTED_BYTES: Long = 2L * 1024L * 1024L
    const val MAX_STATEMENT_BYTES: Int = 256 * 1024
    const val MAX_ENVELOPE_BYTES: Int = 512 * 1024
    const val MAX_INSTRUCTION_BYTES: Int = 512 * 1024
    const val MAX_INTENT_PROJECTION_BYTES: Int = 512 * 1024
    const val MAX_UNSIGNED_TRANSACTION_BYTES: Int = 768 * 1024
    const val MAX_SIGNED_TRANSACTION_BYTES: Int = 1024 * 1024
    private const val MAX_ROW_ENCODED_BYTES: Long = 2L * 1024L * 1024L
    private const val MAX_WIRE_ID_ENCODED_BYTES: Long = 128L
    private const val FIXED_HASH_ENCODED_BYTES: Long = 32L
    private const val HEADER_PAYLOAD_LENGTH_OFFSET: Int = 23
    private const val HEADER_COMPRESSION_OFFSET: Int = 22
    private const val HEADER_FLAGS_OFFSET: Int = NoritoHeader.HEADER_LENGTH - 1
    private val UINT32_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(32)
    private val STRING_ADAPTER: TypeAdapter<String> = NoritoAdapters.stringAdapter()
    private val RAW_BYTES_ADAPTER: TypeAdapter<ByteArray> = NoritoAdapters.rawByteVecAdapter()
    private val FIXED_HASH_ADAPTER: TypeAdapter<ByteArray> = NoritoAdapters.fixedBytes(HASH_BYTES)

    /** Decode a complete canonical archive and reject every alternate representation. */
    @JvmStatic
    fun decodeCanonical(archive: ByteArray): PrivacyExact12FixtureBundleV1 {
        require(archive.isNotEmpty()) { "exact-12 fixture archive must not be empty" }
        require(archive.size <= MAX_ARCHIVE_BYTES) {
            "exact-12 fixture archive exceeds $MAX_ARCHIVE_BYTES bytes"
        }
        require(archive.size >= NoritoHeader.HEADER_LENGTH) {
            "exact-12 fixture archive is truncated before the Norito header"
        }
        val snapshot = archive.copyOf()
        require((snapshot[HEADER_COMPRESSION_OFFSET].toInt() and 0xff) == NoritoHeader.COMPRESSION_NONE) {
            "exact-12 fixture must use uncompressed Norito"
        }
        require((snapshot[HEADER_FLAGS_OFFSET].toInt() and 0xff) == NoritoHeader.COMPACT_LEN) {
            "exact-12 fixture must use only the canonical compact-length flag"
        }
        val declaredPayloadLength = ByteBuffer.wrap(snapshot)
            .order(ByteOrder.LITTLE_ENDIAN)
            .getLong(HEADER_PAYLOAD_LENGTH_OFFSET)
        require(declaredPayloadLength in 0L..(MAX_ARCHIVE_BYTES - NoritoHeader.HEADER_LENGTH).toLong()) {
            "exact-12 fixture declares an oversized Norito payload"
        }
        require(declaredPayloadLength == (snapshot.size - NoritoHeader.HEADER_LENGTH).toLong()) {
            "exact-12 fixture payload length does not cover the complete archive"
        }

        val decodedHeader = NoritoHeader.decode(snapshot, SchemaHash.hash16(SCHEMA_NAME))
        decodedHeader.header.validateChecksum(decodedHeader.payload)
        val decoder = NoritoDecoder(
            decodedHeader.payload,
            decodedHeader.header.flags,
        )
        val bundle = BundleAdapter.decode(decoder)
        require(decoder.remaining() == 0) { "exact-12 fixture contains trailing payload data" }
        val canonical = encodeCanonical(bundle)
        require(snapshot.contentEquals(canonical)) {
            "exact-12 fixture is not byte-canonical Norito"
        }
        return bundle
    }

    /** Encode a validated bundle with the exact first-release schema and layout flags. */
    @JvmStatic
    fun encodeCanonical(bundle: PrivacyExact12FixtureBundleV1): ByteArray {
        val encoded = NoritoCodec.encode(bundle, SCHEMA_NAME, BundleAdapter)
        require(encoded.size <= MAX_ARCHIVE_BYTES) {
            "exact-12 fixture archive exceeds $MAX_ARCHIVE_BYTES bytes"
        }
        require(canonicalArchiveDigestHex(encoded) == CANONICAL_ARCHIVE_SHA256_HEX) {
            "exact-12 fixture differs from the pinned Rust-derived first-release KAT"
        }
        return encoded
    }

    /** Decode standard padded Base64 without accepting whitespace or alternate spellings. */
    @JvmStatic
    fun decodeCanonicalBase64(encoded: String): PrivacyExact12FixtureBundleV1 {
        require(encoded.isNotEmpty()) { "exact-12 fixture base64 must not be empty" }
        require(encoded.length.toLong() <= canonicalBase64EncodedLength(MAX_ARCHIVE_BYTES.toLong())) {
            "exact-12 fixture base64 exceeds the archive limit"
        }
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("exact-12 fixture must use canonical standard base64", error)
        }
        require(Base64.getEncoder().encodeToString(bytes) == encoded) {
            "exact-12 fixture must use canonical padded standard base64"
        }
        return decodeCanonical(bytes)
    }

    /** Encode one validated bundle as canonical padded standard Base64. */
    @JvmStatic
    fun encodeCanonicalBase64(bundle: PrivacyExact12FixtureBundleV1): String =
        Base64.getEncoder().encodeToString(encodeCanonical(bundle))

    /**
     * Decode `candidate` and require byte identity with an independently supplied canonical fixture.
     * This closes same-shape cross-row and cross-field substitutions without inventing fixture semantics.
     */
    @JvmStatic
    fun requireCanonicalArchive(
        candidate: ByteArray,
        expectedCanonicalArchive: ByteArray,
    ): PrivacyExact12FixtureBundleV1 {
        val candidateSnapshot = candidate.copyOf()
        val expectedSnapshot = expectedCanonicalArchive.copyOf()
        decodeCanonical(expectedSnapshot)
        val decoded = decodeCanonical(candidateSnapshot)
        require(candidateSnapshot.contentEquals(expectedSnapshot)) {
            "exact-12 fixture differs from the supplied canonical archive"
        }
        return decoded
    }

    /** Compute the canonical Base64 size without allocating the encoded archive. */
    @JvmStatic
    fun canonicalBase64EncodedLength(decodedByteCount: Long): Long {
        require(decodedByteCount >= 0L) { "decodedByteCount must be non-negative" }
        return try {
            val groups = Math.addExact(decodedByteCount / 3L, if (decodedByteCount % 3L == 0L) 0L else 1L)
            Math.multiplyExact(groups, 4L)
        } catch (error: ArithmeticException) {
            throw IllegalArgumentException("canonical base64 length overflows the supported range", error)
        }
    }

    private fun canonicalArchiveDigestHex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private object BundleAdapter : TypeAdapter<PrivacyExact12FixtureBundleV1> {
        override fun encode(encoder: NoritoEncoder, value: PrivacyExact12FixtureBundleV1) {
            encodeSizedField(encoder, UINT32_ADAPTER, value.version.toLong())
            encodeSizedField(encoder, RowsAdapter(null), value.rows)
        }

        override fun decode(decoder: NoritoDecoder): PrivacyExact12FixtureBundleV1 {
            val version = decodeExactSizedField(decoder, UINT32_ADAPTER, 4L, "bundle version").toInt()
            val budget = DecodeBudget(MAX_AGGREGATE_NESTED_BYTES)
            val rows = decodeBoundedSizedField(
                decoder,
                RowsAdapter(budget),
                MAX_ARCHIVE_BYTES.toLong(),
                "bundle rows",
            )
            return PrivacyExact12FixtureBundleV1(version, rows)
        }
    }

    private class RowsAdapter(private val budget: DecodeBudget?) : TypeAdapter<List<PrivacyExact12TypedFixtureRowV1>> {
        override fun encode(encoder: NoritoEncoder, value: List<PrivacyExact12TypedFixtureRowV1>) {
            require(value.size == ROW_COUNT) { "exact-12 row count must be $ROW_COUNT" }
            encoder.writeLength(value.size.toLong(), false)
            val adapter = RowAdapter(null)
            value.forEach { row -> encodeSizedField(encoder, adapter, row) }
        }

        override fun decode(decoder: NoritoDecoder): List<PrivacyExact12TypedFixtureRowV1> {
            require(decoder.readLength(false) == ROW_COUNT.toLong()) {
                "exact-12 fixture must declare exactly $ROW_COUNT rows"
            }
            val expected = PrivacyProtocolIdV1.values()
            val adapter = RowAdapter(requireNotNull(budget))
            return List(ROW_COUNT) { index ->
                val row = decodeBoundedSizedField(
                    decoder,
                    adapter,
                    MAX_ROW_ENCODED_BYTES,
                    "row $index",
                )
                require(row.protocolId == expected[index]) {
                    "exact-12 row $index is out of canonical protocol order"
                }
                row
            }
        }
    }

    private class RowAdapter(private val budget: DecodeBudget?) : TypeAdapter<PrivacyExact12TypedFixtureRowV1> {
        override fun encode(encoder: NoritoEncoder, value: PrivacyExact12TypedFixtureRowV1) {
            encodeSizedField(encoder, UINT32_ADAPTER, value.protocolId.ordinal.toLong())
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.statementNoritoBytes())
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.envelopeNoritoBytes())
            encodeSizedField(encoder, STRING_ADAPTER, value.submitProofWireId)
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.submitProofInstructionNoritoBytes())
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.transactionIntentProjectionNoritoBytes())
            encodeSizedField(encoder, FIXED_HASH_ADAPTER, value.transactionIntentDigestBytes())
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.unsignedTransactionPayloadNoritoBytes())
            encodeSizedField(encoder, RAW_BYTES_ADAPTER, value.signedTransactionVersionedNoritoBytes())
            encodeSizedField(encoder, FIXED_HASH_ADAPTER, value.signedTransactionHashBytes())
        }

        override fun decode(decoder: NoritoDecoder): PrivacyExact12TypedFixtureRowV1 {
            val decodeBudget = requireNotNull(budget)
            val protocolTag = decodeExactSizedField(decoder, UINT32_ADAPTER, 4L, "protocol id")
            val protocols = PrivacyProtocolIdV1.values()
            require(protocolTag >= 0L && protocolTag < protocols.size.toLong()) {
                "unknown exact-12 protocol discriminant: $protocolTag"
            }
            val statement = decodeRawBytesField(decoder, MAX_STATEMENT_BYTES, decodeBudget, "statement")
            val envelope = decodeRawBytesField(decoder, MAX_ENVELOPE_BYTES, decodeBudget, "envelope")
            val wireId = decodeBoundedSizedField(
                decoder,
                STRING_ADAPTER,
                MAX_WIRE_ID_ENCODED_BYTES,
                "submit-proof wire id",
            )
            require(wireId == SUBMIT_PROOF_WIRE_ID) { "unknown or retired submit-proof wire id" }
            decodeBudget.claim(wireId.toByteArray(StandardCharsets.UTF_8).size.toLong(), "submit-proof wire id")
            val instruction = decodeRawBytesField(
                decoder,
                MAX_INSTRUCTION_BYTES,
                decodeBudget,
                "submit-proof instruction",
            )
            val projection = decodeRawBytesField(
                decoder,
                MAX_INTENT_PROJECTION_BYTES,
                decodeBudget,
                "transaction intent projection",
            )
            val intentDigest = decodeExactSizedField(
                decoder,
                FIXED_HASH_ADAPTER,
                FIXED_HASH_ENCODED_BYTES,
                "transaction intent digest",
            )
            decodeBudget.claim(intentDigest.size.toLong(), "transaction intent digest")
            val unsigned = decodeRawBytesField(
                decoder,
                MAX_UNSIGNED_TRANSACTION_BYTES,
                decodeBudget,
                "unsigned transaction payload",
            )
            val signed = decodeRawBytesField(
                decoder,
                MAX_SIGNED_TRANSACTION_BYTES,
                decodeBudget,
                "signed transaction",
            )
            val transactionHash = decodeExactSizedField(
                decoder,
                FIXED_HASH_ADAPTER,
                FIXED_HASH_ENCODED_BYTES,
                "signed transaction hash",
            )
            decodeBudget.claim(transactionHash.size.toLong(), "signed transaction hash")
            return PrivacyExact12TypedFixtureRowV1(
                protocols[protocolTag.toInt()],
                statement,
                envelope,
                wireId,
                instruction,
                projection,
                intentDigest,
                unsigned,
                signed,
                transactionHash,
            )
        }
    }

    private class DecodeBudget(private val maximum: Long) {
        private var used: Long = 0L

        fun claim(bytes: Long, fieldName: String) {
            require(bytes >= 0L) { "$fieldName declares a negative byte count" }
            used = try {
                Math.addExact(used, bytes)
            } catch (error: ArithmeticException) {
                throw IllegalArgumentException("exact-12 aggregate byte count overflows", error)
            }
            require(used <= maximum) { "exact-12 aggregate nested-byte limit exceeded at $fieldName" }
        }
    }

    private fun decodeRawBytesField(
        decoder: NoritoDecoder,
        maximum: Int,
        budget: DecodeBudget,
        fieldName: String,
    ): ByteArray {
        val encodedLength = decoder.readLength(true)
        require(encodedLength in 9L..(maximum.toLong() + 8L)) {
            "$fieldName field exceeds its encoded byte limit"
        }
        val child = NoritoDecoder(
            decoder.readBytes(encodedLength.toInt()),
            decoder.flags,
        )
        val declaredLength = child.readLength(false)
        require(declaredLength in 1L..maximum.toLong()) { "$fieldName byte length is invalid" }
        require(declaredLength == child.remaining().toLong()) {
            "$fieldName declared length does not cover its complete field"
        }
        budget.claim(declaredLength, fieldName)
        return child.readBytes(declaredLength.toInt())
    }

    private fun <T> encodeSizedField(encoder: NoritoEncoder, adapter: TypeAdapter<T>, value: T) {
        val child = encoder.childEncoder()
        adapter.encode(child, value)
        val payload = child.toByteArray()
        encoder.writeLength(payload.size.toLong(), true)
        encoder.writeBytes(payload)
    }

    private fun <T> decodeExactSizedField(
        decoder: NoritoDecoder,
        adapter: TypeAdapter<T>,
        expectedEncodedLength: Long,
        fieldName: String,
    ): T {
        val actual = decoder.readLength(true)
        require(actual == expectedEncodedLength) {
            "$fieldName must contain exactly $expectedEncodedLength encoded bytes"
        }
        return decodeChild(decoder, adapter, actual.toInt(), fieldName)
    }

    private fun <T> decodeBoundedSizedField(
        decoder: NoritoDecoder,
        adapter: TypeAdapter<T>,
        maximumEncodedLength: Long,
        fieldName: String,
    ): T {
        val length = decoder.readLength(true)
        require(length in 0L..maximumEncodedLength) { "$fieldName exceeds its encoded byte limit" }
        return decodeChild(decoder, adapter, length.toInt(), fieldName)
    }

    private fun <T> decodeChild(
        decoder: NoritoDecoder,
        adapter: TypeAdapter<T>,
        length: Int,
        fieldName: String,
    ): T {
        val child = NoritoDecoder(decoder.readBytes(length), decoder.flags)
        val value = adapter.decode(child)
        require(child.remaining() == 0) { "$fieldName contains trailing or unknown data" }
        return value
    }
}

private fun boundedBytes(value: ByteArray, maximum: Int, name: String): ByteArray {
    require(value.isNotEmpty()) { "$name must not be empty" }
    require(value.size <= maximum) { "$name must not exceed $maximum bytes" }
    return value.copyOf()
}

private fun fixedBytes(value: ByteArray, expected: Int, name: String): ByteArray {
    require(value.size == expected) { "$name must contain exactly $expected bytes" }
    return value.copyOf()
}
