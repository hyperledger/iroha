// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/** One explicitly authorized issuer operation; Pending does not authorize a new attempt. */
enum class ToriiKagemushaWalletEnrollmentActionV1(internal val tag: Int) {
    PRE_KEY(0), EVIDENCE(1), ISSUE(2), DELIVER(3),
}

/**
 * Immutable canonical enrollment request DATA. Native owns the dispatch and signed evidence
 * originals; this envelope never interprets or regenerates them. Retain [canonicalWire] for
 * recovery, decode it with [decodeCanonical], and explicitly resubmit with fresh account auth.
 */
class ToriiKagemushaWalletEnrollmentRequestV1 private constructor(
    @JvmField val action: ToriiKagemushaWalletEnrollmentActionV1,
    dispatchOriginal: ByteArray,
    evidenceOriginal: ByteArray,
) {
    private val dispatch = enrollmentOriginal(dispatchOriginal, MAXIMUM_DISPATCH_BYTES)
    private val evidence: ByteArray

    init {
        require(evidenceOriginal.size <= MAXIMUM_EVIDENCE_BYTES &&
            (action == ToriiKagemushaWalletEnrollmentActionV1.EVIDENCE) == evidenceOriginal.isNotEmpty()) {
            "KAGEMUSHA Evidence requires its exact bounded original; other actions cannot include evidence"
        }
        evidence = evidenceOriginal.copyOf()
    }

    /** Owned exact native dispatch original, shared by all recovery actions. */
    val dispatchOriginal: ByteArray get() = dispatch.copyOf()
    /** Owned exact signed native evidence original; empty for every other action. */
    val evidenceOriginal: ByteArray get() = evidence.copyOf()

    /** Canonical bytes to persist and sign; independent of application-owned HTTP freshness. */
    fun canonicalWire(): ByteArray = EnrollmentEnvelopeCodec.frame(REQUEST_SCHEMA,
        EnrollmentEnvelopeCodec.fields(listOf(
            EnrollmentEnvelopeCodec.uint(1, 16), EnrollmentEnvelopeCodec.uint(action.tag.toLong(), 32),
            EnrollmentEnvelopeCodec.bytes(dispatch), EnrollmentEnvelopeCodec.bytes(evidence),
        )), MAXIMUM_BYTES)

    /** Decode and bind a result to this exact action. Native still verifies any returned original. */
    fun decodeResponse(original: ByteArray): ToriiKagemushaWalletEnrollmentResponseV1 =
        ToriiKagemushaWalletEnrollmentResponseV1.decodeCanonical(action, original)

    companion object {
        const val MAXIMUM_DISPATCH_BYTES = 16_384
        const val MAXIMUM_EVIDENCE_BYTES = 524_288
        const val MAXIMUM_BYTES = 544 * 1024
        internal const val ROUTE = "/v1/kagemusha/enrollment"
        private const val REQUEST_SCHEMA = "iroha.torii.kagemusha.enrollment.request.v1"

        /** Obtain or recover the original permit before mobile key generation. */
        @JvmStatic fun preKey(dispatchOriginal: ByteArray): ToriiKagemushaWalletEnrollmentRequestV1 =
            ToriiKagemushaWalletEnrollmentRequestV1(ToriiKagemushaWalletEnrollmentActionV1.PRE_KEY, dispatchOriginal, ByteArray(0))

        /** Submit or recover the same account-signed evidence; never reset a consumed attempt. */
        @JvmStatic fun evidence(dispatchOriginal: ByteArray, evidenceOriginal: ByteArray): ToriiKagemushaWalletEnrollmentRequestV1 =
            ToriiKagemushaWalletEnrollmentRequestV1(ToriiKagemushaWalletEnrollmentActionV1.EVIDENCE, dispatchOriginal, evidenceOriginal)

        /** Explicitly issue or recover a retained credential after evidence is durable. */
        @JvmStatic fun issue(dispatchOriginal: ByteArray): ToriiKagemushaWalletEnrollmentRequestV1 =
            ToriiKagemushaWalletEnrollmentRequestV1(ToriiKagemushaWalletEnrollmentActionV1.ISSUE, dispatchOriginal, ByteArray(0))

        /** Obtain the exact retained credential after the issuer's fresh eligibility check. */
        @JvmStatic fun deliver(dispatchOriginal: ByteArray): ToriiKagemushaWalletEnrollmentRequestV1 =
            ToriiKagemushaWalletEnrollmentRequestV1(ToriiKagemushaWalletEnrollmentActionV1.DELIVER, dispatchOriginal, ByteArray(0))

        /** Recover one bounded canonical request; rejects alternative layouts and trailing bytes. */
        @JvmStatic fun decodeCanonical(original: ByteArray): ToriiKagemushaWalletEnrollmentRequestV1 {
            val payload = EnrollmentEnvelopeCodec.unframe(original, REQUEST_SCHEMA, MAXIMUM_BYTES)
            val fields = EnrollmentEnvelopeCodec.readFields(payload, intArrayOf(2, 4, MAXIMUM_DISPATCH_BYTES + 8, MAXIMUM_EVIDENCE_BYTES + 8))
            require(EnrollmentEnvelopeCodec.readUInt(fields[0], 16) == 1L) { "unsupported enrollment version" }
            val tag = EnrollmentEnvelopeCodec.readUInt(fields[1], 32)
            val action = ToriiKagemushaWalletEnrollmentActionV1.values().singleOrNull { it.tag.toLong() == tag }
                ?: throw IllegalArgumentException("unknown enrollment action")
            val value = ToriiKagemushaWalletEnrollmentRequestV1(action,
                EnrollmentEnvelopeCodec.readBytes(fields[2], MAXIMUM_DISPATCH_BYTES),
                EnrollmentEnvelopeCodec.readBytes(fields[3], MAXIMUM_EVIDENCE_BYTES))
            require(value.canonicalWire().contentEquals(original)) { "noncanonical enrollment request" }
            return value
        }
    }
}

/**
 * Closed issuer response DATA. Ready and Pending describe the server operation only; they confer
 * no enrollment or balance authority. Pass Permit/Credential originals to the native wallet owner.
 */
sealed class ToriiKagemushaWalletEnrollmentResponseV1 private constructor(internal val tag: Int) {
    /** Exact original permit, unverified until Native admits it for the retained dispatch. */
    class Permit internal constructor(original: ByteArray) : ToriiKagemushaWalletEnrollmentResponseV1(0) {
        private val original = enrollmentOriginal(original, MAXIMUM_PERMIT_BYTES)
        val unverifiedOriginal: ByteArray get() = original.copyOf()
        override fun originalOrNull(): ByteArray = original.copyOf()
    }
    /** Evidence is durable; Issue remains an explicit separately authorized operation. */
    object EvidenceReady : ToriiKagemushaWalletEnrollmentResponseV1(1)
    /** Attempt remains consumed. An explicit retry recovers the same retained operation. */
    object Pending : ToriiKagemushaWalletEnrollmentResponseV1(2)
    /** Credential is durable; Deliver still checks fresh eligibility. */
    object CredentialReady : ToriiKagemushaWalletEnrollmentResponseV1(3)
    /** Exact original E6, unverified until Native admits it for the retained request. */
    class Credential internal constructor(original: ByteArray) : ToriiKagemushaWalletEnrollmentResponseV1(4) {
        private val original = enrollmentOriginal(original, MAXIMUM_CREDENTIAL_BYTES)
        val unverifiedOriginal: ByteArray get() = original.copyOf()
        override fun originalOrNull(): ByteArray = original.copyOf()
    }

    internal open fun originalOrNull(): ByteArray? = null

    /** Exact canonical envelope for retention; does not grant authority to its contents. */
    fun canonicalWire(): ByteArray {
        val bytes = originalOrNull()
        val payload = EnrollmentEnvelopeCodec.uint(tag.toLong(), 32) +
            if (bytes == null) ByteArray(0) else EnrollmentEnvelopeCodec.fields(listOf(EnrollmentEnvelopeCodec.bytes(bytes)))
        // Canonical Rust emits no length flag for unit variants, whose payload is only a u32.
        return EnrollmentEnvelopeCodec.frame(RESPONSE_SCHEMA, payload, MAXIMUM_BYTES,
            if (bytes == null) 0 else NoritoHeader.COMPACT_LEN)
    }

    companion object {
        const val MAXIMUM_PERMIT_BYTES = 2048
        const val MAXIMUM_CREDENTIAL_BYTES = 262_144
        const val MAXIMUM_BYTES = 264 * 1024
        private const val RESPONSE_SCHEMA = "iroha.torii.kagemusha.enrollment.response.v1"

        /** Parse only a canonical result legal for the explicitly requested action. */
        @JvmStatic fun decodeCanonical(action: ToriiKagemushaWalletEnrollmentActionV1,
            original: ByteArray): ToriiKagemushaWalletEnrollmentResponseV1 {
            val payload = EnrollmentEnvelopeCodec.unframe(original, RESPONSE_SCHEMA, MAXIMUM_BYTES, response = true)
            val decoder = NoritoDecoder(payload, NoritoHeader.COMPACT_LEN)
            val tag = decoder.readUInt(32)
            val remainder = decoder.readBytes(decoder.remaining())
            val response = when (tag) {
                0L, 4L -> {
                    val bound = if (tag == 0L) MAXIMUM_PERMIT_BYTES else MAXIMUM_CREDENTIAL_BYTES
                    val fields = EnrollmentEnvelopeCodec.readFields(remainder, intArrayOf(bound + 8))
                    val bytes = EnrollmentEnvelopeCodec.readBytes(fields.single(), bound)
                    if (tag == 0L) Permit(bytes) else Credential(bytes)
                }
                1L, 2L, 3L -> {
                    require(remainder.isEmpty()) { "trailing enrollment status bytes" }
                    when (tag) { 1L -> EvidenceReady; 2L -> Pending; else -> CredentialReady }
                }
                else -> throw IllegalArgumentException("unknown enrollment response")
            }
            val matches = when (action) {
                ToriiKagemushaWalletEnrollmentActionV1.PRE_KEY -> response is Permit
                ToriiKagemushaWalletEnrollmentActionV1.EVIDENCE -> response === EvidenceReady || response === Pending
                ToriiKagemushaWalletEnrollmentActionV1.ISSUE -> response === CredentialReady
                ToriiKagemushaWalletEnrollmentActionV1.DELIVER -> response is Credential
            }
            require(matches) { "enrollment response does not match requested action" }
            require(response.canonicalWire().contentEquals(original)) { "noncanonical enrollment response" }
            return response
        }
    }
}

private fun enrollmentOriginal(original: ByteArray, maximumBytes: Int): ByteArray {
    require(original.isNotEmpty() && original.size <= maximumBytes) { "empty or excessive enrollment original" }
    return original.copyOf()
}

/** Canonical COMPACT_LEN fields with the Rust Vec<u8> fixed-count raw-byte specialization. */
private object EnrollmentEnvelopeCodec {
    private const val FLAGS = NoritoHeader.COMPACT_LEN
    fun uint(value: Long, bits: Int): ByteArray = NoritoEncoder(FLAGS).apply { writeUInt(value, bits) }.toByteArray()
    fun readUInt(bytes: ByteArray, bits: Int): Long {
        require(bytes.size == bits / 8) { "invalid enrollment integer width" }
        return NoritoDecoder(bytes, FLAGS).readUInt(bits)
    }
    fun bytes(value: ByteArray): ByteArray = NoritoEncoder(FLAGS).apply {
        NoritoAdapters.rawByteVecAdapter().encode(this, value)
    }.toByteArray()
    fun readBytes(value: ByteArray, bound: Int): ByteArray {
        val decoder = NoritoDecoder(value, FLAGS)
        val count = decoder.readLength(false)
        require(count <= bound && count == decoder.remaining().toLong()) { "invalid enrollment byte vector length" }
        return decoder.readBytes(count.toInt())
    }
    fun fields(values: List<ByteArray>): ByteArray = NoritoEncoder(FLAGS).apply {
        values.forEach { writeLength(it.size.toLong(), true); writeBytes(it) }
    }.toByteArray()
    fun readFields(payload: ByteArray, bounds: IntArray): List<ByteArray> {
        val decoder = NoritoDecoder(payload, FLAGS)
        val fields = bounds.map { bound ->
            val size = decoder.readLength(true)
            require(size <= bound && size <= decoder.remaining().toLong()) { "invalid enrollment field length" }
            decoder.readBytes(size.toInt())
        }
        require(decoder.remaining() == 0 && fields(fields).contentEquals(payload)) { "noncanonical enrollment fields" }
        return fields
    }
    fun frame(schema: String, payload: ByteArray, bound: Int, flags: Int = FLAGS): ByteArray {
        require(payload.size <= bound - NoritoHeader.HEADER_LENGTH)
        return NoritoHeader(SchemaHash.hash16(schema), payload.size, CRC64.compute(payload), flags,
            NoritoHeader.COMPRESSION_NONE).encode() + payload
    }
    fun unframe(original: ByteArray, schema: String, bound: Int, response: Boolean = false): ByteArray {
        require(original.size in NoritoHeader.HEADER_LENGTH..bound) { "empty or excessive enrollment frame" }
        val decoded = NoritoHeader.decode(original, SchemaHash.hash16(schema))
        require((decoded.header.flags == FLAGS || (response && decoded.header.flags == 0)) &&
            decoded.header.compression == NoritoHeader.COMPRESSION_NONE)
        decoded.header.validateChecksum(decoded.payload)
        require(frame(schema, decoded.payload, bound, decoded.header.flags).contentEquals(original)) { "noncanonical enrollment frame" }
        return decoded.payload
    }
}
