// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import org.hyperledger.iroha.sdk.norito.Varint

/**
 * Exact role label of one domain-separated KAGEMUSHA wallet V1 digest `H(role, body)`.
 *
 * Mirrors Rust `iroha_data_model::kagemusha::KagemushaWalletDigestRoleV1::ALL` (20 roles, including the NEW unsigned E1 policy identities) in
 * declaration order. `H` remains only for values no relation recomputes: fixed identities,
 * ledger, platform-attestation and artifact boundaries, output descriptors and local custody
 * records (wire record section 1). Only the artifact manifest hashes `m || signature`; other signed-object digests
 * are Poseidon values computed by the native core.
 *
 * `credit_id`, `proof_digest`, the Payment, lineage, credit-opening, credit-status and credited
 * digests, every signing message, map values, leaves and roots, chains, the state commitment, the
 * σ statement digest and the blacklist, quota-window and credit-digest trees are not SHA-256 roles:
 * they are Poseidon values over the σ field that the native Rust core computes (wire record
 * sections 1 and 3.2). Kotlin carries them as opaque canonical field values
 * ([KagemushaWalletWireV1.isCanonicalFieldValue]) and never recomputes them.
 */
enum class KagemushaWalletDigestRoleV1(
    /** Exact ASCII role label hashed after [KagemushaWalletWireV1.DIGEST_PREFIX]. */
    @JvmField val label: String,
) {
    SCHEME("scheme"),
    RELATION("relation"),
    PROVIDER_CONTRACT("provider-contract"),
    ASSET_SCOPE("asset-scope"),
    ACCOUNT("account"),
    ENROLLMENT_CHALLENGE("enrollment-challenge"),
    /** NEW first-release typed app identity; unsigned selection, no approval implied. */
    APP_POLICY("app-policy"),
    /** NEW first-release typed enrollment inputs; unsigned selection, no approval implied. */
    ENROLLMENT_POLICY("enrollment-policy"),
    ENROLLMENT_ID("enrollment-id"),
    ENROLLMENT_KEY_BINDING("enrollment-key-binding"),
    WALLET_ID("wallet-id"),
    ARTIFACT_MANIFEST("artifact-manifest"),
    EVIDENCE("evidence"),
    RENEWAL_ASSERTION("renewal-assertion"),
    /**
     * σ verifying-key allowlist transcript: `LE16 version || LE32 n || n × (tag kind ||
     * LE32 enabled_controls || verifying_key_digest || LE32 proof_bytes) ||
     * lineage_verifying_key_digest || LE32 lineage_proof_bytes`.
     */
    VERIFYING_KEY_SET("verifying-key-set"),
    OUTPUT("output"),
    MARKER("marker"),
    CAPSULE("capsule"),
    COMPLETION("completion"),
    FOLD("fold"),
    ;
    companion object {
        /** The exact retained H label, or null. Retired body/delivery roles have no alias. */
        @JvmStatic
        fun fromLabel(label: String): KagemushaWalletDigestRoleV1? = entries.firstOrNull { it.label == label }
    }
}

/**
 * Signing domain of one signed KAGEMUSHA wallet V1 body (wire record section 1, owner answer A1).
 *
 * Mirrors Rust `KagemushaWalletSigningDomainV1::ALL` (17 domains) in declaration order. Every
 * P-256 signature of the protocol signs, as its message, the 32-byte canonical encoding `m` of
 * the Poseidon value `P_bytes(d, transcript)` with standard ECDSA-P256-SHA256 (the ECDSA hash is
 * `SHA-256(m)`): Android KeyMint through a `DIGEST_SHA256` key and `SHA256withECDSA`, the Secure
 * Enclave through `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`, and issuer, policy, ledger
 * and artifact signers with the same algorithm. No-digest modes are never used. The native core
 * computes `m`; Kotlin treats it as an opaque canonical σ-field value.
 */
enum class KagemushaWalletSigningDomainV1(
    /** The 8 ASCII bytes of the Poseidon domain word, for example `kgwcert1`. */
    @JvmField val label: String,
    /** Exact byte length of the signed transcript. */
    @JvmField val transcriptBytes: Int,
) {
    CERTIFICATE("kgwcert1", 108),
    CREDENTIAL("kgwcred1", 476),
    RENEWAL_CHALLENGE("kgwrnch1", 130),
    RENEWAL_KEY_BINDING("kgwrnkb1", 163),
    ARTIFACT_MANIFEST("kgwartf1", 290),
    RECEIPT("kgwrcpt1", 338),
    SCHEME_POLICY("kgwspol1", 142),
    FEE_SCHEDULE("kgwfsch1", 191),
    BLACKLIST("kgwblst1", 118),
    QUOTA_SHARE("kgwqshr1", 190),
    TIME_ANCHOR("kgwtanc1", 138),
    CHARGE_QUOTE("kgwchgq1", 219),
    OFFER("kgwoffr1", 194),
    SESSION_CONTROL("kgwsctl1", 197),
    REQUEST("kgwrqst1", 458),
    LEDGER_CONTROL("kgwlctl1", 211),
    ;

    companion object {
        /** Domain whose label is exactly [label], or `null` for an unknown label. */
        @JvmStatic
        fun fromLabel(label: String): KagemushaWalletSigningDomainV1? = entries.firstOrNull { it.label == label }
    }
}

/** Peer message kind carried by a KAGEMUSHA wallet V1 envelope; its tag selects the frame bound. */
enum class KagemushaWalletMessageKindV1(
    /** Norito `u32` enum tag of `KagemushaWalletMessageV1`. */
    @JvmField val wireTag: Int,
    /** Rust variant name of `KagemushaWalletMessageV1`. */
    @JvmField val label: String,
    /** Maximum complete canonical envelope frame, header and padding included. */
    @JvmField val maximumFrameBytes: Int,
    /** Maximum complete `kgm1:` text of an envelope of this kind. */
    @JvmField val maximumTextBytes: Int,
) {
    OFFER(
        1,
        "Offer",
        KagemushaWalletWireV1.SESSION_MAX_BYTES,
        KagemushaWalletWireV1.SESSION_TEXT_MAX_BYTES,
    ),
    REQUEST(
        2,
        "Request",
        KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
        KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
    ),
    PAYMENT(
        3,
        "Payment",
        KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
        KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
    ),
    CREDITED(
        4,
        "Credited",
        KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
        KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
    ),
    SESSION_CONTROL(
        5,
        "SessionControl",
        KagemushaWalletWireV1.SESSION_MAX_BYTES,
        KagemushaWalletWireV1.SESSION_TEXT_MAX_BYTES,
    ),
    POLICY_DATA(
        6,
        "PolicyData",
        KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
        KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
    ),

    /** Ω of the payer's folded head; sent only after an authenticated Offer. */
    LINEAGE(
        7,
        "Lineage",
        KagemushaWalletWireV1.MESSAGE_MAX_BYTES,
        KagemushaWalletWireV1.MESSAGE_TEXT_MAX_BYTES,
    ),
    ;

    companion object {
        /** Kind with exactly [tag], or `null` for an unknown tag. */
        @JvmStatic
        fun fromWireTag(tag: Int): KagemushaWalletMessageKindV1? = entries.firstOrNull { it.wireTag == tag }

        /** Kind whose Rust variant name is exactly [label], or `null` for an unknown name. */
        @JvmStatic
        fun fromLabel(label: String): KagemushaWalletMessageKindV1? = entries.firstOrNull { it.label == label }
    }
}

/**
 * One canonical KAGEMUSHA wallet V1 envelope frame whose Norito header, envelope version and
 * message tag were validated by [KagemushaWalletWireV1.inspectEnvelope].
 *
 * This is a structural transport check only: the carried message is not decoded or verified
 * and grants no monetary authority. Equality is identity; compare [frame] bytes instead.
 */
class KagemushaWalletEnvelopeFrameV1 internal constructor(
    frame: ByteArray,
    /** Message kind read from the envelope payload tag. */
    @JvmField val kind: KagemushaWalletMessageKindV1,
    /** Norito layout flags; always [KagemushaWalletWireV1.ENVELOPE_FLAGS]. */
    @JvmField val flags: Int,
    /** Zero padding between the header and the payload. */
    @JvmField val paddingLength: Int,
    /** Payload bytes after the header and padding. */
    @JvmField val payloadLength: Int,
    /** CRC64-XZ of the payload, as stored little-endian in the header. */
    @JvmField val crc64: Long,
) {
    private val bytes: ByteArray = frame.copyOf()

    /** Complete frame length, header and padding included. */
    val frameLength: Int
        get() = bytes.size

    /** 16-byte Norito schema hash of the envelope frame name; a defensive copy. */
    val schemaHash: ByteArray
        get() = bytes.copyOfRange(SCHEMA_HASH_OFFSET, SCHEMA_HASH_OFFSET + SCHEMA_HASH_BYTES)

    /** Complete canonical frame bytes; a defensive copy. */
    fun frame(): ByteArray = bytes.copyOf()

    /** Strict `kgm1:` text of this frame, within [KagemushaWalletMessageKindV1.maximumTextBytes]. */
    fun toText(): String = KagemushaWalletWireV1.encodeText(bytes).also { text ->
        check(text.length <= kind.maximumTextBytes) {
            "KAGEMUSHA wallet V1 ${kind.label} text exceeds ${kind.maximumTextBytes} bytes"
        }
    }

    private companion object {
        const val SCHEMA_HASH_OFFSET = 6
        const val SCHEMA_HASH_BYTES = 16
    }
}

/**
 * Bounds, domain digests, envelope header validation and strict `kgm1:` text for the KAGEMUSHA
 * wallet V1 protocol, matching the Rust owner `iroha_data_model::kagemusha::kagemusha_wallet_v1`
 * and `fixtures/kagemusha/wallet_v1_vectors.json`.
 *
 * Every peer message travels as one canonical Norito frame of `KagemushaWalletEnvelopeV1`: a
 * 40-byte header with flags `0x02`, eight zero padding bytes (the envelope archive alignment is
 * 16), then the payload. Bounds count the complete frame.
 */
object KagemushaWalletWireV1 {
    /** Version carried by every wallet V1 object and transcript. */
    const val VERSION: Int = 1

    /** Text transport discriminator. */
    const val TEXT_PREFIX: String = "kgm1:"

    /** ASCII prefix of every wallet V1 digest preimage. */
    const val DIGEST_PREFIX: String = "iroha:kagemusha:wallet:v1:"

    /** Length of every wallet V1 digest. */
    const val DIGEST_BYTES: Int = 32

    /** Maximum complete envelope frame for Offer and SessionControl. */
    const val SESSION_MAX_BYTES: Int = 2_048

    /**
     * Maximum complete envelope frame for Request, Payment, Credited, PolicyData and Lineage.
     *
     * σ and Ω byte caps are the exact proof lengths of the frozen σ verifying-key allowlist
     * (owner answer Q6), with Ω plus the largest σ_send at most [PAYMENT_PROOF_BUDGET_BYTES] and
     * σ_recv at most [CREDITED_RECEIVE_PROOF_BUDGET_BYTES] and Ω at most [LINEAGE_PROOF_CAP_BYTES].
     * Until the artifacts freeze (TODO(G3)) only the carrying frame bounds them, which is all a
     * structural carrier check enforces.
     */
    const val MESSAGE_MAX_BYTES: Int = 10_000

    /** `F_payment`: the bytes of a Payment envelope frame other than its Ω and σ_send proofs. */
    const val PAYMENT_FIXED_BYTES: Int = 1_723

    /** Joint budget of the Ω transport proof and the largest σ_send (R9): `10,000 − F_payment`. */
    const val PAYMENT_PROOF_BUDGET_BYTES: Int = MESSAGE_MAX_BYTES - PAYMENT_FIXED_BYTES

    /** Bytes of a Credited::Receive envelope other than its σ proof. */
    const val CREDITED_RECEIVE_FIXED_BYTES: Int = 679

    /** Available σ bytes in a complete Credited::Receive envelope. */
    const val CREDITED_RECEIVE_PROOF_BUDGET_BYTES: Int = MESSAGE_MAX_BYTES - CREDITED_RECEIVE_FIXED_BYTES

    /**
     * `F_status`: the bytes of a Credited::Status envelope frame other than its Ω(h) transport
     * proof, with the fixed 32-sibling credit opening.
     */
    const val CREDITED_STATUS_FIXED_BYTES: Int = 2_188

    /** Cap of the Ω transport proof so that Credited::Status fits: `10,000 − F_status`. */
    const val LINEAGE_PROOF_CAP_BYTES: Int = MESSAGE_MAX_BYTES - CREDITED_STATUS_FIXED_BYTES

    /**
     * Maximum σ entries of the verifying-key allowlist: one per operation, Send also once per
     * supported enabled-controls mask, and Receive also once with the blacklist bit.
     */
    const val VERIFYING_KEY_ENTRIES_MAX: Int = 16

    /** Maximum standalone canonical frame of the σ verifying-key allowlist. */
    const val VERIFYING_KEY_ALLOWLIST_MAX_BYTES: Int = 2_048

    /**
     * Depth of every Poseidon indexed map tree and of the credit-digest tree (owner answer A2):
     * every opening carries exactly this many siblings.
     */
    const val INDEXED_TREE_DEPTH: Int = 32

    /** Depth of the quota-window and aligned quota-usage arrays. */
    const val QUOTA_TREE_DEPTH: Int = 6

    /** Exact number of slots in each quota-usage array. */
    const val QUOTA_USAGE_SLOTS: Int = 1 shl QUOTA_TREE_DEPTH

    /**
     * Exact credit-opening transcript of a CreditStatus: `credit_id || payment_digest || u8 burned
     * || next_key || LE32 slot || 32 siblings`.
     */
    const val CREDIT_OPENING_BYTES: Int = 3 * 32 + 1 + 4 + INDEXED_TREE_DEPTH * 32

    /** Length of one canonical little-endian σ-field value (Pasta `Fp`). */
    const val FIELD_VALUE_BYTES: Int = 32

    /** Length of a signing message `m`: one canonical σ-field value (wire record section 1). */
    const val SIGNING_MESSAGE_BYTES: Int = FIELD_VALUE_BYTES

    /** Maximum complete `kgm1:` text for a session-bounded envelope. */
    const val SESSION_TEXT_MAX_BYTES: Int = 2_736

    /** Maximum complete `kgm1:` text for a message-bounded envelope. */
    const val MESSAGE_TEXT_MAX_BYTES: Int = 13_339

    /** Maximum certificates in one certificate set. */
    const val CERTIFICATE_SET_MAX: Int = 3

    /** Norito frame name of the envelope; its schema hash is derived from this name. */
    const val ENVELOPE_FRAME_NAME: String =
        "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnvelopeV1"

    /** Archive alignment of the envelope payload (it contains `u128`). */
    const val ENVELOPE_PAYLOAD_ALIGNMENT: Int = 16

    /** Exact zero padding between the 40-byte header and the envelope payload. */
    const val ENVELOPE_PADDING_BYTES: Int =
        (ENVELOPE_PAYLOAD_ALIGNMENT - NoritoHeader.HEADER_LENGTH % ENVELOPE_PAYLOAD_ALIGNMENT) %
            ENVELOPE_PAYLOAD_ALIGNMENT

    /** Exact header flags of every canonical envelope frame (`COMPACT_LEN`). */
    const val ENVELOPE_FLAGS: Int = NoritoHeader.COMPACT_LEN

    private const val PAYLOAD_OFFSET: Int = NoritoHeader.HEADER_LENGTH + ENVELOPE_PADDING_BYTES
    private const val SCHEMA_HASH_OFFSET: Int = 6
    private const val COMPRESSION_OFFSET: Int = 22
    private const val PAYLOAD_LENGTH_OFFSET: Int = 23
    private const val CRC64_OFFSET: Int = 31
    private const val FLAGS_OFFSET: Int = 39
    private const val VERSION_FIELD_BYTES: Long = 2L
    private const val TAG_BYTES: Int = 4

    // Top-level field layouts of the bound messages (wire record section 3.4).
    private const val REQUEST_FIELDS: Int = 5
    private const val REQUEST_BODY_FIELD: Int = 0
    private const val REQUEST_SIGNATURE_FIELD: Int = 4
    private const val REQUEST_BODY_FIELDS: Int = 19
    private const val REQUEST_BODY_SCHEME_FIELD: Int = 1
    private const val REQUEST_BODY_AMOUNT_FIELD: Int = 9
    private const val PAYMENT_FIELDS: Int = 5
    private const val PAYMENT_REQUEST_FIELD: Int = 1
    private const val SIGNED_REQUEST_FIELDS: Int = 2
    private const val SIGNED_REQUEST_BODY_FIELD: Int = 0
    private const val SIGNED_REQUEST_SIGNATURE_FIELD: Int = 1
    private const val CREDITED_FIELDS: Int = 3
    private const val CREDITED_SCHEME_FIELD: Int = 1

    private val DIGEST_PREFIX_BYTES: ByteArray = DIGEST_PREFIX.toByteArray(Charsets.US_ASCII)
    private val ENVELOPE_SCHEMA_HASH: ByteArray = SchemaHash.hash16(ENVELOPE_FRAME_NAME)

    /** `p` of the σ field, Pasta `Fp` (the Vesta scalar field). */
    private val FIELD_MODULUS: BigInteger =
        BigInteger("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)

    /** 16-byte Norito schema hash of [ENVELOPE_FRAME_NAME]; a defensive copy. */
    @JvmStatic
    fun envelopeSchemaHash(): ByteArray = ENVELOPE_SCHEMA_HASH.copyOf()

    /** The σ field modulus `p` as [FIELD_VALUE_BYTES] little-endian bytes; a fresh array. */
    @JvmStatic
    fun fieldModulus(): ByteArray =
        ByteArray(FIELD_VALUE_BYTES) { index -> FIELD_MODULUS.shiftRight(8 * index).toInt().toByte() }

    /**
     * Whether [value] is one canonical σ-field value: exactly [FIELD_VALUE_BYTES] bytes whose
     * little-endian integer is below `p`.
     *
     * Every Poseidon value of the protocol (`credit_id`, `proof_digest`, the Payment, lineage,
     * credit-opening, credit-status and credited digests, every signing message, the state
     * commitment, chains, map, blacklist, quota-window and credit-digest roots and their opening
     * siblings) is computed by the native Rust core; Kotlin checks only this encoding and
     * otherwise treats the value as opaque.
     */
    @JvmStatic
    fun isCanonicalFieldValue(value: ByteArray): Boolean =
        value.size == FIELD_VALUE_BYTES && BigInteger(1, value.reversedArray()) < FIELD_MODULUS

    /**
     * Defensive copy of [value] after requiring it to be a canonical σ-field value
     * ([isCanonicalFieldValue]) that is also nonzero when [nonzero] is set.
     *
     * @throws IllegalArgumentException for another length, a value of at least `p`, or a zero
     * value where a nonzero one is required.
     */
    @JvmStatic
    @JvmOverloads
    fun requireCanonicalFieldValue(value: ByteArray, nonzero: Boolean = false): ByteArray {
        require(value.size == FIELD_VALUE_BYTES) {
            "KAGEMUSHA wallet V1 field value must be exactly $FIELD_VALUE_BYTES bytes"
        }
        require(isCanonicalFieldValue(value)) { "KAGEMUSHA wallet V1 field value is not canonical" }
        require(!nonzero || value.any { it.toInt() != 0 }) { "KAGEMUSHA wallet V1 field value is zero" }
        return value.copyOf()
    }

    /** Exact `kgm1:` text length of a frame of [frameBytes]: the prefix and unpadded base64url. */
    @JvmStatic
    fun textBytesForFrame(frameBytes: Int): Int {
        require(frameBytes in 0..MESSAGE_MAX_BYTES) {
            "KAGEMUSHA wallet V1 frame length $frameBytes is outside 0..$MESSAGE_MAX_BYTES"
        }
        val remainder = frameBytes % 3
        val tail = if (remainder == 0) 0 else remainder + 1
        return TEXT_PREFIX.length + frameBytes / 3 * 4 + tail
    }

    /**
     * Exact SHA-256 preimage of `H(role, body)`: `prefix || role || 0x00 || LE64(len(body)) ||
     * body`. It is never a signed message; signatures sign the Poseidon message `m` of their
     * [KagemushaWalletSigningDomainV1].
     */
    @JvmStatic
    fun preimage(role: KagemushaWalletDigestRoleV1, body: ByteArray): ByteArray {
        val label = role.label.toByteArray(Charsets.US_ASCII)
        val out = ByteArray(DIGEST_PREFIX_BYTES.size + label.size + 1 + 8 + body.size)
        var cursor = 0
        DIGEST_PREFIX_BYTES.copyInto(out, cursor)
        cursor += DIGEST_PREFIX_BYTES.size
        label.copyInto(out, cursor)
        cursor += label.size
        out[cursor] = 0
        cursor += 1
        val length = body.size.toLong()
        for (index in 0 until 8) {
            out[cursor + index] = (length ushr (8 * index)).toByte()
        }
        cursor += 8
        body.copyInto(out, cursor)
        return out
    }

    /** Domain-separated digest `H(role, body) = SHA-256(preimage(role, body))`. */
    @JvmStatic
    fun digest(role: KagemushaWalletDigestRoleV1, body: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(preimage(role, body))

    /**
     * Artifact manifest digest, `H(artifact-manifest, m || signature)`, where `m` is its
     * 32-byte Poseidon signing message and the signature is the canonical 64-byte low-S
     * `r || s`.
     *
     * @throws IllegalArgumentException for a message that is not a canonical σ-field value or a
     * non-canonical signature.
     */
    @JvmStatic
    fun artifactManifestDigest(
        message: ByteArray,
        rawSignature: ByteArray,
    ): ByteArray {
        require(message.size == SIGNING_MESSAGE_BYTES && isCanonicalFieldValue(message)) {
            "KAGEMUSHA wallet V1 signing message must be one canonical $SIGNING_MESSAGE_BYTES-byte field value"
        }
        val signature = KagemushaP256Codec.requireRawLowSSignature(rawSignature)
        return digest(KagemushaWalletDigestRoleV1.ARTIFACT_MANIFEST, message + signature)
    }

    /**
     * Verify one received low-S ECDSA-P256-SHA256 signature over the 32-byte signing message
     * [message] (wire record section 1): the ECDSA hash is `SHA-256(message)`.
     *
     * The message must be one canonical σ-field value, the Poseidon `P_bytes(d, transcript)` that
     * the native core computed for the body's [KagemushaWalletSigningDomainV1]; the signature
     * then passes [KagemushaP256Codec.verifyRawLowS], which rejects high S before JCA. Received
     * bytes are never normalized.
     *
     * Returns `false` for another message length, a non-canonical message, key or signature, and
     * a signature that does not verify.
     */
    @JvmStatic
    fun verifySignature(publicKeySec1: ByteArray, message: ByteArray, rawSignature: ByteArray): Boolean =
        message.size == SIGNING_MESSAGE_BYTES &&
            isCanonicalFieldValue(message) &&
            KagemushaP256Codec.verifyRawLowS(publicKeySec1, message, rawSignature)

    /**
     * Encode one canonical frame as `kgm1:` and unpadded base64url.
     *
     * The frame must be non-empty and at most [MESSAGE_MAX_BYTES], the domain that [decodeText]
     * accepts, so every produced text decodes back to the same bytes.
     */
    @JvmStatic
    fun encodeText(frame: ByteArray): String {
        require(frame.isNotEmpty()) { "KAGEMUSHA wallet V1 frame is empty" }
        require(frame.size <= MESSAGE_MAX_BYTES) {
            "KAGEMUSHA wallet V1 frame exceeds $MESSAGE_MAX_BYTES bytes"
        }
        return TEXT_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(frame)
    }

    /**
     * Strictly decode `kgm1:` text into frame bytes, with the rules of the Rust codec in order:
     * at most [MESSAGE_TEXT_MAX_BYTES], the exact prefix, a non-empty body of only the base64url
     * alphabet (no padding or whitespace), a body length that is not `1 mod 4`, and re-encoding
     * equality (which rejects nonzero trailing bits).
     */
    @JvmStatic
    fun decodeText(text: String): ByteArray {
        require(text.length <= MESSAGE_TEXT_MAX_BYTES) {
            "KAGEMUSHA wallet V1 text exceeds $MESSAGE_TEXT_MAX_BYTES bytes"
        }
        require(text.startsWith(TEXT_PREFIX)) { "KAGEMUSHA wallet V1 text prefix is invalid" }
        val body = text.substring(TEXT_PREFIX.length)
        require(body.isNotEmpty()) { "KAGEMUSHA wallet V1 text body is empty" }
        require(body.all(::isBase64UrlCharacter)) { "KAGEMUSHA wallet V1 text alphabet is invalid" }
        require(body.length % 4 != 1) { "KAGEMUSHA wallet V1 text length is invalid" }
        val frame = try {
            Base64.getUrlDecoder().decode(body)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("KAGEMUSHA wallet V1 base64url is invalid", error)
        }
        require(Base64.getUrlEncoder().withoutPadding().encodeToString(frame) == body) {
            "KAGEMUSHA wallet V1 base64url is non-canonical"
        }
        return frame
    }

    /**
     * Validate one canonical envelope frame header and its per-kind bound.
     *
     * Checks: the largest bound before parsing; magic, major and minor
     * version; the schema hash of [ENVELOPE_FRAME_NAME]; no compression; flags exactly
     * [ENVELOPE_FLAGS]; exactly [ENVELOPE_PADDING_BYTES] zero padding bytes; the payload length;
     * the CRC64; the envelope version field and the exact field spans of the message; a known
     * message tag; the message's own version and 32-byte decode-time scheme field; and finally
     * the bound of the kind that tag selects.
     *
     * The carried message is not fully decoded or authenticated. These structural checks do not
     * select a trusted scheme or authorize a payment.
     * TODO(G4): decode and validate the typed wallet message once the Kotlin exchange
     * integration owns the typed codec.
     *
     * @throws IllegalArgumentException for any violation.
     */
    @JvmStatic
    fun inspectEnvelope(frame: ByteArray): KagemushaWalletEnvelopeFrameV1 {
        val bytes = frame.copyOf()
        require(bytes.size <= MESSAGE_MAX_BYTES) {
            "KAGEMUSHA wallet V1 envelope exceeds $MESSAGE_MAX_BYTES bytes"
        }
        require(bytes.size > PAYLOAD_OFFSET) { "KAGEMUSHA wallet V1 envelope is truncated" }
        require(bytes.copyOfRange(0, NoritoHeader.MAGIC.size).contentEquals(NoritoHeader.MAGIC)) {
            "KAGEMUSHA wallet V1 envelope magic is invalid"
        }
        require(
            unsigned(bytes[4]) == NoritoHeader.MAJOR_VERSION &&
                unsigned(bytes[5]) == NoritoHeader.MINOR_VERSION,
        ) { "KAGEMUSHA wallet V1 envelope Norito version is unsupported" }
        require(
            bytes.copyOfRange(SCHEMA_HASH_OFFSET, SCHEMA_HASH_OFFSET + ENVELOPE_SCHEMA_HASH.size)
                .contentEquals(ENVELOPE_SCHEMA_HASH),
        ) { "KAGEMUSHA wallet V1 envelope schema hash does not match $ENVELOPE_FRAME_NAME" }
        require(unsigned(bytes[COMPRESSION_OFFSET]) == NoritoHeader.COMPRESSION_NONE) {
            "KAGEMUSHA wallet V1 envelope must not be compressed"
        }
        val flags = unsigned(bytes[FLAGS_OFFSET])
        require(flags == ENVELOPE_FLAGS) { "KAGEMUSHA wallet V1 envelope flags are not canonical" }
        for (index in NoritoHeader.HEADER_LENGTH until PAYLOAD_OFFSET) {
            require(bytes[index].toInt() == 0) { "KAGEMUSHA wallet V1 envelope padding is not zero" }
        }
        val payloadLength = bytes.size - PAYLOAD_OFFSET
        require(readLongLe(bytes, PAYLOAD_LENGTH_OFFSET) == payloadLength.toLong()) {
            "KAGEMUSHA wallet V1 envelope payload length does not match the frame"
        }
        val payload = bytes.copyOfRange(PAYLOAD_OFFSET, bytes.size)
        val crc64 = readLongLe(bytes, CRC64_OFFSET)
        require(CRC64.compute(payload) == crc64) { "KAGEMUSHA wallet V1 envelope CRC64 mismatch" }
        val kind = envelopeKind(payload)
        require(bytes.size <= kind.maximumFrameBytes) {
            "KAGEMUSHA wallet V1 ${kind.label} envelope exceeds ${kind.maximumFrameBytes} bytes"
        }
        return KagemushaWalletEnvelopeFrameV1(
            bytes,
            kind,
            flags,
            ENVELOPE_PADDING_BYTES,
            payloadLength,
            crc64,
        )
    }

    /** Strictly decode `kgm1:` text and validate the envelope frame it carries. */
    @JvmStatic
    fun decodeEnvelopeText(text: String): KagemushaWalletEnvelopeFrameV1 {
        val envelope = inspectEnvelope(decodeText(text))
        require(text.length <= envelope.kind.maximumTextBytes) {
            "KAGEMUSHA wallet V1 ${envelope.kind.label} text exceeds ${envelope.kind.maximumTextBytes} bytes"
        }
        return envelope
    }

    /**
     * Require that one exchange's envelopes are structurally bound: [payment] carries exactly the
     * signed Request of [request], and [credited], when present, is evidence under that Request's
     * scheme.
     *
     * Each frame is first checked by [inspectEnvelope], must have the kind of its parameter and
     * must split into exactly the record fields of its message (wire record section 3.4: Request
     * `{body, receiver_credential, fee_schedule, certificates, signature}` with a 19-field body,
     * compact Payment `{version, request: {body, signature}, payer_payment_key,
     * payer_credential_digest, send}`, Credited `{version, scheme_id, evidence}`). The comparisons
     * are over exact canonical field bytes: the Payment's signed Request body and signature are
     * the Request's, and the Credited `scheme_id` is the Request body's `scheme_id`. A carrier thus
     * rejects a Payment that belongs to another Request, and Credited evidence under another
     * scheme, before handing either to the wallet. No digest or signature is checked here and
     * nothing grants monetary authority.
     * TODO(G4): the typed decoder also checks the Credited evidence against the held Request and
     * the retained Payment (its credit, payer wallet and amount, or its opening, and the Payment
     * digest the evidence binds). The receiver is matched by the Request's receiver wallet and
     * its receiver credential's payment key, never by credential digest, so evidence from a
     * receiver that renewed its credential after quoting the Request still matches (owner
     * answer Q8).
     *
     * @throws IllegalArgumentException for any violation.
     */
    @JvmStatic
    @JvmOverloads
    fun requireExchangeBinding(request: ByteArray, payment: ByteArray, credited: ByteArray? = null) {
        val requestFields = messageFields(request, KagemushaWalletMessageKindV1.REQUEST, REQUEST_FIELDS)
        val requestBody = recordFields(requestFields[REQUEST_BODY_FIELD], REQUEST_BODY_FIELDS, "Request body")
        val paymentFields = messageFields(payment, KagemushaWalletMessageKindV1.PAYMENT, PAYMENT_FIELDS)
        val signedRequest = recordFields(
            paymentFields[PAYMENT_REQUEST_FIELD],
            SIGNED_REQUEST_FIELDS,
            "Payment signed Request",
        )
        require(
            signedRequest[SIGNED_REQUEST_BODY_FIELD].contentEquals(requestFields[REQUEST_BODY_FIELD]) &&
                signedRequest[SIGNED_REQUEST_SIGNATURE_FIELD].contentEquals(
                    requestFields[REQUEST_SIGNATURE_FIELD],
                ),
        ) { "KAGEMUSHA wallet V1 Payment does not carry this Request" }
        if (credited != null) {
            val creditedFields = messageFields(credited, KagemushaWalletMessageKindV1.CREDITED, CREDITED_FIELDS)
            require(creditedFields[CREDITED_SCHEME_FIELD].contentEquals(requestBody[REQUEST_BODY_SCHEME_FIELD])) {
                "KAGEMUSHA wallet V1 Credited does not name this Request's scheme"
            }
        }
    }

    /** Exact unsigned amount carried in the Payment's signed Request, for display only.
     * This bounded structural parser authenticates nothing. A wallet must first obtain the
     * exact Payment from its genuine Native completion or authenticated retained Send.
     * Neither a decoded amount nor successful framing establishes a payment or receipt.
     */
    @JvmStatic
    fun paymentAmountData(payment: ByteArray): BigInteger {
        val fields = messageFields(payment, KagemushaWalletMessageKindV1.PAYMENT, PAYMENT_FIELDS)
        val signed = recordFields(fields[PAYMENT_REQUEST_FIELD], SIGNED_REQUEST_FIELDS, "Payment signed Request")
        val body = recordFields(signed[SIGNED_REQUEST_BODY_FIELD], REQUEST_BODY_FIELDS, "Request body")
        val amount = body[REQUEST_BODY_AMOUNT_FIELD]
        require(amount.size == 16) { "Payment amount must be canonical LE128" }
        return BigInteger(1, amount.reversedArray()).also { require(it.signum() > 0) { "Payment amount must be positive" } }
    }

    /**
     * The message of an envelope of [expected] kind, split into exactly [fieldCount] top-level
     * record fields.
     */
    private fun messageFields(
        frame: ByteArray,
        expected: KagemushaWalletMessageKindV1,
        fieldCount: Int,
    ): List<ByteArray> {
        val envelope = inspectEnvelope(frame)
        require(envelope.kind == expected) {
            "KAGEMUSHA wallet V1 ${envelope.kind.label} envelope is not a ${expected.label}"
        }
        // inspectEnvelope checked these spans: [len] version [len] (tag [len] message).
        val payload = frame.copyOfRange(PAYLOAD_OFFSET, frame.size)
        var cursor = Varint.decode(payload, 0).nextOffset + VERSION_FIELD_BYTES.toInt()
        cursor = Varint.decode(payload, cursor).nextOffset + TAG_BYTES
        val messageStart = Varint.decode(payload, cursor).nextOffset
        return recordFields(payload.copyOfRange(messageStart, payload.size), fieldCount, expected.label)
    }

    /**
     * Exact canonical bytes of the [fieldCount] compact-length fields `[len] field` that make up
     * [record] completely (Norito `COMPACT_LEN` record layout).
     */
    private fun recordFields(record: ByteArray, fieldCount: Int, label: String): List<ByteArray> {
        val fields = ArrayList<ByteArray>(fieldCount)
        var offset = 0
        while (offset < record.size) {
            require(fields.size < fieldCount) { "KAGEMUSHA wallet V1 $label has more than $fieldCount fields" }
            val field = Varint.decode(record, offset)
            require(field.value in 0L..(record.size - field.nextOffset).toLong()) {
                "KAGEMUSHA wallet V1 $label field exceeds the record"
            }
            offset = field.nextOffset + field.value.toInt()
            fields += record.copyOfRange(field.nextOffset, offset)
        }
        require(fields.size == fieldCount) { "KAGEMUSHA wallet V1 $label has ${fields.size} of $fieldCount fields" }
        return fields
    }

    /**
     * Read the envelope payload `[len] version: u16 [len] (u32 tag [len] variant)` with compact
     * lengths, requiring version 1, exact field spans and a known tag.
     */
    private fun envelopeKind(payload: ByteArray): KagemushaWalletMessageKindV1 {
        val versionField = Varint.decode(payload, 0)
        require(versionField.value == VERSION_FIELD_BYTES) {
            "KAGEMUSHA wallet V1 envelope version field is not two bytes"
        }
        var cursor = versionField.nextOffset
        require(cursor + VERSION_FIELD_BYTES.toInt() <= payload.size) {
            "KAGEMUSHA wallet V1 envelope is truncated"
        }
        val version = unsigned(payload[cursor]) or (unsigned(payload[cursor + 1]) shl 8)
        require(version == VERSION) { "KAGEMUSHA wallet V1 envelope version $version is unsupported" }
        cursor += VERSION_FIELD_BYTES.toInt()
        val messageField = Varint.decode(payload, cursor)
        cursor = messageField.nextOffset
        require(messageField.value == (payload.size - cursor).toLong()) {
            "KAGEMUSHA wallet V1 envelope message field does not span the payload"
        }
        require(payload.size - cursor > TAG_BYTES) { "KAGEMUSHA wallet V1 envelope message is truncated" }
        val tag = readIntLe(payload, cursor)
        val kind = KagemushaWalletMessageKindV1.fromWireTag(tag)
            ?: throw IllegalArgumentException("KAGEMUSHA wallet V1 envelope message tag $tag is unknown")
        cursor += TAG_BYTES
        val variantField = Varint.decode(payload, cursor)
        cursor = variantField.nextOffset
        require(variantField.value > 0L && variantField.value == (payload.size - cursor).toLong()) {
            "KAGEMUSHA wallet V1 envelope ${kind.label} field does not span the message"
        }
        val message = payload.copyOfRange(cursor, payload.size)
        val versionPath = when (kind) {
            KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> intArrayOf(0, 0)
            else -> intArrayOf(0)
        }
        val messageVersion = messageField(message, versionPath, "message version")
        require(messageVersion.size == VERSION_FIELD_BYTES.toInt()) {
            "KAGEMUSHA wallet V1 message version field is not two bytes"
        }
        require((unsigned(messageVersion[0]) or (unsigned(messageVersion[1]) shl 8)) == VERSION) {
            "KAGEMUSHA wallet V1 message version is unsupported"
        }
        val schemePath = when (kind) {
            KagemushaWalletMessageKindV1.OFFER, KagemushaWalletMessageKindV1.REQUEST -> intArrayOf(0, 1)
            KagemushaWalletMessageKindV1.PAYMENT, KagemushaWalletMessageKindV1.LINEAGE -> intArrayOf(1, 0, 1)
            else -> intArrayOf(1)
        }
        require(messageField(message, schemePath, "scheme identity").size == DIGEST_BYTES) {
            "KAGEMUSHA wallet V1 decode-time scheme field is not 32 bytes"
        }
        return kind
    }

    /** Read only the fixed field path needed for structural version or scheme admission. */
    private fun messageField(record: ByteArray, path: IntArray, label: String): ByteArray =
        path.fold(record) { current, index ->
            var offset = 0
            var selected: ByteArray? = null
            for (position in 0..index) {
                require(offset < current.size) { "KAGEMUSHA wallet V1 $label field is missing" }
                val field = Varint.decode(current, offset)
                require(field.value in 0L..(current.size - field.nextOffset).toLong()) {
                    "KAGEMUSHA wallet V1 $label field exceeds its record"
                }
                offset = field.nextOffset + field.value.toInt()
                if (position == index) selected = current.copyOfRange(field.nextOffset, offset)
            }
            checkNotNull(selected)
        }

    private fun readLongLe(bytes: ByteArray, offset: Int): Long {
        var value = 0L
        for (index in 7 downTo 0) {
            value = (value shl 8) or unsigned(bytes[offset + index]).toLong()
        }
        return value
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int {
        var value = 0
        for (index in 3 downTo 0) {
            value = (value shl 8) or unsigned(bytes[offset + index])
        }
        return value
    }

    private fun unsigned(value: Byte): Int = value.toInt() and 0xff

    private fun isBase64UrlCharacter(character: Char): Boolean =
        character in 'A'..'Z' ||
            character in 'a'..'z' ||
            character in '0'..'9' ||
            character == '-' ||
            character == '_'
}
