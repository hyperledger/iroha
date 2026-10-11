// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.crypto.Ed25519PublicKeyAdmission
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/**
 * Eligibility middleware protocol and callback adapter. Authenticate the issuer transport,
 * select current authority policy independently, and resolve actor/account/provider binding in
 * the lookup. Bank approval includes required KYC. Scheme operators require authenticated
 * asset/scheme-owner selection; missing bank data never selects one. Policy DATA grants no authority.
 *
 * The adapter generates no key, persists no secret or customer document, caches no decision,
 * and grants no enrollment/monetary capability. All u64 values are exact positive BigIntegers.
 */
object KagemushaEnrollmentEligibilityV1 {
    const val MAX_FRAME_BYTES = 2048
    private const val PREFIX = "iroha.kagemusha.eligibility."
    private const val FLAGS = NoritoHeader.COMPACT_LEN
    private val MAX_U64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
    private val ORDER = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

    enum class Authority { BANK, SCHEME_OPERATOR }
    enum class Purpose { PRE_KEY_PERMIT, VERIFY_EVIDENCE, ISSUE_CREDENTIAL, DELIVER_CREDENTIAL }
    enum class Decision { APPROVED_UNFROZEN, NOT_APPROVED, FROZEN }
    enum class FailureCode { INVALID_REQUEST, UNAVAILABLE, CLOCK, INVALID_OBSERVATION, SIGNING, SIGNATURE }
    class Failure(val code: FailureCode, cause: Exception? = null) :
        IllegalArgumentException("enrollment eligibility: ${code.name}", cause)

    /** Positive genuine Unix time; callback exceptions are clock failures. */
    fun interface Clock { fun nowMs(): BigInteger }
    /** One authenticated atomic current-source read. Unknown/unavailable subjects must throw. */
    fun interface CurrentLookup { fun read(asset: AssetScope, policy: Policy, request: Request): Current }
    /**
     * Sign the exact 32-byte message with ordinary Ed25519 using existing provider-owned custody.
     * Do not apply the transaction signer's additional IrohaHash prehash or Ed25519ph mode.
     */
    fun interface Signer { fun sign(message: ByteArray): ByteArray }

    /** Current read time is not a record's last-update time. Frozen takes precedence. */
    class Current(val approved: Boolean, val frozen: Boolean, val revision: BigInteger, val observedAtMs: BigInteger)

    /** Authenticated by the middleware deployment owner; decoding this DATA confers no approval. */
    class PolicyTemplate private constructor(original: ByteArray, private val fields: List<ByteArray>) {
        private val original = original.copyOf()
        private val network = identity(fields[1]); private val scheme = identity(fields[2])
        val revision: BigInteger = positive(fields[3])
        private val authorityFields = variant(fields[4])
        val authority: Authority = when (authorityFields.first) { 1 -> Authority.BANK; 2 -> Authority.SCHEME_OPERATOR; else -> invalid() }
        private val authorityId = identity(parseFields(authorityFields.second, 1)[0])
        private val key = fixed(fields[5], 32)
        val maximumResponseMs: BigInteger = positive(fields[6])
        init { version(fields[0]); require(Ed25519PublicKeyAdmission.isValid(key)) }
        fun originalBytes(): ByteArray = original.copyOf()
        fun networkId(): ByteArray = network.copyOf()
        fun schemeId(): ByteArray = scheme.copyOf()
        fun scopeDigest(): ByteArray = authorityId.copyOf()
        fun publicKey(): ByteArray = key.copyOf()
        /** Exact policy DATA; the issuer still authenticates registration before dispatch. */
        fun forAsset(asset: AssetScope): Policy = Policy.parse(frame("policy", listOf(
            fields[0], fields[1], fields[2], asset.digest(), fields[3], fields[4], fields[5], fields[6])))
        companion object {
            internal fun parse(original: ByteArray): PolicyTemplate = PolicyTemplate(original, unframe(original, "policy_template", 7))
        }
    }

    /** Exact canonical token/incarnation/scale DATA, without registration authority. */
    class AssetScope private constructor(private val fields: List<ByteArray>) {
        private val id = parseFields(fields[1], 16).map { fixed(it, 1)[0] }.toByteArray()
        private val incarnation = identity(fields[2])
        val scale: Int = BigInteger(1, fixed(fields[3], 4).reversedArray()).intValueExact()
        init {
            version(fields[0]); require((id[6].toInt() and 0xf0) == 0x40 && (id[8].toInt() and 0xc0) == 0x80)
            require((incarnation[31].toInt() and 1) == 1)
            require(incarnation.take(31).any { it != 0.toByte() } || (incarnation[31].toInt() and 0xfe) != 0)
            require(scale in 0..28)
        }
        fun assetDefinitionBytes(): ByteArray = id.copyOf()
        fun incarnationBytes(): ByteArray = incarnation.copyOf()
        fun originalBytes(): ByteArray = namedFrame(ASSET_SCHEMA, fields)
        fun digest(): ByteArray = KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ASSET_SCOPE,
            byteArrayOf(1, 0) + id + incarnation + fields[3])
        companion object {
            private const val ASSET_SCHEMA = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAssetScopeV1"
            internal fun payload(original: ByteArray): AssetScope = AssetScope(parseFields(original, 4))
        }
    }

    /** Bounded middleware envelope whose asset only supplies exact request-policy context. */
    class Observation private constructor(original: ByteArray, fields: List<ByteArray>, template: PolicyTemplate) {
        private val original = original.copyOf()
        val asset: AssetScope = AssetScope.payload(fields[1])
        val policy: Policy = template.forAsset(asset)
        val request: Request = Request.parse(policy, frame("request", parseFields(fields[2], 10)))
        init { version(fields[0]) }
        fun originalBytes(): ByteArray = original.copyOf()
        companion object {
            internal fun parse(template: PolicyTemplate, original: ByteArray): Observation = Observation(original, unframe(original, "observation", 3), template)
        }
    }

    /** Canonical policy DATA; authority selection, routing and revocation remain caller duties. */
    class Policy private constructor(original: ByteArray, fields: List<ByteArray>) {
        private val original = original.copyOf()
        private val network = identity(fields[1]); private val scheme = identity(fields[2])
        private val asset = identity(fields[3]); private val key = fixed(fields[6], 32)
        val revision: BigInteger = positive(fields[4])
        private val authorityFields = variant(fields[5])
        val authority: Authority = when (authorityFields.first) { 1 -> Authority.BANK; 2 -> Authority.SCHEME_OPERATOR; else -> invalid() }
        private val authorityId = identity(parseFields(authorityFields.second, 1)[0])
        val maximumResponseMs: BigInteger = positive(fields[7])
        init {
            version(fields[0])
            require(Ed25519PublicKeyAdmission.isValid(key))
        }
        fun originalBytes(): ByteArray = original.copyOf()
        fun networkId(): ByteArray = network.copyOf()
        fun schemeId(): ByteArray = scheme.copyOf()
        fun assetDigest(): ByteArray = asset.copyOf()
        /** Exact selected Bank FI or SchemeOperator identity. */
        fun scopeDigest(): ByteArray = authorityId.copyOf()
        fun publicKey(): ByteArray = key.copyOf()
        fun digest(): ByteArray = hash("policy", original)
        companion object {
            internal fun parse(original: ByteArray): Policy = Policy(original, unframe(original, "policy", 8))
        }
    }

    /** Exact issuer request; parsing does not authenticate its transport or subject routing. */
    class Request private constructor(original: ByteArray, fields: List<ByteArray>, policy: Policy) {
        private val original = original.copyOf()
        private val policyId = identity(fields[1]); private val account = identity(fields[2])
        private val actor = identity(fields[3]); private val attempt = identity(fields[4])
        private val nonce = identity(fields[5]); private val operation = identity(fields[6])
        val purpose: Purpose = enum(fields[7], Purpose.values())
        val requestedAtMs: BigInteger = positive(fields[8])
        val expiresAtMs: BigInteger = positive(fields[9])
        init {
            version(fields[0]); require(policyId.contentEquals(policy.digest()))
            require(expiresAtMs > requestedAtMs && expiresAtMs.subtract(requestedAtMs) <= policy.maximumResponseMs)
        }
        fun originalBytes(): ByteArray = original.copyOf()
        fun policyDigest(): ByteArray = policyId.copyOf()
        fun accountDigest(): ByteArray = account.copyOf()
        fun actorDigest(): ByteArray = actor.copyOf()
        fun attemptId(): ByteArray = attempt.copyOf()
        fun nonce(): ByteArray = nonce.copyOf()
        fun operationDigest(): ByteArray = operation.copyOf()
        fun digest(): ByteArray = hash("request", original)
        companion object {
            internal fun parse(policy: Policy, original: ByteArray): Request = Request(original, unframe(original, "request", 10), policy)
        }
    }

    /** Verified observation for one exact request, not a reusable authorization token. */
    class Response private constructor(original: ByteArray, fields: List<ByteArray>) {
        private val original = original.copyOf()
        private val bodyFields = parseFields(fields[0], 6)
        private val request = identity(bodyFields[1])
        private val signature = fixed(fields[1], 64)
        val decision: Decision = enum(bodyFields[2], Decision.values())
        val sourceRevision: BigInteger = positive(bodyFields[3])
        val observedAtMs: BigInteger = positive(bodyFields[4])
        val validUntilMs: BigInteger = positive(bodyFields[5])
        init { version(bodyFields[0]); require(validUntilMs > observedAtMs); requireSignature(signature) }
        fun originalBytes(): ByteArray = original.copyOf()
        fun requestDigest(): ByteArray = request.copyOf()
        fun signature(): ByteArray = signature.copyOf()
        fun signingMessage(): ByteArray = hash("response", frame("response_body", bodyFields))
        internal fun verify(policy: Policy, request: Request, now: BigInteger) {
            u64(now); require(this.request.contentEquals(request.digest()))
            require(request.policyDigest().contentEquals(policy.digest()))
            require(observedAtMs >= request.requestedAtMs && observedAtMs <= now)
            require(now < validUntilMs && validUntilMs <= request.expiresAtMs)
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(policy.publicKey(), 0))
            val message = signingMessage(); verifier.update(message, 0, message.size)
            require(verifier.verifySignature(signature))
        }
        companion object {
            internal fun parse(original: ByteArray): Response = Response(original, unframe(original, "response", 2))
        }
    }

    /** Decode template DATA; genuine middleware deployment selects and authenticates its authority. */
    @JvmStatic fun decodeTemplate(original: ByteArray): PolicyTemplate = checked(FailureCode.INVALID_REQUEST) { PolicyTemplate.parse(boundedOriginal(original)) }
    /** Decode the asset-bearing envelope against the independently selected template. */
    @JvmStatic fun decodeObservation(template: PolicyTemplate, original: ByteArray): Observation =
        checked(FailureCode.INVALID_REQUEST) { Observation.parse(template, boundedOriginal(original)) }

    /** Decode a bounded canonical policy. This never selects it as trusted authority. */
    @JvmStatic fun decodePolicy(original: ByteArray): Policy = checked(FailureCode.INVALID_REQUEST) { Policy.parse(boundedOriginal(original)) }
    @JvmStatic fun decodeRequest(policy: Policy, original: ByteArray): Request =
        checked(FailureCode.INVALID_REQUEST) { Request.parse(policy, boundedOriginal(original)) }
    /** Recheck current policy/routing externally before verification and nonce consumption. */
    @JvmStatic fun decodeResponse(policy: Policy, request: Request, nowMs: BigInteger, original: ByteArray): Response =
        checked(FailureCode.SIGNATURE) { Response.parse(boundedOriginal(original)).also { it.verify(policy, request, nowMs) } }

    /** One lookup, one signature and three genuine clock samples; no retry or cached approval. */
    @JvmStatic fun answer(template: PolicyTemplate, observationOriginal: ByteArray, clock: Clock, lookup: CurrentLookup, signer: Signer): ByteArray {
        val observation = decodeObservation(template, observationOriginal)
        val policy = observation.policy; val request = observation.request
        val started = checked(FailureCode.CLOCK) { clock.nowMs().also { live(request, it, request.requestedAtMs) } }
        val current = checked(FailureCode.UNAVAILABLE) { requireNotNull(lookup.read(observation.asset, policy, request)) }
        checked(FailureCode.INVALID_OBSERVATION) { positive(current.revision) }
        val readCompleted = checked(FailureCode.CLOCK) { clock.nowMs().also { live(request, it, started) } }
        checked(FailureCode.INVALID_OBSERVATION) {
            positive(current.observedAtMs)
            require(current.observedAtMs >= started && current.observedAtMs <= readCompleted)
        }
        val decision = if (current.frozen) Decision.FROZEN else if (current.approved) Decision.APPROVED_UNFROZEN else Decision.NOT_APPROVED
        val body = listOf(uint(BigInteger.ONE, 2), request.digest(), tag(decision.ordinal + 1),
            uint(current.revision, 8), uint(current.observedAtMs, 8), uint(request.expiresAtMs, 8))
        val message = hash("response", frame("response_body", body))
        val signature = checked(FailureCode.SIGNING) { signer.sign(message.copyOf()).copyOf() }
        val original = checked(FailureCode.SIGNATURE) { requireSignature(signature); frame("response", listOf(fields(body), signature)) }
        val completed = checked(FailureCode.CLOCK) { clock.nowMs().also { live(request, it, readCompleted) } }
        return decodeResponse(policy, request, completed, original).originalBytes()
    }

    private fun live(request: Request, now: BigInteger, floor: BigInteger) {
        positive(now); require(now >= floor && now >= request.requestedAtMs && now < request.expiresAtMs)
    }
    private inline fun <T> checked(code: FailureCode, operation: () -> T): T = try { operation() }
        catch (error: Exception) { throw Failure(code, error) }
    private fun invalid(): Nothing = throw IllegalArgumentException("invalid eligibility DATA")
    private fun boundedOriginal(original: ByteArray): ByteArray {
        require(original.size in NoritoHeader.HEADER_LENGTH..MAX_FRAME_BYTES)
        return original.copyOf()
    }
    private fun fixed(bytes: ByteArray, size: Int): ByteArray { require(bytes.size == size); return bytes.copyOf() }
    private fun identity(bytes: ByteArray): ByteArray = fixed(bytes, 32).also { require(it.any { byte -> byte != 0.toByte() }) }
    private fun version(bytes: ByteArray) { require(bytes.contentEquals(byteArrayOf(1, 0))) }
    private fun u64(value: BigInteger) { require(value.signum() >= 0 && value <= MAX_U64) }
    private fun positive(value: BigInteger): BigInteger { u64(value); require(value.signum() > 0); return value }
    private fun positive(bytes: ByteArray): BigInteger = positive(BigInteger(1, fixed(bytes, 8).reversedArray()))
    private fun uint(value: BigInteger, width: Int): ByteArray {
        require(value.signum() >= 0 && value.bitLength() <= width * 8)
        val bytes = value.toByteArray().reversedArray()
        return ByteArray(width) { if (it < bytes.size) bytes[it] else 0 }
    }
    private fun tag(value: Int): ByteArray = uint(BigInteger.valueOf(value.toLong()), 4)
    private fun <T> enum(bytes: ByteArray, values: Array<T>): T {
        val value = BigInteger(1, fixed(bytes, 4).reversedArray()).intValueExact()
        require(value in 1..values.size); return values[value - 1]
    }
    private fun variant(bytes: ByteArray): Pair<Int, ByteArray> {
        require(bytes.size >= 4)
        val tag = BigInteger(1, bytes.copyOfRange(0, 4).reversedArray()).intValueExact()
        return tag to bytes.copyOfRange(4, bytes.size)
    }
    private fun requireSignature(signature: ByteArray) {
        require(signature.size == 64)
        require(Ed25519PublicKeyAdmission.isValid(signature.copyOfRange(0, 32)))
        require(BigInteger(1, signature.copyOfRange(32, 64).reversedArray()) < ORDER)
    }
    private fun hash(role: String, original: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update("iroha:kagemusha:eligibility:$role:v1\u0000".toByteArray(Charsets.US_ASCII))
        update(uint(BigInteger.valueOf(original.size.toLong()), 8)); update(original)
    }.digest()
    private fun fields(values: List<ByteArray>): ByteArray = NoritoEncoder(FLAGS).apply {
        values.forEach { writeLength(it.size.toLong(), true); writeBytes(it) }
    }.toByteArray()
    private fun parseFields(payload: ByteArray, count: Int): List<ByteArray> {
        val decoder = NoritoDecoder(payload, FLAGS)
        val values = List(count) {
            val size = decoder.readLength(true)
            require(size in 0..MAX_FRAME_BYTES.toLong() && size <= decoder.remaining().toLong())
            decoder.readBytes(size.toInt())
        }
        require(decoder.remaining() == 0 && fields(values).contentEquals(payload))
        return values
    }
    private fun frame(kind: String, values: List<ByteArray>): ByteArray = namedFrame("$PREFIX$kind.v1", values)
    private fun namedFrame(schema: String, values: List<ByteArray>): ByteArray {
        val payload = fields(values)
        val header = NoritoHeader(SchemaHash.hash16(schema), payload.size, CRC64.compute(payload), FLAGS, NoritoHeader.COMPRESSION_NONE)
        return (header.encode() + payload).also { require(it.size <= MAX_FRAME_BYTES) }
    }
    private fun unframe(original: ByteArray, kind: String, count: Int): List<ByteArray> {
        require(original.size in NoritoHeader.HEADER_LENGTH..MAX_FRAME_BYTES)
        val decoded = NoritoHeader.decode(original, SchemaHash.hash16("$PREFIX$kind.v1"))
        require(decoded.header.flags == FLAGS && decoded.header.compression == NoritoHeader.COMPRESSION_NONE)
        decoded.header.validateChecksum(decoded.payload)
        val result = parseFields(decoded.payload, count)
        require(frame(kind, result).contentEquals(original))
        return result
    }
}
