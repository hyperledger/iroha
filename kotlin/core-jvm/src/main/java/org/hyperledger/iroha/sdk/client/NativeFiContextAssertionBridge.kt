package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Complete locally selected LinkApproval target. Construction does not authenticate ledger state. */
class NativeFiLinkApprovalTarget(
    val assetDefinitionId: String,
    val accountId: String,
    val fiAccountId: String,
    referenceDigest: ByteArray,
    val fiRevision: BigInteger,
    val attestationRevision: BigInteger,
    val revision: BigInteger,
    val expectedPolicyRevision: BigInteger,
    val enabled: Boolean,
    val controller: String?,
    val waterfall: Boolean,
    val reverseWaterfall: Boolean,
) {
    private val referenceHex = FiContextWire.raw32(referenceDigest)
    init {
        FiContextWire.text(assetDefinitionId, 128)
        FiContextWire.text(accountId, 1024); FiContextWire.text(fiAccountId, 1024)
        listOf(fiRevision, attestationRevision, revision, expectedPolicyRevision).forEach(FiContextWire::positiveU64)
        controller?.let { FiContextWire.text(it, 256) }
        require(accountId != fiAccountId)
        require(!(waterfall || reverseWaterfall) || (enabled && controller != null))
    }
    val referenceDigest: ByteArray get() = FiContextWire.decodeHex(referenceHex)
    override fun toString(): String = "NativeFiLinkApprovalTarget(unverified, redacted)"
    internal fun fields(): Map<String, Any?> = mapOf(
        "assetDefinitionId" to assetDefinitionId, "accountId" to accountId,
        "fiAccountId" to fiAccountId, "referenceDigest" to referenceHex,
        "fiRevision" to fiRevision, "attestationRevision" to attestationRevision,
        "revision" to revision, "expectedPolicyRevision" to expectedPolicyRevision,
        "enabled" to enabled, "controller" to controller,
        "waterfall" to waterfall, "reverseWaterfall" to reverseWaterfall,
    )
}

/**
 * Independently admitted local expectations, not a response DTO. Keep these together with the
 * original request/challenge and idempotency key before the first uncertain evidence submission.
 * The request digest is explicitly supplied from retained custody, never generated from a response.
 * Native validates every account/asset/controller and imports the pinned Global checkpoint.
 */
class NativeFiContextAssertionTrust(
    networkId: NetworkId,
    chainId: String,
    checkpointSha256: ByteArray,
    val checkpointHeight: BigInteger,
    checkpointContextId: ByteArray,
    assetOwner: String,
    assetIncarnation: ByteArray,
    uid: ByteArray,
    fiParticipant: String,
    uidController: String?,
    runtimeManifestSha256: ByteArray,
    ownerKeyIdentity: String,
    walletScopeCanonical: ByteArray,
    retainedRequestSha256: ByteArray,
    target: NativeFiLinkApprovalTarget,
) {
    internal val requestSha256Hex = FiContextWire.raw32(retainedRequestSha256)
    private val canonical: ByteArray
    init {
        FiContextWire.text(chainId, 1024); FiContextWire.text(assetOwner, 1024)
        FiContextWire.text(fiParticipant, 256); FiContextWire.text(ownerKeyIdentity, 256)
        uidController?.let { FiContextWire.text(it, 256) }
        FiContextWire.positiveU64(checkpointHeight)
        require(checkpointHeight < FiContextWire.U64_MAX)
        require(target.controller == null || target.controller == uidController)
        require(walletScopeCanonical.isNotEmpty() && walletScopeCanonical.size <= 16 * 1024)
        val scope = walletScopeCanonical.copyOf()
        val scopeText = FiContextWire.strictUtf8(scope, 16 * 1024)
        val scopeObject = JsonParser.parse(scopeText)
        require(scopeObject is Map<*, *>) { "Wallet scope must be an object" }
        require(JsonEncoder.encode(scopeObject) == scopeText) { "Wallet scope must be canonical" }
        canonical = JsonEncoder.encode(mapOf(
            "schema" to "iroha.fi-context-verification-trust.v1",
            "networkId" to networkId.literal, "chainId" to chainId,
            "checkpointSha256" to FiContextWire.raw32(checkpointSha256),
            "checkpointHeight" to checkpointHeight.toString(),
            "checkpointContextId" to FiContextWire.marked32(checkpointContextId),
            "assetOwner" to assetOwner, "assetIncarnation" to FiContextWire.raw32(assetIncarnation),
            "assetDefinitionId" to target.assetDefinitionId, "walletAccountId" to target.accountId,
            "uid" to FiContextWire.raw32(uid), "fiAccountId" to target.fiAccountId,
            "fiParticipant" to fiParticipant, "uidController" to uidController,
            "runtimeManifestSha256" to FiContextWire.raw32(runtimeManifestSha256),
            "ownerKeyIdentity" to ownerKeyIdentity, "walletScopeCanonical" to scopeText,
            "requestSha256" to requestSha256Hex, "target" to target.fields(),
        )).toByteArray(StandardCharsets.UTF_8)
        require(canonical.size <= 32 * 1024) { "FI local trust inputs exceed bound" }
    }
    internal fun canonicalBytes(): ByteArray = canonical.copyOf()
    override fun toString(): String = "NativeFiContextAssertionTrust(local expectations, redacted)"
}

/**
 * Native-authenticated execution-cut observation. Snapshot JSON retains exact native u64 scalars.
 * Absence remains absence. This result grants no signing capability, freshness, FI role or route.
 */
class VerifiedFiContextAssertion private constructor(
    val requestSha256Hex: String,
    val blockHashHex: String,
    val blockHeight: BigInteger,
    val blockCreationTimeMs: BigInteger,
    snapshot: ByteArray,
) {
    private val retainedSnapshot = snapshot.copyOf()
    val requestSha256: ByteArray get() = FiContextWire.decodeHex(requestSha256Hex)
    val blockHash: ByteArray get() = FiContextWire.decodeHex(blockHashHex)
    val snapshotJson: ByteArray get() = retainedSnapshot.copyOf()
    override fun toString(): String = "VerifiedFiContextAssertion(redacted)"

    companion object {
        /** Decoder for the native result only; never pass an HTTP response to this internal seam. */
        internal fun fromNativeJSON(bytes: ByteArray): VerifiedFiContextAssertion {
            val fields = JsonParser.parse(FiContextWire.strictUtf8(bytes, 512 * 1024)) as? Map<*, *>
                ?: throw IllegalArgumentException("Native FI result must be an object")
            require(fields.keys == setOf("schema", "requestSha256", "blockHash", "blockHeight",
                "blockCreationTimeMs", "snapshotJsonBase64")) { "Invalid native FI result fields" }
            require(fields["schema"] == "iroha.fi-context-assertion.verified.v1")
            fun text(key: String): String = fields[key] as? String
                ?: throw IllegalArgumentException("Native FI field must be text")
            val digest = text("requestSha256").also(FiContextWire::hex32)
            val block = text("blockHash").also { FiContextWire.marked32(FiContextWire.decodeHex(it)) }
            val height = FiContextWire.decimalU64(text("blockHeight"))
            val time = FiContextWire.decimalU64(text("blockCreationTimeMs"))
            val base64 = text("snapshotJsonBase64")
            require(base64.length <= 512 * 1024) { "Native FI snapshot exceeds bound" }
            val snapshot = Base64.getDecoder().decode(base64)
            require(Base64.getEncoder().encodeToString(snapshot) == base64) { "Noncanonical native FI snapshot base64" }
            val snapshotText = FiContextWire.strictUtf8(snapshot, 512 * 1024)
            val value = JsonParser.parse(snapshotText) as? Map<*, *>
                ?: throw IllegalArgumentException("Native FI snapshot must be an object")
            require(value.keys == setOf("asset_definition_id", "asset_incarnation", "account_id", "uid",
                "fi_account_id", "reference_digest", "binding", "policy", "fi", "attestation", "link", "controller")) {
                "Invalid native FI snapshot fields"
            }
            // Preserve original bytes: no host numeric or account reserialization can alter them.
            return VerifiedFiContextAssertion(digest, block, height, time, snapshot)
        }
    }
}

/** Four-buffer native FI verifier. No HTTP, current-link shortcut, wallet signing or root discovery. */
class NativeFiContextAssertionBridge private constructor() {
    companion object {
        private const val LIBRARY_NAME = "connect_norito_bridge"
        private val nativeAvailable: Boolean = try {
            System.loadLibrary(LIBRARY_NAME)
            nativeBridgeAbiVersion() == 31 && nativeVerifierContractVersion() == 1
        } catch (_: UnsatisfiedLinkError) { false } catch (_: SecurityException) { false }

        @JvmStatic fun isNativeAvailable(): Boolean = nativeAvailable

        /**
         * Callers recheck owner/runtime identity and monotonic freshness immediately before and
         * after this call and at every later use. [trust] and [trustedCheckpoint] must be local,
         * independently admitted originals; transport supplies only [capsule]. Retrying reuses
         * the same retained request, checkpoint selection and idempotency key.
         */
        @JvmStatic
        fun verifyFiContextAssertionV1(
            capsule: ByteArray,
            retainedRequest: ByteArray,
            trustedCheckpoint: ByteArray,
            trust: NativeFiContextAssertionTrust,
        ): VerifiedFiContextAssertion {
            require(capsule.isNotEmpty() && capsule.size <= 512 * 1024)
            require(retainedRequest.isNotEmpty() && retainedRequest.size <= 64 * 1024)
            require(trustedCheckpoint.isNotEmpty() && trustedCheckpoint.size <= 68 * 1024 * 1024)
            val proof = capsule.copyOf()
            val original = retainedRequest.copyOf()
            val checkpoint = trustedCheckpoint.copyOf()
            require(FiContextWire.raw32(MessageDigest.getInstance("SHA-256").digest(original)) == trust.requestSha256Hex) {
                "FI request differs from the retained original digest"
            }
            check(nativeAvailable) { "$LIBRARY_NAME FI context verifier is unavailable" }
            val result = checkNotNull(nativeVerifyFiContextAssertionV1(proof, original, checkpoint, trust.canonicalBytes())) {
                "Native FI context verifier returned no result"
            }
            return VerifiedFiContextAssertion.fromNativeJSON(result).also {
                require(it.requestSha256Hex == trust.requestSha256Hex && it.blockHeight > trust.checkpointHeight) {
                    "Native FI assertion differs from the retained request/checkpoint"
                }
            }
        }

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeVerifierContractVersion(): Int
        @JvmStatic private external fun nativeVerifyFiContextAssertionV1(
            capsule: ByteArray, original: ByteArray, checkpoint: ByteArray, trust: ByteArray,
        ): ByteArray?
    }
}

private object FiContextWire {
    val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64) - BigInteger.ONE
    fun positiveU64(value: BigInteger) { require(value.signum() > 0 && value <= U64_MAX) }
    fun decimalU64(value: String): BigInteger {
        require(Regex("[1-9][0-9]{0,19}").matches(value))
        return BigInteger(value).also(::positiveU64)
    }
    fun text(value: String, maximum: Int) {
        require(value.isNotEmpty() && value.length <= maximum && value == value.trim() && value.none { it.isISOControl() })
        val encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value))
        require(encoded.remaining() <= maximum)
    }
    fun strictUtf8(bytes: ByteArray, maximum: Int): String {
        require(bytes.isNotEmpty() && bytes.size <= maximum)
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
    fun raw32(bytes: ByteArray): String {
        require(bytes.size == 32)
        val captured = bytes.copyOf()
        require(captured.any { it != 0.toByte() })
        val alphabet = "0123456789abcdef"
        return buildString(64) { captured.forEach { byte ->
            val n = byte.toInt() and 255; append(alphabet[n ushr 4]); append(alphabet[n and 15])
        } }
    }
    fun marked32(bytes: ByteArray): String = raw32(bytes).also { value ->
        require((value.last().digitToInt(16) and 1) == 1 && value != "0".repeat(63) + "1")
    }
    fun hex32(value: String) {
        require(Regex("[0-9a-f]{64}").matches(value) && value != "0".repeat(64))
    }
    fun decodeHex(value: String): ByteArray {
        hex32(value)
        return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
