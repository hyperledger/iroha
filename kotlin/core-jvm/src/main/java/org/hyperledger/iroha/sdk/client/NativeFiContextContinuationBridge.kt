package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Exact native-admitted signed candidate, not a finality, snapshot, success or freshness claim.
 * The status locator remains untrusted. Retain this original and its immutable runtime/floor
 * association before any continuation, and never replace it after uncertain submission.
 */
class AdmittedFiAssertionOriginal private constructor(
    val requestSha256Hex: String,
    val assertionEntrypointHashHex: String,
    val assertionWireSha256Hex: String,
    val originalCheckpointHeight: BigInteger,
    val originalCheckpointBlockHashHex: String,
    wire: ByteArray, request: ByteArray, originalTrust: ByteArray,
) {
    private val retainedWire = wire.copyOf()
    private val retainedRequest = request.copyOf()
    private val retainedTrust = originalTrust.copyOf()
    val signedWire: ByteArray get() = retainedWire.copyOf()
    val originalRequest: ByteArray get() = retainedRequest.copyOf()
    internal fun requireSameTrust(trust: NativeFiContextAssertionTrust) {
        require(retainedTrust.contentEquals(trust.canonicalBytes())) { "Continuation replaced original trust selection" }
    }
    override fun toString(): String = "AdmittedFiAssertionOriginal(candidate only, redacted)"

    companion object {
        internal fun fromNative(bytes: ByteArray, wire: ByteArray, request: ByteArray,
            trust: NativeFiContextAssertionTrust, statusEntrypointHash: ByteArray,
            statusWireSHA256: ByteArray): AdmittedFiAssertionOriginal {
            ContinuationWire.bound(wire,64*1024); ContinuationWire.bound(request,64*1024)
            val objectValue = JsonParser.parse(ContinuationWire.text(bytes,2048)) as? Map<*, *>
                ?: throw IllegalArgumentException("Native original admission must be an object")
            require(objectValue.keys == setOf("schema","requestSha256","assertionEntrypointHash",
                "assertionWireSha256","originalCheckpointHeight","originalCheckpointBlockHash"))
            fun field(name: String) = objectValue[name] as? String
                ?: throw IllegalArgumentException("Native admission fields must be strings")
            require(field("schema") == "iroha.fi-assertion-original.admitted.v1")
            val digest=field("requestSha256").also(ContinuationWire::hex32)
            val entrypoint=field("assertionEntrypointHash").also(ContinuationWire::marked32)
            val wireDigest=field("assertionWireSha256").also(ContinuationWire::hex32)
            val height=ContinuationWire.height(field("originalCheckpointHeight"))
            val block=field("originalCheckpointBlockHash").also(ContinuationWire::marked32)
            require(digest==trust.requestSha256Hex && digest==ContinuationWire.sha(request))
            require(entrypoint==ContinuationWire.raw(statusEntrypointHash) &&
                wireDigest==ContinuationWire.raw(statusWireSHA256) && wireDigest==ContinuationWire.sha(wire)) {
                "Native original differs from retained status identity"
            }
            require(height==trust.checkpointHeight)
            return AdmittedFiAssertionOriginal(digest,entrypoint,wireDigest,height,block,wire,request,trust.canonicalBytes())
        }
    }
}

/**
 * Local original expectation plus separately admitted branch cursor. Its constructor is not a
 * lineage verifier. Supply only the protected durable branch owner's selected native checkpoint,
 * not a global latest checkpoint or HTTP selectors. Capture/recheck branch generation across each
 * asynchronous read, native call and atomic adoption; keep original floor and earlier branches.
 */
class NativeFiContextContinuationTrust(
    val original: NativeFiContextAssertionTrust,
    cursor: VerifiedFiCheckpointSelection,
    independentlyRetainedCursorSHA256: ByteArray,
) {
    val cursorHeight: BigInteger = cursor.height
    private val cursorSHA = ContinuationWire.raw(independentlyRetainedCursorSHA256)
    private val canonical: ByteArray
    init {
        require(cursorHeight>=original.checkpointHeight)
        val originalFields=JsonParser.parse(ContinuationWire.text(original.canonicalBytes(),32*1024))
        canonical=JsonEncoder.encode(mapOf("schema" to "iroha.fi-context-continuation-trust.v1",
            "original" to originalFields,"cursor" to mapOf("checkpointSha256" to cursorSHA,
                "checkpointHeight" to cursorHeight.toString(),"checkpointContextId" to cursor.contextIdHex,
                "checkpointBlockHash" to cursor.blockHashHex))).toByteArray(StandardCharsets.UTF_8)
        require(canonical.size<=36*1024)
    }
    internal fun bytes(): ByteArray = canonical.copyOf()
    internal fun checkCursorBytes(bytes: ByteArray) { require(ContinuationWire.sha(bytes)==cursorSHA) }
    override fun toString(): String = "NativeFiContextContinuationTrust(local branch selection, redacted)"
}

/** Candidate admission and continuation are separate native contracts; neither signs or submits. */
class NativeFiContextContinuationBridge private constructor() {
    companion object {
        private const val LIBRARY = "connect_norito_bridge"
        private val available = try {
            System.loadLibrary(LIBRARY)
            nativeBridgeAbiVersion()==31 && nativeVerifierContractVersion()==1
        } catch (_: UnsatisfiedLinkError) { false } catch (_: SecurityException) { false }
        @JvmStatic fun isNativeAvailable(): Boolean = available

        /**
         * Status hashes are candidates compared to the actual native signed wire. The returned
         * private type seals their equality, without asserting the transaction ever executed.
         * Recheck current owner/PSP/runtime admission before/after, then retain it atomically with
         * the unchanged operation provenance. No current clock or freshness decision is made.
         */
        @JvmStatic fun admitFiAssertionOriginalV1(signedWire: ByteArray, retainedRequest: ByteArray,
            originalCheckpoint: ByteArray, trust: NativeFiContextAssertionTrust,
            statusEntrypointHash: ByteArray, statusWireSHA256: ByteArray): AdmittedFiAssertionOriginal {
            ContinuationWire.bound(signedWire,64*1024); ContinuationWire.bound(retainedRequest,64*1024)
            ContinuationWire.bound(originalCheckpoint,68*1024*1024)
            require(statusEntrypointHash.size==32 && statusWireSHA256.size==32)
            val wire=signedWire.copyOf();val request=retainedRequest.copyOf();val checkpoint=originalCheckpoint.copyOf()
            val entrypoint=statusEntrypointHash.copyOf();val digest=statusWireSHA256.copyOf()
            ContinuationWire.marked32(ContinuationWire.raw(entrypoint))
            require(ContinuationWire.sha(wire)==ContinuationWire.raw(digest))
            require(ContinuationWire.sha(request)==trust.requestSha256Hex)
            check(available) { "$LIBRARY FI original admission is unavailable" }
            val bytes=checkNotNull(nativeAdmitFiAssertionOriginalV1(wire,request,checkpoint,trust.canonicalBytes()))
            return AdmittedFiAssertionOriginal.fromNative(bytes,wire,request,trust,entrypoint,digest)
        }

        /**
         * Retain exact original floor independently of cursor; do not change request/challenge/key.
         * This call authenticates exact successful execution and snapshot only. Freshness and
         * current owner/runtime/branch-generation guards remain required before every use.
         */
        @JvmStatic fun verifyFiContextContinuationV1(capsule: ByteArray, original: AdmittedFiAssertionOriginal,
            originalCheckpoint: ByteArray, cursorCheckpoint: ByteArray,
            trust: NativeFiContextContinuationTrust): VerifiedFiContextAssertion {
            ContinuationWire.bound(capsule,512*1024);ContinuationWire.bound(originalCheckpoint,68*1024*1024)
            ContinuationWire.bound(cursorCheckpoint,68*1024*1024)
            require(original.requestSha256Hex==trust.original.requestSha256Hex &&
                original.originalCheckpointHeight==trust.original.checkpointHeight)
            original.requireSameTrust(trust.original)
            val proof=capsule.copyOf();val floor=originalCheckpoint.copyOf();val cursor=cursorCheckpoint.copyOf()
            trust.checkCursorBytes(cursor)
            check(available) { "$LIBRARY FI continuation verifier is unavailable" }
            val bytes=checkNotNull(nativeVerifyFiContextContinuationV1(proof,original.originalRequest,
                original.signedWire,floor,cursor,trust.bytes()))
            return VerifiedFiContextAssertion.fromNativeJSON(bytes).also {
                require(it.requestSha256Hex==original.requestSha256Hex && it.blockHeight>original.originalCheckpointHeight &&
                    it.blockHeight>=trust.cursorHeight)
            }
        }

        @JvmStatic private external fun nativeBridgeAbiVersion(): Int
        @JvmStatic private external fun nativeVerifierContractVersion(): Int
        @JvmStatic private external fun nativeAdmitFiAssertionOriginalV1(wire: ByteArray, request: ByteArray,
            checkpoint: ByteArray, trust: ByteArray): ByteArray?
        @JvmStatic private external fun nativeVerifyFiContextContinuationV1(capsule: ByteArray, request: ByteArray,
            wire: ByteArray, originalCheckpoint: ByteArray, cursorCheckpoint: ByteArray, trust: ByteArray): ByteArray?
    }
}

private object ContinuationWire {
    private val maximum=BigInteger.ONE.shiftLeft(64)-BigInteger.ONE
    fun bound(bytes: ByteArray, max: Int) { require(bytes.isNotEmpty() && bytes.size<=max) }
    fun text(bytes: ByteArray,max: Int): String {
        bound(bytes,max)
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
    fun height(value: String): BigInteger {
        require(Regex("[1-9][0-9]{0,19}").matches(value))
        return BigInteger(value).also { require(it.signum()>0 && it<maximum) }
    }
    fun hex32(value: String) { require(Regex("[0-9a-f]{64}").matches(value) && value!="0".repeat(64)) }
    fun marked32(value: String) { hex32(value);require((value.last().digitToInt(16) and 1)==1 && value!="0".repeat(63)+"1") }
    fun raw(bytes: ByteArray): String {
        require(bytes.size==32)
        return bytes.copyOf().joinToString("") { "%02x".format(it.toInt() and 255) }.also(::hex32)
    }
    fun sha(bytes: ByteArray): String = raw(MessageDigest.getInstance("SHA-256").digest(bytes))
}
