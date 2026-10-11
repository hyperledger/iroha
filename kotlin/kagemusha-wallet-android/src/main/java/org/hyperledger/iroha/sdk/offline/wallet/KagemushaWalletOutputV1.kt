package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder

private fun invalidOutput(): Nothing = throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
private fun input(bytes: ByteArray, magic: String, minimum: Int, maximum: Int): ByteBuffer {
    if (bytes.size !in minimum..maximum || !bytes.copyOfRange(0, 8).contentEquals(magic.toByteArray(Charsets.US_ASCII))) invalidOutput()
    return ByteBuffer.wrap(bytes.copyOf()).order(ByteOrder.LITTLE_ENDIAN).also { it.position(8) }
}
private fun ByteBuffer.word(): ByteArray = ByteArray(32).also { get(it); if (it.all { byte -> byte == 0.toByte() }) invalidOutput() }
private fun ByteBuffer.scalar() = KagemushaWalletUInt128V1(long, long)

/** Exact Native-admitted originals. Instances use identity equality; bytes grant no authority. */
class KagemushaWalletMetadataV1 internal constructor(original: ByteArray) {
    val assetScale: Int
    private val scheme: ByteArray
    private val wallet: ByteArray
    private val asset: ByteArray
    private val account: ByteArray
    private val accountBytes: ByteArray
    private val assetBytes: ByteArray
    init {
        val input = input(original, "KWMDV1\u0000\u0000", 150, 5268)
        assetScale = input.int
        if (assetScale !in 0..28) invalidOutput()
        scheme = input.word(); wallet = input.word(); asset = input.word(); account = input.word()
        val accountLength = input.int; val assetLength = input.int
        if (accountLength !in 1..4096 || assetLength !in 1..1024 || input.remaining() != accountLength + assetLength) invalidOutput()
        accountBytes = ByteArray(accountLength).also(input::get); assetBytes = ByteArray(assetLength).also(input::get)
    }
    fun schemeId(): ByteArray = scheme.copyOf()
    fun walletId(): ByteArray = wallet.copyOf()
    fun assetDigest(): ByteArray = asset.copyOf()
    fun accountDigest(): ByteArray = account.copyOf()
    fun accountOriginal(): ByteArray = accountBytes.copyOf()
    fun assetOriginal(): ByteArray = assetBytes.copyOf()
    override fun toString() = "KagemushaWalletMetadataV1(originals=[REDACTED])"
}

/** Exact released output DATA, never a retry capability. Instances use identity equality. */
class KagemushaWalletReleasedOutputV1 internal constructor(original: ByteArray) {
    enum class Kind { BOOTSTRAP, LOAD, SEND, RECEIVE, ARCHIVE_SENT, UNLOAD, REFRESH_POLICY, RETIRING }
    val kind: Kind
    val sequence: KagemushaWalletUInt128V1
    val peerKind: KagemushaWalletTransportKindV1?
    private val operation: ByteArray
    private val output: ByteArray
    private val peer: ByteArray?
    init {
        val input = input(original, "KWROV1\u0000\u0000", 67, 20_066)
        val tag = input.get().toInt()
        if (tag !in 1..8) invalidOutput()
        kind = Kind.values()[tag - 1]
        operation = input.word(); sequence = input.scalar()
        val length = input.int; val peerTag = input.get().toInt(); val peerLength = input.int
        val expected = when (kind) { Kind.SEND -> 3; Kind.RECEIVE -> 4; else -> 0 }
        if (length !in 1..10_000 || peerLength !in 0..10_000 || peerTag != expected ||
            (peerTag == 0) != (peerLength == 0) || input.remaining() != length + peerLength) invalidOutput()
        output = ByteArray(length).also(input::get)
        peer = if (peerTag == 0) null else ByteArray(peerLength).also(input::get)
        if (kind == Kind.SEND && !output.contentEquals(peer)) invalidOutput()
        peerKind = when (peerTag) { 3 -> KagemushaWalletTransportKindV1.PAYMENT; 4 -> KagemushaWalletTransportKindV1.CREDITED; else -> null }
    }
    fun operationId(): ByteArray = operation.copyOf()
    fun original(): ByteArray = output.copyOf()
    fun peerOriginal(): ByteArray? = peer?.copyOf()
    override fun toString() = "KagemushaWalletReleasedOutputV1(kind=$kind, originals=[REDACTED])"
}

/** Exact retained Load terms; no new ordinal or instruction is selected. Identity equality. */
class KagemushaWalletPreparedLoadV1 private constructor(original: ByteArray) {
    private val request: ByteArray
    private val scheme: ByteArray
    private val wallet: ByteArray
    private val asset: ByteArray
    private val payer: ByteArray
    private val instruction: ByteArray
    val ordinal: KagemushaWalletUInt128V1
    val amount: KagemushaWalletUInt128V1
    val onlineCharge: KagemushaWalletUInt128V1
    val wireName: String get() = "iroha.kagemusha.wallet.ledger.v1"
    init {
        val input = input(original, "KWLPV1\u0000\u0000", 221, 65_756)
        request = input.word(); scheme = input.word(); wallet = input.word(); asset = input.word(); payer = input.word()
        ordinal = input.scalar(); amount = input.scalar(); onlineCharge = input.scalar()
        val length = input.int
        if ((amount.low == 0L && amount.high == 0L) || onlineCharge.low != 0L || onlineCharge.high != 0L ||
            length !in 1..65_536 || input.remaining() != length) invalidOutput()
        instruction = ByteArray(length).also(input::get)
    }
    fun requestId(): ByteArray = request.copyOf()
    fun schemeId(): ByteArray = scheme.copyOf()
    fun walletId(): ByteArray = wallet.copyOf()
    fun assetDigest(): ByteArray = asset.copyOf()
    fun payerAccountDigest(): ByteArray = payer.copyOf()
    fun instructionOriginal(): ByteArray = instruction.copyOf()
    override fun toString() = "KagemushaWalletPreparedLoadV1(originals=[REDACTED])"
    companion object {
        internal fun observation(bytes: ByteArray, requestId: ByteArray): KagemushaWalletPreparedLoadV1? {
            require(requestId.size == 32 && requestId.any { it != 0.toByte() })
            if (bytes.contentEquals("KWLNV1\u0000\u0000".toByteArray(Charsets.US_ASCII))) return null
            val result = KagemushaWalletPreparedLoadV1(bytes)
            if (!result.request.contentEquals(requestId)) invalidOutput()
            return result
        }
    }
}

/** Private JNI response domain; larger observations never expand general wallet result bounds. */
internal class KagemushaWalletObservationReplyV1(
    private val status: Int, private val reason: Int, private val platformCode: Int,
    sequenceLow: Long, sequenceHigh: Long, detail: Int, bytes: ByteArray,
) {
    private val original = bytes.copyOf()
    init {
        if (sequenceLow != 0L || sequenceHigh != 0L || detail != 0 || bytes.size > 65_756 ||
            (status < 0 && bytes.isNotEmpty()) ||
            (status >= 0 && (status != 12 || reason != -1 || platformCode != 0 || bytes.isEmpty()))) invalidOutput()
    }
    internal fun original(maximum: Int): ByteArray {
        if (status < 0) throw KagemushaWalletExceptionV1(status, reason, platformCode)
        if (original.size > maximum) invalidOutput()
        return original.copyOf()
    }
    override fun toString() = "KagemushaWalletObservationReplyV1(original=[REDACTED])"
}

internal object KagemushaWalletObservationNativeV1 {
    @JvmStatic external fun observe(handle: Long, selector: Int, identity: ByteArray): KagemushaWalletObservationReplyV1?
}
