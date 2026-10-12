package org.hyperledger.iroha.sdk.core.model

import java.util.Collections
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address

private const val MAX_U32 = 0xffff_ffffL
private const val DEFAULT_TRANSACTION_TTL_MS = 100_000L

/**
 * Representation of a transaction payload prior to Norito encoding.
 *
 * The structure mirrors the Rust data model sufficiently for encoding and signing, including
 * instruction lists, by-reference contract calls, IVM bytecode, and flat mixed batches. `authority`
 * must use the canonical I105 account literal. `networkId` is the exact canonical hash identity of
 * the genesis header. `nonce` uses a [Long] carrier for the full nonzero unsigned 32-bit wire range.
 * Attachments are part of the signed payload and therefore affect both authorization signatures
 * and the canonical transaction identifier. On the wire the field is `SignedAttachmentsV1` (the
 * ordered intent descriptor and signed attachment occurrences). The canonical attachment codec
 * validates its inline bytes, descriptor and binding before accepting a signed payload.
 */
class TransactionPayload(
    val networkId: NetworkId,
    val authority: String,
    val creationTimeMs: Long = System.currentTimeMillis(),
    val executable: Executable,
    val timeToLiveMs: Long? = DEFAULT_TRANSACTION_TTL_MS,
    val nonce: Long? = null,
    val feePayment: FeePaymentIntent,

    metadata: Map<String, JsonValue> = emptyMap(),
    val attachments: SignedAttachmentsV1? = null,
) {
    private val _metadata: Map<String, JsonValue> = Collections.unmodifiableMap(
        metadata.toMap().also { values ->
            values.forEach { (key, value) ->
                require(!key.isNullOrBlank()) { "metadata key must not be blank" }
                requireNotNull(value) { "metadata values must be JSON values; use JsonValue.nullValue() for JSON null" }
            }
        },
    )
    val metadata: Map<String, JsonValue> get() = _metadata

    init {
        requireCanonicalI105Address(authority, "authority")
        require(creationTimeMs >= 0) { "creationTimeMs must be non-negative" }
        require(timeToLiveMs != null && timeToLiveMs > 0) {
            "timeToLiveMs must be a positive signature-bound lifetime"
        }
        if (nonce != null) {
            require(nonce in 1..MAX_U32) { "nonce must fit in the nonzero u32 range" }
        }
    }

    fun copy(
        networkId: NetworkId = this.networkId,
        authority: String = this.authority,
        creationTimeMs: Long = this.creationTimeMs,
        executable: Executable = this.executable,
        timeToLiveMs: Long? = this.timeToLiveMs,
        nonce: Long? = this.nonce,
        feePayment: FeePaymentIntent = this.feePayment,

        metadata: Map<String, JsonValue> = this.metadata,
        attachments: SignedAttachmentsV1? = this.attachments,
    ): TransactionPayload = TransactionPayload(
        networkId = networkId,
        authority = authority,
        creationTimeMs = creationTimeMs,
        executable = executable,
        timeToLiveMs = timeToLiveMs,
        nonce = nonce,
        feePayment = feePayment,

        metadata = metadata,
        attachments = attachments,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionPayload) return false
        return networkId == other.networkId
            && authority == other.authority
            && creationTimeMs == other.creationTimeMs
            && executable == other.executable
            && timeToLiveMs == other.timeToLiveMs
            && nonce == other.nonce
            && feePayment == other.feePayment

            && _metadata == other._metadata
            && attachments == other.attachments
    }

    override fun hashCode(): Int {
        var result = networkId.hashCode()
        result = 31 * result + authority.hashCode()
        result = 31 * result + creationTimeMs.hashCode()
        result = 31 * result + executable.hashCode()
        result = 31 * result + (timeToLiveMs?.hashCode() ?: 0)
        result = 31 * result + (nonce?.hashCode() ?: 0)
        result = 31 * result + feePayment.hashCode()

        result = 31 * result + _metadata.hashCode()
        result = 31 * result + (attachments?.hashCode() ?: 0)
        return result
    }
}
