package org.hyperledger.iroha.sdk.core.model.instructions

import org.hyperledger.iroha.sdk.client.IdentifierResolutionReceipt
import org.hyperledger.iroha.sdk.client.IdentifierReceiptCanonicalEncoder
import org.hyperledger.iroha.sdk.client.PhoneRetailCanonicalityAttestationV1
import org.hyperledger.iroha.sdk.client.IdentifierOwnerInputV1
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.TypeAdapter

/**
 * Encodes `ClaimIdentifier` instructions in wire-framed Norito format.
 *
 * The Torii identifier endpoints expose canonical `{ payload, attestation }` receipts, so the
 * encoder derives payload bytes from the structured payload and encodes the explicit attestation.
 */
object ClaimIdentifierWirePayloadEncoder {

    const val WIRE_NAME = "identity::ClaimIdentifier"
    private const val SCHEMA_PATH = "iroha_data_model::isi::identifier::ClaimIdentifier"

    /** Encodes a `ClaimIdentifier` instruction as a wire-framed [InstructionBox]. */
    @JvmStatic
    fun encode(accountId: String, receipt: IdentifierResolutionReceipt): InstructionBox {
        val normalizedAccountId = requireExactNonBlank(accountId, "accountId")
        val receiptAccountId = requireExactNonBlank(receipt.accountId, "receipt.accountId")
        require(normalizedAccountId == receiptAccountId) { "ClaimIdentifier accountId must match receipt.accountId" }
        require(receipt.payload.execution.backend == IdentifierOwnerInputV1.BACKEND && receipt.payload.execution.verificationMode == "signed" && receipt.attestation.kind == "signed") { "ClaimIdentifier requires current signed HKDF receipt metadata" }
        IdentifierOwnerInputV1.originalLease(receipt.payload.opening.payload.openedAtMs, receipt.payload.opening.payload.expiresAtMs)
        val phone = receipt.phoneRetailCanonicality
        if (receipt.policyId == "phone#retail") {
            requireNotNull(phone) { "phone#retail requires its original independent signed canonicality statement" }
            require(phone.payload.networkId == receipt.payload.networkId && phone.payload.accountId == receiptAccountId && phone.payload.uaid == receipt.uaid) { "phone canonicality scope differs from receipt" }
            phone.requireOriginalOpening(receipt.payload.opening)
        } else require(phone == null) { "nonphone receipt must not contain phone canonicality" }
        val phonePayload = phone?.let(IdentifierReceiptCanonicalEncoder::encodePhoneCarrier)
        val accountPayload = TransferWirePayloadEncoder.encodeAccountIdPayload(normalizedAccountId)
        val receiptPayload = IdentifierReceiptCanonicalEncoder.encodePayload(receipt.payload)
        val attestationPayload = IdentifierReceiptCanonicalEncoder.encodeAttestation(receipt.attestation)
        val wirePayload = NoritoCodec.encode(
            ClaimIdentifierPayload(accountPayload, receiptPayload, attestationPayload, phonePayload),
            SCHEMA_PATH,
            ClaimIdentifierPayloadAdapter()
        )
        return InstructionBox.fromWirePayload(WIRE_NAME, wirePayload)
    }

    /**
     * Structurally decodes a canonical Norito-framed claim and retains its original phone bytes.
     *
     * This validates framing and required fields. Receipt signatures and policy authority
     * still require separate verification before use.
     */
    @JvmStatic
    fun decodePayload(
        wirePayload: ByteArray,
        chainDiscriminant: Int,
    ): DecodedClaimIdentifierPayload {
        val payload = NoritoCodec.decode(wirePayload, ClaimIdentifierPayloadAdapter(), SCHEMA_PATH)
        val original = IdentifierReceiptCanonicalEncoder.decodePayload(payload.receiptPayload, chainDiscriminant)
        val phone = payload.phonePayload?.let { IdentifierReceiptCanonicalEncoder.decodePhoneCarrier(it, chainDiscriminant) }
        if (original.policyId == "phone#retail") {
            requireNotNull(phone) { "phone claim must retain its original canonicality" }
            require(phone.payload.networkId == original.networkId && phone.payload.accountId == original.accountId && phone.payload.uaid == original.uaid) { "decoded phone scope differs from receipt" }
            phone.requireOriginalOpening(original.opening)
        } else require(phone == null) { "nonphone claim contains phone canonicality" }
        return DecodedClaimIdentifierPayload(
            accountId = TransferWirePayloadEncoder.decodeAccountIdPayload(
                payload.accountPayload,
                chainDiscriminant,
            ),
            receiptPayloadBytes = payload.receiptPayload,
            attestationPayloadBytes = payload.attestationPayload,
            phoneCanonicalityBytes = payload.phonePayload,
        )
    }

    /** Structurally decoded claim fields, with owned defensive copies of receipt bytes. */
    class DecodedClaimIdentifierPayload internal constructor(
        val accountId: String,
        receiptPayloadBytes: ByteArray,
        attestationPayloadBytes: ByteArray,
        phoneCanonicalityBytes: ByteArray?,
    ) {
        private val receiptBytes = receiptPayloadBytes.clone()
        private val attestationBytes = attestationPayloadBytes.clone()
        private val phoneBytes = phoneCanonicalityBytes?.clone()

        val receiptPayloadBytes: ByteArray get() = receiptBytes.clone()
        val attestationPayloadBytes: ByteArray get() = attestationBytes.clone()
        val phoneCanonicalityBytes: ByteArray? get() = phoneBytes?.clone()
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecodedClaimIdentifierPayload) return false
            return accountId == other.accountId &&
                receiptBytes.contentEquals(other.receiptBytes) &&
                attestationBytes.contentEquals(other.attestationBytes) &&
                (phoneBytes?.contentEquals(other.phoneBytes ?: return false) ?: (other.phoneBytes == null))
        }

        override fun hashCode(): Int {
            var result = accountId.hashCode()
            result = 31 * result + receiptBytes.contentHashCode()
            result = 31 * result + attestationBytes.contentHashCode()
            result = 31 * result + (phoneBytes?.contentHashCode() ?: 0)
            return result
        }
    }

    private class ClaimIdentifierPayload(accountPayload: ByteArray, receiptPayload: ByteArray, attestationPayload: ByteArray, phonePayload: ByteArray?) {
        val accountPayload: ByteArray = accountPayload.clone()
        val receiptPayload: ByteArray = receiptPayload.clone()
        val attestationPayload: ByteArray = attestationPayload.clone()
        val phonePayload: ByteArray? = phonePayload?.clone()
    }

    private class ClaimIdentifierPayloadAdapter : TypeAdapter<ClaimIdentifierPayload> {
        override fun encode(encoder: NoritoEncoder, value: ClaimIdentifierPayload) {
            encodeSizedField(encoder, PASSTHROUGH_ADAPTER, value.accountPayload)
            encodeSizedField(encoder, RECEIPT_ADAPTER, ReceiptPayload(value.receiptPayload, value.attestationPayload, value.phonePayload))
        }
        override fun decode(decoder: NoritoDecoder): ClaimIdentifierPayload {
            val accountPayload = decodeSizedField(decoder, PASSTHROUGH_ADAPTER, "ClaimIdentifier.account_id")
            val receipt = decodeSizedField(decoder, RECEIPT_ADAPTER, "ClaimIdentifier.receipt")
            return ClaimIdentifierPayload(accountPayload, receipt.payloadBytes, receipt.attestationBytes, receipt.phoneBytes)
        }
        companion object {
            private val PASSTHROUGH_ADAPTER = PassthroughBytesAdapter()
            private val RECEIPT_ADAPTER = ReceiptPayloadAdapter()
        }
    }

    private class ReceiptPayload(payloadBytes: ByteArray, attestationBytes: ByteArray, phoneBytes: ByteArray?) {
        val payloadBytes: ByteArray = payloadBytes.clone()
        val attestationBytes: ByteArray = attestationBytes.clone()
        val phoneBytes: ByteArray? = phoneBytes?.clone()
    }

    private class ReceiptPayloadAdapter : TypeAdapter<ReceiptPayload> {
        override fun encode(encoder: NoritoEncoder, value: ReceiptPayload) {
            encodeSizedField(encoder, PASSTHROUGH_ADAPTER, value.payloadBytes)
            encodeSizedField(encoder, PASSTHROUGH_ADAPTER, value.attestationBytes)
            encodeSizedField(encoder, CANONICALITY_ADAPTER, value.phoneBytes)
        }
        override fun decode(decoder: NoritoDecoder): ReceiptPayload {
            val payloadBytes = decodeSizedField(decoder, PASSTHROUGH_ADAPTER, "IdentifierReceipt.payload")
            val attestationBytes = decodeSizedField(decoder, PASSTHROUGH_ADAPTER, "IdentifierReceipt.attestation")
            val phoneBytes = decodeSizedField(decoder, CANONICALITY_ADAPTER, "IdentifierReceipt.phone_retail_canonicality")
            return ReceiptPayload(payloadBytes, attestationBytes, phoneBytes)
        }
        companion object {
            private val PASSTHROUGH_ADAPTER = PassthroughBytesAdapter()
            private val CANONICALITY_ADAPTER = CanonicalityAdapter()
        }
    }

    private class CanonicalityAdapter : TypeAdapter<ByteArray?> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray?) {
            if (value == null) encoder.writeByte(0)
            else {
                encoder.writeByte(1)
                encodeSizedField(encoder, PassthroughBytesAdapter(), value)
            }
        }
        override fun decode(decoder: NoritoDecoder): ByteArray? {
            val tag = decoder.readByte()
            if (tag == 0) return null
            require(tag == 1) { "Invalid phone canonicality option tag" }
            return decodeSizedField(decoder, PassthroughBytesAdapter(), "phone canonicality original")
        }
    }

    private class PassthroughBytesAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) {
            require(value.isNotEmpty()) { "payload bytes must not be empty" }
            encoder.writeBytes(value)
        }
        override fun decode(decoder: NoritoDecoder): ByteArray {
            val payload = decoder.readBytes(decoder.remaining())
            require(payload.isNotEmpty()) { "payload bytes must not be empty" }
            return payload
        }
    }

    private fun <T> encodeSizedField(encoder: NoritoEncoder, adapter: TypeAdapter<T>, value: T) {
        val child = encoder.childEncoder()
        adapter.encode(child, value)
        val payload = child.toByteArray()
        val compact = (encoder.flags and NoritoHeader.COMPACT_LEN) != 0
        encoder.writeLength(payload.size.toLong(), compact)
        encoder.writeBytes(payload)
    }

    private fun <T> decodeSizedField(decoder: NoritoDecoder, adapter: TypeAdapter<T>, fieldName: String): T {
        val length = decoder.readLength((decoder.flags and NoritoHeader.COMPACT_LEN) != 0)
        require(length <= Int.MAX_VALUE) { "$fieldName payload too large" }
        val payload = decoder.readBytes(length.toInt())
        val child = NoritoDecoder(payload, decoder.flags)
        val value = adapter.decode(child)
        require(child.remaining() == 0) { "Trailing bytes after $fieldName payload" }
        return value
    }

    private fun requireExactNonBlank(value: String?, field: String): String {
        val exact = value ?: ""
        require(exact.isNotBlank()) { "$field must not be blank" }
        require(exact.trim() == exact) { "$field must not contain surrounding whitespace" }
        return exact
    }
}
