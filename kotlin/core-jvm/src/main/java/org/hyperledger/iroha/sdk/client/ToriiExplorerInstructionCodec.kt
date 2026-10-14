package org.hyperledger.iroha.sdk.client

import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.model.instructions.TransferWirePayloadEncoder
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.TypeAdapter
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

/** An explorer instruction cannot be bound to its advertised canonical frame. */
class ToriiExplorerInstructionException internal constructor(cause: Exception) :
    IllegalArgumentException("Explorer instruction response is invalid.", cause)

/** Decodes the canonical `box` projection returned by Torii's explorer instruction routes.
 * Digest and canonical encoding checks bind display data to the returned frame; they do not
 * authenticate ledger finality or authorize execution of the instruction.
 */
object ToriiExplorerInstructionCodec {
    /** Validate the response wire id, lowercase SHA-256 and canonical base64 instruction frame. */
    @JvmStatic
    fun decode(wireId: String, framedSha256: String, instructionBase64: String): InstructionBox = checked {
        require(wireId.isNotBlank() && wireId == wireId.trim()) { "Explorer wire id is invalid" }
        require(framedSha256.length == 64 && framedSha256.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Explorer frame digest is not canonical SHA-256"
        }
        val frame = Base64.getDecoder().decode(instructionBase64)
        require(frame.isNotEmpty() && Base64.getEncoder().encodeToString(frame) == instructionBase64) {
            "Explorer instruction is not canonical base64"
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(frame)
            .joinToString("") { "%02x".format(it) }
        require(digest == framedSha256) { "Explorer frame digest differs from instruction" }
        val instruction = NoritoJavaCodecAdapter.decodeInstructionBox(frame)
        val wire = instruction.payload as? WirePayload
            ?: throw IllegalArgumentException("Explorer instruction must be wire-framed")
        require(wire.wireName == wireId) { "Explorer wire id differs from instruction" }
        instruction
    }

    /** Project one asset transfer; unrelated instruction kinds have no asset transfer projection.
     * The explicit chain discriminant is required when rendering domainless account identities.
     */
    @JvmStatic
    fun assetTransfer(instruction: InstructionBox, chainDiscriminant: Int): AssetTransfer? = checked {
        val wire = instruction.payload as? WirePayload
            ?: throw IllegalArgumentException("Explorer instruction must be wire-framed")
        if (wire.wireName != TransferWirePayloadEncoder.WIRE_NAME) return@checked null
        val payload = wire.payloadBytes
        val variant = NoritoCodec.decode(payload, transferVariantAdapter, TRANSFER_SCHEMA)
        require(payload.contentEquals(NoritoCodec.encode(variant, TRANSFER_SCHEMA, transferVariantAdapter))) {
            "Explorer transfer frame is not canonical"
        }
        if (variant.tag != 2L) return@checked null
        val transfer = TransferWirePayloadEncoder.decodeAssetTransferPayload(payload, chainDiscriminant)
        val canonical = TransferWirePayloadEncoder.encodeAssetTransfer(
            transfer.assetId, transfer.amount, transfer.destinationAccountId,
        ).payload as WirePayload
        require(payload.contentEquals(canonical.payloadBytes)) { "Explorer transfer payload is not canonical" }
        AssetTransfer(transfer.assetId, transfer.amount, transfer.destinationAccountId)
    }

    /** Exact display fields from a canonical `TransferBox::Asset`, without execution authority. */
    class AssetTransfer internal constructor(
        val assetId: String,
        val amount: String,
        val destinationAccountId: String,
    )

    private const val TRANSFER_SCHEMA = "iroha_data_model::isi::transfer::TransferBox"
    private class TransferVariant(val tag: Long, val payload: ByteArray)
    private val transferVariantAdapter = object : TypeAdapter<TransferVariant> {
        private val uint32 = NoritoAdapters.uint(32)

        override fun encode(encoder: NoritoEncoder, value: TransferVariant) {
            uint32.encode(encoder, value.tag)
            encoder.writeLength(value.payload.size.toLong(), (encoder.flags and NoritoHeader.COMPACT_LEN) != 0)
            encoder.writeBytes(value.payload)
        }

        override fun decode(decoder: NoritoDecoder): TransferVariant {
            val tag = uint32.decode(decoder)
            require(tag in 0L..3L) { "Unknown TransferBox variant" }
            val size = decoder.readLength((decoder.flags and NoritoHeader.COMPACT_LEN) != 0)
            require(size > 0 && size <= decoder.remaining()) { "Invalid TransferBox payload length" }
            return TransferVariant(tag, decoder.readBytes(size.toInt()))
        }
    }

    private inline fun <T> checked(block: () -> T): T = try {
        block()
    } catch (error: ToriiExplorerInstructionException) {
        throw error
    } catch (error: Exception) {
        throw ToriiExplorerInstructionException(error)
    }
}
