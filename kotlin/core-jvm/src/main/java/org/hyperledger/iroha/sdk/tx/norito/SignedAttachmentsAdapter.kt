package org.hyperledger.iroha.sdk.tx.norito

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.hyperledger.iroha.sdk.core.model.*
import org.hyperledger.iroha.sdk.crypto.Blake3
import org.hyperledger.iroha.sdk.norito.*

/** One canonical signed attachment codec, also used to write the proof-free hash projection. */
internal class SignedAttachmentsAdapter(private val account: TypeAdapter<String>) : TypeAdapter<SignedAttachmentsV1> {
    override fun encode(encoder: NoritoEncoder, value: SignedAttachmentsV1) {
        value.validateStructure()
        encodeValue(encoder, value, false)
    }

    internal fun encodeValue(encoder: NoritoEncoder, value: SignedAttachmentsV1, normalized: Boolean) {
        requireAggregateBytes(value)
        requireCanonicalSize(value, encoder.flags, normalized)
        field(encoder) { actions ->
            sequence(actions, value.actions) { child, action -> encodeAction(child, action, normalized) }
        }
        field(encoder) { occurrences ->
            sequence(occurrences, value.occurrences) { child, occurrence ->
                u32Field(child, occurrence.index)
                tagField(child, occurrence.kind.ordinal)
                u64Field(child, if (normalized && occurrence.kind == AttachmentKindV1.Proof) 0 else occurrence.length)
                digestField(child, if (normalized && occurrence.kind == AttachmentKindV1.Proof) ZERO else occurrence.contentHash.bytes)
                field(child) { bytes ->
                    val content = if (normalized) ByteArray(0) else occurrence.bytes
                    bytes.writeLength(content.size.toLong(), false)
                    bytes.writeBytes(content)
                }
            }
        }
    }

    override fun decode(decoder: NoritoDecoder): SignedAttachmentsV1 {
        require(decoder.remaining() + NoritoHeader.HEADER_LENGTH <= SignedAttachmentLimitsV1.MAX_FRAME_BYTES) {
            "signed attachment frame exceeds its aggregate bound"
        }
        val actions = readField(decoder, METADATA_LIMIT) { readSequence(it, SignedAttachmentLimitsV1.MAX_ACTIONS, METADATA_LIMIT, ::decodeAction) }
        val occurrences = readField(decoder, SignedAttachmentLimitsV1.MAX_FRAME_BYTES) {
            readSequence(it, SignedAttachmentLimitsV1.MAX_OCCURRENCES, SignedAttachmentLimitsV1.MAX_FRAME_BYTES) { child ->
                val index = readU32Field(child)
                val kind = readKind(child)
                val length = readU64Field(child)
                require(length in 0..SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES.toLong()) { "attachment declared length exceeds its bound" }
                val hash = AttachmentContentHashV1(readDigestField(child))
                val bytes = readField(child, SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES + 8) { body ->
                    val count = body.readLength(false)
                    require(count <= SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES) { "attachment byte count exceeds its bound" }
                    body.readBytes(count.toInt())
                }
                SignedAttachmentOccurrenceV1(index, kind, length, hash, bytes)
            }
        }
        return SignedAttachmentsV1(actions, occurrences).also { it.validateStructure() }
    }

    internal fun canonicalFrame(value: SignedAttachmentsV1): ByteArray {
        requireAggregateBytes(value)
        val encoded = NoritoCodec.encode(value, SCHEMA, this)
        require(encoded.size <= SignedAttachmentLimitsV1.MAX_FRAME_BYTES) { "signed attachment frame exceeds its aggregate bound" }
        return encoded
    }

    // Compute the exact bounded frame size using only small action metadata, before copying
    // or concatenating inline proof bytes into any aggregate encoder.
    private fun requireCanonicalSize(value: SignedAttachmentsV1, flags: Int, normalized: Boolean, declaredByteCounts: Boolean = false) {
        fun prefix(size: Long): Long {
            if (flags and NoritoHeader.COMPACT_LEN == 0) return 8
            var remaining = size
            var bytes = 1L
            while (remaining >= 128) { remaining = remaining ushr 7; bytes++ }
            return bytes
        }
        fun field(size: Long): Long = prefix(size) + size
        var actions = 8L
        for (action in value.actions) {
            val child = NoritoEncoder(flags)
            encodeAction(child, action, normalized)
            actions += field(child.toByteArray().size.toLong())
        }
        var occurrences = 8L
        for (occurrence in value.occurrences) {
            val bytes = if (normalized) 0L else if (declaredByteCounts) occurrence.length else occurrence.byteCount.toLong()
            val body = field(4) + field(4) + field(8) + field(field(32)) + field(8 + bytes)
            occurrences += field(body)
        }
        require(NoritoHeader.HEADER_LENGTH + field(actions) + field(occurrences) <= SignedAttachmentLimitsV1.MAX_FRAME_BYTES) {
            "signed attachment frame exceeds its aggregate bound"
        }
    }

    internal fun requireTransactionCarrierSizes(sizes: List<Long>) {
        require(sizes.size in 1..SignedAttachmentLimitsV1.MAX_OCCURRENCES) { "invalid carrier count" }
        val hash = AttachmentContentHashV1(ZERO)
        val occurrences = sizes.mapIndexed { index, size ->
            require(size in 1..SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES.toLong()) {
                "proof carrier exceeds the signed occurrence bound before encoding"
            }
            SignedAttachmentOccurrenceV1(index.toLong(), AttachmentKindV1.Proof, size, hash, ByteArray(0))
        }
        val actions = occurrences.map { occurrence ->
            ActionIntentV1(occurrence.index, ActionOperationV1.TransactionProof, ActionRoleV1.ProofVerification,
                ActionAuthorityBindingV1.TransactionAuthority, ActionInvocationBindingV1.Transaction,
                ActionPublicInputsDigestV1(ZERO), ActionStatementDigestV1(ZERO),
                listOf(AttachmentReferenceV1(occurrence.index, occurrence.kind, AttachmentRoleV1.ActionProof,
                    occurrence.length, hash)))
        }
        requireCanonicalSize(SignedAttachmentsV1(actions, occurrences), NoritoCodec.DEFAULT_FLAGS, false, true)
    }

    internal fun statementDigest(action: ActionIntentV1, intent: OrderedIntentDigestV1): ActionStatementDigestV1 {
        val adapter = object : TypeAdapter<ActionIntentV1> {
            override fun encode(encoder: NoritoEncoder, value: ActionIntentV1) {
                digestField(encoder, intent.bytes)
                u32Field(encoder, value.actionIndex)
                field(encoder) { encodeOperation(it, value.operation) }
                tagField(encoder, value.role.ordinal)
                field(encoder) { encodeAuthority(it, value.authority) }
                field(encoder) { encodeInvocation(it, value.invocation) }
                digestField(encoder, value.publicInputsDigest.bytes)
            }
            override fun decode(decoder: NoritoDecoder): ActionIntentV1 =
                throw UnsupportedOperationException("statement hashing does not decode action intents")
        }
        return ActionStatementDigestV1(domainDigest(STATEMENT_DOMAIN, NoritoCodec.encode(action, STATEMENT_SCHEMA, adapter)))
    }

    private fun encodeAction(encoder: NoritoEncoder, action: ActionIntentV1, normalized: Boolean) {
        u32Field(encoder, action.actionIndex)
        field(encoder) { encodeOperation(it, action.operation) }
        tagField(encoder, action.role.ordinal)
        field(encoder) { encodeAuthority(it, action.authority) }
        field(encoder) { encodeInvocation(it, action.invocation) }
        digestField(encoder, action.publicInputsDigest.bytes)
        digestField(encoder, if (normalized) ZERO else action.statementDigest.bytes)
        field(encoder) { references ->
            sequence(references, action.attachments) { child, reference ->
                u32Field(child, reference.index)
                tagField(child, reference.kind.ordinal)
                tagField(child, reference.role.ordinal)
                u64Field(child, if (normalized && reference.kind == AttachmentKindV1.Proof) 0 else reference.length)
                digestField(child, if (normalized && reference.kind == AttachmentKindV1.Proof) ZERO else reference.contentHash.bytes)
            }
        }
    }

    private fun decodeAction(decoder: NoritoDecoder): ActionIntentV1 = ActionIntentV1(
        readU32Field(decoder),
        readField(decoder, SignedAttachmentLimitsV1.MAX_WIRE_ID_BYTES + 20, ::decodeOperation),
        enumValue(readTagField(decoder), ActionRoleV1.values(), "action role"),
        readField(decoder, METADATA_LIMIT, ::decodeAuthority),
        readField(decoder, METADATA_LIMIT, ::decodeInvocation),
        ActionPublicInputsDigestV1(readDigestField(decoder)),
        ActionStatementDigestV1(readDigestField(decoder)),
        readField(decoder, METADATA_LIMIT) {
            readSequence(it, SignedAttachmentLimitsV1.MAX_OCCURRENCES, 128) { child ->
                AttachmentReferenceV1(
                    readU32Field(child), readKind(child),
                    enumValue(readTagField(child), AttachmentRoleV1.values(), "attachment role"),
                    readU64Field(child), AttachmentContentHashV1(readDigestField(child)),
                )
            }
        },
    )

    private fun encodeOperation(encoder: NoritoEncoder, value: ActionOperationV1) {
        when (value) {
            is ActionOperationV1.NativeInstruction -> {
                encoder.writeUInt(0, 32)
                field(encoder) { NoritoAdapters.stringAdapter().encode(it, value.wireId) }
            }
            ActionOperationV1.TransactionProof -> encoder.writeUInt(1, 32)
            ActionOperationV1.IvmProvedExecution -> encoder.writeUInt(2, 32)
        }
    }
    private fun decodeOperation(decoder: NoritoDecoder): ActionOperationV1 = when (val tag = decoder.readUInt(32)) {
        0L -> ActionOperationV1.NativeInstruction(readField(decoder, SignedAttachmentLimitsV1.MAX_WIRE_ID_BYTES + 8) {
            val count = it.readLength(it.compactLenActive())
            require(count in 1..SignedAttachmentLimitsV1.MAX_WIRE_ID_BYTES.toLong()) { "native operation wire ID exceeds its bound" }
            val bytes = it.readBytes(count.toInt())
            require(bytes.all { byte -> byte.toInt() in 33..126 }) { "native operation must be graphic ASCII" }
            String(bytes, Charsets.US_ASCII)
        })
        1L -> ActionOperationV1.TransactionProof
        2L -> ActionOperationV1.IvmProvedExecution
        else -> throw IllegalArgumentException("unknown action operation tag $tag")
    }

    private fun encodeAuthority(encoder: NoritoEncoder, value: ActionAuthorityBindingV1) {
        when (value) {
            ActionAuthorityBindingV1.TransactionAuthority -> encoder.writeUInt(0, 32)
            is ActionAuthorityBindingV1.ContractSubject -> {
                encoder.writeUInt(1, 32)
                field(encoder) { account.encode(it, value.accountId) }
            }
            is ActionAuthorityBindingV1.Account -> {
                encoder.writeUInt(2, 32)
                field(encoder) { account.encode(it, value.accountId) }
            }
        }
    }
    private fun decodeAuthority(decoder: NoritoDecoder): ActionAuthorityBindingV1 = when (val tag = decoder.readUInt(32)) {
        0L -> ActionAuthorityBindingV1.TransactionAuthority
        1L -> ActionAuthorityBindingV1.ContractSubject(readField(decoder, METADATA_LIMIT, account::decode))
        2L -> ActionAuthorityBindingV1.Account(readField(decoder, METADATA_LIMIT, account::decode))
        else -> throw IllegalArgumentException("unknown action authority tag $tag")
    }

    private fun encodeInvocation(encoder: NoritoEncoder, value: ActionInvocationBindingV1) {
        when (value) {
            ActionInvocationBindingV1.Transaction -> encoder.writeUInt(0, 32)
            is ActionInvocationBindingV1.Direct -> {
                encoder.writeUInt(1, 32)
                u32Field(encoder, value.instructionIndex)
            }
            is ActionInvocationBindingV1.Contract -> {
                encoder.writeUInt(2, 32)
                u32Field(encoder, value.rootIndex)
                field(encoder) { path -> sequence(path, value.callPath) { child, index -> child.writeUInt(index, 32) } }
            }
        }
    }
    private fun decodeInvocation(decoder: NoritoDecoder): ActionInvocationBindingV1 = when (val tag = decoder.readUInt(32)) {
        0L -> ActionInvocationBindingV1.Transaction
        1L -> ActionInvocationBindingV1.Direct(readU32Field(decoder))
        2L -> ActionInvocationBindingV1.Contract(readU32Field(decoder), readField(decoder, METADATA_LIMIT) {
            readSequence(it, SignedAttachmentLimitsV1.MAX_CALL_PATH, 4) { child -> child.readUInt(32) }
        })
        else -> throw IllegalArgumentException("unknown action invocation tag $tag")
    }

    companion object {
        internal const val SCHEMA = "iroha_data_model::transaction::signed_attachments::SignedAttachmentsV1"
        private const val STATEMENT_SCHEMA = "iroha_data_model::transaction::signed_attachments::ActionStatementV1"
        private const val STATEMENT_DOMAIN = "iroha.transaction.action-statement-digest.v1"
        private const val METADATA_LIMIT = SignedAttachmentLimitsV1.MAX_FRAME_BYTES
        private val ZERO = ByteArray(32)

        internal fun domainDigest(domain: String, frame: ByteArray): ByteArray {
            val domainBytes = domain.toByteArray(Charsets.US_ASCII)
            val buffer = ByteBuffer.allocate(domainBytes.size + 8 + frame.size).order(ByteOrder.LITTLE_ENDIAN)
            buffer.put(domainBytes).putLong(frame.size.toLong()).put(frame)
            return Blake3.hash(buffer.array())
        }
        private fun requireAggregateBytes(value: SignedAttachmentsV1) {
            require(value.occurrences.sumOf { it.byteCount.toLong() } + NoritoHeader.HEADER_LENGTH <= SignedAttachmentLimitsV1.MAX_FRAME_BYTES) {
                "signed attachment bytes exceed the aggregate frame bound"
            }
        }
        private fun field(encoder: NoritoEncoder, encode: (NoritoEncoder) -> Unit) {
            val child = encoder.childEncoder()
            encode(child)
            val payload = child.toByteArray()
            encoder.writeLength(payload.size.toLong(), encoder.flags and NoritoHeader.COMPACT_LEN != 0)
            encoder.writeBytes(payload)
        }
        private fun <T> readField(decoder: NoritoDecoder, maximum: Int, decode: (NoritoDecoder) -> T): T {
            val size = decoder.readLength(decoder.compactLenActive())
            require(size <= maximum) { "signed attachment field exceeds its bound" }
            val child = NoritoDecoder(ByteBuffer.wrap(decoder.readBytes(size.toInt())).order(ByteOrder.LITTLE_ENDIAN), decoder.flags)
            val value = decode(child)
            require(child.remaining() == 0) { "trailing signed attachment field bytes" }
            return value
        }
        private fun <T> sequence(encoder: NoritoEncoder, values: List<T>, encode: (NoritoEncoder, T) -> Unit) {
            encoder.writeLength(values.size.toLong(), false)
            values.forEach { value -> field(encoder) { encode(it, value) } }
        }
        private fun <T> readSequence(decoder: NoritoDecoder, maximum: Int, maximumElement: Int, decode: (NoritoDecoder) -> T): List<T> {
            val count = decoder.readLength(false)
            require(count <= maximum) { "signed attachment sequence count exceeds its bound" }
            return List(count.toInt()) { readField(decoder, maximumElement, decode) }
        }
        private fun u32Field(encoder: NoritoEncoder, value: Long) = field(encoder) { it.writeUInt(value, 32) }
        private fun u64Field(encoder: NoritoEncoder, value: Long) = field(encoder) { it.writeUInt(value, 64) }
        private fun tagField(encoder: NoritoEncoder, value: Int) = u32Field(encoder, value.toLong())
        private fun readU32Field(decoder: NoritoDecoder): Long = readField(decoder, 4) { it.readUInt(32) }
        private fun readU64Field(decoder: NoritoDecoder): Long = readField(decoder, 8) { it.readUInt(64) }
        private fun readTagField(decoder: NoritoDecoder): Long = readU32Field(decoder)
        private fun digestField(encoder: NoritoEncoder, bytes: ByteArray) = field(encoder) { digest -> field(digest) { it.writeBytes(bytes) } }
        private fun readDigestField(decoder: NoritoDecoder): ByteArray = readField(decoder, 40) { readField(it, 32) { raw -> raw.readBytes(32) } }
        private fun readKind(decoder: NoritoDecoder): AttachmentKindV1 = enumValue(readTagField(decoder), AttachmentKindV1.values(), "attachment kind")
        private fun <T> enumValue(tag: Long, values: Array<T>, name: String): T {
            require(tag in 0..Int.MAX_VALUE) { "unknown $name tag $tag" }
            return values.getOrNull(tag.toInt()) ?: throw IllegalArgumentException("unknown $name tag $tag")
        }
    }
}
