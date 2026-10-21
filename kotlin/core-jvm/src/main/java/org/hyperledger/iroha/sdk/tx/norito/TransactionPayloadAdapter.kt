package org.hyperledger.iroha.sdk.tx.norito

import org.hyperledger.iroha.sdk.core.model.instructions.KaigiWirePayloadEncoderV1
import org.hyperledger.iroha.sdk.core.model.instructions.UpdatePlainConvictionWirePayloadEncoder

import java.math.BigInteger
import java.util.LinkedHashMap
import java.util.Optional
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.AccountAddressException
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.address.MultisigMemberPayload
import org.hyperledger.iroha.sdk.address.MultisigPolicyPayload
import org.hyperledger.iroha.sdk.address.PublicKeyPayload
import org.hyperledger.iroha.sdk.address.algorithmForCurveId
import org.hyperledger.iroha.sdk.address.compactPublicKeyPayload
import org.hyperledger.iroha.sdk.address.decodeCompactPublicKeyPayload
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.core.model.ContractInvocation
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.ExecutableBatchItem
import org.hyperledger.iroha.sdk.core.model.FeeChargeKind
import org.hyperledger.iroha.sdk.core.model.FeeChargeLimit
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.FeeSponsorProgramId
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.core.model.SignedAttachmentsV1
import org.hyperledger.iroha.sdk.core.model.ActionIntentV1
import org.hyperledger.iroha.sdk.core.model.ActionOperationV1
import org.hyperledger.iroha.sdk.core.model.ActionInvocationBindingV1
import org.hyperledger.iroha.sdk.core.model.ActionPublicInputsDigestV1
import org.hyperledger.iroha.sdk.core.model.OrderedIntentDigestV1
import org.hyperledger.iroha.sdk.core.model.AttachmentRoleV1
import org.hyperledger.iroha.sdk.core.model.SignedAttachmentLimitsV1
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.model.instructions.LanePrivacyMerkleWitness
import org.hyperledger.iroha.sdk.core.model.instructions.LanePrivacyProof
import org.hyperledger.iroha.sdk.core.model.instructions.LanePrivacyWitness
import org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment
import org.hyperledger.iroha.sdk.core.model.instructions.ProofVerifierKeyRef
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.TypeAdapter
import org.hyperledger.iroha.sdk.numeric.KotodamaQuantity

internal class TransactionPayloadAdapter private constructor(
    private val chainDiscriminant: Int,
) : TypeAdapter<TransactionPayload> {

    /** Complete canonical Norito archive using the transaction's sole fee-field adapter. */
    fun encodeFeePaymentIntent(value: FeePaymentIntent): ByteArray = withChainContext(chainDiscriminant) {
        NoritoCodec.encode(value, "iroha_data_model::transaction::signed::model::FeePaymentIntent", FEE_PAYMENT_ADAPTER)
    }

    override fun encode(encoder: NoritoEncoder, value: TransactionPayload) = encodePayload(encoder, value, false)

    private fun encodePayload(encoder: NoritoEncoder, value: TransactionPayload, normalized: Boolean) {
        withChainContext(chainDiscriminant) {
            if (!normalized) validateSignedAttachments(value)
            if (!normalized) when (val executable = value.executable) {
                is Executable.Instructions -> executable.instructions.forEach {
                    it.requirePrivacyExact12Network(value.networkId)
                }
                is Executable.Batch -> executable.entries.forEach {
                    if (it is ExecutableBatchItem.Instruction) {
                        it.instruction.requirePrivacyExact12Network(value.networkId)
                    }
                }
                is Executable.IvmProved -> executable.overlay.forEach { it.requirePrivacyExact12Network(value.networkId) }
                is Executable.Ivm, is Executable.ContractCall -> Unit
            }
            require(!value.executable.requiresTransactionGasLimit() || value.feePayment.gasLimit != null) {
                "feePayment.gasLimit is required for IVM and contract-call executables"
            }
            encodeSizedField(encoder, TRANSACTION_DOMAIN_ADAPTER, value.networkId)
            encodeSizedField(encoder, ACCOUNT_ID_ADAPTER, value.authority)
            encodeSizedField(encoder, UINT64_ADAPTER, value.creationTimeMs)
            encodeSizedField(encoder, if (normalized) IntentExecutableAdapter() else EXECUTABLE_ADAPTER, value.executable)
            encodeSizedField(encoder, TTL_ADAPTER, Optional.ofNullable(value.timeToLiveMs))
            encodeSizedField(encoder, NONCE_ADAPTER, Optional.ofNullable(value.nonce))
            encodeSizedField(encoder, FEE_PAYMENT_ADAPTER, value.feePayment)

            encodeSizedField(encoder, METADATA_ADAPTER, value.metadata)
            encodeSizedField(
                encoder,
                if (normalized) NORMALIZED_ATTACHMENTS_OPTION_ADAPTER else ATTACHMENTS_OPTION_ADAPTER,
                Optional.ofNullable(value.attachments),
            )
        }
    }

    override fun decode(decoder: NoritoDecoder): TransactionPayload =
        withChainContext(chainDiscriminant) {
            val networkId = decodeSizedField(decoder, TRANSACTION_DOMAIN_ADAPTER)
            val authority = decodeAuthorityField(decoder)
            val creationTimeMs = decodeSizedField(decoder, UINT64_ADAPTER)
            val executable = decodeSizedField(decoder, EXECUTABLE_ADAPTER)
            val ttl: Optional<Long> = decodeSizedField(decoder, TTL_ADAPTER)
            require(ttl.isPresent) {
                "TransactionPayload.time_to_live_ms must be signature-bound"
            }
            val nonceRaw: Optional<Long> = decodeSizedField(decoder, NONCE_ADAPTER)
            val feePayment = decodeSizedField(decoder, FEE_PAYMENT_ADAPTER)

            val metadata = LinkedHashMap(decodeSizedField(decoder, METADATA_ADAPTER))
            val attachments: Optional<SignedAttachmentsV1> =
                decodeBoundedSizedField(decoder, ATTACHMENTS_OPTION_ADAPTER,
                    SignedAttachmentLimitsV1.MAX_FRAME_BYTES.toLong(), "signed attachments")

            TransactionPayload(
                networkId = networkId,
                authority = authority,
                creationTimeMs = creationTimeMs,
                executable = executable,
                timeToLiveMs = ttl.get(),
                nonce = nonceRaw.orElse(null),
                feePayment = feePayment,

                metadata = metadata,
                attachments = attachments.orElse(null),
            ).also(::validateSignedAttachments)
        }

    /** Decode one canonical standalone attachment frame with the transaction's account codec. */
    internal fun decodeAttachmentsFrame(bytes: ByteArray): SignedAttachmentsV1 = withChainContext(chainDiscriminant) {
        require(bytes.size <= SignedAttachmentLimitsV1.MAX_FRAME_BYTES) { "signed attachment frame exceeds its bound" }
        val frame = NoritoHeader.decode(bytes, org.hyperledger.iroha.sdk.norito.SchemaHash.hash16(SignedAttachmentsAdapter.SCHEMA))
        require(frame.header.flags == NoritoCodec.DEFAULT_FLAGS && frame.header.compression == NoritoHeader.COMPRESSION_NONE) {
            "signed attachments require canonical framing"
        }
        val value = NoritoCodec.decode(bytes, SIGNED_ATTACHMENTS_ADAPTER, SignedAttachmentsAdapter.SCHEMA)
        require(SIGNED_ATTACHMENTS_ADAPTER.canonicalFrame(value).contentEquals(bytes)) { "noncanonical signed attachments" }
        value.actions.filter { it.operation == ActionOperationV1.TransactionProof || it.operation == ActionOperationV1.IvmProvedExecution }.forEach { validateCarrier(it, value) }
        value
    }

    internal fun actionStatementDigest(action: ActionIntentV1, intent: OrderedIntentDigestV1) =
        withChainContext(chainDiscriminant) { SIGNED_ATTACHMENTS_ADAPTER.statementDigest(action, intent) }

    /** Exact canonical frame hashed by Rust's ordered intent digest. */
    internal fun orderedIntentProjection(value: TransactionPayload): ByteArray = withChainContext(chainDiscriminant) {
        NoritoCodec.encode(value, CANONICAL_PAYLOAD_SCHEMA, object : TypeAdapter<TransactionPayload> {
            override fun encode(encoder: NoritoEncoder, value: TransactionPayload) = encodePayload(encoder, value, true)
            override fun decode(decoder: NoritoDecoder): TransactionPayload =
                throw UnsupportedOperationException("an ordered intent projection is not a decodable transaction")
        })
    }

    /** Encode-only adapters keep proof-free bytes outside admitted instruction models. */
    private inner class IntentExecutableAdapter : TypeAdapter<Executable> {
        override fun encode(encoder: NoritoEncoder, value: Executable) {
            when (value) {
                is Executable.Instructions -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_INSTRUCTIONS_TAG)
                    encodeSizedField(encoder, NoritoAdapters.sequence(IntentInstructionAdapter()), value.instructions)
                }
                is Executable.Batch -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_BATCH_TAG)
                    encodeSizedField(encoder, NoritoAdapters.sequence(IntentBatchItemAdapter()), value.entries)
                }
                else -> encodeExecutable(encoder, normalizeExecutable(value))
            }
        }
        override fun decode(decoder: NoritoDecoder): Executable =
            throw UnsupportedOperationException("an ordered intent projection is not executable")
    }

    private inner class IntentBatchItemAdapter : TypeAdapter<ExecutableBatchItem> {
        override fun encode(encoder: NoritoEncoder, value: ExecutableBatchItem) {
            when (value) {
                is ExecutableBatchItem.Instruction -> {
                    ENUM_TAG_ADAPTER.encode(encoder, BATCH_ITEM_INSTRUCTION_TAG)
                    encodeSizedField(encoder, IntentInstructionAdapter(), value.instruction)
                }
                is ExecutableBatchItem.ContractCall -> {
                    ENUM_TAG_ADAPTER.encode(encoder, BATCH_ITEM_CONTRACT_CALL_TAG)
                    encodeSizedField(encoder, CONTRACT_INVOCATION_ADAPTER, value.invocation)
                }
            }
        }
        override fun decode(decoder: NoritoDecoder): ExecutableBatchItem =
            throw UnsupportedOperationException("an ordered intent projection is not executable")
    }

    private class IntentInstructionAdapter : TypeAdapter<InstructionBox> {
        override fun encode(encoder: NoritoEncoder, value: InstructionBox) {
            val wire = value.payload as? WirePayload
            if (wire?.wireName != "iroha.privacy.submit_proof.v1") {
                INSTRUCTION_ADAPTER.encode(encoder, value)
                return
            }
            val projection = org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge
                .submitProofIntentProjectionV1(wire.payloadBytes)
            encodeSizedField(encoder, STRING_ADAPTER, wire.wireName)
            encodeSizedField(encoder, RAW_BYTE_VEC_ADAPTER, projection.bytes())
        }
        override fun decode(decoder: NoritoDecoder): InstructionBox =
            throw UnsupportedOperationException("an ordered intent projection is not an admitted instruction")
    }

    private fun normalizeExecutable(executable: Executable): Executable = when (executable) {
        is Executable.IvmProved -> {
            // Hash::prehashed([0; 32]) retains the mandatory Iroha hash marker.
            val clearedHash = ByteArray(32).also { it[31] = 1 }
            Executable.IvmProved(executable.ivmBytes, emptyList(), clearedHash, clearedHash)
        }
        else -> executable
    }

    internal fun orderedIntentDigest(value: TransactionPayload): OrderedIntentDigestV1 =
        OrderedIntentDigestV1(SignedAttachmentsAdapter.domainDigest(ORDERED_INTENT_DOMAIN, orderedIntentProjection(value)))

    /** Rebind the descriptor after independent payload fields change; proofs must then be regenerated. */
    internal fun bindAttachmentStatements(value: TransactionPayload): TransactionPayload = withChainContext(chainDiscriminant) {
        val attachments = value.attachments ?: return@withChainContext value
        val intent = orderedIntentDigest(value)
        value.copy(attachments = SignedAttachmentsV1(
            attachments.actions.map { it.withStatementDigest(SIGNED_ATTACHMENTS_ADAPTER.statementDigest(it, intent)) },
            attachments.occurrences,
        )).also(::validateSignedAttachments)
    }

    internal fun withProofAttachments(value: TransactionPayload, proofs: List<ProofAttachment>): TransactionPayload =
        withChainContext(chainDiscriminant) {
            val count = proofs.size
            require(count in 1..SignedAttachmentLimitsV1.MAX_OCCURRENCES) { "proof carrier count exceeds its bound" }
            val carriers = List(count) { proofs[it] }
            preflightProofAttachments(carriers)
            val occurrences = carriers.mapIndexed { index, proof ->
                org.hyperledger.iroha.sdk.core.model.SignedAttachmentOccurrenceV1.of(
                    index.toLong(), org.hyperledger.iroha.sdk.core.model.AttachmentKindV1.Proof,
                    NoritoCodec.encode(proof, PROOF_ATTACHMENT_SCHEMA, PROOF_ATTACHMENT_ADAPTER),
                )
            }
            val actions = carriers.mapIndexed { index, proof ->
                val occurrence = occurrences[index]
                ActionIntentV1(
                    index.toLong(), ActionOperationV1.TransactionProof,
                    org.hyperledger.iroha.sdk.core.model.ActionRoleV1.ProofVerification,
                    org.hyperledger.iroha.sdk.core.model.ActionAuthorityBindingV1.TransactionAuthority,
                    ActionInvocationBindingV1.Transaction,
                    ActionPublicInputsDigestV1(SignedAttachmentsAdapter.domainDigest(PROOF_CARRIER_DOMAIN,
                        NoritoCodec.encode(proof, PROOF_ATTACHMENT_SCHEMA, PROOF_FREE_ATTACHMENT_ADAPTER))),
                    org.hyperledger.iroha.sdk.core.model.ActionStatementDigestV1(ByteArray(32)),
                    listOf(org.hyperledger.iroha.sdk.core.model.AttachmentReferenceV1(
                        index.toLong(), occurrence.kind,
                        if (proof.lanePrivacy == null) AttachmentRoleV1.ActionProof else AttachmentRoleV1.LanePrivacyProof,
                        occurrence.length, occurrence.contentHash,
                    )),
                )
            }
            bindAttachmentStatements(value.copy(attachments = SignedAttachmentsV1(actions, occurrences)))
        }

    internal fun withIvmExecutionProof(value: TransactionPayload, proof: ProofAttachment): TransactionPayload =
        withChainContext(chainDiscriminant) {
            require(value.executable is Executable.IvmProved) { "execution proof requires a proved executable" }
            require(proof.lanePrivacy == null) { "execution proof cannot carry a lane privacy witness" }
            val carrier = withProofAttachments(value, listOf(proof)).attachments!!
            val action = carrier.actions.single()
            val reference = action.attachments.single()
            val execution = ActionIntentV1(action.actionIndex, ActionOperationV1.IvmProvedExecution,
                org.hyperledger.iroha.sdk.core.model.ActionRoleV1.ProofEffect, action.authority,
                action.invocation, action.publicInputsDigest, action.statementDigest,
                listOf(org.hyperledger.iroha.sdk.core.model.AttachmentReferenceV1(reference.index,
                    reference.kind, AttachmentRoleV1.ExecutionProof, reference.length, reference.contentHash)))
            bindAttachmentStatements(value.copy(attachments = SignedAttachmentsV1(listOf(execution), carrier.occurrences)))
        }

    internal fun preflightProofAttachments(proofs: List<ProofAttachment>) {
        require(proofs.size in 1..SignedAttachmentLimitsV1.MAX_OCCURRENCES) { "proof carrier count exceeds its bound" }
        // Plan all sizes before any proofBytes() copy or canonical frame construction.
        preflightCarrierSizes(proofs.map { canonicalCarrierSize(it) })
    }

    internal fun preflightCarrierSizes(sizes: List<Long>) = SIGNED_ATTACHMENTS_ADAPTER.requireTransactionCarrierSizes(sizes)

    private fun canonicalCarrierSize(proof: ProofAttachment): Long {
        require(proof.proofByteCount <= SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES) {
            "proof carrier exceeds the signed occurrence bound before encoding"
        }
        val empty = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
        ProofAttachmentAdapter(omitProofBytes = true).encode(empty, proof)
        val backendSize = proof.backend.toByteArray(Charsets.UTF_8).size.toLong()
        fun field(size: Long): Long {
            var remaining = size
            var prefix = 1L
            while (remaining >= 128) { remaining = remaining ushr 7; prefix++ }
            return size + prefix
        }
        val zeroBox = ProofAttachment.canonicalProofBoxEncodedLength(backendSize, 0)
        val realBox = ProofAttachment.canonicalProofBoxEncodedLength(backendSize, proof.proofByteCount.toLong())
        return NoritoHeader.HEADER_LENGTH + empty.toByteArray().size - field(zeroBox) + field(realBox)
    }

    private fun validateSignedAttachments(value: TransactionPayload) {
        val attachments = value.attachments ?: return
        SIGNED_ATTACHMENTS_ADAPTER.canonicalFrame(attachments)
        val intent = orderedIntentDigest(value)
        val direct = HashSet<Long>()
        var executionCarrierSeen = false
        for (action in attachments.actions) {
            when (val operation = action.operation) {
                ActionOperationV1.TransactionProof -> validateCarrier(action, attachments)
                ActionOperationV1.IvmProvedExecution -> {
                    require(!executionCarrierSeen && value.executable is Executable.IvmProved) {
                        "execution carrier requires a proved executable and must be unique"
                    }
                    executionCarrierSeen = true
                    validateCarrier(action, attachments)
                }
                is ActionOperationV1.NativeInstruction -> {
                    require(operation.wireId in InstructionWireIdsV1.values) { "unregistered native action wire ID" }
                    when (val invocation = action.invocation) {
                    is ActionInvocationBindingV1.Direct -> {
                        val instruction = when (val executable = value.executable) {
                            is Executable.Instructions -> executable.instructions.getOrNull(invocation.instructionIndex.toInt())
                            is Executable.Batch -> (executable.entries.getOrNull(invocation.instructionIndex.toInt()) as? ExecutableBatchItem.Instruction)?.instruction
                            else -> null
                        }
                        require((instruction?.payload as? WirePayload)?.wireName == operation.wireId) { "action invocation target mismatch" }
                        require(direct.add(invocation.instructionIndex)) { "duplicate direct action invocation" }
                    }
                    is ActionInvocationBindingV1.Contract -> {
                        val validRoot = when (val executable = value.executable) {
                            is Executable.Ivm, is Executable.IvmProved, is Executable.ContractCall -> invocation.rootIndex == 0L
                            is Executable.Batch -> executable.entries.getOrNull(invocation.rootIndex.toInt()) is ExecutableBatchItem.ContractCall
                            else -> false
                        }
                        require(validRoot) { "action contract root mismatch" }
                    }
                    ActionInvocationBindingV1.Transaction -> throw IllegalArgumentException("native action requires an instruction or contract invocation")
                    }
                }
            }
            require(action.statementDigest == SIGNED_ATTACHMENTS_ADAPTER.statementDigest(action, intent)) { "action statement binding mismatch" }
        }
    }

    private fun validateCarrier(action: ActionIntentV1, attachments: SignedAttachmentsV1) {
        val reference = action.attachments.single()
        val encoded = attachments.occurrences[reference.index.toInt()].bytes
        val decoded = NoritoHeader.decode(encoded, org.hyperledger.iroha.sdk.norito.SchemaHash.hash16(PROOF_ATTACHMENT_SCHEMA))
        require(decoded.header.flags == NoritoCodec.DEFAULT_FLAGS && decoded.header.compression == NoritoHeader.COMPRESSION_NONE) { "proof carrier must use canonical Norito framing" }
        val proof = NoritoCodec.decode(encoded, PROOF_ATTACHMENT_ADAPTER, PROOF_ATTACHMENT_SCHEMA)
        require(encoded.contentEquals(NoritoCodec.encode(proof, PROOF_ATTACHMENT_SCHEMA, PROOF_ATTACHMENT_ADAPTER))) { "proof carrier is not canonically encoded" }
        require((reference.role == AttachmentRoleV1.LanePrivacyProof) == (proof.lanePrivacy != null)) { "proof carrier role mismatch" }
        val normalized = NoritoCodec.encode(proof, PROOF_ATTACHMENT_SCHEMA, PROOF_FREE_ATTACHMENT_ADAPTER)
        require(action.publicInputsDigest == ActionPublicInputsDigestV1(SignedAttachmentsAdapter.domainDigest(PROOF_CARRIER_DOMAIN, normalized))) { "proof carrier public-input digest mismatch" }
    }

    private class ProofBoxValue(
        val backend: String,
        bytes: ByteArray,
    ) {
        private val encodedBytes = bytes.copyOf()

        fun bytes(): ByteArray = encodedBytes.copyOf()
    }

    private class ProofBoxAdapter : TypeAdapter<ProofBoxValue> {
        override fun encode(encoder: NoritoEncoder, value: ProofBoxValue) {
            encodeSizedField(encoder, STRING_ADAPTER, value.backend)
            encodeSizedField(encoder, RAW_BYTE_VEC_ADAPTER, value.bytes())
        }

        override fun decode(decoder: NoritoDecoder): ProofBoxValue =
            ProofBoxValue(
                decodeBoundedSizedField(
                    decoder,
                    STRING_ADAPTER,
                    PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES,
                    "ProofBox backend",
                ),
                decodeSizedField(decoder, RAW_BYTE_VEC_ADAPTER),
            )
    }

    private class ProofVerifierKeyRefAdapter : TypeAdapter<ProofVerifierKeyRef> {
        override fun encode(encoder: NoritoEncoder, value: ProofVerifierKeyRef) {
            encodeSizedField(encoder, STRING_ADAPTER, value.backend)
            encodeSizedField(encoder, STRING_ADAPTER, value.name)
        }

        override fun decode(decoder: NoritoDecoder): ProofVerifierKeyRef =
            ProofVerifierKeyRef(
                decodeBoundedSizedField(
                    decoder,
                    STRING_ADAPTER,
                    PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES,
                    "verifier-key backend",
                ),
                decodeBoundedSizedField(
                    decoder,
                    STRING_ADAPTER,
                    PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES,
                    "verifier-key name",
                ),
            )
    }

    private object LanePrivacyAuditPathAdapter : TypeAdapter<List<ByteArray>> {
        private val delegate = NoritoAdapters.sequence(OPTIONAL_LANE_PRIVACY_HASH_ADAPTER)

        override fun encode(encoder: NoritoEncoder, value: List<ByteArray>) {
            require(value.size in 1..LanePrivacyMerkleWitness.MAX_DEPTH) {
                "lane privacy audit path depth must be between 1 and ${LanePrivacyMerkleWitness.MAX_DEPTH}"
            }
            delegate.encode(encoder, value.map { Optional.of(it.copyOf()) })
        }

        override fun decode(decoder: NoritoDecoder): List<ByteArray> {
            val countValue = decoder.readLength(false)
            require(countValue in 1L..LanePrivacyMerkleWitness.MAX_DEPTH.toLong()) {
                "lane privacy audit path depth must be between 1 and ${LanePrivacyMerkleWitness.MAX_DEPTH}"
            }
            return decodeDelimited(decoder, countValue.toInt())
        }

        override fun isSelfDelimiting(): Boolean = true

        private fun decodeDelimited(decoder: NoritoDecoder, count: Int): List<ByteArray> {
            val siblings = ArrayList<ByteArray>(count)
            repeat(count) { index ->
                val length = decoder.readLength(decoder.compactLenActive())
                require(length in 1L..LANE_PRIVACY_MAX_SIBLING_OPTION_ENCODED_BYTES) {
                    "lane privacy sibling $index payload is oversized"
                }
                siblings.add(decodeSibling(decoder.readBytes(length.toInt()), decoder, index))
            }
            return siblings
        }

        private fun decodeSibling(
            payload: ByteArray,
            parent: NoritoDecoder,
            index: Int,
        ): ByteArray {
            val child = NoritoDecoder(payload, parent.flags)
            val sibling = OPTIONAL_LANE_PRIVACY_HASH_ADAPTER.decode(child)
            require(child.remaining() == 0) {
                "lane privacy sibling $index has trailing bytes"
            }
            require(sibling.isPresent) {
                "lane privacy sibling $index must be present"
            }
            val bytes = sibling.get()
            require(bytes.last().toInt() and 1 == 1) {
                "lane privacy sibling $index is missing the Iroha prehashed marker"
            }
            return bytes
        }
    }

    private class LanePrivacyMerkleProofValue(
        val leafIndex: Long,
        val auditPath: List<ByteArray>,
    )

    private class LanePrivacyMerkleProofAdapter : TypeAdapter<LanePrivacyMerkleProofValue> {
        override fun encode(encoder: NoritoEncoder, value: LanePrivacyMerkleProofValue) {
            encodeSizedField(encoder, UINT32_ADAPTER, value.leafIndex)
            encodeSizedField(encoder, LANE_PRIVACY_AUDIT_PATH_ADAPTER, value.auditPath)
        }

        override fun decode(decoder: NoritoDecoder): LanePrivacyMerkleProofValue {
            val leafIndex = decodeSizedField(decoder, UINT32_ADAPTER)
            val auditPath = decodeBoundedSizedField(
                decoder,
                LANE_PRIVACY_AUDIT_PATH_ADAPTER,
                LANE_PRIVACY_MAX_AUDIT_PATH_ENCODED_BYTES,
                "lane privacy audit path",
            )
            return LanePrivacyMerkleProofValue(leafIndex, auditPath)
        }
    }

    private class LanePrivacyMerkleWitnessAdapter : TypeAdapter<LanePrivacyMerkleWitness> {
        override fun encode(encoder: NoritoEncoder, value: LanePrivacyMerkleWitness) {
            encodeSizedField(encoder, HASH_ADAPTER, value.leafBytes())
            encodeSizedField(
                encoder,
                LANE_PRIVACY_MERKLE_PROOF_ADAPTER,
                LanePrivacyMerkleProofValue(value.leafIndex, value.auditPathBytes()),
            )
        }

        override fun decode(decoder: NoritoDecoder): LanePrivacyMerkleWitness {
            val leaf = decodeSizedField(decoder, HASH_ADAPTER)
            val proof = decodeSizedField(decoder, LANE_PRIVACY_MERKLE_PROOF_ADAPTER)
            return LanePrivacyMerkleWitness(leaf, proof.leafIndex, proof.auditPath)
        }
    }

    private class LanePrivacyWitnessAdapter : TypeAdapter<LanePrivacyWitness> {
        override fun encode(encoder: NoritoEncoder, value: LanePrivacyWitness) {
            when (value) {
                is LanePrivacyWitness.Merkle -> {
                    ENUM_TAG_ADAPTER.encode(encoder, LANE_PRIVACY_MERKLE_TAG)
                    encodeSizedField(encoder, LANE_PRIVACY_MERKLE_WITNESS_ADAPTER, value.value)
                }
            }
        }

        override fun decode(decoder: NoritoDecoder): LanePrivacyWitness =
            when (val tag = ENUM_TAG_ADAPTER.decode(decoder)) {
                LANE_PRIVACY_MERKLE_TAG -> LanePrivacyWitness.Merkle(
                    decodeSizedField(decoder, LANE_PRIVACY_MERKLE_WITNESS_ADAPTER),
                )
                else -> throw IllegalArgumentException("unknown lane privacy witness tag: $tag")
            }
    }

    private object LaneCommitmentIdAdapter : TypeAdapter<Long> {
        override fun encode(encoder: NoritoEncoder, value: Long) = encodeSizedField(encoder, UINT16_ADAPTER, value)
        override fun decode(decoder: NoritoDecoder): Long = decodeSizedField(decoder, UINT16_ADAPTER)
    }

    private class LanePrivacyProofAdapter : TypeAdapter<LanePrivacyProof> {
        override fun encode(encoder: NoritoEncoder, value: LanePrivacyProof) {
            encodeSizedField(encoder, LANE_COMMITMENT_ID_ADAPTER, value.commitmentId.toLong())
            encodeSizedField(encoder, LANE_PRIVACY_WITNESS_ADAPTER, value.witness)
        }

        override fun decode(decoder: NoritoDecoder): LanePrivacyProof =
            LanePrivacyProof(
                decodeSizedField(decoder, LANE_COMMITMENT_ID_ADAPTER).toInt(),
                decodeSizedField(decoder, LANE_PRIVACY_WITNESS_ADAPTER),
            )
    }

    private class ProofAttachmentAdapter(private val normalized: Boolean = false, private val omitProofBytes: Boolean = false) : TypeAdapter<ProofAttachment> {
        override fun encode(encoder: NoritoEncoder, value: ProofAttachment) {
            encodeSizedField(encoder, STRING_ADAPTER, value.backend)
            encodeSizedField(
                encoder,
                PROOF_BOX_ADAPTER,
                ProofBoxValue(value.backend, if (normalized || omitProofBytes) ByteArray(0) else value.proofBytes()),
            )
            encodeSizedField(encoder, PROOF_VERIFIER_KEY_REF_ADAPTER, value.verifyingKeyRef)

            val commitment = value.verifyingKeyCommitmentBytes()
            val envelopeHash = if (normalized) null else value.envelopeHashBytes()
            val lanePrivacy = value.lanePrivacy
            if (commitment != null || envelopeHash != null || lanePrivacy != null) {
                encodeSizedField(
                    encoder,
                    OPTIONAL_HASH_ADAPTER,
                    Optional.ofNullable(commitment),
                )
            }
            if (envelopeHash != null || lanePrivacy != null) {
                encodeSizedField(
                    encoder,
                    OPTIONAL_HASH_ADAPTER,
                    Optional.ofNullable(envelopeHash),
                )
            }
            if (lanePrivacy != null) {
                encodeSizedField(
                    encoder,
                    OPTIONAL_LANE_PRIVACY_ADAPTER,
                    Optional.of(lanePrivacy),
                )
            }
        }

        override fun decode(decoder: NoritoDecoder): ProofAttachment {
            val backend = decodeBoundedSizedField(
                decoder,
                STRING_ADAPTER,
                PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES,
                "ProofAttachment backend",
            )
            val proof = decodeBoundedSizedField(
                decoder,
                PROOF_BOX_ADAPTER,
                PROOF_BOX_MAX_ENCODED_BYTES,
                "ProofBox",
            )
            require(proof.backend == backend) {
                "proof.backend must match attachment backend"
            }
            val verifyingKeyRef = decodeBoundedSizedField(
                decoder,
                PROOF_VERIFIER_KEY_REF_ADAPTER,
                VERIFYING_KEY_REF_MAX_ENCODED_BYTES,
                "verifier-key reference",
            )
            require(verifyingKeyRef.backend == backend) {
                "vk_ref.backend must match attachment backend"
            }

            var presentTailFields = 0
            val commitment = if (decoder.remaining() == 0) {
                null
            } else {
                presentTailFields = 1
                decodeBoundedSizedField(
                    decoder,
                    OPTIONAL_HASH_ADAPTER,
                    OPTIONAL_FIXED_ARRAY_HASH_MAX_ENCODED_BYTES,
                    "verifier-key commitment",
                ).orElse(null)
            }
            val envelopeHash = if (decoder.remaining() == 0) {
                null
            } else {
                presentTailFields = 2
                decodeBoundedSizedField(
                    decoder,
                    OPTIONAL_HASH_ADAPTER,
                    OPTIONAL_FIXED_ARRAY_HASH_MAX_ENCODED_BYTES,
                    "envelope hash",
                ).orElse(null)
            }
            val lanePrivacy = if (decoder.remaining() == 0) {
                null
            } else {
                presentTailFields = 3
                decodeBoundedSizedField(
                    decoder,
                    OPTIONAL_LANE_PRIVACY_ADAPTER,
                    LANE_PRIVACY_MAX_OPTION_ENCODED_BYTES,
                    "lane privacy proof",
                ).orElse(null)
            }
            require(decoder.remaining() == 0) { "trailing ProofAttachment fields" }
            val canonicalTailFields = when {
                lanePrivacy != null -> 3
                envelopeHash != null -> 2
                commitment != null -> 1
                else -> 0
            }
            require(presentTailFields == canonicalTailFields) {
                "non-canonical redundant ProofAttachment optional tail"
            }

            return ProofAttachment(
                backend,
                proof.bytes(),
                verifyingKeyRef,
                commitment,
                envelopeHash,
                lanePrivacy,
            )
        }
    }

    private object FixedHashArrayAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) {
            require(value.size == 32) { "expected 32-byte hash" }
            encodeFixedByteArray(encoder, value)
        }

        override fun decode(decoder: NoritoDecoder): ByteArray =
            decodeFixedByteArray(decoder, 32, "proof attachment hash")
    }

    private class FeePaymentIntentAdapter : TypeAdapter<FeePaymentIntent> {
        override fun encode(encoder: NoritoEncoder, value: FeePaymentIntent) {
            when (value) {
                is FeePaymentIntent.Authority -> {
                    ENUM_TAG_ADAPTER.encode(encoder, FEE_PAYER_AUTHORITY_TAG)
                    encodeSizedField(encoder, AUTHORITY_FEE_PAYMENT_ADAPTER, value)
                }
                is FeePaymentIntent.Sponsor -> {
                    ENUM_TAG_ADAPTER.encode(encoder, FEE_PAYER_SPONSOR_TAG)
                    encodeSizedField(encoder, SPONSOR_FEE_PAYMENT_ADAPTER, value)
                }
            }
        }

        override fun decode(decoder: NoritoDecoder): FeePaymentIntent = when (val tag = ENUM_TAG_ADAPTER.decode(decoder)) {
            FEE_PAYER_AUTHORITY_TAG -> decodeSizedField(decoder, AUTHORITY_FEE_PAYMENT_ADAPTER)
            FEE_PAYER_SPONSOR_TAG -> decodeSizedField(decoder, SPONSOR_FEE_PAYMENT_ADAPTER)
            else -> throw IllegalArgumentException("Unknown FeePaymentIntent discriminant: $tag")
        }
    }

    private class AuthorityFeePaymentAdapter : TypeAdapter<FeePaymentIntent.Authority> {
        override fun encode(encoder: NoritoEncoder, value: FeePaymentIntent.Authority) {
            encodeSizedField(encoder, FEE_CHARGE_LIMIT_LIST_ADAPTER, value.chargeLimits)
            encodeSizedField(encoder, GAS_LIMIT_ADAPTER, Optional.ofNullable(value.gasLimit))
        }

        override fun decode(decoder: NoritoDecoder): FeePaymentIntent.Authority =
            FeePaymentIntent.Authority(
                decodeSizedField(decoder, FEE_CHARGE_LIMIT_LIST_ADAPTER),
                decodeSizedField<Optional<Long>>(decoder, GAS_LIMIT_ADAPTER).orElse(null),
            )
    }

    private class SponsorFeePaymentAdapter : TypeAdapter<FeePaymentIntent.Sponsor> {
        override fun encode(encoder: NoritoEncoder, value: FeePaymentIntent.Sponsor) {
            encodeSizedField(encoder, FEE_SPONSOR_PROGRAM_ID_ADAPTER, value.programId)
            encodeSizedField(encoder, UINT64_ADAPTER, value.programRevision)
            encodeSizedField(encoder, FEE_CHARGE_LIMIT_LIST_ADAPTER, value.chargeLimits)
            encodeSizedField(encoder, GAS_LIMIT_ADAPTER, Optional.ofNullable(value.gasLimit))
        }

        override fun decode(decoder: NoritoDecoder): FeePaymentIntent.Sponsor =
            FeePaymentIntent.Sponsor(
                decodeSizedField(decoder, FEE_SPONSOR_PROGRAM_ID_ADAPTER),
                decodeSizedField(decoder, UINT64_ADAPTER),
                decodeSizedField(decoder, FEE_CHARGE_LIMIT_LIST_ADAPTER),
                decodeSizedField<Optional<Long>>(decoder, GAS_LIMIT_ADAPTER).orElse(null),
            )
    }

    private class FeeSponsorProgramIdAdapter : TypeAdapter<FeeSponsorProgramId> {
        override fun encode(encoder: NoritoEncoder, value: FeeSponsorProgramId) {
            encodeSizedField(encoder, ACCOUNT_ID_ADAPTER, value.sponsor)
            encodeSizedField(encoder, STRING_ADAPTER, value.name)
        }

        override fun decode(decoder: NoritoDecoder): FeeSponsorProgramId =
            FeeSponsorProgramId(
                decodeSizedField(decoder, ACCOUNT_ID_ADAPTER),
                decodeSizedField(decoder, STRING_ADAPTER),
            )
    }

    private class FeeChargeLimitAdapter : TypeAdapter<FeeChargeLimit> {
        override fun encode(encoder: NoritoEncoder, value: FeeChargeLimit) {
            encodeSizedField(encoder, FEE_CHARGE_KIND_ADAPTER, value.kind)
            encodeSizedField(encoder, ASSET_DEFINITION_ID_ADAPTER, value.assetDefinitionId)
            encodeSizedField(encoder, QUANTITY_ADAPTER, KotodamaQuantity.parseCanonical(value.maxAmount))
        }

        override fun decode(decoder: NoritoDecoder): FeeChargeLimit =
            FeeChargeLimit(
                decodeSizedField(decoder, FEE_CHARGE_KIND_ADAPTER),
                decodeSizedField(decoder, ASSET_DEFINITION_ID_ADAPTER),
                decodeSizedField(decoder, QUANTITY_ADAPTER).toString(),
            )
    }

    private class FeeChargeKindAdapter : TypeAdapter<FeeChargeKind> {
        override fun encode(encoder: NoritoEncoder, value: FeeChargeKind) {
            ENUM_TAG_ADAPTER.encode(
                encoder,
                when (value) {
                    FeeChargeKind.NEXUS -> FEE_CHARGE_NEXUS_TAG
                    FeeChargeKind.PIPELINE_GAS -> FEE_CHARGE_PIPELINE_GAS_TAG
                },
            )
        }

        override fun decode(decoder: NoritoDecoder): FeeChargeKind = when (val tag = ENUM_TAG_ADAPTER.decode(decoder)) {
            FEE_CHARGE_NEXUS_TAG -> FeeChargeKind.NEXUS
            FEE_CHARGE_PIPELINE_GAS_TAG -> FeeChargeKind.PIPELINE_GAS
            else -> throw IllegalArgumentException("Unknown FeeChargeKind discriminant: $tag")
        }
    }

    private class AssetDefinitionIdAdapter : TypeAdapter<String> {
        override fun encode(encoder: NoritoEncoder, value: String) {
            encodeFixedByteArray(encoder, AssetDefinitionIdEncoder.parseAddressBytes(value))
        }

        override fun decode(decoder: NoritoDecoder): String =
            AssetDefinitionIdEncoder.encodeFromBytes(decodeFixedByteArray(decoder, 16, "AssetDefinitionId"))
    }

    private class QuantityAdapter : TypeAdapter<KotodamaQuantity> {
        override fun encode(encoder: NoritoEncoder, value: KotodamaQuantity) {
            encodeSizedBigInt(encoder, value.mantissa)
            encodeSizedField(encoder, UINT32_ADAPTER, value.scale.toLong())
        }

        override fun decode(decoder: NoritoDecoder): KotodamaQuantity =
            KotodamaQuantity.of(
                decodeSizedBigInt(decoder),
                Math.toIntExact(decodeSizedField(decoder, UINT32_ADAPTER)),
            )
    }

    private class InstructionAdapter : TypeAdapter<InstructionBox> {
        override fun encode(encoder: NoritoEncoder, value: InstructionBox) {
            value.requirePrivacyExact12ConstructionAdmission()
            val payload = value.payload
            if (payload is WirePayload) {
                require(isWirePayloadCandidate(payload.wireName, payload.payloadBytes)) {
                    "Wire payload must include a valid Norito header"
                }
                KaigiWirePayloadEncoderV1.requireCanonicalIfKnown(payload.wireName, payload.payloadBytes)
                UpdatePlainConvictionWirePayloadEncoder.requireCanonicalIfKnown(
                    payload.wireName,
                    payload.payloadBytes,
                )
                encodeSizedField(encoder, STRING_ADAPTER, payload.wireName)
                encodeSizedField(encoder, RAW_BYTE_VEC_ADAPTER, payload.payloadBytes)
                return
            }
            throw IllegalArgumentException("Instruction payload must be wire-framed")
        }

        override fun decode(decoder: NoritoDecoder): InstructionBox {
            val payload = decoder.readBytes(decoder.remaining())
            require(payload.isNotEmpty()) { "Instruction payload must not be empty" }
            return tryDecodeWireInstruction(payload, decoder.flags)
                ?: throw IllegalArgumentException("Instruction payload must be wire-framed")
        }
    }

    private class EncodedInstructionAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) {
            require(value.isNotEmpty()) { "instruction bytes must not be empty" }
            INSTRUCTION_ADAPTER.encode(encoder, decodeInstructionBox(value))
        }

        override fun decode(decoder: NoritoDecoder): ByteArray =
            throw UnsupportedOperationException("Multisig instruction byte decoding is not supported")
    }

    private class CustomInstructionAdapter : TypeAdapter<String> {
        override fun encode(encoder: NoritoEncoder, value: String) {
            // This is CustomInstruction's field; JSON_VALUE_ADAPTER owns Json's wire field.
            encodeSizedField(encoder, JSON_VALUE_ADAPTER, value)
        }

        override fun decode(decoder: NoritoDecoder): String =
            decodeSizedField(decoder, JSON_VALUE_ADAPTER)
    }

    internal class LogInstructionValue(
        val level: Long,
        val message: String,
    )

    private class LogInstructionAdapter : TypeAdapter<LogInstructionValue> {
        override fun encode(encoder: NoritoEncoder, value: LogInstructionValue) {
            require(value.level in 0L..4L) { "log level must be a canonical Level tag" }
            encodeSizedField(encoder, UINT8_ADAPTER, value.level)
            encodeSizedField(encoder, STRING_ADAPTER, value.message)
        }

        override fun decode(decoder: NoritoDecoder): LogInstructionValue {
            val level = decodeSizedField(decoder, UINT8_ADAPTER)
            require(level in 0L..4L) { "log level must be a canonical Level tag" }
            return LogInstructionValue(
                level = level,
                message = decodeSizedField(decoder, STRING_ADAPTER),
            )
        }
    }

    private class ContractArgumentRecordAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) {
            require(value.size <= ContractInvocation.MAX_ARGUMENT_BYTES) {
                "Contract argument record exceeds ${ContractInvocation.MAX_ARGUMENT_BYTES} bytes"
            }
            RAW_BYTE_VEC_ADAPTER.encode(encoder, value)
        }

        override fun decode(decoder: NoritoDecoder): ByteArray {
            val length = decoder.readLength(false)
            require(length in 0L..ContractInvocation.MAX_ARGUMENT_BYTES.toLong()) {
                "Contract argument record exceeds ${ContractInvocation.MAX_ARGUMENT_BYTES} bytes"
            }
            return decoder.readBytes(length.toInt())
        }
    }

    private class ContractInvocationAdapter : TypeAdapter<ContractInvocation> {
        override fun encode(encoder: NoritoEncoder, value: ContractInvocation) {
            encodeSizedField(encoder, STRING_ADAPTER, value.contractAddress)
            encodeSizedField(encoder, HASH_ADAPTER, value.expectedCodeHash)
            encodeSizedField(encoder, STRING_ADAPTER, value.entrypoint)
            encodeSizedField(
                encoder,
                CONTRACT_ARGUMENTS_ADAPTER,
                Optional.ofNullable(value.arguments),
            )
        }

        override fun decode(decoder: NoritoDecoder): ContractInvocation =
            ContractInvocation(
                contractAddress = decodeSizedField(decoder, STRING_ADAPTER),
                expectedCodeHash = decodeSizedField(decoder, HASH_ADAPTER),
                entrypoint = decodeSizedField(decoder, STRING_ADAPTER),
                arguments = decodeBoundedSizedField<Optional<ByteArray>>(
                    decoder,
                    CONTRACT_ARGUMENTS_ADAPTER,
                    ContractInvocation.MAX_ARGUMENT_BYTES.toLong() + 32L,
                    "ContractInvocation.arguments",
                ).orElse(null),
            )
    }

    private class ExecutableBatchItemAdapter : TypeAdapter<ExecutableBatchItem> {
        override fun encode(encoder: NoritoEncoder, value: ExecutableBatchItem) {
            when (value) {
                is ExecutableBatchItem.Instruction -> {
                    ENUM_TAG_ADAPTER.encode(encoder, BATCH_ITEM_INSTRUCTION_TAG)
                    encodeSizedField(encoder, INSTRUCTION_ADAPTER, value.instruction)
                }
                is ExecutableBatchItem.ContractCall -> {
                    ENUM_TAG_ADAPTER.encode(encoder, BATCH_ITEM_CONTRACT_CALL_TAG)
                    encodeSizedField(encoder, CONTRACT_INVOCATION_ADAPTER, value.invocation)
                }
            }
        }

        override fun decode(decoder: NoritoDecoder): ExecutableBatchItem =
            when (val tag = ENUM_TAG_ADAPTER.decode(decoder)) {
                BATCH_ITEM_INSTRUCTION_TAG -> ExecutableBatchItem.instruction(
                    decodeSizedField(decoder, INSTRUCTION_ADAPTER),
                )
                BATCH_ITEM_CONTRACT_CALL_TAG -> ExecutableBatchItem.contractCall(
                    decodeSizedField(decoder, CONTRACT_INVOCATION_ADAPTER),
                )
                else -> throw IllegalArgumentException(
                    "Unknown ExecutableBatchItem discriminant: $tag",
                )
            }
    }

    private class ExecutableAdapter : TypeAdapter<Executable> {
        override fun encode(encoder: NoritoEncoder, value: Executable) {
            encodeExecutable(encoder, value)
        }

        override fun decode(decoder: NoritoDecoder): Executable {
            return decodeExecutable(decoder)
        }
    }

    private class AccountIdAdapter : TypeAdapter<String> {
        override fun encode(encoder: NoritoEncoder, value: String) {
            CONTROLLER_ADAPTER.encode(encoder, parseAuthority(value))
        }

        override fun decode(decoder: NoritoDecoder): String {
            val payload = decoder.readBytes(decoder.remaining())
            return decodePayload(payload, decoder.flags)
        }

        companion object {
            private const val SINGLE_CONTROLLER_TAG = 0L
            private const val MULTISIG_CONTROLLER_TAG = 1L
            private val CONTROLLER_ADAPTER: TypeAdapter<ControllerPayload> = AccountControllerAdapter()
            private val MULTISIG_POLICY_ADAPTER: TypeAdapter<MultisigPolicyPayload> = MultisigPolicyNoritoAdapter()
            private val MULTISIG_MEMBER_ADAPTER: TypeAdapter<MultisigMemberPayload> = MultisigMemberNoritoAdapter()
            private val MULTISIG_MEMBER_LIST_ADAPTER: TypeAdapter<List<MultisigMemberPayload>> =
                NoritoAdapters.sequence(MULTISIG_MEMBER_ADAPTER)

            fun decodePayload(payload: ByteArray, flags: Int): String {
                val decoder = NoritoDecoder(payload, flags)
                val controller = decodeControllerPayload(decoder)
                require(decoder.remaining() == 0) { "Trailing bytes after authority payload" }
                return renderAuthority(controller)
            }

            private fun decodeControllerPayload(decoder: NoritoDecoder): ControllerPayload {
                val controllerTag = ENUM_TAG_ADAPTER.decode(decoder)
                return when (controllerTag) {
                    SINGLE_CONTROLLER_TAG -> {
                        val publicKeyPayload = decodeSizedField(decoder, BYTE_VECTOR_ADAPTER)
                        ControllerPayload.single(publicKeyPayload)
                    }
                    MULTISIG_CONTROLLER_TAG -> {
                        val policy = decodeSizedField(decoder, MULTISIG_POLICY_ADAPTER)
                        ControllerPayload.multisig(policy)
                    }
                    else -> throw IllegalArgumentException("Unsupported AccountController tag: $controllerTag")
                }
            }

            private fun parseAuthority(authority: String): ControllerPayload {
                val canonicalAuthority = requireCanonicalI105Address(authority, "authority")
                val parsed = try {
                    AccountAddress.parseEncoded(
                        canonicalAuthority,
                        requiredChainDiscriminant(),
                    )
                } catch (e: AccountAddressException) {
                    throw IllegalArgumentException("authority must use canonical I105 encoding", e)
                }
                return parseAddressToController(parsed)
            }

            private fun parseAddressToController(address: AccountAddress): ControllerPayload {
                try {
                    val singlePayload = address.singleKeyPayload()
                    if (singlePayload != null) {
                        val publicKeyPayload = compactPublicKeyPayload(singlePayload.curveId, singlePayload.publicKey)
                        return ControllerPayload.single(publicKeyPayload)
                    }
                    val multisigPayload = address.multisigPolicyPayload()
                    if (multisigPayload != null) {
                        return ControllerPayload.multisig(multisigPayload)
                    }
                } catch (e: AccountAddressException) {
                    throw IllegalArgumentException(
                        "Failed to extract controller from canonical I105 account id",
                        e,
                    )
                }
                throw IllegalArgumentException(
                    "Address contains neither single-key nor multisig controller"
                )
            }

            private fun renderAuthority(controller: ControllerPayload): String {
                if (controller.isSingle) {
                    val publicKeyPayload = controller.publicKeyPayload()
                    val payload = decodeCompactPublicKeyPayload(publicKeyPayload)
                        ?: throw IllegalArgumentException("Invalid single-key AccountController payload")
                    return renderSingleAuthority(payload)
                }
                return renderMultisigAuthority(controller.multisigPolicy!!)
            }

            private fun renderSingleAuthority(payload: PublicKeyPayload): String {
                val algorithm = algorithmForCurveId(payload.curveId)
                    ?: throw IllegalArgumentException(
                        "Unsupported curve id in AccountController payload: ${payload.curveId}"
                    )
                return try {
                    val address = AccountAddress.fromAccount(payload.keyBytes, algorithm)
                    address.toI105(requiredChainDiscriminant())
                } catch (e: AccountAddressException) {
                    throw IllegalArgumentException("Invalid single-key AccountController payload", e)
                }
            }

            private fun renderMultisigAuthority(policy: MultisigPolicyPayload): String {
                try {
                    val address = AccountAddress.fromMultisigPolicy(policy)
                    return address.toI105(requiredChainDiscriminant())
                } catch (ex: AccountAddressException) {
                    throw IllegalArgumentException("Invalid multisig policy for AccountId", ex)
                }
            }
        }

        private class ControllerPayload private constructor(
            publicKeyPayload: ByteArray?,
            val multisigPolicy: MultisigPolicyPayload?,
        ) {
            private val publicKeyPayload: ByteArray? = publicKeyPayload?.copyOf()

            val isSingle: Boolean get() = multisigPolicy == null

            fun publicKeyPayload(): ByteArray = publicKeyPayload!!.copyOf()

            companion object {
                fun single(publicKeyPayload: ByteArray): ControllerPayload {
                    require(publicKeyPayload.isNotEmpty()) { "public key payload must not be empty" }
                    return ControllerPayload(publicKeyPayload, null)
                }

                fun multisig(multisigPolicy: MultisigPolicyPayload): ControllerPayload =
                    ControllerPayload(null, multisigPolicy)
            }
        }

        private class AccountControllerAdapter : TypeAdapter<ControllerPayload> {
            override fun encode(encoder: NoritoEncoder, value: ControllerPayload) {
                if (value.isSingle) {
                    ENUM_TAG_ADAPTER.encode(encoder, SINGLE_CONTROLLER_TAG)
                    encodeSizedField(encoder, BYTE_VECTOR_ADAPTER, value.publicKeyPayload())
                    return
                }
                ENUM_TAG_ADAPTER.encode(encoder, MULTISIG_CONTROLLER_TAG)
                encodeSizedField(encoder, MULTISIG_POLICY_ADAPTER, value.multisigPolicy!!)
            }

            override fun decode(decoder: NoritoDecoder): ControllerPayload {
                val controllerTag = ENUM_TAG_ADAPTER.decode(decoder)
                val controller = when (controllerTag) {
                    SINGLE_CONTROLLER_TAG -> {
                        val publicKeyPayload = decodeSizedField(decoder, BYTE_VECTOR_ADAPTER)
                        ControllerPayload.single(publicKeyPayload)
                    }
                    MULTISIG_CONTROLLER_TAG -> {
                        val policy = decodeSizedField(decoder, MULTISIG_POLICY_ADAPTER)
                        ControllerPayload.multisig(policy)
                    }
                    else -> throw IllegalArgumentException("Unsupported AccountController tag: $controllerTag")
                }
                require(decoder.remaining() == 0) { "Trailing bytes after AccountController payload" }
                return controller
            }
        }

        private class MultisigPolicyNoritoAdapter : TypeAdapter<MultisigPolicyPayload> {
            override fun encode(encoder: NoritoEncoder, value: MultisigPolicyPayload) {
                UINT8_ADAPTER.encode(encoder, value.version.toLong())
                UINT16_ADAPTER.encode(encoder, value.threshold.toLong())
                MULTISIG_MEMBER_LIST_ADAPTER.encode(encoder, value.members)
            }

            override fun decode(decoder: NoritoDecoder): MultisigPolicyPayload {
                val version = Math.toIntExact(UINT8_ADAPTER.decode(decoder))
                val threshold = Math.toIntExact(UINT16_ADAPTER.decode(decoder))
                val members = MULTISIG_MEMBER_LIST_ADAPTER.decode(decoder)
                return MultisigPolicyPayload.of(version, threshold, members)
            }
        }

        private class MultisigMemberNoritoAdapter : TypeAdapter<MultisigMemberPayload> {
            override fun encode(encoder: NoritoEncoder, value: MultisigMemberPayload) {
                val publicKeyPayload = compactPublicKeyPayload(value.curveId, value.publicKey)
                BYTE_VECTOR_ADAPTER.encode(encoder, publicKeyPayload)
                UINT16_ADAPTER.encode(encoder, value.weight.toLong())
            }

            override fun decode(decoder: NoritoDecoder): MultisigMemberPayload {
                val publicKeyPayload = BYTE_VECTOR_ADAPTER.decode(decoder)
                val weight = Math.toIntExact(UINT16_ADAPTER.decode(decoder))
                val payload = decodeCompactPublicKeyPayload(publicKeyPayload)
                    ?: throw IllegalArgumentException("Invalid multisig member public key")
                return MultisigMemberPayload(payload.curveId, weight, payload.keyBytes)
            }
        }
    }

    private class TransactionDomainAdapter : TypeAdapter<NetworkId> {
        override fun encode(encoder: NoritoEncoder, value: NetworkId) {
            ENUM_TAG_ADAPTER.encode(encoder, TRANSACTION_DOMAIN_NETWORK_TAG)
            encodeSizedField(encoder, HASH_ADAPTER, value.bytes())
        }

        override fun decode(decoder: NoritoDecoder): NetworkId {
            val tag = ENUM_TAG_ADAPTER.decode(decoder)
            require(tag == TRANSACTION_DOMAIN_NETWORK_TAG) {
                if (tag == TRANSACTION_DOMAIN_GENESIS_TAG) {
                    "Genesis-only transaction domains are not accepted by the SDK"
                } else {
                    "Unknown TransactionDomain discriminant: $tag"
                }
            }
            return NetworkId.fromBytes(decodeSizedField(decoder, HASH_ADAPTER))
        }
    }

    /** Every instruction has a field prefix; reject impossible counts before allocating its list. */
    private class InstructionListAdapter : TypeAdapter<List<InstructionBox>> {
        override fun encode(encoder: NoritoEncoder, value: List<InstructionBox>) =
            NoritoAdapters.sequence(INSTRUCTION_ADAPTER).encode(encoder, value)

        override fun decode(decoder: NoritoDecoder): List<InstructionBox> {
            val count = decoder.readLength(false)
            require(count in 0..decoder.remaining().toLong()) { "instruction count exceeds the encoded field" }
            return List(count.toInt()) { decodeSizedField(decoder, INSTRUCTION_ADAPTER) }
        }
    }

    private class IvmProvedAdapter : TypeAdapter<Executable.IvmProved> {
        override fun encode(encoder: NoritoEncoder, value: Executable.IvmProved) {
            encodeSizedField(encoder, IVM_BYTECODE_ADAPTER, value.ivmBytes)
            encodeSizedField(encoder, INSTRUCTION_LIST_ADAPTER, value.overlay)
            encodeSizedField(encoder, HASH_ADAPTER, value.eventsCommitment)
            encodeSizedField(encoder, HASH_ADAPTER, value.gasPolicyCommitment)
        }

        override fun decode(decoder: NoritoDecoder): Executable.IvmProved = Executable.IvmProved(
            decodeSizedField(decoder, IVM_BYTECODE_ADAPTER),
            decodeSizedField(decoder, INSTRUCTION_LIST_ADAPTER),
            decodeSizedField(decoder, HASH_ADAPTER),
            decodeSizedField(decoder, HASH_ADAPTER),
        )
    }

    private class IvmBytecodeAdapter : TypeAdapter<ByteArray> {
        override fun encode(encoder: NoritoEncoder, value: ByteArray) {
            encodeSizedField(encoder, RAW_BYTE_VEC_ADAPTER, value)
        }

        override fun decode(decoder: NoritoDecoder): ByteArray {
            val payload = decoder.readBytes(decoder.remaining())
            val sized = NoritoDecoder(payload, decoder.flags)
            val value = decodeSizedField(sized, RAW_BYTE_VEC_ADAPTER)
            require(sized.remaining() == 0) { "Trailing bytes after IVM payload" }
            return value
        }
    }

    private class JsonValueFieldAdapter : TypeAdapter<String> {
        override fun encode(encoder: NoritoEncoder, value: String) {
            encodeSizedField(encoder, STRING_ADAPTER, value)
        }

        override fun decode(decoder: NoritoDecoder): String {
            return decodeSizedField(decoder, STRING_ADAPTER)
        }

        override fun isSelfDelimiting(): Boolean = true
    }

    private class MetadataAdapter : TypeAdapter<Map<String, JsonValue>> {
        private val entryListAdapter: TypeAdapter<List<MetadataEntry>> =
            NoritoAdapters.sequence(MetadataEntryAdapter())

        override fun encode(encoder: NoritoEncoder, value: Map<String, JsonValue>) {
            val keys = value.keys.sorted()
            val entries = keys.map { key ->
                val entryValue = value[key]
                    ?: throw IllegalArgumentException("Metadata values must not be null")
                MetadataEntry(key, entryValue)
            }
            entryListAdapter.encode(encoder, entries)
        }

        override fun decode(decoder: NoritoDecoder): Map<String, JsonValue> {
            val entries = entryListAdapter.decode(decoder)
            val decoded = LinkedHashMap<String, JsonValue>(entries.size)
            for (entry in entries) {
                require(decoded.put(entry.key, entry.value) == null) { "Duplicate metadata key" }
            }
            return decoded
        }
    }

    private class MetadataEntry(val key: String, val value: JsonValue)

    private class MetadataEntryAdapter : TypeAdapter<MetadataEntry> {
        override fun encode(encoder: NoritoEncoder, value: MetadataEntry) {
            encodeSizedField(encoder, STRING_ADAPTER, value.key)
            encodeSizedField(encoder, JSON_VALUE_ADAPTER, value.value.canonicalJson)
        }

        override fun decode(decoder: NoritoDecoder): MetadataEntry {
            val key = decodeSizedField(decoder, STRING_ADAPTER)
            val raw = decodeSizedField(decoder, JSON_VALUE_ADAPTER)
            return MetadataEntry(key, JsonValue.fromCanonicalWire(raw))
        }
    }

    companion object {
        // Validation never exposes rendered account text. Controller bytes are independent of the
        // I105 display prefix, so this private synthetic context does not become a network default.
        private const val CANONICAL_VALIDATION_DISCRIMINANT = 0
        private const val PROOF_BOX_MAX_ENCODED_BYTES = 64L * 1024L * 1024L
        private const val PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES = 8L + 256L
        private const val VERIFYING_KEY_REF_MAX_ENCODED_BYTES =
            2L * (8L + PORTABLE_IDENTIFIER_MAX_ENCODED_BYTES)
        private const val OPTIONAL_FIXED_ARRAY_HASH_MAX_ENCODED_BYTES = 1L + 8L + 32L * 9L
        private const val LANE_PRIVACY_MAX_SIBLING_OPTION_ENCODED_BYTES = 1L + 8L + 32L
        private const val LANE_PRIVACY_MAX_AUDIT_PATH_ENCODED_BYTES =
            8L + (LanePrivacyMerkleWitness.MAX_DEPTH + 1L) * 8L +
                LanePrivacyMerkleWitness.MAX_DEPTH * LANE_PRIVACY_MAX_SIBLING_OPTION_ENCODED_BYTES
        private const val LANE_PRIVACY_MAX_OPTION_ENCODED_BYTES = 16L * 1024L
        private const val LANE_PRIVACY_MERKLE_TAG = 0L
        private val CHAIN_DISCRIMINANT = ThreadLocal<Int?>()

        fun forChain(chainDiscriminant: Int): TransactionPayloadAdapter {
            require(chainDiscriminant in 0..0xffff) {
                "chainDiscriminant must fit in u16"
            }
            return TransactionPayloadAdapter(chainDiscriminant)
        }

        fun validateCanonicalPayloadBytes(encoded: ByteArray): TransactionPayload {
            val validator = forChain(CANONICAL_VALIDATION_DISCRIMINANT)
            val decoded = NoritoCodec.decodeAdaptive(encoded, validator)
            val reencoded = NoritoCodec.encodeAdaptive(decoded, validator).payload()
            require(encoded.contentEquals(reencoded)) {
                "transaction payload bytes are not the exact canonical encoding"
            }
            return decoded
        }

        private fun requiredChainDiscriminant(): Int =
            checkNotNull(CHAIN_DISCRIMINANT.get()) {
                "Account controller encoding/rendering requires an explicit chainDiscriminant"
            }

        private fun <T> withChainContext(chainDiscriminant: Int, operation: () -> T): T {
            require(chainDiscriminant in 0..0xffff) {
                "chainDiscriminant must fit in u16"
            }
            val previous = CHAIN_DISCRIMINANT.get()
            check(previous == null || previous == chainDiscriminant) {
                "Conflicting nested chainDiscriminant context"
            }
            CHAIN_DISCRIMINANT.set(chainDiscriminant)
            return try {
                operation()
            } finally {
                if (previous == null) {
                    CHAIN_DISCRIMINANT.remove()
                } else {
                    CHAIN_DISCRIMINANT.set(previous)
                }
            }
        }

        private val STRING_ADAPTER: TypeAdapter<String> = NoritoAdapters.stringAdapter()
        private val ACCOUNT_ID_ADAPTER: TypeAdapter<String> = AccountIdAdapter()
        private val TRANSACTION_DOMAIN_ADAPTER: TypeAdapter<NetworkId> = TransactionDomainAdapter()
        private val JSON_VALUE_ADAPTER: TypeAdapter<String> = JsonValueFieldAdapter()
        private val UINT64_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(64)
        private val UINT32_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(32)
        private val UINT16_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(16)
        private val UINT8_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(8)
        private val BYTE_VECTOR_ADAPTER: TypeAdapter<ByteArray> = NoritoAdapters.byteVecAdapter()
        private val RAW_BYTE_VEC_ADAPTER: TypeAdapter<ByteArray> = NoritoAdapters.rawByteVecAdapter()
        private val HASH_ADAPTER: TypeAdapter<ByteArray> = NoritoAdapters.fixedBytes(32)
        private val HASH_ARRAY_ADAPTER: TypeAdapter<ByteArray> = FixedHashArrayAdapter
        private val OPTIONAL_HASH_ADAPTER: TypeAdapter<Optional<ByteArray>> =
            NoritoAdapters.option(HASH_ARRAY_ADAPTER)
        private val OPTIONAL_LANE_PRIVACY_HASH_ADAPTER: TypeAdapter<Optional<ByteArray>> =
            NoritoAdapters.option(HASH_ADAPTER)
        private val LANE_PRIVACY_AUDIT_PATH_ADAPTER: TypeAdapter<List<ByteArray>> =
            LanePrivacyAuditPathAdapter
        private val LANE_PRIVACY_MERKLE_PROOF_ADAPTER: TypeAdapter<LanePrivacyMerkleProofValue> =
            LanePrivacyMerkleProofAdapter()
        private val LANE_PRIVACY_MERKLE_WITNESS_ADAPTER: TypeAdapter<LanePrivacyMerkleWitness> =
            LanePrivacyMerkleWitnessAdapter()
        private val LANE_PRIVACY_WITNESS_ADAPTER: TypeAdapter<LanePrivacyWitness> =
            LanePrivacyWitnessAdapter()
        private val LANE_COMMITMENT_ID_ADAPTER = LaneCommitmentIdAdapter
        private val LANE_PRIVACY_PROOF_ADAPTER: TypeAdapter<LanePrivacyProof> =
            LanePrivacyProofAdapter()
        private val OPTIONAL_LANE_PRIVACY_ADAPTER: TypeAdapter<Optional<LanePrivacyProof>> =
            NoritoAdapters.option(LANE_PRIVACY_PROOF_ADAPTER)
        private val IVM_PROVED_ADAPTER: TypeAdapter<Executable.IvmProved> = IvmProvedAdapter()
        private val IVM_BYTECODE_ADAPTER: TypeAdapter<ByteArray> = IvmBytecodeAdapter()
        private val INSTRUCTION_ADAPTER: TypeAdapter<InstructionBox> = InstructionAdapter()
        private val INSTRUCTION_LIST_ADAPTER: TypeAdapter<List<InstructionBox>> =
            InstructionListAdapter()
        private val ENCODED_INSTRUCTION_LIST_ADAPTER: TypeAdapter<List<ByteArray>> =
            NoritoAdapters.sequence(EncodedInstructionAdapter())
        private val CUSTOM_INSTRUCTION_ADAPTER: TypeAdapter<String> = CustomInstructionAdapter()
        private val LOG_INSTRUCTION_ADAPTER: TypeAdapter<LogInstructionValue> = LogInstructionAdapter()
        private val CONTRACT_ARGUMENT_RECORD_ADAPTER: TypeAdapter<ByteArray> =
            ContractArgumentRecordAdapter()
        private val CONTRACT_ARGUMENTS_ADAPTER: TypeAdapter<Optional<ByteArray>> =
            NoritoAdapters.option(CONTRACT_ARGUMENT_RECORD_ADAPTER)
        private val CONTRACT_INVOCATION_ADAPTER: TypeAdapter<ContractInvocation> =
            ContractInvocationAdapter()
        private val BATCH_ITEM_ADAPTER: TypeAdapter<ExecutableBatchItem> =
            ExecutableBatchItemAdapter()
        private val BATCH_ADAPTER: TypeAdapter<List<ExecutableBatchItem>> =
            NoritoAdapters.sequence(BATCH_ITEM_ADAPTER)
        private val ENUM_TAG_ADAPTER: TypeAdapter<Long> = NoritoAdapters.uint(32)
        private const val TRANSACTION_DOMAIN_NETWORK_TAG = 0L
        private const val TRANSACTION_DOMAIN_GENESIS_TAG = 1L


        private const val EXECUTABLE_INSTRUCTIONS_TAG = 0L
        private const val EXECUTABLE_CONTRACT_CALL_TAG = 1L
        private const val EXECUTABLE_IVM_TAG = 2L
        private const val EXECUTABLE_IVM_PROVED_TAG = 3L
        private const val EXECUTABLE_BATCH_TAG = 4L
        private const val BATCH_ITEM_INSTRUCTION_TAG = 0L
        private const val BATCH_ITEM_CONTRACT_CALL_TAG = 1L
        private val TTL_ADAPTER: TypeAdapter<Optional<Long>> = NoritoAdapters.option(NoritoAdapters.uint(64))
        private val NONCE_ADAPTER: TypeAdapter<Optional<Long>> = NoritoAdapters.option(NoritoAdapters.uint(32))
        private val GAS_LIMIT_ADAPTER: TypeAdapter<Optional<Long>> = NoritoAdapters.option(NoritoAdapters.uint(64))
        private val FEE_CHARGE_KIND_ADAPTER: TypeAdapter<FeeChargeKind> = FeeChargeKindAdapter()
        private val ASSET_DEFINITION_ID_ADAPTER: TypeAdapter<String> = AssetDefinitionIdAdapter()
        private val QUANTITY_ADAPTER: TypeAdapter<KotodamaQuantity> = QuantityAdapter()
        private val FEE_CHARGE_LIMIT_LIST_ADAPTER: TypeAdapter<List<FeeChargeLimit>> =
            NoritoAdapters.sequence(FeeChargeLimitAdapter())
        private val FEE_SPONSOR_PROGRAM_ID_ADAPTER: TypeAdapter<FeeSponsorProgramId> =
            FeeSponsorProgramIdAdapter()
        private val AUTHORITY_FEE_PAYMENT_ADAPTER: TypeAdapter<FeePaymentIntent.Authority> =
            AuthorityFeePaymentAdapter()
        private val SPONSOR_FEE_PAYMENT_ADAPTER: TypeAdapter<FeePaymentIntent.Sponsor> =
            SponsorFeePaymentAdapter()
        private val FEE_PAYMENT_ADAPTER: TypeAdapter<FeePaymentIntent> = FeePaymentIntentAdapter()

        private val EXECUTABLE_ADAPTER: TypeAdapter<Executable> = ExecutableAdapter()
        private val METADATA_ADAPTER: TypeAdapter<Map<String, JsonValue>> = MetadataAdapter()
        private val PROOF_BOX_ADAPTER: TypeAdapter<ProofBoxValue> = ProofBoxAdapter()
        private val PROOF_VERIFIER_KEY_REF_ADAPTER: TypeAdapter<ProofVerifierKeyRef> =
            ProofVerifierKeyRefAdapter()
        private val PROOF_ATTACHMENT_ADAPTER: TypeAdapter<ProofAttachment> = ProofAttachmentAdapter()
        private val PROOF_FREE_ATTACHMENT_ADAPTER: TypeAdapter<ProofAttachment> = ProofAttachmentAdapter(normalized = true)
        private const val CANONICAL_PAYLOAD_SCHEMA = "iroha_data_model::transaction::signed::model::TransactionPayload"
        private const val PROOF_ATTACHMENT_SCHEMA = "iroha_data_model::proof::ProofAttachment"
        private const val ORDERED_INTENT_DOMAIN = "iroha.transaction.ordered-intent-digest.v1"
        private const val PROOF_CARRIER_DOMAIN = "iroha.transaction.proof-carrier-public-inputs-digest.v1"
        private val SIGNED_ATTACHMENTS_ADAPTER = SignedAttachmentsAdapter(ACCOUNT_ID_ADAPTER)
        private val ATTACHMENTS_OPTION_ADAPTER: TypeAdapter<Optional<SignedAttachmentsV1>> =
            NoritoAdapters.option(SIGNED_ATTACHMENTS_ADAPTER)
        private val NORMALIZED_ATTACHMENTS_OPTION_ADAPTER: TypeAdapter<Optional<SignedAttachmentsV1>> =
            NoritoAdapters.option(object : TypeAdapter<SignedAttachmentsV1> {
                override fun encode(encoder: NoritoEncoder, value: SignedAttachmentsV1) = SIGNED_ATTACHMENTS_ADAPTER.encodeValue(encoder, value, true)
                override fun decode(decoder: NoritoDecoder): SignedAttachmentsV1 =
                    throw UnsupportedOperationException("a proof-free projection is not a signed attachment payload")
            })
        private const val INSTRUCTION_BOX_SCHEMA =
            "(alloc::string::String, alloc::vec::Vec<u8>)"
        private const val CUSTOM_INSTRUCTION_SCHEMA =
            "iroha_data_model::isi::transparent::CustomInstruction"
        private const val LOG_INSTRUCTION_SCHEMA =
            "iroha_data_model::isi::transparent::Log"
        private const val FEE_PAYER_AUTHORITY_TAG = 0L
        private const val FEE_PAYER_SPONSOR_TAG = 1L
        private const val FEE_CHARGE_NEXUS_TAG = 0L
        private const val FEE_CHARGE_PIPELINE_GAS_TAG = 1L

        internal fun encodeInstructionBox(value: InstructionBox): ByteArray =
            NoritoCodec.encode(value, INSTRUCTION_BOX_SCHEMA, InstructionAdapter())

        internal fun decodeInstructionBox(encoded: ByteArray): InstructionBox =
            NoritoCodec.decode(encoded, InstructionAdapter(), INSTRUCTION_BOX_SCHEMA)

        /** Encodes the bare Norito vector preimage hashed by `HashOf<Vec<InstructionBox>>`. */
        internal fun encodeCanonicalInstructionBoxes(encodedInstructions: List<ByteArray>): ByteArray {
            require(encodedInstructions.isNotEmpty()) { "encodedInstructions must not be empty" }
            encodedInstructions.forEachIndexed { index, encoded ->
                require(encoded.isNotEmpty()) { "encodedInstructions[$index] must not be empty" }
                val canonical = encodeInstructionBox(decodeInstructionBox(encoded))
                require(encoded.contentEquals(canonical)) {
                    "encodedInstructions[$index] is not canonical"
                }
            }
            val encoder = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
            ENCODED_INSTRUCTION_LIST_ADAPTER.encode(encoder, encodedInstructions)
            return encoder.toByteArray()
        }

        /** Decodes one exact canonical `iroha.custom` instruction JSON payload. */
        internal fun decodeCanonicalCustomInstructionJson(instruction: InstructionBox): String {
            val wire = instruction.payload as? WirePayload
                ?: throw IllegalArgumentException("instruction must contain a wire payload")
            require(wire.wireName == "iroha.custom") {
                "instruction wire name must be iroha.custom"
            }
            val framed = wire.payloadBytes
            val json = NoritoCodec.decode(
                framed,
                CUSTOM_INSTRUCTION_ADAPTER,
                CUSTOM_INSTRUCTION_SCHEMA,
            )
            val canonical = NoritoCodec.encode(
                json,
                CUSTOM_INSTRUCTION_SCHEMA,
                CUSTOM_INSTRUCTION_ADAPTER,
            )
            require(framed.contentEquals(canonical)) {
                "custom instruction payload is not the exact canonical encoding"
            }
            JsonValue.fromCanonicalWire(json)
            return json
        }

        /** Test and fixture support for the canonical custom-instruction envelope. */
        internal fun encodeCanonicalCustomInstructionJson(json: String): ByteArray {
            val canonical = JsonValue.parse(json).canonicalJson
            return NoritoCodec.encode(
                canonical,
                CUSTOM_INSTRUCTION_SCHEMA,
                CUSTOM_INSTRUCTION_ADAPTER,
            )
        }

        internal fun encodeCanonicalLogInstruction(level: Long, message: String): ByteArray {
            val framed = NoritoCodec.encode(
                LogInstructionValue(level, message),
                LOG_INSTRUCTION_SCHEMA,
                LOG_INSTRUCTION_ADAPTER,
            )
            return encodeInstructionBox(InstructionBox.fromWirePayload("iroha.log", framed))
        }

        internal fun decodeCanonicalLogInstruction(encoded: ByteArray): LogInstructionValue {
            val instruction = decodeInstructionBox(encoded)
            val canonicalInstruction = encodeInstructionBox(instruction)
            require(encoded.contentEquals(canonicalInstruction)) {
                "log instruction box is not the exact canonical encoding"
            }
            val wire = instruction.payload as? WirePayload
                ?: throw IllegalArgumentException("instruction must contain a wire payload")
            require(wire.wireName == "iroha.log") { "instruction wire name must be iroha.log" }
            val framed = wire.payloadBytes
            val value = NoritoCodec.decode(
                framed,
                LOG_INSTRUCTION_ADAPTER,
                LOG_INSTRUCTION_SCHEMA,
            )
            val canonical = NoritoCodec.encode(
                value,
                LOG_INSTRUCTION_SCHEMA,
                LOG_INSTRUCTION_ADAPTER,
            )
            require(framed.contentEquals(canonical)) {
                "log instruction payload is not the exact canonical encoding"
            }
            return value
        }

        internal fun encodeProofAttachmentPayload(value: ProofAttachment, flags: Int = 0): ByteArray {
            val encoder = NoritoEncoder(flags)
            PROOF_ATTACHMENT_ADAPTER.encode(encoder, value)
            return encoder.toByteArray()
        }

        internal fun decodeProofAttachmentPayload(encoded: ByteArray, flags: Int = 0): ProofAttachment {
            val decoder = NoritoDecoder(encoded, flags)
            val value = PROOF_ATTACHMENT_ADAPTER.decode(decoder)
            require(decoder.remaining() == 0) { "trailing ProofAttachment payload bytes" }
            return value
        }

        private fun <T> encodeSizedField(encoder: NoritoEncoder, adapter: TypeAdapter<T>, value: T) {
            val child = encoder.childEncoder()
            adapter.encode(child, value)
            val payload = child.toByteArray()
            val compact = (encoder.flags and NoritoHeader.COMPACT_LEN) != 0
            encoder.writeLength(payload.size.toLong(), compact)
            encoder.writeBytes(payload)
        }

        private fun <T> decodeSizedField(decoder: NoritoDecoder, adapter: TypeAdapter<T>): T {
            val length = decoder.readLength(decoder.compactLenActive())
            require(length <= Int.MAX_VALUE) { "Field payload too large" }
            val payload = decoder.readBytes(length.toInt())
            val child = NoritoDecoder(payload, decoder.flags)
            val value = adapter.decode(child)
            require(child.remaining() == 0) { "Trailing bytes after field payload" }
            return value
        }

        private fun <T> decodeBoundedSizedField(
            decoder: NoritoDecoder,
            adapter: TypeAdapter<T>,
            maxEncodedLength: Long,
            fieldName: String,
        ): T {
            val length = decoder.readLength(decoder.compactLenActive())
            require(length in 0L..maxEncodedLength) {
                "$fieldName payload exceeds $maxEncodedLength bytes"
            }
            val payload = decoder.readBytes(length.toInt())
            val child = NoritoDecoder(payload, decoder.flags)
            val value = adapter.decode(child)
            require(child.remaining() == 0) { "Trailing bytes after $fieldName payload" }
            return value
        }

        private fun encodeFixedByteArray(encoder: NoritoEncoder, bytes: ByteArray) {
            val compact = (encoder.flags and NoritoHeader.COMPACT_LEN) != 0
            for (byte in bytes) {
                encoder.writeLength(1, compact)
                encoder.writeByte(byte.toInt())
            }
        }

        private fun decodeFixedByteArray(decoder: NoritoDecoder, length: Int, fieldName: String): ByteArray {
            val compact = (decoder.flags and NoritoHeader.COMPACT_LEN) != 0
            return ByteArray(length) { index ->
                require(decoder.readLength(compact) == 1L) {
                    "$fieldName element $index must contain exactly one byte"
                }
                decoder.readByte().toByte()
            }
        }

        private fun encodeSizedBigInt(encoder: NoritoEncoder, value: BigInteger) {
            val child = encoder.childEncoder()
            val bytes = toTwosComplementLittleEndian(value)
            child.writeUInt(bytes.size.toLong(), 32)
            child.writeBytes(bytes)
            val payload = child.toByteArray()
            encoder.writeLength(payload.size.toLong(), (encoder.flags and NoritoHeader.COMPACT_LEN) != 0)
            encoder.writeBytes(payload)
        }

        private fun decodeSizedBigInt(decoder: NoritoDecoder): BigInteger {
            val length = decoder.readLength(decoder.compactLenActive())
            require(length <= Int.MAX_VALUE) { "numeric mantissa payload too large" }
            val child = NoritoDecoder(decoder.readBytes(length.toInt()), decoder.flags)
            val byteLength = child.readUInt(32)
            require(byteLength <= 64L) { "numeric mantissa exceeds 512 bits" }
            val bytes = child.readBytes(byteLength.toInt())
            require(child.remaining() == 0) { "Trailing bytes after numeric mantissa payload" }
            val value = fromTwosComplementLittleEndian(bytes)
            require(toTwosComplementLittleEndian(value).contentEquals(bytes)) {
                "Numeric mantissa is not canonical"
            }
            return value
        }

        private fun fromTwosComplementLittleEndian(bytes: ByteArray): BigInteger {
            if (bytes.isEmpty()) return BigInteger.ZERO
            return BigInteger(bytes.reversedArray())
        }

        private fun toTwosComplementLittleEndian(value: BigInteger): ByteArray {
            if (value.signum() == 0) return ByteArray(0)
            val result = value.toByteArray().reversedArray()
            var length = result.size
            if (value.signum() > 0) {
                while (length > 1 && result[length - 1] == 0.toByte() &&
                    (result[length - 2].toInt() and 0x80) == 0
                ) length--
            } else {
                while (length > 1 && result[length - 1] == 0xff.toByte() &&
                    (result[length - 2].toInt() and 0x80) != 0
                ) length--
            }
            return if (length == result.size) result else result.copyOf(length)
        }

        private fun decodeAuthorityField(decoder: NoritoDecoder): String {
            val length = decoder.readLength(decoder.compactLenActive())
            require(length <= Int.MAX_VALUE) { "Field payload too large" }
            val payload = decoder.readBytes(length.toInt())
            return AccountIdAdapter.decodePayload(payload, decoder.flags)
        }

        private fun encodeExecutable(encoder: NoritoEncoder, executable: Executable) {
            when (executable) {
                is Executable.IvmProved -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_IVM_PROVED_TAG)
                    encodeSizedField(encoder, IVM_PROVED_ADAPTER, executable)
                }
                is Executable.Ivm -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_IVM_TAG)
                    encodeSizedField(encoder, IVM_BYTECODE_ADAPTER, executable.ivmBytes)
                }
                is Executable.Instructions -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_INSTRUCTIONS_TAG)
                    encodeSizedField(encoder, INSTRUCTION_LIST_ADAPTER, executable.instructions)
                }
                is Executable.ContractCall -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_CONTRACT_CALL_TAG)
                    encodeSizedField(encoder, CONTRACT_INVOCATION_ADAPTER, executable.invocation)
                }
                is Executable.Batch -> {
                    ENUM_TAG_ADAPTER.encode(encoder, EXECUTABLE_BATCH_TAG)
                    encodeSizedField(encoder, BATCH_ADAPTER, executable.entries)
                }
            }
        }

        private fun decodeExecutable(decoder: NoritoDecoder): Executable {
            val tag = ENUM_TAG_ADAPTER.decode(decoder)
            return when (tag) {
                EXECUTABLE_IVM_TAG -> {
                    val bytes = decodeSizedField(decoder, IVM_BYTECODE_ADAPTER)
                    Executable.ivm(bytes)
                }
                EXECUTABLE_INSTRUCTIONS_TAG -> {
                    val instructions = decodeSizedField(decoder, INSTRUCTION_LIST_ADAPTER)
                    Executable.instructions(instructions)
                }
                EXECUTABLE_CONTRACT_CALL_TAG -> Executable.contractCall(
                    decodeSizedField(decoder, CONTRACT_INVOCATION_ADAPTER),
                )
                EXECUTABLE_BATCH_TAG -> Executable.batch(
                    decodeSizedField(decoder, BATCH_ADAPTER),
                )
                EXECUTABLE_IVM_PROVED_TAG -> decodeSizedField(decoder, IVM_PROVED_ADAPTER)
                else -> throw IllegalArgumentException("Unknown Executable discriminant: $tag")
            }
        }

        private fun tryDecodeWireInstruction(payload: ByteArray, flags: Int): InstructionBox? {
            return try {
                val wireDecoder = NoritoDecoder(payload, flags)
                val wireName = decodeSizedField(wireDecoder, STRING_ADAPTER)
                val wirePayload = decodeSizedField(wireDecoder, RAW_BYTE_VEC_ADAPTER)
                if (wireDecoder.remaining() != 0) return null
                if (!isWirePayloadCandidate(wireName, wirePayload)) return null
                KaigiWirePayloadEncoderV1.requireCanonicalIfKnown(wireName, wirePayload)
                UpdatePlainConvictionWirePayloadEncoder.requireCanonicalIfKnown(
                    wireName,
                    wirePayload,
                )
                InstructionBox.fromWirePayload(wireName, wirePayload)
            } catch (_: IllegalArgumentException) {
                null
            }
        }

        private fun isWirePayloadCandidate(wireName: String?, payload: ByteArray?): Boolean {
            if (wireName.isNullOrBlank()) return false
            if (payload == null || payload.size < NoritoHeader.HEADER_LENGTH) return false
            if (payload[0] != 'N'.code.toByte() || payload[1] != 'R'.code.toByte() ||
                payload[2] != 'T'.code.toByte() || payload[3] != '0'.code.toByte()
            ) return false
            return try {
                val decoded = NoritoHeader.decode(payload, null)
                decoded.header.validateChecksum(decoded.payload)
                true
            } catch (_: IllegalArgumentException) {
                false
            }
        }
    }
}
