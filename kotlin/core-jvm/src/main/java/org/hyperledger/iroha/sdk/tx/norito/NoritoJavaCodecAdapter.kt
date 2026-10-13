package org.hyperledger.iroha.sdk.tx.norito

import java.util.Base64
import java.util.Collections
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.MultisigProposeRequest
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.util.HashLiteral
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoHeader

class NoritoJavaCodecAdapter @JvmOverloads constructor(
    val chainDiscriminant: Int,
    private val schemaName: String = DEFAULT_SCHEMA,
) : NoritoCodecAdapter {

    private val adapter = TransactionPayloadAdapter.forChain(chainDiscriminant)

    @Throws(NoritoException::class)
    override fun encodeTransaction(payload: TransactionPayload): ByteArray {
        try {
            return NoritoCodec.encodeAdaptive(payload, adapter).payload()
        } catch (ex: Exception) {
            throw NoritoException("Failed to encode Norito transaction payload", ex)
        }
    }

    @Throws(NoritoException::class)
    override fun decodeTransaction(encoded: ByteArray): TransactionPayload {
        try {
            if (hasHeader(encoded)) {
                return NoritoCodec.decode(encoded, adapter, schemaName)
            }
            return NoritoCodec.decodeAdaptive(encoded, adapter)
        } catch (ex: Exception) {
            throw NoritoException("Failed to decode Norito transaction payload", ex)
        }
    }

    /** Canonical proof-free frame committed by each action's ordered intent. */
    fun orderedIntentProjection(payload: TransactionPayload): ByteArray = adapter.orderedIntentProjection(payload)

    /** BLAKE3 domain-separated digest of the proof-free ordered intent. */
    fun orderedIntentDigest(payload: TransactionPayload): org.hyperledger.iroha.sdk.core.model.OrderedIntentDigestV1 =
        adapter.orderedIntentDigest(payload)

    /** Rebind statements after changing independent intent fields, before regenerating proofs. */
    fun bindAttachmentStatements(payload: TransactionPayload): TransactionPayload = adapter.bindAttachmentStatements(payload)

    /** Replace carriers with canonical signed occurrences and bind their derived statements. */
    fun withProofAttachments(payload: TransactionPayload, proofs: List<org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment>): TransactionPayload =
        adapter.withProofAttachments(payload, proofs)

    /** Replace carriers with the single canonical proof of this proved IVM executable. */
    fun withIvmExecutionProof(payload: TransactionPayload, proof: org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment): TransactionPayload =
        adapter.withIvmExecutionProof(payload, proof)

    override fun schemaName(): String = schemaName

    companion object {
        private const val DEFAULT_SCHEMA = "iroha.android.transaction.Payload.v1"

        @JvmStatic
        @Throws(NoritoException::class)
        fun encodeInstructionBox(instruction: InstructionBox): ByteArray {
            try {
                return TransactionPayloadAdapter.encodeInstructionBox(instruction)
            } catch (ex: Exception) {
                throw NoritoException("Failed to encode Norito instruction box", ex)
            }
        }

        /**
         * Builds a canonical Log instruction using the protocol Level tag.
         *
         * Tags are TRACE=0, DEBUG=1, INFO=2, WARN=3 and ERROR=4. The instruction carries
         * the exact Norito-framed Log payload required by transaction encoding.
         */
        @JvmStatic
        @Throws(NoritoException::class)
        fun logInstruction(level: Long, message: String): InstructionBox {
            try {
                return decodeInstructionBox(
                    TransactionPayloadAdapter.encodeCanonicalLogInstruction(level, message),
                )
            } catch (ex: Exception) {
                throw NoritoException("Failed to build canonical Norito Log instruction", ex)
            }
        }

        /** Decode one exact canonical wire-framed instruction box. */
        @JvmStatic
        @Throws(NoritoException::class)
        fun decodeInstructionBox(encoded: ByteArray): InstructionBox {
            try {
                val decoded = TransactionPayloadAdapter.decodeInstructionBox(encoded)
                val canonical = TransactionPayloadAdapter.encodeInstructionBox(decoded)
                require(encoded.contentEquals(canonical)) {
                    "instruction box is not canonically encoded"
                }
                return decoded
            } catch (ex: Exception) {
                throw NoritoException("Failed to decode canonical Norito instruction box", ex)
            }
        }

        /**
         * Returns the exact canonical inner instruction frames committed by a multisig proposal.
         *
         * Torii appends the exact canonical retail assessment marker when one is reviewed. The returned list is defensive and includes that marker.
         */
        @JvmStatic
        @Throws(NoritoException::class)
        fun canonicalMultisigProposalInstructionBoxes(
            request: MultisigProposeRequest,
        ): List<ByteArray> {
            try {
                require(request.instructions.isNotEmpty()) {
                    "multisig instructions must not be empty"
                }
                val instructions = request.instructions.mapIndexed { index, encoded ->
                    require(encoded.isNotEmpty()) { "multisig instructions[$index] must not be empty" }
                    encoded.copyOf()
                }.toMutableList()
                TransactionPayloadAdapter.encodeCanonicalInstructionBoxes(instructions).fill(0)
                instructions.forEach { encoded ->
                    val instruction = TransactionPayloadAdapter.decodeInstructionBox(encoded)
                    val wire = instruction.payload as? WirePayload
                    if (wire?.wireName == LOG_WIRE_NAME) {
                        val log = TransactionPayloadAdapter.decodeCanonicalLogInstruction(encoded)
                        require(!log.message.startsWith(RETAIL_FEE_ASSESSMENT_RESERVED_PREFIX)) {
                            "multisig propose request instructions must not contain a validation-fee marker"
                        }
                    }
                }

                request.validationFeeAssessment?.let { assessment ->
                    val marker = org.hyperledger.iroha.sdk.validationfee.RetailFeeAssessmentBridge
                        .assessmentMarkerV1(assessment.canonicalJson.toByteArray(Charsets.UTF_8))
                    instructions.add(TransactionPayloadAdapter.encodeCanonicalLogInstruction(
                        TRACE_LEVEL_TAG, String(marker, Charsets.UTF_8),
                    ))
                }
                return Collections.unmodifiableList(instructions.map(ByteArray::copyOf))
            } catch (ex: Exception) {
                throw NoritoException("Failed to build canonical multisig proposal instructions", ex)
            }
        }

        /** Rust-compatible `HashOf<Vec<InstructionBox>>` for exact canonical instruction frames. */
        @JvmStatic
        @Throws(NoritoException::class)
        fun hashCanonicalInstructionBoxes(encodedInstructions: List<ByteArray>): ByteArray {
            var preimage: ByteArray? = null
            try {
                val snapshot = snapshotInstructionBoxes(encodedInstructions)
                preimage = TransactionPayloadAdapter.encodeCanonicalInstructionBoxes(snapshot)
                return IrohaHash.prehash(preimage)
            } catch (ex: Exception) {
                throw NoritoException("Failed to hash canonical Norito instruction boxes", ex)
            } finally {
                preimage?.fill(0)
            }
        }

        /**
         * Verifies the exact outer action built by `POST /v1/multisig/propose`.
         *
         * The executable must contain only the canonical propose instruction and optional
         * quorum-one approval. The returned bytes are the locally computed proposal hash.
         */
        @JvmStatic
        @Throws(NoritoException::class)
        fun verifyCanonicalMultisigProposeExecutable(
            transactionPayload: TransactionPayload,
            expectedMultisigAccountId: String,
            expectedProposalNonce: String,
            expectedProposalId: String,
            expectedInstructionBoxes: List<ByteArray>,
        ): ByteArray {
            val expected = snapshotInstructionBoxes(expectedInstructionBoxes)
            try {
                val canonicalAccount = requireCanonicalI105Address(
                    expectedMultisigAccountId,
                    "expectedMultisigAccountId",
                )
                val executable = transactionPayload.executable as? Executable.Instructions
                    ?: throw IllegalArgumentException(
                        "multisig proposal transaction must contain an instruction executable",
                    )
                require(executable.instructions.size in 1..2) {
                    "multisig proposal transaction must contain only propose and optional approve"
                }
                val instructionsHash = hashCanonicalInstructionBoxes(expected)
                verifyMultisigProposeJson(
                    TransactionPayloadAdapter.decodeCanonicalCustomInstructionJson(
                        executable.instructions[0],
                    ),
                    canonicalAccount,
                    expectedProposalNonce,
                    expected,
                )
                if (executable.instructions.size == 2) {
                    verifyMultisigApproveJson(
                        TransactionPayloadAdapter.decodeCanonicalCustomInstructionJson(
                            executable.instructions[1],
                        ),
                        canonicalAccount,
                        expectedProposalId,
                        HashLiteral.canonicalize(instructionsHash),
                    )
                }
                return instructionsHash
            } catch (ex: Exception) {
                throw NoritoException("Invalid canonical multisig propose executable", ex)
            } finally {
                expected.forEach { it.fill(0) }
            }
        }

        /** Reject transaction payload bytes that are not the exact canonical Norito encoding. */
        @JvmStatic
        @Throws(NoritoException::class)
        fun validateCanonicalTransactionPayload(encoded: ByteArray) {
            decodeCanonicalTransactionPayload(encoded)
        }

        /** Decode one exact canonical payload so callers can verify signature-bound fields. */
        @JvmStatic
        @Throws(NoritoException::class)
        fun decodeCanonicalTransactionPayload(
            encoded: ByteArray,
        ): TransactionPayload {
            try {
                val payload = TransactionPayloadAdapter.validateCanonicalPayloadBytes(encoded)
                return payload
            } catch (ex: Exception) {
                throw NoritoException("Invalid canonical Norito transaction payload", ex)
            }
        }

        private fun snapshotInstructionBoxes(encodedInstructions: List<ByteArray>): List<ByteArray> {
            require(encodedInstructions.isNotEmpty()) {
                "Expected multisig instruction boxes must not be empty"
            }
            return encodedInstructions.mapIndexed { index, instruction ->
                require(instruction.isNotEmpty()) {
                    "Expected multisig instruction box $index must not be empty"
                }
                instruction.copyOf()
            }
        }

        private fun verifyMultisigProposeJson(
            json: String,
            expectedAccount: String,
            expectedProposalNonce: String,
            expectedInstructions: List<ByteArray>,
        ) {
            val root = requireJsonObject(JsonParser.parse(json), "multisig custom")
            requireExactKeys(root, setOf("Propose"), "multisig custom")
            val propose = requireJsonObject(root["Propose"], "multisig custom.Propose")
            requireExactKeys(
                propose,
                setOf("account", "proposal_nonce", "instructions", "transaction_ttl_ms"),
                "multisig custom.Propose",
            )
            requireExactString(
                propose["account"],
                expectedAccount,
                "multisig custom.Propose.account",
            )
            requireExactString(propose["proposal_nonce"], expectedProposalNonce, "multisig custom.Propose.proposal_nonce")
            require(propose["transaction_ttl_ms"] == null) {
                "multisig custom.Propose.transaction_ttl_ms must be null"
            }
            val embedded = propose["instructions"] as? List<*>
                ?: throw IllegalArgumentException(
                    "multisig custom.Propose.instructions must be an array",
                )
            require(embedded.size == expectedInstructions.size) {
                "multisig custom.Propose.instructions changed instruction count"
            }
            embedded.forEachIndexed { index, value ->
                requireExactString(
                    value,
                    Base64.getEncoder().encodeToString(expectedInstructions[index]),
                    "multisig custom.Propose.instructions[$index]",
                )
            }
        }

        private fun verifyMultisigApproveJson(
            json: String,
            expectedAccount: String,
            expectedProposalId: String,
            expectedHashLiteral: String,
        ) {
            val root = requireJsonObject(JsonParser.parse(json), "multisig custom")
            requireExactKeys(root, setOf("Approve"), "multisig custom")
            val approve = requireJsonObject(root["Approve"], "multisig custom.Approve")
            requireExactKeys(
                approve,
                setOf("account", "proposal_id", "instructions_hash"),
                "multisig custom.Approve",
            )
            requireExactString(
                approve["account"],
                expectedAccount,
                "multisig custom.Approve.account",
            )
            requireExactString(approve["proposal_id"], expectedProposalId, "multisig custom.Approve.proposal_id")
            requireExactString(
                approve["instructions_hash"],
                expectedHashLiteral,
                "multisig custom.Approve.instructions_hash",
            )
        }

        @Suppress("UNCHECKED_CAST")
        private fun requireJsonObject(value: Any?, field: String): Map<String, Any?> {
            require(value is Map<*, *>) { "$field must be an object" }
            require(value.keys.all { it is String }) { "$field keys must be strings" }
            return value as Map<String, Any?>
        }

        private fun requireExactKeys(
            value: Map<String, Any?>,
            expected: Set<String>,
            field: String,
        ) {
            require(value.keys == expected) { "$field has unexpected fields" }
        }

        private fun requireExactString(value: Any?, expected: String, field: String) {
            require(value is String && value == expected) { "$field changed" }
        }

        private fun hasHeader(encoded: ByteArray): Boolean {
            if (encoded.size < NoritoHeader.HEADER_LENGTH) return false
            return encoded[0] == 'N'.code.toByte()
                && encoded[1] == 'R'.code.toByte()
                && encoded[2] == 'T'.code.toByte()
                && encoded[3] == '0'.code.toByte()
        }

        private const val LOG_WIRE_NAME = "iroha.log"
        private const val TRACE_LEVEL_TAG = 0L
        private const val RETAIL_FEE_ASSESSMENT_RESERVED_PREFIX =
            "iroha:retail_fee:assessment:"

    }
}
