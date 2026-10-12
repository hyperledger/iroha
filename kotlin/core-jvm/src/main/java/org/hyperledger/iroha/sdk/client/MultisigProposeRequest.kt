package org.hyperledger.iroha.sdk.client

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

/** Request payload for Torii `/v1/multisig/propose`. */
class MultisigProposeRequest @JvmOverloads constructor(
    val multisigAccountId: String? = null,
    val multisigAccountAlias: String? = null,
    val signerAccountId: String,
    val proposalNonce: String,
    instructions: List<ByteArray>,
    val publicKeyHex: String? = null,
    val signatureB64: String? = null,
    val creationTimeMs: Long? = null,
    val feePayment: FeePaymentIntent,
    val memo: String? = null,
    val validationFeeAssessment: JsonValue? = null,
) {
    private val instructionSnapshot = instructions.map(ByteArray::copyOf)
    val instructions: List<ByteArray> get() = instructionSnapshot.map(ByteArray::copyOf)

    init {
        require(Regex("[0-9a-f]{64}").matches(proposalNonce) && proposalNonce.any { it != '0' }) { "proposalNonce must be nonzero canonical 32-byte hex" }
        require((multisigAccountId == null) != (multisigAccountAlias == null)) {
            "Exactly one multisig account identity is required"
        }
        require(instructionSnapshot.isNotEmpty() && instructionSnapshot.all { it.isNotEmpty() }) {
            "Multisig instructions must be nonempty canonical instruction frames"
        }
        validationFeeAssessment?.let {
            require(it.canonicalJson.toByteArray(Charsets.UTF_8).size <= 4096 &&
                JsonParser.parse(it.canonicalJson) is Map<*, *>) {
                "validationFeeAssessment must be a bounded native JSON object"
            }
        }
    }

    /** Current Torii JSON request with canonical instruction validation and exact fee intent. */
    fun canonicalToriiJsonBytes(): ByteArray {
        NoritoJavaCodecAdapter.canonicalMultisigProposalInstructionBoxes(this)
        return JsonEncoder.encode(HttpClientTransport.buildMultisigProposePayload(this))
            .toByteArray(StandardCharsets.UTF_8)
    }

    /** Verify Torii's proposal response against this exact request and trusted NetworkId. */
    fun verifyToriiResponse(responseBytes: ByteArray, networkId: NetworkId): MultisigResponse {
        val payload = HttpClientTransport.buildMultisigProposePayload(this)
        val proposalInstructions = NoritoJavaCodecAdapter.canonicalMultisigProposalInstructionBoxes(this)
        return HttpClientTransport.validateMultisigResponse(
            ContractJsonParser.parseMultisigResponse(responseBytes),
            this,
            payload,
            proposalInstructions,
            HttpClientTransport.canonicalMultisigMetadata(payload),
            networkId,
        )
    }

    companion object {
        /** Builds a request from typed instruction boxes by encoding each box as native Norito. */
        @JvmStatic
        @JvmOverloads
        fun fromInstructionBoxes(
            multisigAccountId: String? = null,
            multisigAccountAlias: String? = null,
            signerAccountId: String,
            proposalNonce: String,
            instructions: List<InstructionBox>,
            publicKeyHex: String? = null,
            signatureB64: String? = null,
            creationTimeMs: Long? = null,
            feePayment: FeePaymentIntent,
            memo: String? = null,
            validationFeeAssessment: JsonValue? = null,
        ): MultisigProposeRequest = MultisigProposeRequest(
            multisigAccountId = multisigAccountId,
            multisigAccountAlias = multisigAccountAlias,
            signerAccountId = signerAccountId,
            proposalNonce = proposalNonce,
            instructions = instructions.map { NoritoJavaCodecAdapter.encodeInstructionBox(it) },
            publicKeyHex = publicKeyHex,
            signatureB64 = signatureB64,
            creationTimeMs = creationTimeMs,
            feePayment = feePayment,
            memo = memo,
            validationFeeAssessment = validationFeeAssessment,
        )
    }
}
