// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.core.model.instructions

import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/**
 * Typed ordinary ledger instruction carrying the complete Native Activation original.
 *
 * [activation] is the original bounded `KagemushaWalletActivationV1` frame, including its
 * payment-key-signed control, credential, Bootstrap package, asset and certificates. This
 * constructor preserves those bytes; it does not assemble, sign, verify or approve them.
 * Core verifies the complete activation against the registered scheme before ledger effects.
 *
 * The application's existing account signer signs this instruction in an ordinary transaction.
 * Transaction submission or construction does not establish committed activation, a folded
 * wallet head, user confirmation or permission to spend. Exact signed transaction retention
 * and authoritative committed-outcome recovery remain the caller's responsibility.
 */
class KagemushaWalletActivateInstructionV1(schemeId: ByteArray, activation: ByteArray) : InstructionTemplate {
    private val originalSchemeId: ByteArray
    private val originalActivation: ByteArray

    init {
        require(schemeId.size == 32) { "schemeId must be 32 bytes" }
        require(activation.size in 1..ACTIVATION_MAX_BYTES) {
            "Activation frame must contain 1..$ACTIVATION_MAX_BYTES bytes"
        }
        originalSchemeId = schemeId.copyOf()
        require(originalSchemeId.any { it.toInt() != 0 }) { "schemeId must be nonzero" }
        originalActivation = activation.copyOf()
    }

    /** Copy of the exact independently selected scheme identity. */
    fun schemeId(): ByteArray = originalSchemeId.copyOf()

    /** Copy of the complete retained Native original, without reinterpretation. */
    fun activation(): ByteArray = originalActivation.copyOf()

    override val kind: InstructionKind = InstructionKind.CUSTOM
    override val arguments: Map<String, String> get() = toInstructionBox().arguments

    /** Canonical concrete ledger frame with the Rust root's eight alignment bytes. */
    fun concreteFrame(): ByteArray {
        val root = NoritoEncoder(NoritoCodec.DEFAULT_FLAGS)
        activateField(root) { it.writeBytes(originalSchemeId) }
        activateField(root) { action ->
            action.writeUInt(2, 32)
            activateField(action) { NoritoAdapters.rawByteVecAdapter().encode(it, originalActivation) }
        }
        val payload = root.toByteArray()
        val header = NoritoHeader(
            SchemaHash.hash16(SCHEMA_NAME), payload.size, CRC64.compute(payload),
            NoritoCodec.DEFAULT_FLAGS, NoritoHeader.COMPRESSION_NONE,
        )
        // Root padding is excluded from the payload length and checksum.
        return header.encode() + ByteArray(8) + payload
    }

    /** Exact registered instruction consumed by the existing transaction encoder and signer. */
    override fun toInstructionBox(): InstructionBox = InstructionBox.fromWirePayload(WIRE_ID, concreteFrame())

    override fun equals(other: Any?): Boolean = other is KagemushaWalletActivateInstructionV1 &&
        originalSchemeId.contentEquals(other.originalSchemeId) && originalActivation.contentEquals(other.originalActivation)

    override fun hashCode(): Int = 31 * originalSchemeId.contentHashCode() + originalActivation.contentHashCode()

    companion object {
        /** Sole first-release dynamic registry identity, shared by the typed ledger actions. */
        const val WIRE_ID: String = "iroha.kagemusha.wallet.ledger.v1"
        /** Current Rust concrete schema identity; Activate is action tag 2. */
        const val SCHEMA_NAME: String = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1"
        /** Complete original Activation-frame bound from the canonical wallet wire contract. */
        const val ACTIVATION_MAX_BYTES: Int = 16_384
    }
}

private fun activateField(encoder: NoritoEncoder, write: (NoritoEncoder) -> Unit) {
    val field = encoder.childEncoder().also(write).toByteArray()
    encoder.writeLength(field.size.toLong(), (encoder.flags and NoritoHeader.COMPACT_LEN) != 0)
    encoder.writeBytes(field)
}
