package org.hyperledger.iroha.sdk.client

import java.util.Base64
import java.util.Optional
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.model.zk.VerifyingKeyBackendTag
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.TypeAdapter
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

internal enum class VerifyingKeyDraftOperation(
    val wireName: String,
    val schemaPath: String,
) {
    REGISTER(
        "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
        "iroha_data_model::isi::verifying_keys::RegisterVerifyingKey",
    ),
    UPDATE(
        "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
        "iroha_data_model::isi::verifying_keys::UpdateVerifyingKey",
    ),
}

/**
 * Binds an unsigned Torii draft to the exact verifying-key mutation requested by the caller.
 *
 * The response is decoded as a canonical transaction and its one native instruction is compared
 * byte-for-byte with a freshly encoded canonical instruction. That comparison covers the complete
 * 17-field `VerifyingKeyRecord`, including server-derived defaults and inline-key commitment.
 */
internal object VerifyingKeyDraftBinding {
    fun validate(
        transactionPayload: ByteArray,
        expectedNetworkId: NetworkId,
        request: Map<String, Any>,
        operation: VerifyingKeyDraftOperation,
    ) {
        val authority = requiredString(request, "authority")
        val discriminant = AccountAddress.detectI105Discriminant(authority)
            ?: throw IllegalArgumentException(
                "verifying-key draft request authority must be a canonical I105 account literal",
            )
        val payload = try {
            NoritoJavaCodecAdapter(discriminant).decodeTransaction(transactionPayload)
        } catch (ex: Exception) {
            throw IllegalArgumentException(
                "transaction_payload_b64 must contain one canonical transaction payload",
                ex,
            )
        }
        require(payload.networkId == expectedNetworkId && payload.authority == authority) {
            "verifying-key draft transaction payload changed the requested network or authority"
        }
        val executable = payload.executable as? Executable.Instructions
            ?: throw IllegalArgumentException(
                "verifying-key draft transaction payload must contain native instructions",
            )
        require(executable.instructions.size == 1) {
            "verifying-key draft transaction payload must contain exactly one instruction"
        }
        val actual = executable.instructions.single().payload as? WirePayload
            ?: throw IllegalArgumentException(
                "verifying-key draft transaction payload must contain a wire-framed instruction",
            )
        val expected = expectedInstruction(request, operation).payload as WirePayload
        require(
            actual.wireName == expected.wireName &&
                actual.payloadBytes.contentEquals(expected.payloadBytes),
        ) {
            "verifying-key draft transaction payload does not contain the requested registry operation"
        }
    }

    internal fun expectedInstruction(
        request: Map<String, Any>,
        operation: VerifyingKeyDraftOperation,
    ): InstructionBox {
        val expected = ExpectedInstruction.fromRequest(request)
        return InstructionBox.fromWirePayload(
            operation.wireName,
            NoritoCodec.encode(expected, operation.schemaPath, ExpectedInstructionAdapter),
        )
    }

    private class ExpectedInstruction(
        val backend: String,
        val name: String,
        val version: Long,
        val circuitId: String,
        val backendTag: Long,
        val curve: String,
        val publicInputsSchemaHash: ByteArray,
        val commitment: ByteArray,
        val verifyingKeyLength: Long,
        val maxProofBytes: Long,
        val gasScheduleId: String?,
        val metadataUriCid: String?,
        val verifyingKeyBytesCid: String?,
        val activationHeight: Long?,
        val withdrawHeight: Long?,
        val verifyingKeyBytes: ByteArray?,
        val status: Long,
    ) {
        companion object {
            fun fromRequest(request: Map<String, Any>): ExpectedInstruction {
                val backend = requiredString(request, "backend")
                val backendTag = when (
                    VerifyingKeyBackendTag.verifierBackendRegistryTagV1(backend)
                ) {
                    VerifyingKeyBackendTag.STARK -> 1L
                    VerifyingKeyBackendTag.NATIVE_PIPA_R_PASTA -> 0L
                    null -> throw IllegalArgumentException(
                        "verifying-key draft request uses an unsupported backend",
                    )
                }
                val keyBytes = optionalCanonicalBase64(request, "vk_bytes")
                val commitment = if (keyBytes != null) {
                    hex32(
                        HttpClientTransport.verifyingKeyCommitmentHex(backend, keyBytes),
                        "computed commitment",
                    )
                } else {
                    hex32(
                        requiredString(request, "commitment_hex"),
                        "commitment_hex",
                    )
                }
                val keyLength = keyBytes?.size?.toLong()
                    ?: requiredU32(request, "vk_len", positive = true)
                return ExpectedInstruction(
                    backend = backend,
                    name = requiredString(request, "name"),
                    version = requiredU32(request, "version", positive = true),
                    circuitId = requiredString(request, "circuit_id"),
                    backendTag = backendTag,
                    curve = optionalString(request, "curve") ?: "unknown",
                    publicInputsSchemaHash = hex32(
                        requiredString(request, "public_inputs_schema_hash_hex"),
                        "public_inputs_schema_hash_hex",
                    ),
                    commitment = commitment,
                    verifyingKeyLength = keyLength,
                    maxProofBytes = optionalU32(request, "max_proof_bytes") ?: 0L,
                    gasScheduleId = optionalString(request, "gas_schedule_id"),
                    metadataUriCid = optionalString(request, "metadata_uri_cid"),
                    verifyingKeyBytesCid = optionalString(request, "vk_bytes_cid"),
                    activationHeight = optionalU64(request, "activation_height"),
                    withdrawHeight = optionalU64(request, "withdraw_height"),
                    verifyingKeyBytes = keyBytes,
                    status = when (optionalString(request, "status") ?: "Active") {
                        "Proposed" -> 0L
                        "Active" -> 1L
                        "Withdrawn" -> 2L
                        else -> throw IllegalArgumentException(
                            "verifying-key draft request uses an invalid status",
                        )
                    },
                )
            }
        }
    }

    private object ExpectedInstructionAdapter : TypeAdapter<ExpectedInstruction> {
        override fun encode(encoder: NoritoEncoder, value: ExpectedInstruction) {
            encodeSized(encoder) { id ->
                encodeSized(id) { STRING.encode(it, value.backend) }
                encodeSized(id) { STRING.encode(it, value.name) }
            }
            encodeSized(encoder) { record ->
                encodeSized(record) { it.writeUInt(value.version, 32) }
                encodeSized(record) { STRING.encode(it, value.circuitId) }
                encodeSized(record) { OPTIONAL_STRING.encode(it, Optional.empty()) }
                encodeSized(record) { STRING.encode(it, CORE_NAMESPACE) }
                encodeSized(record) { it.writeUInt(value.backendTag, 32) }
                encodeSized(record) { STRING.encode(it, value.curve) }
                encodeSized(record) { it.writeBytes(value.publicInputsSchemaHash) }
                encodeSized(record) { it.writeBytes(value.commitment) }
                encodeSized(record) { it.writeUInt(value.verifyingKeyLength, 32) }
                encodeSized(record) { it.writeUInt(value.maxProofBytes, 32) }
                encodeSized(record) {
                    OPTIONAL_STRING.encode(it, Optional.ofNullable(value.gasScheduleId))
                }
                encodeSized(record) {
                    OPTIONAL_STRING.encode(it, Optional.ofNullable(value.metadataUriCid))
                }
                encodeSized(record) {
                    OPTIONAL_STRING.encode(it, Optional.ofNullable(value.verifyingKeyBytesCid))
                }
                encodeSized(record) {
                    OPTIONAL_U64.encode(it, Optional.ofNullable(value.activationHeight))
                }
                encodeSized(record) {
                    OPTIONAL_U64.encode(it, Optional.ofNullable(value.withdrawHeight))
                }
                encodeSized(record) {
                    OPTIONAL_KEY.encode(
                        it,
                        Optional.ofNullable(
                            value.verifyingKeyBytes?.let { bytes ->
                                ExpectedKey(value.backend, bytes)
                            },
                        ),
                    )
                }
                encodeSized(record) { it.writeUInt(value.status, 32) }
            }
        }

        override fun decode(decoder: NoritoDecoder): ExpectedInstruction =
            throw UnsupportedOperationException("verifying-key expectation is encode-only")
    }

    private class ExpectedKey(
        val backend: String,
        val bytes: ByteArray,
    )

    private object ExpectedKeyAdapter : TypeAdapter<ExpectedKey> {
        override fun encode(encoder: NoritoEncoder, value: ExpectedKey) {
            encodeSized(encoder) { STRING.encode(it, value.backend) }
            encodeSized(encoder) { RAW_BYTES.encode(it, value.bytes) }
        }

        override fun decode(decoder: NoritoDecoder): ExpectedKey =
            throw UnsupportedOperationException("verifying-key expectation is encode-only")
    }

    private fun encodeSized(
        encoder: NoritoEncoder,
        encode: (NoritoEncoder) -> Unit,
    ) {
        val child = encoder.childEncoder()
        encode(child)
        val bytes = child.toByteArray()
        encoder.writeLength(
            bytes.size.toLong(),
            (encoder.flags and NoritoHeader.COMPACT_LEN) != 0,
        )
        encoder.writeBytes(bytes)
    }

    private fun requiredString(request: Map<String, Any>, field: String): String =
        request[field] as? String
            ?: throw IllegalArgumentException("verifying-key draft request.$field must be a string")

    private fun optionalString(request: Map<String, Any>, field: String): String? {
        val value = request[field] ?: return null
        return value as? String
            ?: throw IllegalArgumentException("verifying-key draft request.$field must be a string")
    }

    private fun requiredU32(
        request: Map<String, Any>,
        field: String,
        positive: Boolean,
    ): Long = optionalU32(request, field, positive)
        ?: throw IllegalArgumentException("verifying-key draft request.$field is required")

    private fun optionalU32(
        request: Map<String, Any>,
        field: String,
        positive: Boolean = false,
    ): Long? {
        val value = request[field] ?: return null
        val number = exactLong(value, field)
        require(number in (if (positive) 1L else 0L)..U32_MAX) {
            "verifying-key draft request.$field must fit in u32"
        }
        return number
    }

    private fun optionalU64(request: Map<String, Any>, field: String): Long? {
        val value = request[field] ?: return null
        val number = exactLong(value, field)
        require(number >= 0) {
            "verifying-key draft request.$field must be a non-negative u64"
        }
        return number
    }

    private fun exactLong(value: Any, field: String): Long {
        require(value is Number) {
            "verifying-key draft request.$field must be an integer"
        }
        val number = value.toLong()
        require(value.toString() == number.toString()) {
            "verifying-key draft request.$field must be an exact integer"
        }
        return number
    }

    private fun optionalCanonicalBase64(
        request: Map<String, Any>,
        field: String,
    ): ByteArray? {
        val encoded = optionalString(request, field) ?: return null
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (ex: IllegalArgumentException) {
            throw IllegalArgumentException(
                "verifying-key draft request.$field must be canonical base64",
                ex,
            )
        }
        require(bytes.isNotEmpty() && Base64.getEncoder().encodeToString(bytes) == encoded) {
            "verifying-key draft request.$field must be canonical non-empty base64"
        }
        return bytes
    }

    private fun hex32(value: String, field: String): ByteArray {
        require(value.length == 64) {
            "verifying-key draft request.$field must contain 64 lowercase hex characters"
        }
        return ByteArray(32) { index ->
            val offset = index * 2
            val high = Character.digit(value[offset], 16)
            val low = Character.digit(value[offset + 1], 16)
            require(high >= 0 && low >= 0 && value[offset] !in 'A'..'F' &&
                value[offset + 1] !in 'A'..'F'
            ) {
                "verifying-key draft request.$field must contain 64 lowercase hex characters"
            }
            ((high shl 4) or low).toByte()
        }
    }

    private val STRING = NoritoAdapters.stringAdapter()
    private val RAW_BYTES = NoritoAdapters.rawByteVecAdapter()
    private val OPTIONAL_STRING = NoritoAdapters.option(STRING)
    private val OPTIONAL_U64 = NoritoAdapters.option(NoritoAdapters.uint(64))
    private val OPTIONAL_KEY = NoritoAdapters.option(ExpectedKeyAdapter)
    private const val CORE_NAMESPACE = "core"
    private const val U32_MAX = 0xffff_ffffL
}
