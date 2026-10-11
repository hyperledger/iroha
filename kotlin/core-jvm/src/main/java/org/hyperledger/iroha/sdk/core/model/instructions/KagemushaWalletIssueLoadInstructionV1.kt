// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.core.model.instructions

import java.math.BigInteger
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.norito.CRC64
import org.hyperledger.iroha.sdk.norito.NoritoAdapters
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash

/**
 * Original online charge terms carried by Rust `KagemushaWalletLoadChargeV1`.
 *
 * [quote] is the complete original ChargeQuote frame, within its 1,024-byte wire bound.
 * Construction does not authenticate its signature, terms or beneficiary; Core verifies them
 * against the actual IssueLoad and registered scheme before any ledger effect.
 */
class KagemushaWalletLoadChargeV1(quote: ByteArray, beneficiary: String) {
    private val originalQuote: ByteArray

    init {
        require(quote.size in 1..1024) { "ChargeQuote frame must contain 1..1024 bytes" }
        originalQuote = quote.copyOf()
    }

    /** Exact canonical domainless account named by the original quote. */
    val beneficiary: String = requireCanonicalI105Address(beneficiary, "beneficiary")
    private val beneficiaryPayload = TransferWirePayloadEncoder.encodeAccountIdPayload(this.beneficiary)

    /** A copy of the original frame; no parsed or re-signed substitute is produced. */
    fun quote(): ByteArray = originalQuote.copyOf()

    internal fun barePayload(): ByteArray = issueLoadBare {
        issueLoadField(it) { field -> NoritoAdapters.rawByteVecAdapter().encode(field, originalQuote) }
        issueLoadField(it) { field -> field.writeBytes(beneficiaryPayload) }
    }

    override fun equals(other: Any?): Boolean = other is KagemushaWalletLoadChargeV1 &&
        originalQuote.contentEquals(other.originalQuote) &&
        beneficiaryPayload.contentEquals(other.beneficiaryPayload)

    override fun hashCode(): Int = 31 * originalQuote.contentHashCode() + beneficiaryPayload.contentHashCode()
}

/**
 * Typed constructor for the current Rust `KagemushaWalletLedgerActionV1::IssueLoad`.
 *
 * The existing account signer signs this instruction inside an ordinary transaction. These
 * fields are transaction intent, not authenticated wallet ownership or permission to credit
 * offline balance. Core authenticates the payer, exact scheme/asset/wallet, successive ordinal,
 * retry identity and any charge. Offline credit still requires the original successful receipt
 * and independently verified ordinary finality through the native wallet.
 */
class KagemushaWalletIssueLoadInstructionV1 @JvmOverloads constructor(
    schemeId: ByteArray,
    walletId: ByteArray,
    assetDigest: ByteArray,
    /** Expected next ordinal, including zero for the first Load. */
    val ordinal: BigInteger,
    requestId: ByteArray,
    /** Positive net offline amount in the registered asset's atomic units. */
    val amount: BigInteger,
    /** Original optional displayed online charge, separate from [amount]. */
    val charge: KagemushaWalletLoadChargeV1? = null,
) : InstructionTemplate {
    private val originalSchemeId = issueLoadIdentity(schemeId, "schemeId")
    private val originalWalletId = issueLoadIdentity(walletId, "walletId")
    private val originalAssetDigest = issueLoadIdentity(assetDigest, "assetDigest")
    private val originalRequestId = issueLoadIdentity(requestId, "requestId")

    init {
        require(ordinal.signum() >= 0 && ordinal.bitLength() <= 128) { "ordinal must fit u128" }
        require(amount.signum() > 0 && amount.bitLength() <= 128) { "amount must be positive u128" }
    }

    /** Copy of the exact selected scheme identity. */
    fun schemeId(): ByteArray = originalSchemeId.copyOf()
    /** Copy of the intended wallet incarnation. */
    fun walletId(): ByteArray = originalWalletId.copyOf()
    /** Copy of the registered asset digest. */
    fun assetDigest(): ByteArray = originalAssetDigest.copyOf()
    /** Copy of the stable, nonzero retry identity. */
    fun requestId(): ByteArray = originalRequestId.copyOf()

    override val kind: InstructionKind = InstructionKind.CUSTOM
    override val arguments: Map<String, String> get() = toInstructionBox().arguments

    /** Complete concrete frame, including the Rust u128 root's eight alignment bytes. */
    fun concreteFrame(): ByteArray {
        val payload = issueLoadBare { root ->
            issueLoadField(root) { it.writeBytes(originalSchemeId) }
            issueLoadField(root) { action ->
                action.writeUInt(5, 32)
                issueLoadField(action) { it.writeBytes(originalWalletId) }
                issueLoadField(action) { it.writeBytes(originalAssetDigest) }
                issueLoadField(action) { issueLoadU128(it, ordinal) }
                issueLoadField(action) { it.writeBytes(originalRequestId) }
                issueLoadField(action) { issueLoadU128(it, amount) }
                issueLoadField(action) { optional ->
                    if (charge == null) {
                        optional.writeByte(0)
                    } else {
                        optional.writeByte(1)
                        issueLoadField(optional) { it.writeBytes(charge.barePayload()) }
                    }
                }
            }
        }
        val header = NoritoHeader(
            SchemaHash.hash16(SCHEMA_NAME), payload.size, CRC64.compute(payload),
            NoritoCodec.DEFAULT_FLAGS, NoritoHeader.COMPRESSION_NONE,
        )
        // Root padding is outside payload length/checksum; nested structs have no root padding.
        return header.encode() + ByteArray(8) + payload
    }

    /** Canonical registered wire instruction accepted by the ordinary transaction encoder. */
    override fun toInstructionBox(): InstructionBox = InstructionBox.fromWirePayload(WIRE_ID, concreteFrame())

    override fun equals(other: Any?): Boolean = other is KagemushaWalletIssueLoadInstructionV1 &&
        concreteFrame().contentEquals(other.concreteFrame())

    override fun hashCode(): Int = concreteFrame().contentHashCode()

    companion object {
        /** Sole first-release dynamic registry identity. */
        const val WIRE_ID: String = "iroha.kagemusha.wallet.ledger.v1"
        /** Current Rust concrete schema identity; the action tag is 5. */
        const val SCHEMA_NAME: String = "iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1"
    }
}

private fun issueLoadIdentity(value: ByteArray, label: String): ByteArray {
    require(value.size == 32) { "$label must be 32 bytes" }
    return value.copyOf().also { snapshot ->
        require(snapshot.any { it.toInt() != 0 }) { "$label must be nonzero" }
    }
}

private fun issueLoadBare(write: (NoritoEncoder) -> Unit): ByteArray =
    NoritoEncoder(NoritoCodec.DEFAULT_FLAGS).also(write).toByteArray()

private fun issueLoadField(encoder: NoritoEncoder, write: (NoritoEncoder) -> Unit) {
    val field = encoder.childEncoder().also(write).toByteArray()
    encoder.writeLength(field.size.toLong(), (encoder.flags and NoritoHeader.COMPACT_LEN) != 0)
    encoder.writeBytes(field)
}

private fun issueLoadU128(encoder: NoritoEncoder, value: BigInteger) {
    // Constructor range checks make every shift lossless, including values above signed Long.
    repeat(16) { index -> encoder.writeByte(value.shiftRight(index * 8).toInt() and 0xff) }
}
