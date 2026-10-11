// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletLoadIssuanceOriginalV1
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletLoadSelectionV1
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge

/**
 * Exact canonical receipt and native BLS evidence bound to the signed read's selectors
 * and payer. Decoding grants no verified finality, wallet admission, balance or Load permission.
 * The existing native wallet [KagemushaWalletV1.load] independently verifies its certificate,
 * event path, installed genesis/epoch authority, enrolled account, ordinal and durable operation.
 */
class KagemushaWalletLoadOriginalV1 private constructor(
    private val input: KagemushaWalletLoadOriginalInputV1,
    /** Network retained from the original authenticated transport, not inferred from receipt data. */
    @JvmField val networkId: NetworkId,
    /** Exact canonical payer literal retained from the authenticated read. */
    @JvmField val payerAccountId: String,
    /** Canonical receipt height DATA, never authenticated finality by itself. */
    @JvmField val blockHeight: java.math.BigInteger,
    /** Exact authenticated-read route selectors. */
    @JvmField val selection: ToriiKagemushaWalletLoadSelectionV1,
) {
    /** Exact retained request selector, already bound to the canonical receipt data. */
    fun requestId(): ByteArray = input.requestId()
    /** Whole original receipt, never reconstructed from a managed projection. */
    fun receiptOriginal(): ByteArray = input.receipt()
    /** Whole original native BLS evidence; no finality verdict has been conferred. */
    fun finalityOriginal(): ByteArray = input.finality()
    override fun toString(): String = "KagemushaWalletLoadOriginalV1(originals=[REDACTED])"

    companion object {
        /** Decode with the maintained Native canonical types, preserving exact originals. */
        @JvmStatic
        fun decode(issuance: ToriiKagemushaWalletLoadIssuanceOriginalV1,
            finalityOriginal: ByteArray): KagemushaWalletLoadOriginalV1 {
            return decodeRetained(issuance.selection, issuance.payerAccountId, issuance.networkId,
                issuance.unverifiedResponseOriginal, finalityOriginal)
        }

        /** Reopen exact retained DATA through the same Native decoder. All selectors and the
         * network remain untrusted until the installed wallet verifies finality before Load. */
        @JvmStatic
        fun decodeRetained(selection: ToriiKagemushaWalletLoadSelectionV1, payerAccountId: String,
            networkId: NetworkId, receiptOriginal: ByteArray,
            finalityOriginal: ByteArray): KagemushaWalletLoadOriginalV1 {
            val input = KagemushaWalletLoadOriginalInputV1(selection, payerAccountId,
                receiptOriginal, finalityOriginal)
            if (!PrivacyNativeBridge.isNativeAvailable()) {
                throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
            }
            val height = LongArray(1)
            val status = try {
                if (KagemushaWalletNativeV1.revision() != 1) {
                    throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
                }
                KagemushaWalletLoadOriginalNativeV1.validate(input.schemeId(), input.walletId(),
                    input.requestId(), input.payer(), input.receipt(), input.finality(), height)
            } catch (_: LinkageError) {
                throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.BRIDGE_UNAVAILABLE)
            }
            if (status < 0) throw KagemushaWalletExceptionV1(status)
            if (status != 0 || height[0] == 0L) throw KagemushaWalletExceptionV1(KagemushaWalletExceptionV1.INVALID_NATIVE_OUTPUT)
            return KagemushaWalletLoadOriginalV1(input, networkId, payerAccountId,
                java.math.BigInteger(java.lang.Long.toUnsignedString(height[0])), selection)
        }
    }
}

/** Finite owned inputs only; this constructor does not decode, authenticate or authorize value. */
internal class KagemushaWalletLoadOriginalInputV1(
    selection: ToriiKagemushaWalletLoadSelectionV1, payerAccountId: String,
    receipt: ByteArray, finality: ByteArray,
) {
    private val scheme = selection.schemeId
    private val wallet = selection.walletId
    private val request = selection.requestId
    private val account: ByteArray
    private val retainedReceipt: ByteArray
    private val retainedFinality: ByteArray
    init {
        // Retain exact DATA bytes, including I105 kana. Native owns canonical account parsing.
        require(payerAccountId.isNotEmpty() && payerAccountId.length <= 1024) {
            "payer exceeds its UTF-8 input bound"
        }
        val encodedPayer = try {
            Charsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(payerAccountId))
        } catch (error: CharacterCodingException) {
            throw IllegalArgumentException("payer must encode as exact UTF-8 without replacement", error)
        }
        require(encodedPayer.remaining() <= 1024) { "payer exceeds its UTF-8 byte bound" }
        account = ByteArray(encodedPayer.remaining()).also { encodedPayer.get(it) }
        require(receipt.isNotEmpty() && receipt.size <= 512) { "canonical receipt bound exceeded" }
        require(finality.isNotEmpty() && finality.size <= 256 * 1024) { "canonical finality bound exceeded" }
        retainedReceipt = receipt.copyOf()
        retainedFinality = finality.copyOf()
    }
    fun schemeId() = scheme.copyOf()
    fun walletId() = wallet.copyOf()
    fun requestId() = request.copyOf()
    fun payer() = account.copyOf()
    fun receipt() = retainedReceipt.copyOf()
    fun finality() = retainedFinality.copyOf()
    override fun toString(): String = "KagemushaWalletLoadOriginalInputV1(originals=[REDACTED])"
}

/** Calls the sole Native DATA decoder, without raw wallet handles or proof providers. */
internal object KagemushaWalletLoadOriginalNativeV1 {
    @JvmStatic external fun validate(scheme: ByteArray, wallet: ByteArray, request: ByteArray,
        payer: ByteArray, receipt: ByteArray, finality: ByteArray, outHeight: LongArray): Int
}
