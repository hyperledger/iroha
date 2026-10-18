package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent

/** Response payload returned by Torii multisig participation endpoints. */
data class MultisigResponse(
    val ok: Boolean,
    val resolvedMultisigAccountId: String,
    val submitted: Boolean,
    val proposalId: String,
    val instructionsHash: String,
    val txHashHex: String?,
    val executedTxHashHex: String?,
    val creationTimeMs: Long?,
    val feePayment: FeePaymentIntent,
    val transactionPayloadB64: String?,
    val signingMessageB64: String?,
)
