// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Explicit Native terminalization only; exported instructions are not ledger inclusion evidence. */
internal fun exportEnrollmentAbandonment(
    owner: KagemushaWalletEnrollmentV1, publish: (String, ByteArray) -> Unit,
): String = when (val abandoned = owner.abandon()) {
    KagemushaWalletEnrollmentAbandonmentV1.LocalAbandoned -> {
        probeRequire(owner.abandonmentLedgerInstruction() == null, "abandonment-form")
        publish("abandonment.json", probeJson("form" to "local", "ledgerFinalityClaimed" to "false"))
        "native-local-abandoned"
    }
    is KagemushaWalletEnrollmentAbandonmentV1.Abandonment -> {
        // Publish the already durable signed original before requesting its ledger wrapper.
        publish("abandonment.norito", abandoned.frame())
        val instruction = owner.abandonmentLedgerInstruction()
            ?: throw EnrollmentProbeFailure("abandonment-form")
        publish("abandonment-ledger-instruction.norito", instruction)
        publish("abandonment.json", probeJson("form" to "signed", "ledgerFinalityClaimed" to "false"))
        "native-signed-abandonment-exported"
    }
}

/** Expiry consumes only the real issuer proof; Native decides expiry and the local terminal form. */
internal fun exportExpiredEnrollmentAbandonment(
    owner: KagemushaWalletEnrollmentV1, proof: ByteArray, publish: (String, ByteArray) -> Unit,
): String {
    probeRequire(owner.abandonExpired(proof) === KagemushaWalletEnrollmentAbandonmentV1.LocalAbandoned,
        "abandonment-form")
    publish("abandonment.json", probeJson("form" to "expired-local", "ledgerFinalityClaimed" to "false"))
    return "native-expired-local-abandoned"
}
