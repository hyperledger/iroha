// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

/** Portable controller handoff, emitted by the driver only after the actual Native retain call. */
internal fun activationRetentionReceipt(
    wire: ByteArray, value: KagemushaWalletActivationFinalityV1, returned: Long,
    invocation: String, sequence: Int,
): ByteArray? {
    probeRequire(wire.size in 1..65_536 && returned > 0 && sequence in 0..9999)
    EnrollmentProbeConfiguration.uuid(invocation)
    if (value.confirmation != null || value.rejected || value.verifiedHeightBits != null ||
        value.blockHash() != null) return null
    return probeJson("schema" to "iroha.kagemusha.wallet-activation-retained.v1",
        "action" to "retain-activation", "signedWireSHA256" to EnrollmentProbeFiles.digest(wire),
        "signedWireBytes" to wire.size.toString(), "nativeResult" to "not_started",
        "nativeReturnedTicks" to returned.toString(), "invocation" to invocation,
        "sequence" to sequence.toString())
}
