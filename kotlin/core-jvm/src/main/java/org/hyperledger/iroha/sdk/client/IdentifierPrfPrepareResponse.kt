package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Structural prepare projection; no standalone opening or phone signature admission. */
class IdentifierPrfPrepareResponse(
    @JvmField val networkId: NetworkId,
    @JvmField val policyId: String,
    @JvmField val accountId: String,
    @JvmField val uaid: String,
    @JvmField val outputOpening: RamLfeOutputOpening,
    @JvmField val phoneRetailCanonicalityPayload: PhoneRetailCanonicalityPayloadV1?,
)
