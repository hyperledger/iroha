package org.hyperledger.iroha.sdk.client

import java.net.URI
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Stable, non-secret public metadata for the SORA Taira testnet. */
object TairaTestnetProfile {
    /** Public Torii origin. */
    @JvmField
    val TORII_BASE_URI: URI = URI.create("https://taira.sora.org")

    /** Stable semantic chain UUID; this is not a transaction-signing [NetworkId]. */
    const val CHAIN_ID: String = "fc56984b-2be7-431d-840e-21514d1883f0"

    /** Canonical I105 address discriminant for Taira. */
    const val I105_DISCRIMINANT: Int = 369

    /** Canonical Digital Shekel asset-definition ID on Taira. */
    const val DIGITAL_SHEKEL_ASSET_DEFINITION_ID: String = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv"

    /** Canonical Digital Shekel alias on Taira. */
    const val DIGITAL_SHEKEL_ASSET_ALIAS: String = "ds#boi.is"

    /** Canonical Digital Shekel fixed-point scale on Taira. */
    const val DIGITAL_SHEKEL_ASSET_SCALE: Int = 2

    /** Public Taira XOR asset-definition ID used for transaction fees. */
    const val XOR_ASSET_DEFINITION_ID: String = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"

    /** Public Taira XOR alias used for transaction fees. */
    const val XOR_ASSET_ALIAS: String = "xor#universal"

    /** Public Taira XOR fee-asset fixed-point scale. */
    const val XOR_ASSET_SCALE: Int = 9

    /**
     * Creates a Taira client config bound to the caller-supplied deployed genesis identity.
     *
     * Taira resets can change [NetworkId], so callers must obtain this value from the current
     * deployment config or genesis material. The profile never guesses or downloads signing
     * identity from an unauthenticated server response.
     */
    @JvmStatic
    fun clientConfig(deployedNetworkId: NetworkId): ClientConfig =
        ClientConfig.builder()
            .setBaseUri(TORII_BASE_URI)
            .setLocalSigningContext(LocalSigningContext(deployedNetworkId))
            .build()
}
