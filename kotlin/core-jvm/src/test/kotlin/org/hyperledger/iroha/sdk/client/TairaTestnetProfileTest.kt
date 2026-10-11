package org.hyperledger.iroha.sdk.client

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import org.hyperledger.iroha.sdk.core.model.NetworkId

class TairaTestnetProfileTest {
    @Test
    fun `profile uses caller supplied deployment network identity`() {
        val deployedNetworkId = NetworkId.parse(TEST_NETWORK_ID)
        val config = TairaTestnetProfile.clientConfig(deployedNetworkId)

        assertEquals(URI.create("https://taira.sora.org"), config.baseUri())
        assertEquals(deployedNetworkId, config.localSigningContext().get().networkId())
        assertEquals("fc56984b-2be7-431d-840e-21514d1883f0", TairaTestnetProfile.CHAIN_ID)
        assertEquals(369, TairaTestnetProfile.I105_DISCRIMINANT)
        assertEquals(
            "7ZepsJTHCVLKsrFFNZGSRGZgvBhv",
            TairaTestnetProfile.DIGITAL_SHEKEL_ASSET_DEFINITION_ID,
        )
        assertEquals("ds#boi.is", TairaTestnetProfile.DIGITAL_SHEKEL_ASSET_ALIAS)
        assertEquals(2, TairaTestnetProfile.DIGITAL_SHEKEL_ASSET_SCALE)
    }

    private companion object {
        private const val TEST_NETWORK_ID =
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
    }
}
