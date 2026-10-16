// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

/** A receiver advertising before it holds a Request (`specs/kagemusha_wallet_wire_v1.md` §6, Nearby). */
class IrohaPeerNearbyFreshReceiverV1Test {
    @Test
    fun `fresh receiver contexts bind random nonzero session and binding values`() {
        val profile = IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1
        val first = IrohaPeerNearbyDiscoveryContextV1.freshReceiver(profile)
        val second = IrohaPeerNearbyDiscoveryContextV1.freshReceiver(profile)
        assertEquals(IrohaPeerNearbyRoleV1.RECEIVER, first.role)
        assertEquals(profile, first.profile)
        assertEquals(16, first.sessionId.size)
        assertEquals(32, first.requestCanonicalHash.size)
        assertFalse(first.sessionId.all { it.toInt() == 0 })
        assertFalse(first.requestCanonicalHash.all { it.toInt() == 0 })
        assertFalse(first.isSenderBootstrap)
        assertFalse(first.sessionId.contentEquals(second.sessionId))
        assertFalse(first.requestCanonicalHash.contentEquals(second.requestCanonicalHash))
        assertEquals(first, IrohaPeerNearbyDiscoveryContextV1.decode(first.encode()))
        assertEquals(first, IrohaPeerNearbyDiscoveryContextV1.decodeRadioDiscovery(first.encodeRadioDiscovery()))

        // A bootstrapping sender adopts the advertised session and binding.
        val sender = assertNotNull(
            IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(
                IrohaPeerNearbyDiscoveryContextV1.senderBootstrap(profile),
                first,
                IrohaPeerNearbyRoleV1.RECEIVER,
            ),
        )
        assertEquals(IrohaPeerNearbyRoleV1.SENDER, sender.role)
        assertContentEquals(first.sessionId, sender.sessionId)
        assertContentEquals(first.requestCanonicalHash, sender.requestCanonicalHash)
    }
}
