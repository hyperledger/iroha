package org.hyperledger.iroha.sdk.offline

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** The per-connection receive budget covers the receiver-led exchange (`specs/kagemusha_wallet_wire_v1.md` §6, Nearby). */
class IrohaPeerNearbyReceiveBudgetV1Test {
    @Test
    fun `a payer connection admits hello authentication request and credited`() {
        val configuration = IrohaPeerNearbyConnectionsConfigurationV1()
        assertEquals(4, configuration.maximumReceiveRecordsPerConnection)
        assertFailsWith<IllegalArgumentException> { IrohaPeerNearbyConnectionsConfigurationV1(maximumReceiveRecordsPerConnection = 5) }
        assertFailsWith<IllegalArgumentException> { IrohaPeerNearbyConnectionsConfigurationV1(maximumReceiveRecordsPerConnection = 3) }

        val pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            configuration.maximumPendingReceiveCallbacks,
            configuration.maximumReceiveRecordsPerConnection,
        ) { drain ->
            drain()
            true
        }
        val payerRecords = listOf("HELLO", "AUTHENTICATION", "REQUEST", "CREDITED")
        val delivered = mutableListOf<String>()
        pump.activate(1, "receiver")
        for (record in payerRecords) {
            assertEquals(IrohaPeerNearbyReceiveAdmissionV1.ACCEPTED, pump.enqueue(1, "receiver") { delivered += record }, record)
        }
        assertEquals(payerRecords, delivered)
        assertEquals(IrohaPeerNearbyReceiveAdmissionV1.BUDGET_EXCEEDED, pump.enqueue(1, "receiver") { delivered += "extra" })

        // The next connection starts with a fresh budget.
        pump.activate(2, "receiver")
        assertEquals(IrohaPeerNearbyReceiveAdmissionV1.ACCEPTED, pump.enqueue(2, "receiver") { delivered += "next" })
        assertEquals(payerRecords + "next", delivered)
    }
}
