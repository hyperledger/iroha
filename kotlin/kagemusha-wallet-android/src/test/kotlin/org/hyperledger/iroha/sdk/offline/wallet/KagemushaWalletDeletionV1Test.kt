package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.*
import org.junit.jupiter.api.Test

class KagemushaWalletDeletionV1Test {
    private fun frame(): ByteArray = ByteArray(254).also { value ->
        byteArrayOf(75, 87, 67, 68, 86, 49, 0, 0).copyInto(value)
        value[8] = 1; value[9] = 2; value[10] = 8
        value[11] = 1; value[12] = 1; value[13] = 1
        listOf(14, 46, 78, 110, 142, 174).forEach { value[it] = 1 }
        value[206] = 7; value[222] = 9; value[238] = 3
    }
    private fun call(status: Int, token: Long = 0, bytes: ByteArray = byteArrayOf()) =
        KagemushaWalletCallV1(status, 0, 0, token, 0, 0, bytes)

    @Test fun exactClosedProjectionCopiesEveryIdentityAndUsesUnsignedAmounts() {
        val bytes = frame()
        val projection = KagemushaWalletDeletionProjectionV1(bytes)
        bytes[14] = 2
        assertEquals(1, projection.slot()[0].toInt())
        projection.slot()[0] = 4
        assertEquals(1, projection.slot()[0].toInt())
        assertTrue(projection.pending)
        assertEquals(KagemushaWalletLifecycleV1.RETIRING, projection.lifecycle)
        assertEquals(8, projection.operationKind)
        assertTrue(projection.pendingOutgoing && projection.feeClaims && projection.loadRedeem)
        assertEquals(KagemushaWalletUInt128V1(7, 0), projection.sequence)
        assertEquals(KagemushaWalletUInt128V1(9, 0), projection.grossBalance)
        assertEquals(KagemushaWalletUInt128V1(3, 0), projection.coreBurnedTotal)
        for (offset in 8..13) {
            val invalid = frame(); invalid[offset] = -1
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletDeletionProjectionV1(invalid) }
        }
        for (offset in listOf(14, 46, 78, 110, 142, 174)) {
            val invalid = frame(); (offset until offset + 32).forEach { invalid[it] = 0 }
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletDeletionProjectionV1(invalid) }
        }
        val wrongMagic = frame().also { it[7] = 1 }
        for (invalid in listOf(byteArrayOf(), frame().copyOf(253), frame().copyOf(255), wrongMagic)) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletDeletionProjectionV1(invalid) }
        }
        val maximum = frame().also { (222 until 254).forEach { index -> it[index] = -1 } }
        assertEquals(KagemushaWalletUInt128V1(-1, -1), KagemushaWalletDeletionProjectionV1(maximum).grossBalance)
        maximum[222] = -2
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletDeletionProjectionV1(maximum) }
    }
    @Test fun requestsAndResponsesHaveClosedShapes() {
        for (selector in 48..51) {
            val token = if (selector == 49 || selector == 51) 7L else 0L
            val input = KagemushaWalletSetupInputV1(selector, token = token)
            assertContentEquals(ByteArray(32), input.identity())
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, token = token, first = byteArrayOf(1)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, token = token, amount = KagemushaWalletUInt128V1(1, 0)) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletSetupInputV1(selector, token = if (token == 0L) 1 else 0) }
        }
        call(53, Long.MAX_VALUE, frame()); call(54, bytes = ByteArray(32) { 1 }); call(55); call(56)
        assertFailsWith<KagemushaWalletExceptionV1> { call(53, bytes = frame()) }
        assertFailsWith<KagemushaWalletExceptionV1> { call(53, 1, frame().copyOf(255)) }
        assertFailsWith<KagemushaWalletExceptionV1> { call(54, bytes = ByteArray(32)) }
        for (status in 54..56) {
            assertFailsWith<KagemushaWalletExceptionV1> { call(status, 1, if (status == 54) ByteArray(32) { 1 } else byteArrayOf()) }
        }
        assertFailsWith<KagemushaWalletExceptionV1> { call(57) }
    }
    @Test fun uncertainConfirmationFreezesOrdinaryCallsUntilDefinitiveRecovery() {
        val gate = KagemushaWalletDeletionGateV1()
        val foreign = KagemushaWalletDeletionGateV1()
        assertFailsWith<IllegalStateException> { gate.resume { fail("fresh resume dispatched") } }
        gate.requireOrdinary()
        val review = gate.review { call(53, 7, frame()) }
        assertFailsWith<IllegalArgumentException> { foreign.confirm(review) { fail("foreign dispatch") } }
        val stale = gate.review { call(53, 8, frame()) }
        assertFailsWith<UnsupportedOperationException> {
            gate.confirm(review) { token ->
                assertEquals(7L, token)
                assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
                assertFailsWith<IllegalStateException> { gate.resume { fail("concurrent resume") } }
                throw UnsupportedOperationException("simulated delivery loss")
            }
        }
        assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
        assertFailsWith<IllegalArgumentException> { gate.discard(review) { fail("cannot undo") } }
        assertSame(KagemushaWalletDeletionStatusV1.NotDeleted, gate.resume { call(56) })
        gate.requireOrdinary()
        assertFailsWith<IllegalArgumentException> { gate.confirm(stale) { fail("stale review") } }
        val fresh = gate.review { call(53, 9, frame()) }
        val marker = ByteArray(32) { 3 }
        assertContentEquals(marker, gate.confirm(fresh) { call(54, bytes = marker) })
        assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
        val resumed = gate.resume { call(54, bytes = marker) } as KagemushaWalletDeletionStatusV1.Deleted
        resumed.marker()[0] = 99
        assertContentEquals(marker, resumed.marker())
        assertFailsWith<KagemushaWalletExceptionV1> { gate.resume { call(54, bytes = ByteArray(32) { 4 }) } }
        assertFailsWith<KagemushaWalletExceptionV1> { gate.resume { call(56) } }
        assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
    }
    @Test fun discardCannotUndoAnAttemptAndMalformedRecoveryStaysFrozen() {
        val gate = KagemushaWalletDeletionGateV1()
        val review = gate.review { call(53, 1, frame()) }
        gate.discard(review) { call(55) }
        gate.requireOrdinary()
        assertFailsWith<IllegalArgumentException> { gate.confirm(review) { fail("discarded") } }
        val fresh = gate.review { call(53, 2, frame()) }
        assertFailsWith<KagemushaWalletExceptionV1> { gate.confirm(fresh) { call(55) } }
        assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
        assertFailsWith<KagemushaWalletExceptionV1> { gate.resume { call(55) } }
        assertFailsWith<IllegalStateException> { gate.requireOrdinary() }
        gate.resume { call(56) }
        gate.requireOrdinary()
    }
}
