package org.hyperledger.iroha.sdk.offline.wallet

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.*
import org.junit.jupiter.api.Test

/** Projection DATA tests only, not an installed owner or financial admission. */
class KagemushaWalletOutputV1Test {
    private fun buffer(size: Int, magic: String) = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        .also { it.put(magic.toByteArray(Charsets.US_ASCII)) }
    private fun metadata() = buffer(153, "KWMDV1\u0000\u0000").putInt(2).put(ByteArray(128) { 7 })
        .putInt(2).putInt(3).put(byteArrayOf(11,12,21,22,23)).array()
    private fun released(kind: Int, peer: Int) = buffer(if (peer == 0) 68 else 70, "KWROV1\u0000\u0000")
        .put(kind.toByte()).put(ByteArray(32) { 7 }).putLong(-1).putLong(-1)
        .putInt(2).put(peer.toByte()).putInt(if (peer == 0) 0 else 2).put(byteArrayOf(11,12))
        .also { if (peer != 0) it.put(byteArrayOf(11,12)) }.array()
    private fun load(length: Int = 1) = buffer(220 + length, "KWLPV1\u0000\u0000")
        .also { for (value in 1..5) it.put(ByteArray(32) { value.toByte() }) }
        .putLong(-1).putLong(-1).putLong(1).putLong(0).putLong(0).putLong(0)
        .putInt(length).put(ByteArray(length) { 99 }).array()
    private fun invalid(action: () -> Unit) = assertFailsWith<KagemushaWalletExceptionV1>(block = action)
    @Test fun metadataPreservesExactOriginalsAndDefensiveCopies() {
        val original = metadata(); val value = KagemushaWalletMetadataV1(original); original.fill(0)
        assertEquals(2, value.assetScale); assertContentEquals(byteArrayOf(11,12), value.accountOriginal())
        value.assetOriginal().fill(0); assertContentEquals(byteArrayOf(21,22,23), value.assetOriginal())
        for (id in listOf(value.schemeId(),value.walletId(),value.assetDigest(),value.accountDigest())) assertContentEquals(ByteArray(32) { 7 }, id)
        assertTrue(value.toString().contains("[REDACTED]"))
    }
    @Test fun metadataRefusesMalformedScopeLengthsAndExtents() {
        for (offset in listOf(0,8,140,144)) { val bytes = metadata(); bytes[offset] = -1; invalid { KagemushaWalletMetadataV1(bytes) } }
        for (offset in listOf(12,44,76,108)) { val bytes = metadata(); bytes.fill(0,offset,offset+32); invalid { KagemushaWalletMetadataV1(bytes) } }
        for (bytes in listOf(byteArrayOf(),metadata().copyOf(149),metadata()+byteArrayOf(0))) invalid { KagemushaWalletMetadataV1(bytes) }
    }
    @Test fun sendReceiveAndOtherFamiliesKeepClosedPeerRoles() {
        val send = KagemushaWalletReleasedOutputV1(released(3,3)); assertEquals(KagemushaWalletTransportKindV1.PAYMENT,send.peerKind)
        assertContentEquals(send.original(),send.peerOriginal()); assertEquals(-1L,send.sequence.high)
        assertEquals(KagemushaWalletTransportKindV1.CREDITED,KagemushaWalletReleasedOutputV1(released(4,4)).peerKind)
        for (kind in listOf(1,2,5,6,7,8)) assertNull(KagemushaWalletReleasedOutputV1(released(kind,0)).peerOriginal())
        for ((kind,peer) in listOf(3 to 4,4 to 3,6 to 3,3 to 0,4 to 0,9 to 0)) invalid { KagemushaWalletReleasedOutputV1(released(kind,peer)) }
    }
    @Test fun releasedRejectsChangedSendTruncatedAndOverlongOriginals() {
        val changed = released(3,3); changed[changed.lastIndex] = 99; invalid { KagemushaWalletReleasedOutputV1(changed) }
        for (bytes in listOf(released(4,4).dropLast(1).toByteArray(),released(4,4)+byteArrayOf(0))) invalid { KagemushaWalletReleasedOutputV1(bytes) }
        val value = KagemushaWalletReleasedOutputV1(released(3,3)); value.original().fill(0); value.peerOriginal()!!.fill(0)
        assertContentEquals(byteArrayOf(11,12),value.original()); assertContentEquals(value.original(),value.peerOriginal())
        assertTrue(value.toString().contains("[REDACTED]"))
    }
    @Test fun preparedLoadPreservesFullBoundAndRequiresExactRequest() {
        val identity = ByteArray(32) { 1 }; val original = load(65_536)
        val value = assertNotNull(KagemushaWalletPreparedLoadV1.observation(original,identity)); original.fill(0)
        assertEquals(65_536,value.instructionOriginal().size); assertEquals(-1L,value.ordinal.high); assertEquals(1L,value.amount.low)
        value.requestId().fill(0); assertContentEquals(identity,value.requestId()); assertEquals("iroha.kagemusha.wallet.ledger.v1",value.wireName)
        invalid { KagemushaWalletPreparedLoadV1.observation(load(),ByteArray(32) { 2 }) }
        invalid { KagemushaWalletPreparedLoadV1.observation(load(65_537),identity) }
        for (offset in listOf(0,8,200,216)) { val bytes = load(); bytes[offset] = -1; invalid { KagemushaWalletPreparedLoadV1.observation(bytes,identity) } }
        val zero = load(); zero[184] = 0; invalid { KagemushaWalletPreparedLoadV1.observation(zero,identity) }
    }
    @Test fun absentLoadIsOnlyItsExactDomainFrame() {
        val id = ByteArray(32) { 1 }; val absent = "KWLNV1\u0000\u0000".toByteArray(Charsets.US_ASCII)
        assertNull(KagemushaWalletPreparedLoadV1.observation(absent,id))
        for (bytes in listOf(byteArrayOf(),absent+byteArrayOf(0),absent.copyOf(7))) invalid { KagemushaWalletPreparedLoadV1.observation(bytes,id) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletPreparedLoadV1.observation(absent,ByteArray(32)) }
    }
    @Test fun replyUsesSeparateDataGeometryAndPreservesNativeFailures() {
        val original = ByteArray(65_756) { 3 }; val value = KagemushaWalletObservationReplyV1(12,-1,0,0,0,0,original); original.fill(0)
        assertEquals(3,value.original(65_756)[0].toInt()); invalid { value.original(20_066) }
        invalid { KagemushaWalletObservationReplyV1(1,-1,0,0,0,0,byteArrayOf(1)) }
        invalid { KagemushaWalletObservationReplyV1(12,-1,0,1,0,0,byteArrayOf(1)) }
        invalid { KagemushaWalletObservationReplyV1(12,-1,0,0,0,0,ByteArray(65_757)) }
        val failure = assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletObservationReplyV1(-2,-1,0,0,0,0,byteArrayOf()).original(5268) }
        assertEquals(-2,failure.status)
    }
}
