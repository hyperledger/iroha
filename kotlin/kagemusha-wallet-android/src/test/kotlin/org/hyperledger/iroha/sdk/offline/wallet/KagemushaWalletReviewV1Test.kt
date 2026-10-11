package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** DATA-only framing/origin tests; no fixture is a Native review or financial grant. */
class KagemushaWalletReviewV1Test {
    private fun data(send: Boolean = true): ByteArray = ByteArray(if(send)498 else 495).also { b ->
        byteArrayOf(75,87,79,82,86,49,0,0).copyInto(b)
        b[8] = if (send) 1 else 8
        for (offset in listOf(9,25,41,57)) for (i in 0..15) b[offset+i] = (i+1).toByte()
        if (send) { b[73]=1; b[74]=2; b[138]=3 }
        for (offset in listOf(106,202,234,266,298,330,362,394)) b[offset]=4
        b[426]=4; b[427]=5
        if(send) { b[491]=3; byteArrayOf(0xa1.toByte(),0xb2.toByte(),0xc3.toByte()).copyInto(b,495) }
    }
    private fun reply(bytes: ByteArray = data(), status: Int=18, token: Long=8, high: Long=0, detail: Int=0) =
        KagemushaWalletReviewReplyV1(status, -1, 0, token, high, detail, bytes)
    private fun rejects(action: () -> Unit) { try { action(); fail("expected refusal") } catch (_: IllegalStateException) {} }
    @Test fun preservesAllUnsignedScalarBitsAndWholeProjection() {
        val bytes=data(); for(i in 9..24) bytes[i]=0xff.toByte()
        val p=KagemushaWalletReviewProjectionV1(bytes)
        assertEquals(KagemushaWalletUInt128V1(-1,-1),p.amount)
        assertArrayEquals(bytes,p.bytes()); assertEquals(KagemushaWalletReviewProjectionV1.Kind.SEND,p.kind)
    }
    @Test fun retainsDefensiveCopiesOfSourceAndEveryGetter() {
        val bytes=data(); val p=KagemushaWalletReviewProjectionV1(bytes); val original=bytes.copyOf()
        bytes.fill(0); p.bytes().fill(0); p.walletId().fill(0); p.paymentPublicKey().fill(0); p.receiverWalletId()!!.fill(0); p.destinationAccountOriginal()!!.fill(0)
        assertArrayEquals(byteArrayOf(0xa1.toByte(),0xb2.toByte(),0xc3.toByte()),p.destinationAccountOriginal())
        assertArrayEquals(original,p.bytes()); assertEquals(4,p.walletId()[0].toInt()); assertEquals(4,p.paymentPublicKey()[0].toInt())
    }
    @Test fun requiresExactLengthMagicSelectorAndHardwareKeyForm() {
        val original=data()
        for(bytes in listOf(original.copyOf(490),original.copyOf(492), original.copyOf().also{it[0]=0}, original.copyOf().also{it[8]=2},original.copyOf().also{it[426]=3})) rejects { KagemushaWalletReviewProjectionV1(bytes) }
    }
    @Test fun sendAndUnloadHaveDifferentBoundReceiverAndRequestShape() {
        rejects { KagemushaWalletReviewProjectionV1(data().also { it[73]=0 }) }
        rejects { KagemushaWalletReviewProjectionV1(data().also { it[170]=1 }) }
        val unload=KagemushaWalletReviewProjectionV1(data(false))
        assertNull(unload.receiverWalletId()); assertNull(unload.destinationAccountOriginal()); assertTrue(unload.requestDigest().all{it==0.toByte()})
        rejects { KagemushaWalletReviewProjectionV1(data(false).also{it[74]=1}) }
    }
    @Test fun accountOriginalLengthIsMandatoryExactAndBounded() {
        val variants = mutableListOf(data().copyOf(491),data().copyOf(495),data()+byteArrayOf(0),data().copyOf(491)+ByteArray(4))
        for(length in listOf(byteArrayOf(2,0,0,0),byteArrayOf(4,0,0,0),byteArrayOf(1,16,0,0),ByteArray(4){0xff.toByte()})) {
            variants += data().also { length.copyInto(it,491) }
        }
        variants += (data(false)+byteArrayOf(7)).also{it[491]=1}
        for(bytes in variants) rejects { KagemushaWalletReviewProjectionV1(bytes) }
        val maximum=data().copyOf(491)+byteArrayOf(0,16,0,0)+ByteArray(4_096){7}
        assertEquals(4_096,KagemushaWalletReviewProjectionV1(maximum).destinationAccountOriginal()!!.size)
    }
    @Test fun rejectsMissingActualSourceBindingsAndZeroAmount() {
        for(offset in listOf(106,202,234,266,298,330,362,394)) rejects { KagemushaWalletReviewProjectionV1(data().also{it.fill(0,offset,offset+32)}) }
        rejects { KagemushaWalletReviewProjectionV1(data().also{it.fill(0,9,25)}) }
    }
    @Test fun dedicatedReviewNeverAcceptsOpenActivationOrMalformedToken() {
        for(status in listOf(0,1,12,13,14,15,16,17,19)) rejects { reply(status=status).review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND) }
        for(r in listOf(reply(token=0),reply(token=-1),reply(high=1),reply(detail=1))) rejects { r.review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND) }
        rejects { reply().review(Any(),KagemushaWalletReviewProjectionV1.Kind.UNLOAD) }
        rejects { KagemushaWalletCallV1(18,-1,0,8,0,0,data()) }
    }
    @Test fun negativeFailureMustCarryNoTokenOrProjection() {
        val failure=KagemushaWalletReviewReplyV1(-4,-1,0,0,0,0,byteArrayOf())
        try { failure.review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND); fail() } catch(e:KagemushaWalletExceptionV1){assertEquals(-4,e.status)}
        rejects { reply(status=-4).review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND) }
    }
    @Test fun foreignOwnerCannotConsumeAndOriginCanConsumeOnlyOnce() {
        val owner=Any(); val review=reply().review(owner,KagemushaWalletReviewProjectionV1.Kind.SEND)
        rejects { review.consume(Any()) }; assertEquals(8L,review.consume(owner)); rejects { review.consume(owner) }
    }
}
