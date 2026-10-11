package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.*
import org.junit.jupiter.api.Test
import org.hyperledger.iroha.sdk.testing.JvmApiInventory

/** FFI projection fixture only; it has no native provider, attestation or qualified proof grant. */
class KagemushaWalletEnrollmentV1Test {
    @Test fun `session originals preserve exact BPNG empty proof and CBSI proof and carry no Android root`() {
        val token = byteArrayOf(1, 2)
        val bpng = KagemushaWalletEnrollmentSessionOriginalsV1(token, byteArrayOf())
        token.fill(0)
        assertEquals(3, bpng.frames().size)
        assertContentEquals(byteArrayOf(1, 2), bpng.frames()[0])
        assertTrue(bpng.frames()[1].isEmpty())
        // Android supplies no attestation root: the KeyMint chain carries its own SPKI-pinned root.
        assertTrue(bpng.frames()[2].isEmpty())
        bpng.frames()[0].fill(0)
        assertContentEquals(byteArrayOf(1, 2), bpng.frames()[0])
        val cbsi = KagemushaWalletEnrollmentSessionOriginalsV1(byteArrayOf(1), byteArrayOf(2))
        assertContentEquals(byteArrayOf(2), cbsi.frames()[1])
        assertTrue(cbsi.frames()[2].isEmpty())
        for (bad in listOf(
            listOf(byteArrayOf(), byteArrayOf()),
            listOf(ByteArray(16_385), byteArrayOf()),
            listOf(byteArrayOf(1), ByteArray(4097)),
        )) assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentSessionOriginalsV1(bad[0], bad[1]) }
        KagemushaWalletEnrollmentSessionOriginalsV1(ByteArray(16_384), ByteArray(4096))
        assertEquals("KagemushaWalletEnrollmentSessionOriginalsV1(originals=[REDACTED])", bpng.toString())
    }
    private class Driver : KagemushaWalletEnrollmentDriverV1 {
        var reply = KagemushaWalletCallV1(18,-1,0,7,0,0,ByteArray(32) { 4 })
        var calls = 0; var closes = 0; var lastSelector = -1; var original = byteArrayOf()
        var closeStatus = 0
        var retainedCertificates = emptyArray<ByteArray>()
        var retainedFrames = emptyList<ByteArray>()
        override fun call(handle: Long, selector: Int, first: ByteArray, second: ByteArray, third: ByteArray, certificates: Array<ByteArray>): KagemushaWalletCallV1 {
            retainedFrames = listOf(first, second, third).map { it.copyOf() }
            assertEquals(7,handle); lastSelector=selector; calls++; original=first.copyOf();first.fill(0)
            retainedCertificates = certificates.map { it.copyOf() }.toTypedArray()
            certificates.forEach { it.fill(0) }; return reply
        }
        override fun close(handle: Long): Int {assertEquals(7,handle);closes++;return closeStatus}
    }
    @Test fun `renewed session keeps exact originals and requires same owner nonmonetary acknowledgement`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7,driver,byteArrayOf(1,2),Any(),2)
        val session = KagemushaWalletEnrollmentSessionOriginalsV1(byteArrayOf(1),byteArrayOf(2))
        driver.reply = KagemushaWalletCallV1(39,-1,0,7,0,0,byteArrayOf())
        owner.renewSession(session)
        assertEquals(19,driver.lastSelector)
        session.frames().zip(driver.retainedFrames).forEach { (expected,actual) -> assertContentEquals(expected,actual) }
        assertTrue(driver.retainedCertificates.isEmpty())
        assertEquals(0,driver.closes)
        assertFailsWith<KagemushaWalletExceptionV1> { driver.reply.completion() }
        for (reply in listOf(KagemushaWalletCallV1(39,-1,0,8,0,0,byteArrayOf()),
            KagemushaWalletCallV1(20,-1,0,7,0,0,byteArrayOf()),
            KagemushaWalletCallV1(-5,17,23,0,0,0,byteArrayOf()))) {
            driver.reply = reply
            assertFailsWith<KagemushaWalletExceptionV1> { owner.renewSession(session) }
        }
        owner.close()
    }
    @Test fun `enrollment projections never become payment completion and retain exact originals`() {
        for ((status,size) in listOf(18 to 32,19 to 161,20 to 0,21 to 0,22 to 0,23 to 32,24 to 131072,25 to 262144,26 to 0,27 to 16384,28 to 1024,58 to 0)) {
            val bytes=ByteArray(size) { 5 };val reply=KagemushaWalletCallV1(status,-1,0,7,0,0,bytes)
            assertFailsWith<KagemushaWalletExceptionV1>{reply.completion()}
            bytes.fill(0);if(size>0)assertEquals(5,reply.bytes()[0].toInt())
            assertFailsWith<KagemushaWalletExceptionV1>{KagemushaWalletCallV1(status,-1,0,0,0,0,reply.bytes())}
        }
        assertFailsWith<KagemushaWalletExceptionV1>{KagemushaWalletCallV1(1,-1,0,0,0,0,ByteArray(10001))}
        assertFailsWith<KagemushaWalletExceptionV1>{KagemushaWalletCallV1(25,-1,0,7,0,0,ByteArray(262145))}
    }
    @Test fun `wrapper copies inputs requires exact projection and closes once`() {
        val driver=Driver();val owner=KagemushaWalletEnrollmentV1(7,driver,byteArrayOf(1,2),Any(),2);val input=byteArrayOf(1,2)
        driver.reply=KagemushaWalletCallV1(27,-1,0,7,0,0,byteArrayOf(6,7))
        assertContentEquals(byteArrayOf(6,7),owner.begin(ByteArray(32){8},input));assertContentEquals(byteArrayOf(1,2),input)
        driver.reply=KagemushaWalletCallV1(18,-1,0,7,0,0,ByteArray(32){4})
        assertContentEquals(ByteArray(32){4},owner.acceptPermit(input))
        val beforePermit=driver.calls
        assertFailsWith<IllegalArgumentException>{owner.acceptPermit(ByteArray(2049))}
        assertFailsWith<IllegalArgumentException>{owner.begin(ByteArray(31),input)}
        assertEquals(beforePermit,driver.calls)
        driver.reply=KagemushaWalletCallV1(20,-1,0,7,0,0,byteArrayOf())
        assertSame(KagemushaWalletEnrollmentProgressV1.Pending,owner.progress())
        assertFailsWith<KagemushaWalletExceptionV1>{owner.retainRequest(ByteArray(64))}
        driver.reply=KagemushaWalletCallV1(24,-1,0,7,0,0,byteArrayOf(9,8,7))
        assertContentEquals(byteArrayOf(9,8,7),assertIs<KagemushaWalletEnrollmentRequestV1.Retained>(owner.prepareRequest(listOf(byteArrayOf(1),byteArrayOf(2)))).bytes())
        // The chain is the whole Android evidence: every other original frame is empty.
        assertEquals(3, driver.lastSelector); assertTrue(driver.retainedFrames.all { it.isEmpty() })
        val before=driver.calls;assertFailsWith<IllegalArgumentException>{owner.acceptCredential(ByteArray(262145))};assertEquals(before,driver.calls)
        driver.reply=KagemushaWalletCallV1(28,-1,0,7,0,0,byteArrayOf(7,8))
        val marker = assertIs<KagemushaWalletEnrollmentAbandonmentV1.Abandonment>(owner.abandon())
        assertContentEquals(byteArrayOf(7,8),marker.frame())
        marker.frame().fill(0); assertContentEquals(byteArrayOf(7,8),marker.frame())
        assertContentEquals(byteArrayOf(7,8),assertIs<KagemushaWalletEnrollmentAbandonmentV1.Abandonment>(owner.abandon()).frame())
        assertEquals(10, driver.lastSelector)
        owner.close();owner.close();assertEquals(1,driver.closes);assertFailsWith<KagemushaWalletExceptionV1>{owner.progress()}
    }
    @Test fun `retained request distinguishes absent original from durable E5`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        driver.reply = KagemushaWalletCallV1(20,-1,0,7,0,0,byteArrayOf())
        assertNull(owner.retainedRequest())
        driver.reply = KagemushaWalletCallV1(24,-1,0,7,0,0,byteArrayOf(4,5,6))
        assertContentEquals(byteArrayOf(4,5,6), owner.retainedRequest())
        owner.close()
    }
    @Test fun `native evidence target fields are immutable exact FFI slices`() {
        val bytes=ByteArray(161){it.toByte()};val target=KagemushaWalletEnrollmentTargetV1(bytes);bytes.fill(0)
        assertEquals(32,target.slot().size);assertEquals(65,target.paymentKey().size)
        assertEquals(97,target.challengeDigest()[0].toInt());assertEquals(129.toByte(),target.keyBindingDigest()[0])
        target.paymentKey().fill(0);assertEquals(32,target.paymentKey()[0].toInt())
    }

    @Test fun `failed enrollment close retains actual owner and fences operations until explicit cleanup`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        driver.closeStatus = -5
        val failure = assertFailsWith<KagemushaWalletExceptionV1> { owner.close() }
        assertFalse(owner.cleanupReleased())
        assertSame(failure, assertFailsWith<KagemushaWalletExceptionV1> { owner.progress() })
        assertSame(failure, assertFailsWith<KagemushaWalletExceptionV1> { owner.close() })
        assertEquals(1, driver.closes)
        driver.closeStatus = 0
        owner.retryCleanup()
        assertTrue(owner.cleanupReleased())
        assertEquals(2, driver.closes)
        owner.close()
        assertEquals(2, driver.closes)
        assertFailsWith<KagemushaWalletExceptionV1> { owner.progress() }
        KagemushaWalletInstalledRuntimeV1.requireNoUnreleasedAdmissions()
    }
    @Test fun `canonical request retains maximum DER originals and rejects bounds before dispatch`() {
        val driver = Driver()
        driver.reply = KagemushaWalletCallV1(23, -1, 0, 7, 0, 0, ByteArray(32) { 1 })
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        // Four maximal certificates fill the 65,536-byte chain bound exactly.
        val maximum = List(4) { certificate -> ByteArray(16384) { index -> ((index + certificate) % 251).toByte() } }
        assertIs<KagemushaWalletEnrollmentRequestV1.AccountChallenge>(owner.prepareRequest(maximum))
        maximum.zip(driver.retainedCertificates).forEach { (expected, actual) -> assertContentEquals(expected, actual) }
        assertIs<KagemushaWalletEnrollmentRequestV1.AccountChallenge>(owner.prepareRequest(List(8) { byteArrayOf(it.toByte()) }))
        val before = driver.calls
        for (bad in listOf(List(9) { byteArrayOf(1) }, listOf(byteArrayOf(1)), emptyList(), listOf(byteArrayOf(), byteArrayOf(1)),
            listOf(byteArrayOf(1), ByteArray(16385)), List(5) { ByteArray(16384) }, List(4) { ByteArray(16384) } + listOf(byteArrayOf(1)))) {
            assertFailsWith<IllegalArgumentException> { owner.prepareRequest(bad) }
        }
        assertEquals(before, driver.calls)
        owner.close()
    }

    @Test fun `abandonment is explicit local or marker and never an inferred outcome`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        driver.reply = KagemushaWalletCallV1(58, -1, 0, 7, 0, 0, byteArrayOf())
        assertSame(KagemushaWalletEnrollmentAbandonmentV1.LocalAbandoned, owner.abandon())
        assertSame(KagemushaWalletEnrollmentAbandonmentV1.LocalAbandoned, owner.abandon())
        driver.reply = KagemushaWalletCallV1(28, -1, 0, 7, 0, 0, ByteArray(1024) { 3 })
        assertEquals(1024, assertIs<KagemushaWalletEnrollmentAbandonmentV1.Abandonment>(owner.abandon()).frame().size)
        // Kind 58 never carries bytes, kind 28 always does, and no other kind is an abandonment.
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(58, -1, 0, 7, 0, 0, byteArrayOf(1)) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(28, -1, 0, 7, 0, 0, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(58, -1, 0, 7, 0, 1, byteArrayOf()) }
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(60, -1, 0, 7, 0, 0, byteArrayOf()) }
        for (reply in listOf(KagemushaWalletCallV1(20, -1, 0, 7, 0, 0, byteArrayOf()), KagemushaWalletCallV1(58, -1, 0, 8, 0, 0, byteArrayOf()),
            KagemushaWalletCallV1(24, -1, 0, 7, 0, 0, byteArrayOf(1)))) {
            driver.reply = reply
            assertFailsWith<KagemushaWalletExceptionV1> { owner.abandon() }
        }
        // A Native refusal (for example once Bootstrap is selected) is preserved, never mapped to a form.
        driver.reply = KagemushaWalletCallV1(-5, 17, 23, 0, 0, 0, byteArrayOf())
        assertEquals(-5, assertFailsWith<KagemushaWalletExceptionV1> { owner.abandon() }.status)
        owner.close()
    }
    @Test fun `abandonment ledger framing keeps local absence and exact retained instruction distinct`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        driver.reply = KagemushaWalletCallV1(58, -1, 0, 7, 0, 0, byteArrayOf())
        assertNull(owner.abandonmentLedgerInstruction())
        assertEquals(20, driver.lastSelector)
        val frame = byteArrayOf(1, 2, 3)
        driver.reply = KagemushaWalletCallV1(59, -1, 0, 7, 0, 0, frame)
        owner.abandonmentLedgerInstruction()!!.fill(0)
        assertContentEquals(frame, owner.abandonmentLedgerInstruction())
        driver.reply = KagemushaWalletCallV1(59, -1, 0, 8, 0, 0, frame)
        assertFailsWith<KagemushaWalletExceptionV1> { owner.abandonmentLedgerInstruction() }
        driver.reply = KagemushaWalletCallV1(28, -1, 0, 7, 0, 0, frame)
        assertFailsWith<KagemushaWalletExceptionV1> { owner.abandonmentLedgerInstruction() }
        for (bytes in listOf(byteArrayOf(), ByteArray(65_537))) {
            assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletCallV1(59, -1, 0, 7, 0, 0, bytes) }
        }
        owner.close()
    }
    @Test fun `canonical JNI enrollment carries only native selector and original frames`() {
        val method = JvmApiInventory.read(KagemushaWalletNativeV1::class.java).methods.single { it.name == "enrollment" && it.isNative }
        assertTrue(method.isStatic)
        assertEquals("(JI[B[B[B[[B)Lorg/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletCallV1;", method.descriptor)
    }
    @Test fun `private chain callback deep copies every bounded DER original`() {
        val one = byteArrayOf(1)
        val certificate = byteArrayOf(7)
        val chain = arrayOf(certificate, certificate)
        val response = KagemushaWalletNativeReplyV1(0, chain = chain)
        certificate.fill(0); response.certificatesDer().forEach { it.fill(0) }
        response.certificatesDer().forEach { assertContentEquals(byteArrayOf(7), it) }
        assertTrue(response.bytes().isEmpty())
        for (make in listOf<() -> KagemushaWalletNativeReplyV1>(
            { KagemushaWalletNativeReplyV1(0, chain = arrayOf(one)) },
            { KagemushaWalletNativeReplyV1(0, chain = Array(9) { one }) },
            { KagemushaWalletNativeReplyV1(0, chain = arrayOf(one, ByteArray(16385))) },
            { KagemushaWalletNativeReplyV1(0, bytes = one, chain = chain) },
            { KagemushaWalletNativeReplyV1(1, chain = chain) },
        )) assertFailsWith<IllegalArgumentException> { make() }
    }
    @Test fun `retained E5 and E6 distinguish original absence refusal and wrong result kind`() {
        val driver = Driver()
        val owner = KagemushaWalletEnrollmentV1(7, driver, byteArrayOf(1,2), Any(), 2)
        for ((selector, present, read) in listOf(
            Triple(16, 24, { owner.retainedRequest() }),
            Triple(18, 25, { owner.retainedResult() })
        )) {
            driver.reply = KagemushaWalletCallV1(20,-1,0,7,0,0,byteArrayOf())
            assertNull(read()); assertEquals(selector, driver.lastSelector)
            val original = byteArrayOf(4,5,6)
            driver.reply = KagemushaWalletCallV1(present,-1,0,7,0,0,original)
            val received = assertNotNull(read()); assertContentEquals(original, received)
            received.fill(0); assertContentEquals(original, read())
            driver.reply = KagemushaWalletCallV1(-5,17,23,0,0,0,byteArrayOf())
            val error = assertFailsWith<KagemushaWalletExceptionV1> { read() }
            assertEquals(-5,error.status); assertEquals(17,error.reason); assertEquals(23,error.platformCode)
            driver.reply = KagemushaWalletCallV1(if(present == 24)25 else 24,-1,0,7,0,0,original)
            assertFailsWith<KagemushaWalletExceptionV1> { read() }
            driver.reply = KagemushaWalletCallV1(present,-1,0,8,0,0,original)
            assertFailsWith<KagemushaWalletExceptionV1> { read() }
        }
        owner.close()
    }

}
