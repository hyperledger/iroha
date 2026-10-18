// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.offline.KagemushaWalletEnrollmentRefusalV1
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

/** Actual host JNI boundary checks; no installed monetary provider or phone qualification. */
@Tag("host-native")
class KagemushaWalletHostNativeV1Test {
    @TempDir lateinit var directory: File

    @BeforeEach
    fun requireCurrentNativeBridge() {
        assertTrue(NativeSignerBridge.isNativeAvailable(), "The supplied ABI-30 native bridge must load")
        assertEquals(1, KagemushaWalletNativeV1.revision())
    }

    @Test
    fun theKotlinRefusalTableIsExactlyNativesClosedTable() {
        // Native owns the closed design §2.4 table; the SDK relays codes unchanged. Every code,
        // including zero, unknown and platform-inapplicable ones, agrees for both platforms.
        for (android in listOf(true, false)) {
            for (code in (-1..300) + listOf(65_535, 65_536, Int.MAX_VALUE, Int.MIN_VALUE)) {
                val reason = KagemushaWalletEnrollmentRefusalV1.fromCode(code)?.takeIf { it.appliesTo(android) }
                val expected = reason?.let { it.holderClass.ordinal + 1 } ?: -1
                assertEquals(expected, KagemushaWalletNativeV1.enrollmentRefusal(code, android), "code $code android $android")
            }
        }
    }

    @Test
    fun registrationRelocationCallsActualJniAndRefusesMalformedOriginalData() {
        val error = assertFailsWith<KagemushaWalletExceptionV1> {
            KagemushaWalletInstallationOriginalsV1.relocateRegistrationSource(byteArrayOf(1), directory.absolutePath)
        }
        assertEquals(-1, error.status)
        assertTrue(directory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun loadOriginalHeightOutputUsesActualJniAndClearsRefusedData() {
        val id = ByteArray(32) { 1 }
        fun validate(output: LongArray, receipt: ByteArray = byteArrayOf(1),
            finality: ByteArray = byteArrayOf(2)) =
            KagemushaWalletLoadOriginalNativeV1.validate(id, id, id,
                "not-a-canonical-account".toByteArray(Charsets.UTF_8), receipt, finality, output)
        for (length in listOf(0, 2)) {
            val output = LongArray(length) { 37 }
            assertEquals(-1, validate(output))
            assertTrue(output.all { it == 37L })
        }
        val output = longArrayOf(37)
        assertEquals(-1, validate(output))
        assertEquals(0L, output[0])
        output[0] = 41
        assertEquals(-1, validate(output, receipt = ByteArray(513)))
        assertEquals(0L, output[0])
        output[0] = 43
        assertEquals(-1, validate(output, finality = ByteArray(256 * 1024 + 1)))
        assertEquals(0L, output[0])
    }

    @Test
    fun epochSetupUsesActualJniAndRejectsMalformedInputsBeforeOwnerLookup() {
        fun call(selector: Int, low: Long = 0, high: Long = 0, token: Long = 0,
            identity: ByteArray = ByteArray(32), first: ByteArray = byteArrayOf(),
            second: ByteArray = byteArrayOf(), third: ByteArray = byteArrayOf()) =
            assertNotNull(KagemushaWalletNativeV1.setup(0, identity, selector, low, high,
                token, first, second, third))
        for (reply in listOf(call(52), call(53, first = byteArrayOf(1)),
            call(53, low = -1, first = byteArrayOf(1)))) {
            assertEquals(-2, reply.status)
            assertTrue(reply.bytes().isEmpty())
        }
        val malformed = listOf(
            call(52, low = 1), call(52, first = byteArrayOf(1)),
            call(53), call(53, high = 1, first = byteArrayOf(1)),
            call(53, token = 1, first = byteArrayOf(1)),
            call(53, identity = ByteArray(32) { 1 }, first = byteArrayOf(1)),
            call(53, first = ByteArray(256 * 1024 + 1)),
            call(53, first = byteArrayOf(1), second = byteArrayOf(1)),
            call(53, first = byteArrayOf(1), third = byteArrayOf(1)),
        )
        for (reply in malformed) {
            assertEquals(-1, reply.status)
            assertTrue(reply.bytes().isEmpty())
        }
    }

    @Test
    fun unloadSetupUsesActualJniAndNeverInventsACompletedClaim() {
        val id = ByteArray(32) { 9 }
        fun call(identity: ByteArray = id, beneficiary: ByteArray = byteArrayOf(), token: Long = 0) =
            assertNotNull(KagemushaWalletNativeV1.setup(0, identity, 45, 0, 0, token,
                beneficiary, byteArrayOf(), byteArrayOf()))
        val unknown = call()
        assertEquals(-2, unknown.status)
        assertEquals(-1, unknown.reason)
        assertEquals(0, unknown.platformCode)
        assertTrue(unknown.bytes().isEmpty())
        for (invalid in listOf(call(ByteArray(32)), call(beneficiary = ByteArray(16_385)), call(token = 1))) {
            assertEquals(-1, invalid.status)
            assertTrue(invalid.bytes().isEmpty())
        }
    }

    @Test
    fun unavailableArtifactsNeverOpenAnOwnerOrMutateCustody() {
        val keys = TestKeyStoreV1()
        val platform = KagemushaWalletAndroidPlatformV1.create(TestEnvironmentV1(directory), keys)
        fun files() = directory.walkTopDown().filter { it.isFile }
            .associate { it.relativeTo(directory).path to it.readBytes().toList() }
        val before = files()
        val probes = keys.getKeyCalls
        val id = ByteArray(32) { 1 }
        repeat(2) {
            val error = assertFailsWith<KagemushaWalletExceptionV1> {
                KagemushaWalletRuntimeV1(Long.MAX_VALUE, Any()).begin(KagemushaWalletOpenOriginalsV1(id, id, id, id))
            }
            assertEquals(KagemushaWalletExceptionV1.ARTIFACTS_UNAVAILABLE, error.status)
        }
        assertEquals(before, files())
        assertEquals(probes, keys.getKeyCalls)
        assertTrue(keys.generated.isEmpty())
        assertEquals(0, keys.signCalls)
        assertEquals(0, keys.deleteCalls)
    }

    @Test
    fun unknownHandlesReturnExactFailureObjectsAndNeverCompletionBytes() {
        val id = ByteArray(32) { 1 }
        for (operation in 1..5) {
            val first = if (operation == 1 || operation == 4 || operation == 5) id else byteArrayOf()
            val second = if (operation == 4) id else byteArrayOf()
            val reply = assertNotNull(KagemushaWalletNativeV1.call(0, operation, first, second))
            assertEquals(-2, reply.status)
            assertEquals(-1, reply.reason)
            assertEquals(0, reply.platformCode)
            assertTrue(reply.bytes().isEmpty())
        }
        val execute = assertNotNull(KagemushaWalletNativeV1.execute(0, id, 9, 0, 0, byteArrayOf(), byteArrayOf(), byteArrayOf()))
        assertEquals(-2, execute.status)
        assertTrue(execute.bytes().isEmpty())
        val snapshot = assertNotNull(KagemushaWalletNativeV1.snapshot(0))
        assertEquals(-2, snapshot.status)
        assertEquals(-1, snapshot.reason)
        assertEquals(0, snapshot.platformCode)
        assertFailsWith<KagemushaWalletExceptionV1> { KagemushaWalletSnapshotV1(snapshot) }
        assertEquals(-2, KagemushaWalletNativeV1.close(0))
        assertEquals(-2, KagemushaWalletNativeV1.activity(0, 1, 0))
        assertEquals(-1, KagemushaWalletNativeV1.activity(0, 2, 0))
    }

    @Test
    fun malformedNativeCallsRejectBeforeUnknownHandleLookup() {
        val id = ByteArray(32) { 1 }
        val platform = KagemushaWalletAndroidPlatformV1.create(TestEnvironmentV1(directory), TestKeyStoreV1())
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.openBegin(0, byteArrayOf(), id, id, id)).status)
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.openBegin(0, id, id, ByteArray(4097), id)).status)
        assertEquals(-4, assertNotNull(KagemushaWalletNativeV1.openFinish(0, ByteArray(64))).status)
        assertEquals(-4, KagemushaWalletNativeV1.openCancel(0))
        val cases = listOf(
            Triple(0, byteArrayOf(), byteArrayOf()),
            Triple(1, ByteArray(31), byteArrayOf()),
            Triple(2, byteArrayOf(1), byteArrayOf()),
            Triple(3, byteArrayOf(), byteArrayOf(1)),
            Triple(4, ByteArray(31), id),
            Triple(4, id, ByteArray(31)),
            Triple(99, byteArrayOf(), byteArrayOf()),
        )
        for (selector in 0..10) {
            val reply = assertNotNull(KagemushaWalletNativeV1.execute(0, id, selector, 0, 0,
                ByteArray(2_228_737), byteArrayOf(), byteArrayOf()))
            assertEquals(-1, reply.status)
            assertTrue(reply.bytes().isEmpty())
        }
        for ((operation, first, second) in cases) {
            val reply = assertNotNull(KagemushaWalletNativeV1.call(0, operation, first, second))
            assertEquals(-1, reply.status)
            assertEquals(-1, reply.reason)
            assertEquals(0, reply.platformCode)
            assertTrue(reply.bytes().isEmpty())
        }
    }

    @Test
    fun enrollmentOriginalsRequireNativeProvisioningAndBoundsPrecedeLookup() {
        fun enrollment(selector: Int, first: ByteArray = byteArrayOf(), second: ByteArray = byteArrayOf(),
            third: ByteArray = byteArrayOf(), certificates: Array<ByteArray> = emptyArray()) =
            assertNotNull(KagemushaWalletNativeV1.enrollment(Long.MAX_VALUE, selector, first, second, third, certificates))
        val id = ByteArray(32) { 1 }
        val originals = listOf(
            enrollment(0, id, id, id), enrollment(1, ByteArray(64)), enrollment(2),
            // Android E5 is the KeyMint chain only (2-8 certificates); no token rides along.
            enrollment(3, certificates = arrayOf(byteArrayOf(2), byteArrayOf(3))),
            enrollment(3, certificates = Array(4) { ByteArray(16384) { 7 } }),
            enrollment(4, id, byteArrayOf(1), byteArrayOf(2)), enrollment(5, ByteArray(64)),
            enrollment(6, byteArrayOf(1)), enrollment(7), enrollment(8), enrollment(9, byteArrayOf(1)), enrollment(10),
        )
        for (reply in originals) {
            assertEquals(-4, reply.status)
            assertEquals(-1, reply.reason)
            assertEquals(0, reply.platformCode)
            assertTrue(reply.bytes().isEmpty())
        }
        val malformed = listOf(
            enrollment(0, ByteArray(33), id, id), enrollment(1, ByteArray(65)),
            enrollment(2, byteArrayOf(1)), enrollment(3, ByteArray(65537)),
            // A retired Play Integrity token, a short, long or oversized chain are refused.
            enrollment(3, byteArrayOf(1), certificates = arrayOf(byteArrayOf(2), byteArrayOf(3))),
            enrollment(3, certificates = arrayOf(byteArrayOf(2))),
            enrollment(3, certificates = Array(9) { byteArrayOf(1) }),
            enrollment(3, certificates = arrayOf(byteArrayOf(2), ByteArray(16385))),
            enrollment(3, certificates = Array(5) { ByteArray(16384) { 7 } }),
            enrollment(4, id, byteArrayOf(1), ByteArray(4097)),
            enrollment(10, byteArrayOf(1)), enrollment(9, ByteArray(2049)), enrollment(6, ByteArray(262145)), enrollment(7, byteArrayOf(1)), enrollment(99),
        )
        for (reply in malformed) {
            assertEquals(-1, reply.status)
            assertTrue(reply.bytes().isEmpty())
        }
    }
    @Test
    fun realReviewJniReturnsSeparateFailuresWithoutAdmittingUnknownOwners() {
        val id = ByteArray(32) { 1 }
        // Both required original slots must pass the shape gate before the unknown owner.
        val reply = assertNotNull(KagemushaWalletNativeV1.review(0, 1, 0, 0, byteArrayOf(1), byteArrayOf(2)))
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.review(0, 1, 0, 0, byteArrayOf(1), byteArrayOf())).status)
        assertEquals(-2, reply.status); assertEquals(-1, reply.reason); assertEquals(0, reply.platformCode)
        // Strict negative Review parsing checks every private zero token/high/detail/bytes
        // field. A malformed negative reply yields INVALID_NATIVE_OUTPUT rather than -2.
        assertTrue(reply.cleanupToken()==null)
        val refusal=assertFailsWith<KagemushaWalletExceptionV1> {
            reply.review(Any(),KagemushaWalletReviewProjectionV1.Kind.SEND)
        }
        assertEquals(-2,refusal.status)
        for (selector in listOf(0, 2, 9, 99)) {
            assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.review(0, selector, 0, 0, byteArrayOf(1), byteArrayOf())).status)
        }
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.review(0, 1, 1, 0, byteArrayOf(1), byteArrayOf())).status)
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.review(0, 1, 0, 0, ByteArray(10_001), byteArrayOf())).status)
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.review(0, 8, 1, 0, byteArrayOf(1), byteArrayOf())).status)
        val execution = assertNotNull(KagemushaWalletNativeV1.executeReviewed(0, 1, id))
        assertEquals(-2, execution.status); assertTrue(execution.bytes().isEmpty())
        assertEquals(-1, assertNotNull(KagemushaWalletNativeV1.executeReviewed(0, 1, ByteArray(31))).status)
        assertEquals(-2, KagemushaWalletNativeV1.discardReview(0, 1))
    }

}
