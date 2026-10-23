package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.core.model.NetworkId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Serialization fixtures only; the C suite separately exercises genuine certified execution. */
class NativeFiContextAssertionBridgeTest {
    private val network = NetworkId.fromBytes(ByteArray(32) { 0x11 })
    private val original = "{}".toByteArray()
    private val digest = MessageDigest.getInstance("SHA-256").digest(original)
    private fun target(reference: ByteArray = ByteArray(32) { 0x22 }, revision: BigInteger = BigInteger.ONE,
        controller: String? = null, waterfall: Boolean = false) = NativeFiLinkApprovalTarget(
        "native-validates-asset", "native-validates-wallet", "native-validates-fi", reference,
        BigInteger("9007199254740993"), BigInteger.ONE, revision, BigInteger.ONE,
        true, controller, waterfall, false)
    private fun trust(requestDigest: ByteArray = digest, scope: ByteArray = original,
        height: BigInteger = BigInteger.valueOf(2), selected: NativeFiLinkApprovalTarget = target()) =
        NativeFiContextAssertionTrust(network, "chain", ByteArray(32) { 0x33 }, height,
            ByteArray(32) { 0x55 }, "native-validates-owner", ByteArray(32) { 0x66 },
            ByteArray(32) { 0x77 }, "fixture-fi", null, ByteArray(32) { 0x22 },
            "protected-key-lease", scope, requestDigest, selected)
    private fun snapshot() = JsonEncoder.encode(mapOf(
        "asset_definition_id" to "native-validates-asset", "asset_incarnation" to "66".repeat(32),
        "account_id" to "native-validates-wallet", "uid" to "77".repeat(32),
        "fi_account_id" to "native-validates-fi", "reference_digest" to "22".repeat(32),
        "binding" to null, "policy" to null, "fi" to null, "attestation" to null,
        "link" to mapOf("revision" to BigInteger("18446744073709551615")), "controller" to null,
    )).toByteArray()
    private fun output(snapshot: ByteArray = snapshot()): Map<String, Any?> = mapOf(
        "schema" to "iroha.fi-context-assertion.verified.v1", "requestSha256" to "22".repeat(32),
        "blockHash" to "33".repeat(32), "blockHeight" to "9007199254740993",
        "blockCreationTimeMs" to "18446744073709551615",
        "snapshotJsonBase64" to Base64.getEncoder().encodeToString(snapshot))
    private fun bytes(value: Map<String, Any?>) = JsonEncoder.encode(value).toByteArray()

    @Test fun localTrustRetainsExplicitDigestFullTargetAndCanonicalScopeWithDefensiveCopies() {
        val reference = ByteArray(32) { 0x22 }; val requestDigest = digest.copyOf(); val scope = original.copyOf()
        val selected = target(reference); val value = trust(requestDigest, scope, selected = selected)
        val retained = value.canonicalBytes()
        reference.fill(0); requestDigest.fill(0); scope.fill(0)
        selected.referenceDigest.fill(0); value.canonicalBytes().fill(0)
        assertContentEquals(retained, value.canonicalBytes())
        assertContentEquals(ByteArray(32) { 0x22 }, selected.referenceDigest)
        val fields = JsonParser.parse(String(retained, Charsets.UTF_8)) as Map<*, *>
        assertEquals(19, fields.size)
        assertEquals("2", fields["checkpointHeight"])
        assertEquals("{}", fields["walletScopeCanonical"])
        assertEquals(JsonEncoder.encode(selected.fields()), JsonEncoder.encode(fields["target"]))
        assertEquals(value.requestSha256Hex, fields["requestSha256"])
        assertEquals("9007199254740993", (fields["target"] as Map<*, *>)["fiRevision"].toString())
    }

    @Test fun localTrustRejectsInvalidBoundsNoncanonicalScopeAndUnsupportedCapabilities() {
        for (bad in listOf(ByteArray(31), ByteArray(33), ByteArray(32))) assertFails { trust(requestDigest = bad) }
        for (bad in listOf("", " {}", "{\"x\":1,\"x\":2}", "[]", "x".repeat(16385))) {
            assertFails { trust(scope = bad.toByteArray()) }
        }
        for (bad in listOf(BigInteger.ZERO, BigInteger.ONE.shiftLeft(64) - BigInteger.ONE, BigInteger.ONE.shiftLeft(64))) {
            assertFails { trust(height = bad) }
        }
        assertFails { target(waterfall = true) }
        assertFails { trust(selected = target(controller = "unselected-controller")) }
        assertFails { target(revision = BigInteger.ZERO) }
        assertFails { target(revision = BigInteger.ONE.shiftLeft(64)) }
        assertEquals(BigInteger.ONE.shiftLeft(64) - BigInteger.ONE,
            target(revision = BigInteger.ONE.shiftLeft(64) - BigInteger.ONE).revision)
    }

    @Test fun nativeOutputDecoderRetainsLosslessSnapshotOriginalAndCopiesWithoutGrantingProofAuthority() {
        val expected = snapshot(); val supplied = bytes(output(expected))
        val value = VerifiedFiContextAssertion.fromNativeJSON(supplied)
        supplied.fill(0); value.snapshotJson.fill(0); value.blockHash.fill(0); value.requestSha256.fill(0)
        assertContentEquals(expected, value.snapshotJson)
        assertEquals(BigInteger("9007199254740993"), value.blockHeight)
        assertEquals(BigInteger("18446744073709551615"), value.blockCreationTimeMs)
        assertEquals("33".repeat(32), value.blockHashHex)
        assertEquals("22".repeat(32), value.requestSha256Hex)
    }

    @Test fun nativeOutputRejectsUnknownMissingDuplicateCoercedFieldsAndNoncanonicalSnapshotEncoding() {
        val valid = output()
        val invalid = listOf(valid + ("unknown" to null), valid - "blockHash",
            valid + ("blockHeight" to 3), valid + ("blockCreationTimeMs" to "01"),
            valid + ("blockHash" to "22".repeat(32)), valid + ("requestSha256" to "AA".repeat(32)),
            valid + ("snapshotJsonBase64" to "e30"), valid + ("snapshotJsonBase64" to "e30=\n"),
            output("{}".toByteArray()), output(byteArrayOf(0xc3.toByte(), 0x28)))
        invalid.forEach { assertFails { VerifiedFiContextAssertion.fromNativeJSON(bytes(it)) } }
        assertFails { VerifiedFiContextAssertion.fromNativeJSON(bytes(valid).toString(Charsets.UTF_8)
            .replace("{", "{\"schema\":\"duplicate\",").toByteArray()) }
        for (bad in listOf(byteArrayOf(), ByteArray(512 * 1024 + 1), byteArrayOf(0xff.toByte()))) {
            assertFails { VerifiedFiContextAssertion.fromNativeJSON(bad) }
        }
    }

    @Test fun requestDigestAndInputBoundsFailBeforeNativeInvocation() {
        fun verify(proof: ByteArray = byteArrayOf(1), request: ByteArray = original,
            checkpoint: ByteArray = byteArrayOf(1), selected: NativeFiContextAssertionTrust = trust()) =
            NativeFiContextAssertionBridge.verifyFiContextAssertionV1(proof, request, checkpoint, selected)
        assertFailsWith<IllegalArgumentException> { verify(proof = byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { verify(proof = ByteArray(512 * 1024 + 1)) }
        assertFailsWith<IllegalArgumentException> { verify(request = ByteArray(64 * 1024 + 1)) }
        assertFailsWith<IllegalArgumentException> { verify(checkpoint = byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { verify(request = "{\"changed\":true}".toByteArray()) }
        assertFailsWith<IllegalArgumentException> { verify(selected = trust(requestDigest = ByteArray(32) { 7 })) }
    }

    @Test fun realJniRejectsMalformedCandidateEvenWithMatchingLocallyRetainedRequestDigest() {
        assertTrue(NativeFiContextAssertionBridge.isNativeAvailable(), "Requires qualified FI context JNI producer")
        assertFailsWith<IllegalArgumentException> {
            NativeFiContextAssertionBridge.verifyFiContextAssertionV1(byteArrayOf(1, 2), original, byteArrayOf(3, 4), trust())
        }
    }
}
