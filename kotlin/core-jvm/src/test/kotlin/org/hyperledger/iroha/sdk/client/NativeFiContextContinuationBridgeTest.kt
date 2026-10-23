package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.security.MessageDigest
import org.hyperledger.iroha.sdk.core.model.NetworkId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Native-output shape fixtures only; certified continuation positives live in the Rust suite. */
class NativeFiContextContinuationBridgeTest {
    private val request="{}".toByteArray()
    private val wire=byteArrayOf(1,2,3)
    private val entrypoint=ByteArray(32){0x33}
    private val height=BigInteger("9007199254740993")
    private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun hex(bytes:ByteArray)=bytes.joinToString(""){"%02x".format(it.toInt() and 255)}
    private fun trust()=NativeFiContextAssertionTrust(NetworkId.fromBytes(ByteArray(32){0x11}),"chain",
        ByteArray(32){0x22},height,ByteArray(32){0x33},"native-owner",ByteArray(32){0x44},ByteArray(32){0x55},
        "demo-fi",null,ByteArray(32){0x66},"owner-key",request,sha(request),NativeFiLinkApprovalTarget(
            "native-asset","native-wallet","native-fi",ByteArray(32){0x77},BigInteger.ONE,BigInteger.ONE,
            BigInteger.ONE,BigInteger.ONE,false,null,false,false))
    private fun fields():Map<String,Any?> = mapOf("schema" to "iroha.fi-assertion-original.admitted.v1",
        "requestSha256" to hex(sha(request)),"assertionEntrypointHash" to hex(entrypoint),
        "assertionWireSha256" to hex(sha(wire)),"originalCheckpointHeight" to height.toString(),
        "originalCheckpointBlockHash" to "55".repeat(32))
    private fun admitted(values:Map<String,Any?> = fields(),signed:ByteArray=wire,raw:ByteArray=request,
        hash:ByteArray=entrypoint,digest:ByteArray=sha(wire))=AdmittedFiAssertionOriginal.fromNative(
        JsonEncoder.encode(values).toByteArray(),signed,raw,trust(),hash,digest)
    private fun cursor(at:BigInteger=height+BigInteger.ONE)=VerifiedFiCheckpointSelection.fromNativeJSON(
        JsonEncoder.encode(mapOf("height" to at.toString(),"context_id" to "33".repeat(32),
            "block_hash" to "55".repeat(32))).toByteArray())

    @Test fun admissionRetainsExactOriginalAndStatusIdentityWithDefensiveCopies() {
        val signed=wire.copyOf();val raw=request.copyOf();val value=admitted(signed=signed,raw=raw)
        signed.fill(0);raw.fill(0);value.signedWire.fill(0);value.originalRequest.fill(0)
        assertContentEquals(wire,value.signedWire);assertContentEquals(request,value.originalRequest)
        assertEquals(height,value.originalCheckpointHeight);assertEquals(hex(entrypoint),value.assertionEntrypointHashHex)
    }

    @Test fun admissionRejectsSubstitutionCoercionUnknownKeysAndNoncanonicalMetadata() {
        for (bad in listOf(fields()+mapOf("snapshot" to "invented"),fields()-"assertionWireSha256",
            fields()+mapOf("originalCheckpointHeight" to 2),fields()+mapOf("originalCheckpointHeight" to "0$height"),
            fields()+mapOf("assertionEntrypointHash" to "22".repeat(32)),
            fields()+mapOf("requestSha256" to "AA".repeat(32)))) assertFails {admitted(bad)}
        assertFails {admitted(signed=byteArrayOf(3,2,1))}
        assertFails {admitted(raw="{\"changed\":true}".toByteArray())}
        assertFails {admitted(hash=ByteArray(32){0x55})}
        assertFails {admitted(digest=ByteArray(32){0x55})}
        assertFails {AdmittedFiAssertionOriginal.fromNative(ByteArray(2049),wire,request,trust(),entrypoint,sha(wire))}
    }

    @Test fun continuationKeepsOriginalPinsAndCursorSelectionDistinctAndLossless() {
        val cp=byteArrayOf(9,8,7);val digest=sha(cp)
        val original=trust();val value=NativeFiContextContinuationTrust(original,cursor(),digest)
        val expected=value.bytes();digest.fill(0);value.bytes().fill(0)
        assertContentEquals(expected,value.bytes());value.checkCursorBytes(cp)
        val objectValue=JsonParser.parse(String(expected,Charsets.UTF_8)) as Map<*,*>
        assertEquals(setOf("schema","original","cursor"),objectValue.keys)
        assertEquals(JsonParser.parse(String(original.canonicalBytes(),Charsets.UTF_8)),objectValue["original"])
        assertEquals((height+BigInteger.ONE).toString(),(objectValue["cursor"] as Map<*,*>)["checkpointHeight"])
        assertFails {value.checkCursorBytes(byteArrayOf(1))}
        assertFails {NativeFiContextContinuationTrust(original,cursor(height-BigInteger.ONE),sha(cp))}
    }

    @Test fun boundAndDigestFailuresPrecedeNativeDispatch() {
        fun call(signed:ByteArray=wire,raw:ByteArray=request,entry:ByteArray=entrypoint,digest:ByteArray=sha(wire))=
            NativeFiContextContinuationBridge.admitFiAssertionOriginalV1(signed,raw,byteArrayOf(1),trust(),entry,digest)
        assertFailsWith<IllegalArgumentException>{call(signed=ByteArray(65537))}
        assertFailsWith<IllegalArgumentException>{call(raw=ByteArray(65537))}
        assertFailsWith<IllegalArgumentException>{call(entry=ByteArray(33))}
        assertFailsWith<IllegalArgumentException>{call(digest=ByteArray(32){0x55})}
        assertFailsWith<IllegalArgumentException>{call(raw="changed".toByteArray())}
    }

    @Test fun realJniRefusesMalformedAdmissionAndContinuationWithoutGrantingAuthority() {
        assertTrue(NativeFiContextContinuationBridge.isNativeAvailable(),"Requires qualified continuation JNI")
        assertFailsWith<IllegalArgumentException>{NativeFiContextContinuationBridge.admitFiAssertionOriginalV1(
            wire,request,byteArrayOf(1),trust(),entrypoint,sha(wire))}
        val cp=byteArrayOf(1)
        val selection=NativeFiContextContinuationTrust(trust(),cursor(),sha(cp))
        assertFailsWith<IllegalArgumentException>{NativeFiContextContinuationBridge.verifyFiContextContinuationV1(
            byteArrayOf(1),admitted(),cp,cp,selection)}
    }
}
