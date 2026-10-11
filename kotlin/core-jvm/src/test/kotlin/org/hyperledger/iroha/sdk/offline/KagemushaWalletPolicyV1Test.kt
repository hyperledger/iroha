// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1PolicyV1
import org.hyperledger.iroha.sdk.crypto.keystore.attestation.AndroidAttestationE1RootV1
import org.hyperledger.iroha.sdk.norito.CRC64
import org.junit.jupiter.api.Test

/** Byte agreement with the Rust Model's shared policy vectors; DATA only, no approval. */
class KagemushaWalletPolicyV1Test {
    private val cases: List<JsonObject> by lazy {
        val fixture = Paths.get("..", "..", "fixtures", "kagemusha", "wallet_enrollment_policy_v1_vectors.json")
        Json.parseToJsonElement(String(Files.readAllBytes(fixture), Charsets.UTF_8)).jsonObject
            .getValue("cases").jsonArray.map { it.jsonObject }
    }

    private fun case(name: String) = cases.single { it.getValue("name").jsonPrimitive.content == name }
    private fun JsonObject.hex(key: String): ByteArray = decodeHex(getValue(key).jsonPrimitive.content)

    @Test fun `every shared vector decodes re-encodes and reproduces its transcript and digest`() {
        assertEquals(setOf("android", "apple", "android_maximal", "apple_maximal"), cases.map { it.getValue("name").jsonPrimitive.content }.toSet())
        for (vector in cases) {
            val appFrame = vector.hex("app_policy_frame_hex")
            val app = KagemushaWalletAppPolicyV1.decodeCanonical(appFrame)
            assertContentEquals(appFrame, app.encodeCanonical())
            assertContentEquals(vector.hex("app_policy_transcript_hex"), app.transcript())
            assertContentEquals(vector.hex("app_policy_digest_hex"), app.policyDigest())
            val enrollmentFrame = vector.hex("enrollment_policy_frame_hex")
            val enrollment = KagemushaWalletEnrollmentPolicyV1.decodeCanonical(enrollmentFrame)
            assertContentEquals(enrollmentFrame, enrollment.encodeCanonical())
            assertContentEquals(vector.hex("enrollment_policy_transcript_hex"), enrollment.transcript())
            assertContentEquals(vector.hex("enrollment_policy_digest_hex"), enrollment.policyDigest())
            assertContentEquals(app.policyDigest(), enrollment.appPolicyDigest())
            // The frame checksum is the Norito CRC64 of the payload.
            assertEquals(CRC64.compute(appFrame.copyOfRange(40, appFrame.size)),
                java.nio.ByteBuffer.wrap(appFrame, 31, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long)
        }
    }

    @Test fun `the maximal Android and Apple policies fit the 1024-byte frame cap`() {
        for (name in listOf("android_maximal", "apple_maximal")) {
            val vector = case(name)
            assertTrue(vector.hex("app_policy_frame_hex").size <= 1024, name)
            assertTrue(vector.hex("enrollment_policy_frame_hex").size <= 1024, name)
        }
        val maximal = KagemushaWalletAppPolicyV1.decodeCanonical(case("android_maximal").hex("app_policy_frame_hex"))
        val android = assertIs<KagemushaWalletAppPolicyV1.Identity.Android>(maximal.identity)
        assertEquals(255, android.packageName.length)
        assertEquals(4, android.signerSet().size)
        assertEquals(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE), android.minimumPackageVersion)
        assertEquals(431, maximal.transcript().size)
        val enrollment = KagemushaWalletEnrollmentPolicyV1.decodeCanonical(case("android_maximal").hex("enrollment_policy_frame_hex"))
        assertEquals(572, enrollment.transcript().size)
        assertEquals(8, assertIs<KagemushaWalletEnrollmentPolicyV1.Platform.Android>(enrollment.platform).roots().size)
        assertEquals(167, KagemushaWalletEnrollmentPolicyV1.decodeCanonical(case("apple").hex("enrollment_policy_frame_hex")).transcript().size)
        assertTrue(KagemushaWalletAppPolicyV1.decodeCanonical(case("apple_maximal").hex("app_policy_frame_hex")).transcript().size <= 294)
    }

    @Test fun `Android admission inputs come from the paired originals`() {
        val vector = case("android")
        val policy = AndroidAttestationE1PolicyV1.fromPolicyOriginals(vector.hex("app_policy_frame_hex"), vector.hex("enrollment_policy_frame_hex"))
        assertEquals("org.example.wallet", policy.packageName)
        assertEquals(BigInteger.valueOf(7), policy.minimumPackageVersion)
        assertContentEquals(ByteArray(32) { 5 }, policy.signerSet().single())
        val root = policy.roots().single()
        assertEquals(AndroidAttestationE1RootV1.Family.GOOGLE_RSA, root.family)
        assertNull(root.adapterId)
        assertContentEquals(ByteArray(32) { 4 }, root.spkiSha256())
        val maximal = case("android_maximal")
        val vendors = AndroidAttestationE1PolicyV1.fromPolicyOriginals(maximal.hex("app_policy_frame_hex"), maximal.hex("enrollment_policy_frame_hex")).roots()
        assertEquals((1..8).map { "vendor-00000000$it" }, vendors.map { it.adapterId })
        assertTrue(vendors.all { it.family == AndroidAttestationE1RootV1.Family.VENDOR })
    }

    @Test fun `substituted pairs and platforms are refused`() {
        val android = case("android")
        val apple = case("apple")
        val maximal = case("android_maximal")
        // The enrollment policy names a different app-policy digest.
        assertFailsWith<IllegalArgumentException> {
            AndroidAttestationE1PolicyV1.fromPolicyOriginals(maximal.hex("app_policy_frame_hex"), android.hex("enrollment_policy_frame_hex"))
        }
        // Apple policies carry no Android admission inputs.
        assertFailsWith<IllegalArgumentException> {
            AndroidAttestationE1PolicyV1.fromPolicyOriginals(apple.hex("app_policy_frame_hex"), apple.hex("enrollment_policy_frame_hex"))
        }
        // Frames are not interchangeable between the two policy types.
        assertFailsWith<IllegalArgumentException> { KagemushaWalletAppPolicyV1.decodeCanonical(android.hex("enrollment_policy_frame_hex")) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentPolicyV1.decodeCanonical(android.hex("app_policy_frame_hex")) }
    }

    @Test fun `every single-byte mutation, truncation and extension of a frame is refused`() {
        for (vector in cases) {
            for (key in listOf("app_policy_frame_hex", "enrollment_policy_frame_hex")) {
                val frame = vector.hex(key)
                val decode: (ByteArray) -> Any = if (key.startsWith("app")) KagemushaWalletAppPolicyV1::decodeCanonical
                    else KagemushaWalletEnrollmentPolicyV1::decodeCanonical
                decode(frame)
                for (index in frame.indices) {
                    val mutated = frame.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }
                    assertFailsWith<Exception>("$key byte $index") { decode(mutated) }
                }
                assertFailsWith<Exception> { decode(frame.copyOf(frame.size - 1)) }
                assertFailsWith<Exception> { decode(frame + 0) }
                assertFailsWith<Exception> { decode(ByteArray(1025)) }
            }
        }
    }

    @Test fun `semantic rules of the Model are enforced after canonical decoding`() {
        // A frame re-encoded from altered fields with a correct checksum is still invalid.
        val vector = case("android")
        val frame = vector.hex("enrollment_policy_frame_hex")
        val payload = frame.copyOfRange(40, frame.size)
        // Patch floor 202608 -> 202613 (month 13): rewrite the u32 and the checksum.
        val floor = byteArrayOf(0x70, 0x17, 0x03, 0x00)
        val at = indexOf(payload, floor)
        val altered = payload.copyOf().also { it[at] = 0x75 }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentPolicyV1.decodeCanonical(withPayload(frame, altered)) }
        // Zero challenge lifetime.
        val lifetime = byteArrayOf(0xc0.toByte(), 0xd4.toByte(), 0x01, 0, 0, 0, 0, 0)
        val zero = payload.copyOf().also { val i = indexOf(payload, lifetime); for (k in 0 until 8) it[i + k] = 0 }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentPolicyV1.decodeCanonical(withPayload(frame, zero)) }
        // The unaltered payload under a rebuilt header still decodes.
        KagemushaWalletEnrollmentPolicyV1.decodeCanonical(withPayload(frame, payload))
    }

    private fun withPayload(frame: ByteArray, payload: ByteArray): ByteArray {
        val header = frame.copyOfRange(0, 40)
        val checksum = CRC64.compute(payload)
        for (index in 0 until 8) header[31 + index] = (checksum ushr (8 * index)).toByte()
        return header + payload
    }

    private fun indexOf(data: ByteArray, needle: ByteArray): Int =
        (0..data.size - needle.size).first { start -> needle.indices.all { data[start + it] == needle[it] } }

    private fun decodeHex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
