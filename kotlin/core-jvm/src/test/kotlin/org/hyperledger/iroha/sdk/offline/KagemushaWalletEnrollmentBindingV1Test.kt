// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test

/** Cross-language fixed vectors from the actual Python E1 verifier and Rust-written wire fixture. */
class KagemushaWalletEnrollmentBindingV1Test {
    @Test fun `exact Python E1 challenge and key binding digests`() {
        val selected = KagemushaWalletEnrollmentBindingV1(transcript(), generator())
        assertContentEquals(hex("9ee9b71a3026e333f8c69d1c5f338bdf8639fbd85644730be5bf5a3bdaf53682"), selected.challengeDigest())
        assertContentEquals(hex("b4129d2396a72c9288160f28f26f1fc63f6935b8512a37fd722cc2aa5859454e"), selected.enrollmentKeyBinding())
    }

    @Test fun `Rust canonical challenge fixture agrees with actual Python enrollment binding`() {
        val fixture = Paths.get("..", "..", "fixtures", "kagemusha", "wallet_v1_vectors.json")
        val vectors = Json.parseToJsonElement(String(Files.readAllBytes(fixture), Charsets.UTF_8)).jsonObject
        val challenge = vectors.getValue("digests").jsonArray.map { it.jsonObject }
            .single { it.getValue("role").jsonPrimitive.content == "enrollment-challenge" }
        val key = vectors.getValue("keys").jsonArray.map { it.jsonObject }
            .single { it.getValue("name").jsonPrimitive.content == "payer_payment" }
        val selected = KagemushaWalletEnrollmentBindingV1(
            hex(challenge.getValue("body_hex").jsonPrimitive.content),
            hex(key.getValue("public_key_hex").jsonPrimitive.content),
        )
        assertContentEquals(hex(challenge.getValue("digest_hex").jsonPrimitive.content), selected.challengeDigest())
        // Rust vectors_tests.rs supplies the payer enrollment-id body (challenge digest || key).
        // Reframed for enrollment-key-binding and independently checked with Python WalletEnrollmentScope.
        assertContentEquals(hex("3aac630d33df2f64c8bc18e5465630588b8b8cfddf536c5ec2e26cff3765b9c2"), selected.enrollmentKeyBinding())
    }

    @Test fun `reject wrong extent version and every zero E1 binding`() {
        for (size in listOf(0, 32, 193, 195, 385)) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentBindingV1(ByteArray(size), generator()) }
        }
        for (index in 0..1) {
            val wrong = transcript().also { it[index] = 2 }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentBindingV1(wrong, generator()) }
        }
        for (offset in 2 until 194 step 32) {
            val wrong = transcript().also { it.fill(0, offset, offset + 32) }
            assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentBindingV1(wrong, generator()) }
        }
    }

    @Test fun `reject compressed malformed and off curve payment keys`() {
        val malformed = listOf(ByteArray(0), ByteArray(33), ByteArray(64), ByteArray(66),
            generator().also { it[0] = 2 }, ByteArray(65).also { it[0] = 4 },
            generator().also { it.fill(0xff.toByte(), 1, 33) })
        for (key in malformed) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletEnrollmentBindingV1(transcript(), key) }
        }
    }

    @Test fun `each E1 field and exact payment key affect the key binding`() {
        val selected = KagemushaWalletEnrollmentBindingV1(transcript(), generator())
        for (offset in 2 until 194 step 32) {
            val different = KagemushaWalletEnrollmentBindingV1(transcript().also { it[offset] = 7 }, generator())
            assertFalse(selected.challengeDigest().contentEquals(different.challengeDigest()))
            assertFalse(selected.enrollmentKeyBinding().contentEquals(different.enrollmentKeyBinding()))
        }
        val otherKey = hex("049a65173d48a0a0c706eeec2a75ae1f56793be988b2d407e9a7d3aba7574a9ea5101daceaadf42b661543a353e4f505ec41281df8535fecc5912ea39ed6b50568")
        val different = KagemushaWalletEnrollmentBindingV1(transcript(), otherKey)
        assertContentEquals(selected.challengeDigest(), different.challengeDigest())
        assertFalse(selected.enrollmentKeyBinding().contentEquals(different.enrollmentKeyBinding()))
    }

    @Test fun `inputs and returned digests cannot change retained binding`() {
        val transcript = transcript()
        val key = generator()
        val selected = KagemushaWalletEnrollmentBindingV1(transcript, key)
        transcript.fill(0); key.fill(0)
        selected.challengeDigest().fill(0); selected.enrollmentKeyBinding().fill(0)
        assertContentEquals(hex("b4129d2396a72c9288160f28f26f1fc63f6935b8512a37fd722cc2aa5859454e"), selected.enrollmentKeyBinding())
        assertTrue(selected.challengeDigest().any { it != 0.toByte() })
        assertEquals("KagemushaWalletEnrollmentBindingV1(binding=[REDACTED])", selected.toString())
    }

    private fun transcript(): ByteArray = byteArrayOf(1, 0) + (1..6).flatMap { value -> List(32) { value.toByte() } }.toByteArray()
    private fun generator(): ByteArray = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
