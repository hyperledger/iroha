package org.hyperledger.iroha.samples.attestationprobe

import java.security.KeyPairGenerator
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProbeEncodingTest {
    @Test
    fun challengeIsExactly32BytesAndRejectsAmbiguousInput() {
        val hex = "00".repeat(31) + "aF"
        val bytes = ProbeEncoding.challenge(hex)
        assertEquals(32, bytes.size)
        assertEquals(hex.lowercase(), ProbeEncoding.hex(bytes))
        listOf("", "00".repeat(31), "00".repeat(33), "gg".repeat(32), " " + "00".repeat(32)).forEach {
            assertThrows(IllegalArgumentException::class.java) { ProbeEncoding.challenge(it) }
        }
    }

    @Test
    fun pemPreservesGeneratedSpkiAndUsesBoundedLines() {
        val spki = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().public.encoded
        val lines = ProbeEncoding.pem("PUBLIC KEY", spki).trim().lines()
        assertEquals("-----BEGIN PUBLIC KEY-----", lines.first())
        assertEquals("-----END PUBLIC KEY-----", lines.last())
        val body = lines.drop(1).dropLast(1)
        assertEquals(true, body.all { it.length <= 64 })
        assertArrayEquals(spki, Base64.getDecoder().decode(body.joinToString("")))
    }

    @Test
    fun sha256UsesCertificateDigestConvention() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", ProbeEncoding.sha256("abc".toByteArray()))
    }
}
