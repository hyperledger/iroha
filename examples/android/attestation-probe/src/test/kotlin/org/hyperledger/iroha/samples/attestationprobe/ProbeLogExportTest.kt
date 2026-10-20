package org.hyperledger.iroha.samples.attestationprobe

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeLogExportTest {
    @Test
    fun publicBytesRoundTripAcrossBoundedIndexedChunks() {
        val bytes = ByteArray(4097) { (it % 251).toByte() }
        val lines = ProbeLogExport.lines("capture-123", bytes)
        val metadata = "id=capture-123 bytes=${bytes.size} sha256=${ProbeEncoding.sha256(bytes)} chunks=${lines.size - 2}"
        assertEquals("IROHA_ATTESTATION BEGIN $metadata", lines.first())
        assertEquals("IROHA_ATTESTATION END $metadata", lines.last())
        val body = lines.drop(1).dropLast(1).mapIndexed { index, line ->
            val prefix = "IROHA_ATTESTATION CHUNK id=capture-123 index=$index data="
            assertTrue(line.startsWith(prefix))
            line.removePrefix(prefix).also { assertTrue(it.length <= ProbeLogExport.CHUNK_CHARACTERS) }
        }.joinToString("")
        assertArrayEquals(bytes, Base64.getDecoder().decode(body))
    }

    @Test
    fun exportRejectsOversizeEmptyAndInvalidIds() {
        assertThrows(IllegalArgumentException::class.java) { ProbeLogExport.lines("x", ByteArray(0)) }
        assertThrows(IllegalArgumentException::class.java) {
            ProbeLogExport.lines("x", ByteArray(ProbeLogExport.MAX_ZIP_BYTES + 1))
        }
        listOf("../file", "x\nBEGIN", "x".repeat(81)).forEach {
            assertThrows(IllegalArgumentException::class.java) { ProbeLogExport.lines(it, byteArrayOf(1)) }
        }
        assertEquals(294, ProbeLogExport.lines("x", ByteArray(ProbeLogExport.MAX_ZIP_BYTES)).size)
    }

    @Test
    fun errorMessagesExcludeExceptionDetailsAndStayBounded() {
        val line = ProbeLogExport.error("capture\n".repeat(100), IllegalStateException("PRIVATE DETAILS"))
        assertTrue(line.length < 180)
        assertTrue(!line.contains("PRIVATE") && !line.contains("\n"))
        assertTrue(line.endsWith("kind=IllegalStateException"))
    }
}
