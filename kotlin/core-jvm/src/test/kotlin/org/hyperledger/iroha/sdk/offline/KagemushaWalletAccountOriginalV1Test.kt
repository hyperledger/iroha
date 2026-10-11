package org.hyperledger.iroha.sdk.offline

import java.io.File
import org.hyperledger.iroha.sdk.client.JsonParser
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class KagemushaWalletAccountOriginalV1Test {
    private fun vectors(): List<Map<*, *>> {
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }
            .map { File(it, "fixtures/account/multisig_wire_v1.json") }.first(File::isFile)
        val root = JsonParser.parse(file.readText()) as Map<*, *>
        assertEquals("iroha.account.multisig-wire.v1", root["schema"])
        return (root["positive"] as List<*>).map { it as Map<*, *> }
    }
    private fun hex(value: Any?): ByteArray = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun exactRustAccountFramesRenderAndReencodeUnderSelectedNetwork() {
        var admitted = 0
        for (vector in vectors()) {
            val original = hex(vector["account_id_frame_hex"])
            val literal = vector["i105"] as String
            if (original.size > 4_096) {
                assertFailsWith<IllegalArgumentException> { KagemushaWalletAccountOriginalV1.decode(original, 753) }
                assertFailsWith<IllegalArgumentException> { KagemushaWalletAccountOriginalV1.encode(literal) }
            } else {
                assertEquals(literal, KagemushaWalletAccountOriginalV1.decode(original, 753), vector["name"] as String)
                assertContentEquals(original, KagemushaWalletAccountOriginalV1.encode(literal))
                admitted++
            }
        }
        assertTrue(admitted > 0)
    }

    @Test fun malformedHeadersTruncationTrailingBytesAndCompressionAreRefused() {
        val original = hex(vectors().first { hex(it["account_id_frame_hex"]).size <= 4_096 }["account_id_frame_hex"])
        val invalid = listOf(ByteArray(0), ByteArray(4_097), original.copyOf(original.size - 1),
            original + byteArrayOf(0), original.copyOf().apply { this[6] = (this[6].toInt() xor 1).toByte() },
            original.copyOf().apply { this[22] = 1 },
            original.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
        for (bytes in invalid) assertFailsWith<IllegalArgumentException> {
            KagemushaWalletAccountOriginalV1.decode(bytes, 753)
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletAccountOriginalV1.decode(original, -1) }
    }
}
