package org.hyperledger.iroha.sdk.offline

import kotlin.test.assertEquals
import kotlin.test.assertFails
import org.junit.jupiter.api.Test

class KagemushaWalletArtifactTransportV1Test {
    private val raw = "11".repeat(32)
    private val stored = "aa".repeat(32)
    private fun row(rawDigest: String = raw) =
        "{\"bytes\":8000,\"sha256\":\"$rawDigest\",\"storedBytes\":27,\"storedSha256\":\"$stored\"}"
    private fun frame(rows: String = row()) =
        "{\"schema\":\"${KagemushaWalletArtifactTransportV1.SCHEMA}\",\"encoding\":\"zstd\",\"walletOriginals\":[$rows]}\n"
    private fun decode(text: String) = KagemushaWalletArtifactTransportV1.decode(text.toByteArray())

    @Test fun `preserves distinct decoded and stored identities`() {
        assertEquals(listOf(KagemushaWalletArtifactExtentV1(8000, raw, 27, stored)), decode(frame()))
        assertEquals(2, decode(frame(row() + "," + row("22".repeat(32)))).size)
    }

    @Test fun `rejects raw carriers duplicate keys and noncanonical representations`() {
        val original = frame()
        for (bad in listOf(original.replace("\"encoding\":\"zstd\",", ""),
            original.replace("zstd", "gzip"), original.replace("\"encoding\":", "\"encoding\":\"zstd\",\"encoding\":"),
            original.trimEnd(), " $original", original.replace("8000", "8e3"),
            original.replace("8000", "8000.0"), original.replace("8000", "true"),
            original.replace("\"storedBytes\":27", "\"storedBytes\":\"27\""),
            original.replace("]}", "],\"finalityOriginals\":[]}"),
            original.replace("{\"bytes\":", "{\"unknown\":0,\"bytes\":"))) {
            assertFails(bad) { decode(bad) }
        }
    }

    @Test fun `rejects invalid lengths hashes and row ordering`() {
        val original = frame()
        for (bad in listOf(original.replace("8000", "0"), original.replace("8000", "1073741825"),
            original.replace("\"storedBytes\":27", "\"storedBytes\":0"),
            original.replace("\"storedBytes\":27", "\"storedBytes\":1077936129"),
            original.replace(stored, stored.uppercase()), original.replace(stored, "00".repeat(32)),
            original.replace(raw, "../" + "a".repeat(61)), frame(""), frame(row() + "," + row()),
            frame(row("22".repeat(32)) + "," + row()))) assertFails(bad) { decode(bad) }
        assertFails { decode(frame(List(12289) { row() }.joinToString(","))) }
    }

    @Test fun `accepts exact extent bounds and refuses truncated UTF8`() {
        val row = decode(frame().replace("8000", "1073741824").replace("\"storedBytes\":27", "\"storedBytes\":1077936128")).single()
        assertEquals(KagemushaWalletArtifactTransportV1.MAX_RAW_BYTES, row.rawBytes)
        assertEquals(KagemushaWalletArtifactTransportV1.MAX_STORED_BYTES, row.storedBytes)
        assertFails { KagemushaWalletArtifactTransportV1.decode(byteArrayOf(0xc3.toByte())) }
    }

    @Test fun rejectsExcessiveDepthAndNodesBeforeMaterializingJson() {
        for (value in listOf("[".repeat(50000) + "0" + "]".repeat(50000),
            "[" + List(100000) { "0" }.joinToString(",") + "]",
            "[" + List(12291) { "{}" }.joinToString(",") + "]")) {
            assertFails { KagemushaWalletArtifactTransportV1.decode(value.toByteArray()) }
        }
    }
    @Test fun acceptsMaximumCanonicalRowCount() {
        val rows = (1..12288).joinToString(",") { row(it.toString(16).padStart(64, '0')) }
        assertEquals(12288, decode(frame(rows)).size)
    }

}
