package org.hyperledger.iroha.sdk.client

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.crypto.IrohaHash

/** Original Native program frame DATA and the producer's exact domain commitments. */
internal object RamLfeExecuteConsistencyV1 {
    class Commitments(val output: String, val opaque: String, val receipt: String, val associated: String)
    fun upperHex(value: String, bytes: Int?, field: String): ByteArray {
        require(value.isNotEmpty() && value.length % 2 == 0 && (bytes == null || value.length == bytes * 2) && value.all { it in '0'..'9' || it in 'A'..'F' }) { "$field must contain exact uppercase bare hex" }
        return ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
    fun programFrame(value: String): ByteArray {
        require(value.length <= 8192) { "ram-lfe execute response.program_id_canonical exceeds 4096 bytes" }
        return upperHex(value, null, "ram-lfe execute response.program_id_canonical")
    }
    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    fun commitments(program: ByteArray, output: String): Commitments {
        val raw = upperHex(output, 32, "ram-lfe execute response.opaque_output")
        val outputHash = IrohaHash.prehash("iroha.ram_lfe.output_hash.v1".toByteArray(StandardCharsets.UTF_8) + raw)
        val opaque = IrohaHash.prehash("iroha.ram_lfe.identifier.opaque_hash.v1".toByteArray(StandardCharsets.UTF_8) + program + outputHash)
        val receipt = IrohaHash.prehash("iroha.ram_lfe.identifier.receipt_hash.v1".toByteArray(StandardCharsets.UTF_8) + program + outputHash + opaque)
        return Commitments(hex(outputHash), hex(opaque), hex(receipt), hex(IrohaHash.prehash(program)))
    }
}
