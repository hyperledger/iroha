// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline

import java.util.Collections
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonArray
import org.hyperledger.iroha.sdk.json.JsonNumber
import org.hyperledger.iroha.sdk.json.JsonObject
import org.hyperledger.iroha.sdk.json.JsonString

/** One immutable encoded original. Native authenticates the stored and decoded identities. */
data class KagemushaWalletArtifactExtentV1(
    val rawBytes: Long,
    val rawSha256: String,
    val storedBytes: Long,
    val storedSha256: String,
)

/** Bounded delivery metadata only; parsing never grants proof or wallet admission. */
object KagemushaWalletArtifactTransportV1 {
    const val MAX_BYTES: Int = 32 * 1024 * 1024
    const val MAX_RAW_BYTES: Long = 1024L * 1024 * 1024
    const val MAX_STORED_BYTES: Long = MAX_RAW_BYTES + 4 * 1024 * 1024
    const val SCHEMA: String = "iroha.kagemusha.wallet-artifact-original-transport.v1"

    /** Decode the sole canonical zstd transport, rejecting raw and noncanonical forms. */
    @JvmStatic fun decode(original: ByteArray): List<KagemushaWalletArtifactExtentV1> {
        require(original.size in 1..MAX_BYTES)
        preflight(original)
        val body = Json.parse(original) as? JsonObject ?: error("transport object required")
        require(body.keys == setOf("schema", "encoding", "walletOriginals"))
        require((body["schema"] as? JsonString)?.value == SCHEMA)
        require((body["encoding"] as? JsonString)?.value == "zstd")
        val rows = body["walletOriginals"] as? JsonArray ?: error("original rows required")
        require(rows.size in 1..12288)
        fun digest(row: JsonObject, key: String): String {
            val value = (row[key] as? JsonString)?.value ?: error("digest string required")
            require(value.matches(Regex("[0-9a-f]{64}")) && value.any { it != '0' })
            return value
        }
        fun length(row: JsonObject, key: String, maximum: Long): Long {
            val value = (row[key] as? JsonNumber)?.text ?: error("integer length required")
            require(value.matches(Regex("[1-9][0-9]*")))
            return requireNotNull(value.toLongOrNull()).also { require(it in 1..maximum) }
        }
        val canonical = StringBuilder("{\"schema\":\"$SCHEMA\",\"encoding\":\"zstd\",\"walletOriginals\":[")
        var previous = ""
        val result = rows.items.mapIndexed { index, value ->
            val row = value as? JsonObject ?: error("original object required")
            require(row.keys == setOf("bytes", "sha256", "storedBytes", "storedSha256"))
            val extent = KagemushaWalletArtifactExtentV1(length(row, "bytes", MAX_RAW_BYTES),
                digest(row, "sha256"), length(row, "storedBytes", MAX_STORED_BYTES), digest(row, "storedSha256"))
            require(extent.rawSha256 > previous) { "original digests must be unique and sorted" }
            previous = extent.rawSha256
            if (index > 0) canonical.append(',')
            canonical.append("{\"bytes\":${extent.rawBytes},\"sha256\":\"${extent.rawSha256}\",\"storedBytes\":${extent.storedBytes},\"storedSha256\":\"${extent.storedSha256}\"}")
            extent
        }
        canonical.append("]}\n")
        require(original.contentEquals(canonical.toString().toByteArray(Charsets.UTF_8))) { "noncanonical transport" }
        return Collections.unmodifiableList(result)
    }

    /** Bound structure allocation before the generic JSON parser creates any objects. */
    private fun preflight(original: ByteArray) {
        var quoted = false
        var depth = 0
        var containers = 0
        var separators = 0
        original.forEach { byte ->
            val character = byte.toInt() and 0xff
            // Canonical field names, schema and hex digests never need JSON escaping.
            require(character != 92) { "escaped transport string" }
            if (character == 34) quoted = !quoted
            else if (!quoted) when (character) {
                123, 91 -> { depth++; containers++; require(depth <= 4 && containers <= 12290) }
                125, 93 -> { depth--; require(depth >= 0) }
                44, 58 -> { separators++; require(separators <= 8 * 12288 + 4) }
            }
        }
        require(!quoted && depth == 0)
    }

}
