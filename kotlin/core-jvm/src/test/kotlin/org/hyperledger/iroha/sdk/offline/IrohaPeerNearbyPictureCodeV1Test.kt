// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.util.Random
import java.nio.file.Files
import java.nio.file.Paths
import org.hyperledger.iroha.sdk.client.JsonParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Nearby pairing by picture, byte for byte with the Swift tests (`fixtures/kagemusha/nearby_picture_v1.json`). */
class IrohaPeerNearbyPictureCodeV1Test {
    private val vectors: Map<*, *> = run {
        val root = generateSequence(Paths.get("").toAbsolutePath()) { it.parent }
            .first { Files.isRegularFile(it.resolve("fixtures/kagemusha/nearby_picture_v1.json")) }
        val parsed = JsonParser.parse(String(Files.readAllBytes(root.resolve("fixtures/kagemusha/nearby_picture_v1.json")), Charsets.UTF_8)) as Map<*, *>
        assertEquals(2, (parsed["fixture_version"] as Number).toInt())
        parsed["nearby_picture"] as Map<*, *>
    }
    private val count = IrohaPeerNearbyPictureCodeV1.PICTURE_COUNT
    private val size = IrohaPeerNearbyPictureCodeV1.GRID_SIZE

    @Test
    fun `both phones derive the shared picture from the pairing token`() {
        assertEquals(16, count)
        assertEquals(6, size)
        assertEquals((vectors["picture_count"] as Number).toInt(), count)
        assertEquals((vectors["grid_size"] as Number).toInt(), size)
        val pictures = (vectors["vectors"] as List<*>).map { it as Map<*, *> }
        assertEquals(12, pictures.size)
        for (vector in pictures) {
            val token = vector["token"] as String
            assertTrue(IrohaPeerNearbyPairingTokenV1.isValid(token), token)
            assertEquals((vector["index"] as Number).toInt(), IrohaPeerNearbyPictureCodeV1.targetIndex(token), token)
        }
    }

    @Test
    fun `android rebuilds the token iOS Nearby passes from the raw verification string`() {
        val tokens = (vectors["token_vectors"] as List<*>).map { it as Map<*, *> }
        assertEquals(6, tokens.size)
        for (vector in tokens) {
            val hex = vector["raw_hex"] as String
            val raw = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            assertEquals(32, raw.size, hex)
            assertEquals(vector["token"] as String, IrohaPeerNearbyPairingTokenV1.fromRawAuthenticationToken(raw), hex)
        }
        // Fewer than four raw bytes cannot fill five characters.
        assertEquals("AQID", IrohaPeerNearbyPairingTokenV1.fromRawAuthenticationToken(byteArrayOf(1, 2, 3)))
        assertEquals(false, IrohaPeerNearbyPairingTokenV1.isValid(IrohaPeerNearbyPairingTokenV1.fromRawAuthenticationToken(byteArrayOf(1, 2, 3))))
        assertEquals("", IrohaPeerNearbyPairingTokenV1.fromRawAuthenticationToken(ByteArray(0)))
    }

    @Test
    fun `text outside the pairing token rule is refused`() {
        val invalid = (vectors["invalid_tokens"] as List<*>).map { it as String }
        assertEquals(13, invalid.size)
        assertTrue("1234" in invalid, "Android's retired authentication digits")
        for (token in invalid + listOf("ABCD\u0000", "AB\u0000CD", " ABCD", "ABCD ", "ABC\u200BD", "K7Q2f")) {
            assertEquals(false, IrohaPeerNearbyPairingTokenV1.isValid(token), token)
            assertFailsWith<IllegalArgumentException>(token) { IrohaPeerNearbyPictureCodeV1.targetIndex(token) }
        }
        for (character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") {
            val token = character.toString().repeat(IrohaPeerNearbyPairingTokenV1.LENGTH)
            assertTrue(IrohaPeerNearbyPictureCodeV1.targetIndex(token) in 0 until count, token)
        }
    }

    @Test
    fun `the receiver grid holds the target and five other distinct pictures in random order`() {
        val orders = HashSet<List<Int>>()
        for (target in 0 until count) {
            val positions = BooleanArray(size)
            val seen = BooleanArray(count)
            for (seed in 0L until 200L) {
                val grid = IrohaPeerNearbyPictureCodeV1.grid(target, Random(seed))
                assertEquals(size, grid.size)
                assertEquals(size, grid.toSet().size)
                assertTrue(grid.all { it in 0 until count })
                assertTrue(target in grid)
                positions[grid.indexOf(target)] = true
                grid.forEach { seen[it] = true }
                if (target == 0) orders += grid
            }
            // Over these seeds the target takes every position and every other picture appears.
            assertTrue(positions.all { it }, "positions of $target")
            assertTrue(seen.all { it }, "pictures around $target")
        }
        assertTrue(orders.size > 1)
        assertEquals(IrohaPeerNearbyPictureCodeV1.grid(3, Random(7)), IrohaPeerNearbyPictureCodeV1.grid(3, Random(7)))
        // The default source is SecureRandom.
        val secure = IrohaPeerNearbyPictureCodeV1.grid(9)
        assertEquals(size, secure.toSet().size)
        assertTrue(9 in secure)
        for (target in listOf(-1, count)) {
            assertFailsWith<IllegalArgumentException>("$target") { IrohaPeerNearbyPictureCodeV1.grid(target) }
        }
    }
}
