// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Nearby pairing by picture, byte for byte with the Swift tests (`fixtures/kagemusha/peer_ask_v1.json`). */
class IrohaPeerNearbyPictureCodeV1Test {
    private val vectors = IrohaPeerAskTestVectorsV1.section("nearby_picture")
    private val count = IrohaPeerNearbyPictureCodeV1.PICTURE_COUNT
    private val size = IrohaPeerNearbyPictureCodeV1.GRID_SIZE

    @Test
    fun `both phones derive the shared picture from the authentication digits`() {
        assertEquals(16, count)
        assertEquals(6, size)
        assertEquals((vectors["picture_count"] as Number).toInt(), count)
        assertEquals((vectors["grid_size"] as Number).toInt(), size)
        val pictures = IrohaPeerAskTestVectorsV1.list("vectors", vectors)
        assertEquals(10, pictures.size)
        for (vector in pictures) {
            val digits = vector["digits"] as String
            assertEquals((vector["index"] as Number).toInt(), IrohaPeerNearbyPictureCodeV1.targetIndex(digits), digits)
        }
    }

    @Test
    fun `digits outside the verification code rule are refused`() {
        val invalid = (vectors["invalid_digits"] as List<*>).map { it as String }
        assertEquals(6, invalid.size)
        for (digits in invalid + listOf("12345678901234", "+1234", "1234\u0000", "１２３４")) {
            assertFailsWith<IllegalArgumentException>(digits) { IrohaPeerNearbyPictureCodeV1.targetIndex(digits) }
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
