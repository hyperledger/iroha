// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** Exact owned DATA contracts only. No wallet, Native admission or financial fixture is faked. */
class KagemushaWalletInstalledHolderV1Test {
    private fun runtime(inputs: List<ByteArray> = List(6) { byteArrayOf(7) }, root: String = "/selected/originals") =
        KagemushaWalletInstallationOriginalsV1(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], root.toByteArray(Charsets.UTF_8), byteArrayOf())
    @Test fun `runtime and enrollment bytes survive source and accessor mutation`() {
        val bytes = ByteArray(2) { 7 }
        val r = runtime(List(6) { bytes })
        val e = KagemushaWalletOpenOriginalsV1(bytes, bytes, bytes, bytes)
        bytes[0] = 0; r.frames()[0][1] = 0; e.frames()[0][1] = 0
        r.frames().take(6).forEach { assertContentEquals(byteArrayOf(7, 7), it) }
        e.frames().forEach { assertContentEquals(byteArrayOf(7, 7), it) }
        assertTrue(r.toString().contains("[REDACTED]"))
    }
    @Test fun `signed base without financial originals remains available for native authentication`() {
        val originals = listOf(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(), byteArrayOf(), byteArrayOf(4))
        val retained = runtime(originals, "").frames()
        originals.forEachIndexed { index, bytes -> assertContentEquals(bytes, retained[index]) }
        assertTrue(retained[6].isEmpty())
    }
    @Test fun `required signed metadata cannot be absent`() {
        for (i in 0..5) {
            val inputs = MutableList(6) { byteArrayOf(7) }; inputs[i] = byteArrayOf()
            assertFailsWith<IllegalArgumentException> { runtime(inputs) }
        }
    }
    @Test fun `all six runtime boundaries precede native installation`() {
        val caps = intArrayOf(8_388_608, 2048, 131_072, 16_842_752, 16_777_216, 67_108_864)
        for (i in caps.indices) {
            val inputs = MutableList(6) { byteArrayOf(7) }; inputs[i] = ByteArray(caps[i] + 1)
            assertFailsWith<IllegalArgumentException> { runtime(inputs) }
        }
    }
    @Test fun `retained financial root bytes are copied and independently bounded`() {
        val value=runtime(root="/検証");assertContentEquals("/検証".toByteArray(Charsets.UTF_8),value.frames()[6])
        assertFailsWith<IllegalArgumentException>{runtime(root="")}
        assertFailsWith<IllegalArgumentException>{runtime(root="/"+"x".repeat(4096))}
    }
    @Test fun `every enrollment original is required and independently finite`() {
        val caps = intArrayOf(1024, 10_000, 4096, 1024)
        for (i in caps.indices) for (bad in listOf(byteArrayOf(), ByteArray(caps[i] + 1))) {
            val inputs = MutableList(4) { byteArrayOf(7) }; inputs[i] = bad
            assertFailsWith<IllegalArgumentException> { KagemushaWalletOpenOriginalsV1(inputs[0], inputs[1], inputs[2], inputs[3]) }
        }
    }
}
