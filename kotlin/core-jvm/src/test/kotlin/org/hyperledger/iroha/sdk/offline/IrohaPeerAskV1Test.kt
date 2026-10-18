// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline

import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.JsonParser

/** The receiver's ask (`IAK1`), byte for byte with the Swift tests (`fixtures/kagemusha/peer_ask_v1.json`). */
class IrohaPeerAskV1Test {
    private val vectors = IrohaPeerAskTestVectorsV1

    @Test
    fun `shared asks encode decode and render their vectors`() {
        assertEquals(IrohaPeerAskV1.RECORD_BYTES, (vectors.section("ask_record")["bytes"] as Number).toInt())
        assertEquals(56, IrohaPeerAskV1.RECORD_BYTES)
        assertEquals("IAK1:", IrohaPeerAskV1.TEXT_PREFIX)
        val asks = vectors.list("asks")
        assertEquals(5, asks.size)
        for (vector in asks) {
            val name = vector["name"] as String
            val amount = BigInteger(vector["amount_decimal"] as String)
            val digest = vectors.hex(vector["account_digest_hex"])
            val record = vectors.hex(vector["record_hex"])
            val text = vector["text"] as String
            val ask = IrohaPeerAskV1.of(amount, digest)
            assertContentEquals(record, ask.encode(), name)
            assertContentEquals(vectors.hex(vector["amount_le128_hex"]), record.copyOfRange(8, 24), name)
            assertEquals(text, ask.toText(), name)
            assertEquals(90, text.length, name)
            assertEquals(vector["check_code"], ask.checkCode, name)
            assertEquals(KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest), ask.checkCode, name)
            assertEquals(amount, ask.amount, name)
            assertContentEquals(digest, ask.receiverAccountDigest, name)
            val decoded = IrohaPeerAskV1.decode(record)
            assertEquals(ask, decoded, name)
            assertEquals(ask.hashCode(), decoded.hashCode(), name)
            assertEquals(ask, IrohaPeerAskV1.fromText(text), name)
        }
    }

    @Test
    fun `asks keep defensive copies and do not render their amount`() {
        val vector = vectors.list("asks").first()
        val digest = vectors.hex(vector["account_digest_hex"])
        val ask = IrohaPeerAskV1.of(BigInteger.ONE, digest)
        digest.fill(0)
        ask.receiverAccountDigest.fill(0)
        ask.encode().fill(0)
        assertContentEquals(vectors.hex(vector["account_digest_hex"]), ask.receiverAccountDigest)
        assertContentEquals(vectors.hex(vector["record_hex"]), ask.encode())
        assertEquals("IrohaPeerAskV1(KAGEMUSHA_WALLET_V1)", ask.toString())
    }

    @Test
    fun `construction requires a positive 128-bit amount and one nonzero digest`() {
        val digest = ByteArray(32) { 1 }
        val maximum = BigInteger.ONE.shiftLeft(128) - BigInteger.ONE
        assertEquals(maximum, IrohaPeerAskV1.of(maximum, digest).amount)
        for (amount in listOf(BigInteger.ZERO, BigInteger.ONE.negate(), BigInteger.ONE.shiftLeft(128))) {
            assertFailsWith<IllegalArgumentException>(amount.toString()) { IrohaPeerAskV1.of(amount, digest) }
        }
        for (invalid in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            assertFailsWith<IllegalArgumentException>("digest ${invalid.size}") { IrohaPeerAskV1.of(BigInteger.ONE, invalid) }
        }
    }

    @Test
    fun `every invalid record is refused`() {
        val invalid = vectors.list("invalid_records")
        assertEquals(11, invalid.size)
        for (vector in invalid) {
            assertFailsWith<IllegalArgumentException>(vector["name"] as String) {
                IrohaPeerAskV1.decode(vectors.hex(vector["record_hex"]))
            }
        }
        // Any change to the 8-byte header (magic, version, flags, the single known profile) is refused.
        val record = vectors.hex(vectors.list("asks")[1]["record_hex"])
        for (index in 0 until 8) {
            for (bit in 0 until 8) {
                val changed = record.copyOf().also { it[index] = (it[index].toInt() xor (1 shl bit)).toByte() }
                assertFailsWith<IllegalArgumentException>("byte $index bit $bit") { IrohaPeerAskV1.decode(changed) }
            }
        }
    }

    @Test
    fun `every invalid text is refused`() {
        val invalid = vectors.list("invalid_texts")
        assertEquals(9, invalid.size)
        for (vector in invalid) {
            assertFailsWith<IllegalArgumentException>(vector["name"] as String) {
                IrohaPeerAskV1.fromText(vector["text"] as String)
            }
        }
        val text = vectors.list("asks")[1]["text"] as String
        val body = text.substring(5, text.length - 1)
        val zeroAmount = vectors.hex(vectors.list("invalid_records").single { it["name"] == "zero-amount" }["record_hex"])
        for ((name, candidate) in listOf(
            // A Base45 triple above 0xFFFF ("GGW" is 65,536) has no canonical bytes.
            "triple-above-u16" to "IAK1:GGW" + body.substring(3) + ":",
            "fullwidth-character" to text.replaceRange(5, 6, "Ｘ"),
            "line-break" to text.replaceRange(50, 51, "\n"),
            "double-suffix" to "$text:",
            "lowercase-prefix" to "iak1:$body:",
            // Canonical Base45 of a record that is not a valid ask.
            "zero-amount-record" to IrohaPeerAskV1.TEXT_PREFIX + PeerBase45.encode(zeroAmount) + ":",
        )) {
            // All but the doubled suffix keep 90 characters and fail past the length check.
            if (name != "double-suffix") assertEquals(90, candidate.length, name)
            assertFailsWith<IllegalArgumentException>(name) { IrohaPeerAskV1.fromText(candidate) }
        }
    }

    @Test
    fun `an ask for an account id names its account digest and check code`() {
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }
            .map { File(it, "fixtures/kagemusha/wallet_account_check_code_v1.json") }.first(File::isFile)
        val accounts = ((JsonParser.parse(file.readText()) as Map<*, *>)["accounts"] as List<*>).map { it as Map<*, *> }
        assertEquals(3, accounts.size)
        val amount = BigInteger.valueOf(1_200)
        for (account in accounts) {
            val name = account["name"] as String
            val literal = account["i105"] as String
            val ask = IrohaPeerAskV1.forAccountId(amount, literal)
            assertContentEquals(vectors.hex(account["account_digest_hex"]), ask.receiverAccountDigest, name)
            assertEquals(account["check_code"], ask.checkCode, name)
            assertEquals(KagemushaWalletAccountCheckCodeV1.forAccountId(literal), ask.checkCode, name)
            assertEquals(amount, ask.amount, name)
        }
        // The shared asks whose digests are these accounts are exactly the asks for their account ids.
        var shared = 0
        for (vector in vectors.list("asks")) {
            val account = accounts.firstOrNull { it["account_digest_hex"] == vector["account_digest_hex"] } ?: continue
            val ask = IrohaPeerAskV1.forAccountId(BigInteger(vector["amount_decimal"] as String), account["i105"] as String)
            assertEquals(vector["text"], ask.toText(), vector["name"] as String)
            shared += 1
        }
        assertEquals(3, shared)
        assertFailsWith<IllegalArgumentException> { IrohaPeerAskV1.forAccountId(amount, "not an account") }
        assertFailsWith<IllegalArgumentException> {
            IrohaPeerAskV1.forAccountId(BigInteger.ZERO, accounts.first()["i105"] as String)
        }
    }
}
