package org.hyperledger.iroha.sdk.offline

import java.io.File
import org.hyperledger.iroha.sdk.client.JsonParser
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class KagemushaWalletAccountCheckCodeV1Test {
    private val fixture: Map<*, *> by lazy {
        val file = generateSequence(File(".").canonicalFile) { it.parentFile }
            .map { File(it, "fixtures/kagemusha/wallet_account_check_code_v1.json") }.first(File::isFile)
        (JsonParser.parse(file.readText()) as Map<*, *>).also {
            assertEquals("iroha.kagemusha.wallet-account-check-code.v1", it["schema"])
        }
    }
    private fun vectors(key: String): List<Map<*, *>> = (fixture[key] as List<*>).map { it as Map<*, *> }
    private fun hex(value: Any?): ByteArray = (value as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun sharedAccountsGiveTheSameCodeFromTheirIdOriginalAndDigest() {
        val discriminant = (fixture["chain_discriminant"] as Number).toInt()
        for (vector in vectors("accounts")) {
            val name = vector["name"] as String
            val literal = vector["i105"] as String
            val original = hex(vector["account_original_hex"])
            val digest = hex(vector["account_digest_hex"])
            val code = vector["check_code"] as String
            assertContentEquals(original, KagemushaWalletAccountOriginalV1.encode(literal), name)
            assertEquals(literal, KagemushaWalletAccountOriginalV1.decode(original, discriminant), name)
            assertContentEquals(digest, KagemushaWalletWireV1.digest(KagemushaWalletDigestRoleV1.ACCOUNT, original), name)
            assertEquals(code, KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest), name)
            assertEquals(code, KagemushaWalletAccountCheckCodeV1.forAccountOriginal(original), name)
            assertEquals(code, KagemushaWalletAccountCheckCodeV1.forAccountId(literal), name)
        }
    }

    @Test fun digestEdgesAreUnsignedReducedAndZeroPadded() {
        for (vector in vectors("digests")) {
            assertEquals(vector["check_code"], KagemushaWalletAccountCheckCodeV1.forAccountDigest(hex(vector["account_digest_hex"])),
                vector["name"] as String)
        }
    }

    @Test fun onlyTheFirstFourDigestBytesChooseTheCode() {
        val digest = hex(vectors("accounts").first()["account_digest_hex"])
        val code = KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest)
        assertEquals(code, KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest.copyOf().apply { this[31] = (this[31].toInt() xor 1).toByte() }))
        assertNotEquals(code, KagemushaWalletAccountCheckCodeV1.forAccountDigest(digest.copyOf().apply { this[3] = (this[3].toInt() xor 1).toByte() }))
    }

    @Test fun aDigestOfAnyOtherLengthIsRefused() {
        for (length in (fixture["invalid_digest_lengths"] as List<*>).map { (it as Number).toInt() }) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletAccountCheckCodeV1.forAccountDigest(ByteArray(length)) }
        }
    }
}
