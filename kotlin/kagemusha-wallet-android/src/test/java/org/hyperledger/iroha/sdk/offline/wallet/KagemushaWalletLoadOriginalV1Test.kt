package org.hyperledger.iroha.sdk.offline.wallet

import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletLoadSelectionV1
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Owned DATA bounds only; these tests create no Native owner or financial proof. */
class KagemushaWalletLoadOriginalV1Test {
    private fun selection() = ToriiKagemushaWalletLoadSelectionV1(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
    @Test fun originalsAndAccessorsCannotRetargetTheFrozenNativeInputs() {
        val receipt = byteArrayOf(7, 8); val finality = byteArrayOf(9, 10)
        val input = KagemushaWalletLoadOriginalInputV1(selection(), "bounded-I105-input", receipt, finality)
        receipt.fill(0); finality.fill(0)
        assertArrayEquals(byteArrayOf(7, 8), input.receipt()); assertArrayEquals(byteArrayOf(9, 10), input.finality())
        input.receipt().fill(0); input.finality().fill(0); input.requestId().fill(0)
        assertArrayEquals(byteArrayOf(7, 8), input.receipt()); assertArrayEquals(byteArrayOf(9, 10), input.finality())
        assertArrayEquals(ByteArray(32) { 3 }, input.requestId())
    }
    @Test fun retainedReopeningAppliesOriginalBoundsBeforeAccessingNative() {
        val network = org.hyperledger.iroha.sdk.core.model.NetworkId.parse(
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
        for ((receipt, finality) in listOf(byteArrayOf() to byteArrayOf(1),
            byteArrayOf(1) to ByteArray(256 * 1024 + 1))) {
            assertThrows(IllegalArgumentException::class.java) {
                KagemushaWalletLoadOriginalV1.decodeRetained(selection(), "payer", network, receipt, finality)
            }
        }
    }
    @Test fun oversizedOrAbsentFinancialOriginalIsNeverSentToNative() {
        for (bad in listOf(byteArrayOf(), ByteArray(513)))
            assertThrows(IllegalArgumentException::class.java) { KagemushaWalletLoadOriginalInputV1(selection(), "x", bad, byteArrayOf(1)) }
        for (bad in listOf(byteArrayOf(), ByteArray(256 * 1024 + 1)))
            assertThrows(IllegalArgumentException::class.java) { KagemushaWalletLoadOriginalInputV1(selection(), "x", byteArrayOf(1), bad) }
    }
    @Test fun maintainedKanaI105PayerRetainsExactUtf8AndDefensiveCopies() {
        // Maintained CanonicalRequestSignerTest I105 literal, not a new account or proof fixture.
        val payer = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        val expected = payer.toByteArray(Charsets.UTF_8)
        val input = KagemushaWalletLoadOriginalInputV1(selection(), payer, byteArrayOf(1), byteArrayOf(1))
        assertArrayEquals(expected, input.payer())
        assertEquals(payer, String(input.payer(), Charsets.UTF_8))
        input.payer().fill(0)
        assertArrayEquals(expected, input.payer())
    }
    @Test fun payerCeilingCountsUtf8BytesForAsciiKanaAndSupplementaryCharacters() {
        // Carrier DATA only: these boundary strings do not claim canonical account validity.
        val atLimit = listOf("x".repeat(1024), "é".repeat(512), "ﾛ".repeat(341) + "x", "😀".repeat(256))
        for (payer in atLimit) {
            val input = KagemushaWalletLoadOriginalInputV1(selection(), payer, byteArrayOf(1), byteArrayOf(1))
            assertEquals(1024, input.payer().size)
            assertArrayEquals(payer.toByteArray(Charsets.UTF_8), input.payer())
            assertThrows(IllegalArgumentException::class.java) {
                KagemushaWalletLoadOriginalInputV1(selection(), payer + "x", byteArrayOf(1), byteArrayOf(1))
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            KagemushaWalletLoadOriginalInputV1(selection(), "", byteArrayOf(1), byteArrayOf(1))
        }
    }
    @Test fun malformedUtf16CannotBecomeReplacementBytes() {
        for (payer in listOf("\uD800", "\uDC00", "\uD800x", "x\uDC00", "\uD800\uD800", "\uDC00\uD800")) {
            assertThrows(IllegalArgumentException::class.java) {
                KagemushaWalletLoadOriginalInputV1(selection(), payer, byteArrayOf(1), byteArrayOf(1))
            }
        }
    }
    @Test fun dataCarrierDoesNotNormalizeOrPretendToParseCanonicalAccounts() {
        for (payer in listOf("é", "e\u0301", " payer ", "x\n", "\u0000")) {
            val input = KagemushaWalletLoadOriginalInputV1(selection(), payer, byteArrayOf(1), byteArrayOf(1))
            assertArrayEquals(payer.toByteArray(Charsets.UTF_8), input.payer())
        }
    }
    @Test fun independentRouteSelectorsStayExactAndDiagnosticOutputIsRedacted() {
        val input = KagemushaWalletLoadOriginalInputV1(selection(), "secret-account", ByteArray(512), ByteArray(256 * 1024))
        assertArrayEquals(ByteArray(32) { 1 }, input.schemeId()); assertArrayEquals(ByteArray(32) { 2 }, input.walletId())
        input.schemeId().fill(0); input.walletId().fill(0); input.payer().fill(0)
        assertArrayEquals(ByteArray(32) { 1 }, input.schemeId()); assertArrayEquals(ByteArray(32) { 2 }, input.walletId())
        assertFalse(input.toString().contains("secret-account"))
    }
}
