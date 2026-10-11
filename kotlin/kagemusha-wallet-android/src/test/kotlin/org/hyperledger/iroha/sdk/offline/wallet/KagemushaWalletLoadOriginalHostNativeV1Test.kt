// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline.wallet

import java.io.File
import java.math.BigInteger
import java.net.URI
import java.util.concurrent.CompletableFuture
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.ClientConfig
import org.hyperledger.iroha.sdk.client.HttpClientTransport
import org.hyperledger.iroha.sdk.client.HttpTransportExecutor
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.LocalSigningContext
import org.hyperledger.iroha.sdk.client.RequestSigner
import org.hyperledger.iroha.sdk.client.ToriiCanonicalRequestAuth
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletLoadIssuanceOriginalV1
import org.hyperledger.iroha.sdk.client.ToriiKagemushaWalletLoadSelectionV1
import org.hyperledger.iroha.sdk.client.transport.TransportRequest
import org.hyperledger.iroha.sdk.client.transport.TransportResponse
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** Actual JNI DATA decoding. The existing Rust vector deliberately has no valid BLS certificate.
 * Success grants no finality, wallet admission, signature or monetary completion. */
@Tag("host-native")
class KagemushaWalletLoadOriginalHostNativeV1Test {
    @BeforeEach
    fun requireRebuiltNativeBridge() {
        assertTrue(NativeSignerBridge.isNativeAvailable(), "The explicitly supplied rebuilt bridge must load")
        assertEquals(1, KagemushaWalletNativeV1.revision())
    }

    @Test
    fun publicDecodeRetainsCanonicalKanaPayerAndExactNonproofDataThroughJni() {
        val fixture = Fixture.read()
        val issuance = fixture.issuance()
        val receiptBefore = fixture.receipt.copyOf()
        val finalityBefore = fixture.finality.copyOf()
        val value = KagemushaWalletLoadOriginalV1.decode(issuance, fixture.finality)
        assertEquals(BigInteger.valueOf(42), value.blockHeight)
        assertEquals(fixture.network, value.networkId)
        assertEquals(issuance.payerAccountId, value.payerAccountId)
        assertContentEquals(fixture.selection.schemeId, value.selection.schemeId)
        assertContentEquals(fixture.selection.walletId, value.selection.walletId)
        assertContentEquals(fixture.selection.requestId, value.selection.requestId)
        assertContentEquals(fixture.selection.requestId, value.requestId())
        assertContentEquals(receiptBefore, value.receiptOriginal())
        assertContentEquals(finalityBefore, value.finalityOriginal())
        fixture.receipt.fill(0); fixture.finality.fill(0)
        value.receiptOriginal().fill(0); value.finalityOriginal().fill(0); value.requestId().fill(0)
        assertContentEquals(receiptBefore, value.receiptOriginal())
        assertContentEquals(finalityBefore, value.finalityOriginal())
        assertContentEquals(fixture.selection.requestId, value.requestId())
    }

    @Test
    fun retainedReopeningUsesExactOriginalsAndRechecksRequestIdentityThroughJni() {
        val fixture = Fixture.read()
        val issuance = fixture.issuance()
        val retained = KagemushaWalletLoadOriginalV1.decodeRetained(fixture.selection,
            issuance.payerAccountId, fixture.network, fixture.receipt, fixture.finality)
        assertEquals(BigInteger.valueOf(42), retained.blockHeight)
        assertContentEquals(fixture.receipt, retained.receiptOriginal())
        assertContentEquals(fixture.finality, retained.finalityOriginal())
        val wrong = ToriiKagemushaWalletLoadSelectionV1(fixture.selection.schemeId,
            fixture.selection.walletId, ByteArray(32) { 0x7f })
        assertNativeInvalid {
            KagemushaWalletLoadOriginalV1.decodeRetained(wrong, issuance.payerAccountId,
                fixture.network, retained.receiptOriginal(), retained.finalityOriginal())
        }
        fixture.receipt.fill(0); fixture.finality.fill(0)
        val reopened = KagemushaWalletLoadOriginalV1.decodeRetained(retained.selection,
            retained.payerAccountId, retained.networkId, retained.receiptOriginal(), retained.finalityOriginal())
        assertContentEquals(retained.receiptOriginal(), reopened.receiptOriginal())
        assertContentEquals(retained.finalityOriginal(), reopened.finalityOriginal())
    }

    @Test
    fun publicDecodeRejectsEachForeignReadIdentityThroughJni() {
        val fixture = Fixture.read()
        val ids = listOf(fixture.selection.schemeId, fixture.selection.walletId, fixture.selection.requestId)
        for (index in ids.indices) {
            val changed = ids.map { it.copyOf() }
            changed[index][0] = (changed[index][0].toInt() xor 1).toByte()
            val selection = ToriiKagemushaWalletLoadSelectionV1(changed[0], changed[1], changed[2])
            val issuance = fixture.issuance(selection)
            assertNativeInvalid { KagemushaWalletLoadOriginalV1.decode(issuance, fixture.finality) }
        }
        val foreignPayer = fixture.issuance(payerSeed = 0x5c)
        assertNativeInvalid { KagemushaWalletLoadOriginalV1.decode(foreignPayer, fixture.finality) }
    }

    @Test
    fun publicDecodeRejectsTrailingReceiptAndFinalityThroughJni() {
        val fixture = Fixture.read()
        val trailingReceipt = fixture.issuance(receiptOriginal = fixture.receipt + byteArrayOf(0))
        assertNativeInvalid { KagemushaWalletLoadOriginalV1.decode(trailingReceipt, fixture.finality) }
        val issuance = fixture.issuance()
        assertNativeInvalid { KagemushaWalletLoadOriginalV1.decode(issuance, fixture.finality + byteArrayOf(0)) }
    }

    private fun assertNativeInvalid(action: () -> KagemushaWalletLoadOriginalV1) {
        assertEquals(-1, assertFailsWith<KagemushaWalletExceptionV1> { action() }.status)
    }

    private class Fixture(val selection: ToriiKagemushaWalletLoadSelectionV1,
        val receipt: ByteArray, val finality: ByteArray) {
        val network = NetworkId.fromBytes(ByteArray(32) { 0x41 })

        fun issuance(selected: ToriiKagemushaWalletLoadSelectionV1 = selection,
            payerSeed: Int = 0x5b, receiptOriginal: ByteArray = receipt): ToriiKagemushaWalletLoadIssuanceOriginalV1 {
            // Same raw 32-byte Ed25519 seed as Rust vectors_tests::BENEFICIARY_SEED; public test DATA.
            val privateKey = ByteArray(32) { payerSeed.toByte() }
            val publicKey = NativeSignerBridge.publicKeyFromPrivate(SigningAlgorithm.ED25519, privateKey)
            val payer = AccountAddress.fromAccount(publicKey, "ed25519").toI105Default()
            assertTrue(payer.any { it.code > 0x7f }, "exercise canonical I105 kana")
            val executor = object : HttpTransportExecutor {
                override fun execute(request: TransportRequest): CompletableFuture<TransportResponse> =
                    CompletableFuture.completedFuture(TransportResponse(200, receiptOriginal, "",
                        mapOf("Content-Type" to listOf("application/x-norito")), request.uri, false))
            }
            val client = HttpClientTransport(executor, ClientConfig.builder()
                .setBaseUri(URI.create("https://example.test"))
                .setLocalSigningContext(LocalSigningContext(network)).build())
            // Canned transport DATA obtains the public response type; no server or wallet is admitted.
            try {
                val auth = ToriiCanonicalRequestAuth(payer, RequestSigner { message ->
                    NativeSignerBridge.signDetached(SigningAlgorithm.ED25519, privateKey, message)
                })
                return client.getKagemushaWalletLoadIssuanceOriginalV1(selected, auth, Runnable {}).join()
            } finally { client.close() }
        }

        companion object {
            fun read(): Fixture {
                var directory: File? = File("").absoluteFile
                var source: File? = null
                while (directory != null) {
                    val candidate = File(directory, "fixtures/kagemusha/wallet_v1_vectors.json")
                    if (candidate.isFile) { source = candidate; break }
                    directory = directory.parentFile
                }
                val root = JsonParser.parse(checkNotNull(source) { "Rust wallet fixture is missing" }.readText(Charsets.UTF_8)) as Map<*, *>
                val objects = root["objects"] as List<*>
                fun original(type: String, standIn: Boolean): ByteArray {
                    val row = objects.map { it as Map<*, *> }.single { it["type"] == type }
                    assertEquals(standIn, row["stand_in_proof"])
                    return hex(row["canonical_hex"] as String)
                }
                val transcript = hex((root["ordinary_load_receipt"] as Map<*, *>)["transcript_hex"] as String)
                // Rust's explicit fixed receipt transcript, never a guessed Norito payload layout.
                assertEquals(282, transcript.size)
                assertContentEquals(byteArrayOf(1, 0), transcript.copyOfRange(0, 2))
                assertContentEquals(byteArrayOf(42, 0, 0, 0, 0, 0, 0, 0), transcript.copyOfRange(242, 250))
                return Fixture(ToriiKagemushaWalletLoadSelectionV1(transcript.copyOfRange(2, 34),
                    transcript.copyOfRange(66, 98), transcript.copyOfRange(98, 130)),
                    original("KagemushaWalletLoadReceiptV1", false),
                    original("KagemushaWalletLoadFinalityV1", true))
            }

            private fun hex(text: String): ByteArray {
                require(text.length % 2 == 0)
                return text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
        }
    }
}
