package org.hyperledger.iroha.sdk.client

import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.core.model.InstructionBox
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.core.model.instructions.TransferWirePayloadEncoder
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ToriiExplorerInstructionCodecTest {
    @Test fun rustCapturedAssetInstructionProjectsItsExactDisplayFields() {
        // Frozen by Rust generated_box_identity_tests: no Kotlin encoder creates this input.
        val fixture = rustTransfer("Asset")
        val frame = hex(fixture["instruction_frame"] as String)
        val decoded = ToriiExplorerInstructionCodec.decode("iroha.transfer", sha256(frame), fixture["instruction_json"] as String)
        assertContentEquals(frame, NoritoJavaCodecAdapter.encodeInstructionBox(decoded))
        val transfer = assertNotNull(ToriiExplorerInstructionCodec.assetTransfer(decoded, CHAIN))
        val account = AccountAddress.fromAccount(hex("93db9f2ee0f7e39e942fb59441190bf20b9c43cfcc8a051a152499cf392b7a37"), "ed25519").toI105(CHAIN)
        val definition = AssetDefinitionIdEncoder.encodeFromBytes(hex("94f8e55a767d4cbc84fdc0d946bd787a"))
        assertEquals("$definition#$account", transfer.assetId)
        assertEquals("7", transfer.amount)
        assertEquals(account, transfer.destinationAccountId)
    }

    @Test fun rustCapturedOwnershipTransfersAreNotReportedAsAssetPayments() {
        for (name in listOf("Domain", "AssetDefinition", "Nft")) {
            val fixture = rustTransfer(name)
            val frame = hex(fixture["instruction_frame"] as String)
            val decoded = ToriiExplorerInstructionCodec.decode("iroha.transfer", sha256(frame), fixture["instruction_json"] as String)
            assertNull(ToriiExplorerInstructionCodec.assetTransfer(decoded, CHAIN), name)
        }
    }

    @Test fun transferProjectionPreservesExactQuantityAndDataspace() {
        val source = account(31)
        val destination = account(32)
        val asset = "$ASSET#$source#dataspace:42"
        val amount = "12345678901234567890.123456"
        val original = TransferWirePayloadEncoder.encodeAssetTransfer(asset, amount, destination)
        val transfer = assertNotNull(ToriiExplorerInstructionCodec.assetTransfer(decode(frame(original)), CHAIN))
        assertEquals(asset, transfer.assetId)
        assertEquals(amount, transfer.amount)
        assertEquals(destination, transfer.destinationAccountId)
    }

    @Test fun callerChainDiscriminantControlsBothRenderedAccountIdentities() {
        val decoded = decode(frame(transfer()))
        val otherChain = 42
        val result = assertNotNull(ToriiExplorerInstructionCodec.assetTransfer(decoded, otherChain))
        assertEquals("$ASSET#${account(31, otherChain)}", result.assetId)
        assertEquals(account(32, otherChain), result.destinationAccountId)
        for (invalid in listOf(-1, 65536)) {
            assertFailsWith<ToriiExplorerInstructionException> { ToriiExplorerInstructionCodec.assetTransfer(decoded, invalid) }
        }
    }

    @Test fun advertisedWireIdentityMustExactlyMatchTheCanonicalInstruction() {
        val bytes = frame(transfer())
        for (wire in listOf("", "iroha.mint", " iroha.transfer", "iroha.transfer ", "IROHA.TRANSFER")) {
            assertFailsWith<ToriiExplorerInstructionException>(wire) { decode(bytes, wire = wire) }
        }
    }

    @Test fun digestMustBeExactLowercaseSha256OfTheWholeFrame() {
        val bytes = frame(transfer())
        for (digest in listOf("", "0".repeat(64), sha256(bytes).uppercase(), "0x${sha256(bytes)}", sha256(bytes) + " ")) {
            assertFailsWith<ToriiExplorerInstructionException>(digest) { decode(bytes, digest = digest) }
        }
    }

    @Test fun instructionCarrierMustUseExactStandardPaddedBase64() {
        val bytes = hex(rustTransfer("Asset")["instruction_frame"] as String)
        val encoded = base64(bytes)
        for (text in listOf("", "not base64", " $encoded", "$encoded\n", encoded.trimEnd('='), Base64.getUrlEncoder().encodeToString(bytes))) {
            assertFailsWith<ToriiExplorerInstructionException> { ToriiExplorerInstructionCodec.decode("iroha.transfer", sha256(bytes), text) }
        }
    }

    @Test fun digestCannotMakeTruncatedCorruptOrTrailingFramesAcceptable() {
        val bytes = frame(transfer())
        for (invalid in listOf(ByteArray(0), bytes.copyOf(bytes.size - 1), bytes + byteArrayOf(0),
            bytes.copyOf().also { it[6] = (it[6].toInt() xor 1).toByte() },
            bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })) {
            assertFailsWith<ToriiExplorerInstructionException> { decode(invalid) }
        }
    }

    @Test fun malformedTransferPayloadCannotProduceADisplayProjection() {
        val payload = (transfer().payload as WirePayload).payloadBytes
        for (invalid in listOf(byteArrayOf(0), payload.copyOf(payload.size - 1), payload + byteArrayOf(0),
            payload.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })) {
            val outer = InstructionBox.fromWirePayload("iroha.transfer", invalid)
            assertFailsWith<ToriiExplorerInstructionException> {
                ToriiExplorerInstructionCodec.assetTransfer(outer, CHAIN)
            }
        }
    }

    @Test fun validNonTransferInstructionHasNoPaymentProjection() {
        val bytes = frame(NoritoJavaCodecAdapter.logInstruction(2, "audit"))
        assertNull(ToriiExplorerInstructionCodec.assetTransfer(decode(bytes, wire = "iroha.log"), CHAIN))
    }

    private fun transfer() = TransferWirePayloadEncoder.encodeAssetTransfer("$ASSET#${account(31)}", "12.345", account(32))
    private fun account(seed: Int, chain: Int = CHAIN) = AccountAddress.fromAccount(TestEd25519Keys.publicKey(seed), "ed25519").toI105(chain)
    private fun frame(instruction: InstructionBox) = NoritoJavaCodecAdapter.encodeInstructionBox(instruction)
    private fun decode(bytes: ByteArray, wire: String = "iroha.transfer", digest: String = sha256(bytes)) =
        ToriiExplorerInstructionCodec.decode(wire, digest, base64(bytes))
    private fun base64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun rustTransfer(variant: String): Map<*, *> {
        val path = listOf("../..", "..", ".").map { Paths.get(it, FIXTURE) }.first { Files.isRegularFile(it) }
        val rows = JsonParser.parse(String(Files.readAllBytes(path), Charsets.UTF_8)) as List<*>
        val row = rows.map { it as Map<*, *> }.single { it["nominal"] == "iroha_data_model::isi::transfer::TransferBox" }
        return (row["cases"] as List<*>).map { it as Map<*, *> }.single { it["variant"] == variant }
    }

    companion object {
        private const val CHAIN = 0x0171
        private const val ASSET = "839FV3NJC8NfgWQvghXU2hEFQm9a"
        private const val FIXTURE = "crates/iroha_data_model/tests/fixtures/instruction_box_generated_identity_frames.json"
    }
}
