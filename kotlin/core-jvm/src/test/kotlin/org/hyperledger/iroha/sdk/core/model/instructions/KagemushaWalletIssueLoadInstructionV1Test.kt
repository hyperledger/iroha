// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.core.model.instructions

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer as BcEd25519Signer
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.TairaTestnetProfile
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.core.model.WirePayload
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.crypto.Ed25519Signer
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import org.hyperledger.iroha.sdk.tx.TransactionBuilder
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Codec/signer component checks. Cross-language parity also requires the paired Rust test. */
class KagemushaWalletIssueLoadInstructionV1Test {
    @Test fun `uncharged load matches the complete frozen Rust ledger frame`() {
        val row = (json(IDENTITY_FIXTURE) as List<*>).map { it as Map<*, *> }
            .single { it["nominal"] == KagemushaWalletIssueLoadInstructionV1.SCHEMA_NAME }
        val frame = ((row["cases"] as List<*>).single() as Map<*, *>)["frame"] as String
        val actual = ordinary().concreteFrame()
        assertEquals(222, actual.size)
        assertContentEquals(hex(frame), actual)
        assertContentEquals(ByteArray(8), actual.copyOfRange(40, 48))
        val decoded = NoritoHeader.decode(actual, SchemaHash.hash16(KagemushaWalletIssueLoadInstructionV1.SCHEMA_NAME))
        decoded.header.validateChecksum(decoded.payload)
        assertEquals(174, decoded.payload.size)
        assertEquals(InstructionKind.CUSTOM, ordinary().toInstructionBox().kind)
    }

    @Test fun `charged load preserves original quote and exact beneficiary fields`() {
        val instruction = charged()
        val action = fields(NoritoHeader.decode(instruction.concreteFrame(), null).payload)[1]
        val tag = NoritoDecoder(action, 2)
        assertEquals(5L, tag.readUInt(32))
        val actionFields = fields(tag.readBytes(tag.remaining()))
        assertEquals(6, actionFields.size)
        assertContentEquals(instruction.walletId(), actionFields[0])
        assertContentEquals(instruction.assetDigest(), actionFields[1])
        val optional = NoritoDecoder(actionFields[5], 2)
        assertEquals(1, optional.readByte())
        val charge = fields(optional.readBytes(optional.readLength(true).toInt()))
        assertEquals(0, optional.remaining())
        val quote = NoritoDecoder(charge[0], 2)
        val original = quoteBytes()
        assertEquals(original.size.toLong(), quote.readLength(false))
        assertContentEquals(original, quote.readBytes(original.size))
        assertEquals(0, quote.remaining())
        assertContentEquals(TransferWirePayloadEncoder.encodeAccountIdPayload(beneficiary()), charge[1])
    }

    @Test fun `u128 limits are encoded losslessly beyond Long`() {
        val instruction = ordinary(MAX_U128, MAX_U128)
        val action = fields(NoritoHeader.decode(instruction.concreteFrame(), null).payload)[1]
        val payload = fields(action.copyOfRange(4, action.size))
        assertContentEquals(ByteArray(16) { 0xff.toByte() }, payload[2])
        assertContentEquals(ByteArray(16) { 0xff.toByte() }, payload[4])
        assertFailsWith<IllegalArgumentException> { ordinary(BigInteger.ONE.shiftLeft(128)) }
        assertFailsWith<IllegalArgumentException> { ordinary(BigInteger.valueOf(-1)) }
        assertFailsWith<IllegalArgumentException> { ordinary(amount = BigInteger.ONE.shiftLeft(128)) }
        assertFailsWith<IllegalArgumentException> { ordinary(amount = BigInteger.valueOf(-1)) }
        assertFailsWith<IllegalArgumentException> { ordinary(amount = BigInteger.ZERO) }
    }

    @Test fun `construction and access never share mutable instruction or quote bytes`() {
        val scheme = ByteArray(32) { 1 }; val wallet = ByteArray(32) { 2 }
        val asset = ByteArray(32) { 4 }; val request = ByteArray(32) { 3 }
        val quote = quoteBytes()
        val charge = KagemushaWalletLoadChargeV1(quote, beneficiary())
        val instruction = KagemushaWalletIssueLoadInstructionV1(
            scheme, wallet, asset, BigInteger.ZERO, request, BigInteger.valueOf(7), charge,
        )
        val original = instruction.concreteFrame()
        listOf(scheme, wallet, asset, request, quote, instruction.schemeId(), instruction.walletId(),
            instruction.assetDigest(), instruction.requestId(), charge.quote(), instruction.concreteFrame(),
            (instruction.toInstructionBox().payload as WirePayload).payloadBytes).forEach { it.fill(0) }
        assertContentEquals(original, instruction.concreteFrame())
        assertEquals(charge, KagemushaWalletLoadChargeV1(quoteBytes(), beneficiary()))
        assertEquals(instruction.toInstructionBox(), instruction.toInstructionBox())
    }

    @Test fun `invalid identities and unbounded charge input are refused`() {
        for (index in 0..3) for (invalid in listOf(ByteArray(31), ByteArray(33), ByteArray(32))) {
            val ids = mutableListOf(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 4 }, ByteArray(32) { 3 })
            ids[index] = invalid
            assertFailsWith<IllegalArgumentException> {
                KagemushaWalletIssueLoadInstructionV1(ids[0], ids[1], ids[2], BigInteger.ZERO, ids[3], BigInteger.ONE)
            }
        }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletLoadChargeV1(ByteArray(0), beneficiary()) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletLoadChargeV1(ByteArray(1025), beneficiary()) }
        assertFailsWith<IllegalArgumentException> { KagemushaWalletLoadChargeV1(quoteBytes(), "beneficiary@domain") }
    }

    @Test fun `existing SDK transaction builder and account signer bind the exact IssueLoad`() {
        val seed = ByteArray(32) { 0x5b }
        val key = Ed25519PrivateKeyParameters(seed, 0)
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val signer = Ed25519Signer(
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(hex("302e020100300506032b657004220420") + seed)),
            keyFactory.generatePublic(X509EncodedKeySpec(hex("302a300506032b6570032100") + key.generatePublicKey().encoded)),
        )
        val codec = NoritoJavaCodecAdapter(TairaTestnetProfile.I105_DISCRIMINANT)
        for (instruction in listOf(ordinary(), charged())) {
            val payload = TransactionPayload(
                networkId = TestNetworkIds.canonical(), authority = beneficiary(), creationTimeMs = 1_735_369_000_000L,
                executable = Executable.instructions(listOf(instruction.toInstructionBox())),
                feePayment = FeePaymentIntent.authority(emptyList()),
            )
            // Fixture keys exercise the real SDK path; Android protected key-record/owner
            // binding remains an application integration requirement, not a result of this test.
            val signed = TransactionBuilder(codec).encodeAndSign(payload, signer)
            val encoded = signed.encodedPayload()
            val signature = signed.signature()
            assertContentEquals(codec.encodeTransaction(payload), encoded)
            assertContentEquals(signer.publicKey(), signed.publicKey())
            val retained = SignedTransactionEncoder.decodeVersioned(SignedTransactionEncoder.encodeVersioned(signed))
            assertContentEquals(encoded, retained.encodedPayload())
            assertContentEquals(signature, retained.signature())
            val decoded = codec.decodeTransaction(retained.encodedPayload())
            assertEquals(payload.authority, decoded.authority)
            assertEquals(payload.networkId, decoded.networkId)
            assertEquals(instruction.toInstructionBox(), assertIs<Executable.Instructions>(decoded.executable).instructions.single())
            assertContentEquals(encoded, codec.encodeTransaction(decoded))
            fun verify(bytes: ByteArray): Boolean = BcEd25519Signer().run {
                val hash = IrohaHash.prehash(bytes)
                init(false, key.generatePublicKey()); update(hash, 0, hash.size); verifySignature(signature)
            }
            assertTrue(verify(encoded))
            val different = KagemushaWalletIssueLoadInstructionV1(
                instruction.schemeId(), instruction.walletId(), instruction.assetDigest(), instruction.ordinal,
                instruction.requestId(), instruction.amount.add(BigInteger.ONE), instruction.charge,
            )
            assertFalse(verify(codec.encodeTransaction(payload.copy(executable = Executable.instructions(listOf(different.toInstructionBox()))))))
            assertFalse(verify(codec.encodeTransaction(payload.copy(networkId = TestNetworkIds.fromSeed(91)))))
        }
    }

    @Test fun `emit complete frames for independent Rust registry comparison`() {
        // The paired Rust ignored test constructs these same typed values independently. This
        // output alone establishes no charged cross-language parity, issuance, or finality.
        val path = Paths.get(System.getProperty("kagemusha.issueLoad.parityOutput"))
        Files.createDirectories(path.toAbsolutePath().parent)
        val cases = linkedMapOf("uncharged" to ordinary(), "u128_max" to ordinary(MAX_U128, MAX_U128), "charged" to charged())
        Files.write(path, cases.map { (name, value) -> "$name=${value.concreteFrame().toHex()}" })
    }

    private fun ordinary(ordinal: BigInteger = BigInteger.ZERO, amount: BigInteger = BigInteger.valueOf(7)) =
        KagemushaWalletIssueLoadInstructionV1(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 4 },
            ordinal, ByteArray(32) { 3 }, amount)

    private fun charged(): KagemushaWalletIssueLoadInstructionV1 {
        val quote = quoteBytes()
        val body = fields(fields(NoritoHeader.decode(quote, null).payload)[0])
        // ChargeQuoteBody orders scheme, asset, wallet; IssueLoad orders wallet, asset.
        val schemeId = body[1]
        val assetDigest = body[2]
        val walletId = body[3]
        return KagemushaWalletIssueLoadInstructionV1(
            schemeId = schemeId, walletId = walletId, assetDigest = assetDigest,
            ordinal = unsigned(body[5]), requestId = ByteArray(32) { 7 }, amount = unsigned(body[6]),
            charge = KagemushaWalletLoadChargeV1(quote, beneficiary()),
        )
    }

    private fun quoteBytes(): ByteArray {
        val objects = (json(QUOTE_FIXTURE) as Map<*, *>)["objects"] as List<*>
        val row = objects.map { it as Map<*, *> }.single {
            it["type"] == "KagemushaWalletChargeQuoteV1" && it["variant"] == "Load"
        }
        return hex(row["canonical_hex"] as String)
    }

    private fun beneficiary(): String = AccountAddress.fromAccount(TestEd25519Keys.publicKey(0x5b), "ed25519")
        .toI105(TairaTestnetProfile.I105_DISCRIMINANT)

    private fun fields(bytes: ByteArray): List<ByteArray> {
        val decoder = NoritoDecoder(bytes, 2)
        val result = mutableListOf<ByteArray>()
        while (decoder.remaining() > 0) result.add(decoder.readBytes(decoder.readLength(true).toInt()))
        return result
    }

    private fun json(relative: String): Any? {
        val root = listOf("../..", "..", ".").map { Paths.get(it, relative) }.first { Files.isRegularFile(it) }
        return JsonParser.parse(String(Files.readAllBytes(root), Charsets.UTF_8))
    }

    private fun unsigned(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())
    private fun hex(text: String): ByteArray = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        private const val IDENTITY_FIXTURE = "crates/iroha_data_model/tests/fixtures/instruction_record_generated_identity_frames.json"
        private const val QUOTE_FIXTURE = "fixtures/kagemusha/wallet_v1_vectors.json"
        private val MAX_U128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
    }
}
