// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.core.model.instructions

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
import org.hyperledger.iroha.sdk.crypto.Ed25519Signer
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.norito.SchemaHash
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
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Codec/signer checks only. The frozen Activation fixture explicitly contains a stand-in proof. */
class KagemushaWalletActivateInstructionV1Test {
    @Test fun `complete frozen activation original retains its exact canonical ledger action`() {
        val instruction = fixtureInstruction()
        val original = instruction.activation()
        assertEquals(1751, original.size)
        assertEquals(1848, instruction.concreteFrame().size)
        assertEquals("iroha.kagemusha.wallet.ledger.v1", KagemushaWalletActivateInstructionV1.WIRE_ID)
        assertContentEquals(hex("8eef66c2b4be9ed7b2604aec85793350"), SchemaHash.hash16(KagemushaWalletActivateInstructionV1.SCHEMA_NAME))
        assertContentEquals(hex("a42b6ae59b4107b71368b42ef219abe3"), original.copyOfRange(6, 22))
        assertContentEquals(original, unpack(instruction))
        assertEquals(InstructionKind.CUSTOM, instruction.toInstructionBox().kind)
        assertContentEquals(instruction.concreteFrame(), assertIs<WirePayload>(instruction.toInstructionBox().payload).payloadBytes)
    }

    @Test fun `raw byte vector and compact field boundaries preserve every byte through the maximum`() {
        for (length in listOf(1, 113, 114, 119, 120, 16_383, 16_384)) {
            val original = ByteArray(length) { it.toByte() }
            val instruction = KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, original)
            assertContentEquals(original, unpack(instruction))
            if (length == 16_384) assertEquals(16_483, instruction.concreteFrame().size)
        }
    }

    @Test fun `activation custody never shares mutable input output or wire bytes`() {
        val original = fixtureInstruction()
        val scheme = original.schemeId(); val activation = original.activation()
        val instruction = KagemushaWalletActivateInstructionV1(scheme, activation)
        val frame = instruction.concreteFrame()
        listOf(scheme, activation, instruction.schemeId(), instruction.activation(), instruction.concreteFrame(),
            assertIs<WirePayload>(instruction.toInstructionBox().payload).payloadBytes).forEach { it.fill(0) }
        assertContentEquals(frame, instruction.concreteFrame())
        assertEquals(original, instruction)
        assertEquals(original.hashCode(), instruction.hashCode())
        assertNotEquals(instruction, KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, original.activation()))
        assertNotEquals(instruction, KagemushaWalletActivateInstructionV1(original.schemeId(), byteArrayOf(1)))
    }

    @Test fun `invalid scheme and empty or excessive complete originals are refused`() {
        for (scheme in listOf(ByteArray(0), ByteArray(31), ByteArray(33), ByteArray(32))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletActivateInstructionV1(scheme, byteArrayOf(1)) }
        }
        for (activation in listOf(ByteArray(0), ByteArray(16_385))) {
            assertFailsWith<IllegalArgumentException> { KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, activation) }
        }
    }

    @Test fun `existing account signer binds activation scheme network and exact retained signature`() {
        val seed = ByteArray(32) { 0x5b }
        val key = Ed25519PrivateKeyParameters(seed, 0)
        val factory = KeyFactory.getInstance("Ed25519")
        val signer = Ed25519Signer(
            factory.generatePrivate(PKCS8EncodedKeySpec(hex("302e020100300506032b657004220420") + seed)),
            factory.generatePublic(X509EncodedKeySpec(hex("302a300506032b6570032100") + key.generatePublicKey().encoded)),
        )
        val instruction = fixtureInstruction()
        val codec = NoritoJavaCodecAdapter(TairaTestnetProfile.I105_DISCRIMINANT)
        val payload = TransactionPayload(
            networkId = TestNetworkIds.canonical(),
            authority = AccountAddress.fromAccount(key.generatePublicKey().encoded, "ed25519").toI105(TairaTestnetProfile.I105_DISCRIMINANT),
            creationTimeMs = 1_735_369_000_000L,
            executable = Executable.instructions(listOf(instruction.toInstructionBox())),
            feePayment = FeePaymentIntent.authority(emptyList()),
        )
        val signed = TransactionBuilder(codec).encodeAndSign(payload, signer)
        val exactWire = SignedTransactionEncoder.encodeVersioned(signed)
        val retained = SignedTransactionEncoder.decodeVersioned(exactWire)
        assertContentEquals(exactWire, SignedTransactionEncoder.encodeVersioned(retained))
        assertContentEquals(signed.encodedPayload(), retained.encodedPayload())
        assertContentEquals(signed.signature(), retained.signature())
        // The existing public key is retained independently; it is not in SignedTransaction wire.
        assertContentEquals(signer.publicKey(), signed.publicKey())
        val decoded = codec.decodeTransaction(retained.encodedPayload())
        assertEquals(instruction.toInstructionBox(), assertIs<Executable.Instructions>(decoded.executable).instructions.single())
        fun verify(bytes: ByteArray, signature: ByteArray = retained.signature()): Boolean = BcEd25519Signer().run {
            val hash = IrohaHash.prehash(bytes)
            init(false, key.generatePublicKey()); update(hash, 0, hash.size); verifySignature(signature)
        }
        assertTrue(verify(retained.encodedPayload()))
        for (changed in listOf(
            KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, instruction.activation()),
            KagemushaWalletActivateInstructionV1(instruction.schemeId(), instruction.activation().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }),
        )) assertFalse(verify(codec.encodeTransaction(payload.copy(executable = Executable.instructions(listOf(changed.toInstructionBox()))))))
        assertFalse(verify(codec.encodeTransaction(payload.copy(networkId = TestNetworkIds.fromSeed(91)))))
        assertFalse(verify(retained.encodedPayload(), retained.signature().also { it[0] = (it[0].toInt() xor 1).toByte() }))
    }

    @Test fun `emit complete frames for independent Rust canonical registry comparison`() {
        // A successful Kotlin test alone is not Rust parity or proof/ledger acceptance.
        val output = Paths.get(System.getProperty("kagemusha.activate.parityOutput"))
        Files.createDirectories(output.toAbsolutePath().parent)
        val cases = linkedMapOf(
            "activation_fixture" to fixtureInstruction(),
            "minimum_opaque" to KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, byteArrayOf(0x7f)),
            "maximum_opaque" to KagemushaWalletActivateInstructionV1(ByteArray(32) { 1 }, ByteArray(16_384) { it.toByte() }),
        )
        Files.write(output, cases.map { (name, instruction) -> "$name=${instruction.concreteFrame().joinToString("") { "%02x".format(it.toInt() and 0xff) }}" })
    }

    private fun unpack(instruction: KagemushaWalletActivateInstructionV1): ByteArray {
        val frame = instruction.concreteFrame()
        assertContentEquals(ByteArray(8), frame.copyOfRange(40, 48))
        val decoded = NoritoHeader.decode(frame, SchemaHash.hash16(KagemushaWalletActivateInstructionV1.SCHEMA_NAME))
        decoded.header.validateChecksum(decoded.payload)
        val root = NoritoDecoder(decoded.payload, 2)
        assertContentEquals(instruction.schemeId(), root.readBytes(root.readLength(true).toInt()))
        val action = NoritoDecoder(root.readBytes(root.readLength(true).toInt()), 2)
        assertEquals(0, root.remaining())
        assertEquals(2L, action.readUInt(32))
        val vector = NoritoDecoder(action.readBytes(action.readLength(true).toInt()), 2)
        assertEquals(0, action.remaining())
        assertEquals(instruction.activation().size.toLong(), vector.readLength(false))
        return vector.readBytes(vector.remaining())
    }

    private fun fixtureInstruction(): KagemushaWalletActivateInstructionV1 {
        val relative = "fixtures/kagemusha/wallet_v1_vectors.json"
        val path = listOf("../..", "..", ".").map { Paths.get(it, relative) }.first { Files.isRegularFile(it) }
        val document = JsonParser.parse(String(Files.readAllBytes(path), Charsets.UTF_8)) as Map<*, *>
        val fixture = (document["objects"] as List<*>).map { it as Map<*, *> }.single { it["type"] == "KagemushaWalletActivationV1" }
        assertEquals(true, fixture["stand_in_proof"], "Fixture is codec DATA, not a valid Bootstrap proof")
        val activation = hex(fixture["canonical_hex"] as String)
        val activationFields = fields(NoritoHeader.decode(activation, null).payload)
        val controlBody = fields(fields(activationFields[1])[0])
        return KagemushaWalletActivateInstructionV1(controlBody[1], activation)
    }

    private fun fields(bytes: ByteArray): List<ByteArray> {
        val decoder = NoritoDecoder(bytes, 2)
        val fields = mutableListOf<ByteArray>()
        while (decoder.remaining() > 0) fields.add(decoder.readBytes(decoder.readLength(true).toInt()))
        return fields
    }

    private fun hex(text: String): ByteArray = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
