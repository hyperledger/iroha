package org.hyperledger.iroha.sdk.core.model.instructions

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.hyperledger.iroha.sdk.norito.NoritoEncoder
import org.hyperledger.iroha.sdk.norito.NoritoHeader
import org.hyperledger.iroha.sdk.tx.norito.TransactionPayloadAdapter
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.core.model.FeeChargeKind
import org.hyperledger.iroha.sdk.core.model.FeeChargeLimit
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.crypto.NativeSignedTransaction
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder

class ZkAssetInstructionsTest {
    @Test
    fun confidentialEncryptedPayloadIsStrictAndDefensive() {
        val ephemeral = fill(0x11, 32)
        val nonce = fill(0x22, 24)
        val ciphertext = byteArrayOf(0x33, 0x34)
        val payload = ConfidentialEncryptedPayload(
            ephemeralPublicKey = ephemeral,
            nonce = nonce,
            ciphertext = ciphertext,
        )

        ephemeral[0] = 0
        nonce[0] = 0
        ciphertext[0] = 0
        assertEquals(ConfidentialEncryptedPayload.VERSION_V1, payload.version)
        assertEquals(0x11, payload.ephemeralPublicKey[0].toInt())
        assertEquals(0x22, payload.nonce[0].toInt())
        assertEquals(0x33, payload.ciphertext[0].toInt())

        val exposed = payload.ephemeralPublicKey
        exposed[0] = 0
        assertEquals(0x11, payload.ephemeralPublicKey[0].toInt())

        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(2, fill(1, 32), fill(2, 24), byteArrayOf(3))
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = ByteArray(32),
                nonce = fill(2, 24),
                ciphertext = byteArrayOf(3),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = ByteArray(32).also { it[0] = 1 },
                nonce = fill(2, 24),
                ciphertext = byteArrayOf(3),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = fill(1, 31),
                nonce = fill(2, 24),
                ciphertext = byteArrayOf(3),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = fill(1, 32),
                nonce = fill(2, 23),
                ciphertext = byteArrayOf(3),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = fill(1, 32),
                nonce = fill(2, 24),
                ciphertext = ByteArray(0),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload(
                ephemeralPublicKey = fill(1, 32),
                nonce = fill(2, 24),
                ciphertext = ByteArray(ConfidentialEncryptedPayload.MAX_CIPHERTEXT_BYTES + 1),
            )
        }
    }

    @Test
    fun confidentialEncryptedPayloadMatchesRustWireFixture() {
        val ephemeral = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val nonce = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7")
        val ciphertext = hex("436f6e666964656e7469616c5061796c6f61645631")
        val serialized = hex(
            "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b715" +
                "436f6e666964656e7469616c5061796c6f61645631",
        )
        val payload = ConfidentialEncryptedPayload(
            ephemeralPublicKey = ephemeral,
            nonce = nonce,
            ciphertext = ciphertext,
        )

        assertContentEquals(serialized, payload.toWireBytes())
        assertEquals(payload, ConfidentialEncryptedPayload.fromWireBytes(serialized))
        val exposedWire = payload.toWireBytes()
        exposedWire[0] = 0
        assertContentEquals(serialized, payload.toWireBytes())

        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload.fromWireBytes(serialized.copyOf(serialized.size - 1))
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload.fromWireBytes(serialized + byteArrayOf(0))
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload.fromWireBytes(
                byteArrayOf(0) + ephemeral + nonce + byteArrayOf(ciphertext.size.toByte()) + ciphertext,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload.fromWireBytes(
                byteArrayOf(1) + ephemeral + nonce + byteArrayOf(0x95.toByte(), 0) + ciphertext,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ConfidentialEncryptedPayload.fromWireBytes(
                byteArrayOf(1) + ephemeral + nonce +
                    byteArrayOf(0x81.toByte(), 0x80.toByte(), 0x04),
            )
        }
    }

    @Test
    fun proofAttachmentValidatesBackendAndJsonShape() {
        val proofBytes = byteArrayOf(0x40, 0x41)
        val attachment = ProofAttachment(
            backend = "halo2/ipa",
            proofBytes = proofBytes,
            verifyingKeyRef = ProofVerifierKeyRef("halo2/ipa", "unshield-v3"),
            verifyingKeyCommitment = fill(0x55, 32),
            envelopeHash = IrohaHash.prehash(proofBytes),
        )

        val json = attachment.toNativeJson()
        assert(json.contains("\"backend\":\"halo2/ipa\""))
        assert(json.contains("\"proof_b64\":\"QEE=\""))
        assert(json.contains("\"vk_ref\":{\"backend\":\"halo2/ipa\",\"name\":\"unshield-v3\"}"))
        assert(json.contains("\"envelope_hash_hex\":\"99108c58a4d312fe46d8e0d5d36340d62413cd2ffb4b1c4ec8d78ea40b8679a1\""))
        assertFalse(json.contains("vk_inline"))
        val derivedEnvelopeJson = ProofAttachment(
            backend = "halo2/ipa",
            proofBytes = proofBytes,
            verifyingKeyRef = ProofVerifierKeyRef("halo2/ipa", "unshield-v3"),
        ).toNativeJson()
        assert(derivedEnvelopeJson.contains("\"envelope_hash_hex\":\"99108c58a4d312fe46d8e0d5d36340d62413cd2ffb4b1c4ec8d78ea40b8679a1\""))

        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                backend = "halo2/ipa",
                proofBytes = ByteArray(0),
                verifyingKeyRef = ProofVerifierKeyRef("halo2/ipa", "vk"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                backend = "halo2/ipa",
                proofBytes = byteArrayOf(1),
                verifyingKeyRef = ProofVerifierKeyRef("stark/fri", "vk"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                backend = "halo2/ipa",
                proofBytes = byteArrayOf(1),
                verifyingKeyRef = ProofVerifierKeyRef("halo2/ipa", "vk"),
                verifyingKeyCommitment = ByteArray(32),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                backend = "halo2/ipa",
                proofBytes = proofBytes,
                verifyingKeyRef = ProofVerifierKeyRef("halo2/ipa", "vk"),
                envelopeHash = fill(0x66, 32),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofVerifierKeyRef.fromWireId("missing-separator")
        }
    }

    @Test
    fun retiredGenericConfidentialSurfacesAreAbsent() {
        val packageName = "org.hyperledger.iroha.sdk.core.model.instructions."
        val methods = NativeSignerBridge::class.java.declaredMethods.map { it.name }.toSet()
        for (parts in listOf(listOf("Shi", "eld"), listOf("Zk", "Transfer"), listOf("Un", "shield"))) {
            val variant = parts.joinToString("")
            assertFailsWith<ClassNotFoundException> {
                Class.forName(packageName + variant + "Instruction")
            }
            assertFalse(methods.contains("encode" + variant + "SignedTransaction"))
            assertFalse(methods.contains("nativeEncode" + variant + "SignedTransaction"))
        }
    }

    @Test
    fun registerZkAssetInstructionBuildsVerifierControls() {
        val instruction = RegisterZkAssetInstruction.builder()
            .setAsset("rose#wonderland")
            .setUnshieldVerifyingKey("halo2/ipa:unshield-v3")
            .build()

        assertEquals(InstructionKind.REGISTER, instruction.kind)
        assertEquals("halo2/ipa:unshield-v3", instruction.arguments["vk_unshield"])
        assertEquals(setOf("action", "asset", "vk_unshield"), instruction.arguments.keys)
    }

    @Test
    fun nativeSignerRegisterZkAssetRejectsBadInputsBeforeNativeDispatch() {
        val register = RegisterZkAssetInstruction.builder()
            .setAsset("rose#wonderland")
            .build()

        assertFailsWith<IllegalArgumentException> {
                NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                    SigningAlgorithm.ED25519,
                    TestNetworkIds.canonical(),
                    AccountAddress.DEFAULT_I105_DISCRIMINANT,
                    "alice",
                0,
                0L,
                register,
                byteArrayOf(1),
                noFeePayment(),
            )
        }
    }

    @Test
    fun nativeSignerFeePaymentRejectsInvalidBoundsBeforeNativeDispatch() {
        assertFailsWith<IllegalArgumentException> {
            FeePaymentIntent.authority(emptyList(), 0)
        }
        assertFailsWith<IllegalArgumentException> {
            FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, "xor#universal", "1")
        }
        assertFailsWith<IllegalArgumentException> {
            FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, "7EAD8EFYUx1aVKZPUU1fyKvr8dF1", "0")
        }
        assertFailsWith<IllegalArgumentException> {
            FeePaymentIntent.authority(
                listOf(
                    FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, "7EAD8EFYUx1aVKZPUU1fyKvr8dF1", "1"),
                    FeeChargeLimit(FeeChargeKind.NEXUS, "7EAD8EFYUx1aVKZPUU1fyKvr8dF1", "1"),
                ),
            )
        }
    }

    @Test
    fun nativeSignedTransactionCopiesInputsAndOutputs() {
        val versioned = byteArrayOf(1, 2, 3)
        val hash = fill(0x30, 32)
        val signed = NativeSignedTransaction(versioned, hash)
        versioned[0] = 9
        hash[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), signed.versionedSignedTransaction)
        assertEquals(0x30, signed.transactionHash[0].toInt())
        val exposed = signed.versionedSignedTransaction
        exposed[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), signed.versionedSignedTransaction)

        assertFailsWith<IllegalArgumentException> {
            NativeSignedTransaction(ByteArray(0), fill(1, 32))
        }
        assertFailsWith<IllegalArgumentException> {
            NativeSignedTransaction(byteArrayOf(1), fill(1, 31))
        }
    }

    @Test
    fun nativeSignerRegisterZkAssetBindsFeePaymentWhenBridgeAvailable() {
        assertEquals(29, NativeSignerBridge.REQUIRED_BRIDGE_ABI_VERSION)
        assertEquals(7, NativeSignerBridge.REQUIRED_NATIVE_SIGNER_CONTRACT_REVISION)
        assertTrue(
            NativeSignerBridge.isNativeAvailable(),
            "connect_norito_bridge ABI 29 native-signer contract revision 7 is required",
        )

        val (privateKey, publicKey) = NativeSignerBridge.keypairFromSeed(
            SigningAlgorithm.ED25519,
            ByteArray(32) { index -> (index + 1).toByte() },
        )
        val authority = AccountAddress.fromAccount(publicKey, "ed25519").toI105Default()
        val gasAssetId = "7EAD8EFYUx1aVKZPUU1fyKvr8dF1"
        val gasLimit = 1_000L
        val feePayment = FeePaymentIntent.authority(
            listOf(FeeChargeLimit(FeeChargeKind.PIPELINE_GAS, gasAssetId, gasLimit.toString())),
            gasLimit,
        )

        val register = RegisterZkAssetInstruction.builder()
            .setAsset(gasAssetId)
            .build()
        assertNativeFeePayment(
            NativeSignerBridge.encodeRegisterZkAssetSignedTransaction(
                algorithm = SigningAlgorithm.ED25519,
                networkId = TestNetworkIds.canonical(),
                chainDiscriminant = AccountAddress.DEFAULT_I105_DISCRIMINANT,
                authority = authority,
                creationTimeMs = 1_736_000_000_000,
                ttlMs = null,
                instruction = register,
                privateKey = privateKey,
                feePayment = feePayment,
            ),
            feePayment,
        )

    }

    @Test
    fun registerZkAssetFromArgumentsRoundTrips() {
        val original = RegisterZkAssetInstruction.builder()
            .setAsset("rose#wonderland")
            .setUnshieldVerifyingKey("halo2/ipa:unshield-v3")
            .build()

        val restored = RegisterZkAssetInstruction.fromArguments(original.arguments)

        assertEquals(original.asset, restored.asset)
        assertEquals(original.unshieldVerifyingKey, restored.unshieldVerifyingKey)
        assertEquals(original.arguments, restored.arguments)
    }

    @Test
    fun registerZkAssetFromArgumentsOmitsBlankVerifyingKeys() {
        val original = RegisterZkAssetInstruction.builder()
            .setAsset("rose#wonderland")
            .build()

        val restored = RegisterZkAssetInstruction.fromArguments(original.arguments)

        assertEquals(null, restored.unshieldVerifyingKey)
        assertEquals(original.arguments, restored.arguments)
    }

    @Test
    fun registerZkAssetFromArgumentsRejectsRetiredShieldVerifierField() {
        val arguments = validRegisterArguments().toMutableMap()
        arguments["vk_shield"] = "halo2/ipa:shield-v3"
        assertFailsWith<IllegalArgumentException> {
            RegisterZkAssetInstruction.fromArguments(arguments)
        }
    }

    @Test
    fun registerZkAssetFromArgumentsRejectsMissingAsset() {
        val arguments = validRegisterArguments().toMutableMap()
        arguments.remove("asset")
        assertFailsWith<IllegalArgumentException> {
            RegisterZkAssetInstruction.fromArguments(arguments)
        }
    }

    @Test
    fun registerZkAssetFromArgumentsRejectsRetiredModeField() {
        val arguments = validRegisterArguments().toMutableMap()
        arguments["mode"] = "Hybrid"
        assertFailsWith<IllegalArgumentException> {
            RegisterZkAssetInstruction.fromArguments(arguments)
        }
    }

    @Test
    fun registerZkAssetFromArgumentsRejectsRetiredAllowFlag() {
        val arguments = validRegisterArguments().toMutableMap()
        arguments["allow_shield"] = "true"
        assertFailsWith<IllegalArgumentException> {
            RegisterZkAssetInstruction.fromArguments(arguments)
        }
    }

    @Test
    fun registerZkAssetFromArgumentsRejectsRetiredTransferVerifierField() {
        val arguments = validRegisterArguments().toMutableMap()
        arguments["vk_transfer"] = "halo2/ipa:transfer-v2"
        assertFailsWith<IllegalArgumentException> {
            RegisterZkAssetInstruction.fromArguments(arguments)
        }
    }

    private fun validRegisterArguments(): Map<String, String> =
        RegisterZkAssetInstruction.builder()
            .setAsset("rose#wonderland")
            .build()
            .arguments

    private fun assertNativeFeePayment(
        native: NativeSignedTransaction,
        expected: FeePaymentIntent,
    ) {
        val signed = SignedTransactionEncoder.decodeVersioned(native.versionedSignedTransaction)
        val payload = NoritoJavaCodecAdapter(org.hyperledger.iroha.sdk.address.AccountAddress.DEFAULT_I105_DISCRIMINANT).decodeTransaction(signed.encodedPayload())
        assertEquals(expected, payload.feePayment)
        assertFalse(payload.metadata.containsKey("gas_asset_id"))
        assertFalse(payload.metadata.containsKey("gas_limit"))
    }

    private fun noFeePayment(): FeePaymentIntent = FeePaymentIntent.authority(emptyList())

    private fun samplePayload(): ConfidentialEncryptedPayload =
        ConfidentialEncryptedPayload(
            ephemeralPublicKey = fill(0x11, 32),
            nonce = fill(0x22, 24),
            ciphertext = byteArrayOf(0x33, 0x34),
        )

    private fun fill(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

class ProofAttachmentTest {
    @Test
    fun `portable verifier identifiers match the Rust grammar exactly`() {
        val ref = ProofVerifierKeyRef("halo2/ipa", "halo2/ipa::transfer_v1")
        assertEquals("halo2/ipa:halo2/ipa::transfer_v1", ref.wireId())
        assertEquals(ref, ProofVerifierKeyRef.fromWireId(ref.wireId()))

        val invalid = listOf(
            " leading", "trailing ", "Uppercase", ".hidden", "trailing_", "a..b",
            "a//b", "a:::b", "a/:b", "a:/b", "a/.b", "a./b", "a:.b", "a.:b",
            "a\\b", "a\u200bb", "a\nb", "a+b",
        )
        for (value in invalid) {
            assertFailsWith<IllegalArgumentException>(value) {
                ProofVerifierKeyRef("halo2/ipa", value)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            ProofVerifierKeyRef("halo2/ipa", "a".repeat(257))
        }
    }

    @Test
    fun `ProofBox limit covers complete encoding without large allocations`() {
        val maximum = ProofAttachment.MAXIMUM_ENCODED_PROOF_BOX_BYTES
        val backendBytes = "halo2/ipa".encodeToByteArray().size.toLong()
        assertEquals(
            maximum,
            ProofAttachment.canonicalProofBoxEncodedLength(
                backendBytes,
                maximum - 23L,
            ),
        )
        assertEquals(
            maximum + 1L,
            ProofAttachment.canonicalProofBoxEncodedLength(
                backendBytes,
                maximum - 22L,
            ),
        )
        assertEquals(137L, ProofAttachment.canonicalProofBoxEncodedLength(126L, 0L))
        assertEquals(139L, ProofAttachment.canonicalProofBoxEncodedLength(127L, 0L))
        assertEquals(141L, ProofAttachment.canonicalProofBoxEncodedLength(128L, 0L))
        assertEquals(131L, ProofAttachment.canonicalProofBoxEncodedLength(1L, 119L))
        assertEquals(133L, ProofAttachment.canonicalProofBoxEncodedLength(1L, 120L))
        assertEquals(16_388L, ProofAttachment.canonicalProofBoxEncodedLength(1L, 16_375L))
        assertEquals(16_390L, ProofAttachment.canonicalProofBoxEncodedLength(1L, 16_376L))
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment.canonicalProofBoxEncodedLength(Long.MAX_VALUE, 1L)
        }
    }

    @Test
    fun `proof attachment validates commitments hashes and exact native JSON`() {
        val proof = byteArrayOf(1, 2)
        val lane = sampleLanePrivacy()
        val attachment = ProofAttachment(
            "halo2/ipa",
            proof,
            ProofVerifierKeyRef("halo2/ipa", "vk_transfer"),
            ByteArray(32) { 0x55 },
            IrohaHash.prehash(proof),
            lane,
        )
        val root = Json.parseToJsonElement(attachment.toNativeJson()).jsonObject
        assertEquals(
            setOf(
                "backend", "proof_b64", "vk_ref", "vk_commitment_hex",
                "envelope_hash_hex", "lane_privacy",
            ),
            root.keys,
        )
        assertFalse("proof_backend" in root)
        assertFalse("vk_inline" in root)
        assertEquals(
            setOf("commitment_id", "witness"),
            root.getValue("lane_privacy").jsonObject.keys,
        )

        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                "halo2/ipa",
                proof,
                ProofVerifierKeyRef("halo2/ipa", "vk_transfer"),
                ByteArray(32),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                "halo2/ipa",
                proof,
                ProofVerifierKeyRef("halo2/ipa", "vk_transfer"),
                envelopeHash = ByteArray(32) { 0x66 },
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ProofAttachment(
                "halo2/ipa",
                proof,
                ProofVerifierKeyRef("stark/fri", "vk_transfer"),
            )
        }
    }

    @Test
    fun `lane privacy API canonicalizes raw siblings and is defensive`() {
        val leaf = ByteArray(32) { 0x11 }
        val sibling = ByteArray(32) { 0x22 }
        val witness = LanePrivacyMerkleWitness(leaf, 1L, listOf(sibling, ByteArray(32) { 0x44 }))
        leaf[0] = 0
        sibling[0] = 0
        assertEquals(0x11, witness.leafBytes()[0].toInt() and 0xff)
        assertEquals(0x22, witness.auditPathBytes()[0][0].toInt() and 0xff)
        assertEquals(0x23, witness.auditPathBytes()[0].last().toInt() and 0xff)
        val exposed = witness.auditPathBytes()[0]
        exposed[0] = 0
        assertEquals(0x22, witness.auditPathBytes()[0][0].toInt() and 0xff)

        assertFailsWith<IllegalArgumentException> {
            LanePrivacyMerkleWitness(ByteArray(32), 0L, emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            LanePrivacyMerkleWitness(ByteArray(32), 2L, listOf(ByteArray(32)))
        }
        assertFailsWith<IllegalArgumentException> {
            LanePrivacyMerkleWitness(
                ByteArray(32),
                0L,
                List(LanePrivacyMerkleWitness.MAX_DEPTH + 1) { ByteArray(32) },
            )
        }
        assertFailsWith<IllegalArgumentException> {
            LanePrivacyMerkleWitness(ByteArray(31), 0L, listOf(ByteArray(32)))
        }
        assertFailsWith<IllegalArgumentException> {
            LanePrivacyMerkleWitness(ByteArray(32), 0x1_0000_0000L, listOf(ByteArray(32)))
        }
        assertFailsWith<IllegalArgumentException> {
            LanePrivacyProof(0x1_0000, LanePrivacyWitness.merkle(witness))
        }
    }

    @Test
    fun `lane privacy third tail matches the canonical Norito layout`() {
        val attachment = sampleAttachment()
        val encoded = TransactionPayloadAdapter.encodeProofAttachmentPayload(attachment)
        val expected = manualAttachmentPayload(
            leafIndex = 1L,
            auditPath = listOf(marked(0x22), marked(0x44)),
        )
        assertContentEquals(expected, encoded)
        assertEquals(
            attachment,
            TransactionPayloadAdapter.decodeProofAttachmentPayload(encoded),
        )
    }

    @Test
    fun `all proof attachment tails match current Rust under both length layouts`() {
        val rows = FixtureGeneratorRunner.run("proof-attachments-v1")
        val seen = mutableSetOf<Pair<Int, Int>>()
        for (row in rows) {
            val columns = row.split('\t')
            assertEquals(3, columns.size)
            val flags = columns[0].toInt()
            val mask = columns[1].toInt()
            assertTrue(flags in listOf(0, NoritoHeader.COMPACT_LEN))
            assertTrue(mask in 0..7)
            assertTrue(seen.add(flags to mask), "duplicate fixture row")
            val attachment = attachmentWithTailMask(mask)
            val rust = FixtureGeneratorRunner.hexToBytes(columns[2])
            assertContentEquals(rust, TransactionPayloadAdapter.encodeProofAttachmentPayload(attachment, flags))
            assertEquals(attachment, TransactionPayloadAdapter.decodeProofAttachmentPayload(rust, flags))
        }
        assertEquals(16, seen.size)
    }

    @Test
    fun `proof attachment rejects redundant absent tails under both length layouts`() {
        for (flags in listOf(0, NoritoHeader.COMPACT_LEN)) {
            val absentField = NoritoEncoder(flags).apply {
                writeLength(1L, flags and NoritoHeader.COMPACT_LEN != 0)
                writeByte(0)
            }.toByteArray()
            for (mask in 0..7) {
                val attachment = attachmentWithTailMask(mask)
                val canonical = TransactionPayloadAdapter.encodeProofAttachmentPayload(attachment, flags)
                assertEquals(attachment, TransactionPayloadAdapter.decodeProofAttachmentPayload(canonical, flags))
                val tail = when {
                    mask and 4 != 0 -> 3
                    mask and 2 != 0 -> 2
                    mask and 1 != 0 -> 1
                    else -> 0
                }
                var padded = canonical
                repeat(3 - tail) {
                    padded += absentField
                    assertFailsWith<IllegalArgumentException> {
                        TransactionPayloadAdapter.decodeProofAttachmentPayload(padded, flags)
                    }
                }
            }
        }
    }

    private fun attachmentWithTailMask(mask: Int): ProofAttachment {
        val proof = byteArrayOf(1, 2)
        return ProofAttachment(
            "pipa-r/pasta",
            proof,
            ProofVerifierKeyRef("pipa-r/pasta", "vk_transfer"),
            if (mask and 1 != 0) ByteArray(32) { 0x55 } else null,
            if (mask and 2 != 0) IrohaHash.prehash(proof) else null,
            if (mask and 4 != 0) sampleLanePrivacy() else null,
        )
    }

    @Test
    fun `lane privacy roundtrips under both supported Norito length layouts`() {
        val attachment = sampleAttachment()
        for (flags in listOf(0, NoritoHeader.COMPACT_LEN)) {
            val encoded = TransactionPayloadAdapter.encodeProofAttachmentPayload(attachment, flags)
            assertEquals(
                attachment,
                TransactionPayloadAdapter.decodeProofAttachmentPayload(encoded, flags),
                "flags=$flags",
            )
        }
    }

    @Test
    fun `lane privacy Norito decoder fails closed on adversarial paths`() {
        val malformed = listOf(
            manualAttachmentPayload(0L, emptyList()),
            manualAttachmentPayload(0L, listOf(null)),
            manualAttachmentPayload(0L, listOf(ByteArray(32) { 0x22 })),
            manualAttachmentPayload(2L, listOf(ByteArray(32) { 0x23 })),
            manualAttachmentPayload(
                0L,
                List(LanePrivacyMerkleWitness.MAX_DEPTH + 1) { ByteArray(32) { 0x23 } },
            ),
            manualAttachmentPayload(0L, listOf(ByteArray(31) { 0x23 })),
            manualAttachmentPayload(0L, listOf(ByteArray(32) { 0x23 }), witnessTag = 7L),
        )
        for (payload in malformed) {
            assertFailsWith<IllegalArgumentException> {
                TransactionPayloadAdapter.decodeProofAttachmentPayload(payload)
            }
        }

        val trailingTail = manualAttachmentPayload(
            0L,
            listOf(ByteArray(32) { 0x23 }),
        ) + field(byteArrayOf(0))
        assertFailsWith<IllegalArgumentException> {
            TransactionPayloadAdapter.decodeProofAttachmentPayload(trailingTail)
        }

        val oversizedProofBox = ByteArrayOutputStream().apply {
            write(field(encodeString("halo2/ipa")))
            write(u64(ProofAttachment.MAXIMUM_ENCODED_PROOF_BOX_BYTES + 1L))
        }.toByteArray()
        val oversizedAttachmentBackend = u64(8L + 256L + 1L)
        val oversizedProofBackend = ByteArrayOutputStream().apply {
            write(field(encodeString("halo2/ipa")))
            write(field(u64(8L + 256L + 1L)))
        }.toByteArray()
        val oversizedVerifierReference = ByteArrayOutputStream().apply {
            write(requiredAttachmentPrefix())
            write(u64(2L * (8L + 8L + 256L) + 1L))
        }.toByteArray()
        val oversizedCommitment = ByteArrayOutputStream().apply {
            write(requiredAttachmentPrefix())
            write(u64(1L + 8L + 32L * 9L + 1L))
        }.toByteArray()
        for (payload in listOf(
            oversizedProofBox,
            oversizedAttachmentBackend,
            oversizedProofBackend,
            oversizedVerifierReference,
            oversizedCommitment,
        )) {
            assertFailsWith<IllegalArgumentException> {
                TransactionPayloadAdapter.decodeProofAttachmentPayload(payload)
            }
        }
    }

    private fun sampleAttachment(): ProofAttachment = ProofAttachment(
        "pipa-r/pasta",
        byteArrayOf(1, 2),
        ProofVerifierKeyRef("pipa-r/pasta", "vk_transfer"),
        lanePrivacy = sampleLanePrivacy(),
    )

    private fun sampleLanePrivacy(): LanePrivacyProof = LanePrivacyProof(
        7,
        LanePrivacyWitness.merkle(
            LanePrivacyMerkleWitness(
                ByteArray(32) { 0xaa.toByte() },
                1L,
                listOf(ByteArray(32) { 0x22 }, ByteArray(32) { 0x44 }),
            ),
        ),
    )

    private fun manualAttachmentPayload(
        leafIndex: Long,
        auditPath: List<ByteArray?>,
        witnessTag: Long = 0L,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(requiredAttachmentPrefix())
        output.write(field(byteArrayOf(0)))
        output.write(field(byteArrayOf(0)))
        output.write(field(option(manualLanePrivacy(leafIndex, auditPath, witnessTag))))
        return output.toByteArray()
    }

    private fun requiredAttachmentPrefix(): ByteArray {
        val backend = "pipa-r/pasta"
        return ByteArrayOutputStream().apply {
            write(field(encodeString(backend)))
            write(field(manualProofBox(backend, byteArrayOf(1, 2))))
            write(field(manualVerifyingKeyRef(backend, "vk_transfer")))
        }.toByteArray()
    }

    private fun manualProofBox(backend: String, proof: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            write(field(encodeString(backend)))
            write(field(u64(proof.size.toLong()) + proof))
        }.toByteArray()

    private fun manualVerifyingKeyRef(backend: String, name: String): ByteArray =
        ByteArrayOutputStream().apply {
            write(field(encodeString(backend)))
            write(field(encodeString(name)))
        }.toByteArray()

    private fun manualLanePrivacy(
        leafIndex: Long,
        auditPath: List<ByteArray?>,
        witnessTag: Long,
    ): ByteArray {
        val path = ByteArrayOutputStream().apply {
            write(u64(auditPath.size.toLong()))
            for (sibling in auditPath) write(field(option(sibling)))
        }.toByteArray()
        val merkleProof = field(u32(leafIndex)) + field(path)
        val merkleWitness = field(ByteArray(32) { 0xaa.toByte() }) + field(merkleProof)
        val witness = u32(witnessTag) + field(merkleWitness)
        return field(field(u16(7))) + field(witness)
    }

    private fun option(payload: ByteArray?): ByteArray =
        if (payload == null) byteArrayOf(0) else byteArrayOf(1) + u64(payload.size.toLong()) + payload

    private fun marked(value: Int): ByteArray =
        ByteArray(32) { value.toByte() }.also { it[it.lastIndex] = (it.last().toInt() or 1).toByte() }

    private fun field(payload: ByteArray): ByteArray = u64(payload.size.toLong()) + payload

    private fun encodeString(value: String): ByteArray {
        val bytes = value.encodeToByteArray()
        return u64(bytes.size.toLong()) + bytes
    }

    private fun u16(value: Int): ByteArray =
        ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(value.toShort()).array()

    private fun u32(value: Long): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value.toInt()).array()

    private fun u64(value: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()

}
