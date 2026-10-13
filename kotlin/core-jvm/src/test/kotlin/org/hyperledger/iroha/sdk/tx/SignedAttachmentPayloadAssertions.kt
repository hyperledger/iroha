package org.hyperledger.iroha.sdk.tx

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder
import org.hyperledger.iroha.sdk.tx.norito.InstructionWireIdsV1
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.TairaTestnetProfile
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

/** The canonical Rust vectors pin every byte and hash preimage, including signed attachment Some. */
internal object SignedAttachmentPayloadAssertions {
    private val adapter = NoritoJavaCodecAdapter(TairaTestnetProfile.I105_DISCRIMINANT)

    fun attachmentFreeRoundtrips() {
        val entry = vectors().objectValue("attachment_free")
        val payload = hex(entry.text("payload_hex"))

        val decoded = adapter.decodeTransaction(payload)

        assertEquals(null, decoded.attachments)
        assertContentEquals(payload, adapter.encodeTransaction(decoded))
    }

    fun acceptedPayloadsAndDigests() {
        val accepted = vectors().arrayValue("accepted")
        assertEquals(7, accepted.size)
        for (entry in accepted) {
            val vector = entry.objectValue()
            val payload = hex(vector.text("payload_hex"))

            val decoded = adapter.decodeTransaction(payload)
            assertContentEquals(hex(vector.text("ordered_intent_projection_hex")), adapter.orderedIntentProjection(decoded))
            assertContentEquals(hex(vector.text("ordered_intent_digest_hex")), adapter.orderedIntentDigest(decoded).bytes)
            val digests = vector.arrayValue("statement_digests_hex")
            decoded.attachments!!.actions.forEachIndexed { index, action ->
                assertContentEquals(hex(digests[index] as String), action.statementDigest.bytes)
            }
            val signed = decodeSignedFrame(hex(vector.text("signed_transaction_hex")))
            assertContentEquals(payload, signed.encodedPayload())

            assertContentEquals(payload, adapter.encodeTransaction(decoded))
        }
    }

    fun rejectedPayloads() {
        // Establish a working native/account boundary before any negative assertion can pass.
        val valid = vectors().arrayValue("accepted").first().objectValue()
        adapter.decodeTransaction(hex(valid.text("payload_hex")))
        val rejected = vectors().arrayValue("rejected")
        assertEquals(12, rejected.size)
        for (entry in rejected) {
            val vector = entry.objectValue()
            var rejected = false
            try {
                val signed = decodeSignedFrame(hex(vector.text("signed_transaction_hex")))
                adapter.decodeTransaction(signed.encodedPayload())
            } catch (_: Exception) {
                rejected = true
            }
            check(rejected) { "accepted rejected vector ${vector.text("name")}" }
        }
    }

    fun carrierConstructionAndRebinding() {
        val vector = vectors().arrayValue("accepted").first().objectValue()
        val bytes = hex(vector.text("payload_hex"))
        val payload = adapter.decodeTransaction(bytes)
        val plain = payload.copy(attachments = null)
        fun proof(content: ByteArray) = org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment(
            "halo2/ipa", content, org.hyperledger.iroha.sdk.core.model.instructions.ProofVerifierKeyRef("halo2/ipa", "vk_a"))
        val constructed = adapter.withProofAttachments(plain, listOf(proof(byteArrayOf(1, 2, 3))))
        assertContentEquals(bytes, adapter.encodeTransaction(constructed))
        val replaced = adapter.withProofAttachments(plain, listOf(proof(byteArrayOf(4, 5, 6))))
        assertEquals(adapter.orderedIntentDigest(constructed), adapter.orderedIntentDigest(replaced))
        check(!adapter.encodeTransaction(constructed).contentEquals(adapter.encodeTransaction(replaced)))
        val changed = constructed.copy(nonce = 8L)
        var staleRefused = false
        try { adapter.encodeTransaction(changed) } catch (_: org.hyperledger.iroha.sdk.tx.norito.NoritoException) {
            staleRefused = true
        }
        check(staleRefused) { "independent intent mutation retained a stale statement" }
        val rebound = adapter.bindAttachmentStatements(changed)
        adapter.encodeTransaction(rebound)
        check(rebound.attachments!!.actions[0].statementDigest != constructed.attachments!!.actions[0].statementDigest)
        assertContentEquals(bytes, adapter.encodeTransaction(constructed))
    }

    fun provedExecutableBindings() {
        val vector = vectors().arrayValue("accepted").map { it.objectValue() }
            .single { it.text("name") == "ivm_proved_execution_carrier" }
        val bytes = hex(vector.text("payload_hex"))
        val payload = adapter.decodeTransaction(bytes)
        val proved = payload.executable as org.hyperledger.iroha.sdk.core.model.Executable.IvmProved
        // Locate the overlay's declared count through canonical field boundaries, not byte search.
        val cursor = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val fields = org.hyperledger.iroha.sdk.norito.NoritoDecoder(cursor,
            org.hyperledger.iroha.sdk.norito.NoritoCodec.DEFAULT_FLAGS)
        repeat(3) { fields.readBytes(fields.readLength(true).toInt()) }
        fields.readLength(true) // executable field
        val executableTagOffset = cursor.position()
        check(fields.readUInt(32) == 3L)
        fields.readLength(true) // proved variant field
        fields.readBytes(fields.readLength(true).toInt()) // bytecode
        val overlaySize = fields.readLength(true).toInt()
        val overlayCountOffset = cursor.position()
        fields.readBytes(overlaySize)
        check(fields.readLength(true) == 32L)
        val eventsOffset = cursor.position()
        fun refusesWire(candidate: ByteArray, reason: String) {
            var refused = false
            try { adapter.decodeTransaction(candidate) } catch (error: org.hyperledger.iroha.sdk.tx.norito.NoritoException) {
                refused = generateSequence<Throwable>(error) { it.cause }.any { it.message?.contains(reason) == true }
            }
            check(refused) { "malformed IvmProved did not report $reason" }
        }
        val excessiveOverlay = bytes.copyOf()
        java.nio.ByteBuffer.wrap(excessiveOverlay).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putLong(overlayCountOffset, 1_000_000L)
        refusesWire(excessiveOverlay, "instruction count exceeds")
        refusesWire(bytes.copyOf().also { it[eventsOffset + 31] = 0 }, "marked hash")
        val unknownTag = bytes.copyOf()
        java.nio.ByteBuffer.wrap(unknownTag).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(executableTagOffset, 99)
        refusesWire(unknownTag, "Unknown Executable")
        val originalCode = proved.ivmBytes
        val mutatedCode = originalCode.copyOf().also { it[0] = 99 }
        val digest = adapter.orderedIntentDigest(payload)
        val hash = ByteArray(32).also { it[31] = 1 }
        val newOutputs = org.hyperledger.iroha.sdk.core.model.Executable.IvmProved(
            originalCode, emptyList(), hash, hash)
        val changedOutputs = payload.copy(executable = newOutputs)
        assertEquals(digest, adapter.orderedIntentDigest(changedOutputs))
        adapter.encodeTransaction(changedOutputs)
        val changedCode = payload.copy(executable = org.hyperledger.iroha.sdk.core.model.Executable.IvmProved(
            mutatedCode, proved.overlay, proved.eventsCommitment, proved.gasPolicyCommitment))
        check(digest != adapter.orderedIntentDigest(changedCode))
        var rejected = false
        try { adapter.encodeTransaction(changedCode) } catch (_: Exception) { rejected = true }
        check(rejected) { "code change retained a stale execution statement" }
        val proof = org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment("halo2/ipa",
            byteArrayOf(1, 2, 3), org.hyperledger.iroha.sdk.core.model.instructions.ProofVerifierKeyRef("halo2/ipa", "ivm_v1"))
        assertContentEquals(bytes, adapter.encodeTransaction(adapter.withIvmExecutionProof(payload.copy(attachments = null), proof)))
        rejected = false
        try { adapter.withIvmExecutionProof(payload.copy(executable = org.hyperledger.iroha.sdk.core.model.Executable.instructions(emptyList())), proof) }
        catch (_: IllegalArgumentException) { rejected = true }
        check(rejected) { "execution proof accepted an ordinary executable" }
        originalCode[0] = 99
        hash[31] = 0
        check(proved.ivmBytes[0] == 1.toByte())
        check(newOutputs.eventsCommitment[31] == 1.toByte())
        check(proved.requiresTransactionGasLimit())
        check(proved == org.hyperledger.iroha.sdk.core.model.Executable.IvmProved(
            proved.ivmBytes, proved.overlay, proved.eventsCommitment, proved.gasPolicyCommitment))
        check(proved.hashCode() == org.hyperledger.iroha.sdk.core.model.Executable.IvmProved(
            proved.ivmBytes, proved.overlay, proved.eventsCommitment, proved.gasPolicyCommitment).hashCode())
        for (invalid in listOf(ByteArray(31), ByteArray(32))) {
            rejected = false
            try { org.hyperledger.iroha.sdk.core.model.Executable.IvmProved(byteArrayOf(1), emptyList(), invalid, invalid) }
            catch (_: IllegalArgumentException) { rejected = true }
            check(rejected) { "invalid commitment was accepted" }
        }
    }

    fun typedPrivacyProjections() {
        val limits = vectors().objectValue("privacy_frame_limits")
        assertEquals((limits["envelope_bytes"] as Number).toInt(),
            org.hyperledger.iroha.sdk.privacy.PRIVACY_ACTION_ENVELOPE_MAX_BYTES_V1)
        assertEquals((limits["submit_frame_bytes"] as Number).toInt(),
            org.hyperledger.iroha.sdk.privacy.PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1)
        assertEquals((limits["block_privacy_bytes"] as Number).toInt(),
            org.hyperledger.iroha.sdk.privacy.PRIVACY_BLOCK_MAX_BYTES_V1)
        val rows = vectors().arrayValue("privacy_intents")
        assertEquals(24, rows.size)
        for (entry in rows) {
            val row = entry.objectValue()
            val payload = adapter.decodeTransaction(hex(row.text("payload_hex")))
            val expected = hex(row.text("ordered_intent_projection_hex"))
            assertContentEquals(expected, adapter.orderedIntentProjection(payload))
            assertContentEquals(hex(row.text("ordered_intent_digest_hex")), adapter.orderedIntentDigest(payload).bytes)
            val instructionFrame = hex(row.text("instruction_frame_hex"))
            assertContentEquals(hex(row.text("instruction_projection_hex")),
                org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge.submitProofIntentProjectionV1(instructionFrame).bytes())
            fun replacing(frame: ByteArray): org.hyperledger.iroha.sdk.core.model.TransactionPayload {
                fun instruction(value: org.hyperledger.iroha.sdk.core.model.InstructionBox): org.hyperledger.iroha.sdk.core.model.InstructionBox =
                    if (value.name == "iroha.privacy.submit_proof.v1")
                        org.hyperledger.iroha.sdk.core.model.InstructionBox.fromWirePayload(value.name, frame) else value
                val executable = when (val original = payload.executable) {
                    is org.hyperledger.iroha.sdk.core.model.Executable.Instructions ->
                        org.hyperledger.iroha.sdk.core.model.Executable.Instructions(original.instructions.map(::instruction))
                    is org.hyperledger.iroha.sdk.core.model.Executable.Batch ->
                        org.hyperledger.iroha.sdk.core.model.Executable.Batch(original.entries.map {
                            if (it is org.hyperledger.iroha.sdk.core.model.ExecutableBatchItem.Instruction)
                                org.hyperledger.iroha.sdk.core.model.ExecutableBatchItem.Instruction(instruction(it.instruction)) else it
                        })
                    else -> error("privacy fixture must be direct or batch")
                }
                return payload.copy(executable = executable)
            }
            assertContentEquals(expected, adapter.orderedIntentProjection(replacing(hex(row.text("generated_fields_changed_frame_hex")))))
            check(!expected.contentEquals(adapter.orderedIntentProjection(replacing(hex(row.text("independent_context_changed_frame_hex"))))))
            // Hashing never grants governed construction admission, including after a valid projection.
            var refused = false
            try { adapter.encodeTransaction(payload) } catch (_: org.hyperledger.iroha.sdk.tx.norito.NoritoException) { refused = true }
            check(refused) { "privacy projection accidentally granted construction admission" }
            val wrongSchema = instructionFrame.copyOf().also { it[6] = (it[6].toInt() xor 1).toByte() }
            val checksumDamage = instructionFrame.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            for (bad in listOf(byteArrayOf(), instructionFrame.copyOf(instructionFrame.size - 1),
                               instructionFrame + byteArrayOf(0), wrongSchema, checksumDamage)) {
                refused = false
                try { org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge.submitProofIntentProjectionV1(bad) }
                catch (_: IllegalArgumentException) { refused = true }
                check(refused) { "malformed typed instruction projected successfully" }
            }
        }
        var oversized = false
        try { org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge.submitProofIntentProjectionV1(
            ByteArray(org.hyperledger.iroha.sdk.privacy.PRIVACY_SUBMIT_PROOF_FRAME_MAX_BYTES_V1 + 1)) }
        catch (_: IllegalArgumentException) { oversized = true }
        check(oversized) { "oversized typed instruction entered the codec" }
    }

    fun nativeRegistryMatches() {
        val source = String(Files.readAllBytes(findVectors().parent.parent.parent.parent
            .resolve("crates/iroha_data_model/src/isi/registry/wire_ids.rs")), StandardCharsets.UTF_8)
        val expected = Regex("=>\\s*\"(iroha\\.[^\"]+)\"").findAll(source).map { it.groupValues[1] }.toSet()
        assertTrue(expected.isNotEmpty())
        assertEquals(expected, InstructionWireIdsV1.values)
    }

    private fun decodeSignedFrame(bytes: ByteArray): SignedTransaction {
        val frame = org.hyperledger.iroha.sdk.norito.NoritoHeader.decode(bytes,
            org.hyperledger.iroha.sdk.norito.SchemaHash.hash16("iroha_data_model::transaction::signed::model::SignedTransaction"))
        frame.header.validateChecksum(frame.payload)
        assertEquals(org.hyperledger.iroha.sdk.norito.NoritoCodec.DEFAULT_FLAGS, frame.header.flags)
        return SignedTransactionEncoder.decode(frame.payload)
    }

    private fun assertEquals(expected: Any?, actual: Any?) = check(expected == actual) { "expected $expected, got $actual" }
    private fun assertContentEquals(expected: ByteArray, actual: ByteArray) = check(expected.contentEquals(actual)) { "canonical bytes differ" }
    private fun assertTrue(value: Boolean) = check(value)

    private fun vectors(): MutableMap<String, Any?> = JsonParser.parse(
        String(Files.readAllBytes(findVectors()), StandardCharsets.UTF_8),
    ).objectValue()

    private fun findVectors(): Path {
        var current = Paths.get("").toAbsolutePath().normalize()
        repeat(8) {
            val candidate = current.resolve(FixturePath.VECTORS)
            if (Files.isRegularFile(candidate)) return candidate
            current = current.parent ?: return@repeat
        }
        error("${FixturePath.VECTORS} was not found from the test working directory")
    }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0) { "hex text has an odd length" }
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun MutableMap<String, Any?>.text(key: String): String =
        this[key] as? String ?: error("vector field $key must be text")

    private fun MutableMap<String, Any?>.objectValue(key: String): MutableMap<String, Any?> =
        this[key].objectValue()

    private fun MutableMap<String, Any?>.arrayValue(key: String): List<Any?> =
        this[key] as? List<Any?> ?: error("vector field $key must be an array")

    @Suppress("UNCHECKED_CAST")
    private fun Any?.objectValue(): MutableMap<String, Any?> =
        this as? MutableMap<String, Any?> ?: error("vector value must be an object")

    private object FixturePath {
        const val VECTORS = "fixtures/zk/signed_attachments_v1/vectors.json"
    }
}
