package org.hyperledger.iroha.sdk.tx.norito

import java.nio.file.Files
import java.nio.file.Paths
import java.util.Base64
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.core.model.OrderedIntentDigestV1
import org.hyperledger.iroha.sdk.core.model.SignedAttachmentLimitsV1
import org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment
import org.hyperledger.iroha.sdk.core.model.instructions.ProofVerifierKeyRef

/** Exact-source assertions runnable independently of the native account admission boundary. */
internal object SignedAttachmentsCodecAssertions {
    private val codec = TransactionPayloadAdapter.forChain(369)
    private fun rejects(message: String, block: () -> Unit) {
        try { block() } catch (error: IllegalArgumentException) {
            check(error.message?.contains(message) == true) { error.message ?: "missing error" }; return
        }
        error("malformed carrier plan was accepted")
    }

    fun canonicalRustFramesAndDigests() {
        var root = Paths.get("").toAbsolutePath()
        while (!Files.exists(root.resolve("fixtures/zk/signed_attachments_v1/vectors.json"))) {
            root = checkNotNull(root.parent) { "shared fixture not found" }
        }
        @Suppress("UNCHECKED_CAST")
        val vectors = JsonParser.parse(String(Files.readAllBytes(root.resolve(
            "fixtures/zk/signed_attachments_v1/vectors.json")), Charsets.UTF_8)) as Map<String, Any?>
        var checked = 0
        for (raw in vectors["accepted"] as List<*>) {
            val vector = raw as Map<*, *>
            val name = vector["name"] as String
            // These two require complete account admission and are exercised by the payload suite.
            if (name == "contract_subject_nested_invocation" || name == "explicit_account_direct_invocation") continue
            val frame = Base64.getDecoder().decode(vector["attachments_frame_base64"] as String)
            val attachments = codec.decodeAttachmentsFrame(frame)
            val intent = OrderedIntentDigestV1(hex(vector["ordered_intent_digest_hex"] as String))
            val digests = vector["statement_digests_hex"] as List<*>
            attachments.actions.forEachIndexed { index, action ->
                check(codec.actionStatementDigest(action, intent).bytes.contentEquals(hex(digests[index] as String)))
            }
            val corrupted = frame.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            rejects("Checksum mismatch") { codec.decodeAttachmentsFrame(corrupted) }
            checked++
        }
        check(checked == 5)
    }

    fun carrierSizePreflightRejectsBeforeProofEncoding() {
        fun proof(size: Int) = ProofAttachment("halo2/ipa", ByteArray(size) { 1 }, ProofVerifierKeyRef("halo2/ipa", "vk"))
        codec.preflightProofAttachments(listOf(proof(3)))
        rejects("before encoding") {
            codec.preflightProofAttachments(listOf(proof(SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES + 1)))
        }
        val part = proof(5 * 1024 * 1024)
        rejects("aggregate bound") { codec.preflightProofAttachments(listOf(part, part)) }
        val excessive = object : AbstractList<ProofAttachment>() {
            override val size = 17
            override fun get(index: Int): ProofAttachment = error("count must be rejected before reading a proof")
        }
        rejects("count") { codec.preflightProofAttachments(excessive) }
        rejects("frame exceeds") { codec.decodeAttachmentsFrame(ByteArray(SignedAttachmentLimitsV1.MAX_FRAME_BYTES + 1)) }
    }

    fun aggregateFrameBoundaryIsExact() {
        // Two carrier descriptors have equal encoded sizes: all index/length fields are fixed-width.
        // This independent field accounting pins the complete frame, including compact prefixes.
        fun field(size: Long): Long {
            var remaining = size
            var width = 1L
            while (remaining >= 128) { remaining = remaining ushr 7; width++ }
            return size + width
        }
        val reference = field(4) + field(4) + field(4) + field(8) + field(field(32))
        val action = field(4) + field(4) + field(4) + field(4) + field(4) +
            2 * field(field(32)) + field(8 + field(reference))
        val actions = 8 + 2 * field(action)
        fun frameSize(first: Long, second: Long): Long {
            fun occurrence(bytes: Long): Long = field(4) + field(4) + field(8) + field(field(32)) + field(8 + bytes)
            return 40 + field(actions) + field(8 + field(occurrence(first)) + field(occurrence(second)))
        }
        val first = 4L * 1024 * 1024
        val maximum = SignedAttachmentLimitsV1.MAX_FRAME_BYTES.toLong()
        val second = maximum - frameSize(first, 4L * 1024 * 1024) + 4L * 1024 * 1024
        check(frameSize(first, second) == maximum)
        codec.preflightCarrierSizes(listOf(first, second))
        rejects("aggregate bound") { codec.preflightCarrierSizes(listOf(first, second + 1)) }
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
