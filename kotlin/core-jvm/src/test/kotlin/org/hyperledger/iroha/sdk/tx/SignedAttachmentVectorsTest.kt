package org.hyperledger.iroha.sdk.tx

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.TairaTestnetProfile
import org.hyperledger.iroha.sdk.tx.norito.NoritoException
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import org.hyperledger.iroha.sdk.tx.norito.TransactionPayloadAdapter

/**
 * Shared vectors of the signed attachment layout (`fixtures/zk/signed_attachments_v1`).
 *
 * The SDK codec implements only the attachment-free form of the ninth payload field. The first
 * test pins that form: its vector round-trips byte for byte. The second test is the conformance
 * check of the current layout and fails until the codec implements `SignedAttachmentsV1`
 * (ZK delivery plan tasks S.1 and S.3). Until then the codec refuses every attachment-bearing
 * payload with a typed message, so it can neither write nor read the retired proof-attachment
 * list layout; `SignedTransactionHasherTest` pins the refusal on the encoding side.
 */
class SignedAttachmentVectorsTest {
    private val adapter = NoritoJavaCodecAdapter(TairaTestnetProfile.I105_DISCRIMINANT)

    @Test
    fun `attachment free vector round trips byte for byte`() {
        val entry = vectors().objectValue("attachment_free")
        val payload = hex(entry.text("payload_hex"))

        val decoded = adapter.decodeTransaction(payload)

        assertEquals(null, decoded.attachments)
        assertContentEquals(payload, adapter.encodeTransaction(decoded))
    }

    @Test
    fun `attachment bearing vectors decode and re-encode byte for byte`() {
        val accepted = vectors().arrayValue("accepted")
        assertEquals(2, accepted.size)
        for (entry in accepted) {
            val vector = entry.objectValue()
            val payload = hex(vector.text("payload_hex"))

            val decoded = try {
                adapter.decodeTransaction(payload)
            } catch (refusal: NoritoException) {
                // TODO(S.1, S.3): implement `SignedAttachmentsV1` in `TransactionPayloadAdapter`
                // (layout: `norito.md`, "Signed attachments and ordered intent"). This check stays
                // red until the codec decodes, validates and re-encodes these vectors.
                assertTrue(
                    generateSequence<Throwable>(refusal) { it.cause }
                        .any { it.message == TransactionPayloadAdapter.SIGNED_ATTACHMENTS_UNSUPPORTED },
                    "expected the typed unsupported-attachments refusal, got $refusal",
                )
                throw AssertionError(
                    "vector ${vector.text("name")}: the Kotlin codec does not implement " +
                        "SignedAttachmentsV1 (ZK delivery plan S.1/S.3)",
                    refusal,
                )
            }

            assertContentEquals(payload, adapter.encodeTransaction(decoded))
        }
    }

    private fun vectors(): MutableMap<String, Any?> = JsonParser.parse(
        String(Files.readAllBytes(findVectors()), StandardCharsets.UTF_8),
    ).objectValue()

    private fun findVectors(): Path {
        var current = Paths.get("").toAbsolutePath().normalize()
        repeat(8) {
            val candidate = current.resolve(VECTORS)
            if (Files.isRegularFile(candidate)) return candidate
            current = current.parent ?: return@repeat
        }
        error("$VECTORS was not found from the test working directory")
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

    private companion object {
        const val VECTORS = "fixtures/zk/signed_attachments_v1/vectors.json"
    }
}
