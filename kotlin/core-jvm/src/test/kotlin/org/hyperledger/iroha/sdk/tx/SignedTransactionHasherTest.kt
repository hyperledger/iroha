package org.hyperledger.iroha.sdk.tx

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Base64
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.client.TairaTestnetProfile
import org.hyperledger.iroha.sdk.core.model.Executable
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.core.model.JsonValue
import org.hyperledger.iroha.sdk.core.model.TransactionPayload
import org.hyperledger.iroha.sdk.core.model.instructions.ProofAttachment
import org.hyperledger.iroha.sdk.core.model.instructions.ProofVerifierKeyRef
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.norito.NoritoCodec
import org.hyperledger.iroha.sdk.norito.NoritoDecoder
import org.hyperledger.iroha.sdk.testing.TestEd25519Keys
import org.hyperledger.iroha.sdk.testing.TestNetworkIds
import org.hyperledger.iroha.sdk.tx.norito.NoritoException
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter
import org.hyperledger.iroha.sdk.tx.norito.SignedTransactionEncoder

class SignedTransactionHasherTest {
    private val adapter = NoritoJavaCodecAdapter(TairaTestnetProfile.I105_DISCRIMINANT)

    @Test
    fun `authorization proof changes do not change transaction identity`() {
        val encodedPayload = adapter.encodeTransaction(samplePayload())
        val first = signed(encodedPayload, 0x11)
        val second = signed(encodedPayload, 0x22)

        assertNotEquals(
            hex(SignedTransactionEncoder.encode(first)),
            hex(SignedTransactionEncoder.encode(second)),
        )
        assertEquals(SignedTransactionHasher.hashHex(first), SignedTransactionHasher.hashHex(second))
        assertContentEquals(
            SignedTransactionHasher.canonicalBytes(first),
            SignedTransactionHasher.canonicalBytes(second),
        )
    }

    @Test
    fun `payload and proof attachment changes alter transaction identity`() {
        val base = signed(adapter.encodeTransaction(samplePayload()), 0x33)
        val changedMetadata = signed(
            adapter.encodeTransaction(
                samplePayload(metadata = mapOf("purpose" to JsonValue.string("changed"))),
            ),
            0x33,
        )
        val attachment = ProofAttachment(
            "halo2",
            byteArrayOf(0x01, 0x02, 0x03),
            ProofVerifierKeyRef("halo2", "vk1"),
        )

        assertNotEquals(
            SignedTransactionHasher.hashHex(base),
            SignedTransactionHasher.hashHex(changedMetadata),
        )
        val attachedPayload = adapter.withProofAttachments(samplePayload(), listOf(attachment))
        val attached = signed(adapter.encodeTransaction(attachedPayload), 0x33)
        assertNotEquals(SignedTransactionHasher.hashHex(base), SignedTransactionHasher.hashHex(attached))
        val changedProof = ProofAttachment("halo2", byteArrayOf(4, 5, 6), ProofVerifierKeyRef("halo2", "vk1"))
        val replaced = adapter.withProofAttachments(samplePayload(), listOf(changedProof))
        assertEquals(adapter.orderedIntentDigest(attachedPayload), adapter.orderedIntentDigest(replaced))
        assertNotEquals(SignedTransactionHasher.hashHex(attached),
            SignedTransactionHasher.hashHex(signed(adapter.encodeTransaction(replaced), 0x33)))
    }

    @Test
    fun `transaction wire field counts match rust first release layout`() {
        val transaction = signed(adapter.encodeTransaction(samplePayload()), 0x44)

        assertEquals(9, countSizedFields(transaction.encodedPayload()))
        assertEquals(3, countSizedFields(SignedTransactionEncoder.encode(transaction)))
    }

    @Test
    fun `compact length boundaries use minimal unsigned leb128`() {
        assertCompactLength(0, 0x00)
        assertCompactLength(127, 0x7f)
        assertCompactLength(128, 0x80, 0x01)
        assertCompactLength(16_383, 0xff, 0x7f)
        assertCompactLength(16_384, 0x80, 0x80, 0x01)
        assertCompactLength(Int.MAX_VALUE.toLong(), 0xff, 0xff, 0xff, 0xff, 0x07)
        assertCompactLength(
            Long.MAX_VALUE,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x7f,
        )
        assertFailsWith<IllegalArgumentException> {
            SignedTransactionHasher.encodeCompactLength(-1)
        }
    }

    @Test
    fun `canonical external entrypoint matches native rust golden`() {
        val fixture = loadCompactHashFixture()
        assertEquals("2", fixture.getProperty("schema.version"))
        assertEquals("transfer_asset", fixture.getProperty("source.fixture"))
        val versioned = decodeCanonicalBase64(
            fixture.getProperty("versioned.base64"),
            "versioned.base64",
        )
        assertEquals(fixture.getProperty("versioned.bytes").toInt(), versioned.size)
        assertEquals(1, versioned.first().toInt())
        assertEquals(
            fixture.getProperty("versioned.sha256"),
            hex(MessageDigest.getInstance("SHA-256").digest(versioned)),
        )

        val decoded = SignedTransactionEncoder.decodeVersioned(versioned)
        assertEquals(
            fixture.getProperty("payload.prehash"),
            hex(IrohaHash.prehash(decoded.encodedPayload())),
        )
        val bare = SignedTransactionEncoder.encode(decoded)
        assertEquals(fixture.getProperty("bare.bytes").toInt(), bare.size)
        assertContentEquals(versioned.copyOfRange(1, versioned.size), bare)

        val canonical = SignedTransactionHasher.canonicalBytes(decoded)
        val expectedPrefix = decodeHex(fixture.getProperty("canonical.prefix.hex"))
        assertContentEquals(expectedPrefix, canonical.copyOf(expectedPrefix.size))
        assertEquals(fixture.getProperty("canonical.hash"), SignedTransactionHasher.hashHex(decoded))
        assertEquals(
            fixture.getProperty("canonical.hash"),
            SignedTransactionHasher.hashCanonicalHex(bare),
        )
        assertNotEquals(fixture.getProperty("canonical.hash"), hex(IrohaHash.prehash(bare)))
    }

    @Test
    fun `object and canonical bare byte paths share one external wrapper`() {
        val fixture = loadCompactHashFixture()
        val versioned = decodeCanonicalBase64(
            fixture.getProperty("versioned.base64"),
            "versioned.base64",
        )
        val decoded = SignedTransactionEncoder.decodeVersioned(versioned)
        val bare = SignedTransactionEncoder.encode(decoded)

        assertContentEquals(
            SignedTransactionHasher.canonicalBytes(decoded),
            SignedTransactionHasher.canonicalBytesFromBare(bare),
        )
        assertEquals(
            SignedTransactionHasher.hashHex(decoded),
            SignedTransactionHasher.hashCanonicalHex(bare),
        )
    }

    @Test
    fun `bare byte helpers reject malformed versioned and wrapped encodings`() {
        val fixture = loadCompactHashFixture()
        val versioned = decodeCanonicalBase64(
            fixture.getProperty("versioned.base64"),
            "versioned.base64",
        )
        val decoded = SignedTransactionEncoder.decodeVersioned(versioned)
        val bare = SignedTransactionEncoder.encode(decoded)
        val trailing = bare + byteArrayOf(0)
        kotlin.test.assertTrue((bare[0].toInt() and 0x80) != 0)
        kotlin.test.assertTrue((bare[1].toInt() and 0x80) == 0)
        val overlongFirstLength =
            byteArrayOf(bare[0], (bare[1].toInt() or 0x80).toByte(), 0) +
                bare.copyOfRange(2, bare.size)

        for (
            malformed in
                listOf(
                    ByteArray(0),
                    bare.copyOf(bare.size - 1),
                    trailing,
                    versioned,
                    SignedTransactionHasher.canonicalBytesFromBare(bare),
                    overlongFirstLength,
                )
        ) {
            val error = assertFailsWith<IllegalArgumentException> {
                SignedTransactionHasher.hashCanonicalHex(malformed)
            }
            kotlin.test.assertTrue(error.message.orEmpty().contains("canonical bare"))
        }
    }

    @Test
    fun `compact fixture parser rejects duplicate keys and base64 aliases`() {
        val contents = resolveCompactHashFixture().toFile().readText(Charsets.UTF_8)
        val duplicate = assertFailsWith<IllegalStateException> {
            parseCompactHashFixture("$contents\ncanonical.hash=duplicate\n")
        }
        kotlin.test.assertTrue(duplicate.message.orEmpty().contains("Duplicate compact fixture property"))

        for (malformed in listOf("YQ!!", "Y Q==", "YQ=", "YQ===", "YR==")) {
            assertFailsWith<IllegalStateException>("must reject $malformed") {
                decodeCanonicalBase64(malformed, "versioned.base64")
            }
        }
    }

    private fun assertCompactLength(value: Long, vararg expected: Int) {
        assertContentEquals(
            expected.map(Int::toByte).toByteArray(),
            SignedTransactionHasher.encodeCompactLength(value),
            "Unexpected COMPACT_LEN encoding for $value",
        )
    }

    private fun samplePayload(
        metadata: Map<String, JsonValue> = emptyMap(),
        attachments: org.hyperledger.iroha.sdk.core.model.SignedAttachmentsV1? = null,
    ): TransactionPayload = TransactionPayload(
        networkId = TestNetworkIds.canonical(),
        authority = AccountAddress
            .fromAccount(TestEd25519Keys.publicKey(0x2C), "ed25519")
            .toI105(TairaTestnetProfile.I105_DISCRIMINANT),
        creationTimeMs = 1_735_369_000_000L,
        executable = Executable.ivm(byteArrayOf(0x01, 0x02)),
        feePayment = FeePaymentIntent.authority(emptyList(), 1L),
        metadata = metadata,
        attachments = attachments,
    )

    private fun signed(encodedPayload: ByteArray, signatureSeed: Int): SignedTransaction =
        SignedTransaction(
            encodedPayload,
            ByteArray(64) { signatureSeed.toByte() },
            TestEd25519Keys.publicKey(0x2C),
            adapter.schemaName(),
        )

    private fun countSizedFields(bytes: ByteArray): Int {
        val decoder = NoritoDecoder(bytes, NoritoCodec.DEFAULT_FLAGS)
        var count = 0
        while (decoder.remaining() != 0) {
            val length = decoder.readLength(decoder.compactLenActive())
            require(length <= Int.MAX_VALUE) { "field is too large" }
            decoder.readBytes(length.toInt())
            count++
        }
        return count
    }

    private fun loadCompactHashFixture(): Properties {
        val fixture = resolveCompactHashFixture()
        return parseCompactHashFixture(fixture.toFile().readText(Charsets.UTF_8))
    }

    private fun parseCompactHashFixture(contents: String): Properties {
        val expectedKeys = setOf(
            "schema.version",
            "source.fixture",
            "versioned.bytes",
            "versioned.sha256",
            "bare.bytes",
            "compact.length.hex",
            "canonical.prefix.hex",
            "canonical.hash",
            "payload.prehash",
            "versioned.base64",
        )
        val result = Properties()
        for (line in contents.lineSequence()) {
            if (line.isEmpty() || line.startsWith("#")) continue
            val separator = line.indexOf('=')
            require(separator > 0 && separator < line.lastIndex) {
                "Malformed compact fixture property: $line"
            }
            val key = line.substring(0, separator)
            val value = line.substring(separator + 1)
            check(!result.containsKey(key)) { "Duplicate compact fixture property: $key" }
            result.setProperty(key, value)
        }
        check(result.stringPropertyNames() == expectedKeys) {
            "Compact fixture property keys must match the required set"
        }
        decodeCanonicalBase64(result.getProperty("versioned.base64"), "versioned.base64")
        return result
    }

    private fun decodeCanonicalBase64(value: String, context: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (ex: IllegalArgumentException) {
            throw IllegalStateException("$context is not valid base64", ex)
        }
        check(Base64.getEncoder().encodeToString(decoded) == value) {
            "$context is not canonical base64"
        }
        return decoded
    }

    private fun resolveCompactHashFixture(): Path {
        var current: Path? = Paths.get("").toAbsolutePath().normalize()
        while (current != null) {
            val candidate = current.resolve("fixtures/norito_rpc/iroha_compact_hash_vector.properties")
            if (Files.isRegularFile(candidate)) return candidate
            current = current.parent
        }
        error("Unable to locate compact transaction hash fixture")
    }

    private fun decodeHex(value: String): ByteArray {
        require(value.length % 2 == 0) { "Expected even-length hexadecimal fixture value" }
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
