package org.hyperledger.iroha.samples.wallet

import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.Test
import java.util.Base64
import kotlin.test.assertFailsWith
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.JsonEncoder

class PosManifestParserTest {

    @Test
    fun `parse manifest fixture`() {
        val raw = readResource("manifest_v1.json")
        val manifest = PosManifestLoader.parse(raw)
        assertEquals("pos-retail-v1", manifest.manifestId)
        assertEquals(7L, manifest.sequence)
        assertEquals(
            "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP",
            manifest.operator
        )
        assertEquals(1056, manifest.payloadBase64.length)
        assertEquals(2, manifest.backendRoots.size)
        val admission = manifest.backendRoots.first()
        assertEquals("torii-admission", admission.label)
        assertEquals("release_signer", admission.role)
        assertEquals(
            "ed0120D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A",
            admission.publicKey
        )
    }

    @Test
    fun `invalid signature is rejected`() {
        val raw = readResource("manifest_v1.json")
        val signature = envelope(raw)["operator_signature"] as String
        val changed = (if (signature[0] == '0') "1" else "0") + signature.substring(1)
        val tampered = JsonEncoder.encode(envelope(raw) + ("operator_signature" to changed)) + "\n"
        try {
            PosManifestLoader.parse(tampered)
        } catch (ex: IllegalArgumentException) {
            assertTrue(ex.message?.contains("manifest signature", ignoreCase = true) == true)
            return
        }
        kotlin.test.fail("Expected manifest parsing to fail when signature is tampered")
    }

    @Test
    fun `manifest status reports healthy dual signature`() {
        val manifest = PosManifestLoader.parse(readResource("manifest_v1.json"))
        val clock = Clock.fixed(Instant.ofEpochMilli(1732000000000L), ZoneOffset.UTC)
        val status = ManifestStatus.from(manifest, clock)
        assertTrue(status.dualStatusHealthy)
        assertTrue(status.warnings.isEmpty())
        assertEquals(2, status.backendRoots.size)
        assertTrue(status.backendRoots.all { it.active })
    }

    @Test
    fun `manifest status flags missing witness`() {
        val manifest = PosManifestLoader.parse(readResource("manifest_v1.json"))
        val degraded = manifest.copy(backendRoots = listOf(manifest.backendRoots.first()))
        val clock = Clock.fixed(Instant.ofEpochMilli(1732000000000L), ZoneOffset.UTC)
        val status = ManifestStatus.from(degraded, clock)
        assertFalse(status.dualStatusHealthy)
        assertTrue(status.warnings.any { it.contains("missing") })
    }

    @Test
    fun `displayed fields are bound to signature`() {
        val original = readResource("manifest_v1.json")
        for ((field, value) in listOf(
            "manifest_id" to "substituted", "operator" to "substituted",
            "sequence" to 8L, "valid_until_ms" to 9999999999999L,
            "backend_roots" to emptyList<Any>(), "metadata" to mapOf("fixture" to "substituted")
        )) {
            val payload = payload(original) + (field to value)
            val replaced = envelope(original) + ("payload_base64" to Base64.getEncoder()
                .encodeToString(JsonEncoder.encode(payload).toByteArray(Charsets.UTF_8)))
            assertFailsWith<IllegalArgumentException>(field) {
                PosManifestLoader.parse(JsonEncoder.encode(replaced) + "\n")
            }
        }
    }

    @Test
    fun `unsigned envelope fields are rejected`() {
        val original = readResource("manifest_v1.json")
        for (field in listOf("manifest_id", "operator", "metadata", "backend_roots")) {
            assertFailsWith<IllegalArgumentException>(field) {
                PosManifestLoader.parse(JsonEncoder.encode(envelope(original) + (field to "substituted")) + "\n")
            }
        }
    }

    @Test
    fun `signed unknown and duplicate payload fields are rejected`() {
        val original = readResource("manifest_v1.json")
        val text = JsonEncoder.encode(payload(original))
        for (changed in listOf(
            JsonEncoder.encode(payload(original) + ("unknown" to true)),
            text.replace("\"sequence\":7", "\"sequence\":7,\"sequence\":7"),
            text.replace("\"label\":\"torii-admission\"", "\"label\":\"torii-admission\",\"unknown\":true"),
            text.replace("\"label\":\"torii-admission\"", "\"label\":\"torii-admission\",\"label\":\"torii-admission\"")
        )) {
            assertTrue(changed != text)
            assertFailsWith<IllegalArgumentException> { PosManifestLoader.parse(signedEnvelope(changed)) }
        }
    }

    @Test
    fun `signed numeric and operator layouts are strict`() {
        val original = readResource("manifest_v1.json")
        val text = JsonEncoder.encode(payload(original))
        for (changed in listOf(
            text.replace("\"sequence\":7", "\"sequence\":-1"),
            text.replace("\"sequence\":7", "\"sequence\":7.0"),
            text.replace("\"sequence\":7", "\"sequence\":9223372036854775808"),
            JsonEncoder.encode(payload(original) + ("operator" to "ed0120D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")),
            JsonEncoder.encode(payload(original) + ("schema" to "retired"))
        )) {
            assertFailsWith<IllegalArgumentException> { PosManifestLoader.parse(signedEnvelope(changed)) }
        }
    }

    @Test
    fun `noncanonical encodings and invalid UTF8 are rejected`() {
        val original = readResource("manifest_v1.json")
        val text = JsonEncoder.encode(payload(original))
        val base64 = envelope(original)["payload_base64"] as String
        val signature = envelope(original)["operator_signature"] as String
        for (changed in listOf(
            original.trimEnd(), " " + original,
            original.replace("\"operator_signature\":", "\"operator_signature\":\"$signature\",\"operator_signature\":"),
            JsonEncoder.encode(envelope(original) + ("operator_signature" to signature.uppercase())) + "\n",
            JsonEncoder.encode(envelope(original) + ("payload_base64" to base64.trimEnd('='))) + "\n",
            signedEnvelope(" " + text),
            signedEnvelope(byteArrayOf(0xc3.toByte(), 0x28))
        )) {
            assertFailsWith<IllegalArgumentException> { PosManifestLoader.parse(changed) }
        }
    }

    @Test
    fun `stream parser enforces envelope bound`() {
        val original = readResource("manifest_v1.json")
        assertEquals("pos-retail-v1", PosManifestLoader.parse(original.byteInputStream()).manifestId)
        assertFailsWith<IllegalArgumentException> {
            PosManifestLoader.parse(ByteArray(65537) { 0x20 }.inputStream())
        }
    }

    @Test
    fun `signed metadata keeps the shared typed string schema`() {
        val original = readResource("manifest_v1.json")
        for (metadata in listOf(null, 7L, mapOf("fixture" to 7L))) {
            assertFailsWith<IllegalArgumentException> {
                PosManifestLoader.parse(signedEnvelope(JsonEncoder.encode(payload(original) + ("metadata" to metadata))))
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun envelope(raw: String): Map<String, Any?> = JsonParser.parse(raw) as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun payload(raw: String): Map<String, Any?> = JsonParser.parse(String(
        Base64.getDecoder().decode(envelope(raw)["payload_base64"] as String), Charsets.UTF_8
    )) as Map<String, Any?>

    private fun signedEnvelope(payload: String): String = signedEnvelope(payload.toByteArray(Charsets.UTF_8))

    private fun signedEnvelope(payload: ByteArray): String {
        // RFC 8032 vector 1 is public synthetic test material, shared by the signed fixture.
        val seedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        val seed = ByteArray(32) { index -> seedHex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(payload, 0, payload.size)
        val signature = signer.generateSignature().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return JsonEncoder.encode(mapOf(
            "operator_signature" to signature,
            "payload_base64" to Base64.getEncoder().encodeToString(payload)
        )) + "\n"
    }

    private fun readResource(name: String): String {
        val stream = javaClass.classLoader?.getResourceAsStream(name)
        assertNotNull(stream, "missing test resource $name")
        return stream.bufferedReader().use { it.readText() }
    }
}
