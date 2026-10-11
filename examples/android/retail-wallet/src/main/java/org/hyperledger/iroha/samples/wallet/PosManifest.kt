package org.hyperledger.iroha.samples.wallet

import android.content.Context
import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.client.JsonEncoder
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import org.json.JSONObject
import org.hyperledger.iroha.sdk.address.AccountAddress
import org.hyperledger.iroha.sdk.address.AccountAddressException

data class PosProvisionManifest(
    val manifestId: String,
    val sequence: Long,
    val publishedAtMs: Long,
    val validFromMs: Long,
    val validUntilMs: Long,
    val rotationHintMs: Long?,
    val operator: String,
    val backendRoots: List<PosBackendRoot>,
    val metadata: JSONObject?,
    val payloadBase64: String,
    val operatorSignature: String
)

data class PosBackendRoot(
    val label: String,
    val role: String,
    val publicKey: String,
    val validFromMs: Long,
    val validUntilMs: Long,
    val metadata: JSONObject?
)

data class ManifestStatus(
    val manifestId: String,
    val sequence: Long,
    val operator: String,
    val validWindowLabel: String,
    val rotationLabel: String,
    val dualStatusLabel: String,
    val dualStatusHealthy: Boolean,
    val warnings: List<String>,
    val backendRoots: List<BackendRootStatus>
) {
    companion object {
        fun from(
            manifest: PosProvisionManifest,
            clock: Clock = Clock.systemUTC()
        ): ManifestStatus {
            val formatter = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC)
            val validLabel = formatter.format(Instant.ofEpochMilli(manifest.validFromMs)) +
                " – " + formatter.format(Instant.ofEpochMilli(manifest.validUntilMs))
            val rotationLabel = manifest.rotationHintMs?.let { hint ->
                formatter.format(Instant.ofEpochMilli(hint))
            } ?: "n/a"
            val now = clock.millis()
            val backendStatuses = manifest.backendRoots.map { root ->
                val active = now in root.validFromMs..root.validUntilMs
                val statusLabel = buildBackendStatusLabel(root, active, formatter, now)
                BackendRootStatus(
                    label = root.label,
                    role = root.role,
                    statusLabel = statusLabel,
                    active = active
                )
            }
            val dualStatus = buildDualStatus(manifest, backendStatuses, now)
            val warnings = buildWarnings(manifest, backendStatuses, dualStatus, now, formatter)
            return ManifestStatus(
                manifestId = manifest.manifestId,
                sequence = manifest.sequence,
                operator = manifest.operator,
                validWindowLabel = validLabel,
                rotationLabel = rotationLabel,
                dualStatusLabel = dualStatus.label,
                dualStatusHealthy = dualStatus.healthy,
                warnings = warnings,
                backendRoots = backendStatuses
            )
        }

        private fun buildBackendStatusLabel(
            root: PosBackendRoot,
            active: Boolean,
            formatter: DateTimeFormatter,
            nowMs: Long
        ): String {
            val expiresIn = root.validUntilMs - nowMs
            val expiresLabel = if (expiresIn > 0) {
                "expires ${formatDuration(expiresIn)}"
            } else {
                "expired ${formatter.format(Instant.ofEpochMilli(root.validUntilMs))}"
            }
            val validity = formatter.format(Instant.ofEpochMilli(root.validFromMs)) +
                " – " + formatter.format(Instant.ofEpochMilli(root.validUntilMs))
            val state = if (active) "active" else "inactive"
            return "$state · $validity ($expiresLabel)"
        }

        private fun buildDualStatus(
            manifest: PosProvisionManifest,
            roots: List<BackendRootStatus>,
            now: Long
        ): DualStatus {
            val roles = roots.filter { it.active }.map { it.role }.toSet()
            val required = setOf("release_signer", "device_attestation_ca")
            val missing = required.filterNot { roles.contains(it) }
            return if (missing.isEmpty()) {
                DualStatus(true, "required trust roots present until ${formatDuration(manifest.validUntilMs - now)}")
            } else {
                DualStatus(false, "missing ${missing.joinToString(", ")}")
            }
        }

        private fun buildWarnings(
            manifest: PosProvisionManifest,
            roots: List<BackendRootStatus>,
            dualStatus: DualStatus,
            now: Long,
            formatter: DateTimeFormatter
        ): List<String> {
            val warnings = mutableListOf<String>()
            if (now < manifest.validFromMs) {
                warnings.add("manifest not active until ${formatter.format(Instant.ofEpochMilli(manifest.validFromMs))}")
            }
            val manifestExpiresIn = manifest.validUntilMs - now
            if (manifestExpiresIn <= MANIFEST_WARNING_WINDOW_MS) {
                warnings.add("manifest expires in ${formatDuration(manifestExpiresIn)}")
            }
            manifest.rotationHintMs?.let { hint ->
                if (now >= hint) {
                    warnings.add("rotation hint passed ${formatDuration(now - hint)} ago")
                } else if (hint - now <= ROTATION_WARNING_WINDOW_MS) {
                    warnings.add("rotation hint in ${formatDuration(hint - now)}")
                }
            }
            roots.filter { it.active.not() }.forEach { inactive ->
                warnings.add("${inactive.label} inactive")
            }
            if (!dualStatus.healthy) {
                warnings.add(dualStatus.label)
            }
            if (warnings.isEmpty()) {
                return emptyList()
            }
            return warnings
        }

        private fun formatDuration(durationMs: Long): String {
            if (durationMs <= 0) {
                return "0s"
            }
            val duration = Duration.ofMillis(durationMs)
            val days = duration.toDays()
            val hours = duration.minusDays(days).toHours()
            val minutes = duration.minusDays(days).minusHours(hours).toMinutes()
            val parts = mutableListOf<String>()
            if (days > 0) {
                parts.add("${days}d")
            }
            if (hours > 0) {
                parts.add("${hours}h")
            }
            if (minutes > 0) {
                parts.add("${minutes}m")
            }
            if (parts.isEmpty()) {
                parts.add("${duration.seconds}s")
            }
            return parts.joinToString(" ")
        }
    }
}

data class BackendRootStatus(
    val label: String,
    val role: String,
    val statusLabel: String,
    val active: Boolean
)

private data class DualStatus(val healthy: Boolean, val label: String)

/** Reads displayed fields exclusively from the canonical, Ed25519-signed V1 payload. */
object PosManifestLoader {
    private const val MANIFEST_ASSET = "manifest_v1.json"
    private const val MAX_MANIFEST_BYTES = 65_536
    private const val SCHEMA = "iroha.example.pos-manifest.v1"
    private val payloadRequired = setOf(
        "schema", "manifest_id", "sequence", "published_at_ms", "valid_from_ms",
        "valid_until_ms", "operator", "backend_roots"
    )
    private val rootRequired = setOf("label", "role", "public_key", "valid_from_ms", "valid_until_ms")

    fun loadFromAssets(context: Context): PosProvisionManifest {
        context.assets.open(MANIFEST_ASSET).use { return parse(it) }
    }

    /** Read at most one bounded envelope before decoding any signed payload. */
    internal fun parse(input: InputStream): PosProvisionManifest {
        val bytes = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer, 0, minOf(buffer.size, MAX_MANIFEST_BYTES + 1 - bytes.size()))
            if (count < 0) break
            require(bytes.size() + count <= MAX_MANIFEST_BYTES) { "manifest exceeds byte bound" }
            bytes.write(buffer, 0, count)
        }
        return parse(decodeUtf8(bytes.toByteArray()))
    }

    fun parse(raw: String): PosProvisionManifest {
        require(raw.length <= MAX_MANIFEST_BYTES) { "manifest exceeds byte bound" }
        val envelope = objectValue(parseJson(raw), "manifest envelope")
        exactFields(envelope, setOf("operator_signature", "payload_base64"), emptySet())
        require(JsonEncoder.encode(envelope) + "\n" == raw) { "manifest envelope is not canonical" }
        val payloadBase64 = string(envelope, "payload_base64")
        val operatorSignature = string(envelope, "operator_signature")
        require(operatorSignature.matches(Regex("[0-9a-f]{128}"))) {
            "manifest signature must be 128 lowercase hex characters"
        }
        val payload = try {
            Base64.getDecoder().decode(payloadBase64)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("invalid base64 payload", error)
        }
        require(Base64.getEncoder().encodeToString(payload) == payloadBase64) {
            "manifest payload base64 is not canonical"
        }
        val payloadText = decodeUtf8(payload)
        val signed = objectValue(parseJson(payloadText), "manifest payload")
        require(JsonEncoder.encode(signed) == payloadText) { "manifest payload is not canonical" }
        exactFields(signed, payloadRequired, setOf("rotation_hint_ms", "metadata"))
        require(string(signed, "schema") == SCHEMA) { "unsupported manifest schema" }
        val operator = string(signed, "operator")
        verifySignature(decodeOperatorPublicKey(operator), payload, decodeHex(operatorSignature))
        val roots = signed["backend_roots"] as? List<*>
            ?: throw IllegalArgumentException("backend_roots must be an array")
        return PosProvisionManifest(
            manifestId = string(signed, "manifest_id"),
            sequence = nonnegativeInteger(signed, "sequence"),
            publishedAtMs = nonnegativeInteger(signed, "published_at_ms"),
            validFromMs = nonnegativeInteger(signed, "valid_from_ms"),
            validUntilMs = nonnegativeInteger(signed, "valid_until_ms"),
            rotationHintMs = if (signed.containsKey("rotation_hint_ms")) {
                nonnegativeInteger(signed, "rotation_hint_ms")
            } else null,
            operator = operator,
            backendRoots = roots.map { parseBackendRoot(objectValue(it, "backend root")) },
            metadata = metadata(signed),
            payloadBase64 = payloadBase64,
            operatorSignature = operatorSignature
        )
    }

    private fun parseBackendRoot(root: Map<String, Any?>): PosBackendRoot {
        exactFields(root, rootRequired, setOf("metadata"))
        return PosBackendRoot(
            label = string(root, "label"),
            role = string(root, "role"),
            publicKey = string(root, "public_key"),
            validFromMs = nonnegativeInteger(root, "valid_from_ms"),
            validUntilMs = nonnegativeInteger(root, "valid_until_ms"),
            metadata = metadata(root)
        )
    }

    private fun parseJson(raw: String): Any? = try {
        JsonParser.parse(raw)
    } catch (error: IllegalStateException) {
        throw IllegalArgumentException("invalid manifest JSON", error)
    }

    private fun objectValue(value: Any?, name: String): Map<String, Any?> {
        val objectValue = value as? Map<*, *>
            ?: throw IllegalArgumentException("$name must be an object")
        return objectValue.entries.associate { (key, entry) ->
            require(key is String) { "$name contains a non-string key" }
            key to entry
        }
    }

    private fun exactFields(value: Map<String, Any?>, required: Set<String>, optional: Set<String>) {
        require(value.keys.containsAll(required) && (value.keys - required - optional).isEmpty()) {
            "manifest object has missing or unknown fields"
        }
    }

    private fun string(value: Map<String, Any?>, key: String): String =
        (value[key] as? String)?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("$key must be a nonempty string")

    private fun nonnegativeInteger(value: Map<String, Any?>, key: String): Long {
        val integer = value[key] as? Long
            ?: throw IllegalArgumentException("$key must be an Int64 integer")
        require(integer >= 0) { "$key must be nonnegative" }
        return integer
    }

    private fun metadata(value: Map<String, Any?>): JSONObject? {
        if (!value.containsKey("metadata")) return null
        val fields = objectValue(value["metadata"], "metadata")
        require(fields.values.all { it is String }) { "metadata values must be strings" }
        return JSONObject(fields)
    }

    private fun decodeUtf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (error: java.nio.charset.CharacterCodingException) {
        throw IllegalArgumentException("manifest must contain valid UTF-8", error)
    }

    private fun decodeOperatorPublicKey(operator: String): ByteArray {
        val canonical = try {
            AccountAddress.fromI105(operator, null).canonicalBytes
        } catch (error: AccountAddressException) {
            throw IllegalArgumentException("failed to parse operator account", error)
        }
        require(canonical.size == 36 && canonical.copyOfRange(0, 4).contentEquals(
            byteArrayOf(0x02, 0x00, 0x01, 0x20)
        )) { "operator must be a canonical single Ed25519 account" }
        return canonical.copyOfRange(4, 36)
    }

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        ((Character.digit(value[index * 2], 16) shl 4) or Character.digit(value[index * 2 + 1], 16)).toByte()
    }

    private fun verifySignature(publicKey: ByteArray, payload: ByteArray, signature: ByteArray) {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(payload, 0, payload.size)
        require(verifier.verifySignature(signature)) { "manifest signature verification failed" }
    }
}

private const val MANIFEST_WARNING_WINDOW_MS = 7L * 24 * 60 * 60 * 1000 // 7 days
private const val ROTATION_WARNING_WINDOW_MS = 3L * 24 * 60 * 60 * 1000 // 3 days
