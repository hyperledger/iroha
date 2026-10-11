package org.hyperledger.iroha.sdk.client

import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral

/** Minimal JSON parser for RAM-LFE program-policy, execute, and verify payloads. */
object RamLfeJsonParser {

    @JvmStatic
    fun parsePolicyList(payload: ByteArray): RamLfeProgramPolicyListResponse {
        val root = expectObject(parse(payload, "ram-lfe program policy list"), "ram-lfe program policy list")
        val itemValues = asArrayOrEmpty(root["items"], "ram-lfe program policy list.items")
        val items = ArrayList<RamLfeProgramPolicySummary>(itemValues.size)
        for (i in itemValues.indices) {
            val item = expectObject(itemValues[i], "ram-lfe program policy list.items[$i]")
            items.add(
                RamLfeProgramPolicySummary(
                    requiredExactString(item["program_id"], "ram-lfe program policy list.items[$i].program_id"),
                    requiredExactString(item["owner"], "ram-lfe program policy list.items[$i].owner"),
                    asBoolean(item["active"], "ram-lfe program policy list.items[$i].active"),
                    requiredPublicKeyLiteral(item["resolver_public_key"], "ram-lfe program policy list.items[$i].resolver_public_key"),
                    RamLfeWireTags.parseBackend(item["backend"], "ram-lfe program policy list.items[$i].backend"),
                    RamLfeWireTags.parseVerificationMode(item["verification_mode"], "ram-lfe program policy list.items[$i].verification_mode"),
                    optionalExactString(item["input_encryption"], "ram-lfe program policy list.items[$i].input_encryption"),
                    optionalExactHex(item["input_encryption_public_parameters"], "ram-lfe program policy list.items[$i].input_encryption_public_parameters"),
                    if (item["input_encryption_public_parameters_decoded"] == null) null
                    else parseBfvPublicParameters(
                        expectObject(item["input_encryption_public_parameters_decoded"],
                            "ram-lfe program policy list.items[$i].input_encryption_public_parameters_decoded"),
                        "ram-lfe program policy list.items[$i].input_encryption_public_parameters_decoded"
                    ),
                    optionalString(item["note"], "ram-lfe program policy list.items[$i].note"),
                    proofVerifier = if (item["proof_verifier"] == null) null
                    else parseProofVerifier(
                        expectObject(item["proof_verifier"], "ram-lfe program policy list.items[$i].proof_verifier"),
                        "ram-lfe program policy list.items[$i].proof_verifier"
                    ),
                    outputOpeningPublicKey = requiredPublicKeyLiteral(
                        item["output_opening_public_key"],
                        "ram-lfe program policy list.items[$i].output_opening_public_key",
                    ),
                    ramFheProfile = RamFheProfileJsonParser.parseOptional(
                        item["ram_fhe_profile"], "ram-lfe program policy list.items[$i].ram_fhe_profile",
                    ),
                )
            )
        }
        val total = if (root.containsKey("total"))
            asLong(root["total"], "ram-lfe program policy list.total")
        else items.size.toLong()
        return RamLfeProgramPolicyListResponse(total, items)
    }

    @JvmStatic
    fun parseExecuteResponse(payload: ByteArray): RamLfeExecuteResponse {
        val root = expectObject(parse(payload, "ram-lfe execute response"), "ram-lfe execute response")
        val fields = setOf(
            "program_id", "program_id_canonical", "opaque_hash", "receipt_hash", "opaque_output", "output_hash",
            "associated_data_hash", "executed_at_ms", "expires_at_ms", "backend",
            "verification_mode", "receipt",
        )
        root.keys.forEach { field ->
            check(field in fields) { "ram-lfe execute response.$field is not supported" }
        }
        fields.forEach { field -> check(root.containsKey(field) && root[field] != null) { "ram-lfe execute response.$field is required" } }
        check(root["backend"] == IdentifierOwnerInputV1.BACKEND) { "ram-lfe execute response.backend requires the current HKDF backend" }
        check(root["verification_mode"] == "signed") { "ram-lfe execute response.verification_mode requires signed metadata" }
        IdentifierOwnerInputV1.originalLease(asLong(root["executed_at_ms"], "execute.executed_at_ms"), asLong(root["expires_at_ms"], "execute.expires_at_ms"))
        return RamLfeExecuteResponse(
            requiredExactString(root["program_id"], "ram-lfe execute response.program_id"),
            requiredExactString(root["program_id_canonical"], "ram-lfe execute response.program_id_canonical"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["opaque_hash"], "ram-lfe execute response.opaque_hash"), "ram-lfe execute response.opaque_hash"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["receipt_hash"], "ram-lfe execute response.receipt_hash"), "ram-lfe execute response.receipt_hash"),
            exactOpaque32(root["opaque_output"]),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["output_hash"], "ram-lfe execute response.output_hash"), "ram-lfe execute response.output_hash"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["associated_data_hash"], "ram-lfe execute response.associated_data_hash"), "ram-lfe execute response.associated_data_hash"),
            asLong(root["executed_at_ms"], "ram-lfe execute response.executed_at_ms"),
            if (root.containsKey("expires_at_ms")) asOptionalLong(root["expires_at_ms"], "ram-lfe execute response.expires_at_ms") else null,
            RamLfeWireTags.parseBackend(root["backend"], "ram-lfe execute response.backend"),
            RamLfeWireTags.parseVerificationMode(root["verification_mode"], "ram-lfe execute response.verification_mode"),
            expectObject(root["receipt"], "ram-lfe execute response.receipt"),
        )
    }

    @JvmStatic
    fun parseReceiptVerifyResponse(payload: ByteArray): RamLfeReceiptVerifyResponse {
        val root = expectObject(parse(payload, "ram-lfe receipt verify response"), "ram-lfe receipt verify response")
        return RamLfeReceiptVerifyResponse(
            asBoolean(root["valid"], "ram-lfe receipt verify response.valid"),
            requiredExactString(root["program_id"], "ram-lfe receipt verify response.program_id"),
            RamLfeWireTags.parseBackend(root["backend"], "ram-lfe receipt verify response.backend"),
            RamLfeWireTags.parseVerificationMode(root["verification_mode"], "ram-lfe receipt verify response.verification_mode"),
            canonicalizeExactHash32(root["output_hash"], "ram-lfe receipt verify response.output_hash"),
            canonicalizeExactHash32(root["associated_data_hash"], "ram-lfe receipt verify response.associated_data_hash"),
            if (root.containsKey("output_hash_matches"))
                asOptionalBoolean(root["output_hash_matches"], "ram-lfe receipt verify response.output_hash_matches")
            else null,
            optionalString(root["error"], "ram-lfe receipt verify response.error")
        )
    }

    private fun exactOpaque32(value: Any?): String {
        check(value is String) { "ram-lfe execute response.opaque_output must be exact uppercase raw32 hex" }
        RamLfeExecuteConsistencyV1.upperHex(value, 32, "ram-lfe execute response.opaque_output")
        return value
    }

    private fun parse(payload: ByteArray?, context: String): Any? {
        check(payload != null && payload.isNotEmpty()) { "$context returned an empty payload" }
        val json = String(payload, StandardCharsets.UTF_8).trim()
        check(json.isNotEmpty()) { "$context returned a blank payload" }
        return JsonParser.parse(json)
    }

    @Suppress("UNCHECKED_CAST")
    private fun expectObject(value: Any?, path: String): Map<String, Any> {
        check(value is Map<*, *>) { "$path must be a JSON object" }
        return value as Map<String, Any>
    }

    private fun asArrayOrEmpty(value: Any?, path: String): List<Any?> {
        if (value == null) return emptyList()
        check(value is List<*>) { "$path must be a JSON array" }
        return value
    }

    private fun requiredString(value: Any?, path: String): String {
        val string = optionalString(value, path)
        check(!string.isNullOrBlank()) { "$path must be a non-empty string" }
        return string.trim()
    }

    private fun requiredExactString(value: Any?, path: String): String {
        val string = optionalString(value, path)
        check(!string.isNullOrBlank()) { "$path must be a non-empty string" }
        check(string.trim() == string) { "$path must not contain surrounding whitespace" }
        return string
    }

    private fun requiredPublicKeyLiteral(value: Any?, path: String): String {
        val string = requiredExactString(value, path)
        check(decodePublicKeyLiteral(string) != null) { "$path must be a valid public key literal" }
        return string
    }

    private fun optionalExactString(value: Any?, path: String): String? {
        if (value == null) return null
        return requiredExactString(value, path)
    }

    private fun optionalExactHex(value: Any?, path: String): String? {
        if (value == null) return null
        return canonicalizeExactHex(value, path)
    }

    private fun optionalString(value: Any?, path: String): String? {
        if (value == null) return null
        check(value is String) { "$path must be a string" }
        return value
    }

    private fun asLong(value: Any?, path: String): Long {
        if (value is String) return value.toLongOrNull() ?: error("$path must be an integer string")
        return JsonNumbers.asLong(value, path)
    }

    private fun asOptionalLong(value: Any?, path: String): Long? {
        if (value == null) return null
        return asLong(value, path)
    }

    private fun asBoolean(value: Any?, path: String): Boolean {
        check(value is Boolean) { "$path must be a boolean" }
        return value
    }

    private fun asOptionalBoolean(value: Any?, path: String): Boolean? {
        if (value == null) return null
        check(value is Boolean) { "$path must be a boolean" }
        return value
    }

    private fun canonicalizeHex(value: String, context: String): String {
        var trimmed = value.trim()
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            trimmed = trimmed.substring(2)
        }
        require(trimmed.length % 2 == 0 && trimmed.matches(Regex("(?i)[0-9a-f]+"))) {
            "$context must contain an even number of hex characters"
        }
        return trimmed.lowercase()
    }

    private fun canonicalizeExactHex(value: Any?, context: String): String {
        var hex = requiredExactString(value, context)
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2)
        }
        require(hex.isNotEmpty() && hex.length % 2 == 0 && hex.matches(Regex("(?i)[0-9a-f]+"))) {
            "$context must contain an even number of hex characters"
        }
        return hex.lowercase()
    }

    private fun canonicalizeHex32(value: String, context: String): String {
        val normalized = canonicalizeHex(value, context)
        require(normalized.length == 64) { "$context must contain 32 bytes" }
        return normalized
    }

    private fun canonicalizeExactHash32(value: Any?, context: String): String {
        var body = requiredExactString(value, context)
        if (body.lowercase().startsWith("hash:")) {
            body = body.substring("hash:".length)
        }
        val suffixIndex = body.indexOf('#')
        if (suffixIndex >= 0) {
            body = body.substring(0, suffixIndex)
        }
        if (body.startsWith("0x") || body.startsWith("0X")) {
            body = body.substring(2)
        }
        require(body.length == 64 && body.matches(Regex("(?i)[0-9a-f]{64}"))) {
            "$context must contain 32 bytes"
        }
        return body.lowercase()
    }

    private fun parseBfvPublicParameters(root: Map<String, Any?>, context: String): IdentifierBfvPublicParameters {
        val parameters = expectObject(root["parameters"], "$context.parameters")
        val publicKey = expectObject(root["public_key"], "$context.public_key")
        return IdentifierBfvPublicParameters(
            IdentifierBfvPublicParameters.Parameters(
                asLong(parameters["polynomial_degree"], "$context.parameters.polynomial_degree"),
                asLong(parameters["plaintext_modulus"], "$context.parameters.plaintext_modulus"),
                asLong(parameters["ciphertext_modulus"], "$context.parameters.ciphertext_modulus"),
                JsonNumbers.asInt(parameters["decomposition_base_log"], "$context.parameters.decomposition_base_log")
            ),
            IdentifierBfvPublicParameters.PublicKey(
                asLongList(publicKey["b"], "$context.public_key.b"),
                asLongList(publicKey["a"], "$context.public_key.a")
            ),
            JsonNumbers.asInt(root["max_input_bytes"], "$context.max_input_bytes"),
            root["norito_length_encoding"] as? String
        )
    }

    private fun parseProofVerifier(root: Map<String, Any?>, context: String): RamLfeProofVerifierMetadata =
        RamLfeProofVerifierMetadata(
            requiredExactString(root["proof_backend"], "$context.proof_backend"),
            requiredExactString(root["circuit_id"], "$context.circuit_id"),
            canonicalizeExactHash32(root["public_inputs_schema_hash"], "$context.public_inputs_schema_hash"),
            requiredExactString(root["verifying_key_bytes_b64"], "$context.verifying_key_bytes_b64")
        )

    private fun asLongList(value: Any?, path: String): List<Long> {
        val values = asArrayOrEmpty(value, path)
        return values.mapIndexed { index, v -> asLong(v, "$path[$index]") }
    }
}
