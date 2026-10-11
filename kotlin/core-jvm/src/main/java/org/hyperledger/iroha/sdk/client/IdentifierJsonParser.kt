package org.hyperledger.iroha.sdk.client

import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import java.nio.charset.StandardCharsets
import java.util.Base64
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral
import org.hyperledger.iroha.sdk.nexus.UaidLiteral

/** Minimal JSON parser for identifier-policy and identifier-resolution payloads. */
object IdentifierJsonParser {

    @JvmStatic
    fun parsePolicyList(payload: ByteArray): IdentifierPolicyListResponse {
        val root = expectObject(parse(payload, "identifier policy list"), "identifier policy list")
        val itemValues = asArrayOrEmpty(root["items"], "identifier policy list.items")
        val items = ArrayList<IdentifierPolicySummary>(itemValues.size)
        for (i in itemValues.indices) {
            val item = expectObject(itemValues[i], "identifier policy list.items[$i]")
            items.add(
                IdentifierPolicySummary(
                    requiredExactString(item["policy_id"], "identifier policy list.items[$i].policy_id"),
                    requiredExactString(item["program_id"], "identifier policy list.items[$i].program_id"),
                    requiredExactString(item["owner"], "identifier policy list.items[$i].owner"),
                    asBoolean(item["active"], "identifier policy list.items[$i].active"),
                    IdentifierNormalization.fromWireValue(
                        requiredExactLowercaseString(item["normalization"], "identifier policy list.items[$i].normalization")
                    ),
                    requiredPublicKeyLiteral(item["resolver_public_key"], "identifier policy list.items[$i].resolver_public_key"),
                    RamLfeWireTags.parseBackend(item["backend"], "identifier policy list.items[$i].backend"),
                    optionalExactLowercaseString(item["input_encryption"], "identifier policy list.items[$i].input_encryption"),
                    optionalExactHexString(item["input_encryption_public_parameters"], "identifier policy list.items[$i].input_encryption_public_parameters"),
                    if (item["input_encryption_public_parameters_decoded"] == null) null
                    else parseBfvPublicParameters(
                        expectObject(item["input_encryption_public_parameters_decoded"],
                            "identifier policy list.items[$i].input_encryption_public_parameters_decoded"),
                        "identifier policy list.items[$i].input_encryption_public_parameters_decoded"
                    ),
                    optionalExactString(item["note"], "identifier policy list.items[$i].note"),
                    proofVerifier = if (item["proof_verifier"] == null) null
                    else parseProofVerifier(
                        expectObject(item["proof_verifier"], "identifier policy list.items[$i].proof_verifier"),
                        "identifier policy list.items[$i].proof_verifier"
                    ),
                    outputOpeningPublicKey = requiredPublicKeyLiteral(
                        item["output_opening_public_key"],
                        "identifier policy list.items[$i].output_opening_public_key",
                    ),
                    phoneRetailAttestorPublicKey = if (item["phone_retail_attestor_public_key"] == null) null
                    else requiredPublicKeyLiteral(
                        item["phone_retail_attestor_public_key"],
                        "identifier policy list.items[$i].phone_retail_attestor_public_key",
                    ),
                    ramFheProfile = RamFheProfileJsonParser.parseOptional(
                        item["ram_fhe_profile"], "identifier policy list.items[$i].ram_fhe_profile",
                    ),
                )
            )
        }
        val total = if (root.containsKey("total"))
            asLong(root["total"], "identifier policy list.total")
        else items.size.toLong()
        return IdentifierPolicyListResponse(total, items)
    }

    @JvmStatic
    fun parseResolutionReceipt(payload: ByteArray): IdentifierResolutionReceipt {
        val root = expectObject(parse(payload, "identifier resolution receipt"), "identifier resolution receipt")
        exactFields(root, setOf("payload", "attestation"), setOf("phone_retail_canonicality"), "identifier receipt")
        val receiptPayload = parseResolutionPayload(
            expectObject(root["payload"], "identifier resolution receipt.payload"),
            "identifier resolution receipt.payload"
        )
        val attestation = parseReceiptAttestation(
            expectObject(root["attestation"], "identifier resolution receipt.attestation"),
            "identifier resolution receipt.attestation"
        )
        val phone = root["phone_retail_canonicality"]?.let { parsePhoneAttestation(expectObject(it, "phone attestation"), "phone attestation") }
        if (receiptPayload.policyId == "phone#retail") {
            requireNotNull(phone) { "phone receipt requires its original signed phone carrier" }
            check(phone.payload.networkId == receiptPayload.networkId && phone.payload.accountId == receiptPayload.accountId && phone.payload.uaid == receiptPayload.uaid) { "phone receipt scope differs from its signed carrier" }
            phone.requireOriginalOpening(receiptPayload.opening)
        } else check(phone == null) { "nonphone receipt contains phone statement" }
        check(receiptPayload.execution.backend == IdentifierOwnerInputV1.BACKEND && receiptPayload.execution.verificationMode == "signed" && attestation.kind == "signed") { "current identifier receipt requires signed HKDF metadata" }
        IdentifierOwnerInputV1.originalLease(receiptPayload.opening.payload.openedAtMs, receiptPayload.opening.payload.expiresAtMs)
        return IdentifierResolutionReceipt(receiptPayload, attestation, phone)
    }

    @JvmStatic
    fun parsePrepareResponse(payload: ByteArray): IdentifierPrfPrepareResponse {
        val root = expectObject(parse(payload, "identifier prepare"), "identifier prepare")
        exactFields(root, setOf("network_id", "policy_id", "account_id", "uaid", "output_opening"), setOf("phone_retail_canonicality_payload"), "identifier prepare")
        val network = IdentifierOwnerInputV1.rawNetworkId(requiredExactString(root["network_id"], "prepare.network_id"))
        val policy = requiredExactString(root["policy_id"], "prepare.policy_id")
        val account = requireCanonicalI105Address(requiredExactString(root["account_id"], "prepare.account_id"), "prepare.account_id")
        val uaid = UaidLiteral.canonicalize(requiredExactString(root["uaid"], "prepare.uaid"), "prepare.uaid")
        val opening = parseTypedOriginalOpening(expectObject(root["output_opening"], "prepare.output_opening"), "prepare.output_opening")
        IdentifierOwnerInputV1.originalLease(opening.payload.openedAtMs, opening.payload.expiresAtMs)
        val phone = root["phone_retail_canonicality_payload"]?.let { parsePhonePayload(expectObject(it, "prepare.phone"), "prepare.phone") }
        if (policy == "phone#retail") {
            requireNotNull(phone) { "phone prepare requires its original attestor projection" }
            check(phone.networkId == network && phone.accountId == account && phone.uaid == uaid) { "phone prepare projection differs from selected scope" }
            PhoneRetailCanonicalityAttestationV1.requireOpeningFields(phone, opening)
        } else check(phone == null) { "nonphone prepare contains phone projection" }
        return IdentifierPrfPrepareResponse(network, policy, account, uaid, opening, phone)
    }

    private fun exactFields(root: Map<String, Any?>, required: Set<String>, optional: Set<String>, path: String) {
        check(root.keys.all { it in required || it in optional } && required.all { root.containsKey(it) && root[it] != null }) { "$path must contain exactly its current required/optional fields" }
    }

    internal fun parsePhonePayload(root: Map<String, Any?>, path: String): PhoneRetailCanonicalityPayloadV1 {
        exactFields(root, setOf("network_id", "policy_id", "program_id", "input_ciphertext_hash", "output_ciphertext_hash", "opened_output_hash", "canonical_phone_nullifier", "uaid", "account_id", "issued_at_ms", "expires_at_ms"), emptySet(), path)
        fun hash(field: String) = IdentifierOwnerInputV1.rawModelHash(requiredExactString(root[field], "$path.$field"))
        return PhoneRetailCanonicalityPayloadV1(
            NetworkId.parse(requiredExactString(root["network_id"], "$path.network_id")), parsePhonePolicyId(root["policy_id"], "$path.policy_id"), parseModelProgramId(root["program_id"], "$path.program_id"),
            hash("input_ciphertext_hash"), hash("output_ciphertext_hash"), hash("opened_output_hash"), hash("canonical_phone_nullifier"),
            parseModelUaid(root["uaid"], "$path.uaid"), requireCanonicalI105Address(requiredExactString(root["account_id"], "$path.account_id"), "$path.account_id"), asUnsignedLong(root["issued_at_ms"], "$path.issued_at_ms"), asUnsignedLong(root["expires_at_ms"], "$path.expires_at_ms"),
        )
    }

    private fun parseModelUaid(value: Any?, path: String): String {
        check(value is List<*> && value.size == 1) { "$path must be the exact one-field Model tuple" }
        val hash = IdentifierOwnerInputV1.rawModelHash(requiredExactString(value[0], "$path[0]"))
        return UaidLiteral.canonicalize("uaid:$hash", path)
    }
    private fun parsePhonePolicyId(value: Any?, path: String): String {
        val fields = expectObject(value, path)
        exactFields(fields, setOf("kind", "business_rule"), emptySet(), path)
        check(fields["kind"] == "phone" && fields["business_rule"] == "retail") { "$path must be the typed phone#retail policy" }
        return "phone#retail"
    }
    private fun parseModelProgramId(value: Any?, path: String): String {
        val fields = expectObject(value, path)
        exactFields(fields, setOf("name"), emptySet(), path)
        return requiredExactString(fields["name"], "$path.name")
    }
    private fun parseModelSignature(value: Any?, path: String): String {
        val signature = requiredExactString(value, path)
        check(signature.isNotEmpty() && signature.length <= 2 * CanonicalRequestSigner.CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 && signature.length % 2 == 0 && signature.all { it in '0'..'9' || it in 'A'..'F' }) { "$path must be its exact uppercase Model signature" }
        return signature.lowercase()
    }
    private fun parseTypedOriginalOpening(root: Map<String, Any?>, path: String): RamLfeOutputOpening {
        exactFields(root, setOf("payload", "signature"), emptySet(), path)
        val payload = expectObject(root["payload"], "$path.payload")
        exactFields(payload, setOf("program_id", "input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "opened_output_hash", "opened_at_ms", "expires_at_ms"), emptySet(), "$path.payload")
        fun hash(field: String) = IdentifierOwnerInputV1.rawModelHash(requiredExactString(payload[field], "$path.payload.$field"))
        return RamLfeOutputOpening(RamLfeOutputOpeningPayload(parseModelProgramId(payload["program_id"], "$path.payload.program_id"), hash("input_ciphertext_hash"), hash("output_ciphertext_hash"), hash("parameter_digest"), hash("evaluation_key_digest"), hash("opened_output_hash"), asUnsignedLong(payload["opened_at_ms"], "$path.payload.opened_at_ms"), asUnsignedLong(payload["expires_at_ms"], "$path.payload.expires_at_ms")), parseModelSignature(root["signature"], "$path.signature"))
    }

    private fun parsePhoneAttestation(root: Map<String, Any?>, path: String): PhoneRetailCanonicalityAttestationV1 {
        exactFields(root, setOf("payload", "signature"), emptySet(), path)
        return PhoneRetailCanonicalityAttestationV1(parsePhonePayload(expectObject(root["payload"], "$path.payload"), "$path.payload"), parseModelSignature(root["signature"], "$path.signature"))
    }

    @JvmStatic
    fun parseClaimRecord(payload: ByteArray): IdentifierClaimRecord {
        val root = expectObject(parse(payload, "identifier claim record"), "identifier claim record")
        return IdentifierClaimRecord(
            requiredExactString(root["policy_id"], "identifier claim record.policy_id"),
            canonicalizeOpaque(requiredExactString(root["opaque_id"], "identifier claim record.opaque_id"), "identifier claim record.opaque_id"),
            canonicalizeHex32(requiredExactString(root["receipt_hash"], "identifier claim record.receipt_hash"), "identifier claim record.receipt_hash"),
            UaidLiteral.canonicalize(requiredExactString(root["uaid"], "identifier claim record.uaid"), "identifier claim record.uaid"),
            requiredExactString(root["account_id"], "identifier claim record.account_id"),
            asLong(root["verified_at_ms"], "identifier claim record.verified_at_ms"),
            if (root.containsKey("expires_at_ms")) asOptionalLong(root["expires_at_ms"], "identifier claim record.expires_at_ms") else null
        )
    }

    private fun parse(payload: ByteArray?, context: String): Any? {
        check(payload != null && payload.isNotEmpty()) { "$context returned an empty payload" }
        val json = String(payload, StandardCharsets.UTF_8).trim()
        check(json.isNotEmpty()) { "$context returned a blank payload" }
        return JsonParser.parse(json)
    }

    @Suppress("UNCHECKED_CAST")
    private fun expectObject(value: Any?, path: String): Map<String, Any?> {
        check(value is Map<*, *>) { "$path must be a JSON object" }
        return value as Map<String, Any?>
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

    private fun requiredExactLowercaseString(value: Any?, path: String): String {
        val string = requiredExactString(value, path)
        check(string == string.lowercase()) { "$path must be an exact lowercase wire value" }
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

    private fun optionalExactLowercaseString(value: Any?, path: String): String? {
        val string = optionalExactString(value, path) ?: return null
        check(string == string.lowercase()) { "$path must be an exact lowercase wire value" }
        return string
    }

    private fun optionalExactHexString(value: Any?, path: String): String? {
        var hex = optionalExactString(value, path) ?: return null
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2)
        }
        check(hex.isNotEmpty() && hex.length % 2 == 0 && hex.matches(Regex("(?i)[0-9a-f]+"))) {
            "$path must contain an even number of hex characters"
        }
        return hex
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

    private fun asUnsignedLong(value: Any?, path: String): Long {
        // Current typed Model clocks are JSON numbers; string aliases are not accepted.
        val parsed = JsonNumbers.asLong(value, path)
        check(parsed >= 0L) { "$path must be a non-negative u64" }
        return parsed
    }

    private fun asOptionalUnsignedLong(value: Any?, path: String): Long? {
        if (value == null) return null
        return asUnsignedLong(value, path)
    }

    private fun canonicalizeOpaque(value: String, context: String): String {
        check(value.startsWith("opaque:") && value.length == 71) { "$context must be exact opaque:lowerhex32" }
        IdentifierOwnerInputV1.rawHash32(value.removePrefix("opaque:"), context)
        return value
    }

    private fun canonicalizeHex32(value: String, context: String): String {
        var body = value
        check(body.isNotEmpty()) { "$context must not be blank" }
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
        check(body.length == 64 && body.matches(Regex("(?i)[0-9a-f]{64}"))) {
            "$context must contain 64 hex characters"
        }
        return body.lowercase()
    }

    private fun canonicalizeHex(value: String, context: String): String {
        var trimmed = value.trim()
        check(trimmed.isNotEmpty()) { "$context must not be blank" }
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            trimmed = trimmed.substring(2)
        }
        check(trimmed.length % 2 == 0 && trimmed.matches(Regex("(?i)[0-9a-f]+"))) {
            "$context must contain an even number of hex characters"
        }
        return trimmed.lowercase()
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
            optionalExactString(root["norito_length_encoding"], "$context.norito_length_encoding")
        )
    }

    private fun parseProofVerifier(root: Map<String, Any?>, context: String): RamLfeProofVerifierMetadata =
        RamLfeProofVerifierMetadata(
            requiredExactString(root["proof_backend"], "$context.proof_backend"),
            requiredExactString(root["circuit_id"], "$context.circuit_id"),
            canonicalizeHex32(requiredExactString(root["public_inputs_schema_hash"], "$context.public_inputs_schema_hash"), "$context.public_inputs_schema_hash"),
            requiredExactString(root["verifying_key_bytes_b64"], "$context.verifying_key_bytes_b64")
        )

    private fun parseResolutionPayload(root: Map<String, Any?>, context: String): IdentifierResolutionPayload {
        exactFields(root, setOf("network_id", "policy_id", "execution", "opening", "opaque_id", "receipt_hash", "uaid", "account_id"), emptySet(), context)
        val execution = parseResolutionExecutionPayload(
            expectObject(root["execution"], "$context.execution"),
            "$context.execution"
        )
        val opening = parseOutputOpening(
            expectObject(root["opening"], "$context.opening"),
            "$context.opening"
        )
        return IdentifierResolutionPayload(
            IdentifierOwnerInputV1.rawNetworkId(requiredExactString(root["network_id"], "$context.network_id")),
            requiredExactString(root["policy_id"], "$context.policy_id"),
            execution,
            opening,
            canonicalizeOpaque(requiredExactString(root["opaque_id"], "$context.opaque_id"), "$context.opaque_id"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["receipt_hash"], "$context.receipt_hash"), "$context.receipt_hash"),
            UaidLiteral.canonicalize(requiredExactString(root["uaid"], "$context.uaid"), "$context.uaid"),
            requireCanonicalI105Address(requiredExactString(root["account_id"], "$context.account_id"), "$context.account_id")
        )
    }

    internal fun parseResolutionExecutionPayload(root: Map<String, Any?>, context: String): IdentifierResolutionExecutionPayload {
        exactFields(root, setOf("program_id", "program_digest", "backend", "verification_mode", "input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "output_hash", "associated_data_hash", "executed_at_ms", "expires_at_ms"), emptySet(), context)
        return IdentifierResolutionExecutionPayload(
            requiredExactString(root["program_id"], "$context.program_id"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["program_digest"], "$context.program_digest"), "$context.program_digest"),
            RamLfeWireTags.parseBackend(root["backend"], "$context.backend"),
            RamLfeWireTags.parseVerificationMode(root["verification_mode"], "$context.verification_mode"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["input_ciphertext_hash"], "$context.input_ciphertext_hash"), "$context.input_ciphertext_hash"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["output_ciphertext_hash"], "$context.output_ciphertext_hash"), "$context.output_ciphertext_hash"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["parameter_digest"], "$context.parameter_digest"), "$context.parameter_digest"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["evaluation_key_digest"], "$context.evaluation_key_digest"), "$context.evaluation_key_digest"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["output_hash"], "$context.output_hash"), "$context.output_hash"),
            IdentifierOwnerInputV1.rawHash32(requiredExactString(root["associated_data_hash"], "$context.associated_data_hash"), "$context.associated_data_hash"),
            asUnsignedLong(root["executed_at_ms"], "$context.executed_at_ms"),
            if (root.containsKey("expires_at_ms")) asOptionalUnsignedLong(root["expires_at_ms"], "$context.expires_at_ms") else null
        )

    }

    internal fun parseOutputOpening(root: Map<String, Any?>, context: String): RamLfeOutputOpening {
        exactFields(root, setOf("payload", "signature"), emptySet(), context)
        val payload = expectObject(root["payload"], "$context.payload")
        exactFields(payload, setOf("program_id", "input_ciphertext_hash", "output_ciphertext_hash", "parameter_digest", "evaluation_key_digest", "opened_output_hash", "opened_at_ms"), setOf("expires_at_ms"), "$context.payload")
        return RamLfeOutputOpening(
            RamLfeOutputOpeningPayload(
                requiredExactString(payload["program_id"], "$context.payload.program_id"),
                IdentifierOwnerInputV1.rawHash32(requiredExactString(payload["input_ciphertext_hash"], "$context.payload.input_ciphertext_hash"), "$context.payload.input_ciphertext_hash"),
                IdentifierOwnerInputV1.rawHash32(requiredExactString(payload["output_ciphertext_hash"], "$context.payload.output_ciphertext_hash"), "$context.payload.output_ciphertext_hash"),
                IdentifierOwnerInputV1.rawHash32(requiredExactString(payload["parameter_digest"], "$context.payload.parameter_digest"), "$context.payload.parameter_digest"),
                IdentifierOwnerInputV1.rawHash32(requiredExactString(payload["evaluation_key_digest"], "$context.payload.evaluation_key_digest"), "$context.payload.evaluation_key_digest"),
                IdentifierOwnerInputV1.rawHash32(requiredExactString(payload["opened_output_hash"], "$context.payload.opened_output_hash"), "$context.payload.opened_output_hash"),
                asUnsignedLong(payload["opened_at_ms"], "$context.payload.opened_at_ms"),
                if (payload.containsKey("expires_at_ms")) asOptionalUnsignedLong(payload["expires_at_ms"], "$context.payload.expires_at_ms") else null
            ),
            IdentifierOwnerInputV1.rawSignature(requiredExactString(root["signature"], "$context.signature"), "$context.signature")
        )
    }

    internal fun parseReceiptAttestation(root: Map<String, Any?>, context: String): IdentifierReceiptAttestation {
        val kind = requiredExactString(root["kind"], "$context.kind")
        return when (kind) {
            "signed" -> {
                exactFields(root, setOf("kind", "signature"), emptySet(), context)
                val signature = parseModelSignature(root["signature"], "$context.signature")
                check(root["proof_backend"] == null && root["proof_b64"] == null) {
                    "$context signed attestation must not include proof fields"
                }
                IdentifierReceiptAttestation(kind, signature, null, null)
            }
            "proof" -> {
                val backend = requiredExactString(root["proof_backend"], "$context.proof_backend")
                val proofB64 = requiredExactString(root["proof_b64"], "$context.proof_b64")
                try {
                    Base64.getDecoder().decode(proofB64)
                } catch (ex: IllegalArgumentException) {
                    throw IllegalStateException("$context.proof_b64 must be valid base64", ex)
                }
                check(root["signature"] == null) {
                    "$context proof attestation must not include signature"
                }
                IdentifierReceiptAttestation(kind, null, backend, proofB64)
            }
            else -> error("$context.kind must be signed or proof")
        }
    }

    private fun asLongList(value: Any?, path: String): List<Long> {
        val values = asArrayOrEmpty(value, path)
        return values.mapIndexed { index, v -> asLong(v, "$path[$index]") }
    }
}
