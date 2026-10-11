package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Base64
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.core.model.FeePaymentIntent
import org.hyperledger.iroha.sdk.crypto.IrohaHash
import org.hyperledger.iroha.sdk.tx.norito.NoritoJavaCodecAdapter

/** Minimal JSON parser for Torii contract deploy/call responses. */
object ContractJsonParser {

    /** Parse the complete `/v1/contracts/artifacts/{dataspace_id}/{code_hash}` manifest response. */
    @JvmStatic
    fun parseManifestRecord(payload: ByteArray): ContractManifestRecord =
        ContractManifestJsonParser.parseRecord(payload)

    @JvmStatic
    fun parseCallResponse(payload: ByteArray): ContractCallResponse {
        val root = expectObject(parse(payload, "contract call response"), "contract call response")
        rejectRetiredDraftFields(root, "contract call response")
        val response = ContractCallResponse(
            ok = requiredBoolean(root["ok"], "contract call response.ok"),
            submitted = requiredBoolean(root["submitted"], "contract call response.submitted"),
            dataspace = requiredString(root["dataspace"], "contract call response.dataspace"),
            codeHashHex = HttpClientTransport.normalizeHex32(requiredString(root["code_hash_hex"], "contract call response.code_hash_hex"), "codeHashHex"),
            abiHashHex = HttpClientTransport.normalizeHex32(requiredString(root["abi_hash_hex"], "contract call response.abi_hash_hex"), "abiHashHex"),
            creationTimeMs = asNonNegativeLong(
                root["creation_time_ms"],
                "contract call response.creation_time_ms",
            ),
            contractAddress = optionalString(root["contract_address"], "contract call response.contract_address"),
            txHashHex = if (root.containsKey("tx_hash_hex") && root["tx_hash_hex"] != null)
                transactionHash(root["tx_hash_hex"], "contract call response.tx_hash_hex")
            else null,
            pipelineStatus = optionalObject(root["pipeline_status"], "contract call response.pipeline_status"),
            entrypoint = optionalString(root["entrypoint"], "contract call response.entrypoint"),
            transactionTtlMs = asOptionalNonNegativeLong(
                root["transaction_ttl_ms"],
                "contract call response.transaction_ttl_ms",
            ),
            entrypointHashHex = optionalTransactionHash(root["entrypoint_hash_hex"], "contract call response.entrypoint_hash_hex"),
            transactionPayloadB64 = optionalBase64(root["transaction_payload_b64"], "contract call response.transaction_payload_b64"),
            signingMessageB64 = optionalBase64(root["signing_message_b64"], "contract call response.signing_message_b64"),
            operationReceipt = parseOperationReceipt(
                expectObject(root["operation_receipt"], "contract call response.operation_receipt"),
                "contract call response.operation_receipt",
            ),
        )
        validateUnsignedTransactionState(
            submitted = response.submitted,
            txHashHex = response.txHashHex,
            executedTxHashHex = null,
            creationTimeMs = response.creationTimeMs,
            feePayment = response.operationReceipt.feePayment,
            transactionPayloadB64 = response.transactionPayloadB64,
            signingMessageB64 = response.signingMessageB64,

            context = "contract call response",
        )
        check(
            response.submitted ||
                (response.entrypointHashHex == null &&
                    response.operationReceipt.txHashHex == null &&
                    response.operationReceipt.entrypointHashHex == null),
        ) {
            "contract call response unsigned draft must not contain transaction hashes"
        }
        return response
    }

    private fun parseOperationReceipt(
        receipt: Map<String, Any?>,
        path: String,
    ): ContractOperationReceipt {
        val gasLimit = asOptionalNonNegativeLong(receipt["gas_limit"], "$path.gas_limit")
        check(gasLimit == null || gasLimit > 0) { "$path.gas_limit must be positive" }
        return ContractOperationReceipt(
            operationKind = requiredString(receipt["operation_kind"], "$path.operation_kind"),
            status = requiredString(receipt["status"], "$path.status"),
            transport = requiredString(receipt["transport"], "$path.transport"),
            dataspace = requiredString(receipt["dataspace"], "$path.dataspace"),
            contractAlias = optionalString(receipt["contract_alias"], "$path.contract_alias"),
            contractAddress = optionalString(receipt["contract_address"], "$path.contract_address"),
            codeHashHex = optionalHash(receipt["code_hash_hex"], "$path.code_hash_hex"),
            abiHashHex = optionalHash(receipt["abi_hash_hex"], "$path.abi_hash_hex"),
            txHashHex = optionalTransactionHash(receipt["tx_hash_hex"], "$path.tx_hash_hex"),
            entrypoint = optionalString(receipt["entrypoint"], "$path.entrypoint"),
            entrypointHashHex = optionalTransactionHash(receipt["entrypoint_hash_hex"], "$path.entrypoint_hash_hex"),
            gasLimit = gasLimit,
            gasUsed = asOptionalNonNegativeLong(receipt["gas_used"], "$path.gas_used"),
            feePayment = receipt["fee_payment"]?.let { FeePaymentJson.parse(it, "$path.fee_payment") },
            payloadDigestHex = exactLowerHex32(
                receipt["payload_digest_hex"],
                "$path.payload_digest_hex",
            ),
        )
    }

    private fun exactLowerHex32(value: Any?, path: String): String {
        val literal = requiredString(value, path)
        check(literal.length == 64 && literal.all { it in '0'..'9' || it in 'a'..'f' }) {
            "$path must be canonical lowercase 32-byte hex"
        }
        return literal
    }

    @JvmStatic
    fun parseMultisigResponse(payload: ByteArray): MultisigResponse {
        val root = expectObject(parse(payload, "multisig response"), "multisig response")
        check(root["ok"] == true) { "multisig response.ok must be true" }
        rejectRetiredDraftFields(root, "multisig response")
        val response = MultisigResponse(
            ok = true,
            resolvedMultisigAccountId = requiredExactAccountId(root["resolved_multisig_account_id"], "multisig response.resolved_multisig_account_id"),
            submitted = requiredBoolean(root["submitted"], "multisig response.submitted"),
            proposalId = optionalString(root["proposal_id"], "multisig response.proposal_id"),
            instructionsHash = if (root.containsKey("instructions_hash") && root["instructions_hash"] != null)
                HttpClientTransport.normalizeHex32(requiredString(root["instructions_hash"], "multisig response.instructions_hash"), "instructionsHash")
            else null,
            txHashHex = if (root.containsKey("tx_hash_hex") && root["tx_hash_hex"] != null)
                transactionHash(root["tx_hash_hex"], "multisig response.tx_hash_hex")
            else null,
            executedTxHashHex = if (root.containsKey("executed_tx_hash_hex") && root["executed_tx_hash_hex"] != null)
                transactionHash(root["executed_tx_hash_hex"], "multisig response.executed_tx_hash_hex")
            else null,
            creationTimeMs = asOptionalNonNegativeLong(root["creation_time_ms"], "multisig response.creation_time_ms"),
            feePayment = FeePaymentJson.parse(
                root["fee_payment"],
                "multisig response.fee_payment",
            ),
            transactionPayloadB64 = optionalBase64(root["transaction_payload_b64"], "multisig response.transaction_payload_b64"),
            signingMessageB64 = optionalBase64(root["signing_message_b64"], "multisig response.signing_message_b64"),
        )
        validateUnsignedTransactionState(
            submitted = response.submitted,
            txHashHex = response.txHashHex,
            executedTxHashHex = response.executedTxHashHex,
            creationTimeMs = response.creationTimeMs,
            feePayment = response.feePayment,
            transactionPayloadB64 = response.transactionPayloadB64,
            signingMessageB64 = response.signingMessageB64,

            context = "multisig response",
        )
        return response
    }

    @JvmStatic
    fun parseGovernanceContractResponse(payload: ByteArray): GovernanceContractResponse {
        val root = expectObject(parse(payload, "governance contract response"), "governance contract response")
        val context = "governance contract response"
        val found = requiredBoolean(root["found"], "$context.found")
        val active = if (found) requiredBoolean(root["active"], "$context.active") else null
        val expectedFields = when {
            active == true -> setOf(
                "found", "contract_address", "contract_subject_account", "dataspace", "active",
                "lifecycle", "emergency_hold_active", "code_hash_hex", "abi_hash_hex",
                "public_entrypoints",
            )
            found -> setOf(
                "found", "contract_address", "contract_subject_account", "dataspace", "active",
                "lifecycle", "emergency_hold_active",
            )
            else -> setOf("found", "contract_address", "dataspace")
        }
        requireExactKeys(root, expectedFields, context)
        val contractSubjectAccount = if (found) {
            requiredExactAccountId(root["contract_subject_account"], "$context.contract_subject_account")
        } else {
            null
        }
        val dataspace = requiredExactString(root["dataspace"], "$context.dataspace")
        val lifecycle = if (found) {
            parseGovernanceContractLifecycle(root["lifecycle"], "$context.lifecycle")
        } else {
            null
        }
        val emergencyHoldActive = if (found) {
            requiredBoolean(root["emergency_hold_active"], "$context.emergency_hold_active")
        } else {
            null
        }
        val codeHashHex = if (active == true) exactLowerHex32(root["code_hash_hex"], "$context.code_hash_hex") else null
        val abiHashHex = if (active == true) exactLowerHex32(root["abi_hash_hex"], "$context.abi_hash_hex") else null
        val publicEntrypoints = if (active == true) {
            governancePublicEntrypoints(root["public_entrypoints"], "$context.public_entrypoints")
        } else {
            null
        }
        if (found) {
            check(active != null && lifecycle != null && emergencyHoldActive != null)
            if (active) {
                check(codeHashHex != null && abiHashHex != null && publicEntrypoints != null) {
                    "$context active response must contain all artifact fields"
                }
                check(lifecycle.activeCodeHashHex == codeHashHex) {
                    "$context lifecycle active code hash must match code_hash_hex"
                }
            } else {
                check(lifecycle.activeCodeHashHex == null) {
                    "$context lifecycle active code hash must be null for an inactive contract"
                }
            }
            check(!emergencyHoldActive || lifecycle.emergencyHold != null) {
                "$context active emergency-hold state requires a retained hold record"
            }
        }
        return GovernanceContractResponse(
            found = found,
            contractAddress = requiredExactString(root["contract_address"], "$context.contract_address"),
            contractSubjectAccount = contractSubjectAccount,
            dataspace = dataspace,
            active = active,
            lifecycle = lifecycle,
            emergencyHoldActive = emergencyHoldActive,
            codeHashHex = codeHashHex,
            abiHashHex = abiHashHex,
            publicEntrypoints = publicEntrypoints,
        )
    }

    private fun parseGovernanceContractLifecycle(value: Any?, context: String): GovernanceContractLifecycle {
        val record = expectObject(value, context)
        requireExactKeys(
            record,
            setOf(
                "version", "origin", "origin_account", "origin_proposal_content_id_hex",
                "origin_governance_attempt_id_hex", "owner", "pending_owner",
                "parliament_delegated", "active_code_hash_hex", "retained_code_hash_hex", "revision", "emergency_hold",
            ),
            context,
        )
        val version = asNonNegativeLong(record["version"], "$context.version")
        check(version == 1L) {
            "$context.version must equal the first-release lifecycle schema version 1"
        }
        val origin = requiredExactString(record["origin"], "$context.origin")
        check(origin == "direct" || origin == "parliament") { "$context.origin must be direct or parliament" }
        val revision = asU64(record["revision"], "$context.revision")
        check(revision.signum() > 0) { "$context.revision must be positive" }
        val proposalContentId = optionalExactHash(
            record["origin_proposal_content_id_hex"],
            "$context.origin_proposal_content_id_hex",
        )
        val governanceAttemptId = optionalExactHash(
            record["origin_governance_attempt_id_hex"],
            "$context.origin_governance_attempt_id_hex",
        )
        check(origin != "direct" || proposalContentId == null && governanceAttemptId == null) {
            "$context direct origin must not carry Parliament identifiers"
        }
        check(origin != "parliament" || proposalContentId != null && governanceAttemptId != null) {
            "$context Parliament origin requires both governance identifiers"
        }
        val activeCodeHash = optionalExactHash(record["active_code_hash_hex"], "$context.active_code_hash_hex")
        val retainedCodeHash = optionalExactHash(record["retained_code_hash_hex"], "$context.retained_code_hash_hex")
        check(activeCodeHash == null || retainedCodeHash == activeCodeHash) {
            "$context.retained_code_hash_hex must match active_code_hash_hex for an active binding"
        }
        return GovernanceContractLifecycle(
            version = version.toInt(),
            origin = origin,
            originAccount = requiredExactAccountId(record["origin_account"], "$context.origin_account"),
            originProposalContentIdHex = proposalContentId,
            originGovernanceAttemptIdHex = governanceAttemptId,
            owner = governanceContractOwner(record["owner"], "$context.owner"),
            pendingOwner = record["pending_owner"]?.let {
                governanceContractOwner(it, "$context.pending_owner")
            },
            parliamentDelegated = requiredBoolean(record["parliament_delegated"], "$context.parliament_delegated"),
            activeCodeHashHex = activeCodeHash,
            retainedCodeHashHex = retainedCodeHash,
            revision = revision,
            emergencyHold = record["emergency_hold"]?.let {
                parseGovernanceContractEmergencyHold(it, "$context.emergency_hold")
            },
        )
    }

    private fun parseGovernanceContractEmergencyHold(value: Any?, context: String): GovernanceContractEmergencyHold {
        val record = expectObject(value, context)
        requireExactKeys(
            record,
            setOf(
                "incident_digest_hex", "proposal_content_id_hex", "governance_attempt_id_hex",
                "reason", "imposed_at_height", "expires_at_height",
            ),
            context,
        )
        val imposedAtHeight = asU64(record["imposed_at_height"], "$context.imposed_at_height")
        val expiresAtHeight = asU64(record["expires_at_height"], "$context.expires_at_height")
        check(imposedAtHeight.signum() > 0) { "$context.imposed_at_height must be positive" }
        check(expiresAtHeight > imposedAtHeight) { "$context.expires_at_height must follow imposed_at_height" }
        return GovernanceContractEmergencyHold(
            incidentDigestHex = optionalExactHash(record["incident_digest_hex"], "$context.incident_digest_hex")
                ?: error("$context.incident_digest_hex is required"),
            proposalContentIdHex = optionalExactHash(record["proposal_content_id_hex"], "$context.proposal_content_id_hex")
                ?: error("$context.proposal_content_id_hex is required"),
            governanceAttemptIdHex = optionalExactHash(record["governance_attempt_id_hex"], "$context.governance_attempt_id_hex")
                ?: error("$context.governance_attempt_id_hex is required"),
            reason = requiredExactString(record["reason"], "$context.reason"),
            imposedAtHeight = imposedAtHeight,
            expiresAtHeight = expiresAtHeight,
        )
    }

    private fun requireExactKeys(value: Map<String, Any?>, expected: Set<String>, path: String) {
        check(value.keys == expected) { "$path fields must match the exact first-release schema" }
    }

    private fun optionalExactHash(value: Any?, path: String): String? =
        if (value == null) null else exactLowerHex32(value, path)

    private fun governanceContractOwner(value: Any?, path: String): String {
        val literal = requiredExactString(value, path)
        return if (literal == "parliament") literal else requiredExactAccountId(literal, path)
    }

    private fun governancePublicEntrypoints(value: Any?, path: String): List<String> {
        val entries = requiredList(value, path).mapIndexed { index, item ->
            val entry = requiredExactString(item, "$path[$index]")
            check(entry.matches(Regex("[a-z][a-z0-9_]{0,127}"))) {
                "$path[$index] must be a canonical public entrypoint name"
            }
            entry
        }
        check(entries.isNotEmpty()) { "$path must not be empty" }
        check(entries.zipWithNext().all { (left, right) -> left < right }) {
            "$path must be sorted and contain no duplicates"
        }
        return entries
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

    private fun requiredString(value: Any?, path: String): String {
        check(value is String) { "$path must be a string" }
        check(value.isNotBlank()) { "$path must be a non-empty string" }
        return value.trim()
    }

    private fun requiredExactAccountId(value: Any?, path: String): String {
        val string = requiredExactString(value, path)
        return try {
            requireCanonicalI105Address(string, path)
        } catch (ex: IllegalArgumentException) {
            throw IllegalStateException("$path must be a canonical I105 account id", ex)
        }
    }

    private fun requiredExactString(value: Any?, path: String): String {
        check(value is String) { "$path must be a string" }
        check(value.isNotBlank()) { "$path must be a non-empty string" }
        check(value.trim() == value) { "$path must not contain surrounding whitespace" }
        return value
    }

    private fun optionalString(value: Any?, path: String): String? {
        if (value == null) return null
        check(value is String) { "$path must be a string when present" }
        return value.trim().ifEmpty { null }
    }

    private fun optionalHash(value: Any?, path: String): String? {
        if (value == null) return null
        return HttpClientTransport.normalizeHex32(requiredString(value, path), path)
    }

    private fun transactionHash(value: Any?, path: String): String {
        check(value is String) { "$path must be a string" }
        val literal = value
        check(literal.matches(Regex("[0-9a-f]{63}[13579bdf]"))) {
            "$path must match [0-9a-f]{63}[13579bdf] with the Iroha HashOf marker"
        }
        return literal
    }

    private fun optionalTransactionHash(value: Any?, path: String): String? =
        if (value == null) null else transactionHash(value, path)

    private fun optionalObject(value: Any?, path: String): Map<String, Any?>? {
        if (value == null) return null
        return expectObject(value, path).toMap()
    }

    private fun requiredBoolean(value: Any?, path: String): Boolean {
        check(value is Boolean) { "$path must be a boolean" }
        return value
    }

    private fun asLong(value: Any?, path: String): Long {
        return JsonNumbers.asLong(value, path)
    }

    private fun asOptionalLong(value: Any?, path: String): Long? {
        if (value == null) return null
        return asLong(value, path)
    }

    private fun asOptionalNonNegativeLong(value: Any?, path: String): Long? {
        val parsed = asOptionalLong(value, path) ?: return null
        check(parsed >= 0) { "$path must be non-negative" }
        return parsed
    }

    private fun asNonNegativeLong(value: Any?, path: String): Long {
        val parsed = asLong(value, path)
        check(parsed >= 0) { "$path must be non-negative" }
        return parsed
    }

    private fun asU64(value: Any?, path: String): BigInteger {
        val parsed = when (value) {
            is BigInteger -> value
            is Byte, is Short, is Int, is Long -> BigInteger.valueOf((value as Number).toLong())
            else -> throw IllegalStateException("$path must be an integer")
        }
        check(parsed.signum() >= 0 && parsed <= U64_MAX) { "$path must fit u64" }
        return parsed
    }

    private fun requiredList(value: Any?, path: String): List<Any?> {
        check(value is List<*>) { "$path must be an array" }
        return value
    }

    private fun requiredStringList(value: Any?, path: String): List<String> {
        return requiredList(value, path).mapIndexed { index, item ->
            requiredString(item, "$path[$index]")
        }
    }

    private fun optionalBase64(value: Any?, path: String): String? {
        if (value == null) return null
        check(value is String) { "$path must be a base64 string when present" }
        val literal = value
        check(literal.isNotEmpty() && literal == literal.trim()) {
            "$path must be exact standard-base64"
        }
        val decoded = try {
            Base64.getDecoder().decode(literal)
        } catch (ex: IllegalArgumentException) {
            throw IllegalStateException("$path must be valid base64", ex)
        }
        check(decoded.isNotEmpty()) { "$path must not decode to empty bytes" }
        check(Base64.getEncoder().encodeToString(decoded) == literal) {
            "$path must be exact standard-base64"
        }
        return literal
    }

    private fun rejectRetiredDraftFields(value: Map<String, Any?>, context: String) {
        val retired = RETIRED_DRAFT_FIELDS.firstOrNull(value::containsKey)
        check(retired == null) { "$context contains retired field `$retired`" }
    }

    private fun validateUnsignedTransactionState(
        submitted: Boolean,
        txHashHex: String?,
        executedTxHashHex: String?,
        creationTimeMs: Long?,
        feePayment: FeePaymentIntent?,
        transactionPayloadB64: String?,
        signingMessageB64: String?,

        context: String,
    ) {
        if (submitted) {
            check(txHashHex != null && transactionPayloadB64 == null && signingMessageB64 == null) {
                "$context submitted response must contain only the final transaction hash"
            }
            return
        }
        check(txHashHex == null && transactionPayloadB64 != null && signingMessageB64 != null) {
            "$context unsigned response must contain exactly one payload and signing-message pair"
        }
        val transactionPayload = Base64.getDecoder().decode(transactionPayloadB64)
        val signingMessage = Base64.getDecoder().decode(signingMessageB64)
        val decodedPayload = try {
            NoritoJavaCodecAdapter.decodeCanonicalTransactionPayload(
                transactionPayload,

            )
        } catch (ex: Exception) {
            throw IllegalStateException(
                "$context.transaction_payload_b64 must contain one canonical TransactionPayload",
                ex,
            )
        }
        check(signingMessage.size == 32 && signingMessage.contentEquals(IrohaHash.prehash(transactionPayload))) {
            "$context.signing_message_b64 must be the exact TransactionPayload hash"
        }
        check(feePayment != null && decodedPayload.feePayment == feePayment) {
            "$context.fee_payment must match the exact TransactionPayload"
        }
        check(decodedPayload.creationTimeMs == creationTimeMs) {
            "$context.creation_time_ms must match the exact TransactionPayload"
        }
        check(executedTxHashHex == null) {
            "$context unsigned response must not contain transaction hashes"
        }
    }

    private val RETIRED_DRAFT_FIELDS = setOf(
        "transaction_scaffold_b64",
        "transaction_scaffold_base64",
        "signed_transaction_b64",
        "placeholder_transaction_hash_hex",
        "placeholder_entrypoint_hash_hex",
    )

    private val U64_MAX: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
}
