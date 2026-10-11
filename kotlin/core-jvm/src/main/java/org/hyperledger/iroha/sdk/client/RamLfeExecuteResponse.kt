package org.hyperledger.iroha.sdk.client

/** Exact32 native opaque output and generic program receipt; this is no network-audience admission. */
class RamLfeExecuteResponse(
    @JvmField val programId: String,
    @JvmField val programIdCanonicalHex: String,
    @JvmField val opaqueHash: String,
    @JvmField val receiptHash: String,
    @JvmField val opaqueOutputHex: String,
    @JvmField val outputHash: String,
    @JvmField val associatedDataHash: String,
    @JvmField val executedAtMs: Long,
    @JvmField val expiresAtMs: Long?,
    @JvmField val backend: String,
    @JvmField val verificationMode: String,
    receipt: Map<String, Any>,
) {
    @JvmField
    val receipt: Map<String, Any> = copyObject(receipt)
    @JvmField val execution: IdentifierResolutionExecutionPayload
    @JvmField val attestation: IdentifierReceiptAttestation
    private val originalProgramFrame: ByteArray
    init {
        IdentifierOwnerInputV1.exactText(programId, "ram-lfe execute response.program_id")
        originalProgramFrame = RamLfeExecuteConsistencyV1.programFrame(programIdCanonicalHex)
        val fields = this.receipt
        require(fields.keys == setOf("payload", "attestation")) { "ram-lfe execute response.receipt requires exact original fields" }
        @Suppress("UNCHECKED_CAST")
        val payload = fields["payload"] as? Map<String, Any?> ?: throw IllegalArgumentException("Original execute receipt payload is required")
        @Suppress("UNCHECKED_CAST")
        val signature = fields["attestation"] as? Map<String, Any?> ?: throw IllegalArgumentException("Original execute receipt attestation is required")
        execution = IdentifierJsonParser.parseResolutionExecutionPayload(payload, "ram-lfe execute response.receipt.payload")
        attestation = IdentifierJsonParser.parseReceiptAttestation(signature, "ram-lfe execute response.receipt.attestation")
        require(backend == IdentifierOwnerInputV1.BACKEND && verificationMode == "signed" && attestation.kind == "signed") { "Current execute requires HKDF/Signed metadata" }
        IdentifierOwnerInputV1.originalLease(executedAtMs, expiresAtMs)
        val hashes = RamLfeExecuteConsistencyV1.commitments(originalProgramFrame, opaqueOutputHex)
        require(hashes.output == outputHash) { "ram-lfe execute response.output_hash differs from original opaque_output" }
        require(hashes.opaque == opaqueHash) { "ram-lfe execute response.opaque_hash differs from original program/output" }
        require(hashes.receipt == receiptHash) { "ram-lfe execute response.receipt_hash differs from original program/output/opaque hash" }
        require(hashes.associated == associatedDataHash) { "ram-lfe execute response.associated_data_hash differs from original native program frame" }
        require(execution.programId == programId && execution.backend == backend && execution.verificationMode == verificationMode &&
            execution.outputHash == outputHash && execution.outputCiphertextHash == outputHash && execution.associatedDataHash == associatedDataHash &&
            execution.executedAtMs == executedAtMs && execution.expiresAtMs == expiresAtMs) { "Execute response differs from the unchanged original signed receipt" }
    }
    /** Original native frame DATA; this does not decode, replace or confer codec authority. */
    fun programIdCanonicalBytes(): ByteArray = originalProgramFrame.copyOf()
    /** Uses an independently selected current policy and the complete genuine original signature. */
    fun verifyResolverSignature(policy: RamLfeProgramPolicySummary): Boolean =
        IdentifierReceiptVerifier.verifyExecutionResolverSignature(this, policy)
    companion object {
        @Suppress("UNCHECKED_CAST")
        private fun copyObject(value: Map<String, Any?>): Map<String, Any> =
            java.util.Collections.unmodifiableMap(value.mapValues { (_, child) -> copyValue(child) }) as Map<String, Any>
        private fun copyValue(value: Any?): Any? = when (value) {
            null -> null
            is Map<*, *> -> copyObject(value.entries.associate { entry -> require(entry.key is String); (entry.key as String) to entry.value })
            is List<*> -> java.util.Collections.unmodifiableList(value.map { copyValue(it) })
            is String, is Boolean, is Long, is Int, is Double, is Float, is java.math.BigInteger, is java.math.BigDecimal -> value
            else -> throw IllegalArgumentException("receipt must contain immutable JSON data")
        }
    }
}
