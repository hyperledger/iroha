package org.hyperledger.iroha.sdk.core.model

import java.util.Collections
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.crypto.Blake3

/** Protocol bounds shared by the ordered intent and signed inline attachment layout. */
object SignedAttachmentLimitsV1 {
    const val MAX_ACTIONS = 16
    const val MAX_OCCURRENCES = 16
    const val MAX_OCCURRENCE_BYTES = 9 * 1024 * 1024
    const val MAX_FRAME_BYTES = MAX_OCCURRENCE_BYTES + 64 * 1024
    const val MAX_CALL_PATH = 32
    const val MAX_WIRE_ID_BYTES = 128
}

private fun attachmentU32(value: Long, name: String) {
    require(value in 0..0xffff_ffffL) { "$name must fit u32" }
}

private fun <T : Any> attachmentList(values: List<T>, maximum: Int): List<T> {
    val count = values.size
    require(count in 0..maximum) { "attachment list exceeds its bound" }
    return Collections.unmodifiableList(List(count) { requireNotNull(values[it]) })
}

private fun attachmentDigest(bytes: ByteArray): ByteArray {
    require(bytes.size == 32) { "attachment digest requires 32 bytes" }
    return bytes.copyOf()
}

/** BLAKE3 of the exact inline occurrence bytes. */
class AttachmentContentHashV1(bytes: ByteArray) {
    private val value = attachmentDigest(bytes)
    val bytes: ByteArray get() = value.copyOf()
    fun isZero(): Boolean = value.all { it == 0.toByte() }
    override fun equals(other: Any?): Boolean = other is AttachmentContentHashV1 && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

/** Digest of the independent public inputs of one action. */
class ActionPublicInputsDigestV1(bytes: ByteArray) {
    private val value = attachmentDigest(bytes)
    val bytes: ByteArray get() = value.copyOf()
    fun isZero(): Boolean = value.all { it == 0.toByte() }
    override fun equals(other: Any?): Boolean = other is ActionPublicInputsDigestV1 && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

/** Digest of the statement derived from the ordered transaction intent. */
class ActionStatementDigestV1(bytes: ByteArray) {
    private val value = attachmentDigest(bytes)
    val bytes: ByteArray get() = value.copyOf()
    fun isZero(): Boolean = value.all { it == 0.toByte() }
    override fun equals(other: Any?): Boolean = other is ActionStatementDigestV1 && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

/** Digest of the canonical proof-free ordered transaction intent. */
class OrderedIntentDigestV1(bytes: ByteArray) {
    private val value = attachmentDigest(bytes)
    val bytes: ByteArray get() = value.copyOf()
    fun isZero(): Boolean = value.all { it == 0.toByte() }
    override fun equals(other: Any?): Boolean = other is OrderedIntentDigestV1 && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

/** Occurrence type; declaration order is the canonical Norito enum tag. */
enum class AttachmentKindV1 { Proof, KeyMaterial }

/** Role of one occurrence; declaration order is the canonical Norito enum tag. */
enum class AttachmentRoleV1 {
    ActionProof, VerifyingKey, LanePrivacyProof, ExecutionProof;

    fun admits(kind: AttachmentKindV1): Boolean =
        if (this == VerifyingKey) kind == AttachmentKindV1.KeyMaterial else kind == AttachmentKindV1.Proof
}

/** Action role; declaration order is the canonical Norito enum tag. */
enum class ActionRoleV1 { ProofEffect, ProofVerification, Administrative, Effect }

/** Closed operation vocabulary, with native operations identified by their canonical wire ID. */
sealed class ActionOperationV1 {
    class NativeInstruction(val wireId: String) : ActionOperationV1() {
        init {
            require(wireId.isNotEmpty() && wireId.length <= SignedAttachmentLimitsV1.MAX_WIRE_ID_BYTES &&
                wireId.all { it.code in 33..126 }) { "native operation must be bounded graphic ASCII" }
        }
        override fun equals(other: Any?): Boolean = other is NativeInstruction && wireId == other.wireId
        override fun hashCode(): Int = wireId.hashCode()
    }
    object TransactionProof : ActionOperationV1()
    object IvmProvedExecution : ActionOperationV1()
}

/** Effective authority of the declared action, separate from the transaction signer. */
sealed class ActionAuthorityBindingV1 {
    object TransactionAuthority : ActionAuthorityBindingV1()
    class ContractSubject(val accountId: String) : ActionAuthorityBindingV1() {
        init { requireCanonicalI105Address(accountId, "contract subject") }
        override fun equals(other: Any?): Boolean = other is ContractSubject && accountId == other.accountId
        override fun hashCode(): Int = accountId.hashCode()
    }
    class Account(val accountId: String) : ActionAuthorityBindingV1() {
        init { requireCanonicalI105Address(accountId, "action account") }
        override fun equals(other: Any?): Boolean = other is Account && accountId == other.accountId
        override fun hashCode(): Int = accountId.hashCode()
    }
}

/** Exact transaction, direct instruction, or contract invocation addressed by an action. */
sealed class ActionInvocationBindingV1 {
    object Transaction : ActionInvocationBindingV1()
    class Direct(val instructionIndex: Long) : ActionInvocationBindingV1() {
        init { attachmentU32(instructionIndex, "instructionIndex") }
        override fun equals(other: Any?): Boolean = other is Direct && instructionIndex == other.instructionIndex
        override fun hashCode(): Int = instructionIndex.hashCode()
    }
    class Contract(val rootIndex: Long, callPath: List<Long>) : ActionInvocationBindingV1() {
        val callPath: List<Long> = attachmentList(callPath, SignedAttachmentLimitsV1.MAX_CALL_PATH)
        init {
            attachmentU32(rootIndex, "rootIndex")
            require(this.callPath.size <= SignedAttachmentLimitsV1.MAX_CALL_PATH) { "contract call path is too deep" }
            this.callPath.forEach { attachmentU32(it, "call path ordinal") }
        }
        override fun equals(other: Any?): Boolean = other is Contract && rootIndex == other.rootIndex && callPath == other.callPath
        override fun hashCode(): Int = 31 * rootIndex.hashCode() + callPath.hashCode()
    }
}

/** One action slot's complete reference to an inline occurrence. */
class AttachmentReferenceV1(
    val index: Long,
    val kind: AttachmentKindV1,
    val role: AttachmentRoleV1,
    val length: Long,
    val contentHash: AttachmentContentHashV1,
) {
    init {
        attachmentU32(index, "occurrence index")
        require(length in 0..SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES.toLong()) { "occurrence length exceeds its bound" }
    }
    override fun equals(other: Any?): Boolean = other is AttachmentReferenceV1 &&
        index == other.index && kind == other.kind && role == other.role && length == other.length && contentHash == other.contentHash
    override fun hashCode(): Int = arrayOf(index, kind, role, length, contentHash).contentHashCode()
}

/** Ordered proof-free action descriptor and its derived statement binding. */
class ActionIntentV1(
    val actionIndex: Long,
    val operation: ActionOperationV1,
    val role: ActionRoleV1,
    val authority: ActionAuthorityBindingV1,
    val invocation: ActionInvocationBindingV1,
    val publicInputsDigest: ActionPublicInputsDigestV1,
    val statementDigest: ActionStatementDigestV1,
    attachments: List<AttachmentReferenceV1>,
) {
    val attachments: List<AttachmentReferenceV1> = attachmentList(attachments, SignedAttachmentLimitsV1.MAX_OCCURRENCES)
    init {
        attachmentU32(actionIndex, "actionIndex")
        require(this.attachments.size <= SignedAttachmentLimitsV1.MAX_OCCURRENCES) { "too many attachment references" }
    }
    /** Replace only the digest derived from the enclosing transaction's ordered intent. */
    fun withStatementDigest(digest: ActionStatementDigestV1): ActionIntentV1 = ActionIntentV1(
        actionIndex, operation, role, authority, invocation, publicInputsDigest, digest, attachments,
    )
    override fun equals(other: Any?): Boolean = other is ActionIntentV1 &&
        actionIndex == other.actionIndex && operation == other.operation && role == other.role &&
        authority == other.authority && invocation == other.invocation && publicInputsDigest == other.publicInputsDigest &&
        statementDigest == other.statementDigest && attachments == other.attachments
    override fun hashCode(): Int = arrayOf(actionIndex, operation, role, authority, invocation, publicInputsDigest, statementDigest, attachments).contentHashCode()
}

/** Exact signed occurrence bytes, including their declared length and BLAKE3 hash. */
class SignedAttachmentOccurrenceV1(
    val index: Long,
    val kind: AttachmentKindV1,
    val length: Long,
    val contentHash: AttachmentContentHashV1,
    bytes: ByteArray,
) {
    private val value: ByteArray
    val bytes: ByteArray get() = value.copyOf()
    internal val byteCount: Int get() = value.size
    init {
        attachmentU32(index, "occurrence index")
        require(bytes.size <= SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES) { "occurrence bytes exceed their bound" }
        require(length in 0..SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES.toLong()) { "declared occurrence length exceeds its bound" }
        value = bytes.copyOf()
    }
    /** Construct one reference without changing its declared type, length or content hash. */
    fun reference(role: AttachmentRoleV1): AttachmentReferenceV1 = AttachmentReferenceV1(index, kind, role, length, contentHash)
    internal fun validate() {
        require(value.isNotEmpty()) { "empty attachment occurrence" }
        require(length == value.size.toLong()) { "attachment occurrence length mismatch" }
        require(contentHash == AttachmentContentHashV1(Blake3.hash(value))) { "attachment occurrence hash mismatch" }
    }
    override fun equals(other: Any?): Boolean = other is SignedAttachmentOccurrenceV1 &&
        index == other.index && kind == other.kind && length == other.length && contentHash == other.contentHash && value.contentEquals(other.value)
    override fun hashCode(): Int = 31 * arrayOf(index, kind, length, contentHash).contentHashCode() + value.contentHashCode()
    companion object {
        /** Record an occurrence's length and content hash from its exact bytes. */
        @JvmStatic
        fun of(index: Long, kind: AttachmentKindV1, bytes: ByteArray): SignedAttachmentOccurrenceV1 {
            require(bytes.isNotEmpty() && bytes.size <= SignedAttachmentLimitsV1.MAX_OCCURRENCE_BYTES) {
                "occurrence bytes must be nonempty and within their bound"
            }
            return SignedAttachmentOccurrenceV1(index, kind, bytes.size.toLong(), AttachmentContentHashV1(Blake3.hash(bytes)), bytes)
        }
    }
}

/**
 * Canonical ninth transaction field: ordered action descriptors and signed inline occurrences.
 *
 * Construction permits an unfinished proof plan; encoding and decoding require [validateStructure]
 * plus transaction-specific invocation, carrier and statement validation. Zero derived digests
 * are useful while deriving the proof-free intent and are never admitted in a signed payload.
 */
class SignedAttachmentsV1(actions: List<ActionIntentV1>, occurrences: List<SignedAttachmentOccurrenceV1>) {
    val actions: List<ActionIntentV1> = attachmentList(actions, SignedAttachmentLimitsV1.MAX_ACTIONS)
    val occurrences: List<SignedAttachmentOccurrenceV1> = attachmentList(occurrences, SignedAttachmentLimitsV1.MAX_OCCURRENCES)
    init {
        require(this.actions.isNotEmpty() && this.actions.size <= SignedAttachmentLimitsV1.MAX_ACTIONS) { "signed attachment action count is out of range" }
        require(this.occurrences.size <= SignedAttachmentLimitsV1.MAX_OCCURRENCES) { "too many signed attachment occurrences" }
    }
    /** Check counts, ordinals, contents, exact reference ownership and closed operation rules. */
    fun validateStructure() {
        val proofHashes = HashSet<AttachmentContentHashV1>()
        occurrences.forEachIndexed { position, occurrence ->
            require(occurrence.index == position.toLong()) { "attachment occurrences are out of order" }
            occurrence.validate()
            if (occurrence.kind == AttachmentKindV1.Proof) require(proofHashes.add(occurrence.contentHash)) { "duplicate proof occurrence" }
        }
        var nextReference = 0L
        actions.forEachIndexed { position, action ->
            require(action.actionIndex == position.toLong()) { "actions are out of order" }
            require(!action.publicInputsDigest.isZero()) { "zero action public-input digest" }
            require(!action.statementDigest.isZero()) { "zero action statement digest" }
            action.attachments.forEach { reference ->
                require(reference.index == nextReference) { "duplicate or out-of-order attachment reference" }
                val occurrence = occurrences.getOrNull(nextReference.toInt())
                    ?: throw IllegalArgumentException("missing attachment occurrence")
                require(reference.kind == occurrence.kind && reference.role.admits(reference.kind)) { "attachment type or role mismatch" }
                require(reference.length == occurrence.length && reference.contentHash == occurrence.contentHash) { "attachment reference length or hash mismatch" }
                nextReference++
            }
            when (action.operation) {
                ActionOperationV1.TransactionProof, ActionOperationV1.IvmProvedExecution -> {
                    val execution = action.operation == ActionOperationV1.IvmProvedExecution
                    require(action.role == if (execution) ActionRoleV1.ProofEffect else ActionRoleV1.ProofVerification) { "invalid carrier action role" }
                    require(action.authority == ActionAuthorityBindingV1.TransactionAuthority && action.invocation == ActionInvocationBindingV1.Transaction) { "invalid carrier authority or invocation" }
                    require(action.attachments.size == 1) { "a carrier requires exactly one attachment" }
                    val role = action.attachments.single().role
                    require(if (execution) role == AttachmentRoleV1.ExecutionProof else role == AttachmentRoleV1.ActionProof || role == AttachmentRoleV1.LanePrivacyProof) { "invalid carrier attachment role" }
                }
                is ActionOperationV1.NativeInstruction -> {
                    val authorityAdmitted = when (action.invocation) {
                        ActionInvocationBindingV1.Transaction -> false
                        is ActionInvocationBindingV1.Direct -> action.authority == ActionAuthorityBindingV1.TransactionAuthority || action.authority is ActionAuthorityBindingV1.Account
                        is ActionInvocationBindingV1.Contract -> action.authority is ActionAuthorityBindingV1.ContractSubject || action.authority is ActionAuthorityBindingV1.Account
                    }
                    require(authorityAdmitted) { "invalid native action authority or invocation" }
                    require(action.attachments.all { it.role == AttachmentRoleV1.ActionProof || it.role == AttachmentRoleV1.VerifyingKey }) { "invalid native attachment role" }
                }
            }
        }
        require(nextReference == occurrences.size.toLong()) { "unreferenced attachment occurrence" }
    }
    override fun equals(other: Any?): Boolean = other is SignedAttachmentsV1 && actions == other.actions && occurrences == other.occurrences
    override fun hashCode(): Int = 31 * actions.hashCode() + occurrences.hashCode()
}
