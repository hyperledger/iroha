package org.hyperledger.iroha.sdk.core.model

/** Shared assertions also runnable with the offline embedded compiler when Gradle is unavailable. */
internal object SignedAttachmentsModelAssertions {
    private fun rejects(block: () -> Unit) {
        try { block() } catch (_: IllegalArgumentException) { return }
        error("malformed attachment was accepted")
    }

    private fun occurrence(index: Long = 0, byte: Byte = 7) =
        SignedAttachmentOccurrenceV1.of(index, AttachmentKindV1.Proof, byteArrayOf(byte))

    private fun action(occurrence: SignedAttachmentOccurrenceV1, index: Long = 0) = ActionIntentV1(
        index, ActionOperationV1.TransactionProof, ActionRoleV1.ProofVerification,
        ActionAuthorityBindingV1.TransactionAuthority, ActionInvocationBindingV1.Transaction,
        ActionPublicInputsDigestV1(ByteArray(32) { 1 }), ActionStatementDigestV1(ByteArray(32) { 2 }),
        listOf(AttachmentReferenceV1(occurrence.index, occurrence.kind, AttachmentRoleV1.ActionProof,
            occurrence.length, occurrence.contentHash)),
    )

    fun digestsAreDistinctDefensiveValues() {
        val bytes = ByteArray(32) { 3 }
        val content = AttachmentContentHashV1(bytes)
        val inputs = ActionPublicInputsDigestV1(bytes)
        val statement = ActionStatementDigestV1(bytes)
        val intent = OrderedIntentDigestV1(bytes)
        bytes[0] = 0
        for (copy in listOf(content.bytes, inputs.bytes, statement.bytes, intent.bytes)) {
            check(copy[0] == 3.toByte()); copy[1] = 0
        }
        check(content == AttachmentContentHashV1(ByteArray(32) { 3 }))
        check(content.hashCode() == AttachmentContentHashV1(ByteArray(32) { 3 }).hashCode())
        check(!content.isZero() && OrderedIntentDigestV1(ByteArray(32)).isZero())
        rejects { AttachmentContentHashV1(ByteArray(31)) }
        rejects { ActionPublicInputsDigestV1(ByteArray(33)) }
        rejects { ActionStatementDigestV1(ByteArray(0)) }
        rejects { OrderedIntentDigestV1(ByteArray(64)) }
    }

    fun listsCheckBoundsBeforeReadingAndAreDefensive() {
        fun <T> oversized(size: Int): List<T> = object : AbstractList<T>() {
            override val size = size
            override fun get(index: Int): T = error("must reject count before copying elements")
        }
        rejects { SignedAttachmentsV1(oversized(17), emptyList()) }
        val item = occurrence()
        rejects { SignedAttachmentsV1(listOf(action(item)), oversized(17)) }
        rejects { ActionInvocationBindingV1.Contract(0, oversized(33)) }
        val path = mutableListOf(0L, 1L)
        val invocation = ActionInvocationBindingV1.Contract(0, path)
        path.clear(); check(invocation.callPath == listOf(0L, 1L))
        val indexOnly = object : AbstractList<ActionIntentV1>() {
            override val size = 1
            override fun get(index: Int) = action(item)
            override fun iterator(): Iterator<ActionIntentV1> = error("bounded snapshot must not use an unbounded iterator")
        }
        SignedAttachmentsV1(indexOnly, listOf(item)).validateStructure()
        val actions = mutableListOf(action(item))
        val occurrences = mutableListOf(item)
        val signed = SignedAttachmentsV1(actions, occurrences)
        actions.clear(); occurrences.clear(); signed.validateStructure()
        rejects { SignedAttachmentsV1(emptyList(), emptyList()) }
    }

    fun occurrenceContentsAndReferencesAreAdmittedExactly() {
        val bytes = byteArrayOf(7)
        val item = SignedAttachmentOccurrenceV1.of(0, AttachmentKindV1.Proof, bytes)
        bytes[0] = 8; item.bytes[0] = 9
        item.validate(); check(item.bytes[0] == 7.toByte())
        rejects { SignedAttachmentOccurrenceV1.of(0, AttachmentKindV1.Proof, byteArrayOf()) }
        rejects { SignedAttachmentOccurrenceV1(0, item.kind, 2, item.contentHash, item.bytes).validate() }
        rejects { SignedAttachmentOccurrenceV1(0, item.kind, 1, AttachmentContentHashV1(ByteArray(32)), item.bytes).validate() }
        SignedAttachmentsV1(listOf(action(item)), listOf(item)).validateStructure()
        rejects { SignedAttachmentsV1(listOf(action(item)), emptyList()).validateStructure() }
        rejects { SignedAttachmentsV1(listOf(action(item)), listOf(item, occurrence(1, 8))).validateStructure() }
        rejects { SignedAttachmentsV1(listOf(action(item), action(item, 1)), listOf(item)).validateStructure() }
        val duplicate = occurrence(1)
        rejects { SignedAttachmentsV1(listOf(action(item), action(duplicate, 1)), listOf(item, duplicate)).validateStructure() }
        rejects { SignedAttachmentsV1(listOf(action(item, 1)), listOf(item)).validateStructure() }
        rejects { SignedAttachmentsV1(listOf(action(item).withStatementDigest(ActionStatementDigestV1(ByteArray(32)))), listOf(item)).validateStructure() }
    }

    fun closedBindingsAndPrimitiveBoundsAreEnforced() {
        check(AttachmentRoleV1.VerifyingKey.admits(AttachmentKindV1.KeyMaterial))
        check(!AttachmentRoleV1.VerifyingKey.admits(AttachmentKindV1.Proof))
        rejects { ActionOperationV1.NativeInstruction("contains space") }
        rejects { ActionOperationV1.NativeInstruction("x".repeat(129)) }
        rejects { ActionInvocationBindingV1.Direct(-1) }
        rejects { ActionInvocationBindingV1.Contract(0x1_0000_0000L, emptyList()) }
        rejects { ActionAuthorityBindingV1.Account("alias@domain") }
        val item = occurrence()
        val invalid = ActionIntentV1(0, ActionOperationV1.TransactionProof, ActionRoleV1.Effect,
            ActionAuthorityBindingV1.TransactionAuthority, ActionInvocationBindingV1.Transaction,
            ActionPublicInputsDigestV1(ByteArray(32) { 1 }), ActionStatementDigestV1(ByteArray(32) { 2 }),
            action(item).attachments)
        rejects { SignedAttachmentsV1(listOf(invalid), listOf(item)).validateStructure() }
    }
}
