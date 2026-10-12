package org.hyperledger.iroha.sdk.core.model;

import java.util.Collections;

/** Java-source consumer of the single Kotlin-owned signed attachment API. */
public final class SignedAttachmentsJavaCalls {
    private SignedAttachmentsJavaCalls() {}

    public static void verify() {
        byte[] proof = {7};
        SignedAttachmentOccurrenceV1 occurrence = SignedAttachmentOccurrenceV1.of(0, AttachmentKindV1.Proof, proof);
        proof[0] = 8;
        byte[] inputs = new byte[32];
        byte[] statement = new byte[32];
        inputs[0] = 1;
        statement[0] = 2;
        ActionIntentV1 action = new ActionIntentV1(0, ActionOperationV1.TransactionProof.INSTANCE,
                ActionRoleV1.ProofVerification, ActionAuthorityBindingV1.TransactionAuthority.INSTANCE,
                ActionInvocationBindingV1.Transaction.INSTANCE, new ActionPublicInputsDigestV1(inputs),
                new ActionStatementDigestV1(statement), Collections.singletonList(occurrence.reference(AttachmentRoleV1.ActionProof)));
        SignedAttachmentsV1 attachments = new SignedAttachmentsV1(Collections.singletonList(action), Collections.singletonList(occurrence));
        attachments.validateStructure();
        if (attachments.getOccurrences().get(0).getBytes()[0] != 7) throw new AssertionError("mutable proof escaped");
        if (!attachments.getActions().get(0).equals(action)) throw new AssertionError("action access failed");
        byte[] commitment = new byte[32];
        commitment[31] = 1;
        Executable proved = Executable.ivmProved(new byte[] {1, 2}, Collections.emptyList(), commitment, commitment);
        commitment[31] = 0;
        if (!proved.requiresTransactionGasLimit()) throw new AssertionError("proved execution lacks gas binding");
        if (((Executable.IvmProved) proved).getEventsCommitment()[31] != 1) throw new AssertionError("mutable commitment escaped");
    }

    public static void main(String[] args) {
        verify();
        System.out.println("Java-source signed attachment consumer passed");
    }
}
