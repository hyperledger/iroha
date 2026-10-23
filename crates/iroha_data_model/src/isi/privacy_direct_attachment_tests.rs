// Canonical direct PGC request/attachment binding controls (included in privacy::tests).
fn pgc_reference_payload(
    request: BootstrapPrivacyPgcAccountsV1,
    proof: Vec<u8>,
) -> crate::transaction::TransactionPayload {
    use crate::transaction::{FeePaymentIntent, TransactionBuilder, signed_attachments::*};
    let key: iroha_crypto::PrivateKey =
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .unwrap();
    let authority = crate::account::AccountId::new(iroha_crypto::PublicKey::from(key));
    let network = crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        crate::block::BlockHeader,
    >::from_untyped_unchecked(
        iroha_crypto::Hash::prehashed([0x41; 32])
    ));
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(
            BootstrapPrivacyPgcAccountsV1::WIRE_ID.into(),
        ),
        role: ActionRoleV1::Administrative,
        authority: ActionAuthorityBindingV1::TransactionAuthority,
        invocation: ActionInvocationBindingV1::Direct {
            instruction_index: 0,
        },
        public_inputs_digest: ActionPublicInputsDigestV1::new(
            *request.bootstrap.digest().unwrap().as_bytes(),
        ),
        attachments: vec![PlannedAttachmentV1 {
            kind: AttachmentKindV1::Proof,
            role: AttachmentRoleV1::ActionProof,
            bytes: proof,
        }],
    });
    TransactionBuilder::new(
        network,
        authority,
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([request])
    .with_signed_attachments(plan.declare())
    .payload()
    .clone()
}
fn pgc_reference_request() -> BootstrapPrivacyPgcAccountsV1 {
    BootstrapPrivacyPgcAccountsV1::new(
        pgc_bootstrap(),
        ActionAttachmentRefV1 {
            action_index: 0,
            slot_index: 0,
        },
    )
}
#[test]
fn pgc_reference_request_roundtrips_and_old_embedded_frame_is_rejected() {
    let request = pgc_reference_request();
    let frame = norito::to_bytes(&request).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<BootstrapPrivacyPgcAccountsV1>(&frame).unwrap(),
        request
    );
    let json = norito::json::to_json(&request).unwrap();
    assert!(json.contains("proof_ref"));
    assert_eq!(
        norito::json::from_json::<BootstrapPrivacyPgcAccountsV1>(&json).unwrap(),
        request
    );
    let old = include_bytes!("../../tests/fixtures/rejected_pgc_embedded_proof_frame.bin");
    assert!(norito::decode_from_bytes::<BootstrapPrivacyPgcAccountsV1>(old).is_err());
    let old_json = norito::json!({"bootstrap": (request.bootstrap), "proof": {"bytes": "pVoB"}});
    assert!(norito::json::from_value::<BootstrapPrivacyPgcAccountsV1>(old_json).is_err());
}
#[test]
fn pgc_reference_requires_exact_declared_direct_action_and_slot() {
    use crate::transaction::signed_attachments::SignedAttachmentErrorV1;
    let payload = pgc_reference_payload(pgc_reference_request(), vec![1]);
    payload.validate_signed_attachments_v1().unwrap();
    let mut missing = payload.clone();
    missing.attachments = None;
    assert!(matches!(
        missing.validate_signed_attachments_v1(),
        Err(SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 })
    ));
    for (action_index, slot_index) in [(1, 0), (0, 1)] {
        let request = BootstrapPrivacyPgcAccountsV1::new(
            pgc_bootstrap(),
            ActionAttachmentRefV1 {
                action_index,
                slot_index,
            },
        );
        let changed = pgc_reference_payload(request, vec![1]);
        assert!(changed.validate_signed_attachments_v1().is_err());
    }
    let mut reordered = payload;
    let crate::transaction::Executable::Instructions(instructions) = &reordered.instructions else {
        unreachable!()
    };
    reordered.instructions = crate::transaction::Executable::Instructions(
        vec![
            crate::isi::Log::new(crate::Level::INFO, "before".to_owned()).into(),
            instructions[0].clone(),
        ]
        .into(),
    );
    reordered.bind_attachment_statements_v1().unwrap();
    assert!(matches!(
        reordered.validate_signed_attachments_v1(),
        Err(SignedAttachmentErrorV1::InvocationTargetMismatch { action_index: 0 })
    ));
}
#[test]
fn pgc_ordered_intent_excludes_only_occurrence_bytes_and_keeps_request_reference() {
    let original = pgc_reference_payload(pgc_reference_request(), vec![1]);
    let mut changed = original.clone();
    changed
        .attachments
        .as_mut()
        .unwrap()
        .set_occurrence_bytes(0, vec![2, 3, 4])
        .unwrap();
    changed.bind_attachment_statements_v1().unwrap();
    changed.validate_signed_attachments_v1().unwrap();
    assert_eq!(
        original.ordered_intent_digest_v1().unwrap(),
        changed.ordered_intent_digest_v1().unwrap()
    );
    assert_eq!(
        original.action_statement_digests_v1().unwrap(),
        changed.action_statement_digests_v1().unwrap()
    );
    let mut request = pgc_reference_request();
    request.proof_ref.slot_index = 1;
    let mut changed = original.clone();
    changed.instructions =
        crate::transaction::Executable::Instructions(vec![request.into()].into());
    assert_ne!(
        original.ordered_intent_digest_v1().unwrap(),
        changed.ordered_intent_digest_v1().unwrap()
    );
    let mut request = pgc_reference_request();
    request.bootstrap.total_supply += 1;
    changed.instructions =
        crate::transaction::Executable::Instructions(vec![request.into()].into());
    changed.bind_attachment_statements_v1().unwrap();
    assert!(matches!(
        changed.validate_signed_attachments_v1(),
        Err(
            crate::transaction::signed_attachments::SignedAttachmentErrorV1::PublicInputsMismatch {
                action_index: 0
            }
        )
    ));
}
