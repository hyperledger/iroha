//! Original-source and adversarial controls for bounded host custody only.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    Level, NetworkId,
    block::BlockHeader,
    isi::{InstructionBox, Log, instruction_wire_id},
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    transaction::{
        Executable, FeePaymentIntent, TransactionBuilder,
        executable::IvmBytecode,
        signed_attachments::{
            PlannedActionV1, PlannedAttachmentV1, SignedAttachmentPlanV1, SignedAttachmentsV1,
        },
    },
};

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}
fn instruction() -> InstructionBox {
    Log::new(Level::INFO, "custody".to_owned()).into()
}
fn builder(executable: Executable) -> TransactionBuilder {
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"custody-fixture"),
    ));
    TransactionBuilder::new(
        network,
        account(1),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(executable)
}
fn native(
    binding: ActionInvocationBindingV1,
    authority: ActionAuthorityBindingV1,
    seed: u8,
) -> PlannedActionV1 {
    PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(
            instruction_wire_id(&instruction()).unwrap().to_owned(),
        ),
        role: ActionRoleV1::ProofEffect,
        authority,
        invocation: binding,
        public_inputs_digest: ActionPublicInputsDigestV1::new([seed; 32]),
        attachments: vec![
            PlannedAttachmentV1 {
                kind: AttachmentKindV1::Proof,
                role: AttachmentRoleV1::ActionProof,
                bytes: vec![seed; 65536],
            },
            PlannedAttachmentV1 {
                kind: AttachmentKindV1::KeyMaterial,
                role: AttachmentRoleV1::VerifyingKey,
                bytes: vec![seed.wrapping_add(1); 16],
            },
        ],
    }
}
fn signed(actions: Vec<PlannedActionV1>, contract: bool) -> SignedTransaction {
    let executable = if contract {
        Executable::Ivm(IvmBytecode::from_compiled(vec![0x01, 0x02]))
    } else {
        Executable::Instructions(
            (0..actions.len())
                .map(|_| instruction())
                .collect::<Vec<_>>()
                .into(),
        )
    };
    let mut plan = SignedAttachmentPlanV1::new();
    for action in actions {
        plan.push_action(action);
    }
    builder(executable)
        .with_attachment_plan(plan)
        .unwrap()
        .sign(key(1).private_key())
}
fn direct() -> SignedTransaction {
    signed(
        vec![native(
            ActionInvocationBindingV1::Direct {
                instruction_index: 0,
            },
            ActionAuthorityBindingV1::TransactionAuthority,
            3,
        )],
        false,
    )
}
fn contract() -> SignedTransaction {
    signed(
        vec![
            native(
                ActionInvocationBindingV1::Contract {
                    root_index: 0,
                    call_path: vec![],
                },
                ActionAuthorityBindingV1::ContractSubject(account(2)),
                3,
            ),
            native(
                ActionInvocationBindingV1::Contract {
                    root_index: 0,
                    call_path: vec![0],
                },
                ActionAuthorityBindingV1::ContractSubject(account(4)),
                5,
            ),
        ],
        true,
    )
}
fn request(source: &SignedTransaction, index: u32) -> ActionRequest<'_> {
    let action = source.attachments().unwrap().action(index).unwrap();
    ActionRequest {
        index,
        operation: &action.operation,
        role: action.role,
        public_inputs_digest: action.public_inputs_digest,
    }
}
fn consume_action(
    frame: &mut Invocation<'_, '_>,
    source: &SignedTransaction,
    index: u32,
) -> Result<(), CustodyError> {
    let action = source.attachments().unwrap().action(index).unwrap();
    for (slot, reference) in action.attachments.iter().enumerate() {
        let handle = frame.open(
            request(source, index),
            slot as u32,
            reference.kind,
            reference.role,
        )?;
        let bytes = frame.consume(
            request(source, index),
            handle,
            reference.kind,
            reference.role,
        )?;
        let original = &source
            .attachments()
            .unwrap()
            .occurrence(reference.index)
            .unwrap()
            .bytes;
        assert_eq!(bytes.as_ptr(), original.as_ptr());
        assert_eq!(bytes.len(), original.len());
        assert_eq!(bytes, original.as_slice());
    }
    frame.finish_action(request(source, index))
}

#[test]
fn original_signed_source_and_every_consumed_byte_remain_borrowed() {
    let tx = direct();
    let before = norito::encode_canonical(&tx).unwrap();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert!(std::ptr::eq(custody.owner.source, &tx));
    custody
        .direct(0, tx.authority(), |frame| consume_action(frame, &tx, 0))
        .unwrap();
    custody.finish().unwrap();
    assert_eq!(norito::encode_canonical(&tx).unwrap(), before);
}

#[test]
fn original_wrapped_transaction_carrier_has_one_consuming_scope() {
    let proof = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![9; 48]),
        VerifyingKeyId::new("halo2/ipa", "custody"),
    );
    let tx = builder(Executable::Instructions(vec![instruction()].into()))
        .with_proof_attachments([proof])
        .unwrap()
        .sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .transaction(|frame| consume_action(frame, &tx, 0))
        .unwrap();
    custody.finish().unwrap();
}

#[test]
fn attachment_free_source_needs_no_synthetic_action_or_proof() {
    let tx =
        builder(Executable::Instructions(vec![instruction()].into())).sign(key(1).private_key());
    AttachmentCustody::new(&tx).unwrap().finish().unwrap();
}

#[test]
fn invalid_original_signature_is_not_authenticated_by_the_descriptor() {
    let tx = direct();
    let invalid = TransactionBuilder::from_payload(tx.payload().clone())
        .unwrap()
        .build_with_signature(Signature::from_bytes(&[0; 64]));
    assert!(matches!(
        AttachmentCustody::new(&invalid).err(),
        Some(CustodyError::Signature(_))
    ));
}

#[test]
fn changed_occurrence_metadata_uses_the_original_schema_refusal() {
    let tx = direct();
    let parts = tx.attachments().unwrap();
    let mut occurrences = parts.occurrences().to_vec();
    occurrences[0].length += 1;
    let malformed =
        SignedAttachmentsV1::from_parts_unvalidated(parts.actions().to_vec(), occurrences);
    let invalid = builder(tx.instructions().clone())
        .with_signed_attachments(malformed)
        .sign(key(1).private_key());
    assert_eq!(
        AttachmentCustody::new(&invalid).err(),
        Some(CustodyError::Declaration(
            SignedAttachmentErrorV1::OccurrenceLengthMismatch {
                index: 0,
                declared: 65537,
                actual: 65536
            }
        ))
    );
}

#[test]
fn wrong_actor_cannot_borrow_a_signed_action() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, &account(2), |frame| consume_action(frame, &tx, 0)),
        Err(CustodyError::WrongAuthority(0))
    );
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn wrong_direct_position_cannot_borrow_a_signed_action() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(1, tx.authority(), |frame| consume_action(frame, &tx, 0)),
        Err(CustodyError::WrongInvocation(0))
    );
}

#[test]
fn actual_request_operation_role_and_public_inputs_must_all_match() {
    let tx = direct();
    let other = ActionOperationV1::TransactionProof;
    for case in 0..3 {
        let mut custody = AttachmentCustody::new(&tx).unwrap();
        let result: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
            let mut actual = request(&tx, 0);
            match case {
                0 => actual.operation = &other,
                1 => actual.role = ActionRoleV1::Administrative,
                _ => actual.public_inputs_digest = ActionPublicInputsDigestV1::new([0xFF; 32]),
            }
            frame.open(
                actual,
                0,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            Ok(())
        });
        assert_eq!(result, Err(CustodyError::WrongAction(0)));
    }
}

#[test]
fn missing_action_and_missing_slot_refuse_the_whole_attempt() {
    let tx = direct();
    for missing_action in [true, false] {
        let mut custody = AttachmentCustody::new(&tx).unwrap();
        let result: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
            let mut actual = request(&tx, 0);
            if missing_action {
                actual.index = 99;
            }
            frame.open(
                actual,
                99,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            Ok(())
        });
        let expected = if missing_action {
            CustodyError::MissingAction(99)
        } else {
            CustodyError::MissingSlot {
                action: 0,
                slot: 99,
            }
        };
        assert_eq!(result, Err(expected));
        assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
    }
}

#[test]
fn wrong_type_or_role_is_refused_at_open_and_consume() {
    let tx = direct();
    for at_consume in [false, true] {
        for (kind, role) in [
            (AttachmentKindV1::KeyMaterial, AttachmentRoleV1::ActionProof),
            (AttachmentKindV1::Proof, AttachmentRoleV1::ExecutionProof),
        ] {
            let mut custody = AttachmentCustody::new(&tx).unwrap();
            let result: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
                if at_consume {
                    let token = frame.open(
                        request(&tx, 0),
                        0,
                        AttachmentKindV1::Proof,
                        AttachmentRoleV1::ActionProof,
                    )?;
                    frame.consume(request(&tx, 0), token, kind, role)?;
                } else {
                    frame.open(request(&tx, 0), 0, kind, role)?;
                }
                Ok(())
            });
            assert_eq!(result, Err(CustodyError::WrongTypeOrRole(0)));
        }
    }
}

#[test]
fn copied_token_does_not_allow_duplicate_consumption() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
        let token = frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        frame.consume(
            request(&tx, 0),
            token,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        frame.consume(
            request(&tx, 0),
            token,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        Ok(())
    });
    assert_eq!(result, Err(CustodyError::ReusedAttachment(0)));
    assert_eq!(
        (
            custody.attempt.issued,
            custody.attempt.consumed,
            custody.attempt.completed
        ),
        (0, 0, 0)
    );
}

#[test]
fn opening_the_same_occurrence_twice_is_not_a_new_handle() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
        frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        Ok(())
    });
    assert_eq!(result, Err(CustodyError::ReusedAttachment(0)));
}

#[test]
fn an_exact_signed_clone_cannot_consume_an_original_owners_handle() {
    let tx = direct();
    let clone = tx.clone();
    let mut first = AttachmentCustody::new(&tx).unwrap();
    let mut second = AttachmentCustody::new(&clone).unwrap();
    let result: Result<(), CustodyError> = first.direct(0, tx.authority(), |frame| {
        let token = frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        let other: Result<(), CustodyError> = second.direct(0, clone.authority(), |other| {
            other.consume(
                request(&clone, 0),
                token,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            Ok(())
        });
        assert_eq!(other, Err(CustodyError::ForeignOwner));
        frame.consume(
            request(&tx, 0),
            token,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        let key = frame.open(
            request(&tx, 0),
            1,
            AttachmentKindV1::KeyMaterial,
            AttachmentRoleV1::VerifyingKey,
        )?;
        frame.consume(
            request(&tx, 0),
            key,
            AttachmentKindV1::KeyMaterial,
            AttachmentRoleV1::VerifyingKey,
        )?;
        frame.finish_action(request(&tx, 0))
    });
    result.unwrap();
    first.finish().unwrap();
    assert_eq!(second.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn token_for_one_action_cannot_be_used_as_another_action() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), CustodyError> = custody.contract(0, &account(2), |frame| {
        let token = frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        frame.consume(
            request(&tx, 1),
            token,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        Ok(())
    });
    assert_eq!(result, Err(CustodyError::WrongAction(1)));
}

#[test]
fn nested_child_consumes_only_its_signed_path_then_parent_resumes() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .contract(0, &account(2), |frame| {
            let parent = frame.open(
                request(&tx, 0),
                0,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            frame.child(&account(4), |child| consume_action(child, &tx, 1))?;
            frame.consume(
                request(&tx, 0),
                parent,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            let key = frame.open(
                request(&tx, 0),
                1,
                AttachmentKindV1::KeyMaterial,
                AttachmentRoleV1::VerifyingKey,
            )?;
            frame.consume(
                request(&tx, 0),
                key,
                AttachmentKindV1::KeyMaterial,
                AttachmentRoleV1::VerifyingKey,
            )?;
            frame.finish_action(request(&tx, 0))
        })
        .unwrap();
    custody.finish().unwrap();
}

#[test]
fn parent_token_is_not_implicitly_delegated_to_child() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), CustodyError> = custody.contract(0, &account(2), |frame| {
        let parent = frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        frame.child(&account(4), |child| {
            child.consume(
                request(&tx, 0),
                parent,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            Ok(())
        })
    });
    assert_eq!(result, Err(CustodyError::ExpiredHandle));
}

#[test]
fn sibling_ordinal_is_derived_from_actual_order_and_cannot_be_replayed() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result = custody.contract(0, &account(2), |frame| {
        consume_action(frame, &tx, 0)?;
        frame.child(&account(4), |child| consume_action(child, &tx, 1))?;
        frame.child(&account(4), |child| consume_action(child, &tx, 1))
    });
    assert_eq!(result, Err(CustodyError::WrongInvocation(1)));
}

#[test]
fn unfinished_action_and_occurrence_are_explicit_refusals() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |_| Ok::<_, CustodyError>(())),
        Err(CustodyError::UnconsumedAction(0))
    );
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| frame
            .finish_action(request(&tx, 0))),
        Err(CustodyError::UnconsumedAttachment(0))
    );
    assert_eq!(
        AttachmentCustody::new(&tx).unwrap().finish(),
        Err(CustodyError::UnconsumedAction(0))
    );
}

#[test]
fn duplicate_action_completion_refuses_even_after_all_data_was_consumed() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| {
            consume_action(frame, &tx, 0)?;
            frame.finish_action(request(&tx, 0))
        }),
        Err(CustodyError::ReusedAction(0))
    );
}

#[test]
fn swallowing_a_refusal_cannot_complete_or_restart_the_attempt() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| {
            assert!(
                frame
                    .open(
                        request(&tx, 0),
                        0,
                        AttachmentKindV1::KeyMaterial,
                        AttachmentRoleV1::VerifyingKey
                    )
                    .is_err()
            );
            Ok::<_, CustodyError>(())
        }),
        Err(CustodyError::FailedAttempt)
    );
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| consume_action(frame, &tx, 0)),
        Err(CustodyError::FailedAttempt)
    );
}

#[test]
fn native_error_is_preserved_and_discards_earlier_consumption() {
    #[derive(Debug, PartialEq, Eq)]
    enum NativeError {
        Custody(CustodyError),
        InvalidProof,
    }
    impl From<CustodyError> for NativeError {
        fn from(error: CustodyError) -> Self {
            Self::Custody(error)
        }
    }
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), NativeError> = custody.direct(0, tx.authority(), |frame| {
        consume_action(frame, &tx, 0)?;
        Err(NativeError::InvalidProof)
    });
    assert_eq!(result, Err(NativeError::InvalidProof));
    assert_eq!(
        (
            custody.attempt.issued,
            custody.attempt.consumed,
            custody.attempt.completed
        ),
        (0, 0, 0)
    );
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn unwind_discards_consumption_even_if_the_host_catches_the_panic() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), CustodyError> = custody.direct(0, tx.authority(), |frame| {
            consume_action(frame, &tx, 0)?;
            panic!("native consumer unwind");
        });
    }));
    assert!(caught.is_err());
    assert_eq!(
        (
            custody.attempt.issued,
            custody.attempt.consumed,
            custody.attempt.completed
        ),
        (0, 0, 0)
    );
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn generation_overflow_refuses_before_opening_any_scope() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody.attempt.generation = u64::MAX;
    assert_eq!(
        custody.direct(0, tx.authority(), |_| Ok::<_, CustodyError>(())),
        Err(CustodyError::GenerationExhausted)
    );
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn direct_invocation_cannot_fabricate_a_contract_child() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| frame
            .child(&account(4), |_| Ok::<_, CustodyError>(()))),
        Err(CustodyError::InvalidChild)
    );
}

#[test]
fn custody_does_not_remove_the_existing_no_native_consumer_refusal() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .direct(0, tx.authority(), |frame| consume_action(frame, &tx, 0))
        .unwrap();
    custody.finish().unwrap();
    assert!(!crate::tx::attachment_operation_is_supported(
        &tx.attachments().unwrap().action(0).unwrap().operation
    ));
    assert_eq!(
        crate::tx::first_unsupported_attachment_operation(&tx),
        Some(SignedAttachmentErrorV1::UnsupportedOperation { action_index: 0 })
    );
}

#[test]
fn later_action_failure_discards_prior_completed_action_bookkeeping() {
    let tx = signed(
        (0..2)
            .map(|index| {
                native(
                    ActionInvocationBindingV1::Direct {
                        instruction_index: index,
                    },
                    ActionAuthorityBindingV1::TransactionAuthority,
                    3 + index as u8,
                )
            })
            .collect(),
        false,
    );
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .direct(0, tx.authority(), |frame| consume_action(frame, &tx, 0))
        .unwrap();
    assert_eq!(custody.attempt.completed, 1);
    assert_eq!(
        custody.direct(1, &account(9), |frame| consume_action(frame, &tx, 1)),
        Err(CustodyError::WrongAuthority(1))
    );
    assert_eq!(
        (
            custody.attempt.issued,
            custody.attempt.consumed,
            custody.attempt.completed
        ),
        (0, 0, 0)
    );
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}

#[test]
fn omitted_child_declaration_prevents_whole_attempt_completion() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .contract(0, &account(2), |frame| consume_action(frame, &tx, 0))
        .unwrap();
    assert_eq!(custody.finish(), Err(CustodyError::UnconsumedAction(1)));
}

#[test]
fn contract_root_and_child_authority_are_both_exact() {
    let tx = contract();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.contract(1, &account(2), |frame| consume_action(frame, &tx, 0)),
        Err(CustodyError::WrongInvocation(0))
    );
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.contract(0, &account(2), |frame| {
            consume_action(frame, &tx, 0)?;
            frame.child(&account(2), |child| consume_action(child, &tx, 1))
        }),
        Err(CustodyError::WrongAuthority(1))
    );
}

#[test]
fn protocol_actor_must_be_the_explicitly_authorized_account() {
    let tx = signed(
        vec![native(
            ActionInvocationBindingV1::Direct {
                instruction_index: 0,
            },
            ActionAuthorityBindingV1::Account(account(8)),
            3,
        )],
        false,
    );
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    assert_eq!(
        custody.direct(0, tx.authority(), |frame| consume_action(frame, &tx, 0)),
        Err(CustodyError::WrongAuthority(0))
    );
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    custody
        .direct(0, &account(8), |frame| consume_action(frame, &tx, 0))
        .unwrap();
    custody.finish().unwrap();
}

#[test]
fn child_depth_and_ordinal_overflow_refuse_without_wraparound() {
    let tx = contract();
    for depth in [false, true] {
        let mut custody = AttachmentCustody::new(&tx).unwrap();
        let result = custody.contract(0, &account(2), |frame| {
            if depth {
                // Exercise the exact terminal guard without fabricating 33 signed paths.
                frame.binding = ActionInvocationBindingV1::Contract {
                    root_index: 0,
                    call_path: vec![0; ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1],
                };
            } else {
                frame.next_child = u32::MAX;
            }
            frame.child(&account(4), |_| Ok::<_, CustodyError>(()))
        });
        assert_eq!(
            result,
            Err(if depth {
                CustodyError::InvalidChild
            } else {
                CustodyError::GenerationExhausted
            })
        );
        assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
    }
}

#[test]
fn forged_internal_bad_slot_poison_cannot_be_swallowed() {
    let tx = direct();
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result = custody.direct(0, tx.authority(), |frame| {
        let legitimate = frame.open(
            request(&tx, 0),
            0,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        // Deliberately breach the private constructor boundary only in this
        // descendant test. No guest or other module can forge these fields.
        let forged = AttachmentHandle {
            slot: u32::MAX,
            ..legitimate
        };
        assert_eq!(
            frame.consume(
                request(&tx, 0),
                forged,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            ),
            Err(CustodyError::MissingSlot {
                action: 0,
                slot: u32::MAX
            })
        );
        assert!(frame.attempt.failed);
        assert_eq!(
            (
                frame.attempt.issued,
                frame.attempt.consumed,
                frame.attempt.completed
            ),
            (0, 0, 0)
        );
        assert_eq!(
            frame.consume(
                request(&tx, 0),
                legitimate,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            ),
            Err(CustodyError::FailedAttempt)
        );
        Ok::<_, CustodyError>(())
    });
    assert_eq!(result, Err(CustodyError::FailedAttempt));
    assert_eq!(custody.finish(), Err(CustodyError::FailedAttempt));
}
