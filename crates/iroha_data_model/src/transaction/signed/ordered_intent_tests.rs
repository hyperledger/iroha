//! Payload-level tests of the ordered intent and its attachment bindings.

use super::*;
use crate::{
    Level,
    account::AccountId,
    isi::Log,
    privacy::{
        PrivacyStatementDigestV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
        PrivacyVegaDeviceAuthenticationDigestV1,
    },
    proof::{ProofBox, VerifyingKeyId},
    transaction::{
        IvmBytecode, IvmProved, TransactionDomain,
        executable::ContractInvocation,
        signed::FeePaymentIntent,
        signed_attachments::{
            ActionAuthorityBindingV1, ActionIntentV1, ActionPublicInputsDigestV1, ActionRoleV1,
            AttachmentKindV1, PlannedActionV1, PlannedAttachmentV1,
            SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
            SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1, SignedAttachmentOccurrenceV1,
        },
    },
};
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_model_base::{metadata::Metadata, name::Name};
use iroha_primitives::json::Json;
use std::{
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
    time::Duration,
};

const CREATION_TIME_MS: u64 = 1_725_000_000_000;

fn private_key() -> PrivateKey {
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
        .parse()
        .expect("fixed test key")
}

fn authority() -> AccountId {
    AccountId::new(PublicKey::from(private_key()))
}

fn other_account() -> AccountId {
    let other: PrivateKey =
        "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
            .parse()
            .expect("fixed other test key");
    AccountId::new(PublicKey::from(other))
}

fn attachment(name: &str, proof: Vec<u8>) -> ProofAttachment {
    ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), proof),
        VerifyingKeyId::new("halo2/ipa", name),
    )
}

fn log(message: &str) -> InstructionBox {
    InstructionBox::from(Log::new(Level::INFO, message.to_owned()))
}

fn log_wire_id() -> String {
    instruction_wire_id(&log("x"))
        .expect("Log is a registered instruction")
        .to_owned()
}

fn builder(executable: Executable) -> TransactionBuilder {
    let mut builder = TransactionBuilder::new_with_time(
        TransactionDomain::Network(super::super::test_network_id(0x41)),
        authority(),
        CREATION_TIME_MS,
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000)),
    )
    .with_executable(executable);
    builder.set_nonce(NonZeroU32::new(7).expect("nonzero"));
    builder
}

fn instructions() -> Executable {
    Executable::Instructions(vec![log("first"), log("second")].into())
}

fn contract_call() -> ContractInvocation {
    ContractInvocation {
        contract_address: crate::smart_contract::ContractAddress::derive(
            &super::super::test_network_id(0x41),
            &authority(),
            0,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("test contract address"),
        expected_code_hash: Hash::new(b"ordered intent test contract"),
        entrypoint: "run".to_owned(),
        arguments: None,
    }
}

/// A native action on the direct `Log` instruction at `instruction_index`.
fn direct_action(instruction_index: u32, slots: Vec<PlannedAttachmentV1>) -> PlannedActionV1 {
    PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(log_wire_id()),
        role: ActionRoleV1::ProofEffect,
        authority: ActionAuthorityBindingV1::TransactionAuthority,
        invocation: ActionInvocationBindingV1::Direct { instruction_index },
        public_inputs_digest: ActionPublicInputsDigestV1::new([0x5a; 32]),
        attachments: slots,
    }
}

/// A native action issued by the root contract invocation at `root_index`.
fn contract_action(root_index: u32, slots: Vec<PlannedAttachmentV1>) -> PlannedActionV1 {
    PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(log_wire_id()),
        role: ActionRoleV1::ProofEffect,
        authority: ActionAuthorityBindingV1::ContractSubject(other_account()),
        invocation: ActionInvocationBindingV1::Contract {
            root_index,
            call_path: Vec::new(),
        },
        public_inputs_digest: ActionPublicInputsDigestV1::new([0x5b; 32]),
        attachments: slots,
    }
}

fn proof_slot(bytes: Vec<u8>) -> PlannedAttachmentV1 {
    PlannedAttachmentV1 {
        kind: AttachmentKindV1::Proof,
        role: AttachmentRoleV1::ActionProof,
        bytes,
    }
}

fn key_slot(bytes: Vec<u8>) -> PlannedAttachmentV1 {
    PlannedAttachmentV1 {
        kind: AttachmentKindV1::KeyMaterial,
        role: AttachmentRoleV1::VerifyingKey,
        bytes,
    }
}

/// One carrier, then a direct native action with a proof and a key.
fn fixture_plan() -> SignedAttachmentPlanV1 {
    let mut plan = SignedAttachmentPlanV1::transaction_proofs(&[attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier");
    plan.push_action(direct_action(
        1,
        vec![proof_slot(vec![0xAA; 48]), key_slot(vec![0xBB; 32])],
    ));
    plan
}

fn fixture_payload() -> TransactionPayload {
    builder(instructions())
        .with_attachment_plan(fixture_plan())
        .expect("valid plan")
        .into_payload()
        .expect("valid payload")
}

fn sign(payload: TransactionPayload) -> SignedTransaction {
    // `from_payload` keeps the payload exactly as given: nothing is rebound.
    TransactionBuilder::from_payload(payload)
        .expect("ordinary payload")
        .sign(&private_key())
}

/// The typed violation, and proof that the signed transaction does not decode.
fn rejected(payload: &TransactionPayload) -> SignedAttachmentErrorV1 {
    let error = payload
        .validate_signed_attachments_v1()
        .expect_err("schema violation");
    let signed = sign(payload.clone());
    assert_eq!(signed.validate_signed_attachments_v1(), Err(error.clone()));
    let framed = norito::encode_canonical(&signed).expect("canonical frame");
    let decode_error = norito::decode_canonical::<SignedTransaction>(&framed)
        .expect_err("a signed transaction with this violation does not decode");
    assert!(
        decode_error.to_string().contains(&error.to_string()),
        "decoder reported `{decode_error}`, validation `{error}`"
    );
    error
}

fn mutate_attachments(
    payload: &TransactionPayload,
    change: impl FnOnce(&mut Vec<ActionIntentV1>, &mut Vec<SignedAttachmentOccurrenceV1>),
) -> TransactionPayload {
    let mut changed = payload.clone();
    let (mut actions, mut occurrences) = changed
        .attachments
        .take()
        .expect("fixture attachments")
        .into_parts();
    change(&mut actions, &mut occurrences);
    changed.attachments = Some(SignedAttachmentsV1::from_parts_unvalidated(
        actions,
        occurrences,
    ));
    changed
}

#[test]
fn attachment_free_payload_has_an_intent_and_nothing_to_bind() {
    let mut payload = builder(instructions()).into_payload().expect("payload");
    let digest = payload.ordered_intent_digest_v1().expect("intent");
    assert!(!digest.is_zero());
    assert_eq!(payload.action_statement_digests_v1(), Ok(Vec::new()));
    payload.validate_signed_attachments_v1().expect("valid");
    let before = payload.clone();
    payload.bind_attachment_statements_v1().expect("no-op");
    assert_eq!(payload, before);
    let signed = sign(payload);
    assert!(signed.attachments().is_none());
    assert_eq!(signed.proof_attachments_v1(), Ok(Vec::new()));
    assert_eq!(signed.lane_privacy_proofs_v1(), Ok(Vec::new()));
    assert_eq!(signed.ordered_intent_digest_v1(), Ok(digest));
}

#[test]
fn former_proof_attachment_list_in_the_ninth_field_does_not_decode() {
    use norito::codec::{Decode, Encode};

    /// The payload as it was before this layout: the same nine fields, the
    /// ninth carrying the optional proof attachment list.
    #[derive(Encode)]
    struct FormerTransactionPayload {
        domain: TransactionDomain,
        authority: AccountId,
        creation_time_ms: u64,
        instructions: Executable,
        time_to_live_ms: Option<NonZeroU64>,
        nonce: Option<NonZeroU32>,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
        attachments: Option<crate::proof::ProofAttachmentList>,
    }

    let payload = builder(instructions()).into_payload().expect("payload");
    let former = |attachments| FormerTransactionPayload {
        domain: payload.domain,
        authority: payload.authority.clone(),
        creation_time_ms: payload.creation_time_ms,
        instructions: payload.instructions.clone(),
        time_to_live_ms: payload.time_to_live_ms,
        nonce: payload.nonce,
        fee_payment: payload.fee_payment.clone(),
        metadata: payload.metadata.clone(),
        attachments,
    };

    // Without attachments the field is the single `None` byte in both
    // layouts, so the bytes are identical and decode to the same payload.
    let without = former(None).encode();
    assert_eq!(without, payload.encode());
    assert_eq!(
        TransactionPayload::decode(&mut without.as_slice()).expect("attachment-free payload"),
        payload
    );

    // With the former list in the ninth field the payload does not decode:
    // the field has one decoder and it reads the current layout only.
    let list = crate::proof::ProofAttachmentList::try_from(vec![attachment("vk_a", vec![1, 2, 3])])
        .expect("bounded list");
    let with_list = former(Some(list)).encode();
    assert_ne!(with_list, without);
    assert!(
        TransactionPayload::decode(&mut with_list.as_slice()).is_err(),
        "the former proof attachment list is not a transaction field"
    );
}

#[test]
fn ordered_intent_preimage_is_the_domain_the_length_and_the_normalized_frame() {
    let payload = fixture_payload();
    let projection = payload
        .ordered_intent_projection_bytes_v1()
        .expect("projection");
    assert_eq!(
        projection,
        norito::encode_canonical(&payload.ordered_intent_normalized_payload_v1()).expect("frame")
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(ORDERED_INTENT_DIGEST_DOMAIN_V1);
    hasher.update(&(projection.len() as u64).to_le_bytes());
    hasher.update(&projection);
    assert_eq!(
        payload
            .ordered_intent_digest_v1()
            .expect("intent")
            .into_bytes(),
        *hasher.finalize().as_bytes()
    );

    // The projection is stable under the ambient Norito layout flags.
    let alternate = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate);
    assert_eq!(
        payload
            .ordered_intent_projection_bytes_v1()
            .expect("projection under alternate ambient flags"),
        projection
    );
}

#[test]
fn ordered_intent_excludes_generated_values_and_binds_everything_else() {
    let payload = fixture_payload();
    let digest = payload.ordered_intent_digest_v1().expect("intent");

    let same = |changed: &TransactionPayload| {
        assert_ne!(changed, &payload, "the mutation must change the payload");
        assert_eq!(changed.ordered_intent_digest_v1().expect("intent"), digest);
    };
    let different = |changed: &TransactionPayload| {
        assert_ne!(changed.ordered_intent_digest_v1().expect("intent"), digest);
    };

    // Generated: proof bytes with their length and hash, and statement digests.
    let mut other_proof = payload.clone();
    other_proof
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(1, vec![0xCD; 77])
        .expect("proof slot");
    same(&other_proof);
    same(&mutate_attachments(&payload, |actions, _| {
        actions[0].statement_digest =
            crate::transaction::signed_attachments::ActionStatementDigestV1::new([9; 32]);
    }));
    let mut other_carrier = payload.clone();
    other_carrier
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(
            0,
            norito::encode_canonical(&attachment("vk_a", vec![7; 300])).expect("frame"),
        )
        .expect("carrier slot");
    same(&other_carrier);

    // Independent: admitted key material.
    let mut other_key = payload.clone();
    other_key
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(2, vec![0xBC; 32])
        .expect("key slot");
    different(&other_key);

    // Independent: every descriptor field.
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].public_inputs_digest = ActionPublicInputsDigestV1::new([0x5c; 32]);
    }));
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].role = ActionRoleV1::ProofVerification;
    }));
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].authority = ActionAuthorityBindingV1::Account(other_account());
    }));
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].invocation = ActionInvocationBindingV1::Direct {
            instruction_index: 0,
        };
    }));
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].operation = ActionOperationV1::NativeInstruction("iroha.transfer".into());
    }));
    different(&mutate_attachments(&payload, |actions, _| {
        actions[1].attachments[1].role = AttachmentRoleV1::ActionProof;
    }));

    // Independent: every other signed field.
    let mut changed = payload.clone();
    changed.domain = TransactionDomain::Network(super::super::test_network_id(0x42));
    different(&changed);
    let mut changed = payload.clone();
    changed.authority = other_account();
    different(&changed);
    let mut changed = payload.clone();
    changed.creation_time_ms += 1;
    different(&changed);
    let mut changed = payload.clone();
    changed.time_to_live_ms = NonZeroU64::new(1);
    different(&changed);
    let mut changed = payload.clone();
    changed.nonce = NonZeroU32::new(8);
    different(&changed);
    let mut changed = payload.clone();
    changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_001));
    different(&changed);
    let mut changed = payload.clone();
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("intent_context").expect("valid key"),
        Json::from(1_u64),
    );
    changed.metadata = metadata;
    different(&changed);
    let mut changed = payload.clone();
    changed.instructions = Executable::Instructions(vec![log("second"), log("first")].into());
    different(&changed);
}

#[test]
fn proved_executable_outputs_are_outside_the_ordered_intent() {
    let proved = |overlay: Vec<InstructionBox>, events: &[u8], gas: &[u8]| {
        Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 4]),
            overlay: overlay.into(),
            events_commitment: Hash::new(events),
            gas_policy_commitment: Hash::new(gas),
        })
    };
    let digest = |executable: Executable| {
        builder(executable)
            .into_payload()
            .expect("payload")
            .ordered_intent_digest_v1()
            .expect("intent")
    };
    let baseline = digest(proved(vec![log("effect")], b"events", b"gas"));
    assert_eq!(digest(proved(Vec::new(), b"events", b"gas")), baseline);
    assert_eq!(
        digest(proved(vec![log("effect")], b"other", b"gas")),
        baseline
    );
    assert_eq!(
        digest(proved(vec![log("effect")], b"events", b"other")),
        baseline
    );
    let other_code = Executable::IvmProved(IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 5]),
        overlay: vec![log("effect")].into(),
        events_commitment: Hash::new(b"events"),
        gas_policy_commitment: Hash::new(b"gas"),
    });
    assert_ne!(digest(other_code), baseline);
}

#[test]
fn hashing_order_is_not_circular() {
    // 1. Declare the actions. The generated proof does not exist yet.
    let mut plan = SignedAttachmentPlanV1::transaction_proofs(&[attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier");
    plan.push_action(direct_action(
        1,
        vec![proof_slot(Vec::new()), key_slot(vec![0xBB; 32])],
    ));
    let mut payload = builder(instructions())
        .with_signed_attachments(plan.declare())
        .into_payload()
        .expect("payload");

    // 2. The ordered intent digest is defined before any proof byte exists.
    let intent = payload.ordered_intent_digest_v1().expect("intent");

    // 3. Each action's statement is derived from it; the proof binds the statement.
    let statements = payload.action_statement_digests_v1().expect("statements");
    assert_eq!(statements.len(), 2);
    let generated_proof = blake3::hash(statements[1].as_bytes()).as_bytes().repeat(4);

    // 4. Record the generated proof with its exact length and hash.
    payload
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(1, generated_proof.clone())
        .expect("proof slot");
    payload.bind_attachment_statements_v1().expect("bound");

    // The intent and every statement are unchanged by the proof that binds them.
    assert_eq!(payload.ordered_intent_digest_v1().expect("intent"), intent);
    assert_eq!(
        payload.action_statement_digests_v1().expect("statements"),
        statements
    );
    payload.validate_signed_attachments_v1().expect("complete");

    // 5. The signature covers the complete payload, proof bytes included.
    let signed = sign(payload);
    signed.verify_signature().expect("signature");
    let framed = norito::encode_canonical(&signed).expect("frame");
    assert!(
        framed
            .windows(generated_proof.len())
            .any(|window| window == generated_proof)
    );
    assert_eq!(
        norito::decode_canonical::<SignedTransaction>(&framed).expect("decode"),
        signed
    );
    let mut tampered = signed.clone();
    tampered
        .payload_mut()
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(1, vec![0; generated_proof.len()])
        .expect("proof slot");
    assert_eq!(
        tampered.ordered_intent_digest_v1().expect("intent"),
        intent,
        "a proof cannot change the intent it binds"
    );
    assert_ne!(tampered.hash(), signed.hash());
    tampered
        .verify_signature()
        .expect_err("replacing proof bytes invalidates the signature");
}

#[test]
fn builder_keeps_statements_bound_while_the_payload_changes() {
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("intent_context").expect("valid key"),
        Json::from(1_u64),
    );
    let mut changed = builder(instructions())
        .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier")
        .with_metadata(metadata)
        .with_fee_payment_intent(FeePaymentIntent::authority(
            Vec::new(),
            NonZeroU64::new(10_001),
        ))
        .with_instructions([log("third")]);
    changed.set_nonce(NonZeroU32::new(9).expect("nonzero"));
    changed.set_ttl(Duration::from_secs(30));
    changed.set_creation_time(Duration::from_millis(CREATION_TIME_MS + 5));
    let payload = changed.payload().clone();
    payload
        .validate_signed_attachments_v1()
        .expect("every change rebinds the statements");
    let signed = changed.sign(&private_key());
    let framed = norito::encode_canonical(&signed).expect("frame");
    assert_eq!(
        norito::decode_canonical::<SignedTransaction>(&framed).expect("decode"),
        signed
    );

    for executable in [
        Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
        Executable::Batch(vec![ExecutableBatchItem::Instruction(log("item"))].into()),
    ] {
        let rebuilt = builder(instructions())
            .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
            .expect("carrier")
            .with_executable(executable);
        rebuilt
            .payload()
            .validate_signed_attachments_v1()
            .expect("rebound");
    }
    let bytecode = builder(instructions())
        .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier")
        .with_bytecode(IvmBytecode::from_compiled(vec![1, 2, 3]));
    bytecode
        .payload()
        .validate_signed_attachments_v1()
        .expect("rebound");
    let batch = builder(instructions())
        .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier")
        .with_executable_batch([ExecutableBatchItem::Instruction(log("item"))]);
    batch
        .payload()
        .validate_signed_attachments_v1()
        .expect("rebound");

    // No attachment is not a carrier.
    assert_eq!(
        builder(instructions())
            .with_proof_attachments(Vec::new())
            .map(|_| ())
            .expect_err("empty"),
        SignedAttachmentErrorV1::NoActions
    );
}

#[test]
fn stale_binding_of_another_transaction_is_rejected() {
    let payload = fixture_payload();
    payload.validate_signed_attachments_v1().expect("valid");
    let expected_of = |changed: &TransactionPayload| {
        changed.action_statement_digests_v1().expect("statements")[0]
    };
    let actual = payload.action_statement_digests_v1().expect("statements")[0];

    // The same descriptor and occurrences under another nonce, network,
    // authority, lifetime and instruction order.
    let mut other_nonce = payload.clone();
    other_nonce.nonce = NonZeroU32::new(8);
    let mut other_network = payload.clone();
    other_network.domain = TransactionDomain::Network(super::super::test_network_id(0x42));
    let mut other_time = payload.clone();
    other_time.creation_time_ms += 1;
    let mut other_order = payload.clone();
    other_order.instructions = Executable::Instructions(vec![log("second"), log("first")].into());
    for lifted in [other_nonce, other_network, other_time, other_order] {
        assert_eq!(
            rejected(&lifted),
            SignedAttachmentErrorV1::StatementBindingMismatch {
                action_index: 0,
                expected: expected_of(&lifted),
                actual,
            }
        );
    }

    // Rebinding makes the descriptor consistent again. A proof generated for
    // the first transaction then binds another statement: only verifying it
    // against the recomputed statement rejects the replay cryptographically.
    let mut rebound = payload.clone();
    rebound.nonce = NonZeroU32::new(8);
    rebound.bind_attachment_statements_v1().expect("rebound");
    rebound
        .validate_signed_attachments_v1()
        .expect("consistent");
    assert_ne!(
        rebound.action_statement_digests_v1().expect("statements")[1],
        payload.action_statement_digests_v1().expect("statements")[1]
    );
}

#[test]
fn signed_transaction_with_a_schema_violation_does_not_decode() {
    let payload = fixture_payload();

    // Reorder.
    assert!(matches!(
        rejected(&mutate_attachments(&payload, |actions, _| actions.swap(0, 1))),
        SignedAttachmentErrorV1::ActionOutOfOrder { position: 0, .. }
    ));
    assert!(matches!(
        rejected(&mutate_attachments(&payload, |_, occurrences| occurrences.swap(1, 2))),
        SignedAttachmentErrorV1::OccurrenceOutOfOrder { position: 1, .. }
    ));
    // Substitute.
    assert_eq!(
        rejected(&mutate_attachments(&payload, |_, occurrences| {
            occurrences[1] =
                SignedAttachmentOccurrenceV1::new(1, AttachmentKindV1::Proof, vec![0xAC; 48]);
        })),
        SignedAttachmentErrorV1::ReferenceHashMismatch {
            action_index: 1,
            index: 1
        }
    );
    // Omit.
    assert_eq!(
        rejected(&mutate_attachments(&payload, |_, occurrences| {
            occurrences.pop();
        })),
        SignedAttachmentErrorV1::MissingOccurrence {
            action_index: 1,
            index: 2
        }
    );
    // Duplicate.
    assert_eq!(
        rejected(&mutate_attachments(&payload, |actions, _| {
            let first = actions[1].attachments[0];
            actions[1].attachments[1] = first;
        })),
        SignedAttachmentErrorV1::DuplicateReference {
            action_index: 1,
            index: 1
        }
    );
    // Unused declaration.
    assert_eq!(
        rejected(&mutate_attachments(&payload, |_, occurrences| {
            occurrences.push(SignedAttachmentOccurrenceV1::new(
                3,
                AttachmentKindV1::Proof,
                vec![0xEE; 8],
            ));
        })),
        SignedAttachmentErrorV1::UnreferencedOccurrence { index: 3 }
    );
    // Another type, another length.
    assert_eq!(
        rejected(&mutate_attachments(&payload, |actions, _| {
            actions[1].attachments[1].kind = AttachmentKindV1::Proof;
        })),
        SignedAttachmentErrorV1::ReferenceKindMismatch {
            action_index: 1,
            index: 2
        }
    );
    assert_eq!(
        rejected(&mutate_attachments(&payload, |actions, _| {
            actions[1].attachments[1].length += 1;
        })),
        SignedAttachmentErrorV1::ReferenceLengthMismatch {
            action_index: 1,
            index: 2,
            declared: 33,
            actual: 32
        }
    );
}

fn with_plan(executable: Executable, plan: SignedAttachmentPlanV1) -> TransactionPayload {
    builder(executable)
        .with_signed_attachments(plan.declare())
        .into_payload()
        .expect("payload")
}

fn single(action: PlannedActionV1) -> SignedAttachmentPlanV1 {
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(action);
    plan
}

#[test]
fn direct_invocation_binding_names_a_matching_instruction() {
    let slots = || vec![proof_slot(vec![0xAA; 48])];
    with_plan(instructions(), single(direct_action(1, slots())))
        .validate_signed_attachments_v1()
        .expect("instruction 1 is a Log");

    assert_eq!(
        rejected(&with_plan(
            instructions(),
            single(direct_action(2, slots()))
        )),
        SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
    );

    // The instruction at the bound position is of another operation.
    let mut other_operation = direct_action(1, slots());
    other_operation.operation = ActionOperationV1::NativeInstruction("iroha.transfer".into());
    assert_eq!(
        rejected(&with_plan(instructions(), single(other_operation))),
        SignedAttachmentErrorV1::InvocationTargetMismatch { action_index: 0 }
    );

    // A wire identifier nobody registered.
    let mut unregistered = direct_action(1, slots());
    unregistered.operation =
        ActionOperationV1::NativeInstruction("iroha.unregistered.operation.v1".into());
    assert_eq!(
        rejected(&with_plan(instructions(), single(unregistered))),
        SignedAttachmentErrorV1::UnregisteredOperation { action_index: 0 }
    );

    // Two actions on one instruction.
    let mut twice = single(direct_action(1, slots()));
    twice.push_action(direct_action(1, vec![proof_slot(vec![0xAB; 48])]));
    assert_eq!(
        rejected(&with_plan(instructions(), twice)),
        SignedAttachmentErrorV1::DuplicateInvocation { action_index: 1 }
    );

    // A batch position that holds a contract call, and one past the batch.
    let batch = || {
        Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(log("item")),
                ExecutableBatchItem::ContractCall(contract_call()),
            ]
            .into(),
        )
    };
    with_plan(batch(), single(direct_action(0, slots())))
        .validate_signed_attachments_v1()
        .expect("batch item 0 is a Log");
    assert_eq!(
        rejected(&with_plan(batch(), single(direct_action(1, slots())))),
        SignedAttachmentErrorV1::InvocationTargetMismatch { action_index: 0 }
    );
    assert_eq!(
        rejected(&with_plan(batch(), single(direct_action(2, slots())))),
        SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
    );

    // An executable without direct instructions.
    assert_eq!(
        rejected(&with_plan(
            Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
            single(direct_action(0, slots()))
        )),
        SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
    );
}

#[test]
fn contract_invocation_binding_names_a_contract_root() {
    let slots = || vec![proof_slot(vec![0xAA; 48])];
    for standalone in [
        Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
        Executable::ContractCall(contract_call()),
    ] {
        with_plan(standalone.clone(), single(contract_action(0, slots())))
            .validate_signed_attachments_v1()
            .expect("standalone root");
        assert_eq!(
            rejected(&with_plan(standalone, single(contract_action(1, slots())))),
            SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
        );
    }

    let batch = || {
        Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(log("item")),
                ExecutableBatchItem::ContractCall(contract_call()),
            ]
            .into(),
        )
    };
    with_plan(batch(), single(contract_action(1, slots())))
        .validate_signed_attachments_v1()
        .expect("batch item 1 is a contract call");
    assert_eq!(
        rejected(&with_plan(batch(), single(contract_action(0, slots())))),
        SignedAttachmentErrorV1::InvocationTargetMismatch { action_index: 0 }
    );
    assert_eq!(
        rejected(&with_plan(batch(), single(contract_action(2, slots())))),
        SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
    );

    // A list of direct instructions issues no contract action.
    assert_eq!(
        rejected(&with_plan(
            instructions(),
            single(contract_action(0, slots()))
        )),
        SignedAttachmentErrorV1::InvocationOutOfRange { action_index: 0 }
    );
}

#[test]
fn execution_carrier_needs_a_proved_executable_and_is_unique() {
    let carrier = || {
        PlannedActionV1::ivm_proved_execution(&attachment("ivm_v1", vec![1, 2, 3]))
            .expect("execution carrier")
    };
    let proved = Executable::IvmProved(IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 4]),
        overlay: vec![log("effect")].into(),
        events_commitment: Hash::new(b"events"),
        gas_policy_commitment: Hash::new(b"gas"),
    });
    with_plan(proved.clone(), single(carrier()))
        .validate_signed_attachments_v1()
        .expect("proved executable with its carrier");

    assert_eq!(
        rejected(&with_plan(instructions(), single(carrier()))),
        SignedAttachmentErrorV1::ExecutionCarrierNotAdmitted { action_index: 0 }
    );

    let mut twice = single(carrier());
    twice.push_action(
        PlannedActionV1::ivm_proved_execution(&attachment("ivm_v1", vec![4, 5, 6]))
            .expect("execution carrier"),
    );
    assert_eq!(
        rejected(&with_plan(proved, twice)),
        SignedAttachmentErrorV1::ExecutionCarrierNotAdmitted { action_index: 1 }
    );
}

#[test]
fn carriers_are_checked_against_their_declaration_in_a_payload() {
    let payload = builder(instructions())
        .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier")
        .into_payload()
        .expect("payload");
    let signed = sign(payload.clone());
    assert_eq!(
        signed.proof_attachments_v1().expect("carriers"),
        vec![attachment("vk_a", vec![1, 2, 3])]
    );
    assert_eq!(signed.lane_privacy_proofs_v1(), Ok(Vec::new()));
    assert_eq!(
        signed.attachments().expect("attachments").actions().len(),
        1
    );

    // Other verifying-key metadata under the signed public-input digest.
    let mut substituted = payload.clone();
    substituted
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(
            0,
            norito::encode_canonical(&attachment("vk_other", vec![1, 2, 3])).expect("frame"),
        )
        .expect("carrier slot");
    assert_eq!(
        rejected(&substituted),
        SignedAttachmentErrorV1::PublicInputsMismatch { action_index: 0 }
    );

    // Bytes that are no proof attachment at all.
    let mut garbage = payload;
    garbage
        .attachments
        .as_mut()
        .expect("attachments")
        .set_occurrence_bytes(0, vec![0xFF; 64])
        .expect("carrier slot");
    assert!(matches!(
        rejected(&garbage),
        SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, .. }
    ));
}

#[test]
fn payload_level_carrier_setter_binds_validates_and_is_atomic() {
    let mut payload = builder(instructions()).into_payload().expect("payload");
    payload
        .set_proof_attachments_v1(&[attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier");
    payload.validate_signed_attachments_v1().expect("bound");
    assert_eq!(
        sign(payload.clone())
            .proof_attachments_v1()
            .expect("carrier"),
        vec![attachment("vk_a", vec![1, 2, 3])]
    );

    // A refused replacement leaves the payload as it was.
    let before = payload.clone();
    assert_eq!(
        payload.set_proof_attachments_v1(&[]),
        Err(SignedAttachmentErrorV1::NoActions)
    );
    let mut zero_commitment = attachment("vk_b", vec![4, 5, 6]);
    zero_commitment.vk_commitment = Some([0; 32]);
    assert!(matches!(
        payload.set_proof_attachments_v1(&[zero_commitment]),
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { .. })
    ));
    assert_eq!(payload, before);
}

#[test]
fn ceiling_sized_proof_fits_the_frame_bound_and_the_transaction_cap() {
    let max_tx_bytes = usize::try_from(
        crate::parameter::TransactionParameters::default()
            .max_tx_bytes()
            .get(),
    )
    .expect("transaction cap fits usize");
    let payload = with_plan(
        Executable::ContractCall(contract_call()),
        single(contract_action(
            0,
            vec![proof_slot(vec![
                0x5a;
                SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1
            ])],
        )),
    );
    payload
        .validate_signed_attachments_v1()
        .expect("ceiling proof");
    let frame_len = payload
        .attachments
        .as_ref()
        .expect("attachments")
        .canonical_frame_len_v1()
        .expect("frame length");
    assert!(frame_len <= SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1);

    let signed = sign(payload);
    let framed = norito::encode_canonical(&signed).expect("frame");
    assert!(
        framed.len() <= max_tx_bytes,
        "a ceiling-sized proof must be carriable: {} > {max_tx_bytes}",
        framed.len()
    );
    assert_eq!(
        norito::decode_canonical::<SignedTransaction>(&framed).expect("decode"),
        signed
    );
    // The complete signed transaction adds this much to the raw proof: the
    // attachment frame's own share and the rest of the signed transaction.
    let attachment_overhead = frame_len - SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1;
    let transaction_overhead = framed.len() - SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1;
    assert!(attachment_overhead < transaction_overhead);
    assert!(transaction_overhead < max_tx_bytes - SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1);
}

const VECTORS_PATH: &str = "fixtures/zk/signed_attachments_v1/vectors.json";
const CAPTURE_DIR_VARIABLE: &str = "IROHA_CAPTURE_SIGNED_ATTACHMENT_VECTORS_DIR";

fn hex_digests<D: AsRef<[u8]>>(digests: impl IntoIterator<Item = D>) -> Vec<String> {
    digests.into_iter().map(hex::encode).collect()
}

fn json_value<T: norito::json::JsonSerialize>(value: &T) -> norito::json::Value {
    norito::json::to_value(value).expect("json value")
}

fn json_count(value: usize) -> norito::json::Value {
    json_value(&u64::try_from(value).expect("count fits u64"))
}

fn json_object(entries: Vec<(&str, norito::json::Value)>) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate key {key}"
        );
    }
    norito::json::Value::Object(map)
}

/// The exact unsigned payload bytes an external signer receives.
fn payload_bytes(payload: &TransactionPayload) -> Vec<u8> {
    TransactionBuilder::from_payload(payload.clone())
        .expect("ordinary payload")
        .encode_payload()
}

/// One accepted transaction with every derived value an SDK must reproduce.
fn accepted_vector(name: &str, payload: &TransactionPayload) -> norito::json::Value {
    payload
        .validate_signed_attachments_v1()
        .expect("accepted vector is valid");
    let attachments = payload.attachments.clone().expect("attachments");
    let signed = sign(payload.clone());
    let framed = norito::encode_canonical(&signed).expect("frame");
    assert_eq!(
        norito::decode_canonical::<SignedTransaction>(&framed).expect("decode"),
        signed
    );
    json_object(vec![
        ("name", json_value(&name)),
        (
            "payload_hex",
            json_value(&hex::encode(payload_bytes(payload))),
        ),
        ("signed_transaction_hex", json_value(&hex::encode(&framed))),
        ("attachments_frame_base64", json_value(&attachments)),
        (
            "ordered_intent_projection_hex",
            json_value(&hex::encode(
                payload
                    .ordered_intent_projection_bytes_v1()
                    .expect("projection"),
            )),
        ),
        (
            "ordered_intent_digest_hex",
            json_value(&hex::encode(
                payload
                    .ordered_intent_digest_v1()
                    .expect("intent")
                    .as_bytes(),
            )),
        ),
        (
            "public_inputs_digests_hex",
            json_value(&hex_digests(
                attachments
                    .actions()
                    .iter()
                    .map(|action| *action.public_inputs_digest.as_bytes()),
            )),
        ),
        (
            "statement_digests_hex",
            json_value(&hex_digests(
                payload
                    .action_statement_digests_v1()
                    .expect("statements")
                    .iter()
                    .map(|digest| *digest.as_bytes()),
            )),
        ),
        (
            "content_hashes_hex",
            json_value(&hex_digests(
                attachments
                    .occurrences()
                    .iter()
                    .map(|occurrence| *occurrence.content_hash.as_bytes()),
            )),
        ),
        (
            "occurrence_lengths",
            json_value(
                &attachments
                    .occurrences()
                    .iter()
                    .map(|occurrence| occurrence.length)
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

/// One signed transaction no node decodes, with the typed violation.
fn rejected_vector(name: &str, payload: &TransactionPayload) -> norito::json::Value {
    let error = rejected(payload);
    let framed = norito::encode_canonical(&sign(payload.clone())).expect("frame");
    json_object(vec![
        ("name", json_value(&name)),
        ("signed_transaction_hex", json_value(&hex::encode(&framed))),
        ("error", json_value(&error.to_string())),
    ])
}

fn ceiling_vector() -> norito::json::Value {
    let payload = with_plan(
        Executable::ContractCall(contract_call()),
        single(contract_action(
            0,
            vec![proof_slot(vec![
                0x5a;
                SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1
            ])],
        )),
    );
    payload
        .validate_signed_attachments_v1()
        .expect("ceiling proof");
    let attachment_frame = norito::encode_canonical(payload.attachments.as_ref().expect("field"))
        .expect("attachment frame");
    let framed = norito::encode_canonical(&sign(payload)).expect("frame");
    json_object(vec![
        (
            "what",
            json_value(
                &"One native action with one proof occurrence of exactly the occurrence ceiling, every byte 0x5a, issued by a standalone contract call.",
            ),
        ),
        (
            "occurrence_bytes",
            json_count(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1),
        ),
        (
            "attachments_frame_bytes",
            json_count(attachment_frame.len()),
        ),
        (
            "attachments_frame_max_bytes",
            json_count(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1),
        ),
        (
            "attachments_frame_blake3_hex",
            json_value(&hex::encode(blake3::hash(&attachment_frame).as_bytes())),
        ),
        ("signed_transaction_bytes", json_count(framed.len())),
        (
            "signed_transaction_blake3_hex",
            json_value(&hex::encode(blake3::hash(&framed).as_bytes())),
        ),
        (
            "transaction_max_tx_bytes",
            json_value(
                &crate::parameter::TransactionParameters::default()
                    .max_tx_bytes()
                    .get(),
            ),
        ),
    ])
}

/// All protocol-tagged privacy instructions, using the same typed normalizer as admission.
fn privacy_intent_vectors() -> Vec<norito::json::Value> {
    let bundle = crate::privacy::privacy_exact12_fixture_bundle_v1().expect("exact12 fixture");
    let mut rows = Vec::new();
    for (index, row) in bundle.rows.into_iter().enumerate() {
        let instruction =
            norito::decode_canonical::<SubmitPrivacyProofV1>(&row.submit_proof_instruction_norito)
                .expect("typed instruction");
        let projection = instruction
            .ordered_intent_projection_bytes_v1()
            .expect("instruction projection");
        let mut generated = instruction.clone();
        generated.envelope.proof.bytes_mut().bytes = vec![0x91, 0x92, 0x93];
        generated
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0xA1; 32]);
        generated.envelope.statement_digest = PrivacyStatementDigestV1::new([0xA2; 32]);
        match &mut generated.envelope.statement {
            PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) => {
                statement.replay_nullifier =
                    crate::privacy::PrivacyZkAceReplayNullifierV1::new([17; 6])
                        .expect("canonical nullifier")
            }
            PrivacyStatementV1::VegaExistingCredentialZkV1(statement) => {
                statement.device_authentication_digest =
                    PrivacyVegaDeviceAuthenticationDigestV1::new([0xA3; 32])
            }
            PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) => {
                statement.action_digest = crate::privacy::PrivacyActionDigestV1::new([0xA4; 32])
            }
            _ => {}
        }
        assert_eq!(
            generated
                .ordered_intent_projection_bytes_v1()
                .expect("generated projection"),
            projection
        );
        let generated_frame = norito::encode_canonical(&generated).expect("generated frame");
        let mut independent = instruction.clone();
        independent.envelope.statement.context_mut().action_index += 1;
        assert_ne!(
            independent
                .ordered_intent_projection_bytes_v1()
                .expect("independent projection"),
            projection
        );
        let independent_frame = norito::encode_canonical(&independent).expect("independent frame");
        let direct = TransactionBuilder::decode_payload(&row.unsigned_transaction_payload_norito)
            .expect("fixture payload")
            .into_payload()
            .expect("ordinary payload");
        let batch = builder(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(log("before")),
                ExecutableBatchItem::Instruction(instruction.into()),
                ExecutableBatchItem::ContractCall(contract_call()),
            ]
            .into(),
        ))
        .into_payload()
        .expect("batch payload");
        for (kind, payload) in [("direct", direct), ("batch", batch)] {
            rows.push(json_object(vec![
                ("name", json_value(&format!("privacy_{index}_{kind}"))),
                (
                    "generated_fields_changed_frame_hex",
                    json_value(&hex::encode(&generated_frame)),
                ),
                (
                    "independent_context_changed_frame_hex",
                    json_value(&hex::encode(&independent_frame)),
                ),
                (
                    "instruction_frame_hex",
                    json_value(&hex::encode(&row.submit_proof_instruction_norito)),
                ),
                (
                    "instruction_projection_hex",
                    json_value(&hex::encode(&projection)),
                ),
                (
                    "payload_hex",
                    json_value(&hex::encode(payload_bytes(&payload))),
                ),
                (
                    "ordered_intent_projection_hex",
                    json_value(&hex::encode(
                        payload
                            .ordered_intent_projection_bytes_v1()
                            .expect("projection"),
                    )),
                ),
                (
                    "ordered_intent_digest_hex",
                    json_value(&hex::encode(
                        payload
                            .ordered_intent_digest_v1()
                            .expect("digest")
                            .as_bytes(),
                    )),
                ),
            ]));
        }
    }
    rows
}

/// The complete shared vector set, deterministically generated.
fn signed_attachment_vectors() -> String {
    use crate::transaction::signed_attachments::{
        ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1, ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1,
        ACTION_STATEMENT_DIGEST_DOMAIN_V1, PROOF_CARRIER_PUBLIC_INPUTS_DIGEST_DOMAIN_V1,
        SIGNED_ATTACHMENTS_MAX_ACTIONS_V1, SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
    };
    let domain = |bytes: &[u8]| json_value(&String::from_utf8_lossy(bytes).into_owned());
    let attachment_free = builder(instructions()).into_payload().expect("payload");
    let attachment_free_frame =
        norito::encode_canonical(&sign(attachment_free.clone())).expect("frame");
    let carrier = builder(instructions())
        .with_proof_attachments([attachment("vk_a", vec![1, 2, 3])])
        .expect("carrier")
        .into_payload()
        .expect("payload");
    let mixed = fixture_payload();
    let mut optional_carrier = attachment("vk_optional", vec![4, 5, 6]);
    optional_carrier.vk_commitment = Some([0x31; 32]);
    optional_carrier.envelope_hash = Some(Hash::new(&optional_carrier.proof.bytes).into());
    let optional_carrier = builder(instructions())
        .with_proof_attachments([optional_carrier])
        .expect("optional carrier")
        .into_payload()
        .expect("optional carrier payload");
    let mut lane_carrier = attachment("vk_lane", vec![7, 8, 9]);
    lane_carrier.lane_privacy = Some(
        crate::nexus::LanePrivacyProof::merkle_from_raw_path(
            iroha_crypto::privacy::LaneCommitmentId::new(3),
            [0x44; 32],
            1,
            vec![Some([0x55; 32]), Some([0x66; 32])],
        )
        .expect("lane privacy witness"),
    );
    let lane_carrier = builder(instructions())
        .with_proof_attachments([lane_carrier])
        .expect("lane carrier")
        .into_payload()
        .expect("lane carrier payload");
    let mut contract = contract_action(0, vec![proof_slot(vec![0xC1; 9])]);
    contract.invocation = ActionInvocationBindingV1::Contract {
        root_index: 0,
        call_path: vec![2, 4],
    };
    let contract_subject = builder(Executable::ContractCall(contract_call()))
        .with_attachment_plan(single(contract))
        .expect("contract subject plan")
        .into_payload()
        .expect("contract subject payload");
    let mut account_action = direct_action(0, vec![proof_slot(vec![0xC2; 9])]);
    account_action.authority = ActionAuthorityBindingV1::Account(other_account());
    let account_bound = builder(instructions())
        .with_attachment_plan(single(account_action))
        .expect("account plan")
        .into_payload()
        .expect("account payload");

    let proved_executable = Executable::IvmProved(IvmProved {
        bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 4]),
        overlay: vec![log("effect")].into(),
        events_commitment: Hash::new(b"events"),
        gas_policy_commitment: Hash::new(b"gas"),
    });
    let execution_carrier = || {
        PlannedActionV1::ivm_proved_execution(&attachment("ivm_v1", vec![1, 2, 3]))
            .expect("execution carrier")
    };
    let proved = builder(proved_executable.clone())
        .with_attachment_plan(single(execution_carrier()))
        .expect("execution plan")
        .into_payload()
        .expect("proved payload");
    let wrong_execution_target = with_plan(instructions(), single(execution_carrier()));
    let mut duplicate_execution_plan = single(execution_carrier());
    duplicate_execution_plan.push_action(
        PlannedActionV1::ivm_proved_execution(&attachment("ivm_other", vec![4, 5, 6]))
            .expect("second execution carrier"),
    );
    let duplicate_execution = with_plan(proved_executable, duplicate_execution_plan);

    let mut lifted = mixed.clone();
    lifted.nonce = NonZeroU32::new(8);
    let rejected_vectors = vec![
        rejected_vector(
            "reordered_actions",
            &mutate_attachments(&mixed, |actions, _| actions.swap(0, 1)),
        ),
        rejected_vector(
            "reordered_occurrences",
            &mutate_attachments(&mixed, |_, occurrences| occurrences.swap(1, 2)),
        ),
        rejected_vector(
            "substituted_proof",
            &mutate_attachments(&mixed, |_, occurrences| {
                occurrences[1] =
                    SignedAttachmentOccurrenceV1::new(1, AttachmentKindV1::Proof, vec![0xAC; 48]);
            }),
        ),
        rejected_vector(
            "omitted_occurrence",
            &mutate_attachments(&mixed, |_, occurrences| {
                occurrences.pop();
            }),
        ),
        rejected_vector(
            "duplicated_reference",
            &mutate_attachments(&mixed, |actions, _| {
                let first = actions[1].attachments[0];
                actions[1].attachments[1] = first;
            }),
        ),
        rejected_vector(
            "unused_occurrence",
            &mutate_attachments(&mixed, |_, occurrences| {
                occurrences.push(SignedAttachmentOccurrenceV1::new(
                    3,
                    AttachmentKindV1::Proof,
                    vec![0xEE; 8],
                ));
            }),
        ),
        rejected_vector(
            "declared_type_mismatch",
            &mutate_attachments(&mixed, |actions, _| {
                actions[1].attachments[1].kind = AttachmentKindV1::Proof;
            }),
        ),
        rejected_vector(
            "declared_length_mismatch",
            &mutate_attachments(&mixed, |actions, _| {
                actions[1].attachments[1].length += 1;
            }),
        ),
        rejected_vector(
            "occurrence_hash_mismatch",
            &mutate_attachments(&mixed, |_, occurrences| occurrences[2].bytes[0] ^= 1),
        ),
        rejected_vector("stale_statement_binding", &lifted),
        rejected_vector(
            "execution_carrier_wrong_executable",
            &wrong_execution_target,
        ),
        rejected_vector("duplicate_execution_carrier", &duplicate_execution),
    ];

    let vectors = json_object(vec![
        ("schema", json_value(&"iroha.signed_attachments.vectors.v1")),
        (
            "generator",
            json_value(
                &"IROHA_CAPTURE_SIGNED_ATTACHMENT_VECTORS_DIR=\"$PWD/fixtures/zk/signed_attachments_v1\" cargo test -p iroha_data_model --lib capture_signed_attachment_vectors -- --ignored",
            ),
        ),
        (
            "layout",
            json_value(&"norito.md, section \"Signed attachments and ordered intent\""),
        ),
        (
            "domains",
            json_object(vec![
                (
                    "ordered_intent_digest",
                    domain(ORDERED_INTENT_DIGEST_DOMAIN_V1),
                ),
                (
                    "action_statement_digest",
                    domain(ACTION_STATEMENT_DIGEST_DOMAIN_V1),
                ),
                (
                    "proof_carrier_public_inputs_digest",
                    domain(PROOF_CARRIER_PUBLIC_INPUTS_DIGEST_DOMAIN_V1),
                ),
            ]),
        ),
        (
            "bounds",
            json_object(vec![
                (
                    "occurrence_max_bytes",
                    json_count(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1),
                ),
                (
                    "max_occurrences",
                    json_count(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1),
                ),
                ("max_actions", json_count(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1)),
                (
                    "frame_max_bytes",
                    json_count(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1),
                ),
                (
                    "invocation_max_call_path_depth",
                    json_count(ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1),
                ),
                (
                    "operation_max_wire_id_bytes",
                    json_count(ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1),
                ),
            ]),
        ),
        (
            "attachment_free",
            json_object(vec![
                (
                    "what",
                    json_value(
                        &"The same transaction without attachments: the ninth payload field is the single None byte.",
                    ),
                ),
                (
                    "payload_hex",
                    json_value(&hex::encode(payload_bytes(&attachment_free))),
                ),
                (
                    "signed_transaction_hex",
                    json_value(&hex::encode(&attachment_free_frame)),
                ),
                (
                    "ordered_intent_digest_hex",
                    json_value(&hex::encode(
                        attachment_free
                            .ordered_intent_digest_v1()
                            .expect("intent")
                            .as_bytes(),
                    )),
                ),
            ]),
        ),
        (
            "accepted",
            norito::json::Value::Array(vec![
                accepted_vector("transaction_proof_carrier", &carrier),
                accepted_vector(
                    "transaction_proof_carrier_optional_hashes",
                    &optional_carrier,
                ),
                accepted_vector("transaction_proof_carrier_lane_privacy", &lane_carrier),
                accepted_vector("contract_subject_nested_invocation", &contract_subject),
                accepted_vector("explicit_account_direct_invocation", &account_bound),
                accepted_vector("ivm_proved_execution_carrier", &proved),
                accepted_vector(
                    "carrier_then_direct_native_action_with_proof_and_key",
                    &mixed,
                ),
            ]),
        ),
        ("rejected", norito::json::Value::Array(rejected_vectors)),
        ("ceiling", ceiling_vector()),
        (
            "privacy_intents",
            norito::json::Value::Array(privacy_intent_vectors()),
        ),
        (
            "privacy_frame_limits",
            json_object(vec![
                (
                    "envelope_bytes",
                    json_value(&crate::privacy::TAIRA_PRIVACY_MAX_ACTION_BYTES_V1),
                ),
                (
                    "submit_frame_bytes",
                    json_value(&SubmitPrivacyProofV1::canonical_frame_byte_limit_v1()),
                ),
                (
                    "block_privacy_bytes",
                    json_value(&crate::privacy::TAIRA_PRIVACY_MAX_BYTES_PER_BLOCK_V1),
                ),
            ]),
        ),
    ]);
    let mut text = norito::json::to_string_pretty(&vectors).expect("pretty json");
    text.push('\n');
    text
}

fn tracked_vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(VECTORS_PATH)
}

#[test]
fn tracked_signed_attachment_vectors_are_the_current_generator_output() {
    let generated = signed_attachment_vectors();
    let tracked = std::fs::read_to_string(tracked_vectors_path())
        .expect("the shared signed attachment vectors are tracked");
    assert_eq!(
        tracked, generated,
        "regenerate {VECTORS_PATH} with capture_signed_attachment_vectors"
    );

    // The tracked text is what another implementation reads: every accepted
    // transaction decodes and validates, every rejected one fails to decode
    // with its recorded violation, and the attachment-free bytes carry `None`.
    let vectors: norito::json::Value = norito::json::from_str(&tracked).expect("json");
    let entries = |key: &str| {
        vectors
            .get(key)
            .and_then(norito::json::Value::as_array)
            .unwrap_or_else(|| panic!("`{key}` is an array"))
            .clone()
    };
    let text = |entry: &norito::json::Value, key: &str| {
        entry
            .get(key)
            .and_then(norito::json::Value::as_str)
            .unwrap_or_else(|| panic!("`{key}` is a string"))
            .to_owned()
    };
    let accepted = entries("accepted");
    assert_eq!(accepted.len(), 7);
    for entry in &accepted {
        let framed = hex::decode(text(entry, "signed_transaction_hex")).expect("hex");
        let signed = norito::decode_canonical::<SignedTransaction>(&framed).expect("decode");
        signed.verify_signature().expect("signature");
        signed.validate_signed_attachments_v1().expect("valid");
        assert_eq!(
            hex::encode(
                signed
                    .ordered_intent_digest_v1()
                    .expect("intent")
                    .as_bytes()
            ),
            text(entry, "ordered_intent_digest_hex")
        );
        let attachments: SignedAttachmentsV1 = norito::json::from_value(
            entry
                .get("attachments_frame_base64")
                .expect("frame")
                .clone(),
        )
        .expect("attachment frame");
        assert_eq!(signed.attachments(), Some(&attachments));
        let payload = hex::decode(text(entry, "payload_hex")).expect("hex");
        let decoded = TransactionBuilder::decode_payload(&payload).expect("payload decode");
        assert_eq!(decoded.payload(), signed.payload());
    }
    let rejected_entries = entries("rejected");
    assert_eq!(rejected_entries.len(), 12);
    for entry in &rejected_entries {
        let framed = hex::decode(text(entry, "signed_transaction_hex")).expect("hex");
        let error = norito::decode_canonical::<SignedTransaction>(&framed)
            .expect_err("a rejected vector does not decode");
        assert!(
            error.to_string().contains(&text(entry, "error")),
            "{}: {error}",
            text(entry, "name")
        );
    }
    let attachment_free = vectors
        .get("attachment_free")
        .expect("attachment-free vector");
    let framed = hex::decode(text(attachment_free, "signed_transaction_hex")).expect("hex");
    let signed = norito::decode_canonical::<SignedTransaction>(&framed).expect("decode");
    assert!(signed.attachments().is_none());
    // The payload ends with its ninth field: a one-byte length and the `None` byte.
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let payload = norito::codec::Encode::encode(signed.payload());
    assert_eq!(&payload[payload.len() - 2..], &[1_u8, 0][..]);
}

/// Rewrite the tracked vectors. Without the variable the capture goes to a
/// scratch directory and the tracked file is untouched.
#[test]
#[ignore = "regenerates the shared signed attachment vectors"]
fn capture_signed_attachment_vectors() {
    let directory = std::env::var_os(CAPTURE_DIR_VARIABLE).map_or_else(
        || std::env::temp_dir().join("iroha-signed-attachment-vectors"),
        std::path::PathBuf::from,
    );
    std::fs::create_dir_all(&directory).expect("capture directory");
    let path = directory.join("vectors.json");
    std::fs::write(&path, signed_attachment_vectors()).expect("write vectors");
    println!("wrote {}", path.display());
}

#[test]
fn payload_attachment_validation_preserves_the_actual_original_codec_refusal() {
    let payload = fixture_payload();
    let bytes = payload_bytes(&payload);
    let limits = |allocation| {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, usize::MAX)
    };
    let context = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let baseline = context
        .with(|| TransactionBuilder::decode_payload(&bytes))
        .expect("complete actual payload");
    assert_eq!(baseline.payload(), &payload);
    let demand = usize::try_from(context.consumed_allocated_bytes())
        .expect("measured local demand fits this host");
    assert!(demand > 0);
    let error = norito::with_decode_limits_scope(limits(demand - 1), || {
        norito::core::classify_decode_attempt(|| TransactionBuilder::decode_payload(&bytes))
    })
    .unwrap_err();
    assert_eq!(
        error.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(error.local_refusal().is_some());
    assert!(
        matches!(error.error().decode_resource_error(), Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit }) if attempted > limit)
    );
    let direct =
        norito::with_decode_limits_scope(limits(0), || payload.validate_signed_attachments_v1())
            .unwrap_err();
    assert_eq!(
        direct.into_local_refusal().unwrap().kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    let decoded = TransactionBuilder::decode_payload(&bytes).expect("unchanged source retries");
    assert_eq!(decoded.payload(), &payload);
}
