//! Schema tests of the ordered intent descriptor and signed attachment occurrences.

use super::*;
use crate::{
    nexus::{LanePrivacyMerkleWitness, LanePrivacyProof, LanePrivacyWitness},
    proof::{ProofBox, VerifyingKeyId},
};
use iroha_crypto::{Algorithm, KeyPair, privacy::LaneCommitmentId};

const INTENT: OrderedIntentDigestV1 = OrderedIntentDigestV1::new([0x11; 32]);

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn attachment(name: &str, proof: Vec<u8>) -> ProofAttachment {
    ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), proof),
        VerifyingKeyId::new("halo2/ipa", name),
    )
}

fn lane_attachment() -> ProofAttachment {
    let mut wrapped = attachment("vk_lane", vec![7, 7, 7]);
    wrapped.lane_privacy = Some(LanePrivacyProof {
        commitment_id: LaneCommitmentId::new(3),
        witness: LanePrivacyWitness::Merkle(LanePrivacyMerkleWitness {
            leaf: [0x21; 32],
            proof: iroha_crypto::MerkleProof::from_audit_path_bytes(0, vec![[0x43; 32]]),
        }),
    });
    wrapped
}

/// A native action bound to a contract invocation, with the given slots.
fn native_action(slots: Vec<PlannedAttachmentV1>) -> PlannedActionV1 {
    PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction("iroha.privacy.submit_proof.v1".into()),
        role: ActionRoleV1::ProofEffect,
        authority: ActionAuthorityBindingV1::ContractSubject(account(0x41)),
        invocation: ActionInvocationBindingV1::Contract {
            root_index: 0,
            call_path: Vec::new(),
        },
        public_inputs_digest: ActionPublicInputsDigestV1::new([0x5a; 32]),
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

/// Declare a plan and bind its statements to a fixed intent digest.
fn bound(plan: SignedAttachmentPlanV1) -> SignedAttachmentsV1 {
    let mut value = plan.declare();
    value.bind_statements_v1(INTENT).expect("bound statements");
    value
}

/// Two carrier actions and one native action with a proof and a key.
fn fixture() -> SignedAttachmentsV1 {
    let mut plan = SignedAttachmentPlanV1::transaction_proofs(&[
        attachment("vk_a", vec![1, 2, 3]),
        attachment("vk_b", vec![4, 5, 6, 7]),
    ])
    .expect("carriers");
    plan.push_action(native_action(vec![
        proof_slot(vec![0xAA; 48]),
        key_slot(vec![0xBB; 32]),
    ]));
    let value = bound(plan);
    value.validate_v1().expect("valid fixture");
    value
}

fn frame(value: &SignedAttachmentsV1) -> Vec<u8> {
    norito::encode_canonical(value).expect("canonical frame")
}

fn bare(value: &SignedAttachmentsV1) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    norito::codec::Encode::encode(value)
}

/// The typed error, and proof that the decoder refuses the same value with it.
fn rejected(value: &SignedAttachmentsV1) -> SignedAttachmentErrorV1 {
    let error = value.validate_v1().expect_err("schema violation");
    let decode_error = norito::decode_canonical::<SignedAttachmentsV1>(&frame(value))
        .expect_err("the decoder refuses what validation refuses");
    assert!(
        decode_error.to_string().contains(&error.to_string()),
        "decoder reported `{decode_error}`, validation `{error}`"
    );
    assert!(
        SignedAttachmentsV1::try_from_parts(value.actions.clone(), value.occurrences.clone())
            .is_err()
    );
    error
}

#[test]
fn content_hash_is_blake3_of_the_exact_bytes() {
    let bytes = b"attachment bytes";
    assert_eq!(
        AttachmentContentHashV1::of(bytes).into_bytes(),
        *blake3::hash(bytes).as_bytes()
    );
    assert!(AttachmentContentHashV1::ZERO.is_zero());
    assert!(!AttachmentContentHashV1::of(bytes).is_zero());
    assert_eq!(
        AttachmentContentHashV1::new([3; 32]).as_bytes(),
        &[3_u8; 32]
    );
}

#[test]
fn occurrence_records_exact_length_and_hash_and_its_reference_repeats_them() {
    let occurrence =
        SignedAttachmentOccurrenceV1::new(4, AttachmentKindV1::KeyMaterial, vec![9; 5]);
    assert_eq!(occurrence.index, 4);
    assert_eq!(occurrence.length, 5);
    assert_eq!(
        occurrence.content_hash,
        AttachmentContentHashV1::of(&[9; 5])
    );
    let reference = occurrence.reference(AttachmentRoleV1::VerifyingKey);
    assert_eq!(
        reference,
        AttachmentReferenceV1 {
            index: 4,
            kind: AttachmentKindV1::KeyMaterial,
            role: AttachmentRoleV1::VerifyingKey,
            length: 5,
            content_hash: occurrence.content_hash,
        }
    );
}

#[test]
fn kinds_and_roles_form_a_closed_table() {
    assert!(AttachmentKindV1::Proof.is_generated());
    assert!(!AttachmentKindV1::KeyMaterial.is_generated());
    for role in [
        AttachmentRoleV1::ActionProof,
        AttachmentRoleV1::LanePrivacyProof,
        AttachmentRoleV1::ExecutionProof,
    ] {
        assert!(role.admits_kind(AttachmentKindV1::Proof));
        assert!(!role.admits_kind(AttachmentKindV1::KeyMaterial));
    }
    assert!(AttachmentRoleV1::VerifyingKey.admits_kind(AttachmentKindV1::KeyMaterial));
    assert!(!AttachmentRoleV1::VerifyingKey.admits_kind(AttachmentKindV1::Proof));
}

#[test]
fn operation_accessors_distinguish_carriers_from_native_instructions() {
    let native = ActionOperationV1::NativeInstruction("iroha.log".into());
    assert_eq!(native.instruction_wire_id(), Some("iroha.log"));
    assert!(!native.is_proof_carrier());
    for carrier in [
        ActionOperationV1::TransactionProof,
        ActionOperationV1::IvmProvedExecution,
    ] {
        assert_eq!(carrier.instruction_wire_id(), None);
        assert!(carrier.is_proof_carrier());
    }
}

#[test]
fn plan_assigns_contiguous_ordinals_slots_lengths_and_hashes() {
    let value = fixture();
    assert_eq!(value.actions().len(), 3);
    assert_eq!(value.occurrences().len(), 4);
    for (position, action) in value.actions().iter().enumerate() {
        assert_eq!(action.action_index as usize, position);
        assert_eq!(value.action(action.action_index), Some(action));
    }
    let mut next = 0_u32;
    for action in value.actions() {
        for reference in &action.attachments {
            assert_eq!(reference.index, next);
            let occurrence = value.occurrence(next).expect("occurrence");
            assert_eq!(reference.kind, occurrence.kind);
            assert_eq!(reference.length, occurrence.bytes.len() as u64);
            assert_eq!(
                reference.content_hash,
                AttachmentContentHashV1::of(&occurrence.bytes)
            );
            next += 1;
        }
    }
    assert_eq!(next as usize, value.occurrences().len());
    assert_eq!(value.action(3), None);
    assert_eq!(value.occurrence(4), None);
    assert_eq!(
        value.total_occurrence_bytes(),
        value
            .occurrences()
            .iter()
            .map(|occurrence| occurrence.bytes.len())
            .sum::<usize>()
    );
    let (actions, occurrences) = value.clone().into_parts();
    assert_eq!(
        SignedAttachmentsV1::try_from_parts(actions, occurrences).expect("valid parts"),
        value
    );
    assert_eq!(SignedAttachmentPlanV1::new().actions().len(), 0);
}

#[test]
fn canonical_frame_bare_payload_and_json_roundtrip() {
    let value = fixture();
    let framed = frame(&value);
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&framed).expect("framed decode"),
        value
    );
    assert_eq!(
        value.canonical_frame_len_v1().expect("length"),
        framed.len()
    );

    let payload = bare(&value);
    let flags_guard = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let (decoded, used) = SignedAttachmentsV1::decode_from_slice(&payload).expect("bare decode");
    assert_eq!((decoded, used), (value.clone(), payload.len()));
    drop(flags_guard);

    let json = norito::json::to_json(&value).expect("json");
    assert_eq!(json, format!("\"{}\"", STANDARD.encode(&framed)));
    assert_eq!(
        norito::json::from_json::<SignedAttachmentsV1>(&json).expect("json decode"),
        value
    );
    let as_value = norito::json::Value::String(STANDARD.encode(&framed));
    assert_eq!(
        <SignedAttachmentsV1 as norito::json::JsonDeserialize>::json_from_value(&as_value)
            .expect("value decode"),
        value
    );
}

#[test]
fn json_form_accepts_only_the_canonical_base64_spelling() {
    let value = fixture();
    let encoded = STANDARD.encode(frame(&value));
    // Trailing bytes after the frame, an escape and an unpadded token are refused.
    let unpadded = encoded.trim_end_matches('=').to_owned();
    for token in [
        String::new(),
        format!("{encoded}AAAA"),
        encoded.replacen('A', "\\u0041", 1),
        format!("{unpadded}*"),
        "AAA".to_owned(),
    ] {
        assert!(
            norito::json::from_json::<SignedAttachmentsV1>(&format!("\"{token}\"")).is_err(),
            "token `{}` must be refused",
            &token[..token.len().min(16)]
        );
    }
    assert!(norito::json::from_json::<SignedAttachmentsV1>("17").is_err());
    assert!(
        <SignedAttachmentsV1 as norito::json::JsonDeserialize>::json_from_value(
            &norito::json::Value::Bool(true)
        )
        .is_err()
    );
}

#[test]
fn reordered_actions_occurrences_and_references_are_rejected() {
    let mut actions_swapped = fixture();
    actions_swapped.actions.swap(0, 1);
    assert_eq!(
        rejected(&actions_swapped),
        SignedAttachmentErrorV1::ActionOutOfOrder {
            position: 0,
            action_index: 1
        }
    );

    let mut occurrences_swapped = fixture();
    occurrences_swapped.occurrences.swap(0, 1);
    assert_eq!(
        rejected(&occurrences_swapped),
        SignedAttachmentErrorV1::OccurrenceOutOfOrder {
            position: 0,
            index: 1
        }
    );

    // The same occurrences declared in another order: each reference still
    // matches its occurrence, but the references no longer enumerate them.
    let mut references_swapped = fixture();
    let first = references_swapped.actions[0].attachments[0];
    let second = references_swapped.actions[1].attachments[0];
    references_swapped.actions[0].attachments[0] = second;
    references_swapped.actions[1].attachments[0] = first;
    assert_eq!(
        rejected(&references_swapped),
        SignedAttachmentErrorV1::ReferenceOutOfOrder {
            action_index: 0,
            index: 1,
            expected: 0
        }
    );
}

#[test]
fn substituted_occurrences_are_rejected_by_length_and_by_hash() {
    // Another proof of another length in the declared slot.
    let mut other_length = fixture();
    other_length.occurrences[2] =
        SignedAttachmentOccurrenceV1::new(2, AttachmentKindV1::Proof, vec![0xAA; 49]);
    assert_eq!(
        rejected(&other_length),
        SignedAttachmentErrorV1::ReferenceLengthMismatch {
            action_index: 2,
            index: 2,
            declared: 48,
            actual: 49
        }
    );

    // Another proof of the same length.
    let mut other_bytes = fixture();
    other_bytes.occurrences[2] =
        SignedAttachmentOccurrenceV1::new(2, AttachmentKindV1::Proof, vec![0xAC; 48]);
    assert_eq!(
        rejected(&other_bytes),
        SignedAttachmentErrorV1::ReferenceHashMismatch {
            action_index: 2,
            index: 2
        }
    );

    // Bytes changed under an unchanged occurrence header.
    let mut stale_hash = fixture();
    stale_hash.occurrences[3].bytes[0] ^= 1;
    assert_eq!(
        rejected(&stale_hash),
        SignedAttachmentErrorV1::OccurrenceHashMismatch { index: 3 }
    );
    let mut stale_length = fixture();
    stale_length.occurrences[3].bytes.push(0);
    assert_eq!(
        rejected(&stale_length),
        SignedAttachmentErrorV1::OccurrenceLengthMismatch {
            index: 3,
            declared: 32,
            actual: 33
        }
    );
}

#[test]
fn omitted_occurrences_and_declarations_are_rejected() {
    let mut occurrence_omitted = fixture();
    occurrence_omitted.occurrences.pop();
    assert_eq!(
        rejected(&occurrence_omitted),
        SignedAttachmentErrorV1::MissingOccurrence {
            action_index: 2,
            index: 3
        }
    );

    let mut empty_occurrence = fixture();
    empty_occurrence.occurrences[3] =
        SignedAttachmentOccurrenceV1::new(3, AttachmentKindV1::KeyMaterial, Vec::new());
    assert_eq!(
        rejected(&empty_occurrence),
        SignedAttachmentErrorV1::EmptyOccurrence { index: 3 }
    );

    let no_actions = SignedAttachmentsV1::from_parts_unvalidated(Vec::new(), Vec::new());
    assert_eq!(
        no_actions.validate_v1(),
        Err(SignedAttachmentErrorV1::NoActions)
    );
    assert!(norito::decode_canonical::<SignedAttachmentsV1>(&frame(&no_actions)).is_err());
}

#[test]
fn duplicated_declarations_and_replayed_proof_bytes_are_rejected() {
    // One occurrence declared by two actions.
    let mut twice = fixture();
    twice.actions[1].attachments[0] = twice.actions[0].attachments[0];
    assert_eq!(
        rejected(&twice),
        SignedAttachmentErrorV1::DuplicateReference {
            action_index: 1,
            index: 0
        }
    );

    // The same proof bytes carried twice.
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(native_action(vec![proof_slot(vec![0xAA; 48])]));
    plan.push_action(native_action(vec![proof_slot(vec![0xAA; 48])]));
    assert_eq!(
        rejected(&bound(plan)),
        SignedAttachmentErrorV1::DuplicateProofContent {
            first: 0,
            second: 1
        }
    );

    // Identical key material admitted for two actions is not a replay.
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(native_action(vec![key_slot(vec![0xBB; 32])]));
    plan.push_action(native_action(vec![key_slot(vec![0xBB; 32])]));
    bound(plan).validate_v1().expect("shared key material");
}

#[test]
fn unused_occurrences_are_rejected() {
    let mut undeclared = fixture();
    undeclared
        .occurrences
        .push(SignedAttachmentOccurrenceV1::new(
            4,
            AttachmentKindV1::Proof,
            vec![0xEE; 8],
        ));
    assert_eq!(
        rejected(&undeclared),
        SignedAttachmentErrorV1::UnreferencedOccurrence { index: 4 }
    );

    // Dropping the declaration of a carried occurrence leaves it unused.
    let mut declaration_dropped = fixture();
    declaration_dropped.actions[2].attachments.pop();
    assert_eq!(
        rejected(&declaration_dropped),
        SignedAttachmentErrorV1::UnreferencedOccurrence { index: 3 }
    );
}

#[test]
fn declared_type_and_role_must_match_the_occurrence() {
    let mut other_kind = fixture();
    other_kind.actions[2].attachments[1].kind = AttachmentKindV1::Proof;
    assert_eq!(
        rejected(&other_kind),
        SignedAttachmentErrorV1::ReferenceKindMismatch {
            action_index: 2,
            index: 3
        }
    );

    let mut other_role = fixture();
    other_role.actions[2].attachments[1].role = AttachmentRoleV1::ActionProof;
    assert_eq!(
        rejected(&other_role),
        SignedAttachmentErrorV1::ReferenceRoleMismatch {
            action_index: 2,
            index: 3
        }
    );
}

#[test]
fn zero_digests_are_rejected() {
    let mut zero_inputs = fixture();
    zero_inputs.actions[1].public_inputs_digest = ActionPublicInputsDigestV1::ZERO;
    assert_eq!(
        rejected(&zero_inputs),
        SignedAttachmentErrorV1::ZeroPublicInputsDigest { action_index: 1 }
    );
    let mut zero_statement = fixture();
    zero_statement.actions[1].statement_digest = ActionStatementDigestV1::ZERO;
    assert_eq!(
        rejected(&zero_statement),
        SignedAttachmentErrorV1::ZeroStatementDigest { action_index: 1 }
    );
    // A declared but unbound plan is exactly that state.
    let unbound = SignedAttachmentPlanV1::transaction_proofs(&[attachment("vk", vec![1])])
        .expect("carrier")
        .declare();
    assert_eq!(
        unbound.validate_v1(),
        Err(SignedAttachmentErrorV1::ZeroStatementDigest { action_index: 0 })
    );
}

fn rule_of(action: &ActionIntentV1) -> Option<ActionRuleViolationV1> {
    action.rule_violation()
}

#[test]
fn carriers_follow_their_closed_operation_rules() {
    let value = fixture();
    let carrier = value.actions()[0].clone();
    assert_eq!(rule_of(&carrier), None);

    let mut role = carrier.clone();
    role.role = ActionRoleV1::ProofEffect;
    assert_eq!(rule_of(&role), Some(ActionRuleViolationV1::Role));

    let mut authority = carrier.clone();
    authority.authority = ActionAuthorityBindingV1::Account(account(1));
    assert_eq!(rule_of(&authority), Some(ActionRuleViolationV1::Authority));

    let mut invocation = carrier.clone();
    invocation.invocation = ActionInvocationBindingV1::Direct {
        instruction_index: 0,
    };
    assert_eq!(
        rule_of(&invocation),
        Some(ActionRuleViolationV1::Invocation)
    );

    let mut none = carrier.clone();
    none.attachments.clear();
    assert_eq!(rule_of(&none), Some(ActionRuleViolationV1::AttachmentCount));
    let mut two = carrier.clone();
    two.attachments.push(two.attachments[0]);
    assert_eq!(rule_of(&two), Some(ActionRuleViolationV1::AttachmentCount));

    let mut attachment_role = carrier.clone();
    attachment_role.attachments[0].role = AttachmentRoleV1::ExecutionProof;
    assert_eq!(
        rule_of(&attachment_role),
        Some(ActionRuleViolationV1::AttachmentRole)
    );

    // The execution carrier admits only its own role class and attachment role.
    let mut execution = carrier;
    execution.operation = ActionOperationV1::IvmProvedExecution;
    assert_eq!(rule_of(&execution), Some(ActionRuleViolationV1::Role));
    execution.role = ActionRoleV1::ProofEffect;
    assert_eq!(
        rule_of(&execution),
        Some(ActionRuleViolationV1::AttachmentRole)
    );
    execution.attachments[0].role = AttachmentRoleV1::ExecutionProof;
    assert_eq!(rule_of(&execution), None);

    // A violated rule is a schema violation of the whole value.
    let mut invalid = value;
    invalid.actions[0].role = ActionRoleV1::Administrative;
    assert_eq!(
        rejected(&invalid),
        SignedAttachmentErrorV1::OperationRule {
            action_index: 0,
            rule: ActionRuleViolationV1::Role
        }
    );
}

#[test]
fn native_instruction_actions_follow_their_closed_operation_rules() {
    let value = fixture();
    let native = value.actions()[2].clone();
    assert_eq!(rule_of(&native), None);

    // The transaction binding belongs to transaction-level carriers only.
    let mut transaction = native.clone();
    transaction.invocation = ActionInvocationBindingV1::Transaction;
    assert_eq!(
        rule_of(&transaction),
        Some(ActionRuleViolationV1::Invocation)
    );

    // A contract invocation never executes under the transaction signer.
    let mut signer = native.clone();
    signer.authority = ActionAuthorityBindingV1::TransactionAuthority;
    assert_eq!(rule_of(&signer), Some(ActionRuleViolationV1::Authority));

    // A direct instruction never executes under a contract subject.
    let mut direct = native.clone();
    direct.invocation = ActionInvocationBindingV1::Direct {
        instruction_index: 0,
    };
    assert_eq!(rule_of(&direct), Some(ActionRuleViolationV1::Authority));
    direct.authority = ActionAuthorityBindingV1::TransactionAuthority;
    assert_eq!(rule_of(&direct), None);
    direct.authority = ActionAuthorityBindingV1::Account(account(2));
    assert_eq!(rule_of(&direct), None);

    let mut carrier_role = native.clone();
    carrier_role.attachments[0].role = AttachmentRoleV1::ExecutionProof;
    assert_eq!(
        rule_of(&carrier_role),
        Some(ActionRuleViolationV1::AttachmentRole)
    );

    // An action without attachments is a declared action all the same.
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(native_action(Vec::new()));
    bound(plan)
        .validate_v1()
        .expect("action without attachments");
}

#[test]
fn instruction_wire_identifier_is_bounded_ascii() {
    let with_wire_id = |wire_id: String| {
        let mut plan = SignedAttachmentPlanV1::new();
        let mut action = native_action(vec![proof_slot(vec![1, 2, 3])]);
        action.operation = ActionOperationV1::NativeInstruction(wire_id);
        plan.push_action(action);
        bound(plan)
    };
    with_wire_id("x".repeat(ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1))
        .validate_v1()
        .expect("wire identifier at the limit");
    for malformed in [
        String::new(),
        "x".repeat(ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1 + 1),
        "iroha.log\n".to_owned(),
        "iroha log".to_owned(),
        "iroha.lög".to_owned(),
    ] {
        assert_eq!(
            rejected(&with_wire_id(malformed)),
            SignedAttachmentErrorV1::MalformedOperation { action_index: 0 }
        );
    }
}

#[test]
fn invocation_path_depth_accepts_the_limit_and_rejects_one_over() {
    let with_depth = |depth: usize| {
        let mut plan = SignedAttachmentPlanV1::new();
        let mut action = native_action(vec![proof_slot(vec![1, 2, 3])]);
        action.invocation = ActionInvocationBindingV1::Contract {
            root_index: 0,
            call_path: vec![0; depth],
        };
        plan.push_action(action);
        bound(plan)
    };
    with_depth(ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1)
        .validate_v1()
        .expect("path at the limit");
    assert_eq!(
        rejected(&with_depth(ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 + 1)),
        SignedAttachmentErrorV1::CallPathTooDeep {
            action_index: 0,
            actual: ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 + 1,
            maximum: ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1
        }
    );
}

fn with_actions(count: usize) -> SignedAttachmentsV1 {
    let mut plan = SignedAttachmentPlanV1::new();
    for _ in 0..count {
        plan.push_action(native_action(Vec::new()));
    }
    bound(plan)
}

fn with_occurrences(count: usize) -> SignedAttachmentsV1 {
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(native_action(
        (0..count)
            .map(|slot| proof_slot(vec![u8::try_from(slot).expect("small"), 1, 2]))
            .collect(),
    ));
    bound(plan)
}

#[test]
fn action_count_accepts_the_limit_and_rejects_one_over() {
    let at_limit = with_actions(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1);
    at_limit.validate_v1().expect("actions at the limit");
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&frame(&at_limit)).expect("decode"),
        at_limit
    );
    assert_eq!(
        rejected(&with_actions(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 + 1)),
        SignedAttachmentErrorV1::TooManyActions {
            actual: SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 + 1,
            maximum: SIGNED_ATTACHMENTS_MAX_ACTIONS_V1
        }
    );
}

#[test]
fn occurrence_count_accepts_the_limit_and_rejects_one_over() {
    let at_limit = with_occurrences(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1);
    at_limit.validate_v1().expect("occurrences at the limit");
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&frame(&at_limit)).expect("decode"),
        at_limit
    );
    assert_eq!(
        rejected(&with_occurrences(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1)),
        SignedAttachmentErrorV1::TooManyOccurrences {
            actual: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1,
            maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1
        }
    );
}

#[test]
fn decoder_refuses_forged_counts_before_decoding_elements() {
    let value = with_actions(1);
    let mut payload = bare(&value);
    // The first field is the action sequence: a compact field length, then the
    // fixed eight-byte element count.
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let (_, header) = ncore::read_len_dyn_slice(&payload).expect("action field length");
    let forged = u64::try_from(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 + 1).expect("count");
    payload[header..header + 8].copy_from_slice(&forged.to_le_bytes());
    let error = SignedAttachmentsV1::decode_from_slice(&payload).expect_err("forged action count");
    assert!(error.to_string().contains("more than the maximum of 16"));

    payload[header..header + 8].copy_from_slice(&0_u64.to_le_bytes());
    let error = SignedAttachmentsV1::decode_from_slice(&payload).expect_err("zero action count");
    assert!(error.to_string().contains("declare no action"));

    // The occurrence sequence is the second field.
    let mut payload = bare(&value);
    let (action_len, header) = ncore::read_len_dyn_slice(&payload).expect("action field length");
    let second = header + action_len;
    let (_, second_header) =
        ncore::read_len_dyn_slice(&payload[second..]).expect("occurrence field length");
    let count_at = second + second_header;
    let forged = u64::try_from(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1).expect("count");
    payload[count_at..count_at + 8].copy_from_slice(&forged.to_le_bytes());
    let error =
        SignedAttachmentsV1::decode_from_slice(&payload).expect_err("forged occurrence count");
    assert!(
        error
            .to_string()
            .contains("occurrences, more than the maximum")
    );
}

#[test]
fn action_decoder_roundtrips_every_binding_and_exact_nested_limits() {
    let mut actions = fixture().actions().to_vec();
    let mut direct = actions[2].clone();
    direct.authority = ActionAuthorityBindingV1::Account(account(0x42));
    direct.invocation = ActionInvocationBindingV1::Direct {
        instruction_index: 2,
    };
    actions.push(direct);
    let mut execution = actions[0].clone();
    execution.operation = ActionOperationV1::IvmProvedExecution;
    execution.role = ActionRoleV1::ProofEffect;
    execution.attachments[0].role = AttachmentRoleV1::ExecutionProof;
    actions.push(execution);
    for action in &actions {
        let encoded = norito::encode_canonical(action).expect("canonical action");
        assert_eq!(
            norito::decode_canonical::<ActionIntentV1>(&encoded).expect("bounded action decode"),
            *action
        );
    }
    let mut value = with_occurrences(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1);
    let action = &mut value.actions[0];
    action.operation =
        ActionOperationV1::NativeInstruction("x".repeat(ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1));
    action.invocation = ActionInvocationBindingV1::Contract {
        root_index: 0,
        call_path: vec![0; ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1],
    };
    value
        .validate_v1()
        .expect("all nested limits are inclusive");
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&frame(&value))
            .expect("nested fields at their limits"),
        value
    );

    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut trailing = norito::codec::Encode::encode(&value.actions[0]);
    trailing.push(0);
    assert!(ActionIntentV1::decode_from_slice(&trailing).is_err());
}

#[test]
fn borrowed_action_preflight_does_not_charge_owned_allocation() {
    let value = with_occurrences(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1);
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let encoded = norito::codec::Encode::encode(&value.actions[0]);
    let limits = ncore::DecodeLimits::new(usize::MAX, usize::MAX, 0, 0, 32);
    ncore::with_decode_limits(limits, || {
        let mut offset = 0;
        let mut fields = [&[][..]; 8];
        for field in &mut fields {
            *field = take_field(&encoded, &mut offset, encoded.len())?;
        }
        assert_eq!(offset, encoded.len());
        preflight_action_fields(0, fields[1], fields[4], fields[7])
    })
    .expect("borrowing fields and inspecting counts need no owned allocation or elements");
}

#[test]
fn action_decoder_refuses_nested_counts_before_decoding_elements() {
    let value = with_occurrences(1);
    let action = &value.actions[0];
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let encoded = norito::codec::Encode::encode(action);
    let replace_field = |position: usize, replacement: &[u8]| {
        let mut offset = 0;
        let mut result = Vec::new();
        for field_index in 0..8 {
            let field = take_field(&encoded, &mut offset, encoded.len()).expect("field");
            let field = if field_index == position {
                replacement
            } else {
                field
            };
            ncore::write_len_to_vec(
                &mut result,
                u64::try_from(field.len()).expect("field length"),
            );
            result.extend_from_slice(field);
        }
        assert_eq!(offset, encoded.len());
        result
    };
    let bounded_decode = |bytes: &[u8]| {
        // Nothing in these rejected descriptors needs an owned allocation.
        // Charging a borrowed field or attempting to decode the forged
        // vectors would exhaust this budget before the schema error appears.
        let limits = ncore::DecodeLimits::new(usize::MAX, usize::MAX, 0, 0, 32);
        ncore::with_decode_limits(limits, || ActionIntentV1::decode_from_slice(bytes))
    };

    // Supply only a count, with no reference elements. The bounded error must
    // win over the generic vector's malformed-span error and allocation.
    let references = u64::try_from(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1)
        .expect("reference count")
        .to_le_bytes();
    let error = bounded_decode(&replace_field(7, &references)).expect_err("references over limit");
    assert!(
        error.to_string().contains("17 attachment references"),
        "{error}"
    );

    // The same rule applies to a contract path with no encoded ordinals.
    let mut invocation = 2_u32.to_le_bytes().to_vec();
    ncore::write_len_to_vec(&mut invocation, 4);
    invocation.extend_from_slice(&0_u32.to_le_bytes());
    ncore::write_len_to_vec(&mut invocation, 8);
    invocation.extend_from_slice(
        &u64::try_from(ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 + 1)
            .expect("path depth")
            .to_le_bytes(),
    );
    let error = bounded_decode(&replace_field(4, &invocation)).expect_err("path over limit");
    assert!(error.to_string().contains("path of 33 calls"), "{error}");

    // An oversized declared wire identifier is refused before its String is
    // allocated or its deliberately missing bytes are visited.
    let mut name = Vec::new();
    ncore::write_len_to_vec(
        &mut name,
        u64::try_from(ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1 + 1).expect("wire id length"),
    );
    let mut operation = 0_u32.to_le_bytes().to_vec();
    ncore::write_len_to_vec(
        &mut operation,
        u64::try_from(name.len()).expect("name field"),
    );
    operation.extend_from_slice(&name);
    let error =
        bounded_decode(&replace_field(1, &operation)).expect_err("wire identifier over limit");
    assert!(
        error
            .to_string()
            .contains("malformed instruction wire identifier"),
        "{error}"
    );
}

#[test]
fn action_reference_count_accepts_the_limit_and_rejects_one_over() {
    let mut value = with_occurrences(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1);
    value.validate_v1().expect("exact reference bound");
    let duplicate = value.actions[0].attachments[0];
    value.actions[0].attachments.push(duplicate);
    assert_eq!(
        rejected(&value),
        SignedAttachmentErrorV1::TooManyReferences {
            action_index: 0,
            actual: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1,
            maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
        }
    );
}

#[test]
fn occurrence_decoder_refuses_a_declared_byte_count_over_the_limit_before_allocating() {
    let occurrence = SignedAttachmentOccurrenceV1::new(0, AttachmentKindV1::Proof, vec![5; 24]);
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut payload = norito::codec::Encode::encode(&occurrence);
    let (decoded, used) =
        SignedAttachmentOccurrenceV1::decode_from_slice(&payload).expect("bare occurrence");
    assert_eq!((decoded, used), (occurrence, payload.len()));

    // The byte sequence is the last field: its fixed eight-byte count precedes the bytes.
    let count_at = payload.len() - 24 - 8;
    let forged = u64::try_from(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 1).expect("count");
    payload[count_at..count_at + 8].copy_from_slice(&forged.to_le_bytes());
    let error = SignedAttachmentOccurrenceV1::decode_from_slice(&payload)
        .expect_err("declared count over the limit");
    assert!(
        error
            .to_string()
            .contains("more than the maximum of 9437184 bytes"),
        "{error}"
    );

    // Trailing bytes after the last field are refused.
    let mut trailing = norito::codec::Encode::encode(&SignedAttachmentOccurrenceV1::new(
        0,
        AttachmentKindV1::Proof,
        vec![5; 24],
    ));
    trailing.push(0);
    assert!(SignedAttachmentOccurrenceV1::decode_from_slice(&trailing).is_err());
}

#[test]
fn occurrence_bytes_accept_the_limit_and_reject_one_over() {
    let with_proof = |length: usize| {
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(native_action(vec![proof_slot(vec![0x5a; length])]));
        bound(plan)
    };
    let at_limit = with_proof(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1);
    at_limit.validate_v1().expect("occurrence at the limit");
    let framed = frame(&at_limit);
    assert!(framed.len() <= SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1);
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&framed).expect("decode at the limit"),
        at_limit
    );

    let over = with_proof(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 1);
    assert_eq!(
        over.validate_v1(),
        Err(SignedAttachmentErrorV1::OccurrenceTooLarge {
            index: 0,
            actual: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 1,
            maximum: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1
        })
    );
    let error = norito::decode_canonical::<SignedAttachmentsV1>(&frame(&over))
        .expect_err("decode one over");
    assert!(
        error
            .to_string()
            .contains("more than the maximum of 9437184 bytes"),
        "{error}"
    );
}

/// A value whose complete canonical frame has exactly the requested length.
fn with_frame_len(target: usize) -> SignedAttachmentsV1 {
    let build = |second: usize| {
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(native_action(vec![
            proof_slot(vec![0x5a; SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1]),
            key_slot(vec![0xa5; second]),
        ]));
        bound(plan)
    };
    let mut second = (target - SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1) / 2;
    loop {
        let value = build(second);
        let actual = value.canonical_frame_len_v1().expect("frame length");
        if actual == target {
            return value;
        }
        second = second + target - actual;
    }
}

#[test]
fn frame_accepts_the_limit_and_rejects_one_over() {
    let at_limit = with_frame_len(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1);
    at_limit.validate_v1().expect("frame at the limit");
    let framed = frame(&at_limit);
    assert_eq!(
        framed.len(),
        SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1
    );
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&framed).expect("decode at the limit"),
        at_limit
    );

    let over = with_frame_len(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 + 1);
    assert_eq!(
        over.validate_v1(),
        Err(SignedAttachmentErrorV1::FrameTooLarge {
            actual: SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 + 1,
            maximum: SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1
        })
    );
    let error = norito::decode_canonical::<SignedAttachmentsV1>(&frame(&over))
        .expect_err("decode one over");
    assert!(
        error
            .to_string()
            .contains("more than the maximum of 9502720 bytes"),
        "{error}"
    );
    // The frame bound is the occurrence ceiling plus the 64 KiB framing allowance.
    assert_eq!(
        SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 - SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
        65_536
    );
}

#[test]
fn normalized_projection_removes_only_generated_values() {
    let value = fixture();
    let normalized = value.normalized_for_intent_v1();
    assert_eq!(normalized.actions.len(), value.actions.len());
    assert_eq!(normalized.occurrences.len(), value.occurrences.len());
    for (before, after) in value.occurrences.iter().zip(&normalized.occurrences) {
        assert!(after.bytes.is_empty());
        assert_eq!((after.index, after.kind), (before.index, before.kind));
        if before.kind.is_generated() {
            assert_eq!(after.length, 0);
            assert!(after.content_hash.is_zero());
        } else {
            assert_eq!(after.length, before.length);
            assert_eq!(after.content_hash, before.content_hash);
        }
    }
    for (before, after) in value.actions.iter().zip(&normalized.actions) {
        assert!(after.statement_digest.is_zero());
        assert_eq!(after.action_index, before.action_index);
        assert_eq!(after.operation, before.operation);
        assert_eq!(after.role, before.role);
        assert_eq!(after.authority, before.authority);
        assert_eq!(after.invocation, before.invocation);
        assert_eq!(after.public_inputs_digest, before.public_inputs_digest);
        for (reference, projected) in before.attachments.iter().zip(&after.attachments) {
            assert_eq!(
                (projected.index, projected.kind, projected.role),
                (reference.index, reference.kind, reference.role)
            );
            if reference.kind.is_generated() {
                assert_eq!(projected.length, 0);
                assert!(projected.content_hash.is_zero());
            } else {
                assert_eq!(projected, reference);
            }
        }
    }

    // Replacing a generated proof leaves the projection unchanged; replacing
    // key material changes it.
    let mut other_proof = value.clone();
    other_proof
        .set_occurrence_bytes(2, vec![0xCD; 77])
        .expect("proof slot");
    assert_ne!(other_proof, value);
    assert_eq!(other_proof.normalized_for_intent_v1(), normalized);
    let mut other_key = value.clone();
    other_key
        .set_occurrence_bytes(3, vec![0xCD; 32])
        .expect("key slot");
    assert_ne!(other_key.normalized_for_intent_v1(), normalized);
}

#[test]
fn set_occurrence_bytes_updates_the_occurrence_and_its_reference() {
    let mut value = fixture();
    value
        .set_occurrence_bytes(2, vec![0x33; 9])
        .expect("occurrence 2");
    let occurrence = value.occurrence(2).expect("occurrence 2");
    assert_eq!(occurrence.bytes, vec![0x33; 9]);
    assert_eq!(occurrence.kind, AttachmentKindV1::Proof);
    assert_eq!(
        value.actions()[2].attachments[0],
        occurrence.reference(AttachmentRoleV1::ActionProof)
    );
    value.validate_v1().expect("still valid");
    assert_eq!(
        value.set_occurrence_bytes(9, vec![1]),
        Err(SignedAttachmentErrorV1::MissingOccurrence {
            action_index: 0,
            index: 9
        })
    );
}

#[test]
fn statement_digest_binds_every_member_of_the_statement() {
    let value = fixture();
    let action = value.actions()[2].clone();
    let statement = action.statement_for_v1(INTENT);
    let digest = statement.digest().expect("digest");
    assert_eq!(
        action.statement_digest_for_v1(INTENT).expect("digest"),
        digest
    );
    assert_eq!(action.statement_digest, digest);

    // The preimage is the domain, the frame length and the canonical frame.
    let encoded = norito::encode_canonical(&statement).expect("frame");
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACTION_STATEMENT_DIGEST_DOMAIN_V1);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    assert_eq!(digest.into_bytes(), *hasher.finalize().as_bytes());

    let mut changed = Vec::new();
    changed.push(action.statement_for_v1(OrderedIntentDigestV1::new([0x12; 32])));
    let mut next = statement.clone();
    next.action_index += 1;
    changed.push(next);
    let mut next = statement.clone();
    next.operation = ActionOperationV1::NativeInstruction("iroha.log".into());
    changed.push(next);
    let mut next = statement.clone();
    next.role = ActionRoleV1::ProofVerification;
    changed.push(next);
    let mut next = statement.clone();
    next.authority = ActionAuthorityBindingV1::ContractSubject(account(0x42));
    changed.push(next);
    let mut next = statement.clone();
    next.invocation = ActionInvocationBindingV1::Contract {
        root_index: 0,
        call_path: vec![0],
    };
    changed.push(next);
    let mut next = statement.clone();
    next.public_inputs_digest = ActionPublicInputsDigestV1::new([0x5b; 32]);
    changed.push(next);
    for other in changed {
        assert_ne!(other.digest().expect("digest"), digest);
    }
}

#[test]
fn statement_bindings_of_another_intent_are_rejected() {
    let value = fixture();
    value
        .validate_statement_bindings_v1(INTENT)
        .expect("bound to this intent");
    let other = OrderedIntentDigestV1::new([0x12; 32]);
    let expected = value.actions()[0]
        .statement_digest_for_v1(other)
        .expect("digest");
    assert_eq!(
        value.validate_statement_bindings_v1(other),
        Err(SignedAttachmentErrorV1::StatementBindingMismatch {
            action_index: 0,
            expected,
            actual: value.actions()[0].statement_digest
        })
    );
    let mut rebound = value.clone();
    rebound.bind_statements_v1(other).expect("rebound");
    rebound
        .validate_statement_bindings_v1(other)
        .expect("bound to the other intent");
    assert_ne!(rebound, value);
}

#[test]
fn domain_separated_digest_frames_the_length() {
    let digest = domain_separated_digest(b"domain", b"ab").expect("digest");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"domain");
    hasher.update(&2_u64.to_le_bytes());
    hasher.update(b"ab");
    assert_eq!(digest, *hasher.finalize().as_bytes());
    // The length frame separates the domain from the bytes.
    assert_ne!(
        domain_separated_digest(b"domaina", b"b").expect("digest"),
        domain_separated_digest(b"domain", b"ab").expect("digest")
    );
}

#[test]
fn proof_carrier_public_inputs_exclude_only_the_generated_proof() {
    let wrapped = attachment("vk_a", vec![1, 2, 3]);
    let digest = proof_carrier_public_inputs_digest_v1(&wrapped).expect("digest");
    assert!(!digest.is_zero());

    let mut other_proof = wrapped.clone();
    other_proof.proof.bytes = vec![9; 64];
    other_proof.envelope_hash = Some(iroha_crypto::Hash::new(&other_proof.proof.bytes).into());
    assert_eq!(
        proof_carrier_public_inputs_digest_v1(&other_proof).expect("digest"),
        digest
    );

    let mut other_key = wrapped.clone();
    other_key.vk_ref = VerifyingKeyId::new("halo2/ipa", "vk_b");
    let mut other_commitment = wrapped.clone();
    other_commitment.vk_commitment = Some([4; 32]);
    let mut other_backend = wrapped.clone();
    other_backend.backend = "stark/fri".into();
    other_backend.proof.backend = "stark/fri".into();
    other_backend.vk_ref = VerifyingKeyId::new("stark/fri", "vk_a");
    let mut with_witness = wrapped;
    with_witness.lane_privacy = lane_attachment().lane_privacy;
    for other in [other_key, other_commitment, other_backend, with_witness] {
        assert_ne!(
            proof_carrier_public_inputs_digest_v1(&other).expect("digest"),
            digest
        );
    }
}

#[test]
fn planned_carriers_wrap_one_canonical_proof_attachment() {
    let wrapped = attachment("vk_a", vec![1, 2, 3]);
    let planned = PlannedActionV1::transaction_proof(&wrapped).expect("carrier");
    assert_eq!(planned.operation, ActionOperationV1::TransactionProof);
    assert_eq!(planned.role, ActionRoleV1::ProofVerification);
    assert_eq!(
        planned.authority,
        ActionAuthorityBindingV1::TransactionAuthority
    );
    assert_eq!(planned.invocation, ActionInvocationBindingV1::Transaction);
    assert_eq!(
        planned.public_inputs_digest,
        proof_carrier_public_inputs_digest_v1(&wrapped).expect("digest")
    );
    assert_eq!(
        planned.attachments,
        vec![PlannedAttachmentV1 {
            kind: AttachmentKindV1::Proof,
            role: AttachmentRoleV1::ActionProof,
            bytes: norito::encode_canonical(&wrapped).expect("frame"),
        }]
    );

    let lane = PlannedActionV1::transaction_proof(&lane_attachment()).expect("lane carrier");
    assert_eq!(lane.attachments[0].role, AttachmentRoleV1::LanePrivacyProof);

    let execution = PlannedActionV1::ivm_proved_execution(&wrapped).expect("execution carrier");
    assert_eq!(execution.operation, ActionOperationV1::IvmProvedExecution);
    assert_eq!(execution.role, ActionRoleV1::ProofEffect);
    assert_eq!(
        execution.attachments[0].role,
        AttachmentRoleV1::ExecutionProof
    );
    assert_eq!(
        PlannedActionV1::ivm_proved_execution(&lane_attachment()),
        Err(SignedAttachmentErrorV1::ProofCarrierRoleMismatch { index: 0 })
    );

    // A structurally invalid attachment is refused when it is planned.
    let mut zero_commitment = attachment("vk_a", vec![1, 2, 3]);
    zero_commitment.vk_commitment = Some([0; 32]);
    assert!(matches!(
        PlannedActionV1::transaction_proof(&zero_commitment),
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, .. })
    ));
    assert!(matches!(
        SignedAttachmentPlanV1::transaction_proofs(&[zero_commitment.clone()]),
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { .. })
    ));

    // The unvalidated constructor wraps it; validation then refuses the carrier.
    let mut plan = SignedAttachmentPlanV1::new();
    plan.push_action(
        PlannedActionV1::transaction_proof_unvalidated(&zero_commitment).expect("wrapped"),
    );
    let wrapped_malformed = bound(plan);
    wrapped_malformed
        .validate_v1()
        .expect("the descriptor itself is well formed");
    match wrapped_malformed.validate_proof_carriers_v1() {
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason }) => {
            assert!(reason.contains("vk_commitment"), "{reason}");
        }
        other => panic!("expected a malformed carrier, got {other:?}"),
    }
    assert_eq!(
        PlannedActionV1::transaction_proof_unvalidated(&wrapped).expect("wrapped"),
        planned
    );
}

#[test]
fn carrier_accessors_return_the_wrapped_attachments() {
    let first = attachment("vk_a", vec![1, 2, 3]);
    let lane = lane_attachment();
    let mut plan =
        SignedAttachmentPlanV1::transaction_proofs(&[first.clone(), lane.clone()]).expect("plan");
    plan.push_action(native_action(vec![proof_slot(vec![0xAA; 48])]));
    let value = bound(plan);
    value.validate_v1().expect("valid");
    value.validate_proof_carriers_v1().expect("valid carriers");

    let carriers = value.proof_carriers_v1().expect("carriers");
    assert_eq!(
        carriers
            .iter()
            .map(|(action, wrapped)| (action.action_index, wrapped.clone()))
            .collect::<Vec<_>>(),
        vec![(0, first.clone()), (1, lane.clone())]
    );
    assert_eq!(
        value
            .proof_carrier_v1(&value.actions()[0])
            .expect("carrier"),
        Some(first)
    );
    // A native action wraps nothing.
    assert_eq!(
        value.proof_carrier_v1(&value.actions()[2]).expect("native"),
        None
    );
    assert_eq!(
        value.lane_privacy_proofs_v1().expect("witnesses"),
        vec![lane.lane_privacy.expect("witness")]
    );
}

#[test]
fn malformed_and_misdeclared_carriers_are_rejected() {
    let wrapped = attachment("vk_a", vec![1, 2, 3]);
    let valid = bound(
        SignedAttachmentPlanV1::transaction_proofs(std::slice::from_ref(&wrapped)).expect("plan"),
    );

    // Bytes that are not a canonical proof attachment.
    let mut garbage = valid.clone();
    garbage
        .set_occurrence_bytes(0, vec![0xFF; 40])
        .expect("slot");
    garbage.validate_v1().expect("structurally valid");
    assert!(matches!(
        garbage.validate_proof_carriers_v1(),
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, .. })
    ));
    assert!(garbage.proof_carriers_v1().is_err());

    // A trailing byte after the canonical frame.
    let mut trailing = valid.clone();
    let mut bytes = norito::encode_canonical(&wrapped).expect("frame");
    bytes.push(0);
    trailing.set_occurrence_bytes(0, bytes).expect("slot");
    assert!(matches!(
        trailing.validate_proof_carriers_v1(),
        Err(SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, .. })
    ));

    // Other verifying-key metadata under the declared public-input digest.
    let mut other_key = valid.clone();
    let mut substituted = wrapped.clone();
    substituted.vk_ref = VerifyingKeyId::new("halo2/ipa", "vk_other");
    other_key
        .set_occurrence_bytes(0, norito::encode_canonical(&substituted).expect("frame"))
        .expect("slot");
    other_key.validate_v1().expect("structurally valid");
    assert_eq!(
        other_key.validate_proof_carriers_v1(),
        Err(SignedAttachmentErrorV1::PublicInputsMismatch { action_index: 0 })
    );

    // A lane witness under the plain proof role, and the reverse.
    let mut hidden_witness = valid.clone();
    hidden_witness
        .set_occurrence_bytes(
            0,
            norito::encode_canonical(&lane_attachment()).expect("frame"),
        )
        .expect("slot");
    assert_eq!(
        hidden_witness.validate_proof_carriers_v1(),
        Err(SignedAttachmentErrorV1::ProofCarrierRoleMismatch { index: 0 })
    );
    let mut missing_witness = valid;
    missing_witness.actions[0].attachments[0].role = AttachmentRoleV1::LanePrivacyProof;
    missing_witness.validate_v1().expect("structurally valid");
    assert_eq!(
        missing_witness.validate_proof_carriers_v1(),
        Err(SignedAttachmentErrorV1::ProofCarrierRoleMismatch { index: 0 })
    );
    assert_eq!(missing_witness.lane_privacy_proofs_v1(), Ok(Vec::new()));
}
