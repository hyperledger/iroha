//! Candidate-policy codecs and exact-source extraction using genuine signed genesis.

mod native_source;

use super::*;
use crate::{
    account::AccountId,
    block::SignedBlock,
    events::execute_trigger::ExecuteTriggerEventFilter,
    isi::{InstructionBox, Register},
    parameter::system::ConsensusMode,
    sumeragi_finality::{
        SignedGenesisPinsV1, authenticate_signed_genesis_v1, test_fixtures::NativeFinalityFixture,
    },
    transaction::TransactionBuilder,
    trigger::{
        Trigger,
        action::{Action, Repeats},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::peer::PeerId;
use sha2::{Digest as _, Sha256};
use std::time::Duration;

const CHAIN: &str = "parliament-candidate-testing-fixture";

fn instruction(parameter: CustomParameter) -> InstructionBox {
    SetParameter::new(Parameter::Custom(parameter)).into()
}

fn candidate_instruction() -> InstructionBox {
    instruction(
        ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
            .to_custom_parameter()
            .unwrap(),
    )
}

fn signed(extra: Vec<InstructionBox>) -> SignedBlock {
    NativeFinalityFixture::start_with_genesis_extension(CHAIN, [0x73; 32], extra)
        .genesis()
        .clone()
}

// Fixed public fixture authorities select these pins independently of the policy under test.
// This helper is not deployment trust discovery and executes no World transition.
fn pins(block: &SignedBlock) -> (Vec<u8>, SignedGenesisPinsV1) {
    let wire = block.encode_wire().unwrap();
    let mut roster: Vec<_> = (1..=4_u8)
        .map(|seed| {
            PeerId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .public_key()
                    .clone(),
            )
        })
        .collect();
    roster.sort();
    let pins = SignedGenesisPinsV1 {
        chain_id: CHAIN.into(),
        network_id: NetworkId::from_genesis_hash(block.hash()),
        genesis_hash: block.hash(),
        signed_genesis_sha256: Sha256::digest(&wire).into(),
        genesis_public_key: KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
        roster,
        mode: ConsensusMode::Permissioned,
    };
    (wire, pins)
}

fn authenticate(block: &SignedBlock) -> AuthenticatedSignedGenesisV1 {
    let (wire, pins) = pins(block);
    authenticate_signed_genesis_v1(&wire, &pins).unwrap()
}

fn unchecked_parameter(policy: ParliamentCandidateTestingPolicyV1) -> CustomParameter {
    CustomParameter::new(
        ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
        Json::try_new(policy).unwrap(),
    )
}

#[test]
fn candidate_testing_policy_roundtrips_canonical_norito_and_json() {
    let policy = ParliamentCandidateTestingPolicyV1::CANDIDATE_V1;
    policy.validate().unwrap();
    let bytes = policy.to_canonical_bytes().unwrap();
    assert!(bytes.len() <= ParliamentCandidateTestingPolicyV1::MAX_WIRE_BYTES);
    assert_eq!(&bytes[..4], b"NRT0");
    assert_eq!(
        ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&bytes).unwrap(),
        policy
    );
    let parameter = policy.to_custom_parameter().unwrap();
    assert_eq!(
        parameter.id().to_string(),
        "parliament_candidate_testing_v1"
    );
    assert!(parameter.payload().get().len() <= ParliamentCandidateTestingPolicyV1::MAX_JSON_BYTES);
    assert_eq!(
        ParliamentCandidateTestingPolicyV1::from_custom_parameter(&parameter).unwrap(),
        policy
    );
    let encoded_parameter = norito::encode_canonical(&parameter).unwrap();
    let decoded_parameter: CustomParameter = norito::decode_canonical(&encoded_parameter).unwrap();
    assert_eq!(decoded_parameter, parameter);
}

#[test]
fn candidate_testing_policy_refuses_truncation_trailing_layout_and_size() {
    let bytes = ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
        .to_canonical_bytes()
        .unwrap();
    for end in 0..bytes.len() {
        assert!(
            ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&bytes[..end]).is_err(),
            "truncation at {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&trailing).is_err());
    let mut foreign_schema = bytes.clone();
    foreign_schema[6] ^= 1;
    assert!(ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&foreign_schema).is_err());
    let mut layout = bytes;
    layout[39] |= 0x80;
    assert!(ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&layout).is_err());
    assert!(matches!(
        ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&vec![
            0;
            ParliamentCandidateTestingPolicyV1::MAX_WIRE_BYTES
                + 1
        ]),
        Err(ParliamentCandidateTestingErrorV1::Codec(
            AnonymousBallotCodecErrorV1::TooLarge { .. }
        ))
    ));
}

#[test]
fn candidate_testing_policy_refuses_unsupported_version_and_profile_on_every_reader() {
    let candidate = ParliamentCandidateTestingPolicyV1::CANDIDATE_V1;
    for policy in [
        ParliamentCandidateTestingPolicyV1 {
            version: 0,
            ..candidate
        },
        ParliamentCandidateTestingPolicyV1 {
            version: 2,
            ..candidate
        },
        ParliamentCandidateTestingPolicyV1 {
            profile: ProofProfileIdV1::new([0; 64]),
            ..candidate
        },
    ] {
        assert!(policy.validate().is_err());
        assert!(policy.to_canonical_bytes().is_err());
        assert!(policy.to_custom_parameter().is_err());
        let wire = super::super::framing::enc(&policy).unwrap();
        assert!(ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&wire).is_err());
        assert!(
            ParliamentCandidateTestingPolicyV1::from_custom_parameter(&unchecked_parameter(policy))
                .is_err()
        );
    }
}

#[test]
fn candidate_testing_parameter_rejects_wrong_identity_malformed_unknown_and_oversized_json() {
    let valid = ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
        .to_custom_parameter()
        .unwrap();
    let foreign = CustomParameter::new("other".parse().unwrap(), valid.payload().clone());
    assert!(matches!(
        ParliamentCandidateTestingPolicyV1::from_custom_parameter(&foreign),
        Err(ParliamentCandidateTestingErrorV1::ParameterIdentity)
    ));
    for payload in [
        r#"{"version":1}"#.to_owned(),
        r#"{"profile":1,"version":1}"#.to_owned(),
        valid.payload().get().replacen('{', r#"{"extra":0,"#, 1),
    ] {
        let malformed = CustomParameter::new(
            ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
            payload.parse::<Json>().unwrap(),
        );
        assert!(matches!(
            ParliamentCandidateTestingPolicyV1::from_custom_parameter(&malformed),
            Err(ParliamentCandidateTestingErrorV1::Json(_))
        ));
    }
    let oversized = CustomParameter::new(
        ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
        Json::try_new("a".repeat(ParliamentCandidateTestingPolicyV1::MAX_JSON_BYTES)).unwrap(),
    );
    assert!(matches!(
        ParliamentCandidateTestingPolicyV1::from_custom_parameter(&oversized),
        Err(ParliamentCandidateTestingErrorV1::JsonTooLarge { .. })
    ));
    assert!(
        format!("{}false", valid.payload().get())
            .parse::<Json>()
            .is_err(),
        "the canonical custom-parameter owner must reject trailing JSON"
    );
}

#[test]
fn candidate_testing_absent_policy_stays_disabled_even_with_other_parameters() {
    let source = authenticate(&signed(vec![instruction(CustomParameter::new(
        "unrelated".parse().unwrap(),
        Json::try_new(ParliamentCandidateTestingPolicyV1::CANDIDATE_V1).unwrap(),
    ))]));
    assert!(
        parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id)
            .unwrap()
            .is_none()
    );
    assert!(!super::super::parliament_ballot_qualified_v1());
}

#[test]
fn candidate_testing_genuine_genesis_retains_exact_network_input_and_instruction() {
    let block = signed(vec![candidate_instruction()]);
    let source = authenticate(&block);
    let selection =
        parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        selection.network_id(),
        NetworkId::from_genesis_hash(block.hash())
    );
    assert_eq!(
        selection.policy(),
        &ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
    );
    let (input, index) = selection.source_position();
    let transaction = block.external_transactions().nth(input).unwrap();
    assert_eq!(
        selection.source_entrypoint_hash(),
        transaction.hash_as_entrypoint()
    );
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("original signed instructions");
    };
    assert_eq!(instructions[index], candidate_instruction());
    assert_eq!(input, 0);
    assert_eq!(index, instructions.len() - 1);
    assert!(!super::super::parliament_ballot_qualified_v1());
}

#[test]
fn candidate_testing_refuses_foreign_genesis_even_with_the_same_chain_label() {
    let selected_block = signed(vec![candidate_instruction()]);
    let foreign_block = signed(Vec::new());
    let selected = authenticate(&selected_block);
    let foreign = authenticate(&foreign_block);
    assert_eq!(selected.pins().chain_id, foreign.pins().chain_id);
    assert_ne!(selected.pins().network_id, foreign.pins().network_id);
    for (source, expected) in [
        (&selected, foreign.pins().network_id),
        (&foreign, selected.pins().network_id),
    ] {
        assert!(matches!(
            parliament_candidate_testing_from_genesis_v1(source, &expected),
            Err(ParliamentCandidateTestingErrorV1::ForeignNetwork)
        ));
    }
    let (wire, _) = pins(&foreign_block);
    assert!(authenticate_signed_genesis_v1(&wire, selected.pins()).is_err());
}

#[test]
fn candidate_testing_rejects_duplicate_original_instructions_in_one_or_two_inputs() {
    let same_input = signed(vec![candidate_instruction(), candidate_instruction()]);
    let first = signed(vec![candidate_instruction()]);
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let original = first.external_transactions().next().unwrap();
    let mut builder = TransactionBuilder::new_genesis(
        original.authority().clone(),
        original.fee_payment_intent().clone(),
    );
    builder.set_creation_time(Duration::from_millis(1));
    let duplicate = builder
        .with_instructions([candidate_instruction()])
        .sign(signer.private_key());
    let two_inputs = SignedBlock::try_genesis(
        vec![original.clone(), duplicate],
        signer.private_key(),
        None,
        None,
    )
    .unwrap();
    for block in [same_input, two_inputs] {
        let source = authenticate(&block);
        assert!(matches!(
            parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id),
            Err(ParliamentCandidateTestingErrorV1::DuplicatePolicy)
        ));
    }
}

#[test]
fn candidate_testing_rejects_invalid_policy_even_when_original_signatures_are_valid() {
    for parameter in [
        unchecked_parameter(ParliamentCandidateTestingPolicyV1 {
            version: 2,
            ..ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
        }),
        unchecked_parameter(ParliamentCandidateTestingPolicyV1 {
            profile: ProofProfileIdV1::new([0; 64]),
            ..ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
        }),
        CustomParameter::new(
            ParliamentCandidateTestingPolicyV1::parameter_id().clone(),
            r#"{"version":1}"#.parse::<Json>().unwrap(),
        ),
    ] {
        let source = authenticate(&signed(vec![instruction(parameter)]));
        assert!(
            parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id)
                .is_err()
        );
    }
}

#[test]
fn candidate_testing_extraction_preserves_original_json_resource_refusal() {
    let source = authenticate(&signed(vec![candidate_instruction()]));
    let decoder = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000,
        48 * 1024 * 1024,
        1_000_000,
        0,
        64,
    ));
    let error = decoder
        .with(|| parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id))
        .unwrap_err();
    assert!(
        matches!(
            error,
            ParliamentCandidateTestingErrorV1::Json(norito::json::Error::DecodeResource(_))
        ),
        "{error:?}"
    );
}

#[test]
fn candidate_testing_binary_reader_preserves_original_enclosing_field_refusal() {
    let policy = ParliamentCandidateTestingPolicyV1::CANDIDATE_V1;
    let bytes = policy.to_canonical_bytes().unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64);
    let error = norito::with_decode_limits_scope(limits, || {
        ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&bytes)
    })
    .unwrap_err();
    let ParliamentCandidateTestingErrorV1::Codec(AnonymousBallotCodecErrorV1::DecodeUnavailable(
        refusal,
    )) = error
    else {
        panic!("original caller refusal must not become invalid policy: {error:?}");
    };
    assert_eq!(
        refusal.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert!(matches!(
        refusal.resource_error(),
        norito::core::DecodeResourceError::FieldLengthExceeded { limit: 1, .. }
    ));
    assert_eq!(
        ParliamentCandidateTestingPolicyV1::from_canonical_bytes(&bytes).unwrap(),
        policy
    );
}

#[test]
fn candidate_testing_nested_trigger_policy_cannot_authorize_testing() {
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let trigger = Trigger::new(
        "nested_candidate_policy".parse().unwrap(),
        Action::new(
            Executable::Instructions(vec![candidate_instruction()].into()),
            Repeats::Exactly(1),
            AccountId::new(signer.public_key().clone()),
            ExecuteTriggerEventFilter::new(),
        )
        .unwrap(),
    );
    let source = authenticate(&signed(vec![Register::trigger(trigger).into()]));
    assert!(
        parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id)
            .unwrap()
            .is_none(),
        "a reserved parameter inside an independently executed owner is not a direct genesis selection"
    );
}

#[test]
fn candidate_testing_policy_in_second_original_input_retains_nonzero_coordinate() {
    let first = signed(Vec::new());
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let original = first.external_transactions().next().unwrap();
    let mut builder = TransactionBuilder::new_genesis(
        original.authority().clone(),
        original.fee_payment_intent().clone(),
    );
    builder.set_creation_time(Duration::from_millis(1));
    let second = builder
        .with_instructions([candidate_instruction()])
        .sign(signer.private_key());
    let expected_entrypoint = second.hash_as_entrypoint();
    assert_ne!(expected_entrypoint, original.hash_as_entrypoint());
    let block = SignedBlock::try_genesis(
        vec![original.clone(), second],
        signer.private_key(),
        None,
        None,
    )
    .unwrap();
    let source = authenticate(&block);
    let selection =
        parliament_candidate_testing_from_genesis_v1(&source, &source.pins().network_id)
            .unwrap()
            .unwrap();
    assert_eq!(selection.source_position(), (1, 0));
    assert_eq!(selection.source_entrypoint_hash(), expected_entrypoint);
    assert_eq!(selection.network_id(), source.pins().network_id);
}
