//! Native genesis authentication must precede selection from the same original source.

use super::*;
use crate::{
    block::builder::BlockBuilder,
    governance::anonymous_ballot::{
        BallotChoiceV1, CanonicalAnonymousBallotEnvelopeV1, test_fixtures::envelope,
    },
    sumeragi_finality::{GenesisReadError, authenticated_genesis},
};
use iroha_crypto::Signature;

#[test]
fn candidate_testing_native_reader_matches_independently_pinned_selection() {
    let block = signed(vec![candidate_instruction()]);
    let pinned = authenticate(&block);
    let network = pinned.pins().network_id;
    let expected = parliament_candidate_testing_from_genesis_v1(&pinned, &network)
        .unwrap()
        .unwrap();
    let (original, actual) =
        authenticate_parliament_candidate_genesis_v1(&block, &network).unwrap();
    let actual = actual.unwrap();
    assert_eq!(original.network_id(), network);
    assert_eq!(
        original.into_parts(),
        authenticated_genesis(&block).unwrap().into_parts()
    );
    assert_eq!(actual.network_id(), expected.network_id());
    assert_eq!(actual.policy(), expected.policy());
    assert_eq!(actual.source_position(), expected.source_position());
    assert_eq!(
        actual.source_entrypoint_hash(),
        expected.source_entrypoint_hash()
    );
    assert!(!super::super::super::parliament_ballot_qualified_v1());
}

#[test]
fn candidate_testing_native_reader_rejects_foreign_network_even_when_policy_is_absent() {
    let absent = signed(Vec::new());
    let selected = signed(vec![candidate_instruction()]);
    let absent_network = NetworkId::from_genesis_hash(absent.hash());
    let selected_network = NetworkId::from_genesis_hash(selected.hash());
    assert_ne!(absent_network, selected_network);
    for (source, expected) in [(&absent, selected_network), (&selected, absent_network)] {
        assert!(matches!(
            authenticate_parliament_candidate_genesis_v1(source, &expected),
            Err(ParliamentCandidateTestingErrorV1::ForeignNetwork)
        ));
    }
    assert!(
        authenticate_parliament_candidate_genesis_v1(&absent, &absent_network)
            .unwrap()
            .1
            .is_none()
    );
}

#[test]
fn candidate_testing_native_reader_rejects_changed_authorization_with_identical_intent() {
    let block = signed(vec![candidate_instruction()]);
    let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let foreign = KeyPair::from_seed(vec![0x94; 32], Algorithm::Ed25519);
    let original = block.external_transactions().next().unwrap();
    let builder = TransactionBuilder::from_genesis_payload(original.payload().clone()).unwrap();
    let signature =
        Signature::try_new(foreign.private_key(), &builder.payload_hash_bytes()).unwrap();
    let substituted = builder.build_with_signature(signature);
    assert_eq!(
        substituted.hash_as_entrypoint(),
        original.hash_as_entrypoint()
    );
    assert!(original.verify_signature().is_ok());
    assert!(substituted.verify_signature().is_err());
    let forged =
        SignedBlock::try_genesis(vec![substituted], authority.private_key(), None, None).unwrap();
    assert_eq!(
        forged.hash(),
        block.hash(),
        "intent identity excludes authorization proofs"
    );
    forged.validate_proposal_commitments().unwrap();
    forged
        .signatures()
        .next()
        .unwrap()
        .signature()
        .verify_hash(authority.public_key(), forged.hash())
        .unwrap();
    let network = NetworkId::from_genesis_hash(block.hash());
    assert!(authenticate_parliament_candidate_genesis_v1(&block, &network).is_ok());
    assert!(matches!(
        authenticate_parliament_candidate_genesis_v1(&forged, &network),
        Err(ParliamentCandidateTestingErrorV1::Genesis(
            GenesisReadError::Invalid(_)
        ))
    ));
}

#[test]
fn candidate_testing_native_reader_rejects_changed_block_signature_with_identical_header() {
    let block = signed(vec![candidate_instruction()]);
    let foreign = KeyPair::from_seed(vec![0x95; 32], Algorithm::Ed25519);
    let forged = SignedBlock::try_genesis(
        block.external_transactions().cloned().collect(),
        foreign.private_key(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(forged.header(), block.header());
    assert_eq!(forged.hash(), block.hash());
    forged.validate_proposal_commitments().unwrap();
    assert!(
        forged
            .external_transactions()
            .all(|tx| tx.verify_signature().is_ok())
    );
    let network = NetworkId::from_genesis_hash(block.hash());
    assert!(matches!(
        authenticate_parliament_candidate_genesis_v1(&forged, &network),
        Err(ParliamentCandidateTestingErrorV1::Genesis(
            GenesisReadError::Invalid(_)
        ))
    ));
}

#[test]
fn candidate_testing_native_reader_rejects_nonexternal_genesis_inputs() {
    let block = signed(vec![candidate_instruction()]);
    let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = BlockBuilder::new(block.header());
    for transaction in block.external_transactions() {
        builder.push_transaction(transaction.clone());
    }
    builder.set_da_proof_policies(block.da_proof_policies().cloned());
    builder.push_anonymous_ballot(
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(BallotChoiceV1::Aye, 1))
            .unwrap(),
    );
    let mixed = builder.build_with_signature(0, authority.private_key());
    mixed.validate_proposal_commitments().unwrap();
    let network = NetworkId::from_genesis_hash(mixed.hash());
    assert!(matches!(
        authenticate_parliament_candidate_genesis_v1(&mixed, &network),
        Err(ParliamentCandidateTestingErrorV1::NonInstructionGenesis)
    ));
}

#[test]
fn candidate_testing_native_reader_preserves_original_genesis_json_refusal_and_retry() {
    let block = signed(vec![candidate_instruction()]);
    let original_wire = block.encode_wire().unwrap();
    let network = NetworkId::from_genesis_hash(block.hash());
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let error = norito::with_decode_limits_scope(limits, || {
        authenticate_parliament_candidate_genesis_v1(&block, &network)
    })
    .unwrap_err();
    assert!(
        matches!(
            &error,
            ParliamentCandidateTestingErrorV1::Genesis(GenesisReadError::Json(
                norito::json::Error::DecodeResource(_)
            ))
        ),
        "{error:?}"
    );
    assert_eq!(block.encode_wire().unwrap(), original_wire);
    assert!(
        authenticate_parliament_candidate_genesis_v1(&block, &network)
            .unwrap()
            .1
            .is_some()
    );
}

#[test]
fn candidate_testing_native_reader_refuses_duplicate_policy_after_genuine_authentication() {
    let block = signed(vec![candidate_instruction(), candidate_instruction()]);
    let network = NetworkId::from_genesis_hash(block.hash());
    authenticated_genesis(&block).unwrap();
    assert!(matches!(
        authenticate_parliament_candidate_genesis_v1(&block, &network),
        Err(ParliamentCandidateTestingErrorV1::DuplicatePolicy)
    ));
}

#[test]
fn candidate_testing_native_reader_preserves_invalid_signed_policy_error() {
    let block = signed(vec![instruction(unchecked_parameter(
        ParliamentCandidateTestingPolicyV1 {
            version: 2,
            ..ParliamentCandidateTestingPolicyV1::CANDIDATE_V1
        },
    ))]);
    let network = NetworkId::from_genesis_hash(block.hash());
    authenticated_genesis(&block).unwrap();
    assert!(matches!(
        authenticate_parliament_candidate_genesis_v1(&block, &network),
        Err(ParliamentCandidateTestingErrorV1::Version { actual: 2 })
    ));
}
