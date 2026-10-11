//! Exact joins between independently verified native receipts; fixture results are synthetic.

use super::{test_fixtures::NativeFinalityFixture, tests::Fixture, *};
use crate::{
    account::AccountId,
    block::{BlockSignatures, builder::BlockBuilder, output_test_support},
    isi::Log,
    level::Level,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_crypto::KeyPair;
use std::{num::NonZeroU64, time::Duration};

fn fixture_successor(fixture: &Fixture) -> SumeragiFinalityProof {
    let parent = fixture.second.decode_checked().unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(3).unwrap(),
        Some(parent.block.hash()),
        None,
        parent.block.header().creation_time_ms + 1,
        0,
    );
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut transaction = TransactionBuilder::new(
        fixture.network,
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let transaction = transaction
        .with_instructions([Log::new(Level::INFO, "successor join work".into())])
        .sign(signer.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    output_test_support::install_network(&mut block, vec![Ok(Vec::new())]).unwrap();
    let result = tests::result(&block, &parent.commitment.schedule.current);
    tests::certify_successor(
        &fixture.keys,
        &fixture.validators,
        fixture.verifier().instance(),
        &parent,
        block,
        &result,
    )
}

#[test]
fn immediate_global_successor_joins_alternate_original_quorum_witnesses() {
    let fixture = Fixture::new();
    let child_proof = fixture_successor(&fixture);
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    let parent = verifier.verify(&fixture.second).unwrap();
    let alternate_proof = fixture.alternate();
    let alternate = verifier
        .verify_same_decision(&fixture.second, &alternate_proof)
        .unwrap();
    let child = verifier.verify(&child_proof).unwrap();
    assert_ne!(fixture.second.block_wire, alternate_proof.block_wire);
    assert_eq!(parent.core_hash(), alternate.core_hash());
    assert_eq!(parent.result(), alternate.result());
    for original in [&parent, &alternate] {
        child
            .verify_immediate_global_successor_of(
                original,
                fixture.network,
                "portable-finality-test",
            )
            .unwrap();
    }
    // The join does not deserialize or reauthenticate a witness under a new budget.
    let limits = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    norito::core::with_decode_limits_scope(limits, || {
        child.verify_immediate_global_successor_of(
            &parent,
            fixture.network,
            "portable-finality-test",
        )
    })
    .unwrap();
}

#[test]
fn immediate_global_successor_binds_same_proposal_parent_execution_result() {
    let mut first = NativeFinalityFixture::start("same-proposal-native-parent");
    let mut other = first.clone();
    let original = first.block_with_submitted_work(first.next_header());
    let first_parent_proof =
        first.certify_with_world_root(original.clone(), Hash::new(b"first complete World"));
    let other_parent_proof =
        other.certify_with_world_root(original, Hash::new(b"other complete World"));
    let first_parent = first
        .verifier()
        .verify_retained_decision(&first_parent_proof)
        .unwrap();
    let other_parent = other
        .verifier()
        .verify_retained_decision(&other_parent_proof)
        .unwrap();
    assert_eq!(first_parent.header().hash(), other_parent.header().hash());
    assert_eq!(first_parent.core_hash(), other_parent.core_hash());
    assert_ne!(first_parent.result(), other_parent.result());
    let block = first.block_with_submitted_work(first.next_header());
    let child_proof = first.certify(block);
    let child = first
        .verifier()
        .verify_retained_decision(&child_proof)
        .unwrap();
    child
        .verify_immediate_global_successor_of(&first_parent, first.network_id(), first.chain_id())
        .unwrap();
    assert!(
        child
            .verify_immediate_global_successor_of(
                &other_parent,
                first.network_id(),
                first.chain_id(),
            )
            .is_err()
    );
    assert!(other.verifier().verify(&child_proof).is_err());
    let block = other.block_with_submitted_work(other.next_header());
    let other_child_proof = other.certify(block);
    let other_child = other
        .verifier()
        .verify_retained_decision(&other_child_proof)
        .unwrap();
    other_child
        .verify_immediate_global_successor_of(&other_parent, other.network_id(), other.chain_id())
        .unwrap();
    assert_eq!(child.header().hash(), other_child.header().hash());
    assert_ne!(child.core_hash(), other_child.core_hash());
}

#[test]
fn immediate_global_successor_preserves_boundary_and_next_epoch_authority() {
    let (fixture, proofs) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let verifier = fixture.verifier();
    let previous = verifier.verify_retained_decision(&proofs[1]).unwrap();
    let boundary = verifier.verify_retained_decision(&proofs[2]).unwrap();
    let next = verifier.verify_retained_decision(&proofs[3]).unwrap();
    assert!(boundary.commitment().schedule.boundary.is_some());
    assert!(matches!(
        previous.commitment().schedule.after_next,
        ScheduledSlot::PendingBoundary { .. }
    ));
    assert_ne!(
        boundary.commitment().schedule.current.authorization.epoch,
        next.commitment().schedule.current.authorization.epoch
    );
    for (child, parent) in [(&boundary, &previous), (&next, &boundary)] {
        child
            .verify_immediate_global_successor_of(parent, fixture.network_id(), fixture.chain_id())
            .unwrap();
    }
}

#[test]
fn immediate_global_successor_rejects_foreign_roots_labels_heights_and_genesis() {
    let mut fixture = NativeFinalityFixture::new();
    let original_proof = fixture.latest().clone();
    let parent = fixture
        .verifier()
        .verify_retained_decision(&original_proof)
        .unwrap();
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let child_proof = fixture.certify(block);
    let child = fixture
        .verifier()
        .verify_retained_decision(&child_proof)
        .unwrap();
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let later_proof = fixture.certify(block);
    let later = fixture
        .verifier()
        .verify_retained_decision(&later_proof)
        .unwrap();
    let foreign_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign successor network",
    )));
    for chain in ["", "another-selected-chain", "control\nchain"] {
        assert!(
            child
                .verify_immediate_global_successor_of(&parent, fixture.network_id(), chain)
                .is_err()
        );
    }
    assert!(
        child
            .verify_immediate_global_successor_of(&parent, foreign_network, fixture.chain_id())
            .is_err()
    );
    for (bad_child, bad_parent) in [(&later, &parent), (&parent, &child), (&parent, &parent)] {
        assert!(
            bad_child
                .verify_immediate_global_successor_of(
                    bad_parent,
                    fixture.network_id(),
                    fixture.chain_id(),
                )
                .is_err()
        );
    }
    let genesis = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    assert!(
        parent
            .verify_immediate_global_successor_of(
                &genesis,
                fixture.network_id(),
                fixture.chain_id(),
            )
            .is_err()
    );
    let root = crate::block::consensus::SumeragiRootScope::Dataspace {
        parent_network_id: fixture.network_id(),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(800),
    };
    let mut private = NativeFinalityFixture::start_with_scope("private-successor-join", root);
    let block = private.block_with_submitted_work(private.next_header());
    let private_parent_proof = private.certify(block);
    let private_parent = private
        .verifier()
        .verify_retained_decision(&private_parent_proof)
        .unwrap();
    let block = private.block_with_submitted_work(private.next_header());
    let private_child_proof = private.certify(block);
    let private_child = private
        .verifier()
        .verify_retained_decision(&private_child_proof)
        .unwrap();
    assert!(
        private_child
            .verify_immediate_global_successor_of(
                &private_parent,
                private.network_id(),
                private.chain_id(),
            )
            .is_err()
    );
}
