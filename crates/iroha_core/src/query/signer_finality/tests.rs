//! Native State/Kura association over a real certified chain: a four-validator committee with
//! real BLS signatures certifies every block (`sumeragi::test_chain`).

use std::sync::Arc;

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{NetworkId, block::BlockHeader};

use super::{SignerFinalityErrorV1, verify_signer_finality_v1};
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
    sumeragi::{
        certified_chain::committed_block,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};

fn chain() -> CertifiedTestChain {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).expect("chain");
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}

fn hash(chain: &CertifiedTestChain, height: u64) -> [u8; 32] {
    *chain.committed(height).block_hash().as_ref()
}

#[test]
fn invalid_or_absent_coordinates_fail_closed() {
    let chain = chain();
    let view = chain.state().view();
    for (height, hash) in [
        (0, hash(&chain, 1)),
        (2, [0; 32]),
        (2, [1; 32]),
        (4, hash(&chain, 3)),
        (u64::MAX, [1; 32]),
    ] {
        assert!(
            matches!(verify_signer_finality_v1(&view, height, hash), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                SignerFinalityErrorV1
            ))
        );
    }
    assert_eq!(
        SignerFinalityErrorV1.to_string(),
        "signer finality is unavailable for the exact native block"
    );
}

#[test]
fn every_certified_height_is_final_with_its_certified_block_id() {
    let chain = chain();
    let view = chain.state().view();
    for height in 1..=3 {
        let verified = verify_signer_finality_v1(&view, height, hash(&chain, height))
            .expect("certified block");
        assert_eq!(verified.height(), height);
        assert_eq!(verified.block_hash(), hash(&chain, height));
        assert_eq!(verified.context_id(), chain.committed(height).id());
    }
    // Another height's hash is not this height's block.
    assert!(
        matches!(verify_signer_finality_v1(&view, 2, hash(&chain, 3)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}

#[test]
fn native_hash_cache_without_a_durable_block_is_not_finality() {
    let chain = chain();
    let mut state = State::new_with_chain_and_network_id_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        chain.network_id(),
    );
    state.push_block_hash_for_testing(chain.genesis().hash());
    assert!(
        matches!(verify_signer_finality_v1(&state.view(), 1, hash(&chain, 1)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}

#[test]
fn durable_certificate_cannot_substitute_for_the_same_state_history() {
    let chain = chain();
    // The same Kura behind a State whose journal names another block at height 2.
    let mut other = State::new_with_chain_and_network_id_for_testing(
        World::default(),
        Arc::clone(chain.kura()),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        chain.network_id(),
    );
    other.push_block_hash_for_testing(chain.genesis().hash());
    let foreign = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"other native view"));
    other.push_block_hash_for_testing(foreign);
    // Shared signed genesis identity is insufficient: this view has no authenticated
    // successor anchoring the genesis execution result.
    assert!(
        matches!(verify_signer_finality_v1(&other.view(), 1, hash(&chain, 1)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
    assert!(
        matches!(verify_signer_finality_v1(&other.view(), 2, hash(&chain, 2)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
    assert!(
        matches!(verify_signer_finality_v1(&other.view(), 2, *foreign.as_ref()), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}

#[test]
fn identical_blocks_and_certificates_cannot_authorize_a_foreign_state_network() {
    let chain = chain();
    let foreign_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different State network with identical retained blocks and certificates",
    )));
    // The same frames, certificates included, in the Kura of a State of another network.
    let kura = Kura::blank_kura_for_testing();
    let mut foreign = State::new_with_chain_and_network_id_for_testing(
        World::default(),
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        "sumeragi-certified-test-chain".parse().unwrap(),
        foreign_network,
    );
    for height in 1..=3 {
        let block = chain.committed(height).block().clone();
        assert!(block.commit_certificate().is_some());
        kura.store_block(block.clone()).unwrap();
        foreign.push_block_hash_for_testing(block.hash());
    }
    assert!(
        foreign
            .view()
            .block_hashes()
            .iter()
            .eq(chain.state().view().block_hashes().iter()),
        "both States retain the same ordered block history"
    );
    for height in 1..=3 {
        assert!(
            matches!(verify_signer_finality_v1(&foreign.view(), height, hash(&chain, height)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                SignerFinalityErrorV1
            ))
        );
    }
}

/// A genuinely committed block whose local QC is subsequently corrupted is not signer-final;
/// its original native execution remains authoritative for deterministic State reads.
#[test]
fn an_invalid_local_certificate_is_not_signer_finality() {
    let mut chain = chain();
    chain.commit_at(4_000, Vec::new());
    chain.corrupt_local_quorum_for_test(4, Signers::BelowQuorum);
    let view = chain.state().view();
    assert!(
        matches!(verify_signer_finality_v1(&view, 4, hash(&chain, 4)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
    verify_signer_finality_v1(&view, 3, hash(&chain, 3)).expect("earlier heights stay final");
    let committed = committed_block(&view, 4).expect("committed");
    assert_eq!(*committed.block_hash().as_ref(), hash(&chain, 4));
}

#[test]
fn original_genesis_without_a_successor_has_execution_but_no_signer_finality() {
    use crate::sumeragi::certified_chain::{CertifiedChain, QcVerification};

    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original executed genesis");
    let view = chain.state().view();
    assert_eq!(chain.state().committed_height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
    assert!(committed_block(&view, 1).is_ok());
    let reader = CertifiedChain::new(&view).unwrap();
    assert_eq!(
        reader.certified(1).unwrap().verification(),
        QcVerification::Genesis
    );
    assert!(super::certified_block_v1(&reader, 1, hash(&chain, 1)).is_err());
    assert!(
        matches!(verify_signer_finality_v1(&view, 1, hash(&chain, 1)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}

#[test]
fn genesis_execution_finality_requires_a_verified_successor() {
    use crate::sumeragi::certified_chain::{CertifiedChain, QcVerification};

    for (has_successor, changed_result, bad_successor) in [
        (false, false, false),
        (false, true, false),
        (true, true, false),
        (true, false, true),
    ] {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("original native genesis execution");
        let genesis = chain.committed(1).block().clone();
        if has_successor {
            chain.commit_at(2_000, Vec::new());
            verify_signer_finality_v1(&chain.state().view(), 1, hash(&chain, 1)).expect(
                "exact original successor authenticates the genesis result before corruption",
            );
        }
        if changed_result {
            let original = genesis.commit_certificate().unwrap();
            let (original_x, mut preimage) =
                iroha_data_model::sumeragi_finality::CertifiedResultV1::decode(
                    original.result_preimage(),
                    chain.root_scope().into(),
                )
                .unwrap()
                .into_parts();
            preimage.execution.world_state_root = Hash::new(b"unsigned replacement genesis result");
            preimage.validate().expect(
                "the forged World root preserves result shape and the native-lane proof; only authenticated R rejects it",
            );
            chain
                .kura()
                .corrupt_commit_result_for_testing(
                    std::num::NonZeroUsize::new(1).unwrap(),
                    iroha_data_model::sumeragi_finality::CertifiedResultV1::from_parts_unvalidated(
                        original_x, preimage,
                    )
                    .preimage()
                    .unwrap(),
                )
                .expect("change only the unsigned local result after genuine publication");
            let changed = chain
                .kura()
                .get_block(
                    std::num::NonZeroUsize::new(1).unwrap(),
                    &chain.state().ivm_execution_budget(),
                )
                .expect("changed canonical history read completes")
                .expect("changed genesis is retained");
            assert_eq!(changed.hash(), genesis.hash());
            assert_eq!(
                changed.signatures().collect::<Vec<_>>(),
                genesis.signatures().collect::<Vec<_>>()
            );
            assert_eq!(
                changed.executed_block_wire_identity().unwrap(),
                genesis.executed_block_wire_identity().unwrap()
            );
            let certificate = changed.commit_certificate().unwrap();
            assert_eq!(certificate.consensus_header(), original.consensus_header());
            assert_eq!(certificate.commit_qc(), original.commit_qc());
            assert_eq!(certificate.availability(), original.availability());
            assert_ne!(certificate.result_preimage(), original.result_preimage());
        }
        if bad_successor {
            chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        }
        let view = chain.state().view();
        // State's original tip authenticates R even when the proposal hash is unchanged.
        // A replaced local result fails that native ancestry check before any signer use.
        let native_read = committed_block(&view, 1);
        if changed_result {
            assert!(
                matches!(&native_read, Err(crate::execution_attempt::ExecutionAttemptError::Rejected(crate::sumeragi::certified_chain::ChainReadError::Malformed { height: 1, reason }))
                    if reason.contains("native header or R differs from authenticated execution ancestry at 1")),
                "substituted result must fail its original State ancestry: {native_read:?}"
            );
        } else {
            native_read.expect("unchanged original execution survives absent or invalid local QC");
        }
        let reader = CertifiedChain::new(&view).unwrap();
        assert_eq!(
            reader.certified(1).unwrap().verification(),
            QcVerification::Genesis
        );
        assert!(super::certified_block_v1(&reader, 1, *genesis.hash().as_ref()).is_err());
        assert!(
            matches!(verify_signer_finality_v1(&view, 1, *genesis.hash().as_ref()), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
                SignerFinalityErrorV1
            ))
        );
    }
    let chain = chain();
    let view = chain.state().view();
    let verified = verify_signer_finality_v1(&view, 1, hash(&chain, 1)).unwrap();
    assert_eq!(verified.context_id(), chain.committed(1).id());
}

#[test]
fn genesis_result_rejects_a_substituted_native_lane_witness_root() {
    use crate::sumeragi::certified_chain::{CertifiedChain, ChainReadError};

    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original native genesis execution");
    let original = chain.committed(1).block().clone();
    let (original_x, mut preimage) =
        iroha_data_model::sumeragi_finality::CertifiedResultV1::decode(
            original.commit_certificate().unwrap().result_preimage(),
            chain.root_scope().into(),
        )
        .unwrap()
        .into_parts();
    preimage.execution.ordinary_writes_root = Hash::new(b"substituted native lane witness root");
    assert_eq!(
        preimage.validate().unwrap_err().to_string(),
        "invalid native context proof"
    );
    chain
        .kura()
        .corrupt_commit_result_for_testing(
            std::num::NonZeroUsize::new(1).unwrap(),
            iroha_data_model::sumeragi_finality::CertifiedResultV1::from_parts_unvalidated(
                original_x, preimage,
            )
            .preimage()
            .unwrap(),
        )
        .unwrap();
    let view = chain.state().view();
    assert!(matches!(committed_block(&view, 1),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(ChainReadError::Malformed { height: 1, reason }))
            if reason.contains("invalid native context proof")));
    assert!(matches!(CertifiedChain::new(&view).unwrap().certified(1),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(ChainReadError::Malformed { height: 1, reason }))
            if reason.contains("invalid native context proof")));
    assert!(
        matches!(verify_signer_finality_v1(&view, 1, *original.hash().as_ref()), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}

#[test]
fn imported_genesis_frame_and_hash_journal_cannot_replace_original_execution() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original native genesis");
    let genesis = chain.committed(1).block().clone();
    let kura = Kura::blank_kura_for_testing();
    let mut state = State::new_with_chain_and_network_id_for_testing(
        World::new(),
        std::sync::Arc::clone(&kura),
        LiveQueryStore::start_test(),
        chain.state().chain_id_ref().clone(),
        chain.network_id(),
    );
    kura.store_block(genesis.clone()).unwrap();
    state.push_block_hash_for_testing(genesis.hash());
    let view = state.view();
    assert!(committed_block(&view, 1).is_err());
    assert!(
        matches!(verify_signer_finality_v1(&view, 1, hash(&chain, 1)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            SignerFinalityErrorV1
        ))
    );
}
