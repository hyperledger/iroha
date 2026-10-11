//! Genuine native complete-effect handoff, original allocation and hostile offered-wire controls.
use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use iroha_crypto::Hash;
use iroha_data_model::{block::SharedSignedBlock, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

fn original_source() -> (CertifiedTestChain, FinalizedFastpqSource, usize, Vec<u8>) {
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "finalized_job".parse().unwrap());
    let definition = AssetDefinition::new(
        definition_id.clone(),
        "finalized job".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let source = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let destination = AssetId::new(definition_id, BOB_ID.clone());
    let world = World::with_assets(
        [domain],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [definition],
        [
            Asset::new(source.clone(), Quantity::from(60_u32)),
            Asset::new(destination, Quantity::from(10_u32)),
        ],
        [],
    );
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
    let created_ms = chain.committed(1).block_time_ms();
    let transactions = [3_u32, 5]
        .into_iter()
        .map(|amount| {
            chain.sign(
                &ALICE_KEYPAIR,
                [Transfer::asset_quantity(source.clone(), amount, BOB_ID.clone()).into()],
                created_ms,
            )
        })
        .collect();
    let proposal = chain.proposal(None, transactions);
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();

    // Only observation escapes before publication; the protected wire never clones
    // into a job and both unpublished and prepared states refuse the real handoff.
    assert!(pending.take_finalized_fastpq_source().is_err());
    let (bundles, bytes) = pending
        .inspect(|execution| {
            assert!(execution.block.as_ref().failed_outputs().next().is_none());
            assert_eq!(execution.witness.fastpq_transcripts.len(), 2);
            (
                execution.witness.fastpq_transcripts.as_ptr() as usize,
                norito::encode_canonical(&execution.witness.fastpq_transcripts).unwrap(),
            )
        })
        .unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    assert!(pending.take_finalized_fastpq_source().is_err());
    pending.publish(Signers::Quorum).unwrap();
    let source = pending.take_finalized_fastpq_source().unwrap();
    assert!(
        pending.take_finalized_fastpq_source().is_err(),
        "original source moves once"
    );
    assert!(
        pending.publish(Signers::Quorum).is_ok(),
        "source handoff does not repeat or disable publication"
    );
    drop(pending);
    assert_eq!(chain.height(), 2);
    (chain, source, bundles, bytes)
}
fn authority(chain: &CertifiedTestChain, height: u64) -> AuthenticatedExecutionBlock {
    let view = chain.state().view();
    CertifiedChain::new(&view)
        .unwrap()
        .authenticated_execution(height)
        .unwrap()
}

#[test]
fn native_source_join_retains_original_block_and_witness_allocations() {
    let (_chain, joined, bundles, bytes) = original_source();
    let FinalizedFastpqSource { native, witness } = joined;
    let original_block = native.block().clone();
    let joined = FinalizedFastpqSource::bind(witness, native).unwrap();
    // Canonical history retains the original same shared block graph; the witness
    // and charged source graph are the actual Worker allocations that produced R.
    assert!(SharedSignedBlock::ptr_eq(
        joined.native().block(),
        &original_block
    ));
    assert_eq!(
        joined.witness.wire().fastpq_transcripts.as_ptr() as usize,
        bundles
    );
    assert_eq!(
        norito::encode_canonical(&joined.witness.wire().fastpq_transcripts).unwrap(),
        bytes
    );
    assert_eq!(joined.native().committed().height(), 2);
    assert_eq!(joined.entries().len(), 2);
    assert_eq!(joined.leaves().len(), 2);
    assert_eq!(joined.manifest().executed_entry_count, 2);
    assert_eq!(joined.manifest().statement_count, 2);
    assert_eq!(
        joined.manifest().coverage,
        iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Complete
    );
    let count = crate::fastpq::quantity_materializer_invocations_for_testing();
    let reserved = joined.pool().reserved_bytes();
    for (index, leaf) in joined.leaves().iter().enumerate() {
        let first = joined.entry(index).unwrap();
        let second = joined.entry(index).unwrap();
        assert!(std::ptr::eq(first.effects(), second.effects()));
        assert!(std::ptr::eq(first.leaf(), leaf));
        assert_eq!(first.effects().effects.len(), 1);
        assert_eq!(
            <[u8; 32]>::from(
                iroha_data_model::fastpq::execution_effects_digest_v1(first.effects()).unwrap()
            ),
            leaf.effects_digest
        );
        assert!(std::ptr::eq(first.pool(), joined.pool()));
    }
    assert!(joined.entry(2).is_err());
    assert_eq!(
        joined.pool().reserved_bytes(),
        reserved,
        "borrowed selection performs no work admission"
    );
    assert_eq!(
        crate::fastpq::quantity_materializer_invocations_for_testing(),
        count
    );
}

#[test]
fn native_source_join_rejects_other_height_or_certified_block_identity() {
    let (mut chain, joined, _, _) = original_source();
    let (_, other, _, _) = original_source();
    chain.commit(Vec::new());
    for wrong in [authority(&chain, 1), authority(&chain, 3)] {
        assert_eq!(
            joined.witness.verify_finalized_source(&wrong),
            Err(FinalizedFastpqSourceError::BlockIdentity)
        );
    }
    // Equal-looking work from another authentic genesis is still independent
    // authority; fixture genesis may be deterministic, so force later native work.
    assert!(
        other
            .witness
            .verify_finalized_source(&authority(&chain, 3))
            .is_err()
    );
    assert!(
        joined
            .witness
            .verify_finalized_source(&authority(&chain, 2))
            .is_ok()
    );
}

#[test]
fn native_source_join_rejects_complete_inventory_substitution() {
    let (_, mut joined, _, _) = original_source();
    for mutation in 0..5 {
        joined
            .witness
            .offer_reconstructed_tamper_for_test(|offered| {
                let bundles = &mut offered.fastpq_transcripts;
                match mutation {
                    0 => {
                        bundles.pop();
                    }
                    1 => bundles.push(bundles[0].clone()),
                    2 => bundles.reverse(),
                    3 => bundles[1] = bundles[0].clone(),
                    4 => bundles[1].entry_hash = Hash::new(b"unrelated execution call"),
                    _ => unreachable!(),
                }
            });
        let count = crate::fastpq::quantity_materializer_invocations_for_testing();
        assert!(
            joined
                .witness
                .verify_finalized_source(&joined.native)
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            crate::fastpq::quantity_materializer_invocations_for_testing(),
            count
        );
    }
    joined.witness.offer_reconstructed_tamper_for_test(|_| {});
    assert!(
        joined
            .witness
            .verify_finalized_source(&joined.native)
            .is_ok()
    );
}

#[test]
fn native_source_join_rejects_public_occurrence_and_private_path_changes() {
    let (_, mut joined, _, _) = original_source();
    for mutation in 0..16 {
        joined
            .witness
            .offer_reconstructed_tamper_for_test(|offered| {
                let transcripts = &mut offered.fastpq_transcripts[0].transcripts;
                if mutation == 0 {
                    transcripts.push(transcripts[0].clone());
                } else if mutation == 1 {
                    transcripts.clear();
                } else {
                    let transcript = &mut transcripts[0];
                    let delta = &mut transcript.deltas[0];
                    match mutation {
                        2 => transcript.batch_hash = Hash::new(b"other source"),
                        3 => transcript.authority_digest = Hash::new(b"other authority"),
                        4 => transcript.poseidon_preimage_digest = None,
                        5 => delta.amount = Quantity::from(99_u32),
                        6 => delta.from_balance_before = Quantity::from(999_u32),
                        7 => delta.from_balance_after = Quantity::from(999_u32),
                        8 => delta.to_balance_before = Quantity::from(999_u32),
                        9 => delta.to_balance_after = Quantity::from(999_u32),
                        10 => delta.from_account = BOB_ID.clone(),
                        11 => delta.to_account = ALICE_ID.clone(),
                        12 => delta.from_smt_witness.root_before[0] ^= 1,
                        13 => delta.to_smt_witness.root_after[0] ^= 1,
                        14 => delta.from_smt_witness.path_bits.push(1),
                        15 => delta.to_smt_witness.siblings.push([1; 32]),
                        _ => unreachable!(),
                    }
                }
            });
        let count = crate::fastpq::quantity_materializer_invocations_for_testing();
        assert!(
            joined
                .witness
                .verify_finalized_source(&joined.native)
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            crate::fastpq::quantity_materializer_invocations_for_testing(),
            count
        );
    }
}

#[test]
fn later_valid_certificate_cannot_rebind_an_earlier_complete_effect_source() {
    let (mut chain, joined, _, _) = original_source();
    chain.commit(Vec::new());
    let later = authority(&chain, 3);
    assert!(later.block().fastpq_transcripts().is_empty());
    assert_eq!(
        joined.witness.verify_finalized_source(&later),
        Err(FinalizedFastpqSourceError::BlockIdentity)
    );
}

#[test]
fn protected_d7_and_ordinary_writes_remain_bound_after_native_result() {
    // Keep the original State and its query-store owners alive while observing
    // their shared pool. Teardown can otherwise refund unrelated live custody
    // during this synchronous offered-wire check.
    let (_chain, mut joined, _, _) = original_source();
    let original_pool = joined.pool().clone();
    let reserved = original_pool.reserved_bytes();
    for mutation in 0..4 {
        joined.witness.offer_reconstructed_tamper_for_test(|offered| {
            let key = iroha_data_model::execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1;
            let index = offered.writes.iter().position(|write| write.key == key).unwrap();
            match mutation {
                0 => { offered.writes.remove(index); }
                1 => offered.writes[index].value.push(0),
                2 => offered.writes[index].key.push(0),
                3 => offered.writes.iter_mut().find(|write| write.key != key).unwrap().value.push(0),
                _ => unreachable!(),
            }
        });
        assert!(
            joined
                .witness
                .verify_finalized_source(&joined.native)
                .is_err()
        );
        assert_eq!(
            original_pool.reserved_bytes(),
            reserved,
            "offered test clone never changes original credit"
        );
    }
}

#[test]
fn genuinely_finalized_empty_effect_source_has_an_authenticated_zero_statement_census() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let proposal = chain.proposal(None, Vec::new());
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    pending.publish(Signers::Quorum).unwrap();
    let joined = pending.take_finalized_fastpq_source().unwrap();
    assert_eq!(
        joined.entries().len(),
        1,
        "actual signed clock work remains in the complete source"
    );
    assert_eq!(joined.manifest().executed_entry_count, 1);
    assert_eq!(joined.manifest().statement_count, 0);
    assert!(joined.leaves().is_empty());
    assert!(joined.entry(0).is_err());
    assert!(joined.entry(usize::MAX).is_err());
    assert_eq!(
        joined.manifest().coverage,
        iroha_data_model::fastpq::FastpqSourceEffectCoverageV1::Complete
    );
    assert!(
        joined
            .witness
            .verify_finalized_source(joined.native())
            .is_ok()
    );
}
