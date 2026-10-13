//! Genuine native carrier verification, genesis anchoring and interval refusal.

use super::*;
use crate::state::{StateReadOnly, World};
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
use std::num::NonZeroUsize;

fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}
fn frame(chain: &CertifiedTestChain, height: usize) -> iroha_data_model::block::SharedSignedBlock {
    chain
        .kura()
        .get_block(
            NonZeroUsize::new(height).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original State carrier read")
        .expect("stored carrier")
}
fn projection(chain: &CertifiedTestChain, block: &SignedBlock) -> Vec<u8> {
    let archive = crate::query::native_context_archive::NativeContextArchive::open(
        chain.kura(),
        chain.state().ivm_execution_budget(),
        chain.kura().native_context_archive_max_bytes(),
    )
    .unwrap();
    archive
        .read_exact(block.header().height().get(), block.hash())
        .unwrap()
        .as_slice()
        .to_vec()
}

fn reader(chain: &CertifiedTestChain) -> NativeExecutionEvidenceVerifier {
    NativeExecutionEvidenceVerifier::new(
        ChainId::from("sumeragi-certified-test-chain"),
        chain.network_id(),
        NativeExecutionEvidenceLimits {
            max_carriers: 3,
            max_carrier_bytes: 16 * 1024 * 1024,
            max_context_bytes: 1024 * 1024,
            max_retained_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap()
}

#[test]
fn only_actual_native_successor_authenticates_genesis_execution_and_empty_contexts() {
    let chain = chain();
    let mut reader = reader(&chain);
    let genesis = frame(&chain, 1);
    assert!(
        reader
            .push_height(genesis.clone(), &projection(&chain, &genesis))
            .unwrap()
            .is_none()
    );
    assert_eq!(reader.authenticated_carriers, 0);
    assert!(reader.lanes.is_none());
    assert!(reader.pending_genesis.is_some());
    for height in 2..=3 {
        let block = frame(&chain, height);
        let expected = block.hash();
        let mut verified = reader
            .push_height(block.clone(), &projection(&chain, &block))
            .unwrap()
            .unwrap();
        assert_eq!(verified.block().hash(), expected);
        assert_eq!(
            verified.ordinary_writes_root(),
            chain
                .committed(u64::try_from(height).unwrap())
                .commitment()
                .execution
                .ordinary_writes_root
        );
        assert!(verified.lanes().lanes.is_empty());
        assert_eq!(
            verified.matches_original_tip(chain.state().view().native_execution_tip().unwrap()),
            height == 3
        );
        if height == 3 {
            let tip = chain.state().view().native_execution_tip().unwrap();
            let core_hash = verified.core_hash;
            verified.core_hash = iroha_sumeragi::types::Hash32([0x81; 32]);
            assert!(
                !verified.matches_original_tip(tip),
                "same Iroha carrier cannot replace native core identity"
            );
            verified.core_hash = core_hash;
            verified.result = iroha_sumeragi::types::Hash32([0x82; 32]);
            assert!(
                !verified.matches_original_tip(tip),
                "same Iroha carrier cannot replace original execution result"
            );
        }
    }
    assert!(reader.pending_genesis.is_none());
    assert_eq!(reader.authenticated_carriers, 3);
}

#[test]
fn wrong_projection_carrier_and_skipped_successor_poison_the_exact_interval() {
    let chain = chain();
    let genesis = frame(&chain, 1);
    let next = frame(&chain, 2);
    let later = frame(&chain, 3);
    for false_projection in [true, false] {
        let mut reader = reader(&chain);
        reader
            .push_height(genesis.clone(), &projection(&chain, &genesis))
            .unwrap();
        let error = if false_projection {
            reader.push_height(next.clone(), &projection(&chain, &later))
        } else {
            reader.push_height(later.clone(), &projection(&chain, &later))
        };
        assert!(error.is_err());
        assert!(
            reader.authenticated_carriers == 0,
            "no unauthenticated genesis capability escapes"
        );
        assert!(
            reader
                .push_height(next.clone(), &projection(&chain, &next))
                .is_err()
        );
    }
}

#[test]
fn canonical_projection_limit_is_checked_before_decode_or_native_progress() {
    let chain = chain();
    let genesis = frame(&chain, 1);
    let bytes = projection(&chain, &genesis);
    let mut reader = reader(&chain);
    reader.limits.max_context_bytes = (bytes.len() - 1) as u64;
    assert!(reader.push_height(genesis, &bytes).is_err());
    assert!(reader.finality.is_none());
    assert_eq!(reader.retained_bytes, 0);
}

#[test]
fn live_reader_reuses_original_archived_contexts_through_actual_native_tip() {
    let chain = chain();
    let current = chain
        .state()
        .verified_sumeragi_lane_state()
        .unwrap()
        .unwrap();
    assert!(current.lanes().lanes.is_empty());
    assert_eq!(current.height(), 3);
    assert!(current.is_current(chain.state()));
    let opening = frame(&chain, 2);
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            2,
            hex::encode(opening.hash().as_ref()),
        ));
    let original = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let archive = crate::query::native_context_archive::NativeContextArchive::open_existing(
        chain.kura(),
        chain.state().ivm_execution_budget(),
        chain.kura().native_context_archive_max_bytes(),
    )
    .unwrap();
    let missing_source = archive
        .read_exact(2, opening.hash())
        .err()
        .expect("the exact height-2 original archive record is missing");
    assert!(matches!(
        &missing_source,
        crate::query::native_context_archive::NativeContextArchiveError::Io(error)
            if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert_eq!(
        chain.state().verified_sumeragi_lane_state().unwrap_err(),
        crate::execution_attempt::ExecutionAttemptError::Rejected(format!(
            "required historical native lane state source 2: {missing_source}"
        )),
        "the live reader must propagate the original missing-record refusal"
    );
    std::fs::write(&path, &original).unwrap();
    assert!(
        chain
            .state()
            .verified_sumeragi_lane_state()
            .unwrap()
            .is_some()
    );
    let mut foreign: NativeExecutionProjectionV1 = norito::decode_canonical(&original).unwrap();
    foreign.carrier_hash = frame(&chain, 3).hash();
    std::fs::write(&path, norito::encode_canonical(&foreign).unwrap()).unwrap();
    assert!(matches!(
        chain.state().verified_sumeragi_lane_state().unwrap_err(),
        crate::execution_attempt::ExecutionAttemptError::Rejected(reason)
            if reason.contains("carrier identity")
    ));
    std::fs::write(&path, original).unwrap();
    assert!(
        chain
            .state()
            .verified_sumeragi_lane_state()
            .unwrap()
            .is_some()
    );
}

#[test]
fn native_live_capability_requires_completed_successor_anchor() {
    let chain = chain();
    let mut unanchored = reader(&chain);
    let genesis = frame(&chain, 1);
    assert!(
        unanchored
            .push_height(genesis.clone(), &projection(&chain, &genesis))
            .unwrap()
            .is_none()
    );
    assert!(unanchored.into_current_lanes().is_err());
    let mut anchored = reader(&chain);
    for height in 1..=2 {
        let block = frame(&chain, height);
        let bytes = projection(&chain, &block);
        anchored.push_height(block, &bytes).unwrap();
    }
    assert!(anchored.into_current_lanes().unwrap().lanes.is_empty());
}

#[test]
fn certified_result_rejects_changed_actual_lane_history_and_counter() {
    let chain = chain();
    let genesis = frame(&chain, 1);
    let second = frame(&chain, 2);
    for field in 0..3 {
        let mut verifier = reader(&chain);
        verifier
            .push_height(genesis.clone(), &projection(&chain, &genesis))
            .unwrap();
        let mut value: NativeExecutionProjectionV1 =
            norito::decode_canonical(&projection(&chain, &second)).unwrap();
        match field {
            0 => value.lanes.incarnations += 1,
            1 => value.lanes.last_transition = 2,
            _ => {
                let mut samples = value.lanes.samples.to_vec();
                samples.push(iroha_data_model::sumeragi_lanes::SumeragiLaneSample {
                    height: 2,
                    time_ms: 2000,
                    transactions: 1,
                    lanes: 1,
                });
                value.lanes.samples = samples.try_into().unwrap();
            }
        }
        // The actual source must differ. Clearing an empty list would be no tamper.
        assert_ne!(
            norito::encode_canonical(&value).unwrap(),
            projection(&chain, &second)
        );
        assert!(
            verifier
                .push_height(second.clone(), &norito::encode_canonical(&value).unwrap())
                .is_err()
        );
        assert!(verifier.into_current_lanes().is_err());
    }
}

#[test]
fn live_receipt_cannot_move_to_an_equivalent_distinct_state_owner() {
    let original = chain();
    let equivalent = chain();
    let receipt = original
        .state()
        .verified_sumeragi_lane_state()
        .unwrap()
        .unwrap();
    assert!(receipt.is_current(original.state()));
    assert!(
        !receipt.is_current(equivalent.state()),
        "equal chain data/generation never replace the original State owner"
    );
}

#[test]
fn authenticated_genesis_callback_requires_actual_successor_and_rejection_poisons_interval() {
    let chain = chain();
    let mut reader = reader(&chain);
    let genesis = frame(&chain, 1);
    let next = frame(&chain, 2);
    assert!(
        reader
            .push_shared_height_with_genesis(
                genesis.clone(),
                &projection(&chain, &genesis),
                |_| panic!("unsigned genesis cannot escape")
            )
            .unwrap()
            .is_none()
    );
    let mut called = false;
    let error = reader
        .push_shared_height_with_genesis(next.clone(), &projection(&chain, &next), |receipt| {
            called = true;
            assert_eq!(receipt.block().hash(), genesis.hash());
            assert_eq!(
                receipt.ordinary_writes_root(),
                chain
                    .committed(1)
                    .commitment()
                    .execution
                    .ordinary_writes_root
            );
            Err("selected original creation rejected".to_owned())
        })
        .unwrap_err();
    assert!(called);
    assert!(error.contains("selected original creation rejected"));
    assert!(
        reader
            .push_height(next.clone(), &projection(&chain, &next))
            .unwrap_err()
            .contains("poisoned")
    );
}

#[test]
fn completed_evidence_releases_original_carriers_after_their_last_receipt() {
    use iroha_allocation::AllocationBudget;
    use iroha_data_model::block::SharedSignedBlock;

    let chain = chain();
    let mut verifier = reader(&chain);
    let layout = SharedSignedBlock::allocation_layout();
    let pools = std::array::from_fn::<_, 3, _>(|_| AllocationBudget::new(layout.size()));
    for height in 1..=3 {
        let original = frame(&chain, height);
        let bytes = projection(&chain, &original);
        // Each exact signed fixture has its own original control pool, independent
        // of Kura's retained frame. Its refund observes the last real owner.
        let block = SharedSignedBlock::reserve(&pools[height - 1])
            .unwrap()
            .initialize(original.as_ref().clone());
        let receipt = verifier.push_height(block, &bytes).unwrap();
        assert_eq!(pools[height - 1].reserved_bytes(), layout.size());
        if let Some(receipt) = &receipt {
            assert_eq!(receipt.block().hash(), original.hash());
        }
        drop(receipt);
        for pool in &pools[..height - 1] {
            assert_eq!(
                pool.reserved_bytes(),
                0,
                "completed evidence must release historical original carrier custody"
            );
        }
    }
    assert!(verifier.into_current_lanes().unwrap().lanes.is_empty());
    assert!(pools.iter().all(|pool| pool.reserved_bytes() == 0));
}

#[test]
fn completed_evidence_keeps_cumulative_bounds_after_retiring_carrier_owners() {
    let chain = chain();
    let blocks = (1..=3)
        .map(|height| frame(&chain, height))
        .collect::<Vec<_>>();
    let contexts = blocks
        .iter()
        .map(|block| projection(&chain, block))
        .collect::<Vec<_>>();
    let demand = blocks
        .iter()
        .zip(&contexts)
        .map(|(block, context)| {
            u64::try_from(norito::canonical_frame_len(block.as_ref()).unwrap()).unwrap()
                + 1
                + u64::try_from(context.len()).unwrap()
        })
        .sum::<u64>();
    for (carrier_limit, byte_limit, succeeds) in [
        (3, demand, true),
        (2, demand, false),
        (3, demand - 1, false),
    ] {
        let mut verifier = NativeExecutionEvidenceVerifier::new(
            ChainId::from("sumeragi-certified-test-chain"),
            chain.network_id(),
            NativeExecutionEvidenceLimits {
                max_carriers: carrier_limit,
                max_carrier_bytes: blocks
                    .iter()
                    .map(|block| {
                        u64::try_from(norito::canonical_frame_len(block.as_ref()).unwrap()).unwrap()
                            + 1
                    })
                    .max()
                    .unwrap(),
                max_context_bytes: contexts
                    .iter()
                    .map(|context| u64::try_from(context.len()).unwrap())
                    .max()
                    .unwrap(),
                max_retained_bytes: byte_limit,
            },
        )
        .unwrap();
        for index in 0..2 {
            verifier
                .push_height(blocks[index].clone(), &contexts[index])
                .unwrap();
        }
        let result = verifier.push_height(blocks[2].clone(), &contexts[2]);
        assert_eq!(result.is_ok(), succeeds);
        if succeeds {
            assert_eq!(result.unwrap().unwrap().block().hash(), blocks[2].hash());
            assert!(verifier.into_current_lanes().is_ok());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .contains("independently admitted interval")
            );
            assert!(
                verifier
                    .push_height(blocks[2].clone(), &contexts[2])
                    .unwrap_err()
                    .contains("poisoned")
            );
            assert!(verifier.into_current_lanes().is_err());
        }
    }
}
