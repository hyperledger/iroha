//! Original lane merge references are work; metadata alone cannot create a proposal.
use super::*;
use iroha_data_model::block::{BlockHeader, builder::BlockBuilder as WireBlockBuilder};
use iroha_model_base::topology::LaneId;
use std::num::NonZeroU64;

#[test]
fn native_lane_merge_is_work_without_a_direct_network_execution_leaf() {
    let merge = SumeragiLaneMerge {
        lane: LaneId::new(1),
        incarnation: [1; 32],
        from: 1,
        to: 1,
        tip_hash: [2; 32],
        tip_result: [3; 32],
    };
    let mut builder = WireBlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        2,
        0,
    ));
    let mut context = BlockExecutionContextBundle::default();
    context.lane_merge = Some(SumeragiLaneMergeSection {
        merges: vec![merge],
        time_floor_ms: 1,
        merged_count: 0,
    });
    builder.set_execution_context(Some(context));
    let block = builder.build(iroha_data_model::block::BlockSignatures::default());
    assert_eq!(block.network_entrypoint_count(), 0);
    assert!(block.has_consensus_work());
    let encoded = encode(&block).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert!(decoded.has_consensus_work());
    assert_eq!(decoded.lane_merge().unwrap().merges, vec![merge]);
    assert_eq!(decoded.encode_wire().unwrap(), encoded);
    // Work classification does not grant execution authority. Native merge expansion
    // authenticates exact tip/hash/result/incarnation and time against the source store;
    // malformed_merges_are_invalid_and_missing_blocks_pending exercises those checks.
}

#[test]
fn outputs_and_empty_context_cannot_create_proposal_work() {
    let mut builder = WireBlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        2,
        19,
    ));
    builder.set_execution_context(Some(BlockExecutionContextBundle::default()));
    let block = builder.build(iroha_data_model::block::BlockSignatures::default());
    assert!(!block.has_consensus_work());
    assert!(matches!(encode(&block), Err(PayloadError::EmptyBlock)));
    assert!(matches!(
        decode(&block.encode_wire().unwrap()),
        Err(PayloadError::EmptyBlock)
    ));
}

thread_local! {
    static BUILD_AT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn record_build_at() {
    BUILD_AT_CALLS.with(|calls| calls.set(calls.get() + 1));
}

fn counted<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    BUILD_AT_CALLS.with(|calls| calls.set(0));
    let value = operation();
    let calls = BUILD_AT_CALLS.with(std::cell::Cell::get);
    (value, calls)
}

#[inline(never)]
fn original_parent_chain() -> crate::sumeragi::test_chain::CertifiedTestChain {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    assert_eq!(chain.height(), 2);
    chain
}

fn accepted_tick(
    chain: &crate::sumeragi::test_chain::CertifiedTestChain,
    created_ms: u64,
) -> AcceptedTransaction<'static> {
    let original = chain.tick(created_ms);
    let (_, clock) =
        TimeSource::new_mock(Duration::from_millis(created_ms.checked_add(1).unwrap()));
    let view = chain.state().view();
    AcceptedTransaction::accept_with_time_source(
        original,
        &chain.network_id(),
        Duration::from_secs(1),
        view.world().parameters().transaction(),
        &iroha_config::parameters::actual::Crypto::default(),
        &clock,
    )
    .unwrap()
}

// This is an assembly input, not an admitted lane certificate. The assembler has always
// retained the proposed reference verbatim; actual lane expansion authenticates its owner.
fn proposed_merge(floor: u64) -> MergeProposal {
    MergeProposal {
        merges: vec![SumeragiLaneMerge {
            lane: LaneId::new(1),
            incarnation: [1; 32],
            from: 1,
            to: 1,
            tip_hash: [2; 32],
            tip_result: [3; 32],
        }],
        transactions: 0,
        time_floor_ms: floor,
    }
}

fn previous_two_build_reference(
    state: &State,
    assembly: Assembly<'_>,
    transactions: &[AcceptedTransaction<'static>],
    merges: &MergeProposal,
) -> SignedBlock {
    let parent_time = assembly.parent.header().creation_time();
    let minimum = parent_time.checked_add(assembly.cadence).unwrap();
    let first = build_at(state, assembly, transactions, merges, minimum).unwrap();
    let canonical = ValidBlock::sumeragi_block_time(&first, parent_time, assembly.cadence).unwrap();
    if canonical == first.header().creation_time() {
        first
    } else {
        build_at(state, assembly, transactions, merges, canonical).unwrap()
    }
}

#[test]
fn merge_floor_avoids_duplicate_original_parent_build_with_exact_wire_parity() {
    let chain = original_parent_chain();
    let parent = chain
        .state()
        .view()
        .latest_block()
        .expect("original committed parent read completes")
        .expect("fixture retains its actual committed parent");
    let assembly = Assembly {
        parent: &parent,
        view: 7,
        cadence: Duration::from_millis(1),
    };
    let base = u64::try_from(parent.header().creation_time().as_millis())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let future = base.checked_add(10_000).unwrap();
    // Merge-only, merge floor beyond own input, own input beyond merge floor,
    // floor below the parent, and empty-section metadata have the same exact wire.
    let cases = [
        (proposed_merge(future), None, future, 2),
        (proposed_merge(future), Some(base), future, 2),
        (proposed_merge(base), Some(future), future + 1, 1),
        (proposed_merge(0), None, base, 1),
        (
            MergeProposal {
                time_floor_ms: u64::MAX,
                ..Default::default()
            },
            Some(base),
            base + 1,
            1,
        ),
        (proposed_merge(u64::MAX), None, u64::MAX, 2),
    ];
    for (merges, created, expected_time, previous_count) in cases {
        let inputs = created
            .map(|time| accepted_tick(&chain, time))
            .into_iter()
            .collect::<Vec<_>>();
        let (previous, calls) =
            counted(|| previous_two_build_reference(chain.state(), assembly, &inputs, &merges));
        assert_eq!(
            calls, previous_count,
            "reference must exercise the actual old build boundary"
        );
        let (current, calls) =
            counted(|| assemble_with_merges(chain.state(), assembly, &inputs, &merges).unwrap());
        assert_eq!(calls, 1, "original State/QC assembly must run exactly once");
        assert_eq!(
            current.header().creation_time(),
            Duration::from_millis(expected_time)
        );
        assert_eq!(
            current.encode_wire().unwrap(),
            previous.encode_wire().unwrap()
        );
        assert!(
            current
                .npos_consensus_effects()
                .unwrap()
                .parent_service_commit_qc
                .is_some(),
            "real signed parent QC remains mandatory at height three"
        );
        assert_eq!(current.header().prev_block_hash(), Some(parent.hash()));
        assert_eq!(current.header().view_change_index(), assembly.view);
        assert_eq!(current.lane_merge().is_some(), !merges.merges.is_empty());
    }
    assert_eq!(
        chain.height(),
        2,
        "proposal construction never publishes state"
    );
}

#[test]
fn empty_work_and_cadence_overflow_refuse_before_any_parent_build() {
    let chain = original_parent_chain();
    let parent = chain
        .state()
        .view()
        .latest_block()
        .expect("original committed parent read completes")
        .expect("fixture retains its actual committed parent");
    let assembly = Assembly {
        parent: &parent,
        view: 0,
        cadence: Duration::from_millis(1),
    };
    let (empty, calls) = counted(|| {
        assemble_with_merges(
            chain.state(),
            assembly,
            &[],
            &MergeProposal {
                time_floor_ms: u64::MAX,
                ..Default::default()
            },
        )
    });
    assert!(matches!(empty, Err(PayloadError::EmptyBlock)));
    assert_eq!(calls, 0);
    let (overflow, calls) = counted(|| {
        assemble_with_merges(
            chain.state(),
            Assembly {
                cadence: Duration::MAX,
                ..assembly
            },
            &[],
            &proposed_merge(1),
        )
    });
    assert!(matches!(overflow, Err(PayloadError::TimeOverflow)));
    assert_eq!(calls, 0);
    assert_eq!(chain.height(), 2);
}
