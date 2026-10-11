//! Native execution provenance and complete source-budget controls for offchain consumers.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn history_read_budget() -> crate::state::CanonicalHistoryReadBudget {
    crate::state::CanonicalHistoryReadBudget::new(
        iroha_allocation::AllocationBudget::new(48 * 1024 * 1024),
        norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            1_000_000,
            48 * 1024 * 1024,
            1_000_000,
            48 * 1024 * 1024,
            64,
        )),
    )
}

pub(super) fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain
}

pub(super) fn bounds(chain: &CertifiedTestChain, height: u64) -> (u64, u64) {
    let block = chain.committed(height);
    let validation = block
        .block()
        .network_entrypoint_count()
        .max(block.block().execution_outputs().len())
        .max(1) as u64;
    let source_bytes = (1..=height.max(2))
        .map(|height| chain.committed(height).block().encode_wire().unwrap().len() as u64)
        .sum();
    (height.max(2) + validation, source_bytes)
}

#[test]
fn native_carrier_charges_the_complete_source_and_preserves_exact_outputs() {
    let chain = chain();
    for height in 1..=2 {
        let (work, bytes) = bounds(&chain, height);
        let carrier = chain
            .state()
            .read_finalized_execution_carrier(
                NonZeroUsize::new(height as usize).unwrap(),
                work,
                bytes,
            )
            .unwrap();
        assert_eq!(carrier.work_items(), work);
        assert_eq!(carrier.wire_bytes(), bytes);
        assert_eq!(
            carrier.block().encode_wire().unwrap(),
            chain.committed(height).block().encode_wire().unwrap()
        );
        assert!(!chain.kura().store_root().join("v2_finality").exists());
    }
}

#[test]
fn cold_checkpoint_reader_uses_original_frame_pool_and_refunds_after_last_block() {
    let chain = chain();
    let frames = iroha_allocation::AllocationBudget::new(0);
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 48_000_000, 64,
    ));
    let budget = crate::state::CanonicalHistoryReadBudget::new(frames.clone(), context.clone());
    let height = NonZeroUsize::new(2).unwrap();
    assert!(
        chain
            .state()
            .read_executed_carrier_from_checkpoints(height, 1_000, 1 << 40, &budget)
            .is_err()
    );
    assert_eq!(frames.reserved_bytes(), 0);
    frames.set_limit_bytes(48_000_000);
    let carrier = chain
        .state()
        .read_executed_carrier_from_checkpoints(height, 1_000, 1 << 40, &budget)
        .unwrap();
    assert!(carrier.block().belongs_to(&frames));
    assert!(context.consumed_allocated_bytes() > carrier.wire_bytes() as u64);
    let held = carrier.block().clone();
    let charge = frames.reserved_bytes();
    assert!(charge > 0);
    drop(carrier);
    assert_eq!(frames.reserved_bytes(), charge);
    drop(held);
    assert_eq!(frames.reserved_bytes(), 0);
}

#[test]
fn cold_checkpoint_reader_refuses_native_allocation_expansion_before_graph_publication() {
    let chain = chain();
    let frames = iroha_allocation::AllocationBudget::new(48_000_000);
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 1, 64,
    ));
    let budget = crate::state::CanonicalHistoryReadBudget::new(frames.clone(), context.clone());
    assert!(
        chain
            .state()
            .read_executed_carrier_from_checkpoints(
                NonZeroUsize::new(2).unwrap(),
                1_000,
                1 << 40,
                &budget,
            )
            .is_err()
    );
    assert_eq!(frames.reserved_bytes(), 0);
    assert_eq!(context.consumed_allocated_bytes(), 0);
}

#[test]
fn checkpointed_carrier_reads_start_near_their_target() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    for _ in 0..5 {
        chain.commit(Vec::new());
    }
    let tip = u64::try_from(chain.state().view().height()).unwrap();
    assert!(tip >= 4, "the chain spans several blocks");
    let validation = |height: u64| {
        let block = chain.committed(height);
        block
            .block()
            .network_entrypoint_count()
            .max(block.block().execution_outputs().len())
            .max(1) as u64
    };
    let read = |height: u64| {
        chain
            .state()
            .read_executed_carrier_from_checkpoints(
                NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap(),
                1_000,
                1 << 40,
                &history_read_budget(),
            )
            .unwrap()
    };
    // Cold: the walk starts at the tip and pays for every newer block.
    chain.kura().history_checkpoints().clear();
    let cold = read(2);
    assert_eq!(cold.work_items(), tip - 1 + validation(2));
    assert_eq!(
        cold.block().encode_wire().unwrap(),
        chain.committed(2).block().encode_wire().unwrap()
    );
    let finalized = chain
        .state()
        .read_finalized_execution_carrier(NonZeroUsize::new(2).unwrap(), 1_000, 1 << 40)
        .unwrap();
    assert_eq!(
        cold.block().encode_wire().unwrap(),
        finalized.block().encode_wire().unwrap(),
        "both readers authenticate the same execution"
    );
    // Warm: the cold walk remembered every identity it verified.
    let warm = read(3);
    assert_eq!(warm.work_items(), 1 + validation(3));
    assert_eq!(
        warm.block().encode_wire().unwrap(),
        chain.committed(3).block().encode_wire().unwrap()
    );
    assert!(
        matches!(
            chain.state().read_executed_carrier_from_checkpoints(
                NonZeroUsize::new(3).unwrap(),
                validation(3),
                1 << 40,
                &history_read_budget()
            ),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ),
        "the source block counts against the work bound"
    );
}

#[test]
fn checkpointed_reads_discard_foreign_journal_entries_and_recheck_execution() {
    use crate::kura::history_checkpoints::HistoryCheckpoint;
    let mut chain = chain();
    chain.commit(Vec::new());
    let height = NonZeroUsize::new(2).unwrap();
    let source = chain.committed(2);
    let checkpoints = chain.kura().history_checkpoints();
    let authentic = HistoryCheckpoint {
        iroha_hash: source.block_hash(),
        core_hash: source.core_hash(),
        result: source.result(),
    };
    checkpoints.record(
        2,
        HistoryCheckpoint {
            iroha_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign history")),
            ..authentic
        },
    );
    let read = || {
        chain.state().read_executed_carrier_from_checkpoints(
            height,
            1_000,
            1 << 40,
            &history_read_budget(),
        )
    };
    let repaired =
        read().expect("foreign checkpoint is discarded and the tip authenticates history");
    assert_eq!(
        repaired.block().encode_wire().unwrap(),
        source.block().encode_wire().unwrap()
    );
    assert!(
        checkpoints
            .candidates(2, 2)
            .iter()
            .copied()
            .eq([(2, authentic)])
    );

    checkpoints.record(
        2,
        HistoryCheckpoint {
            result: iroha_sumeragi::types::Hash32([0xD7; 32]),
            ..authentic
        },
    );
    assert!(
        read().is_err(),
        "a matching journal hash never bypasses native result validation"
    );
}

#[test]
fn checkpoint_warming_does_not_change_consensus_history_metering() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let height = NonZeroUsize::new(2).unwrap();
    chain.kura().history_checkpoints().clear();
    let read = || {
        chain
            .state()
            .read_finalized_execution_carrier(height, 1_000, 1 << 40)
            .unwrap()
    };
    let cold = read();
    let warm = read();
    assert_eq!(cold.work_items(), warm.work_items());
    assert_eq!(cold.wire_bytes(), warm.wire_bytes());
    assert_eq!(
        cold.block().encode_wire().unwrap(),
        warm.block().encode_wire().unwrap()
    );
    let offchain_cold = chain
        .state()
        .read_executed_carrier_from_checkpoints(height, 1_000, 1 << 40, &history_read_budget())
        .unwrap();
    let offchain = chain
        .state()
        .read_executed_carrier_from_checkpoints(height, 1_000, 1 << 40, &history_read_budget())
        .unwrap();
    assert!(offchain.work_items() < offchain_cold.work_items());
    assert!(offchain.work_items() < warm.work_items());
    let after_offchain = read();
    assert_eq!(after_offchain.work_items(), cold.work_items());
    assert_eq!(after_offchain.wire_bytes(), cold.wire_bytes());
}

#[test]
fn native_carrier_refusal_never_projects_partial_transaction_results() {
    let chain = chain();
    let height = NonZeroUsize::new(2).unwrap();
    let block = chain.committed(2);
    let (work, bytes) = bounds(&chain, 2);
    for (max_work, max_bytes) in [(0, bytes), (work, 0), (work - 1, bytes), (work, bytes - 1)] {
        let mut visits = 0;
        assert!(matches!(
            visit_finalized_network_transactions(
                chain.state(),
                height,
                block.block_hash(),
                max_work,
                max_bytes,
                |_, _| visits += 1,
            ),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
        assert_eq!(visits, 0);
    }
    let foreign = HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign carrier"));
    let mut visits = 0;
    assert!(
        visit_finalized_network_transactions(
            chain.state(),
            height,
            foreign,
            work,
            bytes,
            |_, _| visits += 1,
        )
        .is_err()
    );
    assert_eq!(visits, 0);
    visit_finalized_network_transactions(
        chain.state(),
        height,
        block.block_hash(),
        work,
        bytes,
        |_, _| visits += 1,
    )
    .unwrap();
    assert_eq!(visits, block.block().network_entrypoint_count());
}

#[test]
fn native_carrier_requires_actual_genesis_successor_and_configured_instance() {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    assert!(
        chain
            .state()
            .read_finalized_execution_carrier(NonZeroUsize::MIN, 128, 16 * 1024 * 1024,)
            .is_err()
    );
    let chain = self::chain();
    let view = chain.state().view();
    let block = chain.committed(2);
    let (work, bytes) = bounds(&chain, 2);
    assert!(
        read_finalized_execution_carrier(
            chain.kura(),
            &iroha_model_base::chain::ChainId::from("foreign-instance"),
            *view.network_id(),
            view.block_hashes(),
            NonZeroUsize::new(2).unwrap(),
            block.block_hash(),
            work,
            bytes,
            &chain.state().ivm_execution_budget(),
        )
        .is_err()
    );
}

#[test]
fn checkpoint_tip_status_authentication_uses_one_original_source_without_changing_prefix_metering()
{
    let mut chain = chain();
    for _ in 0..4 {
        chain.commit(Vec::new());
    }
    let tip = chain.height();
    let height = NonZeroUsize::new(usize::try_from(tip).unwrap()).unwrap();
    let original = chain.committed(tip);
    let validation = u64::try_from(
        original
            .block()
            .network_entrypoint_count()
            .max(original.block().execution_outputs().len())
            .max(1),
    )
    .unwrap();
    let work = validation + 1;
    let bytes = u64::try_from(original.block().encode_wire().unwrap().len()).unwrap();
    chain.kura().history_checkpoints().clear();
    let budget = history_read_budget();
    let read = || {
        chain
            .state()
            .read_executed_carrier_from_checkpoints(height, work, bytes, &budget)
    };
    let cold = read().expect("the original State tip authenticates exactly one admitted source");
    assert_eq!(cold.work_items(), work);
    assert_eq!(cold.wire_bytes(), bytes);
    assert_eq!(
        cold.block().encode_wire().unwrap(),
        original.block().encode_wire().unwrap()
    );
    let warm = read().expect("a verified checkpoint still authenticates the actual source");
    assert_eq!(warm.work_items(), cold.work_items());
    assert_eq!(warm.wire_bytes(), cold.wire_bytes());
    assert_eq!(
        warm.block().encode_wire().unwrap(),
        cold.block().encode_wire().unwrap()
    );
    assert!(
        matches!(
            chain
                .state()
                .read_finalized_execution_carrier(height, work, bytes),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ),
        "off-chain warming cannot shorten the original full-prefix reader's work"
    );
}

#[test]
fn checkpoint_status_refusal_retries_the_original_frame_pool_and_refunds_after_last_carrier() {
    let chain = chain();
    let frames = iroha_allocation::AllocationBudget::new(48_000_000);
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 48_000_000, 64,
    ));
    let budget = crate::state::CanonicalHistoryReadBudget::new(frames.clone(), context.clone());
    // Metadata reads genuinely consume the same cumulative codec owner before the
    // shell gate. Measure that exact original marker-only path, never reset its work.
    let original = chain.committed(2);
    let original_length = u64::try_from(original.block().encode_wire().unwrap().len()).unwrap();
    let metadata_before = context.consumed_allocated_bytes();
    let source = budget.with(|| {
        chain
            .kura()
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap()
    });
    assert_eq!(source.wire_len(), original_length);
    drop(source);
    let marker_work = context
        .consumed_allocated_bytes()
        .checked_sub(metadata_before)
        .unwrap();
    assert!(
        marker_work > 0,
        "the actual durable marker is decoded before shell admission"
    );
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let expected = frames
        .try_reserve(iroha_data_model::block::SharedSignedBlock::allocation_layout())
        .unwrap_err();
    let read = || {
        chain.state().read_executed_carrier_from_checkpoints(
            NonZeroUsize::new(2).unwrap(),
            1_000,
            1 << 40,
            &budget,
        )
    };
    let before_refusals = context.consumed_allocated_bytes();
    for attempt in 1..=2_u64 {
        match read() {
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(original)) => {
                assert_eq!(original.allocation_refusal(), Some(&expected));
            }
            other => panic!(
                "occupied original frame pool must retain its exact typed refusal: {other:?}"
            ),
        }
        assert_eq!(
            context.consumed_allocated_bytes(),
            before_refusals
                .checked_add(marker_work.checked_mul(attempt).unwrap())
                .unwrap(),
            "original marker preflight remains cumulative; no body decode follows the refused shell"
        );
        assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    }
    let refused_work = context.consumed_allocated_bytes();
    drop(blocker);
    let carrier = read().expect("retry uses the same original query source and decoder owners");
    assert!(carrier.block().belongs_to(&frames));
    assert!(context.consumed_allocated_bytes() > refused_work);
    let retained = carrier.block().clone();
    let charged = frames.reserved_bytes();
    assert!(charged > 0);
    drop(carrier);
    assert_eq!(frames.reserved_bytes(), charged);
    drop(retained);
    assert_eq!(frames.reserved_bytes(), 0);
}

#[test]
fn authenticated_carrier_network_visitor_preserves_borrowed_rows_and_refuses_foreign_selection() {
    let chain = chain();
    let carrier = chain
        .state()
        .read_executed_carrier_from_checkpoints(
            NonZeroUsize::new(2).unwrap(),
            1_000,
            1 << 40,
            &history_read_budget(),
        )
        .unwrap();
    let foreign =
        HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign selected status carrier"));
    let mut visits = 0;
    assert!(
        carrier
            .visit_network_transactions(foreign, |_, _| visits += 1)
            .is_err()
    );
    assert_eq!(
        visits, 0,
        "a foreign selection cannot expose even the first borrowed result"
    );
    let header = carrier
        .visit_network_transactions(carrier.block().hash(), |source, result| {
            assert!(std::ptr::eq(
                source,
                carrier.block().network_entrypoint_at(visits).unwrap()
            ));
            let index = u32::try_from(visits).unwrap();
            assert!(std::ptr::eq(
                result,
                &carrier.block().network_output_at(index).unwrap().1.result
            ));
            visits += 1;
        })
        .unwrap();
    assert_eq!(header, carrier.block().header());
    assert_eq!(visits, carrier.block().network_entrypoint_count());
    assert!(
        visits > 0,
        "the certified fixture executes genuine nonempty work"
    );
}

#[test]
fn genesis_status_prefix_retains_original_admitted_pool_and_cumulative_refusal_work() {
    use crate::{execution_attempt::ExecutionAttemptError, state::CanonicalHistoryReadBudget};
    use iroha_allocation::AllocationBudget;
    use norito::{DecodeLimits, core::DecodeBudgetContext};
    use std::alloc::Layout;

    let chain = chain();
    let frames = AllocationBudget::new(48_000_000);
    let context = DecodeBudgetContext::new(DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 48_000_000, 64,
    ));
    let budget = CanonicalHistoryReadBudget::new(frames.clone(), context.clone());
    // The retained prepared signed input is not the later applied native carrier body.
    // Source lengths/results must come from the exact consensus-visible committed G1.
    let original_g1 = chain.committed(1);
    let original_wire = original_g1.block().encode_wire().unwrap();
    assert_eq!(original_g1.block_hash(), chain.genesis().hash());
    let original_length = u64::try_from(original_wire.len()).unwrap();
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let expected = frames
        .try_reserve(Layout::array::<u8>(original_wire.len()).unwrap())
        .unwrap_err();
    // Exercise the actual original slot and occupied byte allocation once as a precise
    // source-work preflight. Its successful metadata/nominal prefix remains on this same
    // context; the full-prefix attempt must add both its metadata captures and read prefix.
    let metadata_before = context.consumed_allocated_bytes();
    let source = budget.with(|| {
        chain
            .kura()
            .native_frame_read(1, original_g1.block_hash())
            .unwrap()
            .unwrap()
    });
    assert_eq!(source.wire_len(), original_length);
    let marker_work = context
        .consumed_allocated_bytes()
        .checked_sub(metadata_before)
        .unwrap();
    assert!(marker_work > 0);
    let read_before = context.consumed_allocated_bytes();
    match budget.with(|| source.read(original_length, &frames)) {
        Err(crate::kura::Error::NativeFrameAllocation(
            iroha_allocation::ChargedBufferError::Admission(original),
        )) => assert_eq!(original, expected),
        other => {
            panic!("the original native G1 byte backing must retain its exact refusal: {other:?}")
        }
    }
    let frame_work = context
        .consumed_allocated_bytes()
        .checked_sub(read_before)
        .unwrap();
    assert_eq!(
        frame_work,
        marker_work.checked_add(original_length).unwrap(),
        "only original read metadata and admitted byte backing precede the physical refusal"
    );
    let before_prefix = context.consumed_allocated_bytes();
    let read = || {
        chain
            .state()
            .read_finalized_execution_carrier_with_read_budget(
                NonZeroUsize::MIN,
                1_000,
                1 << 40,
                &budget,
            )
    };
    match read() {
        Err(ExecutionAttemptError::Deferred(original)) => {
            assert_eq!(original.allocation_refusal(), Some(&expected));
        }
        other => {
            panic!("finalized status must retain the original admitted query frame pool: {other:?}")
        }
    }
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    assert_eq!(
        context.consumed_allocated_bytes(),
        before_prefix
            .checked_add(marker_work.checked_mul(2).unwrap())
            .unwrap()
            .checked_add(frame_work)
            .unwrap(),
        "target admission and original G1 acquisition retain all original metadata/byte work"
    );
    let admitted_prefix = context.consumed_allocated_bytes();
    drop(blocker);
    let carrier =
        read().expect("retry preserves the same cumulative native owner and original pool");
    assert!(carrier.block().belongs_to(&frames));
    assert_eq!(carrier.block().encode_wire().unwrap(), original_wire);
    assert!(context.consumed_allocated_bytes() > admitted_prefix);
    let retained = carrier.block().clone();
    let original: *const iroha_data_model::block::SignedBlock = retained.as_ref();
    let charge = frames.reserved_bytes();
    assert!(charge > 0);
    drop(carrier);
    assert!(std::ptr::eq(retained.as_ref(), original));
    assert_eq!(frames.reserved_bytes(), charge);
    drop(retained);
    assert_eq!(frames.reserved_bytes(), 0);
}

#[test]
fn genesis_status_prefix_requires_actual_h2_and_refuses_substituted_successor() {
    use crate::execution_attempt::ExecutionAttemptError;
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let budget = history_read_budget();
    let read = || {
        chain
            .state()
            .read_finalized_execution_carrier_with_read_budget(
                NonZeroUsize::MIN,
                1_000,
                1 << 40,
                &budget,
            )
    };
    let error =
        read().expect_err("an opaque G1 tip does not replace the original status H2 requirement");
    match error {
        ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message)) => {
            assert!(
                message.contains("height 2 is not committed in this view"),
                "{message}"
            );
        }
        other => panic!("missing H2 preserves original full-prefix rejection: {other:?}"),
    }
    chain.commit(Vec::new());
    let carrier = chain
        .state()
        .read_finalized_execution_carrier_with_read_budget(
            NonZeroUsize::MIN,
            1_000,
            1 << 40,
            &budget,
        )
        .expect("the genuine H2 successor authenticates original G1 execution");
    assert_eq!(
        carrier.block().encode_wire().unwrap(),
        chain.committed(1).block().encode_wire().unwrap()
    );
    drop(carrier);
    let replacement =
        HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign H2 status anchor"));
    assert_ne!(replacement, chain.committed(2).block().hash());
    let mut journal = chain.state().block_hashes.block_and_revert();
    journal.push_for_tests(replacement);
    journal.commit_for_tests();
    assert_eq!(
        chain.state().block_hashes.view().get(0).copied(),
        Some(chain.genesis().hash())
    );
    let ordinary = chain
        .state()
        .read_finalized_execution_carrier(NonZeroUsize::MIN, 1_000, 1 << 40)
        .expect_err("the deterministic prefix rejects the same substituted H2");
    let admitted = chain
        .state()
        .read_finalized_execution_carrier_with_read_budget(
            NonZeroUsize::MIN,
            1_000,
            1 << 40,
            &budget,
        )
        .expect_err("neither original G1 nor a node-local checkpoint can rescue substituted H2");
    match (ordinary, admitted) {
        (
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(original)),
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(actual)),
        ) => assert_eq!(actual, original),
        changed => {
            panic!("the admitted G1 prefix preserves the exact original rejection: {changed:?}")
        }
    }
}

#[test]
fn event_carrier_reads_recent_certified_source_under_original_finite_work() {
    let mut chain = chain();
    while chain.height() < 5 {
        chain.commit(Vec::new());
    }
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let source_heights = [1, chain.height(), chain.height() - 1];
    let bytes: u64 = source_heights
        .into_iter()
        .map(|height| {
            u64::try_from(chain.committed(height).block().encode_wire().unwrap().len()).unwrap()
        })
        .sum();
    let target = chain.committed(chain.height()).block().clone();
    let output_work = u64::try_from(
        target
            .network_entrypoint_count()
            .max(target.execution_outputs().len())
            .max(1),
    )
    .unwrap();
    let work = u64::try_from(source_heights.len()).unwrap() + output_work;
    let pool = chain.state().ivm_execution_budget();
    chain.kura().reset_canonical_query_reads_for_test();
    let (result, relations) = crate::sumeragi::certified_chain::relation_counts::measure(|| {
        chain
            .state()
            .read_finalized_event_carrier(height, work, bytes)
    });
    if let Err(error) = &result {
        assert!(
            matches!(
                error,
                crate::state::FinalizedEventReadError::Execution(
                    crate::execution_attempt::ExecutionAttemptError::Rejected(
                        QueryExecutionFail::GasBudgetExceeded
                    )
                )
            ),
            "finite event source refusal must retain the actual GasBudgetExceeded category: {error:?}",
        );
    }
    let carrier = result.expect(
        "current block-event projection must not spend its finite source allowance on the completed genesis prefix",
    );
    assert_eq!(carrier.work_items(), work);
    assert_eq!(carrier.wire_bytes(), bytes);
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        (source_heights.len(), bytes)
    );
    assert_eq!(
        relations.qcs,
        [chain.height()],
        "the actual target QC must still run"
    );
    assert!(carrier.block().belongs_to(&pool));
    assert_eq!(carrier.block().hash(), target.hash());
    assert_eq!(
        carrier.block().encode_wire().unwrap(),
        target.encode_wire().unwrap()
    );
}

// Spend exactly one real durable metadata acquisition before entering either actual
// State reader. Its cumulative decoder remains installed across both later refusals.
fn assert_state_carrier_metadata_refusal_is_local(event: bool, cause: &str) {
    use crate::execution_attempt::ExecutionAttemptError;
    use ivm::error::ExecutionDeferral;

    let mut chain = chain();
    while chain.height() < 3 {
        chain.commit(Vec::new());
    }
    let height = NonZeroUsize::new(3).unwrap();
    let original = chain.committed(3);
    let expected = original.block_hash();
    let original_wire = original.block().encode_wire().unwrap();
    let (work, bytes) = bounds(&chain, 3);
    let limits = |allocation| {
        norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, allocation, 64)
    };
    let probe = norito::core::DecodeBudgetContext::new(limits(48 * 1024 * 1024));
    probe.with(|| {
        chain
            .kura()
            .native_frame_read(3, expected)
            .unwrap()
            .unwrap();
    });
    let marker_work = probe.consumed_allocated_bytes();
    assert!(
        marker_work > 0,
        "the actual original durable marker has codec work"
    );
    let context =
        norito::core::DecodeBudgetContext::new(limits(usize::try_from(marker_work).unwrap()));
    let frames = chain.state().ivm_execution_budget();
    let budget = crate::state::CanonicalHistoryReadBudget::new(frames.clone(), context.clone());
    budget.with(|| {
        chain
            .kura()
            .native_frame_read(3, expected)
            .unwrap()
            .unwrap();
    });
    assert_eq!(context.consumed_allocated_bytes(), marker_work);
    let charge = frames.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    let read = || {
        if event {
            budget
                .with(|| {
                    chain
                        .state()
                        .read_finalized_event_carrier(height, work, bytes)
                })
                .map_err(|error| match error {
                    crate::state::FinalizedEventReadError::Execution(error) => error,
                    error => panic!(
                        "stable original State capture must precede metadata refusal: {error:?}"
                    ),
                })
        } else {
            chain
                .state()
                .read_finalized_execution_carrier_with_read_budget(height, work, bytes, &budget)
        }
    };
    for _ in 0..2 {
        let error = read().expect_err("the original exhausted marker context cannot read a body");
        let ExecutionAttemptError::Deferred(ref original) = error else {
            panic!("{cause}: {error:?}");
        };
        assert_eq!(
            original.reason(),
            ExecutionDeferral::ActiveMemoryCapacity,
            "{cause}: {error:?}"
        );
        assert!(
            original.allocation_refusal().is_none(),
            "a codec ceiling cannot invent a pool release"
        );
        assert_eq!(context.consumed_allocated_bytes(), marker_work);
        assert_eq!(frames.reserved_bytes(), charge);
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    }
    let retry_context = norito::core::DecodeBudgetContext::new(limits(48 * 1024 * 1024));
    let retry_budget =
        crate::state::CanonicalHistoryReadBudget::new(frames.clone(), retry_context.clone());
    let carrier = if event {
        retry_budget
            .with(|| {
                chain
                    .state()
                    .read_finalized_event_carrier(height, work, bytes)
            })
            .unwrap()
    } else {
        chain
            .state()
            .read_finalized_execution_carrier_with_read_budget(height, work, bytes, &retry_budget)
            .unwrap()
    };
    assert!(carrier.block().belongs_to(&frames));
    assert_eq!(carrier.block().hash(), expected);
    assert_eq!(carrier.block().encode_wire().unwrap(), original_wire);
    assert!(retry_context.consumed_allocated_bytes() > marker_work);
    drop(carrier);
    assert_eq!(frames.reserved_bytes(), charge);
    // A distinct later attempt never resets the original exhausted cumulative owner.
    assert_eq!(context.consumed_allocated_bytes(), marker_work);
}

#[test]
fn full_prefix_carrier_preserves_original_cumulative_metadata_refusal() {
    assert_state_carrier_metadata_refusal_is_local(
        false,
        "original full-prefix metadata refusal must remain local before body acquisition",
    );
}

#[test]
fn event_carrier_preserves_original_cumulative_metadata_refusal() {
    assert_state_carrier_metadata_refusal_is_local(
        true,
        "original event metadata refusal must remain local before body acquisition",
    );
}

#[test]
fn bounded_native_extent_preserves_original_cumulative_metadata_refusal() {
    use crate::execution_attempt::ExecutionAttemptError;
    use ivm::error::ExecutionDeferral;

    let chain = chain();
    let (expected, expected_wire_len) = {
        let target = chain.committed(2);
        (
            target.block_hash(),
            target.block().encode_wire().unwrap().len(),
        )
    };
    let limits = |allocation| {
        norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, allocation, 64)
    };
    let probe = norito::core::DecodeBudgetContext::new(limits(48 * 1024 * 1024));
    probe.with(|| {
        chain
            .kura()
            .native_frame_read(2, expected)
            .unwrap()
            .unwrap();
    });
    let marker_work = probe.consumed_allocated_bytes();
    assert!(marker_work > 0);
    let context =
        norito::core::DecodeBudgetContext::new(limits(usize::try_from(marker_work).unwrap()));
    context.with(|| {
        chain
            .kura()
            .native_frame_read(2, expected)
            .unwrap()
            .unwrap();
    });
    let pool = chain.state().ivm_execution_budget();
    let charge = pool.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    for _ in 0..2 {
        let error = context
            .with(|| {
                crate::sumeragi::certified_chain::bounded_native_carrier_extent(
                    &chain.state().view(),
                    2,
                    usize::try_from(crate::kura::STRICT_INIT_MAX_BLOCK_BYTES).unwrap(),
                )
            })
            .expect_err("the original marker context cannot admit another extent");
        let ExecutionAttemptError::Deferred(ref original) = error else {
            panic!("original bounded native extent metadata refusal must remain local: {error:?}");
        };
        assert_eq!(original.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert!(original.allocation_refusal().is_none());
        assert_eq!(context.consumed_allocated_bytes(), marker_work);
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        assert_eq!(pool.reserved_bytes(), charge);
    }
    let actual = crate::sumeragi::certified_chain::bounded_native_carrier_extent(
        &chain.state().view(),
        2,
        usize::try_from(crate::kura::STRICT_INIT_MAX_BLOCK_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(actual, expected_wire_len);
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert_eq!(context.consumed_allocated_bytes(), marker_work);
    assert_eq!(pool.reserved_bytes(), charge);
}
