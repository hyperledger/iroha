//! Original event-source identities, real publication and cumulative refusal controls.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    smartcontracts::isi::tx,
    sumeragi::{
        certified_chain::relation_counts,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};

fn event_chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    while chain.height() < 5 {
        chain.commit(Vec::new());
    }
    chain
}

fn exact_recent_bounds(chain: &CertifiedTestChain, height: u64, captured_tip: u64) -> (u64, u64) {
    let target = chain.committed(height).block().clone();
    let validation = u64::try_from(
        target
            .network_entrypoint_count()
            .max(target.execution_outputs().len())
            .max(1),
    )
    .unwrap();
    let bytes = std::iter::once(1)
        .chain((height - 1..=captured_tip).rev())
        .map(|source| {
            u64::try_from(chain.committed(source).block().encode_wire().unwrap().len()).unwrap()
        })
        .sum();
    (1 + captured_tip - height + 2 + validation, bytes)
}

#[test]
fn event_carrier_keeps_original_execution_source_while_state_appends() {
    let mut chain = event_chain();
    let state = Arc::clone(chain.state());
    let kura = Arc::clone(chain.kura());
    let original_height = chain.height();
    let target = chain.committed(original_height).block().clone();
    let target_hash = target.hash();
    let original_wire = target.encode_wire().unwrap();
    let pool = state.ivm_execution_budget();
    let hashes = state.block_hashes.view();
    let tip = *state.native_execution_tip.view().get();
    let source = CanonicalHistorySource::new(&kura, &hashes, tip, pool.clone());
    let (work, bytes) = exact_recent_bounds(&chain, original_height, original_height);
    // This is a genuine original Worker/State publication while the immutable hash
    // generation remains retained; no World view or write-blocking guard is kept.
    chain.commit(Vec::new());
    assert_eq!(state.block_hashes.view().len(), hashes.len() + 1);
    let (result, counts) = relation_counts::measure(|| {
        tx::read_finalized_event_carrier(
            source,
            &kura,
            state.chain_id_ref(),
            *state.network_id_ref(),
            NonZeroUsize::new(usize::try_from(original_height).unwrap()).unwrap(),
            target_hash,
            work,
            bytes,
        )
    });
    let carrier = result
        .expect("appending the genuine tip cannot replace the retained original event source");
    assert_eq!(counts.qcs, [original_height]);
    assert!(carrier.block().belongs_to(&pool));
    assert_eq!(carrier.block().encode_wire().unwrap(), original_wire);
    // A fresh capture authenticates the older target through the actual newer tip.
    let (work, bytes) = exact_recent_bounds(&chain, original_height, chain.height());
    let historical = state
        .read_finalized_event_carrier(
            NonZeroUsize::new(usize::try_from(original_height).unwrap()).unwrap(),
            work,
            bytes,
        )
        .unwrap();
    assert_eq!(historical.work_items(), work);
    assert_eq!(
        historical.block().encode_wire().unwrap(),
        carrier.block().encode_wire().unwrap()
    );
}

#[test]
fn event_carrier_refuses_unanchored_and_changed_original_execution_source() {
    let chain = event_chain();
    let state = Arc::clone(chain.state());
    let kura = Arc::clone(chain.kura());
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let hashes = state.block_hashes.view();
    let expected = hashes.get(height.get() - 1).copied().unwrap();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    let source = CanonicalHistorySource::new(&kura, &hashes, None, state.ivm_execution_budget());
    let (result, counts) = relation_counts::measure(|| {
        tx::read_finalized_event_carrier(
            source,
            &kura,
            state.chain_id_ref(),
            *state.network_id_ref(),
            height,
            expected,
            work,
            bytes,
        )
    });
    assert!(
        matches!(result, Err(ExecutionAttemptError::Rejected(_))),
        "a decoded or absent tip is never execution authority"
    );
    assert!(counts.qcs.is_empty());
    kura.corrupt_native_frame_for_test(height);
    let (result, counts) =
        relation_counts::measure(|| state.read_finalized_event_carrier(height, work, bytes));
    assert!(
        matches!(
            result,
            Err(FinalizedEventReadError::Execution(
                ExecutionAttemptError::Rejected(_)
            ))
        ),
        "the opaque tip cannot replace the changed actual frame"
    );
    assert!(
        counts.qcs.is_empty(),
        "source authentication precedes the target QC"
    );
    kura.corrupt_native_frame_for_test(height);
    let carrier = state
        .read_finalized_event_carrier(height, work, bytes)
        .unwrap();
    assert_eq!(carrier.block().hash(), expected);
}

#[test]
fn event_carrier_refusal_preserves_original_pool_and_cumulative_metadata_owner() {
    let chain = event_chain();
    let state = chain.state();
    let pool = state.ivm_execution_budget();
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 48_000_000, 64,
    ));
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    let before_metadata = context.consumed_allocated_bytes();
    for source_height in [chain.height(), 1] {
        let original = chain.committed(source_height).block().clone();
        let source = context.with(|| {
            chain
                .kura()
                .native_frame_read(source_height, original.hash())
                .unwrap()
                .unwrap()
        });
        drop(source);
    }
    let exact_metadata = context.consumed_allocated_bytes() - before_metadata;
    let original_reserved = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - original_reserved)
        .unwrap();
    let expected = pool
        .try_reserve(iroha_data_model::block::SharedSignedBlock::allocation_layout())
        .unwrap_err();
    let before = context.consumed_allocated_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    for attempt in 1..=2_u64 {
        let result = context.with(|| state.read_finalized_event_carrier(height, work, bytes));
        let Err(FinalizedEventReadError::Execution(ExecutionAttemptError::Deferred(reason))) =
            result
        else {
            panic!("original event source shell must retain typed local refusal");
        };
        assert_eq!(reason.allocation_refusal(), Some(&expected));
        assert_eq!(
            context.consumed_allocated_bytes(),
            before + attempt * exact_metadata,
            "only the actual target/genesis marker preflight follows the same cumulative owner before shell refusal"
        );
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    }
    drop(blocker);
    let carrier = context
        .with(|| state.read_finalized_event_carrier(height, work, bytes))
        .unwrap();
    assert!(carrier.block().belongs_to(&pool));
    assert!(context.consumed_allocated_bytes() > before + 2 * exact_metadata);
    let held = carrier.block().clone();
    let retained = pool.reserved_bytes();
    drop(carrier);
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "the original returned body owns its same shell charge"
    );
    drop(held);
    assert_eq!(pool.reserved_bytes(), original_reserved);
}

#[test]
fn event_carrier_refuses_foreign_and_relocated_original_target_before_body_admission() {
    let chain = event_chain();
    let foreign = event_chain();
    let state = chain.state();
    let kura = chain.kura();
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let hash = chain.committed(chain.height()).block_hash();
    let original = kura
        .native_frame_read(chain.height(), hash)
        .unwrap()
        .unwrap();
    let foreign_height = kura
        .native_frame_read(
            chain.height() - 1,
            chain.committed(chain.height() - 1).block_hash(),
        )
        .unwrap()
        .unwrap();
    let foreign_store = foreign
        .kura()
        .native_frame_read(
            foreign.height(),
            foreign.committed(foreign.height()).block_hash(),
        )
        .unwrap()
        .unwrap();
    let hashes = state.block_hashes.view();
    let tip = *state.native_execution_tip.view().get();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    let genesis_bytes =
        u64::try_from(chain.committed(1).block().encode_wire().unwrap().len()).unwrap();
    for descriptor in [&foreign_height, &foreign_store] {
        kura.reset_canonical_query_reads_for_test();
        let source = CanonicalHistorySource::new(kura, &hashes, tip, state.ivm_execution_budget());
        let (result, counts) = relation_counts::measure(|| {
            crate::sumeragi::certified_chain::read_event_execution(
                source,
                state.chain_id_ref(),
                *state.network_id_ref(),
                height,
                descriptor,
                work,
                bytes,
            )
        });
        assert!(
            matches!(result, Err(ExecutionAttemptError::Rejected(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(ref message)))
            if message == "native event target differs from its original admitted slot"),
            "foreign height or archive cannot substitute the actual admitted native target"
        );
        assert!(counts.qcs.is_empty());
        assert_eq!(
            kura.canonical_query_reads_for_test(),
            (1, genesis_bytes),
            "original target substitution must refuse before any target body admission"
        );
    }
    // This second real BlockStore handle writes the same actual index inode. It
    // changes only the target start, leaving height/hash/length and source paths intact.
    let path = crate::kura::Kura::canonical_storage_path(&kura.store_root());
    let mut store = crate::kura::BlockStore::new(&path);
    let index = u64::try_from(height.get() - 1).unwrap();
    let slot = store.read_block_index(index).unwrap();
    assert_eq!(slot.length, original.wire_len());
    store
        .write_block_index(index, slot.start.checked_add(1).unwrap(), slot.length)
        .unwrap();
    kura.reset_canonical_query_reads_for_test();
    let source = CanonicalHistorySource::new(kura, &hashes, tip, state.ivm_execution_budget());
    let (result, counts) = relation_counts::measure(|| {
        crate::sumeragi::certified_chain::read_event_execution(
            source,
            state.chain_id_ref(),
            *state.network_id_ref(),
            height,
            &original,
            work,
            bytes,
        )
    });
    // Restore the occupied original slot before an assertion can unwind the fixture.
    store
        .write_block_index(index, slot.start, slot.length)
        .unwrap();
    assert!(
        matches!(result, Err(ExecutionAttemptError::Rejected(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(ref message)))
        if message == "native event target differs from its original admitted slot"),
        "event target must retain the original slot start through certification"
    );
    assert!(counts.qcs.is_empty());
    assert_eq!(kura.canonical_query_reads_for_test(), (1, genesis_bytes));
    let source = CanonicalHistorySource::new(kura, &hashes, tip, state.ivm_execution_budget());
    let (result, counts) = relation_counts::measure(|| {
        crate::sumeragi::certified_chain::read_event_execution(
            source,
            state.chain_id_ref(),
            *state.network_id_ref(),
            height,
            &original,
            work,
            bytes,
        )
    });
    assert_eq!(result.unwrap().0.block().hash(), hash);
    assert_eq!(counts.qcs, [chain.height()]);
}

#[test]
fn event_carrier_authenticates_original_committee_transition_and_historical_target() {
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit(Vec::new());
    assert_eq!(chain.height(), 10);
    let height = NonZeroUsize::new(10).unwrap();
    assert!(chain.committed(10).commitment().schedule.boundary.is_some());
    let original = chain.committed(10).block().clone();
    let (work, bytes) = exact_recent_bounds(&chain, 10, chain.height());
    let (result, counts) = relation_counts::measure(|| {
        chain
            .state()
            .read_finalized_event_carrier(height, work, bytes)
    });
    let carrier = result.unwrap();
    assert_eq!(counts.qcs, [10]);
    assert_eq!(
        carrier.block().encode_wire().unwrap(),
        original.encode_wire().unwrap()
    );
    chain.commit(Vec::new());
    let (work, bytes) = exact_recent_bounds(&chain, 10, chain.height());
    let (result, counts) = relation_counts::measure(|| {
        chain
            .state()
            .read_finalized_event_carrier(height, work, bytes)
    });
    assert_eq!(counts.qcs, [10]);
    assert_eq!(
        result.unwrap().block().encode_wire().unwrap(),
        carrier.block().encode_wire().unwrap()
    );
}

#[test]
fn event_carrier_preserves_actual_g1_h2_result_anchor() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    assert_eq!(chain.height(), 1);
    assert!(
        matches!(
            chain
                .state()
                .read_finalized_event_carrier(NonZeroUsize::MIN, 100, 16 * 1024 * 1024),
            Err(FinalizedEventReadError::Execution(
                ExecutionAttemptError::Rejected(_)
            ))
        ),
        "event genesis result cannot be authorized without the actual H2 successor"
    );
    chain.commit(Vec::new());
    for source_height in [1, 2] {
        let height = NonZeroUsize::new(source_height).unwrap();
        let expected = chain
            .state()
            .read_finalized_execution_carrier(height, 100, 16 * 1024 * 1024)
            .unwrap();
        let observed = chain
            .state()
            .read_finalized_event_carrier(height, 100, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            observed.block().encode_wire().unwrap(),
            expected.block().encode_wire().unwrap()
        );
        assert_eq!(observed.wire_bytes(), expected.wire_bytes());
        assert_eq!(observed.work_items(), expected.work_items());
    }
}

#[test]
fn event_carrier_refuses_substituted_opaque_tip_and_intermediate_hash_ancestry() {
    let chain = event_chain();
    let mut foreign = CertifiedTestChain::start(TestChainConfig::new(World::new(), 2_000)).unwrap();
    while foreign.height() < 5 {
        foreign.commit(Vec::new());
    }
    assert_ne!(
        chain.committed(5).block_hash(),
        foreign.committed(5).block_hash()
    );
    let state = chain.state();
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let expected = chain.committed(chain.height()).block_hash();
    let hashes = state.block_hashes.view();
    let tip = *state.native_execution_tip.view().get();
    let foreign_tip = *foreign.state().native_execution_tip.view().get();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    let source = CanonicalHistorySource::new(
        chain.kura(),
        &hashes,
        foreign_tip,
        state.ivm_execution_budget(),
    );
    let (result, counts) = relation_counts::measure(|| {
        tx::read_finalized_event_carrier(
            source,
            chain.kura(),
            state.chain_id_ref(),
            *state.network_id_ref(),
            height,
            expected,
            work,
            bytes,
        )
    });
    assert!(
        matches!(result, Err(ExecutionAttemptError::Rejected(_))),
        "another actual opaque tip cannot authenticate this original hash generation"
    );
    assert!(counts.qcs.is_empty());
    // Only this State-private adversarial fixture supplies a changed journal. Public
    // event callers cannot supply a tip, journal, or independently claimed committee.
    let mut changed = hashes.iter().copied().collect::<Vec<_>>();
    let parent = height.get() - 2;
    changed[parent] = iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
        b"different original intermediate ancestry",
    ));
    let source =
        CanonicalHistorySource::new(chain.kura(), &changed, tip, state.ivm_execution_budget());
    let (result, counts) = relation_counts::measure(|| {
        tx::read_finalized_event_carrier(
            source,
            chain.kura(),
            state.chain_id_ref(),
            *state.network_id_ref(),
            height,
            expected,
            work,
            bytes,
        )
    });
    assert!(
        matches!(result, Err(ExecutionAttemptError::Rejected(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(ref message)))
        if message.contains("native execution parent contradicts State hash")),
        "the opaque tip must bind every intermediate Iroha parent before target QC authority"
    );
    assert!(counts.qcs.is_empty());
}

#[test]
fn event_carrier_returns_from_original_writer_refusal_without_waiting() {
    let chain = event_chain();
    let state = Arc::clone(chain.state());
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let expected_hash = chain.committed(chain.height()).block_hash();
    // This finite fixture allowance also admits the unchanged full-prefix baseline,
    // so an unrelated work refusal cannot stand in for the original writer refusal.
    let (work, bytes) = (100, 16 * 1024 * 1024);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (returned_tx, returned_rx) = std::sync::mpsc::channel();
    let mut job = None;
    let (entered, returned) = state.with_held_view_publication_for_reader_test(|expected_wait| {
        let source = Arc::clone(&state);
        job = Some(std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            let observed = match source.read_finalized_event_carrier(height, work, bytes) {
                Err(FinalizedEventReadError::StateView(StateViewError::Busy(wait)))
                    if wait == expected_wait =>
                {
                    Ok(true)
                }
                Ok(carrier) if carrier.block().hash() == expected_hash => Ok(false),
                Ok(_) => Err("unexpected carrier identity".to_string()),
                Err(error) => Err(format!("unexpected event refusal: {error:?}")),
            };
            returned_tx.send(observed).unwrap();
        }));
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let returned = returned_rx.recv_timeout(Duration::from_secs(2));
        (entered, returned)
    });
    // Retire the genuine writer before join/assert on every outcome: baseline
    // Ok(Ok(false)) is the original carrier, mutant Err(Timeout) is the old spin.
    job.unwrap().join().unwrap();
    assert!(entered.is_ok(), "the actual event reader entered its call");
    assert!(
        matches!(&returned, Ok(Ok(true))),
        "block-event reader must return the original State writer refusal without waiting for publication: observed {returned:?}"
    );
}

#[test]
fn event_carrier_busy_capture_retains_exact_physical_writer_release_and_no_decode_work() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let chain = event_chain();
    let state = chain.state();
    let pool = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let original_reserved = pool.reserved_bytes();
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000, 48_000_000, 1_000_000, 48_000_000, 64,
    ));
    let original_work = context.consumed_allocated_bytes();
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    chain.kura().reset_canonical_query_reads_for_test();
    let mut notice = state.state_view_publication();
    let held = state.state_write_lock.lock();
    let publication = notice.begin();
    let expected = state.state_write_lock.observe_release();
    let mut wait = None;
    for target in [NonZeroUsize::MIN, NonZeroUsize::new(2).unwrap(), height] {
        let result = context.with(|| state.read_finalized_event_carrier(target, work, bytes));
        let Err(FinalizedEventReadError::StateView(StateViewError::Busy(original))) = result else {
            panic!("every event target must retain the original busy State capture");
        };
        assert_eq!(original, expected);
        wait = Some(original);
    }
    assert_eq!(context.consumed_allocated_bytes(), original_work);
    assert_eq!(pool.reserved_bytes(), original_reserved);
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let wait = wait.unwrap();
    let mut pending = std::pin::pin!(wait.wait_for_release(&mut registration));
    let cx = &mut Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(cx).is_pending());
    // A different owner release and then visibility completion are not this writer's
    // physical retirement. Its actual release wait must remain pending through both.
    drop(state.latest_block_header.read());
    assert!(pending.as_mut().poll(cx).is_pending());
    drop(publication);
    drop(notice);
    assert!(pending.as_mut().poll(cx).is_pending());
    drop(held);
    assert!(pending.as_mut().poll(cx).is_ready());
    let carrier = state
        .read_finalized_event_carrier(height, work, bytes)
        .unwrap();
    assert!(carrier.block().belongs_to(&pool));
    assert_eq!(
        carrier.block().hash(),
        chain.committed(chain.height()).block_hash()
    );
}

#[test]
fn event_carrier_changed_capture_returns_original_release_without_retrying_new_generation() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let mut chain = event_chain();
    let state = Arc::clone(chain.state());
    let expected = state.state_write_lock.observe_release();
    let mut releases = state.block_hashes.reader_release_batch();
    let before = state.state_view_generation();
    let original_height = chain.height();
    let result = state.try_event_source(&mut releases, || {
        chain.commit(Vec::new());
    });
    let Err(StateViewError::Busy(wait)) = result else {
        panic!(
            "changed original event capture must return its writer release instead of recapturing"
        );
    };
    assert_eq!(wait, expected);
    assert_eq!(chain.height(), original_height + 1);
    assert!(state.state_view_generation() > before);
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let mut pending = std::pin::pin!(wait.wait_for_release(&mut registration));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    // This is a new explicit attempt after the original writer actually retired.
    let (hashes, tip) = state.try_event_source(&mut releases, || {}).unwrap();
    assert_eq!(hashes.len(), usize::try_from(chain.height()).unwrap());
    assert_eq!(tip.unwrap().height(), chain.height());
}

#[test]
fn event_carrier_post_read_writer_refusal_retires_carrier_and_preserves_original_cause() {
    let chain = event_chain();
    let state = Arc::clone(chain.state());
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    let (work, bytes) = exact_recent_bounds(&chain, chain.height(), chain.height());
    let pool = state.ivm_execution_budget();
    let original_reserved = pool.reserved_bytes();
    let (begin_tx, begin_rx) = std::sync::mpsc::channel();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer_state = Arc::clone(&state);
    let writer = std::thread::spawn(move || {
        if begin_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
            writer_state.with_held_view_publication_for_reader_test(|wait| {
                held_tx.send(wait).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(5));
            });
        }
    });
    let mut expected = None;
    chain.kura().reset_canonical_query_reads_for_test();
    let (result, counts) = relation_counts::measure(|| {
        state.read_finalized_event_carrier_after_read(height, work, bytes, || {
            if begin_tx.send(()).is_ok() {
                expected = held_rx.recv_timeout(Duration::from_secs(5)).ok();
            }
        })
    });
    // Always retire the real writer before classifying or asserting this read.
    let _ = release_tx.send(());
    writer.join().unwrap();
    assert!(
        expected.is_some(),
        "the original writer reached the post-read fence"
    );
    let Err(FinalizedEventReadError::StateView(StateViewError::Busy(wait))) = result else {
        panic!("post-read State publication must remain an original local refusal");
    };
    assert_eq!(Some(wait), expected);
    assert_eq!(counts.qcs, [chain.height()]);
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (3, bytes));
    assert_eq!(
        pool.reserved_bytes(),
        original_reserved,
        "a completed but unreturned carrier retires before the explicit next event attempt"
    );
    let carrier = state
        .read_finalized_event_carrier(height, work, bytes)
        .unwrap();
    assert_eq!(
        carrier.block().hash(),
        chain.committed(chain.height()).block_hash()
    );
    assert!(carrier.block().belongs_to(&pool));
}

#[test]
fn event_carrier_error_adapter_preserves_zero_work_rejection_before_busy_capture() {
    let chain = event_chain();
    let state = chain.state();
    state.with_held_view_publication_for_reader_test(|_| {
        for height in [NonZeroUsize::MIN, NonZeroUsize::new(5).unwrap()] {
            assert!(matches!(
                state.read_finalized_event_carrier(height, 0, 1),
                Err(FinalizedEventReadError::Execution(
                    ExecutionAttemptError::Rejected(
                        iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
                    )
                ))
            ));
        }
    });
}
