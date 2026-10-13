//! Original executor ownership through durable-append refusal, success, and consuming failure.
//!
//! The fixture executes actual signed genesis and the real State validator. Its four BLS keys
//! sign the real result; no synthetic genesis QC or substitute overlay is used.

use super::*;
use crate::{
    state::World,
    sumeragi::{
        block_store::KuraBlockStore,
        crypto::BlsCrypto,
        driver::traits::BlockStore as _,
        startup,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use iroha_sumeragi::preimage::payload_hash;

fn permissioned_chain() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("actual signed genesis")
}

pub(super) fn with_worker(
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ) + Send
    + 'static,
) {
    with_worker_from(permissioned_chain, ConsensusMode::Permissioned, test);
}

pub(super) fn with_worker_from(
    make_chain: impl FnOnce() -> CertifiedTestChain + Send + 'static,
    consensus_mode: ConsensusMode,
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-publication-test")
        .spawn(move || {
            let chain = make_chain();
            with_worker_chain_and_clock(
                &chain,
                consensus_mode,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                fixture_clock(&chain),
                test,
            );
        })
        .expect("spawn publication worker fixture")
        .join()
        .expect("publication worker fixture");
}

/// Construct the actual Global executor with a caller-controlled local clock.
pub(super) fn with_worker_clock(
    time_source: iroha_primitives::time::TimeSource,
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ) + Send
    + 'static,
) {
    with_worker_from_clock(
        permissioned_chain,
        ConsensusMode::Permissioned,
        time_source,
        test,
    );
}

/// Construct a genuine root with the local clock injected before any worker can execute.
pub(super) fn with_worker_from_clock(
    make_chain: impl FnOnce() -> CertifiedTestChain + Send + 'static,
    consensus_mode: ConsensusMode,
    time_source: iroha_primitives::time::TimeSource,
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-publication-test")
        .spawn(move || {
            let chain = make_chain();
            with_worker_chain_and_clock(
                &chain,
                consensus_mode,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                time_source,
                test,
            );
        })
        .expect("spawn publication worker fixture")
        .join()
        .expect("publication worker fixture");
}

/// Borrow an actual signed chain and its actual lane source on the caller's
/// Sumeragi fixture thread. Borrowed callbacks stay inside that original lifetime.
pub(super) fn with_worker_chain(
    chain: &CertifiedTestChain,
    consensus_mode: ConsensusMode,
    lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ),
) {
    with_worker_chain_and_clock(
        chain,
        consensus_mode,
        lane_blocks,
        fixture_clock(chain),
        test,
    );
}

fn fixture_clock(chain: &CertifiedTestChain) -> iroha_primitives::time::TimeSource {
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let cadence = view
        .world()
        .consensus_schedule()
        .ready(chain.height() + 1)
        .unwrap()
        .params
        .block_time_ms;
    // Each ordinary fixture signs its next work within one second of its real tip.
    // Tests of ahead/rewound clocks inject their own source through the explicit helpers.
    iroha_primitives::time::TimeSource::new_mock(
        parent.header().creation_time() + Duration::from_millis(cadence.max(1_001)),
    )
    .1
}

/// Borrow the original chain and lane source while injecting its local executor clock.
pub(super) fn with_worker_chain_and_clock(
    chain: &CertifiedTestChain,
    consensus_mode: ConsensusMode,
    lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
    time_source: iroha_primitives::time::TimeSource,
    test: impl FnOnce(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ),
) {
    let mut test = Some(test);
    with_worker_chain_erased(
        chain,
        consensus_mode,
        lane_blocks,
        time_source,
        &mut |chain, worker, blocks, events| {
            test.take().expect("the fixture consumes its callback once")(
                chain, worker, blocks, events,
            );
        },
    );
}

/// Construct the same signed fixture once per binary rather than per callback type.
/// The borrowed adapter retains each original FnOnce closure without another allocation.
#[inline(never)]
fn with_worker_chain_erased(
    chain: &CertifiedTestChain,
    consensus_mode: ConsensusMode,
    lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
    time_source: iroha_primitives::time::TimeSource,
    test: &mut dyn FnMut(
        &CertifiedTestChain,
        &mut Worker<'_>,
        &KuraBlockStore,
        &mut tokio::sync::broadcast::Receiver<EventBox>,
    ),
) {
    assert_eq!(chain.validators().len(), 4);
    let (_, certificate, _) = startup::stored_genesis(chain.state()).unwrap().unwrap();
    assert!(certificate.consensus_header().is_empty());
    assert!(
        certificate.commit_qc().is_empty(),
        "genesis carries its executed result, never a fabricated quorum"
    );
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            chain
                .validators()
                .iter()
                .map(|(peer, pop)| (peer.public_key(), pop.as_slice())),
        )
        .unwrap();
    let (events, mut receiver) = tokio::sync::broadcast::channel(1024);
    let context = ExecutorContext {
        time_source,
        state: Clone::clone(chain.state()),
        native_context_archive: Arc::new(
            crate::query::native_context_archive::NativeContextArchive::open(
                chain.state().kura(),
                chain.state().ivm_execution_budget(),
                chain.state().kura().native_context_archive_max_bytes(),
            )
            .expect("original-pool native context archive"),
        ),
        queue: None,
        staging: Staging::new(),
        events,
        genesis_account: chain.genesis_account().clone(),
        consensus_mode,
        root_scope: chain.root_scope(),
        applied: (chain.height(), chain.committed(chain.height()).core_hash()),
        crypto: Some(Clone::clone(&crypto)),
        applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(1, None)),
        lane_blocks,
    };
    let schedule = Arc::new(
        crate::sumeragi::runtime_availability::NativeGlobalAvailability::new(
            Clone::clone(chain.state()),
            chain.instance(),
            Clone::clone(&crypto),
        )
        .unwrap(),
    );

    let blocks = KuraBlockStore::new(
        Clone::clone(chain.kura()),
        crypto,
        1,
        chain.root_scope(),
        context.staging.clone(),
        context.state.ivm_execution_budget(),
        schedule,
    );
    let mut worker = Worker {
        payload_build: None,
        signature_decode: None,
        routing_refusal: None,
        payload_refusal: None,
        context: &context,
        state: &context.state,
        applied: context.applied,
        live: None,
        finishing: None,
        results: BTreeMap::new(),
        completed_payload: None,
        assembly_parent_service: None,
        queue: None,
        recovery: None,
        beacon: None,
        archives: None,
        pending_commit: None,
        completed_replay: None,
        quarantine_context: None,
    };
    test(chain, &mut worker, &blocks, &mut receiver);
}

pub(super) fn proposal(chain: &CertifiedTestChain, worker: &Worker<'_>) -> AvailableBody {
    proposal_with_transaction(chain, worker, CertifiedTestChain::tick)
}

#[test]
fn payload_decode_refusal_retains_available_owner_without_negative_cache() {
    use iroha_data_model::block::BlockSignatures;

    with_worker(|chain, worker, _blocks, events| {
        let block = proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let source = std::ptr::from_ref(block.source());
        let payload = block.payload().as_slice().as_ptr();
        let budget = worker.state.ivm_execution_budget();
        let state_height = worker.state.view().height();
        assert!(block.admitted_to(&budget));
        // Pin only the refusal observations: unrelated MV reclamation must not change the
        // baseline while this test measures the request's exact retained decode controls.
        let epoch = crossbeam_epoch::pin();
        let retained = budget.reserved_bytes();
        let decoder_controls = norito::core::PreparedDecodeWorkspace::allocation_layouts()
            .iter()
            .map(core::alloc::Layout::size)
            .sum::<usize>();
        let signature_control = BlockSignatures::allocation_layout().size();
        let mut original_decode_owner = None;
        let mut original_signature_control = None;
        // The first field-byte refusal precedes the empty signature leaf. The
        // allocation refusal completes that exact zero-count control, and the
        // later depth refusal must retain it without reconstructing the leaf.
        for (limits, signatures_completed) in [
            (
                norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64),
                false,
            ),
            (
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 64),
                true,
            ),
            (
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
                true,
            ),
        ] {
            let error = norito::with_decode_limits_scope(limits, || {
                iroha_data_model::block::decode_framed_signed_block(block.payload().as_slice())
            })
            .unwrap_err();
            assert!(
                error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit,
                "{error:?}"
            );
            let payload::PayloadError::DecodeResource(refusal) =
                norito::with_decode_limits_scope(limits, || {
                    payload::decode(block.payload().as_slice())
                })
                .unwrap_err()
            else {
                panic!("an enclosing decoder limit retains its local refusal");
            };
            assert_eq!(
                refusal.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            let original = refusal
                .decode_refusal()
                .expect("payload decoding retains the original opaque refusal");
            assert_eq!(
                original.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            // Separate decoding attempts have distinct opaque identities, but
            // the same input and limits must refuse at the same resource bound.
            assert_eq!(
                original.resource_error(),
                error.local_refusal().unwrap().resource_error()
            );
            let outcome =
                norito::with_decode_limits_scope(limits, || worker.execute(&block, hash, false));
            assert!(
                matches!(outcome, Some(ExecOutcome::Failed(_))),
                "local payload decode refusal must defer, got {outcome:?}; negatively cached: {}",
                worker.results.contains_key(&hash)
            );
            assert!(!worker.results.contains_key(&hash));
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.recovery.is_none());
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), state_height);
            assert_eq!(std::ptr::from_ref(block.source()), source);
            assert_eq!(block.payload().as_slice().as_ptr(), payload);
            assert!(block.admitted_to(&budget));
            // Every refusal retains both original workspace controls. Only
            // a completed leaf owns the additional exact signature control.
            let attempt = worker.signature_decode.as_ref().unwrap();
            assert_eq!(attempt.block_hash, hash);
            assert_eq!(attempt.source, block);
            assert_eq!(attempt.source.payload().as_slice().as_ptr(), payload);
            assert!(attempt.decoder.belongs_to(&budget));
            let decode_owner = (
                std::ptr::from_ref(attempt.source.source()),
                std::ptr::from_ref(&attempt.decoder),
            );
            assert_eq!(
                *original_decode_owner.get_or_insert(decode_owner),
                decode_owner
            );
            let signatures = attempt
                .decoder
                .retained_signatures(
                    block
                        .payload()
                        .charged_source(&budget)
                        .expect("original funded body source"),
                )
                .unwrap();
            if signatures_completed {
                let signatures =
                    signatures.expect("this refusal follows original signature completion");
                assert!(signatures.is_empty());
                assert!(signatures.admitted_to(&budget));
                let original = original_signature_control.get_or_insert_with(|| signatures.clone());
                assert!(BlockSignatures::ptr_eq(original, signatures));
            } else {
                assert!(signatures.is_none());
                assert!(original_signature_control.is_none());
            }
            assert_eq!(
                budget.reserved_bytes(),
                retained + decoder_controls + usize::from(signatures_completed) * signature_control
            );
        }
        drop(epoch);
        assert!(matches!(
            worker.execute(&block, hash, false),
            Some(ExecOutcome::Valid { .. })
        ));
        assert!(!worker.results.contains_key(&hash));
        assert!(worker.signature_decode.is_none());
        assert_eq!(std::ptr::from_ref(block.source()), source);
        assert_eq!(block.payload().as_slice().as_ptr(), payload);
        assert!(block.admitted_to(&budget));
        assert_eq!(
            worker.state.view().height(),
            state_height,
            "execution has not published"
        );
    });
}

#[test]
fn original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry() {
    with_worker_from(
        || {
            use iroha_data_model::parameter::{
                Parameter,
                system::{SumeragiConsensusMode, SumeragiNposParameters},
            };
            let mut config = TestChainConfig::new(World::new(), 1_000);
            config.consensus_mode = SumeragiConsensusMode::Npos;
            config.genesis_parameters.push(Parameter::Custom(
                SumeragiNposParameters {
                    slashing_delay_blocks: 1,
                    ..SumeragiNposParameters::default()
                }
                .into_custom_parameter(),
            ));
            CertifiedTestChain::start(config).expect("actual four-validator NPoS genesis")
        },
        ConsensusMode::Npos,
        |chain, worker, _blocks, events| {
            use crate::state::EvidencePreparationError;
            use std::task::Context;
            let transaction = chain.tick(2_000);
            let original_hash = transaction.hash_as_entrypoint();
            let (_, time) =
                iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
                &time,
            )
            .unwrap();
            queue.push(accepted, chain.state().view()).unwrap();
            worker.queue = Some(Clone::clone(&queue));
            let (due, requested_bytes) =
                super::super::penalties::pending_payload_penalty_fixture(worker.state);
            let original = worker
                .state
                .world
                .consensus_evidence
                .view()
                .get(&due)
                .cloned()
                .unwrap();
            let budget = worker.state.evidence_preparation_budget();
            let mut registration = crate::unit_test_support::release_registration(budget);
            let observer_bytes = budget.reserved_bytes();
            let occupied_bytes = budget.limit_bytes() - observer_bytes - requested_bytes + 1;
            let blocking_owner = budget.try_reserve_bytes(occupied_bytes).unwrap();
            let header = iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::new(2).unwrap(),
                None,
                None,
                2_001,
                0,
            );
            let original_error = super::super::penalties::PenaltyApplier::new(worker.state, None)
                .derive_npos_consensus_effects(&header)
                .unwrap_err();
            let EvidencePreparationError::Admission(original_allocation) = original_error
                .downcast_ref::<EvidencePreparationError>()
                .unwrap()
            else {
                panic!("the original evidence pool must refuse its actual due-entry backing");
            };
            let original_refusal: crate::execution_attempt::ExecutionDeferred =
                original_allocation.clone().into();
            let returned = worker.build(2, 0, 1 << 20, 100);
            let Err(PublicationError::Deferred(returned)) = returned else {
                panic!("original staking capacity must reach the driver as a typed deferral");
            };
            assert_eq!(returned.allocation_refusal(), Some(original_allocation));
            assert_eq!(
                returned,
                PublicationDeferral::EvidencePreparation(
                    original_error
                        .downcast_ref::<EvidencePreparationError>()
                        .unwrap()
                        .clone()
                )
            );
            assert_eq!(
                worker.routing_refusal.as_ref(),
                Some(&original_refusal),
                "the payload worker retains the same evidence-pool release owner"
            );
            assert!(matches!(
                worker.payload_refusal.as_ref(),
                Some(payload::PayloadError::StakingPreparation(refusal))
                    if Some(refusal) == original_error.downcast_ref::<EvidencePreparationError>()
            ));
            let iroha_allocation::AllocationRefusal::Capacity { release, .. } = worker
                .routing_refusal
                .as_ref()
                .unwrap()
                .allocation_refusal()
                .unwrap()
            else {
                panic!("the original occupied pool remains retryable");
            };
            let release = release.clone();
            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(registration.poll_wait(&release, &mut context).is_pending());
            assert_eq!(budget.reserved_bytes(), occupied_bytes + observer_bytes);
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert_eq!(
                worker.state.world.consensus_evidence.view().get(&due),
                Some(&original)
            );
            assert_eq!(worker.state.view().height(), 1);
            assert!(worker.payload_build.is_none());
            assert!(worker.completed_payload.is_none());
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.pending_commit.is_none());
            assert!(worker.recovery.is_none());
            assert!(events.try_recv().is_err());
            drop(blocking_owner);
            assert!(registration.poll_wait(&release, &mut context).is_ready());
            let Some(bytes) = worker.build(2, 0, 1 << 20, 100).unwrap() else {
                panic!("the exact original queued work retries after the original release");
            };
            assert!(worker.routing_refusal.is_none());
            assert!(worker.payload_refusal.is_none());
            let proposal = payload::decode(bytes.as_slice()).unwrap();
            assert_eq!(
                proposal.external_entrypoints_slice()[0].hash(),
                original_hash
            );
            assert!(
                matches!(proposal.npos_consensus_effects().unwrap().penalty_actions.as_slice(),
                [iroha_data_model::consensus::NposPenaltyAction::MarkConsensusEvidenceApplied(mark)] if mark.evidence_key == due && mark.height == 2)
            );
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert_eq!(
                worker.state.world.consensus_evidence.view().get(&due),
                Some(&original)
            );
            assert_eq!(worker.state.view().height(), 1);
            drop(registration);
            assert_eq!(budget.reserved_bytes(), 0);
            assert!(events.try_recv().is_err());
        },
    );
}

#[test]
fn malformed_available_payload_remains_invalid_and_negatively_cached() {
    with_worker(|chain, worker, _blocks, events| {
        let original = proposal(chain, worker);
        let mut malformed = original.payload().as_slice().to_vec();
        malformed.pop().unwrap();
        let mut header = original.header().clone();
        header.payload_hash = payload_hash(&**worker.context.crypto.as_ref().unwrap(), &malformed);
        header.payload_len = u32::try_from(malformed.len()).unwrap();
        // Availability is genuine for these malformed application bytes. Its signatures
        // authenticate custody, not the nested block's validity.
        let block = chain.author_payload(header, malformed);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let state_height = worker.state.view().height();
        assert!(matches!(
            payload::decode(block.payload().as_slice()),
            Err(payload::PayloadError::NotCanonical(_))
        ));
        assert!(matches!(
            worker.execute(&block, hash, false),
            Some(ExecOutcome::Invalid)
        ));
        let (source, outcome) = worker
            .results
            .get(&hash)
            .expect("deterministic negative verdict");
        assert_eq!(source, block.source());
        assert!(matches!(outcome, ExecOutcome::Invalid));
        let limits = norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 64);
        assert!(matches!(
            norito::with_decode_limits_scope(limits, || worker.execute(&block, hash, false)),
            Some(ExecOutcome::Invalid)
        ));
        assert_eq!(worker.results.len(), 1);
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), state_height);
    });
}

pub(super) fn proposal_with_transaction(
    chain: &CertifiedTestChain,
    worker: &Worker<'_>,
    transaction: impl FnOnce(
        &CertifiedTestChain,
        u64,
    ) -> iroha_data_model::transaction::SignedTransaction,
) -> AvailableBody {
    proposal_with_transactions(chain, worker, |chain, time| vec![transaction(chain, time)])
}

/// Assemble separately signed original inputs through the same admission owner.
pub(super) fn proposal_with_transactions(
    chain: &CertifiedTestChain,
    worker: &Worker<'_>,
    transactions: impl FnOnce(
        &CertifiedTestChain,
        u64,
    ) -> Vec<iroha_data_model::transaction::SignedTransaction>,
) -> AvailableBody {
    let height = worker.applied.0 + 1;
    let certified_parent = chain.committed(worker.applied.0);
    let scheduled = worker.scheduled(height).unwrap().height_config().unwrap();
    let crypto = worker.context.crypto.as_ref().unwrap();
    let view = chain.state().view();
    let parent = view
        .latest_block()
        .expect("completed original State parent read")
        .unwrap();
    let cadence = Duration::from_millis(scheduled.params.block_time);
    let block_time = parent.header().creation_time() + cadence;
    let transactions = transactions(chain, u64::try_from(block_time.as_millis()).unwrap() - 1);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(block_time);
    let accepted = transactions
        .into_iter()
        .map(|tx| {
            crate::tx::AcceptedTransaction::accept_with_time_source(
                tx,
                &chain.network_id(),
                Duration::from_secs(1),
                view.world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
                &time,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    drop(view);
    let proposal = payload::assemble(
        chain.state(),
        Assembly {
            parent: &parent,
            view: 0,
            cadence,
            proposed_time: block_time,
        },
        &accepted,
    )
    .unwrap();
    let payload = payload::encode(&proposal).unwrap();
    chain.author_payload(
        iroha_sumeragi::message::BlockHeader {
            instance: chain.instance(),
            epoch: scheduled.epoch.id,
            height,
            origin_view: 0,
            parent_hash: certified_parent.core_hash(),
            parent_result: certified_parent.result(),
            payload_hash: payload_hash(&**crypto, &payload),
            payload_len: u32::try_from(payload.len()).unwrap(),
            availability_digest: Hash32::ZERO,
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: iroha_sumeragi::types::ControlWitness::empty(),
        },
        payload,
    )
}

pub(super) fn executed(chain: &CertifiedTestChain, worker: &mut Worker<'_>) -> (AvailableBody, Qc) {
    let block = proposal(chain, worker);
    execute_proposal(chain, worker, block)
}

fn execute_proposal(
    chain: &CertifiedTestChain,
    worker: &mut Worker<'_>,
    block: AvailableBody,
) -> (AvailableBody, Qc) {
    let crypto = worker.context.crypto.as_ref().unwrap();
    let block_hash = block.hash(&**crypto);
    let Some(ExecOutcome::Valid { result, .. }) = worker.execute(&block, block_hash, false) else {
        panic!("original native validation must succeed")
    };
    let height = block.header().height;
    let qc = chain.commit_qc(height, block_hash, result, Signers::Quorum);
    let committee = worker
        .scheduled(height)
        .unwrap()
        .height_config()
        .unwrap()
        .committee;
    iroha_sumeragi::crypto::Verifier::new(
        &**worker.context.crypto.as_ref().unwrap(),
        &chain.instance(),
        &block.header().epoch,
        &committee,
    )
    .verify_qc(&qc)
    .unwrap();
    (block, qc)
}

fn original_overlay(worker: &Worker<'_>) -> usize {
    std::ptr::from_ref(worker.live.as_ref().unwrap().overlay.as_deref().unwrap()) as usize
}

#[test]
fn replay_completion_retirement_keeps_exact_source_and_original_pool_retry() {
    use iroha_sumeragi::availability::{AvailabilitySource, BodyRestoration};

    // Keep this chain's retired MV generations alive while comparing exact pool usage.
    // The global EBR collector may otherwise refund them between two retry observations;
    // replay scratch still has to release its own original-pool charges immediately.
    let _retirement_pin = crossbeam_epoch::pin();
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let alternate = chain.commit_qc(2, qc.block_hash, qc.result, Signers::LastThree);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        assert!(
            worker.live.is_none(),
            "the large Published owner is retired"
        );
        assert!(worker.finishing.is_none());
        assert!(worker.pending_commit.is_none());
        assert!(worker.completed_replay.is_some());
        assert!(worker.context.staging.get(&qc.block_hash).is_none());
        let mut emitted = 0;
        while events.try_recv().is_ok() {
            emitted += 1;
        }
        assert!(emitted > 0, "the original publication emits real events");
        let budget = worker.state.ivm_execution_budget();
        let retained = budget.reserved_bytes();
        worker.replay(&block, &qc).unwrap();
        assert_eq!(budget.reserved_bytes(), retained);
        assert!(events.try_recv().is_err());
        assert!(worker.replay(&block, &alternate).is_err());
        for field in 0..6 {
            let mut changed = qc.clone();
            match field {
                0 => changed.agg_sig.0[0] ^= 1,
                1 => changed.result.0[0] ^= 1,
                2 => changed.instance.0[0] ^= 1,
                3 => changed.epoch.context.0[0] ^= 1,
                4 => changed.view += 1,
                _ => changed.kind = iroha_sumeragi::message::VoteKind::Prepare,
            }
            assert!(worker.replay(&block, &changed).is_err());
        }
        // Equal voting authority and exact signed body still do not authorize
        // replacement chain parameters after the original schedule has retired.
        for field in 0..6 {
            let mut config = block.source().config().clone();
            match field {
                0 => config.params.block_time += 1,
                1 => config.params.payload_retry_interval += 1,
                2 => config.params.e_max += 1,
                3 => config.params.a_max += 1,
                4 => config.params.max_block_bytes += 1,
                _ => config.params.epoch_length += 1,
            }
            let source = AvailabilitySource::new(
                block.source().instance(),
                block.source().height(),
                block.source().block_hash(),
                config,
            )
            .unwrap();
            let rebound = BodyRestoration::new(
                source,
                block.header().clone(),
                block.availability().clone(),
                block.payload().clone(),
            )
            .complete(&budget, &**worker.context.crypto.as_ref().unwrap())
            .map_err(|(_, error)| error)
            .expect("availability is valid under equal signing authority");
            assert!(worker.replay(&rebound, &qc).is_err());
        }
        assert_eq!(worker.state.committed_height(), 2);
        assert_eq!(budget.reserved_bytes(), retained);
        assert!(events.try_recv().is_err());

        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let held = budget.reserved_bytes();
        let refusal = worker.replay(&block, &qc).unwrap_err();
        let PublicationError::Deferred(original) = refusal else {
            panic!("replay must retain the original encoding allocation refusal");
        };
        assert!(original.allocation_refusal().is_some());
        assert_eq!(budget.reserved_bytes(), held);
        assert!(worker.completed_replay.is_some());
        assert!(worker.live.is_none());
        assert!(events.try_recv().is_err());
        drop(occupied);
        worker.replay(&block, &qc).unwrap();
        assert_eq!(budget.reserved_bytes(), retained);
        assert!(worker.routing_refusal.is_none());
        assert!(events.try_recv().is_err());

        // A certificate or serialized tip claim alone cannot recreate the
        // private evidence issued by the original completed replay.
        let original = worker.completed_replay.take().unwrap();
        assert!(worker.replay(&block, &qc).is_err());
        worker.completed_replay = Some(original);
        let applied = worker.applied;
        worker.applied.1.0[0] ^= 1;
        assert!(worker.replay(&block, &qc).is_err());
        worker.applied = applied;
        worker.replay(&block, &qc).unwrap();
        assert!(worker.live.is_none());
        assert!(events.try_recv().is_err());
    });
}

#[cfg(feature = "telemetry")]
#[test]
fn canonical_replay_origin_retains_transition_idempotence_through_publication_retry() {
    use iroha_data_model::{
        governance::types::{
            AbiVersion, ContractAbiHash, ContractCodeHash, DeployContractProposal, ProposalKind,
        },
        isi::governance::{
            CreateParliamentGovernanceAttemptV1, ParliamentLifecycleTransitionV1,
            SubmitParliamentLifecycleTransitionV1,
        },
        permission::Permission,
        prelude::InstructionBox,
    };
    use iroha_executor_data_model::permission::governance::CanManageParliament;
    use mv::storage::StorageReadOnly as _;
    use std::collections::BTreeSet;

    for origin in [
        CommitTelemetryOrigin::Forward,
        CommitTelemetryOrigin::HistoricalReplay,
    ] {
        let manager =
            iroha_crypto::KeyPair::from_seed(vec![0xCE; 32], iroha_crypto::Algorithm::Ed25519);
        let manager_account =
            iroha_data_model::account::AccountId::new(manager.public_key().clone());
        let create = CreateParliamentGovernanceAttemptV1 {
            proposal: ProposalKind::DeployContract(DeployContractProposal {
                proposal_operator: manager_account.clone(),
                contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                    .parse()
                    .unwrap(),
                code_hash: ContractCodeHash::new([0x31; 32]),
                abi_hash: ContractAbiHash::new([0x41; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            }),
            attempt_sequence: 0,
        };
        let seeded_proposal = create.proposal.clone();
        with_worker_from(
            move || {
                // Fix the initial proposal and manager in World before the actual
                // signed genesis is executed. No post-genesis source is replaced.
                let mut world = World::new();
                world.account_permissions.insert(
                    manager_account.clone(),
                    BTreeSet::from([Permission::from(CanManageParliament)]),
                );
                world.governance_proposals.insert(
                    seeded_proposal.fingerprint(),
                    crate::state::GovernanceProposalRecord {
                        proposer: manager_account,
                        kind: seeded_proposal,
                        created_height: 1,
                        status: crate::state::GovernanceProposalStatus::Proposed,
                    },
                );
                // Parliament attempt creation freezes the consensus-native NPoS pulse cadence,
                // so the governance World is fixed under an actual signed NPoS genesis.
                let mut config = TestChainConfig::new(world, 1_000);
                config.consensus_mode =
                    iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
                config
                    .genesis_parameters
                    .push(iroha_data_model::parameter::Parameter::Custom(
                        iroha_data_model::parameter::system::SumeragiNposParameters {
                            slashing_delay_blocks: 1,
                            ..Default::default()
                        }
                        .into_custom_parameter(),
                    ));
                CertifiedTestChain::start(config)
                    .expect("actual signed NPoS genesis with initial governance World")
            },
            ConsensusMode::Npos,
            move |chain, worker, blocks, _| {
                // Signed instructions create the real reducer state and event before
                // the original execution witness and publication surface are captured.
                let attempt_id = create.governance_attempt_id();
                let transition = SubmitParliamentLifecycleTransitionV1 {
                    governance_attempt_id: attempt_id,
                    transition: ParliamentLifecycleTransitionV1::CompleteQualification,
                };
                let body = proposal_with_transaction(chain, worker, |chain, created_ms| {
                    chain.sign(
                        &manager,
                        [
                            InstructionBox::from(create),
                            InstructionBox::from(transition),
                        ],
                        created_ms,
                    )
                });
                let (block, qc) = execute_proposal(chain, worker, body);
                let stage = worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_ref()
                    .unwrap()
                    .world
                    .parliament_attempts
                    .get(&attempt_id)
                    .expect("signed Parliament instructions executed")
                    .attempt()
                    .stage;
                assert_ne!(
                    stage,
                    iroha_data_model::governance::types::GovernanceStageV1::Qualification,
                    "the actual reducer completed qualification before witness capture"
                );
                worker.prepare_with_origin(&block, &qc, origin).unwrap();
                let original = original_overlay(worker);
                let other = match origin {
                    CommitTelemetryOrigin::Forward => CommitTelemetryOrigin::HistoricalReplay,
                    CommitTelemetryOrigin::HistoricalReplay => CommitTelemetryOrigin::Forward,
                };
                assert!(worker.prepare_with_origin(&block, &qc, other).is_err());
                assert_eq!(original_overlay(worker), original);
                blocks.append(&block, &qc).unwrap();
                let metric = chain
                    .state()
                    .telemetry
                    .governance_parliament_transitions_total
                    .with_label_values(&["complete_qualification"]);
                assert_eq!(metric.get(), 0);
                for _ in 0..2 {
                    chain.state().with_publication_blocked_for_test(|| {
                        assert!(matches!(
                            worker.commit(&block, &qc),
                            Err(PublicationError::Deferred(
                                PublicationDeferral::PublicationBusy(_)
                            ))
                        ));
                    });
                    assert_eq!(
                        metric.get(),
                        0,
                        "refusal cannot publish transition observations"
                    );
                    assert_eq!(original_overlay(worker), original);
                    assert_eq!(
                        worker.prepare_with_origin(&block, &qc, origin).unwrap(),
                        Some(qc.result)
                    );
                    assert!(worker.prepare_with_origin(&block, &qc, other).is_err());
                }
                worker.commit(&block, &qc).unwrap();
                assert_eq!(
                    chain
                        .state()
                        .view()
                        .world()
                        .parliament_attempts()
                        .get(&attempt_id)
                        .unwrap()
                        .attempt()
                        .stage,
                    stage,
                    "both origins publish the same authenticated transition state"
                );
                let expected = u64::from(origin == CommitTelemetryOrigin::Forward);
                assert_eq!(metric.get(), expected);
                worker.commit(&block, &qc).unwrap();
                assert_eq!(
                    metric.get(),
                    expected,
                    "the original publication completes once"
                );
            },
        );
    }
}

#[test]
fn prepared_block_moves_original_graph_and_rejects_replaced_shared_control() {
    with_worker(|chain, worker, blocks, events| {
        let (body, qc) = executed(chain, worker);
        let original_entries = match &worker.live.as_ref().unwrap().phase {
            PublicationPhase::Executed { valid, .. } => {
                let entries = valid.as_ref().external_entrypoints_slice();
                assert!(
                    !entries.is_empty(),
                    "genuine signed work owns a concrete graph"
                );
                entries.as_ptr()
            }
            _ => panic!("original executed graph"),
        };
        worker.prepare(&body, &qc).unwrap();
        let original = worker.context.staging.get(&qc.block_hash).unwrap();
        assert_eq!(
            original.executed.external_entrypoints_slice().as_ptr(),
            original_entries
        );
        let PublicationPhase::Prepared {
            committed, staged, ..
        } = &worker.live.as_ref().unwrap().phase
        else {
            panic!("original prepared owner");
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            committed.shared(),
            &original.executed
        ));
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &staged.executed,
            &original.executed
        ));
        let budget = worker.state.ivm_execution_budget();
        assert!(original.executed.belongs_to(&budget));
        blocks.append(&body, &qc).unwrap();
        let stored = chain
            .kura()
            .get_block(std::num::NonZeroUsize::new(2).unwrap(), &budget)
            .unwrap()
            .unwrap();
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &stored,
            &original.executed
        ));
        // Identical canonical content and the right pool cannot replace original execution custody.
        let replacement = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
            .unwrap()
            .initialize(original.executed.as_ref().clone());
        assert_eq!(
            replacement.encode_wire().unwrap(),
            original.executed.encode_wire().unwrap()
        );
        assert!(
            replacement
                .commit_certificate()
                .unwrap()
                .admitted_to(&budget)
        );
        assert!(!iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &replacement,
            &original.executed
        ));
        let PublicationPhase::Prepared { staged, .. } = &mut worker.live.as_mut().unwrap().phase
        else {
            panic!("same prepared owner");
        };
        staged.executed = replacement;
        let error = worker
            .commit(&body, &qc)
            .expect_err("same bytes cannot replace original shared execution");
        assert!(matches!(error, PublicationError::RecoveryRequired(_)));
        assert_eq!(worker.state.committed_height(), 1);
        assert!(worker.live.as_ref().unwrap().overlay.is_some());
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn reversible_publication_refusal_retains_original_overlay_capture_and_certified_frame() {
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let overlay = original_overlay(worker);
        let witness = iroha_crypto::HashOf::new(
            worker
                .live
                .as_ref()
                .unwrap()
                .witness
                .as_ref()
                .unwrap()
                .wire(),
        );
        let context = worker
            .live
            .as_ref()
            .unwrap()
            .commitment()
            .get()
            .commitment()
            .schedule
            .current
            .committee
            .as_ptr();
        let preimage = match &worker.live.as_ref().unwrap().phase {
            PublicationPhase::Executed { preimage, .. } => preimage.as_slice().as_ptr(),
            _ => panic!("new original execution"),
        };
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
        let original = worker.context.staging.get(&qc.block_hash).unwrap();
        let certificate = original.executed.commit_certificate().unwrap();
        assert_eq!(
            certificate.result_preimage().as_ptr(),
            preimage,
            "the original captured R allocation moved into its sole certificate"
        );
        let bytes = original.executed.encode_wire().unwrap();
        let pending_events = worker.live.as_ref().unwrap().events.len();
        for _ in 0..3 {
            let error = worker.commit(&block, &qc).unwrap_err();
            assert!(matches!(&error, PublicationError::Retryable(_)));
            assert!(error.to_string().contains("durably stored"));
            assert!(worker.recovery.is_none());
            assert_eq!(original_overlay(worker), overlay);
            assert_eq!(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .commitment()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                context,
                "publication retry retains the original canonical authority allocation"
            );
            assert_eq!(
                iroha_crypto::HashOf::new(
                    worker
                        .live
                        .as_ref()
                        .unwrap()
                        .witness
                        .as_ref()
                        .unwrap()
                        .wire()
                ),
                witness
            );
            assert_eq!(worker.live.as_ref().unwrap().events.len(), pending_events);
            assert!(
                events.try_recv().is_err(),
                "authorization refusal publishes no events"
            );
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
            let retry = worker.context.staging.get(&qc.block_hash).unwrap();
            assert_eq!(retry.block_hash, original.block_hash);
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                &retry.executed,
                &original.executed
            ));
            assert!(std::ptr::eq(
                retry.executed.commit_certificate().unwrap(),
                certificate
            ));
        }
        blocks.append(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        assert_eq!(original.executed.encode_wire().unwrap(), bytes);
        let next = worker.commit(&block, &qc).unwrap();
        assert_eq!(worker.state.view().height(), 2);
        assert_eq!(worker.applied, (2, qc.block_hash));
        assert!(worker.live.as_ref().unwrap().overlay.is_none());
        let mut emitted = 0;
        while events.try_recv().is_ok() {
            emitted += 1;
        }
        assert!(
            emitted > 0,
            "actual validation/application emits its events once"
        );
        assert_eq!(worker.commit(&block, &qc).unwrap(), next);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
        assert_eq!(worker.commit(&block, &qc).unwrap(), next);
        assert!(
            events.try_recv().is_err(),
            "completed retry cannot duplicate side effects"
        );
        assert_eq!(blocks.entry(2).unwrap().unwrap().commit_qc, qc);
    });
}

#[test]
fn prepared_certificate_cannot_be_rebound_to_another_epoch_context() {
    with_worker(|chain, worker, blocks, _| {
        let (block, qc) = executed(chain, worker);
        let overlay = original_overlay(worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        let staged = worker.context.staging.get(&qc.block_hash).unwrap();
        let mut changed = qc.clone();
        changed.epoch.context.0[0] ^= 1;
        assert!(worker.prepare(&block, &changed).is_err());
        assert!(worker.commit(&block, &changed).is_err());
        assert_eq!(original_overlay(worker), overlay);
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &staged.executed,
            &worker.context.staging.get(&qc.block_hash).unwrap().executed
        ));
        assert_eq!(worker.state.committed_height(), 1);
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert_eq!(worker.state.committed_height(), 2);
    });
}

#[test]
fn preparation_pins_original_even_against_discard_replacement_and_another_valid_quorum() {
    with_worker(|chain, worker, blocks, _| {
        let (block, qc) = executed(chain, worker);
        let overlay = original_overlay(worker);
        worker.prepare(&block, &qc).unwrap();
        let original = worker.context.staging.get(&qc.block_hash).unwrap();
        worker.discard(2, &[]);
        assert_eq!(original_overlay(worker), overlay);
        let mut competing_header = block.header().clone();
        competing_header.origin_view += 1;
        let competing = chain.author_payload(competing_header, block.payload().as_slice().to_vec());
        let hash = competing.hash(&**worker.context.crypto.as_ref().unwrap());
        assert!(matches!(
            worker.execute(&competing, hash, false),
            Some(ExecOutcome::Failed(_))
        ));
        assert_eq!(original_overlay(worker), overlay);
        let alternate = chain.commit_qc(2, qc.block_hash, qc.result, Signers::LastThree);
        let committee = worker
            .scheduled(2)
            .unwrap()
            .height_config()
            .unwrap()
            .committee;
        iroha_sumeragi::crypto::Verifier::new(
            &**worker.context.crypto.as_ref().unwrap(),
            &chain.instance(),
            &block.header().epoch,
            &committee,
        )
        .verify_qc(&alternate)
        .unwrap();
        assert!(worker.prepare(&block, &alternate).is_err());
        assert!(worker.commit(&block, &alternate).is_err());
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &worker.context.staging.get(&qc.block_hash).unwrap().executed,
            &original.executed
        ));
        blocks.append(&block, &qc).unwrap();
        let original_wire = chain
            .kura()
            .get_block(
                std::num::NonZeroUsize::new(2).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .unwrap()
            .encode_wire()
            .unwrap();
        assert!(
            blocks.append(&block, &alternate).is_err(),
            "durable retry cannot replace the prepared certificate"
        );
        blocks.append(&block, &qc).unwrap();
        assert_eq!(blocks.committed_body(2).unwrap().unwrap().1, qc);
        assert_eq!(
            chain
                .kura()
                .get_block(
                    std::num::NonZeroUsize::new(2).unwrap(),
                    &chain.state().ivm_execution_budget()
                )
                .expect("original block read attempt")
                .unwrap()
                .encode_wire()
                .unwrap(),
            original_wire,
            "refusal and exact retry retain the complete original durable frame"
        );
        worker.commit(&block, &qc).unwrap();
    });
}

#[test]
fn mismatching_certified_result_reports_original_without_reexecuting_or_pinning_it() {
    with_worker(|chain, worker, _, _| {
        let (block, qc) = executed(chain, worker);
        let overlay = original_overlay(worker);
        let other_result = chain.commit_qc(2, qc.block_hash, Hash32([0x71; 32]), Signers::Quorum);
        assert_eq!(
            worker.prepare(&block, &other_result).unwrap(),
            Some(qc.result)
        );
        assert_eq!(original_overlay(worker), overlay);
        assert!(worker.context.staging.get(&qc.block_hash).is_none());
        assert!(matches!(
            worker.live.as_ref().unwrap().phase,
            PublicationPhase::Executed { .. }
        ));
        worker.prepare(&block, &qc).unwrap();
        assert_eq!(original_overlay(worker), overlay);
    });
}

#[test]
fn consuming_publication_failure_blocks_every_reexecution_path() {
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let original = worker.context.staging.get(&qc.block_hash).unwrap();
        let mut consumed = 0;
        let failure = worker
            .commit_with(&block, &qc, |overlay| {
                consumed += 1;
                StateBlock::fail_publication_after_preparation_for_test();
                overlay.try_publish()
            })
            .unwrap_err();
        assert_eq!(consumed, 1);
        assert!(matches!(failure, PublicationError::RecoveryRequired(_)));
        assert!(
            worker.live.as_ref().unwrap().overlay.is_some(),
            "terminal recovery retains its original allocation"
        );
        assert_eq!(worker.state.view().height(), 1);
        assert!(worker.prepare(&block, &qc).is_err());
        assert!(worker.commit(&block, &qc).is_err());
        assert!(matches!(
            worker.execute(&block, qc.block_hash, false),
            Some(ExecOutcome::Failed(_))
        ));
        worker.discard(2, &[]);
        worker.reject(2, 0, qc.block_hash);
        assert!(matches!(
            worker.build(2, 0, 1024, 100),
            Err(PublicationError::RecoveryRequired(_))
        ));
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &worker.context.staging.get(&qc.block_hash).unwrap().executed,
            &original.executed
        ));
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn panic_after_actual_visibility_is_local_recovery_never_success_or_reexecution() {
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let result = worker.commit_with(&block, &qc, |overlay| {
            assert!(
                matches!(
                    overlay.try_publish(),
                    crate::state::StatePublicationOutcome::Published
                ),
                "actual State publication succeeds"
            );
            panic!("injected failure after State visibility");
        });
        assert!(matches!(result, Err(PublicationError::RecoveryRequired(_))));
        assert_eq!(
            worker.state.view().height(),
            2,
            "the failure happened after real visibility"
        );
        assert_eq!(
            worker.applied.0, 1,
            "no successful completion was advertised"
        );
        assert!(worker.prepare(&block, &qc).is_err());
        assert!(worker.commit(&block, &qc).is_err());
        assert!(matches!(
            worker.execute(&block, qc.block_hash, false),
            Some(ExecOutcome::Failed(_))
        ));
        let (reply, response) = mpsc::sync_channel(1);
        worker.serve(Request::Commit(block, qc, reply));
        assert!(
            response.recv().unwrap().is_err(),
            "actual request dispatcher retains recovery"
        );
        assert!(events.try_recv().is_err());
    });
}

/// The actual original State owner reports its consuming failure through the production kernel.
#[test]
fn original_worker_consuming_failure_halts_driver_status_without_reexecution() {
    use crate::sumeragi::driver::{
        Completion, DriverConfig, Kernel, KernelStart, Op,
        exec::{ExecDone, ExecOp},
        ingress::{Ingress, IngressLimits},
    };
    use iroha_sumeragi::api::{Action, CommittedTip, Event, HaltReason, Init, LocalParams};
    use parking_lot::Mutex;

    with_worker(|chain, worker, blocks, _| {
        let (block, qc) = executed(chain, worker);
        let original = original_overlay(worker);
        let (_, _, genesis) = startup::stored_genesis(chain.state()).unwrap().unwrap();
        let make_crypto = || {
            let crypto = BlsCrypto::new();
            crypto
                .admit_committee(
                    chain
                        .validators()
                        .iter()
                        .map(|(peer, pop)| (peer.public_key(), pop.as_slice())),
                )
                .unwrap();
            Box::new(crypto)
        };
        let (mut kernel, _) = Kernel::start(KernelStart {
            allocation_budget: chain.state().ivm_execution_budget(),
            local: LocalParams::default(),
            init: Init {
                instance: chain.instance(),
                records: Vec::new(),
                genesis_height: 1,
                demotion_window: 128,
                nonce: 1,
                tip: CommittedTip {
                    height: 1,
                    block_hash: genesis.block_hash,
                    result: genesis.result,
                    header: None,
                    commit_qc: None,
                },
                configs: vec![
                    (
                        2,
                        iroha_sumeragi::types::ConfigSlot::Ready(
                            worker.scheduled(2).unwrap().height_config().unwrap(),
                        ),
                    ),
                    (
                        3,
                        iroha_sumeragi::types::ConfigSlot::Ready(
                            worker.scheduled(3).unwrap().height_config().unwrap(),
                        ),
                    ),
                ],
                recent_headers: Vec::new(),
            },
            signers: Vec::new(),
            crypto: make_crypto(),
            hasher: make_crypto(),
            now: 0,
            ingress: Arc::new(Mutex::new(Ingress::new(IngressLimits::default()))),
            config: DriverConfig::default(),
        })
        .unwrap();
        kernel.route(vec![Action::CommitBlock {
            block: block.clone(),
            commit_qc: qc.clone(),
        }]);
        assert!(
            kernel
                .poll(0)
                .iter()
                .any(|op| matches!(op, Op::Exec(ExecOp::Prepare(_))))
        );
        kernel.complete(
            0,
            Completion::Exec(ExecDone::Prepared(worker.prepare(&block, &qc))),
        );
        assert_eq!(original_overlay(worker), original);
        assert!(
            kernel
                .poll(0)
                .iter()
                .any(|op| matches!(op, Op::Exec(ExecOp::Append(_))))
        );
        blocks.append(&block, &qc).unwrap();
        kernel.complete(
            0,
            Completion::Exec(ExecDone::Appended {
                durable: true,
                deferred: None,
            }),
        );
        assert!(
            kernel
                .poll(0)
                .iter()
                .any(|op| matches!(op, Op::Exec(ExecOp::Commit(_))))
        );
        let result = worker.commit_with(&block, &qc, |overlay| {
            StateBlock::fail_publication_after_preparation_for_test();
            overlay.try_publish()
        });
        assert!(matches!(result, Err(PublicationError::RecoveryRequired(_))));
        kernel.complete(
            0,
            Completion::Exec(ExecDone::Committed(result.map(Box::new))),
        );
        let halt = HaltReason::PublicationRecoveryRequired { height: 2 };
        assert_eq!(kernel.core().status().halted, Some(halt));
        assert_eq!(kernel.exec().halted(), Some(halt));
        assert_eq!(kernel.exec().applied(), 1);
        assert_eq!(worker.state.view().height(), 1);
        assert!(
            worker.live.as_ref().unwrap().overlay.is_some(),
            "terminal recovery retains its original allocation"
        );
        kernel.route(vec![Action::Execute {
            block: block.clone(),
            req: 88,
            certified: true,
        }]);
        for now in [1, 1000, 10_000] {
            kernel.handle(now, Event::Tick);
            assert!(
                !kernel
                    .poll(now)
                    .iter()
                    .any(|op| matches!(op, Op::Exec(_) | Op::Send { .. }))
            );
        }
        assert!(matches!(
            worker.prepare(&block, &qc),
            Err(PublicationError::RecoveryRequired(_))
        ));
        assert_eq!(
            original_overlay(worker),
            original,
            "no reconstructed execution owner"
        );
    });
}

#[test]
fn state_busy_retry_retains_original_metadata_snapshot_certificate_and_pool_custody() {
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let overlay = original_overlay(worker);
        let witness = iroha_crypto::HashOf::new(
            worker
                .live
                .as_ref()
                .unwrap()
                .witness
                .as_ref()
                .unwrap()
                .wire(),
        );
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let staged = worker.context.staging.get(&qc.block_hash).unwrap();
        let cert = staged.executed.commit_certificate().unwrap();
        let certificate_bytes = staged.executed.encode_wire().unwrap();
        let dir = tempfile::tempdir().unwrap();
        chain
            .state()
            .enable_publication_snapshot_for_test(dir.path());
        State::observe_publication_captures_for_test(|captures| {
            let mut phase_identity = None;
            let mut occupancy = None;
            let mut metadata_identity = None;
            for attempt in 0..4 {
                let mut attempt_commit = || {
                    let result = worker.commit(&block, &qc);
                    assert!(
                        matches!(result, Err(PublicationError::Deferred(_))),
                        "{result:?}"
                    );
                };
                if attempt % 2 == 0 {
                    chain
                        .state()
                        .with_publication_blocked_for_test(&mut attempt_commit);
                } else {
                    chain
                        .state()
                        .with_hash_publication_blocked_for_test(&mut attempt_commit);
                }
                assert!(worker.recovery.is_none());
                assert_eq!(original_overlay(worker), overlay);
                assert_eq!(worker.applied.0, 1);
                assert_eq!(chain.state().committed_height(), 1);
                assert_eq!(
                    captures.counts(),
                    (1, 0),
                    "capture exactly once and retain on refusal"
                );
                assert!(events.try_recv().is_err());
                let live = worker.live.as_ref().unwrap();
                assert_eq!(
                    iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
                    witness
                );
                let PublicationPhase::Prepared {
                    state_events: Some(tail),
                    ..
                } = &live.phase
                else {
                    panic!("the original metadata finalization survives State refusal")
                };
                let metadata = (tail.as_ptr() as usize, tail.len(), tail.capacity());
                assert_eq!(*metadata_identity.get_or_insert(metadata), metadata);
                let identity = live
                    .overlay
                    .as_ref()
                    .unwrap()
                    .publication_identity_for_test();
                assert_ne!(identity.0, 0);
                assert_ne!(identity.1, 0);
                assert!(identity.2);
                assert_eq!(*phase_identity.get_or_insert(identity), identity);
                let used = chain.state().publication_pool_usage_for_test();
                assert_eq!(
                    *occupancy.get_or_insert(used),
                    used,
                    "same original pool allocations across retry"
                );
                let retry = worker.context.staging.get(&qc.block_hash).unwrap();
                assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                    &retry.executed,
                    &staged.executed
                ));
                assert!(std::ptr::eq(
                    retry.executed.commit_certificate().unwrap(),
                    cert
                ));
                assert_eq!(retry.executed.encode_wire().unwrap(), certificate_bytes);
                assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
            }
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.applied.0, 2);
            assert_eq!(chain.state().committed_height(), 2);
            assert_eq!(captures.counts(), (1, 1));
            let mut delivered = 0;
            while events.try_recv().is_ok() {
                delivered += 1;
            }
            assert!(delivered > 0);
            worker.commit(&block, &qc).unwrap();
            assert!(
                events.try_recv().is_err(),
                "successful repeat emits no second effect"
            );
            assert_eq!(captures.counts(), (1, 1));
            assert!(
                iroha_data_model::block::SharedSignedBlock::ptr_eq(
                    &worker.context.staging.get(&qc.block_hash).unwrap().executed,
                    &staged.executed
                ),
                "Kura handoff still uses the same retained certified source"
            );
        });
    });
}

#[test]
fn context_proof_capacity_retry_retains_original_witness_inputs_and_execution() {
    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let mut occupied = None;
        let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
            assert!(matches!(
                worker.finishing.as_ref().unwrap().phase,
                FinishingPhase::ContextProof { .. }
            ));
            let budget = worker.state.ivm_execution_budget();
            occupied = Some(
                budget
                    .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                    .unwrap(),
            );
            worker.finish_execution_with_encoder(false, encode_result_preimage)
        });
        assert!(matches!(outcome, Err(_)));
        assert!(worker.recovery.is_none());
        assert!(worker.live.is_none());
        assert!(!worker.results.contains_key(&block_hash));
        let pending = worker
            .finishing
            .as_ref()
            .expect("same original completed execution");
        let FinishingPhase::ContextProof { inputs, refusal } = &pending.phase else {
            panic!("proof scratch refused before consuming original inputs")
        };
        assert!(matches!(
            refusal,
            Some(NativeLaneStateProofError::Scratch(
                iroha_allocation::ChargedBufferError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                )
            ))
        ));
        let overlay = std::ptr::from_ref(pending.overlay.as_ref());
        let authority = inputs.get().schedule.current.committee.as_ptr();
        let writes = pending.witness.writes.as_ptr();
        let witness = iroha_crypto::HashOf::new(pending.witness.wire());
        let event_count = pending.events.len();
        let budget = worker.state.ivm_execution_budget();
        let retained_bytes = budget.reserved_bytes();
        for _ in 0..2 {
            assert!(matches!(
                worker.execute(&block, block_hash, false),
                Some(ExecOutcome::Failed(_))
            ));
            let pending = worker.finishing.as_ref().unwrap();
            let FinishingPhase::ContextProof { inputs, refusal } = &pending.phase else {
                panic!("original proof frontier retained")
            };
            assert!(refusal.as_ref().unwrap().is_local_refusal());
            assert_eq!(std::ptr::from_ref(pending.overlay.as_ref()), overlay);
            assert_eq!(inputs.get().schedule.current.committee.as_ptr(), authority);
            assert_eq!(pending.witness.writes.as_ptr(), writes);
            assert_eq!(iroha_crypto::HashOf::new(pending.witness.wire()), witness);
            assert_eq!(pending.events.len(), event_count);
            assert_eq!(budget.reserved_bytes(), retained_bytes);
            assert!(!worker.results.contains_key(&block_hash));
        }
        assert!(events.try_recv().is_err());
        drop(occupied);
        let Some(ExecOutcome::Valid { result, .. }) = worker.execute(&block, block_hash, false)
        else {
            panic!("same original execution completes after real pool release")
        };
        assert!(worker.finishing.is_none());
        let live = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(live.overlay.as_deref().unwrap()),
            overlay
        );
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            authority
        );
        assert_eq!(live.witness.as_ref().unwrap().writes.as_ptr(), writes);
        assert_eq!(
            iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
            witness
        );
        assert_eq!(live.events.len(), event_count);
        let qc = chain.commit_qc(2, block_hash, result, Signers::Quorum);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert_eq!(worker.state.view().height(), 2);
    });
}

#[test]
fn result_encoding_capacity_retry_keeps_original_execution_and_allocation_custody() {
    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let mut occupied = None;
        let outcome =
            worker.run_execution_with_encoder(&block, block_hash, false, |original, budget| {
                let remaining = budget
                    .limit_bytes()
                    .checked_sub(budget.reserved_bytes())
                    .unwrap();
                occupied = Some(
                    budget
                        .try_reserve_bytes(remaining)
                        .expect("occupy real original pool"),
                );
                encode_result_preimage(original, budget)
            });
        assert!(matches!(outcome, Err(_)));
        assert!(worker.recovery.is_none());
        assert!(worker.live.is_none());
        assert!(!worker.results.contains_key(&block_hash));
        let pending = worker
            .finishing
            .as_ref()
            .expect("same completed execution is retained");
        assert!(matches!(
            pending.encoding_refusal,
            Some(
                crate::sumeragi::commitment::ResultPreimageError::Allocation(
                    iroha_allocation::ChargedBufferError::Admission(
                        iroha_allocation::AllocationRefusal::Capacity { .. }
                    )
                )
            )
        ));
        let overlay = std::ptr::from_ref(pending.overlay.as_ref());
        let authority = pending
            .phase
            .ready()
            .unwrap()
            .get()
            .commitment()
            .schedule
            .current
            .committee
            .as_ptr();
        let witness = iroha_crypto::HashOf::new(pending.witness.wire());
        let event_count = pending.events.len();
        for _ in 0..2 {
            assert!(matches!(
                worker.execute(&block, block_hash, false),
                Some(ExecOutcome::Failed(_))
            ));
            let pending = worker.finishing.as_ref().unwrap();
            assert_eq!(std::ptr::from_ref(pending.overlay.as_ref()), overlay);
            assert_eq!(
                pending
                    .phase
                    .ready()
                    .unwrap()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                authority
            );
            assert_eq!(iroha_crypto::HashOf::new(pending.witness.wire()), witness);
            assert_eq!(pending.events.len(), event_count);
            assert!(!worker.results.contains_key(&block_hash));
        }
        assert!(events.try_recv().is_err());
        drop(occupied);
        let Some(ExecOutcome::Valid { result, .. }) = worker.execute(&block, block_hash, false)
        else {
            panic!("release permits encoding of the same original execution");
        };
        assert!(worker.finishing.is_none());
        let live = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(live.overlay.as_deref().unwrap()),
            overlay
        );
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            authority
        );
        assert_eq!(
            iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
            witness
        );
        assert_eq!(live.events.len(), event_count);
        let qc = chain.commit_qc(2, block_hash, result, Signers::Quorum);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert_eq!(worker.state.view().height(), 2);
    });
}

#[test]
fn result_encoding_foreign_pool_requires_recovery_and_retains_original_execution() {
    with_worker(|chain, worker, _, _| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let outcome =
            worker.run_execution_with_encoder(&block, block_hash, false, |original, budget| {
                let foreign = iroha_allocation::AllocationBudget::new(budget.limit_bytes());
                encode_result_preimage(original, &foreign)
            });
        assert!(matches!(outcome, Err(_)));
        assert!(worker.recovery.is_some());
        let pending = worker
            .finishing
            .as_ref()
            .expect("original retained for recovery");
        assert!(matches!(
            pending.encoding_refusal,
            Some(crate::sumeragi::commitment::ResultPreimageError::ForeignBudget)
        ));
        let overlay = std::ptr::from_ref(pending.overlay.as_ref());
        assert!(matches!(
            worker.execute(&block, block_hash, false),
            Some(ExecOutcome::Failed(_))
        ));
        assert_eq!(
            std::ptr::from_ref(worker.finishing.as_ref().unwrap().overlay.as_ref()),
            overlay
        );
        assert!(worker.live.is_none());
        assert!(!worker.results.contains_key(&block_hash));
    });
}

fn assert_certificate_allocation_retry(
    occupy_after_part: usize,
    make_chain: fn() -> CertifiedTestChain,
    consensus_mode: ConsensusMode,
) {
    with_worker_from(
        make_chain,
        consensus_mode,
        move |chain, worker, blocks, events| {
            let (block, qc) = executed(chain, worker);
            let overlay = original_overlay(worker);
            let live = worker.live.as_ref().unwrap();
            let witness = iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire());
            let authority = live
                .commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr();
            let preimage = match &live.phase {
                PublicationPhase::Executed { preimage, .. } => preimage.as_slice().as_ptr(),
                _ => panic!("original executed phase"),
            };
            let event_count = live.events.len();
            let mut occupied = None;
            let mut encoded = 0;
            let mut header_pointer = None;
            let mut qc_pointer = None;
            let mut availability_pointer = None;
            let outcome = worker.prepare_with_encoder(
                &block,
                &qc,
                CommitTelemetryOrigin::Forward,
                |part, budget| {
                    let bytes = crate::sumeragi::commitment::encode_certificate_part(
                        part,
                        budget,
                        crate::sumeragi::commitment::MAX_RESULT_PREIMAGE_BYTES,
                    )?;
                    encoded += 1;
                    if encoded == 1 {
                        header_pointer = Some(bytes.as_slice().as_ptr());
                    }
                    if encoded == 2 {
                        qc_pointer = Some(bytes.as_slice().as_ptr());
                    }
                    if encoded == 3 {
                        availability_pointer = Some(bytes.as_slice().as_ptr());
                    }
                    if encoded == occupy_after_part {
                        // The immutable block shell is admitted before consuming any original
                        // certificate parts. Leave exactly its real layout available when this
                        // fixture targets the later certificate-control admission boundary.
                        let block_control = if occupy_after_part == 3 {
                            iroha_data_model::block::SharedSignedBlock::allocation_layout().size()
                        } else {
                            0
                        };
                        occupied = Some(
                            budget
                                .try_reserve_bytes(
                                    budget
                                        .limit_bytes()
                                        .checked_sub(budget.reserved_bytes())
                                        .and_then(|remaining| remaining.checked_sub(block_control))
                                        .unwrap(),
                                )
                                .expect("occupy original capacity beyond the earlier block shell"),
                        );
                    }
                    Ok(bytes)
                },
            );
            assert!(matches!(outcome, Err(PublicationError::Deferred(_))));
            assert_eq!(encoded, occupy_after_part);
            for _ in 0..2 {
                assert!(worker.recovery.is_none());
                assert_eq!(original_overlay(worker), overlay);
                let live = worker.live.as_ref().unwrap();
                assert_eq!(
                    iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
                    witness
                );
                assert_eq!(
                    live.commitment()
                        .get()
                        .commitment()
                        .schedule
                        .current
                        .committee
                        .as_ptr(),
                    authority
                );
                assert_eq!(live.events.len(), event_count);
                match &live.phase {
                    PublicationPhase::EncodingCertificate {
                        preimage: original,
                        header_wire: Some(header),
                        qc_wire: None,
                        refusal:
                            Some(crate::sumeragi::commitment::ResultPreimageError::Allocation(
                                iroha_allocation::ChargedBufferError::Admission(
                                    iroha_allocation::AllocationRefusal::Capacity { .. },
                                ),
                            )),
                        ..
                    } if occupy_after_part == 1 => {
                        assert_eq!(original.as_slice().as_ptr(), preimage);
                        assert_eq!(Some(header.as_slice().as_ptr()), header_pointer);
                    }
                    PublicationPhase::EncodingCertificate {
                        preimage: original,
                        header_wire: Some(header),
                        qc_wire: Some(original_qc),
                        availability_wire: None,
                        refusal:
                            Some(crate::sumeragi::commitment::ResultPreimageError::Allocation(
                                iroha_allocation::ChargedBufferError::Admission(
                                    iroha_allocation::AllocationRefusal::Capacity { .. },
                                ),
                            )),
                        ..
                    } if occupy_after_part == 2 => {
                        assert_eq!(original.as_slice().as_ptr(), preimage);
                        assert_eq!(Some(header.as_slice().as_ptr()), header_pointer);
                        assert_eq!(Some(original_qc.as_slice().as_ptr()), qc_pointer);
                    }
                    PublicationPhase::Certifying {
                        parts: Some(parts),
                        refusal:
                            Some(iroha_data_model::block::CertificateAdmissionError::ControlAdmission(
                                iroha_allocation::AllocationRefusal::Capacity { .. },
                            )),
                        ..
                    } if occupy_after_part == 3 => {
                        assert_eq!(
                            Some(parts.availability.as_slice().as_ptr()),
                            availability_pointer
                        );
                        assert_eq!(parts.result_preimage.as_slice().as_ptr(), preimage);
                        assert_eq!(
                            Some(parts.consensus_header.as_slice().as_ptr()),
                            header_pointer
                        );
                        assert_eq!(Some(parts.commit_qc.as_slice().as_ptr()), qc_pointer);
                    }
                    _ => panic!("exact original allocation refusal must survive"),
                }
                assert!(worker.context.staging.get(&qc.block_hash).is_none());
                assert!(events.try_recv().is_err());
                assert!(matches!(
                    worker.prepare(&block, &qc),
                    Err(PublicationError::Deferred(_))
                ));
            }
            let alternate = chain.commit_qc(
                block.header().height,
                qc.block_hash,
                qc.result,
                Signers::LastThree,
            );
            assert!(
                worker.prepare(&block, &alternate).is_err(),
                "frozen exact QC cannot be replaced"
            );
            drop(occupied);
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
            let staged = worker.context.staging.get(&qc.block_hash).unwrap();
            let certificate = staged.executed.commit_certificate().unwrap();
            assert!(certificate.admitted_to(&worker.state.ivm_execution_budget()));
            assert_eq!(certificate.result_preimage().as_ptr(), preimage);
            assert_eq!(
                Some(certificate.consensus_header().as_ptr()),
                header_pointer
            );
            if let Some(original_qc) = qc_pointer {
                assert_eq!(certificate.commit_qc().as_ptr(), original_qc);
            }
            if let Some(original_availability) = availability_pointer {
                assert_eq!(certificate.availability().as_ptr(), original_availability);
            }
            let decoded_frame: iroha_sumeragi::availability::AvailabilityFrame =
                norito::decode_canonical(certificate.availability()).unwrap();
            assert_eq!(&decoded_frame, block.availability());
            assert_eq!(original_overlay(worker), overlay);
            blocks.append(&block, &qc).unwrap();
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.state.view().height() as u64, block.header().height);
        },
    );
}

#[test]
fn qc_encoding_refusal_retains_original_header_result_and_execution_until_capacity_returns() {
    assert_certificate_allocation_retry(1, permissioned_chain, ConsensusMode::Permissioned);
}

#[test]
fn certificate_control_refusal_retains_every_original_part_through_publication_retry() {
    assert_certificate_allocation_retry(3, permissioned_chain, ConsensusMode::Permissioned);
}

/// Mandatory availability encoding retains both earlier encodings and the execution owner.
#[test]
fn availability_encoding_refusal_retains_original_header_qc_and_execution() {
    assert_certificate_allocation_retry(2, permissioned_chain, ConsensusMode::Permissioned);
}

#[test]
fn native_control_is_attached_once_and_remote_refusal_preserves_the_original_owner() {
    with_worker(|chain, worker, _, _| {
        let block = proposal(chain, worker);
        let source = ApplicationControlContext {
            instance: block.header().instance,
            epoch: block.header().epoch,
            height: block.header().height,
            parent_hash: block.header().parent_hash,
            parent_result: block.header().parent_result,
        };
        let build = ControlWitnessContext {
            height: source.height,
            view: block.header().origin_view,
            epoch: source.epoch,
            parent_hash: source.parent_hash,
            parent_result: source.parent_result,
        };
        assert!(matches!(
            worker.drive_control(&source),
            Err(PublicationError::RecoveryRequired(_))
        ));
        worker.attach_beacon(chain.instance(), None, None).unwrap();
        assert!(matches!(
            worker.build_control_witness(&build),
            Err(PublicationError::Retryable(_))
        ));
        assert!(worker.drive_control(&source).unwrap().is_none());
        let original = worker.build_control_witness(&build).unwrap();
        assert!(original.is_empty());
        assert!(matches!(
            worker.attach_beacon(Hash32([99; 32]), None, None),
            Err(PublicationError::RecoveryRequired(_))
        ));
        // A failed replacement leaves the old actual instance functional.
        assert!(worker.drive_control(&source).unwrap().is_none());
        let sender = schedule::consensus_key(&chain.validators()[0].0).unwrap();
        worker
            .receive_application_control(
                &sender,
                &ApplicationControl {
                    context: source,
                    bytes: ControlWitness::try_from_slice(&[1, 2, 3]).unwrap(),
                },
            )
            .unwrap();
        assert!(worker.recovery.is_none());
        assert_eq!(worker.build_control_witness(&build).unwrap(), original);
        let mut stale = source;
        stale.parent_result = Hash32([98; 32]);
        worker
            .receive_application_control(
                &sender,
                &ApplicationControl {
                    context: stale,
                    bytes: ControlWitness::empty(),
                },
            )
            .unwrap();
        assert_eq!(worker.build_control_witness(&build).unwrap(), original);
    });
}

#[test]
fn native_control_never_displaces_the_original_prepared_publication() {
    with_worker(|chain, worker, _, _| {
        worker.attach_beacon(chain.instance(), None, None).unwrap();
        let (block, qc) = executed(chain, worker);
        let original = original_overlay(worker);
        let source = ApplicationControlContext {
            instance: block.header().instance,
            epoch: block.header().epoch,
            height: block.header().height,
            parent_hash: block.header().parent_hash,
            parent_result: block.header().parent_result,
        };
        assert!(
            worker.drive_control(&source).unwrap().is_none(),
            "committed reads remain available while the original speculative overlay is retained"
        );
        assert_eq!(original_overlay(worker), original);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));

        assert!(matches!(
            worker.drive_control(&source),
            Err(PublicationError::Retryable(_))
        ));
        assert_eq!(original_overlay(worker), original);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
    });
}

#[test]
fn quarantine_requires_the_exact_control_free_transaction_rejection_hash() {
    with_worker(|chain, worker, _, _| {
        let block = proposal(chain, worker);
        let crypto = worker.context.crypto.as_ref().unwrap();
        let hash = block.hash(&**crypto);
        let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
            chain.tick(2_000),
            &chain.network_id(),
            Duration::from_secs(1),
            chain.state().view().world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &time,
        )
        .unwrap();
        let original_input = accepted.hash_as_entrypoint();
        queue.push(accepted, chain.state().view()).unwrap();
        worker.queue = Some(Arc::clone(&queue));
        worker.reject(2, 0, hash);
        assert!(
            queue.queued_len() == 1 && queue.contains_entrypoint_hash(original_input),
            "no transaction verdict authorizes queue isolation"
        );
        worker.quarantine_context = Some(QuarantineContext {
            height: 2,
            view: 0,
            block_hash: hash,
            _pulse_context: control::pulse_context(block.header()),
        });
        worker.reject(2, 0, Hash32([201; 32]));
        assert!(
            queue.queued_len() == 1 && queue.contains_entrypoint_hash(original_input),
            "another proposal cannot consume the original queue selection"
        );
        let mut controlled = block.header().clone();
        controlled.control_witness = ControlWitness::try_from_slice(&[1, 2, 3]).unwrap();
        let block = chain.author_payload(controlled, block.payload().as_slice().to_vec());
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        assert!(matches!(
            worker.execute(&block, hash, false),
            Some(ExecOutcome::Invalid)
        ));
        assert!(
            worker.quarantine_context.is_none(),
            "malformed control never authorizes transaction blame"
        );
        worker.reject(2, 0, hash);
        assert!(queue.queued_len() == 1 && queue.contains_entrypoint_hash(original_input));
    });
}

#[test]
fn native_header_source_is_checked_against_the_pristine_committed_parent() {
    with_worker(|chain, worker, _, _| {
        for changed in 0..3 {
            let block = proposal(chain, worker);
            let mut header = block.header().clone();
            let mut foreign_context = block.source().config().clone();
            match changed {
                0 => header.instance = Hash32([201; 32]),
                1 => header.parent_result = Hash32([202; 32]),
                _ => {
                    header.epoch.context = Hash32([203; 32]);
                    foreign_context.epoch.id = header.epoch;
                }
            }
            let changed_body = chain
                .author_payload_under_test_context(
                    header,
                    block.payload().as_slice().to_vec(),
                    &foreign_context,
                )
                .unwrap_or_else(|(_, error)| panic!("genuinely signed altered context: {error:?}"));
            assert_ne!(changed_body.header(), block.header());
            if changed != 1 {
                assert_ne!(changed_body.source(), block.source());
            }
            let block = changed_body;
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            assert!(matches!(
                worker.execute(&block, hash, false),
                Some(ExecOutcome::Invalid)
            ));
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert_eq!(worker.applied.0, 1);
        }
        let (block, _) = executed(chain, worker);
        let expected = control::pulse_context(block.header());
        assert_eq!(expected.instance, chain.instance().0);
        assert_eq!(expected.parent_consensus_hash, block.header().parent_hash.0);
        assert_eq!(expected.parent_result, block.header().parent_result.0);
        assert_eq!(expected.epoch, block.header().epoch.epoch);
        assert_eq!(expected.epoch_context_id, block.header().epoch.context.0);
    });
}

#[test]
fn state_executor_serializes_real_control_requests_and_one_time_attachment() {
    with_worker(|chain, worker, _, _| {
        let block = proposal(chain, worker);
        let mut executor = StateExecutor::spawn(worker.context.clone()).unwrap();
        let source = ApplicationControlContext {
            instance: block.header().instance,
            epoch: block.header().epoch,
            height: block.header().height,
            parent_hash: block.header().parent_hash,
            parent_result: block.header().parent_result,
        };
        let build = ControlWitnessContext {
            height: source.height,
            view: block.header().origin_view,
            epoch: source.epoch,
            parent_hash: source.parent_hash,
            parent_result: source.parent_result,
        };
        executor
            .attach_beacon(chain.instance(), None, None)
            .unwrap();
        assert!(executor.drive_control(&source).unwrap().is_none());
        assert_eq!(
            executor.build_control_witness(&build).unwrap(),
            ControlWitness::empty()
        );
        let sender = schedule::consensus_key(&chain.validators()[0].0).unwrap();
        executor
            .receive_application_control(
                &sender,
                &ApplicationControl {
                    context: source,
                    bytes: ControlWitness::try_from_slice(&[1]).unwrap(),
                },
            )
            .unwrap();
        assert!(
            executor
                .attach_beacon(Hash32([211; 32]), None, None)
                .is_err()
        );
        assert!(executor.drive_control(&source).unwrap().is_none());
        assert_eq!(
            executor.build_control_witness(&build).unwrap(),
            ControlWitness::empty()
        );
    });
}

/// Native execution rejects malformed signed payloads before an overlay exists, at every height.
#[test]
fn native_invalid_payloads_are_rejected_at_ordinary_and_boundary_heights() {
    let fixtures: [(fn() -> CertifiedTestChain, ConsensusMode); 2] = [
        (permissioned_chain, ConsensusMode::Permissioned),
        (
            CertifiedTestChain::npos_boundary_fixture,
            ConsensusMode::Npos,
        ),
    ];
    for (make_chain, consensus_mode) in fixtures {
        with_worker_from(
            make_chain,
            consensus_mode,
            |chain, worker, blocks, events| {
                let applied = worker.applied;
                let state_height = worker.state.view().height();
                let block = proposal(chain, worker);
                let malformed = vec![0xFF];
                let crypto = worker.context.crypto.as_ref().unwrap();
                let mut header = block.header().clone();
                // Genuine availability authenticates these exact malformed application bytes;
                // retaining the valid proposal's declared digest would fail before execution.
                header.payload_hash = payload_hash(&**crypto, &malformed);
                header.payload_len = u32::try_from(malformed.len()).unwrap();
                let flagged = chain.author_payload(header, malformed);
                assert_eq!(flagged.source().config(), block.source().config());
                assert_eq!(flagged.header().height, block.header().height);
                assert_eq!(flagged.header().payload_len, 1);
                assert_eq!(
                    flagged.header().payload_hash,
                    payload_hash(&**crypto, flagged.payload().as_slice())
                );
                assert!(flagged.admitted_to(&worker.state.ivm_execution_budget()));
                assert!(matches!(
                    payload::decode(flagged.payload().as_slice()),
                    Err(payload::PayloadError::NotCanonical(_))
                ));
                let flagged_hash = flagged.hash(&**worker.context.crypto.as_ref().unwrap());
                for _ in 0..2 {
                    assert!(matches!(
                        worker.execute(&flagged, flagged_hash, false),
                        Some(ExecOutcome::Invalid)
                    ));
                    let (source, verdict) = worker.results.get(&flagged_hash).unwrap();
                    assert_eq!(source, flagged.source());
                    assert!(matches!(verdict, ExecOutcome::Invalid));
                    assert!(worker.live.is_none());
                    assert!(worker.finishing.is_none());
                    assert!(worker.context.staging.get(&flagged_hash).is_none());
                    assert!(worker.recovery.is_none());
                    assert_eq!(worker.applied, applied);
                    assert_eq!(worker.state.view().height(), state_height);
                    assert!(events.try_recv().is_err());
                }
                // Rejection of the malformed source does not poison the original valid payload.
                let (block, qc) = execute_proposal(chain, worker, block);
                assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
                blocks.append(&block, &qc).unwrap();
                worker.commit(&block, &qc).unwrap();
                assert_eq!(worker.applied, (block.header().height, qc.block_hash));
            },
        );
    }
}

#[test]
fn native_prepare_checks_real_quorum_before_changing_original_publication_owners() {
    with_worker(|chain, worker, _, _| {
        let (block, qc) = executed(chain, worker);
        let original = original_overlay(worker);
        let commitment = std::ptr::from_ref(worker.live.as_ref().unwrap().commitment().get());
        let mut changed = qc.clone();
        changed.result = Hash32([0xA9; 32]);
        // The unchanged genuine signature cannot authenticate a different execution result.
        assert!(worker.prepare(&block, &changed).is_err());
        assert_eq!(original_overlay(worker), original);
        assert_eq!(
            std::ptr::from_ref(worker.live.as_ref().unwrap().commitment().get()),
            commitment
        );
        assert!(matches!(
            worker.live.as_ref().unwrap().phase,
            PublicationPhase::Executed { .. }
        ));
        assert!(worker.context.staging.get(&qc.block_hash).is_none());
        assert!(worker.recovery.is_none());
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
        assert_eq!(original_overlay(worker), original);
    });
}

/// Invalid quorum or result signatures retain every original publication owner.
#[test]
fn native_certificate_refusals_retain_original_execution_until_exact_publication() {
    let fixtures: [(fn() -> CertifiedTestChain, ConsensusMode); 2] = [
        (permissioned_chain, ConsensusMode::Permissioned),
        (
            CertifiedTestChain::npos_boundary_fixture,
            ConsensusMode::Npos,
        ),
    ];
    for (make_chain, consensus_mode) in fixtures {
        with_worker_from(
            make_chain,
            consensus_mode,
            |chain, worker, blocks, events| {
                let (block, qc) = executed(chain, worker);
                let budget = worker.state.ivm_execution_budget();
                let applied = worker.applied;
                let state_height = worker.state.view().height();
                let overlay = original_overlay(worker);
                let live = worker.live.as_ref().unwrap();
                let commitment = std::ptr::from_ref(live.commitment().get());
                let authority = live
                    .commitment()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr();
                let event_count = live.events.len();
                let PublicationPhase::Executed { preimage, .. } = &live.phase else {
                    panic!("actual execution owns its original result preimage")
                };
                let preimage_pointer = preimage.as_slice().as_ptr();
                let committee = worker
                    .scheduled(block.header().height)
                    .unwrap()
                    .height_config()
                    .unwrap()
                    .committee;
                let crypto = Clone::clone(worker.context.crypto.as_ref().unwrap());
                let instance = chain.instance();
                let verifier = iroha_sumeragi::crypto::Verifier::new(
                    &*crypto,
                    &instance,
                    &block.header().epoch,
                    &committee,
                );
                let below_quorum = chain.commit_qc(
                    block.header().height,
                    qc.block_hash,
                    qc.result,
                    Signers::BelowQuorum,
                );
                assert_eq!(
                    verifier.verify_qc(&below_quorum),
                    Err(iroha_sumeragi::crypto::CertError::TooFewSigners),
                );
                let oversized = chain.commit_qc(
                    block.header().height,
                    qc.block_hash,
                    qc.result,
                    Signers::All,
                );
                assert_eq!(
                    verifier.verify_qc(&oversized),
                    Err(iroha_sumeragi::crypto::CertError::TooManySigners),
                );
                let mut changed_result = qc.clone();
                changed_result.result.0[0] ^= 1;
                assert!(verifier.verify_qc(&changed_result).is_err());
                let wire = norito::encode_canonical(&changed_result).unwrap();
                let decoded: Qc = norito::decode_canonical(&wire).unwrap();
                assert_eq!(
                    decoded, changed_result,
                    "original signature is not changed by decoding"
                );
                for refused in [&below_quorum, &oversized, &changed_result, &decoded] {
                    assert!(
                        worker
                            .prepare_with_encoder(
                                &block,
                                refused,
                                CommitTelemetryOrigin::Forward,
                                |_, _| panic!(
                                    "refused certificate must not enter result/certificate encoding"
                                ),
                            )
                            .is_err()
                    );
                    assert!(blocks.append(&block, refused).is_err());
                    assert!(worker.commit(&block, refused).is_err());
                    assert_eq!(original_overlay(worker), overlay);
                    let live = worker.live.as_ref().unwrap();
                    assert_eq!(std::ptr::from_ref(live.commitment().get()), commitment);
                    assert_eq!(
                        live.commitment()
                            .get()
                            .commitment()
                            .schedule
                            .current
                            .committee
                            .as_ptr(),
                        authority
                    );
                    assert_eq!(live.events.len(), event_count);
                    let PublicationPhase::Executed { preimage, .. } = &live.phase else {
                        panic!("refusal must retain the exact original executed phase")
                    };
                    assert_eq!(preimage.as_slice().as_ptr(), preimage_pointer);
                    assert_eq!(live.result, qc.result);
                    assert!(worker.context.staging.get(&qc.block_hash).is_none());
                    assert!(worker.recovery.is_none());
                    assert_eq!(worker.applied, applied);
                    assert_eq!(worker.state.view().height(), state_height);
                    assert!(events.try_recv().is_err());
                }
                assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
                let staged = worker.context.staging.get(&qc.block_hash).unwrap();
                let certificate = staged.executed.commit_certificate().unwrap();
                assert!(certificate.admitted_to(&budget));
                assert_eq!(certificate.result_preimage().as_ptr(), preimage_pointer);
                let stored_qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
                assert_eq!(stored_qc, qc);

                assert_eq!(original_overlay(worker), overlay);
                blocks.append(&block, &qc).unwrap();
                worker.commit(&block, &qc).unwrap();
                assert_eq!(worker.applied, (block.header().height, qc.block_hash));
                assert!(worker.live.as_ref().unwrap().overlay.is_none());
            },
        );
    }
}

/// Every certificate allocation boundary also preserves the genuine NPoS boundary execution.
#[test]
fn boundary_certificate_refusals_retain_original_preimage_authority_and_exact_quorum() {
    for part in 1..=3 {
        assert_certificate_allocation_retry(
            part,
            CertifiedTestChain::npos_boundary_fixture,
            ConsensusMode::Npos,
        );
    }
}

#[test]
fn boundary_certificate_read_refusal_retains_original_source_and_availability_until_publication() {
    with_worker_from(
        CertifiedTestChain::npos_boundary_fixture,
        ConsensusMode::Npos,
        |chain, worker, blocks, events| {
            let (block, qc) = executed(chain, worker);
            assert_eq!(block.header().height, 10);

            let overlay = original_overlay(worker);
            let live = worker.live.as_ref().unwrap();
            let authority = live
                .commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr();
            let PublicationPhase::Executed { preimage, .. } = &live.phase else {
                panic!("actual original boundary preimage")
            };
            let preimage_pointer = preimage.as_slice().as_ptr();
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
            blocks.append(&block, &qc).unwrap();
            let budget = worker.state.ivm_execution_budget();
            let source = chain
                .kura()
                .get_block(std::num::NonZeroUsize::new(10).unwrap(), &budget)
                .expect("original boundary block read")
                .unwrap();
            let limit = budget.limit_bytes();
            let reserved = budget.reserved_bytes();
            let table_len = block.availability().as_slice().len();
            // Admit the original table backing, then refuse its actual shared control.
            budget.set_limit_bytes(reserved.checked_add(table_len).unwrap());
            assert_eq!(
                blocks.certified(10).unwrap_err().io_kind(),
                std::io::ErrorKind::WouldBlock
            );
            let owners = blocks.pending_certificate_read_for_test().unwrap();
            assert_eq!(owners.0, std::ptr::from_ref(source.as_ref()));
            assert!(owners.1.is_some());
            assert_eq!(budget.reserved_bytes(), reserved + table_len);
            for height in [10, 9, 10] {
                assert_eq!(
                    blocks.certified(height).unwrap_err().io_kind(),
                    std::io::ErrorKind::WouldBlock
                );
                assert_eq!(blocks.pending_certificate_read_for_test(), Some(owners));
                assert_eq!(budget.reserved_bytes(), reserved + table_len);
                assert_eq!(original_overlay(worker), overlay);
                assert_eq!(
                    worker
                        .live
                        .as_ref()
                        .unwrap()
                        .commitment()
                        .get()
                        .commitment()
                        .schedule
                        .current
                        .committee
                        .as_ptr(),
                    authority
                );
                assert!(events.try_recv().is_err());
            }
            budget.set_limit_bytes(limit);
            let (recovered_body, recovered_qc) = blocks.committed_body(10).unwrap().unwrap();
            assert_eq!(
                recovered_body.availability().as_slice().as_ptr(),
                owners.1.unwrap()
            );
            assert_eq!(recovered_body.header(), block.header());
            assert_eq!(recovered_body.source(), block.source());
            assert_eq!(recovered_qc, qc);

            assert!(blocks.pending_certificate_read_for_test().is_none());
            let entry = blocks.entry(10).unwrap().unwrap();
            assert_eq!(entry.manifest.header, *block.header());
            assert_eq!(&entry.manifest.availability, block.availability());
            assert_eq!(entry.commit_qc, qc);
            let (stored_header, stored_qc) = blocks.certified(10).unwrap().unwrap();
            assert_eq!(&stored_header, block.header());
            assert_eq!(stored_qc, qc);
            let staged = worker.context.staging.get(&qc.block_hash).unwrap();
            assert_eq!(
                staged
                    .executed
                    .commit_certificate()
                    .unwrap()
                    .result_preimage()
                    .as_ptr(),
                preimage_pointer
            );
            assert_eq!(original_overlay(worker), overlay);
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.applied, (10, qc.block_hash));
            assert_eq!(worker.state.view().height(), 10);
            assert!(worker.live.as_ref().unwrap().overlay.is_none());
        },
    );
}

#[test]
fn boundary_discard_releases_only_the_unretained_original_execution_and_result() {
    with_worker_from(
        CertifiedTestChain::npos_boundary_fixture,
        ConsensusMode::Npos,
        |chain, worker, blocks, events| {
            let (block, qc) = executed(chain, worker);
            assert_eq!(block.header().height, 10);
            let budget = worker.state.ivm_execution_budget();
            let reserved = budget.reserved_bytes();
            let applied = worker.applied;
            let state_height = worker.state.view().height();
            let overlay = original_overlay(worker);
            let live = worker.live.as_ref().unwrap();
            let commitment = std::ptr::from_ref(live.commitment().get());
            let PublicationPhase::Executed { preimage, .. } = &live.phase else {
                panic!("actual original boundary execution")
            };
            let preimage_pointer = preimage.as_slice().as_ptr();
            worker.discard(10, &[qc.block_hash]);
            assert_eq!(original_overlay(worker), overlay);
            let live = worker.live.as_ref().unwrap();
            assert_eq!(std::ptr::from_ref(live.commitment().get()), commitment);
            assert_eq!(live.result, qc.result);
            let PublicationPhase::Executed { preimage, .. } = &live.phase else {
                panic!("keep preserves the same original result preimage")
            };
            assert_eq!(preimage.as_slice().as_ptr(), preimage_pointer);
            assert_eq!(budget.reserved_bytes(), reserved);
            worker.discard(10, &[]);
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(!worker.results.contains_key(&qc.block_hash));
            assert!(
                budget.reserved_bytes() < reserved,
                "discard refunds actual original execution custody"
            );
            assert!(
                worker.commit(&block, &qc).is_err(),
                "a genuine QC cannot publish a discarded unprepared overlay"
            );
            assert!(
                blocks.append(&block, &qc).is_err(),
                "a genuine QC cannot append without the original staged execution"
            );
            assert!(worker.context.staging.get(&qc.block_hash).is_none());
            assert!(worker.recovery.is_none());
            assert_eq!(worker.applied, applied);
            assert_eq!(worker.state.view().height(), state_height);
            assert!(events.try_recv().is_err());
        },
    );
}

// Traverse actual retained error owners without reconstructing decoder fields. This also
// keeps the before control independent of the prospective captured Decode variant.
fn native_archive_error_source<'a, E: std::error::Error + 'static>(
    mut original: &'a (dyn std::error::Error + 'static),
) -> &'a E {
    loop {
        if let Some(error) = original.downcast_ref::<E>() {
            return error;
        }
        original = original
            .source()
            .expect("actual original decoder remains in the error chain");
    }
}

#[test]
fn context_proof_decoder_refusal_retains_original_inputs_and_retries() {
    use iroha_data_model::sumeragi_finality::{
        NativeLaneStateProof, SUMERAGI_LANE_STATE_WITNESS_KEY,
    };

    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let budget = worker.state.ivm_execution_budget();
        let epoch = crossbeam_epoch::pin();
        let mut identities = None;
        let mut original_resource = None;
        let mut held = None;
        let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
            let original = worker.finishing.as_ref().unwrap();
            let FinishingPhase::ContextProof {
                inputs,
                refusal: None,
            } = &original.phase
            else {
                panic!("actual original execution precedes its first result proof")
            };
            let target = original
                .witness
                .writes
                .iter()
                .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
                .unwrap();
            let canonical = norito::canonical_decode_limits(target.value.len());
            let limits = norito::DecodeLimits::new(
                canonical.max_sequence_elements(),
                canonical.max_field_bytes(),
                canonical.max_total_elements(),
                canonical.max_total_allocated_bytes(),
                0,
            );
            NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap();
            let error = norito::with_decode_limits_scope(limits, || {
                NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap_err()
            });
            original_resource =
                native_archive_error_source::<norito::Error>(&error).decode_resource_error();
            assert!(matches!(
                original_resource,
                Some(norito::core::DecodeResourceError::NestingDepthExceeded {
                    limit: 0,
                    context: "decode budget",
                    ..
                })
            ));
            assert!(inputs.belongs_to(&budget));
            assert!(original.witness.pool().same_pool(&budget));
            identities = Some((
                std::ptr::from_ref(original.overlay.as_ref()),
                inputs.get().schedule.current.committee.as_ptr(),
                original.witness.writes.as_ptr(),
                target.value.as_ptr(),
                iroha_crypto::HashOf::new(original.witness.wire()),
                original.events.len(),
            ));
            held = Some(budget.reserved_bytes());
            norito::with_decode_limits_scope(limits, || {
                worker.finish_execution_with_encoder(false, encode_result_preimage)
            })
        });
        assert!(
            matches!(&outcome, Err(PublicationError::Deferred(PublicationDeferral::Execution(original)))
            if original.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                && original.allocation_refusal().is_none()),
            "original result proof decoder refusal must remain deferred, got {outcome:?}"
        );
        let Err(PublicationError::Deferred(original_deferral)) = outcome else {
            unreachable!("exact local category checked above")
        };
        assert!(original_deferral.release_wait().is_none());
        assert!(worker.recovery.is_none());
        assert!(worker.live.is_none());
        assert!(!worker.results.contains_key(&block_hash));
        let original = worker.finishing.as_ref().unwrap();
        let FinishingPhase::ContextProof { inputs, refusal } = &original.phase else {
            panic!("same original proof frontier must survive admission refusal")
        };
        let refused = refusal.as_ref().unwrap();
        let decoder = native_archive_error_source::<norito::core::DecodeAttemptError>(refused);
        assert_eq!(
            decoder.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            native_archive_error_source::<norito::Error>(decoder).decode_resource_error(),
            original_resource
        );
        assert!(refused.is_local_refusal());
        assert!(original.native_contexts.is_none());
        assert!(original.archive_refusal.is_none());
        let (overlay, committee, writes, commitment_bytes, witness_hash, event_count) =
            identities.unwrap();
        assert_eq!(std::ptr::from_ref(original.overlay.as_ref()), overlay);
        assert_eq!(inputs.get().schedule.current.committee.as_ptr(), committee);
        assert_eq!(original.witness.writes.as_ptr(), writes);
        assert_eq!(
            original
                .witness
                .writes
                .iter()
                .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
                .unwrap()
                .value
                .as_ptr(),
            commitment_bytes
        );
        assert_eq!(
            iroha_crypto::HashOf::new(original.witness.wire()),
            witness_hash
        );
        assert_eq!(original.events.len(), event_count);
        assert_eq!(budget.reserved_bytes(), held.unwrap());
        assert_eq!(worker.state.committed_height(), 1);
        assert!(events.try_recv().is_err());
        let Some(ExecOutcome::Valid { result, .. }) = worker.execute(&block, block_hash, false)
        else {
            panic!("same original result proof must complete after the caller scope retires")
        };
        let live = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(live.overlay.as_deref().unwrap()),
            overlay
        );
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            committee
        );
        let witness = live.witness.as_ref().unwrap();
        assert_eq!(witness.writes.as_ptr(), writes);
        assert_eq!(iroha_crypto::HashOf::new(witness.wire()), witness_hash);
        assert!(witness.pool().same_pool(&budget));
        assert!(live.commitment().belongs_to(&budget));
        let context = live.native_contexts.as_ref().unwrap();
        let bytes = context.canonical_bytes().to_vec();
        let carrier = context.carrier_hash();
        let qc = chain.commit_qc(2, block_hash, result, Signers::Quorum);
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        let durable = worker
            .context
            .native_context_archive
            .read_exact(2, carrier)
            .unwrap();
        assert_eq!(durable.as_slice(), bytes);
        assert_eq!(worker.state.committed_height(), 2);
        drop(durable);
        drop(epoch);
    });
}

#[test]
fn native_context_archive_decoder_refusal_retains_original_execution_and_retries() {
    use crate::sumeragi::driver::traits::PublicationDeferral;
    use iroha_data_model::sumeragi_finality::{
        NativeLaneStateProof, SUMERAGI_LANE_STATE_WITNESS_KEY,
    };

    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let budget = worker.state.ivm_execution_budget();
        let epoch = crossbeam_epoch::pin();
        let mut identities = None;
        let mut original_resource = None;
        let mut held = None;
        let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
            // Complete the actual native result before narrowing only the archive decoder.
            worker.prepare_original_result().unwrap();
            let original = worker.finishing.as_ref().unwrap();
            let target = original
                .witness
                .writes
                .iter()
                .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
                .expect("genuine completed lane-state commitment");
            let canonical = norito::canonical_decode_limits(target.value.len());
            let limits = norito::DecodeLimits::new(
                canonical.max_sequence_elements(),
                canonical.max_field_bytes(),
                canonical.max_total_elements(),
                canonical.max_total_allocated_bytes(),
                0,
            );
            assert_eq!(
                NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap(),
                original
                    .phase
                    .ready()
                    .unwrap()
                    .get()
                    .commitment()
                    .native_lanes,
                "the same original witness is valid before local admission refusal"
            );
            let oracle = norito::with_decode_limits_scope(limits, || {
                NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap_err()
            });
            let cause =
                native_archive_error_source::<norito::Error>(&oracle).decode_resource_error();
            assert!(matches!(
                cause,
                Some(norito::core::DecodeResourceError::NestingDepthExceeded {
                    limit: 0,
                    context: "decode budget",
                    ..
                })
            ));
            original_resource = cause;
            let result = original.phase.ready().unwrap();
            assert!(result.belongs_to(&budget));
            assert!(original.witness.pool().same_pool(&budget));
            identities = Some((
                std::ptr::from_ref(original.overlay.as_ref()),
                original.witness.writes.as_ptr(),
                target.value.as_ptr(),
                iroha_crypto::HashOf::new(original.witness.wire()),
                result
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                result.get().preimage().unwrap(),
                original.valid.as_ref().hash(),
            ));
            held = Some(budget.reserved_bytes());
            norito::with_decode_limits_scope(limits, || {
                worker.finish_execution_with_encoder(false, encode_result_preimage)
            })
        });
        assert!(
            matches!(
                &outcome,
                Err(PublicationError::Deferred(PublicationDeferral::Execution(original)))
                    if original.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                        && original.allocation_refusal().is_none()
            ),
            "original archive decoder refusal must remain deferred, got {outcome:?}"
        );
        let Err(PublicationError::Deferred(deferral)) = outcome else {
            unreachable!("exact local category checked above")
        };
        assert!(
            deferral.release_wait().is_none(),
            "codec admission has no invented pool waiter"
        );
        assert!(worker.recovery.is_none());
        assert!(worker.live.is_none());
        assert!(!worker.results.contains_key(&block_hash));
        let original = worker.finishing.as_ref().unwrap();
        assert!(original.native_contexts.is_none());
        let refused = original.archive_refusal.as_ref().unwrap();
        let decoder = native_archive_error_source::<norito::core::DecodeAttemptError>(refused);
        assert_eq!(
            decoder.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            std::error::Error::source(decoder)
                .unwrap()
                .downcast_ref::<norito::Error>()
                .unwrap()
                .decode_resource_error(),
            original_resource,
        );
        assert!(
            refused.is_local_refusal(),
            "captured decoder origin survives scope retirement"
        );
        let (
            overlay,
            writes,
            commitment_bytes,
            witness_hash,
            committee,
            canonical_result,
            executed_hash,
        ) = identities.unwrap();
        assert_eq!(std::ptr::from_ref(original.overlay.as_ref()), overlay);
        assert_eq!(original.witness.writes.as_ptr(), writes);
        assert_eq!(
            original
                .witness
                .writes
                .iter()
                .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
                .unwrap()
                .value
                .as_ptr(),
            commitment_bytes,
        );
        assert_eq!(
            iroha_crypto::HashOf::new(original.witness.wire()),
            witness_hash
        );
        assert_eq!(
            original
                .phase
                .ready()
                .unwrap()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            committee
        );
        assert_eq!(
            original.phase.ready().unwrap().get().preimage().unwrap(),
            canonical_result
        );
        assert_eq!(original.valid.as_ref().hash(), executed_hash);
        assert_eq!(budget.reserved_bytes(), held.unwrap());
        assert_eq!(worker.state.committed_height(), 1);
        assert!(events.try_recv().is_err());

        let Some(ExecOutcome::Valid { result, .. }) = worker.execute(&block, block_hash, false)
        else {
            panic!(
                "the unchanged original execution must finish after the caller decoder scope retires"
            )
        };
        let live = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(live.overlay.as_deref().unwrap()),
            overlay
        );
        let witness = live.witness.as_ref().unwrap();
        assert_eq!(witness.writes.as_ptr(), writes);
        assert_eq!(iroha_crypto::HashOf::new(witness.wire()), witness_hash);
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            committee
        );
        assert_eq!(
            live.commitment().get().preimage().unwrap(),
            canonical_result
        );
        assert!(live.commitment().belongs_to(&budget));
        assert!(witness.pool().same_pool(&budget));
        let context = live.native_contexts.as_ref().unwrap();
        let bytes = context.canonical_bytes().to_vec();
        let carrier = context.carrier_hash();
        assert_eq!(carrier, executed_hash);
        assert!(worker.recovery.is_none());
        let qc = chain.commit_qc(2, block_hash, result, Signers::Quorum);
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        let durable = worker
            .context
            .native_context_archive
            .read_exact(2, carrier)
            .unwrap();
        assert_eq!(durable.as_slice(), bytes);
        assert_eq!(worker.state.committed_height(), 2);
        drop(durable);
        drop(epoch);
    });
}

#[test]
fn native_context_archive_corrupt_commitment_remains_sticky_recovery() {
    use iroha_data_model::sumeragi_finality::{
        NativeLaneStateProof, SUMERAGI_LANE_STATE_WITNESS_KEY,
    };

    for result_completed in [false, true] {
        with_worker(move |chain, worker, _blocks, events| {
            let block = proposal(chain, worker);
            let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let epoch = crossbeam_epoch::pin();
            let mut identities = None;
            let mut held = None;
            let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
                if result_completed {
                    worker.prepare_original_result().unwrap();
                }
                let original = worker.finishing.as_mut().unwrap();
                // Offer an adversarial reconstruction through the existing seam; the funded
                // original stays immutable and cannot be extracted by this test.
                original
                    .witness
                    .offer_reconstructed_tamper_for_test(|offered| {
                        offered
                            .writes
                            .iter_mut()
                            .find(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
                            .unwrap()
                            .value
                            .pop()
                            .unwrap();
                    });
                let error =
                    NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap_err();
                assert!(
                    native_archive_error_source::<norito::Error>(&error)
                        .decode_resource_error()
                        .is_none(),
                    "malformed bytes must not masquerade as local admission"
                );
                identities = Some((
                    std::ptr::from_ref(original.overlay.as_ref()),
                    original.committee.as_ptr(),
                    iroha_crypto::HashOf::new(original.witness.wire()),
                ));
                held = Some(budget.reserved_bytes());
                worker.finish_execution_with_encoder(false, encode_result_preimage)
            });
            assert!(
                matches!(outcome, Err(PublicationError::RecoveryRequired(_))),
                "corrupt original commitment must require recovery: {outcome:?}"
            );
            assert!(worker.recovery.is_some());
            let original = worker.finishing.as_ref().unwrap();
            assert_eq!(original.phase.ready().is_some(), result_completed);
            match &original.phase {
                FinishingPhase::ContextProof { refusal, .. } => {
                    assert!(!refusal.as_ref().unwrap().is_local_refusal());
                    assert!(original.archive_refusal.is_none());
                }
                FinishingPhase::Ready(_) => assert!(
                    !original
                        .archive_refusal
                        .as_ref()
                        .unwrap()
                        .is_local_refusal()
                ),
                FinishingPhase::Consuming => {
                    panic!("no destructive transition begins on corrupt commitment")
                }
            }
            assert!(original.native_contexts.is_none());
            assert!(worker.live.is_none());
            let (overlay, committee, witness) = identities.unwrap();
            for _ in 0..2 {
                let Some(ExecOutcome::Failed(reason)) = worker.execute(&block, block_hash, false)
                else {
                    panic!("unchanged corrupt execution stays in recovery")
                };
                assert!(reason.contains("publication recovery required"));
                let original = worker.finishing.as_ref().unwrap();
                assert_eq!(std::ptr::from_ref(original.overlay.as_ref()), overlay);
                assert_eq!(original.committee.as_ptr(), committee);
                assert_eq!(iroha_crypto::HashOf::new(original.witness.wire()), witness);
                assert!(original.native_contexts.is_none());
                assert_eq!(budget.reserved_bytes(), held.unwrap());
                assert!(!worker.results.contains_key(&block_hash));
                assert_eq!(worker.state.committed_height(), 1);
                assert!(events.try_recv().is_err());
            }
            drop(epoch);
        });
    }
}

#[test]
fn native_context_archive_capacity_retry_retains_original_overlay_and_result() {
    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let mut occupied = None;
        let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
            worker.prepare_original_result().unwrap();
            let budget = worker.state.ivm_execution_budget();
            occupied = Some(
                budget
                    .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                    .unwrap(),
            );
            worker.finish_execution_with_encoder(false, encode_result_preimage)
        });
        assert!(matches!(outcome, Err(_)));
        assert!(worker.recovery.is_none());
        assert!(worker.live.is_none());
        let original = worker.finishing.as_ref().unwrap();
        assert!(original.native_contexts.is_none());
        assert!(
            original
                .archive_refusal
                .as_ref()
                .unwrap()
                .is_local_refusal()
        );
        let overlay = std::ptr::from_ref(original.overlay.as_ref());
        let commitment = original.phase.ready().unwrap().get();
        let authority = commitment.commitment().schedule.current.committee.as_ptr();
        let proofs: Vec<_> = commitment
            .commitment()
            .schedule
            .current
            .committee
            .iter()
            .map(|member| member.proof_of_possession.as_ptr())
            .collect();
        let canonical_result = commitment.preimage().unwrap();
        let witness = iroha_crypto::HashOf::new(original.witness.wire());
        let budget = worker.state.ivm_execution_budget();
        assert!(original.phase.ready().unwrap().belongs_to(&budget));
        let held = budget.reserved_bytes();
        for _ in 0..2 {
            assert!(matches!(
                worker.execute(&block, block_hash, false),
                Some(ExecOutcome::Failed(_))
            ));
            let retained = worker.finishing.as_ref().unwrap();
            assert_eq!(std::ptr::from_ref(retained.overlay.as_ref()), overlay);
            assert_eq!(
                retained
                    .phase
                    .ready()
                    .unwrap()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                authority
            );
            let commitment = retained.phase.ready().unwrap().get();
            assert_eq!(
                commitment
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .iter()
                    .map(|member| member.proof_of_possession.as_ptr())
                    .collect::<Vec<_>>(),
                proofs
            );
            assert_eq!(commitment.preimage().unwrap(), canonical_result);
            assert_eq!(iroha_crypto::HashOf::new(retained.witness.wire()), witness);
            assert!(
                retained
                    .archive_refusal
                    .as_ref()
                    .unwrap()
                    .is_local_refusal()
            );
            assert!(retained.native_contexts.is_none());
            assert_eq!(budget.reserved_bytes(), held);
            assert!(retained.phase.ready().unwrap().belongs_to(&budget));
            assert!(!worker.results.contains_key(&block_hash));
            assert!(worker.recovery.is_none());
        }
        assert!(events.try_recv().is_err());
        drop(occupied);
        let Some(ExecOutcome::Valid { result: digest, .. }) =
            worker.execute(&block, block_hash, false)
        else {
            panic!("original execution finishes after actual pool capacity returns")
        };
        let live = worker.live.as_ref().unwrap();
        assert_eq!(
            std::ptr::from_ref(live.overlay.as_deref().unwrap()),
            overlay
        );
        // RetainedPayload's inline value moves into Live. Its original heap allocations,
        // complete canonical value and allocation-pool custody must survive that move.
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .as_ptr(),
            authority
        );
        assert_eq!(
            live.commitment()
                .get()
                .commitment()
                .schedule
                .current
                .committee
                .iter()
                .map(|member| member.proof_of_possession.as_ptr())
                .collect::<Vec<_>>(),
            proofs
        );
        assert_eq!(
            live.commitment().get().preimage().unwrap(),
            canonical_result
        );
        assert!(live.commitment().belongs_to(&budget));
        assert_eq!(
            iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
            witness
        );
        let source = live.native_contexts.as_ref().unwrap();
        let bytes = source.canonical_bytes().to_vec();
        let carrier_hash = source.carrier_hash();
        let projection: crate::state::NativeExecutionProjectionV1 =
            norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap();
        assert_eq!(projection.carrier_hash, carrier_hash);
        assert_eq!(projection.carrier_height, 2);
        assert_eq!(
            &projection.casting_bindings,
            live.overlay
                .as_ref()
                .unwrap()
                .captured_parliament_casting_bindings()
                .unwrap()
        );
        assert_eq!(
            projection.ordinary_writes,
            live.witness.as_ref().unwrap().writes,
            "archive retains the exact original execution write order"
        );
        assert!(
            live.commitment()
                .get()
                .commitment()
                .native_lanes
                .matches_state_encoding(chain.network_id(), 2, &projection.lanes)
                .unwrap()
        );
        let qc = chain.commit_qc(2, block_hash, digest, Signers::Quorum);
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        let stored = worker
            .context
            .native_context_archive
            .read_exact(2, carrier_hash)
            .unwrap();
        assert_eq!(stored.as_slice(), bytes);
        assert_eq!(worker.state.view().height(), 2);
    });
}

#[test]
fn native_context_archive_failure_preserves_original_bytes_until_durable_acknowledgement() {
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let original = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let pointer = original.canonical_bytes().as_ptr();
        let bytes = original.canonical_bytes().to_vec();
        let hash = original.carrier_hash();
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let directory = chain.kura().store_root().join("native-contexts");
        let hidden = directory.with_extension("temporarily-unavailable");
        std::fs::rename(&directory, &hidden).unwrap();
        assert!(
            worker
                .commit(&block, &qc)
                .unwrap_err()
                .to_string()
                .contains("native context archive publication")
        );
        assert_eq!(worker.state.view().height(), 2);
        assert_eq!(worker.applied.0, 1);
        assert!(worker.live.as_ref().unwrap().overlay.is_none());
        let pending = worker.pending_commit.as_ref().unwrap();
        let event_count = pending.events.len();
        assert!(event_count > 0);
        assert_eq!(pending.native_contexts.canonical_bytes().as_ptr(), pointer);
        assert_eq!(pending.native_contexts.canonical_bytes(), bytes);
        for _ in 0..2 {
            assert!(worker.commit(&block, &qc).is_err());
            assert_eq!(
                worker
                    .pending_commit
                    .as_ref()
                    .unwrap()
                    .native_contexts
                    .canonical_bytes()
                    .as_ptr(),
                pointer
            );
            assert!(worker.execute(&block, qc.block_hash, false).is_none());
            assert_eq!(worker.build(3, 0, 1 << 20, 100).unwrap(), None);
            assert_eq!(worker.applied.0, 1);
            assert!(events.try_recv().is_err());
        }
        std::fs::rename(&hidden, &directory).unwrap();
        let next = worker.commit(&block, &qc).unwrap();
        assert!(worker.pending_commit.is_none());
        assert_eq!(worker.applied, (2, qc.block_hash));
        assert_eq!(
            worker
                .context
                .native_context_archive
                .read_exact(2, hash)
                .unwrap()
                .as_slice(),
            bytes
        );
        let mut emitted = 0;
        while events.try_recv().is_ok() {
            emitted += 1;
        }
        assert_eq!(emitted, event_count);
        assert_eq!(worker.commit(&block, &qc).unwrap(), next);
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn native_context_archive_preparation_refuses_foreign_pool_without_reexecuting() {
    with_worker(|chain, worker, _blocks, events| {
        let archive_files = || {
            std::fs::read_dir(chain.kura().store_root().join("native-contexts"))
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<BTreeMap<_, _>>()
        };
        let original_archives = archive_files();
        assert_eq!(
            original_archives.len(),
            1,
            "original genesis context is durable"
        );
        let genesis_context = worker
            .context
            .native_context_archive
            .read_exact(1, chain.genesis().hash())
            .unwrap();
        assert_eq!(
            original_archives.values().next().unwrap().as_slice(),
            genesis_context.as_slice()
        );
        drop(genesis_context);
        let block = proposal(chain, worker);
        let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let foreign_budget = iroha_allocation::AllocationBudget::new(1 << 20);
        let foreign = NativeContextArchive::open(
            chain.kura(),
            foreign_budget.clone(),
            chain.kura().native_context_archive_max_bytes(),
        )
        .unwrap();
        let mut original_overlay = None;
        let mut original_result = None;
        let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
            worker.prepare_original_result().unwrap();
            let original = worker.finishing.as_ref().unwrap();
            original_overlay = Some(std::ptr::from_ref(original.overlay.as_ref()));
            let result = original.phase.ready().unwrap();
            assert!(result.belongs_to(&worker.state.ivm_execution_budget()));
            original_result = Some((
                result
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                result
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .iter()
                    .map(|member| member.proof_of_possession.as_ptr())
                    .collect::<Vec<_>>(),
                result.get().preimage().unwrap(),
            ));
            assert!(matches!(
                foreign.prepare(
                    &original.overlay,
                    original.valid.as_ref(),
                    original.phase.ready().unwrap(),
                    &original.witness
                ),
                Err(NativeContextArchiveError::Source(_)),
            ));
            assert_eq!(foreign_budget.reserved_bytes(), 0);
            assert!(original.native_contexts.is_none());
            assert_eq!(archive_files(), original_archives);
            worker.finish_execution_with_encoder(false, encode_result_preimage)
        });
        assert!(matches!(outcome, Ok(Some(_))));
        let retained = worker.live.as_ref().unwrap();
        assert_eq!(
            Some(std::ptr::from_ref(retained.overlay.as_deref().unwrap())),
            original_overlay
        );
        assert_eq!(
            Some((
                retained
                    .commitment()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .as_ptr(),
                retained
                    .commitment()
                    .get()
                    .commitment()
                    .schedule
                    .current
                    .committee
                    .iter()
                    .map(|member| member.proof_of_possession.as_ptr())
                    .collect::<Vec<_>>(),
                retained.commitment().get().preimage().unwrap(),
            )),
            original_result
        );
        assert!(
            retained
                .commitment()
                .belongs_to(&worker.state.ivm_execution_budget())
        );
        assert!(retained.native_contexts.is_some());
        assert_eq!(
            archive_files(),
            original_archives,
            "preparation publishes no H2 archive"
        );
        assert_eq!(foreign_budget.reserved_bytes(), 0);
        assert_eq!(worker.state.view().height(), 1);
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry() {
    with_worker_from(
        || {
            let mut config = TestChainConfig::new(World::new(), 1_000);
            config
                .genesis_parameters
                .push(iroha_data_model::parameter::Parameter::Custom(
                    iroha_data_model::sumeragi_lanes::SumeragiLanePolicy::for_chain(
                        iroha_data_model::parameter::system::SumeragiParameters::default(),
                        iroha_sumeragi::availability::recommended_data_availability_layout(),
                    )
                    .into_custom_parameter(),
                ));
            CertifiedTestChain::start(config).expect("original signed lane policy")
        },
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let transaction = chain.tick(2_000);
            let hash = transaction.hash_as_entrypoint();
            let (_, time) =
                iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
                &time,
            )
            .unwrap();
            queue.push(accepted, chain.state().view()).unwrap();
            worker.queue = Some(Clone::clone(&queue));
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
            let original = norito::with_decode_limits_scope(limits, || {
                super::super::lanes::lane_policy(worker.state.view().world()).unwrap_err()
            });
            assert_eq!(
                original.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            assert!(original.allocation_refusal().is_none());
            let policy_id = iroha_data_model::sumeragi_lanes::SumeragiLanePolicy::parameter_id();
            let original_policy = worker
                .state
                .view()
                .world()
                .parameters()
                .custom()
                .get(&policy_id)
                .unwrap()
                .payload()
                .get()
                .to_owned();
            let budget = worker.state.ivm_execution_budget();
            let charged = budget.reserved_bytes();
            let returned =
                norito::with_decode_limits_scope(limits, || worker.build(2, 0, 1 << 20, 100));
            let Err(PublicationError::Deferred(returned)) = returned else {
                panic!("original lane policy refusal must reach the driver as a typed deferral");
            };
            assert_eq!(returned, PublicationDeferral::Execution(original.clone()));
            assert!(returned.release_wait().is_none());
            assert_eq!(
                worker.routing_refusal.as_ref(),
                Some(&original),
                "the actual merge proposal must retain the original policy owner before diagnostics"
            );
            assert!(worker.payload_build.is_none());
            assert!(worker.completed_payload.is_none());
            assert!(worker.live.is_none());
            assert!(worker.recovery.is_none());
            assert!(worker.results.is_empty());
            assert!(worker.pending_commit.is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(queue.queued_len(), 1);
            assert_eq!(budget.reserved_bytes(), charged);
            assert_eq!(
                worker
                    .state
                    .view()
                    .world()
                    .parameters()
                    .custom()
                    .get(&policy_id)
                    .unwrap()
                    .payload()
                    .get(),
                &original_policy
            );
            let payload = worker.build(2, 0, 1 << 20, 100).unwrap();
            let payload = payload.expect("same queued original retries after caller scope removal");
            let block = super::super::payload::decode(payload.as_slice()).unwrap();
            assert!(
                block
                    .external_entrypoints_slice()
                    .iter()
                    .any(|entry| entry.hash() == hash)
            );
            assert!(worker.routing_refusal.is_none());
            assert_eq!(queue.queued_len(), 1);
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.view().height(), 1);
        },
    );
}

#[test]
fn beacon_startup_retains_original_capacity_through_worker_channel_and_node() {
    with_worker(|chain, worker, _, _| {
        use crate::sumeragi::node::NodeError;
        use iroha_allocation::AllocationRefusal;
        use std::task::{Context, Poll, Waker};

        let (block, _) = executed(chain, worker);
        let overlay = original_overlay(worker);
        let applied = worker.applied;
        let budget = worker.state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        registration.bind_thread(std::thread::current());
        let executor = StateExecutor::spawn(worker.context.clone()).unwrap();
        let _epoch = crossbeam_epoch::pin();
        let pressure = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("the original State pool is occupied, not policy-invalid");
        };
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );

        let direct = worker
            .attach_beacon(chain.instance(), None, None)
            .unwrap_err();
        let PublicationError::Deferred(ref original) = direct else {
            panic!("readiness must retain the exact original State refusal: {direct:?}");
        };
        assert_eq!(original.release_wait(), Some(&release));
        assert!(
            matches!(original.allocation_refusal(), Some(AllocationRefusal::Capacity { requested_bytes, .. }) if *requested_bytes > 0)
        );
        assert!(worker.beacon.is_none());
        assert!(worker.recovery.is_none());
        assert_eq!(original_overlay(worker), overlay);
        assert_eq!(worker.applied, applied);
        assert_eq!(
            worker.live.as_ref().unwrap().block_hash,
            block.hash(&**worker.context.crypto.as_ref().unwrap())
        );

        let error = executor
            .attach_beacon(chain.instance(), None, None)
            .unwrap_err();
        assert_eq!(
            error, direct,
            "the request channel preserves the complete refusal"
        );
        let NodeError::ControlAttachment(PublicationError::Deferred(retained)) =
            NodeError::from(error)
        else {
            panic!("node startup must retain the original publication error");
        };
        assert_eq!(retained, *original);
        assert_eq!(retained.release_wait(), Some(&release));
        let again = executor
            .attach_beacon(chain.instance(), None, None)
            .unwrap_err();
        assert_eq!(
            again, direct,
            "failed attachment did not replace or attach a producer"
        );

        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        drop(pressure);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Ready(())
        );
        registration.cancel();

        let report = worker.attach_beacon(chain.instance(), None, None).unwrap();
        let serialized_report = executor
            .attach_beacon(chain.instance(), None, None)
            .unwrap();
        assert!(worker.beacon.is_some());
        assert!(worker.recovery.is_none());
        assert_eq!(original_overlay(worker), overlay);
        assert_eq!(worker.applied, applied);
        assert!(report.read(0, applied.0 + 1, applied.0).is_none());
        assert!(
            serialized_report
                .read(0, applied.0 + 1, applied.0)
                .is_none()
        );
        assert!(matches!(
            executor.attach_beacon(chain.instance(), None, None),
            Err(PublicationError::RecoveryRequired(_))
        ));
    });
}

#[test]
fn original_prepared_signature_owner_survives_refusal_validation_publication_apply_and_replay() {
    use crate::test_allocations::refuse_one_layout_during;
    use iroha_data_model::block::BlockSignatures;
    with_worker(|chain, worker, blocks, events| {
        let block = proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let source_pointer = block.payload().as_slice().as_ptr();
        let (outcome, refused) =
            refuse_one_layout_during(BlockSignatures::allocation_layout(), || {
                worker.execute(&block, hash, false)
            });
        assert!(refused);
        assert!(matches!(outcome, Some(ExecOutcome::Failed(_))));
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert!(!worker.results.contains_key(&hash));
        let attempt = worker
            .signature_decode
            .as_ref()
            .expect("same original signature decode retained");
        assert_eq!(attempt.source.payload().as_slice().as_ptr(), source_pointer);
        assert!(
            attempt
                .decoder
                .belongs_to(&chain.state().ivm_execution_budget())
        );
        let (block, qc) = execute_proposal(chain, worker, block);
        assert!(worker.signature_decode.is_none());
        let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase else {
            panic!("same original completed validation");
        };
        assert!(
            valid
                .as_ref()
                .signatures_admitted_to(&chain.state().ivm_execution_budget())
        );
        let original = valid.as_ref().clone();
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        let staged = worker.context.staging.get(&hash).unwrap();
        assert!(staged.executed.same_signature_custody(&original));
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        let applied = worker.state.view().latest_block().unwrap().unwrap();
        assert!(applied.same_signature_custody(&original));
        assert!(applied.signatures_admitted_to(&chain.state().ivm_execution_budget()));
        while events.try_recv().is_ok() {}
        // Original already-applied replay retires once and never replaces its custody.
        worker.replay(&block, &qc).unwrap();
        assert!(
            worker
                .state
                .view()
                .latest_block()
                .unwrap()
                .unwrap()
                .same_signature_custody(&original)
        );
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn explicit_signature_preparation_rejection_retires_only_its_original_source() {
    use crate::test_allocations::refuse_one_layout_during;
    use iroha_data_model::block::BlockSignatures;
    with_worker(|chain, worker, _blocks, _events| {
        let block = proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let (outcome, refused) =
            refuse_one_layout_during(BlockSignatures::allocation_layout(), || {
                worker.execute(&block, hash, false)
            });
        assert!(refused);
        assert!(matches!(outcome, Some(ExecOutcome::Failed(_))));
        let pointer = worker
            .signature_decode
            .as_ref()
            .unwrap()
            .source
            .payload()
            .as_slice()
            .as_ptr();
        worker.reject(block.header().height, block.header().origin_view + 1, hash);
        assert_eq!(
            worker
                .signature_decode
                .as_ref()
                .unwrap()
                .source
                .payload()
                .as_slice()
                .as_ptr(),
            pointer
        );
        worker.reject(block.header().height, block.header().origin_view, hash);
        assert!(worker.signature_decode.is_none());
        assert!(worker.routing_refusal.is_none());
        assert!(worker.results.is_empty());
    });
}

#[test]
fn later_canonical_child_allocator_refusal_keeps_the_original_prepared_signature_owner() {
    use crate::test_allocations::refuse_one_layout_during;
    use norito::core::SequenceSpan;
    with_worker(|chain, worker, _blocks, _events| {
        let block = proposal(chain, worker);
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let (outcome, refused) =
            refuse_one_layout_during(std::alloc::Layout::array::<u8>(64).unwrap(), || {
                worker.execute(&block, hash, false)
            });
        assert!(refused);
        assert!(matches!(outcome, Some(ExecOutcome::Failed(_))));
        assert!(!worker.results.contains_key(&hash));
        let pool = chain.state().ivm_execution_budget();
        let attempt = worker.signature_decode.as_mut().unwrap();
        let source = attempt.source.payload().charged_source(&pool).unwrap();
        assert!(
            attempt
                .decoder
                .retained_signatures(source)
                .unwrap()
                .unwrap()
                .admitted_to(&pool)
        );
        // Read the same original canonical input to observe custody identity; this does
        // not execute any transaction or replace the existing production validator.
        let original = attempt
            .decoder
            .decode(
                source,
                SequenceSpan {
                    start: 0,
                    end: source.as_slice().len(),
                },
                norito::canonical_decode_limits(source.as_slice().len()),
            )
            .unwrap();
        let (_block, _qc) = execute_proposal(chain, worker, block);
        let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase else {
            panic!("the original prepared signature owner completed validation");
        };
        assert!(valid.as_ref().same_signature_custody(&original));
        assert!(worker.signature_decode.is_none());
    });
}

/// The global proposer selects within the payload limit less the reserve the data model owns
/// (`specs/zk_resource_contract.json`, `block.payload_transaction_reserve_bytes`), which is the
/// budget queue admission grants. The real build carries a queued transaction of exactly that
/// length inside the committed limit, and skips it under a limit one byte smaller without
/// proposing an empty block.
#[test]
fn global_build_carries_a_transaction_of_the_payload_limit_less_the_reserve() {
    use iroha_data_model::{
        isi::{InstructionBox, Log},
        parameter::{
            Parameter,
            system::{
                BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, SumeragiParameter,
                TransactionParameter,
            },
        },
        privacy::PrivacyConsensusLimitsV1,
    };
    const INCLUDABLE: u32 = 16 * 1024;
    const MAX_BLOCK_BYTES: u32 = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + INCLUDABLE;
    assert_eq!(
        PAYLOAD_OVERHEAD,
        BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES as usize
    );
    let (send_clock, receive_clock) = std::sync::mpsc::channel();
    with_worker_from(
        move || {
            let world = World::new();
            // The fixture keeps its original 16-KiB boundary. Its initial
            // privacy profile and signed transaction cap must fit that bound,
            // so actual genesis execution can certify a coherent policy.
            let limits = PrivacyConsensusLimitsV1 {
                max_proof_bytes_per_action: INCLUDABLE,
                max_action_bytes: INCLUDABLE,
                max_privacy_bytes_per_transaction: INCLUDABLE,
                max_privacy_bytes_per_block: INCLUDABLE,
                max_statement_and_encrypted_output_bytes_per_transaction: INCLUDABLE,
                ..PrivacyConsensusLimitsV1::taira_default()
            };
            limits
                .validate()
                .expect("coherent small-cap privacy profile");
            let mut privacy = world.privacy_consensus_policy.block();
            privacy.get_mut().current_limits = limits;
            privacy.commit();
            let mut config = TestChainConfig::new(world, 1_000);
            config.genesis_parameters.extend([
                Parameter::Transaction(TransactionParameter::MaxTxBytes(
                    std::num::NonZeroU64::new(u64::from(INCLUDABLE)).unwrap(),
                )),
                Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
                    std::num::NonZeroU32::new(MAX_BLOCK_BYTES).unwrap(),
                )),
            ]);
            let prepared = CertifiedTestChain::prepare(config).expect("prepared signed genesis");
            send_clock
                .send(prepared.clock.clone())
                .expect("fixture clock key");
            CertifiedTestChain::from_prepared(prepared).expect("actual signed genesis")
        },
        ConsensusMode::Permissioned,
        move |chain, worker, _blocks, _events| {
            let clock = receive_clock.recv().expect("fixture clock key");
            let (_, time) =
                iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(2_001));
            let accept = |message_len: usize| {
                crate::tx::AcceptedTransaction::accept_with_time_source(
                    chain.sign(
                        &clock,
                        [InstructionBox::from(Log::new(
                            iroha_data_model::Level::DEBUG,
                            "x".repeat(message_len),
                        ))],
                        2_000,
                    ),
                    &chain.network_id(),
                    Duration::from_secs(1),
                    chain.state().view().world().parameters().transaction(),
                    &iroha_config::parameters::actual::Crypto::default(),
                    &time,
                )
                .expect("within the transaction cap")
            };
            assert_eq!(
                chain
                    .state()
                    .view()
                    .world()
                    .parameters()
                    .transaction()
                    .max_tx_bytes()
                    .get(),
                u64::from(INCLUDABLE)
            );
            assert_eq!(
                chain
                    .state()
                    .view()
                    .world()
                    .privacy_consensus_policy()
                    .current_limits
                    .max_privacy_bytes_per_block,
                INCLUDABLE
            );
            // A transaction whose framed length is exactly the includable bound.
            let target = usize::try_from(INCLUDABLE).unwrap();
            let slack = 1_024;
            let probe = accept(target - slack).encoded_len();
            let transaction = accept(target - slack + (target - probe));
            assert_eq!(transaction.encoded_len(), target);
            assert_eq!(
                chain
                    .state()
                    .view()
                    .world()
                    .parameters()
                    .sumeragi()
                    .max_block_bytes
                    .get(),
                MAX_BLOCK_BYTES
            );
            let hash = transaction.hash_as_entrypoint();
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            queue
                .push(transaction, chain.state().view())
                .expect("admission accepts the includable bound itself");
            worker.queue = Some(Clone::clone(&queue));
            let exec_budget_ms = u32::try_from(
                chain
                    .state()
                    .view()
                    .world()
                    .consensus_schedule()
                    .ready(2)
                    .expect("committed schedule authorizes the payload build")
                    .params
                    .exec_budget_ms,
            )
            .expect("fixture execution budget fits the worker request");

            // One byte less payload leaves a budget one byte short of the transaction.
            let payload = worker
                .build(2, 0, MAX_BLOCK_BYTES - 1, exec_budget_ms)
                .unwrap();
            assert!(
                payload.is_none(),
                "the transaction is skipped and no empty block is proposed"
            );
            assert!(worker.completed_payload.is_none());
            assert!(worker.payload_build.is_none());

            // The committed limit carries it, with the block framing inside the reserve.
            let Some(bytes) = worker.build(2, 0, MAX_BLOCK_BYTES, exec_budget_ms).unwrap() else {
                panic!("the committed payload limit carries the includable bound");
            };
            let wire = bytes.as_slice().len();
            assert!(
                wire > target && wire <= usize::try_from(MAX_BLOCK_BYTES).unwrap(),
                "assembled payload: {wire} bytes"
            );
            let proposal = payload::decode(bytes.as_slice()).unwrap();
            assert_eq!(proposal.external_entrypoints_slice().len(), 1);
            assert_eq!(proposal.external_entrypoints_slice()[0].hash(), hash);
            assert_eq!(
                queue.queued_len(),
                1,
                "the builder peeks; it removes nothing"
            );
            assert!(queue.contains_entrypoint_hash(hash));
        },
    );
}

#[test]
fn worker_fixture_invokes_and_consumes_one_move_only_callback_on_the_actual_chain() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CallbackOwner(Arc<AtomicUsize>);
    impl Drop for CallbackOwner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = CallbackOwner(Arc::clone(&drops));
    let observed = Arc::clone(&calls);
    with_worker(move |chain, worker, _, _| {
        assert_eq!(observed.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(chain.validators().len(), 4);
        assert!(std::ptr::eq(worker.state, &**chain.state()));
        assert_eq!(worker.applied.0, chain.height());
        assert_eq!(
            worker.applied.1,
            chain.committed(chain.height()).core_hash()
        );
        drop(owner);
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// Late World-cut control funding must not discard successful native reconstruction.
#[test]
fn original_worker_world_cut_retains_completed_tail_after_final_control_refusal() {
    use crate::state::world_projection::world_state_accumulator::world_state_cut::completion_observer;
    with_worker(|chain, worker, blocks, events| {
        let (block, qc) = executed(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let limit = budget.limit_bytes();
        let height = worker.state.view().height();
        let applied = worker.applied;
        let overlay = original_overlay(worker);
        let wire = block.payload().as_slice().as_ptr();
        let source = std::ptr::from_ref(block.source());
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
        blocks.append(&block, &qc).unwrap();
        completion_observer::observe(&budget, |observation| {
            let Err(PublicationError::Deferred(reason)) = worker.commit(&block, &qc) else {
                panic!("actual completed World cut must defer at final original shell funding");
            };
            assert!(matches!(reason.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, limit_bytes, .. })
                if *requested_bytes == completion_observer::control_bytes()
                && *limit_bytes == limit));
            drop(reason);
            let completed = observation.snapshot();
            assert_eq!(
                completed.0, 1,
                "actual native reconstruction completed once"
            );
            assert!(completed.1.is_some());
            assert_eq!(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_deref()
                    .unwrap()
                    .completed_world_cut_identity_for_test(),
                completed.1,
                "completed original World cut must survive final shared-control refusal"
            );
            assert_eq!(original_overlay(worker), overlay);
            assert_eq!(worker.applied, applied);
            assert_eq!(worker.state.view().height(), height);
            assert!(worker.recovery.is_none());
            assert!(events.try_recv().is_err());
            assert!(budget.same_pool(&worker.state.ivm_execution_budget()));
            assert_eq!(block.payload().as_slice().as_ptr(), wire);
            assert_eq!(std::ptr::from_ref(block.source()), source);
            let (write_free, commit_free) = worker.state.publication_fences_available_for_test();
            assert!(write_free);
            assert!(commit_free);
            // The original reconstructed scratch retired on the refused return.
            // Its freed capacity may already fit the shell; never require another
            // refusal or change the configured limit to manufacture a retry.
            observation.release_original_blocker();
            worker
                .commit(&block, &qc)
                .expect("same original completed cut publishes after release");
            assert_eq!(
                observation.snapshot(),
                completed,
                "final shell retry must not hash or reconstruct the original tail again"
            );
            assert_eq!(budget.limit_bytes(), limit);
            assert_eq!(worker.applied, (block.header().height, qc.block_hash));
            assert_eq!(worker.state.view().height(), height + 1);
            assert!(worker.live.as_ref().unwrap().overlay.is_none());
            assert!(worker.recovery.is_none());
            let original_events = std::iter::from_fn(|| events.try_recv().ok()).count();
            assert!(
                original_events > 0,
                "real original publication emits its retained events"
            );
            worker.commit(&block, &qc).unwrap();
            assert_eq!(observation.snapshot(), completed);
            assert!(
                events.try_recv().is_err(),
                "published completion delivers events once"
            );
        });
    });
}

/// Completed local cut custody cannot authorize a changed State visibility source.
#[test]
fn original_worker_completed_world_cut_refuses_changed_publication_source() {
    use crate::state::world_projection::world_state_accumulator::world_state_cut::completion_observer;
    with_worker(|chain, worker, blocks, _events| {
        let (block, qc) = executed(chain, worker);
        let budget = worker.state.ivm_execution_budget();
        let height = worker.state.view().height();
        let overlay = original_overlay(worker);
        assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
        blocks.append(&block, &qc).unwrap();
        completion_observer::observe(&budget, |observation| {
            assert!(matches!(
                worker.commit(&block, &qc),
                Err(PublicationError::Deferred(_))
            ));
            let completed = observation.snapshot();
            assert_eq!(completed.0, 1);
            assert_eq!(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_deref()
                    .unwrap()
                    .completed_world_cut_identity_for_test(),
                completed.1
            );
            let generation = worker.state.state_view_generation();
            worker
                .state
                .with_held_view_publication_for_reader_test(|_| {});
            assert_eq!(worker.state.state_view_generation(), generation + 2);
            observation.release_original_blocker();
            let mut exact_changed_source = false;
            let retry = worker.commit_with(&block, &qc, |original| {
                let outcome = original.try_publish();
                exact_changed_source = matches!(&outcome,
                    crate::state::StatePublicationOutcome::RecoveryRequired(
                        crate::state::storage_transactions::TransactionsBlockError::SnapshotObservationChanged));
                outcome
            });
            assert!(
                exact_changed_source,
                "the original typed generation refusal precedes completed capsule reuse"
            );
            assert!(matches!(retry, Err(PublicationError::RecoveryRequired(_))));
            assert_eq!(observation.snapshot(), completed);
            assert_eq!(original_overlay(worker), overlay);
            assert_eq!(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_deref()
                    .unwrap()
                    .completed_world_cut_identity_for_test(),
                completed.1
            );
            assert_eq!(worker.state.view().height(), height);
            assert!(worker.recovery.is_some());
            assert!(matches!(
                worker.commit(&block, &qc),
                Err(PublicationError::RecoveryRequired(_))
            ));
            assert_eq!(observation.snapshot(), completed);
        });
    });
}

#[test]
fn native_lane_proof_scratch_ceiling_remains_terminal_in_both_worker_stages() {
    for result_completed in [false, true] {
        with_worker(move |chain, worker, _blocks, events| {
            let block = proposal(chain, worker);
            let block_hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let original_limit = budget.limit_bytes();
            let epoch = crossbeam_epoch::pin();
            let mut identities = None;
            let mut held = None;
            let outcome = worker.run_execution_with_finisher(&block, block_hash, false, |worker| {
                if result_completed { worker.prepare_original_result().unwrap(); }
                let original = worker.finishing.as_ref().unwrap();
                let demand = NativeLaneStateProof::scratch_bytes(original.witness.writes.len()).unwrap();
                assert!(demand > 0);
                budget.set_limit_bytes(demand - 1);
                let error = NativeLaneStateProof::from_witness(&original.witness, &budget).unwrap_err();
                assert!(matches!(error, NativeLaneStateProofError::Scratch(iroha_allocation::ChargedBufferError::Admission(iroha_allocation::AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes })) if requested_bytes == demand && limit_bytes == demand - 1));
                assert!(!error.is_local_refusal());
                identities = Some((std::ptr::from_ref(original.overlay.as_ref()), original.witness.writes.as_ptr(), iroha_crypto::HashOf::new(original.witness.wire())));
                held = Some(budget.reserved_bytes());
                worker.finish_execution_with_encoder(false, encode_result_preimage)
            });
            budget.set_limit_bytes(original_limit);
            assert!(
                matches!(outcome, Err(PublicationError::RecoveryRequired(_))),
                "a proof scratch demand above its hard ceiling remains terminal: {outcome:?}"
            );
            assert!(worker.recovery.is_some());
            assert!(worker.live.is_none());
            let original = worker.finishing.as_ref().unwrap();
            assert_eq!(original.phase.ready().is_some(), result_completed);
            let (overlay, writes, witness) = identities.unwrap();
            assert_eq!(std::ptr::from_ref(original.overlay.as_ref()), overlay);
            assert_eq!(original.witness.writes.as_ptr(), writes);
            assert_eq!(iroha_crypto::HashOf::new(original.witness.wire()), witness);
            assert_eq!(budget.reserved_bytes(), held.unwrap());
            assert_eq!(worker.state.committed_height(), 1);
            assert!(events.try_recv().is_err());
            drop(epoch);
        });
    }
}
