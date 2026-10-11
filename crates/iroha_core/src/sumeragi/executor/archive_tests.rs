//! Current archive ownership after State publication, using genuine four-validator certificates.
//!
//! Archive failure retains an already committed decision; retry may capture it, but cannot execute or notify it twice.
use super::*;
use crate::{
    query::{
        provider_ingest_finalized::{
            ProviderIngestFinalizedArchiveBoundsV1, ProviderIngestFinalizedArchiveInsertOutcomeV1,
            ProviderIngestFinalizedArchiveV1,
        },
        reputation_finalized::{ReputationFinalizedArchive, ReputationFinalizedArchiveBounds},
    },
    state::World,
    sumeragi::{
        block_store::KuraBlockStore,
        crypto::BlsCrypto,
        driver::traits::BlockStore as _,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use iroha_data_model::{
    isi::sorafs::SetSorafsReputationJournalAuthorityPolicy,
    sorafs::reputation::{
        REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1, REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
        ReputationJournalAuthorityPolicyV1,
    },
};
use iroha_executor_data_model::permission::sorafs::CanManageSorafsReputationJournalPolicy;

fn chain() -> CertifiedTestChain {
    CertifiedTestChain::start(config()).unwrap()
}

/// The same deterministic configuration on every call: a restart rebuilds its pristine State.
fn config() -> TestChainConfig {
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
        isi::{
            Grant, Register,
            sorafs::{SetSorafsOrderbookPolicy, SetSorafsReservePolicy},
        },
        sorafs::{
            orderbook::{ORDERBOOK_ADMISSION_POLICY_VERSION_V1, OrderbookAdmissionPolicyV1},
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1,
            },
        },
    };
    use iroha_executor_data_model::permission::sorafs::{
        CanSetSorafsPricing, CanSetSorafsReservePolicy,
    };
    let mut config = TestChainConfig::new(World::new(), 1_750_000_000_000);
    let authority = AccountId::new(config.genesis_key.public_key().clone());
    let custody = iroha_test_samples::ALICE_ID.clone();
    let asset_id = AssetDefinitionId::derive_from_components(
        iroha_genesis::GENESIS_DOMAIN_ID.clone(),
        "reserve".parse().unwrap(),
    );
    // Every feed capture queries has its actual governed policy, enacted by signed genesis.
    config.genesis_instructions.extend([
        Grant::account_permission(CanManageSorafsReputationJournalPolicy, authority.clone()).into(),
        SetSorafsReputationJournalAuthorityPolicy::new(ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: authority.clone(),
            dispute_recorder_authority: authority.clone(),
            token_recorder_authority: authority.clone(),
            stream_token_delivery: Default::default(),
            max_source_age_ms: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
        })
        .into(),
        Grant::account_permission(CanSetSorafsPricing, authority.clone()).into(),
        SetSorafsOrderbookPolicy::new(OrderbookAdmissionPolicyV1 {
            version: ORDERBOOK_ADMISSION_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            market_id: [0xA5; 32],
            matcher_authority: authority.clone(),
            settlement_authority: authority.clone(),
            paused: false,
            min_order_gib: 1,
            max_order_gib: 1024,
            price_tick_micro_xor: 10,
            max_maker_fee_bps: 100,
            max_taker_fee_bps: 200,
            max_order_lifetime_secs: 3600,
            max_receipt_age_secs: 300,
            max_clock_skew_secs: 5,
            max_receipt_bytes: 1024,
            max_receipts_per_channel: 2,
        })
        .into(),
        Register::account(Account::new(custody.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_id.clone(),
            "Reserve".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Grant::account_permission(CanSetSorafsReservePolicy, authority.clone()).into(),
        SetSorafsReservePolicy::new(ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            economics: ReservePolicyV1::default(),
            asset_definition: asset_id,
            custody_account: custody,
            treasury_account: authority.clone(),
            operations_authority: authority.clone(),
            decision_authority: authority,
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: sorafs_manifest::deal::XorQuantity::try_from_micro(1_000_000_000)
                .unwrap(),
            max_pending_movements_per_provider: 4,
            max_open_appeals_per_provider: 2,
        })
        .into(),
    ]);
    config
}

fn provider_bounds() -> ProviderIngestFinalizedArchiveBoundsV1 {
    ProviderIngestFinalizedArchiveBoundsV1::try_new(4 << 20, 32, 64 << 20, 32, 32, 128, 32).unwrap()
}

fn archives() -> (tempfile::TempDir, FinalizedArchives) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let provider = ProviderIngestFinalizedArchiveV1::try_open(
        directory.path().join("provider"),
        provider_bounds(),
    )
    .unwrap();
    let reputation = ReputationFinalizedArchive::try_open(
        directory.path().join("reputation"),
        ReputationFinalizedArchiveBounds::try_new(4 << 20, 32, 64 << 20).unwrap(),
    )
    .unwrap();
    (
        directory,
        FinalizedArchives {
            provider_ingest: Some(Arc::new(provider)),
            reputation: Some(Arc::new(reputation)),
        },
    )
}

fn archive_files(root: &std::path::Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn walk(
        root: &std::path::Path,
        path: &std::path::Path,
        files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

fn context(
    chain: &CertifiedTestChain,
) -> (ExecutorContext, tokio::sync::broadcast::Receiver<EventBox>) {
    let (events, receiver) = tokio::sync::broadcast::channel(1024);
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            chain
                .validators()
                .iter()
                .map(|(peer, pop)| (peer.public_key(), pop.as_slice())),
        )
        .unwrap();
    (
        ExecutorContext {
            state: Clone::clone(chain.state()),
            native_context_archive: Arc::new(
                NativeContextArchive::open(
                    chain.kura(),
                    chain.state().ivm_execution_budget(),
                    chain.kura().native_context_archive_max_bytes(),
                )
                .unwrap(),
            ),
            queue: None,
            staging: Staging::new(),
            events,
            genesis_account: chain.genesis_account().clone(),
            consensus_mode: ConsensusMode::Permissioned,
            applied: (1, chain.committed(1).core_hash()),
            crypto: Some(crypto),
            applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(1, None)),
            lane_blocks: std::sync::Arc::new(crate::sumeragi::lanes::merge::NoLanes),
        },
        receiver,
    )
}

fn worker(context: &ExecutorContext, archives: FinalizedArchives) -> Worker<'_> {
    Worker {
        payload_build: None,
        signature_decode: None,
        routing_refusal: None,
        payload_refusal: None,
        context,
        state: &context.state,
        applied: context.applied,
        live: None,
        finishing: None,
        recovery: None,
        results: BTreeMap::new(),
        completed_payload: None,
        queue: context.queue.clone(),
        beacon: None,
        archives: Some(archives),
        pending_commit: None,
        completed_replay: None,
        quarantine_context: None,
    }
}

fn prepare_and_append(worker: &mut Worker<'_>, block: &AvailableBody, qc: &Qc) -> usize {
    assert_eq!(worker.prepare(block, qc).unwrap(), Some(qc.result));
    let original = worker
        .live
        .as_ref()
        .unwrap()
        .native_contexts
        .as_ref()
        .unwrap()
        .canonical_bytes()
        .as_ptr() as usize;
    KuraBlockStore::new(
        worker.state.kura_handle(),
        worker.context.crypto.as_ref().unwrap().clone(),
        1,
        worker.context.staging.clone(),
        worker.state.ivm_execution_budget(),
        Arc::new(
            crate::sumeragi::runtime_availability::NativeGlobalAvailability::new(
                Clone::clone(&worker.context.state),
                block.header().instance,
                Clone::clone(worker.context.crypto.as_ref().unwrap()),
            )
            .unwrap(),
        ),
    )
    .append(block, qc)
    .unwrap();
    original
}

fn hold_archive_completion(worker: &mut Worker<'_>, block: &AvailableBody, qc: &Qc) {
    let original = prepare_and_append(worker, block, qc);
    let root = worker
        .archives
        .as_ref()
        .unwrap()
        .reputation
        .as_ref()
        .unwrap()
        .root()
        .to_owned();
    let hidden = root.with_extension("temporarily-unavailable");
    std::fs::rename(&root, &hidden).unwrap();
    let error = worker.commit(block, qc).unwrap_err();
    std::fs::rename(&hidden, &root).unwrap();
    assert!(
        error
            .to_string()
            .contains("reputation archive capture failed"),
        "{error}"
    );
    let pending = worker.pending_commit.as_ref().unwrap();
    assert_eq!(
        pending.native_contexts.canonical_bytes().as_ptr() as usize,
        original
    );
    assert!(worker.live.as_ref().unwrap().overlay.is_none());
}

fn run(test: impl FnOnce() + Send + 'static) {
    crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-archive-test")
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn partial_archive_failure_retains_exact_decision_and_retries_without_reexecution_or_notifications()
{
    run(partial_archive_failure_retains_exact_decision_and_retries_without_reexecution_or_notifications_case);
}

fn assert_pending_archive_owner(
    worker: &mut Worker<'_>,
    block: &AvailableBody,
    qc: &Qc,
    original: usize,
    events: &mut tokio::sync::broadcast::Receiver<EventBox>,
) -> usize {
    let pending = worker.pending_commit.as_ref().unwrap();
    let event_count = pending.events.len();
    assert!(event_count > 0);
    assert_eq!(
        pending.native_contexts.canonical_bytes().as_ptr() as usize,
        original
    );
    assert_eq!(worker.state.view().height(), 2);
    assert_eq!(
        worker.state.view().latest_block_hash(),
        Some(pending.state_hash)
    );
    assert_eq!(worker.applied.0, 1);
    assert!(events.try_recv().is_err());
    assert!(worker.live.as_ref().unwrap().overlay.is_none());
    assert!(worker.execute(block, qc.block_hash).is_none());
    assert_eq!(worker.prepare(block, qc).unwrap(), Some(qc.result));
    event_count
}

fn complete_archive_once(
    worker: &mut Worker<'_>,
    block: &AvailableBody,
    qc: &Qc,
    events: &mut tokio::sync::broadcast::Receiver<EventBox>,
    expected_events: usize,
) {
    let state_hash = worker.pending_commit.as_ref().unwrap().state_hash;
    let completed = worker.commit(block, qc).unwrap();
    assert!(worker.pending_commit.is_none());
    assert_eq!(worker.applied, (2, qc.block_hash));
    assert_eq!(worker.state.view().height(), 2);
    assert_eq!(worker.state.view().latest_block_hash(), Some(state_hash));
    let mut emitted = 0;
    while events.try_recv().is_ok() {
        emitted += 1;
    }
    assert_eq!(
        emitted, expected_events,
        "each original notification is published once"
    );
    assert_eq!(worker.commit(block, qc).unwrap(), completed);
    assert!(events.try_recv().is_err());
}

#[test]
fn committed_archive_index_refusal_retains_original_release_and_exact_publication() {
    run(|| {
        use std::task::{Context, Waker};
        for provider_busy in [true, false] {
            let chain = chain();
            let mut registration = crate::unit_test_support::release_registration(
                &chain.state().ivm_execution_budget(),
            );
            let (_directory, archives) = archives();
            archives.capture(&chain.state().view()).unwrap();
            let provider = archives.provider_ingest.as_ref().unwrap();
            let reputation = archives.reputation.as_ref().unwrap();
            let provider_before = provider.health_generation().unwrap();
            let reputation_before = reputation.health_generation().unwrap();
            let (context, mut events) = context(&chain);
            let mut worker = worker(&context, archives.clone());
            let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
            let original = prepare_and_append(&mut worker, &block, &qc);
            let mut probe = || {
                let PublicationError::Deferred(reason) = worker.commit(&block, &qc).unwrap_err()
                else {
                    panic!("actual archive index contention must remain a typed deferral");
                };
                assert!(matches!(
                    (&reason, provider_busy),
                    (PublicationDeferral::ProviderArchiveBusy(_), true)
                        | (PublicationDeferral::ReputationArchiveBusy(_), false)
                ));
                assert!(
                    reason.execution().is_none(),
                    "an index lock is not VM capacity"
                );
                assert_eq!(
                    worker
                        .pending_commit
                        .as_ref()
                        .unwrap()
                        .archive_refusal
                        .as_ref(),
                    Some(&reason)
                );
                let expected_events =
                    assert_pending_archive_owner(&mut worker, &block, &qc, original, &mut events);
                let released = reason.release_wait().unwrap().clone();
                let mut cx = Context::from_waker(Waker::noop());
                assert!(registration.poll_wait(&released, &mut cx).is_pending());
                let foreign = iroha_allocation::AllocationBudget::new(8);
                drop(
                    foreign
                        .try_reserve(core::alloc::Layout::new::<u64>())
                        .unwrap(),
                );
                assert!(
                    registration.poll_wait(&released, &mut cx).is_pending(),
                    "foreign pool release is not archive release"
                );
                assert!(matches!(
                    worker.commit(&block, &qc),
                    Err(PublicationError::Deferred(_))
                ));
                (reason, expected_events)
            };
            let (reason, expected_events) = if provider_busy {
                provider.with_index_reader_for_testing(&mut probe).unwrap()
            } else {
                reputation
                    .with_index_reader_for_testing(&mut probe)
                    .unwrap()
            };
            let released = reason.release_wait().unwrap().clone();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                registration.poll_wait(&released, &mut cx).is_ready(),
                "original reader dropped"
            );
            complete_archive_once(&mut worker, &block, &qc, &mut events, expected_events);
            assert_eq!(provider.health_generation().unwrap(), provider_before + 1);
            assert_eq!(
                reputation.health_generation().unwrap(),
                reputation_before + 1
            );
        }
    });
}

#[test]
fn committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication() {
    run(|| {
        use iroha_allocation::AllocationBudget;
        use std::task::{Context, Waker};
        for provider_capture in [true, false] {
            let chain = chain();
            let mut registration = crate::unit_test_support::release_registration(
                &chain.state().ivm_execution_budget(),
            );
            let (_directory, archives) = archives();
            archives.capture(&chain.state().view()).unwrap();
            let (context, mut events) = context(&chain);
            let mut worker = worker(&context, archives.clone());
            let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
            hold_archive_completion(&mut worker, &block, &qc);
            worker.archives = Some(FinalizedArchives {
                provider_ingest: provider_capture
                    .then(|| archives.provider_ingest.as_ref().unwrap().clone()),
                reputation: (!provider_capture)
                    .then(|| archives.reputation.as_ref().unwrap().clone()),
            });
            let original = worker
                .pending_commit
                .as_ref()
                .unwrap()
                .native_contexts
                .canonical_bytes()
                .as_ptr() as usize;
            let expected_events =
                assert_pending_archive_owner(&mut worker, &block, &qc, original, &mut events);
            let genesis = std::num::NonZeroUsize::MIN;
            let original_wire = chain
                .kura()
                .canonical_block_wire_bytes_for_testing(genesis)
                .unwrap();
            chain
                .kura()
                .forget_cached_block_for_testing(genesis)
                .unwrap();
            let budget = chain.state().ivm_execution_budget();
            let occupied = budget
                .try_reserve(
                    core::alloc::Layout::from_size_align(
                        budget.limit_bytes() - budget.reserved_bytes(),
                        1,
                    )
                    .unwrap(),
                )
                .unwrap();
            // The authenticated cold reader first funds the exact stored frame,
            // before reserving the decoded SharedSignedBlock control.
            let layout = core::alloc::Layout::array::<u8>(original_wire.len()).unwrap();
            let expected: crate::execution_attempt::ExecutionDeferred =
                budget.try_reserve(layout).unwrap_err().into();
            let PublicationError::Deferred(reason) = worker.commit(&block, &qc).unwrap_err() else {
                panic!("original authenticated cold history read must remain deferred");
            };
            assert_eq!(reason.execution(), Some(&expected));
            assert_eq!(
                worker
                    .pending_commit
                    .as_ref()
                    .unwrap()
                    .archive_refusal
                    .as_ref(),
                Some(&reason)
            );
            assert_eq!(
                assert_pending_archive_owner(&mut worker, &block, &qc, original, &mut events),
                expected_events
            );
            assert_eq!(
                chain
                    .kura()
                    .canonical_block_wire_bytes_for_testing(genesis)
                    .unwrap(),
                original_wire
            );
            let released = reason.release_wait().unwrap().clone();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(registration.poll_wait(&released, &mut cx).is_pending());
            let foreign = AllocationBudget::new(layout.size());
            drop(foreign.try_reserve(layout).unwrap());
            assert!(registration.poll_wait(&released, &mut cx).is_pending());
            drop(occupied);
            assert!(registration.poll_wait(&released, &mut cx).is_ready());
            complete_archive_once(&mut worker, &block, &qc, &mut events, expected_events);
            assert_eq!(
                chain
                    .kura()
                    .canonical_block_wire_bytes_for_testing(genesis)
                    .unwrap(),
                original_wire
            );
        }
    });
}

fn partial_archive_failure_retains_exact_decision_and_retries_without_reexecution_or_notifications_case()
 {
    let chain = chain();
    let (directory, archives) = archives();
    archives.capture(&chain.state().view()).unwrap();
    let provider = archives.provider_ingest.as_ref().unwrap();
    let reputation = archives.reputation.as_ref().unwrap();
    let provider_before = provider.health_generation().unwrap();
    let reputation_before = reputation.health_generation().unwrap();
    let (context, mut events) = context(&chain);
    let mut worker = worker(&context, archives.clone());
    let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
    let proposal = payload::decode(block.payload().as_slice()).unwrap();
    let TransactionEntrypoint::External(transaction) = &proposal.external_entrypoints_slice()[0]
    else {
        panic!("real fixture carries its signed external transaction")
    };
    let transaction = transaction.clone();
    let entry_hash = transaction.hash_as_entrypoint();
    let (_clock, time) =
        iroha_primitives::time::TimeSource::new_mock(proposal.header().creation_time());
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
    assert!(queue.contains_entrypoint_hash(entry_hash));
    let original_contexts = prepare_and_append(&mut worker, &block, &qc);
    let staged = context.staging.get(&qc.block_hash).unwrap();
    assert!(
        staged
            .executed
            .network_output_at(0)
            .is_some_and(|(_, output)| output.result.is_ok()),
        "the original queued transaction executes successfully"
    );
    assert_eq!(
        worker.state.view().height(),
        1,
        "append does not publish State"
    );
    let hash = staged.executed.hash();
    let input_hashes: Vec<_> = staged
        .executed
        .external_entrypoints_slice()
        .iter()
        .map(TransactionEntrypoint::hash)
        .collect();
    assert!(!input_hashes.is_empty());
    assert_eq!(provider.health_generation().unwrap(), provider_before);
    assert_eq!(reputation.health_generation().unwrap(), reputation_before);
    let root = reputation.root().to_owned();
    let hidden = root.with_extension("temporarily-unavailable");
    std::fs::rename(&root, &hidden).unwrap();
    let error = worker.commit(&block, &qc).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("reputation archive capture failed"),
        "{error}"
    );
    let retained_events = worker.pending_commit.as_ref().unwrap().events.len();
    assert!(retained_events > 0);
    assert_eq!(
        worker
            .pending_commit
            .as_ref()
            .unwrap()
            .native_contexts
            .canonical_bytes()
            .as_ptr() as usize,
        original_contexts
    );
    assert_eq!(provider.health_generation().unwrap(), provider_before + 1);
    let original_provider_files = archive_files(&directory.path().join("provider"));
    assert!(!original_provider_files.is_empty());
    assert!(
        reputation.health_generation().is_err(),
        "the actual archive directory is unavailable"
    );
    assert_eq!(worker.applied.0, 1);
    assert_eq!(worker.state.view().height(), 2);
    assert_eq!(worker.state.view().latest_block_hash(), Some(hash));
    assert_eq!(worker.pending_commit.as_ref().unwrap().hashes, input_hashes);
    assert!(
        queue.contains_entrypoint_hash(entry_hash),
        "archive failure cannot clean committed queue work"
    );
    assert!(events.try_recv().is_err());
    assert!(worker.execute(&block, qc.block_hash).is_none());
    assert_eq!(worker.build(3, 0, 1 << 20, 100).unwrap(), None);
    assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(qc.result));
    assert!(
        worker.live.as_ref().unwrap().overlay.is_none(),
        "retry must not acquire another State overlay"
    );
    std::fs::rename(&hidden, &root).unwrap();
    assert_eq!(reputation.health_generation().unwrap(), reputation_before);
    let completed = worker.commit(&block, &qc).unwrap();
    assert_eq!(worker.applied, (2, qc.block_hash));
    assert!(worker.pending_commit.is_none());
    assert!(
        !queue.contains_entrypoint_hash(entry_hash),
        "successful capture retires the original queue entry"
    );
    assert_eq!(
        archive_files(&directory.path().join("provider")),
        original_provider_files
    );
    assert_eq!(provider.health_generation().unwrap(), provider_before + 1);
    assert_eq!(
        reputation.health_generation().unwrap(),
        reputation_before + 1
    );
    assert_eq!(worker.state.view().height(), 2);
    assert_eq!(worker.state.view().latest_block_hash(), Some(hash));
    let mut emitted = 0;
    while events.try_recv().is_ok() {
        emitted += 1;
    }
    assert_eq!(
        emitted, retained_events,
        "publish every original real event once"
    );
    assert!(events.try_recv().is_err());
    assert_eq!(worker.commit(&block, &qc).unwrap(), completed);
    assert!(events.try_recv().is_err(), "completion cannot emit twice");
    assert_eq!(provider.health_generation().unwrap(), provider_before + 1);
}

#[test]
fn pending_capture_rejects_substituted_header_qc_state_and_missing_certificate() {
    run(pending_capture_rejects_substituted_header_qc_state_and_missing_certificate_case);
}

fn pending_capture_rejects_substituted_header_qc_state_and_missing_certificate_case() {
    let chain = chain();
    let (_directory, archives) = archives();
    archives.capture(&chain.state().view()).unwrap();
    let (context, mut events) = context(&chain);
    let mut worker = worker(&context, archives.clone());
    let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
    hold_archive_completion(&mut worker, &block, &qc);
    let mut wrong_header = block.header().clone();
    wrong_header.height += 1;
    let wrong_block = chain.author_payload(wrong_header, block.payload().as_slice().to_vec());
    assert!(worker.prepare(&wrong_block, &qc).is_err());
    assert!(worker.commit(&wrong_block, &qc).is_err());
    let mut wrong_qc = qc.clone();
    wrong_qc.view += 1;
    assert!(worker.prepare(&block, &wrong_qc).is_err());
    assert!(worker.commit(&block, &wrong_qc).is_err());
    worker.pending_commit.as_mut().unwrap().state_hash =
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign state"));
    assert!(worker.commit(&block, &qc).is_err());
    worker.pending_commit.as_mut().unwrap().state_hash = chain.committed(2).block_hash();
    assert!(events.try_recv().is_err());
    let original_state = Arc::as_ptr(chain.state());
    let original_contexts = worker
        .pending_commit
        .as_ref()
        .unwrap()
        .native_contexts
        .canonical_bytes()
        .as_ptr();
    // Corrupt only the already-durable frame. The actual State, allocation pool and pending
    // archive owner remain exactly the original ones, so rejection must reach the read boundary.
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(std::num::NonZeroUsize::new(2).unwrap(), None)
        .unwrap();
    let stored = chain
        .kura()
        .get_block(
            std::num::NonZeroUsize::new(2).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    assert!(stored.commit_certificate().is_none());
    assert_eq!(
        chain.state().view().latest_block_hash(),
        Some(stored.hash())
    );
    assert_eq!(Arc::as_ptr(&worker.context.state), original_state);
    assert!(worker.commit(&block, &qc).is_err());
    assert!(worker.pending_commit.is_some());
    assert_eq!(
        worker
            .pending_commit
            .as_ref()
            .unwrap()
            .native_contexts
            .canonical_bytes()
            .as_ptr(),
        original_contexts
    );
    assert_eq!(worker.applied.0, 1);
    assert_eq!(worker.state.view().height(), 2);
    assert!(events.try_recv().is_err());
}

#[test]
fn archive_attachment_captures_exact_tip_once_before_executor_work_and_survives_reopen() {
    run(archive_attachment_captures_exact_tip_once_before_executor_work_and_survives_reopen_case);
}

fn archive_attachment_captures_exact_tip_once_before_executor_work_and_survives_reopen_case() {
    let chain = chain();
    let (directory, archives) = archives();
    let provider = archives.provider_ingest.as_ref().unwrap();
    let reputation = archives.reputation.as_ref().unwrap();
    let (context, _events) = context(&chain);
    let executor = StateExecutor::spawn(context).unwrap();
    let reputation_root = reputation.root().to_owned();
    let reputation_bounds = reputation.bounds();
    let hidden_root = reputation_root.with_extension("temporarily-unavailable");
    std::fs::rename(&reputation_root, &hidden_root).unwrap();
    assert!(
        executor
            .attach_finalized_archives(archives.clone())
            .is_err()
    );
    let provider_generation = provider.health_generation().unwrap();
    assert_eq!(provider_generation, 1);
    assert_eq!(chain.state().view().height(), 1);
    std::fs::rename(&hidden_root, &reputation_root).unwrap();
    executor
        .attach_finalized_archives(archives.clone())
        .unwrap();
    assert_eq!(provider.health_generation().unwrap(), provider_generation);
    let generation = (
        provider.health_generation().unwrap(),
        reputation.health_generation().unwrap(),
    );
    assert!(
        executor
            .attach_finalized_archives(archives.clone())
            .is_err()
    );
    assert_eq!(
        generation,
        (
            provider.health_generation().unwrap(),
            reputation.health_generation().unwrap()
        )
    );
    // The sole executor owner closes admission and joins before archive writers reopen.
    drop(executor);
    drop(archives);
    let provider_reopened = ProviderIngestFinalizedArchiveV1::try_open(
        directory.path().join("provider"),
        provider_bounds(),
    )
    .unwrap();
    let reputation_reopened =
        ReputationFinalizedArchive::try_open(&reputation_root, reputation_bounds).unwrap();
    let view = chain.state().view();
    let provider_qualification = provider_reopened
        .qualify_against_certified_tip(&view, chain.kura(), 0)
        .unwrap();
    let reputation_qualification = reputation_reopened
        .qualify_against_certified_tip(&view, chain.kura(), 0)
        .unwrap();
    assert_eq!(provider_qualification.kura_tip_height(), 1);
    assert_eq!(provider_qualification.lag_blocks(), 0);
    assert_eq!(provider_qualification.generation(), generation.0);
    assert_eq!(reputation_qualification.kura_tip_height(), 1);
    assert_eq!(reputation_qualification.lag_blocks(), 0);
    assert_eq!(reputation_qualification.generation(), generation.1);
    assert_eq!(provider_reopened.health_generation().unwrap(), generation.0);
    assert_eq!(
        reputation_reopened.health_generation().unwrap(),
        generation.1
    );
}

#[test]
fn below_quorum_current_frame_cannot_finish_pending_archive_capture() {
    run(below_quorum_current_frame_cannot_finish_pending_archive_capture_case);
}

fn below_quorum_current_frame_cannot_finish_pending_archive_capture_case() {
    let chain = chain();
    let (_directory, archives) = archives();
    archives.capture(&chain.state().view()).unwrap();
    let (context, mut events) = context(&chain);
    let mut worker = worker(&context, archives.clone());
    let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
    let below = chain.commit_qc(2, qc.block_hash, qc.result, Signers::BelowQuorum);
    let committee = worker
        .scheduled(2)
        .unwrap()
        .height_config()
        .unwrap()
        .committee;
    assert!(
        iroha_sumeragi::crypto::Verifier::new(
            &**worker.context.crypto.as_ref().unwrap(),
            &chain.instance(),
            &block.header().epoch,
            &committee
        )
        .verify_qc(&below)
        .is_err(),
        "negative durable frame has an actual insufficient signed quorum"
    );
    hold_archive_completion(&mut worker, &block, &qc);
    let generation = archives
        .provider_ingest
        .as_ref()
        .unwrap()
        .health_generation()
        .unwrap();
    let original_state = Arc::as_ptr(chain.state());
    let original_contexts = worker
        .pending_commit
        .as_ref()
        .unwrap()
        .native_contexts
        .canonical_bytes()
        .as_ptr();
    let original_block = chain.committed(2);
    // Only the published frame's QC is corrupt. Retain the exact already-published State,
    // original pool, source bytes and pending archive owner throughout the negative read.
    let bad_qc = norito::encode_canonical(&below).unwrap();
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            std::num::NonZeroUsize::new(2).unwrap(),
            Some(bad_qc.clone()),
        )
        .unwrap();
    let stored = chain
        .kura()
        .get_block(
            std::num::NonZeroUsize::new(2).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .expect("original block read attempt")
        .unwrap();
    assert_eq!(stored.commit_certificate().unwrap().commit_qc(), bad_qc);
    assert_eq!(
        stored.executed_block_wire_identity().unwrap(),
        original_block
            .block()
            .executed_block_wire_identity()
            .unwrap()
    );
    assert_eq!(
        stored.commit_certificate().unwrap().availability(),
        original_block
            .block()
            .commit_certificate()
            .unwrap()
            .availability()
    );
    assert_eq!(Arc::as_ptr(&worker.context.state), original_state);
    assert!(
        matches!(
            worker.commit(&block, &qc),
            Err(PublicationError::Retryable(_))
        ),
        "an actually invalid certificate cannot become local resource deferral"
    );
    assert!(worker.pending_commit.is_some());
    assert!(
        worker
            .pending_commit
            .as_ref()
            .unwrap()
            .archive_refusal
            .is_none()
    );
    assert_eq!(
        worker
            .pending_commit
            .as_ref()
            .unwrap()
            .native_contexts
            .canonical_bytes()
            .as_ptr(),
        original_contexts
    );
    assert_eq!(worker.state.view().height(), 2);
    assert_eq!(worker.applied.0, 1);
    assert_eq!(
        archives
            .provider_ingest
            .as_ref()
            .unwrap()
            .health_generation()
            .unwrap(),
        generation
    );
    assert!(events.try_recv().is_err());
}

/// A node killed after Kura's durable append of a height and before that height's archive
/// capture restarts through the production startup replay: the replayed tip is published, the
/// archives bind to it, and the one missing height is captured exactly once.
#[test]
fn restart_binds_archives_after_replay_and_captures_the_missing_tip_once() {
    run(restart_binds_archives_after_replay_and_captures_the_missing_tip_once_case);
}

fn restart_binds_archives_after_replay_and_captures_the_missing_tip_once_case() {
    let mut chain = chain();
    let (directory, archives) = archives();
    // The original process captured genesis and every committed height before advancing.
    archives.capture(&chain.state().view()).unwrap();
    for _ in 0..2 {
        chain.commit(Vec::new());
        archives.capture(&chain.state().view()).unwrap();
    }
    // It was killed after the next height became durable in Kura, before its capture.
    chain.commit(Vec::new());
    let tip = chain.height();
    assert_eq!(tip, 4);
    let reputation_root = archives.reputation.as_ref().unwrap().root().to_owned();
    let reputation_bounds = archives.reputation.as_ref().unwrap().bounds();
    drop(archives);

    // Restart: a pristine configured State over a Kura holding the same certified blocks.
    let restarted = CertifiedTestChain::prepare(config()).unwrap();
    assert_eq!(restarted.genesis.block().hash(), chain.genesis().hash());
    for height in 1..=tip {
        let height = std::num::NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap();
        restarted
            .kura
            .store_block(
                chain
                    .kura()
                    .get_block(height, &chain.state().ivm_execution_budget())
                    .expect("original block read attempt")
                    .unwrap(),
            )
            .unwrap();
    }
    let node = crate::sumeragi::node::prepare(crate::sumeragi::node::PrepareInputs {
        state: Clone::clone(&restarted.state),
        events: tokio::sync::broadcast::channel(1024).0,
        genesis: None,
        genesis_account: chain.genesis_account().clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .unwrap();
    assert_eq!(restarted.state.view().height(), 4, "startup replayed Kura");
    let provider = Arc::new(
        ProviderIngestFinalizedArchiveV1::try_open(
            directory.path().join("provider"),
            provider_bounds(),
        )
        .unwrap(),
    );
    let reputation = Arc::new(
        ReputationFinalizedArchive::try_open(&reputation_root, reputation_bounds).unwrap(),
    );
    let before = (
        provider.health_generation().unwrap(),
        reputation.health_generation().unwrap(),
    );
    // The daemon reconciles the provider archive against the replayed tip before binding (the
    // one committed successor); the reputation archive is left to the binding's own capture.
    let reconciliation = provider
        .reconcile_certified_state_tip(&restarted.state.view(), &restarted.kura)
        .unwrap();
    assert_eq!(
        reconciliation.insertion(),
        ProviderIngestFinalizedArchiveInsertOutcomeV1::Inserted
    );
    assert_eq!(reconciliation.qualification().kura_tip_height(), tip);
    assert_eq!(reconciliation.qualification().lag_blocks(), 0);
    assert!(!reconciliation.activation_floor_created());
    assert_eq!(provider.health_generation().unwrap(), before.0 + 1);
    let bound = FinalizedArchives {
        provider_ingest: Some(Clone::clone(&provider)),
        reputation: Some(Clone::clone(&reputation)),
    };
    node.attach_finalized_archives(bound.clone())
        .expect("the replayed, published tip is not an execution beyond the applied tip");
    // Each archive holds the tip once: the reconciled provider tip is not captured again.
    let captured = (before.0 + 1, before.1 + 1);
    assert_eq!(
        (
            provider.health_generation().unwrap(),
            reputation.health_generation().unwrap()
        ),
        captured
    );
    let view = restarted.state.view();
    let provider_tip = provider
        .qualify_against_certified_tip(&view, &restarted.kura, 0)
        .unwrap();
    assert_eq!(provider_tip.archive_tip().height, tip);
    assert_eq!(provider_tip.lag_blocks(), 0);
    let reputation_tip = reputation
        .qualify_against_certified_tip(&view, &restarted.kura, 0)
        .unwrap();
    assert_eq!(reputation_tip.archive_tip().height, tip);
    assert_eq!(reputation_tip.lag_blocks(), 0);
    drop(view);
    assert!(
        node.attach_finalized_archives(bound).is_err(),
        "archives bind once per process"
    );
    assert_eq!(
        (
            provider.health_generation().unwrap(),
            reputation.health_generation().unwrap()
        ),
        captured
    );
}

/// An execution beyond the applied tip, executed or prepared, refuses binding: capture would
/// skip it. Once published it is the applied tip, which the binding captures.
#[test]
fn binding_refuses_unpublished_execution_and_captures_the_published_tip() {
    run(binding_refuses_unpublished_execution_and_captures_the_published_tip_case);
}

fn binding_refuses_unpublished_execution_and_captures_the_published_tip_case() {
    let chain = chain();
    let (_directory, archives) = archives();
    archives.capture(&chain.state().view()).unwrap();
    let (context, _events) = context(&chain);
    let mut worker = worker(&context, archives.clone());
    worker.archives = None;
    let (block, qc) = super::publication_tests::executed(&chain, &mut worker);
    let refused = worker
        .bind_finalized_archives(archives.clone())
        .unwrap_err();
    assert!(refused.contains("beyond the applied tip"), "{refused}");
    prepare_and_append(&mut worker, &block, &qc);
    assert!(
        worker.bind_finalized_archives(archives.clone()).is_err(),
        "a prepared publication is not the applied tip"
    );
    worker.commit(&block, &qc).unwrap();
    assert_eq!(worker.applied, (2, qc.block_hash));
    let provider = archives.provider_ingest.as_ref().unwrap();
    let reputation = archives.reputation.as_ref().unwrap();
    let generation = (
        provider.health_generation().unwrap(),
        reputation.health_generation().unwrap(),
    );
    worker.bind_finalized_archives(archives.clone()).unwrap();
    assert_eq!(
        (
            provider.health_generation().unwrap(),
            reputation.health_generation().unwrap()
        ),
        (generation.0 + 1, generation.1 + 1),
        "the published tip is captured once"
    );
    assert!(worker.bind_finalized_archives(archives).is_err());
}
