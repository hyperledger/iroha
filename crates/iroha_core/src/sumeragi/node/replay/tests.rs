//! Genuine signed-genesis reconstruction with original certified monetary effects.
use super::*;
use crate::{
    query::native_context_archive::fastpq_source::{NativeFastpqSourceRead, SourceReadLimits},
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::prelude::*;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use std::{collections::BTreeMap, num::NonZeroUsize, path::Path};

fn store_config(path: &Path) -> config::Kura {
    use iroha_config::{
        kura::{FsyncMode, InitMode},
        parameters::defaults,
    };
    use iroha_config_base::WithOrigin;
    config::Kura {
        init_mode: InitMode::Strict,
        store_dir: WithOrigin::inline(path.to_path_buf()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        native_context_archive_max_bytes: defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        history_checkpoint_cache_capacity: defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes: defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes: defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::kura::FASTPQ_ARTIFACT_POLICY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,
    }
}
fn run(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("isolated-native-replay".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap_or_else(|failure| std::panic::resume_unwind(failure));
}
pub(super) fn fixture() -> (CertifiedTestChain, NativeReplaySeed, AssetId) {
    let (chain, mut seeds, asset) = fixture_with_seeds(1);
    (chain, seeds.pop().unwrap(), asset)
}

// Every restart owns a separate capture of the same original empty State.
// No seed is cloned, serialized, or reconstructed from the later World.
pub(super) fn fixture_with_seeds(
    seed_count: usize,
) -> (CertifiedTestChain, Vec<NativeReplaySeed>, AssetId) {
    assert!(seed_count > 0);
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.clock_bootstrap_in_genesis = true;
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::try_new("replay-principal", "universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "principal".parse().unwrap());
    let asset = AssetId::new(definition.clone(), ALICE_ID.clone());
    config.genesis_instructions = vec![
        Register::account(Account::new(ALICE_ID.clone())).into(),
        Register::account(Account::new(BOB_ID.clone())).into(),
        Register::domain(Domain::new(domain)).into(),
        Register::asset_definition(AssetDefinition::new(
            definition.clone(),
            "Replay principal",
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(100_u32, asset.clone()).into(),
        Mint::asset_quantity(10_u32, AssetId::new(definition, BOB_ID.clone())).into(),
    ];
    let prepared = CertifiedTestChain::prepare(config).unwrap();
    let seeds = (0..seed_count)
        .map(|_| {
            NativeReplaySeed::capture(
                &prepared.state,
                store_config(&prepared.kura.store_root()),
                genesis_account.clone(),
                ConsensusMode::Permissioned,
            )
            .unwrap()
        })
        .collect();
    let mut chain = CertifiedTestChain::from_prepared(prepared).unwrap();
    let transaction = chain.sign(
        &ALICE_KEYPAIR,
        [Transfer::asset_quantity(asset.clone(), 3_u32, BOB_ID.clone()).into()],
        1_099,
    );
    assert_eq!(chain.commit_at(1_100, vec![transaction]), [true]);
    (chain, seeds, asset)
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), files);
            } else if entry.file_type().unwrap().is_file() {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}
fn native(
    chain: &CertifiedTestChain,
    height: u64,
) -> super::super::super::certified_chain::AuthenticatedExecutionBlock {
    let view = chain.state().view();
    CertifiedChain::new(&view)
        .unwrap()
        .authenticated_execution(height)
        .unwrap()
}
fn complete_read(
    read: &mut NativeFastpqSourceRead,
) -> crate::query::native_context_archive::fastpq_source::AuthenticatedRecoveredFastpqSource {
    for _ in 0..64 {
        if let Some(source) = read.poll().unwrap() {
            return source;
        }
    }
    panic!("bounded genuine source read did not finish");
}
fn limits() -> SourceReadLimits {
    SourceReadLimits {
        max_entries: 64,
        max_statements: 64,
        max_effects_per_statement: 128,
    }
}

#[test]
fn isolated_replay_recovers_nonempty_h1_and_h2_without_live_publication() {
    run(|| {
        let _status = crate::status::operator_status_test_guard();
        let (chain, seed, _) = fixture();
        let pool = chain.state().ivm_execution_budget();
        let limit = pool.limit_bytes();
        let selected = native(&chain, 2);
        let source_path = chain
            .kura()
            .store_root()
            .join(Kura::fastpq_source_namespace());
        let originals = inventory(&source_path);
        assert!(
            originals
                .keys()
                .any(|path| path.extension().is_some_and(|ext| ext == "fqs"))
        );
        for path in originals
            .keys()
            .filter(|path| path.extension().is_some_and(|ext| ext == "fqs"))
        {
            std::fs::remove_file(source_path.join(path)).unwrap();
        }
        let live_files = inventory(&chain.kura().store_root());
        let live_root = chain.state().verify_world_state_accumulator().unwrap();
        let operator_status = crate::status::lane_scoped_status_fingerprint_for_tests();
        let settlements = format!("{:?}", crate::status::settlement_snapshot());
        let live_height = chain.state().committed_height();
        for height in [1, 2] {
            let target = native(&chain, height);
            let mut read =
                NativeFastpqSourceRead::new(chain.kura().clone(), target, pool.clone(), limits());
            let missing = (0..64)
                .find_map(|_| read.poll().err())
                .expect("nonempty missing original tape is not empty success");
            assert!(
                matches!(missing, crate::query::native_context_archive::fastpq_source::SourceReadError::Archive(
                crate::query::native_context_archive::NativeContextArchiveError::Io(ref e)) if e.kind()==io::ErrorKind::NotFound)
            );
            let deadline = Instant::now() + Duration::from_secs(120);
            let mut replay = seed.begin(read.native().unwrap(), deadline).unwrap();
            let completed = replay
                .advance(read.native().unwrap(), deadline, 64)
                .unwrap()
                .unwrap();
            assert_eq!(replay.prepared.state.committed_height(), height as usize);
            read.use_replayed_transport(completed).unwrap();
            let recovered = complete_read(&mut read);
            assert!(
                !recovered.leaves().is_empty(),
                "actual mint/transfer effects are retained"
            );
            assert_eq!(recovered.native().committed().height(), height);
            assert_eq!(
                recovered.native().committed().result(),
                native(&chain, height).committed().result()
            );
            drop(recovered);
            drop(read);
            drop(replay);
        }
        assert_eq!(chain.state().committed_height(), live_height);
        assert_eq!(
            chain.state().verify_world_state_accumulator().unwrap(),
            live_root
        );
        assert_eq!(inventory(&chain.kura().store_root()), live_files);
        assert_eq!(pool.limit_bytes(), limit);
        assert_eq!(
            crate::status::lane_scoped_status_fingerprint_for_tests(),
            operator_status
        );
        assert_eq!(
            format!("{:?}", crate::status::settlement_snapshot()),
            settlements
        );
        assert_eq!(
            chain
                .kura()
                .canonical_block_wire_bytes_for_testing(NonZeroUsize::new(2).unwrap())
                .unwrap(),
            selected.committed().block().encode_wire().unwrap()
        );
    });
}

#[test]
fn replay_preserves_original_target_and_expired_deadline() {
    run(|| {
        let (mut chain, seed, asset) = fixture();
        let target = native(&chain, 2);
        let files = inventory(&chain.kura().store_root());
        assert!(matches!(
            seed.begin(&target, Instant::now()),
            Err(IsolatedReplayError::Deadline)
        ));
        assert_eq!(inventory(&chain.kura().store_root()), files);
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut replay = seed.begin(&target, deadline).unwrap();
        let transaction = chain.sign(
            &ALICE_KEYPAIR,
            [Transfer::asset_quantity(asset, 1_u32, BOB_ID.clone()).into()],
            1_199,
        );
        assert_eq!(chain.commit_at(1_200, vec![transaction]), [true]);
        let newer = native(&chain, 3);
        assert!(matches!(
            replay.advance(&newer, deadline, 64),
            Err(IsolatedReplayError::Identity(_))
        ));
        assert_eq!(replay.next, 2);
        assert!(matches!(
            replay.advance(&target, Instant::now(), 64),
            Err(IsolatedReplayError::Deadline)
        ));
        assert_eq!(replay.next, 2);
        let completed = replay.advance(&target, deadline, 1).unwrap().unwrap();
        assert!(matches!(
            completed.into_for(&newer),
            Err(IsolatedReplayError::Identity(_))
        ));
    });
}

#[test]
fn isolated_state_configuration_preserves_live_pool_and_process_cache() {
    run(|| {
        let sentinel = ivm::ivm_cache::CacheLimits {
            capacity: 9,
            max_bytes: 4_096,
            max_decoded_ops: 17,
        };
        let _cache = ivm::ivm_cache::CacheLimitsGuard::new(sentinel);
        let pool = iroha_allocation::AllocationBudget::new(512 * 1024 * 1024);
        let retained = pool.try_reserve_bytes(128).unwrap();
        let original_limit = pool.limit_bytes();
        let world = World::try_with_execution_budget([], [], [], &pool).unwrap();
        let nexus = config::Nexus::default();
        let kura = Kura::new_temporary_with_configured_lane_catalog(
            &store_config(Path::new("unused")),
            &nexus.lane_config,
            &nexus.configured_lane_catalog,
        )
        .unwrap();
        let mut pipeline = config::Pipeline::default();
        pipeline.cache_size = 3;
        pipeline.ivm_cache_max_bytes = 123;
        pipeline.ivm_cache_max_decoded_ops = 5;
        pipeline.ivm_execution_max_bytes = 1;
        let query = crate::query::store::LiveQueryStore::start_test();
        let state = State::try_new_for_isolated_replay(
            pool.clone(),
            world,
            kura,
            query,
            iroha_model_base::chain::ChainId::from("replay resources"),
            iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"isolated runtime fixture",
                )),
            ),
            pipeline,
        )
        .unwrap();
        assert!(state.ivm_execution_budget().same_pool(&pool));
        assert_eq!(pool.limit_bytes(), original_limit);
        assert_eq!(ivm::ivm_cache::cache_limits(), sentinel);
        assert_eq!(state.installed_pipeline().cache_size, 3);
        assert!(retained.belongs_to(&pool));
        drop(state);
        drop(retained);
        assert_eq!(pool.reserved_bytes(), 0);
    });
}

#[test]
fn replay_seed_cannot_capture_current_applied_state() {
    run(|| {
        let (chain, seed, _) = fixture();
        let original_files = inventory(&chain.kura().store_root());
        let original_root = chain.state().verify_world_state_accumulator().unwrap();
        assert!(matches!(
            NativeReplaySeed::capture(
                chain.state(),
                seed.kura_config.clone(),
                seed.genesis_account.clone(),
                seed.consensus_mode,
            ),
            Err(NativeReplaySeedError::NotEmpty)
        ));
        assert_eq!(
            chain.state().verify_world_state_accumulator().unwrap(),
            original_root
        );
        assert_eq!(inventory(&chain.kura().store_root()), original_files);
    });
}

fn replay_retryable(error: &IsolatedReplayError) -> bool {
    crate::fastpq::lane::isolated_replay_retryable_for_test(error)
}

fn assert_genesis_capacity(
    error: &IsolatedReplayError,
    phase: super::super::super::startup::test_hooks::Phase,
) {
    use super::super::super::startup::{StartupError, test_hooks::Phase};
    use iroha_allocation::{AllocationRefusal, ChargedBufferError};
    let IsolatedReplayError::Startup(NodeError::Startup(original)) = error else {
        panic!("expected the original genesis owner at {phase:?}: {error:?}")
    };
    match (phase, original) {
        (Phase::Validation, StartupError::InvalidGenesis(original)) => {
            use crate::block::BlockValidationError;
            assert!(
                matches!(original.as_ref(),
                BlockValidationError::ExecutionDeferred(reason) if matches!(reason.allocation_refusal(), Some(AllocationRefusal::Capacity { .. })))
                    || matches!(original.as_ref(), BlockValidationError::StateStorageAdmission(error) if error.release_wait().is_some())
                    || matches!(original.as_ref(), BlockValidationError::MembershipAdmission(error) if error.release_wait().is_some())
                    || matches!(original.as_ref(), BlockValidationError::BlockHashAdmission(error) if error.release_wait().is_some()),
                "validation must retain its actual original capacity: {original:?}"
            );
        }
        (
            Phase::LaneProof,
            StartupError::LaneProof(
                iroha_data_model::sumeragi_finality::NativeLaneStateProofError::Scratch(
                    ChargedBufferError::Admission(AllocationRefusal::Capacity { .. }),
                ),
            ),
        ) => {}
        (
            Phase::ResultPreimage,
            StartupError::ResultPreimage(
                super::super::super::commitment::ResultPreimageError::Allocation(
                    ChargedBufferError::Admission(AllocationRefusal::Capacity { .. }),
                ),
            ),
        ) => {}
        (
            Phase::Certificate,
            StartupError::Certificate(
                iroha_data_model::block::CertificateAdmissionError::ControlAdmission(
                    AllocationRefusal::Capacity { .. },
                ),
            ),
        ) => {}
        _ => panic!("different original owner at {phase:?}: {original:?}"),
    }
    assert!(
        replay_retryable(error),
        "actual capacity cannot permanently stop the producer"
    );
}

// Fill the original pool only after the actual seed's empty State is built, or
// after the real nonempty genesis has executed into its witness/result. No pool
// ceiling, global cache, prover setting, current World or source file is changed.
fn genesis_original_capacity_retries(phase: super::super::super::startup::test_hooks::Phase) {
    use super::super::super::startup::test_hooks;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    let (chain, seed, _) = fixture();
    let target = native(&chain, 1);
    let budget = chain.state().ivm_execution_budget();
    let maximum = budget.limit_bytes();
    let files = inventory(&chain.kura().store_root());
    let root = chain.state().verify_world_state_accumulator().unwrap();
    let occupied = Rc::new(RefCell::new(None));
    let called = Rc::new(Cell::new(false));
    let original = budget.clone();
    let hold = Rc::clone(&occupied);
    let observed = Rc::clone(&called);
    let _hook = test_hooks::install(phase, move |pool, witness| {
        assert!(pool.same_pool(&original));
        assert_eq!(pool.limit_bytes(), maximum);
        if let Some(witness) = witness {
            assert!(
                !witness.writes.is_empty(),
                "late pressure follows genuine genesis execution"
            );
        }
        *hold.borrow_mut() = Some(
            pool.try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                .unwrap(),
        );
        observed.set(true);
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let error = match seed.begin(&target, deadline) {
        Ok(_) => panic!("the full original pool must refuse {phase:?}"),
        Err(error) => error,
    };
    assert!(called.get(), "the hook must reach the actual genesis owner");
    assert_genesis_capacity(&error, phase);
    drop(occupied.borrow_mut().take());
    assert_eq!(budget.limit_bytes(), maximum);
    assert_eq!(inventory(&chain.kura().store_root()), files);
    assert_eq!(chain.state().committed_height(), 2);
    assert_eq!(
        chain.state().verify_world_state_accumulator().unwrap(),
        root
    );
    let mut replay = seed.begin(&target, deadline).unwrap();
    let completed = replay.advance(&target, deadline, 64).unwrap().unwrap();
    let mut read =
        NativeFastpqSourceRead::new(chain.kura().clone(), target, budget.clone(), limits());
    read.use_replayed_transport(completed).unwrap();
    let recovered = complete_read(&mut read);
    assert!(!recovered.leaves().is_empty());
    assert_eq!(
        recovered.native().committed().result(),
        native(&chain, 1).committed().result()
    );
    assert_eq!(replay.prepared.state.committed_height(), 1);
    assert_eq!(inventory(&chain.kura().store_root()), files);
    assert_eq!(chain.state().committed_height(), 2);
    assert_eq!(
        chain.state().verify_world_state_accumulator().unwrap(),
        root
    );
    assert_eq!(budget.limit_bytes(), maximum);
}

#[test]
fn isolated_h1_validation_retries_original_pool_after_empty_state_construction() {
    run(|| {
        genesis_original_capacity_retries(
            super::super::super::startup::test_hooks::Phase::Validation,
        )
    });
}
#[test]
fn isolated_h1_lane_proof_retries_original_pool_after_witness_execution() {
    run(|| {
        genesis_original_capacity_retries(
            super::super::super::startup::test_hooks::Phase::LaneProof,
        )
    });
}
#[test]
fn isolated_h1_result_preimage_retries_original_pool_after_witness_execution() {
    run(|| {
        genesis_original_capacity_retries(
            super::super::super::startup::test_hooks::Phase::ResultPreimage,
        )
    });
}
#[test]
fn isolated_h1_certificate_retries_original_pool_after_witness_execution() {
    run(|| {
        genesis_original_capacity_retries(
            super::super::super::startup::test_hooks::Phase::Certificate,
        )
    });
}

#[test]
fn isolated_h1_malformed_original_witness_is_terminal_without_live_publication() {
    run(|| {
        use super::super::super::startup::{
            StartupError,
            test_hooks::{self, Phase},
        };
        use iroha_data_model::sumeragi_finality::NativeLaneStateProofError;
        let (chain, seed, _) = fixture();
        let target = native(&chain, 1);
        let files = inventory(&chain.kura().store_root());
        let root = chain.state().verify_world_state_accumulator().unwrap();
        let _hook = test_hooks::install(Phase::LaneProof, |_, witness| {
            witness.unwrap().offer_reconstructed_tamper_for_test(|offered| {
                offered.writes.retain(|write| write.key.as_slice() != iroha_data_model::sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY);
            });
        });
        let error = match seed.begin(&target, Instant::now() + Duration::from_secs(120)) {
            Ok(_) => panic!("missing lane commitment cannot become a source"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            IsolatedReplayError::Startup(NodeError::Startup(StartupError::LaneProof(
                NativeLaneStateProofError::Malformed(_)
            )))
        ));
        assert!(!replay_retryable(&error));
        assert_eq!(inventory(&chain.kura().store_root()), files);
        assert_eq!(
            chain.state().verify_world_state_accumulator().unwrap(),
            root
        );
        assert_eq!(chain.state().committed_height(), 2);
    });
}

#[test]
fn isolated_genesis_original_fixed_bounds_and_invariants_never_request_retry() {
    use super::super::super::{
        commitment::ResultPreimageError,
        startup::{GenesisStatePublicationError, StartupError},
    };
    use iroha_allocation::{AllocationRefusal, ChargedBuffer, ChargedBufferError};
    let budget = iroha_allocation::AllocationBudget::new(16);
    let exceeds = ChargedBuffer::<u8>::new(17, &budget)
        .err()
        .expect("an over-limit buffer must be refused");
    assert!(matches!(
        &exceeds,
        ChargedBufferError::Admission(AllocationRefusal::ExceedsLimit { .. })
    ));
    let layout = std::alloc::Layout::from_size_align(isize::MAX as usize, 1).unwrap();
    let overflow = budget
        .try_reserve_layouts([layout, layout, layout])
        .unwrap_err();
    assert!(matches!(&overflow, AllocationRefusal::DemandOverflow));
    let errors = [
        StartupError::ResultPreimage(ResultPreimageError::Allocation(exceeds)),
        StartupError::Certificate(
            iroha_data_model::block::CertificateAdmissionError::ControlAdmission(overflow.clone()),
        ),
        StartupError::InvalidGenesis(Box::new(
            crate::block::BlockValidationError::ExecutionDeferred(overflow.into()),
        )),
        StartupError::InvalidGenesis(Box::new(
            crate::block::BlockValidationError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
            ),
        )),
        StartupError::StatePublication(GenesisStatePublicationError(
            crate::state::storage_transactions::TransactionsBlockError::PublicationRecoveryRequired,
        )),
        StartupError::Local("actual local invariant requires recovery".into()),
    ];
    for original in errors {
        assert!(!replay_retryable(&IsolatedReplayError::Startup(
            NodeError::Startup(original)
        )));
    }
    assert_eq!(budget.reserved_bytes(), 0);
}
