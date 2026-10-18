// Shared native storage fixtures. Original execution comes only from CertifiedTestChain.
use super::*;
use crate::{
    block::{BlockBuilder, ValidBlock},
    prelude::{AcceptedTransaction, World},
    query::store::LiveQueryStore,
    state::State,
    sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_config::{
    base::WithOrigin,
    kura::{FsyncMode, InitMode},
    parameters::{
        actual::{Kura as KuraConfig, LaneConfig as RuntimeLaneConfig},
        defaults::kura::{BLOCKS_IN_MEMORY, FSYNC_INTERVAL},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::{
    Level,
    block::BlockHeader,
    isi::Log,
    nexus::{LaneCatalog, LaneConfig as ModelLaneConfig},
    transaction::{
        TransactionBuilder,
        signed::{TransactionEntrypoint, TransactionResult},
    },
    trigger::DataTriggerSequence,
};
use iroha_model_base::{
    chain::ChainId,
    topology::{DataSpaceId, LaneId},
};
use iroha_telemetry::metrics::Metrics;
use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use nonzero_ext::nonzero;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

/// Original executed native carriers, retained without changing their signed body or QC.
fn native_storage_frames(count: usize) -> Vec<iroha_data_model::block::SharedSignedBlock> {
    assert!(count > 0);
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("execute genuine native genesis");
    while chain.height() < count as u64 {
        chain.commit(Vec::new());
    }
    (1..=count)
        .map(|height| (chain.committed(height as u64).block()).clone())
        .collect()
}

/// Explicit standalone structural fixture control; real executed chains retain their State owner.
fn share_storage_fixture(block: SignedBlock) -> iroha_data_model::block::SharedSignedBlock {
    let budget = crate::state::AllocationBudget::new(
        iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
    );
    iroha_data_model::block::SharedSignedBlock::try_new(block, &budget)
        .expect("admit one standalone structural fixture block")
}

fn test_network_id(label: &[u8]) -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(label),
    ))
}

#[test]
fn io_error_display_preserves_path_and_underlying_cause() {
    let path = PathBuf::from("lane_geometry_journal.norito");
    let error = Error::IO(
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected journal denial",
        ),
        path.clone(),
    );
    let rendered = error.to_string();
    assert!(rendered.contains(&format!("{path:?}")), "{rendered}");
    assert!(rendered.contains("injected journal denial"), "{rendered}");
}

#[test]
fn kura_new_rejects_empty_production_store_root_before_persistence_initialization() {
    let temp_dir = TempDir::new().expect("tempdir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.store_dir = WithOrigin::inline(PathBuf::new());
    let err = match Kura::open_test_kura_with_configured_lane_config(
        &config,
        &RuntimeLaneConfig::default(),
    ) {
        Ok(_) => panic!("empty production Kura root must fail closed"),
        Err(err) => err,
    };
    assert!(matches!(err, Error::EmptyStoreRoot));
}

#[test]
fn strict_startup_rejects_every_retired_kura_artifact_after_fast_defers_the_audit() {
    for (name, in_pipeline, directory) in [
        ("commit-rosters", false, true),
        ("commit-rosters.norito", false, false),
        ("commit-rosters.norito.tmp", false, false),
        ("roster_sidecars.norito", true, false),
        ("roster_sidecars.index", true, false),
        ("roster_sidecars.norito.tmp", true, false),
        ("roster_sidecars.index.tmp", true, false),
        ("block_1.json", true, false),
    ] {
        let temp_dir = TempDir::new().expect("retired-artifact tempdir");
        let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
        let lane_config = RuntimeLaneConfig::default();
        let (kura, _) = test_kura_with_default_lane_markers(&config, &lane_config);
        let store_root = kura.store_root();
        let blocks_root = kura.active_blocks_dir.lock().clone();
        drop(kura);
        let parent = if in_pipeline {
            blocks_root.join(PIPELINE_DIR_NAME)
        } else {
            store_root
        };
        fs::create_dir_all(&parent).expect("create retired-artifact parent");
        let path = parent.join(name);
        if directory {
            fs::create_dir(&path).expect("create retired directory artifact");
        } else {
            fs::write(&path, b"retired artifact must remain").expect("write retired artifact");
        }
        let mut fast_config = config.clone();
        fast_config.init_mode = InitMode::Fast;
        let (fast_kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&fast_config, &lane_config)
                .expect("Fast startup must defer retired-artifact audits");
        drop(fast_kura);
        assert!(
            fs::symlink_metadata(&path).is_ok(),
            "Fast startup must not inspect or mutate retired artifacts",
        );
        let err = match Kura::open_test_kura_with_configured_lane_config(&config, &lane_config) {
            Ok(_) => panic!("retired artifact {name} must abort Kura startup"),
            Err(err) => err,
        };
        assert!(
            matches!(&err, Error::RetiredKuraArtifact { path: rejected } if rejected == &path),
            "unexpected rejection for {name}: {err:?}",
        );
        assert!(
            fs::symlink_metadata(&path).is_ok(),
            "retired artifact must remain for operator-directed removal",
        );
        if !directory {
            assert_eq!(
                fs::read(&path).expect("retired bytes remain"),
                b"retired artifact must remain"
            );
        }
    }
}

#[test]
fn strict_startup_rejects_retired_rollback_intents_after_fast_defers_the_audit() {
    for temporary in [false, true] {
        let temp_dir = TempDir::new().expect("retired rollback tempdir");
        let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
        let lane_config = RuntimeLaneConfig::default();
        let (kura, _) = test_kura_with_default_lane_markers(&config, &lane_config);
        for original in native_storage_frames(2) {
            kura.store_block(original).unwrap();
        }
        let blocks_root = kura.active_blocks_dir.lock().clone();
        drop(kura);
        let stable = Kura::rollback_intent_path(&blocks_root);
        let path = if temporary {
            stable.with_extension("norito.tmp")
        } else {
            stable
        };
        fs::write(&path, b"retired rollback bytes must remain")
            .expect("write retired rollback intent");
        sync_dir(&blocks_root).expect("sync retired rollback intent");
        let before = snapshot_regular_test_tree(&blocks_root);
        let mut fast_config = config.clone();
        fast_config.init_mode = InitMode::Fast;
        let (fast_kura, _) =
            Kura::open_test_kura_with_configured_lane_config(&fast_config, &lane_config)
                .expect("Fast startup must defer retired rollback-intent audits");
        drop(fast_kura);
        assert_eq!(
            snapshot_regular_test_tree(&blocks_root),
            before,
            "Fast startup must not inspect or mutate retired rollback evidence",
        );
        let err = match Kura::open_test_kura_with_configured_lane_config(&config, &lane_config) {
            Ok(_) => panic!("retired rollback intent must abort startup"),
            Err(err) => err,
        };
        assert!(
            matches!(&err, Error::RetiredKuraArtifact { path: rejected } if rejected == &path),
            "unexpected retired rollback rejection: {err:?}",
        );
        assert_eq!(
            snapshot_regular_test_tree(&blocks_root),
            before,
            "retired rollback evidence must be rejected before any recovery mutation",
        );
        assert_eq!(
            fs::read(&path).expect("retired rollback bytes remain"),
            b"retired rollback bytes must remain",
        );
    }
}

#[test]
fn checked_keypair_helpers_preserve_requested_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::BlsNormal).algorithm(),
        Algorithm::BlsNormal
    );
}

#[test]
fn blank_kura_for_testing_uses_isolated_canonical_primary_storage() {
    let kura = Kura::blank_kura_for_testing();
    let block_store_path = kura.block_store.lock().path_to_blockchain.clone();
    let active_blocks_path = kura.active_blocks_dir.lock().clone();
    let expected_blocks = Kura::canonical_storage_path(&kura.store_root());
    assert!(
        block_store_path.is_absolute(),
        "test Kura block store must live under an isolated temporary directory"
    );
    assert_ne!(
        block_store_path,
        std::env::current_dir().expect("current directory"),
        "test Kura must not write blocks.* into the crate working directory"
    );
    assert_eq!(
        block_store_path, expected_blocks,
        "test Kura must use the fixed canonical block namespace"
    );
    assert_eq!(
        active_blocks_path, expected_blocks,
        "active block storage must match the fixed canonical namespace"
    );
    assert!(
        expected_blocks.is_dir(),
        "canonical primary block directory must exist"
    );
    for name in [
        DATA_FILE_NAME,
        INDEX_FILE_NAME,
        HASHES_FILE_NAME,
        COUNT_FILE_NAME,
    ] {
        let path = expected_blocks.join(name);
        let metadata =
            std::fs::symlink_metadata(&path).expect("inspect blank canonical journal file");
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "blank test Kura must initialize canonical journal file {name}"
        );
        if name != COUNT_FILE_NAME {
            assert_eq!(
                metadata.len(),
                0,
                "blank canonical journal file {name} must be empty"
            );
        }
    }
    assert_eq!(
        kura.exact_durable_blocks_count()
            .expect("read blank durable height"),
        0
    );
    assert!(!kura.store_root().join("merge_ledger").exists());
    assert_eq!(
        kura.configured_lane_catalog_baseline().unwrap(),
        Some(LaneLifecycleParameterV1::catalog_hash(
            &LaneCatalog::default()
        )),
    );
    assert!(
        kura.lane_storage_entry(LaneId::SINGLE).is_err(),
        "configured catalog alone does not authenticate a network or lane instance"
    );
    let state = State::new(
        World::default(),
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
    );
    let primary = kura.lane_storage_entry(LaneId::SINGLE).unwrap();
    assert_eq!(primary.network_id, state.network_id);
    kura.require_retained_lane_storage_entry(&primary)
        .expect("State fixture provisioning retains the exact authenticated journal reference");
}

#[test]
fn blank_kura_applies_staged_pre_genesis_nexus_geometry() {
    let lane_zero = ModelLaneConfig::default();
    let lane_one = ModelLaneConfig {
        id: LaneId::new(1),
        alias: "staged-secondary".to_owned(),
        ..ModelLaneConfig::default()
    };
    let catalog = LaneCatalog::new(nonzero!(2_u32), vec![lane_zero, lane_one])
        .expect("staged two-lane catalog");
    let lane_config = RuntimeLaneConfig::from_catalog(&catalog);
    let ignored_store = PathBuf::from("staged-genesis-temporary");
    let config = kura_config_for_path(&ignored_store, BLOCKS_IN_MEMORY);
    let kura = Kura::new_temporary_with_configured_lane_catalog(&config, &lane_config, &catalog)
        .expect("open the exact configured startup baseline");
    let store_root = kura.store_root().clone();
    let constructor_world = World::default();
    let mut state = State::try_new_with_chain(
        constructor_world
            .sccp_committee_generations
            .allocation_budget()
            .clone(),
        constructor_world,
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        ChainId::from("staged-genesis-geometry"),
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
    .expect("construct the actual empty startup State");
    state
        .prepare_configured_primary_geometry_anchor(&catalog)
        .expect("authenticate the configured H0 reference before staged Nexus publication");
    state
        .set_nexus_from_config(iroha_config::parameters::actual::Nexus {
            lane_catalog: catalog.clone(),
            configured_lane_catalog: catalog,
            lane_config: lane_config.clone(),
            ..Default::default()
        })
        .expect("fresh staged state must extend authenticated primary geometry");
    for entry in lane_config.entries() {
        let identity = state
            .lane_storage_identity(entry.lane_id)
            .expect("published State identity");
        assert!(identity.blocks_dir(&store_root).is_dir());
        for name in [
            DATA_FILE_NAME,
            INDEX_FILE_NAME,
            HASHES_FILE_NAME,
            COUNT_FILE_NAME,
        ] {
            assert!(identity.blocks_dir(&store_root).join(name).is_file());
        }
    }
}

#[test]
fn temporary_configured_kura_owns_authenticated_storage_lifetime() {
    let configured = LaneCatalog::default();
    let lane_config = RuntimeLaneConfig::from_catalog(&configured);
    let ignored_store = PathBuf::from("must-not-be-used-by-temporary-kura");
    let config = kura_config_for_path(&ignored_store, BLOCKS_IN_MEMORY);
    let kura = Kura::new_temporary_with_configured_lane_catalog(&config, &lane_config, &configured)
        .expect("initialize temporary authenticated Kura");
    let store_root = kura.store_root().clone();
    assert!(store_root.is_dir());
    assert_ne!(store_root, ignored_store);
    let canonical_blocks = Kura::canonical_storage_path(&store_root);
    assert!(canonical_blocks.is_dir());
    assert!(!store_root.join("merge_ledger").exists());
    assert!(kura.lane_storage_entries.lock().is_empty());
    assert!(!store_root.join("blocks/instances").exists());
    drop(kura);
    assert!(
        !store_root.exists(),
        "temporary authenticated Kura must remove its storage when its final owner drops"
    );
}

#[test]
fn store_root_lock_rejects_a_second_live_kura_and_releases_on_drop() {
    let temp_dir = TempDir::new().expect("create Kura store root");
    let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let lane_config = RuntimeLaneConfig::default();
    let (first, _) = Kura::open_test_kura_with_configured_lane_config(&config, &lane_config)
        .expect("open first Kura");
    let expected_lock_path = std::fs::canonicalize(temp_dir.path())
        .expect("canonical Kura root")
        .join(STORE_ROOT_LOCK_FILE_NAME);
    assert!(matches!(
        Kura::open_test_kura_with_configured_lane_config(&config, &lane_config),
        Err(Error::Locked(path)) if path == expected_lock_path
    ));
    drop(first);
    let (reopened, _) = Kura::open_test_kura_with_configured_lane_config(&config, &lane_config)
        .expect("the OS lock must be released when the first Kura is dropped");
    drop(reopened);
}

#[test]
fn emergency_fast_store_root_lock_does_not_create_a_missing_file() {
    let temp_dir = TempDir::new().expect("create Kura store root");
    let lock_path = std::fs::canonicalize(temp_dir.path())
        .expect("canonical Kura root")
        .join(STORE_ROOT_LOCK_FILE_NAME);
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;

    assert!(!lock_path.exists());
    assert!(matches!(
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default()),
        Err(Error::IO(error, observed_path))
            if error.kind() == ErrorKind::NotFound && observed_path == lock_path
    ));
    assert!(
        !lock_path.exists(),
        "emergency Fast startup must not create the store-root lock file"
    );
}

#[cfg(unix)]
#[test]
fn store_root_lock_rejects_a_symlink_without_touching_its_target() {
    use std::os::unix::fs::symlink;
    let temp_dir = TempDir::new().expect("create Kura store root");
    let victim = temp_dir.path().join("lock-victim");
    let victim_bytes = b"must remain untouched";
    std::fs::write(&victim, victim_bytes).expect("create lock victim");
    let lock_path = std::fs::canonicalize(temp_dir.path())
        .expect("canonical Kura root")
        .join(STORE_ROOT_LOCK_FILE_NAME);
    symlink(&victim, &lock_path).expect("plant lockfile symlink");
    let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    assert!(matches!(
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default()),
        Err(Error::IO(error, observed_path))
            if error.kind() == ErrorKind::InvalidData && observed_path == lock_path
    ));
    assert_eq!(
        std::fs::read(&victim).expect("read lock victim"),
        victim_bytes
    );
}

#[cfg(unix)]
#[test]
fn store_root_lock_canonicalizes_a_symlinked_root_for_all_kura_paths() {
    use std::os::unix::fs::symlink;
    let real_root = TempDir::new().expect("create real Kura root");
    let alias_parent = TempDir::new().expect("create Kura alias parent");
    let alias_root = alias_parent.path().join("kura-alias");
    symlink(real_root.path(), &alias_root).expect("create Kura root alias");
    let canonical_root = std::fs::canonicalize(real_root.path()).expect("canonical real root");
    let mut alias_config = kura_config_for_dir(&real_root, BLOCKS_IN_MEMORY);
    alias_config.store_dir = WithOrigin::inline(alias_root);
    let real_config = kura_config_for_dir(&real_root, BLOCKS_IN_MEMORY);
    let lane_config = RuntimeLaneConfig::default();
    let (aliased, _) =
        Kura::open_test_kura_with_configured_lane_config(&alias_config, &lane_config)
            .expect("open aliased Kura root");
    assert_eq!(aliased.store_root, canonical_root);
    assert!(
        aliased
            .active_blocks_dir
            .lock()
            .starts_with(&canonical_root)
    );
    assert!(matches!(
        Kura::open_test_kura_with_configured_lane_config(&real_config, &lane_config),
        Err(Error::Locked(path))
            if path == canonical_root.join(STORE_ROOT_LOCK_FILE_NAME)
    ));
    drop(aliased);
    let (reopened, _) =
        Kura::open_test_kura_with_configured_lane_config(&real_config, &lane_config)
            .expect("canonical root must reopen after aliased owner drops");
    drop(reopened);
}

#[test]
fn immutable_sidecar_publication_never_clobbers_a_racing_destination() {
    let kura = Kura::blank_kura_for_testing();
    let directory = kura.store_root().join("native-publication-test");
    create_dir_all_with_context(&directory).expect("create immutable sidecar directory");
    let path = directory.join("race.norito");
    std::fs::write(&path, b"attacker-won-the-race").expect("publish racing destination");
    assert!(
        !kura
            .write_atomic_synced_noclobber(&path, b"candidate")
            .expect("no-clobber race is not an I/O failure")
    );
    assert_eq!(
        std::fs::read(&path).expect("read racing destination"),
        b"attacker-won-the-race",
        "immutable publication must not overwrite a destination created after lookup"
    );
}

#[test]
fn native_storage_original_frames_and_certificates_survive_strict_restart() {
    let originals = native_storage_frames(3);
    let hashes = originals
        .iter()
        .map(|block| block.hash())
        .collect::<Vec<_>>();
    let network = iroha_data_model::NetworkId::from_genesis_hash(hashes[0]);
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let directory = TempDir::new().unwrap();
    let config = kura_config_for_dir(&directory, BLOCKS_IN_MEMORY);
    let lanes = RuntimeLaneConfig::default();
    let (kura, _) = test_kura_with_default_lane_markers(&config, &lanes);
    for block in &originals {
        kura.store_block((block).clone()).unwrap();
    }
    kura.block_store.lock().flush_pending_fsync(true).unwrap();
    let original_wires = originals
        .iter()
        .map(|block| block.encode_wire().unwrap())
        .collect::<Vec<_>>();
    drop(kura);
    let (reopened, count) =
        Kura::open_test_kura_with_configured_lane_config(&config, &lanes).unwrap();
    assert_eq!(count.0, originals.len());
    let history_budget = crate::state::AllocationBudget::new(64 * 1024 * 1024);
    let verified =
        CertifiedChain::from_pinned(&chain_id, &network, &hashes, &reopened, &history_budget)
            .unwrap();
    for height in 1..=3 {
        let authority = verified.authenticated_execution(height).unwrap();
        let original = &originals[usize::try_from(height).expect("fixture value fits usize") - 1];
        assert_eq!(
            authority.block().commit_certificate(),
            original.commit_certificate()
        );
        let (retained, bytes) = reopened
            .read_authenticated_execution_wire(
                &authority,
                original_wires[usize::try_from(height).expect("fixture value fits usize") - 1].len()
                    as u64,
                &history_budget,
            )
            .unwrap()
            .unwrap();
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &retained,
            authority.block()
        ));
        assert_eq!(
            bytes.as_slice(),
            original_wires[usize::try_from(height).expect("fixture value fits usize") - 1]
        );
    }
    assert!(!reopened.store_root().join("merge_ledger").exists());
    assert!(!reopened.store_root().join("v2_finality").exists());
}

#[test]
fn native_storage_reads_preserve_original_bytes_when_recovery_or_poison_blocks_access() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let authority = reader.authenticated_execution(2).unwrap();
    let kura = chain.kura();
    let original = authority.block().encode_wire().unwrap();
    for canonical in [false, true] {
        let flag = if canonical {
            &kura.canonical_storage_poisoned
        } else {
            &kura.prune_recovery_required
        };
        flag.store(true, Ordering::Release);
        assert!(
            kura.read_authenticated_execution_wire(
                &authority,
                original.len() as u64,
                &chain.state().ivm_execution_budget()
            )
            .is_err()
        );
        flag.store(false, Ordering::Release);
        assert_eq!(
            kura.read_authenticated_execution_wire(
                &authority,
                original.len() as u64,
                &chain.state().ivm_execution_budget()
            )
            .unwrap()
            .unwrap()
            .1
            .as_slice(),
            original
        );
    }
}

/// Network committed by the same genuine signed genesis used by NativeBlocks.
pub(super) fn native_storage_network_id() -> iroha_data_model::NetworkId {
    static NETWORK: std::sync::OnceLock<iroha_data_model::NetworkId> = std::sync::OnceLock::new();
    *NETWORK.get_or_init(|| {
        iroha_data_model::NetworkId::from_genesis_hash(native_storage_frames(1)[0].hash())
    })
}

#[test]
fn native_storage_fixture_network_is_pinned_to_original_signed_genesis() {
    let original = native_storage_frames(1).pop().unwrap();
    let expected = iroha_data_model::NetworkId::from_genesis_hash(original.hash());
    assert_eq!(native_storage_network_id(), expected);
    let kura = Kura::blank_kura_for_testing();
    kura.bind_lane_storage_network(expected).unwrap();
    assert!(
        kura.bind_lane_storage_network(test_network_id(b"foreign-fixture-network"))
            .is_err()
    );
    assert_eq!(*kura.lane_storage_network.lock(), Some(expected));
}

// Observe exact fixture bytes without granting storage or execution authority.
fn snapshot_regular_files_recursively(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("read snapshot entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("inspect snapshot entry");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                collect(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .expect("snapshot file is below root")
                        .to_path_buf(),
                    fs::read(&path).expect("read snapshot file"),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

// Independent original-file physical observations, shared by current canonical writer tests.
fn initialize_physical_fixture(kura: &Kura) -> IndexResourceCounts {
    let generation = kura.resource_inventory.reconciliation_generation().unwrap();
    let counts = kura
        .physical_resource_scope()
        .unwrap()
        .observe(kura.evidence_resource_limits())
        .expect("independently observe every physical fixture owner");
    kura.resource_inventory
        .initialize(
            generation,
            &PHYSICAL_RESOURCE_FAMILIES
                .iter()
                .map(|family| (*family, counts[*family as usize]))
                .collect::<Vec<_>>(),
        )
        .expect("register only observed physical families after fixture preparation");
    counts
}

fn assert_physical_fixture(kura: &Kura) -> IndexResourceCounts {
    let observed = kura
        .physical_resource_scope()
        .unwrap()
        .observe(kura.evidence_resource_limits())
        .unwrap();
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert_eq!(
            kura.resource_inventory
                .component_usage_for_tests(family)
                .unwrap(),
            observed[family as usize],
            "independent real-file recount for {family:?}",
        );
    }
    observed
}

fn assert_physical_unavailable(kura: &Kura) {
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert!(
            kura.resource_inventory
                .component_usage_for_tests(family)
                .is_err()
        );
    }
}

#[test]
fn pipeline_recovery_format_has_one_current_tag_and_rejects_unknown_tags() {
    let encoded = PipelineRecoveryFormat::Current.encode();
    assert_eq!(u32::from_le_bytes(encoded[..4].try_into().unwrap()), 0);
    for tag in [1_u32, u32::MAX] {
        let invalid = tag.encode();
        assert!(
            <PipelineRecoveryFormat as DecodeAll>::decode_all(&mut invalid.as_slice()).is_err()
        );
    }
}

#[test]
fn every_startup_mode_rejects_retired_snapshot_markers_without_changing_bytes() {
    for (name, directory) in [
        (VERIFIED_SNAPSHOT_TAIL_FILE_NAME, false),
        ("verified_snapshot_tail.norito.tmp", false),
        (".verified-snapshot-tail-unpublished", false),
        (VERIFIED_SNAPSHOT_TAIL_FILE_NAME, true),
    ] {
        let temp = TempDir::new().unwrap();
        let mut config = kura_config_for_dir(&temp, BLOCKS_IN_MEMORY);
        let lanes = RuntimeLaneConfig::default();
        let (kura, _) = test_kura_with_default_lane_markers(&config, &lanes);
        // Startup checks the configured spelling before canonicalizing or mutating storage.
        // On macOS the configured temporary root may use /var and the active root /private/var.
        let blocks = Kura::canonical_storage_path(&config.store_dir.resolve_relative_path());
        assert_eq!(
            fs::canonicalize(&blocks).unwrap(),
            *kura.active_blocks_dir.lock()
        );
        drop(kura);
        let path = blocks.join(name);
        if directory {
            fs::create_dir(&path).unwrap();
            fs::write(path.join("evidence"), b"retired snapshot authority").unwrap();
        } else {
            // Neither syntactically valid nor malformed bytes gain a decode/recovery path.
            fs::write(&path, b"retired snapshot authority").unwrap();
        }
        let before = snapshot_regular_files_recursively(temp.path());
        for mode in [InitMode::Strict, InitMode::Fast] {
            config.init_mode = mode;
            assert!(matches!(
                Kura::new_with_configured_lane_catalog(&config, &lanes, &LaneCatalog::default()),
                Err(Error::RetiredKuraArtifact { path: rejected }) if rejected == path
            ));
            assert_eq!(snapshot_regular_files_recursively(temp.path()), before);
        }
        let mut direct = BlockStore::new(&blocks);
        assert!(matches!(
            direct.create_files_if_they_do_not_exist(),
            Err(Error::RetiredKuraArtifact { .. })
        ));
        assert!(matches!(
            direct.init_commit_marker(),
            Err(Error::RetiredKuraArtifact { .. })
        ));
        assert_eq!(snapshot_regular_files_recursively(temp.path()), before);
    }
}

#[test]
fn retired_snapshot_marker_is_rejected_before_initializing_storage() {
    let temp = TempDir::new().unwrap();
    let config = kura_config_for_dir(&temp, BLOCKS_IN_MEMORY);
    let root = config.store_dir.resolve_relative_path();
    let blocks = Kura::canonical_storage_path(&root);
    fs::create_dir_all(&blocks).unwrap();
    fs::write(
        blocks.join(VERIFIED_SNAPSHOT_TAIL_FILE_NAME),
        b"untrusted prefix",
    )
    .unwrap();
    let before = snapshot_regular_files_recursively(temp.path());
    assert!(matches!(
        Kura::new_with_configured_lane_catalog(
            &config,
            &RuntimeLaneConfig::default(),
            &LaneCatalog::default()
        ),
        Err(Error::RetiredKuraArtifact { .. })
    ));
    assert_eq!(snapshot_regular_files_recursively(temp.path()), before);
    assert!(!root.join(STORE_ROOT_LOCK_FILE_NAME).exists());
    assert!(!blocks.join(INDEX_FILE_NAME).exists());
}

#[cfg(unix)]
#[test]
fn retired_snapshot_symlink_is_rejected_without_following_or_removing_it() {
    let temp = TempDir::new().unwrap();
    let config = kura_config_for_dir(&temp, BLOCKS_IN_MEMORY);
    let (kura, _) = test_kura_with_default_lane_markers(&config, &RuntimeLaneConfig::default());
    let blocks = Kura::canonical_storage_path(&config.store_dir.resolve_relative_path());
    assert_eq!(
        fs::canonicalize(&blocks).unwrap(),
        *kura.active_blocks_dir.lock()
    );
    drop(kura);
    let target = temp.path().join("untrusted-snapshot-target");
    fs::write(&target, b"preserve exact original evidence").unwrap();
    let marker = blocks.join(VERIFIED_SNAPSHOT_TAIL_FILE_NAME);
    std::os::unix::fs::symlink(&target, &marker).unwrap();
    assert!(matches!(
        Kura::new_with_configured_lane_catalog(&config, &RuntimeLaneConfig::default(), &LaneCatalog::default()),
        Err(Error::RetiredKuraArtifact { path }) if path == marker
    ));
    assert_eq!(fs::read_link(&marker).unwrap(), target);
    assert_eq!(
        fs::read(&target).unwrap(),
        b"preserve exact original evidence"
    );
}
