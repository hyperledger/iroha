//! Original archive backing, immutable publication and canonical reader regressions.

use super::*;
use crate::state::NativeExecutionProjectionV1;
use iroha_allocation::AllocationRefusal;
use iroha_crypto::Hash;
use std::fs;

fn hash() -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::new(b"exact original native carrier"))
}
static EMPTY_WRITES: Vec<ExecKv> = Vec::new();
static EMPTY_CASTING: Vec<
    iroha_data_model::parliament_casting::ParliamentTimedOvnCastingContextBindingV1,
> = Vec::new();
fn projection(lanes: &SumeragiLaneState) -> Projection<'_> {
    Projection {
        carrier_height: 2,
        carrier_hash: hash(),
        lanes: LaneStateRef(lanes),
        ordinary_writes: OrdinaryWritesRef(&EMPTY_WRITES),
        casting_bindings: CastingBindingsRef(&EMPTY_CASTING),
        sccp_delta: &[],
    }
}
fn archive(root: &Path, budget: AllocationBudget, maximum: usize) -> NativeContextArchive {
    let (root, directory) = open_directory(root, true).unwrap();
    NativeContextArchive {
        root,
        directory,
        budget,
        maximum: NonZeroUsize::new(maximum).unwrap(),
        writable: true,
    }
}
fn canonical_path(root: &Path) -> std::path::PathBuf {
    root.join("native-contexts")
        .join(RecordName::new(2, hash(), false).as_str())
}
fn stage_path(root: &Path) -> std::path::PathBuf {
    root.join("native-contexts")
        .join(RecordName::new(2, hash(), true).as_str())
}

#[test]
fn exact_canonical_projection_owns_original_pool_until_last_drop() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState {
        samples: vec![iroha_data_model::sumeragi_lanes::SumeragiLaneSample {
            height: 2,
            time_ms: 2_000,
            transactions: 7,
            lanes: 1,
        }]
        .try_into()
        .unwrap(),
        last_transition: 1,
        incarnations: 3,
        ..SumeragiLaneState::default()
    };
    let writes = vec![
        ExecKv {
            key: vec![0x42],
            value: vec![1, 2],
        },
        ExecKv {
            key: vec![0x42],
            value: vec![3, 4],
        },
    ];
    let mut source = projection(&lanes);
    source.ordinary_writes = OrdinaryWritesRef(&writes);
    let bytes = norito::encode_canonical(&NativeExecutionProjectionV1 {
        carrier_height: 2,
        carrier_hash: hash(),
        lanes: lanes.clone(),
        ordinary_writes: writes.clone(),
        casting_bindings: vec![],
        sccp_delta: vec![],
    })
    .unwrap();
    let budget = AllocationBudget::new(bytes.len() * 2);
    let archive_owner = archive(dir.path(), budget.clone(), bytes.len());
    let original = archive_owner.encode_projection(&source).unwrap();
    assert_eq!(original.canonical_bytes(), bytes);
    assert_eq!(original.height(), 2);
    assert_eq!(original.carrier_hash(), hash());
    assert_eq!(budget.reserved_bytes(), bytes.len());
    archive_owner.publish(&original).unwrap();
    archive_owner.publish(&original).unwrap();
    assert!(!stage_path(dir.path()).exists());
    let reader = NativeContextArchive::open_read_only(
        dir.path(),
        budget.clone(),
        NonZeroUsize::new(bytes.len()).unwrap(),
    )
    .unwrap();
    let acquired = reader.read_exact(2, hash()).unwrap();
    assert_eq!(acquired.as_slice(), bytes);
    assert_eq!(budget.reserved_bytes(), bytes.len() * 2);
    reader.recheck_namespace().unwrap();
    drop(acquired);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn occupied_original_pool_refuses_then_retries_exact_projection_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let source = projection(&lanes);
    let length = norito::canonical_frame_len(&source).unwrap();
    let budget = AllocationBudget::new(length);
    let writer = archive(dir.path(), budget.clone(), length);
    let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    let refusal = match writer.encode_projection(&source) {
        Err(error) => error,
        Ok(_) => panic!("occupied original pool admitted archive"),
    };
    assert!(refusal.is_local_refusal());
    assert!(matches!(
        refusal,
        NativeContextArchiveError::Allocation(ChargedBufferError::Admission(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 1);
    assert!(!canonical_path(dir.path()).exists());
    drop(occupied);
    let original = writer.encode_projection(&source).unwrap();
    let identity = original.canonical_bytes().as_ptr();
    writer.publish(&original).unwrap();
    assert!(writer.read_exact(2, hash()).is_err());
    assert_eq!(original.canonical_bytes().as_ptr(), identity);
    assert_eq!(budget.reserved_bytes(), length);
    drop(original);
    let read = writer.read_exact(2, hash()).unwrap();
    assert_eq!(read.as_slice().len(), length);
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn configured_limit_and_foreign_pool_are_never_local_capacity_retries() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let source = projection(&lanes);
    let length = norito::canonical_frame_len(&source).unwrap();
    let budget = AllocationBudget::new(length);
    let small = archive(dir.path(), budget.clone(), length - 1);
    let error = match small.encode_projection(&source) {
        Err(error) => error,
        Ok(_) => panic!("oversized record"),
    };
    assert!(
        matches!(error, NativeContextArchiveError::Limit { maximum, actual } if maximum == length - 1 && actual == length)
    );
    assert!(!error.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), 0);
    let writer = archive(dir.path(), budget.clone(), length);
    let original = writer.encode_projection(&source).unwrap();
    let foreign = archive(dir.path(), AllocationBudget::new(length), length);
    assert!(matches!(
        foreign.publish(&original),
        Err(NativeContextArchiveError::Source(_))
    ));
    assert!(!canonical_path(dir.path()).exists());
    writer.publish(&original).unwrap();
    let reader = NativeContextArchive::open_read_only(
        dir.path(),
        AllocationBudget::new(length),
        NonZeroUsize::new(length).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        reader.publish(&original),
        Err(NativeContextArchiveError::Source(_))
    ));
    assert!(matches!(
        small.read_exact(2, hash()),
        Err(NativeContextArchiveError::Limit { .. })
    ));
}

#[test]
fn changed_canonical_record_fails_without_overwriting_or_losing_original() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let writer = archive(dir.path(), AllocationBudget::new(4096), 4096);
    let original = writer.encode_projection(&projection(&lanes)).unwrap();
    let pointer = original.canonical_bytes().as_ptr();
    writer.publish(&original).unwrap();
    let mut changed = original.canonical_bytes().to_vec();
    changed[0] ^= 1;
    fs::write(canonical_path(dir.path()), &changed).unwrap();
    assert!(writer.publish(&original).is_err());
    assert_eq!(fs::read(canonical_path(dir.path())).unwrap(), changed);
    assert_eq!(original.canonical_bytes().as_ptr(), pointer);
    assert!(!stage_path(dir.path()).exists());
}

#[test]
fn interrupted_unlinked_stage_rewrites_only_from_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let writer = archive(dir.path(), AllocationBudget::new(4096), 4096);
    let original = writer.encode_projection(&projection(&lanes)).unwrap();
    fs::write(stage_path(dir.path()), b"interrupted incomplete staging").unwrap();
    writer.publish(&original).unwrap();
    assert_eq!(
        fs::read(canonical_path(dir.path())).unwrap(),
        original.canonical_bytes()
    );
    assert!(!stage_path(dir.path()).exists());
}

#[test]
fn interruption_after_link_cleans_identical_stage_on_original_retry() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let writer = archive(dir.path(), AllocationBudget::new(4096), 4096);
    let original = writer.encode_projection(&projection(&lanes)).unwrap();
    fs::write(stage_path(dir.path()), original.canonical_bytes()).unwrap();
    fs::hard_link(stage_path(dir.path()), canonical_path(dir.path())).unwrap();
    writer.publish(&original).unwrap();
    assert!(!stage_path(dir.path()).exists());
    assert_eq!(
        fs::read(canonical_path(dir.path())).unwrap(),
        original.canonical_bytes()
    );
}

#[test]
fn foreign_staged_hardlink_is_never_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let lanes = SumeragiLaneState::default();
    let writer = archive(dir.path(), AllocationBudget::new(4096), 4096);
    let original = writer.encode_projection(&projection(&lanes)).unwrap();
    let external = dir.path().join("foreign");
    fs::write(&external, b"foreign owner").unwrap();
    fs::hard_link(&external, stage_path(dir.path())).unwrap();
    assert!(writer.publish(&original).is_err());
    assert_eq!(fs::read(&external).unwrap(), b"foreign owner");
    assert!(!canonical_path(dir.path()).exists());
}

#[test]
fn readonly_open_and_missing_record_do_not_create_or_synthesize() {
    let dir = tempfile::tempdir().unwrap();
    let budget = AllocationBudget::new(4096);
    assert!(
        NativeContextArchive::open_read_only(
            dir.path(),
            budget.clone(),
            NonZeroUsize::new(4096).unwrap()
        )
        .is_err()
    );
    assert!(!dir.path().join("native-contexts").exists());
    let writer = archive(dir.path(), budget.clone(), 4096);
    assert!(writer.read_exact(2, hash()).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[cfg(unix)]
#[test]
fn directory_and_record_symlinks_and_namespace_substitution_fail_closed() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let budget = AllocationBudget::new(4096);
    symlink(other.path(), dir.path().join("native-contexts")).unwrap();
    assert!(
        NativeContextArchive::open_read_only(
            dir.path(),
            budget.clone(),
            NonZeroUsize::new(4096).unwrap()
        )
        .is_err()
    );
    fs::remove_file(dir.path().join("native-contexts")).unwrap();
    let writer = archive(dir.path(), budget.clone(), 4096);
    let outside = other.path().join("record");
    fs::write(&outside, b"external").unwrap();
    symlink(&outside, canonical_path(dir.path())).unwrap();
    assert!(writer.read_exact(2, hash()).is_err());
    fs::remove_file(canonical_path(dir.path())).unwrap();
    fs::rename(
        dir.path().join("native-contexts"),
        dir.path().join("retained-original"),
    )
    .unwrap();
    fs::create_dir(dir.path().join("native-contexts")).unwrap();
    assert!(writer.recheck_namespace().is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn fixed_record_identity_uses_exact_height_and_raw_carrier_bytes() {
    let name = RecordName::new(u64::MAX, hash(), false);
    assert!(name.as_str().starts_with("18446744073709551615-"));
    assert_eq!(name.as_str().len(), 89);
    assert_eq!(
        std::path::Path::new(name.as_str()).extension(),
        Some(std::ffi::OsStr::new("nrt"))
    );
    assert_eq!(
        RecordName::new(u64::MAX, hash(), true).as_str(),
        format!(".{}", name.as_str())
    );
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn production_open_retains_exact_kura_root_and_rejects_replaced_path() {
    use std::os::unix::fs::MetadataExt as _;
    let kura = Kura::blank_kura_for_testing();
    let budget = AllocationBudget::new(4096);
    let bound = NativeContextArchive::open(
        &kura,
        budget.clone(),
        kura.native_context_archive_max_bytes(),
    )
    .unwrap();
    let original = kura.native_context_archive_root().unwrap();
    assert_eq!(
        bound.root.metadata().unwrap().dev(),
        original.metadata().unwrap().dev()
    );
    assert_eq!(
        bound.root.metadata().unwrap().ino(),
        original.metadata().unwrap().ino()
    );
    let path = kura.store_root();
    let hidden = path.with_extension("retained-original");
    fs::rename(&path, &hidden).unwrap();
    fs::create_dir(&path).unwrap();
    let refusal =
        NativeContextArchive::open(&kura, budget, kura.native_context_archive_max_bytes());
    let created_in_substitute = path.join("native-contexts").exists();
    fs::remove_dir(&path).unwrap();
    fs::rename(&hidden, &path).unwrap();
    assert!(
        matches!(refusal, Err(NativeContextArchiveError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    assert!(
        !created_in_substitute,
        "opening cannot mutate a substitute Kura root"
    );
    bound.recheck_namespace().unwrap();
}

#[test]
fn live_readonly_open_requires_existing_original_archive_and_cannot_publish() {
    let kura = Kura::blank_kura_for_testing();
    let budget = AllocationBudget::new(4096);
    let maximum = kura.native_context_archive_max_bytes();
    let path = kura.store_root().join("native-contexts");
    assert!(!path.exists());
    assert!(matches!(
        NativeContextArchive::open_existing(&kura, budget.clone(), maximum),
        Err(NativeContextArchiveError::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
    assert!(
        !path.exists(),
        "a read cannot create missing evidence storage"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let writer = NativeContextArchive::open(&kura, budget.clone(), maximum).unwrap();
    let lanes = SumeragiLaneState::default();
    let original = writer.encode_projection(&projection(&lanes)).unwrap();
    writer.publish(&original).unwrap();
    let reader = NativeContextArchive::open_existing(&kura, budget.clone(), maximum).unwrap();
    assert!(!reader.writable);
    assert!(matches!(
        reader.publish(&original),
        Err(NativeContextArchiveError::Source(_))
    ));
    let read = reader.read_exact(2, hash()).unwrap();
    assert_eq!(read.as_slice(), original.canonical_bytes());
    reader.recheck_namespace().unwrap();
    drop(read);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_native_archive_retains_writes_bound_to_the_original_execution_root() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::sumeragi_finality::NativeLaneStateProof;
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let committed = chain.committed(2);
    let budget = chain.state().ivm_execution_budget();
    let archive = NativeContextArchive::open_existing(
        chain.kura(),
        budget.clone(),
        chain.kura().native_context_archive_max_bytes(),
    )
    .unwrap();
    let bytes = archive.read_exact(2, committed.block_hash()).unwrap();
    let projection: NativeExecutionProjectionV1 = norito::decode_canonical_with_limits(
        bytes.as_slice(),
        norito::canonical_decode_limits(bytes.as_slice().len()),
    )
    .unwrap();
    assert_eq!(projection.carrier_hash, committed.block_hash());
    let mut witness = ExecWitness {
        writes: projection.ordinary_writes,
        ..ExecWitness::default()
    };
    let expected = &committed.commitment().native_lanes;
    assert_eq!(
        &NativeLaneStateProof::from_witness(&witness, &budget).unwrap(),
        expected
    );
    witness.writes.push(ExecKv {
        key: b"foreign-write".to_vec(),
        value: vec![1],
    });
    let changed = NativeLaneStateProof::from_witness(&witness, &budget).unwrap();
    assert_ne!(
        &changed, expected,
        "adding an unexecuted write changes the authenticated path"
    );
    assert!(!changed.verify(
        chain.network_id(),
        2,
        committed.commitment().execution.ordinary_writes_root
    ));
}

#[test]
fn exact_sccp_delta_capture_is_funded_and_matches_the_original_overlay() {
    use crate::smartcontracts::isi::sccp::{store, test_support};
    let state = test_support::blank_state();
    let mut block = state.block(test_support::header(2));
    {
        let mut transaction = block.transaction();
        store::parameters::set(
            &mut transaction,
            Some(iroha_data_model::sccp::params::SccpParametersV1::taira_default()),
        );
        transaction.apply();
    }
    let expected = block.world.sccp_execution_write_set_bytes();
    assert!(!expected.is_empty());
    let budget = AllocationBudget::new(expected.len());
    let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    let error = capture_sccp_delta(&block.world, &budget, expected.len())
        .err()
        .expect("original pool occupied");
    assert!(error.is_local_refusal());
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let original = capture_sccp_delta(&block.world, &budget, expected.len()).unwrap();
    assert!(original.belongs_to(&budget));
    assert_eq!(original.as_slice(), expected);
    assert_eq!(budget.reserved_bytes(), expected.len());
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(matches!(
        capture_sccp_delta(&block.world, &budget, expected.len() - 1),
        Err(NativeContextArchiveError::Limit { .. })
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}
