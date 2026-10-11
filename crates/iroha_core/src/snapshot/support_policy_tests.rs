// Snapshot policy fixtures preserve exact source identity and authenticated history.
use super::*;
use crate::{
    block::BlockBuilder,
    query::store::LiveQueryStore,
    state::{AssetDefinitionAliasBindingRecord, ContractAliasBindingRecord},
    tx::AcceptedTransaction,
};
use iroha_config::{
    base::WithOrigin,
    kura::FsyncMode,
    parameters::{
        actual::{Kura as KuraConfig, LaneConfig},
        defaults::{
            self,
            kura::{FSYNC_INTERVAL, MAX_DISK_USAGE_BYTES},
        },
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    Level, Registrable,
    account::{
        AccountAlias, AccountAliasDomain, AccountDetails, AccountId, AccountRekeyRecord,
        AccountValue,
    },
    asset::{AssetDefinition, AssetDefinitionAlias, AssetDefinitionId},
    block::{
        BlockHeader, SignedBlock,
        consensus::{
            Evidence, EvidenceAttribution, EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord,
        },
    },
    isi::{Log, space_directory::PublishSpaceDirectoryManifest},
    nexus::{
        AssetPermissionManifest, LaneCatalog, LaneConfig as ModelLaneConfig, ManifestVersion,
        UniversalAccountId,
    },
    smart_contract::{ContractAddress, ContractAlias},
    transaction::TransactionBuilder,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use nonzero_ext::nonzero;
use std::{
    borrow::Cow,
    fs::File,
    num::{NonZeroU64, NonZeroUsize},
    path::Path,
    sync::{Arc, Barrier},
};
use tempfile::tempdir;
const TEST_CHUNK_SIZE: NonZeroUsize = nonzero!(1024_usize);
fn dummy_block_hash(marker: u8) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::prehashed([marker; 32]))
}
const TEST_CHAIN_ID: &str = "test-chain";
const SMALL_ORDER_ED25519_R: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCANONICAL_ED25519_R: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
fn snapshot_test_network_id() -> NetworkId {
    let mut genesis_hash = [0_u8; Hash::LENGTH];
    genesis_hash[Hash::LENGTH - 1] = 1;
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(genesis_hash),
    ))
}
fn checked_seeded_keypair(seed: u8, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], algorithm)
        .expect("test snapshot seeded keypair should be valid")
}
fn checked_random_snapshot_keypair() -> KeyPair {
    KeyPair::try_random().expect("snapshot fixture key generation should succeed")
}
fn checked_random_snapshot_bls_keypair() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
        .expect("snapshot BLS fixture key generation should succeed")
}
// Hash-projection fixture only: these signed artifacts do not create admitted history.
fn snapshot_evidence_fixture(network_id: NetworkId) -> (Evidence, EvidenceAttribution) {
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Vote, VoteKind},
        types::{EpochId, Hash32, SIGNATURE_LEN, Signature as NativeSignature},
    };
    let mut keys = (1_u8..=4)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let signer = 1;
    let key = &keys[signer as usize];
    let vote = |subject: u8| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: Hash32(*network_id.as_bytes()),
            epoch: EpochId {
                epoch: 0,
                context: Hash32([0x51; 32]),
            },
            height: 1,
            view: 0,
            block_hash: Hash32([subject; 32]),
            result: Hash32([0x52; 32]),
            signer,
            sig: NativeSignature([0; SIGNATURE_LEN]),
        };
        vote.sig = NativeSignature(
            Signature::new(key.private_key(), &vote.preimage())
                .payload()
                .try_into()
                .unwrap(),
        );
        vote
    };
    let evidence =
        Evidence::from_native(&NativeEvidence::VoteEquivocation(vote(0x61), vote(0x62))).unwrap();
    let attribution = EvidenceAttribution {
        scope: iroha_data_model::block::consensus::EvidenceScope::Root,
        instance: *network_id.as_bytes(),
        height: 1,
        epoch: 0,
        context_id: [0x51; 32],
        authority_generation: [0x53; 32],
        offenders: vec![EvidenceOffender {
            lane_stake: None,
            signer,
            peer_id: PeerId::new(key.public_key().clone()),
        }],
        safety_violation: false,
    };
    (evidence, attribution)
}
#[test]
fn snapshot_evidence_fixture_preserves_original_signed_bytes() {
    let (evidence, attribution) = snapshot_evidence_fixture(snapshot_test_network_id());
    let iroha_sumeragi::message::Evidence::VoteEquivocation(first, mut second) =
        evidence.decode_native().unwrap()
    else {
        panic!("native vote pair")
    };
    for vote in [&first, &second] {
        Signature::from_bytes(&vote.sig.0)
            .verify(
                attribution.offenders[0].peer_id.public_key(),
                &vote.preimage(),
            )
            .unwrap();
    }
    second.epoch.context.0[0] ^= 1;
    assert!(
        Signature::from_bytes(&second.sig.0)
            .verify(
                attribution.offenders[0].peer_id.public_key(),
                &second.preimage()
            )
            .is_err()
    );
}
fn current_generation_name(store_dir: &Path) -> String {
    let pointer_path = store_dir.join(SNAPSHOT_CURRENT_FILE_NAME);
    let pointer = std::fs::read(&pointer_path).expect("read canonical snapshot pointer");
    parse_snapshot_current_pointer(&pointer, &pointer_path)
        .expect("canonical snapshot pointer must name one generation")
}
fn current_generation_dir(store_dir: &Path) -> PathBuf {
    store_dir
        .join(SNAPSHOT_GENERATIONS_DIR_NAME)
        .join(current_generation_name(store_dir))
}
fn current_generation_artifact(store_dir: &Path, name: &str) -> PathBuf {
    current_generation_dir(store_dir).join(name)
}
fn current_snapshot_bundle_auth_digest(store_dir: &Path) -> [u8; 32] {
    let digest_path = current_generation_artifact(store_dir, SNAPSHOT_DIGEST_FILE_NAME);
    let digest_bytes = std::fs::read(&digest_path).expect("read snapshot digest");
    let payload_digest =
        parse_snapshot_digest_bytes(&digest_bytes, &digest_path).expect("canonical payload digest");
    let manifest_bytes = std::fs::read(current_generation_artifact(
        store_dir,
        SNAPSHOT_FAST_MANIFEST_FILE_NAME,
    ))
    .expect("read emergency Fast manifest");
    snapshot_bundle_auth_digest(&payload_digest, &manifest_bytes)
}
fn assert_canonical_snapshot_generation(store_dir: &Path) {
    let mut root_entries = std::fs::read_dir(store_dir)
        .expect("read snapshot root")
        .map(|entry| {
            entry
                .expect("read snapshot root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    root_entries.sort();
    assert_eq!(
        root_entries,
        vec![
            SNAPSHOT_CURRENT_FILE_NAME.to_owned(),
            SNAPSHOT_GENERATIONS_DIR_NAME.to_owned(),
        ],
        "first-release snapshots expose only the atomic pointer and immutable generations"
    );
    let generation_dir = current_generation_dir(store_dir);
    let generation_name = current_generation_name(store_dir);
    let payload = std::fs::read(generation_dir.join(SNAPSHOT_FILE_NAME))
        .expect("read selected snapshot payload");
    assert_eq!(generation_name, hex::encode(Sha256::digest(&payload)));
    assert_eq!(
        std::fs::read(generation_dir.join(SNAPSHOT_DIGEST_FILE_NAME))
            .expect("read selected snapshot digest"),
        format!("{generation_name}\n").as_bytes()
    );
    let mut artifact_names = std::fs::read_dir(&generation_dir)
        .expect("read selected generation")
        .map(|entry| {
            entry
                .expect("read generation entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    artifact_names.sort();
    let mut expected = vec![
        SNAPSHOT_FILE_NAME.to_owned(),
        SNAPSHOT_DIGEST_FILE_NAME.to_owned(),
        SNAPSHOT_SIGNATURE_FILE_NAME.to_owned(),
        SNAPSHOT_FAST_MANIFEST_FILE_NAME.to_owned(),
        SNAPSHOT_MERKLE_FILE_NAME.to_owned(),
    ];
    expected.sort();
    assert_eq!(artifact_names, expected);
}
fn native_snapshot_chain() -> crate::sumeragi::test_chain::CertifiedTestChain {
    crate::sumeragi::test_chain::CertifiedTestChain::start(
        crate::sumeragi::test_chain::TestChainConfig::new(crate::state::World::new(), 1_000),
    )
    .expect("original signed native genesis")
}
fn assert_snapshot_bundle_absent(store_dir: &Path) {
    assert!(
        !store_dir.join(SNAPSHOT_CURRENT_FILE_NAME).exists(),
        "rejected snapshot must not publish a current pointer"
    );
    let generations = store_dir.join(SNAPSHOT_GENERATIONS_DIR_NAME);
    assert!(
        !generations.exists()
            || std::fs::read_dir(&generations)
                .expect("read unpublished generations directory")
                .next()
                .is_none(),
        "rejected snapshot must not leave a selectable immutable generation"
    );
}
#[test]
fn emergency_fast_manifest_decode_requires_canonical_v1_boundary() {
    let path = Path::new(SNAPSHOT_FAST_MANIFEST_FILE_NAME);
    let valid = EmergencyFastSnapshotManifestV1 {
        version: SNAPSHOT_FAST_MANIFEST_VERSION,
        payload_len: 4096,
        chain_id: ChainId::from(TEST_CHAIN_ID),
        network_id: snapshot_test_network_id(),
        committed_height: 1,
        tip_hash: Some(dummy_block_hash(0xA5)),
        sccp_policy_hash: [0x5A; 32],
    };
    let bytes = valid.encode();
    assert!(
        u64::try_from(bytes.len()).expect("manifest length fits u64")
            <= SNAPSHOT_FAST_MANIFEST_MAX_BYTES
    );
    assert_eq!(
        decode_emergency_fast_manifest(&bytes, path).expect("canonical V1 manifest"),
        valid
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert!(
        decode_emergency_fast_manifest(&trailing, path).is_err(),
        "trailing Norito bytes must fail exact decode"
    );

    let mut unsupported = valid.clone();
    unsupported.version = SNAPSHOT_FAST_MANIFEST_VERSION.saturating_add(1);
    assert!(decode_emergency_fast_manifest(&unsupported.encode(), path).is_err());

    let mut missing_tip = valid.clone();
    missing_tip.tip_hash = None;
    assert!(decode_emergency_fast_manifest(&missing_tip.encode(), path).is_err());

    let mut unexpected_tip = valid;
    unexpected_tip.committed_height = 0;
    assert!(decode_emergency_fast_manifest(&unexpected_tip.encode(), path).is_err());
}
#[tokio::test]
async fn bounded_snapshot_reader_rejects_oversized_regular_file() {
    let root = tempdir().expect("tempdir");
    let path = root.path().join("oversized");
    std::fs::write(&path, [0_u8; 9]).expect("write oversized fixture");
    let error = read_bounded_stable_regular_file(&path, 8)
        .expect_err("oversized snapshot artifact must fail before allocation");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
#[tokio::test]
async fn bounded_snapshot_reader_rechecks_the_opened_file_length() {
    let error = bounded_snapshot_read_capacity(9, 8)
        .expect_err("growth between path metadata and the opened descriptor must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
#[cfg(unix)]
#[tokio::test]
async fn authenticated_bound_payload_rejects_in_place_change_before_decode() {
    let root = tempdir().expect("tempdir");
    let path = root.path().join("snapshot.data");
    std::fs::write(&path, b"canonical").expect("write canonical payload");
    let binding = bind_snapshot_file_handle(&path, 9)
        .expect("bind canonical payload")
        .expect("payload exists");
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .and_then(|mut file| file.write_all(b"malicious"))
        .expect("replace bytes in the already-open inode");
    assert!(matches!(
        read_bound_snapshot_payload(&binding, &snapshot_read_budget_for_testing()),
        Err(TryReadError::SnapshotBindingChanged(changed)) if changed == path
    ));
}
#[cfg(unix)]
#[tokio::test]
async fn snapshot_bindings_reject_untrusted_unix_owner_or_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = tempdir().expect("tempdir");
    let directory = root.path().join("snapshot");
    std::fs::create_dir(&directory).expect("create snapshot directory");
    let metadata = std::fs::symlink_metadata(&directory).expect("snapshot directory metadata");
    let effective_uid = rustix::process::geteuid().as_raw();
    assert!(snapshot_unix_owner_and_mode_are_trusted(
        metadata.uid(),
        metadata.mode(),
        effective_uid
    ));
    assert!(!snapshot_unix_owner_and_mode_are_trusted(
        metadata.uid().wrapping_add(1),
        metadata.mode(),
        effective_uid
    ));
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770))
        .expect("make snapshot directory group-writable");
    assert!(matches!(
        direct_snapshot_directory_identity(&directory),
        Err(TryReadError::SnapshotGenerationInvalid { .. })
    ));
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("restore snapshot directory permissions");
    let artifact = directory.join("artifact");
    std::fs::write(&artifact, b"snapshot").expect("write snapshot artifact");
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o660))
        .expect("make snapshot artifact group-writable");
    let error = read_bounded_stable_regular_file(&artifact, 1024)
        .expect_err("group-writable snapshot artifact must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
#[cfg(unix)]
#[tokio::test]
async fn bounded_snapshot_reader_rejects_symlink_and_hardlink() {
    use std::os::unix::fs::symlink;
    let root = tempdir().expect("tempdir");
    let victim = root.path().join("victim");
    let symlink_path = root.path().join("symlink");
    let hardlink_path = root.path().join("hardlink");
    std::fs::write(&victim, b"sensitive victim bytes").expect("write victim");
    symlink(&victim, &symlink_path).expect("create symlink");
    std::fs::hard_link(&victim, &hardlink_path).expect("create hardlink");
    for path in [&symlink_path, &hardlink_path] {
        let error = read_bounded_stable_regular_file(path, 1024)
            .expect_err("linked snapshot artifact must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
    assert_eq!(
        std::fs::read(&victim).expect("read victim"),
        b"sensitive victim bytes"
    );
}
#[tokio::test]
async fn snapshot_publication_rejects_body_without_original_execution() {
    let kura = Kura::blank_kura_for_testing();
    let mut state = state_factory_with_kura(Arc::clone(&kura));
    let block = signed_block_with_transaction(accepted_log_transaction("unexecuted body"));
    store_block_and_mark_state_height(&mut state, &kura, block);
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let error = try_write_snapshot(
        &state,
        &store,
        &checked_random_snapshot_keypair(),
        TEST_CHUNK_SIZE,
    )
    .expect_err("a durable body cannot substitute for original native execution");
    assert!(matches!(error, TryWriteError::CommitEvidence { .. }));
    assert_snapshot_bundle_absent(&store);
    assert_eq!(kura.blocks_count(), 1);
}
#[tokio::test]
async fn snapshot_publication_rejects_foreign_captured_tip() {
    let mut chain = native_snapshot_chain();
    chain.commit_at(2_000, Vec::new());
    let original = CapturedStateSnapshot::capture(chain.state()).unwrap();
    let mut other = native_snapshot_chain();
    other.commit_at(3_000, Vec::new());
    let foreign = CapturedStateSnapshot::capture(other.state()).unwrap();
    let checkpoint = geometry_checkpoint_from_snapshot(foreign.json.as_bytes()).unwrap();
    assert!(matches!(
        ensure_snapshot_commit_evidence(chain.state(), &checkpoint, &original.identity),
        Err(TryWriteError::CommitEvidence { .. })
    ));
    assert_ne!(original.identity.native_tip, foreign.identity.native_tip);
}
#[tokio::test]
async fn snapshot_commit_evidence_refusal_retains_original_pool_and_captured_publication() {
    use crate::{
        execution_attempt::ExecutionAttemptError, sumeragi::certified_chain::CertifiedChain,
    };
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use iroha_data_model::block::SharedSignedBlock;
    use std::{
        future::Future as _,
        pin::pin,
        task::{Context, Waker},
    };

    let config =
        crate::sumeragi::test_chain::TestChainConfig::new(crate::state::World::new(), 1_000);
    let work_key = config.genesis_key.clone();
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("original signed native genesis");
    let genesis_wire_bytes = usize::try_from(
        chain
            .kura()
            .native_frame_read(1, chain.committed(1).block_hash())
            .unwrap()
            .unwrap()
            .wire_len(),
    )
    .unwrap();
    // Real signed work, rather than frame padding, makes the durable successor
    // larger than the original genesis. Canonical SignedBlockWire is uncompressed.
    let message_bytes = genesis_wire_bytes.checked_add(1).unwrap();
    let signed = chain.sign(
        &work_key,
        [Log::new(Level::INFO, "x".repeat(message_bytes)).into()],
        1_999,
    );
    assert_eq!(chain.commit_at(2_000, vec![signed.clone()]), vec![true]);
    let successor = chain.committed(2);
    assert_eq!(successor.block().network_entrypoint_count(), 1);
    assert_eq!(
        successor.block().network_entrypoint_at(0).unwrap(),
        &iroha_data_model::transaction::TransactionEntrypoint::External(signed)
    );
    drop(successor); // The cold evidence reader must own its separate original admission.
    let captured = CapturedStateSnapshot::capture(chain.state()).unwrap();
    let checkpoint = geometry_checkpoint_from_snapshot(captured.json.as_bytes()).unwrap();
    ensure_snapshot_commit_evidence(chain.state(), &checkpoint, &captured.identity).unwrap();
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let key = checked_random_snapshot_keypair();
    let budget = chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let layout = SharedSignedBlock::allocation_layout();
    // Cold reads physically admit the exact durable frame before its decoded shell.
    let frame_layout = |height: usize| {
        let source = chain
            .kura()
            .native_frame_read(height as u64, checkpoint.block_hashes[height - 1])
            .unwrap()
            .unwrap();
        std::alloc::Layout::array::<u8>(usize::try_from(source.wire_len()).unwrap()).unwrap()
    };
    let genesis_frame = frame_layout(1);
    let successor_frame = frame_layout(2);
    assert!(successor_frame.size() > genesis_frame.size());
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let original_tip = chain.state().latest_block_hash_fast();
    let original_frame = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(nonzero!(2_usize))
        .unwrap();
    for admitted_controls in [0, 1] {
        let occupied = budget
            .try_reserve_bytes(
                ceiling - baseline - admitted_controls * (genesis_frame.size() + layout.size()),
            )
            .unwrap();
        if admitted_controls == 1 {
            let original_reader = CertifiedChain::from_pinned(
                &captured.identity.chain_id,
                &captured.identity.network_id,
                &checkpoint.block_hashes,
                chain.kura(),
                &budget,
            )
            .expect("the exact prepaid frame and shared shell admit the original genesis reader");
            assert_eq!(budget.reserved_bytes(), ceiling - genesis_frame.size());
            assert!(matches!(
                original_reader.certified(2),
                Err(ExecutionAttemptError::Deferred(_))
            ));
            drop(original_reader);
        }
        let error = ensure_snapshot_commit_evidence(chain.state(), &checkpoint, &captured.identity)
            .expect_err("original evidence read must wait for its own finite pool");
        let TryWriteError::CommitEvidenceResourceDeferred { height, reason } = error else {
            panic!("resource refusal became bad snapshot evidence: {error:?}");
        };
        assert_eq!(height, 2);
        let Some(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = reason.allocation_refusal()
        else {
            panic!("exact original native-frame capacity refusal must survive");
        };
        assert_eq!(
            (*requested_bytes, *reserved_bytes, *limit_bytes),
            (
                if admitted_controls == 0 {
                    genesis_frame.size()
                } else {
                    successor_frame.size()
                },
                ceiling - admitted_controls * genesis_frame.size(),
                ceiling,
            )
        );
        let mut released = pin!(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(Waker::noop());
        if admitted_controls == 0 {
            assert!(released.as_mut().poll(&mut context).is_pending());
            let unrelated = AllocationBudget::new(layout.size());
            drop(unrelated.try_reserve(layout).unwrap());
            assert!(released.as_mut().poll(&mut context).is_pending());
        } else {
            // Dropping the admitted genesis reader refunds its exact original control.
            assert!(released.as_mut().poll(&mut context).is_ready());
        }
        assert!(matches!(
            try_write_snapshot(chain.state(), &store, &key, TEST_CHUNK_SIZE),
            Err(TryWriteError::CommitEvidenceResourceDeferred { height: 2, .. })
        ));
        assert_snapshot_bundle_absent(&store);
        assert_eq!(chain.state().latest_block_hash_fast(), original_tip);
        assert_eq!(
            chain
                .kura()
                .canonical_block_wire_bytes_for_testing(nonzero!(2_usize))
                .unwrap(),
            original_frame
        );
        captured
            .identity
            .validate_bytes(captured.json.as_bytes())
            .unwrap();
        drop(occupied);
        assert!(released.as_mut().poll(&mut context).is_ready());
        ensure_snapshot_commit_evidence(chain.state(), &checkpoint, &captured.identity).unwrap();
        assert_eq!(budget.reserved_bytes(), baseline);
    }
    try_write_snapshot(chain.state(), &store, &key, TEST_CHUNK_SIZE).unwrap();
    assert_canonical_snapshot_generation(&store);
    assert_eq!(
        std::fs::read(current_generation_artifact(&store, SNAPSHOT_FILE_NAME)).unwrap(),
        captured.json.as_bytes()
    );
    assert_eq!(chain.state().latest_block_hash_fast(), original_tip);
}

#[tokio::test]
async fn snapshot_publication_preserves_native_cut_and_requires_original_replay() {
    let mut chain = native_snapshot_chain();
    chain.commit(Vec::new());
    let state = chain.state();
    let root = tempdir().unwrap();
    let store = root.path().join("snapshot");
    let key = checked_random_snapshot_keypair();
    let before = exact_snapshot_payload_bytes(state);
    try_write_snapshot(state, &store, &key, TEST_CHUNK_SIZE).unwrap();
    assert_canonical_snapshot_generation(&store);
    assert_eq!(
        std::fs::read(current_generation_artifact(&store, SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    let budget = snapshot_read_budget_for_testing();
    assert!(matches!(
        strict_snapshot_read_for_custody_test(&store, state, chain.kura(), &key, &budget, &|_| Ok(
            ()
        )),
        Err(TryReadError::NativeExecutionReplayRequired)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(exact_snapshot_payload_bytes(state), before);
    assert_eq!(chain.kura().exact_durable_blocks_count().unwrap(), 2);
}
#[tokio::test]
async fn snapshot_fixture_key_generation_preserves_algorithm() {
    assert_eq!(
        checked_random_snapshot_keypair().public_key().algorithm(),
        Algorithm::default()
    );
    assert_eq!(
        checked_random_snapshot_bls_keypair()
            .public_key()
            .algorithm(),
        Algorithm::BlsNormal
    );
}
fn state_factory_with_kura_and_chain(kura: Arc<Kura>, chain_id: ChainId) -> State {
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::try_new_with_chain(
        crate::state::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        crate::queue::tests::world_with_test_domains(),
        Arc::clone(&kura),
        query_handle,
        chain_id,
        #[cfg(feature = "telemetry")]
        <_>::default(),
    )
    .expect("construct snapshot State before materializing configured storage");
    kura.bind_lane_storage_network(state.network_id)
        .expect("bind the exact snapshot fixture network before its geometry anchor");
    let (baseline, _, _) = kura
        .lane_geometry_journal_state_for_test()
        .expect("snapshot fixture has readable geometry custody");
    if let Some(baseline) = baseline {
        let lanes = state.nexus_snapshot().lane_config;
        let incarnation = state
            .lane_incarnation(lanes.primary().lane_id)
            .expect("snapshot primary has a canonical incarnation");
        kura.establish_or_verify_configured_primary_geometry_anchor(
            lanes.primary(),
            incarnation,
            baseline,
        )
        .expect("snapshot fixture anchors its configured primary geometry");
    }
    state.install_active_lane_markers_for_tests();
    state.configure_test_runtime_defaults();
    state
}
fn state_factory_with_kura(kura: Arc<Kura>) -> State {
    state_factory_with_kura_and_chain(kura, ChainId::from(TEST_CHAIN_ID))
}
fn state_factory() -> State {
    state_factory_with_kura(Kura::blank_kura_for_testing())
}
fn kura_config_for_snapshot_test(store_dir: &Path, blocks_in_memory: NonZeroUsize) -> KuraConfig {
    KuraConfig {
        init_mode: iroha_config::kura::InitMode::Strict,
        store_dir: WithOrigin::inline(store_dir.to_path_buf()),
        max_disk_usage_bytes: MAX_DISK_USAGE_BYTES,
        blocks_in_memory,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: FSYNC_INTERVAL,
        native_context_archive_max_bytes:
            iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        history_checkpoint_cache_capacity:
            iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
    }
}
fn install_active_space_directory_manifest(
    state: &mut State,
) -> (UniversalAccountId, DataSpaceId, AccountId) {
    let uaid = UniversalAccountId::from_hash(Hash::new(b"snapshot-space-directory"));
    let dataspace = DataSpaceId::new(7);
    let account_id = AccountId::new(checked_random_snapshot_keypair().public_key().clone());
    let details = AccountDetails::new(Metadata::default(), None, Some(uaid), Vec::new());
    state
        .world
        .accounts
        .insert(account_id.clone(), AccountValue::new(details));
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::default(),
        uaid,
        dataspace,
        issued_ms: 1,
        activation_epoch: 1,
        expiry_epoch: None,
        entries: Vec::new(),
    };
    let mut record = crate::nexus::space_directory::SpaceDirectoryManifestRecord::new(manifest);
    record.lifecycle.mark_activated(1);
    let mut set = crate::nexus::space_directory::SpaceDirectoryManifestSet::default();
    set.upsert(record);
    state.world.space_directory_manifests.insert(uaid, set);
    (uaid, dataspace, account_id)
}
fn resource_policy(
    max_decode_depth: usize,
    max_decode_items: usize,
    max_string_bytes: usize,
    max_blob_bytes: usize,
    max_transient_bytes: usize,
) -> SnapshotResourcePolicy {
    SnapshotResourcePolicy {
        max_decode_depth: NonZeroUsize::new(max_decode_depth).expect("non-zero depth"),
        max_decode_items: NonZeroUsize::new(max_decode_items).expect("non-zero item limit"),
        max_string_bytes: NonZeroUsize::new(max_string_bytes).expect("non-zero string limit"),
        max_blob_bytes: NonZeroUsize::new(max_blob_bytes).expect("non-zero blob limit"),
        max_transient_bytes: NonZeroUsize::new(max_transient_bytes)
            .expect("non-zero transient limit"),
    }
}
#[tokio::test]
async fn snapshot_json_scanner_enforces_every_resource_budget() {
    assert_eq!(
        count_borrowed_json_array_items("[0,{\"nested\":true},[]]")
            .expect("borrowed array item count"),
        3
    );
    let generous = usize::MAX / 4;
    let cases = [
        (
            b"[[0]]".as_slice(),
            resource_policy(2, generous, generous, generous, generous),
            "nesting depth",
        ),
        (
            b"[0,1]".as_slice(),
            resource_policy(8, 1, generous, generous, generous),
            "aggregate items",
        ),
        (
            br#""four""#.as_slice(),
            resource_policy(8, generous, 3, generous, generous),
            "JSON string",
        ),
        (
            br#"{"encoded_hex":"000102030405060708090a0b0c"}"#.as_slice(),
            resource_policy(8, generous, 12, 12, generous),
            "decoded blob",
        ),
        (
            b"[0,1,2,3,4,5,6,7,8,9,10,11,12]".as_slice(),
            resource_policy(8, generous, 12, 12, generous),
            "byte-vector blobs",
        ),
        (
            b"[0]".as_slice(),
            resource_policy(8, generous, generous, generous, 1),
            "transient estimate",
        ),
    ];
    for (payload, policy, expected) in cases {
        let error = validate_snapshot_json_resources(payload, policy)
            .expect_err("payload must exceed its configured resource budget");
        match error {
            TryReadError::SnapshotResourceLimit(message) => {
                assert!(
                    message.contains(expected),
                    "unexpected resource error: {message}"
                );
            }
            other => panic!("unexpected resource rejection: {other:?}"),
        }
    }
}
#[tokio::test]
async fn snapshot_json_scanner_rejects_noncanonical_spelling() {
    let policy = SnapshotResourcePolicy::default();
    for payload in [b"{ \"a\":0}".as_slice(), br#""\u0061""#.as_slice()] {
        assert!(matches!(
            validate_snapshot_json_resources(payload, policy),
            Err(TryReadError::NonCanonicalSnapshotPayload)
        ));
    }
}
#[tokio::test]
async fn borrowed_snapshot_wsv_hash_matches_typed_canonical_surface() {
    let state = state_factory();
    let payload = exact_snapshot_payload_bytes(&state);
    validate_snapshot_json_resources(&payload, SnapshotResourcePolicy::default())
        .expect("generated snapshot must satisfy the default resource policy");
    let tree_reference = Hash::new(canonical_state_snapshot_bytes(&state));
    assert_eq!(
        canonical_snapshot_wsv_hash(&payload).expect("borrowed canonical WSV hash"),
        tree_reference,
    );
    assert_eq!(
        canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"),
        tree_reference
    );
}
#[test]
fn staged_and_committed_wsv_hashes_commit_consensus_evidence() {
    let state = state_factory();
    let committed_without_evidence =
        canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot");
    let staged = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    assert_eq!(
        canonical_staged_state_snapshot_hash(&staged),
        committed_without_evidence,
        "an unchanged evidence table must preserve staged and committed WSV parity"
    );
    drop(staged);

    let (evidence, attribution) = snapshot_evidence_fixture(*state.network_id_ref());
    let evidence_key = crate::sumeragi::evidence::evidence_key(&evidence);
    let mut staged = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    staged.world.consensus_evidence.insert(
        evidence_key,
        crate::state::RetainedEvidenceRecord::from_fixture(
            EvidenceRecord {
                evidence,
                attribution,
                recorded_at_height: 2,
                recorded_at_view: 0,
                recorded_at_ms: 2_000,
                penalty_status: EvidencePenaltyStatus::Pending,
            },
            &state.ivm_execution_budget(),
        )
        .unwrap(),
    );
    let staged_with_evidence = canonical_staged_state_snapshot_hash(&staged);
    assert_ne!(
        staged_with_evidence, committed_without_evidence,
        "consensus-owned evidence must change the canonical WSV hash"
    );
    staged
        .commit_world_overlay_for_testing()
        .expect("commit the consensus evidence overlay");
    assert_eq!(
        staged_with_evidence,
        canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"),
        "consensus evidence must have identical staged and committed WSV hashes"
    );
}
#[tokio::test]
async fn borrowed_snapshot_wsv_hash_canonicalizes_json_lexemes() {
    let lexical = br#"{"\u0077orld":{"note":"\u0061","number":1e0}}"#;
    let canonical = br#"{"world":{"note":"a","number":1.0}}"#;
    assert_eq!(
        canonical_snapshot_wsv_hash(lexical).expect("hash lexical snapshot spelling"),
        Hash::new(canonical),
    );
}

#[tokio::test]
async fn staged_snapshot_wsv_hash_injects_committed_event_buffer() {
    let staged = br#"{"world":{"accounts":{}}}"#;
    let committed_event_buffer = r#"{"revert":{},"blocks":[]}"#;
    let canonical = br#"{"world":{"accounts":{},"external_event_buf":[]}}"#;
    assert_eq!(
        canonical_snapshot_wsv_hash_with_overrides(
            staged,
            CanonicalWsvOverrides {
                committed_external_event_buf: Some(committed_event_buffer),
                ..CanonicalWsvOverrides::default()
            },
        )
        .expect("hash staged snapshot with its committed event buffer"),
        Hash::new(canonical),
    );
}

#[tokio::test]
async fn staged_snapshot_wsv_hash_projects_deferred_storage_and_undo_history() {
    let staged = br#"{"world":{"axt_replay_ledger":{"blocks":{"expired":1},"revert":{}},"smart_contract_state":{"blocks":{"quota":[1]},"revert":{}}},"other":{"axt_replay_ledger":{"keep":true}}}"#;
    let replay = r#"{"revert":{"expired":{"value":1}},"blocks":{}}"#;
    let quota = r#"{"revert":{"quota":{"value":[1]}},"blocks":{"quota":[2]}}"#;
    // Independently spelled canonical bytes also prove that the override is
    // restricted to the exact World field, and keeps storage undo history.
    let canonical = br#"{"other":{"axt_replay_ledger":{"keep":true}},"world":{"axt_replay_ledger":{"blocks":{},"revert":{"expired":{"value":1}}},"smart_contract_state":{"blocks":{"quota":[2]},"revert":{"quota":{"value":[1]}}}}}"#;
    let actual = canonical_snapshot_wsv_hash_with_overrides(
        staged,
        CanonicalWsvOverrides {
            committed_axt_replay_ledger: Some(replay),
            committed_smart_contract_state: Some(quota),
            ..CanonicalWsvOverrides::default()
        },
    )
    .expect("hash exact deferred storage projections");
    assert_eq!(actual, Hash::new(canonical));
    assert_ne!(
        actual,
        canonical_snapshot_wsv_hash(staged).expect("hash unprojected state")
    );
    assert_ne!(
        actual,
        canonical_snapshot_wsv_hash_with_overrides(
            staged,
            CanonicalWsvOverrides {
                committed_axt_replay_ledger: Some(r#"{"blocks":{},"revert":{}}"#),
                committed_smart_contract_state: Some(quota),
                ..CanonicalWsvOverrides::default()
            },
        )
        .expect("hash a projection missing the required undo history"),
    );
}

#[tokio::test]
async fn staged_snapshot_wsv_hash_commits_consensus_evidence() {
    for evidence in [
        None,
        Some(snapshot_evidence_fixture(snapshot_test_network_id())),
    ] {
        let state = State::new_with_chain_and_network_id_for_testing(
            crate::state::World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            ChainId::from(TEST_CHAIN_ID),
            snapshot_test_network_id(),
        );
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero test height"),
            None,
            None,
            1_000,
            0,
        );
        let mut state_block = state.block(header);
        if let Some((evidence, attribution)) = evidence {
            let key = crate::sumeragi::evidence::evidence_key(&evidence);
            state_block.world.consensus_evidence.insert(
                key,
                crate::state::RetainedEvidenceRecord::from_fixture(
                    EvidenceRecord {
                        evidence,
                        attribution,
                        recorded_at_height: 1,
                        recorded_at_view: 0,
                        recorded_at_ms: 1_000,
                        penalty_status: EvidencePenaltyStatus::Pending,
                    },
                    &state.ivm_execution_budget(),
                )
                .unwrap(),
            );
        }
        let staged_hash = canonical_staged_state_snapshot_hash(&state_block);
        state_block
            .commit_world_overlay_for_testing()
            .expect("commit consensus-evidence world overlay");
        assert_eq!(
            staged_hash,
            canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"),
            "empty and populated consensus evidence must have identical staged and committed WSV projections",
        );
    }
}

#[tokio::test]
async fn canonical_wsv_hash_uses_current_mv_cell_values() {
    let state = state_factory();
    let before = canonical_state_snapshot_bytes_for_tests(&state);
    {
        let mut parameters = state.world.parameters.block();
        let current = parameters.get().clone();
        *parameters.get_mut() = current;
        parameters.commit();
    }
    let after = canonical_state_snapshot_bytes_for_tests(&state);
    assert_eq!(
        before, after,
        "MV cell history must not affect replay WSV checkpoints when the current value is unchanged"
    );
    assert_eq!(
        canonical_snapshot_wsv_hash(&exact_snapshot_payload_bytes(&state))
            .expect("borrowed WSV hashing must unwrap MV cells"),
        Hash::new(&after),
    );
    let value = canonical_state_snapshot_value(&state);
    let parameters = value
        .get("world")
        .and_then(|world| world.get("parameters"))
        .and_then(json::Value::as_object)
        .expect("canonical snapshot should contain parameters as a plain object");
    assert!(
        !parameters.contains_key("revert") && !parameters.contains_key("blocks"),
        "canonical WSV checkpoint surface should serialize current cell values"
    );
}
#[tokio::test]
async fn canonical_wsv_hash_sorts_sumeragi_key_algorithm_set() {
    let state = state_factory();
    {
        let mut parameters = state.world.parameters.block();
        parameters.sumeragi.key_allowed_algorithms = vec![
            Algorithm::Secp256k1,
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
        ];
        parameters.commit();
    }
    let first = canonical_state_snapshot_bytes_for_tests(&state);
    let first_payload = exact_snapshot_payload_bytes(&state);
    assert_eq!(
        canonical_snapshot_wsv_hash(&first_payload)
            .expect("borrowed WSV hashing must canonicalize set-like key policy fields"),
        Hash::new(&first),
    );
    {
        let mut parameters = state.world.parameters.block();
        parameters.sumeragi.key_allowed_algorithms = vec![Algorithm::Ed25519, Algorithm::Secp256k1];
        parameters.commit();
    }
    let second = canonical_state_snapshot_bytes_for_tests(&state);
    let second_payload = exact_snapshot_payload_bytes(&state);
    assert_eq!(
        canonical_snapshot_wsv_hash(&second_payload)
            .expect("borrowed WSV hashing must preserve canonical key policy sets"),
        Hash::new(&second),
    );
    assert_eq!(
        first, second,
        "the set-like Sumeragi key algorithm field must not make WSV checkpoints order-sensitive"
    );
}
#[tokio::test]
async fn canonical_state_snapshot_ignores_consensus_topology_caches() {
    let state = state_factory();
    let expected = canonical_state_snapshot_bytes_for_tests(&state);
    let keypair = checked_random_snapshot_bls_keypair();
    let peer = PeerId::new(keypair.public_key().clone());
    {
        let mut commit_topology = state.commit_topology.block();
        commit_topology.push(peer.clone());
        commit_topology.commit();
    }
    {
        let mut prev_commit_topology = state.prev_commit_topology.block();
        prev_commit_topology.push(peer);
        prev_commit_topology.commit();
    }
    assert_eq!(
        canonical_state_snapshot_bytes_for_tests(&state),
        expected,
        "consensus topology caches must not perturb canonical replay checkpoints"
    );
}
fn sample_space_directory_manifest() -> AssetPermissionManifest {
    AssetPermissionManifest {
        version: ManifestVersion::default(),
        uaid: UniversalAccountId::from_hash(Hash::new(b"snapshot-legacy-manifest")),
        dataspace: DataSpaceId::new(11),
        issued_ms: 1,
        activation_epoch: 1,
        expiry_epoch: None,
        entries: Vec::new(),
    }
}
fn insert_account_with_uaid(state: &mut State, uaid: UniversalAccountId) -> AccountId {
    let account_id = AccountId::new(checked_random_snapshot_keypair().public_key().clone());
    let details = AccountDetails::new(Metadata::default(), None, Some(uaid), Vec::new());
    state
        .world
        .accounts
        .insert(account_id.clone(), AccountValue::new(details));
    account_id
}
fn accepted_manifest_transaction() -> AcceptedTransaction<'static> {
    let key_pair = checked_seeded_keypair(0x31, Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let transaction = TransactionBuilder::new(
        snapshot_test_network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([PublishSpaceDirectoryManifest {
        manifest: sample_space_directory_manifest(),
    }])
    .sign(key_pair.private_key());
    AcceptedTransaction::new_unchecked(Cow::Owned(transaction))
}
fn accepted_log_transaction(message: &str) -> AcceptedTransaction<'static> {
    let key_pair = checked_seeded_keypair(0x32, Algorithm::Ed25519);
    let authority = AccountId::new(key_pair.public_key().clone());
    let transaction = TransactionBuilder::new(
        snapshot_test_network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, message.to_owned())])
    .sign(key_pair.private_key());
    AcceptedTransaction::new_unchecked(Cow::Owned(transaction))
}
fn signed_block_with_transaction(
    transaction: AcceptedTransaction<'static>,
) -> iroha_data_model::block::SharedSignedBlock {
    signed_block_after_transaction(transaction, None)
}
fn signed_block_after_transaction(
    transaction: AcceptedTransaction<'static>,
    latest_block: Option<&SignedBlock>,
) -> iroha_data_model::block::SharedSignedBlock {
    let block_signer = checked_seeded_keypair(0x33, Algorithm::BlsNormal);
    iroha_data_model::block::SharedSignedBlock::try_new(
        BlockBuilder::new(vec![transaction])
            .chain(0, latest_block)
            .sign(block_signer.private_key())
            .unpack(|_| {})
            .into(),
        &crate::state::AllocationBudget::new(
            iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
        ),
    )
    .expect("admit structural snapshot fixture block")
}
/// Apply hostile fixture changes without changing unrelated signed schema ordering.
fn snapshot_json_with_mutation(original: &str, mutated: &json::Value) -> String {
    let baseline: json::Value = json::from_str(original).expect("valid snapshot JSON template");
    if &baseline == mutated {
        return original.to_owned();
    }
    match (&baseline, mutated) {
        (json::Value::Object(_), json::Value::Object(changes)) => {
            let members = borrowed_json_object_members(original).expect("snapshot object members");
            let mut fields = Vec::new();
            for member in &members {
                if let Some(value) = changes.get(&member.key) {
                    fields.push(format!(
                        "{}:{}",
                        member.encoded_key,
                        snapshot_json_with_mutation(member.value, value)
                    ));
                }
            }
            for (key, value) in changes {
                if !members.iter().any(|member| &member.key == key) {
                    fields.push(format!(
                        "{}:{}",
                        json::to_json(key).expect("JSON field name"),
                        json::to_json(value).expect("new JSON fixture field")
                    ));
                }
            }
            format!("{{{}}}", fields.join(","))
        }
        (json::Value::Array(_), json::Value::Array(changes)) => {
            let items = borrowed_json_array_items(original).expect("snapshot array items");
            let items: Vec<_> = changes
                .iter()
                .enumerate()
                .map(|(index, value)| match items.get(index) {
                    Some(original) => snapshot_json_with_mutation(original, value),
                    None => json::to_json(value).expect("new JSON fixture item"),
                })
                .collect();
            format!("[{}]", items.join(","))
        }
        _ => json::to_json(mutated).expect("mutated JSON fixture value"),
    }
}
#[test]
fn snapshot_mutation_preserves_schema_order_and_changes_only_requested_fields() {
    let original = r#"{"z":{"later":1,"earlier":2},"a":[{"y":3,"b":4}]}"#;
    let mut value: json::Value = json::from_str(original).expect("ordered JSON fixture");
    value
        .as_object_mut()
        .unwrap()
        .get_mut("z")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("later".to_owned(), json::Value::from(5_u64));
    assert_eq!(
        snapshot_json_with_mutation(original, &value),
        r#"{"z":{"later":5,"earlier":2},"a":[{"y":3,"b":4}]}"#
    );
}
fn exact_snapshot_payload_bytes(state: &State) -> Vec<u8> {
    let payload = CapturedStateSnapshot::capture(state)
        .expect("stable valid fixture snapshot")
        .json;
    payload.into_bytes()
}
fn snapshot_payload_without_space_directory_manifest_section(state: &State) -> Vec<u8> {
    let mut snapshot: json::Value = json::from_slice(&exact_snapshot_payload_bytes(state))
        .expect("first-release snapshot must be canonical JSON");
    snapshot
        .as_object_mut()
        .expect("first-release snapshot must be an object")
        .remove("space_directory_manifests")
        .expect("first-release snapshot must carry Space Directory manifests");
    json::to_json(&snapshot)
        .expect("missing-section rejection fixture must remain valid JSON")
        .into_bytes()
}
fn publish_test_snapshot_generation(
    store_dir: &std::path::Path,
    bytes: &[u8],
    key_pair: &KeyPair,
) -> (StableSnapshotFileIdentity, PublishedSnapshotGeneration) {
    std::fs::create_dir_all(store_dir).expect("snapshot dir");
    let digest_bytes: [u8; 32] = Sha256::digest(bytes).into();
    let digest_vec = digest_bytes.to_vec();
    let digest_hex = hex::encode(&digest_vec);
    let digest_line = format!("{digest_hex}\n").into_bytes();
    let payload_len = u64::try_from(bytes.len()).expect("snapshot length fits u64");
    let fast_manifest = match geometry_checkpoint_from_snapshot(bytes) {
        Ok(checkpoint) => EmergencyFastSnapshotManifestV1 {
            version: SNAPSHOT_FAST_MANIFEST_VERSION,
            payload_len,
            chain_id: checkpoint.chain_id,
            network_id: checkpoint.network_id,
            committed_height: checkpoint.height,
            tip_hash: checkpoint.block_hash,
            sccp_policy_hash: checkpoint.sccp_policy_hash,
        },
        Err(_) => EmergencyFastSnapshotManifestV1 {
            version: SNAPSHOT_FAST_MANIFEST_VERSION,
            payload_len,
            chain_id: ChainId::from(TEST_CHAIN_ID),
            network_id: snapshot_test_network_id(),
            committed_height: 0,
            tip_hash: None,
            sccp_policy_hash: [0; 32],
        },
    };
    let fast_manifest_bytes = fast_manifest.encode();
    let bundle_digest = snapshot_bundle_auth_digest(&digest_bytes, &fast_manifest_bytes);
    let signature = Signature::try_new(key_pair.private_key(), &bundle_digest)
        .expect("checked snapshot signature");
    let signature_hex = hex::encode(signature.payload()).into_bytes();
    let merkle = SnapshotMerkleMetadata::from_bytes(bytes, TEST_CHUNK_SIZE);
    let merkle_bytes = json::to_json(&merkle)
        .expect("canonical snapshot merkle")
        .into_bytes();
    let merkle_limit = SNAPSHOT_MERKLE_FIXED_OVERHEAD_BYTES.saturating_add(
        u64::try_from(merkle.leaf_hashes_hex.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(SNAPSHOT_MERKLE_BYTES_PER_LEAF),
    );
    let store_identity = direct_snapshot_directory_identity(store_dir).expect("bind snapshot root");
    let generation = publish_immutable_snapshot_generation(
        store_dir,
        store_identity,
        &digest_hex,
        bytes,
        &digest_line,
        &signature_hex,
        &fast_manifest_bytes,
        &merkle_bytes,
        merkle_limit,
        key_pair.public_key(),
    )
    .expect("publish immutable test generation");
    (store_identity, generation)
}
pub(super) fn write_snapshot_bundle_from_bytes(
    store_dir: &std::path::Path,
    bytes: &[u8],
    key_pair: &KeyPair,
) {
    let (store_identity, generation) = publish_test_snapshot_generation(store_dir, bytes, key_pair);
    publish_snapshot_current_pointer(
        store_dir,
        store_identity,
        &generation,
        defaults::snapshot::MAX_PAYLOAD_BYTES,
        TEST_CHUNK_SIZE,
        key_pair.public_key(),
        &snapshot_read_budget_for_testing(),
    )
    .expect("publish canonical test pointer");
}
fn store_block_and_mark_state_height(
    state: &mut State,
    kura: &Arc<Kura>,
    block: iroha_data_model::block::SharedSignedBlock,
) {
    kura.store_block(block.clone()).expect("store block");
    state.push_block_hash_for_testing(block.hash());
    seed_snapshot_genesis_resolver_checkpoint(&state);
}

/// Direct block fixtures retain the resolver anchor required of every committed state.
fn seed_snapshot_genesis_resolver_checkpoint(state: &State) {
    let genesis_hash = state
        .block_hashes
        .view()
        .iter()
        .next()
        .copied()
        .expect("committed snapshot fixture has a genesis hash");
    let revision = crate::state::MusubiResolverIndexRevisionV1::default();
    let checkpoint = iroha_data_model::musubi::MusubiRegistrySnapshotV1 {
        finalized_height: 1,
        finalized_block_hash: *genesis_hash.as_ref(),
        index_revision: revision.get(),
    };
    checkpoint
        .validate()
        .expect("canonical resolver genesis checkpoint");
    let mut world = state.world.block();
    if let Some(existing) = world.musubi_resolver_index_checkpoints.get(&revision) {
        assert_eq!(existing, &checkpoint);
    } else {
        world
            .musubi_resolver_index_checkpoints
            .insert(revision, checkpoint);
    }
    world.commit();
}

fn snapshot_read_budget_for_testing() -> AllocationBudget {
    AllocationBudget::new(iroha_config::parameters::defaults::snapshot::MAX_READ_BUFFER_BYTES.get())
}
