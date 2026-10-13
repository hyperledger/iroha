use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{GovernanceProposalRecord, State, StateReadOnly, World},
};
use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use mv::cell::Cell;
const GOVERNANCE_EXECUTION_HEIGHT: u64 = 42;
fn location_fixture(
    archive_byte: u8,
    pin: iroha_data_model::sorafs::pin_registry::ManifestDigest,
    order: iroha_data_model::sorafs::pin_registry::ReplicationOrderId,
) -> MusubiArchiveLocationV1 {
    MusubiArchiveLocationV1 {
        location_id: MusubiArchiveLocationIdV1::new([archive_byte; 32]),
        archive_id: ArchiveId::new([archive_byte; 32]),
        pin_manifest: pin,
        replication_order: order,
        providers: Vec::new(),
        provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1::new(
            [archive_byte.wrapping_add(1); 32],
        ),
        renew_after_epoch: 1,
        expires_at_epoch: 2,
        finalized_height: 1,
        revision: 1,
        state: MusubiArchiveLocationStateV1::Healthy,
    }
}
fn account(seed: u8) -> AccountId {
    let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("fixture seed derives an account");
    AccountId::new(keypair.public_key().clone())
}
#[cfg(feature = "telemetry")]
fn governance_rejection_counts(
    metrics: &crate::telemetry::Metrics,
    action: &str,
    reason: &str,
) -> (u64, u64) {
    let exposition = metrics.try_to_string().expect("encode metrics");
    let action_label = format!("action=\"{action}\"");
    let reason_label = format!("reason=\"{reason}\"");
    exposition
        .lines()
        .filter(|line| line.starts_with("musubi_governance_rejections_total{"))
        .fold((0_u64, 0_u64), |(total, exact), line| {
            let (labels, value) = line
                .rsplit_once(' ')
                .expect("Prometheus counter sample has a value");
            let value = value.parse::<u64>().expect("counter sample is an integer");
            let exact = if labels.contains(&action_label) && labels.contains(&reason_label) {
                exact + value
            } else {
                exact
            };
            (total + value, exact)
        })
}
#[cfg(feature = "telemetry")]
#[test]
fn governance_rejections_are_counted_once_at_the_authoritative_isi_boundary() {
    use std::sync::Arc;
    let metrics = Arc::new(crate::telemetry::Metrics::default());
    let telemetry = crate::telemetry::StateTelemetry::new(Arc::clone(&metrics), true);
    let state = State::with_telemetry(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        telemetry,
    );
    let before_unauthorized = governance_rejection_counts(&metrics, "remove", "unauthorized");
    let before_stale = governance_rejection_counts(&metrics, "remove", "stale_revision");
    let before_last_owner = governance_rejection_counts(&metrics, "remove", "last_owner");
    {
        let header = iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).expect("nonzero block height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let owner = account(11);
        let stranger = account(12);
        let package = package("telemetry-last-owner");
        seed_package_owner(&package, &owner, 1, &mut transaction);
        let remove = |expected_governance_revision| RemoveMusubiPackageMaintainerV1 {
            package: package.clone(),
            account: owner.clone(),
            expected_governance_revision,
        };
        remove(1)
            .execute(&stranger, &mut transaction)
            .expect_err("a non-owner must be rejected");
        remove(2)
            .execute(&owner, &mut transaction)
            .expect_err("a stale governance revision must be rejected");
        let error = remove(1)
            .execute(&owner, &mut transaction)
            .expect_err("the sole owner cannot be removed");
        assert!(error.to_string().contains("retain its last owner"));
    }
    let after_unauthorized = governance_rejection_counts(&metrics, "remove", "unauthorized");
    let after_stale = governance_rejection_counts(&metrics, "remove", "stale_revision");
    let after_last_owner = governance_rejection_counts(&metrics, "remove", "last_owner");
    assert_eq!(after_unauthorized.1, before_unauthorized.1 + 1);
    assert_eq!(after_stale.1, before_stale.1 + 1);
    assert_eq!(after_last_owner.1, before_last_owner.1 + 1);
    assert_eq!(after_last_owner.0, before_last_owner.0 + 3);
}
#[test]
fn publication_snapshot_accepts_a_canonical_finalized_ancestor() {
    let snapshot = MusubiRegistrySnapshotV1 {
        finalized_height: 2,
        finalized_block_hash: [0x22; 32],
        index_revision: 7,
    };
    validate_publication_snapshot_anchor(&snapshot, 5, Some([0x22; 32]), 9)
        .expect("a canonical ancestor remains valid while publication evidence finalizes");
}
#[test]
fn publication_snapshot_rejects_future_or_noncanonical_anchors() {
    let snapshot = MusubiRegistrySnapshotV1 {
        finalized_height: 3,
        finalized_block_hash: [0x33; 32],
        index_revision: 4,
    };
    assert!(validate_publication_snapshot_anchor(&snapshot, 2, Some([0x33; 32]), 4).is_err());
    assert!(validate_publication_snapshot_anchor(&snapshot, 3, Some([0x44; 32]), 4).is_err());
    assert!(validate_publication_snapshot_anchor(&snapshot, 3, Some([0x33; 32]), 3).is_err());
}
fn canonical_block_hashes(count: u8) -> Vec<HashOf<BlockHeader>> {
    (1..=count)
        .map(|byte| HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([byte; 32])))
        .collect()
}
#[test]
fn publication_snapshot_requires_its_exact_revision_activation_interval() {
    let block_hashes = canonical_block_hashes(9);
    // The typed hash applies its canonical marker bit. Snapshot anchors must
    // use those exact bytes, including at even-numbered activation heights.
    let hash_at = |height: usize| *block_hashes[height - 1].as_ref();
    let mut world = World::new();
    world.musubi_resolver_index_checkpoints.insert(
        MusubiResolverIndexRevisionV1::new(1).expect("genesis revision"),
        MusubiRegistrySnapshotV1 {
            finalized_height: 1,
            finalized_block_hash: hash_at(1),
            index_revision: 1,
        },
    );
    world.musubi_resolver_index_checkpoints.insert(
        MusubiResolverIndexRevisionV1::new(7).expect("revision seven"),
        MusubiRegistrySnapshotV1 {
            finalized_height: 2,
            finalized_block_hash: hash_at(2),
            index_revision: 7,
        },
    );
    world.musubi_resolver_index_checkpoints.insert(
        MusubiResolverIndexRevisionV1::new(9).expect("revision nine"),
        MusubiRegistrySnapshotV1 {
            finalized_height: 6,
            finalized_block_hash: hash_at(6),
            index_revision: 9,
        },
    );
    world.musubi_resolver_index_revision =
        Cell::new(MusubiResolverIndexRevisionV1::new(9).expect("revision nine"));
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    {
        let mut committed_hashes = state.block_hashes.block();
        for hash in &block_hashes {
            committed_hashes.push_for_tests(*hash);
        }
        committed_hashes.commit_for_tests();
    }
    let view = state.query_view();
    validate_musubi_registry_snapshot_history_v1(
        &MusubiRegistrySnapshotV1 {
            finalized_height: 5,
            finalized_block_hash: hash_at(5),
            index_revision: 7,
        },
        &view,
    )
    .expect("an unchanged block inside revision seven's activation interval is valid");
    let wrong_hash = MusubiRegistrySnapshotV1 {
        finalized_height: 5,
        finalized_block_hash: [0xFF; 32],
        index_revision: 7,
    };
    assert!(validate_musubi_registry_snapshot_history_v1(&wrong_hash, &view).is_err());
    let future_height = MusubiRegistrySnapshotV1 {
        finalized_height: 10,
        finalized_block_hash: [10; 32],
        index_revision: 7,
    };
    assert!(validate_musubi_registry_snapshot_history_v1(&future_height, &view).is_err());
    let future_revision = MusubiRegistrySnapshotV1 {
        finalized_height: 5,
        finalized_block_hash: hash_at(5),
        index_revision: 10,
    };
    assert!(validate_musubi_registry_snapshot_history_v1(&future_revision, &view).is_err());
    let predates_activation = MusubiRegistrySnapshotV1 {
        finalized_height: 1,
        finalized_block_hash: hash_at(1),
        index_revision: 7,
    };
    assert!(validate_musubi_registry_snapshot_history_v1(&predates_activation, &view).is_err());
    let successor_already_active = MusubiRegistrySnapshotV1 {
        finalized_height: 6,
        finalized_block_hash: hash_at(6),
        index_revision: 7,
    };
    assert!(
        validate_musubi_registry_snapshot_history_v1(&successor_already_active, &view).is_err()
    );
    let skipped_same_block_revision = MusubiRegistrySnapshotV1 {
        finalized_height: 5,
        finalized_block_hash: hash_at(5),
        index_revision: 8,
    };
    let error = validate_musubi_registry_snapshot_history_v1(&skipped_same_block_revision, &view)
        .expect_err("an intra-block revision without a checkpoint cannot be claimed");
    assert!(
        error
            .to_string()
            .contains("unrecorded resolver-index revision")
    );
}
#[test]
fn publication_resolution_binds_rows_and_selection_state_to_snapshot() {
    let root_release = MusubiReleaseIdV1::new(
        package("snapshot-root"),
        "1.0.0".parse().expect("root version"),
    );
    let dependency_release = MusubiReleaseIdV1::new(
        package("snapshot-dependency"),
        "1.2.0".parse().expect("dependency version"),
    );
    let requirement: MusubiVersionReqV1 = "^1.0.0".parse().expect("requirement");
    let edge = MusubiExactDependencyEdgeV1 {
        alias: "dependency".parse().expect("dependency alias"),
        kind: MusubiDependencyKindV1::Normal,
        package: dependency_release.package.clone(),
        requirement: requirement.clone(),
        selected: dependency_release.clone(),
    };
    let archive_id = ArchiveId::new([0x61; 32]);
    let node = MusubiVerificationNodeV1 {
        release: dependency_release.clone(),
        release_digest: MusubiReleaseDigestV1::new([0x62; 32]),
        archive_id,
        source_digest: MusubiContentDigestV1::new([0x63; 32]),
        interface_digest: MusubiContentDigestV1::new([0x64; 32]),
        abi: MusubiAbiBindingV1::new([0x65; 32]).expect("dependency ABI"),
        dependencies: Vec::new(),
    };
    let lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: MUSUBI_REGISTRY_VERSION_V1,
        root: root_release.clone(),
        root_dependencies: vec![edge],
        nodes: vec![node.clone()],
    };
    let publication = MusubiPublicationV1 {
        manifest: MusubiReleaseManifestV1 {
            release: root_release,
            edition: MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([0x66; 32]).expect("root ABI"),
            dependencies: vec![MusubiDependencyReqV1 {
                alias: "dependency".parse().expect("dependency alias"),
                package: dependency_release.package.clone(),
                requirement,
            }],
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([0x67; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            archive_id: ArchiveId::new([0x68; 32]),
            verification_lock_digest: lock.digest(),
        },
        resolution: MusubiResolutionProofV1 {
            snapshot: snapshot(7),
            lock,
        },
    };
    publication.validate().expect("valid exact proof fixture");
    let row = MusubiResolverReleaseRowV1 {
        release: dependency_release.clone(),
        release_digest: node.release_digest,
        archive_id,
        source_digest: node.source_digest,
        interface_digest: node.interface_digest,
        abi: node.abi,
        dependencies: Vec::new(),
        selection: MusubiReleaseSelectionStateV1 {
            yank: MusubiReleaseYankV1 {
                release: dependency_release.clone(),
                yanked: false,
                reason: "snapshot fixture".parse().expect("yank reason"),
                changed_by: account(0x69),
                changed_at_height: 7,
                revision: 1,
            },
            storage: MusubiArchiveAvailabilityV1 {
                archive_id,
                availability: MusubiStorageAvailabilityV1::Selectable,
                healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                active_locations: 1,
                finalized_height: 7,
                finalized_block_hash: [7; 32],
                index_revision: 7,
            },
            governance: MusubiArtifactGovernanceStateV1::Available,
        },
        index_revision: 7,
    };
    row.validate().expect("matching resolver row");
    let block_hashes = canonical_block_hashes(7);
    let validate_row = |candidate: MusubiResolverReleaseRowV1| {
        let mut world = World::new();
        world
            .musubi_resolver_index
            .insert(dependency_release.clone(), candidate);
        let world_view = world.view();
        validate_resolution_proof(&publication, &world_view, &block_hashes)
    };
    validate_row(row.clone()).expect("a row at the claimed snapshot is admissible");
    let mut storage_newer_than_row = row.clone();
    storage_newer_than_row.selection.storage.index_revision = 8;
    assert!(storage_newer_than_row.validate().is_err());
    let error = validate_row(storage_newer_than_row)
        .expect_err("availability cannot be newer than its resolver row");
    assert!(error.to_string().contains("invalid resolver row"));
    let mut newer_row = row.clone();
    newer_row.index_revision = 8;
    newer_row
        .validate()
        .expect("newer resolver row remains canonical");
    let error =
        validate_row(newer_row).expect_err("a newer row did not exist at the claimed snapshot");
    assert!(error.to_string().contains("newer than the claimed"));
    let mut newer_storage_revision = row.clone();
    newer_storage_revision.index_revision = 8;
    newer_storage_revision.selection.storage.index_revision = 8;
    newer_storage_revision
        .validate()
        .expect("newer availability projection remains canonical");
    let error = validate_row(newer_storage_revision)
        .expect_err("a newer availability projection did not exist at the snapshot");
    assert!(error.to_string().contains("storage revision"));
    let mut newer_storage_height = row.clone();
    newer_storage_height.selection.storage.finalized_height = 8;
    newer_storage_height.selection.storage.finalized_block_hash = [8; 32];
    newer_storage_height
        .validate()
        .expect("future-height availability projection remains canonical");
    let error = validate_row(newer_storage_height)
        .expect_err("future availability state did not exist at the snapshot");
    assert!(error.to_string().contains("storage state is newer"));
    let mut mismatched_storage_hash = row.clone();
    mismatched_storage_hash
        .selection
        .storage
        .finalized_block_hash = [0x6A; 32];
    mismatched_storage_hash
        .validate()
        .expect("nonzero availability block hashes are structurally valid");
    let error = validate_row(mismatched_storage_hash)
        .expect_err("equal-height availability must bind the snapshot block");
    assert!(error.to_string().contains("claimed finalized block"));
    let mut noncanonical_older_storage = row.clone();
    noncanonical_older_storage
        .selection
        .storage
        .finalized_height = 6;
    noncanonical_older_storage
        .selection
        .storage
        .finalized_block_hash = [0x6A; 32];
    noncanonical_older_storage
        .validate()
        .expect("an older availability anchor is structurally valid");
    let error = validate_row(noncanonical_older_storage)
        .expect_err("older availability must still bind its own canonical block");
    assert!(error.to_string().contains("not anchored to its canonical"));
    let mut newer_yank = row;
    newer_yank.selection.yank.changed_at_height = 8;
    newer_yank
        .validate()
        .expect("future-height yank projection remains canonical");
    let error =
        validate_row(newer_yank).expect_err("future yank state did not exist at the snapshot");
    assert!(error.to_string().contains("yank state is newer"));
}
fn initial_executor_archive_registration_fixture() -> (State, AccountId, RegisterMusubiArchiveV1) {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };

    let mut archive = retention_archive(0x34);
    let publisher = archive.registered_by.clone();
    let broker = archive
        .staging_receipt
        .payload
        .binding
        .ingress_broker
        .clone();
    let mut world = World::with(
        [],
        [
            iroha_data_model::account::Account::new(publisher.clone()).build(&publisher),
            iroha_data_model::account::Account::new(broker.clone()).build(&broker),
            iroha_data_model::account::Account::new(account(0x90)).build(&account(0x90)),
        ],
        [],
    );
    // Exercise the real execution boundary with committed, validated global authority.
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    world.provider_owners.insert(
        archive.staging_receipt.payload.binding.seed_provider,
        broker,
    );
    let config = TestChainConfig::new(world, 0);
    let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare original Musubi genesis");
    let state = std::sync::Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished Musubi State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_account,
        mode.into(),
        None,
    )
    .expect("apply actual signed Musubi genesis");
    archive.staging_receipt.payload.binding.network_id = *state.network_id_ref();
    archive.staging_receipt.payload.issued_at_ms = 500;
    archive.staging_receipt.payload.expires_at_ms = 2_000;
    let broker_key = KeyPair::try_from_seed(vec![0x35; 32], Algorithm::Ed25519)
        .expect("same original fixture ingress broker key");
    archive.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
        broker_key.private_key(),
        archive.staging_receipt.payload.signing_hash(),
    )
    .expect("sign exact archive receipt for the actual execution network");
    archive.commitment.validate().expect("canonical commitment");
    archive
        .staging_receipt
        .verify(&archive.staging_receipt.payload.binding, 1_500)
        .expect("authenticated fixture receipt at execution time");
    (
        state,
        publisher,
        RegisterMusubiArchiveV1::new(archive.commitment, archive.staging_receipt, 1),
    )
}

fn initial_executor_archive_block(state: &State) -> crate::state::StateBlock<'_> {
    state.block(BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("post-genesis archive height"),
        state.view().latest_block_hash(),
        None,
        1_500,
        0,
    ))
}

#[test]
fn initial_executor_registers_authenticated_musubi_archive_and_preserves_exact_replay() {
    let (state, publisher, instruction) = initial_executor_archive_registration_fixture();
    let archive_id = instruction.commitment.archive_id();
    let receipt = instruction.staging_receipt.clone();
    let mut block = initial_executor_archive_block(&state);
    let mut transaction = block.transaction();
    assert!(
        crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok(),
        "authenticated archive cases require the ordinary signed-genesis root"
    );
    crate::executor::Executor::Initial
        .execute_instruction(&mut transaction, &publisher, instruction.clone().into())
        .expect("Initial executor routes the authenticated archive registration through Core");
    let registered = transaction
        .world
        .musubi_archives
        .get(&archive_id)
        .expect("archive was actually registered")
        .clone();
    assert_eq!(registered.registered_by, publisher);
    assert_eq!(registered.staging_receipt, receipt);
    assert_eq!(registered.registered_at_height, 2);
    assert!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id)
            .is_some()
    );
    assert!(
        transaction
            .world
            .musubi_archive_reverse_references
            .get(&archive_id)
            .is_some()
    );
    assert_eq!(take_musubi_events(&mut transaction).len(), 2);

    crate::executor::Executor::Initial
        .execute_instruction(&mut transaction, &publisher, instruction.clone().into())
        .expect("exact original registrant replay remains idempotent");
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&registered)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    let error = crate::executor::Executor::Initial
        .execute_instruction(&mut transaction, &account(0x90), instruction.into())
        .expect_err("an unrelated authority cannot replay the registrant's receipt");
    let iroha_data_model::ValidationFail::InstructionFailed(error) = error else {
        panic!("unauthorized replay must reach the Core handler: {error:?}");
    };
    assert!(
        error
            .to_string()
            .contains("only the original Musubi archive registrant")
    );
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&registered)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}

#[test]
fn initial_executor_musubi_archive_registration_keeps_native_authority_and_policy_checks() {
    for (case, expected) in [
        ("publisher", "network, publisher, or archive body"),
        ("closed_policy", "admission is closed"),
        ("stale_policy", "stale Musubi registry policy revision"),
        ("provider", "provider is not admitted"),
        ("network", "network, publisher, or archive body"),
        ("signature", "receipt signature failed"),
        ("expired", "validity window does not match"),
    ] {
        let (state, publisher, mut instruction) = initial_executor_archive_registration_fixture();
        let mut block = initial_executor_archive_block(&state);
        let mut transaction = block.transaction();
        assert!(
            crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok(),
            "every native archive refusal must reach its handler through an authentic root"
        );
        let mut authority = publisher;
        match case {
            "publisher" => authority = account(0x90),
            "closed_policy" => {
                *transaction.world.musubi_registry_policy.get_mut() = MusubiRegistryPolicyV1 {
                    mode: MusubiRegistryAdmissionModeV1::Closed,
                    ..MusubiRegistryPolicyV1::default()
                };
            }
            "stale_policy" => instruction.expected_policy_revision = 2,
            "provider" => {
                instruction.staging_receipt.payload.binding.seed_provider =
                    iroha_data_model::sorafs::capacity::ProviderId::new([0xff; 32]);
            }
            "network" => {
                instruction.staging_receipt.payload.binding.network_id = retention_archive(0x60)
                    .staging_receipt
                    .payload
                    .binding
                    .network_id;
            }
            "signature" => {
                let wrong_key = KeyPair::try_from_seed(vec![0x99; 32], Algorithm::Ed25519)
                    .expect("unrelated signing key");
                instruction.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
                    wrong_key.private_key(),
                    instruction.staging_receipt.payload.signing_hash(),
                )
                .expect("wrong-key signature is structurally well formed");
            }
            "expired" => {
                instruction.staging_receipt.payload.expires_at_ms = 1_000;
                let broker_key = KeyPair::try_from_seed(vec![0x35; 32], Algorithm::Ed25519)
                    .expect("original admitted broker");
                instruction.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    instruction.staging_receipt.payload.signing_hash(),
                )
                .expect("correctly signed expired receipt");
            }
            _ => unreachable!("closed native rejection matrix"),
        }
        let archive_id = instruction.commitment.archive_id();
        let error = crate::executor::Executor::Initial
            .execute_instruction(&mut transaction, &authority, instruction.into())
            .expect_err("native archive checks must remain mandatory through Initial");
        let iroha_data_model::ValidationFail::InstructionFailed(error) = error else {
            panic!("{case} must reach the actual Core handler: {error:?}");
        };
        assert!(error.to_string().contains(expected), "{case}: {error}");
        assert!(
            transaction.world.musubi_archives.get(&archive_id).is_none(),
            "{case}"
        );
        assert!(
            transaction
                .world
                .musubi_archive_availability
                .get(&archive_id)
                .is_none(),
            "{case}"
        );
        assert!(
            transaction
                .world
                .musubi_archive_reverse_references
                .get(&archive_id)
                .is_none(),
            "{case}"
        );
        assert!(take_musubi_events(&mut transaction).is_empty(), "{case}");
    }
}

#[test]
fn archive_registration_replay_requires_the_exact_original_receipt() {
    let mut world = World::new();
    let publisher_key =
        KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).expect("publisher key");
    let publisher = AccountId::new(publisher_key.public_key().clone());
    let broker_key =
        KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).expect("broker key");
    let broker = AccountId::new(broker_key.public_key().clone());
    let provider = iroha_data_model::sorafs::capacity::ProviderId::new([0x33; 32]);
    world.provider_owners.insert(provider, broker.clone());
    let genesis = archive_replay_genesis_at(500);
    let genesis_hash = genesis.hash();
    let kura = Kura::blank_kura_for_testing();
    // Authenticate and provision the configured lane before publishing history.
    let state = State::new_with_chain_and_network_id_for_testing(
        world,
        std::sync::Arc::clone(&kura),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("archive-replay-test"),
        iroha_data_model::NetworkId::from_genesis_hash(genesis_hash),
    );
    kura.store_block(
        iroha_data_model::block::SharedSignedBlock::try_new(genesis, &state.ivm_execution_budget())
            .expect("admit signed genesis block control"),
    )
    .expect("retain the exact genesis body advertised by archive replay state");
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(genesis_hash);
        block_hashes.commit_for_tests();
    }
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("replay height"),
        Some(genesis_hash),
        None,
        1_500,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let commitment = retention_archive(0x34).commitment;
    let binding = MusubiSeedIngressReceiptBindingV1 {
        network_id: *transaction.network_id(),
        publisher: publisher.clone(),
        ingress_broker: broker,
        seed_provider: provider,
        semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([0x35; 32]),
        archive_id: commitment.archive_id(),
        car_body_digest: commitment.car_digest,
        car_body_length: commitment.car_size,
        nonce: [0x36; 32],
    };
    let signed_receipt =
        |binding: MusubiSeedIngressReceiptBindingV1, issued_at_ms, expires_at_ms| {
            let payload = MusubiSeedIngressReceiptPayloadV1 {
                version: MUSUBI_REGISTRY_VERSION_V1,
                binding,
                issued_at_ms,
                expires_at_ms,
            };
            MusubiSeedIngressReceiptV1 {
                approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                    public_key: broker_key.public_key().clone(),
                    signature: SignatureOf::try_from_hash(
                        broker_key.private_key(),
                        payload.signing_hash(),
                    )
                    .expect("receipt signature"),
                }],
                payload,
            }
        };
    let registered_receipt = signed_receipt(binding.clone(), 500, 1_000);
    let archive_id = commitment.archive_id();
    transaction.world.musubi_archives.insert(
        archive_id,
        MusubiArchiveRecordV1 {
            archive_id,
            commitment: commitment.clone(),
            staging_receipt: registered_receipt.clone(),
            registered_by: publisher.clone(),
            registered_at_height: 1,
            location_revision: 1,
            location_ids: Vec::new(),
        },
    );
    RegisterMusubiArchiveV1::new(commitment.clone(), registered_receipt.clone(), 1)
        .execute(&publisher, &mut transaction)
        .expect("the exact registered receipt remains idempotent after expiry");
    assert_eq!(
        transaction
            .world
            .musubi_archives
            .get(&archive_id)
            .expect("registered archive")
            .staging_receipt,
        registered_receipt,
        "the first authoritative receipt remains immutable"
    );
    let refreshed_receipt = signed_receipt(binding.clone(), 1_400, 2_000);
    let error = RegisterMusubiArchiveV1::new(commitment.clone(), refreshed_receipt, 1)
        .execute(&publisher, &mut transaction)
        .expect_err("a refreshed receipt must not replace the registered receipt");
    assert!(
        error
            .to_string()
            .contains("different commitment or staging receipt")
    );
    let mut different_binding = binding;
    different_binding.nonce = [0xee; 32];
    let different_receipt = signed_receipt(different_binding, 1_400, 2_000);
    let error = RegisterMusubiArchiveV1::new(commitment, different_receipt, 1)
        .execute(&publisher, &mut transaction)
        .expect_err("a different operation nonce must not cross archive registration");
    assert!(
        error
            .to_string()
            .contains("different commitment or staging receipt")
    );
}
fn package(name: &str) -> MusubiPackageIdV1 {
    MusubiPackageIdV1::new(
        iroha_model_base::topology::DataSpaceId::new(7),
        MusubiPackageScopeV1::DataspaceRoot,
        name.parse().expect("package name"),
    )
}
fn seed_package_owner(
    package: &MusubiPackageIdV1,
    owner: &AccountId,
    governance_revision: u64,
    transaction: &mut StateTransaction<'_, '_>,
) {
    transaction.world.musubi_packages.insert(
        package.clone(),
        MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: "sora".parse().expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([1; 32]),
            owners: vec![owner.clone()],
            member_accounts: vec![owner.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: governance_revision,
                metadata: 1,
                archive_locations: 1,
            },
        },
    );
    let member = MusubiPackageMemberV1 {
        package: package.clone(),
        account: owner.clone(),
        role: MusubiPackageRoleV1::Owner,
        accepted_at_height: 1,
        governance_revision,
    };
    transaction
        .world
        .musubi_package_members
        .insert(member.key(), member.clone());
    upsert_maintainer_directory(
        MusubiMaintainerDirectoryEntryV1::Accepted(member),
        transaction,
    );
}
fn seed_pending_invitation(
    invitation: MusubiMaintainerInvitationV1,
    transaction: &mut StateTransaction<'_, '_>,
) {
    transaction
        .world
        .musubi_package_invitations
        .insert(invitation.invite_id, invitation.clone());
    upsert_maintainer_directory(
        MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation),
        transaction,
    );
}
fn take_musubi_events(transaction: &mut StateTransaction<'_, '_>) -> Vec<MusubiEvent> {
    transaction
        .world
        .take_external_events()
        .into_iter()
        .filter_map(|event| match event {
            iroha_data_model::events::EventBox::Data(data) => match data.as_ref() {
                DataEvent::Musubi(event) => Some(event.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}
fn decision_for_current_block(
    decision_id: [u8; 32],
    action: &MusubiParliamentActionV1,
    transaction: &StateTransaction<'_, '_>,
) -> MusubiGovernanceDecisionV1 {
    let execute_after_height = execution_height(transaction);
    let delay = transaction.gov.min_enactment_delay.max(1);
    let enacted_at_height = execute_after_height
        .checked_sub(delay)
        .filter(|height| *height > 0)
        .expect("fixture block leaves a positive enactment height");
    MusubiGovernanceDecisionV1 {
        decision_id,
        action_digest: action.action_digest(),
        enacted_at_height,
        execute_after_height,
    }
}
fn insert_enacted_proposal(
    decision_id: [u8; 32],
    kind: ProposalKind,
    enacted_at_height: u64,
    transaction: &mut StateTransaction<'_, '_>,
) {
    let proposer = account(80);
    let created_height = enacted_at_height.saturating_sub(1).max(1);
    let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
        &kind,
        vec![account(81), account(82), account(83)],
        transaction.network_id(),
        enacted_at_height,
    );
    let attempt_id = attempt.attempt().id;
    transaction
        .world
        .put_governance_proposal(
            decision_id,
            GovernanceProposalRecord {
                proposer,
                kind,
                created_height,
                status: GovernanceProposalStatus::Enacted,
            },
        )
        .expect("Musubi test proposal must satisfy first-release JSON bounds");
    transaction
        .world
        .put_parliament_attempt_for_testing(attempt_id, attempt)
        .expect("persist exact enacted Musubi Parliament attempt");
}
fn seed_enacted_decision(
    action: &MusubiParliamentActionV1,
    transaction: &mut StateTransaction<'_, '_>,
) -> MusubiGovernanceDecisionV1 {
    let kind = ProposalKind::MusubiRegistryGovernance(action.clone());
    let decision_id = kind.fingerprint();
    let decision = decision_for_current_block(decision_id, action, transaction);
    insert_enacted_proposal(decision_id, kind, decision.enacted_at_height, transaction);
    decision
}
fn snapshot(revision: u64) -> MusubiRegistrySnapshotV1 {
    MusubiRegistrySnapshotV1 {
        finalized_height: 7,
        finalized_block_hash: [7; 32],
        index_revision: revision,
    }
}
fn retention_archive(seed: u8) -> MusubiArchiveRecordV1 {
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: iroha_data_model::sorafs::pin_registry::ManifestRootCid::from_blake3_digest(
            [seed; 32],
        )
        .expect("retention fixture root CID"),
        chunker: iroha_data_model::sorafs::pin_registry::ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        },
        chunk_plan_digest: MusubiContentDigestV1::new([seed.wrapping_add(1); 32]),
        por_root: MusubiContentDigestV1::new([seed.wrapping_add(2); 32]),
        content_length: 1,
        car_digest: MusubiContentDigestV1::new([seed.wrapping_add(3); 32]),
        car_size: 1,
        bundle_digest: MusubiContentDigestV1::new([seed.wrapping_add(4); 32]),
        source_tree_digest: MusubiContentDigestV1::new([seed.wrapping_add(5); 32]),
        descriptor_digest: MusubiContentDigestV1::new([seed.wrapping_add(6); 32]),
        file_count: 1,
        chunk_count: 1,
    };
    let archive_id = commitment.archive_id();
    let publisher = account(seed);
    let broker_keypair = KeyPair::try_from_seed(vec![seed.wrapping_add(1); 32], Algorithm::Ed25519)
        .expect("retention fixture broker keypair");
    let broker = AccountId::new(broker_keypair.public_key().clone());
    let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: MusubiSeedIngressReceiptBindingV1 {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                    [seed.wrapping_add(7); 32],
                )),
            ),
            publisher: publisher.clone(),
            ingress_broker: broker,
            seed_provider: iroha_data_model::sorafs::capacity::ProviderId::new(
                [seed.wrapping_add(8); 32],
            ),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new(
                [seed.wrapping_add(9); 32],
            ),
            archive_id,
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [seed.wrapping_add(10); 32],
        },
        issued_at_ms: 1,
        expires_at_ms: 2,
    };
    let receipt_approval = MusubiSeedIngressReceiptApprovalV1 {
        public_key: broker_keypair.public_key().clone(),
        signature: SignatureOf::try_from_hash(
            broker_keypair.private_key(),
            receipt_payload.signing_hash(),
        )
        .expect("sign retention fixture receipt"),
    };
    MusubiArchiveRecordV1 {
        archive_id,
        commitment: commitment.clone(),
        staging_receipt: MusubiSeedIngressReceiptV1 {
            payload: receipt_payload,
            approvals: vec![receipt_approval],
        },
        registered_by: publisher,
        registered_at_height: 1,
        location_revision: 1,
        location_ids: Vec::new(),
    }
}
fn retention_release(
    archive_id: ArchiveId,
    version: &str,
    yanked: bool,
    artifact_governance: MusubiArtifactGovernanceStateV1,
) -> MusubiReleaseRecordV1 {
    let release = MusubiReleaseIdV1::new(
        package("retention"),
        version.parse().expect("retention release version"),
    );
    let manifest = MusubiReleaseManifestV1 {
        release: release.clone(),
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([0xA1; 32]).expect("retention ABI"),
        dependencies: Vec::new(),
        exports: Vec::new(),
        interface_digest: MusubiContentDigestV1::new([0xA2; 32]),
        metadata: MusubiReleaseMetadataV1::default(),
        archive_id,
        verification_lock_digest: MusubiVerificationLockDigestV1::new([0xA3; 32]),
    };
    MusubiReleaseRecordV1 {
        release_digest: manifest.release_digest(),
        manifest,
        published_by: account(111),
        published_at_height: 1,
        yank: MusubiReleaseYankV1 {
            release,
            yanked,
            reason: "retention fixture".parse().expect("yank reason"),
            changed_by: account(111),
            changed_at_height: 1,
            revision: 1,
        },
        artifact_governance,
        revisions: MusubiReleaseRevisionsV1 {
            yank: 1,
            artifact_governance: 1,
        },
    }
}
fn exact_release_query_fixture(
    include_home: bool,
    include_universal: bool,
) -> (State, MusubiExactReleaseQueryV1) {
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero genesis height"),
        None,
        None,
        0,
        0,
    );
    let genesis_hash = header.hash();
    let archive = retention_archive(0x71);
    let release = retention_release(
        archive.archive_id,
        "1.2.3",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    );
    let release_id = release.manifest.release.clone();
    let universal_release = MusubiResolverReleaseRowV1 {
        release: release_id.clone(),
        release_digest: release.release_digest,
        archive_id: archive.archive_id,
        source_digest: archive.commitment.source_tree_digest,
        interface_digest: release.manifest.interface_digest,
        abi: release.manifest.abi,
        dependencies: release.manifest.dependencies.clone(),
        selection: MusubiReleaseSelectionStateV1 {
            yank: release.yank.clone(),
            storage: MusubiArchiveAvailabilityV1 {
                archive_id: archive.archive_id,
                availability: MusubiStorageAvailabilityV1::Selectable,
                healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                active_locations: 1,
                finalized_height: 1,
                finalized_block_hash: *genesis_hash.as_ref(),
                index_revision: 1,
            },
            governance: release.artifact_governance.clone(),
        },
        index_revision: 1,
    };
    let mut world = World::new();
    if include_home {
        world.musubi_releases.insert(release_id.clone(), release);
    }
    if include_universal {
        world
            .musubi_resolver_index
            .insert(release_id.clone(), universal_release);
    }
    let state = State::new_with_chain_and_network_id_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("exact-release-query-test"),
        iroha_data_model::NetworkId::from_genesis_hash(genesis_hash),
    );
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(genesis_hash);
        block_hashes.commit_for_tests();
    }
    (
        state,
        MusubiExactReleaseQueryV1 {
            release: release_id,
        },
    )
}
#[test]
fn exact_release_query_returns_paired_projections_from_one_snapshot() {
    let (state, request) = exact_release_query_fixture(true, true);
    let response = ValidSingularQuery::execute(
        &FindMusubiExactReleaseV1::new(request.clone()),
        &state.view(),
    )
    .expect("paired exact release query");
    response
        .validate_for(&request)
        .expect("paired response validates for its request");
    assert_eq!(response.snapshot.finalized_height, 1);
    assert_eq!(response.snapshot.index_revision, 1);
    assert_eq!(response.network_id, *state.network_id_ref());
    assert_eq!(response.home_release.manifest.release, request.release);
    assert_eq!(response.universal_release.release, request.release);
}
#[test]
fn exact_release_query_fails_closed_for_one_sided_projection() {
    for (include_home, include_universal) in [(true, false), (false, true)] {
        let (state, request) = exact_release_query_fixture(include_home, include_universal);
        let error =
            ValidSingularQuery::execute(&FindMusubiExactReleaseV1::new(request), &state.view())
                .expect_err("one-sided exact release projection must fail closed");
        assert!(matches!(
            error,
            QueryExecutionFail::Conversion(message)
                if message.contains("home and universal projections are inconsistent")
        ));
    }
}
#[test]
fn exact_release_query_reports_not_found_only_when_both_projections_are_absent() {
    let (state, request) = exact_release_query_fixture(false, false);
    let error = ValidSingularQuery::execute(&FindMusubiExactReleaseV1::new(request), &state.view())
        .expect_err("absent exact release must be reported as not found");
    assert_eq!(error, QueryExecutionFail::NotFound);
}
fn seed_retention_archive(
    world: &mut World,
    archive: MusubiArchiveRecordV1,
    releases: Vec<MusubiReleaseRecordV1>,
) -> ArchiveId {
    let archive_id = archive.archive_id;
    let mut release_ids = releases
        .iter()
        .map(|release| release.manifest.release.clone())
        .collect::<Vec<_>>();
    release_ids.sort();
    let release_count = u64::try_from(release_ids.len()).expect("release fixture count fits u64");
    for release in releases {
        world
            .musubi_releases
            .insert(release.manifest.release.clone(), release);
    }
    world.musubi_archives.insert(archive_id, archive);
    world.musubi_archive_availability.insert(
        archive_id,
        MusubiArchiveAvailabilityV1 {
            archive_id,
            availability: MusubiStorageAvailabilityV1::Unavailable,
            healthy_replicas: 0,
            active_locations: 0,
            finalized_height: 1,
            finalized_block_hash: [0xB1; 32],
            index_revision: 1,
        },
    );
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: release_ids,
        },
    );
    let shortfall = *world.musubi_replication_shortfall_releases.view().get();
    world.musubi_replication_shortfall_releases = crate::state::scalar_cell_custody::fixture(
        shortfall
            .checked_add(release_count)
            .expect("retention fixture shortfall count fits u64"),
    );
    archive_id
}
fn archive_location_replay_fixture(
    seed: u8,
) -> (
    World,
    AccountId,
    MusubiArchiveLocationKeyV1,
    AddMusubiArchiveLocationV1,
) {
    let mut world = World::new();
    let mut archive = retention_archive(seed);
    let genesis_hash = archive_location_genesis_header().hash();
    archive.staging_receipt.payload.binding.network_id =
        iroha_data_model::NetworkId::from_genesis_hash(genesis_hash);
    let broker_keypair = KeyPair::try_from_seed(vec![seed.wrapping_add(1); 32], Algorithm::Ed25519)
        .expect("fixture ingress broker keypair");
    archive.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
        broker_keypair.private_key(),
        archive.staging_receipt.payload.signing_hash(),
    )
    .expect("resign fixture ingress receipt");
    let authority = archive.registered_by.clone();
    let location_id = MusubiArchiveLocationIdV1::new([seed.wrapping_add(11); 32]);
    let pin =
        iroha_data_model::sorafs::pin_registry::ManifestDigest::new([seed.wrapping_add(12); 32]);
    let order = iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new(
        [seed.wrapping_add(13); 32],
    );
    archive.location_revision = 7;
    archive.location_ids = vec![location_id];
    let archive_id = archive.archive_id;
    let key = MusubiArchiveLocationKeyV1::new(archive_id, location_id);
    let mut location = location_fixture(seed, pin, order);
    location.archive_id = archive_id;
    location.location_id = location_id;
    location.revision = archive.location_revision;
    location.state = MusubiArchiveLocationStateV1::Degraded;
    let provider_keypair =
        KeyPair::try_from_seed(vec![seed.wrapping_add(14); 32], Algorithm::Ed25519)
            .expect("fixture provider keypair");
    let provider_signer = AccountId::new(provider_keypair.public_key().clone());
    let provider_owner = account(seed.wrapping_add(20));
    assert_ne!(
        provider_owner, provider_signer,
        "owner and completion signer are independent"
    );
    let provider_id =
        iroha_data_model::sorafs::capacity::ProviderId::new([seed.wrapping_add(15); 32]);
    let completion_authority =
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1::new(
            provider_owner.clone(),
            provider_signer.clone(),
            iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [seed.wrapping_add(16); 32],
                revision: 1,
                predecessor_digest: None,
                policy_digest: [seed.wrapping_add(17); 32],
            },
        );
    let binding = MusubiProviderBundleVerificationBindingV1 {
        network_id: archive.staging_receipt.payload.binding.network_id,
        provider_id,
        completed_by: provider_signer.clone(),
        completion_authority,
        replication_order: order,
        assignment_revision: 1,
        completion_epoch: 1,
        finalized_anchor: iroha_data_model::sorafs::pin_registry::ProviderIngestFinalizedAnchorV1 {
            height: 1,
            block_hash: *genesis_hash.as_ref(),
        },
        archive_id,
        bundle_digest: archive.commitment.bundle_digest,
        descriptor_digest: archive.commitment.descriptor_digest,
        semantic_release_manifest_digest: archive
            .staging_receipt
            .payload
            .binding
            .semantic_release_manifest_digest,
        verification_lock_digest: MusubiVerificationLockDigestV1::new([seed.wrapping_add(19); 32]),
        source_tree_digest: archive.commitment.source_tree_digest,
    };
    let payload = MusubiProviderBundleVerificationPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: binding.clone(),
    };
    let attestation = MusubiProviderBundleVerificationAttestationV1 {
        approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
            public_key: provider_keypair.public_key().clone(),
            signature: SignatureOf::try_from_hash(
                provider_keypair.private_key(),
                payload.signing_hash(),
            )
            .expect("sign fixture provider attestation"),
        }],
        payload,
    };
    attestation
        .verify(&binding)
        .expect("fixture provider attestation is cryptographically valid");
    let attestation_key = attestation.key();
    let attestation_digest = attestation.digest();
    let provider_attestation_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
        archive_id,
        order,
        &[attestation.reference()],
    )
    .expect("fixture provider attestation set digest");
    location.providers = vec![provider_id];
    location.provider_attestation_set_digest = provider_attestation_set_digest;
    location.finalized_height = 2;
    location
        .validate()
        .expect("fixture archive location is structurally valid");
    let instruction = AddMusubiArchiveLocationV1 {
        archive_id,
        location_id,
        pin_manifest: location.pin_manifest,
        replication_order: location.replication_order,
        provider_attestation_set_digest,
        renew_after_epoch: location.renew_after_epoch,
        expires_at_epoch: location.expires_at_epoch,
        expected_location_revision: 1,
    };
    let mut pin_record = iroha_data_model::sorafs::pin_registry::PinManifestRecord::new(
        pin,
        archive.commitment.root_cid.clone(),
        archive.commitment.chunker.clone(),
        *archive.commitment.chunk_plan_digest.as_bytes(),
        *archive.commitment.por_root.as_bytes(),
        archive.commitment.content_length,
        iroha_data_model::sorafs::pin_registry::PinPolicy {
            min_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
            storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
            retention_epoch: location.expires_at_epoch,
        },
        authority.clone(),
        1,
        None,
        None,
        iroha_model_base::metadata::Metadata::default(),
    );
    pin_record.approve(1, None);
    world.pin_manifests.insert(pin, pin_record);
    world.replication_orders.insert(
        order,
        iroha_data_model::sorafs::pin_registry::ReplicationOrderRecord {
            order_id: order,
            manifest_digest: pin,
            manifest_root_cid: archive.commitment.root_cid.clone(),
            musubi_archive: Some(archive_id),
            issued_by: authority.clone(),
            issued_epoch: 1,
            deadline_epoch: location.expires_at_epoch,
            canonical_order: vec![seed],
            assignment_revision: binding.assignment_revision,
            provider_completions: vec![
                iroha_data_model::sorafs::pin_registry::ReplicationOrderCompletionRecord {
                    provider_id,
                    completed_by: provider_signer.clone(),
                    completion_epoch: binding.completion_epoch,
                    assignment_revision: binding.assignment_revision,
                    completion_authority: binding.completion_authority.clone(),
                    finalized_anchor: binding.finalized_anchor,
                },
            ],
            status: ReplicationOrderStatus::Completed(binding.completion_epoch),
        },
    );
    world.provider_owners.insert(provider_id, provider_owner);
    world.musubi_provider_bundle_attestations.insert(
        attestation_key,
        MusubiProviderBundleAttestationRecordV1 {
            key: attestation_key,
            attestation_digest,
            attestation,
            registered_by: authority.clone(),
            registered_at_height: 1,
        },
    );
    world.musubi_locations_by_pin.insert(
        pin,
        MusubiPinLocationReferenceV1 {
            pin_manifest: pin,
            location: key,
            active: true,
        },
    );
    world.musubi_locations_by_replication_order.insert(
        order,
        MusubiReplicationOrderLocationReferenceV1 {
            binding: MusubiReplicationOrderArchiveBindingV1::new(
                order,
                archive_id,
                archive.commitment.clone(),
            ),
            lifecycle: MusubiReplicationOrderLocationLifecycleV1::Active(key),
        },
    );
    world
        .musubi_locations_by_provider
        .insert(MusubiProviderLocationKeyV1::new(provider_id, key), ());
    world.musubi_archives.insert(archive_id, archive);
    world.musubi_archive_locations.insert(key, location);
    (world, authority, key, instruction)
}
#[test]
fn archive_package_governance_replaces_the_prepublication_registrant_capability() {
    let former_registrant = account(0x51);
    let current_owner = account(0x52);
    let mut archive = retention_archive(0x53);
    archive.registered_by = former_registrant.clone();
    let governed_package = package("archive-recovery");
    let governed_release =
        MusubiReleaseIdV1::new(governed_package.clone(), "1.0.0".parse().expect("version"));
    let mut world = World::new();
    world.musubi_packages.insert(
        governed_package.clone(),
        MusubiPackageRecordV1 {
            package: governed_package.clone(),
            claimed_namespace: "sora".parse().expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([0x54; 32]),
            owners: vec![current_owner.clone()],
            member_accounts: vec![current_owner.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: 2,
                metadata: 1,
                archive_locations: 2,
            },
        },
    );
    let owner = MusubiPackageMemberV1 {
        package: governed_package,
        account: current_owner.clone(),
        role: MusubiPackageRoleV1::Owner,
        accepted_at_height: 2,
        governance_revision: 2,
    };
    world.musubi_package_members.insert(owner.key(), owner);
    let mut reason = MusubiGovernanceRejectionReasonV1::Other;
    {
        let world_view = world.view();
        ensure_archive_manager(&archive, &former_registrant, &world_view, &mut reason)
            .expect("the archive registrant manages an unpublished archive");
    }
    world.musubi_archive_reverse_references.insert(
        archive.archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id: archive.archive_id,
            releases: vec![governed_release],
        },
    );
    let world_view = world.view();
    ensure_archive_manager(&archive, &current_owner, &world_view, &mut reason)
        .expect("the current package owner manages a published archive");
    let error = ensure_archive_manager(&archive, &former_registrant, &world_view, &mut reason)
        .expect_err("a removed registrant must not retain archive-location authority");
    assert!(error.to_string().contains("lacks the required"));
    assert_eq!(reason, MusubiGovernanceRejectionReasonV1::Unauthorized);
}
#[test]
fn explicit_location_invalidation_preserves_a_protected_archives_replica_quorum() {
    let (mut world, _, remaining_key, _) = archive_location_replay_fixture(0x55);
    let archive_id = remaining_key.archive_id;
    let remaining = world
        .musubi_archive_locations
        .view()
        .get(&remaining_key)
        .cloned()
        .expect("fixture remaining location");
    assert_eq!(
        current_location_providers(&remaining, &world.view())
            .expect("fixture evidence is current")
            .len(),
        1
    );
    assert!(!provider_count_is_healthy(2));
    assert!(provider_count_is_healthy(3));
    let invalidated_id = MusubiArchiveLocationIdV1::new([0x56; 32]);
    let invalidated_key = MusubiArchiveLocationKeyV1::new(archive_id, invalidated_id);
    let mut archive = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .cloned()
        .expect("fixture archive");
    archive.location_ids.push(invalidated_id);
    archive.location_ids.sort();
    world.musubi_archives.insert(archive_id, archive);
    let release = retention_release(
        archive_id,
        "1.0.0",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    );
    let release_id = release.manifest.release.clone();
    world.musubi_releases.insert(release_id.clone(), release);
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: vec![release_id],
        },
    );
    let world_view = world.view();
    let error = ensure_locations_may_be_invalidated(&[invalidated_key], &world_view)
        .expect_err("one remaining fetchable replica is not a healthy release floor");
    assert!(error.to_string().contains("quorum-healthy"));
}
/// Retain a deterministic log-only genesis anchor for these seeded ISI unit states.
/// Advertising only its hash would make ordinary StateBlock creation fail DA hydration
/// before any native archive authorization or exact-receipt check could execute.
fn archive_replay_genesis_at(creation_time_ms: u64) -> iroha_data_model::block::SignedBlock {
    let key = KeyPair::try_from_seed(vec![0xA6; 32], Algorithm::Ed25519)
        .expect("archive replay genesis fixture key");
    let authority = AccountId::new(key.public_key().clone());
    let transaction_time =
        iroha_primitives::time::TimeSource::new_fixed(std::time::Duration::from_millis(
            creation_time_ms
                .checked_sub(1)
                .expect("genesis block time follows its transaction"),
        ));
    let transaction =
        iroha_data_model::transaction::TransactionBuilder::new_genesis_with_time_source(
            authority,
            &transaction_time,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "archive replay anchor".to_owned(),
        )])
        .sign(key.private_key());
    let mut genesis = iroha_data_model::block::SignedBlock::genesis(
        vec![transaction],
        key.private_key(),
        None,
        None,
    );
    let entrypoints = genesis
        .external_entrypoints_cloned()
        .map(|entrypoint| entrypoint.hash())
        .collect::<Vec<_>>();
    {
        let outputs = crate::execution_output_test_support::structural_network_outputs(
            &genesis,
            &entrypoints,
            vec![Ok(
                iroha_data_model::transaction::DataTriggerSequence::default(),
            )],
        );
        let fragments =
            u64::try_from(outputs.iter().filter(|row| row.result().is_ok()).count()).unwrap();
        genesis.set_execution_outputs(
            outputs,
            fragments,
            std::collections::BTreeMap::default(),
            Vec::new(),
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &crate::execution_output_test_support::structural_output_limits(),
        )
    }
    .expect("retain the successful log-only genesis result");
    let signature = iroha_data_model::block::BlockSignature::new(
        0,
        SignatureOf::try_from_hash(key.private_key(), genesis.hash())
            .expect("sign the retained result-bearing genesis"),
    );
    genesis
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                .expect("at most 31 block signatures"),
        )
        .expect("install exact retained genesis signature");
    assert_eq!(
        genesis.header().creation_time(),
        std::time::Duration::from_millis(creation_time_ms)
    );
    assert_eq!(genesis.output_results().len(), 1);
    assert!(
        genesis
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    genesis
        .validate_proposal_commitments()
        .expect("canonical genesis entrypoints");
    genesis
        .validate_output_merkle_cache()
        .expect("canonical genesis results");
    genesis
}
fn archive_location_genesis_header() -> iroha_data_model::block::BlockHeader {
    archive_replay_genesis_at(1).header()
}
fn archive_location_replay_state(world: World) -> State {
    let genesis = archive_replay_genesis_at(1);
    let genesis_hash = genesis.hash();
    assert_eq!(genesis_hash, archive_location_genesis_header().hash());
    let kura = Kura::blank_kura_for_testing();
    // Authenticate and provision the configured lane before publishing history.
    let state = State::new_with_chain_and_network_id_for_testing(
        world,
        std::sync::Arc::clone(&kura),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("retention-test"),
        iroha_data_model::NetworkId::from_genesis_hash(archive_location_genesis_header().hash()),
    );
    kura.store_block(
        iroha_data_model::block::SharedSignedBlock::try_new(genesis, &state.ivm_execution_budget())
            .expect("admit signed genesis block control"),
    )
    .expect("retain the exact genesis body before advertising committed height");
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(genesis_hash);
        block_hashes.commit_for_tests();
    }
    state
}
fn archive_location_replay_block(state: &State) -> crate::state::StateBlock<'_> {
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("nonzero replay height"),
        Some(archive_location_genesis_header().hash()),
        None,
        2,
        0,
    );
    state.block(header)
}
#[test]
fn provider_attestation_audit_query_loads_one_exact_immutable_record() {
    let (world, _, location_key, instruction) = archive_location_replay_fixture(0x40);
    let locations = world.musubi_archive_locations.view();
    let location = locations.get(&location_key).expect("fixture location");
    let key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: instruction.archive_id,
        replication_order: instruction.replication_order,
        provider_id: location.providers[0],
    };
    let expected = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture provider attestation");
    let state = archive_location_replay_state(world);
    let actual = ValidSingularQuery::execute(
        &FindMusubiProviderBundleAttestationV1::new(key),
        &state.view(),
    )
    .expect("exact provider attestation audit query");
    assert_eq!(actual, expected);
}
#[test]
fn provider_attestation_registration_is_exactly_idempotent_after_cas_consumption() {
    let (world, authority, location_key, instruction) = archive_location_replay_fixture(0x3A);
    let provider = world
        .musubi_archive_locations
        .view()
        .get(&location_key)
        .expect("fixture location")
        .providers[0];
    let key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: instruction.archive_id,
        replication_order: instruction.replication_order,
        provider_id: provider,
    };
    let record = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture provider attestation");
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    RegisterMusubiProviderBundleAttestationV1::new(record.attestation.clone(), 1)
        .execute(&authority, &mut transaction)
        .expect("exact retry ignores the consumed location CAS revision");
    assert_eq!(
        transaction
            .world
            .musubi_provider_bundle_attestations
            .get(&key),
        Some(&record)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn successor_archive_manager_can_replay_identical_provider_evidence_without_rewriting_audit() {
    let (world, former_manager, location_key, instruction) = archive_location_replay_fixture(0x3E);
    let provider = world
        .musubi_archive_locations
        .view()
        .get(&location_key)
        .expect("fixture location")
        .providers[0];
    let key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: instruction.archive_id,
        replication_order: instruction.replication_order,
        provider_id: provider,
    };
    let record = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture provider attestation");
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let successor = account(0x3F);
    let governed_package = package("attestation-recovery");
    seed_package_owner(&governed_package, &successor, 2, &mut transaction);
    transaction.world.musubi_archive_reverse_references.insert(
        instruction.archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id: instruction.archive_id,
            releases: vec![MusubiReleaseIdV1::new(
                governed_package,
                "1.0.0".parse().expect("version"),
            )],
        },
    );
    let replay = RegisterMusubiProviderBundleAttestationV1::new(record.attestation.clone(), 1);
    replay
        .clone()
        .execute(&successor, &mut transaction)
        .expect("a current successor manager may replay identical immutable evidence");
    assert_eq!(
        transaction
            .world
            .musubi_provider_bundle_attestations
            .get(&key),
        Some(&record),
        "an idempotent successor replay must retain the original registrant audit"
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    let error = replay
        .execute(&former_manager, &mut transaction)
        .expect_err("the removed former manager must not retain replay authority");
    assert!(error.to_string().contains("lacks the required"));
    assert_eq!(
        transaction
            .world
            .musubi_provider_bundle_attestations
            .get(&key),
        Some(&record)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn new_provider_attestation_registration_requires_the_current_location_revision() {
    let (world, authority, location_key, instruction) = archive_location_replay_fixture(0x3B);
    let provider = world
        .musubi_archive_locations
        .view()
        .get(&location_key)
        .expect("fixture location")
        .providers[0];
    let key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: instruction.archive_id,
        replication_order: instruction.replication_order,
        provider_id: provider,
    };
    let record = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture provider attestation");
    let mut attestations = world.musubi_provider_bundle_attestations.block();
    let _ = attestations.remove(key);
    attestations.commit();
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let error = RegisterMusubiProviderBundleAttestationV1::new(record.attestation, 1)
        .execute(&authority, &mut transaction)
        .expect_err("new immutable evidence must use the current location revision");
    assert!(
        error
            .to_string()
            .contains("stale Musubi archive location revision")
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn archive_location_add_recomputes_the_registered_attestation_set_digest() {
    let (world, authority, _, mut instruction) = archive_location_replay_fixture(0x3C);
    instruction.expected_location_revision = 7;
    instruction.provider_attestation_set_digest =
        MusubiProviderBundleAttestationSetDigestV1::new([0xEE; 32]);
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("a substituted compact attestation-set digest must be rejected");
    assert!(
        error
            .to_string()
            .contains("does not cover the finalized completion set")
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn archive_location_add_requires_attestation_records_from_an_earlier_finalized_height() {
    let (mut world, authority, key, mut instruction) = archive_location_replay_fixture(0x3D);
    let provider = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .expect("fixture location")
        .providers[0];
    let attestation_key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: key.archive_id,
        replication_order: instruction.replication_order,
        provider_id: provider,
    };
    let record = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&attestation_key)
        .cloned()
        .expect("fixture provider attestation");
    let mut attestations = world.musubi_provider_bundle_attestations.block();
    let _ = attestations.remove(attestation_key);
    attestations.commit();
    let mut archive = world
        .musubi_archives
        .view()
        .get(&key.archive_id)
        .cloned()
        .expect("fixture archive");
    archive.location_ids.clear();
    world.musubi_archives.insert(key.archive_id, archive);
    let mut locations = world.musubi_archive_locations.block();
    let _ = locations.remove(key);
    locations.commit();
    instruction.expected_location_revision = 7;
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    RegisterMusubiProviderBundleAttestationV1::new(record.attestation, 7)
        .execute(&authority, &mut transaction)
        .expect("current-revision provider evidence registers immutably");
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("same-height provider evidence is not finalized for location admission");
    assert!(
        error
            .to_string()
            .contains("must be finalized before archive location admission")
    );
    assert!(matches!(
        take_musubi_events(&mut transaction).as_slice(),
        [MusubiEvent::ProviderBundleAttestationRegistered(_)]
    ));
}
fn assert_exact_archive_location_replay_rejects_corruption(
    seed: u8,
    corrupt: impl FnOnce(&mut World, MusubiArchiveLocationKeyV1, &mut AddMusubiArchiveLocationV1),
    expected_message: &str,
) {
    let (mut world, authority, key, mut instruction) = archive_location_replay_fixture(seed);
    corrupt(&mut world, key, &mut instruction);
    let archive_id = instruction.archive_id;
    let archive_before = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .cloned()
        .expect("fixture archive");
    let location_before = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture location");
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("corrupt authoritative replay state must fail closed");
    assert!(
        error.to_string().contains(expected_message),
        "unexpected replay error: {error}"
    );
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&archive_before)
    );
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location_before)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn exact_archive_location_replay_ignores_stale_revision_without_mutation() {
    let seed = 0x41;
    let (world, authority, key, instruction) = archive_location_replay_fixture(seed);
    let archive_id = instruction.archive_id;
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let archive_before = transaction
        .world
        .musubi_archives
        .get(&archive_id)
        .cloned()
        .expect("fixture archive");
    let location_before = transaction
        .world
        .musubi_archive_locations
        .get(&key)
        .cloned()
        .expect("fixture location");
    instruction
        .execute(&authority, &mut transaction)
        .expect("an exact replay must not require the consumed CAS revision");
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&archive_before)
    );
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location_before)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn exact_archive_location_replay_rejects_a_malformed_stored_location() {
    let seed = 0x44;
    let (mut world, authority, key, instruction) = archive_location_replay_fixture(seed);
    let mut malformed = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture location");
    malformed.providers.clear();
    world
        .musubi_archive_locations
        .insert(key, malformed.clone());
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("an exact replay must not bless malformed authoritative state");
    assert!(error.to_string().contains("archive location is invalid"));
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&malformed)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn exact_archive_location_replay_rejects_a_future_location_revision() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x4A,
        |world, key, _| {
            let mut location = world
                .musubi_archive_locations
                .view()
                .get(&key)
                .cloned()
                .expect("fixture location");
            location.revision = world
                .musubi_archives
                .view()
                .get(&key.archive_id)
                .expect("fixture archive")
                .location_revision
                .checked_add(1)
                .expect("fixture revision remains bounded");
            world.musubi_archive_locations.insert(key, location);
        },
        "location revision or finalized height is inconsistent",
    );
}
#[test]
fn exact_archive_location_replay_rejects_mismatched_immutable_attestation_evidence() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x4B,
        |world, key, _| {
            let location = world
                .musubi_archive_locations
                .view()
                .get(&key)
                .cloned()
                .expect("fixture location");
            let attestation_key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: key.archive_id,
                replication_order: location.replication_order,
                provider_id: location.providers[0],
            };
            let mut record = world
                .musubi_provider_bundle_attestations
                .view()
                .get(&attestation_key)
                .cloned()
                .expect("fixture provider attestation");
            record.attestation.payload.binding.bundle_digest =
                MusubiContentDigestV1::new([0xEE; 32]);
            record.attestation_digest = record.attestation.digest();
            world
                .musubi_provider_bundle_attestations
                .insert(attestation_key, record);
        },
        "attestation does not match its immutable archive commitments",
    );
}
#[test]
fn exact_archive_location_replay_rejects_an_invalid_stored_attestation_signature() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x4C,
        |world, key, _| {
            let location = world
                .musubi_archive_locations
                .view()
                .get(&key)
                .cloned()
                .expect("fixture location");
            let attestation_key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: key.archive_id,
                replication_order: location.replication_order,
                provider_id: location.providers[0],
            };
            let mut record = world
                .musubi_provider_bundle_attestations
                .view()
                .get(&attestation_key)
                .cloned()
                .expect("fixture provider attestation");
            let foreign_keypair = KeyPair::try_from_seed(vec![0xFD; 32], Algorithm::Ed25519)
                .expect("foreign fixture keypair");
            record.attestation.approvals[0].public_key = foreign_keypair.public_key().clone();
            record.attestation_digest = record.attestation.digest();
            world
                .musubi_provider_bundle_attestations
                .insert(attestation_key, record);
        },
        "approval is not a completion-signer key",
    );
}
#[test]
fn exact_archive_location_replay_rejects_a_missing_pin_reverse_reference() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x45,
        |world, _, instruction| {
            let mut block = world.musubi_locations_by_pin.block();
            let _ = block.remove(instruction.pin_manifest);
            block.commit();
        },
        "pin reverse index is inconsistent",
    );
}
#[test]
fn exact_archive_location_replay_rejects_an_inactive_order_reverse_reference() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x46,
        |world, _, instruction| {
            let mut reference = world
                .musubi_locations_by_replication_order
                .view()
                .get(&instruction.replication_order)
                .cloned()
                .expect("fixture order reverse reference");
            reference.lifecycle = MusubiReplicationOrderLocationLifecycleV1::PreLocation;
            world
                .musubi_locations_by_replication_order
                .insert(instruction.replication_order, reference);
        },
        "order reverse index is inconsistent",
    );
}
#[test]
fn exact_archive_location_replay_rejects_a_missing_provider_reverse_reference() {
    assert_exact_archive_location_replay_rejects_corruption(
        0x47,
        |world, key, _| {
            let provider = world
                .musubi_archive_locations
                .view()
                .get(&key)
                .expect("fixture location")
                .providers[0];
            let mut block = world.musubi_locations_by_provider.block();
            let _ = block.remove(MusubiProviderLocationKeyV1::new(provider, key));
            block.commit();
        },
        "provider reverse index is inconsistent",
    );
}
#[test]
fn exact_archive_location_replay_ignores_mutable_sorafs_degradation() {
    let seed = 0x48;
    let (mut world, authority, key, instruction) = archive_location_replay_fixture(seed);
    let archive_id = instruction.archive_id;
    let mut pin = world
        .pin_manifests
        .view()
        .get(&instruction.pin_manifest)
        .cloned()
        .expect("fixture pin manifest");
    pin.retire(2, Some("fixture lifecycle degradation".to_owned()));
    world.pin_manifests.insert(instruction.pin_manifest, pin);
    let mut order = world
        .replication_orders
        .view()
        .get(&instruction.replication_order)
        .cloned()
        .expect("fixture replication order");
    order.status = ReplicationOrderStatus::Expired(2);
    world
        .replication_orders
        .insert(instruction.replication_order, order);
    let provider = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .expect("fixture location")
        .providers[0];
    let mut provider_owners = world.provider_owners.block();
    let _ = provider_owners.remove(provider);
    provider_owners.commit();
    let archive_before = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .cloned()
        .expect("fixture archive");
    let location_before = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture location");
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    instruction
        .execute(&authority, &mut transaction)
        .expect("later mutable SoraFS degradation must not invalidate an exact replay");
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&archive_before)
    );
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location_before)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn changed_archive_location_replay_still_requires_current_revision() {
    let seed = 0x42;
    let (world, authority, key, mut instruction) = archive_location_replay_fixture(seed);
    let archive_id = instruction.archive_id;
    instruction.expires_at_epoch = instruction
        .expires_at_epoch
        .checked_add(1)
        .expect("fixture expiry remains bounded");
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let archive_before = transaction
        .world
        .musubi_archives
        .get(&archive_id)
        .cloned()
        .expect("fixture archive");
    let location_before = transaction
        .world
        .musubi_archive_locations
        .get(&key)
        .cloned()
        .expect("fixture location");
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("changed location content must not bypass compare-and-set");
    assert!(
        error
            .to_string()
            .contains("stale Musubi archive location revision")
    );
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&archive_before)
    );
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location_before)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn retired_archive_location_identity_rejects_exact_stale_replay() {
    let seed = 0x43;
    let (mut world, authority, key, instruction) = archive_location_replay_fixture(seed);
    let mut retired = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .expect("fixture location");
    retired.state = MusubiArchiveLocationStateV1::Retired;
    world.musubi_archive_locations.insert(key, retired.clone());
    let state = archive_location_replay_state(world);
    let mut block = archive_location_replay_block(&state);
    let mut transaction = block.transaction();
    let error = instruction
        .execute(&authority, &mut transaction)
        .expect_err("a retired location identity must never be replayed or reused");
    assert!(
        error
            .to_string()
            .contains("retired archive location identities")
    );
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&retired)
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn replication_shortfall_transition_is_checked_and_boundary_scoped() {
    use MusubiStorageAvailabilityV1::{BelowQuorum, Selectable, Unavailable};
    assert_eq!(
        plan_replication_shortfall_transition(5, Selectable, BelowQuorum, 3)
            .expect("selectable-to-shortfall transition"),
        Some(8)
    );
    assert_eq!(
        plan_replication_shortfall_transition(5, Selectable, Unavailable, 3)
            .expect("selectable-to-unavailable transition"),
        Some(8)
    );
    assert_eq!(
        plan_replication_shortfall_transition(5, BelowQuorum, Selectable, 3)
            .expect("shortfall-to-selectable transition"),
        Some(2)
    );
    assert_eq!(
        plan_replication_shortfall_transition(5, Unavailable, Selectable, 3)
            .expect("unavailable-to-selectable transition"),
        Some(2)
    );
    assert_eq!(
        plan_replication_shortfall_transition(5, BelowQuorum, Unavailable, 3)
            .expect("non-selectable transition"),
        None
    );
    assert_eq!(
        plan_replication_shortfall_transition(5, Selectable, BelowQuorum, 0)
            .expect("empty reverse-reference transition"),
        None
    );
    assert!(
        plan_replication_shortfall_transition(u64::MAX, Selectable, BelowQuorum, 1).is_err(),
        "consensus aggregate overflow must fail closed"
    );
    assert!(
        plan_replication_shortfall_transition(0, Unavailable, Selectable, 1).is_err(),
        "consensus aggregate underflow must fail closed"
    );
}
#[test]
fn availability_refresh_preflights_resolver_rows_and_packages_before_mutation() {
    let mut world = World::new();
    let archive = retention_archive(17);
    let archive_id = archive.archive_id;
    let source_digest = archive.commitment.source_tree_digest;
    let release = retention_release(
        archive_id,
        "1.0.0",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    );
    let release_id = release.manifest.release.clone();
    let resolver_release = release.clone();
    seed_retention_archive(&mut world, archive, vec![release]);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("nonzero fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let availability_before = *transaction
        .world
        .musubi_archive_availability
        .get(&archive_id)
        .expect("fixture archive has availability");
    let index_revision_before = transaction.world.musubi_resolver_index_revision.get().get();
    let shortfall_before = *transaction
        .world
        .musubi_replication_shortfall_releases
        .get();
    let error = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("a reverse-referenced release must have an exact resolver row");
    assert!(error.to_string().contains("missing its exact resolver row"));
    assert!(
        transaction
            .world
            .musubi_resolver_index
            .get(&release_id)
            .is_none()
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert_eq!(
        *transaction
            .world
            .musubi_replication_shortfall_releases
            .get(),
        shortfall_before
    );
    let row = MusubiResolverReleaseRowV1 {
        release: release_id.clone(),
        release_digest: resolver_release.release_digest,
        archive_id,
        source_digest,
        interface_digest: resolver_release.manifest.interface_digest,
        abi: resolver_release.manifest.abi,
        dependencies: resolver_release.manifest.dependencies.clone(),
        selection: MusubiReleaseSelectionStateV1 {
            yank: resolver_release.yank,
            storage: availability_before,
            governance: resolver_release.artifact_governance,
        },
        index_revision: index_revision_before,
    };
    row.validate().expect("fixture resolver row is canonical");
    transaction
        .world
        .musubi_resolver_index
        .insert(release_id, row);
    let error = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("a reverse-referenced release must retain its package record");
    assert!(error.to_string().contains("missing package record"));
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert_eq!(
        *transaction
            .world
            .musubi_replication_shortfall_releases
            .get(),
        shortfall_before
    );
}
#[test]
fn availability_refresh_rejects_an_invalid_archive_before_mutation() {
    let mut world = World::new();
    let mut archive = retention_archive(18);
    let archive_id = archive.archive_id;
    archive.location_revision = 0;
    seed_retention_archive(&mut world, archive.clone(), Vec::new());
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("nonzero fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let availability_before = *transaction
        .world
        .musubi_archive_availability
        .get(&archive_id)
        .expect("fixture archive has availability");
    let index_revision_before = transaction.world.musubi_resolver_index_revision.get().get();
    let error = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("an invalid authoritative archive must fail closed");
    assert!(error.to_string().contains("archive record"));
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&archive)
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn availability_refresh_rejects_a_mismatched_archive_identity_before_mutation() {
    let mut world = World::new();
    let canonical = retention_archive(19);
    let archive_id = canonical.archive_id;
    let mismatched = retention_archive(20);
    mismatched
        .validate()
        .expect("mismatched archive fixture is structurally valid");
    seed_retention_archive(&mut world, canonical, Vec::new());
    world.musubi_archives.insert(archive_id, mismatched.clone());
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("nonzero fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let availability_before = *transaction
        .world
        .musubi_archive_availability
        .get(&archive_id)
        .expect("fixture archive has availability");
    let index_revision_before = transaction.world.musubi_resolver_index_revision.get().get();
    let error = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("an archive stored under another identity must fail closed");
    assert!(
        error
            .to_string()
            .contains("wrong embedded archive identity")
    );
    assert_eq!(
        transaction.world.musubi_archives.get(&archive_id),
        Some(&mismatched)
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn availability_refresh_preflights_location_validation_and_identity() {
    let mut world = World::new();
    let mut archive = retention_archive(21);
    let archive_id = archive.archive_id;
    let location_id = MusubiArchiveLocationIdV1::new([0x51; 32]);
    archive.location_ids = vec![location_id];
    archive
        .validate()
        .expect("archive with one location identity is valid");
    seed_retention_archive(&mut world, archive.clone(), Vec::new());
    let key = MusubiArchiveLocationKeyV1::new(archive_id, location_id);
    let mut location = location_fixture(
        0x51,
        iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x52; 32]),
        iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new([0x53; 32]),
    );
    location.archive_id = archive_id;
    location.location_id = location_id;
    world.musubi_archive_locations.insert(key, location.clone());
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(2).expect("nonzero fixture height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let availability_before = *transaction
        .world
        .musubi_archive_availability
        .get(&archive_id)
        .expect("fixture archive has availability");
    let index_revision_before = transaction.world.musubi_resolver_index_revision.get().get();
    let invalid = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("a malformed location must fail before availability changes");
    assert!(invalid.to_string().contains("archive location is invalid"));
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location)
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
    location.location_id = MusubiArchiveLocationIdV1::new([0x54; 32]);
    transaction
        .world
        .musubi_archive_locations
        .insert(key, location.clone());
    let mismatched = refresh_archive_availability(archive_id, &mut transaction)
        .expect_err("a location stored under another identity must fail closed");
    assert!(mismatched.to_string().contains("wrong embedded identity"));
    assert_eq!(
        transaction.world.musubi_archive_locations.get(&key),
        Some(&location)
    );
    assert_eq!(
        transaction
            .world
            .musubi_archive_availability
            .get(&archive_id),
        Some(&availability_before)
    );
    assert_eq!(
        transaction.world.musubi_resolver_index_revision.get().get(),
        index_revision_before
    );
    assert!(take_musubi_events(&mut transaction).is_empty());
}
#[test]
fn archive_retention_uses_cached_finalized_time_for_the_exact_snapshot() {
    const FINALIZED_TIME_MS: u64 = 1_700_000_000_000;
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).expect("nonzero finalized height"),
        None,
        None,
        FINALIZED_TIME_MS,
        0,
    );
    let header_hash = header.hash();
    let state = State::new_with_chain_and_network_id_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("retention-finalized-time-test"),
        iroha_data_model::NetworkId::from_genesis_hash(header_hash),
    );
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(header_hash);
        block_hashes.commit_for_tests();
    }
    state.update_latest_block_header_cache_for_tests(header);
    let snapshot = MusubiRegistrySnapshotV1 {
        finalized_height: 1,
        finalized_block_hash: *header_hash.as_ref(),
        index_revision: state.view().world().musubi_resolver_index_revision(),
    };
    let query = |expected_snapshot| {
        FindMusubiArchiveRetentionV1::new(MusubiArchiveRetentionQueryV1 {
            archive_ids: vec![ArchiveId::new([0x73; 32])],
            expected_snapshot,
        })
    };
    let response = ValidSingularQuery::execute(&query(Some(snapshot)), &state.view())
        .expect("exact finalized snapshot");
    assert_eq!(response.snapshot, snapshot);
    assert_eq!(response.finalized_time_ms, FINALIZED_TIME_MS);
    let mut mismatched_height = snapshot;
    mismatched_height.finalized_height += 1;
    assert!(matches!(
        ValidSingularQuery::execute(&query(Some(mismatched_height)), &state.view()),
        Err(QueryExecutionFail::Expired)
    ));
    let mut mismatched_hash = snapshot;
    mismatched_hash.finalized_block_hash = [0x72; 32];
    assert!(matches!(
        ValidSingularQuery::execute(&query(Some(mismatched_hash)), &state.view()),
        Err(QueryExecutionFail::Expired)
    ));
}
#[test]
fn archive_retention_point_lookups_keep_active_yanked_and_unknown_archives() {
    let mut world = World::new();
    let unreferenced = seed_retention_archive(&mut world, retention_archive(11), Vec::new());
    let referenced_archive = retention_archive(21);
    let referenced = referenced_archive.archive_id;
    let takedown = |seed| {
        MusubiArtifactGovernanceStateV1::TakenDown(MusubiArtifactTakedownV1 {
            action_digest: MusubiGovernanceActionDigestV1::new([seed; 32]),
            reason: "Parliament fixture".parse().expect("takedown reason"),
            applied_at_height: 1,
        })
    };
    seed_retention_archive(
        &mut world,
        referenced_archive,
        vec![
            retention_release(
                referenced,
                "1.0.0",
                false,
                MusubiArtifactGovernanceStateV1::Available,
            ),
            retention_release(
                referenced,
                "1.1.0",
                true,
                MusubiArtifactGovernanceStateV1::Available,
            ),
            retention_release(referenced, "1.2.0", false, takedown(31)),
        ],
    );
    let taken_down_archive = retention_archive(41);
    let taken_down = taken_down_archive.archive_id;
    seed_retention_archive(
        &mut world,
        taken_down_archive,
        vec![retention_release(taken_down, "2.0.0", true, takedown(42))],
    );
    let view = world.view();
    let unknown =
        archive_retention_decision(ArchiveId::new([0xF1; 32]), &view).expect("unknown decision");
    assert_eq!(
        unknown.disposition,
        MusubiArchiveRetentionDispositionV1::RetainUnknown
    );
    assert!(unknown.must_retain());
    let unreferenced =
        archive_retention_decision(unreferenced, &view).expect("unreferenced decision");
    assert_eq!(
        unreferenced.disposition,
        MusubiArchiveRetentionDispositionV1::PruneUnreferenced
    );
    let referenced = archive_retention_decision(referenced, &view).expect("referenced decision");
    assert_eq!(
        referenced.disposition,
        MusubiArchiveRetentionDispositionV1::RetainReferenced
    );
    assert_eq!(referenced.active_releases, 1);
    assert_eq!(referenced.yanked_releases, 1);
    assert_eq!(referenced.taken_down_releases, 1);
    assert!(referenced.must_retain());
    let taken_down = archive_retention_decision(taken_down, &view).expect("taken-down decision");
    assert_eq!(
        taken_down.disposition,
        MusubiArchiveRetentionDispositionV1::PruneGovernedTakedown
    );
    assert_eq!(taken_down.taken_down_releases, 1);
    assert!(!taken_down.must_retain());
}
#[test]
fn archive_retention_point_lookups_reject_projection_identity_mismatches() {
    let mut world = World::new();
    let archive = retention_archive(51);
    let archive_id = seed_retention_archive(&mut world, archive.clone(), Vec::new());
    let other_archive_id = retention_archive(52).archive_id;
    let valid_storage = world
        .musubi_archive_availability
        .view()
        .get(&archive_id)
        .cloned()
        .expect("seeded archive availability");
    world
        .musubi_archives
        .insert(archive_id, retention_archive(52));
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
    world.musubi_archives.insert(archive_id, archive.clone());
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id: other_archive_id,
            releases: Vec::new(),
        },
    );
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: Vec::new(),
        },
    );
    let mut mismatched_storage = valid_storage.clone();
    mismatched_storage.archive_id = other_archive_id;
    world
        .musubi_archive_availability
        .insert(archive_id, mismatched_storage);
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
    world
        .musubi_archive_availability
        .insert(archive_id, valid_storage);
    let missing_release = retention_release(
        archive_id,
        "1.0.0",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    )
    .manifest
    .release;
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: vec![missing_release],
        },
    );
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
    let mut mismatched_release = retention_release(
        archive_id,
        "2.0.0",
        false,
        MusubiArtifactGovernanceStateV1::Available,
    );
    let referenced_release = mismatched_release.manifest.release.clone();
    mismatched_release.manifest.release = MusubiReleaseIdV1::new(
        package("retention"),
        "2.1.0".parse().expect("mismatched release version"),
    );
    mismatched_release.yank.release = mismatched_release.manifest.release.clone();
    mismatched_release.release_digest = mismatched_release.manifest.release_digest();
    world
        .musubi_releases
        .insert(referenced_release.clone(), mismatched_release);
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: vec![referenced_release],
        },
    );
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
    let mut wrong_archive_release = retention_release(
        archive_id,
        "3.0.0",
        true,
        MusubiArtifactGovernanceStateV1::Available,
    );
    let referenced_release = wrong_archive_release.manifest.release.clone();
    wrong_archive_release.manifest.archive_id = other_archive_id;
    wrong_archive_release.release_digest = wrong_archive_release.manifest.release_digest();
    world
        .musubi_releases
        .insert(referenced_release.clone(), wrong_archive_release);
    world.musubi_archive_reverse_references.insert(
        archive_id,
        MusubiArchiveReverseReferencesV1 {
            archive_id,
            releases: vec![referenced_release],
        },
    );
    assert!(archive_retention_decision(archive_id, &world.view()).is_err());
}
#[test]
fn pagination_continues_after_exact_last_key() {
    let request = MusubiPageRequestV1 {
        limit: 2,
        cursor: None,
    };
    let hash = query_hash(b"test", b"request");
    let rows = vec![
        ("a".to_owned(), 1_u8),
        ("b".to_owned(), 2_u8),
        ("c".to_owned(), 3_u8),
    ];
    let (first, cursor) = paginate(rows.clone(), &request, hash, snapshot(1)).expect("first page");
    assert_eq!(first, vec![1, 2]);
    let cursor = cursor.expect("continuation");
    assert_eq!(cursor.last_key, "b");
    let request = MusubiPageRequestV1 {
        limit: 2,
        cursor: Some(cursor),
    };
    let (second, cursor) = paginate(rows, &request, hash, snapshot(1)).expect("second page");
    assert_eq!(second, vec![3]);
    assert!(cursor.is_none());
}
#[test]
fn pagination_accepts_the_longest_canonical_semver_cursor_tail() {
    let prerelease = vec![
        MusubiPrereleaseIdentifierV1::AlphaNumeric(
            "a".repeat(MUSUBI_MAX_PRERELEASE_IDENTIFIER_BYTES_V1),
        );
        MUSUBI_MAX_PRERELEASE_IDENTIFIERS_V1
    ];
    let maximum_prerelease = MusubiVersionV1::new(u64::MAX, u64::MAX, u64::MAX, prerelease)
        .expect("maximum bounded prerelease version");
    let stable = MusubiVersionV1::new(u64::MAX, u64::MAX, u64::MAX, Vec::new())
        .expect("stable maximum version");
    assert!(maximum_prerelease < stable);
    let maximum_text = maximum_prerelease.to_string();
    assert_eq!(maximum_text.len(), MUSUBI_MAX_VERSION_CURSOR_KEY_BYTES_V1);
    let rows = vec![
        (maximum_text.clone(), maximum_prerelease.clone()),
        (stable.to_string(), stable.clone()),
    ];
    let query_hash = query_hash(b"versions", b"maximum-semver-cursor");
    let request = MusubiPageRequestV1 {
        limit: 1,
        cursor: None,
    };
    let page_snapshot = snapshot(1);
    let (first, cursor) = paginate(rows.clone(), &request, query_hash, page_snapshot)
        .expect("maximum semantic version fits a finalized cursor");
    assert_eq!(first, vec![maximum_prerelease.clone()]);
    let cursor = cursor.expect("stable maximum remains after the prerelease");
    assert_eq!(cursor.last_key, maximum_text);
    cursor
        .validate()
        .expect("the longest canonical semantic version is a valid cursor key");
    let start = package_release_page_start(
        &package("maximum-version-cursor"),
        &MusubiPageRequestV1 {
            limit: 1,
            cursor: Some(cursor.clone()),
        },
    )
    .expect("version page start parses the longest canonical semantic version");
    assert_eq!(start.version, maximum_prerelease);
    let (continued, cursor) = paginate(
        rows,
        &MusubiPageRequestV1 {
            limit: 1,
            cursor: Some(cursor),
        },
        query_hash,
        page_snapshot,
    )
    .expect("pagination resumes strictly after the longest semantic-version key");
    assert_eq!(continued, vec![stable]);
    assert!(cursor.is_none());
}
#[test]
fn resolver_pagination_truncates_at_json_budget_and_continues_after_its_tail() {
    let resolver_row = |version: &str, seed: u8| {
        let archive = retention_archive(seed);
        let release = retention_release(
            archive.archive_id,
            version,
            false,
            MusubiArtifactGovernanceStateV1::Available,
        );
        MusubiResolverReleaseRowV1 {
            release: release.manifest.release.clone(),
            release_digest: release.release_digest,
            archive_id: archive.archive_id,
            source_digest: archive.commitment.source_tree_digest,
            interface_digest: release.manifest.interface_digest,
            abi: release.manifest.abi,
            dependencies: release.manifest.dependencies,
            selection: MusubiReleaseSelectionStateV1 {
                yank: release.yank,
                storage: MusubiArchiveAvailabilityV1 {
                    archive_id: archive.archive_id,
                    availability: MusubiStorageAvailabilityV1::Selectable,
                    healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                    active_locations: 1,
                    finalized_height: 7,
                    finalized_block_hash: [7; 32],
                    index_revision: 1,
                },
                governance: release.artifact_governance,
            },
            index_revision: 1,
        }
    };
    let rows = vec![
        ("1.0.0".to_owned(), resolver_row("1.0.0", 0x81)),
        ("2.0.0".to_owned(), resolver_row("2.0.0", 0x82)),
        ("3.0.0".to_owned(), resolver_row("3.0.0", 0x83)),
    ];
    rows.iter()
        .try_for_each(|(_, row)| row.validate())
        .expect("resolver fixtures are canonical");
    let two_item_budget = norito::json::to_json(&rows[0].1)
        .expect("first resolver row encodes")
        .len()
        .checked_add(1)
        .and_then(|bytes| {
            bytes.checked_add(
                norito::json::to_json(&rows[1].1)
                    .expect("second resolver row encodes")
                    .len(),
            )
        })
        .expect("two bounded resolver rows fit usize");
    let query_hash = query_hash(b"resolver-index", b"budget-test");
    let request = MusubiPageRequestV1 {
        limit: 3,
        cursor: None,
    };
    let page_snapshot = snapshot(1);
    let (first, next_cursor) = paginate_with_json_items_budget(
        rows.clone(),
        &request,
        query_hash,
        page_snapshot,
        two_item_budget,
    )
    .expect("the first resolver page fits exactly two rows");
    assert_eq!(first.len(), 2);
    let next_cursor = next_cursor.expect("the byte-truncated page has a continuation");
    assert_eq!(next_cursor.last_key, "2.0.0");
    let query = MusubiResolverIndexQueryV1 {
        package: package("retention"),
        requirement: None,
        page: request,
    };
    let response = MusubiResolverIndexPageV1 {
        query: query.clone(),
        network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x91; 32])),
        ),
        items: first,
        next_cursor: Some(next_cursor.clone()),
        snapshot: page_snapshot,
    };
    response
        .validate_for(&query)
        .expect("a nonempty short resolver page may carry its exact tail cursor");
    assert!(
        norito::json::to_json(&response)
            .expect("resolver response encodes")
            .len()
            <= MUSUBI_PUBLIC_QUERY_MAX_RESPONSE_BYTES_V1
    );
    let continued_request = MusubiPageRequestV1 {
        limit: 3,
        cursor: Some(next_cursor),
    };
    let (second, next_cursor) = paginate_with_json_items_budget(
        rows,
        &continued_request,
        query_hash,
        page_snapshot,
        two_item_budget,
    )
    .expect("the continuation advances after the exact byte-truncated tail");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].release.version.to_string(), "3.0.0");
    assert!(next_cursor.is_none());
}
#[test]
fn pagination_preserves_exact_cursor_failure_reasons() {
    fn assert_reason<T>(
        result: Result<(Vec<T>, Option<MusubiFinalizedCursorV1>), MusubiQueryExecutionErrorV1>,
        expected: MusubiCursorFailureV1,
    ) {
        let error = match result {
            Ok(_) => panic!("cursor must fail"),
            Err(error) => error,
        };
        assert_eq!(error.cursor_failure(), Some(expected));
        assert_eq!(error.into_query_error(), QueryExecutionFail::Expired);
    }
    let hash = query_hash(b"test", b"request");
    let cursor = |cursor_snapshot, query_hash, last_key: &str, caller| MusubiFinalizedCursorV1 {
        snapshot: cursor_snapshot,
        query_hash,
        last_key: last_key.to_owned(),
        caller,
    };
    let page = |cursor| MusubiPageRequestV1 {
        limit: 1,
        cursor: Some(cursor),
    };
    let mut changed_anchor = snapshot(1);
    changed_anchor.finalized_height += 1;
    assert_reason(
        paginate(
            vec![("a".to_owned(), 1_u8)],
            &page(cursor(snapshot(1), hash, "a", None)),
            hash,
            changed_anchor,
        ),
        MusubiCursorFailureV1::FinalizedAnchorMismatch,
    );
    assert_reason(
        paginate(
            vec![("a".to_owned(), 1_u8)],
            &page(cursor(snapshot(1), hash, "a", None)),
            hash,
            snapshot(2),
        ),
        MusubiCursorFailureV1::IndexRevisionMismatch,
    );
    assert_reason(
        paginate(
            vec![("a".to_owned(), 1_u8)],
            &page(cursor(
                snapshot(1),
                query_hash(b"other", b"request"),
                "a",
                None,
            )),
            hash,
            snapshot(1),
        ),
        MusubiCursorFailureV1::QueryMismatch,
    );
    let expected_caller = account(1);
    assert_reason(
        paginate_for_caller(
            vec![("a".to_owned(), 1_u8)],
            &page(cursor(snapshot(1), hash, "a", Some(account(2)))),
            hash,
            snapshot(1),
            Some(&expected_caller),
        ),
        MusubiCursorFailureV1::CallerMismatch,
    );
    assert_reason(
        paginate(
            vec![("a".to_owned(), 1_u8)],
            &page(cursor(snapshot(1), hash, "missing", None)),
            hash,
            snapshot(1),
        ),
        MusubiCursorFailureV1::LastKeyStale,
    );
    let invalid_version_cursor = page(cursor(snapshot(1), hash, "01.0.0", None));
    let error = package_release_page_start(&package("cursor-test"), &invalid_version_cursor)
        .expect_err("noncanonical version boundary must fail");
    assert_eq!(
        error.cursor_failure(),
        Some(MusubiCursorFailureV1::LastKeyStale)
    );
}
include!("archive_replay_hash_tests.rs");
#[test]
fn owned_borrowed_musubi_page_sources_preserve_exact_wire_bytes() {
    fn assert_owned_projection<S, T>(source: &S, owned: &T)
    where
        S: norito::SerializePayload,
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + PartialEq
            + std::fmt::Debug,
    {
        assert_eq!(source.encode(), owned.encode());
        let bytes = crate::smartcontracts::isi::query::encode_singular_query_source_for_test::<_, T>(
            source,
        );
        assert_eq!(
            bytes,
            norito::encode_canonical(owned).expect("owned page frame")
        );
        let decoded: T = norito::decode_canonical(&bytes).expect("decode projected page frame");
        assert_eq!(&decoded, owned);
        let mut substituted = bytes.clone();
        substituted[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<T>(&substituted),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(norito::decode_canonical::<T>(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(norito::decode_canonical::<T>(&trailing).is_err());
    }
    let snapshot = snapshot(19);
    let archive = retention_archive(0x41);
    let network_id = archive.staging_receipt.payload.binding.network_id;
    let resolver_query = MusubiResolverIndexQueryV1 {
        package: package("bounded-resolver-page"),
        requirement: Some("^1.2.3".parse().expect("version requirement")),
        page: MusubiPageRequestV1 {
            limit: 7,
            cursor: None,
        },
    };
    assert_owned_projection(
        &MusubiResolverIndexPageSource {
            query: &resolver_query,
            network_id,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiResolverIndexPageV1 {
            query: resolver_query.clone(),
            network_id,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
    let package_query = MusubiPackagePageQueryV1 {
        package: package("bounded-package-page"),
        page: MusubiPageRequestV1 {
            limit: 11,
            cursor: None,
        },
    };
    assert_owned_projection(
        &MusubiVersionPageSource {
            query: &package_query,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiVersionPageV1 {
            query: package_query.clone(),
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
    assert_owned_projection(
        &MusubiMaintainerPageSource {
            query: &package_query,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiMaintainerPageV1 {
            query: package_query.clone(),
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
    assert_owned_projection(
        &MusubiArchiveLocationPageSource {
            network_id,
            archive: &archive,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiArchiveLocationPageV1 {
            network_id,
            archive: archive.clone(),
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
    let alias_query = MusubiAliasQueryV1 {
        alias: "bounded-page".parse().expect("alias"),
        page: MusubiPageRequestV1 {
            limit: 13,
            cursor: None,
        },
    };
    assert_owned_projection(
        &MusubiAliasHistoryPageSource {
            query: &alias_query,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiAliasHistoryPageV1 {
            query: alias_query.clone(),
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
    let ordered_query = MusubiOrderedPrefixQueryV1 {
        prefix: MusubiOrderedPrefixV1::new("sora/bounded-").expect("ordered prefix"),
        page: MusubiPageRequestV1 {
            limit: 17,
            cursor: None,
        },
    };
    let namespace_binding = MusubiNamespaceBindingV1 {
        namespace: "sora".parse().expect("namespace"),
        home_dataspace: DataSpaceId::new(7),
        scope: MusubiPackageScopeV1::DataspaceRoot,
        generation: 1,
    };
    assert_owned_projection(
        &MusubiOrderedPackagePageSource {
            query: &ordered_query,
            network_id,
            namespace_binding: &namespace_binding,
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        &MusubiOrderedPackagePageV1 {
            query: ordered_query.clone(),
            network_id,
            namespace_binding: namespace_binding.clone(),
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
    );
}
