use super::*;
use crate::provider_ingest_outbox::{
    ProviderIngestCompletionStateV1, ProviderIngestDeliveryStateV1, ProviderIngestOutboxPolicyV1,
};
use crate::{
    FinalizedProviderIngestError, NodeHandle,
    config::StorageConfig,
    provider_attestation_journal::{
        MusubiProviderAttestationInventoryErrorV1, MusubiProviderAttestationInventoryItemV1,
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryReadbackV1, MusubiProviderAttestationInventoryReaderV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
        MusubiProviderAttestationInventoryRuntimeV1, MusubiProviderAttestationInventoryScopeV1,
        MusubiProviderAttestationInventorySinkV1, MusubiProviderAttestationInventoryV1,
        MusubiProviderAttestationJournalCasOutcomeV1, MusubiProviderAttestationJournalPolicyV1,
        MusubiProviderAttestationJournalStoreErrorV1,
        MusubiProviderAttestationJournalStoreSnapshotV1, MusubiProviderAttestationJournalStoreV1,
        MusubiProviderAttestationJournalV1, musubi_provider_attestation_approval_id_v1,
        musubi_provider_attestation_journal_checkpoint_revision_v1,
    },
    scheduler::{StorageSchedulerConfig, StorageSchedulersRuntime},
    store::StorageBackend,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    isi::{InstructionBox, sorafs::CompleteReplicationOrder},
    musubi::{
        MusubiAbiBindingV1, MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1,
        MusubiProviderBundleVerificationApprovalV1, MusubiProviderBundleVerificationAttestationV1,
        MusubiReleaseIdV1, MusubiReleaseMetadataV1, MusubiSemanticReleaseManifestV1,
        MusubiVerificationLockV1,
    },
    sorafs::pin_registry::{
        ChunkerProfileHandle, ManifestDigest, ManifestRootCid, PinManifestFinalizedCursorV1,
        PinManifestRecord, PinPolicy, ProviderIngestFinalizedAnchorV1,
        ReplicationOrderCompletionRecord, ReplicationOrderId,
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use norito::decode_from_bytes_with_limits;
use sorafs_car::{
    CarBuildPlan, CarWriter, FileEntry, compute_chunk_plan_digest_sha3, compute_por_root,
    musubi::{
        MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1, MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1,
        MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1, MusubiBundleVerifierV1,
    },
};
use sorafs_manifest::{
    BLAKE3_256_MULTIHASH_CODE, DagCodecId, ManifestBuilder, ManifestV1,
    capacity::{REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1},
};
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
const LOCAL_PROVIDER: [u8; 32] = [0x11; 32];
const SOURCE_PROVIDER: [u8; 32] = [0x22; 32];
const THIRD_PROVIDER: [u8; 32] = [0x33; 32];
const TEST_GENESIS_BLOCK_HASH: [u8; 32] = [0xA7; 32];
fn test_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(TEST_GENESIS_BLOCK_HASH),
    ))
}
fn unmarked_test_network_id() -> NetworkId {
    let mut hash = Hash::prehashed([0; 32]);
    // Test-only logically invalid material: the safe Hash representation has no invalid bit pattern.
    iroha_crypto::zeroize_value_for_confidential_discard(&mut hash);
    assert_eq!(
        hash.as_ref()[31] & 1,
        0,
        "negative fixture must actually be unmarked"
    );
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(hash))
}
fn foreign_test_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0xB7; 32]),
    ))
}
fn validate_assignment(
    row: &ProviderIngestFinalizedAssignmentV1,
    cursor: ProviderIngestFinalizedCursorV1,
    provider_id: [u8; 32],
    policy: ProviderIngestRuntimePolicyV1,
) -> Result<ValidatedAssignmentV1, ProviderIngestRuntimeErrorV1> {
    super::validate_assignment(row, cursor, provider_id, &test_network_id(), policy)
}
fn account(seed: u8) -> AccountId {
    let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key");
    AccountId::new(key.public_key().clone())
}
fn cursor(height: u64) -> ProviderIngestFinalizedCursorV1 {
    ProviderIngestFinalizedCursorV1 {
        height,
        block_hash: [u8::try_from(height).unwrap_or(0xFE); 32],
    }
}
fn completion_signer_policy(revision: u64) -> ProviderIngestCompletionSignerPolicyV1 {
    let digest_byte = u8::try_from(revision).unwrap_or(0xFE);
    ProviderIngestCompletionSignerPolicyV1 {
        policy_id: [0xA1; 32],
        revision,
        predecessor_digest: (revision > 1).then(|| [digest_byte.saturating_sub(1); 32]),
        policy_digest: [digest_byte; 32],
    }
}
#[test]
fn completion_signer_binding_rejects_test_handles_stale_revisions_and_key_mismatch() {
    let key =
        KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519).expect("completion signer key");
    let authority = AccountId::new(key.public_key().clone());
    let qualification = ProviderIngestCompletionSignerQualificationV1::new(
        1,
        completion_signer_policy(1),
        Algorithm::Ed25519,
        key.public_key().clone(),
    );
    assert!(qualification.matches_authority(&authority));
    assert_eq!(qualification.validate(), Ok(()));
    assert_eq!(
        ProviderIngestCompletionSignerBindingV1::new(
            "provider:sorafs-provider-ingest-primary",
            qualification.clone(),
        )
        .validate(),
        Ok(())
    );
    assert_eq!(
        ProviderIngestCompletionSignerBindingV1::new(
            "provider:sorafs-provider-ingest-test",
            qualification.clone(),
        )
        .validate(),
        Err(ProviderIngestCompletionSignerBindingErrorV1::InvalidSignerHandle)
    );
    let mut stale = qualification.clone();
    stale.adapter_revision = 0;
    assert_eq!(
        stale.validate(),
        Err(ProviderIngestCompletionSignerBindingErrorV1::InvalidSignerQualification)
    );
    let mut mismatched_algorithm = qualification;
    mismatched_algorithm.algorithm = Algorithm::MlDsa;
    assert_eq!(
        mismatched_algorithm.validate(),
        Err(ProviderIngestCompletionSignerBindingErrorV1::InvalidSignerQualification)
    );
}
fn completion_record(
    provider_id: ProviderId,
    completed_by: AccountId,
    completion_epoch: u64,
) -> ReplicationOrderCompletionRecord {
    ReplicationOrderCompletionRecord {
        provider_id,
        completed_by: completed_by.clone(),
        completion_epoch,
        assignment_revision: 1,
        completion_authority: ProviderIngestCompletionAuthorityV1::new(
            (completed_by).clone(),
            completed_by,
            completion_signer_policy(1),
        ),
        finalized_anchor: ProviderIngestFinalizedAnchorV1 {
            height: completion_epoch,
            block_hash: cursor(completion_epoch).block_hash,
        },
    }
}
fn fixture_row(order_seed: u8) -> ProviderIngestFinalizedAssignmentV1 {
    let digest = ManifestDigest::new([order_seed.wrapping_add(0x40); 32]);
    let root = ManifestRootCid::from_blake3_digest([order_seed.wrapping_add(0x50); 32]).unwrap();
    let chunker = ChunkerProfileHandle {
        profile_id: 1,
        namespace: "sorafs".to_owned(),
        name: "sf1".to_owned(),
        semver: "1.0.0".to_owned(),
        multihash_code: 0x1f,
    };
    let mut manifest = PinManifestRecord::new(
        digest,
        root.clone(),
        chunker,
        [order_seed.wrapping_add(0x60); 32],
        [order_seed.wrapping_add(0x70); 32],
        4_096,
        PinPolicy::default(),
        account(1),
        7,
        None,
        None,
        Metadata::default(),
    );
    manifest.approve(7, None);
    let order_id = [order_seed; 32];
    let order_body = ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id,
        manifest_cid: root.as_bytes().to_vec(),
        manifest_digest: *digest.as_bytes(),
        chunking_profile: "sorafs.sf1@1.0.0".to_owned(),
        target_replicas: 2,
        assignments: vec![
            ReplicationAssignmentV1 {
                provider_id: LOCAL_PROVIDER,
                slice_gib: 1,
                lane: None,
            },
            ReplicationAssignmentV1 {
                provider_id: SOURCE_PROVIDER,
                slice_gib: 1,
                lane: None,
            },
        ],
        issued_at: 7,
        deadline_at: 20,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: 10,
            min_availability_percent_milli: 99_000,
            min_por_success_percent_milli: 99_000,
        },
        metadata: Vec::new(),
    };
    order_body.validate().expect("valid order");
    ProviderIngestFinalizedAssignmentV1 {
        pin: PinManifestFinalizedRecordV1 {
            finalized_cursor: PinManifestFinalizedCursorV1 {
                height: 8,
                block_hash: cursor(8).block_hash,
            },
            manifest,
        },
        order: ReplicationOrderRecord {
            order_id: ReplicationOrderId::new(order_id),
            manifest_digest: digest,
            manifest_root_cid: root,
            musubi_archive: None,
            issued_by: account(1),
            issued_epoch: 7,
            deadline_epoch: 20,
            canonical_order: norito::encode_canonical(&order_body).expect("order bytes"),
            assignment_revision: 1,
            provider_completions: Vec::new(),
            status: ReplicationOrderStatus::Pending,
        },
        musubi_archive: None,
        completed_musubi_archive: None,
        provider_owner: Some(account(8)),
        completion_authority: Some(ProviderIngestCompletionAuthorityV1::new(
            (account(8)).clone(),
            account(8),
            completion_signer_policy(1),
        )),
        completion_epoch: Some(8),
        committed_transaction_hash: None,
    }
}
fn fixture_page(
    row: ProviderIngestFinalizedAssignmentV1,
) -> ProviderIngestFinalizedAssignmentPageV1 {
    let finalized_cursor = ProviderIngestFinalizedCursorV1 {
        height: row.pin.finalized_cursor.height,
        block_hash: row.pin.finalized_cursor.block_hash,
    };
    ProviderIngestFinalizedAssignmentPageV1 {
        finalized_cursor,
        finalized_block_time_ms: finalized_cursor.height.saturating_mul(1_000),
        rows: vec![row],
        next_after_order_id: None,
    }
}
fn musubi_binding_for_row(
    row: &ProviderIngestFinalizedAssignmentV1,
    seed: u8,
) -> MusubiReplicationOrderArchiveBindingV1 {
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: row.pin.manifest.root_cid.clone(),
        chunker: row.pin.manifest.chunker.clone(),
        chunk_plan_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(
            row.pin.manifest.chunk_digest_sha3_256,
        ),
        por_root: iroha_data_model::musubi::MusubiContentDigestV1::new(row.pin.manifest.por_root),
        content_length: row.pin.manifest.content_length,
        car_digest: iroha_data_model::musubi::MusubiContentDigestV1::new([seed; 32]),
        car_size: row.pin.manifest.content_length.saturating_add(1_024),
        bundle_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(
            [seed.wrapping_add(1); 32],
        ),
        source_tree_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(
            [seed.wrapping_add(2); 32],
        ),
        descriptor_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(
            [seed.wrapping_add(3); 32],
        ),
        file_count: 1,
        chunk_count: 1,
    };
    MusubiReplicationOrderArchiveBindingV1::new(
        row.order.order_id,
        commitment.archive_id(),
        commitment,
    )
}
fn configure_musubi_replication_fixture(row: &mut ProviderIngestFinalizedAssignmentV1) {
    let mut order = decode_bound_replication_order(&row.order).expect("canonical generic fixture");
    order.target_replicas = iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1;
    order.assignments.push(ReplicationAssignmentV1 {
        provider_id: THIRD_PROVIDER,
        slice_gib: 1,
        lane: None,
    });
    order
        .validate()
        .expect("canonical three-replica Musubi order");
    assert_eq!(order.assignments.len(), usize::from(order.target_replicas));
    row.order.canonical_order = norito::encode_canonical(&order).expect("canonical Musubi order");
    row.pin.manifest.policy.min_replicas = order.target_replicas;
}
fn fixture_musubi_row(order_seed: u8, commitment_seed: u8) -> ProviderIngestFinalizedAssignmentV1 {
    let mut row = fixture_row(order_seed);
    configure_musubi_replication_fixture(&mut row);
    let binding = musubi_binding_for_row(&row, commitment_seed);
    let claim = ProviderIngestFinalizedClaimFactoryV1::new(test_network_id(), LOCAL_PROVIDER)
        .seal_musubi_archive(
            &test_network_id(),
            cursor(8),
            *row.order.order_id.as_bytes(),
            &row.pin.manifest,
            binding.clone(),
        )
        .expect("seal Musubi fixture claim");
    row.order.musubi_archive = Some(binding.archive_id);
    row.musubi_archive = Some(claim);
    row
}
fn test_verified_musubi_receipt(
    claim: &ProviderIngestFinalizedMusubiArchiveClaimV1,
    authorization: &FinalizedProviderIngestAuthorizationV1,
) -> ProviderIngestVerifiedMusubiBundleReceiptV1 {
    ProviderIngestVerifiedMusubiBundleReceiptV1 {
        network_id: *claim.network_id(),
        provider_id: claim.provider_id(),
        observed_finalized_cursor: claim.observed_finalized_cursor(),
        replication_order: claim.replication_order(),
        manifest_digest: authorization.manifest_digest(),
        archive_id: claim.archive_id(),
        commitment: claim.commitment().clone(),
        semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([0xC1; 32]),
        verification_lock_digest: MusubiVerificationLockDigestV1::new([0xC2; 32]),
    }
}
fn append_attestation_fixture_frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("fixture frame length")
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
}
fn attestation_fixture_domain_digest(domain: &[u8], material: &[u8]) -> MusubiContentDigestV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(
        &u64::try_from(material.len())
            .expect("fixture transcript length")
            .to_be_bytes(),
    );
    hasher.update(material);
    MusubiContentDigestV1::new(*hasher.finalize().as_bytes())
}
struct VerifiedAttestationBundleFixtureV1 {
    verified: VerifiedMusubiBundleV1,
    commitment: MusubiArchiveCommitmentV1,
    plan: CarBuildPlan,
    payload: Vec<u8>,
}
fn verified_attestation_bundle_fixture(source_seed: u8) -> VerifiedAttestationBundleFixtureV1 {
    const SOURCE_TREE_DOMAIN: &[u8] = b"musubi-source-tree-v1\0";
    const BUNDLE_DOMAIN: &[u8] = b"musubi-bundle-v1\0";
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "attestation-fixture".parse().expect("fixture package name"),
        ),
        "1.0.0".parse().expect("fixture version"),
    );
    let verification_lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: MUSUBI_REGISTRY_VERSION_V1,
        root: release.clone(),
        root_dependencies: Vec::new(),
        nodes: Vec::new(),
    };
    let semantic_release = MusubiSemanticReleaseManifestV1 {
        release,
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([0xA8; 32]).expect("fixture ABI"),
        dependencies: Vec::new(),
        exports: Vec::new(),
        interface_digest: MusubiContentDigestV1::new([0xA9; 32]),
        metadata: MusubiReleaseMetadataV1::default(),
        verification_lock_digest: verification_lock.digest(),
    };
    let source_path = "src/lib.ko";
    let source = vec![source_seed; 37];
    let mut source_material = Vec::new();
    append_attestation_fixture_frame(&mut source_material, SOURCE_TREE_DOMAIN);
    source_material.extend_from_slice(&1_u32.to_be_bytes());
    append_attestation_fixture_frame(&mut source_material, source_path.as_bytes());
    source_material.extend_from_slice(
        &u64::try_from(source.len())
            .expect("fixture source length")
            .to_be_bytes(),
    );
    source_material.extend_from_slice(blake3::hash(&source).as_bytes());
    let source_tree_digest =
        attestation_fixture_domain_digest(SOURCE_TREE_DOMAIN, &source_material);
    let descriptor = MusubiArtifactDescriptorV1::new(
        semantic_release.semantic_digest(),
        source_tree_digest,
        verification_lock.digest(),
        u64::try_from(source.len()).expect("fixture source length"),
        1,
    )
    .expect("fixture descriptor");
    let semantic_release_bytes = semantic_release.encode();
    let descriptor_bytes = descriptor.encode();
    let verification_lock_bytes = verification_lock.encode();
    let mut descriptor_material = Vec::new();
    append_attestation_fixture_frame(
        &mut descriptor_material,
        MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1,
    );
    append_attestation_fixture_frame(&mut descriptor_material, &descriptor_bytes);
    let descriptor_digest = attestation_fixture_domain_digest(
        MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1,
        &descriptor_material,
    );
    let mut bundle_material = Vec::new();
    for transcript in [
        BUNDLE_DOMAIN,
        semantic_release_bytes.as_slice(),
        descriptor_material.as_slice(),
        source_material.as_slice(),
        verification_lock_bytes.as_slice(),
    ] {
        append_attestation_fixture_frame(&mut bundle_material, transcript);
    }
    let bundle_digest = attestation_fixture_domain_digest(BUNDLE_DOMAIN, &bundle_material);
    let entries = vec![
        FileEntry {
            path: source_path.split('/').map(str::to_owned).collect(),
            data: source,
        },
        FileEntry {
            path: MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: semantic_release_bytes,
        },
        FileEntry {
            path: MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: descriptor_bytes,
        },
        FileEntry {
            path: MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: verification_lock_bytes,
        },
    ];
    let (plan, payload) = CarBuildPlan::from_files(entries).expect("fixture bundle plan");
    let mut car = Vec::new();
    let stats = CarWriter::new(&plan, &payload)
        .expect("fixture CAR writer")
        .write_to(&mut car)
        .expect("fixture canonical CAR");
    let chunker = sorafs_car::chunker_registry::default_descriptor();
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::try_from(stats.root_cids[0].clone()).expect("fixture root CID"),
        chunker: ChunkerProfileHandle {
            profile_id: chunker.id.0,
            namespace: chunker.namespace.to_owned(),
            name: chunker.name.to_owned(),
            semver: chunker.semver.to_owned(),
            multihash_code: chunker.multihash_code,
        },
        chunk_plan_digest: MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&plan.chunks)),
        por_root: MusubiContentDigestV1::new(
            compute_por_root(&payload, &plan).expect("fixture PoR"),
        ),
        content_length: plan.content_length,
        car_digest: MusubiContentDigestV1::new(*stats.car_archive_digest.as_bytes()),
        car_size: stats.car_size,
        bundle_digest,
        source_tree_digest,
        descriptor_digest,
        file_count: 1,
        chunk_count: u32::try_from(plan.chunks.len()).expect("fixture chunk count"),
    };
    let verified = MusubiBundleVerifierV1::verify(&plan, &car, &commitment)
        .expect("fixture canonical bundle verification");
    VerifiedAttestationBundleFixtureV1 {
        verified,
        commitment,
        plan,
        payload,
    }
}
fn completed_attestation_claim(
    commitment: MusubiArchiveCommitmentV1,
) -> ProviderIngestFinalizedMusubiCompletionClaimV1 {
    completed_attestation_claim_with_order_id(commitment, [0xAC; 32])
}
fn completed_attestation_claim_with_order_id(
    commitment: MusubiArchiveCommitmentV1,
    order_id: [u8; 32],
) -> ProviderIngestFinalizedMusubiCompletionClaimV1 {
    ProviderIngestFinalizedMusubiCompletionClaimV1 {
        network_id: test_network_id(),
        provider_id: LOCAL_PROVIDER,
        observed_finalized_cursor: cursor(8),
        binding: MusubiReplicationOrderArchiveBindingV1::new(
            ReplicationOrderId::new(order_id),
            commitment.archive_id(),
            commitment,
        ),
        completion: completion_record(ProviderId::new(LOCAL_PROVIDER), account(8), 8),
        completed_musubi_store_instance: Some(CompletedMusubiStoreInstanceV1::new()),
    }
}
fn completed_attestation_inventory_item(
    fixture: &VerifiedAttestationBundleFixtureV1,
    substitute_bundle_digest: bool,
) -> MusubiProviderAttestationInventoryItemV1 {
    let claim = completed_attestation_claim(fixture.commitment.clone());
    let request = ProviderIngestMusubiAttestationApprovalRequestV1::from_verified_completion(
        &claim,
        &fixture.verified,
    )
    .expect("derive completed-attestation inventory payload");
    let mut payload = request.payload().clone();
    if substitute_bundle_digest {
        payload.binding.bundle_digest = MusubiContentDigestV1::new([0xDD; 32]);
    }
    let owner_key = KeyPair::try_from_seed(vec![8; 32], Algorithm::Ed25519)
        .expect("derive completed-attestation owner key");
    let attestation = MusubiProviderBundleVerificationAttestationV1 {
        approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
            public_key: owner_key.public_key().clone(),
            signature: SignatureOf::try_from_hash(owner_key.private_key(), payload.signing_hash())
                .expect("sign completed-attestation inventory payload"),
        }],
        payload,
    };
    MusubiProviderAttestationInventoryItemV1::new(attestation)
        .expect("construct completed-attestation inventory item")
}
fn completed_attestation_authorization(
    claim: &ProviderIngestFinalizedMusubiCompletionClaimV1,
    manifest_digest: [u8; 32],
) -> FinalizedProviderIngestAuthorizationV1 {
    FinalizedProviderIngestAuthorizationV1::from_finalized_musubi_state(
        claim.observed_finalized_cursor().height,
        claim.observed_finalized_cursor().block_hash,
        claim.provider_id(),
        claim.replication_order(),
        manifest_digest,
        claim.commitment().root_cid.as_bytes().to_vec(),
        claim.commitment().chunker.to_handle(),
        *claim.commitment().chunk_plan_digest.as_bytes(),
        *claim.commitment().por_root.as_bytes(),
        claim.commitment().content_length,
        FinalizedProviderIngestMusubiContextV1::new(*claim.network_id(), claim.archive_id())
            .expect("completed-claim Musubi context"),
    )
    .expect("completed-claim retained authorization")
}
fn completed_attestation_manifest(fixture: &VerifiedAttestationBundleFixtureV1) -> ManifestV1 {
    let car_stats = CarWriter::new(&fixture.plan, &fixture.payload)
        .expect("prepare completed-attestation fixture CAR")
        .write_to(io::sink())
        .expect("compute completed-attestation fixture CAR");
    ManifestBuilder::new()
        .root_cid(
            car_stats
                .root_cids
                .first()
                .cloned()
                .expect("completed-attestation fixture root"),
        )
        .dag_codec(DagCodecId(car_stats.dag_codec))
        .chunking_from_profile(fixture.plan.chunk_profile, BLAKE3_256_MULTIHASH_CODE)
        .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&fixture.plan.chunks))
        .por_root(
            compute_por_root(&fixture.payload, &fixture.plan)
                .expect("completed-attestation fixture PoR root"),
        )
        .content_length(fixture.plan.content_length)
        .car_digest(*car_stats.car_archive_digest.as_bytes())
        .car_size(car_stats.car_size)
        .pin_policy(sorafs_manifest::PinPolicy {
            min_replicas: iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1,
            ..sorafs_manifest::PinPolicy::default()
        })
        .build()
        .expect("completed-attestation fixture manifest")
}
fn completed_attestation_capture_source_row(
    fixture: &VerifiedAttestationBundleFixtureV1,
    manifest: &ManifestV1,
) -> ProviderIngestCompletedMusubiCaptureSourceRowV1 {
    completed_attestation_capture_source_row_with_order_id(fixture, manifest, [0xAC; 32])
}
fn completed_attestation_capture_source_row_with_order_id(
    fixture: &VerifiedAttestationBundleFixtureV1,
    manifest: &ManifestV1,
    order_id: [u8; 32],
) -> ProviderIngestCompletedMusubiCaptureSourceRowV1 {
    let claim = completed_attestation_claim_with_order_id(fixture.commitment.clone(), order_id);
    let manifest_digest =
        ManifestDigest::from_manifest(manifest).expect("completed-attestation manifest digest");
    let manifest_root = ManifestRootCid::try_from_slice(&manifest.root_cid)
        .expect("completed-attestation manifest root");
    let chunker = ChunkerProfileHandle {
        profile_id: manifest.chunking.profile_id.0,
        namespace: manifest.chunking.namespace.clone(),
        name: manifest.chunking.name.clone(),
        semver: manifest.chunking.semver.clone(),
        multihash_code: manifest.chunking.multihash_code,
    };
    let mut pin = PinManifestRecord::new(
        manifest_digest,
        manifest_root.clone(),
        chunker.clone(),
        manifest.chunk_digest_sha3_256,
        manifest.por_root,
        manifest.content_length,
        PinPolicy {
            min_replicas: iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1,
            ..PinPolicy::default()
        },
        account(8),
        8,
        None,
        None,
        Metadata::default(),
    );
    pin.approve(8, None);
    let order_id = claim.replication_order();
    let order_body = ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id,
        manifest_cid: manifest.root_cid.clone(),
        manifest_digest: *manifest_digest.as_bytes(),
        chunking_profile: chunker.to_handle(),
        target_replicas: iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1,
        assignments: [LOCAL_PROVIDER, SOURCE_PROVIDER, THIRD_PROVIDER]
            .into_iter()
            .map(|provider_id| ReplicationAssignmentV1 {
                provider_id,
                slice_gib: 1,
                lane: None,
            })
            .collect(),
        issued_at: 8,
        deadline_at: 20,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: 10,
            min_availability_percent_milli: 99_000,
            min_por_success_percent_milli: 99_000,
        },
        metadata: Vec::new(),
    };
    order_body
        .validate()
        .expect("completed-attestation replication order");
    ProviderIngestCompletedMusubiCaptureSourceRowV1::from_projected_fields(
        PinManifestFinalizedRecordV1 {
            finalized_cursor: PinManifestFinalizedCursorV1 {
                height: cursor(8).height,
                block_hash: cursor(8).block_hash,
            },
            manifest: pin,
        },
        ReplicationOrderRecord {
            order_id: ReplicationOrderId::new(order_id),
            manifest_digest,
            manifest_root_cid: manifest_root,
            musubi_archive: Some(claim.archive_id()),
            issued_by: account(1),
            issued_epoch: 8,
            deadline_epoch: 20,
            canonical_order: norito::encode_canonical(&order_body)
                .expect("encode completed-attestation replication order"),
            assignment_revision: 1,
            provider_completions: vec![claim.completion().clone()],
            // The local provider is complete; the two remote assignments remain pending.
            status: ReplicationOrderStatus::Pending,
        },
        Some(claim.binding.clone()),
        Some(account(8)),
        Some(claim.completion().completion_authority.clone()),
        Some(8),
        None,
    )
}
#[derive(Default)]
struct CaptureJournalMemoryStore {
    checkpoint: Mutex<Option<Vec<u8>>>,
}
impl MusubiProviderAttestationJournalStoreV1 for CaptureJournalMemoryStore {
    fn load<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalStoreSnapshotV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    > {
        Box::pin(async move {
            let checkpoint = self
                .checkpoint
                .lock()
                .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
            checkpoint.as_ref().map_or_else(
                || Ok(MusubiProviderAttestationJournalStoreSnapshotV1::empty()),
                |bytes| {
                    MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
                        bytes.clone(),
                    )
                },
            )
        })
    }
    fn compare_and_swap<'a>(
        &'a self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalCasOutcomeV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    > {
        Box::pin(async move {
            let replacement =
                MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
                    replacement_checkpoint_bytes,
                )?;
            let replacement_revision = replacement
                .revision()
                .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?;
            let replacement_bytes = replacement
                .checkpoint_bytes()
                .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?;
            let mut checkpoint = self
                .checkpoint
                .lock()
                .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
            if checkpoint.as_deref() == Some(replacement_bytes) {
                return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                    revision: replacement_revision,
                });
            }
            let retained_revision = checkpoint
                .as_ref()
                .map(|bytes| musubi_provider_attestation_journal_checkpoint_revision_v1(bytes));
            if retained_revision != expected_revision {
                return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict);
            }
            *checkpoint = Some(replacement_bytes.to_vec());
            Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: replacement_revision,
            })
        })
    }
}
struct CaptureInventory {
    item: Mutex<Option<MusubiProviderAttestationInventoryItemV1>>,
    get_error: Mutex<Option<MusubiProviderAttestationInventoryErrorV1>>,
    block_get: AtomicBool,
    block_get_call: AtomicUsize,
    get_entered: tokio::sync::Notify,
    release_get: tokio::sync::Notify,
    readiness_calls: AtomicUsize,
    put_calls: AtomicUsize,
    get_calls: AtomicUsize,
    inventory_calls: AtomicUsize,
}
impl CaptureInventory {
    fn new(item: Option<MusubiProviderAttestationInventoryItemV1>) -> Self {
        Self {
            item: Mutex::new(item),
            get_error: Mutex::new(None),
            block_get: AtomicBool::new(false),
            block_get_call: AtomicUsize::new(0),
            get_entered: tokio::sync::Notify::new(),
            release_get: tokio::sync::Notify::new(),
            readiness_calls: AtomicUsize::new(0),
            put_calls: AtomicUsize::new(0),
            get_calls: AtomicUsize::new(0),
            inventory_calls: AtomicUsize::new(0),
        }
    }
    fn set_item(&self, item: MusubiProviderAttestationInventoryItemV1) {
        *self.item.lock().expect("capture inventory item lock") = Some(item);
    }
    fn set_get_error(&self, error: Option<MusubiProviderAttestationInventoryErrorV1>) {
        *self.get_error.lock().expect("capture inventory error lock") = error;
    }
    fn block_get(&self) {
        self.block_get.store(true, Ordering::SeqCst);
    }
    fn block_get_on_call(&self, call: usize) {
        assert_ne!(call, 0, "capture inventory call index must be non-zero");
        self.block_get_call.store(call, Ordering::SeqCst);
    }
    fn unblock_get(&self) {
        self.block_get.store(false, Ordering::SeqCst);
        self.block_get_call.store(0, Ordering::SeqCst);
        self.release_get.notify_waiters();
    }
    async fn wait_until_get_entered(&self) {
        self.get_entered.notified().await;
    }
}
impl MusubiProviderAttestationInventorySinkV1 for CaptureInventory {
    fn put<'a>(
        &'a self,
        _item: MusubiProviderAttestationInventoryItemV1,
    ) -> ProviderIngestFutureV1<'a, Result<u64, MusubiProviderAttestationInventoryErrorV1>> {
        Box::pin(async move {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
        })
    }
}
impl MusubiProviderAttestationInventoryReaderV1 for CaptureInventory {
    fn get<'a>(
        &'a self,
        _scope: &'a MusubiProviderAttestationInventoryScopeV1,
        _key: iroha_data_model::musubi::MusubiProviderBundleAttestationKeyV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            Option<MusubiProviderAttestationInventoryReadbackV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            let call = self.get_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.block_get.load(Ordering::SeqCst)
                || self.block_get_call.load(Ordering::SeqCst) == call
            {
                self.get_entered.notify_one();
                self.release_get.notified().await;
            }
            if let Some(error) = *self
                .get_error
                .lock()
                .map_err(|_| MusubiProviderAttestationInventoryErrorV1::Unavailable)?
            {
                return Err(error);
            }
            self.item
                .lock()
                .map_err(|_| MusubiProviderAttestationInventoryErrorV1::Unavailable)?
                .clone()
                .map(|item| MusubiProviderAttestationInventoryReadbackV1::try_new(item, 1))
                .transpose()
        })
    }
    fn inventory<'a>(
        &'a self,
        _scope: &'a MusubiProviderAttestationInventoryScopeV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            Option<MusubiProviderAttestationInventoryV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            self.inventory_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
    }
}
impl MusubiProviderAttestationInventoryRuntimeV1 for CaptureInventory {
    fn runtime_handle(&self) -> &str {
        "inventory://sorafs/musubi/provider-attestation/primary"
    }
    fn qualification(
        &self,
    ) -> Result<
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
    > {
        Ok(MusubiProviderAttestationInventoryQualificationV1::new(
            1, [0xD1; 32],
        ))
    }
    fn check_readiness<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<'a, Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1>>
    {
        Box::pin(async move {
            self.readiness_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
fn outbox_policy() -> ProviderIngestOutboxPolicyV1 {
    ProviderIngestOutboxPolicyV1 {
        max_active_entries: 32,
        max_terminal_entries: 32,
        max_attempts: 4,
        checkpoint_max_bytes: 16 * 1024 * 1024,
        checkpoint_operation_timeout_ms: 250,
        source_lease_ttl_ms: 20,
        retry_base_delay_ms: 10_000,
        retry_max_delay_ms: 100_000,
        terminal_retention_blocks: 100,
        max_signed_transaction_bytes: 128 * 1024,
        max_status_page_size: 32,
    }
}
fn runtime_policy() -> ProviderIngestRuntimePolicyV1 {
    ProviderIngestRuntimePolicyV1 {
        max_page_rows: 16,
        max_pages_per_tick: 2,
        max_source_jobs_per_tick: 4,
        max_source_providers: 4,
        scan_interval_ms: 10,
        source_operation_timeout_ms: 250,
        source_lease_renew_interval_ms: 5,
        signer_timeout_ms: 100,
        ingress_timeout_ms: 100,
    }
}
struct TestLedger {
    page: Mutex<ProviderIngestFinalizedAssignmentPageV1>,
}
impl ProviderIngestFinalizedLedgerV1 for TestLedger {
    fn read_assignment_page<'a>(
        &'a self,
        _claim_factory: ProviderIngestFinalizedClaimFactoryV1,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        _limit: usize,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1>,
    > {
        let page = self.page.lock().unwrap().clone();
        Box::pin(async move {
            if at_finalized_cursor.is_some_and(|cursor| cursor != page.finalized_cursor) {
                return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
            }
            if after_order_id.is_some() {
                Ok(ProviderIngestFinalizedAssignmentPageV1 {
                    finalized_cursor: page.finalized_cursor,
                    finalized_block_time_ms: page.finalized_block_time_ms,
                    rows: Vec::new(),
                    next_after_order_id: None,
                })
            } else {
                Ok(page)
            }
        })
    }
}
fn fixture_completed_musubi_capture_row(
    order_seed: u8,
    commitment_seed: u8,
) -> ProviderIngestCompletedMusubiCaptureSourceRowV1 {
    let mut row = fixture_musubi_row(order_seed, commitment_seed);
    row.order.provider_completions.push(completion_record(
        ProviderId::new(LOCAL_PROVIDER),
        account(8),
        8,
    ));
    ProviderIngestCompletedMusubiCaptureSourceRowV1::from_projected_fields(
        row.pin,
        row.order,
        row.musubi_archive.map(|claim| claim.binding),
        row.provider_owner,
        row.completion_authority,
        row.completion_epoch,
        row.committed_transaction_hash,
    )
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureScannerLedgerFaultV1 {
    None,
    MalformedRow,
    SubstitutedArchiveBinding,
    MutatedAfterSigning,
    WrongSigningKey,
    RequestMismatch,
    ReplayPrevious,
    Unavailable,
}
struct CaptureScannerLedgerV1 {
    rows: Vec<ProviderIngestCompletedMusubiCaptureSourceRowV1>,
    finalized_height: AtomicU64,
    fault: Mutex<CaptureScannerLedgerFaultV1>,
    requested_limits: Mutex<Vec<usize>>,
    requested_generations: Mutex<Vec<u64>>,
    key_pair: KeyPair,
    binding: ProviderIngestCompletedMusubiCaptureVerifierBindingV1,
    previous_response: Mutex<Option<ProviderIngestCompletedMusubiSignedCapturePageV1>>,
}
impl CaptureScannerLedgerV1 {
    fn new(
        rows: Vec<ProviderIngestCompletedMusubiCaptureSourceRowV1>,
        finalized_height: u64,
        fault: CaptureScannerLedgerFaultV1,
    ) -> Self {
        let key_pair = KeyPair::from_seed(vec![0xC7; 32], Algorithm::Ed25519);
        let public_key: [u8; 32] = key_pair
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 capture test key");
        let binding =
            ProviderIngestCompletedMusubiCaptureVerifierBindingV1::try_from_untrusted_reader_parts(
                test_network_id(),
                LOCAL_PROVIDER,
                1,
                public_key,
            )
            .expect("capture test verifier binding");
        Self {
            rows,
            finalized_height: AtomicU64::new(finalized_height),
            fault: Mutex::new(fault),
            requested_limits: Mutex::new(Vec::new()),
            requested_generations: Mutex::new(Vec::new()),
            key_pair,
            binding,
            previous_response: Mutex::new(None),
        }
    }
    fn set_finalized_height(&self, height: u64) {
        self.finalized_height.store(height, Ordering::SeqCst);
    }
    fn set_fault(&self, fault: CaptureScannerLedgerFaultV1) {
        *self.fault.lock().unwrap() = fault;
    }
    fn requested_limits(&self) -> Vec<usize> {
        self.requested_limits.lock().unwrap().clone()
    }
    fn requested_generations(&self) -> Vec<u64> {
        self.requested_generations.lock().unwrap().clone()
    }
}
impl ProviderIngestCompletedMusubiSignedCaptureLedgerV1 for CaptureScannerLedgerV1 {
    fn capture_verifier_binding(
        &self,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureVerifierBindingV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        Ok(self.binding.clone())
    }
    fn read_signed_completed_musubi_capture_page<'a>(
        &'a self,
        request: ProviderIngestCompletedMusubiCaptureRequestV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            ProviderIngestCompletedMusubiSignedCapturePageV1,
            ProviderIngestFinalizedLedgerErrorV1,
        >,
    > {
        Box::pin(async move {
            let limit = usize::from(request.limit());
            self.requested_limits.lock().unwrap().push(limit);
            self.requested_generations
                .lock()
                .unwrap()
                .push(request.generation());
            let fault = *self.fault.lock().unwrap();
            if fault == CaptureScannerLedgerFaultV1::Unavailable {
                return Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
            }
            if fault == CaptureScannerLedgerFaultV1::ReplayPrevious {
                return self
                    .previous_response
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected);
            }
            let finalized_cursor = request
                .at_finalized_cursor()
                .unwrap_or_else(|| cursor(self.finalized_height.load(Ordering::SeqCst)));
            let after_order_id = request.after_order_id();
            let mut rows = self
                .rows
                .iter()
                .filter(|row| {
                    after_order_id.is_none_or(|after| *row.order.order_id.as_bytes() > after)
                })
                .take(limit.saturating_add(1))
                .cloned()
                .collect::<Vec<_>>();
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            for row in &mut rows {
                row.pin.finalized_cursor = PinManifestFinalizedCursorV1 {
                    height: finalized_cursor.height,
                    block_hash: finalized_cursor.block_hash,
                };
            }
            match fault {
                CaptureScannerLedgerFaultV1::None => {}
                CaptureScannerLedgerFaultV1::MalformedRow => {
                    if let Some(row) = rows.first_mut() {
                        row.pin.finalized_cursor.block_hash = [0xE1; 32];
                    }
                }
                CaptureScannerLedgerFaultV1::SubstitutedArchiveBinding => {
                    if let Some(binding) =
                        rows.first_mut().and_then(|row| row.musubi_archive.as_mut())
                    {
                        binding.replication_order = ReplicationOrderId::new([0x62; 32]);
                    }
                }
                CaptureScannerLedgerFaultV1::MutatedAfterSigning
                | CaptureScannerLedgerFaultV1::WrongSigningKey
                | CaptureScannerLedgerFaultV1::RequestMismatch
                | CaptureScannerLedgerFaultV1::ReplayPrevious
                | CaptureScannerLedgerFaultV1::Unavailable => {}
            }
            let next_after_order_id = has_more.then(|| {
                *rows
                    .last()
                    .expect("a continued capture page has one row")
                    .order
                    .order_id
                    .as_bytes()
            });
            let mut source_page = ProviderIngestCompletedMusubiCaptureSourcePageV1 {
                network_id: test_network_id(),
                provider_id: LOCAL_PROVIDER,
                finalized_cursor,
                finalized_block_time_ms: finalized_cursor.height.saturating_mul(1_000),
                rows,
                next_after_order_id,
            };
            let digest = provider_ingest_completed_musubi_capture_transcript_digest_v1(
                &request,
                &source_page,
            )?;
            let wrong_key = KeyPair::from_seed(vec![0xD8; 32], Algorithm::Ed25519);
            let signing_key = if fault == CaptureScannerLedgerFaultV1::WrongSigningKey {
                &wrong_key
            } else {
                &self.key_pair
            };
            let signature = IrohaSignature::try_new(signing_key.private_key(), &digest)
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            let signature: [u8; 64] = signature
                .payload()
                .try_into()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
            let mut response_request = request.clone();
            if fault == CaptureScannerLedgerFaultV1::RequestMismatch {
                response_request.generation = response_request.generation.saturating_add(1);
            }
            if fault == CaptureScannerLedgerFaultV1::MutatedAfterSigning {
                source_page.finalized_block_time_ms =
                    source_page.finalized_block_time_ms.saturating_add(1);
            }
            let response =
                ProviderIngestCompletedMusubiSignedCapturePageV1::from_untrusted_reader_parts(
                    response_request,
                    source_page,
                    signature,
                );
            *self.previous_response.lock().unwrap() = Some(response.clone());
            Ok(response)
        })
    }
}
