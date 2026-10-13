//! Typed construction of the shared Musubi SDK V1 fixture.
use crate::musubi_fixture_values::{
    account, fixture_network_id, fixture_replication_order, keypair,
};
use iroha_crypto::SignatureOf;
use iroha_data_model::{
    account::AccountId,
    musubi::{
        ArchiveId, MUSUBI_MIN_HEALTHY_REPLICAS_V1, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1,
        MusubiAliasHistoryActionV1, MusubiAliasHistoryEntryV1, MusubiAliasHistoryPageV1,
        MusubiAliasNameV1, MusubiAliasPricingPolicyV1, MusubiAliasQueryV1, MusubiAliasRecordV1,
        MusubiArchiveAvailabilityV1, MusubiArchiveCommitmentV1, MusubiArchiveLocationPageV1,
        MusubiArchiveLocationQueryV1, MusubiArchiveRecordV1, MusubiArchiveRetentionDecisionV1,
        MusubiArchiveRetentionDispositionV1, MusubiArchiveRetentionPageV1,
        MusubiArchiveRetentionQueryV1, MusubiArtifactGovernanceStateV1, MusubiContentDigestV1,
        MusubiDescriptionV1, MusubiDocumentRefV1, MusubiExactPackageQueryV1,
        MusubiExactReleaseQueryV1, MusubiExactReleaseSnapshotV1, MusubiInvitationStateV1,
        MusubiInviteIdV1, MusubiKeywordV1, MusubiKotodamaEditionV1,
        MusubiMaintainerDirectoryEntryV1, MusubiMaintainerInvitationV1, MusubiMaintainerPageV1,
        MusubiMaintainerPermissionsV1, MusubiNamespaceBindingDigestV1, MusubiNamespaceBindingV1,
        MusubiNamespaceV1, MusubiOrderedPackageEntryV1, MusubiOrderedPackagePageV1,
        MusubiOrderedPrefixQueryV1, MusubiOrderedPrefixV1, MusubiPackageIdV1, MusubiPackageNameV1,
        MusubiPackagePageQueryV1, MusubiPackageRecordV1, MusubiPackageRevisionsV1,
        MusubiPackageRoleV1, MusubiPackageScopeV1, MusubiPackageSelectorV1, MusubiPageRequestV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1,
        MusubiProviderBundleVerificationApprovalV1, MusubiProviderBundleVerificationAttestationV1,
        MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
        MusubiRegistrySnapshotV1, MusubiReleaseIdV1, MusubiReleaseManifestV1,
        MusubiReleaseMetadataV1, MusubiReleaseRecordV1, MusubiReleaseRevisionsV1,
        MusubiReleaseSelectionStateV1, MusubiReleaseYankV1, MusubiResolverIndexPageV1,
        MusubiResolverIndexQueryV1, MusubiResolverReleaseRowV1, MusubiSearchHitV1,
        MusubiSearchPageRequestV1, MusubiSearchPageV1, MusubiSearchQueryV1, MusubiSearchSnapshotV1,
        MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptBindingV1,
        MusubiSeedIngressReceiptPayloadV1, MusubiSeedIngressReceiptV1, MusubiStorageAvailabilityV1,
        MusubiVerificationLockDigestV1, MusubiVersionPageV1, MusubiVersionReqV1, MusubiVersionV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ChunkerProfileHandle, ManifestRootCid, ProviderIngestCompletionAuthorityV1,
            ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
        },
    },
};
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use norito::json::{self, JsonDeserialize, JsonSerialize, Value};
use std::fmt::Debug;
// Public test material only. Every non-zero Ed25519 seed has one fixture role.
const SDK_PUBLISHER_SEED: u8 = 0x31;
const SDK_RECEIPT_BROKER_SEED: u8 = 0x32;
const SDK_PROVIDER_OWNER_SEED: u8 = 0x33;
const SDK_PACKAGE_OWNER_SEED: u8 = 0x34;
fn package() -> MusubiPackageIdV1 {
    MusubiPackageIdV1::new(
        DataSpaceId::new(7),
        MusubiPackageScopeV1::DataspaceRoot,
        MusubiPackageNameV1::new("math-utils").expect("SDK fixture package name"),
    )
}
fn release() -> MusubiReleaseIdV1 {
    MusubiReleaseIdV1::new(
        package(),
        "1.2.3"
            .parse::<MusubiVersionV1>()
            .expect("SDK fixture release version"),
    )
}
fn snapshot() -> MusubiRegistrySnapshotV1 {
    MusubiRegistrySnapshotV1 {
        finalized_height: 50,
        finalized_block_hash: [7; 32],
        index_revision: 9,
    }
}
fn page_request() -> MusubiPageRequestV1 {
    MusubiPageRequestV1 {
        limit: 50,
        cursor: None,
    }
}
fn archive_commitment() -> MusubiArchiveCommitmentV1 {
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::from_blake3_digest([1; 32]).expect("SDK fixture root CID"),
        chunker: ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        },
        chunk_plan_digest: MusubiContentDigestV1::new([2; 32]),
        por_root: MusubiContentDigestV1::new([3; 32]),
        content_length: 1_024,
        car_digest: MusubiContentDigestV1::new([4; 32]),
        car_size: 2_048,
        bundle_digest: MusubiContentDigestV1::new([5; 32]),
        source_tree_digest: MusubiContentDigestV1::new([6; 32]),
        descriptor_digest: MusubiContentDigestV1::new([7; 32]),
        file_count: 2,
        chunk_count: 4,
    };
    commitment
        .validate()
        .expect("SDK fixture archive commitment");
    commitment
}
fn release_metadata() -> MusubiReleaseMetadataV1 {
    let mut metadata = MusubiReleaseMetadataV1 {
        description: Some(
            "Canonical arithmetic helpers"
                .parse::<MusubiDescriptionV1>()
                .expect("SDK fixture description"),
        ),
        readme: Some(
            "README.md"
                .parse::<MusubiDocumentRefV1>()
                .expect("SDK fixture readme"),
        ),
        license: Some(
            "Apache-2.0"
                .parse::<MusubiDocumentRefV1>()
                .expect("SDK fixture license"),
        ),
        repository: Some(
            "https://example.invalid/sora/math-utils"
                .parse::<MusubiDocumentRefV1>()
                .expect("SDK fixture repository"),
        ),
        keywords: ["math", "utility"]
            .into_iter()
            .map(|keyword| {
                keyword
                    .parse::<MusubiKeywordV1>()
                    .expect("SDK fixture keyword")
            })
            .collect(),
    };
    metadata.canonicalize();
    metadata.validate().expect("SDK fixture metadata");
    metadata
}
fn release_manifest(commitment: &MusubiArchiveCommitmentV1) -> MusubiReleaseManifestV1 {
    let manifest = MusubiReleaseManifestV1 {
        release: release(),
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([2; 32]).expect("SDK fixture ABI"),
        dependencies: Vec::new(),
        exports: vec!["add".parse::<Name>().expect("SDK fixture export")],
        interface_digest: MusubiContentDigestV1::new([3; 32]),
        metadata: release_metadata(),
        archive_id: commitment.archive_id(),
        verification_lock_digest: MusubiVerificationLockDigestV1::new([5; 32]),
    };
    manifest.validate().expect("SDK fixture release manifest");
    manifest
}
fn release_record(
    manifest: &MusubiReleaseManifestV1,
    publisher: &AccountId,
) -> MusubiReleaseRecordV1 {
    let yank = MusubiReleaseYankV1 {
        release: manifest.release.clone(),
        yanked: false,
        reason: "initial publication".parse().expect("SDK fixture reason"),
        changed_by: publisher.clone(),
        changed_at_height: 43,
        revision: 1,
    };
    let record = MusubiReleaseRecordV1 {
        manifest: manifest.clone(),
        release_digest: manifest.release_digest(),
        published_by: publisher.clone(),
        published_at_height: 43,
        yank,
        artifact_governance: MusubiArtifactGovernanceStateV1::Available,
        revisions: MusubiReleaseRevisionsV1 {
            yank: 1,
            artifact_governance: 1,
        },
    };
    record.validate().expect("SDK fixture release record");
    record
}
fn signed_seed_receipt(
    commitment: &MusubiArchiveCommitmentV1,
    manifest: &MusubiReleaseManifestV1,
) -> MusubiSeedIngressReceiptV1 {
    let broker = keypair(SDK_RECEIPT_BROKER_SEED);
    let payload = MusubiSeedIngressReceiptPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: MusubiSeedIngressReceiptBindingV1 {
            network_id: fixture_network_id(),
            publisher: account(SDK_PUBLISHER_SEED),
            ingress_broker: AccountId::new(broker.public_key().clone()),
            seed_provider: ProviderId::new([0x16; 32]),
            semantic_release_manifest_digest: manifest.semantic_digest(),
            archive_id: commitment.archive_id(),
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [0x18; 32],
        },
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
    };
    let receipt = MusubiSeedIngressReceiptV1 {
        approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
            public_key: broker.public_key().clone(),
            signature: SignatureOf::try_from_hash(broker.private_key(), payload.signing_hash())
                .expect("sign SDK seed-ingress receipt"),
        }],
        payload,
    };
    receipt
        .verify(&receipt.payload.binding, 1_001)
        .expect("SDK seed-ingress receipt signature");
    receipt
}
fn signed_provider_attestation(
    commitment: &MusubiArchiveCommitmentV1,
    manifest: &MusubiReleaseManifestV1,
) -> MusubiProviderBundleVerificationAttestationV1 {
    let owner_keypair = keypair(SDK_PROVIDER_OWNER_SEED);
    let owner = AccountId::new(owner_keypair.public_key().clone());
    let binding = MusubiProviderBundleVerificationBindingV1 {
        network_id: fixture_network_id(),
        provider_id: ProviderId::new([0xD1; 32]),
        completed_by: owner.clone(),
        completion_authority: ProviderIngestCompletionAuthorityV1::new(
            owner.clone(),
            owner,
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0xE1; 32],
                revision: 1,
                predecessor_digest: None,
                policy_digest: [0xF1; 32],
            },
        ),
        replication_order: fixture_replication_order(),
        assignment_revision: 1,
        completion_epoch: 600,
        finalized_anchor: ProviderIngestFinalizedAnchorV1 {
            height: 49,
            block_hash: [7; 32],
        },
        archive_id: commitment.archive_id(),
        bundle_digest: commitment.bundle_digest,
        descriptor_digest: commitment.descriptor_digest,
        semantic_release_manifest_digest: manifest.semantic_digest(),
        verification_lock_digest: manifest.verification_lock_digest,
        source_tree_digest: commitment.source_tree_digest,
    };
    let payload = MusubiProviderBundleVerificationPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: binding.clone(),
    };
    let attestation = MusubiProviderBundleVerificationAttestationV1 {
        approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
            public_key: owner_keypair.public_key().clone(),
            signature: SignatureOf::try_from_hash(
                owner_keypair.private_key(),
                payload.signing_hash(),
            )
            .expect("sign SDK provider attestation"),
        }],
        payload,
    };
    attestation
        .verify(&binding)
        .expect("SDK provider attestation signature");
    attestation
}
fn typed_value<T>(value: &T, label: &str) -> Value
where
    T: Debug + PartialEq + JsonDeserialize + JsonSerialize,
{
    let encoded = json::to_value(value).unwrap_or_else(|error| panic!("encode {label}: {error}"));
    let decoded: T =
        json::from_value(encoded.clone()).unwrap_or_else(|error| panic!("decode {label}: {error}"));
    assert_eq!(&decoded, value, "{label} typed JSON round-trip");
    let reencoded =
        json::to_value(&decoded).unwrap_or_else(|error| panic!("re-encode {label}: {error}"));
    assert_eq!(reencoded, encoded, "{label} canonical typed JSON");
    encoded
}
fn route<T, U>(id: &str, request: &T, response: &U) -> Value
where
    T: Debug + PartialEq + JsonDeserialize + JsonSerialize,
    U: Debug + PartialEq + JsonDeserialize + JsonSerialize,
{
    norito::json!({
        "id": id,
        "path": (format!("/v1/musubi/queries/{id}")),
        "request": (typed_value(request, "SDK route request")),
        "response": (typed_value(response, "SDK route response")),
    })
}
fn canonical_vectors() -> Value {
    let namespace = "sora"
        .parse::<MusubiNamespaceV1>()
        .expect("SDK fixture namespace");
    let package_name = MusubiPackageNameV1::new("math-utils").expect("SDK fixture package name");
    let selector = MusubiPackageSelectorV1 {
        namespace: namespace.clone(),
        name: package_name.clone(),
    };
    let version = "1.2.3-rc.1"
        .parse::<MusubiVersionV1>()
        .expect("SDK fixture prerelease");
    let requirement_text = ["^1.2.3", "~1.2.3", "1.2.*", "=1.2.3", ">=1.2.3,<2.0.0"];
    let requirements = requirement_text
        .into_iter()
        .map(|text| {
            let wire = text
                .parse::<MusubiVersionReqV1>()
                .expect("SDK fixture version requirement");
            norito::json!({
                "text": text,
                "wire": (typed_value(&wire, "SDK version requirement")),
            })
        })
        .collect::<Vec<_>>();
    let requirement_aliases = [
        ("=1.2.3,=1.2.3", "=1.2.3"),
        ("<2.0.0, >=1.0.0,>=1.0.0", ">=1.0.0,<2.0.0"),
    ]
    .into_iter()
    .map(|(input, canonical)| {
        let wire = input
            .parse::<MusubiVersionReqV1>()
            .expect("SDK fixture requirement alias");
        assert_eq!(wire.to_string(), canonical);
        norito::json!({
            "input": input,
            "canonical": canonical,
            "wire": (typed_value(&wire, "SDK requirement alias")),
        })
    })
    .collect::<Vec<_>>();
    let match_inputs = [
        ("^0.18446744073709551615.0", "0.18446744073709551615.1"),
        ("^0.18446744073709551615.0", "1.0.0"),
        ("^0.0.18446744073709551615", "0.1.0"),
        ("~0.18446744073709551615.0", "1.0.0"),
        ("^1.2.3-alpha.1", "1.2.3-beta.1"),
        ("^1.2.0", "1.2.3-beta.1"),
    ];
    let requirement_matches = match_inputs
        .into_iter()
        .map(|(requirement, candidate)| {
            let parsed_requirement = requirement
                .parse::<MusubiVersionReqV1>()
                .expect("SDK fixture match requirement");
            let parsed_candidate = candidate
                .parse::<MusubiVersionV1>()
                .expect("SDK fixture match candidate");
            norito::json!({
                "requirement": requirement,
                "candidate": candidate,
                "matches": (parsed_requirement.matches(&parsed_candidate)),
            })
        })
        .collect::<Vec<_>>();
    norito::json!({
        "namespace": (typed_value(&namespace, "SDK namespace")),
        "package_name": (typed_value(&package_name, "SDK package name")),
        "selector": (typed_value(&selector, "SDK package selector")),
        "package": (typed_value(&package(), "SDK package")),
        "version": (typed_value(&version, "SDK version")),
        "requirements": requirements,
        "requirement_aliases": requirement_aliases,
        "requirement_matches": requirement_matches,
    })
}
fn routes() -> Vec<Value> {
    let network_id = fixture_network_id();
    let snapshot = snapshot();
    let package = package();
    let release = release();
    let owner = account(SDK_PACKAGE_OWNER_SEED);
    let publisher = account(SDK_PUBLISHER_SEED);
    let commitment = archive_commitment();
    let manifest = release_manifest(&commitment);
    let home_release = release_record(&manifest, &publisher);
    let storage = MusubiArchiveAvailabilityV1 {
        archive_id: commitment.archive_id(),
        availability: MusubiStorageAvailabilityV1::Selectable,
        healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
        active_locations: 1,
        finalized_height: snapshot.finalized_height,
        finalized_block_hash: snapshot.finalized_block_hash,
        index_revision: snapshot.index_revision,
    };
    storage
        .validate()
        .expect("SDK selectable storage projection");
    let universal_release = MusubiResolverReleaseRowV1 {
        release: release.clone(),
        release_digest: manifest.release_digest(),
        archive_id: commitment.archive_id(),
        source_digest: commitment.source_tree_digest,
        interface_digest: manifest.interface_digest,
        abi: manifest.abi,
        dependencies: manifest.dependencies.clone(),
        selection: MusubiReleaseSelectionStateV1 {
            yank: home_release.yank.clone(),
            storage,
            governance: home_release.artifact_governance.clone(),
        },
        index_revision: snapshot.index_revision,
    };
    let exact_release = MusubiExactReleaseSnapshotV1 {
        network_id,
        snapshot,
        home_release,
        universal_release,
    };
    let exact_release_query = MusubiExactReleaseQueryV1 {
        release: release.clone(),
    };
    exact_release
        .validate_for(&exact_release_query)
        .expect("SDK exact-release route");
    let package_record = MusubiPackageRecordV1 {
        package: package.clone(),
        claimed_namespace: "sora".parse().expect("SDK claimed namespace"),
        claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([1; 32]),
        owners: vec![owner.clone()],
        member_accounts: vec![owner.clone()],
        claimed_at_height: 42,
        revisions: MusubiPackageRevisionsV1 {
            governance: 2,
            metadata: 1,
            archive_locations: 1,
        },
    };
    package_record.validate().expect("SDK exact package record");
    let provider_attestation = signed_provider_attestation(&commitment, &manifest);
    let provider_key = provider_attestation.key();
    let provider_record = MusubiProviderBundleAttestationRecordV1 {
        key: provider_key,
        attestation_digest: provider_attestation.digest(),
        registered_by: provider_attestation.payload.binding.completed_by.clone(),
        registered_at_height: 44,
        attestation: provider_attestation,
    };
    provider_record
        .validate()
        .expect("SDK provider attestation record");
    provider_record
        .attestation
        .verify(&provider_record.attestation.payload.binding)
        .expect("SDK provider attestation remains signed");
    let resolver_query = MusubiResolverIndexQueryV1 {
        package: package.clone(),
        requirement: Some(
            "^1.2.3"
                .parse::<MusubiVersionReqV1>()
                .expect("SDK resolver requirement"),
        ),
        page: page_request(),
    };
    let resolver_page = MusubiResolverIndexPageV1 {
        query: resolver_query.clone(),
        network_id,
        items: Vec::new(),
        next_cursor: None,
        snapshot,
    };
    resolver_page
        .validate_for(&resolver_query)
        .expect("SDK resolver page");
    let package_page_query = MusubiPackagePageQueryV1 {
        package: package.clone(),
        page: page_request(),
    };
    let version_page = MusubiVersionPageV1 {
        query: package_page_query.clone(),
        items: vec![release.version.clone()],
        next_cursor: None,
        snapshot,
    };
    version_page
        .validate_for(&package_page_query)
        .expect("SDK version page");
    let maintainer_page = MusubiMaintainerPageV1 {
        query: package_page_query.clone(),
        items: vec![
            MusubiMaintainerDirectoryEntryV1::Accepted(
                iroha_data_model::musubi::MusubiPackageMemberV1 {
                    package: package.clone(),
                    account: owner.clone(),
                    role: MusubiPackageRoleV1::Owner,
                    accepted_at_height: 42,
                    governance_revision: 1,
                },
            ),
            MusubiMaintainerDirectoryEntryV1::PendingInvitation(MusubiMaintainerInvitationV1 {
                invite_id: MusubiInviteIdV1::new([0x0D; 32]),
                package: package.clone(),
                invited_by: owner.clone(),
                invited_account: owner.clone(),
                role: MusubiPackageRoleV1::Maintainer(MusubiMaintainerPermissionsV1 {
                    publish: true,
                    yank: true,
                    metadata: true,
                    archive_locations: true,
                }),
                expected_governance_revision: 2,
                expires_at_height: 100,
                state: MusubiInvitationStateV1::Pending,
            }),
        ],
        next_cursor: None,
        snapshot,
    };
    maintainer_page
        .validate_for(&package_page_query)
        .expect("SDK maintainer page");
    let receipt = signed_seed_receipt(&commitment, &manifest);
    let archive_record = MusubiArchiveRecordV1 {
        archive_id: commitment.archive_id(),
        commitment: commitment.clone(),
        registered_by: receipt.payload.binding.publisher.clone(),
        registered_at_height: 42,
        location_revision: 1,
        location_ids: Vec::new(),
        staging_receipt: receipt,
    };
    archive_record.validate().expect("SDK archive record");
    let archive_query = MusubiArchiveLocationQueryV1 {
        archive_id: commitment.archive_id(),
        page: page_request(),
    };
    let archive_page = MusubiArchiveLocationPageV1 {
        network_id,
        archive: archive_record,
        items: Vec::new(),
        next_cursor: None,
        snapshot,
    };
    archive_page.validate().expect("SDK archive-location page");
    let retention_ids = [0x10, 0x20, 0x30, 0x40].map(|byte| ArchiveId::new([byte; 32]));
    let retention_query = MusubiArchiveRetentionQueryV1 {
        archive_ids: retention_ids.to_vec(),
        expected_snapshot: Some(snapshot),
    };
    retention_query
        .validate()
        .expect("SDK archive-retention query");
    let unavailable = MusubiArchiveAvailabilityV1 {
        archive_id: retention_ids[1],
        availability: MusubiStorageAvailabilityV1::Unavailable,
        healthy_replicas: 0,
        active_locations: 0,
        finalized_height: 49,
        finalized_block_hash: [6; 32],
        index_revision: 8,
    };
    let below_quorum = MusubiArchiveAvailabilityV1 {
        archive_id: retention_ids[2],
        availability: MusubiStorageAvailabilityV1::BelowQuorum,
        healthy_replicas: 1,
        active_locations: 1,
        finalized_height: 50,
        finalized_block_hash: [7; 32],
        index_revision: 9,
    };
    let selectable = MusubiArchiveAvailabilityV1 {
        archive_id: retention_ids[3],
        availability: MusubiStorageAvailabilityV1::Selectable,
        healthy_replicas: MUSUBI_MIN_HEALTHY_REPLICAS_V1,
        active_locations: 1,
        finalized_height: 50,
        finalized_block_hash: [7; 32],
        index_revision: 9,
    };
    let retention_page = MusubiArchiveRetentionPageV1 {
        network_id,
        items: vec![
            MusubiArchiveRetentionDecisionV1 {
                archive_id: retention_ids[0],
                disposition: MusubiArchiveRetentionDispositionV1::RetainUnknown,
                active_releases: 0,
                yanked_releases: 0,
                taken_down_releases: 0,
                storage: None,
            },
            MusubiArchiveRetentionDecisionV1 {
                archive_id: retention_ids[1],
                disposition: MusubiArchiveRetentionDispositionV1::RetainReferenced,
                active_releases: 1,
                yanked_releases: 1,
                taken_down_releases: 1,
                storage: Some(unavailable),
            },
            MusubiArchiveRetentionDecisionV1 {
                archive_id: retention_ids[2],
                disposition: MusubiArchiveRetentionDispositionV1::PruneUnreferenced,
                active_releases: 0,
                yanked_releases: 0,
                taken_down_releases: 0,
                storage: Some(below_quorum),
            },
            MusubiArchiveRetentionDecisionV1 {
                archive_id: retention_ids[3],
                disposition: MusubiArchiveRetentionDispositionV1::PruneGovernedTakedown,
                active_releases: 0,
                yanked_releases: 0,
                taken_down_releases: 2,
                storage: Some(selectable),
            },
        ],
        snapshot,
        finalized_time_ms: 1_700_000_000_000,
    };
    retention_page.validate().expect("SDK retention page");
    let alias = "math"
        .parse::<MusubiAliasNameV1>()
        .expect("SDK fixture alias");
    let alias_query = MusubiAliasQueryV1 {
        alias: alias.clone(),
        page: page_request(),
    };
    let pricing = MusubiAliasPricingPolicyV1::GENESIS;
    let alias_record = MusubiAliasRecordV1 {
        alias: alias.clone(),
        target: package.clone(),
        registered_by: owner.clone(),
        pricing_revision: pricing.revision,
        paid_xor: pricing.price_for(&alias),
        registered_at_height: 44,
        history_revision: 1,
    };
    alias_record.validate(&pricing).expect("SDK alias record");
    let alias_history_page = MusubiAliasHistoryPageV1 {
        query: alias_query.clone(),
        items: vec![MusubiAliasHistoryEntryV1 {
            alias: alias.clone(),
            revision: 1,
            action: MusubiAliasHistoryActionV1::Registered,
            previous_target: None,
            target: package.clone(),
            governance_action: None,
            finalized_height: 44,
        }],
        next_cursor: None,
        snapshot,
    };
    alias_history_page
        .validate_for(&alias_query)
        .expect("SDK alias-history page");
    let ordered_query = MusubiOrderedPrefixQueryV1 {
        prefix: MusubiOrderedPrefixV1::new("sora/").expect("SDK ordered prefix"),
        page: page_request(),
    };
    let ordered_page = MusubiOrderedPackagePageV1 {
        query: ordered_query.clone(),
        network_id,
        namespace_binding: MusubiNamespaceBindingV1 {
            namespace: "sora".parse().expect("SDK namespace binding"),
            home_dataspace: DataSpaceId::new(7),
            scope: MusubiPackageScopeV1::DataspaceRoot,
            generation: 1,
        },
        items: vec![MusubiOrderedPackageEntryV1 {
            selector: MusubiPackageSelectorV1 {
                namespace: "sora".parse().expect("SDK ordered selector namespace"),
                name: MusubiPackageNameV1::new("math-utils").expect("SDK ordered selector name"),
            },
            package: package.clone(),
            latest_selectable: Some(release.version.clone()),
            metadata_revision: 1,
            index_revision: 9,
        }],
        next_cursor: None,
        snapshot,
    };
    ordered_page
        .validate_for(&ordered_query)
        .expect("SDK ordered-prefix page");
    let search_query = MusubiSearchQueryV1 {
        query: "arithmetic math".to_owned(),
        page: MusubiSearchPageRequestV1 {
            limit: 50,
            cursor: None,
        },
    };
    let search_page = MusubiSearchPageV1 {
        query: search_query.clone(),
        items: vec![MusubiSearchHitV1 {
            package: package.clone(),
            claimed_namespace: "sora".parse().expect("SDK search namespace"),
            description: release_metadata().description,
            keywords: release_metadata().keywords,
            metadata_revision: 1,
        }],
        next_cursor: None,
        snapshot: MusubiSearchSnapshotV1 {
            finalized_height: 50,
            finalized_block_hash: [7; 32],
            projection_revision: 9,
        },
    };
    search_page
        .validate_for(&search_query)
        .expect("SDK search page");
    vec![
        route(
            "exact-package",
            &MusubiExactPackageQueryV1 {
                package: package.clone(),
            },
            &package_record,
        ),
        route("exact-release", &exact_release_query, &exact_release),
        route(
            "provider-bundle-attestation",
            &MusubiProviderBundleAttestationKeyV1 {
                archive_id: provider_key.archive_id,
                replication_order: provider_key.replication_order,
                provider_id: provider_key.provider_id,
            },
            &provider_record,
        ),
        route("resolver-index", &resolver_query, &resolver_page),
        route("versions", &package_page_query, &version_page),
        route("maintainers", &package_page_query, &maintainer_page),
        route("archive-locations", &archive_query, &archive_page),
        route("archive-retention", &retention_query, &retention_page),
        route("alias", &alias_query, &alias_record),
        route("alias-history", &alias_query, &alias_history_page),
        route("ordered-prefix", &ordered_query, &ordered_page),
        route("search", &search_query, &search_page),
    ]
}
fn rejection_vectors() -> Value {
    const NAMES: [&str; 5] = ["", "Upper", "leading-", "two--hyphens", "has/slash"];
    const VERSIONS: [&str; 7] = [
        "1.2",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3+build",
        "1.2.3-01",
        "1.2.3-١",
    ];
    const REQUIREMENTS: [&str; 9] = [
        "",
        "1",
        "1.2",
        "1.2.x",
        "+1.*",
        " ^1.2.3 ",
        ">=1.0.0,",
        ">=1.0.0, <2.0.0",
        "=1.0.0,=2.0.0",
    ];
    assert!(
        NAMES
            .iter()
            .all(|value| value.parse::<MusubiPackageNameV1>().is_err())
    );
    assert!(
        VERSIONS
            .iter()
            .all(|value| value.parse::<MusubiVersionV1>().is_err())
    );
    assert!(
        REQUIREMENTS
            .iter()
            .all(|value| value.parse::<MusubiVersionReqV1>().is_err())
    );
    norito::json!({
        "fixture_versions": [0, 2],
        "names": (NAMES.to_vec()),
        "versions": (VERSIONS.to_vec()),
        "requirements": (REQUIREMENTS.to_vec()),
    })
}
/// Construct the complete SDK fixture from concrete request and response types.
#[must_use]
pub fn sdk_document() -> Value {
    norito::json!({
        "format": "iroha-musubi-sdk-v1",
        "fixture_version": 1,
        "rust_owner": "iroha_data_model::musubi",
        "canonical": (canonical_vectors()),
        "routes": (routes()),
        "reject": (rejection_vectors()),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{NetworkId, block::BlockHeader};
    fn substituted_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xA7; Hash::LENGTH]),
        ))
    }
    #[test]
    fn stale_seed_receipt_signature_rejects_network_substitution() {
        let commitment = archive_commitment();
        let manifest = release_manifest(&commitment);
        let mut receipt = signed_seed_receipt(&commitment, &manifest);
        receipt.payload.binding.network_id = substituted_network_id();
        assert!(
            receipt.verify(&receipt.payload.binding, 1_001).is_err(),
            "changing NetworkId without resigning must invalidate the receipt"
        );
    }
    #[test]
    fn stale_provider_signature_rejects_network_substitution() {
        let commitment = archive_commitment();
        let manifest = release_manifest(&commitment);
        let mut attestation = signed_provider_attestation(&commitment, &manifest);
        attestation.payload.binding.network_id = substituted_network_id();
        assert!(
            attestation.verify(&attestation.payload.binding).is_err(),
            "changing NetworkId without resigning must invalidate the attestation"
        );
    }
}
