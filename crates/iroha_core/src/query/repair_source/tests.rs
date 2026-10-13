//! Live repair-source reads over native admission/lease transitions on a certified chain.
//! The admission fixture bypasses Parliament only for setup; these tests do not qualify enactment.
use super::*;
use crate::smartcontracts::{
    Execute,
    isi::sorafs_provider_admission::test_fixture::{
        NOW, ProviderAdmissionTestFixtureV1 as Admission, enact_for_test, key, sign_envelope,
    },
};
use iroha_data_model::{
    isi::{
        Revoke,
        sorafs::{
            ApplySorafsRepairTaskAction, SorafsRepairClaimV1, SorafsRepairTaskActionV1,
            SubmitSorafsRepairTask,
        },
    },
    sorafs::{
        moderation_ledger::{RepairFinalizedCursorV1, sorafs_repair_task_id_v1},
        pin_registry::{
            ChunkerProfileHandle, ManifestRootCid, PinManifestRecord, PinPolicy, StorageClass,
        },
        provider_admission::governance::ProviderAdmissionGovernanceActionV1 as Action,
    },
};
use sorafs_manifest::repair::{
    REPAIR_EVIDENCE_VERSION_V1, REPAIR_REPORT_VERSION_V1, RepairCauseV1, RepairEvidenceV1,
    RepairManualCauseV1, RepairReportV1, RepairTicketId,
};

struct Fixture {
    admission: Admission,
    source_envelope: sorafs_manifest::ProviderAdmissionEnvelopeV1,
    owner: AccountId,
    request: RepairSourceRequestV1,
}
impl Fixture {
    fn new() -> Self {
        Self::with_lease_duration(60_000)
    }
    fn with_lease_duration(lease_duration_ms: u64) -> Self {
        let mut admission = Admission::new();
        admission.admit();
        let owner = AccountId::new(key(1).public_key().clone());
        let target = admission.provider();
        let mut source = admission.envelope.clone();
        source.proposal.provider_id = [0x71; 32];
        source.advert_body.provider_id = source.proposal.provider_id;
        sign_envelope(&mut source, &admission.policy, &admission.signer);
        let manifest = [0x72; 32];
        let mut pin = PinManifestRecord::new(
            ManifestDigest::new(manifest),
            ManifestRootCid::from_blake3_digest(manifest).unwrap(),
            ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".into(),
                name: "sf1".into(),
                semver: "1.0.0".into(),
                multihash_code: 0x1f,
            },
            [0x73; 32],
            [0x74; 32],
            1024,
            PinPolicy {
                min_replicas: 2,
                storage_class: StorageClass::Hot,
                retention_epoch: NOW + 3600,
            },
            owner.clone(),
            NOW,
            None,
            None,
            iroha_model_base::metadata::Metadata::default(),
        );
        pin.approve(NOW, None);
        let report = RepairReportV1 {
            version: REPAIR_REPORT_VERSION_V1,
            ticket_id: RepairTicketId("REP-NATIVE-SOURCE".into()),
            auditor_account: owner.to_string(),
            submitted_at_unix: NOW,
            evidence: RepairEvidenceV1 {
                version: REPAIR_EVIDENCE_VERSION_V1,
                manifest_digest: manifest,
                provider_id: *target.as_bytes(),
                por_history_id: None,
                cause: RepairCauseV1::Manual(RepairManualCauseV1 {
                    reason: "source authorization regression".into(),
                }),
                evidence_json: None,
                notes: None,
            },
            notes: None,
        };
        admission.commit(
            |tx| {
                tx.world
                    .provider_owners
                    .insert(ProviderId::new(source.proposal.provider_id), owner.clone());
                enact_for_test(
                    Action::Admit(norito::encode_canonical(&source).unwrap()),
                    tx,
                );
                let mut permissions = iroha_data_model::permission::Permissions::new();
                permissions.insert(Permission::from(CanOperateSorafsRepair {
                    provider_id: target,
                }));
                tx.world
                    .account_permissions
                    .insert(owner.clone(), permissions);
                tx.world.pin_manifests.insert(pin.digest, pin);
                SubmitSorafsRepairTask::new([0x75; 32], norito::encode_canonical(&report).unwrap())
                    .execute(&owner, tx)
                    .unwrap();
                ApplySorafsRepairTaskAction::new(
                    report.ticket_id.0.clone(),
                    1,
                    SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                        lease_duration_ms,
                        idempotency_key: "claim-native-source".into(),
                    }),
                )
                .execute(&owner, tx)
                .unwrap();
            },
            true,
        );
        let view = admission.state.view();
        let request = RepairSourceRequestV1 {
            floor: RepairFinalizedCursorV1 {
                height: view.height() as u64,
                block_hash: *view.latest_block_hash().unwrap().as_ref(),
            },
            task_id: sorafs_repair_task_id_v1([0x75; 32]),
            ticket_id: report.ticket_id.0,
            task_revision: 2,
            lease_generation: 1,
            target_provider: *target.as_bytes(),
            source_provider: source.proposal.provider_id,
            manifest_digest: manifest,
            chunk_digest: [0x76; 32],
            chunk_length: 1024,
        };
        drop(view);
        Self {
            admission,
            source_envelope: source,
            owner,
            request,
        }
    }
    fn authorize(
        &self,
        request: &RepairSourceRequestV1,
        now: u64,
    ) -> Result<(), RepairSourceAuthorizationErrorV1> {
        authorize_repair_source_v1(&self.admission.state.view(), &self.owner, request, now)
    }
}

#[test]
fn lagging_local_clock_cannot_revive_a_lease_or_pin_expired_at_finality() {
    for expire_pin in [false, true] {
        let mut fixture = Fixture::with_lease_duration(if expire_pin { 60_000 } else { 1_000 });
        let lagging_clock = (NOW + 2) * 1000;
        fixture.authorize(&fixture.request, lagging_clock).unwrap();
        fixture.admission.commit(
            |tx| {
                if expire_pin {
                    let digest = ManifestDigest::new(fixture.request.manifest_digest);
                    let mut pin = tx.world.pin_manifests.get(&digest).unwrap().clone();
                    pin.policy.retention_epoch = NOW + 3;
                    tx.world.pin_manifests.insert(digest, pin);
                }
            },
            true,
        );
        assert!(fixture.authorize(&fixture.request, lagging_clock).is_err());
    }
}

#[test]
fn source_requires_both_live_admissions_exact_lease_owner_and_unchanged_claims() {
    let fixture = Fixture::new();
    let now = (NOW + 3) * 1000;
    fixture.authorize(&fixture.request, now).unwrap();
    assert!(
        authorize_repair_source_v1(
            &fixture.admission.state.view(),
            &AccountId::new(key(2).public_key().clone()),
            &fixture.request,
            now
        )
        .is_err()
    );
    for mutation in 0..8 {
        let mut request = fixture.request.clone();
        match mutation {
            0 => request.task_revision += 1,
            1 => request.lease_generation += 1,
            2 => request.floor.block_hash[0] ^= 1,
            3 => request.floor.height += 1,
            4 => request.task_id[0] ^= 1,
            5 => request.manifest_digest[0] ^= 1,
            6 => request.target_provider[0] ^= 1,
            _ => request.source_provider[0] ^= 1,
        }
        assert!(
            fixture.authorize(&request, now).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(
        fixture
            .authorize(&fixture.request, (NOW + 1) * 1000)
            .is_err()
    );
    assert!(
        fixture
            .authorize(&fixture.request, (NOW + 62) * 1000)
            .is_err()
    );
}

#[test]
fn permission_removal_pin_expiry_and_native_revocation_close_existing_lease() {
    for mutation in 0..4 {
        let mut fixture = Fixture::new();
        fixture
            .authorize(&fixture.request, (NOW + 3) * 1000)
            .unwrap();
        let mut revoke = fixture.admission.revocation();
        if mutation == 3 {
            let digest = sorafs_manifest::provider_admission::compute_envelope_digest(
                &fixture.source_envelope,
            )
            .unwrap();
            revoke.provider_id = fixture.source_envelope.proposal.provider_id;
            revoke.envelope_digest = digest;
            revoke.expected_current_event_digest = digest;
            revoke.council_signatures[0].signature = iroha_crypto::Signature::new(
                fixture.admission.signer.private_key(),
                &revoke.digest().unwrap(),
            )
            .payload()
            .to_vec();
        }
        fixture.admission.commit(
            |tx| match mutation {
                0 => Revoke::account_permission(
                    Permission::from(CanOperateSorafsRepair {
                        provider_id: ProviderId::new(fixture.request.target_provider),
                    }),
                    fixture.owner.clone(),
                )
                .execute(&fixture.owner, tx)
                .unwrap(),
                1 => {
                    let digest = ManifestDigest::new(fixture.request.manifest_digest);
                    let mut pin = tx.world.pin_manifests.get(&digest).unwrap().clone();
                    pin.policy.retention_epoch = NOW + 3;
                    tx.world.pin_manifests.insert(digest, pin);
                }
                _ => enact_for_test(
                    Action::Revoke(norito::encode_canonical(&revoke).unwrap()),
                    tx,
                ),
            },
            true,
        );
        assert!(
            fixture
                .authorize(&fixture.request, (NOW + 3) * 1000)
                .is_err()
        );
    }
}

#[test]
fn source_requires_the_current_and_original_floor_durable_qcs() {
    for floor in [true, false] {
        let mut fixture = Fixture::new();
        fixture.admission.commit(|_| {}, true);
        fixture
            .authorize(&fixture.request, (NOW + 3) * 1000)
            .unwrap();
        let height = if floor {
            fixture.request.floor.height
        } else {
            fixture.admission.state.view().height() as u64
        };
        // The certified frame (block and commit certificate) is no longer held.
        fixture
            .admission
            .state
            .kura()
            .corrupt_canonical_body_for_testing(
                std::num::NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap(),
            )
            .unwrap();
        assert!(
            fixture
                .authorize(&fixture.request, (NOW + 3) * 1000)
                .is_err()
        );
    }
}
