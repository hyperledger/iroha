//! Actual encrypted-service controls for Musubi's exact approval subject.
use super::*;
use crate::external_software_signer::{
    SignerKeyAlgorithmV1, SignerPurposeBindingV1, SoftwareSignerProvisioningV1,
    SoftwareSignerServiceV1, SoftwareSignerWrappingKeyV1,
    protocol::{AdminCommandV1, AdminRequestV1, AdminStatusV1, admin_request_digest},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    musubi::{
        ArchiveId, MusubiContentDigestV1, MusubiProviderBundleVerificationBindingV1,
        MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ProviderIngestCompletionAuthorityV1, ProviderIngestFinalizedAnchorV1,
            ReplicationOrderId,
        },
    },
};
use std::os::unix::fs::PermissionsExt as _;
const WRAP: [u8; 32] = [0x74; 32];
fn wrap() -> SoftwareSignerWrappingKeyV1 {
    SoftwareSignerWrappingKeyV1::try_from_bytes(WRAP).unwrap()
}
fn policy() -> ProviderIngestCompletionSignerPolicyV1 {
    ProviderIngestCompletionSignerPolicyV1 {
        policy_id: [3; 32],
        revision: 2,
        predecessor_digest: Some([4; 32]),
        policy_digest: [5; 32],
    }
}
fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([6; 32]),
    ))
}
fn provider_owner() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn purpose(owner: &AccountId) -> SignerPurposeBindingV1 {
    SignerPurposeBindingV1::MusubiProviderAttestation {
        network_id: *network().as_bytes(),
        provider_id: [7; 32],
        provider_owner_account_id: norito::encode_canonical(&provider_owner()).unwrap(),
        completion_signer_account_id: norito::encode_canonical(owner).unwrap(),
        policy_id: policy().policy_id,
        policy_revision: policy().revision,
        predecessor_digest: policy().predecessor_digest,
        policy_digest: policy().policy_digest,
    }
}
fn payload(owner: AccountId) -> MusubiProviderBundleVerificationPayloadV1 {
    MusubiProviderBundleVerificationPayloadV1 {
        version: 1,
        binding: MusubiProviderBundleVerificationBindingV1 {
            network_id: network(),
            provider_id: ProviderId::new([7; 32]),
            completed_by: owner.clone(),
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                provider_owner(),
                owner,
                policy(),
            ),
            replication_order: ReplicationOrderId::new([8; 32]),
            assignment_revision: 1,
            completion_epoch: 1,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 1,
                block_hash: [9; 32],
            },
            archive_id: ArchiveId::new([10; 32]),
            bundle_digest: MusubiContentDigestV1::new([11; 32]),
            descriptor_digest: MusubiContentDigestV1::new([12; 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([13; 32]),
            verification_lock_digest: MusubiVerificationLockDigestV1::new([14; 32]),
            source_tree_digest: MusubiContentDigestV1::new([15; 32]),
        },
    }
}
fn provision(
    parent: &std::path::Path,
    name: &str,
    owner: &AccountId,
    key: KeyPair,
) -> Arc<SoftwareSignerServiceV1> {
    let uid = rustix::process::geteuid().as_raw();
    Arc::new(
        SoftwareSignerServiceV1::provision_with_keypair(
            parent.join(name),
            SoftwareSignerProvisioningV1 {
                handle: format!("software://sorafs/musubi-provider-attestation/{name}"),
                service_id: format!("musubi-service-{name}"),
                administrator_id: format!("musubi-administrator-{name}"),
                service_uid: uid,
                client_uid: uid + 1,
                administrator_uid: uid + 2,
                role: SignerRoleV1::MusubiProviderAttestation,
                purpose_binding: purpose(owner),
                algorithm: SignerKeyAlgorithmV1::try_from(key.algorithm()).unwrap(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: [16; 32],
                max_request_bytes: 1024 * 1024,
            },
            wrap(),
            key,
        )
        .unwrap(),
    )
}
pub fn service_fixture() -> (
    tempfile::TempDir,
    Arc<SoftwareSignerServiceV1>,
    MusubiProviderBundleVerificationPayloadV1,
) {
    let parent = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyPair::from_seed(vec![17; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let service = provision(parent.path(), "primary", &owner, key);
    (parent, service, payload(owner))
}
fn adapter(
    clients: Vec<SoftwareSignerClientV1>,
) -> ExternalSoftwareSignerMusubiProviderAttestationAdapterV1 {
    let handle = "software://sorafs/musubi-provider-attestation/controller".to_owned();
    let mut bindings: Vec<_> = clients
        .iter()
        .map(|c| c.expected_binding().clone())
        .collect();
    bindings.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let digest =
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::policy_digest_for_bindings(
            &handle, 1, &bindings,
        )
        .unwrap();
    ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::try_new(handle, 1, digest, clients)
        .unwrap()
}
fn client(service: &Arc<SoftwareSignerServiceV1>) -> SoftwareSignerClientV1 {
    SoftwareSignerClientV1::new_direct(Arc::clone(service)).unwrap()
}
fn encoded(payload: &MusubiProviderBundleVerificationPayloadV1) -> Vec<u8> {
    encode_typed_signing_payload(
        SignerRoleV1::MusubiProviderAttestation,
        SoftwareSignerPurposeV1::MusubiProviderAttestation,
        &norito::encode_canonical(payload).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn dedicated_completion_approval_retains_independent_provider_owner() {
    let (_parent, service, payload) = service_fixture();
    let binding = &payload.binding;
    assert_ne!(
        binding.completion_authority.provider_owner,
        binding.completed_by
    );
    assert_eq!(
        binding.completion_authority.completion_signer,
        binding.completed_by
    );
    let approval = adapter(vec![client(&service)])
        .approve_payload(payload.clone(), [61; 32])
        .await
        .unwrap();
    approval.verify(binding).unwrap();
    assert_eq!(approval.payload, payload);
    let mut wrong = payload.clone();
    wrong.binding.completion_authority.provider_owner = wrong.binding.completed_by.clone();
    assert!(
        adapter(vec![client(&service)])
            .approve_payload(wrong, [62; 32])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn approval_worker_panic_is_unavailable() {
    let result: Result<(), _> = approve_payload_recoverably(|| {
        assert!(iroha_panic_hook::is_suppressed());
        panic!("injected approval worker failure");
    })
    .await;
    assert_eq!(
        result,
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable)
    );
}

#[tokio::test]
async fn musubi_software_replays_exact_approval_after_service_restart_and_lost_reply() {
    let (parent, service, payload) = service_fixture();
    let operation = [20; 32];
    // Simulate the caller losing the result after durable commit.
    let committed = client(&service)
        .sign(operation, &encoded(&payload))
        .unwrap();
    assert!(!committed.replayed);
    let expected = adapter(vec![client(&service)])
        .approve_payload(payload.clone(), operation)
        .await
        .unwrap();
    assert_eq!(
        expected.approvals[0].signature.payload(),
        committed.signature
    );
    drop(service);
    let reopened =
        Arc::new(SoftwareSignerServiceV1::open(parent.path().join("primary"), wrap()).unwrap());
    let replay = client(&reopened)
        .sign(operation, &encoded(&payload))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.signature, committed.signature);
    assert_eq!(replay.commit_sequence, committed.commit_sequence);
    assert_eq!(
        adapter(vec![client(&reopened)])
            .approve_payload(payload, operation)
            .await
            .unwrap(),
        expected
    );
}
#[test]
fn musubi_software_rejects_cross_identity_and_policy_before_signing() {
    let (_parent, service, payload) = service_fixture();
    let client = client(&service);
    let initial = service.provenance().unwrap().audit_sequence;
    for index in 0..8 {
        let mut altered = payload.clone();
        match index {
            0 => {
                altered.binding.network_id = NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([42; 32])),
                )
            }
            1 => altered.binding.provider_id = ProviderId::new([42; 32]),
            2 => {
                let owner = AccountId::new(
                    KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                );
                altered.binding.completed_by = owner.clone();
                altered.binding.completion_authority.completion_signer = owner;
            }
            3 => altered.binding.completion_authority.signer_policy.policy_id = [42; 32],
            4 => altered.binding.completion_authority.signer_policy.revision = 3,
            5 => {
                altered
                    .binding
                    .completion_authority
                    .signer_policy
                    .predecessor_digest = Some([42; 32])
            }
            6 => {
                altered
                    .binding
                    .completion_authority
                    .signer_policy
                    .policy_digest = [42; 32]
            }
            _ => {
                altered.binding.completion_authority.provider_owner =
                    altered.binding.completed_by.clone()
            }
        }
        assert!(client.sign([index + 1; 32], &encoded(&altered)).is_err());
        assert_eq!(service.provenance().unwrap().audit_sequence, initial);
    }
    let mut noncanonical = norito::encode_canonical(&payload).unwrap();
    noncanonical.push(0);
    let malformed = encode_typed_signing_payload(
        SignerRoleV1::MusubiProviderAttestation,
        SoftwareSignerPurposeV1::MusubiProviderAttestation,
        &noncanonical,
    )
    .unwrap();
    assert!(client.sign([30; 32], &malformed).is_err());
    assert_eq!(service.provenance().unwrap().audit_sequence, initial);
    let foreign = encode_typed_signing_payload(
        SignerRoleV1::GovernanceDag,
        SoftwareSignerPurposeV1::GovernanceLogNode,
        b"foreign-purpose",
    )
    .unwrap();
    assert!(client.sign([31; 32], &foreign).is_err());
    assert_eq!(service.provenance().unwrap().audit_sequence, initial);
}
#[tokio::test]
async fn musubi_software_equivocation_and_revocation_never_release_approval() {
    let (parent, service, payload) = service_fixture();
    let client = client(&service);
    let adapter = adapter(vec![client.clone()]);
    client.sign([32; 32], &encoded(&payload)).unwrap();
    let mut altered = payload.clone();
    altered.binding.bundle_digest = MusubiContentDigestV1::new([33; 32]);
    assert!(matches!(
        client.sign([32; 32], &encoded(&altered)),
        Err(super::super::unix::ExternalSoftwareSignerClientErrorV1::Equivocation)
    ));
    let before = service.provenance().unwrap();
    let command = AdminCommandV1::Revoke {
        operation_id: [34; 32],
        expected_audit_head: before.audit_head,
        expected_key_revision: before.binding.key_revision,
        reason_digest: [35; 32],
    };
    let binding_digest = before.binding.digest().unwrap();
    let response = service
        .handle_admin_request(&AdminRequestV1 {
            binding_digest,
            request_digest: admin_request_digest(binding_digest, &command).unwrap(),
            command,
        })
        .unwrap();
    assert_eq!(response.status, AdminStatusV1::Ok);
    assert!(
        adapter
            .approve_payload(payload.clone(), [32; 32])
            .await
            .is_err()
    );
    assert_eq!(
        adapter.current_eligibility(),
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
    drop(adapter);
    drop(client);
    drop(service);
    let reopened =
        Arc::new(SoftwareSignerServiceV1::open(parent.path().join("primary"), wrap()).unwrap());
    assert!(
        SoftwareSignerClientV1::new_direct(reopened)
            .unwrap()
            .sign([32; 32], &encoded(&payload))
            .is_err()
    );
}
#[tokio::test]
async fn musubi_software_multisig_uses_same_sorted_complete_controller_set() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let parent = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let keys: Vec<_> = (40..43)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519))
        .collect();
    let owner = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            keys.iter()
                .map(|key| MultisigMember::new(key.public_key().clone(), 1).unwrap())
                .collect(),
        )
        .unwrap(),
    );
    let services: Vec<_> = keys
        .into_iter()
        .enumerate()
        .map(|(i, key)| provision(parent.path(), &format!("member-{i}"), &owner, key))
        .collect();
    let incomplete = vec![client(&services[0])];
    let handle = "software://sorafs/musubi-provider-attestation/controller";
    let digest =
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::policy_digest_for_bindings(
            handle,
            1,
            &[incomplete[0].expected_binding().clone()],
        )
        .unwrap();
    assert!(
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::try_new(
            handle.to_owned(),
            1,
            digest,
            incomplete,
        )
        .is_err()
    );
    let adapter = adapter(services.iter().rev().map(client).collect());
    let payload = payload(owner);
    // One member committed before the coordinator lost its result. The complete
    // retry must combine that exact durable approval with the remaining members.
    let partial_client = client(&services[1]);
    let partial = partial_client.sign([44; 32], &encoded(&payload)).unwrap();
    let first = adapter
        .approve_payload(payload.clone(), [44; 32])
        .await
        .unwrap();
    assert_eq!(first.approvals.len(), 3);
    assert_eq!(
        first
            .approvals
            .iter()
            .find(|approval| {
                approval.public_key == partial_client.expected_binding().public_key
            })
            .unwrap()
            .signature
            .payload(),
        partial.signature,
    );
    assert!(
        first
            .approvals
            .windows(2)
            .all(|p| p[0].public_key < p[1].public_key)
    );
    assert_eq!(
        adapter.approve_payload(payload, [44; 32]).await.unwrap(),
        first
    );
}

#[test]
fn musubi_software_cannot_rotate_outside_pinned_controller_or_replace_its_policy() {
    let (parent, service, _payload) = service_fixture();
    let before = service.provenance().unwrap();
    let bytes = std::fs::read(parent.path().join("primary/key-envelope-v1.norito")).unwrap();
    let command = AdminCommandV1::Rotate {
        operation_id: [45; 32],
        expected_audit_head: before.audit_head,
        expected_key_revision: before.binding.key_revision,
        new_key_revision: 2,
        new_policy_revision: 2,
        new_policy_digest: [46; 32],
        algorithm: SignerKeyAlgorithmV1::Ed25519,
    };
    let binding_digest = before.binding.digest().unwrap();
    assert!(
        service
            .handle_admin_request(&AdminRequestV1 {
                request_digest: admin_request_digest(binding_digest, &command).unwrap(),
                binding_digest,
                command,
            })
            .is_err()
    );
    assert_eq!(service.public_binding().unwrap(), before.binding);
    assert_eq!(
        service.provenance().unwrap().audit_sequence,
        before.audit_sequence
    );
    assert_eq!(
        std::fs::read(parent.path().join("primary/key-envelope-v1.norito")).unwrap(),
        bytes
    );
}
#[test]
fn musubi_software_adapter_rejects_duplicate_keys_and_unreviewed_custody_set() {
    let (_parent, service, _payload) = service_fixture();
    let client = client(&service);
    let handle = "software://sorafs/musubi-provider-attestation/controller".to_owned();
    let binding = client.expected_binding().clone();
    assert!(
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::policy_digest_for_bindings(
            &handle,
            1,
            &[binding.clone(), binding.clone()]
        )
        .is_err()
    );
    assert!(
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::try_new(
            handle.clone(),
            1,
            [99; 32],
            vec![client.clone()]
        )
        .is_err()
    );
    let digest =
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::policy_digest_for_bindings(
            &handle,
            1,
            &[binding],
        )
        .unwrap();
    assert!(
        ExternalSoftwareSignerMusubiProviderAttestationAdapterV1::try_new(
            handle,
            2,
            digest,
            vec![client]
        )
        .is_err()
    );
}

#[tokio::test]
async fn musubi_software_mldsa_approves_the_canonical_typed_hash() {
    let parent = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyPair::from_seed(vec![61; 32], Algorithm::MlDsa);
    let owner = AccountId::new(key.public_key().clone());
    let service = provision(parent.path(), "post-quantum", &owner, key);
    let payload = payload(owner);
    let attestation = adapter(vec![client(&service)])
        .approve_payload(payload.clone(), [62; 32])
        .await
        .unwrap();
    attestation.verify(&payload.binding).unwrap();
    assert_eq!(
        attestation.approvals[0].public_key.algorithm(),
        Algorithm::MlDsa
    );
    assert!(service.provenance().unwrap().audit_sequence > 1);
}

#[test]
fn musubi_software_nonmember_key_is_rejected_before_custody_creation() {
    let (parent, service, _) = service_fixture();
    let binding = service.public_binding().unwrap();
    let directory = parent.path().join("nonmember");
    let provisioning = SoftwareSignerProvisioningV1 {
        handle: "software://sorafs/musubi-provider-attestation/nonmember".to_owned(),
        service_id: "musubi-service-nonmember".to_owned(),
        administrator_id: "musubi-administrator-nonmember".to_owned(),
        service_uid: binding.service_uid,
        client_uid: binding.client_uid,
        administrator_uid: binding.administrator_uid,
        role: binding.role,
        purpose_binding: binding.purpose_binding,
        algorithm: binding.key_algorithm,
        key_revision: binding.key_revision,
        policy_revision: binding.policy_revision,
        policy_digest: binding.policy_digest,
        max_request_bytes: binding.max_request_bytes,
    };
    let other_key = KeyPair::from_seed(vec![63; 32], Algorithm::Ed25519);
    assert!(matches!(
        SoftwareSignerServiceV1::provision_with_keypair(
            directory.clone(),
            provisioning,
            wrap(),
            other_key,
        ),
        Err(crate::external_software_signer::SoftwareSignerErrorV1::InvalidBinding)
    ));
    assert!(!directory.exists());
}

#[tokio::test]
async fn musubi_software_shared_admission_refuses_without_custody_effects() {
    let (_directory, service, payload) = service_fixture();
    let adapter = adapter(vec![client(&service)]);
    let clone = adapter.clone();
    let permit = Arc::clone(&adapter.admission).try_acquire_owned().unwrap();
    let before = service.provenance().unwrap().audit_sequence;
    assert_eq!(
        clone.approve_payload(payload.clone(), [64; 32]).await,
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable),
    );
    assert_eq!(service.provenance().unwrap().audit_sequence, before);
    drop(permit);
    clone.approve_payload(payload, [64; 32]).await.unwrap();
}
