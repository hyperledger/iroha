//! Native selection and ordinary-open controls, without fabricated finalized authority.
use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::block::BlockHeader;
use std::sync::OnceLock;

fn fixture() -> (
    tempfile::TempDir,
    NetworkId,
    Arc<NativeResolverV1>,
    SorafsProviderAttestationJournal,
) {
    let root = tempfile::tempdir().unwrap();
    let key = KeyPair::try_from_seed(vec![0x35; 32], Algorithm::Ed25519).unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0x41; 32]),
    ));
    let mut config = super::super::tests::native_attestation_test_config();
    config.completion_signer_public_key = key.public_key().clone();
    let resolver = Arc::new(NativeResolverV1 {
        config,
        provider: ProviderId::new([0x42; 32]),
        key: Arc::new(key),
        completion_signer: authority.clone(),
        state: Arc::new(OnceLock::new()),
    });
    let policy = MusubiProviderAttestationJournalPolicyV1::default();
    let journal = SorafsProviderAttestationJournal {
        clock: SorafsProviderAttestationRuntimeBinding {
            handle: NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1.to_owned(),
            revision: 1,
            policy_digest: policy.digest().unwrap(),
        },
        approval_signer: SorafsProviderAttestationRuntimeBinding {
            handle: NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1.to_owned(),
            revision: 1,
            policy_digest: musubi_provider_attestation_controller_policy_digest_v1(&authority)
                .unwrap(),
        },
        inventory: SorafsProviderAttestationRuntimeBinding {
            handle: NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1.to_owned(),
            revision: 1,
            policy_digest: policy.digest().unwrap(),
        },
        max_entries: policy.max_entries,
        max_attempts: policy.max_attempts,
        lease_ttl_ms: policy.lease_ttl_ms,
        approval_timeout_ms: policy.approval_timeout_ms,
        handoff_timeout_ms: policy.handoff_timeout_ms,
        retry_delay_ms: policy.retry_delay_ms,
        checkpoint_max_bytes: policy.checkpoint_max_bytes,
        max_cas_retries: policy.max_cas_retries,
    };
    (root, network, resolver, journal)
}

#[test]
fn native_selection_ordinary_open_never_initializes_and_exposes_no_current_authority() {
    let (root, network, resolver, journal) = fixture();
    assert!(NativeAttestationV1::open(root.path(), network, resolver.clone(), &journal).is_err());
    assert!(!root.path().join("provider-attestation-native").exists());
    NativeMusubiProviderAttestationCustodyV1::initialize(
        root.path(),
        network,
        resolver.provider,
        provider_attestation_journal_policy(&journal).unwrap(),
    )
    .unwrap();
    let native =
        NativeAttestationV1::open(root.path(), network, resolver.clone(), &journal).unwrap();
    let qualification = native.signer.qualification().unwrap();
    qualification.validate().unwrap();
    assert_eq!(qualification.authority, resolver.completion_signer);
    assert_eq!(
        qualification.adapter_policy_digest,
        journal.approval_signer.policy_digest
    );
    assert_eq!(
        native.signer.current_eligibility(),
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable)
    );
    assert!(Arc::ptr_eq(
        &native.custody.inventory(),
        &native.custody.inventory()
    ));
    assert!(NativeAttestationV1::open(root.path(), network, resolver.clone(), &journal).is_err());
    drop(native);
    NativeAttestationV1::open(root.path(), network, resolver, &journal).unwrap();
}

#[test]
fn every_native_binding_is_exact_before_history_is_opened() {
    let (root, network, resolver, journal) = fixture();
    for field in 0..3 {
        for mutation in 0..3 {
            let mut changed = journal.clone();
            let binding = match field {
                0 => &mut changed.clock,
                1 => &mut changed.approval_signer,
                _ => &mut changed.inventory,
            };
            match mutation {
                0 => binding.handle.push_str("-other"),
                1 => binding.revision += 1,
                _ => binding.policy_digest[0] ^= 1,
            }
            let error = NativeAttestationV1::open(root.path(), network, resolver.clone(), &changed)
                .err()
                .unwrap();
            assert_eq!(
                error.to_string(),
                "native provider-attestation qualification binding rejected"
            );
        }
    }
    assert!(!root.path().join("provider-attestation-native").exists());
}

#[test]
fn wrong_current_scope_refuses_existing_original_without_repair() {
    let (root, network, resolver, journal) = fixture();
    let policy = provider_attestation_journal_policy(&journal).unwrap();
    NativeMusubiProviderAttestationCustodyV1::initialize(
        root.path(),
        network,
        resolver.provider,
        policy,
    )
    .unwrap();
    let original =
        std::fs::read(root.path().join("provider-attestation-native/journal.nrt")).unwrap();
    let foreign_network = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x45; 32])),
    );
    assert_ne!(network, foreign_network);
    assert!(
        NativeAttestationV1::open(root.path(), foreign_network, resolver.clone(), &journal)
            .is_err()
    );
    let mut different_policy = journal.clone();
    different_policy.max_attempts -= 1;
    let digest = provider_attestation_journal_policy(&different_policy)
        .unwrap()
        .digest()
        .unwrap();
    different_policy.clock.policy_digest = digest;
    different_policy.inventory.policy_digest = digest;
    assert!(NativeAttestationV1::open(root.path(), network, resolver, &different_policy).is_err());
    assert_eq!(
        std::fs::read(root.path().join("provider-attestation-native/journal.nrt")).unwrap(),
        original
    );
}

#[test]
fn dedicated_signer_request_bindings_refuse_before_unbound_state_is_read() {
    let (root, network, resolver, journal) = fixture();
    NativeMusubiProviderAttestationCustodyV1::initialize(
        root.path(),
        network,
        resolver.provider,
        provider_attestation_journal_policy(&journal).unwrap(),
    )
    .unwrap();
    let native =
        NativeAttestationV1::open(root.path(), network, resolver.clone(), &journal).unwrap();
    // Structurally valid payload only. No opaque request or finalized authority is manufactured.
    let mut payload = super::super::tests::test_musubi_attestation_payload(&resolver.key);
    payload.binding.network_id = network;
    payload.binding.provider_id = resolver.provider;
    payload.binding.completion_authority.signer_policy = resolver.config.completion_signer_policy;
    let owner = KeyPair::try_from_seed(vec![0x77; 32], Algorithm::Ed25519).unwrap();
    payload.binding.completion_authority.provider_owner =
        AccountId::new(owner.public_key().clone());
    assert_ne!(
        payload.binding.completion_authority.provider_owner,
        resolver.completion_signer
    );
    payload.validate().unwrap();
    let observed = sorafs_node::provider_ingest_outbox::ProviderIngestFinalizedCursorV1 {
        height: 80,
        block_hash: [0x2C; 32],
    };
    let check = |payload: &MusubiProviderBundleVerificationPayloadV1, claim| {
        native.signer.check_request(
            payload,
            observed,
            claim,
            resolver.config.completion_signer_policy,
        )
    };
    assert_eq!(
        check(&payload, [0x2B; 32]),
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable)
    );
    assert_eq!(
        check(&payload, [0; 32]),
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
    let mut substituted = payload.clone();
    substituted.binding.completed_by = payload.binding.completion_authority.provider_owner.clone();
    assert_eq!(
        check(&substituted, [0x2B; 32]),
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
    substituted = payload.clone();
    substituted.binding.provider_id = ProviderId::new([0x81; 32]);
    assert_eq!(
        check(&substituted, [0x2B; 32]),
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
    substituted = payload;
    substituted.binding.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x83; 32])),
    );
    assert_eq!(
        check(&substituted, [0x2B; 32]),
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
}

#[test]
fn source_capacity_refusal_remains_retryable_instead_of_rejecting_the_signer() {
    use iroha_core::execution_attempt::ExecutionAttemptError;
    assert_eq!(
        map_execution_attempt(&ExecutionAttemptError::<()>::Deferred(
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
        )),
        MusubiProviderAttestationSignerErrorV1::Unavailable,
    );
    assert_eq!(
        map_execution_attempt(&ExecutionAttemptError::Rejected(())),
        MusubiProviderAttestationSignerErrorV1::Rejected,
    );
}
