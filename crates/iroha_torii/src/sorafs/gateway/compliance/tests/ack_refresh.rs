//! Same-vote ACK refresh through the native controller, real signatures and durable stores.
//!
//! These component fixtures sign new gateway observations. They do not assert that a running
//! gateway reloaded; the runtime owner must observe the actual reload before creating an ACK.
use super::*;
use crate::sorafs::gateway::ProductionGatewayComplianceFeedTransport;
use ed25519_dalek::SigningKey;

fn empty_config() -> GatewayComplianceControllerConfig {
    let mut selected = config();
    selected.feeds.clear();
    selected.feed_transport_provider = Some(
        GatewayProviderBindingV1::try_new(
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.into(),
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            gateway_compliance_feed_transport_policy_digest(&BTreeMap::new()).unwrap(),
        )
        .unwrap(),
    );
    selected
}

fn open_with(
    selected: GatewayComplianceControllerConfig,
    store: Arc<dyn GatewayComplianceStore>,
) -> GatewayComplianceController {
    let transport = ProductionGatewayComplianceFeedTransport::try_new(BTreeMap::new()).unwrap();
    GatewayComplianceController::new_with_feed_transport(selected, store, &transport).unwrap()
}

fn open(store: Arc<dyn GatewayComplianceStore>) -> GatewayComplianceController {
    open_with(empty_config(), store)
}

fn catalog(selected: &GatewayComplianceControllerConfig) -> GatewayComplianceCatalogV1 {
    let mut value = payload(1, None);
    value.source_anchors.clear();
    value.policy_digest = selected.trust_policy.canonical_digest().unwrap();
    sign_catalog(value)
}

fn stage(controller: &GatewayComplianceController) -> [u8; 32] {
    controller
        .stage_catalog(
            catalog(&empty_config()),
            NOW + 5,
            indexed_mutation_binding(1),
        )
        .unwrap()
        .catalog_digest
}

fn original_acks(controller: &GatewayComplianceController, digest: [u8; 32]) {
    for index in 0..2 {
        controller
            .acknowledge(
                acknowledgement_at(index, digest, true, NOW + 10),
                NOW + 10,
                indexed_mutation_binding(2 + index as u64),
            )
            .unwrap();
    }
}

fn assert_unchanged(
    controller: &GatewayComplianceController,
    store: &MemoryStore,
    before: &GatewayComplianceCheckpointV1,
    bytes: &[u8],
) {
    assert_eq!(&controller.checkpoint().unwrap(), before);
    assert_eq!(store.durable_bytes().unwrap(), bytes);
}

fn exercise_restart_refresh(
    store: Arc<dyn GatewayComplianceStore>,
    durable_bytes: impl Fn() -> Vec<u8>,
) {
    let controller = open(store.clone());
    let digest = stage(&controller);
    original_acks(&controller, digest);
    let original_catalog = controller.checkpoint().unwrap().candidate.unwrap();
    assert_eq!(original_catalog.approvals.len(), 2);
    let before = durable_bytes();
    drop(controller);
    let controller = open(store.clone());
    assert_eq!(durable_bytes(), before);
    assert!(matches!(
        controller.promote(digest, 1, NOW + 311, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::InvalidAcknowledgement(_))
    ));
    assert_eq!(durable_bytes(), before);

    // A genuine new signature over the same vote and catalog replaces exactly one stale ACK.
    let eu = acknowledgement_at(0, digest, true, NOW + 311);
    assert_ne!(eu.signature, acknowledgement(0, digest, true).signature);
    let refreshed = controller
        .acknowledge(eu.clone(), NOW + 311, indexed_mutation_binding(4))
        .unwrap();
    let one_fresh = controller.checkpoint().unwrap();
    assert_eq!(one_fresh.revision, 4);
    assert_eq!(one_fresh.acknowledgements.len(), 2);
    assert_eq!(one_fresh.acknowledgements[0], eu);
    assert_eq!(
        one_fresh.acknowledgements[1],
        acknowledgement(1, digest, true)
    );
    assert_eq!(one_fresh.candidate.as_ref(), Some(&original_catalog));
    let after_one = durable_bytes();
    assert!(matches!(
        controller.promote(digest, 1, NOW + 311, indexed_mutation_binding(5)),
        Err(GatewayComplianceError::InvalidAcknowledgement(_))
    ));
    assert_eq!(durable_bytes(), after_one);
    // The original request replay cannot downgrade the newer vote or refresh either timestamp.
    let original_result = controller
        .acknowledge(
            acknowledgement(0, digest, true),
            NOW + 312,
            indexed_mutation_binding(2),
        )
        .unwrap();
    assert_eq!(original_result.recorded_at_unix, NOW + 10);
    assert_eq!(controller.checkpoint().unwrap(), one_fresh);
    assert_eq!(durable_bytes(), after_one);
    drop(controller);

    // Restart retains the refreshed EU observation and the independently stale US observation.
    let controller = open(store.clone());
    assert_eq!(controller.checkpoint().unwrap(), one_fresh);
    let us = acknowledgement_at(1, digest, true, NOW + 312);
    controller
        .acknowledge(us.clone(), NOW + 312, indexed_mutation_binding(5))
        .unwrap();
    let both_fresh = controller.checkpoint().unwrap();
    assert_eq!(both_fresh.revision, 5);
    assert_eq!(both_fresh.acknowledgements, vec![eu.clone(), us]);
    assert_eq!(both_fresh.candidate.as_ref(), Some(&original_catalog));
    controller
        .promote(digest, 1, NOW + 313, indexed_mutation_binding(6))
        .unwrap();
    let promoted = controller.checkpoint().unwrap();
    assert_eq!(promoted.revision, 6);
    assert_eq!(promoted.serving.as_ref(), Some(&original_catalog));
    assert!(promoted.candidate.is_none() && promoted.acknowledgements.is_empty());
    let final_bytes = durable_bytes();
    drop(controller);
    let controller = open(store);
    assert_eq!(controller.checkpoint().unwrap(), promoted);
    assert_eq!(
        controller
            .acknowledge(eu, NOW + 7_200, indexed_mutation_binding(4))
            .unwrap(),
        refreshed
    );
    assert_eq!(durable_bytes(), final_bytes);
    assert!(matches!(
        controller.evaluate(
            "global",
            GatewayComplianceSubjectKindV1::Provider,
            &subject(1),
            original_catalog.payload.valid_until_unix,
        ),
        Err(GatewayComplianceError::CatalogNotFresh)
    ));
    assert_eq!(durable_bytes(), final_bytes);
}

#[test]
fn memory_reopen_refreshes_only_new_signed_same_votes_and_preserves_expiry() {
    let store = Arc::new(MemoryStore::default());
    exercise_restart_refresh(store.clone(), || store.durable_bytes().unwrap());
}

#[test]
fn file_reopen_refreshes_only_new_signed_same_votes_and_preserves_expiry() {
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path()).unwrap().join("checkpoint.to");
    let store = Arc::new(FileGatewayComplianceStore::new(path.clone()).unwrap());
    exercise_restart_refresh(store, || fs::read(&path).unwrap());
}

#[test]
fn refresh_refuses_stale_future_unsigned_and_changed_vote_observations_without_mutation() {
    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    original_acks(&controller, digest);
    let before = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    for (ack, now) in [
        (acknowledgement_at(0, digest, true, NOW + 11), NOW + 312),
        (acknowledgement_at(0, digest, true, NOW + 613), NOW + 312),
        (
            acknowledgement_at(0, [0xAF; 32], true, NOW + 100),
            NOW + 100,
        ),
    ] {
        assert!(matches!(
            controller.acknowledge(ack, now, indexed_mutation_binding(4)),
            Err(GatewayComplianceError::InvalidAcknowledgement(_))
        ));
        assert_unchanged(&controller, &store, &before, &bytes);
    }
    let mut rewritten = acknowledgement(0, digest, true);
    rewritten.payload.observed_at_unix = NOW + 100;
    assert!(matches!(
        controller.acknowledge(rewritten, NOW + 100, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::InvalidSignature { .. })
    ));
    assert_unchanged(&controller, &store, &before, &bytes);
    let mut substituted_gateway = acknowledgement_at(0, digest, true, NOW + 100);
    substituted_gateway.payload.gateway_id = "gateway-us".into();
    assert!(matches!(
        controller.acknowledge(substituted_gateway, NOW + 100, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::InvalidSignature { .. })
    ));
    assert_unchanged(&controller, &store, &before, &bytes);
    let mut version = acknowledgement_at(0, digest, true, NOW + 100);
    version.payload.version += 1;
    assert!(matches!(
        controller.acknowledge(version, NOW + 100, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::InvalidAcknowledgement(_))
    ));
    assert_unchanged(&controller, &store, &before, &bytes);
    for ack in [
        acknowledgement_at(0, digest, true, NOW + 9),
        acknowledgement_at(0, digest, false, NOW + 10),
        acknowledgement_at(0, digest, false, NOW + 11),
    ] {
        assert!(matches!(
            controller.acknowledge(ack, NOW + 100, indexed_mutation_binding(4)),
            Err(GatewayComplianceError::GatewayEquivocation(_))
        ));
        assert_unchanged(&controller, &store, &before, &bytes);
    }
    // Each rejection leaves this original request key available for an authentic fresh vote.
    controller
        .acknowledge(
            acknowledgement_at(0, digest, true, NOW + 100),
            NOW + 100,
            indexed_mutation_binding(4),
        )
        .unwrap();
    let after = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    // The old exact ACK under a NEW request key is not an old idempotency replay.
    assert!(matches!(
        controller.acknowledge(
            acknowledgement(0, digest, true),
            NOW + 101,
            indexed_mutation_binding(5)
        ),
        Err(GatewayComplianceError::GatewayEquivocation(_))
    ));
    assert_unchanged(&controller, &store, &after, &bytes);
}

#[test]
fn refresh_preserves_rejected_vote_and_exact_rejection_code_without_adding_quorum() {
    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    controller
        .acknowledge(
            acknowledgement(0, digest, false),
            NOW + 10,
            indexed_mutation_binding(2),
        )
        .unwrap();
    let rejected = acknowledgement_at(0, digest, false, NOW + 311);
    controller
        .acknowledge(rejected.clone(), NOW + 311, indexed_mutation_binding(3))
        .unwrap();
    let before = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    assert_eq!(before.acknowledgements, vec![rejected]);
    let mut different_reason = acknowledgement_at(0, digest, false, NOW + 312);
    different_reason.payload.rejection_code = Some("different-reload-failure".into());
    different_reason.signature = gateway_keys()[0]
        .sign(&different_reason.payload.signing_digest().unwrap())
        .to_bytes();
    for changed in [
        different_reason,
        acknowledgement_at(0, digest, true, NOW + 312),
    ] {
        assert!(matches!(
            controller.acknowledge(changed, NOW + 312, indexed_mutation_binding(4)),
            Err(GatewayComplianceError::GatewayEquivocation(_))
        ));
        assert_unchanged(&controller, &store, &before, &bytes);
    }
    controller
        .acknowledge(
            acknowledgement_at(1, digest, true, NOW + 312),
            NOW + 312,
            indexed_mutation_binding(4),
        )
        .unwrap();
    assert!(matches!(
        controller.promote(digest, 1, NOW + 313, indexed_mutation_binding(5)),
        Err(GatewayComplianceError::GatewayQuorumNotMet {
            found: 1,
            required: 2
        })
    ));
}

#[test]
fn refresh_uses_current_revocation_and_cannot_extend_original_catalog_lifetime() {
    let mut selected = empty_config();
    // A third distinct real gateway key keeps the configured two-vote quorum attainable even
    // with EU revoked. No policy or checkpoint is rewritten after controller construction.
    selected.trust_policy.gateway_signers.insert(
        0,
        GatewayComplianceTrustedSignerV1 {
            signer_id: "gateway-apac".into(),
            public_key: SigningKey::from_bytes(&[0x55; 32])
                .verifying_key()
                .to_bytes(),
        },
    );
    selected.trust_policy.revoked_gateway_signer_ids = vec!["gateway-eu".into()];
    selected.gateway_scope = "gateway:gateway-us".into();
    let store = Arc::new(MemoryStore::default());
    let controller = open_with(selected.clone(), store.clone());
    let digest = controller
        .stage_catalog(catalog(&selected), NOW + 5, indexed_mutation_binding(1))
        .unwrap()
        .catalog_digest;
    let before = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    assert!(matches!(
        controller.acknowledge(
            acknowledgement_at(0, digest, true, NOW + 311),
            NOW + 311,
            indexed_mutation_binding(2)
        ),
        Err(GatewayComplianceError::RevokedSigner(_))
    ));
    assert_unchanged(&controller, &store, &before, &bytes);

    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    original_acks(&controller, digest);
    let original_catalog = controller.checkpoint().unwrap().candidate.unwrap();
    for index in 0..2 {
        controller
            .acknowledge(
                acknowledgement_at(index, digest, true, NOW + 3_600),
                NOW + 3_600,
                indexed_mutation_binding(4 + index as u64),
            )
            .unwrap();
    }
    let before = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    assert_eq!(before.candidate.as_ref(), Some(&original_catalog));
    assert!(matches!(
        controller.promote(digest, 1, NOW + 3_600, indexed_mutation_binding(6)),
        Err(GatewayComplianceError::CatalogNotFresh)
    ));
    assert_unchanged(&controller, &store, &before, &bytes);
}

#[test]
fn refresh_failed_persistence_preserves_original_bytes_and_allows_same_request_retry() {
    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    original_acks(&controller, digest);
    let before = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    let refreshed = acknowledgement_at(0, digest, true, NOW + 311);
    store.fail_next_store();
    assert!(matches!(
        controller.acknowledge(refreshed.clone(), NOW + 311, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::Persistence(_))
    ));
    assert_unchanged(&controller, &store, &before, &bytes);
    controller
        .acknowledge(refreshed.clone(), NOW + 311, indexed_mutation_binding(4))
        .unwrap();
    assert_eq!(
        controller.checkpoint().unwrap().acknowledgements[0],
        refreshed
    );
    assert_eq!(
        controller.checkpoint().unwrap().revision,
        before.revision + 1
    );
}

#[test]
fn refresh_crash_after_durable_replace_reopens_without_rewriting_or_downgrading() {
    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    original_acks(&controller, digest);
    let refreshed = acknowledgement_at(0, digest, true, NOW + 311);
    store.fail_after_store();
    assert!(matches!(
        controller.acknowledge(refreshed.clone(), NOW + 311, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    let durable = store.durable_bytes().unwrap();
    let expected = decode_checkpoint(&durable).unwrap();
    assert_eq!(expected.acknowledgements[0], refreshed);
    assert_eq!(expected.revision, 4);
    drop(controller);
    let controller = open(store.clone());
    assert_eq!(controller.checkpoint().unwrap(), expected);
    assert_eq!(
        controller
            .acknowledge(refreshed, NOW + 7_200, indexed_mutation_binding(4))
            .unwrap()
            .recorded_at_unix,
        NOW + 311
    );
    assert_eq!(
        controller
            .acknowledge(
                acknowledgement(0, digest, true),
                NOW + 7_200,
                indexed_mutation_binding(2)
            )
            .unwrap()
            .recorded_at_unix,
        NOW + 10
    );
    assert_unchanged(&controller, &store, &expected, &durable);
}

#[test]
fn refresh_file_cas_conflict_preserves_external_checkpoint_and_fences_stale_owner() {
    let temp = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temp.path()).unwrap().join("checkpoint.to");
    let store = Arc::new(FileGatewayComplianceStore::new(path.clone()).unwrap());
    let controller = open(store.clone());
    let digest = stage(&controller);
    let original_staged = fs::read(&path).unwrap();
    original_acks(&controller, digest);
    // The existing store race hook substitutes an earlier genuine signed checkpoint during
    // preparation. The refresh must neither overwrite it nor expose an updated in-memory vote.
    store.replace_before_next_persist(original_staged.clone());
    assert!(matches!(
        controller.acknowledge(
            acknowledgement_at(0, digest, true, NOW + 311),
            NOW + 311,
            indexed_mutation_binding(4)
        ),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert_eq!(fs::read(&path).unwrap(), original_staged);
    drop(controller);
    let controller = open(store);
    let recovered = controller.checkpoint().unwrap();
    assert_eq!(recovered.revision, 1);
    assert!(recovered.acknowledgements.is_empty());
    assert_eq!(
        recovered
            .candidate
            .unwrap()
            .payload
            .catalog_digest()
            .unwrap(),
        digest
    );
    assert_eq!(fs::read(&path).unwrap(), original_staged);
}

#[test]
fn identical_ack_under_new_request_key_keeps_one_vote_and_original_signed_time() {
    let store = Arc::new(MemoryStore::default());
    let controller = open(store.clone());
    let digest = stage(&controller);
    let original = acknowledgement(0, digest, true);
    controller
        .acknowledge(original.clone(), NOW + 10, indexed_mutation_binding(2))
        .unwrap();
    let second = controller
        .acknowledge(original.clone(), NOW + 11, indexed_mutation_binding(3))
        .unwrap();
    let after = controller.checkpoint().unwrap();
    assert_eq!(after.revision, 3);
    assert_eq!(after.idempotency_records.len(), 3);
    assert_eq!(after.acknowledgements, vec![original.clone()]);
    assert_eq!(second.recorded_at_unix, NOW + 11);
    assert!(matches!(
        controller.promote(digest, 1, NOW + 12, indexed_mutation_binding(4)),
        Err(GatewayComplianceError::GatewayQuorumNotMet {
            found: 1,
            required: 2,
        })
    ));
    let refresh = acknowledgement_at(0, digest, true, NOW + 311);
    controller
        .acknowledge(refresh.clone(), NOW + 311, indexed_mutation_binding(4))
        .unwrap();
    let after = controller.checkpoint().unwrap();
    let bytes = store.durable_bytes().unwrap();
    assert_eq!(after.acknowledgements, vec![refresh]);
    assert_eq!(
        controller
            .acknowledge(original, NOW + 7_200, indexed_mutation_binding(3))
            .unwrap(),
        second,
    );
    assert_unchanged(&controller, &store, &after, &bytes);
}
