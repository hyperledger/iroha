//! Recovery binds its original child cursor and independently selected pre-dispatch parent.

use super::*;
use crate::attachment::tests::Fixture;

#[test]
fn pending_checkpoint_and_exact_next_decision_survive_canonical_reopen() {
    let mut fixture = Fixture::new();
    fixture.parent_receipt();
    let pending = PendingOperation {
        kind: PendingKind::Registration,
        checkpoint: fixture.parent.checkpoint().encode_canonical().unwrap(),
        replay: None,
    };
    pending.validate(&fixture.identity).unwrap();
    assert_eq!(pending.target(&fixture.identity).unwrap().height, 1);
    assert_eq!(pending.journal_name().unwrap(), "registration");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    let mut record = store.record.clone();
    record.pending = Some(pending);
    store.publish(&record, PublishMode::Replace).unwrap();
    store.record = record;
    assert!(store.progress(None).pending);
    drop(store);
    let store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert!(store.record.pending.is_some());
    let previous = PrivateDataspaceAnchorState::from_authorized_registration(
        fixture.identity.registration.clone(),
    )
    .unwrap();
    let anchor = fixture.child_anchor();
    let mut pending = PendingOperation {
        kind: PendingKind::Anchor { previous, anchor },
        checkpoint: fixture.parent.checkpoint().encode_canonical().unwrap(),
        replay: None,
    };
    pending.validate(&fixture.identity).unwrap();
    assert_eq!(pending.target(&fixture.identity).unwrap().height, 2);
    assert_eq!(pending.journal_name().unwrap(), "anchor-2");
    if let PendingKind::Anchor { anchor, .. } = &mut pending.kind {
        *anchor = fixture.child_anchor(); // genuine QC, but a gap from the retained cursor
    }
    assert!(pending.validate(&fixture.identity).is_err());
    pending.checkpoint = fixture.child.checkpoint().encode_canonical().unwrap();
    assert!(pending.verifier(&fixture.identity).is_err());
}

#[test]
fn status_carrier_is_only_a_bounded_hint_and_elapsed_budget_fails_before_io() {
    let mut report = OperationReport {
        status: OperationStatus::Applied,
        data: norito::json!({"evidence": {"block_height": 2}}),
    };
    assert_eq!(carrier_height(&report).unwrap().get(), 2);
    for evidence in [
        norito::json!(null),
        norito::json!({"block_height": 0}),
        norito::json!({"block_height": 1}),
        norito::json!({"block_height": "2"}),
    ] {
        report.data = norito::json!({"evidence": evidence});
        assert!(carrier_height(&report).is_err());
    }
    assert!(require_deadline(Instant::now()).is_err());
    assert!(require_deadline(Instant::now() + std::time::Duration::from_secs(1)).is_ok());
}

#[test]
fn parent_context_and_fresh_quorum_are_required_before_preparation_or_dispatch() {
    use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
    use iroha_data_model::{
        sumeragi_finality::SumeragiFinalityProof, transaction::FeePaymentIntent,
    };
    use iroha_model_base::peer::PeerId;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Offline(AtomicUsize);
    impl crate::verify::finality::FinalitySource for Offline {
        type Error = std::io::Error;
        fn finality_proof(
            &self,
            _: NonZeroU64,
        ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(std::io::Error::other("offline fixture"))
        }
        fn latest_attestation(
            &self,
            _: &PeerId,
            _: &[u8; 32],
        ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error>
        {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(std::io::Error::other("offline fixture"))
        }
    }
    let mut fixture = Fixture::new();
    fixture.parent_receipt();
    let dir = tempfile::tempdir().unwrap();
    let bootstrap = fixture.bootstrap(&dir.path().join("release"));
    let mut parent = ParentFinalityStore::open(&dir.path().join("parent"), &bootstrap).unwrap();
    let mut store =
        AttachmentStore::open(&dir.path().join("attachment"), fixture.identity.clone()).unwrap();
    let key = KeyPair::from_seed(vec![47; 32], Algorithm::Ed25519);
    let config = Config::load_table(
        "attachment-tests.toml",
        toml::toml! {
            chain = (fixture.parent.chain_id())
            network_id = (fixture.parent.network_id().to_string())
            torii_url = "https://parent.example/"
            [account]
            chain_discriminant = 753
            public_key = (key.public_key().to_string())
            private_key = (ExposedPrivateKey(key.private_key().clone()).to_string())
        },
    )
    .unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(vec![], None),
        max_total_fees: Default::default(),
        deadline: Instant::now() + std::time::Duration::from_secs(5),
    };
    let offline = Offline(AtomicUsize::new(0));
    let mut wrong = config.clone();
    wrong.torii_api_url = "https://foreign.example/".parse().unwrap();
    assert!(
        store
            .advance_parent(&wrong, &bootstrap, &mut parent, &offline, &options, None)
            .is_err()
    );
    assert_eq!(offline.0.load(Ordering::Relaxed), 0);
    assert!(
        store
            .advance_parent(&config, &bootstrap, &mut parent, &offline, &options, None)
            .is_err()
    );
    assert!(offline.0.load(Ordering::Relaxed) >= 3);
    assert!(!store.progress(None).pending);
    assert!(!store.directory.path().join("transactions").exists());
    assert!(store.confirmed().is_none());
}

#[test]
fn confirmed_receipt_and_pending_clear_are_one_durable_publication() {
    let mut fixture = Fixture::new();
    let original = fixture.parent.checkpoint().encode_canonical().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    store
        .publish_pending(PendingOperation {
            kind: PendingKind::Registration,
            checkpoint: original,
            replay: None,
        })
        .unwrap();
    let (receipt, verifier) = fixture.parent_receipt();
    let expected = store
        .confirm_completed_operation(receipt, &verifier)
        .unwrap();
    assert!(!store.progress(None).pending);
    assert_eq!(store.confirmed(), Some(expected));
    drop(store);
    let store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert!(!store.progress(None).pending);
    assert_eq!(store.confirmed(), Some(expected));
}

#[test]
fn failed_atomic_completion_preserves_old_receipt_and_pending_then_reopens_exact_work() {
    let mut fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    let (first_receipt, first_verifier) = fixture.parent_receipt();
    store
        .confirm_with_verifier(first_receipt, &first_verifier)
        .unwrap();
    let old = store.confirmed();
    // Replaying the already registered identity is sufficient to test atomic completion
    // without inventing a child execution result or a fake parent finality capability.
    store
        .publish_pending(PendingOperation {
            kind: PendingKind::Registration,
            checkpoint: fixture.parent.checkpoint().encode_canonical().unwrap(),
            replay: None,
        })
        .unwrap();
    let retained_bytes = store
        .directory
        .read("attachment.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let (receipt, verifier) = fixture.parent_receipt();
    std::fs::remove_file(path.join("attachment.nrt")).unwrap();
    std::fs::create_dir(path.join("attachment.nrt")).unwrap();
    assert!(
        store
            .confirm_completed_operation(receipt.clone(), &verifier)
            .is_err()
    );
    assert_eq!(store.confirmed(), old);
    assert!(store.progress(None).pending);
    assert!(store.revalidate().is_err());
    drop(store);
    std::fs::remove_dir(path.join("attachment.nrt")).unwrap();
    PrivateDirectory::open(&path)
        .unwrap()
        .write_atomic("attachment.nrt", &retained_bytes, PublishMode::CreateNew)
        .unwrap();
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert_eq!(store.confirmed(), old);
    assert!(store.progress(None).pending);
    store
        .confirm_completed_operation(receipt, &verifier)
        .unwrap();
    assert!(!store.progress(None).pending);
}

#[test]
fn cancelled_attachment_refuses_new_parent_work_but_preserves_pending_reconciliation() {
    use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
    use iroha_data_model::{
        sumeragi_finality::SumeragiFinalityProof, transaction::FeePaymentIntent,
    };
    use iroha_model_base::peer::PeerId;
    use std::cell::Cell;
    struct Offline(Cell<usize>);
    impl crate::verify::finality::FinalitySource for Offline {
        type Error = std::io::Error;
        fn finality_proof(
            &self,
            _: NonZeroU64,
        ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
            self.0.set(self.0.get() + 1);
            Err(std::io::Error::other("offline cancellation fixture"))
        }
        fn latest_attestation(
            &self,
            _: &PeerId,
            _: &[u8; 32],
        ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error>
        {
            self.0.set(self.0.get() + 1);
            Err(std::io::Error::other("offline cancellation fixture"))
        }
    }
    struct NoLocalRead;
    impl PrivateRootSource for NoLocalRead {
        fn anchor(&self, _: NonZeroU64) -> Result<Option<PrivateDataspaceAnchor>> {
            panic!("cancelled new relay must not read a child successor")
        }
    }
    let mut fixture = Fixture::new();
    fixture.parent_receipt();
    let dir = tempfile::tempdir().unwrap();
    let bootstrap = fixture.bootstrap(&dir.path().join("release"));
    let mut parent = ParentFinalityStore::open(&dir.path().join("parent"), &bootstrap).unwrap();
    let path = dir.path().join("attachment");
    let mut store = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    let signal = Arc::new(AtomicBool::new(true));
    store.bind_cancellation(Arc::clone(&signal)).unwrap();
    store.bind_cancellation(Arc::clone(&signal)).unwrap();
    assert!(
        store
            .bind_cancellation(Arc::new(AtomicBool::new(false)))
            .is_err()
    );
    let key = KeyPair::from_seed(vec![47; 32], Algorithm::Ed25519);
    let config = Config::load_table(
        "attachment-tests.toml",
        toml::toml! {
            chain = (fixture.parent.chain_id())
            network_id = (fixture.parent.network_id().to_string())
            torii_url = "https://parent.example/"
            [account]
            chain_discriminant = 753
            public_key = (key.public_key().to_string())
            private_key = (ExposedPrivateKey(key.private_key().clone()).to_string())
        },
    )
    .unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(vec![], None),
        max_total_fees: Default::default(),
        deadline: Instant::now() + std::time::Duration::from_secs(10),
    };
    let source = Offline(Cell::new(0));
    assert!(matches!(
        store.advance_parent(&config, &bootstrap, &mut parent, &source, &options, None),
        Err(AttachmentError::Cancelled)
    ));
    assert!(matches!(
        store.relay_once(
            &NoLocalRead,
            RelayParent {
                config: &config,
                bootstrap: &bootstrap,
                finality: &mut parent,
                source: &source,
                options: &options
            }
        ),
        Err(AttachmentError::Cancelled)
    ));
    assert_eq!(source.0.get(), 0);
    assert!(!store.progress(None).pending);
    assert!(!store.directory.path().join("transactions").exists());
    // Existing exact operation state still enters independent read-only reconciliation.
    store
        .publish_pending(PendingOperation {
            kind: PendingKind::Registration,
            checkpoint: fixture.parent.checkpoint().encode_canonical().unwrap(),
            replay: None,
        })
        .unwrap();
    let original = store
        .directory
        .read("attachment.nrt", MAX_RECORD_BYTES)
        .unwrap();
    assert!(!matches!(
        store.advance_parent(&config, &bootstrap, &mut parent, &source, &options, None),
        Ok(_) | Err(AttachmentError::Cancelled)
    ));
    assert!(source.0.get() >= 3);
    assert_eq!(
        store
            .directory
            .read("attachment.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert!(!store.directory.path().join("transactions").exists());
    drop(store);
    let reopened = AttachmentStore::open(&path, fixture.identity.clone()).unwrap();
    assert_eq!(
        reopened
            .directory
            .read("attachment.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert!(reopened.progress(None).pending);
    assert!(signal.load(Ordering::Acquire));
}
