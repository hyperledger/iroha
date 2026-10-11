//! Compact relay selection, local credential boundaries and independent parent failure.

use std::{cell::RefCell, time::Duration};

use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::{sumeragi_finality::SumeragiFinalityProof, transaction::FeePaymentIntent};
use iroha_model_base::peer::PeerId;

use super::*;
use crate::attachment::tests::Fixture;

struct Child {
    value: Option<PrivateDataspaceAnchor>,
    requested: RefCell<Vec<u64>>,
}

impl PrivateRootSource for Child {
    fn anchor(&self, height: NonZeroU64) -> Result<Option<PrivateDataspaceAnchor>> {
        self.requested.borrow_mut().push(height.get());
        Ok(self.value.clone())
    }
}

struct Offline;
impl FinalitySource for Offline {
    type Error = std::io::Error;

    fn finality_proof(
        &self,
        _: NonZeroU64,
    ) -> std::result::Result<SumeragiFinalityProof, Self::Error> {
        Err(std::io::Error::other("offline fixture"))
    }

    fn latest_attestation(
        &self,
        _: &PeerId,
        _: &[u8; 32],
    ) -> std::result::Result<crate::verify::finality::FinalityAttestation, Self::Error> {
        Err(std::io::Error::other("offline fixture"))
    }
}

fn config(fixture: &Fixture, private: bool) -> Config {
    let key = KeyPair::from_seed(vec![47; 32], Algorithm::Ed25519);
    let mut config = Config::load_table(
        "relay-test.toml",
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
    if private {
        config.chain = fixture.identity.registration.child_chain_id.clone();
        config.network_id = fixture.child.network_id();
        config.torii_api_url = "http://127.0.0.1:9/".parse().unwrap();
        config.api_token = Some(iroha::secrecy::SecretString::new(
            "owner-only-fixture".into(),
        ));
    }
    config
}

#[test]
fn next_certificate_is_contiguous_verified_and_never_a_parent_receipt() {
    let mut fixture = Fixture::new();
    let temporary = tempfile::tempdir().unwrap();
    let mut store = AttachmentStore::open(
        &temporary.path().join("attachment"),
        fixture.identity.clone(),
    )
    .unwrap();
    let mut child = Child {
        value: Some(fixture.child_anchor()),
        requested: RefCell::default(),
    };
    // Registration and retained recovery do not need a new child response.
    assert!(store.next_child_anchor(&child).unwrap().is_none());
    assert!(child.requested.borrow().is_empty());
    let (receipt, verifier) = fixture.parent_receipt();
    store.confirm_with_verifier(receipt, &verifier).unwrap();
    let confirmed = store.confirmed();
    let (_, cursor) = store.next_child_anchor(&child).unwrap().unwrap();
    assert_eq!(cursor.height, 2);
    assert_eq!(*child.requested.borrow(), vec![2]);
    assert_eq!(store.confirmed(), confirmed);

    child.value = Some(fixture.child_anchor()); // Genuine third decision, with a missing second.
    assert!(store.next_child_anchor(&child).is_err());
    child.value.as_mut().unwrap().child_network_id = fixture.parent.network_id();
    assert!(store.next_child_anchor(&child).is_err());
    child.value = None;
    assert!(store.next_child_anchor(&child).unwrap().is_none());
    assert_eq!(store.confirmed(), confirmed);
    assert!(!store.directory.path().join("transactions").exists());
}

#[test]
fn local_source_rejects_credential_or_identity_escape_before_io() {
    let fixture = Fixture::new();
    let valid = config(&fixture, true);
    let deadline = Instant::now() + Duration::from_secs(10);
    let source = LocalPrivateRootSource::new(valid.clone(), &fixture.identity, deadline).unwrap();
    assert!(source.anchor(NonZeroU64::new(1).unwrap()).is_err());
    for endpoint in [
        "https://parent.example/",
        "http://localhost:9/",
        "http://192.0.2.1/",
        "http://user@127.0.0.1/",
    ] {
        let mut changed = valid.clone();
        changed.torii_api_url = endpoint.parse().unwrap();
        assert!(LocalPrivateRootSource::new(changed, &fixture.identity, deadline).is_err());
    }
    let mut changed = valid.clone();
    changed.api_token = None;
    assert!(LocalPrivateRootSource::new(changed, &fixture.identity, deadline).is_err());
    let mut changed = valid.clone();
    changed.network_id = fixture.parent.network_id();
    assert!(LocalPrivateRootSource::new(changed, &fixture.identity, deadline).is_err());
    let mut changed = valid.clone();
    changed.account = AccountId::new(KeyPair::random().public_key().clone());
    assert!(LocalPrivateRootSource::new(changed, &fixture.identity, deadline).is_err());
    assert!(LocalPrivateRootSource::new(valid, &fixture.identity, Instant::now()).is_err());
    assert!(require_time(deadline).is_ok());
    assert!(require_time(Instant::now()).is_err());
    let expired = LocalPrivateRootSource {
        deadline: Instant::now(),
        ..source
    };
    assert!(expired.anchor(NonZeroU64::new(2).unwrap()).is_err());
}

#[test]
fn a_relay_turn_cannot_prepare_or_claim_anchoring_without_fresh_parent_quorum() {
    let mut fixture = Fixture::new();
    fixture.parent_receipt();
    let temporary = tempfile::tempdir().unwrap();
    let bootstrap = fixture.bootstrap(&temporary.path().join("release"));
    let mut finality =
        ParentFinalityStore::open(&temporary.path().join("parent"), &bootstrap).unwrap();
    let mut store = AttachmentStore::open(
        &temporary.path().join("attachment"),
        fixture.identity.clone(),
    )
    .unwrap();
    let child = Child {
        value: None,
        requested: RefCell::default(),
    };
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(vec![], None),
        max_total_fees: Default::default(),
        deadline: Instant::now() + Duration::from_secs(10),
    };
    assert!(
        store
            .relay_once(
                &child,
                RelayParent {
                    config: &config(&fixture, false),
                    bootstrap: &bootstrap,
                    finality: &mut finality,
                    source: &Offline,
                    options: &options,
                }
            )
            .is_err()
    );
    assert!(child.requested.borrow().is_empty());
    assert!(store.confirmed().is_none());
    assert!(store.record.pending.is_none());
    assert!(!store.directory.path().join("transactions").exists());
}
