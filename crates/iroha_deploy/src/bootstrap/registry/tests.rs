//! Registry context rejection and mandatory fresh quorum before any provider read.

use std::{cell::Cell, num::NonZeroU64};

use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::sumeragi_finality::{
    SumeragiFinalityProof, test_fixtures::NativeFinalityFixture,
};
use iroha_model_base::peer::PeerId;

use super::*;
use crate::bootstrap::{
    ReleaseBuildRegistry, ReleaseCheckpointStore,
    tests::{metadata, signed, trust},
};

struct Offline(Cell<usize>);
impl FinalitySource for Offline {
    type Error = std::io::Error;
    fn finality_proof(&self, _: NonZeroU64) -> std::io::Result<SumeragiFinalityProof> {
        Err(std::io::Error::other("offline"))
    }
    fn latest_attestation(
        &self,
        _: &PeerId,
        _: &[u8; 32],
    ) -> std::io::Result<crate::verify::finality::FinalityAttestation> {
        self.0.set(self.0.get() + 1);
        Err(std::io::Error::other("offline"))
    }
}

#[test]
fn registry_requires_explicit_public_context_current_release_and_fresh_quorum() {
    let native = NativeFinalityFixture::new();
    let checkpoint = native.checkpoint();
    let key = KeyPair::from_seed(vec![151; 32], Algorithm::Ed25519);
    let now = unix_ms().unwrap();
    let mut release = metadata(&checkpoint);
    release.issued_at_ms = now - 1_000;
    release.expires_at_ms = now + 60_000;
    release.build_registry = Some(ReleaseBuildRegistry {
        torii_roots: release.torii_roots.clone(),
    });
    let directory = tempfile::tempdir().unwrap();
    let release_store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = release_store
        .authenticate(
            &trust(&key, 1),
            &signed(release.clone(), &checkpoint, &key),
            now,
        )
        .unwrap();
    let mut store =
        ParentFinalityStore::open(&directory.path().join("finality"), &bootstrap).unwrap();
    let config = Config::load_table(
        "fixture.toml",
        toml::toml! {
            chain = (release.chain_id.clone())
            network_id = (release.network_id.to_string())
            torii_url = (release.torii_roots[0].as_str())
            [account]
            chain_discriminant = (release.account_chain_discriminant)
            public_key = (key.public_key().to_string())
            private_key = (ExposedPrivateKey(key.private_key().clone()).to_string())
        },
    )
    .unwrap();
    let provider = ProviderId([4; 32]);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        store
            .registry_deadline(&bootstrap, &config, provider, deadline, now)
            .unwrap(),
        deadline
    );
    let capped = store
        .registry_deadline(
            &bootstrap,
            &config,
            provider,
            Instant::now() + Duration::from_secs(600),
            now,
        )
        .unwrap();
    assert!(capped < Instant::now() + Duration::from_secs(61));
    for now in [release.issued_at_ms - 1, release.expires_at_ms] {
        assert!(
            store
                .registry_deadline(&bootstrap, &config, provider, deadline, now)
                .is_err()
        );
    }
    for mutation in 0..5 {
        let mut changed = config.clone();
        match mutation {
            0 => {
                changed.api_token = Some(iroha::secrecy::SecretString::new("private-child".into()))
            }
            1 => changed.torii_api_url = "http://127.0.0.1:8080/".parse().unwrap(),
            2 => changed.torii_api_url = "https://foreign.example/".parse().unwrap(),
            3 => changed.account_chain_discriminant += 1,
            _ => changed.chain = "other-parent".parse().unwrap(),
        }
        assert!(
            store
                .discover_build_provider(&bootstrap, &changed, provider, deadline)
                .is_err()
        );
    }
    assert!(
        store
            .discover_build_provider(&bootstrap, &config, ProviderId([0; 32]), deadline)
            .is_err()
    );
    assert!(
        store
            .discover_build_provider(&bootstrap, &config, provider, Instant::now())
            .is_err()
    );
    let source = Offline(Cell::new(0));
    let called = Cell::new(false);
    assert!(
        store
            .discover_build_provider_with(&bootstrap, &config, provider, deadline, &source, |_| {
                called.set(true);
                Err(BootstrapError::Invalid("unexpected provider read"))
            })
            .is_err()
    );
    assert!(source.0.get() >= 3);
    assert!(!called.get());
    release.serial += 1;
    release.build_registry = None;
    let without_registry = release_store
        .authenticate(&trust(&key, 1), &signed(release, &checkpoint, &key), now)
        .unwrap();
    assert!(
        store
            .discover_build_provider(&without_registry, &config, provider, deadline)
            .is_err()
    );
}
