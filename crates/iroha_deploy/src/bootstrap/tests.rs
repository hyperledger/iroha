//! Release authority, replay and native-checkpoint binding regressions.
//!
//! Native fixtures use genuine BLS certificates over synthetic execution outputs; these tests
//! authenticate bootstrap material and do not qualify a running parent or private dataspace.
use super::*;
use iroha_crypto::KeyPair;
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

pub(super) fn trust(key: &KeyPair, floor: u64) -> ReleaseTrust {
    ReleaseTrust::new("fixture".into(), key.public_key().clone(), floor).unwrap()
}

pub(super) fn metadata(checkpoint: &SumeragiFinalityCheckpoint) -> NetworkRelease {
    NetworkRelease {
        network_name: "fixture".into(),
        serial: 5,
        generation: 1,
        network_id: checkpoint.network_id(),
        chain_id: checkpoint.chain_id().into(),
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
        torii_roots: vec!["https://torii.example/".into()],
        account_chain_discriminant: 753,
        native_world_schema: Hash::new(b"independently qualified fixture World schema"),
        peers: checkpoint
            .tip()
            .committee
            .iter()
            .map(|validator| crate::bootstrap::ReleasePeer {
                node_id: iroha_model_base::peer::PeerId::new(validator.public_key.clone()),
                torii_root: "https://torii.example/".into(),
            })
            .collect(),
        faucet: None,
        build_registry: None,
        checkpoint_hash: Hash::new(checkpoint.encode_canonical().unwrap()),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_hash: checkpoint.block_hash().into(),
    }
}

pub(super) fn signed(
    release: NetworkRelease,
    checkpoint: &SumeragiFinalityCheckpoint,
    key: &KeyPair,
) -> Vec<u8> {
    SignedNetworkCheckpoint::sign(release, checkpoint, key.private_key())
        .unwrap()
        .encode_canonical()
        .unwrap()
}

#[test]
fn signed_native_checkpoint_roundtrips_and_resumes_after_exclusive_reopen() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(81);
    let trust = trust(&key, 5);
    let release = metadata(&checkpoint);
    let bytes = signed(release.clone(), &checkpoint, &key);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release");
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(matches!(
        ReleaseCheckpointStore::open(&path),
        Err(BootstrapError::Busy)
    ));
    let result = store.authenticate(&trust, &bytes, 2_000).unwrap();
    assert_eq!(result.release(), &release);
    assert!(!result.is_network_reset());
    assert_eq!(result.into_verifier().checkpoint(), &checkpoint);
    drop(store);
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(
        !store
            .authenticate(&trust, &bytes, 2_001)
            .unwrap()
            .is_network_reset()
    );
    assert!(store.authenticate(&trust, &bytes, 2_000).is_err());
    assert!(store.authenticate(&trust, &bytes, 10_000).is_err());
    assert!(store.authenticate(&trust, &bytes, 999).is_err());
}

#[test]
fn retained_release_reauthenticates_offline_without_repairing_expiry_or_invalid_custody() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let authority = key(93);
    let selected = trust(&authority, 1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release");
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(
        store
            .authenticate_retained(&selected, 2_000)
            .unwrap()
            .is_none()
    );
    let release = metadata(&checkpoint);
    store
        .authenticate(
            &selected,
            &signed(release.clone(), &checkpoint, &authority),
            2_000,
        )
        .unwrap();
    let loaded = store
        .authenticate_retained(&selected, 3_000)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.release(), &release);
    assert_eq!(loaded.into_verifier().checkpoint(), &checkpoint);
    assert!(store.authenticate_retained(&selected, 2_999).is_err());
    assert!(
        store
            .authenticate_retained(&trust(&key(94), 1), 3_001)
            .is_err()
    );
    assert!(
        store
            .authenticate_retained(&trust(&authority, release.serial + 1), 3_001)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authenticate_retained(&selected, release.expires_at_ms)
            .unwrap()
            .is_none()
    );
    drop(store);
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(store.authenticate_retained(&selected, 2_999).is_err());
    std::fs::remove_file(path.join("accepted.nrt")).unwrap();
    assert!(store.authenticate_retained(&selected, 3_001).is_err());
}

#[test]
fn response_cannot_choose_authority_network_floor_or_checkpoint() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(82);
    let release = metadata(&checkpoint);
    let bytes = signed(release.clone(), &checkpoint, &key);
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    assert!(
        store
            .authenticate(&trust(&super::tests::key(83), 1), &bytes, 2_000)
            .is_err()
    );
    assert!(store.authenticate(&trust(&key, 6), &bytes, 2_000).is_err());
    let wrong_name = ReleaseTrust::new("other".into(), key.public_key().clone(), 1).unwrap();
    assert!(store.authenticate(&wrong_name, &bytes, 2_000).is_err());
    let mut changed: SignedNetworkCheckpoint =
        decode(&bytes, MAX_RELEASE_CHECKPOINT_BYTES).unwrap();
    changed.release.torii_roots[0] = "https://attacker.example/".into();
    assert!(
        store
            .authenticate(&trust(&key, 1), &changed.encode_canonical().unwrap(), 2_000)
            .is_err()
    );
    changed = decode(&bytes, MAX_RELEASE_CHECKPOINT_BYTES).unwrap();
    changed.checkpoint[0] ^= 1;
    assert!(
        store
            .authenticate(&trust(&key, 1), &changed.encode_canonical().unwrap(), 2_000)
            .is_err()
    );
    assert!(
        store
            .directory
            .entries(10)
            .unwrap()
            .iter()
            .all(|name| name == "release.lock" || name == "accepted.nrt")
    );
    assert!(store.read_watermark().unwrap().accepted.is_none());
    let mut appended = bytes.clone();
    appended.push(0);
    assert!(
        store
            .authenticate(&trust(&key, 1), &appended, 2_000)
            .is_err()
    );
    assert!(decode::<SignedNetworkCheckpoint>(&[], 10).is_err());
    assert!(decode::<SignedNetworkCheckpoint>(&bytes, bytes.len() - 1).is_err());
}

#[test]
fn private_root_cannot_be_installed_as_public_parent_even_with_release_signature() {
    let parent = NativeFinalityFixture::new();
    let mut child = NativeFinalityFixture::start_with_scope(
        "private-child-is-not-parent",
        iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(u64::MAX),
        },
    );
    child.certify(child.block_with_submitted_work(child.next_header()));
    let checkpoint = child.checkpoint();
    let authority = key(90);
    assert!(
        SignedNetworkCheckpoint::sign(metadata(&checkpoint), &checkpoint, authority.private_key())
            .is_err()
    );
    let release = metadata(&checkpoint);
    let artifact = SignedNetworkCheckpoint {
        signature: Signature::new(
            authority.private_key(),
            &release_preimage(&release).unwrap(),
        ),
        release,
        checkpoint: checkpoint.encode_canonical().unwrap(),
    };
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    assert!(
        store
            .authenticate(
                &trust(&authority, 1),
                &artifact.encode_canonical().unwrap(),
                2_000
            )
            .is_err()
    );
}

#[test]
fn signed_metadata_still_requires_exact_native_identity_height_and_quorum() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(84);
    let base = metadata(&checkpoint);
    for mutation in 0..5 {
        let mut release = base.clone();
        match mutation {
            0 => release.chain_id = "foreign".into(),
            1 => {
                release.network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign")),
                )
            }
            2 => release.checkpoint_height += 1,
            3 => release.checkpoint_block_hash = Hash::new(b"other block"),
            4 => release.checkpoint_hash = Hash::new(b"other frame"),
            _ => unreachable!(),
        }
        assert!(SignedNetworkCheckpoint::sign(release, &checkpoint, key.private_key()).is_err());
    }
    // Signing a corrupt checkpoint digest cannot turn the payload into native finality.
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let mut release = base;
    let bad = vec![0; 32];
    release.checkpoint_hash = Hash::new(&bad);
    let artifact = SignedNetworkCheckpoint {
        signature: Signature::new(key.private_key(), &release_preimage(&release).unwrap()),
        release,
        checkpoint: bad,
    };
    assert!(
        store
            .authenticate(
                &trust(&key, 1),
                &artifact.encode_canonical().unwrap(),
                2_000
            )
            .is_err()
    );
}

#[test]
fn monotonic_release_rejects_rollback_equivocation_and_allows_installation_floor_upgrade() {
    let mut fixture = NativeFinalityFixture::new();
    let old_checkpoint = fixture.checkpoint();
    let key = key(85);
    let original = metadata(&old_checkpoint);
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    store
        .authenticate(
            &trust(&key, 5),
            &signed(original.clone(), &old_checkpoint, &key),
            2_000,
        )
        .unwrap();
    for mutation in 0..4 {
        let mut release = original.clone();
        match mutation {
            0 => release.serial -= 1,
            1 => release.expires_at_ms += 1,
            2 => {
                release.serial += 1;
                release.issued_at_ms -= 1;
            }
            3 => {
                release.serial += 1;
                release.generation += 1;
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .authenticate(
                    &trust(&key, 1),
                    &signed(release, &old_checkpoint, &key),
                    2_001
                )
                .is_err()
        );
    }
    fixture.certify(fixture.block_with_submitted_work(fixture.next_header()));
    let newer = fixture.checkpoint();
    let mut next = metadata(&newer);
    next.serial = 6;
    let result = store
        .authenticate(&trust(&key, 6), &signed(next.clone(), &newer, &key), 2_001)
        .unwrap();
    assert_eq!(result.into_verifier().checkpoint().height(), 3);
    let mut regressed = original;
    regressed.serial = 7;
    assert!(
        store
            .authenticate(
                &trust(&key, 6),
                &signed(regressed, &old_checkpoint, &key),
                2_002
            )
            .is_err()
    );
    let mut changed = next.clone();
    changed.checkpoint_block_hash = Hash::new(b"equivocation");
    changed.serial += 1;
    assert!(validate_successor(&next, &changed).is_err());
    changed = next.clone();
    changed.checkpoint_hash = Hash::new(b"different restart context");
    changed.serial += 1;
    assert!(validate_successor(&next, &changed).is_err());
}

#[test]
fn authenticated_reset_is_explicit_and_an_expired_prior_release_still_prevents_rollback() {
    let fixture = NativeFinalityFixture::new();
    let old_checkpoint = fixture.checkpoint();
    let key = key(86);
    let original = metadata(&old_checkpoint);
    // A different mode changes the signed genesis, producing a genuine independent network.
    let mut reset = NativeFinalityFixture::start_with_mode(
        "reset-fixture",
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
    );
    reset.certify(reset.block_with_submitted_work(reset.next_header()));
    let new_checkpoint = reset.checkpoint();
    assert_ne!(old_checkpoint.network_id(), new_checkpoint.network_id());
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    store
        .authenticate(
            &trust(&key, 1),
            &signed(original.clone(), &old_checkpoint, &key),
            2_000,
        )
        .unwrap();
    let mut next = metadata(&new_checkpoint);
    next.serial = 6;
    next.issued_at_ms = 11_000;
    next.expires_at_ms = 20_000;
    assert!(
        store
            .authenticate(
                &trust(&key, 1),
                &signed(next.clone(), &new_checkpoint, &key),
                12_000
            )
            .is_err()
    );
    next.generation = 2;
    let result = store
        .authenticate(
            &trust(&key, 1),
            &signed(next.clone(), &new_checkpoint, &key),
            12_000,
        )
        .unwrap();
    assert!(result.is_network_reset());
    assert_eq!(result.release().network_id, new_checkpoint.network_id());
    let mut resurrected = original;
    resurrected.serial = 7;
    resurrected.issued_at_ms = 12_000;
    resurrected.expires_at_ms = 20_000;
    assert!(
        store
            .authenticate(
                &trust(&key, 1),
                &signed(resurrected, &old_checkpoint, &key),
                12_001
            )
            .is_err()
    );
    assert!(
        store
            .authenticate(
                &trust(&key, 1),
                &signed(next, &new_checkpoint, &key),
                12_001
            )
            .is_ok()
    );
}

#[test]
fn release_policy_rejects_unbounded_or_ambiguous_metadata_and_noncanonical_custody() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(87);
    let base = metadata(&checkpoint);
    for url in [
        "http://torii.example/",
        "https://user:secret@torii.example/",
        "https://torii.example/?secret=yes",
        "https://torii.example/#fragment",
        "https://torii.example/path",
        "https://TORII.example/",
    ] {
        let mut release = base.clone();
        release.torii_roots = vec![url.into()];
        assert!(validate_release(&release).is_err(), "{url}");
    }
    for mutation in 0..7 {
        let mut release = base.clone();
        match mutation {
            0 => release.serial = 0,
            1 => release.generation = 0,
            2 => release.expires_at_ms = release.issued_at_ms,
            3 => release.expires_at_ms = release.issued_at_ms + MAX_RELEASE_VALIDITY_MS + 1,
            4 => release.torii_roots.push(release.torii_roots[0].clone()),
            5 => release.checkpoint_height = 1,
            6 => release.network_name = "../escape".into(),
            _ => unreachable!(),
        }
        assert!(validate_release(&release).is_err());
    }
    assert!(ReleaseTrust::new("fixture".into(), key.public_key().clone(), 0).is_err());
    assert!(ReleaseTrust::new("Fixture".into(), key.public_key().clone(), 1).is_err());
    assert!(
        ReleaseTrust::new(
            "fixture".into(),
            KeyPair::from_seed(vec![5; 32], Algorithm::BlsNormal)
                .public_key()
                .clone(),
            1
        )
        .is_err()
    );
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    store
        .directory
        .write_atomic("accepted.nrt", b"partial", PublishMode::Replace)
        .unwrap();
    assert!(
        store
            .authenticate(&trust(&key, 1), &signed(base, &checkpoint, &key), 2_000)
            .is_err()
    );
    assert_eq!(
        store.directory.read("accepted.nrt", 20).unwrap().as_slice(),
        b"partial"
    );
}

#[test]
fn authenticated_release_only_authorizes_its_exact_http_endpoints() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(88);
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = store
        .authenticate(
            &trust(&key, 1),
            &signed(metadata(&checkpoint), &checkpoint, &key),
            2_000,
        )
        .unwrap();
    let client = |endpoint: &str| {
        let table = toml::toml! {
            chain = (checkpoint.chain_id())
            network_id = (checkpoint.network_id().to_string())
            torii_url = endpoint
            [account]
            chain_discriminant = 753
            public_key = (key.public_key().to_string())
            private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
        };
        iroha::client::Client::builder(
            iroha::config::Config::load_table("bootstrap-tests.toml", table).unwrap(),
        )
        .build()
        .unwrap()
    };
    let peer =
        iroha_model_base::peer::PeerId::new(checkpoint.tip().committee[0].public_key.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    bootstrap
        .http_source(
            vec![client("https://torii.example/")],
            vec![(peer.clone(), client("https://torii.example/"))],
            deadline,
        )
        .unwrap();
    for endpoint in [
        "https://torii.example/other/",
        "https://foreign.example/",
        "http://127.0.0.1:18080/",
    ] {
        assert!(
            bootstrap
                .http_source(
                    vec![client(endpoint)],
                    vec![(peer.clone(), client("https://torii.example/"))],
                    deadline
                )
                .is_err()
        );
        assert!(
            bootstrap
                .http_source(
                    vec![client("https://torii.example/")],
                    vec![(peer.clone(), client(endpoint))],
                    deadline
                )
                .is_err()
        );
    }
}

struct RuntimeSource {
    proof: iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
}
impl crate::verify::finality::FinalitySource for RuntimeSource {
    type Error = std::io::Error;
    fn finality_proof(
        &self,
        height: std::num::NonZeroU64,
    ) -> std::io::Result<iroha_data_model::sumeragi_finality::SumeragiFinalityProof> {
        if height.get() == self.proof.height() {
            Ok(self.proof.clone())
        } else {
            Err(std::io::Error::other("fixture height unavailable"))
        }
    }
    fn latest_attestation(
        &self,
        _: &iroha_model_base::peer::PeerId,
        _: &[u8; 32],
    ) -> std::io::Result<crate::verify::finality::FinalityAttestation> {
        Err(std::io::Error::other("fixture peer offline"))
    }
}

#[test]
fn runtime_checkpoint_persists_verified_progress_without_release_rewind_or_readiness_reuse() {
    let mut native = NativeFinalityFixture::new();
    let checkpoint = native.checkpoint();
    let key = key(89);
    let directory = tempfile::tempdir().unwrap();
    let release_store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = release_store
        .authenticate(
            &trust(&key, 1),
            &signed(metadata(&checkpoint), &checkpoint, &key),
            2_000,
        )
        .unwrap();
    let runtime_path = directory.path().join("runtime");
    let mut runtime = ParentFinalityStore::open(&runtime_path, &bootstrap).unwrap();
    assert!(ParentFinalityStore::open(&runtime_path, &bootstrap).is_err());
    let source = RuntimeSource {
        proof: native.certify(native.block_with_submitted_work(native.next_header())),
    };
    assert_eq!(
        runtime
            .catch_up(&source, std::num::NonZeroU64::new(3).unwrap())
            .unwrap(),
        3
    );
    let before = runtime.verifier().checkpoint().clone();
    let bytes = std::fs::read(runtime_path.join("verified.nrt")).unwrap();
    assert!(runtime.observe(&source, &[7; 32]).is_err());
    assert_eq!(runtime.verifier().checkpoint(), &before);
    assert_eq!(
        std::fs::read(runtime_path.join("verified.nrt")).unwrap(),
        bytes
    );
    assert!(
        runtime
            .catch_up(&source, std::num::NonZeroU64::new(4).unwrap())
            .is_err()
    );
    assert_eq!(runtime.verifier().checkpoint(), &before);
    drop(runtime);
    let runtime = ParentFinalityStore::open(&runtime_path, &bootstrap).unwrap();
    assert_eq!(
        runtime.verifier().checkpoint(),
        &before,
        "older release never rewinds runtime"
    );
    assert_eq!(runtime.verifier().verified_tip().unwrap().height(), 3);
    drop(runtime);
    // A newly issued same-height checkpoint with the same certified decision also reopens.
    let mut next = metadata(&native.checkpoint());
    next.serial += 1;
    let next = release_store
        .authenticate(
            &trust(&key, 1),
            &signed(next, &native.checkpoint(), &key),
            2_001,
        )
        .unwrap();
    assert_eq!(
        ParentFinalityStore::open(&runtime_path, &next)
            .unwrap()
            .verifier()
            .checkpoint()
            .height(),
        3
    );
}

#[test]
fn runtime_checkpoint_rejects_reset_and_incomplete_or_replaced_custody() {
    let native = NativeFinalityFixture::new();
    let checkpoint = native.checkpoint();
    let key = key(90);
    let directory = tempfile::tempdir().unwrap();
    let release_store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = release_store
        .authenticate(
            &trust(&key, 1),
            &signed(metadata(&checkpoint), &checkpoint, &key),
            2_000,
        )
        .unwrap();
    for missing in ["lock", "verified.nrt"] {
        let path = directory.path().join(missing.replace('.', "-"));
        drop(ParentFinalityStore::open(&path, &bootstrap).unwrap());
        std::fs::remove_file(path.join(missing)).unwrap();
        assert!(ParentFinalityStore::open(&path, &bootstrap).is_err());
        assert!(!path.join(missing).exists());
    }
    let path = directory.path().join("corrupt");
    drop(ParentFinalityStore::open(&path, &bootstrap).unwrap());
    std::fs::write(path.join("verified.nrt"), b"partial").unwrap();
    assert!(ParentFinalityStore::open(&path, &bootstrap).is_err());
    assert_eq!(
        std::fs::read(path.join("verified.nrt")).unwrap(),
        b"partial"
    );
    let path = directory.path().join("changed");
    let mut runtime = ParentFinalityStore::open(&path, &bootstrap).unwrap();
    #[cfg(unix)]
    {
        std::fs::rename(path.join("lock"), path.join("original-lock")).unwrap();
        let private = PrivateDirectory::open(&path).unwrap();
        private.create_lock("lock").unwrap();
        let before = runtime.verifier().checkpoint().clone();
        let source = RuntimeSource {
            proof: native.latest().clone(),
        };
        assert!(
            runtime
                .catch_up(&source, std::num::NonZeroU64::new(2).unwrap())
                .is_err()
        );
        assert!(runtime.observe(&source, &[7; 32]).is_err());
        assert_eq!(runtime.verifier().checkpoint(), &before);
    }
    #[cfg(windows)]
    {
        // The native Windows lock handle forbids replacement while owned.
        assert!(std::fs::rename(path.join("lock"), path.join("original-lock")).is_err());
        assert!(ParentFinalityStore::open(&path, &bootstrap).is_err());
    }
    drop(runtime);
    let path = directory.path().join("old-network");
    drop(ParentFinalityStore::open(&path, &bootstrap).unwrap());
    let mut reset = NativeFinalityFixture::start_with_mode(
        "new-runtime-generation",
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
    );
    reset.certify(reset.block_with_submitted_work(reset.next_header()));
    let checkpoint = reset.checkpoint();
    let mut release = metadata(&checkpoint);
    release.serial += 1;
    release.generation += 1;
    let reset = release_store
        .authenticate(&trust(&key, 1), &signed(release, &checkpoint, &key), 2_001)
        .unwrap();
    assert!(reset.is_network_reset());
    assert!(ParentFinalityStore::open(&path, &reset).is_err());
    ParentFinalityStore::open(&directory.path().join("new-network"), &reset).unwrap();
}

#[test]
fn uncertain_checkpoint_publication_requires_reopen_and_never_rewinds_on_retry() {
    let mut native = NativeFinalityFixture::new();
    let checkpoint = native.checkpoint();
    let key = key(91);
    let directory = tempfile::tempdir().unwrap();
    let releases = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let bootstrap = releases
        .authenticate(
            &trust(&key, 1),
            &signed(metadata(&checkpoint), &checkpoint, &key),
            2_000,
        )
        .unwrap();
    let path = directory.path().join("runtime");
    let mut runtime = ParentFinalityStore::open(&path, &bootstrap).unwrap();
    let source = RuntimeSource {
        proof: native.certify(native.block_with_submitted_work(native.next_header())),
    };
    let before = runtime.verifier().checkpoint().clone();
    std::fs::rename(path.join("verified.nrt"), path.join("retained.nrt")).unwrap();
    std::fs::create_dir(path.join("verified.nrt")).unwrap();
    assert!(
        runtime
            .catch_up(&source, std::num::NonZeroU64::new(3).unwrap())
            .is_err()
    );
    assert_eq!(runtime.verifier().checkpoint(), &before);
    std::fs::remove_dir(path.join("verified.nrt")).unwrap();
    std::fs::rename(path.join("retained.nrt"), path.join("verified.nrt")).unwrap();
    assert!(
        runtime
            .catch_up(&source, std::num::NonZeroU64::new(2).unwrap())
            .is_err()
    );
    assert!(runtime.observe(&source, &[7; 32]).is_err());
    drop(runtime);
    let mut reopened = ParentFinalityStore::open(&path, &bootstrap).unwrap();
    assert_eq!(reopened.verifier().checkpoint(), &before);
    assert_eq!(
        reopened
            .catch_up(&source, std::num::NonZeroU64::new(3).unwrap())
            .unwrap(),
        3
    );
}

#[test]
fn release_watermark_and_exact_lock_cannot_be_recreated_after_loss() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(93);
    let bytes = signed(metadata(&checkpoint), &checkpoint, &key);
    let trust = trust(&key, 1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release");
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    store.authenticate(&trust, &bytes, 2_000).unwrap();
    std::fs::remove_file(path.join("accepted.nrt")).unwrap();
    assert!(store.authenticate(&trust, &bytes, 2_001).is_err());
    drop(store);
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(store.authenticate(&trust, &bytes, 2_001).is_err());
    drop(store);
    std::fs::remove_file(path.join("release.lock")).unwrap();
    assert!(ReleaseCheckpointStore::open(&path).is_err());

    #[cfg(unix)]
    {
        let path = directory.path().join("replaced");
        let store = ReleaseCheckpointStore::open(&path).unwrap();
        store.authenticate(&trust, &bytes, 2_000).unwrap();
        std::fs::rename(path.join("release.lock"), path.join("old.lock")).unwrap();
        drop(store.directory.create_lock("release.lock").unwrap());
        assert!(store.authenticate(&trust, &bytes, 2_001).is_err());
    }
}

#[test]
fn release_publication_failure_requires_reopening_exact_watermark() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(94);
    let bytes = signed(metadata(&checkpoint), &checkpoint, &key);
    let trust = trust(&key, 1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release");
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    store.authenticate(&trust, &bytes, 2_000).unwrap();
    let retained = store.read_watermark().unwrap().accepted.unwrap();
    std::fs::rename(path.join("accepted.nrt"), path.join("retained.nrt")).unwrap();
    std::fs::create_dir(path.join("accepted.nrt")).unwrap();
    assert!(
        store
            .publish(&mut store.state.lock().unwrap(), retained)
            .is_err()
    );
    std::fs::remove_dir(path.join("accepted.nrt")).unwrap();
    std::fs::rename(path.join("retained.nrt"), path.join("accepted.nrt")).unwrap();
    assert!(store.authenticate(&trust, &bytes, 2_001).is_err());
    assert!(store.authenticate_retained(&trust, 2_001).is_err());
    drop(store);
    ReleaseCheckpointStore::open(&path)
        .unwrap()
        .authenticate(&trust, &bytes, 2_001)
        .unwrap();
}

#[test]
fn concurrent_release_authentication_cannot_lose_the_higher_watermark() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(95);
    let trust = trust(&key, 1);
    let directory = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&directory.path().join("release")).unwrap();
    let mut six = metadata(&checkpoint);
    six.serial = 6;
    let six = signed(six, &checkpoint, &key);
    let mut seven = metadata(&checkpoint);
    seven.serial = 7;
    let seven = signed(seven, &checkpoint, &key);
    std::thread::scope(|scope| {
        let low = scope.spawn(|| store.authenticate(&trust, &six, 2_000));
        let high = scope.spawn(|| store.authenticate(&trust, &seven, 2_000));
        let _ = low.join().unwrap();
        high.join().unwrap().unwrap();
    });
    let retained = store.read_watermark().unwrap().accepted.unwrap();
    assert_eq!(retained.artifact.release.serial, 7);
    assert!(store.authenticate(&trust, &six, 2_001).is_err());
}

#[test]
fn failed_first_release_can_resume_without_resetting_an_accepted_watermark() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = key(96);
    let bytes = signed(metadata(&checkpoint), &checkpoint, &key);
    let trust = trust(&key, 1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release");
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    assert!(
        store
            .authenticate(&trust, b"invalid response", 2_000)
            .is_err()
    );
    assert!(store.read_watermark().unwrap().accepted.is_none());
    drop(store);
    let store = ReleaseCheckpointStore::open(&path).unwrap();
    store.authenticate(&trust, &bytes, 2_001).unwrap();
    assert_eq!(
        store
            .read_watermark()
            .unwrap()
            .accepted
            .unwrap()
            .artifact
            .release
            .serial,
        5
    );
}
