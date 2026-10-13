//! Thin native command grammar and retained signing/proof input custody tests.

use super::*;
use clap::Parser as _;
use iroha_crypto::Algorithm;
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

#[test]
fn operator_command_requires_pins_complete_allowance_and_fresh_output_choice() {
    let fixture = NativeFinalityFixture::new();
    let public = KeyPair::from_seed(vec![113; 32], Algorithm::Ed25519)
        .public_key()
        .to_string();
    let peer = fixture.latest().committee[0].public_key.to_string();
    let args = vec![
        "kagami".to_string(),
        "advanced".into(),
        "network-bootstrap".into(),
        "prepare".into(),
        "--genesis-manifest".into(),
        "genesis.json".into(),
        "--expected-genesis-manifest-sha256".into(),
        hex::encode(iroha_crypto::sha256(
            b"independently authenticated fixture manifest",
        )),
        "--signed-genesis".into(),
        "genesis.nrt".into(),
        "--genesis-public-key".into(),
        public.clone(),
        "--expected-network-id".into(),
        fixture.network_id().to_string(),
        "--proof-json".into(),
        "h1.json".into(),
        "--proof-json".into(),
        "h2.json".into(),
        "--network-name".into(),
        "fixture".into(),
        "--serial".into(),
        "7".into(),
        "--generation".into(),
        "2".into(),
        "--issued-at-ms".into(),
        "1000".into(),
        "--expires-at-ms".into(),
        "10000".into(),
        "--torii-root".into(),
        "https://torii.example/".into(),
        "--peer".into(),
        format!("{peer}=https://torii.example/"),
        "--checkpoint-url".into(),
        "https://releases.example/checkpoint.nrt".into(),
        "--release-public-key".into(),
        public,
        "--release-key-file".into(),
        "/runtime/release.key".into(),
        "--output-dir".into(),
        "/runtime/fresh-publication".into(),
    ];
    assert!(crate::Cli::try_parse_from(args.clone()).is_ok());
    let mut unpinned_manifest = args.clone();
    let pin_index = unpinned_manifest
        .iter()
        .position(|value| value == "--expected-genesis-manifest-sha256")
        .unwrap();
    unpinned_manifest.drain(pin_index..pin_index + 2);
    assert!(crate::Cli::try_parse_from(unpinned_manifest).is_err());
    let mut ambiguous_pin = args.clone();
    ambiguous_pin[pin_index + 1] = "AB".repeat(32);
    assert!(crate::Cli::try_parse_from(ambiguous_pin).is_err());
    let mut missing = args.clone();
    let index = missing
        .iter()
        .position(|value| value == "--genesis-public-key")
        .unwrap();
    missing.drain(index..index + 2);
    assert!(crate::Cli::try_parse_from(missing).is_err());
    let mut partial = args;
    partial.extend(["--faucet-root".into(), "https://torii.example/".into()]);
    assert!(crate::Cli::try_parse_from(partial).is_err());
}

#[test]
fn native_proof_input_preserves_typed_original_and_refuses_malformed_json() {
    let fixture = NativeFinalityFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("proof.json");
    std::fs::write(&path, json::to_json(fixture.latest()).unwrap()).unwrap();
    let read = read_proofs(std::slice::from_ref(&path)).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].block_wire, fixture.latest().block_wire);
    assert_eq!(read[0].committee, fixture.latest().committee);
    std::fs::write(&path, b"{}").unwrap();
    assert!(read_proofs(&[path]).is_err());
}

#[test]
fn proof_input_refuses_count_depth_raw_and_cumulative_decode_expansion() {
    let too_many = vec![PathBuf::from("/not-opened"); MAX_ADVANCE_PROOFS + 2];
    assert!(
        read_proofs(&too_many)
            .unwrap_err()
            .to_string()
            .contains("count bound")
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("proof.json");
    let limits = norito::DecodeLimits::new(1_000_000, 1_000_000, 1_000_000, 4_000_000, 16);
    std::fs::write(&path, format!("{}0{}", "[".repeat(17), "]".repeat(17))).unwrap();
    assert!(
        read_proofs_with_limits(std::slice::from_ref(&path), 1000, limits)
            .unwrap_err()
            .to_string()
            .contains("lexical")
    );
    let fixture = NativeFinalityFixture::new();
    let encoded = json::to_json(fixture.latest()).unwrap();
    std::fs::write(&path, &encoded).unwrap();
    assert!(
        read_proofs_with_limits(std::slice::from_ref(&path), encoded.len() - 1, limits).is_err()
    );
    let allocation_limit = norito::DecodeLimits::new(
        1_000_000,
        1_000_000,
        1_000_000,
        std::mem::size_of::<SumeragiFinalityProof>() + encoded.len(),
        16,
    );
    assert!(
        read_proofs_with_limits(std::slice::from_ref(&path), encoded.len(), allocation_limit)
            .is_err()
    );
    let profile = json::preflight_slice(
        encoded.as_bytes(),
        json::JsonPreflightLimits::from_decode_limits(encoded.len(), limits),
    )
    .unwrap();
    let element_limit = norito::DecodeLimits::new(
        1_000_000,
        1_000_000,
        profile.array_entries() + profile.object_entries(),
        4_000_000,
        16,
    );
    assert!(
        read_proofs_with_limits(std::slice::from_ref(&path), encoded.len(), element_limit).is_ok()
    );
    assert!(
        read_proofs_with_limits(&[path.clone(), path], encoded.len() * 2, element_limit).is_err()
    );
}

#[cfg(unix)]
#[test]
fn release_signer_is_native_private_canonical_and_never_echoes_bad_key_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
    let key = KeyPair::from_seed(vec![113; 32], Algorithm::Ed25519);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("release.key");
    std::fs::write(
        &path,
        format!("{}\n", ExposedPrivateKey(key.private_key().clone())),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        release_signer(&path).unwrap().public_key(),
        key.public_key()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(release_signer(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"private-sentinel-not-a-key\n").unwrap();
    let error = release_signer(&path).unwrap_err();
    assert!(!format!("{error:?}").contains("private-sentinel"));
    let link = directory.path().join("hardlink.key");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(release_signer(&path).is_err());
}

#[cfg(unix)]
#[test]
fn operator_prepares_both_canonical_artifacts_atomically_from_real_native_execution() {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        isi::Log,
        level::Level,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_deploy::bootstrap::{InstalledNetworkProfiles, ReleaseCheckpointStore};
    use std::os::unix::fs::PermissionsExt as _;
    let config = TestChainConfig::new(World::new(), 1_000);
    let genesis_key = config.genesis_key.clone();
    let prepared = CertifiedTestChain::prepare(config).unwrap();
    let manifest = prepared.manifest.clone();
    let signed = prepared.genesis.canonical_wire().to_vec();
    let mut chain = CertifiedTestChain::from_prepared(prepared).unwrap();
    let mut transaction = TransactionBuilder::new(
        chain.network_id(),
        chain.genesis_account().clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(std::time::Duration::from_millis(1_001));
    let transaction = transaction
        .with_instructions([Log::new(
            Level::INFO,
            "native bootstrap operator fixture work".into(),
        )])
        .sign(genesis_key.private_key());
    assert_eq!(chain.commit(vec![transaction]), [true]);
    let committee = chain
        .validators()
        .iter()
        .map(
            |(peer, pop)| iroha_data_model::sumeragi_finality::FinalityValidator {
                public_key: peer.public_key().clone(),
                proof_of_possession: pop.clone(),
            },
        )
        .collect::<Vec<_>>();
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = directory.path().join("genesis.json");
    let manifest_json = json::to_json(&manifest).unwrap();
    std::fs::write(&manifest_path, &manifest_json).unwrap();
    let signed_path = directory.path().join("genesis.nrt");
    std::fs::write(&signed_path, &signed).unwrap();
    let proof_paths = (1..=2)
        .map(|height| {
            let decision = chain.committed(height);
            let block = decision.block();
            let proof = SumeragiFinalityProof {
                block_header: block.header(),
                block_wire: block.encode_wire().unwrap(),
                committee: committee.clone(),
            };
            let path = directory.path().join(format!("proof-{height}.json"));
            std::fs::write(&path, json::to_json(&proof).unwrap()).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let release_key = KeyPair::from_seed(vec![113; 32], Algorithm::Ed25519);
    let key_path = directory.path().join("release.key");
    std::fs::write(
        &key_path,
        format!("{}\n", ExposedPrivateKey(release_key.private_key().clone())),
    )
    .unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = directory.path().join("prepared");
    let args = PrepareArgs {
        genesis_manifest: manifest_path.clone(),
        expected_genesis_manifest_sha256: iroha_crypto::sha256(manifest_json.as_bytes()),
        signed_genesis: signed_path,
        genesis_public_key: genesis_key.public_key().clone(),
        expected_network_id: chain.network_id(),
        proof_json: proof_paths,
        network_name: "fixture".into(),
        serial: 7,
        generation: 2,
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
        torii_root: vec!["https://torii.example/".into()],
        peer: committee
            .iter()
            .map(|member| format!("{}=https://torii.example/", member.public_key))
            .collect(),
        checkpoint_url: "https://releases.example/checkpoint.nrt".into(),
        release_public_key: release_key.public_key().clone(),
        release_key_file: key_path,
        faucet_root: None,
        faucet_issuer: None,
        faucet_asset: None,
        faucet_amount: None,
        max_operation_fee: None,
        max_namespace_rent: None,
        build_registry_root: vec![],
        output_dir: output.clone(),
    };
    let retry = args.clone();
    let receipt = args.prepare(2_000).unwrap();
    assert_eq!(
        receipt.get("live_network_qualified"),
        Some(&Value::Bool(false))
    );
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 2);
    let profiles = InstalledNetworkProfiles::load(&output.join("network-profiles.nrt")).unwrap();
    let profile = profiles.select("fixture").unwrap();
    assert_eq!(profile.release_public_key(), release_key.public_key());
    let bytes = iroha_fs::read_regular(
        output.join("checkpoint.nrt"),
        iroha_deploy::bootstrap::MAX_RELEASE_CHECKPOINT_BYTES,
    )
    .unwrap();
    let store =
        ReleaseCheckpointStore::open(&directory.path().join("independent-receiver")).unwrap();
    let authenticated = store
        .authenticate(profile.release_trust(), &bytes, 2_000)
        .unwrap();
    assert_eq!(authenticated.release().network_id, chain.network_id());
    assert_eq!(authenticated.release().checkpoint_height, 2);
    assert_eq!(
        authenticated.release().account_chain_discriminant,
        manifest.chain_discriminant()
    );
    assert!(retry.clone().prepare(2_001).is_err());
    let mut substituted = retry;
    substituted.output_dir = directory.path().join("must-not-publish");
    std::fs::write(&manifest_path, format!("{manifest_json}\n")).unwrap();
    assert!(substituted.prepare(2_001).is_err());
    assert!(!directory.path().join("must-not-publish").exists());
}
