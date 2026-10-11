//! Genuine native finality/signature fixtures; synthetic results do not qualify live execution.

use super::*;
use iroha_crypto::Algorithm;
use iroha_data_model::sumeragi_finality::{
    authenticated_genesis, test_fixtures::NativeFinalityFixture,
};

fn signer() -> KeyPair {
    KeyPair::from_seed(vec![113; 32], Algorithm::Ed25519)
}

fn policy(checkpoint: &SumeragiFinalityCheckpoint) -> NetworkPublicationPolicy {
    NetworkPublicationPolicy {
        network_name: "fixture".into(),
        serial: 7,
        generation: 2,
        issued_at_ms: 1_000,
        expires_at_ms: 10_000,
        torii_roots: vec!["https://torii.example/".into()],
        peers: checkpoint
            .tip()
            .committee
            .iter()
            .map(|member| ReleasePeer {
                node_id: iroha_model_base::peer::PeerId::new(member.public_key.clone()),
                torii_root: "https://torii.example/".into(),
            })
            .collect(),
        faucet: None,
        build_registry: None,
        checkpoint_url: "https://releases.example/checkpoint.nrt".into(),
        release_public_key: signer().public_key().clone(),
    }
}

fn anchor(fixture: &NativeFinalityFixture) -> GenesisAnchor {
    GenesisAnchor {
        network_id: fixture.network_id(),
        chain_id: fixture.chain_id().into(),
        genesis: fixture.genesis().clone(),
        validators: authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap()
            .committee
            .into_iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession,
            })
            .collect(),
    }
}

#[test]
fn derived_checkpoint_and_signed_installation_roundtrip_through_native_authentication() {
    let fixture = NativeFinalityFixture::new();
    let checkpoint = checkpoint_from_proofs(
        &anchor(&fixture),
        &[fixture.genesis_proof().clone(), fixture.latest().clone()],
    )
    .unwrap();
    assert_eq!(checkpoint, fixture.checkpoint());
    let prepared = prepare_checkpoint(
        checkpoint.clone(),
        369,
        policy(&checkpoint),
        &signer(),
        2_000,
    )
    .unwrap();
    assert_eq!(prepared.release.network_id, fixture.network_id());
    assert_eq!(prepared.release.chain_id, fixture.chain_id());
    assert_eq!(prepared.release.checkpoint_height, 2);
    assert_eq!(
        prepared.release.checkpoint_hash,
        Hash::new(checkpoint.encode_canonical().unwrap())
    );
    assert_eq!(
        prepared.release.native_world_schema,
        iroha_core::state::State::native_world_schema_hash_v1().unwrap()
    );
    let profiles =
        InstalledNetworkProfiles::from_installation_bytes(&prepared.profile_bytes).unwrap();
    assert_eq!(
        profiles.encode_installation().unwrap(),
        prepared.profile_bytes
    );
    let profile = profiles.select("fixture").unwrap();
    assert_eq!(profile.release_public_key(), signer().public_key());
    assert_eq!(profile.minimum_serial(), 7);
    let root = tempfile::tempdir().unwrap();
    let store = super::super::ReleaseCheckpointStore::open(&root.path().join("retained")).unwrap();
    let authenticated = store
        .authenticate(profile.release_trust(), &prepared.checkpoint_bytes, 2_000)
        .unwrap();
    assert_eq!(authenticated.release(), &prepared.release);
    assert_eq!(authenticated.into_verifier().checkpoint(), &checkpoint);
    let mut noncanonical = prepared.checkpoint_bytes;
    noncanonical.push(0);
    assert!(
        store
            .authenticate(profile.release_trust(), &noncanonical, 2_001)
            .is_err()
    );
}

#[test]
fn offline_prefix_rejects_missing_duplicate_substituted_and_oversized_evidence() {
    let fixture = NativeFinalityFixture::new();
    let selected = anchor(&fixture);
    assert!(checkpoint_from_proofs(&selected, &[]).is_err());
    assert!(checkpoint_from_proofs(&selected, &[fixture.genesis_proof().clone()]).is_err());
    assert!(
        checkpoint_from_proofs(
            &selected,
            &[
                fixture.genesis_proof().clone(),
                fixture.genesis_proof().clone()
            ]
        )
        .is_err()
    );
    let mut changed = selected.clone();
    changed.chain_id = "substituted-chain".into();
    assert!(
        checkpoint_from_proofs(
            &changed,
            &[fixture.genesis_proof().clone(), fixture.latest().clone()]
        )
        .is_err()
    );
    changed = selected.clone();
    changed.validators[0].proof_of_possession[0] ^= 1;
    assert!(
        checkpoint_from_proofs(
            &changed,
            &[fixture.genesis_proof().clone(), fixture.latest().clone()]
        )
        .is_err()
    );
    let mut oversized = fixture.genesis_proof().clone();
    oversized.block_wire.resize(MAX_ADVANCE_BYTES + 1, 0);
    assert!(
        checkpoint_from_proofs(&selected, &[oversized, fixture.latest().clone()])
            .unwrap_err()
            .to_string()
            .contains("byte bound")
    );
    let source = OfflineProofSource;
    assert!(source.finality_proof(NonZeroU64::new(1).unwrap()).is_err());
    assert!(
        source
            .latest_attestation(
                &iroha_model_base::peer::PeerId::new(signer().public_key().clone()),
                &[0; 32]
            )
            .is_err()
    );
}

#[test]
fn release_policy_rejects_signer_substitution_expiry_excess_lifetime_and_untrusted_urls() {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let mut selected = policy(&checkpoint);
    selected.release_public_key = KeyPair::from_seed(vec![114; 32], Algorithm::Ed25519)
        .public_key()
        .clone();
    assert!(prepare_checkpoint(checkpoint.clone(), 369, selected, &signer(), 2_000).is_err());
    for now in [999, 10_000] {
        assert!(
            prepare_checkpoint(checkpoint.clone(), 369, policy(&checkpoint), &signer(), now)
                .is_err()
        );
    }
    let mut selected = policy(&checkpoint);
    selected.expires_at_ms = selected.issued_at_ms + super::super::MAX_RELEASE_VALIDITY_MS + 1;
    assert!(prepare_checkpoint(checkpoint.clone(), 369, selected, &signer(), 2_000).is_err());
    for location in [
        "http://releases.example/checkpoint.nrt",
        "https://user:credential@releases.example/checkpoint.nrt",
        "https://releases.example/checkpoint.nrt?authority=peer",
    ] {
        let mut selected = policy(&checkpoint);
        selected.checkpoint_url = location.into();
        assert!(prepare_checkpoint(checkpoint.clone(), 369, selected, &signer(), 2_000).is_err());
    }
    let mut selected = policy(&checkpoint);
    selected.peers.pop();
    assert!(prepare_checkpoint(checkpoint, 369, selected, &signer(), 2_000).is_err());
}

#[test]
fn operator_preparation_refuses_unpinned_genesis_key_and_network_before_signing() {
    let fixture = NativeFinalityFixture::new();
    let metadata = iroha_genesis::signed_genesis_consensus_metadata(fixture.genesis()).unwrap();
    let manifest = iroha_genesis::GenesisBuilder::new_without_executor(
        fixture.chain_id().parse().unwrap(),
        ".",
    )
    .with_sumeragi_context_parameters(metadata.sumeragi_context)
    .build_raw()
    .unwrap();
    let wire = fixture.genesis().encode_wire().unwrap();
    let manifest_json = norito::json::to_json(&manifest).unwrap();
    let manifest_sha256 = iroha_crypto::sha256(manifest_json.as_bytes());
    let checkpoint = fixture.checkpoint();
    let wrong_key = KeyPair::from_seed(vec![115; 32], Algorithm::Ed25519);
    let proofs = [fixture.genesis_proof().clone(), fixture.latest().clone()];
    assert!(
        prepare_network_publication(
            PinnedPublicationGenesis {
                signed_genesis: &wire,
                manifest_json: manifest_json.as_bytes(),
                expected_manifest_sha256: manifest_sha256,
                genesis_public_key: wrong_key.public_key(),
                expected_network: fixture.network_id(),
            },
            &proofs,
            policy(&checkpoint),
            &signer(),
            2_000
        )
        .is_err()
    );
    let wrong_network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"other independently selected genesis"),
    ));
    let genesis_key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    assert!(
        prepare_network_publication(
            PinnedPublicationGenesis {
                signed_genesis: &wire,
                manifest_json: manifest_json.as_bytes(),
                expected_manifest_sha256: manifest_sha256,
                genesis_public_key: genesis_key.public_key(),
                expected_network: wrong_network,
            },
            &proofs,
            policy(&checkpoint),
            &signer(),
            2_000
        )
        .is_err()
    );
}

#[test]
fn operator_entry_point_authenticates_original_manifest_and_real_executed_successor() {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        account::{Account, AccountId},
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
        isi::{Log, Mint, Register},
        level::Level,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_primitives::numeric::Quantity;
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let issuer = AccountId::new(
        KeyPair::from_seed(vec![116; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let currency = AssetDefinitionId::derive_from_components(
        iroha_genesis::GENESIS_DOMAIN_ID.clone(),
        "publication_currency".parse().unwrap(),
    );
    config.genesis_instructions.extend([
        Register::account(Account::new(issuer.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            currency.clone(),
            "Publication Currency",
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(30_000_u32, AssetId::new(currency.clone(), issuer.clone())).into(),
    ]);
    let genesis_key = config.genesis_key.clone();
    let prepared = CertifiedTestChain::prepare(config).unwrap();
    let manifest = prepared.manifest.clone();
    let manifest_json = norito::json::to_json(&manifest).unwrap();
    let manifest_sha256 = iroha_crypto::sha256(manifest_json.as_bytes());
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
            "native publication fixture work".into(),
        )])
        .sign(genesis_key.private_key());
    assert_eq!(chain.commit(vec![transaction]), [true]);
    let committee = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect::<Vec<_>>();
    let proofs = (1..=2)
        .map(|height| {
            let committed = chain.committed(height);
            let block = committed.block();
            SumeragiFinalityProof {
                block_header: block.header(),
                block_wire: block.encode_wire().unwrap(),
                committee: committee.clone(),
            }
        })
        .collect::<Vec<_>>();
    let selected = GenesisAnchor {
        network_id: chain.network_id(),
        chain_id: manifest.chain_id().to_string(),
        genesis: chain.genesis().clone(),
        validators: committee,
    };
    let checkpoint = checkpoint_from_proofs(&selected, &proofs).unwrap();
    let mut publication_policy = policy(&checkpoint);
    publication_policy.faucet = Some(ReleaseFaucet {
        torii_root: "https://torii.example/".into(),
        issuer,
        asset_definition_id: currency,
        amount: Quantity::from(25_000_u32),
        max_operation_fee: Quantity::from(25_000_u32),
        max_namespace_rent: Quantity::from(25_000_u32),
    });
    let artifacts = prepare_network_publication(
        PinnedPublicationGenesis {
            signed_genesis: &signed,
            manifest_json: manifest_json.as_bytes(),
            expected_manifest_sha256: manifest_sha256,
            genesis_public_key: genesis_key.public_key(),
            expected_network: chain.network_id(),
        },
        &proofs,
        publication_policy.clone(),
        &signer(),
        2_000,
    )
    .unwrap();
    assert_eq!(artifacts.release.network_id, chain.network_id());
    assert_eq!(artifacts.release.chain_id, manifest.chain_id().to_string());
    assert_eq!(
        artifacts.release.account_chain_discriminant,
        manifest.chain_discriminant()
    );
    assert_eq!(artifacts.release.checkpoint_height, 2);
    for changed_issuer in [true, false] {
        let mut substituted = publication_policy.clone();
        let allowance = substituted.faucet.as_mut().unwrap();
        if changed_issuer {
            allowance.issuer = AccountId::new(
                KeyPair::from_seed(vec![117; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            );
        } else {
            allowance.asset_definition_id = AssetDefinitionId::derive_from_components(
                iroha_genesis::GENESIS_DOMAIN_ID.clone(),
                "substituted_currency".parse().unwrap(),
            );
        }
        assert!(
            prepare_network_publication(
                PinnedPublicationGenesis {
                    signed_genesis: &signed,
                    manifest_json: manifest_json.as_bytes(),
                    expected_manifest_sha256: manifest_sha256,
                    genesis_public_key: genesis_key.public_key(),
                    expected_network: chain.network_id(),
                },
                &proofs,
                substituted,
                &signer(),
                2_000,
            )
            .is_err()
        );
    }
    let substituted_discriminant = if manifest.chain_discriminant() == 369 {
        753
    } else {
        369
    };
    let substituted_manifest = manifest.with_chain_discriminant(substituted_discriminant);
    let substituted_json = norito::json::to_json(&substituted_manifest).unwrap();
    assert!(
        prepare_network_publication(
            PinnedPublicationGenesis {
                signed_genesis: &signed,
                manifest_json: substituted_json.as_bytes(),
                expected_manifest_sha256: manifest_sha256,
                genesis_public_key: genesis_key.public_key(),
                expected_network: chain.network_id(),
            },
            &proofs,
            policy(&checkpoint),
            &signer(),
            2_000
        )
        .is_err()
    );
}
