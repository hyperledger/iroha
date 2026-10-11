//! Export locally selected deployment expectations; no host or authorization is consulted.

use super::*;
use crate::taira_dataspace_deploy::{
    DeploymentPeerV1, DeploymentTrustV1, validate_deployment_peer_routes, validate_deployment_trust,
};
use iroha_data_model::NetworkId;

#[derive(clap::Args, Debug)]
pub(super) struct ExportDeploymentProfile {
    /// Exact native assembled inventory for the selected candidate.
    #[arg(long, value_name = "FILE")]
    inventory: PathBuf,
    /// Complete native prepare-public-inputs bundle.
    #[arg(long, value_name = "DIR")]
    public_inputs: PathBuf,
    /// New public profile file under an existing owner-private directory.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

fn derive_profile(
    inventory: &InventoryV1,
    public: &public_inputs::PublicInputsV1,
    wire: &[u8],
) -> Result<DeploymentTrustV1> {
    validate_inventory(inventory)?;
    derive_admitted_profile(
        &inventory.next_genesis_hash,
        &inventory.canary_onboarding_request,
        &inventory.validators,
        &inventory.validator_clients,
        public,
        wire,
    )
}

// The caller admits either the complete inventory or the native-derived public
// context. Profile derivation precedes a completed artifact plan and
// confers no deployment or owner authorization.
pub(super) fn derive_admitted_profile(
    next_genesis_hash: &str,
    canary_onboarding_request: &AccountOnboardingPlanRequestV1,
    validators: &[ValidatorV1],
    validator_clients: &[ValidatorClientV1],
    public: &public_inputs::PublicInputsV1,
    wire: &[u8],
) -> Result<DeploymentTrustV1> {
    if next_genesis_hash != public.genesis_hash
        || canary_onboarding_request != &public.canary_onboarding_request
        || sha256_hex(wire) != public.signed_genesis_sha256
    {
        return Err(eyre!(
            "inventory differs from the selected native public input bundle"
        ));
    }
    // Full inventory admission already enforces this. The standalone public
    // context path must also reject extra/missing rows before zip truncation.
    if validators.len() != VALIDATOR_SLUGS.len() || validator_clients.len() != VALIDATOR_SLUGS.len()
    {
        return Err(eyre!(
            "deployment profile requires exactly four validator and client slots"
        ));
    }
    let hash_file = format!("{}\n", public.genesis_hash);
    let mut peers = Vec::new();
    for ((validator, client), expected_slug) in validators
        .iter()
        .zip(validator_clients)
        .zip(VALIDATOR_SLUGS)
    {
        if validator.slug != expected_slug || client.slug != expected_slug {
            return Err(eyre!("deployment profile validator slots differ"));
        }
        for (role, expected, size) in [
            ("genesis", public.signed_genesis_sha256.clone(), wire.len()),
            (
                "genesis_hash",
                sha256_hex(hash_file.as_bytes()),
                hash_file.len(),
            ),
        ] {
            let artifact = validator
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .ok_or_else(|| eyre!("inventory omits a native genesis artifact"))?;
            if artifact.sha256 != expected || artifact.size != u64::try_from(size)? {
                return Err(eyre!(
                    "inventory genesis artifact differs from public bundle"
                ));
            }
        }
        peers.push(DeploymentPeerV1 {
            torii_origin: client.torii_origin.clone(),
            peer_id: client.peer_id.parse()?,
            node_fingerprint: validator.node_fingerprint.parse()?,
            build_fingerprint: validator.build_fingerprint.parse()?,
            config_fingerprint: validator.config_fingerprint.parse()?,
        });
    }
    let profile = DeploymentTrustV1 {
        chain: CHAIN_ID.into(),
        account_chain_discriminant: CHAIN_DISCRIMINANT,
        genesis_public_key: public.genesis_public_key.clone(),
        genesis_signed_wire_hex: hex::encode(wire),
        peers,
    };
    validate_deployment_trust(&profile, public.network_id)?;
    validate_deployment_peer_routes(&profile)?;
    Ok(profile)
}

#[derive(JsonSerialize)]
struct ExportReceiptV1 {
    schema: String,
    network_id: NetworkId,
    profile: String,
    profile_sha256: String,
    inventory_sha256: String,
    signed_genesis_sha256: String,
    target_expectation_only: bool,
    authorization_verified: bool,
    deployment_verified: bool,
}

pub(super) fn export(args: &ExportDeploymentProfile, output: &mut impl Write) -> Result<()> {
    let (inventory, inventory_bytes, _chain_guard) =
        read_inventory(&args.inventory, "deployment profile inventory")?;
    let public = public_inputs::load(&args.public_inputs)?;
    let path = args.public_inputs.join("genesis.signed.nrt");
    let (file, snapshot) = open_pinned_regular(&path, "public deployment genesis")?;
    let wire = read_pinned_bytes(
        &path,
        "public deployment genesis",
        file,
        &snapshot,
        MAX_JSON_BYTES,
    )?;
    let profile = derive_profile(&inventory, &public, &wire)?;
    let mut bytes = json::to_vec(&profile)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(eyre!("deployment profile exceeds the native JSON bound"));
    }
    // Publish once through the existing native atomic output custodian. This reads
    // no paths from the inventory and never opens validator configs or credentials.
    inputs::write_new_private(&args.output, &bytes)?;
    let receipt = ExportReceiptV1 {
        schema: "iroha.taira.deployment-profile-export.v1".into(),
        network_id: public.network_id,
        profile: args.output.to_string_lossy().into_owned(),
        profile_sha256: sha256_hex(&bytes),
        inventory_sha256: sha256_hex(&inventory_bytes),
        signed_genesis_sha256: public.signed_genesis_sha256,
        target_expectation_only: true,
        authorization_verified: false,
        deployment_verified: false,
    };
    output.write_all(&json::to_vec(&receipt)?)?;
    output.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::Encode as _;

    fn admitted_inventory_profile(
        inventory: &InventoryV1,
        public: &public_inputs::PublicInputsV1,
        wire: &[u8],
    ) -> Result<DeploymentTrustV1> {
        derive_admitted_profile(
            &inventory.next_genesis_hash,
            &inventory.canary_onboarding_request,
            &inventory.validators,
            &inventory.validator_clients,
            public,
            wire,
        )
    }

    fn fixture() -> (InventoryV1, public_inputs::PublicInputsV1, Vec<u8>) {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let mut inventory = sample_inventory_fixture();
        inventory.qualification_scope = QualificationScopeV1::CoreTestnet;
        inventory.inrou_canary = None;
        inventory.inrou_stage_tree_sha256 = None;
        let (genesis, key) = deployment_genesis_fixture();
        let wire = genesis.encode_wire().unwrap();
        let genesis_hash = Hash::from(genesis.hash()).to_string();
        let canary =
            iroha_crypto::KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519).unwrap();
        let public = public_inputs::PublicInputsV1 {
            schema: "iroha.taira.public-reset.public-inputs.v1".into(),
            network_id: NetworkId::from_genesis_hash(genesis.hash()),
            genesis_hash: genesis_hash.clone(),
            signed_genesis_sha256: sha256_hex(&wire),
            nexus_amx_context_sha256: "11".repeat(32),
            raw_manifest_sha256: "1".repeat(64),
            genesis_public_key: key.public_key().clone(),
            canary_public_key: canary.public_key().clone(),
            canary_onboarding_request: inventory.canary_onboarding_request.clone(),
        };
        inventory.next_genesis_hash = genesis_hash;
        let hash_file = format!("{}\n", public.genesis_hash);
        let validators = iroha_genesis::signed_genesis_validator_pops(&genesis).unwrap();
        for ((validator, client), peer) in inventory
            .validators
            .iter_mut()
            .zip(&mut inventory.validator_clients)
            .zip(validators.into_keys())
        {
            let peer = PeerId::new(peer);
            client.peer_id = peer.to_string();
            validator.node_fingerprint = Hash::new(peer.encode()).to_string();
            for artifact in &mut validator.artifacts {
                match artifact.role.as_str() {
                    "genesis" => {
                        artifact.sha256 = public.signed_genesis_sha256.clone();
                        artifact.size = wire.len() as u64;
                    }
                    "genesis_hash" => {
                        artifact.sha256 = sha256_hex(hash_file.as_bytes());
                        artifact.size = hash_file.len() as u64;
                    }
                    _ => {}
                }
            }
        }
        inventory.beacon_bootstrap = host::beacon::fixture_plan(
            &inventory.validators,
            &inventory.validator_clients,
            public.network_id,
        );
        inventory.artifact_closure_sha256 = artifact_closure_sha256(&inventory);
        validate_inventory_structure(&inventory).expect("complete profile binding fixture");
        (inventory, public, wire)
    }

    #[test]
    fn deployment_profile_binds_native_genesis_and_ordered_inventory_peers() {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let (inventory, public, wire) = fixture();
        let profile = admitted_inventory_profile(&inventory, &public, &wire).unwrap();
        let admitted = derive_profile(&inventory, &public, &wire);
        if test_compiled_release_commit().is_some() {
            assert_eq!(
                json::to_vec(&admitted.unwrap()).unwrap(),
                json::to_vec(&profile).unwrap()
            );
        } else {
            let error = admitted.expect_err("development executable cannot admit a release");
            assert_compiled_admission_error(&error, "unused on development builds");
        }
        assert_eq!(profile.peers.len(), 4);
        for (peer, client) in profile.peers.iter().zip(&inventory.validator_clients) {
            assert_eq!(peer.peer_id.to_string(), client.peer_id);
            assert_eq!(peer.torii_origin, client.torii_origin);
        }
        assert_eq!(profile.genesis_signed_wire_hex, hex::encode(wire));
        assert_eq!(profile.genesis_public_key, public.genesis_public_key);
    }

    #[test]
    fn deployment_profile_rejects_genesis_artifact_peer_and_slot_substitution() {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let (inventory, public, wire) = fixture();
        let mut wrong = inventory.clone();
        wrong.next_genesis_hash = Hash::new(b"other genesis").to_string();
        wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
        assert!(
            admitted_inventory_profile(&wrong, &public, &wire)
                .unwrap_err()
                .to_string()
                .contains("inventory differs from the selected native public input bundle"),
        );
        let mut wrong = inventory.clone();
        wrong.validators[0]
            .artifacts
            .iter_mut()
            .find(|v| v.role == "genesis")
            .unwrap()
            .sha256 = "a".repeat(64);
        wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
        assert!(
            admitted_inventory_profile(&wrong, &public, &wire)
                .unwrap_err()
                .to_string()
                .contains("inventory genesis artifact differs from public bundle"),
        );
        let mut wrong = inventory.clone();
        wrong.validators.swap(0, 1);
        wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
        assert!(
            admitted_inventory_profile(&wrong, &public, &wire)
                .unwrap_err()
                .to_string()
                .contains("deployment profile validator slots differ"),
        );
        let mut wrong = inventory.clone();
        wrong.validator_clients[1].torii_origin = wrong.validator_clients[0].torii_origin.clone();
        wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
        assert!(admitted_inventory_profile(&wrong, &public, &wire).is_err());
        let mut wrong = inventory;
        let foreign =
            iroha_crypto::KeyPair::try_from_seed(vec![99; 32], Algorithm::BlsNormal).unwrap();
        let peer = PeerId::new(foreign.public_key().clone());
        wrong.validator_clients[0].peer_id = peer.to_string();
        wrong.validators[0].node_fingerprint = Hash::new(peer.encode()).to_string();
        wrong.artifact_closure_sha256 = artifact_closure_sha256(&wrong);
        assert!(
            admitted_inventory_profile(&wrong, &public, &wire)
                .unwrap_err()
                .to_string()
                .contains("validator profile must bind four distinct genesis peers and their selected endpoints"),
        );
    }

    #[test]
    fn deployment_profile_public_context_precedes_artifact_closure_without_weakening_export() {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let (mut inventory, public, wire) = fixture();
        let expected = admitted_inventory_profile(&inventory, &public, &wire).unwrap();
        inventory.artifact_closure_sha256 = "not-yet-assembled".into();
        let profile = derive_admitted_profile(
            &inventory.next_genesis_hash,
            &inventory.canary_onboarding_request,
            &inventory.validators,
            &inventory.validator_clients,
            &public,
            &wire,
        )
        .unwrap();
        assert_eq!(
            json::to_vec(&profile).unwrap(),
            json::to_vec(&expected).unwrap()
        );
        assert!(derive_profile(&inventory, &public, &wire).is_err());
    }

    #[test]
    fn deployment_profile_public_context_rejects_truncated_or_extra_slot_vectors() {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let (inventory, public, wire) = fixture();
        for (validator_count, client_count) in [(3, 4), (4, 3), (5, 4), (4, 5)] {
            let mut validators = inventory.validators.clone();
            let mut clients = inventory.validator_clients.clone();
            validators.resize(validator_count, validators[0].clone());
            clients.resize(client_count, clients[0].clone());
            let error = derive_admitted_profile(
                &inventory.next_genesis_hash,
                &inventory.canary_onboarding_request,
                &validators,
                &clients,
                &public,
                &wire,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("exactly four validator and client slots")
            );
        }
    }

    #[test]
    fn deployment_profile_command_parses_without_private_or_runtime_arguments() {
        use clap::Parser as _;
        let args = crate::Args::try_parse_from([
            "iroha",
            "taira",
            "public-reset",
            "export-deployment-profile",
            "--inventory",
            "/public/inventory.json",
            "--public-inputs",
            "/public/bundle",
            "--output",
            "/public/profile.json",
        ])
        .unwrap();
        let crate::Command::Taira(taira) = args.command else {
            panic!("Taira command")
        };
        let crate::taira::Command::PublicReset(reset) = taira else {
            panic!("reset command")
        };
        assert!(matches!(
            reset.command,
            PublicResetCommand::ExportDeploymentProfile(_)
        ));
    }
}
