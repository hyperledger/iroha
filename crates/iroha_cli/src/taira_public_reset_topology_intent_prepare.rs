//! Read-only producer for one fresh topology intent after a durable dispatcher apply.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
#[cfg(any(target_os = "linux", test))]
use super::super::admission;
#[cfg(target_os = "linux")]
use super::super::storage;
use super::*;
#[cfg(any(target_os = "linux", test))]
use crate::taira_public_reset as reset;
#[cfg(target_os = "linux")]
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
#[cfg(any(target_os = "linux", test))]
use reset::history::TerminalInventory;
#[cfg(any(target_os = "linux", test))]
use reset::{
    BUILD_PROFILE, BUILD_TARGET, CHAIN_ID, FaucetPolicyV1, RevisionV1, SourceManifestV1,
    ValidatorClientV1,
};
#[cfg(target_os = "linux")]
use reset::{EdgeInitialStateV1, FeeIntentV1, ValidatorInitialStateV1};

/// Live predecessor identity comes from the sealed plan, stopped capture and selected inventory.
#[derive(clap::Args, Debug)]
pub(in super::super::super::super) struct PrepareTopologyIntent {
    /// Inventory of the terminal predecessor bound to the transition lease.
    #[arg(long)]
    retained_inventory: PathBuf,
    #[arg(long)]
    expected_retained_inventory_sha256: String,
    /// Inventory of the release actually selected after the transition.
    #[arg(long)]
    selected_inventory: PathBuf,
    #[arg(long)]
    expected_selected_inventory_sha256: String,
    /// Prior authorization signed by the transition plan's trusted public key.
    #[arg(long)]
    selected_authorization: PathBuf,
    #[arg(long)]
    current_runtime: PathBuf,
    #[arg(long)]
    expected_current_runtime_sha256: String,
    #[arg(long)]
    transition_plan: PathBuf,
    #[arg(long)]
    expected_plan_sha256: String,
    #[arg(long)]
    import_root: PathBuf,
    #[arg(long)]
    public_inputs: PathBuf,
    #[arg(long)]
    source_manifest: PathBuf,
    #[arg(long)]
    known_hosts: PathBuf,
    #[arg(long, num_args = 4)]
    validator_client_config: Vec<PathBuf>,
    #[arg(long, num_args = 4)]
    validator_config: Vec<PathBuf>,
    #[arg(long, num_args = 4)]
    initial_unit: Vec<PathBuf>,
    #[arg(long)]
    edge_config: PathBuf,
    /// Retained public Darwin artifact copy admitted by the signed transition candidate.
    #[arg(long)]
    native_edge_cli: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[cfg(any(target_os = "linux", test))]
fn absolute(path: &Path, label: &str) -> Result<String> {
    validate_absolute_normal_path(path, label)?;
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre!("{label} must be UTF-8"))
}

#[cfg(any(target_os = "linux", test))]
fn artifact(
    role: &str,
    local: &Path,
    remote: String,
) -> Result<reset::inputs::ResetArtifactIntentV1> {
    validate_absolute_normal_path(Path::new(&remote), "candidate remote artifact")?;
    Ok(reset::inputs::ResetArtifactIntentV1 {
        role: role.into(),
        local_path: absolute(local, "candidate local artifact")?,
        remote_path: remote,
    })
}

#[cfg(any(target_os = "linux", test))]
fn bind_predecessor(old: &TerminalInventory, runtime: &CurrentRuntime, plan: &Plan) -> Result<()> {
    need(
        old.validators.len() == 4
            && old.validator_clients.len() == 4
            && runtime.validators.len() == 4
            && plan.predecessor.occupied.len() == 4
            && plan.host_identity_sha256 == runtime.host_identity_sha256
            && json::to_vec(&plan.hosts)? == json::to_vec(&runtime.hosts)?
            && json::to_vec(&plan.predecessor.native_edge_capture)?
                == json::to_vec(&runtime.native_edge)?
            && old.revision.commit != plan.candidate.commit,
        "retained inventory, stopped runtime and candidate revision differ",
    )?;
    for index in 0..4 {
        let old_validator = &old.validators[index];
        let current = &runtime.validators[index];
        let occupied = &plan.predecessor.occupied[index];
        need(
            old_validator.slug == SLUGS[index]
                && old.validator_clients[index].slug == SLUGS[index]
                && current.commit == old.revision.commit
                && old_validator.endpoint.host_identity_sha256 == runtime.host_identity_sha256
                && occupied.slug == SLUGS[index]
                && occupied.selector.target == current.release_root
                && occupied.files.len() == current.artifacts.len(),
            "stopped validator differs from selected predecessor",
        )?;
        current
            .service_state
            .validate_state_identity(occupied.state.device, occupied.state.inode)?;
        for (pin, file) in occupied.files.iter().zip(&current.artifacts) {
            need(
                pin.path == file.path
                    && pin.sha256 == file.sha256
                    && pin.size == file.size
                    && pin.mode == u32::from(file.mode),
                "stopped validator artifact differs from transition plan",
            )?;
        }
        // A takeover retains the loaded unit's independently captured configuration.
        // Genesis remains bound to the selected predecessor in every path.
        for role in ["config", "genesis", "genesis_hash"] {
            let signed = old_validator
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .ok_or_else(|| eyre!("retained validator omits {role}"))?;
            let selected = current.artifact(role)?;
            bind_validator_artifact(
                signed,
                selected,
                &current.release_root,
                plan.predecessor.unresolved_journal.is_some(),
            )?;
        }
        let genesis_hash = current.artifact("genesis_hash")?;
        let selected_hash = occupied
            .files
            .iter()
            .find(|pin| pin.path == genesis_hash.path)
            .ok_or_else(|| eyre!("selected genesis-hash artifact is absent"))?;
        need(
            admission::read(selected_hash)?.as_slice()
                == format!("{}\n", old.next_genesis_hash).as_bytes(),
            "selected genesis-hash artifact differs from restored network identity",
        )?;
    }
    bind_edge_predecessor(old, runtime, plan.predecessor.unresolved_journal.is_some())
}

/// Preserve genesis identity while admitting a takeover's captured native config lifecycle.
#[cfg(any(target_os = "linux", test))]
fn bind_validator_artifact(
    signed: &reset::ArtifactV1,
    selected: &reset::OccupiedArtifactV1,
    release: &str,
    deployment_proven_takeover: bool,
) -> Result<()> {
    need(
        signed.role == selected.role,
        "selected validator artifact role differs",
    )?;
    if deployment_proven_takeover && selected.role == "config" {
        let name = reset::host::occupied::validator_config_name(Path::new(&selected.path))?;
        return need(
            selected.path == format!("{release}/config/{name}")
                && selected.mode == 0o600
                && selected.size > 0
                && selected.size <= 1024 * 1024,
            "captured validator configuration escaped its native lifecycle",
        );
    }
    need(
        signed.sha256 == selected.sha256
            && signed.size == selected.size
            && signed.mode == selected.mode,
        "sealed validator configuration or genesis differs from selected runtime",
    )
}

/// A takeover binds the current independently signed publication, retaining its actual owner.
#[cfg(any(target_os = "linux", test))]
fn bind_edge_predecessor(
    old: &TerminalInventory,
    runtime: &CurrentRuntime,
    deployment_proven_takeover: bool,
) -> Result<()> {
    old.validate_physical_binding(&runtime.hosts)?;
    let edge = &runtime.native_edge.claims.release;
    need(
        old.edge.slug == "taira-edge"
            && old.edge.endpoint.host_identity_sha256
                == runtime.hosts.native_edge.endpoint.host_identity_sha256
            && edge.commit == old.revision.commit
            && runtime.native_edge.claims.owner_uid == runtime.hosts.native_edge.owner_uid
            && runtime.native_edge.claims.owner_gid == runtime.hosts.native_edge.owner_gid
            && runtime.native_edge.claims.custody_root == runtime.hosts.native_edge.custody_root
            && edge.config_sha256
                == runtime
                    .native_edge
                    .claims
                    .owned_publication
                    .publication
                    .sha256
            && (deployment_proven_takeover
                || old.edge.artifacts.iter().any(|artifact| {
                    artifact.role == "edge_config" && artifact.sha256 == edge.config_sha256
                })),
        "independently captured native edge differs from selected predecessor",
    )
}

/// A failed reset remains the transition predecessor, while its admitted prior
/// release is again the selected network after a complete rollback. Do not use
/// the failed reset's candidate revision, genesis or client identities as the
/// source of the successor topology.
#[cfg(any(target_os = "linux", test))]
fn bind_selected_inventory(
    selected: &TerminalInventory,
    selected_sha256: &str,
    predecessor: &TerminalInventory,
    runtime: &CurrentRuntime,
    plan: &Plan,
) -> Result<()> {
    bind_inventory_lineage(
        selected,
        selected_sha256,
        predecessor,
        runtime,
        &plan.predecessor.inventory_sha256,
        plan.predecessor.rolled_back,
    )?;
    bind_predecessor(selected, runtime, plan)
}

#[cfg(any(target_os = "linux", test))]
fn bind_inventory_lineage(
    selected: &TerminalInventory,
    selected_sha256: &str,
    predecessor: &TerminalInventory,
    runtime: &CurrentRuntime,
    predecessor_sha256: &str,
    rolled_back: bool,
) -> Result<()> {
    selected.validate_physical_binding(&runtime.hosts)?;
    predecessor.validate_physical_binding(&runtime.hosts)?;
    if rolled_back {
        need(
            selected_sha256 != predecessor_sha256
                && selected.revision.commit != predecessor.revision.commit
                && selected.next_genesis_hash == predecessor.previous_genesis_hash
                && predecessor.validators.len() == 4
                && runtime.validators.len() == 4,
            "restored inventory does not precede the rolled-back reset",
        )?;
        for (index, attempted) in predecessor.validators.iter().enumerate() {
            need(
                json::to_vec(attempted.admitted_release()?)?
                    == json::to_vec(&runtime.validators[index])?,
                "rolled-back validator does not bind the restored release",
            )?;
        }
        need(
            json::to_vec(predecessor.edge.admitted_release()?)?
                == json::to_vec(&runtime.native_edge.claims.release)?,
            "rolled-back native edge does not bind the restored release",
        )?;
    } else {
        need(
            selected_sha256 == predecessor_sha256,
            "selected inventory differs from completed predecessor",
        )?;
    }
    Ok(())
}

/// Fresh takeover clients select current validated peer routes; ordinary successors retain theirs.
#[cfg(any(target_os = "linux", test))]
fn candidate_client_origin(current: &str, retained: &str, takeover: bool) -> Result<String> {
    reset::validate_validator_public_origin(current)?;
    need(
        current == retained
            || (takeover
                && url::Url::parse(current)?.host_str() == url::Url::parse(retained)?.host_str()),
        "candidate client Torii origin differs from retained public hostname",
    )?;
    Ok(current.to_owned())
}

#[cfg(any(target_os = "linux", test))]
fn distinct_new_clients(
    old: &TerminalInventory,
    new: &[ValidatorClientV1],
    faucet: &FaucetPolicyV1,
    new_canary: &str,
) -> Result<()> {
    need(new.len() == 4, "four new validator clients required")?;
    let old_accounts: BTreeSet<&str> = old
        .validator_clients
        .iter()
        .map(|v| v.account_id.as_str())
        .collect();
    let old_peers: BTreeSet<&str> = old
        .validator_clients
        .iter()
        .map(|v| v.peer_id.as_str())
        .collect();
    let accounts: BTreeSet<&str> = new.iter().map(|v| v.account_id.as_str()).collect();
    let peers: BTreeSet<&str> = new.iter().map(|v| v.peer_id.as_str()).collect();
    need(
        accounts.len() == 4
            && peers.len() == 4
            && accounts.is_disjoint(&old_accounts)
            && peers.is_disjoint(&old_peers)
            && !accounts.contains(faucet.authority.as_str())
            && !accounts.contains(old.canary_onboarding_request.account_id.as_str())
            && !accounts.contains(new_canary)
            && faucet.authority != old.faucet_policy.authority
            && !old_accounts.contains(faucet.authority.as_str())
            && faucet.authority != old.canary_onboarding_request.account_id
            && faucet.authority != new_canary
            && new_canary != old.canary_onboarding_request.account_id
            && new_canary != old.faucet_policy.authority
            && !old_accounts.contains(new_canary),
        "candidate account, peer or faucet identity was reused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal_fixture() -> TerminalInventory {
        let bytes = reset::canonical_inventory_bytes(&reset::sample_inventory_fixture()).unwrap();
        reset::history::decode(&bytes, "fixture").unwrap().0
    }

    fn lineage_fixture() -> (TerminalInventory, TerminalInventory, CurrentRuntime) {
        let mut selected = terminal_fixture();
        selected.revision.commit = "4".repeat(40);
        selected.revision.build_id = selected.revision.commit.clone();
        let mut predecessor = selected.clone();
        predecessor.revision.commit = "a".repeat(40);
        predecessor.revision.build_id = predecessor.revision.commit.clone();
        predecessor.previous_genesis_hash = selected.next_genesis_hash.clone();
        predecessor.next_genesis_hash = "b".repeat(64);
        let hosts: reset::host_pair::ResetHostPairV1 =
            json::from_value(selected.hosts.clone()).unwrap();
        let runtime = CurrentRuntime {
            schema: "iroha.taira.dispatcher-current-runtime.v1".into(),
            host_identity_sha256: selected.validators[0].endpoint.host_identity_sha256.clone(),
            hosts: hosts.clone(),
            validators: predecessor
                .validators
                .iter()
                .map(|v| v.admitted_release().unwrap().clone())
                .collect(),
            native_edge: reset::host_pair::fixture_native_edge_capture(
                &hosts,
                predecessor.edge.admitted_release().unwrap().clone(),
                &"a".repeat(64),
                &"b".repeat(64),
                &predecessor.authorization_nonce,
                &predecessor.next_genesis_hash,
            ),
        };
        (selected, predecessor, runtime)
    }

    #[test]
    fn completed_transition_requires_its_selected_inventory() {
        let (selected, predecessor, runtime) = lineage_fixture();
        bind_inventory_lineage(&selected, "a", &predecessor, &runtime, "a", false).unwrap();
        assert!(
            bind_inventory_lineage(&selected, "different", &predecessor, &runtime, "a", false)
                .is_err()
        );
    }

    #[test]
    fn takeover_clients_use_current_public_peer_routes() {
        let old = "https://taira.sora.org/";
        for port in 9441..=9444 {
            let origin = format!("https://taira.sora.org:{port}/");
            assert_eq!(candidate_client_origin(&origin, old, true).unwrap(), origin);
            assert!(candidate_client_origin(&origin, old, false).is_err());
            candidate_client_origin(&origin, &origin, false).unwrap();
        }
        for invalid in [
            "http://taira.sora.org:9441/",
            "https://other.example.org/",
            "https://taira.sora.org:9441/foreign",
        ] {
            assert!(candidate_client_origin(invalid, old, true).is_err());
        }
    }

    #[test]
    fn takeover_accepts_captured_beacon_config_but_retains_genesis_identity() {
        let fixture = terminal_fixture();
        let validator = &fixture.validators[0];
        let signed = validator
            .artifacts
            .iter()
            .find(|v| v.role == "config")
            .unwrap();
        let release = format!(
            "{}/releases/{}",
            validator.service_root, fixture.revision.commit
        );
        let selected = reset::OccupiedArtifactV1 {
            role: "config".into(),
            path: format!("{release}/config/beacon.toml"),
            sha256: if signed.sha256 == "a".repeat(64) {
                "b".repeat(64)
            } else {
                "a".repeat(64)
            },
            size: signed.size + 1,
            mode: 0o600,
            source_commit: fixture.revision.commit.clone(),
        };
        assert!(bind_validator_artifact(signed, &selected, &release, false).is_err());
        bind_validator_artifact(signed, &selected, &release, true).unwrap();
        for case in 0..5 {
            let mut changed = selected.clone();
            match case {
                0 => changed.path = format!("{release}/config/foreign.toml"),
                1 => changed.path = format!("{release}/other/beacon.toml"),
                2 => changed.mode = 0o644,
                3 => changed.size = 0,
                _ => changed.role = "genesis".into(),
            }
            assert!(bind_validator_artifact(signed, &changed, &release, true).is_err());
        }
        for role in ["genesis", "genesis_hash"] {
            let signed = validator.artifacts.iter().find(|v| v.role == role).unwrap();
            let mut changed = selected.clone();
            changed.role = role.into();
            changed.sha256 = if signed.sha256 == "a".repeat(64) {
                "b".repeat(64)
            } else {
                "a".repeat(64)
            };
            changed.size = signed.size;
            changed.mode = signed.mode;
            assert!(bind_validator_artifact(signed, &changed, &release, true).is_err());
            changed.sha256 = signed.sha256.clone();
            bind_validator_artifact(signed, &changed, &release, true).unwrap();
        }
    }

    #[test]
    fn takeover_accepts_current_signed_edge_publication_with_original_owner() {
        let (selected, _, mut runtime) = lineage_fixture();
        runtime.native_edge.claims.release.commit = selected.revision.commit.clone();
        let historical = selected
            .edge
            .artifacts
            .iter()
            .find(|artifact| artifact.role == "edge_config")
            .unwrap()
            .sha256
            .clone();
        runtime.native_edge.claims.release.config_sha256 = historical.clone();
        runtime
            .native_edge
            .claims
            .owned_publication
            .publication
            .sha256 = historical;
        bind_edge_predecessor(&selected, &runtime, false).unwrap();
        let current = if runtime.native_edge.claims.release.config_sha256 == "a".repeat(64) {
            "b".repeat(64)
        } else {
            "a".repeat(64)
        };
        runtime.native_edge.claims.release.config_sha256 = current.clone();
        runtime
            .native_edge
            .claims
            .owned_publication
            .publication
            .sha256 = current;
        assert!(bind_edge_predecessor(&selected, &runtime, false).is_err());
        bind_edge_predecessor(&selected, &runtime, true).unwrap();
        for case in 0..5 {
            let mut changed = runtime.clone();
            match case {
                0 => changed.native_edge.claims.release.commit = "0".repeat(40),
                1 => {
                    changed
                        .native_edge
                        .claims
                        .owned_publication
                        .publication
                        .sha256 = "0".repeat(64)
                }
                2 => changed.native_edge.claims.owner_uid += 1,
                3 => changed.native_edge.claims.owner_gid += 1,
                _ => changed.hosts.native_edge.endpoint.hostname = "other-mac.example.org".into(),
            }
            assert!(
                bind_edge_predecessor(&selected, &changed, true).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn rolled_back_transition_requires_restored_genesis_and_exact_admitted_releases() {
        let (selected, predecessor, runtime) = lineage_fixture();
        bind_inventory_lineage(
            &selected,
            "selected",
            &predecessor,
            &runtime,
            "failed",
            true,
        )
        .unwrap();
        assert!(
            bind_inventory_lineage(&selected, "failed", &predecessor, &runtime, "failed", true)
                .is_err()
        );
        let mut wrong = predecessor.clone();
        wrong.previous_genesis_hash = "c".repeat(64);
        assert!(
            bind_inventory_lineage(&selected, "selected", &wrong, &runtime, "failed", true)
                .is_err()
        );
        let mut wrong = predecessor.clone();
        wrong.revision.commit = selected.revision.commit.clone();
        assert!(
            bind_inventory_lineage(&selected, "selected", &wrong, &runtime, "failed", true)
                .is_err()
        );
        let mut wrong_runtime = runtime.clone();
        wrong_runtime.validators[0].artifacts[0].sha256 = "d".repeat(64);
        assert!(
            bind_inventory_lineage(
                &selected,
                "selected",
                &predecessor,
                &wrong_runtime,
                "failed",
                true,
            )
            .is_err()
        );
        wrong_runtime = runtime.clone();
        wrong_runtime.native_edge.claims.release.config_sha256 = "e".repeat(64);
        assert!(
            bind_inventory_lineage(
                &selected,
                "selected",
                &predecessor,
                &wrong_runtime,
                "failed",
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn topology_producer_requires_both_inventory_digests() {
        use clap::Parser as _;

        let args = vec![
            "iroha",
            "taira",
            "public-reset",
            "prepare-topology-intent",
            "--retained-inventory",
            "/failed.json",
            "--expected-retained-inventory-sha256",
            "a",
            "--selected-inventory",
            "/restored.json",
            "--expected-selected-inventory-sha256",
            "b",
            "--selected-authorization",
            "/selected-authorization.json",
            "--current-runtime",
            "/runtime.json",
            "--expected-current-runtime-sha256",
            "c",
            "--transition-plan",
            "/plan.json",
            "--expected-plan-sha256",
            "d",
            "--import-root",
            "/import",
            "--public-inputs",
            "/public",
            "--source-manifest",
            "/source.json",
            "--known-hosts",
            "/known_hosts",
            "--validator-client-config",
            "/client1",
            "/client2",
            "/client3",
            "/client4",
            "--validator-config",
            "/config1",
            "/config2",
            "/config3",
            "/config4",
            "--initial-unit",
            "/unit1",
            "/unit2",
            "/unit3",
            "/unit4",
            "--edge-config",
            "/edge.conf",
            "--native-edge-cli",
            "/darwin/iroha",
            "--output",
            "/intent.json",
        ];
        assert!(crate::Args::try_parse_from(args.clone()).is_ok());
        let mut missing_selected = args.clone();
        missing_selected.drain(8..10);
        assert!(crate::Args::try_parse_from(missing_selected).is_err());
        let mut missing_digest = args.clone();
        missing_digest.drain(10..12);
        assert!(crate::Args::try_parse_from(missing_digest).is_err());
        let mut missing_authorization = args;
        missing_authorization.drain(12..14);
        assert!(crate::Args::try_parse_from(missing_authorization).is_err());
    }

    #[test]
    fn predecessor_lineage_refuses_a_substituted_native_mac_host() {
        let (selected, predecessor, mut runtime) = lineage_fixture();
        runtime.hosts.native_edge.endpoint.hostname = "other-mac.example.org".into();
        assert!(
            bind_inventory_lineage(
                &selected,
                "selected",
                &predecessor,
                &runtime,
                "failed",
                true,
            )
            .is_err()
        );
        let (mut selected, predecessor, runtime) = lineage_fixture();
        selected
            .hosts
            .as_object_mut()
            .unwrap()
            .get_mut("native_edge")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("owner_uid".into(), Value::from(999_u32));
        assert!(
            bind_inventory_lineage(
                &selected,
                "selected",
                &predecessor,
                &runtime,
                "failed",
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn selected_inventory_requires_its_signed_prior_authorization() {
        use iroha_crypto::{Algorithm, KeyPair, Signature};

        let fixture = reset::sample_inventory_fixture();
        let execution_lifetime_ms = reset::execution_lifetime_ms(&fixture).unwrap();
        let bytes = reset::canonical_inventory_bytes(&fixture).unwrap();
        let inventory_sha256 = sha256_hex(&bytes);
        let (selected, _guard) = reset::history::decode(&bytes, "selected fixture").unwrap();
        let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).unwrap();
        let issued_at_unix_ms = 990_000;
        let claims = reset::AuthorizationClaimsV1 {
            action: "reset_and_deploy".into(),
            qualification_scope: selected.qualification_scope,
            deployment_id: selected.deployment_id.clone(),
            inventory_sha256: inventory_sha256.clone(),
            artifact_closure_sha256: selected.artifact_closure_sha256.clone(),
            runtime_client_config_sha256: selected.runtime_client_config_sha256.clone(),
            onboarding_token_sha256: selected.onboarding_token_sha256.clone(),
            validator_client_configs_sha256: selected.validator_client_configs_sha256.clone(),
            inrou_stage_tree_sha256: selected.inrou_stage_tree_sha256.clone(),
            faucet_policy: selected.faucet_policy.clone(),
            fee_intent: selected.fee_intent.clone(),
            authorization_nonce: selected.authorization_nonce.clone(),
            issued_at_unix_ms,
            not_before_unix_ms: issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms + reset::MAX_AUTHORIZATION_LIFETIME_MS,
            execution_expires_at_unix_ms: issued_at_unix_ms + execution_lifetime_ms,
        };
        let signature = Signature::try_new(
            key.private_key(),
            &reset::authorization_message(&claims).unwrap(),
        )
        .unwrap();
        let authorization = reset::AuthorizationEnvelopeV1 {
            schema: reset::AUTHORIZATION_SCHEMA_V1.into(),
            claims,
            signature_hex: hex::encode(signature.payload()),
        };
        let trusted = reset::TrustedKeyV1 {
            schema: reset::TRUSTED_KEY_SCHEMA_V1.into(),
            algorithm: "ed25519".into(),
            public_key: key.public_key().to_string(),
        };
        reset::history::verify_authorization(
            &selected,
            &inventory_sha256,
            &authorization,
            &trusted,
        )
        .unwrap();
        assert!(
            reset::history::verify_authorization(
                &selected,
                &"0".repeat(64),
                &authorization,
                &trusted,
            )
            .is_err()
        );
        let wrong = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).unwrap();
        let untrusted = reset::TrustedKeyV1 {
            public_key: wrong.public_key().to_string(),
            ..trusted
        };
        assert!(
            reset::history::verify_authorization(
                &selected,
                &inventory_sha256,
                &authorization,
                &untrusted,
            )
            .is_err()
        );
    }

    #[test]
    fn topology_candidate_rejects_reused_or_duplicate_account_peer_and_faucet_identities() {
        let old = terminal_fixture();
        let mut clients = old.validator_clients.clone();
        for (index, client) in clients.iter_mut().enumerate() {
            client.account_id = format!("new-account-{index}");
            client.peer_id = format!("new-peer-{index}");
        }
        let mut faucet = old.faucet_policy.clone();
        faucet.authority = "new-faucet".into();
        distinct_new_clients(&old, &clients, &faucet, "new-canary").unwrap();
        clients[0].account_id = old.validator_clients[0].account_id.clone();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-canary").is_err());
        clients[0].account_id = clients[1].account_id.clone();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-canary").is_err());
        clients[0].account_id = "new-account-0".into();
        clients[0].peer_id = old.validator_clients[0].peer_id.clone();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-canary").is_err());
        clients[0].peer_id = "new-peer-0".into();
        faucet.authority = clients[0].account_id.clone();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-canary").is_err());
        faucet.authority = old.validator_clients[0].account_id.clone();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-canary").is_err());
        faucet.authority = "new-faucet".into();
        assert!(distinct_new_clients(&old, &clients, &faucet, "new-account-0").is_err());
        assert!(
            distinct_new_clients(
                &old,
                &clients,
                &faucet,
                &old.canary_onboarding_request.account_id
            )
            .is_err()
        );
    }
}

#[cfg(any(target_os = "linux", test))]
fn daemon_identity(
    path: &Path,
    release: &str,
    public: &reset::public_inputs::PublicInputsV1,
    observed: &mut Observed,
) -> Result<(String, String, FaucetPolicyV1)> {
    use iroha_config::{
        base::toml::{MAX_TOML_SOURCE_BYTES, TomlSource},
        parameters::actual,
    };
    let pin = observed.pin(path, Some(0o600), MAX_TOML_SOURCE_BYTES as u64)?;
    let bytes = zeroize::Zeroizing::new(admission::read(&pin)?);
    reset::validate_validator_genesis_config(
        &bytes,
        Path::new(&format!("{release}/genesis/genesis.json")),
        &public.genesis_hash,
    )?;
    let text = std::str::from_utf8(&bytes).wrap_err("candidate validator config is not UTF-8")?;
    let table: toml::Table =
        toml::from_str(text).wrap_err("candidate validator config is not TOML")?;
    let config = actual::Root::from_toml_source(TomlSource::new_sensitive(
        path.to_path_buf(),
        table,
        crate::soracloud::zeroize_taira_toml_table,
    ))
    .map_err(|_| eyre!("candidate validator config failed current typed admission"))?;
    need(
        config.common.chain.to_string() == CHAIN_ID,
        "candidate validator chain differs",
    )?;
    let faucet = config
        .torii
        .faucet
        .as_ref()
        .ok_or_else(|| eyre!("candidate validator faucet is absent"))?;
    let policy = FaucetPolicyV1 {
        authority: faucet.authority.to_string(),
        asset_definition_id: faucet.asset_definition_id.clone(),
        amount: faucet.amount.clone(),
    };
    reset::validate_faucet_policy(&policy)?;
    reset::validate_validator_faucet_config(&bytes, &policy)?;
    reset::inputs::validate_validator_pin_fee_asset(
        &config.gov.sorafs_pin_fee_asset_id,
        &policy.asset_definition_id,
    )?;
    let origin = format!("http://127.0.0.1:{}/", config.torii.address.value().port());
    reset::validate_candidate_probe_bind(&origin, config.torii.address.value())?;
    observed.revalidate()?;
    Ok((config.common.peer.id.to_string(), origin, policy))
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn source_revision(
    source_manifest: &Path,
    import_root: &Path,
    candidate_commit: &str,
    observed: &mut Observed,
) -> Result<RevisionV1> {
    let manifest_pin = observed.pin(source_manifest, None, MAX_PROOF)?;
    let bytes = admission::read(&manifest_pin)?;
    let source: SourceManifestV1 = json::from_slice(&bytes)?;
    let revision = RevisionV1 {
        branch: source.branch,
        commit: source.head_commit_sha1.clone(),
        tree: source.head_tree_sha1,
        cargo_lock_sha256: source.cargo_lock_sha256,
        source_root: absolute(&import_root.join("source/source"), "qualified source root")?,
        source_manifest_path: absolute(source_manifest, "native source manifest")?,
        source_manifest_sha256: sha256_hex(&bytes),
        source_closure_sha256: source.closure_sha256,
        target: BUILD_TARGET.into(),
        profile: BUILD_PROFILE.into(),
        build_id: source.head_commit_sha1,
    };
    need(
        revision.commit == candidate_commit,
        "signed source differs from qualified candidate",
    )?;
    reset::validate_revision(&revision)?;
    reset::validate_source_closure(&revision)?;
    Ok(revision)
}

impl PrepareTopologyIntent {
    /// Create a private reviewable intent without starting, deploying or signing a reset.
    pub(in super::super::super::super) fn run<W: Write>(&self, output: &mut W) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = output;
            return Err(eyre!("topology intent preparation requires Linux"));
        }
        #[cfg(target_os = "linux")]
        {
            need(rustix::process::geteuid().as_raw() == 0, "root is required")?;
            validate_absolute_normal_path(&self.output, "topology output")?;
            let parent = self
                .output
                .parent()
                .ok_or_else(|| eyre!("topology output has no parent"))?;
            reset::validate_owner_private_dir(parent, "topology output directory")?;
            need(!self.output.exists(), "topology output already exists")?;
            for hash in [
                &self.expected_retained_inventory_sha256,
                &self.expected_selected_inventory_sha256,
                &self.expected_current_runtime_sha256,
                &self.expected_plan_sha256,
            ] {
                require_lower_sha256(hash, "topology producer input digest")?;
            }
            for paths in [
                &self.validator_client_config,
                &self.validator_config,
                &self.initial_unit,
            ] {
                need(paths.len() == 4, "four ordered candidate inputs required")?;
                let unique: BTreeSet<&PathBuf> = paths.iter().collect();
                need(unique.len() == 4, "candidate input paths must be distinct")?;
            }
            let mut observed = Observed(Vec::new());
            let plan_pin = observed.pin(&self.transition_plan, Some(0o600), MAX_PROOF)?;
            need(
                plan_pin.sha256 == self.expected_plan_sha256,
                "transition plan digest differs",
            )?;
            let plan_bytes = admission::read(&plan_pin)?;
            let plan: Plan = json::from_slice(&plan_bytes)?;
            admission::validate_plan(&plan)?;
            need(
                self.import_root.as_path()
                    == Path::new(&plan.candidate.executable.path)
                        .parent()
                        .ok_or_else(|| eyre!("candidate executable has no parent"))?
                        .parent()
                        .ok_or_else(|| eyre!("candidate binary has no import root"))?
                        .parent()
                        .ok_or_else(|| eyre!("candidate artifact has no import root"))?
                    && plan.candidate.preparation.path
                        == self
                            .import_root
                            .join("preparation/result.json")
                            .to_string_lossy()
                            .as_ref(),
                "qualified import root differs from reviewed transition plan",
            )?;
            let locks = admission::locks(&plan)?;
            let inventory_pin = observed.pin(&self.retained_inventory, None, MAX_PROOF)?;
            need(
                inventory_pin.sha256 == self.expected_retained_inventory_sha256
                    && inventory_pin.sha256 == plan.predecessor.inventory_sha256,
                "retained inventory digest differs from transition plan",
            )?;
            let inventory_bytes = admission::read(&inventory_pin)?;
            let (predecessor, _chain_guard) =
                reset::history::decode(&inventory_bytes, "retained inventory")?;
            let selected_pin = observed.pin(&self.selected_inventory, None, MAX_PROOF)?;
            need(
                selected_pin.sha256 == self.expected_selected_inventory_sha256,
                "selected inventory digest differs",
            )?;
            let (old, _selected_chain_guard) =
                reset::history::decode(&admission::read(&selected_pin)?, "selected inventory")?;
            let selected_authorization_pin =
                observed.pin(&self.selected_authorization, Some(0o600), MAX_PROOF)?;
            let selected_authorization: reset::AuthorizationEnvelopeV1 =
                json::from_slice(&admission::read(&selected_authorization_pin)?)?;
            let trusted: reset::TrustedKeyV1 =
                json::from_slice(&admission::read(&plan.trusted_public_key)?)?;
            reset::history::verify_authorization(
                &old,
                &selected_pin.sha256,
                &selected_authorization,
                &trusted,
            )
            .wrap_err("selected inventory lacks a signed prior authorization")?;
            let runtime_pin = observed.pin(&self.current_runtime, Some(0o600), MAX_PROOF)?;
            need(
                runtime_pin.sha256 == self.expected_current_runtime_sha256,
                "stopped runtime digest differs",
            )?;
            let runtime: CurrentRuntime = json::from_slice(&admission::read(&runtime_pin)?)?;
            validate_runtime(&runtime)?;
            bind_selected_inventory(&old, &selected_pin.sha256, &predecessor, &runtime, &plan)?;
            let held = admission::admit(&plan)?;
            let operation = operation_root(&plan);
            let guards = admission::new_guards(&plan, &operation)?;
            storage::check_applied(&plan, &plan_bytes, &operation, &guards)?;
            let revision = source_revision(
                &self.source_manifest,
                &self.import_root,
                &plan.candidate.commit,
                &mut observed,
            )?;
            plan.candidate.native_edge_candidate.verify(
                &plan.hosts,
                &revision.commit,
                &revision.tree,
                &revision.cargo_lock_sha256,
                &revision.source_closure_sha256,
                &trusted,
            )?;
            let public = reset::public_inputs::load(&self.public_inputs)?;
            need(
                old.next_genesis_hash != public.genesis_hash,
                "fresh public genesis must differ from completed predecessor",
            )?;
            let mut intent = old.topology_intent(&plan.hosts)?;
            intent.hosts = plan.hosts.clone();
            intent.hosts.validator_guest.dispatcher_sha256 =
                plan.candidate.executable.sha256.clone();
            intent.hosts.validator_guest.guard_sha256 = sha256_hex(&guards[0]);
            intent.deployment_id = format!("taira-public-{}-", &revision.commit[..8]);
            let mut nonce = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|error| eyre!("topology nonce OS RNG failed: {error}"))?;
            intent.authorization_nonce = hex::encode(nonce);
            intent
                .deployment_id
                .push_str(&intent.authorization_nonce[..8]);
            intent.previous_genesis_hash = old.next_genesis_hash.clone();
            intent.revision.source_root = revision.source_root.clone();
            intent.revision.source_manifest_path = revision.source_manifest_path.clone();
            intent.canary_onboarding_request = public.canary_onboarding_request.clone();
            intent.fee_intent = FeeIntentV1 {
                payer: "authority".into(),
                sponsor_program: None,
                sponsor_program_revision: None,
            };
            let import_bins = self.import_root.join("artifacts/bin");
            for name in ["iroha3d_taira", "iroha", "kagami", "sorafs-node"] {
                observed.pin(&import_bins.join(name), Some(0o755), MAX_BINARY)?;
            }
            let mut clients = Vec::new();
            let mut policy: Option<FaucetPolicyV1> = None;
            for index in 0..4 {
                let slug = SLUGS[index];
                let release = format!("/srv/taira/{slug}/releases/{}", revision.commit);
                let client_observed =
                    observed.pin(&self.validator_client_config[index], Some(0o600), MAX_PROOF)?;
                let client_pinned = reset::pin_owner_private_file(
                    &self.validator_client_config[index],
                    "candidate validator client",
                )?;
                need(
                    reset::host::hash_pinned_input(
                        &client_pinned,
                        "candidate validator client",
                        None,
                    )? == client_observed.sha256,
                    "candidate validator client changed between custody and typed admission",
                )?;
                let client = reset::host::load_client_config_for_reset_genesis(
                    &client_pinned,
                    "candidate validator client",
                    &public.genesis_hash,
                )?;
                let origin = candidate_client_origin(
                    client.torii_api_url.as_str(),
                    &old.validator_clients[index].torii_origin,
                    plan.predecessor.unresolved_journal.is_some(),
                )?;
                let (peer_id, probe_origin, current_policy) = daemon_identity(
                    &self.validator_config[index],
                    &release,
                    &public,
                    &mut observed,
                )?;
                need(
                    probe_origin == old.validator_clients[index].probe_origin,
                    "candidate probe origin differs from retained topology and daemon bind",
                )?;
                if let Some(expected) = &policy {
                    need(
                        *expected == current_policy,
                        "candidate validator faucet policies differ",
                    )?;
                } else {
                    policy = Some(current_policy);
                }
                clients.push(ValidatorClientV1 {
                    slug: slug.into(),
                    torii_origin: origin,
                    probe_origin,
                    account_id: client.account.to_string(),
                    peer_id,
                });
                let unit = &self.initial_unit[index];
                need(
                    unit.file_name()
                        == Some(std::ffi::OsStr::new(&format!("iroha3d-{slug}.service"))),
                    "candidate initial validator unit order differs",
                )?;
                observed.pin(unit, Some(0o644), MAX_PROOF)?;
                let validator = &mut intent.validators[index];
                validator.endpoint.remote_cli = format!("{release}/bin/iroha");
                validator.endpoint.upload_guard_sha256 = sha256_hex(&guards[index]);
                validator.initial_state =
                    ValidatorInitialStateV1::AdmittedRelease(runtime.validators[index].clone());
                validator.artifacts = vec![
                    artifact(
                        "iroha3d",
                        &import_bins.join("iroha3d_taira"),
                        format!("{release}/bin/iroha3d_taira"),
                    )?,
                    artifact(
                        "iroha_cli",
                        &import_bins.join("iroha"),
                        format!("{release}/bin/iroha"),
                    )?,
                    artifact(
                        "kagami",
                        &import_bins.join("kagami"),
                        format!("{release}/bin/kagami"),
                    )?,
                    artifact(
                        "sorafs_node",
                        &import_bins.join("sorafs-node"),
                        format!("{release}/bin/sorafs-node"),
                    )?,
                    artifact(
                        "config",
                        &self.validator_config[index],
                        format!("{release}/config/config.toml"),
                    )?,
                    artifact(
                        "genesis",
                        &self.public_inputs.join("genesis.signed.nrt"),
                        format!("{release}/genesis/genesis.json"),
                    )?,
                    artifact(
                        "genesis_hash",
                        &self.public_inputs.join("genesis.hash"),
                        format!("{release}/genesis/genesis.sha256"),
                    )?,
                    artifact(
                        "validator_unit",
                        unit,
                        format!("{release}/systemd/iroha3d-{slug}.service"),
                    )?,
                ];
            }
            let policy = policy.ok_or_else(|| eyre!("candidate faucet policy is absent"))?;
            distinct_new_clients(
                &old,
                &clients,
                &policy,
                &public.canary_onboarding_request.account_id,
            )?;
            if plan.predecessor.rolled_back {
                distinct_new_clients(
                    &predecessor,
                    &clients,
                    &policy,
                    &public.canary_onboarding_request.account_id,
                )?;
            }
            intent.validator_clients = clients;
            intent.faucet_policy = policy;
            observed.pin(&self.edge_config, Some(0o640), MAX_PROOF)?;
            let native_cli = observed.pin(&self.native_edge_cli, Some(0o755), MAX_BINARY)?;
            let signed_cli = &plan.candidate.native_edge_candidate.claims.iroha_cli;
            need(
                native_cli.path == signed_cli.local_path
                    && native_cli.sha256 == signed_cli.sha256
                    && native_cli.size == signed_cli.size
                    && native_cli.mode == u32::from(signed_cli.mode),
                "topology Darwin artifact copy differs from the independently signed native candidate",
            )?;
            let edge_release = format!(
                "{}/.local/share/iroha/taira/edge/releases/{}",
                intent.hosts.native_edge.owner_home, revision.commit,
            );
            intent.edge.platform = intent.hosts.native_edge.platform.clone();
            intent.edge.endpoint.remote_cli = signed_cli.remote_path.clone();
            intent.edge.endpoint.upload_guard_sha256 = plan
                .candidate
                .native_edge_candidate
                .claims
                .native_guard
                .sha256
                .clone();
            intent.edge.initial_state =
                EdgeInitialStateV1::AdmittedRelease(runtime.native_edge.claims.release.clone());
            intent.edge.artifacts = vec![
                artifact(
                    "iroha_cli",
                    &self.native_edge_cli,
                    signed_cli.remote_path.clone(),
                )?,
                artifact(
                    "edge_config",
                    &self.edge_config,
                    format!("{edge_release}/taira.conf"),
                )?,
            ];
            let endpoints = intent
                .validators
                .iter()
                .map(|v| &v.endpoint)
                .chain(std::iter::once(&intent.edge.endpoint))
                .collect::<Vec<_>>();
            let known_hosts = reset::validate_known_host_endpoints(&endpoints, &self.known_hosts)?;
            reset::inputs::validate_topology_intent(&intent)?;
            let mut bytes = json::to_vec(&intent)?;
            bytes.push(b'\n');
            let (decoded, _guard) = reset::inputs::decode_reset_topology_intent(&bytes)?;
            need(
                json::to_vec(&decoded)? == json::to_vec(&intent)?,
                "topology intent roundtrip differs",
            )?;
            observed.revalidate()?;
            reset::revalidate_pinned(&known_hosts, "topology known-hosts")?;
            locks.revalidate()?;
            admission::revalidate(&plan, &held)?;
            storage::check_applied(&plan, &plan_bytes, &operation, &guards)?;
            need(
                reset::public_inputs::load(&self.public_inputs)? == public,
                "public input bundle changed",
            )?;
            reset::inputs::write_new_private(&self.output, &bytes)?;
            writeln!(
                output,
                "{}",
                json::to_json(&norito::json!({
                    "schema": "iroha.taira.public-reset.topology-intent-prepared.v1",
                    "path": (absolute(&self.output, "topology output")?),
                    "sha256": (sha256_hex(&bytes)),
                    "deployment_id": (intent.deployment_id),
                    "retained_inventory_sha256": (inventory_pin.sha256),
                    "selected_inventory_sha256": (selected_pin.sha256),
                    "selected_authorization_sha256": (selected_authorization_pin.sha256),
                    "rolled_back_predecessor": (plan.predecessor.rolled_back),
                    "previous_genesis_hash": (intent.previous_genesis_hash),
                    "next_genesis_hash": (public.genesis_hash),
                    "ledger_mutated": false,
                }))?
            )?;
            Ok(())
        }
    }
}
