//! Native plan producer: qualified import plus explicit current typed occupied bindings.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
#[cfg(any(target_os = "linux", test))]
use super::super::super::{
    ValidatorAdmittedReleaseV1,
    host_pair::{ResetHostPairV1, SignedNativeEdgeCaptureV1},
};
use super::*;

#[path = "taira_public_reset_dispatcher_runtime_capture.rs"]
pub(in super::super::super) mod capture;
#[path = "taira_public_reset_topology_intent_prepare.rs"]
pub(in super::super::super) mod topology;

/// Derive a transition plan without replacing controllers, services, or ledger state.
#[derive(clap::Args, Debug)]
pub(in super::super::super) struct PrepareDispatcherTransition {
    #[arg(long)]
    import_root: PathBuf,
    #[arg(long)]
    expected_result_sha256: String,
    /// Owner-signed Darwin artifact and prepared native Mac guard authorization.
    #[arg(long)]
    native_edge_candidate: PathBuf,
    #[arg(long)]
    expected_native_edge_candidate_sha256: String,
    /// Retained public copy of the Darwin CLI; this command never executes it.
    #[arg(long)]
    native_edge_cli: PathBuf,
    #[arg(long)]
    source_manifest: PathBuf,
    #[arg(long)]
    retained_inventory: PathBuf,
    #[arg(long)]
    expected_retained_inventory_sha256: String,
    /// The current host lease belongs to a terminally rolled-back occupied reset.
    /// This admits a new signed candidate without reusing the failed authorization.
    #[arg(long)]
    terminal_rolled_back: bool,
    /// Supersede a deployment-proven predecessor whose seal bookkeeping is unfinished.
    /// Preserve its original journal; require sealed guest custody and stopped runtime.
    #[arg(long, conflicts_with = "terminal_rolled_back")]
    deployment_proven_predecessor: bool,
    #[arg(long)]
    current_runtime: PathBuf,
    #[arg(long)]
    expected_current_runtime_sha256: String,
    #[arg(long)]
    trusted_public_key: PathBuf,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    output: PathBuf,
}

/// Existing current-type occupied bindings; their executable source may differ from configuration.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct CurrentRuntime {
    schema: String,
    host_identity_sha256: String,
    hosts: ResetHostPairV1,
    validators: Vec<ValidatorAdmittedReleaseV1>,
    native_edge: SignedNativeEdgeCaptureV1,
}
#[cfg(any(target_os = "linux", test))]
struct Observed(Vec<(Pin, File, super::super::super::FileSnapshot)>);
#[cfg(any(target_os = "linux", test))]
impl Observed {
    #[cfg(any(target_os = "linux", test))]
    fn pin(&mut self, path: &Path, mode: Option<u32>, maximum: u64) -> Result<Pin> {
        validate_absolute_normal_path(path, "plan producer input")?;
        require_root_no_symlink_ancestors(path, "plan producer input")?;
        let (mut file, snapshot) = open_pinned_regular(path, "plan producer input")?;
        need(
            snapshot.uid == 0
                && snapshot.len > 0
                && snapshot.len <= maximum
                && snapshot.mode & 0o022 == 0
                && mode.is_none_or(|mode| snapshot.mode & 0o7777 == mode),
            "plan producer input custody differs",
        )?;
        let value = Pin {
            path: path.to_string_lossy().into_owned(),
            sha256: hash_reader(&mut file)?,
            size: snapshot.len,
            mode: snapshot.mode & 0o7777,
        };
        ensure_pinned_unchanged(path, "plan producer input", &file, &snapshot)?;
        self.0.push((value.clone(), file, snapshot));
        Ok(value)
    }
    #[cfg(any(target_os = "linux", test))]
    fn revalidate(&self) -> Result<()> {
        for (pin, file, snapshot) in &self.0 {
            require_root_no_symlink_ancestors(Path::new(&pin.path), "plan producer input")?;
            ensure_pinned_unchanged(Path::new(&pin.path), "plan producer input", file, snapshot)?;
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", test))]
fn text<'a>(record: &'a Value, field: &str) -> Result<&'a str> {
    record
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("missing producer {field}"))
}
#[cfg(any(target_os = "linux", test))]
fn candidate(
    command: &PrepareDispatcherTransition,
    hosts: &ResetHostPairV1,
    trusted: &super::super::super::TrustedKeyV1,
    observed: &mut Observed,
) -> Result<Candidate> {
    let import = &command.import_root;
    let expected = &command.expected_result_sha256;
    let proof = import.join("preparation");
    let preparation = observed.pin(&proof.join("result.json"), Some(0o400), 16 * 1024 * 1024)?;
    need(
        &preparation.sha256 == expected,
        "qualified result digest differs",
    )?;
    let value: Value = json::from_slice(&admission::read(&preparation)?)?;
    let native_pin = observed.pin(&command.native_edge_candidate, None, 16 * 1024)?;
    need(
        native_pin.sha256 == command.expected_native_edge_candidate_sha256,
        "native Darwin candidate envelope public pin differs",
    )?;
    let native_edge_candidate: super::super::super::host_pair::SignedNativeEdgeCandidateV1 =
        json::from_slice(&admission::read(&native_pin)?)?;
    let source = topology::source_revision(
        &command.source_manifest,
        import,
        text(&value, "commit")?,
        observed,
    )?;
    need(
        source.tree == text(&value, "tree")?,
        "native signed source tree differs from the qualified guest candidate",
    )?;
    native_edge_candidate.verify(
        hosts,
        text(&value, "commit")?,
        text(&value, "tree")?,
        &source.cargo_lock_sha256,
        &source.source_closure_sha256,
        trusted,
    )?;
    let native_cli = observed.pin(&command.native_edge_cli, Some(0o755), MAX_BINARY)?;
    let signed_cli = &native_edge_candidate.claims.iroha_cli;
    need(
        native_cli.path == signed_cli.local_path
            && native_cli.sha256 == signed_cli.sha256
            && native_cli.size == signed_cli.size
            && native_cli.mode == u32::from(signed_cli.mode),
        "retained Darwin artifact copy differs from its independently signed native candidate",
    )?;
    let candidate = Candidate {
        commit: text(&value, "commit")?.into(),
        tree: text(&value, "tree")?.into(),
        revision: source,
        signer_fingerprint: text(&value, "signer_fingerprint")?.into(),
        executable: observed.pin(&import.join("artifacts/bin/iroha"), Some(0o755), MAX_BINARY)?,
        native_edge_candidate,
        preparation,
        request: observed.pin(&proof.join("request.json"), Some(0o400), 16 * 1024 * 1024)?,
        checks: observed.pin(&proof.join("checks.json"), Some(0o400), 16 * 1024 * 1024)?,
        capture: observed.pin(&proof.join("capture.json"), Some(0o400), 16 * 1024 * 1024)?,
        transfer_request: observed.pin(
            &import.join("request.json"),
            Some(0o400),
            16 * 1024 * 1024,
        )?,
        transfer_completed: observed.pin(
            &import.join("completed.json"),
            Some(0o400),
            16 * 1024 * 1024,
        )?,
        binary_transfer: observed.pin(
            &import.join("artifacts/verified-manifest.json"),
            Some(0o400),
            16 * 1024 * 1024,
        )?,
        source_transfer: observed.pin(
            &import.join("source/verified-manifest.json"),
            Some(0o400),
            16 * 1024 * 1024,
        )?,
    };
    need(
        import
            == Path::new(&format!(
                "{RUNTIME}/release-import-{}-{expected}",
                candidate.commit
            )),
        "exact qualified import root required",
    )?;
    Ok(candidate)
}
#[cfg(any(target_os = "linux", test))]
pub(super) fn validate_runtime(runtime: &CurrentRuntime) -> Result<()> {
    need(
        runtime.schema == "iroha.taira.dispatcher-current-runtime.v1"
            && runtime.validators.len() == 4,
        "current typed runtime with four ordered validators required",
    )?;
    require_lower_sha256(&runtime.host_identity_sha256, "host identity")?;
    runtime.hosts.validate()?;
    need(
        runtime.host_identity_sha256 == runtime.hosts.validator_guest.endpoint.host_identity_sha256,
        "runtime identity must bind the admitted Linux guest",
    )?;
    for (index, prior) in runtime.validators.iter().enumerate() {
        let slug = SLUGS[index];
        let service = format!("/srv/taira/{slug}");
        validate_lower_hex("current configuration revision", &prior.commit, 40)?;
        need(
            prior.release_root == format!("{service}/releases/{}", prior.commit)
                && prior.service_state.stopped_state().is_some(),
            "exact stopped configuration binding required",
        )?;
        occupied::validate_prior_binding(prior, &service, &format!("iroha3d-{slug}.service"))?;
    }
    let claims = &runtime.native_edge.claims;
    runtime.native_edge.verify(
        &runtime.hosts,
        &claims.retained_inventory_sha256,
        &claims.authorization_sha256,
        &claims.authorization_nonce,
        &claims.next_genesis_hash,
    )
}
#[cfg(any(target_os = "linux", test))]
fn selected_role(slug: &str, release: &str, files: Vec<Pin>) -> Result<OccupiedRole> {
    need(
        SLUGS.contains(&slug),
        "guest runtime role must be a validator",
    )?;
    let state = format!("/var/lib/taira/{slug}");
    require_root_directory(Path::new(&state), true, "preserved state")?;
    let state_meta = fs::symlink_metadata(&state)?;
    let current = format!("/srv/taira/{slug}/current");
    require_root_no_symlink_ancestors(Path::new(&current), "preserved selector")?;
    let meta = fs::symlink_metadata(&current)?;
    need(
        meta.file_type().is_symlink()
            && meta.uid() == 0
            && fs::read_link(&current)? == Path::new(release),
        "selected runtime differs from current selector",
    )?;
    Ok(OccupiedRole {
        slug: slug.into(),
        state: DirectoryIdentity {
            path: state,
            device: state_meta.dev(),
            inode: state_meta.ino(),
        },
        selector: Selector {
            path: current,
            target: release.into(),
            device: meta.dev(),
            inode: meta.ino(),
        },
        files,
    })
}
#[cfg(any(target_os = "linux", test))]
fn runtime_roles(runtime: &CurrentRuntime, observed: &mut Observed) -> Result<Vec<OccupiedRole>> {
    validate_runtime(runtime)?;
    let mut roles = Vec::new();
    for (index, prior) in runtime.validators.iter().enumerate() {
        let mut files = Vec::new();
        for artifact in &prior.artifacts {
            let pin = observed.pin(
                Path::new(&artifact.path),
                Some(u32::from(artifact.mode)),
                MAX_BINARY,
            )?;
            need(
                pin.sha256 == artifact.sha256 && pin.size == artifact.size,
                "current artifact differs from selected binding",
            )?;
            files.push(pin);
        }
        let role = selected_role(SLUGS[index], &prior.release_root, files)?;
        prior
            .service_state
            .validate_state_identity(role.state.device, role.state.inode)?;
        roles.push(role);
    }
    Ok(roles)
}

#[cfg(any(target_os = "linux", test))]
fn validate_rolled_back_inventory(
    bytes: &[u8],
    runtime: &CurrentRuntime,
    plan: &Plan,
) -> Result<()> {
    let (inventory, _chain_guard) =
        super::super::super::history::decode(bytes, "rolled-back inventory")?;
    let predecessor = &plan.predecessor;
    need(
        inventory.schema == super::super::super::INVENTORY_SCHEMA_V1
            && inventory.validators.len() == 4
            && inventory.authorization_nonce == predecessor.authorization_nonce
            && inventory.revision.commit != plan.candidate.commit,
        "rolled-back inventory identity differs",
    )?;
    let terminal: Value = json::from_slice(&admission::read(&predecessor.completed)?)?;
    need(
        terminal.get("deployment_id").and_then(Value::as_str)
            == Some(inventory.deployment_id.as_str())
            && terminal.get("qualification_scope")
                == Some(&json::to_value(&inventory.qualification_scope)?),
        "rolled-back terminal is not the retained execution",
    )?;
    for (index, row) in inventory.validators.iter().enumerate() {
        need(
            row.slug == SLUGS[index]
                && row.endpoint.upload_guard_sha256 == predecessor.guards[index].sha256
                && json::to_vec(row.admitted_release()?)?
                    == json::to_vec(&runtime.validators[index])?,
            "rolled-back validator is not the restored stopped release",
        )?;
    }
    inventory.validate_physical_binding(&runtime.hosts)?;
    need(
        inventory.edge.slug == "taira-edge"
            && json::to_vec(inventory.edge.admitted_release()?)?
                == json::to_vec(&runtime.native_edge.claims.release)?,
        "rolled-back native edge is not the restored selected release",
    )
}
impl PrepareDispatcherTransition {
    /// Produce private reviewable input from current typed records; never apply it.
    pub(in super::super::super) fn run<W: Write>(&self, output: &mut W) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = output;
            return Err(eyre!("dispatcher preparation requires Linux"));
        }
        #[cfg(target_os = "linux")]
        {
            need(rustix::process::geteuid().as_raw() == 0, "root is required")?;
            validate_lower_hex("operation ID", &self.operation_id, 32)?;
            for hash in [
                &self.expected_result_sha256,
                &self.expected_retained_inventory_sha256,
                &self.expected_current_runtime_sha256,
                &self.expected_native_edge_candidate_sha256,
            ] {
                require_lower_sha256(hash, "producer input digest")?;
            }
            let mut observed = Observed(Vec::new());
            let input = observed.pin(&self.current_runtime, Some(0o600), 16 * 1024 * 1024)?;
            need(
                input.sha256 == self.expected_current_runtime_sha256,
                "runtime input digest differs",
            )?;
            let runtime: CurrentRuntime = json::from_slice(&admission::read(&input)?)?;
            validate_runtime(&runtime)?;
            let coordination = Path::new(CONTROL)
                .join("hosts")
                .join(&runtime.host_identity_sha256);
            // Acquire exactly the same existing locks before observing mutable predecessor files.
            let locks = admission::locks_for_host(&runtime.host_identity_sha256)?;
            let inventory = observed.pin(&self.retained_inventory, None, 16 * 1024 * 1024)?;
            need(
                inventory.sha256 == self.expected_retained_inventory_sha256,
                "retained inventory digest differs",
            )?;
            let retained_inventory_bytes = admission::read(&inventory)?;
            let (retained_inventory, _chain_guard) = super::super::super::history::decode(
                &retained_inventory_bytes,
                "transition retained inventory",
            )?;
            retained_inventory.validate_physical_binding(&runtime.hosts)?;
            let lease_pin = observed.pin(
                &coordination.join("lease.json"),
                Some(0o600),
                16 * 1024 * 1024,
            )?;
            let lease: HostLeaseV1 = json::from_slice(&admission::read(&lease_pin)?)?;
            need(
                lease.inventory_sha256 == inventory.sha256,
                "sealed lease does not bind selected retained inventory",
            )?;
            runtime.native_edge.verify(
                &runtime.hosts,
                &inventory.sha256,
                &lease.authorization_semantic_sha256,
                &lease.authorization_nonce,
                &retained_inventory.next_genesis_hash,
            )?;
            let progress_pin = observed.pin(
                &coordination.join("progress.json"),
                Some(0o600),
                16 * 1024 * 1024,
            )?;
            let progress: HostProgressV1 = json::from_slice(&admission::read(&progress_pin)?)?;
            require_lower_sha256(&lease.authorization_semantic_sha256, "sealed authorization")?;
            let terminal_dir = if self.terminal_rolled_back {
                "rolled-back"
            } else if self.deployment_proven_predecessor {
                "deployment-proven"
            } else {
                "completed"
            };
            let terminal_pin = observed.pin(
                &Path::new(RUNTIME)
                    .join("journal-v1")
                    .join(terminal_dir)
                    .join(format!("{}.json", lease.authorization_semantic_sha256)),
                Some(0o600),
                16 * 1024 * 1024,
            )?;
            let terminal: Value = json::from_slice(&admission::read(&terminal_pin)?)?;
            let unresolved_journal = if self.deployment_proven_predecessor {
                let deployment_id = terminal
                    .get("deployment_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| eyre!("deployment-proven ID missing"))?;
                super::super::super::validate_slug("deployment ID", deployment_id)?;
                Some(
                    observed.pin(
                        &Path::new(RUNTIME)
                            .join("journal-v1")
                            .join(format!("{deployment_id}.journal.json")),
                        Some(0o600),
                        16 * 1024 * 1024,
                    )?,
                )
            } else {
                None
            };
            let completed_next_step = u16::try_from(
                terminal
                    .get("next_step")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| eyre!("terminal next_step missing"))?,
            )?;
            let mut guards = Vec::new();
            for slug in SLUGS {
                guards.push(observed.pin(
                    &Path::new(CONTROL).join(slug).join("guard.json"),
                    Some(0o600),
                    16 * 1024 * 1024,
                )?);
            }
            let trusted_public_key = observed.pin(&self.trusted_public_key, None, 16 * 1024)?;
            let trusted: super::super::super::TrustedKeyV1 =
                json::from_slice(&admission::read(&trusted_public_key)?)?;
            let plan = Plan {
                schema: SCHEMA.into(),
                operation_id: self.operation_id.clone(),
                host_identity_sha256: runtime.host_identity_sha256.clone(),
                hosts: runtime.hosts.clone(),
                trusted_public_key,
                candidate: candidate(self, &runtime.hosts, &trusted, &mut observed)?,
                predecessor: Predecessor {
                    inventory_sha256: inventory.sha256,
                    authorization_sha256: lease.authorization_semantic_sha256,
                    authorization_nonce: lease.authorization_nonce,
                    native_edge_capture: runtime.native_edge.clone(),
                    rolled_back: self.terminal_rolled_back,
                    unresolved_journal,
                    completed_next_step,
                    sealed_forward_ordinal: progress.next_forward_ordinal,
                    completed: terminal_pin,
                    lease: lease_pin,
                    progress: progress_pin,
                    dispatcher: observed.pin(
                        Path::new(FIXED_DISPATCHER),
                        Some(0o755),
                        MAX_BINARY,
                    )?,
                    guards,
                    occupied: runtime_roles(&runtime, &mut observed)?,
                },
            };
            if self.terminal_rolled_back {
                validate_rolled_back_inventory(&retained_inventory_bytes, &runtime, &plan)?;
            }
            admission::validate_plan(&plan)?;
            let held = admission::admit(&plan)?;
            let new_guards = admission::new_guards(&plan, &operation_root(&plan))?;
            let bytes = json::to_vec(&plan)?;
            storage::check(&plan, &bytes, &operation_root(&plan), &new_guards)?;
            locks.revalidate()?;
            observed.revalidate()?;
            admission::revalidate(&plan, &held)?;
            require_root_no_symlink_ancestors(&self.output, "transition plan output")?;
            super::super::super::inputs::write_new_private(&self.output, &bytes)?;
            writeln!(
                output,
                "{}",
                json::to_json(&norito::json!({
                    "schema": "iroha.taira.dispatcher-transition-prepared.v1",
                    "plan_path": (self.output.to_string_lossy().as_ref()),
                    "plan_sha256": (sha256_hex(&bytes)),
                    "operation_id": (plan.operation_id),
                    "controller_mutated": false,
                    "ledger_mutated": false,
                }))?
            )?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taira_public_reset as reset;

    #[test]
    fn deployment_proven_selection_is_explicit_and_conflicts_with_rollback() {
        use clap::Parser as _;
        let mut args = vec![
            "iroha",
            "taira",
            "public-reset",
            "prepare-dispatcher-transition",
        ];
        for flag in [
            "--import-root",
            "--expected-result-sha256",
            "--native-edge-candidate",
            "--expected-native-edge-candidate-sha256",
            "--native-edge-cli",
            "--source-manifest",
            "--retained-inventory",
            "--expected-retained-inventory-sha256",
            "--current-runtime",
            "--expected-current-runtime-sha256",
            "--trusted-public-key",
            "--operation-id",
            "--output",
        ] {
            args.extend([flag, "/selected"]);
        }
        assert!(crate::Args::try_parse_from(args.clone()).is_ok());
        args.push("--deployment-proven-predecessor");
        assert!(crate::Args::try_parse_from(args.clone()).is_ok());
        args.push("--terminal-rolled-back");
        assert!(crate::Args::try_parse_from(args).is_err());
    }

    fn runtime_fixture() -> CurrentRuntime {
        let inventory = reset::sample_inventory_fixture();
        let hosts = inventory.hosts.clone();
        let validators = inventory
            .validators
            .iter()
            .map(|validator| {
                let mut release = validator.admitted_release().unwrap().clone();
                release.service_state =
                    reset::PriorValidatorServiceStateV1::Stopped(reset::StoppedValidatorStateV1 {
                        device: 1,
                        inode: 2,
                    });
                release
            })
            .collect();
        let mut release = inventory.edge.admitted_release().unwrap().clone();
        release.release_root = format!(
            "{}/.local/share/iroha/taira/edge/releases/{}",
            hosts.native_edge.owner_home, release.commit,
        );
        let native_edge = reset::host_pair::fixture_native_edge_capture(
            &hosts,
            release,
            &"a".repeat(64),
            &"b".repeat(64),
            &inventory.authorization_nonce,
            &inventory.next_genesis_hash,
        );
        CurrentRuntime {
            schema: "iroha.taira.dispatcher-current-runtime.v1".into(),
            host_identity_sha256: hosts.validator_guest.endpoint.host_identity_sha256.clone(),
            hosts,
            validators,
            native_edge,
        }
    }

    #[test]
    fn runtime_requires_four_stopped_guest_roles_and_a_signed_native_mac_capture() {
        let runtime = runtime_fixture();
        validate_runtime(&runtime).unwrap();
        let bytes = json::to_vec(&runtime).unwrap();
        let roundtrip: CurrentRuntime = json::from_slice(&bytes).unwrap();
        validate_runtime(&roundtrip).unwrap();
        for mutation in 0..5 {
            let mut changed = runtime.clone();
            match mutation {
                0 => changed.validators.push(changed.validators[0].clone()),
                1 => {
                    changed.host_identity_sha256 = changed
                        .hosts
                        .native_edge
                        .endpoint
                        .host_identity_sha256
                        .clone()
                }
                2 => changed.native_edge.claims.release.config_sha256 = "e".repeat(64),
                3 => {
                    changed.native_edge.claims.host_identity_sha256 =
                        changed.host_identity_sha256.clone()
                }
                _ => changed.native_edge.signature_hex = "0".repeat(128),
            }
            assert!(validate_runtime(&changed).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn runtime_refuses_retired_unsigned_guest_edge_layout() {
        let runtime = runtime_fixture();
        let mut record = json::to_value(&runtime).unwrap();
        let object = record.as_object_mut().unwrap();
        object.remove("native_edge");
        object.insert(
            "edge".into(),
            json::to_value(&runtime.native_edge.claims.release).unwrap(),
        );
        assert!(json::from_value::<CurrentRuntime>(record).is_err());
    }

    #[test]
    fn transition_producer_requires_owner_signed_darwin_candidate_and_explicit_copy() {
        use clap::Parser as _;
        let arguments = vec![
            "iroha",
            "taira",
            "public-reset",
            "prepare-dispatcher-transition",
            "--import-root",
            "/import",
            "--expected-result-sha256",
            "result",
            "--retained-inventory",
            "/inventory",
            "--expected-retained-inventory-sha256",
            "inventory",
            "--current-runtime",
            "/runtime",
            "--expected-current-runtime-sha256",
            "runtime",
            "--trusted-public-key",
            "/trusted",
            "--operation-id",
            "operation",
            "--native-edge-candidate",
            "/native-candidate",
            "--expected-native-edge-candidate-sha256",
            "native",
            "--native-edge-cli",
            "/darwin/iroha",
            "--source-manifest",
            "/source-manifest",
            "--output",
            "/plan",
        ];
        assert!(crate::Args::try_parse_from(arguments.clone()).is_ok());
        for required in [
            "--native-edge-candidate",
            "--expected-native-edge-candidate-sha256",
            "--native-edge-cli",
            "--source-manifest",
        ] {
            let mut missing = arguments.clone();
            let index = missing.iter().position(|value| *value == required).unwrap();
            missing.drain(index..index + 2);
            assert!(crate::Args::try_parse_from(missing).is_err(), "{required}");
        }
    }
}
