//! Closed candidate/predecessor admission and read-only runtime custody.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
use super::super::super::FileSnapshot;
use super::*;
use std::io::Seek as _;
#[path = "taira_public_reset_dispatcher_transition_qualification.rs"]
pub(super) mod qualification;

pub(super) struct Held {
    files: Vec<(Pin, File, FileSnapshot)>,
}
fn pin(value: &Pin, maximum: u64) -> Result<(File, FileSnapshot)> {
    validate_absolute_normal_path(Path::new(&value.path), "transition pin")?;
    require_lower_sha256(&value.sha256, "transition pin digest")?;
    need(
        value.size > 0 && value.size <= maximum,
        "input size exceeds bound",
    )?;
    require_root_no_symlink_ancestors(Path::new(&value.path), "transition input")?;
    let (mut file, snapshot) = open_pinned_regular(Path::new(&value.path), "transition input")?;
    need(
        snapshot.uid == 0 && snapshot.mode & 0o7777 == value.mode && snapshot.len == value.size,
        "input custody or size differs",
    )?;
    need(
        hash_reader(&mut file)? == value.sha256,
        "input digest differs",
    )?;
    ensure_pinned_unchanged(Path::new(&value.path), "transition input", &file, &snapshot)?;
    file.rewind()?;
    Ok((file, snapshot))
}
pub(super) fn read(value: &Pin) -> Result<Vec<u8>> {
    let (file, snapshot) = pin(value, MAX_PROOF)?;
    read_pinned_bytes(
        Path::new(&value.path),
        "transition public record",
        file,
        &snapshot,
        MAX_PROOF,
    )
}
fn record(value: &Pin) -> Result<Value> {
    Ok(json::from_slice(&read(value)?)?)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("missing string {key}"))
}
fn flag(value: &Value, key: &str, expected: bool) -> Result<()> {
    need(
        value.get(key).and_then(Value::as_bool) == Some(expected),
        &format!("invalid {key}"),
    )
}

fn protected_validator_config_name(path: &str, release: &str) -> Result<&'static str> {
    let name = occupied::validator_config_name(Path::new(path))?;
    need(
        path == format!("{release}/config/{name}"),
        "protected validator configuration escaped its selected release",
    )?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_transition_binds_beacon_config_to_exact_selected_release() {
        let release = format!("/srv/taira/taira-validator-1/releases/{}", "a".repeat(40));
        for name in ["config.toml", "beacon.toml"] {
            assert_eq!(
                protected_validator_config_name(&format!("{release}/config/{name}"), &release)
                    .unwrap(),
                name
            );
        }
        for path in [
            format!("{release}/config/foreign.toml"),
            format!("{release}/config/../config/beacon.toml"),
            format!("{release}/beacon.toml"),
            format!("{release}-other/config/beacon.toml"),
            "/srv/taira/taira-validator-2/current/config/beacon.toml".to_owned(),
            "/private/runtime/taira-public-reset/beacon.toml".to_owned(),
        ] {
            assert!(
                protected_validator_config_name(&path, &release).is_err(),
                "{path}"
            );
        }
    }
}

pub(super) fn validate_plan(plan: &Plan) -> Result<()> {
    need(plan.schema == SCHEMA, "exact transition schema required")?;
    validate_lower_hex("operation ID", &plan.operation_id, 32)?;
    require_lower_sha256(&plan.host_identity_sha256, "host identity")?;
    plan.hosts.validate()?;
    need(
        plan.host_identity_sha256 == plan.hosts.validator_guest.endpoint.host_identity_sha256,
        "transition must execute on the independently admitted validator guest",
    )?;
    let p = &plan.predecessor;
    require_lower_sha256(&p.inventory_sha256, "predecessor inventory")?;
    require_lower_sha256(&p.authorization_sha256, "predecessor authorization")?;
    super::super::super::validate_nonce(&p.authorization_nonce)?;
    p.native_edge_capture.verify(
        &plan.hosts,
        &p.inventory_sha256,
        &p.authorization_sha256,
        &p.authorization_nonce,
        &p.native_edge_capture.claims.next_genesis_hash,
    )?;
    need(
        p.completed_next_step > 0
            && p.completed_next_step <= 256
            && p.sealed_forward_ordinal > 0
            && p.sealed_forward_ordinal <= 4096,
        "invalid retained completion counters",
    )?;
    let coordination = coordination_root(plan);
    need(
        !(p.rolled_back && p.unresolved_journal.is_some()),
        "deployment-proven takeover cannot claim a completed rollback",
    )?;
    need(
        p.lease.path == coordination.join("lease.json").to_string_lossy()
            && p.progress.path == coordination.join("progress.json").to_string_lossy()
            && p.completed.path
                == format!(
                    "{RUNTIME}/journal-v1/{}/{}.json",
                    if p.rolled_back {
                        "rolled-back"
                    } else if p.unresolved_journal.is_some() {
                        "deployment-proven"
                    } else {
                        "completed"
                    },
                    p.authorization_sha256
                )
            && p.dispatcher.path == FIXED_DISPATCHER
            && p.dispatcher.mode == 0o755,
        "predecessor control paths differ",
    )?;
    need(
        p.guards.len() == SLUGS.len() && p.occupied.len() == SLUGS.len(),
        "four exact guest role closures and independently captured native edge required",
    )?;
    for ((guard, role), slug) in p.guards.iter().zip(&p.occupied).zip(SLUGS) {
        let directory = slug;
        need(
            guard.path == format!("{CONTROL}/{slug}/guard.json")
                && guard.mode == 0o600
                && role.slug == slug
                && role.state.path == format!("/var/lib/taira/{directory}")
                && role.state.inode > 0
                && role.selector.path == format!("/srv/taira/{directory}/current")
                && role.selector.inode > 0,
            "role paths or identities differ",
        )?;
        let release = Path::new(&role.selector.target);
        need(
            release.parent() == Some(Path::new(&format!("/srv/taira/{directory}/releases"))),
            "selector release escaped",
        )?;
        validate_lower_hex(
            "occupied configuration commit",
            release.file_name().and_then(OsStr::to_str).unwrap_or(""),
            40,
        )?;
        let paths: BTreeSet<&str> = role.files.iter().map(|p| p.path.as_str()).collect();
        need(paths.len() == role.files.len(), "duplicate protected path")?;
        {
            need(
                role.files.len() == 5,
                "validator protected closure incomplete",
            )?;
            let config_name =
                protected_validator_config_name(&role.files[1].path, &role.selector.target)?;
            need(
                paths.contains(format!("/etc/systemd/system/iroha3d-{slug}.service").as_str()),
                "validator protected closure incomplete",
            )?;
            for (index, basename) in [
                "iroha3d_taira",
                config_name,
                "genesis.json",
                "genesis.sha256",
                "",
            ]
            .iter()
            .enumerate()
            {
                if !basename.is_empty() {
                    need(
                        Path::new(&role.files[index].path).file_name()
                            == Some(OsStr::new(basename)),
                        "protected role order differs",
                    )?;
                }
            }
            for file in &role.files[..4] {
                need(
                    Path::new(&file.path).starts_with(&role.selector.target)
                        || Path::new(&file.path).starts_with(RUNTIME),
                    "protected artifact escaped runtime",
                )?;
            }
        }
    }
    Ok(())
}

pub(super) struct Locks {
    pinned: Vec<(PathBuf, File, FileSnapshot)>,
    deployment: deployment_lifecycle::Guard,
}
impl Locks {
    pub(super) fn revalidate(&self) -> Result<()> {
        for (path, file, snapshot) in &self.pinned {
            require_root_no_symlink_ancestors(path, "held transition lock")?;
            ensure_pinned_unchanged(path, "held transition lock", file, snapshot)?;
        }
        self.deployment.revalidate_unowned()
    }
}
pub(super) fn locks(plan: &Plan) -> Result<Locks> {
    locks_for_host(&plan.host_identity_sha256)
}
pub(super) fn locks_for_host(host_identity: &str) -> Result<Locks> {
    require_lower_sha256(host_identity, "host identity")?;
    let mut held = Vec::new();
    for path in [
        Path::new(RUNTIME).join(".routine-update.lock"),
        Path::new(RUNTIME).join("journal-v1/public-reset.lock"),
        Path::new(CONTROL)
            .join("hosts")
            .join(host_identity)
            .join("action.lock"),
    ] {
        require_root_no_symlink_ancestors(&path, "transition lock")?;
        let (file, snapshot) = open_pinned_regular(&path, "existing transition lock")?;
        need(
            snapshot.uid == 0 && snapshot.len == 0 && snapshot.mode & 0o7777 == 0o600,
            "unsafe existing lock",
        )?;
        file.try_lock()
            .wrap_err("deployment or host action owns a transition lock")?;
        ensure_pinned_unchanged(&path, "transition lock", &file, &snapshot)?;
        held.push((path, file, snapshot));
    }
    let deployment =
        deployment_lifecycle::acquire_unowned_existing(Instant::now() + Duration::from_secs(30))?;
    Ok(Locks {
        pinned: held,
        deployment,
    })
}

fn sealed(plan: &Plan) -> Result<()> {
    let p = &plan.predecessor;
    let lease: HostLeaseV1 = json::from_slice(&read(&p.lease)?)?;
    let progress: HostProgressV1 = json::from_slice(&read(&p.progress)?)?;
    let terminal = record(&p.completed)?;
    if p.rolled_back {
        validate_rolled_back_records(plan, &lease, &progress, &terminal)?;
    } else if let Some(unresolved) = &p.unresolved_journal {
        let operational = record(unresolved)?;
        validate_deployment_proven_records(plan, &lease, &progress, &terminal, &operational)?;
        let deployment_id = text(&terminal, "deployment_id")?;
        super::super::super::validate_slug("deployment ID", deployment_id)?;
        need(
            unresolved.path == format!("{RUNTIME}/journal-v1/{deployment_id}.journal.json")
                && unresolved.mode == 0o600,
            "unresolved predecessor journal path differs",
        )?;
    } else {
        validate_sealed_records(plan, &lease, &progress, &terminal)?;
    }
    for name in [
        "progress.successor.json",
        ".progress.json.next",
        ".progress.successor.json.next",
    ] {
        need(
            !storage::exists(&coordination_root(plan).join(name))?,
            "unfinished host progress publication exists",
        )?;
    }
    Ok(())
}

/// Admit a completed rollback as a fresh transition predecessor only when the
/// physical host progress and native terminal receipt agree on every target.
pub(super) fn validate_rolled_back_records(
    plan: &Plan,
    lease: &HostLeaseV1,
    progress: &HostProgressV1,
    terminal: &Value,
) -> Result<()> {
    let p = &plan.predecessor;
    need(p.rolled_back, "rolled-back predecessor flag required")?;
    need(
        lease.schema == LEASE_SCHEMA_V1
            && lease.inventory_sha256 == p.inventory_sha256
            && lease.authorization_semantic_sha256 == p.authorization_sha256
            && lease.authorization_nonce == p.authorization_nonce,
        "rolled-back lease differs",
    )?;
    let touched = SLUGS[..4]
        .iter()
        .map(|slug| (*slug).to_owned())
        .collect::<Vec<_>>();
    let rolled_back = touched.iter().rev().cloned().collect::<Vec<_>>();
    let edge_touched = terminal
        .get("edge_touched")
        .and_then(Value::as_bool)
        .ok_or_else(|| eyre!("rolled-back edge touch flag missing"))?;
    let expected_touched = touched.clone();
    // Native edge rollback is checked through its independently signed capture;
    // it cannot appear in the guest's physical progress/rollback roster.
    if edge_touched {
        need(
            terminal
                .get("edge_rollback_complete")
                .and_then(Value::as_bool)
                == Some(true),
            "native edge rollback has not completed at the global predecessor boundary",
        )?;
    }
    need(
        progress.schema == HOST_PROGRESS_SCHEMA_V1
            && progress.inventory_sha256 == p.inventory_sha256
            && progress.authorization_sha256 == p.authorization_sha256
            && progress.authorization_nonce == p.authorization_nonce
            && progress.prepared_action.is_none()
            && progress.rolling_back
            && !progress.sealed
            && progress.touched_hosts == expected_touched
            && progress.rolled_back_hosts == rolled_back
            && progress.last_rollback_rank == 1
            && progress.next_forward_ordinal == p.sealed_forward_ordinal,
        "host rollback is incomplete or differs",
    )?;
    qualification::names(
        terminal,
        "schema qualification_scope deployment_id inventory_sha256 authorization_sha256 authorization_nonce status phase next_step recovery_intent touched_validators edge_touched edge_rollback_complete rollback_next_validator failure_summary rollback_failures",
    )?;
    let _: super::super::super::executor_model::JournalV1 = json::from_value(terminal.clone())?;
    need(
        terminal.get("next_step").and_then(Value::as_u64) == Some(u64::from(p.completed_next_step))
            && terminal.get("touched_validators") == Some(&json::to_value(&touched)?)
            && terminal
                .get("edge_rollback_complete")
                .and_then(Value::as_bool)
                == Some(edge_touched)
            && terminal
                .get("rollback_next_validator")
                .and_then(Value::as_u64)
                == Some(4)
            && terminal.get("recovery_intent") == Some(&Value::Null)
            && terminal
                .get("failure_summary")
                .and_then(Value::as_str)
                .is_some_and(|summary| !summary.is_empty() && summary.len() <= 512)
            && terminal
                .get("rollback_failures")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty),
        "native terminal rollback is incomplete",
    )?;
    for (name, expected) in [
        ("schema", super::super::super::JOURNAL_SCHEMA_V1),
        ("inventory_sha256", p.inventory_sha256.as_str()),
        ("authorization_sha256", p.authorization_sha256.as_str()),
        ("authorization_nonce", p.authorization_nonce.as_str()),
        ("status", "rolled_back"),
        ("phase", "rolled_back"),
    ] {
        need(
            text(terminal, name)? == expected,
            "rolled-back receipt differs",
        )?;
    }
    Ok(())
}

pub(super) fn validate_sealed_records(
    plan: &Plan,
    lease: &HostLeaseV1,
    progress: &HostProgressV1,
    terminal: &Value,
) -> Result<()> {
    need(
        plan.predecessor.unresolved_journal.is_none(),
        "unfinished predecessor requires explicit deployment-proven admission",
    )?;
    validate_sealed_boundary(plan, lease, progress, terminal, "completed", "completed")
}

/// Retain an unfinished seal as history while a fresh reset adopts its exact live custody.
pub(super) fn validate_deployment_proven_records(
    plan: &Plan,
    lease: &HostLeaseV1,
    progress: &HostProgressV1,
    proof: &Value,
    operational: &Value,
) -> Result<()> {
    need(
        !plan.predecessor.rolled_back && plan.predecessor.unresolved_journal.is_some(),
        "deployment-proven takeover must be explicitly selected",
    )?;
    validate_sealed_boundary(plan, lease, progress, proof, "sealing", "seal")?;
    let sealing_step = match text(proof, "qualification_scope")? {
        "core_testnet" => 11,
        "full_inrou" => 12,
        _ => return Err(eyre!("deployment-proven qualification scope differs")),
    };
    need(
        plan.predecessor.completed_next_step == sealing_step,
        "deployment-proven receipt is not at its sealing boundary",
    )?;
    // The coordinator can add only its failed-seal diagnostic after publishing
    // the immutable proof. Never rewrite either file or assert it completed.
    let _: super::super::super::executor_model::JournalV1 = json::from_value(operational.clone())?;
    need(
        text(operational, "failure_summary")?.len() <= 512,
        "unresolved predecessor diagnostic exceeds its bound",
    )?;
    let mut expected = operational.clone();
    expected
        .as_object_mut()
        .ok_or_else(|| eyre!("unresolved predecessor journal is not an object"))?
        .insert("failure_summary".into(), Value::String(String::new()));
    need(
        expected == *proof,
        "unresolved predecessor differs from its immutable deployment proof",
    )
}

fn validate_sealed_boundary(
    plan: &Plan,
    lease: &HostLeaseV1,
    progress: &HostProgressV1,
    terminal: &Value,
    expected_status: &str,
    expected_phase: &str,
) -> Result<()> {
    let p = &plan.predecessor;
    need(
        lease.schema == LEASE_SCHEMA_V1
            && lease.inventory_sha256 == p.inventory_sha256
            && lease.authorization_semantic_sha256 == p.authorization_sha256
            && lease.authorization_nonce == p.authorization_nonce,
        "predecessor lease differs",
    )?;
    need(
        progress.schema == HOST_PROGRESS_SCHEMA_V1
            && progress.inventory_sha256 == p.inventory_sha256
            && progress.authorization_sha256 == p.authorization_sha256
            && progress.authorization_nonce == p.authorization_nonce
            && progress.sealed
            && progress.prepared_action.is_none()
            && !progress.rolling_back
            && progress.next_forward_ordinal == p.sealed_forward_ordinal
            && progress.last_rollback_rank == 0
            && progress.rolled_back_hosts.is_empty(),
        "predecessor session is not sealed",
    )?;
    need(
        progress
            .touched_hosts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == SLUGS.into_iter().collect()
            && progress.touched_hosts.len() == SLUGS.len(),
        "sealed session role closure differs",
    )?;
    need(
        now_unix_ms()? > lease.execution_expires_at_unix_ms,
        "predecessor lease has not expired",
    )?;
    qualification::names(
        &terminal,
        "schema qualification_scope deployment_id inventory_sha256 authorization_sha256 authorization_nonce status phase next_step recovery_intent touched_validators edge_touched edge_rollback_complete rollback_next_validator failure_summary rollback_failures",
    )?;
    let _: super::super::super::executor_model::JournalV1 = json::from_value(terminal.clone())?;
    need(
        terminal.get("next_step").and_then(Value::as_u64) == Some(u64::from(p.completed_next_step))
            && terminal
                .get("rollback_next_validator")
                .and_then(Value::as_u64)
                == Some(0)
            && terminal.get("edge_touched").and_then(Value::as_bool) == Some(true)
            && terminal
                .get("edge_rollback_complete")
                .and_then(Value::as_bool)
                == Some(false)
            && terminal.get("failure_summary").and_then(Value::as_str) == Some("")
            && terminal
                .get("rollback_failures")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            && terminal.get("touched_validators") == Some(&json::to_value(&SLUGS[..4].to_vec())?),
        "completed predecessor shape differs",
    )?;
    for (name, expected) in [
        ("schema", super::super::super::JOURNAL_SCHEMA_V1),
        ("inventory_sha256", p.inventory_sha256.as_str()),
        ("authorization_sha256", p.authorization_sha256.as_str()),
        ("authorization_nonce", p.authorization_nonce.as_str()),
        ("status", expected_status),
        ("phase", expected_phase),
    ] {
        need(
            text(&terminal, name)? == expected,
            "completed predecessor receipt differs",
        )?;
    }
    need(
        terminal.get("recovery_intent") == Some(&Value::Null),
        "terminal recovery remains",
    )?;
    Ok(())
}

fn protected(plan: &Plan) -> Result<()> {
    need(
        !storage::exists(Path::new("/var/lib/taira-epoch-supervisor"))?,
        "supervisor appeared",
    )?;
    need(
        !storage::exists(Path::new(
            "/etc/systemd/system/iroha-taira-epoch-supervisor.service",
        ))?,
        "supervisor unit appeared",
    )?;
    let absent = run_host_command(
        SYSTEMCTL,
        &[
            "show",
            "--property=LoadState,FragmentPath,DropInPaths,ActiveState,SubState,MainPID,ControlPID,Job",
            "iroha-taira-epoch-supervisor.service",
        ],
        Instant::now() + Duration::from_secs(30),
    )?;
    let fields = std::str::from_utf8(&absent)?
        .lines()
        .map(|line| {
            line.split_once('=')
                .ok_or_else(|| eyre!("malformed supervisor unit"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    need(
        fields
            == BTreeMap::from([
                ("LoadState", "not-found"),
                ("FragmentPath", ""),
                ("DropInPaths", ""),
                ("ActiveState", "inactive"),
                ("SubState", "dead"),
                ("MainPID", "0"),
                ("ControlPID", "0"),
                ("Job", ""),
            ]),
        "supervisor is not absent",
    )?;
    for role in &plan.predecessor.occupied {
        let state = Path::new(&role.state.path);
        require_root_directory(state, true, "protected stopped state")?;
        let meta = fs::symlink_metadata(state)?;
        need(
            meta.dev() == role.state.device && meta.ino() == role.state.inode,
            "protected state identity changed",
        )?;
        let selector = Path::new(&role.selector.path);
        require_root_no_symlink_ancestors(selector, "protected selector")?;
        let info = fs::symlink_metadata(selector)?;
        need(
            info.file_type().is_symlink()
                && info.uid() == 0
                && info.dev() == role.selector.device
                && info.ino() == role.selector.inode
                && fs::read_link(selector)? == Path::new(&role.selector.target),
            "protected selector changed",
        )?;
        for value in &role.files {
            pin(value, MAX_BINARY)?;
        }
        let (unit, active, substate) =
            (format!("iroha3d-{}.service", role.slug), "inactive", "dead");
        let bytes = run_host_command(
            SYSTEMCTL,
            &[
                "show",
                "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,ControlPID,MainPID,Job",
                &unit,
            ],
            Instant::now() + Duration::from_secs(30),
        )?;
        let mut parsed = std::str::from_utf8(&bytes)?
            .lines()
            .map(|line| {
                line.split_once('=')
                    .ok_or_else(|| eyre!("malformed unit state"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let main_pid = parsed
            .remove("MainPID")
            .ok_or_else(|| eyre!("missing MainPID"))?
            .parse::<u32>()?;
        need(main_pid == 0, "protected MainPID changed")?;
        let fragment = format!("/etc/systemd/system/{unit}");
        let expected = BTreeMap::from([
            ("LoadState", "loaded"),
            ("ActiveState", active),
            ("SubState", substate),
            ("FragmentPath", fragment.as_str()),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("ControlPID", "0"),
            ("Job", ""),
        ]);
        need(parsed == expected, "protected loaded unit state changed")?;
    }
    Ok(())
}

pub(super) fn admit(plan: &Plan) -> Result<Held> {
    let candidate = &plan.candidate;
    super::super::super::validate_revision(&candidate.revision)?;
    super::super::super::validate_source_closure(&candidate.revision)?;
    need(
        candidate.revision.commit == candidate.commit
            && candidate.revision.tree == candidate.tree
            && candidate.revision.source_root
                == Path::new(&candidate.source_transfer.path)
                    .parent()
                    .ok_or_else(|| eyre!("native source transfer has no parent"))?
                    .join("source")
                    .to_string_lossy(),
        "candidate revision differs from the exact authenticated native source import",
    )?;
    let trusted: super::super::super::TrustedKeyV1 =
        json::from_slice(&read(&plan.trusted_public_key)?)?;
    candidate.native_edge_candidate.verify(
        &plan.hosts,
        &candidate.commit,
        &candidate.tree,
        &candidate.revision.cargo_lock_sha256,
        &candidate.revision.source_closure_sha256,
        &trusted,
    )?;
    need(
        candidate.native_edge_candidate.claims.native_guard
            == plan.predecessor.native_edge_capture.claims.native_guard
            && candidate
                .native_edge_candidate
                .claims
                .helper_source_closure_sha256
                == plan
                    .predecessor
                    .native_edge_capture
                    .claims
                    .helper_source_closure_sha256,
        "native candidate guard differs from the independently captured prepared Mac custodian",
    )?;
    let native_cli = &candidate.native_edge_candidate.claims.iroha_cli;
    let native_cli_pin = Pin {
        path: native_cli.local_path.clone(),
        sha256: native_cli.sha256.clone(),
        size: native_cli.size,
        mode: u32::from(native_cli.mode),
    };
    let native_source_pin = Pin {
        path: candidate.revision.source_manifest_path.clone(),
        sha256: candidate.revision.source_manifest_sha256.clone(),
        size: fs::symlink_metadata(&candidate.revision.source_manifest_path)?.len(),
        mode: fs::symlink_metadata(&candidate.revision.source_manifest_path)?.mode() & 0o7777,
    };
    let binaries = qualification::admit(&plan.candidate)?;
    sealed(plan)?;
    protected(plan)?;
    let mut held = Held { files: Vec::new() };
    let p = &plan.predecessor;
    let c = &plan.candidate;
    for value in [
        &plan.trusted_public_key,
        &p.completed,
        &p.lease,
        &p.progress,
        &c.preparation,
        &c.request,
        &c.checks,
        &c.capture,
        &c.binary_transfer,
        &c.source_transfer,
        &c.transfer_request,
        &c.transfer_completed,
        &c.executable,
        &native_cli_pin,
        &native_source_pin,
    ]
    .into_iter()
    .chain(p.unresolved_journal.iter())
    .chain(p.occupied.iter().flat_map(|r| r.files.iter()))
    .chain(binaries.iter())
    {
        let (file, snapshot) = pin(value, MAX_BINARY)?;
        held.files.push((value.clone(), file, snapshot));
    }
    Ok(held)
}
pub(super) fn revalidate(plan: &Plan, held: &Held) -> Result<()> {
    for (value, file, snapshot) in &held.files {
        ensure_pinned_unchanged(
            Path::new(&value.path),
            "preserved transition input",
            file,
            snapshot,
        )?;
    }
    super::super::super::validate_source_closure(&plan.candidate.revision)?;
    sealed(plan)?;
    protected(plan)
}
pub(super) fn new_guards(plan: &Plan, root: &Path) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    for (index, slug) in SLUGS.iter().enumerate() {
        let _ = slug;
        let original = &plan.predecessor.guards[index];
        let archived = root.join(format!("old-guard-{index}"));
        let pin = if storage::exists(&archived)? {
            Pin {
                path: archived.to_string_lossy().into_owned(),
                ..original.clone()
            }
        } else {
            original.clone()
        };
        result.push(derive_guard(plan, index, &read(&pin)?)?);
    }
    Ok(result)
}

pub(super) fn derive_guard(plan: &Plan, index: usize, bytes: &[u8]) -> Result<Vec<u8>> {
    let slug = &SLUGS[index];
    let directory = *slug;
    need(
        sha256_hex(bytes) == plan.predecessor.guards[index].sha256,
        "old guard bytes differ",
    )?;
    let mut guard: HostGuardV1 = json::from_slice(bytes)?;
    need(
        guard.schema == HOST_GUARD_SCHEMA_V1
            && guard.host_slug == *slug
            && guard.service_root == format!("/srv/taira/{directory}")
            && guard.state_root == format!("/var/lib/taira/{directory}")
            && guard.upload_parent == format!("/srv/taira/{directory}/.public-reset-upload-v1")
            && guard.dispatcher_path == FIXED_DISPATCHER
            && guard.dispatcher_sha256 == plan.predecessor.dispatcher.sha256
            && guard.trusted_key_sha256 == plan.trusted_public_key.sha256,
        "existing guard authority differs",
    )?;
    guard
        .dispatcher_sha256
        .clone_from(&plan.candidate.executable.sha256);
    Ok(json::to_vec(&guard)?)
}
