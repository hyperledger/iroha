//! Routine root-owned updater adapter for the shared stopped Inrou owner boundary.
//!
//! This command carries no reset or signing authority. The live parent updater,
//! its exclusive flock, and its retained public plan delimit routine maintenance.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]

use super::*;
#[cfg(any(target_os = "linux", test))]
use base64::Engine as _;
#[cfg(any(target_os = "linux", test))]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;

#[cfg(any(target_os = "linux", test))]
const REQUEST_SCHEMA: &str = "taira.stopped-owner-maintenance.request.v1";
#[cfg(any(target_os = "linux", test))]
const RESULT_SCHEMA: &str = "taira.stopped-owner-maintenance.result.v1";

/// Credential-free stopped-owner maintenance for the active routine updater.
#[derive(clap::Args, Debug)]
pub(crate) struct StoppedOwnerMaintenance {
    /// Read the bounded root-owned public request from this inherited read-only descriptor.
    #[arg(long)]
    request_fd: u32,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
pub(super) struct MaintenanceRequest {
    pub(super) schema: String,
    pub(super) operation_directory: String,
    pub(super) owner: MaintenanceOwner,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
pub(super) struct MaintenanceOwner {
    pub(super) pid: u32,
    pub(super) start_time_ticks: u64,
    pub(super) argv: Vec<String>,
    pub(super) lock: MaintenanceLock,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
pub(super) struct MaintenanceLock {
    pub(super) device: u64,
    pub(super) inode: u64,
}

impl StoppedOwnerMaintenance {
    /// Run without opening client configuration or signing inputs.
    pub(crate) fn run_without_client_config(&self, mut output: impl Write) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(eyre!("stopped-owner maintenance requires OS root"));
            }
            let bytes = crate::client_config::read_inherited_private_file(
                self.request_fd,
                16_384,
                "stopped-owner maintenance request",
            )?;
            let request: MaintenanceRequest = json::from_slice(&bytes)?;
            let report = run_maintenance(&request)?;
            output.write_all(&json::to_vec(&report)?)?;
            output.write_all(b"\n")?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut output;
            Err(eyre!("stopped-owner maintenance requires Linux"))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn text_field<'a>(value: &'a json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(json::Value::as_str)
        .ok_or_else(|| eyre!("maintenance public plan is missing required text field: {field}"))
}

#[cfg(any(target_os = "linux", test))]
struct ObservedDaemon {
    selector: PathBuf,
    release: PathBuf,
    sha256: String,
    size: u64,
}

#[cfg(any(target_os = "linux", test))]
struct PreviousDaemon {
    resolved: PathBuf,
    observed: Option<ObservedDaemon>,
}

#[cfg(any(target_os = "linux", test))]
fn exact_fields(value: &json::Value, names: &[&str]) -> Result<()> {
    let map = value
        .as_object()
        .ok_or_else(|| eyre!("maintenance predecessor is not an object"))?;
    ensure!(
        map.len() == names.len() && names.iter().all(|name| map.contains_key(*name)),
        "maintenance predecessor fields differ"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn require_commit(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "maintenance source identity differs"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn previous_daemons(
    deployment: &json::Value,
    runtime: &Path,
    config: &Path,
) -> Result<Vec<PreviousDaemon>> {
    let installed = deployment
        .get("current")
        .ok_or_else(|| eyre!("maintenance installed runtime is absent"))?;
    require_commit(text_field(installed, "commit")?)?;
    match text_field(installed, "kind")? {
        "observed-installation" => {
            exact_fields(installed, &["kind", "commit", "daemons"])?;
            let release = text_field(deployment, "config_release")?;
            require_commit(release)?;
            let daemons = installed
                .get("daemons")
                .ok_or_else(|| eyre!("maintenance observed daemons are absent"))?;
            exact_fields(daemons, &super::super::VALIDATOR_SLUGS)?;
            super::super::VALIDATOR_SLUGS
                .iter()
                .map(|role| {
                    let row = daemons.get(*role).expect("exact role fields checked");
                    exact_fields(row, &["command", "resolved", "sha256", "size"])?;
                    let selector = config.join(role).join("current");
                    let release = config.join(role).join("releases").join(release);
                    let resolved = release.join("bin/iroha3d_taira");
                    ensure!(
                        OsStr::new(text_field(row, "command")?)
                            == selector.join("bin/iroha3d_taira").as_os_str()
                            && OsStr::new(text_field(row, "resolved")?) == resolved.as_os_str(),
                        "maintenance observed daemon paths differ"
                    );
                    let sha256 = text_field(row, "sha256")?;
                    require_lower_sha256(sha256, "maintenance observed daemon digest")?;
                    let size = row
                        .get("size")
                        .and_then(json::Value::as_u64)
                        .filter(|size| *size > 1_000_000 && *size < 1024 * 1024 * 1024)
                        .ok_or_else(|| eyre!("maintenance observed daemon size differs"))?;
                    Ok(PreviousDaemon {
                        resolved,
                        observed: Some(ObservedDaemon {
                            selector,
                            release,
                            sha256: sha256.into(),
                            size,
                        }),
                    })
                })
                .collect()
        }
        "completed-update" => {
            exact_fields(
                installed,
                &[
                    "kind",
                    "commit",
                    "daemon",
                    "attempt_name",
                    "plan_schema",
                    "result_schema",
                    "local_plan",
                    "local_plan_sha256",
                ],
            )?;
            let resolved = PathBuf::from(text_field(installed, "daemon")?);
            super::super::validate_absolute_normal_path(&resolved, "maintenance installed daemon")?;
            ensure!(
                resolved.starts_with(runtime)
                    && resolved.file_name() == Some(OsStr::new("iroha3d_taira")),
                "maintenance installed daemon differs"
            );
            Ok(vec![PreviousDaemon {
                resolved,
                observed: None,
            }])
        }
        _ => Err(eyre!("maintenance predecessor kind differs")),
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct MaintenanceScope {
    pub(super) operation: String,
    pub(super) runtime: PathBuf,
    pub(super) config: PathBuf,
    pub(super) state: PathBuf,
    previous_daemons: Vec<PreviousDaemon>,
    pub(super) candidate_cli: PathBuf,
    pub(super) units: Vec<Vec<u8>>,
}

#[cfg(any(target_os = "linux", test))]
impl MaintenanceScope {
    pub(super) fn vacant_paths(&self) -> Vec<&Path> {
        let mut paths = vec![self.config.as_path(), self.state.as_path()];
        paths.extend(
            self.previous_daemons
                .iter()
                .map(|daemon| daemon.resolved.as_path()),
        );
        paths
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn maintenance_scope(
    request: &MaintenanceRequest,
    plan: &json::Value,
) -> Result<MaintenanceScope> {
    let operation = text_field(plan, "operation")?;
    if request.schema != REQUEST_SCHEMA
        || text_field(plan, "schema")? != "taira.daemon-update.plan.v2"
        || plan.get("failed_start").is_some()
        || !operation.strip_prefix("update-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || request.owner.pid == 0
        || request.owner.start_time_ticks == 0
        || request.owner.argv != ["/usr/bin/python3", "-I", "-"]
    {
        return Err(eyre!(
            "maintenance request or routine updater identity differs"
        ));
    }
    let deployment = plan
        .get("deployment")
        .ok_or_else(|| eyre!("maintenance deployment is absent"))?;
    if text_field(deployment, "schema")? != "taira.runtime-deployment.v2" {
        return Err(eyre!("maintenance deployment schema differs"));
    }
    let runtime = PathBuf::from(text_field(deployment, "runtime_root")?);
    let config = PathBuf::from(text_field(deployment, "config_root")?);
    let state = PathBuf::from(text_field(deployment, "state_root")?);
    let commit = text_field(plan, "commit")?;
    require_commit(commit)?;
    for path in [
        &runtime,
        &config,
        &state,
        Path::new(&request.operation_directory),
    ] {
        super::super::validate_absolute_normal_path(path, "maintenance public path")?;
    }
    if runtime.join(operation) != Path::new(&request.operation_directory)
        || config.starts_with(&runtime)
        || runtime.starts_with(&config)
        || state.starts_with(&runtime)
        || runtime.starts_with(&state)
        || state.starts_with(&config)
        || config.starts_with(&state)
    {
        return Err(eyre!("maintenance public roots or installed daemon differ"));
    }
    let roles = deployment
        .get("roles")
        .and_then(json::Value::as_array)
        .ok_or_else(|| eyre!("maintenance roles are absent"))?;
    let rows = plan
        .get("units")
        .and_then(json::Value::as_array)
        .ok_or_else(|| eyre!("maintenance units are absent"))?;
    if roles.len() != 4 || rows.len() != 4 {
        return Err(eyre!("maintenance requires all four ordered owner slots"));
    }
    let mut units = Vec::new();
    for (index, slug) in super::super::VALIDATOR_SLUGS.iter().enumerate() {
        if roles[index].as_str() != Some(*slug) || text_field(&rows[index], "role")? != *slug {
            return Err(eyre!("maintenance owner ordering differs"));
        }
        let raw = BASE64.decode(text_field(&rows[index], "before")?)?;
        if raw.is_empty()
            || raw.len() > 1024 * 1024
            || sha256_hex(&raw) != text_field(&rows[index], "before_sha256")?
        {
            return Err(eyre!("maintenance installed unit bytes differ"));
        }
        units.push(raw);
    }
    let previous_daemons = previous_daemons(deployment, &runtime, &config)?;
    Ok(MaintenanceScope {
        operation: operation.to_owned(),
        candidate_cli: runtime.join(format!("release-{commit}-{operation}/bin/iroha")),
        runtime,
        config,
        state,
        previous_daemons,
        units,
    })
}

#[cfg(any(target_os = "linux", test))]
fn hash_observed_daemon(mut input: impl Read, size: u64, deadline: Instant) -> Result<String> {
    let mut digest = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure!(
            Instant::now() < deadline,
            "maintenance daemon hash deadline expired"
        );
        let capacity = usize::try_from(remaining.min(buffer.len() as u64))?;
        if capacity == 0 {
            ensure!(
                input.read(&mut buffer[..1])? == 0,
                "maintenance daemon grew while hashing"
            );
            break;
        }
        let read = input.read(&mut buffer[..capacity])?;
        ensure!(read != 0, "maintenance daemon shortened while hashing");
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(target_os = "linux")]
struct PinnedPreviousDaemon<'a> {
    daemon: &'a PreviousDaemon,
    file: File,
    snapshot: super::super::FileSnapshot,
    selector_snapshot: Option<super::super::FileSnapshot>,
}

/// Holds predecessor descriptors and the admitted selector identities for the whole action.
#[cfg(target_os = "linux")]
pub(super) struct PreviousDaemonsGuard<'a>(Vec<PinnedPreviousDaemon<'a>>);

#[cfg(target_os = "linux")]
fn selector_snapshot(observed: &ObservedDaemon) -> Result<super::super::FileSnapshot> {
    require_root_no_symlink_ancestors(&observed.selector, "maintenance installed selector")?;
    let before = fs::symlink_metadata(&observed.selector)?;
    ensure!(
        before.file_type().is_symlink()
            && before.uid() == 0
            && fs::read_link(&observed.selector)?.as_os_str() == observed.release.as_os_str(),
        "maintenance installed selector differs"
    );
    let snapshot = super::super::file_snapshot(&before)?;
    ensure!(
        super::super::file_snapshot(&fs::symlink_metadata(&observed.selector)?)? == snapshot,
        "maintenance installed selector changed during inspection"
    );
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
impl<'a> PreviousDaemonsGuard<'a> {
    pub(super) fn admit(scope: &'a MaintenanceScope, deadline: Instant) -> Result<Self> {
        let mut pinned = Vec::with_capacity(scope.previous_daemons.len());
        for daemon in &scope.previous_daemons {
            ensure!(
                Instant::now() < deadline,
                "maintenance daemon admission deadline expired"
            );
            let selector_snapshot = daemon
                .observed
                .as_ref()
                .map(selector_snapshot)
                .transpose()?;
            require_root_no_symlink_ancestors(&daemon.resolved, "maintenance installed daemon")?;
            let (mut file, snapshot) =
                open_pinned_regular(&daemon.resolved, "maintenance installed daemon")?;
            ensure!(
                snapshot.uid == 0 && snapshot.mode & 0o111 != 0,
                "maintenance installed daemon lacks root executable custody"
            );
            if let Some(observed) = &daemon.observed {
                ensure!(
                    snapshot.len == observed.size,
                    "maintenance installed daemon size differs"
                );
                ensure!(
                    hash_observed_daemon(&mut file, observed.size, deadline)? == observed.sha256,
                    "maintenance installed daemon digest differs"
                );
            }
            pinned.push(PinnedPreviousDaemon {
                daemon,
                file,
                snapshot,
                selector_snapshot,
            });
        }
        let guard = Self(pinned);
        guard.revalidate(deadline)?;
        Ok(guard)
    }

    pub(super) fn revalidate(&self, deadline: Instant) -> Result<()> {
        for pinned in &self.0 {
            ensure!(
                Instant::now() < deadline,
                "maintenance daemon revalidation deadline expired"
            );
            require_root_no_symlink_ancestors(
                &pinned.daemon.resolved,
                "maintenance installed daemon",
            )?;
            ensure_pinned_unchanged(
                &pinned.daemon.resolved,
                "maintenance installed daemon",
                &pinned.file,
                &pinned.snapshot,
            )?;
            if let Some(observed) = &pinned.daemon.observed {
                ensure!(
                    Some(selector_snapshot(observed)?) == pinned.selector_snapshot,
                    "maintenance installed selector changed"
                );
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn public_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    require_root_no_symlink_ancestors(path, "maintenance public evidence")?;
    let pinned = pin_owner_private_file(path, "maintenance public evidence")?;
    if pinned.snapshot.len > maximum {
        return Err(eyre!("maintenance public evidence exceeds its bound"));
    }
    read_pinned_bytes(
        path,
        "maintenance public evidence",
        pinned.file,
        &pinned.snapshot,
        maximum,
    )
}

#[cfg(target_os = "linux")]
pub(super) fn proc_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(eyre!("maintenance process evidence exceeds its bound"));
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn process_identity(bytes: &[u8]) -> Result<(u32, u32, u64)> {
    let text = std::str::from_utf8(bytes)?;
    let (prefix, tail) = text
        .rsplit_once(") ")
        .ok_or_else(|| eyre!("maintenance process stat is malformed"))?;
    let pid = prefix
        .split_once(' ')
        .ok_or_else(|| eyre!("maintenance process PID is absent"))?
        .0
        .parse()?;
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    if fields.len() < 20 || matches!(fields[0], "Z" | "X") {
        return Err(eyre!("maintenance updater process is not live"));
    }
    Ok((pid, fields[1].parse()?, fields[19].parse()?))
}

#[cfg(any(target_os = "linux", test))]
fn require_updater_flock(bytes: &[u8], owner: &MaintenanceOwner) -> Result<()> {
    let mut matches = 0;
    for line in std::str::from_utf8(bytes)?.lines() {
        let row: Vec<_> = line.split_ascii_whitespace().collect();
        if row.len() != 8
            || row[1..4] != ["FLOCK", "ADVISORY", "WRITE"]
            || row[4].parse::<u32>().ok() != Some(owner.pid)
            || row[6..] != ["0", "EOF"]
        {
            continue;
        }
        let identity: Vec<_> = row[5].split(':').collect();
        if identity.len() == 3
            && u32::from_str_radix(identity[0], 16).ok()
                == Some(rustix::fs::major(owner.lock.device as rustix::fs::Dev))
            && u32::from_str_radix(identity[1], 16).ok()
                == Some(rustix::fs::minor(owner.lock.device as rustix::fs::Dev))
            && identity[2].parse::<u64>().ok() == Some(owner.lock.inode)
        {
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(eyre!(
            "maintenance updater no longer holds the exact exclusive flock"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn verify_owner(
    request: &MaintenanceRequest,
    scope: &MaintenanceScope,
    deadline: Instant,
    allow_failure: bool,
) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(eyre!("maintenance deadline elapsed"));
    }
    let directory = Path::new(&request.operation_directory);
    require_root_directory(directory, true, "maintenance operation")?;
    for terminal in [
        "result.json",
        "failure.json",
        "rollback.json",
        "start-intent.json",
    ] {
        if allow_failure && terminal == "failure.json" {
            continue;
        }
        match fs::symlink_metadata(directory.join(terminal)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(eyre!("maintenance operation has started or terminated")),
        }
    }
    let lock_path = scope.runtime.join(".routine-update.lock");
    require_root_no_symlink_ancestors(&lock_path, "maintenance updater lock")?;
    let lock = fs::symlink_metadata(&lock_path)?;
    if !lock.is_file()
        || lock.uid() != 0
        || lock.gid() != 0
        || lock.nlink() != 1
        || lock.mode() & 0o7777 != 0o600
        || (lock.dev(), lock.ino()) != (request.owner.lock.device, request.owner.lock.inode)
    {
        return Err(eyre!("maintenance updater lock custody differs"));
    }
    let own = process_identity(&proc_bytes(Path::new("/proc/self/stat"), 4096)?)?;
    let process = PathBuf::from(format!("/proc/{}", request.owner.pid));
    let expected = process_identity(&proc_bytes(&process.join("stat"), 4096)?)?;
    if own.1 != request.owner.pid
        || expected.0 != request.owner.pid
        || expected.2 != request.owner.start_time_ticks
        || proc_bytes(&process.join("cmdline"), 4096)? != b"/usr/bin/python3\0-I\0-\0"
    {
        return Err(eyre!(
            "maintenance caller is not the retained live parent updater"
        ));
    }
    require_updater_flock(
        &proc_bytes(Path::new("/proc/locks"), 1024 * 1024)?,
        &request.owner,
    )
}

#[cfg(target_os = "linux")]
fn require_cohort_vacant(scope: &MaintenanceScope, deadline: Instant) -> Result<()> {
    require_root_directory(&scope.config, false, "maintenance config root")?;
    require_root_directory(&scope.state, false, "maintenance state root")?;
    for (slot, slug) in super::super::VALIDATOR_SLUGS.iter().enumerate() {
        let unit = format!("iroha3d-{slug}.service");
        let fragment = Path::new("/etc/systemd/system").join(&unit);
        require_root_no_symlink_ancestors(&fragment, "maintenance installed unit")?;
        let (file, snapshot) = open_pinned_regular(&fragment, "maintenance installed unit")?;
        if snapshot.len > 1024 * 1024 {
            return Err(eyre!("maintenance unit exceeds its bound"));
        }
        // Unit files may be world-readable, but no non-root writer may alter them.
        let metadata = fs::symlink_metadata(&fragment)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || read_pinned_bytes(
                &fragment,
                "maintenance installed unit",
                file,
                &snapshot,
                1024 * 1024,
            )? != scope.units[slot]
        {
            return Err(eyre!(
                "maintenance installed unit differs from the retained plan"
            ));
        }
        let loaded = run_host_command(
            SYSTEMCTL,
            &[
                "show",
                "--all",
                "--property=FragmentPath",
                "--property=DropInPaths",
                "--property=NeedDaemonReload",
                &unit,
            ],
            deadline,
        )?;
        validate_loaded_unit_evidence(&loaded, &fragment)?;
        let evidence = run_host_command(
            SYSTEMCTL,
            &[
                "show",
                "--all",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--property=ControlPID",
                "--property=ControlGroup",
                "--property=Job",
                &unit,
            ],
            deadline,
        )?;
        if let Some(cgroup) = validate_vacant_unit_evidence(&evidence, true)? {
            require_root_directory(&cgroup, false, "maintenance supervisor cgroup")?;
            if rustix::fs::statfs(&cgroup)?.f_type as u64 != 0x6367_7270
                || fs::read_to_string(cgroup.join("cgroup.events"))?
                    .lines()
                    .filter(|line| line.starts_with("populated "))
                    .collect::<Vec<_>>()
                    != ["populated 0"]
            {
                return Err(eyre!("maintenance supervisor cgroup is not kernel-empty"));
            }
        }
    }
    require_no_live_path_references(&scope.vacant_paths(), deadline)
}

#[cfg(target_os = "linux")]
fn run_maintenance(request: &MaintenanceRequest) -> Result<json::Value> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let directory = Path::new(&request.operation_directory);
    require_root_directory(directory, true, "maintenance operation")?;
    let plan_bytes = public_bytes(&directory.join("intent.json"), 8 * 1024 * 1024)?;
    let plan: json::Value = json::from_slice(&plan_bytes)?;
    let scope = maintenance_scope(request, &plan)?;
    require_root_directory(&scope.runtime, true, "maintenance runtime")?;
    if std::env::current_exe()? != scope.candidate_cli {
        return Err(eyre!(
            "maintenance executable is not the planned candidate CLI"
        ));
    }
    let previous_daemons = PreviousDaemonsGuard::admit(&scope, deadline)?;
    let vacant = || {
        verify_owner(request, &scope, deadline, false)?;
        if public_bytes(&directory.join("intent.json"), 8 * 1024 * 1024)? != plan_bytes {
            return Err(eyre!("maintenance public plan changed"));
        }
        previous_daemons.revalidate(deadline)?;
        require_cohort_vacant(&scope, deadline)?;
        previous_daemons.revalidate(deadline)
    };
    vacant()?;
    // Keep every slot lock alive. A later owner's failed preflight prevents any
    // earlier owner mutation, and no supervisor can claim a preflighted slot.
    let plans = (0..4)
        .map(|slot| stopped_runtime::preflight_stopped_owner(slot, true, false, deadline, &vacant))
        .collect::<Result<Vec<_>>>()?;
    let publish = |name: &str, value: &json::Value| {
        super::super::inputs::write_new_private(&directory.join(name), &json::to_vec(value)?)
    };
    publish(
        "stopped-owner-maintenance-intent.json",
        &norito::json!({
            "schema": "taira.stopped-owner-maintenance.intent.v1", "operation": (scope.operation.clone()),
            "all_four_preflighted": true, "kills_or_flushes": false,
        }),
    )?;
    for (slot, plan) in plans.iter().enumerate() {
        stopped_runtime::apply_stopped_owner(plan, true, &vacant)?;
        publish(
            &format!("stopped-owner-maintenance-slot-{slot}.json"),
            &norito::json!({
                "slot": slot, "stopped_owner_clean": true,
            }),
        )?;
    }
    vacant()?;
    let result = norito::json!({"schema": RESULT_SCHEMA, "operation": (scope.operation.clone()),
        "all_four_stopped_owners_clean": true});
    publish("stopped-owner-maintenance-result.json", &result)?;
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn fixture() -> (MaintenanceRequest, json::Value) {
        let operation = format!("update-{}", "a".repeat(32));
        let units = super::super::super::VALIDATOR_SLUGS
            .iter()
            .map(|slug| {
                let raw = format!("[Unit]\nDescription={slug}\n");
                norito::json!({"role": (*slug), "before": (BASE64.encode(raw.as_bytes())),
                "before_sha256": (sha256_hex(raw.as_bytes()))})
            })
            .collect::<Vec<_>>();
        (
            MaintenanceRequest {
                schema: REQUEST_SCHEMA.into(),
                operation_directory: format!("/private/runtime/taira/{operation}"),
                owner: MaintenanceOwner {
                    pid: 123,
                    start_time_ticks: 456,
                    argv: vec!["/usr/bin/python3".into(), "-I".into(), "-".into()],
                    lock: MaintenanceLock {
                        device: rustix::fs::makedev(8, 1) as u64,
                        inode: 789,
                    },
                },
            },
            norito::json!({"schema": "taira.daemon-update.plan.v2", "operation": operation,
                "commit": ("b".repeat(40)), "units": units,
                "deployment": {"schema": "taira.runtime-deployment.v2",
                    "runtime_root": "/private/runtime/taira", "config_root": "/srv/taira",
                    "state_root": "/var/lib/taira", "roles": (super::super::super::VALIDATOR_SLUGS.to_vec()),
                    "current": {"kind": "completed-update", "commit": ("c".repeat(40)),
                        "daemon": "/private/runtime/taira/selected/bin/iroha3d_taira",
                        "attempt_name": "prior-update", "plan_schema": "taira.daemon-update.plan.v2",
                        "result_schema": "taira.daemon-update.result.v2",
                        "local_plan": "/private/operator/prior-plan.json",
                        "local_plan_sha256": ("d".repeat(64))}}}),
        )
    }

    // This is the maintained observed-installation descriptor shape, including
    // the actual retained release, executable digest and size from first adoption.
    fn observed_fixture() -> (MaintenanceRequest, json::Value) {
        let (mut request, mut plan) = fixture();
        let release = "c30e0b18cd7f5b9e1d680abe6478aea7f37ea5b9";
        let mut daemons = norito::json!({});
        for role in super::super::super::VALIDATOR_SLUGS {
            daemons.as_object_mut().unwrap().insert(
                role.into(),
                norito::json!({
                    "command": (format!("/srv/taira/{role}/current/bin/iroha3d_taira")),
                    "resolved": (format!("/srv/taira/{role}/releases/{release}/bin/iroha3d_taira")),
                    "sha256": "b764f5485343264985e5b257433eef77a4adf64c04f695f24c093de311f8e192",
                    "size": 321112736_u64,
                }),
            );
        }
        let deployment = plan.get_mut("deployment").unwrap().as_object_mut().unwrap();
        deployment.insert(
            "runtime_root".into(),
            norito::json!("/private/runtime/taira-public-reset"),
        );
        deployment.insert("config_release".into(), norito::json!(release));
        deployment.insert(
            "current".into(),
            norito::json!({
                "kind": "observed-installation", "commit": release, "daemons": daemons,
            }),
        );
        request.operation_directory = format!(
            "/private/runtime/taira-public-reset/update-{}",
            "a".repeat(32)
        );
        (request, plan)
    }

    #[test]
    fn maintenance_scope_admits_all_four_observed_daemon_pins() -> Result<()> {
        let (request, plan) = observed_fixture();
        let scope = maintenance_scope(&request, &plan)?;
        assert_eq!(scope.previous_daemons.len(), 4);
        let paths = scope.vacant_paths();
        assert_eq!(
            &paths[..2],
            &[Path::new("/srv/taira"), Path::new("/var/lib/taira")]
        );
        for (index, role) in super::super::super::VALIDATOR_SLUGS.iter().enumerate() {
            let daemon = &scope.previous_daemons[index];
            let observed = daemon.observed.as_ref().expect("observed per-role pin");
            let release = PathBuf::from(format!(
                "/srv/taira/{role}/releases/c30e0b18cd7f5b9e1d680abe6478aea7f37ea5b9"
            ));
            assert_eq!(
                observed.selector,
                PathBuf::from(format!("/srv/taira/{role}/current"))
            );
            assert_eq!(observed.release, release);
            assert_eq!(daemon.resolved, release.join("bin/iroha3d_taira"));
            assert_eq!(paths[index + 2], daemon.resolved);
            assert_eq!(observed.size, 321112736);
            assert_eq!(
                observed.sha256,
                "b764f5485343264985e5b257433eef77a4adf64c04f695f24c093de311f8e192"
            );
        }
        assert_eq!(paths.len(), 6);
        Ok(())
    }

    #[test]
    fn maintenance_scope_rejects_incomplete_or_crossed_observed_cohorts() {
        for role in super::super::super::VALIDATOR_SLUGS {
            let (request, mut plan) = observed_fixture();
            plan.get_mut("deployment")
                .unwrap()
                .get_mut("current")
                .unwrap()
                .get_mut("daemons")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(role);
            assert!(
                maintenance_scope(&request, &plan).is_err(),
                "omitted {role}"
            );
        }
        let (request, mut plan) = observed_fixture();
        plan.get_mut("deployment")
            .unwrap()
            .get_mut("current")
            .unwrap()
            .get_mut("daemons")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("taira-validator-5".into(), norito::json!({}));
        assert!(maintenance_scope(&request, &plan).is_err());
        for (field, value) in [
            (
                "command",
                norito::json!("/srv/taira/taira-validator-3/current/bin/iroha3d_taira"),
            ),
            (
                "resolved",
                norito::json!(
                    "/srv/taira/taira-validator-3/releases/c30e0b18cd7f5b9e1d680abe6478aea7f37ea5b9/bin/iroha3d_taira"
                ),
            ),
            (
                "resolved",
                norito::json!("/private/runtime/taira/selected/bin/iroha3d_taira"),
            ),
            (
                "sha256",
                norito::json!("B764f5485343264985e5b257433eef77a4adf64c04f695f24c093de311f8e192"),
            ),
            ("sha256", norito::json!("00")),
            ("size", norito::json!(1000000_u64)),
            ("size", norito::json!(1073741824_u64)),
            ("size", norito::json!("321112736")),
            ("unexpected", norito::json!(true)),
        ] {
            let (request, mut plan) = observed_fixture();
            plan.get_mut("deployment")
                .unwrap()
                .get_mut("current")
                .unwrap()
                .get_mut("daemons")
                .unwrap()
                .get_mut("taira-validator-4")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), value);
            assert!(
                maintenance_scope(&request, &plan).is_err(),
                "changed {field}"
            );
        }
        for field in ["config_release", "current"] {
            let (request, mut plan) = observed_fixture();
            plan.get_mut("deployment")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(maintenance_scope(&request, &plan).is_err());
        }
    }

    #[test]
    fn maintenance_predecessor_kind_is_explicit_and_never_inferred() {
        for kind in ["unknown", "completed-update", "observed-installation\n"] {
            let (request, mut plan) = observed_fixture();
            *plan
                .get_mut("deployment")
                .unwrap()
                .get_mut("current")
                .unwrap()
                .get_mut("kind")
                .unwrap() = norito::json!(kind);
            assert!(maintenance_scope(&request, &plan).is_err());
        }
        let (request, mut plan) = fixture();
        plan.get_mut("deployment")
            .unwrap()
            .get_mut("current")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("kind");
        assert!(maintenance_scope(&request, &plan).is_err());
        assert!(
            text_field(&norito::json!({}), "daemon")
                .unwrap_err()
                .to_string()
                .ends_with(": daemon")
        );
    }

    #[test]
    fn observed_daemon_hash_is_exact_size_and_deadline_bounded() -> Result<()> {
        let bytes = vec![17_u8; 131073];
        let deadline = Instant::now() + Duration::from_secs(10);
        assert_eq!(
            hash_observed_daemon(bytes.as_slice(), bytes.len() as u64, deadline)?,
            sha256_hex(&bytes)
        );
        assert!(hash_observed_daemon(bytes.as_slice(), bytes.len() as u64 - 1, deadline).is_err());
        assert!(hash_observed_daemon(bytes.as_slice(), bytes.len() as u64 + 1, deadline).is_err());
        assert!(
            hash_observed_daemon(bytes.as_slice(), bytes.len() as u64, Instant::now()).is_err()
        );
        Ok(())
    }

    #[test]
    fn maintenance_scope_binds_v2_all_four_units_and_installed_runtime() -> Result<()> {
        let (request, mut plan) = fixture();
        let scope = maintenance_scope(&request, &plan)?;
        assert_eq!(scope.units.len(), 4);
        assert_eq!(
            scope.previous_daemons[0].resolved,
            Path::new("/private/runtime/taira/selected/bin/iroha3d_taira")
        );
        assert_eq!(scope.previous_daemons.len(), 1);
        assert!(scope.previous_daemons[0].observed.is_none());
        assert_eq!(scope.vacant_paths().len(), 3);
        assert_eq!(
            scope.candidate_cli,
            PathBuf::from(format!(
                "/private/runtime/taira/release-{}-update-{}/bin/iroha",
                "b".repeat(40),
                "a".repeat(32)
            ))
        );
        *plan
            .get_mut("units")
            .unwrap()
            .get_mut(3_usize)
            .unwrap()
            .get_mut("role")
            .unwrap() = norito::json!("taira-validator-3");
        assert!(maintenance_scope(&request, &plan).is_err());
        let (request, mut plan) = fixture();
        *plan
            .get_mut("units")
            .unwrap()
            .get_mut(3_usize)
            .unwrap()
            .get_mut("before")
            .unwrap() = norito::json!(BASE64.encode(b"changed"));
        assert!(maintenance_scope(&request, &plan).is_err());
        let (mut request, plan) = fixture();
        request.operation_directory.push_str("/extra");
        assert!(maintenance_scope(&request, &plan).is_err());
        let (request, mut plan) = fixture();
        *plan
            .get_mut("deployment")
            .unwrap()
            .get_mut("state_root")
            .unwrap() = norito::json!("/private/runtime/taira");
        assert!(maintenance_scope(&request, &plan).is_err());
        Ok(())
    }

    #[test]
    fn maintenance_scope_rejects_unsupported_update_contracts() {
        for schema in [
            "taira.daemon-update.plan.v1",
            "taira.daemon-update.plan.v3",
            "taira.daemon-update.plan.v2\n",
        ] {
            let (request, mut plan) = fixture();
            *plan.get_mut("schema").unwrap() = norito::json!(schema);
            assert!(maintenance_scope(&request, &plan).is_err());
        }
        for schema in ["taira.runtime-deployment.v1", "taira.runtime-deployment.v3"] {
            let (request, mut plan) = fixture();
            *plan
                .get_mut("deployment")
                .unwrap()
                .get_mut("schema")
                .unwrap() = norito::json!(schema);
            assert!(maintenance_scope(&request, &plan).is_err());
        }
        let (request, mut plan) = fixture();
        plan.as_object_mut().unwrap().insert(
            "failed_start".into(),
            norito::json!({"installed": {
                "daemon": "/private/runtime/taira/failed/bin/iroha3d_taira"}}),
        );
        assert!(maintenance_scope(&request, &plan).is_err());
    }

    #[test]
    fn maintenance_flock_requires_one_exact_live_updater_owner() -> Result<()> {
        let (request, _) = fixture();
        let valid = b"1: FLOCK ADVISORY WRITE 123 08:01:789 0 EOF\n";
        require_updater_flock(valid, &request.owner)?;
        for bad in [
            "1: FLOCK ADVISORY WRITE 124 08:01:789 0 EOF\n",
            "1: FLOCK ADVISORY READ 123 08:01:789 0 EOF\n",
            "1: POSIX ADVISORY WRITE 123 08:01:789 0 EOF\n",
            "1: FLOCK ADVISORY WRITE 123 08:01:790 0 EOF\n",
            "1: FLOCK ADVISORY WRITE 123 08:02:789 0 EOF\n",
            "1: -> FLOCK ADVISORY WRITE 123 08:01:789 0 EOF\n",
        ] {
            assert!(require_updater_flock(bad.as_bytes(), &request.owner).is_err());
        }
        assert!(require_updater_flock(&valid.repeat(2), &request.owner).is_err());
        Ok(())
    }

    #[test]
    fn maintenance_process_identity_handles_names_and_rejects_dead_owner() -> Result<()> {
        let mut fields = vec!["S", "42"];
        fields.extend(std::iter::repeat_n("0", 17));
        fields.push("456");
        let live = format!("123 (python ) worker) {}", fields.join(" "));
        assert_eq!(process_identity(live.as_bytes())?, (123, 42, 456));
        fields[0] = "Z";
        assert!(process_identity(format!("123 (python) {}", fields.join(" ")).as_bytes()).is_err());
        assert!(process_identity(b"123 (python) S 42").is_err());
        Ok(())
    }
}
