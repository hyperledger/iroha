//! Four exact public validator units for one fresh Taira reset run.
//!
//! The same-release, source-closed Python renderer remains the sole definition
//! of FD198/200 custody. Its bytes are embedded in the signed native CLI;
//! this command never opens or prints a retained signer or beacon credential.
//!
//! The renderer also defines the one-shot Sumeragi first boot (record provenance,
//! `specs/sumeragi.md` §7.4) of every unit, initial and beacon alike: the launcher
//! starts `iroha3d_taira --config … --sora` and adds `--sumeragi-assert-fresh-key`
//! only when it consumes the token `/var/lib/taira/<slug>/sumeragi-first-boot`.
//! Public reset creates that token with its authorization-marked fresh state;
//! manual provisioning uses `scripts/taira_validator_unit.py --arm-first-boot`.
//! Both require that the
//! configured `sumeragi-records` directory and `sumeragi-installation.log` are
//! absent (`specs/runbooks/sumeragi_taira_reset.md` §5).

use super::*;
use std::process::{Command, Stdio};

const RUNTIME_ROOT: &str = "/private/runtime/taira-public-reset";
const RENDERER_PATH: &str = "scripts/taira_validator_unit.py";
const RENDERER: &str = include_str!("../../../scripts/taira_validator_unit.py");
const UNIT_MAX_BYTES: usize = 1024 * 1024;
const SOURCE_MANIFEST_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PYTHON: &str = "/usr/bin/python3";
const RENDER_WRAPPER: &str = r#"import sys
namespace = {"__name__": "_taira_signed_renderer"}
exec(compile(sys.stdin.buffer.read(), "<signed-taira-validator-unit>", "exec"), namespace)
role, runtime_key, beacon_credential, config_file = sys.argv[1:]
sys.stdout.write(namespace["render"](
    role, runtime_key, beacon_credential or None, config_file=config_file
))
"#;

/// Render and publish four units under a fresh, owner-private reset run.
#[derive(clap::Args, Debug)]
pub(super) struct PrepareValidatorUnits {
    /// Same-release imported artifact directory, named by commit and result digest.
    #[arg(long, value_name = "DIR")]
    import_root: PathBuf,
    /// Owner-private native source manifest from this run.
    #[arg(long, value_name = "PATH")]
    source_manifest: PathBuf,
    /// Owner-private fresh Kagami network directory for this run.
    #[arg(long, value_name = "DIR")]
    network_dir: PathBuf,
    /// Owner-private native beacon seat map; omit for initial config.toml units.
    #[arg(long, value_name = "PATH")]
    beacon_inputs: Option<PathBuf>,
    /// Fresh owner-private directory for four public mode-0644 unit files.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[derive(JsonSerialize)]
struct UnitReceipt {
    schema: String,
    output_dir: String,
    units: u8,
    config_file: String,
}

fn checked_runtime_path(path: &Path, label: &str) -> Result<()> {
    validate_absolute_normal_path(path, label)?;
    let text = path
        .to_str()
        .ok_or_else(|| eyre!("{label} must be a UTF-8 Linux path"))?;
    if !path.starts_with(RUNTIME_ROOT)
        || path == Path::new(RUNTIME_ROOT)
        || text.contains("//")
        || text.ends_with('/')
        || text.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(eyre!(
            "{label} must be a canonical path under the approved runtime root"
        ));
    }
    Ok(())
}

fn import_commit(path: &Path) -> Result<&str> {
    checked_runtime_path(path, "release import directory")?;
    if path.parent() != Some(Path::new(RUNTIME_ROOT)) {
        return Err(eyre!(
            "release import must be an immediate runtime-root child"
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre!("release import has no canonical name"))?;
    let (commit, result_digest) = name
        .strip_prefix("release-import-")
        .and_then(|rest| rest.split_once('-'))
        .ok_or_else(|| eyre!("release import name must bind commit and preparation result"))?;
    validate_lower_hex("release import commit", commit, 40)?;
    validate_lower_hex("release import result digest", result_digest, 64)?;
    Ok(commit)
}

fn read_owned_json<T: JsonDeserialize>(
    path: &Path,
    label: &str,
    maximum: u64,
) -> Result<(T, PinnedInput)> {
    let pin = pin_owner_private_file(path, label)?;
    if pin.snapshot.len == 0 || pin.snapshot.len > maximum {
        return Err(eyre!("{label} is empty or exceeds its bound"));
    }
    let bytes = read_pinned_bytes(path, label, pin.file.try_clone()?, &pin.snapshot, maximum)?;
    let value = json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to decode exact Norito JSON {label}"))?;
    revalidate_pinned(&pin, label)?;
    Ok((value, pin))
}

fn checked_renderer_manifest(manifest: &SourceManifestV1, commit: &str) -> Result<()> {
    if manifest.schema != SOURCE_MANIFEST_SCHEMA_V1
        || manifest.branch != SOURCE_BRANCH
        || manifest.head_commit_sha1 != commit
        || !manifest.untracked_files.is_empty()
        || manifest.tracked_files.is_empty()
        || manifest.tracked_files.len() > MAX_SOURCE_FILES
    {
        return Err(eyre!(
            "native source manifest differs from the imported release"
        ));
    }
    let renderer = manifest
        .tracked_files
        .iter()
        .filter(|entry| entry.path == RENDERER_PATH)
        .collect::<Vec<_>>();
    if renderer.len() != 1
        || renderer[0].mode != 0o644
        || renderer[0].size != RENDERER.len() as u64
        || renderer[0].sha256 != sha256_hex(RENDERER.as_bytes())
    {
        return Err(eyre!(
            "signed source manifest does not bind the native unit renderer"
        ));
    }
    Ok(())
}

fn check_run_paths(args: &PrepareValidatorUnits) -> Result<()> {
    for (path, label) in [
        (&args.source_manifest, "source manifest"),
        (&args.network_dir, "generated network directory"),
        (&args.output_dir, "validator unit output directory"),
    ] {
        checked_runtime_path(path, label)?;
    }
    if args.network_dir.file_name().and_then(|name| name.to_str()) != Some("network") {
        return Err(eyre!(
            "generated network directory must be the run's network directory"
        ));
    }
    let run = args
        .network_dir
        .parent()
        .ok_or_else(|| eyre!("generated network has no reset run"))?;
    if run == Path::new(RUNTIME_ROOT)
        || run.parent() != Some(Path::new(RUNTIME_ROOT))
        || args.source_manifest != run.join("source-manifest.json")
        || args.output_dir.parent() != Some(run)
    {
        return Err(eyre!(
            "manifest, network, and units must share one reset run"
        ));
    }
    let (expected_output, expected_beacon) = if args.beacon_inputs.is_some() {
        ("units-beacon", Some(run.join("beacon-inputs.json")))
    } else {
        ("units-initial", None)
    };
    if args.output_dir.file_name().and_then(|name| name.to_str()) != Some(expected_output)
        || args.beacon_inputs != expected_beacon
    {
        return Err(eyre!(
            "unit output and beacon inputs differ from the selected phase"
        ));
    }
    validate_owner_private_dir(run, "reset run directory")?;
    validate_owner_private_dir(&args.network_dir, "generated network directory")?;
    Ok(())
}

fn render_one(
    role: &str,
    runtime_key: &Path,
    beacon_credential: Option<&str>,
    config_file: &str,
) -> Result<Vec<u8>> {
    let runtime_key = runtime_key
        .to_str()
        .ok_or_else(|| eyre!("runtime signer path is not UTF-8"))?;
    let mut child = Command::new(PYTHON)
        .args([
            "-I",
            "-c",
            RENDER_WRAPPER,
            role,
            runtime_key,
            beacon_credential.unwrap_or(""),
            config_file,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .wrap_err("failed to launch the fixed embedded unit renderer")?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.wait();
        return Err(eyre!("unit renderer stdin is unavailable"));
    };
    if let Err(error) = stdin.write_all(RENDERER.as_bytes()) {
        drop(stdin);
        let _ = child.wait();
        return Err(error).wrap_err("failed to send embedded unit renderer");
    }
    drop(stdin);
    let rendered = child.wait_with_output()?;
    if !rendered.status.success()
        || rendered.stdout.is_empty()
        || rendered.stdout.len() > UNIT_MAX_BYTES
    {
        return Err(eyre!(
            "embedded unit renderer rejected an exact validator role or path"
        ));
    }
    Ok(rendered.stdout)
}

#[cfg(unix)]
fn existing_matches(path: &Path, units: &[(String, Vec<u8>)]) -> Result<()> {
    validate_owner_private_dir(path, "published validator unit directory")?;
    let names = fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| eyre!("published unit name is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = units
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    if names != expected {
        return Err(eyre!(
            "published validator unit set is incomplete or foreign"
        ));
    }
    for (name, bytes) in units {
        let path = path.join(name);
        let (file, snapshot) = open_pinned_regular(&path, "published validator unit")?;
        if snapshot.uid != rustix::process::geteuid().as_raw()
            || snapshot.mode & 0o7777 != 0o644
            || snapshot.len != bytes.len() as u64
            || read_pinned_bytes(
                &path,
                "published validator unit",
                file,
                &snapshot,
                UNIT_MAX_BYTES as u64,
            )? != *bytes
        {
            return Err(eyre!(
                "published validator unit differs from signed renderer"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn publish_units(path: &Path, units: &[(String, Vec<u8>)]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("validator unit output has no parent"))?;
    validate_owner_private_dir(parent, "validator unit output parent")?;
    if path.try_exists()? {
        return existing_matches(path, units);
    }
    let temporary = tempfile::Builder::new()
        .prefix(".validator-units-")
        .tempdir_in(parent)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in units {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary.path().join(name))?;
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
    }
    File::open(temporary.path())?.sync_all()?;
    validate_owner_private_dir(parent, "validator unit output parent")?;
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        temporary.path(),
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => existing_matches(path, units)?,
        Err(error) => return Err(error).wrap_err("publish validator units without replacement"),
    }
    File::open(parent)?.sync_all()?;
    existing_matches(path, units)
}

/// Prepare the exact four-unit bundle; replays require an identical complete bundle.
#[cfg(unix)]
pub(super) fn prepare(args: &PrepareValidatorUnits, output: &mut impl Write) -> Result<()> {
    let commit = import_commit(&args.import_root)?;
    validate_owner_private_dir(&args.import_root, "same-release imported artifacts")?;
    check_run_paths(args)?;
    // Distributions commonly make /usr/bin/python3 a root-owned symlink. Check
    // its resolved, direct executable using the same custody rule as the
    // validator launcher, while retaining the fixed interpreter invocation.
    let python = fs::canonicalize(PYTHON)?;
    validate_fixed_executable(&python, "embedded unit renderer")?;
    let (manifest, manifest_pin) = read_owned_json::<SourceManifestV1>(
        &args.source_manifest,
        "native signed source manifest",
        SOURCE_MANIFEST_MAX_BYTES,
    )?;
    checked_renderer_manifest(&manifest, commit)?;
    let (credentials, beacon_pin, config_file) = if let Some(path) = &args.beacon_inputs {
        let (beacon, pin) = read_owned_json::<host::beacon::PreparedBeaconInputsV1>(
            path,
            "native beacon inputs",
            MAX_JSON_BYTES,
        )?;
        (
            host::beacon::validated_unit_credential_paths(&beacon)?,
            Some(pin),
            "beacon.toml",
        )
    } else {
        (std::array::from_fn(|_| None), None, "config.toml")
    };
    let mut units = Vec::with_capacity(4);
    for (index, slug) in VALIDATOR_SLUGS.iter().enumerate() {
        let runtime_key = args.network_dir.join(format!(
            "runtime/taira-runtime-signers/peer{index}.private_key"
        ));
        let bytes = render_one(
            slug,
            &runtime_key,
            credentials[index].as_deref(),
            config_file,
        )?;
        units.push((format!("iroha3d-{slug}.service"), bytes));
    }
    revalidate_pinned(&manifest_pin, "native signed source manifest")?;
    if let Some(pin) = &beacon_pin {
        revalidate_pinned(pin, "native beacon inputs")?;
    }
    publish_units(&args.output_dir, &units)?;
    revalidate_pinned(&manifest_pin, "native signed source manifest")?;
    if let Some(pin) = &beacon_pin {
        revalidate_pinned(pin, "native beacon inputs")?;
    }
    let receipt = UnitReceipt {
        schema: "iroha.taira.public-reset.validator-units.v1".into(),
        output_dir: args.output_dir.display().to_string(),
        units: 4,
        config_file: config_file.into(),
    };
    writeln!(output, "{}", json::to_json(&receipt)?)?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn prepare(_args: &PrepareValidatorUnits, _output: &mut impl Write) -> Result<()> {
    Err(eyre!(
        "validator unit preparation requires a Unix operator host"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Cmd {
        #[command(flatten)]
        units: PrepareValidatorUnits,
    }

    #[test]
    fn parser_requires_exact_publication_inputs() {
        let parsed = Cmd::try_parse_from([
            "test", "--import-root", "/private/runtime/taira-public-reset/release-import-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--source-manifest", "/private/runtime/taira-public-reset/cutover-aaaaaaaa-bbbbbbbb/source-manifest.json",
            "--network-dir", "/private/runtime/taira-public-reset/cutover-aaaaaaaa-bbbbbbbb/network",
            "--output-dir", "/private/runtime/taira-public-reset/cutover-aaaaaaaa-bbbbbbbb/units-initial",
        ]).expect("required inputs parse");
        assert!(parsed.units.beacon_inputs.is_none());
        assert!(Cmd::try_parse_from(["test", "--network-dir", "/tmp/network"]).is_err());
    }

    #[test]
    fn imported_release_and_run_paths_must_be_exact() {
        let valid = Path::new(
            "/private/runtime/taira-public-reset/release-import-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert_eq!(
            import_commit(valid).unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(
            import_commit(Path::new(
                "/private/runtime/taira-public-reset/release-import-aaaaaaaa-cccc"
            ))
            .is_err()
        );
        assert!(
            checked_runtime_path(
                Path::new("/private/runtime/taira-public-reset//run"),
                "test"
            )
            .is_err()
        );
        assert!(
            checked_runtime_path(
                Path::new("/private/runtime/taira-public-reset/../other"),
                "test"
            )
            .is_err()
        );
    }

    #[test]
    fn embedded_renderer_keeps_exact_roles_fds_and_config_selection() {
        for (index, slug) in VALIDATOR_SLUGS.iter().enumerate() {
            let base = "/private/runtime/taira-public-reset/run/network/runtime";
            let runtime =
                Path::new(&base).join(format!("taira-runtime-signers/peer{index}.private_key"));
            let initial = render_one(slug, &runtime, None, "config.toml").unwrap();
            let initial = String::from_utf8(initial).unwrap();
            assert!(initial.contains(&format!("Description=Taira {slug}\n")));
            assert!(initial.contains("reserved_fds = (198, 200)"));
            assert!(initial.contains("stage_signer(runtime_key, 198, 71"));
            assert!(initial.contains("/config/config.toml"));
            assert!(!initial.contains("/config/beacon.toml"));
            let beacon = render_one(
                slug,
                &runtime,
                Some("/var/lib/taira/beacon/credential.norito"),
                "beacon.toml",
            )
            .unwrap();
            let beacon = String::from_utf8(beacon).unwrap();
            assert!(beacon.contains("/config/beacon.toml"));
            assert!(beacon.contains("stage_signer(global_beacon_credential, 200"));
            assert!(beacon.contains("/var/lib/taira/beacon/credential.norito"));
            assert_ne!(initial, beacon);
        }
    }

    #[test]
    fn embedded_renderer_carries_the_one_shot_first_boot_contract() {
        let base = "/private/runtime/taira-public-reset/run/network/runtime";
        for (index, slug) in VALIDATOR_SLUGS.iter().enumerate() {
            let runtime =
                Path::new(base).join(format!("taira-runtime-signers/peer{index}.private_key"));
            let state = format!("/var/lib/taira/{slug}");
            let current = format!("/srv/taira/{slug}/current");
            for (credential, config_file) in [
                (None, "config.toml"),
                (
                    Some("/var/lib/taira/beacon/credential.norito"),
                    "beacon.toml",
                ),
            ] {
                let unit =
                    String::from_utf8(render_one(slug, &runtime, credential, config_file).unwrap())
                        .unwrap();
                // The token and the configured Sumeragi history share the unit's state root.
                assert!(unit.contains(&format!("WorkingDirectory={state}\n")));
                assert!(unit.contains(&format!("state_root = '{state}'")));
                assert!(
                    unit.contains(&format!("first_boot_token = '{state}/sumeragi-first-boot'"))
                );
                assert!(unit.contains(&format!(
                    "sumeragi_history = ('{state}/sumeragi-records', \
                     '{state}/sumeragi-installation.log')"
                )));
                // Native unit capture reads one literal daemon argv, as `daemon_in_unit` does;
                // only a consumed token appends the assertion to it.
                let argv = unit
                    .split("\\n")
                    .filter(|line| line.starts_with("cmd = ['"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    argv,
                    [format!(
                        "cmd = ['{current}/bin/iroha3d_taira', '--config', \
                         '{current}/config/{config_file}', '--sora']"
                    )]
                );
                assert_eq!(unit.matches("--sumeragi-assert-fresh-key").count(), 1);
                assert!(unit.contains("launch_argv = cmd + ['--sumeragi-assert-fresh-key']"));
            }
        }
    }

    #[test]
    fn renderer_manifest_must_bind_the_embedded_source_bytes() {
        let commit = "a".repeat(40);
        let mut manifest = SourceManifestV1 {
            schema: SOURCE_MANIFEST_SCHEMA_V1.into(),
            branch: SOURCE_BRANCH.into(),
            head_commit_sha1: commit.clone(),
            head_tree_sha1: "b".repeat(40),
            cargo_lock_sha256: "c".repeat(64),
            tracked_files: vec![SourceFileV1 {
                path: RENDERER_PATH.into(),
                mode: 0o644,
                size: RENDERER.len() as u64,
                git_blob_sha1: "d".repeat(40),
                sha256: sha256_hex(RENDERER.as_bytes()),
            }],
            untracked_files: Vec::new(),
            closure_sha256: "e".repeat(64),
        };
        checked_renderer_manifest(&manifest, &commit).unwrap();
        manifest.tracked_files[0].sha256 = "f".repeat(64);
        assert!(checked_renderer_manifest(&manifest, &commit).is_err());
        manifest.tracked_files[0].sha256 = sha256_hex(RENDERER.as_bytes());
        manifest.branch = "foreign".into();
        assert!(checked_renderer_manifest(&manifest, &commit).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publication_is_exact_and_replay_rejects_partial_or_changed_units() {
        use std::os::unix::fs::MetadataExt as _;

        let root = private_custody_test_dir("validator-unit-test-");
        let output = root.path().join("units-initial");
        let units = VALIDATOR_SLUGS
            .iter()
            .map(|slug| (format!("iroha3d-{slug}.service"), b"public unit\n".to_vec()))
            .collect::<Vec<_>>();
        publish_units(&output, &units).unwrap();
        publish_units(&output, &units).unwrap();
        let first = output.join(&units[0].0);
        assert_eq!(fs::metadata(&first).unwrap().mode() & 0o7777, 0o644);
        fs::write(&first, b"altered unit\n").unwrap();
        assert!(publish_units(&output, &units).is_err());
        fs::remove_file(&first).unwrap();
        assert!(publish_units(&output, &units).is_err());
    }
}
