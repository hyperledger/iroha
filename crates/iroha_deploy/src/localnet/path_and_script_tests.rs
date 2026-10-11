#[test]
fn relative_out_dir_paths_are_absolute_in_configs() {
    struct DirGuard {
        prev: PathBuf,
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            env::set_current_dir(&self.prev).expect("restore current dir");
        }
    }

    let base = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let previous = env::current_dir().expect("current dir");
    env::set_current_dir(base.path()).expect("chdir into temp");
    let _guard = DirGuard { prev: previous };

    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: Some("absolute-paths".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 19081,
        base_p2p_port: 23338,
        out_dir: PathBuf::from("localnet"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };

    let mut handoff = BufWriter::new(Vec::new());
    generate_localnet(&opts, &mut handoff).expect("generate localnet with relative path");
    let handoff = String::from_utf8(handoff.into_inner().expect("flush localnet handoff"))
        .expect("localnet handoff is UTF-8");

    let out_dir = fs::canonicalize(base.path().join("localnet"))
        .expect("canonical generated localnet output directory");
    assert!(handoff.contains(&out_dir.display().to_string()));
    let shell_out_dir = crate::shell::absolute_quote_path(&out_dir)
        .expect("quote canonical localnet output directory");
    let readme = fs::read_to_string(out_dir.join("README.md")).expect("read localnet guide");
    assert!(readme.contains(&format!("cd {shell_out_dir}")));
    let peer_cfg = fs::read_to_string(out_dir.join("peer0.toml")).expect("read peer config");
    let parsed: toml::Value = toml::from_str(&peer_cfg).expect("parse peer config");
    let genesis_path = parsed
        .get("genesis")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("file"))
        .and_then(toml::Value::as_str)
        .expect("genesis path");
    let kura_path = parsed
        .get("kura")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("store_dir"))
        .and_then(toml::Value::as_str)
        .expect("kura store");
    let soracloud_runtime_path = parsed
        .get("soracloud_runtime")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("state_dir"))
        .and_then(toml::Value::as_str)
        .expect("soracloud runtime state dir");
    let tiered_state = parsed
        .get("tiered_state")
        .and_then(toml::Value::as_table)
        .expect("tiered_state table");
    let tiered_root = tiered_state
        .get("cold_store_root")
        .and_then(toml::Value::as_str)
        .expect("tiered_state cold_store_root");
    let da_root = tiered_state
        .get("da_store_root")
        .and_then(toml::Value::as_str)
        .expect("tiered_state da_store_root");
    let rans_tables_path = parsed
        .get("streaming")
        .and_then(toml::Value::as_table)
        .and_then(|streaming| streaming.get("codec"))
        .and_then(toml::Value::as_table)
        .and_then(|codec| codec.get("rans_tables_path"))
        .and_then(toml::Value::as_str)
        .expect("streaming codec rANS tables path");
    assert!(
        Path::new(genesis_path).is_absolute(),
        "genesis path should be absolute"
    );
    assert!(
        Path::new(kura_path).is_absolute(),
        "kura store path should be absolute"
    );
    assert!(
        Path::new(soracloud_runtime_path).is_absolute(),
        "soracloud runtime state_dir should be absolute"
    );
    let peer_state_path = Path::new(kura_path)
        .parent()
        .and_then(Path::parent)
        .expect("Kura path lives below the localnet output root")
        .join("state")
        .join("peer0");
    assert!(
        Path::new(soracloud_runtime_path).starts_with(&peer_state_path)
            && !Path::new(soracloud_runtime_path).starts_with(Path::new(kura_path)),
        "soracloud runtime state_dir must remain outside the pristine Kura root"
    );
    assert!(
        Path::new(tiered_root).is_absolute(),
        "tiered_state cold_store_root should be absolute"
    );
    assert!(
        Path::new(da_root).is_absolute(),
        "tiered_state da_store_root should be absolute"
    );
    let expected_rans_tables_path =
        fs::canonicalize(out_dir.join(LOCALNET_RANS_TABLE_RELATIVE_PATH))
            .expect("canonical generated rANS table");
    assert!(
        Path::new(rans_tables_path).is_absolute(),
        "streaming codec rANS tables path should be absolute"
    );
    assert_eq!(
        Path::new(rans_tables_path),
        expected_rans_tables_path,
        "streaming codec must bind the rANS table emitted into its output directory"
    );
    assert!(
        Path::new(tiered_root).starts_with(&peer_state_path)
            && Path::new(da_root).starts_with(&peer_state_path)
            && !Path::new(tiered_root).starts_with(Path::new(kura_path))
            && !Path::new(da_root).starts_with(Path::new(kura_path)),
        "auxiliary state roots must remain outside the pristine Kura root"
    );
    for peer_index in 0..opts.peers.get() {
        let peer_config: toml::Value = toml::from_str(
            &fs::read_to_string(out_dir.join(format!("peer{peer_index}.toml")))
                .expect("read generated peer config"),
        )
        .expect("parse generated peer config");
        let expected_state = out_dir.join("state").join(format!("peer{peer_index}"));
        let streaming = peer_config
            .get("streaming")
            .and_then(toml::Value::as_table)
            .expect("streaming table");
        let session_store = streaming
            .get("session_store_dir")
            .and_then(toml::Value::as_str)
            .expect("streaming session store");
        let torii_data = peer_config
            .get("torii")
            .and_then(toml::Value::as_table)
            .and_then(|torii| torii.get("data_dir"))
            .and_then(toml::Value::as_str)
            .expect("Torii data directory");
        let torii_da = peer_config
            .get("torii")
            .and_then(toml::Value::as_table)
            .and_then(|torii| torii.get("da_ingest"))
            .and_then(toml::Value::as_table)
            .expect("Torii DA ingest table");
        let torii_da_replay = torii_da
            .get("replay_cache_store_dir")
            .and_then(toml::Value::as_str)
            .expect("Torii DA replay-cache directory");
        let torii_da_manifests = torii_da
            .get("manifest_store_dir")
            .and_then(toml::Value::as_str)
            .expect("Torii DA manifest directory");
        let sorafs_data = peer_config
            .get("sorafs")
            .and_then(toml::Value::as_table)
            .and_then(|sorafs| sorafs.get("storage"))
            .and_then(toml::Value::as_table)
            .and_then(|storage| storage.get("data_dir"))
            .and_then(toml::Value::as_str)
            .expect("SoraFS data directory");
        let sorafs_por_state = peer_config
            .get("sorafs")
            .and_then(toml::Value::as_table)
            .and_then(|sorafs| sorafs.get("por"))
            .and_then(toml::Value::as_table)
            .and_then(|por| por.get("state_dir"))
            .and_then(toml::Value::as_str)
            .expect("SoraFS PoR state directory");
        let soranet_ticket_revocations = peer_config
            .get("network")
            .and_then(toml::Value::as_table)
            .and_then(|network| network.get("soranet_handshake"))
            .and_then(toml::Value::as_table)
            .and_then(|handshake| handshake.get("pow"))
            .and_then(toml::Value::as_table)
            .and_then(|pow| pow.get("revocation_store_path"))
            .and_then(toml::Value::as_str)
            .expect("SoraNet ticket revocation store");
        assert_eq!(Path::new(session_store), expected_state.join("streaming"));
        assert_eq!(Path::new(torii_data), expected_state.join("torii"));
        assert_eq!(
            Path::new(torii_da_replay),
            expected_state.join("torii").join("da_replay")
        );
        assert_eq!(
            Path::new(torii_da_manifests),
            expected_state.join("torii").join("da_manifests")
        );
        assert_eq!(Path::new(sorafs_data), expected_state.join("sorafs"));
        assert_eq!(
            Path::new(sorafs_por_state),
            expected_state.join("sorafs").join("por")
        );
        assert_eq!(
            Path::new(soranet_ticket_revocations),
            expected_state
                .join("soranet")
                .join("ticket_revocations.norito")
        );
    }
    assert!(
        fs::read_dir(kura_path)
            .expect("read pristine Kura root")
            .next()
            .is_none(),
        "generated localnet must leave the Kura root pristine for catalog binding"
    );
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn start_and_stop_scripts_are_executable() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let client_account_literal = localnet_client_account_literal(None);
    let fee_asset_definition_id = localnet_xor_asset_literal();
    write_scripts(
        temp.path(),
        1,
        false,
        false,
        &client_account_literal,
        &fee_asset_definition_id,
    )
    .expect("write scripts");

    let start_path = temp.path().join("start.sh");
    let stop_path = temp.path().join("stop.sh");
    let start_mode = fs::metadata(&start_path)
        .expect("start metadata")
        .permissions()
        .mode();
    let stop_mode = fs::metadata(&stop_path)
        .expect("stop metadata")
        .permissions()
        .mode();
    assert_ne!(
        start_mode & 0o111,
        0,
        "start script should be marked executable"
    );
    assert_ne!(
        stop_mode & 0o111,
        0,
        "stop script should be marked executable"
    );

    let start_contents = fs::read_to_string(&start_path).expect("read start script");
    assert_eq!(
        start_contents.lines().take(3).collect::<Vec<_>>(),
        ["#!/usr/bin/env bash", "set -euo pipefail", "umask 077"],
        "generated startup must keep logs, pidfiles, and runtime directories owner-only",
    );
    let (debug_path, release_path) = default_irohad_bin_paths(false);
    let expected_debug = format!(
        "DEFAULT_IROHAD_BIN_DEBUG={}",
        crate::shell::quote_path(&debug_path).expect("quote debug path")
    );
    let expected_release = format!(
        "DEFAULT_IROHAD_BIN_RELEASE={}",
        crate::shell::quote_path(&release_path).expect("quote release path")
    );
    assert!(
        start_contents.lines().any(|line| line == expected_debug),
        "start script should set debug default"
    );
    assert!(
        start_contents.lines().any(|line| line == expected_release),
        "start script should set release default"
    );
    assert!(
        start_contents.contains("if [ -x \"$DEFAULT_IROHAD_BIN_DEBUG\" ]; then"),
        "start script should prefer the debug iroha3d for local contract development"
    );
    assert!(
        start_contents.contains("elif [ -x \"$DEFAULT_IROHAD_BIN_RELEASE\" ]; then"),
        "start script should fall back to the release iroha3d when no debug binary exists"
    );
    assert!(
        start_contents.contains("DEFAULT_IROHA_CLI_RELEASE="),
        "start script should also wire the iroha CLI defaults"
    );
    assert!(start_contents.contains("explicit genesis allocation"));
    assert!(!start_contents.contains("ledger asset mint"));
    assert!(!start_contents.contains("FAUCET_RESERVE_TARGET="));
    assert!(!start_contents.contains("FAUCET_RESERVE_RETRIES="));
    assert!(!start_contents.contains("faucet-topup"));
    assert!(!start_contents.contains("gas_asset_id"));
    assert!(
        start_contents.contains("start_new_session=True"),
        "start script should detach peers into a new session"
    );
    assert!(
        start_contents.contains("subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, close_fds=True, start_new_session=True)"),
        "ordinary peers must launch with their log and fresh process session"
    );
    assert!(!start_contents.contains("nohup env SNAPSHOT_STORE_DIR="));
    assert!(start_contents.contains("python3 is required to launch localnet validators"));
    assert!(
        start_contents.contains("SNAPSHOT_STORE_DIR=\"$DIR/state/peer${i}/snapshot\""),
        "snapshot state must remain outside the pristine Kura root"
    );
    assert!(
        start_contents.contains("mkdir -p \"$SNAPSHOT_STORE_DIR/generations\""),
        "start script should create the snapshot generations directory"
    );
    assert!(
        start_contents.contains("peer$i already running with pid $existing_pid"),
        "start script should refuse to overwrite live pidfiles"
    );
    assert!(
        start_contents.contains("pid_is_running()")
            && start_contents.contains("pid_is_running \"$existing_pid\""),
        "start script should probe pid liveness without null signals"
    );
    assert!(
        start_contents.contains("command -v ps >/dev/null 2>&1 || return 0"),
        "start script should treat missing ps as live rather than stale"
    );
    assert!(
        !start_contents.contains("kill -0"),
        "start script should not use null-signal pid probes"
    );
    assert!(
        start_contents.contains("rm -f \"$PIDFILE\""),
        "start script should clear stale pidfiles before relaunch"
    );
    let stop_contents = fs::read_to_string(&stop_path).expect("read stop script");
    assert_eq!(
        stop_contents.lines().take(3).collect::<Vec<_>>(),
        ["#!/usr/bin/env bash", "set -euo pipefail", "umask 077"],
        "generated shutdown must preserve owner-only runtime custody",
    );
    assert!(
        stop_contents.contains("pid_matches_peer()"),
        "stop script should validate pid ownership before signaling"
    );
    assert!(
        stop_contents.contains("pid_is_running()"),
        "stop script should probe pid liveness without null signals"
    );
    assert!(
        stop_contents.contains("command -v ps >/dev/null 2>&1 || return 0"),
        "stop script should treat missing ps as live rather than stale"
    );
    assert!(
        !stop_contents.contains("kill -0"),
        "stop script should not use null-signal pid probes"
    );
    assert!(
        stop_contents.contains("grep -F -- \"--config $config\""),
        "stop script should bind live pid checks to the peer config path"
    );
    assert!(
        stop_contents.contains("live pid $pid does not match $config"),
        "stop script should leave reused pidfiles untouched"
    );
    assert!(
        !stop_contents.contains("kill -9 \"$pid\""),
        "stop script should not escalate to SIGKILL"
    );
    assert!(
        stop_contents.contains("localnet peer $peer_name pid $pid is still running"),
        "stop script should leave still-running owned peers visible"
    );
    assert!(
        stop_contents.contains("rm -f \"$pidfile\""),
        "stop script should clean pidfiles after shutdown"
    );
}

#[cfg(unix)]
#[test]
fn ordinary_localnet_launcher_detaches_and_logs_without_private_descriptors() {
    let root = localnet_test_helpers::private_tempdir().unwrap();
    let start_path = root.path().join("start.sh");
    write_start_script(
        &start_path,
        1,
        false,
        false,
        &localnet_client_account_literal(None),
        &localnet_xor_asset_literal(),
    )
    .unwrap();
    let start = fs::read_to_string(&start_path).unwrap();
    let body = start
        .split("<<'PY'\n")
        .nth(1)
        .unwrap()
        .split("\nPY\n")
        .next()
        .unwrap();
    let python = format!("{body}\nassert process.wait(timeout=10) == 0\n");
    let daemon = root.path().join("daemon");
    custody::write(
        &daemon,
        br#"#!/usr/bin/env python3
import errno, os, sys
assert os.getsid(0) == os.getpid()
assert os.getpgrp() == os.getpid()
for descriptor in (198, 199, 200):
    try:
        os.fstat(descriptor)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("ordinary validator inherited a private descriptor")
assert sys.argv[1:] == ["--config", os.environ["IROHA_PEER_CONFIG"]]
print("ordinary stdout")
print("ordinary stderr", file=sys.stderr)
"#,
    )
    .unwrap();
    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o700)).unwrap();
    let log = root.path().join("peer0.log");
    for _ in 0..2 {
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(&python)
            .env("IROHAD_BIN", &daemon)
            .env("IROHA_SORA_MODE", "0")
            .env("IROHA_PEER_FRESH_KEY", "")
            .env("IROHA_PEER_CONFIG", root.path().join("peer0.toml"))
            .env("IROHA_PEER_LOG", &log)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap()
                > 0
        );
    }
    let log = fs::read_to_string(log).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| *line == "ordinary stdout")
            .count(),
        2
    );
    assert_eq!(
        log.lines()
            .filter(|line| *line == "ordinary stderr")
            .count(),
        2
    );
    assert!(!root.path().join("runtime/mint-finality-signers").exists());
}

/// Drives the stock Taira launcher three times with a child that consumes FD 198 and FD 200 in
/// the daemon's order, alternating whether the launcher returns before the child's
/// post-consumption check ("launcher-first") or only after it ("daemon-check-first"). Linux
/// pidfd identity capture is replaced by a double that only orders the launcher's return.
#[cfg(unix)]
const TAIRA_LAUNCH_ORDER_HARNESS_PY: &str = r#"
CONSUME = """
import os, sys, time
order, markers, attempt = sys.argv[1], sys.argv[2], sys.argv[3]
def wait_for(path):
    deadline = time.monotonic() + 20.0
    while not os.path.exists(path):
        if time.monotonic() >= deadline:
            sys.exit("timed out waiting for " + path)
        time.sleep(0.01)
consumed = []
for descriptor, size in ((198, 71), (200, 257)):
    before = os.fstat(descriptor)
    if before.st_nlink != 1 or before.st_size != size:
        sys.exit("the launcher changed a one-shot path before consumption")
    if len(os.read(descriptor, size + 1)) != size:
        sys.exit("short one-shot record")
    os.lseek(descriptor, 0, 0)
    if os.write(descriptor, bytes(size)) != size:
        sys.exit("short erasure")
    os.fsync(descriptor)
    os.ftruncate(descriptor, 0)
    os.fsync(descriptor)
    consumed.append((descriptor, before))
if order == "launcher-first":
    wait_for(os.path.join(markers, "returned-" + attempt))
for descriptor, before in consumed:
    after = os.fstat(descriptor)
    if (after.st_dev, after.st_ino, after.st_nlink, after.st_size) != (before.st_dev, before.st_ino, 1, 0):
        sys.exit("a one-shot path changed before the post-consumption check")
open(os.path.join(markers, "checked-" + attempt), "w").close()
print("checked " + order, flush=True)
"""

def _wait_for_marker(path):
    deadline = time.monotonic() + 20.0
    while not os.path.exists(path):
        if time.monotonic() >= deadline:
            raise RuntimeError("timed out waiting for " + path)
        time.sleep(0.01)

ORDER = None
ATTEMPT = None

def capture_taira_start(pid, record_path, peer_index, expected_argv):
    if ORDER == "daemon-check-first":
        _wait_for_marker(os.path.join(markers, "checked-" + ATTEMPT))

env = os.environ.copy()
network = env["IROHA_NETWORK_DIR"]
markers = os.path.join(network, "markers")
os.mkdir(markers, 0o700)
records = [
    (os.path.join(network, "runtime", "taira-runtime-signers", "peer0.private_key"),
     os.path.join(network, "runtime", "taira-runtime-signers", "peer0.fd198"), 71, 198),
    (os.path.join(network, "runtime", "beacon-credential"),
     os.path.join(network, "runtime", "peer0.fd200"), 257, 200),
]
def selection():
    return {"initial_config": os.path.join(network, "initial.toml"), "initial_identity": _taira_file_identity(os.lstat(os.path.join(network, "initial.toml"))),
        "beacon_config": os.path.join(network, "beacon.toml"), "beacon_identity": _taira_file_identity(os.lstat(os.path.join(network, "beacon.toml"))),
        "sources": [{"path": source, "size": size, "descriptor": descriptor, "identity": _taira_file_identity(os.lstat(source))} for source, _launch, size, descriptor in records]}
for attempt, order in enumerate(("launcher-first", "daemon-check-first", "launcher-first")):
    ORDER, ATTEMPT = order, str(attempt)
    process = launch_taira_process([sys.executable, "-c", CONSUME, order, markers, ATTEMPT], env, records, selection())
    open(os.path.join(markers, "returned-" + ATTEMPT), "w").close()
    if process.wait(timeout=30) != 0:
        raise RuntimeError("the consuming child failed in order " + order)
    for _source, launch, _size, _descriptor in records:
        consumed = os.lstat(launch)
        if not stat.S_ISREG(consumed.st_mode) or consumed.st_nlink != 1 or consumed.st_size != 0:
            raise RuntimeError("the launcher changed a consumed one-shot path after start")
"#;

#[cfg(unix)]
#[test]
fn taira_launcher_keeps_consumed_launch_paths_in_either_consumption_order() {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let root =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("private localnet root");
    let runtime = root.path().join("runtime");
    let signer_dir = runtime.join(TAIRA_RUNTIME_SIGNER_DIRECTORY);
    for directory in [&signer_dir] {
        fs::create_dir_all(directory).expect("create private record directory");
    }
    for directory in [&runtime, &signer_dir] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protect record directories");
    }
    let retained = [
        (signer_dir.join("peer0.private_key"), vec![0x41; 71]),
        (runtime.join("beacon-credential"), vec![0x66; 257]),
    ];
    for (path, bytes) in &retained {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create retained record");
        file.write_all(bytes).expect("write retained record");
        file.sync_all().expect("sync retained record");
    }

    custody::write(root.path().join("initial.toml"), b"initial exact bytes").unwrap();
    custody::write(root.path().join("beacon.toml"), b"projected exact bytes").unwrap();

    // On a successful start the launcher keeps each one-shot path, so the daemon's
    // post-consumption check sees one link in either order and the next start replaces the
    // consumed file: the launcher never races the daemon for the pathname.
    let python = format!(
        "import errno\nimport os\nimport stat\nimport subprocess\nimport sys\nimport time\n{TAIRA_RUNTIME_LAUNCH_PY}{TAIRA_LAUNCH_ORDER_HARNESS_PY}"
    );
    let log = root.path().join("peer0.log");
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(python)
        .env("IROHA_NETWORK_DIR", root.path())
        .env("IROHA_PEER_INDEX", "0")
        .env("IROHA_PEER_LOG", &log)
        .env(
            "IROHA_PEER_PROCESS_RECORD",
            root.path().join("peer0.process.json"),
        )
        .output()
        .expect("run stock Taira descriptor launcher");
    assert!(
        output.status.success(),
        "Taira launcher order check failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&log).unwrap_or_default()
    );
    assert_eq!(
        fs::read_to_string(&log)
            .expect("read child log")
            .lines()
            .collect::<Vec<_>>(),
        [
            "checked launcher-first",
            "checked daemon-check-first",
            "checked launcher-first"
        ]
    );
    for (path, bytes) in &retained {
        assert_eq!(&fs::read(path).expect("retained record"), bytes);
        assert_eq!(fs::metadata(path).expect("retained metadata").nlink(), 1);
    }
    for launch in [signer_dir.join("peer0.fd198"), runtime.join("peer0.fd200")] {
        assert_eq!(fs::metadata(launch).expect("consumed launch path").len(), 0);
    }
}

#[cfg(unix)]
#[test]
fn taira_lifecycle_is_exact_process_record_and_pidfd_only() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    write_scripts(
        temp.path(),
        4,
        true,
        true,
        &localnet_client_account_literal(Some(369)),
        &localnet_xor_asset_literal(),
    )
    .expect("write Taira scripts");

    let start = fs::read_to_string(temp.path().join("start.sh")).expect("read Taira start");
    let stop = fs::read_to_string(temp.path().join("stop.sh")).expect("read Taira stop");
    for (name, script) in [("start", &start), ("stop", &stop)] {
        assert!(
            script.contains("peer${i}.process.json"),
            "{name} record path"
        );
        assert!(script.contains("\"schema_version\": 1"), "{name} V1 schema");
        assert!(script.contains("\"start_time_ticks\""), "{name} start time");
        assert!(
            script.contains("\"executable_device\""),
            "{name} executable device"
        );
        assert!(
            script.contains("\"executable_inode\""),
            "{name} executable inode"
        );
        assert!(
            script.contains("\"process_group_id\""),
            "{name} process group"
        );
        assert!(
            script.contains("os.pidfd_open(pid, 0)"),
            "{name} pidfd open"
        );
        assert!(
            script.contains("signal.pidfd_send_signal(descriptor, signal_number, None, 0)"),
            "{name} pidfd signaling"
        );
        assert!(script.contains("select.poll()"), "{name} pidfd wait");
        assert!(script.contains("/proc/sys/kernel/random/boot_id"));
        assert!(script.contains("retired Taira PID file is unsupported"));
        assert!(
            !script.contains("PIDFILE="),
            "{name} must not write PID files"
        );
        assert!(!script.contains("pid_is_running()"), "{name} PID fallback");
        assert!(!script.contains("command -v ps"), "{name} ps fallback");
        assert!(
            !script.contains("kill \"$pid\""),
            "{name} shell kill fallback"
        );
    }
    assert!(start.contains("capture_taira_start(process.pid"));
    assert!(start.contains("os.link(temporary, path, follow_symlinks=False)"));
    assert!(start.contains("stat.S_IMODE(metadata.st_mode) != 0o600"));
    assert!(!start.contains("nohup env SNAPSHOT_STORE_DIR="));
    assert!(!start.contains("echo \"$peer_pid\" >"));
    assert!(stop.contains("stop_taira_process(env[\"IROHA_PEER_PROCESS_RECORD\"]"));
    assert!(stop.contains("_terminate_pidfd(descriptor)"));
    assert!(!stop.contains("ps -p"));
}

#[cfg(unix)]
#[test]
fn shell_assignment_quoting_preserves_metacharacters_as_data() {
    let input = "target dir/it's-$(printf injected)-`printf other`";
    let quoted = crate::shell::single_quote(input).expect("quote shell value");
    let command = format!("value={quoted}; printf '%s' \"$value\"");
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("run generated assignment");
    assert!(output.status.success());
    assert_eq!(output.stdout, input.as_bytes());
    assert!(crate::shell::single_quote("line one\nline two").is_err());
}

#[cfg(unix)]
#[test]
fn start_script_preserves_explicit_faucet_allocation_without_minting() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    write_scripts(
        temp.path(),
        4,
        false,
        false,
        &localnet_client_account_literal(None),
        &localnet_xor_asset_literal(),
    )
    .expect("write scripts");
    let start = fs::read_to_string(temp.path().join("start.sh")).expect("read start script");
    assert!(start.contains("startup does not issue assets"));
    assert!(!start.contains("ledger asset mint"));
    assert!(!start.contains("IROHA_LOCALNET_FAUCET_RESERVE_RETRIES"));
    assert!(!start.contains("faucet-topup"));
}

#[cfg(unix)]
#[test]
fn lifecycle_scripts_enforce_exact_peer_selector_grammar() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    write_scripts(
        temp.path(),
        4,
        false,
        false,
        &localnet_client_account_literal(None),
        &localnet_xor_asset_literal(),
    )
    .expect("write scripts");

    for name in ["start.sh", "stop.sh"] {
        let path = temp.path().join(name);
        let contents = fs::read_to_string(&path).expect("read lifecycle script");
        assert!(contents.contains("PEER_COUNT=4"));
        assert!(contents.contains("SELECTED_PEERS="));
        assert!(contents.contains("usage: $0 [--peer-index INDEX]"));
        assert!(contents.contains("for i in $SELECTED_PEERS; do"));
        for arguments in [
            vec!["--peer-index"],
            vec!["--peer-index", "04"],
            vec!["--peer-index", "4"],
            vec!["--other", "0"],
        ] {
            let status = std::process::Command::new("/bin/bash")
                .arg(&path)
                .args(arguments)
                .status()
                .expect("run lifecycle script with invalid selector");
            assert_eq!(
                status.code(),
                Some(2),
                "{name} must reject invalid selectors"
            );
        }
    }

    let status = std::process::Command::new("/bin/bash")
        .arg(temp.path().join("stop.sh"))
        .args(["--peer-index", "3"])
        .status()
        .expect("run harmless exact selected stop");
    assert!(status.success());
}
