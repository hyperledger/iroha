//! Kagami localnet bootstrap coverage for permissioned Sumeragi.
use eyre::{Result, WrapErr, ensure, eyre};
use integration_tests::{kagami::resolve_kagami_bin, process as test_process, sandbox};
use iroha::{
    blocking::Client,
    config::{Config, LoadPath},
    data_model::{Level, isi::Log},
};
use iroha_test_network::{
    Program, fslock_ports::AllocatedPortBlock, init_instruction_registry, repo_root,
};
use std::{
    any::Any,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::time::sleep;
const LOCALNET_PEERS: u16 = 4;
const READY_TIMEOUT: Duration = Duration::from_secs(180);
const READY_POLL: Duration = Duration::from_millis(200);
const LOCALNET_BLOCK_TIME_MS: u64 = 2_000;
const LOCALNET_COMMIT_TIME_MS: u64 = 2_000;
const LOG_TAIL_LINES: usize = 80;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kagami_localnet_bootstrap_produces_blocks() -> Result<()> {
    init_instruction_registry();
    let _guard = sandbox::serial_guard();
    let temp_dir = localnet_tempdir()?;
    let out_dir = temp_dir.path().join("localnet");
    let result: Result<()> = async {
        let api_ports = alloc_port_block(LOCALNET_PEERS)?;
        let p2p_ports = alloc_port_block(LOCALNET_PEERS)?;
        let base_api_port = api_ports.base();
        let base_p2p_port = p2p_ports.base();
        generate_localnet(&out_dir, base_api_port, base_p2p_port)?;
        let irohad_bin = Program::Irohad
            .resolve()
            .wrap_err("resolve iroha3d binary")?;
        let mut localnet = KagamiLocalnet::start(
            &out_dir,
            &irohad_bin,
            LOCALNET_PEERS,
            (api_ports, p2p_ports),
        )?;
        let client = load_localnet_client(&out_dir)?;
        wait_for_status_ready(&client, &mut localnet, READY_TIMEOUT).await?;
        let baseline = client.client().status().get().await?.blocks_non_empty;
        client.submit(
            Log::new(Level::INFO, "kagami localnet smoke".to_string()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let status =
            wait_for_blocks_non_empty(&client, baseline.saturating_add(1), READY_TIMEOUT).await?;
        ensure!(
            status.blocks_non_empty >= baseline.saturating_add(1),
            "expected non-empty block in kagami localnet (baseline={baseline}, current={})",
            status.blocks_non_empty
        );
        wait_for_validator_count_and_reducer(&client, u64::from(LOCALNET_PEERS), READY_TIMEOUT)
            .await?;
        Ok(())
    }
    .await;
    if let Err(err) = result {
        if let Some(reason) = sandbox::sandbox_reason(&err) {
            eprintln!(
                "sandboxed network restriction detected while running kagami localnet test; skipping ({reason})"
            );
            return Ok(());
        }
        if std::env::var_os("IROHA_KAGAMI_LOCALNET_KEEP").is_some() {
            eprintln!(
                "keeping kagami localnet artifacts at {}",
                temp_dir.path().display()
            );
            let _ = temp_dir.keep();
        }
        return Err(err);
    }
    Ok(())
}
fn alloc_port_block(count: u16) -> Result<AllocatedPortBlock> {
    std::panic::catch_unwind(|| AllocatedPortBlock::new(count))
        .map_err(|panic| eyre!(panic_message(&panic)))
}
fn panic_message(panic: &Box<dyn Any + Send>) -> String {
    let panic = panic.as_ref();
    panic.downcast_ref::<&str>().map_or_else(
        || {
            panic
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "port allocation panicked".to_string())
        },
        |message| (*message).to_string(),
    )
}
struct KagamiLocalnet {
    dir: PathBuf,
    children: Vec<Child>,
    _port_reservations: (AllocatedPortBlock, AllocatedPortBlock),
}
impl KagamiLocalnet {
    fn start(
        out_dir: &Path,
        irohad_bin: &Path,
        peers: u16,
        port_reservations: (AllocatedPortBlock, AllocatedPortBlock),
    ) -> Result<Self> {
        let mut children = Vec::with_capacity(peers as usize);
        for idx in 0..peers {
            let config_path = out_dir.join(format!("peer{idx}.toml"));
            let snapshot_dir = out_dir
                .join("storage")
                .join(format!("peer{idx}"))
                .join("snapshot");
            fs::create_dir_all(&snapshot_dir)
                .wrap_err_with(|| format!("create snapshot dir {}", snapshot_dir.display()))?;
            let log_path = out_dir.join(format!("peer{idx}.log"));
            let log_file = fs::File::create(&log_path)
                .wrap_err_with(|| format!("create log file {}", log_path.display()))?;
            let log_file_err = log_file
                .try_clone()
                .wrap_err_with(|| format!("clone log file {}", log_path.display()))?;
            let mut cmd = Command::new(irohad_bin);
            cmd.arg("--config").arg(&config_path);
            cmd.current_dir(out_dir);
            cmd.env("SNAPSHOT_STORE_DIR", &snapshot_dir);
            if std::env::var_os("RUST_LOG").is_none() {
                cmd.env("RUST_LOG", "info");
            }
            let child = cmd
                .stdout(Stdio::from(log_file))
                .stderr(Stdio::from(log_file_err))
                .spawn()
                .wrap_err_with(|| format!("spawn iroha3d for peer {idx}"))?;
            children.push(child);
        }
        Ok(Self {
            dir: out_dir.to_path_buf(),
            children,
            _port_reservations: port_reservations,
        })
    }
    fn unexpected_exit_report(&mut self) -> Result<Option<String>> {
        for (idx, child) in self.children.iter_mut().enumerate() {
            let Some(status) = child
                .try_wait()
                .wrap_err_with(|| format!("poll irohad peer {idx}"))?
            else {
                continue;
            };
            let log_path = self.dir.join(format!("peer{idx}.log"));
            let tail = log_tail(&log_path, LOG_TAIL_LINES);
            return Ok(Some(format!(
                "irohad peer {idx} exited before localnet became ready: status={status}; log tail from {}:\n{tail}",
                log_path.display()
            )));
        }
        Ok(None)
    }
}
impl Drop for KagamiLocalnet {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        if cfg!(unix) {
            let script = self.dir.join("stop.sh");
            if script.exists() {
                let mut command = Command::new("bash");
                command.arg(script).current_dir(&self.dir);
                let _ = test_process::output_with_timeout(
                    &mut command,
                    test_process::process_timeout(),
                );
            }
        }
    }
}
fn localnet_tempdir() -> Result<TempDir> {
    let root = repo_root().join("target").join("kagami-localnet");
    fs::create_dir_all(&root)
        .wrap_err_with(|| format!("create localnet temp root {}", root.display()))?;
    tempfile::tempdir_in(&root).wrap_err("create localnet temp dir")
}
fn generate_localnet(out_dir: &Path, base_api_port: u16, base_p2p_port: u16) -> Result<()> {
    let kagami_bin = resolve_kagami_bin()?;
    let peers = LOCALNET_PEERS.to_string();
    let api_port = base_api_port.to_string();
    let p2p_port = base_p2p_port.to_string();
    let block_time = LOCALNET_BLOCK_TIME_MS.to_string();
    let commit_time = LOCALNET_COMMIT_TIME_MS.to_string();
    let out_dir = out_dir.to_string_lossy().to_string();
    let mut command = Command::new(kagami_bin);
    command
        .arg("localnet")
        .arg("generate")
        .arg("--peers")
        .arg(peers)
        .arg("--seed")
        .arg("kagami-localnet")
        .arg("--consensus-mode")
        .arg("permissioned")
        .arg("--bind-host")
        .arg("127.0.0.1")
        .arg("--public-host")
        .arg("127.0.0.1")
        .arg("--base-api-port")
        .arg(api_port)
        .arg("--base-p2p-port")
        .arg(p2p_port)
        .arg("--block-time-ms")
        .arg(block_time)
        .arg("--commit-time-ms")
        .arg(commit_time)
        .arg("--out-dir")
        .arg(out_dir);
    let output = test_process::output_with_timeout(&mut command, test_process::process_timeout())
        .wrap_err("run kagami localnet")?;
    ensure!(
        output.status.success(),
        "kagami localnet failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
fn load_localnet_client(out_dir: &Path) -> Result<Client> {
    let client_path = out_dir.join("client.toml");
    let mut config = Config::load(LoadPath::Explicit(client_path.clone())).map_err(|err| {
        eyre!(
            "load localnet client config {}: {err:?}",
            client_path.display()
        )
    })?;
    config.transaction_status_timeout = READY_TIMEOUT;
    Client::new(config)
}
async fn wait_for_status_ready(
    client: &Client,
    localnet: &mut KagamiLocalnet,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(eyre!("timed out waiting for localnet status"));
        }
        if client.client().status().get().await.is_ok() {
            return Ok(());
        }
        if let Some(report) = localnet.unexpected_exit_report()? {
            return Err(eyre!(report));
        }
        sleep(READY_POLL).await;
    }
}
fn log_tail(path: &Path, lines: usize) -> String {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let mut tail = contents.lines().rev().take(lines).collect::<Vec<_>>();
            tail.reverse();
            tail.join("\n")
        }
        Err(err) => format!("failed to read log {}: {err}", path.display()),
    }
}
async fn wait_for_blocks_non_empty(
    client: &Client,
    target: u64,
    timeout: Duration,
) -> Result<iroha_torii_shared::status::Status> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = client.client().status().get().await?;
        if status.blocks_non_empty >= target {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "timed out waiting for non-empty block target {target}"
            ));
        }
        sleep(READY_POLL).await;
    }
}
async fn wait_for_validator_count_and_reducer(
    client: &Client,
    expected_peers: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_status_peers: Option<u64> = None;
    let mut reducer_available = false;
    loop {
        if Instant::now() >= deadline {
            let last_validator_count = last_status_peers.map(|peers| peers.saturating_add(1));
            return Err(eyre!(
                "timed out waiting for validator count and reducer readiness: expected_peers={expected_peers}, last_validator_count={last_validator_count:?}, reducer_available={reducer_available}"
            ));
        }
        if let Ok(status) = client.client().status().get().await {
            last_status_peers = Some(status.peers);
            // Status.peers excludes the reporting peer, so add 1 for the validator count.
            if status.peers.saturating_add(1) == expected_peers
                && let Ok(sumeragi) = client.client().get_sumeragi_status()
            {
                reducer_available = sumeragi.halted.is_none();
                if reducer_available {
                    return Ok(());
                }
            }
        }
        sleep(READY_POLL).await;
    }
}
