//! Fresh four-seat custody through the real native provisioning and provider boundary.
//! Every running daemon uses its stock runtime-provider broker.
use super::*;
use iroha_config::base::read::ConfigReader;
use iroha_core::beacon::credential::global_beacon_partial_signer_public_inventory_digest_v1;
use iroha_core::{
    beacon,
    kura::{BlockIndex, BlockStore, Kura},
    sumeragi::{
        certified_chain::CertifiedBlock,
        native_journal::{NativeJournalCursor, with_verified_native_journal},
    },
};
use iroha_crypto::{ExposedPrivateKey, HashOf, KeyPair};
use iroha_data_model::sumeragi::epoch::{BeaconEpochBindingV1, ValidatorEpochDecisionV1};
use iroha_data_model::{
    consensus::GlobalThresholdBeaconChainAnchorV1,
    isi::consensus_keys::{
        ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
        ThresholdKeyLifecycleCertificateV1,
    },
    sumeragi::finality::{NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits},
    transaction::TransactionEntrypoint,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_test_network::{
    DisposableGenesisConfigSeat, DisposableGenesisDkgOutput, NativeGenesisProvisioningBundle,
    Program, ReleasePrebuiltBinary, revalidate_release_prebuilt_binary,
    run_disposable_genesis_dkg_from_configs,
};
use irohad::{
    IrohaRuntimeProviderBindingsV1,
    external_software_signer::encode_consensus_threshold_credential_bundle_v1,
};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Seek as _, Write as _},
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt},
    process::{Child, Command},
};
use zeroize::Zeroizing;

#[path = "production_beacon_canary_receipt.rs"]
mod canary_receipt;
#[path = "production_epoch_retention.rs"]
mod epoch_retention;
#[path = "production_beacon_prepare.rs"]
mod prepare;
#[path = "public_transaction_sequence.rs"]
mod public_sequence;

const CHAIN: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
const PHASE_BUDGET: Duration = Duration::from_secs(180);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| eyre!("native output omitted {name}"))
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| eyre!("native {name} is not text"))
}
fn private_file(path: &Path, bytes: &[u8]) -> Result<File> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(file)
}

// A build target may be inside Git. Only the explicit runtime root (or the
// established external artifact root) admits the fixture's generated custody.
fn validate_runtime_root(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| !matches!(c, Component::ParentDir | Component::CurDir)),
        "runtime root must be an absolute direct path"
    );
    let canonical = fs::canonicalize(path)?;
    ensure!(
        canonical == path,
        "runtime root must have no symlink or alias components"
    );
    let owner = nix::unistd::geteuid().as_raw();
    for (index, ancestor) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink() && meta.mode() & 0o022 == 0,
            "unsafe runtime root ancestor"
        );
        ensure!(
            !ancestor.join(".git").exists(),
            "generated custody must remain outside Git"
        );
        if index == 0 {
            ensure!(
                meta.uid() == owner && meta.mode() & 0o077 == 0,
                "runtime root must be owner-only"
            );
        }
    }
    Ok(canonical)
}
fn runtime_workspace() -> Result<tempfile::TempDir> {
    let root = std::env::var_os("TAIRA_TESTNET_BEACON_FIXTURE_DIR")
        .or_else(|| std::env::var_os("IROHA_RELEASE_ARTIFACT_ROOT"))
        .ok_or_else(|| eyre!("an explicit owner-only external beacon fixture root is required"))?;
    let root = validate_runtime_root(Path::new(&root))?;
    let workspace = tempfile::Builder::new()
        .prefix("beacon-production-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(root)?;
    validate_runtime_root(workspace.path())?;
    Ok(workspace)
}
fn binary(variable: &str, kind: ReleasePrebuiltBinary) -> Result<PathBuf> {
    let path = std::env::var_os(variable)
        .map(PathBuf::from)
        .ok_or_else(|| eyre!("{variable} must name the exact prebuilt binary"))?;
    ensure!(
        path.is_absolute() && path.is_file(),
        "prebuilt executable is absent"
    );
    revalidate_release_prebuilt_binary(kind, &path)?;
    Ok(path)
}

/// Descriptor duplication is confined to the child between fork and exec.
#[allow(unsafe_code)]
fn inherit(command: &mut Command, descriptors: &[(RawFd, RawFd)]) -> Result<()> {
    let mut targets = BTreeSet::new();
    ensure!(
        descriptors.iter().all(|(source, target)| *source >= 3
            && *target >= 3
            && source != target
            && targets.insert(*target)),
        "invalid inherited descriptor map"
    );
    ensure!(
        descriptors
            .iter()
            .all(|(source, _)| !targets.contains(source)),
        "descriptor mapping would overwrite a source"
    );
    let descriptors = descriptors.to_vec();
    // SAFETY: the closure only invokes async-signal-safe libc descriptor calls.
    unsafe {
        command.pre_exec(move || {
            for &(source, target) in &descriptors {
                if nix::libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}
fn consumed_copy(source: &Path, target: &Path, maximum: u64) -> Result<ConsumedCopy> {
    let before = fs::symlink_metadata(source)?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == nix::unistd::geteuid().as_raw()
            && before.mode() & 0o777 == 0o600
            && before.nlink() == 1
            && (1..=maximum).contains(&before.len()),
        "invalid fixture-owned credential source"
    );
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)?;
    let opened = input.metadata()?;
    ensure!(
        (opened.dev(), opened.ino(), opened.len()) == (before.dev(), before.ino(), before.len()),
        "credential source changed before copy"
    );
    let mut output = ConsumedCopy {
        file: private_file(target, &[])?,
        path: target.to_path_buf(),
        maximum,
    };
    ensure!(
        std::io::copy(&mut input, &mut output.file)? == before.len(),
        "credential source changed during copy"
    );
    output.file.sync_all()?;
    let after = input.metadata()?;
    ensure!(
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        ) == (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        "credential source changed after copy"
    );
    output.file.rewind()?;
    Ok(output)
}
#[derive(Debug)]
struct ConsumedCopy {
    file: File,
    path: PathBuf,
    maximum: u64,
}
impl Drop for ConsumedCopy {
    fn drop(&mut self) {
        let retire = (|| -> Result<()> {
            let descriptor = self.file.metadata()?;
            let path = fs::symlink_metadata(&self.path)?;
            ensure!(
                descriptor.is_file()
                    && descriptor.dev() == path.dev()
                    && descriptor.ino() == path.ino()
                    && descriptor.uid() == nix::unistd::geteuid().as_raw()
                    && descriptor.mode() & 0o7777 == 0o600
                    && descriptor.nlink() == 1
                    && descriptor.len() <= self.maximum,
                "native one-shot credential changed before retirement"
            );
            if descriptor.len() != 0 {
                self.file.rewind()?;
                self.file
                    .write_all(&vec![0; usize::try_from(descriptor.len())?])?;
                self.file.sync_all()?;
                self.file.set_len(0)?;
                self.file.sync_all()?;
            }
            fs::remove_file(&self.path)?;
            Ok(())
        })();
        if let Err(error) = retire {
            eprintln!(
                "failed to retire native one-shot credential {}: {error:#}",
                self.path.display()
            );
        }
    }
}
#[test]
fn native_one_shot_copies_retire_without_consuming_the_retained_source() {
    let root = tempfile::tempdir().expect("private test root");
    let source = root.path().join("retained.seed");
    private_file(&source, &[0x71; 32]).expect("retained private seed");
    let first_path = root.path().join("first.fd199");
    let mut first = consumed_copy(&source, &first_path, 32).expect("first one-shot copy");
    assert_eq!(first.file.metadata().unwrap().len(), 32);
    first.file.rewind().unwrap();
    first.file.write_all(&[0; 32]).unwrap();
    first.file.set_len(0).unwrap();
    drop(first);
    assert!(!first_path.exists(), "consumed child must be removed");
    let failed_path = root.path().join("failed.fd199");
    drop(consumed_copy(&source, &failed_path, 32).expect("failed-launch child copy"));
    assert!(
        !failed_path.exists(),
        "failed child must be erased and removed"
    );
    let credential_source = root.path().join("retained-credential.norito");
    private_file(&credential_source, &[0x53; 1024]).expect("retained credential");
    let credential_child = root.path().join("credential-child.norito");
    drop(
        consumed_copy(&credential_source, &credential_child, 2048)
            .expect("larger one-shot credential copy"),
    );
    assert!(
        !credential_child.exists(),
        "larger credential child must be erased and removed"
    );
    assert_eq!(fs::read(&credential_source).unwrap(), [0x53; 1024]);
    assert_eq!(fs::read(&source).unwrap(), [0x71; 32]);
}
fn command(binary: &Path, directory: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .current_dir(directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    command
}
async fn run(mut command: Command, deadline: Instant) -> Result<Vec<u8>> {
    let output = timeout_at(deadline, command.spawn()?.wait_with_output())
        .await
        .wrap_err("native fixture child exceeded its fixed deadline")??;
    ensure!(
        output.status.success(),
        "native fixture child exited {}; stderr is retained",
        output.status
    );
    Ok(output.stdout)
}
fn config(path: &Path) -> Result<iroha_config::parameters::actual::Root> {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let parsed: iroha_config::parameters::actual::Root = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(path)
        .map_err(|_| eyre!("cannot read native fixture config"))?
        .read_and_complete::<iroha_config::parameters::user::Root>()
        .map_err(|_| eyre!("cannot decode native fixture config"))?
        .parse()
        .map_err(|_| eyre!("cannot validate native fixture config"))?;
    // These are the original retained-catalog fixture prerequisites. Verify
    // the generated native values; never rewrite a differing protocol mode.
    ensure!(
        matches!(parsed.kura.init_mode, iroha_config::kura::InitMode::Strict),
        "native fixture must retain strict Kura replay"
    );
    ensure!(
        matches!(
            parsed.nexus.staking.restricted_validator_mode,
            iroha_config::parameters::actual::LaneValidatorMode::AdminManaged
        ),
        "native restricted lanes must retain admin-managed validator admission"
    );
    Ok(parsed)
}
fn client(path: &Path, port: u16) -> Result<iroha::client::Client> {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let mut config = iroha::config::Config::load_file(path)
        .map_err(|error| eyre!("native fixture client configuration failed: {error:?}"))?;
    config.torii_api_url = format!("http://127.0.0.1:{port}/").parse()?;
    config.transaction_status_timeout = PHASE_BUDGET;
    Ok(iroha::client::Client::builder(config).build()?)
}
async fn status_height(clients: &[iroha::client::Client], deadline: Instant) -> Result<u64> {
    timeout_at(deadline, async {
        loop {
            let statuses = try_join_all(
                clients
                    .iter()
                    .map(|client| validator_status_until(client, deadline)),
            )
            .await?;
            if statuses.iter().all(|s| {
                s.blocks > 0 && s.blocks == statuses[0].blocks && s.queue_size == 0 && s.peers == 3
            }) {
                return Ok(statuses[0].blocks);
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .wrap_err("four validators did not reach the same drained committed height and full mesh")?
}
fn exact_height_reached(
    statuses: &[iroha_torii_shared::status::Status],
    expected: u64,
) -> Result<bool> {
    ensure!(
        statuses.len() == 4 && expected > 0,
        "exact height requires four validators and a positive target"
    );
    for (peer, status) in statuses.iter().enumerate() {
        ensure!(
            status.blocks <= expected,
            "validator {peer} advanced beyond exact height {expected}: observed {}",
            status.blocks
        );
    }
    Ok(statuses
        .iter()
        .all(|status| status.blocks == expected && status.queue_size == 0))
}

fn exact_meshed_height_reached(
    statuses: &[iroha_torii_shared::status::Status],
    expected: u64,
) -> Result<bool> {
    Ok(
        exact_height_reached(statuses, expected)?
            && statuses.iter().all(|status| status.peers == 3),
    )
}

async fn wait_for_exact_meshed_height(
    clients: &[iroha::client::Client],
    expected: u64,
    deadline: Instant,
) -> Result<()> {
    let mut last = Vec::new();
    timeout_at(deadline, async {
        loop {
            let statuses = try_join_all(
                clients.iter().map(|client| validator_status_until(client, deadline)),
            ).await?;
            last = statuses
                .iter()
                .map(|status| (status.blocks, status.queue_size, status.peers))
                .collect::<Vec<_>>();
            if exact_meshed_height_reached(&statuses, expected)? {
                return Ok::<_, eyre::Report>(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    }).await.wrap_err_with(|| format!(
        "four validators did not form a drained full mesh at exact height {expected}; last (height, queue, connected peers) observations={last:?}"
    ))?
}

async fn wait_for_exact_height(
    clients: &[iroha::client::Client],
    expected: u64,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        clients.len() == 4 && expected > 0,
        "exact height requires four validators and a positive target"
    );
    let mut last = Vec::new();
    timeout_at(deadline, async {
        loop {
            let statuses = try_join_all(
                clients.iter().map(|client| validator_status_until(client, deadline)),
            ).await?;
            last = statuses.iter().map(|status| (status.blocks, status.queue_size)).collect::<Vec<_>>();
            if exact_height_reached(&statuses, expected)? {
                return Ok::<_, eyre::Report>(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    }).await.wrap_err_with(|| format!(
        "four validators did not reach exact drained height {expected}; last (height, queue) observations={last:?}"
    ))?
}

async fn ready(port: u16, expected: u16, deadline: Instant) -> Result<()> {
    timeout_at(deadline, async {
        loop {
            let address = format!("127.0.0.1:{port}");
            if let Ok(mut stream) = tokio::net::TcpStream::connect(&address).await {
                stream.write_all(format!("GET /readyz HTTP/1.1\r\nHost: {address}\r\nAccept: */*\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                let mut line = String::new();
                tokio::io::BufReader::new(stream).read_line(&mut line).await?;
                if line.starts_with(&format!("HTTP/1.1 {expected} ")) { return Ok::<_, eyre::Report>(()); }
                ensure!(!line.starts_with("HTTP/1.1 200 ") || expected == 200, "validator readiness disagrees with the expected admission state");
            }
            sleep(Duration::from_millis(200)).await;
        }
    }).await.wrap_err("native admission readiness did not reach the expected state")?
}

async fn listeners_started(peers: &mut Peers, api: u16, deadline: Instant) -> Result<()> {
    let started = Instant::now();
    eprintln!(
        "beacon fixture waiting for public listeners: remaining={:.3}s",
        deadline.saturating_duration_since(started).as_secs_f64()
    );
    timeout_at(deadline, async {
        for offset in 0..4 {
            loop {
                for (index, child) in peers.children.iter_mut().enumerate() {
                    if let Some(status) = child.try_wait()? {
                        return Err(eyre!(
                            "fixture validator {index} exited before public listeners: {status}; inspect its retained stderr log"
                        ));
                    }
                }
                if tokio::net::TcpStream::connect(("127.0.0.1", api + offset))
                    .await
                    .is_ok()
                {
                    eprintln!(
                        "beacon fixture validator {offset} listener bound: elapsed={:.3}s",
                        started.elapsed().as_secs_f64()
                    );
                    break;
                }
                sleep(Duration::from_millis(200)).await;
            }
        }
        Ok::<_, eyre::Report>(())
    })
    .await
    .wrap_err_with(|| {
        format!(
            "fixture validators did not bind their public listeners after {:.3}s of listener wait",
            started.elapsed().as_secs_f64()
        )
    })??;
    Ok(())
}
struct Peers {
    children: Vec<Child>,
}
impl Peers {
    async fn stop(&mut self, deadline: Instant) -> Result<()> {
        for child in &mut self.children {
            if let Some(pid) = child.id() {
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(pid)?),
                    nix::sys::signal::Signal::SIGTERM,
                )?;
            }
        }
        for child in &mut self.children {
            timeout_at(deadline, child.wait())
                .await
                .wrap_err("fixture-owned validator did not stop")??;
        }
        self.children.clear();
        Ok(())
    }
}
// Only the fixture's first launch owns the assertion that its freshly generated keys never
// signed. A later launch must preserve that distinction even if safety files were lost.
fn configure_consensus_boot(
    command: &mut Command,
    records_dir: &Path,
    installation_log: &Path,
    first_launch: bool,
) -> Result<()> {
    if first_launch {
        for path in [records_dir, installation_log] {
            ensure!(
                matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "initial fixture launch requires absent consensus history: {}",
                path.display(),
            );
        }
        command.arg("--sumeragi-assert-fresh-key");
    }
    Ok(())
}

#[test]
fn production_beacon_fresh_key_assertion_is_only_for_the_original_launch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let records = directory.path().join("sumeragi-records");
    let log = directory.path().join("sumeragi-installation.log");
    let mut first = Command::new("iroha3d");
    configure_consensus_boot(&mut first, &records, &log, true)?;
    assert_eq!(
        first.as_std().get_args().collect::<Vec<_>>(),
        ["--sumeragi-assert-fresh-key"]
    );
    let mut restart = Command::new("iroha3d");
    configure_consensus_boot(&mut restart, &records, &log, false)?;
    assert_eq!(restart.as_std().get_args().count(), 0);
    fs::create_dir(&records)?;
    assert!(configure_consensus_boot(&mut Command::new("iroha3d"), &records, &log, true).is_err());
    fs::remove_dir(&records)?;
    fs::write(&log, b"retained installation")?;
    assert!(configure_consensus_boot(&mut Command::new("iroha3d"), &records, &log, true).is_err());
    Ok(())
}

fn spawn_peers(
    directory: &Path,
    daemon: &Path,
    roster: &[iroha_model_base::peer::PeerId],
    run_number: u16,
) -> Result<Peers> {
    let mut peers = Peers {
        children: Vec::new(),
    };
    for index in 0..4 {
        let path = directory.join(format!("peer{index}.toml"));
        let native = config(&path)?;
        let _seat = roster
            .iter()
            .position(|peer| peer == &native.common.peer.id)
            .ok_or_else(|| eyre!("peer is outside signed genesis roster"))?
            + 1;
        let mut child = command(daemon, directory);
        child
            .arg("--sora")
            .arg("--config")
            .arg(&path)
            .stdout(private_file(
                &directory.join(format!("peer{index}-run{run_number}-stdout.log")),
                &[],
            )?)
            .stderr(private_file(
                &directory.join(format!("peer{index}-run{run_number}-stderr.log")),
                &[],
            )?);
        configure_consensus_boot(
            &mut child,
            &native.sumeragi.records_dir,
            &native.sumeragi.installation_log,
            run_number == 1,
        )?;
        peers.children.push(child.spawn()?);
    }
    Ok(peers)
}

fn reserve_ports() -> Result<(u16, u16, Vec<std::net::TcpListener>)> {
    fn range() -> Result<(u16, Vec<std::net::TcpListener>)> {
        for _ in 0..100 {
            let first = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            let base = first.local_addr()?.port();
            if base > u16::MAX - 3 {
                continue;
            }
            let mut held = vec![first];
            for offset in 1..4 {
                if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", base + offset)) {
                    held.push(listener);
                } else {
                    break;
                }
            }
            if held.len() == 4 {
                return Ok((base, held));
            }
        }
        Err(eyre!("cannot reserve four contiguous loopback ports"))
    }
    let (api, mut held) = range()?;
    let (p2p, peers) = range()?;
    held.extend(peers);
    Ok((api, p2p, held))
}

fn fresh_client(directory: &Path, network_id: &iroha_data_model::NetworkId) -> Result<PathBuf> {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let key = KeyPair::try_random()?;
    let path = directory.join("fresh-client.toml");
    let private = directory.join("runtime/fresh-client.private_key");
    private_file(
        &private,
        format!("{}\n", ExposedPrivateKey(key.private_key().clone())).as_bytes(),
    )?;
    let mut table: toml::Table =
        toml::from_str(&fs::read_to_string(directory.join("client.toml"))?)?;
    table.remove("network_id_file");
    table.insert(
        "network_id".into(),
        toml::Value::String(network_id.to_string()),
    );
    let account = table
        .get_mut("account")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("generated client omitted account"))?;
    account.remove("private_key");
    account.insert(
        "public_key".into(),
        toml::Value::String(key.public_key().to_string()),
    );
    account.insert(
        "private_key_file".into(),
        toml::Value::String(private.to_string_lossy().into_owned()),
    );
    private_file(&path, toml::to_string(&table)?.as_bytes())?;
    Ok(path)
}
fn idempotency(nonce: &str, kind: &str) -> String {
    let mut bytes = Vec::new();
    for frame in [
        b"iroha:taira:public-reset:child-idempotency:v1\0".as_slice(),
        nonce.as_bytes(),
        b"pre_edge",
        kind.as_bytes(),
    ] {
        bytes.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        bytes.extend_from_slice(frame);
    }
    hex(&iroha_crypto::sha256(bytes))
}
struct Canary<'a> {
    binary: &'a Path,
    directory: &'a Path,
    config: &'a Path,
    root: String,
    nonce: String,
    authorization: String,
    expires_ms: u64,
    faucet: [String; 3],
}
impl Canary<'_> {
    async fn operation(
        &self,
        operation: &str,
        predecessor: Option<&Path>,
        deadline: Instant,
    ) -> Result<(PathBuf, u64)> {
        let envelope = self.directory.join(format!("{operation}.prepared.json"));
        let mut proved_height = None;
        let kind = if operation == "final-canary" {
            "write_canary"
        } else {
            operation
        };
        for prepare in [true, false] {
            let mut child = command(self.binary, self.directory);
            child
                .args(["--machine", "--config"])
                .arg(self.config)
                .arg("--operator-private-key-file")
                .arg(self.directory.join("runtime/operator-signer.key"))
                .args(["--fee-payer", "authority"])
                .args([
                    "taira",
                    "write-canary",
                    "--public-root",
                    &self.root,
                    "--operation",
                    operation,
                    "--authorization-sha256",
                    &self.authorization,
                    "--authorization-nonce",
                    &self.nonce,
                    "--mutation-phase",
                    "pre_edge",
                    "--idempotency-key",
                    &idempotency(&self.nonce, kind),
                    "--execution-expires-at-unix-ms",
                    &self.expires_ms.to_string(),
                    "--timeout-secs",
                    "120",
                    "--json",
                ]);
            if operation == "onboarding" {
                child
                    .arg("--onboarding-token-file")
                    .arg(self.directory.join("runtime/onboarding.token"));
            }
            if operation == "faucet" {
                child.args([
                    "--faucet-authority",
                    &self.faucet[0],
                    "--faucet-asset-id",
                    &self.faucet[1],
                    "--faucet-amount",
                    &self.faucet[2],
                ]);
            } else if operation == "final-canary" && prepare {
                child.args([
                    "--predecessor-faucet-authority",
                    &self.faucet[0],
                    "--predecessor-faucet-asset-id",
                    &self.faucet[1],
                    "--predecessor-faucet-amount",
                    &self.faucet[2],
                ]);
            }
            let file = if prepare {
                child.args(["--prepare-envelope", "--prepared-output-fd", "100"]);
                private_file(&envelope, &[])?
            } else {
                child.args(["--submit-prepared-envelope-fd", "100"]);
                File::open(&envelope)?
            };
            let previous = if prepare {
                predecessor.map(File::open).transpose()?
            } else {
                None
            };
            let mut descriptors = vec![(file.as_raw_fd(), 100)];
            if let Some(previous) = &previous {
                child.args(["--prerequisite-envelope-fd", "101"]);
                descriptors.push((previous.as_raw_fd(), 101));
            }
            inherit(&mut child, &descriptors)?;
            let phase = if prepare { "prepare" } else { "submit" };
            let started = Instant::now();
            eprintln!(
                "beacon fixture {operation} {phase} started: remaining={:.3}s",
                deadline.saturating_duration_since(started).as_secs_f64()
            );
            let bytes = run(child, deadline).await.wrap_err_with(|| {
                format!(
                    "native {operation} {phase} failed after {:.3}s",
                    started.elapsed().as_secs_f64()
                )
            })?;
            eprintln!(
                "beacon fixture {operation} {phase} complete: elapsed={:.3}s",
                started.elapsed().as_secs_f64()
            );
            if let Some(height) = self.retain_receipt(operation, kind, prepare, &bytes)? {
                proved_height = Some(height);
            }
        }
        Ok((
            envelope,
            proved_height.ok_or_else(|| eyre!("missing native canary proof receipt"))?,
        ))
    }

    fn assert_committed_prepared_replay(
        &self,
        operation: &str,
        client: &iroha::client::Client,
    ) -> Result<()> {
        let envelope_path = self.directory.join(format!("{operation}.prepared.json"));
        let envelope: Value = json::from_slice(&fs::read(&envelope_path)?)?;
        let prepared_operation = field(&envelope, "operation")?;
        let prepared = field(prepared_operation, "envelope")?;
        let (response, transaction_hash_hex) = match operation {
            "onboarding" => {
                ensure!(
                    text(prepared_operation, "kind")? == "onboarding_prepared",
                    "retained onboarding envelope has the wrong operation"
                );
                let prepared: iroha::client::AccountOnboardingPreparedTransactionV1 =
                    json::from_value(prepared.clone())?;
                let token = fs::read_to_string(self.directory.join("runtime/onboarding.token"))?;
                let response = client.post_prepared_account_onboarding(
                    &prepared.receipt.body.request,
                    &prepared,
                    &prepared.fee_payment,
                    &token,
                )?;
                (response, prepared.transaction_hash_hex)
            }
            "faucet" => {
                ensure!(
                    text(prepared_operation, "kind")? == "faucet_prepared",
                    "retained faucet envelope has the wrong operation"
                );
                let prepared: iroha::client::AccountFaucetPreparedTransactionV1 =
                    json::from_value(prepared.clone())?;
                let policy = iroha::client::AccountFaucetPolicyV1::try_new(
                    AccountId::parse_encoded(&self.faucet[0])?,
                    self.faucet[1].parse()?,
                    self.faucet[2].parse()?,
                )?;
                let response = client.post_prepared_account_faucet(
                    &prepared,
                    &prepared.fee_payment,
                    &policy,
                )?;
                (response, prepared.transaction_hash_hex)
            }
            _ => {
                return Err(eyre!(
                    "committed prepared replay requires onboarding or faucet"
                ));
            }
        };
        let replay_path = self
            .directory
            .join(format!("{operation}-committed-replay.json"));
        private_file(&replay_path, response.body())?;
        ensure!(
            response.status().as_u16() == 200,
            "committed {operation} prepared-envelope replay returned HTTP {}; retained response: {}",
            response.status(),
            replay_path.display()
        );
        let replay: Value = json::from_slice(response.body())?;
        ensure!(
            text(&replay, "outcome")? == "Applied"
                && text(&replay, "transaction_hash_hex")? == transaction_hash_hex,
            "committed {operation} replay did not return Applied for the exact retained transaction; retained response: {}",
            replay_path.display()
        );
        Ok(())
    }
}

struct ProviderBroker {
    child: Child,
    endpoint: PathBuf,
    _owner_root: Arc<tempfile::TempDir>,
}

impl ProviderBroker {
    async fn stop(&mut self, deadline: Instant) -> Result<()> {
        if let Some(pid) = self.child.id() {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(pid)?),
                nix::sys::signal::Signal::SIGTERM,
            )?;
        }
        timeout_at(deadline, self.child.wait())
            .await
            .wrap_err("fixture-owned stock broker did not stop")??;
        Ok(())
    }
}

fn configure_stock_broker(table: &mut toml::Table, endpoint: &Path) -> Result<()> {
    table
        .get_mut("sumeragi")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("native Sumeragi config absent"))?;
    let broker = table
        .entry("runtime_provider_broker")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| eyre!("runtime_provider_broker is not a table"))?;
    broker.insert(
        "endpoint_path".into(),
        toml::Value::String(endpoint.to_string_lossy().into_owned()),
    );
    Ok(())
}

#[test]
fn production_beacon_stock_config_preserves_providers_and_binds_the_broker() -> Result<()> {
    let mut table: toml::Table = "[sumeragi]\nrole = 'validator'\n[soracloud_runtime.mutation_signer]\nhandle = 'original-signer'\n".parse()?;
    let original = table["soracloud_runtime"].clone();
    configure_stock_broker(&mut table, Path::new("/owner/initial/broker.sock"))?;
    assert!(table["sumeragi"].get("mint_finality_seed_fd").is_none());
    assert_eq!(table["soracloud_runtime"], original);
    table["sumeragi"].as_table_mut().unwrap().insert(
        "global_beacon_partial_signer_provider_handle".into(),
        toml::Value::String("beacon-seat".into()),
    );
    configure_stock_broker(&mut table, Path::new("/owner/activated/broker.sock"))?;
    assert_eq!(
        table["sumeragi"]["global_beacon_partial_signer_provider_handle"].as_str(),
        Some("beacon-seat")
    );
    assert_eq!(table["soracloud_runtime"], original);
    assert_eq!(
        table["runtime_provider_broker"]["endpoint_path"].as_str(),
        Some("/owner/activated/broker.sock")
    );
    Ok(())
}

async fn spawn_provider_broker(
    directory: &Path,
    peer: usize,
    binary: &Path,
    catalog: &[u8],
    credentials: &[u8],
) -> Result<ProviderBroker> {
    let root = iroha_test_network::new_disposable_owner_private_root()?;
    let catalog_path = root.path().join("catalog.norito");
    let catalog_file = private_file(&catalog_path, catalog)?;
    catalog_file.set_permissions(fs::Permissions::from_mode(0o400))?;
    catalog_file.sync_all()?;
    let signer = consumed_copy(
        &directory.join(format!(
            "runtime/taira-runtime-signers/peer{peer}.private_key"
        )),
        &root.path().join("runtime-signer.fd198"),
        71,
    )?;
    let endpoint = root.path().join("runtime-provider-broker-v1.sock");
    iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath::try_new(endpoint.clone())?;
    let policy_path = root.path().join("broker-policy.toml");
    let mut policy = toml::Table::new();
    policy.insert(
        "endpoint_path".into(),
        toml::Value::String(
            endpoint
                .to_str()
                .ok_or_else(|| eyre!("broker endpoint must be UTF-8"))?
                .into(),
        ),
    );
    policy.insert(
        "observer_operation_timeout_ms".into(),
        toml::Value::Integer(15_000),
    );
    let policy_file = private_file(&policy_path, toml::to_string(&policy)?.as_bytes())?;
    policy_file.set_permissions(fs::Permissions::from_mode(0o400))?;
    policy_file.sync_all()?;
    let mut child = command(binary, root.path());
    child
        .arg("--catalog")
        .arg(&catalog_path)
        .arg("--broker-policy")
        .arg(&policy_path)
        .stdin(Stdio::piped())
        .stderr(Stdio::from(private_file(
            &root.path().join("broker-stderr.log"),
            &[],
        )?));
    inherit(&mut child, &[(signer.file.as_raw_fd(), 198)])?;
    let mut child = child.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("stock broker stdin handoff absent"))?;
    stdin.write_all(credentials).await?;
    stdin.shutdown().await?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre!("stock broker readiness pipe absent"))?;
    let mut ready = [0_u8; 6];
    timeout_at(Instant::now() + PHASE_BUDGET, stdout.read_exact(&mut ready)).await??;
    ensure!(
        ready == *b"READY\n" && child.try_wait()?.is_none(),
        "stock broker did not qualify the exact runtime providers"
    );
    drop(signer);
    Ok(ProviderBroker {
        child,
        endpoint,
        _owner_root: root,
    })
}

async fn stage_initial_provider_brokers(
    directory: &Path,
    binary: &Path,
) -> Result<Vec<ProviderBroker>> {
    let credentials = Zeroizing::new(encode_consensus_threshold_credential_bundle_v1(None, None)?);
    let mut brokers = Vec::new();
    for peer in 0..4 {
        let path = directory.join(format!("peer{peer}.toml"));
        let native = config(&path)?;
        let catalog =
            IrohaRuntimeProviderBindingsV1::try_from_config(&native)?.export_canonical_v1()?;
        let broker = spawn_provider_broker(directory, peer, binary, &catalog, &credentials).await?;
        let mut table: toml::Table = fs::read_to_string(&path)?.parse()?;
        configure_stock_broker(&mut table, &broker.endpoint)?;
        fs::write(&path, toml::to_string(&table)?)?;
        config(&path)?;
        brokers.push(broker);
    }
    Ok(brokers)
}

async fn stage_provider_brokers(
    directory: &Path,
    broker_binary: &Path,
    bundle: &Value,
    dkg: &DisposableGenesisDkgOutput,
    roster: &[iroha_model_base::peer::PeerId],
) -> Result<(Vec<ProviderBroker>, Vec<PathBuf>)> {
    let providers = field(bundle, "providers")?
        .as_array()
        .ok_or_else(|| eyre!("public provider inventory is not an array"))?;
    ensure!(
        providers.len() == 4 && dkg.seats.len() == 4 && roster.len() == 4,
        "signed genesis must bind four independently provisioned providers"
    );
    let mut brokers = Vec::new();
    let mut paths = Vec::new();
    for index in 0..4 {
        let path = directory.join(format!("peer{index}.toml"));
        let native = config(&path)?;
        let seat = roster
            .iter()
            .position(|peer| peer == &native.common.peer.id)
            .ok_or_else(|| eyre!("unbound signed-genesis peer"))?;
        let output = &dkg.seats[seat];
        let provider = &providers[seat];
        let peer: iroha_model_base::peer::PeerId =
            json::from_value(field(provider, "validator")?.clone())?;
        let digest: [u8; 32] = json::from_value(field(provider, "policy_digest")?.clone())?;
        let expected_digest = global_beacon_partial_signer_public_inventory_digest_v1(
            dkg.public_session.network_id,
            &[(dkg.public_session.record(), output.signer_index)],
        )?;
        let revision = field(provider, "revision")?
            .as_u64()
            .ok_or_else(|| eyre!("provider revision absent"))?;
        let handle = text(provider, "handle")?;
        ensure!(
            peer == native.common.peer.id
                && peer == output.validator
                && field(provider, "signer_index")?.as_u64() == Some((seat + 1) as u64)
                && output.signer_index == u16::try_from(seat + 1)?
                && handle == output.provider_handle
                && revision == output.provider_revision
                && digest == expected_digest,
            "native provider inventory changed this exact signed DKG seat"
        );
        let retained = IrohaRuntimeProviderBindingsV1::try_from_config(&native)?;
        let catalog = IrohaRuntimeProviderBindingsV1::with_prepared_beacon_inventory_v1(
            Some(&retained),
            CHAIN,
            dkg.public_session.network_id,
            handle,
            revision,
            digest,
            retained.credential_max_memory_bytes(),
        )?
        .export_canonical_v1()?;
        let credential_path = iroha_test_network::new_disposable_owner_private_root()?;
        let mut credential_file = consumed_copy(
            &output.credential_path,
            &credential_path.path().join("beacon-credential.norito"),
            16 * 1024 * 1024,
        )?;
        let mut credential = Zeroizing::new(Vec::new());
        credential_file.file.read_to_end(&mut credential)?;
        let credential_bundle = Zeroizing::new(encode_consensus_threshold_credential_bundle_v1(
            Some(&credential),
            None,
        )?);
        drop(credential_file);
        let broker = spawn_provider_broker(
            directory,
            index,
            broker_binary,
            &catalog,
            &credential_bundle,
        )
        .await?;
        let mut table: toml::Table = toml::from_str(&fs::read_to_string(&path)?)?;
        let sumeragi = table
            .entry("sumeragi")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| eyre!("sumeragi is not a table"))?;
        sumeragi.insert(
            "global_beacon_partial_signer_provider_handle".into(),
            toml::Value::String(handle.into()),
        );
        sumeragi.insert(
            "global_beacon_partial_signer_provider_revision".into(),
            toml::Value::Integer(i64::try_from(revision)?),
        );
        sumeragi.insert(
            "global_beacon_partial_signer_provider_policy_digest_hex".into(),
            toml::Value::String(hex(&digest)),
        );
        configure_stock_broker(&mut table, &broker.endpoint)?;
        fs::write(&path, toml::to_string(&table)?)?;
        config(&path)?;
        brokers.push(broker);
        paths.push(path);
    }
    Ok((brokers, paths))
}
async fn submit_install(
    client: &iroha::client::Client,
    instructions_path: &Path,
    expected_certificate: &ThresholdKeyLifecycleCertificateV1,
    deadline: Instant,
) -> Result<u64> {
    let instructions: Vec<InstructionBox> = json::from_slice(&fs::read(instructions_path)?)?;
    ensure!(
        instructions.len() == 1,
        "native installation must be one certificate instruction"
    );
    let installation = instructions[0]
        .as_any()
        .downcast_ref::<ApplyThresholdKeyLifecycleCertificateV1>()
        .ok_or_else(|| eyre!("native installation is not a lifecycle certificate"))?;
    let mut unsigned_certificate = installation.certificate.clone();
    unsigned_certificate.signatures.clear();
    ensure!(
        unsigned_certificate == *expected_certificate
            && unsigned_certificate.action
                == ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        "assembled installation differs from the native bootstrap certificate"
    );
    let install_height = installation.certificate.effective_height;
    let client = client.with_request_deadline(deadline.into_std());
    let account = client.account_client()?;
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions,
        FeePaymentIntent::authority(Vec::new(), None),
        Metadata::default(),
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    ensure!(
        quote.observation.next_block_height == install_height,
        "install quote changed the certificate's exact next height"
    );
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "install quote changed payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    let transaction = account.sign_transaction(payload)?;
    // Persist the exact signed transaction before the sole submission attempt.
    private_file(
        &instructions_path.with_extension("submitted.nrt"),
        &transaction.encode_wire_v1()?,
    )?;
    let expected = transaction.hash();
    ensure!(
        timeout_at(deadline, account.submit_transaction_and_wait(&transaction)).await?? == expected,
        "installation hash changed"
    );
    Ok(install_height)
}

fn native_genesis_bundle(prepared: &prepare::Prepared) -> Result<NativeGenesisProvisioningBundle> {
    let manifest = iroha_genesis::RawGenesisTransaction::from_path(
        prepared.genesis_directory.join("genesis.json"),
    )?;
    let manifest_json = json::to_vec(&manifest)?;
    let signed_wire = fs::read(prepared.genesis_directory.join("genesis.signed.nrt"))?;
    let block_hash = prepared.network_id.into_genesis_hash();
    let validated = iroha_genesis::validate_prepared_genesis_bundle(
        &signed_wire,
        &manifest,
        &prepared.genesis_public_key,
        block_hash,
    )?;
    ensure!(
        validated.canonical_wire() == signed_wire,
        "native DKG input differs from the exact signed genesis"
    );
    Ok(NativeGenesisProvisioningBundle {
        manifest_sha256: iroha_crypto::sha256(&manifest_json),
        manifest_json,
        signed_wire,
        public_key: prepared.genesis_public_key.clone(),
        block_hash,
        chain_discriminant: manifest.chain_discriminant(),
    })
}

fn native_finality_limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 32 * 1024 * 1024,
        journal_bytes: 64 * 1024 * 1024,
        block_count: 256,
        allocated_bytes: 512 * 1024 * 1024,
    }
}

fn journal_from_store(
    store: &mut BlockStore,
    height: u64,
    deadline: Option<Instant>,
) -> Result<NativeFinalityJournal> {
    let limits = native_finality_limits();
    ensure!(
        (2..=u64::try_from(limits.block_count)?).contains(&height),
        "native finality needs a bounded H2+ prefix"
    );
    let mut blocks = Vec::with_capacity(usize::try_from(height)?);
    let mut total = 0_usize;
    for at in 1..=height {
        if let Some(deadline) = deadline {
            ensure!(
                Instant::now() < deadline,
                "native phase finality deadline elapsed"
            );
        }
        let mut index = [BlockIndex {
            start: 0,
            length: 0,
        }];
        store.read_block_indices(at - 1, &mut index)?;
        let length = usize::try_from(index[0].length)?;
        total = total
            .checked_add(length)
            .ok_or_else(|| eyre!("native journal length overflow"))?;
        ensure!(
            length > 0 && length <= limits.block_bytes && total <= limits.journal_bytes,
            "native source exceeds configured bounds before allocation"
        );
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        bytes.resize(length, 0);
        store.read_block_data(index[0].start, &mut bytes)?;
        blocks.push(NativeFinalityArtifact { block_wire: bytes });
    }
    Ok(NativeFinalityJournal { blocks })
}

fn read_exact_finality(
    config_path: &Path,
    height: u64,
    deadline: Instant,
) -> Result<NativeFinalityJournal> {
    ensure!(
        Instant::now() < deadline,
        "native phase finality deadline elapsed"
    );
    let native = config(config_path)?;
    let mut store =
        BlockStore::open_read_only(Kura::canonical_storage_path(native.kura.store_dir.value()))?;
    let journal = journal_from_store(&mut store, height, Some(deadline))?;
    let mut cursor = NativeJournalCursor::new(
        native.common.chain.clone(),
        iroha_data_model::NetworkId::from_genesis_hash(native.genesis.expected_hash),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        native_finality_limits(),
        &iroha_allocation::AllocationBudget::new(native_finality_limits().allocated_bytes),
    )
    .map_err(|error| eyre!(error))?;
    ensure!(
        cursor
            .advance((&journal).into())
            .map_err(|error| eyre!(error))?
            .height()
            == height,
        "native finality differs from requested phase"
    );
    ensure!(
        Instant::now() < deadline,
        "native phase finality deadline elapsed"
    );
    Ok(journal)
}

fn verify_pulse(
    peer_configs: &[PathBuf],
    bundle: &Value,
    catalog_entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> Result<()> {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    iroha_genesis::init_instruction_registry();
    let record: beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1 =
        json::from_value(field(bundle, "record")?.clone())?;
    let session_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    record.validate(&session_budget)?;
    let genesis = field(bundle, "genesis")?;
    let manifest: iroha_genesis::RawGenesisTransaction =
        json::from_value(field(genesis, "manifest")?.clone())?;
    let signed_wire: Vec<u8> = json::from_value(field(genesis, "signed_wire")?.clone())?;
    let public_key: iroha_crypto::PublicKey =
        json::from_value(field(genesis, "public_key")?.clone())?;
    iroha_genesis::validate_prepared_genesis_bundle(
        &signed_wire,
        &manifest,
        &public_key,
        record.session.network_id.into_genesis_hash(),
    )?;
    let parameters = manifest.effective_parameters()?;
    let epoch_length = parameters.sumeragi().epoch_length_blocks.get();
    ensure!(
        epoch_length == epoch_retention::EPOCH_LENGTH,
        "fixture must exercise the native catalog decision at mandatory height 6"
    );
    let pulse_height = epoch_length
        .checked_sub(1)
        .filter(|height| *height > 1)
        .ok_or_else(|| eyre!("signed genesis has no first mandatory pulse anchor"))?;
    let anchor_height = pulse_height - 1;
    let session = beacon::validate_global_threshold_beacon_session_v1(
        &record.session,
        &beacon::GlobalThresholdBeaconSessionBindingV1 {
            network_id: record.session.network_id,
            session_id: record.session.session_id,
            roster_hash: record.session.roster_hash,
            transcript_hash: record.session.transcript_hash,
        },
        &session_budget,
    )?;
    let mut common = None;
    for config_path in peer_configs {
        // All fixture children have stopped. This is a strict read-only native
        // journal reader, so validation cannot repair or rewrite the evidence.
        let native = config(config_path)?;
        let mut store = BlockStore::open_read_only(Kura::canonical_storage_path(
            native.kura.store_dir.value(),
        ))?;
        ensure!(
            store.read_index_count()? > epoch_length,
            "paid deployment did not cross the mandatory epoch boundary"
        );
        ensure!(
            iroha_data_model::NetworkId::from_genesis_hash(native.genesis.expected_hash)
                == record.session.network_id
                && native.common.chain == *manifest.chain_id(),
            "peer configuration differs from independently signed ceremony source"
        );
        let journal = journal_from_store(&mut store, epoch_length + 1, None)?;
        let cursor = NativeJournalCursor::new(
            native.common.chain.clone(),
            record.session.network_id,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            native_finality_limits(),
            &iroha_allocation::AllocationBudget::new(native_finality_limits().allocated_bytes),
        )
        .map_err(|error| eyre!(error))?;
        let certified = with_verified_native_journal(
            (&journal).into(),
            &native.common.chain,
            &record.session.network_id,
            native_finality_limits(),
            cursor.allocation_budget(),
            |reader| {
                reader
                    .walk(1, epoch_length + 1)
                    .collect::<std::result::Result<Vec<CertifiedBlock>, _>>()
                    .map_err(iroha_core::sumeragi::native_journal::NativeJournalError::History)
            },
        )
        .map_err(|error| eyre!(error))?;
        let anchor = certified[usize::try_from(anchor_height - 1)?].block();
        let pulse_source = &certified[usize::try_from(pulse_height - 1)?];
        let block = pulse_source.block();
        // Native completion authenticated this exact catalog transaction on all
        // four peers. Bind its sole direct input and committed route to the pulse.
        let context = block
            .execution_context()
            .ok_or_else(|| eyre!("mandatory pulse has no certified execution context"))?;
        ensure!(
            context.lane_merge.is_none()
                && block.external_entrypoint_count() == 1
                && context.external.len() == 1
                && context.external[0].entrypoint_hash == catalog_entrypoint_hash
                && context.external[0].lane_id == LaneId::SINGLE
                && context.external[0].dataspace_id == DataSpaceId::UNIVERSAL,
            "mandatory pulse carrier is not the exact one-transaction catalog execution"
        );
        let initial_authority = certified[0].commitment().schedule.current.generation();
        let mut prior_authorization = None;
        for proof in certified.iter().skip(1) {
            let height = proof.height();
            let context = &proof.commitment().schedule.current;
            ensure!(
                context.generation() == initial_authority,
                "unchanged committee must retain the same immutable authority generation"
            );
            if height == epoch_length {
                prior_authorization = Some(context.authorization);
            }
            if height == epoch_length + 1 {
                let authorization = &context.authorization;
                ensure!(
                    authorization.epoch == 1,
                    "scheduling epoch must advance after retained boundary"
                );
                ensure!(
                    authorization.decision == ValidatorEpochDecisionV1::Retain,
                    "unchanged committee must authenticate a retain decision"
                );
                ensure!(
                    authorization.beacon
                        == BeaconEpochBindingV1::Installed(
                            iroha_data_model::sumeragi::epoch::InstalledBeaconEpochBindingV1 {
                                session_id: record.session.session_id,
                                transcript_hash: record.session.transcript_hash
                            }
                        ),
                    "retained epoch must bind installed beacon authority"
                );
                authorization.validate_successor(
                    prior_authorization
                        .as_ref()
                        .ok_or_else(|| eyre!("missing certified boundary authorization"))?,
                )?;
            }
        }
        // Native completion already authenticated this catalog transaction as Applied
        // on every peer. Bind its sole network entrypoint to the real pulse block.
        ensure!(
            block.network_entrypoint_count() == 1
                && block
                    .network_entrypoint_at(0)
                    .is_some_and(|entrypoint| entrypoint.hash() == catalog_entrypoint_hash),
            "mandatory pulse block is not the exact catalog transaction"
        );
        let pulse = pulse_source.commitment().beacon.as_ref().ok_or_else(|| {
            eyre!("mandatory pulse absent from native certified result at height {pulse_height}")
        })?;
        ensure!(
            pulse.height == pulse_height,
            "mandatory pulse height differs"
        );
        beacon::verify_finalized_global_threshold_beacon_pulse_v1(
            &session,
            pulse,
            GlobalThresholdBeaconChainAnchorV1 {
                height: anchor_height,
                block_hash: anchor.hash(),
            },
            &{
                let header = pulse_source
                    .header()
                    .ok_or_else(|| eyre!("native pulse header is absent"))?;
                iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
                    instance: header.instance.0,
                    epoch: header.epoch.epoch,
                    epoch_context_id: header.epoch.context.0,
                    parent_consensus_hash: header.parent_hash.0,
                    parent_result: header.parent_result.0,
                }
            },
        )?;
        let proof = (block.hash(), *pulse);
        if let Some(expected) = &common {
            ensure!(
                expected == &proof,
                "validators disagree on the real threshold pulse"
            );
        } else {
            common = Some(proof);
        }
    }
    ensure!(
        peer_configs.len() == 4,
        "pulse verification needs every validator"
    );
    Ok(())
}

fn set_snapshot_mode(peer_configs: &[PathBuf], mode: &str) -> Result<()> {
    ensure!(
        matches!(mode, "disabled" | "read_write"),
        "invalid fixture snapshot mode"
    );
    for path in peer_configs {
        let mut table: toml::Table = fs::read_to_string(path)?.parse()?;
        let snapshot = table
            .get_mut("snapshot")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| eyre!("fixture snapshot configuration missing"))?;
        snapshot.insert("mode".into(), toml::Value::String(mode.into()));
        fs::write(path, toml::to_string(&table)?)?;
    }
    Ok(())
}
fn peer_logs(directory: &Path, peer: usize, run: u16) -> [PathBuf; 2] {
    [
        directory.join(format!("peer{peer}-run{run}-stdout.log")),
        directory.join(format!("peer{peer}-run{run}-stderr.log")),
    ]
}
struct Runtime<'a> {
    directory: &'a Path,
    daemon: &'a Path,
    roster: &'a [iroha_model_base::peer::PeerId],
    api: u16,
    clients: &'a [iroha::client::Client],
    peers: &'a mut Peers,
    run: u16,
}
impl Runtime<'_> {
    async fn restart(&mut self, deadline: Instant) -> Result<()> {
        self.peers.stop(deadline).await?;
        self.run = self
            .run
            .checked_add(1)
            .ok_or_else(|| eyre!("fixture run counter overflow"))?;
        *self.peers = spawn_peers(self.directory, self.daemon, self.roster, self.run)?;
        listeners_started(self.peers, self.api, deadline).await?;
        for index in 0..4 {
            ready(self.api + index, 200, deadline).await?;
        }
        status_height(self.clients, deadline).await?;
        Ok(())
    }
    async fn signed_snapshot_restart(&mut self, applied_height: u64) -> Result<()> {
        let snapshot_deadline = Instant::now() + Duration::from_secs(60);
        timeout_at(snapshot_deadline, async {
            loop {
                let mut complete = true;
                for peer in 0..4 {
                    let root = self.directory.join(format!("state/peer{peer}/snapshot"));
                    let height = public_sequence::snapshot_height(&root)?;
                    complete &= if let Some(height) = height {
                        height >= applied_height && public_sequence::snapshot_log_contains_height(&peer_logs(self.directory, peer, self.run), "Successfully created a snapshot of state", height)?
                    } else { false };
                }
                if complete { return Ok::<_, eyre::Report>(()); }
                sleep(Duration::from_millis(200)).await;
            }
        }).await.wrap_err("all validators must publish complete signed snapshots after the exact Applied transaction")??;
        let restart = Instant::now() + PHASE_BUDGET;
        self.peers.stop(restart).await?;
        let heights = (0..4)
            .map(|peer| {
                public_sequence::snapshot_height(
                    &self.directory.join(format!("state/peer{peer}/snapshot")),
                )?
                .ok_or_else(|| eyre!("snapshot disappeared during shutdown"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            heights.iter().all(|height| *height >= applied_height),
            "shutdown snapshot regressed"
        );
        // Restart reconnects to each peer's still-running stock broker, which
        // retains its original runtime signer.
        self.restart(restart).await?;
        timeout_at(restart, async {
            loop {
                let mut complete = true;
                for (peer, &height) in heights.iter().enumerate() {
                    let status = validator_status_until(&self.clients[peer], restart).await?;
                    complete &= status.blocks >= height
                        && public_sequence::snapshot_log_contains_height(
                            &peer_logs(self.directory, peer, self.run),
                            "Successfully loaded the state from a snapshot",
                            height,
                        )?;
                }
                if complete {
                    return Ok::<_, eyre::Report>(());
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .wrap_err("native restart did not authenticate each retained signed snapshot")??;
        Ok(())
    }
}

fn assert_native_routes(
    peer_configs: &[PathBuf],
    universal: &iroha::client::Client,
    routed: &iroha::client::Client,
) -> Result<()> {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let universal = universal
        .to_builder()
        .account
        .to_i105_for_discriminant(369)?;
    let routed = routed.to_builder().account.to_i105_for_discriminant(369)?;
    ensure!(
        universal != routed,
        "route scenarios must use different canonical accounts"
    );
    for path in peer_configs {
        let native = config(path)?;
        let policy = &native.nexus.routing_policy;
        ensure!(
            policy.default_lane.as_u32() == 0,
            "universal scenario lost its native default route"
        );
        ensure!(
            policy
                .rules
                .iter()
                .all(|rule| rule.matcher.account.as_deref() != Some(universal.as_str())),
            "default-route account gained an exact override"
        );
        let selected = policy
            .rules
            .iter()
            .find(|rule| rule.matcher.account.as_deref() == Some(routed.as_str()))
            .ok_or_else(|| eyre!("explicit routed fixture account absent"))?;
        let lane = native
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .find(|lane| lane.id.as_u32() == 3)
            .ok_or_else(|| eyre!("native PayNet lane absent"))?;
        ensure!(
            selected.lane == lane.id
                && selected.dataspace == Some(lane.dataspace_id)
                && selected.matcher.instruction.is_none(),
            "explicit account route changed native lane or dataspace"
        );
    }
    Ok(())
}

// The preceding paid helper has already authenticated the exact three retained
// transactions and completion on all four peers. Reconstruct its catalog result
// from that local plan and the unchanged generated startup authority, never from
// an HTTP state response that the next scenario is meant to verify.
fn catalog_fixture(
    prepared: &prepare::Prepared,
    peer_configs: &[PathBuf],
    clients: &[iroha::client::Client],
    api: u16,
) -> Result<super::runtime_catalog_transition::real_custody::CatalogFixture> {
    use super::runtime_catalog_transition::real_custody::{CatalogFixture, CatalogPeer};
    use iroha_core::governance::manifest::LaneManifestRegistry;
    use iroha_crypto::Hash;
    use iroha_data_model::nexus::{
        LaneCatalog, LaneLifecycleParameterV1, LaneLifecycleStatusV1, NexusCatalogTransitionV1,
        NexusRuntimeCatalogV1, dataspace_catalog_hash,
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    ensure!(
        peer_configs.len() == 4 && clients.len() == 4,
        "catalog requires four native configurations"
    );
    let configs = peer_configs
        .iter()
        .map(|path| config(path))
        .collect::<Result<Vec<_>>>()?;
    let first = &configs[0].nexus;
    let registry = LaneManifestRegistry::from_config(
        &first.configured_lane_catalog,
        &first.governance,
        &first.registry,
    );
    let manifests_hash = Hash::prehashed(registry.baseline_consensus_policy_digest());
    for config in &configs {
        let nexus = &config.nexus;
        let registry = LaneManifestRegistry::from_config(
            &nexus.configured_lane_catalog,
            &nexus.governance,
            &nexus.registry,
        );
        ensure!(
            nexus.configured_lane_catalog == first.configured_lane_catalog
                && nexus.configured_dataspace_catalog == first.configured_dataspace_catalog
                && Hash::prehashed(registry.baseline_consensus_policy_digest()) == manifests_hash,
            "four generated immutable catalog authorities differ"
        );
    }
    let plan: Value = json::from_slice(&fs::read(
        prepared
            .directory
            .join("paid-deployment/journal/clean-client-dpn/plan.json"),
    )?)?;
    let baseline: LaneLifecycleStatusV1 = json::from_value(field(&plan, "baseline")?.clone())?;
    let transition: NexusCatalogTransitionV1 =
        json::from_value(field(&plan, "catalog_transition")?.clone())?;
    transition.validate_structure()?;
    ensure!(
        text(&plan, "operation_id")? == "clean-client-dpn"
            && field(&plan, "baseline_overlay")?.is_null()
            && baseline.validate()? == first.configured_lane_catalog
            && baseline.catalog_hash
                == LaneLifecycleParameterV1::catalog_hash(&first.configured_lane_catalog)
            && transition.expected_catalog_hash == baseline.catalog_hash
            && transition.expected_incarnation_root == baseline.incarnation_root
            && transition.expected_runtime_catalog_hash.is_none(),
        "retained paid transition is not bound to the exact native baseline"
    );
    ensure!(
        transition.lane_additions.len() == 1
            && transition.lane_additions[0].id == LaneId::new(6)
            && transition.dataspace_additions.len() == 1
            && transition.manifest_additions.len() == 1,
        "paid fixture no longer has its exact single catalog addition"
    );
    let mut lanes = first.configured_lane_catalog.lanes().to_vec();
    lanes.extend(transition.lane_additions.clone());
    let lane_count = lanes
        .iter()
        .map(|lane| lane.id.as_u32() + 1)
        .max()
        .unwrap()
        .max(baseline.lane_count);
    let lanes = LaneCatalog::new(
        std::num::NonZeroU32::new(lane_count).ok_or_else(|| eyre!("zero namespace"))?,
        lanes,
    )?;
    let runtime = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: dataspace_catalog_hash(&first.configured_dataspace_catalog),
        baseline_manifests_hash: manifests_hash,
        dataspaces: transition.dataspace_additions,
        manifests: transition.manifest_additions,
    };
    runtime.validate_structure()?;
    let old = first
        .configured_lane_catalog
        .lanes()
        .iter()
        .find(|lane| lane.id == first.routing_policy.default_lane)
        .ok_or_else(|| eyre!("configured default lane missing"))?;
    let writer = client(&prepared.directory.join("client.toml"), api)?;
    let grantee = client(&prepared.routed_client, api)?.to_builder().account;
    let manifest = iroha_genesis::RawGenesisTransaction::from_path(
        prepared.genesis_directory.join("genesis.json"),
    )?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &fs::read(prepared.genesis_directory.join("genesis.signed.nrt"))?,
        &manifest,
        &prepared.genesis_public_key,
        prepared.network_id.into_genesis_hash(),
    )?;
    let peers = configs
        .iter()
        .zip(clients)
        .map(|(config, client)| CatalogPeer {
            client: client.clone(),
            peer_id: config.common.peer.id.clone(),
            kura_store: config.kura.store_dir.value().to_path_buf(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| eyre!("catalog reader count differs"))?;
    Ok(CatalogFixture {
        peers,
        delegator: writer.to_builder().account,
        writer,
        genesis,
        chain_id: manifest.chain_id().to_string(),
        baseline_dataspaces: first.configured_dataspace_catalog.clone(),
        baseline_lanes: lanes.lanes().to_vec(),
        previous_runtime: Some(runtime),
        old_route: (old.id, old.dataspace_id),
        added_lane: LaneId::new(5),
        added_dataspace: DataSpaceId::new(56_005),
        grantee,
    })
}

async fn retained_catalog_recovery(
    runtime: &mut Runtime<'_>,
    prepared: &prepare::Prepared,
    peer_configs: &[PathBuf],
) -> Result<()> {
    use super::runtime_catalog_transition::real_custody::{
        CatalogScenario, replayed_complete_history,
    };
    let mut scenario = CatalogScenario::begin(catalog_fixture(
        prepared,
        peer_configs,
        runtime.clients,
        runtime.api,
    )?)
    .await?;
    let replay_height = scenario.replay_height();
    let restart_deadline = Instant::now() + FUNCTIONAL_FINALITY_TIMEOUT;
    runtime.peers.stop(restart_deadline).await?;
    for peer in 0..4 {
        ensure!(
            public_sequence::snapshot_height(
                &runtime.directory.join(format!("state/peer{peer}/snapshot"))
            )?
            .is_none(),
            "retained full replay must precede every signed snapshot publication"
        );
    }
    // Enabling the writer on this restart matches the retained contract: state
    // first reconstructs the complete Kura prefix, then may publish snapshots.
    set_snapshot_mode(peer_configs, "read_write")?;
    let previous_run = runtime.run;
    runtime.restart(restart_deadline).await?;
    ensure!(
        runtime.run > previous_run,
        "full replay reused a prior daemon run"
    );
    timeout_at(restart_deadline, async {
        loop {
            let mut complete = true;
            for peer in 0..4 {
                complete &= validator_status_until(&runtime.clients[peer], restart_deadline)
                    .await?
                    .blocks
                    >= replay_height
                    && replayed_complete_history(
                        &peer_logs(runtime.directory, peer, runtime.run),
                        replay_height,
                    )?;
            }
            if complete {
                return Ok::<_, eyre::Report>(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .wrap_err("all four validators must replay the authenticated complete Kura prefix")??;
    let snapshot_height = scenario.after_full_replay().await?;
    runtime.signed_snapshot_restart(snapshot_height).await?;
    scenario.after_snapshot_restore().await?;
    eprintln!(
        "catalog expansion retained exact four-peer execution, committee and permission history through full replay and signed snapshot restore"
    );
    Ok(())
}

async fn both_public_sequences(
    runtime: &mut Runtime<'_>,
    peer_configs: &[PathBuf],
    routed_config: &Path,
) -> Result<()> {
    let universal = client(&runtime.directory.join("client.toml"), runtime.api)?;
    let routed = client(routed_config, runtime.api)?;
    assert_native_routes(peer_configs, &universal, &routed)?;
    set_snapshot_mode(peer_configs, "read_write")?;
    runtime.restart(Instant::now() + PHASE_BUDGET).await?;
    for (scope, client) in [("universal", universal), ("explicit PayNet", routed)] {
        let mut height = status_height(runtime.clients, Instant::now() + PHASE_BUDGET).await?;
        for sequence in 1..=3 {
            height =
                public_sequence::submit_and_observe(&client, runtime.clients, sequence, height)
                    .await?;
            if sequence == 2 {
                runtime.signed_snapshot_restart(height).await?;
            }
        }
        eprintln!(
            "retained {scope} three-transaction contract passed on real custody, including all-four signed-snapshot restore and post-restart Applied"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_peer_fresh_custody_bootstrap_reaches_mandatory_pulse() -> Result<()> {
    run_fresh_custody_bootstrap().await
}

async fn run_fresh_custody_bootstrap() -> Result<()> {
    // Validate the same immutable identity used by the paid trust helper before
    // artifact reads, custody creation, genesis generation, or child startup.
    // The complete fixture binds every proof to this exact release source.
    let build_identity = epoch_retention::admit_build_identity(
        iroha_core::compiled_build_identity!()
            .wrap_err("production beacon fixture has invalid compiled build metadata")?,
    )?;
    init_instruction_registry();
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let daemon = binary("TEST_NETWORK_BIN_IROHAD", ReleasePrebuiltBinary::Irohad)?;
    let launcher = binary(
        "TEST_NETWORK_BIN_IROHAD_TAIRA",
        ReleasePrebuiltBinary::IrohadTaira,
    )?;
    let cli = binary("TEST_NETWORK_BIN_IROHA", ReleasePrebuiltBinary::Iroha)?;
    let kagami = binary("KAGAMI_BIN", ReleasePrebuiltBinary::Kagami)?;
    let broker_binary = Program::IrohadDisposableBroker.resolve_skip_build()?;
    let workspace = runtime_workspace()?;
    let (api, p2p, reservations) = reserve_ports()?;
    let preparation_started = Instant::now();
    let preparation_deadline = preparation_started + PHASE_BUDGET;
    eprintln!(
        "beacon fixture preparing fresh genesis: budget={:.3}s",
        PHASE_BUDGET.as_secs_f64()
    );
    let prepared = match prepare::prepare(
        workspace.path(),
        &kagami,
        &cli,
        api,
        p2p,
        preparation_deadline,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!(
                "beacon fixture preparation retained at {}",
                workspace.keep().display()
            );
            return Err(error);
        }
    };
    eprintln!(
        "beacon fixture fresh genesis prepared: elapsed={:.3}s",
        preparation_started.elapsed().as_secs_f64()
    );
    let directory = &prepared.directory;
    // The running fixture uses the stock daemon and authenticated provider broker.
    // Qualify the shipping launcher separately against every exact generated
    // core-testnet config before any peer starts: its deployment profile guard
    // must accept the same four-node inputs the reset will materialize.
    let launcher_check_deadline = Instant::now() + PHASE_BUDGET;
    let launcher_check = async {
        for peer in 0..4 {
            let mut check = command(&launcher, directory);
            check
                .args(["--sora", "--config"])
                .arg(directory.join(format!("peer{peer}.toml")))
                .args(["--genesis-manifest-json"])
                .arg(prepared.genesis_directory.join("genesis.json"))
                .arg("--check-config");
            let output = run(check, launcher_check_deadline)
                .await
                .wrap_err_with(|| {
                    format!("shipping Taira launcher rejected generated peer{peer} config")
                })?;
            if output != b"Ready: configuration and available genesis are valid\n" {
                let diagnostic = workspace
                    .path()
                    .join(format!("launcher-check-peer{peer}.stdout"));
                private_file(&diagnostic, &output)?;
                return Err(eyre!(
                    "shipping Taira launcher did not complete offline genesis validation for peer{peer}; private stdout: {}",
                    diagnostic.display()
                ));
            }
        }
        Ok::<(), color_eyre::Report>(())
    }
    .await;
    if let Err(error) = launcher_check {
        eprintln!(
            "beacon fixture launcher precheck retained at {}",
            workspace.keep().display()
        );
        return Err(error);
    }
    let fresh = fresh_client(directory, &prepared.network_id)?;
    let clients = (0..4)
        .map(|index| client(&directory.join("client.toml"), api + index))
        .collect::<Result<Vec<_>>>()?;
    let public_config = config(&directory.join("peer0.toml"))?;
    ensure!(
        public_config.common.chain.to_string() == CHAIN,
        "fixture must use the exact Taira chain"
    );
    // Read only the fixture's generated public policy as independent authority;
    // an HTTP discovery response does not select faucet identity.
    let table: toml::Table = toml::from_str(&fs::read_to_string(directory.join("peer0.toml"))?)?;
    let faucet = &table["torii"]["faucet"];
    let faucet = ["authority", "asset_definition_id", "amount"]
        .map(|key| {
            faucet
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("native fixture faucet {key} absent"))
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let faucet: [String; 3] = faucet
        .try_into()
        .map_err(|_| eyre!("faucet policy length"))?;
    drop(table);
    drop(reservations);
    // Native genesis generation is a separate bounded phase. Listener availability
    // and exact committed genesis are separate observations under one startup deadline.
    let startup_started = Instant::now();
    let startup = startup_started + PHASE_BUDGET;
    eprintln!(
        "beacon fixture starting four validators: budget={:.3}s",
        PHASE_BUDGET.as_secs_f64()
    );
    let mut brokers = stage_initial_provider_brokers(directory, &broker_binary).await?;
    let mut peers = spawn_peers(directory, &daemon, &prepared.roster, 1)?;
    let mut outcome: Result<()> = async {
        listeners_started(&mut peers, api, startup).await?;
        wait_for_exact_height(&clients, 1, startup).await?;
        for offset in 0..4 { ready(api + offset, 200, startup).await?; }
        eprintln!("beacon fixture initial startup complete: elapsed={:.3}s", startup_started.elapsed().as_secs_f64());
        let ceremony_deadline = Instant::now() + PHASE_BUDGET;
        let signed_genesis = native_genesis_bundle(&prepared)?;
        let chain_id = config(&directory.join("peer0.toml"))?.common.chain;
        let seats = prepared
            .roster
            .iter()
            .map(|validator| {
                let config_path = (0..4)
                    .map(|index| directory.join(format!("peer{index}.toml")))
                    .find(|path| config(path).is_ok_and(|native| native.common.peer.id == *validator))
                    .ok_or_else(|| eyre!("signed genesis voter has no native config"))?;
                Ok(DisposableGenesisConfigSeat {
                    validator: validator.clone(),
                    config_path,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let genesis_sha256 = iroha_crypto::sha256(&signed_genesis.signed_wire);
        let nonce = hex(&genesis_sha256)[..32].to_owned();
        let network_id = prepared.network_id;
        let genesis_sha256_hex = hex(&genesis_sha256);
        let authorization_context = norito::json!({
            "network_id": network_id,
            "signed_genesis_sha256": genesis_sha256_hex,
            "fixture": "fresh-production-beacon"
        });
        let authorization = hex(&iroha_crypto::sha256(json::to_vec(&authorization_context)?));
        let expires_ms = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis())? + 180_000;
        let canary = Canary { binary: &cli, directory, config: &fresh, root: format!("http://127.0.0.1:{api}"), nonce, authorization, expires_ms, faucet };
        let predecessor = Arc::new(StdMutex::new(None::<PathBuf>));
        let canary_ref = &canary;
        let clients_ref = &clients;
        let dkg = run_disposable_genesis_dkg_from_configs(
            signed_genesis,
            network_id,
            &chain_id,
            &seats,
            &launcher,
            native_finality_limits(),
            5,
            move |expected, _public_snapshot, deadline| {
                let predecessor = Arc::clone(&predecessor);
                let first_config = directory.join("peer0.toml");
                let canary = canary_ref;
                let clients = clients_ref;
                async move {
                    let ceremony_deadline = ceremony_deadline.min(Instant::from_std(deadline));
                    ensure!(Instant::now() < ceremony_deadline, "native phase callback deadline elapsed");
                    let operation = match expected {
                        2 => "onboarding",
                        3 => "faucet",
                        4 => "final-canary",
                        _ => return Err(eyre!("unexpected native genesis DKG phase")),
                    };
                    let previous = predecessor
                        .lock()
                        .map_err(|_| eyre!("beacon canary predecessor lock poisoned"))?
                        .clone();
                    let (envelope, proved_height) = canary
                        .operation(operation, previous.as_deref(), ceremony_deadline)
                        .await?;
                    ensure!(
                        proved_height == expected,
                        "live canary did not reach exact h{expected} DKG phase"
                    );
                    wait_for_exact_height(clients, expected, ceremony_deadline).await?;
                    if matches!(operation, "onboarding" | "faucet") {
                        // The SDK's synchronous client rejects a Tokio runtime thread.
                        // Replay the retained prepared envelope on an OS thread.
                        std::thread::scope(|scope| {
                            scope
                                .spawn(|| {
                                    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
                                    let client = clients[0].with_request_deadline(ceremony_deadline.into_std());
                                    canary.assert_committed_prepared_replay(operation, &client)
                                })
                                .join()
                                .map_err(|_| eyre!("committed prepared replay worker panicked"))?
                        })?;
                        wait_for_exact_height(clients, expected, ceremony_deadline).await?;
                    }
                    *predecessor
                        .lock()
                        .map_err(|_| eyre!("beacon canary predecessor lock poisoned"))? =
                        Some(envelope);
                    ensure!(Instant::now() < ceremony_deadline, "native phase callback deadline elapsed");
                    let journal = read_exact_finality(&first_config, expected, ceremony_deadline)?;
                    ensure!(Instant::now() < ceremony_deadline, "native phase callback deadline elapsed");
                    Ok(journal)
                }
            },
        )
        .await?;
        let bundle: Value = json::from_slice(&fs::read(&dkg.public_bundle_path)?)?;
        ensure!(field(&bundle, "finalized_observed_height")?.as_u64() == Some(4), "ceremony backdated its finalization");
        let certificate: ThresholdKeyLifecycleCertificateV1 = json::from_value(field(&bundle, "finalization_draft")?.clone())?;
        ensure!(certificate.effective_height == 5, "native certificate is not effective at exact h5");
        let instruction = &dkg.install_instruction_path;
        // Match the maintained controller: commit the certificate without a
        // local beacon provider, then activate custody on the same four ledgers.
        // Installation has a finite phase deadline; pending-work recovery is bounded below.
        let restart = Instant::now() + PHASE_BUDGET;
        let install_height = submit_install(&clients[0], instruction, &certificate, restart).await?;
        wait_for_exact_height(&clients, install_height, restart).await?;
        for offset in 0..4 { ready(api + offset, 200, restart).await?; }
        // Admission is available without beacon custody. The paid catalog operation below
        // independently proves that a required pulse cannot be omitted.
        wait_for_exact_meshed_height(&clients, install_height, restart).await?;
        let peer_configs = (0..4).map(|index| directory.join(format!("peer{index}.toml"))).collect::<Vec<_>>();
        let mut doctor = command(&cli, directory);
        doctor.args(["--machine", "taira", "doctor", "--scope", "basic", "--public-root", &format!("http://127.0.0.1:{api}"), "--json"]);
        let doctor_deadline = (Instant::now() + Duration::from_secs(60)).min(restart);
        let doctor_report: Value = json::from_slice(&run(doctor, doctor_deadline).await?)
            .wrap_err("basic public doctor returned invalid JSON")?;
        ensure!(doctor_report.get("status").and_then(Value::as_str) == Some("ok")
            && doctor_report.get("scope").and_then(Value::as_str) == Some("basic"),
            "basic public doctor omitted its successful scope");
        // The complete prior clean-client assertions run on real custody.
        // Their genuine operations cross the signed genesis's mandatory pulse.
        let genesis_wire = fs::read(prepared.genesis_directory.join("genesis.signed.nrt"))?;
        // Deployment uses the generated genesis-authorized client. The fresh
        // public account remains the onboarding/faucet/canary actor and receives
        // no deployment administration permissions.
        // The first genuine paid catalog transaction executes at required pulse height 6.
        // Its bounded initial observation must remain pending without providers; recovery
        // resumes the same signed transaction and native dispatch claim.
        let catalog_entrypoint_hash = super::dataspace_deploy_cli::run_paid_deployment(super::dataspace_deploy_cli::PaidDeploymentFixture {
            binary: &cli, build_identity, config: &directory.join("client.toml"), operator: &directory.join("runtime/operator-signer.key"),
            root: &directory.join("paid-deployment"), genesis_wire: &genesis_wire,
            genesis_public_key: &prepared.genesis_public_key, peer_configs: &peer_configs, clients: &clients,
        }, || async {
            let recovery = Instant::now() + PHASE_BUDGET;
            peers.stop(recovery).await?;
            for broker in &mut brokers { broker.stop(recovery).await?; }
            brokers.clear();
            let (active_brokers, active_configs) = stage_provider_brokers(
                directory, &broker_binary, &bundle, &dkg, &prepared.roster,
            ).await?;
            ensure!(active_configs == peer_configs, "provider restart changed validator configuration paths");
            brokers = active_brokers;
            peers = spawn_peers(directory, &daemon, &prepared.roster, 2)?;
            listeners_started(&mut peers, api, recovery).await?;
            for offset in 0..4 { ready(api + offset, 200, recovery).await?; }
            // The retained real catalog may now commit immediately; do not demand idle h5.
            Ok(())
        }).await?;
        {
            let mut runtime = Runtime { directory, daemon: &daemon, roster: &prepared.roster,
                api, clients: &clients, peers: &mut peers, run: 2 };
            retained_catalog_recovery(&mut runtime, &prepared, &peer_configs).await?;
            both_public_sequences(&mut runtime, &peer_configs, &prepared.routed_client).await?;
        }
        let installed: beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1 =
            json::from_value(field(&bundle, "record")?.clone())?;
        epoch_retention::verify_boundary_chain(
            &prepared, &clients, &installed, Instant::now() + PHASE_BUDGET,
        ).await?;
        peers.stop(Instant::now() + PHASE_BUDGET).await?;
        verify_pulse(&peer_configs, &bundle, catalog_entrypoint_hash)?;
        eprintln!("four fresh production-custody validators completed native onboarding/faucet/canary/install and paid deployment across a verified mandatory pulse");
        Ok(())
    }.await;
    if !peers.children.is_empty() {
        let stopped = peers.stop(Instant::now() + Duration::from_secs(30)).await;
        if outcome.is_ok() {
            stopped?;
        }
    }
    for broker in &mut brokers {
        if let Err(error) = broker.stop(Instant::now() + Duration::from_secs(10)).await
            && outcome.is_ok()
        {
            outcome = Err(error);
        }
    }
    // Keep failure diagnostics and generated custody owner-private outside Git.
    if outcome.is_err() {
        eprintln!(
            "beacon fixture evidence retained at {}",
            workspace.keep().display()
        );
    }
    outcome
}

#[test]
fn production_beacon_exact_height_wait_preserves_retained_tip() -> Result<()> {
    use iroha_torii_shared::status::Status;
    let mut statuses: [Status; 4] = std::array::from_fn(|_| Status {
        blocks: 6,
        ..Status::default()
    });
    // A shared drained replay prefix is not the retained tip. Require every
    // peer to finish its pending tip rather than returning the common prefix.
    assert!(!exact_height_reached(&statuses, 7)?);
    for peer in 0..3 {
        statuses[peer].blocks = 7;
        assert!(!exact_height_reached(&statuses, 7)?);
    }
    statuses[3].blocks = 7;
    statuses[2].queue_size = 1;
    assert!(!exact_height_reached(&statuses, 7)?);
    statuses[2].queue_size = 0;
    assert!(exact_height_reached(&statuses, 7)?);
    // Overshoot is fatal even while another peer is behind or has queued work.
    statuses[0].blocks = 8;
    statuses[1].blocks = 6;
    statuses[1].queue_size = 1;
    assert!(exact_height_reached(&statuses, 7).is_err());
    assert!(exact_height_reached(&statuses[..3], 7).is_err());
    assert!(exact_height_reached(&statuses, 0).is_err());
    Ok(())
}

#[test]
fn production_beacon_paid_deployment_waits_for_full_mesh_at_exact_height() -> Result<()> {
    use iroha_torii_shared::status::Status;
    let mut statuses: [Status; 4] = std::array::from_fn(|_| Status {
        blocks: 8,
        peers: 3,
        ..Status::default()
    });
    assert!(exact_meshed_height_reached(&statuses, 8)?);
    statuses[0].peers = 0;
    assert!(!exact_meshed_height_reached(&statuses, 8)?);
    statuses[0].peers = 3;
    statuses[1].queue_size = 1;
    assert!(!exact_meshed_height_reached(&statuses, 8)?);
    statuses[1].queue_size = 0;
    statuses[2].blocks = 7;
    assert!(!exact_meshed_height_reached(&statuses, 8)?);
    statuses[2].blocks = 9;
    assert!(exact_meshed_height_reached(&statuses, 8).is_err());
    Ok(())
}

#[test]
fn production_beacon_fixture_root_rejects_git_symlink_and_shared_custody() -> Result<()> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME absent"))?;
    let base = fs::canonicalize(home)?;
    let root = tempfile::Builder::new()
        .prefix("beacon-root-contract-")
        .tempdir_in(base)?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    assert_eq!(validate_runtime_root(root.path())?, root.path());
    fs::create_dir(root.path().join(".git"))?;
    assert!(validate_runtime_root(root.path()).is_err());
    fs::remove_dir(root.path().join(".git"))?;
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias)?;
    assert!(validate_runtime_root(&alias).is_err());
    fs::remove_file(alias)?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777))?;
    assert!(validate_runtime_root(root.path()).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    Ok(())
}
