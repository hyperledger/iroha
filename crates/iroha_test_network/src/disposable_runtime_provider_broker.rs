//! Owner-private broker supervision for disposable validator networks.

use super::*;
use iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath;
use std::{
    fs::Permissions,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};
use tempfile::{NamedTempFile, TempDir};
use zeroize::Zeroizing;

const PRIVATE_DIRECTORY_PREFIX: &str = ".iroha-b-";
const PRIVATE_DIRECTORY_RANDOM_BYTES: usize = 6;
const BROKER_SOCKET_BASENAME: &str = "runtime-provider-broker-v1.sock";
const PUBLIC_CATALOG_MAX_BYTES: usize = 256 * 1024;
const CREDENTIAL_BUNDLE_MAX_BYTES: usize = 2 * 16 * 1024 * 1024 + 28;
const BROKER_READY_TOKEN: &[u8; 6] = b"READY\n";
const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(120);
const BROKER_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Exact public signer binding installed in one disposable validator's config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisposableBeaconProviderBinding {
    /// Stable credential-free production provider identity.
    pub handle: String,
    /// Positive catalog generation.
    pub revision: u64,
    /// Non-zero digest of this seat's public credential inventory.
    pub policy_digest: [u8; 32],
}

impl DisposableBeaconProviderBinding {
    /// Validate the same public tuple required by production Sumeragi config.
    ///
    /// # Errors
    ///
    /// Rejects a test-marked or malformed handle, zero revision, or zero digest.
    pub fn validate(&self) -> Result<()> {
        iroha_config::parameters::validate_production_runtime_handle(&self.handle)
            .map_err(|_| eyre!("disposable beacon handle is not production-canonical"))?;
        if self.revision == 0 || self.revision > i64::MAX as u64 || self.policy_digest == [0; 32] {
            return Err(eyre!(
                "disposable beacon binding has a zero revision or digest"
            ));
        }
        Ok(())
    }
}

/// One peer's stable endpoint and zeroizing credential handoff across restarts.
pub(super) struct DisposableBrokerConfig {
    directory: Arc<TempDir>,
    endpoint: RuntimeProviderBrokerEndpointPath,
    catalog_path: PathBuf,
    policy_path: PathBuf,
    credential_bundle: Zeroizing<Vec<u8>>,
    beacon_binding: DisposableBeaconProviderBinding,
}

impl fmt::Debug for DisposableBrokerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisposableBrokerConfig")
            .field("endpoint", &self.endpoint)
            .field("catalog_path", &self.catalog_path)
            .field("policy_path", &self.policy_path)
            .field("beacon_binding", &self.beacon_binding)
            .field("credential_bundle", &"[REDACTED]")
            .finish()
    }
}

fn verify_trusted_directory_chain(path: &Path, immediate_owner: u32) -> Result<()> {
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.mode() & 0o022 != 0
            || (index == 0 && metadata.uid() != immediate_owner)
            || (index != 0 && metadata.uid() != immediate_owner && metadata.uid() != 0)
        {
            return Err(eyre!(
                "disposable broker endpoint has an untrusted directory ancestor: {}",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn create_private_directory() -> Result<Arc<TempDir>> {
    let parent = match std::env::var_os(TEMPDIR_IN_ENV) {
        Some(configured) => PathBuf::from(configured),
        None => {
            let uid = nix::unistd::Uid::effective();
            nix::unistd::User::from_uid(uid)?
                .ok_or_else(|| eyre!("cannot resolve current service UID for broker custody"))?
                .dir
        }
    };
    create_private_directory_in(&parent)
}

fn create_private_directory_in(parent: &Path) -> Result<Arc<TempDir>> {
    let uid = nix::unistd::Uid::effective().as_raw();
    let raw = parent
        .to_str()
        .ok_or_else(|| eyre!("disposable broker root must be canonical absolute UTF-8"))?;
    if !raw.starts_with('/')
        || raw.split('/').skip(1).any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.contains('\\')
                || component.chars().any(char::is_control)
        })
    {
        return Err(eyre!(
            "disposable broker root must be canonical absolute UTF-8"
        ));
    }
    verify_trusted_directory_chain(parent, uid)?;
    // Reserve the real fixed-width directory suffix in the same endpoint bound
    // before creating anything. Long configured test roots must fail explicitly.
    RuntimeProviderBrokerEndpointPath::try_new(
        parent
            .join(format!(
                "{PRIVATE_DIRECTORY_PREFIX}{}",
                "x".repeat(PRIVATE_DIRECTORY_RANDOM_BYTES)
            ))
            .join(BROKER_SOCKET_BASENAME),
    )
    .map_err(|_| eyre!("disposable broker root makes the canonical socket path too long"))?;
    // Created owner-private: without explicit permissions the directory gets the process umask.
    let directory = tempfile::Builder::new()
        .prefix(PRIVATE_DIRECTORY_PREFIX)
        .rand_bytes(PRIVATE_DIRECTORY_RANDOM_BYTES)
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    verify_trusted_directory_chain(directory.path(), uid)?;
    if fs::symlink_metadata(directory.path())?.permissions().mode() & 0o7777 != 0o700 {
        return Err(eyre!("disposable broker directory must be mode 0700"));
    }
    Ok(Arc::new(directory))
}

/// Create one owner-private root for a disposable peer's native DKG attempt.
///
/// The existing developer-only `TEST_NETWORK_TMP_DIR` chooses its parent when
/// set; otherwise the effective service UID's home is used. Every ancestor must
/// satisfy the stock broker's ownership and mode policy. Each call creates a
/// distinct root; dropping the handle removes that attempt's material.
///
/// # Errors
///
/// Rejects an unresolved service UID, a noncanonical or unsafe parent, an
/// oversized socket path, or a directory without exact owner-only permissions.
pub fn new_disposable_owner_private_root() -> Result<Arc<TempDir>> {
    create_private_directory()
}

fn publish_public_catalog(directory: &Path, catalog_path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > PUBLIC_CATALOG_MAX_BYTES {
        return Err(eyre!("disposable broker public catalog has invalid size"));
    }
    let mut staged = NamedTempFile::new_in(directory)?;
    staged.write_all(bytes)?;
    staged
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    staged.as_file().sync_all()?;
    staged.persist(catalog_path)?;
    Ok(())
}

impl DisposableBrokerConfig {
    fn prepare(
        existing_directory: Option<Arc<TempDir>>,
        catalog: &[u8],
        credential_bundle: Zeroizing<Vec<u8>>,
        beacon_binding: DisposableBeaconProviderBinding,
    ) -> Result<Self> {
        beacon_binding.validate()?;
        if credential_bundle.is_empty() || credential_bundle.len() > CREDENTIAL_BUNDLE_MAX_BYTES {
            return Err(eyre!(
                "disposable broker credential bundle has invalid size"
            ));
        }
        let directory = match existing_directory {
            Some(directory) => directory,
            None => create_private_directory()?,
        };
        verify_trusted_directory_chain(directory.path(), nix::unistd::Uid::effective().as_raw())?;
        let endpoint = RuntimeProviderBrokerEndpointPath::try_new(
            directory.path().join(BROKER_SOCKET_BASENAME),
        )
        .map_err(|_| eyre!("owner-private broker socket path is not canonical or is too long"))?;
        let catalog_path = directory.path().join("catalog.norito");
        publish_public_catalog(directory.path(), &catalog_path, catalog)?;
        let policy_path = directory.path().join("broker-policy.toml");
        let mut policy = toml::Table::new();
        policy.insert(
            "endpoint_path".into(),
            toml::Value::String(
                endpoint
                    .as_path()
                    .to_str()
                    .ok_or_else(|| eyre!("broker endpoint must be UTF-8"))?
                    .into(),
            ),
        );
        policy.insert(
            "observer_operation_timeout_ms".into(),
            toml::Value::Integer(15_000),
        );
        publish_public_catalog(
            directory.path(),
            &policy_path,
            toml::to_string(&policy)?.as_bytes(),
        )?;
        Ok(Self {
            directory,
            endpoint,
            catalog_path,
            policy_path,
            credential_bundle,
            beacon_binding,
        })
    }
}

impl NetworkPeer {
    /// Provision one exact public broker catalog and a one-shot native credential bundle.
    ///
    /// The caller must construct the bundle from this peer's actual DKG share and
    /// retain any still-active credential when adding a pending generation. The
    /// broker is launched before the daemon and receives only the bundle on an
    /// inherited pipe. Reprovisioning requires the peer to be stopped.
    ///
    /// # Errors
    ///
    /// Rejects a running peer, an unsafe owner path, oversized inputs, an
    /// invalid public binding, or a catalog that cannot be staged as a
    /// single-link read-only public file.
    pub async fn provision_disposable_runtime_provider_broker(
        &self,
        catalog: &[u8],
        credential_bundle: Zeroizing<Vec<u8>>,
        beacon_binding: DisposableBeaconProviderBinding,
    ) -> Result<PathBuf> {
        let run = self.run.lock().await;
        if run.is_some() {
            return Err(eyre!("stop peer before changing broker credentials"));
        }
        let mut current = self
            .disposable_runtime_provider_broker
            .lock()
            .map_err(|_| eyre!("disposable broker configuration lock is poisoned"))?;
        let existing_directory = current
            .as_ref()
            .map(|current| Arc::clone(&current.directory));
        let prepared = Arc::new(DisposableBrokerConfig::prepare(
            existing_directory,
            catalog,
            credential_bundle,
            beacon_binding,
        )?);
        let endpoint = prepared.endpoint.as_path().to_path_buf();
        *current = Some(prepared);
        drop(current);
        self.write_base_config();
        drop(run);
        Ok(endpoint)
    }

    pub(super) fn has_disposable_runtime_provider_broker(&self) -> bool {
        self.disposable_runtime_provider_broker
            .lock()
            .expect("disposable broker configuration lock should not be poisoned")
            .is_some()
    }

    pub(super) fn disposable_runtime_provider_broker_endpoint(&self) -> Option<PathBuf> {
        self.disposable_runtime_provider_broker
            .lock()
            .expect("disposable broker configuration lock should not be poisoned")
            .as_ref()
            .map(|current| current.endpoint.as_path().to_path_buf())
    }

    pub(super) fn disposable_beacon_provider_binding(
        &self,
    ) -> Option<DisposableBeaconProviderBinding> {
        self.disposable_runtime_provider_broker
            .lock()
            .expect("disposable broker configuration lock should not be poisoned")
            .as_ref()
            .map(|current| current.beacon_binding.clone())
    }

    pub(super) async fn spawn_disposable_runtime_provider_broker(
        &self,
        run_num: usize,
    ) -> Result<Option<Child>> {
        let configured = self
            .disposable_runtime_provider_broker
            .lock()
            .map_err(|_| eyre!("disposable broker configuration lock is poisoned"))?
            .clone();
        let Some(configured) = configured else {
            return Ok(None);
        };
        let binary = Program::IrohadDisposableBroker.resolve_async().await?;
        let stderr_path = self.dir.join(format!("run-{run_num}-broker-stderr.log"));
        let stderr = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&stderr_path)?;
        let mut command = tokio::process::Command::new(&binary);
        command
            .arg("--catalog")
            .arg(&configured.catalog_path)
            .arg("--broker-policy")
            .arg(&configured.policy_path)
            .current_dir(configured.directory.path())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .wrap_err("spawn disposable runtime-provider broker")?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| eyre!("disposable broker stdin pipe unavailable"))?;
        stdin.write_all(&configured.credential_bundle).await?;
        stdin.shutdown().await?;
        drop(stdin);
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| eyre!("disposable broker readiness pipe unavailable"))?;
        let mut ready = [0_u8; 6];
        timeout(BROKER_READY_TIMEOUT, stdout.read_exact(&mut ready))
            .await
            .map_err(|_| eyre!("disposable broker did not publish readiness"))??;
        if ready != *BROKER_READY_TOKEN {
            return Err(eyre!(
                "disposable broker published an invalid readiness token"
            ));
        }
        if let Some(status) = child.try_wait()? {
            return Err(eyre!(
                "disposable broker exited after readiness with status {status}"
            ));
        }
        Ok(Some(child))
    }
}

pub(super) async fn stop_disposable_broker(child: &mut Child) {
    if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        );
    }
    if !matches!(timeout(BROKER_STOP_TIMEOUT, child.wait()).await, Ok(Ok(_))) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(revision: u64) -> DisposableBeaconProviderBinding {
        DisposableBeaconProviderBinding {
            handle: "software://iroha/global-beacon/validator-a".to_owned(),
            revision,
            policy_digest: [u8::try_from(revision).expect("small revision"); 32],
        }
    }

    #[test]
    fn disposable_beacon_binding_rejects_unqualified_public_identity() {
        let mut candidate = binding(1);
        assert!(candidate.validate().is_ok());
        candidate.handle = "software://test/global-beacon/a".to_owned();
        assert!(candidate.validate().is_err());
        candidate = binding(1);
        candidate.revision = 0;
        assert!(candidate.validate().is_err());
        candidate = binding(1);
        candidate.policy_digest = [0; 32];
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn private_broker_endpoint_and_catalog_are_staged_without_exposing_credentials() -> Result<()> {
        let bundle = vec![0x5A; 28];
        let prepared = DisposableBrokerConfig::prepare(
            None,
            b"public-catalog",
            Zeroizing::new(bundle),
            binding(1),
        )?;
        assert_eq!(
            prepared
                .endpoint
                .as_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("runtime-provider-broker-v1.sock")
        );
        assert_eq!(fs::read(&prepared.catalog_path)?, b"public-catalog");
        let policy = iroha_config::parameters::actual::RuntimeProviderBroker::from_toml_source(
            iroha_config::base::toml::TomlSource::inline(
                fs::read_to_string(&prepared.policy_path)?.parse()?,
            ),
        )
        .map_err(|error| eyre!("parse staged disposable broker policy: {error:?}"))?;
        assert_eq!(policy.endpoint_path, prepared.endpoint);
        assert_eq!(policy.observer_operation_timeout, Duration::from_secs(15));
        assert_eq!(
            fs::symlink_metadata(&prepared.policy_path)?.mode() & 0o7777,
            0o400
        );
        assert_eq!(
            fs::symlink_metadata(&prepared.catalog_path)?.mode() & 0o7777,
            0o400
        );
        let other = DisposableBrokerConfig::prepare(
            None,
            b"other-public-catalog",
            Zeroizing::new(vec![0xA5; 28]),
            binding(1),
        )?;
        assert_ne!(prepared.endpoint, other.endpoint);
        let debug = format!("{prepared:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("90, 90"));
        verify_trusted_directory_chain(
            prepared.directory.path(),
            nix::unistd::Uid::effective().as_raw(),
        )?;
        Ok(())
    }

    #[test]
    fn separate_peer_attempt_roots_are_owner_private() -> Result<()> {
        let first = new_disposable_owner_private_root()?;
        let second = new_disposable_owner_private_root()?;
        assert_ne!(first.path(), second.path());
        for root in [&first, &second] {
            assert_eq!(fs::symlink_metadata(root.path())?.mode() & 0o7777, 0o700);
            verify_trusted_directory_chain(root.path(), nix::unistd::Uid::effective().as_raw())?;
        }
        Ok(())
    }

    fn configured_root_fixture() -> Result<TempDir> {
        // A short checkout-local parent also leaves room for the full canonical
        // Unix socket basename on macOS; no home or system-temp file is created.
        Ok(tempfile::Builder::new()
            .prefix("")
            .rand_bytes(6)
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(repo_root().join("target"))?)
    }

    #[test]
    fn configured_broker_root_retains_exact_parent_owner_and_endpoint_bound() -> Result<()> {
        let parent = configured_root_fixture()?;
        let first = create_private_directory_in(parent.path())?;
        let second = create_private_directory_in(parent.path())?;
        assert_ne!(first.path(), second.path());
        for child in [&first, &second] {
            assert_eq!(child.path().parent(), Some(parent.path()));
            assert_eq!(fs::symlink_metadata(child.path())?.mode() & 0o7777, 0o700);
            verify_trusted_directory_chain(child.path(), nix::unistd::Uid::effective().as_raw())?;
            RuntimeProviderBrokerEndpointPath::try_new(child.path().join(BROKER_SOCKET_BASENAME))?;
        }
        drop(first);
        drop(second);
        assert_eq!(fs::read_dir(parent.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn configured_broker_root_rejects_noncanonical_mutable_and_symlink_parents() -> Result<()> {
        let parent = configured_root_fixture()?;
        for bad in [
            PathBuf::new(),
            PathBuf::from("relative"),
            PathBuf::from(format!("{}/", parent.path().display())),
            PathBuf::from(format!("{}/./child", parent.path().display())),
            PathBuf::from(format!("{}/../child", parent.path().display())),
            PathBuf::from(format!("{}//child", parent.path().display())),
            PathBuf::from(format!("{}/bad\\child", parent.path().display())),
            PathBuf::from(format!("{}/bad\nchild", parent.path().display())),
        ] {
            let error = create_private_directory_in(&bad).unwrap_err();
            assert!(
                error.to_string().contains("canonical absolute"),
                "{error:?}"
            );
        }
        assert_eq!(fs::read_dir(parent.path())?.count(), 0);
        fs::set_permissions(parent.path(), Permissions::from_mode(0o770))?;
        let error = create_private_directory_in(parent.path()).unwrap_err();
        fs::set_permissions(parent.path(), Permissions::from_mode(0o700))?;
        assert!(error.to_string().contains("untrusted directory ancestor"));
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(parent.path(), &link)?;
        let error = create_private_directory_in(&link).unwrap_err();
        assert!(error.to_string().contains("untrusted directory ancestor"));
        assert_eq!(fs::read_dir(parent.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn configured_broker_root_rejects_oversized_endpoint_before_creating_custody() -> Result<()> {
        let parent = configured_root_fixture()?;
        let long = parent.path().join("x".repeat(64));
        fs::create_dir(&long)?;
        fs::set_permissions(&long, Permissions::from_mode(0o700))?;
        let error = create_private_directory_in(&long).unwrap_err();
        assert!(error.to_string().contains("socket path too long"));
        assert_eq!(fs::read_dir(&long)?.count(), 0);
        Ok(())
    }

    #[test]
    fn broker_catalog_replacement_retains_private_endpoint() -> Result<()> {
        let first =
            DisposableBrokerConfig::prepare(None, b"first", Zeroizing::new(vec![1]), binding(1))?;
        let second = DisposableBrokerConfig::prepare(
            Some(Arc::clone(&first.directory)),
            b"second",
            Zeroizing::new(vec![2]),
            binding(2),
        )?;
        assert_eq!(first.endpoint, second.endpoint);
        assert_eq!(fs::read(&second.catalog_path)?, b"second");
        assert!(
            DisposableBrokerConfig::prepare(
                Some(Arc::clone(&first.directory)),
                &vec![0; PUBLIC_CATALOG_MAX_BYTES + 1],
                Zeroizing::new(vec![2]),
                binding(3),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn broker_directory_rejects_mutable_and_symlink_ancestors() -> Result<()> {
        let directory = create_private_directory()?;
        let uid = nix::unistd::Uid::effective().as_raw();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o770))?;
        assert!(verify_trusted_directory_chain(directory.path(), uid).is_err());
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700))?;
        let link = directory.path().join("linked-parent");
        std::os::unix::fs::symlink(directory.path(), &link)?;
        assert!(verify_trusted_directory_chain(&link, uid).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn peer_provisioning_threads_one_endpoint_across_reprovisioning() -> Result<()> {
        let environment = Environment::new();
        let peer = NetworkPeer::builder().build(&environment);
        let first = peer
            .provision_disposable_runtime_provider_broker(
                b"first",
                Zeroizing::new(vec![1]),
                binding(1),
            )
            .await?;
        assert!(peer.has_disposable_runtime_provider_broker());
        let table = peer.base_config_table();
        assert_eq!(
            get_nested_value(&table, &["runtime_provider_broker", "endpoint_path"])
                .and_then(Value::as_str),
            first.to_str(),
        );
        assert_eq!(
            get_nested_value(
                &table,
                &["sumeragi", "global_beacon_partial_signer_provider_handle"],
            )
            .and_then(Value::as_str),
            Some("software://iroha/global-beacon/validator-a")
        );
        assert_eq!(
            get_nested_value(
                &table,
                &["sumeragi", "global_beacon_partial_signer_provider_revision"],
            )
            .and_then(Value::as_integer),
            Some(1)
        );
        let digest = "01".repeat(32);
        assert_eq!(
            get_nested_value(
                &table,
                &[
                    "sumeragi",
                    "global_beacon_partial_signer_provider_policy_digest_hex",
                ],
            )
            .and_then(Value::as_str),
            Some(digest.as_str())
        );
        let second = peer
            .provision_disposable_runtime_provider_broker(
                b"second",
                Zeroizing::new(vec![2]),
                binding(2),
            )
            .await?;
        assert_eq!(first, second);
        let (shutdown, _shutdown_rx) = oneshot::channel();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        *peer.run.lock().await = Some(PeerRun {
            tasks: JoinSet::new(),
            shutdown,
            fatal_tx,
            pid: None,
            broker_child: None,
        });
        assert!(
            peer.provision_disposable_runtime_provider_broker(
                b"third",
                Zeroizing::new(vec![3]),
                binding(3),
            )
            .await
            .is_err(),
            "a live peer must retain its exact active broker catalog"
        );
        assert_eq!(
            fs::read(
                peer.disposable_runtime_provider_broker
                    .lock()
                    .expect("broker config lock")
                    .as_ref()
                    .expect("provisioned")
                    .catalog_path
                    .as_path()
            )?,
            b"second",
        );
        peer.run.lock().await.take();
        Ok(())
    }
}
