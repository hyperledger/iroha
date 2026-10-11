//! Workspace selection and immutable client identity shared by desktop and CLI frontends.

use super::{
    Error, LocalnetRequest, MAX_METADATA, ManagedContext, ManagedPhase, ManagedStatus,
    ManagedStore, Result,
};
use iroha::{config::Config, data_model::account::address::ChainDiscriminantGuard};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Matching installed native programs used by either developer frontend.
///
/// Kagami owns the background worker entry point. Mochi resolves that same sibling program;
/// neither frontend searches PATH or starts a source build during a developer action.
#[derive(Debug, Clone)]
pub struct InstalledRuntime {
    kagami: PathBuf,
    daemon: PathBuf,
    profiles: PathBuf,
    programs: Arc<super::program::RuntimePrograms>,
}

impl InstalledRuntime {
    /// Resolve the installed runtime beside the calling Kagami or Mochi executable.
    ///
    /// # Errors
    /// The executable directory must contain both native runtime programs as direct files.
    pub fn discover() -> Result<Self> {
        let executable = std::env::current_exe()?;
        Self::from_directory(
            executable.parent().ok_or_else(|| {
                Error::Invalid("installed executable has no parent directory".into())
            })?,
        )
    }

    /// Resolve matching programs in a canonical package or an explicit loose development directory.
    ///
    /// macOS desktop applications use only `.app/Contents/MacOS` and `Contents/Resources`.
    /// The native CLI package and explicit loose developer binaries load profiles beside their
    /// two matching programs. A desktop UI is never a CLI runtime prerequisite.
    ///
    /// # Errors
    /// Missing, indirect, unsafe, nonregular or non-native programs are rejected. Live request
    /// clones retain the original program objects; a later path or content change is refused.
    pub fn from_directory(directory: &Path) -> Result<Self> {
        super::bundle::runtime_profiles_path(directory)?;
        let directory = directory.canonicalize()?;
        let profiles = super::bundle::runtime_profiles_path(&directory)?;
        let kagami = directory.join(format!("kagami{}", std::env::consts::EXE_SUFFIX));
        let daemon = directory.join(format!("iroha3d{}", std::env::consts::EXE_SUFFIX));
        let programs = Arc::new(
            super::program::RuntimePrograms::capture(&kagami, &daemon).map_err(|error| {
                match error {
                    Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Error::Invalid("the matching Kagami and iroha3d programs must be installed together; install the complete native developer bundle".into())
                    }
                    error => error,
                }
            })?,
        );
        Ok(Self {
            kagami,
            daemon,
            profiles,
            programs,
        })
    }

    /// Construct a fresh global startup request with the installed worker and daemon.
    ///
    /// Service-authority prerequisites are generated in the original genesis; services stay disabled.
    #[must_use]
    pub fn localnet_request(&self, name: &str, timeout: std::time::Duration) -> LocalnetRequest {
        let mut request = LocalnetRequest::new(self.kagami.clone(), self.daemon.clone());
        request.name = name.into();
        request.startup_timeout = timeout;
        request.installed_programs = Some(Arc::clone(&self.programs));
        request
    }

    /// Construct a private-root startup request with no global service-authority profile.
    #[must_use]
    pub fn private_root_request(
        &self,
        name: &str,
        timeout: std::time::Duration,
    ) -> LocalnetRequest {
        let mut request = LocalnetRequest::private_root(self.kagami.clone(), self.daemon.clone());
        request.name = name.into();
        request.startup_timeout = timeout;
        request.installed_programs = Some(Arc::clone(&self.programs));
        request
    }

    /// Load independently installed network authorities from the exact runtime resource location.
    ///
    /// The authenticated installation supplies this artifact. Neither a remote response nor a
    /// missing artifact can choose a trust key, checkpoint URL or default network.
    ///
    /// # Errors
    /// Missing, unsafe or malformed installation custody is refused without network I/O.
    pub fn network_profiles(&self) -> Result<crate::bootstrap::InstalledNetworkProfiles> {
        crate::bootstrap::InstalledNetworkProfiles::load(&self.profiles)
            .map_err(|error| Error::Invalid(format!("installed network profiles: {error}")))
    }
}

impl ManagedStore {
    /// Ensure a selected developer environment is ready, creating the default only when none exists.
    ///
    /// An explicit context starts without changing the workspace selection; an unknown one is
    /// an error. A retained selection restarts the exact same generation; no frontend substitutes
    /// a fresh network after failed startup or corrupt state.
    ///
    /// # Errors
    /// Returns context, custody, startup or readiness errors without replacing retained state.
    pub fn ensure_selected(
        &self,
        runtime: &InstalledRuntime,
        requested: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<ManagedStatus> {
        let (name, retained) = match self.context(requested) {
            Ok(context) => (context.name.clone(), Some(context)),
            Err(Error::NoSelection) if requested.is_none() => ("local".into(), None),
            Err(error) => return Err(error),
        };
        let mut request = runtime.localnet_request(&name, timeout);
        let status = if let Some(expected) = retained.as_ref() {
            request.service_profile = self.prepared(&name)?.service_profile;
            self.up_retained_with_selection(
                &request,
                expected,
                super::store::StartupSelection::for_requested_context(requested),
            )?
        } else {
            self.up(&request)?
        };
        if status.phase != ManagedPhase::Ready {
            return Err(Error::Invalid(status.failure.unwrap_or_else(|| {
                "selected developer environment is not ready".into()
            })));
        }
        Ok(status)
    }
}

/// Resolve a stable per-workspace store below an application-state directory.
///
/// Canonical workspace identity keeps equivalent paths on one context, without placing
/// configuration or credentials in a checkout. Neither directory is created by this function.
///
/// # Errors
/// The workspace must resolve to an existing directory and the state root must be absolute.
pub fn workspace_state_root(root: &Path, workspace: &Path) -> Result<PathBuf> {
    if !root.is_absolute() {
        return Err(Error::Invalid(
            "developer state root must be absolute".into(),
        ));
    }
    let workspace = workspace.canonicalize()?;
    if !workspace.is_dir() {
        return Err(Error::Invalid(
            "developer workspace must be a directory".into(),
        ));
    }
    let key = blake3::hash(workspace.as_os_str().as_encoded_bytes());
    Ok(root.join("workspaces").join(key.to_hex().as_str()))
}

/// Locate the OS application-state root used by both Kagami and Mochi.
///
/// # Errors
/// Fails when the current user's application directory cannot be determined or is relative.
pub fn default_state_root() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join("Iroha").join("developer"))
            .ok_or_else(|| {
                Error::Invalid(
                    "LOCALAPPDATA must identify an absolute application directory".into(),
                )
            })
    }
    #[cfg(not(windows))]
    {
        let home = std::env::home_dir().ok_or_else(|| {
            Error::Invalid("cannot locate the user's application-state directory".into())
        })?;
        #[cfg(target_os = "macos")]
        {
            Ok(home
                .join("Library")
                .join("Application Support")
                .join("Iroha")
                .join("developer"))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let base = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local/state"));
            if !base.is_absolute() {
                return Err(Error::Invalid("XDG_STATE_HOME must be absolute".into()));
            }
            Ok(base.join("iroha").join("developer"))
        }
    }
}

impl ManagedContext {
    /// Load owner-private signing configuration and verify its complete retained client identity.
    ///
    /// Frontends receive an immutable SDK value, never discover project configuration, and do
    /// not print parsing diagnostics that might contain a private key.
    ///
    /// # Errors
    /// Rejects unsafe file custody, invalid configuration, or a changed signer/network/endpoint.
    pub fn load_client_config(&self) -> Result<Config> {
        let bytes = iroha_fs::read_private(&self.client_config, MAX_METADATA)?;
        let (config, _) =
            Config::load_bytes_with_musubi_publication(&self.client_config, &bytes)
                .map_err(|_| Error::Invalid("managed client configuration is invalid".into()))?;
        self.validate_client_config(&config)?;
        Ok(config)
    }

    /// Apply the original context identity checks to canonically parsed bytes from either owner.
    pub(crate) fn validate_client_config(&self, config: &Config) -> Result<()> {
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        if config.chain.to_string() != self.chain_id
            || config.network_id.to_string() != self.network_id
            || config.account.to_string() != self.account_id
            || config.torii_api_url.as_str() != self.torii_url
        {
            return Err(Error::Invalid(
                "managed client identity or endpoint differs from its retained context".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_fs::{PrivateDirectory, PublishMode};

    #[test]
    fn installed_runtime_requires_the_complete_sibling_pair() {
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        assert!(InstalledRuntime::from_directory(temporary.path()).is_err());
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                temporary
                    .path()
                    .join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let runtime = InstalledRuntime::from_directory(temporary.path()).unwrap();
        let request = runtime.localnet_request("named", std::time::Duration::from_secs(7));
        assert_eq!(request.name, "named");
        assert_eq!(request.startup_timeout, std::time::Duration::from_secs(7));
        assert_eq!(request.launcher.parent(), request.daemon.parent());
        assert_eq!(
            request.service_profile,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities
        );
        let private = runtime.private_root_request("private", std::time::Duration::from_secs(9));
        assert_eq!(private.name, "private");
        assert_eq!(private.startup_timeout, std::time::Duration::from_secs(9));
        assert_eq!(private.launcher, request.launcher);
        assert_eq!(private.daemon, request.daemon);
        assert_eq!(
            private.service_profile,
            crate::localnet::LocalnetServiceProfile::Standard
        );
        let store = ManagedStore::open(&temporary.path().join("state")).unwrap();
        assert!(
            store
                .ensure_selected(&runtime, Some("missing"), std::time::Duration::from_secs(1))
                .is_err()
        );
        assert!(store.contexts().unwrap().is_empty());
    }

    #[test]
    fn installed_network_profiles_require_the_exact_bundle_without_defaults() {
        let _resources = super::super::native_test_guard();
        use crate::bootstrap::{InstalledNetworkProfiles, NETWORK_PROFILES_FILENAME};

        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("bundle")).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                directory
                    .path()
                    .join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let runtime = InstalledRuntime::from_directory(directory.path()).unwrap();
        assert!(runtime.network_profiles().is_err());
        directory
            .write_atomic(
                NETWORK_PROFILES_FILENAME,
                &InstalledNetworkProfiles::new(Vec::new())
                    .unwrap()
                    .encode_installation()
                    .unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        assert!(runtime.network_profiles().unwrap().select("taira").is_err());
        directory
            .write_atomic(
                NETWORK_PROFILES_FILENAME,
                b"untrusted malformed profile",
                PublishMode::Replace,
            )
            .unwrap();
        assert!(runtime.network_profiles().is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn relocated_and_renamed_app_uses_only_its_exact_resources() {
        let _resources = super::super::native_test_guard();
        use super::super::{NativeBundleLayout, macos_info_plist};
        use crate::bootstrap::{InstalledNetworkProfiles, NETWORK_PROFILES_FILENAME};
        let temporary = tempfile::tempdir().unwrap();
        let bundle = temporary.path().join("assembled");
        let layout = NativeBundleLayout::MacOs;
        let programs = layout.runtime_directory(&bundle);
        std::fs::create_dir_all(&programs).unwrap();
        std::fs::create_dir_all(layout.resources_directory(&bundle)).unwrap();
        std::fs::write(
            bundle.join("Mochi.app/Contents/Info.plist"),
            macos_info_plist("0.1.0").unwrap(),
        )
        .unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                programs.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let profiles = InstalledNetworkProfiles::new(Vec::new())
            .unwrap()
            .encode_installation()
            .unwrap();
        // An adjacent file must never replace a missing packaged resource.
        std::fs::write(programs.join(NETWORK_PROFILES_FILENAME), &profiles).unwrap();
        assert!(
            InstalledRuntime::from_directory(&programs)
                .unwrap()
                .network_profiles()
                .is_err()
        );
        std::fs::write(layout.profiles_path(&bundle), &profiles).unwrap();
        let moved_app = temporary.path().join("Renamed Mochi.app");
        std::fs::rename(bundle.join("Mochi.app"), &moved_app).unwrap();
        let runtime = InstalledRuntime::from_directory(&moved_app.join("Contents/MacOS")).unwrap();
        assert!(runtime.network_profiles().is_ok());
        assert!(
            runtime
                .localnet_request("local", std::time::Duration::from_secs(1))
                .launcher
                .starts_with(moved_app.canonicalize().unwrap())
        );
        // Malformed resource custody cannot be replaced by the valid adjacent artifact either.
        std::fs::write(
            moved_app
                .join("Contents/Resources")
                .join(NETWORK_PROFILES_FILENAME),
            b"invalid",
        )
        .unwrap();
        assert!(runtime.network_profiles().is_err());
        assert!(InstalledRuntime::from_directory(&moved_app.join("Contents")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn packaged_runtime_rejects_indirect_application_resources_and_metadata() {
        let _resources = super::super::native_test_guard();
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir().unwrap();
        let contents = temporary.path().join("Mochi.app/Contents");
        let programs = contents.join("MacOS");
        std::fs::create_dir_all(&programs).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(std::env::current_exe().unwrap(), programs.join(program)).unwrap();
        }
        std::fs::write(contents.join("Info.plist"), b"installed metadata").unwrap();
        let resources = temporary.path().join("resources");
        std::fs::create_dir(&resources).unwrap();
        symlink(&resources, contents.join("Resources")).unwrap();
        assert!(InstalledRuntime::from_directory(&programs).is_err());
        std::fs::remove_file(contents.join("Resources")).unwrap();
        std::fs::create_dir(contents.join("Resources")).unwrap();
        assert!(InstalledRuntime::from_directory(&programs).is_ok());
        std::fs::rename(contents.join("Info.plist"), temporary.path().join("plist")).unwrap();
        symlink(temporary.path().join("plist"), contents.join("Info.plist")).unwrap();
        assert!(InstalledRuntime::from_directory(&programs).is_err());
        std::fs::remove_file(contents.join("Info.plist")).unwrap();
        std::fs::rename(temporary.path().join("plist"), contents.join("Info.plist")).unwrap();
        let external_programs = temporary.path().join("loose");
        std::fs::rename(&programs, &external_programs).unwrap();
        symlink(&external_programs, &programs).unwrap();
        assert!(InstalledRuntime::from_directory(&external_programs).is_ok());
        assert!(InstalledRuntime::from_directory(&programs).is_err());
        std::fs::remove_file(&programs).unwrap();
        std::fs::rename(&external_programs, &programs).unwrap();
        let parent_alias = temporary.path().join("parent-alias");
        symlink(temporary.path(), &parent_alias).unwrap();
        assert!(
            InstalledRuntime::from_directory(&parent_alias.join("Mochi.app/Contents/MacOS"))
                .is_ok()
        );
    }

    #[test]
    fn workspace_selection_is_stable_separate_and_outside_the_project() {
        let temporary = tempfile::tempdir().unwrap();
        let a = temporary.path().join("a");
        let b = temporary.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let root = temporary.path().join("state");
        let selected = workspace_state_root(&root, &a).unwrap();
        assert_eq!(selected, workspace_state_root(&root, &a.join(".")).unwrap());
        assert_ne!(selected, workspace_state_root(&root, &b).unwrap());
        assert!(selected.starts_with(&root));
        assert!(!root.exists());
        assert!(workspace_state_root(Path::new("relative"), &a).is_err());
        assert!(workspace_state_root(&root, &root).is_err());
        assert!(default_state_root().unwrap().is_absolute());
    }

    #[test]
    fn selected_authority_profile_reaches_native_spawn_without_repreparing_identity() {
        let _resources = super::super::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
        let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
        let directory = networks.create_child("native-authorities").unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                directory
                    .path()
                    .join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let runtime = InstalledRuntime::from_directory(directory.path()).unwrap();
        let mut request =
            runtime.localnet_request("native-authorities", std::time::Duration::from_secs(60));
        request.service_profile = crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities;
        let retained = {
            let _operation =
                super::super::store::acquire(&directory, "operation.lock", &request.name).unwrap();
            let ports = super::super::LocalnetPorts::reserve().unwrap();
            super::super::generation::prepare(
                &directory,
                &request,
                super::super::RootKind::Global,
                super::super::store::pin_binary(&runtime.kagami).unwrap(),
                super::super::store::pin_binary(&runtime.daemon).unwrap(),
                &ports,
            )
            .unwrap()
        };
        store.select(&request.name).unwrap();
        let error = store
            .ensure_selected(&runtime, None, std::time::Duration::from_secs(60))
            .unwrap_err();
        assert!(
            matches!(error, Error::Timeout(timeout) if timeout == std::time::Duration::from_secs(60)),
            "expected original-budget worker-start failure after exact profile selection: {error}"
        );
        assert_eq!(store.prepared(&request.name).unwrap(), retained.prepared);
        assert!(!directory.path().join(".preparing").exists());
    }

    #[test]
    fn retained_client_identity_rejects_every_substitution_without_leaking_secrets() {
        let temporary = tempfile::tempdir().unwrap();
        let private = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        let source = br#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "http://127.0.0.1:9/"
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
"#;
        private
            .write_atomic("client.toml", source, PublishMode::CreateNew)
            .unwrap();
        let path = private.path().join("client.toml");
        let (config, _) = Config::load_bytes_with_musubi_publication(&path, source).unwrap();
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let context = ManagedContext {
            name: "local".into(),
            chain_id: config.chain.to_string(),
            network_id: config.network_id.to_string(),
            account_id: config.account.to_string(),
            dataspace_id: 0,
            dataspace_alias: "universal".into(),
            torii_url: config.torii_api_url.to_string(),
            client_config: path,
        };
        context.load_client_config().unwrap();
        for field in ["chain", "network", "account", "endpoint"] {
            let mut changed = context.clone();
            match field {
                "chain" => changed.chain_id.push('x'),
                "network" => changed.network_id.push('x'),
                "account" => changed.account_id.push('x'),
                _ => changed.torii_url.push('x'),
            }
            assert!(changed.load_client_config().is_err(), "{field}");
        }
        private
            .write_atomic(
                "client.toml",
                b"private_key = 'secret-invalid'",
                PublishMode::Replace,
            )
            .unwrap();
        let error = context.load_client_config().unwrap_err().to_string();
        assert!(!error.contains("secret-invalid"));
    }
}
