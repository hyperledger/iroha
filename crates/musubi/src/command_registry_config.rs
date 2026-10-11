//! Canonical wallet/native configuration selection for authenticated registry consumers.

use super::*;
use std::sync::Arc;

#[derive(Args, Clone, Debug, Default)]
pub(super) struct NetworkArgs {
    /// Explicit native client configuration instead of the integrated wallet.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["wallet", "wallet_dir"])]
    pub(super) config: Option<PathBuf>,
    /// Integrated wallet for registry authentication; omission selects the default wallet.
    #[arg(long, value_name = "NAME")]
    pub(super) wallet: Option<String>,
    /// Private wallet store outside projects.
    #[arg(long, value_name = "DIRECTORY")]
    pub(super) wallet_dir: Option<PathBuf>,
}

impl NetworkArgs {
    pub(super) fn config_path(&self) -> Result<PathBuf, Diagnostic> {
        if let Some(config) = &self.config {
            return crate::registry::selected_client_config_path_v1(Some(config))
                .map_err(|error| registry_diagnostic(error, ErrorCode::Usage));
        }
        if self.wallet.is_some() || self.wallet_dir.is_some() {
            return wallet::open_store(None, self.wallet_dir.as_deref())?
                .config_path(self.wallet.as_deref().unwrap_or("default"))
                .map_err(wallet::wallet_error);
        }
        crate::registry::selected_client_config_path_v1(None)
            .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))
    }

    pub(super) fn workspace_image(
        &self,
        root: Option<&Path>,
    ) -> Result<Arc<RegistryPublicConfigImageV1>, Diagnostic> {
        let explicit = self.config.is_some() || self.wallet.is_some() || self.wallet_dir.is_some();
        let path = explicit.then(|| self.config_path()).transpose()?;
        if let Some(root) = root {
            let selected = network::select_network(
                root,
                None,
                path.as_deref(),
                None,
                network::NetworkPurpose::Deployment,
            )?;
            if let Some(image) = selected.config_image {
                return Ok(image);
            }
        }
        let path = path.map_or_else(|| self.config_path(), Ok)?;
        RegistryPublicConfigImageV1::load(Some(&path))
            .map(Arc::new)
            .map_err(|error| registry_diagnostic(error, ErrorCode::Usage))
    }

    pub(super) fn publication_image(
        &self,
        explicit_manifest: Option<&Path>,
    ) -> Result<Arc<RegistryPublicConfigImageV1>, Diagnostic> {
        let manifest = if let Some(manifest) = explicit_manifest {
            Some(project_manifest_path(Some(manifest))?)
        } else {
            let current = std::env::current_dir()
                .map_err(|error| io_diagnostic("read current directory", Path::new("."), &error))?;
            current
                .ancestors()
                .find(|path| path.join(MANIFEST_FILE_NAME).exists())
                .map(|path| path.join(MANIFEST_FILE_NAME))
        };
        let workspace = manifest
            .as_deref()
            .map(load_workspace)
            .transpose()
            .map_err(workspace_diagnostic)?;
        self.workspace_image(workspace.as_ref().map(Workspace::root))
    }
}

#[cfg(all(test, unix))]
#[path = "command_registry_config_tests.rs"]
mod tests;
