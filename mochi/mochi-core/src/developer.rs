//! Desktop actions over the same managed environments and contract service as Kagami.
//!
//! This adapter owns no process lifecycle, genesis renderer, signing journal or compiler.
//! Run blocking actions on the desktop task executor and report their typed progress on the UI.

use color_eyre::eyre::{Result, ensure};
pub use iroha_contract_deploy::{DeploymentPreflight, DeploymentProgress};
use iroha_data_model::{smart_contract::ContractAlias, transaction::FeePaymentIntent};
use iroha_deploy::managed::{
    InstalledRuntime, ManagedStore, default_state_root, workspace_state_root,
};
pub use iroha_deploy::managed::{
    ManagedAttachmentFailure, ManagedAttachmentPhase, ManagedAttachmentStatus,
    ManagedConfirmedAnchor, ManagedContext, ManagedDataspaceStatus, ManagedDeploymentReport,
    ManagedPhase, ManagedStatus, PreparedLocalnet,
};
pub use musubi::deployment_runtime::ContractInput;
use musubi::deployment_runtime::{AliasSelection, DeploymentRuntime};
pub use musubi::generated_publication::{GeneratedPublishAction, GeneratedPublishOutcome};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

/// An immutable workspace choice for desktop background actions.
///
/// Selection is persisted by `iroha_deploy`, so Kagami launched from the same workspace sees
/// the same identity, endpoints and recovery journals. Opening a workspace starts no validators.
#[derive(Clone)]
pub struct DeveloperWorkspace {
    root: PathBuf,
    project: PathBuf,
    runtime: InstalledRuntime,
}

/// One desktop action's exact target and result, including failures after target acquisition.
///
/// The target remains available for read-only refresh without resolving a mutable context name.
/// An error in `outcome` never authorizes replacement, repeat dispatch or another generation.
pub struct ManagedActionOutcome<T> {
    /// Immutable network captured before the action entered compilation or publication.
    pub network: ManagedNetwork,
    /// Original operation result; completed receipts and failures retain their exact target.
    pub outcome: Result<T>,
}

fn run_on_network<T>(
    network: ManagedNetwork,
    action: impl FnOnce(&ManagedNetwork) -> Result<T>,
) -> ManagedActionOutcome<T> {
    let outcome = action(&network);
    ManagedActionOutcome { network, outcome }
}

impl DeveloperWorkspace {
    /// Select a workspace using the installed bundle and OS application-state location.
    ///
    /// # Errors
    /// Missing workspace, invalid state location, or incomplete installed runtime.
    pub fn open(workspace: &Path) -> Result<Self> {
        Self::with_runtime(
            &default_state_root()?,
            workspace,
            InstalledRuntime::discover()?,
        )
    }

    /// Select a workspace below an explicit application-state root and installed runtime.
    ///
    /// # Errors
    /// Invalid workspace identity or unsafe private store custody.
    pub fn with_runtime(
        state_root: &Path,
        workspace: &Path,
        runtime: InstalledRuntime,
    ) -> Result<Self> {
        let project = workspace.canonicalize()?;
        let root = workspace_state_root(state_root, &project)?;
        let store = ManagedStore::open(&root)?;
        Ok(Self {
            root: store.root().to_path_buf(),
            project,
            runtime,
        })
    }

    /// Resolve desktop input against the immutable opened project, not the process directory.
    #[must_use]
    pub fn resolve_path(&self, path: &Path) -> PathBuf {
        self.project.join(path)
    }

    /// Public storage location; no credentials are copied into the project.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.root
    }

    /// Inspect the contexts shared with Kagami.
    ///
    /// # Errors
    /// A retained generation is invalid or its private storage is inaccessible.
    pub fn contexts(&self) -> Result<Vec<ManagedContext>> {
        Ok(ManagedStore::open(&self.root)?.contexts()?)
    }

    /// Names authenticated by the installed network profile artifact, without contacting a node.
    /// # Errors
    /// Missing, unsafe or malformed installation authority. Local contexts remain usable.
    pub fn network_profiles(&self) -> Result<Vec<String>> {
        Ok(self
            .runtime
            .network_profiles()?
            .names()
            .map(str::to_owned)
            .collect())
    }

    /// Create or recover one owner-private dataspace using the installed parent profile.
    ///
    /// The shared native worker owns custody, funding, paid namespace and `admin@alias` leases,
    /// and outbound relay work.
    /// A timeout retains exact work for retry; the complete foreground budget is sixty seconds.
    /// # Errors
    /// Invalid identity/profile, unsafe custody, failed private startup or unconfirmed attachment.
    pub fn start_dataspace(
        &self,
        name: &str,
        network: &str,
        alias: &str,
    ) -> Result<ManagedDataspaceStatus> {
        Ok(ManagedStore::open(&self.root)?.up_dataspace(
            &self.runtime,
            &iroha_deploy::managed::DataspaceRequest {
                name: name.to_owned(),
                network: network.to_owned(),
                alias: alias.to_owned(),
                account_alias: "admin".to_owned(),
                timeout: Duration::from_secs(60),
            },
        )?)
    }

    /// Observe shared parent attachment progress without treating retained receipts as liveness.
    /// # Errors
    /// Missing generation, malformed custody, replaced identity or unauthenticated worker.
    pub fn dataspace_status(&self, name: &str) -> Result<Option<ManagedDataspaceStatus>> {
        Ok(ManagedStore::open(&self.root)?.dataspace_status(name)?)
    }

    /// Return the selected context name, distinguishing an empty selection from invalid custody.
    ///
    /// # Errors
    /// Existing selection or retained generation metadata is invalid.
    pub fn selected_name(&self) -> Result<Option<String>> {
        match ManagedStore::open(&self.root)?.context(None) {
            Ok(context) => Ok(Some(context.name)),
            Err(iroha_deploy::managed::Error::NoSelection) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Load the selected environment for immutable, network-bound observation and composition.
    ///
    /// # Errors
    /// Missing selection, invalid generated credentials or replaced generation.
    pub fn network(&self, name: Option<&str>) -> Result<ManagedNetwork> {
        let store = ManagedStore::open(&self.root)?;
        let context = store.context(name)?;
        let prepared = store.prepared(&context.name)?;
        self.network_from_prepared(&context, prepared)
    }

    fn network_from_prepared(
        &self,
        selected: &ManagedContext,
        prepared: PreparedLocalnet,
    ) -> Result<ManagedNetwork> {
        ensure!(
            prepared.context == *selected,
            "managed generation changed before loading network credentials"
        );
        let config = prepared.context.load_client_config()?;
        let operator = prepared.load_operator_key_pair()?;
        let network = ManagedNetwork {
            root: self.root.clone(),
            prepared,
            config,
            operator,
        };
        network.validate()?;
        Ok(network)
    }

    /// Select an existing environment without starting it.
    ///
    /// # Errors
    /// Unknown or invalid retained context.
    pub fn select(&self, name: &str) -> Result<ManagedContext> {
        Ok(ManagedStore::open(&self.root)?.select(name)?)
    }

    /// Create a new named global localnet without resuming any existing context.
    ///
    /// The canonical store owns the name check under its operation lock. A stale desktop
    /// context list cannot adopt a global or private generation created by another frontend.
    ///
    /// # Errors
    /// Existing or concurrently owned name, generation, custody or startup failure.
    pub fn create_localnet(&self, name: &str) -> Result<ManagedStatus> {
        Ok(ManagedStore::open(&self.root)?
            .create_localnet(&self.runtime.localnet_request(name, Duration::from_secs(30)))?)
    }

    /// Restart exactly the displayed generation without changing workspace selection.
    ///
    /// # Errors
    /// A foreign, missing/replaced generation, custody, startup or readiness failure is refused.
    pub fn start(&self, network: &ManagedNetwork) -> Result<ManagedStatus> {
        self.validate_action_network(network)?;
        Ok(ManagedStore::open(&self.root)?.ensure_captured(
            &self.runtime,
            network.prepared(),
            Duration::from_secs(30),
        )?)
    }

    /// Observe the native worker without inferring liveness from stored numeric PIDs.
    ///
    /// # Errors
    /// Unknown generation or an owner which cannot be authenticated.
    pub fn status(&self, name: &str) -> Result<ManagedStatus> {
        Ok(ManagedStore::open(&self.root)?.status(name)?)
    }

    /// Stop the owned validators while retaining keys, ledger, selection and deployment journals.
    ///
    /// # Errors
    /// Unknown generation, unsafe custody or uncertain process ownership.
    pub fn stop(&self, network: &ManagedNetwork) -> Result<ManagedStatus> {
        self.validate_action_network(network)?;
        Ok(ManagedStore::open(&self.root)?.down_captured(network.prepared())?)
    }

    /// Reset the exact captured stopped localnet after the desktop obtains reset intent.
    ///
    /// # Errors
    /// Refuses a running or orphan-owned network and unsafe generation storage.
    pub fn reset(&self, network: &ManagedNetwork) -> Result<()> {
        self.validate_action_network(network)?;
        Ok(ManagedStore::open(&self.root)?.reset_captured(network.prepared())?)
    }

    /// Read a bounded private log tail from the captured generation, validating before and after.
    ///
    /// # Errors
    /// Unknown peer, excessive byte limit, or unsafe log custody.
    pub fn logs(
        &self,
        network: &ManagedNetwork,
        peer: Option<usize>,
        maximum: usize,
    ) -> Result<String> {
        self.validate_action_network(network)?;
        let logs =
            ManagedStore::open(&self.root)?.logs(&network.prepared().context.name, peer, maximum);
        network.validate()?;
        Ok(logs?)
    }

    /// Publish an explicit package action through the same generated context and engine as Kagami.
    ///
    /// Run this blocking action on the desktop executor. Begin without a captured network creates
    /// the default only in an unselected workspace; Resume/Recover require a captured network.
    /// Existing selections retain their exact generation and original operation. Original
    /// generation-bound publication/cache roots and namespace custody are shared with the CLI.
    /// The returned outcome uses canonical redacting output; it is not a readiness assertion.
    /// # Errors
    /// Invalid input, missing/replaced target or startup failure is returned directly. Later
    /// profile/registry and publication failures remain in the target-bound outcome.
    pub fn publish_package(
        &self,
        manifest: &Path,
        context: Option<&ManagedNetwork>,
        action: GeneratedPublishAction,
    ) -> Result<ManagedActionOutcome<GeneratedPublishOutcome>> {
        let manifest = self.resolve_path(manifest);
        let action =
            musubi::generated_publication::prepare_generated_publish_action(&manifest, action)?;
        let network = self.action_network(
            context,
            matches!(&action, GeneratedPublishAction::Begin { .. }),
        )?;
        Ok(run_on_network(network, |network| {
            network.validate()?;
            let store = ManagedStore::open(&self.root)?;
            let prepared = network.prepared();
            let selected = &prepared.context;
            let deadline = Instant::now() + Duration::from_secs(60);
            let original = prepared.publication_client_config()?.ok_or_else(|| {
                color_eyre::eyre::eyre!("selected generation has no generated publication intent")
            })?;
            let context =
                musubi::publication_runtime::GeneratedPublicationContextV1::from_original_image(
                    original.client_config_path(),
                    original.client_config_image(),
                    original.publication_transport()?,
                    musubi::publication_runtime::GeneratedPublicationNamespaceIntentV1 {
                        publisher: original.publisher().clone(),
                        binding: original.namespace_binding().clone(),
                        policy: original.registry_policy().clone(),
                        fee_payment: original.namespace_fee_payment(),
                        journal_root: original.namespace_journal_root().to_path_buf(),
                    },
                )?;
            let (registry, archive_transport) = store
                .build_registry(&self.runtime, prepared, deadline)?
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "selected generation has no authenticated build registry"
                    )
                })?;
            ensure!(
                registry.account == *original.publisher()
                    && registry.network_id == original.service_plan().network_id()
                    && registry.chain.as_str() == original.service_plan().chain_id()
                    && registry.torii_api_url.as_str() == prepared.context.torii_url
                    && store.prepared(&selected.name)? == *prepared,
                "generated publication registry or generation changed"
            );
            Ok(musubi::generated_publication::publish_generated(
                &context,
                &musubi::generated_publication::GeneratedPublishRequest {
                    manifest_path: manifest,
                    state_root: original.publication_state_root(),
                    cache_root: original.publication_cache_root(),
                    archive_transport,
                    action,
                },
            ))
        }))
    }

    /// Compile and deploy one input against a captured network, or create the unselected default.
    ///
    /// `review` sees exact signed-plan fee quotes before dispatch; `progress` reports native
    /// stage evidence. Exact repeats recover the same journal and submitted transaction hashes.
    ///
    /// # Errors
    /// Target admission/startup failure is returned directly. Preparation, authorization, budget,
    /// original-hash recovery and readback failures remain in the target-bound outcome.
    pub fn deploy(
        &self,
        input: &ContractInput,
        context: Option<&ManagedNetwork>,
        alias: Option<ContractAlias>,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<ManagedActionOutcome<ManagedDeploymentReport>> {
        let network = self.action_network(context, true)?;
        Ok(run_on_network(network, |network| {
            network.validate()?;
            let store = ManagedStore::open(&self.root)?;
            let prepared = network.prepared();
            let selected = &prepared.context;
            let target = store.capture_deployment(selected)?;
            let runtime = self.deployment_runtime(network);
            let alias = alias.map_or_else(
                || AliasSelection::Scope {
                    domain: None,
                    dataspace: selected.dataspace_alias.clone(),
                },
                AliasSelection::Exact,
            );
            let run = runtime.deploy(
                input,
                &alias,
                FeePaymentIntent::authority(Vec::new(), None),
                &mut |preflight| {
                    ensure!(
                        preflight.dataspace_id.as_u64() == selected.dataspace_id,
                        "deployment resolved outside the selected dataspace"
                    );
                    review(preflight)
                },
                progress,
            )?;
            let mut report = target.finish(&store, run.receipt, run.journal)?;
            report.lifecycle = run.lifecycle;
            Ok(report)
        }))
    }

    /// Recover an exact retained journal using its selected environment without rebuilding.
    ///
    /// # Errors
    /// Missing/replaced target is returned directly. Mismatched original authority, pending
    /// finality or failed readback remains in the target-bound outcome.
    pub fn resume(
        &self,
        journal: &Path,
        context: Option<&ManagedNetwork>,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<ManagedActionOutcome<ManagedDeploymentReport>> {
        let network = self.action_network(context, false)?;
        Ok(run_on_network(network, |network| {
            network.validate()?;
            let store = ManagedStore::open(&self.root)?;
            let prepared = network.prepared();
            let selected = &prepared.context;
            let target = store.capture_deployment(selected)?;
            let runtime = self.deployment_runtime(network);
            let run = runtime.resume(
                journal,
                &mut |preflight| {
                    ensure!(
                        preflight.dataspace_id.as_u64() == selected.dataspace_id,
                        "recovery belongs to another dataspace"
                    );
                    review(preflight)
                },
                progress,
            )?;
            let mut report = target.finish(&store, run.receipt, run.journal)?;
            report.lifecycle = run.lifecycle;
            Ok(report)
        }))
    }

    fn validate_action_network(&self, network: &ManagedNetwork) -> Result<()> {
        ensure!(
            network.root == self.root,
            "selected network belongs to another workspace"
        );
        network.validate()
    }

    fn action_network(
        &self,
        captured: Option<&ManagedNetwork>,
        create_default: bool,
    ) -> Result<ManagedNetwork> {
        if let Some(network) = captured {
            // The startup owner repeats complete preparation admission under its operation lock.
            self.start(network)?;
            network.validate()?;
            return Ok(network.clone());
        }
        if !create_default {
            return Err(iroha_deploy::managed::Error::NoSelection.into());
        }
        let store = ManagedStore::open(&self.root)?;
        match store.context(None) {
            Err(iroha_deploy::managed::Error::NoSelection) => {}
            Ok(_) => {
                return Err(color_eyre::eyre::eyre!(
                    "workspace selection changed; select the network explicitly"
                ));
            }
            Err(error) => return Err(error.into()),
        }
        // Empty-desktop startup creates only its own default. A retained/concurrently created
        // `local` is refused; an unrelated concurrent selection is never adopted as authority.
        // Successfully creating our fresh default selects it through the ordinary explicit
        // create owner, even if another frontend selected a different name while it started.
        let status = store.create_localnet(
            &self
                .runtime
                .localnet_request("local", Duration::from_secs(30)),
        )?;
        ensure!(
            status.phase == ManagedPhase::Ready,
            "{}",
            status
                .failure
                .unwrap_or_else(|| "default developer environment is not ready".into())
        );
        let prepared = store.prepared(&status.context.name)?;
        self.network_from_prepared(&status.context, prepared)
    }

    fn deployment_runtime(&self, network: &ManagedNetwork) -> DeploymentRuntime {
        let registry_root = self.root.clone();
        let captured = network.clone();
        let installed = self.runtime.clone();
        DeploymentRuntime::new(
            network.config.clone(),
            self.root
                .join("deployments")
                .join(&network.prepared.context.name),
            network.prepared.build_cache_root(),
        )
        .with_build_registry_resolver(Arc::new(move || {
            // External dependencies require the original registry binding before cache
            // selection. Local-only graphs never call this; complete cache hits skip
            // registry/provider reads after this binding and custody are resolved.
            let deadline = Instant::now() + Duration::from_secs(60);
            let store = ManagedStore::open(&registry_root)?;
            Ok(store.build_registry(&installed, &captured.prepared, deadline)?)
        }))
    }
}

/// An immutable observation and signing authority for one generated network.
///
/// This value owns no child processes. Releasing it only releases local client credentials;
/// Kagami and the desktop continue to share the independently owned native worker.
#[derive(Clone)]
pub struct ManagedNetwork {
    root: PathBuf,
    prepared: PreparedLocalnet,
    config: iroha::config::Config,
    operator: iroha_crypto::KeyPair,
}

impl ManagedNetwork {
    /// Public metadata for this exact four-validator generation.
    #[must_use]
    pub fn prepared(&self) -> &PreparedLocalnet {
        &self.prepared
    }

    /// Refuse a removed or replaced generation without adopting its authority or endpoint.
    ///
    /// # Errors
    /// Invalid custody or a different generation is currently stored under this name.
    pub fn validate(&self) -> Result<()> {
        let current = ManagedStore::open(&self.root)?.prepared(&self.prepared.context.name)?;
        ensure!(
            current == self.prepared,
            "selected network was replaced; select it again"
        );
        Ok(())
    }

    /// Chain-specific address formatting for synchronous desktop draft input and output.
    #[must_use]
    pub fn address_discriminant(&self) -> u16 {
        self.config.account_chain_discriminant
    }

    /// Generated account authority for transaction previews and authenticated state queries.
    #[must_use]
    pub fn signer(&self) -> crate::SigningAuthority {
        crate::SigningAuthority::new(
            self.prepared.context.name.clone(),
            self.config.account.clone(),
            self.config.key_pair.clone(),
        )
    }

    /// Build a peer-bound Torii observer with the generated operator authority.
    ///
    /// # Errors
    /// Invalid index, stale generation or invalid immutable endpoint.
    pub fn observer(&self, peer: usize) -> Result<crate::ToriiClient> {
        self.validate()?;
        let endpoint = &self
            .prepared
            .peers
            .get(peer)
            .ok_or_else(|| color_eyre::eyre::eyre!("unknown validator index"))?
            .torii_url;
        Ok(crate::ToriiClient::builder(endpoint)?
            .with_api_token(self.config.api_token.clone())
            .with_network_id(self.config.network_id)
            .with_operator_signing_context(crate::OperatorSigningContext::new(
                self.config.network_id,
                self.operator.clone(),
            ))
            .build()?)
    }

    /// Read canonical block/event streams as the exact generated account.
    ///
    /// # Errors
    /// Invalid index, replaced generation or an invalid SDK authority.
    pub fn ledger_reader(&self, peer: usize) -> Result<iroha::client::AccountClient> {
        self.validate()?;
        let endpoint = &self
            .prepared
            .peers
            .get(peer)
            .ok_or_else(|| color_eyre::eyre::eyre!("unknown validator index"))?
            .torii_url;
        let mut config = self.config.clone();
        config.torii_api_url = endpoint.parse()?;
        Ok(iroha::client::Client::builder(config)
            .build()?
            .account_client()?)
    }

    /// Compose one exact transaction using this generation's authority and lineage.
    ///
    /// # Errors
    /// Stale generation or drafts rejected by the canonical composer.
    pub fn preview(&self, drafts: &[crate::InstructionDraft]) -> Result<crate::TransactionPreview> {
        self.validate()?;
        let _address_profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            self.address_discriminant(),
        );
        Ok(crate::compose_preview_with_options(
            self.config.network_id,
            drafts,
            &self.signer(),
            &crate::TransactionComposeOptions::default().with_ttl(Duration::from_secs(300)),
        )?)
    }

    /// Submit a reviewed transaction once, then observe its original hash until the deadline.
    ///
    /// # Errors
    /// Wrong generation/authority, rejection or uncertain finality. An error never rebuilds it.
    pub async fn submit(
        &self,
        peer: usize,
        preview: &crate::TransactionPreview,
    ) -> Result<crate::SmokeCommitSnapshot> {
        ensure!(
            preview.signed_transaction().network_id() == Some(&self.config.network_id),
            "transaction belongs to another network"
        );
        ensure!(
            preview.signed_transaction().authority() == &self.config.account,
            "transaction belongs to another authority"
        );
        let client = self.observer(peer)?;
        let reader = self.ledger_reader(peer)?;
        Ok(client
            .submit_and_wait_for_commit(
                &reader,
                preview.signed_transaction(),
                crate::SmokeCommitOptions::new(Duration::from_secs(30)),
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_publication_refuses_invalid_input_and_missing_recovery_selection_without_workers() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let bin = temporary.path().join("bin");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&bin).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                bin.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let desktop = DeveloperWorkspace::with_runtime(
            &temporary.path().join("state"),
            &project,
            InstalledRuntime::from_directory(&bin).unwrap(),
        )
        .unwrap();
        let manifest = project.join("Musubi.toml");
        std::fs::write(&manifest, "invalid manifest").unwrap();
        assert!(
            desktop
                .publish_package(
                    Path::new("Musubi.toml"),
                    None,
                    GeneratedPublishAction::Begin {
                        package: None,
                        detach: false
                    }
                )
                .is_err()
        );
        assert!(desktop.contexts().unwrap().is_empty());
        std::fs::write(&manifest, "manifest-version = 1\n[package]\nnamespace = \"dev.universal\"\nname = \"demo\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n").unwrap();
        let operation_id = "56".repeat(32).parse().unwrap();
        for action in [
            GeneratedPublishAction::Resume { operation_id },
            GeneratedPublishAction::Recover { operation_id },
        ] {
            let error = desktop
                .publish_package(Path::new("Musubi.toml"), None, action)
                .err()
                .unwrap();
            assert!(matches!(
                error.downcast_ref::<iroha_deploy::managed::Error>(),
                Some(iroha_deploy::managed::Error::NoSelection)
            ));
            assert!(desktop.contexts().unwrap().is_empty());
            assert_eq!(desktop.selected_name().unwrap(), None);
        }
        for missing in [false, true] {
            if missing {
                std::fs::remove_file(&manifest).unwrap();
            } else {
                std::fs::write(&manifest, "invalid changed source").unwrap();
            }
            let error = desktop
                .publish_package(
                    Path::new("Musubi.toml"),
                    None,
                    GeneratedPublishAction::Resume { operation_id },
                )
                .err()
                .unwrap();
            assert!(
                matches!(
                    error.downcast_ref::<iroha_deploy::managed::Error>(),
                    Some(iroha_deploy::managed::Error::NoSelection)
                ),
                "resume must reach original context without reopening source: {error}"
            );
            assert!(desktop.contexts().unwrap().is_empty());
        }
        assert!(!desktop.state_root().join("deployments").exists());
    }

    fn assert_create_refuses_retained_context(desktop: &DeveloperWorkspace, name: &str) {
        let store = ManagedStore::open(desktop.state_root()).unwrap();
        let original = store.prepared(name).unwrap();
        let selection = desktop.selected_name().unwrap();
        let config = std::fs::read(&original.context.client_config).unwrap();
        let error = desktop.create_localnet(name).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<iroha_deploy::managed::Error>(),
            Some(iroha_deploy::managed::Error::Invalid(message)) if message.contains("already exists")
        ));
        assert_eq!(store.prepared(name).unwrap(), original);
        assert_eq!(desktop.selected_name().unwrap(), selection);
        assert_eq!(
            std::fs::read(&original.context.client_config).unwrap(),
            config
        );
    }

    #[test]
    fn desktop_restart_keeps_the_cli_prepared_private_root_and_owner() {
        use iroha_data_model::sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1};
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let bin = temporary.path().join("bin");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&bin).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                bin.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let desktop = DeveloperWorkspace::with_runtime(
            &temporary.path().join("state"),
            &project,
            InstalledRuntime::from_directory(&bin).unwrap(),
        )
        .unwrap();
        let alias = "desktop-private";
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias).unwrap();
        let spec = iroha_deploy::localnet::PrivateRootSpec {
            parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"desktop parent",
                )),
            ),
            dataspace_id: iroha_model_base::topology::DataSpaceId::from_hash(&selector.name_hash()),
            dataspace_alias: alias.into(),
        };
        let store = ManagedStore::open(desktop.state_root()).unwrap();
        let request = desktop
            .runtime
            .private_root_request("private", Duration::from_secs(120));
        assert!(
            matches!(
                store.up_private_root(&request, &spec),
                Err(iroha_deploy::managed::Error::Timeout(timeout)) if timeout == request.startup_timeout
            ),
            "genuine CLI preparation reaches the original-budget worker-start failure"
        );
        let prepared = store.prepared("private").unwrap();
        let owner = prepared.context.load_client_config().unwrap();
        assert!(owner.api_token.is_some());
        assert_create_refuses_retained_context(&desktop, "private");
        let captured = desktop.network(Some("private")).unwrap();
        let failure = desktop.start(&captured).unwrap_err();
        assert!(
            matches!(
                failure.downcast_ref::<iroha_deploy::managed::Error>(),
                Some(iroha_deploy::managed::Error::Timeout(timeout)) if *timeout == Duration::from_secs(30)
            ),
            "desktop restart must reach the original-budget worker-start failure with the same private root: {failure}"
        );
        assert_eq!(store.prepared("private").unwrap(), prepared);
        let restarted = store
            .prepared("private")
            .unwrap()
            .context
            .load_client_config()
            .unwrap();
        assert_eq!(restarted.account, owner.account);
        assert!(
            restarted
                .api_token
                .as_ref()
                .map(|token| token.expose_secret())
                == owner.api_token.as_ref().map(|token| token.expose_secret())
        );
        let observed = desktop.network(Some("private")).unwrap();
        assert_eq!(observed.prepared(), &prepared);
        assert_eq!(
            observed.ledger_reader(0).unwrap().network_id(),
            &owner.network_id
        );
    }

    #[test]
    fn desktop_and_cli_share_store_identity_without_writing_the_project_or_starting_nodes() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("project");
        let installation = temporary.path().join("bin");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&installation).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                installation.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let runtime = InstalledRuntime::from_directory(&installation).unwrap();
        let base = temporary.path().join("state");
        let desktop = DeveloperWorkspace::with_runtime(&base, &workspace, runtime).unwrap();
        let expected = workspace_state_root(&base, &workspace).unwrap();
        assert_eq!(desktop.state_root(), expected.canonicalize().unwrap());
        assert_eq!(
            desktop.resolve_path(Path::new("contracts/app.ko")),
            workspace.canonicalize().unwrap().join("contracts/app.ko")
        );
        assert_eq!(desktop.resolve_path(&installation), installation);
        assert!(desktop.contexts().unwrap().is_empty());
        assert!(desktop.network_profiles().is_err());
        assert!(
            desktop
                .start_dataspace("private", "missing", "private")
                .is_err()
        );
        assert!(desktop.dataspace_status("missing").is_err());
        let profiles = iroha_deploy::bootstrap::InstalledNetworkProfiles::new(vec![
            iroha_deploy::bootstrap::InstalledNetworkProfile::new(
                "fixture".into(),
                iroha_crypto::KeyPair::from_seed(vec![231; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
                1,
                "https://checkpoint.example/release.nrt",
            )
            .unwrap(),
        ])
        .unwrap();
        std::fs::write(
            installation.join(iroha_deploy::bootstrap::NETWORK_PROFILES_FILENAME),
            profiles.encode_installation().unwrap(),
        )
        .unwrap();
        assert_eq!(desktop.network_profiles().unwrap(), vec!["fixture"]);
        assert_eq!(desktop.selected_name().unwrap(), None);
        assert!(
            ManagedStore::open(&expected)
                .unwrap()
                .contexts()
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read_dir(&workspace).unwrap().count(), 0);
        assert!(desktop.select("missing").is_err());
        assert!(desktop.status("missing").is_err());
        // Lifecycle actions require a captured network; missing/invalid names fail capture.
        assert!(desktop.network(Some("missing")).is_err());
        assert!(desktop.network(Some("../invalid")).is_err());
        assert!(desktop.create_localnet("../invalid").is_err());
        assert!(
            desktop
                .resume(Path::new("journal"), None, &mut |_| Ok(()), &mut |_| {})
                .is_err()
        );
        // A genuine selected source outside the project keeps this control about the missing
        // managed context; source admission must not fail before that original owner gate.
        let selected_source = temporary.path().join("unselected.ko");
        std::fs::write(&selected_source, "seiyaku Unselected {}").unwrap();
        assert!(ContractInput::from_path(&selected_source, None, None, false).is_ok());
        // A name cannot be supplied directly to the typed action API; failed capture prevents
        // the action before startup. Removed captured targets are exercised below.
        assert!(desktop.network(Some("missing")).is_err());
        // Desktop input selection uses the same early native admission as Kagami. Invalid
        // content cannot reach deploy/start, change selection, or create a managed generation.
        for (name, contents) in [
            ("invalid.to", "not an IVM artifact"),
            ("Musubi.toml", "[broken"),
        ] {
            let path = temporary.path().join(name);
            std::fs::write(&path, contents).unwrap();
            assert!(ContractInput::from_path(&path, None, None, false).is_err());
            assert!(desktop.contexts().unwrap().is_empty());
            assert_eq!(desktop.selected_name().unwrap(), None);
        }
        assert!(desktop.contexts().unwrap().is_empty());
    }
    #[test]
    fn generated_authority_and_observers_survive_desktop_close_but_reject_reset() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let bin = temporary.path().join("bin");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&bin).unwrap();
        // The native harness does not implement Kagami's worker entry point. Canonical
        // preparation is real; the original budget expires after that worker exits.
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                bin.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        let desktop = DeveloperWorkspace::with_runtime(
            &temporary.path().join("state"),
            &project,
            InstalledRuntime::from_directory(&bin).unwrap(),
        )
        .unwrap();
        let failure = desktop.create_localnet("fixture").unwrap_err();
        assert!(
            matches!(
                failure.downcast_ref::<iroha_deploy::managed::Error>(),
                Some(iroha_deploy::managed::Error::Timeout(timeout)) if *timeout == Duration::from_secs(30)
            ),
            "genuine generation must reach the original-budget worker-start failure: {failure}"
        );
        let context = desktop.select("fixture").unwrap();
        assert_create_refuses_retained_context(&desktop, "fixture");
        let network = desktop.network(None).unwrap();
        assert_eq!(network.prepared().peers.len(), 4);
        // The selected identity must survive the second metadata read, before credentials
        // or an observation object can be acquired from a replacement generation.
        for field in ["network", "account", "endpoint", "dataspace"] {
            let mut stale = context.clone();
            match field {
                "network" => stale.network_id.push('x'),
                "account" => stale.account_id.push('x'),
                "endpoint" => stale.torii_url.push('x'),
                _ => stale.dataspace_id += 1,
            }
            let error = desktop
                .network_from_prepared(&stale, network.prepared().clone())
                .err()
                .unwrap();
            assert_eq!(
                error.to_string(),
                "managed generation changed before loading network credentials",
                "{field}"
            );
        }
        let mut unreadable = network.prepared().clone();
        unreadable.context.client_config = temporary.path().join("absent-client.toml");
        assert_eq!(
            desktop
                .network_from_prepared(&context, unreadable)
                .err()
                .unwrap()
                .to_string(),
            "managed generation changed before loading network credentials",
            "identity refusal precedes even a missing credential source"
        );
        // Even a deliberately absent registry context cannot affect a local source build.
        // The desktop adapter must preserve Musubi's lazy registry discovery boundary.
        let source = temporary.path().join("offline.ko");
        std::fs::write(
            &source,
            "seiyaku Offline { view fn quote(int cups) authorize(anyone) -> int { return cups * 10; } }",
        )
        .unwrap();
        let mut absent_registry = network.clone();
        absent_registry.prepared.context.name = "missing-registry-context".into();
        assert_eq!(
            desktop
                .deployment_runtime(&absent_registry)
                .build(&ContractInput::from_path(&source, None, None, false).unwrap())
                .unwrap()
                .name(),
            "Offline"
        );
        assert!(!desktop.state_root().join("deployments").exists());
        assert!(!network.prepared().build_cache_root().exists());
        assert_eq!(
            network.signer().account_id().to_string(),
            context.account_id
        );
        assert_ne!(
            network.signer().account_id(),
            &*iroha_test_samples::ALICE_ID
        );
        for peer in 0..4 {
            let observer = network.observer(peer).unwrap();
            let reader = network.ledger_reader(peer).unwrap();
            assert_eq!(observer.network_id().as_ref(), Some(reader.network_id()));
            assert_eq!(observer.base_url(), reader.endpoint().as_str());
        }
        assert!(network.observer(4).is_err());
        assert!(network.ledger_reader(4).is_err());
        let draft = crate::InstructionDraft::register_account_from_input(
            &iroha_test_samples::BOB_ID.to_string(),
        )
        .unwrap();
        let preview = network.preview(&[draft]).unwrap();
        assert_eq!(
            preview.signed_transaction().authority(),
            network.signer().account_id()
        );
        assert_eq!(
            preview
                .signed_transaction()
                .network_id()
                .unwrap()
                .to_string(),
            context.network_id
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let wrong_authority = crate::compose_preview_with_options(
            network.config.network_id,
            &[crate::InstructionDraft::register_account_from_input(
                &iroha_test_samples::BOB_ID.to_string(),
            )
            .unwrap()],
            &crate::SigningAuthority::new(
                "foreign",
                iroha_test_samples::ALICE_ID.clone(),
                iroha_test_samples::ALICE_KEYPAIR.clone(),
            ),
            &crate::TransactionComposeOptions::default(),
        )
        .unwrap();
        let error = runtime
            .block_on(network.submit(0, &wrong_authority))
            .unwrap_err();
        assert!(error.to_string().contains("another authority"));
        let mut wrong_network = network.clone();
        wrong_network.config.network_id = crate::torii::test_network_id();
        let error = runtime
            .block_on(wrong_network.submit(0, &preview))
            .unwrap_err();
        assert!(error.to_string().contains("another network"));
        // A desktop that observed no selection must not adopt one that appeared externally.
        assert_eq!(
            desktop
                .action_network(None, true)
                .err()
                .unwrap()
                .to_string(),
            "workspace selection changed; select the network explicitly"
        );
        assert!(matches!(
            desktop
                .action_network(None, false)
                .err()
                .unwrap()
                .downcast_ref::<iroha_deploy::managed::Error>(),
            Some(iroha_deploy::managed::Error::NoSelection)
        ));
        // All actual action entries reject a captured authority from another workspace before
        // readiness, compile/review, namespace wallets or any network operation.
        let input = ContractInput::from_path(&source, None, None, false).unwrap();
        let mut foreign = network.clone();
        foreign.root = temporary.path().join("another-workspace");
        let operation_id = "56".repeat(32).parse().unwrap();
        let failures = [
            desktop
                .deploy(
                    &input,
                    Some(&foreign),
                    None,
                    &mut |_| panic!("foreign deployment reached review"),
                    &mut |_| panic!("foreign deployment reached progress"),
                )
                .err()
                .unwrap(),
            desktop
                .resume(
                    Path::new("missing-journal"),
                    Some(&foreign),
                    &mut |_| panic!("foreign recovery reached review"),
                    &mut |_| panic!("foreign recovery reached progress"),
                )
                .err()
                .unwrap(),
            desktop
                .publish_package(
                    Path::new("missing-manifest"),
                    Some(&foreign),
                    GeneratedPublishAction::Resume { operation_id },
                )
                .err()
                .unwrap(),
        ];
        for error in failures {
            assert_eq!(
                error.to_string(),
                "selected network belongs to another workspace"
            );
        }
        for error in [
            desktop.start(&foreign).err().unwrap(),
            desktop.stop(&foreign).err().unwrap(),
            desktop.reset(&foreign).err().unwrap(),
            desktop.logs(&foreign, None, 1024).err().unwrap(),
        ] {
            assert_eq!(
                error.to_string(),
                "selected network belongs to another workspace"
            );
        }
        // The exact stopped generation remains a valid stop/log target without spawning peers.
        assert_eq!(desktop.stop(&network).unwrap().context, context);
        assert!(desktop.logs(&network, None, 1024).is_ok());
        assert_eq!(desktop.selected_name().unwrap().as_deref(), Some("fixture"));
        assert!(!temporary.path().join("another-workspace").exists());
        let root = desktop.state_root().to_path_buf();
        let retained_desktop = desktop.clone();
        drop(desktop);
        assert_eq!(
            ManagedStore::open(&root).unwrap().context(None).unwrap(),
            context
        );
        network.validate().unwrap();
        ManagedStore::open(&root).unwrap().reset("fixture").unwrap();
        assert!(network.validate().is_err());
        assert!(network.observer(0).is_err());
        assert!(network.ledger_reader(0).is_err());
        assert!(network.preview(&[]).is_err());
        // Removal after capture refuses all three real action entrances. None may restart a
        // replacement generation or create a missing journal on a different authority.
        assert!(
            retained_desktop
                .deploy(
                    &input,
                    Some(&network),
                    None,
                    &mut |_| panic!("stale deployment reached review"),
                    &mut |_| panic!("stale deployment reached progress")
                )
                .is_err()
        );
        assert!(
            retained_desktop
                .resume(
                    Path::new("missing-journal"),
                    Some(&network),
                    &mut |_| panic!("stale recovery reached review"),
                    &mut |_| panic!("stale recovery reached progress")
                )
                .is_err()
        );
        assert!(
            retained_desktop
                .publish_package(
                    Path::new("missing-manifest"),
                    Some(&network),
                    GeneratedPublishAction::Resume { operation_id }
                )
                .is_err()
        );
        assert!(retained_desktop.start(&network).is_err());
        assert!(retained_desktop.stop(&network).is_err());
        assert!(retained_desktop.reset(&network).is_err());
        assert!(retained_desktop.logs(&network, None, 1024).is_err());
        assert!(
            ManagedStore::open(&root)
                .unwrap()
                .contexts()
                .unwrap()
                .is_empty()
        );
        assert!(!root.join("deployments").exists());
        // Failure after the target was admitted keeps that same target in the production
        // outcome owner; observing its name cannot replace this saved authority.
        let failed = run_on_network(network.clone(), ManagedNetwork::validate);
        assert!(failed.outcome.is_err());
        assert_eq!(failed.network.prepared(), network.prepared());
        assert_eq!(
            failed.network.signer().account_id(),
            network.signer().account_id()
        );
        assert_eq!(std::fs::read_dir(project).unwrap().count(), 0);
    }

    #[test]
    fn desktop_member_publication_refuses_another_package_without_starting_workers() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let bin = temporary.path().join("bin");
        std::fs::create_dir_all(project.join("app")).unwrap();
        std::fs::create_dir(project.join("other")).unwrap();
        std::fs::create_dir(&bin).unwrap();
        for program in ["kagami", "iroha3d"] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                bin.join(format!("{program}{}", std::env::consts::EXE_SUFFIX)),
            )
            .unwrap();
        }
        std::fs::write(project.join("Musubi.toml"), "manifest-version = 1\n[workspace]\nmembers = [\"app\", \"other\"]\ndefault-members = [\"other\"]\n").unwrap();
        for name in ["app", "other"] {
            std::fs::write(project.join(name).join("Musubi.toml"), format!("manifest-version = 1\n[package]\nnamespace = \"dev.universal\"\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n")).unwrap();
        }
        let desktop = DeveloperWorkspace::with_runtime(
            &temporary.path().join("state"),
            &project,
            InstalledRuntime::from_directory(&bin).unwrap(),
        )
        .unwrap();
        for input in ["app", "app/Musubi.toml"] {
            let error = desktop
                .publish_package(
                    Path::new(input),
                    None,
                    GeneratedPublishAction::Begin {
                        package: Some("dev.universal/other".parse().unwrap()),
                        detach: false,
                    },
                )
                .err()
                .unwrap();
            assert_eq!(
                error.to_string(),
                "selected member manifest cannot select another package"
            );
            assert!(desktop.contexts().unwrap().is_empty());
            assert_eq!(desktop.selected_name().unwrap(), None);
            assert!(!project.join("Musubi.lock").exists());
            assert!(!project.join("target").exists());
        }
    }
}
