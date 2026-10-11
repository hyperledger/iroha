//! Presentation-free contract compilation and durable native deployment.
//!
//! Callers supply the exact SDK configuration, alias scope, private journal root and cache root.
//! This boundary never discovers a wallet, network configuration, cache location or signing
//! material from a project or the operating-system user cache.
use crate::archive_fetch::PreparedProductionSorafsArchiveTransportV1;
use eyre::{Result, WrapErr as _, bail, eyre};
use iroha::config::Config;
use iroha_contract_deploy::{
    DeploymentError, DeploymentLifecycleGuidance, DeploymentPreflight, DeploymentProgress,
    DeploymentReceipt, DeploymentRequest, DeploymentService, JournalDisposition, LifecycleHook,
    MAX_DEPLOYMENT_ARTIFACT_BYTES, PreparedDeployment,
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, smart_contract::ContractAlias,
    transaction::FeePaymentIntent,
};
use iroha_fs::{PrivateDirectory, PublishMode, SelectedRegularFile};
use kotodama_lang::{
    compiler::CompilerOptions,
    driver::{BuildDriver, discover_selected_source_link_request},
    session::CompilerSession,
};
use std::path::{Path, PathBuf};

mod slot;
pub(crate) use slot::{DeploymentSlot, RetainedDeployment, RetryRequest};

/// Explicit contract input; source and bytecode require no project manifest.
#[derive(Debug)]
pub enum ContractInput {
    /// A native-selected Kotodama root and its explicitly declared local includes.
    Source(SelectedRegularFile),
    /// A native-selected complete, self-describing IVM `.to` artifact.
    Bytecode(SelectedRegularFile),
    /// A Musubi package or workspace with canonical dependency resolution.
    Package {
        /// Original native-selected package/workspace manifest.
        manifest: SelectedRegularFile,
        /// Workspace-root package selection; a selected member permits only its own selector.
        package: Option<String>,
        /// Declared target, required when more than one target is selected.
        contract: Option<String>,
        /// Reject changes to the existing dependency lock.
        locked: bool,
    },
}

impl ContractInput {
    /// Select source, bytecode or an explicit Musubi package from one user-supplied path.
    /// Native selection runs before provisioning and retains the original root file through
    /// startup and build. An explicitly selected non-root member deploys only its owning package;
    /// an actual workspace root retains declared defaults and explicit package selection.
    /// The selected artifact or manifest passes network-independent admission before startup.
    /// Declared companions, full package graphs and source compilation still belong to their
    /// canonical owners under the actual selected network. Later validation is never skipped.
    ///
    /// # Errors
    /// Rejects missing or nonregular inputs, missing package manifests, package selectors on
    /// standalone files, unsupported file names, malformed artifacts and invalid manifests.
    pub fn from_path(
        path: &Path,
        package: Option<String>,
        contract: Option<String>,
        locked: bool,
    ) -> Result<Self> {
        let input = Self::select_path(path, package, contract, locked)?;
        input.validate_local()?;
        Ok(input)
    }

    fn validate_local(&self) -> Result<()> {
        // Keep the captured original file alive. Every read uses that same native owner;
        // close ordinary parser failures as well as success before returning the selection.
        // Do not install/reset a decode budget or retain a validation result across startup.
        let (selected, result) = match self {
            Self::Source(_) => return Ok(()),
            Self::Bytecode(selected) => (
                selected,
                selected
                    .read(MAX_DEPLOYMENT_ARTIFACT_BYTES)
                    .wrap_err("read exact contract bytecode")
                    .and_then(BuiltArtifact::from_bytes)
                    .map(|_| ()),
            ),
            Self::Package { manifest, .. } => (
                manifest,
                crate::workspace::read_manifest_selected(manifest.path(), Some(manifest))
                    .map(|_| ())
                    .map_err(Into::into),
            ),
        };
        selected
            .revalidate()
            .wrap_err("retain original deployment input")?;
        result
    }

    fn select_path(
        path: &Path,
        package: Option<String>,
        contract: Option<String>,
        locked: bool,
    ) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)
            .wrap_err_with(|| format!("inspect contract input {}", path.display()))?;
        if metadata.is_dir() && !input_is_redirected(&metadata) {
            let manifest = path.join("Musubi.toml");
            let manifest_metadata = std::fs::symlink_metadata(&manifest)
                .wrap_err_with(|| format!("package directory requires {}", manifest.display()))?;
            if !manifest_metadata.is_file() || input_is_redirected(&manifest_metadata) {
                bail!(
                    "package manifest must be a regular file: {}",
                    manifest.display()
                );
            }
            return Ok(Self::Package {
                manifest: SelectedRegularFile::capture(&manifest)
                    .wrap_err("retain selected package manifest")?,
                package,
                contract,
                locked,
            });
        }
        if !metadata.is_file() || input_is_redirected(&metadata) {
            bail!("contract input must be a regular file or package directory");
        }
        match path.extension().and_then(|value| value.to_str()) {
            Some("ko" | "to") => {
                if package.is_some() || contract.is_some() || locked {
                    bail!("package, contract and locked options require a Musubi package");
                }
                if path.extension().is_some_and(|value| value == "ko") {
                    Ok(Self::Source(
                        SelectedRegularFile::capture(path)
                            .wrap_err("retain selected Kotodama source")?,
                    ))
                } else {
                    Ok(Self::Bytecode(
                        SelectedRegularFile::capture(path)
                            .wrap_err("retain selected contract bytecode")?,
                    ))
                }
            }
            _ if path.file_name().is_some_and(|name| name == "Musubi.toml") => Ok(Self::Package {
                manifest: SelectedRegularFile::capture(path)
                    .wrap_err("retain selected package manifest")?,
                package,
                contract,
                locked,
            }),
            _ => bail!(
                "contract input must be .ko source, .to bytecode, Musubi.toml or a package directory"
            ),
        }
    }
}

fn input_is_redirected(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Explicit alias or an already acquired namespace selected by the environment owner.
#[derive(Clone, Debug)]
pub enum AliasSelection {
    /// Use this exact canonical alias.
    Exact(ContractAlias),
    /// Derive the contract label from the verified embedded seiyaku name.
    Scope {
        /// Optional owned domain within the dataspace.
        domain: Option<String>,
        /// Canonical dataspace alias, for example `universal`.
        dataspace: String,
    },
}

/// Verified immutable bytes handed directly from the compiler to deployment.
pub struct BuiltArtifact {
    bytes: Vec<u8>,
    name: String,
    code_hash: iroha::crypto::Hash,
    lifecycle_hook: Option<LifecycleHook>,
}
impl BuiltArtifact {
    /// Verify complete artifact bytes and retain their canonical contract name.
    ///
    /// # Errors
    /// Rejects oversized, malformed or unnamed artifacts before contacting a network.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_DEPLOYMENT_ARTIFACT_BYTES {
            bail!("contract artifact exceeds the deployment byte limit");
        }
        let verified = ivm::verify_contract_artifact(&bytes)
            .map_err(|error| eyre!("invalid contract artifact: {error}"))?;
        if !verified.private_input_entrypoints().is_empty() {
            bail!(
                "contract entrypoints {} require raw private inputs from a prover/test host; production consensus hosts do not provide them. Generate proofs off-chain and deploy a public-proof verifier instead",
                verified.private_input_entrypoints().join(", ")
            );
        }
        let name = verified
            .manifest
            .seiyaku_name
            .clone()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| eyre!("contract artifact has no embedded seiyaku name"))?;
        Ok(Self {
            bytes,
            name,
            code_hash: verified.code_hash,
            lifecycle_hook: LifecycleHook::from_verified(&verified),
        })
    }

    /// Borrow the exact verified bytes; deployment never reopens a compiled artifact.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Embedded seiyaku name used for default alias selection.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Select a canonical alias without acquiring or inferring permissions.
    ///
    /// # Errors
    /// Rejects invalid alias components. Effective permissions are verified by deployment.
    pub fn alias(&self, selection: &AliasSelection) -> Result<ContractAlias> {
        match selection {
            AliasSelection::Exact(alias) => Ok(alias.clone()),
            AliasSelection::Scope { domain, dataspace } => {
                ContractAlias::from_components(&self.name, domain.as_deref(), dataspace)
                    .map_err(|error| eyre!("invalid default contract alias: {error}"))
            }
        }
    }
}

/// A finalized deployment and its retained, owner-private recovery directory.
pub struct DeploymentRun {
    /// Selected-root Applied evidence and authenticated artifact/alias readback; parent anchoring is separate.
    pub receipt: DeploymentReceipt,
    /// Exact journal used for this operation.
    pub journal: PathBuf,
    /// Optional artifact-derived guidance; it never asserts the current lifecycle state.
    pub lifecycle: Option<DeploymentLifecycleGuidance>,
}

/// Lazy exact registry configuration and archive policy supplied by the environment owner.
pub type BuildRegistryResolver =
    dyn Fn() -> Result<Option<(Config, PreparedProductionSorafsArchiveTransportV1)>> + Send + Sync;

/// Shared native runtime for Kagami, Mochi and other callers with an explicit network context.
pub struct DeploymentRuntime {
    config: Config,
    journal_root: PathBuf,
    cache_root: PathBuf,
    archive_transport: Option<PreparedProductionSorafsArchiveTransportV1>,
    build_registry: Option<Config>,
    registry_resolver: Option<std::sync::Arc<BuildRegistryResolver>>,
}
impl DeploymentRuntime {
    /// Retain immutable context without reading files, loading keys or contacting the network.
    #[must_use]
    pub fn new(config: Config, journal_root: PathBuf, cache_root: PathBuf) -> Self {
        Self {
            config,
            journal_root,
            cache_root,
            archive_transport: None,
            build_registry: None,
            registry_resolver: None,
        }
    }

    /// Bind external dependencies to this runtime's registry and retain its archive transport.
    /// Even a complete cache requires the explicit registry binding; provider requests are
    /// needed only for missing archives. Source, bytecode and local-only graphs need neither.
    #[must_use]
    pub fn with_archive_transport(
        mut self,
        transport: PreparedProductionSorafsArchiveTransportV1,
    ) -> Self {
        self.build_registry = Some(self.config.clone());
        self.registry_resolver = None;
        self.archive_transport = Some(transport);
        self
    }

    /// Bind package resolution/downloads to an independently selected build registry.
    /// The deployment signer and compiler address policy remain the selected target context.
    /// # Errors
    /// Refuses transport and registry configuration belonging to different networks.
    pub fn with_build_registry(
        mut self,
        registry: Config,
        transport: PreparedProductionSorafsArchiveTransportV1,
    ) -> Result<Self> {
        if registry.network_id != transport.network_id() {
            bail!("build registry transport belongs to another network");
        }
        self.build_registry = Some(registry);
        self.registry_resolver = None;
        self.archive_transport = Some(transport);
        Ok(self)
    }

    /// Resolve an authenticated registry only if the package needs external dependencies.
    /// Source, bytecode and purely local package graphs never call the resolver.
    #[must_use]
    pub fn with_build_registry_resolver(
        mut self,
        resolver: std::sync::Arc<BuildRegistryResolver>,
    ) -> Self {
        self.build_registry = None;
        self.archive_transport = None;
        self.registry_resolver = Some(resolver);
        self
    }

    /// Compile source, authenticate bytecode or build one exact package target.
    ///
    /// # Errors
    /// Returns canonical compiler, dependency, filesystem or artifact diagnostics.
    pub fn build(&self, input: &ContractInput) -> Result<BuiltArtifact> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        match input {
            ContractInput::Bytecode(selected) => BuiltArtifact::from_bytes(
                selected
                    .read(MAX_DEPLOYMENT_ARTIFACT_BYTES)
                    .wrap_err("read exact contract bytecode")?,
            ),
            ContractInput::Source(selected) => {
                selected
                    .revalidate()
                    .wrap_err("retain original Kotodama source")?;
                let root = selected
                    .path()
                    .parent()
                    .ok_or_else(|| eyre!("source has no parent"))?;
                let graph =
                    discover_selected_source_link_request(selected, root, Vec::new(), Vec::new())
                        .map_err(|error| eyre!("load Kotodama source graph: {error}"))?;
                let name = graph.root.source_name.clone();
                let driver =
                    BuildDriver::for_current_executable(CompilerSession::new(CompilerOptions {
                        chain_discriminant: self.config.account_chain_discriminant,
                        ..CompilerOptions::default()
                    }))
                    .map_err(|error| eyre!("create canonical compiler: {error}"))?;
                let output = driver
                    .compile_project(graph, &name)
                    .map_err(|error| eyre!("compile Kotodama contract: {error}"))?;
                selected
                    .revalidate()
                    .wrap_err("retain original compiled source")?;
                BuiltArtifact::from_bytes(output.artifact)
            }
            ContractInput::Package {
                manifest,
                package,
                contract,
                locked,
            } => {
                manifest
                    .revalidate()
                    .wrap_err("retain original package manifest")?;
                crate::command::build_runtime_package(
                    &self.config,
                    &self.cache_root,
                    self.build_registry.as_ref(),
                    self.registry_resolver.as_deref(),
                    &crate::command::RuntimePackageSelection {
                        manifest,
                        package: package.as_deref(),
                        contract: contract.as_deref(),
                        locked: *locked,
                    },
                    self.archive_transport.clone(),
                )
            }
        }
    }

    /// Build and deploy a contract using exact quoted fees and canonical finality.
    /// The review callback may reject or reserve a caller's spending budget before persistence.
    ///
    /// # Errors
    /// Returns build, review, unresolved prior journal, native deployment or readback errors.
    pub fn deploy(
        &self,
        input: &ContractInput,
        alias: &AliasSelection,
        fee_payment: FeePaymentIntent,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<DeploymentRun> {
        self.deploy_artifact(self.build(input)?, alias, fee_payment, review, progress)
    }

    /// Deploy already verified compiler output without reopening source or artifact files.
    ///
    /// # Errors
    /// Rejects invalid aliases, competing unresolved work, failed review or native execution.
    pub fn deploy_artifact(
        &self,
        artifact: BuiltArtifact,
        selection: &AliasSelection,
        fee_payment: FeePaymentIntent,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<DeploymentRun> {
        let alias = artifact.alias(selection)?;
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let service = DeploymentService::new(self.config.clone())?;
        let slot = deployment_slot(&self.config, &self.journal_root, &alias);
        let session = DeploymentSlot::open(&slot)?;
        if let Some(retained) = session.recover_matching(
            &service,
            RetryRequest {
                code_hash: artifact.code_hash,
                alias: &alias,
                fee_payment: &fee_payment,
                prepare_only: false,
            },
            review,
            progress,
        )? {
            let receipt = retained
                .receipt
                .ok_or_else(|| eyre!("deployment recovery returned no receipt"))?;
            return Ok(DeploymentRun {
                receipt,
                journal: retained.journal,
                lifecycle: artifact.lifecycle_hook.map(|hook| hook.guidance(true)),
            });
        }
        let lifecycle = artifact.lifecycle_hook.map(|hook| hook.guidance(false));
        let prepared = service.prepare(&DeploymentRequest {
            artifact: artifact.bytes,
            alias,
            fee_payment,
            governance_approvers: Vec::new(),
        })?;
        review(prepared.preflight())?;
        let journal = session.persist(&service, &prepared)?;
        let receipt = session.execute(&service, &prepared, &journal, progress)?;
        Ok(DeploymentRun {
            receipt,
            journal,
            lifecycle,
        })
    }

    /// Recover the exact retained plan without compiling, signing replacements or replaying.
    ///
    /// # Errors
    /// Rejects a journal outside this runtime's root, concurrent work or invalid native evidence.
    pub fn resume(
        &self,
        journal: &Path,
        review: &mut dyn FnMut(&DeploymentPreflight) -> Result<()>,
        progress: &mut dyn FnMut(DeploymentProgress),
    ) -> Result<DeploymentRun> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let root = self
            .journal_root
            .canonicalize()
            .wrap_err("resolve deployment journal root")?;
        let name = journal
            .file_name()
            .ok_or_else(|| eyre!("deployment journal has no commit ID"))?;
        let retained = journal
            .parent()
            .ok_or_else(|| eyre!("deployment journal has no slot"))?
            .canonicalize()
            .wrap_err("resolve exact deployment slot")?
            .join(name);
        if retained
            .strip_prefix(&root)
            .map(|relative| relative.components().count())
            != Ok(2)
        {
            bail!("deployment journal is outside this runtime's journal slots");
        }
        let slot = retained
            .parent()
            .ok_or_else(|| eyre!("deployment journal has no slot"))?;
        let session = DeploymentSlot::open_read(slot)?;
        let service = DeploymentService::new(self.config.clone())?;
        session.admit_resume(&service, &retained)?;
        let retained_preflight = service
            .retained_preflight(&retained)
            .map_err(|error| journal_failure(error, &retained))?;
        validate_journal_location(
            &self.config,
            &root,
            &retained,
            &retained_preflight.contract_alias,
            &plan_journal_id(&retained_preflight)?,
        )?;
        let receipt = after_review(&retained_preflight, review, || {
            session.resume(&service, &retained, &retained_preflight, progress)
        })?;
        // Guidance is a separate read-only convenience. Its failure cannot erase Applied.
        let lifecycle = service
            .retained_lifecycle_hook(&retained, receipt.code_hash)
            .ok()
            .flatten()
            .map(|hook| hook.guidance(true));
        Ok(DeploymentRun {
            receipt,
            journal: retained,
            lifecycle,
        })
    }

    /// Locate and authenticate the current completed deployment for one exact alias.
    ///
    /// No build, wallet discovery, signing or dispatch occurs. The same native alias slot and
    /// retained journal ownership used by deployment also governs this read.
    ///
    /// # Errors
    /// Rejects absent, unresolved, substituted, unsafe or changed current deployments.
    pub fn current_deployment(&self, alias: &ContractAlias) -> Result<CurrentDeployment> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let slot = deployment_slot(&self.config, &self.journal_root, alias);
        // A read must not create a new alias slot merely because no deployment exists.
        let session = DeploymentSlot::open_read(&slot)?;
        let journal = session
            .current_journal()?
            .ok_or_else(|| eyre!("contract alias has no retained deployment"))?;
        let service = DeploymentService::new(self.config.clone())?;
        let preflight = service
            .retained_preflight(&journal)
            .map_err(|error| journal_failure(error, &journal))?;
        if &preflight.contract_alias != alias {
            bail!("retained deployment resolves a different alias");
        }
        validate_journal_location(
            &self.config,
            &self.journal_root,
            &journal,
            alias,
            &plan_journal_id(&preflight)?,
        )?;
        let contract = service
            .current_completed_contract(&journal)
            .map_err(|error| journal_failure(error, &journal))?;
        session.revalidate()?;
        Ok(CurrentDeployment { contract, journal })
    }
}

/// Exact completed deployment selected by the native alias slot.
pub struct CurrentDeployment {
    /// Authenticated Applied receipt and complete retained artifact.
    pub contract: iroha_contract_deploy::CompletedContract,
    /// Owner-private original deployment recovery path.
    pub journal: PathBuf,
}

fn journal_failure(error: DeploymentError, journal: &Path) -> eyre::Report {
    // Frontends commonly display only the outer message. Preserve the native public diagnostic
    // alongside its exact recovery path without expanding arbitrary underlying error chains.
    let message = format!("{error}\nDeployment journal: {}", journal.display());
    eyre::Report::new(error).wrap_err(message)
}

fn after_review<T, R, F: FnMut(&T) -> Result<()> + ?Sized>(
    retained: &T,
    review: &mut F,
    dispatch: impl FnOnce() -> Result<R>,
) -> Result<R> {
    review(retained)?;
    dispatch()
}

fn deployment_slot(config: &Config, root: &Path, alias: &ContractAlias) -> PathBuf {
    root.join(deployment_slot_name(
        &config.network_id,
        config.account_chain_discriminant,
        &config.account,
        alias,
    ))
}

fn deployment_slot_name(
    network: &iroha_data_model::NetworkId,
    discriminant: u16,
    authority: &iroha_data_model::account::AccountId,
    alias: &ContractAlias,
) -> String {
    let _profile = ChainDiscriminantGuard::enter(discriminant);
    let identity = format!(
        "iroha.contract-deployment-slot.v1\n{network}\n{discriminant}\n{authority}\n{alias}"
    );
    blake3::hash(identity.as_bytes()).to_hex().to_string()
}

fn validate_journal_location(
    config: &Config,
    root: &Path,
    journal: &Path,
    alias: &ContractAlias,
    commit_id: &str,
) -> Result<()> {
    validate_journal_id(commit_id)?;
    if deployment_slot(config, root, alias).join(commit_id) != journal {
        bail!("deployment journal location differs from its authenticated target and commit");
    }
    Ok(())
}

pub(crate) fn plan_journal_id(preflight: &DeploymentPreflight) -> Result<String> {
    let hash = preflight
        .transaction_hashes
        .last()
        .ok_or_else(|| eyre!("deployment plan contains no atomic commit"))?;
    let hash = hash
        .parse::<iroha::crypto::Hash>()
        .wrap_err("deployment plan contains an invalid transaction hash")?;
    Ok(hex::encode(hash.as_ref()))
}

fn validate_journal_id(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("deployment journal must name one exact transaction hash");
    }
    id.parse::<iroha::crypto::Hash>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const SOURCE: &str =
        "seiyaku Coffee { view fn quote(int cups) authorize(anyone) -> int { return cups * 10; } }";

    #[test]
    fn journal_failure_display_preserves_pending_hash_cause_and_exact_recovery_path() {
        let hash = iroha::crypto::Hash::new(b"original attempted deployment").to_string();
        let journal = Path::new("managed state/deployments/original journal");
        let diagnostic =
            eyre!("internal transport detail").wrap_err("the original finality deadline elapsed");
        let error = journal_failure(
            DeploymentError::Pending {
                step: "upload".to_owned(),
                hash: hash.clone(),
                source: diagnostic,
            },
            journal,
        );
        let displayed = error.to_string();
        assert!(displayed.contains("deployment step `upload`"));
        assert!(displayed.contains(&hash));
        assert!(displayed.contains("the original finality deadline elapsed"));
        assert!(displayed.contains("resume this journal without creating another deployment"));
        assert!(displayed.ends_with(&format!("Deployment journal: {}", journal.display())));
        assert!(!displayed.contains("internal transport detail"));
        assert!(matches!(
            error.downcast_ref::<DeploymentError>(),
            Some(DeploymentError::Pending { hash: original, .. }) if original == &hash
        ));
    }

    #[test]
    fn journal_failure_preserves_native_error_categories_and_public_messages() {
        let journal = Path::new("managed state/original journal");
        for native in [
            DeploymentError::Preflight {
                operation: "fee quote",
                source: eyre!("approved fee cap exceeded"),
            },
            DeploymentError::Journal(eyre!("original journal is busy")),
            DeploymentError::Readback(eyre!("alias differs from original contract")),
        ] {
            let public = native.to_string();
            let error = journal_failure(native, journal);
            assert!(error.to_string().starts_with(&public));
            assert!(error.downcast_ref::<DeploymentError>().is_some());
            assert!(
                error
                    .to_string()
                    .ends_with(&format!("Deployment journal: {}", journal.display()))
            );
        }
    }

    #[test]
    fn retained_plan_review_rejection_prevents_recovery_dispatch() {
        let dispatches = std::cell::Cell::new(0);
        let result = after_review(
            &"exact retained plan",
            &mut |plan: &&str| {
                assert_eq!(*plan, "exact retained plan");
                bail!("selected dataspace or fee cap rejected")
            },
            || {
                dispatches.set(dispatches.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(dispatches.get(), 0);
        after_review(&(), &mut |()| Ok(()), || {
            dispatches.set(dispatches.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(dispatches.get(), 1);
    }

    #[test]
    fn input_selection_is_explicit_and_rejects_ignored_options() -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("x.ko");
        let bytecode = temp.path().join("x.to");
        let manifest = temp.path().join("Musubi.toml");
        fs::write(&source, SOURCE)?;
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .map_err(|error| eyre!(error))?;
        fs::write(&bytecode, artifact)?;
        assert!(ContractInput::from_path(temp.path(), None, None, false).is_err());
        assert!(ContractInput::from_path(&manifest, None, None, false).is_err());
        let package_manifest = "manifest-version = 1\n[package]\nnamespace = \"demo\"\nname = \"coffee\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n[[contract]]\nname = \"coffee\"\npath = \"x.ko\"\n";
        fs::write(&manifest, package_manifest)?;
        assert!(matches!(
            ContractInput::from_path(&source, None, None, false)?,
            ContractInput::Source(_)
        ));
        assert!(matches!(
            ContractInput::from_path(&bytecode, None, None, false)?,
            ContractInput::Bytecode(_)
        ));
        assert!(
            matches!(ContractInput::from_path(temp.path(), Some("demo/coffee".into()), Some("coffee".into()), true)?, ContractInput::Package { manifest, locked: true, .. } if manifest.path() == temp.path().canonicalize()?.join("Musubi.toml"))
        );
        assert!(matches!(
            ContractInput::from_path(&manifest, None, None, false)?,
            ContractInput::Package { .. }
        ));
        let source_named_directory = temp.path().join("package.ko");
        fs::create_dir(&source_named_directory)?;
        assert!(ContractInput::from_path(&source_named_directory, None, None, false).is_err());
        fs::write(source_named_directory.join("Musubi.toml"), package_manifest)?;
        assert!(matches!(
            ContractInput::from_path(&source_named_directory, None, None, false)?,
            ContractInput::Package { .. }
        ));
        for path in ["other.toml", "unknown", "x.KO"] {
            let path = temp.path().join(path);
            fs::write(&path, b"existing unsupported input")?;
            assert!(ContractInput::from_path(&path, None, None, false).is_err());
        }
        assert!(
            ContractInput::from_path(&temp.path().join("missing.ko"), None, None, false).is_err()
        );
        assert!(ContractInput::from_path(&source, Some("demo".into()), None, false).is_err());
        assert!(ContractInput::from_path(&bytecode, None, Some("target".into()), false).is_err());
        assert!(ContractInput::from_path(&source, None, None, true).is_err());
        #[cfg(unix)]
        {
            let link = temp.path().join("linked.ko");
            std::os::unix::fs::symlink(&source, &link)?;
            assert!(ContractInput::from_path(&link, None, None, false).is_err());
            assert!(ContractInput::from_path(Path::new("/dev/null"), None, None, false).is_err());
        }
        Ok(())
    }

    #[test]
    fn input_preflight_rejects_local_content_and_preserves_active_decode_limits() -> Result<()> {
        let temporary = TempDir::new()?;
        let artifact_path = temporary.path().join("invalid.to");
        for bytes in [b"".as_slice(), b"not an IVM artifact"] {
            fs::write(&artifact_path, bytes)?;
            let error = ContractInput::from_path(&artifact_path, None, None, false).unwrap_err();
            assert!(format!("{error:#}").contains("contract artifact"));
        }
        fs::File::create(&artifact_path)?.set_len((MAX_DEPLOYMENT_ARTIFACT_BYTES + 1) as u64)?;
        assert!(ContractInput::from_path(&artifact_path, None, None, false).is_err());
        let manifest = temporary.path().join("Musubi.toml");
        fs::File::create(&manifest)?.set_len(crate::workspace::MAX_MANIFEST_BYTES + 1)?;
        assert!(ContractInput::from_path(&manifest, None, None, false).is_err());
        for bytes in [b"[broken".as_slice(), b"manifest-version = 1", &[0xff]] {
            fs::write(&manifest, bytes)?;
            assert!(ContractInput::from_path(&manifest, None, None, false).is_err());
            assert!(ContractInput::from_path(temporary.path(), None, None, false).is_err());
        }
        // A virtual root needs no invented package/network binding during local admission.
        fs::write(
            &manifest,
            "manifest-version = 1\n[workspace]\nmembers = []\n",
        )?;
        assert!(ContractInput::from_path(&manifest, None, None, false).is_ok());
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .map_err(|error| eyre!(error))?;
        fs::write(&artifact_path, &bytes)?;
        for allocation in [0, 1] {
            let limits = norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                allocation,
                usize::MAX,
            );
            let result = norito::core::with_decode_limits_scope(limits, || {
                ContractInput::from_path(&artifact_path, None, None, false)
            });
            assert!(
                result.is_err(),
                "selection must retain the caller's decode refusal"
            );
        }
        let selected = ContractInput::from_path(&artifact_path, None, None, false)?;
        let runtime = DeploymentRuntime::new(
            config(),
            temporary.path().join("journals"),
            temporary.path().join("cache"),
        );
        // Early admission does not bypass a later active owner or replace authoritative build.
        assert!(
            norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || runtime.build(&selected),
            )
            .is_err()
        );
        assert_eq!(runtime.build(&selected)?.bytes(), bytes);
        assert!(!temporary.path().join("journals").exists());
        assert!(!temporary.path().join("cache").exists());
        Ok(())
    }

    pub(super) fn config() -> Config {
        let source = br#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "http://127.0.0.1:9/"
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
"#;
        Config::load_bytes_with_musubi_publication(Path::new("unused-runtime.toml"), source)
            .expect("fixture config")
            .0
    }

    #[test]
    fn current_deployment_read_never_creates_or_repairs_an_absent_slot() -> Result<()> {
        let temporary = TempDir::new()?;
        let config = config();
        let root = temporary.path().join("absent-deployments");
        let runtime =
            DeploymentRuntime::new(config.clone(), root.clone(), temporary.path().join("cache"));
        let alias: ContractAlias = "Counter::universal".parse()?;
        assert!(runtime.current_deployment(&alias).is_err());
        assert!(!root.exists());

        let slot = deployment_slot(&config, &root, &alias);
        let directory = PrivateDirectory::open_or_create(&slot)?;
        directory.write_atomic("sentinel", b"original", PublishMode::CreateNew)?;
        assert!(runtime.current_deployment(&alias).is_err());
        assert!(!slot.join("deployment.lock").exists());
        assert!(!slot.join("publication.json").exists());
        assert_eq!(directory.read("sentinel", 8)?.as_slice(), b"original");
        Ok(())
    }

    #[test]
    fn repeated_deploy_and_resume_keep_original_journal_when_retained_plan_authentication_fails()
    -> Result<()> {
        let temporary = TempDir::new()?;
        let root = PrivateDirectory::open_or_create(temporary.path().join("journals"))?;
        let runtime = DeploymentRuntime::new(
            config(),
            root.path().to_path_buf(),
            temporary.path().join("unused-cache"),
        );
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .map_err(|error| eyre!("{error}"))?;
        let artifact = BuiltArtifact::from_bytes(bytes)?;
        let selection = AliasSelection::Scope {
            domain: None,
            dataspace: "universal".into(),
        };
        let alias = artifact.alias(&selection)?;
        let session = DeploymentSlot::open(&deployment_slot(&runtime.config, root.path(), &alias))?;
        let directory = &session.writer;
        let id = hex::encode(iroha::crypto::Hash::new(b"original retained deployment").as_ref());
        let journal = directory.create_child(&id)?;
        let original_plan = b"invalid retained plan, never a new deployment";
        journal.write_atomic("plan.json", original_plan, PublishMode::CreateNew)?;
        let original_journal = journal.path().to_path_buf();
        session.write_state(&slot::Publication::Active {
            journal: id.clone(),
        })?;
        drop(journal);
        drop(session);

        let repeated = runtime
            .deploy_artifact(
                artifact,
                &selection,
                FeePaymentIntent::authority(Vec::new(), None),
                &mut |_| panic!("an unauthenticated retained plan must never reach review"),
                &mut |_| panic!("an unauthenticated retained plan must never reach dispatch"),
            )
            .err()
            .expect("invalid original plan must refuse another deployment");
        let resumed = runtime
            .resume(
                &original_journal,
                &mut |_| panic!("an unauthenticated retained plan must never reach review"),
                &mut |_| panic!("an unauthenticated retained plan must never reach dispatch"),
            )
            .err()
            .expect("invalid original plan must refuse recovery");
        let current = runtime
            .current_deployment(&alias)
            .err()
            .expect("invalid original plan must refuse the read-only deployment view");
        for error in [repeated, resumed, current] {
            assert!(matches!(
                error.downcast_ref::<DeploymentError>(),
                Some(DeploymentError::Journal(_))
            ));
            assert!(error.to_string().ends_with(&format!(
                "Deployment journal: {}",
                original_journal.display()
            )));
        }
        assert_eq!(fs::read(original_journal.join("plan.json"))?, original_plan);
        let directory =
            PrivateDirectory::open(deployment_slot(&runtime.config, root.path(), &alias))?;
        assert_eq!(
            DeploymentSlot::open_read(directory.path())?.current_journal()?,
            Some(original_journal)
        );
        assert_eq!(
            fs::read_dir(directory.path())?.count(),
            3,
            "failure must not create a replacement journal"
        );
        assert!(!temporary.path().join("unused-cache").exists());
        Ok(())
    }

    #[test]
    fn source_and_bytecode_ignore_neighboring_configuration() -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("arbitrary-filename.ko");
        fs::write(&source, SOURCE)?;
        fs::write(
            temp.path().join("client.toml"),
            "invalid caller configuration",
        )?;
        fs::write(
            temp.path().join("Musubi.toml"),
            "invalid unrelated manifest",
        )?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("explicit-build-cache"),
        );
        let built = runtime.build(&ContractInput::from_path(&source, None, None, false)?)?;
        assert_eq!(built.name(), "Coffee");
        let bytecode = temp.path().join("contract.to");
        fs::write(&bytecode, built.bytes())?;
        let loaded = runtime.build(&ContractInput::from_path(&bytecode, None, None, false)?)?;
        assert_eq!(loaded.bytes(), built.bytes());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("explicit-build-cache").exists());
        assert!(!temp.path().join("Musubi.lock").exists());
        Ok(())
    }

    #[test]
    fn source_bytecode_and_package_keep_the_same_canonical_lifecycle_guidance() -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("counter.ko");
        fs::write(
            &source,
            "seiyaku Counter { state int value; 始まり(int start) { value = start; } view fn current() authorize(anyone) -> int { return value; } }",
        )?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("cache"),
        );
        let built = runtime.build(&ContractInput::from_path(&source, None, None, false)?)?;
        let bytecode = temp.path().join("counter.to");
        fs::write(&bytecode, built.bytes())?;
        let loaded = runtime.build(&ContractInput::from_path(&bytecode, None, None, false)?)?;
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "demo"
name = "counter"
version = "0.1.0"
edition = "1"
abi-version = 1
[[contract]]
name = "counter"
path = "counter.ko"
"#,
        )?;
        let packaged = runtime.build(&ContractInput::from_path(temp.path(), None, None, false)?)?;
        let expected = Some(LifecycleHook {
            name: "hajimari".into(),
            params: vec![iroha_contract_deploy::LifecycleParameter {
                name: "start".into(),
                type_name: "int".into(),
            }],
        });
        for artifact in [built, loaded, packaged] {
            assert_eq!(artifact.lifecycle_hook, expected);
            let hook = artifact.lifecycle_hook.unwrap();
            assert!(!hook.clone().guidance(false).recovered);
            assert!(hook.guidance(true).recovered);
        }
        assert!(!temp.path().join("journals").exists());
        Ok(())
    }

    #[test]
    fn default_alias_uses_embedded_name_and_explicit_scope() -> Result<()> {
        let bytes = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .map_err(|error| eyre!("{error}"))?;
        let artifact = BuiltArtifact::from_bytes(bytes)?;
        let scope = AliasSelection::Scope {
            domain: Some("developer".into()),
            dataspace: "universal".into(),
        };
        assert_eq!(
            artifact.alias(&scope)?,
            ContractAlias::from_components("Coffee", Some("developer"), "universal")?
        );
        let exact: ContractAlias = "other::private".parse()?;
        assert_eq!(
            artifact.alias(&AliasSelection::Exact(exact.clone()))?,
            exact
        );
        assert!(
            artifact
                .alias(&AliasSelection::Scope {
                    domain: None,
                    dataspace: "invalid.scope".into()
                })
                .is_err()
        );
        assert!(BuiltArtifact::from_bytes(vec![0; 32]).is_err());
        Ok(())
    }

    #[test]
    fn deployment_rejects_private_witnesses_without_rejecting_other_zk_artifacts() {
        let compiler = kotodama_lang::compiler::Compiler::new_with_options(
            kotodama_lang::compiler::CompilerOptions {
                force_zk: true,
                ..Default::default()
            },
        );
        let public = compiler
            .compile_source("seiyaku Public { view fn read() authorize(anyone) -> int { 1 } }")
            .unwrap();
        assert!(BuiltArtifact::from_bytes(public).is_ok());
        let private = compiler.compile_source("seiyaku Prover { fn witness() -> Secret<int> { crypto::private_input(0) } kotoage fn commitment() authorize(anyone) -> int { let value = witness(); crypto::valcom(left: value, right: value) } }").unwrap();
        let error = BuiltArtifact::from_bytes(private)
            .err()
            .expect("private inputs cannot deploy");
        assert!(error.to_string().contains("commitment"));
        assert!(error.to_string().contains("prover/test host"));
    }

    #[test]
    fn package_build_uses_runtime_context_without_network_bindings() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(temp.path().join("contract.ko"), SOURCE)?;
        let manifest = temp.path().join("Musubi.toml");
        fs::write(
            &manifest,
            "manifest-version = 1\n[package]\nnamespace = \"demo\"\nname = \"coffee\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n[[contract]]\nname = \"coffee\"\npath = \"contract.ko\"\n",
        )?;
        fs::write(
            temp.path().join("Musubi.networks.toml"),
            "invalid unused network binding",
        )?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("explicit-build-cache"),
        )
        .with_build_registry_resolver(std::sync::Arc::new(|| {
            panic!("local package must not resolve a parent registry")
        }));
        let input = |locked| ContractInput::from_path(&manifest, None, None, locked);
        assert!(runtime.build(&input(true)?).is_err());
        let artifact = runtime.build(&input(false)?)?;
        assert_eq!(artifact.name(), "Coffee");
        assert_eq!(runtime.build(&input(true)?)?.bytes(), artifact.bytes());
        assert!(temp.path().join("Musubi.lock").is_file());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("explicit-build-cache").exists());
        Ok(())
    }

    #[test]
    fn absent_registry_refuses_external_dependencies_before_http() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(temp.path().join("contract.ko"), SOURCE)?;
        let manifest = temp.path().join("Musubi.toml");
        fs::write(
            &manifest,
            "manifest-version = 1\n[package]\nnamespace = \"demo\"\nname = \"coffee\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n[[contract]]\nname = \"coffee\"\npath = \"contract.ko\"\n[dependencies]\ndependency = { package = \"deps.sora/dependency\", version = \"^1.0.0\" }\n",
        )?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("explicit-build-cache"),
        );
        let error = runtime
            .build(&ContractInput::from_path(&manifest, None, None, false)?)
            .err()
            .expect("external dependency requires an authenticated registry");
        assert!(
            error
                .to_string()
                .contains("no authenticated build registry"),
            "{error:#}"
        );
        assert!(!temp.path().join("Musubi.lock").exists());
        assert!(!temp.path().join("explicit-build-cache").exists());
        Ok(())
    }

    #[test]
    fn selected_source_repeats_real_compilation_and_preserves_declared_graph_selection()
    -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("selected.ko");
        fs::write(
            &source,
            "seiyaku Selected { include \"state.ko\"; import \"math.ko\" as Math; view fn quote(int cups) authorize(anyone) -> int { return cups * 10 + total + Math::value(); } }",
        )?;
        fs::write(
            temp.path().join("state.ko"),
            "state int total; hajimari() { total = 0; }",
        )?;
        fs::write(
            temp.path().join("math.ko"),
            "module Math { export fn value() -> int { return 1; } }",
        )?;
        fs::write(
            temp.path().join("unrelated.ko"),
            "invalid and never selected",
        )?;
        let input = ContractInput::from_path(&source, None, None, false)?;
        let ContractInput::Source(selected) = &input else {
            unreachable!()
        };
        let graph =
            discover_selected_source_link_request(selected, temp.path(), Vec::new(), Vec::new())?;
        assert_eq!(
            graph
                .sources
                .iter()
                .map(|unit| unit.source_name.as_str())
                .collect::<Vec<_>>(),
            ["math.ko", "state.ko"]
        );
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("cache"),
        );
        let first = runtime.build(&input)?;
        let second = runtime.build(&input)?;
        assert_eq!(first.name(), "Selected");
        assert_eq!(first.bytes(), second.bytes());
        let bytecode_path = temp.path().join("selected.to");
        fs::write(&bytecode_path, first.bytes())?;
        let bytecode = ContractInput::from_path(&bytecode_path, None, None, false)?;
        assert_eq!(runtime.build(&bytecode)?.bytes(), first.bytes());
        assert_eq!(runtime.build(&bytecode)?.bytes(), first.bytes());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("cache").exists());
        Ok(())
    }

    fn selected_member_fixture(root: &Path, hybrid: bool) -> Result<(PathBuf, PathBuf)> {
        let root = root.join(if hybrid { "hybrid" } else { "virtual" });
        fs::create_dir_all(root.join("app"))?;
        fs::create_dir(root.join("other"))?;
        let package = |name: &str| {
            format!(
                "[package]\nnamespace = \"demo\"\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n[[contract]]\nname = \"{name}\"\npath = \"contract.ko\"\n"
            )
        };
        let root_manifest = format!(
            "manifest-version = 1\n{}[workspace]\nmembers = [\"app\", \"other\"]\ndefault-members = [\"other\"]\n",
            if hybrid {
                package("root")
            } else {
                String::new()
            }
        );
        fs::write(root.join("Musubi.toml"), root_manifest)?;
        if hybrid {
            fs::write(
                root.join("contract.ko"),
                "seiyaku SelectedRoot { view fn quote(int cups) authorize(anyone) -> int { return cups * 3; } }",
            )?;
        }
        for (name, source) in [
            (
                "app",
                "seiyaku SelectedApp { view fn quote(int cups) authorize(anyone) -> int { return cups; } }",
            ),
            (
                "other",
                "seiyaku DefaultOther { view fn quote(int cups) authorize(anyone) -> int { return cups * 2; } }",
            ),
        ] {
            fs::write(
                root.join(name).join("Musubi.toml"),
                format!("manifest-version = 1\n{}", package(name)),
            )?;
            fs::write(root.join(name).join("contract.ko"), source)?;
        }
        Ok((root.clone(), root.join("app/Musubi.toml")))
    }

    #[test]
    fn selected_member_defaults_to_its_own_contract_while_workspace_root_keeps_declared_selection()
    -> Result<()> {
        let temp = TempDir::new()?;
        for hybrid in [false, true] {
            let (root, member) = selected_member_fixture(temp.path(), hybrid)?;
            let runtime = DeploymentRuntime::new(
                config(),
                temp.path().join("journals"),
                temp.path().join("cache"),
            );
            let input = ContractInput::from_path(member.parent().unwrap(), None, None, false)?;
            assert_eq!(runtime.build(&input)?.name(), "SelectedApp");
            let explicit_member =
                ContractInput::from_path(&member, Some("demo/app".into()), None, false)?;
            assert_eq!(
                runtime.build(&explicit_member)?.bytes(),
                runtime.build(&input)?.bytes()
            );
            let root_input = ContractInput::from_path(&root, None, None, false)?;
            assert_eq!(runtime.build(&root_input)?.name(), "DefaultOther");
            let root_member = ContractInput::from_path(
                &root.join("Musubi.toml"),
                Some("demo/app".into()),
                None,
                false,
            )?;
            assert_eq!(runtime.build(&root_member)?.name(), "SelectedApp");
            if hybrid {
                let root_package =
                    ContractInput::from_path(&root, Some("demo/root".into()), None, false)?;
                assert_eq!(runtime.build(&root_package)?.name(), "SelectedRoot");
            }
            assert!(!temp.path().join("journals").exists());
            assert!(!temp.path().join("cache").exists());
        }
        Ok(())
    }

    #[test]
    fn selected_member_refuses_other_package_before_lock_compile_review_and_retries_original()
    -> Result<()> {
        let temp = TempDir::new()?;
        let (root, member) = selected_member_fixture(temp.path(), false)?;
        let mut input = ContractInput::from_path(&member, Some("demo/other".into()), None, false)?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("cache"),
        );
        let error = runtime
            .deploy(
                &input,
                &AliasSelection::Scope {
                    domain: None,
                    dataspace: "universal".into(),
                },
                FeePaymentIntent::authority(Vec::new(), None),
                &mut |_| panic!("other member reached deployment review"),
                &mut |_| panic!("other member reached deployment dispatch"),
            )
            .err()
            .expect("a selected member cannot deploy another package");
        assert!(
            error
                .to_string()
                .contains("selected member manifest cannot select another package"),
            "{error:#}"
        );
        assert!(!root.join("Musubi.lock").exists());
        assert!(!root.join("target").exists());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("cache").exists());
        let ContractInput::Package {
            manifest, package, ..
        } = &mut input
        else {
            unreachable!()
        };
        manifest.revalidate()?;
        *package = None;
        assert_eq!(runtime.build(&input)?.name(), "SelectedApp");
        let ContractInput::Package { manifest, .. } = &input else {
            unreachable!()
        };
        manifest.revalidate()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn selected_source_accepts_resolved_parent_alias_and_parent_components_but_refuses_leaf_links()
    -> Result<()> {
        let temp = TempDir::new()?;
        let original = temp.path().join("original");
        fs::create_dir_all(original.join("nested"))?;
        fs::write(original.join("hello.ko"), SOURCE)?;
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&original, &alias)?;
        let path = alias.join("nested/../hello.ko");
        let input = ContractInput::from_path(&path, None, None, false)?;
        let ContractInput::Source(selected) = &input else {
            unreachable!()
        };
        assert_eq!(selected.path(), original.canonicalize()?.join("hello.ko"));
        assert_eq!(
            kotodama_lang::source::read_selected_source(selected)?,
            SOURCE
        );
        std::os::unix::fs::symlink(original.join("hello.ko"), original.join("leaf.ko"))?;
        assert!(ContractInput::from_path(&original.join("leaf.ko"), None, None, false).is_err());
        selected.revalidate()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn changed_selected_roots_refuse_before_review_journal_or_dispatch() -> Result<()> {
        let temp = TempDir::new()?;
        let bytecode = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .map_err(|error| eyre!(error))?;
        for kind in ["source", "bytecode", "manifest"] {
            for mutation in ["edit", "replace", "link"] {
                let directory = temp.path().join(format!("{kind}-{mutation}"));
                fs::create_dir(&directory)?;
                let name = match kind {
                    "source" => "selected.ko",
                    "bytecode" => "selected.to",
                    _ => "Musubi.toml",
                };
                let path = directory.join(name);
                let original = match kind {
                    "source" => SOURCE.as_bytes().to_vec(),
                    "bytecode" => bytecode.clone(),
                    _ => b"manifest-version = 1\n[package]\nnamespace = \"demo\"\nname = \"coffee\"\nversion = \"0.1.0\"\nedition = \"1\"\nabi-version = 1\n[[contract]]\nname = \"coffee\"\npath = \"contract.ko\"\n".to_vec(),
                };
                fs::write(&path, &original)?;
                if kind == "manifest" {
                    fs::write(directory.join("contract.ko"), SOURCE)?;
                }
                let input = ContractInput::from_path(&path, None, None, false)?;
                match mutation {
                    "edit" => fs::write(&path, b"changed original")?,
                    "replace" => {
                        fs::rename(&path, directory.join("retired"))?;
                        fs::write(&path, &original)?;
                    }
                    "link" => {
                        fs::rename(&path, directory.join("retired"))?;
                        fs::write(directory.join("target"), &original)?;
                        std::os::unix::fs::symlink(directory.join("target"), &path)?;
                    }
                    _ => unreachable!(),
                }
                let journals = directory.join("journals");
                let cache = directory.join("cache");
                let runtime = DeploymentRuntime::new(config(), journals.clone(), cache.clone());
                let error = runtime
                    .deploy(
                        &input,
                        &AliasSelection::Scope {
                            domain: None,
                            dataspace: "universal".into(),
                        },
                        FeePaymentIntent::authority(Vec::new(), None),
                        &mut |_| panic!("changed selected root reached review"),
                        &mut |_| panic!("changed selected root reached dispatch"),
                    )
                    .err()
                    .expect("changed selected root must refuse");
                assert!(
                    error.downcast_ref::<std::io::Error>().is_some(),
                    "{kind}/{mutation}: {error:#}"
                );
                assert!(!journals.exists(), "{kind}/{mutation}");
                assert!(!cache.exists(), "{kind}/{mutation}");
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn selected_source_fifo_substitution_and_direct_fifo_read_refuse_without_processes()
    -> Result<()> {
        fn create_fifo(path: &Path) -> Result<()> {
            #[cfg(target_vendor = "apple")]
            #[allow(
                unsafe_code,
                reason = "the native syscall creates only this test-owned FIFO without spawning a process"
            )]
            {
                use std::os::unix::ffi::OsStrExt as _;
                unsafe extern "C" {
                    fn mkfifo(path: *const std::ffi::c_char, mode: u16) -> std::ffi::c_int;
                }
                let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
                // SAFETY: Apple mode_t is u16 and this owned NUL-terminated path lives through the call.
                if unsafe { mkfifo(path.as_ptr(), 0o600) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            #[cfg(not(target_vendor = "apple"))]
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                path,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
            Ok(())
        }
        let temp = TempDir::new()?;
        let path = temp.path().join("selected.ko");
        fs::write(&path, SOURCE)?;
        let selected = ContractInput::from_path(&path, None, None, false)?;
        fs::rename(&path, temp.path().join("retired.ko"))?;
        create_fifo(&path)?;
        let runtime = DeploymentRuntime::new(
            config(),
            temp.path().join("journals"),
            temp.path().join("cache"),
        );
        let error = runtime
            .build(&selected)
            .err()
            .expect("FIFO substitution must refuse");
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(matches!(
            kotodama_lang::source::read_source_file(&path),
            Err(kotodama_lang::source::SourceReadError::Io(_))
        ));
        assert!(ContractInput::from_path(&path, None, None, false).is_err());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("cache").exists());
        Ok(())
    }

    #[test]
    fn slots_separate_network_authority_and_alias() -> Result<()> {
        let config = config();
        let alias = "coffee::universal".parse()?;
        let root = Path::new("/runtime/deployments");
        let expected = deployment_slot(&config, root, &alias);
        let mut changed = config.clone();
        changed.network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha::crypto::HashOf::from_untyped_unchecked(iroha::crypto::Hash::new(
                b"another network",
            )),
        );
        assert_ne!(deployment_slot(&changed, root, &alias), expected);
        changed = config.clone();
        changed.account_chain_discriminant = 369;
        assert_ne!(deployment_slot(&changed, root, &alias), expected);
        changed = config.clone();
        changed.key_pair = iroha::crypto::KeyPair::try_from_seed(
            vec![0x71; 32],
            iroha::crypto::Algorithm::Ed25519,
        )?;
        changed.account =
            iroha_data_model::account::AccountId::of(changed.key_pair.public_key().clone());
        assert_ne!(deployment_slot(&changed, root, &alias), expected);
        assert_ne!(
            deployment_slot(&config, root, &"other::universal".parse()?),
            expected
        );
        let id = hex::encode(iroha::crypto::Hash::new(b"journal").as_ref());
        validate_journal_id(&id)?;
        let journal = expected.join(&id);
        validate_journal_location(&config, root, &journal, &alias, &id)?;
        assert!(validate_journal_location(&changed, root, &journal, &alias, &id).is_err());
        assert!(
            validate_journal_location(&config, root, &journal, &"other::universal".parse()?, &id)
                .is_err()
        );
        assert!(
            validate_journal_location(&config, root, &expected.join("renamed"), &alias, &id)
                .is_err()
        );
        for invalid in ["../escape", "plan.json", "", &id.to_uppercase()] {
            assert!(validate_journal_id(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn slot_lock_and_corrupt_active_record_fail_before_network_access() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("private/slot");
        let session = DeploymentSlot::open(&path)?;
        assert!(DeploymentSlot::open(&path).is_err());
        let service = DeploymentService::new(config())?;
        assert!(session.reconcile(&service)?.is_none());
        session
            .writer
            .write_atomic("publication.json", b"../escape", PublishMode::Replace)?;
        assert!(session.reconcile(&service).is_err());
        drop(session);
        assert!(DeploymentSlot::open(&path).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn missing_retained_slot_cannot_hide_an_active_deployment() -> Result<()> {
        let temp = TempDir::new()?;
        // Slots report canonical journal paths; temporary roots may sit behind a symlink.
        let root = fs::canonicalize(temp.path())?;
        let path = root.join("private/slot");
        let moved = root.join("private/original-slot");
        let session = DeploymentSlot::open(&path)?;
        assert!(session.current_journal()?.is_none());
        let id = hex::encode(iroha::crypto::Hash::new(b"retained active deployment").as_ref());
        session.write_state(&slot::Publication::Active {
            journal: id.clone(),
        })?;
        assert_eq!(session.current_journal()?, Some(path.join(&id)));
        fs::rename(&path, &moved)?;
        let result = session.current_journal();
        fs::rename(&moved, &path)?;
        assert!(matches!(
            result.unwrap_err().downcast_ref::<std::io::Error>(),
            Some(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(session.current_journal()?, Some(path.join(id)));
        Ok(())
    }

    #[test]
    fn invalid_source_and_foreign_journal_cannot_dispatch() -> Result<()> {
        let _caller_profile = ChainDiscriminantGuard::enter(73);
        let temp = TempDir::new()?;
        let source = temp.path().join("invalid.ko");
        fs::write(&source, "not Kotodama")?;
        let root = temp.path().join("journals");
        fs::create_dir(&root)?;
        let runtime = DeploymentRuntime::new(
            config(),
            root.clone(),
            temp.path().join("explicit-build-cache"),
        );
        let alias = AliasSelection::Scope {
            domain: None,
            dataspace: "universal".into(),
        };
        let result = runtime.deploy(
            &ContractInput::from_path(&source, None, None, false)?,
            &alias,
            FeePaymentIntent::authority(Vec::new(), None),
            &mut |_| panic!("invalid source reached review"),
            &mut |_| panic!("invalid source reached dispatch"),
        );
        assert!(result.is_err());
        assert!(
            runtime
                .resume(
                    temp.path(),
                    &mut |_| panic!("foreign journal reached review"),
                    &mut |_| panic!("foreign journal reached dispatch")
                )
                .is_err()
        );
        let nested = root.join("unexpected").join("nested").join("journal");
        fs::create_dir_all(&nested)?;
        let error = runtime
            .resume(
                &nested,
                &mut |_| panic!("nested journal reached review"),
                &mut |_| panic!("nested journal reached dispatch"),
            )
            .err()
            .expect("nested journal rejected");
        assert!(
            error
                .to_string()
                .contains("outside this runtime's journal slots")
        );
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 73);
        assert!(!temp.path().join("explicit-build-cache").exists());
        Ok(())
    }
}

#[cfg(test)]
#[path = "deployment_runtime/resume_tests.rs"]
pub(crate) mod resume_tests;
